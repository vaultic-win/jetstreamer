"""Keep the sole regular clock running across an authenticated incomplete host census."""
import datetime as dt
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

from evidence import BASE, SEALER, bound, checked, durable, ensure_dir, names, need, sealed, utc

SCHEMA = 'horizon-incomplete-resident-census-next-routine-v1'
CONSUMER = 'horizon-archive-status-cadence-after172-20261120-v1.service'
SEALER_PATH = Path('/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment')


def incomplete(sample):
    host = sample['host_resident_memory']
    failed = {}
    for edge in ('before', 'after'):
        item = host[edge]
        if item['status'] == 'observed':
            continue
        errors = item.get('discarded_attempt_errors')
        count = item.get('census_attempts')
        need(item['status'] == 'unavailable' and isinstance(count, int) and 1 <= count <= 5 and
             isinstance(errors, list) and len(errors) == count and item['error'] == errors[-1] and
             all(isinstance(v, str) and v for v in errors) and 'rss' not in item,
             'invalid unavailable host census')
        failed[edge] = item
    return failed


def generation(ref, config_ref):
    return Path(ref['path']).parent/'resident-census-recovery'/config_ref['sha256']


def derived(fleet, cfg, sample):
    clock = sample['cadence']
    stamp = utc(sample['recorded_at_utc'])
    due = clock['next_routine_observation_not_before_utc']
    need(sample['schema'] == 'jetstreamer-horizon-live-resource-sample-v2' and
         cfg['observation_reason'] == clock['observation_reason'] == 'routine' and
         cfg['minimum_interval_seconds'] == clock['minimum_interval_seconds'] == 1800 and
         clock['routine_minimum_interval_enforced'] is True and clock['observed_interval_seconds'] >= 1800 and
         clock['previous_sample_recorded_at_utc'] == fleet['sampled_at_utc'] and
         clock['observed_interval_seconds'] == (stamp-utc(fleet['sampled_at_utc'])).total_seconds() and
         cfg['previous_sample'] == clock['previous_sample'] == fleet['observer']['path'] and
         clock['previous_sample_sha256'] == fleet['observer']['sha256'] and
         cfg['not_before_utc'] == clock['configured_not_before_utc'] and
         utc(cfg['not_before_utc']) <= stamp <= utc(sample['completed_at_utc']) and
         utc(due) == stamp + dt.timedelta(seconds=1800) and bool(incomplete(sample)),
         'invalid failed sample clock')
    return dict(cfg, not_before_utc=due, output=str(names(due)['sample']))


def resolve(ref, fleet, cfg):
    current = fleet['sole_next_observer']
    latest = None
    while True:
        directory = generation(ref, current)
        p = directory/'REGISTERED.json'
        if not p.exists():
            break
        latest = bound(p)
        receipt = checked(latest)
        target = directory/'sealed-next/observer.json'
        failed = bound(Path(cfg['output']))
        need(receipt['schema'] == SCHEMA and receipt['fleet'] == ref and
             receipt['failed_config'] == current and receipt['failed_sample'] == failed and
             receipt['replacement_config'] == bound(target) and
             receipt['native']['unit'] == names(cfg['not_before_utc'])['timer'].removesuffix('.timer')+'.service',
             'foreign resident-census registration')
        new = sealed(receipt['replacement_config'])
        need(new == derived(fleet, cfg, checked(failed)), 'changed replacement observation')
        cfg, current = new, receipt['replacement_config']
    if latest:
        fleet = dict(fleet, sole_next_timer=names(cfg['not_before_utc'])['timer'],
                     sole_next_observer=current, latest_incomplete_census_handoff=latest)
    return fleet, cfg


def owner():
    from race166 import properties
    state = properties(CONSUMER, 'MainPID', 'ActiveState', 'Job')
    pid = Path('/proc')/state['MainPID']
    need(state['ActiveState']=='active' and not state['Job'] and
         (pid/'fd/9').samefile(BASE/'stable-cadence-controller-20261120-v1/consumer.lock') and
         ' FLOCK ' in (pid/'fdinfo/9').read_text() and
         (pid/'fd/255').samefile(Path(__file__).with_name('consume')) and
         (pid/'cgroup').read_text() == Path('/proc/self/cgroup').read_text(),
         'scheduled repair requires original sole consumer')


def register(ref, fleet, cfg, sample_ref):
    from race166 import successful_sample
    sample = checked(sample_ref)
    old = fleet['sole_next_observer']
    path = Path(cfg['output'])
    need(sample_ref == bound(path) and sealed(old) == cfg, 'foreign incomplete sample')
    new = derived(fleet, cfg, sample)
    scheduled = names(cfg['not_before_utc'])
    need(not (scheduled['out']/'ROOT_COMPLETE_OPERATIONAL_FLEET.json').exists() and
         not scheduled['statuses'].exists(), 'cycle already published or attempted status writes')
    native = successful_sample(SimpleNamespace(fleet=fleet,sample=sample))
    directory = generation(ref, old)
    ensure_dir(directory.parent)
    ensure_dir(directory)
    src = directory/'observer.json'
    durable(src, new)
    destination = directory/'sealed-next'
    plan = directory/'seal.json'
    durable(plan, dict(schema='jetstreamer-sealed-deployment-plan-v1',destination=str(destination),
                       members=[dict(name=src.name,source=str(src),sha256=bound(src)['sha256'],mode=0o444)]))
    need(bound(SEALER_PATH)['sha256']==SEALER, 'changed deployment sealer')
    if not destination.exists():
        subprocess.run([SEALER_PATH,plan,'--plan-sha256',bound(plan)['sha256'],'--self-sha256',SEALER],
                       stdout=subprocess.DEVNULL,check=True)
    target = bound(destination/'observer.json')
    need(sealed(target) == new, 'failed to seal exact successor')
    durable(directory/'REGISTERED.json',dict(schema=SCHEMA,fleet=ref,failed_config=old,failed_sample=sample_ref,
            native=native,unavailable=incomplete(sample),replacement_config=target,
            next_due=new['not_before_utc'],new_capacity_credit=0,status_writes=0))


def scheduled(path):
    from cycle import load_fleet
    from race166 import properties
    # <accepted fleet>/resident-census-recovery/<config digest>/sealed-next/observer.json
    ancestor = path.parent.parent.parent
    need(ancestor.name=='resident-census-recovery' and ancestor.parent.parent==BASE,'foreign replacement directory')
    ref = bound(ancestor.parent/'ROOT_COMPLETE_OPERATIONAL_FLEET.json')
    f,cfg,_ = load_fleet(ref)
    unit = f['sole_next_timer'].removesuffix('.timer')+'.service'
    need(f['sole_next_observer']==bound(path) and
         Path('/proc/self/cgroup').read_text().strip()=='0::/system.slice/'+unit and
         properties(unit,'MainPID','InvocationID')==dict(MainPID=str(os.getpid()),InvocationID=os.environ['INVOCATION_ID'])
         and not Path(cfg['output']).exists(),'unregistered replacement invocation')
    return cfg,ref,bound(path)


def existing_timer(unit,timers,cmd):
    from race166 import properties
    pending=properties(unit+'.service','LoadState','ActiveState','Job')
    if pending['LoadState']=='not-found':
        need(not timers and not pending['Job'] and pending['ActiveState']=='inactive',
             'competing observer during new timer registration')
    elif timers or pending['Job'] or pending['ActiveState'] in ('active','activating'):
        actual=properties(unit+'.service','ExecStart')
        need((not timers or timers==[unit+'.timer']) and ' '.join(cmd) in actual['ExecStart'],
             'competing observer schedule')
        return True
    return False


def ensure_timer(fleet,cfg):
    path=Path(fleet['sole_next_observer']['path'])
    if path.parent.parent.parent.name!='resident-census-recovery' or Path(cfg['output']).exists():
        return
    unit=fleet['sole_next_timer'].removesuffix('.timer')
    cmd=['/usr/bin/python3','-B',str(Path(__file__).with_name('guard_stops.py')),str(path)]
    timers=[l.split()[0] for l in subprocess.check_output(['systemctl','list-units','--type=timer','--state=waiting',
            '--no-legend','--plain','horizon-observer-*.timer'],text=True).splitlines()]
    if existing_timer(unit,timers,cmd):return
    due=utc(cfg['not_before_utc'])
    clock=(['--on-calendar='+due.strftime('%F %T UTC')] if due>dt.datetime.now(dt.timezone.utc)
           else ['--on-active=1s'])
    subprocess.run(['systemd-run','--quiet','--unit='+unit,*clock,'--timer-property=AccuracySec=1s',
                    '--timer-property=RemainAfterElapse=no',*cmd],check=True)


def main():
    from cycle import load_fleet
    op,path,sha,*args=sys.argv[1:]
    need(os.geteuid()==0 and __debug__ and op in ('ensure','decide'),'invalid clock operation')
    owner()
    ref=dict(path=path,sha256=sha)
    if op=='decide':
        need(len(args)==2,'expected scheduled sample binding')
        sample=dict(path=args[0],sha256=args[1])
        if not incomplete(checked(sample)):
            print('publish')
            return
    fleet,cfg,_=load_fleet(ref)
    if op=='decide':
        register(ref,fleet,cfg,sample)
        print('reschedule')
    else:
        ensure_timer(fleet,cfg)


if __name__=='__main__':
    main()
