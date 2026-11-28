"""Apply or roll back the audit slice's idle-only CPU ceiling on the same live PIDs."""
import datetime as dt
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

R = Path('/var/lib/jetstreamer/horizon_runtime_data')
ROOT = R/'ready-idle-cpu-20261121-v1'
PKG = ROOT/'cadence-tools'
sys.path.insert(0, str(PKG))
from evidence import bound, checked, durable, need
from idle_audit_cpu import ASSIGNMENT, GROUP, POLICY, profile
from owners import show
from public_witness import slice_envelope
from ready_audit_jobs import UNITS, native_jobs

SLICE = 'horizonaudit.slice'
PAID = 'horizon-holding-export145-20261121-v1.service'
Q = R/'ready-audit-growth-20261121-v1/REGISTERED.json'
SERVICE_FIELDS = ('Id','ControlGroup','ActiveState','MainPID','InvocationID','CPUQuotaPerSecUSec','MemoryHigh','MemoryMax','MemorySwapMax','TasksMax','NRestarts')
PAID_FIELDS = ('Id','ActiveState','MainPID','InvocationID','ExecStart')
GUARD_FIELDS = ('Id','ActiveState','InvocationID','Triggers')
PULSE = re.compile(rb'horizon_tps elapsed_seconds=([\d.]+) transactions=(\d+)')
REPLAY = re.compile(rb'progress slot (\d+)/\d+ .*?txs=(\d+)')

def read_tail(path, pattern):
    with path.open('rb') as stream:
        st = os.fstat(stream.fileno())
        stream.seek(max(0, st.st_size-65536))
        matches = list(pattern.finditer(stream.read()))
        need(matches, 'missing native progress at '+str(path))
        return dict(device=st.st_dev, inode=st.st_ino, progress=[n.decode() for n in matches[-1].groups()])

def counters(path):
    return dict((k,int(v)) for k,v in (row.split() for row in path.read_text().splitlines()))

def roots(head):
    fleet = checked(head)
    need(fleet['authenticated_status_count']==19 and fleet['all_active_status_reports_authenticated_readback'], 'incomplete native fleet')
    audit = checked(fleet['current_audit_progress']['observation'])
    return fleet, audit['inventory']

def snapshot(head):
    fleet, scope = roots(head)
    gate = checked(bound(Q))
    jobs = native_jobs(scope)
    readers = {}
    pulses = {}
    for job in jobs:
        key = '-'.join(str(v) for v in job['range'])
        need(key not in readers, 'duplicate active audit reader')
        readers[key] = job
        pulses[key] = read_tail(Path('/proc')/str(job['pid'])/'fd/1', PULSE)
    children = {}
    for group in GROUP.iterdir():
        if group.is_dir() and (group/'cgroup.procs').read_text().strip():
            row = show(group.name, SERVICE_FIELDS)
            need(row['ControlGroup']=='/horizonaudit.slice/'+group.name, 'foreign audit child')
            children[group.name] = dict(unit=row, cpu_max=(group/'cpu.max').read_text().strip())
    producers, guards, progress = {}, {}, {}
    for row in fleet['actual_executing_replays']:
        epoch = str(row['epoch'])
        unit = row['unit']
        producers[epoch] = show(unit['Id'], SERVICE_FIELDS)
        need(unit['InvocationID'] and int(unit['MainPID'])>1 and producers[epoch]['ActiveState']=='active', 'missing native producer')
        need(all(producers[epoch][key]==unit[key] for key in ('InvocationID','MainPID','CPUQuotaPerSecUSec','MemoryMax','ControlGroup') if key in unit), 'producer departed native fleet')
        guard = row['guard_timer']
        guards[epoch] = show(guard['Id'], GUARD_FIELDS)
        need(guards[epoch]['ActiveState']=='active' and guards[epoch]['InvocationID']==guard['InvocationID'], 'producer guard departed native fleet')
        binding = row['progress']['append_log_evidence']
        value = read_tail(Path(binding['path']), REPLAY)
        need(all(value[key]==binding[key] for key in ('device','inode')), 'producer progress inode changed')
        progress[epoch] = value
    limits = slice_envelope()
    return dict(schema='horizon-existing-audit-slice-cpu-snapshot-v1', observed=dt.datetime.now(dt.timezone.utc).isoformat(),
                monotonic_ns=time.monotonic_ns(), boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                head=head, output_guard=gate['operator_basis'], scope=scope, profile=profile(), slice_limits=limits,
                raw_cpu_max=(GROUP/'cpu.max').read_text().strip(), raw_idle=(GROUP/'cpu.idle').read_text().strip(),
                manager_weight=show(SLICE, ('CPUWeight',))['CPUWeight'], cpu=counters(GROUP/'cpu.stat'), host_cpu=Path('/proc/stat').read_text().splitlines()[0],
                cpu_pressure=(GROUP/'cpu.pressure').read_text(), memory_current=int((GROUP/'memory.current').read_text()), tasks_current=int((GROUP/'pids.current').read_text()),
                children=children, readers=readers, reader_pulses=pulses, producers=producers, guards=guards, producer_progress=progress,
                paid=show(PAID, PAID_FIELDS))

def set_property(value):
    subprocess.run(['systemctl','set-property','--runtime',SLICE,value], check=True, timeout=45)

def restore(change=set_property, inspect=profile):
    change('CPUQuota=400%')
    need(inspect()=='paid-four', 'could not restore paid quota before restoring priority')
    change('CPUWeight=')
    need(inspect()=='paid-four', 'paid profile was lost after restoring priority')

def raise_ceiling(change=set_property, inspect=profile, marker=lambda:(GROUP/'cpu.idle').read_text().strip()):
    try:
        change('CPUWeight=idle')
        need(inspect()=='paid-four' and marker()=='1', 'manager failed to set top-level idle at the paid quota')
        change('CPUQuota=1200%')
        need(inspect()=='idle-twelve', 'manager failed to install the qualified idle CPU ceiling')
    except BaseException:
        restore(change, inspect)
        raise

def event_fence(epoch, delivery, service_name):
    registration = bound(R/'incident-replay-fit-20261121-v1/BOUNDED_FIVE_PUBLICATION_EVENT_FENCE.json')
    need(registration['sha256']=='69d3ee179a4d562e748b645cec9cff3b7075261b2173678986a022c779d83440', 'foreign event fence')
    recorded = checked(registration)
    marker_ref = recorded['marker']
    marker = Path(marker_ref['path'])
    policy = checked(marker_ref)
    need(policy['epochs']==[166,167,168,170,172] and policy['publication_permitted'] is False and marker.stat().st_mode&0o777==0o400,
         'unregistered terminal hold marker')
    row = recorded['after'][str(epoch)]
    prior_service = row['event_service']
    before_path = row['path_watcher']
    need(prior_service['Id']==service_name and before_path['Id']==service_name.removesuffix('.service')+'.path', 'different event owner')
    path = show(before_path['Id'], tuple(before_path))
    service = show(service_name, tuple(k for k in prior_service if k!='Conditions'))
    need(path==before_path and all(prior_service[k]==v for k,v in service.items()), 'changed original terminal watcher or service')
    drop = recorded['dropins'][str(epoch)]
    props = show(service_name, ('DropInPaths','NeedDaemonReload','ControlPID'))
    need(props['NeedDaemonReload']=='no' and props['ControlPID']=='0' and drop['path'] in props['DropInPaths'].split() and bound(Path(drop['path']))==drop,
         'original event fence is absent in PID1')
    bus = ['busctl','--system','--json=short']
    object_path = json.loads(subprocess.check_output(bus+['call','org.freedesktop.systemd1','/org/freedesktop/systemd1','org.freedesktop.systemd1.Manager','GetUnit','s',service_name]))['data'][0]
    conditions = json.loads(subprocess.check_output(bus+['get-property','org.freedesktop.systemd1',object_path,'org.freedesktop.systemd1.Unit','Conditions']))
    need(conditions=={'type':'a(sbbsi)','data':[['ConditionPathExists',False,True,str(marker),0]]}, 'effective inverted event condition differs')
    need(path['Paths']==row['terminal']+' (PathExists)' and not Path(row['terminal']).exists()
         and Path(row['event_state'])==delivery/'event-state' and not any((delivery/'event-state').iterdir()), 'actual terminal or delivery intent pending')
    return dict(registration=registration, marker=marker_ref, path=path, service=service, dropin=drop, conditions=conditions)

def checked_prices():
    root = R/'incident-replay-fit-20261121-v1'
    registration = bound(root/'BOUNDED_FIVE_PUBLICATION_CAPACITY.json')
    body = checked(registration)
    provider = Path(body['provider']['path'])
    need(bound(provider)==body['provider'] and provider.name=='post-stop-fit' and provider.parent.parent==root, 'unrecognized live paid provider')
    need(bound(provider.parent/'idle_audit_cpu.py')['sha256']==bound(PKG/'idle_audit_cpu.py')['sha256']
         and bound(provider.parent/'idle_floor.py')['sha256']==bound(ROOT/'staging/idle_floor.py')['sha256'], 'historical CPU floor helper changed')
    checked(body['qualification'])
    bindings = {}
    for epoch, unit in {166:'horizon-166-retry10-publication',167:'horizon-current-publication@167',
                       168:'horizon-168-metered-publication',170:'horizon-current-publication@170',172:'horizon-current-publication@172'}.items():
        value = body['epochs'][str(epoch)]
        adapter = Path(value['executable']['path'])
        delivery = R/('epoch166-retry10-delivery-20261121-v1' if epoch==166 else f'epoch{epoch}-current-delivery-20261121-v1')
        need(adapter==delivery/'capacity-tools-bounded/publication-fit' and bound(adapter)==value['executable'], 'foreign terminal price adapter')
        seal = checked(value['seal'])
        need(any(m['name']==adapter.name and m['sha256']==value['executable']['sha256'] for m in seal['members']), 'terminal adapter not in registered seal')
        path = show(unit+'.path', ('ActiveState','SubState','Triggers'))
        service = show(unit+'.service', ('MainPID','ActiveState','ExecStart','Job'))
        need(path['ActiveState']=='active' and unit+'.service' in path['Triggers'].split()
             and service['ActiveState']=='inactive' and service['MainPID']=='0' and not service['Job'], 'event in flight or unarmed')
        fence = None
        if str(delivery/'event-tools-bounded')+'/' not in service['ExecStart']:
            fence = event_fence(epoch, delivery, unit+'.service')
        bindings[str(epoch)] = dict(path=path,service=service,adapter=value,active_fence=fence)
    return dict(registration=registration,provider=body['provider'],epochs=bindings)

def child_limits(snapshot):
    need(snapshot['readers'], 'no active native audit readers')
    for name, child in snapshot['children'].items():
        if name in UNITS:
            need(child['cpu_max']=='400000 100000', 'audit child CPU ceiling changed')
            continue
        need(name=='horizon-bounded-five-after-145-20261121-v1.service', 'unregistered concurrent audit child')
        unit=child['unit']
        qa=R/'incident-replay-fit-20261121-v1/paid145-five-controller-qa-bounded-d859e5380946/run-native-qa.sh'
        need(child['cpu_max']=='50000 100000' and unit['CPUQuotaPerSecUSec']=='500ms' and unit['MemoryMax']==str(768<<20)
             and unit['MemorySwapMax']=='0' and unit['TasksMax']=='96' and unit['InvocationID']=='808558e26a87432ba4f8f96d377dd951',
             'unexpected resources or invocation on the paid native publisher qualification')
        need(bound(qa)['sha256']=='ceda87b5df92a0ec731a0cc1b14074078d08da0aa7f2f37bf582be5232031b11'
             and str(qa) in show(name,('ExecStart',))['ExecStart'], 'concurrent qualification is not the registered V16 reader')

def paid_semantic(head, manager):
    root=R/'epoch145-semantic-continuity-20261121-v1'
    ref=bound(root/'V5E_ACTUAL_ADVANCING_WORKER.json')
    proof=checked(ref)
    previous, current=proof['observations']
    accepted=checked(proof['manager'])
    need(proof['invocation_id']==manager['InvocationID']==accepted['new']['InvocationID']
         and current['parent_pid']==int(manager['MainPID']) and previous['child_pid']==current['child_pid']
         and previous['child_ticks']==current['child_ticks'] and current['source_offset']>previous['source_offset']
         and current['worker_cpu_ticks']>previous['worker_cpu_ticks'], 'paid verifier owner or progression changed')
    intent=checked(accepted['intent'])
    need(intent['fleet']==head and checked(intent['fit'])['fits'] and intent['provider']==intent['semantic_provider']
         and intent['provider']['sha256']=='b11e6366a6fc0cf3ed91d2584314851b628f2589d60b70d41b922cb1170d0cb5', 'unexpected paid admission price')
    checked(intent['provider'])
    child=Path('/proc')/str(current['child_pid'])
    need(int((child/'stat').read_text().rsplit(')',1)[1].split()[19])==current['child_ticks'], 'paid semantic PID changed')
    expected={tuple(row) for row in current['native_leases']}
    observed={tuple(line.split()[1:]) for line in Path('/proc/locks').read_text().splitlines() if len(line.split())>4 and line.split()[4] in (str(current['child_pid']),manager['MainPID'])}
    need(expected==observed and sum(row[:3]==('LEASE','ACTIVE','READ') for row in observed)==6
         and sum(row[:3]==('FLOCK','ADVISORY','WRITE') for row in observed)==1, 'paid worker leases or parent lock changed')
    return dict(advancement=ref, manager=proof['manager'], native_leases=sorted(observed), prestart=intent['fit'], native_price=intent['provider'])

def apply(head, handoff_refs):
    need(handoff_refs, 'accepted price and event handoffs required for this CPU transition')
    for ref in handoff_refs:
        checked(ref)
    dependencies = checked_prices()
    before = snapshot(head)
    need(before['profile']=='paid-four' and before['raw_idle']=='0' and before['manager_weight']=='[not set]', 'unexpected starting CPU service policy')
    child_limits(before)
    semantic=None
    paid = before['paid']
    if paid['ActiveState']=='active':
        expected = R/'epoch145-semantic-continuity-20261121-v1'
        if str(expected/'tools-v5e/export145') in paid['ExecStart']:
            semantic=paid_semantic(head,paid)
        need(any(str(expected/version)+'/export145' in paid['ExecStart'] for version in ('tools-v5e','tools-v11')), 'old paid guard remains selected')
    else:
        need(paid['ActiveState'] in ('failed','inactive') and paid['MainPID']=='0', 'paid worker is transitioning')
    durable(ASSIGNMENT, POLICY)
    raised = False
    try:
        raise_ceiling()
        raised = True
        after = snapshot(head)
        need(dependencies==checked_prices(), 'selected publication guards changed during cutover')
        child_limits(after)
        for name, row in before['children'].items():
            if name in UNITS or name in after['children']:
                need(after['children'].get(name)==row, 'protected audit child changed during CPU transition')
        need(set(after['children']).issubset(before['children']), 'new audit child during CPU transition')
        if semantic:
            need(semantic==paid_semantic(head,after['paid']), 'paid worker changed during CPU transition')
        for key in ('boot','scope','readers','producers','guards','paid'):
            need(before[key]==after[key], 'live identity or protection changed during cutover: '+key)
        need(before['slice_limits']==dict(after['slice_limits'],CPUQuotaPerSecUSec='4s'), 'non-CPU slice setting changed')
        need(after['profile']=='idle-twelve' and after['raw_idle']=='1', 'idle CPU profile readback failed')
        receipt = ROOT/'IN_PLACE_CPU_ACTIVE.json'
        durable(receipt, dict(schema='horizon-existing-audit-slice-idle-ceiling-v1', before=before, after=after,
                               live_handoffs=handoff_refs, terminal_prices=dependencies, paid_worker=semantic, assignment=bound(ASSIGNMENT), observer=bound(ROOT/'ACTIVE.json')))
        print(json.dumps(bound(receipt)))
    except BaseException:
        if raised:
            restore()
        raise

def compare(before, after):
    first, last = checked(before), checked(after)
    elapsed = (last['monotonic_ns']-first['monotonic_ns'])/1e9
    need(first['boot']==last['boot'] and elapsed>0 and first['profile']==last['profile'], 'window crosses boot or resource change')
    audit = {}
    for name, old in first['reader_pulses'].items():
        if first['readers'][name]!=last['readers'].get(name):
            continue
        new = last['reader_pulses'][name]
        need((old['device'],old['inode'])==(new['device'],new['inode']), 'reader output changed mid-window')
        native_time = float(new['progress'][0])-float(old['progress'][0])
        tx = int(new['progress'][1])-int(old['progress'][1])
        need(native_time>=0 and tx>=0, 'native audit progress regressed')
        audit[name] = dict(native_seconds=native_time, transactions=tx, tps=tx/native_time if native_time else None)
    produced = {}
    for epoch, old in first['producer_progress'].items():
        if first['producers'][epoch]!=last['producers'].get(epoch):
            continue
        new = last['producer_progress'][epoch]
        need((old['device'],old['inode'])==(new['device'],new['inode']), 'producer output changed mid-window')
        slot, tx = (int(y)-int(x) for x,y in zip(old['progress'],new['progress']))
        need(slot>=0 and tx>=0, 'native producer progress regressed')
        produced[epoch] = dict(slot_delta=slot, transactions=tx, approximate_tps=tx/elapsed)
    cpu = (last['cpu']['usage_usec']-first['cpu']['usage_usec'])/1e6/elapsed
    host = [int(y)-int(x) for x,y in zip(first['host_cpu'].split()[1:9],last['host_cpu'].split()[1:9])]
    return dict(snapshots=[before,after], profile=first['profile'], elapsed_seconds=elapsed, readers=audit, producers=produced,
                native_aggregate_tps=sum(row['tps'] for row in audit.values() if row['tps'] is not None),
                slice_cpus_used=cpu, host_idle_fraction=host[3]/sum(host),
                throttled_periods=last['cpu']['nr_throttled']-first['cpu']['nr_throttled'],
                elapsed_periods=last['cpu']['nr_periods']-first['cpu']['nr_periods'])

def main():
    need(os.geteuid()==0 and sys.flags.isolated and __debug__, 'root isolated Python required')
    command, *args = sys.argv[1:]
    if command=='rollback' and not args:
        restore()
        print(json.dumps(slice_envelope()))
    elif command=='snapshot' and len(args)==3:
        head=dict(path=args[0],sha256=args[1])
        output=Path(args[2])
        need(output.parent==ROOT, 'unexpected CPU qualification output directory')
        durable(output,snapshot(head))
        print(json.dumps(bound(output)))
    elif command=='compare' and len(args)==3:
        paths = [Path(name) for name in args]
        need(all(p.parent==ROOT for p in paths), 'unexpected CPU evidence directory')
        durable(paths[2], compare(bound(paths[0]), bound(paths[1])))
        print(json.dumps(bound(paths[2])))
    elif command=='apply' and len(args)>=4 and len(args)%2==0:
        refs=[dict(path=path,sha256=digest) for path,digest in zip(args[::2],args[1::2])]
        apply(refs[0],refs[1:])
    else:
        raise ValueError('use rollback, snapshot HEAD SHA OUTPUT, compare START END OUTPUT, or apply HEAD SHA HANDOFF SHA [...]')

if __name__=='__main__':
    main()
