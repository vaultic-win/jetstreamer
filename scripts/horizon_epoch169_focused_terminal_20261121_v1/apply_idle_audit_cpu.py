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
        need(str(delivery/'event-tools-bounded')+'/' in service['ExecStart'], 'old terminal event selector remains armed')
        bindings[str(epoch)] = dict(path=path,service=service,adapter=value)
    return dict(registration=registration,provider=body['provider'],epochs=bindings)

def apply(head, handoff_refs):
    need(handoff_refs, 'accepted price and event handoffs required for this CPU transition')
    for ref in handoff_refs:
        checked(ref)
    dependencies = checked_prices()
    before = snapshot(head)
    need(before['profile']=='paid-four' and before['raw_idle']=='0' and before['manager_weight']=='[not set]', 'unexpected starting CPU service policy')
    need(before['readers'] and set(before['children']).issubset(UNITS), 'no active audit readers or another job is sharing the slice')
    need(all(v['cpu_max']=='400000 100000' for v in before['children'].values()), 'audit child CPU ceiling changed')
    paid = before['paid']
    if paid['ActiveState']=='active':
        expected = R/'epoch145-semantic-continuity-20261121-v1'
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
        for key in ('boot','scope','readers','children','producers','guards','paid'):
            need(before[key]==after[key], 'live identity or protection changed during cutover: '+key)
        need(before['slice_limits']==dict(after['slice_limits'],CPUQuotaPerSecUSec='4s'), 'non-CPU slice setting changed')
        need(after['profile']=='idle-twelve' and after['raw_idle']=='1', 'idle CPU profile readback failed')
        receipt = ROOT/'IN_PLACE_CPU_ACTIVE.json'
        durable(receipt, dict(schema='horizon-existing-audit-slice-idle-ceiling-v1', before=before, after=after,
                               live_handoffs=handoff_refs, terminal_prices=dependencies, assignment=bound(ASSIGNMENT), observer=bound(ROOT/'ACTIVE.json')))
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
