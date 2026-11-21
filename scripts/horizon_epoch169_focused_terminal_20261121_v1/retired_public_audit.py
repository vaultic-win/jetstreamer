"""Observe the ready-only successor of the retired chronological audit."""
from pathlib import Path
import time
from evidence import BASE, bound, checked, content, need
from owners import show

READY = BASE / 'ready-range-audit-20261121-v1'
UNIT = 'horizon-r2-ready-ranges-101-300-20261121-v1.service'
CG = Path('/sys/fs/cgroup/horizonaudit.slice')
FIELDS = ('Id','ActiveState','SubState','Job','MainPID','InvocationID','NRestarts','ControlGroup')

def retired(row, group):
    need(row['MainPID']=='0' and row['ActiveState'] in ('inactive','failed') and not row['Job'],
         'retired chronological unit returned')
    need(not (group/'cgroup.procs').exists() or not (group/'cgroup.procs').read_text().strip(),
         'retired chronological group contains processes')

def regions(scope):
    need(scope['schema']=='horizon-ready-strict-audit-scope-v1' and scope['scope']==[101,300], 'unexpected ready scope')
    eligible=[r['epoch'] for r in scope['objects'] if r['ready']]
    ranges=scope['eligible_ranges']
    need([n for lo,hi in ranges for n in range(lo,hi+1)]==sorted(set(eligible))
         and all(101<=lo<=hi<=300 for lo,hi in ranges)
         and all(a[1]+1<b[0] for a,b in zip(ranges,ranges[1:])), 'invalid complete ready partitions')
    return ranges

def measure(obligation, native, envelope):
    transition_ref=bound(Path(__file__).with_name('CHRONOLOGICAL_RETIREMENT.json'))
    transition=checked(transition_ref)
    scope_ref=transition['scope']; scope=checked(scope_ref); ranges=regions(scope)
    old=native(); retired(old,CG/transition['legacy_unit'])
    group=envelope()
    fast=show(UNIT,FIELDS)
    status_path=READY/'status.json'
    progress=content(status_path) if status_path.exists() else {}
    phase=progress.get('phase','awaiting_controller_status')
    if fast['ActiveState']=='active':
        pid=int(fast['MainPID']); proc=Path('/proc')/str(pid)
        expected='/horizonaudit.slice/'+UNIT
        need(pid>1 and fast['ControlGroup']==expected and (proc/'cgroup').read_text().strip()=='0::'+expected,
             'ready audit process outside its assigned slice')
        argv=(proc/'cmdline').read_bytes().split(b'\0')[:-1]
        need(argv==[b'/usr/bin/python3',b'-IB',str(READY/'ready-controller.py').encode()],
             'unexpected ready audit controller')
    elif fast['ActiveState']!='active':
        phase='ready_controller_'+fast['ActiveState']
    accepted=[]
    for lo,hi in ranges:
        path=READY/'accepted'/f'{lo}-{hi}.json'
        if not path.exists(): continue
        ref=bound(path); row=checked(ref)
        need(row['schema']=='horizon-ready-range-verified-v1' and row['range']==[lo,hi] and
             row['scope']==scope_ref and row['method']=='strict-public-slot-ranges' and
             [e['epoch'] for e in row['epochs']]==list(range(lo,hi+1)), 'foreign ready-range result')
        accepted.append((lo,hi,ref))
    count=sum(hi-lo+1 for lo,hi,_ in accepted); total=sum(hi-lo+1 for lo,hi in ranges)
    now=int(time.time()); active=progress.get('range')
    current={'phase':phase,'epoch':active[0] if active in ranges else None,'range':active,'controller_status':progress,
             'legacy_phase':'retired_by_operator','retirement':transition_ref}
    summary=dict(scope='ready public archives in epochs 101–300',archives=total,passed=count,failed=0,
                 pending=total-count,complete=count==total,accepted_ranges=[ref for _,_,ref in accepted])
    audit=dict(observed_at=now,progress=current,summary=summary,child=None,inventory=scope_ref,
               predecessor_stop=transition['original_download_stop'],chronological_retirement=transition_ref)
    work=obligation['working_allocation_cap_bytes']; cargo=obligation['cargo_growth_allowance_bytes']
    storage=dict(epoch=current['epoch'],archive_bytes=None,resident_archive_bytes=0,remaining_archive_growth_bytes=0,
                 remaining_working_growth_bytes=work,remaining_cargo_growth_allowance_bytes=cargo,
                 remaining_DATA_growth_bytes=work+cargo,largest_archive_booked=False,promise_ending_bytes=0,resource_credit_bytes=0)
    witness=dict(native=fast,retired_chronological_native=old,retirement=transition_ref,shared_slice=group,
                 ready_scope=scope_ref,controller_file=bound(READY/'ready-controller.py'))
    return audit,storage,witness

def observe_public(dev, obligation):
    import audit_handoff
    from public_witness import slice_envelope
    need(READY.stat().st_dev==dev,'ready audit filesystem changed')
    return measure(obligation,audit_handoff.native,slice_envelope)
