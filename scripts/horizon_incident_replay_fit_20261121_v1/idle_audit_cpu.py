"""Verify the paid four-CPU audit ceiling or its exact top-level idle-only extension."""
import json
import os
from pathlib import Path
import stat

GROUP=Path('/sys/fs/cgroup/horizonaudit.slice')
ASSIGNMENT=Path('/var/lib/jetstreamer/horizon_runtime_data/public-stream-observer-continuity-20261120-v1/SHARED_CPU_ASSIGNMENT.json')
POLICY=dict(schema='public-ready-idle-cpu-assignment-v1',slice='horizonaudit.slice',previous_cpu_quota='4s',
            cpu_quota='12s',paid_cpu_quota_micros=4_000_000,additional_memory_bytes=0,
            required_cpu_idle=1,shared_memory_high_bytes=20<<30,shared_memory_max_bytes=24<<30,
            shared_swap_max_bytes=0,shared_tasks_max=512)

def read_assignment(path):
    if not path.exists(): return None
    with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb') as stream:
        info=os.fstat(stream.fileno())
        if not (stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_uid==0
                and info.st_mode&0o022==0 and info.st_size<=8192 and path.resolve()==path):
            raise ValueError('untrusted public CPU assignment')
        return json.loads(stream.read(8193))

def profile(group=GROUP,assignment=ASSIGNMENT):
    required={'memory.high':str(20<<30),'memory.max':str(24<<30),'memory.swap.max':'0','pids.max':'512'}
    if any((group/name).read_text().strip()!=v for name,v in required.items()):
        raise ValueError('changed audit memory, swap or task ceiling')
    quota=(group/'cpu.max').read_text().split();idle=(group/'cpu.idle').read_text().strip()
    if quota==['400000','100000'] and idle in ('0','1'):
        return 'paid-four'
    if quota==['1200000','100000'] and idle=='1' and read_assignment(assignment)==POLICY:
        return 'idle-twelve'
    raise ValueError('unexpected public audit CPU entitlement')


# This was a single use of the chronological owner, charged in addition to the
# permanent census/build phases. Its original IID can never be recreated.
RUNTIME = Path('/var/lib/jetstreamer/horizon_runtime_data')
HANDOFF = RUNTIME / 'r2-audit-storage-20261119-v1/epoch79-clean-handoff-v1/proof.json'
HANDOFF_SHA = '3607504df7749884023d51c90026babd2fad9dec23f48af38b68ea72b8130c78'
RETIREMENT = RUNTIME / 'prefix140-status-cadence-20261122-v1/cadence-tools/CHRONOLOGICAL_RETIREMENT.json'
RETIREMENT_SHA = '9f88aa22cefd4bc7b239cb6d386c5b9fca36cb5316c56da75ef590edb317cef9'
LEGACY = 'horizon-r2-chronological-plugin-audit-20261118-v1.service'
SWITCH = 'horizon-audit79-after84-cleanup-20261120-v1'
ONCE_MEMORY = 128 << 20
ONCE_CPU = 250_000

def switch_units():
    import subprocess
    fields = 'Id,LoadState,ActiveState,SubState,InvocationID,Job,MainPID,ControlPID,ControlGroup,Triggers,TriggeredBy,UnitFileState,NRestarts,Restart'
    args = ['/usr/bin/systemctl', 'show', '--property='+fields, LEGACY, SWITCH+'.service', SWITCH+'.path']
    result = subprocess.run(args, check=False, capture_output=True, text=True, timeout=10)
    # Some kernels unload a closed transient unit. systemctl then returns 4.
    if result.returncode not in (0, 4):
        raise ValueError('cannot inspect chronological handoff units')
    rows = [dict(line.split('=',1) for line in entry.splitlines()) for entry in result.stdout.strip().split('\n\n')]
    if {row['Id'] for row in rows} != {LEGACY, SWITCH+'.service', SWITCH+'.path'}:
        raise ValueError('incomplete handoff unit inspection')
    return {row['Id']: row for row in rows}

def next_admission_basis(price, fleet, ledger, read, units=switch_units):
    """Price a new admission after the exact old handoff has permanently ended."""
    def need(condition, message):
        if not condition:
            raise ValueError(message)
    need(price['schema']=='horizon-incident-replay-fit-v1' and price['replay_launch_authorized'] is False and
         price['complete_memory_plus_reserve_bytes']==810658050048 and price['complete_cpu_quota_micros']==64_000_000
         and price['resource_credit_bytes']==0, 'different historical host price')
    need(fleet['schema']=='horizon-Root-complete-fleet-operational-review-v1' and fleet['owner']=='/root',
         'unexpected fleet authority')
    historical=fleet['continuing_audit_obligation']['current_storage']
    ready=fleet['active_ready_range_audit_obligation']
    ready_storage=ready['current_storage']
    retired=ready['chronological_retirement']
    need(retired==dict(path=str(RETIREMENT),sha256=RETIREMENT_SHA) and historical['retired'] is True and
         historical['pricing_basis_only'] is True and historical['included_in_current_aggregate'] is False and
         historical['remaining_DATA_growth_bytes']==18<<30, 'chronological retirement is unproven')
    closure,_=read(RETIREMENT,RETIREMENT_SHA)
    target=fleet['current_home_cycle_capacity']
    need(Path(target['path'])==Path(price['fleet']['path']).with_name('HOME_CAPACITY.json'), 'foreign HOME cycle')
    home,actual=read(Path(target['path']),target['sha256'])
    need(target==actual and ready['current_observation']==fleet['current_audit_progress']['observation'] and
         home['audit_storage']==ready_storage and ready_storage['maximum_host_allocation_bytes']==256<<20 and
         0<=ready_storage['remaining_DATA_growth_bytes']<=256<<20 and ready['archive_staging_bytes']==0 and
         ready_storage['remaining_archive_growth_bytes']==ready_storage['remaining_cargo_growth_allowance_bytes']==0,
         'unbound public audit allocation')
    need(closure['schema']=='horizon-chronological-retirement-to-ready-range-v1' and closure['legacy_unit']==LEGACY
         and closure['legacy']['ActiveState']=='inactive' and closure['legacy']['UnitFileState']=='disabled',
         'wrong retired chronological owner')
    aux=ledger['native_inputs']['auxiliary']
    proof_ref=aux['phase_admissions']['AUDIT79_HANDOFF']
    need(proof_ref==dict(path=str(HANDOFF),sha256=HANDOFF_SHA) and aux['memory_bytes']==(6<<30)+ONCE_MEMORY
         and aux['cpu_quota_micros']==3_000_000+ONCE_CPU, 'handoff missing from the historical price')
    proof,_=read(HANDOFF,HANDOFF_SHA)
    need(proof['applies_to']=='one transient clean-boundary handoff while original replay and audit reservations remain intact'
         and proof['handoff_memory']==ONCE_MEMORY and proof['handoff_cpu_quota']=='25%'
         and proof['combined_peak']==price['complete_memory_plus_reserve_bytes']==proof['prior_peak']+ONCE_MEMORY,
         'different one-time charge')
    observed=units()
    legacy=observed[LEGACY]
    need(legacy['InvocationID']==closure['legacy']['InvocationID'] and legacy['ActiveState']=='inactive' and
         legacy['SubState']=='dead' and legacy['UnitFileState']=='disabled', 'chronological service changed')
    svc,trig=observed[SWITCH+'.service'],observed[SWITCH+'.path']
    for row in (legacy,svc,trig):
        need(row['ActiveState'] in ('failed','inactive') and not row['Job'] and not row.get('ControlGroup') and
             row.get('MainPID','0')==row.get('ControlPID','0')=='0', 'handoff owner or job exists')
    for row,iid in ((svc,'d98c0d34cae94fb6bcda3689c894cd72'),(trig,'3254f8b330fb4e828935955825d6ddea')):
        need((row['LoadState']=='not-found' and row['ActiveState']=='inactive') or
             (row['LoadState']=='loaded' and row['InvocationID']==iid and row['ActiveState']=='failed' and
              row['UnitFileState']=='transient'), 'changed switch invocation or trigger')
    if svc['LoadState']=='loaded':
        need(svc['NRestarts']=='0' and svc['Restart']=='no' and svc['TriggeredBy']==SWITCH+'.path',
             'switch acquired another route')
    if trig['LoadState']=='loaded':
        need(trig['Triggers']==SWITCH+'.service','switch trigger changed')
    for unit in (LEGACY, SWITCH+'.service'):
        for slice_name in ('system.slice','horizonaudit.slice'):
            need(not os.path.lexists(Path('/sys/fs/cgroup')/slice_name/unit), 'handoff cgroup still exists')
    need(units()==observed, 'handoff changed during inspection')
    return dict(schema='horizon-next-admission-after-chronological-handoff-v1',fleet=price['fleet'],
                original_handoff=proof_ref,chronological_retirement=retired,ready_capacity=actual,observed_units=observed,
                complete_required_HOME_bytes=price['complete_required_HOME_bytes'],
                historical_audit_HOME_bytes=historical['remaining_DATA_growth_bytes'],
                public_audit_remaining_HOME_bytes=ready_storage['remaining_DATA_growth_bytes'],
                complete_memory_plus_reserve_bytes=proof['prior_peak'],
                required_available_memory_bytes=price['required_available_memory_bytes']-ONCE_MEMORY,
                complete_cpu_quota_micros=price['complete_cpu_quota_micros']-ONCE_CPU,
                removed_handoff_memory_bytes=ONCE_MEMORY,removed_handoff_cpu_quota_micros=ONCE_CPU,
                removed_HOME_bytes=0,live_limits_changed=False,replay_launch_authorized=False,
                fits=price['available_HOME_bytes']>=price['complete_required_HOME_bytes'] and
                     price['available_memory_bytes']>=price['required_available_memory_bytes']-ONCE_MEMORY)
