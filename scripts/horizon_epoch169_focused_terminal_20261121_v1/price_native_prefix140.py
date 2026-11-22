"""Add the epoch 140 metadata commitment once to the current complete native paid floor."""
import datetime as dt
import json
from pathlib import Path
import os
import subprocess
import sys
import time

R=Path('/var/lib/jetstreamer/horizon_runtime_data')
D=R/'ready-idle-cpu-20261121-v1';sys.path.insert(0,str(D/'cadence-tools'))
from evidence import bound,checked,durable,need
from idle_audit_cpu import profile,GROUP
from public_witness import slice_envelope
from ready_audit_jobs import native_jobs

def read_mem():
    v=Path('/proc/meminfo').read_text().splitlines()
    return int(next(line for line in v if line.startswith('MemAvailable:')).split()[1])*1024
def free():
    t=os.statvfs('/home/sol');return t.f_frsize*t.f_bavail
def capacity(head_ref):
    fleet=checked(head_ref)
    need(fleet['owner']=='/root' and fleet['authenticated_status_count']==19,'incomplete fleet')
    need(0<=time.time()-fleet['recorded_unix_seconds']<2400,'fleet is no longer fresh')
    proof=checked(bound(D/'V17_FLOOR_ACTUAL_IDLE.json'));p=Path(proof['v17']['path'])
    need(bound(p)==proof['v17'] and profile()=='idle-twelve','registered live audit or V17 price changed')
    done=subprocess.run([p,'145',head_ref['path'],head_ref['sha256']],capture_output=True,timeout=150)
    need(done.returncode==0,'native full-host V17 price unavailable: '+done.stderr.decode()[-1500:])
    result=json.loads(done.stdout)
    need(result['fleet']==head_ref and result['fits'] and result['epoch']==145,'native V17 price belongs to a different fleet')
    need(result['complete_cpu_quota_micros']==64_000_000 and result['complete_memory_plus_reserve_bytes']==810_658_050_048,'unexpected historical paid host total')
    resources={k:(GROUP/k).read_text().strip() for k in ('cpu.max','cpu.idle','memory.high','memory.max','memory.swap.max','pids.max','memory.current','pids.current')}
    need(int(resources['memory.current'])+(1<<30)<int(resources['memory.high']) and int(resources['pids.current'])+16<=int(resources['pids.max']),'internal child cannot fit under present shared ceiling')
    current_free=min(free(),result['available_HOME_bytes']); current_ram=min(read_mem(),result['available_memory_bytes']); reserve=16<<20
    required=result['complete_required_HOME_bytes']+reserve;need(current_free>=required,'140 metadata would consume the genuine paid guards HOME floor')
    need(current_ram>=result['required_available_memory_bytes'],'native protected memory floor unavailable')
    cap=checked(fleet['current_home_cycle_capacity']);aud=checked(fleet['current_audit_progress']['observation']);existing=cap['audit_storage']
    need(existing['schema']=='ready-public-queue-home-growth-v1' and existing['maximum_host_allocation_bytes']==256<<20,'unexpected incumbent ready budget')
    need(fleet['complete_DATA_with_remaining_audit_growth_bytes']==fleet['complete_DATA_bytes']+existing['remaining_DATA_growth_bytes'],'ready HOME charge missing')
    key=Path(head_ref['path']).parent.name
    output=D/f'PREFIX140_NATIVE_PRICE_{key}.json';durable(output,result)
    row=dict(schema='horizon-independent-epoch140-prefix-analysis-fit-v1',head=head_ref,native_v17=proof['v17'],genuine_full_host_price=bound(output),kernel_and_shared=slice_envelope(),sampled_shared_resources=resources,native_ready_workers=native_jobs(aud['inventory']),
             epoch=140,specified_child=dict(parent='horizonaudit.slice',cpu_max='100000 100000',memory_max=1<<30,swap_max=0,tasks_max=16,maximum_seconds=86400),
             child_inside_paid_parent=True,extra_weighted_cpu_quota_micros=0,extra_host_memory_entitlement_bytes=0,extra_parent_tasks=0,archive_staging_bytes=0,
             separate_maximum_HOME_allocation_bytes=reserve,existing_ready_output_cap_bytes=256<<20,
             current_remaining_ready_HOME_growth_bytes=existing['remaining_DATA_growth_bytes'],new_complete_fleet_DATA_including_separate_140_cap_bytes=fleet['complete_DATA_with_remaining_audit_growth_bytes']+reserve,
             native_full_floor_before_140_bytes=result['complete_required_HOME_bytes'],required_HOME_including_140_cap_bytes=required,conservative_available_HOME_bytes=current_free,
             available_above_paid_floor_and_140_cap_bytes=current_free-required,native_memory_after_protected_floor_bytes=current_ram-result['required_available_memory_bytes'],
             accounting='full independent 16 MiB reserved until root supplied hard allocation proof and the job retires; no offset for already covered or deleted bytes',native_unit_launched=False,
             observed_utc=dt.datetime.now(dt.timezone.utc).isoformat())
    receipt=D/f'PREFIX140_FIT_{key}.json';durable(receipt,row);print(json.dumps(bound(receipt)))
if __name__=='__main__':capacity(dict(path=sys.argv[1],sha256=sys.argv[2]))
