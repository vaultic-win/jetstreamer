"""Render real controller commands and exercise its admission arithmetic at this fleet."""
import hashlib
import json
import os
import runpy
import subprocess
import sys
from datetime import datetime,timezone
from pathlib import Path

HERE=Path(__file__).resolve().parent
m=runpy.run_path(str(HERE/'measured.py'))
B=m['B'];G=m['G'];check=m['check'];take=m['take'];load=m['load'];save=m['save']
D=B.parent/'incident-replay-fit-20261121-v1/tools-v9'
CTRL=B/'controller-v1'
ROOT=Path('/home/sol/.jetstreamer-private/epoch199200-reconstruction-v1')
HOLD='horizon-qualify-199200-reservation-20261121-v1.service'
GUARD=B.parent/'epoch170-retry9-recovery-20261120-v1/guard-v1/guard'
GUARD_SHA='b2271db6f25696612c388297db3a10852f7911560887f67dcb404392d91f7016'
CANDIDATE='e199200-joint-measured-v1'

def render(fit,measured,out):
    take(CTRL/'deployment-seal-receipt.json','259063b2eb900876bfb98b23b8e534ba6ad8a7b67fe4c0339ba6b979c6bf3d07')
    ctrl_ref=take(CTRL/'adaptive_root_cohort_sweep.py','70996cce1ce991a3086ca462400650e6cb414090dbacd132c56ad84e4ef2e404')[1]
    sys.path.insert(0,str(CTRL))
    import adaptive_root_cohort_sweep as s
    authority,authref=load(B/'RETAINED_INPUT_AUTHORITY.json')
    b=authority['retained_bootstrap'];boot=Path(b['path'])
    proj,pref=load(authority['controller_projection']['path'],authority['controller_projection']['sha256'])
    check(proj['worker']['sha256']==m['WORKER_SHA'] and proj['controller_source']==ctrl_ref['sha256'],'binary/source mismatch')
    take(proj['manifest']['path'],proj['manifest']['sha256'])
    dep=Path(proj['deployment']);manifest=Path(proj['manifest']['path']);fp=proj['fingerprint']
    lane=s.Lane('lane-a',ROOT/'lane-a')
    pubs=[ROOT/'public',ROOT/'public-private']
    check(all(p==p.resolve(strict=True) and p.stat().st_dev==ROOT.stat().st_dev and p.is_relative_to(ROOT) for p in (lane.root,*pubs)), 'incomplete allocation root')
    cap=measured['estimate']['scheduler_reservation'];mem=measured['estimate']['max_memory'];maxg=mem//G
    cohort,=s.load_cohorts(manifest,fp,199,200)
    s.verify_epoch199200_plan([cohort],pubs[0])
    data=dict(cohort=cohort,deploy=dep,manifest=manifest,fingerprint=fp,memory_high_gib=128,memory_max_gib=maxg,cpu_quota_percent=800)
    prod=s.build_producer_command(**data,lane=lane,unit=f'jetstreamer-root-sweep-{CANDIDATE}-e199-200-lane-a-1.service',solana_rayon_threads=8,cohort_bootstrap=boot,epoch199200_index=True)
    imp=s.build_import_command(**data,receipt=lane.private/'PENDING-AUTHENTICATED-BATCH.json',public_dir=pubs[0],public_private_root=pubs[1],unit=f'jetstreamer-root-import-{CANDIDATE}-e199-200-2.service',publish_through_epoch=200)
    check('--publish-through-epoch=200' in imp and str(boot) in ' '.join(prod) and str(s.EPOCH199200_INDEX_SOURCE) in ' '.join(prod),'lost source or boundary')
    for cmd in (prod,imp):
        for k in ['MemoryHigh='+str(128*G),'MemoryMax='+str(mem),'MemorySwapMax=0','CPUQuota=800%']:
            check(any(x.endswith(k) for x in cmd),'lost worker property '+k)
    for p in (ROOT,*pubs,lane.root):
        check(ROOT.stat().st_dev==p.stat().st_dev,'different stage device')
    for name in ('complete_cpu_quota_micros','complete_memory_plus_reserve_bytes','complete_required_HOME_bytes'):
        check(fit[name]>0,'missing existing commitment')
    cpu=os.sysconf('SC_NPROCESSORS_ONLN')
    memory=int(Path('/proc/meminfo').read_text().splitlines()[0].split()[1])*1024
    required=fit['complete_required_HOME_bytes']
    args=dict(memory_total=memory,memory_available=fit['available_memory_bytes'],logical_cpus=cpu,active=0,owned_active=0,external_active=0,external_disk_growth_claim=0,elapsed_seconds=300,lane_count=1,initial=1,target=1,maximum=1,settle_seconds=300,memory_max=mem,memory_admission=mem,memory_reserve=fit['required_available_memory_bytes']+G,protected_memory=0,cpus_per_lane=8,memory_current=[],memory_peak=[],memory_high=128*G,disk_available=fit['available_HOME_bytes'],disk_reserve=required,disk_budget_per_worker=cap)
    result=s.admission_capacity(**args)
    # Second fixture validates the same routine at fit and a one-byte shortfall.
    fixture=dict(args,memory_reserve=0,memory_available=mem,memory_total=mem,disk_reserve=0,disk_available=cap)
    check(s.admission_capacity(**fixture)==1 and s.admission_capacity(**dict(fixture,disk_available=cap-1))==0 and s.admission_capacity(**dict(fixture,memory_available=mem-1))==0,'controller failed exact boundary')
    gaps=dict(disk=max(0,required+cap-fit['available_HOME_bytes']),committed_memory=max(0,fit['complete_memory_plus_reserve_bytes']+mem+G-memory),available_memory=max(0,fit['required_available_memory_bytes']+mem+G-fit['available_memory_bytes']),cpu=max(0,fit['complete_cpu_quota_micros']+8000000-cpu*1000000))
    ok=result>0 and not any(gaps.values())
    check(not ok and result==0,'expected complete current estate to refuse')
    guard=dict(schema='jetstreamer-horizon-standalone-guard-plan-v1',unit=HOLD,invocation_id='1'*32,filesystem='/home/sol',minimum_free_bytes=required,worker_root=str(ROOT),maximum_worker_vmas=3500000,maximum_root_physical_bytes=cap,receipt_directory=str(out))
    plan=out/'GUARD_STATIC_PROJECTION.json';save(plan,guard)
    take(GUARD,GUARD_SHA)
    static=json.loads(subprocess.check_output([GUARD,plan,'--plan-sha256',take(plan)[1]['sha256'],'--self-sha256',GUARD_SHA,'--validate-plan-only']))
    check(static['validated'] and not static['producer_signaled'] and not static['protective_guard_proven'],'static guard')
    return dict(current_replay_admission=ok,ordinary_controller_capacity=result,ordinary_native_capacity_args=args,full_fleet_gaps=gaps,candidate_disk=cap,candidate_worker_memory=mem,candidate_aux_memory=G,old_disk=768*G,old_worker_memory=192*G,hard_RAM_saving=40*G,disk_reservation_reduction=320*G,CPU=8,memory_high=128*G,memory_swap=0,whole_tree=str(ROOT),required_current_free_floor=required,guard_static_validation=static,producer_argv=prod,import_argv_projection=imp,price_timestamp=datetime.now(timezone.utc).isoformat(),authority=authref,projection=pref,controller=ctrl_ref,no_source_credit=0)

def main():
    fleet,digest,seal=sys.argv[1:]
    take(D/'deployment-seal-receipt.json',seal)
    out=B/('joint-measure-'+os.environ['INVOCATION_ID']);out.mkdir(mode=0o700)
    fit=json.loads(subprocess.check_output([D/'post-stop-fit','145',fleet,digest],timeout=65))
    check(fit['fits'] and fit['fleet']=={'path':fleet,'sha256':digest} and fit['phase145']['resource_credit_bytes']==0 and fit['complete_memory_plus_reserve_bytes']==810658050048 and fit['complete_cpu_quota_micros']==64000000 and fit['available_memory_bytes']-fit['required_available_memory_bytes']>=512<<20 and fit['available_HOME_bytes']-fit['complete_required_HOME_bytes']>=55<<20,'native fit failed')
    save(out/'FIT.json',fit)
    measured=m['collect']()
    save(out/'MEASURED.json',measured)
    result=render(fit,measured,out)
    save(out/'PROFILE.json',result)
    print(json.dumps({'evidence':str(out),'profile':take(out/'PROFILE.json')[1], 'gap':result['full_fleet_gaps'],'estimate':measured['estimate']}))

if __name__=='__main__':
    main()
