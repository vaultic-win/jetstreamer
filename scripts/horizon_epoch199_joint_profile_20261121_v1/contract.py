"""Price the entire 199–200 lifecycle and produce PID1 dependencies for each phase."""
import hashlib
import json
from pathlib import Path

G=1<<30
B=Path('/var/lib/jetstreamer/horizon_runtime_data/epoch199-delivery-recovery-20261121-v1')
HISTORY=B/'joint-measure-08c90435c93a476f99acda7f19f6e4ed'
ROOT=Path('/home/sol/.jetstreamer-private/epoch199200-reconstruction-v1')
HOLD='horizon-qualify-199200-reservation-20261121-v1.service'
CTRL='horizon-199200-joint-cached-controller-20261121-v1.service'
PROD='jetstreamer-root-sweep-e199200-joint-measured-v1-e199-200-lane-a-1.service'
IMP='jetstreamer-root-import-e199200-joint-measured-v1-e199-200-2.service'
GUARD_SHA='b2271db6f25696612c388297db3a10852f7911560887f67dcb404392d91f7016'
FULL=448*G
TRIP=416*G
FIXED_SHA='440ef1cf341ea8032cb3d6b0447309a3b8ef20a2000359c0a783b8357488a653'
MEASURED_SHA='76c9579bf0ed66331e753833909fcd1da2dc36287845b962483e3a3af07160de'

def need(x, msg):
    if not x:
        raise ValueError(msg)

def bound(p,h):
    b=p.read_bytes()
    need(hashlib.sha256(b).hexdigest()==h, 'different '+str(p))
    return json.loads(b)

def measurements(measured):
    c=measured['comparisons']
    need([(r['range'],r['count']) for r in c]==[('191-194',271),('196',77),('197',76),('198',71),('199-200',84)],'incomplete observed population')
    need(c[0]['observed_epochs']==[191,192,193,194] and c[-1]['observed_epochs']==[199] and not measured['empirical_epoch_200'],'unfunded observed extension into 200')
    need(all(r['sha256']=='9339aa0ee5c39e91ec446bfa561c0e81280a0ddc474a03cf5bb0ce07a3674893' for r in measured['source_workers']) and len(measured['source_workers'])==3, 'different worker')
    est=measured['estimate']
    need(est['scheduler_reservation']==FULL and est['max_memory']==152*G and est['conservative_total']<TRIP and est['raw_memory_margin']>=20*G,'conservative sizing')

def measure_charge(credit=0):
    # Imports move inodes within the owned tree. Continue charging the whole promise
    # even after producer exit, sparse allocation, receipt commit, or archival copy.
    need(credit==0,'199–200 retains its whole reservation through final reconciliation')
    return FULL

def controls(phase):
    need(phase in {CTRL,PROD,IMP},'foreign phase')
    return ['--property=BindsTo='+HOLD,'--property=After='+HOLD,'--property=Requisite='+HOLD]

def monitor(owner_iid,available_floor,receipt_dir):
    import re
    need(isinstance(owner_iid,str) and re.fullmatch('[0-9a-f]{32}',owner_iid) and int(owner_iid,16)>0,'unbound guard owner')
    need(available_floor>0 and isinstance(receipt_dir,Path) and receipt_dir.is_absolute(),'missing capacity floor or receipt directory')
    return dict(schema='jetstreamer-horizon-standalone-guard-plan-v1',unit=HOLD,invocation_id=owner_iid,filesystem='/home/sol',minimum_free_bytes=available_floor+FULL-TRIP,worker_root=str(ROOT),maximum_worker_vmas=3500000,maximum_root_physical_bytes=TRIP,receipt_directory=str(receipt_dir))

def gate(receipt,guard_plan,plan_sha,owner_pid,now,cgroup):
    need(receipt['guard_sha256']==GUARD_SHA and receipt['plan_sha256']==plan_sha and receipt['producer_invocation_id']==guard_plan['invocation_id'] and receipt['producer']['pid']==owner_pid and owner_pid>1 and receipt['producer']['active']=='active' and receipt['producer']['cgroup']==cgroup and cgroup.endswith('/'+HOLD) and receipt['producer']['restarts']==0, 'stale active guard generation')
    need(receipt['maximum_root_physical_bytes']==guard_plan['maximum_root_physical_bytes']==TRIP and receipt['minimum_free_bytes']==guard_plan['minimum_free_bytes'] and receipt['available_bytes']>=receipt['minimum_free_bytes'] and receipt['trip_reason'] is None and receipt['root_physical_observation_error'] is None and receipt['producer_stop_enabled'] is True and receipt['root_physical_observation']['exceeds_budget'] is False and 0<=now-receipt['recorded_unix_seconds']<=45,'nonprotecting or expired guard')

def price(fit,raw_ram,online_cpus,credit=0):
    need(fit['fits'] and fit['resource_credit_bytes']==fit['stopped_generation_resident_credit_bytes']==0,'stale fit or unproven capacity credit')
    return dict(disk=max(0,fit['complete_required_HOME_bytes']+measure_charge(credit)-fit['available_HOME_bytes']),committed_memory=max(0,fit['complete_memory_plus_reserve_bytes']+153*G-raw_ram),available_memory=max(0,fit['required_available_memory_bytes']+153*G-fit['available_memory_bytes']),cpu_quota_micros=max(0,fit['complete_cpu_quota_micros']+8000000-online_cpus*1000000))

def check_sources():
    profile=bound(HISTORY/'PROFILE.json',FIXED_SHA)
    measured=bound(HISTORY/'MEASURED.json',MEASURED_SHA)
    measurements(measured)
    need(profile['whole_tree']==str(ROOT) and profile['candidate_disk']==FULL and not profile['current_replay_admission'],'incorrect original projection')
    for child in (ROOT/'lane-a',ROOT/'public',ROOT/'public-private'):
        need(child.resolve(strict=True)==child and child.stat().st_dev==ROOT.stat().st_dev,'changed charged roots')
    return profile,measured

def controller_options(fit):
    """Validate prospective CLI options with the sealed controller's normal parser."""
    import sys
    src=B/'controller-v1'
    code=src/'adaptive_root_cohort_sweep.py'
    need(hashlib.sha256(code.read_bytes()).hexdigest()=='70996cce1ce991a3086ca462400650e6cb414090dbacd132c56ad84e4ef2e404','different controller')
    sys.path.insert(0,str(src))
    import adaptive_root_cohort_sweep as ordinary
    profile,_=check_sources()
    authority=bound(B/'RETAINED_INPUT_AUTHORITY.json',profile['authority']['sha256'])
    q=bound(Path(authority['controller_projection']['path']),authority['controller_projection']['sha256'])
    positive_gib=lambda n:(n+G-1)//G
    # Existing foreign claims stay inside the full native floors. The ordinary
    # controller may further reserve disk for live foreign producers at launch.
    live=fit['required_available_memory_bytes']+G
    hard=fit['complete_memory_plus_reserve_bytes']+G
    argv=['--deploy-dir='+str(q['deployment']),'--manifest='+q['manifest']['path'],'--manifest-fingerprint='+q['fingerprint'],
          '--public-dir='+str(ROOT/'public'),'--public-private-root='+str(ROOT/'public-private'),'--state-dir='+str(B/'controller-state-v1'),
          '--lane=lane-a='+str(ROOT/'lane-a'),'--first-epoch=199','--last-epoch=200','--initial-concurrency=1','--target-concurrency=1','--max-concurrency=1',
          '--memory-high-gib=128','--memory-max-gib=152','--memory-admission-gib=152','--disk-budget-per-worker-gib=448',
          '--memory-reserve-gib='+str(positive_gib(live)),'--protected-memory-gib='+str(positive_gib(hard-live)),
          '--disk-reserve-gib='+str(positive_gib(fit['complete_required_HOME_bytes'])),
          '--cpus-per-lane=8','--cpu-quota-percent=800','--solana-rayon-threads=8','--epoch199200-qualified-index',
          '--cohort-bootstrap=199-200='+authority['retained_bootstrap']['path'],'--controller-id=e199200-joint-measured-v1','--controller-sha256='+q['controller_source']]
    parsed=ordinary.build_argument_parser().parse_args(argv)
    ordinary.validate_options(parsed)
    need(parsed.disk_budget_per_worker_gib==448 and parsed.memory_max_gib==parsed.memory_admission_gib==152 and parsed.epoch199200_index and not parsed.execute and dict(parsed.cohort_bootstrap)[(199,200)]==Path(authority['retained_bootstrap']['path']), 'controller CLI lost profile')
    return ['/usr/bin/python3','-IB',str(code),*argv]

def service_dropins():
    # systemd applies prefix drop-ins to all sequence numbers, including source
    # recovery. Bind the cadence controller too so it cannot schedule a new phase
    # after a trip. No drop-in or unit is installed by this projection.
    cfg='[Unit]\nBindsTo='+HOLD+'\nAfter='+HOLD+'\nRequisite='+HOLD+'\n'
    result={k:cfg+'[Service]\nSlice=horizon199200.slice\n' for k in ('jetstreamer-root-sweep-e199200-joint-measured-v1-.service.d',
        'jetstreamer-root-source-recovery-e199200-joint-measured-v1-.service.d','jetstreamer-root-import-e199200-joint-measured-v1-.service.d')}
    result[CTRL+'.d']=cfg+'[Service]\nSlice=horizon199200-aux.slice\nMemoryMax=512M\nMemorySwapMax=0\n'
    return result

def slices():
    return {'horizon199200.slice':'[Unit]\nDescription=Historical epochs 199 and 200 resources\n[Slice]\nCPUQuota=800%\nMemoryMax=153G\nMemorySwapMax=0\n',
            'horizon199200-aux.slice':'[Unit]\nDescription=Epoch 199 and 200 controller and guard resources\n[Slice]\nMemoryMax=1G\nMemorySwapMax=0\n'}
