#!/usr/bin/env python3
"""Root-only SOURCE template. Materializes immutable plans/argv, never launches.
Not executed or qualified by the source helper. No archive/executable body reads.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat

GIB = 1 << 30
DATA_FLOOR = 5114649588372
MEM_FLOOR = 790890381312
ACTOR = 'horizon-epoch163-native-input-20261106-v1.service'
ISSUER = 'horizon-epoch163-native-input-admission-20261107-v1.service'
TOOLS = '/usr/local/lib/jetstreamer/horizon-epoch163-native-input-tools-20261106-v7'
NATIVE_SHA = '9e9de6bdcb149d08d17cc53ce4322577e4a1aab164a1ac848b04ae8426205850'
FINAL_SHA = '58d4308877caac1be4178d4deedc954d4350b3ca177b0c8877d4409c85a981ff'
WORKER_SHA = 'cf5fa883df75b23de82af52dc0e90c013f8e83397b445027e510a1137decc819'
GENESIS_SHA = '133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945'
PRIMARY = '01a1af2a-9ce8-76a2-8939-b2112bd38f53'
R24 = {'path':'/home/sol/.jetstreamer-private/epoch163-native-input-qa-20261106-v7/RESOURCE_PHASES_R24_NATIVE163_QA_DATA_BOOKED.json','sha256':'0d95b4cfe5cde644d3b9105c32116598a8a7a449c14b9003f48e380bf6ad96da'}
TAKEOVER = {'path':'/home/sol/.jetstreamer-private/epoch163-first-output128-admission-source-20261106-v1/ROOT_USER_ORDERED_VISIBLE_THREAD_TAKEOVER_20261107.json','sha256':'9b895fd8e137c30ba7a6d94432639c2e7e114140bb2cde5700f32e08987ab61f'}
# Exact helper-v13 current_phase_scope retained145 object; DATA is not RAM.
RETAINED145 = {'exporter_memory_bytes':80*GIB,'guard_memory_bytes':256<<20,
 'exporter_DATA_bytes':160*GIB+(128<<20),'source_DATA_bytes':4*GIB,'exporter_cpu_quota_micros':8000000,
 'guard_cpu_quota_micros':1000000,'failed_exporter_does_not_release_promises':True,
 'memory_in_existing_total':True}


def require(ok, reason):
    if not ok:
        raise SystemExit(reason)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON key: '+key)
        result[key] = value
    return result


def bound(path, sha):
    path = str(path)
    require(Path(path).is_absolute() and not any(c.isspace() for c in path), 'absolute whitespace-free bound path')
    require(re.fullmatch('[0-9a-f]{64}', sha) is not None, 'actual lower SHA256 required')
    return {'path':path,'sha256':sha}


def metadata(b, immutable=True):
    b = bound(b['path'], b['sha256'])
    p = Path(b['path'])
    require(p.suffix == '.json', 'only explicit JSON metadata is opened by preparer: '+str(p))
    require(p.resolve(strict=True) == p, 'canonical metadata path required')
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(p, flags)
    try:
        m = os.fstat(fd)
        require(stat.S_ISREG(m.st_mode) and m.st_uid == 0 and m.st_nlink == 1 and m.st_size <= 32<<20, 'Root singleton bounded metadata')
        require(not (m.st_mode & (0o222 if immutable else 0o022)), 'metadata custody/mode')
        raw = bytearray()
        while len(raw) <= m.st_size:
            chunk = os.read(fd, min(65536, m.st_size + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        identity = lambda x: (x.st_dev,x.st_ino,x.st_mode,x.st_nlink,x.st_uid,x.st_gid,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
        require(len(raw) == m.st_size and identity(os.fstat(fd)) == identity(m) and identity(os.lstat(p)) == identity(m), 'metadata changed')
    finally:
        os.close(fd)
    require(hashlib.sha256(raw).hexdigest() == b['sha256'], 'actual metadata digest mismatch')
    return json.loads(raw, object_pairs_hook=unique)


def save(parent, name, value, published_parent=None):
    p = parent/name
    raw = (json.dumps(value, indent=2, sort_keys=True)+'\n').encode()
    fd = os.open(p, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC, 0o400)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())
    finally:
        directory = os.open(parent, os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    return bound((published_parent/name) if published_parent is not None else p, hashlib.sha256(raw).hexdigest())


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('config')
    args=parser.parse_args()
    require(os.geteuid() == 0, 'Root is sole operator')
    c=json.loads(Path(args.config).read_bytes(), object_pairs_hook=unique)
    require(c['schema']=='native128-root-template-config-v2-original-reader-before', 'configuration schema')
    required=['previous_phase_ledger','extra_QA6_closure','issuer_program','worker_image_path',
        'memory_receipt','memory_completion','data_receipt','data_completion','data_policy',
        'data_policy_seal','resource_accounting_spec','expected_current','expected_memory_program','expected_DATA_program']
    missing=[k for k in required if c.get(k) is None]
    require(not missing, 'unresolved actual bindings: '+', '.join(missing))
    issuer=bound(c['issuer_program']['path'],c['issuer_program']['sha256'])
    require(Path(issuer['path']).parent.parent == Path('/usr/local/lib/jetstreamer'), 'normal sealed issuer destination')
    previous=metadata(c['previous_phase_ledger'],immutable=False)
    closure=metadata(c['extra_QA6_closure'])
    require(closure['schema']=='native163-full-reader-extra-QA6-closure-v1'
        and closure['extra_QA_memory_bytes']==6*GIB and closure['released_bytes']==6*GIB
        and closure['normal_pool_released_bytes']==0
        and closure['all_original_QA_actors_terminal_and_drained'] is True
        and closure['all_required_qualification_actors_terminal_successful_and_drained'] is True
        and closure['source_and_DATA_promises_retained'] is True, 'actual extraQA6 authoritative closure required')
    m=metadata(c['memory_receipt']); d=metadata(c['data_receipt'])
    require(m.get('schema')=='terminal199-parent-memory-selector-original-execution-v1'
        and m.get('capability_only') is False and m.get('program')==c['expected_memory_program'],
        'actual qualified memory4 original selector required')
    require(d.get('schema')=='epoch183-native-ended-DATA-selector-original-execution-v1'
        and d.get('program')==c['expected_DATA_program'], 'actual qualified DATA4 original selector required')
    for receipt,key,kind in [(m,'memory_completion','memory'),(d,'data_completion','DATA')]:
        completion=metadata(c[key]); receipt_binding=c['memory_receipt' if kind=='memory' else 'data_receipt']
        require(completion['receipt']==receipt_binding and completion['invocation_id']==receipt['invocation_id']
            and completion['result']=='success' and completion['exec_main_status']==0
            and completion['original_outer_reaped'] is True and completion['original_cgroup_empty'] is True
            and completion['original_descriptors_drained'] is True, 'original '+kind+' selection/drain required')
    request=m['selection']['request']
    current=request['current']
    require(current==c['expected_current'], 'actual selectors crossed explicitly configured current tuple')
    original_reader=bound(request['current_reader']['path'],request['current_reader']['sha256'])
    require(d['memory_selection']==c['memory_receipt'], 'crossed memory/DATA selection')
    raw_sources=metadata(c['resource_accounting_spec'])
    require(all(raw_sources[k]==current[k] for k in ['observer','fleet','fleet_plan'])
        and raw_sources['phase_events'][1]['source']==current['frame'], 'fresh full current tuple crossed')
    require(raw_sources['live145_prefix_export']['terminal_retained'] is True,
        'failed145 must use explicit terminal_retained selector; no refund or guard renewal')
    reader=metadata(original_reader)
    require(reader.get('schema')=='failed4-current-complete-accounting-reader-proof-v1'
        and reader.get('raw_history_preserved') is True
        and reader.get('all_DATA_promises_preserved') is True
        and reader.get('terminal_legacy_minimum_already_applied_once') is True
        and reader.get('memory_budget_credit_applied_bytes')==0
        and reader.get('DATA_credit_bytes')==0
        and reader.get('physical_credit_bytes')==0
        and reader.get('replay_launch_authorized') is False, 'genuine original successful before reader scope required')
    accounting=metadata(reader['accounting'])
    minimum_existing=m['selection']['effective_total_memory_promises_bytes']
    data_floor=max(DATA_FLOOR,c['protected_existing_DATA_bytes'],
        d['data_selection']['projection']['proposed_protected_existing_DATA_bytes'],
        accounting['inherited_live_guard_maximum_bytes'])
    memory_floor=max(MEM_FLOOR,c['minimum_available_memory_bytes'])
    require(minimum_existing >= (80*GIB)+(256<<20), 'actual complete typed existing memory total required')
    require(60<=c['maximum_runtime_seconds']<=7200, 'finite native restore deadline')
    # Root must already have prepared ledger/genesis, scratch host leaf and state.
    for name in ['ledger_directory','scratch_directory','state_directory']:
        p=Path(c[name]); s=p.lstat()
        require(p.is_absolute() and p.resolve()==p and stat.S_ISDIR(s.st_mode)
            and s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o700, 'Root0700 prepared directory: '+name)
    out=Path(c['output_directory'])
    require(out.parent==Path('/usr/local/lib/jetstreamer') and not out.exists(), 'fresh normal-seal destination required')
    stage=Path(c['staging_directory'])
    require(stage.is_absolute() and str(stage).startswith('/home/sol/.jetstreamer-private/'), 'private source staging required')
    stage.mkdir(mode=0o700, exist_ok=False)
    def write(name,value):
        return save(stage,name,value,published_parent=out)
    phase={'schema':'horizon-native163-current-fixed128-phase-v1','previous_phase_ledger':c['previous_phase_ledger'],
        'legacy_phase_anchor':R24,'visible_thread_takeover':TAKEOVER,'exclusive_operational_owner':PRIMARY,
        'current_DATA_booking':c['current_DATA_booking'],'normal_external_pool_bytes':6*GIB,
        'extra_full_reader_QA_memory_bytes':0,'additional_QA_memory_bytes_retained_until_authoritative_closure':0,
        'extra_QA6_closure':c['extra_QA6_closure'],'protected_existing_DATA_bytes':data_floor,
        'complete_conservative_raw_DATA_booking_bytes':data_floor,
        'minimum_available_memory_bytes':memory_floor,'minimum_existing_memory_bytes':minimum_existing,
        'retained145':RETAINED145,'all_original_memory_DATA_and_raw_producer_promises_retained':True,
        'no_release_or_idle_credit':True}
    phase_b=write('current-phase.json',phase)
    state=Path(c['state_directory']); ledger=Path(c['ledger_directory']); scratch=Path(c['scratch_directory'])
    plan={'schema':'epoch163-native-input-plan-v3','program':bound(TOOLS+'/native-input',NATIVE_SHA),
        'worker':bound(c['worker_image_path'],WORKER_SHA),'genesis':bound(ledger/'genesis.tar.bz2',GENESIS_SHA),
        'download':c['download_receipt'],'admission_program':issuer,'admission':str(state/'admission.json'),
        'snapshot':c['snapshot'],'ledger':str(ledger),'scratch':str(scratch),'protected_filesystem':'/home/sol',
        'state':str(state),'minimum_free_bytes':data_floor+40*GIB,
        'minimum_available_memory_bytes':memory_floor,'maximum_runtime_seconds':c['maximum_runtime_seconds']}
    plan_b=write('native-plan.json',plan)
    booking={'schema':'epoch163-native-restore-fixed128-phase-booking-v2','native_plan':plan_b,
        'previous_phase_ledger':phase_b,'legacy_phase_anchor':R24,'visible_thread_takeover':TAKEOVER,
        'primary_thread_id':PRIMARY,'actor_unit':ACTOR,'issuer_unit':ISSUER,'actor_memory_bytes':128*GIB,
        'issuer_memory_within_normal_pool_bytes':2*GIB,'normal_pool_bytes':6*GIB,
        'candidate_incremental_DATA_bytes':40*GIB,'protected_existing_DATA_bytes':data_floor,
        'minimum_available_memory_bytes':memory_floor,'minimum_existing_memory_bytes':minimum_existing,
        'retained145':RETAINED145,'extra_full_reader_QA_memory_bytes':0,
        'all_original_memory_and_DATA_promises_retained':True,'no_release_or_idle_credit':True,
        'native_restore_only':True,'replay_launch_authorized':False,'publication_authorized':False,
        'remote_mutations':False,'r2_mutations':False}
    booking_b=write('native-booking.json',booking)
    spec={'schema':'epoch163-native-restore-issuer-spec-v1','native_plan':plan_b,'native_booking':booking_b,
        'current_phase_ledger':phase_b,'memory_request':request,'resource_accounting':raw_sources,
        'download_plan':c['download_plan'],'download_unit':'horizon-visible-bootstrap163-download-20261107-v1.service',
        'current_reader_before':original_reader}
    for key in ['memory_receipt','memory_completion','data_receipt','data_completion','data_policy','data_policy_seal']:
        spec[key]=c[key]
    spec_b=write('issuer-spec.json',spec)
    actor_argv=[TOOLS+'/native-input',plan_b['path'],'--plan-sha256',plan_b['sha256'],'--self-sha256',NATIVE_SHA]
    issuer_argv=[issuer['path'],'admit-native163',spec_b['path'],'--spec-sha256',spec_b['sha256'],'--self-sha256',issuer['sha256']]
    common=['Type=exec','User=root','Group=root','Restart=no','KillMode=control-group','MemoryAccounting=yes',
        'MemorySwapMax=0','TasksMax=512','NoNewPrivileges=yes','PrivateNetwork=yes','PrivateTmp=no',
        'ProtectSystem=strict','ProtectHome=read-only','CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_KILL CAP_SYS_PTRACE',
        'AmbientCapabilities=','RestrictSUIDSGID=yes','LockPersonality=yes','UMask=0077',
        'TimeoutStopSec=30s','SendSIGKILL=yes']
    actor_properties=common+['MemoryMax=128G','CPUQuota=800%','RemainAfterExit=yes',
        'RuntimeMaxSec='+str(c['maximum_runtime_seconds']+120)+'s',
        'BindReadOnlyPaths='+c['snapshot']+' '+str(ledger),
        'ReadWritePaths='+str(state),
        'TemporaryFileSystem=/tmp:ro /var/tmp:ro '+str(scratch)+':rw,nosuid,nodev,exec,size=40G,nr_inodes=131072,mode=0700']
    issuer_properties=common+['MemoryMax=2G','CPUQuota=100%','RemainAfterExit=yes','RuntimeMaxSec=95s',
        'ReadWritePaths='+str(state),'TemporaryFileSystem=/tmp:ro /var/tmp:ro']
    def service_argv(unit, props, argv, environment=()):
        return ['/usr/bin/systemd-run','--unit='+unit,'--quiet']+['--property='+p for p in props]+['--setenv='+e for e in environment]+argv
    write('actor-argv.json',{'unit':ACTOR,'argv':service_argv(ACTOR,actor_properties,actor_argv,
        ['TMPDIR='+str(scratch),'TMP='+str(scratch),'TEMP='+str(scratch)]),'direct_ExecStart_argv':actor_argv})
    write('issuer-argv.json',{'unit':ISSUER,'argv':service_argv(ISSUER,issuer_properties,issuer_argv),
        'direct_ExecStart_argv':issuer_argv})
    write('prepared-bindings.json',{'current_phase':phase_b,'native_plan':plan_b,
        'native_booking':booking_b,'issuer_spec':spec_b,'original_reader_before':original_reader,
        'before_basis_is_original_successful_full_reader_after_not_new_capture':True,
        'actual_memory_program':m['program'],'actual_DATA_program':d['program'],
        'admission_created':False,'no_launch_performed':True})
    members=[]
    for source in sorted(stage.iterdir()):
        members.append({'source':str(source),'name':source.name,'sha256':hashlib.sha256(source.read_bytes()).hexdigest(),'mode':292})
    seal_plan={'schema':'jetstreamer-sealed-deployment-plan-v1','destination':str(out),'members':members}
    save(stage,'ROOT_NORMAL_SEAL_PLAN.UNSTARTED.json',seal_plan)
    print(str(stage/'ROOT_NORMAL_SEAL_PLAN.UNSTARTED.json'))
    print('No package deployed and no actor launched; Root must run qualified Rust normal sealer on this plan before dispatch.')


if __name__ == '__main__':
    main()
