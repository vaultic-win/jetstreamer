"""Source-only metadata/argv validator; does not launch or mutate anything."""
import os
from pathlib import Path
import stat

GIB=1<<30
SCRATCH_BYTES=40*GIB
SCRATCH_INODES=131072

def require(condition,message):
    if not condition:
        raise ValueError(message)

def canonical(path):
    p=Path(path)
    require(p.is_absolute() and str(p)==str(p.resolve(strict=True)), 'absolute canonical path required: '+str(p))
    return p

def private_directory(path):
    p=canonical(path);m=p.lstat()
    require(stat.S_ISDIR(m.st_mode) and m.st_uid==0 and stat.S_IMODE(m.st_mode)==0o700, 'Root0700 namespace required: '+str(p))
    return p,m

def validate_config(c):
    """Validate host identities before namespace creation; no archive bodies open."""
    protected=canonical('/home/sol');host=protected.stat()
    ledger,lm=private_directory(c['ledger_directory'])
    scratch,_=private_directory(c['scratch_directory'])
    state,_=private_directory(c['state_directory'])
    snapshot=canonical(c['snapshot']);private_directory(snapshot.parent)
    for i,root in enumerate([ledger,scratch,state]):
        require(not snapshot.is_relative_to(root),'immutable snapshot overlaps namespace')
        for other in [ledger,scratch,state][i+1:]:
            require(not root.is_relative_to(other) and not other.is_relative_to(root),'owned namespaces overlap')
    require(host.st_dev==lm.st_dev,'protected /home/sol and ledger must be same host DATA device')
    # Host scratch may share DATA here. Only the actual service namespace must
    # replace it with a distinct bounded executable tmpfs; never infer this from
    # the host directory or a declared TemporaryFileSystem string alone.
    sm=snapshot.lstat()
    require(stat.S_ISREG(sm.st_mode) and sm.st_uid==0 and sm.st_nlink==1
        and stat.S_IMODE(sm.st_mode)==0o444 and sm.st_size==1901405026,'verified snapshot metadata changed')
    genesis=ledger/'genesis.tar.bz2';gm=genesis.lstat()
    require(genesis.resolve(strict=True)==genesis and stat.S_ISREG(gm.st_mode)
        and gm.st_uid==0 and gm.st_nlink==1 and stat.S_IMODE(gm.st_mode)==0o444
        and 0<gm.st_size<=10<<20,'canonical immutable genesis metadata changed')
    require(not (ledger/'genesis.bin').exists(),'shadow genesis source forbidden')
    for name in ['ready.json','admission.json','initial-guard.json','outcome.json']:
        require(not (state/name).exists(),'original native state already used: '+name)
    require(not any(scratch.iterdir()),'host scratch leaf must be empty before isolated tmpfs mount')
    require(60<=c['maximum_runtime_seconds']<=7200,'finite native profile')
    require(c['protected_existing_DATA_bytes']>=5114649588372,'complete retained DATA floor lowered')
    require(c['minimum_available_memory_bytes']>=790890381312,'full physical exporter/native floor lowered')
    require(c['expected_current'] is not None,'new accepted midnight current tuple still unresolved')
    return {'protected_device':host.st_dev,'ledger_device':lm.st_dev,
        'host_scratch_is_not_namespace_proof':True,'input_bodies_opened':False}

def assignments(properties):
    result={}
    for value in properties:
        key,sep,text=value.partition('=')
        require(sep and key not in result,'invalid or duplicate native property: '+key)
        result[key]=text
    return result

def validate_actor_properties(plan,properties,environment):
    """Reject the actual2330 mount collision without starting any unit."""
    a=assignments(properties)
    scratch=plan['scratch'];state=plan['state'];ledger=plan['ledger'];snapshot=plan['snapshot']
    expected={
        'Type':'exec','User':'root','Group':'root','Restart':'no','KillMode':'control-group',
        'MemoryAccounting':'yes','MemorySwapMax':'0','TasksMax':'512',
        'NoNewPrivileges':'yes','PrivateNetwork':'yes','PrivateTmp':'no',
        'ProtectSystem':'strict','ProtectHome':'read-only',
        'CapabilityBoundingSet':'CAP_DAC_OVERRIDE CAP_KILL CAP_SYS_PTRACE',
        'AmbientCapabilities':'','RestrictSUIDSGID':'yes','LockPersonality':'yes','UMask':'0077',
        'TimeoutStopSec':'30s','SendSIGKILL':'yes','MemoryMax':'128G','CPUQuota':'800%',
        'RemainAfterExit':'yes','RuntimeMaxSec':str(plan['maximum_runtime_seconds']+120)+'s',
        'ReadWritePaths':state,
        'BindReadOnlyPaths':snapshot+' '+ledger,
        'TemporaryFileSystem':'/tmp:ro /var/tmp:ro '+scratch+':rw,nosuid,nodev,exec,size=40G,nr_inodes=131072,mode=0700',
    }
    require(a==expected,'native properties differ from exact reviewed no-collision envelope')
    # Same-target higher-priority access/bind/exec entries suppress MOUNT_TMPFS
    # in systemd255. Ancestor RO policies are deliberate; exact target entries
    # in any of these lists are forbidden. RW must remain only the state leaf.
    for key in ['ReadWritePaths','ReadOnlyPaths','InaccessiblePaths','BindPaths','BindReadOnlyPaths','ExecPaths','NoExecPaths']:
        for entry in a.get(key,'').split():
            target=entry.lstrip('-+')
            if ':' in target:
                pieces=target.split(':');target=pieces[1] if len(pieces)>1 else pieces[0]
            require(target!=scratch,'scratch tmpfs suppressed by duplicate '+key+' target')
    require(environment==['TMPDIR='+scratch,'TMP='+scratch,'TEMP='+scratch],'exact bounded temporary directory aliases required')
    require(plan['protected_filesystem']=='/home/sol','protected filesystem must remain exact /home/sol')
    require(plan['minimum_free_bytes']>=5114649588372+SCRATCH_BYTES,'native candidate DATA omitted')
    return True

def validate_prepared_directory(directory):
    """Offline/host-metadata preflight of already normally sealed new plans."""
    import hashlib,json
    directory=canonical(directory)
    def read(name):
        path=directory/name;m=path.lstat()
        require(stat.S_ISREG(m.st_mode) and m.st_uid==0 and m.st_nlink==1 and not m.st_mode&0o222,
            'prepared input must be Root immutable singleton JSON')
        require(0<m.st_size<=1<<20,'bounded plan metadata required')
        return json.loads(path.read_bytes())
    prepared=read('prepared-bindings.json');pb=prepared['native_plan']
    require(Path(pb['path'])==directory/'native-plan.json','native prepared plan namespace crossed')
    raw=(directory/'native-plan.json').read_bytes()
    require(hashlib.sha256(raw).hexdigest()==pb['sha256'],'native prepared plan digest crossed')
    plan=read('native-plan.json');actor=read('actor-argv.json')
    require(actor['unit']=='horizon-epoch163-native-input-20261106-v1.service','exact actor role')
    argv=actor['argv'];prefix=['/usr/bin/systemd-run','--unit='+actor['unit'],'--quiet']
    require(argv[:3]==prefix,'exact native systemd transport')
    props=[];environment=[];i=3
    while i<len(argv) and argv[i].startswith('--property='):
        props.append(argv[i][len('--property='):]);i+=1
    while i<len(argv) and argv[i].startswith('--setenv='):
        environment.append(argv[i][len('--setenv='):]);i+=1
    require(argv[i:]==actor['direct_ExecStart_argv'],'exact original actor direct argv')
    require(argv[i:]==[plan['program']['path'],pb['path'],'--plan-sha256',pb['sha256'],
        '--self-sha256',plan['program']['sha256']],'native program/plan/self CLI crossed')
    validate_actor_properties(plan,props,environment)
    ledger,lm=private_directory(plan['ledger']);private_directory(plan['scratch']);private_directory(plan['state'])
    protected=canonical(plan['protected_filesystem'])
    require(protected==Path('/home/sol') and protected.stat().st_dev==lm.st_dev,'actual host DATA/ledger identity differs')
    return {'schema':'native128-offline-no-collision-plan-preflight-v1',
        'plan':pb,'canonical_protected_filesystem':'/home/sol',
        'ReadWritePaths_only_original_state':True,'scratch_tmpfs_duplicate_absent':True,
        'all_original_profile_and_clock_limits_retained':True,
        'namespace_created':False,'kernel_namespace_proof_claimed':False,
        'actor_launched':False,'archive_or_worker_body_reads':False}

if __name__=='__main__':
    import argparse,json
    parser=argparse.ArgumentParser();parser.add_argument('normally_sealed_prepared_directory')
    print(json.dumps(validate_prepared_directory(parser.parse_args().normally_sealed_prepared_directory),indent=2))
