#!/usr/bin/env python3
"""Root-only SOURCE: bind actual completed native outcome; never run finalizer."""
import argparse
import json
import os
from pathlib import Path
from prepare_native128 import metadata, require, bound, save, TOOLS, FINAL_SHA


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('prepared_directory')
    parser.add_argument('staging_directory')
    parser.add_argument('output_directory')
    args=parser.parse_args()
    require(os.geteuid()==0,'Root is sole operator')
    directory=Path(args.prepared_directory)
    prepared=json.loads((directory/'prepared-bindings.json').read_bytes())
    plan=metadata(prepared['native_plan'])
    state=Path(plan['state'])
    # This opens only actual outcome JSON after terminal native completion.
    # It does not read or fabricate snapshot/bank/account data.
    import hashlib
    p=state/'outcome.json'
    require(p.suffix=='.json' and p.resolve()==p and p.stat().st_uid==0 and p.stat().st_nlink==1
        and p.stat().st_size<=1<<20, 'actual bounded Root original outcome JSON')
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        before=os.fstat(fd)
        raw=os.read(fd,(1<<20)+1)
        after=os.fstat(fd)
        require((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)
            ==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns),
            'native outcome changed')
    finally:
        os.close(fd)
    outcome=bound(p,hashlib.sha256(raw).hexdigest())
    value=metadata(outcome,immutable=False)
    require(value.get('original_capability_actor_drained') is False,
        'original unfinalized native outcome required; qualified finalizer proves native drain itself')
    final={'schema':'epoch163-native-input-finalization-plan-v1','native_plan':prepared['native_plan'],
        'native_outcome':outcome,'acceptance':str(state/'input-capability.json'),
        'original_completion':str(state/'original-completion.json')}
    stage=Path(args.staging_directory)
    require(stage.is_absolute() and str(stage).startswith('/home/sol/.jetstreamer-private/'), 'private source staging required')
    stage.mkdir(mode=0o700,exist_ok=False)
    output=Path(args.output_directory)
    require(output.parent==Path('/usr/local/lib/jetstreamer') and not output.exists(), 'fresh normal-seal finalization destination required')
    final_b=save(stage,'finalization-plan.json',final,published_parent=output)
    direct=[TOOLS+'/native-input-finalize',final_b['path'],'--plan-sha256',final_b['sha256'],'--self-sha256',FINAL_SHA]
    props=['Type=exec','User=root','Group=root','Restart=no','KillMode=control-group',
        'MemoryAccounting=yes','MemoryMax=512M','MemorySwapMax=0','CPUQuota=100%','TasksMax=512',
        'NoNewPrivileges=yes','PrivateNetwork=yes','PrivateTmp=no','ProtectSystem=strict',
        'ProtectHome=read-only','ReadWritePaths='+str(state),'CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_SYS_PTRACE',
        'AmbientCapabilities=','TemporaryFileSystem=/tmp:ro /var/tmp:ro','RuntimeMaxSec=120s',
        'RemainAfterExit=yes','UMask=0077']
    argv=['/usr/bin/systemd-run','--unit=horizon-epoch163-native-input-finalize-20261107-v1.service','--quiet']
    argv += ['--property='+p for p in props]+direct
    save(stage,'finalizer-argv.json',{'argv':argv,'direct_ExecStart_argv':direct,
        'finalization_plan':final_b,'no_finalization_performed':True})
    members=[{'source':str(f),'name':f.name,'sha256':hashlib.sha256(f.read_bytes()).hexdigest(),'mode':292} for f in sorted(stage.iterdir())]
    save(stage,'ROOT_NORMAL_SEAL_PLAN.UNSTARTED.json',{'schema':'jetstreamer-sealed-deployment-plan-v1','destination':str(output),'members':members})
    print(str(stage/'ROOT_NORMAL_SEAL_PLAN.UNSTARTED.json'))
    print('Root must normally seal the finalization plan and argv before invoking the finalizer once.')


if __name__=='__main__':
    main()
