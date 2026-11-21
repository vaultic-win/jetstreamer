"""Keep the native 199–200 tree guard in force while PID1 owns a funded reservation."""
import hashlib
import json
import os
import runpy
import subprocess
import sys
import time
import uuid
from pathlib import Path

HERE=Path(__file__).resolve().parent
C=runpy.run_path(str(HERE/'contract.py'))
B=C['B']; ROOT=C['ROOT']; HOLD=C['HOLD']; G=C['G']; need=C['need']
NATIVE=B.parent/'epoch170-retry9-recovery-20261120-v1/guard-v1/guard'
AUX='horizon199200-aux.slice'

def save(p,obj):
    with p.open('x') as f:
        os.fchmod(f.fileno(),0o400)
        json.dump(obj,f,sort_keys=True)
        f.write('\n');f.flush();os.fsync(f.fileno())

def props(name):
    res=subprocess.run(['/usr/bin/systemctl','show',name,'-p','Id,ActiveState,SubState,MainPID,InvocationID,ControlGroup,Slice,Restart,NRestarts,MemorySwapMax'],text=True,capture_output=True,check=True,timeout=10)
    return dict(x.split('=',1) for x in res.stdout.splitlines() if '=' in x)

def owner(iid):
    me=props(HOLD)
    need(me['Id']==HOLD and me['InvocationID']==iid and me['SubState']=='running' and me['ActiveState']=='active' and int(me['MainPID'])==os.getpid() and me['NRestarts']=='0' and me['Restart']=='no' and me['MemorySwapMax']=='0','lost reservation generation')
    cg=Path('/sys/fs/cgroup')/me['ControlGroup'].lstrip('/')
    need(Path('/proc/self/cgroup').read_text().strip()=='0::'+me['ControlGroup'] and cg.is_dir(), 'wrong reservation cgroup')
    return me

def cycle(plan,path,iid):
    name='horizon-199200-native-guard-'+uuid.uuid4().hex+'.service'
    argv=['/usr/bin/systemd-run','--quiet','--pipe','--wait','--collect','--unit='+name,'--service-type=exec','--slice='+AUX,
          '--property=Restart=no','--property=MemoryMax=512M','--property=MemorySwapMax=0','--property=CPUQuota=50%','--property=RuntimeMaxSec=45s',
          '--property=NoNewPrivileges=yes','--property=PrivateNetwork=yes','--property=ProtectSystem=strict','--property=ProtectHome=read-only',
          '--property=ReadWritePaths='+str(path.parent),str(NATIVE),str(path),'--plan-sha256',hashlib.sha256(path.read_bytes()).hexdigest(),'--self-sha256',C['GUARD_SHA']]
    res=subprocess.run(argv,check=True,capture_output=True,text=True,timeout=50)
    record=json.loads(res.stdout)
    orig=owner(iid)
    C['gate'](record,plan,argv[-3],int(orig['MainPID']),time.time(),orig['ControlGroup'])
    sr=path.parent/('sample-'+record['guard_invocation_id']+'.json')
    need(sr.resolve()==sr and json.loads(sr.read_bytes())==record,'native sample not durably recorded')
    return {'path':str(sr),'sha256':hashlib.sha256(sr.read_bytes()).hexdigest()}

def run(fleet,head,provider,provider_seal):
    need(os.geteuid()==0 and sys.flags.isolated and __debug__, 'isolated root required')
    C['check_sources']()
    need(hashlib.sha256(NATIVE.read_bytes()).hexdigest()==C['GUARD_SHA'],'different guard')
    d=Path(provider)
    need(d.resolve()==d and d.parent==B.parent/'incident-replay-fit-20261121-v1' and d.name in ('tools-v9','tools-v10') and
         provider_seal=={'tools-v9':'a3c04e5f662aaca041398496a609bb9a7072177cbc180fa6e1dac32fd1ab0b9c','tools-v10':'d32722386d1511d8db85801e349dd645107b2f3c0043a7debebb22c9eae60085'}[d.name],'unqualified provider')
    seal=C['bound'](d/'deployment-seal-receipt.json',provider_seal)
    image=d/'post-stop-fit';members={v['name']:v['sha256'] for v in seal['members']}
    need(seal['destination']==str(d) and hashlib.sha256(image.read_bytes()).hexdigest()==members[image.name],'provider changed')
    fit=json.loads(subprocess.check_output([image,'145',fleet,head],timeout=150))
    need(fit['fleet']=={'path':fleet,'sha256':head} and 0<=time.time()-fit['recorded_unix_seconds']<=90,'wrong or stale fleet')
    mem=int(Path('/proc/meminfo').read_text().splitlines()[0].split()[1])*1024
    gaps=C['price'](fit,mem,os.sysconf('SC_NPROCESSORS_ONLN'))
    need(not any(gaps.values()),'unfunded 199-200 reservation '+json.dumps(gaps,sort_keys=True))
    protect(fit)

def protect(fit, authorization=None):
    # Every admitted provider enters the same qualified whole-tree guard.
    need(os.geteuid()==0 and sys.flags.isolated and __debug__, 'isolated root required')
    C['check_sources']()
    need(hashlib.sha256(NATIVE.read_bytes()).hexdigest()==C['GUARD_SHA'],'different native guard')
    iid=os.environ['INVOCATION_ID']
    me=owner(iid)
    need(me['Slice']==AUX,'unbounded reservation service')
    slice_cg=Path('/sys/fs/cgroup/horizon199200.slice')
    auxiliary=slice_cg/AUX
    need(int((slice_cg/'memory.max').read_text())==153*G and int((auxiliary/'memory.max').read_text())==G and int((slice_cg/'memory.swap.max').read_text())==0,'unbounded 199 parent')
    quota,period=map(int,(slice_cg/'cpu.max').read_text().split())
    need(quota==8*period,'aggregate CPU not exactly eight')
    out=B/('guard-'+iid);out.mkdir(mode=0o700)
    save(out/'FIT.json',fit)
    if authorization is not None:save(out/'EXCLUSIVE_TRANSITION.json',authorization)
    plan=C['monitor'](iid,fit['complete_required_HOME_bytes'],out)
    path=out/'PLAN.json';save(path,plan)
    counter=0
    while True:
        sample=cycle(plan,path,iid)
        if not counter:save(out/'FIRST_PROTECTING_GUARD.json',dict(sample=sample,owner=me,full_disk_charge=C['FULL'],service_dependencies=C['service_dropins']()))
        counter+=1
        time.sleep(5)

if __name__=='__main__':run(*sys.argv[1:])
