"""Exercise the deployed physical guard and systemd dependency on isolated real inodes."""
import hashlib
import json
import os
import re
import runpy
import copy
import uuid
import subprocess
import sys
from pathlib import Path

BASE=Path('/var/lib/jetstreamer/horizon_runtime_data')
B=BASE/'epoch199-delivery-recovery-20261121-v1'
GUARD=BASE/'epoch170-retry9-recovery-20261120-v1/guard-v1/guard'
IMAGE='b2271db6f25696612c388297db3a10852f7911560887f67dcb404392d91f7016'
PROFILE=B/'joint-measure-08c90435c93a476f99acda7f19f6e4ed/PROFILE.json'
G=1<<30

def need(ok,err):
    if not ok:
        raise ValueError(err)

def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

def save(path,value):
    with path.open('x') as f:
        json.dump(value,f,sort_keys=True,indent=2)
        f.write('\n')
        f.flush()
        os.fsync(f.fileno())
    path.chmod(0o400)

def sh(*argv, check=True):
    result=subprocess.run(list(map(str,argv)),capture_output=True,text=True,check=False,timeout=20)
    if check and result.returncode:
        print(result.stderr.rstrip(), file=sys.stderr,flush=True)
        result.check_returncode()
    return result

def show(unit):
    p=sh('/usr/bin/systemctl','show',unit,'-p','Id,ActiveState,SubState,MainPID,InvocationID,BindsTo,After,ControlGroup,LoadState',check=False)
    return dict(l.split('=',1) for l in p.stdout.splitlines() if '=' in l)

def properties(unit,hold):
    need(re.fullmatch(r'[a-z0-9-]+\.service',unit) and re.fullmatch(r'horizon-qualify-199200-[a-z0-9-]+\.service',hold),'invalid unit')
    return ['--property=BindsTo='+hold,'--property=After='+hold,'--property=Requisite='+hold]

def service(unit,cmd,props=(),wait=False):
    args=['/usr/bin/systemd-run','--quiet','--unit='+unit,'--collect','--service-type=exec','--property=Restart=no','--property=Nice=19','--property=MemorySwapMax=0','--property=PrivateNetwork=yes','--property=CPUQuota=10%','--property=MemoryMax=40M','--property=RuntimeMaxSec=45s','--property=NoNewPrivileges=yes']
    return sh(*args,*(['--wait','--pipe'] if wait else []),*props,*cmd)

def guard_call(plan,role,sequence,wrong_hash=False):
    p=plan.parent/f'{role}-{sequence}.json'
    guard_unit='horizon-199-guard-probe-'+os.environ['INVOCATION_ID'][:12]+'-'+role+'-'+str(sequence)+'-'+uuid.uuid4().hex[:8]+'.service'
    args=[GUARD,p,'--plan-sha256',sha(p),'--self-sha256','0'*64 if wrong_hash else IMAGE]
    return service(guard_unit,args,['--property=ProtectHome=read-only','--property=ProtectSystem=strict','--property=ReadWritePaths='+str(plan.parent)],wait=True)

def exercise(out,role,sequence,scope):
    tag=os.environ['INVOCATION_ID'][:12]+'-'+role+'-'+str(sequence)
    holder='horizon-qualify-199200-guard-fixture-'+tag+'.service'
    actor='horizon-199200-'+role+'-fixture-'+tag+'.service'
    root=out/(role+str(sequence));root.mkdir(mode=0o700)
    tree=root/'tree';tree.mkdir();private=tree/'lane-a';private.mkdir();public=tree/'public';public.mkdir();receipts=root/'receipts';receipts.mkdir(mode=0o700)
    p=root/f'{role}-{sequence}.json'
    launched=[]
    try:
        service(holder,['/usr/bin/sleep','44']);launched.append(holder)
        owner=show(holder)
        need(owner['ActiveState']=='active' and owner['MainPID']!='0' and re.fullmatch(r'[0-9a-f]{32}',owner['InvocationID']), 'missing original PID1 reservation owner')
        budget=96<<10
        fs=os.statvfs(tree)
        floor=1 if scope=='tree' else (fs.f_blocks+1)*fs.f_frsize
        plan=dict(schema='jetstreamer-horizon-standalone-guard-plan-v1',unit=holder,invocation_id=owner['InvocationID'],filesystem='/home/sol',minimum_free_bytes=floor,worker_root=str(tree),maximum_worker_vmas=3500000,maximum_root_physical_bytes=budget,receipt_directory=str(receipts))
        save(p,plan)
        try:guard_call(p,role,sequence,wrong_hash=True)
        except subprocess.CalledProcessError as e:need('digest mismatch' in e.stderr,'wrong failure in image negative case')
        else:raise ValueError('native guard accepted wrong image SHA')
        need(show(holder)['InvocationID']==owner['InvocationID'] and not list(receipts.iterdir()), 'negative case affected owner')
        if scope=='tree':
            body=private/'frame.jet'
            with body.open('xb') as f:os.posix_fallocate(f.fileno(),0,32768)
            observation=json.loads(guard_call(p,role,sequence).stdout)
            need(observation['producer_stop_enabled'] and observation['trip_reason'] is None and observation['producer_invocation_id']==owner['InvocationID'], 'first protecting sample')
            # A normal same-device commit transfers the original inode to publication.
            old=body.stat();dest=public/body.name
            body.rename(dest)
            need(os.path.samestat(old,dest.stat()), 'same-device commit replaced inode')
            next_obs=json.loads(guard_call(p,role,sequence).stdout)
            need(next_obs['trip_reason'] is None and next_obs['root_physical_observation']['conservative_physical_bytes'] >= 32768, 'loss of charge after import')
        service(actor,['/usr/bin/sleep','44'],properties(actor,holder));launched.append(actor)
        active=show(actor)
        need(holder in active['BindsTo'].split() and holder in active['After'].split() and active['ActiveState']=='active','unbound phase')
        if scope=='tree':
            with (private/'growth').open('xb') as f:os.posix_fallocate(f.fileno(),0,budget)
        sample=json.loads(guard_call(p,role,sequence).stdout)
        expected='root-physical-budget' if scope=='tree' else 'filesystem-floor'
        stopped=show(actor);held=show(holder)
        need(sample['trip_reason']==expected and sample['producer_invocation_id']==owner['InvocationID'] and sample['producer_stop_enabled'] is True,'wrong native trip')
        need(all(s.get('ActiveState') in (None,'inactive') and s.get('MainPID','0')=='0' and not s.get('ControlGroup') for s in (stopped,held)), 'dependency tree not drained')
        intent=json.loads((receipts/'stop-intent.json').read_bytes());end=json.loads((receipts/'stop-completion.json').read_bytes())
        need(intent['reason']==expected and end['intent']==str(receipts/'stop-intent.json') and end['producer_invocation_id']==owner['InvocationID'], 'missing durable trip')
        try:service(actor,['/usr/bin/sleep','2'],properties(actor,holder))
        except subprocess.CalledProcessError:pass
        else:raise ValueError('future phase started with expired transient owner')
        return dict(scope=scope,original=owner,active_phase=active,held_terminal=held,phase_terminal=stopped,sample=sample,stop_completion=end,expired_phase_rejected=True,wrong_hash_rejected=True)
    finally:
        for unit in reversed(launched):
            if show(unit).get('ActiveState')=='active':
                sh('/usr/bin/systemctl','stop',unit)

def main():
    need(sha(GUARD)==IMAGE and sha(PROFILE)=='440ef1cf341ea8032cb3d6b0447309a3b8ef20a2000359c0a783b8357488a653','different source')
    out=B/('joint-phase-guard-'+os.environ['INVOCATION_ID']);out.mkdir(mode=0o700)
    fs=os.statvfs(out)
    priced=json.loads(PROFILE.read_bytes())
    need(priced['candidate_disk']==448*G and priced['candidate_worker_memory']==152*G and priced['current_replay_admission'] is False,'profile changed')
    fleet,fh,provider,seal=sys.argv[1:]
    pkg=Path(provider)
    need(pkg.parent==BASE/'incident-replay-fit-20261121-v1' and pkg.name in ('tools-v9','tools-v10') and sha(pkg/'deployment-seal-receipt.json')==seal,'different current fit')
    mod=runpy.run_path(str(Path(__file__).resolve().with_name('external_v10.py')))
    fit=mod['capture'](pkg/'post-stop-fit',fleet,fh,'34d90f2a5ae8a821109b2bbf99c5527d43c3eb141f68cea212109fc876f28c8d')
    need(fit['fits'] and fit['fleet']=={'path':fleet,'sha256':fh} and fit['complete_memory_plus_reserve_bytes']==810658050048 and fit['complete_cpu_quota_micros']==64000000 and fit['available_HOME_bytes']-fit['complete_required_HOME_bytes']>=55<<20 and fit['available_memory_bytes']-fit['required_available_memory_bytes']>=512<<20 and fit['resource_credit_bytes']==0,'native QA fit refused')
    save(out/'FIT.json',fit)
    # The fit owns 0.5CPU/512MiB alone. Return part of that same booking to
    # the three 0.1CPU/40MiB fixture children before any child is started.
    unit='/system.slice/horizon-199200-native-phase-guard-qa-b.service'
    need(Path('/proc/self/cgroup').read_text().strip()=='0::'+unit, 'foreign QA resource owner')
    sh('/usr/bin/systemctl','set-property','--runtime',unit.split('/')[-1],'CPUQuota=20%','MemoryMax=392M')
    cg=Path('/sys/fs/cgroup'+unit)
    quota,period=map(int,(cg/'cpu.max').read_text().split())
    need(quota*5==period and int((cg/'memory.max').read_text())==392<<20, 'aggregate QA budget')
    c=runpy.run_path(str(Path(__file__).resolve().with_name('contract.py')))
    profile,original=c['check_sources']()
    def denied(fn):
        try:fn()
        except ValueError:return
        raise ValueError('negative test unexpectedly passed')
    bad=copy.deepcopy(original);bad['comparisons'][-1]['observed_epochs']=[199,200];denied(lambda:c['measurements'](bad))
    bad=copy.deepcopy(original);bad['source_workers'][0]['sha256']='0'*64;denied(lambda:c['measurements'](bad))
    denied(lambda:c['measure_charge'](1));denied(lambda:c['bound'](PROFILE,'0'*64))
    raw_ram=int(Path('/proc/meminfo').read_text().splitlines()[0].split()[1])*1024
    current=c['price'](fit,raw_ram,os.sysconf('SC_NPROCESSORS_ONLN'))
    need(current['disk']>0 and current['committed_memory']>0 and current['cpu_quota_micros']>0,'stale incumbent negative case')
    dependencies={unit:c['controls'](unit) for unit in (c['CTRL'],c['PROD'],c['IMP'])}
    denied(lambda:c['controls']('foreign.service'))
    true_plan=c['monitor'](os.environ['INVOCATION_ID'],fit['complete_required_HOME_bytes'],out)
    stage=out/'REAL_PROFILE_STATIC.json';save(stage,true_plan)
    static=json.loads(sh(GUARD,stage,'--plan-sha256',sha(stage),'--self-sha256',IMAGE,'--validate-plan-only').stdout)
    need(static['validated'] and not static['protective_guard_proven'] and true_plan['maximum_root_physical_bytes']==416*G,'real phase threshold')
    controller=c['controller_options'](fit)
    dropins=c['service_dropins']()
    # The real sealed monitor must refuse this exact active fleet prior to creating a
    # watcher or phase. Use the same arithmetic as its entry point without a second
    # routine resource capture.
    monitor=runpy.run_path(str(Path(__file__).resolve().with_name('watch.py')))
    need(monitor['C']['price'](fit,raw_ram,os.sysconf('SC_NPROCESSORS_ONLN'))==current,'monitor and renderer disagree')
    need(monitor['C']['HOLD']==c['HOLD'] and monitor['AUX']=='horizon199200-aux.slice','wrong guard scope')
    cases=[exercise(out,'producer',1,'tree'),exercise(out,'import',2,'tree'),exercise(out,'producer',3,'floor'),exercise(out,'import',4,'floor')]
    save(out/'QUALIFIED.json',dict(guard_sha256=IMAGE,profile_sha256=sha(PROFILE),cases=cases,raw_ceiling=priced['candidate_disk'],early_guard_threshold=c['TRIP'],response_headroom=c['FULL']-c['TRIP'],native_static_guard=static,full_candidate_gaps=current,production_dependencies=dependencies,prospective_controller_check_only=controller,systemd_dropin_projection=dropins,aggregate_slices=c['slices'](),production_watch_sha256=sha(Path(__file__).resolve().with_name('watch.py')),first_guard_required_before_payload=True,zero_disk_credit_until_final_reprice=True,replay_admitted=False))
    print(out,sha(out/'QUALIFIED.json'))

if __name__=='__main__':
    main()
