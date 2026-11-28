"""Main-only preparation, guarded first activation and original terminal capture."""
import argparse,hashlib,json,os,re,runpy,shutil,stat,subprocess,sys,time
from pathlib import Path

HERE=Path(__file__).resolve().parent
BASE=Path('/var/lib/jetstreamer/horizon267-slot-input-v1')
SRC=BASE/'source'
DIAG=Path('/home/ubuntu/.codex/diagnostics')
CG=Path('/sys/fs/cgroup/system.slice')
MAIN='01a1f8f4-293b-7a91-a36e-2e7658bba721'
SEALER=Path('/var/lib/jetstreamer/horizon251-published-sealer-20261118-v1/horizon251-sealer')
SEALER_SHA='faf7aa8270b3472969bf394d4486cdf94445e30e4f15bc6acd38bed56880877a'
CONTRACT='2be7ff5b50e1013dbea7b34c718c3cc6dce0ef9b04912246643517d027779b75'
SYSTEM_SHA='27a7d8f6a005702618e92c88f20b829d38247ad3369e0c35b1ff219d15194bd1'
ORIG=Path('/var/lib/jetstreamer/horizon265-prestart-accepted-20261120-v3')
FILES=('payload.py','guard.py','phase-contract.json','indexes.json','267-car.bin','267-slot-to-cid.bin','slot267.rs','toolchain.py','toolchain.json')
DONE='7ad2d189f7e94e70a38c781354912448'
FAILED='d9b373ed55a64feb8242e02dbe79a49c'

def need(c,r):
    if not c: raise ValueError(r)
def digest(p):
    with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def ref(p):return {'path':str(p),'sha256':digest(p)}
def load(p):return json.loads(p.read_bytes())
def fixed(p):
    m=p.lstat()
    need(p.resolve()==p and stat.S_ISREG(m.st_mode) and m.st_nlink==1 and m.st_uid==m.st_gid==0 and not m.st_mode&0o222,'unsafe immutable file '+str(p))
    return load(p)
def data(p,o):
    with p.open('x') as f:json.dump(o,f,indent=2);f.write('\n');f.flush();os.fchmod(f.fileno(),0o400);os.fsync(f.fileno())
    fd=os.open(p.parent,os.O_DIRECTORY);os.fsync(fd);os.close(fd)
def mkdir(p,mode):p.mkdir(mode=mode);p.chmod(mode)
def system(*args,timeout=10):
    return subprocess.check_output(['/usr/bin/systemctl',*args],text=True,timeout=timeout)
def props(unit,keys):
    p=subprocess.run(['/usr/bin/systemctl','show','--all','-p',','.join(keys),unit],capture_output=True,text=True,timeout=5)
    need(p.returncode in (0,4),p.stderr);return dict(l.split('=',1) for l in p.stdout.splitlines())
def journal(unit,iid):
    need(re.fullmatch('[0-9a-f]{32}',iid),'native IID')
    raw=subprocess.check_output(['journalctl','-b','--all','--no-pager','-o','json','_PID=1','_UID=0','UNIT='+unit,'INVOCATION_ID='+iid],timeout=8)
    return [json.loads(l) for l in raw.splitlines()]
def ended(rows):
    last=[r for r in rows if r.get('MESSAGE_ID') in (DONE,FAILED)]
    need(len(last)==1,'ambiguous/missing PID1 terminal')
    row,=last
    return row['MESSAGE_ID']==DONE and row.get('UNIT_RESULT','success')=='success'
def root():
    need(os.geteuid()==0 and os.environ.get('CODEX_THREAD_ID')==MAIN and __debug__,'Main authority')
def seal(plan_path,dest,members):
    need(digest(SEALER)==SEALER_SHA and not os.path.lexists(dest),'sealer or destination')
    plan={'schema':'jetstreamer-sealed-deployment-plan-v1','destination':str(dest),'members':members}
    data(plan_path,plan)
    subprocess.run([SEALER,plan_path,'--plan-sha256',digest(plan_path),'--self-sha256',SEALER_SHA],check=True,timeout=15,umask=0o022,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
    result=fixed(dest/'deployment-seal-receipt.json')
    need(result['destination']==str(dest) and result['plan_sha256']==digest(plan_path) and result['sealer_sha256']==SEALER_SHA and {m['name']:m['sha256'] for m in result['members']}=={m['name']:m['sha256'] for m in members},'sealer receipt')
def compiler_tools():
    path=HERE/'toolchain.py'
    need(digest(path)=='4dd32fac995c3af2f8a848683fd7f76daea317239bb26eb2ab329d58da3a0f82','compiler verifier source changed')
    return runpy.run_path(str(path))
def compiler_binds():
    tc=compiler_tools()
    return [[str(host),str(target),False,0] for host,target in tc['files'](tc['manifest']())]
def prepare(manifest_sha):
    root()
    p=HERE/'SHA256SUMS';need(digest(p)==manifest_sha and re.fullmatch('[0-9a-f]{64}',manifest_sha),'packet manifest')
    hashes={line.split('  ',1)[1]:line.split('  ',1)[0] for line in p.read_text().splitlines()}
    need(all(digest(HERE/name)==sha for name,sha in hashes.items()) and hashes['phase-contract.json']==CONTRACT and hashes['operate.py']==digest(Path(__file__).resolve()),'packet drift')
    need(not BASE.exists(),'used preparation namespace');mkdir(BASE,0o711)
    seal(BASE/'source-plan.json',SRC,[dict(source=str(HERE/f),name=f,sha256=hashes[f],mode=0o444) for f in FILES])
    tc=compiler_tools();tc['setup'](tc['manifest']())
    for phase in ('transfer','verify'):
        mkdir(BASE/phase,0o711);ctl=BASE/(phase+'-control');mkdir(ctl,0o700);mkdir(ctl/'tokens',0o700)
    data(BASE/'prepared.json',dict(packet_manifest=ref(p),source_seal=ref(SRC/'deployment-seal-receipt.json'),operator=ref(Path(__file__).resolve()),authority=False))
def funding(p,phase):
    need(p.is_relative_to(DIAG),'original funding path')
    f=fixed(p);c=fixed(SRC/'phase-contract.json');lim=c[phase]
    need(ref(SRC/'phase-contract.json')['sha256']==CONTRACT==f['phase_contract']['sha256'] and f['schema']=='horizon267-finite-input-funding-v1' and f['controller']==MAIN and f['phase']==phase and f['unit']==lim['unit'] and f['limits']==lim,'different phase contract')
    need(f['cpu']==56 and f['fits'] is True and f['replay_authorized'] is False and f['publication_authorized'] is False and f['physical_credit_taken_bytes']==0 and f['requested_memory']==lim['memory_max_bytes']+lim['controller_memory_bytes'] and f['disk_reserve']==lim['phase_peak_disk_bytes'],'funding amounts')
    need(f['minimum_free_bytes']>0 and min(f['finite_memory'][k] for k in ('disk_margin','hard_margin','growth_margin'))>=0 and f['recorded_unix_seconds']<=time.time()<f['expires_unix_seconds']<=f['recorded_unix_seconds']+121,'financial gate or expiry')
    need(f['fleet']==ref(Path(f['fleet']['path']))==f['complete_fit']['fleet'] and f['handoff266']==ref(Path(f['handoff266']['path']))==f['complete_fit']['live_266']['handoff'],'owner binding')
    return f
def cmd(path,*args):
    words=[str(path),*map(str,args)];return [str(path),str(len(words)),*words,'false']
def actor_command(phase,l):
    unit=l['unit'];out=BASE/phase;ctl=BASE/(phase+'-control');token=str(ctl)+'/tokens/${INVOCATION_ID}/guard-admission.json'
    caps=(1<<0)|(1<<2)|(1<<6)|(1<<7) if phase=='verify' else 0
    p=[('Description','s','Epoch 267 bounded slot-index '+phase),('Type','s','exec'),('User','s','root'),('Group','s','root'),('Restart','s','no'),('KillMode','s','control-group'),('UMask','u','63'),('NoNewPrivileges','b','true'),('ProtectSystem','s','strict'),('ProtectHome','s','read-only' if phase=='verify' else 'yes'),('PrivateNetwork','b','true' if phase=='verify' else 'false'),('PrivateDevices','b','true'),('CapabilityBoundingSet','t',str(caps)),('ReadWritePaths','as','1',str(out)),('MemoryMax','t',str(l['memory_max_bytes'])),('MemorySwapMax','t','0'),('TasksMax','t',str(l['tasks_max'])),('LimitFSIZE','t',str(32<<20 if phase=='verify' else 15166712)),('LimitFSIZESoft','t',str(32<<20 if phase=='verify' else 15166712)),('AllowedCPUs','ay','8','0','0','0','0','0','0','0','1'),('CPUQuotaPerSecUSec','t','1000000'),('CPUQuotaPeriodUSec','t','100000'),('TimeoutStartUSec','t','75000000'),('TimeoutStopUSec','t','10000000'),('RuntimeMaxUSec','t',str(1000000*l['runtime_seconds'])),('ExecStartPre','a(sasb)','3',*cmd('/usr/bin/sleep','60'),*cmd('/usr/bin/test','-f',token),*cmd('/usr/bin/test','!','-L',token)),('ExecStart','a(sasb)','1',*cmd('/usr/bin/python3','-I','-B',SRC/'payload.py',phase))]
    if phase=='verify':
        binds=compiler_binds()
        p.append(('BindReadOnlyPaths','a(ssbt)',str(len(binds)),*[word for src,dest,_,_ in binds for word in (src,dest,'false','0')]))
    return ['/usr/bin/busctl','--system','call','org.freedesktop.systemd1','/org/freedesktop/systemd1','org.freedesktop.systemd1.Manager','StartTransientUnit','ssa(sv)a(sa(sv))',unit,'fail',str(len(p)),*[word for item in p for word in item],'0']
def dbus_prop(unit,property_name):
    escaped=''.join(ch if ch.isalnum() else '_'+format(ord(ch),'02x') for ch in unit)
    target='/org/freedesktop/systemd1/unit/'+escaped
    s=subprocess.check_output(['/usr/bin/busctl','--json=short','get-property','org.freedesktop.systemd1',target,'org.freedesktop.systemd1.Service',property_name],timeout=3)
    return json.loads(s)
def exact_gate(phase,unit):
    ctl=BASE/(phase+'-control');token=str(ctl)+'/tokens/${INVOCATION_ID}/guard-admission.json'
    for name,typ in [('Environment','as'),('EnvironmentFiles','a(sb)'),('PassEnvironment','as'),('UnsetEnvironment','as')]:
        x=dbus_prop(unit,name);need(x['type']==typ and x['data']==[],'unexpected '+name)
    bind=dbus_prop(unit,'BindReadOnlyPaths')
    expected=compiler_binds() if phase=='verify' else []
    need(bind['type']=='a(ssbt)' and sorted(bind['data'])==sorted(expected),'effective compiler file bindings')
    for name,want in [('ExecStartPre',[['/usr/bin/sleep','60'],['/usr/bin/test','-f',token],['/usr/bin/test','!','-L',token]]),('ExecStart',[['/usr/bin/python3','-I','-B',str(SRC/'payload.py'),phase]])]:
        x=dbus_prop(unit,name)
        need(x['type']=='a(sasbttttuii)' and [r[1] for r in x['data']]==want and all(r[0]==r[1][0] and r[2] is False for r in x['data']),'different native '+name)
def validate_actor(phase,b):
    u=b['unit'];m=props(u,['Id','InvocationID','ActiveState','SubState','MainPID','ControlPID','NRestarts','MemoryMax','MemorySwapMax','AllowedCPUs','TasksMax','ReadWritePaths','ProtectSystem','ProtectHome','NoNewPrivileges','PrivateNetwork','Environment','EnvironmentFiles','PassEnvironment','UnsetEnvironment','DropInPaths','Restart','Type','LimitFSIZE','ControlGroup'])
    need(m['ActiveState']=='activating' and m['SubState']=='start-pre' and m['MainPID']=='0' and int(m['ControlPID'])>1 and re.fullmatch('[0-9a-f]{32}',m['InvocationID']) and m['NRestarts']=='0' and m['Id']==u,'incorrect prestart actor')
    need(m['MemoryMax']==str(b['limits']['memory_max_bytes']) and m['TasksMax']==str(b['limits']['tasks_max']) and m['MemorySwapMax']=='0' and m['AllowedCPUs']=='56' and m['ReadWritePaths']==str(BASE/phase) and m['ProtectSystem']=='strict' and m['ProtectHome']==('read-only' if phase=='verify' else 'yes') and m['PrivateNetwork']==('yes' if phase=='verify' else 'no') and m['NoNewPrivileges']=='yes' and not any(m.get(k) for k in ('Environment','EnvironmentFiles','PassEnvironment','UnsetEnvironment','DropInPaths')) and m['Restart']=='no' and m['Type']=='exec' and m['ControlGroup']=='/system.slice/'+u,'effective service')
    g=CG/u
    need(m['ControlPID'] in (g/'cgroup.procs').read_text().split() and (g/'cpuset.cpus.effective').read_text().strip()=='56' and (g/'cpu.max').read_text().strip()=='100000 100000' and (g/'memory.max').read_text().strip()==m['MemoryMax'] and (g/'memory.swap.max').read_text().strip()=='0','kernel limits')
    return m
def guard_command(phase,unit,ctl):
    p=['Type=oneshot','User=root','Group=root','MemoryMax=33554432','MemorySwapMax=0','TasksMax=12','CPUQuota=100%','AllowedCPUs=56','TimeoutStartSec=8','NoNewPrivileges=yes','PrivateNetwork=yes','ProtectHome=yes','ProtectSystem=strict','CapabilityBoundingSet=CAP_DAC_READ_SEARCH','ReadWritePaths='+str(ctl),'UMask=0077','Restart=no','KillMode=control-group']
    return ['/usr/bin/systemd-run','--quiet','--unit='+unit[:-8]+'-guard','--on-active=1s','--on-unit-inactive=3s','--timer-property=AccuracySec=1us',*['--property='+x for x in p],'/usr/bin/python3','-I','-B',str(SRC/'guard.py'),phase]
def prior(phase):
    if phase!='verify':return None
    p=BASE/'transfer-control/completion.json';v=fixed(p);tr=BASE/'transfer/result.json'
    need(v['success'] is True and v['native']==ref(tr) and v['invocation']==fixed(tr)['invocation'] and not (CG/'horizon267-slot-transfer-v1.service').exists(),'missing original transfer terminal')
    return ref(p)
def launch(phase,fp):
    root();boot=fixed(BASE/'prepared.json');need(boot['source_seal']==ref(SRC/'deployment-seal-receipt.json') and boot['operator']==ref(Path(__file__).resolve()),'prepared source or operator differs')
    need(digest(ORIG/'acceptance.json')=='2c47b0960316289cf31ea89e1bdb3b24d2b0e6131ed41e4273a7c2d5583a1323' and fixed(ORIG/'acceptance.json')['qualification']==ref(ORIG/'qualification.json') and all(digest(Path('/usr/bin')/k)==SYSTEM_SHA for k in ('test','sleep')),'native controls differ')
    f=funding(fp,phase);unit=f['unit'];guard=unit[:-8]+'-guard.service';timer=guard[:-8]+'.timer';ctl=BASE/(phase+'-control');prev=prior(phase)
    for name in (unit,guard,timer):need(props(name,['LoadState']).get('LoadState')=='not-found','used unit '+name)
    need(not list((BASE/phase).iterdir()) and set(os.listdir(ctl))=={'tokens'} and not list((ctl/'tokens').iterdir()),'spent namespace')
    b=dict(f,funding=ref(fp),source_seal=boot['source_seal'],previous=prev);data(ctl/'booking.json',b)
    argv=actor_command(phase,b['limits']);gargv=guard_command(phase,unit,ctl)
    data(ctl/'request.json',dict(booking=ref(ctl/'booking.json'),actor=argv,guard=gargv,prestart_acceptance=ref(ORIG/'acceptance.json')))
    funding(fp,phase);deadline=time.monotonic()+49;subprocess.run(argv,check=True,timeout=8)
    iid=None
    try:
        while time.monotonic()<deadline:
            m=props(unit,['SubState','ControlPID'])
            if m.get('SubState')=='start-pre' and int(m['ControlPID'])>1:break
            time.sleep(.1)
        m=validate_actor(phase,b);iid=m['InvocationID'];exact_gate(phase,unit)
        data(ctl/'binding.json',dict(iid=iid,booking=ref(ctl/'booking.json'),effective=m,monotonic_deadline=deadline))
        subprocess.run(gargv,check=True,timeout=8)
        while time.monotonic()<deadline:
            if (ctl/'trip.json').exists():raise ValueError('first guard trip')
            if (ctl/'first.json').exists():
                sample=fixed(ctl/'first.json');events=journal(guard,sample['guard_invocation'])
                if any(e.get('MESSAGE_ID') in (DONE,FAILED) for e in events):break
            time.sleep(.2)
        need(time.monotonic()<deadline and ended(events) and sample['invocation']==iid and sample['actor']['ControlPID']==m['ControlPID'] and not sample['trip'] and sample['booking']==ref(ctl/'booking.json'),'first guard deadline, terminal or identity')
        t=props(timer,['ActiveState','Unit','SubState','LastTriggerUSecMonotonic','NextElapseUSecMonotonic'])
        need(t['ActiveState']=='active' and t['Unit']==guard and t['LastTriggerUSecMonotonic'] not in ('','0','n/a') and validate_actor(phase,b)==m,'timer or control PID changed')
        data(ctl/'first-PID1.json',events)
        token=dict(phase=phase,invocation=iid,booking=ref(ctl/'booking.json'),first_guard=ref(ctl/'first.json'),guard_pid1=ref(ctl/'first-PID1.json'),timer=t,guard_invocation=sample['guard_invocation'])
        data(ctl/'token.data.json',token)
        need(time.monotonic()<deadline and not (ctl/'trip.json').exists() and validate_actor(phase,b)==m,'late token')
        seal(ctl/'token-plan.json',ctl/'tokens'/iid,[dict(name='guard-admission.json',source=str(ctl/'token.data.json'),sha256=digest(ctl/'token.data.json'),mode=0o400)])
        need(time.monotonic()<deadline and validate_actor(phase,b)==m,'token publication missed active setup')
        data(ctl/'launch.json',dict(invocation=iid,actor=m,booking=ref(ctl/'booking.json'),request=ref(ctl/'request.json'),token=ref(ctl/'tokens'/iid/'guard-admission.json'),guard=guard,timer=timer));print(iid)
    except BaseException:
        if iid is None or props(unit,['InvocationID']).get('InvocationID')==iid:system('--no-block','stop',unit)
        if props(timer,['ActiveState']).get('ActiveState') in ('active','activating'):system('--no-block','stop',timer)
        raise
def terminal(phase):
    root();ctl=BASE/(phase+'-control');b=fixed(ctl/'booking.json');unit=b['unit'];started=fixed(ctl/'binding.json');iid=started['iid']
    need(started['booking']==ref(ctl/'booking.json') and not (CG/unit).exists(),'different or undrained original actor')
    state=props(unit,['ActiveState','MainPID','ControlPID','InvocationID','Result','ExecMainStatus'])
    need(state['ActiveState'] in ('inactive','failed') and state['MainPID']==state['ControlPID']=='0' and state.get('InvocationID','') in ('',iid),'still live or replaced')
    journal_rows=journal(unit,iid);success=ended(journal_rows);timer=unit[:-8]+'-guard.timer';guard=unit[:-8]+'-guard.service'
    for n in (timer,guard):
        if props(n,['ActiveState']).get('ActiveState') in ('active','activating','deactivating'):system('stop',n)
    need(not (CG/guard).exists(),'original guard not drained')
    receipt=BASE/phase/'result.json';result=None
    if success:
        la=fixed(ctl/'launch.json');r=fixed(receipt)
        need(la['invocation']==iid==r['invocation'] and r['phase']==phase and not r['replay_authorized'] and not r['r2_mutations'] and not (ctl/'trip.json').exists(),'incomplete or tripped original')
        if phase=='verify':
            cache=Path(r['cache_path']);seal=fixed(cache.parent/'deployment-seal-receipt.json');m,=seal['members'];need(la['booking']==ref(ctl/'booking.json') and b['previous']==prior(phase) and m['name']==cache.name and m['sha256']==r['full_sha256'] and r['seal_sha256']==digest(cache.parent/'deployment-seal-receipt.json') and r['transfer_receipt_sha256']==digest(BASE/'transfer/result.json'),'output seal or input chain')
        result=ref(receipt)
    final=dict(phase=phase,invocation=iid,booking=ref(ctl/'booking.json'),success=success,native=result,cgroup_drained=True,guard_drained=True,replay_authorized=False)
    if (ctl/'completion.json').exists():need(fixed(ctl/'completion.json')==final,'conflicting terminal')
    else:data(ctl/'terminal-PID1.json',journal_rows);data(ctl/'completion.json',final)
    print(json.dumps(final));return 0 if success else 1
if __name__=='__main__':
    ap=argparse.ArgumentParser();sub=ap.add_subparsers(dest='mode',required=True);a=sub.add_parser('prepare');a.add_argument('manifest_sha256')
    a=sub.add_parser('launch');a.add_argument('phase',choices=('transfer','verify'));a.add_argument('funding',type=Path)
    a=sub.add_parser('terminal');a.add_argument('phase',choices=('transfer','verify'))
    a=ap.parse_args()
    if a.mode=='prepare':prepare(a.manifest_sha256)
    elif a.mode=='launch':launch(a.phase,a.funding)
    else:sys.exit(terminal(a.phase))
