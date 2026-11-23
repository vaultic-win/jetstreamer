"""Book and guard one exact native stage against the original stopped generation."""
import hashlib,json,os,re,stat,subprocess as sp,sys,time
from pathlib import Path
here=Path(__file__).resolve().parent;sys.path.insert(0,str(here))
from funding import price,M,partition
import funds

from owners import MAIN
from owners import CG,D,V,need,props,ref,bound
phase=sys.argv[1];attempt=sys.argv[2];need(phase in ('retire','close') and attempt.isdecimal(),'phase')
assert __debug__ and os.geteuid()==0 and os.environ['CODEX_THREAD_ID']==MAIN and here==Path('/run/horizon266-bounded-retirement-v215-f1') and here.stat().st_uid==0
COMMIT='2af2842a667652aa1bf743d4d1098df022421d09'
lock=partition.take()
unit='horizon266-stopped-'+phase+'-v215-a'+attempt+'.service'
dest=D/unit[:-8]
cap=price(352*M,8*M,4*M)
rr=D/('horizon-bounded265-residual-'+unit[:-8]);rr.mkdir(mode=0o700);allocation=funds.put(rr/'assignment.json',cap)
dest.mkdir(mode=0o700)
state=V/'horizon266-stopped-bounded-v215-state';grants=Path('/run/horizon266-stopped-bounded-v215-grants');seal=V/'horizon266-stopped-bounded-v215-qualified'
sealer=V/'horizon251-published-sealer-20261118-v1/horizon251-sealer';sealer_sha='faf7aa8270b3472969bf394d4486cdf94445e30e4f15bc6acd38bed56880877a'
def stamp(p):
 with p.open('rb') as f:return dict(path=str(p),sha256=hashlib.file_digest(f,'sha256').hexdigest())
def write(p,b):
    # No-clobber publication after the entire file is durable.
    tmp=p.with_name('.'+p.name+'.new')
    with tmp.open('xb') as f:
        os.fchmod(f.fileno(),0o400);f.write(b);f.flush();os.fsync(f.fileno())
    os.link(tmp,p);tmp.unlink();fd=os.open(p.parent,os.O_DIRECTORY);os.fsync(fd);os.close(fd)
def put(p,d):
    write(p,(json.dumps(d,indent=2)+'\n').encode());return ref(p)
def rootdir(p):
    p.mkdir(mode=0o700,exist_ok=True);m=p.lstat()
    need(p.resolve()==p and stat.S_ISDIR(m.st_mode) and (m.st_uid,m.st_gid,m.st_mode & 0o7777)==(0,0,0o700),'control directory')
M=1<<20
build_binding=ref(D/'horizon266-bounded-retire-controller-v215-a1/completion.json')
real_binding=ref(D/'horizon266-bounded-retire-real-check-v215-a1/completion.json')
assert real_binding['sha256']=='a2bb189c4fd04c4198be02ef4b04e5a41a4c17bb4f6c4c391365ae535bb10347'
actual=bound(real_binding);build=bound(build_binding)
assert actual['build']==build_binding and actual['image']==build['image'] and build['fixture_tests']==36
assert actual['result']['files']==398514 and actual['result']['allocated_file_bytes']==96705163264
assert bound(build['process'])['stdout'].count('9 passed; 0 failed;')==4 and bound(build['process'])['exit']==0
git=['sudo','-n','--preserve-env=SSH_AUTH_SOCK','-u','ubuntu','git','-C','/home/ubuntu/workspace/jetstreamer']
sp.run([*git,'fetch','--quiet','origin','account-updates'],check=True)
head=sp.check_output([*git,'rev-parse','origin/account-updates'],text=True).strip()
sp.run([*git,'merge-base','--is-ancestor',COMMIT,head],check=True)
need(not sp.check_output([*git,'diff',COMMIT,head,'--','tools/native266-stopped-scratch']),'controller branch drift')
for name,r in build['sources'].items():
 path='tools/native266-stopped-scratch/src/'+name
 need(stamp(Path(r['path']))==r and hashlib.sha256(sp.check_output([*git,'show',COMMIT+':'+path])).hexdigest()==r['sha256'],'source '+path)
need(stamp(Path(build['image']['path']))==build['image'] and stamp(sealer)['sha256']==sealer_sha,'production image')
stage=V/'horizon266-capped-bounded-v210-control';terminal=cap['closed266']
assert terminal['sha256']=='94958f52d3f1265519325c5b5bbccacf68b119cf441a8939ea678eb8946f5667'
st=bound(bound(terminal)['handoff'])
guard='horizon-266-capped-bounded-v210-protective.service'
retained=bound(allocation)['retained'];assert retained==8*M
roots=[state,grants,seal,Path(allocation['path']).parent,*D.glob('horizon266-stopped-*-v215-*'),Path(__file__)]
usage={str(p):int(sp.check_output(['du','-sx','-B1',p],text=True).split()[0]) for p in roots if p.exists()}
assert sum(usage.values())+(4*M)<retained
control=props('horizon266-capped-bounded-v210-control.service',['ActiveState','SubState','Job','MainPID','Restart','NRestarts'])
need(control==dict(ActiveState='inactive',SubState='dead',Job='',MainPID='0',Restart='no',NRestarts='0'),'launch controller is live')
need(not (CG/'horizon266-capped-bounded-v210-control.service').exists(),'controller cgroup')
pilot=stage/'pilot'
names=[st['unit'],guard,guard.replace('.service','-failsafe.service'),guard.replace('.service','.timer')]
references={}
for base in map(Path,['/etc/systemd/system','/run/systemd/system','/etc/cron.d','/etc/cron.hourly','/etc/cron.daily']):
 for path in base.rglob('*'):
    try:
        if not path.is_file():continue
        data=path.read_bytes()
    except FileNotFoundError:continue
    if any(v in data for v in [b'qualification-266-capped-bounded-v210',os.fsencode(pilot),os.fsencode(st['unit'])]):
        need(path.name in names and path.resolve()==pilot/path.name,'unaccounted old guest launcher '+str(path))
        references[str(path)]=stamp(path)
for n in names:
    m=props(n,['Id','Job','ActiveState','DropInPaths','WantedBy','RequiredBy','FragmentPath'])
    need(m['Id']==n and m['ActiveState'] in ('inactive','failed') and not any(m[k] for k in ('Job','WantedBy','RequiredBy','DropInPaths')) and Path(m['FragmentPath']).resolve()==pilot/n,'staged/active trigger')
need(phase=='retire' or (state/'retired').is_file(),'retirement missing')
rootdir(state);rootdir(state/'bookings');rootdir(grants)
assert here.resolve()==here and here.stat().st_uid==0 and not here.stat().st_mode&0o022
if phase=='close':
 previous=[(r,bound(ref(r))) for r in D.glob('horizon266-stopped-retire-v215-a*/completion.json')]
 assert len(previous)>=1 and any(ref(Path(x['exact_state']['path']))==x['exact_state'] and x['source']==COMMIT for _,x in previous)
if not seal.exists():
 provenance=put(dest/'provenance.json',dict(commit=COMMIT,remote=head,sources=build['sources'],build=build_binding,qualification=real_binding,image=build['image']))
 plan=dict(schema='jetstreamer-sealed-deployment-plan-v1',destination=str(seal),members=[dict(name='native266-stopped-scratch',source=build['image']['path'],sha256=build['image']['sha256'],mode=0o555),dict(name='provenance.json',source=provenance['path'],sha256=provenance['sha256'],mode=0o444)])
 pl=put(dest/'seal-plan.json',plan);sp.run([sealer,pl['path'],'--plan-sha256',pl['sha256'],'--self-sha256',sealer_sha],check=True)
image=seal/'native266-stopped-scratch';sealed=ref(seal/'deployment-seal-receipt.json')
need(stamp(image)['sha256']==build['image']['sha256'] and image.stat().st_uid==0 and image.stat().st_mode&0o777==0o555,'sealed image')
prov=bound(ref(seal/'provenance.json'));assert prov['qualification']==real_binding and prov['build']==build_binding and prov['commit']==COMMIT and prov['image']==build['image']
propset=['Type=exec','User=root','Group=root','Restart=no','KillMode=control-group','MemoryMax=256M','MemoryHigh=160M','MemorySwapMax=0','CPUQuota=100%','AllowedCPUs=8','TasksMax=16','RuntimeMaxSec='+('1200' if phase=='retire' else '420'),'Nice=10','IOSchedulingClass=best-effort','IOSchedulingPriority=6','NoNewPrivileges=yes','UMask=0077','RestrictAddressFamilies=AF_UNIX']
caps='CAP_DAC_READ_SEARCH CAP_DAC_OVERRIDE CAP_FOWNER CAP_CHOWN CAP_SYS_PTRACE'+(' CAP_SYS_ADMIN' if phase=='close' else '')
propset.extend(['CapabilityBoundingSet='+caps,'AmbientCapabilities='+caps])
need(props(unit,['LoadState'])['LoadState']=='not-found','spent unit')
fit=put(dest/'authorization.json',dict(fit=cap,allocation=allocation,source=COMMIT,verified_remote_head=head,sealed=sealed,provenance=ref(seal/'provenance.json'),build=build_binding,qualification=real_binding,original_stop=terminal,launch_controller=control,existing_guest_references=references,retained_control_cap=retained,retained_usage=usage,replay_authority=False,capacity_credit=0,unit=unit,phase=phase,properties=propset))
sp.run(['systemd-run','--quiet','--unit='+unit,*['--property='+s for s in propset],str(image),'--'+phase],check=True)
m=props(unit,['Id','InvocationID','MainPID','ActiveState','SubState','ExecStart','Restart','NRestarts','Job','MemoryMax','MemorySwapMax','TasksMax','ControlGroup'])
iid=m['InvocationID'];pid=int(m['MainPID']);g=CG/unit
need(m['ActiveState']=='active' and m['SubState']=='running' and re.fullmatch('[0-9a-f]{32}',iid) and pid>1 and os.path.samefile('/proc/'+str(pid)+'/exe',image) and (Path('/proc')/str(pid)/'cmdline').read_bytes().rstrip(b'\0').split(b'\0')==[os.fsencode(image),os.fsencode('--'+phase)],'waiting native child')
need((g/'memory.max').read_text().strip()==str(256*M) and (g/'memory.swap.max').read_text().strip()=='0' and (g/'cpu.max').read_text().strip()=='100000 100000' and (g/'pids.max').read_text().strip()=='16' and os.sched_getaffinity(pid)=={8} and m['Job']=='' and m['Restart']=='no' and m['NRestarts']=='0','kernel first guard')
assert m['Id']==unit and m['ControlGroup']=='/system.slice/'+unit and (Path('/proc',str(pid),'cgroup')).read_text().strip()=='0::/system.slice/'+unit and (g/'memory.high').read_text().strip()==str(160*M) and str(pid) in (g/'cgroup.procs').read_text().split()
booking=put(state/'bookings'/(iid+'.json'),dict(authorization=fit,pid=pid,invocation=iid,manager=m,phase=phase,job_launch=False))
grant='\n'.join(['horizon266-stopped-first-guard-v1',unit,iid,phase,str(int(time.time())+110),build['image']['sha256'],booking['sha256'],'cf0b9ea9a89f287b8259d86222415e6c613222db4f224e9350acf50e0eba8d38'])+'\n'
write(grants/iid,grant.encode());print('issued',unit,iid,flush=True)
# Wait for this phase's actual manager terminal only. Never start the next phase here.
start=time.monotonic()
while g.exists() and time.monotonic()-start<(1250 if phase=='retire' else 470):time.sleep(5)
need(not g.exists(),'phase cgroup still present')
history=[json.loads(x) for x in sp.check_output(['journalctl','-b','--no-pager','-o','json','_PID=1','_UID=0','UNIT='+unit,'INVOCATION_ID='+iid]).splitlines()]
h=put(dest/'pid1.json',history);record=state/(phase+'-confirmed-'+iid)
need(record.is_file() and any(x.get('MESSAGE_ID')=='7ad2d189f7e94e70a38c781354912448' and x.get('UNIT_RESULT','success')=='success' for x in history),'missing confirmed exit')
print(put(dest/'completion.json',dict(phase=phase,exact_state=ref(record),manager=h,authorization=fit,booking=booking,initial_guard=ref(grants/iid),source=COMMIT,extra_archive_publications=0)),flush=True)
