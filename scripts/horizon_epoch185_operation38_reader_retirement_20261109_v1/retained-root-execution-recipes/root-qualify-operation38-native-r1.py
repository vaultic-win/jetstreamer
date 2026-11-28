from pathlib import Path
import json,os,hashlib,subprocess,time,shutil,re,datetime
p=Path('/home/sol/.jetstreamer-private/epoch185-operation38-driver12-helper35-qa-20261109-v1');packet=Path('/tmp/operation38-driver12-helper35-source-20261109-v1');source=json.loads((packet/'NATIVE_CONTROL_RECIPES.NOT_EXECUTED.json').read_text());sha=lambda f:hashlib.sha256(Path(f).read_bytes()).hexdigest();b=lambda f:dict(path=str(f),sha256=sha(f))
def save(n,v):
 fd=os.open(p/n,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(fd,'w')as f:json.dump(v,f,indent=2);f.flush();os.fsync(f.fileno())
 fd=os.open(p,os.O_DIRECTORY);os.fsync(fd);os.close(fd)
assert (p/'ALL_FOUR_R3_ORIGINAL_COMPILERS_PASSED.json').exists()
executions=[]
def run(label,a,timeout=330):
 save(label+'-ORIGINAL-ARGV.json',a);print(datetime.datetime.now(datetime.timezone.utc).isoformat(),'BEGIN',label,flush=True);z=subprocess.run(a,capture_output=True,text=True,timeout=timeout);save(label+'-ORIGINAL-EXECUTION.json',dict(argv=a,code=z.returncode,stdout=z.stdout,stderr=z.stderr));print(label,z.returncode,z.stdout[-1800:],z.stderr[-2200:],flush=True);assert z.returncode==0,label;executions.append(b(p/(label+'-ORIGINAL-EXECUTION.json')));return z
sealer='/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment';h='e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3';assert sha(sealer)==h;os.umask(0o022)
def seal(label,dest,files):
 save(label+'-SEAL-PLAN.json',dict(schema='jetstreamer-sealed-deployment-plan-v1',destination=str(dest),members=[dict(source=str(f),name=n,sha256=sha(f),mode=m)for f,n,m in files]));f=p/(label+'-SEAL-PLAN.json');run(label+'-SEAL',[sealer,str(f),'--plan-sha256',sha(f),'--self-sha256',h])
test=Path('/usr/local/lib/jetstreamer/horizon-positive185-current-operation-tests-20261109-v38-driver12-helper35-r1/tests');candidate=Path('/usr/local/lib/jetstreamer/horizon-positive185-current-operation-candidate-20261109-v38-driver12-helper35-r1/operation')
seal('TEST',test.parent,[(p/'qa/r3/planner-tests','tests',0o555)])
base=['systemd-run','--wait','--pipe','--service-type=exec']
for prop in ['User=root','Group=root','Restart=no','MemoryMax=512M','MemorySwapMax=0','TasksMax=128','RuntimeMaxSec=120','NoNewPrivileges=yes','PrivateNetwork=yes','ProtectSystem=strict','ProtectHome=read-only','CapabilityBoundingSet=CAP_DAC_OVERRIDE','AmbientCapabilities=CAP_DAC_OVERRIDE']:base+=['-p',prop]
base+=['--unit=horizon-operation38-ordinary-20261109-v1',str(test)]
allz=run('CENSUS-ALL',base[:-2]+['--unit=horizon-operation38-census-all-20261109-v1',str(test),'--list']);names=[x[:-6]for x in allz.stdout.splitlines()if x.endswith(': test')];z=run('ORDINARY',base+['--test-threads=1']);match=re.search(r'test result: ok\. (\d+) passed; 0 failed; (\d+) ignored;',z.stdout);assert match and int(match[1])==71 and int(match[2])==5 and len(names)==76
save('STATIC-QUALIFIED-NATIVE-PENDING.json',dict(schema='horizon-positive185-upstream-static-qualified-native-control-pending-v1',production_artifact=b(p/'qa/r3/planner'),exact_source_and_compiler_graph=b(p/'SOURCE_AND_EXACT4_FROZEN_RECIPES_R3.json'),ordinary_tests_passed=71,ignored_tests=5,prod_clippy_passed=True,test_clippy_passed=True,all_required_tests_passed=False,replay_launch_authorized=False,publication_authorized=False))
seal('CANDIDATE',candidate.parent,[(p/'qa/r3/planner','operation',0o555),(p/'STATIC-QUALIFIED-NATIVE-PENDING.json','artifact-proof.json',0o444)])
for name in ['requests','controls']:shutil.copytree(packet/name,p/name)
replacements={'__ROOT_NORMALLY_SEALED_OPERATION38_PROGRAM_PATH__':str(candidate),'__ROOT_QUALIFIED_OPERATION38_SHA256__':sha(candidate),'__ROOT_NORMALLY_SEALED_OPERATION38_TEST_IMAGE__':str(test)}
def adapt(x):
 if isinstance(x,str):return replacements.get(x,x)
 if isinstance(x,list):return[adapt(v)for v in x]
 if isinstance(x,dict):return{k:adapt(v)for k,v in x.items()}
 return x
plan=json.loads((packet/'FRESH_TIMER_CONTROL_SEAL_PLAN.NOT_EXECUTED.json').read_text());files=[]
for v in plan['members']:assert sha(v['source'])==v['sha256'];files.append((Path(v['source']),v['name'],v['mode']))
seal('CONTROL',plan['destination'],files)
protect=['horizon-guard145-prefix-shared72h-20261107-v8g1.timer','horizon-guard145-prefix-real1328-20261106-v1.timer','jetstreamer-adaptive-reserve-epoch199-backfill-20261102-v1.timer','jetstreamer-adaptive-reserve-controller-rebind-183-184-20261023-v1.timer','jetstreamer-adaptive-reserve-memory152-recovery-20261024-v1.timer','jetstreamer-adaptive-reserve-controller-rebind-155-156-20261023-v1.timer','jetstreamer-adaptive-reserve-package-rebind-198-20261021-v1.timer']
def policies():
 out={}
 for u in protect:
  raw=subprocess.check_output(['systemctl','show',u,'-pId,InvocationID,ActiveState,Unit,FragmentPath,TimersMonotonic,LastTriggerUSecMonotonic,NextElapseUSecMonotonic'],text=True);row={};intervals=[]
  for line in raw.splitlines():
   k,v=line.split('=',1)
   if k=='TimersMonotonic':intervals.append(v.split(' ; next_elapse=',1)[0])
   elif k not in ['LastTriggerUSecMonotonic','NextElapseUSecMonotonic']:row[k]=v
  out[u]=dict(identity_and_source=row,intervals=sorted(intervals),raw=raw)
 return out
before=policies();save('CONTROL-LINK-PROTECTIVE-POLICIES-BEFORE.json',before);unitnames=['horizon-operation32-coherence-disposable-20261108-v38-r1.'+e for e in ['service','timer']];run('CONTROL-LINK',['systemctl','link']+[plan['destination']+'/'+n for n in unitnames]);after=policies();save('CONTROL-LINK-PROTECTIVE-POLICIES-AFTER.json',after);assert{k:(v['identity_and_source'],v['intervals'])for k,v in before.items()}=={k:(v['identity_and_source'],v['intervals'])for k,v in after.items()}
(p/'qa/actual-timer-native-evidence').mkdir(mode=0o700);run('CONTROL-FIRST-TIMER-START',['systemctl','start',unitnames[1]]);barrier=None;until=time.monotonic()+3
while time.monotonic()<until:
 n=dict(x.split('=',1)for x in subprocess.check_output(['systemctl','show',unitnames[0],'-pActiveState,SubState,MainPID,InvocationID,ExecMainStartTimestampMonotonic'],text=True).splitlines())
 if n['ActiveState']=='activating'and n['SubState']=='start'and int(n['MainPID'])>1 and len(n['InvocationID'])==32:barrier=n;break
 time.sleep(.05)
assert barrier,'No original running oneshot; no refire';save('CONTROL-FIRST-ORIGINAL-FIRE-BARRIER.json',barrier)
timer=next(x for x in source['ignored_controls']if x['label']=='ACTUAL-TIMER-COHERENCE-CONTROL');run(timer['label'],adapt(timer['argv']));run('CONTROL-OWN-TIMER-STOP',['systemctl','stop',unitnames[1]])
for row in source['ignored_controls']:
 if row['label']!=timer['label']:run(row['label'],adapt(row['argv']))
results={};controls=source['qualification_controls'];controls=[x for x in controls if x['label']=='ACTUAL-RUN-LAYOUT-CONTROL']+[x for x in controls if x['label']!='ACTUAL-RUN-LAYOUT-CONTROL']
for row in controls:
 label=row['label'];f=Path(row['request']['path']);assert sha(f)==row['request']['sha256'];request=json.loads(f.read_text())
 if label=='PROFILE-R3':request['reader_lifecycle_control']=results['ACTUAL-READER-CONTROL']['members']['completion.json']
 Path(request['operation_root']).mkdir(mode=0o700);req=p/(label+'-REQUEST.json');save(req.name,request);argv=adapt(row['argv']);i=argv.index(row['mode']);argv[i+1]=str(req);argv[argv.index('--request-sha256')+1]=sha(req);argv[argv.index('--self-sha256')+1]=sha(candidate);z=run(label,argv);results[label]=json.loads(z.stdout)
save('ALL_THIRTEEN_ORIGINAL_NATIVE_CONTROLS_PASSED.json',dict(labels=[x['label']for x in source['ignored_controls']]+[x['label']for x in controls],results=results,ordinary_passed=71,ignored_passed=5,actual_unprivileged_layout_passed=True,actual_Final6_profile_and_eight_file_read_passed=True,executions=executions,no_replay_or_publication=True));print('OPERATION38_ALL_THIRTEEN_NATIVE_CONTROLS_PASSED',flush=True)
