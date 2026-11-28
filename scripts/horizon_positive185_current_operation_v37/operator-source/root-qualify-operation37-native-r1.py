from pathlib import Path
import json,os,hashlib,subprocess,time,shutil
p=Path('/home/sol/.jetstreamer-private/epoch185-operation37-final4-layout-qa-20261109-v1');packet=Path('/tmp/operation37-final4-directories-and-reader-retirement-source-20261109-v1');source=json.loads((packet/'ROOT_NATIVE_CONTROL_RECIPES.NOT_EXECUTED.json').read_text());proposed='/home/sol/.jetstreamer-private/epoch185-positive-current-operation37-final4-layout-qa-20261109-v1';sha=lambda f:hashlib.sha256(Path(f).read_bytes()).hexdigest();b=lambda f:dict(path=str(f),sha256=sha(f))
def save(n,v):
 fd=os.open(p/n,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(fd,'w') as f:json.dump(v,f,indent=2);f.flush();os.fsync(f.fileno())
 fd=os.open(p,os.O_DIRECTORY);os.fsync(fd);os.close(fd)
def run(label,a,timeout=330):
 save(label+'-ORIGINAL-ARGV.json',a);print('BEGIN',label,flush=True);z=subprocess.run(a,capture_output=True,text=True,timeout=timeout);save(label+'-ORIGINAL-EXECUTION.json',dict(code=z.returncode,stdout=z.stdout,stderr=z.stderr));print(label,z.returncode,z.stdout[-1400:],z.stderr[-1200:],flush=True);assert z.returncode==0,label;return z
sealer='/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment';h='e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3';assert sha(sealer)==h;os.umask(0o022)
def seal(label,dest,files):
 save(label+'-SEAL-PLAN.json',dict(schema='jetstreamer-sealed-deployment-plan-v1',destination=dest,members=[dict(source=str(f),name=n,sha256=sha(f),mode=m) for f,n,m in files]));f=p/(label+'-SEAL-PLAN.json');run(label+'-SEAL',[sealer,str(f),'--plan-sha256',sha(f),'--self-sha256',h])
test=Path('/usr/local/lib/jetstreamer/horizon-positive185-current-operation-tests-20261109-v37-final4-layout-r1/tests');candidate=Path('/usr/local/lib/jetstreamer/horizon-positive185-current-operation-candidate-20261109-v37-final4-layout-r1/operation')
seal('TEST',str(test.parent),[(p/'qa/planner-tests','tests',0o555)])
base=json.loads(Path('/home/sol/.jetstreamer-private/epoch185-positive-current-operation36-planner5-qa-20261108-v1/ORDINARY-ORIGINAL-ARGV.json').read_text());base=[x.replace('/home/sol/.jetstreamer-private/epoch185-positive-current-operation36-planner5-qa-20261108-v1',str(p)) for x in base];base=[str(test) if x.endswith('/tests') and 'current-operation-tests-' in x else '--unit=horizon-operation37-ordinary-20261109-v1' if x.startswith('--unit=') else x for x in base]
z=run('ORDINARY',base);assert '66 passed; 0 failed; 3 ignored;' in z.stdout
save('STATIC-QUALIFIED-NATIVE-PENDING.json',dict(schema='horizon-positive185-upstream-static-qualified-native-control-pending-v1',production_artifact=b(p/'qa/planner'),exact_source_and_compiler_graph=b(p/'SOURCE_AND_EXACT4_FROZEN_RECIPES.json'),ordinary_tests_passed=66,ignored_tests=3,prod_clippy_passed=True,test_clippy_passed=True,all_required_tests_passed=False,replay_launch_authorized=False,publication_authorized=False))
seal('CANDIDATE',str(candidate.parent),[(p/'qa/planner','operation',0o555),(p/'STATIC-QUALIFIED-NATIVE-PENDING.json','artifact-proof.json',0o444)])
for name in ['requests','controls']:shutil.copytree(packet/name,p/name)
replacements={'__ROOT_NORMALLY_SEALED_OPERATION37_PROGRAM_PATH__':str(candidate),'__ROOT_QUALIFIED_OPERATION37_SHA256__':sha(candidate),'__ROOT_NORMALLY_SEALED_OPERATION37_TEST_IMAGE__':str(test)}
def adapt(x):
 if isinstance(x,str):return replacements.get(x,x).replace(proposed,str(p))
 if isinstance(x,list):return [adapt(v) for v in x]
 if isinstance(x,dict):return {k:adapt(v) for k,v in x.items()}
 return x
# Disjoint disposable timer, with seven actual protective policies retained across its manager link.
plan=adapt(json.loads((packet/'FRESH_TIMER_CONTROL_SEAL_PLAN.NOT_EXECUTED.json').read_text()));files=[(Path(v['source']),v['name'],v['mode']) for v in plan['members']];seal('CONTROL',plan['destination'],files)
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
before=policies();save('CONTROL-LINK-PROTECTIVE-POLICIES-BEFORE.json',before)
names=['horizon-operation32-coherence-disposable-20261108-v37-r1.'+e for e in ['service','timer']];run('CONTROL-LINK',['systemctl','link']+[plan['destination']+'/'+n for n in names]);after=policies();save('CONTROL-LINK-PROTECTIVE-POLICIES-AFTER.json',after)
assert {k:(v['identity_and_source'],v['intervals']) for k,v in before.items()}=={k:(v['identity_and_source'],v['intervals']) for k,v in after.items()}
(p/'qa/actual-timer-native-evidence').mkdir(mode=0o700);run('CONTROL-FIRST-TIMER-START',['systemctl','start',names[1]])
barrier=None;until=time.monotonic()+3
while time.monotonic()<until:
 n=dict(x.split('=',1) for x in subprocess.check_output(['systemctl','show',names[0],'-pActiveState,SubState,MainPID,InvocationID,ExecMainStartTimestampMonotonic'],text=True).splitlines())
 if n['ActiveState']=='activating' and n['SubState']=='start' and int(n['MainPID'])>1 and len(n['InvocationID'])==32:barrier=n;break
 time.sleep(.05)
assert barrier,'No original running oneshot; no refire';save('CONTROL-FIRST-ORIGINAL-FIRE-BARRIER.json',barrier)
timer=source['ignored_tests'][-1];run(timer['label'],adapt(timer['argv']));run('CONTROL-OWN-TIMER-STOP',['systemctl','stop',names[1]])
for row in source['ignored_tests'][:-1]:run(row['label'],adapt(row['argv']))
results={}
# Authenticate the actual fixed layout before the rest of the native route qualification.
controls=source['qualification_controls'];controls=[x for x in controls if x['label']=='ACTUAL-RUN-LAYOUT-CONTROL']+[x for x in controls if x['label']!='ACTUAL-RUN-LAYOUT-CONTROL']
for row in controls:
 label=row['label'];request=json.loads(Path(row['request_template']['path']).read_text())
 if label=='PROFILE-R3':request['reader_lifecycle_control']=results['ACTUAL-READER-CONTROL']['members']['completion.json']
 Path(request['operation_root']).mkdir(mode=0o700);req=p/(label+'-REQUEST.json');save(req.name,request);argv=adapt(row['argv']);i=argv.index(row['mode']);argv[i+1]=str(req);argv[argv.index('--request-sha256')+1]=sha(req);argv[argv.index('--self-sha256')+1]=sha(candidate);z=run(label,argv);results[label]=json.loads(z.stdout)
save('ALL_ELEVEN_ORIGINAL_NATIVE_CONTROLS_PASSED.json',dict(labels=[x['label'] for x in source['ignored_tests']]+[x['label'] for x in controls],results=results,ordinary_passed=66,ignored_passed=3,actual_unprivileged_layout_passed=True,actual_Final4_profile_and_eight_file_read_passed=True,no_replay_or_publication=True));print('OPERATION37_ALL_ELEVEN_NATIVE_CONTROLS_PASSED',flush=True)
