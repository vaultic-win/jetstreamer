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
replacements={'__ROOT_NORMALLY_SEALED_OPERATION38_PROGRAM_PATH__':str(candidate),'__ROOT_QUALIFIED_OPERATION38_SHA256__':sha(candidate),'__ROOT_NORMALLY_SEALED_OPERATION38_TEST_IMAGE__':str(test)}
def adapt(x):
 if isinstance(x,str):return replacements.get(x,x)
 if isinstance(x,list):return[adapt(v)for v in x]
 if isinstance(x,dict):return{k:adapt(v)for k,v in x.items()}
 return x
results={};controls=source['qualification_controls'];controls=[x for x in controls if x['label']=='ACTUAL-RUN-LAYOUT-CONTROL']+[x for x in controls if x['label']!='ACTUAL-RUN-LAYOUT-CONTROL']
for row in controls:
 label=row['label'];f=Path(row['request']['path']);assert sha(f)==row['request']['sha256'];request=json.loads(f.read_text())
 if label=='ACTUAL-RUN-LAYOUT-CONTROL':
  request['generation']='positive-layout-v38-r2'
  for k in ['operation_root','layout_sol_run_root','layout_sol_control_root']:request[k]=request[k]+'-r2'
  label='ACTUAL-RUN-LAYOUT-CONTROL-R2'
 if label=='PROFILE-R3':request['reader_lifecycle_control']=results['ACTUAL-READER-CONTROL']['members']['completion.json']
 Path(request['operation_root']).mkdir(mode=0o700);req=p/(label+'-REQUEST.json');save(req.name,request);argv=adapt(row['argv']);i=argv.index(row['mode']);argv[i+1]=str(req);argv[argv.index('--request-sha256')+1]=sha(req);argv[argv.index('--self-sha256')+1]=sha(candidate);z=run(label,argv);results[row['label']]=json.loads(z.stdout)
save('ALL_THIRTEEN_ORIGINAL_NATIVE_CONTROLS_PASSED.json',dict(labels=[x['label']for x in source['ignored_controls']]+[x['label']for x in controls],results=results,ordinary_passed=71,ignored_passed=5,actual_unprivileged_layout_passed=True,actual_Final6_profile_and_eight_file_read_passed=True,executions=executions,no_replay_or_publication=True));print('OPERATION38_ALL_THIRTEEN_NATIVE_CONTROLS_PASSED',flush=True)
