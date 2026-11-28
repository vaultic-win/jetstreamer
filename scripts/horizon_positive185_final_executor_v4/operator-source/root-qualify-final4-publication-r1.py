from pathlib import Path
import json,os,subprocess,hashlib
p=Path('/home/sol/.jetstreamer-private/epoch185-final4-guard-publication-qa-20261109-v1');sha=lambda f:hashlib.sha256(Path(f).read_bytes()).hexdigest();b=lambda f:dict(path=str(f),sha256=sha(f))
def save(n,v):
 f=os.open(p/n,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(f,'w') as h:json.dump(v,h,indent=2);h.flush();os.fsync(h.fileno())
 f=os.open(p,os.O_DIRECTORY);os.fsync(f);os.close(f)
assert (p/'ALL_FOUR_ORIGINAL_COMPILERS_PASSED.json').exists();s='/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment';h='e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3';assert sha(s)==h;os.umask(0o022)
def seal(label,dest,files):
 plan=dict(schema='jetstreamer-sealed-deployment-plan-v1',destination=dest,members=[dict(source=str(f),name=n,sha256=sha(f),mode=m) for f,n,m in files]);save(label+'-SEAL-PLAN.json',plan);path=p/(label+'-SEAL-PLAN.json');z=subprocess.run([s,str(path),'--plan-sha256',sha(path),'--self-sha256',h],capture_output=True,text=True);save(label+'-SEAL-EXECUTION.json',dict(code=z.returncode,stdout=z.stdout,stderr=z.stderr));assert z.returncode==0,z.stderr
pkg=Path('/usr/local/lib/jetstreamer/horizon-positive185-final-tests-20261109-v4-closed-write');seal('TEST',str(pkg),[(p/'work/planner-tests','tests',0o555)])
base=['systemd-run','--wait','--pipe','--service-type=exec']
for prop in ['User=root','Group=root','UMask=0022','Restart=no','MemoryMax=512M','MemorySwapMax=0','TasksMax=128','RuntimeMaxSec=120','NoNewPrivileges=yes','PrivateNetwork=yes','ProtectSystem=strict','ProtectHome=read-only','CapabilityBoundingSet=CAP_DAC_OVERRIDE','AmbientCapabilities=CAP_DAC_OVERRIDE','ReadWritePaths='+str(p/'work')]:base+=['-p',prop]
base+=['--setenv=TMPDIR='+str(p/'work/tmp')]
originals=[]
def run(label,args):
 argv=base+['--unit=horizon-positive185-final4-'+label+'-20261109-v1',str(pkg/'tests')]+args;save(label+'-ORIGINAL-ARGV.json',argv);z=subprocess.run(argv,capture_output=True,text=True,timeout=130);save(label+'-ORIGINAL-EXECUTION.json',dict(code=z.returncode,stdout=z.stdout,stderr=z.stderr));print(label,z.returncode,z.stdout[-1800:],z.stderr[-1000:],flush=True);assert z.returncode==0,label;originals.append(b(p/(label+'-ORIGINAL-EXECUTION.json')));return z
allnames=[x[:-6] for x in run('census-all',['--list']).stdout.splitlines() if x.endswith(': test')];ignored=[x[:-6] for x in run('census-ignored',['--ignored','--list']).stdout.splitlines() if x.endswith(': test')];assert len(allnames)==32 and len(ignored)==4
z=run('ordinary',['--test-threads=1']);assert '28 passed; 0 failed; 4 ignored;' in z.stdout
for i,name in enumerate(ignored):
 assert name.startswith('events::publication_native_tests::');z=run('native-'+str(i),[name,'--ignored','--exact','--nocapture','--test-threads=1']);assert '1 passed; 0 failed;' in z.stdout
for label in ['clippy-production','clippy-tests','test-build','release']:
 argv=json.loads((p/(label+'-ORIGINAL-ARGV.json')).read_text());unit=next(x.split('=',1)[1] for x in argv if x.startswith('--unit='))+'.service';n=dict(x.split('=',1) for x in subprocess.check_output(['systemctl','show',unit,'-pMainPID,ControlPID,NRestarts,Result,ExecMainStatus,ControlGroup,Job'],text=True).splitlines());assert n['MainPID']==n['ControlPID']==n['NRestarts']==n['ExecMainStatus']=='0' and n['Result']=='success' and n['Job']==n['ControlGroup']==''
proof=dict(schema='horizon-positive185-final4-closed-write-qualified-v1',production_artifact=b(p/'work/planner'),exact_source_and_compiler_graph=b(p/'SOURCE_AND_EXACT4_FROZEN_RECIPES.json'),actual_test_binary=b(pkg/'tests'),ordinary_tests_passed=28,ignored_tests=4,all_four_ignored_native_publication_controls_passed=True,ordinary_and_native_originals=originals,actual_census=allnames,actual_ignored_census=ignored,prod_clippy_passed=True,test_clippy_passed=True,all_required_tests_passed=True,all_original_actors_terminal_and_drained=True,Driver11_and_qualified_helper_policy_unchanged=True,original_setup_final_token_clocks_unchanged=True,failed_guard_still_rejected=True,replay_launch_authorized=False,publication_authorized=False,memory_credit_bytes=0,DATA_credit_bytes=0,normal_pool_bytes=6<<30,complete_DATA_bytes=5163504841364)
save('ARTIFACT-PROOF.json',proof);dest=Path('/usr/local/lib/jetstreamer/horizon-positive185-final-transaction-tools-20261109-v4');seal('PRODUCTION',str(dest),[(p/'work/planner','horizon-positive185-final',0o555),(p/'ARTIFACT-PROOF.json','artifact-proof.json',0o444),(p/'SOURCE_AND_EXACT4_FROZEN_RECIPES.json','exact-source-and-recipes.json',0o444)])
manifest=dict(program=b(dest/'horizon-positive185-final'),qualification=b(dest/'artifact-proof.json'),normal_seal=b(dest/'deployment-seal-receipt.json'),booking=b(p/'ROOT_NORMAL6_FINAL4_DATA512_BOOKING.json'),complete_DATA_bytes=5163504841364,native_event_publication_controls_passed=True,actual_fresh_guard_and_native_launch_still_required=True)
save('ROOT_ACTUAL_QUALIFIED_FINAL4_BINDINGS.json',manifest);print('FINAL4_QUALIFIED',json.dumps(manifest),flush=True)
