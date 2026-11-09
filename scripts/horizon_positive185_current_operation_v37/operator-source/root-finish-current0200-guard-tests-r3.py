from pathlib import Path
import os,json,hashlib,subprocess,re
packet=Path('/tmp/root-current0200-window-source-20261109-v2');v=json.loads((packet/'SOURCE_ONLY_MANIFEST.json').read_text());p=Path(v['root_QA_directory']);sha=lambda raw:hashlib.sha256(raw).hexdigest();b=lambda f:dict(path=str(f),sha256=sha(Path(f).read_bytes()))
def save(n,x):
 fd=os.open(p/n,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(fd,'w') as f:json.dump(x,f,indent=2);f.flush();os.fsync(f.fileno())
 fd=os.open(p,os.O_DIRECTORY);os.fsync(fd);os.close(fd)
originals=[]
def accept(label,argv,execution):
 unit=next(x.split('=',1)[1] for x in argv if x.startswith('--unit='))+'.service'
 n=dict(x.split('=',1) for x in subprocess.check_output(['systemctl','show',unit,'-pMainPID,ControlPID,ControlGroup,NRestarts,Result,ExecMainStatus'],text=True).splitlines());assert n['MainPID']==n['ControlPID']==n['NRestarts']==n['ExecMainStatus']=='0' and n['Result']=='success' and n['ControlGroup']==''
 lower=(p/(label+'-ORIGINAL-ARGV.json')).stat().st_mtime_ns//1000;upper=execution.stat().st_mtime_ns//1000+2000000
 rows=[json.loads(x) for x in subprocess.check_output(['journalctl','--all','--no-pager','-ojson','-u',unit],text=True).splitlines()];done=[r for r in rows if lower<=int(r.get('__REALTIME_TIMESTAMP','0'))<=upper and r.get('_PID')=='1' and r.get('_UID')=='0' and r.get('UNIT')==unit and r.get('MESSAGE_ID')=='7ad2d189f7e94e70a38c781354912448'];assert len(done)==1
 originals.append(dict(execution=b(execution),original_native=n,original_PID1_success=done[0],original_outer_reaped=True,original_cgroup_empty=True))
for stage in v['recipes']:
 argv=json.loads((p/(stage+'-ORIGINAL-ARGV.json')).read_text());execution=p/(stage+'-ORIGINAL-EXECUTION.json');assert json.loads(execution.read_text())['code']==0;accept(stage,argv,execution)
counts={};old='/usr/local/lib/jetstreamer/horizon-current0200-bound-guard-window-tests-20261109-v1/guard-tests';new='/usr/local/lib/jetstreamer/horizon-current0200-bound-guard-window-tests-20261109-v1-root-r2/guard-tests'
for name in ['census-all','census-ignored','all61']:
 argv=json.loads((packet/'recipes'/(name+'-ARGV.UNSTARTED.json')).read_text())['argv'];argv=[new if x==old else x for x in argv];argv=[x+'-r3' if x.startswith('--unit=') else x for x in argv];label=name+'-R3';save(label+'-ORIGINAL-ARGV.json',argv);z=subprocess.run(argv,capture_output=True,text=True,timeout=330);save(label+'-ORIGINAL-EXECUTION.json',dict(code=z.returncode,stdout=z.stdout,stderr=z.stderr));print(label,z.returncode,z.stdout[-1400:],z.stderr[-800:],flush=True);assert z.returncode==0;accept(label,argv,p/(label+'-ORIGINAL-EXECUTION.json'))
 if name!='all61':counts[name]=[x[:-6] for x in z.stdout.splitlines() if x.endswith(': test')]
 else:assert len(counts['census-all'])==65 and not counts['census-ignored'] and '65 passed; 0 failed; 0 ignored;' in z.stdout
proof=dict(schema='horizon-current0200-qualified-guard-v1',source=b(p/'source/main.rs'),production=b(p/'work/horizon-current0200-guard-window'),actual_test_census=counts,ordinary_tests_passed=65,all_original_61_names_preserved=True,all_original_actors_drained=True,prod_clippy_passed=True,test_clippy_passed=True,all_required_tests_passed=True,originals=originals,sample_utc=v['sample_utc'],sample_unix=v['sample_unix'],native_guard_window_still_required=True,replay_launch_authorized=False,memory_credit_bytes=0,DATA_credit_bytes=0,changed_recovery='R1numeric Rust literal still0130; R2correctedonlyactualSAMPLE_UNIX to0200 but nativeargv selected oldR1test image. R3uses existinggenuineR2fourcompilers and its separatelynormallysealedtestimage; no recompilation,reset,bookingreusecredit or rewrittenfailures.')
save('work/ARTIFACT_PROOF_BEFORE_SEAL.json',proof)
plan=json.loads((packet/'PRODUCTION_NORMAL_SEAL_PLAN.UNSTARTED.json').read_text());
for row in plan['members']:row['sha256']=b(row['source'])['sha256']
save('PRODUCTION-R3-NORMAL-SEAL-PLAN.json',plan);path=p/'PRODUCTION-R3-NORMAL-SEAL-PLAN.json';sealer='/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment';h='e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3';os.umask(0o022);z=subprocess.run([sealer,str(path),'--plan-sha256',b(path)['sha256'],'--self-sha256',h],capture_output=True,text=True);save('PRODUCTION-R3-NORMAL-SEAL-EXECUTION.json',dict(code=z.returncode,stdout=z.stdout,stderr=z.stderr));print(z.stdout,z.stderr);assert z.returncode==0;print('ACTUAL0200_GUARD_R2_SOURCE_R3_CORRECT_IMAGE_TESTS_QUALIFIED',flush=True)
