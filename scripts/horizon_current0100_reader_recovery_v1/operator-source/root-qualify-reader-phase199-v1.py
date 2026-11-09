from pathlib import Path
import os,json,subprocess,hashlib
p=Path('/home/sol/.jetstreamer-private/current-reader-phase199-recovery-qa-20261109-v1');old=Path('/home/sol/.jetstreamer-private/epoch185-positive-current-operation36-planner5-qa-20261108-v1');sha=lambda f:hashlib.sha256(Path(f).read_bytes()).hexdigest();b=lambda f:dict(path=str(f),sha256=sha(f))
def save(n,v):
 fd=os.open(p/n,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(fd,'w') as f:json.dump(v,f,indent=2);f.flush();os.fsync(f.fileno())
 fd=os.open(p,os.O_DIRECTORY);os.fsync(fd);os.close(fd)
assert (p/'ALL_FOUR_ORIGINAL_COMPILERS_PASSED.json').exists()
sealer='/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment';h='e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3';assert sha(sealer)==h;os.umask(0o022)
def seal(label,dest,files):
 save(label+'-SEAL-PLAN.json',dict(schema='jetstreamer-sealed-deployment-plan-v1',destination=dest,members=[dict(source=str(f),name=n,sha256=sha(f),mode=m) for f,n,m in files]));f=p/(label+'-SEAL-PLAN.json');z=subprocess.run([sealer,str(f),'--plan-sha256',sha(f),'--self-sha256',h],capture_output=True,text=True);save(label+'-SEAL-EXECUTION.json',dict(code=z.returncode,stdout=z.stdout,stderr=z.stderr));assert z.returncode==0,z.stderr
proof=dict(schema='horizon-readonly-advisory-phase199-static-qualified-v1',production_artifact=b(p/'qa/planner'),exact_source_and_compiler_graph=b(p/'SOURCE_AND_EXACT4_FROZEN_RECIPES.json'),all_required_tests_passed=False,native_phase_pending=True,scope='Only qualifier/read-original timing route; admission/assembly/replay commands refused')
save('STATIC-QUALIFIED-NATIVE-PENDING.json',proof)
test='/usr/local/lib/jetstreamer/horizon-reader-phase199-tests-20261109-v1';candidate='/usr/local/lib/jetstreamer/horizon-reader-phase199-candidate-20261109-v1'
seal('TESTS',test,[(p/'qa/planner-tests','tests',0o555)])
seal('CANDIDATE',candidate,[(p/'qa/planner','operation',0o555),(p/'STATIC-QUALIFIED-NATIVE-PENDING.json','artifact-proof.json',0o444)])
a=json.loads((old/'ORDINARY-ORIGINAL-ARGV.json').read_text());a=[x.replace(str(old),str(p)).replace('/usr/local/lib/jetstreamer/horizon-positive185-current-operation-tests-20261108-v36-helper34-planner5-r1',test) for x in a];a=['--unit=horizon-reader-phase199-ordinary-20261109-v1' if x.startswith('--unit=') else x for x in a]
save('ORDINARY-ORIGINAL-ARGV.json',a);z=subprocess.run(a,capture_output=True,text=True,timeout=610);save('ORDINARY-ORIGINAL-EXECUTION.json',dict(code=z.returncode,stdout=z.stdout,stderr=z.stderr));print(z.stdout,z.stderr,flush=True);assert z.returncode==0 and '63 passed; 0 failed; 3 ignored;' in z.stdout
root=Path('/home/sol/.jetstreamer-private/epoch185-positive-upstream-advisory-phase199-qualification-20261109-v1');root.mkdir(mode=0o700);save('ACTUAL-READER-PHASE-REQUEST.json',dict(operation_root=str(root),generation='positive-reader-phase199-v1'))
a=json.loads((old/'ACTUAL-READER-PHASE-ORIGINAL-ARGV.json').read_text());a=[x.replace('horizon-positive185-reader-phase-actual-20261108-v36-helper34-planner5-r1','horizon-reader-phase199-native-qualification-20261109-v1').replace('/usr/local/lib/jetstreamer/horizon-positive185-current-operation-candidate-20261108-v36-helper34-planner5-r1',candidate).replace(str(old),str(p)) for x in a];a[a.index('--request-sha256')+1]=sha(p/'ACTUAL-READER-PHASE-REQUEST.json');a[a.index('--self-sha256')+1]=sha(p/'qa/planner');save('ACTUAL-NATIVE-PHASE-ARGV.json',a)
z=subprocess.run(a,capture_output=True,text=True,timeout=245);save('ACTUAL-NATIVE-PHASE-EXECUTION.json',dict(code=z.returncode,stdout=z.stdout,stderr=z.stderr));print(z.stdout,z.stderr,flush=True);assert z.returncode==0
proof.update(all_required_tests_passed=True,native_phase_pending=False,ordinary_tests_passed=63,ignored_tests=3,genuine_native_advisory_phase=json.loads(z.stdout),actual_native_phase_execution=b(p/'ACTUAL-NATIVE-PHASE-EXECUTION.json'),no_snapshot_equality_relaxed=True,no_guard_or_timer_mutation=True)
save('ARTIFACT-PROOF.json',proof);dest='/usr/local/lib/jetstreamer/horizon-reader-phase199-tools-20261109-v1';seal('PRODUCTION',dest,[(p/'qa/planner','operation',0o555),(p/'ARTIFACT-PROOF.json','artifact-proof.json',0o444),(p/'SOURCE_AND_EXACT4_FROZEN_RECIPES.json','exact-source-and-recipes.json',0o444)])
save('ROOT_ACTUAL_QUALIFIED_ADVISORY_PHASE199_BINDINGS.json',dict(program=b(Path(dest)/'operation'),qualification=b(Path(dest)/'artifact-proof.json'),normal_seal=b(Path(dest)/'deployment-seal-receipt.json'),complete_DATA_bytes=5162967970452,booking=b(p/'ROOT_NORMAL6_PHASE199_DATA512_BOOKING.json'),scope=proof['scope'],actual_reader_not_started=True));print('PHASE199_QUALIFIED_NOT_REPLAY',flush=True)
