from pathlib import Path
import os,json,subprocess,hashlib
p=Path('/home/sol/.jetstreamer-private/current0030-failed-reader-retirement-qa-20261109-v1');sha=lambda f:hashlib.sha256(Path(f).read_bytes()).hexdigest();b=lambda f:dict(path=str(f),sha256=sha(f))
def save(n,v):
 fd=os.open(p/n,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(fd,'w') as f:json.dump(v,f,indent=2);f.flush();os.fsync(f.fileno())
 fd=os.open(p,os.O_DIRECTORY);os.fsync(fd);os.close(fd)
proof=json.loads((p/'r2-ALL_FOUR_AND_ORDINARY_PASSED.json').read_text());assert proof['all_required_tests_passed']
control=json.loads(json.loads((p/'r2-NATIVE-CONTROL-EXECUTION.json').read_text())['stdout']);binding=control['native_control'];assert b(binding['path'])==binding and control['program_sha256']==sha(p/'qa/r2-retirement')
for label in list(proof['labels'])+['ordinary','native-control']:
 unit={'ordinary':'horizon-retire0030-tests-20261109-v2.service','native-control':'horizon-retire0030-native-control-20261109-v2.service'}.get(label,f'horizon-retire0030-compiler-{label}-20261109-v2.service')
 n=dict(x.split('=',1) for x in subprocess.check_output(['systemctl','show',unit,'-pMainPID,ControlPID,ControlGroup,Job,NRestarts,Result,ExecMainStatus'],text=True).splitlines());assert n['MainPID']==n['ControlPID']==n['NRestarts']==n['ExecMainStatus']=='0' and n['ControlGroup']==n['Job']=='' and n['Result']=='success',n
save('ROOT_ALL_REQUIRED_COMPILERS_ORDINARY_AND_NATIVE_DRAINED.json',dict(proof=b(p/'r2-ALL_FOUR_AND_ORDINARY_PASSED.json'),native_control=binding,all_required_tests_passed=True,original_failed_native_control=b(p/'NATIVE-CONTROL-EXECUTION.json'),changed_recovery='First nestedsystemd-run failed ETOOMANYREFS before child existed. Retained original; r2 nativeouter uses LimitNOFILE1048576 inherited by child. Original productionreader unchanged.',no_replay_or_publication=True))
os.umask(0o022);s=Path('/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment');h='e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3';assert sha(s)==h
dest=Path('/usr/local/lib/jetstreamer/horizon-exact0030-transient-reader-retirement-tools-20261109-v1')
files=[(p/'qa/r2-retirement','retirement',0o555),(Path(binding['path']),'native-control.json',0o444),(p/'ROOT_ALL_REQUIRED_COMPILERS_ORDINARY_AND_NATIVE_DRAINED.json','artifact-proof.json',0o444),(p/'r2-SOURCE_AND_EXACT4_FROZEN_RECIPES.json','exact-source-and-recipes.json',0o444)]
plan=dict(schema='jetstreamer-sealed-deployment-plan-v1',destination=str(dest),members=[dict(source=str(f),name=n,sha256=sha(f),mode=m) for f,n,m in files]);save('PRODUCTION-SEAL-PLAN.json',plan)
z=subprocess.run([str(s),str(p/'PRODUCTION-SEAL-PLAN.json'),'--plan-sha256',sha(p/'PRODUCTION-SEAL-PLAN.json'),'--self-sha256',h],capture_output=True,text=True);save('PRODUCTION-SEAL-EXECUTION.json',dict(code=z.returncode,stdout=z.stdout,stderr=z.stderr));print(z.stdout,z.stderr,flush=True);assert z.returncode==0
argv=json.loads((p/'r2-NATIVE-CONTROL-ARGV.json').read_text());argv=[x.replace('horizon-retire0030-native-control-20261109-v2','horizon-retire0030-actual-retirement-20261109-v1').replace('/usr/local/lib/jetstreamer/horizon-exact0030-transient-reader-retirement-candidate-20261109-v2/retirement',str(dest/'retirement')) for x in argv];argv[argv.index('qualify')]='retire0030';save('ACTUAL-RETIREMENT-ARGV.json',argv)
assert sha('/home/sol/.jetstreamer-private/epoch185-positive-upstream-current0030-reader-phase-20261109-v15/94-actual-phase-gated-original-reader-original-outcome.json')=='84d880ee10cf1b8a3258cf5e5fdd7526f3bd58b9b30e40d29b2466c74233a13d'
z=subprocess.run(argv,capture_output=True,text=True,timeout=130);save('ACTUAL-RETIREMENT-EXECUTION.json',dict(code=z.returncode,stdout=z.stdout,stderr=z.stderr));print(z.stdout,z.stderr,flush=True);assert z.returncode==0
completion=json.loads(z.stdout)['actual_retirement'];assert b(completion['path'])==completion
save('ROOT_ACTUAL_QUALIFIED_TRANSIENT0030_READER_RETIREMENT.json',dict(program=b(dest/'retirement'),normal_seal=b(dest/'deployment-seal-receipt.json'),artifact=b(dest/'artifact-proof.json'),actual_retirement=completion,complete_DATA_bytes=5161894228628,booking=b(p/'ROOT_NORMAL6_RETIRE0030_DATA512_BOOKING.json'),no_replay_or_publication_authority=True));print('ORIGINAL0030_FAILURE_PRESERVED_AND_FAILED_TRANSIENT_RETIRED',flush=True)
