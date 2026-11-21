import hashlib,json,os,re,stat,subprocess,sys
from pathlib import Path
work=Path(__file__).resolve().parents[2]
base=Path("/var/lib/jetstreamer/horizon_runtime_data/epoch170-retry10-guard384-20261121-v1")
build=sys.argv[2]
assert re.fullmatch(r"[0-9a-f]{32}",build)
proof=base/("build-"+build)
out=Path((proof/"build-dir").read_text().strip())
group=Path('/sys/fs/cgroup/system.slice/horizon-170-retry10-guard384-qualify.service')
sealer=Path('/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment')
sha_sealer='e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3'
code=sys.argv[1]
def sha(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def ref(p):return dict(path=str(p),sha256=sha(p))
def git(*args):return subprocess.check_output(['git','-c','safe.directory='+str(work),'-C',work,*args])
def durable(p,j):
 b=(json.dumps(j,sort_keys=True,indent=2)+'\n').encode()
 if p.exists():
  assert p.read_bytes()==b and p.stat().st_uid==0 and stat.S_IMODE(p.stat().st_mode)==0o400
  return
 with p.open('xb') as f:
  f.write(b);f.flush();os.fchmod(f.fileno(),0o400);os.fsync(f.fileno())
 d=os.open(p.parent,os.O_DIRECTORY);os.fsync(d);os.close(d)
def member(name,path,mode):return dict(name=name,source=str(path),sha256=sha(path),mode=mode)
def seal(where,members):
 fp=base/(where+'-seal-plan.json')
 plan={'schema':'jetstreamer-sealed-deployment-plan-v1','destination':str(base/where),'members':members}
 durable(fp,plan)
 if not (base/where).exists():
  subprocess.run([sealer,fp,'--plan-sha256',sha(fp),'--self-sha256',sha_sealer],check=True)
 p=base/where/'deployment-seal-receipt.json'; r=json.loads(p.read_bytes())
 assert r['destination']==str(base/where) and r['plan_sha256']==sha(fp) and r['sealer_sha256']==sha_sealer
 for m in members:
  q=base/where/m['name'];m0=q.stat();assert sha(q)==m['sha256'] and m0.st_uid==0 and stat.S_IMODE(m0.st_mode)==m['mode']
 return ref(p)
assert __debug__ and os.geteuid()==0 and (group/'cpu.max').read_text().split()==['100000','100000'] and int((group/'memory.max').read_text())==1<<30 and int((group/'memory.swap.max').read_text())==0
os.umask(0o077)
assert sha(sealer)==sha_sealer
git('merge-base','--is-ancestor',code,'origin/account-updates')
sources={}
for row in (proof/'sources').read_text().splitlines():
 digest,n=row.split('  ',1);assert sha(out/n)==digest==hashlib.sha256(git('show',code+':'+n)).hexdigest();sources[n]=digest
assert len(sources)>=10
log=(proof/'build.log').read_text()
assert '101 passed; 0 failed; 1 ignored' in log and '1 passed; 0 failed; 0 ignored' in log and 'original_namespace_receipts_and_all_precreated_roots ... ok' in log
assert 'Deactivated successfully' in subprocess.check_output(['journalctl','_PID=1','INVOCATION_ID='+build,'-o','cat','--no-pager'],text=True)
artifacts={Path(line.split("  ",1)[1]).name:line.split("  ",1)[0] for line in (proof/"artifacts").read_text().splitlines()}
assert set(artifacts)=={"guard","tests"} and all(sha(out/name)==h for name,h in artifacts.items())
build_source=work/'scripts/horizon_epoch166_guard_recovery_20261121_v1/build-guard.sh'
assert sha(build_source)==hashlib.sha256(git('show',code+':scripts/horizon_epoch166_guard_recovery_20261121_v1/build-guard.sh')).hexdigest()
j=dict(schema='horizon-170-384-native-guard-build-v1',commit=code,source_hashes=sources,artifact=ref(out/'guard'),test=ref(out/'tests'),script=ref(build_source),build_iid=build,captured_source=ref(proof/'sources'),qualification_log=ref(proof/'build.log'),test_count=102)
bp=base/'BUILD.json';durable(bp,j)
bseal=seal('tools',[member('guard',out/'guard',0o555),member('build.json',bp,0o444)])
old=base.parent/'epoch166-independent-cold-20261120-v1/staging/p0355/sealed-contract/contract.json'
assert sha(old)=='368731e6d8330b00a1b7d4e3613815cc59a9d4598d2a63f54a356550c29fe7d9'
c=json.loads(old.read_bytes())
seed=c['witness_set'];ss=c['witness_set_deployment_seal']
w=base/'NATIVE_WITNESS.json'
exe=base/'tools/guard'
if not w.exists():
 subprocess.run([exe,'--qualify-data-witness',seed['path'],'--seed-sha256',seed['sha256'],'--seal',ss['path'],'--seal-sha256',ss['sha256'],'--output',w,'--self-sha256',sha(exe)],check=True)
j=json.loads(w.read_bytes());assert (j['native_identity']['executable_sha256']==sha(exe) and j['native_identity']['executable']==str(exe) and j['allocation']['first']==j['allocation']['second'] and len(j['allocation']['first'])==12 and len(j['independent_roots_receipt']['receipts'])==3)
c['qualified_native_witness']=ref(w);cp=base/'qualified-contract.json';durable(cp,c)
cs=seal('contract',[member('contract.json',cp,0o444)])
binding={'contract':ref(base/'contract/contract.json'),'deployment_seal':cs}
profiles=[
 (166,'horizon-qualify-166-independent-recovery-20261121-v1.service','epoch166-independent-cold-20261120-v1','epoch166-independent-cold-recovery-20261121-v1',288),
 (167,'horizon-qualify-167-source-index-v1-20261121.service','epoch167-standard-lane-20261109-v1','epoch167-source-index-recovery-20261121-v1',512),
 (170,'horizon-qualify-170-replacement-local3retry10-20261121-v1.service','epoch170-standard-lane-20261109-v1','epoch170-retry10-recovery-20261121-v1',288)]
unit="horizon-qualify-170-replacement-local3retry10-20261121-v1.service"
run=base.parent/"epoch170-retry10-recovery-20261121-v1"
plan=dict(schema="jetstreamer-horizon-standalone-guard-plan-v1",unit=unit,invocation_id=os.environ["INVOCATION_ID"],
          filesystem="/home/sol",minimum_free_bytes=8297502499408,worker_root="/home/sol/.jetstreamer-private/epoch170-standard-lane-20261109-v1",
          maximum_root_physical_bytes=384<<30,maximum_worker_vmas=3500000,receipt_directory=str(run/"guard-receipts"),data_fulfillment=binding)
records={}
for label,p in [("positive",plan),("wrong-cap",dict(plan,maximum_root_physical_bytes=288<<30)),
                ("wrong-epoch",dict(plan,unit="horizon-qualify-167-source-index-v1-20261121.service")),
                ("wrong-root",dict(plan,worker_root="/home/sol/.jetstreamer-private")),
                ("missing-witness",{k:v for k,v in plan.items() if k!="data_fulfillment"})]:
 fp=base/(label+"-"+os.environ["INVOCATION_ID"]+".json");durable(fp,p)
 proc=subprocess.run([exe,fp,"--plan-sha256",sha(fp),"--self-sha256",sha(exe),"--validate-plan-only"],capture_output=True)
 if label=="positive":assert proc.returncode==0 and json.loads(proc.stdout)["validated"]
 else:assert proc.returncode and b"Error" in proc.stderr or (proc.returncode and proc.stderr)
 records[label]=ref(fp)
result=dict(schema="horizon-170-384-native-guard-qualified-v1",build=ref(bp),guard=ref(exe),seal=bseal,witness=ref(w),
            contract=binding,static_controls=records,physical_launch=False,qualification_invocation=os.environ["INVOCATION_ID"])
durable(base/"GUARD_QUALIFIED.json",result)
print(json.dumps(result))
