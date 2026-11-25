import hashlib,json,os,re,stat,subprocess,sys
from pathlib import Path
work=Path(__file__).resolve().parents[2]
assert len(sys.argv)==3 or (len(sys.argv)==4 and sys.argv[3] in ('epoch167-cold-v3','epoch168-cold-v2','epoch168-cold-v3','epoch168-cold-v4','epoch168-cold-v5','epoch166-retry11','epoch170-retry11','epoch170-retry12','epoch170-retry13'))
cold167=sys.argv[3:]==['epoch167-cold-v3']
cold168v3=sys.argv[3:]==['epoch168-cold-v3']
cold168v4=sys.argv[3:]==['epoch168-cold-v4']
cold168v5=sys.argv[3:]==['epoch168-cold-v5']
cold168=sys.argv[3:]==['epoch168-cold-v2'] or cold168v3 or cold168v4 or cold168v5
guard168ver='v5' if cold168v5 else ('v4' if cold168v4 else ('v3' if cold168v3 else 'v2'))
guard168date='20261125' if cold168v5 else ('20261123' if cold168v3 or cold168v4 else '20261122')
attempt168=int(guard168ver[1:])
retry11=sys.argv[3:]==['epoch166-retry11']
retry170=sys.argv[3:] in (['epoch170-retry11'],['epoch170-retry12'],['epoch170-retry13'])
attempt=sys.argv[3].split('-')[-1] if retry170 else None
cold=cold167 or cold168 or retry11 or retry170
runtime=Path('/var/lib/jetstreamer/horizon_runtime_data')
base=runtime/('epoch167-cold-guard-20261122-v3' if cold167 else 'epoch170-retry10-guard384-20261121-v1')
if retry170:base=runtime/f'epoch170-{attempt}-guard-20261122-v1'
if retry11:base=runtime/'epoch166-retry11-guard-20261122-v1'
if cold168:base=runtime/f'epoch168-cold-guard-{guard168date}-{guard168ver}'
build=sys.argv[2]
assert re.fullmatch(r"[0-9a-f]{32}",build)
proof=base/("build-"+build)
out=Path((proof/"build-dir").read_text().strip())
group=Path('/sys/fs/cgroup/system.slice')/('horizon-167-cold-guard-v3-qualify.service' if cold167 else 'horizon-170-retry10-guard384-qualify.service')
if retry170:group=Path(f'/sys/fs/cgroup/system.slice/horizon-170-{attempt}-guard-qualify.service')
if retry11:group=Path('/sys/fs/cgroup/system.slice/horizon-166-retry11-guard-qualify.service')
if cold168:group=Path(f'/sys/fs/cgroup/system.slice/horizon-168-cold-guard-{guard168ver}-qualify.service')
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
j=dict(schema='horizon-cold167-v3-native-guard-build-v1' if cold167 else 'horizon-170-384-native-guard-build-v1',commit=code,source_hashes=sources,artifact=ref(out/'guard'),test=ref(out/'tests'),script=ref(build_source),build_iid=build,captured_source=ref(proof/'sources'),qualification_log=ref(proof/'build.log'),test_count=102)
if retry170:j['schema']=f'horizon-170-{attempt}-native-guard-build-v1'
if retry11:j['schema']='horizon-166-retry11-native-guard-build-v1'
if cold168:j['schema']=f'horizon-168-cold-{guard168ver}-native-guard-build-v1'
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
j=json.loads(w.read_bytes());assert (j['native_identity']['executable_sha256']==sha(exe) and j['native_identity']['executable']==str(exe) and j['allocation']['first']==j['allocation']['second'] and len(j['allocation']['first'])==12 and len(j['independent_roots_receipt']['receipts'])==(5 if cold168v5 else (4 if retry11 or retry170 or cold168 else 3)))
c['qualified_native_witness']=ref(w);cp=base/'qualified-contract.json';durable(cp,c)
cs=seal('contract',[member('contract.json',cp,0o444)])
binding={'contract':ref(base/'contract/contract.json'),'deployment_seal':cs}
unit="horizon-qualify-170-replacement-local3retry10-20261121-v1.service"
run=base.parent/"epoch170-retry10-recovery-20261121-v1"
plan=dict(schema="jetstreamer-horizon-standalone-guard-plan-v1",unit=unit,invocation_id=os.environ["INVOCATION_ID"],
          filesystem="/home/sol",minimum_free_bytes=8297502499408,worker_root="/home/sol/.jetstreamer-private/epoch170-standard-lane-20261109-v1",
          maximum_root_physical_bytes=384<<30,maximum_worker_vmas=3500000,receipt_directory=str(run/"guard-receipts"),data_fulfillment=binding)
if cold168:
 plan.update(unit=f'horizon-qualify-168-full-metered-cold-{guard168ver}-{guard168date}.service',
             worker_root='/home/sol/.jetstreamer-private/epoch168-standard-lane-20261109-v1',
             maximum_root_physical_bytes=(512 if cold168v5 else 288)<<30,
             receipt_directory=str(runtime/f'epoch168-retry{attempt168}-rebook-{guard168date}-v1/guard-receipts'))
if cold167:
 plan.update(unit='horizon-qualify-167-source-index-v3-20261122.service',
             worker_root='/home/sol/.jetstreamer-private/epoch167-standard-lane-20261109-v1',
             maximum_root_physical_bytes=512<<30,
             receipt_directory=str(runtime/'epoch167-source-index-rebook-20261122-v3/guard-receipts'))
if retry11:
 plan.update(unit='horizon-qualify-166-independent-retry11-20261122.service',
             worker_root='/home/sol/.jetstreamer-private/epoch166-independent-cold-20261120-v1',
             maximum_root_physical_bytes=288<<30,
             receipt_directory=str(runtime/'epoch166-retry11-rebook-20261122-v1/guard-receipts'))
if retry170:
 plan.update(unit=f'horizon-qualify-170-replacement-local3{attempt}-20261122.service',
             receipt_directory=str(runtime/f'epoch170-{attempt}-rebook-20261122-v1/guard-receipts'))
records={}
cases=[("positive",plan),("wrong-cap",dict(plan,maximum_root_physical_bytes=(384 if retry11 or cold168 else 288)<<30)),
                ("wrong-epoch",dict(plan,unit="horizon-qualify-167-source-index-v1-20261121.service")),
                ("wrong-root",dict(plan,worker_root="/home/sol/.jetstreamer-private")),
                ("missing-witness",{k:v for k,v in plan.items() if k!="data_fulfillment"})]
if cold168:
 cases.append(('wrong-predecessor-168',dict(plan,unit='horizon-qualify-168-full-metered-20261121-v1.service')))
if cold168v3 or cold168v4 or cold168v5:
 cases.append(('spent-retry2-168',dict(plan,unit='horizon-qualify-168-full-metered-cold-v2-20261122.service')))
 old=runtime/'epoch168-cold-guard-20261122-v2/contract'
 cases.append(('spent-retry2-contract',dict(plan,data_fulfillment={'contract':ref(old/'contract.json'),'deployment_seal':ref(old/'deployment-seal-receipt.json')})))
if cold168v4 or cold168v5:
 cases.append(('spent-retry3-168',dict(plan,unit='horizon-qualify-168-full-metered-cold-v3-20261123.service')))
 old=runtime/'epoch168-cold-guard-20261123-v3/contract'
 cases.append(('spent-retry3-contract',dict(plan,data_fulfillment={'contract':ref(old/'contract.json'),'deployment_seal':ref(old/'deployment-seal-receipt.json')})))
if cold168v5:
 cases.append(('spent-retry4-168',dict(plan,unit='horizon-qualify-168-full-metered-cold-v4-20261123.service')))
 old=runtime/'epoch168-cold-guard-20261123-v4/contract'
 cases.extend([('spent-retry4-contract',dict(plan,data_fulfillment={'contract':ref(old/'contract.json'),
                'deployment_seal':ref(old/'deployment-seal-receipt.json')})),
               ('spent-retry4-cap',dict(plan,maximum_root_physical_bytes=288<<30))])
if retry170:
 predecessor={'retry11':'retry10','retry12':'retry11','retry13':'retry12'}[attempt]
 old_170_contract=runtime/(f'epoch170-{predecessor}-guard-20261122-v1/contract' if predecessor!='retry10' else 'epoch170-retry10-guard384-20261121-v1/contract')
 old_170_unit=f'horizon-qualify-170-replacement-local3{predecessor}-20261122.service' if predecessor!='retry10' else unit
 cases.extend([('wrong-predecessor-170',dict(plan,unit=old_170_unit)),
               ('wrong-predecessor-170-contract',dict(plan,data_fulfillment={'contract':ref(old_170_contract/'contract.json'),
                    'deployment_seal':ref(old_170_contract/'deployment-seal-receipt.json')}))])
if cold:
 old_contract=runtime/'incident-replay-guard-20261121-v1/contract'
 cases.extend([('wrong-old-unit',dict(plan,unit='horizon-qualify-166-independent-recovery-20261121-v1.service' if retry11 else 'horizon-qualify-167-source-index-v2-20261122.service')),
               ('wrong-floor',dict(plan,minimum_free_bytes=plan['minimum_free_bytes']-1)),
               ('wrong-receipts',dict(plan,receipt_directory=str(runtime/'epoch167-source-index-rebook-20261122-v2/guard-receipts'))),
               ('wrong-contract',dict(plan,data_fulfillment={'contract':ref(old_contract/'contract.json'),
                                                              'deployment_seal':ref(old_contract/'deployment-seal-receipt.json')})),
               ('wrong-contract-digest',dict(plan,data_fulfillment={**binding,'contract':{**binding['contract'],'sha256':'0'*64}}))])
for label,p in cases:
 fp=base/(label+"-"+os.environ["INVOCATION_ID"]+".json");durable(fp,p)
 proc=subprocess.run([exe,fp,"--plan-sha256",sha(fp),"--self-sha256",sha(exe),"--validate-plan-only"],capture_output=True)
 if label=="positive":assert proc.returncode==0 and json.loads(proc.stdout)["validated"]
 else:assert proc.returncode != 0 and proc.stderr
 records[label]=ref(fp)
result=dict(schema="horizon-cold167-v3-native-guard-qualified-v1" if cold167 else "horizon-170-384-native-guard-qualified-v1",build=ref(bp),guard=ref(exe),seal=bseal,witness=ref(w),
            contract=binding,static_controls=records,physical_launch=False,qualification_invocation=os.environ["INVOCATION_ID"])
if retry170:result['schema']=f'horizon-170-{attempt}-native-guard-qualified-v1'
if retry11:result['schema']='horizon-166-retry11-native-guard-qualified-v1'
if cold168:result['schema']=f'horizon-168-cold-{guard168ver}-native-guard-qualified-v1'
durable(base/"GUARD_QUALIFIED.json",result)
print(json.dumps(result))
