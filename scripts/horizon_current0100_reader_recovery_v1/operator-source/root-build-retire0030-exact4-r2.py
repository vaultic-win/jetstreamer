from pathlib import Path
import json,os,hashlib,subprocess
p=Path('/home/sol/.jetstreamer-private/current0030-failed-reader-retirement-qa-20261109-v1');sha=lambda f:hashlib.sha256(Path(f).read_bytes()).hexdigest()
def save(n,v):
 fd=os.open(p/('r2-'+n),os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(fd,'w') as f:json.dump(v,f,indent=2);f.flush();os.fsync(f.fileno())
 fd=os.open(p,os.O_DIRECTORY);os.fsync(fd);os.close(fd)
old=json.loads(Path('/home/sol/.jetstreamer-private/epoch185-positive-current-operation36-planner5-qa-20261108-v1/SOURCE_AND_EXACT4_FROZEN_RECIPES.json').read_text())
a=old['recipes']['clippy-production'];i=next(i for i,x in enumerate(a) if x.endswith('/clippy-driver'));prefix=a[:i]
prefix=[x.replace('horizon-positive185-current-operation-clippy-production-20261108-v36-helper34-planner5-r1','horizon-retire0030-compiler-LABEL-20261109-v2').replace('/home/sol/.jetstreamer-private/epoch185-positive-current-operation36-planner5-qa-20261108-v1/qa',str(p/'qa')) for x in prefix]
deps=Path('/home/sol/.jetstreamer-private/completion156-correction-adapter-20261029-v1/compiler-target/release/deps');ext=[]
for name in ['serde_json','sha2','libc','anyhow']:
 x=next(a[k+1] for k in range(len(a)-1) if a[k]=='--extern' and a[k+1].startswith(name+'='));ext+=['--extern',x]
base=['--crate-name','horizon_retire0030','--edition=2024','-Dwarnings','-C','debuginfo=0','-C','codegen-units=2','--check-cfg','cfg(test)','-L','dependency='+str(deps)]+ext
recipes={}
for label,tool,tail,output in [('clippy-production',a[i],['--emit=metadata'],'clippy.rmeta'),('clippy-tests',a[i],['--test','--emit=metadata'],'test-clippy.rmeta'),('build-tests',a[i].replace('clippy-driver','rustc'),['--test'],'tests'),('build-release',a[i].replace('clippy-driver','rustc'),['-C','opt-level=2'],'retirement')]:
 recipes[label]=[x.replace('LABEL',label) for x in prefix]+[tool]+base+tail+[str(p/'source/main-r2.rs'),'-o',str(p/'qa'/('r2-'+output))]
save('SOURCE_AND_EXACT4_FROZEN_RECIPES.json',dict(source=dict(path=str(p/'source/main-r2.rs'),sha256=sha(p/'source/main-r2.rs')),extern_bindings=[dict(path=x.split('=',1)[1],sha256=sha(x.split('=',1)[1])) for x in ext[1::2]],recipes=recipes,previous_recipe_authority=dict(path='/home/sol/.jetstreamer-private/epoch185-positive-current-operation36-planner5-qa-20261108-v1/SOURCE_AND_EXACT4_FROZEN_RECIPES.json',sha256=sha('/home/sol/.jetstreamer-private/epoch185-positive-current-operation36-planner5-qa-20261108-v1/SOURCE_AND_EXACT4_FROZEN_RECIPES.json')),normal_pool_bytes=6<<30,complete_DATA_bytes=5161894228628))
for label,argv in recipes.items():
 print('BEGIN',label,flush=True);z=subprocess.run(argv,capture_output=True,text=True,timeout=610);save(label+'-ORIGINAL-EXECUTION.json',dict(argv=argv,code=z.returncode,stdout=z.stdout,stderr=z.stderr));print(label,z.returncode,z.stderr[-4000:],flush=True);assert z.returncode==0,label
z=subprocess.run(['systemd-run','--wait','--pipe','--service-type=exec','--unit=horizon-retire0030-tests-20261109-v2','-p','User=root','-p','Group=root','-p','Restart=no','-p','MemoryMax=512M','-p','MemorySwapMax=0','-p','RuntimeMaxSec=120',str(p/'qa/r2-tests'),'--test-threads=1'],capture_output=True,text=True,timeout=130);save('ORDINARY-ORIGINAL-EXECUTION.json',dict(code=z.returncode,stdout=z.stdout,stderr=z.stderr));print(z.stdout,z.stderr,flush=True);assert z.returncode==0
save('ALL_FOUR_AND_ORDINARY_PASSED.json',dict(labels=list(recipes),production=dict(path=str(p/'qa/r2-retirement'),sha256=sha(p/'qa/r2-retirement')),all_required_tests_passed=True,no_replay_or_publication=True));print('ALL_FOUR_AND_ORDINARY_PASSED',flush=True)
