from pathlib import Path
import json,os,hashlib,shutil
p=Path('/home/sol/.jetstreamer-private/epoch185-helper35-current-witness-planner-qa-20261109-v6');sha=lambda f:hashlib.sha256(Path(f).read_bytes()).hexdigest();b=lambda f:dict(path=str(f),sha256=sha(f))
def save(n,v):
 f=os.open(p/n,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(f,'w')as h:json.dump(v,h,indent=2);h.flush();os.fsync(h.fileno())
 f=os.open(p,os.O_DIRECTORY);os.fsync(f);os.close(f)
shutil.copytree(p/'source',p/'source-r2');f=p/'source-r2/lineage.rs';s=f.read_text();needle='pub const DRIVER11_NATIVE_SHA: &str';assert s.count(needle)==1;s=s.replace(needle,'#[cfg(test)]\n'+needle);f.write_text(s);(p/'qa/r2/tmp').mkdir(mode=0o700,parents=True)
g=json.loads((p/'SOURCE_AND_EXACT4_FROZEN_RECIPES.json').read_text());recipes={}
for label,a in g['recipes'].items():
 recipes[label]=[x.replace(str(p/'source/'),str(p/'source-r2/')).replace(str(p/'qa'),str(p/'qa/r2')).replace('-20261109-v1','-20261109-r2')if x.startswith('--unit=')or str(p)in x else x for x in a]
 assert str(p/'source-r2/main.rs')in recipes[label]
g.update(source=[b(f)for f in sorted((p/'source-r2').rglob('*'))if f.is_file()],recipes=recipes,retained_first_compiler_failure=b(p/'clippy-production-ORIGINAL-EXECUTION.json'),correction='Historical Helper34 SHA constant is test-only; its historical role regression remains active, current production role unchanged.',same_original_DATA512_booking=True)
save('SOURCE_AND_EXACT4_FROZEN_RECIPES_R2.json',g)
s=Path('/tmp/root-build-qualify-planner6-driver12-helper35-r1.py').read_text();start=s.index('executions=[];units=[]');tail=s[start:];tail=tail.replace("save(label+'-ORIGINAL-ARGV.json'","save('R2-'+label+'-ORIGINAL-ARGV.json'").replace("save(label+'-ORIGINAL-EXECUTION.json'","save('R2-'+label+'-ORIGINAL-EXECUTION.json'").replace("p/(label+'-ORIGINAL-EXECUTION.json')","p/('R2-'+label+'-ORIGINAL-EXECUTION.json')").replace("p/'qa/planner'","p/'qa/r2/planner'").replace("p/'qa/planner-tests'","p/'qa/r2/planner-tests'").replace('SOURCE_AND_EXACT4_FROZEN_RECIPES.json','SOURCE_AND_EXACT4_FROZEN_RECIPES_R2.json').replace('ACTUAL2300-ACCEPTED-CURRENT-HELPER35-ORIGINAL-EXECUTION.json','R2-ACTUAL2300-ACCEPTED-CURRENT-HELPER35-ORIGINAL-EXECUTION.json')
needle="a=[str(candidate/'tests')if x==str(p/'qa/r2/planner-tests')else x for x in a]";assert needle in tail;tail=tail.replace(needle,"a=[x.replace(str(p/'qa/planner-tests'),str(candidate/'tests')) for x in a]")
head=s[:s.index('previous=base/')];head=head.replace(';p.mkdir(mode=0o700)','');head+="graph=json.loads((p/'SOURCE_AND_EXACT4_FROZEN_RECIPES_R2.json').read_text());recipes=graph['recipes']\n"
Path('/tmp/root-build-qualify-planner6-driver12-helper35-r2.py').write_text(head+tail)
print('R2 prepared; original booking/source/failure retained')
