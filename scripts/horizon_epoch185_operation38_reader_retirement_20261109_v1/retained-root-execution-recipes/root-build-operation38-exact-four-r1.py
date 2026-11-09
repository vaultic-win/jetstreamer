from pathlib import Path
import os,json,shutil,hashlib,subprocess,datetime
base=Path('/home/sol/.jetstreamer-private');p=base/'epoch185-operation38-driver12-helper35-qa-20261109-v1';packet=Path('/tmp/operation38-driver12-helper35-source-20261109-v1');p.mkdir(mode=0o700);sha=lambda f:hashlib.sha256(Path(f).read_bytes()).hexdigest();b=lambda f:dict(path=str(f),sha256=sha(f))
def save(n,v):
 fd=os.open(p/n,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(fd,'w')as h:json.dump(v,h,indent=2);h.flush();os.fsync(h.fileno())
 fd=os.open(p,os.O_DIRECTORY);os.fsync(fd);os.close(fd)
prev=base/'epoch185-helper35-current-witness-planner-qa-20261109-v6/ROOT_NORMAL6_PLANNER6_DATA512_BOOKING.json';assert json.loads(prev.read_text())['complete_DATA_bytes']==5175852872340
save('ROOT_NORMAL6_OPERATION38_DATA512_BOOKING.json',dict(schema='horizon-normal6-operation38-driver12-helper35-booking-v1',owner='/root',previous=b(prev),previous_retained_DATA_lower_bound_bytes=5175852872340,new_retained_DATA_bytes=536870912,complete_DATA_bytes=5176389743252,normal_pool_bytes=6<<30,extra_QA_bytes=0,one_serial_compiler_bytes=512<<20,all_previous_source_and_DATA_promises_retained=True,no_replay_or_resource_credit=True))
g=json.loads((packet/'SOURCE_AND_EXACT4_COMPILER_RECIPES.NOT_EXECUTED.json').read_text());assert g['proposed_qa_root']==str(p);shutil.copytree(packet/'source',p/'source');(p/'qa/tmp').mkdir(mode=0o700,parents=True)
recipes=g['recipes'];assert all(sum(x=='--extern'for x in a)==6 for a in recipes.values())
for x in g['extern_bindings'].values():assert sha(x['path'])==x['sha256']
g.update(source=[b(f)for f in sorted((p/'source').rglob('*'))if f.is_file()],recipes=recipes,source_candidate_graph=b(packet/'SOURCE_AND_EXACT4_COMPILER_RECIPES.NOT_EXECUTED.json'),booking=b(p/'ROOT_NORMAL6_OPERATION38_DATA512_BOOKING.json'),complete_DATA_bytes=5176389743252,extra_QA_bytes=0)
save('SOURCE_AND_EXACT4_FROZEN_RECIPES.json',g)
for label,a in recipes.items():
 print(datetime.datetime.now(datetime.timezone.utc).isoformat(),'BEGIN',label,flush=True);save(label+'-ORIGINAL-ARGV.json',a);z=subprocess.run(a,capture_output=True,text=True,timeout=710);save(label+'-ORIGINAL-EXECUTION.json',dict(argv=a,code=z.returncode,stdout=z.stdout,stderr=z.stderr));print(label,z.returncode,z.stdout[-500:],z.stderr[-4000:],flush=True);assert z.returncode==0,label
save('ALL_FOUR_ORIGINAL_COMPILERS_PASSED.json',dict(labels=list(recipes),graph=b(p/'SOURCE_AND_EXACT4_FROZEN_RECIPES.json'),all_unchanged_externs_preserved=True,no_replay_or_publication=True))
