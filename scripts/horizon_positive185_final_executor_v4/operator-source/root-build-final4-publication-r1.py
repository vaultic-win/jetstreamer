from pathlib import Path
import json,os,subprocess,shutil,hashlib
p=Path('/home/sol/.jetstreamer-private/epoch185-final4-guard-publication-qa-20261109-v1');packet=Path('/tmp/final4-guard-publication-source-20261109-v1');sha=lambda f:hashlib.sha256(Path(f).read_bytes()).hexdigest();b=lambda f:dict(path=str(f),sha256=sha(f))
def save(n,v):
 fd=os.open(p/n,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(fd,'w') as f:json.dump(v,f,indent=2);f.flush();os.fsync(f.fileno())
 fd=os.open(p,os.O_DIRECTORY);os.fsync(fd);os.close(fd)
assert json.loads((p/'ROOT_NORMAL6_FINAL4_DATA512_BOOKING.json').read_text())['complete_DATA_bytes']==5163504841364
assert (packet/'HANDOFF.md').exists()
for n in ['source','work','work/tmp']:(p/n).mkdir(mode=0o700)
for f in (packet/'source').iterdir():
 if f.is_file():shutil.copyfile(f,p/'source'/f.name);os.chmod(p/'source'/f.name,0o444)
base=Path('/home/sol/.jetstreamer-private/epoch185-positive-final3-driver11-qa-20261108-v1/SOURCE_AND_EXACT4_FROZEN_RECIPES.json');v=json.loads(base.read_text());template=json.loads((packet/'ROOT_QA_RECIPE_TEMPLATES.NOT_EXECUTED.json').read_text());proposed=template['proposed_QA_directory_not_created'];recipes={k:[x.replace(proposed,str(p)).replace('MemoryMax=1G','MemoryMax=512M') for x in a] for k,a in template['recipes'].items()}
v.update(source=[b(f) for f in sorted((p/'source').iterdir()) if f.is_file()],recipes=recipes,source_only_handoff=b(packet/'HANDOFF.md'),previous_qualified_graph=b(base),booking=b(p/'ROOT_NORMAL6_FINAL4_DATA512_BOOKING.json'),complete_DATA_bytes=5163504841364,normal_pool_bytes=6<<30,scope='Closed-writer guard receipt notification only; actualguardfailure still rejects; 600/30/15 clocks and generic qualifiedhelper roles unchanged')
save('SOURCE_AND_EXACT4_FROZEN_RECIPES.json',v)
for label,a in recipes.items():
 print('BEGIN',label,flush=True);save(label+'-ORIGINAL-ARGV.json',a);z=subprocess.run(a,capture_output=True,text=True,timeout=330);save(label+'-ORIGINAL-EXECUTION.json',dict(argv=a,code=z.returncode,stdout=z.stdout,stderr=z.stderr));print(label,z.returncode,z.stderr[-3000:],flush=True);assert z.returncode==0,label
save('ALL_FOUR_ORIGINAL_COMPILERS_PASSED.json',dict(labels=list(recipes),graph=b(p/'SOURCE_AND_EXACT4_FROZEN_RECIPES.json')))
