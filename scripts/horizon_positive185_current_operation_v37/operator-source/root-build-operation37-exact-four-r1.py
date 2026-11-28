from pathlib import Path
import os,json,shutil,hashlib,subprocess
p=Path('/home/sol/.jetstreamer-private/epoch185-operation37-final4-layout-qa-20261109-v1');packet=Path('/tmp/operation37-final4-directories-and-reader-retirement-source-20261109-v1');sha=lambda f:hashlib.sha256(Path(f).read_bytes()).hexdigest();b=lambda f:dict(path=str(f),sha256=sha(f))
def save(n,v):
 fd=os.open(p/n,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(fd,'w') as h:json.dump(v,h,indent=2);h.flush();os.fsync(h.fileno())
 fd=os.open(p,os.O_DIRECTORY);os.fsync(fd);os.close(fd)
assert sha(packet/'SOURCE_ONLY_MANIFEST.json')=='1094607755a502d3df06b838f59ef70d32cd3de2ccb1d47864afb15f7f5a9fb3'
assert json.loads((p/'ROOT_NORMAL6_OPERATION37_DATA512_BOOKING.json').read_text())['complete_DATA_bytes']==5164041712276
shutil.copytree(packet/'source',p/'source');(p/'qa').mkdir(mode=0o700);(p/'qa/tmp').mkdir(mode=0o700)
v=json.loads((packet/'ROOT_EXACT4_COMPILER_RECIPES.NOT_EXECUTED.json').read_text());old=v['proposed_qa_root'];recipes={k:[x.replace(old,str(p)) for x in a] for k,a in v['recipes'].items()}
base=json.loads(Path(v['base']['path']).read_text());source=[b(f) for f in sorted((p/'source').rglob('*')) if f.is_file()];base.update(source=source,recipes=recipes,source_handoff=b(packet/'HANDOFF.md'),source_manifest=b(packet/'SOURCE_ONLY_MANIFEST.json'),booking=b(p/'ROOT_NORMAL6_OPERATION37_DATA512_BOOKING.json'),complete_DATA_bytes=5164578583188,operation37_booking_total_before_future0200_guard=5164041712276,extra_QA_bytes=0)
save('SOURCE_AND_EXACT4_FROZEN_RECIPES.json',base)
for label,a in recipes.items():
 print('BEGIN',label,flush=True);save(label+'-ORIGINAL-ARGV.json',a);z=subprocess.run(a,capture_output=True,text=True,timeout=710);save(label+'-ORIGINAL-EXECUTION.json',dict(argv=a,code=z.returncode,stdout=z.stdout,stderr=z.stderr));print(label,z.returncode,z.stderr[-4000:],flush=True);assert z.returncode==0,label
save('ALL_FOUR_ORIGINAL_COMPILERS_PASSED.json',dict(labels=list(recipes),graph=b(p/'SOURCE_AND_EXACT4_FROZEN_RECIPES.json'),all_unchanged_externs_preserved=True,no_replay_or_publication=True))
