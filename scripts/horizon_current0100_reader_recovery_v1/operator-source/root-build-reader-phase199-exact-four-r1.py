from pathlib import Path
import json,hashlib,os,subprocess
p=Path('/home/sol/.jetstreamer-private/current-reader-phase199-recovery-qa-20261109-v1');sha=lambda f:hashlib.sha256(Path(f).read_bytes()).hexdigest()
def save(n,v):
 fd=os.open(p/n,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(fd,'w') as h:json.dump(v,h,indent=2);h.flush();os.fsync(h.fileno())
 f=os.open(p,os.O_DIRECTORY);os.fsync(f);os.close(f)
j=json.loads((p/'SOURCE_AND_EXACT4_FROZEN_RECIPES.json').read_text())
for b in j['source']+list(j['extern_bindings'].values()):assert sha(b['path'])==b['sha256']
for label,a in j['recipes'].items():
 save(label+'-ORIGINAL-ARGV.json',a);print('BEGIN',label,flush=True);z=subprocess.run(a,capture_output=True,text=True,timeout=700);save(label+'-ORIGINAL-EXECUTION.json',dict(argv=a,code=z.returncode,stdout=z.stdout,stderr=z.stderr));print(label,z.returncode,z.stdout[-1000:],z.stderr[-1500:],flush=True);assert z.returncode==0,label
save('ALL_FOUR_ORIGINAL_COMPILERS_PASSED.json',dict(labels=list(j['recipes']),no_replay_or_publication=True));print('PHASE199_ALL_FOUR_COMPILERS_PASSED',flush=True)
