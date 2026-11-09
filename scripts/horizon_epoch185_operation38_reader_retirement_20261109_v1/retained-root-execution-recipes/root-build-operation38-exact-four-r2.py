from pathlib import Path
import os,json,shutil,hashlib,subprocess,datetime
p=Path('/home/sol/.jetstreamer-private/epoch185-operation38-driver12-helper35-qa-20261109-v1');sha=lambda f:hashlib.sha256(Path(f).read_bytes()).hexdigest();b=lambda f:dict(path=str(f),sha256=sha(f))
def save(n,v):
 fd=os.open(p/n,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(fd,'w')as h:json.dump(v,h,indent=2);h.flush();os.fsync(h.fileno())
 fd=os.open(p,os.O_DIRECTORY);os.fsync(fd);os.close(fd)
shutil.copytree(p/'source',p/'source-r2');f=p/'source-r2/successful_reader_retirement_0230.rs';s=f.read_text();assert s.count('MAIN_PID.to_string()')==1;s=s.replace('    let actor = query(r, ACTOR)?;','    let actor = query(r, ACTOR)?;\n    let main_pid_text = MAIN_PID.to_string();').replace('actor["ExecMainPID"] == MAIN_PID.to_string()','actor["ExecMainPID"] == main_pid_text.as_str()');f.write_text(s);(p/'qa/r2/tmp').mkdir(mode=0o700,parents=True)
g=json.loads((p/'SOURCE_AND_EXACT4_FROZEN_RECIPES.json').read_text());recipes={}
for label,a in g['recipes'].items():recipes[label]=[x.replace(str(p/'source/'),str(p/'source-r2/')).replace(str(p/'qa'),str(p/'qa/r2')).replace('v38-driver12-helper35-r1','v38-driver12-helper35-r2')if x.startswith('--unit=')or str(p)in x else x for x in a]
g.update(source=[b(f)for f in sorted((p/'source-r2').rglob('*'))if f.is_file()],recipes=recipes,retained_first_compiler_failure=b(p/'clippy-production-ORIGINAL-EXECUTION.json'),same_original_DATA512_booking=True,correction='Bind expected MainPID string once before comparison; preserve exact systemd string equality.')
save('SOURCE_AND_EXACT4_FROZEN_RECIPES_R2.json',g)
for label,a in recipes.items():
 print(datetime.datetime.now(datetime.timezone.utc).isoformat(),'BEGIN',label,flush=True);save(label+'-R2-ORIGINAL-ARGV.json',a);z=subprocess.run(a,capture_output=True,text=True,timeout=710);save(label+'-R2-ORIGINAL-EXECUTION.json',dict(argv=a,code=z.returncode,stdout=z.stdout,stderr=z.stderr));print(label,z.returncode,z.stdout[-500:],z.stderr[-4000:],flush=True);assert z.returncode==0,label
save('ALL_FOUR_R2_ORIGINAL_COMPILERS_PASSED.json',dict(labels=list(recipes),graph=b(p/'SOURCE_AND_EXACT4_FROZEN_RECIPES_R2.json'),all_unchanged_externs_preserved=True,no_replay_or_publication=True))
