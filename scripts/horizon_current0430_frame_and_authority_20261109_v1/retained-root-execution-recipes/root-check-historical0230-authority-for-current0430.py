from pathlib import Path
import os,json,subprocess,hashlib
p=Path('/home/sol/.jetstreamer-private/first-lane-full-reader-witness-qualification-20261107-v1/current0430-20261109-v1')
def save(n,v):
 raw=(json.dumps(v,indent=2)+'\n').encode();fd=os.open(p/n,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(fd,'wb')as h:h.write(raw);h.flush();os.fsync(h.fileno())
 fd=os.open(p,os.O_DIRECTORY);os.fsync(fd);os.close(fd)
a=['/usr/bin/python3','-c',"import sys,json;sys.path.insert(0,'/tmp/continuations0230-qualified-phase-required-source-20261109-v1');from next_operation_bindings import next_operation_bindings;print(json.dumps(next_operation_bindings(),sort_keys=True))"]
save('ROOT_VALIDATE_HISTORICAL0230_AUTHORITY_ARGV.json',a);z=subprocess.run(a,capture_output=True,text=True,timeout=240);save('ROOT_VALIDATE_HISTORICAL0230_AUTHORITY_EXECUTION.json',dict(argv=a,code=z.returncode,stdout=z.stdout,stderr=z.stderr));print('Historical0230 validator',z.returncode,z.stderr[-2500:],flush=True);assert z.returncode==0;v=json.loads(z.stdout);assert v['current_complete_DATA_lower_bound_bytes']==5165652325012;save('ROOT_ACTUAL_VALIDATED_HISTORICAL0230_AUTHORITY.json',v);print('Strict unchanged historical0230 authority validated; not current0430 admission',flush=True)
