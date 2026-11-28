from pathlib import Path
import os,json,subprocess,hashlib
p=Path('/home/sol/.jetstreamer-private/current0030-failed-reader-retirement-qa-20261109-v1');sha=lambda f:hashlib.sha256(Path(f).read_bytes()).hexdigest()
def save(n,v):
 fd=os.open(p/n,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(fd,'w') as f:json.dump(v,f,indent=2);f.flush();os.fsync(f.fileno())
 fd=os.open(p,os.O_DIRECTORY);os.fsync(fd);os.close(fd)
os.umask(0o022)
s=Path('/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment');h='e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3';assert sha(s)==h
members=[(p/'qa/retirement','retirement',0o555),(p/'ALL_FOUR_AND_ORDINARY_PASSED.json','artifact-proof.json',0o444),(p/'SOURCE_AND_EXACT4_FROZEN_RECIPES.json','exact-source-and-recipes.json',0o444)]
plan=dict(schema='jetstreamer-sealed-deployment-plan-v1',destination='/usr/local/lib/jetstreamer/horizon-exact0030-transient-reader-retirement-candidate-20261109-v1',members=[dict(source=str(f),name=n,sha256=sha(f),mode=m) for f,n,m in members]);save('CANDIDATE-SEAL-PLAN.json',plan)
z=subprocess.run([str(s),str(p/'CANDIDATE-SEAL-PLAN.json'),'--plan-sha256',sha(p/'CANDIDATE-SEAL-PLAN.json'),'--self-sha256',h],capture_output=True,text=True);save('CANDIDATE-SEAL-EXECUTION.json',dict(code=z.returncode,stdout=z.stdout,stderr=z.stderr));print(z.stdout,z.stderr);assert z.returncode==0
image=Path(plan['destination'])/'retirement';argv=['systemd-run','--wait','--pipe','--service-type=exec','--unit=horizon-retire0030-native-control-20261109-v1']
for prop in ['User=root','Group=root','UMask=0077','Restart=no','MemoryMax=512M','MemorySwapMax=0','TasksMax=128','RuntimeMaxSec=120','TimeoutStopSec=10','KillMode=control-group','NoNewPrivileges=yes','PrivateNetwork=yes','CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_SYS_PTRACE','AmbientCapabilities=CAP_DAC_OVERRIDE CAP_SYS_PTRACE','ProtectHome=read-only','ProtectSystem=strict','ReadWritePaths='+str(p),'AppArmorProfile=horizon-witness-test-deny199-20261107-v1']:argv+=['-p',prop]
argv+=[str(image),'qualify','--self-sha256',sha(image)];save('NATIVE-CONTROL-ARGV.json',argv);z=subprocess.run(argv,capture_output=True,text=True,timeout=130);save('NATIVE-CONTROL-EXECUTION.json',dict(code=z.returncode,stdout=z.stdout,stderr=z.stderr));print(z.stdout,z.stderr);assert z.returncode==0
