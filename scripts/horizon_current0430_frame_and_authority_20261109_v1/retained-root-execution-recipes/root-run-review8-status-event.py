from pathlib import Path
import json,os,subprocess
p=Path('/home/sol/.jetstreamer-private/epoch185-explicit-control-review8-model-20261109-next-v1');d=Path('/home/sol/.jetstreamer-private/current0430-explicit-control-review8-status-event-20261109-v1');d.mkdir(mode=0o700)
def save(n,v):
 fd=os.open(p/n,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(fd,'w')as h:json.dump(v,h,indent=2);h.flush();os.fsync(h.fileno())
 fd=os.open(p,os.O_DIRECTORY);os.fsync(fd);os.close(fd)
a=json.loads(Path('/home/sol/.jetstreamer-private/actual043022-visible-root-acceptance-20261109-v1/status-audit043022-argv.json').read_text());a=a[:a.index('/usr/bin/flock')];a=['--unit=horizon-status185-explicit-control-review8-event-20261109-v1'if x.startswith('--unit=')else 'ReadWritePaths=/home/sol/.jetstreamer-private/r2-status-receipts '+str(d)if x.startswith('ReadWritePaths=')else x for x in a];a+=['/usr/bin/flock','--exclusive','--wait','30','/home/sol/.jetstreamer-private/r2-status-receipts/status-publish.lock','/usr/bin/python3','/usr/local/lib/jetstreamer/horizon-status185-review8-tools-20261109-v1/status.py'];save('STATUS-EVENT-ORIGINAL-ARGV.json',a);z=subprocess.run(a,capture_output=True,text=True,timeout=210);save('STATUS-EVENT-ORIGINAL-EXECUTION.json',dict(argv=a,code=z.returncode,stdout=z.stdout,stderr=z.stderr));print(z.stdout,z.stderr[-2500:],flush=True);assert z.returncode==0
