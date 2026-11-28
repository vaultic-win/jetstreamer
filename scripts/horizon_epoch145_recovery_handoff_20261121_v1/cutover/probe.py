"""Launch one metadata-only cap probe. All normal subsystem writers are left idle."""
import hashlib,json,os,re,subprocess,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from envelope import *
p=Path(__file__).resolve().parent
if len(sys.argv)!=3 or not re.fullmatch(r"[a-z0-9-]+",sys.argv[1]) or sys.argv[2] not in ("tools","tools-v2"):
    raise SystemExit("probe.py RUN_SUFFIX tools|tools-v2")
name="horizon-145-fs-proof-20261122-"+sys.argv[1]
evidence=DIR/"cutover-qualifications"
evidence.mkdir(mode=0o700,exist_ok=True)
out=evidence/name
out.mkdir(mode=0o700)
pkg=DIR/sys.argv[2];seal=hashlib.sha256((pkg/"deployment-seal-receipt.json").read_bytes()).hexdigest()
extra=["StandardOutput=append:"+str(out/"proof.json"),"StandardError=append:"+str(out/"stderr"),"RuntimeMaxSec=360"]
args=cmd(name,"/usr/bin/python3",["-IB",str(p/"qualify.py"),str(pkg),seal],extra,"horizonaudit.slice")
subprocess.run(args,check=True)
print(name)
