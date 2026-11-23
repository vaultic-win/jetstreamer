import json,os,sys,shutil,subprocess as sp
from pathlib import Path
base=Path(__file__).resolve().parent;sys.path.insert(0,str(base));from funding import price,M,partition

from owners import D,V,CG,MAIN,ref,bound
import funds
assert __debug__ and os.geteuid()==0 and os.environ['CODEX_THREAD_ID']==MAIN
with partition.take():
 name='horizon266-bounded-retire-controller-v215-'+sys.argv[1];dest=D/name;stage=base/name;u=name+'.service'
 fit=price(640*M,4*M,2*M);res=D/('horizon-bounded265-residual-'+name);res.mkdir(mode=0o700);assignment=funds.put(res/'assignment.json',fit);src=Path('/home/ubuntu/workspace/jetstreamer/tools/native266-stopped-scratch/src')
 dest.mkdir(mode=0o700);stage.mkdir(mode=0o755);shutil.copytree(src,stage/'src');out=stage/'out';out.mkdir(mode=0o700);os.chown(out,1000,1000)
 sources={f.name:ref(f) for f in (stage/'src').iterdir() if f.is_file()};assert len(sources)>=15 and all(ref(src/n)['sha256']==b['sha256'] for n,b in sources.items())
 rust=Path('/home/ubuntu/.rustup/toolchains/1.98.0-x86_64-unknown-linux-gnu/bin/rustc')
 cmd=['/bin/bash','-euc','set -euo pipefail\nfor feature in default stopped-v194 stopped-v207 stopped-v210; do\n    cfg=()\n    if [[ "$feature" != default ]]; then cfg=(--cfg "feature=\\"$feature\\""); fi\n    "$1" --edition=2024 -Dwarnings "${cfg[@]}" --test /src/main.rs -C debuginfo=0 -o /tmp/check\n    /tmp/check --test-threads=1\ndone\n"$1" --edition=2024 -Dwarnings --cfg \'feature="stopped-v210"\' -C opt-level=2 -C strip=symbols /src/main.rs -o /tmp/actor\ninstall -m 0555 /tmp/actor "$2/controller"','bash',str(rust),'/result']
 props=['Type=exec','User=ubuntu','Group=ubuntu','KillMode=control-group','Restart=no','CPUQuota=100%','AllowedCPUs=8','MemoryMax=512M','MemorySwapMax=0','TasksMax=32','RuntimeMaxSec=320','LimitFSIZE=16M','Nice=10','NoNewPrivileges=yes','PrivateNetwork=yes','PrivateDevices=yes','ProtectSystem=strict','ProtectHome=read-only','ReadOnlyPaths=/','TemporaryFileSystem=/tmp:rw,nosuid,nodev,noswap,size=64M,mode=1777','BindReadOnlyPaths='+str(stage/'src')+':/src','BindPaths='+str(out)+':/result']
 book=funds.put(dest/'booking.json',dict(resources=assignment,sources=sources,argv=cmd,properties=props,compiler=str(rust)))
 p=sp.run(['systemd-run','--expand-environment=no','--quiet','--wait','--pipe','--unit='+u,*['--property='+q for q in props],*cmd],capture_output=True,timeout=350)
 pr=funds.put(dest/'process.json',dict(exit=p.returncode,stdout=p.stdout.decode()[-5000:],stderr=p.stderr.decode()[-3500:]));assert p.returncode==0 and p.stdout.count(b'9 passed; 0 failed;')==4,(p.stdout[-800:],p.stderr[-1200:])
 os.chown(out,0,0);image=out/'controller';os.chown(image,0,0);assert image.lstat().st_mode&0o7777==0o555 and image.stat().st_size<1<<20
 ev=[json.loads(l) for l in sp.check_output(['journalctl','-b','--no-pager','-o','json','_PID=1','_UID=0','UNIT='+u]).splitlines()]
 assert not (CG/u).exists() and len([x for x in ev if x.get('MESSAGE_ID')=='7ad2d189f7e94e70a38c781354912448' and x.get('UNIT_RESULT','success')=='success'])==1 and not (CG/'horizon-qualify-266-capped-bounded-v210.service').exists()
 print(funds.put(dest/'completion.json',dict(resources=book,process=pr,pid1=funds.put(dest/'pid1.json',ev),image=ref(image),sources=sources,fixture_tests=36,retirement_performed=False,capacity_credit=0)),flush=True)
