import json,hashlib,os,subprocess as sp,sys
from pathlib import Path
base=Path(__file__).resolve().parent;sys.path.insert(0,str(base))
from funding import M,price,partition

from owners import MAIN,D,V,CG,ref,bound,props
import funds
def binref(path):
 st=path.lstat()
 assert path.resolve()==path and st.st_nlink==1 and st.st_uid==0 and st.st_mode&0o777==0o555 and st.st_size<2<<20
 return ref(path)
with partition.take():
 assert __debug__ and os.geteuid()==0 and os.environ['CODEX_THREAD_ID']==MAIN
 version,attempt=sys.argv[1:];build=ref(D/f'horizon266-bounded-retire-controller-v215-{version}/completion.json');b=bound(build);assert b['fixture_tests']==36 and not b['retirement_performed']
 image=b['image'];assert binref(Path(image['path']))==image
 name='horizon266-bounded-retire-real-check-v215-'+attempt;dest=D/name;u=name+'.service'
 fit=price(320*M,2*M,2*M);rr=D/('horizon-bounded265-residual-'+name);rr.mkdir(mode=0o700);funds.put(rr/'assignment.json',fit)
 fixed=Path('/home/ubuntu/workspace/jetstreamer/tools/native266-stopped-scratch/src')
 assert all(ref(fixed/k)['sha256']==v['sha256'] for k,v in b['sources'].items())
 origin=bound(fit['closed266']);src=bound(origin['handoff']);assert origin['producer_drained'] and not (CG/src['unit']).exists()
 # The census must see host PID and mount namespaces. The Rust check-only path has no retirement grant.
 properties=['Type=exec','User=root','Group=root','MemoryMax=256M','MemorySwapMax=0','CPUQuota=100%','AllowedCPUs=8','TasksMax=16','RuntimeMaxSec=600','Restart=no','NoNewPrivileges=yes','RestrictAddressFamilies=AF_UNIX','CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_DAC_OVERRIDE CAP_SYS_PTRACE CAP_FOWNER','AmbientCapabilities=CAP_DAC_READ_SEARCH CAP_DAC_OVERRIDE CAP_SYS_PTRACE CAP_FOWNER','KillMode=control-group','UMask=0077','Nice=10','IOSchedulingClass=idle']
 cmd=[image['path'],'--check-terminal'];dest.mkdir(mode=0o700);book=funds.put(dest/'booking.json',dict(fit=fit,build=build,image=image,properties=properties,argv=cmd,original=origin['handoff'],new_worker=False))
 p=sp.run(['systemd-run','--quiet','--wait','--pipe','--unit='+u,*['--property='+v for v in properties],*cmd],capture_output=True,timeout=630)
 pr=funds.put(dest/'process.json',dict(exit=p.returncode,stdout=p.stdout.decode()[-1200:],stderr=p.stderr.decode()[-1600:]));assert p.returncode==0,p.stderr[-1500:]
 result=json.loads(p.stdout);actual=bound(ref(D/'horizon266-bounded-stopped-inventory-v215-a1/completion.json'))['inventory']
 assert [result[k] for k in ('files','directories','file_bytes','allocated_file_bytes')]==[actual[k] for k in ('files','directories','logical','allocated_files')]
 keep=ref(D/'horizon266-bounded-stopped-inventory-v215-a1/completion.json');a,s=bound(keep)['members']
 assert result['partial_sha256']==a['sha256'] and result['state_sha256']==s['sha256'] and not (CG/u).exists() and not (CG/src['unit']).exists()
 ev=[json.loads(l) for l in sp.check_output(['journalctl','-b','--no-pager','-o','json','_PID=1','_UID=0','UNIT='+u]).splitlines()]
 assert len([x for x in ev if x.get('MESSAGE_ID')=='7ad2d189f7e94e70a38c781354912448' and x.get('UNIT_RESULT','success')=='success'])==1
 print(funds.put(dest/'completion.json',dict(booking=book,build=build,image=image,process=pr,pid1=funds.put(dest/'pid1.json',ev),result=result,preserved=keep,capacity_credit=0,retirement_performed=False)),flush=True)
