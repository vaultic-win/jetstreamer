"""Bind retained files, native derived-file inventory and namespace census before any reclamation."""
import sys,os,subprocess as sp,json,hashlib,stat
from pathlib import Path
sys.path.insert(0,str(Path(__file__).parent))
from funding import price, M, D, V, CG, ref, bound, partition
import funds
prior=Path('/run/horizon249-251-rotation-v205-a1')
def replace(src,values):
 for old,new in values:
  assert old in src,old
  src=src.replace(old,new)
 return src
with partition.take():
 key='horizon266-bounded-stopped-inventory-v215-'+sys.argv[1];dest=D/key;stage=Path('/run')/key
 fit=price(416*M,8*M,4*M)
 rr=D/('horizon-bounded265-residual-'+key);rr.mkdir(mode=0o700);assignment=funds.put(rr/'assignment.json',fit)
 stop=fit['closed266'];q=bound(stop);h=bound(q['handoff']);mt=ref(Path(h['spec']['path']).with_name('mount.json'));mount=bound(mt)
 root=Path(mount['root']);img=Path(mount['backing']);arc=Path(q['archive']['path']);run=arc.parents[1];parent=run/'scratch/.historical-runtime'
 assert q['bounded_target_met'] and q['handoff']==ref(V/'horizon266-capped-bounded-v210-control/pilot/handoff.json')
 assert img.stat().st_ino==13850126 and img.stat().st_size==344997011456 and root.stat().st_dev==1810 and mount['loop']=='/dev/loop18'
 child,=parent.iterdir();runtime,=[x for x in child.iterdir() if x.name.startswith('jetstreamer-historical-v1.8.11-')]
 assert (parent.stat().st_ino,child.stat().st_ino,runtime.stat().st_ino)==(19005455,19005456,19005461)
 expected=[arc,run/'cohort-state.json']
 def ids():
  return [[s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns] for s in [p.lstat() for p in expected]]
 original=ids();assert [(r[0],r[1],r[2]) for r in original]==[(1810,19005466,5085745842),(1810,19005451,222)]
 stage.mkdir(mode=0o755);dest.mkdir(mode=0o700)
 for old,digest in [('v194-inventory/inventory.rs','847ef307ecdd42bf3096a68a493f3bc658e230c92d0d24f097b2c2e95343f5eb'),('retained266-a2.py','d611f960081834e6aa4a72067474b45624541f1182f2fae3328aaee94dd40965'),('census266.py','520fc4dd00c8afc5eb4fc2fc9951941cd10da60a692a6a0be827920c283e5420')]:
  assert ref(prior/old)['sha256']==digest
 def source(name,s):
  p=stage/name;p.write_text(s);p.chmod(0o444);return p
 oldroot='/home/ubuntu/.jetstreamer-private/qualification-266-instructions-2789f821-v194'
 oldrun=oldroot+'/state/destination-74cdfe7e1c89e4a0cb05e5bab400c86f7c3bf8eb5465bf28fcda37ebfd52105c/work/root-cohort-266-266/run-3215067-1795375088043578768'
 mappings=[(oldrun,str(run)),('jetstreamer-historical-parent-RXHuqy',child.name),('16252944','19005456'),('1804','1810')]
 inv=source('inventory.rs',replace((prior/'v194-inventory/inventory.rs').read_text(),mappings+[('/dev/loop12','/dev/loop18'),('jetstreamer-historical-v1.8.11-DUyhUa',runtime.name)]))
 retained=source('retained.py',replace((prior/'retained266-a2.py').read_text(),mappings+[(oldroot,str(root)),('16252954,5085926416','19005466,5085745842')]))
 cen=source('census.py',replace((prior/'census266.py').read_text(),[(oldroot,str(root)),('/var/lib/jetstreamer/horizon266-instructions-2789f821-v194-control/pilot/private.ext4',str(img)),('loop12','loop18'),('7, 12','7, 18'),('7:12','7:18'),('7:0c','7:12'),('7:c ','7:12 '),('7:0*c','7:0*12'),('18340079','13850126'),('416','804'),('320 << 30','344997011456'),('320<<30','344997011456')]))
 out=stage/'output';out.mkdir(mode=0o700);os.chown(out,1000,1000)
 common=['Type=exec','KillMode=control-group','Restart=no','CPUQuota=100%','AllowedCPUs=8','MemoryMax=256M','MemorySwapMax=0','TasksMax=24','RuntimeMaxSec=660','Nice=10','IOSchedulingClass=idle','PrivateNetwork=yes','PrivateDevices=yes','NoNewPrivileges=yes','ProtectSystem=strict','ProtectHome=read-only','ReadOnlyPaths=/','TemporaryFileSystem=/tmp:rw,nosuid,nodev,noswap,size=48M,mode=1777','LimitFSIZE=5M','UMask=0077']
 def invoke(phase,cmd,props):
  u=key+'-'+phase+'.service'
  plan=funds.put(dest/(phase+'-request.json'),dict(cmd=list(map(str,cmd)),props=props,unit=u))
  r=sp.run(['systemd-run','--quiet','--wait','--pipe','--unit='+u,*['--property='+v for v in props],*map(str,cmd)],capture_output=True,timeout=685)
  process=funds.put(dest/(phase+'-process.json'),dict(exit=r.returncode,stderr=r.stderr.decode()[-2400:],stdout_sha256=hashlib.sha256(r.stdout).hexdigest()));assert r.returncode==0,r.stderr[-1400:]
  ev=[json.loads(l) for l in sp.check_output(['journalctl','-b','--no-pager','-o','json','_PID=1','_UID=0','UNIT='+u]).splitlines()]
  end,=[x for x in ev if x.get('MESSAGE_ID')=='7ad2d189f7e94e70a38c781354912448' and x.get('UNIT_RESULT','success')=='success'];assert not (CG/u).exists() and not (CG/h['unit']).exists() and original==ids()
  return r.stdout,dict(plan=plan,process=process,iid=end['INVOCATION_ID'],manager=funds.put(dest/(phase+'-manager.json'),ev))
 b=funds.put(dest/'booking.json',dict(assignment=assignment,stop=stop,mount=mt,members=original,source=[ref(x) for x in (cen,inv,retained)],original_source=[ref(prior/'v194-inventory/inventory.rs'),ref(prior/'census266.py'),ref(prior/'retained266-a2.py')],phase_floor=fit['protected_floor'],issuer=ref(Path(__file__))))
 proof={}
 rust='/home/ubuntu/.rustup/toolchains/1.98.0-x86_64-unknown-linux-gnu/bin/rustc';image=out/'inspect'
 _,proof['build']=invoke('build',[rust,'--edition=2024','-Dwarnings','-C','opt-level=1','-C','strip=symbols',inv,'-o',image],common+['User=ubuntu','Group=ubuntu','ReadWritePaths='+str(out)])
 os.chown(out,0,0);os.chown(image,0,0);os.chmod(image,0o555)
 ro=common+['CapabilityBoundingSet=CAP_DAC_READ_SEARCH','AmbientCapabilities=CAP_DAC_READ_SEARCH']
 raw,proof['preserve']=invoke('preserve',['/usr/bin/sha256sum','--',*expected],ro)
 members=[dict(path=str(p),identity=identity,sha256=line.split('  ')[0]) for p,identity,line in zip(expected,original,raw.decode().splitlines(),strict=True)]
 assert original[0][2]==q['archive']['size'] and all(line.split('  ')[1]==m['path'] for line,m in zip(raw.decode().splitlines(),members))
 raw,proof['inventory']=invoke('inventory',[image],ro);inventory=json.loads(raw)
 hist=bound(bound(fit['planning'])['peak_sample']);assert inventory['files']>100000 and 0<inventory['allocated_files']<=hist['maximum_root_physical_bytes']
 records=[]
 for i in (1,2):
  raw,proof[f'retained{i}']=invoke(f'retained{i}',['/usr/bin/python3','-IB',retained],ro);records.append(json.loads(raw))
 assert records[0]==records[1] and sum(r['kind']=='file' for r in records[0].values())==7
 for r in members:
  x=records[0][str(Path(r['path']).relative_to(root))];assert [x[k] for k in ('dev','ino','size','mtime','ctime')]==r['identity']
 host=bound(ref(D/'horizon266-stopped-v194-release-basis-v206-a1/booking.json'))['properties'];assert 'AllowedCPUs=40' in host;host=[v.replace('AllowedCPUs=40','AllowedCPUs=8') for v in host]
 raw,proof['census']=invoke('census',['/usr/bin/python3','-IB',cen],host);c=json.loads(raw)
 assert c['geometry']==[804,1810,2,66305,13850126,344997011456] and c['readonly_observation'] and not c['references'] and c['invocation']==proof['census']['iid']
 print(funds.put(dest/'completion.json',dict(booking=b,evidence=proof,original_stop=stop,members=members,retained=funds.put(dest/'retained.json',records[0]),inventory=inventory,census=funds.put(dest/'census.json',c),image=ref(image),root=str(root),run=str(run),derived=str(child),runtime=runtime.name,resources_released=False,retirement_authorized=False)),flush=True)
