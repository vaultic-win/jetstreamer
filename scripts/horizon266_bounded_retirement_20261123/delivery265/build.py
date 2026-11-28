import sys,os,time,tarfile,json,hashlib,subprocess as sp
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
from funding import price,partition,M,D,V,ref,bound,CG
import funds
commit=sys.argv[1];attempt=sys.argv[2];name='horizon265-delivery-consumers-v215-'+attempt;stage=Path('/run')/name;dst=V/(name+'-qualified');unit=name+'.service'
old=Path('/run/horizon266-capped-consumers-v201-a4');git=['sudo','-n','-u','ubuntu','git','-C','/home/ubuntu/workspace/jetstreamer']
def sha(p):
 with Path(p).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def put(p,b):
 with p.open('xb') as f: f.write(b);os.fchmod(f.fileno(),0o444);f.flush();os.fsync(f.fileno())
def dump(v):return (json.dumps(v,indent=2)+'\n').encode()
with partition.take():
 q=price(6400*M,256*M,112*M,consumer_build=True,closed_disk=(V/'horizon266-closed-residual-delivery265-v215/assignment.json').exists());dest=D/name;dest.mkdir(mode=0o700)
 previous=bound(ref(D/'horizon266-capped-consumers-v201-a4/completion.json'));seal=bound(previous['seal'])
 original=bound(ref(old/'booking.json'))
 for leaf in ('commands.json','source.sha256','offline-qualification.json','tools.sha256','externs.sha256','build.py'):
  assert any(x['name']==leaf and x['sha256']==sha(old/leaf) for x in seal['members']),leaf
 files=set(l.split('  ',1)[1] for l in (old/'source.sha256').read_text().splitlines())
 files.update(sp.check_output([*git,'ls-tree','-r','--name-only',commit,'--','jetstreamer-r2/src','jetstreamer-horizon-observe/src','tools/singleton211-launch/src'],text=True).splitlines())
 import re,posixpath
 known=set(sp.check_output([*git,'ls-tree','-r','--name-only',commit],text=True).splitlines())
 source=Path('/home/ubuntu/workspace/jetstreamer')
 for k in tuple(files):
  if not k.endswith('.rs'): continue
  data=(source/k).read_text()
  for val in re.findall(r'include_(?:str|bytes)!\s*\(\s*"([^"]+)"',data):
   inc=posixpath.normpath(posixpath.join(posixpath.dirname(k),val))
   if inc in known:files.add(inc)
 assert 'scripts/horizon_epoch167_ancestor_accounts_20261122_v1/profiles168.json' in files
 stage.mkdir(mode=0o755);src=stage/'src';src.mkdir(mode=0o755);out=stage/'result';out.mkdir(mode=0o700);os.chown(out,1000,1000)
 rs=D/('horizon-bounded265-residual-consumers265-v215-'+attempt);rs.mkdir(mode=0o700);assignment=funds.put(rs/'assignment.json',q)
 with sp.Popen([*git,'archive',commit,'--',*sorted(files)],stdout=sp.PIPE) as proc,tarfile.open(fileobj=proc.stdout,mode='r|') as tar:
  for m in tar:
   if m.isdir():continue
   assert m.isfile() and m.name in files
   file=src/m.name;file.parent.mkdir(parents=True,exist_ok=True);put(file,tar.extractfile(m).read())
 assert proc.returncode==0 and all((src/x).is_file() for x in files)
 put(stage/'source.sha256',''.join(f'{sha(src/x)}  {x}\n' for x in sorted(files)).encode())
 for leaf in ('commands.json','tools.sha256','externs.sha256','build.py'):put(stage/leaf,(old/leaf).read_bytes())
 recipe=json.loads((old/'offline-qualification.json').read_bytes());recipe.update(commit=commit,source_files=len(files),deployed_observer=str(dst/'jetstreamer-horizon-observe'))
 put(stage/'offline-qualification.json',dump(recipe));put(stage/'host-netns',(os.readlink('/proc/self/ns/net')+'\n').encode())
 put(stage/'inputs.sha256',''.join(f'{sha(stage/k)}  {k}\n' for k in ('source.sha256','commands.json','offline-qualification.json','build.py','externs.sha256','tools.sha256')).encode())
 assert int(sp.check_output(['du','-sB1',stage],text=True).split()[0])<=64*M
 args=[a.replace(old.name,name).replace('AllowedCPUs=56','AllowedCPUs=8') for a in original['args']]
 book=dict(unit=unit,cpu=8,activate_before_unix=int(time.time())+180,args=args,assignment=assignment,source=commit,prior=previous['seal'],public_archive_authority=False)
 put(stage/'booking.json',dump(book));bk=funds.put(dest/'booking.json',book)
 run=sp.run([args[0],'--wait',*args[1:]],capture_output=True,timeout=2500)
 pr=funds.put(dest/'process.json',dict(code=run.returncode,stdout=run.stdout.decode()[-500:],stderr=run.stderr.decode()[-800:]))
 assert run.returncode==0,(run.stderr[-600:],pr)
 qual=ref(out/'qualification.json');data=json.loads((out/'qualification.json').read_bytes());assert data['booking']==ref(stage/'booking.json') and data['unit']==unit
 # The registration test needs the original private PID1 receipts.
 test=out/'wrapper-tests';before=sha(test)
 rc=sp.run(['taskset','-c','8',test,'bounded_writer_reopens_its_runtime_and_issued_booking','--ignored','--test-threads=1'],capture_output=True)
 rootqa=funds.put(dest/'bounded-test.json',dict(code=rc.returncode,stdout=rc.stdout.decode(),stderr=rc.stderr.decode(),image=before))
 assert rc.returncode==0 and b'1 passed; 0 failed' in rc.stdout and sha(test)==before,(rc.stdout,rc.stderr)
 assert not (CG/unit).exists()
 print(funds.put(dest/'completion.json',dict(booking=bk,compiler=qual,originals=rootqa,assignment=assignment,commit=commit,process=pr,archive_ready=False)),flush=True)
