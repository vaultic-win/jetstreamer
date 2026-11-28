"""Retain original native 266 custody on its original mount and discharge only proven future growth."""
import argparse,ctypes,fcntl,hashlib,json,os,stat,subprocess,time,tempfile
from pathlib import Path
V=Path('/var/lib/jetstreamer');D=Path('/home/ubuntu/.codex/diagnostics')
ROOT=Path('/run/horizon266-native-cold-v1');UNIT='horizon-266-native-input-20261121-v1.service'
GUARD='horizon-native266-protective-v1';IID='de754f74bbac40b9877d3b912af14886'
BOOT='3b17d005-5c3a-4a0e-8841-da097e0957b5';MAIN='01a1f8f4-293b-7a91-a36e-2e7658bba721'
PROOF=V/'horizon-native266-terminal-proof-v161-cold-a1/proof.json'
EVENT=D/'horizon266-original-terminal-event-v161-v2/completion.json'
ACCT=V/'horizon266-native-accounting-v161-v1/accounting.json'
READY=D/'horizon266-scratch-v160-first-s1/ready.json'
OUT=V/'horizon266-cold-owner-discharge-v162-v1'
PIN={PROOF:'7affafddf177c057661d73b339a1e7453a9e6330b7722cf26a789088661c1658',EVENT:'c29ae381dfdbe065fdfd481f63d763884d7839345fc086c9ce9b78887f3bd13c',ACCT:'fa5d43cb4be48bde528811fbb154ebc9d98dfb436582c7f83cf2f25db808be81',READY:'a910edb6cede17e1ecc69cd8c590ee0fcff49573162ca737b6fe8fff66a6a514'}
# This is the 1MiB physical superblock maximum plus a 63MiB allowance for kernel structures.
SMALL=1<<20;RESERVE=64<<20;OLD=192000000000;OLD_FS=128<<30
IMAGE='c091d9f4007a163c43938d8f03fecdcc70c5082ff0e06d9110178d86a7917a8c'
GENESIS='133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945'
def need(ok,reason):
 if not ok:raise ValueError(reason)
def raw(p,uid=0,limit=16<<20):
 p=Path(p);fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 with os.fdopen(fd,'rb') as stream:
  m=os.fstat(fd);need(p.resolve()==p and stat.S_ISREG(m.st_mode) and m.st_uid==uid and m.st_nlink==1 and not m.st_mode&0o022 and m.st_size<=limit,'file custody '+str(p))
  data=stream.read(limit+1);after=p.lstat();need(len(data)==m.st_size and (m.st_dev,m.st_ino,m.st_ctime_ns)==(after.st_dev,after.st_ino,after.st_ctime_ns),'changed file '+str(p));return data
def sha(data):return hashlib.sha256(data).hexdigest()
def bound(p,expected=None):
 p=Path(p);data=raw(p);b=dict(path=str(p),sha256=sha(data));need(not expected or expected==b['sha256'],'different '+str(p));return b
def val(b):
 p=Path(b['path']);data=raw(p);need(sha(data)==b['sha256'],'binding '+str(p));return json.loads(data)
def ref(p):return bound(p,PIN.get(p))
def save(p,v):
 data=json.dumps(v,sort_keys=True,indent=2).encode()+b'\n'
 # Same-filesystem RENAME_NOREPLACE publishes only complete, synced bytes and never
 # replaces an existing immutable receipt. A crashed temporary file is recoverable under the lock.
 part=p.with_suffix(p.suffix+'.part')
 if part.exists():
  partial=part.lstat()
  need(stat.S_ISREG(partial.st_mode) and partial.st_uid==0,'unexpected temporary path')
  part.unlink()
 if not p.exists():
  with part.open('xb') as f:
   os.fchmod(f.fileno(),0o400);f.write(data);f.flush();os.fsync(f.fileno())
  try:
   rename=ctypes.CDLL(None,use_errno=True).renameat2
   if rename(-100,os.fsencode(part),-100,os.fsencode(p),1):
    e=ctypes.get_errno();raise OSError(e,os.strerror(e))
  except FileExistsError:pass
  finally:part.unlink(missing_ok=True)
 need(raw(p)==data,'existing record differs '+str(p))
 fs=os.open(p.parent,os.O_DIRECTORY)
 try:os.fsync(fs)
 finally:os.close(fs)
def props(unit,keys):
 ret=subprocess.check_output(['systemctl','show',unit,'-p',','.join(keys)],text=True)
 out=dict(s.split('=',1) for s in ret.splitlines());need(set(out)==set(keys),'missing manager keys');return out
def mounts(lines):
 result=[]
 for ln in lines.splitlines():
  lf,rt=ln.split(' - ',1);a,b=lf.split(),rt.split()
  if a[4]==str(ROOT) or a[4].startswith(str(ROOT)+'/'):
   result.append(dict(mount_id=int(a[0]),parent_id=int(a[1]),device=a[2],root=a[3],target=a[4],flags=a[5].split(','),fstype=b[0],source=b[1],options=b[2].split(',')))
 return result
def inspect(root=ROOT):
 need(root==ROOT and root.resolve()==root and (root.parent.lstat().st_uid==0 and not root.parent.lstat().st_mode&0o022),'unsafe root')
 need(os.readlink('/proc/self/ns/mnt')==os.readlink('/proc/1/ns/mnt') and Path('/proc/sys/kernel/random/boot_id').read_text().strip()==BOOT,'wrong original host namespace/boot')
 a=val(ref(READY))['actual'];r,=mounts(Path('/proc/self/mountinfo').read_text());m=root.lstat();v=os.statvfs(root)
 need(r['mount_id']==a['mount_rows'][0]['mount_id']==1359 and r['parent_id']==33 and r['device']=='0:123' and r['root']=='/' and r['target']==str(ROOT) and r['source']=='horizon266-native-cold' and r['fstype']=='tmpfs' and 'noswap' in r['options'] and set(('nosuid','nodev','noexec'))<=set(r['flags']),'different original mount')
 need((m.st_dev,m.st_ino,m.st_uid,m.st_gid,stat.S_IMODE(m.st_mode))==(123,1,1000,1000,0o700),'changed mount root pin')
 content={};expected={'native-result.json':(4728,IMAGE),'worker.stderr':(0,sha(b'')),'ledger/genesis.tar.bz2':(20144,GENESIS)}
 allowed=set(expected)|{'tmp','scratch','ledger'}
 def visit(d):
  for p in d.iterdir():
   n=str(p.relative_to(root));m=p.lstat()
   need(n in allowed and m.st_dev==123 and m.st_uid==1000 and not stat.S_ISLNK(m.st_mode),'unexpected residual file '+n)
   if n in expected:
    data=raw(p,1000,32768);need((len(data),sha(data))==expected[n],'changed retained '+n);content[n]={'inode':m.st_ino,'bytes':m.st_size,'sha256':sha(data)}
   else:need(stat.S_ISDIR(m.st_mode),'wrong directory');content[n]={'inode':m.st_ino};visit(p)
 visit(root);need(set(content)==allowed,'incomplete residue')
 used=(v.f_blocks-v.f_bfree)*v.f_frsize; cap=v.f_blocks*v.f_frsize
 need(used==28672 and v.f_files-v.f_ffree==7,'unexpected allocated tmpfs contents')
 return dict(boot=BOOT,mount=r,contents=content,physical_bytes=used,cap=cap,inodes=v.f_files,free_inodes=v.f_ffree,readonly=bool(v.f_flag&os.ST_RDONLY))
def frozen(s):
 r=s['mount'];return s['readonly'] and 'ro' in r['flags'] and 'ro' in r['options'] and s['cap']==SMALL and s['inodes']==64
def drained():
 e=val(ref(EVENT));p=val(ref(PROOF));a=val(ref(ACCT));f=val(e['fleet']);require_image=val(e['source_transition'])['successor']
 need(e['terminal']==ref(PROOF) and e['consumer']==require_image and f['metadata_event']==ref(PROOF) and p['native_input_qualified'] and p['cause']=='bootstrap checkpoint verified' and not p['resource_release_authorized'] and p['native_result']['worker_reaped'] and p['native_result']['worker_pid']==2563592 and p['invocation_id']==IID,'terminal acceptance')
 need(os.geteuid()==0,'privileged original custody read needed')
 m=p['terminal_manager'];keys=['Id','LoadState','InvocationID','ExecMainPID','MainPID','ControlPID','NRestarts','ActiveState','SubState','Result','ExecMainStatus','Job','TriggeredBy','Restart','KillMode','Delegate']
 s=props(UNIT,keys)
 need(all(m[k]==v for k,v in s.items()) and s['Id']==UNIT and s['MainPID']==s['ControlPID']==s['NRestarts']=='0' and s['ActiveState']=='inactive' and not (Path('/sys/fs/cgroup/system.slice')/UNIT).exists(),'native owner changed')
 orig=p['guard_history']['records'];ids=[]
 for role in ('main','worker'):
  pin=orig[role+'-pin.json']['pin'];pid=pin['pid'];ids.append(pid);statfile=Path('/proc')/str(pid)/'stat'
  if statfile.exists():
   need(int(statfile.read_text().rsplit(') ',1)[1].split()[19])!=pin['start_ticks'],'original process survives')
 need(ids==[2563315,2563592] and any(r.get('drain',{}).get('original_processes_gone') and r['producer_invocation_id']==IID for r in orig.values()),'missing authenticated drain')
 need(a['reservation']['maximum_memory_bytes']==OLD and a['reservation']['invocation_id']==IID and a['reservation']['remaining_disk_growth_bytes']==256<<20 and a['original']['guard_memory_bytes']==256<<20,'original charge')
 return dict(canonical_terminal=ref(PROOF),registered_terminal_event=e['fleet'],event_completion=ref(EVENT),original_accounting=ref(ACCT),producer=s,guard_service=GUARD+'.service',unchanged_guard_memory_bytes=256<<20,unchanged_disk_growth_bytes=256<<20)
def remount(path,limit=SMALL,inodes=64):
 # First action on the original mount is one atomic MS_REMOUNT. Its superblock
 # must show "ro" as well as the mount's VFS flags for aliases to be covered.
 fd=os.open(path,os.O_PATH|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  need(os.path.samestat(os.fstat(fd),path.lstat()),'mountpoint changed')
  fn=ctypes.CDLL(None,use_errno=True).mount
  fn.argtypes=[ctypes.c_char_p,ctypes.c_char_p,ctypes.c_char_p,ctypes.c_ulong,ctypes.c_char_p]
  rc=fn(None,os.fsencode('/proc/self/fd/'+str(fd)),None,32|1|2|4|8|(1<<21),f'size={limit},nr_inodes={inodes},noswap'.encode())
  if rc:err=ctypes.get_errno();raise OSError(err,os.strerror(err))
 finally:os.close(fd)
def active():
 need(os.geteuid()==0 and os.environ.get('CODEX_THREAD_ID')==MAIN,'Main owner only')
def proof():
 r=OUT/'discharge.json';v=val(bound(r));s=inspect();d=drained()
 need(v['schema']=='horizon266-cold-owner-physical-discharge-v1' and v['basis']==d and v['after']==s and frozen(s) and v['original_producer_memory_bytes']==OLD and v['residual_memory_reserve_bytes']==RESERVE and v['producer_future_growth_released_bytes']==OLD-RESERVE and not v['replay_admitted'] and val(v['intent'])['before']['contents']==s['contents'],'discharge changed')
 return {**v,'receipt':bound(r)}
def apply():
 active(); d=drained();OUT.mkdir(mode=0o700,exist_ok=True);need(OUT.resolve()==OUT and OUT.lstat().st_uid==0 and not OUT.lstat().st_mode&0o077,'discharge namespace')
 with (OUT/'lock').open('ab') as lock:
  fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);s=inspect()
  if (OUT/'discharge.json').exists():return proof()
  ip=OUT/'intent.json'
  if not ip.exists():
   need(not s['readonly'] and s['cap']==OLD_FS and s['inodes']==1048576,'different initial scratch state')
   save(ip,dict(schema='horizon266-cold-owner-physical-discharge-intent-v1',basis=d,before=s,qualified_source=source(),boot=BOOT))
  intent=val(bound(ip));need(intent['basis']==d and intent['qualified_source']==source(),'different interrupted transaction')
  if not frozen(s):
   need(s==intent['before'],'unaccounted partial mount change');remount(ROOT)
  after=inspect();need(frozen(after) and after['contents']==intent['before']['contents'] and after['physical_bytes']==intent['before']['physical_bytes'] and drained()==d,'failed original custody after remount')
  out=dict(schema='horizon266-cold-owner-physical-discharge-v1',intent=bound(ip),basis=d,after=after,original_producer_memory_bytes=OLD,residual_memory_reserve_bytes=RESERVE,producer_future_growth_released_bytes=OLD-RESERVE,replay_admitted=False,r2_mutations=False,remote_mutations=False)
  save(OUT/'discharge.json',out);return proof()
def source():
 # Compare actual bytes against the controlling repo's remote-tracking branch.
 repo=Path('/home/ubuntu/workspace/jetstreamer');key='tools/horizon266-full-qualification/discharge.py'
 cmd=['sudo','-n','-u','ubuntu','git','-C',repo];tip=subprocess.check_output(cmd+['rev-parse','origin/account-updates'],text=True).strip()
 data=subprocess.check_output(cmd+['show',tip+':'+key]);need(data==raw(Path(__file__).resolve()),'discharge source not published')
 return dict(repository_path=key,sha256=sha(data))
if __name__=='__main__':
 a=argparse.ArgumentParser();a.add_argument('op',choices=('inspect','apply','verify'));x=a.parse_args()
 result={'basis':drained(),'actual':inspect()} if x.op=='inspect' else (apply() if x.op=='apply' else proof())
 print(json.dumps(result,indent=2))
