"""Project the authenticated std-only compiler closure into a closed directory tree."""
import hashlib
import json
import os
import stat
from pathlib import Path

ORIGINAL = Path('/var/lib/jetstreamer/horizon-status234-toolchain1641-v1/toolchain.json')
MANIFEST_SHA = 'de5155665ce8d8975bf8aad79e24909f05942b4c235125a33cf98d123da2067f'
BASE = Path('/var/lib/jetstreamer/horizon267-slot-input-v1')
VIEW = BASE / 'toolchain'
HOST = Path('/home/ubuntu/.rustup/toolchains/1.98.0-x86_64-unknown-linux-gnu')
FIELDS = ('device','inode','length','mode','uid','gid','link_count','mtime_ns','ctime_ns')

def check(value, message):
    if not value:
        raise ValueError(message)

def manifest():
    p=Path(__file__).resolve().parent/'toolchain.json'
    raw=p.read_bytes()
    check(hashlib.sha256(raw).hexdigest()==MANIFEST_SHA,'compiler provenance digest')
    v=json.loads(raw)
    check(v['sysroot']==str(HOST) and len(v['files'])==88 and v['total_file_bytes']==526411005,'compiler inventory')
    return v

def files(v):
    return [(Path(f['path']),VIEW/Path(f['path']).relative_to(HOST)) for f in v['files'] if Path(f['path']).is_relative_to(HOST)]

def setup(v):
    check(ORIGINAL.read_bytes()==(Path(__file__).resolve().parent/'toolchain.json').read_bytes(),'original root compiler receipt differs')
    check(not os.path.lexists(VIEW),'used compiler projection')
    VIEW.mkdir(mode=0o755)
    for source,target in files(v):
        check(source.resolve()==source,'compiler source path alias')
        target.parent.mkdir(mode=0o755,parents=True,exist_ok=True)
        with target.open('xb') as f:
            os.fchmod(f.fileno(),0o444)
    for d in [VIEW,*[p for p in VIEW.rglob('*') if p.is_dir()]]:d.chmod(0o555)

def stamp(m):
    return [m.st_dev,m.st_ino,m.st_size,m.st_mode,m.st_uid,m.st_gid,m.st_nlink,m.st_mtime_ns,m.st_ctime_ns]

def check_view(v,full):
    pairs=dict(files(v))
    lib=VIEW/Path(v['target_library_directory']).relative_to(HOST)
    check(sorted(p.name for p in lib.iterdir())==sorted(v['complete_target_lib_directory_entries']),'projected target-library census')
    check({p for p in VIEW.rglob('*') if p.is_file()}==set(pairs.values()),'unexpected file in projected sysroot')
    mounts={s.split(' - ',1)[0].split()[4]:s.split(' - ',1)[0].split()[5].split(',') for s in Path('/proc/self/mountinfo').read_text().splitlines()}
    for d in [VIEW,*[p for p in VIEW.rglob('*') if p.is_dir()]]:
        m=d.lstat();check(d.resolve()==d and m.st_uid==m.st_gid==0 and stat.S_IMODE(m.st_mode)==0o555,'sysroot directory ownership')
    for rec in v['files']:
        host=Path(rec['path']);p=pairs.get(host,host)
        expected=[rec[k] for k in FIELDS]
        check(p.resolve()==p and stat.S_ISREG(rec['mode']) and stamp(p.lstat())==expected,'unrecognized compiler input '+str(p))
        if host in pairs:
            check('ro' in mounts.get(str(p),[]) and stamp(host.lstat())==expected,'unbound compiler inode '+str(p))
        else:
            check(rec['uid']==rec['gid']==0 and not rec['mode']&0o022 and os.statvfs(p).f_flag&os.ST_RDONLY,'writable system linker input '+str(p))
        if full:
            with p.open('rb') as f:
                check(stamp(os.fstat(f.fileno()))==expected and hashlib.file_digest(f,'sha256').hexdigest()==rec['sha256'] and stamp(os.fstat(f.fileno()))==expected and stamp(p.lstat())==expected,'compiler read/hash drift '+str(p))
    return dict(manifest_sha256=MANIFEST_SHA,files=88,individual_readonly_binds=len(pairs),bytes_hashed=sum(r['length'] for r in v['files']) if full else 0,closed_sysroot=str(VIEW))
