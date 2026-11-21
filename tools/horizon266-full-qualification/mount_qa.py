"""Run by Main via sudo unshare -m --propagation private python3 -B <this-file>."""
import ctypes, errno, json, os, subprocess, tempfile
from pathlib import Path
from discharge import need, remount, sha, SMALL
def run():
    need(os.geteuid()==0 and os.readlink('/proc/self/ns/mnt')!=os.readlink('/proc/1/ns/mnt'),'requires isolated private mount namespace')
    before=Path('/proc/self/mountinfo').read_text().splitlines()
    need(all(not any(k.startswith(('shared:','master:')) for k in l.split(' - ')[0].split()[6:]) for l in before),'requires private propagation')
    with tempfile.TemporaryDirectory(prefix='horizon266-mount-qa-',dir='/tmp') as tmp:
        path=Path(tmp)
        subprocess.run(['/usr/bin/mount','-t','tmpfs','-o','size=4M,nr_inodes=128,nosuid,nodev,noexec,noswap','horizon266-qa',path],check=True)
        try:
            f=path/'sample'; f.write_bytes(b'original proof\n'*2048); pin=f.stat()
            old=os.statvfs(path);digest=sha(f.read_bytes())
            remount(path)
            now=os.statvfs(path); flags=[l for l in Path('/proc/self/mountinfo').read_text().splitlines() if l.split()[4]==tmp]
            need(len(flags)==1 and flags[0].split()[5].split(',')[0]=='ro' and flags[0].split(' - ')[1].split()[2].split(',')[0]=='ro','read-only mount/superblock')
            need(now.f_flag&os.ST_RDONLY and now.f_frsize*now.f_blocks==SMALL and now.f_files==64 and old.f_frsize*old.f_blocks==4<<20,'physical limits')
            need(os.path.samestat(f.stat(),pin) and sha(f.read_bytes())==digest and 'noswap' in flags[0],'content or noswap lost')
            try:f.open('ab').close()
            except OSError as e:need(e.errno==errno.EROFS,'wrong denial')
            else:raise RuntimeError('writable after seal')
            need(tmp not in Path('/proc/1/mountinfo').read_text(),'host namespace changed')
            print(json.dumps({'private_namespace':True,'before_bytes':old.f_blocks*old.f_frsize,'after_bytes':now.f_blocks*now.f_frsize,'after_inodes':now.f_files,'EROFS':True,'unchanged_content':digest,'mountinfo':flags[0]}))
        finally:subprocess.run(['/usr/bin/umount',tmp],check=True)
if __name__=='__main__':run()
