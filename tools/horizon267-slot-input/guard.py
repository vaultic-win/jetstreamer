"""One timer-driven physical-floor check for the exact finite actor."""
import hashlib,json,os,stat,subprocess,sys,time
from pathlib import Path
BASE=Path('/var/lib/jetstreamer/horizon267-slot-input-v1')
CG=Path('/sys/fs/cgroup/system.slice')

def need(ok,why):
    if not ok:raise ValueError(why)
def props(unit,keys):
    p=subprocess.run(['/usr/bin/systemctl','show',unit,'--all','-p',','.join(keys)],text=True,capture_output=True)
    need(p.returncode in (0,4),p.stderr)
    return dict(l.split('=',1) for l in p.stdout.splitlines())
def ref(p):
    with p.open('rb') as f: return dict(path=str(p),sha256=hashlib.file_digest(f,'sha256').hexdigest())
def save(p,v,replace=False):
    t=p.with_suffix('.new') if replace else p
    with t.open('x') as f:
        json.dump(v,f,separators=(',',':'));f.flush();os.fchmod(f.fileno(),0o400);os.fsync(f.fileno())
    if replace:os.replace(t,p)
    fd=os.open(p.parent,os.O_DIRECTORY);os.fsync(fd);os.close(fd)
def physical(p):
    s=p.lstat()
    if not stat.S_ISDIR(s.st_mode):return s.st_blocks*512
    return s.st_blocks*512+sum(physical(Path(child.path)) for child in os.scandir(p))
def run(phase):
    need(phase in ('transfer','verify'),'wrong phase')
    ctl=BASE/(phase+'-control');book=ctl/'booking.json'
    b=json.loads(book.read_bytes());unit=b['unit'];bind=json.loads((ctl/'binding.json').read_bytes());iid=bind['iid']
    name=unit[:-8]+'-guard.service';tick=os.environ['INVOCATION_ID']
    need(Path('/proc/self/cgroup').read_text().strip()=='0::/system.slice/'+name and b['phase']==phase and bind['booking']==ref(book),'guard binding')
    actor=props(unit,['Id','ActiveState','SubState','MainPID','ControlPID','NRestarts','InvocationID'])
    if actor.get('ActiveState') in ('inactive','failed'):
        subprocess.run(['/usr/bin/systemctl','--no-block','stop',name[:-8]+'.timer'],check=True);return
    try:
        need(actor['Id']==unit and actor['InvocationID']==iid and actor['NRestarts']=='0','original actor changed')
        root=CG/unit
        need((root/'memory.max').read_text().strip()==str(b['limits']['memory_max_bytes']) and (root/'memory.swap.max').read_text().strip()=='0' and (root/'cpuset.cpus.effective').read_text().strip()==str(b['cpu']),'kernel budget')
        try:n=physical(BASE)
        except FileNotFoundError:n=physical(BASE)
        v=os.statvfs(BASE);free=v.f_bavail*v.f_frsize
        need(n<=b['disk_reserve'] and free>b['minimum_free_bytes'],'disk ceiling or fleet floor')
        report=dict(actor=actor,invocation=iid,guard_invocation=tick,booking=ref(book),guard_unit=name,free=free,charged=n,monotonic=time.monotonic(),trip=False)
        if not (ctl/'first.json').exists():
            need(actor['ActiveState']=='activating' and actor['SubState']=='start-pre' and actor['MainPID']=='0' and int(actor['ControlPID'])>1,'missed native startup gate')
            save(ctl/'first.json',report)
        save(ctl/'latest.json',report,True)
    except BaseException as err:
        if not (ctl/'trip.json').exists(): save(ctl/'trip.json',dict(invocation=iid,guard_invocation=tick,error=str(err)))
        if props(unit,['InvocationID']).get('InvocationID')==iid:
            subprocess.run(['/usr/bin/systemctl','--no-block','stop',unit],check=True)
        raise
if __name__=='__main__':run(sys.argv[1])
