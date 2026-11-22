"""Exercise the freeze, default SIGTERM, shared inode and terminal event race with disposable units."""
import fcntl,hashlib,os,select,signal,stat,subprocess,sys,time,json
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import cutover as c
def unit(name,*args):return c.run(["systemctl",name,*args])
def participant(who,root):
    lock=os.open(root/"lock",os.O_RDWR);fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    (root/(who+".active")).write_text(str(os.getpid()))
    end=time.monotonic()+45
    while not (root/"complete").exists() and time.monotonic()<end:time.sleep(.05)
    if (root/"complete").exists():
        with (root/(who+".crossed")).open("x") as f:f.write("semantic result")
    else:raise RuntimeError("timed out")
def launch(name,who,r):
    opts=["Type=exec","CPUQuota=25%","CPUWeight=10","Nice=15","MemoryMax=134217728","MemorySwapMax=0","TasksMax=64","Restart=no","KillMode=control-group","UMask=0077","ProtectSystem=strict","ProtectHome=read-only","ReadWritePaths="+str(r),"NoNewPrivileges=yes","RuntimeMaxSec=60"]
    c.run(["systemd-run","--quiet","--unit="+name,"--slice=horizonaudit.slice",*[x for item in opts for x in ("-p",item)],"--","/usr/bin/python3","-IB",str(Path(__file__).resolve()),who,str(r)])
    c.wait(lambda:(r/(who+".active")).exists(),"fixture did not acquire controller")
def fixture(root):
    import ctypes
    lib=ctypes.CDLL("libc.so.6",use_errno=True);fd=lib.inotify_init1(os.O_CLOEXEC)
    c.need(fd>=0,"inotify fixture")
    try:
        c.need(lib.inotify_add_watch(fd,os.fsencode(root),0x588)>0,"real ready watch")
        line=next(x for x in Path(f"/proc/self/fdinfo/{fd}").read_text().splitlines() if x.startswith("inotify wd:"))
        c.need(c.watch_matches(line,root) and not c.watch_matches(line,root.parent) and not c.watch_matches(line.replace("mask:588","mask:8"),root),"wrong inotify identity")
    finally:os.close(fd)
    results={"ready_watch":"kernel dev_t,exact inode and mask; other parent/mask rejected"}
    for ix,kind in enumerate(["crossed_while_frozen","arrived_in_handoff_gap"]):
        here=root/kind;here.mkdir(mode=0o700)
        lock=here/"lock";lock.touch(mode=0o600)
        old="horizon-145-cutover-fixture-"+str(os.getpid())+"-"+str(ix)+".service";new=old.replace("fixture-","fixture-new-")
        try:
            launch(old,'legacy',here);pid=int((here/'legacy.active').read_text());fd=os.pidfd_open(pid)
            unit('freeze',old);cg=Path('/sys/fs/cgroup/horizonaudit.slice')/old
            c.need("frozen 1" in (cg/"cgroup.events").read_text().splitlines(),"cgroup not frozen")
            if ix==0:
                (here/"complete").touch();unit('thaw',old);c.wait(lambda:(here/"legacy.crossed").exists(),"old lost completion");c.need(not (here/"successor.active").exists(),"duplicate successor")
                results[kind]="old continued and consumed completion"
            else:
                original_iid=c.native(old)['InvocationID'];c.pidfd_term(pid,fd);c.stop_queued(old,original_iid,cg)
                c.need(not cg.exists() or not (cg/'cgroup.procs').read_text().strip(),"legacy cgroup remains")
                l=os.open(lock,os.O_RDWR);fcntl.flock(l,fcntl.LOCK_EX|fcntl.LOCK_NB);os.close(l)
                (here/"complete").touch();launch(new,"successor",here)
                c.wait(lambda:(here/"successor.crossed").exists(),"new owner missed completion")
                c.need(not (here/"legacy.crossed").exists(),"old crossed")
                results[kind]="new owner acquired exact original lock and consumed buffered completion"
            os.close(fd)
        finally:
            for name in (old,new):
                subprocess.run(['systemctl','stop',name],capture_output=True)
    print(json.dumps(results))
if __name__=="__main__":
    who,path=sys.argv[1:];r=Path(path)
    if who=='fixture':fixture(r)
    else:participant(who,r)
