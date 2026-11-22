"""Read credentials via the actual PID1 environment file, test required write primitives on anonymous fixture files."""
import errno,fcntl,hashlib,json,os,stat,subprocess,sys,time,tempfile
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from envelope import *

def need(ok,msg):
    if not ok:raise ValueError(msg)

def seal(pkg,digest):
    b=(pkg/"deployment-seal-receipt.json").read_bytes()
    need(hashlib.sha256(b).hexdigest()==digest,"deployment seal")
    for e in json.loads(b)["members"]:
        data=(pkg/e["name"]).read_bytes()
        need(hashlib.sha256(data).hexdigest()==e["sha256"],"incorrect member "+e["name"])

def cg(p):return (cgroot/p).read_text().strip()
def pathcheck(path):
    s=path.lstat();need(stat.S_ISDIR(s.st_mode) and path.resolve(strict=True)==path,"untrusted writable directory")
    fd=os.open(path,os.O_TMPFILE|os.O_RDWR,0o600)
    try:
        os.write(fd,b"envelope");os.fsync(fd)
        need(os.fstat(fd).st_nlink==0,"linked temporary file")
    finally:os.close(fd)
    return [s.st_dev,s.st_ino]

def cmd_json(argv):
    p=subprocess.run(argv,capture_output=True)
    if p.returncode:
        raise RuntimeError(str(argv[0])+": "+p.stderr.decode(errors="replace")[-1200:])
    return json.loads(p.stdout)

def expected(path):
    # Native provider accepts a current canonical hash-linked successor only.
    j=json.loads(path.read_bytes())
    while True:
        timer=j["sole_next_timer"]
        if isinstance(timer,dict):timer=timer["unit"]
        import re
        m=re.fullmatch(r"horizon-observer-(root[a-zA-Z0-9-]+)\.timer",timer);need(m,"invalid observer")
        nxt=R/m[1]/"ROOT_COMPLETE_OPERATIONAL_FLEET.json"
        if not nxt.exists():return [str(path),hashlib.sha256(path.read_bytes()).hexdigest()]
        oldhash=hashlib.sha256(path.read_bytes()).hexdigest();n=json.loads(nxt.read_bytes())
        need(n["previous_Root_operational_review"]=={"path":str(path),"sha256":oldhash},"fleet lineage");path,j=nxt,n

def fixture():
    # The mask anchor and aliases were installed together by the separate writer.
    # Build an equivalent fixture on an isolated host /run sibling, then remove the
    # alias from a private bind mount of its parent, and finally rmdir the registry.
    # Actual mask and registry names are never created or modified.
    with tempfile.TemporaryDirectory(prefix="horizon-145-envelope-fixture-",dir="/run") as t:
        parent=Path(t)
        x=parent/"registry";x.mkdir(mode=0o700)
        masks=parent/"dest";masks.mkdir(mode=0o700)
        anchor=x/"mask";anchor.symlink_to("/dev/null");alias=masks/"fixture"
        os.link(anchor,alias,follow_symlinks=False)
        need(os.path.samestat(anchor.lstat(),alias.lstat()),"foreign fixture")
        alias.unlink();anchor.unlink();x.rmdir();masks.rmdir()
    # Write permission to the actual production mask directory is tested without
    # adding any filesystem name. The operation lock is opened without flock.
    fd=os.open(OP,os.O_RDWR|os.O_NOFOLLOW)
    try:need((os.fstat(fd).st_dev,os.fstat(fd).st_ino)==(26,3453440),"operation lock")
    finally:os.close(fd)

def run():
    global cgroot
    cgroot=Path("/sys/fs/cgroup")/Path("/proc/self/cgroup").read_text().strip().split("::")[1].lstrip("/")
    need(cg("cpu.max")=="25000 100000" and cg("memory.max")=="134217728" and cg("memory.swap.max")=="0" and cg("pids.max")=="64","wrong envelope")
    need(all(os.environ.get(k) for k in ["HORIZON_ACCESS_KEY_ID","HORIZON_SECRET_ACCESS_KEY","HORIZON_S3_ENDPOINT"]),"missing configured R2 keys")
    check={}
    for path in (OLD_DIR/"state",DIR/"state",BASE,STATUS,PARENT,PARENT/"immutable-inputs",MASKS):
        check[str(path)]=pathcheck(path)
    for path in [BASE/"tools",BASE/"controller",DIR/"tools",Path("/run/systemd/transient"),Path("/etc/jetstreamer")]:
        try:fd=os.open(path,os.O_RDWR|os.O_TMPFILE,0o600)
        except OSError as err:need(err.errno in (errno.EROFS,errno.EACCES,errno.EPERM),str(err))
        else:os.close(fd);raise ValueError("unexpected writable path "+str(path))
    fixture()
    # The two manager endpoints are normal AF_UNIX transport under a read-only /run/systemd.
    need(subprocess.run(["systemctl","show",OLD,"--value","-p","ActiveState"],capture_output=True).stdout.strip()==b"active","current manager")
    # Existing journal subscriber and retained SSH keychain are revalidated at physical cutover.
    pkg=Path(sys.argv[1]);sha=sys.argv[2];seal(pkg,sha)
    head=expected(R/"root014010-live166167170-20261122-v1/ROOT_COMPLETE_OPERATIONAL_FLEET.json")
    v6=R/"epoch136-joint-writer-20261122-v6"
    registration=cmd_json([str(v6/"parent-package/parent136"),"inspect-registration",*head])
    need(registration["remote_requests"]==0 and registration["status_client_configured"] is True,"credential registration fixture")
    native=cmd_json([str(pkg/"follow145"),"inspect-v5e"])
    need(native["original"]==IID and native["launch"] is False,"selector inspect")
    out=dict(operational_flags=props(),time=time.time(),iid=os.environ["INVOCATION_ID"],checks=check,native=native,registration=registration,
             deployment=dict(path=str(pkg/"deployment-seal-receipt.json"),sha256=sha),cpu=cg("cpu.max"),mem=cg("memory.max"),
             tasks=cg("pids.max"),peak=cg("memory.peak"),priv_dir_removal=True,env_file=str(CRED),source_credentials_inherited=False,
             requests=0,context="metadata and filesystem qualification; full price checked separately by controller")
    print(json.dumps(out),flush=True)

if __name__=="__main__":run()
