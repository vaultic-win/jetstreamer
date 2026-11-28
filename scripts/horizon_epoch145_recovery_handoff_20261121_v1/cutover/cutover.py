"""Transfer the original waiting V5e follower. The semantic worker is never signalled."""
from pathlib import Path
import contextlib,fcntl,hashlib,json,os,re,select,signal,stat,subprocess,sys,time
sys.path.insert(0,str(Path(__file__).resolve().parent))
from envelope import *
ACTIVE=OLD_DIR/"EVENT_FOLLOWER_ACTIVE.json"
ACTIVE_SHA="befb55846f167579bafe8ea1b7a04a2e0f177c1764ec16c3076dee9d603761d0"
OLD_FRAGMENT="4cd3517b243e9c97144cf6ccc3e02ca167b63eea7078c8e7419c0761bb07048d"
OLD_IID="f956e61abeae40628c04cca1f9d9db79"
PROPS="Id,LoadState,ActiveState,SubState,Job,MainPID,ControlPID,InvocationID,FreezerState,ControlGroup,FragmentPath,NRestarts,Restart,CPUQuotaPerSecUSec,MemoryMax,MemorySwapMax,TasksMax,KillMode,Type,NoNewPrivileges,PrivateTmp,ProtectHome,ProtectSystem"
oldmarkers=["post-full-submission.json","post-full-actor.json","publish-submission.json","publish-actor.json","completed.json"]
boot="763ea84c-a81f-4ddd-ad36-4b1ea2ba36dd"
def need(ok,message):
    if not ok:raise RuntimeError(message)
def pin(p):
    p=Path(p);m=p.lstat()
    need(p.resolve(strict=True)==p and stat.S_ISREG(m.st_mode) and m.st_uid==m.st_gid==0 and m.st_nlink==1 and not m.st_mode&0o022 and m.st_size<=32<<20,"untrusted input "+str(p))
    with p.open('rb') as f:
        need(os.path.samestat(m,os.fstat(f.fileno())),"opening different inode")
        data=f.read()
    need(len(data)==m.st_size and m.st_ctime_ns==p.lstat().st_ctime_ns,"changing input")
    return dict(path=str(p),sha256=hashlib.sha256(data).hexdigest())
def doc(p,h):
    ref=pin(p);need(ref["sha256"]==h,"input SHA-256 mismatch "+str(p))
    raw=Path(p).read_bytes();need(hashlib.sha256(raw).hexdigest()==h,"changing input");return json.loads(raw)
def run(argv):return subprocess.run(argv,check=True,capture_output=True)
def native(unit):
    p=subprocess.run(["/usr/bin/systemctl","show",unit,"-p",PROPS],capture_output=True,text=True)
    v=dict(line.split("=",1) for line in p.stdout.splitlines())
    need(v.get("Id")==unit and (p.returncode==0 or (p.returncode==4 and v["LoadState"]=="not-found")),"manager error "+unit)
    return v
def cg(unit):return Path('/sys/fs/cgroup/system.slice')/unit
def members(unit):
    p=cg(unit)/'cgroup.procs'
    try:return set(map(int,p.read_text().split()))
    except FileNotFoundError:need(not cg(unit).exists(),"incomplete cgroup");return set()
def ticks(pid):return int(Path(f'/proc/{pid}/stat').read_bytes().rsplit(b')',1)[1].split()[19])
def argv(pid):return Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0')[:-1]
def stable(unit):
    v=native(unit)
    need(v["ActiveState"]=="active" and v["SubState"]=="running" and v["Job"]=="" and v["NRestarts"]=="0" and v["ControlGroup"]=="/system.slice/"+unit,"unit not running "+unit)
    pid=int(v["MainPID"]);need(pid in members(unit) and Path(f'/proc/{pid}/cgroup').read_text().strip()=="0::/system.slice/"+unit,"wrong process group")
    return v,pid
def drained(unit):
    v=native(unit)
    return v["ActiveState"]=="inactive" and v.get("Job","")=="" and v.get("MainPID","0")=="0" and v.get("ControlPID","0")=="0" and not members(unit)
def monitor():
    proof=doc(ACTIVE,ACTIVE_SHA)["payload"]
    for ref in [proof["deployed"],proof["seal"],proof["source_receipt"]]:need(pin(ref["path"])==ref,"previous native qualification invalid")
    op=OP.lstat()
    need((op.st_dev,op.st_ino,op.st_mode,op.st_uid,op.st_nlink)==(26,3453440,0o100600,0,1),"operation flock replaced")
    m=CONTROLLER.lstat()
    need((m.st_dev,m.st_ino,m.st_mode,m.st_uid,m.st_nlink)==(64512,100091195,0o100600,0,1),"controller flock replaced")
    need(Path('/proc/sys/kernel/random/boot_id').read_text().strip()==boot,"different boot")
    return proof
def owns(pid):
    for fd in Path(f"/proc/{pid}/fd").iterdir():
        try:
            if not os.path.samefile(fd,CONTROLLER):continue
            for line in Path(f"/proc/{pid}/fdinfo/{fd.name}").read_text().splitlines():
                v=line.split()
                if len(v)==9 and v[0]=="lock:" and v[2:]==['FLOCK','ADVISORY','WRITE',str(pid),'fc:00:100091195','0','EOF']:return True
        except FileNotFoundError:continue
    return False
def envelope(unit):
    v=native(unit);expect=dict(CPUQuotaPerSecUSec="250ms",MemoryMax="134217728",MemorySwapMax="0",TasksMax="64",KillMode="control-group",Restart="no",Type="exec",PrivateTmp="no",ProtectHome="read-only",ProtectSystem="strict",NoNewPrivileges="yes")
    need(all(v[k]==w for k,w in expect.items()),"envelope changed "+unit)
def journal(pid,proof):
    want=list(map(os.fsencode,proof['journal_argv']))
    return argv(pid)==want and os.path.samefile(f"/proc/{pid}/exe",want[0])
def original(known,frozen=False):
    proof=monitor();v,pid=stable(OLD);envelope(OLD)
    need(v['InvocationID']==OLD_IID and v['MainPID']==proof['native']['MainPID'] and ticks(pid)==365174248 and v['ControlPID']=='0',"original follower changed")
    need((v["FreezerState"]=="frozen") if frozen else (v["FreezerState"]=="running"),"unexpected freezer state")
    need(pin(v["FragmentPath"])["sha256"]==OLD_FRAGMENT,"old definition changed")
    image=Path(proof["deployed"]["path"]);need(os.path.samefile(f"/proc/{pid}/exe",image) and argv(pid)==[os.fsencode(image),b'follow-v5e'] and owns(pid),"original image/lock")
    jp=proof["journal_pid"]
    need(members(OLD)=={pid,jp} and ticks(jp)==365174257 and journal(jp,proof),"original follower crossed its journal boundary")
    if frozen:need("frozen 1" in (cg(OLD)/"cgroup.events").read_text().splitlines(),"kernel freezer incomplete")
    if known:need(v["InvocationID"]==known["invocation"] and pid==known["pid"],"follower identity changed")
    return dict(pid=pid,ticks=ticks(pid),journal_pid=jp,invocation=v["InvocationID"],controller_inode=CONTROLLER.stat().st_ino)
def empty():
    for name in oldmarkers:need(not os.path.lexists(OLD_DIR/"state"/name),"old post submission exists "+name)
    for name in ["OFFER.json","READY.json"]:need(not os.path.lexists(DIR/name),"registered selector already exists "+name)
    need(not list((DIR/"state").iterdir()),"prior selector state")
    for name in ["prestart-intent.json","admission.json","prestart-released.json","reproduction"]:
        need(not os.path.lexists(BASE/name),"prior writer state "+name)
    need(not os.path.lexists(REG),"donor registry already present")
    for unit in ["horizon-admit-136-actual-20261120-g1.service","horizon-qualify-136-actual-20261120-g1.service"]:
        need(drained(unit),"donor unit not drained "+unit)
def semantic():
    need(not os.path.lexists(INCIDENT/"failed.json"),"original semantic failure")
    need(not os.path.lexists(INCIDENT/"complete.json"),"semantic completion race, leave previous follower in charge")
    v,pid=stable(SEM)
    need(v["InvocationID"]==IID and pid==94449 and ticks(pid)==365122971,"changed semantic PID")
    return dict(invocation=IID,pid=pid,ticks=ticks(pid))
def required(sealsha,proof,proofsha):
    need(sealsha=="297a6e7c3923d3df976e1e2e9404d0422b0d0c00fbe52a27cc84e353e486b8f1","unqualified final dispatcher")
    good=doc(proof,proofsha)
    need(re.fullmatch(r"[0-9a-f]{32}",good["iid"]),"invalid filesystem service invocation")
    jid=run(["journalctl","-q","--no-pager","-b","-o","json","_PID=1","INVOCATION_ID="+good["iid"],"MESSAGE_ID=7ad2d189f7e94e70a38c781354912448"]).stdout
    records=[json.loads(line) for line in jid.splitlines()]
    need(any(row.get("UNIT","").startswith("horizon-145-fs-proof-20261122-") and row["INVOCATION_ID"]==good["iid"] for row in records),"envelope proof did not complete in PID1")
    package=IMAGE.parent;seal=doc(package/"deployment-seal-receipt.json",sealsha)
    need(seal["destination"]==str(package) and seal["sealer_sha256"]=="e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3","foreign deployment")
    for m in seal["members"]:need(pin(package/m["name"])["sha256"]==m["sha256"],"incorrect deployed "+m["name"])
    need(good["deployment"]==pin(package/"deployment-seal-receipt.json") and good["requests"]==0 and good["native"]["original"]==IID and good["priv_dir_removal"] is True,"wrong envelope witness")
    need(good["operational_flags"]==props(),"mounts or service envelope changed since filesystem qualification")
    need(good["cpu"]=="25000 100000" and good["tasks"]=="64" and good["mem"]=="134217728","wrong qualification limits")
    return good
def record(p,contents):
    raw=(json.dumps(contents,sort_keys=True,indent=2)+"\n").encode()
    tmp=p.with_name("."+p.name+"."+str(os.getpid()))
    with tmp.open("xb") as f:
        os.fchmod(f.fileno(),0o400);f.write(raw);f.flush();os.fsync(f.fileno())
    try:os.link(tmp,p)
    finally:tmp.unlink()
    d=os.open(p.parent,os.O_DIRECTORY);os.fsync(d);os.close(d)
def plan(args):
    need(len(args)==3,"supply FINAL_SEAL_HASH CAP_PROOF_PATH CAP_PROOF_HASH")
    need(drained(NEW),"successor already owns a service")
    witness=required(*args);old=original(None);empty();live=semantic()
    # Validate the actual final selector (all sealed files matched its envelope proof).
    response=json.loads(run([str(IMAGE),"inspect-v5e"]).stdout)
    need(response["original"]==IID and response["launch"] is False,"invalid current selector")
    return dict(source=live,previous=old,evidence=pin(args[1]),seal=pin(IMAGE.parent/"deployment-seal-receipt.json"),image=pin(IMAGE))
def wait(test,reason,seconds=40):
    end=time.monotonic()+seconds
    while time.monotonic()<end:
        if test():return
        time.sleep(.05)
    raise RuntimeError(reason)
def pidfd_term(pid,fd):
    fields=dict(l.split(':',1) for l in Path(f"/proc/{pid}/status").read_text().splitlines() if ':' in l)
    bit=1<<(signal.SIGTERM-1)
    need(all(not (int(fields[k].strip(),16)&bit) for k in ['SigBlk','SigCgt','SigIgn']),"frozen original does not have default unblocked SIGTERM")
    signal.pidfd_send_signal(fd,signal.SIGTERM)
def watch_matches(line,path):
    if not line.startswith("inotify wd:"):return False
    v=dict(word.split(":",1) for word in line.split()[1:] if ":" in word)
    meta=path.stat()
    # /proc/fdinfo prints the kernel dev_t (20 minor bits).
    dev=os.major(meta.st_dev)<<20 | os.minor(meta.st_dev)
    return v.get("ino")==format(meta.st_ino,"x") and v.get("sdev")==format(dev,"x") and v.get("mask")=="588"
def stop_queued(unit,original_iid,group):
    # A fatal default signal can be delivered immediately even while frozen.
    # A collected original transient service is a successful native outcome.
    v=native(unit)
    if v["LoadState"]!="not-found" and v["ActiveState"]!="inactive":
        need(v["InvocationID"]==original_iid,"service generation changed before StopUnit")
        result=subprocess.run(["systemctl","stop",unit],capture_output=True)
        need(result.returncode in (0,5),"original stop failed")
    def finished():
        v=native(unit)
        return (v["ActiveState"]=="inactive" and not v.get("Job","") and v.get("MainPID","0")=="0"
                and (not group.exists() or not (group/"cgroup.procs").read_text().strip()))
    wait(finished,"original invocation did not physically drain")
def current_owner():
    v=native(NEW)
    if v["ActiveState"]!="active" or v["SubState"]!="running":return None
    _,pid=stable(NEW);envelope(NEW)
    need(os.path.samefile(f"/proc/{pid}/exe",IMAGE) and argv(pid)==[os.fsencode(IMAGE),b'follow-v5e'],"foreign successor")
    if not owns(pid):return None
    proof=monitor()
    modes=[]
    for c in members(NEW)-{pid}:
        try:
            if journal(c,proof):modes.append(["original_semantic_journal",c])
        except FileNotFoundError:pass
    if not modes and (INCIDENT/"complete.json").is_file():
        # The genuine native binary calls completed_semantics() before installing
        # this IN_CREATE|IN_CLOSE_WRITE|IN_MOVED_TO|IN_DELETE_SELF watch on DIR.
        for f in Path(f"/proc/{pid}/fdinfo").iterdir():
            try:lines=f.read_text().splitlines()
            except FileNotFoundError:continue
            for l in lines:
                if watch_matches(l,DIR):modes.append(["ready_event_after_semantic_completion",f.name])
    if not modes:return None
    return dict(pid=pid,start_ticks=ticks(pid),iid=v["InvocationID"],controller=CONTROLLER.stat().st_ino,subscription=modes)
def cutover(args):
    good=plan(args);out=DIR/("cutover-"+str(time.time_ns()));out.mkdir(mode=0o700)
    record(out/"prepared.json",good);fd=os.pidfd_open(good['previous']['pid'])
    operation=os.open(OP,os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC)
    frozen=False;queued=False
    try:
        fcntl.flock(operation,fcntl.LOCK_EX|fcntl.LOCK_NB)
        need(os.path.samestat(os.fstat(operation),OP.lstat()),"operation lock replaced")
        original(good["previous"]);empty();semantic()
        # Mark before the manager call: interruption after a successful freeze must thaw.
        frozen=True
        run(["systemctl","freeze",OLD])
        original(good["previous"],True);empty();semantic()
        need(drained(NEW),"successor appeared")
        record(out/"frozen.json",dict(previous=good['previous'],operation=[OP.stat().st_dev,OP.stat().st_ino],time=time.time()))
        # Parent has default SIGTERM. Queue that exact signal on its kernel pidfd while
        # frozen: automatic thaw by StopUnit cannot run old user code past the barrier.
        # Persist the irreversible point before signalling; the pidfd pins the original.
        record(out/"handoff-intent.json",dict(previous=good["previous"],seal=good["seal"],time=time.time()))
        pidfd_term(good['previous']['pid'],fd);queued=True
        stop_queued(OLD,OLD_IID,cg(OLD));frozen=False
        need(drained(OLD),"old cgroup not drained");empty()
        lock=os.open(CONTROLLER,os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            need(os.path.samestat(os.fstat(lock),CONTROLLER.lstat()),"old controller lock replaced")
            record(out/"drained.json",dict(old=good['previous'],controller_inode=os.fstat(lock).st_ino,time=time.time()))
        finally:os.close(lock)
        # A terminal semantic event in this interval is retained in PID1's boot journal.
        need(not (INCIDENT/"failed.json").exists(),"semantic failure during cutover")
        run(cmd(NEW,IMAGE,["follow-v5e"]))
        result=[]
        def ready():
            observed=current_owner()
            if observed:result.append(observed)
            return bool(observed)
        wait(ready,"successor has no proven journal/inotify subscription and kernel lock")
        need(drained(OLD),"old owner reappeared");empty()
        record(out/"active.json",dict(old=good['previous'],new=result[-1],qualification=good,semantic_complete_at_start=(INCIDENT/"complete.json").exists(),when=time.time()))
        print(json.dumps(pin(out/"active.json")))
    except BaseException as exc:
        record(out/"interrupted.json",dict(error=str(exc),signal_queued=queued,prior_frozen=frozen,time=time.time()))
        if not queued and frozen and native(OLD)["InvocationID"]==OLD_IID:
            run(["systemctl","thaw",OLD])
        elif queued and drained(OLD) and drained(NEW):
            # Only rearm the exact legacy binary when no replacement or boundary
            # exists. Never submit a second owner after an ambiguous StartTransientUnit.
            empty()
            need(not (INCIDENT/"failed.json").exists(),"semantic worker failed")
            proof=monitor();image=Path(proof["deployed"]["path"])
            v=native(OLD)
            if v["LoadState"]=="loaded":
                need(pin(v["FragmentPath"])["sha256"]==OLD_FRAGMENT,"legacy fragment differs")
                run(["systemctl","start",OLD])
            elif v["LoadState"]=="not-found":
                legacy=["Type=exec","CPUQuota=25%","CPUWeight=10","Nice=15","MemoryMax=134217728","MemorySwapMax=0","TasksMax=64",
                       "UMask=0077","Restart=no","KillMode=control-group","ProtectSystem=strict","ProtectHome=read-only","PrivateTmp=no","NoNewPrivileges=yes",
                       "ReadWritePaths="+str(OLD_DIR/"state"),"StandardOutput=append:"+str(OLD_DIR/"follow.stdout"),"StandardError=append:"+str(OLD_DIR/"follow.stderr")]
                run(["/usr/bin/systemd-run","--quiet","--unit="+OLD,*[x for item in legacy for x in ("-p",item)],"--",str(image),"follow-v5e"])
            else:raise RuntimeError("uncertain original unit")
            vv,pp=stable(OLD);need(os.path.samefile(f"/proc/{pp}/exe",image),"rollback image")
            wait(lambda:owns(pp),"rearmed follower lacks controller lock")
            record(out/"legacy-restored.json",dict(pid=pp,invocation=vv["InvocationID"],image=pin(image),time=time.time()))
        raise
    finally:os.close(operation);os.close(fd)
if __name__=="__main__":
    need(os.geteuid()==0 and __debug__,"root operator")
    def interrupted(signum,frame):
        raise InterruptedError("operator received signal "+str(signum))
    for signum in [signal.SIGHUP,signal.SIGTERM]:signal.signal(signum,interrupted)
    mode,*args=sys.argv[1:]
    if mode=="original":print(json.dumps(dict(old=original(None),source=semantic(),empty=empty() is None)))
    elif mode=="preflight":print(json.dumps(plan(args)))
    elif mode=="cutover":cutover(args)
    else:raise SystemExit("original|preflight|cutover")
