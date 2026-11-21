"""Prepare the exact original epoch 170 node, manifest, worker and verified cache projections."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import time

R=Path("/var/lib/jetstreamer/horizon_runtime_data")
D=R/"epoch170-retry10-recovery-20261121-v1"
GUARD=R/"epoch170-retry10-guard384-20261121-v1"
OLD=R/"epoch170-retry9-recovery-20261120-v1/launch-state/epoch170"
OLD_ROOTS=R/"epoch170-ancestor-accounts-20261121-v1"
LANE=Path("/home/sol/.jetstreamer-private/epoch170-standard-lane-20261109-v1")
PARENT=LANE/"replacement-local3retry7-20261110-v1"
OLD_RUN=PARENT/"replacement-local3retry9-20261110-v1"
RUN=PARENT/"replacement-local3retry10-20261121-v1"
UNIT="horizon-qualify-170-replacement-local3retry10-20261121-v1.service"
TIMER="horizon-guard-170-replacement-local3retry10-20261121-v1.timer"
OLD_UNIT="horizon-qualify-170-replacement-local3retry9-20261110-v1.service"
IID="8d120ed88adc4afb9485fb3f61dfa29c"
PKG=Path("/usr/local/lib/jetstreamer/horizon-independent170-singleton-package-20261109-v1")
INPUTS=Path("/usr/local/lib/jetstreamer/horizon-standard-local-input170-20261110-v1")
SEAL="7c5477094ab14c267f287a76104524029f8a69ac3e489bbdb41fbe04e678e58b"
INPUT_SEAL="730ee7981393c2f8ae98e18c2b266d0436ae3593ced223602f5412be58599e26"
ARGSHA="3c15a722a6937816dc824f6656ca8b8dc96cbcdc5e145cf9eebc719846b9a09a"
GARGSHA="a2fee2fead63561e983cf9cc489962e671ee2b3e6a734d0bf74e4d572b11d4b3"
ROOTSHA="dfde6272e53a73ab669a56fe273a72c183c1871be5406b951c22452349bdf7a0"
BOOT="snapshot-73439777-AAfuW4HhAkKNYunC4zf6ipDSCUYsnVfoLMFrmBeb5Sbs.tar.zst"
NODE=PKG/"jetstreamer-node"
WORKER=PKG/"jetstreamer-historical-worker-v1-5-6"
CAP=384<<30

def need(ok,msg):
    if not ok:raise ValueError(msg)

def digest(path):
    with path.open("rb") as f:return hashlib.file_digest(f,"sha256").hexdigest()

def read(path,sha=None):
    need(path.resolve(strict=True)==path,"indirect proof "+str(path))
    with os.fdopen(os.open(path,os.O_NOFOLLOW|os.O_RDONLY|os.O_NONBLOCK),"rb") as f:
        m=os.fstat(f.fileno());need(stat.S_ISREG(m.st_mode) and m.st_uid==0 and not m.st_mode&0o022 and m.st_nlink==1 and 0<m.st_size<64<<20,"untrusted receipt "+str(path))
        raw=f.read(m.st_size+1);need(len(raw)==m.st_size and os.fstat(f.fileno()).st_ctime_ns==m.st_ctime_ns and os.path.samestat(m,path.stat()),"changed receipt")
    h=hashlib.sha256(raw).hexdigest();need(sha is None or h==sha,"foreign digest "+str(path))
    return json.loads(raw),dict(path=str(path),sha256=h)

def record(path,v,mode=0o400):
    raw=(json.dumps(v,indent=2,sort_keys=True)+"\n").encode()
    if path.exists():
        old,ref=read(path);need(old==v,"conflicting receipt "+str(path));return ref
    stage=path.with_name("."+path.name+"-"+str(os.getpid()))
    with stage.open("xb") as f:
        os.fchmod(f.fileno(),mode);f.write(raw);f.flush();os.fsync(f.fileno())
    import ctypes
    c=ctypes.CDLL(None,use_errno=True)
    if c.renameat2(-100,os.fsencode(stage),-100,os.fsencode(path),1):
        stage.unlink();raise OSError(ctypes.get_errno(),"publish "+str(path))
    fsyncdir(path.parent)
    return read(path)[1]

def fsyncdir(path):
    fd=os.open(path,os.O_DIRECTORY);os.fsync(fd);os.close(fd)

def identity(path):
    m=path.lstat();need(path.resolve(strict=True)==path and stat.S_ISREG(m.st_mode),"indirect or nonregular original")
    return [m.st_dev,m.st_ino,m.st_size,m.st_mtime_ns,m.st_ctime_ns]

def show(unit):
    keys="Id,LoadState,ActiveState,SubState,InvocationID,MainPID,ControlPID,ControlGroup,Job,NRestarts,Triggers,TriggeredBy,CPUQuotaPerSecUSec,MemoryMax,MemorySwapMax"
    raw=subprocess.check_output(["/usr/bin/systemctl","show","-p",keys,unit],text=True,timeout=15)
    return dict(l.split("=",1) for l in raw.splitlines())

def members(unit):
    cg=Path("/sys/fs/cgroup/system.slice")/unit/"cgroup.procs"
    return sorted(map(int,cg.read_text().split())) if cg.exists() else []

def native(pid):
    path=Path(f"/proc/{pid}");f=(path/"stat").read_text().rsplit(")",1)[1].split();z=(path/"exe").stat()
    return int(f[1]),int(f[19]),(path/"cgroup").read_text().strip(),z.st_dev,z.st_ino

def inputs(full):
    rows=[]
    for directory,sh in ((PKG,SEAL),(INPUTS,INPUT_SEAL)):
        seal,_=read(directory/"deployment-seal-receipt.json",sh);need(seal["destination"]==str(directory),"different input deployment")
        for v in seal["members"]:
            p=directory/v["name"];key=identity(p);m=p.stat()
            need(m.st_uid==0 and not m.st_mode&0o222 and m.st_nlink==1 and key[2]==v["bytes"],"changed normal input")
            if full:need(digest(p)==v["sha256"] and identity(p)==key,"input contents differ")
            rows.append((p,dict(path=str(p),sha256=v["sha256"],identity=key)))
    return dict(rows)

def proof():
    root,rr=read(OLD_ROOTS/"RETRY10_ROOT_PRECREATED.json",ROOTSHA);m=RUN.lstat()
    need(root["root"]==str(RUN) and RUN.resolve(strict=True)==RUN and [m.st_dev,m.st_ino,m.st_uid,m.st_gid,m.st_mode]==root["identity"][:5],
         "changed permanent successor root")
    report_path=R/"incident-replay-fit-20261121-v1/ORIGINAL_GUARD_TIMERS_RETIRED.json"
    release,_=read(report_path,"59ec2c86879321c3fb6499d0e602d1eab78c4a4d8dbcdef6f48264ded650ecbc")
    report=release["reports"]["170"];v,_=read(Path(report["path"]),report["sha256"]);st=v["guard_stop_completion"];it=v["guard_stop_intent"]
    stopped,_=read(Path(st["path"]),st["sha256"]);intent,_=read(Path(it["path"]),it["sha256"])
    need(stopped["producer_invocation_id"]==intent["producer_invocation_id"]==IID and intent["reason"]=="DATA-fulfillment-observation-failed" and
         stopped["terminal"]["pid"]==0 and not stopped["scratch_deleted"] and not members(OLD_UNIT) and show(OLD_UNIT)["ActiveState"]=="inactive","unbound predecessor")
    inv,ir=read(OLD_ROOTS/"TERMINAL9_CHECKPOINT_INVENTORY.json","cf240fbb9a490713c58617266316acf85c3380773da4ab4a9329b56102bfecd2")
    need(inv["replay_resume_available"] is False and inv["epoch_terminal"]==73871999,"different restart origin")
    for k in ("archive","bootstrap_copy"):
        q=inv[k];key=identity(Path(q["path"]));need(key[:4]==[q["device"],q["inode"],q["size"],q["mtime_ns"]],"retained predecessor differs")
    return dict(stable_root=rr,predecessor_stop=st,predecessor_intent=it,original_custody=ir)

def profile(full=False):
    origin,ref=read(OLD/"ORIGINAL_PRODUCER_ARGV.json",ARGSHA)
    need(origin[0]=="/usr/bin/systemd-run" and len(origin)==92 and origin.count(str(NODE))==1,"different normal source")
    at=origin.index(str(NODE));node_args=[a.replace(str(OLD_RUN),str(RUN)) for a in origin[at:]]
    need(node_args==[str(NODE),"170",str(RUN/"output"),"--verify","--root-checkpoint-cohort",
         "--cohort-manifest="+str(PKG/"preflight-170-v4.json"),"--cohort-manifest-fingerprint=sha256:a18e763167b4cd47833f89627209ea7b5e08e55de16152df612e2c0d9be05890",
         "--snapshot-archive="+str(INPUTS/BOOT)],"different authenticated normal argv")
    images=inputs(full);need(images[INPUTS/BOOT]["identity"][2]==2151049662,"different Bank bootstrap archive")
    indexbase=OLD_RUN/"output/compact-indexes"
    expected={(169,"slot-to-cid",15250890,114041069),(170,"slot-to-cid",15077987,114041071),(170,"cid-to-offset-and-size",4334770962,114041072)}
    indexes=list(indexbase.glob("*/*.index"));need(len(indexes)==3,"foreign compact cache population")
    projections=[dict(source=str(INPUTS/"genesis.tar.bz2"),target=str(RUN/"output/genesis.tar.bz2"),
                      identity=images[INPUTS/"genesis.tar.bz2"]["identity"],sha256=images[INPUTS/"genesis.tar.bz2"]["sha256"])]
    for p in sorted(indexes):
        ep=int(p.parent.name);key=identity(p);kind=p.name.split("-mainnet-",1)[-1].removesuffix(".index")
        need((ep,kind,key[2],key[1]) in expected and key[0]==64512 and p.stat().st_uid==1001 and p.stat().st_nlink==1,"unexpected retained cache")
        v=dict(source=str(p),target=str(RUN/"output/compact-indexes"/p.relative_to(indexbase)),identity=key)
        if full:
            independent=LANE/"output/compact-indexes"/p.relative_to(indexbase)
            h=digest(p);need(digest(independent)==h and identity(p)==key,"independent original index disagrees")
            v["sha256"]=h
        projections.append(v)
    environment=dict(a.removeprefix("--setenv=").replace(str(OLD_RUN),str(RUN)).split("=",1) for a in origin if a.startswith("--setenv="))
    return dict(epoch=170,normal_argv=node_args,environment=environment,projections=projections,node=images[NODE],worker=images[WORKER],
                manifest=images[PKG/"preflight-170-v4.json"],bootstrap=images[INPUTS/BOOT],original_argv=ref,**proof())

def prepare():
    need(os.geteuid()==0 and show(UNIT)["LoadState"]=="not-found" and not members(UNIT) and not any((RUN/"private").iterdir()),"occupied successor")
    src=profile(True);D.mkdir(mode=0o700,exist_ok=True)
    for name,mode in (("barrier",0o755),("guard-receipts",0o700)):
        p=D/name;p.mkdir(mode=mode,exist_ok=True);os.chmod(p,mode)
        need(p.stat().st_uid==0 and p.resolve(strict=True)==p,"different staged directory")
    p=RUN/"producer.log"
    with os.fdopen(os.open(p,os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK),"r+b") as f:
        m=os.fstat(f.fileno())
        need((m.st_dev,m.st_ino,m.st_size,m.st_nlink,stat.S_IMODE(m.st_mode))==(64512,113710111,0,1,0o600) and
             (m.st_uid,m.st_gid) in ((1001,1003),(0,0)) and os.path.samestat(m,p.stat()),"wrong new append inode")
        fcntl.fcntl(f,fcntl.F_SETLEASE,fcntl.F_WRLCK);os.fchown(f.fileno(),0,0);os.fsync(f.fileno());fcntl.fcntl(f,fcntl.F_SETLEASE,fcntl.F_UNLCK)
    for v in src["projections"]:
        t=Path(v["target"])
        # The service runs as sol and traverses these root-owned empty bind targets.
        for directory in reversed(t.parents):
            if directory.is_relative_to(RUN/"output") and directory!=RUN/"output":
                directory.mkdir(mode=0o755,exist_ok=True)
                need(directory.resolve(strict=True)==directory and directory.stat().st_uid==0,"foreign cache target directory")
                os.chmod(directory,0o755)
        need(t.parent.resolve(strict=True)==t.parent and t.is_relative_to(RUN/"output"),"noncanonical projection target")
        if not t.exists():
            fd=os.open(t,os.O_CREAT|os.O_EXCL|os.O_RDWR|os.O_NOFOLLOW,0o444);os.fchmod(fd,0o444);os.fsync(fd);os.close(fd);fsyncdir(t.parent)
        m=t.lstat();need(t.resolve(strict=True)==t and stat.S_ISREG(m.st_mode) and m.st_uid==0 and m.st_nlink==1 and
                         stat.S_IMODE(m.st_mode)==0o444 and m.st_size==0,"occupied projection target")
    pref=record(D/"profile.json",src,0o444)
    return record(D/"PREPARED.json",dict(schema="horizon-170-retry10-held-gate-prepared-v1",profile=pref,source=src["original_argv"],
           stable_root=src["stable_root"],predecessor_stop=src["predecessor_stop"],append_log=dict(path=str(p),device=64512,inode=113710111),
           activation=False,resource_credit_bytes=0))
