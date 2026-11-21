#!/usr/bin/python3 -IB
"""Archive the positively drained first 167 bootstrap inside its paid root and reset its empty launch surface."""
import ctypes
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

D=Path("/var/lib/jetstreamer/horizon_runtime_data/epoch167-source-index-recovery-20261121-v1")
R=Path("/home/sol/.jetstreamer-private/epoch167-standard-lane-20261109-v1/replacement-source-index-v1-20261121")
IID="4b34bcc984f640be8a7adfe9ecd5e2da"
TID="0063be80a7554b43b60768bd3179ded9"
UNIT="horizon-qualify-167-source-index-v1-20261121.service"
GUARD="horizon-guard-167-source-index-v1-20261121"
LOCK=Path("/run/horizon-epoch171-to136-g1.operation.lock")
ARCH=D/("stopped-bootstrap-"+IID)
SAVED=R/("stopped-bootstrap-"+IID)
LOG_HASH="cc61f6e1861344c8ba236a89a2e086f8659a99bca1c34e355ea82354c2765cb6"
SAMPLE="sample-b2bfcd1c36404d42b8754cfce2b6020c.json"
RECORDS={"INVENTORY_PRESTART.json":"f860c606cb28a0c371f46a0004842873fd80677be2879de6a089b4c9487f8e2a",
 "START_INTENT.json":"c19d6ad734a1b51295a688c8981a14684b2d8bed7f4acec09bd733875e0e7222",
 "ACTUAL_PRODUCER_NATIVE.json":"7f4169874112012747c8f8f05d3ee324bc2183eb430b8b1e7a93572b136cfabf",
 "ACTUAL_GUARD_PLAN.json":"e3d91cffb1143ee1dc7dd2db70c1d8603306b332d044e4d9b4e1b2170327476f",
 "GUARD_ARGV.json":"5bbae7689d95c7d2580ec529f614771091ef7c839059051da649102d20fe1d3f",
 "FIRST_GUARD.json":"e0615284a4828ec74bc126a9e4e171ba8186720f4a4f966ad2fc0040c8da1956",
 "START_FAILURE.json":"acf762b48e86ce2aea1672c00a1580b219b0f92e2fd009e8f4439c940b0d2ad6",
 "guard-receipts/"+SAMPLE:"4e9433cfe21b1c388b4ccaef4282093e63ddc0d9ebe1b9984d1c6623e5f46aa0"}

def need(ok,message):
    if not ok: raise ValueError(message)

def secure_file(p,digest=None):
    s=p.lstat()
    need(p.resolve(strict=True)==p and stat.S_ISREG(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022
         and s.st_nlink==1 and s.st_size<=8<<20,"unexpected root record "+str(p))
    b=p.read_bytes()
    need(os.path.samestat(s,p.lstat()) and (digest is None or hashlib.sha256(b).hexdigest()==digest),"replaced record "+str(p))
    return b

def sync(p):
    fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)

def move(a,b):
    need(a.parent.resolve(strict=True)==a.parent and b.parent.resolve(strict=True)==b.parent,"aliased parent")
    if ctypes.CDLL(None,use_errno=True).renameat2(-100,os.fsencode(a),-100,os.fsencode(b),1):
        n=ctypes.get_errno();raise OSError(n,os.strerror(n),str(b))
    sync(a.parent);sync(b.parent)

def put(p,data):
    if p.exists():
        need(secure_file(p)==data,"different retained record")
        return
    tmp=p.with_suffix(".writing")
    with tmp.open("xb") as f:
        f.write(data);os.fchmod(f.fileno(),0o400);f.flush();os.fsync(f.fileno())
    move(tmp,p)

def manager(unit):
    return dict(line.split("=",1) for line in subprocess.check_output(
        ["/usr/bin/systemctl","show",unit,"-p","Id,MainPID,InvocationID,ActiveState,Job,ExecStart"],text=True,timeout=10).splitlines())

def stop_event(unit,iid):
    raw=subprocess.check_output(["/usr/bin/journalctl","-b","--no-pager","-ojson","_PID=1","UNIT="+unit,
        "INVOCATION_ID="+iid,"MESSAGE_ID=9d1aaa27d60140bd96365438aad20286","JOB_TYPE=stop","JOB_RESULT=done","-n2"],text=True,timeout=10)
    rows=[json.loads(x) for x in raw.splitlines()]
    need(len(rows)==1,"missing exact original stop")
    return rows[0]["__CURSOR"]

def apply():
    need(os.geteuid()==0 and sys.flags.isolated and __debug__,"use isolated root session")
    top=R.lstat()
    need(R.resolve(strict=True)==R and (top.st_dev,top.st_ino,top.st_uid,top.st_gid)==(64512,107675649,1001,1003),"wrong permanent root")
    native=stop_event(UNIT,IID);timer=stop_event(GUARD+".timer",TID)
    for u in (UNIT,GUARD+".timer",GUARD+".service"):
        m=manager(u)
        need(m["ActiveState"] in ("inactive","failed") and not m["Job"] and int(m.get("MainPID",0))==0
             and not (Path("/sys/fs/cgroup/system.slice")/u).exists(),"unit still populated")
        if m["ActiveState"]=="failed":
            need(u==GUARD+".service" and m["InvocationID"]=="b54f8b691e7043508935a1a0cd343081" and
                 RECORDS["ACTUAL_GUARD_PLAN.json"] in m["ExecStart"],"foreign failed guard")
            subprocess.run(["/usr/bin/systemctl","reset-failed",u],check=True,timeout=10)
    need(not any((D/n).exists() for n in ("ACTUAL_ADMISSION_AND_PROTECTION.json","FIRST_PROTECTED_WORKER.json","POST_GUARD_CAPACITY.json")),
         "already admitted or partly committed")
    for p in (ARCH,ARCH/"guard-receipts",SAVED):
        p.mkdir(mode=0o700,exist_ok=True)
        m=p.lstat()
        need(p.resolve(strict=True)==p and m.st_uid==0 and m.st_mode==stat.S_IFDIR|0o700,"different archive directory")
    rows={}
    for name,expected in RECORDS.items():
        src=D/name;dst=ARCH/name
        need(src.exists()!=dst.exists(),"missing or split original "+name)
        rows[name]=json.loads(secure_file(src if src.exists() else dst,expected))
    need(rows["START_FAILURE.json"]["cgroup"]==[] and rows["START_FAILURE.json"]["producer_invocation_id"]==IID and
         "native worker transition or guard mismatch" in rows["START_FAILURE.json"]["error"] and
         rows["FIRST_GUARD.json"]["timer"]["InvocationID"]==TID and rows["ACTUAL_PRODUCER_NATIVE.json"]["MainStartTicks"]==360714218,
         "different drained candidate")
    private=R/"private";old=SAVED/"private"
    if not old.exists(): move(private,old)
    need(old.resolve(strict=True)==old and old.is_dir(),"different stopped private state")
    if not private.exists():
        private.mkdir(mode=0o700);os.chown(private,1001,1003);sync(R)
    m=private.lstat()
    need(private.resolve(strict=True)==private and (m.st_uid,m.st_gid,m.st_mode)==(1001,1003,stat.S_IFDIR|0o700)
         and not any(private.iterdir()),"occupied fresh private state")
    fd=os.open(R/"producer.log",os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,"r+b") as f:
        m=os.fstat(fd)
        need((m.st_dev,m.st_ino,m.st_uid,m.st_gid,m.st_nlink,m.st_mode)==(64512,107675655,0,0,1,stat.S_IFREG|0o600),"changed observer log")
        fcntl.fcntl(fd,fcntl.F_SETLEASE,fcntl.F_WRLCK)
        if m.st_size:
            need(m.st_size==3621,"different original log size")
            data=f.read(m.st_size+1)
            need(hashlib.sha256(data).hexdigest()==LOG_HASH,"different original log")
            put(ARCH/"producer.log",data);os.ftruncate(fd,0);os.fsync(fd)
        secure_file(ARCH/"producer.log",LOG_HASH)
        need(os.path.samestat(m,(R/"producer.log").lstat()),"changed observer log path")
        fcntl.fcntl(fd,fcntl.F_SETLEASE,fcntl.F_UNLCK)
    for name in [*RECORDS,"guard.stdout","guard.stderr"]:
        src=D/name;dst=ARCH/name
        if src.exists():
            secure_file(src,RECORDS.get(name))
            move(src,dst)
        secure_file(dst,RECORDS.get(name))
    need(not any((D/"guard-receipts").iterdir()) and os.path.samestat(top,R.lstat()),"different staged root")
    proof=dict(schema="horizon-167-closed-bootstrap-before-retry-v1",closed=IID,private=str(old),archive=str(ARCH),
         archived_records=RECORDS,original_append=LOG_HASH,producer_pid1_stop=native,timer_pid1_stop=timer,
         original_partial_retained=True,resource_credit_bytes=0,production_launch=False)
    put(D/"CLOSED_FIRST_BOOTSTRAP.json",(json.dumps(proof,sort_keys=True,indent=2)+"\n").encode())
    print(json.dumps(proof,sort_keys=True))

if __name__=="__main__":
    with LOCK.open("r+b") as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        apply()
