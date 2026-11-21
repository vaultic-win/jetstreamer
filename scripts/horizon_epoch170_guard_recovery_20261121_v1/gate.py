"""Hold the actual epoch 170 service PID until its own native guard and post-fit are durable."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

ALIAS=Path("/run/horizon-recovered170")
UNIT="horizon-qualify-170-replacement-local3retry10-20261121-v1.service"

def need(ok,msg):
    if not ok:raise ValueError(msg)

def trusted(path,sha=None):
    with os.fdopen(os.open(path,os.O_NOFOLLOW|os.O_RDONLY|os.O_NONBLOCK),"rb") as f:
        m=os.fstat(f.fileno())
        need(stat.S_ISREG(m.st_mode) and not m.st_mode&0o022 and m.st_uid==0 and
             os.fstatvfs(f.fileno()).f_flag&os.ST_RDONLY,"untrusted gate input")
        if sha is not None:need(hashlib.file_digest(f,"sha256").hexdigest()==sha,"gate input changed")
        return m

def permit(iid, path=ALIAS/"barrier/allow"):
    try:fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    except FileNotFoundError:return False
    with os.fdopen(fd,"rb") as f:
        m=os.fstat(f.fileno())
        need(stat.S_ISREG(m.st_mode) and m.st_uid==0 and stat.S_IMODE(m.st_mode)==0o444 and m.st_nlink==1 and
             m.st_size==32 and f.read(33)==iid.encode() and os.fstatvfs(f.fileno()).f_flag&os.ST_RDONLY,"wrong gate permit")
    return True

def payload(arguments):
    profile=ALIAS/"profile.json";trusted(profile,os.environ["HORIZON_REPLAY170_PROFILE_SHA256"]);p=json.loads(profile.read_bytes())
    need(p["epoch"]==170 and arguments==p["normal_argv"] and all(os.environ.get(k)==v for k,v in p["environment"].items()),"foreign normal payload")
    trusted(Path(p["normal_argv"][0]),p["node"]["sha256"])
    for v in p["projections"]:
        path=Path(v["target"]);m=path.stat()
        need(os.statvfs(path).f_flag&os.ST_RDONLY and [m.st_dev,m.st_ino,m.st_size,m.st_mtime_ns,m.st_ctime_ns]==v["identity"],
             "source projection changed")
    return p

def main():
    need(sys.flags.isolated and __debug__ and os.getuid()==1001 and os.getgid()==1003,"unexpected service owner")
    iid=os.environ["INVOCATION_ID"]
    need(re.fullmatch(r"[a-f0-9]{32}",iid) and int(iid,16) and Path("/proc/self/cgroup").read_text().strip()=="0::/system.slice/"+UNIT,
         "unexpected actual cgroup")
    cg=Path("/sys/fs/cgroup/system.slice")/UNIT
    quota,period=map(int,(cg/"cpu.max").read_text().split())
    need(quota==9*period and int((cg/"memory.max").read_text())==68<<30 and (cg/"memory.swap.max").read_text().strip()=="0",
         "changed cgroup limits")
    p=payload(sys.argv[1:])
    end=time.monotonic()+360
    while time.monotonic()<end:
        if permit(iid):os.execv(p["normal_argv"][0],p["normal_argv"])
        time.sleep(.2)
    raise TimeoutError("native guard did not release the actual epoch 170 gate")

if __name__=="__main__":main()
