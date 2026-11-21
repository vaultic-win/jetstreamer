#!/usr/bin/python3 -I
"""Wait in the exact epoch 168 cgroup for its root-created first-guard permit."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

ALIAS = Path("/run/horizon-full168-metered")
RUN = Path("/home/sol/.jetstreamer-private/epoch168-standard-lane-20261109-v1/full-metered-20261121-v1")
UNIT = "horizon-qualify-168-full-metered-20261121-v1.service"
NODE = "jetstreamer-node"
WORKER = "jetstreamer-historical-worker-v1-5-6"


def need(test, msg):
    if not test:
        raise RuntimeError(msg)


def pinned(path, expected):
    need(os.statvfs(path).f_flag & os.ST_RDONLY, f"not a read-only bind: {path}")
    with path.open("rb") as f:
        m = os.fstat(f.fileno())
        need(stat.S_ISREG(m.st_mode) and m.st_uid == 0 and not m.st_mode & 0o222
             and hashlib.file_digest(f, "sha256").hexdigest() == expected, f"wrong sealed file: {path}")


def permit_matches(path, iid):
    try:
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    except FileNotFoundError:
        return False
    with os.fdopen(fd,"rb") as f:
        m=os.fstat(f.fileno())
        need(stat.S_ISREG(m.st_mode) and m.st_uid==0 and stat.S_IMODE(m.st_mode)==0o444
             and m.st_nlink==1 and m.st_size==32 and f.read(33)==iid.encode()
             and os.fstatvfs(f.fileno()).f_flag & os.ST_RDONLY, "wrong root permit")
    return True


def main():
    iid = os.environ["INVOCATION_ID"]
    args = sys.argv[1:]
    control = "/system.slice/"+UNIT
    group = Path("/sys/fs/cgroup"+control)
    quota, period = (int(v) for v in (group/"cpu.max").read_text().split())
    need(os.geteuid() == 1001 and os.getegid() == 1003 and re.fullmatch("[a-f0-9]{32}",iid)
         and int(iid,16) and Path("/proc/self/cgroup").read_text().strip() == "0::"+control
         and (group/"memory.max").read_text().strip() == str(68<<30)
         and (group/"memory.swap.max").read_text().strip() == "0" and quota == period*9,
         "producer cgroup, limits or generation differs")
    payload=RUN/"runtime/payload.json"
    pinned(payload, os.environ["HORIZON_FULL168_PAYLOAD_SHA256"])
    j=json.loads(payload.read_bytes())
    need(j["epoch"] == 168 and args == j["regular_node_argv"]
         and all(os.environ.get(k)==v for k,v in j["environment"].items()),
         "normal producer argv or environment differs")
    for name,(_,digest) in j["members"].items():
        pinned(RUN/"runtime"/name,digest)
    pinned(ALIAS/NODE, j["members"][NODE][1])
    for pair in j["indexes"]:
        p=Path(pair["target"]);m=p.stat()
        need(os.statvfs(p).f_flag & os.ST_RDONLY and
             [m.st_dev,m.st_ino,m.st_size,m.st_mtime_ns,m.st_ctime_ns]==pair["source"]["identity"],
             f"original compact-index projection differs: {p}")
    deadline=time.monotonic()+180
    permit=ALIAS/"barrier/allow"
    while time.monotonic()<deadline:
        if permit_matches(permit,iid):
            os.execve(ALIAS/NODE,args,os.environ)
        time.sleep(0.2)
    raise TimeoutError("matching first guard and post-fit permit did not arrive")


if __name__=="__main__":
    main()
