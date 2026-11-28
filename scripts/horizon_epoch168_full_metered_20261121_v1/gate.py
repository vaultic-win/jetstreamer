#!/usr/bin/python3 -I
"""Wait in the exact epoch 168 cgroup for its root-created first-guard permit."""
import fcntl
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
COLD_ROUTES = {
    Path("/run/horizon-full168-cold-v2/gate.py"): ("cold-retry2-20261122", "cold-v2-20261122"),
    Path("/run/horizon-full168-cold-v3/gate.py"): ("cold-retry3-20261123", "cold-v3-20261123"),
    Path("/run/horizon-full168-cold-v4/gate.py"): ("cold-retry4-20261123", "cold-v4-20261123"),
    Path("/run/horizon-full168-cold-v5/gate.py"): ("cold-retry5-20261125", "cold-v5-20261125"),
}
gate = Path(__file__)
COLD = gate in COLD_ROUTES
if COLD:
    directory, generation = COLD_ROUTES[gate]
    ALIAS = gate.parent
    RUN = RUN / directory
    UNIT = f"horizon-qualify-168-full-metered-{generation}.service"
INPUTS = ALIAS if COLD else RUN / "runtime"
NODE = "jetstreamer-node"
WORKER = "jetstreamer-historical-worker-v1-5-6"
V5_GATE = Path("/run/horizon-full168-cold-v5/gate.py")
FS_IOC_GETFLAGS = 0x80086601
FS_IMMUTABLE_FL = 0x10


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


def verify_common_mount(run):
    """Ensure archive staging and publication can use an atomic rename."""
    ids = set()
    for path in (run, run / "private", run / "output"):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            m = os.fstat(fd)
            flags = int.from_bytes(fcntl.ioctl(fd, FS_IOC_GETFLAGS, bytes(8)), "little")
            need((m.st_uid, m.st_gid, stat.S_IMODE(m.st_mode)) == (1001, 1003, 0o700)
                 and bool(flags & FS_IMMUTABLE_FL) == (path == run)
                 and not os.fstatvfs(fd).f_flag & os.ST_RDONLY,
                 f"different common replay directory: {path}")
            info = (Path("/proc/self/fdinfo") / str(fd)).read_text().splitlines()
            mount, = (line.split()[1] for line in info if line.startswith("mnt_id:"))
            ids.add(mount)
        finally:
            os.close(fd)
    need(len(ids) == 1, "archive staging and publication must share a mount")


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
    payload=INPUTS/"payload.json"
    pinned(payload, os.environ["HORIZON_FULL168_PAYLOAD_SHA256"])
    j=json.loads(payload.read_bytes())
    need(j["epoch"] == 168 and args == j["regular_node_argv"]
         and all(os.environ.get(k)==v for k,v in j["environment"].items()),
         "normal producer argv or environment differs")
    for name,(_,digest) in j["members"].items():
        pinned(INPUTS/name,digest)
    pinned(ALIAS/NODE, j["members"][NODE][1])
    for pair in j["indexes"]:
        p=Path(pair["target"]);m=p.stat()
        need(os.statvfs(p).f_flag & os.ST_RDONLY and
             [m.st_dev,m.st_ino,m.st_size,m.st_mtime_ns,m.st_ctime_ns]==pair["source"]["identity"],
             f"original compact-index projection differs: {p}")
    if COLD:
        for target, row in [(Path(j["bootstrap_file"]["path"]), j["bootstrap_file"]),
                            (RUN/"output/genesis.tar.bz2", j["genesis"])]:
            m = target.stat()
            need(os.statvfs(target).f_flag & os.ST_RDONLY and
                 [m.st_dev,m.st_ino,m.st_size,m.st_mtime_ns,m.st_ctime_ns] == row["identity"],
                 f"original bank or genesis projection differs: {target}")
    if gate == V5_GATE:
        need(j["producer_unit"] == UNIT and j["whole_root_cap"] == 512 << 30,
             "different retry5 producer or physical cap")
        verify_common_mount(RUN)
    deadline=time.monotonic()+180
    permit=ALIAS/"barrier/allow"
    while time.monotonic()<deadline:
        if permit_matches(permit,iid):
            if gate == V5_GATE:
                verify_common_mount(RUN)
            os.execve(ALIAS/NODE,args,os.environ)
        time.sleep(0.2)
    raise TimeoutError("matching first guard and post-fit permit did not arrive")


if __name__=="__main__":
    main()
