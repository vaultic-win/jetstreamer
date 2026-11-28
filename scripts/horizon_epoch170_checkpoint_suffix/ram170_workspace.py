"""Verify the historical worker through the producer's private noswap scratch mount."""
import hashlib
import os
from pathlib import Path
import re
import stat

SCRATCH_BYTES = 40 << 30
UID, GID = 1001, 1003


def require(ok, message):
    if not ok:
        raise ValueError(message)


def mount(pid, scratch):
    proc = Path("/proc") / str(pid)
    rows = []
    for line in (proc/"mountinfo").read_text().splitlines():
        left, right = line.split(" - ", 1)
        fields = left.split()
        if fields[4] == str(scratch):
            rows.append((fields, right.split()))
    require(len(rows) == 1, "expected one private scratch mount")
    entry, fs = rows[0]
    path = proc/"root"/scratch.relative_to("/")
    st = path.stat()
    info = os.statvfs(path)
    flags = set(entry[5].split(","))
    require(entry[3] == "/" and fs[0] == "tmpfs" and "noswap" in fs[2].split(",")
            and {"rw","nosuid","nodev"} <= flags and "noexec" not in flags
            and not any(x.startswith(("master:","shared:","propagate_from:")) for x in entry[6:])
            and not info.f_flag & (os.ST_NOEXEC|os.ST_RDONLY)
            and info.f_frsize*info.f_blocks == SCRATCH_BYTES
            and (st.st_uid,st.st_gid,stat.S_IMODE(st.st_mode)) == (UID,GID,0o700)
            and st.st_dev != Path("/home/sol").stat().st_dev
            and entry[2] == f"{os.major(st.st_dev)}:{os.minor(st.st_dev)}", "wrong scratch mount")
    return dict(path=str(scratch),mount_id=int(entry[0]),device=st.st_dev,inode=st.st_ino,bytes=SCRATCH_BYTES)


def start_ticks(proc):
    return int((proc/"stat").read_text().rsplit(") ",1)[1].split()[19])


def identity(st):
    return (st.st_dev,st.st_ino,st.st_mode,st.st_uid,st.st_gid,st.st_size,st.st_mtime_ns,st.st_ctime_ns)


def worker(pid, parent_pid, scratch, digest, group):
    proc = Path("/proc")/str(pid)
    parent = Path("/proc")/str(parent_pid)
    workspace = mount(parent_pid,scratch)
    require((proc/"ns/mnt").samefile(parent/"ns/mnt"), "worker left the producer mount namespace")
    ticks = start_ticks(proc)
    exe = proc/"exe"
    pathname = exe.readlink()
    pieces = pathname.relative_to(scratch).parts
    require(len(pieces)==4 and pieces[0]==".historical-runtime" and
            re.fullmatch(r"jetstreamer-historical-parent-[a-zA-Z0-9]+", pieces[1]) and
            pieces[2:]==("bound-worker","historical-worker"), "unregistered historical worker path")
    projected = proc/"root"/pathname.relative_to("/")
    cgroup = Path("/sys/fs/cgroup")/group.removeprefix("/")
    def census():
        return {int(v) for v in (cgroup/"cgroup.procs").read_text().split()}
    expected={pid,parent_pid}
    require(census()==expected and (proc/"cgroup").read_text().strip()=="0::"+group
            and (parent/"cgroup").read_text().strip()=="0::"+group,
            "unexpected worker or parent cgroup membership")
    # /proc/PID/exe names a file on a unit-local mount. Resolving its link
    # text against the host filesystem would inspect the wrong namespace.
    with exe.open("rb") as image, projected.open("rb") as local:
        st = os.fstat(image.fileno())
        require(identity(os.fstat(local.fileno()))==identity(st) and st.st_dev==workspace["device"]
                and stat.S_ISREG(st.st_mode) and st.st_nlink==1 and st.st_uid==UID and st.st_gid==GID
                and st.st_mode & 0o111 and not st.st_mode & 0o222 and st.st_size>0,
                "historical worker is not the private scratch executable")
        marks=[line.partition(":")[2].strip() for line in
               Path(f"/proc/self/fdinfo/{local.fileno()}").read_text().splitlines() if line.startswith("mnt_id:")]
        require(marks==[str(workspace["mount_id"])] and hashlib.file_digest(image,"sha256").hexdigest()==digest,
                "incorrect bound historical worker image or mount")
        require(all(identity(v)==identity(st) for v in (os.fstat(image.fileno()),exe.stat(),projected.lstat()))
                and exe.readlink()==pathname and start_ticks(proc)==ticks and census()==expected
                and (proc/"ns/mnt").samefile(parent/"ns/mnt") and mount(parent_pid,scratch)==workspace,
                "worker changed during inspection")
    return dict(pid=pid, path=str(pathname), start_ticks=ticks, sha256=digest, device=st.st_dev,
                inode=st.st_ino, scratch_mount=workspace)
