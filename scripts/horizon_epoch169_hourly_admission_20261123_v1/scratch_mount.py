"""Validate the host-visible HOME and unit-private writable scratch for 169."""
import os
import stat
from pathlib import Path

GIB = 1 << 30
SCRATCH = Path("/home/sol/.jetstreamer-private/epoch169-hourly-source-20261123-v1/v158/scratch")
TMPFS_BYTES = 44 * GIB
INODES = 600_000
OUTPUT_ALLOWANCE = 8 * GIB
CONTROL_ALLOWANCE = 64 << 20
MOUNT_OPTIONS = "rw,nosuid,nodev,exec,noswap,mode=0700,uid=1001,gid=1003,size=44G,nr_inodes=600000"


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def parse_record(data, scratch):
    records = []
    for line in data.splitlines():
        left, sep, right = line.partition(" - ")
        require(sep, "incomplete mount record")
        fields = left.split()
        require(len(fields) >= 6, "malformed mount record")
        if fields[4] == str(scratch):
            records.append((fields, right.split()))
    require(len(records) == 1, "missing or stacked private scratch mount")
    fields, super_fields = records[0]
    require(len(super_fields) == 3, "incomplete scratch superblock")
    options = set(fields[5].split(","))
    super_options = set(super_fields[2].split(","))
    require(super_fields[:2] == ["tmpfs", "tmpfs"] and fields[3] == "/"
            and {"rw", "nodev", "nosuid"} <= options and not {"ro", "noexec"} & options
            and {"rw", "noswap", "mode=700", "uid=1001", "gid=1003",
                 "size=46137344k", "nr_inodes=600000"} <= super_options,
            "scratch type, access, hard limit, or swap changed")
    return fields[0], fields[2]


def native(pid, scratch=SCRATCH):
    require(isinstance(pid, int) and pid > 1 and scratch.is_absolute(), "invalid scratch owner")
    proc = Path("/proc") / str(pid)
    mount_id, device = parse_record((proc / "mountinfo").read_text(), scratch)
    projected = proc / "root" / scratch.relative_to("/")
    before = projected.stat()
    vfs = os.statvfs(projected)
    require(stat.S_ISDIR(before.st_mode) and stat.S_IMODE(before.st_mode) == 0o700
            and (before.st_uid, before.st_gid) == (1001, 1003)
            and f"{os.major(before.st_dev)}:{os.minor(before.st_dev)}" == device
            and vfs.f_frsize * vfs.f_blocks == TMPFS_BYTES and vfs.f_files == INODES,
            "private scratch inode or capacity changed")
    same_host_namespace = (Path("/proc/self/ns/mnt").stat().st_ino == (proc / "ns/mnt").stat().st_ino)
    if not same_host_namespace:
        host = scratch.stat()
        require(host.st_dev != before.st_dev and host.st_dev == Path("/home/sol").stat().st_dev
                and not any(scratch.iterdir()), "HOME scratch mountpoint is occupied or aliases the tmpfs")
    now = projected.stat()
    require((before.st_dev, before.st_ino) == (now.st_dev, now.st_ino)
            and (mount_id, device) == parse_record((proc / "mountinfo").read_text(), scratch),
            "private scratch mount crossed identity")
    return dict(mount_id=mount_id, device=before.st_dev, inode=before.st_ino, path=str(scratch),
                type="tmpfs", noswap=True, ram_limit_bytes=TMPFS_BYTES, maximum_inodes=INODES)
