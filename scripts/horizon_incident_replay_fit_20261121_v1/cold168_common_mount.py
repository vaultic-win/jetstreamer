"""Inspect the common epoch 168 scratch/output mount used for atomic publication."""
import fcntl
import os
from pathlib import Path

FS_IOC_GETFLAGS = 0x80086601
FS_IMMUTABLE_FL = 0x10


def immutable(path):
    fd = os.open(path, os.O_DIRECTORY | os.O_RDONLY | os.O_CLOEXEC)
    try:
        return bool(int.from_bytes(fcntl.ioctl(fd, FS_IOC_GETFLAGS, bytes(8)), 'little') & FS_IMMUTABLE_FL)
    finally:
        os.close(fd)


def mount_id(path):
    fd = os.open(path, os.O_PATH | os.O_CLOEXEC)
    try:
        rows = (Path('/proc/self/fdinfo') / str(fd)).read_text().splitlines()
        identifier, = (row.split()[1] for row in rows if row.startswith('mnt_id:'))
        return int(identifier)
    finally:
        os.close(fd)


def verify(s, proc, run, mounted):
    parent = proc/'root'/run.relative_to('/')
    st = parent.stat()
    s.need((st.st_uid, st.st_gid, st.st_mode) == (1001, 1003, 0o40700),
           'epoch 168 attempt has foreign ownership or permissions')
    s.need(mounted[run] >= {'rw'} and 'noexec' not in mounted[run] and immutable(parent),
           'epoch 168 attempt must be an executable writable mount with immutable parent')
    original = mount_id(parent)
    for name in ('private','output'):
        dst = parent/name
        st = dst.stat()
        s.need(s.same_file(dst,run/name) and mount_id(dst)==original and
               (st.st_uid,st.st_gid,st.st_mode)==(1001,1003,0o40700) and not immutable(dst),
               'epoch 168 endpoints do not share the registered writable mount')
