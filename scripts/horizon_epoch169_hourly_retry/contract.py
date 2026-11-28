"""The independently priced, single-attempt epoch 169 hourly retry."""
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile


HOME = Path("/home/sol")
RT = Path("/var/lib/jetstreamer/horizon_runtime_data")
PRIVATE = HOME / ".jetstreamer-private"
OLD = PRIVATE / "epoch169-hourly-source-20261123-v1"
OLD_CONTROL = RT / "epoch169-hourly-admission-20261123-v1"
OLD_UNIT = "horizon-qualify-169-focused-hourly-20261123-v1.service"
OLD_IID = "b01da82c3091478f920ddcc71f4d9191"
RETRY = PRIVATE / "epoch169-hourly-retry-20261128-v1"
CONTROL = RT / RETRY.name
UNIT = "horizon-qualify-169-hourly-retry-20261128-v1.service"
BARRIER = Path("/run/horizon-169-hourly-retry")
NODE_BIND = Path("/run/horizon-169-hourly")
BASE_NAME = "epoch-169-through-73245218.jet"
G = 1 << 30
M = 1 << 20
HOME_OUTPUT = 4 * G
CONTROL_BYTES = 64 * M
RAM = 56 * G
GUARD_RAM = G
PRODUCER_CPU = 2_000_000
GUARD_CPU = 1_000_000


def need(condition, reason):
    if not condition:
        raise ValueError(reason)


def identity(st):
    return dict(device=st.st_dev, inode=st.st_ino, size=st.st_size, blocks=st.st_blocks,
                mtime_ns=st.st_mtime_ns, ctime_ns=st.st_ctime_ns, owner=st.st_uid,
                group=st.st_gid, mode=stat.S_IMODE(st.st_mode), links=st.st_nlink)


def stable(path, *, expected=None, sealed=False, keep_bytes=False):
    before = path.lstat()
    need(path.resolve(strict=True) == path and stat.S_ISREG(before.st_mode) and before.st_nlink == 1
         and before.st_uid in (0, 1001) and not before.st_mode & 0o022, "unsafe regular file " + str(path))
    if sealed:
        need(before.st_uid == 0 and not before.st_mode & 0o222, "unsealed input " + str(path))
    if keep_bytes:
        need(before.st_size <= 10 << 20, "oversized receipt " + str(path))
    with path.open("rb") as source:
        need(identity(before) == identity(os.fstat(source.fileno())), "file replaced " + str(path))
        if keep_bytes:
            data = source.read()
            digest = hashlib.sha256(data).hexdigest()
        else:
            data = None
            digest = hashlib.file_digest(source, "sha256").hexdigest()
        need(identity(before) == identity(os.fstat(source.fileno())) == identity(path.lstat()),
             "file changed while reading " + str(path))
    need(expected is None or digest == expected, "unexpected digest " + str(path))
    return dict(path=str(path), sha256=digest, **identity(before)), data


def read(path, expected=None, *, sealed=True):
    binding, data = stable(path, expected=expected, sealed=sealed, keep_bytes=True)
    return json.loads(data), dict(path=str(path), sha256=binding["sha256"])


def recorded(path, value, mode=0o400):
    """No-clobber promotion after fsync, with byte-identical recovery on retry."""
    directory = path.parent
    st = directory.lstat()
    need(os.geteuid() == 0 and directory.resolve(strict=True) == directory and st.st_uid == 0
         and stat.S_ISDIR(st.st_mode) and not st.st_mode & 0o022
         and st.st_dev == HOME.stat().st_dev, "unsafe receipt destination")
    raw = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
    with tempfile.NamedTemporaryFile(mode="wb", dir=directory, prefix=".issue-", delete=False) as output:
        temporary = Path(output.name)
        try:
            os.fchmod(output.fileno(), mode)
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
            try:
                os.link(temporary, path)
            except FileExistsError:
                pass
        finally:
            temporary.unlink()
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _, ref = read(path, hashlib.sha256(raw).hexdigest())
    return ref
