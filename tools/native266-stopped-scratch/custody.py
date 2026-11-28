"""Hold verified, sealed in-memory copies of the two stopped producer files for one phase."""
import contextlib
import errno
import fcntl
import hashlib
import json
import os
import stat
import sys
from pathlib import Path

GUEST = Path('/home/ubuntu/.jetstreamer-private/qualification-266-instructions-2789f821-v169')
RUN = (GUEST / 'state/destination-7842454ffe9bde170be8ce42da5b2a5b9ffe7770939d4697f306fceecf45b7c3'
       / 'work/root-cohort-266-266/run-2863142-1795309320359102473')
FILES = {
    'archives/epoch-266.jet': (5767194, 488934107, 1795310933092021856,
                              '0cbc940306fb1fce868729390ff4c38b0967fd18ff73eaf4b19a0ddbc71cff2d'),
    'cohort-state.json': (5767179, 222, 1795309320358444375,
                          '2c9c246126a8878f8e11928858512f8ef881a6a794118c04d1a1572b18427c87'),
}
SEALS = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SEAL

def require(value, message):
    if not value:
        raise ValueError(message)

def identity(m):
    return (m.st_dev, m.st_ino, m.st_size, m.st_mode, m.st_uid, m.st_gid, m.st_nlink,
            m.st_mtime_ns, m.st_ctime_ns)

def capture(stack, name):
    inode, size, timestamp, expected = FILES[name]
    path = RUN / name
    original = (1801, inode, size, stat.S_IFREG | 0o600, 1000, 1000, 1, timestamp, timestamp)
    require(path.resolve(strict=True) == path and identity(path.lstat()) == original, 'source custody')
    source = stack.enter_context(os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NOATIME), 'rb', buffering=0))
    require(identity(os.fstat(source.fileno())) == original, 'opened different file')
    fd = os.memfd_create('stopped-266-' + path.name, os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    dest = stack.enter_context(os.fdopen(fd, 'w+b', buffering=0))
    h = hashlib.sha256()
    copied = 0
    while block := source.read(1 << 20):
        copied += len(block)
        require(copied <= size, 'source grew')
        h.update(block)
        view = memoryview(block)
        while view:
            n = dest.write(view)
            require(n and n > 0, 'short memfd write')
            view = view[n:]
    require(copied == size and h.hexdigest() == expected, 'source length or digest')
    fcntl.fcntl(fd, fcntl.F_ADD_SEALS, SEALS)
    require(fcntl.fcntl(fd, fcntl.F_GET_SEALS) & SEALS == SEALS, 'incomplete sealing')
    try:
        os.pwrite(fd, b'X', 0)
    except OSError as error:
        if error.errno != errno.EPERM:
            raise
    else:
        raise ValueError('sealed file accepted a write')
    dest.seek(0)
    require(hashlib.file_digest(dest, 'sha256').hexdigest() == expected, 'sealed content')
    require(identity(os.fstat(source.fileno())) == identity(path.lstat()) == original, 'source changed')
    st = os.fstat(fd)
    require(st.st_dev != 1801 and st.st_nlink == 0 and st.st_size == size, 'custody geometry')
    return dict(name=name, original=list(original), memfd_device=st.st_dev, memfd_inode=st.st_ino,
                bytes=size, sha256=expected, seals=fcntl.fcntl(fd, fcntl.F_GET_SEALS))

@contextlib.contextmanager
def hold_originals():
    # Both immutable copies and both originals remain open until the enclosing phase exits.
    with contextlib.ExitStack() as stack:
        yield [capture(stack, name) for name in FILES]

if __name__ == '__main__':
    if sys.argv[1:] != ['--qualify']:
        raise SystemExit('expected --qualify')
    with hold_originals() as members:
        print(json.dumps(dict(members=members, phase_only=True, invocation=os.environ['INVOCATION_ID'])))
