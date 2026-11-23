"""Retire a pinned set of single-link compiler outputs on the same Linux mount.

The owner gate and current consumer census are supplied by the host entry point.
An interrupted run retains its root-private quarantine and can resume from its
last durable batch. Neither inspection nor fixture qualification authorizes it.
"""
import contextlib
import ctypes
import fcntl
import hashlib
import json
import os
import signal
import stat
import tempfile
from pathlib import Path


class Refused(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise Refused(str(message))


def stamp(st):
    return [st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid, st.st_nlink,
            st.st_size, st.st_blocks, st.st_mtime_ns, st.st_ctime_ns]


def identity(path):
    return stamp(path.lstat())


def fingerprint(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def read(path):
    return json.loads(path.read_bytes())


def free(path):
    disk = os.statvfs(path)
    return disk.f_bavail * disk.f_frsize


@contextlib.contextmanager
def directory(path):
    require(path.resolve(strict=True) == path, f'aliased directory {path}')
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        require(os.path.samestat(os.fstat(fd), path.lstat()), f'directory changed: {path}')
        yield fd
    finally:
        os.close(fd)


def rename(src_fd, src, dst_fd, dst):
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.renameat2(src_fd, os.fsencode(src), dst_fd, os.fsencode(dst), 1):
        number = ctypes.get_errno()
        raise OSError(number, os.strerror(number), str(src))


def publish(path, value):
    raw = (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()
    with directory(path.parent) as parent:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix='.write-', delete=False) as file:
            tmp = Path(file.name)
            os.fchmod(file.fileno(), 0o400)
            file.write(raw)
            file.flush()
            os.fsync(file.fileno())
        try:
            rename(parent, tmp.name, parent, path.name)
            os.fsync(parent)
        finally:
            tmp.unlink(missing_ok=True)


@contextlib.contextmanager
def locks(bindings):
    with contextlib.ExitStack() as held:
        for path, expected in bindings:
            require(path.resolve(strict=True) == path and stat.S_ISREG(expected[2]) and expected[5] == 1, path)
            fd = os.open(path, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
            held.callback(os.close, fd)
            require(stamp(os.fstat(fd)) == expected == identity(path), f'lock identity changed: {path}')
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
        for path, expected in bindings:
            require(identity(path) == expected, f'lock replaced while held: {path}')


@contextlib.contextmanager
def lease(parent, name, expected, *, moved=False):
    fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    try:
        fcntl.fcntl(fd, fcntl.F_SETLEASE, fcntl.F_WRLCK)
        before = stamp(os.fstat(fd))
        require(before == stamp(os.stat(name, dir_fd=parent, follow_symlinks=False)), 'leased pathname changed')
        require((before[:-1] == expected[:-1] if moved else before == expected), f'changed compiler inode: {name}')
        yield fd
        require(fcntl.fcntl(fd, fcntl.F_GETLEASE) == fcntl.F_WRLCK, 'file lease broken')
    finally:
        os.close(fd)


def interrupted(number, frame):
    raise Refused(f'interrupted by signal {number}')


def state_of(parent, leaf):
    try:
        return stamp(os.stat(leaf, dir_fd=parent, follow_symlinks=False))
    except FileNotFoundError:
        return None


def secure_state(path):
    s = path.lstat()
    require(path.resolve(strict=True) == path and s.st_uid == os.geteuid()
            and s.st_mode == stat.S_IFDIR | 0o700, f'unsafe state directory {path}')


class Retirement:
    """A persisted intent binds all originals, parents and retained dependencies."""

    def __init__(self, state, files, scope, closure, batch_size=128, *, open_lease=lease):
        self.state = state
        self.quarantine = state / 'quarantine'
        self.files = sorted((Path(path), ids) for path, ids in files.items())
        self.scope = scope
        self.closure = closure
        self.batch_size = batch_size
        self.open_lease = open_lease
        self.total = sum(x[7] * 512 for _, x in self.files)
        require(self.files and 0 < batch_size <= 128, 'empty or oversized batch')
        unique = {(s[0], s[1]) for _, s in self.files}
        require(len(unique) == len(self.files) and all(stat.S_ISREG(s[2]) and s[5] == 1 and s[7] > 0
                                                     for _, s in self.files), 'non-exclusive inode')

    def visit(self, first, last, parents, function):
        with directory(self.quarantine) as dst:
            for i in range(first, last):
                path, original = self.files[i]
                with directory(path.parent) as src:
                    require(stamp(os.fstat(src))[:5] == parents[str(path.parent)], f'changed parent {path.parent}')
                    function(i, src, path.name, dst, str(i), original)

    def parents(self):
        result = {}
        for d in sorted({x.parent for x, _ in self.files}):
            with directory(d) as handle:
                result[str(d)] = stamp(os.fstat(handle))[:5]
        return result

    def verify_originals(self):
        for path, expected in self.files:
            require(identity(path) == expected and path.resolve(strict=True) == path, f'original changed: {path}')

    def inspect(self):
        self.verify_originals()
        controls = self.closure()
        self.verify_originals()
        return dict(schema='horizon-exact-cargo-inspection-v1', scope=self.scope, files=len(self.files),
                    allocated_bytes=self.total, parents=self.parents(), controls=controls, credited_bytes=0)

    def run(self, inspection, *, event=lambda _: None):
        secure_state(self.state)
        require(inspection['scope'] == self.scope and inspection['allocated_bytes'] == self.total
                and inspection['files'] == len(self.files), 'inspection scope differs')
        parents = inspection['parents']
        require(self.parents() == parents, 'parent identities changed after inspection')
        initial = self.state / 'intent.json'
        controls = self.closure()
        if not initial.exists():
            self.verify_originals()
            require(not self.quarantine.exists(), 'quarantine predates intent')
            publish(initial, dict(scope=self.scope, selection_sha256=digest([(str(p), s) for p, s in self.files]),
                                  parent_sha256=digest(parents), batch_size=self.batch_size,
                                  controls=controls, free_before=free(self.state)))
        intent = read(initial)
        require(intent['scope'] == self.scope and intent['selection_sha256'] == digest([(str(p), s) for p, s in self.files])
                and intent['parent_sha256'] == digest(parents) and intent['batch_size'] == self.batch_size,
                'intent changed')
        if not self.quarantine.exists():
            self.quarantine.mkdir(mode=0o700)
            with directory(self.state) as fd:
                os.fsync(fd)
        secure_state(self.quarantine)
        require(self.quarantine.stat().st_dev == self.files[0][1][0], 'quarantine on different filesystem')
        if (self.state / 'complete.json').exists():
            receipt = read(self.state / 'complete.json')
            require(receipt['intent_sha256'] == fingerprint(initial) and receipt['allocated_bytes_retired_once'] == self.total,
                    'unexpected completion receipt')
            self.verify_absence()
            return receipt
        for start in range(0, len(self.files), self.batch_size):
            end = min(start + self.batch_size, len(self.files))
            self.batch(start, end, parents, event)
        self.verify_absence()
        receipt = dict(schema='horizon-exact-cargo-retired-v1', intent_sha256=fingerprint(initial),
                       allocated_bytes_retired_once=self.total, files=len(self.files), free_before=intent['free_before'],
                       free_after=free(self.state), controls=self.closure(), credited_bytes=0, remote_mutations=False)
        publish(self.state / 'complete.json', receipt)
        return receipt

    def verify_absence(self):
        require(not list(self.quarantine.iterdir()) and all(not os.path.lexists(path) for path, _ in self.files),
                'unexpected surviving source or quarantine entry')

    def batch(self, start, end, parents, event):
        stage = self.state / f'captured-{start}.json'
        done = self.state / f'retired-{start}.json'
        if done.exists():
            require(read(done) == dict(captured_sha256=fingerprint(stage), start=start, end=end), 'bad completed batch')
            return

        def capture(i, src, original, dst, name, expected):
            current, staged = state_of(src, original), state_of(dst, name)
            if staged is None:
                require(current == expected, f'missing original before capture: {i}')
                with self.open_lease(src, original, expected) as fd:
                    rename(src, original, dst, name)
                    require(state_of(src, original) is None and state_of(dst, name) == stamp(os.fstat(fd)), 'capture replaced')
                    event('after-rename')
            else:
                require(current is None, f'original recreated during interrupted capture: {i}')
            with self.open_lease(dst, name, expected, moved=True) as fd:
                return stamp(os.fstat(fd))

        if not stage.exists():
            captured = {}
            def record(i, *args):
                captured[str(i)] = capture(i, *args)
            self.visit(start, end, parents, record)
            # Ensure every source removal and captured name is durable before recording
            # the batch which permits unlinks. Sync each participating directory once.
            for parent in {p.parent for p, _ in self.files[start:end]} | {self.quarantine}:
                with directory(parent) as handle:
                    os.fsync(handle)
            publish(stage, dict(start=start, end=end, stamps=captured, intent_sha256=fingerprint(self.state / 'intent.json')))
            event('after-captured-receipt')
        batch = read(stage)
        require(batch['start'] == start and batch['end'] == end and batch['intent_sha256'] == fingerprint(self.state / 'intent.json')
                and set(batch['stamps']) == {str(i) for i in range(start, end)}, 'invalid captured batch')

        def unlink(i, src, original, dst, name, expected):
            captured = batch['stamps'][str(i)]
            require(state_of(src, original) is None and captured[:-1] == expected[:-1], 'unexpected original or capture')
            # A durable batch receipt exists before the first unlink. This is a
            # root-private directory; an absent captured name is an interrupted unlink.
            if state_of(dst, name) is None:
                return
            with self.open_lease(dst, name, captured) as fd:
                os.unlink(name, dir_fd=dst)
                require(os.fstat(fd).st_nlink == 0 and state_of(dst, name) is None, 'inode still linked')
                event('after-unlink')
        self.visit(start, end, parents, unlink)
        with directory(self.quarantine) as dst:
            os.fsync(dst)
        publish(done, dict(captured_sha256=fingerprint(stage), start=start, end=end))
