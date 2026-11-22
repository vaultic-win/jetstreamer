"""Limit creation in the two original HOME metadata directories of the ready audit."""
import array
import ctypes
import errno
import fcntl
import json
import os
import re
import resource
import select
import socket
import stat
import struct
import sys
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path

RUNTIME = Path('/run/jetstreamer-ready-bounds-20261121-v1')
ROOTS = [
    Path('/var/lib/jetstreamer/horizon_runtime_data/ready-range-audit-20261121-v1'),
    Path('/home/sol/horizon-audit-reports/bucket-slot-ranges-256-20261121-v1'),
]
LOCK_OWNERS = {
    '0::/horizonaudit.slice/horizon-r2-fast-ranges-256-20261121-v1.service',
    '0::/horizonaudit.slice/horizon-r2-ready-ranges-101-300-20261121-v1.service',
}
PERMIT = 0x10000
CLOSE_WRITE, CLOSE_NOWRITE = 8, 16
OVERFLOW = 0x4000
MAX_FDS = 1024
EVENT = struct.Struct('=IBBHQii')
RESPONSE = struct.Struct('=iI')
WORD = re.compile(r'(?:0x[0-9a-fA-F]{1,16}|[0-9]{1,20})\Z')
# The event may reach the group before the submitting task has gone to sleep.
RETRY_INTERVAL = 0.02
SYSCALL_TIMEOUT = 2.0
PROC_GONE = (FileNotFoundError, ProcessLookupError)


def notify(message, fd=None):
    address = os.environ.get('NOTIFY_SOCKET')
    if address:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
            sock.connect('\0' + address[1:] if address.startswith('@') else address)
            rights = [] if fd is None else [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [fd]))]
            sock.sendmsg([message.encode()], rights)


def identity(pid):
    return Path('/proc', str(pid), 'stat').read_text().rsplit(') ', 1)[1].split()[19]


def tgid(tid):
    for line in Path('/proc', str(tid), 'status').read_text().splitlines():
        if line.startswith('Tgid:'):
            return int(line.split()[1])
    raise ValueError('missing thread group')


def syscall_text(tid):
    return Path('/proc', str(tid), 'syscall').read_text()


def open_flags(text):
    """Return None only for documented transient procfs states on x86-64."""
    fields = text.split()
    if fields == ['running']:
        return None
    if len(fields) == 3 and fields[0] == '-1' and all(WORD.fullmatch(v) for v in fields[1:]):
        return None
    if (len(fields) != 9 or not fields[0].isascii() or not fields[0].isdecimal()
            or not all(WORD.fullmatch(v) and int(v, 0) < 1 << 64 for v in fields[1:])):
        raise ValueError('invalid syscall fields')
    number = int(fields[0])
    if number == 85:  # creat
        return os.O_CREAT | os.O_WRONLY | os.O_TRUNC
    if number not in (2, 257):  # open, openat
        raise ValueError('unsupported open syscall')
    return int(fields[2 if number == 2 else 3], 0)


def persist(path, data):
    tmp = path.with_suffix('.tmp')
    tmp.write_text(json.dumps(data, sort_keys=True) + '\n')
    os.replace(tmp, path)


def load(path):
    return json.loads(path.read_bytes()) if path.exists() else {}


def key(pid, st):
    return f'{pid}/{st.st_dev}/{st.st_ino}'


def respond(fan, fd, allow):
    try:
        os.write(fan, RESPONSE.pack(fd, 1 if allow else 2))
    except OSError as exc:
        if exc.errno != errno.ENOENT:
            raise  # PID1 retains the group for the successor's orphan sweep.
        os.close(fd)
        return False
    os.close(fd)
    return True


def open_group(roots):
    inherited = int(os.getenv('LISTEN_FDS', '0'))
    if inherited:
        if (inherited != 1 or int(os.environ['LISTEN_PID']) != os.getpid()
                or os.environ.get('LISTEN_FDNAMES') != 'ready-top-guard'
                or os.readlink('/proc/self/fd/3') != 'anon_inode:[fanotify]'):
            raise RuntimeError('unexpected stored descriptor')
        # Consumed predecessor permission events retain the original numeric
        # event FD in this kernel group. Unread notifications stay queued.
        for oldfd in range(MAX_FDS):
            try:
                os.write(3, RESPONSE.pack(oldfd, 2))
            except OSError as exc:
                if exc.errno != errno.ENOENT:
                    raise
        return 3, True

    lib = ctypes.CDLL(None, use_errno=True)
    fan = lib.fanotify_init(1 | 2 | 4 | 0x100 | 0x10, os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK)
    if fan < 0:
        raise OSError(ctypes.get_errno(), 'fanotify_init')
    for root in roots:
        mask = ctypes.c_uint64(PERMIT | CLOSE_WRITE | CLOSE_NOWRITE | 0x08000000)
        if lib.fanotify_mark(fan, 1, mask, -100, os.fsencode(root)) < 0:
            raise OSError(ctypes.get_errno(), 'fanotify_mark')
    notify('FDSTORE=1\nFDNAME=ready-top-guard', fan)
    return fan, False


@dataclass
class Request:
    fd: int
    tid: int
    deadline: float = 0


class Guard:
    def __init__(self, fixture):
        self.roots = [fixture / 'metadata'] if fixture else ROOTS
        self.runtime = fixture or RUNTIME
        self.limit, self.step, self.slots = (8192, 32768, 1) if fixture else (4 << 20, 4 << 20, 2)
        self.fixture = fixture
        self.writer_state = self.runtime / 'metadata-reservations.json'
        self.reader_state = self.runtime / 'metadata-read-holds.json'
        self.writers = load(self.writer_state)
        self.readers = load(self.reader_state)
        self.fan, self.inherited = open_group(self.roots)
        self.pending = deque()

    def topology(self):
        total = 0
        linked = set()
        for root in self.roots:
            total += root.stat().st_blocks * 512
            with os.scandir(root) as entries:
                for entry in entries:
                    st = entry.stat(follow_symlinks=False)
                    if stat.S_ISREG(st.st_mode):
                        total += st.st_blocks * 512
                        linked.add(f'{st.st_dev}/{st.st_ino}')
        detached = {}
        for row in self.readers.values():
            inode = row['inode']
            if inode not in linked:
                detached[inode] = max(detached.get(inode, 0), row['bytes'])
        return total + sum(detached.values())

    def trip(self):
        for root in self.roots:
            fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                flags = array.array('L', [0])
                fcntl.ioctl(fd, 0x80086601, flags, True)
                flags[0] |= 0x10
                fcntl.ioctl(fd, 0x40086602, flags, True)
            finally:
                os.close(fd)
        persist(self.runtime / 'metadata-trip.json', {'time': time.time(), 'allocated': self.topology()})

    def release_writer(self, k):
        row = self.writers[k]
        pid = row['pid']
        try:
            if identity(pid) == row['start'] and not any(
                    v['pid'] == pid for other, v in self.writers.items() if other != k):
                soft, hard = resource.prlimit(pid, resource.RLIMIT_FSIZE)
                if soft == row['applied']:
                    restore = row['soft']
                    if hard >= 0 and (restore < 0 or restore > hard):
                        restore = hard
                    resource.prlimit(pid, resource.RLIMIT_FSIZE, (restore, hard))
        except PROC_GONE:
            pass
        del self.writers[k]
        persist(self.writer_state, self.writers)

    def release_reader(self, k):
        self.readers[k]['references'] -= 1
        if self.readers[k]['references'] == 0:
            del self.readers[k]
        persist(self.reader_state, self.readers)

    def reap(self):
        for rows in (self.readers, self.writers):
            for k, row in list(rows.items()):
                try:
                    if identity(row['pid']) == row['start']:
                        continue
                except PROC_GONE:
                    pass
                if rows is self.writers:
                    self.release_writer(k)
                else:
                    del self.readers[k]
                    persist(self.reader_state, self.readers)

    def grant(self, req):
        """Only return True when the event has been answered or canceled."""
        fd = req.fd
        try:
            flags = open_flags(syscall_text(req.tid))
            if flags is None:
                now = time.monotonic()
                if not req.deadline:
                    req.deadline = now + SYSCALL_TIMEOUT
                if now < req.deadline:
                    return False
                raise ValueError('transient syscall timed out')
            req.deadline = 0
            pid = tgid(req.tid)
            start = identity(pid)
        except (OSError, ValueError, IndexError):
            respond(self.fan, fd, False)
            return True

        st = os.fstat(fd)
        k = key(pid, st)
        if not flags & (os.O_ACCMODE | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
            previous = self.readers.get(k, {})
            reserved = self.limit if any(v['fd_inode'] == st.st_ino for v in self.writers.values()) else 0
            self.readers[k] = dict(pid=pid, start=start, inode=f'{st.st_dev}/{st.st_ino}',
                                   references=previous.get('references', 0) + 1,
                                   bytes=max(previous.get('bytes', 0), st.st_blocks * 512, reserved))
            persist(self.reader_state, self.readers)
            if not respond(self.fan, fd, True):
                self.release_reader(k)
            return True

        name = os.path.basename(os.readlink(f'/proc/self/fd/{fd}'))
        if (not self.fixture and name in ('queue.lock', 'controller.lock') and st.st_size == 0
                and flags & os.O_APPEND and not flags & os.O_TRUNC):
            try:
                owner = Path('/proc', str(pid), 'cgroup').read_text().strip()
            except OSError:
                respond(self.fan, fd, False)
                return True
            if owner in LOCK_OWNERS:
                respond(self.fan, fd, True)
                return True

        try:
            allocated = self.topology()
        except FileNotFoundError:
            # A sibling atomic rename raced the directory scan.
            respond(self.fan, fd, False)
            return True
        if allocated >= self.step:
            if not (self.runtime / 'metadata-trip.json').exists():
                self.trip()
            respond(self.fan, fd, False)
            return True
        if len(self.writers) >= self.slots or any(v['pid'] == pid for v in self.writers.values()):
            return False
        try:
            old, hard = resource.prlimit(pid, resource.RLIMIT_FSIZE)
        except OSError:
            respond(self.fan, fd, False)
            return True
        soft = min(old, self.limit) if old >= 0 else self.limit
        self.writers[k] = dict(pid=pid, start=start, soft=old, applied=soft, fd_inode=st.st_ino)
        persist(self.writer_state, self.writers)
        try:
            resource.prlimit(pid, resource.RLIMIT_FSIZE, (soft, hard))
        except OSError:
            respond(self.fan, fd, False)
            self.release_writer(k)
            return True
        if not respond(self.fan, fd, True):
            self.release_writer(k)
        return True

    def consume(self):
        data = os.read(self.fan, 65536)
        at = 0
        while at < len(data):
            length, ver, _, _, mask, fd, tid = EVENT.unpack_from(data, at)
            if ver != 3 or length < EVENT.size or length > len(data) - at or mask & OVERFLOW:
                raise RuntimeError('invalid fanotify queue record')
            at += length
            if fd < 0:
                continue
            if mask & PERMIT:
                self.pending.append(Request(fd, tid))
                continue
            try:
                if mask & (CLOSE_WRITE | CLOSE_NOWRITE):
                    k = key(tgid(tid), os.fstat(fd))
                    if mask & CLOSE_WRITE and k in self.writers:
                        self.release_writer(k)
                    if mask & CLOSE_NOWRITE and k in self.readers:
                        self.release_reader(k)
            except PROC_GONE:
                pass
            finally:
                os.close(fd)

    def run(self):
        # A granted open may still be installing its FD when PID1 hands over
        # the group. Only a close notification or a proven task exit releases
        # its reservation. The inherited queue contains any unread closes.
        self.reap()
        persist(self.runtime / 'metadata-guard-ready.json',
                dict(pid=os.getpid(), seen_blocks=self.topology(), step=self.step, per_file=self.limit,
                     simultaneous_writable_opens=self.slots, roots=list(map(str, self.roots)),
                     inherited_kernel_queue=self.inherited))
        notify('READY=1')
        while True:
            wait = RETRY_INTERVAL if any(r.deadline for r in self.pending) else .25
            if select.select([self.fan], [], [], wait)[0]:
                self.consume()
            self.reap()
            for _ in range(len(self.pending)):
                if self.grant(self.pending[0]):
                    self.pending.popleft()
                else:
                    self.pending.rotate(-1)


def main(fixture=None):
    resource.setrlimit(resource.RLIMIT_NOFILE, (MAX_FDS, MAX_FDS))
    Guard(fixture).run()


if __name__ == '__main__':
    main(Path(sys.argv[1]) if len(sys.argv) > 1 else None)
