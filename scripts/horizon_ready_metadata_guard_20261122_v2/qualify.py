"""Exercise the metadata guard with an isolated marked directory and PID1's FD store."""
import ctypes
import errno
import hashlib
import importlib.util
import json
import os
import resource
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
GUARD = HERE / 'metadata.py'


def guard_module():
    spec = importlib.util.spec_from_file_location('ready_guard', GUARD)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def fixture_receiver(base):
    predecessor = base / 'initial-v1'
    if predecessor.exists():
        source = Path('/usr/local/lib/jetstreamer/horizon-ready-output-budget-20261121-v1/metadata.py')
        assert hashlib.sha256(source.read_bytes()).hexdigest() == '5ed3b9d132cdafb12feb9a825e6ec32972bbc5f200d32a604488ea50c3dd41ca'
        predecessor.unlink()
        os.execv('/usr/bin/python3', ['/usr/bin/python3', '-IB', str(source), str(base)])
    guard = guard_module()
    native_read = guard.syscall_text

    def syscall_text(tid):
        control = base / f'fixture-{tid}'
        if control.exists():
            mode = control.read_text()
            marker = base / f'observed-{tid}'
            marker.touch()
            if mode == 'running':
                return 'running\n'
            if mode == 'malformed':
                return '257 0x0 invalid\n'
            if mode == 'unsupported':
                return '437 ' + '0x0 ' * 8
            if mode == 'gone':
                raise ProcessLookupError(errno.ESRCH, 'task gone')
        return native_read(tid)

    guard.syscall_text = syscall_text
    guard.main(base)


def wait_for(predicate, limit=8):
    deadline = time.monotonic() + limit
    while not predicate():
        if time.monotonic() >= deadline:
            raise RuntimeError(f'timed out waiting for {predicate}')
        time.sleep(.015)


def read(path):
    return json.loads(path.read_bytes())


def state(base, name):
    filename = base / f'metadata-{name}.json'
    return read(filename) if filename.exists() else {}


def child(base, file, write, expected, mode, retain=False):
    # The controlling process conveys observations over pipes, outside the mark.
    def action():
        if mode:
            (base / f'fixture-{os.getpid()}').write_text(mode)
        orig = resource.getrlimit(resource.RLIMIT_FSIZE)
        (base / f'opening-{os.getpid()}').touch()
        try:
            fd = os.open(base / 'metadata' / file, os.O_RDWR if write else os.O_RDONLY)
        except OSError as exc:
            assert exc.errno == expected, (exc, expected)
            print('denied', flush=True)
            return
        assert expected == 0
        assert resource.getrlimit(resource.RLIMIT_FSIZE) == ((8192, orig[1]) if write else orig)
        if write:
            signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
            os.pwrite(fd, bytes(8192), 0)
            try:
                os.pwrite(fd, b'x', 8192)
            except OSError as exc:
                assert exc.errno == errno.EFBIG
            else:
                raise AssertionError('missing file-size limit')
        print('open', flush=True)
        if retain:
            assert sys.stdin.readline() == 'close\n'
        os.close(fd)
        if write:
            wait_for(lambda: resource.getrlimit(resource.RLIMIT_FSIZE) == orig)
        print('closed', flush=True)
    action()


def spawn(base, file, *, write=False, expected=0, mode='', retain=False):
    return subprocess.Popen([sys.executable, '-IB', __file__, 'actor', base, file,
                             str(int(write)), str(expected), mode, str(int(retain))],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)


def finish(proc, expected='open\nclosed\n'):
    stdout, _ = proc.communicate(timeout=8)
    assert proc.returncode == 0 and stdout == expected, (proc.pid, proc.returncode, stdout)


def opened(proc):
    import select
    assert select.select([proc.stdout], [], [], 8)[0] and proc.stdout.readline() == 'open\n'


def close_actor(proc):
    proc.stdin.write('close\n')
    proc.stdin.flush()
    finish(proc, 'closed\n')


def ctl(*args):
    return subprocess.check_output(['systemctl', *args], text=True).strip()


def snapshot(unit):
    keys = ['MainPID', 'InvocationID', 'MemoryMax', 'MemorySwapMax', 'TasksMax', 'NFileDescriptorStore',
            'FileDescriptorStorePreserve', 'Type', 'Slice', 'CPUQuotaPerSecUSec']
    data = dict(line.split('=', 1) for line in ctl('show', *[f'--property={k}' for k in keys], unit).splitlines())
    assert all(data[k] == v for k, v in dict(MemoryMax=str(96 << 20), MemorySwapMax='0', TasksMax='4',
               NFileDescriptorStore='1', FileDescriptorStorePreserve='yes', Type='notify').items()), data
    pid = int(data['MainPID'])
    fd_dir = Path('/proc') / str(pid) / 'fd'
    fds = [int(f.name) for f in fd_dir.iterdir() if os.readlink(f) == 'anon_inode:[fanotify]']
    assert len(fds) == 1
    data['queue_fd'] = fds[0]
    data['fdinfo'] = (fd_dir.parent / 'fdinfo' / str(fds[0])).read_text()
    data['hard_fds'] = resource.prlimit(pid, resource.RLIMIT_NOFILE)
    assert data['hard_fds'] == (1024, 1024)
    return data


def syscall(number, *args):
    lib = ctypes.CDLL(None, use_errno=True)
    result = lib.syscall(number, *args)
    if result < 0:
        raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
    return result


def reference(snapshot):
    pidfd = os.pidfd_open(int(snapshot['MainPID']))
    try:
        return syscall(438, pidfd, snapshot['queue_fd'], 0)  # pidfd_getfd on x86-64
    finally:
        os.close(pidfd)


def same_queue(fd, snapshot):
    return syscall(312, os.getpid(), int(snapshot['MainPID']), 0, fd, snapshot['queue_fd']) == 0


def fixture(base):
    unit = 'horizon-ready-top-fixture-' + base.name + '.service'
    root = base / 'metadata'
    root.mkdir()
    (base / 'initial-v1').touch()
    for name in ('reader', 'writer', 'pending', 'separate', 'last'):
        (root / name).touch()
    (root / 'reader').write_bytes(b'stable')
    options = ['Type=notify', 'FileDescriptorStoreMax=1', 'FileDescriptorStorePreserve=yes', 'NotifyAccess=main',
               'MemoryMax=96M', 'MemorySwapMax=0', 'TasksMax=4', 'UMask=0077']
    subprocess.run(['systemd-run', '--quiet', f'--unit={unit}', *[f'--property={s}' for s in options],
                    '/usr/bin/python3', '-IB', __file__, 'receiver', base], check=True)
    actors = []
    try:
        original = snapshot(unit)
        qfd = reference(original)
        def predecessor_actor(file, **kwargs):
            # Deliver a sleeping actor to the unmodified predecessor, whose
            # known race otherwise prevents establishing the old live grants.
            pid = int(original['MainPID'])
            os.kill(pid, signal.SIGSTOP)
            try:
                proc = spawn(base, file, **kwargs)
                actors.append(proc)
                def sleeping():
                    task = Path('/proc', str(proc.pid))
                    return ((base / f'opening-{proc.pid}').exists()
                            and (task / 'stat').read_text().rsplit(') ', 1)[1].startswith(('S ', 'D '))
                            and (task / 'syscall').read_text().startswith('257 '))
                wait_for(sleeping)
            finally:
                os.kill(pid, signal.SIGCONT)
            return proc

        reader = predecessor_actor('reader', retain=True)
        opened(reader)
        writer = predecessor_actor('writer', write=True, retain=True)
        opened(writer)
        expected_readers, expected_writers = state(base, 'read-holds'), state(base, 'reservations')
        assert len(expected_readers) == len(expected_writers) == 1
        (root / 'reader').unlink()
        pending = predecessor_actor('pending', write=True, expected=errno.EPERM)
        guard_fds = Path('/proc') / original['MainPID'] / 'fd'

        def waiting():
            try:
                return any(os.readlink(f) == str(root / 'pending') for f in guard_fds.iterdir())
            except FileNotFoundError:
                return False

        wait_for(waiting)
        finish(predecessor_actor('separate'))
        wait_for(lambda: state(base, 'read-holds') == expected_readers)
        assert state(base, 'reservations') == expected_writers and pending.poll() is None
        ctl('restart', unit)
        recovered = snapshot(unit)
        assert original['InvocationID'] != recovered['InvocationID'] and same_queue(qfd, recovered)
        assert state(base, 'guard-ready')['inherited_kernel_queue']
        assert state(base, 'read-holds') == expected_readers and state(base, 'reservations') == expected_writers
        used = state(base, 'guard-ready')['seen_blocks']
        assert used == sum(p.stat().st_blocks * 512 for p in (root, *root.iterdir())) + next(iter(expected_readers.values()))['bytes']
        finish(pending, 'denied\n')
        close_actor(reader)
        close_actor(writer)
        wait_for(lambda: not state(base, 'read-holds') and not state(base, 'reservations'))
        import threading
        writer_path = root / 'writer'
        original_limit = resource.getrlimit(resource.RLIMIT_FSIZE)
        first = os.open(writer_path, os.O_RDWR)
        received = []
        another = threading.Thread(target=lambda: received.append(os.open(writer_path, os.O_RDWR)))
        another.start()
        def same_inode_queued():
            receiver_fds = Path('/proc') / recovered['MainPID'] / 'fd'
            try:
                return any(os.readlink(f) == str(writer_path) for f in receiver_fds.iterdir())
            except FileNotFoundError:
                return False
        wait_for(same_inode_queued)
        writer_rows = list(state(base, 'reservations').values())
        assert len(writer_rows) == 1 and writer_rows[0]['pid'] == os.getpid() and not received
        os.close(first)
        another.join(timeout=5)
        assert len(received) == 1 and resource.getrlimit(resource.RLIMIT_FSIZE)[0] == 8192
        os.close(received[0])
        wait_for(lambda: resource.getrlimit(resource.RLIMIT_FSIZE) == original_limit)
        transient = spawn(base, 'separate', mode='running')
        actors.append(transient)
        wait_for(lambda: (base / f'observed-{transient.pid}').exists())
        assert transient.poll() is None and not state(base, 'reservations') and not state(base, 'read-holds')
        finish(spawn(base, 'last'))
        (base / f'fixture-{transient.pid}').unlink()
        finish(transient)
        for mode in ('malformed', 'unsupported', 'gone', 'running'):
            proc = spawn(base, 'separate', expected=errno.EPERM, mode=mode)
            finish(proc, 'denied\n')
            assert (base / f'observed-{proc.pid}').exists()
        lost = spawn(base, 'separate', mode='running')
        wait_for(lambda: (base / f'observed-{lost.pid}').exists())
        lost.kill()
        assert lost.wait(timeout=8) == -signal.SIGKILL
        finish(spawn(base, 'last', write=True))
        assert snapshot(unit)['InvocationID'] == recovered['InvocationID']
        for i in range(4):
            name = root / f'trip-{i}'
            # Use a pre-existing file to test the original irreversible directory threshold.
            if not (base / 'metadata-trip.json').exists():
                try:
                    name.touch()
                except PermissionError:
                    break
                if root.stat().st_blocks * 512 + sum(p.stat().st_blocks * 512 for p in root.iterdir()) >= 32768:
                    finish(spawn(base, name.name, write=True, expected=errno.EPERM), 'denied\n')
                    break
                finish(spawn(base, name.name, write=True))
        assert (base / 'metadata-trip.json').exists()
        assert not state(base, 'reservations') and not state(base, 'read-holds')
        return dict(original=original, recovered=recovered, kernel_open_file_description_equal=True,
                    actual_v1_to_v2_handoff=True, same_process_duplicate_serialized=True,
                    inherited_writers=expected_writers, inherited_readers=expected_readers,
                    detached_charge_bytes=used, duplicate_blocked_then_orphan_denied=True,
                    independent_reader_progress=True, transient_recovered=True, persistent_transient_denied=True,
                    malformed_denied=True, unknown_denied=True, disappeared_denied=True, killed_waiter_recovered=True,
                    native_efbig_and_limit_restored=True, directory_threshold=read(base / 'metadata-trip.json'))
    finally:
        for proc in actors:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
        subprocess.run(['systemctl', 'stop', unit], check=True)
        subprocess.run(['systemctl', 'clean', '--what=fdstore', unit], check=False, stderr=subprocess.DEVNULL)
        subprocess.run(['chattr', '-i', root], check=True)


if __name__ == '__main__':
    op, *args = sys.argv[1:]
    if op == 'receiver':
        fixture_receiver(Path(args[0]))
    elif op == 'actor':
        base, file, write, expected, mode, retain = args
        child(Path(base), file, bool(int(write)), int(expected), mode, bool(int(retain)))
    elif op == 'qualify':
        guard = guard_module()
        assert guard.open_flags('-1 0x01 0x02') is None
        assert guard.open_flags('2 0x0 0x1 0x0 0x0 0x0 0x0 0x0 0x0') == os.O_WRONLY
        assert guard.open_flags('85 ' + '0x0 ' * 8) == (os.O_CREAT | os.O_WRONLY | os.O_TRUNC)
        with tempfile.TemporaryDirectory(prefix='qa-', dir=args[0]) as work:
            print(json.dumps(fixture(Path(work)), sort_keys=True))
