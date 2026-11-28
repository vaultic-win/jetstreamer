"""Linux regression for the first census of the epoch 145 recover-worker."""
import contextlib
import fcntl
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

# Use the original inspector on actual kernel F_SETLEASE locks.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "horizon_epoch168_full_metered_20261121_v1"))
from overlap import leases


def hold_read_leases(stack, paths):
    for path in paths:
        stream = stack.enter_context(path.open("rb"))
        fcntl.fcntl(stream, fcntl.F_SETOWN, os.getpid())
        fcntl.fcntl(stream, fcntl.F_SETLEASE, fcntl.F_RDLCK)
        assert fcntl.fcntl(stream, fcntl.F_GETLEASE) == fcntl.F_RDLCK


def ordinary_worker(directory, count):
    # The early signal from the test controller can land during metadata setup.
    sys.stdout.write("metadata\n")
    sys.stdout.flush()
    if sys.stdin.buffer.read(1) != b"L":
        return 2
    with contextlib.ExitStack() as stack:
        hold_read_leases(stack, sorted(directory.glob("input-*"))[:count])
        os.kill(os.getpid(), signal.SIGSTOP)
        (directory / "body-read").write_bytes(b"passed readiness")
    return 0


def stopped(pid):
    until = time.monotonic() + 5
    while time.monotonic() < until:
        result = os.waitid(os.P_PID, pid, os.WSTOPPED | os.WEXITED | os.WNOWAIT | os.WNOHANG)
        if result is None:
            time.sleep(0.01)
            continue
        if (result.si_pid, result.si_code, result.si_status) != (pid, os.CLD_STOPPED, signal.SIGSTOP):
            raise AssertionError(f"unexpected child status {result}")
        return
    raise AssertionError("timed out waiting for the child stop")


class LeaseStartupTest(unittest.TestCase):
    def check_order(self, count, premature_stop=False):
        with tempfile.TemporaryDirectory() as temp, contextlib.ExitStack() as leases_stack:
            root = Path(temp)
            paths = [root / f"input-{i}" for i in range(3)]
            for p in paths:
                p.write_bytes(b"small local fixture")
                p.chmod(0o400)
            originals = {(p.stat().st_dev, p.stat().st_ino): str(p) for p in paths}
            hold_read_leases(leases_stack, paths)
            with subprocess.Popen(
                [sys.executable, "-IB", __file__, "--worker", str(root), str(count)],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            ) as child:
                try:
                    self.assertEqual(child.stdout.readline(), b"metadata\n")
                    if premature_stop:
                        # V5j could freeze the child before its independent lease acquisition.
                        child.send_signal(signal.SIGSTOP)
                    else:
                        child.stdin.write(b"L")
                        child.stdin.flush()
                    stopped(child.pid)
                    self.assertEqual(set(leases(os.getpid(), originals)), {ino for _, ino in originals})
                    self.assertFalse((root / "body-read").exists())
                    if premature_stop or count < 3:
                        with self.assertRaisesRegex(ValueError, "original recovery read lease absent"):
                            leases(child.pid, originals)
                    else:
                        self.assertEqual(set(leases(child.pid, originals)), {ino for _, ino in originals})
                        child.send_signal(signal.SIGCONT)
                        self.assertEqual(child.wait(timeout=5), 0)
                        self.assertTrue((root / "body-read").exists())
                finally:
                    if child.poll() is None:
                        child.kill()
                        child.wait(timeout=5)
            if premature_stop or count < 3:
                self.assertFalse((root / "body-read").exists())

    def test_v5j_premature_freeze_fails_exact_census(self):
        self.check_order(3, premature_stop=True)

    def test_self_stopped_with_all_six_original_leases(self):
        self.check_order(3)

    def test_self_stopped_with_missing_child_lease_is_never_released(self):
        self.check_order(2)


if __name__ == "__main__":
    if sys.argv[1:2] == ["--worker"]:
        raise SystemExit(ordinary_worker(Path(sys.argv[2]), int(sys.argv[3])))
    unittest.main()
