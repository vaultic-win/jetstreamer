"""Exercise exact-file cleanup against isolated disposable HOME-backed fixtures."""
import fcntl
import os
import runpy
import signal
import tempfile
import unittest
from pathlib import Path

m = runpy.run_path(str(Path(__file__).with_name('retirement.py')))
signal.signal(signal.SIGIO, m['interrupted'])


class TestRetirement(unittest.TestCase):
    def setUp(self):
        root = os.environ['HORIZON_CARGO_FIXTURE_ROOT']
        self.tmp = tempfile.TemporaryDirectory(dir=root)
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.state = self.base / 'state'
        self.state.mkdir(mode=0o700)
        self.profile = self.base / 'profile'
        self.profile.mkdir()
        self.rows = {}
        for i in range(5):
            p = self.profile / f'{i}.o'
            p.write_bytes(b'fixture' * (i+1) * 1024)
            self.rows[str(p)] = m['identity'](p)
        self.keep = self.profile / 'keep'
        self.keep.write_bytes(b'preserved')
        self.closure_ok = True
        self.operator = m['Retirement'](self.state, self.rows, 'pinned fixture', self.closure, batch_size=2)
        self.inspection = self.operator.inspect()

    def closure(self):
        m['require'](self.closure_ok, 'fixture consumer active')
        return {'closed': True}

    def execute(self, event=lambda _: None):
        return self.operator.run(self.inspection, event=event)

    def success(self):
        r = self.execute()
        self.assertEqual(r['allocated_bytes_retired_once'], sum(s[7]*512 for s in self.rows.values()))
        self.assertEqual(r, self.execute())
        self.assertEqual(self.keep.read_bytes(), b'preserved')
        self.assertTrue(all(not os.path.lexists(p) for p in self.rows))
        self.assertFalse(list((self.state / 'quarantine').iterdir()))
        self.assertEqual(r['credited_bytes'], 0)

    def test_complete_idempotently(self):
        self.success()

    def crash(self, phase):
        def stop(point):
            if point == phase:
                raise InterruptedError(point)
        with self.assertRaises(InterruptedError):
            self.execute(stop)
        self.success()

    def test_rename_crash(self):
        self.crash('after-rename')

    def test_captured_receipt_crash(self):
        self.crash('after-captured-receipt')

    def test_unlink_crash(self):
        self.crash('after-unlink')

    def test_foreign_quarantine(self):
        (self.state / 'quarantine').mkdir()
        with self.assertRaises(m['Refused']):
            self.execute()
        self.assertTrue(all(Path(p).exists() for p in self.rows))

    def test_wrong_stamp(self):
        Path(next(iter(self.rows))).write_bytes(b'replacement')
        with self.assertRaises(m['Refused']):
            self.execute()
        self.assertTrue(all(Path(p).exists() for p in self.rows))

    def test_replaced_parent(self):
        old = self.base / 'old'
        self.profile.rename(old)
        self.profile.mkdir()
        with self.assertRaises(m['Refused']):
            self.execute()
        self.assertTrue((old / '0.o').exists())

    def test_hardlink_refusal(self):
        os.link(next(iter(self.rows)), self.base / 'alias')
        with self.assertRaises(m['Refused']):
            self.execute()

    def test_file_in_use_refusal_and_retry(self):
        with open(next(iter(self.rows)), 'rb'):
            with self.assertRaises(BlockingIOError):
                self.execute()
            self.assertTrue(all(Path(p).exists() for p in self.rows))
        self.success()

    def test_symlink_refusal(self):
        p = Path(next(iter(self.rows)))
        p.unlink()
        p.symlink_to(self.keep)
        with self.assertRaises(m['Refused']):
            self.execute()
        self.assertTrue(p.is_symlink())

    def test_foreign_staged_file_after_partial_capture(self):
        def substitute(phase):
            if phase == 'after-rename':
                (self.state / 'quarantine' / '1').write_bytes(b'foreign')
                raise InterruptedError
        with self.assertRaises(InterruptedError):
            self.execute(substitute)
        with self.assertRaises(m['Refused']):
            self.execute()
        self.assertEqual((self.state / 'quarantine' / '1').read_bytes(), b'foreign')

    def test_recreated_original(self):
        def replace(phase):
            if phase == 'after-captured-receipt':
                Path(next(iter(self.rows))).write_bytes(b'recreated')
        with self.assertRaises(m['Refused']):
            self.execute(replace)
        self.assertEqual(Path(next(iter(self.rows))).read_bytes(), b'recreated')

    def test_new_consumer_before_mutation(self):
        self.closure_ok = False
        with self.assertRaises(m['Refused']):
            self.execute()
        self.assertTrue(all(Path(p).exists() for p in self.rows))

    def test_busy_or_replaced_mutex(self):
        self.keep.touch()
        bindings = [(self.keep, m['identity'](self.keep))]
        with self.keep.open('rb') as held:
            fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError), m['locks'](bindings):
                self.fail('accepted busy mutex')
        different = self.base / 'different-mutex'
        different.write_bytes(b'different')
        self.assertNotEqual(different.stat().st_ino, self.keep.stat().st_ino)
        different.replace(self.keep)
        with self.assertRaises(m['Refused']), m['locks'](bindings):
            self.fail('accepted different mutex')

    def test_open_file_limit(self):
        import resource
        previous = resource.getrlimit(resource.RLIMIT_NOFILE)
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (min(previous[0], 24), previous[1]))
            self.success()
        finally:
            resource.setrlimit(resource.RLIMIT_NOFILE, previous)


if __name__ == '__main__':
    unittest.main(verbosity=2)
