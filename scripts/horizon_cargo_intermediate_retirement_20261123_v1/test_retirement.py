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


class TestInspectionBindings(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ['HORIZON_CARGO_FIXTURE_ROOT'])
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.state = self.base / 'state'
        self.state.mkdir(mode=0o700)
        runtime = Path('/var/lib/jetstreamer/horizon_runtime_data')
        home = Path('/home/sol/.jetstreamer-private/horizon-root-runtime-data')
        self.alias = home / self.state.relative_to(runtime)
        self.assertTrue(self.alias.samefile(self.state))
        self.name = 'inspection-1795403151826474427.json'
        self.leaf = self.state / self.name
        self.leaf.write_text('{"schema":"horizon-exact-cargo-inspection-v1"}\n')
        self.leaf.chmod(0o400)
        self.inode = self.leaf.stat().st_ino
        st = self.state.stat()
        self.dirid = (st.st_dev, st.st_ino)
        self.pins = {self.name: dict(ino=self.inode, sha256=m['fingerprint'](self.leaf))}
        self.aliases = {self.alias, self.state}
        self.module = runpy.run_path(str(Path(__file__).with_name('consumers.py')))

    def check(self, path):
        return self.module['inspection_evidence'](path, self.aliases, self.dirid, self.pins)

    def test_both_true_mount_aliases(self):
        self.assertNotEqual(str(self.state), str(self.alias))
        self.assertTrue(self.check(self.leaf))
        self.assertTrue(self.check(self.alias / self.name))

    def test_foreign_directory_or_other_receipt_name(self):
        foreign = self.base / self.name
        foreign.write_bytes(self.leaf.read_bytes())
        foreign.chmod(0o400)
        self.assertFalse(self.check(foreign))
        self.assertFalse(self.check(self.state / 'inspection.json'))
        self.assertFalse(self.check(self.state / 'inspection-1795403151826474428.json'))

    def test_substitute_or_wrong_inode_not_exempt(self):
        alternate = self.state / 'different'
        alternate.write_bytes(self.leaf.read_bytes())
        alternate.chmod(0o400)
        alternate.replace(self.leaf)
        with self.assertRaises(RuntimeError):
            self.check(self.alias / self.name)

    def test_wrong_checksum_editor_and_parent(self):
        self.pins[self.name]['sha256'] = '0' * 64
        with self.assertRaises(RuntimeError):
            self.check(self.leaf)
        self.pins[self.name]['sha256'] = m['fingerprint'](self.leaf)
        self.dirid = (self.dirid[0], self.dirid[1] + 1)
        with self.assertRaises(RuntimeError):
            self.check(self.leaf)

    def test_foreign_link_and_mutable_receipt(self):
        self.leaf.chmod(0o600)
        with self.assertRaises(RuntimeError):
            self.check(self.leaf)
        self.leaf.chmod(0o400)
        os.link(self.leaf, self.base / 'another')
        with self.assertRaises(RuntimeError):
            self.check(self.leaf)

    def test_symlink_with_real_contents(self):
        target = self.base / 'target'
        self.leaf.rename(target)
        self.leaf.symlink_to(target)
        with self.assertRaises(OSError):
            self.check(self.leaf)

    def test_real_scanner_retains_foreign_file_references(self):
        import json
        from unittest.mock import patch
        bundle = self.base / 'history'
        bundle.mkdir()
        route = self.base / 'route.json'
        route.write_text('{"reviewed_routes":{}}')
        fleet = self.base / 'fleet.json'
        fleet.write_text('{}')
        files = {'live-survey.json': {'roots': [], 'installed_roots': []},
                 'indirect.json': {'control_roots': [], 'route': str(route)},
                 'indirect-source-lines.json': {}, 'scheduler-evidence.json': {},
                 'actual-controls.json': {'concrete_direct_mentions_of_retained': []}}
        for n, v in files.items():
            (bundle / n).write_text(json.dumps(v))
        candidate = self.base / 'old/target/debug/deps/libfixture-a.rlib'
        self.leaf.chmod(0o600)
        self.leaf.write_text(json.dumps({'parents': [str(candidate)]}))
        self.leaf.chmod(0o400)
        self.pins[self.name]['sha256'] = m['fingerprint'](self.leaf)
        external = self.base / self.name
        external.write_bytes(self.leaf.read_bytes())
        external.chmod(0o400)
        control = self.module['controls']
        args = (self.base, bundle, {'old/target/debug': 'compiler'}, {str(candidate): 1}, fleet,
                self.aliases, self.dirid, self.pins)
        hits = {self.alias / self.name}
        with patch.dict(control.__globals__, {'scan': lambda *a, **kw: hits}):
            self.assertEqual(control(*args)['native_controls'], 1)
            hits.add(external)
            with self.assertRaisesRegex(RuntimeError, 'file referenced'):
                control(*args)


if __name__ == '__main__':
    unittest.main(verbosity=2)
