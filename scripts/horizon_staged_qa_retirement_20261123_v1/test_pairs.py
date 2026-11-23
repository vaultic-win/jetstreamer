"""Exercise pair checking and physical operator crash boundaries on tiny fixtures."""
import fcntl
import hashlib
import mmap
import os
import runpy
import signal
import tempfile
import time
import unittest
from pathlib import Path

base = Path(__file__).resolve().parent
engine_path = base/'retirement.py'
if not engine_path.is_file():
    engine_path = base.parent/'horizon_cargo_intermediate_retirement_20261123_v1/retirement.py'
m = runpy.run_path(str(engine_path))
Pair = runpy.run_path(str(base/'pairs.py'))['PairedFiles']
signal.signal(signal.SIGIO, m['interrupted'])


class TestPair(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ['HORIZON_QA_FIXTURE_HOME'])
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.state = root/'state'
        self.state.mkdir(mode=0o700)
        self.rows = {}
        self.keep = []
        for i in range(3):
            data = hashlib.shake_256(str(i).encode()).digest(4111+i)
            source = root/f'staged{i}'
            keeper = root/f'keeper{i}'
            source.write_bytes(data)
            keeper.write_bytes(data)
            self.keep.append(keeper)
            self.rows[str(source)] = {'source_stat':m['identity'](source),'keeper_stat':m['identity'](keeper),
                                      'keeper_path':str(keeper), 'whole_sha256_at_seal':hashlib.sha256(data).hexdigest()}
        self.stamps = {p:r['source_stat'] for p,r in self.rows.items()}
        self.proof = None
        self.key = 'paired exact fixture'
        self.inspection = m['Retirement'](self.state,self.stamps,self.key,self.closure,batch_size=3).inspect()
        self.unselected = root/'unselected'
        self.unselected.write_bytes(b'preserve')

    def closure(self):
        return {'body_proof':self.proof}

    def run_op(self,event=lambda _:None,opened=lambda _:None):
        pair = Pair(self.state,self.rows,m)
        with pair.leases():
            opened(pair)
            p = self.state/f'paired-{time.time_ns()}.json'
            m['publish'](p,{'pairs':pair.pairs})
            self.proof = {'path':str(p),'sha256':m['fingerprint'](p)}
            op=m['Retirement'](self.state,self.stamps,self.key,self.closure,batch_size=3,open_lease=pair.retained_source_lease)
            return op.run(self.inspection,event=event)

    def assert_complete(self):
        first = self.run_op()
        again = self.run_op()
        self.assertEqual(first,again)
        self.assertEqual(first['allocated_bytes_retired_once'],sum(s[7]*512 for s in self.stamps.values()))
        self.assertEqual(self.unselected.read_bytes(),b'preserve')
        for key,row in self.rows.items():
            self.assertFalse(os.path.lexists(key))
            self.assertEqual(m['identity'](Path(row['keeper_path'])),row['keeper_stat'])
            self.assertEqual(m['fingerprint'](Path(row['keeper_path'])),row['whole_sha256_at_seal'])

    def test_complete(self):
        self.assert_complete()

    def test_all_leases_remain_held(self):
        def inspect(pair):
            self.assertEqual(len(pair.sources),3)
            self.assertTrue(all(fcntl.fcntl(fd,fcntl.F_GETLEASE)==fcntl.F_WRLCK for fd in pair.sources.values()))
            self.assertTrue(all(fcntl.fcntl(fd,fcntl.F_GETLEASE)==fcntl.F_RDLCK for fd,_,_ in pair.keepers.values()))
        self.run_op(opened=inspect)
        self.assert_complete()

    def test_late_wrong_pair_preserves_every_source(self):
        row=list(self.rows.values())[-1]
        p=Path(row['keeper_path'])
        p.write_bytes(b'x'*p.stat().st_size)
        row['keeper_stat']=m['identity'](p)
        with self.assertRaisesRegex(RuntimeError,'paired file bodies differ'):
            self.run_op()
        self.assertTrue(all(Path(p).is_file() for p in self.rows))
        self.assertFalse((self.state/'intent.json').exists())

    def test_unsealed_bytes_even_if_equal(self):
        name=next(iter(self.rows))
        row=self.rows[name]
        row['whole_sha256_at_seal']='0'*64
        with self.assertRaisesRegex(RuntimeError,'sealed digest mismatch'):
            self.run_op()

    def crash_and_resume(self,transition):
        def crash(point):
            if point==transition:
                raise InterruptedError(point)
        with self.assertRaises(InterruptedError):
            self.run_op(event=crash)
        self.assert_complete()

    def test_interrupted_capture(self):
        self.crash_and_resume('after-rename')

    def test_interrupted_stage_receipt(self):
        self.crash_and_resume('after-captured-receipt')

    def test_interrupted_unlink(self):
        self.crash_and_resume('after-unlink')

    def test_foreign_open_rejected(self):
        with open(next(iter(self.rows)),'rb'), self.assertRaises(BlockingIOError):
            self.run_op()

    def test_mapped_source_rejected(self):
        with open(next(iter(self.rows)),'rb') as file:
            mapping = mmap.mmap(file.fileno(),0,access=mmap.ACCESS_READ)
        with mapping, self.assertRaises(BlockingIOError):
            self.run_op()
        self.assert_complete()

    def test_retained_copy_writer_rejected(self):
        with self.keep[0].open('ab'), self.assertRaises(BlockingIOError):
            self.run_op()

    def test_missing_source_requires_durable_body_and_capture(self):
        Path(next(iter(self.rows))).unlink()
        with self.assertRaises(FileNotFoundError):
            self.run_op()
        self.assertFalse((self.state/'intent.json').exists())

    def test_hardlink_or_replacement_refused(self):
        p=Path(next(iter(self.rows)))
        alias=p.with_name('alias')
        os.link(p,alias)
        with self.assertRaises(RuntimeError):
            self.run_op()
        self.assertTrue(p.exists())

    def test_orphan_in_quarantine_preserves_sources(self):
        quarantine = self.state/'quarantine'
        quarantine.mkdir(mode=0o700)
        (quarantine/'rogue').write_bytes(b'unrelated')
        with self.assertRaisesRegex(RuntimeError,'foreign entry'):
            self.run_op()
        self.assertTrue(all(Path(p).is_file() for p in self.rows))

    def test_missing_comparison_receipt_stops_recovery_after_unlink(self):
        def stop(point):
            if point == 'after-unlink':
                raise InterruptedError()
        with self.assertRaises(InterruptedError):
            self.run_op(event=stop)
        Path(self.proof['path']).unlink()
        with self.assertRaises(FileNotFoundError):
            self.run_op()
        self.assertFalse((self.state/'complete.json').exists())

if __name__=='__main__':
    unittest.main(verbosity=2)
