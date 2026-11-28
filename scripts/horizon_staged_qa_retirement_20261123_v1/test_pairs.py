"""Exercise pair checking and physical operator crash boundaries on tiny fixtures."""
import fcntl
import hashlib
import json
import mmap
import os
import runpy
import signal
import subprocess
import tempfile
import time
import unittest
from unittest import mock
from pathlib import Path

base = Path(__file__).resolve().parent
engine_path = base/'retirement.py'
if not engine_path.is_file():
    engine_path = base.parent/'horizon_cargo_intermediate_retirement_20261123_v1/retirement.py'
m = runpy.run_path(str(engine_path))
Pair = runpy.run_path(str(base/'pairs.py'))['PairedFiles']
signal.signal(signal.SIGIO, m['interrupted'])


class TestFixedSelections(unittest.TestCase):
    def setUp(self):
        self.host = runpy.run_path(str(base/'host.py'))
        self.package = self.host['CURRENT_22']
        self.rows = {f'additional-{i}': {} for i in range(22)}
        self.manifest = {
            'proposed_files': self.rows, 'excluded_source_paths': [f'excluded-{i}' for i in range(59)],
            'physical_allocated_bytes': 10064564224, 'logical_source_bytes': 10065734136,
            'final_pair_read_bound': 20131468272, 'stage30_exclusion': {
                'path': str(self.host['STAGE30_ORIGINAL']), 'sha256': self.host['STAGE30_ORIGINAL_SHA']}}
        self.older = {f'prior-{i}': {} for i in range(35)}

    def check(self):
        def bound(path, digest):
            self.assertEqual(path, self.host['STAGE30_ORIGINAL'])
            self.assertEqual(digest, self.host['STAGE30_ORIGINAL_SHA'])
            return {'files': self.older}
        return self.host['checked_selection'](self.manifest, self.package, bound)

    def test_exact_stage22(self):
        self.assertIs(self.check(), self.rows)

    def test_unknown_or_crossed_package(self):
        for path in (self.host['LEGACY_30'], self.package/'alternate'):
            self.package = path
            with self.assertRaises(RuntimeError):
                self.check()

    def test_old_selection_preserved(self):
        self.package = self.host['LEGACY_30']
        self.manifest = dict(proposed_files={f'legacy-{i}': {} for i in range(30)},
                             excluded_source_paths=[f'excluded-{i}' for i in range(5)],
                             physical_allocated_bytes=12639535104, logical_source_bytes=12641076584,
                             final_pair_read_bound=25282153168)
        self.assertEqual(len(self.check()), 30)

    def test_earlier_staged_inode_path_excluded(self):
        self.older.pop('prior-0')
        self.older['additional-0'] = {}
        with self.assertRaisesRegex(RuntimeError, 'overlap'):
            self.check()

    def test_missing_earlier_candidate_and_foreign_manifest(self):
        self.older.pop('prior-0')
        with self.assertRaisesRegex(RuntimeError, 'overlap'):
            self.check()
        self.manifest['stage30_exclusion']['sha256'] = '0' * 64
        with self.assertRaisesRegex(RuntimeError, 'changed'):
            self.check()

    def test_altered_byte_or_pruned_exclusions(self):
        self.manifest['physical_allocated_bytes'] += 1
        with self.assertRaisesRegex(RuntimeError, 'exact selection'):
            self.check()
        self.manifest['physical_allocated_bytes'] -= 1
        self.manifest['excluded_source_paths'][0] = 'additional-0'
        with self.assertRaisesRegex(RuntimeError, 'exact selection'):
            self.check()


class TestRemainder(unittest.TestCase):
    def setUp(self):
        self.host = runpy.run_path(str(base/'host.py'))
        _, prior_path, prior_sha, _ = self.host['selection'](self.host['CURRENT_22'])
        prior = {f'prior-{i}': [i] for i in range(22)}
        rows = {f'remaining-{i}': [i+22] for i in range(41)}
        original = {'proposed_files': {**prior, **rows}, 'excluded_source_paths': [f'outside-{i}' for i in range(18)]}
        self.selection = dict(proposed_files=rows, excluded_source_paths=[*prior, *original['excluded_source_paths']],
                              physical_allocated_bytes=14806351872, logical_source_bytes=14807426016,
                              final_pair_read_bound=29614852032)
        self.inputs = {}
        def bind(key, path, digest, value):
            self.selection[key] = {'path': str(path), 'sha256': digest}
            self.inputs[(path, digest)] = value
        bind('completed_stage22_scope', prior_path, prior_sha, {'proposed_files':prior})
        bind('eligible_original_scope', prior_path.with_name('MANIFEST_63.json'),
             '29f669b121146d55c1250d02ca1aa346b87a5aa71797c800ac582b3cdf898885', original)
        self.completed = dict(files=22, allocated_bytes_retired_once=10064564224)
        bind('stage22_completion', self.host['CURRENT_22'].parent/'state/complete.json',
             'cfd9dbe64a6cddd02a001aa0e32ef4b4964ccd5c43e46062aa265a39ada38be7', self.completed)
        bind('stage30_exclusion', self.host['STAGE30_ORIGINAL'], self.host['STAGE30_ORIGINAL_SHA'],
             {'files': {f'earlier-{i}': i for i in range(35)}})

    def check(self):
        return self.host['checked_selection'](self.selection, self.host['REMAINDER_41'],
                                               lambda p, d: self.inputs[(p,d)])

    def test_exact_remaining_selection(self):
        self.assertEqual(len(self.check()), 41)

    def test_selected_identity_must_match_original(self):
        self.selection['proposed_files']['remaining-0'] = [800]
        with self.assertRaisesRegex(RuntimeError, 'exact 41-file'):
            self.check()

    def test_cannot_substitute_excluded_file(self):
        self.selection['proposed_files']['outside-0'] = self.selection['proposed_files'].pop('remaining-0')
        excluded = self.selection['excluded_source_paths']
        excluded[excluded.index('outside-0')] = 'remaining-0'
        with self.assertRaisesRegex(RuntimeError, 'exact 41-file'):
            self.check()

    def test_previous_completion_required(self):
        self.completed['allocated_bytes_retired_once'] -= 1
        with self.assertRaisesRegex(RuntimeError, 'previous stage incomplete'):
            self.check()
        self.selection['stage22_completion']['sha256'] = 'f' * 64
        with self.assertRaisesRegex(RuntimeError, 'changed remainder input'):
            self.check()


class TestSmallStaging(unittest.TestCase):
    def setUp(self):
        self.host = runpy.run_path(str(base/'host.py'))
        self.earlier = {f'prior35-{i}': {} for i in range(35)}
        self.prior = {f'prior81-{i}': {} for i in range(81)}
        self.rows = {f'small-{i}': {} for i in range(88)}
        self.done = dict(files=41, allocated_bytes_retired_once=14806351872)
        self.manifest = dict(proposed_files=self.rows, excluded_source_paths=[*self.earlier, *self.prior],
                             physical_allocated_bytes=3494883328, logical_source_bytes=3496875656,
                             final_pair_read_bound=6993751312)
        bindings = [
            ('stage30_exclusion', self.host['STAGE30_ORIGINAL'], self.host['STAGE30_ORIGINAL_SHA'],
             {'files': self.earlier}),
            ('prior81_exclusion', self.host['BASE']/'late-qa-stage-duplicates-20261123-v1/PRIMARY.json',
             '0e18d96784f183a4c8fa3ecc3be15baed2919dc77597ecce0a24a9463a2a88a7', {'files': self.prior}),
            ('stage41_completion', self.host['REMAINDER_41'].parent/'state/complete.json',
             '4f803e54725562cdd28d69e5ef051f8da260a6c1de1ea1d7dcd7c184babc0257', self.done),
        ]
        self.inputs = {}
        for key, path, digest, contents in bindings:
            self.manifest[key] = dict(path=str(path), sha256=digest)
            self.inputs[path, digest] = contents

    def check(self):
        return self.host['checked_selection'](self.manifest, self.host['SMALL_88'],
                                              lambda path, digest: self.inputs[path, digest])

    def test_exact_stage_and_previous_boundaries(self):
        self.assertIs(self.check(), self.rows)
        self.done['files'] -= 1
        with self.assertRaisesRegex(RuntimeError, 'previous stage incomplete'):
            self.check()

    def test_old_inventory_cannot_be_exchanged_for_new_path(self):
        self.prior[next(iter(self.rows))] = self.prior.pop('prior81-0')
        with self.assertRaisesRegex(RuntimeError, 'incomplete exclusions'):
            self.check()

    def test_changed_previous_manifest_rejected(self):
        self.manifest['prior81_exclusion']['sha256'] = '0' * 64
        with self.assertRaisesRegex(RuntimeError, 'changed previous'):
            self.check()


class TestDisjointExecutables(TestSmallStaging):
    def setUp(self):
        super().setUp()
        self.stage88 = self.rows
        self.rows = {f'executable-{i}': {} for i in range(128)}
        _, path, digest, _ = self.host['selection'](self.host['SMALL_88'])
        self.inputs[path, digest] = {'proposed_files': self.stage88}
        self.manifest.update(proposed_files=self.rows, physical_allocated_bytes=13105426432,
                             logical_source_bytes=13106666192, final_pair_read_bound=26213332384,
                             stage88_exclusion=dict(path=str(path), sha256=digest))
        self.manifest['excluded_source_paths'].extend(self.stage88)

    def check(self):
        return self.host['checked_selection'](self.manifest, self.host['EXECUTABLES_128'],
                                              lambda path, digest: self.inputs[path, digest])

    def test_stage88_must_remain_excluded_before_or_after_its_cleanup(self):
        self.assertIs(self.check(), self.rows)
        self.manifest['excluded_source_paths'][-1] = 'foreign-path'
        with self.assertRaisesRegex(RuntimeError, 'incomplete exclusions'):
            self.check()

    def test_prior88_exact_binding(self):
        self.manifest['stage88_exclusion']['sha256'] = '0' * 64
        with self.assertRaisesRegex(RuntimeError, 'preceding 88-file'):
            self.check()


class TestLive145Price(unittest.TestCase):
    def setUp(self):
        host = runpy.run_path(str(base/'host.py'))
        self.host = host
        self.check = host['checked_live145_price']
        self.check_stopped = host['checked_stopped145_price']
        self.assertEqual(host['selection'](host['SMALL_88']), host['selection'](host['SMALL_88_LIVE145']))
        self.assertEqual(host['selection'](host['SMALL_88']), host['selection'](host['SMALL_88_STOPPED145']))
        self.fleet = {'path': '/fleet.json', 'sha256': '0' * 64}
        self.now = 1000
        self.frame = {
            'schema': 'horizon-incident-replay-fit-v1', 'epoch': 145, 'fits': True,
            'fleet': self.fleet, 'resource_credit_bytes': 0, 'recorded_unix_seconds': 990,
            'replacements': {'166': {}, '167': {}, '168': {}, '170': {}}, 'survivors': {'172': {}},
            'phase145': {'stage': 'leased-worker', 'invocation_id': 'f86e7e61f4b34dc7aedc4e08a128e713'},
            'available_HOME_bytes': 2 << 30, 'complete_required_HOME_bytes': 1 << 30,
            'available_memory_bytes': 3 << 30, 'required_available_memory_bytes': 1 << 30,
        }
        self.guard = {'fleet': self.fleet, 'resource_credit_bytes': 0, 'recorded_unix_seconds': 991,
                      'free_bytes': 2 << 30, 'protected_bytes': 1 << 30,
                      'available_memory': 3 << 30, 'required_memory': 1 << 30}

    def test_requires_agreeing_fresh_five_peer_frame_and_guard(self):
        self.check(self.frame, self.guard, self.fleet, self.now)
        with self.assertRaisesRegex(RuntimeError, 'five-peer'):
            self.check({**self.frame, 'replacements': {'167': {}, '168': {}, '170': {}}},
                       self.guard, self.fleet, self.now)
        for changed in ({'fleet': {}}, {'recorded_unix_seconds': 879}, {'resource_credit_bytes': 1}):
            with self.subTest(changed=changed), self.assertRaisesRegex(RuntimeError, 'guard quote'):
                self.check(self.frame, {**self.guard, **changed}, self.fleet, self.now)

    def test_stricter_margin_applies_to_both_resources(self):
        with self.assertRaisesRegex(RuntimeError, 'do not fit'):
            self.check(self.frame, {**self.guard, 'protected_bytes': 2 << 30}, self.fleet, self.now)
        with self.assertRaisesRegex(RuntimeError, 'do not fit'):
            self.check({**self.frame, 'required_available_memory_bytes': 3 << 30},
                       self.guard, self.fleet, self.now)

    def test_stopped_price_retains_original_donor_charge(self):
        phase = dict(InvocationID='f86e7e61f4b34dc7aedc4e08a128e713', ActiveState='failed',
                     SubState='failed', MainPID='0', source_checkpoint_exists=False, resource_credit_bytes=0)
        donor = dict(schema='horizon-145-drained-159-donor-cover-v1', fleet=self.fleet, credited_retirement_bytes=0,
                     general_slot_cpu_micros=1_000_000, native_home_required=1536 << 20, remaining_home_bytes=256 << 20)
        frame = dict(self.frame, phase145=phase, epoch159_donor_cover=donor, replay_launch_authorized=False)
        self.check_stopped(frame, self.fleet, self.now, 2 << 30)
        with self.assertRaisesRegex(RuntimeError, 'do not fit'):
            self.check_stopped(frame, self.fleet, self.now, 1536 << 20)
        with self.assertRaisesRegex(RuntimeError, 'unbound retained donor'):
            self.check_stopped(dict(frame, epoch159_donor_cover=dict(donor, credited_retirement_bytes=1)),
                               self.fleet, self.now, 2 << 30)
        with self.assertRaisesRegex(RuntimeError, 'unrecognized stopped'):
            self.check_stopped(dict(frame, phase145=dict(phase, MainPID='100')), self.fleet, self.now, 2 << 30)

    def test_paired_quote_retries_only_authenticated_donor_pressure(self):
        head = Path(self.fleet['path'])
        directory = Path('/sealed/fit')
        command = directory/'post-stop-fit'
        trace = ('Traceback (most recent call last):\n'
                 f'  File "{command}", line 1389, in <module>\n'
                 f'  File "{command}", line 1301, in capture\n'
                 f'  File "{directory}/build_159_price.py", line 150, in cover\n'
                 'ValueError: insufficient HOME or general-slot memory\n')
        insufficient = subprocess.CompletedProcess([], 1, '', trace)
        accepted = subprocess.CompletedProcess([], 0, json.dumps(self.frame), '')
        unbound = subprocess.CompletedProcess([], 1, '', trace.replace(', in cover', ', in snapshot'))
        provider = {'fleet': lambda: head, 'sha': lambda _: self.fleet['sha256']}
        quote = self.host['stopped145_quote']
        capacity_check = mock.Mock()
        with mock.patch.dict(quote.__globals__, {'checked_stopped145_price': capacity_check}):
            with mock.patch.object(subprocess, 'run', side_effect=[insufficient, accepted]) as run, \
                    mock.patch.object(time, 'sleep') as sleep:
                self.assertEqual(quote(provider, directory, self.fleet, head, True), self.frame)
                self.assertEqual(run.call_count, 2)
                sleep.assert_called_once_with(3)
                capacity_check.assert_called_once()
            for result, wait in ((unbound, True), (insufficient, False)):
                with mock.patch.object(subprocess, 'run', return_value=result) as run, \
                        mock.patch.object(time, 'sleep') as sleep, self.assertRaises(RuntimeError):
                    quote(provider, directory, self.fleet, head, wait)
                run.assert_called_once()
                sleep.assert_not_called()

    def test_maintenance_checks_live_floors_and_its_own_booking(self):
        phase = dict(InvocationID='f86e7e61f4b34dc7aedc4e08a128e713', ActiveState='failed',
                     SubState='failed', MainPID='0', source_checkpoint_exists=False, resource_credit_bytes=0)
        growth = {'remaining_DATA_growth_bytes': 160 << 20}
        frame = dict(self.frame, phase145=phase, replay_launch_authorized=False,
                     recovery_obligations={'public_storage': growth})
        booking = dict(build_and_native_qualification_serial=True, holding_and_build_may_overlap=True,
                       build_cpu_quota_micros=1_000_000, build_memory_bytes=2 << 30)
        registered = dict(retry9_auxiliary_commitments=booking, all_existing_memory_DATA_OS_native_transport_promises_retained=True,
                          all_reservation_ending_bytes=0, complete_cycle_conservative_available_DATA_bytes=2 << 30,
                          active_ready_range_audit_obligation={'current_storage': growth})
        check = self.host['checked_maintenance_price']
        result = check(frame, self.fleet, registered, self.now, 2 << 30)
        self.assertEqual(result['complete_required_HOME_bytes'], (1024 + 160 + 48) << 20)
        with self.assertRaisesRegex(RuntimeError, 'do not fit'):
            check(frame, self.fleet, registered, self.now, (1232 << 20) - 1)
        with self.assertRaisesRegex(RuntimeError, 'maintenance booking'):
            check(frame, self.fleet, dict(registered, retry9_auxiliary_commitments=dict(booking, build_cpu_quota_micros=500_000)),
                  self.now, 2 << 30)


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
            self.add_pair(i)
        self.stamps = {p:r['source_stat'] for p,r in self.rows.items()}
        self.proof = None
        self.key = 'paired exact fixture'
        self.inspection = m['Retirement'](self.state,self.stamps,self.key,self.closure,batch_size=3).inspect()
        self.unselected = root/'unselected'
        self.unselected.write_bytes(b'preserve')

    def add_pair(self, i):
        root = Path(self.tmp.name)
        data = hashlib.shake_256(str(i).encode()).digest(4111+i)
        source = root/f'staged{i}'
        keeper = root/f'keeper{i}'
        source.write_bytes(data)
        keeper.write_bytes(data)
        self.keep.append(keeper)
        self.rows[str(source)] = {'source_stat':m['identity'](source),'keeper_stat':m['identity'](keeper),
                                  'keeper_path':str(keeper), 'whole_sha256_at_seal':hashlib.sha256(data).hexdigest()}

    def closure(self):
        return {'body_proof':self.proof}

    def run_op(self,event=lambda _:None,opened=lambda _:None):
        pair = Pair(self.state,self.rows,m)
        with pair.leases():
            opened(pair)
            p = self.state/f'paired-{time.time_ns()}.json'
            m['publish'](p,{'pairs':pair.pairs})
            self.proof = {'path':str(p),'sha256':m['fingerprint'](p)}
            op=m['Retirement'](self.state,self.stamps,self.key,self.closure,batch_size=len(self.rows),open_lease=pair.retained_source_lease)
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

    def test_41_pairs_share_one_proof_and_retry_idempotently(self):
        for i in range(3,41):
            self.add_pair(i)
        self.stamps = {p:r['source_stat'] for p,r in self.rows.items()}
        self.inspection = m['Retirement'](self.state,self.stamps,self.key,self.closure,batch_size=41).inspect()
        def inspect(pair):
            self.assertEqual(len(pair.sources), 41)
            self.assertEqual(len(pair.keepers), 41)
        self.run_op(opened=inspect)
        self.assert_complete()
        self.assertEqual(m['read'](self.state/'captured-0.json')['end'], 41)

    def test_88_pairs_leased_before_first_mutation(self):
        for i in range(3, 88):
            self.add_pair(i)
        self.stamps = {p:r['source_stat'] for p,r in self.rows.items()}
        self.inspection = m['Retirement'](self.state,self.stamps,self.key,self.closure,batch_size=88).inspect()
        def inspect(pair):
            self.assertEqual(len(pair.sources), 88)
            self.assertEqual(len(pair.keepers), 88)
            self.assertTrue(all(Path(p).exists() for p in self.rows))
        self.run_op(opened=inspect)
        self.assertEqual(m['read'](self.state/'captured-0.json')['end'], 88)
        self.assert_complete()

    def test_128_pairs_leased_before_first_mutation(self):
        for i in range(3, 128):
            self.add_pair(i)
        self.stamps = {p:r['source_stat'] for p,r in self.rows.items()}
        self.inspection = m['Retirement'](self.state,self.stamps,self.key,self.closure,batch_size=128).inspect()
        def inspect(pair):
            self.assertEqual(len(pair.sources), 128)
            self.assertEqual(len(pair.keepers), 128)
            self.assertTrue(all(Path(p).exists() for p in self.rows))
        self.run_op(opened=inspect)
        self.assertEqual(m['read'](self.state/'captured-0.json')['end'], 128)
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
