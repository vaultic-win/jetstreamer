"""Exercise the retry5/full170 cadence switch with offline owner and receipt fixtures."""
import ast
import json
import os
from pathlib import Path
import runpy
import sys
import tempfile
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import Mock, patch


HERE = Path(__file__).resolve().parent
V12 = 'tools-cold168-retry5-failed166-v12-entry146'
V13 = 'tools-cold168-retry5-failed166-v13-entry146'
ACTIVE_SHA = 'b42e7b3c5327438cd355357f73f2574c05ffbd67fd9597aa7d05c17f8324cc54'
SEAL_SHA = '6899ee7708ca74e9bf2a04cb932ce2fc75dff18e16866149b1dbeea3887496ac'


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def reference(path, digest='a' * 64):
    return dict(path=str(path), sha256=digest)


def cycle_functions(*names, **scope):
    path = HERE / 'status_cycle.py'
    body = [node for node in ast.parse(path.read_text()).body
            if isinstance(node, ast.FunctionDef) and node.name in names]
    exec(compile(ast.Module(body=body, type_ignores=[]), str(path), 'exec'), scope)
    return scope


class Rejoin(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        base = Path(temporary.name)
        root = base / 'survivor'
        lock = tempfile.TemporaryFile(dir=base)
        self.addCleanup(lock.close)
        self.fd = lock.fileno()
        identity = os.fstat(self.fd)
        self.consumer = dict(path=str(base/'consumer.lock'), device=identity.st_dev,
                             inode=identity.st_ino, fd=3)
        self.unit = 'cadence.service'
        self.state = dict(Id=self.unit, ActiveState='active', Job='', InvocationID='b'*32)
        self.old = dict(unit=self.unit, program=str(root/V12/'status_cycle.py'), invocation_id='a'*32,
                        pid=100, start_ticks=10, lock=self.consumer)
        active_path = root/'FAILED166_CADENCE_V12_ACTIVE.json'
        old_ready_path = root/'FAILED166_CADENCE_V12_READY.json'
        old_seal_path = root/V12/'deployment-seal-receipt.json'
        old_binding = root/V12/'retry5-168-generation.json'
        current = root/V13/'status_cycle.py'
        binding = current.with_name(old_binding.name)
        receiver = current.with_name('full170_status.py')
        ready_path = root/'FAILED166_CADENCE_V13_READY.json'
        fleet_path = base/'root-current'/'ROOT_COMPLETE_OPERATIONAL_FLEET.json'
        fleet_path.parent.mkdir()
        fleet_path.touch()
        stop = reference(base/'retry4-stop.json')
        self.fleet = dict(sole_next_observer=reference(base/'observer.json'), sole_next_timer='observer.timer')
        self.cfg = dict(output=str(base/'sample.json'), diagnostic_replays=[])
        self.timer = Mock(return_value=[self.fleet['sole_next_timer']])
        self.write = Mock()
        self.receipt = reference(current.with_name('deployment-seal-receipt.json'))
        self.references = {active_path: reference(active_path, ACTIVE_SHA),
                           old_seal_path: reference(old_seal_path, SEAL_SHA)}
        bound = lambda path: self.references.get(path, reference(path))
        self.active = dict(schema='horizon-epoch166-cadence-rejoin-active-v1',
                           producer_mutations=False, ready=bound(old_ready_path), new=self.old)
        self.previous = dict(package=bound(old_seal_path), retry5_generation=bound(old_binding),
                             retained_retry4_stop=stop)
        self.ready = dict(schema='horizon-epoch166-cadence-rejoin-ready-v1', package=self.receipt,
                          old_owner=bound(active_path), fleet=bound(fleet_path),
                          config=self.fleet['sole_next_observer'], timer=self.fleet['sole_next_timer'],
                          retry5_generation=bound(binding), retained_retry4_stop=stop,
                          full170_receiver=bound(receiver))
        documents = {str(path): value for path, value in (
            (active_path, self.active), (old_ready_path, self.previous), (ready_path, self.ready),
            (old_seal_path, dict(members=[dict(name=old_binding.name, mode='0444', sha256='a'*64)])),
            (fleet_path, self.fleet))}
        self.retry5 = SimpleNamespace(BINDING=binding, RETRY4_STOP=stop, generation=Mock())
        self.guard_stop = Mock()
        self.full170 = SimpleNamespace(historical_diagnostic=Mock(), generation=Mock(), hold_image=Mock())
        self.scope = cycle_functions(
            'failed166_package', 'check_v13_predecessor', 'rejoin_failed166_cadence',
            BASE=base, ROOT=root, CURRENT=current, CONTROLLER=self.unit, FAILED166_VERSION=13,
            RETRY5_CADENCE_VERSIONS=(12, 13), RETRY5_168=True, METERED_FULL170=True, HOLDING185=False,
            os=os, Path=Path, need=need, bound=bound, checked=lambda ref: documents[ref['path']],
            sealed=lambda ref: self.cfg, timer_names=self.timer, durable=self.write,
            cold166_status=SimpleNamespace(failed_route=Mock()),
            cold_workers=SimpleNamespace(cold168=self.retry5, cold170=None, full170=self.full170,
                                         failed_route=Mock(return_value=True),
                                         cold168_commit=SimpleNamespace(guard_stop=self.guard_stop)),
            owners=SimpleNamespace(ticks=lambda pid: 20 if pid == os.getpid() else 11))

    def rejoin(self, fd=None):
        return self.scope['rejoin_failed166_cadence'](self.state, self.receipt, self.fd if fd is None else fd)

    def test_reuses_timer_and_registers_both_receivers(self):
        self.assertIs(self.rejoin(), self.ready)
        self.full170.historical_diagnostic.assert_called_once_with(self.fleet)
        self.full170.generation.assert_called_once_with()
        self.full170.hold_image.assert_called_once_with()
        self.retry5.generation.assert_called_once_with()
        self.guard_stop.assert_called_once_with(self.fleet, self.cfg, successor=self.retry5)
        path, record = self.write.call_args.args
        self.assertEqual(path.name, 'FAILED166_CADENCE_V13_ACTIVE.json')
        self.assertEqual(record['old'], self.old)
        self.assertEqual(record['new']['lock'], dict(self.consumer, fd=self.fd))
        self.assertFalse(record['producer_mutations'])
        self.assertEqual(self.ready['timer'], self.fleet['sole_next_timer'])

    def test_rejects_wrong_timer_or_consumer_lock(self):
        with tempfile.TemporaryFile() as other, self.assertRaisesRegex(ValueError, 'incumbent lock'):
            self.rejoin(other.fileno())
        self.timer.return_value += ['other.timer']
        with self.assertRaisesRegex(ValueError, 'observer clock'):
            self.rejoin()
        self.write.assert_not_called()

    def test_rejects_rebound_incumbent_and_changed_retry5_bytes(self):
        path = Path(self.ready['old_owner']['path'])
        self.references[path] = self.ready['old_owner'] = reference(path, 'c'*64)
        with self.assertRaisesRegex(ValueError, 'immutable V12 owner'):
            self.rejoin()
        self.references[path] = self.ready['old_owner'] = reference(path, ACTIVE_SHA)
        binding = self.retry5.BINDING
        self.references[binding] = self.ready['retry5_generation'] = reference(binding, 'c'*64)
        with self.assertRaisesRegex(ValueError, 'sealed retry5 generation'):
            self.rejoin()
        self.write.assert_not_called()

    def test_rejects_foreign_170_receiver_and_pending_diagnostic(self):
        original = self.ready['full170_receiver']
        self.ready['full170_receiver'] = dict(original, sha256='c'*64)
        with self.assertRaisesRegex(ValueError, 'sealed metered epoch 170 receiver'):
            self.rejoin()
        self.ready['full170_receiver'] = original
        self.cfg['diagnostic_replays'] = [{'range': '170'}]
        with self.assertRaisesRegex(ValueError, 'settled epoch 170 diagnostic'):
            self.rejoin()
        self.write.assert_not_called()


class Receivers(unittest.TestCase):
    def test_retry5_and_full170_keep_separate_routes(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            package = base / V13
            package.mkdir()
            for name in ('retry13-170-generation.json', 'retry5-168-generation.json', 'cold170_commit.py'):
                (package/name).touch()
            evidence = ModuleType('evidence')
            evidence.BASE, evidence.need, evidence.bound, evidence.checked = base, need, reference, Mock()
            cold168 = SimpleNamespace(ATTEMPT=5, register=Mock(), projection=Mock())
            cold167 = SimpleNamespace()
            owner168 = {'actor': {'producer_invocation_id': '8'*32}}
            inherited = SimpleNamespace(ROUTES={167: '167'}, native=Mock(return_value='168'), ACTOR=object(),
                                        guard_budget=Mock(), observe_worker=Mock(),
                                        ownership=Mock(return_value={'168': owner168}))
            cold166 = SimpleNamespace(reader=lambda: inherited)
            modules = dict(evidence=evidence, cold166_status=cold166, cold167_status=cold167, cold168_status=cold168)
            with patch.dict(sys.modules, modules):
                for name in ('cold170_status.py', 'full170_status.py'):
                    (package/name).write_text((HERE/name).read_text())
                with patch.object(sys, 'path', [str(package), *sys.path]):
                    cold = runpy.run_path(str(package/'cold170_status.py'))
            full = cold['full170']
            self.assertEqual(full.PACKAGE, V13)
            self.assertTrue(cold['RETRY5_168'] and cold['METERED_FULL'])
            full.generation = Mock(return_value=(None, {'inode': 170}, {'contract': {}, 'guard': {'sha256': 'guard'}}))
            full.native = Mock(return_value='170')
            cold['reader'].__globals__['generation'] = Mock(return_value=(None, {'inode': 13}, {}))
            reader = cold['reader']()
            cold168.register.assert_called_once_with(reader)
            self.assertEqual(reader.ROUTES[170][3], 170)
            self.assertEqual(reader.native(168), '168')
            self.assertEqual(reader.native(170), '170')
            self.assertEqual(reader.guard_budget(170, full.ROOT,
                             dict(maximum_root_physical_bytes=full.CAP, worker_root=str(full.LANE),
                                  data_fulfillment={}), {}), (384, 'guard', {'contract': {}, 'guard': {'sha256': 'guard'}}))
            with self.assertRaisesRegex(ValueError, 'different metered 170 guard plan'):
                reader.guard_budget(170, full.ROOT, dict(maximum_root_physical_bytes=0), {})
            cold['projection']({'range': '168'})
            cold168.projection.assert_called_once_with({'range': '168'})

            self.check_full170_ownership(full, reader, evidence, owner168)

    def check_full170_ownership(self, full, reader, evidence, owner168):
        root = full.ROOT
        root.mkdir()
        actor = dict(producer_unit=full.UNIT, producer_invocation_id='7'*32, producer_pid=170, start_ticks=70)
        unit = {'Id': full.UNIT}
        full.native.return_value = (unit, actor)
        self.assertEqual(reader.ownership({}), {'168': owner168, '170': dict(
            unit=unit, actor=actor, admission=None, first_worker=None)})

        refs = {key: reference(root/name) for key, name in (
            ('intent', 'START_INTENT.json'), ('first_guard', 'FIRST_GUARD.json'),
            ('post_guard_capacity', 'POST_GUARD_CAPACITY.json'), ('actual_guard_plan', 'ACTUAL_GUARD_PLAN.json'))}
        start = {key: reference(root/key) for key in ('fleet', 'stable_root', 'predecessor_stop', 'prepared')}
        admission = dict(actor, **refs, epoch=170, fleet=start['fleet'], stable_root=start['stable_root'],
                         predecessor_stop=start['predecessor_stop'], source=start['prepared'],
                         resource_credit_bytes=0, timer_unit=full.TIMER, timer_invocation_id='1'*32,
                         bootstrap_only=True, transaction_replay_claimed=False)
        admission_path = root/'ACTUAL_ADMISSION_AND_PROTECTION.json'
        first_path = root/'FIRST_PROTECTED_WORKER.json'
        for path in (admission_path, first_path):
            path.touch()
        log = {'inode': 170}
        row = dict(range='170', producer_unit=full.UNIT, controller_unit=full.UNIT, append_log=log,
                   expected_producer_invocation_id=actor['producer_invocation_id'],
                   expected_controller_invocation_id=actor['producer_invocation_id'],
                   scratch_path=str(full.RUN/'private/scratch'), worker_executable_basename='historical-worker')
        first = dict(actor, observer_row=row, epoch=170, admission=reference(admission_path),
                     worker_sha256=full.WORKER_SHA, worker_pid=171, worker_start_ticks=71,
                     worker_exe_device=2, worker_exe_inode=170)
        documents = {str(admission_path): admission, str(first_path): first,
                     refs['first_guard']['path']: {'timer': {'InvocationID': admission['timer_invocation_id']}}}
        evidence.checked.side_effect = lambda ref: documents[ref['path']]
        full.intent = Mock(return_value=(start, {}, {}))
        full.append_identity = Mock(return_value=log)
        self.assertEqual(reader.ownership({}), {'168': owner168, '170': dict(
            unit=unit, actor=actor, admission=reference(admission_path), first_worker=reference(first_path))})
        first['producer_invocation_id'] = '0'*32
        with self.assertRaisesRegex(ValueError, 'different metered 170 worker projection'):
            reader.ownership({})


class ReadyDeliveryInventory(unittest.TestCase):
    def setUp(self):
        self.owner = ('publish-199.service', 'a' * 32)
        self.completion = reference('/completion.json')
        self.original = reference('/inventory.json')
        self.inventory = SimpleNamespace(inventory=lambda: ({140, 199}, {148, 199}, {148: ('old', 1), 199: ('new', 2)}))
        self.context = SimpleNamespace(prior={'inventory': self.original}, completed_deliveries={}, staged_deliveries={},
            fleet={'epochs': [{'epoch': 199, 'current_repair_owner': '/root', 'current_status': {'jet_size_bytes': 2}}]})
        self.legacy = Mock(side_effect=lambda c, source: source.inventory())
        event = {'event': 'r2-readback-start', 'key': 'epoch-199.jet', 'total_bytes': 2, 'expected_etag': 'new'}
        self.journal = Mock(return_value=json.dumps({'_SYSTEMD_UNIT': self.owner[0],
            '_SYSTEMD_INVOCATION_ID': self.owner[1], 'MESSAGE': json.dumps(event), '__CURSOR': 'cursor',
            '__REALTIME_TIMESTAMP': '1'}))
        self.scope = cycle_functions('staged_delivery_inventory', FAILED166_VERSION=16,
            PUBLICATION_INVOCATIONS={199: self.owner}, checked=lambda ref, **kw: {
                '/completion.json': {'etag': 'new', 'length': 2},
                '/inventory.json': {'entries': [{'epoch': 148, 'state': 'ready-pair'}]},
            }[ref['path']], need=need, SimpleNamespace=SimpleNamespace, json=json,
            status=SimpleNamespace(inventory=self.legacy), subprocess=SimpleNamespace(check_output=self.journal))

    def observe(self):
        return self.scope['staged_delivery_inventory'](self.context, self.inventory)

    def test_visible_sidecar_waits_for_native_completion_before_status_removal(self):
        self.assertEqual(self.observe(), ({140, 199}, {148}, {148: ('old', 1)}))
        self.assertEqual(self.context.staged_deliveries[199]['size_bytes'], 2)
        self.context.completed_deliveries = {'199': self.completion}
        self.context.staged_deliveries = {}
        self.inventory.inventory = lambda: ({140}, {148, 199}, {148: ('old', 1), 199: ('new', 2)})
        self.assertEqual(self.observe(), ({140, 199}, {148}, {148: ('old', 1)}))
        self.assertEqual(self.context.staged_deliveries, {})

    def test_changed_ready_identity_or_new_status_fails_closed(self):
        self.context.completed_deliveries = {'199': self.completion}
        with self.assertRaisesRegex(ValueError, 'new status claim'):
            self.observe()
        self.inventory.inventory = lambda: ({140}, {148, 199}, {148: ('old', 1), 199: ('other', 2)})
        with self.assertRaisesRegex(ValueError, 'archive identity changed'):
            self.observe()


if __name__ == '__main__':
    unittest.main()
