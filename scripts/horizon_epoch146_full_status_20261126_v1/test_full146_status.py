import datetime as dt

import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace as NS
from unittest import TestCase, main
from unittest.mock import patch

from botocore.awsrequest import AWSRequest
from botocore.hooks import HierarchicalEmitter

# The qualification runner passes the sealed successor location.
sys.path.insert(0, sys.argv.pop(1))
import status_cycle as cadence
import full146_status as lane

IID = '1' * 32
ENROLL = {'path': str(lane.ENROLLMENT), 'sha256': 'b' * 64}
ROOT_ACTOR = {'producer_invocation_id': IID, 'producer_pid': 321, 'start_ticks': 765,
              'producer_unit': lane.UNIT, 'worker_ready_unix_seconds': 178,
              'profile_sha256': '1' * 64}
WORKER = dict(pid=322, start_ticks=766, path=str(lane.RUN/'private/run/scratch/.historical-runtime/run/bound-worker/historical-worker'),
              device=3, inode=4)
GUARD_PLAN = {'path': '/mock/plan', 'sha256': 'a' * 64}
GUARD_LIMITS = dict(minimum_free_bytes=100, maximum_root_physical_bytes=lane.CAP, maximum_worker_vmas=3500000)
PROFILE = {'guard': {'properties': GUARD_LIMITS}}
ROW = {'ActiveState': 'active', 'MainPID': '321'}
WHEN = dt.datetime(2026, 11, 26, 20, tzinfo=dt.timezone.utc)
FORECAST = dict(epoch=146, phase='verification', elapsed_execution_millis=0, jet_size_bytes=0,
                sampled_at_utc='2026-11-26T19:59:00Z', estimated_remaining_millis=800000)
PROGRESS = dict(last={'slot': 63500000}, transaction_delta=50, elapsed_seconds=60, slot_delta=100)
BINDING = {'path': str(lane.LOG), 'device': 1, 'inode': 2}
DRAIN = dict(ActiveState='inactive', MainPID='0', ControlPID='0', Job='')


class Enrollment(TestCase):
    def setUp(self):
        self.cfg = dict(range='146', controller_unit=lane.UNIT, producer_unit=lane.UNIT,
                        expected_producer_invocation_id=IID, expected_controller_invocation_id=IID,
                        scratch_path=str(lane.RUN/'private/run/scratch'),
                        worker_executable_basename='historical-worker', append_log=BINDING)
        self.ctx = NS(entry146=None, sample_ref={'observer': True}, cfg={'diagnostic_replays': []},
                      sample={'diagnostic_replays': []}, rows={}, advancing={}, fleet={})

    def test_v25_and_incumbent_routes(self):
        self.assertEqual(cadence.FAILED166_VERSION, 25)
        self.assertTrue(cadence.METERED_FULL170 and cadence.HOLDING185 and cadence.RETRY5_168)
        self.assertTrue(cadence.cold_workers.METERED_FULL)
        self.assertEqual(cadence.failed166_package(24), 'tools-cold168-retry5-failed166-v24-entry146')
        self.assertTrue(callable(cadence.focused168_status.terminal))
        self.assertTrue(callable(cadence.install_epoch146_entry))

    def test_no_enrollment_and_foreign_actor(self):
        with patch.object(lane, 'enrollment', return_value=None), patch.object(lane, 'group_pids', return_value=set()), patch.object(lane, 'show', return_value=DRAIN):
            self.assertIsNone(lane.observe(self.ctx, None))
            with patch.object(lane, 'show', return_value=ROW):
                with self.assertRaisesRegex(ValueError, 'lacks an enrollment'):
                    lane.observe(self.ctx, None)

    def test_held_bootstrap_and_protected_worker(self):
        with patch.object(lane, 'enrollment', return_value=(ENROLL, {'actor': ROOT_ACTOR}, PROFILE)), patch.object(lane, 'show', return_value=ROW), patch.object(lane, 'group_pids', return_value={321}), patch.object(lane, 'native', return_value=(Path('/proc/321'), 'held')) as native, patch.object(lane, 'log_identity', return_value=BINDING):
            held = lane.observe(self.ctx, None)
            self.assertEqual(held['phase'], 'held')
            self.assertIsNone(held['observer_config'])
            self.assertEqual(held['actor'], ROOT_ACTOR)
            native.return_value = (Path('/proc/321'), 'bootstrap')
            with patch.object(lane, 'protection', return_value=({'guard_receipt_sha256': 'a'*64}, GUARD_PLAN, {})), patch.object(lane, 'worker_view', return_value=('bootstrap', None, None)) as worker:
                boot = lane.observe(self.ctx, None)
                self.assertEqual(boot['phase'], 'bootstrap')
                self.assertEqual(boot['actor'], held['actor'])
                worker.return_value = ('worker', WORKER, {'first_worker': True})
                port = lane.observe(self.ctx, None)
                self.assertEqual(port['observer_config'], self.cfg)
                self.assertFalse(port['measured_progress'])
                self.ctx.cfg['diagnostic_replays'] = [self.cfg]
                point = dict(pid=WORKER['pid'], executable=WORKER['path'])
                self.ctx.sample['diagnostic_replays'] = [dict(range='146', producer_unit=lane.UNIT,
                    expected_producer_invocation_id=IID, ordinary_replay_claim=False, status='observed',
                    observation=dict(worker_before=point, worker_after=point, useful_work=PROGRESS))]
                self.assertTrue(lane.observe(self.ctx, lambda *_: True)['measured_progress'])
                point['pid'] += 1
                with self.assertRaisesRegex(ValueError, 'crossed'):
                    lane.observe(self.ctx, lambda *_: True)

    def test_crossed_stale_or_tripped_guard(self):
        sample = dict(GUARD_LIMITS, schema='jetstreamer-horizon-standalone-guard-sample-v1',
                      guard_sha256=lane.GUARD_SHA, plan=GUARD_PLAN['path'], plan_sha256='a'*64,
                      guard_invocation_id='3'*32, producer_invocation_id=IID,
                      producer=dict(invocation_id=IID, pid=321, cgroup=lane.GROUP, active='active',
                                    sub='running', restarts=0), producer_stop_enabled=True, trip_reason=None,
                      worker_observation_error=None, root_physical_observation_error=None, available_bytes=500,
                      root_physical_observation={'conservative_physical_bytes': lane.CAP}, workers=[[322, 50]],
                      recorded_unix_seconds=220)
        lane.sample_guard(sample, ROOT_ACTOR, PROFILE, GUARD_PLAN, 322, 200)
        for different in ({'workers': [[323, 50]]}, {'recorded_unix_seconds': 199},
                          {'producer_invocation_id': '2'*32}, {'trip_reason': 'disk-cap'}):
            with self.subTest(different=different), self.assertRaisesRegex(ValueError, 'stale, crossed or unprotected'):
                lane.sample_guard(dict(sample, **different), ROOT_ACTOR, PROFILE, GUARD_PLAN, 322, 200)

    def test_terminal_drains_all_units(self):
        receipt = dict(schema='horizon-epoch146-full-status-terminal-v1', enrollment=ENROLL, disposition='failed',
                       resource_credit_bytes=0, archive_publication_authorized=False,
                       active_repair_owner='/root', remaining_to_sidecar_millis=3600000,
                       pid1_terminal_event={'_PID': '1', '_UID': '0', 'UNIT': lane.UNIT, 'INVOCATION_ID': IID})
        with patch.object(lane, 'secure_ref', return_value={'terminal': True}), patch.object(lane, 'checked', return_value=receipt), patch.object(lane, 'show', side_effect=lambda name, _: dict(DRAIN, Id=name)), patch.object(lane, 'group_pids', return_value=set()) as pids:
            self.assertEqual(lane.terminal(ENROLL, {'actor': ROOT_ACTOR}, dict(DRAIN, Id=lane.UNIT))[1], receipt)
            pids.side_effect = lambda name: {345} if name == lane.SERVICE else set()
            with self.assertRaisesRegex(ValueError, 'surviving'):
                lane.terminal(ENROLL, {'actor': ROOT_ACTOR}, dict(DRAIN, Id=lane.UNIT))

    def test_initial_missing_and_authenticated_existing_status(self):
        self.ctx.full146 = None
        self.assertIsNone(lane.baseline(self.ctx, None))
        self.ctx.full146 = {'enrollment': ENROLL, 'actor': ROOT_ACTOR}
        receipt = dict(schema='horizon-epoch146-full-initial-status-v1', epoch=146, key=lane.KEY,
                       conditional_header='If-None-Match', authenticated_readback=True, previous_receipt=None,
                       full146_enrollment=ENROLL, producer_invocation_id=IID, after_status=FORECAST,
                       after_etag='etag')
        with patch.object(lane, 'INITIAL', NS(exists=lambda: False)):
            with self.assertRaisesRegex(ValueError, 'requires its authenticated initial event'):
                lane.baseline(self.ctx, None)
        with patch.object(lane, 'INITIAL', NS(exists=lambda: True)), patch.object(lane, 'secure_ref', return_value={'initial': True}), patch.object(lane, 'checked', return_value=receipt):
            self.assertEqual(lane.baseline(self.ctx, None), {'initial': True})
            self.assertEqual(lane.baseline(self.ctx, {'existing': True}), {'existing': True})
            receipt['full146_enrollment'] = {'foreign': True}
            with self.assertRaisesRegex(ValueError, 'different enrollment'):
                lane.baseline(self.ctx, {'existing': True})

    def test_listing_requires_authenticated_overlay(self):
        inc = NS(prior={'inventory': 'original'}, staged_deliveries={}, completed_deliveries={})
        store = NS(inventory=lambda: ({136, 140, 146}, set(), {}))
        with patch.object(cadence, 'checked', return_value={'entries': []}), patch.object(cadence.status, 'inventory', side_effect=lambda _, inv: inv.inventory()[0]), patch.object(cadence, 'authenticated') as authenticate:
            with self.assertRaisesRegex(ValueError, 'unregistered'):
                cadence.staged_delivery_inventory(inc, store)
            inc.status146 = {'registered': True}
            self.assertEqual(cadence.staged_delivery_inventory(inc, store), {136, 140})
            authenticate.assert_called_once_with(store, 146, inc.status146)
            authenticate.side_effect = ValueError('remote body changed')
            with self.assertRaisesRegex(ValueError, 'remote body changed'):
                cadence.staged_delivery_inventory(inc, store)


    def test_initial_creation_uses_only_if_none_match_and_checks_readback(self):
        e = dict(actor=ROOT_ACTOR, fleet={'fleet': True}, writer={'writer': True})
        c = NS(fleet_ref=e['fleet'], fleet={})
        request = dict(schema='horizon-epoch146-full-initial-status-intent-v1', owner='/root',
                       enrollment=ENROLL, forecast='Reviewed delivery allowance.',
                       status=dict(FORECAST, sampled_at_utc='1970-01-01T00:03:00Z'))
        active = dict(ActiveState='active', Id=lane.CONTROLLER, InvocationID='2'*32, MainPID='10', Job='')
        writer = dict(new=dict(unit=lane.CONTROLLER, invocation_id='2'*32, pid=10, start_ticks=20))
        emitter = HierarchicalEmitter()
        raw = cadence.status.body(request['status'])
        store = NS(inventory=lambda: (set(), set(), {}), get=lambda _: ('"etag"', raw),
                   s3=NS(meta=NS(events=emitter)), pending=None)
        emitter.register_first('before-sign.s3.PutObject',
                               lambda request, **_: request.headers.add_header('If-Match', store.pending[1]))
        def put(epoch, token, payload):
            self.assertEqual((epoch, token, payload), (146, '*', raw))
            store.pending = (lane.KEY, token)
            write = AWSRequest(method='PUT', url='https://test.invalid/bucket/'+lane.KEY)
            emitter.emit('before-sign.s3.PutObject', request=write)
            self.assertNotIn('If-Match', write.headers)
            self.assertEqual(write.headers['If-None-Match'], '*')
            store.pending = None
            return '"etag"'
        store.put = put
        with TemporaryDirectory() as temp:
            root = Path(temp)
            opened = root/'FULL146_INITIAL_STATUS.json'
            with patch.object(lane, 'ROOT', root), patch.object(lane, 'INITIAL', opened), patch.object(lane, 'enrollment', return_value=(ENROLL, e, PROFILE)), patch.object(lane, 'sealed_doc', return_value=request), patch.object(lane, 'checked', return_value=writer), patch.object(lane, 'show', return_value=active), patch.object(lane, 'ticks', return_value=20), patch.object(lane, 'group_pids', return_value={321}), patch.object(lane, 'native', return_value=(Path('/proc/321'), 'held')), patch.object(lane, 'log_identity'):
                result = lane.publish_initial(c, {'intent': True}, store, cadence.status.body)
                self.assertEqual(result['path'], str(opened))
                self.assertTrue(json.loads(opened.read_bytes())['authenticated_readback'])
                store.inventory = lambda: ({146}, set(), {})
                store.get = lambda _: ('changed', b'other actor')
                with self.assertRaisesRegex(ValueError, 'readback'):
                    lane.publish_initial(c, {'intent': True}, store, cadence.status.body)

    def test_replay_forecast_uses_actual_progress_and_delivery(self):
        active = dict(actor=ROOT_ACTOR, enrollment=ENROLL, measured_progress=True,
                      phase='worker', progress=PROGRESS)
        c = NS(now=WHEN, stamp='2026-11-26T20:00:00Z', full146=active)
        after, details = lane.forecast(c, FORECAST, {'after_status': FORECAST},
                                      lambda *_: {'total_millis': 100000},
                                      lambda *_: {'size': 100})
        self.assertEqual(after['phase'], 'replay')
        self.assertEqual(after['jet_size_bytes'], 100)
        self.assertTrue(details['measured_canonical_progress'])
        self.assertEqual(after['estimated_remaining_millis'], 2739340)


if __name__ == '__main__':
    main()
