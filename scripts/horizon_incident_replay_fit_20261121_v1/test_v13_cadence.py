"""Check external capacity consumers against the exact V12 to V13 transition."""
from copy import deepcopy
from pathlib import Path
import re
import runpy
from types import SimpleNamespace
import unittest
from unittest.mock import Mock


HERE = Path(__file__).resolve().parent
ROUTE = runpy.run_path(str(HERE/'retry4_status.py'))
CAPACITY = runpy.run_path(str(HERE/'full170_capacity.py'))
RETRY5 = runpy.run_path(str(HERE/'retry5_fit.py'))


def ref(path, sha='a'*64):
    return dict(path=str(path), sha256=sha)


def need(ok, message):
    if not ok:
        raise ValueError(message)


class V13Cadence(unittest.TestCase):
    def setUp(self):
        self.cadence = ROUTE['STATUS']
        self.root = ROUTE['R']
        self.v12 = self.cadence/'tools-cold168-retry5-failed166-v12-entry146'
        self.v13 = ROUTE['V13_PACKAGE']
        self.old_active = ref(self.cadence/'FAILED166_CADENCE_V12_ACTIVE.json', ROUTE['V12_ACTIVE_SHA'])
        self.old_seal = ref(self.v12/'deployment-seal-receipt.json', ROUTE['V12_SEAL_SHA'])
        self.v12_ready = ref(self.cadence/'FAILED166_CADENCE_V12_READY.json')
        self.v13_active = ref(self.cadence/'FAILED166_CADENCE_V13_ACTIVE.json')
        self.v13_ready = ref(self.cadence/'FAILED166_CADENCE_V13_READY.json')
        self.new_seal = ref(self.v13/'deployment-seal-receipt.json', 'b'*64)
        generation = 'retry5-168-generation.json'
        binding_sha = '906eabc8de4ead288fcae3b514daff4a18786fd9e7200ff8fbbac6a96e933716'
        self.binding = ref(self.v13/generation, binding_sha)
        self.old_binding = ref(self.v12/generation, binding_sha)
        self.stop = ref(ROUTE['ROOT']/'guard-receipts/stop-completion.json')
        fleet_ref = ref(self.root/'root-current/ROOT_COMPLETE_OPERATIONAL_FLEET.json')
        config = ref(self.root/'root-current/sealed-next/observer.json')
        timer = 'observer.timer'
        receiver_sha = ROUTE['V13_MEMBERS']['full170_status.py']
        schema = 'horizon-epoch166-cadence-rejoin'
        self.ready = dict(schema=schema+'-ready-v1', old_owner=self.old_active, package=self.new_seal,
                          full170_receiver=ref(self.v13/'full170_status.py', receiver_sha),
                          retry5_generation=self.binding, retained_retry4_stop=self.stop,
                          fleet=fleet_ref, config=config, timer=timer)
        unit = 'cadence.service'
        lock = dict(path='/consumer.lock', device=99, inode=42, fd=3)
        old = dict(unit=unit, program=str(self.v12/'status_cycle.py'), invocation_id='1'*32,
                   pid=321, start_ticks=101, lock=lock)
        self.actor = dict(old, program=str(self.v13/'status_cycle.py'), invocation_id='2'*32,
                          pid=322, start_ticks=102, lock=dict(lock, fd=4))
        self.active = dict(schema=schema+'-active-v1', ready=self.v13_ready, old=deepcopy(old),
                           new=self.actor, producer_mutations=False)
        self.prior = self.v12, self.old_seal, old['invocation_id'], old
        old_rows = [dict(name=generation, mode='0444', sha256=binding_sha),
                    dict(name='bounded_entry_owners.py', mode='0444', sha256='e'*64)]
        seal_schema = dict(schema='jetstreamer-sealed-deployment-receipt-v1', sealer_sha256='s'*64,
                           remote_mutations=False, r2_mutations=False, publication_authorized=False,
                           replay_launch_authorized=False)
        previous_seal = dict(seal_schema, destination=str(self.v12), members=old_rows)
        self.seal = dict(seal_schema, destination=str(self.v13), members=deepcopy(old_rows) +
                         [dict(name=name, mode='0444', sha256=sha) for name, sha in ROUTE['V13_MEMBERS'].items()])
        peer = self.root/'epoch168-retry5-rebook-20261125-v1'
        anchor = ref(peer/'SUCCESSOR_ROOT.json')
        prepared = ref(peer/'PREPARED.json')
        guard = ref(self.root/'epoch168-cold-guard-20261125-v5/GUARD_QUALIFIED.json')
        retained = ref(self.root/'incident-replay-fit-20261121-v1/STOPPED168_RETRY5_RETAINED_SOURCE_CONTROL_20261125.json')
        stop = dict(terminal=self.stop, producer_invocation_id='0'*32,
                    resource_credit_bytes=0, reservation_ending_bytes=0)
        fleet = dict(sole_next_observer=config, sole_next_timer=timer, cold168_retry4_root_physical_stop=stop)
        self.docs = {}
        for reference, doc in (
            (self.v13_active, self.active), (self.v13_ready, self.ready), (self.new_seal, self.seal),
            (self.old_active, dict(new=old, ready=self.v12_ready)), (self.old_seal, previous_seal),
            (self.v12_ready, dict(package=self.old_seal, retry5_generation=self.old_binding,
                                  retained_retry4_stop=self.stop)),
            (fleet_ref, fleet),
            (self.binding, dict(prepared=prepared, successor_root=anchor, guard_qualification=guard, retained_source=retained)),
            (prepared, dict(baseline=dict(retry4_root_physical_stop=stop, stable_roots=anchor),
                            profile=dict(guard_binary_sha256='guard', payload=dict(whole_root_cap=512<<30)))),
            (anchor, dict(source_control_sha256=retained['sha256'], whole_tree_cap_bytes=512<<30)),
            (guard, dict(guard=dict(sha256='guard'))), (retained, dict(stop=stop)),
            (self.stop, dict(producer_invocation_id=stop['producer_invocation_id'])),
        ):
            self.docs[reference['path']] = (doc, reference)
        self.scope = SimpleNamespace(read=self.read, bound=self.bound, ref=ref, need=need,
                                     iid=lambda value: bool(re.fullmatch('[a-f0-9]{32}', value)))
        self.binary = Mock()

    def read(self, path):
        return self.docs[str(path)]

    def bound(self, reference, path):
        doc, observed = self.read(path)
        need(reference == observed, 'changed bound receipt')
        return doc

    def rejoin(self):
        return ROUTE['registered_failed166_rejoin'](self.scope, self.prior, 13, binary=self.binary)

    def test_binds_v13_and_keeps_the_retry5_generation(self):
        self.assertEqual(self.rejoin(), (self.v13, self.new_seal, self.actor['invocation_id'], self.actor))
        for row in self.seal['members']:
            self.binary.assert_any_call(self.v13/row['name'], row['sha256'])
        quote = dict(consumer_seal=self.new_seal, **{key: self.actor[key] for key in
                     ('invocation_id', 'pid', 'start_ticks')})
        CAPACITY['require_v13'](self.scope, quote)
        for key, value in (('consumer_seal', self.old_seal), ('invocation_id', '0'*32), ('pid', 1), ('start_ticks', 99)):
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'registered V13 receiver and actor'):
                CAPACITY['require_v13'](self.scope, dict(quote, **{key: value}))
        CAPACITY['require_v12'](self.scope, dict(consumer_seal=self.old_seal))

    def test_rejects_a_self_consistent_but_foreign_receiver(self):
        member = next(row for row in self.seal['members'] if row['name'] == 'full170_status.py')
        member['sha256'] = 'c'*64
        self.ready['full170_receiver'] = ref(self.v13/'full170_status.py', member['sha256'])
        with self.assertRaisesRegex(ValueError, 'different V13 receiver'):
            self.rejoin()
        self.binary.assert_not_called()

    def test_rejects_a_rebound_v12_owner(self):
        path = self.old_active['path']
        previous, _ = self.docs[path]
        replacement = ref(path, 'c'*64)
        self.docs[path] = (previous, replacement)
        self.ready['old_owner'] = replacement
        with self.assertRaisesRegex(ValueError, 'immutable V12 cadence predecessor'):
            self.rejoin()

    def test_rejects_a_foreign_actor_lock_or_retry5_binding(self):
        self.actor['lock']['inode'] += 1
        with self.assertRaisesRegex(ValueError, 'rejoin identity or clock'):
            self.rejoin()
        self.actor['lock']['inode'] -= 1
        self.ready['retry5_generation'] = ref(self.v13/'retry5-168-generation.json', 'c'*64)
        with self.assertRaisesRegex(ValueError, 'retry5 generation or retained stop'):
            self.rejoin()


class JointReplayPrice(unittest.TestCase):
    def setUp(self):
        self.scope = SimpleNamespace(need=need)
        self.gib = 1 << 30
        self.cold168 = dict(CAP=512 * self.gib, OUTSIDE_CAP_STOP_ALLOWANCE=8 * self.gib)

    def quote(self, guard, available, donor_margin):
        g = self.gib
        native = dict(epoch=145, fits=True, active168_guard_floor=guard * g,
                      full170_retry5_owner=dict(floor=guard * g),
                      complete_required_HOME_bytes=120 * g,
                      full170_zero_remaining_native_HOME_bytes=97 * g,
                      stopped_cold168=dict(measured_physical_bytes=289 * g, terminal=ref('/stop')),
                      bookings={'168': dict(physical_bytes=288 * g, remaining_bytes=0)},
                      retry5_retained_source=ref('/retained'),
                      full170_retry5_current=dict(physical_bytes=492 * g, remaining_bytes=20 * g),
                      epoch159_donor_cover=dict(native_home_required=130 * g,
                                               native_home_available=available * g,
                                               remaining_home_bytes=donor_margin * g))
        return RETRY5['price170'](self.scope, native, self.cold168)

    def test_current_and_zero_floors_include_donor_guard_and_retry5_once(self):
        quote = self.quote(136, 161, 31)
        self.assertTrue(quote['fits'])
        self.assertEqual(quote['complete_required_HOME_bytes'], 158 * self.gib)
        self.assertEqual(quote['full170_zero_remaining_native_HOME_bytes'], 156 * self.gib)
        self.assertEqual(quote['epoch159_donor_cover']['native_home_required'], 158 * self.gib)
        self.assertEqual(quote['epoch159_donor_cover']['remaining_home_bytes'], 3 * self.gib)
        self.assertEqual(quote['bookings']['168']['remaining_bytes'], 20 * self.gib)
        quote = self.quote(100, 161, 31)
        self.assertEqual(quote['full170_zero_remaining_native_HOME_bytes'], 135 * self.gib)

    def test_joint_growth_must_fit_both_native_home_and_donor_budget(self):
        self.assertFalse(self.quote(136, 157, 31)['fits'])
        self.assertFalse(self.quote(136, 161, 27)['fits'])


if __name__ == '__main__':
    unittest.main()
