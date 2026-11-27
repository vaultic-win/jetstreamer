"""Focused tests against the saved fleet bindings and the V29 guard retry."""
from copy import deepcopy
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import TestCase, main
from unittest.mock import Mock, patch
import sys

root = Path(__file__).resolve().parent
source = root/'tools-cold168-retry5-failed166-v29-entry146'
authority = Path('/var/lib/jetstreamer/horizon_runtime_data')
sys.path[:0] = [str(source), str(authority/'prefix140-status-cadence-20261122-v1/cadence-tools')]
from evidence import bound, checked, need, sealed
import cold168_commit as retry
import joint168_status as joint

class HistoricalPopulation(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fleet = checked(bound(authority/'root011808-live166167170-20261127-v1/ROOT_COMPLETE_OPERATIONAL_FLEET.json'))
        cls.cfg = sealed(cls.fleet['sole_next_observer'])

    def setUp(self):
        self.fleet = deepcopy(type(self).fleet)
        self.cfg = deepcopy(type(self).cfg)

    def test_exact_joint_is_excluded_only_from_private_diagnostics(self):
        owner = joint.retained_population(self.fleet,self.cfg)
        self.assertEqual(owner,self.fleet[joint.FIELD])
        self.assertEqual(retry.previous_replays(self.fleet,None,owner),[])
        self.fleet['actual_executing_replays'].append(owner)
        self.assertEqual(retry.previous_replays(self.fleet,None,owner),[owner])

    def test_duplicate_diagnostic_fails(self):
        self.fleet['actual_active_private_diagnostics'].append(self.fleet[joint.FIELD])
        with self.assertRaisesRegex(ValueError, 'prior diagnostic differs'):
            joint.retained_population(self.fleet,self.cfg)

    def test_foreign_schedule_fails(self):
        row = next(row for row in self.cfg['diagnostic_replays'] if row['range'] == '168')
        row['expected_controller_invocation_id'] = 'foreign'
        with self.assertRaisesRegex(ValueError, 'diagnostic schedule differs'):
            joint.retained_population(self.fleet,self.cfg)

    def test_same_unit_foreign_actor_fails(self):
        self.fleet[joint.FIELD]['actor']['producer_start_ticks'] += 1
        with self.assertRaisesRegex(ValueError, 'foreign joint 168 predecessor'):
            joint.retained_population(self.fleet,self.cfg)

    def test_missing_prior_fails(self):
        self.fleet.pop(joint.FIELD)
        with self.assertRaisesRegex(ValueError, 'no accepted prior owner'):
            joint.retained_population(self.fleet,self.cfg)

    def test_terminal_cannot_supply_live_exception(self):
        self.fleet[joint.FIELD]['phase'] = 'terminal'
        with self.assertRaisesRegex(ValueError, 'terminal joint 168 still has'):
            joint.retained_population(self.fleet,self.cfg)

class GuardSelection(TestCase):
    def run_guard(self, kind):
        with TemporaryDirectory() as tmp:
            folder = Path(tmp)/'guard-receipts'
            folder.mkdir()
            first = folder/'sample-first.json'
            first.touch()
            second = folder/'sample-second.json'
            read_ref = lambda p: dict(path=str(p))
            guard = dict(plan='bound-plan', timer_invocation_id='bound-timer')
            checkout = lambda p: ({'workers': [[900,1]], 'recorded_unix_seconds': 100+(p==second)}, read_ref(p))
            validate = Mock(side_effect=kind)
            add_second = lambda _n: second.touch()
            with patch.object(joint.lane,'ROOT',folder.parent), patch.object(joint,'bound',side_effect=read_ref), \
                 patch.object(joint,'checked',side_effect=[{'post_guard_fit':'held'},{'native_joint168':{'guard':guard}}]), \
                 patch.object(joint,'read',side_effect=checkout), patch.object(joint.lane,'protective',validate), \
                 patch.object(joint.time,'sleep',side_effect=add_second):
                result=joint.latest_guard({}, {}, {'pid':900})
            return result, validate

    def test_only_newer_sample_can_follow_churn(self):
        result, validate = self.run_guard([joint.lane.GuardDirectoryChurn('vanished'), {'valid':True}])
        self.assertEqual(result,({'valid':True},True))
        self.assertTrue(validate.call_args_list[0].args[1]['sample']['path'].endswith('sample-first.json'))
        self.assertTrue(validate.call_args_list[1].args[1]['sample']['path'].endswith('sample-second.json'))
        self.assertTrue(all(call.kwargs == {'distinguish_churn':True} for call in validate.call_args_list))

    def test_independent_protective_failure_propagates(self):
        with self.assertRaisesRegex(ValueError, 'foreign guard'):
            self.run_guard([ValueError('foreign guard'), AssertionError('unexpected retry')])

class ExactGuardInvariants(TestCase):
    def setUp(self):
        self.fixture = json.loads((root/'EXACT_GUARD_FIXTURE.json').read_text())

    def protective(self, distinguish=True, age=20):
        lane, f = joint.lane, self.fixture
        f['sample']['workers'] = []
        bound_data = {f['requested'][k]['path']:f[k] for k in ('plan','sample')}
        manager_data = {lane.TIMER:f['timer'],lane.SERVICE:f['service']}
        watcher = SimpleNamespace(need=need,bound=lambda ref,_path:bound_data[ref['path']])
        with patch.object(lane,'props',side_effect=lambda unit,_fields:manager_data[unit]), \
             patch.object(lane.time,'time',return_value=f['sample']['recorded_unix_seconds']+age):
            return lane.protective(watcher,f['requested'],f['e'],f['q'],None,
                                   distinguish_churn=distinguish)

    def test_native_churn_is_a_distinct_failure_only_for_cadence(self):
        with self.assertRaises(joint.lane.GuardDirectoryChurn):
            self.protective()
        with self.assertRaises(ValueError) as stopped_admission:
            self.protective(distinguish=False)
        self.assertNotIsInstance(stopped_admission.exception,joint.lane.GuardDirectoryChurn)

    def test_churn_cannot_mask_trip_crossed_identity_or_freshness(self):
        for key,value,age in [('trip_reason','root-physical-budget',20),
                              ('producer_invocation_id','foreign',20),
                              ('available_bytes',0,20),
                              ('trip_reason',None,121)]:
            with self.subTest(key=key,age=age):
                before=self.fixture['sample'][key]
                self.fixture['sample'][key]=value
                with self.assertRaises(ValueError) as plain:
                    self.protective(age=age)
                self.assertNotIsInstance(plain.exception,joint.lane.GuardDirectoryChurn)
                self.fixture['sample'][key]=before

    def test_clean_physical_receipt_returns_bound_guard(self):
        for side in ('first','second'):
            self.fixture['sample']['root_physical_observation'][side]['vanished_entries']=0
        self.assertEqual(self.protective()['sample'],self.fixture['requested']['sample'])

if __name__=='__main__':
    main()
