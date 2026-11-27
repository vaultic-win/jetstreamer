import unittest
from unittest.mock import Mock

import capacity
import peer162


class SplitCapacity(unittest.TestCase):
    def setUp(self):
        self.peer = dict(IMAGE=peer162.IMAGE, CONTROL=peer162.CONTROL, DONOR=peer162.DONOR,
                         geometry=peer162.geometry, recheck=Mock())
        self.base = dict(schema='horizon-169-split-current-native-price-v1', actor=None,
                         accounting=dict(old_six_owner_lineage=dict(same_169_compute=True, static_169_memory=69*capacity.G)),
                         protected_home=100*capacity.G, guard_floor=100*capacity.G+peer162.CONTROL,
                         remaining_output=peer162.IMAGE, available_home=120*capacity.G,
                         ram_margin=1000, started_unix_seconds=5)
        self.base['required_home'] = self.base['guard_floor'] + self.base['remaining_output']
        self.base['home_margin'] = self.base['available_home'] - self.base['required_home']

    def test_prestart_reserves_both_images(self):
        q = capacity.calculate(self.peer, self.base, None, 'prestart', None, 0, {})
        self.assertTrue(q['fits'])
        self.assertEqual(q['required_home'], 116*capacity.G+2*peer162.CONTROL)
        self.assertEqual(q['ram_margin'], self.base['ram_margin'])
        self.assertEqual(q['peers']['169'], {'phase':'precharged'})
        self.assertFalse(capacity.calculate(self.peer, self.base, None, 'prestart', None, 117*capacity.G, {})['fits'])

    def test_held_owner_with_active_peer(self):
        disk = dict(floor=100*capacity.G, remaining=2*capacity.G, fixed_control=peer162.CONTROL)
        actual = dict(phase='worker', unit={'InvocationID':'other'}, hourly169_start_intent={'sha256':'intent'},disk=disk)
        row = dict(phase='held', invocation_id='held', donor=peer162.DONOR, lease={'sha256':'lease'},
                   sampled_at=3, realized_ram=10, disk=disk)
        self.peer['recheck'].return_value = dict(row, realized_ram=5, disk=dict(disk,remaining=capacity.G))
        q = capacity.calculate(self.peer, dict(self.base, actor=actual), row, 'postguard','held',0,{})
        self.assertEqual(q['remaining_162_home'], 2*capacity.G)
        self.assertEqual(q['ram_margin'], 1005)
        self.assertEqual(q['peers']['169']['invocation_id'], 'other')
        self.assertEqual(q['peers']['169']['remaining_home_and_control'], 2*capacity.G+peer162.CONTROL)
        self.assertEqual(q['peers']['169']['start_intent'], actual['hourly169_start_intent'])

    def test_wrong_phase_or_unmatched_lease(self):
        with self.assertRaisesRegex(ValueError, 'already issued'):
            capacity.calculate(self.peer, self.base, {'phase':'held'}, 'prestart', None, 0, {})
        with self.assertRaisesRegex(ValueError, 'different held'):
            capacity.calculate(self.peer, self.base, {'phase':'held','invocation_id':'other'}, 'postguard','ours',0,{})
        with self.assertRaisesRegex(ValueError, 'already charged'):
            capacity.calculate(self.peer, dict(self.base, split162={}), None, 'prestart', None, 0, {})
        self.assertEqual(capacity.report169(dict(phase='terminal', invocation_id='end')),
                         dict(phase='terminal',invocation_id='end'))

    def test_busy_donor_is_refused(self):
        self.assertFalse(capacity.drained(dict(ActiveState='active', MainPID='42', ControlPID='0')))
        self.assertFalse(capacity.drained(dict(ActiveState='failed', MainPID='0', ControlPID='0',ControlGroup='/new')))
        self.assertTrue(capacity.drained(dict(ActiveState='failed', MainPID='0', ControlPID='0',ControlGroup='')))


if __name__ == '__main__':
    unittest.main()
