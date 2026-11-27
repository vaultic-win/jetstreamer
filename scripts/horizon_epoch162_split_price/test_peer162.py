import unittest
from unittest.mock import patch

import peer162 as peer


class PeerPrice(unittest.TestCase):
    def setUp(self):
        self.base = dict(protected_home=100 * peer.G, remaining_output=7 * peer.G,
                         guard_floor=100 * peer.G + peer.CONTROL, available_home=120 * peer.G,
                         fleet={}, ram_margin=10, started_unix_seconds=5)
        self.base['required_home'] = self.base['guard_floor'] + self.base['remaining_output']
        self.base['home_margin'] = self.base['available_home'] - self.base['required_home']
        self.base['fits'] = True

    def test_joint_growth_and_control(self):
        result = peer.geometry(self.base, 6 * peer.G, peer.CONTROL, 0)
        self.assertEqual(result['guard_floor'], 100 * peer.G + 2 * peer.CONTROL)
        self.assertEqual(result['required_home'], result['guard_floor'] + 13 * peer.G)

    def test_higher_existing_floor_survives(self):
        result = peer.geometry(self.base, peer.IMAGE, peer.CONTROL, 110 * peer.G)
        self.assertEqual(result['required_home'], 125 * peer.G)
        self.assertEqual(result['home_margin'], -5 * peer.G)

    def test_charge_retains_worse_of_two_samples(self):
        row = dict(phase='worker', sampled_at=4, realized_ram=30,
                   disk=dict(floor=102 * peer.G, remaining=4 * peer.G))
        later = dict(row, realized_ram=20, disk=dict(floor=102 * peer.G, remaining=3 * peer.G))
        with patch.object(peer, 'bound', return_value={}), patch.object(peer, 'recheck', return_value=later):
            result = peer.charge(self.base, row)
            self.assertEqual(result['required_home'], 113 * peer.G)
            self.assertEqual(result['ram_margin'], 30)
            self.assertEqual(peer.charge(self.base, dict(row, sampled_at=6))['realized_162_ram'], 0)
            with self.assertRaisesRegex(ValueError, 'duplicate'):
                peer.charge(result, row)

    def test_missing_and_drained_peer(self):
        self.assertIs(peer.charge(self.base, None), self.base)
        row = dict(phase='terminal')
        with patch.object(peer, 'bound', return_value={}), patch.object(peer, 'recheck', return_value=row):
            result = peer.charge(self.base, row)
        self.assertEqual(result['realized_162_ram'], 0)
        self.assertEqual(result['required_home'], 115 * peer.G + 2 * peer.CONTROL)

    def test_reject_invalid_base_or_excess_image(self):
        with self.assertRaisesRegex(ValueError, 'HOME shape'):
            peer.geometry(dict(self.base, home_margin=0), 0, peer.CONTROL, 0)
        with self.assertRaisesRegex(ValueError, 'HOME shape'):
            peer.geometry(self.base, peer.IMAGE + 1, peer.CONTROL, 0)

    def test_enrollment_changing_during_quote(self):
        with patch.object(peer, 'current', return_value={'phase': 'held'}):
            with self.assertRaisesRegex(ValueError, 'crossed enrollment'):
                peer.recheck({}, None)


if __name__ == '__main__':
    unittest.main()
