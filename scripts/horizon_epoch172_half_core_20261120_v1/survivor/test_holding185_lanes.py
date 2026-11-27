"""Exercise a lane-k start and handback alongside the retained lane-l event."""
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import unittest

from test_full170_retry5_cadence import cycle_functions, need


class HoldingLanes(unittest.TestCase):
    def setUp(self):
        self.docs = {}
        self.fleet = {'actual_active_holding_transfers': []}
        self.cycle = SimpleNamespace(fleet_ref={'path': '/prior/fleet.json'},
                                     sample_ref={'path': '/samples/one.json'},
                                     paths={'out': Path('/sample')})
        self.install = cycle_functions(
            'install_holding185_result', need=need, checked=lambda ref: self.docs[ref['path']],
            bound=lambda path: {'path': str(path)}, durable=lambda path, v: self.docs.update({str(path): v}),
            Path=Path, json=json, hashlib=hashlib)['install_holding185_result']

    def apply(self, lane, stage):
        date = '20261127' if lane == 'k' else '20261125'
        ticket = {'admission':lane, 'start':lane}
        self.install(self.cycle, self.fleet, {
            'holding_reservation':ticket, 'active_transfer':ticket if stage == 'copying' else None,
            'observation':{'unit':f'horizon-closed185-lane{lane}-park-{date}-v1.service',
                           'schema':f'horizon-epoch185-lane{lane}-holding-observation-v1',
                           'stage':stage, 'custody':lane, 'resource_credit_bytes':0}}, lane)

    def test_serial_handback_preserves_both_event_generations(self):
        self.apply('l', 'custody-recorded')
        prior_l = self.fleet['epoch185_lanel_holding']
        self.apply('k', 'copying')
        self.assertEqual(self.fleet['actual_active_holding_transfers'], [self.fleet['epoch185_lanek_holding']])
        self.cycle.fleet_ref = {'path':'/sample/fleet.json'}
        self.cycle.paths['out'] = Path('/next')
        self.apply('l', 'custody-recorded')
        self.apply('k', 'custody-recorded')
        self.assertEqual(self.fleet['actual_active_holding_transfers'], [])
        self.assertEqual(self.docs[prior_l['path']]['result'],
                         self.docs[self.fleet['epoch185_lanel_holding']['path']]['result'])

    def test_rejects_overlapping_transfers(self):
        self.apply('l', 'copying')
        with self.assertRaisesRegex(ValueError, 'overlapping'):
            self.apply('k', 'copying')
        self.assertNotIn('epoch185_lanek_holding', self.fleet)


if __name__ == '__main__':
    unittest.main()
