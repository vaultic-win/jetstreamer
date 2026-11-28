"""Check simultaneous split outputs against each guard's actual floor."""
from unittest import TestCase
from unittest.mock import Mock
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

import following_peers as pricing


class SplitPeerCosts(TestCase):
    def test_absent_terminal_and_live_outputs(self):
        g, m = pricing.G, pricing.M
        self.assertEqual(pricing.peer_disk(None, 0), (0,0,0))
        self.assertEqual(pricing.peer_disk({'phase':'terminal'},8*g), (0,8*g,64*m))
        for phase in ('held','bootstrap','worker'):
            row = dict(phase=phase, disk=dict(floor=120*g,remaining=3*g,fixed_control=64*m))
            self.assertEqual(pricing.peer_disk(row,8*g), (120*g,3*g,64*m))
        row['disk']['remaining'] = 8*g+1
        with self.assertRaisesRegex(ValueError,'guarded split output'):
            pricing.peer_disk(row,8*g)

    def test_both_outputs_above_highest_floor(self):
        g, m = pricing.G, pricing.M
        basis = dict(guard_floor=100*g,required_home=110*g,available_home=145*g,historical_home_margin=50*g,
                     ram_margin=3*g,available_ram=20*g,phase='start',terminal_tree_bounds=[200*g,201*g],
                     candidate_170_growth_bytes=10*g)
        disks = [(105*g,5*g,64*m),(119*g,8*g,64*m)]
        q = pricing.amounts(basis,disks,2*g,g,2*g)
        self.assertEqual((q['guard_floor'],q['required_home'],q['home_margin'],q['ram_margin']),
                         (132*g,142*g,3*g,4*g))
        with self.assertRaisesRegex(ValueError,'duplicate'):
            pricing.amounts(basis|{'split_peers':{}},disks,2*g,g,2*g)
        self.assertFalse(pricing.amounts(basis|{'available_home':141*g},disks,2*g,g,2*g)['fits'])
        self.assertFalse(pricing.amounts(basis|{'phase':'start','terminal_tree_bounds':[379*g,380*g]},disks,0,0,0)['fits'])

    def test_successive_writer_versions_must_be_contiguous(self):
        with TemporaryDirectory() as tmp:
            d = Path(tmp)
            for version in (48,49,50,51):
                (d/f'FAILED166_CADENCE_V{version}_ACTIVE.json').touch()
            self.assertEqual(pricing.writer_versions(d,49),[49,50,51])
            (d/'FAILED166_CADENCE_V50_ACTIVE.json').unlink()
            with self.assertRaisesRegex(ValueError,'noncontiguous'):
                pricing.writer_versions(d,49)

    def test_holding_serial_rejects_duplicate_m12(self):
        support = SimpleNamespace(active_units=Mock(return_value=set()))
        previous = Mock(return_value={'existing':True})
        self.assertEqual(pricing.holding(None,support,previous),{'existing':True})
        def need(ok, reason):
            if not ok:
                raise ValueError(reason)
        support.active_units.return_value = {'horizon-closed186-park-m12-8.service','old-holding'}
        with self.assertRaisesRegex(ValueError,'several owners'):
            pricing.holding(SimpleNamespace(need=need),support,previous)
