"""Exercise the complete 143 runway, mutable tree cap and peer fluctuation in the hourly 170 fit."""
from copy import deepcopy
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parent))
from after_floor170_price import geometry, G, HOME, CONTROL

DRAWDOWN = 20_011_974_656


def roster():
    required = 800*G
    remaining = 64*G
    raw = dict(guard_floor=690*G,guarded_hourly_remaining=remaining,terminal_tree_bounds=[338*G,338*G],
               joint={},assembly168={})
    return dict(base_169=dict(native=dict(raw=raw)), resource_credit_bytes=0,available_home=850*G,
                guard_floor=780*G,required_home=required,available_ram=300*G,required_ram=280*G,ram_margin=20*G,
                home_margin=50*G,epoch143_remaining_replay_home=remaining,observed_sibling_guard_floors=[720*G],
                epoch143_protected_sibling_floor=required-remaining,epoch143_protected_runway_required_home=required,fits=True)


class GuardGeometry(unittest.TestCase):
    def test_both_working_sets_and_drawdown_remain_available(self):
        whole=roster()
        original=deepcopy(whole)
        quoted=geometry(whole,DRAWDOWN)
        self.assertEqual(whole,original)
        self.assertEqual(quoted["guard_floor"] + 64*G + HOME,quoted["required_home"])
        self.assertEqual(quoted["home_margin"],50*G-DRAWDOWN)
        self.assertTrue(quoted["fits"])

    def test_actual_peer_floor_protects_both_remaining_working_sets(self):
        whole=roster()
        whole["observed_sibling_guard_floors"]=[769*G]
        whole["epoch143_protected_sibling_floor"]=769*G
        whole["epoch143_protected_runway_required_home"]=833*G
        got=geometry(whole,DRAWDOWN)
        self.assertEqual(got["guard_floor"],769*G)
        self.assertEqual(got["required_home"],841*G)
        self.assertFalse(got["fits"])

    def test_existing_143_floor_and_tree_cap(self):
        whole=roster()
        whole["epoch143_installed_guard_floor"]=780*G
        got=geometry(whole,DRAWDOWN)
        self.assertEqual(got["guard_floor"],780*G)
        self.assertFalse(got["fits"])
        whole=roster()
        whole["base_169"]["native"]["raw"]["terminal_tree_bounds"]=[380*G,380*G]
        got=geometry(whole,DRAWDOWN)
        self.assertEqual(got["guard_cap"],384*G)
        self.assertFalse(got["fits"])
        whole["base_169"]["native"]["raw"]["terminal_tree_bounds"]=[376*G,376*G]
        got=geometry(whole,DRAWDOWN)
        self.assertTrue(got["fits"])
        self.assertEqual(got["guard_cap"],384*G-CONTROL)

    def test_foreign_cutoffs_or_other_failed_gates_are_preserved(self):
        whole=roster()
        whole["fits"]=False
        self.assertFalse(geometry(whole,DRAWDOWN)["fits"])
        with self.assertRaisesRegex(ValueError,"drawdown"):
            geometry(whole,0)
        whole["epoch143_remaining_replay_home"]-=G
        with self.assertRaisesRegex(ValueError,"runway"):
            geometry(whole,DRAWDOWN)


if __name__ == "__main__":
    unittest.main()
