"""Check the marginal charge, peer floors and booking sequence independently of a live replay."""
from copy import deepcopy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parent))
import after_ram170_admission as price

G = price.G
COMPARISON = dict(path=str(price.ROOT/"THIRD_CLOSED_COMPARISON.json"),sha256="a"*64)


def base():
    joint = dict(candidate_growth=36*G,producer_allowance=48*G,guard_sibling_allowance=G,
                 producer_quota_micros=6_000_000,guard_quota_micros=1_000_000)
    cost = dict(home_growth=8*G,original_home_growth=36*G,extra_ram=8*G,producer_memory_max=56*G,
                scratch_tmpfs=40*G,original_guard_still_budgeted=True,resident_ram_credit=0)
    native = dict(ram_gap170=None,after_ram170=None,ram170_residency=dict(realized_bytes=0),ram_retry_cost=cost,
                  raw=dict(joint=joint,terminal_tree_bounds=[338*G,338*G],guard_floor=680*G,assembly168={}))
    return dict(base_169=dict(native=native,home_margin=95*G,ram_margin=30*G),
                second_162_accounting=dict(resident_lower_bytes=5*G),epoch167_assembly=dict(phase="booked"),
                available_home=800*G,required_home=720*G,home_margin=80*G,guard_floor=700*G,
                available_ram=300*G,required_ram=275*G,ram_margin=25*G,fits=True,
                recorded_unix_seconds=100,fleet=dict(sha256="b"*64),writer=dict(sha256="c"*64),
                preparation_only=False,resource_credit_bytes=0)


class IncrementalBooking(unittest.TestCase):
    def test_substitution_and_unchanged_peers(self):
        q=base()
        clean=deepcopy(q)
        quote=price.rotated(q)
        self.assertEqual(q,clean)
        self.assertEqual((quote["required_home"]-q["required_home"],quote["required_ram"]-q["required_ram"]),(28*G,-8*G))
        self.assertEqual((quote["home_margin"],quote["ram_margin"],quote["guard_floor"]),(52*G,33*G,700*G))
        self.assertTrue(quote["fits"])

    def test_absolute_143_floor_is_checked_once_with_strict_headroom(self):
        q = base()
        q.update(epoch143_installed_guard_floor=790*G, epoch143_pre_floor_home_margin=80*G, home_margin=10*G)
        changed = price.rotated(q)
        self.assertEqual(changed["home_margin"], 10*G)
        self.assertTrue(changed["fits"])
        q.update(epoch143_installed_guard_floor=800*G, home_margin=0, fits=False)
        self.assertFalse(price.rotated(q)["fits"])
        q["home_margin"] = G
        with self.assertRaisesRegex(ValueError, "inconsistent independent 143"):
            price.rotated(q)

    def test_registered_held_profile_is_charged_only_once(self):
        q=base()
        with patch.object(price,"booking",return_value=None):
            fresh=price.account(deepcopy(q),None,None)
        first=price.candidate(fresh,"start",scope=price.SCOPE,closed=COMPARISON)
        self.assertEqual(first["candidate_170_growth_bytes"],36*G)
        row=dict(phase="held",interface=price.SCOPE,closed_comparison=COMPARISON,release=None)
        q["base_169"]["native"]["after_ram170"]=row
        with patch.object(price,"booking",return_value={"sha256":"1"*64}):
            registered=price.account(q,None,None)
        held=price.candidate(registered,"held",scope=price.SCOPE,closed=COMPARISON)
        self.assertEqual((first["required_home"],first["home_margin"],first["ram_margin"]),
                         (held["required_home"],held["home_margin"],held["ram_margin"]))
        self.assertEqual(registered["epoch167_assembly"],{"phase":"booked"})
        with self.assertRaisesRegex(ValueError,"already accounted"):
            price.account(registered,None,None)
        with self.assertRaisesRegex(ValueError,"already booked"):
            price.candidate(registered,"start",scope=price.SCOPE,closed=COMPARISON)

    def test_no_extra_home_space_and_realized_ram_cannot_pass(self):
        q=base()
        q["available_home"]=q["required_home"]+27*G
        q["home_margin"]=27*G
        self.assertFalse(price.rotated(q)["fits"])
        q["base_169"]["native"]["ram170_residency"]["realized_bytes"]=1
        with self.assertRaisesRegex(ValueError,"live predecessor"):
            price.rotated(q)

    def test_unfunded_guard_floor_and_global_tree_limit(self):
        with patch.object(price,"booking",return_value=None):
            q=price.account(base(),None,None)
        q["guard_floor"]=780*G
        result=price.candidate(q,"start",scope=price.SCOPE,closed=COMPARISON)
        self.assertEqual(result["required_home"],816*G)
        self.assertFalse(result["fits"])
        q["guard_floor"]=700*G
        q["base_169"]["native"]["raw"]["terminal_tree_bounds"]=[350*G,350*G]
        self.assertFalse(price.candidate(q,"start",scope=price.SCOPE,closed=COMPARISON)["fits"])

    def test_independent_negative_or_unknown_fit_is_preserved(self):
        q=base()
        q["base_169"]["home_margin"]=27*G
        self.assertFalse(price.rotated(q)["fits"])
        q=base()
        q["fits"]=False
        with self.assertRaisesRegex(ValueError,"additional shared admission condition"):
            price.rotated(q)
        q=base()
        q.update(required_ram=305*G,ram_margin=-5*G,fits=False)
        self.assertEqual(price.rotated(q)["ram_margin"],3*G)
        self.assertTrue(price.rotated(q)["fits"])


if __name__ == "__main__":
    unittest.main()
