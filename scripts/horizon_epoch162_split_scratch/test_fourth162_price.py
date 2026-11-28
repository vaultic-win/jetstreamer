"""Regressions for the 162 turnover and the simultaneous fourth 162 and compact 169 lane budgets."""
from copy import deepcopy
from pathlib import Path
import unittest

from fourth162_price import next_price
from fourth162_writer import router
from test_third162_price import G, MEASURED, OUTPUT, calculated

HERE = Path(__file__).resolve().parent
module = {}
exec(compile(next_price((HERE/"third162_price.py").read_text()),"fourth162_price.py","exec"),module)


def roster():
    old = calculated()
    old["base_169"]["native"]["raw"]["guard_floor"] = 9_500*G
    old["guard_floor"] = 9_680*G
    old["required_home"] = 9_800*G
    old["available_home"] = 10_000*G
    old["home_margin"] = 200*G
    old["epoch143_protected_sibling_floor"] = old["required_home"]-64*G
    old["epoch143_protected_runway_required_home"] = old["required_home"]
    old["fourth_162_accounting"] = deepcopy(old["third_162_accounting"])
    old["third_162_accounting"]["phase"] = "terminal"
    old["adjacent_169_accounting"] = dict(charged=True,phase="worker",remaining_output=4*G)
    return old


def geometry(q,proposal=False,held=None):
    return module["geometry"](q,"postguard" if held else "prestart",held,q["available_home"],q["available_ram"],MEASURED,proposal=proposal)


class FourthPlacement(unittest.TestCase):
    def test_two_lanes_charge_their_simultaneous_growth(self):
        q = roster()
        result = geometry(q)
        self.assertTrue(result["fits"])
        self.assertEqual(result["protected_169_runway"],4*G)
        self.assertGreaterEqual(result["required_home"]-result["guard_floor"],(64+36+4+3)*G)
        q["adjacent_169_accounting"]["phase"] = "terminal"
        self.assertEqual(geometry(q)["protected_169_runway"],0)

    def test_exact_joint_headroom_and_one_byte_short(self):
        q = roster()
        fair = geometry(q)["minimum_fair_floor"]
        q["available_home"] = max(q["required_home"],fair+107*G)+MEASURED
        q["home_margin"] = q["available_home"]-q["required_home"]
        self.assertTrue(geometry(q)["fits"])
        self.assertEqual(geometry(q)["home_margin"],0)
        q["available_home"] -= 1
        q["home_margin"] -= 1
        self.assertFalse(geometry(q)["fits"])

    def test_unenrolled_arithmetic_is_never_a_native_start(self):
        q = roster()
        q["fourth_162_accounting"]["writer_enrolled"] = False
        self.assertTrue(geometry(q,proposal=True)["fits"])
        with self.assertRaises(ValueError):
            geometry(q)
        q["fourth_162_accounting"]["enrollment"] = "existing owner"
        with self.assertRaises(ValueError):
            geometry(q,proposal=True)

    def test_mismatched_scratch_budget_and_foreign_held_owner(self):
        q = roster()
        q["adjacent_169_accounting"]["remaining_output"] += 1
        with self.assertRaisesRegex(ValueError,"unbounded"):
            geometry(q)
        q = roster()
        fair = geometry(q)["guard_floor"]
        q["fourth_162_accounting"].update(phase="held",enrollment="booking",owner=dict(phase="held",invocation_id="our",release=None),observed_floor=fair)
        with self.assertRaisesRegex(ValueError,"held"):
            geometry(q,held="other")
        q["observed_sibling_guard_floors"].append(fair+1)
        self.assertFalse(geometry(q,held="our")["fits"])

    def test_custody_and_status_keys_belong_to_adjacent_intervals(self):
        code = router((HERE/"third162_route.py").read_text())
        self.assertIn('import third162_route as prior',code)
        self.assertIn('= "private162_fourth_held"',code)
        self.assertIn('old.get("private162_third_held")',code)
        self.assertIn('row["unit"]["Id"] == prior.UNIT',code)
        self.assertIn('bounds=(70_004_938,70_011_988)',code)
        self.assertNotIn('private162_second_reserved_held',code)


if __name__ == "__main__":
    unittest.main()
