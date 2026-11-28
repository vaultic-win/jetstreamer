"""Regression coverage for three simultaneously spendable image budgets and one 166 compute donor."""
from copy import deepcopy
import unittest

from third162_account import CONTROL, G, OUTPUT, compare_samples, occupant, protect_hourly_170, protect_live, reserve
from third162_price import MEASURED, geometry


def snapshot(booked=None):
    return dict(phase="precharged",owner=None,enrolled=True,floor=0,enrollment=booked,
                custody=dict(terminal="second",archived_failures="two failed gates"),remaining=OUTPUT)


def whole():
    ready = 800*G
    return dict(second_162_accounting=dict(phase="terminal",remaining_output=OUTPUT,retained_control=CONTROL,
                                            unreleased_predecessor="two failed gates"),
                prospective_162_interval_two=dict(additional_home=OUTPUT+CONTROL),resource_credit_bytes=0,
                donor_compute=dict(usable_166_ram=63*G,usable_166_cpu_micros=5_750_000),
                base_169=dict(native=dict(raw=dict(guarded_hourly_remaining=64*G,guard_floor=670*G))),
                after_floor170_accounting=dict(replacement_selected=False,home_growth=8*G,scope="hourly",intent=None),
                after_ram170_accounting=dict(phase="booked",home_growth_bytes=36*G),required_home=ready,
                available_home=ready+100*G,home_margin=100*G,required_ram=230*G,available_ram=256*G,
                ram_margin=26*G,fits=True,guard_floor=780*G,epoch143_remaining_replay_home=64*G,
                observed_sibling_guard_floors=[670*G,680*G])


def calculated(row=None):
    sample = row or snapshot()
    q = reserve(whole(),sample,sample,not sample["enrollment"])
    q["epoch143_protected_sibling_floor"] = max(q["required_home"]-64*G,*q["observed_sibling_guard_floors"])
    q["epoch143_protected_runway_required_home"] = max(q["required_home"],q["epoch143_protected_sibling_floor"]+64*G)
    return protect_live(q)


def priced(q, held=None):
    return geometry(q,"postguard" if held else "prestart",held,q["available_home"],q["available_ram"],MEASURED)


class Third162(unittest.TestCase):
    def test_booking_and_predecessors(self):
        before = whole()
        out = reserve(deepcopy(before),snapshot(),snapshot(),False)
        self.assertEqual(out["required_home"],before["required_home"])
        self.assertFalse(out["third_162_accounting"]["charged"])
        joined = calculated()
        self.assertEqual(joined["required_home"]-before["required_home"],OUTPUT+CONTROL)
        self.assertEqual(joined["required_ram"],before["required_ram"])
        self.assertEqual(joined["second_162_accounting"],before["second_162_accounting"])
        with self.assertRaisesRegex(ValueError,"closed custody"):
            reserve(joined,snapshot(),snapshot(),True)

    def test_all_protected_working_sets_and_pinned_drawdown(self):
        q = calculated()
        original = deepcopy(q)
        answer = priced(q)
        self.assertEqual(q,original)
        self.assertTrue(answer["fits"])
        self.assertGreaterEqual(answer["required_home"]-answer["guard_floor"],(64+36+3)*G)
        self.assertGreaterEqual(q["available_home"]-answer["required_home"],MEASURED)
        q["fits"] = False
        self.assertFalse(priced(q)["fits"])
        q["fits"] = True
        q["available_ram"] = q["required_ram"]-1
        self.assertFalse(priced(q)["fits"])
        q = calculated()
        with self.assertRaisesRegex(ValueError,"drawdown"):
            geometry(q,"prestart",None,q["available_home"],q["available_ram"],0)
        q["observed_sibling_guard_floors"].append(850*G)
        self.assertFalse(priced(protect_live(q))["fits"])

    def test_170_turnover_only_when_issued_and_selected(self):
        q = calculated()
        q["after_floor170_accounting"].update(replacement_selected=True)
        with self.assertRaisesRegex(ValueError,"170"):
            priced(q)
        q["after_floor170_accounting"]["intent"] = "exact native intent"
        q["after_ram170_accounting"]["superseded_by"] = "hourly"
        self.assertEqual(priced(q)["protected_170_runway"],8*G)
        new170 = dict(guard_floor=790*G,required_home=862*G,protected_143_remaining=64*G,candidate_170_growth_bytes=8*G,
                      fits=True,available_home=862*G+MEASURED,home_margin=0,shared_drawdown_allowance=MEASURED)
        self.assertFalse(protect_hourly_170(new170,q)["fits"])
        self.assertEqual(protect_hourly_170(new170,q)["required_home"],865*G)

    def test_held_floor_identity_and_no_duplicate_owner(self):
        q = calculated()
        first = priced(q)
        row = dict(snapshot("enrollment"),phase="held",floor=first["guard_floor"],owner=dict(
            invocation_id="the-held",phase="held",release=None),remaining=OUTPUT-65536)
        q = calculated(row)
        self.assertTrue(priced(q,"the-held")["fits"])
        with self.assertRaisesRegex(ValueError,"held"):
            priced(q,"other")
        with self.assertRaisesRegex(ValueError,"changed"):
            compare_samples(row,dict(row,enrollment="other"))
        with self.assertRaisesRegex(ValueError,"two 162"):
            occupant(dict(owner=dict(phase="worker",unit=dict(Id="earlier"))),dict(owner=None))
        q["observed_sibling_guard_floors"].append(first["guard_floor"]+1)
        self.assertFalse(priced(q,"the-held")["fits"])

    def test_measured_drawdown_at_exact_fit_and_one_byte_short(self):
        q = calculated()
        base = priced(q)["minimum_fair_floor"]+103*G+MEASURED
        q["available_home"] = max(q["required_home"]+MEASURED,base)
        q["home_margin"] = q["available_home"]-q["required_home"]
        self.assertEqual(priced(q)["home_margin"],0)
        self.assertTrue(priced(q)["fits"])
        q["available_home"] -= 1
        q["home_margin"] -= 1
        self.assertFalse(priced(q)["fits"])


if __name__ == "__main__":
    unittest.main()
