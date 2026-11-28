"""Exercise the native scanner's shared-budget and audit-slice admission."""

import runpy
import os
import unittest
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch


pricing = runpy.run_path(str(Path(__file__).with_name("split_price.py")))
decision = pricing["decision"]
choose_phase = pricing["choose_phase"]
G, M = 1 << 30, 1 << 20
registry = runpy.run_path(str(Path(__file__).with_name("dispatch.py")))["pricing_registration"]


class Admission(unittest.TestCase):
    def setUp(self):
        self.roster = dict(fits=True,home_margin=9000000000,ram_margin=3<<30,guard_floor=9650000000000)
        self.slice = dict(fits=True,child_quotas={"auditor":1000000},pending=[],additional_audit_ram=2<<30)

    def test_same_serial_slot(self):
        self.assertTrue(decision(self.roster,self.slice,dict(self.slice)))

    def test_prospective_disk_is_charged(self):
        self.assertFalse(decision(dict(self.roster, fits=False,home_margin=-1),self.slice,self.slice))

    def test_refuses_incoherent_positive_fit(self):
        for field in ("home_margin","ram_margin"):
            with self.subTest(field=field), self.assertRaisesRegex(ValueError,"unfunded"):
                decision(dict(self.roster,**{field:-1}),self.slice,self.slice)

    def test_refuses_slice_change(self):
        for field, value in (("pending",["audit"]),("additional_audit_ram",0),("child_quotas",{})):
            with self.subTest(field=field), self.assertRaisesRegex(ValueError,"ownership changed"):
                decision(self.roster,self.slice,dict(self.slice,**{field:value}))

    def test_refuses_full_slice(self):
        self.assertFalse(decision(self.roster,self.slice,dict(self.slice,fits=False)))

    def test_registration_selection(self):
        for name in ("SPLIT_PRICE_DEPLOYMENT_V2.json","SPLIT_PRICE_DEPLOYMENT_V3.json"):
            with patch.dict(os.environ, {"HORIZON_168_PRICE_REGISTRATION":name}):
                self.assertEqual(registry().name,name)
        for name in ("../SPLIT_PRICE_DEPLOYMENT_V2.json","/tmp/other","SPLIT_PRICE_DEPLOYMENT_V02.json"):
            with patch.dict(os.environ, {"HORIZON_168_PRICE_REGISTRATION":name}), self.assertRaises(ValueError):
                registry()


class PhasePrice(unittest.TestCase):
    def setUp(self):
        funding = dict(original_actor_bytes=68*G, original_cpu_micros=9_000_000,
                       both_handlers_and_receivers_ram=4608*M, both_handlers_and_receivers_cpu=3_000_000,
                       passive_199_control_ram=512*M, passive_199_control_cpu=250_000,
                       usable_166_ram=63*G, usable_166_cpu_micros=5_750_000)
        native = {}
        for name in ("horizon-166-committed-event.path", "horizon-166-retry10-publication.path"):
            native[name] = dict(Id=name, Job="", ActiveState="active", SubState="waiting",
                                Paths="/private/fixture (PathExists)", InvocationID=name, Triggers=name[:-4]+"service")
        for name in ("horizon-166-committed-event.service", "horizon-199200-joint-cached-controller-20261121-v1.service",
                     "horizon-qualify-199200-reservation-20261121-v1.service"):
            native[name] = dict(Id=name, Job="", ActiveState="inactive", SubState="dead", ControlGroup="", MainPID="0")
        self.proof = dict(donor=funding, native=deepcopy(native), retained_166_disk_bytes=288*G)
        self.q = dict(existing_162=None, prospective_162=True, fits=False, home_margin=-5*G,
                      ram_margin=-4*G, guard_floor=900*G, required_home=915*G, available_home=910*G,
                      remaining_162_home=8*G, realized_162_ram=0, native_donor=native,
                      donor=pricing["DONOR"], donor_compute=funding)
        self.base = self.q["base_169"] = dict(available_home=910*G, required_home=907*G,
                      remaining_output=7*G, protected_home=899*G, guard_floor=900*G, home_margin=3*G,
                      ram_margin=-4*G, native=dict(home_margin=10*G,historical_home_margin=20*G),
                      observed_actors=[{"epoch":n} for n in (146,167,169,170,172)],
                      actor=dict(phase="worker",disk=dict(floor=900*G, remaining=7*G)))

    def test_only_actual_deficit_is_borrowed(self):
        p = choose_phase(self.q,self.proof)
        self.assertTrue(p["fits"])
        self.assertEqual(p["temporary_166_ram"],4*G + pricing["ENTRY_RAM"])
        self.assertEqual(p["prospective_162_home_deferred"],8*G)
        self.assertEqual(p["required_home"],907*G)
        self.assertEqual(p["guard_floor"],900*G)

    def test_issued_162_keeps_whole_quote_even_when_negative(self):
        self.q.update(existing_162={"phase":"held"},prospective_162=False)
        p = choose_phase(self.q,self.proof)
        self.assertFalse(p["fits"])
        self.assertEqual((p["mode"],p["temporary_166_ram"],p["prospective_162_home_deferred"]),("simultaneous",0,0))

    def test_no_loan_when_both_fit(self):
        self.q.update(fits=True,home_margin=G,ram_margin=G)
        self.assertEqual(choose_phase(self.q,self.proof)["mode"],"simultaneous")

    def test_unrecognized_or_changed_donor(self):
        self.q["donor"] = dict(pricing["DONOR"],sha256="0"*64)
        with self.assertRaisesRegex(ValueError,"unrecognized"):
            choose_phase(self.q,self.proof)
        self.q["donor"] = pricing["DONOR"]
        self.q["native_donor"].pop("horizon-166-committed-event.path")
        with self.assertRaisesRegex(ValueError,"incomplete"):
            choose_phase(self.q,self.proof)

    def test_pending_and_active_donor_refused(self):
        row = self.q["native_donor"]["horizon-166-committed-event.service"]
        row["Job"] = "99"
        with self.assertRaisesRegex(ValueError,"pending"):
            choose_phase(self.q,self.proof)
        row.update(Job="",ActiveState="active")
        with self.assertRaisesRegex(ValueError,"active receiver"):
            choose_phase(self.q,self.proof)

    def test_retains_sibling_floor_and_historical_limit(self):
        self.base["actor"]["disk"]["floor"] += 1
        with self.assertRaisesRegex(ValueError,"169 guard"):
            choose_phase(self.q,self.proof)
        self.base["actor"]["disk"]["floor"] -= 1
        self.base["native"]["historical_home_margin"] = -1
        self.assertFalse(choose_phase(self.q,self.proof)["fits"])

    def test_five_owner_disk_and_donor_capacity_limits(self):
        self.base["available_home"] = self.q["available_home"] = self.base["required_home"]-1
        self.base["home_margin"] = -1
        self.assertFalse(choose_phase(self.q,self.proof)["fits"])
        self.base.update(available_home=910*G, home_margin=3*G,ram_margin=-63*G)
        self.q.update(available_home=910*G,ram_margin=-63*G)
        p = choose_phase(self.q,self.proof)
        self.assertFalse(p["fits"])
        self.assertEqual(p["temporary_166_ram"],63*G)


if __name__ == "__main__":
    unittest.main()
