"""Exercise the native scanner's shared-budget and audit-slice admission."""

import runpy
import unittest
from pathlib import Path


decision = runpy.run_path(str(Path(__file__).with_name("split_price.py")))["decision"]


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


if __name__ == "__main__":
    unittest.main()
