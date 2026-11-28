"""Keep the original donor charge until the compact fourth writer actually selects it."""
from copy import deepcopy
import unittest

from compact_fourth_turnover import G, replace_cap

def require(value,reason):
    if not value:
        raise ValueError(reason)

class ExclusiveCap(unittest.TestCase):
    def setUp(self):
        replace_cap.__globals__.update(compare_samples=lambda a,b:require(a==b,"changed sample"),
            TERMINAL={"path":"third"},INTERFACE={"path":"compact"},QUALIFICATION={"path":"kernel"})
        self.native=dict(required_ram=200*G,available_ram=194*G,ram_margin=-6*G,resource_credit_bytes=0)
        self.prior=dict(phase="terminal",owner=dict(invocation_id="prior"))
        self.row=dict(phase="precharged",enrolled=True,enrollment=None,owner=None,resident=0,
                      custody=dict(terminal={"path":"third"},invocation_id="prior"))

    def apply(self):
        return replace_cap(self.native,self.row,deepcopy(self.row),self.prior)

    def test_selected_and_single_charge(self):
        self.apply()
        self.assertEqual(self.native["required_ram"],192*G)
        self.assertEqual(self.native["ram_margin"],2*G)
        self.assertEqual(self.native["fourth162_effective_cap"]["producer_max"],54*G)
        self.assertRaises(ValueError,self.apply)

    def test_old_writer_keeps_its_charge(self):
        self.row["enrolled"]=False
        self.apply()
        self.assertEqual(self.native["required_ram"],200*G)
        self.assertEqual(self.native["fourth162_effective_cap"]["producer_max"],62*G)

    def test_foreign_terminal_and_live_legacy_refused(self):
        self.prior["phase"]="worker"
        self.assertRaises(ValueError,self.apply)
        self.prior["phase"]="terminal"
        self.row.update(enrolled=False,phase="worker",owner={"invocation_id":"foreign"})
        self.assertRaises(ValueError,self.apply)


if __name__=="__main__":
    unittest.main()
