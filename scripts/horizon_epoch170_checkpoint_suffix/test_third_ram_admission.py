"""Test full-output headroom independently of the armed 170 stop threshold."""
import ast
from pathlib import Path
import unittest
from types import SimpleNamespace

import fourth169_residency as peer


def selected(name, path):
    tree = ast.parse(Path(__file__).with_name(path).read_text())
    fn, = (n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == name)
    ns = {}
    exec(compile(ast.Module(body=[fn], type_ignores=[]), path, "exec"), ns)
    return ns[name]


class ThirdRamAdmission(unittest.TestCase):
    def test_transient_headroom_does_not_raise_the_stop_floor(self):
        apply = selected("sustainable", "ram170_third_price.py")
        funded = selected("funded_guard", "bounded_successor.py")
        fit = dict(fits=True, home_margin=200, guard_floor=1000, required_home=1100,
                   candidate_170_growth_bytes=100, joint={"candidate_growth":100}, assembly168={},
                   terminal_tree_bounds=[50,58], available_home=1300)
        apply(fit,200)
        self.assertTrue(fit["fits"])
        self.assertEqual(fit["home_margin"],0)
        self.assertTrue(funded(fit,1000,150))
        self.assertFalse(funded(fit,1001,150))
        self.assertFalse(funded(fit,1000,151))
        self.assertEqual((fit["guard_floor"],fit["required_home"]),(1000,1100))
        with self.assertRaises(ValueError):
            apply(fit,200)

    def test_temporary_shortfall_can_be_retried_on_a_fresh_quote(self):
        apply = selected("sustainable", "ram170_third_price.py")
        for cash,base,expected in ((199,True,False),(201,True,True),(201,False,False)):
            fit=dict(fits=base,home_margin=cash)
            apply(fit,200)
            self.assertEqual((fit["fits"],fit["home_margin"]),(expected,cash-200))


class Fourth169Residency(unittest.TestCase):
    def setUp(self):
        def need(ok, message):
            if not ok:
                raise ValueError(message)
        self.core = SimpleNamespace(need=need)
        self.historical = dict(phase="terminal")
        self.actor = dict(phase="worker", invocation="iid", release="grant", intent="intent", guard_plan="plan")
        self.native = dict(planned_169_retry=dict(fourth_scope=peer.SCOPE,additional_ram=8<<30),
                           stopped_169_compute_handoff=dict(retained_159_ram=48<<30), independent_retry169=self.actor,
                           resource_credit_bytes=0, required_ram=100<<30,available_ram=95<<30,ram_margin=-(5<<30))
        self.sample = dict(intent="intent",release="grant",plan="plan",scope=peer.SCOPE,invocation="iid",
                           timer="timer",processes=[(1,2),(3,4)],mount="scratch",realized=9<<30)

    def test_one_lower_resident_measurement_preserves_full_guard_and_future_usage(self):
        peer.apply(self.core,self.native,self.sample,dict(self.sample,realized=7<<30),self.historical)
        self.assertEqual(self.native["ram_margin"],2<<30)
        self.assertEqual(self.native["required_ram"],93<<30)
        self.assertEqual(self.native["fourth169_residency"]["remaining_bytes"],49<<30)
        self.assertTrue(self.native["fourth169_residency"]["guard_separately_reserved"])
        with self.assertRaises(ValueError):
            peer.apply(self.core,self.native,self.sample,self.sample,self.historical)

    def test_owners_limits_and_mounts_are_stable_across_measurements(self):
        for field in ("intent","release","plan","scope","invocation","timer","processes","mount"):
            with self.subTest(field=field), self.assertRaises(ValueError):
                peer.apply(self.core,self.native,self.sample,dict(self.sample, **{field:"different"}),self.historical)
        with self.assertRaises(ValueError):
            peer.apply(self.core,self.native,self.sample,dict(self.sample,realized=peer.LIMIT+1),self.historical)
        with self.assertRaises(ValueError):
            peer.apply(self.core,self.native,self.sample,self.sample,dict(phase="worker"))

    def test_held_and_unissued_keep_the_full_limit(self):
        for phase in ("held","bootstrap","absent"):
            native=dict(self.native,independent_retry169=None if phase=="absent" else dict(self.actor,phase=phase))
            with self.assertRaises(ValueError):
                peer.apply(self.core,native,self.sample,self.sample,self.historical)
            peer.apply(self.core,native,None,None,self.historical)
            self.assertEqual(native["fourth169_residency"]["remaining_bytes"],peer.LIMIT)
            self.assertEqual(native["ram_margin"],-(5<<30))


if __name__ == "__main__":
    unittest.main()
