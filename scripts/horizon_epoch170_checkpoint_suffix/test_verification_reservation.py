"""Exercise simultaneous local audit, private verification and replay commitments."""
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import TestCase, main
from unittest.mock import patch

import verification_reservation as sizing


def need(value, reason):
    if not value:
        raise ValueError(reason)


class AuditTests(TestCase):
    def setUp(self):
        root = TemporaryDirectory()
        self.addCleanup(root.cleanup)
        self.slice = Path(root.name)/"slice"
        self.slice.mkdir()
        self.pool = Path(root.name)/"audits"
        self.pool.mkdir()
        for target, value in ((self.slice/"cpu.max", "1200000 100000"), (self.slice/"memory.swap.max", "0")):
            target.write_text(value)
        for name, quota in sizing.BASELINE.items():
            self.add_group(name, quota)
        for field, value in (("SLICE",self.slice), ("AUDIT_POOL",self.pool)):
            replacement=patch.object(sizing, field, value)
            replacement.start()
            self.addCleanup(replacement.stop)
        self.core = SimpleNamespace(need=need)

    def add_group(self, name, cpu):
        group = self.slice/name
        group.mkdir()
        for field, value in (("cgroup.procs", "123"), ("cpu.max", f"{cpu*100000} 100000"),
                             ("memory.max", str(2*sizing.GIB)), ("memory.swap.max", "0")):
            (group/field).write_text(value)
        return group

    def test_active_and_ready_audits_only_count_once(self):
        for epoch in (149, 150):
            (self.pool/str(epoch)).mkdir()
            (self.pool/str(epoch)/"READY").touch()
        (self.pool/"149/current").mkdir()
        (self.pool/"149/current/CONSUMED").touch()
        group = self.add_group("horizon-anza-ready-audit@149.service", 1)
        quote = sizing.audit_roster(self.core,{})
        self.assertEqual(quote["active"], [149])
        self.assertEqual(quote["additional_audit_ram"], 4*sizing.GIB)
        (group/"memory.swap.max").write_text("4096")
        with self.assertRaisesRegex(ValueError, "unrecognized audit"):
            sizing.audit_roster(self.core,{})

    def test_scan_occupies_the_existing_compiler_slot(self):
        name = "horizon-168-private-archive-verify-123.service"
        self.add_group(name, 1)
        with patch.object(sizing, "scanner", return_value={"owner": name}) as prove:
            quote = sizing.audit_roster(self.core, {})
            prove.assert_called_once_with(self.core, name, {})
            self.assertEqual(quote["scanner"], {"owner": name})
            self.assertEqual(quote["additional_audit_ram"], 0)
            self.add_group("horizon-168-private-archive-verify-124.service", 1)
            with self.assertRaisesRegex(ValueError, "multiple owners"):
                sizing.audit_roster(self.core, {})

    def test_unregistered_group_cannot_use_the_compiler_allowance(self):
        self.add_group("unexpected-archive-scan.service", 1)
        with self.assertRaisesRegex(ValueError, "unrecognized audit"):
            sizing.audit_roster(self.core,{})


class TurnoverTests(TestCase):
    def price(self, free):
        charge = dict(additional_home=1_510_182_912, additional_ram=128*sizing.MIB,
                      listener_evidence_within_miscellaneous=16*sizing.MIB, scanner_ram_from_serial=2*sizing.GIB)
        quote = dict(fits=True, fleet="current", charged_control_evidence=32*sizing.MIB,
                     guard_floor=1000, required_home=2000, historical_home_margin=free, home_margin=free,
                     required_ram=129, ram_margin=129*sizing.MIB)
        core = SimpleNamespace(need=need, current_fleet=lambda: ({}, "current"),
                               bound=lambda _: {"retry9_auxiliary_commitments":{}})
        with patch.object(sizing, "reservation", return_value=charge):
            return sizing.apply(core, quote)

    def test_keeps_full_outside_allowance_on_both_screens_and_guard(self):
        home = 1_510_182_912
        valid = self.price(home)
        self.assertTrue(valid["fits"])
        self.assertEqual(valid["historical_home_margin"], 0)
        self.assertEqual(valid["required_home"], home+2000)
        self.assertEqual(valid["guard_floor"], home+1000)
        self.assertEqual(valid["ram_margin"], sizing.MIB)
        self.assertEqual(valid["required_ram"], 128*sizing.MIB+129)
        self.assertFalse(self.price(home-1)["fits"])


if __name__ == "__main__":
    main()
