import unittest

from homefloor_fit import validate_public


class PublicObligationTest(unittest.TestCase):
    def setUp(self):
        self.witness = {"native": {"ActiveState": "active", "InvocationID": "owner"},
                        "shared_slice": {"MemoryMax": "25769803776"}}
        self.paid = {"output_budget": {"sha256": "budget"}, "maximum_host_allocation_bytes": 256 << 20,
                     "remaining_archive_growth_bytes": 0, "resident_archive_bytes": 0,
                     "host_allocation_groups": [{"observed_over_cap_bytes": 0}]}
        self.old = [{"pid": 10, "start_ticks": 100, "range": [101, 135]}]
        self.current = [{"pid": 11, "start_ticks": 101, "range": [148, 156]}]
        self.fleet = {
            "active_ready_range_audit_obligation": {
                "current_observation": "audit", "current_storage": self.paid,
                "maximum_output_allocation_bytes": 256 << 20, "archive_staging_bytes": 0,
            },
            "current_home_cycle_capacity": "home",
            "current_audit_progress": {"observation": "audit"},
        }
        self.evidence = {
            "audit": {"active_ready_workers": self.old},
            "home": {"audit_storage": self.paid, "audit_owner_witness": self.witness},
        }

    def validate(self, workers, *, paid=None, witness=None, fresh_workers=True):
        validate_public(self.fleet, self.evidence.__getitem__, {"active_ready_workers": workers},
                        self.paid if paid is None else paid, self.witness if witness is None else witness,
                        fresh_workers=fresh_workers)

    def test_epoch145_accepts_a_fresh_roster_under_the_same_obligation(self):
        self.validate(self.current)
        self.validate(self.old, fresh_workers=False)
        with self.assertRaisesRegex(ValueError, "since the fleet census"):
            self.validate(self.current, fresh_workers=False)

    def test_changed_owner_or_budget_is_rejected(self):
        for changes in (
            {"witness": dict(self.witness, shared_slice={"MemoryMax": "0"})},
            {"paid": dict(self.paid, output_budget={"sha256": "different"})},
            {"paid": dict(self.paid, remaining_archive_growth_bytes=1)},
            {"paid": dict(self.paid, resident_archive_bytes=1)},
            {"paid": dict(self.paid, host_allocation_groups=[{"observed_over_cap_bytes": 1}])},
        ):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.validate(self.current, **changes)

    def test_duplicate_worker_or_range_is_rejected(self):
        row = self.current[0]
        for second in (dict(row, pid=12), dict(row, range=[174, 184])):
            with self.subTest(second=second), self.assertRaisesRegex(ValueError, "duplicate"):
                self.validate([row, second])


if __name__ == "__main__":
    unittest.main()
