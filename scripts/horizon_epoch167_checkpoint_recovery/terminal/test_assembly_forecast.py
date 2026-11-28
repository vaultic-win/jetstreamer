"""Small fixtures for the booked 167 observer and assembly-to-readiness model."""
import copy
import os
import unittest
from datetime import timedelta
from unittest.mock import patch

import assembly_forecast as f


class ForecastTest(unittest.TestCase):
    def setUp(self):
        self.start = f.instant("2026-11-28T10:53:02.030598+00:00")
        self.path = str(f.OUTPUT / ".pending-167-fixture" / "epoch-167.jet")
        self.arc = dict(path=self.path, device=4, inode=8, size=10**10, complete=False,
                        producer_fd="/proc/37/fd/6")
        self.unit = {"Id": f.UNIT, "MainPID": "37", "InvocationID": f.INVOCATION}
        self.model = dict(current_start_utc=self.start.isoformat(), comparison_wall_usec=16_041_662_684,
                          comparison_archive_bytes=121_787_223_572)
        self.inputs = ({}, {"unit": self.unit}, self.model, self.arc, 99_109_684)
        self.prior = {"after_status": {"epoch": 167, "phase": "verification",
                                      "sampled_at_utc": f.wire_time(self.start)}}
        self.ref = f.ref(f.RECEIPTS / "fixture" / "RECEIPT.json", "9"*64)

    def sample(self, secs=3600, size=20_000_000_000, terminal=False):
        observed = self.start + timedelta(seconds=secs)
        doc = dict(schema=f.SCHEMA, invocation=f.INVOCATION, booking=f.BOOKING, dispatch=f.DISPATCH,
                   assembly_unit=self.unit, observed_at_utc=observed.isoformat(),
                   archive_sample=dict(self.arc, size=size), state="running")
        if terminal:
            doc.update(state="terminal", terminal_at_utc=(self.start + timedelta(hours=5)).isoformat(),
                       terminal=f.ref(f.TERMINAL, "1"*64),
                       private_report=f.ref(f.OUTPUT / "accepted" / "assembly.json", "2"*64))
            doc["archive_sample"].update(complete=True, path=str(f.OUTPUT / "accepted" / "epoch-167.jet"))
        return doc

    def result(self, obs, prior=None):
        with patch.object(f, "basis", return_value=self.inputs), \
             patch.object(f, "status_receipt", return_value=prior or self.prior), \
             patch.object(f, "native_observation", return_value=obs):
            return f.forecast(f.wire_time(f.instant(obs["observed_at_utc"])), self.ref)

    def test_wire_fields_use_the_new_owner_and_bytes(self):
        after, extra = self.result(self.sample())
        self.assertEqual(set(after), {"sampled_at_utc", "phase", "epoch", "elapsed_execution_millis",
                                      "jet_size_bytes", "estimated_remaining_millis"})
        self.assertEqual(after["elapsed_execution_millis"], 3_599_969)
        self.assertEqual(after["jet_size_bytes"], 20_000_000_000)
        self.assertEqual(after["phase"], "verification")
        self.assertFalse(extra["measured_canonical_progress"])
        self.assertGreater(after["estimated_remaining_millis"], 99_109_684)
        self.assertEqual(extra["terminal_delivery_estimate"]["delivery_tail_source"], f.TAIL)

    def test_startup_and_progress(self):
        start = self.sample(1, 8)
        self.assertIn("startup", self.result(start)[1]["terminal_delivery_estimate"]["method"])
        before = self.sample(1800, 8_000_000_000)
        prior_status, first = self.result(before)
        prior = dict(first, after_status=prior_status)
        after, second = self.result(self.sample(3600, 20_000_000_000), prior)
        self.assertLess(after["estimated_remaining_millis"], prior_status["estimated_remaining_millis"])
        self.assertEqual(second["terminal_delivery_estimate"]["interval_growth_bytes"], 12_000_000_000)

    def test_stall_and_comparator_overshoot(self):
        now = self.sample(3600, 20_000_000_000)
        stamp = f.instant(now["observed_at_utc"])
        _, slow = f.assembly_time(now, (stamp - timedelta(minutes=30), 20_000_000_000), self.model)
        _, moving = f.assembly_time(now, (stamp - timedelta(minutes=30), 9_000_000_000), self.model)
        self.assertGreater(slow["remaining_at_observation_ms"], moving["remaining_at_observation_ms"])
        _, extra = self.result(self.sample(18_000, self.model["comparison_archive_bytes"] + 233))
        self.assertGreater(extra["terminal_delivery_estimate"]["remaining_at_observation_ms"], 0)

    def test_exact_terminal_reduces_tail_without_restarting(self):
        first = self.sample(18_001, 120_000_000_000, terminal=True)
        later = self.sample(19_801, 120_000_000_000, terminal=True)
        one, details = self.result(first)
        two, _ = self.result(later)
        self.assertEqual(one["estimated_remaining_millis"] - two["estimated_remaining_millis"], 1_800_000)
        self.assertEqual(one["elapsed_execution_millis"], two["elapsed_execution_millis"])
        self.assertEqual(one["elapsed_execution_millis"], 18_000_000)
        self.assertEqual(details["terminal_delivery_estimate"]["remaining_at_observation_ms"], 0)

    def test_wrong_owner_path_fd_and_previous_epoch_rejected(self):
        for field, val in (("invocation", "0"*32), ("assembly_unit", {}),
                           ("dispatch", f.ref("/tmp/fixture", "0"*64))):
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.result(dict(self.sample(), **{field: val}))
        for field, val in (("path", "/wrong/old-prefix/epoch-167.jet"), ("inode", 99),
                           ("producer_fd", "/proc/37/fd/4")):
            event = self.sample()
            event["archive_sample"][field] = val
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.result(event)
        with self.assertRaisesRegex(ValueError, "another owner"):
            self.result(self.sample(), {"after_status": dict(self.prior["after_status"], phase="upload")})
        with self.assertRaisesRegex(ValueError, "outside"):
            f.status_receipt(f.ref("/tmp/epoch-167.receipt.json", "3"*64))
        alien = copy.deepcopy(self.prior)
        alien.update(assembly_invocation_id="old", archive_sample=self.arc, assembly_observed_at_utc=self.start.isoformat())
        self.assertIsNone(f.previous_measurement(alien, self.ref, self.arc))

    def test_bound_sample_rejects_wrong_seal_and_foreign_file(self):
        with patch.object(f, "basis", return_value=self.inputs), patch.object(f, "status_receipt", return_value=self.prior):
            with self.assertRaisesRegex(ValueError, "location"):
                f.forecast("2026-11-28T11:48:08Z", self.ref, f.ref("/tmp/FORECAST_SAMPLE_9.json", "9"*64))
        if os.geteuid() == 0 and f.STATE.is_dir():
            with self.assertRaisesRegex(ValueError, "digest mismatch"):
                f.checked(dict(f.BOOKING, sha256="0"*64))


if __name__ == "__main__":
    unittest.main()
