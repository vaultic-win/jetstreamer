from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, main, mock
import os
import subprocess
import time

import n_admission as n


class FollowonTest(TestCase):
    def setUp(self):
        self.funded = dict(
            build_and_native_qualification_serial=True,
            holding_and_build_may_overlap=True,
            holding_serial=True,
            holding_staging_bytes=0,
            holding_cpu_quota_micros=2_000_000,
            holding_memory_bytes=2 * n.op.G,
            build_cpu_quota_micros=1_000_000,
            build_fixed_image_bytes=4 * n.op.G,
            build_outside_allowance_bytes=n.op.META,
            build_memory_bytes=2 * n.op.G,
        )
        self.price = dict(
            available_home=300 * n.op.G,
            required_home=200 * n.op.G,
            historical_home_margin=90 * n.op.G,
            home_margin=90 * n.op.G,
            available_ram=100 * n.op.G,
            required_ram=98 * n.op.G,
            ram_margin=2 * n.op.G,
        )

    def test_funded_overlap_and_full_historical_guard(self):
        r = n.margins(self.price, self.funded)
        self.assertEqual(r["remaining_home"], 90 * n.op.G - 4 * n.op.G - n.op.META)
        self.assertEqual(r["remaining_ram"], 4 * n.op.G - n.DASHBOARD_RAM)
        self.assertEqual(
            (r["build_ram"], r["holding_ram_available_from_serial"]),
            (2 * n.op.G, 2 * n.op.G),
        )
        with self.assertRaisesRegex(ValueError, "reserves"):
            n.margins(
                self.price, dict(self.funded, holding_and_build_may_overlap=False)
            )
        with self.assertRaisesRegex(ValueError, "inconsistent"):
            n.margins(
                dict(self.price, required_home=self.price["available_home"] + 1),
                self.funded,
            )

    def test_live_compiler_image_only_offsets_the_current_disk_constraint(self):
        budget = dict(
            self.price,
            available_home=292 * n.op.G,
            historical_home_margin=95 * n.op.G,
            home_margin=92 * n.op.G,
        )
        self.assertEqual(
            n.margins(budget, self.funded, 4 * n.op.G)["remaining_home"],
            91 * n.op.G - n.op.META,
        )
        with self.assertRaisesRegex(ValueError, "fixed cap"):
            n.margins(budget, self.funded, 5 * n.op.G)

    def test_distinct_slots_survive_duplicate_holding_correction(self):
        raw = dict(self.price, required_ram=101 * n.op.G, ram_margin=-n.op.G)
        result = n.margins(raw, self.funded, 4 * n.op.G, 2 * n.op.G)
        self.assertEqual(
            result["post_reservation_ram_margin"], n.op.G - n.DASHBOARD_RAM
        )
        self.assertEqual(result["holding_ram_available_from_serial"], 2 * n.op.G)
        self.assertEqual(result["build_ram"], 2 * n.op.G)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            n.margins(raw, self.funded, 4 * n.op.G, 3 * n.op.G)

    def test_both_slots_refuse_if_dashboard_exhausts_ram(self):
        r = n.margins(
            dict(self.price, required_ram=100 * n.op.G, ram_margin=0), self.funded
        )
        self.assertEqual(r["remaining_ram"], 0)
        self.assertEqual(r["post_reservation_ram_margin"], -n.DASHBOARD_RAM)

    def test_reject_unexpected_replay_or_holding_owner(self):
        fleet = dict(actual_executing_replays=[], actual_active_private_diagnostics=[])
        with mock.patch.object(n, "accepted_fleet", return_value=fleet):
            with self.assertRaisesRegex(ValueError, "replay roster"):
                n.owners({"fleet": None})
        with mock.patch.object(
            n, "active_units", return_value={"horizon-closed186-park-m-4.service"}
        ):
            with self.assertRaisesRegex(ValueError, "other serial holding owner"):
                n.serial_owner()

    def test_bound_fleet_age_and_ancestry(self):
        with TemporaryDirectory() as temp:
            latest = Path(temp) / "root191808/ROOT_COMPLETE_OPERATIONAL_FLEET.json"
            latest.parent.mkdir()
            latest.touch()
            fresh = datetime.now(timezone.utc).isoformat()
            stale = datetime.fromtimestamp(time.time() - 1910, timezone.utc).isoformat()
            row = dict(
                sampled_at_utc=fresh,
                resource_credit_bytes=0,
                all_reservation_ending_bytes=0,
                all_active_status_reports_authenticated_readback=True,
            )
            ref = dict(path=str(latest), sha256=n.FLEET)
            with (
                mock.patch.object(n.op, "RT", Path(temp)),
                mock.patch.object(n.op, "bound", return_value=row),
            ):
                self.assertEqual(n.accepted_fleet(ref), row)
                with self.assertRaisesRegex(ValueError, "superseded"):
                    n.accepted_fleet(dict(ref, path="/some/other/fleet"))
                row["sampled_at_utc"] = stale
                with self.assertRaisesRegex(ValueError, "stale"):
                    n.accepted_fleet(ref)
                row.update(sampled_at_utc=fresh, previous_Root_operational_review=ref)
                with self.assertRaisesRegex(ValueError, "descend"):
                    n.accepted_fleet(dict(ref, sha256="foreign"))

    def test_lane_restriction(self):
        with mock.patch.object(n.op, "TOOLS", n.op.FOLLOWON):
            n.op.deployment("retire", "n")
            with self.assertRaisesRegex(ValueError, "only the lane N"):
                n.op.deployment("park", "m")
            with self.assertRaisesRegex(ValueError, "only the lane N"):
                n.op.deployment("fixture", "n")


class RetirementTest(TestCase):
    def setUp(self):
        self.directory = Path(self.enterContext(TemporaryDirectory()))
        self.lock = self.directory / "operation.lock"
        self.lock.touch()
        self.enterContext(mock.patch.object(n.op, "OPLOCK", self.lock))
        self.enterContext(
            mock.patch.object(
                n, "retirement_guard_directory", return_value=self.directory
            )
        )
        self.positive = dict(remaining_home=n.op.META, remaining_ram=n.op.G)
        self.du = (
            "/usr/bin/du",
            "-sx",
            "-B1",
            str(n.op.BASE / "epoch170-standard-lane-20261109-v1"),
        )
        self.sample = "sample-" + "a" * 32 + ".json"

    def test_native_rename_and_hard_link(self):
        tmp = self.directory / ".guard-writing"
        tmp.write_text("{}")
        snapshot = self.directory / self.sample
        with n.watch_guard(self.directory) as fd:
            (self.directory / "sample-invalid.json").touch()
            tmp.rename(snapshot)
            self.assertEqual(n.wait_for_guard(fd, time.monotonic() + 2), self.sample)
        snapshot.rename(tmp)
        with n.watch_guard(self.directory) as fd:
            os.link(tmp, snapshot)
            self.assertEqual(n.wait_for_guard(fd, time.monotonic() + 2), self.sample)
        with n.watch_guard(self.directory) as fd:
            snapshot.read_bytes()
            (self.directory / "unrelated").touch()
            with self.assertRaisesRegex(ValueError, "timed out"):
                n.wait_for_guard(fd, time.monotonic() + 0.03)

    def test_lost_watch_is_fatal(self):
        watched = self.directory / "guard"
        watched.mkdir()
        with n.watch_guard(watched) as fd:
            (watched / self.sample).touch()
            watched.rename(self.directory / "moved")
            with self.assertRaisesRegex(ValueError, "guard directory changed"):
                n.wait_for_guard(fd, time.monotonic() + 2)

    def test_discard_partial_and_insufficient_quotes(self):
        low = dict(
            self.positive,
            remaining_home=n.op.META - 1,
            fleet="fleet",
            post_reservation_ram_margin=1,
            basis={"after": {"sample": "prior"}},
        )
        failed = subprocess.CalledProcessError(1, self.du, output="9999999999999")

        def next_sample(fd, deadline):
            with n.op.locked(self.lock):
                return self.sample

        with (
            mock.patch.object(
                n, "price", side_effect=[failed, low, self.positive]
            ) as price,
            mock.patch.object(n, "wait_for_guard", side_effect=next_sample) as wait,
            mock.patch.object(n, "owners") as owners,
            n.retirement_quote(n.op.META, n.op.G) as result,
        ):
            self.assertIs(result, self.positive)
            with self.assertRaises(BlockingIOError):
                n.op.locked(self.lock).close()
            first, second = result["retirement_admission_events"]
            self.assertEqual(first["reason"], "incomplete live 170 tree census")
            self.assertNotIn(failed.output, str(first))
            self.assertEqual((second["sample"], second["home"]), ("prior", -1))
            self.assertEqual(first["next_guard_receipt"], self.sample)
            self.assertEqual(second["next_guard_receipt"], self.sample)
            self.assertEqual(
                (price.call_count, wait.call_count, owners.call_count), (3, 2, 2)
            )

    def test_unrelated_or_fatal_errors_do_not_wait(self):
        for error in (
            subprocess.CalledProcessError(2, self.du),
            subprocess.CalledProcessError(1, (*self.du[:-1], "/other")),
            subprocess.CalledProcessError(1, ("/usr/bin/false",)),
            ValueError("different native owner"),
        ):
            with (
                self.subTest(error=error),
                mock.patch.object(n, "price", side_effect=error),
                mock.patch.object(n, "wait_for_guard") as wait,
                self.assertRaises(type(error)) as raised,
                n.retirement_quote(n.op.META, n.op.G),
            ):
                self.fail("unexpected accepted quote")
            wait.assert_not_called()
            self.assertIs(raised.exception, error)

    def test_caller_error_after_admission_is_never_retried(self):
        error = subprocess.CalledProcessError(1, self.du)
        with (
            mock.patch.object(n.op, "TOOLS", n.op.FOLLOWON),
            mock.patch.object(n, "price", return_value=self.positive) as price,
            mock.patch.object(n, "owners"),
            mock.patch.object(n, "wait_for_guard") as wait,
            self.assertRaises(subprocess.CalledProcessError) as raised,
            n.op.phase_quote("retire", n.op.META, n.op.G),
        ):
            raise error
        self.assertIs(raised.exception, error)
        price.assert_called_once()
        wait.assert_not_called()
        with n.op.locked(self.lock):
            pass


if __name__ == "__main__":
    main()
