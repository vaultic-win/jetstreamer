from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, main, mock
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


if __name__ == "__main__":
    main()
