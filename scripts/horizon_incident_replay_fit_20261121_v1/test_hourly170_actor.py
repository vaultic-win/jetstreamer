import ast
from pathlib import Path
import types
import unittest
from unittest.mock import patch

import hourly170_actor as route


MARGIN = 12 << 30
FLOOR = 8_875_000_000_000
PHYSICAL = 275_113_136_128
BIND = {"ready": {"path": "ready", "sha256": "a" * 64}, "inputs": {"path": "inputs", "sha256": "b" * 64}}


def base_price(stage="v5u-drained"):
    return dict(
        bookings={"170": dict(root=str(route.LANE), cap_bytes=route.CAP,
                              physical_bytes=PHYSICAL, remaining_bytes=route.CAP-PHYSICAL)},
        failed_cold170={"reservation_ending_bytes": 0}, complete_cpu_quota_micros=64_000_000,
        complete_memory_plus_reserve_bytes=810_658_050_048, resource_credit_bytes=0,
        replay_launch_authorized=False, candidate136={"occupied": False}, bounded_qualification=None,
        phase145={"stage": stage}, replacements={"166": {"floor": FLOOR}}, survivors={},
        active168_guard_floor=0, complete_required_HOME_bytes=FLOOR+route.GROWTH,
        available_HOME_bytes=FLOOR+route.GROWTH+MARGIN, fits=True,
    )


def actor():
    return {"baseline": PHYSICAL, "intent": {"path": "intent", "sha256": "a" * 64},
            "native_plan": {"maximum_root_physical_bytes": PHYSICAL+route.GROWTH,
                            "minimum_free_bytes": FLOOR}}


def guard(amount=PHYSICAL):
    return {"measured_bytes": amount, "receipt": {"path": "sample", "sha256": "a" * 64},
            "available_bytes": FLOOR + route.GROWTH}


class Hourly170Tests(unittest.TestCase):
    def test_prestart_holds_original_complete_host_and_tree(self):
        base = base_price()
        result = route.price(base, BIND, None, None, "prestart")
        d = result["hourly170_diagnostic"]
        self.assertTrue(result["fits"])
        self.assertEqual(result["bookings"], base["bookings"])
        self.assertEqual(result["complete_required_HOME_bytes"], base["complete_required_HOME_bytes"])
        self.assertEqual(result["complete_cpu_quota_micros"], 64_000_000)
        self.assertEqual(result["complete_memory_plus_reserve_bytes"], 810_658_050_048)
        self.assertEqual(d["whole_tree_guard_cap_bytes"], PHYSICAL+96*route.G)
        self.assertEqual(d["actor_limits"]["cpu_micros"], 3_000_000)
        self.assertEqual(d["guard_limits"]["memory_max"], route.G)
        self.assertFalse(result["replay_launch_authorized"])

    def test_ongoing_v5u_quote_does_not_allow_overlap(self):
        base = base_price("leased-worker")
        result = route.price(base, BIND, None, None, "prestart")
        self.assertTrue(result["hourly170_diagnostic"]["resource_fit"])
        self.assertFalse(result["hourly170_diagnostic"]["launch_compatible"])
        self.assertFalse(result["fits"])
        with self.assertRaisesRegex(ValueError, "V5u"):
            route.price(base, BIND, actor(), guard(), "post-guard")

    def test_prices_remaining_96gib_once_and_lower_guard_free(self):
        base = base_price()
        first = actor()
        realized = PHYSICAL + 11 * route.G
        base["bookings"]["170"].update(physical_bytes=realized, remaining_bytes=route.CAP-realized)
        observed = guard(realized)
        result = route.price(base, BIND, first, observed, "post-guard")
        d = result["hourly170_diagnostic"]
        self.assertTrue(result["fits"])
        self.assertEqual(d["diagnostic_remaining_bytes"], 85 * route.G)
        self.assertEqual(result["complete_required_HOME_bytes"], base["complete_required_HOME_bytes"])
        self.assertEqual(result["available_HOME_bytes"], observed["available_bytes"])
        self.assertEqual(d["intent"], first["intent"])
        self.assertEqual(d["receipt"], observed["receipt"])
        self.assertNotIn("cadence_registration", d)

    def test_active_quote_binds_private_cadence_row_to_current_guard(self):
        running = actor()
        registration = {
            "epoch": 170,
            route.FIELD: running["intent"],
            "canonical_replay_claimed": False,
            "archive_publication_authorized": False,
        }
        running["registration"] = registration
        protection = guard()
        result = route.price(base_price(), BIND, running, protection, "active")
        diagnostic = result["hourly170_diagnostic"]
        row = diagnostic["cadence_registration"]
        self.assertEqual(row, dict(registration, guard_protection=protection["receipt"]))
        roster = dict(actual_executing_replays=[{"epoch": 166}], actual_active_bootstraps=[],
                      actual_active_private_diagnostics=[row])
        self.assertEqual(route.roster(roster, "active"), ([{"epoch": 166}], row))
        self.assertFalse(result["replay_launch_authorized"])

    def test_unfunded_or_mismatched_active_diagnostic_cannot_supply_registration(self):
        running = actor()
        running["registration"] = {
            "epoch": 170,
            route.FIELD: {"path": "different-intent", "sha256": "c" * 64},
            "canonical_replay_claimed": False,
            "archive_publication_authorized": False,
        }
        floor = dict(guard(), available_bytes=FLOOR)
        result = route.price(base_price(), BIND, running, floor, "active")
        self.assertFalse(result["fits"])
        self.assertNotIn("cadence_registration", result["hourly170_diagnostic"])
        with self.assertRaisesRegex(ValueError, "cadence registration"):
            route.price(base_price(), BIND, running, guard(), "active")

    def test_guard_floor_above_native_floor_is_preserved(self):
        base = base_price()
        first = actor()
        first["native_plan"]["minimum_free_bytes"] = FLOOR+1
        result = route.price(base, BIND, first, guard(), "post-guard")
        self.assertEqual(result["complete_required_HOME_bytes"], FLOOR+route.GROWTH+1)
        self.assertFalse(result["fits"])

    def test_booking_and_concurrent_reservation_changes_fail_closed(self):
        for key, value in (("candidate136", {"occupied": True}), ("bounded_qualification", {"epoch": 146}),
                           ("failed_cold170", {"reservation_ending_bytes": 1}),
                           ("complete_cpu_quota_micros", 68_000_000)):
            with self.subTest(key=key), self.assertRaises(ValueError):
                route.price(dict(base_price(), **{key: value}), BIND, None, None, "prestart")
        modified = base_price()
        modified["bookings"]["170"].update(cap_bytes=288*route.G, remaining_bytes=288*route.G-PHYSICAL)
        with self.assertRaisesRegex(ValueError, "booking"):
            route.price(modified, BIND, None, None, "prestart")
        insufficient = base_price()
        full = route.CAP - route.GROWTH + 1
        insufficient["bookings"]["170"].update(physical_bytes=full, remaining_bytes=route.CAP-full)
        with self.assertRaisesRegex(ValueError, "exceeds"):
            route.price(insufficient, BIND, None, None, "prestart")

    def test_private_fleet_row_not_an_ordinary_replay(self):
        row = {"epoch": 170, "unit": {"Id": route.UNIT}}
        f = dict(actual_executing_replays=[{"epoch": 166}], actual_active_bootstraps=[],
                 actual_active_private_diagnostics=[row])
        self.assertEqual(route.roster(f, "active"), ([{"epoch": 166}], row))
        for stage in ("prestart", "post-guard"):
            with self.assertRaises(ValueError):
                route.roster(f, stage)
        f["actual_executing_replays"].append(row)
        with self.assertRaises(ValueError):
            route.roster(f, "active")

    def test_tracked_census_includes_exact_diagnostic_and_rejects_unknown(self):
        # Isolate the native census body from the provider's host-pinned loaders.
        provider = Path(__file__).with_name("post-stop-fit")
        parsed = ast.parse(provider.read_text())
        item, = [node for node in parsed.body if isinstance(node, ast.FunctionDef) and node.name == "census"]
        m = ast.Module(body=[item], type_ignores=[])
        pid, ticks, dev, ino = 4211, 997, 102, 89

        class FakePath:
            def __init__(self, name):
                self.name = name

            def iterdir(self):
                return []

            def stat(self):
                return types.SimpleNamespace(st_dev=dev, st_ino=ino)

        fit = types.SimpleNamespace(units=lambda: {route.UNIT}, members=lambda _u: (pid,))
        status = types.SimpleNamespace(need=route.need, process=lambda _pid: (1, ticks, "0::" + route.CGROUP))
        namespace = dict(fit=fit, s=status, Path=FakePath, HOURLY170=True)
        exec(compile(m, str(provider), "exec"), namespace)
        census = namespace["census"]
        args = ({}, {}, None, {"occupied": False}, 145, {})
        row = dict(unit=route.UNIT, processes=[[pid, ticks, dev, ino]])
        self.assertEqual(census(*args, hourly170_owner=row), ({route.UNIT: [[pid, ticks]]}, None))
        for change in ("unregistered", "outside-provider", "wrong-image", "overlap"):
            with self.subTest(change=change), self.assertRaises(ValueError):
                if change == "unregistered":
                    census(*args)
                elif change == "outside-provider":
                    with patch.dict(namespace, HOURLY170=False):
                        census(*args, hourly170_owner=row)
                elif change == "wrong-image":
                    census(*args, hourly170_owner=dict(row, processes=[[pid, ticks, dev, ino+1]]))
                else:
                    with patch.object(fit, "units", lambda: {route.UNIT, "foreign.service"}):
                        census(*args, hourly170_owner=row)


if __name__ == "__main__":
    unittest.main()
