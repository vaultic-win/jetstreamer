"""Offline observation fixtures for the private predecessor registration."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch


ADAPTER = (Path(__file__).resolve().parents[1] /
           "horizon_foundation_delivery247_20261124/diagnostic296_meter.py")
INVOCATION = "2d9f94eae87d438e82030af17679ad8b"
PID = os.getpid()


class PredecessorObservation(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        delivery = types.ModuleType("ordinary249.delivery248")
        delivery.V = self.root
        delivery.ref = self.reference
        delivery.bound = self.bound
        delivery.props = self.props
        parent = types.ModuleType("ordinary249")
        parent.delivery248 = delivery
        spec = importlib.util.spec_from_file_location("predecessor_adapter_fixture", ADAPTER)
        self.adapter = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules, {"ordinary249": parent, "ordinary249.delivery248": delivery}):
            spec.loader.exec_module(self.adapter)
        self.adapter.sealed = self.reference
        self.live = {}

    @staticmethod
    def reference(path):
        return {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}

    def store(self, relative, row):
        path = self.root / relative
        path.parent.mkdir(exist_ok=True, parents=True)
        path.write_text(json.dumps(row, indent=2))
        return self.reference(path)

    def bound(self, reference):
        path = Path(reference["path"])
        self.assertEqual(reference, self.reference(path))
        return json.loads(path.read_text())

    def props(self, unit, fields):
        return {field: self.live[unit][field] for field in fields}

    def registration(self, version):
        unit, state, root = self.adapter.attempt_paths(version)
        _, _, kind = self.adapter.FOCUSED[version]
        node = str(Path("/proc/self/exe").resolve(strict=True))
        restore = {"path": "/restore", "sha256": "c" * 64}
        profile_path = self.adapter.profile_path(state, version)
        profile = self.store(profile_path, dict(
            worker={"path": "/sealed-worker", "sha256": "b" * 64},
            diagnostic_only=True, restore_receipt=restore,
        ))
        preflight = self.store(state / "preflight.json", {"profile": profile})
        if version == self.adapter.PREDECESSOR_266:
            self.adapter.PREDECESSOR_266_PROFILE_SHA = profile["sha256"]
            self.adapter.PREDECESSOR_266_PREFLIGHT_SHA = preflight["sha256"]
        guard_plan = self.store(state / "guard-plan.json", {"invocation_id": INVOCATION})
        admission = self.store(state / "admission.json", {
            "profile": profile, "admitted": True, "preflight": preflight, "roster": "fixture-roster",
        })
        guard = self.store(state / "active-guard.json", {
            "producer_invocation_id": INVOCATION, "plan_sha256": guard_plan["sha256"],
            "trip_reason": None, "producer_stop_enabled": True, "producer": {"pid": PID},
        })
        release = self.store(state / "guard-release-fit.json", {
            "invocation_id": INVOCATION, "roster": "fixture-roster", "guard_plan": guard_plan,
            "schema": "foundation-epoch266-original-predecessor-guard-release-fit-v1",
            "publication_authorized": False,
        })
        row = dict(schema="jetstreamer-historical-performance-launch-receipt-v1",
                   kind=kind, epoch=266, unit=unit, run_root=str(root),
                   invocation_id=INVOCATION, main_pid=PID, node_path=node,
                   profile=profile, worker=self.bound(profile)["worker"], admission=admission,
                   guard_plan=guard_plan, active_guard=guard, guard_release_fit=release,
                   launched=True, remote_mutations=False, r2_mutations=False,
                   canonical_epoch_publication_authorized=False, diagnostic_only=True,
                   predecessor_native_tuple_qualified=False, cursor_normalization_qualified=False)
        if version == self.adapter.OVERLAP_266:
            row["lossless_restore"] = restore
        else:
            custody = self.store(self.adapter.PREDECESSOR_266_CUSTODY, {
                "profile": profile, "actual_readonly_projection_verified": True,
            })
            self.adapter.PREDECESSOR_266_CUSTODY_SHA = custody["sha256"]
            row["bootstrap_custody"] = custody
        launch = self.store(state / "cadence-registration.json", row)
        self.live[unit] = dict(ActiveState="active", SubState="running", NRestarts="0",
                              InvocationID=INVOCATION, MainPID=str(PID),
                              ControlGroup=f"/system.slice/{unit}")
        return launch, row

    def plan(self):
        return dict(observer=self.store("observer.json", {"replays": []}), diagnostics=[],
                    tracked_units=[], gates={"266": {"evidence": []}})

    def test_exact_predecessor_is_observed_and_registered_after_image_selection(self):
        launch, row = self.registration(self.adapter.PREDECESSOR_266)
        cfg, = self.adapter.configuration()
        self.assertEqual(cfg["range"], "266-266")
        self.assertEqual(cfg["producer_unit"], row["unit"])
        self.assertEqual(cfg["expected_producer_invocation_id"], INVOCATION)
        self.assertEqual(cfg["scratch_path"], row["run_root"])
        plan = self.plan()
        self.adapter.register(plan)
        self.assertEqual(plan["diagnostics"], [])
        self.adapter.register_predecessor_266(plan)
        self.adapter.register_predecessor_266(plan)
        claim, = plan["diagnostics"]
        self.assertEqual(claim["launch_receipt"], launch)
        self.assertEqual(plan["tracked_units"], [row["unit"]])
        self.assertTrue(self.adapter.owns({
            "producer": {"Id": row["unit"], "InvocationID": INVOCATION},
            "epoch": 266, "phase": "diagnostic-qualification",
            "scratch_path": row["run_root"], "ordinary_replay_claim": False,
        }))

    def test_live_manager_mismatch_is_rejected(self):
        _, row = self.registration(self.adapter.PREDECESSOR_266)
        self.live[row["unit"]]["InvocationID"] = "a" * 32
        with self.assertRaises(AssertionError):
            self.adapter.configuration()

    def test_predecessor_and_existing_overlap_cannot_both_own_epoch_266(self):
        _, overlap = self.registration(self.adapter.OVERLAP_266)
        overlap_config, = self.adapter.configuration()
        self.assertEqual(overlap_config["producer_unit"], overlap["unit"])
        _, predecessor = self.registration(self.adapter.PREDECESSOR_266)
        with self.assertRaises(AssertionError):
            self.adapter.configuration()
        self.live[overlap["unit"]].update(ActiveState="inactive", MainPID="0", ControlGroup="")
        predecessor_config, = self.adapter.configuration()
        self.assertEqual(predecessor_config["producer_unit"], predecessor["unit"])

    def test_exact_guard_release_required_and_no_publication_claim(self):
        launch, row = self.registration(self.adapter.PREDECESSOR_266)
        release = self.bound(row["guard_release_fit"])
        release["publication_authorized"] = True
        row["guard_release_fit"] = self.store(row["guard_release_fit"]["path"], release)
        self.store(launch["path"], row)
        with self.assertRaises(AssertionError):
            self.adapter.configuration()


if __name__ == "__main__":
    unittest.main()
