import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import stage_native48 as stage


class Native48Protocol(unittest.TestCase):
    def fixture(self, directory):
        actor = directory / "actor"
        actor.mkdir()
        payload = actor / "native.rs"
        payload.write_bytes(b"source")
        files = {payload.name: stage.sha(payload)}
        plan = stage.seal_plan(actor, actor, files)
        plan_path = directory / "plan.json"
        stage.dump(plan_path, plan)
        seal = {"schema": "jetstreamer-sealed-deployment-receipt-v1",
                "destination": str(actor), "plan_sha256": stage.sha(plan_path),
                "sealer_sha256": stage.SEALER_SHA,
                "members": [{"name": name, "sha256": digest, "mode": "0444"}
                            for name, digest in files.items()]}
        stage.dump(actor / "deployment-seal-receipt.json", seal)
        observed = {"source_files": {k: {"sha256": v} for k, v in files.items()}}
        return actor, plan_path, observed

    def test_installed_source_is_pinned(self):
        with tempfile.TemporaryDirectory() as directory:
            actor, plan, inputs = self.fixture(Path(directory))
            with patch.object(stage, "ACTOR", actor), patch.object(stage, "INPUTS", inputs):
                self.assertEqual(stage.checked_actor(plan), actor / "deployment-seal-receipt.json")
                (actor / "native.rs").write_bytes(b"changed")
                with self.assertRaises(ValueError):
                    stage.checked_actor(plan)

    def test_rejects_wrong_sealer_or_duplicate_member(self):
        with tempfile.TemporaryDirectory() as directory:
            actor, plan, inputs = self.fixture(Path(directory))
            path = actor / "deployment-seal-receipt.json"
            valid = json.loads(path.read_bytes())
            with patch.object(stage, "ACTOR", actor), patch.object(stage, "INPUTS", inputs):
                for key, value in [("sealer_sha256", "0" * 64),
                                   ("members", valid["members"] * 2)]:
                    stage.dump(path, {**valid, key: value})
                    with self.assertRaises(ValueError):
                        stage.checked_actor(plan)

    def test_changes_only_exact_input_and_hashes(self):
        original = stage.snapshot()
        new = copy.deepcopy(original)
        stage.rebind_phases(new)
        names = [row["phase"] for row in new["phases"]]
        self.assertEqual(len(set(names)), 15)
        self.assertEqual(sum(row["expected_passed"] or 0 for row in new["phases"]), 82)
        self.assertEqual(new["phases"][10:], original["phases"][10:])
        for old, row in zip(original["phases"][:10], new["phases"][:10], strict=True):
            changed = [(a, b) for a, b in zip(old["payload"], row["payload"], strict=True) if a != b]
            self.assertEqual(len(changed), 1)
            a, b = map(Path, changed[0])
            self.assertEqual(a.parent, stage.OLD_ACTOR)
            self.assertEqual(b, stage.ACTOR / a.name)
            before = copy.deepcopy(row)
            before.update({k: old[k] for k in ("payload", "payload_sha256", "actor_argv")})
            before["gate_plan"]["payload_sha256"] = old["gate_plan"]["payload_sha256"]
            self.assertEqual(before, old)
            self.assertEqual(row["actor_argv"][-len(row["payload"]):], row["payload"])
            self.assertEqual(row["gate_plan"]["payload_sha256"], stage.compact_digest(row["payload"]))

    def test_refuses_disagreement_between_payload_gate_and_actor(self):
        for mutate in ("gate", "argv", "payload"):
            protocol = stage.snapshot()
            row = protocol["phases"][0]
            if mutate == "gate":
                row["gate_plan"]["payload_sha256"] = "0" * 64
            elif mutate == "argv":
                row["actor_argv"][-1] = "other"
            else:
                row["payload"].append("other")
            with self.assertRaises(ValueError):
                stage.rebind_phases(protocol)


if __name__ == "__main__":
    unittest.main()
