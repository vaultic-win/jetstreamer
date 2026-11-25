from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import retry5_fit
import full170_capacity


def need(condition, error):
    if not condition:
        raise ValueError(error)


def ref(path, digest):
    return {"path": str(path), "sha256": digest}


class Retry5Completion(unittest.TestCase):
    def setUp(self):
        self.fit = SimpleNamespace(A145="fixture.service", members=Mock(return_value=()))
        self.load = Mock()

    def fixture(self, owner):
        invocation = owner["invocation"]
        start = retry5_fit.R / "epoch145-guarded-export-20261121-v1/state" / invocation / "recovery-started.json"
        submission = owner["handoff"] / "START_RESULT.json"
        completion = owner["handoff"] / "SEMANTIC_COMPLETION.json"
        proof = {
            "schema": owner["schema"],
            "invocation_id": invocation,
            "start": ref(start, owner["start_sha"]),
            "startup_evidence": {
                "start": ref(start, owner["start_sha"]),
                "submission_result": ref(submission, owner["submission_sha"]),
            },
            "publication_authorized": False,
            "r2_mutations": False,
        }
        status = SimpleNamespace(
            show=Mock(return_value=dict(ActiveState="inactive", SubState="dead", MainPID="0", ControlPID="0",
                                        InvocationID=invocation, ControlGroup="", Job="")),
            need=need, ref=ref, read=Mock(return_value=(proof, ref(completion, "completion"))),
        )
        return proof, status

    def test_requires_both_startup_receipts_for_each_generation(self):
        for owner in (retry5_fit.V7, retry5_fit.V8, retry5_fit.V9):
            with self.subTest(generation=owner["generation"]), patch.object(Path, "exists", return_value=False):
                proof, status = self.fixture(owner)
                with patch.object(retry5_fit.subprocess, "check_output", return_value=json.dumps(proof)) as check:
                    phase = retry5_fit.drained145(status, self.fit, self.load, owner=owner)
                    self.assertEqual(phase["stage"], f"{owner['generation']}-semantic-complete-drained")
                    self.assertEqual(phase["completed_invocation_id"], owner["invocation"])
                    self.load.assert_called_with(owner["checker"], owner["checker_sha"])
                    check.assert_called_once()
                    self.assertEqual(check.call_args.args[0][-2:], [owner["handoff"] / "START_RESULT.json",
                                                                  owner["submission_sha"]])

                    substituted = deepcopy(proof)
                    substituted["start"] = proof["startup_evidence"]["submission_result"]
                    changed_submission = deepcopy(proof)
                    changed_submission["startup_evidence"]["submission_result"]["sha256"] = "unbound"
                    changed_native = deepcopy(proof)
                    changed_native["startup_evidence"]["start"]["sha256"] = "unbound"
                    for invalid in (substituted, changed_submission, changed_native):
                        status.read.return_value = (invalid, phase["completion"])
                        check.return_value = json.dumps(invalid)
                        with self.assertRaisesRegex(ValueError, "terminal or native owner"):
                            retry5_fit.drained145(status, self.fit, self.load, owner=owner)

    def test_rejects_live_and_failed_v9_manager_before_reading_completion(self):
        _, status = self.fixture(retry5_fit.V9)
        for active, substate in (("active", "running"), ("failed", "failed")):
            with self.subTest(active=active):
                status.show.return_value.update(ActiveState=active, SubState=substate)
                with self.assertRaisesRegex(ValueError, "v9 verifier has not drained"):
                    retry5_fit.drained145(status, self.fit, self.load, owner=retry5_fit.V9)
        self.load.assert_not_called()
        status.read.assert_not_called()

    def test_full170_keeps_each_ownership_mode_under_the_exact_v12_charge(self):
        provider = retry5_fit.R / "survivor172-cadence-20261122-v1"
        v12 = provider / "tools-cold168-retry5-failed166-v12-entry146/deployment-seal-receipt.json"
        status = {"consumer_seal": ref(v12, "6899ee7708ca74e9bf2a04cb932ce2fc75dff18e16866149b1dbeea3887496ac")}
        context = SimpleNamespace(need=need)
        route = {"TIMER": "fixture.timer"}
        with (
            patch.object(full170_capacity, "prestart"),
            patch.object(full170_capacity, "held", return_value="held"),
            patch.object(full170_capacity, "idle"),
            patch.object(full170_capacity, "first_guard", return_value="first"),
            patch.object(full170_capacity, "active", return_value=("active", "current")) as active,
        ):
            for mode, result in (("prestart", (None, None)), ("held", ("held", None)),
                                 ("post-guard", ("held", "first")), ("active", ("active", "current"))):
                with self.subTest(mode=mode):
                    self.assertEqual(full170_capacity.ownership(context, self.fit, route, {}, mode,
                                                               {}, status, {}, v9=True), result)
                    wrong_status = {"consumer_seal": ref(v12, "changed")}
                    with self.assertRaisesRegex(ValueError, "registered V12 receiver"):
                        full170_capacity.ownership(context, self.fit, route, {}, mode, {},
                                                   wrong_status, {}, v9=True)
            self.assertTrue(active.call_args.kwargs["v9"])


if __name__ == "__main__":
    unittest.main()
