from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import retry5_fit


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
        for v8, owner in ((False, retry5_fit.V7), (True, retry5_fit.V8)):
            with self.subTest(v8=v8), patch.object(Path, "exists", return_value=False):
                proof, status = self.fixture(owner)
                with patch.object(retry5_fit.subprocess, "check_output", return_value=json.dumps(proof)) as check:
                    phase = retry5_fit.drained145(status, self.fit, self.load, v8=v8)
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
                            retry5_fit.drained145(status, self.fit, self.load, v8=v8)

    def test_rejects_live_and_failed_v8_manager_before_reading_completion(self):
        _, status = self.fixture(retry5_fit.V8)
        for active, substate in (("active", "running"), ("failed", "failed")):
            with self.subTest(active=active):
                status.show.return_value.update(ActiveState=active, SubState=substate)
                with self.assertRaisesRegex(ValueError, "v8 verifier has not drained"):
                    retry5_fit.drained145(status, self.fit, self.load, v8=True)
        self.load.assert_not_called()
        status.read.assert_not_called()


if __name__ == "__main__":
    unittest.main()
