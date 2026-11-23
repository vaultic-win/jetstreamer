import copy
from pathlib import Path
import runpy
import unittest

M = runpy.run_path(str(Path(__file__).with_name("v5k_stopped.py")))
I, U, P = (M[k] for k in ("IID", "UNIT", "PREV"))


def fixture():
    boot = {"_BOOT_ID": "test-boot"}
    review = {"old_manager": {"InvocationID": P}, "original_pid1_exit": boot,
              "reader": {"path": "/reader", "sha256": "sha"}, "retained_inputs": [{"path": "/candidate"}],
              "failed_phase": {"InvocationID": P, "candidate": {"bytes": 7}}}
    fleet = {"path": "/fleet", "sha256": "digest"}
    argv = ["submit", "--", "/reader", "recover-full-output", "/fleet", "digest", "sha"]
    parent = {"pid": 1359289, "start_ticks": 378357260}
    rec = {"path": str(M["ARTIFACTS"]["started"][0]), "sha256": M["ARTIFACTS"]["started"][1]}
    base = {**boot, "INVOCATION_ID": I, "UNIT": U, "_PID": "1"}
    rows = [dict(base, MESSAGE_ID="39f53479d3a045ac8e11786248231fbf", __CURSOR=M["BIRTH"],
                 __REALTIME_TIMESTAMP="1000000", MESSAGE=f"Started {U} - " + " ".join(argv[2:]) + "."),
            dict(base, MESSAGE_ID="98e322203f7a4ed290d09fe03c09fe15", __CURSOR=M["EXIT"],
                 __REALTIME_TIMESTAMP="4000010", EXIT_STATUS="1", EXIT_CODE="exited", COMMAND="ExecStart")]
    leases = dict.fromkeys(M["LEASES"], 4)
    v = {"argv": argv, "started": {"iid": I, "image": "sha", "file": "/candidate", "r2_mutations": False,
            "fresh_fit": {"phase145": {"invocation_id": I, "stage": "controller", "window": {"native_parent": parent}}}},
         "failed": {"iid": I, "at": 4, "error": "complete 145 capacity observation failed exit status: 1: in fleet_head\nValueError: stale or incomplete root fleet"},
         "worker_sample": {"window": {"native_parent": parent, "native_child": {"pid": 1359692, "start_ticks":378359980},
                                      "leases_parent": leases, "leases_worker": leases.copy(), "recovery": rec},
                           "invocation_id": I, "image_sha256": "sha", "stage": "leased-worker", "source": rec,
                           "manager_start_cursor": M["BIRTH"], "rchar": 10, "sample_unix_ns": 2000000000},
         "intent": {"fleet": fleet, "argv": argv, "review_sha256": M["REVIEW"], "original": boot,
                    "preflight": {"quote_provider": {"sha256": M["DSHA"]}}},
         "submitted": {"invocation_id": I, "argv": argv, "manager_start_cursor": M["BIRTH"]},
         "cadence": {"error": "native HOST RSS unavailable", "fleet": fleet}}
    return review, v, rows


class StoppedVerifier(unittest.TestCase):
    def test_exact_failure_preserves_candidate_without_resource_credit(self):
        prior, values, rows = fixture()
        phase = M["validate"](prior, values, rows)
        self.assertEqual(phase["InvocationID"], I)
        self.assertEqual(phase["candidate"], prior["failed_phase"]["candidate"])
        self.assertEqual(phase["resource_credit_bytes"], 0)
        self.assertFalse(phase["source_checkpoint_exists"])

    def test_wrong_journal_cause_generation_or_lease_is_rejected(self):
        prior, values, rows = fixture()
        for path, changed in [
            (("failed", "error"), "semantic mismatch"), (("failed", "iid"), P),
            (("worker_sample", "window", "leases_worker"), {}), (("worker_sample", "stage"), "controller"),
            (("cadence", "error"), "other"), (("started", "r2_mutations"), True),
            (("intent", "review_sha256"), "unexpected"), (("submitted", "manager_start_cursor"), M["EXIT"]),
        ]:
            with self.subTest(path=path):
                v = copy.deepcopy(values)
                target = v
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = changed
                with self.assertRaises(ValueError):
                    M["validate"](prior, v, rows)
        for key, changed in (("EXIT_STATUS", "0"), ("__CURSOR", "foreign"), ("_PID","2")):
            with self.assertRaises(ValueError):
                M["validate"](prior, values, [rows[0], dict(rows[1], **{key: changed})])


if __name__ == "__main__":
    unittest.main()
