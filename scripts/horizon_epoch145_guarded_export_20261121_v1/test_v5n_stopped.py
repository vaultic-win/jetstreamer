"""Exercise the V5n terminal quote's provenance and no-credit contract."""
from copy import deepcopy
from pathlib import Path
import runpy
import unittest

M = runpy.run_path(str(Path(__file__).with_name("v5n_stopped.py")))
IID, PREV, UNIT = (M[key] for key in ("IID", "PREV", "UNIT"))
ref = M["ref"]


def fixture():
    prior_exit = {"_BOOT_ID": "boot"}
    candidate = {"bytes": 105610995833, "inode": 103237059}
    seal = {"path": "/seal", "sha256": "seal"}
    old_failure = {"path": "/old-failure", "sha256": "old-failure"}
    prior = dict(original_pid1_exit=prior_exit, old_manager={"InvocationID": PREV},
                 reader=dict(path="/reader", sha256="image"), retained_inputs=[{"path": "/candidate"}],
                 seal=seal, failed_phase=dict(InvocationID=PREV, candidate=candidate, failure=old_failure))
    fleet = {"path": "/root-fleet", "sha256": "fleet"}
    argv = ["systemd-run", "--", "/reader", "recover-full-output", fleet["path"], fleet["sha256"], "image"]
    window = dict(native_parent=M["PARENT"], continuity_seal=seal, guard_walk_failure=old_failure)
    startup = dict(iid=IID, file="/candidate", image="image", r2_mutations=False,
                   initial={"fleet": fleet}, prior_frozen_recovery={
                       "failed_preincident_verifier": {"original_candidate": candidate}},
                   fresh_fit=dict(fleet=fleet, phase145=dict(invocation_id=IID, stage="controller", window=window)))
    sample = dict(invocation_id=IID, stage="leased-worker", rchar=1024, sample_unix_ns=3_000_000_000,
                  source=ref("recovery"), intent=ref("intent"), submission=ref("submitted"),
                  manager_start_cursor=M["BIRTH"], dispatch_seal_sha256=M["DSHA"], image_sha256="image",
                  window=dict(window, native_child=M["CHILD"], recovery=ref("recovery"),
                              leases_parent=dict.fromkeys(M["LEASES"], 5),
                              leases_worker=dict.fromkeys(M["LEASES"], 3)))
    fail = dict(iid=IID, at=7, error="complete 145 capacity observation failed exit status: 1: Traceback "
                f"\n{M['PROVIDER']}\nbuild_159_price.py\nValueError: insufficient HOME or general-slot memory")
    values = dict(intent=dict(argv=argv, fleet=fleet, review_sha256=M["REVIEW"],
                  original=prior_exit, preflight={"quote_provider": {"sha256": M["DSHA"]}}),
                  submitted=dict(argv=argv, invocation_id=IID, manager_start_cursor=M["BIRTH"]),
                  argv=argv, recovery=startup, worker_sample=sample, failure=fail)
    manager = dict(_PID="1", _BOOT_ID="boot", UNIT=UNIT, INVOCATION_ID=IID)
    rows = [dict(manager, MESSAGE_ID="39f53479d3a045ac8e11786248231fbf", __CURSOR=M["BIRTH"],
                 __REALTIME_TIMESTAMP="1000000", MESSAGE=f"Started {UNIT} - " + " ".join(argv[2:]) + "."),
            dict(manager, MESSAGE_ID="98e322203f7a4ed290d09fe03c09fe15", __CURSOR=M["EXIT"],
                 __REALTIME_TIMESTAMP="7000100", COMMAND="ExecStart", EXIT_CODE="exited", EXIT_STATUS="1")]
    return prior, values, rows


class StoppedV5n(unittest.TestCase):
    def test_retains_frozen_candidate_and_all_charges(self):
        prior, values, rows = fixture()
        phase = M["validate"](prior, values, rows)
        self.assertEqual(phase["candidate"], prior["failed_phase"]["candidate"])
        self.assertEqual(phase["InvocationID"], IID)
        self.assertEqual(phase["resource_credit_bytes"], 0)
        self.assertFalse(phase["source_checkpoint_exists"])
        self.assertIsNone(phase["retry_worker"])

    def test_refuses_changed_admission_recovery_or_failure(self):
        prior, expected, rows = fixture()
        for path, value in [
            (("intent", "review_sha256"), "other"),
            (("recovery", "r2_mutations"), True),
            (("recovery", "file"), "/changed-candidate"),
            (("recovery", "fresh_fit", "fleet"), {}),
            (("worker_sample", "window", "leases_parent"), {}),
            (("worker_sample", "window", "continuity_seal"), {}),
            (("worker_sample", "sample_unix_ns"), 8_000_000_000),
            (("failure", "iid"), PREV),
            (("failure", "error"), "unexpected exit cause"),
        ]:
            with self.subTest(path=path), self.assertRaises(ValueError):
                values = deepcopy(expected)
                dst = values
                for key in path[:-1]:
                    dst = dst[key]
                dst[path[-1]] = value
                M["validate"](prior, values, rows)

    def test_refuses_different_native_exit(self):
        prior, values, rows = fixture()
        for name, value in (("EXIT_STATUS", "0"), ("__CURSOR", M["BIRTH"]), ("_PID", "2"),
                            ("__REALTIME_TIMESTAMP", "8000000")):
            with self.subTest(name=name), self.assertRaises(ValueError):
                M["validate"](prior, values, [rows[0], dict(rows[1], **{name: value})])


if __name__ == "__main__":
    unittest.main()
