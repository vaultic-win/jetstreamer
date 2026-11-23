"""Counterexamples for historical V5m fixture identity, census rejection and retained charges."""
import copy
from pathlib import Path
import runpy
import unittest

M = runpy.run_path(str(Path(__file__).with_name("v5m_stopped.py")))
I, P, U = (M[k] for k in ("IID", "PREV", "UNIT"))
ref = M["ref"]


def fixture():
    old_exit = {"_BOOT_ID": "boot"}
    prior = dict(original_pid1_exit=old_exit, old_manager={"InvocationID": P},
                 reader=dict(path="/reader", sha256="image"), retained_inputs=[{"path": "/candidate"}],
                 failed_phase={"candidate": {"bytes": 105610995833}, "InvocationID": P})
    fleet = {"path": "/root-fleet", "sha256": "older"}
    argv = ["submit", "--", "/reader", "recover-full-output", fleet["path"], fleet["sha256"], "image"]
    intent = dict(argv=argv, fleet=fleet, review_sha256=M["REVIEW"], original=old_exit,
                  preflight={"quote_provider": {"sha256": M["DSHA"]}})
    submit = dict(argv=argv, invocation_id=I, manager_start_cursor=M["BIRTH"])
    parent = dict(pid=1416212, start_ticks=379174913)
    win = dict(native_parent=parent, native_child=dict(pid=1416486, start_ticks=379177645),
               leases_parent=dict.fromkeys(M["LEASES"], 5), leases_worker=dict.fromkeys(M["LEASES"], 4),
               recovery=ref("recovery"))
    sample = dict(stage="leased-worker", rchar=1024, sample_unix_ns=2000000000, source=ref("recovery"),
                  invocation_id=I, manager_start_cursor=M["BIRTH"], dispatch_seal_sha256=M["DSHA"],
                  submission=ref("submitted"), intent=ref("intent"), window=win, image_sha256="image")
    started = dict(iid=I, file="/candidate", image="image", r2_mutations=False,
                   fresh_fit={"phase145": dict(invocation_id=I, stage="controller", window=dict(native_parent=parent))})
    reg = dict(terminal=ref("cadence"), config={"sha256": "5b1796b7e8cec8e246f032b5200bfbf8f7a5418b592378c5aefc388237da4a39"})
    cut = dict(error="native HOST RSS unavailable",
               failed_sample={"sha256": "12c6e0c8aeebf47eec61587448cfc921d149fc4584eee15786a3a2416b38d551"})

    def guard(iid, count, timestamp):
        return dict(guard_invocation_id=iid, producer_invocation_id="913443d7f9f44d7e9d3e0eec420acfab",
                    producer={"cgroup": "/system.slice/" + M["PRODUCER"]}, trip_reason=None,
                    recorded_unix_seconds=timestamp,
                    root_physical_observation={"first": {"vanished_entries": count}, "second": {"vanished_entries": 0}})

    error = (f"live guard refused the registered hold: guard {M['PRODUCER']} measured remaining 143612534784 "
             f"from {ref('previous_guard')}; new {ref('rejected_guard')} has vanished counts 1/0")
    values = dict(intent=intent, submitted=submit, argv=argv, recovery=started, worker_sample=sample,
                  failure=dict(iid=I, at=7, error=error), registered=reg, cadence=cut,
                  last_accepted={"previous_Root_operational_review": fleet},
                  rejected_sample={"host_resident_memory": {"before": {"status": "unavailable"}, "after": {"status": "observed"}}},
                  previous_guard=guard(M["GUARD0"], 0, 3), rejected_guard=guard(M["GUARD1"], 1, 6))
    mgr = dict(_PID="1", _BOOT_ID="boot", UNIT=U, INVOCATION_ID=I)
    rows = [dict(mgr, MESSAGE_ID="39f53479d3a045ac8e11786248231fbf", __CURSOR=M["BIRTH"],
                 __REALTIME_TIMESTAMP="1000000", MESSAGE=f"Started {U} - " + " ".join(argv[2:]) + "."),
            dict(mgr, MESSAGE_ID="98e322203f7a4ed290d09fe03c09fe15", __CURSOR=M["EXIT"],
                 __REALTIME_TIMESTAMP="7000100", COMMAND="ExecStart", EXIT_STATUS="1", EXIT_CODE="exited")]
    return prior, values, rows


class OriginalClosure(unittest.TestCase):
    def test_retains_candidate_and_has_no_resource_credit(self):
        p, values, rows = fixture()
        result = M["validate"](p, values, rows)
        self.assertEqual((result["candidate"], result["resource_credit_bytes"], result["retry_worker"]),
                         (p["failed_phase"]["candidate"], 0, None))
        self.assertEqual(result["InvocationID"], I)
        self.assertFalse(result["source_checkpoint_exists"])

    def test_wrong_generation_lease_guard_or_failed_clock_is_rejected(self):
        p, values, rows = fixture()
        for path, change in (
            (("worker_sample", "window", "leases_parent"), {}), (("worker_sample", "stage"), "controller"),
            (("failure", "iid"), P), (("failure", "error"), "other"),
            (("intent", "review_sha256"), "other"), (("recovery", "r2_mutations"), True),
            (("registered", "terminal"), {}), (("last_accepted", "previous_Root_operational_review"), {}),
            (("rejected_sample", "host_resident_memory", "before", "status"), "observed"),
            (("rejected_guard", "root_physical_observation", "first", "vanished_entries"), 0),
            (("previous_guard", "trip_reason"), "stress"), (("rejected_guard", "producer_invocation_id"), "foreign"),
        ):
            with self.subTest(path=path):
                mutated = copy.deepcopy(values)
                ptr = mutated
                for k in path[:-1]:
                    ptr = ptr[k]
                ptr[path[-1]] = change
                with self.assertRaises(ValueError):
                    M["validate"](p, mutated, rows)
        for name, value in (("EXIT_STATUS", "0"), ("__CURSOR", M["BIRTH"]), ("_PID", "2")):
            with self.assertRaises(ValueError):
                M["validate"](p, values, [rows[0], dict(rows[1], **{name: value})])


if __name__ == "__main__":
    unittest.main()
