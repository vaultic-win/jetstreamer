from copy import deepcopy
from pathlib import Path
import runpy
import unittest

HERE = Path(__file__).resolve().parent
b = runpy.run_path(str(HERE / "fixture_boundary.py"))
prior = runpy.run_path(str(HERE / "prestart_session.py"))
pin = lambda path: dict(path=str(path), sha256="b" * 64)
iid = "c" * 32


class Fixture(unittest.TestCase):
    def setUp(self):
        self.worker = pin(b["FAMILY"] / "V5F_ACTUAL_ADVANCING_WORKER.json")
        start = pin(b["STATE"] / iid / "recovery-started.json")
        mgr = pin(b["FAMILY"] / "V5F_ACTUAL_MANAGER.json")
        samples = [dict(parent_pid=2, parent_ticks=512, child_pid=10, child_ticks=515, source_inode=312,
                        cgroup="/sys/fs/cgroup/system.slice/" + b["UNIT"], source_offset=x, worker_cpu_ticks=x)
                   for x in (1, 10)]
        self.rows = {
            self.worker["path"]: dict(start=start, manager=mgr, invocation_id=iid, observations=samples,
                                      resource_credit_bytes=0),
            mgr["path"]: dict(parent_pid=2, parent_start_ticks=512, new=dict(Id=b["UNIT"], InvocationID=iid)),
            start["path"]: dict(iid=iid, r2_mutations=False, prior_frozen_recovery=dict(
                failed_qualification_census=dict(current_boot_failure=dict(failure=b["FAILURE"])))),
        }
        self.planref = pin(b["V7"] / "registered-production-plan.json")
        self.readyref = pin(b["DISPATCH"] / "READY.json")
        self.ready = dict(original_semantic_invocation=iid, schema="horizon-145-136-prestart-selector-ready-v1",
                          operation_lock=b["ORIGINAL_LOCK"].copy())
        self.ready["registered_provider"] = {"directory": str(b["V21"])}
        self.plan = dict(holding145_semantic_worker=self.worker)
        si = b["DISPATCH"]/"tools"
        self.ready["boundary_inspector"] = pin(si / "boundary-inspector")

        def package(path, members):
            ref = pin(path / "deployment-seal-receipt.json")
            self.rows[ref["path"]] = dict(schema="jetstreamer-sealed-deployment-receipt-v1", destination=str(path),
                sealer_sha256=b["SEALER"], remote_mutations=False, members=[
                    dict(name=name, mode=mode, sha256="b"*64) for name, mode in members])
            return ref

        self.ready["deployment"] = package(si, [("boundary-inspector", "0555")])
        post = b["V13"]
        self.plan["holding145_completion"] = dict(
            seal=package(post, [("incident-post-phase.py", "0444"), ("build-proof.json", "0444")]),
            build=pin(post/"build-proof.json"), adapter=pin(post/"incident-post-phase.py"))
        self.rows[str(post/"build-proof.json")] = dict(prior_phase=self.worker)

    def call(self):
        def provider(bind, package):
            self.assertEqual(package, b["V21"])
            if bind != {"directory": str(package)}:
                raise ValueError("stale provider")
            return package / "post-stop-fit"

        class Manual:
            def run_path(self, s):
                return s

        start = str(b["STATE"] / iid / "recovery-started.json")
        def sealed_read(ref):
            self.assertNotEqual(ref["path"], start)
            return self.rows[ref["path"]]
        def state_read(ref):
            self.assertEqual(ref["path"], start)
            return self.rows[ref["path"]]
        return b["prepare"](self.planref, self.plan, self.readyref, self.ready, sealed_read, state_read,
                            lambda path, sha: self.assertEqual(sha, "b"*64), provider, Manual())

    def test_selects_original_fixture_worker_post_and_registered_provider(self):
        result = self.call()
        self.assertEqual(result[0], iid)
        self.assertEqual(result[1], str(b["V21"] / "post-stop-fit"))
        self.assertEqual(result[2]["prior_phase"], self.worker)
        self.assertEqual(result[3], str(b["V13"] / "incident-post-phase.py"))

    def test_rejects_archived_v2_selector_v7_path_alias_and_stale_semantic(self):
        for path, key, val in (
            (self.readyref, "path", str(b["RUNTIME"] / "epoch145-phase-dispatch-20261122-v1/READY.json")),
            (self.planref, "path", str(b["RUNTIME"] / "epoch136-joint-writer-20261122-v6/registered-production-plan.json")),
            (self.ready, "original_semantic_invocation", b["OLD"]),
            (self.ready, "operation_lock", dict(b["ORIGINAL_LOCK"], inode=123)),
            (self.ready, "registered_provider", {"directory": "tools-v19"}),
            (self.rows[self.worker["path"]], "invocation_id", b["OLD"]),
            (self.rows[str(b["V13"] / "build-proof.json")], "prior_phase", pin(b["FAMILY"] / "V5E_ACTUAL_ADVANCING_WORKER.json")),
        ):
            old = deepcopy(path[key])
            with self.subTest(key=key, changed=val), self.assertRaises(ValueError):
                path[key] = val
                self.call()
            path[key] = old

    def test_ordinary_price_refuses_a_failed_or_different_semantic_worker(self):
        read = lambda row: self.rows[row["path"]]
        check = lambda phase: b["ordinary_phase"](self.plan, phase, read, None, None, None)
        check(dict(stage="leased-worker", invocation_id=iid))
        for bad in (dict(stage="leased-worker", invocation_id=b["OLD"]), dict(stage="controller", invocation_id=iid),
                    dict(ActiveState="failed", SubState="failed", MainPID="0", InvocationID=b["OLD"])):
            with self.subTest(phase=bad), self.assertRaises(ValueError):
                check(bad)

    def test_success_requires_the_selected_iid(self):
        def native(unit):
            return dict(ActiveState="inactive", SubState="dead", Job="", MainPID="0", ControlPID="0",
                        NRestarts="0", Result="success", ExecMainStatus="0")
        update = prior["holding_complete"]
        from unittest.mock import patch
        fake = lambda observer, build: (pin(b["STATE"] / b["OLD"] / "complete.json"), {"epoch":145})
        with patch.dict(update.__globals__, {"native": native, "HOLDING": "horizon-fixture-nonexistent-136-test.service"}):
            with self.assertRaisesRegex(ValueError, "wrong original"):
                update(fake(None,None)[0], {"completion": fake}, {}, None, iid)


if __name__ == "__main__":
    unittest.main()
