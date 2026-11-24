"""Exercise the new phase observer on native PIDs and a linked promotion fixture."""
from pathlib import Path
import hashlib
import json
import os
import runpy
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

phase = runpy.run_path(os.environ.get("POST_PHASE_UNDER_TEST", str(Path(__file__).with_name("incident-post-phase.py"))))
class Status:
    @staticmethod
    def need(value, message):
        if not value:
            raise ValueError(message)

    @staticmethod
    def same_file(first, second):
        return os.path.samefile(first, second)

    @staticmethod
    def read(path, digest=None):
        raw = path.read_bytes()
        got = hashlib.sha256(raw).hexdigest()
        Status.need(digest is None or got == digest, "fixture SHA")
        return json.loads(raw), {"path": str(path), "sha256": got}

    @staticmethod
    def iid(value):
        return len(value) == 32 and all(c in "0123456789abcdef" for c in value)

    @staticmethod
    def bound(binding, path):
        Status.need(binding["path"] == str(path), "fixture receipt path")
        return Status.read(path, binding["sha256"])[0]

    @staticmethod
    def process(pid):
        p = Path("/proc") / str(pid)
        row = (p / "stat").read_text().rsplit(") ", 1)[1].split()
        return int(row[1]), int(row[19]), (p / "cgroup").read_text().strip()

class PostPhaseTest(unittest.TestCase):
    def test_expected_reader_and_semantic_predecessor(self):
        if "POST_PHASE_UNDER_TEST" in os.environ:
            self.assertTrue(phase["TIMEOUT_SUCCESSOR"])
            if phase["TIMER_SUCCESSOR"]:
                self.assertEqual(phase["PKG"].name, Path(os.environ["POST_PHASE_UNDER_TEST"]).parent.name)
                self.assertEqual(phase["IMAGE"], phase["PKG"] / "export145")
                name = "V5E_ACTUAL_ADVANCING_WORKER.json"
                if phase["FIXTURE_SUCCESSOR"]:
                    name = ("V5F_RETRY1" if phase["SAME_IMAGE_RETRY"] else "V5F") + "_ACTUAL_ADVANCING_WORKER.json"
                self.assertEqual(phase["ADVANCING_NAME"], name)
                self.assertEqual(phase["PIPE"].parent.name, "fast-range-residency-0f29fd116ef5")
                return
            if phase["RETRIED_SEMANTIC"]:
                self.assertEqual(phase["BOOTSTRAP"], "e6551a0bb8a14b989902e15c9ecc0751")
                self.assertEqual(phase["ADVANCING"], "3a41dac31746938b482133b9ff224f9d9d821569cc16f63c83f872fe907c13e0")
                self.assertEqual(phase["ADVANCING_NAME"], "V5D_RETRY1_ACTUAL_ADVANCING_WORKER.json")
            else:
                self.assertEqual(phase["BOOTSTRAP"], "d37f36f898a44932a19fd50d7014a6fe")
                self.assertEqual(phase["ADVANCING"], "6235fbd8e36064d57a9cd6b7af2ad0d05ce8b41766134cde7be7337ebc133d76")
            self.assertEqual(phase["PIPE"].parent.name, "public-rseek-reconnect-56bf2bf0937f")

    def test_full_native_read_and_foreign_command(self):
        fn = phase["ordinary_full"]
        s = Status()
        original = fn.__globals__.copy()
        try:
            with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as temp:
                fifo = Path(temp) / "fixture.jet"
                os.mkfifo(fifo)
                fn.__globals__.update(ARCHIVE=fifo, CGROUP=Status.process(os.getpid())[2][3:])
                with subprocess.Popen(["/usr/bin/sha256sum", "--", str(fifo)], stdout=subprocess.DEVNULL) as worker:
                    try:
                        deadline = time.monotonic() + 3
                        while phase["argv"](worker.pid) != ["/usr/bin/sha256sum", "--", str(fifo)]:
                            self.assertLess(time.monotonic(), deadline)
                            time.sleep(0.005)
                        result = fn(s, os.getpid(), [worker.pid], "f"*32, {"expected_output_provenance_sha256":"0"*64})
                        self.assertEqual(result[0][:2], [worker.pid, Status.process(worker.pid)[1]])
                        fn.__globals__["ARCHIVE"] = fifo.with_name("different")
                        with self.assertRaisesRegex(ValueError, "foreign full verification child"):
                            fn(s, os.getpid(), [worker.pid], "f"*32, {"expected_output_provenance_sha256":"0"*64})
                    finally:
                        worker.terminate()
        finally:
            fn.__globals__.update(original)

    def test_successful_promotion_chain_and_foreign_candidate(self):
        if phase["ENCODED_POST"]:
            self.skipTest("encoded completion has its own invocation fixture")
        fn = phase["completion"]
        before = fn.__globals__.copy()
        gen = phase["BOOTSTRAP"]
        try:
            with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as name:
                base = Path(name)
                folder = base / "state" / gen
                folder.mkdir(parents=True)
                pub = base / "epoch-145.jet"
                def save(path, doc):
                    path.write_text(json.dumps(doc))
                    return Status.read(path)[1]
                def record(label, doc):
                    return save(folder / (label + ".json"), doc)
                started = record("recovery-started", {"iid": gen, "r2_mutations": False})
                proof = save(base / phase["ADVANCING_NAME"],
                             {"invocation_id": gen, "start": started})
                build = None
                if phase["FIXTURE_SUCCESSOR"]:
                    failed = "a99ed8b51e8a482b805b8a36a11b2700"
                    old = folder.parent / failed
                    failure = {"path": str(old / "failed.json"),
                               "sha256": "da29d82a4349444ccc15e0be020aa12918ae5bbb4634f9b62e13cc83a93c5f43"}
                    recovery = {"path": str(old / "recovery-started.json"),
                                "sha256": "6e06652ea695717b18fc29b955e463da8dc2dde16f8173da552df707c478e624"}
                    prior = {"current_boot_failure":{"failure": failure}, "prior_started": recovery,
                             "source_checkpoint_exists":False, "resource_credit_bytes":0,
                             "original_candidate":{"inode":103237059, "bytes":105610995833}}
                    started = record("recovery-started", {"iid":gen, "r2_mutations":False,
                         "file":str(base / ".tmp36MvkN"), "prior_frozen_recovery":{"failed_qualification_census":prior}})
                    outer = {"schema":"horizon-145-retry-after-fixture-census-intent-v1", "old":failed,
                             "failure":failure, "recovery":recovery}
                    if phase["SAME_IMAGE_RETRY"]:
                        owner = "50af3d8ab5da47e8bdc2828feab53908"
                        outer.update(old=owner,
                            failure={"path":str(folder.parent / owner / "failed.json"),
                                     "sha256":"38d828362fed1910cc60c605200380576c165168738dbf00520ce2b2522a0fcd"},
                            recovery={"path":str(folder.parent / owner / "recovery-started.json"),
                                      "sha256":"3dd15e821b9972e3f7f69f787d585bbe86fd9898ec1df5e8e5d08cab14231bb8"},
                            previous_advancement={"path":str(base / "V5F_ACTUAL_ADVANCING_WORKER.json"),
                                      "sha256":"a2a888054492a2be68c5e332ae36daa070b9688c143005cbc97e5cace7cfd496"})
                    intent = save(base / (phase["SEMANTIC_PREFIX"] + "_START_INTENT.json"), outer)
                    manager = save(base / (phase["SEMANTIC_PREFIX"] + "_ACTUAL_MANAGER.json"), {"intent":intent, "parent_pid":91,
                         "parent_start_ticks":123, "new":{"Id":phase["UNIT"], "InvocationID":gen}})
                    sample = dict(parent_pid=91, parent_ticks=123, child_pid=92, child_ticks=127,
                         source_inode=100214450, cgroup="/sys/fs/cgroup"+phase["CGROUP"], native_leases=list(range(7)),
                         time_ns=1000, worker_cpu_ticks=10, source_offset=2500000)
                    observations = [sample,dict(sample,time_ns=2000,worker_cpu_ticks=13,source_offset=5000000)]
                    proof = save(base / phase["ADVANCING_NAME"], {"invocation_id":gen,"start":started,
                                 "manager":manager, "observations":observations})
                    build = dict(prior_phase=proof,semantic_start=started,semantic_manager=manager,
                                 semantic_intent=intent,old_start=recovery,old_failure=failure,
                                 original_candidate=prior["original_candidate"])
                    if phase["SAME_IMAGE_RETRY"]:
                        build.update(retry_failure=outer["failure"], retry_start=outer["recovery"])
                elif phase["TIMER_SUCCESSOR"]:
                    old_failure = {"sha256": "9ef9c938290ea2b43d3b2ce4aa617f08b33f4c893961e63f53ba3f48768e215f"}
                    old_start = {"sha256": "2" * 64}
                    intent = save(base / "V5E_START_INTENT.json", {
                        "schema": "horizon-145-retry-after-timer-inspection-intent-v1",
                        "old": "e6551a0bb8a14b989902e15c9ecc0751", "failure": old_failure, "recovery": old_start})
                    manager = save(base / "V5E_ACTUAL_MANAGER.json", {"intent": intent, "new": {"InvocationID": gen}})
                    proof = save(base / phase["ADVANCING_NAME"], {"invocation_id": gen, "start": started, "manager": manager})
                    build = {"prior_phase": proof, "old_failure": old_failure, "old_start": old_start}
                frozen = record("verified-frozen", {"iid": gen, "r2_mutations": False})
                original = "de6780b860b3467bae21fbd19176ca14"
                e = {"epoch": 145, "archive": str(pub), "archive_bytes": 105610995833,
                     "output_slot_count": 432000, "independent_output_reread_passed": True}
                extracted = record("extraction-complete", {"actor_iid": gen, "original_export": original,
                    "verified_frozen": frozen, "recovery_evidence": started,
                    "archive_publication_authorized": False, "extraction": e})
                done = record("complete", {"iid": gen, "receipt": extracted,
                              "recovered_from": original, "r2_mutations": False})
                fn.__globals__.update(STATE=folder.parent, PKG=base / phase["PKG"].name, ADVANCING=proof["sha256"],
                                      ARCHIVE=pub, OUTPUT=base)
                self.assertEqual(fn(Status(), build), (done, e))
                if phase["SAME_IMAGE_RETRY"]:
                    with self.assertRaisesRegex(ValueError, "different V5F same-image retry predecessor"):
                        fn(Status(), dict(build,retry_failure=failure))
                if phase["FIXTURE_SUCCESSOR"]:
                    with self.assertRaisesRegex(ValueError, "different V5F recovery"):
                        fn(Status(), dict(build, old_start={"sha256":"7"*64}))
                    with self.assertRaisesRegex(ValueError, "fixture receipt path"):
                        fn(Status(), dict(build, prior_phase=dict(proof,path=str(base / "V5E_ACTUAL_ADVANCING_WORKER.json"))))
                    same = save(base / phase["ADVANCING_NAME"], {"invocation_id":gen,"start":started,
                                "manager":manager,"observations":[sample,sample]})
                    with self.assertRaisesRegex(ValueError, "unproven V5F semantic progress"):
                        fn(Status(), dict(build,prior_phase=same))
                    save(base / phase["ADVANCING_NAME"], {"invocation_id":gen,"start":started,
                         "manager":manager,"observations":observations})
                elif phase["TIMER_SUCCESSOR"]:
                    with self.assertRaisesRegex(ValueError, "different original timer recovery"):
                        fn(Status(), dict(build, old_start={"sha256": "7"*64}))
                (base / ".tmp36MvkN").touch()
                with self.assertRaisesRegex(ValueError, "unverified original paid archive promotion"):
                    fn(Status(), build)
                (base / ".tmp36MvkN").unlink()
                record("failed", {"iid": gen, "error": "incomplete"})
                with self.assertRaisesRegex(ValueError, "unverified original paid archive promotion"):
                    fn(Status(), build)
                if phase["FOCUSED_SUCCESSOR"]:
                    second = "a" * 32
                    intent = save(base / "V5D_START_INTENT.json",
                                  {"schema": "horizon-145-focused-census-recovery-intent-v1", "old": gen})
                    manager = save(base / "V5D_ACTUAL_MANAGER.json", {"intent": intent, "new": {"InvocationID": second}})
                    second_state = folder.parent / second
                    second_state.mkdir()
                    second_start = save(second_state / "recovery-started.json", {"iid": second, "r2_mutations": False})
                    save(base / "V5D_ACTUAL_ADVANCING_WORKER.json",
                         {"invocation_id": second, "start": second_start, "manager": manager})
                    with self.assertRaisesRegex(ValueError, "ambiguous semantic predecessor"):
                        fn(Status())
                    (folder / "complete.json").unlink()
                    second_frozen = save(second_state / "verified-frozen.json", {"iid": second, "r2_mutations": False})
                    second_extraction = save(second_state / "extraction-complete.json",
                        {"actor_iid": second, "original_export": original, "verified_frozen": second_frozen,
                         "recovery_evidence": second_start, "archive_publication_authorized": False, "extraction": e})
                    second_done = save(second_state / "complete.json",
                        {"iid": second, "receipt": second_extraction, "recovered_from": original, "r2_mutations": False})
                    self.assertEqual(fn(Status()), (second_done, e))
                    save(base / "V5D_ACTUAL_MANAGER.json", {"intent": intent, "new": {"InvocationID": gen}})
                    with self.assertRaisesRegex(ValueError, "fixture SHA"):
                        fn(Status())
        finally:
            fn.__globals__.update(before)

    def test_encoded_completion_requires_the_bound_capture(self):
        if not phase["ENCODED_POST"]:
            self.skipTest("requires the encoded post profile")
        fn = phase["completion"]
        gen = "a" * 32
        with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as name:
            base = Path(name)
            pkg = base / "tools-v13l"
            pkg.mkdir()
            handoff = base / "v5r-name-handoff"
            handoff.mkdir()
            state = base / "state" / gen
            state.mkdir(parents=True)

            def save(path, doc):
                path.write_text(json.dumps(doc))
                return Status.read(path)[1]

            checker = pkg / "post-inputs"
            checker.write_text("fixture scope")
            save(pkg / "deployment-seal-receipt.json", {
                "destination": str(pkg),
                "sealer_sha256": "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3",
                "members": [{"name": "post-inputs", "mode": "0555",
                             "sha256": hashlib.sha256(checker.read_bytes()).hexdigest()}],
            })
            submission = save(handoff / "submission-result.json", {"invocation_id": gen})
            custody = save(handoff / "ACTUAL_ADVANCING_AND_136_CUSTODY.json", {
                "schema": "horizon-145-encoded-prefix-live-custody-v1",
                "manager": {"InvocationID": gen}, "submission": submission,
            })
            extraction = {"epoch": 145}
            extracted = save(state / "extraction-complete.json", {"extraction": extraction})
            done = save(state / "complete.json", {"receipt": extracted})
            selected = {"invocation_id": gen, "completion": done, "extraction": extracted}
            save(handoff / "semantic-completion.json", selected)
            build = {"encoded_prefix_custody": custody, "semantic_submission": submission}
            with patch.dict(fn.__globals__, PKG=pkg, STATE=state.parent, ENCODED_CUSTODY_SHA=custody["sha256"]):
                with patch.object(subprocess, "check_output", return_value=json.dumps(selected).encode()) as native:
                    self.assertEqual(fn(Status(), build), (done, extraction))
                    native.assert_called_once_with([checker, "inspect-semantic"], timeout=20)
                with patch.object(subprocess, "check_output", return_value=b"null"):
                    with self.assertRaisesRegex(ValueError, "different captured V5r completion"):
                        fn(Status(), build)
                with self.assertRaisesRegex(ValueError, "different encoded-prefix post build"):
                    fn(Status(), dict(build, semantic_submission={}))

    def test_unregistered_controller_and_phase_members(self):
        self.assertIsNone(phase["inspect"](Status(), None, {"MainPID":"0"}, (), 145, None, {}))
        with self.assertRaisesRegex(ValueError, "extra full verifier"):
            phase["ordinary_full"](Status(), 1, [10001,10002], "", {})

if __name__ == "__main__":
    unittest.main()
