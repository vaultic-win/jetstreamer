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
                self.assertEqual(fn(Status()), (done, e))
                (base / ".tmp36MvkN").touch()
                with self.assertRaisesRegex(ValueError, "unverified original paid archive promotion"):
                    fn(Status())
                (base / ".tmp36MvkN").unlink()
                record("failed", {"iid": gen, "error": "incomplete"})
                with self.assertRaisesRegex(ValueError, "unverified original paid archive promotion"):
                    fn(Status())
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

    def test_unregistered_controller_and_phase_members(self):
        self.assertIsNone(phase["inspect"](Status(), None, {"MainPID":"0"}, (), 145, None, {}))
        with self.assertRaisesRegex(ValueError, "extra full verifier"):
            phase["ordinary_full"](Status(), 1, [10001,10002], "", {})

if __name__ == "__main__":
    unittest.main()
