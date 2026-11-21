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

phase = runpy.run_path(str(Path(__file__).with_name("incident-post-phase.py")))
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
    def process(pid):
        p = Path("/proc") / str(pid)
        row = (p / "stat").read_text().rsplit(") ", 1)[1].split()
        return int(row[1]), int(row[19]), (p / "cgroup").read_text().strip()

class PostPhaseTest(unittest.TestCase):
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
                proof = save(base / "V5_ACTUAL_ADVANCING_WORKER.json",
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
                fn.__globals__.update(STATE=folder.parent, PKG=base / "tools-v6", ADVANCING=proof["sha256"],
                                      ARCHIVE=pub, OUTPUT=base)
                self.assertEqual(fn(Status()), (done, e))
                (base / ".tmp36MvkN").touch()
                with self.assertRaisesRegex(ValueError, "unverified original paid archive promotion"):
                    fn(Status())
                (base / ".tmp36MvkN").unlink()
                record("failed", {"iid": gen, "error": "incomplete"})
                with self.assertRaisesRegex(ValueError, "unverified original paid archive promotion"):
                    fn(Status())
        finally:
            fn.__globals__.update(before)

    def test_unregistered_controller_and_phase_members(self):
        self.assertIsNone(phase["inspect"](Status(), None, {"MainPID":"0"}, (), 145, None, {}))
        with self.assertRaisesRegex(ValueError, "extra full verifier"):
            phase["ordinary_full"](Status(), 1, [10001,10002], "", {})

if __name__ == "__main__":
    unittest.main()
