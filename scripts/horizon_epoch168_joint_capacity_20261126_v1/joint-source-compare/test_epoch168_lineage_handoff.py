import contextlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import epoch168_lineage_handoff as handoff


class NativeSelectionTests(unittest.TestCase):
    def setUp(self):
        stack = self.enterContext(contextlib.ExitStack())
        root = Path(stack.enter_context(tempfile.TemporaryDirectory()))
        self.stdout = root / "RESULT.stdout"
        self.copy = root / "SELECTED_PREFIX.json"
        archive = root / "source.jet"
        archive.touch()
        m = archive.stat()
        active_ref = {"sha256": handoff.ACTIVE_SHA}
        intent_ref = {"path": str(root / "START_INTENT.json"), "sha256": "a" * 64}
        self.seal = {"sha256": "c" * 64}
        self.original = {"path": str(self.stdout), "sha256": "d" * 64}
        self.selected = dict(self.original, path=str(self.copy))
        self.event = {"_PID": "1", "_UID": "0", "UNIT": handoff.SELECTOR_UNIT,
                      "INVOCATION_ID": handoff.SELECTOR_IID, "MESSAGE_ID": handoff.SUCCESS}
        active = {
            "intent": intent_ref, "unit": handoff.SELECTOR_UNIT, "invocation_id": handoff.SELECTOR_IID,
            "source_identity": {"device": m.st_dev, "inode": m.st_ino, "length": m.st_size,
                                "mtime_ns": m.st_mtime_ns, "ctime_ns": m.st_ctime_ns, "links": m.st_nlink},
        }
        records = {
            root / "ACTIVE.json": (active_ref, active),
            root / "START_INTENT.json": (intent_ref, {
                "deployment": self.seal, "run_argv": ["--property=StandardOutput=file:" + str(self.stdout)],
            }),
            self.stdout: (self.original, {"physical_archive_bytes_written": 0}),
        }
        stack.enter_context(patch.multiple(handoff, SELECTOR_STATE=root, RETRY4=archive))
        stack.enter_context(patch.object(handoff, "bound_json", side_effect=records.__getitem__))
        stack.enter_context(patch.object(handoff, "bound", return_value=(self.selected, b"")))
        self.journal = stack.enter_context(patch.object(handoff, "journal", return_value=[self.event]))

    def test_original_and_collectors_copy_bind_the_same_stdout(self):
        for path, ref in ((self.stdout, self.original), (self.copy, self.selected)):
            selected, proof = handoff.completed_selection(path, self.seal)
            self.assertEqual(selected, ref)
            self.assertEqual(proof["stdout"], self.original)
            self.assertEqual(proof["pid1_event"], self.event)

    def test_changed_copy_is_rejected(self):
        self.selected["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "differs from the original"):
            handoff.completed_selection(self.copy, self.seal)

    def test_another_invocation_cannot_finish_the_selection(self):
        self.journal.return_value = [dict(self.event, INVOCATION_ID="0" * 32)]
        with self.assertRaisesRegex(ValueError, "successful PID1"):
            handoff.completed_selection(self.stdout, self.seal)
