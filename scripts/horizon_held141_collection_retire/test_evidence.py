"""Regression checks for the fixed 141 remote receipt and terminal-unit gates."""
import copy
import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("evidence_gate", Path(__file__).with_name("evidence_gate.py"))
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class CompletionGate(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)
        stub = patch.object(gate, "STREAM", self.path)
        stub.start()
        self.addCleanup(stub.stop)
        self.members = [{"name": "0001.sst", "bytes": 12, "sha256": "fixture"}]
        self.start = {"started": 1.0, "unit_invocation": gate.IID, "etag": gate.ETAG}
        self.final = dict(self.start, verified=2.0, delivered_compressed_bytes=gate.BODY_BYTES,
                          verified_member_table_sha256=self.write("VERIFIED_MEMBERS", self.members),
                          verifier_result={"compressed_bytes": gate.BODY_BYTES,
                              "source_sha256": gate.BODY_HASH, "collection_receipt_sha256": gate.COLLECTION_SHA,
                              "files": 6094, "verified_member_bytes": gate.LOGICAL, "restored_bytes": 0,
                              "staged_directory": None, "remote_mutations": False})
        self.notice = {"_PID": "1", "UNIT": gate.UNIT, "INVOCATION_ID": gate.IID,
                       "MESSAGE_ID": "7ad2d189f7e94e70a38c781354912448",
                       "MESSAGE": gate.UNIT + ": Deactivated successfully.", "__REALTIME_TIMESTAMP": "2000100"}
        self.fields = "MainPID=0\nControlPID=0\nJob=\nInvocationID=\nResult=success\nExecMainStatus=0\nActiveState=inactive\nSubState=dead\nLoadState=not-found\n"

    def write(self, name, doc):
        data = json.dumps(doc).encode()
        (self.path / (name + ".json")).write_bytes(data)
        return hashlib.sha256(data).hexdigest()

    def check(self, final=None, notice=None):
        digest = self.write("COMPLETE", self.final if final is None else final)
        with patch.object(gate.subprocess, "check_output", side_effect=[self.fields, json.dumps(self.notice if notice is None else notice)]):
            return gate.check_remote_receipt({"complete_sha256": digest}, self.members, self.start)

    def test_full_bound_receipt_accepts_exact_pid1_event_after_transient_gc(self):
        self.assertEqual(self.check()[0], self.final)

    def test_incomplete_or_different_object_and_member_proof(self):
        for bad in [dict(self.final, etag="other"), dict(self.final, unit_invocation="other"),
                    dict(self.final, delivered_compressed_bytes=1),
                    dict(self.final, verifier_result=dict(self.final["verifier_result"], files=6093))]:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                self.check(bad)
        final=copy.deepcopy(self.final)
        final["verified_member_table_sha256"] = self.write("VERIFIED_MEMBERS", [])
        with self.assertRaisesRegex(ValueError, 'full member table'):
            self.check(final)

    def test_pending_status_wrong_or_missing_success_notice(self):
        for key, value in [("__REALTIME_TIMESTAMP", "1900000"), ("INVOCATION_ID", "other"),
                           ("UNIT", "other"), ("_PID", "1234"), ("MESSAGE", "Failed")]:
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'native success'):
                self.check(notice=dict(self.notice, **{key: value}))
        self.fields = self.fields.replace('MainPID=0', 'MainPID=1234')
        with self.assertRaisesRegex(ValueError, 'still owns input'):
            self.check()

    def test_progress_without_terminal_receipt_is_insufficient(self):
        self.write('progress', self.final)
        with self.assertRaises(FileNotFoundError):
            gate.check_remote_receipt({'complete_sha256': '00'*32}, self.members, self.start)


if __name__ == "__main__":
    unittest.main()
