"""Exercise lost journal order, the accepted guard window and the conditional event protocol."""

import hashlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import correct162
import initial162
import progress162

SELECT = {"_SYSTEMD_UNIT":progress162.UNIT, "_SYSTEMD_INVOCATION_ID":"a"*32, "_BOOT_ID":"b"*32, "_PID":"12"}


def point(slot, txs, stamp):
    return dict(SELECT, MESSAGE=f"block slot {slot} total_txs={txs}", __REALTIME_TIMESTAMP=str(stamp),
                __MONOTONIC_TIMESTAMP=str(stamp), __CURSOR="cursor-" + str(stamp))


class Windows(unittest.TestCase):
    def setUp(self):
        self.rows = [point(69_984_000, 5, 2_000_000), point(69_984_010, 25, 3_000_000),
                     point(69_984_020, 50, 4_000_000)]
    def measure(self):
        return progress162.work(self.rows, SELECT, 1, 5, 2_000_000)

    def test_advances_after_worker_start(self):
        self.rows.insert(0, point(69_984_000, 0, 1_000_000))
        report = self.measure()
        self.assertEqual((report["slot_delta"], report["transaction_delta"], report["elapsed_seconds"]), (20, 45, 2))
        self.assertEqual(report["matching_markers"], 3)
    def test_counter_reset_and_stall_do_not_claim_progress(self):
        self.rows[1]["MESSAGE"] = "block slot 69984010 total_txs=99"
        self.assertIsNone(self.measure())
        self.rows = self.rows[:1]
        self.assertIsNone(self.measure())
    def test_foreign_pid_and_outside_cutoff_rejected(self):
        self.rows[-1]["_PID"] = "13"
        with self.assertRaisesRegex(ValueError, "foreign"):
            self.measure()
        self.rows[-1] = point(69_984_020, 50, 5_000_001)
        with self.assertRaisesRegex(ValueError, "window"):
            self.measure()
    def test_newest_first_initial_read(self):
        raw = b"\n".join(json.dumps(r).encode() for r in reversed(self.rows))
        row = dict(worker={"pid":14,"start_ticks":10},actor={"producer_pid":12,"boot_id":"b"*32},
                   guard={"sha256":"c"*64},producer_invocation_id="a"*32)
        with patch("subprocess.check_output", return_value=raw), patch("time.monotonic_ns", return_value=4_000_000_000):
            progress = initial162.journal_progress(progress162.UNIT, row)
        self.assertEqual((progress["first"]["transactions"], progress["last"]["transactions"]), (5, 50))

    def test_supplement_changes_only_wire_view(self):
        original = {"status":"unavailable", "observation":None}
        row = dict(epoch=162,native_diagnostic=original,guard={"sha256":"a"},held_owner={"sha256":"b"},worker={"pid":14},
                   observer={"sha256":"c"},transaction_replay_claimed=True)
        proof = {k:row[k] for k in ("guard","held_owner","worker","observer")}
        row["private162_journal_progress"] = dict(proof,useful_work=self.measure())
        projected = progress162.wire_row(row)
        self.assertEqual(projected["native_diagnostic"]["observation"]["useful_work"], self.measure())
        self.assertIs(row["native_diagnostic"], original)
        row["guard"] = {"sha256":"d"}
        with self.assertRaisesRegex(ValueError,"foreign"):
            progress162.wire_row(row)


class Exchange(unittest.TestCase):
    def setUp(self):
        self.mods = SimpleNamespace(initial=initial162)
        before = {"phase":"verification"}
        after = {"phase":"replay"}
        self.old = '"' + '1'*32 + '"'
        self.new = '"' + hashlib.md5(initial162.body(after)).hexdigest() + '"'
        self.value = self.old, initial162.body(before)
        self.p = dict(key=initial162.KEY,epoch=162,conditional_header="If-Match",before_status=before,after_status=after,
                      before_etag=self.old,before_sha256=initial162.digest(initial162.body(before)),
                      after_sha256=initial162.digest(initial162.body(after)))
        self.puts = 0
        self.drop = False
    def get(self,e):
        self.assertEqual(e,162)
        return self.value
    def put(self,e,t,raw):
        self.assertEqual((e,t),(162,self.old))
        self.puts += 1
        self.value = self.new,raw
        if self.drop:
            raise ConnectionError()
        return self.new
    def test_lost_response_and_repeat(self):
        self.drop = True
        a = correct162.exchange(self.mods,self,self.p,lambda:None)
        self.assertEqual(a,correct162.exchange(self.mods,self,self.p,lambda:None))
        self.assertTrue(a["authenticated_readback"])
        self.assertEqual(self.puts,1)
    def test_different_remote_and_recheck_failure(self):
        self.value = ('"' + '3'*32 + '"',self.value[1])
        with self.assertRaisesRegex(ValueError,"changed"):
            correct162.exchange(self.mods,self,self.p,lambda:None)
        self.value = self.old,self.value[1]
        def changed():
            raise ValueError("owner changed")
        with self.assertRaisesRegex(ValueError,"owner"):
            correct162.exchange(self.mods,self,self.p,changed)
        self.assertEqual(self.puts,0)


if __name__ == "__main__":
    unittest.main()
