"""Recovery fixtures use an inert manager and never submit or reset a system service."""
from contextlib import nullcontext
import importlib.util
import json
import copy
import os
import runpy
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("dispatch145", Path(__file__).with_name("recovery_dispatch.py"))
dispatch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dispatch)

FIRST = {"path": "/fleet/first", "sha256": "a" * 64}
SECOND = {"path": "/fleet/second", "sha256": "b" * 64}
NEW = "e" * 32
ORIGINAL = {"InvocationID": dispatch.OLD, "MainPID": "0"}
MISSING = {"InvocationID": "", "MainPID": "0"}


class Fixture:
    def __init__(self):
        self.manager = ORIGINAL
        self.events = []
        self.crash = None
        self.resets = self.preflights = self.submissions = 0
        self.chain = [FIRST]
        self.source = "original"
        self.quoted = []

    def checkpoint(self, name):
        if self.crash == name:
            self.crash = None
            raise RuntimeError(name)

    def state(self):
        return self.manager, self.events

    def original(self, manager):
        if manager != ORIGINAL:
            raise ValueError("different origin")

    def absent(self, manager):
        if manager != MISSING:
            raise ValueError("different occupant")

    def check_intent(self, intent):
        if intent["argv"] != ["stock", "--", "verifier", FIRST["path"], FIRST["sha256"]]:
            raise ValueError("foreign frozen argv")

    def validate(self, intent):
        self.check_intent(intent)
        if self.source != intent["source"]:
            raise ValueError("replacement source")

    def prepare(self, fleet):
        self.preflights += 1
        self.checkpoint("before authentic preflight")
        return {"fleet": fleet, "source": self.source, "preflight": {"serial_handback": ["a", "b"]}, "argv": ["stock", "--", "verifier", fleet["path"], fleet["sha256"]]}

    def reset(self):
        self.checkpoint("before reset")
        self.resets += 1
        self.manager = MISSING
        self.checkpoint("after reset")

    def preflight_current(self, intent):
        return False

    def quote(self, intent):
        self.checkpoint("unfunded current fleet")
        self.quoted.append(self.chain[-1])
        return {"fleet": self.chain[-1]}

    def submit(self, argv):
        self.checkpoint("before submission")
        self.submissions += 1
        self.events.append({"MESSAGE_ID": dispatch.START, "INVOCATION_ID": NEW,
                            "MESSAGE": "Started " + dispatch.UNIT + " - " + " ".join(argv[2:]) + ".", "__CURSOR": "success"})
        self.manager = {"InvocationID": NEW, "MainPID": "0"}
        self.checkpoint("lost reply")

    accepted = dispatch.Host.accepted


class RecoveryTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name)
        self.host = Fixture()
        self.enterContext(patch.object(dispatch, "read", lambda path: (path.read_bytes(), {})))
        self.enterContext(patch.object(dispatch, "successors", lambda fleet: self.host.chain[self.host.chain.index(fleet):]))

    def run_step(self, lease=nullcontext, fleet=FIRST):
        return dispatch.advance(self.host, fleet, self.path, lease)

    def test_crashes_each_side_of_reset_and_submit(self):
        for fault in ("before reset", "after reset", "before submission", "lost reply"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                self.path, self.host = Path(directory), Fixture()
                self.host.crash = fault
                with self.assertRaisesRegex(RuntimeError, fault):
                    self.run_step()
                self.assertTrue((self.path / "submission-intent.json").is_file())
                self.assertEqual(self.run_step()["invocation_id"], NEW)
                self.assertEqual(self.run_step()["invocation_id"], NEW)
                self.assertEqual(self.host.preflights, 2 if fault == "before reset" else 1)
                self.assertEqual((self.host.resets, self.host.submissions), (1, 1))


    def test_interrupted_across_fleet_rotation_reprices_latest_but_submits_exact_original(self):
        self.host.crash = "after reset"
        with self.assertRaises(RuntimeError):
            self.run_step()
        self.host.chain.append(SECOND)
        result = self.run_step(fleet=SECOND)
        self.assertEqual(result["argv"][-2:], [FIRST["path"], FIRST["sha256"]])
        self.assertEqual(self.host.quoted, [SECOND])

    def test_no_intent_after_failed_native_preflight(self):
        self.host.crash = "before authentic preflight"
        with self.assertRaises(RuntimeError):
            self.run_step()
        self.assertEqual(list(self.path.iterdir()), [])
        self.assertEqual(self.host.manager, ORIGINAL)

    def test_quota_and_lease_failures_do_not_submit(self):
        self.host.crash = "unfunded current fleet"
        with self.assertRaises(RuntimeError):
            self.run_step()
        self.assertEqual(self.host.manager, MISSING)
        def occupied():
            raise BlockingIOError()
        with self.assertRaises(BlockingIOError):
            self.run_step(occupied)
        self.assertEqual(self.host.submissions, 0)
        self.assertEqual(self.run_step()["invocation_id"], NEW)

    def test_replaced_source_or_external_occupant(self):
        self.host.crash = "after reset"
        with self.assertRaises(RuntimeError):
            self.run_step()
        self.host.source = "different inode"
        with self.assertRaisesRegex(ValueError, "replacement source"):
            self.run_step()
        self.host.source = "original"
        self.host.manager = {"InvocationID": NEW, "MainPID": "10"}
        with self.assertRaisesRegex(ValueError, "different occupant"):
            self.run_step()
        self.assertEqual(self.host.submissions, 0)

    def test_external_unloaded_successor_retained_in_journal(self):
        self.host.crash = "after reset"
        with self.assertRaises(RuntimeError):
            self.run_step()
        self.host.events = [{"MESSAGE_ID": dispatch.START, "MESSAGE": "foreign", "INVOCATION_ID": NEW}]
        with self.assertRaisesRegex(ValueError, "before this dispatcher"):
            self.run_step()
        self.assertEqual(self.host.submissions, 0)

    def test_tampered_intent_after_reset(self):
        self.host.crash = "after reset"
        with self.assertRaises(RuntimeError):
            self.run_step()
        p = self.path / "submission-intent.json"
        value = json.loads(p.read_bytes())
        value["argv"].append("other")
        p.unlink()
        p.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, "foreign frozen"):
            self.run_step()
        self.assertEqual(self.host.submissions, 0)

    def test_price_rejects_foreign_failure_limits_or_unclosed_holding(self):
        historical = {k: k for k in ("candidate", "failure", "recovery", "retry_worker", "manager_exit",
                                      "source_checkpoint_exists", "resource_credit_bytes")}
        phase = dict(historical, Id=dispatch.UNIT, InvocationID="", ActiveState="inactive", SubState="dead", MainPID="0")
        holding = dict(stage="completed-copy", additional_reservation_bytes=0, resource_credit_bytes=0)
        price = dict(schema="horizon-incident-replay-fit-v1", epoch=145, fleet=FIRST, fits=True, candidate=None,
                     complete_cpu_quota_micros=64_000_000, complete_memory_plus_reserve_bytes=810_658_050_048,
                     available_HOME_bytes=2, complete_required_HOME_bytes=2, available_memory_bytes=3,
                     required_available_memory_bytes=3, resource_credit_bytes=0, replay_launch_authorized=False,
                     recorded_unix_seconds=int(time.time()), phase145=phase, registered_retry11_holding=holding,
                     registered_cold168_holding=holding)
        review = {"failed_phase": historical}
        dispatch.exact_price(price, FIRST, review)
        for bad in (dict(available_HOME_bytes=1), dict(available_memory_bytes=2), dict(phase145=dict(phase, manager_exit="other")),
                    dict(registered_cold168_holding=dict(holding, stage="copy-only")), dict(complete_cpu_quota_micros=1)):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                dispatch.exact_price(dict(price, **bad), FIRST, review)


class RetryLineageTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # The signed failure is unique to this host. The inert manager tests above
        # remain portable. These tests use only the original archived rows and bytes.
        cls.origin = runpy.run_path(str(Path(__file__).with_name("v5j_retry.py")))
        if os.geteuid() or not cls.origin["ORIGINAL_REVIEW"].exists():
            raise unittest.SkipTest("original failed-generation evidence requires custodial read access")
        cls.records = {}
        for p, sha in [*cls.origin["MEMBERS"].values(),
                       (cls.origin["ORIGINAL_REVIEW"], cls.origin["ORIGINAL_REVIEW_SHA"])]:
            raw, ref = dispatch.read(p, sha)
            cls.records[p] = json.loads(raw), ref
        cls.rows = cls.origin["journal"](dispatch.out)

    def qualify(self, mutated=None, rows=None):
        def read(p, digest):
            value, ref = copy.deepcopy(self.records[p])
            self.assertEqual(ref["sha256"], digest)
            if mutated:
                mutated(p, value)
            return value, ref
        return self.origin["profile"](read, self.rows if rows is None else rows)

    def test_reproduces_exact_archived_review(self):
        body = (json.dumps(self.qualify(), sort_keys=True, separators=(",", ":")) + "\n").encode()
        self.assertEqual(dispatch.hashlib.sha256(body).hexdigest(), dispatch.RETRY_REVIEW_SHA)

    def test_rejects_wrong_native_child_and_predecessor(self):
        worker = self.origin["MEMBERS"]["worker"][0]
        def wrong_child(p, v):
            if p == worker:
                v["leased_worker_observation"]["native_child"]["pid"] += 1
        def stale(p, v):
            if p == self.origin["MEMBERS"]["submission"][0]:
                v["invocation_id"] = self.origin["ORIGINAL"]
        for mutate in (wrong_child, stale):
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                self.qualify(mutate)

    def test_rejects_wrong_exit_cursor_and_foreign_unit(self):
        for key in ("__CURSOR", "UNIT", "EXIT_STATUS"):
            rows = copy.deepcopy(self.rows)
            next(r for r in rows if r.get("EXIT_STATUS") == "1")[key] = "other"
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.qualify(rows=rows)

    def test_rejects_wrong_retained_inode(self):
        review = self.qualify()
        review["retained_inputs"][-1]["ino"] += 1
        with self.assertRaisesRegex(ValueError, "retained 145 input"):
            dispatch.retained(review)


class FailedChildLeaseTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = runpy.run_path(str(Path(__file__).with_name("v5j_lease_failure.py")))
        if os.geteuid() or not cls.mod["STATE"].is_dir():
            raise unittest.SkipTest("original paid failed-generation records unavailable")
        cls.api, cls.proof = cls.mod["historical"]()
        cls.rows = cls.mod["journal"](cls.api["out"])

    def replay(self, key=None, change=None):
        def read(path, expected):
            b, ref = self.api["read"](path, expected)
            value = json.loads(b)
            if key is not None and path == self.mod["ARTIFACTS"][key][0]:
                change(value)
            return value, ref
        return self.mod["profile"](read, self.rows)

    def test_exact_failure_with_no_observed_paid_child(self):
        self.assertEqual(self.replay(), self.proof)
        self.assertIsNone(self.proof["failed_phase"]["retry_worker"])
        self.assertFalse(self.proof["acquired_child_leases_proved"])

    def test_rejects_stale_cursor_or_wrong_child_lease_failure(self):
        for k, change in (("submission", lambda d: d.update(manager_start_cursor="old")),
                          ("failure", lambda d: d.update(error="ValueError: original recovery read lease absent")),
                          ("recovery", lambda d: d["fresh_fit"]["phase145"]["window"].update(native_child={"pid":1})),
                          ("detached", lambda d: d["phase145"].update(InvocationID=self.mod["PREVIOUS"]))):
            with self.subTest(key=k), self.assertRaises(ValueError):
                self.replay(k, change)


if __name__ == "__main__":
    unittest.main()
