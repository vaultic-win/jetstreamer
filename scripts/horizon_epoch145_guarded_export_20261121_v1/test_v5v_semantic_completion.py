"""Qualification fixtures for native successor ownership and the donor retry."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import runpy
import subprocess
import unittest
from unittest.mock import patch

DIRECTORY = Path(__file__).parent
scope = runpy.run_path(str(DIRECTORY / "v5v_semantic_completion.py"))
manager = scope["successor_manager"]
common = manager.__globals__
V5U = scope["V5U"]
UNIT = scope["UNIT"]
OWNER = "a" * 32
OTHER = "b" * 32
INTENT = {"schema": "horizon-epoch145-v5u-semantic-successor-start-intent-v1",
          "unit": UNIT, "r2_mutations": False}
ARGV = ["/sealed/export145", "recover-full-output", "/fleet", "1" * 64, "2" * 64]


def result(iid=OWNER):
    fields = {"Id": UNIT, "InvocationID": iid, "ActiveState": "active", "SubState": "running",
              "MainPID": "42", "ControlPID": "0", "NRestarts": "0", "Job": "",
              "ControlGroup": "/system.slice/" + UNIT}
    return {"status": 0, "manager": fields}


def event(iid, kind, clock):
    stamp = str(clock)
    return {"_PID": "1", "_BOOT_ID": scope["BOOT"], "UNIT": UNIT, "INVOCATION_ID": iid,
            "MESSAGE_ID": scope[kind], "__CURSOR": "test-cursor-" + stamp,
            "__MONOTONIC_TIMESTAMP": stamp, "__REALTIME_TIMESTAMP": stamp}


def history(iid):
    begin = event(iid, "STARTING", 11)
    began = event(iid, "STARTED", 12)
    cmd = " ".join(ARGV)
    begin.update(JOB_TYPE="start", MESSAGE=f"Starting {UNIT} - {cmd}...")
    began.update(JOB_TYPE="start", JOB_RESULT="done", MESSAGE=f"Started {UNIT} - {cmd}.")
    return [begin, began, event(iid, "SUCCESS", 18)]


class QualifiedSuccessor(unittest.TestCase):
    def test_future_native_owner_and_foreign_interposition(self):
        for iid in (OWNER, OTHER):
            with self.subTest(iid=iid):
                self.assertEqual(manager(result(iid), INTENT), (iid, 42))
                terminal = event(V5U, "FAILURE", 5)
                series = history(iid)
                anchors = {"invocation_id": iid, "argv_tail": ARGV, "intent_floor": 10,
                           "predecessor_native": terminal}
                with patch.dict(common, journal=lambda owner, *_events, **_options:
                                series if owner == iid else series + [event("c" * 32, "SUCCESS", 20)]):
                    self.assertEqual(scope["verify_owner_history"](anchors), tuple(series[1:]))
                interposed = event("c" * 32, "STARTING", 7)
                with patch.dict(common, journal=lambda owner, *_events, **_options:
                                series if owner == iid else [interposed, *series]):
                    with self.assertRaisesRegex(ValueError, "different intervening native owner"):
                        scope["verify_owner_history"](anchors)

    def test_predecessor_restart_and_crossed_native_success_rejected(self):
        with self.assertRaisesRegex(ValueError, "foreign successful"):
            manager(result(V5U), INTENT)
        restarted = result()
        restarted["manager"]["NRestarts"] = "1"
        with self.assertRaisesRegex(ValueError, "foreign successful"):
            manager(restarted, INTENT)
        series = [*history(OWNER)[:2], event(OTHER, "SUCCESS", 18)]
        with self.assertRaisesRegex(ValueError, "foreign PID1 event"):
            scope["validate_start_events"](OWNER, series, ARGV, 10, event(V5U, "FAILURE", 5))
        with self.assertRaisesRegex(ValueError, "startup or predecessor clock"):
            scope["validate_start_events"](OWNER, history(OWNER), ARGV, 10,
                                           event(V5U, "FAILURE", 10))

    def test_sealed_start_and_actual_donor_are_bound(self):
        refs = {name: {"path": "/fixtures/" + name, "sha256": str(n) * 64} for n, name in enumerate(
            ("intent", "capacity", "terminal", "worker-seal", "provider-seal", "proof", "fleet",
             "image", "provider", "result"), 0)}
        for name, path in {
            "intent": scope["FAMILY"] / "v5v-name-handoff/START_INTENT.json",
            "capacity": scope["FAMILY"] / "v5v-name-handoff/FIT.json",
            "result": scope["FAMILY"] / "v5v-name-handoff/START_RESULT.json",
        }.items():
            refs[name]["path"] = str(path)
        image = refs["image"]
        built = {"verifier_sha256": image["sha256"], "guard_terminal": refs["terminal"]}
        donor = {"path": str(scope["PROVIDER"] / "build_159_price.py"), "sha256": scope["DONOR_SHA"]}
        window = {"continuity_seal": refs["worker-seal"], "continuity_build": refs["proof"],
                  "guard_terminal_predecessor": refs["terminal"],
                  "native_parent": {"pid": 42, "start_ticks": 99}}
        fit = {"provider_seal": refs["provider-seal"], "fleet": refs["fleet"], "fits": True,
               "resource_credit_bytes": 0,
               "phase145": {"stage": "controller", "invocation_id": OWNER, "window": window}}
        started = {"fresh_fit": fit, "image": image["sha256"], "iid": OWNER,
                   "file": str(scope["PAID"]), "r2_mutations": False}
        launch = {"fleet": refs["fleet"], "fits": True, "resource_credit_bytes": 0, "epoch": 145,
                  "candidate": None, "replay_launch_authorized": False,
                  "phase145": {"InvocationID": V5U, "guard_terminal": refs["terminal"]}}
        argv_tail = [image["path"], "recover-full-output", refs["fleet"]["path"], refs["fleet"]["sha256"],
                     image["sha256"]]
        intent = dict(INTENT, worker=image, fleet=refs["fleet"], capacity=refs["capacity"],
                      terminal=refs["terminal"], provider=refs["provider"],
                      worker_seal=refs["worker-seal"], provider_seal=refs["provider-seal"],
                      not_before_monotonic_usec=10,
                      argv=["/usr/bin/systemd-run", "--unit=" + UNIT.removesuffix(".service"),
                            "--", *argv_tail])
        recorded = dict(result(), intent=refs["intent"])
        documents = {refs["result"]["path"]: recorded, refs["intent"]["path"]: intent,
                     refs["capacity"]["path"]: launch}

        def pinned(ref, path):
            self.assertEqual(ref["path"], str(path))
            return deepcopy(documents[str(path)])

        def read_start(path):
            self.assertEqual(path, scope["STATE"] / OWNER / "recovery-started.json")
            return deepcopy(started), {"path": str(path), "sha256": "9" * 64}

        def member(package, seal, name, mode):
            expected = {
                "export145": (scope["PACKAGE"], refs["worker-seal"], 0o555, b"", image),
                "build-proof.json": (scope["PACKAGE"], refs["worker-seal"], 0o444,
                                     json.dumps(built).encode(), refs["proof"]),
                "post-stop-fit": (scope["PROVIDER"], refs["provider-seal"], 0o555, b"", refs["provider"]),
                "build_159_price.py": (scope["PROVIDER"], refs["provider-seal"], 0o444, b"", donor),
            }
            pkg, ref, protection, data, entry = expected[name]
            self.assertEqual((package, seal, mode), (pkg, ref, protection))
            return data, entry

        with patch.dict(common, pinned_json=pinned, read_json=read_start, sealed_member=member,
                        failed_predecessor=lambda _: ({"inode": 103237059}, event(V5U, "FAILURE", 5))):
            self.assertEqual(scope["startup"](refs["result"])["invocation_id"], OWNER)
            started["iid"] = OTHER
            with self.assertRaisesRegex(ValueError, "foreign successor worker"):
                scope["startup"](refs["result"])
            started["iid"] = OWNER
            donor["sha256"] = "f" * 64
            with self.assertRaisesRegex(ValueError, "donor retry deployment"):
                scope["startup"](refs["result"])

    def test_promoted_semantic_receipts_cannot_cross_successor_invocations(self):
        identity = {"device": 64512, "inode": 103237059, "bytes": scope["BYTES"],
                    "mtime_ns": 1, "ctime_ns": 2}
        report = {
            "schema": "jetstreamer-private-epoch145-canonical-prefix-extraction-v1",
            "epoch": 145, "archive": str(scope["PROMOTED"]), "archive_bytes": scope["BYTES"],
            "output_slot_start": 62_640_000, "output_slot_count": 432_000,
            "source_archive": scope["SOURCE"],
            "source_archive_sha256": "cb8ac0bc47919c22dc7898e068fb43ffac80aceadcacac3ff8f24ef32d3b3353",
            "source_manifest_sha256": "a101b885c5d60a13b8567d3968acd0e5177ec4f04669b91333cb9b3c5ca4b96a",
            "worker_sha256": "2cca500106d274ebfbbc8c5bfa0e6e8343cd5e41003f9e82c93282800732d8c8",
            "source_canonical_checkpoint_slot": 63_072_070,
            "source_canonical_accounts_hash": "DsoBNgzFVZ7j5bF2CpKnt7HAC7fRrMMwdWW9FUafRe1p",
            "retained_verification_tail_slots": 71,
            "source_must_be_retained": True, "independent_output_reread_passed": True,
            "current_plugin_verification_passed": False, "canonical_sidecar_authorized": False,
            "publication_authorized": False, "retirement_authorized": False, "r2_mutations": False,
            "archive_sha256": "3" * 64, "output_semantic_sha256": "4" * 64,
            "expected_output_provenance_sha256": "5" * 64,
        }
        anchors = {"invocation_id": OWNER, "parent": 42, "candidate": identity,
                   "start": {"path": "/test/start", "sha256": "1" * 64}}
        verified_ref = {"path": "/test/verified", "sha256": "2" * 64}
        extraction_ref = {"path": "/test/extraction", "sha256": "3" * 64}
        original = scope["ORIGINAL"]
        verified = {"iid": OWNER, "original_export": original, "parent": 42, "pid": 43,
                    "paid_source": str(scope["PAID"]), "private_projection": scope["VIEW"],
                    "before": identity, "extraction": dict(report, archive=scope["VIEW"]),
                    "r2_mutations": False}
        extraction = {"actor_iid": OWNER, "original_export": original, "extraction": report,
                      "schema": "horizon-epoch145-guarded-private-prefix-completion-v1",
                      "archive_publication_authorized": False, "recovery_evidence": anchors["start"],
                      "verified_frozen": verified_ref, "r2_mutations": False}
        done = {"iid": OWNER, "recovered_from": original, "receipt": extraction_ref, "r2_mutations": False}
        validate = scope["validate_semantic"]
        self.assertEqual(validate(verified, extraction, done, anchors, verified_ref, extraction_ref), report)
        with self.assertRaisesRegex(ValueError, "broken successor semantic receipt chain"):
            validate(verified, extraction, dict(done, iid=OTHER), anchors, verified_ref, extraction_ref)
        with self.assertRaisesRegex(ValueError, "broken successor semantic receipt chain"):
            validate(verified, extraction, done, dict(anchors, invocation_id=OTHER), verified_ref, extraction_ref)

    def test_published_donor_retries_only_the_identical_read_once(self):
        source = DIRECTORY / "build_159_price.py"
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), scope["DONOR_SHA"])
        command = runpy.run_path(str(source))["command"]
        query = ("/usr/bin/systemctl", "show", "-p",
                 "Id,ActiveState,SubState,InvocationID,MainPID,ControlPID,Job,NRestarts",
                 "horizon-epoch159-bounded-vote-trace-20261123-v1.service")
        timeout = subprocess.TimeoutExpired(query, 10)
        with patch.object(subprocess, "check_output", side_effect=[timeout, "Id=fixture.service\n"]) as probe:
            self.assertEqual(command(*query), "Id=fixture.service")
            self.assertEqual(probe.call_count, 2)
            self.assertEqual(probe.call_args_list[0], probe.call_args_list[1])
        with patch.object(subprocess, "check_output", side_effect=[timeout, timeout]) as probe:
            with self.assertRaises(subprocess.TimeoutExpired):
                command(*query)
            self.assertEqual(probe.call_count, 2)
        with patch.object(subprocess, "check_output", side_effect=[timeout]) as probe:
            with self.assertRaises(subprocess.TimeoutExpired):
                command("/usr/bin/systemctl", "start", "fixture.service")
            self.assertEqual(probe.call_count, 1)


if __name__ == "__main__":
    unittest.main()
