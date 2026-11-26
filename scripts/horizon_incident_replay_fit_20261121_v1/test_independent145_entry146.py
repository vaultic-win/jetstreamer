from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import independent145_entry146 as route


def ref(path, sha256):
    return {"path": str(path), "sha256": sha256}


class IndependentEntry(unittest.TestCase):
    def setup_candidate(self, name):
        candidate = route.CANDIDATES[name]
        binding = ref(route.terminal_path(candidate), "8" * 64)
        selection = {"schema": route.SELECT_SCHEMA, "candidate": name, "terminal": binding}
        receipt = {
            "schema": route.TERMINAL_SCHEMA, "epoch": 145,
            "native": {"Id": candidate["unit"], "InvocationID": candidate["invocation"]},
            "report": {
                "invocation_id": candidate["invocation"], "frozen_output": str(route.ARCHIVE),
                "verified_buckets": 3375, "verified_canonical_slots": 432000,
                "output_promoted": False, "source_tail_verified": True,
            },
            "publication_authorized": False, "r2_mutations": False, "journal_time_us": "20",
        }
        return candidate, binding, selection, receipt

    def stop_events(self):
        return [
            {"MESSAGE_ID": message, "JOB_TYPE": job, "JOB_RESULT": "done", "__CURSOR": str(at),
             "_PID": "1", "UNIT": route.UNIT, "_BOOT_ID": route.BOOT, "INVOCATION_ID": route.V10,
             "__REALTIME_TIMESTAMP": str(at), "__MONOTONIC_TIMESTAMP": str(at)}
            for message, at, job in ((route.STARTED, 10, "start"), (route.STOPPING, 25, "stop"),
                                     (route.STOPPED, 30, "stop"))
        ]

    def test_both_exact_terminal_routes(self):
        for name in route.CANDIDATES:
            candidate, binding, selection, receipt = self.setup_candidate(name)
            package = Path("/fixture")
            selection_ref = ref(package / route.SELECT, "9" * 64)
            status = SimpleNamespace(
                read=Mock(side_effect=[(selection, selection_ref), (receipt, binding)]),
                ref=ref,
            )
            fit = SimpleNamespace(binary=Mock())
            file_modes = lambda p: SimpleNamespace(st_mode=0o444 if p.name == route.SELECT else 0o400)
            with (
                self.subTest(name=name),
                patch.object(Path, "lstat", file_modes),
                patch.object(Path, "stat", file_modes),
                patch.object(route, "drained", return_value={"invocation_id": route.V10}),
                patch.object(route, "other_readers_drained") as others,
                patch.object(route, "native_handback", return_value=route.stop_contract(self.stop_events(), "20")),
                patch.object(route.runpy, "run_path", return_value={"capture": lambda: receipt}),
            ):
                phase = route.phase(status, fit, package, selection_ref["sha256"])
                self.assertEqual(phase["stage"], route.STAGE)
                self.assertEqual(phase["semantic_receipt"], binding)
                self.assertEqual(phase["completed_invocation_id"], candidate["invocation"])
                self.assertEqual(phase["previous_verifier_invocation_id"], route.V10)
                self.assertEqual(phase["resource_credit_bytes"], 0)
                status.read.assert_any_call(package / route.SELECT, selection_ref["sha256"])
                others.assert_called_with(status, fit, candidate)
                self.assertEqual(fit.binary.call_count, 2)

    def test_rejects_foreign_receipt_selection(self):
        _, _, selection, _ = self.setup_candidate("four")
        for changed in ({**selection, "candidate": "scaled"},
                        {**selection, "terminal": {"path": "/foreign", "sha256": "8" * 64}},
                        {**selection, "terminal": {**selection["terminal"], "sha256": ""}},
                        {**selection, "other": True}):
            with self.subTest(changed=changed), self.assertRaisesRegex(ValueError, "foreign independent"):
                route.lookup(changed)

    def test_rejects_incomplete_native_report_or_changed_saved_receipt(self):
        candidate, binding, _, report = self.setup_candidate("four")
        for bad in ("changed-recapture", "unverified-root", "short-archive", "foreign-invocation", "promoted"):
            receipt = deepcopy(report)
            observed = receipt
            if bad == "changed-recapture":
                observed = deepcopy(receipt)
                observed["journal_time_us"] = "21"
            elif bad == "unverified-root":
                receipt["report"]["source_tail_verified"] = False
            elif bad == "short-archive":
                receipt["report"]["verified_canonical_slots"] -= 1
            elif bad == "foreign-invocation":
                receipt["native"]["InvocationID"] = route.CANDIDATES["scaled"]["invocation"]
            else:
                receipt["report"]["output_promoted"] = True
            status = SimpleNamespace(read=lambda *_: (receipt, binding), ref=ref)
            fit = SimpleNamespace(binary=Mock())
            with (
                self.subTest(bad=bad),
                patch.object(Path, "stat", return_value=SimpleNamespace(st_mode=0o400)),
                patch.object(Path, "lstat", return_value=SimpleNamespace(st_mode=0o400)),
                patch.object(route.runpy, "run_path", return_value={"capture": lambda: observed}),
                self.assertRaisesRegex(ValueError, "foreign or incomplete"),
            ):
                route.checked_terminal(status, fit, candidate, binding)

    def test_rejects_unproved_v10_handback(self):
        self.assertEqual(route.stop_contract(self.stop_events(), "20"),
                         {"started": "10", "stopping": "25", "stopped": "30"})
        cases = [self.stop_events()[:-1], self.stop_events(), self.stop_events(), self.stop_events()]
        cases[1][1]["INVOCATION_ID"] = route.CANDIDATES["scaled"]["invocation"]
        cases[2][2]["JOB_RESULT"] = "failed"
        cases[3][1]["__REALTIME_TIMESTAMP"] = "19"
        for events in cases:
            with self.subTest(events=events), self.assertRaisesRegex(ValueError, "V10"):
                route.stop_contract(events, "20")

    def test_rejects_unaccounted_second_reader_even_when_chosen_one_passes(self):
        candidate, _, _, _ = self.setup_candidate("scaled")
        live_reader = route.CANDIDATES["four"]["unit"]
        fit = SimpleNamespace(members=lambda unit: (55,) if unit == live_reader else ())
        status = SimpleNamespace(show=lambda unit: {"Id": unit, "MainPID": "0", "ControlPID": "0",
                                                    "Job": "", "ActiveState": "active", "SubState": "exited"})
        with self.assertRaisesRegex(ValueError, "unaccounted epoch 145 verifier"):
            route.other_readers_drained(status, fit, candidate)

    def test_rejects_live_original_before_reading_independent_output(self):
        _, _, selection, _ = self.setup_candidate("scaled")
        status = SimpleNamespace(read=Mock(return_value=(selection, ref("/fixture", "9" * 64))),
                                 show=lambda _: {"Id": route.UNIT, "ActiveState": "active", "SubState": "running"})
        with (
            patch.object(Path, "lstat", return_value=SimpleNamespace(st_mode=0o444)),
            self.assertRaisesRegex(ValueError, "V10 verifier has not drained"),
        ):
            route.phase(status, SimpleNamespace(A145=route.UNIT), Path("/fixture"), "9" * 64)
        status.read.assert_called_once()


if __name__ == "__main__":
    unittest.main()
