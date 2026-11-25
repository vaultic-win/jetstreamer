"""Exercise private diagnostic enrollment and progress without running a worker."""

from copy import deepcopy
from pathlib import Path
import runpy
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


def need(condition, message):
    if not condition:
        raise ValueError(message)


evidence = SimpleNamespace(BASE=Path("/runtime"), need=need, bound=None, checked=None, durable=None)
with patch.dict(sys.modules, {"evidence": evidence}):
    route = runpy.run_path(str(Path(__file__).with_name("hourly170_cadence.py")))

CONFIG = dict(range="170", producer_unit="private.service",
              expected_producer_invocation_id="a"*32, scratch_path="/scratch")
WORKER = dict(pid=23, executable="/scratch/historical-worker")
RECEIPT = dict(path="/observed", sha256="a"*64)


def observation():
    return dict(worker=WORKER, receipt=RECEIPT,
                row=dict(epoch=170, observer_config=CONFIG,
                         unit=dict(InvocationID="a"*32, MainPID="22"),
                         coordinated_sample_observed_this_invocation=False,
                         transaction_replay_claimed=False, canonical_replay_claimed=False,
                         archive_publication_authorized=False))


def fleet():
    return dict(actual_executing_replays=[dict(epoch=166)], actual_active_bootstraps=[],
                canonical_producer_count=1, useful_replay_count=1, active_producer_count=1,
                actual_active_private_diagnostics=[], active_private_diagnostic_count=0,
                epochs=[dict(epoch=170,state="verification",repair_open=True,current_repair_owner="/root")])


def context(active=False):
    field = dict(WORKER, matching_workers=1, executable_beneath_bound_scratch=True)
    first = route["FIRST_SLOT"]
    sample = dict(CONFIG, status="observed", ordinary_replay_claim=False,
                  publication_authorized=False, r2_mutations=False,
                  observation=dict(worker_before=field, worker_after=field,
                                   useful_work=dict(first=dict(slot=first), last=dict(slot=first+1))))
    items = [CONFIG] if active else []
    incumbent = {"range":"144"}
    return SimpleNamespace(cfg=dict(diagnostic_replays=items),
                           sample=dict(diagnostic_replays=[sample] if active else []),
                           next_cfg=dict(diagnostic_replays=[incumbent,*items]))


class Hourly170Cadence(unittest.TestCase):
    def test_drained_diagnostic_can_read_stale_predecessor(self):
        project = route["projection"]
        provider_path = route["PROVIDER"]
        seal = {"destination": str(provider_path), "members": [
            {"name": "post-stop-fit", "sha256": "b" * 64},
        ]}
        predecessor = dict(fleet(), owner="/root", schema="horizon-Root-complete-fleet-operational-review-v1")
        manager = {"ActiveState": "inactive"}
        actor = {"UNIT": "private.service", "properties": Mock(return_value=manager),
                 "ready_contract": Mock(return_value={"qualified": True})}
        fresh_head = Mock(side_effect=ValueError("stale or incomplete root fleet"))
        provider = {"hourly170": actor, "s": object(), "fit": object(), "fleet_head": fresh_head}
        terminal = {"successful_exit": True}
        ref = {"path": "/runtime/root-before-gap/ROOT_COMPLETE_OPERATIONAL_FLEET.json", "sha256": "c" * 64}

        def reference(path):
            digest = route["PROVIDER_SEAL"] if path.name == "deployment-seal-receipt.json" else "b" * 64
            return {"path": str(path), "sha256": digest}

        def checked_reference(value):
            return predecessor if value == ref else seal

        read_terminal = Mock(return_value=terminal)
        with patch.dict(project.__globals__, {"bound": reference, "checked": checked_reference,
                                             "RELEASE": SimpleNamespace(exists=lambda: True),
                                             "terminal": read_terminal}), \
                patch.object(runpy, "run_path", return_value=provider):
            self.assertEqual(project(ref), {"terminal": terminal})
            fresh_head.assert_not_called()
            read_terminal.assert_called_once_with(actor, provider["fit"], {"qualified": True}, None, manager)
            actor["properties"].return_value = {"ActiveState": "active"}
            with self.assertRaisesRegex(ValueError, "stale or incomplete root fleet"):
                project(ref)
            fresh_head.assert_called_once_with(ref)

    def test_enrollment_keeps_current_replay_count_and_verification_phase(self):
        view, c, observed = fleet(), context(), observation()
        route["interpret"](c, observed, lambda *_a, **_k:self.fail("needs a scheduled sample"))
        self.assertEqual(c.next_cfg["diagnostic_replays"], [{"range":"144"},CONFIG])
        route["install"](view, observed)
        self.assertEqual(view["actual_active_private_diagnostics"], [observed["row"]])
        self.assertEqual(view["active_private_diagnostic_count"], 1)
        self.assertEqual(view["active_producer_count"], 2)
        self.assertEqual(view["canonical_producer_count"], 1)
        self.assertEqual(view["useful_replay_count"], 1)
        self.assertEqual(view["epochs"][0]["state"], "verification")
        with self.assertRaises(ValueError):
            route["install"](view, observed)

    def test_progress_requires_both_matching_workers_and_bounded_slots(self):
        for error in (None, "pid", "slot", "missing-worker"):
            with self.subTest(error=error):
                c, observed = context(active=True), observation()
                r = c.sample["diagnostic_replays"][0]["observation"]
                if error == "pid":
                    r["worker_after"] = dict(r["worker_after"], pid=98)
                elif error == "slot":
                    r["useful_work"]["last"]["slot"] = route["LAST_SLOT"]+1
                elif error == "missing-worker":
                    r["worker_before"] = None
                route["interpret"](c, observed, lambda *_a, **_k:True)
                self.assertEqual(observed["row"]["transaction_replay_claimed"], error is None)
                self.assertFalse(observed["row"]["canonical_replay_claimed"])

    def test_terminal_does_not_leave_a_diagnostic_or_close_repair(self):
        view, c = fleet(), context(active=True)
        view["epochs"][0]["current_private_diagnostic"] = deepcopy(observation()["row"])
        observed = dict(receipt=RECEIPT, terminal=dict(successful_exit=True))
        route["interpret"](c, observed, None)
        route["install"](view, observed)
        self.assertEqual(c.next_cfg["diagnostic_replays"], [{"range":"144"}])
        self.assertFalse(view["actual_active_private_diagnostics"])
        self.assertNotIn("current_private_diagnostic", view["epochs"][0])
        self.assertTrue(view["epochs"][0]["repair_open"])


if __name__ == "__main__":
    unittest.main()
