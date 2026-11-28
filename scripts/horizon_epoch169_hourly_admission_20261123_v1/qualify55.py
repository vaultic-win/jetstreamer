"""Exercise the 169 successor with the unchanged original reader and schedule."""
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import sys

if __name__ == "__main__":
    # Arguments are the derived writer directory and the retained V54 package.
    sys.path[:0] = [sys.argv[1], sys.argv[2], str(Path(sys.argv[2]).parents[1] / "prefix140-status-cadence-20261122-v1/cadence-tools")]

import retry169_status as retry
import split_status169 as prior
import split_wire
from evidence import checked


def fixture():
    api = retry.receiver()
    native = api["observe"]
    scope = checked(retry.SCOPE)
    custody = checked(scope["predecessor"])
    old = dict(epoch=169, phase="terminal", invocation_id=custody["producer_invocation"], terminal=custody["terminal"],
               unit={"Id": prior.UNIT}, hourly169_start_intent={"path": "original", "sha256": "prior"})
    iid = "b" * 32
    intent = {"path": "replacement start", "sha256": "replacement"}
    cfg = dict(range="169", producer_unit=retry.UNIT, controller_unit=retry.UNIT,
               expected_producer_invocation_id=iid, expected_controller_invocation_id=iid,
               scratch_path=str(native.c.OLD / "v158/scratch"), worker_executable_basename="historical-worker",
               append_log={"path": scope["log"], "device": 1, "inode": 2})
    observed = dict(epoch=169, phase="worker", unit={"Id": retry.UNIT}, actor={"producer_pid": 120},
                    invocation_id=iid, intent=intent, guard={"proof": 1}, observer_config=cfg,
                    worker={"pid": 121, "path": "historical-worker"}, terminal=None,
                    canonical_replay_claimed=False, archive_publication_authorized=False)
    terminal = dict(observed, phase="terminal", observer_config=None, terminal={"path": "terminal", "sha256": "end"})
    before_status = dict(epoch=169, phase="verification", sampled_at_utc="2026-11-28T00:00:00Z",
                         elapsed_execution_millis=600, estimated_remaining_millis=300000000, jet_size_bytes=1304621799)
    measure = {"slot_delta": 4, "transaction_delta": 20, "elapsed_seconds": 2, "last": {"slot": 73238473},
               "journal_invocation_id": iid}
    child = {"pid": 121, "executable": "historical-worker"}
    sample = dict(cfg, status="observed", ordinary_replay_claim=False, publication_authorized=False, r2_mutations=False,
                  observation={"worker_before": child, "worker_after": child, "useful_work": measure})
    seed = dict(producer_invocation_id=iid, unit=retry.UNIT)
    factory = lambda: dict(epochs=[{"epoch": 169}], actual_active_bootstraps=[], actual_active_private_diagnostics=[],
                           actual_executing_replays=[], active_private_diagnostic_count=0, active_producer_count=0,
                           current_private169_hourly=deepcopy(old))
    seen = []
    def historical(fleet):
        assert not fleet["actual_active_private_diagnostics"]
        return deepcopy(old)
    def progress(detail, assigned, found, pid):
        assert detail == sample["observation"] and assigned == cfg and found == iid and pid == 120
        seen.append(found)
        return True

    for phase, row in (("absent", None), ("held", dict(observed, phase="held", observer_config=None)),
                       ("worker", observed), ("terminal", terminal)):
        fleet = factory()
        assigned = [cfg] if phase in ("worker", "terminal") else []
        if assigned:
            fleet[retry.FIELD] = deepcopy(observed)
            fleet["actual_active_private_diagnostics"] = [fleet[retry.FIELD]]
        ctx = SimpleNamespace(fleet=fleet, cfg={"diagnostic_replays": assigned}, next_cfg={"diagnostic_replays": assigned},
                              sample={"diagnostic_replays": [sample] if assigned else []}, sample_ref={"observation": 1})
        initial = deepcopy(fleet)
        with patch.object(native, "current", side_effect=lambda fleet: deepcopy(row)), patch.object(prior, "reader", return_value={"current": historical}), \
             patch.object(native.c, "read", return_value=(seed, intent)), patch.object(native.quote, "bound", return_value=seed):
            result, previous, original = retry.observe(ctx, progress)
            assert previous["phase"] == "terminal" and previous["terminal"] == old["terminal"]
            assert fleet == initial and original.cfg["diagnostic_replays"] == original.sample["diagnostic_replays"] == []
            prior.project(ctx, previous)
            if result:
                api["project"](ctx, result)
            assert ctx.next_cfg["diagnostic_replays"] == ([cfg] if phase == "worker" else [])
            joined = factory()
            prior.install(joined, previous)
            retry.install(joined, result)
            assert joined["active_private_diagnostic_count"] == joined["active_producer_count"] == int(phase in ("held", "worker"))
            assert joined[prior.FIELD] == previous and joined.get(retry.FIELD) == result
            if phase == "worker":
                assert result["transaction_replay_claimed"] and joined["epochs"][0]["state"] == "executing"
                bad = deepcopy(ctx)
                bad.cfg["diagnostic_replays"][0]["expected_producer_invocation_id"] = "foreign"
                try:
                    retry.observe(bad, progress)
                except ValueError:
                    pass
                else:
                    raise AssertionError("foreign retry sample accepted")
            if result:
                ctx.now = datetime(2026, 11, 28, 0, 30, tzinfo=timezone.utc)
                ctx.stamp = "2026-11-28T00:30:00Z"
                before = {"after_status": before_status, "producer_invocation_id": None}
                part = {"path": scope["output"], "size": 99999}
                result["held"] = intent
                with patch.object(retry, "checked", return_value=seed), patch.object(retry, "output", return_value=part), \
                     patch.object(split_wire, "elapsed", return_value=25), patch.object(split_wire, "checked", return_value={"archive": part}):
                    after, extra = retry.forecast(ctx, result, before_status, before, {"previous": 1}, lambda *_: {"total_millis": 400})
                    assert extra[retry.KEY] == intent and extra["producer_invocation_id"] == (None if phase == "terminal" else iid)
                    assert after["phase"] == ("replay" if phase == "worker" else "verification")
                    if phase == "worker":
                        assert after["jet_size_bytes"] == part["size"] and extra["measured_slots_per_second"] == 2
                        assert extra["archive_sample"]["path"] == scope["output"]
    assert seen == [iid]


if __name__ == "__main__":
    fixture()
    print("169 absent, held, advancing, terminal and foreign invocation; retained original enrollment and replacement forecast passed")
