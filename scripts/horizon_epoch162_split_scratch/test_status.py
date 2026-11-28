"""Check the real original terminal and the status adapter's missing and changing-owner boundaries."""

import copy
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import sys


def module(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).resolve().with_name(name + ".py"))
    obj = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj


def rejected(call):
    try:
        call()
    except (ValueError, KeyError):
        return
    raise ValueError("accepted mismatched owner")


def main(destination):
    l = module("layout")
    s = module("status162")
    fleet = max(l.RT.glob("root*/ROOT_COMPLETE_OPERATIONAL_FLEET.json"), key=lambda p: p.stat().st_mtime_ns)
    actual, ref = l.pinned(fleet)
    l.need(not actual.get(s.FIELD), "fixture requires the original closed predecessor")
    with patch.object(s, "api", return_value=l):
        l.need(s.current(actual) is None, "foreign pre-existing 162 identity")
        stale = copy.deepcopy(actual)
        stale["current_private162_first_hourly"]["actor"]["producer_invocation_id"] = "1" * 32
        rejected(lambda: s.current(stale))
        orphan = dict(
            actual, actual_active_private_diagnostics=[*actual["actual_active_private_diagnostics"], {"epoch": 162}]
        )
        rejected(lambda: s.current(orphan))
        live = dict(l.manager(l.UNIT), ActiveState="active", MainPID="42")
        with patch.object(l, "manager", return_value=live):
            rejected(lambda: s.current(actual))
        sample = {
            "range": "162",
            "producer_unit": l.UNIT,
            "expected_producer_invocation_id": "1" * 32,
            "status": "observed",
            "ordinary_replay_claim": False,
            "publication_authorized": False,
            "r2_mutations": False,
            "observation": {
                "worker_before": {"pid": 42, "executable": "path"},
                "worker_after": {"pid": 42, "executable": "path"},
            },
        }
        row = {
            "epoch": 162,
            "phase": "worker",
            "worker": {"pid": 42, "path": "path"},
            "producer_invocation_id": "1" * 32,
            "actor": {"producer_pid": 41},
            "observer_config": None,
            "native_diagnostic": None,
        }
        assignment = s.assignment(l, row)
        context = SimpleNamespace(
            fleet={s.FIELD: dict(row, observer_config=assignment)},
            cfg={"diagnostic_replays": [assignment]},
            sample_ref={"fixture": True},
            sample={"diagnostic_replays": [sample]},
            next_cfg={"diagnostic_replays": []},
        )
        with patch.object(s, "current", side_effect=lambda _: copy.deepcopy(row)):
            good = s.observe(
                context,
                lambda receipt, cfg, iid, pid: (
                    (receipt, cfg, iid, pid) == (sample["observation"], assignment, "1" * 32, 41)
                ),
            )
            l.need(
                good["transaction_replay_claimed"] and good["native_diagnostic"] == sample, "matching observation lost"
            )
            s.project(context, good)
            l.need(context.next_cfg["diagnostic_replays"] == [assignment], "next-observer assignment changed")
            destination_fleet = {
                k: []
                for k in ("actual_active_private_diagnostics", "actual_executing_replays", "actual_active_bootstraps")
            }
            destination_fleet.update(
                active_private_diagnostic_count=0, active_producer_count=0, epochs=[{"epoch": 162}]
            )
            s.install(destination_fleet, good)
            rejected(lambda: s.install(destination_fleet, good))
            sample["observation"]["worker_after"]["pid"] = 89
            rejected(lambda: s.observe(context, lambda *_: True))
    result = dict(
        fleet=ref,
        original_162_remained_terminal=True,
        absent_owner=True,
        native_sample_pair=True,
        missed_owner_rejected=True,
        orphaned_row_rejected=True,
        changed_old_terminal_rejected=True,
        changed_worker_rejected=True,
        duplicate_claim_rejected=True,
        production_replay=False,
    )
    print(json.dumps(l.save(destination, result)), flush=True)


if __name__ == "__main__":
    main(Path(sys.argv[1]))
