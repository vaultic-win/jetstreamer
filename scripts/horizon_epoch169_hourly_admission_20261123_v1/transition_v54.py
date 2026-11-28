"""Carry the registered owners and observer clock into the epoch 143 status writer."""
from pathlib import Path

from evidence import bound, checked, need
from transition import clock
from transition_v53 import native_assignments
import hourly143_status as report

V53_SHA = "dd10d5bea7b0faac47d92993c058aeee926751af8def1bb4b29ef0d6986473e9"
V53_SEAL = "73358657891cd2a9961d9bff0f8964fac0aa6fda5761271b14a61f06c573e3dc"


def ready(api, head, seal):
    previous = api["ROOT"] / api["failed166_package"](53)
    owner = {"path": str(previous.parent / "FAILED166_CADENCE_V53_ACTIVE.json"), "sha256": V53_SHA}
    active = checked(owner)
    before = checked(active["ready"])
    need(before["package"] == {"path": str(previous / "deployment-seal-receipt.json"), "sha256": V53_SEAL}
         and active["new"]["program"] == str(previous / "status_cycle.py"), "different incumbent writer")
    latest = max(api["BASE"].glob("root*/ROOT_COMPLETE_OPERATIONAL_FLEET.json"), key=lambda p: p.stat().st_mtime_ns)
    need(bound(latest) == head, "fleet changed during handoff")
    fleet = checked(head)
    row = fleet[report.PROFILE.field]
    report.evidence(row)
    report.recheck(row)
    config = fleet["sole_next_observer"]
    timer = fleet["sole_next_timer"]
    cfg = api["sealed"](config)
    done = clock(api, fleet, cfg, timer, config)
    api["tail167_status"].retained_population(fleet, cfg)
    api["bridge170_status"].retained_population(fleet, cfg)
    api["successor170_status"].retained_population(fleet, api["gap170_status"].history_config(fleet, cfg))
    current = api["CURRENT"].parent
    members = {key: bound(current / Path(ref["path"]).name) for key, ref in before.items()
               if isinstance(ref, dict) and "path" in ref and Path(ref["path"]).parent == previous and key != "package"}
    assignments, closed = native_assignments(fleet)
    return before | members | dict(package=seal, old_owner=owner, fleet=head, config=config, timer=timer,
                                   completed_sample=done, protected_private_assignments=assignments,
                                   terminal_private_invocations=closed, hourly143_status=bound(current / "hourly143_status.py"),
                                   hourly143_held=report.HELD, hourly143_first_progress=bound(report.FIRST))


def validate(api, proposed, seal):
    actual = ready(api, proposed["fleet"], seal)
    need(actual == proposed or (proposed["completed_sample"] is None and actual["completed_sample"] is not None
         and dict(actual, completed_sample=None) == proposed), "status handoff lost its fleet or clock")
