"""Preserve the running V52 controller's clock and reconcile the closed epoch 143 gate."""
from pathlib import Path

from evidence import bound, checked, need
from transition import clock
import status162
import split_status169
import first_hourly143
import gap170_status
import rolling170_fourth_status

V52_SHA = "ede08352a67056909967fa5961c1b19987ab894a8a46a0514e5613d9cc5e086b"
V52_SEAL = "eb325e1a0dd2c3c280576f97c4530b18bf3228815176feb8b726c913352eafb9"


def native_assignments(fleet):
    """Reconcile the split 162 completion and a gap that can start between observations."""
    active, closed = {}, {}
    for row in (status162.current(fleet), split_status169.reader()["current"](fleet)):
        if not row:
            continue
        name = row["unit"]["Id"]
        if row["phase"] == "terminal":
            if row["epoch"] == 162:
                need(row["terminal"] and row["held_owner"] == fleet[status162.FIELD]["held_owner"],
                     "epoch 162 terminal has another admission")
                closed[name] = row["producer_invocation_id"]
            continue
        active[name] = dict(unit=name, iid=row["unit"]["InvocationID"], pid=row["unit"]["MainPID"],
                            intent=row.get("hourly169_start_intent") or row["held_owner"])
    gap = gap170_status.gap
    prior = fleet.get(gap.FIELD)
    if not gap.ACTOR.exists():
        need(not prior and not gap.RELEASE.exists() and not gap.ENROLLMENT.exists(), "missing 170 admission")
        gap.native.idle(gap.UNIT)
        return active, closed
    scope = gap170_status.interface()
    gap170_status.contract.stopped_owner(fleet)
    ref, actor = gap.read_actor()
    need(not prior or prior["actor_ref"] == ref, "170 gap changed owners since the fleet")
    manager = gap.native.props(gap.UNIT, gap.PROPS)
    if manager["ActiveState"] in ("inactive", "failed"):
        terminal = gap.terminal(actor)
        need(terminal["INVOCATION_ID"] == actor["producer_invocation_id"], "foreign 170 terminal")
        gap.native.idle(gap.UNIT)
        closed[gap.UNIT] = actor["producer_invocation_id"]
    else:
        _, grant = gap.release(scope, ref, actor, gap170_status.contract.checkpoint(scope))
        need(grant is not None, "epoch 170 is between booking and release")
        _, worker, _ = gap.live(scope, manager, actor, True)
        gap.guard(scope, actor, worker, grant)
        active[gap.UNIT] = dict(unit=gap.UNIT, iid=actor["producer_invocation_id"],
                                pid=manager["MainPID"], intent=ref)
    return active, closed


def ready(api, head, seal):
    previous = api["ROOT"] / api["failed166_package"](52)
    owner = dict(path=str(previous.parent / "FAILED166_CADENCE_V52_ACTIVE.json"), sha256=V52_SHA)
    active = checked(owner)
    before = checked(active["ready"])
    need(before["package"] == dict(path=str(previous / "deployment-seal-receipt.json"), sha256=V52_SEAL)
         and active["new"]["program"] == str(previous / "status_cycle.py")
         and before["gap170_interface"] == gap170_status.INTERFACE
         and before["successor170_interface"] == rolling170_fourth_status.INTERFACE
         and before["prior_successor170_interface"] == rolling170_fourth_status.history.INTERFACE,
         "changed predecessor or epoch 170 assignments")
    latest = max(api["BASE"].glob("root*/ROOT_COMPLETE_OPERATIONAL_FLEET.json"), key=lambda p: p.stat().st_mtime_ns)
    need(bound(latest) == head, "fleet superseded during writer handoff")
    fleet = checked(head)
    history, _ = first_hourly143.bootstrap_history(first_hourly143.EPOCH143)
    row = fleet[first_hourly143.FIELD]
    need(history["reconciliation"] and row["phase"] == "terminal"
         and row[first_hourly143.RETRY_HISTORY] == history
         and row["held_owner"] == history["archived_held_owner"], "different current 143 terminal")
    cfgref, timer = fleet["sole_next_observer"], fleet["sole_next_timer"]
    cfg = api["sealed"](cfgref)
    done = clock(api, fleet, cfg, timer, cfgref)
    api["tail167_status"].retained_population(fleet, cfg)
    api["bridge170_status"].retained_population(fleet, cfg)
    rolling170_fourth_status.retained_population(fleet, gap170_status.history_config(fleet, cfg))
    current = api["CURRENT"].parent
    members = {
        key: bound(current / Path(ref["path"]).name)
        for key, ref in before.items()
        if isinstance(ref, dict) and "path" in ref and Path(ref["path"]).parent == previous and key != "package"
    }
    active_assignments, closed = native_assignments(fleet)
    return before | members | dict(package=seal, old_owner=owner, fleet=head, config=cfgref, timer=timer,
                                   completed_sample=done, protected_private_assignments=active_assignments,
                                   terminal_private_invocations=closed,
                                   retained_143_bootstrap_failure=history)


def validate(api, proposed, seal):
    actual = ready(api, proposed["fleet"], seal)
    need(actual == proposed or (proposed["completed_sample"] is None and actual["completed_sample"] is not None
         and dict(actual, completed_sample=None) == proposed), "observer or fleet changed during handoff")
