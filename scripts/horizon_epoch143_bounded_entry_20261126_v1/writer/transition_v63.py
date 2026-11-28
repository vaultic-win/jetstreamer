"""Carry the V62 observer clock and owners through the second epoch 143 enrollment."""

from pathlib import Path
from types import SimpleNamespace

from evidence import bound, checked, need
import hourly143_status
import second_hourly143 as second
from transition import clock
from transition_v62 import native_assignments as incumbent_assignments


V62_SHA = "be7681e7d92c6617147239e3e534ab008341599e198c1183cbe4f007802fc3cb"
V62_SEAL = "7901076dbe284118014b0d37483368fc5c8b50bc340c8bc181cc33a9f4dcaf99"


def native_assignments(fleet):
    active, closed = incumbent_assignments(fleet)
    first = fleet[hourly143_status.PROFILE.field]
    second.check_prefix(first)
    unit, invocation = hourly143_status.PROFILE.unit, first["actor"]["producer_invocation_id"]
    need(unit not in active and closed.get(unit, invocation) == invocation,
         "epoch 143 predecessor changed native ownership")
    closed[unit] = invocation
    return active, closed


def ready(api, head, seal):
    root = api["ROOT"]
    previous = root / api["failed166_package"](62)
    owner = dict(path=str(root / "FAILED166_CADENCE_V62_ACTIVE.json"), sha256=V62_SHA)
    active = checked(owner)
    before = checked(active["ready"])
    need(before["package"] == dict(path=str(previous / "deployment-seal-receipt.json"), sha256=V62_SEAL)
         and active["new"]["program"] == str(previous / "status_cycle.py"), "different V62 writer")
    latest = max(api["BASE"].glob("root*/ROOT_COMPLETE_OPERATIONAL_FLEET.json"), key=lambda p: p.stat().st_mtime_ns)
    need(bound(latest) == head, "fleet changed during V63 handoff")
    fleet = checked(head)
    first = fleet[hourly143_status.PROFILE.field]
    second.check_prefix(first)
    hourly143_status.evidence(first)
    second.baseline(checked(fleet["complete_active_status_audit"])["receipts"]["143"])
    contract = checked(second.PROFILE.contract)
    need(contract["unit"] == second.PROFILE.unit and contract["prefix_acceptance"] == second.PREFIX
         and contract["native_terminal"] == second.TERMINAL
         and not fleet.get(second.PROFILE.field)
         and not second.observe(SimpleNamespace(fleet=fleet), second.PROFILE),
         "epoch 143 second owner crossed enrollment")
    cfg, timer = fleet["sole_next_observer"], fleet["sole_next_timer"]
    done = clock(api, fleet, api["sealed"](cfg), timer, cfg)
    assignments, closed = native_assignments(fleet)
    need(closed[hourly143_status.PROFILE.unit] == first["actor"]["producer_invocation_id"],
         "V62 dropped the first 143 closure")
    current = api["CURRENT"].parent
    members = {key: bound(current / Path(ref["path"]).name) for key, ref in before.items()
               if isinstance(ref, dict) and "path" in ref and Path(ref["path"]).parent == previous and key != "package"}
    return before | members | dict(
        package=seal, old_owner=owner, fleet=head, config=cfg, timer=timer,
        completed_sample=done, protected_private_assignments=assignments, terminal_private_invocations=closed,
        second_hourly143_contract=second.PROFILE.contract, second_hourly143_prefix=second.PREFIX,
        second_hourly143_reader=bound(current / "second_hourly143.py"),
        second_hourly143_scope=bound(current / "second_hourly143_scope.py"),
    )


def validate(api, proposed, seal):
    actual = ready(api, proposed["fleet"], seal)
    need(actual == proposed or (proposed["completed_sample"] is None and actual["completed_sample"] is not None
         and dict(actual, completed_sample=None) == proposed), "V63 handoff lost its fleet or clock")
