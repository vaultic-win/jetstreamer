"""Validate the drained epoch 143 owner before enrolling its corrected successor."""

from pathlib import Path
from types import SimpleNamespace

from evidence import BASE, bound, checked, need
from transition import clock
import transition_v64 as preceding
import retry_second_hourly143 as retry
import second_hourly143 as earlier
import after_ram170_status as following170


V64_SHA = "986f2778ca9f025b778c5a188d88ecdeaa1c18ae042924429e8d201aece77d29"
V64_SEAL = "3e29cb4264fa554c688e5c18a81a0651bc053000d8856d848b8872d94cae949f"


def native_assignments(fleet):
    native, closed = preceding.native_assignments(fleet)
    head = bound(max(BASE.glob("root*/ROOT_COMPLETE_OPERATIONAL_FLEET.json"), key=lambda p: p.stat().st_mtime_ns))
    need(checked(head) == fleet, "fleet changed during epoch 143 retry enrollment")
    context = SimpleNamespace(fleet=fleet, fleet_ref=head, sample_ref=fleet["observer"])
    second = earlier.census(context, fleet[earlier.EPOCH143.field])
    retry.check_predecessor(second)
    need(closed[earlier.PROFILE.unit] == second["actor"]["producer_invocation_id"],
         "previous second-hourly invocation is still registered as live")
    following170.legacy_idle()
    successor = following170.following
    if successor.ACTOR.exists():
        actor_ref, actor = successor.read_actor()
        manager = successor.native.props(following170.UNIT, successor.PROPS)
        invocation = actor["producer_invocation_id"]
        if manager["ActiveState"] in ("inactive", "failed"):
            need(successor.terminal(actor)["INVOCATION_ID"] == invocation, "foreign 170 successor terminal")
            closed[following170.UNIT] = invocation
        else:
            scope = following170.contract.interface()
            _, grant = successor.release(scope, actor_ref, actor, following170.contract.closed_comparison(scope))
            need(grant, "170 successor is crossing its guarded release")
            native[following170.UNIT] = dict(unit=following170.UNIT, iid=invocation,
                                             pid=manager["MainPID"], intent=actor_ref)
    return native, closed


def ready(api, head, seal):
    root = api["ROOT"]
    previous = root / api["failed166_package"](64)
    owner = dict(path=str(root / "FAILED166_CADENCE_V64_ACTIVE.json"), sha256=V64_SHA)
    active = checked(owner)
    before = checked(active["ready"])
    need(before["package"] == dict(path=str(previous / "deployment-seal-receipt.json"), sha256=V64_SEAL)
         and active["new"]["program"] == str(previous / "status_cycle.py"), "different V64 writer")
    fleet = checked(head)
    assignments, closed = native_assignments(fleet)
    context = SimpleNamespace(fleet=fleet, fleet_ref=head, sample_ref=fleet["observer"])
    first = fleet[earlier.EPOCH143.field]
    second = earlier.census(context, first)
    need(not retry.census(context, first, second), "epoch 143 retry already owns a native unit")
    retry.baseline(checked(fleet["complete_active_status_audit"])["receipts"]["143"])
    contract = checked(retry.PROFILE.contract)
    need(contract["unit"] == retry.PROFILE.unit and contract["prefix_acceptance"] == earlier.PREFIX
         and contract["failed_second_hourly"] == retry.TERMINAL
         and contract["private_run"] == str(retry.PROFILE.run),
         "different corrected epoch 143 contract")
    cfg, timer = fleet["sole_next_observer"], fleet["sole_next_timer"]
    done = clock(api, fleet, api["sealed"](cfg), timer, cfg)
    current = api["CURRENT"].parent
    members = {key: bound(current / Path(ref["path"]).name) for key, ref in before.items()
               if isinstance(ref, dict) and "path" in ref and Path(ref["path"]).parent == previous and key != "package"}
    return before | members | dict(
        package=seal, old_owner=owner, fleet=head, config=cfg, timer=timer, completed_sample=done,
        protected_private_assignments=assignments, terminal_private_invocations=closed,
        second_hourly143_retry_contract=retry.PROFILE.contract, second_hourly143_predecessor=retry.TERMINAL,
        second_hourly143_retry_reader=bound(current / "retry_second_hourly143.py"),
    )


def validate(api, proposed, seal):
    actual = ready(api, proposed["fleet"], seal)
    need(actual == proposed or (proposed["completed_sample"] is None and actual["completed_sample"] is not None
         and dict(actual, completed_sample=None) == proposed), "V65 handoff lost its fleet or clock")
