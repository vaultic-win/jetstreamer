"""Enroll a new epoch 143 invocation while retaining the original unit's floor stop."""

from pathlib import Path
from types import SimpleNamespace

from evidence import BASE, bound, checked, need
from transition import clock
from transition_v65 import native_assignments
import floor_retry143 as replacement
import retry_second_hourly143 as old
import second_hourly143 as hourly


V65_SHA = "53397543058f6c75319bd7e68bf587cf991bf4c984ea155096c34d90a4bb74ac"
V65_SEAL = "53f0d5e2181341b51779c2e91672b61f1b06bfd0c4d493708e2524ab54f2e1c3"


def ready(api, head, seal):
    root = api["ROOT"]
    previous = root / api["failed166_package"](65)
    owner = dict(path=str(root / "FAILED166_CADENCE_V65_ACTIVE.json"), sha256=V65_SHA)
    active = checked(owner)
    before = checked(active["ready"])
    need(before["package"] == dict(path=str(previous / "deployment-seal-receipt.json"), sha256=V65_SEAL)
         and active["new"]["program"] == str(previous / "status_cycle.py"), "foreign V65 writer")
    current = bound(max(BASE.glob("root*/ROOT_COMPLETE_OPERATIONAL_FLEET.json"), key=lambda p: p.stat().st_mtime_ns))
    need(current == head, "observer changed before 143 floor-stop handoff")
    fleet = checked(head)
    assignment, closed = native_assignments(fleet)
    context = SimpleNamespace(fleet=fleet, fleet_ref=head, sample_ref=fleet["observer"])
    previous_row, row = replacement.census(context, fleet[hourly.EPOCH143.field], fleet[hourly.PROFILE.field])
    need(previous_row["phase"] == "terminal" and not row
         and not replacement.PROFILE.base.joinpath("HELD_OWNER.json").exists(),
         "epoch 143 acquired a different native owner during writer handoff")
    closed[replacement.PROFILE.unit] = previous_row["actor"]["producer_invocation_id"]
    replacement.baseline(checked(fleet["complete_active_status_audit"])["receipts"]["143"])
    contract = checked(replacement.PROFILE.contract)
    need(contract["unit"] == replacement.PROFILE.unit and contract["floor_stop"] == replacement.TERMINAL
         and contract["failed_second_hourly"] == old.TERMINAL and contract["prefix_acceptance"] == hourly.PREFIX,
         "foreign floor-stop restart contract")
    cfg, timer = fleet["sole_next_observer"], fleet["sole_next_timer"]
    done = clock(api, fleet, api["sealed"](cfg), timer, cfg)
    new = api["CURRENT"].parent
    members = {key: bound(new / Path(ref["path"]).name) for key, ref in before.items()
               if isinstance(ref, dict) and "path" in ref and Path(ref["path"]).parent == previous and key != "package"}
    return before | members | dict(
        package=seal, old_owner=owner, fleet=head, config=cfg, timer=timer, completed_sample=done,
        protected_private_assignments=assignment, terminal_private_invocations=closed,
        second_hourly143_floor_retry_contract=replacement.PROFILE.contract,
        second_hourly143_floor_terminal=replacement.TERMINAL,
        second_hourly143_floor_reader=bound(new / "floor_retry143.py"),
    )


def validate(api, proposed, seal):
    actual = ready(api, proposed["fleet"], seal)
    need(actual == proposed or (proposed["completed_sample"] is None and actual["completed_sample"] is not None
         and dict(actual, completed_sample=None) == proposed), "V66 handoff lost its fleet or clock")
