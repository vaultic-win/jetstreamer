"""Enroll the epoch 143 RAM retry while preserving the adjacent 169 owner."""

from pathlib import Path
from types import SimpleNamespace

import adjacent169_route as adjacent
from evidence import BASE, bound, checked, need
import ram_retry143 as retry
from transition import clock
import transition_v70 as previous


V70_SHA = "6aef2af6a4c8332e9af577ee55fa27bf44f88cfe39d9d67a32d4056faf008c3f"
V70_SEAL = "838bfc4a45f355e086bc85f2188d6ee8baf12c5b444a5522d7afd43db59ad987"


def native_assignments(fleet):
    active, closed = previous.native_assignments(fleet)
    unit = retry.PROFILE.unit
    need(unit not in active and closed.get(unit) == retry.IID,
         "missing closed epoch 143 RAM refusal")
    head = bound(max(BASE.glob("root*/ROOT_COMPLETE_OPERATIONAL_FLEET.json"), key=lambda p: p.stat().st_mtime_ns))
    need(checked(head) == fleet, "fleet changed during the epoch 143 RAM retry enrollment")
    context = SimpleNamespace(fleet=fleet, fleet_ref=head, sample_ref=fleet["observer"])
    first = fleet[retry.runway.second.EPOCH143.field]
    predecessor = fleet[retry.runway.second.PROFILE.field]
    _, _, _, row = retry.census(context, first, predecessor)
    if row:
        actor = row["actor"]
        iid = actor["producer_invocation_id"]
        need(row["unit"]["Id"] == unit and checked(row["held_owner"]) == actor,
             "different epoch 143 RAM retry owner")
        if row["phase"] == "terminal":
            need(row["native_terminal"]["invocation_id"] == iid, "different epoch 143 RAM retry terminal")
            closed[unit] = iid
        else:
            permit = retry.PROFILE.base / "barrier/allow"
            need(row["phase"] in ("bootstrap", "worker") and row["guard"]
                 and row["unit"]["InvocationID"] == iid and permit.read_bytes() == iid.encode(),
                 "epoch 143 RAM retry is crossing its guarded release")
            del closed[unit]
            active[unit] = dict(unit=unit, iid=iid, pid=str(actor["producer_pid"]), intent=row["held_owner"])
    return active, closed


def ready(api, head, seal):
    root = api["ROOT"]
    old_dir = root / api["failed166_package"](70)
    owner = dict(path=str(root / "FAILED166_CADENCE_V70_ACTIVE.json"), sha256=V70_SHA)
    old = checked(owner)
    prior = checked(old["ready"])
    latest = max(BASE.glob("root*/ROOT_COMPLETE_OPERATIONAL_FLEET.json"), key=lambda p: p.stat().st_mtime_ns)
    need(head == bound(latest) and old["new"]["program"] == str(old_dir / "status_cycle.py")
         and prior["package"] == dict(path=str(old_dir / "deployment-seal-receipt.json"), sha256=V70_SEAL)
         and all(prior[field] == ref for field, ref in adjacent.ready_fields(old_dir).items()),
         "different incumbent writer, fleet or adjacent 169 interface")
    fleet = checked(head)
    active, closed = native_assignments(fleet)
    need(closed[retry.PROFILE.unit] == retry.IID and not (retry.PROFILE.base / "HELD_OWNER.json").exists(),
         "epoch 143 RAM successor precedes writer enrollment")
    contract = checked(retry.PROFILE.contract)
    need(contract["unit"] == retry.PROFILE.unit and contract["held_ram_stop"] == retry.TERMINAL
         and contract["held_stop"] == retry.runway.CLOSURE
         and contract["prefix_acceptance"] == retry.runway.second.PREFIX,
         "unbound epoch 143 held RAM retry contract")
    retry.baseline(checked(fleet["complete_active_status_audit"])["receipts"]["143"])
    config, timer = fleet["sole_next_observer"], fleet["sole_next_timer"]
    completed = clock(api, fleet, api["sealed"](config), timer, config)
    current = api["CURRENT"].parent
    copies = {key: bound(current / Path(ref["path"]).name) for key, ref in prior.items()
              if key != "package" and isinstance(ref, dict) and "path" in ref and Path(ref["path"]).parent == old_dir}
    return prior | copies | adjacent.ready_fields(current) | dict(
        package=seal, old_owner=owner, fleet=head, config=config, timer=timer, completed_sample=completed,
        protected_private_assignments=active, terminal_private_invocations=closed,
        second_hourly143_held_ram_retry_contract=retry.PROFILE.contract,
        second_hourly143_held_ram_terminal=retry.TERMINAL,
        second_hourly143_ram_reader=bound(current / "ram_retry143.py"))


def validate(api, proposed, seal):
    actual = ready(api, proposed["fleet"], seal)
    need(actual == proposed or proposed["completed_sample"] is None and actual["completed_sample"] is not None
         and dict(actual, completed_sample=None) == proposed, "V71 lost the observer or enrolled owner")
