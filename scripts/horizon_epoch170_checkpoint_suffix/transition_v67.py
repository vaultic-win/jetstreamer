"""Keep the current fleet and cadence clock when registering the 170 hourly receiver."""
from pathlib import Path
from types import SimpleNamespace

from evidence import BASE, bound, checked, need
from transition import clock
import after_floor170_status as hourly
import floor_retry143 as retry
import second_hourly143 as second
import transition_v66 as previous


V66_SHA = "b4d26a441e41758d31cb797d746d608b27ecda582126cf58fb5cceac67815dd7"
V66_SEAL = "05a0b11ac5eb14c53aa0bd0773479b9c4d76e616d9e6c03d8508f2b3311171cb"


def native_assignments(fleet):
    active, closed = previous.native_assignments(fleet)
    path = max(BASE.glob("root*/ROOT_COMPLETE_OPERATIONAL_FLEET.json"), key=lambda p: p.stat().st_mtime_ns)
    head = bound(path)
    need(checked(head) == fleet, "fleet changed during hourly handoff")
    context = SimpleNamespace(fleet=fleet, fleet_ref=head, sample_ref=fleet["observer"])
    prior, row = retry.census(context, fleet[second.EPOCH143.field], fleet[second.PROFILE.field])
    unit = retry.PROFILE.unit
    old = prior["actor"]["producer_invocation_id"]
    if row is None:
        closed[unit] = old
    else:
        actor = row["actor"]
        iid = actor["producer_invocation_id"]
        need(iid != old and actor["contract"] == retry.PROFILE.contract, "foreign epoch 143 turnover")
        if row["phase"] == "terminal":
            need(row["native_terminal"]["invocation_id"] == iid, "different epoch 143 native terminal")
            closed[unit] = iid
        else:
            need(row.get("release") and row["phase"] in ("bootstrap", "worker"),
                 "epoch 143 is crossing its guarded release")
            closed.pop(unit, None)
            active[unit] = dict(unit=unit, iid=iid, pid=str(actor["producer_pid"]), intent=row["held_owner"])
    preceding = hourly.contract.stopped_owner(fleet)
    need(closed.get(preceding["unit"]["Id"]) == hourly.contract.PREVIOUS,
         "floor-stopped 170 missing from native census")
    scope = hourly.interface()
    hourly.contract.checkpoint(scope)
    gap = hourly.gap
    if gap.ACTOR.exists():
        actor_ref, actor = gap.read_actor()
        props = gap.native.props(hourly.UNIT, gap.PROPS)
        iid = actor["producer_invocation_id"]
        if props["ActiveState"] in ("inactive", "failed"):
            need(gap.terminal(actor)["INVOCATION_ID"] == iid, "different hourly 170 terminal")
            closed[hourly.UNIT] = iid
        else:
            _, grant = gap.release(scope, actor_ref, actor, hourly.contract.checkpoint(scope))
            need(grant and props["InvocationID"] == iid, "hourly 170 is crossing its guarded release")
            active[hourly.UNIT] = dict(unit=hourly.UNIT, iid=iid, pid=props["MainPID"], intent=actor_ref)
    return active, closed


def ready(api, head, seal):
    root = api["ROOT"]
    prior_dir = root / api["failed166_package"](66)
    owner = dict(path=str(root/"FAILED166_CADENCE_V66_ACTIVE.json"), sha256=V66_SHA)
    old = checked(owner)
    before = checked(old["ready"])
    need(before["package"] == dict(path=str(prior_dir/"deployment-seal-receipt.json"), sha256=V66_SEAL)
         and old["new"]["program"] == str(prior_dir/"status_cycle.py"), "different V66 writer")
    fleet = checked(head)
    active, closed = native_assignments(fleet)
    need(not hourly.gap.ACTOR.exists() and hourly.UNIT not in active, "hourly producer crossed writer handoff")
    hourly.gap.native.idle(hourly.UNIT)
    cfg, timer = fleet["sole_next_observer"], fleet["sole_next_timer"]
    # The sole clock in the 08:48 fleet led to a missed RSS sample. The
    # incumbent recorded a replacement clock and finished its census at 09:48.
    registration = root / ("recover-" + cfg["sha256"][:20]) / "REGISTERED.json"
    registered = bound(registration)
    need(registered["sha256"] == "0ce2ef69991fb438c6b6b18d8c0b9b5965af95aac4fde785058a6f8c9aba712c"
         and (not api["timer_names"]()), "different recovery clock or another observer")
    recovery = checked(registered)
    missed = checked(recovery["terminal"])
    need(missed["prior_config"] == cfg and missed["fleet"] == head and missed["error"] == "native HOST RSS unavailable"
         and api["resident_clock"].incomplete(checked(missed["failed_sample"])), "different failed memory sample")
    repaired = api["sealed"](recovery["config"])
    name = api["names"](repaired["not_before_utc"])
    view = dict(fleet, sole_next_observer=recovery["config"], sole_next_timer=name["timer"])
    sample = clock(api, view, repaired, name["timer"], recovery["config"])
    saved = bound(name["out"] / "CYCLE_OBSERVATION.json")
    need(sample and sample["sha256"] == "dba3e6203a11968176eb869661180b6bda2bb1f62b025993e44c7dfe573e2b89"
         and saved["sha256"] == "a38ae66c6ec19be7fb212507253a53ee0f402258da509e7cb517a1c19d3f8bd3"
         and checked(saved)["observer"] == sample and checked(saved)["fleet_predecessor"] == head
         and not api["resident_clock"].incomplete(checked(sample)), "different recovered census")
    new = api["CURRENT"].parent
    members = {key: bound(new/Path(ref["path"]).name) for key, ref in before.items()
               if isinstance(ref, dict) and "path" in ref and Path(ref["path"]).parent == prior_dir and key != "package"}
    return before | members | dict(package=seal, old_owner=owner, fleet=head, config=cfg, timer=timer,
                                   completed_sample=None, recovered_clock=registered, recovered_sample=sample, saved_census=saved,
                                   protected_private_assignments=active,
                                   terminal_private_invocations=closed, after_floor170_interface=hourly.INTERFACE,
                                   after_floor170_receiver=bound(new/"after_floor170_status.py"))


def validate(api, proposed, seal):
    actual = ready(api, proposed["fleet"], seal)
    need(actual == proposed or (proposed["completed_sample"] is None and actual["completed_sample"] is not None
         and dict(actual, completed_sample=None) == proposed), "V67 handoff changed its fleet or clock")
