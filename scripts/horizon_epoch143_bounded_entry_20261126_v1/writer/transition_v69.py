"""Transfer the existing writer and observed owners to the next epoch 143 attempt."""
from pathlib import Path
from types import SimpleNamespace

from evidence import BASE, bound, checked, need
from transition import clock
import runway_retry143 as following
import transition_v68 as previous


V68_SHA = "747c3740e5beb31f4cc0a87fad47a143fc2337d664922535d156e75da5527355"
V68_SEAL = "290592e137b70208701f11a6dbaba10a0c84551991cd0233024bacc0a60a687f"


def native_assignments(fleet):
    active, closed = previous.native_assignments(fleet)
    need(closed.get(following.older.PROFILE.unit) == following.IID,
         "unreleased 143 owner absent from the native history")
    context = SimpleNamespace(fleet=fleet, sample_ref=fleet["observer"])
    _, _, row = following.census(context, fleet[following.second.EPOCH143.field], fleet[following.second.PROFILE.field])
    if row:
        name, actor = row["unit"]["Id"], row["actor"]
        iid = actor["producer_invocation_id"]
        need(name not in active and iid != following.IID, "foreign 143 producer or duplicated owner")
        if row["phase"] == "terminal":
            need(row["native_terminal"]["invocation_id"] == iid, "different native 143 terminal")
            closed[name] = iid
        else:
            permit = following.PROFILE.base / "barrier/allow"
            need(row["phase"] in ("bootstrap", "worker") and row["guard"]
                 and permit.read_bytes() == iid.encode() and row["unit"]["InvocationID"] == iid,
                 "143 successor is crossing its release")
            closed.pop(name, None)
            active[name] = dict(unit=name, iid=iid, pid=str(actor["producer_pid"]), intent=row["held_owner"])
    return active, closed


def ready(api, head, seal):
    root = api["ROOT"]
    old_dir = root / api["failed166_package"](68)
    owner = dict(path=str(root / "FAILED166_CADENCE_V68_ACTIVE.json"), sha256=V68_SHA)
    old = checked(owner)
    prior = checked(old["ready"])
    latest = max(BASE.glob("root*/ROOT_COMPLETE_OPERATIONAL_FLEET.json"), key=lambda p: p.stat().st_mtime_ns)
    need(old["new"]["program"] == str(old_dir / "status_cycle.py") and head == bound(latest)
         and prior["package"] == dict(path=str(old_dir / "deployment-seal-receipt.json"), sha256=V68_SEAL),
         "different incumbent writer or fleet")
    fleet = checked(head)
    active, closed = native_assignments(fleet)
    need(not (following.PROFILE.base / "HELD_OWNER.json").exists()
         and following.PROFILE.unit not in active, "143 successor precedes writer enrollment")
    contract = checked(following.PROFILE.contract)
    need(contract["unit"] == following.PROFILE.unit and contract["held_stop"] == following.CLOSURE
         and contract["prefix_acceptance"] == following.second.PREFIX, "unbound 143 retry contract")
    config, timer = fleet["sole_next_observer"], fleet["sole_next_timer"]
    completed = clock(api, fleet, api["sealed"](config), timer, config)
    current = api["CURRENT"].parent
    copies = {k:bound(current / Path(v["path"]).name) for k,v in prior.items()
              if isinstance(v, dict) and "path" in v and Path(v["path"]).parent == old_dir and k != "package"}
    return prior | copies | dict(package=seal,old_owner=owner,fleet=head,config=config,timer=timer,
        completed_sample=completed,protected_private_assignments=active,terminal_private_invocations=closed,
        second_hourly143_held_retry_contract=following.PROFILE.contract,second_hourly143_unreleased_terminal=following.CLOSURE,
        second_hourly143_runway_reader=bound(current / "runway_retry143.py"))


def validate(api, proposed, seal):
    actual = ready(api, proposed["fleet"], seal)
    need(actual == proposed or proposed["completed_sample"] is None and actual["completed_sample"] is not None
         and dict(actual, completed_sample=None) == proposed, "V69 lost the existing clock or live owners")
