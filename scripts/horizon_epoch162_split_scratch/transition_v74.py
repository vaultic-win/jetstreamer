"""Enroll the fourth epoch 162 reader after the original third segment reaches custody."""
from pathlib import Path

from evidence import BASE, bound, checked, need
from transition import clock
import transition_v73 as prior
import fourth162_route as route

V73_SHA = "81d8916b2e50ff8989b48c948f6f49c6eed92232b3bdcac05986ccd64bf6aa70"
V73_SEAL = "9a35d3e4d2330a061cd6139d7a8229eb36671c05b67f90dd46082fb5874b22e8"
V73_READY = "a0f1aff75b594840a37a0cfefce95f0e3b98fc2f924b2bf882c33df7025d9dd6"
assembly = prior.assembly


def native_assignments(fleet):
    active, closed = prior.native_assignments(fleet)
    third = route.third_terminal(fleet)
    need(closed.get(third["unit"]["Id"]) == route.IID, "third 162 absent from the terminal roster")
    row = route.fourth.current(fleet)
    if row:
        unit, iid = row["unit"]["Id"], row["producer_invocation_id"]
        need(unit == route.UNIT and unit not in active and unit not in closed
             and checked(row["held_owner"]) == row["actor"] and row["actor"]["producer_invocation_id"] == iid,
             "different fourth 162 actor")
        if row["phase"] == "terminal":
            need(row["terminal"] == route.fourth.native_end(route.fourth.api(),row["actor"]), "different fourth 162 terminal")
            closed[unit] = iid
        else:
            need(row["phase"] in ("bootstrap","worker") and row["release"] and row["unit"]["InvocationID"] == iid,
                 "fourth 162 is crossing its guarded release")
            active[unit] = dict(unit=unit, iid=iid, pid=row["unit"]["MainPID"], intent=row["held_owner"])
    return active, closed


def ready(api, head, seal):
    latest = max(BASE.glob("root*/ROOT_COMPLETE_OPERATIONAL_FLEET.json"),key=lambda p:p.stat().st_mtime_ns)
    old_dir = api["ROOT"]/api["failed166_package"](73)
    owner = dict(path=str(api["ROOT"]/"FAILED166_CADENCE_V73_ACTIVE.json"),sha256=V73_SHA)
    old = checked(owner)
    previous = checked(old["ready"])
    need(head == bound(latest) and old["ready"]["sha256"] == V73_READY
         and old["new"]["program"] == str(old_dir/"status_cycle.py")
         and previous["package"] == dict(path=str(old_dir/"deployment-seal-receipt.json"),sha256=V73_SEAL)
         and all(previous[k] == v for k,v in prior.adjacent.ready_fields(old_dir).items())
         and all(previous[k] == v for k,v in route.prior.ready_fields(old_dir).items()),
         "different V73, fleet, compact 169 or third 162 interface")
    fleet = checked(head)
    active, closed = native_assignments(fleet)
    need(not route.fourth.current(fleet) and route.UNIT not in active, "fourth 162 started before enrollment")
    config, timer = fleet["sole_next_observer"], fleet["sole_next_timer"]
    completed = clock(api,fleet,api["sealed"](config),timer,config)
    current = api["CURRENT"].parent
    refs = {k:bound(current/Path(v["path"]).name) for k,v in previous.items()
            if k != "package" and isinstance(v,dict) and "path" in v and Path(v["path"]).parent == old_dir}
    return previous | refs | prior.adjacent.ready_fields(current) | route.prior.ready_fields(current) | route.ready_fields(current) | dict(
        package=seal,old_owner=owner,fleet=head,config=config,timer=timer,completed_sample=completed,
        protected_private_assignments=active,terminal_private_invocations=closed,epoch167_assembly_owner=assembly.owner_binding())


def validate(api, proposed, seal):
    actual = ready(api,proposed["fleet"],seal)
    need(actual == proposed or proposed["completed_sample"] is None and actual["completed_sample"] is not None
         and dict(actual,completed_sample=None) == proposed, "V74 observer or protected assignment changed")
