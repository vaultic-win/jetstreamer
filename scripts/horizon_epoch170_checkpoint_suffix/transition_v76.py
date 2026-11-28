"""Carry the V75 observer and its exact native assignments into V76."""
from pathlib import Path

from evidence import BASE, bound, checked, need
from transition import clock
import transition_v75 as prior
import next_hourly170_status as route

V75_OWNER = None
V75_PACKAGE = None
V75_READY_SHA = None
assembly = prior.assembly


def native_assignments(fleet):
    active, closed = prior.native_assignments(fleet)
    predecessor = route.contract.stopped_owner(fleet)
    unit = predecessor["unit"]["Id"]
    iid = predecessor["native_terminal"]["INVOCATION_ID"]
    need(unit not in active and closed.get(unit,iid) == iid,"previous 170 still has a live native assignment")
    closed[unit] = iid
    row = fleet.get(route.FIELD)
    if row:
        unit, iid = row["unit"]["Id"], row["actor"]["producer_invocation_id"]
        need(unit == route.UNIT and unit not in active and unit not in closed
             and checked(row["actor_ref"]) == row["actor"],"different next-hourly native owner")
        if row["phase"] == "terminal":
            need(row["native_terminal"] == route.gap.terminal(row["actor"]),"different next-hourly terminal")
            closed[unit] = iid
        else:
            need(row["phase"] in ("bootstrap","worker") and row["release"]
                 and row["unit"]["InvocationID"] == iid,"next-hourly 170 is crossing release")
            active[unit] = dict(unit=unit,iid=iid,pid=row["unit"]["MainPID"],intent=row["actor_ref"])
    return active, closed


def ready(api,head,seal):
    current_fleet = max(BASE.glob("root*/ROOT_COMPLETE_OPERATIONAL_FLEET.json"),key=lambda p:p.stat().st_mtime_ns)
    owner = checked(V75_OWNER)
    previous = checked(owner["ready"])
    old = Path(V75_PACKAGE["path"]).parent
    need(head == bound(current_fleet) and owner["ready"]["sha256"] == V75_READY_SHA
         and owner["new"]["program"] == str(old/"status_cycle.py")
         and previous["package"] == V75_PACKAGE,"different V75 writer, package or fleet")
    fleet = checked(head)
    active, closed = native_assignments(fleet)
    need(not fleet.get(route.FIELD) and route.UNIT not in active,"next-hourly 170 started before enrollment")
    route.gap.native.idle(route.UNIT)
    scope = route.interface()
    route.contract.checkpoint(scope)
    config,timer = fleet["sole_next_observer"],fleet["sole_next_timer"]
    completed = clock(api,fleet,api["sealed"](config),timer,config)
    current = api["CURRENT"].parent
    refs = {key:bound(current/Path(value["path"]).name) for key,value in previous.items()
            if key != "package" and isinstance(value,dict) and "path" in value and Path(value["path"]).parent == old}
    return previous | refs | dict(package=seal,old_owner=V75_OWNER,fleet=head,config=config,timer=timer,
        completed_sample=completed,protected_private_assignments=active,terminal_private_invocations=closed,
        epoch167_assembly_owner=assembly.owner_binding(),next_hourly170_interface=route.INTERFACE)


def validate(api,proposed,seal):
    actual = ready(api,proposed["fleet"],seal)
    need(actual == proposed or proposed["completed_sample"] is None and actual["completed_sample"] is not None
         and dict(actual,completed_sample=None) == proposed,"V76 observer or protected assignment changed")
