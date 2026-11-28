"""Carry the V77 observer and its complete roster into the registered successor 169 interval."""
import os
from pathlib import Path

from evidence import BASE, bound, checked, need
from transition import clock
import transition_v77 as prior
import next169_route as route

V77_OWNER = None
V77_PACKAGE = None
V77_READY = None
assembly = prior.assembly


def native_assignments(fleet):
    active, closed = prior.native_assignments(fleet)
    prev = route.previous(fleet)
    need(closed.get(prev["unit"]["Id"]) == route.OLD_IID, "absent preceding 169 PID1 terminal")
    row = route.live.current(fleet)
    if row is not None:
        unit, iid = row["unit"]["Id"], row["producer_invocation_id"]
        need(unit == route.UNIT and unit not in active and unit not in closed and iid != route.OLD_IID
             and checked(row["held_owner"]) == row["actor"],"unregistered 169 owner")
        if row["phase"] == "terminal":
            need(row["terminal"] == route.live.native_end(route.live.api(),row["actor"]),"different 169 PID1 terminal")
            closed[unit] = iid
        else:
            need(row["phase"] in ("bootstrap","worker") and row["release"] and row["guard"]
                 and row["unit"]["InvocationID"] == iid,"169 is crossing its release")
            active[unit] = dict(unit=unit,iid=iid,pid=row["unit"]["MainPID"],intent=row["held_owner"])
    return active, closed


def ready(api, head, seal):
    latest = max(BASE.glob("root*/ROOT_COMPLETE_OPERATIONAL_FLEET.json"),key=lambda p:p.stat().st_mtime_ns)
    old = Path(V77_PACKAGE["path"]).parent
    current = api["CURRENT"].parent
    active = checked(V77_OWNER)
    inherited = checked(active["ready"])
    need(head == bound(latest) and active["new"]["program"] == str(old/"status_cycle.py")
         and active["ready"]["sha256"] == V77_READY and inherited["package"] == V77_PACKAGE
         and all(inherited[k] == v for k,v in route.prior.ready_fields(old).items())
         and inherited["next_hourly170_interface"] and inherited["fourth162_interface"]
         and route.refs.PREVIOUS == checked(route.refs.SCOPE)["previous"],"different V77 writer, fleet or 169 registration")
    fleet = checked(head)
    protected, closed = native_assignments(fleet)
    need(route.UNIT not in protected and route.UNIT not in closed and not route.live.current(fleet)
         and not fleet.get(route.FIELD),"next 169 interval already occupied")
    layout = route.live.api()
    need(not any(os.path.lexists(p) for p in (layout.DATA,layout.RUN,layout.GUARDS,layout.ALLOW,layout.CGROUP,
             layout.BASE/"NEXT169_ENROLLMENT.json")),"occupied 169 working path")
    for unit in (layout.UNIT,layout.TIMER,layout.TIMER.replace(".timer",".service")):
        state = layout.manager(unit)
        need(state["ActiveState"] in ("inactive","failed") and state.get("MainPID","0") == "0"
             and not state["Job"] and not state.get("ControlGroup"),"occupied 169 unit")
    cfg, timer = fleet["sole_next_observer"],fleet["sole_next_timer"]
    sample = clock(api,fleet,api["sealed"](cfg),timer,cfg)
    copies = {k:bound(current/Path(v["path"]).name) for k,v in inherited.items()
              if k!="package" and isinstance(v,dict) and "path" in v and Path(v["path"]).parent==old}
    return inherited | copies | route.ready_fields(current) | dict(package=seal,old_owner=V77_OWNER,fleet=head,
        config=cfg,timer=timer,completed_sample=sample,protected_private_assignments=protected,
        terminal_private_invocations=closed,epoch167_assembly_owner=assembly.owner_binding())


def validate(api, proposed, seal):
    fresh = ready(api,proposed["fleet"],seal)
    need(fresh == proposed or proposed["completed_sample"] is None and fresh["completed_sample"] is not None
         and dict(fresh,completed_sample=None) == proposed,"observer or roster changed across V78")
