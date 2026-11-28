"""Register the third 162 interval on the incumbent writer's current observation clock."""
from pathlib import Path
from evidence import BASE, bound, checked, need
from transition import clock
from transition_v67 import native_assignments as before
import third162_route as route

V67_SHA = "4748bd09457b12e876763e012bb67371142bc1194349df7def25301ef5967c83"
V67_SEAL = "44451395c11f4de72d6768818e58bd00ac298191746e5167516a375cf24eb3b5"


def native_assignments(fleet):
    active, closed = before(fleet)
    old = route.second_terminal(fleet)
    need(closed.get(old["unit"]["Id"]) == route.IID, "second 162 absent from the terminal roster")
    actor = route.third.current(fleet)
    if actor:
        name, iid = actor["unit"]["Id"], actor["producer_invocation_id"]
        need(name == route.UNIT and name not in active and name not in closed,
             "different owner in the third 162 slot")
        if actor["phase"] == "terminal":
            need(actor["terminal"]["INVOCATION_ID"] == iid, "different native 162 terminal")
            closed[name] = iid
        else:
            need(actor["phase"] in ("bootstrap","worker") and actor["release"]
                 and actor["unit"]["InvocationID"] == iid, "162 is crossing its guarded release")
            active[name] = dict(unit=name, iid=iid, pid=actor["unit"]["MainPID"], intent=actor["held_owner"])
    return active, closed


def ready(api, head, seal):
    root = api["ROOT"]
    previous = root / api["failed166_package"](67)
    owner = dict(path=str(root/"FAILED166_CADENCE_V67_ACTIVE.json"), sha256=V67_SHA)
    old = checked(owner)
    prior = checked(old["ready"])
    need(old["new"]["program"] == str(previous/"status_cycle.py")
         and prior["package"] == dict(path=str(previous/"deployment-seal-receipt.json"),sha256=V67_SEAL)
         and head == bound(max(BASE.glob("root*/ROOT_COMPLETE_OPERATIONAL_FLEET.json"),key=lambda p:p.stat().st_mtime_ns)),
         "different V67 writer or fleet")
    fleet = checked(head)
    active, closed = native_assignments(fleet)
    need(not route.third.current(fleet) and route.UNIT not in active, "third 162 started before enrollment")
    config, timer = fleet["sole_next_observer"], fleet["sole_next_timer"]
    completed = clock(api, fleet, api["sealed"](config), timer, config)
    current = api["CURRENT"].parent
    members = {key:bound(current/Path(ref["path"]).name) for key,ref in prior.items()
               if isinstance(ref,dict) and "path" in ref and Path(ref["path"]).parent == previous and key != "package"}
    historical = {k:v for k,v in prior.items() if k not in ("recovered_clock","recovered_sample","saved_census")}
    return historical | members | route.ready_fields(current) | dict(package=seal, old_owner=owner, fleet=head, config=config, timer=timer,
        completed_sample=completed, protected_private_assignments=active, terminal_private_invocations=closed)


def validate(api, proposed, seal):
    actual = ready(api,proposed["fleet"],seal)
    need(actual == proposed or (proposed["completed_sample"] is None and actual["completed_sample"] is not None
         and dict(actual,completed_sample=None) == proposed), "V68 lost its observation clock or protected owners")
