"""Move the unissued fourth 162 operator to its qualified cap on the existing observer clock."""
from pathlib import Path
import os
import runpy

from evidence import BASE, bound, checked, need
from transition import clock
import transition_v74 as prior
import fourth162_route as route

V74_SHA = "4d965c653dee245c39632d10ab050b565c471d4d68440a4225668ddffc565f42"
V74_SEAL = "9c162fcc08c7c21277ab73c85d9e69f3ef060535bdc9086558e2ad44c5c4c889"
V74_READY = "7e9ff0f99f97a277feff1926f0aa96da3791f0d58c298bb1b2d67ec0eaf99ada"
CONTROL = BASE/"epoch162-fourth-replay-20261128-v1"
FULL = dict(path=str(CONTROL/"INTERFACE.json"),sha256="6102a47dd71ee77c34cd7992cf268cad14c8f4f8c829699bd14d28582df6572b")
SMALL = dict(path=str(CONTROL/"INTERFACE_54.json"),sha256="d0aeddbde2ebef0a6a015dfd06e8917c0842cd7701f1b559fdb3887acd88d396")
native_assignments = prior.native_assignments


def ready(api, head, seal):
    latest = max(BASE.glob("root*/ROOT_COMPLETE_OPERATIONAL_FLEET.json"),key=lambda p:p.stat().st_mtime_ns)
    old_dir = api["ROOT"]/api["failed166_package"](74)
    owner = dict(path=str(api["ROOT"]/"FAILED166_CADENCE_V74_ACTIVE.json"),sha256=V74_SHA)
    old = checked(owner)
    previous = checked(old["ready"])
    original, small = checked(FULL), checked(SMALL)
    layout = route.fourth.api()
    need(head == bound(latest) and old["ready"]["sha256"] == V74_READY and old["new"]["program"] == str(old_dir/"status_cycle.py")
         and previous["package"] == dict(path=str(old_dir/"deployment-seal-receipt.json"),sha256=V74_SEAL)
         and previous["fourth162_interface"] == small["full_size_interface"] == FULL
         and previous["fourth162_scope"] == original["scope"] and previous["fourth162_provider"] == original["provider"]
         and previous["fourth162_reader"] == bound(old_dir/"fourth162_status.py") and previous["fourth162_reader"]["sha256"] == original["reader"]["sha256"]
         and previous["fourth162_predecessor"] == original["previous"] == small["previous"] == route.TERMINAL
         and route.INTERFACE == SMALL and checked(small["scope"]) == layout.scope()
         and layout.PKG.parent == CONTROL and layout.profile(36)["producer_memory_max"] == 54 << 30,
         "changed fourth 162 writer registration or prior custody")
    proof = checked(small["kernel_qualification"])
    need(proof["profile"] == layout.profile(36) and proof["old_interface"]==FULL and small["kernel_qualification"]["sha256"]=="3dff8feb69707a03ee4dda3c6db45b9977a025839565d762b13cc2bdd6396773",
         "wrong 54 GiB geometry")
    fleet = checked(head)
    historic = runpy.run_path(str(old_dir/"fourth162_status.py"))
    active, closed = native_assignments(fleet)
    need(historic["current"](fleet) is None and route.fourth.current(fleet) is None and route.UNIT not in active
         and route.UNIT not in closed and all(not os.path.lexists(path) for path in
          (CONTROL/"SPLIT162_ENROLLMENT.json", layout.DATA, layout.RUN, layout.GUARDS, layout.ALLOW, layout.CGROUP)),
         "fourth 162 has already received an owner")
    for unit in (layout.UNIT,layout.TIMER,layout.TIMER.replace(".timer",".service")):
        p=layout.manager(unit)
        need(p["ActiveState"] in ("inactive","failed") and p.get("MainPID","0")=="0" and not p["Job"] and not p.get("ControlGroup"),"occupied fourth unit")
    config,timer = fleet["sole_next_observer"],fleet["sole_next_timer"]
    sample = clock(api,fleet,api["sealed"](config),timer,config)
    current = api["CURRENT"].parent
    copies = {k:bound(current/Path(v["path"]).name) for k,v in previous.items()
              if k!="package" and isinstance(v,dict) and "path" in v and Path(v["path"]).parent == old_dir}
    return previous | copies | route.ready_fields(current) | dict(package=seal,old_owner=owner,fleet=head,config=config,timer=timer,
        completed_sample=sample,protected_private_assignments=active,terminal_private_invocations=closed,
        epoch167_assembly_owner=prior.assembly.owner_binding(),fourth162_full_size_interface=FULL,
        fourth162_kernel_qualification=small["kernel_qualification"])


def validate(api, proposed, seal):
    actual=ready(api,proposed["fleet"],seal)
    need(actual==proposed or proposed["completed_sample"] is None and actual["completed_sample"] is not None
         and dict(actual,completed_sample=None)==proposed,"V75 changed the observer or protected roster")
