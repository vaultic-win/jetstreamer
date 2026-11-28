"""Select the smaller unissued 169 producer and preserve the complete V71 population."""
from pathlib import Path
import os
import runpy

import adjacent169_route as route
from evidence import BASE, bound, checked, need
from transition import clock
from transition_v71 import native_assignments

V71_SHA="1d9087ae207f193876a0d3e289141e0b21852a9e9b6012344fe4d0871970b463"
V71_SEAL="0c48be5c716513e7de5eb41b61894a39bcffb576cf90f1433443a91dff5ef809"
CONTROL=BASE/"epoch169-from-73245218-20261128-v1"
FULL=dict(path=str(CONTROL/"INTERFACE.json"),sha256="9bd834876a560f4e90dc9623d019acfbf49d1cdaf3edba09fb6da69784152226")
SMALL=dict(path=str(CONTROL/"INTERFACE_48.json"),sha256="f026dcb7ec477936c55ccc558cae4580254d91d4c7d0e7ba5c23a69308dc245e")


def ready(api,head,seal):
    root=api["ROOT"]
    old_dir=root/api["failed166_package"](71)
    owner=dict(path=str(root/"FAILED166_CADENCE_V71_ACTIVE.json"),sha256=V71_SHA)
    old=checked(owner)
    prior=checked(old["ready"])
    latest=max(BASE.glob("root*/ROOT_COMPLETE_OPERATIONAL_FLEET.json"),key=lambda p:p.stat().st_mtime_ns)
    full=checked(FULL)
    compact=checked(SMALL)
    native=route.live.api()
    need(head==bound(latest) and old["new"]["program"]==str(old_dir/"status_cycle.py")
         and prior["package"]==dict(path=str(old_dir/"deployment-seal-receipt.json"),sha256=V71_SEAL)
         and prior["adjacent169_interface"]==compact["prior_interface"]==FULL
         and prior["adjacent169_scope"]==full["scope"] and prior["adjacent169_provider"]==full["provider"]
         and prior["adjacent169_reader"]==bound(old_dir/"adjacent169_status.py")
         and prior["adjacent169_reader"]["sha256"]==full["reader"]["sha256"]
         and compact["previous"]==full["previous"]==prior["adjacent169_predecessor"]
         and route.refs.INTERFACE==SMALL and native.profile(44)["producer_memory_max"]==48<<30
         and checked(compact["scope"])["unissued_full_size_scope"]==full["scope"],
         "different V71 writer, compact scope or precedent")
    refusal=checked(compact["refusal"])
    qualification=checked(compact["reduced_memory_qualification"])
    need(not refusal["fits"] and refusal["phase"]=="prestart" and refusal["ram_margin"]==-3951080448
         and qualification["refusal"]==compact["refusal"] and qualification["profile"]==native.profile(44)
         and qualification["cgroup"]["kernel_values"]==[str(48<<30),str(45<<30),"0","200000 100000"],
         "missing 169 kernel cap or full-size decline")
    fleet=checked(head)
    historic=runpy.run_path(str(old_dir/"adjacent169_status.py"))
    active,closed=native_assignments(fleet)
    need(historic["current"](fleet) is None and route.live.current(fleet) is None and route.UNIT not in active
         and route.UNIT not in closed and all(not os.path.lexists(path) for path in
         (CONTROL/"ADJACENT169_ENROLLMENT.json",native.DATA,native.RUN,native.GUARDS,native.ALLOW,native.CGROUP)),
         "original 169 owns an enrollment, output or producer")
    for unit in (native.UNIT,native.TIMER,native.TIMER.replace(".timer",".service")):
        props=native.manager(unit)
        need(props["ActiveState"] in ("inactive","failed") and props.get("MainPID","0")=="0" and not props["Job"]
             and not props.get("ControlGroup"),"occupied 169 unit while changing caps")
    config,timer=fleet["sole_next_observer"],fleet["sole_next_timer"]
    completed=clock(api,fleet,api["sealed"](config),timer,config)
    current=api["CURRENT"].parent
    copies={key:bound(current/Path(ref["path"]).name) for key,ref in prior.items()
            if key!="package" and isinstance(ref,dict) and "path" in ref and Path(ref["path"]).parent==old_dir}
    return prior|copies|route.ready_fields(current)|dict(package=seal,old_owner=owner,fleet=head,config=config,timer=timer,
        completed_sample=completed,protected_private_assignments=active,terminal_private_invocations=closed,
        adjacent169_full_size_interface=FULL,adjacent169_full_size_refusal=compact["refusal"],
        adjacent169_reduced_memory_qualification=compact["reduced_memory_qualification"])


def validate(api,proposed,seal):
    actual=ready(api,proposed["fleet"],seal)
    need(actual==proposed or proposed["completed_sample"] is None and actual["completed_sample"] is not None
         and dict(actual,completed_sample=None)==proposed,"V72 lost the observer or a protected producer")
