"""Bind the funded 169 reservation to its third invocation after the guarded predecessor stopped."""
import hashlib
import json
from pathlib import Path
import runpy
import sys


RT=Path("/var/lib/jetstreamer/horizon_runtime_data")
PARENT=RT/"epoch162-first-hourly-completion-20261127-v2/issued-price-v9/retry169_peer.py"
OLD=RT/"epoch169-hourly-retry-20261128-v2"
THIRD=RT/"epoch169-hourly-retry-20261128-v3"
SOURCE=THIRD/"operator-v1"
SCOPE="7668d6747cfe67bfbfbc5d0db14331d8db57a73b1fb4d3d6a12820dc08a56daf"
OPERATOR="9203f263c94be2d6ae9cacbcda15b72cfed8662146b940af1704cd617e582196"
STOP="c09b0bf82efe4c970a0810219bdccb03a1869333a30cd1fef39e9034dfc40e02"
FIXTURE="2e772ec0fd3582d02c9f7f29b24810ab4389e8d05684851f0bc271a30827f5ec"


def previous():
    if hashlib.sha256(PARENT.read_bytes()).hexdigest()!="453feab97bdad5e84ed34669cc7e1d5832687307a1f2e13b6dd3b2521f2ed97d":
        raise ValueError("different second peer protocol")
    return runpy.run_path(str(PARENT))


def load():
    parent=previous()
    body,need=parent["body"],parent["require"]
    seal=json.loads(body(SOURCE/"deployment-seal-receipt.json",OPERATOR))
    scope=json.loads(body(THIRD/"SCOPE.json",SCOPE))
    closure=json.loads(body(OLD/"WORKER_ALIAS_STOP.json",STOP))
    prior=json.loads(body(OLD/"SCOPE.json",parent["SCOPE"]))
    receipt=scope["guard_projection_qualification"]
    proof=json.loads(body(Path(receipt["path"]),FIXTURE))
    need(seal["destination"]==str(SOURCE) and scope["operator"]==dict(path=str(SOURCE/"deployment-seal-receipt.json"),sha256=OPERATOR)
         and scope["producer_unit"]=="horizon-qualify-169-hourly-retry-20261128-v3.service"
         and scope["second_guard_stop"]==dict(path=str(OLD/"WORKER_ALIAS_STOP.json"),sha256=STOP)
         and scope["parent_scope"]==dict(path=str(OLD/"SCOPE.json"),sha256=parent["SCOPE"])
         and all(scope[k]==prior[k] for k in ("inputs","node","worker","quota","first","last","terminal_hash","predecessor","first_gate_closure"))
         and closure["invocation_id"]=="1446633fdd224bab9297255a7ad66330"
         and not closure["first_replay_slot_observed"] and not closure["resource_credit_bytes"]
         and scope["guard_readonly_source"]=="/home/sol/.jetstreamer-private/epoch169-hourly-retry-20261128-v3"
         and scope["guard_readonly_target"]==proof["projected_root"]=="/home/sol/.jetstreamer-private/epoch169-hourly-source-20261123-v1"
         and receipt==closure["proof"] and receipt["sha256"]==FIXTURE and not scope["canonical_publication_authorized"],
         "third attempt differs from its predecessor, guard qualification or reserved work")
    for item in seal["members"]:
        file=SOURCE/item["name"]
        need(file.parent==SOURCE and len(body(file,item["sha256"]))==item["bytes"],"invalid third operator")
    names=("contract","namespace","quote")
    for name in names:
        active=sys.modules.get(name)
        need(active is None or Path(active.__file__)==SOURCE/(name+".py"), "foreign 169 dependency "+name)
    search=sys.path[:]
    try:
        api=runpy.run_path(str(SOURCE/"observe.py"))
    finally:
        sys.path[:]=search
    need(all(Path(sys.modules[n].__file__)==SOURCE/(n+".py") for n in names), "different third observer")
    return api


def bind(core,native):
    parent=previous()
    parent["bind"](core,native)
    scope,ref=core.read(THIRD/"SCOPE.json",SCOPE)
    stop,terminal=core.read(OLD/"WORKER_ALIAS_STOP.json",STOP)
    sample=core.bound(stop["stop_intent"])["sample"]
    done=core.bound(stop["stop_completion"])
    end=core.bound(stop["terminal"])
    hold=core.bound(stop["held"])
    need=parent["require"]
    need(scope["second_guard_stop"]==terminal and scope["parent_scope"]==stop["scope"] and end["invocation_id"]==hold["invocation_id"]
         ==done["producer_invocation_id"]==sample["producer_invocation_id"]==stop["invocation_id"]
         and done["terminal"]["pid"]==0 and end["archive"] is None and not end["private_span"]
         and sample["worker_observation_error"]=="worker escaped the bound generation" and sample["trip_reason"]=="worker-observation-failed"
         and scope["guard_projection_qualification"]==stop["proof"] and not stop["resource_credit_bytes"],
         "different 169 guard stop or custody")
    for name in stop["states"]:
        if name.endswith(".timer"):
            st=core.state(name,"Id,ActiveState,Job")
            need(st["ActiveState"]=="inactive" and not st["Job"],"second 169 timer still active")
        else:
            need(not core.inactive(name)["ControlGroup"],"second 169 reacquired its cgroup")
    paid=native["planned_169_retry"]
    need(paid["second_scope"]==scope["parent_scope"] and paid["additional_home"]==scope["quota"]["home_output"]+scope["quota"]["home_control"]
         and paid["additional_ram"]+native["stopped_169_compute_handoff"]["retained_159_ram"]==scope["quota"]["producer_ram"],
         "third 169 changed the paid resource envelope")
    paid.update(third_scope=ref, second_guard_stop=terminal)
