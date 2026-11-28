"""Bind the paid epoch 169 reservation to its second gate after the first drained."""
import hashlib
import json
import os
from pathlib import Path
import runpy
import stat
import sys

RT = Path("/var/lib/jetstreamer/horizon_runtime_data")
FIRST = RT/"epoch169-hourly-retry-20261128-v1"
SECOND = RT/"epoch169-hourly-retry-20261128-v2"
SOURCE = SECOND/"operator-v1"
SCOPE = "322698c6be8e7632654eea5b9074a395b61f27db648bb6ebb818f79b0ee1bd0e"
CLOSURE = "24d2fc5ecf736827e0b06af6194f85ad1dae055f33065d6e9e20606eb17ee9dc"
OPERATOR = "904ceb6b6d3f97f5e3c2dce585cff64254c05aee6fdc4d5f229fa92c62d7a876"
G = 1 << 30


def require(ok, message):
    if not ok:
        raise ValueError(message)


def body(path, digest):
    st = path.lstat()
    require(path.resolve(strict=True)==path and stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_nlink==1
            and not st.st_mode & 0o222, "unsealed second 169 input " + str(path))
    data = path.read_bytes()
    require(hashlib.sha256(data).hexdigest()==digest, "changed second 169 input " + str(path))
    return data


def load():
    seal = json.loads(body(SOURCE/"deployment-seal-receipt.json", OPERATOR))
    scope = json.loads(body(SECOND/"SCOPE.json", SCOPE))
    stop = json.loads(body(FIRST/"UNRELEASED_HELD_CLOSURE.json", CLOSURE))
    old = json.loads(body(FIRST/"SCOPE.json", "eb589f4c2c51dcf75314d50d7074a9411d034e6bd3f6a8bd826705ca4a1feb3a"))
    require(seal["destination"]==str(SOURCE) and scope["operator"]==dict(path=str(SOURCE/"deployment-seal-receipt.json"),sha256=OPERATOR)
            and scope["first_gate_closure"]==dict(path=str(FIRST/"UNRELEASED_HELD_CLOSURE.json"),sha256=CLOSURE)
            and scope["parent_scope"]==dict(path=str(FIRST/"SCOPE.json"),sha256="eb589f4c2c51dcf75314d50d7074a9411d034e6bd3f6a8bd826705ca4a1feb3a")
            and not stop["native_worker_started"] and not stop["resource_credit_bytes"] and not os.path.lexists(FIRST/"GRANT.json")
            and scope["producer_unit"]=="horizon-qualify-169-hourly-retry-20261128-v2.service"
            and all(scope[k]==old[k] for k in ("inputs","worker","node","first","last","terminal_hash","predecessor","quota"))
            and scope["quota"]==dict(guard_cpu=1_000_000,guard_ram=G,home_control=64<<20,home_output=4*G,
                maximum_worker_vmas=3_500_000,producer_cpu=2_000_000,producer_ram=56*G,scratch=44*G)
            and not scope["canonical_publication_authorized"], "changed second 169 scope or old gate custody")
    for item in seal["members"]:
        file = SOURCE/item["name"]
        require(file.parent==SOURCE and len(body(file,item["sha256"]))==item["bytes"], "incorrect 169 source size")
    for name in ("contract","namespace","quote"):
        existing = sys.modules.get(name)
        require(existing is None or Path(existing.__file__)==SOURCE/(name+".py"), "foreign 169 module "+name)
    snapshot = list(sys.path)
    try:
        observer = runpy.run_path(str(SOURCE/"observe.py"))
    finally:
        sys.path[:] = snapshot
    require(all(Path(sys.modules[name].__file__)==SOURCE/(name+".py") for name in ("contract","namespace","quote")),
            "second 169 observer used a different installation")
    # The lower historical comparison filters the authenticated second row
    # out of the original singleton's private input. Its terminal stays intact.
    return observer


def bind(core, native):
    scope, ref = core.read(SECOND/"SCOPE.json", SCOPE)
    old, previous = core.read(FIRST/"UNRELEASED_HELD_CLOSURE.json", CLOSURE)
    old_scope = core.bound(scope["parent_scope"])
    end = core.bound(old["terminal"])
    require(end["disposition"]=="private-payload-never-released" and not end["canonical_publication_authorized"]
            and scope["first_gate_closure"]==previous and old_scope["producer_unit"] in old["manager"],
            "previous 169 terminal does not identify the unpaid gate")
    for name, saved in old["manager"].items():
        if name.endswith(".timer"):
            timer=core.state(name,"Id,ActiveState,Job")
            require(timer["ActiveState"]=="inactive" and not timer["Job"], "first 169 timer reacquired")
        else:
            unit=core.inactive(name)
            require(not unit["ControlGroup"], "first 169 producer, guard or watcher reacquired")
    reservation = native["planned_169_retry"]
    require(reservation["additional_home"]==scope["quota"]["home_output"]+scope["quota"]["home_control"]
            and reservation["additional_ram"]+native["stopped_169_compute_handoff"]["retained_159_ram"]==scope["quota"]["producer_ram"],
            "second 169 does not fit the original paid reservation")
    reservation.update(second_scope=ref, first_unreleased_closure=previous)
