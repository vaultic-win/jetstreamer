"""Exercise the new writer interface against retained target-host evidence."""
from copy import deepcopy
from pathlib import Path
import runpy
import sys
from types import SimpleNamespace


def qualify():
    here=Path(__file__).resolve().parent
    derive=runpy.run_path(str(here/"second_wire.py"))
    rt=Path("/var/lib/jetstreamer/horizon_runtime_data")
    old=rt/"survivor172-cadence-20261122-v1/tools-cold168-retry5-failed166-v55-entry146"
    sys.path[:0]=[str(old),str(rt/"prefix140-status-cadence-20261122-v1/cadence-tools")]
    import evidence
    mod={}
    code=derive["status"]((old/"retry169_status.py").read_text())
    exec(compile(code,"retry169_status.py","exec"),mod)
    compile(derive["wire"]((old/"split_wire.py").read_text()),"split_wire.py","exec")
    fleet=evidence.checked(dict(path=str(rt/"root034808-live166167170-20261128-v1/ROOT_COMPLETE_OPERATIONAL_FLEET.json"),
                                 sha256=derive["FLEET_SHA"]))
    api=mod["receiver"]()
    assert mod["FIELD"]==api["observe"].FIELD=="current_private169_retry2"
    assert mod["KEY"]=="private169_retry2_start"
    scoped=evidence.checked(mod["SCOPE"])
    assert scoped["producer_unit"]==mod["UNIT"] and scoped["cadence_source"]==mod["CADENCE"]
    current=api["observe"].current(fleet)
    assert current is None, "this fixture is for unpublished attempt-two admission"
    assert api["observe"].census(fleet) is None and api["observe"].predecessor_view(fleet)==fleet
    pending=SimpleNamespace(fleet=fleet,cfg=dict(diagnostic_replays=[]),sample=dict(diagnostic_replays=[]))
    assert api["observe_retry"](pending,None) is None
    bad=deepcopy(fleet)
    bad["current_private169_retry"]["invocation_id"]="a"*32
    try:
        api["observe"].current(bad)
    except ValueError:
        pass
    else:
        raise AssertionError("foreign first attempt accepted")
    rebuilt=dict(fleet)
    del rebuilt["current_private169_retry"]
    mod["install"](rebuilt,None)
    assert rebuilt["current_private169_retry"]==fleet["current_private169_retry"]
    print("Second receiver, absent owner, foreign predecessor rejection and retained closure passed")


if __name__=="__main__":
    qualify()
