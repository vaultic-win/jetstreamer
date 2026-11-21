"""Run source, malformed-boundary and actual incumbent checks against the sealed publisher."""
import argparse
import copy
import importlib.util
import json
import sys
from pathlib import Path
from unittest.mock import patch


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("package", type=Path)
    parser.add_argument("fleet", type=Path)
    parser.add_argument("fleet_sha256")
    a = parser.parse_args()
    sys.path.insert(0, str(a.package))
    import evidence
    old = load(a.package / "public_witness.py", "incumbent")
    new = load(Path(__file__).with_name("public_witness.py"), "next_witness")
    fleet = evidence.checked({"path":str(a.fleet),"sha256":a.fleet_sha256})
    obligation = fleet["continuing_audit_obligation"]
    dev = Path("/home/sol").stat().st_dev
    old_audit, old_storage, old_owner = old.observe_public(dev, obligation)
    new_audit, new_storage, new_owner = new.observe_public(dev, obligation)
    for d in (old_audit, new_audit):
        d.pop("observed_at")
        if d["child"]:
            d["child"].pop("elapsed_seconds", None)
            d["child"].pop("updated_at", None)
    assert old_owner == new_owner and old_storage == new_storage and old_audit == new_audit
    assert not (new.V14/"PUBLIC_OWNER.json").exists()
    previous = evidence.bound(new.SUCCESSOR/"PUBLIC_OWNER.json")
    v13 = evidence.checked(previous)
    stopped_path = str(new.V14/"STOPPED.json")
    boundary_path = str(new.V14/"BOUNDARY.json")
    def pair(path):
        return {"path":str(path),"sha256":"1"*64}
    sample = evidence.checked(evidence.bound(new.ATTEMPT/"reports"/"epoch-72.json"))
    report = copy.deepcopy(sample)
    report["expected_first_slot"] = 31536000
    report["expected_last_slot"] = 31967999
    report["report"].update(epoch=73, first_slot=31536000, last_slot=31967999)
    launch = dict(previous_owner=previous,seal={"path":str(new.V14_PACKAGE/"deployment-seal-receipt.json"),"sha256":new.V14_SEAL_SHA},
                  stopped=v13["stopped"],source_commit=new.V14_COMMIT,InvocationID="2"*32,
                  pid=999,start_ticks=v13["start_ticks"]+1,at=103,previous_stopped=pair(stopped_path))
    closure = dict(native=dict(Id=new.native.UNIT, ActiveState="inactive", MainPID="0", Job=""),
                   previous_owner=previous,old_cgroup_empty=True,old_pid_absent_or_reused=True,
                   at=102,boundary=pair(boundary_path))
    boundary = dict(previous_owner=previous,epoch=73,at=101,previous_child_pid=3376515,
                    previous_child_drained=True,new_playback_started=False,
                    inventory={"path":str(new.PUBLIC/"inventory.json"),"sha256":new.INVENTORY_SHA},
                    event=pair(new.ATTEMPT/"branch-change.json"),accepted_epochs=list(range(73)),
                    native_report=pair(new.ATTEMPT/"reports"/"epoch-73.json"))
    event = dict(at=100,completed=3,reader_commit="5bb2637754782ad3f03f5b780a5024fa89602adc")
    args = [previous,launch,closure,boundary,event,report,sample]
    new.v14_chain(*args)
    cases = [(1,"InvocationID",v13["InvocationID"]),(1,"seal",v13["seal"]),(1,"rollback",pair("untrusted")),
             (2,"old_cgroup_empty",False),(2,"old_pid_absent_or_reused",False),
             (3,"accepted_epochs",list(range(71))),(3,"new_playback_started",True),
             (3,"previous_child_drained",False),(3,"inventory",pair("fake")),
             (3,"at",103),(3,"previous_child_pid",1),(4,"reader_commit","0"*40),
             (4,"completed",True),(5,"full_epoch_verified",False),(5,"invocation",[]),
             (5,"expected_last_slot",31967998),(5,"source","http://elsewhere")]
    for idx,key,value in cases:
        bad = copy.deepcopy(args)
        bad[idx][key]=value
        try:
            new.v14_chain(*bad)
        except ValueError:
            continue
        raise AssertionError(f"accepted malformed test {idx}.{key}")
    original_checked = new.checked
    authorized_rollback = pair(new.V14/"ROLLBACK.json")
    fallback = dict(launch, rollback=authorized_rollback, seal=v13["seal"], source_commit=v13["source_commit"])
    failed = dict(stopped=launch["previous_stopped"], attempted_seal=launch["seal"],
                  v14_cgroup_empty=True, accepted_results_unchanged=True, at=102)
    with patch.object(new, "checked", side_effect=lambda ref: failed if ref == authorized_rollback else original_checked(ref)):
        new.v14_chain(previous, fallback, closure, boundary, event, report, sample)
        for key in ("v14_cgroup_empty", "accepted_results_unchanged"):
            failed[key]=False
            try:
                new.v14_chain(previous, fallback, closure, boundary, event, report, sample)
            except ValueError:
                failed[key]=True
            else:
                raise AssertionError(f"accepted unsafe rollback {key}")
    print(json.dumps(dict(passed=5+len(cases), negative=len(cases)+2, fleet=a.fleet_sha256,
                    incumbent_iid=old_owner["native"]["InvocationID"], incumbent_image=old_owner["image"],
                    preserved_slice=old_owner["shared_slice"], live_incumbent_untouched=True,
                    simulated_v14_only=True), indent=2))


if __name__ == "__main__":
    main()
