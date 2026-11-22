"""Record the drained 145 selectors and lock inodes before the same-image handoff."""
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fixture_launch import manager, checked
from qualify import need
c = runpy.run_path(str(Path(__file__).resolve().parents[1] / "register-ready.py"))
r = c["RT"]
prior = r / "epoch145-fixture-phase-dispatch-20261122-v1"
target = r / "epoch145-fixture-retry1-dispatch-20261122-v1"
group = Path("/sys/fs/cgroup/system.slice")
service = "horizon-145-fixture-phase-dispatch-20261122-v1.service"
previous_id = "1419bb0b0fc04fbe849c2f6559045d80"
semantic = r / "epoch145-semantic-continuity-20261121-v1"
worker_sha = "1b16ce2d061e2ec97ab8c1ba81cd2dbcff9d0a759f317fbaf53b64e731a19501"


def closed(name, invocation):
    c["drained"](name, invocation)
    row = manager(name)
    need(not (group / name).exists() and not any(row[k] for k in
         ("ControlGroup", "Triggers", "TriggeredBy", "Job")), "predecessor can still activate")
    return row


def observe():
    base = json.loads(checked(prior / "PREDECESSOR_DRAINED.json",
                      "d267b6e774e26fc5c9d5b95f5845b547afbfde74f58e434b835acd63785a7f07"))
    ready = c["ref"](prior / "READY.json")
    registered = c["read_ref"](ready)
    need(registered["dispatcher"]["invocation_id"] == previous_id and
         registered["original_semantic_invocation"] == "50af3d8ab5da47e8bdc2828feab53908",
         "foreign previous registration")
    c["clean_boundary"](prior / "state", prior)
    c["clean_boundary"](c["SHARED"], c["DIR"])
    previous = closed(service, previous_id)
    earlier = closed(base["previous"]["Id"], base["previous"]["InvocationID"])
    earliest = closed(base["earlier"]["Id"], None)
    journal = subprocess.check_output(["journalctl","--no-pager","-b","-o","json","_PID=1",
            f"UNIT={service}",f"INVOCATION_ID={previous_id}","MESSAGE_ID=98e322203f7a4ed290d09fe03c09fe15"])
    rows = [json.loads(row) for row in journal.splitlines()]
    need(len(rows) == 1 and rows[0].get("EXIT_STATUS") == "1" and
         rows[0]["_BOOT_ID"] == Path("/proc/sys/kernel/random/boot_id").read_text().strip().replace("-",""),
         "previous follower has no terminal PID1 exit")
    op = c["lock_identity"](c["OP"])
    old = c["lock_identity"](c["LOCK"])
    latest = c["lock_identity"](prior / "state/controller.lock")
    need(op == base["operation_lock"] == registered["operation_lock"] and old == base["controller_lock"]
         and old != latest and not any(c["locks"](l) for l in (op,old,latest)), "previous owner retains a lock")
    worker = c["ref"](semantic / "V5F_RETRY1_ACTUAL_ADVANCING_WORKER.json")
    need(worker["sha256"] == worker_sha, "different same-image retry packet")
    actual = c["read_ref"](worker)
    live = manager("horizon-holding-export145-20261121-v1.service")
    need(live["InvocationID"] == actual["invocation_id"] and
         live["ActiveState"] == "active" and live["MainPID"] == str(actual["observations"][-1]["parent_pid"]),
         "retry no longer owns the manager")
    return dict(schema="horizon-145-fixture-retry-drained-predecessor-v1", previous=previous, earlier=earlier,
         earliest=earliest, prior_offer=c["ref"](prior/"OFFER.json"), prior_ready=ready,
         previous_active_follower=c["ref"](prior/"ACTIVE_FOLLOWER.json"),
         predecessor_receipt=c["ref"](prior/"PREDECESSOR_DRAINED.json"),
         exit_record={k:rows[0][k] for k in ("UNIT","INVOCATION_ID","_BOOT_ID","MESSAGE_ID","EXIT_STATUS","__CURSOR")},
         operation_lock=op, controller_lock=old, recent_controller_lock=latest,
         semantic=worker, live_semantic=live, started_units=0, changed_limits=False)


if __name__ == "__main__":
    need(sys.flags.isolated and os.geteuid() == 0 and __debug__, "isolated root inspection required")
    proof = observe()
    target.mkdir(mode=0o700,exist_ok=True)
    fd=c["dirfd"](target)
    try:
        need(os.fstat(fd).st_dev == Path("/home/sol").stat().st_dev, "wrong evidence filesystem")
        (target/"state").mkdir(mode=0o700,exist_ok=True)
        print(json.dumps(c["publish"](target/"PREDECESSOR_DRAINED.json",c["encoded"](proof))))
    finally:
        os.close(fd)
