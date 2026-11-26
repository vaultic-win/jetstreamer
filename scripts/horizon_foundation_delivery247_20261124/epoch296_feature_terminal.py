"""Record the exact epoch 296 feature-account replay result and drain its guard."""

import fcntl
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

sys.path.insert(0, "/var/lib/jetstreamer/horizon249-delivery-v214-tools")
from ordinary249.delivery248 import bound, funds, props, ref


STATE = Path("/var/lib/jetstreamer/horizon296-feature-account-v4")
CADENCE_LOCK = Path("/var/lib/jetstreamer/horizon-seven-publication-controller-v222/cycle.lock")
UNIT = "horizon-qualify-296-feature-account-v4.service"
GUARD = "horizon-296-feature-account-protective-v4.service"
TIMER = GUARD.removesuffix(".service") + ".timer"
WORKER_SHA = "f548675bc4d9a35f21c54c6acfeb67f9ea3c5d8cce76cf1b6abb9d6d92357523"
END_SLOT = 127_961_108
ACCOUNTS_HASH = "CqDfbHBybf1epq7CP5D8nJ5625guBkndaUJLmoMXJhkt"
SUCCESS = "7ad2d189f7e94e70a38c781354912448"
SERVICE_FIELDS = ["Id", "InvocationID", "ActiveState", "MainPID", "ControlPID", "Job",
                  "ControlGroup", "Result"]


def manager(unit):
    row = props(unit, SERVICE_FIELDS)
    assert row["Id"] == unit
    return row


def drained(row):
    return (row["ActiveState"] in ("inactive", "failed")
            and row["MainPID"] == row["ControlPID"] == "0"
            and not row["Job"] and not row["ControlGroup"]
            and not (Path("/sys/fs/cgroup/system.slice") / row["Id"]).exists())


def journal(*matches):
    fields = ",".join(("_PID", "_UID", "UNIT", "INVOCATION_ID", "MESSAGE_ID", "MESSAGE",
                       "_EXE", "_SYSTEMD_UNIT", "_SYSTEMD_INVOCATION_ID"))
    raw = subprocess.check_output(["journalctl", "-b", "--no-pager", "-o", "json",
                                   f"--output-fields={fields}", *matches], timeout=15)
    return [json.loads(line) for line in raw.splitlines()]


def read_result():
    registration = ref(STATE / "cadence-registration.json")
    launch = bound(registration)
    profile = bound(launch["profile"])
    token = bound(launch["launch_token"])
    invocation = launch["invocation_id"]
    assert re.fullmatch(r"[0-9a-f]{32}", invocation)
    assert (launch["epoch"], launch["unit"], launch["kind"]) == (
        296, UNIT, "epoch296-private-feature-account-qualification")
    assert launch["node_path"] == profile["node"]["path"]
    assert launch["worker"] == profile["worker"] and launch["worker"]["sha256"] == WORKER_SHA
    assert (profile["terminal_checkpoint"]["slot"], profile["terminal_checkpoint"]["accounts_hash"]) == (
        END_SLOT, ACCOUNTS_HASH)
    assert (token["unit"], token["invocation_id"], token["guard_plan"]) == (
        UNIT, invocation, launch["guard_plan"])
    crossing_ref = ref(STATE / "previous-failure-crossing.json")
    crossing = bound(crossing_ref)
    assert crossing["registration"] == registration
    assert crossing["previous_failure_slot"] == 127_955_673
    assert crossing["first_observed_emitted_slot_after_failure"] > crossing["previous_failure_slot"]
    producer = manager(UNIT)
    if producer["ActiveState"] == "active":
        assert producer["InvocationID"] == invocation and int(producer["MainPID"]) == launch["main_pid"]
        return {"epoch": 296, "state": "replay-active", "invocation_id": invocation}
    assert drained(producer) and producer["InvocationID"] in ("", invocation)
    assert producer["ActiveState"] == "inactive" and producer["Result"] == "success", producer
    [finish] = journal("_PID=1", "_UID=0", f"UNIT={UNIT}", f"INVOCATION_ID={invocation}",
                       f"MESSAGE_ID={SUCCESS}")
    events = journal(f"_PID={launch['main_pid']}", f"_SYSTEMD_UNIT={UNIT}",
                     f"_SYSTEMD_INVOCATION_ID={invocation}", f"_EXE={launch['node_path']}",
                     f"--grep=historical checkpoint slot={END_SLOT} |verified legacy accounts hash at slot {END_SLOT}|snapshot verification complete")
    checkpoints = [row for row in events if f"historical checkpoint slot={END_SLOT} " in row["MESSAGE"]]
    assert checkpoints and all(f" accounts_hash={ACCOUNTS_HASH} " in row["MESSAGE"]
                               and " complete=true " in row["MESSAGE"] for row in checkpoints)
    [verified] = [row for row in events if f"verified legacy accounts hash at slot {END_SLOT}" in row["MESSAGE"]]
    [finalized] = [row for row in events if "snapshot verification complete" in row["MESSAGE"]]
    assert int(crossing["emitted_event"]["__REALTIME_TIMESTAMP"]) < int(verified["__REALTIME_TIMESTAMP"])
    assert int(verified["__MONOTONIC_TIMESTAMP"]) <= int(finalized["__MONOTONIC_TIMESTAMP"])
    assert int(finalized["__MONOTONIC_TIMESTAMP"]) < int(finish["__MONOTONIC_TIMESTAMP"])
    assert all(int(row["__MONOTONIC_TIMESTAMP"]) < int(finish["__MONOTONIC_TIMESTAMP"]) for row in checkpoints)
    return {"schema": "foundation-epoch296-feature-account-terminal-v1", "epoch": 296,
            "state": "checkpoint-verified", "invocation_id": invocation, "launch": registration,
            "worker": launch["worker"], "prior_failure_crossing": crossing_ref,
            "checkpoint": profile["terminal_checkpoint"], "checkpoint_events": checkpoints,
            "verified": verified, "finalized": finalized, "manager_success": finish,
            "producer": producer, "guard_timer_invocation": token["guard_timer_invocation"],
            "canonical_epoch_publication_authorized": False}


def collect(apply):
    path = STATE / "terminal.json"
    if path.is_file():
        existing = bound(ref(path))
        assert existing["launch"] == ref(STATE / "cadence-registration.json") and existing["guard_drained"]
        return ref(path)
    result = read_result()
    if not apply or result["state"] == "replay-active":
        return result
    fields = ["ActiveState", "InvocationID", "Unit", "Job"]
    timer = props(TIMER, fields)
    assert not timer["Job"] and timer["Unit"] in ("", GUARD)
    assert timer["InvocationID"] in ("", result["guard_timer_invocation"])
    if timer["ActiveState"] == "active":
        assert timer["Unit"] == GUARD and timer["InvocationID"] == result["guard_timer_invocation"]
        subprocess.run(["systemctl", "stop", TIMER], check=True, timeout=15)
    timer_after = props(TIMER, fields)
    assert timer_after["ActiveState"] == "inactive" and not timer_after["Job"]
    assert timer_after["Unit"] in ("", GUARD) and timer_after["InvocationID"] in ("", result["guard_timer_invocation"])
    guard_after = manager(GUARD)
    if not drained(guard_after):
        return {"epoch": 296, "state": "guard-draining", "invocation_id": result["invocation_id"]}
    assert manager(UNIT) == result["producer"]
    result.update(guard_drained=True, timer_after=timer_after, guard_after=guard_after,
                  next_action="Price a full replay with the corrected worker against the accepted fleet.")
    with tempfile.TemporaryDirectory(dir=STATE) as stage:
        staged = Path(stage) / path.name
        funds.put(staged, result)
        assert not path.exists()
        os.rename(staged, path)
    fd = os.open(STATE, os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return ref(path)


if __name__ == "__main__":
    assert os.geteuid() == 0 and sys.argv[1:] in (["--check"], ["--collect"])
    with CADENCE_LOCK.open("r") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        print(json.dumps(collect(sys.argv[1] == "--collect"), indent=2))
