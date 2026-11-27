"""Enter the full 143 booking after the exact 168 assembly drains."""

import fcntl
import json
from pathlib import Path
import stat
import subprocess
import sys
import time

ROOT = Path("/var/lib/jetstreamer/horizon_runtime_data")
TARGET = ROOT / "epoch143-first-hourly-20261127-v1"
WRITER = ROOT / "survivor172-cadence-20261122-v1"
WRITER_PACKAGE = WRITER / "tools-cold168-retry5-failed166-v46-entry146-r2"
ACTIVE = WRITER / "FAILED166_CADENCE_V46_ACTIVE.json"
BOOKER = TARGET / "booking-price-v4"
ASSEMBLY = "horizon-assemble-168-private-20261127-v1.service"
PHASE = TARGET / "PHASE_170_FIRST_168_LIVE.json"
REOPEN = TARGET / "PHASE_170_FIRST_168_RELEASED.json"
OBSERVER = "horizon-archive-status-cadence-after172-20261120-v1.service"
SUCCESS = "7ad2d189f7e94e70a38c781354912448"
FAILURE = "98e322203f7a4ed290d09fe03c09fe15"

sys.path.insert(0, str(WRITER_PACKAGE))
import status_cycle
from cutover41 import BOOKING_LOCK, state
from evidence import bound, checked, durable, need
from first_hourly143 import EPOCH143, process_ids


def terminal_event(event, phase):
    return (event.get("_PID") == "1" and event.get("_UID") == "0"
            and event.get("UNIT") == ASSEMBLY
            and event.get("INVOCATION_ID") == phase["assembly168"]["invocation_id"]
            and event.get("_BOOT_ID") == phase["boot_id"].replace("-", "")
            and (event.get("MESSAGE_ID") == SUCCESS or
                 (event.get("MESSAGE_ID") == FAILURE and event.get("COMMAND") == "ExecStart")))


def close_phase(phase_ref, phase):
    """Commit the drained phase with no credit from retained assembly output."""
    assembly = phase["assembly168"]
    with BOOKING_LOCK.open("rb") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        managed = state(ASSEMBLY, "ActiveState", "MainPID", "ControlPID", "ControlGroup", "Job")
        if (managed["ActiveState"] != "inactive" or managed["MainPID"] != "0"
                or managed["ControlPID"] != "0" or managed["ControlGroup"] or managed["Job"]):
            return False
        plan = checked(assembly["plan"])
        manager_record = bound(Path(assembly["plan"]["path"]).with_name("LAUNCH_NATIVE.json"))
        original = checked(manager_record)
        need(original["Id"] == ASSEMBLY and original["InvocationID"] == assembly["invocation_id"]
             and plan["unit"] == ASSEMBLY and plan["minimum_home_free_bytes"] == assembly["floor"]
             and plan["publication_authorized"] is False, "lost the exact 168 producer and floor")
        native = subprocess.check_output(
            ["/usr/bin/journalctl", "-q", "--no-pager", "-o", "json", "_PID=1", "_UID=0",
             "UNIT=" + ASSEMBLY, "INVOCATION_ID=" + assembly["invocation_id"]], text=True, timeout=15)
        events = [json.loads(line) for line in native.splitlines()]
        terminals = [event for event in events if terminal_event(event, phase)]
        if not terminals:
            return False
        output = Path(plan["output_directory"])
        meta = output.lstat()
        need(output.resolve(strict=True) == output and meta.st_uid == 0 and stat.S_ISDIR(meta.st_mode)
             and stat.S_IMODE(meta.st_mode) == 0o700 and meta.st_dev == Path("/home/sol").stat().st_dev
             and state(ASSEMBLY, *managed) == managed, "168 output custody or native absence changed")
        report = dict(schema="horizon-170-first-168-live-release-v1", phase=phase_ref, plan=assembly["plan"],
                      native_start=manager_record, native_terminal=terminals[-1], epoch168_output=dict(
                          path=str(output), device=meta.st_dev, inode=meta.st_ino),
                      resource_credit_bytes=0, archive_publication_authorized=False)
        durable(REOPEN, report)
        return True


def observer_event(event, owner):
    if event.get("_SYSTEMD_INVOCATION_ID") != owner["invocation_id"]:
        return False
    message = event.get("MESSAGE", "")
    if not message.startswith('{"fleet":'):
        return False
    receipt = json.loads(message)["fleet"]
    path = Path(receipt["path"])
    return (path.parent.parent == ROOT and path.name == "ROOT_COMPLETE_OPERATIONAL_FLEET.json"
            and bound(path) == receipt)


def start(active_ref, package_ref):
    actor_path = TARGET / "HELD_OWNER.json"
    if actor_path.exists():
        owner = checked(bound(actor_path))
        permit = TARGET / "barrier/allow"
        need(owner["contract"] == EPOCH143.contract and permit.is_file()
             and permit.read_text() == owner["producer_invocation_id"], "unreleased 143 owner requires reconciliation")
        return True
    need(not process_ids(EPOCH143), "143 producer exists without an owner receipt")
    quote = subprocess.run(
        ["/usr/bin/python3", "-IB", str(BOOKER / "prepare143.py"), "--runtime-max-seconds", "28800",
         "--v46", active_ref["sha256"], package_ref["sha256"]], capture_output=True, text=True, timeout=80)
    if quote.returncode:
        print(quote.stderr.strip(), flush=True)
        return False
    booking = json.loads(quote.stdout)
    document = checked(booking)
    need(document["writer_active"] == active_ref and document["runtime_max_seconds"] == 28800
         and document["HOME_bytes"] == (64 << 30) + (64 << 20) and document["RAM_bytes"] == 41 << 30,
         "different 143 booking")
    launch = subprocess.run([str(BOOKER / "launch-first-hourly143.sh"), booking["path"], booking["sha256"]])
    need(launch.returncode == 0, "guarded 143 entry refused after booking")
    actor = bound(TARGET / "HELD_OWNER.json")
    owner = checked(actor)
    need(owner["booking"] == booking and (TARGET / "barrier/allow").read_text() == owner["producer_invocation_id"],
         "143 re-entry produced no exact permit")
    print(json.dumps(dict(booking=booking, held_owner=actor, invocation_id=owner["producer_invocation_id"])), flush=True)
    return True


def main():
    active_ref = bound(ACTIVE)
    package = status_cycle.entry()
    owner = checked(active_ref)["new"]
    phase_ref = bound(PHASE)
    phase = checked(phase_ref)
    need(phase["writer"] == active_ref and phase["hourly143"]["contract"] == EPOCH143.contract
         and phase["schema"] == "horizon-170-first-168-live-v1", "different 143 phase authorization")
    if sys.argv[1:] == ["--check-entry"]:
        print(json.dumps(dict(phase=phase_ref, writer=active_ref, package=package)))
        return
    need(not sys.argv[1:], "unexpected 143 re-entry arguments")
    since = f"@{int(time.time())}"
    args = ["/usr/bin/journalctl", "-q", "--no-pager", "-o", "json", "--follow", "--no-tail",
            "--since", since, "-u", ASSEMBLY, "-u", OBSERVER]
    with subprocess.Popen(args, text=True, stdout=subprocess.PIPE) as journal:
        try:
            if close_phase(phase_ref, phase) and start(active_ref, package):
                return
            for line in journal.stdout:
                event = json.loads(line)
                if terminal_event(event, phase) or observer_event(event, owner):
                    if close_phase(phase_ref, phase) and start(active_ref, package):
                        return
            raise ValueError("143 native event stream ended")
        finally:
            journal.terminate()


if __name__ == "__main__":
    main()
