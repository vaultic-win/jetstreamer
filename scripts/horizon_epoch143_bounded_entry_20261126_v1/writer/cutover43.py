"""Adopt the first-hourly reader after the 170 successor's release."""
import fcntl
import hashlib
import json
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cutover41 import BASE, BOOKING_LOCK, WRITER, clock, command, need, private_write, state

OLD = BASE / "tools-cold168-retry5-failed166-v42-entry146-r3"
NEW = BASE / "tools-cold168-retry5-failed166-v43-entry146"
READY = BASE / "FAILED166_CADENCE_V43_READY.json"
ACTIVE = BASE / "FAILED166_CADENCE_V43_ACTIVE.json"
SUCCESSOR = "horizon-qualify-170-from-73726716-20261127-v1.service"
RELEASE = BASE.parent / "epoch170-from-73726716-20261127-v1/SUCCESSOR_RELEASE.json"
TERMINAL = RELEASE.with_name("FAILED_SUCCESSOR_NATIVE_START.json")
TERMINAL_SHA = "d81363677caab2e8789c01fd4ca6d9728d9f47f05ce57a08a9b29db7ab3d0f0a"
PROTECTED = (
    "horizon-qualify-141-first-hourly-20261127-v1.service",
    "horizon-qualify-143-first-hourly-20261127-v1.service",
    "horizon-qualify-146-full-local-20261126-v1.service",
    "horizon-qualify-167-checkpoint-tail-20261127-v1.service",
    "horizon-qualify-172-full-half-core-20261120-v1.service",
    SUCCESSOR,
)


def endpoints():
    return {unit: state(unit, "Id", "MainPID", "InvocationID", "ActiveState") for unit in PROTECTED}


def protected_successor(manager, release_raw):
    release = json.loads(release_raw)
    iid = release["producer_invocation_id"]
    if manager["ActiveState"] == "active":
        permit = RELEASE.with_name("barrier-bounded") / "allow"
        return manager["InvocationID"] == iid and permit.read_text() == iid
    raw = TERMINAL.read_bytes()
    terminal = json.loads(raw)
    return (hashlib.sha256(raw).hexdigest() == TERMINAL_SHA
            and terminal["exit"]["InvocationID"] == manager["InvocationID"] == iid
            and terminal["exit"]["ActiveState"] == manager["ActiveState"] == "failed"
            and terminal["exit"]["MainPID"] == manager["MainPID"] == "0"
            and terminal["release"]["sha256"] == hashlib.sha256(release_raw).hexdigest()
            and terminal["guard_drained"] is True and terminal["node_exited_before_worker"] is True)


def main(path):
    raw = Path(path).read_bytes()
    target = json.loads(raw)
    old = json.loads(Path(target["old_owner"]["path"]).read_bytes())["new"]
    timer = target["timer"]
    with BOOKING_LOCK.open("rb") as admission_lock:
        fcntl.flock(admission_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        checked = json.loads(command("/usr/bin/python3", "-IB", NEW / "status_cycle.py",
                                     "--check-v43-handoff", target["fleet"]["path"],
                                     target["fleet"]["sha256"]))
        need(target == checked and not (READY.exists() or ACTIVE.exists()), "stale V43 handoff")
        incumbent = state(WRITER, "MainPID", "InvocationID", "ActiveState", "ExecStart")
        need(incumbent["MainPID"] == str(old["pid"]) and incumbent["InvocationID"] == old["invocation_id"]
             and incumbent["ActiveState"] == "active" and str(OLD / "status_cycle.py") in incumbent["ExecStart"],
             "V42 is no longer the current writer")
        live = endpoints()
        need(protected_successor(live[SUCCESSOR], RELEASE.read_bytes())
             and live[PROTECTED[0]]["MainPID"] == live[PROTECTED[1]]["MainPID"] == "0",
             "V43 requires the exact 170 outcome and empty first-hourly slots")
        observed_clock = clock(timer)
        due = int(command("/usr/bin/date", "-u", "-d", observed_clock["NextElapseUSecRealtime"], "+%s"))
        need(due - time.time() > 90, "the incumbent observer is too close to writer transfer")
        directory = Path("/run/systemd/system") / f"{WRITER}.d"
        predecessor = max(directory.glob("*.conf"), key=lambda value: value.name)
        previous = predecessor.read_text()
        need("-v42-r3-entry146.conf" in predecessor.name and previous.count(str(OLD)) == 1,
             "unexpected V42 service definition")
        private_write(READY, raw, 0o400)
        successor = directory / ("z" + predecessor.name.replace("-v42-r3-", "-v43-"))
        private_write(successor, previous.replace(str(OLD), str(NEW)).encode(), 0o644)
        command("/usr/bin/systemctl", "daemon-reload")
        need(str(NEW / "status_cycle.py") in state(WRITER, "ExecStart")["ExecStart"]
             and clock(timer) == observed_clock, "V43 changed the incumbent observer")
        command("/usr/bin/systemctl", "stop", WRITER)
        need(state(WRITER, "MainPID")["MainPID"] == "0" and clock(timer) == observed_clock,
             "V42 did not release the writer service")
        command("/usr/bin/systemctl", "start", WRITER)
        cutoff = time.monotonic() + 12
        while not ACTIVE.is_file() and time.monotonic() < cutoff:
            time.sleep(0.1)
        selected = json.loads(ACTIVE.read_bytes())["new"]
        manager = state(WRITER, "MainPID", "InvocationID", "ActiveState", "SubState")
        held = Path(f"/proc/{selected['pid']}/fd/{selected['lock']['fd']}").stat()
        need(manager["MainPID"] == str(selected["pid"]) and manager["InvocationID"] == selected["invocation_id"]
             and (manager["ActiveState"], manager["SubState"]) == ("active", "running")
             and (held.st_dev, held.st_ino) == (old["lock"]["device"], old["lock"]["inode"])
             and endpoints() == live and clock(timer) == observed_clock,
             "V43 did not adopt the same lock, producer identities and observer")
        print(json.dumps({"writer": selected, "timer": observed_clock, "protected": live}, sort_keys=True))


if __name__ == "__main__":
    main(sys.argv[1])
