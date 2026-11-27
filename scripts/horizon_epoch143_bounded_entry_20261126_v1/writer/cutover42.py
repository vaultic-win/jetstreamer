"""Transfer the sole writer after the 140 recording loan has returned."""

import fcntl
import json
from pathlib import Path
import sys
import time

from cutover41 import BASE, BOOKING_LOCK, OLD as V40, WRITER, clock, command, need, private_write, state

OLD = V40.with_name(V40.name.replace("v40", "v41"))
NEW = OLD.with_name(OLD.name.replace("v41", "v42"))
READY = BASE / "FAILED166_CADENCE_V42_READY.json"
ACTIVE = BASE / "FAILED166_CADENCE_V42_ACTIVE.json"
LOAN = Path("/run/horizon-epoch140-epoch170-cpu-loan.active")
RECORDER = "horizon-epoch140-suffix-recording.service"
PROTECTED = (
    "horizon-qualify-143-first-hourly-20261127-v1.service",
    "horizon-qualify-146-full-local-20261126-v1.service",
    "horizon-qualify-167-checkpoint-tail-20261127-v1.service",
    "horizon-qualify-172-full-half-core-20261120-v1.service",
)


def endpoints():
    return {unit: state(unit, "Id", "MainPID", "InvocationID", "ActiveState") for unit in PROTECTED}


def main(path):
    raw = Path(path).read_bytes()
    target = json.loads(raw)
    old = json.loads(Path(target["old_owner"]["path"]).read_bytes())["new"]
    timer = target["timer"]
    with BOOKING_LOCK.open("rb") as admission_lock:
        fcntl.flock(admission_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        checked = json.loads(command("/usr/bin/python3", "-IB", NEW / "status_cycle.py",
                                     "--check-v42-handoff", target["fleet"]["path"],
                                     target["fleet"]["sha256"]))
        need(target == checked and not (READY.exists() or ACTIVE.exists()), "stale V42 handoff")
        recorder = state(RECORDER, "MainPID", "ActiveState", "Job")
        need(recorder["MainPID"] == "0" and recorder["ActiveState"] in ("inactive", "failed")
             and not recorder["Job"] and not LOAN.exists(), "epoch 140 still owns the recording loan")
        incumbent = state(WRITER, "MainPID", "InvocationID", "ActiveState", "ExecStart")
        need(incumbent["MainPID"] == str(old["pid"]) and incumbent["InvocationID"] == old["invocation_id"]
             and incumbent["ActiveState"] == "active" and str(OLD / "status_cycle.py") in incumbent["ExecStart"],
             "V41 is no longer the current writer")
        observed_clock = clock(timer)
        due = int(command("/usr/bin/date", "-u", "-d", observed_clock["NextElapseUSecRealtime"], "+%s"))
        need(due - time.time() > 90, "the incumbent observer is too close to writer transfer")
        live = endpoints()
        directory = Path("/run/systemd/system") / f"{WRITER}.d"
        predecessor = max(directory.glob("*.conf"), key=lambda value: value.name)
        previous = predecessor.read_text()
        need("-v41-entry146.conf" in predecessor.name and previous.count(str(OLD)) == 1,
             "unexpected V41 service definition")
        private_write(READY, raw, 0o400)
        successor = directory / ("z" + predecessor.name.replace("-v41-", "-v42-"))
        private_write(successor, previous.replace(str(OLD), str(NEW)).encode(), 0o644)
        command("/usr/bin/systemctl", "daemon-reload")
        need(str(NEW / "status_cycle.py") in state(WRITER, "ExecStart")["ExecStart"]
             and clock(timer) == observed_clock, "V42 changed the incumbent observer")
        command("/usr/bin/systemctl", "stop", WRITER)
        need(state(WRITER, "MainPID")["MainPID"] == "0" and clock(timer) == observed_clock,
             "V41 did not release the writer service")
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
             "V42 did not adopt the same lock, producer identities and observer")
        print(json.dumps({"writer": selected, "timer": observed_clock, "protected": live}, sort_keys=True))


if __name__ == "__main__":
    main(sys.argv[1])
