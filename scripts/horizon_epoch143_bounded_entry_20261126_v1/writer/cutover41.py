"""Join the existing writer service to V41 while retaining its one observer."""
import fcntl
import json
import os
import subprocess
import sys
import time
from pathlib import Path

BASE = Path("/var/lib/jetstreamer/horizon_runtime_data/survivor172-cadence-20261122-v1")
OLD = BASE / "tools-cold168-retry5-failed166-v40-entry146"
NEW = BASE / "tools-cold168-retry5-failed166-v41-entry146"
WRITER = "horizon-archive-status-cadence-after172-20261120-v1.service"
BOOKING_LOCK = Path("/run/horizon-epoch171-to136-g1.operation.lock")
READY = BASE / "FAILED166_CADENCE_V41_READY.json"
ACTIVE = BASE / "FAILED166_CADENCE_V41_ACTIVE.json"
PROTECTED = (
    "horizon-qualify-146-full-local-20261126-v1.service",
    "horizon-qualify-167-checkpoint-tail-20261127-v1.service",
    "horizon-qualify-170-checkpoint-suffix-20261127-v1.service",
    "horizon-qualify-172-full-half-core-20261120-v1.service",
    "horizon-170-bridge-exit-capture-20261127-v1.service",
)


def command(*args):
    return subprocess.check_output(list(map(str, args)), timeout=40)


def state(unit, *fields):
    output = command("/usr/bin/systemctl", "show", unit, "-p", ",".join(fields))
    return dict(line.split("=", 1) for line in output.decode().splitlines())


def need(condition, message):
    if not condition:
        raise ValueError(message)


def private_write(path, content, mode):
    pending = path.with_name(f".{path.name}.{os.getpid()}")
    try:
        with pending.open("xb") as handle:
            os.fchmod(handle.fileno(), mode)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(pending, path)
    finally:
        pending.unlink(missing_ok=True)
    fd = os.open(path.parent, os.O_NOFOLLOW | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def clock(timer):
    listing = command("/usr/bin/systemctl", "list-units", "--type=timer", "--state=waiting",
                      "--no-legend", "--plain", "horizon-observer-*.timer")
    need([line.split()[0] for line in listing.decode().splitlines() if line] == [timer],
         "the prior observer is no longer the sole waiting timer")
    native = state(timer, "Id", "InvocationID", "ActiveState", "SubState", "NextElapseUSecRealtime")
    need(native["ActiveState"] == "active" and native["SubState"] == "waiting"
         and bool(native["InvocationID"]), "the prior timer identity changed")
    return native


def endpoints():
    return {unit: state(unit, "Id", "MainPID", "InvocationID", "ActiveState") for unit in PROTECTED}


def main(path):
    raw = Path(path).read_bytes()
    target = json.loads(raw)
    old = json.loads(Path(target["old_owner"]["path"]).read_bytes())["new"]
    timer = target["timer"]
    with BOOKING_LOCK.open("rb") as admission_lock:
        fcntl.flock(admission_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        verified = json.loads(command("/usr/bin/python3", "-IB", NEW / "status_cycle.py",
                                     "--check-v41-handoff", target["fleet"]["path"],
                                     target["fleet"]["sha256"]))
        need(target == verified and not (READY.exists() or ACTIVE.exists()), "stale V41 handoff")
        incumbent = state(WRITER, "MainPID", "InvocationID", "ActiveState", "ExecStart")
        need(incumbent["MainPID"] == str(old["pid"]) and incumbent["InvocationID"] == old["invocation_id"]
             and incumbent["ActiveState"] == "active" and str(OLD / "status_cycle.py") in incumbent["ExecStart"],
             "the original writer is no longer current")
        observed_clock = clock(timer)
        due = int(command("/usr/bin/date", "-u", "-d", observed_clock["NextElapseUSecRealtime"], "+%s"))
        need(due - time.time() > 90, "the original clock is too close to transfer ownership")
        live = endpoints()
        directory = Path("/run/systemd/system") / f"{WRITER}.d"
        predecessor = max(directory.glob("*.conf"), key=lambda value: value.name)
        previous = predecessor.read_text()
        need("-v40-entry146.conf" in predecessor.name and previous.count(str(OLD)) == 1,
             "unexpected predecessor service definition")
        private_write(READY, raw, 0o400)
        successor = directory / ("z" + predecessor.name.replace("-v40-", "-v41-"))
        private_write(successor, previous.replace(str(OLD), str(NEW)).encode(), 0o644)
        command("/usr/bin/systemctl", "daemon-reload")
        need(str(NEW / "status_cycle.py") in state(WRITER, "ExecStart")["ExecStart"]
             and clock(timer) == observed_clock, "V41 changed the original observer")
        command("/usr/bin/systemctl", "stop", WRITER)
        need(state(WRITER, "MainPID")["MainPID"] == "0" and clock(timer) == observed_clock,
             "V40 did not release the writer service")
        command("/usr/bin/systemctl", "start", WRITER)
        cutoff = time.monotonic() + 12
        while not ACTIVE.is_file() and time.monotonic() < cutoff:
            time.sleep(0.1)
        selected = json.loads(ACTIVE.read_bytes())["new"]
        manager = state(WRITER, "MainPID", "InvocationID", "ActiveState", "SubState")
        lock = Path(f"/proc/{selected['pid']}/fd/{selected['lock']['fd']}").stat()
        need(manager["MainPID"] == str(selected["pid"]) and manager["InvocationID"] == selected["invocation_id"]
             and (manager["ActiveState"], manager["SubState"]) == ("active", "running")
             and (lock.st_dev, lock.st_ino) == (old["lock"]["device"], old["lock"]["inode"])
             and endpoints() == live and clock(timer) == observed_clock,
             "V41 did not acquire the incumbent lock and preserve producer and observer identities")
        print(json.dumps({"writer": selected, "timer": observed_clock, "protected": live}, sort_keys=True))


if __name__ == "__main__":
    main(sys.argv[1])
