"""Transfer the current writer using the same lock, protected units and observer."""

import fcntl
import json
from pathlib import Path
import subprocess
import sys
import time

from cutover41 import BASE, BOOKING_LOCK, WRITER, clock, command, need, private_write, state

OLD = BASE / "tools-cold168-retry5-failed166-v45-entry146"
NEW = BASE / "tools-cold168-retry5-failed166-v46-entry146"
READY = BASE / "FAILED166_CADENCE_V46_READY.json"
ACTIVE = BASE / "FAILED166_CADENCE_V46_ACTIVE.json"
ASSEMBLY = "horizon-assemble-168-private-20261127-v1.service"
RETRY = "horizon-qualify-170-from-73746882-20261127-v1.service"
ACTOR_PROPS = ("Id", "MainPID", "InvocationID", "ActiveState", "ControlPID", "Job")


def listed(kind, states, pattern):
    lines = command("/usr/bin/systemctl", "list-units", "--plain", "--no-legend",
                    "--type=" + kind, "--state=" + states, pattern).decode().splitlines()
    return {line.split()[0] for line in lines if line}


def endpoints(fleet):
    roster = listed("service", "running,activating,deactivating", "horizon-qualify-*")
    expected = {row["unit"]["Id"]: row["unit"]
                for row in fleet["actual_executing_replays"] + fleet["actual_active_private_diagnostics"]}
    need(roster == set(expected), "a protected producer differs from the accepted roster")
    live = {unit: state(unit, *ACTOR_PROPS) for unit in roster | {ASSEMBLY, RETRY}}
    for unit in roster:
        actual, reported = live[unit], expected[unit]
        need(all(actual[key] == reported[key] for key in ("Id", "MainPID", "InvocationID", "ActiveState"))
             and actual["ActiveState"] == "active" and not actual["Job"],
             "protected producer changed: " + unit)
    for unit in (ASSEMBLY, RETRY):
        actual = live[unit]
        need(actual["ActiveState"] in ("inactive", "failed") and
             actual["MainPID"] == actual["ControlPID"] == "0" and not actual["Job"]
             and not (Path("/sys/fs/cgroup/system.slice") / unit).exists(),
             "unpriced owner is live: " + unit)
    guard_timers = listed("timer", "active", "horizon-guard-*")
    guards = {unit: state(unit, "Id", "InvocationID", "ActiveState") for unit in guard_timers}
    return dict(producers=live, guard_timers=guards)


def owner(actor, package):
    manager = state(WRITER, *ACTOR_PROPS, "ExecStart", "SubState")
    proc = Path(f"/proc/{actor['pid']}")
    held = (proc / "fd" / str(actor["lock"]["fd"])).stat()
    ticks = int((proc / "stat").read_text().rsplit(")", 1)[1].split()[19])
    need(manager["MainPID"] == str(actor["pid"])
         and manager["InvocationID"] == actor["invocation_id"]
         and (manager["ActiveState"], manager["SubState"]) == ("active", "running")
         and actor["program"] == str(package / "status_cycle.py") and actor["program"] in manager["ExecStart"]
         and ticks == actor["start_ticks"]
         and (held.st_dev, held.st_ino) == (actor["lock"]["device"], actor["lock"]["inode"]),
         "writer does not hold the sealed program and consumer lock")


def systemctl(action, *units):
    subprocess.run(["/usr/bin/systemctl", action, *units], check=True, timeout=20)


def restore_before_stop(dropin, old, timer, observed_clock):
    dropin.unlink(missing_ok=True)
    systemctl("daemon-reload")
    owner(old, OLD)
    need(clock(timer) == observed_clock, "observer changed while restoring V45 configuration")


def main(path):
    raw = Path(path).read_bytes()
    target = json.loads(raw)
    timer = target["timer"]
    with BOOKING_LOCK.open("rb") as admission_lock:
        fcntl.flock(admission_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        verified = json.loads(command("/usr/bin/python3", "-IB", NEW / "status_cycle.py",
                                      "--check-v46-handoff", target["fleet"]["path"], target["fleet"]["sha256"]))
        need(target == verified and not ACTIVE.exists(), "stale V46 handoff")
        old = json.loads(Path(target["old_owner"]["path"]).read_bytes())["new"]
        owner(old, OLD)
        fleet = json.loads(Path(target["fleet"]["path"]).read_bytes())
        live = endpoints(fleet)
        observed_clock = clock(timer)
        due = int(command("/usr/bin/date", "-u", "-d", observed_clock["NextElapseUSecRealtime"], "+%s"))
        need(due - time.time() > 120, "observer is too close to transfer the writer")
        directory = Path("/run/systemd/system") / f"{WRITER}.d"
        predecessor = max(directory.glob("*.conf"), key=lambda value: value.name)
        previous = predecessor.read_text()
        need("-v45-entry146.conf" in predecessor.name and previous.count(str(OLD)) == 1,
             "unexpected V45 service definition")
        dropin = directory / ("z" + predecessor.name.replace("-v45-", "-v46-"))
        if READY.exists():
            need(READY.read_bytes() == raw, "V46 has a different ready receipt")
        else:
            private_write(READY, raw, 0o400)
        private_write(dropin, previous.replace(str(OLD), str(NEW)).encode(), 0o644)
        try:
            systemctl("daemon-reload")
            need(str(NEW / "status_cycle.py") in state(WRITER, "ExecStart")["ExecStart"]
                 and clock(timer) == observed_clock and endpoints(fleet) == live,
                 "V46 configuration changed the live roster or observer")
        except Exception:
            restore_before_stop(dropin, old, timer, observed_clock)
            raise
        systemctl("stop", WRITER)
        need(state(WRITER, "MainPID")["MainPID"] == "0" and clock(timer) == observed_clock,
             "V45 did not release the consumer lock before V46 adoption")
        systemctl("start", WRITER)
        deadline = time.monotonic() + 15
        while not ACTIVE.exists() and time.monotonic() < deadline:
            if state(WRITER, "ActiveState")["ActiveState"] == "failed":
                break
            time.sleep(0.2)
        need(ACTIVE.exists(), "V46 rejoin failed; preserve the armed observer and diagnose the writer journal")
        selected = json.loads(ACTIVE.read_bytes())["new"]
        owner(selected, NEW)
        need(all(selected["lock"][key] == old["lock"][key] for key in ("path", "device", "inode"))
             and clock(timer) == observed_clock and endpoints(fleet) == live,
             "V46 did not adopt the same lock, roster and observer")
        print(json.dumps(dict(writer=selected, timer=observed_clock, protected=live), sort_keys=True))


if __name__ == "__main__":
    main(sys.argv[1])
