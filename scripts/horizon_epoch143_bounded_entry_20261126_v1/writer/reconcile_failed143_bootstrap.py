"""Archive the drained V51 epoch 143 attempt after its cadence successor is active."""

import errno
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from reconcile_failed143_gate import digest, locate, move, need, put, ref, show

BASE = Path("/var/lib/jetstreamer/horizon_runtime_data")
RT = BASE / "epoch143-first-hourly-20261127-v1"
RUN = Path("/home/sol/.jetstreamer-private") / RT.name
IID = "03ba8900c208428e81f98314e72f6685"
FAILED = RT / f"failed-{IID}"
OLD_RUN = RUN.with_name(f"{RUN.name}.failed-{IID}")
UNIT = "horizon-qualify-143-first-hourly-20261127-v1.service"
GUARD = "horizon-guard-143-first-hourly-20261127-v1"
LOCK = Path("/run/horizon-epoch171-to136-g1.operation.lock")
TERM_SHA = "48a3d3002e8bd990c69cfc5a551776929fcfa5462275c90a24e1a3f99b24eaa3"
FLEET = BASE / "root014808-live166167170-20261128-v1/ROOT_COMPLETE_OPERATIONAL_FLEET.json"
WRITER = BASE / "survivor172-cadence-20261122-v1"
ASSEMBLY = "horizon-assemble-168-private-20261127-v1.service"
NAMES = ("PRESTART_SCREEN.json", "POST_GUARD_SCREEN.json", "ACTUAL_GUARD_PLAN.json",
         "HELD_OWNER.json", "guard-receipts", "barrier")


def no_mounts():
    namespaces = set()
    for proc in Path("/proc").glob("[0-9]*"):
        try:
            if not (proc / "cmdline").read_bytes():
                continue
            cookie = (proc / "ns/mnt").stat().st_ino
            if cookie in namespaces:
                continue
            rows = (proc / "mountinfo").read_text().splitlines()
        except (FileNotFoundError, ProcessLookupError):
            continue
        except OSError as error:
            if error.errno != errno.EINVAL:
                raise
            try:
                task = (proc / "stat").read_text().rsplit(") ", 1)[1].split()
            except FileNotFoundError:
                continue
            need(task[0] in ("Z", "X") or int(task[6]) & 0x4, f"foreign live mount namespace {proc}")
            continue
        need(not any("/run/horizon143-first-hourly/" in row or f" {RUN}/" in row for row in rows),
             f"143 still has namespace mounts in {proc}")
        namespaces.add(cookie)


def checked(path, expected=None):
    p = Path(path)
    meta = p.lstat()
    need(p.resolve(strict=True) == p and p.is_file() and meta.st_uid == 0 and meta.st_nlink == 1
         and not meta.st_mode & 0o022 and (expected is None or digest(p) == expected), "foreign evidence " + str(p))
    return json.loads(p.read_bytes())


def check():
    proof = checked(FAILED / "NATIVE_TERMINAL.json", TERM_SHA)
    old_fleet = checked(FLEET)
    row = old_fleet["current_private143_first_hourly"]
    need(row["phase"] == "terminal" and row["held_owner"] == proof["held_owner"]
         and row["native_terminal"] == proof["pid1"] and proof["invocation_id"] == IID
         and not proof["worker_progress"] and not proof["archive_present"] and not proof["resource_credit_bytes"],
         "the accepted fleet did not record the exact released terminal actor")
    states = {unit: show(unit) for unit in (UNIT, GUARD+".timer", GUARD+".service", ASSEMBLY)}
    for unit, state in states.items():
        expected = ("failed", "inactive") if unit == UNIT else ("inactive",)
        need(state["Id"] == unit and state["ActiveState"] in expected and not state["Job"]
             and state.get("MainPID", "0") == state.get("ControlPID", "0") == "0"
             and not (Path("/sys/fs/cgroup/system.slice") / unit).exists(), "native owner still present: " + unit)
    need(states[UNIT]["InvocationID"] in ("", IID), "different 143 actor exited")
    no_mounts()
    locations = {name: locate(RT / name, FAILED / name) for name in NAMES}
    run = locate(RUN, OLD_RUN)
    need((locations["barrier"] / "allow").read_text() == IID
         and not (run / "epoch-143-first-hourly.jet").exists() and not (RT / "FIRST_PROTECTED_PROGRESS.json").exists(),
         "failed 143 did not retain its exact permit and unpublished workspace")
    for member in proof["booked_evidence"] + proof["guard_samples"]:
        parts = Path(member["path"]).relative_to(RT).parts
        actual = locations[parts[0]].joinpath(*parts[1:])
        need(digest(actual) == member["sha256"], "changed evidence " + member["path"])
    booking = checked(proof["booking"]["path"], proof["booking"]["sha256"])
    need(booking["latest_start_unix_seconds"] < time.time(), "released 143 booking is still current")
    return proof, locations, run, states


def writer_active():
    path = WRITER / "FAILED166_CADENCE_V52_ACTIVE.json"
    active = checked(path)
    owner = active["new"]
    program = WRITER / "tools-cold168-retry5-failed166-v52-entry146/status_cycle.py"
    state = show(owner["unit"])
    held = Path(f"/proc/{owner['pid']}/fd/{owner['lock']['fd']}").stat()
    need(owner["program"] == str(program) and state["ActiveState"] == "active" and not state["Job"]
         and state["MainPID"] == str(owner["pid"]) and state["InvocationID"] == owner["invocation_id"]
         and (held.st_dev, held.st_ino) == (owner["lock"]["device"], owner["lock"]["inode"])
         and not active["producer_mutations"], "V52 has no live consumer lock")
    return ref(path)


def main():
    os.umask(0o077)
    apply = sys.argv[1:] == ["--apply"]
    need(apply or sys.argv[1:] == ["--check"], "use --check or --apply")
    with LOCK.open("rb") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        receipt = FAILED / "RECONCILED.json"
        if receipt.is_file():
            print(json.dumps(ref(receipt)))
            return
        proof, _, _, _ = check()
        if not apply:
            print(json.dumps(dict(terminal=ref(FAILED / "NATIVE_TERMINAL.json"), accepted_fleet=ref(FLEET))))
            return
        writer = writer_active()
        for name in NAMES:
            move(RT / name, FAILED / name)
        move(RUN, OLD_RUN)
        if show(UNIT)["ActiveState"] == "failed":
            subprocess.run(["/usr/bin/systemctl", "reset-failed", UNIT], check=True, timeout=15)
        final = show(UNIT)
        need(final["LoadState"] == "not-found" and final["ActiveState"] == "inactive", "failed 143 unit still loaded")
        report = dict(schema="horizon-epoch143-bootstrap-failure-reconciled-v1", failed_invocation=IID,
                      released_gate_drained=True, terminal=ref(FAILED / "NATIVE_TERMINAL.json"),
                      accepted_fleet=ref(FLEET), original_held_owner=proof["held_owner"],
                      archived_held_owner=ref(FAILED / "HELD_OWNER.json"), writer=writer,
                      workspace=str(OLD_RUN), native=final, resource_credit_bytes=0,
                      archive_publication_authorized=False, recorded_unix_seconds=int(time.time()))
        print(json.dumps(put(receipt, report)))


if __name__ == "__main__":
    main()
