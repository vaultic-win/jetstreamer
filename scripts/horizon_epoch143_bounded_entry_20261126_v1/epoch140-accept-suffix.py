#!/usr/bin/env python3
"""Accept the guarded epoch 140 suffix after its native recorder exits cleanly."""
import hashlib
import json
import os
import re
import select
import stat
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

AUTHORITY = Path("/var/lib/jetstreamer/horizon_runtime_data/epoch140-suffix-recording-20261127-retry1")
RUN = Path("/home/sol/.jetstreamer-private/epoch140-suffix-recording-20261127-retry1")
UNIT = "horizon-epoch140-suffix-recording.service"
GUARD = "horizon-guard-epoch140-suffix-recording-20261127-retry1"
WORKER = "c536dcf360b7866b3aa99e0ff6d7d927dcf5db27bfbbb8f73887eb4bb7d87344"
BOOTSTRAP = "47d5911465901975e397c570e06ccf72296db7ecd3b3b1beda710cacd3e683a1"


def file_ref(path, uid):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as source:
        before = os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_uid != uid or before.st_nlink != 1:
            raise ValueError(f"wrong file identity: {path}")
        digest = hashlib.file_digest(source, "sha256").hexdigest()
        after = os.fstat(source.fileno())
    current = path.stat(follow_symlinks=False)
    keys = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    identity = lambda info: tuple(getattr(info, key) for key in keys)
    if identity(before) != identity(after) or identity(after) != identity(current):
        raise ValueError(f"file changed during acceptance: {path}")
    return {"path": str(path), "sha256": digest}, before.st_size


def read(path, uid):
    reference, size = file_ref(path, uid)
    if size > 1024 * 1024:
        raise ValueError(f"oversize receipt: {path}")
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != reference["sha256"]:
        raise ValueError(f"receipt changed: {path}")
    return json.loads(data), reference


def native_properties(unit, fields):
    result = subprocess.run(
        ["systemctl", "show", unit, "--property=" + fields],
        capture_output=True, text=True, check=False,
    )
    return dict(line.split("=", 1) for line in result.stdout.splitlines())


def inactive(unit):
    values = native_properties(unit, "Id,ActiveState,MainPID,ControlPID,Job")
    if values["Id"] != unit or values["ActiveState"] != "inactive" or values["Job"]:
        raise ValueError(f"scope has not drained: {unit}")
    if unit.endswith(".service") and (values["MainPID"], values["ControlPID"]) != ("0", "0"):
        raise ValueError(f"scope retains a PID: {unit}")


def accept():
    if os.geteuid() != 0:
        raise ValueError("run acceptance as root")
    for unit in (UNIT, GUARD + ".service", GUARD + ".timer"):
        inactive(unit)
    owner, owner_ref = read(AUTHORITY / "HELD_OWNER.json", 0)
    terminal, terminal_ref = read(AUTHORITY / "NATIVE_TERMINAL.json", 0)
    progress, progress_ref = read(AUTHORITY / "FIRST_PROTECTED_PROGRESS.json", 0)
    returned, returned_ref = read(AUTHORITY / "CPU_LOAN_RETURN.json", 0)
    iid = owner["invocation_id"]
    if not re.fullmatch(r"[0-9a-f]{32}", iid):
        raise ValueError("invalid recording invocation")
    if (
        terminal["invocation_id"] != iid or terminal["boot_id"] != owner["boot_id"]
        or terminal["pid"] != owner["pid"] or terminal["exec_main_code"] != 1
        or terminal["exec_main_status"] != 0 or terminal["result"] != "success"
        or returned["candidate_invocation"] != iid or not returned["producer_and_guard_drained"]
        or progress["producer_invocation_id"] != iid or progress["producer_pid"] != owner["pid"]
        or progress["slot"] <= 60911752 or progress["transactions"] <= 0
    ):
        raise ValueError("native terminal, progress, or CPU return does not match the held recorder")
    guard_root = AUTHORITY / "guard-receipts"
    if (guard_root / "stop-intent.json").exists() or (guard_root / "stop-completion.json").exists():
        raise ValueError("the guard stopped this invocation")
    archive = RUN / "recording/epoch-140-suffix.jet"
    recorder, recorder_ref = read(archive.with_name("suffix-recording.json"), 1001)
    manifest, manifest_ref = read(archive.with_name(archive.name + ".segment.json"), 1001)
    archive_ref, archive_size = file_ref(archive, 1001)
    if (
        archive_size <= 0 or archive.with_name(archive.name + ".sha256").exists()
        or recorder["schema"] != "jetstreamer-private-epoch140-suffix-recording-v1"
        or recorder["invocation_id"] != iid or recorder["archive"] != str(archive)
        or recorder["archive_sha256"] != archive_ref["sha256"] or manifest["archive_sha256"] != archive_ref["sha256"]
        or recorder["plan"]["sha256"] != owner["node_plan"]["sha256"]
        or manifest["schema_version"] != 1 or manifest["epoch"] != 140
        or recorder["recorded_slot_start"] != 60911752 or manifest["output_slot_start"] != 60911752
        or recorder["recorded_slots"] != 248 or manifest["output_slot_count"] != 248
        or recorder["pre_entry_native_checkpoint"] != manifest["bootstrap"] or manifest["bootstrap"]["slot"] != 60911751
        or recorder["terminal"] != manifest["terminal"] or manifest["terminal"]["slot"] != 60911999
        or recorder["original_cut_cursor"] != 28029693043
        or recorder["emitted_raw_write_versions"] != manifest["emitted_raw_write_versions"]
        or manifest["emitted_raw_write_versions"]["start"] != 28087370409
        or manifest["emitted_raw_write_versions"]["end"] <= 28087370409
        or recorder["original_entry_gap_targets_matched"] != 10
        or recorder["worker_sha256"] != WORKER or manifest["worker_executable_sha256"] != WORKER
        or recorder["snapshot_sha256"] != BOOTSTRAP or recorder["pending_canonical_root_slot"] != 61328765
        or recorder["pending_canonical_accounts_hash"] != "8LfMXtdKmPEvMcBzEz2XZ56HZ8pUPGSaWGA6mYG4dAFY"
        or any(recorder[key] is not False for key in (
            "canonical_root_verified", "assembly_authorized", "publication_authorized", "r2_mutations"
        ))
    ):
        raise ValueError("recorded suffix or segment manifest failed its binding checks")
    output = AUTHORITY / "PRIVATE_SUFFIX_ACCEPTANCE.json"
    receipt = {
        "schema": "horizon-epoch140-private-suffix-acceptance-v1", "epoch": 140,
        "recorded_at": datetime.now(timezone.utc).isoformat(), "invocation_id": iid,
        "actor": owner_ref, "first_protected_progress": progress_ref, "native_terminal": terminal_ref,
        "cpu_loan_return": returned_ref, "recorder_receipt": recorder_ref, "segment_manifest": manifest_ref,
        "archive": archive_ref, "archive_bytes": archive_size, "recorded_slots": 248,
        "start_slot": 60911752, "end_slot": 60911999, "pending_canonical_root_slot": 61328765,
        "canonical_root_verified": False, "publication_authorized": False,
    }
    persist(output, receipt)



def persist(output, receipt):
    fd, temp_name = tempfile.mkstemp(dir=AUTHORITY, prefix=".suffix-acceptance-")
    temp = Path(temp_name)
    try:
        with os.fdopen(fd, "w") as destination:
            json.dump(receipt, destination, indent=2)
            destination.write("\n")
            os.fchmod(destination.fileno(), 0o444)
            destination.flush()
            os.fsync(destination.fileno())
        os.link(temp, output)
    finally:
        temp.unlink()
    directory = os.open(AUTHORITY, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    print(json.dumps(file_ref(output, 0)[0]))


def capture_native():
    import dbus

    owner, owner_ref = read(AUTHORITY / "HELD_OWNER.json", 0)
    loan, loan_ref = read(AUTHORITY / "CPU_LOAN_ACTIVE.json", 0)
    iid = owner["invocation_id"]
    pid = owner["pid"]
    if owner["unit"] != UNIT or loan["candidate_invocation"] != iid or loan["candidate_pid"] != pid:
        raise ValueError("CPU loan differs from the held recorder")
    with open("/proc/sys/kernel/random/boot_id") as identity:
        if identity.read().strip() != owner["boot_id"]:
            raise ValueError("recorder boot identity changed")
    bus = dbus.SystemBus(private=True)
    proxy = bus.get_object("org.freedesktop.systemd1", "/org/freedesktop/systemd1")
    manager = dbus.Interface(proxy, "org.freedesktop.systemd1.Manager")
    # Keep the completed transient unit available while reading PID1's exact exit status.
    manager.RefUnit(UNIT)
    try:
        fields = (
            "InvocationID,ActiveState,MainPID,ExecMainPID,ExecMainCode,ExecMainStatus,"
            "ExecMainExitTimestampMonotonic,Result"
        )
        start = native_properties(UNIT, fields)
        if start["InvocationID"] != iid or int(start["MainPID"]) != pid:
            raise ValueError("native recorder changed before capture")
        with os.fdopen(os.pidfd_open(pid), "rb") as handle:
            ticks = int(Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()[19])
            if ticks != owner["start_ticks"]:
                raise ValueError("recorder PID was reused")
            deadline = loan["must_drain_by_unix_seconds"]
            while time.time() < deadline:
                if select.select([handle], [], [], min(50, max(0, deadline - time.time())))[0]:
                    break
            else:
                raise ValueError("recorder missed its drain deadline")
            for _ in range(30):
                end = native_properties(UNIT, fields)
                if end["ActiveState"] in ("inactive", "failed") and end["MainPID"] == "0":
                    break
                time.sleep(0.1)
            else:
                raise ValueError("PID1 did not report recorder drain")
        if end["InvocationID"] != iid or int(end["ExecMainPID"]) != pid:
            raise ValueError("PID1 terminal identity differs from the held recorder")
        if int(end["ExecMainExitTimestampMonotonic"]) <= 0:
            raise ValueError("PID1 has no immutable exit timestamp")
        persist(AUTHORITY / "NATIVE_TERMINAL.json", {
            "schema": "horizon-epoch140-native-terminal-v1", "invocation_id": iid, "pid": pid,
            "boot_id": owner["boot_id"], "exec_main_code": int(end["ExecMainCode"]),
            "exec_main_status": int(end["ExecMainStatus"]), "result": end["Result"],
            "terminal_state": end["ActiveState"],
            "exit_timestamp_monotonic_usec": int(end["ExecMainExitTimestampMonotonic"]),
            "actor": owner_ref, "cpu_loan": loan_ref,
        })
    finally:
        manager.UnrefUnit(UNIT)
        bus.close()


if __name__ == "__main__":
    if sys.argv[1:] == ["--capture-native"]:
        capture_native()
    elif not sys.argv[1:]:
        accept()
    else:
        raise SystemExit("usage: epoch140-accept-suffix.py [--capture-native]")
