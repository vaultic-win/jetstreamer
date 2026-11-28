"""Retain the original epoch 172 reservation through archive finalization and native close."""

import hashlib
import os
from pathlib import Path
import runpy
import stat
import time


UNIT = "horizon-qualify-172-full-half-core-20261120-v1.service"
IID = "0e17b745938546608b0bdc52815151d0"
TIMER = "horizon-guard-172-full-half-core-20261120-v1.timer"
TIMER_IID = "6259c4f5ba654513a1903fc693e4f6a9"
CLOSURE = {
    "closure.py": "1eda4eb778e73a8ab670df50980cad9208215f8d4854432d94f83f4054e92541",
    "closure172.py": "127df81410de8796a04c31f2b839d2d4b7742e4c06ac9f9fd6cdcfcbf9db6e79",
}
FINAL_SHA = "973e3314cf7666298920d750322675c6c0c0d42dbbf665a089681041ba97f845"


def need(ok, message):
    if not ok:
        raise ValueError("original 172: " + message)


def identity(path, expected, *, directory=False):
    path = Path(path)
    info = path.lstat()
    right_kind = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    need(path.resolve(strict=True) == path and right_kind and
         (info.st_dev, info.st_ino) == (expected["device"], expected["inode"]), "different inode " + str(path))
    return info


def actor_key(actor):
    return [actor["pid"], actor["start_ticks"], actor["identity"]["device"], actor["identity"]["inode"]]


def validate_files(core, fleet, roster, anchor):
    delivery = core["RT"] / "epoch172-current-delivery-20261121-v1"
    final, ref = core["read"](delivery / "ORIGINAL_ARCHIVE_FINALIZATION.json", FINAL_SHA)
    live = core["bound"](final["live"])
    admitted = core["bound"](final["admission"])
    first = core["bound"](final["first_worker"])
    end = core["bound"](final["input_end"])
    boundary = core["bound"](final["expected_boundary"])
    plan = core["bound"](admitted["actual_guard_plan"])
    original_sample = core["bound"](anchor)
    native = live["native"]
    parent, worker, archive = native["parent"], native["worker"], native["open_work_archive"]
    retained = fleet.get("full172_local_commit")
    if not retained or "current_full172_admission" in fleet or "current_full172_post_guard_fit" in fleet:
        need(live["admission"] == fleet["current_full172_admission"]
             and admitted["post_guard_capacity"] == fleet["current_full172_post_guard_fit"], "different fleet booking")
    need(live["boot_id"] == Path("/proc/sys/kernel/random/boot_id").read_text().strip()
         and live["admission"] == final["admission"] == end["admission"]
         and live["first_protected_worker"] == final["first_worker"] == end["original_worker"]
         and final["live"] == end["live"]
         and [actor_key(parent), actor_key(worker)] == roster
         and first["worker_pid"] == worker["pid"] and first["worker_start_ticks"] == worker["start_ticks"]
         and parent["pid"] == admitted["producer_pid"] == worker["parent"]
         and parent["start_ticks"] == admitted["start_ticks"]
         and parent["parent"] == 1 and admitted["producer_unit"] == plan["unit"] == UNIT
         and live["actual_guard_plan"] == admitted["actual_guard_plan"]
         and original_sample["plan_sha256"] == live["actual_guard_plan"]["sha256"]
         and original_sample["producer_invocation_id"] == final["producer_invocation_id"]
         == end["producer_invocation_id"] == admitted["producer_invocation_id"] == plan["invocation_id"] == IID
         and native["timer"]["Id"] == TIMER and native["timer"]["InvocationID"] == TIMER_IID
         and admitted["epoch"] == live["epoch"] == final["epoch"] == end["epoch"] == 172
         and final["terminal_slot"] == boundary["terminal_slot"] == end["last_slot"] == 74735999
         and final["terminal_blockhash"] == boundary["terminal_blockhash"]
         and final["slots"] == 432000 and final["blocks"] == 384493 and final["transactions"] == 220241274
         and final["size"] == 114876760099
         and final["retained_cap_bytes"] == live["reserved_disk_bytes"] == plan["maximum_root_physical_bytes"] == 288 << 30
         and plan["worker_root"] == live["booked_tree"]["path"] and plan["filesystem"] == "/home/sol"
         and live["reserved_actor_memory_bytes"] == 68 << 30 and not final["archive_publication_authorized"]
         and final["resource_credit_bytes"] == final["reservation_ending_bytes"] == end["resource_credit_bytes"] == 0
         and final["original_work_archive"] == {k:archive[k] for k in ("device","inode","path")}
         and final["log"] == end["log"] == live["producer_log"], "foreign completion, historical owner or booking")
    identity(live["booked_tree"]["path"], live["booked_tree"], directory=True)
    log = final["log"]
    identity(log["path"], log)
    with open(log["path"], "rb") as stream:
        info = os.fstat(stream.fileno())
        need((info.st_dev, info.st_ino) == (log["device"], log["inode"]), "different opened log")
        for offset, length, sha in [(final["record_offset"], final["record_length"], final["record_sha256"]),
                                    (end["records"]["offset"], end["records"]["length"], end["records"]["sha256"])]:
            need(0 < length <= 4096 and hashlib.sha256(os.pread(stream.fileno(), length, offset)).hexdigest() == sha,
                 "final archive or input log evidence changed")
    return final, ref, live, plan


def fleet_identity(core, fleet, final_ref, live):
    rows = [r for group in ("actual_executing_replays", "actual_active_private_diagnostics", "actual_active_bootstraps")
            for r in fleet[group] if r["epoch"] == 172]
    need(len(rows) <= 1, "duplicate incumbent")
    if rows:
        unit = rows[0]["unit"]
        need(unit["Id"] == UNIT and unit["InvocationID"] == IID
             and rows[0]["admission"] == fleet["current_full172_admission"], "foreign cadence owner")
    finalizing = fleet.get("current_full172_finalization")
    if finalizing:
        need(finalizing["archive_result"] == final_ref and not rows, "different cadence finalization")
        if finalizing["phase"] == "committed":
            need(finalizing["identity"] is None and finalizing["terminal"] == fleet["full172_local_commit"]
                 and finalizing["guard_retirement"] == fleet["full172_guard_retirement"], "different cadence terminal")
        else:
            parent = finalizing["identity"]
            guard = finalizing["guard"]["proof"]
            history = core["bound"](guard["receipt"])
            need(finalizing["phase"] == "finalizing" and parent["admission"] == live["admission"]
                 and all(parent["unit"][key] == live["native"]["manager"][key] for key in
                         ("Id", "InvocationID", "MainPID", "ControlGroup", "CPUQuotaPerSecUSec", "MemoryMax"))
                 and parent["timer"]["InvocationID"] == guard["timer"]["InvocationID"] == TIMER_IID
                 and guard["producer"]["Id"] == UNIT and guard["producer"]["InvocationID"] == IID
                 and history["producer_invocation_id"] == IID and history["workers"] == []
                 and history["plan_sha256"] == live["actual_guard_plan"]["sha256"], "different cadence actor or guard")
    need(bool(rows) or bool(finalizing) or bool(fleet.get("full172_local_commit")),
         "cadence lost the 172 reservation")


def check_guard(sample, original, plan, now):
    need(sample["producer"] == original["producer"]
         and sample["producer_invocation_id"] == IID and sample["plan_sha256"] == original["plan_sha256"]
         and sample["producer_stop_enabled"] and sample["trip_reason"] is None and sample["workers"] == []
         and sample["worker_observation_error"] is sample["root_physical_observation_error"] is None
         and sample["maximum_root_physical_bytes"] == sample["root_physical_observation"]["maximum_physical_bytes"]
         == plan["maximum_root_physical_bytes"] and not sample["root_physical_observation"]["exceeds_budget"]
         and sample["available_bytes"] >= sample["minimum_free_bytes"] == plan["minimum_free_bytes"]
         and 0 <= now - sample["recorded_unix_seconds"] <= 120, "different or stale parent-only guard")


def pending(core, final, live, plan, row, anchor):
    native = live["native"]
    parent = native["parent"]
    pid = parent["pid"]
    need(all(row[k] == native["manager"][k] for k in
             ("Id", "InvocationID", "ActiveState", "SubState", "MainPID", "ControlPID", "Job", "ControlGroup",
              "MemoryMax", "MemorySwapMax", "CPUQuotaPerSecUSec", "NRestarts")), "different native manager or limits")
    proc = Path("/proc") / str(pid)
    stat_fields = (proc / "stat").read_text().rsplit(") ", 1)[1].split()
    exe = (proc / "exe").stat()
    group = Path("/sys/fs/cgroup" + row["ControlGroup"])
    need([int(p) for p in (group / "cgroup.procs").read_text().split()] == [pid]
         and (proc / "cgroup").read_text().strip() == "0::" + row["ControlGroup"]
         and [pid, int(stat_fields[19]), exe.st_dev, exe.st_ino] == actor_key(parent)
         and int(stat_fields[1]) == parent["parent"], "different live process roster")
    archive = native["open_work_archive"]
    expected = identity(archive["path"], archive)
    # The node may open additional readers during its own verification.
    # Bind the underlying inode regardless of the descriptor number it retains.
    handles = []
    for fd in (proc / "fd").iterdir():
        try:
            observed = fd.stat()
        except FileNotFoundError:
            continue
        if (observed.st_dev, observed.st_ino) == (expected.st_dev, expected.st_ino):
            handles.append(observed.st_size)
    need(expected.st_size == final["size"] and handles and all(size == expected.st_size for size in handles),
         "parent does not hold the complete original work archive")
    timer = core["state"](TIMER, "Id,ActiveState,InvocationID,Job,Triggers")
    need(all(timer[k] == native["timer"][k] for k in timer), "foreign original guard timer")
    guard = core["state"](timer["Triggers"], "Id,CPUQuotaPerSecUSec,MemoryMax,MemorySwapMax")
    need(guard["CPUQuotaPerSecUSec"] == "250ms" and guard["MemoryMax"] == str(1 << 30)
         and guard["MemorySwapMax"] == "0", "different original guard limits")
    directory = Path(plan["receipt_directory"])
    need(Path(anchor["path"]).parent == directory and not any(directory.glob("stop-*.json")), "guard stopped")
    latest = max(directory.glob("sample-*.json"), key=lambda p:p.stat().st_mtime_ns)
    sample, sample_ref = core["read"](latest)
    check_guard(sample, core["bound"](anchor), plan, time.time())
    return sample_ref, core["physical"](sample)


def terminal(core, delivery, final, live, plan, row, fleet):
    need(row["ActiveState"] == "inactive" and row["MainPID"] == row["ControlPID"] == "0" and not row["Job"]
         and not Path("/sys/fs/cgroup/system.slice", UNIT, "cgroup.procs").exists(),
         "producer has not closed cleanly")
    directory = delivery / "closure-tools"
    for name, sha in CLOSURE.items():
        path = directory / name
        info = path.stat()
        need(path.resolve(strict=True) == path and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o444
             and hashlib.sha256(path.read_bytes()).hexdigest() == sha, "different terminal verifier")
    guard = runpy.run_path(str(directory / "closure172.py"))["guard"]
    # committed() authenticates PID1, the final native cohort, archive and checksum.
    # inspect() also authenticates the exact original guard retirement if it exists.
    verified = guard.inspect() if guard.completion_path.exists() else guard.committed()
    terminal_row = core["bound"](verified["terminal"])
    local = terminal_row["local_archive"]
    info = identity(local["path"], local)
    need(verified["admission"] == final["admission"] and verified["first_worker"] == final["first_worker"]
         and verified["live"] == final["live"] and verified["producer_invocation_id"] == IID
         and info.st_size == local["size"] == final["size"] and len(local["sha256"]) == 64
         and Path(local["path"]) == Path(live["output"]["path"]) / "epoch-172.jet"
         and not verified["resource_credit_bytes"], "foreign native archive terminal")
    if fleet.get("full172_local_commit"):
        need(fleet["full172_local_commit"] == verified["terminal"] and verified.get("guard_retirement")
             and fleet["full172_guard_retirement"] == verified["guard_retirement"], "different fleet terminal or drain")
    # Count only the extents of the committed copy still present in the charged
    # tree. Retain all other disk and compute commitments after producer exit.
    need(Path(local["path"]).is_relative_to(Path(plan["worker_root"])), "archive outside booked tree")
    return verified, min(info.st_blocks * 512, info.st_size)


def observe(core, fleet, rosters, anchors):
    anchor = anchors[UNIT]
    final, ref, live, plan = validate_files(core, fleet, rosters[UNIT], anchor)
    fleet_identity(core, fleet, ref, live)
    row = core["state"](UNIT, core["FIELDS"] + ",SubState,NRestarts")
    detail = dict(finalization=ref, admission=final["admission"], first_worker=final["first_worker"],
                  producer_unit=UNIT, invocation_id=IID, parent_pid=live["native"]["parent"]["pid"],
                  committed=None, original_guard_plan=live["actual_guard_plan"], retained_home_cap=288 << 30,
                  producer_ram=68 << 30, producer_quota_micros=500000, guard_ram=1 << 30,
                  guard_quota_micros=250000, resident_lower_bytes=0,
                  resource_credit_bytes=0, reservation_ending_bytes=0)
    if row["ActiveState"] == "active":
        need(not fleet.get("full172_local_commit"), "producer active after its recorded terminal")
        sample, lower = pending(core, final, live, plan, row, anchor)
        detail.update(phase="finalizing", guard_sample=sample)
    else:
        committed, lower = terminal(core, Path(ref["path"]).parent, final, live, plan, row, fleet)
        sample = live["actual_guard_plan"]
        detail.update(phase="committed", committed=committed, guard_sample=None)
    return detail, sample, lower
