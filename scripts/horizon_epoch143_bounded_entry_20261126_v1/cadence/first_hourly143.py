"""Observe the source-pinned epoch 143 worker in the existing fleet census."""
import hashlib
import json
from pathlib import Path
import re
import stat
import subprocess

from evidence import bound, checked, need

EPOCH = 143
FIELD = "current_private143_first_hourly"
BASE = Path("/var/lib/jetstreamer/horizon_runtime_data/epoch143-first-hourly-20261127-v1")
RUN = Path("/home/sol/.jetstreamer-private/epoch143-first-hourly-20261127-v1")
UNIT = "horizon-qualify-143-first-hourly-20261127-v1.service"
GUARD_TIMER = "horizon-guard-143-first-hourly-20261127-v1.timer"
CGROUP = f"/system.slice/{UNIT}"
KERNEL = Path("/sys/fs/cgroup") / CGROUP.lstrip("/")
CONTRACT = {
    "path": str(BASE / "contract-v1/LAUNCH_PROFILE.json"),
    "sha256": "84e2846e7c33a1a6b7793861f918344be2af10d8132dc380450345f59903a19f",
}
NODE = Path("/usr/local/lib/jetstreamer/deploy-epochs144-147-upgradeable-loader-20261016-v1/jetstreamer-node")
WORKER_SHA = "2cca500106d274ebfbbc8c5bfa0e6e8343cd5e41003f9e82c93282800732d8c8"
FIELDS = (
    "Id,InvocationID,ActiveState,SubState,MainPID,ControlPID,Job,ControlGroup,MemoryMax,"
    "MemorySwapMax,CPUQuotaPerSecUSec,KillMode,NRestarts"
)
PROCESS_SUCCESS = "7ad2d189f7e94e70a38c781354912448"
PROCESS_FAILURE = "98e322203f7a4ed290d09fe03c09fe15"
TERMINAL_SLOT = 61_787_631


def props(unit, fields=FIELDS):
    output = subprocess.check_output(
        ["/usr/bin/systemctl", "show", unit, "-p", fields],
        text=True,
        timeout=12,
    )
    return dict(line.split("=", 1) for line in output.splitlines())


def process_ids():
    try:
        return {int(pid) for pid in (KERNEL / "cgroup.procs").read_text().split()}
    except FileNotFoundError:
        return set()


def start_ticks(pid):
    return int(Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()[19])


def terminal(actor):
    output = subprocess.check_output(
        ["/usr/bin/journalctl", "--no-pager", "-q", "-o", "json", "_PID=1", "_UID=0",
         f"UNIT={UNIT}", f"INVOCATION_ID={actor['producer_invocation_id']}"],
        text=True,
        timeout=12,
    )
    events = [json.loads(line) for line in output.splitlines()]
    matching = [
        event for event in events
        if event.get("MESSAGE_ID") == PROCESS_SUCCESS
        or (event.get("MESSAGE_ID") == PROCESS_FAILURE and event.get("COMMAND") == "ExecStart")
    ]
    need(bool(matching), "143 has no exact PID1 terminal event")
    event = matching[-1]
    need(
        event["INVOCATION_ID"] == actor["producer_invocation_id"]
        and event["_BOOT_ID"] == actor["boot_id"].replace("-", "")
        and int(event["__REALTIME_TIMESTAMP"]) >= actor["recorded_unix_seconds"] * 1_000_000,
        "143 terminal belongs to another invocation",
    )
    return {
        "cursor": event["__CURSOR"], "message_id": event["MESSAGE_ID"],
        "invocation_id": event["INVOCATION_ID"], "realtime_usec": int(event["__REALTIME_TIMESTAMP"]),
    }


def live_actor(manager, actor):
    pid = actor["producer_pid"]
    need(
        manager["Id"] == UNIT and manager["ActiveState"] == "active"
        and manager["InvocationID"] == actor["producer_invocation_id"] and manager["MainPID"] == str(pid)
        and manager["ControlPID"] == "0" and not manager["Job"] and manager["ControlGroup"] == CGROUP
        and manager["MemoryMax"] == str(40 << 30) and manager["MemorySwapMax"] == "0"
        and manager["CPUQuotaPerSecUSec"] == "2s" and manager["NRestarts"] == "0"
        and manager["KillMode"] == "control-group" and start_ticks(pid) == actor["start_ticks"],
        "143 producer or hard limits changed",
    )
    exe = Path(f"/proc/{pid}/exe")
    if exe.samefile(BASE / "tools-v1/hold-143"):
        return False
    need(exe.samefile(NODE), "143 producer executable differs from the sealed node")
    permit = BASE / "barrier/allow"
    info = permit.lstat()
    need(
        stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0 and info.st_nlink == 1
        and stat.S_IMODE(info.st_mode) == 0o444 and permit.read_text() == actor["producer_invocation_id"],
        "143 node lacks the exact owner permit",
    )
    return True


def live_guard(actor):
    timer = props(GUARD_TIMER, "ActiveState,InvocationID,Job,BindsTo")
    need(
        timer["ActiveState"] == "active" and timer["InvocationID"] == actor["guard_timer_invocation_id"]
        and not timer["Job"] and timer["BindsTo"] == UNIT,
        "143 guard timer changed",
    )
    guard = props(GUARD_TIMER.replace(".timer", ".service"),
                  "MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec")
    need(
        guard == {"MemoryMax": str(1 << 30), "MemorySwapMax": "0", "CPUQuotaPerSecUSec": "1s"},
        "143 guard limits changed",
    )
    plan = checked(actor["guard_plan"])
    need(
        plan["unit"] == UNIT and plan["invocation_id"] == actor["producer_invocation_id"]
        and plan["worker_root"] == str(RUN) and plan["maximum_root_physical_bytes"] == 64 << 30
        and plan["filesystem"] == "/home/sol"
        and plan["receipt_directory"] == str(BASE / "guard-receipts"),
        "143 guard plan does not cover this whole tree",
    )
    paths = sorted((BASE / "guard-receipts").glob("sample-*.json"),
                   key=lambda path: path.stat().st_mtime_ns, reverse=True)
    for path in paths[:8]:
        sample_ref = bound(path)
        sample = checked(sample_ref)
        if sample["producer_invocation_id"] != actor["producer_invocation_id"]:
            continue
        need(
            sample["plan_sha256"] == actor["guard_plan"]["sha256"]
            and sample["producer"]["pid"] == actor["producer_pid"]
            and sample["producer_stop_enabled"] is True and sample["trip_reason"] is None
            and sample["root_physical_observation_error"] is None and sample["worker_observation_error"] is None
            and sample["root_physical_observation"]["exceeds_budget"] is False,
            "143 guard sample lost protection",
        )
        return sample_ref, sample
    raise ValueError("143 lacks an invocation-bound guard sample")


def live_worker(actor, sample):
    members = process_ids()
    workers = []
    for pid in sorted(members - {actor["producer_pid"]}):
        exe = Path(f"/proc/{pid}/exe")
        name = exe.readlink()
        if name.name != "historical-worker":
            continue
        need(name.is_relative_to(RUN), "143 historical worker is outside the private run")
        with exe.open("rb") as file:
            need(hashlib.file_digest(file, "sha256").hexdigest() == WORKER_SHA, "143 worker image changed")
        workers.append({"pid": pid, "start_ticks": start_ticks(pid), "path": str(name)})
    need(len(workers) <= 1, "multiple 143 historic workers")
    if workers and any(pid == workers[0]["pid"] and 0 < vmas <= 3_500_000 for pid, vmas in sample["workers"]):
        return workers[0]
    return None


def observe(context):
    manager = props(UNIT)
    idle = manager["ActiveState"] in ("inactive", "failed")
    active_receipt = BASE / "HELD_OWNER.json"
    prior = context.fleet.get(FIELD)
    if not active_receipt.exists():
        need(idle and not manager.get("Job") and not prior and not process_ids(),
             "143 owner has no accepted receipt")
        return None
    actor_ref = bound(active_receipt)
    actor = checked(actor_ref)
    contract = checked(CONTRACT)
    need(
        actor["schema"] == "horizon-epoch143-first-hourly-held-owner-v1"
        and actor["unit"] == contract["unit"] == UNIT and actor["contract"] == CONTRACT
        and actor["producer_pid"] > 1 and actor["start_ticks"] > 0
        and actor["boot_id"] == Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        and re.fullmatch(r"[0-9a-f]{32}", actor["producer_invocation_id"])
        and actor["producer_invocation_id"] != "0" * 32
        and (not prior or prior["held_owner"] == actor_ref),
        "foreign 143 held owner",
    )
    booking_ref = actor["booking"]
    booking = checked(booking_ref)
    need(
        Path(booking_ref["path"]).parent == BASE and booking["unit"] == UNIT
        and booking["contract"] == CONTRACT and (prior or booking["fleet"] == context.fleet_ref)
        and booking["HOME_bytes"] == (64 << 30) + (64 << 20) and booking["RAM_bytes"] == 41 << 30
        and booking["cpu_quota_micros"] == 3_000_000
        and booking["recording_authorized"] is True and booking["archive_publication_authorized"] is False
        and booking["native_census_enrolled"] is True,
        "143 booking lacks exact owner enrollment",
    )
    row = dict(epoch=EPOCH, unit=manager, actor=actor, held_owner=actor_ref, observer=context.sample_ref,
               observer_config=None, worker=None, transaction_replay_claimed=False,
               canonical_replay_claimed=False, archive_publication_authorized=False, resource_credit_bytes=0)
    if idle:
        need(
            manager["MainPID"] == "0" and not manager["Job"] and not process_ids()
            and manager["InvocationID"] in ("", actor["producer_invocation_id"]),
            "143 terminal still has a process or belongs to a different owner",
        )
        row.update(phase="terminal", native_terminal=terminal(actor))
        return row
    node = live_actor(manager, actor)
    guard_ref, sample = live_guard(actor)
    worker = live_worker(actor, sample) if node else None
    row.update(phase="worker" if worker else "bootstrap" if node else "held",
               guard=guard_ref, worker=worker)
    if worker:
        row["observer_config"] = dict(
            range="143", producer_unit=UNIT, controller_unit=UNIT,
            expected_producer_invocation_id=actor["producer_invocation_id"],
            expected_controller_invocation_id=actor["producer_invocation_id"],
            scratch_path=str(RUN), worker_executable_basename="historical-worker",
        )
        progress_path = BASE / "FIRST_PROTECTED_PROGRESS.json"
        if progress_path.exists():
            progress_ref = bound(progress_path)
            progress = checked(progress_ref)
            need(
                progress["producer_invocation_id"] == actor["producer_invocation_id"]
                and progress["worker_pid"] == worker["pid"] and 61_775_538 < progress["slot"] <= TERMINAL_SLOT,
                "143 first progress belongs to another worker",
            )
            row.update(transaction_replay_claimed=True, first_progress=progress_ref)
    return row


def active(row):
    return bool(row and row["phase"] != "terminal")


def recheck(row):
    if active(row):
        live_actor(props(UNIT), row["actor"])
    elif row:
        need(not process_ids(), "closed 143 acquired another process")


def project(context, row):
    if row is None:
        return
    diagnostics = [item for item in context.next_cfg["diagnostic_replays"] if item["range"] != "143"]
    if active(row) and row["observer_config"] is not None:
        diagnostics.append(row["observer_config"])
    context.next_cfg["diagnostic_replays"] = diagnostics
