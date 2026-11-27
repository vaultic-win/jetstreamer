"""Observe the two registered first-hourly replays in the existing fleet census."""
import hashlib
import json
from pathlib import Path
import re
import stat
import subprocess

from evidence import bound, checked, need


class FirstHourlyProfile:
    def __init__(self, epoch, *, bootstrap, terminal, tree_gib, producer_ram_gib,
                 contract_sha, node, worker_sha):
        self.epoch = epoch
        self.bootstrap = bootstrap
        self.terminal = terminal
        self.tree_bytes = tree_gib << 30
        self.producer_ram = producer_ram_gib << 30
        self.node = Path(node)
        self.worker_sha = worker_sha
        name = f"epoch{epoch}-first-hourly-20261127-v1"
        self.base = Path("/var/lib/jetstreamer/horizon_runtime_data") / name
        self.run = Path("/home/sol/.jetstreamer-private") / name
        self.unit = f"horizon-qualify-{epoch}-first-hourly-20261127-v1.service"
        self.guard_timer = f"horizon-guard-{epoch}-first-hourly-20261127-v1.timer"
        self.cgroup = f"/system.slice/{self.unit}"
        self.field = f"current_private{epoch}_first_hourly"
        self.contract = {"path": str(self.base / "contract-v1/LAUNCH_PROFILE.json"), "sha256": contract_sha}


EPOCH143 = FirstHourlyProfile(
    143, bootstrap=61_775_538, terminal=61_787_631, tree_gib=64, producer_ram_gib=40,
    contract_sha="84e2846e7c33a1a6b7793861f918344be2af10d8132dc380450345f59903a19f",
    node="/usr/local/lib/jetstreamer/deploy-epochs144-147-upgradeable-loader-20261016-v1/jetstreamer-node",
    worker_sha="2cca500106d274ebfbbc8c5bfa0e6e8343cd5e41003f9e82c93282800732d8c8",
)
EPOCH141 = FirstHourlyProfile(
    141, bootstrap=60_911_751, terminal=60_921_282, tree_gib=44, producer_ram_gib=30,
    contract_sha="73a120db97d72a03c05c39139098a10cd6c84802f0f5472a1251f341976ce131",
    node=("/var/lib/jetstreamer/horizon_runtime_data/epoch141-hourly-original-build-20261127-v1/"
          "1a0a89cbd5554a63b87feeec40e7b6c0/node/jetstreamer-node"),
    worker_sha="fce05d551d8154ebda6ff6b3791d02f60b0e0a1e3a69982ea06fa7c31c34b759",
)
# The original single-epoch entry points retain their epoch 143 defaults.
FIELD = EPOCH143.field

FIELDS = (
    "Id,InvocationID,ActiveState,SubState,MainPID,ControlPID,Job,ControlGroup,MemoryMax,"
    "MemorySwapMax,CPUQuotaPerSecUSec,KillMode,NRestarts"
)
PROCESS_SUCCESS = "7ad2d189f7e94e70a38c781354912448"
PROCESS_FAILURE = "98e322203f7a4ed290d09fe03c09fe15"


def props(unit, fields=FIELDS):
    output = subprocess.check_output(
        ["/usr/bin/systemctl", "show", unit, "-p", fields],
        text=True,
        timeout=12,
    )
    return dict(line.split("=", 1) for line in output.splitlines())


def process_ids(profile=EPOCH143):
    try:
        return {int(pid) for pid in (Path("/sys/fs/cgroup") / profile.cgroup.lstrip("/") / "cgroup.procs").read_text().split()}
    except FileNotFoundError:
        return set()


def start_ticks(pid):
    return int(Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()[19])


def terminal(actor, profile=EPOCH143):
    output = subprocess.check_output(
        ["/usr/bin/journalctl", "--no-pager", "-q", "-o", "json", "_PID=1", "_UID=0",
         f"UNIT={profile.unit}", f"INVOCATION_ID={actor['producer_invocation_id']}"],
        text=True,
        timeout=12,
    )
    events = [json.loads(line) for line in output.splitlines()]
    matching = [
        event for event in events
        if event.get("MESSAGE_ID") == PROCESS_SUCCESS
        or (event.get("MESSAGE_ID") == PROCESS_FAILURE and event.get("COMMAND") == "ExecStart")
    ]
    need(bool(matching), f"{profile.epoch} has no exact PID1 terminal event")
    event = matching[-1]
    need(
        event["INVOCATION_ID"] == actor["producer_invocation_id"]
        and event["_BOOT_ID"] == actor["boot_id"].replace("-", "")
        and int(event["__REALTIME_TIMESTAMP"]) >= actor["recorded_unix_seconds"] * 1_000_000,
        f"{profile.epoch} terminal belongs to another invocation",
    )
    return {
        "cursor": event["__CURSOR"], "message_id": event["MESSAGE_ID"],
        "invocation_id": event["INVOCATION_ID"], "realtime_usec": int(event["__REALTIME_TIMESTAMP"]),
    }


def live_actor(manager, actor, profile=EPOCH143):
    pid = actor["producer_pid"]
    need(
        manager["Id"] == profile.unit and manager["ActiveState"] == "active"
        and manager["InvocationID"] == actor["producer_invocation_id"] and manager["MainPID"] == str(pid)
        and manager["ControlPID"] == "0" and not manager["Job"] and manager["ControlGroup"] == profile.cgroup
        and manager["MemoryMax"] == str(profile.producer_ram) and manager["MemorySwapMax"] == "0"
        and manager["CPUQuotaPerSecUSec"] == "2s" and manager["NRestarts"] == "0"
        and manager["KillMode"] == "control-group" and start_ticks(pid) == actor["start_ticks"],
        f"{profile.epoch} producer or hard limits changed",
    )
    exe = Path(f"/proc/{pid}/exe")
    if exe.samefile(profile.base / f"tools-v1/hold-{profile.epoch}"):
        return False
    need(exe.samefile(profile.node), f"{profile.epoch} producer executable differs from the sealed node")
    permit = profile.base / "barrier/allow"
    info = permit.lstat()
    need(
        stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0 and info.st_nlink == 1
        and stat.S_IMODE(info.st_mode) == 0o444 and permit.read_text() == actor["producer_invocation_id"],
        f"{profile.epoch} node lacks the exact owner permit",
    )
    return True


def live_guard(actor, profile=EPOCH143):
    timer = props(profile.guard_timer, "ActiveState,InvocationID,Job,BindsTo")
    need(
        timer["ActiveState"] == "active" and timer["InvocationID"] == actor["guard_timer_invocation_id"]
        and not timer["Job"] and timer["BindsTo"] == profile.unit,
        f"{profile.epoch} guard timer changed",
    )
    guard = props(profile.guard_timer.replace(".timer", ".service"),
                  "MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec")
    need(
        guard == {"MemoryMax": str(1 << 30), "MemorySwapMax": "0", "CPUQuotaPerSecUSec": "1s"},
        f"{profile.epoch} guard limits changed",
    )
    plan = checked(actor["guard_plan"])
    need(
        plan["unit"] == profile.unit and plan["invocation_id"] == actor["producer_invocation_id"]
        and plan["worker_root"] == str(profile.run) and plan["maximum_root_physical_bytes"] == profile.tree_bytes
        and plan["filesystem"] == "/home/sol"
        and plan["receipt_directory"] == str(profile.base / "guard-receipts"),
        f"{profile.epoch} guard plan does not cover this whole tree",
    )
    paths = sorted((profile.base / "guard-receipts").glob("sample-*.json"),
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
            f"{profile.epoch} guard sample lost protection",
        )
        return sample_ref, sample
    raise ValueError(f"{profile.epoch} lacks an invocation-bound guard sample")


def live_worker(actor, sample, profile=EPOCH143):
    members = process_ids(profile)
    workers = []
    for pid in sorted(members - {actor["producer_pid"]}):
        exe = Path(f"/proc/{pid}/exe")
        name = exe.readlink()
        if name.name != "historical-worker":
            continue
        need(name.is_relative_to(profile.run), f"{profile.epoch} historical worker is outside the private run")
        with exe.open("rb") as file:
            need(hashlib.file_digest(file, "sha256").hexdigest() == profile.worker_sha, f"{profile.epoch} worker image changed")
        workers.append({"pid": pid, "start_ticks": start_ticks(pid), "path": str(name)})
    need(len(workers) <= 1, f"multiple {profile.epoch} historic workers")
    if workers and any(pid == workers[0]["pid"] and 0 < vmas <= 3_500_000 for pid, vmas in sample["workers"]):
        return workers[0]
    return None


def observe(context, profile=EPOCH143):
    manager = props(profile.unit)
    idle = manager["ActiveState"] in ("inactive", "failed")
    active_receipt = profile.base / "HELD_OWNER.json"
    prior = context.fleet.get(profile.field)
    if not active_receipt.exists():
        need(idle and not manager.get("Job") and not prior and not process_ids(profile),
             f"{profile.epoch} owner has no accepted receipt")
        return None
    actor_ref = bound(active_receipt)
    actor = checked(actor_ref)
    contract = checked(profile.contract)
    need(
        actor["schema"] == f"horizon-epoch{profile.epoch}-first-hourly-held-owner-v1"
        and actor["unit"] == contract["unit"] == profile.unit and actor["contract"] == profile.contract
        and actor["producer_pid"] > 1 and actor["start_ticks"] > 0
        and actor["boot_id"] == Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        and re.fullmatch(r"[0-9a-f]{32}", actor["producer_invocation_id"])
        and actor["producer_invocation_id"] != "0" * 32
        and (not prior or prior["held_owner"] == actor_ref),
        f"foreign {profile.epoch} held owner",
    )
    booking_ref = actor["booking"]
    booking = checked(booking_ref)
    need(
        Path(booking_ref["path"]).parent == profile.base and booking["unit"] == profile.unit
        and booking["contract"] == profile.contract and (prior or booking["fleet"] == context.fleet_ref)
        and booking["HOME_bytes"] == profile.tree_bytes + (64 << 20) and booking["RAM_bytes"] == profile.producer_ram + (1 << 30)
        and booking["cpu_quota_micros"] == 3_000_000
        and booking["recording_authorized"] is True and booking["archive_publication_authorized"] is False
        and booking["native_census_enrolled"] is True,
        f"{profile.epoch} booking lacks exact owner enrollment",
    )
    row = dict(epoch=profile.epoch, unit=manager, actor=actor, held_owner=actor_ref, observer=context.sample_ref,
               observer_config=None, worker=None, transaction_replay_claimed=False,
               canonical_replay_claimed=False, archive_publication_authorized=False, resource_credit_bytes=0)
    if idle:
        need(
            manager["MainPID"] == "0" and not manager["Job"] and not process_ids(profile)
            and manager["InvocationID"] in ("", actor["producer_invocation_id"]),
            f"{profile.epoch} terminal still has a process or belongs to a different owner",
        )
        row.update(phase="terminal", native_terminal=terminal(actor, profile))
        return row
    node = live_actor(manager, actor, profile)
    guard_ref, sample = live_guard(actor, profile)
    worker = live_worker(actor, sample, profile) if node else None
    row.update(phase="worker" if worker else "bootstrap" if node else "held",
               guard=guard_ref, worker=worker)
    if worker:
        row["observer_config"] = dict(
            range=str(profile.epoch), producer_unit=profile.unit, controller_unit=profile.unit,
            expected_producer_invocation_id=actor["producer_invocation_id"],
            expected_controller_invocation_id=actor["producer_invocation_id"],
            scratch_path=str(profile.run), worker_executable_basename="historical-worker",
        )
        progress_path = profile.base / "FIRST_PROTECTED_PROGRESS.json"
        if progress_path.exists():
            progress_ref = bound(progress_path)
            progress = checked(progress_ref)
            need(
                progress["producer_invocation_id"] == actor["producer_invocation_id"]
                and progress["worker_pid"] == worker["pid"] and profile.bootstrap < progress["slot"] <= profile.terminal,
                f"{profile.epoch} first progress belongs to another worker",
            )
            row.update(transaction_replay_claimed=True, first_progress=progress_ref)
    return row


def active(row):
    return bool(row and row["phase"] != "terminal")


def recheck(row, profile=EPOCH143):
    if active(row):
        live_actor(props(profile.unit), row["actor"], profile)
    elif row:
        need(not process_ids(profile), f"closed {profile.epoch} acquired another process")


def project(context, row, profile=EPOCH143):
    if row is None:
        return
    diagnostics = [item for item in context.next_cfg["diagnostic_replays"] if item["range"] != str(profile.epoch)]
    if active(row) and row["observer_config"] is not None:
        diagnostics.append(row["observer_config"])
    context.next_cfg["diagnostic_replays"] = diagnostics
