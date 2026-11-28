"""Observe registered private hourly replays in the existing fleet census."""
import hashlib
import json
from pathlib import Path
import re
import stat
import subprocess

from evidence import bound, checked, need


class FirstHourlyProfile:
    def __init__(self, epoch, *, bootstrap, terminal, tree_gib, producer_ram_gib,
                 contract_sha, node, worker_sha, interval="first", date="20261127"):
        self.epoch = epoch
        self.bootstrap = bootstrap
        self.terminal = terminal
        self.tree_bytes = tree_gib << 30
        self.producer_ram = producer_ram_gib << 30
        self.node = Path(node)
        self.worker_sha = worker_sha
        self.interval = interval
        suffix = f"{epoch}-{interval}-hourly-{date}-v1"
        name = f"epoch{suffix}"
        self.base = Path("/var/lib/jetstreamer/horizon_runtime_data") / name
        self.run = Path("/home/sol/.jetstreamer-private") / name
        self.unit = f"horizon-qualify-{suffix}.service"
        self.guard_timer = f"horizon-guard-{suffix}.timer"
        self.cgroup = f"/system.slice/{self.unit}"
        self.field = f"current_private{epoch}_{interval}_hourly"
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


FAILED_BOOTSTRAP_IID = "03ba8900c208428e81f98314e72f6685"
FAILED_BOOTSTRAP_ACTOR = "d0b82212bddc871d7b4a5ba07272d323332c875b11805b2e0c610ef2e5630d7c"
FAILED_BOOTSTRAP_TERMINAL = "48a3d3002e8bd990c69cfc5a551776929fcfa5462275c90a24e1a3f99b24eaa3"
FAILED_BOOTSTRAP_FLEET = "a73a1fdd37b149409a01762d9ac82024fc353681080d07646df05c5a8617c8be"
RETRY_BOOKER_SEAL = "fa9e315142bf57e2aca0bd456444caae5921655b47d12c71095cf20919b704d3"
RETRY_GATE_SHA = "c5656f1867ede9b8b33e12e890eae3ba97c572bcaf76d9b45b86aafd0b5cde63"
RETRY_HISTORY = "retained_143_bootstrap_failure"
HELD_FAILURE_HISTORY = "retained_143_unreleased_failure"
HELD_FAILURE_IID = "c643e4e61d0f4b7eb59448824c86bc59"
HELD_FAILURE_BOOKING = "8ea92dafc87a4279910eb160d41660badcf2edc2e57a8412c43e9bbbdc42bfed"
V53_BOOKER_SEAL = "64ef98ccb5c3369e7b730d976983ccd9152e5f7caec9264f850092a3ca4f1c2e"
RETRY_BOOKER_SEALS = {52: RETRY_BOOKER_SEAL, 53: V53_BOOKER_SEAL}


def bootstrap_history(profile):
    base = profile.base
    archive = base / f"failed-{FAILED_BOOTSTRAP_IID}"
    terminal_ref = dict(path=str(archive / "NATIVE_TERMINAL.json"), sha256=FAILED_BOOTSTRAP_TERMINAL)
    fleet_ref = dict(path=str(base.parent / "root014808-live166167170-20261128-v1/ROOT_COMPLETE_OPERATIONAL_FLEET.json"),
                     sha256=FAILED_BOOTSTRAP_FLEET)
    archived = dict(path=str(archive / "HELD_OWNER.json"), sha256=FAILED_BOOTSTRAP_ACTOR)
    terminal_row = checked(terminal_ref)
    old = checked(fleet_ref)[profile.field]
    actor = checked(archived)
    need(old["phase"] == "terminal" and old["held_owner"] == terminal_row["held_owner"]
         and old["held_owner"]["sha256"] == archived["sha256"] and old["actor"] == actor
         and old["native_terminal"] == terminal_row["pid1"]
         and actor["producer_invocation_id"] == terminal_row["invocation_id"] == FAILED_BOOTSTRAP_IID
         and not terminal_row["worker_progress"] and not terminal_row["archive_present"]
         and not terminal_row["resource_credit_bytes"], "different archived 143 bootstrap failure")
    receipt = archive / "RECONCILED.json"
    reconciliation = None
    if receipt.exists():
        reconciliation = bound(receipt)
        settled = checked(reconciliation)
        need(settled["schema"] == "horizon-epoch143-bootstrap-failure-reconciled-v1"
             and settled["failed_invocation"] == FAILED_BOOTSTRAP_IID and settled["released_gate_drained"]
             and settled["terminal"] == terminal_ref and settled["accepted_fleet"] == fleet_ref
             and settled["original_held_owner"] == old["held_owner"] and settled["archived_held_owner"] == archived
             and not settled["resource_credit_bytes"] and not settled["archive_publication_authorized"],
             "different 143 bootstrap reconciled receipt")
    return dict(terminal=terminal_ref, accepted_fleet=fleet_ref, archived_held_owner=archived,
                reconciliation=reconciliation), old


def retry_booking(booking, profile):
    package = Path(booking["sealed_operator"]["path"]).parent
    version = next((version for version in RETRY_BOOKER_SEALS
                    if package == profile.base / f"booking-price-v{version}"), None)
    need(version is not None, "unregistered epoch 143 retry booker")
    seal = checked(dict(path=str(package / "deployment-seal-receipt.json"), sha256=RETRY_BOOKER_SEALS[version]))
    members = {member["name"]: member["sha256"] for member in seal["members"]}
    for field, name in (("sealed_operator", "launch-first-hourly143.sh"), ("sealed_price", "price_hourly143.py")):
        ref = dict(path=str(package / name), sha256=members[name])
        need(booking[field] == ref == bound(package / name), "143 retry changed its sealed booking member")
    writer_ref = booking["writer_active"]
    writer_root = profile.base.parent / "survivor172-cadence-20261122-v1"
    writer_package = writer_root / f"tools-cold168-retry5-failed166-v{version}-entry146"
    need(writer_ref["path"] == str(writer_root / f"FAILED166_CADENCE_V{version}_ACTIVE.json"),
         "143 retry uses another cadence generation")
    active = checked(writer_ref)
    ready = checked(active["ready"])
    need(seal["destination"] == str(package) and booking["writer"] == active["new"]
         and active["new"]["program"] == str(writer_package / "status_cycle.py")
         and booking["sealed_reader"] == ready["hourly_reader"] == bound(writer_package / "first_hourly143.py"),
         "143 retry lost its exact reader or writer")
    return version


def v53_release(actor, booking, profile):
    archive = profile.base / f"failed-{HELD_FAILURE_IID}"
    history_ref = bound(archive / "RECONCILED.json")
    history = checked(history_ref)
    prior_booking = booking["replaces_expired_booking"]
    need(history["schema"] == "horizon-epoch143-unreleased-gate-reconciled-v2"
         and history["failed_invocation"] == HELD_FAILURE_IID != actor["producer_invocation_id"]
         and history["expired_booking"] == prior_booking and prior_booking["sha256"] == HELD_FAILURE_BOOKING
         and history["release_absent"] and not history["archive_created"] and not history["resource_credit_bytes"],
         "epoch 143 lost the exact unreleased V52 attempt")
    plan = checked(actor["guard_plan"])
    post = checked(actor["post_guard_fit"])
    sample = checked(post["candidate_guard_sample"])
    floor = plan["minimum_free_bytes"]
    need(post["fleet"] == booking["fleet"] and post["contract"] == profile.contract
         and post["held_invocation"] == plan["invocation_id"] == sample["producer_invocation_id"] ==
         actor["producer_invocation_id"]
         and sample["plan_sha256"] == actor["guard_plan"]["sha256"]
         and post["disk_fits"] and post["memory_fits"] and post["guard_floor_fits"]
         and post["required_guard_floor_bytes"] <= floor == post["guard_floor_bytes"] == sample["minimum_free_bytes"]
         and post["additional_home_charge_bytes"] == 0 and post["resource_credit_bytes"] == 0
         and post["available_home_bytes"] >= max(floor, post["retained_required_home_bytes"])
         + post["candidate_home_bytes"], "epoch 143 release lacks its fully charged guard floor")
    return history_ref


def corrected_gate(exe, actor, profile):
    if profile.epoch != 143:
        return False
    candidate = profile.base / "tools-bootstrap-v2/hold-143"
    if not candidate.is_file() or not exe.samefile(candidate):
        return False
    need(bound(candidate)["sha256"] == RETRY_GATE_SHA
         and stat.S_IMODE(candidate.stat().st_mode) == 0o555, "different corrected 143 gate image")
    retry_booking(checked(actor["booking"]), profile)
    return True


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
    retry = profile is EPOCH143 and Path(checked(actor["booking"])["sealed_operator"]["path"]).parent in {
        profile.base / f"booking-price-v{version}" for version in RETRY_BOOKER_SEALS
    }
    held = corrected_gate(exe, actor, profile) if retry else exe.samefile(profile.base / f"tools-v1/hold-{profile.epoch}")
    if held:
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
    receipt_ref = bound(active_receipt) if active_receipt.exists() else None
    history = None
    if profile is EPOCH143 and prior:
        old_actor = prior["held_owner"]["sha256"] == FAILED_BOOTSTRAP_ACTOR
        if (old_actor and prior["held_owner"] != receipt_ref) or RETRY_HISTORY in prior:
            history, earlier = bootstrap_history(profile)
            if old_actor:
                need(prior["phase"] == "terminal" and prior["actor"] == earlier["actor"]
                     and prior["native_terminal"] == earlier["native_terminal"],
                     "143 retry has no exact accepted terminal predecessor")
                if receipt_ref is None:
                    need(idle and manager["MainPID"] == manager["ControlPID"] == "0"
                         and not manager["Job"] and not process_ids(profile)
                         and manager["InvocationID"] in ("", FAILED_BOOTSTRAP_IID),
                         "archived 143 terminal crossed another native owner")
                    return dict(earlier, unit=manager, observer=context.sample_ref,
                                held_owner=history["archived_held_owner"], **{RETRY_HISTORY: history})
                need(history["reconciliation"] is not None, "143 retry preceded reconciliation")
                prior = None
            else:
                need(history["reconciliation"] is not None and prior[RETRY_HISTORY] == history,
                     "143 retry lost its retained bootstrap failure")
    if receipt_ref is None:
        need(idle and not manager.get("Job") and not prior and not process_ids(profile),
             f"{profile.epoch} owner has no accepted receipt")
        return None
    actor_ref = receipt_ref
    actor = checked(actor_ref)
    contract = checked(profile.contract)
    need(
        actor["schema"] == f"horizon-epoch{profile.epoch}-{profile.interval}-hourly-held-owner-v1"
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
    if history is not None:
        need(actor["producer_invocation_id"] != FAILED_BOOTSTRAP_IID, "143 retry reused its failed invocation")
        version = retry_booking(booking, profile)
        row[RETRY_HISTORY] = history
        if version == 53:
            recovered = v53_release(actor, booking, profile)
            need(not prior or prior.get(HELD_FAILURE_HISTORY, recovered) == recovered,
                 "epoch 143 unreleased failure receipt changed")
            row[HELD_FAILURE_HISTORY] = recovered
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
