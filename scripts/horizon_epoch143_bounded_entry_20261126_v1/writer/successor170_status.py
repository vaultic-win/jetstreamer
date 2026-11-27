"""Enroll and observe the bounded epoch 170 continuation on the sole clock."""

import json
from pathlib import Path
import re
import stat
import time

from evidence import BASE, bound, checked, durable, need
from bridge170_status import FAILURE, PROPS, SUCCESS, native

ROOT = BASE / "epoch170-from-73726716-20261127-v1"
INTERFACE = dict(path=str(ROOT / "BOUNDED_SUCCESSOR_WRITER_INTERFACE.json"),
                 sha256="30ba2b754885f8ba7cf9abc04d9453bb1b8a030b0534b31d1801543ea8c4906a")
FIELD = "current_private170_bounded_successor"
UNIT = "horizon-qualify-170-from-73726716-20261127-v1.service"
GUARD_TIMER = "horizon-guard-170-from-73726716-20261127-v1.timer"
GUARD_UNIT = GUARD_TIMER.replace(".timer", ".service")
ALIAS = "/run/horizon-170-from-73726716-v1"
GROUP = f"/system.slice/{UNIT}"
CGROUP = Path("/sys/fs/cgroup") / GROUP.lstrip("/")
GUARD_ROOT = "/home/sol/.jetstreamer-private/epoch170-standard-lane-20261109-v1"
ACTOR = ROOT / "SUCCESSOR_ACTOR.json"
RELEASE = ROOT / "SUCCESSOR_RELEASE.json"
ENROLLMENT = ROOT / "WRITER_ENROLLMENT.json"
ACTOR_SCHEMA = "horizon-epoch170-bounded-successor-actor-v1"
RELEASE_SCHEMA = "horizon-epoch170-bounded-successor-release-v1"
ENROLLMENT_SCHEMA = "horizon-epoch170-bounded-successor-writer-enrollment-v1"


def interface():
    scope = checked(INTERFACE)
    need(scope["schema"] == "horizon-170-bounded-continuation-writer-interface-v1"
         and (scope["bootstrap"], scope["first_new_slot"], scope["last"])
         == (73726716, 73726717, 73746882)
         and scope["expected_producer_unit"] == UNIT
         and scope["expected_guard_timer"] == GUARD_TIMER
         and scope["expected_guard_unit"] == GUARD_UNIT
         and scope["recording"] == "private" and scope["admission_or_release"] is False,
         "foreign bounded epoch 170 interface")
    return scope


def closed_comparison(scope):
    ref = bound(Path(scope["closed_comparison"]))
    report = checked(ref)
    segment = report["closed_segment"]
    manifest = checked(segment["manifest"])
    need(report["schema"] == "epoch170-bridge-checkpoint-comparison-v1"
         and report["mode"] == "closed" and report["release"] == scope["old_release"]
         and report["pid1_exit"] and [row["slot"] for row in report["checkpoints"]]
         == [73706460, 73713261, scope["bootstrap"]]
         and manifest["terminal"] == report["checkpoints"][-1]
         and manifest["archive_sha256"] == segment["sha256"]
         and report["publication_authorized"] is False and report["resource_credit_bytes"] == 0,
         "bounded successor lacks the closed bridge comparison")
    return ref


def read_actor():
    ref = bound(ACTOR)
    actor = checked(ref)
    iid = actor["producer_invocation_id"]
    need(actor["schema"] == ACTOR_SCHEMA and actor["interface"] == INTERFACE
         and actor["unit"] == UNIT and re.fullmatch("[0-9a-f]{32}", iid) and int(iid, 16)
         and actor["producer_pid"] > 1 and actor["start_ticks"] > 0
         and actor["boot_id"] == Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
         "foreign bounded epoch 170 actor")
    return ref, actor


def process(pid):
    proc = Path("/proc") / str(pid)
    executable = (proc / "exe").stat()
    need((proc / "cgroup").read_text().strip() == f"0::{GROUP}",
         "bounded epoch 170 process left its cgroup")
    return [pid, native.ticks(pid), executable.st_dev, executable.st_ino]


def live(scope, manager, actor, released):
    pid = actor["producer_pid"]
    proc = Path("/proc") / str(pid)
    need(manager["ActiveState"] == "active" and manager["SubState"] == "running"
         and manager["InvocationID"] == actor["producer_invocation_id"]
         and manager["MainPID"] == str(pid) and manager["ControlPID"] == "0"
         and manager["ControlGroup"] == GROUP and not manager["Job"]
         and manager["Restart"] == "no" and manager["NRestarts"] == "0"
         and manager["KillMode"] == "control-group" and manager["User"] == "sol"
         and manager["Group"] == "horizon" and manager["MemoryMax"] == str(48 << 30)
         and manager["MemorySwapMax"] == "0" and manager["CPUQuotaPerSecUSec"] == "6s"
         and native.ticks(pid) == actor["start_ticks"], "bounded epoch 170 actor changed")
    pids = {int(value) for value in (CGROUP / "cgroup.procs").read_text().split()}
    exe = proc / "exe"
    argv = (proc / "cmdline").read_bytes().split(b"\0")
    gate = Path(scope["profile"]["sealed_package"]["path"]).with_name("gate")
    if exe.samefile(gate):
        need(pids == {pid} and argv == [f"{ALIAS}/gate".encode(), b""],
             "different bounded epoch 170 hold")
        return [process(pid)], None, "held"
    run = Path(scope["run"])
    need(released and exe.samefile(scope["profile"]["node"]["path"]) and pid in pids
         and len(pids) <= 2 and argv[0] == f"{ALIAS}/jetstreamer-node".encode()
         and argv[1:3] == [b"170", str(run / "ledger").encode()]
         and f"--qualification-end-slot={scope['last']}".encode() in argv
         and f"--horizon-output={run}/ledger/epoch-170.diagnostic.jet".encode() in argv,
         "bounded epoch 170 node command or ownership changed")
    child = None
    if pids - {pid}:
        child_pid, = pids - {pid}
        child_exe = Path(f"/proc/{child_pid}/exe").resolve(strict=True)
        need(child_exe.name == "historical-worker" and child_exe.is_relative_to(run / "scratch"),
             "foreign bounded epoch 170 worker")
        native.file_identity(child_exe, scope["profile"]["worker"], executable=True)
        child = dict(pid=child_pid, path=str(child_exe), start_ticks=native.ticks(child_pid))
    return [process(value) for value in sorted(pids)], child, "bootstrap"


def enrollment(actor_ref, closed_ref):
    ref = bound(ENROLLMENT)
    row = checked(ref)
    writer = checked(row["writer_active"])
    need(row["schema"] == ENROLLMENT_SCHEMA and row["interface"] == INTERFACE
         and row["actor"] == actor_ref and row["closed_comparison"] == closed_ref
         and row["enrolled"] is True and row["publication_authorized"] is False
         and checked(writer["ready"])["successor170_interface"] == INTERFACE,
         "bounded epoch 170 writer enrollment changed")
    return ref


def release(scope, actor_ref, actor, closed_ref):
    permit_path = Path(scope["barrier"])
    if not permit_path.exists():
        return None, None
    permit = permit_path.lstat()
    ref = bound(RELEASE)
    grant = checked(ref)
    plan = checked(grant["guard_plan"])
    first = checked(grant["first_guard_sample"])
    iid = actor["producer_invocation_id"]
    need(grant["schema"] == RELEASE_SCHEMA and grant["interface"] == INTERFACE
         and grant["actor"] == actor_ref and grant["producer_invocation_id"] == iid
         and grant["closed_comparison"] == closed_ref
         and grant["writer_enrollment"] == enrollment(actor_ref, closed_ref)
         and grant["resource_credit_bytes"] == 0 and grant["archive_publication_authorized"] is False
         and stat.S_ISREG(permit.st_mode) and stat.S_IMODE(permit.st_mode) == 0o444
         and permit.st_uid == permit.st_gid == 0 and permit.st_nlink == 1
         and permit_path.read_bytes() == iid.encode()
         and grant["guard_plan"]["path"] == scope["plan_path"]
         and plan["unit"] == UNIT and plan["invocation_id"] == iid
         and plan["worker_root"] == GUARD_ROOT and plan["filesystem"] == "/home/sol"
         and plan["receipt_directory"] == scope["guard_receipts"]
         and plan["minimum_free_bytes"] >= 8958105897878
         and 0 < plan["maximum_root_physical_bytes"] <= 384 << 30
         and first["plan_sha256"] == grant["guard_plan"]["sha256"]
         and first["producer_invocation_id"] == iid and first["producer"]["pid"] == actor["producer_pid"]
         and first["producer_stop_enabled"] is True and first["trip_reason"] is None,
         "foreign bounded epoch 170 release or first guard")
    checked(grant["post_guard_capacity"])
    return ref, grant


def guard(scope, actor, worker, grant):
    timer = native.props(GUARD_TIMER, ("Id", "InvocationID", "ActiveState", "SubState", "Job", "Triggers"))
    unit = native.props(GUARD_UNIT, ("Id", "TriggeredBy", "ExecStart", "MemoryMax", "MemorySwapMax", "CPUQuotaPerSecUSec"))
    plan_ref = grant["guard_plan"]
    plan = checked(plan_ref)
    image = Path(scope["guard_seal"]["path"]).with_name("guard")
    need(timer["ActiveState"] == "active" and timer["SubState"] in ("waiting", "running")
         and timer["InvocationID"] == grant["guard_timer_invocation_id"] and not timer["Job"]
         and timer["Triggers"] == GUARD_UNIT and unit["TriggeredBy"] == GUARD_TIMER
         and unit["MemoryMax"] == str(1 << 30) and unit["MemorySwapMax"] == "0"
         and unit["CPUQuotaPerSecUSec"] == "1s"
         and all(value in unit["ExecStart"] for value in
                 (str(image), scope["guard_sha"], plan_ref["path"], plan_ref["sha256"])),
         "bounded epoch 170 lost its protective timer")
    receipts = Path(scope["guard_receipts"])
    sample_path = max(receipts.glob("sample-*.json"), key=lambda path: path.stat().st_mtime_ns)
    sample_ref = bound(sample_path)
    sample = checked(sample_ref)
    workers = sample["workers"]
    iid = actor["producer_invocation_id"]
    need(sample["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
         and sample_path.name == f"sample-{sample['guard_invocation_id']}.json"
         and sample["plan_sha256"] == plan_ref["sha256"]
         and sample["producer_invocation_id"] == sample["producer"]["invocation_id"] == iid
         and sample["producer"]["pid"] == actor["producer_pid"]
         and sample["producer"]["cgroup"] == GROUP and sample["producer"]["active"] == "active"
         and sample["producer"]["restarts"] == 0 and 0 <= time.time() - sample["recorded_unix_seconds"] <= 120
         and sample["producer_stop_enabled"] is True and sample["trip_reason"] is None
         and sample["worker_observation_error"] is sample["root_physical_observation_error"] is None
         and sample["minimum_free_bytes"] == plan["minimum_free_bytes"] <= sample["available_bytes"]
         and sample["maximum_root_physical_bytes"] == plan["maximum_root_physical_bytes"]
         and (not workers or worker and len(workers) == 1 and workers[0][0] == worker["pid"]),
         "bounded epoch 170 guard does not bind its live actor")
    return dict(plan=plan_ref, sample=sample_ref, timer_invocation_id=timer["InvocationID"]), bool(workers)


def terminal(actor):
    native.idle(UNIT)
    iid = actor["producer_invocation_id"]
    query = ["/usr/bin/journalctl", "--no-pager", "-q", "-o", "json", "_PID=1", "_UID=0",
             f"UNIT={UNIT}", f"INVOCATION_ID={iid}"]
    events = [json.loads(line) for line in native.command(query).splitlines()]
    event, = (value for value in events if value.get("MESSAGE_ID") == SUCCESS
              or value.get("MESSAGE_ID") == FAILURE and value.get("COMMAND") == "ExecStart")
    need(event["_BOOT_ID"] == actor["boot_id"].replace("-", "") and event["INVOCATION_ID"] == iid,
         "bounded epoch 170 terminal invocation changed")
    return event


def active(row):
    return bool(row and row["phase"] != "terminal")


def retained_population(fleet, config):
    prior = fleet.get(FIELD)
    rows = [row for row in fleet["actual_active_private_diagnostics"] if row["unit"]["Id"] == UNIT]
    assigned = [row for row in config["diagnostic_replays"] if row["producer_unit"] == UNIT]
    need(not any(row["range"] == "170" and row["producer_unit"] not in (
        UNIT, "horizon-qualify-170-checkpoint-suffix-20261127-v1.service")
        for row in config["diagnostic_replays"]), "foreign private epoch 170 assignment")
    if prior is None:
        need(not assigned and not rows, "unregistered bounded epoch 170 fleet row")
        return None
    need(prior["interface"] == INTERFACE and prior["unit"]["Id"] == UNIT
         and prior["actor_ref"] == bound(ACTOR) and prior["observer"] == fleet["observer"]
         and prior["phase"] in ("held", "bootstrap", "worker", "terminal")
         and prior["archive_publication_authorized"] is prior["canonical_replay_claimed"] is False
         and prior["resource_credit_bytes"] == 0
         and assigned == ([prior["observer_config"]] if prior["observer_config"] else [])
         and rows == ([prior] if active(prior) else []), "bounded epoch 170 crossed its fleet assignment")
    return prior


def observe(c, prior, observed_lane):
    manager = native.props(UNIT, PROPS)
    if not ACTOR.exists():
        need(prior is None and not RELEASE.exists(), "bounded epoch 170 actor evidence disappeared")
        native.idle(UNIT)
        return None
    scope = interface()
    closed = closed_comparison(scope)
    ref, actor = read_actor()
    need(not prior or prior["actor"] == actor and prior["actor_ref"] == ref,
         "bounded epoch 170 invocation changed")
    release_ref, grant = release(scope, ref, actor, closed)
    row = dict(epoch=170, unit=manager, actor=actor, actor_ref=ref, interface=INTERFACE,
               closed_comparison=closed, release=release_ref, observer=c.sample_ref, observer_config=None,
               resource_credit_bytes=0, reservation_ending_bytes=0, canonical_replay_claimed=False,
               archive_publication_authorized=False, transaction_replay_claimed=False)
    if manager["ActiveState"] in ("inactive", "failed"):
        row.update(phase="terminal", native_terminal=terminal(actor))
        need(not prior or prior["phase"] != "terminal" or row["native_terminal"] == prior["native_terminal"],
             "bounded epoch 170 terminal was replaced")
    else:
        processes, worker, phase = live(scope, manager, actor, grant is not None)
        row.update(phase=phase, processes=processes, worker=worker)
        if phase != "held":
            protection, sighted = guard(scope, actor, worker, grant)
            row.update(phase="worker" if sighted else phase, guard=protection)
            if sighted:
                log = Path(scope["log"]).lstat()
                need(stat.S_ISREG(log.st_mode) and log.st_nlink == 1, "different bounded epoch 170 log")
                iid = actor["producer_invocation_id"]
                row["observer_config"] = dict(range="170", producer_unit=UNIT, controller_unit=UNIT,
                    expected_producer_invocation_id=iid, expected_controller_invocation_id=iid,
                    scratch_path=str(Path(scope["run"]) / "scratch"), worker_executable_basename="historical-worker",
                    append_log=dict(path=scope["log"], device=log.st_dev, inode=log.st_ino))
    scheduled = [item for item in c.cfg["diagnostic_replays"] if item["producer_unit"] == UNIT]
    if scheduled:
        expected, = scheduled
        sample, = (item for item in c.sample["diagnostic_replays"] if item["producer_unit"] == UNIT)
        iid = actor["producer_invocation_id"]
        need(prior and expected == prior["observer_config"]
             and sample["expected_producer_invocation_id"] == iid and sample["scratch_path"] == expected["scratch_path"]
             and sample["status"] in ("observed", "unavailable")
             and sample["ordinary_replay_claim"] is sample["publication_authorized"] is sample["r2_mutations"] is False,
             "bounded epoch 170 observation crossed its private assignment")
        row["native_diagnostic"] = sample
        if row["phase"] == "worker" and sample["status"] == "observed":
            need(row["observer_config"] == expected
                 and all(sample["observation"][name]["pid"] == row["worker"]["pid"]
                         and sample["observation"][name]["executable"] == row["worker"]["path"]
                         for name in ("worker_before", "worker_after")),
                 "bounded epoch 170 sample does not bind its protected child")
            row["transaction_replay_claimed"] = observed_lane(
                sample["observation"], expected, iid, actor["producer_pid"])
    return row


def recheck(row):
    if not active(row):
        native.idle(UNIT)
        return
    pids = sorted(map(int, (CGROUP / "cgroup.procs").read_text().split()))
    need([process(value) for value in pids] == row["processes"] and native.props(UNIT, PROPS) == row["unit"],
         "bounded epoch 170 identity changed during the census")


def project(c, row):
    if row and row["observer_config"]:
        c.next_cfg["diagnostic_replays"].append(row["observer_config"])


def install(fleet, row):
    if not row:
        return
    fleet[FIELD] = row
    if active(row):
        need(not any(item["epoch"] == 170 for item in fleet["actual_active_private_diagnostics"]),
             "duplicate private epoch 170 owner")
        fleet["actual_active_private_diagnostics"].append(row)
        fleet["active_private_diagnostic_count"] += 1
        fleet["active_producer_count"] += 1


def enroll(api, head, writer_ref):
    scope = interface()
    closed = closed_comparison(scope)
    ref, actor = read_actor()
    fleet = checked(head)
    writer = checked(writer_ref)["new"]
    manager = native.props(writer["unit"], ("MainPID", "InvocationID", "ActiveState", "ExecStart"))
    lock = Path(f"/proc/{writer['pid']}/fd/{writer['lock']['fd']}").stat()
    need(Path(head["path"]) == max(BASE.glob("root*/ROOT_COMPLETE_OPERATIONAL_FLEET.json"),
                                   key=lambda path: path.stat().st_mtime_ns)
         and fleet["owner"] == "/root" and writer["program"] == str(api["CURRENT"])
         and manager["ActiveState"] == "active" and manager["InvocationID"] == writer["invocation_id"]
         and manager["MainPID"] == str(writer["pid"]) and writer["program"] in manager["ExecStart"]
         and native.ticks(writer["pid"]) == writer["start_ticks"]
         and (lock.st_dev, lock.st_ino) == (writer["lock"]["device"], writer["lock"]["inode"])
         and not Path(scope["barrier"]).exists() and not RELEASE.exists(),
         "bounded epoch 170 enrollment lacks the sole writer and an unreleased successor")
    _, _, phase = live(scope, native.props(UNIT, PROPS), actor, False)
    need(phase == "held", "bounded epoch 170 enrollment must precede release")
    report = dict(schema=ENROLLMENT_SCHEMA, actor=ref, interface=INTERFACE, closed_comparison=closed,
                  writer_active=writer_ref, fleet=head, enrolled=True, publication_authorized=False)
    durable(ENROLLMENT, report)
    return bound(ENROLLMENT)
