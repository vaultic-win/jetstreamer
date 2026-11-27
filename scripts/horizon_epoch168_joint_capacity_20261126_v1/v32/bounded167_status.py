"""Account for the private bounded 167 invocation without reopening historical replay."""
import json
from importlib import util
from pathlib import Path
import stat
import time

from evidence import bound, checked, need
import bounded167_admission as route

FIELD = "current_bounded167_checkpoint"
ROOT = route.ROOT
UNIT = route.UNIT
INTENT = ROOT/"START_INTENT.json"
RELEASE = ROOT/"AUTHORIZED_RELEASE.json"
SCRATCH = route.OUTPUT/".historical-runtime"
SUCCESS = "7ad2d189f7e94e70a38c781354912448"
FAILURE = "98e322203f7a4ed290d09fe03c09fe15"
MANAGER = route.STATE + ("Restart", "NRestarts", "User", "Group", "KillMode")
MEMORY = 42 << 30
MEMORY_HIGH = 40 << 30


def launched_intent(reference):
    doc = checked(reference)
    need(reference["path"] == str(INTENT) and doc["epoch"] == 167
         and doc["schema"] == "horizon-epoch167-bounded-start-intent-v1"
         and doc["terminal"] == route.TERMINAL and doc["producer_unit"] == UNIT
         and doc["resource_credit_bytes"] == 0
         and doc["archive_publication_authorized"] is doc["replay_launch_authorized"] is False
         and doc["producer_memory_bytes"] == MEMORY and doc["guard_memory_bytes"] == route.GUARD_MEMORY
         and route.ORIGINAL_FLOOR <= doc["armed_floor"] and 0 < doc["bounded_cap_bytes"] <= route.CAP,
         "different admitted bounded 167 resources or historical terminal")
    seal = doc["deployment"]
    need(Path(seal["path"]).parent == route.PACKAGE, "foreign bounded producer deployment")
    image = route.present_member(seal, "replay167.py", executable=True)
    prepared = checked(doc["prepared"])
    need(image["sha256"] == prepared["gate_source_sha256"], "candidate launcher crossed the intent")
    spec = util.spec_from_file_location("admitted_bounded167", image["path"])
    reader = util.module_from_spec(spec)
    spec.loader.exec_module(reader)
    need(reader.ROOT == ROOT and reader.UNIT == UNIT and reader.TIMER == route.TIMER
         and reader.CAP == route.CAP and reader.START == route.START and reader.END == route.END
         and reader.WORKER_SHA == route.WORKER_SHA and reader.GUARD_SHA == route.GUARD_SHA
         and reader.MEMORY == MEMORY and reader.MEMORY_HIGH == MEMORY_HIGH and reader.CPU == route.CPU,
         "sealed candidate launcher changed the bounded scope")
    recovered,payload,*_ = reader.intent_data(reference, live=True)
    need(recovered == doc, "bounded 167 intent changed during inspection")
    return doc,payload,reader


def assigned(cfg):
    return [item for item in cfg["diagnostic_replays"]
            if UNIT in (item.get("producer_unit"), item.get("controller_unit"))]


def retained_population(fleet, cfg):
    """Identify only the previously admitted private row, never an ordinary 167 lane."""
    prior = fleet.get(FIELD)
    selected = [item for item in fleet["actual_active_private_diagnostics"] if item["epoch"] == 167]
    scheduled = assigned(cfg)
    need(not any(item["range"] == "167" for item in cfg["replays"]),
         "bounded 167 must not be an ordinary replay assignment")
    if prior is None:
        need(not selected and not scheduled, "bounded 167 has no accepted predecessor")
        return None
    need(prior["epoch"] == 167 and prior["unit"]["Id"] == UNIT
         and prior["historical_terminal"] == route.TERMINAL and prior["observer"] == fleet["observer"]
         and prior["archive_publication_authorized"] is prior["canonical_replay_claimed"] is False
         and prior["reservation_ending_bytes"] == prior["resource_credit_bytes"] == 0
         and prior["retained_cap_bytes"] == route.CAP
         and prior["phase"] in ("held", "bootstrap", "worker", "terminal")
         and prior["intent"] == bound(INTENT), "foreign bounded 167 predecessor")
    doc,*_ = launched_intent(prior["intent"])
    need(prior["bounded_cap_bytes"] == doc["bounded_cap_bytes"]
         and prior["armed_floor"] == doc["armed_floor"], "private 167 lost its original protection")
    terminal = prior["phase"] == "terminal"
    need(selected == ([] if terminal else [prior])
         and scheduled == ([prior["observer_config"]] if prior["observer_config"] else [])
         and (not terminal or not scheduled), "private 167 row or observer changed outside cadence")
    return None if terminal else prior


def bound_release(intent):
    ref = bound(RELEASE)
    row = checked(ref)
    actor = row["actor"]
    post_ref = row["post_guard_capacity"]
    post = checked(post_ref)
    permit = ROOT/"barrier/allow"
    meta = permit.lstat()
    data = permit.read_bytes()
    need(row["schema"] == "horizon-epoch167-bounded-authorized-release-v1" and row["intent"] == intent
         and row["archive_publication_authorized"] is False and row["resource_credit_bytes"] == 0
         and post_ref["path"] == str(ROOT/"POST_GUARD_CAPACITY.json")
         and post["schema"] == "horizon-epoch167-bounded-stage-price-v1" and post["phase"] == "post-guard"
         and post["intent"] == intent and post["actor"] == actor and post["resource_credit_bytes"] == 0
         and post["first_guard"]["sample"] == row["guard_sample"]
         and actor["unit"] == UNIT and actor["intent"] == intent
         and stat.S_ISREG(meta.st_mode) and meta.st_uid == meta.st_gid == 0
         and stat.S_IMODE(meta.st_mode) == 0o444 and meta.st_nlink == 1 and meta.st_size == 32
         and data == actor["producer_invocation_id"].encode()
         and route.digest(data) == row["permit_sha256"], "foreign bounded 167 release, first guard or permit")
    return ref, actor, post


def native_owner(manager, actor, payload, reader):
    pid = actor["producer_pid"]
    process = Path(f"/proc/{pid}")
    group = route.KERNEL/route.CGROUP.lstrip("/")
    need(manager["ActiveState"] == "active" and manager["SubState"] == "running"
         and manager["MainPID"] == str(pid) and manager["InvocationID"] == actor["producer_invocation_id"]
         and manager["ControlPID"] == "0" and manager["ControlGroup"] == route.CGROUP and not manager["Job"]
         and manager["NRestarts"] == "0" and manager["Restart"] == "no" and manager["KillMode"] == "control-group"
         and manager["User"] == "sol" and manager["Group"] == "horizon"
         and route.ticks(pid) == actor["start_ticks"], "foreign bounded 167 active native owner")
    need((process/"cmdline").read_bytes().split(b"\0")[:-1] ==
         [item.encode() for item in payload["argv"]], "bounded 167 node command changed")
    node = (process/"exe").stat()
    need(route.identity(node) == payload["files"][0]["source"]["identity"], "bounded 167 node image changed")
    reader.limits(group)
    pids = {int(value) for value in (group/"cgroup.procs").read_text().split()}
    need(pid in pids and len(pids) <= 2, "foreign member in bounded 167 cgroup")
    processes = [[pid, actor["start_ticks"], node.st_dev, node.st_ino]]
    worker = None
    for worker_pid in pids-{pid}:
        child = Path(f"/proc/{worker_pid}")
        start = route.ticks(worker_pid)
        executable = (child/"exe").resolve(strict=True)
        m = executable.stat()
        real = (child/"exe").stat()
        need(executable.name == "historical-worker" and executable.parent.name == "bound-worker"
             and executable.parent.parent.name.startswith("jetstreamer-historical-parent-")
             and executable.parent.parent.parent == SCRATCH
             and (real.st_dev, real.st_ino) == (m.st_dev, m.st_ino)
             and (child/"cgroup").read_text().strip() == f"0::{route.CGROUP}",
             "foreign bounded 167 worker executable")
        route.file_identity(executable, route.WORKER_SHA, executable=True)
        worker = dict(pid=worker_pid, start_ticks=start, path=str(executable), device=m.st_dev, inode=m.st_ino)
        processes.append([worker_pid,start,m.st_dev,m.st_ino])
    return processes, worker


def current_guard(intent, actor, post, worker):
    first = post["first_guard"]
    plan = checked(first["plan"])
    floor, cap = intent["armed_floor"], intent["bounded_cap_bytes"]
    timer = route.props(route.TIMER, ("Id", "LoadState", "InvocationID", "ActiveState", "SubState", "Job", "Triggers"))
    guard = route.props(route.GUARD_SERVICE, ("Id", "LoadState", "TriggeredBy", "ExecStart",
                                            "CPUQuotaPerSecUSec", "MemoryMax", "MemorySwapMax"))
    need(timer["InvocationID"] == first["timer_invocation_id"] and timer["ActiveState"] == "active"
         and timer["SubState"] in ("waiting", "running") and not timer["Job"]
         and timer["Triggers"] == route.GUARD_SERVICE and guard["TriggeredBy"] == route.TIMER
         and guard["CPUQuotaPerSecUSec"] == "250ms" and guard["MemoryMax"] == str(route.GUARD_MEMORY)
         and guard["MemorySwapMax"] == "0"
         and all(text in guard["ExecStart"] for text in (str(route.GUARD), route.GUARD_SHA,
                                                       first["plan"]["path"],first["plan"]["sha256"]))
         and plan["minimum_free_bytes"] == first["floor"] == floor and plan["maximum_root_physical_bytes"] == cap
         and plan["unit"] == UNIT and plan["invocation_id"] == actor["producer_invocation_id"]
         and plan["worker_root"] == str(route.LANE) and plan["filesystem"] == str(route.HOME)
         and not (ROOT/"guard-receipts/stop-intent.json").exists(), "bounded 167 lost its live protection")
    samples = sorted((ROOT/"guard-receipts").glob("sample-*.json"), key=lambda path: path.stat().st_mtime_ns)
    need(samples, "bounded 167 has no guard observations")
    sample_ref = bound(samples[-1])
    sample = checked(sample_ref)
    producer = sample["producer"]
    walked = sample["root_physical_observation"]
    lower = min(walked[key]["physical_bytes"] for key in ("first", "second"))
    protected = sample["workers"] != []
    need(sample["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
         and sample_ref["path"] == str(ROOT/"guard-receipts"/f"sample-{sample['guard_invocation_id']}.json")
         and sample["plan"] == first["plan"]["path"] and sample["plan_sha256"] == first["plan"]["sha256"]
         and sample.get("guard_sha256", sample.get("self_sha256")) == route.GUARD_SHA
         and sample["producer_invocation_id"] == producer["invocation_id"] == actor["producer_invocation_id"]
         and producer["pid"] == actor["producer_pid"] and producer["cgroup"] == route.CGROUP
         and producer["active"] == "active" and producer["restarts"] == 0
         and first["recorded_unix_seconds"] <= sample["recorded_unix_seconds"]
         and 0 <= time.time()-sample["recorded_unix_seconds"] <= route.MAX_AGE
         and sample["producer_stop_enabled"] is True and sample["trip_reason"] is None
         and sample["worker_observation_error"] is sample["root_physical_observation_error"] is None
         and sample["minimum_free_bytes"] == floor and sample["maximum_root_physical_bytes"] == cap
         and sample["available_bytes"] >= floor and walked["exceeds_budget"] is False
         and all(walked[key]["vanished_entries"] == 0 and 0 < walked[key]["physical_bytes"] <= cap
                 for key in ("first","second"))
         and (not protected or worker and len(sample["workers"]) == 1
              and sample["workers"][0][0] == worker["pid"] and 0 < sample["workers"][0][1] <= route.MAX_VMAS),
         "foreign or unprotected bounded 167 guard observation")
    return dict(plan=first["plan"], sample=sample_ref, timer_invocation_id=timer["InvocationID"],
                floor=floor, physical_bytes=lower, bounded_cap_bytes=cap), protected


def terminal(actor, manager):
    route.idle(UNIT)
    iid = actor["producer_invocation_id"]
    raw = route.command(["/usr/bin/journalctl","--no-pager","-q","-o","json",
                         "_PID=1","_UID=0",f"UNIT={UNIT}",f"INVOCATION_ID={iid}"])
    rows = [json.loads(line) for line in raw.splitlines()]
    events = [row for row in rows if row.get("MESSAGE_ID") == SUCCESS or
              row.get("MESSAGE_ID") == FAILURE and row.get("COMMAND") == "ExecStart"]
    need(len(events) == 1, "bounded 167 lacks one native PID1 exit")
    event = events[0]
    need(event["_PID"] == "1" and event["_UID"] == "0" and event["UNIT"] == UNIT
         and event["INVOCATION_ID"] == iid and event["_BOOT_ID"] == actor["boot_id"].replace("-", "")
         and int(event["__REALTIME_TIMESTAMP"]) >= actor["ready_at"]*1_000_000
         and manager["MainPID"] == manager["ControlPID"] == "0" and not manager["Job"],
         "foreign bounded 167 native terminal")
    return event


def sample_row(c, row, prior, observed_lane):
    selected = assigned(c.cfg)
    if not selected:
        return None, False
    need(prior is not None and selected == [prior["observer_config"]], "bounded 167 observer assignment changed")
    expected = selected[0]
    result, = (item for item in c.sample["diagnostic_replays"] if item["range"] == "167")
    actor = row["actor"]
    iid = actor["producer_invocation_id"]
    need(result["producer_unit"] == UNIT and result["expected_producer_invocation_id"] == iid
         and result["scratch_path"] == expected["scratch_path"]
         and result["status"] in ("observed", "unavailable")
         and result["ordinary_replay_claim"] is result["publication_authorized"] is result["r2_mutations"] is False,
         "foreign bounded 167 native sample")
    if row["phase"] == "terminal" or result["status"] == "unavailable":
        return result, False
    worker = row["worker"]
    sample = result["observation"]
    need(row["phase"] == "worker" and row["observer_config"] == expected
         and all(sample[key]["pid"] == worker["pid"] and sample[key]["executable"] == worker["path"]
                 for key in ("worker_before", "worker_after")), "bounded sample crossed its protected worker")
    return result, observed_lane(sample, expected, iid, actor["producer_pid"])


def observe(c, observed_lane):
    prior = c.fleet.get(FIELD)
    retained_population(c.fleet, c.cfg)
    manager = route.props(UNIT, MANAGER)
    idle = manager["ActiveState"] in ("inactive","failed")
    if not INTENT.exists():
        need(prior is None and idle and not RELEASE.exists(), "bounded 167 lost its admitted start intent")
        route.idle(UNIT)
        return None
    intent = bound(INTENT)
    doc,payload,reader = launched_intent(intent)
    if idle and not prior and not RELEASE.exists():
        route.idle(UNIT)
        return None
    release, post = None, None
    if route.permit_exists():
        release, actor, post = bound_release(intent)
    elif idle:
        actor = prior["actor"]
    else:
        actor = reader.native_owner(intent)
    need(not prior or prior["intent"] == intent and prior["actor"] == actor,
         "bounded 167 changed its admitted producer incarnation")
    row = dict(epoch=167, unit=manager, actor=actor, intent=intent, release=release, observer=c.sample_ref,
               observer_config=None, historical_terminal=route.TERMINAL, retained_cap_bytes=route.CAP,
               bounded_cap_bytes=doc["bounded_cap_bytes"], armed_floor=doc["armed_floor"],
               resource_credit_bytes=0, reservation_ending_bytes=0, canonical_replay_claimed=False,
               archive_publication_authorized=False)
    if idle:
        row.update(phase="terminal", native_terminal=terminal(actor,manager))
        need(not prior or prior["phase"] != "terminal" or row["native_terminal"] == prior["native_terminal"],
             "bounded 167 terminal changed")
    elif release is None:
        need(not prior or prior["phase"] == "held", "bounded 167 returned to the hold gate")
        row.update(phase="held", processes=actor["processes"], worker=None)
    else:
        need(not prior or prior["phase"] != "terminal", "terminal private replay regained an actor")
        members, worker = native_owner(manager, actor, payload, reader)
        guard, sighted = current_guard(doc,actor,post,worker)
        row.update(phase="worker" if sighted else "bootstrap", processes=members, worker=worker, guard=guard)
        if sighted:
            iid = actor["producer_invocation_id"]
            row["observer_config"] = dict(range="167", producer_unit=UNIT, controller_unit=UNIT,
                                          expected_producer_invocation_id=iid,
                                          expected_controller_invocation_id=iid, scratch_path=str(SCRATCH),
                                          worker_executable_basename="historical-worker", append_log=route.private_log())
    sample, advancing = sample_row(c,row,prior,observed_lane)
    return dict(row, native_diagnostic=sample, transaction_replay_claimed=advancing)


def active(row):
    return bool(row and row["phase"] != "terminal")


def recheck(row):
    if not active(row):
        route.idle(UNIT)
        return
    members = (route.KERNEL/route.CGROUP.lstrip("/")/"cgroup.procs").read_text().split()
    need({int(pid) for pid in members} == {p[0] for p in row["processes"]}
         and route.props(UNIT, MANAGER) == row["unit"], "bounded 167 population changed during census")
    for pid,ticks,device,inode in row["processes"]:
        binary = (Path(f"/proc/{pid}")/"exe").stat()
        need(route.ticks(pid) == ticks and (binary.st_dev,binary.st_ino) == (device,inode),
             "bounded 167 execution identity changed during census")


def project(c, row):
    keep = [item for item in c.next_cfg["diagnostic_replays"]
            if UNIT not in (item.get("producer_unit"), item.get("controller_unit"))]
    if row and row["observer_config"]:
        need(not any(item["range"] == "167" for item in keep), "duplicate bounded diagnostic range")
        keep.append(row["observer_config"])
    c.next_cfg["diagnostic_replays"] = keep


def install(fleet, row):
    if row is None:
        return
    fleet[FIELD] = row
    if active(row):
        need(not any(item["epoch"] == 167 for item in fleet["actual_active_private_diagnostics"]),
             "duplicate bounded 167 private roster")
        fleet["actual_active_private_diagnostics"].append(row)
        fleet["active_private_diagnostic_count"] += 1
        fleet["active_producer_count"] += 1
