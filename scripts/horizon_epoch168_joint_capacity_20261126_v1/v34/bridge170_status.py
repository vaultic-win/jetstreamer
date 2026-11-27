"""Read the exact bounded epoch 170 bridge in the existing private diagnostic cadence."""
import json
from pathlib import Path
import re
import stat
import time

from evidence import BASE, bound, checked, need
import bounded167_admission as native

FIELD = "current_private170_checkpoint_bridge"
ROOT = BASE/"epoch170-storage-witness-recovery-20261127-v1/suffix-run-v1"
INTERFACE = {
    "path":str(ROOT/"BRIDGE_ADMISSION_INTERFACE.json"),
    "sha256":"3bdb3395dabfcf60c4018618ea77cef2392016818f9268f10fc5e8ebf26da7ac",
}
ACTOR = ROOT/"BRIDGE_ACTOR.json"
RELEASE = ROOT/"BRIDGE_RELEASE.json"
UNIT = "horizon-qualify-170-checkpoint-suffix-20261127-v1.service"
GUARD_TIMER = "horizon-guard-170-checkpoint-suffix-20261127-v1.timer"
GUARD_UNIT = GUARD_TIMER.replace(".timer",".service")
GROUP = "/system.slice/"+UNIT
CGROUP = Path("/sys/fs/cgroup")/GROUP.lstrip("/")
GATE = "/run/horizon-170-checkpoint-suffix-v1/bridge-gate"
PROPS = native.STATE+("User","Group","Restart","NRestarts","KillMode","MemoryMax","MemorySwapMax","CPUQuotaPerSecUSec")
SUCCESS = "7ad2d189f7e94e70a38c781354912448"
FAILURE = "98e322203f7a4ed290d09fe03c09fe15"


def interface():
    basis = checked(INTERFACE)
    need(basis["schema"] == "epoch170-bridge-73726716-admission-interface-v1"
         and basis["epoch"] == 170 and basis["producer_unit"] == UNIT
         and basis["guard_timer"] == GUARD_TIMER and basis["guard_unit"] == GUARD_UNIT
         and basis["verify_post_bootstrap"] == [73713261,73726716]
         and basis["producer_cpu_quota_micros"] == 6000000 and basis["producer_ram_bytes"] == 48<<30
         and basis["guard_cpu_quota_micros"] == 1000000 and basis["guard_ram_bytes"] == 1<<30
         and basis["resource_promise_ending_bytes"] == 0 and basis["replay_launch_authorized"] is False,
         "foreign bridge 170 interface")
    return basis


def retained_population(fleet, cfg):
    prior = fleet.get(FIELD)
    assigned = [row for row in cfg["diagnostic_replays"] if row["range"] == "170"]
    rows = [row for row in fleet["actual_active_private_diagnostics"] if row["epoch"] == 170]
    need(not any(row["range"] == "170" for row in cfg["replays"]), "170 bridge is private")
    if prior is None:
        need(not assigned and not rows, "unregistered private 170 owner")
        return None
    need(prior["interface"] == INTERFACE and prior["unit"]["Id"] == UNIT
         and prior["observer"] == fleet["observer"] and prior["actor_ref"] == bound(ACTOR)
         and prior["phase"] in ("held","bootstrap","worker","terminal")
         and prior["archive_publication_authorized"] is prior["canonical_replay_claimed"] is False
         and prior["resource_credit_bytes"] == 0
         and assigned == ([prior["observer_config"]] if prior["observer_config"] else [])
         and rows == ([prior] if active(prior) else []),
         "170 bridge does not follow the sole accepted private roster")
    return prior


def read_actor():
    ref = bound(ACTOR)
    row = checked(ref)
    need(row["schema"] == "horizon-epoch170-bridge-actor-v1" and row["interface"] == INTERFACE
         and row["unit"] == UNIT and row["producer_pid"] > 1 and row["start_ticks"] > 0
         and re.fullmatch("[0-9a-f]{32}",row["producer_invocation_id"])
         and row["producer_invocation_id"] != "0"*32
         and row["boot_id"] == Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
         "foreign epoch 170 bridge actor")
    return ref,row


def release_proof(scope, actor_ref, actor):
    barrier=Path(scope["barrier"])
    permit=barrier.lstat()
    iid=actor["producer_invocation_id"]
    ref=bound(RELEASE)
    release=checked(ref)
    plan_ref=release["guard_plan"]
    plan=checked(plan_ref)
    guard_sample=checked(release["first_guard_sample"])
    need(release["schema"] == "horizon-epoch170-bridge-release-v1" and release["interface"] == INTERFACE
         and release["actor"] == actor_ref and release["producer_invocation_id"] == iid
         and release["resource_credit_bytes"] == 0 and release["archive_publication_authorized"] is False
         and stat.S_ISREG(permit.st_mode) and stat.S_IMODE(permit.st_mode) == 0o444 and permit.st_nlink == 1
         and permit.st_uid == permit.st_gid == 0 and barrier.read_bytes() == iid.encode()
         and plan["unit"] == UNIT and plan["invocation_id"] == iid
         and plan["worker_root"] == scope["guard_root"] and plan["filesystem"] == scope["protected_filesystem"]
         and plan["receipt_directory"] == scope["guard_receipts"] and 0 < plan["maximum_root_physical_bytes"] <= 384<<30
         and plan["minimum_free_bytes"] >= scope["minimum_historical_floor"]
         and guard_sample["plan_sha256"] == plan_ref["sha256"] and guard_sample["producer_invocation_id"] == iid
         and guard_sample["producer"]["pid"] == actor["producer_pid"] and guard_sample["trip_reason"] is None
         and guard_sample["producer_stop_enabled"] is True,
         "foreign bridge epoch 170 release, guard or permit")
    return ref,release,plan


def process(pid):
    proc=Path("/proc")/str(pid)
    executable=(proc/"exe").stat()
    need((proc/"cgroup").read_text().strip() == f"0::{GROUP}", "bridge 170 process left its cgroup")
    return [pid,native.ticks(pid),executable.st_dev,executable.st_ino]


def live_owner(scope, manager, actor, released):
    pid=actor["producer_pid"]
    proc=Path("/proc")/str(pid)
    need(manager["ActiveState"] == "active" and manager["SubState"] == "running"
         and manager["InvocationID"] == actor["producer_invocation_id"] and manager["MainPID"] == str(pid)
         and manager["ControlGroup"] == GROUP and manager["ControlPID"] == "0" and not manager["Job"]
         and manager["NRestarts"] == "0" and manager["Restart"] == "no" and manager["KillMode"] == "control-group"
         and manager["User"] == "sol" and manager["Group"] == "horizon"
         and manager["MemoryMax"] == str(scope["producer_ram_bytes"]) and manager["CPUQuotaPerSecUSec"] == "6s"
         and manager["MemorySwapMax"] == "0" and native.ticks(pid) == actor["start_ticks"],
         "foreign live bridge 170 actor")
    pids={int(p) for p in (CGROUP/"cgroup.procs").read_text().split()}
    need(pid in pids and len(pids) <= (2 if released else 1), "foreign bridge 170 cgroup process")
    exe=proc/"exe"
    if not released:
        need(exe.samefile(scope["gate"]["path"]) and
             (proc/"cmdline").read_bytes().split(b"\0") == [GATE.encode(),b""], "different bridge 170 hold")
    else:
        argv=(proc/"cmdline").read_bytes().split(b"\0")
        need(exe.samefile(scope["node"]["path"]) and any(str(scope["output"]).encode() in arg for arg in argv)
             and any(b"73726716" in arg for arg in argv), "bridge node command crossed the bounded output")
    worker=None
    if pids-{pid}:
        child_pid,=pids-{pid}
        child=Path("/proc")/str(child_pid)
        binary=(child/"exe").resolve(strict=True)
        need(binary.name == "historical-worker" and binary.is_relative_to(Path(scope["run"]))
             and (child/"exe").samefile(binary), "foreign bridge 170 worker")
        native.file_identity(binary,scope["worker_sha256"],executable=True)
        worker=dict(pid=child_pid,path=str(binary),start_ticks=native.ticks(child_pid))
    return [process(value) for value in sorted(pids)], worker


def protection(scope, release, plan, actor, worker):
    timer=native.props(GUARD_TIMER,("Id","InvocationID","ActiveState","SubState","Job","Triggers"))
    unit=native.props(GUARD_UNIT,("Id","TriggeredBy","ExecStart","MemoryMax","MemorySwapMax","CPUQuotaPerSecUSec"))
    need(timer["ActiveState"] == "active" and timer["SubState"] in ("waiting","running")
         and timer["InvocationID"] == release["guard_timer_invocation_id"] and not timer["Job"]
         and timer["Triggers"] == GUARD_UNIT and unit["TriggeredBy"] == GUARD_TIMER
         and unit["MemoryMax"] == str(scope["guard_ram_bytes"]) and unit["MemorySwapMax"] == "0"
         and unit["CPUQuotaPerSecUSec"] == "1s"
         and all(item in unit["ExecStart"] for item in (scope["guard"]["path"],scope["guard"]["sha256"],
                 release["guard_plan"]["path"],release["guard_plan"]["sha256"])), "bridge 170 lost its protective timer")
    receipts=Path(scope["guard_receipts"])
    chosen=max(receipts.glob("sample-*.json"),key=lambda path:path.stat().st_mtime_ns)
    sample_ref=bound(chosen)
    sample=checked(sample_ref)
    scoped=sample["workers"]
    need(sample["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
         and chosen.name == f"sample-{sample['guard_invocation_id']}.json"
         and sample["plan_sha256"] == release["guard_plan"]["sha256"]
         and sample["producer_invocation_id"] == sample["producer"]["invocation_id"] == actor["producer_invocation_id"]
         and sample["producer"]["pid"] == actor["producer_pid"] and sample["producer"]["active"] == "active"
         and sample["producer"]["cgroup"] == GROUP and sample["producer"]["restarts"] == 0
         and 0 <= time.time()-sample["recorded_unix_seconds"] <= 120
         and sample["producer_stop_enabled"] is True and sample["trip_reason"] is None
         and sample["worker_observation_error"] is sample["root_physical_observation_error"] is None
         and sample["minimum_free_bytes"] == plan["minimum_free_bytes"] and sample["available_bytes"] >= plan["minimum_free_bytes"]
         and sample["maximum_root_physical_bytes"] == plan["maximum_root_physical_bytes"]
         and (not scoped or worker and len(scoped) == 1 and scoped[0][0] == worker["pid"]),
         "bridge 170 native guard sample crosses its live actor")
    return dict(plan=release["guard_plan"],sample=sample_ref,timer_invocation_id=timer["InvocationID"]),bool(scoped)


def terminal(actor):
    native.idle(UNIT)
    iid=actor["producer_invocation_id"]
    query=["/usr/bin/journalctl","--no-pager","-q","-o","json","_PID=1","_UID=0",f"UNIT={UNIT}",f"INVOCATION_ID={iid}"]
    rows=[json.loads(line) for line in native.command(query).splitlines()]
    endings=[row for row in rows if row.get("MESSAGE_ID") == SUCCESS
             or row.get("MESSAGE_ID") == FAILURE and row.get("COMMAND") == "ExecStart"]
    need(len(endings) == 1 and endings[0]["_BOOT_ID"] == actor["boot_id"].replace("-",""),
         "bridge 170 lacks its exact PID1 exit")
    return endings[0]


def observe(c, prior, observed_lane):
    scope=interface()
    manager=native.props(UNIT,PROPS)
    idle=manager["ActiveState"] in ("inactive","failed")
    if not ACTOR.exists():
        need(prior is None and idle and not RELEASE.exists(), "unregistered bridge 170 invocation")
        native.idle(UNIT)
        return None
    ref,actor=read_actor()
    need(not prior or prior["actor"] == actor and prior["actor_ref"] == ref,
         "bridge 170 invocation changed")
    row=dict(epoch=170,unit=manager,actor=actor,actor_ref=ref,interface=INTERFACE,release=None,
             observer=c.sample_ref,observer_config=None,resource_credit_bytes=0,reservation_ending_bytes=0,
             canonical_replay_claimed=False,archive_publication_authorized=False,transaction_replay_claimed=False)
    released=Path(scope["barrier"]).is_file()
    if released:
        release_ref,release,plan=release_proof(scope,ref,actor)
        row["release"]=release_ref
    if idle:
        row.update(phase="terminal",native_terminal=terminal(actor))
        need(not prior or prior["phase"] != "terminal" or row["native_terminal"] == prior["native_terminal"],
             "bridge 170 terminal was replaced")
    else:
        processes,worker=live_owner(scope,manager,actor,released)
        row.update(phase="held",processes=processes,worker=worker)
        if released:
            guard,sighted=protection(scope,release,plan,actor,worker)
            row.update(phase="worker" if sighted else "bootstrap",guard=guard,release=release_ref)
            if sighted:
                log=Path(scope["log"]).lstat()
                need(stat.S_ISREG(log.st_mode) and log.st_nlink == 1,"different bridge 170 append log")
                iid=actor["producer_invocation_id"]
                row["observer_config"]=dict(range="170",producer_unit=UNIT,controller_unit=UNIT,
                    expected_producer_invocation_id=iid,expected_controller_invocation_id=iid,
                    scratch_path=scope["scratch"],worker_executable_basename="historical-worker",
                    append_log=dict(path=scope["log"],device=log.st_dev,inode=log.st_ino))
    scheduled=[item for item in c.cfg["diagnostic_replays"] if item["range"] == "170"]
    if scheduled:
        expected,=scheduled
        sample,=(item for item in c.sample["diagnostic_replays"] if item["range"] == "170")
        iid=actor["producer_invocation_id"]
        need(prior and expected == prior["observer_config"] and sample["producer_unit"] == UNIT
             and sample["expected_producer_invocation_id"] == iid and sample["scratch_path"] == expected["scratch_path"]
             and sample["status"] in ("observed","unavailable")
             and sample["ordinary_replay_claim"] is sample["publication_authorized"] is sample["r2_mutations"] is False,
             "bridge 170 observation crosses its private assignment")
        row["native_diagnostic"]=sample
        if row["phase"] == "worker" and sample["status"] == "observed":
            need(row["observer_config"] == expected
                 and all(sample["observation"][name]["pid"] == worker["pid"] and
                         sample["observation"][name]["executable"] == worker["path"] for name in ("worker_before","worker_after")),
                 "bridge 170 sample does not bind its protected child")
            row["transaction_replay_claimed"]=observed_lane(sample["observation"],expected,iid,actor["producer_pid"])
    return row


def active(row):
    return bool(row and row["phase"] != "terminal")


def recheck(row):
    if not active(row):
        native.idle(UNIT)
        return
    pids=sorted(map(int,(CGROUP/"cgroup.procs").read_text().split()))
    need([process(value) for value in pids] == row["processes"] and native.props(UNIT,PROPS) == row["unit"],
         "bridge 170 process identity changed during census")


def project(c,row):
    config=[item for item in c.next_cfg["diagnostic_replays"] if item["range"] != "170"]
    if row and row["observer_config"]:
        config.append(row["observer_config"])
    c.next_cfg["diagnostic_replays"]=config


def install(fleet,row):
    if not row:
        return
    fleet[FIELD]=row
    if active(row):
        need(not any(item["epoch"] == 170 for item in fleet["actual_active_private_diagnostics"]),
             "duplicate bridge 170 row")
        fleet["actual_active_private_diagnostics"].append(row)
        fleet["active_private_diagnostic_count"] += 1
        fleet["active_producer_count"] += 1
