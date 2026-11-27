"""Join the funded split-scratch 169 actor to the native fleet and its single observer."""
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path
import runpy
import time

HERE = Path(__file__).resolve().parent
actor = runpy.run_path(str(HERE / "actor.py"))
scratch = runpy.run_path(str(HERE / "scratch_mount.py"))
BASE, UNIT, TIMER = (actor[k] for k in ("BASE", "UNIT", "TIMER"))
SEED, TREE, GUARD_SHA = (actor[k] for k in ("SEED", "TREE", "GUARD_SHA"))
need = actor["need"]
OUTPUT = scratch["OUTPUT_ALLOWANCE"]
CONTROL = scratch["CONTROL_ALLOWANCE"]
FIELD = "current_private169_hourly"
OLD_IID = "0dfa0d36fbc246c28443a1c90a82c9cb"
OLD_TERMINAL = "218954bde25b9176b8063c1555dfcff29e91d5f42281198d3dbf5484ee98c6f5"


def check_fleet(fleet, row, paid):
    peers = fleet["actual_executing_replays"] + fleet["actual_active_bootstraps"]
    private = fleet["actual_active_private_diagnostics"]
    need(not any(p["epoch"] == 169 for p in peers), "canonical 169 competes for the private booking")
    registered = [p for p in private if p["epoch"] == 169]
    need((registered == [row] if row and row["phase"] != "terminal" else not registered)
         and fleet["focused169_terminal"]["sha256"] == OLD_TERMINAL
         and not fleet["all_reservation_ending_bytes"] and not fleet["resource_credit_bytes"],
         "missing retained private closure or changed 169 enrollment")
    if row and paid:
        need(row["hourly169_start_intent"] == paid["intent"]
             and row["unit"]["Id"] == UNIT and row["unit"]["InvocationID"] == paid["producer_iid"]
             and int(row["unit"]["MainPID"]) == paid["processes"][0][0],
             "169 fleet row does not match the observed actor")


def price_guard(binding, sample, now):
    plan = actor["pinned"](binding["plan"])
    need(plan["unit"] == UNIT and plan["invocation_id"] == binding["producer_iid"]
         and plan["worker_root"] == str(TREE) and plan["filesystem"] == "/home/sol"
         and plan["maximum_worker_vmas"] == 3_500_000
         and plan["maximum_root_physical_bytes"] == binding["initial_physical"] + OUTPUT,
         "wrong disk scope for the 169 scratch allocation")
    cap = plan["maximum_root_physical_bytes"]
    need(sample["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
         and sample["guard_sha256"] == GUARD_SHA and sample["plan_sha256"] == binding["plan"]["sha256"]
         and sample["producer_invocation_id"] == binding["producer_iid"]
         and sample["producer"]["pid"] == binding["processes"][0][0] and sample["producer_stop_enabled"]
         and not sample["trip_reason"] and not sample["worker_observation_error"]
         and not sample["root_physical_observation_error"] and 0 <= now - sample["recorded_unix_seconds"] <= 90
         and sample["minimum_free_bytes"] == plan["minimum_free_bytes"]
         and sample["maximum_root_physical_bytes"] == cap and sample["available_bytes"] >= plan["minimum_free_bytes"],
         "expired, tripped, or unbound 169 guard")
    obs = sample["root_physical_observation"]
    need(obs["maximum_physical_bytes"] == cap and not obs["exceeds_budget"], "169 disk cap tripped")
    walks = [obs[x] for x in ("first", "second")]
    size = [p["physical_bytes"] for p in walks]
    need(all(binding["initial_physical"] <= v <= cap for v in size), "169 HOME source changed or cap exceeded")
    low = min(size) if all(p["vanished_entries"] == 0 for p in walks) else binding["initial_physical"]
    return dict(floor=plan["minimum_free_bytes"], maximum=cap, remaining=cap-low, fixed_control=CONTROL)


def receipt(path):
    with Path(path).open("rb") as f:
        digest = hashlib.file_digest(f, "sha256").hexdigest()
    ref = {"path": str(path), "sha256": digest}
    return actor["pinned"](ref), ref


def pid1_terminal(iid, boot):
    need(re.fullmatch(r"[a-f0-9]{32}", iid) and int(iid, 16)
         and re.fullmatch(r"[a-f0-9]{32}", boot), "invalid terminal invocation")
    watch = runpy.run_path(str(HERE / "watch.py"))
    command = ["/usr/bin/journalctl", "--no-pager", "-o", "json", "_PID=1", "_UID=0",
               "_BOOT_ID=" + boot, "UNIT=" + UNIT, "INVOCATION_ID=" + iid]
    rows = [json.loads(line) for line in subprocess.check_output(command, timeout=15).splitlines()]
    return watch["manager_result"](rows, iid, boot)


def current(fleet):
    row = fleet.get(FIELD)
    check_fleet(fleet, row, None)
    props = actor["props"](UNIT, ["Id", "ActiveState", "SubState", "MainPID", "ControlPID",
                                 "ControlGroup", "InvocationID", "Job", "NRestarts"])
    if props["ActiveState"] in ("inactive", "failed"):
        need(props["Id"] == UNIT and props["MainPID"] == props["ControlPID"] == "0" and
             not props["ControlGroup"] and not props["Job"] and
             not (Path("/sys/fs/cgroup/system.slice") / UNIT / "cgroup.procs").exists(),
             "169 terminal still owns a native cgroup")
        end = BASE / "results/TERMINAL.json"
        grant = BASE / "GRANT.json"
        if not SEED.exists() and not end.exists():
            need(not row and not grant.exists(), "169 grant or observer lacks first-guard evidence")
            return None
        terminal, proof = receipt(end)
        if SEED.exists():
            intent, start = receipt(SEED)
            iid, boot = intent["producer_invocation_id"], intent["boot_id"].replace("-", "")
        else:
            # Recovery from a systemd setup or gate failure before the first sample.
            attempt, start = receipt(BASE / "HELD_GATE.json")
            iid, boot = attempt["invocation_id"], attempt["boot_id"].replace("-", "")
            need(attempt["unit"] == UNIT and not grant.exists(), "different early gate")
        need(props["InvocationID"] in ("", iid) and boot == Path("/proc/sys/kernel/random/boot_id").read_text().strip().replace("-", "")
             and not terminal["canonical_publication_authorized"], "different private terminal")
        manager = pid1_terminal(iid, boot)
        if terminal["disposition"] == "private-payload-never-released":
            need(not grant.exists() and manager in ("failure", "interrupted"), "release or unexpected successful gate")
        else:
            released, grant_ref = receipt(grant)
            need(terminal["unit"] == UNIT and terminal["invocation_id"] == released["invocation_id"] == iid
                 and terminal["boot_id"] == boot and not terminal["resource_credit_bytes"]
                 and terminal["grant_sha256"] == grant_ref["sha256"], "unbound private result")
        return dict(epoch=169, phase="terminal", unit=props, hourly169_start_intent=start,
                    invocation_id=iid, pid1_result=manager, terminal=proof, canonical_replay_claimed=False,
                    archive_publication_authorized=False, resource_credit_bytes=0)
    need(props["ActiveState"] == "active" and props["SubState"] == "running", "169 is changing state")
    paid = actor["before"](fleet, row, split_scratch=True)
    check_fleet(fleet, row, paid)
    sample, guard = actor["newest_guard"](paid)
    disk = price_guard(paid, sample, time.time())
    paired = paid["processes"]
    if paid["held"]:
        need(len(paired) == 1 and not sample["workers"], "held 169 already has a worker")
    if len(paired) == 2:
        need(all(w[0] == paired[1][0] and 0 < w[1] <= 3_500_000 for w in sample["workers"])
             and len(sample["workers"]) <= 1, "169 guard saw a different worker")
    guarded_worker = len(paired) == 2 and bool(sample["workers"])
    phase = "held" if paid["held"] else "worker" if guarded_worker else "bootstrap"
    return dict(epoch=169, phase=phase, unit=props, processes=paired, start_ticks=paired[0][1],
                hourly169_start_intent=paid["intent"], guard=guard, guard_plan=paid["plan"],
                binding=paid, disk=disk, canonical_replay_claimed=False,
                archive_publication_authorized=False, resource_credit_bytes=0)


def recheck(fleet, row):
    now = current(fleet)
    if row is None or now is None:
        need(row is now, "169 crossed enrollment")
        return
    for key in ("phase", "unit", "hourly169_start_intent", "processes", "binding", "terminal"):
        need(row.get(key) == now.get(key), "169 crossed native identity during pricing")


def charge(base, row):
    """Add the live 169 HOME obligation once to the historical and guard-floor screens."""
    if not row or row["phase"] == "terminal":
        return base
    need("split169" not in base and row["disk"]["fixed_control"] == CONTROL and
         0 <= row["disk"]["remaining"] <= OUTPUT, "duplicate or unbounded 169 charge")
    extra = row["disk"]["remaining"] + CONTROL
    required = max(base["required_home"], row["disk"]["floor"]) + extra
    historic = base["historical_home_margin"] - extra
    return dict(base, split169=row, required_home=required, historical_home_margin=historic,
                home_margin=min(historic, base["available_home"]-required))
