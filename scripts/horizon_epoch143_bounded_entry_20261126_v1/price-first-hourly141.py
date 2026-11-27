#!/usr/bin/python3 -B
"""Price the held epoch 141 singleton on the existing joint 170 funding."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import time

BASE = Path("/var/lib/jetstreamer/horizon_runtime_data")
AUTHORITY = BASE / "epoch141-first-hourly-20261127-v1"
SUCCESSOR = BASE / "epoch170-from-73726716-20261127-v1"
CORE = SUCCESSOR / "successor-operator-v4/successor_price.py"
CORE_SHA = "22279aee8b0bba0450a2d2503caf1f4abab96569926f12fe8f2e3a09f05c024e"
TERMINAL = SUCCESSOR / "FAILED_SUCCESSOR_NATIVE_START.json"
TERMINAL_SHA = "d81363677caab2e8789c01fd4ca6d9728d9f47f05ce57a08a9b29db7ab3d0f0a"
CONTRACT = AUTHORITY / "contract-v1/LAUNCH_PROFILE.json"
CONTRACT_SHA = "73a120db97d72a03c05c39139098a10cd6c84802f0f5472a1251f341976ce131"
UNIT = "horizon-qualify-141-first-hourly-20261127-v1.service"
TIMER = "horizon-guard-141-first-hourly-20261127-v1.timer"
GUARD_170 = "horizon-guard-170-from-73726716-20261127-v1.timer"
HOME = 47_311_749_120
RAM = 33_285_996_544
CPU = 3_000_000


def load_core():
    # The pinned, root-owned implementation performs the incumbent process, custody
    # and resource checks. Keep one source of truth for the existing 170 quote.
    stat = CORE.stat(follow_symlinks=False)
    with CORE.open("rb") as source:
        digest = hashlib.file_digest(source, "sha256").hexdigest()
    if stat.st_uid != 0 or stat.st_mode & 0o222 or digest != CORE_SHA:
        raise ValueError("joint 170 pricing implementation changed")
    spec = importlib.util.spec_from_file_location("joint_funding", CORE)
    core = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(core)
    return core


def guard(core, unit, timer, authority, native, producer_ram):
    iid = native["InvocationID"]
    pid = int(native["MainPID"])
    cgroup = f"/system.slice/{unit}"
    core.need(
        native["ActiveState"] == "active" and re.fullmatch("[0-9a-f]{32}", iid)
        and pid > 1 and native["ControlPID"] == "0" and not native["Job"]
        and native["ControlGroup"] == cgroup and native["MemoryMax"] == str(producer_ram)
        and native["MemorySwapMax"] == "0"
        and (Path(f"/proc/{pid}/cgroup").read_text().strip() == f"0::{cgroup}"),
        f"unprotected producer identity {unit}",
    )
    clock = core.state(timer, "Id,ActiveState,BindsTo,InvocationID,Job")
    sibling = core.state(timer.replace(".timer", ".service"),
                         "Id,CPUQuotaPerSecUSec,MemoryMax,MemorySwapMax")
    core.need(
        clock["ActiveState"] == "active" and clock["BindsTo"] == unit and not clock["Job"]
        and sibling["CPUQuotaPerSecUSec"] == "1s" and sibling["MemoryMax"] == str(1 << 30)
        and sibling["MemorySwapMax"] == "0",
        f"guard limits changed for {unit}",
    )
    plan, plan_ref = core.read(authority / "ACTUAL_GUARD_PLAN.json")
    samples = Path(plan["receipt_directory"])
    core.need(
        plan["unit"] == unit and plan["invocation_id"] == iid and plan["filesystem"] == "/home/sol"
        and samples.is_relative_to(authority) and samples.is_dir(),
        f"guard plan identity changed for {unit}",
    )
    sample, sample_ref = core.read(max(samples.glob("sample-*.json"), key=lambda path: path.stat().st_mtime_ns))
    core.need(
        sample["producer_invocation_id"] == iid and sample["producer"]["pid"] == pid
        and sample["plan_sha256"] == plan_ref["sha256"] and sample["producer_stop_enabled"]
        and sample["trip_reason"] is sample["root_physical_observation_error"] is sample["worker_observation_error"] is None
        and not sample["root_physical_observation"]["exceeds_budget"]
        and 0 <= time.time() - sample["recorded_unix_seconds"] <= 120
        and sample["minimum_free_bytes"] == plan["minimum_free_bytes"],
        f"fresh protective sample missing for {unit}",
    )
    return plan, sample, sample_ref, clock


def observe_successor(core):
    native = core.state(core.UNIT)
    if native["ActiveState"] == "active":
        for authority in (SUCCESSOR / "attempt-2", SUCCESSOR):
            actor_path = authority / "SUCCESSOR_ACTOR.json"
            if not actor_path.exists():
                continue
            actor, actor_ref = core.read(actor_path)
            if actor["producer_invocation_id"] != native["InvocationID"]:
                continue
            core.need(
                actor["producer_pid"] == int(native["MainPID"]) and actor["unit"] == core.UNIT
                and native["CPUQuotaPerSecUSec"] == "6s"
                and actor["boot_id"] == Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
                "wrong active 170 replacement",
            )
            plan, sample, sample_ref, clock = guard(core, core.UNIT, GUARD_170, authority, native, 48 << 30)
            cap = plan["maximum_root_physical_bytes"]
            lower = core.physical(sample)
            core.need(0 < lower <= cap <= 384 << 30, "170 guard lost the exact retained tree envelope")
            return native, {
                "actor": actor_ref, "guard_sample": sample_ref,
                "guard_timer_invocation_id": clock["InvocationID"],
                "minimum_free_bytes": plan["minimum_free_bytes"],
                "unallocated_HOME_bytes": cap - lower,
            }
        raise ValueError("active 170 replacement has no exact protected actor")
    ended, ended_ref = core.read(TERMINAL, TERMINAL_SHA)
    old = ended["exit"]
    core.inactive(core.UNIT)
    clock = core.state(GUARD_170, "Id,ActiveState,Job")
    core.need(
        ended["node_exited_before_worker"] and ended["private_segment_absent"] and ended["guard_drained"]
        and old["Id"] == core.UNIT and old["Result"] == "exit-code" and old["MainPID"] == "0"
        and old["ControlPID"] == "0" and native["InvocationID"] in ("", old["InvocationID"])
        and any(row["_PID"] == "1" and row["INVOCATION_ID"] == old["InvocationID"] for row in ended["pid1"])
        and clock["ActiveState"] == "inactive" and not clock["Job"],
        "170 has a different or undrained startup terminal",
    )
    return native, {"terminal": ended_ref, "minimum_free_bytes": 0}


def price(fleet, fleet_sha, held):
    core = load_core()
    profile, profile_ref = core.read(CONTRACT, CONTRACT_SHA)
    successor, successor_evidence = observe_successor(core)
    candidate = core.state(UNIT)
    before = core.availability()
    own_guard = None
    if held:
        core.need(candidate["InvocationID"] == held and candidate["CPUQuotaPerSecUSec"] == "2s",
                  "different 141 holder or CPU charge")
        pid = int(candidate["MainPID"])
        core.need(Path(f"/proc/{pid}/exe").samefile(AUTHORITY / "tools-v1/hold-141"),
                  "141 holder is not its sealed release gate")
        plan, _, own_guard, _ = guard(core, UNIT, TIMER, AUTHORITY, candidate, 30 << 30)
        core.need(plan["worker_root"] == profile["root_mount"] and plan["maximum_root_physical_bytes"] == 44 << 30,
                  "wrong 141 whole-tree guard")
    else:
        core.inactive(UNIT)
    joint = core.price("held" if successor["ActiveState"] == "active" else "start")
    core.need(
        joint["fleet"] == {"path": fleet, "sha256": fleet_sha}
        and joint["extra"]["reserved_141"] == profile_ref
        and joint["candidate_growth"] == 36 << 30
        and joint["resource_credit_bytes"] == 0 and joint["candidate_growth"] > 0,
        "joint funding does not bind 141 and the complete 170 replacement",
    )
    core.need(core.state(UNIT) == candidate and core.state(core.UNIT) == successor,
              "141 or 170 owner changed during price")
    after = core.availability()
    home = min(before[0], after[0], joint["available_home"])
    ram = min(before[1], after[1], joint["available_ram"])
    floors = {unit: core.bound(ref)["minimum_free_bytes"] for unit, ref in joint["guard_samples"].items()}
    if successor_evidence["minimum_free_bytes"]:
        floors[core.UNIT] = successor_evidence["minimum_free_bytes"]
    # Back out the two new whole-tree charges once. Protect every incumbent raw
    # floor beneath both allocations, including 170's still-unallocated growth.
    growth = joint["candidate_growth"]
    raw_home = joint["required_home"] - HOME - growth
    remaining_170 = successor_evidence.get("unallocated_HOME_bytes", growth)
    retained_home = max(raw_home, *floors.values()) + remaining_170
    retained_ram = joint["required_ram"] - RAM
    required_home = retained_home + HOME
    required_ram = retained_ram + RAM
    successor_capacity_ok = "actor" in successor_evidence or joint["guard_cap"] >= (
        joint["terminal_tree_bounds"][1] + growth
    )
    disk_fits = home >= required_home and successor_capacity_ok
    return {
        "schema": "horizon-epoch141-first-hourly-native-fit-v1",
        "recorded_unix_seconds": int(time.time()), "fleet": joint["fleet"],
        "held_invocation": held, "candidate_guard_sample": own_guard,
        "candidate_home_bytes": HOME, "candidate_ram_bytes": RAM, "candidate_cpu_quota_micros": CPU,
        "available_home_bytes": home, "available_ram_bytes": ram,
        "retained_required_home_bytes": retained_home, "retained_required_ram_bytes": retained_ram,
        "home_margin_bytes": home - required_home, "ram_margin_bytes": ram - required_ram,
        "disk_fits": disk_fits, "memory_fits": ram >= required_ram,
        "guard_floors_bytes": floors, "protected_170": successor_evidence,
        "unallocated_170_home_bytes": remaining_170,
        "joint_funding": joint, "resource_credit_bytes": 0, "archive_publication_authorized": False,
    }


if __name__ == "__main__":
    cli = argparse.ArgumentParser()
    cli.add_argument("fleet")
    cli.add_argument("fleet_sha")
    cli.add_argument("held_invocation", nargs="?")
    args = cli.parse_args()
    print(json.dumps(price(args.fleet, args.fleet_sha, args.held_invocation), sort_keys=True))
