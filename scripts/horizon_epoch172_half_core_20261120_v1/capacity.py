"""Native, read-only complete fit for the five current replay owners plus full 172."""
import json
import os
import time
from pathlib import Path

from profile import (ACTOR_BYTES, AUDIT_SHA, BASE, CAP, GIB, GUARD_BYTES, LANE, PACKAGE, RUNTIME,
                     UNIT, bound, checked, digest, native, need, reference, run, ticks)

POST169 = RUNTIME / "epoch169-focused-admission-20261120-v4/POST_GUARD_CAPACITY.json"
POST169_SHA = "803bb540a6601238e8754c733a8cf900a9b6d103116ad6dac50bdcc2a081defc"
GUARD169 = POST169.parent / "ACTUAL_GUARD_PLAN.json"
GUARD169_SHA = "3ddbafe25e1b5df2498d86b629ce6411e47c116b4377035f3a6690a504e1aa58"
ORIGINAL = Path("/home/sol/.jetstreamer-private/epoch172-independent-singleton-20261110-v1")
BOOK_MEMORY_SHA = "efbe47079e71036423cc8bd5acfb5dbaf8ee841320c77701837e10dc6607f62c"
PRODUCER_QUOTAS = {166:"9s", 167:"9s", 168:"9s", 169:"3s", 170:"9s"}


def du(path):
    size, name = run("/usr/bin/nice", "-n", "12", "/usr/bin/ionice", "-c", "3", "/usr/bin/du",
                     "-sx", "--block-size=1", "--", path, timeout=45).rstrip().split("\t")
    need(name == str(path), "unexpected du target")
    return int(size)


def available():
    mem = dict((l.split()[0][:-1], int(l.split()[1]) * 1024) for l in
               Path("/proc/meminfo").read_text().splitlines() if l.endswith(" kB"))
    fs = os.statvfs("/home/sol")
    return mem["MemTotal"], mem["MemAvailable"], fs.f_bavail * fs.f_frsize


def owner_snapshot(fleet, own_iid):
    rows = fleet["actual_executing_replays"] + fleet["actual_active_private_diagnostics"]
    need(fleet["actual_active_bootstraps"] == [] and sorted(v["epoch"] for v in rows) == sorted(PRODUCER_QUOTAS),
         "different peer topology requires a fresh fit")
    running = run("/usr/bin/systemctl", "list-units", "--state=running", "--plain", "--no-legend",
                  "--no-pager", "horizon-qualify*.service")
    ids = {x.split()[0] for x in running.splitlines() if x.strip()}
    need(ids == {x["unit"]["Id"] for x in rows} | ({UNIT} if own_iid else set()), "unaccounted replay unit")
    if own_iid:
        own = native(UNIT)
        need(own["InvocationID"] == own_iid and own["CPUQuotaPerSecUSec"] == "500ms"
             and int(own["MemoryMax"]) == ACTOR_BYTES, "candidate native bounds")
    result = {}
    for row in rows:
        e, old = row["epoch"], row["unit"]
        now = native(old["Id"])
        need(now["ActiveState"] == "active" and now["SubState"] == "running" and now["Job"] == ""
             and now["NRestarts"] == "0" and all(now[k] == old[k] for k in ["Id","MainPID","InvocationID"])
             and now["CPUQuotaPerSecUSec"] == PRODUCER_QUOTAS[e] and int(now["MemoryMax"]) == ACTOR_BYTES,
             f"epoch {e} service changed")
        main_pid = int(now["MainPID"])
        started = int(old.get("MainStartTicks") or row["native_start_ticks"])
        need(ticks(main_pid) == started, f"epoch {e} PID changed")
        if "guard_protection" in row:
            protection = bound(row["guard_protection"])
            guard_name, timer_id = protection["timer_unit"], protection["timer_invocation_id"]
        else:
            guard_name, timer_id = row["guard_timer"]["Id"], row["guard_timer"]["InvocationID"]
        timer = native(guard_name)
        guard = native(guard_name.removesuffix(".timer") + ".service")
        need(timer["ActiveState"] == "active" and timer["Job"] == "" and timer["InvocationID"] == timer_id
             and guard["CPUQuotaPerSecUSec"] == "1s" and int(guard["MemoryMax"]) == GUARD_BYTES,
             f"epoch {e} guard changed")
        cg = Path("/sys/fs/cgroup/system.slice") / old["Id"]
        members = sorted(int(p) for p in (cg / "cgroup.procs").read_text().split())
        need(len(members) == 2 and main_pid in members, f"epoch {e} cgroup membership")
        ps = []
        for pid in members:
            image = os.readlink(f"/proc/{pid}/exe")
            main_name = "horizon-169-focused-node" if e == 169 else "jetstreamer-node"
            need(Path(image).name == (main_name if pid == main_pid else "historical-worker"),
                 f"epoch {e} unrecognized executable")
            m = os.stat(f"/proc/{pid}/exe")
            ps.append((pid,ticks(pid),m.st_dev,m.st_ino))
        stats = dict((k,int(v)) for k,v in (l.split() for l in (cg / "memory.stat").read_text().splitlines()))
        pss = sum(int(next(l.split()[1] for l in Path(f"/proc/{p}/smaps_rollup").read_text().splitlines()
                           if l.startswith("Pss:"))) * 1024 for p in members)
        result[e] = {"unit":old["Id"], "iid":now["InvocationID"], "processes":ps,
                     "timer_iid":timer_id, "resident":min(pss, stats["anon"] + stats["file_mapped"], ACTOR_BYTES)}
    return result


def ceiling(booked, supplemental, actor, guard, cores):
    need(all(type(x) is int and x >= 0 for x in (booked, supplemental, actor, guard, cores)),
         "invalid CPU quota")
    need(booked == 63_250_000 and actor == 500_000 and guard == 250_000,
         "changed CPU accounting")
    total = booked + supplemental + actor + guard
    need(total <= cores * 1_000_000, "complete CPU exceeds host")
    return total


def calculate(fleet, obligation, previous, guard169, inputs, candidate_bytes, focused_bytes,
              available_memory, total_memory, free, realized, cores):
    aux, roots = inputs["auxiliary"], inputs["roots"]
    need(aux["memory_bytes"] == 6576668672 and aux["cpu_quota_micros"] == 3250000
         and obligation["additional_cpu_quota_micros"] == 4_000_000
         and obligation["additional_memory_bytes"] == 24 * GIB, "changed auxiliary or audit booking")
    cpu = ceiling(previous["simultaneous_cpu_upper_bound_micros"], inputs["temporary_cpu_micros"],
                  500_000, 250_000, cores)
    memory = (fleet["complete_projected_memory_bytes"] + 16 * GIB + aux["memory_bytes"]
              + obligation["additional_memory_bytes"] + inputs["temporary_memory"])
    need(memory == previous["complete_memory_plus_reserve_bytes"] + inputs["temporary_memory"]
         and 0 <= realized <= memory, "incomplete memory accounting")
    storage = obligation["current_storage"]
    need(storage["remaining_archive_growth_bytes"] == 0 and storage["remaining_DATA_growth_bytes"] == 18 * GIB
         and fleet["all_reservation_ending_bytes"] == 0, "changed audit or prior booking")
    growth = roots["peer_remaining_growth_bytes"] + roots["remaining_standard_root_bytes"]
    # Recompute the inherited bound using the same native membership and twice-observed
    # physical allocations as 169. Add both the disjoint focused169 tree and candidate172.
    extra = (growth + 10 * GIB + aux["remaining_growth_bytes"] + (64 << 20)
             + inputs["independent166_whole_cap_bytes"])
    non_focused = max(inputs["historical_floor_bytes"], obligation["configured_free_floor_bytes"]) + extra + 18 * GIB
    focused_growth = guard169["maximum_root_physical_bytes"] - focused_bytes
    need(0 <= focused_growth <= 96 * GIB and 0 < candidate_bytes < CAP, "whole-tree allocation outside cap")
    # 168 guard protects its peers, but permits its own remaining whole-root growth.
    # 169 has the highest existing floor. Both the floor and its unspent growth survive.
    peer_floor = max(non_focused, guard169["minimum_free_bytes"],
                     previous["protected_raw_floor_bytes"],
                     8297502499408 + roots["remaining_standard_root_bytes"]) + focused_growth
    candidate_growth = CAP - candidate_bytes
    return {"complete_cpu_quota_micros":cpu, "complete_memory_plus_reserve_bytes":memory,
            "available_memory_bytes":available_memory, "total_memory_bytes":total_memory,
            "required_available_memory_bytes":memory-realized, "realized_peer_memory_bytes":realized,
            "base_protected_floor_bytes":peer_floor, "focused169_remaining_bytes":focused_growth,
            "focused169_existing_guard_floor":guard169["minimum_free_bytes"],
            "existing_complete_DATA_bytes":non_focused, "available_HOME_bytes":free,
            "candidate_cap_bytes":CAP, "candidate_allocated_bytes":candidate_bytes,
            "remaining_standard_root_bytes":candidate_growth,
            "complete_required_DATA_bytes":peer_floor+candidate_growth,
            "resource_credit_bytes":0, "resource_promise_ending_bytes":0}


def capture(fleet_ref, own_iid=None):
    path = Path(fleet_ref["path"])
    fleet = bound(fleet_ref)
    need(path.name == "ROOT_COMPLETE_OPERATIONAL_FLEET.json" and path.parent.parent == RUNTIME
         and 0 <= time.time() - fleet["recorded_unix_seconds"] <= 40 * 60, "stale fleet")
    home = bound(fleet["current_home_cycle_capacity"])
    need(home["terminal172_original_booking_bytes"] == CAP and home["terminal172_resource_credit_bytes"] == 0
         and home["all_reservation_ending_bytes"] == 0 and fleet["all_existing_memory_DATA_OS_native_transport_promises_retained"] is True,
         "missing retained epoch 172 reservation")
    original = checked(ORIGINAL / "ACTUAL172_MEMORY_POINT_PLAN.json", BOOK_MEMORY_SHA)
    need(original["candidate_epoch"] == 172 and original["candidate_actor_memory_bytes"] == ACTOR_BYTES
         and original["candidate_guard_memory_bytes"] == GUARD_BYTES, "original 172 memory owner")
    guard169 = checked(GUARD169, GUARD169_SHA)
    previous = checked(POST169, POST169_SHA)
    need(guard169["minimum_free_bytes"] == previous["armed_guard_floor_bytes"]
         and guard169["maximum_root_physical_bytes"] == 96 * GIB, "focused169 ceiling")
    a = available()
    owners0 = owner_snapshot(fleet, own_iid)
    need(owners0[169]["iid"] == guard169["invocation_id"], "foreign focused169 producer")
    obligation = fleet["continuing_audit_obligation"]
    audit_path = PACKAGE / "public_audit.py"
    need(digest(audit_path) == AUDIT_SHA, "different public audit witness")
    def audit():
        return json.loads(run("/usr/bin/python3", "-I", "-B", audit_path, json.dumps(obligation), timeout=60))
    audit0 = audit()
    native_inputs = json.loads(run(PACKAGE / "reservations", "--measure-replay-reservations", path,
                                   fleet_ref["sha256"], timeout=150))
    dest = Path(guard169["worker_root"])
    retained = [min(du(tree), du(tree)) for tree in (LANE, dest)]
    owners1 = owner_snapshot(fleet, own_iid)
    for e,a0 in owners0.items():
        need(all(owners1[e][k] == a0[k] for k in ("iid","processes","timer_iid")), "native peer changed during fit")
    realized = sum(min(row["resident"], owners1[e]["resident"]) for e,row in owners0.items())
    audit1 = audit()
    need(audit0 == audit1 and audit0["shared_slice"]["CPUQuotaPerSecUSec"] == "4s", "audit owner changed")
    b = available()
    need(a[0] == b[0], "physical memory changed")
    c = calculate(fleet,obligation,previous,guard169,native_inputs,*retained,min(a[1],b[1]),a[0],
                  min(a[2],b[2]),realized,min(len(os.sched_getaffinity(0)),os.sysconf("SC_NPROCESSORS_ONLN")))
    return dict(c, fleet=fleet_ref, owners=owners1, current_audit=audit1, native_inputs=native_inputs,
                captured_at=time.time(), worker_replay_claimed=False)


def select(c, armed=None):
    floor = c["base_protected_floor_bytes"]
    if armed is None:
        armed = floor + 16 * GIB
    need(floor <= armed, "pre-payload peer floor moved past armed guard")
    required = armed + c["remaining_standard_root_bytes"]
    need(c["available_HOME_bytes"] >= required,
         f"HOME requires {required} bytes, has {c['available_HOME_bytes']}")
    need(c["total_memory_bytes"] >= c["complete_memory_plus_reserve_bytes"]
         and c["available_memory_bytes"] >= c["required_available_memory_bytes"], "complete memory does not fit")
    return armed
