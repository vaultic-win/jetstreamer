"""Account for the single guarded epoch 140 retry across one observer boundary."""
import time
from pathlib import Path

from evidence import bound, checked, need, utc
from prefix162_status import props, ticks

ROOT = Path("/var/lib/jetstreamer/horizon_runtime_data")
BASE = ROOT / "epoch140-suffix-recording-20261127-retry2"
RUN = Path("/home/sol/.jetstreamer-private/epoch140-suffix-recording-20261127-retry2")
UNIT = "horizon-epoch140-suffix-recording.service"
GUARD_TIMER = "horizon-guard-epoch140-suffix-recording-20261127-retry2.timer"
BRIDGE = "horizon-qualify-170-checkpoint-suffix-20261127-v1.service"
BRIDGE_GUARD = "horizon-guard-170-checkpoint-suffix-20261127-v1.timer"
ORIGINAL = "horizon-qualify-170-full-metered-20261124-v1.service"
MARKER = Path("/run/horizon-epoch140-epoch170-cpu-loan.active")
CGROUP = f"/system.slice/{UNIT}"
FIELD = "current_private140_suffix_recording"
RESERVATION = "private_epoch140_suffix_recording_reservation"
CAP = 44 << 30
EVIDENCE = 64 << 20
RAM = 27 << 30
NODE = ROOT / "epoch140-recording-build-20261122-v1/44153c667a564b36ad8feb7e7cffb5db/node/jetstreamer-node"


def live(manager, actor):
    pid = actor["pid"]
    need(
        manager["ActiveState"] == "active"
        and manager["InvocationID"] == actor["invocation_id"]
        and manager["MainPID"] == str(pid)
        and manager["ControlGroup"] == CGROUP
        and manager["MemoryMax"] == str(26 << 30)
        and manager["MemorySwapMax"] == "0"
        and manager["CPUQuotaPerSecUSec"] == "2s"
        and ticks(pid) == actor["start_ticks"]
        and Path(f"/proc/{pid}/exe").samefile(NODE),
        "epoch 140 private producer lost native identity or limits",
    )


def guard(actor, now):
    timer = props(GUARD_TIMER, "ActiveState,InvocationID")
    need(timer["ActiveState"] == "active" and timer["InvocationID"] == actor["guard_timer_invocation_id"],
         "epoch 140 private guard timer changed")
    paths = sorted((BASE / "guard-receipts").glob("sample-*.json"),
                   key=lambda path: path.stat().st_mtime_ns, reverse=True)
    for path in paths[:8]:
        reference = bound(path)
        sample = checked(reference)
        if sample["producer_invocation_id"] != actor["invocation_id"]:
            continue
        need(
            now - 45 <= sample["recorded_unix_seconds"] <= now + 1
            and sample["producer"]["pid"] == actor["pid"]
            and sample["plan_sha256"] == actor["guard_plan"]["sha256"]
            and sample["maximum_root_physical_bytes"] == CAP
            and sample["producer_stop_enabled"] and sample["trip_reason"] is None
            and sample["root_physical_observation_error"] is None,
            "epoch 140 lacks a current, clean scoped guard sample",
        )
        observation = sample["root_physical_observation"]
        need(not observation["exceeds_budget"] and observation["maximum_physical_bytes"] == CAP,
             "epoch 140 whole tree exceeds the retained cap")
        occupied = min(observation[name]["physical_bytes"] for name in ("first", "second"))
        need(0 <= occupied <= CAP, "invalid epoch 140 allocation")
        return reference, occupied, sample["workers"]
    raise ValueError("epoch 140 has no guard sample for the enrolled invocation")


def book(actor, active_ref, head, old, next_observer):
    booking = checked(actor["booking"])
    need(
        booking["schema"] == "horizon-epoch140-private-recording-booking-v1"
        and booking["profile"] == "retry2"
        and booking["unit"] == UNIT
        and booking["fleet"] == actor["inherited_fleet"]
        and (booking["fleet"] == head or old and old["held_owner"] == bound(BASE / "HELD_OWNER.json"))
        and booking["cross_cadence"] == active_ref
        and booking["HOME_bytes"] == CAP + EVIDENCE and booking["RAM_bytes"] == RAM
        and booking["cpu_quota_micros"] == 3_000_000 and booking["runtime_max_seconds"] == 1600
        and booking["must_drain_by_unix_seconds"] < next_observer
        and booking["recording_authorized"] is True and booking["archive_publication_authorized"] is False,
        "epoch 140 cross-cadence booking differs from the guarded retry2",
    )
    active = checked(active_ref)
    need(booking["writer"]["invocation_id"] == active["new"]["invocation_id"],
         "epoch 140 booking was issued by a different writer generation")
    return booking


def observe(c, active_ref):
    manager = props(UNIT)
    held_path = BASE / "HELD_OWNER.json"
    if not held_path.exists():
        need(manager["MainPID"] == "0", "unregistered epoch 140 producer")
        return None
    held = bound(held_path)
    actor = checked(held)
    old = c.fleet.get(FIELD)
    need(
        actor["schema"] == "horizon-epoch140-guarded-held-owner-v1" and actor["unit"] == UNIT
        and actor["boot_id"] == Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        and actor["guard_timer"] == GUARD_TIMER and actor["guarded_HOME_bytes"] == CAP
        and actor["producer_RAM_bytes"] == 26 << 30 and actor["guard_RAM_bytes"] == 1 << 30
        and (not old or old["held_owner"] == held),
        "epoch 140 held owner is not the registered protected retry2",
    )
    booking = book(actor, active_ref, c.fleet_ref, old, int(utc(c.stamp).timestamp()) + 1800)
    loan_ref = bound(BASE / "CPU_LOAN_ACTIVE.json")
    loan = checked(loan_ref)
    need(
        loan["candidate_invocation"] == actor["invocation_id"] and loan["candidate_pid"] == actor["pid"]
        and loan["booking"] == actor["booking"]
        and loan["outer_runtime_cap_seconds"] == 1600
        and loan["must_drain_by_unix_seconds"] == booking["must_drain_by_unix_seconds"]
        and loan["producer_cpu_quota_micros"] == 2_000_000
        and loan["guard_cpu_quota_micros"] == 1_000_000
        and loan["original_epoch170_producer_quota_micros"] == 9_000_000
        and loan["bridge_cpu_quota_micros"] == 6_000_000,
        "epoch 140 actor does not own the recorded 170 remainder",
    )
    row = {
        "epoch": 140, "unit": manager, "actor": dict(actor, producer_pid=actor["pid"]),
        "held_owner": held, "loan": loan_ref, "booking": actor["booking"], "observer": c.sample_ref,
        "archive_publication_authorized": False, "resource_credit_bytes": 0,
    }
    if manager["MainPID"] == "0":
        need(manager["ActiveState"] in ("inactive", "failed"), "epoch 140 is changing state")
        returned_path = BASE / "CPU_LOAN_RETURN.json"
        if returned_path.exists():
            returned = bound(returned_path)
            proof = checked(returned)
            need(proof["candidate_invocation"] == actor["invocation_id"]
                 and proof["loan"] == loan_ref and proof["producer_and_guard_drained"]
                 and not MARKER.exists(), "epoch 140 loan return belongs to a different producer")
            return dict(row, phase="terminal", loan_return=returned, reservation=None)
        return dict(row, phase="drained-pending-loan-return", reservation=lease(0))
    live(manager, actor)
    permit = BASE / "barrier/allow"
    need(permit.read_text().strip() == actor["invocation_id"]
         and MARKER.read_text().strip() == actor["booking"]["sha256"], "epoch 140 release or fence changed")
    need(bound(Path(loan["overlap_fence"]["path"])) == loan["overlap_fence"],
         "epoch 140 donor fence changed")
    bridge = props(BRIDGE)
    original = props(ORIGINAL)
    retained_timer = props(BRIDGE_GUARD, "ActiveState,InvocationID")
    need(bridge["InvocationID"] == loan["live_bridge_invocation"] and bridge["CPUQuotaPerSecUSec"] == "6s"
         and bridge["ActiveState"] == "active" and original["MainPID"] == "0" and original["Job"] == ""
         and retained_timer["ActiveState"] == "active"
         and retained_timer["InvocationID"] == loan["retained_bridge_guard_timer_invocation"],
         "epoch 140 borrower overlaps a changed 170 actor")
    sampled, physically_occupied, workers = guard(actor, int(time.time()))
    first = BASE / "FIRST_PROTECTED_PROGRESS.json"
    if first.exists():
        progress = checked(bound(first))
        need(
            progress["producer_invocation_id"] == actor["invocation_id"]
            and progress["last_requested_slot"] == 60911999
            and 60911751 < progress["slot"] <= 60911999
            and any(pid == progress["worker_pid"] and 0 < vmas <= 3_500_000 for pid, vmas in workers),
            "epoch 140 progress belongs to a different guarded worker",
        )
        row["first_protected_progress"] = bound(first)
    return dict(row, phase="worker" if "first_protected_progress" in row else "bootstrap",
                guard=sampled, reservation=lease(physically_occupied))


def lease(physical):
    return {"whole_tree_cap_bytes": CAP, "control_evidence_bytes": EVIDENCE,
            "occupied_lower_bound_bytes": physical, "remaining_home_bytes": CAP - physical + EVIDENCE,
            "memory_max_bytes": RAM, "borrowed_from_epoch170_cpu_quota_micros": 3_000_000}


def active(row):
    return bool(row and row["phase"] in ("bootstrap", "worker"))


def recheck(row):
    if active(row):
        live(props(UNIT), row["actor"])


def install(fleet, row):
    if not row:
        return
    fleet[FIELD] = row
    fleet[RESERVATION] = row["reservation"]
    if active(row):
        rows = fleet["actual_active_private_diagnostics"]
        need(all(item["epoch"] != 140 for item in rows), "duplicate epoch 140 owner")
        rows.append(row)
        fleet["active_private_diagnostic_count"] += 1
        fleet["active_producer_count"] += 1
