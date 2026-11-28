"""Retain the exact epoch 143 hourly reservation through first closure and second execution."""

import datetime as dt
import json
from pathlib import Path
import time

RT = Path("/var/lib/jetstreamer/horizon_runtime_data")
FIRST = RT / "epoch143-first-hourly-20261127-v1"
SECOND = RT / "epoch143-second-hourly-20261128-v1"
UNIT = "horizon-qualify-143-second-hourly-20261128-v1.service"
GUARD = "horizon-guard-143-second-hourly-20261128-v1"
FIRST_UNIT = "horizon-qualify-143-first-hourly-20261127-v1.service"
FIRST_GUARD = "horizon-guard-143-first-hourly-20261127-v1"
RUN = Path("/home/sol/.jetstreamer-private") / SECOND.name
G = 1 << 30
M = 1 << 20
TREE = 64 * G
RAM = 41 * G
ACCEPTANCE = dict(path=str(FIRST / "terminal-capture-v1/PRIVATE_FIRST_HOURLY_ACCEPTANCE.json"),
                  sha256="105f7fbf58843f7475eae951ec5d482cc7372204401036db01d4ef4fdbbfe95d")
FIRST_OWNER = dict(path=str(FIRST / "HELD_OWNER.json"),
                   sha256="3e86e32a4e29029bd985a003e94a850d014ee9442a40a45009352577bf817bf8")
FIRST_IID = "4514e85834c34152ae0ecfde8a42001d"
FIRST_TERMINAL = dict(path=str(FIRST / "terminal-capture-v1/PID1_EXIT.json"),
                      sha256="9993b44d66051f856a3554ff65c4106c0efdb70cc9344d0783413440e402fe56")
BOOT = 61787631
END = 61794627
RECOVERY = RT / "survivor172-cadence-20261122-v1/recover-92cfb9733c895652bce8"
REGISTRATION_SHA = "99200d918ee817d84e99f8546ef81b73bdd32dae51cb9200f71f01fc7345e8ce"
RECOVERY_TIMER = "horizon-observer-root071808-live166167170-20261128-v1.timer"
RECOVERY_TIMER_IID = "ec7b29e730d04b4e9a7e45d527172d16"


def closed(core, fleet):
    need, bound, state = core["need"], core["bound"], core["state"]
    accepted = bound(ACCEPTANCE)
    terminal = bound(FIRST_TERMINAL)
    actor = bound(FIRST_OWNER)
    native = terminal["properties"]
    prior = fleet["current_private143_first_hourly"]
    need(prior["phase"] in ("worker", "terminal")
         and prior["held_owner"] == FIRST_OWNER and prior["actor"] == actor
         and accepted["native_terminal"] == FIRST_TERMINAL and accepted["bindings"]["actor"] == FIRST_OWNER
         and accepted["producer_invocation_id"] == native["InvocationID"] == FIRST_IID
         and accepted["terminal_slot"] == BOOT and accepted["resource_credit_bytes"] == 0
         and not accepted["publication_authorized"] and native["Id"] == FIRST_UNIT
         and (native["Result"], native["ExecMainCode"], native["ExecMainStatus"]) == ("success","1","0")
         and native["MainPID"] == native["ControlPID"] == "0"
         and accepted["guard_drain"] == {"unit": FIRST_GUARD + ".service", "state": "inactive"},
         "different closed epoch 143 predecessor")
    independent = bound(accepted["independent_validation"])
    need(independent["validation"] == "pass" and independent["terminal_slot"] == BOOT
         and independent["archive_sha256"] == accepted["archive"]["sha256"], "143 independent reread changed")
    for unit in (FIRST_UNIT, FIRST_GUARD + ".service", FIRST_GUARD + ".timer"):
        fields = "Id,ActiveState,Job"
        if unit.endswith(".service"):
            fields += ",MainPID,ControlPID,ControlGroup"
        row = state(unit, fields)
        need(row["ActiveState"] == "inactive" and not row["Job"]
             and not row.get("ControlGroup") and row.get("MainPID","0") == row.get("ControlPID","0") == "0"
             and not (Path("/sys/fs/cgroup/system.slice") / unit).exists(), "first 143 has not drained: " + unit)
    return dict(invocation=FIRST_IID, terminal=FIRST_TERMINAL, acceptance=ACCEPTANCE,
                retained_home=TREE+64*M, retained_ram=RAM, cpu_quota_micros=3_000_000, resource_credit_bytes=0)


def preparation_anchor(core, fleet, ref):
    read, bound, need, state = (core[key] for key in ("read","bound","need","state"))
    registered = read(RECOVERY / "REGISTERED.json", REGISTRATION_SHA)[0]
    failed = bound(registered["terminal"])
    config = bound(registered["config"])
    sample = bound(failed["failed_sample"])
    when = dt.datetime.fromisoformat(config["not_before_utc"]).timestamp()
    timer = state(RECOVERY_TIMER, "Id,ActiveState,SubState,InvocationID,Job")
    need(failed["error"] == "native HOST RSS unavailable" and failed["fleet"] == ref
         and failed["prior_config"] == fleet["sole_next_observer"]
         and sample["host_resident_memory"]["after"]["status"] == "unavailable"
         and config["observation_reason"] == "routine"
         and when - 1900 <= time.time() < when
         and timer == {"Id":RECOVERY_TIMER, "ActiveState":"active", "SubState":"waiting",
                       "InvocationID":RECOVERY_TIMER_IID, "Job":""},
         "143 preparation lacks the exact automatic next observation")
    closed(core, fleet)
    return dict(recovery=registered, timer=timer, preparation_only=True)


def owner(core, fleet):
    need, state, read, bound = (core[key] for key in ("need","state","read","bound"))
    closure = closed(core, fleet)
    native = state(UNIT)
    if native["ActiveState"] == "inactive":
        need(native["MainPID"] == native["ControlPID"] == "0" and not native["Job"],
             "next epoch 143 has a pending native launch")
        need(not (SECOND / "HELD_OWNER.json").exists(), "second epoch 143 terminal needs reconciliation")
        return closure, None
    actor, actor_ref = read(SECOND / "HELD_OWNER.json")
    booking = bound(actor["booking"])
    plan = bound(actor["guard_plan"])
    iid = actor["producer_invocation_id"]
    pid = actor["producer_pid"]
    need(native["ActiveState"] == "active" and native["InvocationID"] == iid
         and native["MainPID"] == str(pid) and native["ControlPID"] == "0" and not native["Job"]
         and native["ControlGroup"] == "/system.slice/" + UNIT and native["MemoryMax"] == str(40*G)
         and native["MemorySwapMax"] == "0" and native["CPUQuotaPerSecUSec"] == "2s"
         and booking["schema"] == "horizon-143-second-hourly-booking-v1" and booking["closure"] == ACCEPTANCE
         and plan["invocation_id"] == iid and plan["unit"] == UNIT and plan["worker_root"] == str(RUN)
         and plan["maximum_root_physical_bytes"] == TREE and plan["filesystem"] == "/home/sol"
         and actor["unit"] == UNIT and actor["closure"] == ACCEPTANCE and booking["tree"] == str(RUN),
         "foreign second epoch 143 native owner or booking")
    timer = state(GUARD + ".timer", "Id,ActiveState,InvocationID,Job,BindsTo")
    guard = state(GUARD + ".service", "Id,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec")
    need(timer["ActiveState"] == "active" and timer["InvocationID"] == actor["guard_timer_invocation_id"]
         and not timer["Job"] and timer["BindsTo"] == UNIT and guard["MemoryMax"] == str(G)
         and guard["MemorySwapMax"] == "0" and guard["CPUQuotaPerSecUSec"] == "1s",
         "second epoch 143 guard envelope changed")
    directory = SECOND / "guard-receipts"
    need(not any((directory / name).exists() for name in ("stop-intent.json", "stop-completion.json")),
         "second epoch 143 guard stopping")
    sample, sampled = read(max(directory.glob("sample-*.json"), key=lambda p:p.stat().st_mtime_ns))
    need(sample["producer_invocation_id"] == iid and sample["producer"]["pid"] == pid
         and sample["plan_sha256"] == actor["guard_plan"]["sha256"] and sample["producer_stop_enabled"]
         and sample["trip_reason"] is sample["root_physical_observation_error"] is sample["worker_observation_error"] is None
         and 0 <= time.time() - sample["recorded_unix_seconds"] <= 120
         and sample["minimum_free_bytes"] == plan["minimum_free_bytes"],
         "second epoch 143 lacks its current guard sample")
    physical = sample["root_physical_observation"]
    low = min(physical["first"]["physical_bytes"], physical["second"]["physical_bytes"])
    need(0 <= low <= TREE and not physical["exceeds_budget"], "next epoch 143 exceeds the paid tree")
    return closure, dict(unit=UNIT, iid=iid, actor=actor_ref, floor=plan["minimum_free_bytes"],
                         cap=TREE, low=low, sample=sampled, booking=actor["booking"], pid=pid,
                         mode="released" if (SECOND / "barrier/allow").exists() else "gate", second=True)
