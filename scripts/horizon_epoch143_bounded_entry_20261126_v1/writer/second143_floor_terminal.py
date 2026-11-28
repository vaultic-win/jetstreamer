"""Keep the exact guarded floor stop charged until the next epoch 143 admission."""

from pathlib import Path


BASE = Path("/var/lib/jetstreamer/horizon_runtime_data/epoch143-second-hourly-20261128-v2")
UNIT = "horizon-qualify-143-second-hourly-20261128-v2.service"
GUARD = "horizon-guard-143-second-hourly-20261128-v2"
IID = "a04721854c644797903440d2a7eade08"
TERMINAL = dict(path=str(BASE / f"floor-stop-{IID}/TERMINAL.json"),
                sha256="4f736b6ca61ab274c7c643cc237520c59ad62508dddbf6f640f71f8aa2584fcc")


def closed(core, require_unit_drain=True):
    need, read, state, checked = (core[key] for key in ("need", "read", "state", "bound"))
    terminal, receipt = read(Path(TERMINAL["path"]), TERMINAL["sha256"])
    intent = checked(terminal["stop_intent"])
    outcome = checked(terminal["stop_completion"])
    sample = checked(terminal["trip_sample"])
    actor = checked(terminal["prior_held"])
    plan = checked(terminal["guard_plan"])
    need(receipt == TERMINAL and terminal["unit"] == UNIT
         and terminal["invocation_id"] == actor["producer_invocation_id"] == plan["invocation_id"] == IID
         and intent["producer_invocation_id"] == outcome["producer_invocation_id"] == IID
         and sample == intent["sample"] and sample["producer_invocation_id"] == IID
         and sample["plan_sha256"] == intent["plan_sha256"] == outcome["plan_sha256"] == actor["guard_plan"]["sha256"]
         and sample["trip_reason"] == intent["reason"] == "filesystem-floor"
         and sample["available_bytes"] < sample["minimum_free_bytes"] == plan["minimum_free_bytes"]
         and outcome["terminal"]["invocation_id"] == IID and outcome["terminal"]["active"] == "inactive"
         and outcome["terminal"]["pid"] == 0 and not outcome["scratch_deleted"]
         and not terminal["completed_epoch"] and not terminal["publication_authorized"]
         and not terminal["resource_credit_bytes"] and not terminal["output"]["bytes"]
         and terminal["retained_home"] == (64 << 30) + (64 << 20)
         and terminal["retained_ram"] == 41 << 30 and terminal["retained_cpu_micros"] == 3_000_000,
         "epoch 143 floor-stop receipt changed")
    need(Path(terminal["permit"]["path"]).read_text() == IID and
         checked(terminal["first_progress"])["producer_invocation_id"] == IID, "epoch 143 lost its guarded release")
    units = {UNIT, GUARD + ".timer", GUARD + ".service"}
    need(set(terminal["drain"]) == units, "incomplete epoch 143 stop roster")
    for unit in units:
        expected = terminal["drain"][unit]
        need(expected == dict(Id=unit, ActiveState="inactive", Job=""), "invalid 143 drain receipt")
        if require_unit_drain or unit != UNIT:
            need(state(unit, "Id,ActiveState,Job") == expected
                 and not (Path("/sys/fs/cgroup/system.slice") / unit).exists(), "143 floor stop has a live owner")
    return receipt
