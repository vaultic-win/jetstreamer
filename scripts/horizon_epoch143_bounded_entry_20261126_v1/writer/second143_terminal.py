"""Validate the exact drained second-hourly epoch 143 invocation without credit."""

from pathlib import Path

BASE = Path("/var/lib/jetstreamer/horizon_runtime_data/epoch143-second-hourly-20261128-v1")
UNIT = "horizon-qualify-143-second-hourly-20261128-v1.service"
GUARD = "horizon-guard-143-second-hourly-20261128-v1"
IID = "4a1629f9884b406bb104a745053eb5b3"
TERMINAL = dict(path=str(BASE / f"failed-{IID}/TERMINAL.json"),
                sha256="e3337993ebc5ff75dd39c26a462bc8b4757a914289a2770ae221784535175daa")


def closed(core):
    need, read, state, check = (core[key] for key in ("need", "read", "state", "bound"))
    terminal, receipt = read(Path(TERMINAL["path"]), TERMINAL["sha256"])
    native = state(UNIT, "Id,InvocationID,ActiveState,Result,ExecMainCode,ExecMainStatus,MainPID,ControlPID,Job")
    need(receipt == TERMINAL and native == terminal["native"] and native["Id"] == UNIT
         and native["InvocationID"] == terminal["invocation_id"] == IID
         and (native["ActiveState"], native["Result"], native["ExecMainCode"], native["ExecMainStatus"]) ==
             ("failed", "exit-code", "1", "1")
         and native["MainPID"] == native["ControlPID"] == "0" and not native["Job"],
         "epoch 143 second-hourly terminal changed")
    actor = check(terminal["held"])
    _, held = read(BASE / "HELD_OWNER.json")
    need(held == terminal["held"] and actor["producer_invocation_id"] == IID
         and check(terminal["postguard"])["base_169"]["native"]["raw"]["replacement143"]["actor"] == held,
         "epoch 143 second-hourly terminal lost its admitted owner")
    permit = Path(terminal["permit"]["path"])
    need(permit == BASE / "barrier/allow" and permit.read_text() == IID
         and terminal["disposition"] == "restored-checkpoint-verified-terminal-verifier-ran-before-replay"
         and not terminal["resource_credit_bytes"] and not terminal["publication_authorized"]
         and not terminal["production_replay_completed"] and not terminal["elapsed_replay_slots"]
         and not terminal["zero_output_bytes"]
         and terminal["retained_HOME_bytes"] == (64 << 30) + (64 << 20)
         and terminal["retained_RAM_bytes"] == 41 << 30 and terminal["retained_cpu_quota_micros"] == 3_000_000,
         "epoch 143 terminal cannot credit resources or claim replay")
    sample = check(terminal["final_guard_sample"])
    need(sample["producer_invocation_id"] == IID and sample["trip_reason"] is None
         and sample["plan_sha256"] == terminal["guard_plan"]["sha256"], "epoch 143 terminal lost its final guard")
    cgroups = Path("/sys/fs/cgroup/system.slice")
    need(not (cgroups / UNIT).exists(), "epoch 143 terminal has a cgroup")
    for name, expected in terminal["guard_drain"].items():
        need(name in (GUARD + ".timer", GUARD + ".service") and state(name, "Id,ActiveState,Job") == dict(expected, Id=name)
             and expected == dict(ActiveState="inactive", Job="") and not (cgroups / name).exists(),
             "epoch 143 terminal guard has not drained")
    return receipt
