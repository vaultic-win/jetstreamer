"""Bind the bounded epoch 230 checkpoint continuation to fleet cadence."""

import re
from pathlib import Path

from ordinary249.delivery248 import V, bound, props, ref

UNIT = "horizon-qualify-230-checkpoint-continuation-fit-v3.service"
PACKAGE = V / "horizon230-checkpoint-continuation-fit-v3"
REGISTRATION = PACKAGE / "cadence-registration.json"
RUN_ROOT = Path("/home/ubuntu/.jetstreamer-private/epoch230-continuation-tmpfs-v1/run-v3")
INPUTS = {
    "path": str(V / "horizon230-checkpoint-continuation-fit-inputs-v3/inputs.json"),
    "sha256": "8aa61a6982e597daf9c0c97a93f39c00d536740939a6e6aebf398d958c583739",
}
WORKER_SHA = "f39140b9a9659e7c6e8207076a2d0c560a6b69df42cc92e19a421cf46c2b761c"
FIELDS = ["Id", "ActiveState", "SubState", "InvocationID", "MainPID", "NRestarts", "ControlGroup"]


def receipt():
    if not REGISTRATION.is_file():
        return None
    metadata = REGISTRATION.lstat()
    assert REGISTRATION.resolve() == REGISTRATION and metadata.st_uid == 0 and metadata.st_nlink == 1
    assert not metadata.st_mode & 0o222
    binding = ref(REGISTRATION)
    row = bound(binding)
    assert row["schema"] == "jetstreamer-historical-performance-launch-receipt-v1"
    assert (row["epoch"], row["unit"], row["run_root"], row["kind"]) == (
        230, UNIT, str(RUN_ROOT), "epoch230-bounded-checkpoint-continuation")
    assert (row["bootstrap_slot"], row["first_slot"], row["last_slot"]) == (99375855, 99375856, 99383572)
    assert row["worker_sha256"] == WORKER_SHA and row["launched"] and row["entry_replay_requested"]
    assert all(row[key] is False for key in ("canonical_epoch_publication_authorized", "remote_mutations",
                                            "r2_mutations", "full_continuation_peak_qualified"))
    assert re.fullmatch("[0-9a-f]{32}", row["invocation_id"]) and row["main_pid"] > 0
    admission = bound(row["admission"])
    assert admission["epoch"] == 230 and admission["inputs"] == INPUTS and admission["admitted"] is True
    active_guard = bound(row["active_guard"])
    assert active_guard["producer_invocation_id"] == row["invocation_id"] and active_guard["trip_reason"] is None
    assert active_guard["plan_sha256"] == row["guard_plan"]["sha256"]
    assert active_guard["producer"]["pid"] == row["main_pid"]
    return binding, row


def configuration():
    registered = receipt()
    if registered is None:
        return []
    _, row = registered
    live = props(UNIT, FIELDS)
    if live["ActiveState"] in ("inactive", "failed"):
        assert live["MainPID"] == "0" and not live["ControlGroup"]
        return []
    assert (live["Id"], live["ActiveState"], live["SubState"]) == (UNIT, "active", "running")
    assert (live["InvocationID"], int(live["MainPID"])) == (row["invocation_id"], row["main_pid"])
    assert live["ControlGroup"] == "/system.slice/" + UNIT and live["NRestarts"] == "0"
    assert (Path("/proc") / live["MainPID"] / "exe").samefile(row["node_path"])
    return [dict(range="230-230", controller_unit=UNIT, expected_controller_invocation_id=row["invocation_id"],
                 producer_unit=UNIT, expected_producer_invocation_id=row["invocation_id"],
                 scratch_path=str(RUN_ROOT), worker_executable_basename="historical-worker")]


def register(plan):
    registered = receipt()
    if registered is None:
        return None
    source, row = registered
    if UNIT not in plan["tracked_units"]:
        plan["tracked_units"].append(UNIT)
    diagnostics = plan.setdefault("diagnostics", [])
    claim = dict(epoch=230, unit=UNIT, invocation_id=row["invocation_id"],
                 scratch_path=str(RUN_ROOT), launch_receipt=source)
    previous = [owner for owner in diagnostics if owner["unit"] == UNIT]
    assert not previous or previous == [claim]
    if not previous:
        diagnostics.append(claim)
    gate = plan["gates"]["230"]
    if source not in gate["evidence"]:
        gate["evidence"].append(source)
    gate["next_action"] = "Validate the bounded checkpoint and measure restore baseline and replay growth."
    terminal = PACKAGE / "terminal.json"
    if terminal.is_file():
        terminal_ref = ref(terminal)
        completed = bound(terminal_ref)
        assert completed["registration"] == source and completed["epoch"] == 230
        if terminal_ref not in gate["evidence"]:
            gate["evidence"].append(terminal_ref)
        gate["next_action"] = completed["next_action"]
    deployment = bound(ref(PACKAGE / "fleet-tool.json"))
    assert deployment["schema"] == "foundation-epoch230-checkpoint-continuation-fleet-tool-v1"
    return deployment["artifact"]


def owns(row):
    producer = row.get("producer", {})
    if producer.get("Id") != UNIT:
        return False
    _, registration = receipt()
    assert row["epoch"] == 230 and row["phase"] == "diagnostic-qualification"
    assert producer["InvocationID"] == registration["invocation_id"]
    assert row["ordinary_replay_claim"] is False and row["current_sidecar_eta_valid"] is False
    assert row["scratch_path"] == str(RUN_ROOT)
    return True
