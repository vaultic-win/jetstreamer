"""Bind the RAM-backed epoch 229 Bank delta diagnostic to the fleet."""
from pathlib import Path
import re

from ordinary249.delivery248 import V, bound, props, ref

UNIT = "horizon-perf-epoch229-bank-delta@v334.service"
PACKAGE = V / "horizon229-bank-delta-v334"
RUN_ROOT = Path("/home/ubuntu/.jetstreamer-private/epoch229-bank-delta-tmpfs-v334/run")
REGISTRATION = PACKAGE / "cadence-registration.json"
FIELDS = ["Id", "ActiveState", "SubState", "InvocationID", "MainPID", "NRestarts", "ControlGroup"]


def receipt():
    if not REGISTRATION.is_file():
        return None
    binding = ref(REGISTRATION)
    row = bound(binding)
    assert row["schema"] == "jetstreamer-historical-performance-launch-receipt-v1"
    assert row["epoch"] == 229 and row["unit"] == UNIT and row["entry_replay_requested"]
    assert row["kind"] == "europe-rooted-bank-delta-comparison" and row["launched"]
    assert row["canonical_epoch_publication_authorized"] is False and row["run_root"] == str(RUN_ROOT)
    assert (row["bootstrap_slot"], row["target_slot"], row["terminal_slot"]) == (98927417, 98931634, 98939266)
    assert row["first_divergent_slot"] == 98931633
    assert re.fullmatch("[0-9a-f]{32}", row["invocation_id"]) and row["main_pid"] > 0
    assert bound(row["admission"])["profile"]["sha256"] == '7506d3180e37e565791401a1ed7398d9caf55b5397e70a1ad18081c10108b85c'
    active_guard = bound(row["active_guard"])
    assert active_guard["producer_invocation_id"] == row["invocation_id"] and active_guard["trip_reason"] is None
    assert active_guard["plan_sha256"] == row["guard_plan"]["sha256"] and active_guard["producer"]["pid"] == row["main_pid"]
    return binding, row


def configuration():
    registration = receipt()
    if registration is None:
        return []
    _, row = registration
    live = props(UNIT, FIELDS)
    if live["ActiveState"] in ("inactive", "failed"):
        assert live["MainPID"] == "0" and not live["ControlGroup"]
        return []
    assert (live["Id"], live["ActiveState"], live["SubState"]) == (UNIT, "active", "running")
    assert live["InvocationID"] == row["invocation_id"] and int(live["MainPID"]) == row["main_pid"]
    assert live["ControlGroup"] == "/system.slice/" + UNIT and live["NRestarts"] == "0"
    node = Path("/proc") / live["MainPID"] / "exe"
    assert node.samefile(row["node_path"]) and not node.readlink().is_relative_to(RUN_ROOT)
    return [dict(range="229-229", controller_unit=UNIT, expected_controller_invocation_id=row["invocation_id"],
                 producer_unit=UNIT, expected_producer_invocation_id=row["invocation_id"],
                 scratch_path=str(RUN_ROOT), worker_executable_basename="historical-worker")]


def gate(plan):
    registered = receipt()
    if registered is None:
        return
    source, row = registered
    if UNIT not in plan["tracked_units"]:
        plan["tracked_units"].append(UNIT)
    diagnostics = plan.setdefault("diagnostics", [])
    owner = dict(epoch=229, unit=UNIT, invocation_id=row["invocation_id"],
                 scratch_path=str(RUN_ROOT), launch_receipt=source)
    previous = [item for item in diagnostics if item["unit"] == UNIT]
    assert not previous or previous == [owner]
    if not previous:
        diagnostics.append(owner)
    gate_row = plan["gates"]["229"]
    if source not in gate_row["evidence"]:
        gate_row["evidence"].append(source)
    gate_row["next_action"] = "Capture native Bank hashes and account hash leaves at 98931631 and 98931633 for comparison with the finalized vote chain."
    terminal = PACKAGE / "terminal.json"
    if terminal.is_file():
        terminal_ref = ref(terminal)
        acceptance = bound(terminal_ref)
        assert acceptance["registration"] == source
        if terminal_ref not in gate_row["evidence"]:
            gate_row["evidence"].append(terminal_ref)
        gate_row["next_action"] = acceptance["next_action"]


def owns(row):
    producer = row.get("producer", {})
    if producer.get("Id") != UNIT:
        return False
    _, active = receipt()
    assert row["epoch"] == 229 and row["phase"] == "diagnostic-qualification"
    assert producer["InvocationID"] == active["invocation_id"]
    assert row["ordinary_replay_claim"] is False and row["current_sidecar_eta_valid"] is False
    assert row["scratch_path"] == str(RUN_ROOT)
    return True
