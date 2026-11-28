"""Connect the sealed workerless assembly receipt to the existing cadence."""

from pathlib import Path

from ordinary249.delivery248 import V, bound, props, ref


UNIT = "horizon-qualify-226-checkpoint-continuation-assemble-v1.service"
STATE = V / "horizon226-assembly-v1"
ROOT = "/home/ubuntu/.jetstreamer-private/checkpoint-continuation-226-assemble-v1"
FIELDS = ["Id", "ActiveState", "SubState", "InvocationID", "MainPID", "NRestarts", "ControlGroup"]


def registration():
    path = STATE / "cadence-registration.json"
    if not path.is_file():
        return None
    source = ref(path)
    row = bound(source)
    assert row["schema"] == "foundation-epoch226-private-assembly-launch-v1"
    assert (row["unit"], row["epoch"], row["run_root"]) == (UNIT, 226, ROOT)
    assert row["assembly_only_no_replay"] and row["launched"] and not row["publication_authorized"]
    return source, row


def configuration():
    registered = registration()
    if registered is None:
        return []
    _, row = registered
    live = props(UNIT, FIELDS)
    if live["ActiveState"] in ("inactive", "failed"):
        assert live["MainPID"] == "0" and not live["ControlGroup"]
        return []
    assert (live["Id"], live["ActiveState"], live["SubState"]) == (UNIT, "active", "running")
    assert live["InvocationID"] == row["invocation_id"] and int(live["MainPID"]) == row["main_pid"]
    assert live["ControlGroup"] == "/system.slice/" + UNIT and live["NRestarts"] == "0"
    assert (Path("/proc") / live["MainPID"] / "exe").samefile(row["node_path"])
    return [dict(range="226-226", controller_unit=UNIT, expected_controller_invocation_id=row["invocation_id"],
                 producer_unit=UNIT, expected_producer_invocation_id=row["invocation_id"],
                 scratch_path=ROOT, worker_executable_basename="historical-worker")]


def register(plan):
    registered = registration()
    if registered is None:
        return
    source, row = registered
    if UNIT not in plan["tracked_units"]:
        plan["tracked_units"].append(UNIT)
    claim = dict(epoch=226, unit=UNIT, invocation_id=row["invocation_id"], scratch_path=ROOT, launch_receipt=source)
    existing = [item for item in plan["diagnostics"] if item["unit"] == UNIT]
    assert not existing or existing == [claim]
    if not existing:
        plan["diagnostics"].append(claim)
    gate = plan["gates"]["226"]
    if source not in gate["evidence"]:
        gate["evidence"].append(source)
    terminal = STATE / "terminal.json"
    if terminal.is_file():
        record = ref(terminal)
        closed = bound(record)
        assert closed["launch"] == source and closed["guard_drained"]
        if record not in gate["evidence"]:
            gate["evidence"].append(record)
        gate["next_action"] = "Fully verify the private assembled archive against the current reader and plugin."
    else:
        gate["next_action"] = "Collect the workerless assembly result and drain its exact guard."


def owns(row):
    producer = row.get("producer", {})
    if producer.get("Id") != UNIT:
        return False
    _, required = registration()
    assert row["epoch"] == 226 and row["phase"] == "diagnostic-qualification"
    assert producer["InvocationID"] == required["invocation_id"]
    assert row["ordinary_replay_claim"] is False and row["current_sidecar_eta_valid"] is False
    assert row["scratch_path"] == ROOT
    return True
