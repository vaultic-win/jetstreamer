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
JOIN = V / "horizon230-continuation-join-7f90bbed-v1/completion.json"
SUCCESSOR = V / "horizon231-232-input-readmission-v300"
REPLAY231 = V / "horizon231-capped-replay-v1"
UNIT231 = "horizon-perf-epoch231-capped-replay@v1.service"
ROOT231 = Path("/home/ubuntu/.jetstreamer-private/epoch231-capped-replay-tmpfs-v1/run")
STOCK231 = V / "horizon231-stock-warmup-v1"
STOCK_UNIT231 = "horizon-perf-epoch231-stock-warmup@v1.service"
STOCK_ROOT231 = Path("/home/ubuntu/.jetstreamer-private/epoch231-stock-warmup-tmpfs-v1/run")
STOCK_WORKER_SHA231 = "f39140b9a9659e7c6e8207076a2d0c560a6b69df42cc92e19a421cf46c2b761c"
DEMOTION231 = V / "horizon231-demotion-v1"
DEMOTION_UNIT231 = "horizon-perf-epoch231-program-demotion@v1.service"
DEMOTION_ROOT231 = Path("/home/ubuntu/.jetstreamer-private/epoch231-demotion-tmpfs-v1/run")
RUNS231 = {
    UNIT231: (REPLAY231, ROOT231, "epoch231-capped-checkpoint-replay"),
    STOCK_UNIT231: (STOCK231, STOCK_ROOT231, "epoch231-stock-warmup"),
    DEMOTION_UNIT231: (DEMOTION231, DEMOTION_ROOT231, "epoch231-program-demotion"),
}
INPUTS231 = {
    "path": str(V / "horizon231-capped-replay-checkpoints-v1/inputs.json"),
    "sha256": "9a9328d1863ac8b041c8283ffc73021b91dd7f874a13fa401de93956487a4227",
}


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


def configuration230():
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


def receipt231(unit):
    package, root, kind = RUNS231[unit]
    path = package / "cadence-registration.json"
    if not path.is_file():
        return None
    metadata = path.lstat()
    assert path.resolve() == path and metadata.st_uid == 0 and metadata.st_nlink == 1
    assert not metadata.st_mode & 0o222
    source = ref(path)
    row = bound(source)
    assert row["schema"] == "jetstreamer-historical-performance-launch-receipt-v1"
    assert (row["epoch"], row["unit"], row["kind"]) == (231, unit, kind)
    assert row["run_root"] == str(root) and row["last_slot"] == 99_803_089
    assert row["launched"] and row["entry_replay_requested"]
    assert all(row[key] is False for key in ("canonical_epoch_publication_authorized", "remote_mutations",
                                            "r2_mutations", "full_cohort_resource_qualified"))
    iid = row["invocation_id"]
    assert re.fullmatch("[0-9a-f]{32}", iid) and row["main_pid"] > 0
    admission = bound(row["admission"])
    inputs = bound(INPUTS231)
    assert admission["admitted"] and admission["inputs"] == INPUTS231
    expected_worker = STOCK_WORKER_SHA231 if unit == STOCK_UNIT231 else inputs["worker_sha256"]
    if unit == DEMOTION_UNIT231:
        profile = bound(admission["profile"])
        pair = bound(profile["pair"])
        assert pair["schema"] == "foundation-epoch231-program-demotion-pair-v1"
        assert pair["parent"] == profile["node"] and pair["worker"] == profile["worker"]
        assert pair["parent"]["path"] == row["node_path"] and not pair["publication_authorized"]
        expected_worker = pair["worker"]["sha256"]
    assert row["worker_sha256"] == expected_worker
    guard = bound(row["active_guard"])
    assert guard["producer_invocation_id"] == iid and guard["producer"]["pid"] == row["main_pid"]
    assert guard["producer_stop_enabled"] and guard["trip_reason"] is None
    assert guard["plan_sha256"] == row["guard_plan"]["sha256"]
    return source, row


def configuration():
    configured = configuration230()
    for unit in RUNS231:
        registered = receipt231(unit)
        if registered is None:
            continue
        _, row = registered
        live = props(unit, FIELDS)
        if live["ActiveState"] in ("inactive", "failed"):
            assert live["MainPID"] == "0" and not live["ControlGroup"]
            continue
        assert (live["Id"], live["ActiveState"], live["SubState"]) == (unit, "active", "running")
        assert (live["InvocationID"], int(live["MainPID"])) == (row["invocation_id"], row["main_pid"])
        assert live["ControlGroup"] == "/system.slice/" + unit and live["NRestarts"] == "0"
        assert (Path("/proc") / live["MainPID"] / "exe").samefile(row["node_path"])
        configured.append(dict(range="231-231", controller_unit=unit,
            expected_controller_invocation_id=row["invocation_id"], producer_unit=unit,
            expected_producer_invocation_id=row["invocation_id"], scratch_path=row["run_root"],
            worker_executable_basename="historical-worker"))
    assert sum(row["range"] == "231-231" for row in configured) <= 1
    return configured


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
    if JOIN.is_file():
        join_ref = ref(JOIN)
        assert join_ref["sha256"] == "37622f493445c37c4b38e07e4f58cac680b24b3a4a28c7b46e9b633d740a01f7"
        join = bound(join_ref)
        assert join["native"]["consensus_handoff_passed"] and join["native"]["merge"]["slots"] == 23_573
        assert join["remaining_slots"] == 408_427 and not join["canonical_publication_authorized"]
        if join_ref not in gate["evidence"]:
            gate["evidence"].append(join_ref)
        gate["next_action"] = (
            "The private join passed through slot 99,383,572. Fund the remaining 408,427 slots "
            "and qualify the full archive assembly and publication route."
        )
    deployment = bound(ref(PACKAGE / "fleet-tool.json"))
    assert deployment["schema"] == "foundation-epoch230-checkpoint-continuation-fleet-tool-v1"
    return deployment["artifact"]


def register_successor_inputs(plan):
    if not (SUCCESSOR / "compact-acquisition-complete.json").is_file():
        return
    pins = {
        "completion.json": "64d9a4d7bc6aba0f8e0662dd8763ad96804647504b6d3e6b5a3788a1f876f174",
        "compact-acquisition-complete.json": "8ddf2dfcb03f8b2c3dfae805d616519ab6bcffb76be0344f656806fbc59c9018",
        "native-manifest-controls.json": "8b21a5d3b5f2bffbc66e7817c8593dfb7b8fc46da6a1669e1a2b0a51509a40a2",
        "root-catalog.json": "c48c23ca0cd9fee2bf0ec318661dd5d14c5446a4dba0a026d8dd157bdabd8eb2",
        "source-boundary-231.json": "5bc465ecaaa5d52ef71bcd1b2217e607615e67fd807ee56a481bcaddfa165aee",
        "source-boundary-232.json": "d274111912011c5540d7c8710edab747d1059b56648cabadf9cfeb8b7c4b16a5",
        "source-boundary-233.json": "30470045346a504c8f6b0bda47870435d6e75a57c6818cfd23ba4a98c8800ac7",
    }
    evidence = [dict(path=str(SUCCESSOR / name), sha256=sha) for name, sha in pins.items()]
    restore, indexes, manifest, *_ = map(bound, evidence)
    assert restore["epochs"] == manifest["epochs"] == [231, 232]
    assert len(indexes["indexes"]) == 5 and not indexes["replay_started"]
    for epoch in ("231", "232"):
        gate = plan["gates"][epoch]
        for receipt in evidence:
            if receipt not in gate["evidence"]:
                gate["evidence"].append(receipt)
        if gate["state"] == "not-yet-staged":
            gate["next_action"] = (
                "The generation-pinned bootstrap, five compact indexes, original cohort manifest and native "
                "source edges are ready. Book the two-epoch replay and output capacity, then qualify the guarded producer."
            )
    checkpoint = Path(INPUTS231["path"])
    if checkpoint.is_file():
        inputs = bound(INPUTS231)
        assert inputs["epoch"] == 231 and inputs["checkpoint_slot"] == 99_803_089
        gate = plan["gates"]["231"]
        if INPUTS231 not in gate["evidence"]:
            gate["evidence"].append(INPUTS231)
        gate["next_action"] = "Qualify capped-worker growth through the generation-pinned checkpoint at slot 99,803,089."
        register_warmup231(plan, gate)


def register_warmup231(plan, gate):
    for unit, (package, _, _) in RUNS231.items():
        registered = receipt231(unit)
        if registered is not None:
            source, row = registered
            claim = dict(epoch=231, unit=unit, invocation_id=row["invocation_id"],
                         scratch_path=row["run_root"], launch_receipt=source)
            diagnostics = plan.setdefault("diagnostics", [])
            previous = [owner for owner in diagnostics if owner["unit"] == unit]
            assert not previous or previous == [claim]
            if unit not in plan["tracked_units"]:
                plan["tracked_units"].append(unit)
            if source not in gate["evidence"]:
                gate["evidence"].append(source)
            if unit == STOCK_UNIT231:
                gate["next_action"] = "Measure the stock runtime at the finalized warmup vote in slot 99,791,499."
            if unit == DEMOTION_UNIT231:
                gate["next_action"] = "Compare Bank 99,791,498 with the finalized vote and verify the hourly AccountsDb root."
            terminal = package / "terminal.json"
            if terminal.is_file():
                terminal_ref = ref(terminal)
                result = bound(terminal_ref)
                assert result["registration"] == source and not result["publication_authorized"]
                if terminal_ref not in gate["evidence"]:
                    gate["evidence"].append(terminal_ref)
                gate["next_action"] = result["next_action"]
                live = props(unit, FIELDS)
                assert live["ActiveState"] in ("inactive", "failed")
                assert live["MainPID"] == "0" and not live["ControlGroup"]
                diagnostics[:] = [owner for owner in diagnostics if owner["unit"] != unit]
            elif not previous:
                diagnostics.append(claim)


def owns(row):
    producer = row.get("producer", {})
    unit = producer.get("Id")
    if unit in RUNS231:
        _, registration = receipt231(unit)
        assert row["epoch"] == 231 and row["phase"] == "diagnostic-qualification"
        assert producer["InvocationID"] == registration["invocation_id"] and row["scratch_path"] == registration["run_root"]
        assert row["ordinary_replay_claim"] is False and row["current_sidecar_eta_valid"] is False
        return True
    if producer.get("Id") != UNIT:
        return False
    _, registration = receipt()
    assert row["epoch"] == 230 and row["phase"] == "diagnostic-qualification"
    assert producer["InvocationID"] == registration["invocation_id"]
    assert row["ordinary_replay_claim"] is False and row["current_sidecar_eta_valid"] is False
    assert row["scratch_path"] == str(RUN_ROOT)
    return True
