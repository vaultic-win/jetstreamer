"""Enroll the exact private epoch 226 archive verifier in Foundation's cadence."""

from pathlib import Path

from ordinary249.delivery248 import V, bound, props, ref


UNIT = "foundation-226-assembly-read-verification-v1.service"
PHASE = "private-assembly-verification"
STATE = V / "horizon226-postassembly-verification-v1"
ROOT = V / "horizon226-verification-fleet-v1"
FIELDS = ["Id", "ActiveState", "SubState", "InvocationID", "MainPID", "NRestarts", "ControlGroup"]


def registration():
    document = STATE / "cadence-registration.json"
    if not document.is_file():
        return None
    reference = ref(document)
    launch = bound(reference)
    plan = bound(launch["plan"])
    release = bound(ref(ROOT / "acceptance.json"))
    assert launch["schema"] == "foundation-epoch226-assembly-verification-launch-v1"
    assert launch["actual"]["Id"] == UNIT and launch["epoch"] == plan["epoch"] == 226
    assert launch["plan"]["path"] == str(STATE / "plan.json")
    assert launch["roster"] == plan["roster"] and launch["terminal"] == plan["terminal"]
    assert launch["image"] == release["runner"] and launch["archive_copy_bytes"] == 0
    assert launch["publication_authorized"] is False
    return reference, launch


def configuration():
    registered = registration()
    if registered is None:
        return []
    _, launch = registered
    live = props(UNIT, FIELDS)
    if live["ActiveState"] in ("inactive", "failed"):
        assert live["MainPID"] == "0" and not live["ControlGroup"]
        return []
    assert (live["Id"], live["ActiveState"], live["SubState"], live["NRestarts"]) == (UNIT, "active", "running", "0")
    assert live["ControlGroup"] == "/system.slice/" + UNIT
    assert all(live[field] == launch["actual"][field] for field in ("InvocationID", "MainPID"))
    image = launch["image"]
    assert (Path("/proc") / live["MainPID"] / "exe").samefile(image["path"])
    return [dict(epoch=226, unit=UNIT, expected_invocation_id=live["InvocationID"],
                 main_pid=int(live["MainPID"]), scratch_path=str(STATE), executable=image["path"],
                 executable_sha256=image["sha256"])]


def register(plan):
    registered = registration()
    if registered is None:
        return False
    reference, launch = registered
    actual = launch["actual"]
    claim = dict(epoch=226, phase=PHASE, unit=UNIT, invocation_id=actual["InvocationID"],
                 expected_exec_start=actual["ExecStart"], evidence=[reference, launch["plan"]])
    claims = plan.setdefault("pipeline_claims", [])
    existing = [item for item in claims if item["unit"] == UNIT]
    assert not existing or existing == [claim]
    if not existing:
        claims.append(claim)
    gate = plan["gates"]["226"]
    if reference not in gate["evidence"]:
        gate["evidence"].append(reference)
    gate["next_action"] = "Accept the exact private reader and plugin verification receipts before canonical import."
    return True


def owns(row):
    if row.get("unit", {}).get("Id") != UNIT:
        return False
    reference, launch = registration()
    assert row["epoch"] == 226 and row["phase"] == PHASE and row["live"]
    assert row["expected_invocation_id"] == row["unit"]["InvocationID"] == launch["actual"]["InvocationID"]
    assert row["evidence"] == [reference, launch["plan"]]
    assert row["ordinary_replay_claim"] is False and row["current_sidecar_eta_valid"] is False
    return True
