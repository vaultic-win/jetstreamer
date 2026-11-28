"""Enroll the exact Foundation private holding process in the cadence."""

from pathlib import Path

from ordinary249.delivery248 import V, bound, props, ref


UNIT = "foundation-288-closed-partial-custody-v1.service"
ROOT = V / "horizon288-full-partial-custody-hash-v1"
RELEASE = V / "horizon288-closed-partial-custody-tools-v1/acceptance.json"
RELEASE_SHA = "a2f615b0808834bf88f60450a0397dd4eb0965e9cf0a07db88f02981f159bf5f"
FIELDS = ["Id", "ActiveState", "SubState", "InvocationID", "MainPID", "NRestarts", "ControlGroup"]


def registration():
    document = ROOT / "park-launch.json"
    if not document.is_file():
        return None
    reference = ref(document)
    launch = bound(reference)
    admission_ref = launch["admission"]
    assert admission_ref["path"] == str(ROOT / "park-admission.json")
    admission = bound(admission_ref)
    release = bound({"path": str(RELEASE), "sha256": RELEASE_SHA})
    assert launch["schema"] == "foundation-epoch288-partial-custody-launch-v1"
    assert admission["schema"] == "foundation-epoch288-partial-custody-admission-v1"
    assert admission["unit"] == launch["actual"]["Id"] == UNIT
    assert admission["binary"] == release["tools"]["jetstreamer-r2"]
    assert admission["source"] == release["source"]
    assert admission["publication_authorized"] is False and admission["retirement_authorized"] is False
    return reference, launch, admission


def configuration():
    registered = registration()
    if registered is None:
        return []
    _, launch, admission = registered
    live = props(UNIT, FIELDS)
    if live["ActiveState"] in ("inactive", "failed"):
        assert live["MainPID"] == "0" and not live["ControlGroup"]
        return []
    assert (live["ActiveState"], live["SubState"], live["NRestarts"]) == ("active", "running", "0")
    assert live["ControlGroup"] == "/system.slice/" + UNIT
    assert all(live[field] == launch["actual"][field] for field in ("Id", "InvocationID", "MainPID"))
    image = admission["binary"]
    assert (Path("/proc") / live["MainPID"] / "exe").samefile(image["path"])
    return [dict(epoch=288, unit=UNIT, expected_invocation_id=live["InvocationID"],
                 main_pid=int(live["MainPID"]), scratch_path=str(ROOT), executable=image["path"],
                 executable_sha256=image["sha256"])]


def register(plan):
    registered = registration()
    if registered is None:
        return False
    reference, launch, _ = registered
    actual = launch["actual"]
    claim = dict(epoch=288, phase="private-holding", unit=UNIT, invocation_id=actual["InvocationID"],
                 expected_exec_start=actual["ExecStart"], evidence=[reference, launch["admission"]])
    claims = plan.setdefault("pipeline_claims", [])
    previous = [entry for entry in claims if entry["unit"] == UNIT]
    assert not previous or previous == [claim]
    if not previous:
        claims.append(claim)
    gate = plan["gates"]["288"]
    if reference not in gate["evidence"]:
        gate["evidence"].append(reference)
    gate["next_action"] = "Verify encrypted holding custody and confirm the exact local retirement requirements."
    return True
