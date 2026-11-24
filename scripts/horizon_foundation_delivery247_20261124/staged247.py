"""Select the invocation-bound publisher for the existing epoch 247 archive."""

import re
from pathlib import Path

from ordinary249.delivery248 import D, V, bound, props
from staged211 import sealed

EPOCH = 247
UNIT = "horizon-upload-247-pinned-public-v254.service"
PREDECESSOR = "horizon-upload-247-staged-58709604-v221.service"
ROOT = D / UNIT.removesuffix(".service")
REGISTRATION = ROOT / "cadence-registration.json"
STATE = Path("/home/ubuntu/.jetstreamer-private/current-reader-delivery-247-pinned-public-v254")
PREPARATION_SHA = "59e28b3e36771109aee30420430aac869d526e09d487000c3483fa87a6e0d84f"
OBSERVER = V / "horizon247-pinned-public-observer-v254" / "jetstreamer-horizon-observe"
OBSERVER_SHA = "81d9c61e3914fd07548612adb0c299d8ebc42f955047d38ba9e7f959f0362e0a"
FLEET_PACKAGE = V / "horizon-pinned247-fleet-v254"
OLD_STATUS = {
    "path": "/home/ubuntu/.jetstreamer-private/foundation-publication-status-repair.aIkorzZ0/247/completion.json",
    "sha256": "de26b49d2242c0115770277e55105fd6f16ed7fde2843f093a1a4495476ce801",
}


def fleet_image():
    package = bound(sealed(FLEET_PACKAGE / "acceptance.json"))
    assert package["schema"] == "foundation-epoch247-pinned-fleet-release-v1"
    image = FLEET_PACKAGE / "jetstreamer-r2"
    assert package["image"] == sealed(image)
    return image


def load(original):
    if not REGISTRATION.exists():
        assert not REGISTRATION.is_symlink()
        return None

    pointer = sealed(REGISTRATION)
    data = bound(pointer)
    assert set(data) == {
        "schema", "epoch", "predecessor", "predecessor_status", "claim", "spec", "initial_status",
    }
    assert data["schema"] == "foundation-staged-247-cadence-registration-v1"
    assert data["epoch"] == EPOCH and data["predecessor"] == original["claim"]
    assert data["predecessor_status"] == OLD_STATUS
    previous = bound(data["predecessor"])
    assert previous["unit"] == PREDECESSOR and previous["epoch"] == EPOCH
    terminal = props(PREDECESSOR, ["InvocationID", "ActiveState", "MainPID", "ControlPID",
                                  "ControlGroup", "Job", "NRestarts"])
    assert terminal["InvocationID"] == previous["invocation_id"] and terminal["ActiveState"] == "failed"
    assert terminal["MainPID"] == terminal["ControlPID"] == terminal["NRestarts"] == "0"
    assert not terminal["ControlGroup"] and not terminal["Job"]

    assert data["claim"] == sealed(ROOT / "pipeline-claim.json")
    assert data["spec"] == sealed(ROOT / "publication-spec.json")
    claim = bound(data["claim"])
    iid = claim["invocation_id"]
    assert claim["epoch"] == EPOCH and claim["unit"] == UNIT and claim["phase"] == "upload-readback"
    assert re.fullmatch(r"[0-9a-f]{32}", iid) and iid != previous["invocation_id"]
    assert claim["evidence"] == [sealed(ROOT / "booking.json"), sealed(ROOT / "launch.json")]
    booking, launch = (bound(item) for item in claim["evidence"])
    assert booking["handoff"] == original["handoff"] and launch["booking"] == claim["evidence"][0]

    preparation = sealed(STATE / "preparation.json")
    assert preparation["sha256"] == PREPARATION_SHA and booking["preparation"] == preparation
    prepared = bound(preparation)
    args = prepared["intended_argv"]
    plan = sealed(STATE / "epoch-247-plan.json")
    assert prepared["publication_plan"] == plan
    assert prepared["uploader"] == sealed(Path(args[0])) and booking["argv"] == args
    assert claim["expected_exec_start"].startswith(
        f"{{ path={args[0]} ; argv[]={' '.join(args)} ; ignore_errors=no ; start_time="
    )
    started = launch["unit"]
    assert started["Id"] == UNIT and started["InvocationID"] == iid
    assert started["ExecStart"] == claim["expected_exec_start"] and started["ActiveState"] == "active"
    pid = int(started["MainPID"])
    assert pid > 1 and int(started["MemoryMax"]) == 24 << 30
    assert bound(data["spec"]) == dict(
        bound(original["spec"]), uploader_pid=pid, reader_plan=plan,
        receipt_directory=str(STATE / "receipts"),
    )

    assert data["initial_status"] == sealed(ROOT / "initial-status" / "completion.json")
    initial = bound(data["initial_status"])
    intent = bound(initial["intent"])
    status = bound(initial["readback"])
    assert initial["key"] == "epoch-247.epoch-status.json" and initial["authenticated_exact_byte_readback"]
    assert intent["previous"] == OLD_STATUS and intent["key"] == initial["key"]
    owner = {"claim": data["claim"], "unit": UNIT, "invocation_id": iid}
    assert intent["owner"] == owner and intent["payload"] == status
    assert status["epoch"] == EPOCH and status["phase"] == "verification"
    assert status["jet_size_bytes"] == prepared["staged_object"]["archive_length"]
    assert status["estimated_remaining_millis"] > 0
    previous_status = bound(bound(OLD_STATUS)["readback"])
    assert status["sampled_at_utc"] > previous_status["sampled_at_utc"]

    observer = sealed(OBSERVER)
    assert observer["sha256"] == OBSERVER_SHA
    return dict(data, registration=pointer, observer=observer, configuration={
        "pid": pid, "invocation_id": iid, "claim_sha256": data["claim"]["sha256"], "retry_unit": UNIT,
    })


def adopt_status(current, successor):
    if current is None:
        return None
    if current == OLD_STATUS:
        return successor["initial_status"]
    owner = bound(bound(current)["intent"])["owner"]
    assert owner == {
        "claim": successor["claim"], "unit": UNIT,
        "invocation_id": successor["configuration"]["invocation_id"],
    }
    return current
