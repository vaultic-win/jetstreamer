"""Bind the epoch 250 staged publisher to its predecessor and the existing cadence."""

import re
from pathlib import Path

from ordinary249.delivery248 import D, V, bound, props
from staged211 import sealed

EPOCH = 250
UNIT = "horizon-upload-250-staged-public-v257.service"
PREDECESSOR = "horizon-upload-250-ordinary-v221.service"
ROOT = D / UNIT.removesuffix(".service")
REGISTRATION = ROOT / "cadence-registration.json"
PACKAGE = V / "horizon250-staged-published-v257"
PLAN = PACKAGE / "epoch-250-plan.json"
PLAN_SHA = "e96999d456f560fcdc1e1c2c29d11bb4fac9adde7d127542112fe77451c49aa0"
STATE = Path("/home/ubuntu/.jetstreamer-private/current-reader-delivery-250-staged-published-v257")
IMAGE = V / "horizon211-staged-recovery-v1/jetstreamer-r2"
IMAGE_SHA = "7271de0e309c83f8fa2f35cf9091280a8b04f66c51d3175ad1d6ff02faa4c59d"
ETAG = "d152967aadd357c1ce79cea4df147e82-2766"
SIZE = 185599540324
MEMORY_CAP = 10 << 30
OLD_STATUS = {
    "path": "/home/ubuntu/.jetstreamer-private/foundation-publication-status-repair.aIkorzZ0/250/completion.json",
    "sha256": "d9647ae8fe9105eb9886f8a6e8360a6fe9dd2758c00bca77ad64575b24b276cf",
}


def expected_argv(spec):
    return [
        str(IMAGE), "sync", spec["archive_directory"], "--epochs", "250-250",
        "--receipt-directory", str(STATE / "receipts"), "--current-reader-plan", str(PLAN),
        "--current-reader-plan-sha256", PLAN_SHA, "--concurrency", "2",
        "--staged-archive-etag", ETAG, "--staged-archive-bytes", str(SIZE),
    ]


def load(original):
    if not REGISTRATION.exists():
        assert not REGISTRATION.is_symlink()
        return None
    pointer = sealed(REGISTRATION)
    registration = bound(pointer)
    assert set(registration) == {
        "schema", "epoch", "predecessor", "predecessor_status", "claim", "spec", "initial_status",
    }
    assert registration["schema"] == "foundation-staged-250-cadence-registration-v1"
    assert registration["epoch"] == EPOCH and registration["predecessor"] == original["claim"]
    assert registration["predecessor_status"] == OLD_STATUS
    prior = bound(original["claim"])
    assert prior["unit"] == PREDECESSOR and prior["epoch"] == EPOCH
    terminal = props(PREDECESSOR, ["InvocationID", "ActiveState", "MainPID", "ControlPID",
                                   "ControlGroup", "Job", "NRestarts"])
    assert terminal["InvocationID"] == prior["invocation_id"] and terminal["ActiveState"] == "failed"
    assert terminal["MainPID"] == terminal["ControlPID"] == terminal["NRestarts"] == "0"
    assert not terminal["ControlGroup"] and not terminal["Job"]

    assert registration["claim"] == sealed(ROOT / "pipeline-claim.json")
    assert registration["spec"] == sealed(ROOT / "publication-spec.json")
    claim = bound(registration["claim"])
    iid = claim["invocation_id"]
    assert claim["epoch"] == EPOCH and claim["unit"] == UNIT and claim["phase"] == "upload-readback"
    assert re.fullmatch(r"[0-9a-f]{32}", iid) and iid != prior["invocation_id"]
    assert claim["evidence"] == [sealed(ROOT / "booking.json"), sealed(ROOT / "launch.json")]
    booking, launch = map(bound, claim["evidence"])
    assert booking["handoff"] == original["handoff"] and launch["booking"] == claim["evidence"][0]

    proof = bound(sealed(PACKAGE / "acceptance.json"))
    assert proof["schema"] == "foundation-staged-250-publisher-release-v1"
    observer = sealed(PACKAGE / "jetstreamer-horizon-observe")
    fleet = sealed(PACKAGE / "jetstreamer-r2")
    plan = sealed(PLAN)
    assert proof["observer"] == observer and proof["fleet"] == fleet
    assert proof["plan"] == plan and plan["sha256"] == PLAN_SHA
    assert sealed(IMAGE)["sha256"] == IMAGE_SHA
    previous_spec = bound(original["spec"])
    args = expected_argv(previous_spec)
    assert booking["argv"] == args and previous_spec["archive_bytes"] == SIZE
    assert claim["expected_exec_start"].startswith(
        f"{{ path={args[0]} ; argv[]={' '.join(args)} ; ignore_errors=no ; start_time="
    )
    started = launch["unit"]
    assert started["Id"] == UNIT and started["InvocationID"] == iid
    assert started["ExecStart"] == claim["expected_exec_start"] and started["ActiveState"] == "active"
    pid = int(started["MainPID"])
    assert pid > 1 and int(started["MemoryMax"]) == MEMORY_CAP
    assert bound(registration["spec"]) == dict(
        previous_spec, uploader_pid=pid, reader_plan=plan, receipt_directory=str(STATE / "receipts"),
    )

    assert registration["initial_status"] == sealed(ROOT / "initial-status/completion.json")
    initial = bound(registration["initial_status"])
    intent = bound(initial["intent"])
    status = bound(initial["readback"])
    assert initial["key"] == "epoch-250.epoch-status.json" and initial["authenticated_exact_byte_readback"]
    assert intent["previous"] == OLD_STATUS and intent["key"] == initial["key"]
    assert intent["payload"] == status
    assert status["epoch"] == EPOCH and status["phase"] == "verification" and status["jet_size_bytes"] == SIZE
    assert status["estimated_remaining_millis"] > 0
    assert status["sampled_at_utc"] > bound(bound(OLD_STATUS)["readback"])["sampled_at_utc"]
    assert intent["owner"] == dict(claim=registration["claim"], unit=UNIT, invocation_id=iid)
    return dict(registration, registration=pointer, observer=observer, fleet=fleet, configuration={
        "pid": pid, "invocation_id": iid, "claim_sha256": registration["claim"]["sha256"], "retry_unit": UNIT,
    })


def adopt_status(current, successor):
    if current == OLD_STATUS:
        return successor["initial_status"]
    if current is not None:
        owner = bound(bound(current)["intent"])["owner"]
        assert owner == dict(
            claim=successor["claim"], unit=UNIT, invocation_id=successor["configuration"]["invocation_id"],
        )
    return current
