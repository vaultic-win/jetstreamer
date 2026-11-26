"""Register the epoch 261 uploader in the existing Foundation cadence."""

from pathlib import Path

from ordinary249.delivery248 import V, bound, props, ref
import publication_handoff
import seven_status


STATE = V / "horizon261-current-reader-delivery-v1"
PREPARATION = V / "horizon261-current-reader-preparation-v1"
RELEASE = V / "horizon261-delivery-fleet-v1"
UNIT = "horizon-upload-261-current-reader-v1.service"
PLAN = {
    "path": str(PREPARATION / "epoch-261-plan.json"),
    "sha256": "e0b08c8ffdd57dba7d3e24cb4bb24990aae95d88d9ec2e577a4962899c5736f1",
}


def registered():
    path = STATE / "pipeline-claim.json"
    if not path.is_file():
        return None
    reference = ref(path)
    claim = bound(reference)
    assert (claim["epoch"], claim["phase"], claim["unit"]) == (261, "upload-readback", UNIT)
    booking_ref, launch_ref = claim["evidence"]
    assert booking_ref == ref(STATE / "booking.json") and launch_ref == ref(STATE / "launch.json")
    booking, launch = bound(booking_ref), bound(launch_ref)
    assert booking["reader_plan"] == PLAN and launch["booking"] == booking_ref
    assert launch["owner"]["InvocationID"] == claim["invocation_id"]
    assert launch["owner"]["Id"] == UNIT and launch["owner"]["ExecStart"] == claim["expected_exec_start"]
    assert launch["process_start_ticks"] > 0
    return reference, claim, launch


def configuration(registration):
    reference, claim, launch = registration
    current = props(UNIT, ["ActiveState", "SubState", "InvocationID", "MainPID", "ControlGroup", "Job"])
    if current["ActiveState"] in ("inactive", "failed"):
        assert current["InvocationID"] in ("", claim["invocation_id"])
        assert current["MainPID"] == "0" and not current["ControlGroup"] and not current["Job"]
        return None
    assert (current["ActiveState"], current["SubState"]) == ("active", "running")
    assert current["InvocationID"] == claim["invocation_id"]
    assert current["MainPID"] == launch["owner"]["MainPID"] and int(current["MainPID"]) > 1
    return dict(invocation_id=current["InvocationID"], pid=int(current["MainPID"]),
                claim_sha256=reference["sha256"])


def owns(row):
    return row["epoch"] == 261 and row["phase"] == "upload-readback" and row["unit"]["Id"] == UNIT


def refresh(previous, sample, cycle, registration):
    reference, claim, _ = registration
    booking = bound(claim["evidence"][0])
    source = bound(booking["closed_producer"])["archive"]
    length = source["identity"]["length"]
    assert length > 0 and source["path"].endswith("/output/epoch-261.jet")
    seven_status.refresh(261, previous, sample, dict(cycle, roster={261: reference}), archive_length=length)


def image(kind, name):
    release = bound(ref(RELEASE / "acceptance.json"))
    assert release["schema"] == "foundation-epoch261-delivery-fleet-release-v1"
    assert release["reader_plan"] == PLAN and release[kind]["path"] == str(RELEASE / name)
    return publication_handoff.checked_image(release[kind])


def register_fleet(plan, registration, active, add):
    reference, claim, _ = registration
    prior = [row for row in plan["pipeline_claims"] if row["unit"] == UNIT]
    if prior:
        assert prior == [claim] and plan["tracked_units"].count(UNIT) == 1
    else:
        assert UNIT not in plan["tracked_units"]
        plan["tracked_units"].append(UNIT)
        plan["pipeline_claims"].append(claim)
    gate = plan["gates"]["261"]
    add(gate, reference, *claim["evidence"])
    if active:
        gate.update(state="post-replay-pipeline",
                    next_action="Complete epoch 261 archive verification and authenticated R2 delivery.")


def collect(registration, statuses, record):
    reference, claim, _ = registration
    directory = STATE / "publication"
    marker = directory / "completion.json"
    if marker.is_file():
        completion = bound(ref(marker))
        assert completion["claim"] == reference
        assert bound(completion["deletion"])["authenticated_status_absent_after"]
        return ref(marker)
    archive = PREPARATION / "receipts/epoch-261.r2.json"
    if not archive.is_file() or publication_handoff.drained(claim) is None:
        return None
    archive_ref = ref(archive)
    receipt = bound(archive_ref)
    booking = bound(claim["evidence"][0])
    source = bound(booking["closed_producer"])["archive"]
    assert (receipt["epoch"], receipt["archive_key"], receipt["checksum_key"]) == (
        261, "epoch-261.jet", "epoch-261.jet.sha256")
    assert receipt["archive_length"] == source["identity"]["length"]
    assert receipt["archive_sha256"] == source["sha256"] and receipt["remote_sha256_readback"]
    playback = bound(receipt["current_reader_playback"])
    assert playback["reader_plan"] == PLAN and playback["epoch"] == 261
    assert playback["local_playback"] and playback["remote_playback"]
    spec = dict(bucket=receipt["bucket"], archive_directory=str(Path(source["path"]).parent),
                receipt_directory=str(archive.parent))
    terminal = publication_handoff.terminal_evidence(claim)
    directory.mkdir(mode=0o700, exist_ok=True)
    intent_path = directory / "handoff-intent.json"
    if not intent_path.is_file():
        record(intent_path, dict(claim=reference, archive=archive_ref, terminal=terminal, status=statuses[261]))
    intent = bound(ref(intent_path))
    assert (intent["claim"], intent["archive"], intent["terminal"]) == (reference, archive_ref, terminal)
    deletion = publication_handoff.status_cleanup(
        261, reference, spec, {"archive": archive_ref}, intent["status"], directory, record)
    return record(marker, dict(claim=reference, archive=archive_ref,
        playback=receipt["current_reader_playback"], deletion=deletion,
        ready=True, local_retirement_authorized=False, capacity_released=False))
