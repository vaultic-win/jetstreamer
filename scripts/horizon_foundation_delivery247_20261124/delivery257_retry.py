"""Bind epoch 257's ordinary delivery retry into the existing fleet cycle."""

from pathlib import Path

from ordinary249.delivery248 import V, bound, props, ref
import publication_handoff


STATE = V / "horizon257-current-reader-delivery-v2"
PREVIOUS = V / "horizon257-current-reader-delivery-v1"
RELEASE = V / "horizon257-delivery-rss-v3"
UNIT = "horizon-upload-257-current-reader-v2.service"
PREVIOUS_UNIT = "horizon-upload-257-current-reader-v1.service"
PLAN = {
    "path": str(STATE / "epoch-257-plan.json"),
    "sha256": "8f880f488d6732da513716d1dda8073451afe773906fc761f525223567b4dc49",
}
FIELDS = ["Id", "ActiveState", "SubState", "InvocationID", "MainPID", "ControlGroup", "Job"]


def registered():
    path = STATE / "pipeline-claim.json"
    if not path.is_file():
        return None
    reference = ref(path)
    claim = bound(reference)
    assert (claim["epoch"], claim["phase"], claim["unit"]) == (257, "upload-readback", UNIT)
    booking_ref, launch_ref = claim["evidence"]
    assert booking_ref == ref(STATE / "booking.json") and launch_ref == ref(STATE / "launch.json")
    booking, launch = bound(booking_ref), bound(launch_ref)
    assert booking["reader_plan"] == PLAN and launch["booking"] == booking_ref
    assert launch["owner"]["InvocationID"] == claim["invocation_id"]
    assert launch["owner"]["Id"] == UNIT and claim["expected_exec_start"] == launch["owner"]["ExecStart"]
    assert launch["process_start_ticks"] > 0
    timeout = bound(booking["previous_timeout"])
    assert timeout["manager"]["Id"] == PREVIOUS_UNIT and timeout["manager"]["Result"] == "timeout"
    prior = props(PREVIOUS_UNIT, ["ActiveState", "InvocationID", "MainPID", "ControlGroup", "Job"])
    assert prior["ActiveState"] in ("inactive", "failed") and prior["MainPID"] == "0"
    assert prior["InvocationID"] in ("", timeout["manager"]["InvocationID"])
    assert not prior["ControlGroup"] and not prior["Job"]
    return reference, claim, launch


def configuration(registration):
    reference, claim, launch = registration
    current = props(UNIT, FIELDS)
    if current["ActiveState"] in ("inactive", "failed"):
        assert current["InvocationID"] in ("", claim["invocation_id"])
        assert current["MainPID"] == "0" and not current["ControlGroup"] and not current["Job"]
        return None
    assert (current["ActiveState"], current["SubState"]) == ("active", "running")
    assert current["InvocationID"] == claim["invocation_id"]
    assert current["MainPID"] == launch["owner"]["MainPID"] and int(current["MainPID"]) > 1
    return dict(retry_unit=UNIT, invocation_id=current["InvocationID"],
                pid=int(current["MainPID"]), claim_sha256=reference["sha256"])


def image(kind, name):
    release = bound(ref(RELEASE / "acceptance.json"))
    assert release["schema"] == "foundation-epoch257-delivery-rss-retry-release-v1"
    assert release["reader_plan"] == PLAN
    assert release[kind]["path"] == str(RELEASE / name)
    return Path(publication_handoff.checked_image(release[kind]))


def initial_status(current, registration):
    for directory, phase in (("active-status", "verification"), ("upload-status", "upload")):
        path = STATE / directory / "completion.json"
        if not path.is_file():
            continue
        reference = ref(path)
        done = bound(reference)
        intent = bound(done["intent"])
        assert done["key"] == "epoch-257.epoch-status.json" and done["authenticated_exact_byte_readback"]
        assert intent["owner"]["claim"] == registration[0]
        assert intent["payload"]["phase"] == phase and bound(done["readback"]) == intent["payload"]
        if bound(current) == bound(intent["previous"]):
            current = reference
        else:
            assert bound(bound(current)["readback"])["sampled_at_utc"] >= intent["payload"]["sampled_at_utc"]
    return current


def register_fleet(plan, registration, active, add):
    reference, claim, _ = registration
    prior = [row for row in plan["pipeline_claims"] if row["unit"] == UNIT]
    if prior:
        assert prior == [claim] and plan["tracked_units"].count(UNIT) == 1
    else:
        assert UNIT not in plan["tracked_units"]
        plan["tracked_units"].append(UNIT)
        plan["pipeline_claims"].append(claim)
    gate = plan["gates"]["257"]
    add(gate, reference, *claim["evidence"])
    if active:
        gate["next_action"] = "Complete eight-worker verification and authenticated epoch 257 delivery."


def collect(registration, statuses, record):
    reference, claim, _ = registration
    wd = STATE / "publication"
    marker = wd / "completion.json"
    if marker.is_file():
        completion = bound(ref(marker))
        assert completion["claim"] == reference
        assert bound(completion["deletion"])["authenticated_status_absent_after"]
        return ref(marker)
    archive = STATE / "receipts/epoch-257.r2.json"
    if not archive.is_file() or publication_handoff.drained(claim) is None:
        return None
    archive_ref = ref(archive)
    receipt = bound(archive_ref)
    booking = bound(claim["evidence"][0])
    source = bound(booking["closed_producer"])["archive"]
    assert (receipt["epoch"], receipt["archive_key"], receipt["checksum_key"]) == (
        257, "epoch-257.jet", "epoch-257.jet.sha256")
    assert receipt["archive_length"] == source["committed_stamp"]["length"]
    assert receipt["archive_sha256"] == source["sha256"] and receipt["remote_sha256_readback"]
    playback = bound(receipt["current_reader_playback"])
    assert playback["reader_plan"] == PLAN and playback["epoch"] == 257
    assert playback["local_playback"] and playback["remote_playback"]
    spec = dict(bucket=receipt["bucket"], archive_directory=str(Path(source["path"]).parent),
                receipt_directory=str(archive.parent))
    terminal = publication_handoff.terminal_evidence(claim)
    wd.mkdir(mode=0o700, exist_ok=True)
    intent_path = wd / "handoff-intent.json"
    if not intent_path.is_file():
        record(intent_path, dict(claim=reference, archive=archive_ref, terminal=terminal, status=statuses[257]))
    intent = bound(ref(intent_path))
    assert (intent["claim"], intent["archive"], intent["terminal"]) == (reference, archive_ref, terminal)
    deletion = publication_handoff.status_cleanup(
        257, reference, spec, {"archive": archive_ref}, intent["status"], wd, record)
    return record(marker, dict(claim=reference, archive=archive_ref,
        playback=receipt["current_reader_playback"], deletion=deletion,
        ready=True, local_retirement_authorized=False, capacity_released=False))
