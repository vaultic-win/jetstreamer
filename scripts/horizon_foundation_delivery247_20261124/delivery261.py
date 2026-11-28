"""Register current-reader uploaders in the existing Foundation cadence."""

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


def scope(epoch):
    if epoch == 261:
        return STATE, PREPARATION, UNIT, PLAN
    assert epoch == 252
    return (V / "horizon252-current-reader-delivery-v1",
            V / "horizon252-current-reader-preparation-v1",
            "horizon-upload-252-current-reader-v1.service",
            {"path": str(V / "horizon252-current-reader-plan-v1/epoch-252-plan.json"),
             "sha256": "6ba28009779196b5e3cfa7d899c9a671df20c79f1230770b98e90a000a3de7e7"})


def registered(epoch=261):
    state, _, unit, reader = scope(epoch)
    path = state / "pipeline-claim.json"
    if not path.is_file():
        return None
    reference = ref(path)
    claim = bound(reference)
    assert (claim["epoch"], claim["phase"], claim["unit"]) == (epoch, "upload-readback", unit)
    booking_ref, launch_ref = claim["evidence"]
    assert booking_ref == ref(state / "booking.json") and launch_ref == ref(state / "launch.json")
    booking, launch = bound(booking_ref), bound(launch_ref)
    assert booking["reader_plan"] == reader and launch["booking"] == booking_ref
    assert launch["owner"]["InvocationID"] == claim["invocation_id"]
    assert launch["owner"]["Id"] == unit and launch["owner"]["ExecStart"] == claim["expected_exec_start"]
    assert launch["process_start_ticks"] > 0
    return reference, claim, launch


def configuration(registration, epoch=261):
    reference, claim, launch = registration
    _, _, unit, _ = scope(epoch)
    current = props(unit, ["ActiveState", "SubState", "InvocationID", "MainPID", "ControlGroup", "Job"])
    if current["ActiveState"] in ("inactive", "failed"):
        assert current["InvocationID"] in ("", claim["invocation_id"])
        assert current["MainPID"] == "0" and not current["ControlGroup"] and not current["Job"]
        return None
    assert (current["ActiveState"], current["SubState"]) == ("active", "running")
    assert current["InvocationID"] == claim["invocation_id"]
    assert current["MainPID"] == launch["owner"]["MainPID"] and int(current["MainPID"]) > 1
    return dict(invocation_id=current["InvocationID"], pid=int(current["MainPID"]),
                claim_sha256=reference["sha256"])


def owns(row, epoch=261):
    return (row["epoch"] == epoch and row["phase"] == "upload-readback"
            and row["unit"]["Id"] == scope(epoch)[2])


def refresh(previous, sample, cycle, registration, epoch=261):
    reference, claim, _ = registration
    booking = bound(claim["evidence"][0])
    source = bound(booking["closed_producer"])["archive"]
    length = source["identity"]["length"]
    assert length > 0 and source["path"].endswith(f"/output/epoch-{epoch}.jet")
    seven_status.refresh(epoch, previous, sample, dict(cycle, roster={epoch: reference}), archive_length=length)


def image(kind, name, epoch=261):
    _, _, _, reader = scope(epoch)
    directory = RELEASE if epoch == 261 else V / "horizon252-delivery-fleet-v1"
    release = bound(ref(directory / "acceptance.json"))
    assert release["schema"] == f"foundation-epoch{epoch}-delivery-fleet-release-v1"
    assert release["reader_plan"] == reader and release[kind]["path"] == str(directory / name)
    return publication_handoff.checked_image(release[kind])


def register_fleet(plan, registration, active, add, epoch=261):
    reference, claim, _ = registration
    _, _, unit, _ = scope(epoch)
    prior = [row for row in plan["pipeline_claims"] if row["unit"] == unit]
    if prior:
        assert prior == [claim] and plan["tracked_units"].count(unit) == 1
    else:
        assert unit not in plan["tracked_units"]
        plan["tracked_units"].append(unit)
        plan["pipeline_claims"].append(claim)
    gate = plan["gates"][str(epoch)]
    add(gate, reference, *claim["evidence"])
    if active:
        gate.update(state="post-replay-pipeline",
                    next_action=f"Complete epoch {epoch} archive verification and authenticated R2 delivery.")


def collect(registration, statuses, record, epoch=261):
    reference, claim, _ = registration
    state, preparation, _, reader = scope(epoch)
    directory = state / "publication"
    marker = directory / "completion.json"
    if marker.is_file():
        completion = bound(ref(marker))
        assert completion["claim"] == reference
        assert bound(completion["deletion"])["authenticated_status_absent_after"]
        return ref(marker)
    archive = preparation / f"receipts/epoch-{epoch}.r2.json"
    if not archive.is_file() or publication_handoff.drained(claim) is None:
        return None
    archive_ref = ref(archive)
    receipt = bound(archive_ref)
    booking = bound(claim["evidence"][0])
    source = bound(booking["closed_producer"])["archive"]
    assert (receipt["epoch"], receipt["archive_key"], receipt["checksum_key"]) == (
        epoch, f"epoch-{epoch}.jet", f"epoch-{epoch}.jet.sha256")
    assert receipt["archive_length"] == source["identity"]["length"]
    assert receipt["archive_sha256"] == source["sha256"] and receipt["remote_sha256_readback"]
    playback = bound(receipt["current_reader_playback"])
    assert playback["reader_plan"] == reader and playback["epoch"] == epoch
    assert playback["local_playback"] and playback["remote_playback"]
    prior_owner = None
    if epoch == 252:
        producer = bound(booking["closed_producer"])
        assert producer["epoch"] == epoch and producer["state"] == "local-cohort-committed"
        prior_owner = dict(unit=producer["unit"], invocation_id=producer["invocation_id"])
    spec = dict(bucket=receipt["bucket"], archive_directory=str(Path(source["path"]).parent),
                receipt_directory=str(archive.parent))
    terminal = publication_handoff.terminal_evidence(claim)
    directory.mkdir(mode=0o700, exist_ok=True)
    intent_path = directory / "handoff-intent.json"
    if not intent_path.is_file():
        record(intent_path, dict(claim=reference, archive=archive_ref, terminal=terminal, status=statuses[epoch]))
    intent = bound(ref(intent_path))
    assert (intent["claim"], intent["archive"], intent["terminal"]) == (reference, archive_ref, terminal)
    args = (epoch, reference, spec, {"archive": archive_ref}, intent["status"], directory, record)
    deletion = publication_handoff.status_cleanup(
        *args, prior_owner=prior_owner) if prior_owner else publication_handoff.status_cleanup(*args)
    return record(marker, dict(claim=reference, archive=archive_ref,
        playback=receipt["current_reader_playback"], deletion=deletion,
        ready=True, local_retirement_authorized=False, capacity_released=False))
