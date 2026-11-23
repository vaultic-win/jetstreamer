//! Running resource ownership for the guarded epoch 257 cold bootstrap.
use super::native265::{
    EvidenceReader, FsEvidence, binding, deny, hex, namespace, num, sealed, text,
};
use super::*;
pub(super) const UNIT: &str = "horizon-257-native-input-20261120-v1.service";
pub(super) const GUARD_UNIT: &str = "horizon-native257-protective-v1.service";
pub(super) const TIMER: &str = "horizon-native257-protective-v1.timer";
pub(super) const RETAIN: &str = "horizon-native257-terminal-retention.target";
pub(super) const ROOT: &str =
    "/home/ubuntu/.jetstreamer-private/native-input257-selected-20261120-v1";
pub(super) const TEST: &str =
    "/var/lib/jetstreamer/horizon257-native-input-limited-20261120-v1/horizon257-native-input";
pub(super) const TEST_SHA: &str =
    "b8f52e2de7bf4f6232ea66137bb148bb6fb5b3342ce354379f4c237c70c39fce";
pub(super) const GUARD: &str =
    "/var/lib/jetstreamer/horizon257-native-guard-limited-20261120-v1/horizon257-native-guard";
pub(super) const GUARD_SHA: &str =
    "cd20c10244bb4a3a9818a6e459163be1f596165e859b2783f76a2507b8425369";
pub(super) const PROFILE: native265_guard::SampleProfile = native265_guard::SampleProfile {
    unit: UNIT,
    guard_sha: GUARD_SHA,
    harness: TEST,
    harness_sha: TEST_SHA,
    worker: &native265::WORKER_PROFILE,
    memory: 120_000_000_000,
    scratch: 160_000_000_000,
};
pub(super) const SCHEMA: &str = "jetstreamer-private-epoch257-native-input-running-v1";
pub(super) const PHASE: &str = "private-cold-snapshot-verification";
const RUN_SPEC: &str = "jetstreamer-native257-running-capture-spec-v1";

const EPOCH: u64 = 257;
const SLOT: u64 = 111_022_755;
const RANGE: &str = "257-257";
const DISK_RESERVATION: u64 = 256_000_000_000;
const ACCOUNTS_HASH: &str = "8bRdfjkM7Lst2wWtAyv56VKTprAYt1DKPuVy2HzK1wX3";
const SNAPSHOT_SHA: &str = "3e2b236f2cba29fbfe40f39f133fe9c845df9280e3fc6dd1cb70e4e018a4744d";
const SNAPSHOT: &str = "/var/lib/jetstreamer/horizon-contiguous-257-260-current-46b4b4a-v1/snapshot-111022755-8bRdfjkM7Lst2wWtAyv56VKTprAYt1DKPuVy2HzK1wX3.tar.zst";
use super::native257 as current;
use horizon_singleton211_launch::native257::validate_saved_handoff;
macro_rules! epoch_name {
    ($prefix:literal, $suffix:literal) => {
        concat!($prefix, "257", $suffix)
    };
}
pub(super) mod event {
    include!("native_cold/event.rs");
}
mod guard {
    include!("native_cold/guard.rs");
}
mod history {
    include!("native_cold/history.rs");
}
pub(super) mod terminal {
    include!("native_cold/terminal.rs");
}
include!("native_cold/owner.rs");

/// Bind a replacement to the registered owner's final receipt and retained reservation.
pub(super) fn verify_replacement(
    old: &PipelineClaim,
    successor: &PipelineClaim,
    origin: &Value,
    previous: &Plan,
) -> Result<()> {
    let old_origin = sealed(&old.evidence[0])?;
    let (_, admission) = startup(&binding(&origin["startup_handoff"])?)?;
    let review = sealed(&binding(&admission["review"])?)?;
    let closure = bound_json(&binding(&review["previous_closure"])?)?;
    let intent = bound_json(&binding(&closure["intent"])?)?;
    let terminal_ref = binding(&closure["terminal"])?;
    let proof = sealed(&terminal_ref)?;
    ensure!(
        old.invocation_id != successor.invocation_id
            && old_origin["startup_handoff"] == closure["startup"]
            && intent["preparation"] == review["previous_preparation"]
            && closure["reservation"] == review["closed266_booking"]
            && closure["resources_released"] == false
            && closure["all_four_links_removed"] == true
            && closure["original_processes_gone"] == true
            && proof["running_origin"] == private157::binding(&old.evidence[0])
            && proof["invocation_id"] == old.invocation_id
            && previous.gates[&EPOCH].evidence.contains(&terminal_ref),
        "epoch 257 replacement does not close the registered predecessor"
    );
    terminal::validate(&proof, &terminal_ref)
}

const RESTORED_HANDOFF: &str = "a8574efe6ab1198c9b9764505c0eb27b11b8e7538e7f76fc8944ecef67a2deb4";
pub(super) fn recovered_origin(origin: &Value) -> bool {
    origin["schema"] == SCHEMA && origin["startup_handoff"]["sha256"] == RESTORED_HANDOFF
}

/// Recover the routine sample omitted from the fleet while the 257 bootstrap finished.
pub(super) fn seven_delivery_predecessor(
    fleet: &BoundFile,
    previous: &Value,
    observer: &BoundFile,
    observation: &Value,
) -> Result<bool> {
    const BASE: &str = "/home/ubuntu/.codex/diagnostics";
    let bound = |name: &str, digest: &str| BoundFile {
        path: Path::new(BASE).join(name),
        sha256: digest.to_owned(),
    };
    let original = bound("horizon-fleet-takeover-v220-20261120-v1/fleet-v1.json",
        "4b26ee24aac6c5dc08971334b344772e04ea0d1e19ef0963252174790812ccfc");
    if fleet != &original {
        return Ok(false);
    }
    let samples = [
        ("horizon-resume-observer-20261120-v220.json", "be12d4824772a344f9a718b42b275b53533d23b49bf238cafa0634ca34efba86"),
        ("horizon-resume-observer-20261120-v221.json", "767b0fac49dba4ac44f3a2763fb97bb57814b8a59c389aba52a67b016f41e850"),
        ("horizon-resume-observer-20261120-v222.json", "403852efe76a70ec51ceb7fe9c2c6aa1a0e73690e02440bea3cd9eca84dc8368"),
    ].map(|(path, digest)| bound(path, digest));
    if observer != &samples[2] {
        return Ok(false);
    }
    let [first, middle, last] = [&samples[0], &samples[1], &samples[2]];
    let a = bound_json(first)?;
    let b = bound_json(middle)?;
    ensure!(previous["observer_receipt"].as_str() == first.path.to_str()
        && previous["observer_sha256"] == first.sha256
        && previous["sampled_at_utc"] == a["recorded_at_utc"]
        && *observation == bound_json(last)?, "different seven-delivery history");
    for (reference, earlier, later) in [(first, &a, &b), (middle, &b, observation)] {
        let cadence = &later["cadence"];
        ensure!(later["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && cadence["previous_sample"].as_str() == reference.path.to_str()
            && cadence["previous_sample_sha256"] == reference.sha256
            && cadence["previous_sample_recorded_at_utc"] == earlier["recorded_at_utc"]
            && cadence["routine_minimum_interval_enforced"] == true
            && num(cadence, "observed_interval_seconds")? >= 1800,
            "broken seven-delivery observation chain");
    }
    Ok(true)
}

#[cfg(test)]
#[test]
#[ignore = "reads the recorded Foundation fleet and three routine observations"]
fn seven_delivery_chain_requires_the_recorded_fleet_and_sample() -> Result<()> {
    let base = Path::new("/home/ubuntu/.codex/diagnostics");
    let fleet = BoundFile {
        path: base.join("horizon-fleet-takeover-v220-20261120-v1/fleet-v1.json"),
        sha256: "4b26ee24aac6c5dc08971334b344772e04ea0d1e19ef0963252174790812ccfc".into(),
    };
    let sample = BoundFile {
        path: base.join("horizon-resume-observer-20261120-v222.json"),
        sha256: "403852efe76a70ec51ceb7fe9c2c6aa1a0e73690e02440bea3cd9eca84dc8368".into(),
    };
    let previous = bound_json(&fleet)?;
    let mut observation = bound_json(&sample)?;
    assert!(seven_delivery_predecessor(&fleet, &previous, &sample, &observation)?);
    observation["cadence"]["previous_sample_sha256"] = Value::Null;
    assert!(seven_delivery_predecessor(&fleet, &previous, &sample, &observation).is_err());
    let mut wrong = sample.clone();
    wrong.sha256 = "0".repeat(64);
    assert!(!seven_delivery_predecessor(&fleet, &previous, &wrong, &observation)?);
    Ok(())
}

pub(super) fn terminal_helper(
    origin: &Value,
    admission: &Value,
    actor: &str,
    actual: bool,
) -> Result<()> {
    ensure!(recovered_origin(origin), "unknown epoch 257 restore");
    helper(admission, text(origin, "capture_helper_sha256")?, false)?;
    let root = Path::new(
        "/var/lib/jetstreamer/horizon265-delivery-consumers-v215-restored257a1-qualified",
    );
    let image = BoundFile {
        path: root.join("jetstreamer-r2"),
        sha256: actor.to_owned(),
    };
    let read = |name: &str| sealed(&binding(&private157::file_binding(&root.join(name))?)?);
    let provenance = read("jetstreamer-r2-provenance.json")?;
    let qualification = read("qualification.json")?;
    let booking = read("booking.json")?;
    ensure!(
        hex(actor, 64)
            && provenance["artifact"] == private157::binding(&image)
            && provenance["all_source_dependencies_enumerated"] == true
            && provenance["source_commit"] == booking["source"]
            && provenance["build_invocation_id"] == qualification["invocation_id"]
            && qualification["authority"] == false
            && qualification["archive_io"] == false
            && qualification["artifacts"]
                .as_array()
                .is_some_and(|rows| rows.iter().any(|r| r["sha256"] == actor
                    && r["path"]
                        .as_str()
                        .is_some_and(|p| Path::new(p).file_name() == image.path.file_name()))),
        "epoch 257 terminal verifier build mismatch"
    );
    if actual {
        ensure!(
            std::env::current_exe()?.canonicalize()? == image.path,
            "unexpected epoch 257 terminal verifier"
        );
        FsEvidence.bytes(&image, 128 << 20)?;
    }
    Ok(())
}

fn valid_expiry(a: &Value) -> Result<bool> {
    Ok(num(a, "issued_unix_seconds")?.checked_add(60) == Some(num(a, "expires_unix_seconds")?))
}
fn sample_mount(_: &Value, _: &Value) -> Result<()> {
    Ok(())
}
fn pin_mount(_: &Value, _: &Value) -> Result<()> {
    Ok(())
}
#[cfg(test)]
fn mount_fixture(_: &mut Value, _: &mut Value) {}

fn observation_mount(_: &Value, _: &Value) -> Result<()> {
    Ok(())
}
