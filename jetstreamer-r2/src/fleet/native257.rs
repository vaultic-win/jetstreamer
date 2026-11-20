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
