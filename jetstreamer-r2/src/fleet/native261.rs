//! Running resource ownership for the guarded epoch 261 cold bootstrap.
use super::native265::{
    EvidenceReader, FsEvidence, binding, deny, hex, namespace, num, sealed, text,
};
use super::*;
pub(super) const UNIT: &str = "horizon-261-native-input-20261120-v1.service";
pub(super) const GUARD_UNIT: &str = "horizon-native261-protective-v1.service";
pub(super) const TIMER: &str = "horizon-native261-protective-v1.timer";
pub(super) const RETAIN: &str = "horizon-native261-terminal-retention.target";
pub(super) const ROOT: &str = "/run/horizon261-native-cold-v1";
pub(super) const TEST: &str =
    "/var/lib/jetstreamer/horizon261-native-input-tmpfs-20261120-v1/horizon261-native-input";
pub(super) const TEST_SHA: &str =
    "b657cbaa98f543bb40fd9d01786ae0747ef30f4d2ed4727d81469461ea02d899";
pub(super) const GUARD: &str =
    "/var/lib/jetstreamer/horizon261-native-guard-tmpfs-20261120-v1/horizon261-native-guard";
pub(super) const GUARD_SHA: &str =
    "b11fc491490a797ae874d4406e68dd01bdcd5486b486a8b44e3635e66fce8f51";
pub(super) const PROFILE: native265_guard::SampleProfile = native265_guard::SampleProfile {
    unit: UNIT,
    guard_sha: GUARD_SHA,
    harness: TEST,
    harness_sha: TEST_SHA,
    memory: 192_000_000_000,
    scratch: 124 << 30,
};
pub(super) const SCHEMA: &str = "jetstreamer-private-epoch261-native-input-running-v1";
pub(super) const PHASE: &str = "private-cold-snapshot-verification";
const RUN_SPEC: &str = "jetstreamer-native261-running-capture-spec-v1";

const EPOCH: u64 = 261;
const SLOT: u64 = 112_751_208;
const RANGE: &str = "261-261";
const DISK_RESERVATION: u64 = 256 << 20;
const ACCOUNTS_HASH: &str = "Hgio4phsEt74AkKo6KdVmFzDoK35yS3fUkF6u3RkhSut";
const SNAPSHOT_SHA: &str = "5e84f74696d1f3100650e134fb91487d3e083c374a3262b05f67378b9b1c8256";
const SNAPSHOT: &str = "/var/lib/jetstreamer/horizon-contiguous-261-264-current-46b4b4a-v1/snapshot-112751208-Hgio4phsEt74AkKo6KdVmFzDoK35yS3fUkF6u3RkhSut.tar.zst";
use super::native261 as current;
use horizon_singleton211_launch::native261::validate_saved_handoff;
macro_rules! epoch_name {
    ($prefix:literal, $suffix:literal) => {
        concat!($prefix, "261", $suffix)
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
    Ok(num(a, "expires_unix_seconds")?
        .checked_sub(num(a, "issued_unix_seconds")?)
        .is_some_and(|d| (1..=60).contains(&d)))
}
fn sample_mount(first: &Value, sample: &Value) -> Result<()> {
    let original = &first["root_physical_observation"];
    let root = &sample["root_physical_observation"];
    ensure!(
        num(original, "device")? == num(root, "device")?
            && num(original, "inode")? == num(root, "inode")?
            && root["total_inodes"] == 1_048_576
            && root["tmpfs_capacity_bytes"] == 128u64 << 30
            && (4096..=1_048_576).contains(&num(root, "free_inodes")?)
            && root["exceeds_budget"] == false
            && num(root, "conservative_physical_bytes")? <= PROFILE.scratch,
        "261 tmpfs identity or limits changed"
    );
    Ok(())
}
fn pin_mount(first: &Value, pin: &Value) -> Result<()> {
    let root = &first["root_physical_observation"];
    ensure!(
        num(root, "device")? == num(pin, "device")? && num(root, "inode")? == num(pin, "inode")?,
        "261 terminal root pin changed"
    );
    Ok(())
}
#[cfg(test)]
fn mount_fixture(sample: &mut Value, pin: &mut Value) {
    let r = &mut sample["root_physical_observation"];
    r["device"] = json!(15);
    r["inode"] = json!(1);
    r["total_inodes"] = json!(1_048_576);
    r["tmpfs_capacity_bytes"] = json!(128u64 << 30);
    r["free_inodes"] = json!(1_048_575);
    pin["device"] = r["device"].clone();
    pin["inode"] = r["inode"].clone();
}
#[cfg(test)]
mod mount_tests {
    use super::*;
    #[test]
    fn periodic_samples_and_terminal_pin_keep_the_admitted_superblock() {
        let mut s = json!({"root_physical_observation":{"exceeds_budget":false,"conservative_physical_bytes":100}});
        let mut pin = json!({});
        mount_fixture(&mut s, &mut pin);
        sample_mount(&s, &s).unwrap();
        pin_mount(&s, &pin).unwrap();
        for key in [
            "device",
            "inode",
            "tmpfs_capacity_bytes",
            "free_inodes",
            "total_inodes",
            "conservative_physical_bytes",
            "exceeds_budget",
        ] {
            let mut changed = s.clone();
            changed["root_physical_observation"][key] = Value::Null;
            assert!(sample_mount(&s, &changed).is_err());
        }
        pin["device"] = json!(16);
        assert!(pin_mount(&s, &pin).is_err());
    }
}

fn observation_mount(observation: &Value, h: &Value) -> Result<()> {
    let first = sealed(&binding(&h["first_guard_sample"])?)?;
    let mut peak = 0;
    for k in ["scratch_pass_1", "scratch_pass_2"] {
        let r = &observation[k];
        sample_mount(&first, &json!({"root_physical_observation":r}))?;
        peak = peak.max(num(r, "conservative_physical_bytes")?);
    }
    ensure!(
        observation["scratch_measurement_method"] == "dedicated tmpfs superblock"
            && observation["conservative_observed_physical_bytes"] == peak,
        "261 observer scratch accounting differs"
    );
    Ok(())
}
