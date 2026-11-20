//! Running resource ownership for the guarded epoch 212 cold bootstrap.
use super::native265::{
    EvidenceReader, FsEvidence, binding, deny, hex, namespace, num, sealed, text,
};
use super::*;
pub(super) const UNIT: &str = "horizon-212-native-input-20261120-v1.service";
pub(super) const GUARD_UNIT: &str = "horizon-native212-protective-v1.service";
pub(super) const TIMER: &str = "horizon-native212-protective-v1.timer";
pub(super) const RETAIN: &str = "horizon-native212-terminal-retention.target";
pub(super) const ROOT: &str = "/run/horizon212-native-cold-v1";
pub(super) const TEST: &str =
    "/var/lib/jetstreamer/horizon212-native-input-tmpfs-20261120-v1/horizon212-native-input";
pub(super) const TEST_SHA: &str =
    "73f93411831428c4f6cce9c625b817fb12a9746ca4901312ea0d8d820fc6ae9b";
pub(super) const GUARD: &str =
    "/var/lib/jetstreamer/horizon212-native-guard-tmpfs-20261120-v1/horizon212-native-guard";
pub(super) const GUARD_SHA: &str =
    "cd1ef010b27734e7b7ccb0d594289b7d8ca88a2d7ca49ae84f6a6a2841093eee";
pub(super) const PROFILE: native265_guard::SampleProfile = native265_guard::SampleProfile {
    unit: UNIT,
    guard_sha: GUARD_SHA,
    harness: TEST,
    harness_sha: TEST_SHA,
    worker: &native265::WorkerProfile {
        path: "/var/lib/jetstreamer/horizon-singleton211-production-worker-1c89b6a214f9487b-v1/jetstreamer-historical-worker-v1-6-16-shrink-budget",
        sha256: "1c89b6a214f9487babfd9dc121ade06037b371fbfcc3243f0e6ec67b6b961c41",
        backend: "solana-v1.6.16",
        solana_commit: "86c26f843276581509c3434acc2efbf4202c44e0",
    },
    memory: 111_669_149_696,
    scratch: 44 << 30,
};
pub(super) const SCHEMA: &str = "jetstreamer-private-epoch212-native-input-running-v1";
pub(super) const PHASE: &str = "private-cold-snapshot-verification";
const RUN_SPEC: &str = "jetstreamer-native212-running-capture-spec-v1";

const EPOCH: u64 = 212;
const SLOT: u64 = 91_583_512;
const RANGE: &str = "212-212";
const DISK_RESERVATION: u64 = 256 << 20;
const ACCOUNTS_HASH: &str = "548ThATYndZ7kSzuEgkRx9eVd4MD4hbLgU9ydtjZbbKV";
const SNAPSHOT_SHA: &str = "94d7ed8cf39d2b2d665d2c720a3381afb7555d3b3201b7c4d68d6cb0bcbb8a96";
const SNAPSHOT: &str = "/var/lib/jetstreamer/horizon-focused-212-complete-span-store8-ca2e38b-v1/snapshot-91583512-548ThATYndZ7kSzuEgkRx9eVd4MD4hbLgU9ydtjZbbKV.tar.zst";
use super::native212 as current;
use horizon_singleton211_launch::native212::validate_saved_handoff;
macro_rules! epoch_name {
    ($prefix:literal, $suffix:literal) => {
        concat!($prefix, "212", $suffix)
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

const TMPFS_BYTES: u64 = 48 << 30;
include!("native_cold/tmpfs.rs");

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn terminal_requires_the_selected_v1616_worker_and_checkpoint() {
        let (mut result, origin, handoff) = native265_history::tests::result_fixture();
        let hash = bs58::decode(ACCOUNTS_HASH).into_vec().unwrap();
        result["schema"] = json!("horizon212-exact-worker-cold-input-result-v1");
        result["epoch"] = json!(EPOCH);
        result["worker"] = json!({"path":PROFILE.worker.path,"sha256":PROFILE.worker.sha256});
        result["handshake"]["backend_id"] = json!(PROFILE.worker.backend);
        result["handshake"]["solana_commit"] = json!(PROFILE.worker.solana_commit);
        result["bootstrap_slot"] = json!(SLOT);
        result["bootstrap_sha256"] = json!(SNAPSHOT_SHA);
        result["accounts_hash"] = json!(ACCOUNTS_HASH);
        result["initialized"]["slot"] = json!(SLOT);
        result["initialized"]["source"]["SnapshotArchive"] =
            json!({"expected_accounts_hash":hash,"archive_path":SNAPSHOT});
        result["checkpoint"]["slot"] = json!(SLOT);
        result["checkpoint"]["accounts_hash"] = json!(hash);
        assert_eq!(
            terminal::native_result(&result, &origin, &handoff).unwrap(),
            43
        );
        for (key, other) in [
            ("/worker/path", json!(native265::WORKER)),
            ("/worker/sha256", json!(native265::WORKER_SHA)),
            (
                "/handshake/backend_id",
                json!(native265::WORKER_PROFILE.backend),
            ),
            (
                "/handshake/solana_commit",
                json!(native265::WORKER_PROFILE.solana_commit),
            ),
            ("/checkpoint/writes", json!([{}])),
        ] {
            let mut foreign = result.clone();
            *foreign.pointer_mut(key).unwrap() = other;
            assert!(
                terminal::native_result(&foreign, &origin, &handoff).is_err(),
                "{key}"
            );
        }
    }
}
