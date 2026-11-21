//! Running resource ownership for the guarded epoch 266 cold bootstrap.
use super::native265::{
    EvidenceReader, FsEvidence, binding, deny, hex, namespace, num, sealed, text,
};
use super::*;
pub(super) const UNIT: &str = "horizon-266-native-input-20261121-v1.service";
pub(super) const GUARD_UNIT: &str = "horizon-native266-protective-v1.service";
pub(super) const TIMER: &str = "horizon-native266-protective-v1.timer";
pub(super) const RETAIN: &str = "horizon-native266-terminal-retention.target";
pub(super) const ROOT: &str = "/run/horizon266-native-cold-v1";
pub(super) const TEST: &str =
    "/var/lib/jetstreamer/horizon266-native-input-tmpfs-20261121-v1/horizon266-native-input";
pub(super) const TEST_SHA: &str = "0c8aa52ede6067b16991e7d79d3c97f0aacf4de6158d5023c3114e39a40c1397";
pub(super) const GUARD: &str =
    "/var/lib/jetstreamer/horizon266-native-guard-tmpfs-20261121-v1/horizon266-native-guard";
pub(super) const GUARD_SHA: &str = "63defdffad878d470ff6f100471408efcd2a207a5c1bb60ac4b75e7204c49c10";
pub(super) const PROFILE: native265_guard::SampleProfile = native265_guard::SampleProfile {
    unit: UNIT,
    guard_sha: GUARD_SHA,
    harness: TEST,
    harness_sha: TEST_SHA,
    worker: &native265::WorkerProfile {
        path: "/var/lib/jetstreamer/horizon-contiguous-266-266-current-46b4b4a-v1/jetstreamer-historical-worker-v1-8-11",
        sha256: "9f7763ff57c27bcfa112814701314c1b36366a35c7e171a7d6f3ee97ee7330ae",
        backend: "solana-v1.8.11",
        solana_commit: "423a4d65461e36fefb371a2f164c20c4e7ed5afa",
    },
    memory: 192_000_000_000,
    scratch: 124 << 30,
};
pub(super) const SCHEMA: &str = "jetstreamer-private-epoch266-native-input-running-v1";
pub(super) const PHASE: &str = "private-cold-snapshot-verification";
const RUN_SPEC: &str = "jetstreamer-native266-running-capture-spec-v1";

const EPOCH: u64 = 266;
const SLOT: u64 = 114_910_768;
const RANGE: &str = "266-266";
const DISK_RESERVATION: u64 = 256 << 20;
const ACCOUNTS_HASH: &str = "HnePfSpTtWaPDFx9RrPeuamDZREhoUXa7xpK6fbtPGyK";
const SNAPSHOT_SHA: &str = "c3bfdbf63b7941a9c111a668bc03f71b197203eb52a45c9ea39e94797272babb";
const SNAPSHOT: &str = "/var/lib/jetstreamer/horizon-contiguous-266-266-current-46b4b4a-v1/snapshot-114910768-HnePfSpTtWaPDFx9RrPeuamDZREhoUXa7xpK6fbtPGyK.tar.zst";
use super::native266 as current;
use horizon_singleton211_launch::native266::validate_saved_handoff;
macro_rules! epoch_name {
    ($prefix:literal, $suffix:literal) => {
        concat!($prefix, "266", $suffix)
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

const TMPFS_BYTES: u64 = 128 << 30;
include!("native_cold/tmpfs.rs");

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn terminal_requires_the_selected_v1811_worker_and_checkpoint() {
        let (mut result, origin, handoff) = native265_history::tests::result_fixture();
        let hash = bs58::decode(ACCOUNTS_HASH).into_vec().unwrap();
        result["schema"] = json!("horizon266-exact-worker-cold-input-result-v1");
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
        result["handshake"]["solana_tag"] = json!("v1.8.11");
        result["handshake"]["rust_toolchain"] = json!("rustc 1.52.1 (9bc8c42bb 2021-05-09)");
        result["handshake"]["target"] = json!("x86_64-unknown-linux-gnu");
        result["initialized"]["ticks_per_slot"] = json!(64);
        result["checkpoint"]["last_blockhash"] = result["initialized"]["last_blockhash"].clone();
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
            ("/handshake/solana_tag", json!("foreign")),
            ("/handshake/rust_toolchain", json!("foreign")),
            ("/handshake/target", json!("foreign")),
            ("/initialized/ticks_per_slot", json!(1)),
            ("/checkpoint/last_blockhash", json!([])),
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
