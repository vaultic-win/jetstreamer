const EPOCH: u64 = 266;
const SLOT: u64 = 114_910_768;
const RANGE: &str = "266-266";
const DISK_RESERVATION: u64 = 256 << 20;
const ACCOUNTS_HASH: &str = "HnePfSpTtWaPDFx9RrPeuamDZREhoUXa7xpK6fbtPGyK";
const SNAPSHOT_SHA: &str = "c3bfdbf63b7941a9c111a668bc03f71b197203eb52a45c9ea39e94797272babb";
const SNAPSHOT: &str = "/var/lib/jetstreamer/horizon-contiguous-266-266-current-46b4b4a-v1/snapshot-114910768-HnePfSpTtWaPDFx9RrPeuamDZREhoUXa7xpK6fbtPGyK.tar.zst";
pub(super) mod event {
    include!("event.rs");
}
mod guard {
    include!("guard.rs");
}
mod history {
    include!("history.rs");
}
pub(super) mod terminal {
    include!("terminal.rs");
}
include!("owner.rs");

const TMPFS_BYTES: u64 = 128 << 30;
include!("tmpfs.rs");

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
