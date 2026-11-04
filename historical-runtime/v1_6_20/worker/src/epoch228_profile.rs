//! Closed epoch 228 qualification span. No runtime/consensus substitution.
pub const BOOTSTRAP_SLOT: u64 = 98_495_291;
pub const FIRST_ENTRY_SLOT: u64 = BOOTSTRAP_SLOT + 1;
pub const TERMINAL_ROOT_SLOT: u64 = 98_928_278;
pub const END_EXCLUSIVE: u64 = TERMINAL_ROOT_SLOT + 1;
#[cfg(test)]
pub const OUTPUT_START: u64 = 98_496_000;
#[cfg(test)]
pub const EPOCH_END: u64 = 98_927_999;

pub fn validate_snapshot(slot: u64) -> Result<(), String> {
    if slot != BOOTSTRAP_SLOT {
        return Err("epoch228 capped requires the exact cold snapshot 98495291".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn scope_keeps_the_708_slot_prelude_and_279_slot_verification_tail() {
        assert!(validate_snapshot(BOOTSTRAP_SLOT).is_ok());
        for wrong in [BOOTSTRAP_SLOT - 1, BOOTSTRAP_SLOT + 1, 98_063_464].iter() {
            assert!(validate_snapshot(*wrong).is_err());
        }
        assert_eq!(OUTPUT_START - FIRST_ENTRY_SLOT, 708);
        assert_eq!(TERMINAL_ROOT_SLOT - EPOCH_END, 279);
        assert_eq!(EPOCH_END - OUTPUT_START + 1, 432_000);
        assert_eq!(TERMINAL_ROOT_SLOT - OUTPUT_START + 1, 432_279);
        assert_eq!(END_EXCLUSIVE - FIRST_ENTRY_SLOT, 432_987);
    }

    #[cfg(feature = "epoch228-capped-qualification")]
    #[test]
    #[ignore]
    fn native_epoch228_cold_input_matches_canonical_accounts_commitment() {
        use crate::runtime::RuntimeState;
        use jetstreamer_historical_protocol::InitialState;
        use sha2::{Digest, Sha256};
        use solana_sdk::hash::Hash;
        use std::{
            env, fs,
            io::Read,
            os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
            path::Path,
        };
        const SNAPSHOT:&str="/var/lib/jetstreamer/horizon-contiguous-228-230-current-46b4b4a-v1/snapshot-98495291-GfiRSgpC1qvH3uxVd9VAtYZ6qKM8fcdkyoyAkhF7izLq.tar.zst";
        let scratch = env::var("JETSTREAMER_EPOCH228_V1620_TEST_SCRATCH")
            .expect("explicit isolated 228 scratch required");
        let path = Path::new(&scratch);
        let root = path.parent().unwrap();
        assert_eq!(path.file_name().and_then(|n| n.to_str()), Some("scratch"));
        assert_eq!(
            root.parent(),
            Some(Path::new("/home/ubuntu/.jetstreamer-private"))
        );
        assert!(root
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("native-input228-v1620-"));
        let m = fs::symlink_metadata(path).unwrap();
        assert!(
            m.is_dir()
                && m.uid() == unsafe { libc::geteuid() }
                && m.permissions().mode() & 0o077 == 0
        );
        assert_eq!(fs::canonicalize(path).unwrap(), path);
        assert!(fs::read_dir(path).unwrap().next().is_none());
        let mut file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(SNAPSHOT)
            .unwrap();
        let m = file.metadata().unwrap();
        assert!(
            m.is_file() && m.uid() == 0 && m.nlink() == 1 && m.permissions().mode() & 0o222 == 0
        );
        assert_eq!(m.len(), 10_510_540_911);
        let mut digest = Sha256::new();
        let mut buffer = vec![0u8; 1024 * 1024];
        loop {
            let n = file.read(&mut buffer).unwrap();
            if n == 0 {
                break;
            }
            digest.input(&buffer[..n]);
        }
        assert_eq!(
            format!("{:x}", digest.result()),
            "da26bd1b4b3b93be74c9dae28d1d982f821474333aa06e87f32dfa83342915f3"
        );
        let initial = InitialState::SnapshotArchive {
            archive_path: SNAPSHOT.into(),
        };
        let (mut state, initialized) = RuntimeState::initialize(
            "/var/lib/jetstreamer/horizon-stage227-bootstrap-dcaafc6-v1",
            &initial,
            Some(&scratch),
        )
        .unwrap();
        assert_eq!(initialized.slot, BOOTSTRAP_SLOT);
        let checkpoint = state.freeze_checkpoint(BOOTSTRAP_SLOT).unwrap();
        assert!(checkpoint.slot_complete && checkpoint.writes.is_empty());
        assert_eq!(
            checkpoint.next_write_version,
            initialized.next_write_version
        );
        assert_eq!(checkpoint.last_blockhash, initialized.last_blockhash);
        assert_eq!(
            Hash::new(&checkpoint.accounts_hash).to_string(),
            "GfiRSgpC1qvH3uxVd9VAtYZ6qKM8fcdkyoyAkhF7izLq"
        );
        println!("epoch228-v1620-native-input slot={} bank_hash={} accounts_hash={} last_blockhash={} capitalization={} transaction_count={} tick_height={} next_write_version={} replay_entries=0 bootstrap_writes=0",
            checkpoint.slot,Hash::new(&checkpoint.bank_hash),Hash::new(&checkpoint.accounts_hash),Hash::new(&checkpoint.last_blockhash),checkpoint.capitalization,checkpoint.transaction_count,checkpoint.tick_height,checkpoint.next_write_version);
    }
}
