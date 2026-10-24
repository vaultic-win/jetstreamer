//! Closed, test-only native bootstrap proof; no entry replay or publication.
use super::RuntimeState;
use sha2::{Digest, Sha256};
use solana_sdk::hash::Hash;
use std::{
    env,
    fs::{self, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

const PACKAGE: &str = "/var/lib/jetstreamer/horizon-focused-209-complete-span-store8-ca2e38b-v2";
const SNAPSHOT: &str = "snapshot-90287519-6hSbTbwcGhgRGtxQ6iH2aWBhqRzGwhNBPCVDCBZ1fAxp.tar.zst";
const SLOT: u64 = 90_287_519;
const ACCOUNTS_HASH: &str = "6hSbTbwcGhgRGtxQ6iH2aWBhqRzGwhNBPCVDCBZ1fAxp";
const SNAPSHOT_SHA: &str = "ea71553acd1bfee3a735773840155c7b34529809ab5ff64908e0fcc9e5bb70bc";
const GENESIS_SHA: &str = "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945";

fn identity(m: &fs::Metadata) -> (u64, u64, u64, u32, u32, u64, i64, i64, i64, i64) {
    (
        m.dev(),
        m.ino(),
        m.len(),
        m.uid(),
        m.mode(),
        m.nlink(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}

fn checked_input(path: &Path, size: u64, digest: &str, owner: u32) -> Result<(), String> {
    let check = || -> Result<(), Box<dyn std::error::Error>> {
        if !path.is_absolute() || fs::canonicalize(path)? != path {
            return Err("noncanonical native 209 input".into());
        }
        let before = fs::symlink_metadata(path)?;
        if !before.is_file()
            || before.uid() != owner
            || before.mode() & 0o222 != 0
            || before.nlink() != 1
            || before.len() != size
        {
            return Err("unsafe native 209 input identity".into());
        }
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)?;
        if identity(&file.metadata()?) != identity(&before) {
            return Err("native 209 input changed before hashing".into());
        }
        let mut hash = Sha256::new();
        let mut buffer = vec![0u8; 1024 * 1024];
        let mut total = 0u64;
        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            total += count as u64;
            if total > size {
                return Err("native 209 input grew".into());
            }
            hash.input(&buffer[..count]);
        }
        if total != size
            || format!("{:x}", hash.result()) != digest
            || identity(&file.metadata()?) != identity(&before)
            || identity(&fs::symlink_metadata(path)?) != identity(&before)
        {
            return Err("native 209 input hash/identity differs".into());
        }
        Ok(())
    };
    check().map_err(|e| e.to_string())
}

fn scratch_namespace(path: &Path) -> bool {
    path.file_name().and_then(|n| n.to_str()) == Some("scratch")
        && path.parent().and_then(Path::parent)
            == Some(Path::new("/home/ubuntu/.jetstreamer-private"))
        && path
            .parent()
            .and_then(Path::file_name)
            .and_then(|n| n.to_str())
            .map_or(false, |n| n.starts_with("native-input209-v1616-capped-"))
}

#[test]
fn closed_native209_inputs_reject_changed_writable_or_symlinked_files() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("input");
    fs::write(&input, b"bound native input").unwrap();
    fs::set_permissions(&input, fs::Permissions::from_mode(0o444)).unwrap();
    let digest = format!("{:x}", Sha256::digest(b"bound native input"));
    let uid = unsafe { libc::geteuid() };
    checked_input(&input, 18, &digest, uid).unwrap();
    assert!(checked_input(&input, 19, &digest, uid).is_err());
    assert!(checked_input(&input, 18, &"a".repeat(64), uid).is_err());
    assert!(checked_input(&input, 18, &digest, uid + 1).is_err());
    let link = directory.path().join("link");
    symlink(&input, &link).unwrap();
    assert!(checked_input(&link, 18, &digest, uid).is_err());
    fs::set_permissions(&input, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(checked_input(&input, 18, &digest, uid).is_err());
    for path in &[
        "/home/ubuntu/.jetstreamer-private/native-input207-v1616-capped-v1/scratch",
        "/home/ubuntu/.jetstreamer-private/native-input209-v1616-capped-v1/output",
        "/home/ubuntu/.jetstreamer-private/native-input209-v1616-capped-v1/nested/scratch",
    ] {
        assert!(!scratch_namespace(Path::new(path)));
    }
    assert!(scratch_namespace(Path::new(
        "/home/ubuntu/.jetstreamer-private/native-input209-v1616-capped-v1/scratch"
    )));
}

#[test]
#[ignore]
fn native_epoch209_cold_input_matches_canonical_accounts_commitment() {
    let scratch = env::var("JETSTREAMER_EPOCH209_V1616_TEST_SCRATCH")
        .expect("explicit isolated209test scratch required");
    let path = Path::new(&scratch);
    assert!(scratch_namespace(path));
    for directory in &[path.parent().unwrap(), path] {
        let metadata = fs::symlink_metadata(directory).unwrap();
        assert!(metadata.is_dir());
        assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
        assert_eq!(metadata.mode() & 0o077, 0);
        assert_eq!(fs::canonicalize(directory).unwrap(), *directory);
    }
    assert!(fs::read_dir(path).unwrap().next().is_none());
    checked_input(
        &Path::new(PACKAGE).join(SNAPSHOT),
        8_543_246_873,
        SNAPSHOT_SHA,
        0,
    )
    .unwrap();
    checked_input(
        &Path::new(PACKAGE).join("genesis.tar.bz2"),
        20_144,
        GENESIS_SHA,
        0,
    )
    .unwrap();
    let (mut state, initialized) = RuntimeState::initialize(
        PACKAGE,
        &jetstreamer_historical_protocol::InitialState::SnapshotArchive {
            archive_path: Path::new(PACKAGE)
                .join(SNAPSHOT)
                .to_str()
                .unwrap()
                .to_owned(),
        },
        Some(&scratch),
    )
    .unwrap();
    assert_eq!(initialized.slot, SLOT);
    let transactions = state.bank.transaction_count();
    let capitalization = state.bank.capitalization();
    let checkpoint = state.freeze_checkpoint(SLOT).unwrap();
    assert!(checkpoint.slot_complete && checkpoint.writes.is_empty());
    assert_eq!(checkpoint.slot, SLOT);
    assert_eq!(
        checkpoint.next_write_version,
        initialized.next_write_version
    );
    assert_eq!(checkpoint.transaction_count, transactions);
    assert_eq!(checkpoint.capitalization, capitalization);
    assert_eq!(
        Hash::new(&checkpoint.accounts_hash).to_string(),
        ACCOUNTS_HASH
    );
    println!("epoch209-v1616-native-input slot={} bank_hash={} accounts_hash={} last_blockhash={} capitalization={} transaction_count={} tick_height={} next_write_version={} replay_entries=0 bootstrap_writes=0",
        checkpoint.slot,Hash::new(&checkpoint.bank_hash),Hash::new(&checkpoint.accounts_hash),
        Hash::new(&checkpoint.last_blockhash),checkpoint.capitalization,checkpoint.transaction_count,
        checkpoint.tick_height,checkpoint.next_write_version);
}
