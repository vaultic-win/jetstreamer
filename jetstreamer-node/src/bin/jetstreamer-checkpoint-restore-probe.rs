//! Private, no-replay checkpoint comparison using the unchanged historical worker.
//!
//! This is intentionally limited to the retained epoch-213 restart candidate.
//! A successful restore does not authorize a suffix, assembly, or publication.

#[allow(dead_code)]
#[path = "../historical.rs"]
mod historical;

use {
    historical::{
        HistoricalCheckpoint, HistoricalInitialization, HistoricalRuntimeClient,
        SOLANA_V1_6_16_CANDIDATE, SnapshotInitialization, WorkerSpawn,
    },
    jetstreamer_node::{
        archive_checksum::{
            archive_file_identity, open_regular_nofollow, path_matches_archive_identity,
        },
        segment_manifest::{HistoricalSegmentManifest, SegmentCheckpointSummary},
    },
    serde::Deserialize,
    serde_json::json,
    sha2::{Digest, Sha256},
    solana_hash::Hash,
    std::{
        env,
        fs::{self, File, OpenOptions},
        io::{Read, Write},
        os::unix::fs::{MetadataExt, OpenOptionsExt},
        path::{Path, PathBuf},
        str::FromStr,
        time::{SystemTime, UNIX_EPOCH},
    },
};

const WORKER_SHA256: &str = "3f5e8efec328b3e00dd9ce5ae396fc4067e6be6554e4da8831a13273186a748a";
const SNAPSHOT_SHA256: &str = "bae33ebaeaa7bfb3c4c9230ef9f7aabb2e68628ac2fc0a8d435b7e2e976bbe08";
const PREFIX_MANIFEST_SHA256: &str =
    "1d74158c418f67443837b01ae3d218ace43c1e9998e6a91c4d3ead6e2b5e0581";
// This lower bound is not full fleet admission. The sealed operational plan
// must additionally protect every older invocation's remaining-growth claim.
const MINIMUM_FREE_BYTES: u64 = 230_740_693_718 + (128 << 30);

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    worker: PathBuf,
    prefix_manifest: PathBuf,
    snapshot: PathBuf,
    ledger_directory: PathBuf,
    genesis_archive_sha256: String,
    scratch_directory: PathBuf,
    output: PathBuf,
    minimum_free_bytes: u64,
}

fn require(condition: bool, message: &str) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(message.to_owned())
    }
}

fn digest(value: &str) -> Result<[u8; 32], String> {
    require(
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "expected 64 lowercase hexadecimal characters",
    )?;
    let mut result = [0; 32];
    for (index, byte) in result.iter_mut().enumerate() {
        *byte =
            u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).map_err(|e| e.to_string())?;
    }
    Ok(result)
}

fn bound_bytes(
    path: &Path,
    expected: &str,
    limit: u64,
    immutable: bool,
) -> Result<Vec<u8>, String> {
    require(
        path.is_absolute() && fs::canonicalize(path).map_err(|e| e.to_string())? == path,
        "evidence path must be absolute and canonical",
    )?;
    let mut file = open_regular_nofollow(path).map_err(|e| e.to_string())?;
    let before = archive_file_identity(&file).map_err(|e| e.to_string())?;
    let metadata = file.metadata().map_err(|e| e.to_string())?;
    require(
        metadata.nlink() == 1 && metadata.len() <= limit,
        "evidence link count or size mismatch",
    )?;
    if immutable {
        require(
            metadata.uid() == 0 && metadata.mode() & 0o222 == 0,
            "sealed evidence must be root-owned and non-writable",
        )?;
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    require(
        bytes.len() as u64 == metadata.len(),
        "evidence length changed",
    )?;
    require(
        <[u8; 32]>::from(Sha256::digest(&bytes)) == digest(expected)?,
        "evidence SHA-256 mismatch",
    )?;
    require(
        archive_file_identity(&file).map_err(|e| e.to_string())? == before
            && path_matches_archive_identity(path, before).map_err(|e| e.to_string())?,
        "evidence identity changed",
    )?;
    Ok(bytes)
}

fn validate_prefix(prefix: &HistoricalSegmentManifest) -> Result<(), String> {
    prefix.validate().map_err(|e| e.to_string())?;
    require(
        prefix.epoch == 213
            && prefix.output_slot_start == 92_016_000
            && prefix.output_slot_count == 431_543
            && prefix.bootstrap.slot == 92_015_419
            && prefix.terminal.slot == 92_447_542,
        "prefix range mismatch",
    )?;
    require(
        prefix.runtime.runtime_profile == "solana-v1.6.16"
            && prefix.runtime.runtime_revision == "86c26f843276581509c3434acc2efbf4202c44e0"
            && prefix.worker_executable_sha256 == digest(WORKER_SHA256)?,
        "prefix runtime mismatch",
    )
}

fn validate_checkpoint(
    expected: &SegmentCheckpointSummary,
    actual: &HistoricalCheckpoint,
) -> Result<(), String> {
    require(
        actual.slot == expected.slot
            && actual.bank_hash
                == Hash::from_str(&expected.bank_hash)
                    .map_err(|e| e.to_string())?
                    .to_bytes()
            && actual.accounts_hash
                == Hash::from_str(&expected.accounts_hash)
                    .map_err(|e| e.to_string())?
                    .to_bytes()
            && actual.last_blockhash
                == Hash::from_str(&expected.last_blockhash)
                    .map_err(|e| e.to_string())?
                    .to_bytes()
            && actual.capitalization == expected.capitalization
            && actual.transaction_count == expected.transaction_count
            && actual.tick_height == expected.tick_height
            && actual.slot_complete
            && expected.slot_complete,
        "native bootstrap checkpoint differs from prefix terminal consensus state",
    )?;
    // The snapshot loader must emit no updates. Its local cursor is retained,
    // not forced to equal the independently replayed prefix's cursor.
    require(
        actual.writes.is_empty(),
        "snapshot bootstrap emitted account writes",
    )
}

fn free_bytes(path: &Path) -> Result<u64, String> {
    use std::{ffi::CString, os::unix::ffi::OsStrExt};
    let path = CString::new(path.as_os_str().as_bytes()).map_err(|e| e.to_string())?;
    let mut value = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    if unsafe { libc::statvfs(path.as_ptr(), value.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let value = unsafe { value.assume_init() };
    value
        .f_bavail
        .checked_mul(value.f_frsize)
        .ok_or_else(|| "free-space arithmetic overflow".to_owned())
}

fn validate_private_directory(path: &Path) -> Result<(), String> {
    require(
        path.is_absolute() && fs::canonicalize(path).map_err(|e| e.to_string())? == path,
        "private directory must be absolute and canonical",
    )?;
    let metadata = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    require(
        metadata.is_dir()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o077 == 0,
        "private directory ownership or mode mismatch",
    )
}

fn execute(plan_path: &Path, plan_sha: &str, self_sha: &str) -> Result<(), String> {
    // Existing client owns bounded IPC, exact worker handshake, bound private
    // copies, guardian shutdown, and delayed-reap handling. Never send entries.
    require(
        unsafe { libc::geteuid() } != 0,
        "run the probe as the isolated replay user, not root",
    )?;
    bound_bytes(
        &fs::read_link("/proc/self/exe").map_err(|e| e.to_string())?,
        self_sha,
        256 << 20,
        true,
    )?;
    let plan: Plan = serde_json::from_slice(&bound_bytes(plan_path, plan_sha, 1 << 20, true)?)
        .map_err(|e| e.to_string())?;
    require(
        plan.schema == "jetstreamer-private-epoch213-checkpoint-restore-probe-plan-v1",
        "plan schema mismatch",
    )?;
    require(
        plan.minimum_free_bytes >= MINIMUM_FREE_BYTES,
        "free-space bound must protect the retained century floor plus the diagnostic budget",
    )?;
    validate_private_directory(&plan.scratch_directory)?;
    let output_parent = plan.output.parent().ok_or("output needs a parent")?;
    validate_private_directory(output_parent)?;
    require(
        plan.output.is_absolute()
            && fs::symlink_metadata(&plan.output)
                .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        "output must be an absent absolute path",
    )?;
    require(
        fs::read_dir(&plan.scratch_directory)
            .map_err(|e| e.to_string())?
            .next()
            .is_none(),
        "scratch must start empty",
    )?;
    let prefix: HistoricalSegmentManifest = serde_json::from_slice(&bound_bytes(
        &plan.prefix_manifest,
        PREFIX_MANIFEST_SHA256,
        1 << 20,
        true,
    )?)
    .map_err(|e| e.to_string())?;
    validate_prefix(&prefix)?;
    // Snapshot bytes are copied, fully hashed, and length/identity bound by
    // the reviewed historical client immediately before worker initialization.
    require(
        plan.snapshot.file_name().and_then(|s| s.to_str())
            == Some("snapshot-92447542-4gX8J8Y3c36L6W4D38ax2RYShfKmYxHWuDHAkQKeNzqd.tar.zst"),
        "snapshot filename mismatch",
    )?;
    bound_bytes(&plan.worker, WORKER_SHA256, 256 << 20, true)?;
    let genesis = plan.ledger_directory.join("genesis.tar.bz2");
    require(
        fs::canonicalize(&plan.ledger_directory).map_err(|e| e.to_string())?
            == plan.ledger_directory,
        "ledger directory must be canonical",
    )?;
    let ledger_metadata =
        fs::symlink_metadata(&plan.ledger_directory).map_err(|e| e.to_string())?;
    require(
        ledger_metadata.is_dir()
            && ledger_metadata.uid() == 0
            && ledger_metadata.mode() & 0o222 == 0,
        "ledger directory must be sealed and root-owned",
    )?;
    require(
        fs::symlink_metadata(plan.ledger_directory.join("genesis.bin"))
            .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        "an alternate genesis.bin must not shadow the bound genesis archive",
    )?;
    bound_bytes(&genesis, &plan.genesis_archive_sha256, 10 << 20, true)?;
    let available_before = free_bytes(&plan.scratch_directory)?;
    require(
        available_before >= plan.minimum_free_bytes,
        "free-space admission failed",
    )?;
    let mut client = HistoricalRuntimeClient::spawn(
        SOLANA_V1_6_16_CANDIDATE,
        WorkerSpawn {
            executable: plan.worker.clone(),
            initialization: HistoricalInitialization::SnapshotArchive(SnapshotInitialization {
                ledger_path: plan.ledger_directory.clone(),
                archive_path: plan.snapshot.clone(),
                expected_slot: prefix.terminal.slot,
                expected_accounts_hash: Hash::from_str(&prefix.terminal.accounts_hash)
                    .map_err(|e| e.to_string())?
                    .to_bytes(),
                expected_archive_sha256: Some(digest(SNAPSHOT_SHA256)?),
                expected_archive_size: Some(8_894_131_881),
                scratch_parent: Some(plan.scratch_directory.clone()),
            }),
        },
    )
    .map_err(|e| e.to_string())?;
    require(
        client.executable_sha256() == digest(WORKER_SHA256)?,
        "executed worker digest mismatch",
    )?;
    let checkpoint = client
        .freeze_checkpoint(prefix.terminal.slot)
        .map_err(|e| e.to_string())?;
    validate_checkpoint(&prefix.terminal, &checkpoint)?;
    require(
        checkpoint.next_write_version == client.initialized().next_write_version,
        "restored checkpoint unexpectedly advanced the write cursor",
    )?;
    client.shutdown().map_err(|e| e.to_string())?;
    bound_bytes(&genesis, &plan.genesis_archive_sha256, 10 << 20, true)?;
    let receipt = json!({
        "schema": "jetstreamer-private-epoch213-checkpoint-restore-probe-v1",
        "recorded_unix_seconds": SystemTime::now().duration_since(UNIX_EPOCH).map_err(|e| e.to_string())?.as_secs(),
        "plan": {"path": plan_path, "sha256": plan_sha}, "probe_sha256": self_sha,
        "worker": {"path": plan.worker, "sha256": WORKER_SHA256},
        "snapshot": {"path": plan.snapshot, "sha256": SNAPSHOT_SHA256, "bytes": 8_894_131_881u64},
        "prefix_manifest": {"path": plan.prefix_manifest, "sha256": PREFIX_MANIFEST_SHA256},
        "native_checkpoint": {
            "slot": checkpoint.slot, "bank_hash": Hash::new_from_array(checkpoint.bank_hash).to_string(),
            "accounts_hash": Hash::new_from_array(checkpoint.accounts_hash).to_string(),
            "last_blockhash": Hash::new_from_array(checkpoint.last_blockhash).to_string(),
            "capitalization": checkpoint.capitalization, "transaction_count": checkpoint.transaction_count,
            "tick_height": checkpoint.tick_height, "slot_complete": checkpoint.slot_complete,
            "write_count": checkpoint.writes.len(), "next_write_version": checkpoint.next_write_version,
        },
        "prefix_terminal_next_write_version": prefix.terminal.next_write_version,
        "available_bytes_before": available_before,
        "available_bytes_after": free_bytes(&plan.scratch_directory)?,
        "assessment": {"native_consensus_state_matches": true, "replay_entries_sent": 0,
            "prefix_archive_freshly_verified": false, "suffix_generated": false},
        "authority": {"replay_launch_authorized": false, "assembly_authorized": false,
            "canonical_sidecar_authorized": false, "publication_authorized": false,
            "local_retirement_authorized": false, "r2_mutations_authorized": false},
    });
    let mut bytes = serde_json::to_vec_pretty(&receipt).map_err(|e| e.to_string())?;
    bytes.push(b'\n');
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&plan.output)
        .map_err(|e| e.to_string())?;
    output
        .write_all(&bytes)
        .and_then(|_| output.sync_all())
        .map_err(|e| e.to_string())?;
    File::open(output_parent)
        .and_then(|f| f.sync_all())
        .map_err(|e| e.to_string())?;
    println!("checkpoint restore probe passed: {}", plan.output.display());
    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let result = if args.len() == 6 && args[2] == "--plan-sha256" && args[4] == "--self-sha256" {
        execute(Path::new(&args[1]), &args[3], &args[5])
    } else {
        Err(
            "usage: jetstreamer-checkpoint-restore-probe PLAN --plan-sha256 HEX --self-sha256 HEX"
                .to_owned(),
        )
    };
    if let Err(error) = result {
        eprintln!("checkpoint restore probe failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expected() -> SegmentCheckpointSummary {
        SegmentCheckpointSummary {
            slot: 92_447_542,
            bank_hash: "3Bgwz3nqVvy6fTQJnaJvSzcQFr3XqWCV8aHLfMqS11f5".into(),
            accounts_hash: "4gX8J8Y3c36L6W4D38ax2RYShfKmYxHWuDHAkQKeNzqd".into(),
            last_blockhash: "2tN6m26dJcVteCGfgJtRmvSVf82VKMoYwddjn5JecY1v".into(),
            capitalization: 502034460621673635,
            transaction_count: 24562599554,
            tick_height: 5916642752,
            slot_complete: true,
            write_count: 186,
            next_write_version: 94061957899,
        }
    }

    fn actual() -> HistoricalCheckpoint {
        let e = expected();
        HistoricalCheckpoint {
            slot: e.slot,
            bank_hash: Hash::from_str(&e.bank_hash).unwrap().to_bytes(),
            accounts_hash: Hash::from_str(&e.accounts_hash).unwrap().to_bytes(),
            last_blockhash: Hash::from_str(&e.last_blockhash).unwrap().to_bytes(),
            capitalization: e.capitalization,
            transaction_count: e.transaction_count,
            tick_height: e.tick_height,
            slot_complete: true,
            writes: vec![],
            next_write_version: 94273483349,
        }
    }

    #[test]
    fn native_state_equality_does_not_force_validator_local_cursor() {
        assert_ne!(expected().next_write_version, actual().next_write_version);
        validate_checkpoint(&expected(), &actual()).unwrap();
    }

    #[test]
    fn every_consensus_field_is_required() {
        let mutations: [fn(&mut HistoricalCheckpoint); 8] = [
            |v| v.slot += 1,
            |v| v.bank_hash[0] ^= 1,
            |v| v.accounts_hash[0] ^= 1,
            |v| v.last_blockhash[0] ^= 1,
            |v| v.capitalization += 1,
            |v| v.transaction_count += 1,
            |v| v.tick_height += 1,
            |v| v.slot_complete = false,
        ];
        for mutate in mutations {
            let mut value = actual();
            mutate(&mut value);
            assert!(validate_checkpoint(&expected(), &value).is_err());
        }
    }

    #[test]
    fn digest_requires_exact_lowercase_hex() {
        for bad in ["", "00", &"A".repeat(64), &"g".repeat(64)] {
            assert!(digest(bad).is_err());
        }
        assert_eq!(digest(&"00".repeat(32)).unwrap(), [0; 32]);
    }

    #[test]
    fn bootstrap_writes_are_not_treated_as_cursor_rebasing() {
        let mut value = actual();
        value.writes.push(historical::HistoricalAccountWrite {
            slot: value.slot,
            write_version: value.next_write_version,
            transaction_signature: None,
            pubkey: [0; 32],
            lamports: 0,
            owner: [0; 32],
            executable: false,
            rent_epoch: 0,
            data: vec![],
            stored_hash: [0; 32],
        });
        assert!(validate_checkpoint(&expected(), &value).is_err());
    }

    #[test]
    fn evidence_rejects_symlinks_hardlinks_wrong_hashes_and_oversize_inputs() {
        use std::os::unix::fs::symlink;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("evidence");
        fs::write(&path, b"evidence").unwrap();
        let sha = format!("{:x}", Sha256::digest(b"evidence"));
        assert_eq!(bound_bytes(&path, &sha, 8, false).unwrap(), b"evidence");
        assert!(bound_bytes(&path, &sha, 7, false).is_err());
        assert!(bound_bytes(&path, &"00".repeat(32), 8, false).is_err());
        let link = directory.path().join("link");
        symlink(&path, &link).unwrap();
        assert!(bound_bytes(&link, &sha, 8, false).is_err());
        fs::hard_link(&path, directory.path().join("hardlink")).unwrap();
        assert!(bound_bytes(&path, &sha, 8, false).is_err());
    }

    #[test]
    fn plan_rejects_unknown_fields() {
        assert!(
            serde_json::from_value::<Plan>(json!({"schema": "test", "allow_replay": true}))
                .is_err()
        );
    }
}
