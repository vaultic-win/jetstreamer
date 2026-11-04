//! Derive an expected V4 envelope from the two exact sealed source manifests.
//! Never opens the assembled target, replays, creates a sidecar, or grants admission.

use jetstreamer_horizon::archive::*;
use jetstreamer_node::{archive_checksum::*, segment_manifest::*};
use serde_json::json;
use sha2::{Digest, Sha256};
use solana_hash::Hash;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

const PREFIX_MANIFEST: &str = "1d74158c418f67443837b01ae3d218ace43c1e9998e6a91c4d3ead6e2b5e0581";
const SUFFIX_MANIFEST: &str = "959e81cbf269a68718b52dac5fc67ba22e97871fe0c1dcd1ab6b6b7e5953abd1";
const PREFIX_ARCHIVE: &str = "e9b0fa7bbad1fdbf86d9d564baa0c377003ec20e40709dae249fac8ba0cb91d9";
const SUFFIX_ARCHIVE: &str = "3360ba3da029865522511a821c30851447a7a6eca5e9fe28cd536181edf07d03";
const SNAPSHOT: &str = "bae33ebaeaa7bfb3c4c9230ef9f7aabb2e68628ac2fc0a8d435b7e2e976bbe08";
const WORKER: &str = "3f5e8efec328b3e00dd9ce5ae396fc4067e6be6554e4da8831a13273186a748a";
const GENERATION: &str =
    "jetstreamer-node/0.9.0/old-faithful-to-horizon-v2@ae43646af4238345720f8e0ea97823331a7c702e";

fn require(value: bool, message: &str) -> Result<(), String> {
    if value { Ok(()) } else { Err(message.into()) }
}

fn digest(value: &str) -> Result<[u8; 32], String> {
    require(
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "noncanonical digest",
    )?;
    let mut result = [0; 32];
    for (index, byte) in result.iter_mut().enumerate() {
        *byte =
            u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).map_err(|e| e.to_string())?;
    }
    Ok(result)
}

fn hash(value: &str) -> Result<Hash, String> {
    value
        .parse()
        .map_err(|e| format!("invalid checkpoint hash: {e}"))
}

fn checkpoint(value: &SegmentCheckpointSummary) -> Result<RuntimeStateCheckpoint, String> {
    Ok(RuntimeStateCheckpoint {
        slot: value.slot,
        bank_hash: hash(&value.bank_hash)?,
        accounts_hash_kind: AccountsHashKind::LegacyAccountsHash,
        accounts_hash: hash(&value.accounts_hash)?,
        last_blockhash: hash(&value.last_blockhash)?,
        capitalization: value.capitalization,
        transaction_count: value.transaction_count,
        tick_height: value.tick_height,
        slot_complete: value.slot_complete,
        next_write_version: value.next_write_version,
    })
}

fn expectation(
    prefix: &HistoricalSegmentManifest,
    suffix: &HistoricalSegmentManifest,
) -> Result<ArchiveProvenance, String> {
    prefix.validate().map_err(|e| e.to_string())?;
    suffix.validate().map_err(|e| e.to_string())?;
    require(
        prefix.epoch == 213
            && suffix.epoch == 213
            && prefix.output_slot_start == 92_016_000
            && prefix.output_slot_count == 431_543
            && prefix.bootstrap.slot == 92_015_419
            && prefix.terminal.slot == 92_447_542
            && suffix.output_slot_start == 92_447_543
            && suffix.output_slot_count == 457
            && suffix.bootstrap.slot == 92_447_542
            && suffix.terminal.slot == 92_447_999,
        "not the exact epoch213 source coverage",
    )?;
    require(
        prefix.archive_sha256 == digest(PREFIX_ARCHIVE)?
            && suffix.archive_sha256 == digest(SUFFIX_ARCHIVE)?
            && suffix.bootstrap_archive_sha256 == Some(digest(SNAPSHOT)?)
            && suffix.runtime.generation_profile == GENERATION
            && suffix.bootstrap.write_count == 0
            && suffix.terminal.last_blockhash == "2SMgef3T3X5aeHZy1USrSR5qEJqwQbsz2yVr3tRs25Ki",
        "source artifact, restart or canonical terminal identity differs",
    )?;
    let mut segments = Vec::new();
    let mut normalized = 0;
    for source in [prefix, suffix] {
        require(
            source.worker_executable_sha256 == digest(WORKER)?
                && source.runtime.runtime_profile == "solana-v1.6.16"
                && source.runtime.runtime_revision == "86c26f843276581509c3434acc2efbf4202c44e0"
                && source.runtime.runtime_admission == SegmentRuntimeAdmission::Candidate
                && source.runtime.genesis_hash == "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d"
                && source.runtime.runtime_toolchain == prefix.runtime.runtime_toolchain
                && source.runtime.runtime_target == prefix.runtime.runtime_target,
            "source runtime identity differs",
        )?;
        let mapping = WriteVersionNormalization {
            worker_start: source.emitted_raw_write_versions.start,
            worker_end_exclusive: source.emitted_raw_write_versions.end,
            archive_start: normalized,
        };
        normalized = mapping
            .archive_end_exclusive()
            .ok_or("normalization overflow")?;
        segments.push(RuntimeSegmentProvenance {
            slot_start: source.output_slot_start,
            slot_count: source.output_slot_count,
            generation_profile: source.runtime.generation_profile.clone(),
            runtime_profile: source.runtime.runtime_profile.clone(),
            runtime_admission: RuntimeAdmission::Candidate,
            runtime_revision: source.runtime.runtime_revision.clone(),
            runtime_toolchain: source.runtime.runtime_toolchain.clone(),
            worker_executable_sha256: Some(source.worker_executable_sha256),
            write_versions: mapping,
        });
    }
    let result = ArchiveProvenance::V4(ArchiveProvenanceV4 {
        base: ArchiveProvenanceV3 {
            assembly_profile: format!("{GENERATION}/checkpoint-continuation-v1"),
            genesis_hash: hash(&prefix.runtime.genesis_hash)?,
            bootstrap_state_kind: BootstrapStateKind::SnapshotArchive,
            bootstrap_state: StateCommitment {
                slot: prefix.bootstrap.slot,
                kind: StateCommitmentKind::LegacyAccountsHash,
                hash: hash(&prefix.bootstrap.accounts_hash)?,
            },
            requested_slot_start: 92_016_000,
            requested_slot_count: 432_000,
            transaction_metadata: TransactionMetadataPolicy::observed(),
            runtime_segments: segments,
            handoffs: vec![RuntimeHandoffProvenance {
                boundary_slot: 92_447_543,
                predecessor: checkpoint(&prefix.terminal)?,
                successor: checkpoint(&suffix.bootstrap)?,
                successor_bootstrap_kind: BootstrapStateKind::SnapshotArchive,
                successor_bootstrap_archive_sha256: digest(SNAPSHOT)?,
                successor_bootstrap_write_count: 0,
            }],
        },
    });
    result.validate().map_err(|e| e.to_string())?;
    Ok(result)
}

fn read_manifest(path: &Path, expected: &str) -> Result<HistoricalSegmentManifest, String> {
    require(
        path.is_absolute() && fs::canonicalize(path).map_err(|e| e.to_string())? == path,
        "manifest path must be absolute and canonical",
    )?;
    let mut file = open_regular_nofollow(path).map_err(|e| e.to_string())?;
    let identity = archive_file_identity(&file).map_err(|e| e.to_string())?;
    let metadata = file.metadata().map_err(|e| e.to_string())?;
    require(
        metadata.uid() == 0
            && metadata.nlink() == 1
            && metadata.mode() & 0o222 == 0
            && metadata.len() <= 1024 * 1024,
        "manifest must be bounded and immutable under root",
    )?;
    let mut bytes = Vec::new();
    (&mut file)
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    require(
        bytes.len() as u64 == metadata.len()
            && <[u8; 32]>::from(Sha256::digest(&bytes)) == digest(expected)?
            && archive_file_identity(&file).map_err(|e| e.to_string())? == identity
            && path_matches_archive_identity(path, identity).map_err(|e| e.to_string())?,
        "manifest digest or identity mismatch",
    )?;
    serde_json::from_slice(&bytes).map_err(|e| e.to_string())
}

fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    require(
        args.len() == 5 && args[3] == "--self-sha256",
        "usage: jetstreamer-epoch213-provenance-expectation PREFIX_MANIFEST SUFFIX_MANIFEST OUTPUT --self-sha256 HEX",
    )?;
    require(unsafe { libc::geteuid() } == 0, "requires root")?;
    let mut executable = File::open("/proc/self/exe").map_err(|e| e.to_string())?;
    let mut self_hash = Sha256::new();
    std::io::copy(&mut executable, &mut self_hash).map_err(|e| e.to_string())?;
    require(
        <[u8; 32]>::from(self_hash.finalize()) == digest(&args[4])?,
        "self hash mismatch",
    )?;
    let prefix = read_manifest(Path::new(&args[0]), PREFIX_MANIFEST)?;
    let suffix = read_manifest(Path::new(&args[1]), SUFFIX_MANIFEST)?;
    let expected = expectation(&prefix, &suffix)?;
    let bytes = encode_archive_provenance(&expected).map_err(|e| e.to_string())?;
    let output = Path::new(&args[2]);
    let parent = output.parent().ok_or("missing output parent")?;
    require(
        output.is_absolute() && fs::canonicalize(parent).map_err(|e| e.to_string())? == parent,
        "noncanonical output parent",
    )?;
    let metadata = fs::metadata(parent).map_err(|e| e.to_string())?;
    require(
        metadata.is_dir() && metadata.uid() == 0 && metadata.mode() & 0o077 == 0,
        "output parent must be root-private",
    )?;
    let receipt = json!({"schema":"jetstreamer-private-epoch213-provenance-expectation-v1",
        "epoch":213,"producer_generation":GENERATION,"tool_sha256":args[4],
        "prefix_manifest":{"path":args[0],"sha256":PREFIX_MANIFEST},
        "suffix_manifest":{"path":args[1],"sha256":SUFFIX_MANIFEST},
        "prefix_archive_sha256":PREFIX_ARCHIVE,"suffix_archive_sha256":SUFFIX_ARCHIVE,
        "restart_snapshot_sha256":SNAPSHOT,"worker_sha256":WORKER,
        "expected_provenance_sha256":format!("{:x}",Sha256::digest(&bytes)),
        "expected_provenance_encoded_bytes":bytes.len(),"source_manifest_scope_validated":true,
        "assembled_target_opened":false,"source_archives_rehashed":false,
        "independent_final_archive_verification_passed":false,"current_plugin_verification_passed":false,
        "runtime_admission_authorized":false,"canonical_sidecar_authorized":false,
        "publication_authorized":false,"remote_mutations":false,"r2_mutations":false});
    let mut encoded = serde_json::to_vec_pretty(&receipt).map_err(|e| e.to_string())?;
    encoded.push(b'\n');
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(output)
        .map_err(|e| e.to_string())?;
    file.write_all(&encoded)
        .and_then(|_| file.sync_all())
        .map_err(|e| e.to_string())?;
    File::open(parent)
        .and_then(|f| f.sync_all())
        .map_err(|e| e.to_string())?;
    println!(
        "{}",
        receipt["expected_provenance_sha256"].as_str().unwrap()
    );
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sources() -> (HistoricalSegmentManifest, HistoricalSegmentManifest) {
        (
            serde_json::from_str(include_str!(
                "../../tests/fixtures/epoch213-prefix-segment.json"
            ))
            .unwrap(),
            serde_json::from_str(include_str!(
                "../../tests/fixtures/epoch213-suffix-segment.json"
            ))
            .unwrap(),
        )
    }
    #[test]
    fn derives_exact_restart_with_distinct_raw_namespaces() {
        let (p, s) = sources();
        let result = expectation(&p, &s).unwrap();
        let ArchiveProvenance::V4(value) = result else {
            panic!("expected V4")
        };
        assert_eq!(value.base.requested_slot_count, 432000);
        assert_ne!(
            value.base.handoffs[0].predecessor.next_write_version,
            value.base.handoffs[0].successor.next_write_version
        );
        assert_eq!(
            value.base.runtime_segments[1].write_versions.archive_start,
            p.emitted_raw_write_versions.end - p.emitted_raw_write_versions.start
        );
    }
    #[test]
    fn rejects_snapshot_worker_scope_checkpoint_and_terminal_changes() {
        let (p, s) = sources();
        let mutations: [fn(&mut HistoricalSegmentManifest); 6] = [
            |x| x.bootstrap_archive_sha256 = Some([1; 32]),
            |x| x.worker_executable_sha256 = [1; 32],
            |x| x.output_slot_start += 1,
            |x| x.bootstrap.bank_hash = "11111111111111111111111111111111".into(),
            |x| x.bootstrap.write_count = 1,
            |x| x.terminal.last_blockhash = "11111111111111111111111111111111".into(),
        ];
        for mutation in mutations {
            let mut bad = s.clone();
            mutation(&mut bad);
            assert!(expectation(&p, &bad).is_err());
        }
    }
    #[test]
    fn source_changes_cannot_silently_preserve_expected_envelope() {
        let (p, mut s) = sources();
        let original = encode_archive_provenance(&expectation(&p, &s).unwrap()).unwrap();
        s.emitted_raw_write_versions.end += 1;
        s.terminal.next_write_version += 1;
        let changed = encode_archive_provenance(&expectation(&p, &s).unwrap()).unwrap();
        assert_ne!(original, changed);
    }
}
