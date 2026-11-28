//! Derive a private, exact-width epoch 162 archive from a verified focused run.
use anyhow::{Context, Result, ensure};
use jetstreamer_horizon::archive::{
    ArchiveProvenance, ArchiveReader, ArchiveWriterConfig, ChainMismatchPolicy, SemanticDigest,
    reencode_archive_prefix,
};
use jetstreamer_node::{
    archive_checksum::{
        archive_file_identity, measure_open_archive, open_regular_nofollow,
        path_matches_archive_identity, rebind_validated_after_rename,
    },
    segment_manifest::{
        HistoricalSegmentManifest, SegmentRuntimeAdmission,
        read_and_validate_segment_manifest_from, segment_manifest_path, sha256_hex_string,
    },
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    env,
    fs::{self, File},
    io::{self, BufReader, BufWriter, Read, Write},
    os::unix::fs::MetadataExt,
    path::Path,
};

const ROOT: &str =
    "/home/sol/.jetstreamer-private/epoch162-postboundary-replay-20261126-v1/private";
const SOURCE: &str = "epoch-162-with-verification-tail.jet";
const EPOCH: u64 = 162;
const FIRST: u64 = 69_984_000;
const EPOCH_SLOTS: u64 = 432_000;
const TERMINAL: u64 = 70_423_069;
const REPLAY_SLOTS: u64 = TERMINAL - FIRST + 1;
const BOOTSTRAP: u64 = 69_983_760;
const BOOTSTRAP_HASH: &str = "3L1S15myC9s3LUY6yh6h5yMZhmC87miSMxvdrjXD85VP";
const TERMINAL_HASH: &str = "7mxUref2z29aPMpsQvPnaqrMFqfih5kPchKu6m9recc6";
const WORKER_SHA: &str = "cf5fa883df75b23de82af52dc0e90c013f8e83397b445027e510a1137decc819";
const RUNTIME_REVISION: &str = "01e4d0a1e9917701d1a148e1043b0ccf545c27f1";

fn validate_scope(manifest: &HistoricalSegmentManifest) -> Result<()> {
    ensure!(
        manifest.epoch == EPOCH
            && manifest.output_slot_start == FIRST
            && manifest.output_slot_count == REPLAY_SLOTS
            && manifest.runtime.runtime_profile == "solana-v1.5.6"
            && manifest.runtime.runtime_revision == RUNTIME_REVISION
            && manifest.runtime.runtime_admission == SegmentRuntimeAdmission::Candidate
            && manifest.runtime.genesis_hash
                == jetstreamer_historical_protocol::MAINNET_GENESIS_HASH
            && sha256_hex_string(&manifest.worker_executable_sha256) == WORKER_SHA
            && manifest.bootstrap.slot == BOOTSTRAP
            && manifest.bootstrap.accounts_hash == BOOTSTRAP_HASH
            && manifest.bootstrap.slot_complete
            && manifest.bootstrap.write_count == 0
            && manifest.terminal.slot == TERMINAL
            && manifest.terminal.accounts_hash == TERMINAL_HASH
            && manifest.terminal.slot_complete,
        "segment does not bind the selected epoch 162 runtime, bootstrap, and terminal checkpoint"
    );
    Ok(())
}

fn frozen(path: &Path) -> Result<File> {
    ensure!(
        path.canonicalize()? == path,
        "aliased input {}",
        path.display()
    );
    let file = open_regular_nofollow(path)?;
    let meta = file.metadata()?;
    ensure!(
        meta.is_file() && meta.nlink() == 1 && meta.mode() & 0o222 == 0,
        "input must be frozen and singly linked"
    );
    Ok(file)
}

fn check_floor(directory: &File, minimum_free_bytes: u64, next_write: usize) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let mut stats = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    if unsafe { libc::fstatvfs(directory.as_raw_fd(), stats.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let stats = unsafe { stats.assume_init() };
    let available = stats.f_bavail.saturating_mul(stats.f_frsize);
    if available.saturating_sub(next_write as u64) < minimum_free_bytes {
        return Err(io::Error::other(
            "archive extraction would cross its admitted HOME floor",
        ));
    }
    Ok(())
}

// Checks the bound on each actual write beneath the buffered archive encoder.
struct BoundedOutput<'a> {
    file: &'a mut File,
    directory: &'a File,
    maximum_bytes: u64,
    minimum_free_bytes: u64,
    written: u64,
}

impl Write for BoundedOutput<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() as u64 > self.maximum_bytes.saturating_sub(self.written) {
            return Err(io::Error::other(
                "archive extraction exceeds its output allocation",
            ));
        }
        check_floor(self.directory, self.minimum_free_bytes, bytes.len())?;
        let count = self.file.write(bytes)?;
        self.written += count as u64;
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

fn expected_prefix(source: &File) -> Result<ArchiveProvenance> {
    let reader = ArchiveReader::open(BufReader::new(source.try_clone()?))?;
    let header = reader.header();
    ensure!(
        header.epoch == EPOCH && header.slot_start == FIRST && header.slot_count == REPLAY_SLOTS,
        "source archive has an unexpected slot range"
    );
    let Some(ArchiveProvenance::V2(mut provenance)) = reader.provenance()? else {
        anyhow::bail!("source must have uninterrupted single-runtime V2 provenance");
    };
    provenance.base.requested_slot_count = EPOCH_SLOTS;
    Ok(ArchiveProvenance::V2(provenance))
}

fn verify_prefix(file: &File, provenance: &ArchiveProvenance, digest: [u8; 32]) -> Result<()> {
    let mut reader = ArchiveReader::open(BufReader::new(file.try_clone()?))?;
    reader.verify_chain = true;
    reader.chain_mismatch_policy = ChainMismatchPolicy::Reject;
    let header = reader.header();
    ensure!(
        header.epoch == EPOCH
            && header.slot_start == FIRST
            && header.slot_count == EPOCH_SLOTS
            && reader.has_complete_slot_coverage()?
            && reader.provenance()?.as_ref() == Some(provenance),
        "extracted archive does not contain one complete epoch with the expected provenance"
    );
    let mut visitor = SemanticDigest::new();
    ensure!(
        reader.read_slots(FIRST, EPOCH_SLOTS, &mut visitor)? == EPOCH_SLOTS
            && visitor.finish()? == digest,
        "independent semantic reread differs from the extracted prefix"
    );
    Ok(())
}

fn run(manifest_sha: &str, maximum_bytes: u64, minimum_free_bytes: u64) -> Result<Value> {
    ensure!(
        maximum_bytes > 0 && minimum_free_bytes > 0,
        "supply the admitted output allocation and HOME floor"
    );
    let root = Path::new(ROOT);
    let directory = File::open(root)?;
    let m = directory.metadata()?;
    ensure!(
        root.canonicalize()? == root
            && m.is_dir()
            && m.uid() == unsafe { libc::geteuid() }
            && m.mode() & 0o077 == 0
            && m.dev() == fs::metadata("/home/sol")?.dev(),
        "candidate directory must be owner-private and on HOME"
    );
    check_floor(&directory, minimum_free_bytes, 0)?;
    let archive = root.join(SOURCE);
    let manifest_path = segment_manifest_path(&archive)?;
    let source = frozen(&archive)?;
    let source_id = archive_file_identity(&source)?;
    let manifest_file = frozen(&manifest_path)?;
    let manifest_id = archive_file_identity(&manifest_file)?;
    let mut manifest_bytes = Vec::new();
    (&manifest_file)
        .take((1 << 20) + 1)
        .read_to_end(&mut manifest_bytes)?;
    ensure!(
        manifest_bytes.len() <= 1 << 20
            && format!("{:x}", Sha256::digest(&manifest_bytes)) == manifest_sha,
        "source manifest differs from the admitted digest"
    );
    let bound_manifest: HistoricalSegmentManifest = serde_json::from_slice(&manifest_bytes)?;
    validate_scope(&bound_manifest)?;
    let manifest = read_and_validate_segment_manifest_from(&archive, &manifest_path)?;
    ensure!(
        manifest == bound_manifest,
        "source manifest changed during validation"
    );
    let provenance = expected_prefix(&source)?;

    let target = root.join("epoch-162.jet");
    for name in [
        "epoch-162.jet.sha256",
        "epoch-162.sha256",
        "epoch-162.jet.segment.json",
    ] {
        ensure!(
            root.join(name)
                .symlink_metadata()
                .is_err_and(|err| err.kind() == io::ErrorKind::NotFound),
            "private candidate must have no readiness or segment sidecar"
        );
    }
    let existing = match target.symlink_metadata() {
        Ok(_) => Some(frozen(&target)?),
        Err(err) if err.kind() == io::ErrorKind::NotFound => None,
        Err(err) => return Err(err.into()),
    };
    let mut temporary = None;
    let stats = if existing.is_some() {
        reencode_archive_prefix(
            BufReader::new(source.try_clone()?),
            io::sink(),
            ArchiveWriterConfig::default(),
            EPOCH_SLOTS,
        )?
        .1
    } else {
        let mut file = tempfile::NamedTempFile::new_in(root)?;
        let writer = BoundedOutput {
            file: file.as_file_mut(),
            directory: &directory,
            written: 0,
            maximum_bytes,
            minimum_free_bytes,
        };
        let output = BufWriter::with_capacity(8 << 20, writer);
        let (mut output, stats) = reencode_archive_prefix(
            BufReader::new(source.try_clone()?),
            output,
            ArchiveWriterConfig::default(),
            EPOCH_SLOTS,
        )?;
        output.flush()?;
        drop(output);
        file.as_file().sync_all()?;
        temporary = Some(file);
        stats
    };
    ensure!(
        stats.source_epoch == EPOCH
            && stats.source_slot_start == FIRST
            && stats.source_slot_count == REPLAY_SLOTS
            && stats.slots_reencoded == EPOCH_SLOTS
            && stats.source_zero_parent_resume_artifacts == 0
            && stats.output_zero_parent_resume_artifacts == 0,
        "unexpected prefix statistics"
    );
    let file = existing
        .as_ref()
        .or_else(|| temporary.as_ref().map(tempfile::NamedTempFile::as_file))
        .context("missing candidate output")?;
    let identity_before = archive_file_identity(file)?;
    let output_bytes = file.metadata()?.len();
    ensure!(
        output_bytes <= maximum_bytes,
        "candidate exceeds its admitted allocation"
    );
    verify_prefix(file, &provenance, stats.output_semantic_sha256)?;
    let measured = measure_open_archive(file)?;
    ensure!(
        measured.identity == identity_before,
        "candidate changed during readback"
    );
    ensure!(
        path_matches_archive_identity(&archive, source_id)?
            && path_matches_archive_identity(&manifest_path, manifest_id)?,
        "validated source or sidecar changed"
    );
    ensure!(
        fs::metadata(root).is_ok_and(|now| (now.dev(), now.ino()) == (m.dev(), m.ino())),
        "candidate directory changed"
    );
    if let Some(file) = temporary {
        use std::os::unix::fs::PermissionsExt;
        file.as_file()
            .set_permissions(fs::Permissions::from_mode(0o400))?;
        let frozen_identity = rebind_validated_after_rename(file.as_file(), measured)?;
        let file = file.persist_noclobber(&target)?;
        file.sync_all()?;
        let placed = rebind_validated_after_rename(&file, frozen_identity)?;
        ensure!(
            path_matches_archive_identity(&target, placed.identity)?,
            "candidate changed during final placement"
        );
        directory.sync_all()?;
    } else {
        ensure!(
            path_matches_archive_identity(&target, measured.identity)?,
            "candidate changed"
        );
    }
    Ok(json!({
        "schema":"horizon-epoch162-private-prefix-extraction-v1",
        "epoch":EPOCH,"first_slot":FIRST,"slot_count":EPOCH_SLOTS,
        "private_verification_tail_slots":REPLAY_SLOTS-EPOCH_SLOTS,
        "source_archive":archive,"source_sha256":sha256_hex_string(&manifest.archive_sha256),
        "source_manifest_sha256":manifest_sha,"source_checkpoint_slot":TERMINAL,
        "source_checkpoint_accounts_hash":TERMINAL_HASH,
        "candidate":target,"candidate_bytes":output_bytes,"candidate_sha256":sha256_hex_string(&measured.sha256),
        "candidate_semantic_sha256":sha256_hex_string(&stats.output_semantic_sha256),
        "independent_candidate_reread_passed":true,"current_plugin_verification_passed":false,
        "publication_authorized":false,"source_retirement_authorized":false
    }))
}

fn main() -> Result<()> {
    let args: Vec<_> = env::args().skip(1).collect();
    let [manifest_sha, allocation, floor] = args.as_slice() else {
        anyhow::bail!(
            "usage: jetstreamer-epoch162-prefix-extract MANIFEST_SHA256 MAX_OUTPUT_BYTES MIN_HOME_FREE_BYTES"
        );
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&run(manifest_sha, allocation.parse()?, floor.parse()?)?)?
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use jetstreamer_horizon::archive::{
        ArchiveProvenanceV1, ArchiveProvenanceV2, ArchiveWriter, BootstrapStateKind, Compression,
        RuntimeAdmission, TransactionMetadataPolicy,
    };
    use solana_hash::Hash;

    #[test]
    fn exact_epoch_prefix_excludes_every_private_verification_slot() -> Result<()> {
        let provenance = ArchiveProvenance::V2(ArchiveProvenanceV2 {
            base: ArchiveProvenanceV1 {
                generation_profile: "jetstreamer-node/historical-replay-v1".into(),
                runtime_profile: "solana-v1.5.6".into(),
                runtime_admission: RuntimeAdmission::Candidate,
                runtime_revision: RUNTIME_REVISION.into(),
                runtime_toolchain: "rustc1.49.0".into(),
                genesis_hash: jetstreamer_historical_protocol::MAINNET_GENESIS_HASH.parse()?,
                bootstrap_state_kind: BootstrapStateKind::SnapshotArchive,
                bootstrap_slot: BOOTSTRAP,
                bootstrap_state_hash: BOOTSTRAP_HASH.parse()?,
                requested_slot_start: FIRST,
                requested_slot_count: REPLAY_SLOTS,
                transaction_metadata: TransactionMetadataPolicy::runtime_reconstructed(),
            },
            worker_executable_sha256: [7; 32],
        });
        let config = ArchiveWriterConfig {
            compression: Compression::None,
            ..Default::default()
        };
        let mut writer = ArchiveWriter::new_with_provenance(
            tempfile::tempfile()?,
            EPOCH,
            FIRST,
            REPLAY_SLOTS,
            config.clone(),
            &provenance,
        )?;
        writer.preserve_initial_poh_anchor(FIRST, Hash::new_from_array([9; 32]))?;
        for slot in FIRST..=TERMINAL {
            writer.write_skipped_slot(slot)?;
        }
        let source = writer.finish()?.0;
        let before = measure_open_archive(&source)?;
        let prefix_provenance = expected_prefix(&source)?;
        let (candidate, stats) = reencode_archive_prefix(
            BufReader::new(source.try_clone()?),
            tempfile::tempfile()?,
            config,
            EPOCH_SLOTS,
        )?;
        verify_prefix(&candidate, &prefix_provenance, stats.output_semantic_sha256)?;
        assert!(verify_prefix(&candidate, &prefix_provenance, [0; 32]).is_err());
        assert!(verify_prefix(&source, &prefix_provenance, stats.output_semantic_sha256).is_err());
        assert_eq!(stats.source_slot_count - stats.slots_reencoded, 7_070);
        assert_eq!(measure_open_archive(&source)?, before);
        Ok(())
    }
}
