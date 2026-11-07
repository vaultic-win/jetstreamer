//! Correctness core for private epoch 145 prefix extraction.
//!
//! This does not authorize an executor, resources, sidecars, publication or
//! source retirement. A separately admitted controller must bind the completed
//! producer and the exact worker pin, retain the full checkpoint-bearing source,
//! supply a live output-budget guard, and persist the returned evidence.
use crate::{
    archive_checksum::{
        ArchiveFileIdentity, archive_file_identity, open_regular_nofollow,
        path_matches_archive_identity,
    },
    segment_manifest::{
        HistoricalSegmentManifest, SegmentRuntimeAdmission,
        read_and_validate_segment_manifest_from, sha256_hex_string,
    },
};
use anyhow::{Result, ensure};
use jetstreamer_horizon::archive::{
    ArchiveProvenance, ArchiveReader, ArchiveWriterConfig, BootstrapStateKind, ChainMismatchPolicy,
    SemanticDigest, encode_archive_provenance, reencode_archive_prefix,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{self, BufReader, Read, Seek, SeekFrom, Write},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};

pub const FIRST_SLOT: u64 = 62_640_000;
pub const CANONICAL_SLOTS: u64 = 432_000;
pub const FOCUSED_SLOTS: u64 = 432_071;
pub const TERMINAL_ROOT: u64 = 63_072_070;
/// Retained corrected-loader worker, bound by epoch 144 native checkpoint evidence.
/// Its epoch 145 execution remains a candidate, not an inferred qualification.
pub const PINNED_WORKER_SHA256: [u8; 32] = [
    0x2c, 0xca, 0x50, 0x01, 0x06, 0xd2, 0x74, 0xeb, 0xfb, 0xbc, 0x8c, 0x5b, 0xfa, 0x0e, 0x6e, 0x83,
    0x43, 0xcd, 0x5e, 0x41, 0x00, 0x3f, 0x9e, 0x82, 0xc9, 0x32, 0x82, 0x80, 0x07, 0x32, 0xd8, 0xc8,
];
const MAXIMUM_OUTPUT_BYTES: u64 = 160u64 << 30;

/// Immutable source evidence held across the complete transformation.
pub struct PinnedSource {
    path: PathBuf,
    file: File,
    identity: ArchiveFileIdentity,
    manifest: HistoricalSegmentManifest,
    manifest_path: PathBuf,
    manifest_file: File,
    manifest_identity: ArchiveFileIdentity,
    manifest_sha256: [u8; 32],
}

/// Data-integrity evidence only. All operational/publication gates remain closed.
#[derive(Debug, Serialize)]
pub struct ExtractionEvidence {
    pub schema: &'static str,
    pub epoch: u64,
    pub source_archive: PathBuf,
    pub source_archive_sha256: String,
    pub source_manifest_sha256: String,
    pub worker_sha256: String,
    pub source_canonical_checkpoint_slot: u64,
    pub source_canonical_accounts_hash: &'static str,
    pub archive: PathBuf,
    pub archive_sha256: String,
    pub archive_bytes: u64,
    pub output_slot_start: u64,
    pub output_slot_count: u64,
    pub output_semantic_sha256: String,
    /// Commitment derived from authenticated source provenance before output exists.
    /// This is verifier input, never runtime qualification or publication authority.
    pub expected_output_provenance_sha256: String,
    pub retained_verification_tail_slots: u64,
    pub source_must_be_retained: bool,
    pub independent_output_reread_passed: bool,
    pub current_plugin_verification_passed: bool,
    pub canonical_sidecar_authorized: bool,
    pub publication_authorized: bool,
    pub retirement_authorized: bool,
    pub r2_mutations: bool,
}

/// Validates this exact checkpoint-bounded shape, without treating it as a
/// complete epoch or promoting the candidate runtime. `worker` must come from
/// the separately sealed 145 package and the controller's hash-bound admission.
pub fn validate_scope(m: &HistoricalSegmentManifest, worker: [u8; 32]) -> Result<()> {
    ensure!(
        worker == PINNED_WORKER_SHA256
            && m.epoch == 145
            && m.output_slot_start == FIRST_SLOT
            && m.output_slot_count == FOCUSED_SLOTS
            && m.worker_executable_sha256 == worker
            && m.runtime.runtime_profile == "solana-v1.4.25"
            && m.runtime.runtime_revision == "893cc7647248a3536fb6e6d0b5e51c71446b862d"
            && m.runtime.runtime_admission == SegmentRuntimeAdmission::Candidate
            && m.runtime.genesis_hash == jetstreamer_historical_protocol::MAINNET_GENESIS_HASH
            && m.bootstrap.slot == 62_639_490
            && m.bootstrap.accounts_hash == "59bAQjc2c1VqNWqGoCacp3tnyNyie3EYx4bjttvJhgeT"
            && m.bootstrap.bank_hash == "CoM8739uCp31r3ZJoLKPzag2aG9JcL9naR5TMaFAZAZ9"
            && m.bootstrap.last_blockhash == "7AFqLphUQsd92pntzKB25ad5iPiJae9yjt742HFgLuoV"
            && m.bootstrap.capitalization == 488_586_979_125_186_779
            && m.bootstrap.transaction_count == 10_186_599_902
            && m.bootstrap.tick_height == 4_008_927_424
            && m.bootstrap.slot_complete
            && m.bootstrap.write_count == 0
            && m.bootstrap.next_write_version == 31_418_315_426
            && m.terminal.slot == TERMINAL_ROOT
            && m.terminal.accounts_hash == "DsoBNgzFVZ7j5bF2CpKnt7HAC7fRrMMwdWW9FUafRe1p"
            && m.terminal.slot_complete,
        "145 source does not bind the exact cold bootstrap, worker, full output and canonical tail root"
    );
    Ok(())
}
/// Derive a strict full-verifier commitment from authenticated source provenance.
/// The caller must authenticate the source/manifest first. This function does
/// no I/O and does not qualify a runtime or authorize extraction/publication.
pub fn canonical_prefix_provenance(
    source: ArchiveProvenance,
) -> Result<(ArchiveProvenance, String)> {
    let mut prefix = match source {
        ArchiveProvenance::V2(value) => value,
        _ => anyhow::bail!("145 source lost V2 provenance"),
    };
    ensure!(
        prefix.base.bootstrap_state_kind == BootstrapStateKind::SnapshotArchive
            && prefix.base.runtime_admission
                == jetstreamer_horizon::archive::RuntimeAdmission::Candidate
            && prefix.base.requested_slot_start == FIRST_SLOT
            && prefix.base.requested_slot_count == FOCUSED_SLOTS
            && prefix.worker_executable_sha256 == PINNED_WORKER_SHA256,
        "145 expected provenance does not bind the complete candidate source"
    );
    prefix.base.requested_slot_count = CANONICAL_SLOTS;
    let prefix = ArchiveProvenance::V2(prefix);
    let sha256 = format!("{:x}", Sha256::digest(encode_archive_provenance(&prefix)?));
    Ok((prefix, sha256))
}

fn immutable(path: &Path) -> Result<fs::Metadata> {
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "145 input must be canonical"
    );
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_file() && m.nlink() == 1 && m.mode() & 0o222 == 0,
        "145 input must be frozen, singly linked and regular"
    );
    Ok(m)
}

fn open_immutable(path: &Path) -> Result<(File, ArchiveFileIdentity)> {
    immutable(path)?;
    let file = open_regular_nofollow(path)?;
    let metadata = file.metadata()?;
    let identity = archive_file_identity(&file)?;
    ensure!(
        metadata.nlink() == 1
            && metadata.mode() & 0o222 == 0
            && path_matches_archive_identity(path, identity)?,
        "145 immutable input changed while opening"
    );
    Ok((file, identity))
}

fn validate_destination(root: &Path) -> Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(root)?;
    ensure!(
        root.is_absolute()
            && root.canonicalize()? == root
            && metadata.is_dir()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o077 == 0
            && root
                .parent()
                .and_then(Path::file_name)
                .is_some_and(|n| n == ".jetstreamer-private")
            && root
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("epoch145-prefix-extract-") && n.len() > 24),
        "145 destination must be an owner-private epoch145-prefix-extract directory beneath .jetstreamer-private"
    );
    for name in [
        "epoch-145.jet.sha256",
        "epoch-145.sha256",
        "epoch-145.jet.segment.json",
    ] {
        match fs::symlink_metadata(root.join(name)) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
            Ok(_) => anyhow::bail!("145 candidate must have no publication/terminal sidecar"),
        }
    }
    Ok(metadata)
}
impl PinnedSource {
    /// Authenticates the manifest and performs the existing complete archive
    /// SHA-256/deep decode validation, then holds its immutable source handle.
    pub fn open(
        archive: &Path,
        manifest: &Path,
        manifest_sha256: [u8; 32],
        worker: [u8; 32],
    ) -> Result<Self> {
        let (mut manifest_file, manifest_identity) = open_immutable(manifest)?;
        ensure!(
            manifest_file.metadata()?.len() <= 1 << 20,
            "145 manifest oversized"
        );
        let mut bytes = Vec::new();
        (&mut manifest_file)
            .take((1 << 20) + 1)
            .read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 1 << 20, "145 manifest grew beyond its bound");
        ensure!(
            <[u8; 32]>::from(Sha256::digest(&bytes)) == manifest_sha256,
            "145 manifest SHA differs"
        );
        let (file, identity) = open_immutable(archive)?;
        let m = read_and_validate_segment_manifest_from(archive, manifest)?;
        validate_scope(&m, worker)?;
        ensure!(
            archive_file_identity(&file)? == identity
                && path_matches_archive_identity(archive, identity)?
                && archive_file_identity(&manifest_file)? == manifest_identity
                && path_matches_archive_identity(manifest, manifest_identity)?,
            "145 source/manifest changed during qualification"
        );
        Ok(Self {
            path: archive.into(),
            file,
            identity,
            manifest: m,
            manifest_path: manifest.into(),
            manifest_file,
            manifest_identity,
            manifest_sha256,
        })
    }
    fn unchanged(&self) -> Result<()> {
        ensure!(
            archive_file_identity(&self.file)? == self.identity
                && path_matches_archive_identity(&self.path, self.identity)?
                && archive_file_identity(&self.manifest_file)? == self.manifest_identity
                && path_matches_archive_identity(&self.manifest_path, self.manifest_identity)?,
            "145 pinned source changed"
        );
        Ok(())
    }

    fn source_reader(&self) -> Result<BufReader<File>> {
        self.unchanged()?;
        let mut file = self.file.try_clone()?;
        file.seek(SeekFrom::Start(0))?;
        Ok(BufReader::new(file))
    }

    /// Creates a private, canonical-width candidate using the existing strict
    /// prefix re-encoder. The caller's guard runs before every output write and
    /// must enforce its fresh admission/floor. No checksum/segment sidecar is
    /// created: the actual terminal checkpoint stays in the retained source.
    pub fn extract_private<G>(
        &mut self,
        root: &Path,
        maximum_bytes: u64,
        mut guard: G,
    ) -> Result<ExtractionEvidence>
    where
        G: FnMut(u64) -> io::Result<()>,
    {
        ensure!(
            (1..=MAXIMUM_OUTPUT_BYTES).contains(&maximum_bytes),
            "145 output bound exceeds the reviewed 160 GiB ceiling"
        );
        let directory_identity = validate_destination(root)?;
        let target = root.join("epoch-145.jet");
        ensure!(
            self.path != target,
            "145 extraction cannot replace its source"
        );
        self.unchanged()?;
        let original_output = if target.try_exists()? {
            immutable(&target)?;
            Some(archive_file_identity(&open_regular_nofollow(&target)?)?)
        } else {
            None
        };
        let source_provenance = ArchiveReader::open(self.source_reader()?)?
            .provenance()?
            .ok_or_else(|| anyhow::anyhow!("145 source lost V2 provenance"))?;
        let (expected, expected_output_provenance_sha256) =
            canonical_prefix_provenance(source_provenance)?;
        let mut temporary = if original_output.is_none() {
            Some(tempfile::NamedTempFile::new_in(root)?)
        } else {
            None
        };
        let stats = if let Some(t) = temporary.as_mut() {
            let output = Limited {
                sink: t.as_file_mut(),
                bytes: 0,
                maximum: maximum_bytes,
                guard: &mut guard,
            };
            let (_, stats) = reencode_archive_prefix(
                self.source_reader()?,
                output,
                ArchiveWriterConfig::default(),
                CANONICAL_SLOTS,
            )?;
            t.as_file_mut().flush()?;
            t.as_file().sync_all()?;
            stats
        } else {
            // Receipt-recovery retry: derive the expected output semantics
            // without allocating or replacing another archive.
            reencode_archive_prefix(
                self.source_reader()?,
                io::sink(),
                ArchiveWriterConfig::default(),
                CANONICAL_SLOTS,
            )?
            .1
        };
        let output_path = temporary
            .as_ref()
            .map(|t| t.path())
            .unwrap_or(target.as_path());
        let output_file = open_regular_nofollow(output_path)?;
        let output_identity = archive_file_identity(&output_file)?;
        ensure!(
            stats.source_epoch == 145
                && stats.source_slot_start == FIRST_SLOT
                && stats.source_slot_count == FOCUSED_SLOTS
                && stats.slots_reencoded == CANONICAL_SLOTS
                && stats.source_zero_parent_resume_artifacts == 0
                && stats.output_zero_parent_resume_artifacts == 0,
            "145 prefix export shape or strict chain differs"
        );
        let mut reader = ArchiveReader::open(BufReader::new(open_regular_nofollow(output_path)?))?;
        reader.verify_chain = true;
        reader.chain_mismatch_policy = ChainMismatchPolicy::Reject;
        ensure!(
            reader.header().epoch == 145
                && reader.header().slot_start == FIRST_SLOT
                && reader.header().slot_count == CANONICAL_SLOTS
                && reader.has_complete_slot_coverage()?,
            "145 output does not cover exactly one complete epoch"
        );
        ensure!(
            reader.provenance()? == Some(expected),
            "145 output provenance changed"
        );
        let mut semantic = SemanticDigest::new();
        ensure!(
            reader.read_slots(FIRST_SLOT, CANONICAL_SLOTS, &mut semantic)? == CANONICAL_SLOTS
                && semantic.finish()? == stats.output_semantic_sha256,
            "145 independent output semantic reread failed"
        );
        let mut output = open_regular_nofollow(output_path)?;
        let mut hash = Sha256::new();
        io::copy(&mut output, &mut hash)?;
        let bytes = output.metadata()?.len();
        ensure!(bytes <= maximum_bytes, "145 output exceeds admitted bound");
        ensure!(
            archive_file_identity(&output_file)? == output_identity
                && archive_file_identity(&output)? == output_identity
                && path_matches_archive_identity(output_path, output_identity)?,
            "145 output changed during independent reread"
        );
        self.unchanged()?;
        let current_directory = validate_destination(root)?;
        ensure!(
            directory_identity.dev() == current_directory.dev()
                && directory_identity.ino() == current_directory.ino(),
            "145 destination directory changed during extraction"
        );
        if let Some(t) = temporary {
            t.as_file()
                .set_permissions(fs::Permissions::from_mode(0o400))?;
            t.as_file().sync_all()?;
            t.persist_noclobber(&target)
                .map_err(|e| anyhow::anyhow!("145 candidate publication conflict: {e}"))?;
            File::open(root)?.sync_all()?;
        } else {
            ensure!(
                original_output == Some(archive_file_identity(&output)?)
                    && path_matches_archive_identity(&target, original_output.unwrap())?,
                "145 existing candidate changed during receipt recovery"
            );
        }
        Ok(ExtractionEvidence {
            schema: "jetstreamer-private-epoch145-canonical-prefix-extraction-v1",
            epoch: 145,
            source_archive: self.path.clone(),
            source_archive_sha256: sha256_hex_string(&self.manifest.archive_sha256),
            source_manifest_sha256: sha256_hex_string(&self.manifest_sha256),
            worker_sha256: sha256_hex_string(&self.manifest.worker_executable_sha256),
            source_canonical_checkpoint_slot: TERMINAL_ROOT,
            source_canonical_accounts_hash: "DsoBNgzFVZ7j5bF2CpKnt7HAC7fRrMMwdWW9FUafRe1p",
            archive: target,
            archive_sha256: format!("{:x}", hash.finalize()),
            archive_bytes: bytes,
            output_slot_start: FIRST_SLOT,
            output_slot_count: CANONICAL_SLOTS,
            output_semantic_sha256: sha256_hex_string(&stats.output_semantic_sha256),
            expected_output_provenance_sha256,
            retained_verification_tail_slots: 71,
            source_must_be_retained: true,
            independent_output_reread_passed: true,
            current_plugin_verification_passed: false,
            canonical_sidecar_authorized: false,
            publication_authorized: false,
            retirement_authorized: false,
            r2_mutations: false,
        })
    }
}
struct Limited<'a, W, G> {
    sink: W,
    bytes: u64,
    maximum: u64,
    guard: &'a mut G,
}
impl<W: Write, G: FnMut(u64) -> io::Result<()>> Write for Limited<'_, W, G> {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        let next = self
            .bytes
            .checked_add(b.len() as u64)
            .ok_or_else(|| io::Error::other("145 output bound overflow"))?;
        if next > self.maximum {
            return Err(io::Error::other("145 output bound crossed"));
        }
        (self.guard)(next)?;
        let n = self.sink.write(b)?;
        self.bytes += n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.sink.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canonical_width_preserves_events_and_provenance_and_excludes_the_private_tail() {
        use jetstreamer_horizon::account_updates::AccountUpdateView;
        use jetstreamer_horizon::archive::{
            ArchiveProvenanceV1, ArchiveProvenanceV2, ArchiveWriter, BootstrapStateKind,
            Compression, EntryRecord, EpochMeta, RuntimeAdmission, TransactionMetadataPolicy,
        };
        use jetstreamer_horizon::block_metas::BlockMeta;
        use jetstreamer_horizon::transactions::Transaction;
        use solana_address::Address;
        use solana_hash::Hash;
        use solana_signature::Signature;
        let provenance = ArchiveProvenance::V2(ArchiveProvenanceV2 {
            base: ArchiveProvenanceV1 {
                generation_profile: "jetstreamer-node/historical-replay-v1".into(),
                runtime_profile: "solana-v1.4.25".into(),
                runtime_admission: RuntimeAdmission::Candidate,
                runtime_revision: "893cc7647248a3536fb6e6d0b5e51c71446b862d".into(),
                runtime_toolchain: "rustc1.46.0".into(),
                genesis_hash: Hash::new_from_array([5; 32]),
                bootstrap_state_kind: BootstrapStateKind::SnapshotArchive,
                bootstrap_slot: 62639490,
                bootstrap_state_hash: Hash::new_from_array([9; 32]),
                requested_slot_start: FIRST_SLOT,
                requested_slot_count: FOCUSED_SLOTS,
                transaction_metadata: TransactionMetadataPolicy::runtime_reconstructed(),
            },
            worker_executable_sha256: PINNED_WORKER_SHA256,
        });
        // Compute the expectation before an output exists, from the source value.
        let (source_derived_prefix, source_derived_prefix_sha256) =
            canonical_prefix_provenance(provenance.clone()).unwrap();
        assert_ne!(
            source_derived_prefix_sha256,
            format!(
                "{:x}",
                Sha256::digest(encode_archive_provenance(&provenance).unwrap())
            )
        );
        let mut promoted = provenance.clone();
        let ArchiveProvenance::V2(ref mut value) = promoted else {
            unreachable!()
        };
        value.base.runtime_admission = RuntimeAdmission::Verified;
        assert!(canonical_prefix_provenance(promoted).is_err());
        let config = ArchiveWriterConfig {
            compression: Compression::None,
            ..Default::default()
        };
        let mut writer = ArchiveWriter::new_with_provenance(
            Vec::new(),
            145,
            FIRST_SLOT,
            FOCUSED_SLOTS,
            config.clone(),
            &provenance,
        )
        .unwrap();
        writer
            .preserve_initial_poh_anchor(FIRST_SLOT, Hash::new_from_array([7; 32]))
            .unwrap();
        let mut parent = Hash::new_from_array([7; 32]);
        let mut parent_slot = FIRST_SLOT - 1;
        for offset in 0..FOCUSED_SLOTS {
            let slot = FIRST_SLOT + offset;
            if ![1, CANONICAL_SLOTS - 1, FOCUSED_SLOTS - 1].contains(&offset) {
                writer.write_skipped_slot(slot).unwrap();
                continue;
            }
            writer.begin_slot(slot).unwrap();
            let mut update = AccountUpdateView {
                pubkey: Address::new_from_array([7; 32]),
                lamports: offset,
                owner: Address::new_from_array([8; 32]),
                executable: false,
                rent_epoch: u64::MAX,
                write_version: 9_007_199_254_740_993 + offset * 10,
                data: b"retained exactly",
            };
            if offset == 1 {
                let mut epoch = EpochMeta::new_boxed();
                epoch.epoch = 145;
                epoch.start_slot = FIRST_SLOT;
                epoch.slot_count = FOCUSED_SLOTS;
                epoch.first_block_slot = slot;
                epoch.updates.push(&update).unwrap();
                writer.write_epoch_meta(&epoch).unwrap();
                update.write_version += 1;
            }
            writer.write_orphan_update(&update).unwrap();
            update.write_version += 1;
            let mut tx = Transaction::new_boxed();
            tx.signatures.push(Signature::default());
            tx.push_account_update(&update).unwrap();
            writer.write_transaction(&tx).unwrap();
            update.write_version += 1;
            writer.write_orphan_update(&update).unwrap();
            let mut block = BlockMeta::new_boxed();
            block.slot = slot;
            block.parent_slot = parent_slot;
            block.parent_blockhash = parent;
            block.blockhash = Hash::new_from_array([offset as u8; 32]);
            block.executed_transaction_count = 1;
            block.entry_count = 1;
            writer
                .end_slot(
                    &block,
                    &[EntryRecord {
                        num_hashes: 1,
                        tx_count: 1,
                    }],
                )
                .unwrap();
            parent = block.blockhash;
            parent_slot = slot;
        }
        let source = writer.finish().unwrap().0;
        let before = Sha256::digest(&source);
        let (output, stats) = reencode_archive_prefix(
            std::io::Cursor::new(&source),
            Vec::new(),
            config,
            CANONICAL_SLOTS,
        )
        .unwrap();
        let mut reader = ArchiveReader::open(std::io::Cursor::new(output)).unwrap();
        reader.verify_chain = true;
        assert_eq!(reader.header().slot_count, CANONICAL_SLOTS);
        assert!(reader.has_complete_slot_coverage().unwrap());
        let mut digest = SemanticDigest::new();
        assert_eq!(
            reader
                .read_slots(FIRST_SLOT, CANONICAL_SLOTS, &mut digest)
                .unwrap(),
            CANONICAL_SLOTS
        );
        assert_eq!(digest.finish().unwrap(), stats.output_semantic_sha256);
        let mut expected = match provenance {
            ArchiveProvenance::V2(p) => p,
            _ => unreachable!(),
        };
        expected.base.requested_slot_count = CANONICAL_SLOTS;
        assert_eq!(
            reader.provenance().unwrap(),
            Some(ArchiveProvenance::V2(expected))
        );
        assert_eq!(reader.provenance().unwrap(), Some(source_derived_prefix));
        let actual_encoded =
            encode_archive_provenance(&reader.provenance().unwrap().unwrap()).unwrap();
        assert_eq!(
            format!("{:x}", Sha256::digest(actual_encoded)),
            source_derived_prefix_sha256
        );
        let mut selected_source = SemanticDigest::new();
        ArchiveReader::open(std::io::Cursor::new(&source))
            .unwrap()
            .read_slots(FIRST_SLOT, CANONICAL_SLOTS, &mut selected_source)
            .unwrap();
        assert_eq!(
            selected_source.finish().unwrap(),
            stats.source_semantic_sha256
        );
        assert_ne!(stats.source_semantic_sha256, stats.output_semantic_sha256);
        assert_eq!(
            ArchiveReader::open(std::io::Cursor::new(&source))
                .unwrap()
                .header()
                .slot_count,
            FOCUSED_SLOTS
        );
        assert_eq!(before, Sha256::digest(&source));
        assert_eq!(stats.source_slot_count - stats.slots_reencoded, 71);
    }
    fn manifest() -> HistoricalSegmentManifest {
        serde_json::from_value(serde_json::json!({"schema_version":1,"epoch":145,"output_slot_start":FIRST_SLOT,"output_slot_count":FOCUSED_SLOTS,
        "runtime":{"generation_profile":"test","runtime_profile":"solana-v1.4.25","runtime_admission":"candidate","runtime_revision":"893cc7647248a3536fb6e6d0b5e51c71446b862d","runtime_toolchain":"rustc1.46.0","runtime_target":"x86_64-unknown-linux-gnu","genesis_hash":jetstreamer_historical_protocol::MAINNET_GENESIS_HASH},"worker_executable_sha256":sha256_hex_string(&PINNED_WORKER_SHA256),"archive_sha256":"43".repeat(32),"bootstrap_archive_sha256":null,
        "bootstrap":{"slot":62639490,"bank_hash":"CoM8739uCp31r3ZJoLKPzag2aG9JcL9naR5TMaFAZAZ9","accounts_hash":"59bAQjc2c1VqNWqGoCacp3tnyNyie3EYx4bjttvJhgeT","last_blockhash":"7AFqLphUQsd92pntzKB25ad5iPiJae9yjt742HFgLuoV","capitalization":488586979125186779u64,"transaction_count":10186599902u64,"tick_height":4008927424u64,"slot_complete":true,"write_count":0,"next_write_version":31418315426u64},
        "terminal":{"slot":TERMINAL_ROOT,"bank_hash":"test","accounts_hash":"DsoBNgzFVZ7j5bF2CpKnt7HAC7fRrMMwdWW9FUafRe1p","last_blockhash":"test","capitalization":1,"transaction_count":1,"tick_height":1,"slot_complete":true,"write_count":0,"next_write_version":2},"emitted_raw_write_versions":{"start":1,"end":2}})).unwrap()
    }
    #[test]
    fn scope_never_relabels_the_tail_as_a_complete_source() {
        let m = manifest();
        validate_scope(&m, PINNED_WORKER_SHA256).unwrap();
        let mut bad = m.clone();
        bad.output_slot_count = CANONICAL_SLOTS;
        assert!(validate_scope(&bad, PINNED_WORKER_SHA256).is_err());
        bad = m.clone();
        bad.terminal.slot -= 71;
        assert!(validate_scope(&bad, PINNED_WORKER_SHA256).is_err());
        bad = m.clone();
        bad.terminal.accounts_hash = "wrong".into();
        assert!(validate_scope(&bad, PINNED_WORKER_SHA256).is_err());
        assert!(validate_scope(&m, [0x41; 32]).is_err());
        bad = m;
        bad.runtime.runtime_admission = SegmentRuntimeAdmission::Verified;
        assert!(validate_scope(&bad, PINNED_WORKER_SHA256).is_err());
    }
    #[test]
    fn output_cap_and_guard_fail_before_any_excess_write() {
        let mut calls = Vec::new();
        let mut guard = |n| {
            calls.push(n);
            Ok(())
        };
        let mut out = Limited {
            sink: Vec::new(),
            bytes: 0,
            maximum: 3,
            guard: &mut guard,
        };
        assert_eq!(out.write(b"ab").unwrap(), 2);
        assert!(out.write(b"cd").is_err());
        assert_eq!(out.sink, b"ab");
        drop(out);
        assert_eq!(calls, vec![2]);
        let mut guard = |_| Err(io::Error::other("floor"));
        let mut out = Limited {
            sink: Vec::new(),
            bytes: 0,
            maximum: 100,
            guard: &mut guard,
        };
        assert!(out.write(b"a").is_err());
        assert!(out.sink.is_empty());
    }

    #[test]
    fn bootstrap_consensus_tuple_and_runtime_are_not_inferred_from_epoch144_ready() {
        let original = manifest();
        for changed in [
            {
                let mut m = original.clone();
                m.bootstrap.bank_hash = "wrong".into();
                m
            },
            {
                let mut m = original.clone();
                m.bootstrap.last_blockhash = "wrong".into();
                m
            },
            {
                let mut m = original.clone();
                m.bootstrap.capitalization -= 1;
                m
            },
            {
                let mut m = original.clone();
                m.bootstrap.next_write_version -= 1;
                m
            },
            {
                let mut m = original.clone();
                m.runtime.runtime_profile = "solana-v1.5.5".into();
                m
            },
        ] {
            assert!(validate_scope(&changed, PINNED_WORKER_SHA256).is_err());
        }
    }

    fn readonly(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o400)).unwrap();
    }

    fn pinned_fixture(root: &Path) -> PinnedSource {
        let path = root.join("source.jet");
        let manifest_path = root.join("source.jet.segment.json");
        readonly(&path, b"fixture source identity");
        readonly(&manifest_path, b"fixture manifest identity");
        let (file, identity) = open_immutable(&path).unwrap();
        let (manifest_file, manifest_identity) = open_immutable(&manifest_path).unwrap();
        PinnedSource {
            path,
            file,
            identity,
            manifest: manifest(),
            manifest_path,
            manifest_file,
            manifest_identity,
            manifest_sha256: [1; 32],
        }
    }

    #[test]
    fn source_and_manifest_replacement_are_rejected_even_with_identical_bytes() {
        for replace_manifest in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let root = directory.path().canonicalize().unwrap();
            let source = pinned_fixture(&root);
            source.unchanged().unwrap();
            let target = if replace_manifest {
                &source.manifest_path
            } else {
                &source.path
            };
            let replacement = root.join("replacement");
            readonly(&replacement, &fs::read(target).unwrap());
            fs::rename(&replacement, target).unwrap();
            assert!(source.unchanged().is_err());
        }
    }

    #[test]
    fn source_reads_use_the_original_descriptor_and_rewind_it() {
        let directory = tempfile::tempdir().unwrap();
        let source = pinned_fixture(&directory.path().canonicalize().unwrap());
        let mut first = [0; 1];
        source
            .source_reader()
            .unwrap()
            .read_exact(&mut first)
            .unwrap();
        assert_eq!(first, [b'f']);
        let mut bytes = Vec::new();
        source
            .source_reader()
            .unwrap()
            .read_to_end(&mut bytes)
            .unwrap();
        assert_eq!(bytes, b"fixture source identity");
    }

    #[test]
    fn writable_hardlinked_and_symlink_inputs_are_rejected() {
        use std::os::unix::fs::symlink;
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let source = root.join("source");
        fs::write(&source, b"fixture").unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(open_immutable(&source).is_err());
        fs::set_permissions(&source, fs::Permissions::from_mode(0o400)).unwrap();
        open_immutable(&source).unwrap();
        let link = root.join("link");
        symlink(&source, &link).unwrap();
        assert!(open_immutable(&link).is_err());
        fs::remove_file(&link).unwrap();
        fs::hard_link(&source, &link).unwrap();
        assert!(open_immutable(&source).is_err());
    }

    #[test]
    fn private_destination_rejects_sidecars_including_dangling_symlinks() {
        use std::os::unix::fs::symlink;
        let directory = tempfile::tempdir().unwrap();
        let private = directory
            .path()
            .canonicalize()
            .unwrap()
            .join(".jetstreamer-private");
        fs::create_dir(&private).unwrap();
        let root = private.join("epoch145-prefix-extract-fixture");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        validate_destination(&root).unwrap();
        for name in [
            "epoch-145.jet.sha256",
            "epoch-145.sha256",
            "epoch-145.jet.segment.json",
        ] {
            let sidecar = root.join(name);
            symlink(root.join("absent"), &sidecar).unwrap();
            assert!(validate_destination(&root).is_err());
            fs::remove_file(sidecar).unwrap();
        }
        fs::set_permissions(&root, fs::Permissions::from_mode(0o750)).unwrap();
        assert!(validate_destination(&root).is_err());
        let public = private.join("horizon");
        fs::create_dir(&public).unwrap();
        fs::set_permissions(&public, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(validate_destination(&public).is_err());
    }
}
