//! Correctness core for private epoch225 prefix extraction.
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
        HistoricalSegmentManifest, read_and_validate_segment_manifest_from, sha256_hex_string,
    },
};
use anyhow::{Result, ensure};
use jetstreamer_horizon::archive::{
    ArchiveProvenance, ArchiveReader, ArchiveWriterConfig, ChainMismatchPolicy, SemanticDigest,
    reencode_archive_prefix,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{self, BufReader, Write},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};

pub const FIRST_SLOT: u64 = 97_200_000;
pub const CANONICAL_SLOTS: u64 = 432_000;
pub const FOCUSED_SLOTS: u64 = 863_465;
pub const TERMINAL_ROOT: u64 = 98_063_464;
/// Exact shrink-budget worker from the retained225 producer launch.
pub const PINNED_WORKER_SHA256: [u8; 32] = [
    0x2d, 0xcc, 0x9b, 0x84, 0xa6, 0xce, 0x27, 0xed, 0xba, 0x3d, 0x3b, 0x05, 0x3c, 0x6e, 0x61, 0x70,
    0xf6, 0x6a, 0x23, 0x37, 0xf1, 0x2a, 0x5a, 0xae, 0x54, 0x90, 0x0c, 0x3a, 0xd9, 0xe2, 0xee, 0xdd,
];
pub const SOURCE_ARCHIVE: &str = "/home/ubuntu/.jetstreamer-private/qualification-225-v1625-natural-root-shrink-budget-2f856bd-v1/output/epoch-225.jet";
pub const SOURCE_ARCHIVE_BYTES: u64 = 265_610_094_371;
pub const SOURCE_MANIFEST_SHA256: &str =
    "53a69d801e70866b0bc048e1b3a75d9c16c1fb93995503157fc206742f3cdcf6";
const SOURCE_MANIFEST: &[u8] = include_bytes!("epoch225_extract/source-manifest.json");
const MAXIMUM_OUTPUT_BYTES: u64 = 320u64 << 30;

/// Immutable source evidence held across the complete transformation.
pub struct PinnedSource {
    path: PathBuf,
    file: File,
    identity: ArchiveFileIdentity,
    manifest_path: PathBuf,
    manifest_identity: ArchiveFileIdentity,
    manifest: HistoricalSegmentManifest,
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
    pub source_terminal_checkpoint_slot: u64,
    pub source_terminal_accounts_hash: &'static str,
    pub archive: PathBuf,
    pub archive_sha256: String,
    pub archive_bytes: u64,
    pub output_slot_start: u64,
    pub output_slot_count: u64,
    pub output_semantic_sha256: String,
    pub retained_verification_tail_slots: u64,
    pub source_must_be_retained: bool,
    pub independent_output_reread_passed: bool,
    pub source_runtime_admission: &'static str,
    pub epoch226_tail_is_private: bool,
    pub full_verification_passed: bool,
    pub current_plugin_verification_passed: bool,
    pub runtime_promotion_authorized: bool,
    pub canonical_sidecar_authorized: bool,
    pub publication_authorized: bool,
    pub retirement_authorized: bool,
    pub r2_mutations: bool,
}

fn pinned_manifest() -> Result<HistoricalSegmentManifest> {
    ensure!(
        sha256_hex_string(&Sha256::digest(SOURCE_MANIFEST).into()) == SOURCE_MANIFEST_SHA256,
        "225 reviewed manifest source digest differs"
    );
    Ok(serde_json::from_slice(SOURCE_MANIFEST)?)
}
/// Binds all fields of the exact completed private source; the candidate runtime
/// and retained226 tail confer no canonical artifact or runtime qualification.
pub fn validate_scope(m: &HistoricalSegmentManifest, worker: [u8; 32]) -> Result<()> {
    ensure!(
        worker == PINNED_WORKER_SHA256 && *m == pinned_manifest()?,
        "225 source differs from its exact archive SHA, candidate runtime, worker, checkpoints or complete retained226 tail"
    );
    Ok(())
}
fn source_scope(
    archive: &Path,
    manifest: &Path,
    manifest_sha256: [u8; 32],
    worker: [u8; 32],
) -> Result<()> {
    ensure!(
        archive == Path::new(SOURCE_ARCHIVE)
            && manifest == PathBuf::from(format!("{SOURCE_ARCHIVE}.segment.json"))
            && sha256_hex_string(&manifest_sha256) == SOURCE_MANIFEST_SHA256
            && worker == PINNED_WORKER_SHA256,
        "225 extraction accepts only its original completed source, manifest and worker"
    );
    Ok(())
}
fn immutable(path: &Path) -> Result<fs::Metadata> {
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "225 input must be canonical"
    );
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_file() && m.nlink() == 1 && m.mode() & 0o222 == 0,
        "225 input must be frozen, singly linked and regular"
    );
    Ok(m)
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
        source_scope(archive, manifest, manifest_sha256, worker)?;
        let am = immutable(archive)?;
        let mm = immutable(manifest)?;
        ensure!(
            am.uid() == 1000
                && am.len() == SOURCE_ARCHIVE_BYTES
                && mm.uid() == 1000
                && mm.len() <= 1 << 20,
            "225 original source custody, byte length or manifest bound differs"
        );
        let bytes = fs::read(manifest)?;
        ensure!(
            <[u8; 32]>::from(Sha256::digest(&bytes)) == manifest_sha256,
            "225 manifest SHA differs"
        );
        let file = open_regular_nofollow(archive)?;
        let identity = archive_file_identity(&file)?;
        let manifest_identity = archive_file_identity(&open_regular_nofollow(manifest)?)?;
        let m = read_and_validate_segment_manifest_from(archive, manifest)?;
        validate_scope(&m, worker)?;
        ensure!(
            archive_file_identity(&file)? == identity
                && path_matches_archive_identity(archive, identity)?
                && <[u8; 32]>::from(Sha256::digest(fs::read(manifest)?)) == manifest_sha256,
            "225 source/manifest changed during qualification"
        );
        let source = Self {
            path: archive.into(),
            file,
            identity,
            manifest_path: manifest.into(),
            manifest_identity,
            manifest: m,
            manifest_sha256,
        };
        source.unchanged()?;
        Ok(source)
    }
    fn unchanged(&self) -> Result<()> {
        let am = immutable(&self.path)?;
        let mm = immutable(&self.manifest_path)?;
        ensure!(
            am.uid() == 1000
                && mm.uid() == 1000
                && archive_file_identity(&self.file)? == self.identity
                && path_matches_archive_identity(&self.path, self.identity)?
                && mm.len() <= 1 << 20
                && path_matches_archive_identity(&self.manifest_path, self.manifest_identity)?
                && <[u8; 32]>::from(Sha256::digest(fs::read(&self.manifest_path)?))
                    == self.manifest_sha256,
            "225 pinned source or retained manifest changed"
        );
        Ok(())
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
            "225 output bound exceeds the320GiB source ceiling"
        );
        guard(0)?;
        let m = fs::symlink_metadata(root)?;
        ensure!(
            root.is_absolute()
                && root.canonicalize()? == root
                && m.is_dir()
                && m.uid() == unsafe { libc::geteuid() }
                && m.mode() & 0o077 == 0,
            "225 destination must be a canonical owner-private directory"
        );
        ensure!(
            root.parent() == Some(Path::new("/home/ubuntu/.jetstreamer-private"))
                && root
                    .file_name()
                    .and_then(|s| s.to_str())
                    .is_some_and(|n| n.starts_with("epoch225-prefix-extract-") && n.len() > 24),
            "225 destination namespace differs"
        );
        let target = root.join("epoch-225.jet");
        for name in [
            "epoch-225.jet.sha256",
            "epoch-225.sha256",
            "epoch-225.jet.segment.json",
        ] {
            ensure!(
                !root.join(name).try_exists()?,
                "225 candidate must have no publication/terminal sidecar"
            );
        }
        ensure!(
            self.path != target,
            "225 extraction cannot replace its source"
        );
        self.unchanged()?;
        let original_output = if target.try_exists()? {
            immutable(&target)?;
            Some(archive_file_identity(&open_regular_nofollow(&target)?)?)
        } else {
            None
        };
        let mut expected =
            match ArchiveReader::open(BufReader::new(open_regular_nofollow(&self.path)?))?
                .provenance()?
            {
                Some(ArchiveProvenance::V2(p)) => p,
                _ => anyhow::bail!("225 source lost V2 provenance"),
            };
        expected.base.requested_slot_count = CANONICAL_SLOTS;
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
                BufReader::new(open_regular_nofollow(&self.path)?),
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
                BufReader::new(open_regular_nofollow(&self.path)?),
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
        ensure!(
            stats.source_epoch == 225
                && stats.source_slot_start == FIRST_SLOT
                && stats.source_slot_count == FOCUSED_SLOTS
                && stats.slots_reencoded == CANONICAL_SLOTS
                && stats.source_zero_parent_resume_artifacts == 0
                && stats.output_zero_parent_resume_artifacts == 0,
            "225 prefix export shape or strict chain differs"
        );
        let output_identity = archive_file_identity(&open_regular_nofollow(output_path)?)?;
        let mut reader = ArchiveReader::open(BufReader::new(open_regular_nofollow(output_path)?))?;
        reader.verify_chain = true;
        reader.chain_mismatch_policy = ChainMismatchPolicy::Reject;
        ensure!(
            reader.header().epoch == 225
                && reader.header().slot_start == FIRST_SLOT
                && reader.header().slot_count == CANONICAL_SLOTS
                && reader.has_complete_slot_coverage()?,
            "225 output does not cover exactly one complete epoch"
        );
        ensure!(
            reader.provenance()? == Some(ArchiveProvenance::V2(expected)),
            "225 output provenance changed"
        );
        let mut semantic = SemanticDigest::new();
        ensure!(
            reader.read_slots(FIRST_SLOT, CANONICAL_SLOTS, &mut semantic)? == CANONICAL_SLOTS
                && semantic.finish()? == stats.output_semantic_sha256,
            "225 independent output semantic reread failed"
        );
        let mut output = open_regular_nofollow(output_path)?;
        ensure!(
            archive_file_identity(&output)? == output_identity,
            "225 candidate changed after independent semantic reread"
        );
        let mut hash = Sha256::new();
        io::copy(&mut output, &mut hash)?;
        let bytes = output.metadata()?.len();
        ensure!(bytes <= maximum_bytes, "225 output exceeds admitted bound");
        ensure!(
            archive_file_identity(&output)? == output_identity
                && path_matches_archive_identity(output_path, output_identity)?,
            "225 candidate changed during independent hash"
        );
        self.unchanged()?;
        guard(bytes)?;
        if let Some(t) = temporary {
            t.as_file()
                .set_permissions(fs::Permissions::from_mode(0o400))?;
            t.persist_noclobber(&target)
                .map_err(|e| anyhow::anyhow!("225 candidate publication conflict: {e}"))?;
            File::open(root)?.sync_all()?;
        } else {
            ensure!(
                original_output == Some(archive_file_identity(&output)?)
                    && path_matches_archive_identity(&target, original_output.unwrap())?,
                "225 existing candidate changed during receipt recovery"
            );
        }
        self.unchanged()?;
        Ok(ExtractionEvidence {
            schema: "jetstreamer-private-epoch225-canonical-prefix-extraction-v1",
            epoch: 225,
            source_archive: self.path.clone(),
            source_archive_sha256: sha256_hex_string(&self.manifest.archive_sha256),
            source_manifest_sha256: sha256_hex_string(&self.manifest_sha256),
            worker_sha256: sha256_hex_string(&self.manifest.worker_executable_sha256),
            source_terminal_checkpoint_slot: TERMINAL_ROOT,
            source_terminal_accounts_hash: "4TaJaC5esCEWtHp5Fay2aMS9XjA1o9bwQthcvBeSyYbR",
            archive: target,
            archive_sha256: format!("{:x}", hash.finalize()),
            archive_bytes: bytes,
            output_slot_start: FIRST_SLOT,
            output_slot_count: CANONICAL_SLOTS,
            output_semantic_sha256: sha256_hex_string(&stats.output_semantic_sha256),
            retained_verification_tail_slots: 431_465,
            source_must_be_retained: true,
            independent_output_reread_passed: true,
            source_runtime_admission: "candidate",
            epoch226_tail_is_private: true,
            full_verification_passed: false,
            current_plugin_verification_passed: false,
            runtime_promotion_authorized: false,
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
            .ok_or_else(|| io::Error::other("225 output bound overflow"))?;
        if next > self.maximum {
            return Err(io::Error::other("225 output bound crossed"));
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
    use crate::segment_manifest::SegmentRuntimeAdmission;
    #[test]
    fn e225_extract_real_span_keeps_432000_slots_and_retains_private226_tail() {
        use jetstreamer_horizon::archive::{
            ArchiveProvenanceV1, ArchiveProvenanceV2, ArchiveWriter, BootstrapStateKind,
            Compression, RuntimeAdmission, SlotVisitor, TransactionMetadataPolicy,
        };
        use jetstreamer_horizon::{
            account_updates::AccountUpdateView, block_metas::BlockMeta, entries::EntryRecord,
        };
        use solana_address::Address;
        use solana_hash::Hash;
        let provenance = ArchiveProvenance::V2(ArchiveProvenanceV2 {
            base: ArchiveProvenanceV1 {
                generation_profile: "jetstreamer-node/historical-replay-v1".into(),
                runtime_profile: "solana-v1.6.25".into(),
                runtime_admission: RuntimeAdmission::Candidate,
                runtime_revision: "7de8a55b54d3e11058b82f9483bb405d143b455c".into(),
                runtime_toolchain: "rustc1.51.0".into(),
                genesis_hash: Hash::new_from_array([5; 32]),
                bootstrap_state_kind: BootstrapStateKind::SnapshotArchive,
                bootstrap_slot: 97199617,
                bootstrap_state_hash: Hash::new_from_array([9; 32]),
                requested_slot_start: FIRST_SLOT,
                requested_slot_count: FOCUSED_SLOTS,
                transaction_metadata: TransactionMetadataPolicy::runtime_reconstructed(),
            },
            worker_executable_sha256: PINNED_WORKER_SHA256,
        });
        let config = ArchiveWriterConfig {
            compression: Compression::None,
            ..Default::default()
        };
        let mut writer = ArchiveWriter::new_with_provenance(
            Vec::new(),
            225,
            FIRST_SLOT,
            FOCUSED_SLOTS,
            config.clone(),
            &provenance,
        )
        .unwrap();
        writer
            .preserve_initial_poh_anchor(FIRST_SLOT, Hash::new_from_array([7; 32]))
            .unwrap();
        let boundary_slots = [
            FIRST_SLOT,
            FIRST_SLOT + CANONICAL_SLOTS - 1,
            FIRST_SLOT + CANONICAL_SLOTS,
        ];
        let mut previous_hash = Hash::new_from_array([7; 32]);
        let mut previous_slot = FIRST_SLOT - 1;
        for slot in FIRST_SLOT..FIRST_SLOT + FOCUSED_SLOTS {
            let Some(marker) = boundary_slots.iter().position(|n| *n == slot) else {
                writer.write_skipped_slot(slot).unwrap();
                continue;
            };
            writer.begin_slot(slot).unwrap();
            writer
                .write_orphan_update(&AccountUpdateView {
                    pubkey: Address::new_from_array([7; 32]),
                    owner: Address::new_from_array([8; 32]),
                    lamports: slot,
                    executable: false,
                    rent_epoch: u64::MAX,
                    write_version: 9_007_199_254_740_993 + marker as u64,
                    data: if marker == 2 {
                        b"private226 tail"
                    } else {
                        b"retained225"
                    },
                })
                .unwrap();
            let mut block = BlockMeta::new_boxed();
            block.slot = slot;
            block.parent_slot = previous_slot;
            block.parent_blockhash = previous_hash;
            block.blockhash = Hash::new_from_array([10 + marker as u8; 32]);
            block.entry_count = 1;
            writer
                .end_slot(
                    &block,
                    &[EntryRecord {
                        num_hashes: 1,
                        tx_count: 0,
                    }],
                )
                .unwrap();
            previous_slot = slot;
            previous_hash = block.blockhash;
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
        let mut expected = provenance.clone();
        let ArchiveProvenance::V2(p) = &mut expected else {
            unreachable!()
        };
        p.base.requested_slot_count = CANONICAL_SLOTS;
        let mut reader = ArchiveReader::open(std::io::Cursor::new(&output)).unwrap();
        reader.verify_chain = true;
        reader.chain_mismatch_policy = ChainMismatchPolicy::Reject;
        assert_eq!(reader.header().epoch, 225);
        assert_eq!(reader.header().slot_start, FIRST_SLOT);
        assert_eq!(reader.header().slot_count, CANONICAL_SLOTS);
        assert_eq!(reader.provenance().unwrap(), Some(expected));
        assert!(reader.has_complete_slot_coverage().unwrap());
        let mut digest = SemanticDigest::new();
        assert_eq!(
            reader
                .read_slots(FIRST_SLOT, CANONICAL_SLOTS, &mut digest)
                .unwrap(),
            CANONICAL_SLOTS
        );
        assert_eq!(digest.finish().unwrap(), stats.output_semantic_sha256);
        #[derive(Default)]
        struct Markers(Vec<(u64, u64, Vec<u8>)>);
        impl SlotVisitor for Markers {
            fn on_pre_account_update(&mut self, slot: u64, value: &AccountUpdateView<'_>) {
                self.0
                    .push((slot, value.write_version, value.data.to_vec()));
            }
        }
        let mut markers = Markers::default();
        reader
            .read_slots(FIRST_SLOT, CANONICAL_SLOTS, &mut markers)
            .unwrap();
        assert_eq!(
            markers.0,
            vec![
                (FIRST_SLOT, 9_007_199_254_740_993, b"retained225".to_vec()),
                (
                    FIRST_SLOT + CANONICAL_SLOTS - 1,
                    9_007_199_254_740_994,
                    b"retained225".to_vec()
                ),
            ]
        );
        let mut tail = Markers::default();
        ArchiveReader::open(std::io::Cursor::new(&source))
            .unwrap()
            .read_slots(FIRST_SLOT + CANONICAL_SLOTS, 1, &mut tail)
            .unwrap();
        assert_eq!(
            tail.0,
            vec![(
                FIRST_SLOT + CANONICAL_SLOTS,
                9_007_199_254_740_995,
                b"private226 tail".to_vec()
            )]
        );
        assert_eq!(
            ArchiveReader::open(std::io::Cursor::new(&source))
                .unwrap()
                .header()
                .slot_count,
            FOCUSED_SLOTS
        );
        assert_eq!(before, Sha256::digest(&source));
        assert_eq!(stats.source_slot_count - stats.slots_reencoded, 431_465);
        // The retained source still contains226's private tail, while output
        // keeps candidate admission and cannot represent a complete226 epoch.
        assert_eq!(FIRST_SLOT + CANONICAL_SLOTS - 1, 97_631_999);
        assert_eq!(FIRST_SLOT + FOCUSED_SLOTS - 1, TERMINAL_ROOT);
        let truncated = &output[..output.len() / 2];
        let reread = ArchiveReader::open(std::io::Cursor::new(truncated)).and_then(|mut r| {
            r.verify_chain = true;
            r.chain_mismatch_policy = ChainMismatchPolicy::Reject;
            r.read_slots(FIRST_SLOT, CANONICAL_SLOTS, &mut SemanticDigest::new())
        });
        assert!(
            reread.is_err(),
            "truncated candidate cannot pass independent reread"
        );
    }
    fn manifest() -> HistoricalSegmentManifest {
        pinned_manifest().unwrap()
    }
    #[test]
    fn e225_extract_scope_rejects_altered_source_runtime_checkpoint_and_tail() {
        let m = manifest();
        validate_scope(&m, PINNED_WORKER_SHA256).unwrap();
        let mut bad = m.clone();
        bad.output_slot_count = CANONICAL_SLOTS;
        assert!(validate_scope(&bad, PINNED_WORKER_SHA256).is_err());
        bad = m.clone();
        bad.terminal.slot -= 431_465;
        assert!(validate_scope(&bad, PINNED_WORKER_SHA256).is_err());
        bad = m.clone();
        bad.terminal.accounts_hash = "wrong".into();
        assert!(validate_scope(&bad, PINNED_WORKER_SHA256).is_err());
        assert!(validate_scope(&m, [0x41; 32]).is_err());
        bad = m;
        bad.runtime.runtime_admission = SegmentRuntimeAdmission::Verified;
        assert!(validate_scope(&bad, PINNED_WORKER_SHA256).is_err());
        let original = serde_json::to_value(manifest()).unwrap();
        for (pointer, value) in [
            ("/archive_sha256", serde_json::json!("11".repeat(32))),
            ("/runtime/runtime_revision", serde_json::json!("foreign")),
            ("/bootstrap/bank_hash", serde_json::json!("foreign")),
            ("/terminal/bank_hash", serde_json::json!("foreign")),
            ("/terminal/slot_complete", serde_json::json!(false)),
            (
                "/terminal/next_write_version",
                serde_json::json!(111241712668u64),
            ),
            ("/emitted_raw_write_versions/start", serde_json::json!(0)),
            (
                "/worker_executable_sha256",
                serde_json::json!("22".repeat(32)),
            ),
        ] {
            let mut changed = original.clone();
            *changed.pointer_mut(pointer).unwrap() = value;
            let changed: HistoricalSegmentManifest = serde_json::from_value(changed).unwrap();
            assert!(
                validate_scope(&changed, PINNED_WORKER_SHA256).is_err(),
                "{pointer}"
            );
        }
    }
    #[test]
    fn e225_extract_source_scope_rejects_foreign_manifest_worker_and_archive_paths() {
        let digest: [u8; 32] = Sha256::digest(SOURCE_MANIFEST).into();
        let manifest = PathBuf::from(format!("{SOURCE_ARCHIVE}.segment.json"));
        source_scope(
            Path::new(SOURCE_ARCHIVE),
            &manifest,
            digest,
            PINNED_WORKER_SHA256,
        )
        .unwrap();
        for (archive, manifest, digest, worker) in [
            (
                PathBuf::from("/private/epoch-225.jet"),
                manifest.clone(),
                digest,
                PINNED_WORKER_SHA256,
            ),
            (
                SOURCE_ARCHIVE.into(),
                "/private/manifest.json".into(),
                digest,
                PINNED_WORKER_SHA256,
            ),
            (
                SOURCE_ARCHIVE.into(),
                manifest.clone(),
                [0; 32],
                PINNED_WORKER_SHA256,
            ),
            (SOURCE_ARCHIVE.into(), manifest, digest, [0; 32]),
        ] {
            assert!(source_scope(&archive, &manifest, digest, worker).is_err());
        }
    }
    #[test]
    fn e225_extract_requires_frozen_singly_linked_regular_evidence() {
        use std::os::unix::fs::symlink;
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source");
        fs::write(&source, b"retained source").unwrap();
        assert!(immutable(&source).is_err());
        fs::set_permissions(&source, fs::Permissions::from_mode(0o400)).unwrap();
        immutable(&source).unwrap();
        let alias = directory.path().join("alias");
        symlink(&source, &alias).unwrap();
        assert!(immutable(&alias).is_err());
        fs::remove_file(&alias).unwrap();
        fs::hard_link(&source, &alias).unwrap();
        assert!(immutable(&source).is_err());
        assert!(immutable(&alias).is_err());
    }
    #[test]
    fn e225_extract_output_cap_and_guard_reject_before_excess_write() {
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
}
