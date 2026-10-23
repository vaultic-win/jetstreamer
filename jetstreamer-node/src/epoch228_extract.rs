//! Correctness core for private epoch228 prefix extraction.
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

pub const FIRST_SLOT: u64 = 98_496_000;
pub const CANONICAL_SLOTS: u64 = 432_000;
pub const FOCUSED_SLOTS: u64 = 432_279;
pub const TERMINAL_ROOT: u64 = 98_928_278;
/// Separately sealed closed228 capped worker; never the227 binary or stock route.
pub const PINNED_WORKER_SHA256: [u8; 32] = [
    0x1b, 0xfa, 0x8d, 0x51, 0xd4, 0x47, 0x29, 0xc7, 0x5d, 0xb7, 0xff, 0xe5, 0xd4, 0x66, 0xce, 0xc9,
    0xd9, 0x02, 0x21, 0x6d, 0x93, 0x62, 0xa6, 0xef, 0xb1, 0x29, 0xbf, 0x92, 0x7c, 0xa8, 0x56, 0x73,
];
const MAXIMUM_OUTPUT_BYTES: u64 = 160u64 << 30;

/// Immutable source evidence held across the complete transformation.
pub struct PinnedSource {
    path: PathBuf,
    file: File,
    identity: ArchiveFileIdentity,
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
    pub source_canonical_checkpoint_slot: u64,
    pub source_canonical_accounts_hash: &'static str,
    pub archive: PathBuf,
    pub archive_sha256: String,
    pub archive_bytes: u64,
    pub output_slot_start: u64,
    pub output_slot_count: u64,
    pub output_semantic_sha256: String,
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
/// the separately sealed228 package and the controller's hash-bound admission.
pub fn validate_scope(m: &HistoricalSegmentManifest, worker: [u8; 32]) -> Result<()> {
    ensure!(
        worker == PINNED_WORKER_SHA256
            && m.epoch == 228
            && m.output_slot_start == FIRST_SLOT
            && m.output_slot_count == FOCUSED_SLOTS
            && m.worker_executable_sha256 == worker
            && m.runtime.runtime_profile == "solana-v1.6.20"
            && m.runtime.runtime_revision == "77bdb45d4af61fc687161ec06cc0178ff79726d5"
            && m.runtime.runtime_admission == SegmentRuntimeAdmission::Candidate
            && m.runtime.genesis_hash == jetstreamer_historical_protocol::MAINNET_GENESIS_HASH
            && m.bootstrap.slot == 98_495_291
            && m.bootstrap.accounts_hash == "GfiRSgpC1qvH3uxVd9VAtYZ6qKM8fcdkyoyAkhF7izLq"
            && m.bootstrap.slot_complete
            && m.bootstrap.write_count == 0
            && m.terminal.slot == TERMINAL_ROOT
            && m.terminal.accounts_hash == "6Ec1ZPL4kEMFLU2qAsRfrbmYnEhm8pL77Xt1PoBhyGra"
            && m.terminal.slot_complete,
        "228 source does not bind the exact cold bootstrap, worker, full output and canonical tail root"
    );
    Ok(())
}
fn immutable(path: &Path) -> Result<fs::Metadata> {
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "228 input must be canonical"
    );
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_file() && m.nlink() == 1 && m.mode() & 0o222 == 0,
        "228 input must be frozen, singly linked and regular"
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
        immutable(archive)?;
        let mm = immutable(manifest)?;
        ensure!(mm.len() <= 1 << 20, "228 manifest oversized");
        let bytes = fs::read(manifest)?;
        ensure!(
            <[u8; 32]>::from(Sha256::digest(&bytes)) == manifest_sha256,
            "228 manifest SHA differs"
        );
        let file = open_regular_nofollow(archive)?;
        let identity = archive_file_identity(&file)?;
        let m = read_and_validate_segment_manifest_from(archive, manifest)?;
        validate_scope(&m, worker)?;
        ensure!(
            archive_file_identity(&file)? == identity
                && path_matches_archive_identity(archive, identity)?
                && <[u8; 32]>::from(Sha256::digest(fs::read(manifest)?)) == manifest_sha256,
            "228 source/manifest changed during qualification"
        );
        Ok(Self {
            path: archive.into(),
            file,
            identity,
            manifest: m,
            manifest_sha256,
        })
    }
    fn unchanged(&self) -> Result<()> {
        ensure!(
            archive_file_identity(&self.file)? == self.identity
                && path_matches_archive_identity(&self.path, self.identity)?,
            "228 pinned source changed"
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
            "228 output bound exceeds the reviewed160GiB ceiling"
        );
        let m = fs::symlink_metadata(root)?;
        ensure!(
            root.is_absolute()
                && root.canonicalize()? == root
                && m.is_dir()
                && m.uid() == unsafe { libc::geteuid() }
                && m.mode() & 0o077 == 0,
            "228 destination must be a canonical owner-private directory"
        );
        ensure!(
            root.parent() == Some(Path::new("/home/ubuntu/.jetstreamer-private"))
                && root
                    .file_name()
                    .and_then(|s| s.to_str())
                    .is_some_and(|n| n.starts_with("epoch228-prefix-extract-") && n.len() > 24),
            "228 destination namespace differs"
        );
        let target = root.join("epoch-228.jet");
        for name in [
            "epoch-228.jet.sha256",
            "epoch-228.sha256",
            "epoch-228.jet.segment.json",
        ] {
            ensure!(
                !root.join(name).try_exists()?,
                "228 candidate must have no publication/terminal sidecar"
            );
        }
        ensure!(
            self.path != target,
            "228 extraction cannot replace its source"
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
                _ => anyhow::bail!("228 source lost V2 provenance"),
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
            stats.source_epoch == 228
                && stats.source_slot_start == FIRST_SLOT
                && stats.source_slot_count == FOCUSED_SLOTS
                && stats.slots_reencoded == CANONICAL_SLOTS
                && stats.source_zero_parent_resume_artifacts == 0
                && stats.output_zero_parent_resume_artifacts == 0,
            "228 prefix export shape or strict chain differs"
        );
        let mut reader = ArchiveReader::open(BufReader::new(open_regular_nofollow(output_path)?))?;
        reader.verify_chain = true;
        reader.chain_mismatch_policy = ChainMismatchPolicy::Reject;
        ensure!(
            reader.header().epoch == 228
                && reader.header().slot_start == FIRST_SLOT
                && reader.header().slot_count == CANONICAL_SLOTS
                && reader.has_complete_slot_coverage()?,
            "228 output does not cover exactly one complete epoch"
        );
        ensure!(
            reader.provenance()? == Some(ArchiveProvenance::V2(expected)),
            "228 output provenance changed"
        );
        let mut semantic = SemanticDigest::new();
        ensure!(
            reader.read_slots(FIRST_SLOT, CANONICAL_SLOTS, &mut semantic)? == CANONICAL_SLOTS
                && semantic.finish()? == stats.output_semantic_sha256,
            "228 independent output semantic reread failed"
        );
        let mut output = open_regular_nofollow(output_path)?;
        let mut hash = Sha256::new();
        io::copy(&mut output, &mut hash)?;
        let bytes = output.metadata()?.len();
        ensure!(bytes <= maximum_bytes, "228 output exceeds admitted bound");
        self.unchanged()?;
        if let Some(t) = temporary {
            t.as_file()
                .set_permissions(fs::Permissions::from_mode(0o400))?;
            t.persist_noclobber(&target)
                .map_err(|e| anyhow::anyhow!("228 candidate publication conflict: {e}"))?;
            File::open(root)?.sync_all()?;
        } else {
            ensure!(
                original_output == Some(archive_file_identity(&output)?)
                    && path_matches_archive_identity(&target, original_output.unwrap())?,
                "228 existing candidate changed during receipt recovery"
            );
        }
        Ok(ExtractionEvidence {
            schema: "jetstreamer-private-epoch228-canonical-prefix-extraction-v1",
            epoch: 228,
            source_archive: self.path.clone(),
            source_archive_sha256: sha256_hex_string(&self.manifest.archive_sha256),
            source_manifest_sha256: sha256_hex_string(&self.manifest_sha256),
            worker_sha256: sha256_hex_string(&self.manifest.worker_executable_sha256),
            source_canonical_checkpoint_slot: TERMINAL_ROOT,
            source_canonical_accounts_hash: "6Ec1ZPL4kEMFLU2qAsRfrbmYnEhm8pL77Xt1PoBhyGra",
            archive: target,
            archive_sha256: format!("{:x}", hash.finalize()),
            archive_bytes: bytes,
            output_slot_start: FIRST_SLOT,
            output_slot_count: CANONICAL_SLOTS,
            output_semantic_sha256: sha256_hex_string(&stats.output_semantic_sha256),
            retained_verification_tail_slots: 279,
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
            .ok_or_else(|| io::Error::other("228 output bound overflow"))?;
        if next > self.maximum {
            return Err(io::Error::other("228 output bound crossed"));
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
    fn real_size_prefix_keeps_432000_slots_and_preserves_the_279_slot_source_tail() {
        use jetstreamer_horizon::archive::{
            ArchiveProvenanceV1, ArchiveProvenanceV2, ArchiveWriter, BootstrapStateKind,
            Compression, RuntimeAdmission, TransactionMetadataPolicy,
        };
        use solana_hash::Hash;
        let provenance = ArchiveProvenance::V2(ArchiveProvenanceV2 {
            base: ArchiveProvenanceV1 {
                generation_profile: "jetstreamer-node/historical-replay-v1".into(),
                runtime_profile: "solana-v1.6.20".into(),
                runtime_admission: RuntimeAdmission::Candidate,
                runtime_revision: "77bdb45d4af61fc687161ec06cc0178ff79726d5".into(),
                runtime_toolchain: "rustc1.51.0".into(),
                genesis_hash: Hash::new_from_array([5; 32]),
                bootstrap_state_kind: BootstrapStateKind::SnapshotArchive,
                bootstrap_slot: 98495291,
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
            228,
            FIRST_SLOT,
            FOCUSED_SLOTS,
            config.clone(),
            &provenance,
        )
        .unwrap();
        writer
            .preserve_initial_poh_anchor(FIRST_SLOT, Hash::new_from_array([7; 32]))
            .unwrap();
        for slot in FIRST_SLOT..FIRST_SLOT + FOCUSED_SLOTS {
            writer.write_skipped_slot(slot).unwrap();
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
        assert_eq!(
            ArchiveReader::open(std::io::Cursor::new(&source))
                .unwrap()
                .header()
                .slot_count,
            FOCUSED_SLOTS
        );
        assert_eq!(before, Sha256::digest(&source));
        assert_eq!(stats.source_slot_count - stats.slots_reencoded, 279);
    }
    fn manifest() -> HistoricalSegmentManifest {
        serde_json::from_value(serde_json::json!({"schema_version":1,"epoch":228,"output_slot_start":FIRST_SLOT,"output_slot_count":FOCUSED_SLOTS,
        "runtime":{"generation_profile":"test","runtime_profile":"solana-v1.6.20","runtime_admission":"candidate","runtime_revision":"77bdb45d4af61fc687161ec06cc0178ff79726d5","runtime_toolchain":"rustc1.51.0","runtime_target":"x86_64-unknown-linux-gnu","genesis_hash":jetstreamer_historical_protocol::MAINNET_GENESIS_HASH},"worker_executable_sha256":sha256_hex_string(&PINNED_WORKER_SHA256),"archive_sha256":"43".repeat(32),"bootstrap_archive_sha256":null,
        "bootstrap":{"slot":98495291,"bank_hash":"test","accounts_hash":"GfiRSgpC1qvH3uxVd9VAtYZ6qKM8fcdkyoyAkhF7izLq","last_blockhash":"test","capitalization":1,"transaction_count":1,"tick_height":1,"slot_complete":true,"write_count":0,"next_write_version":1},
        "terminal":{"slot":TERMINAL_ROOT,"bank_hash":"test","accounts_hash":"6Ec1ZPL4kEMFLU2qAsRfrbmYnEhm8pL77Xt1PoBhyGra","last_blockhash":"test","capitalization":1,"transaction_count":1,"tick_height":1,"slot_complete":true,"write_count":0,"next_write_version":2},"emitted_raw_write_versions":{"start":1,"end":2}})).unwrap()
    }
    #[test]
    fn scope_never_relabels_the_tail_as_a_complete_source() {
        let m = manifest();
        validate_scope(&m, PINNED_WORKER_SHA256).unwrap();
        let mut bad = m.clone();
        bad.output_slot_count = CANONICAL_SLOTS;
        assert!(validate_scope(&bad, PINNED_WORKER_SHA256).is_err());
        bad = m.clone();
        bad.terminal.slot -= 279;
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
}
