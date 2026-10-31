//! Derive narrowly scoped recovery evidence from a private Horizon archive.
//!
//! This command decodes only independent edge buckets. An explicit optional
//! whole-source hash binds the complete bytes without claiming a full decode. It never
//! mutates the archive, creates a canonical checksum sidecar, or talks to R2.
//! A recovered segment manifest still has to pass the complete archive reread
//! performed by `jetstreamer-segment-recover`.

use {
    jetstreamer_horizon::{
        account_updates::AccountUpdateView,
        archive::{
            ArchiveProvenance, ArchiveReader, BlockNotification, Consumption, EntryRecord,
            EpochMeta, SlotKind, SlotVisitor,
        },
        transactions::Transaction,
    },
    jetstreamer_node::archive_checksum::{
        ArchiveFileIdentity, archive_file_identity, measure_open_archive, open_regular_nofollow,
        path_matches_archive_identity,
    },
    serde::Serialize,
    solana_hash::Hash,
    std::{
        collections::BTreeMap,
        env,
        fs::{self, File, OpenOptions},
        io::{BufReader, Write},
        os::unix::fs::{MetadataExt as _, OpenOptionsExt as _},
        path::{Path, PathBuf},
        process,
    },
};

const SCHEMA: &str = "horizon-private-archive-edge-evidence-v1";

const DECODER_STACK_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
struct Arguments {
    archive: PathBuf,
    output: PathBuf,
    hash_source: bool,
    inspect_slot: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TerminalSlot {
    slot: u64,
    kind: SlotKind,
    blockhash: Option<Hash>,
    pre_write_count: u64,
    transaction_write_count: u64,
    post_write_count: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WritePhase {
    Pre,
    Transaction,
    Post,
}

#[derive(Default)]
struct EdgeVisitor {
    current_slot: Option<u64>,
    current_kind: Option<SlotKind>,
    current_write_count: u64,
    current_pre_write_count: u64,
    current_transaction_write_count: u64,
    current_post_write_count: u64,
    first_write: Option<u64>,
    last_write: Option<u64>,
    terminal: Option<TerminalSlot>,
    error: Option<String>,
}

impl EdgeVisitor {
    fn accept_write(&mut self, slot: u64, write_version: u64, phase: WritePhase) {
        if self.error.is_some() {
            return;
        }
        if self.current_slot != Some(slot) {
            self.error = Some(format!(
                "account update for slot {slot} arrived while decoding slot {:?}",
                self.current_slot
            ));
            return;
        }
        self.current_write_count = match self.current_write_count.checked_add(1) {
            Some(count) => count,
            None => {
                self.error = Some(format!("account-update count overflows at slot {slot}"));
                return;
            }
        };
        let phase_count = match phase {
            WritePhase::Pre => &mut self.current_pre_write_count,
            WritePhase::Transaction => &mut self.current_transaction_write_count,
            WritePhase::Post => &mut self.current_post_write_count,
        };
        *phase_count = match phase_count.checked_add(1) {
            Some(count) => count,
            None => {
                self.error = Some(format!(
                    "{phase:?} account-update count overflows at slot {slot}"
                ));
                return;
            }
        };
        self.first_write = Some(
            self.first_write
                .map_or(write_version, |current| current.min(write_version)),
        );
        self.last_write = Some(
            self.last_write
                .map_or(write_version, |current| current.max(write_version)),
        );
    }

    fn finish(self) -> Result<Self, String> {
        if let Some(error) = &self.error {
            return Err(error.clone());
        }
        Ok(self)
    }
}

impl SlotVisitor for EdgeVisitor {
    fn on_slot_start(&mut self, slot: u64, kind: SlotKind) {
        if self.current_slot.is_some() && self.terminal.is_none() {
            self.error = Some("slot ended without a block notification".to_string());
            return;
        }
        self.current_slot = Some(slot);
        self.current_kind = Some(kind);
        self.current_write_count = 0;
        self.current_pre_write_count = 0;
        self.current_transaction_write_count = 0;
        self.current_post_write_count = 0;
        self.terminal = None;
    }

    fn on_epoch(&mut self, meta: &EpochMeta) {
        let slot = self.current_slot.unwrap_or(0);
        for (update, _) in meta.updates.iter() {
            self.accept_write(slot, update.write_version, WritePhase::Pre);
        }
    }

    fn on_pre_account_update(&mut self, slot: u64, update: &AccountUpdateView<'_>) {
        self.accept_write(slot, update.write_version, WritePhase::Pre);
    }

    fn on_transaction(&mut self, slot: u64, _tx_index: u32, transaction: &Transaction) {
        for (update, _) in transaction.iter_account_updates() {
            self.accept_write(slot, update.write_version, WritePhase::Transaction);
        }
    }

    fn on_post_account_update(&mut self, slot: u64, update: &AccountUpdateView<'_>) {
        self.accept_write(slot, update.write_version, WritePhase::Post);
    }

    fn on_block(&mut self, notification: &BlockNotification, _entries: &[EntryRecord]) {
        let slot = notification.slot();
        if self.current_slot != Some(slot) {
            self.error = Some(format!(
                "block notification for slot {slot} arrived while decoding slot {:?}",
                self.current_slot
            ));
            return;
        }
        let kind = match self.current_kind {
            Some(kind) => kind,
            None => {
                self.error = Some(format!("slot {slot} has no slot-kind callback"));
                return;
            }
        };
        let blockhash = match notification {
            BlockNotification::Block(meta) => Some(meta.blockhash),
            BlockNotification::Skipped(_) => None,
        };
        if (kind == SlotKind::Block) != blockhash.is_some() {
            self.error = Some(format!(
                "slot {slot} kind does not match its block notification"
            ));
            return;
        }
        self.terminal = Some(TerminalSlot {
            slot,
            kind,
            blockhash,
            pre_write_count: self.current_pre_write_count,
            transaction_write_count: self.current_transaction_write_count,
            post_write_count: self.current_post_write_count,
        });
    }

    fn consumption(&self) -> Consumption {
        Consumption::all()
            .without_account_update_data()
            .without_block_account_update_arenas()
    }
}

#[derive(Debug, Serialize)]
struct EpochEvidence {
    archive: PathBuf,
    archive_bytes: u64,
    source_identity: SourceIdentity,
    #[serde(skip_serializing_if = "Option::is_none")]
    whole_source_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    inspected_slot: Option<InspectedSlot>,
    runtime_profile: String,
    parent_recorded_worker_executable_sha256: String,
    output_start_slot: u64,
    observed_first_write_version: u64,
    terminal_slot: u64,
    terminal_kind: &'static str,
    observed_terminal_next_write_version: u64,
    observed_terminal_write_counts: TerminalWriteCounts,
    derived_terminal_checkpoint_write_count: u64,
    checkpoint_write_derivation: &'static str,
    observed_terminal_blockhash: String,
}

#[derive(Debug, Serialize)]
struct SourceIdentity {
    device: u64,
    inode: u64,
    bytes: u64,
    uid: u32,
    gid: u32,
    mode: String,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

impl From<&fs::Metadata> for SourceIdentity {
    fn from(m: &fs::Metadata) -> Self {
        Self {
            device: m.dev(),
            inode: m.ino(),
            bytes: m.len(),
            uid: m.uid(),
            gid: m.gid(),
            mode: format!("{:04o}", m.mode() & 0o7777),
            modified_seconds: m.mtime(),
            modified_nanoseconds: m.mtime_nsec(),
            changed_seconds: m.ctime(),
            changed_nanoseconds: m.ctime_nsec(),
        }
    }
}

fn recorded_worker_digest(digest: &[u8; 32]) -> Result<String, String> {
    if *digest == [0; 32] {
        return Err("single-runtime V2 worker digest must not be zero".to_string());
    }
    Ok(jetstreamer_node::segment_manifest::sha256_hex_string(
        digest,
    ))
}

fn terminal_checkpoint_write_count(
    runtime_profile: &str,
    post_write_count: u64,
) -> Result<(u64, &'static str), String> {
    let derivation = match runtime_profile {
        "solana-v1.4.25" => {
            "solana-v1.4.25 freeze checkpoint writes are terminal post-phase writes minus the final freeze-root drain write"
        }
        "solana-v1.6.16" => {
            "solana-v1.6.16 freeze checkpoint writes are terminal post-phase writes minus the final freeze-root drain write"
        }
        _ => {
            return Err(format!(
                "checkpoint write derivation is not qualified for runtime {runtime_profile}"
            ));
        }
    };
    let write_count = post_write_count.checked_sub(1).ok_or_else(|| {
        format!("{runtime_profile} terminal slot has no post-phase final-freeze write to exclude")
    })?;
    Ok((write_count, derivation))
}

#[derive(Debug, Serialize)]
struct TerminalWriteCounts {
    pre: u64,
    transaction: u64,
    post: u64,
}

#[derive(Debug, Serialize)]
struct InspectedSlot {
    slot: u64,
    kind: &'static str,
    observed_blockhash: Option<String>,
    observed_first_write_version: Option<u64>,
    observed_next_write_version: Option<u64>,
    observed_write_counts: TerminalWriteCounts,
    checkpoint_drained_write_interpretation_qualified: bool,
    complete_prefix_verified: bool,
    native_consensus_comparison_passed: bool,
}

#[derive(Debug, Serialize)]
struct Evidence {
    schema: &'static str,
    evidence_scope: &'static str,
    #[serde(flatten)]
    epochs: BTreeMap<String, EpochEvidence>,
    archive_mutations: bool,
    sidecar_created: bool,
    r2_mutations: bool,
}

fn usage(program: &str) -> String {
    format!(
        "usage: {program} <archive.jet> --output <private-evidence.json> [--hash-source [--inspect-slot SLOT]]"
    )
}

fn parse_arguments(arguments: impl IntoIterator<Item = String>) -> Result<Arguments, String> {
    let mut archive = None;
    let mut output = None;
    let mut hash_source = false;
    let mut inspect_slot = None;
    let mut arguments = arguments.into_iter();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--hash-source" if !hash_source => hash_source = true,
            "--inspect-slot" if inspect_slot.is_none() => {
                let text = arguments
                    .next()
                    .ok_or_else(|| "--inspect-slot requires a slot".to_string())?;
                let slot = text
                    .parse::<u64>()
                    .map_err(|_| "invalid inspection slot".to_string())?;
                if slot.to_string() != text {
                    return Err("inspection slot must be canonical u64".to_string());
                }
                inspect_slot = Some(slot);
            }
            "--output" if output.is_none() => {
                output = Some(
                    arguments
                        .next()
                        .ok_or_else(|| "--output requires a path".to_string())?
                        .into(),
                );
            }
            value if value.starts_with('-') => {
                return Err(format!("unknown option: {value}"));
            }
            _ if archive.is_none() => archive = Some(argument.into()),
            _ => return Err("only one archive path is accepted".to_string()),
        }
    }
    if inspect_slot.is_some() && !hash_source {
        return Err("slot inspection requires --hash-source".to_string());
    }
    Ok(Arguments {
        archive: archive.ok_or_else(|| "missing archive path".to_string())?,
        output: output.ok_or_else(|| "missing --output path".to_string())?,
        hash_source,
        inspect_slot,
    })
}

fn whole_source_hash(file: &File, expected: ArchiveFileIdentity) -> Result<String, String> {
    let measured = measure_open_archive(file)
        .map_err(|error| format!("whole-source measurement failed: {error}"))?;
    if measured.identity != expected {
        return Err("archive changed before whole-source measurement".to_string());
    }
    Ok(jetstreamer_node::segment_manifest::sha256_hex_string(
        &measured.sha256,
    ))
}

fn read_bucket(path: &Path, index: usize) -> Result<EdgeVisitor, String> {
    let file = open_regular_nofollow(path)
        .map_err(|error| format!("failed to open {}: {error}", path.display()))?;
    let mut reader = ArchiveReader::open(BufReader::with_capacity(16 << 20, file))
        .map_err(|error| format!("failed to open Horizon archive: {error}"))?;
    reader.verify_chain = true;
    let mut visitor = EdgeVisitor::default();
    reader
        .read_bucket(index, &mut visitor)
        .map_err(|error| format!("failed to decode bucket {index}: {error}"))?;
    visitor.finish()
}

fn inspected_slot(visitor: EdgeVisitor, requested: u64) -> Result<InspectedSlot, String> {
    let visitor = visitor.finish()?;
    let terminal = visitor
        .terminal
        .ok_or_else(|| "inspection has no terminal slot".to_string())?;
    if terminal.slot != requested {
        return Err("inspection returned the wrong slot".to_string());
    }
    let next = visitor
        .last_write
        .map(|v| {
            v.checked_add(1)
                .ok_or_else(|| "inspection write cursor overflows".to_string())
        })
        .transpose()?;
    Ok(InspectedSlot {
        slot: requested,
        kind: if terminal.kind == SlotKind::Block {
            "block"
        } else {
            "skipped"
        },
        observed_blockhash: terminal.blockhash.map(|h| h.to_string()),
        observed_first_write_version: visitor.first_write,
        observed_next_write_version: next,
        observed_write_counts: TerminalWriteCounts {
            pre: terminal.pre_write_count,
            transaction: terminal.transaction_write_count,
            post: terminal.post_write_count,
        },
        checkpoint_drained_write_interpretation_qualified: false,
        complete_prefix_verified: false,
        native_consensus_comparison_passed: false,
    })
}

fn read_inspected_slot(path: &Path, slot: u64) -> Result<InspectedSlot, String> {
    let file = open_regular_nofollow(path).map_err(|e| format!("inspection open failed: {e}"))?;
    let mut reader = ArchiveReader::open(BufReader::with_capacity(16 << 20, file))
        .map_err(|e| format!("inspection reader failed: {e}"))?;
    reader.verify_chain = true;
    let mut visitor = EdgeVisitor::default();
    let count = reader
        .read_slots(slot, 1, &mut visitor)
        .map_err(|e| format!("inspection decode failed: {e}"))?;
    if count != 1 {
        return Err("inspection did not decode exactly one slot".to_string());
    }
    inspected_slot(visitor, slot)
}

fn collect(arguments: &Arguments) -> Result<Evidence, String> {
    let archive = fs::canonicalize(&arguments.archive).map_err(|error| {
        format!(
            "failed to resolve archive {}: {error}",
            arguments.archive.display()
        )
    })?;
    if archive != arguments.archive {
        return Err(format!(
            "archive path must already be absolute and canonical: {}",
            archive.display()
        ));
    }
    let file = open_regular_nofollow(&archive)
        .map_err(|error| format!("failed to open {}: {error}", archive.display()))?;
    let identity = archive_file_identity(&file)
        .map_err(|error| format!("failed to identify {}: {error}", archive.display()))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("failed to inspect {}: {error}", archive.display()))?;
    let archive_bytes = metadata.len();
    let whole_source_sha256 = if arguments.hash_source {
        Some(whole_source_hash(&file, identity)?)
    } else {
        None
    };
    let reader = ArchiveReader::open(BufReader::with_capacity(16 << 20, file))
        .map_err(|error| format!("failed to open Horizon archive: {error}"))?;
    let header = reader.header().clone();
    let provenance = reader
        .provenance()
        .map_err(|error| format!("invalid archive provenance: {error}"))?
        .ok_or_else(|| "archive has no runtime provenance".to_string())?;
    let ArchiveProvenance::V2(provenance) = provenance else {
        return Err("archive edge recovery requires single-runtime V2 provenance".to_string());
    };
    let runtime_profile = provenance.base.runtime_profile.clone();
    let parent_recorded_worker_executable_sha256 =
        recorded_worker_digest(&provenance.worker_executable_sha256)?;
    let bucket_count = reader.bucket_count();
    if bucket_count == 0 {
        return Err("archive has no buckets".to_string());
    }
    let expected_terminal = header
        .slot_start
        .checked_add(header.slot_count)
        .and_then(|end| end.checked_sub(1))
        .ok_or_else(|| "archive slot range is empty or overflows".to_string())?;
    drop(reader);

    let mut first_write = None;
    for index in 0..bucket_count {
        let visitor = read_bucket(&archive, index)?;
        if visitor.first_write.is_some() {
            first_write = visitor.first_write;
            break;
        }
    }
    let first_write =
        first_write.ok_or_else(|| "archive contains no account writes".to_string())?;

    let terminal_visitor = read_bucket(&archive, bucket_count - 1)?;
    let terminal = terminal_visitor
        .terminal
        .ok_or_else(|| "final bucket contains no terminal slot".to_string())?;
    if terminal.slot != expected_terminal {
        return Err(format!(
            "archive terminal slot is {}, expected {expected_terminal}",
            terminal.slot
        ));
    }
    if terminal.kind != SlotKind::Block {
        return Err(format!(
            "archive terminal slot {} is skipped, not a block checkpoint",
            terminal.slot
        ));
    }
    let (derived_terminal_checkpoint_write_count, checkpoint_write_derivation) =
        terminal_checkpoint_write_count(&runtime_profile, terminal.post_write_count)?;
    let blockhash = terminal
        .blockhash
        .ok_or_else(|| "terminal block has no blockhash".to_string())?;

    let mut last_write = terminal_visitor.last_write;
    if last_write.is_none() {
        for index in (0..bucket_count - 1).rev() {
            let visitor = read_bucket(&archive, index)?;
            if visitor.last_write.is_some() {
                last_write = visitor.last_write;
                break;
            }
        }
    }
    let terminal_next_write = last_write
        .ok_or_else(|| "archive contains no terminal write-version evidence".to_string())?
        .checked_add(1)
        .ok_or_else(|| "terminal write version overflows u64".to_string())?;
    if first_write >= terminal_next_write {
        return Err("archive write-version edge range is empty or inverted".to_string());
    }
    let inspected_slot = if let Some(slot) = arguments.inspect_slot {
        if slot < header.slot_start || slot > expected_terminal {
            return Err("inspection slot lies outside the source archive".to_string());
        }
        Some(read_inspected_slot(&archive, slot)?)
    } else {
        None
    };
    if !path_matches_archive_identity(&archive, identity)
        .map_err(|error| format!("failed to recheck {}: {error}", archive.display()))?
    {
        return Err("archive changed while collecting edge evidence".to_string());
    }

    let mut epochs = BTreeMap::new();
    epochs.insert(
        format!("epoch{}", header.epoch),
        EpochEvidence {
            archive,
            archive_bytes,
            source_identity: SourceIdentity::from(&metadata),
            whole_source_sha256,
            inspected_slot,
            runtime_profile,
            parent_recorded_worker_executable_sha256,
            output_start_slot: header.slot_start,
            observed_first_write_version: first_write,
            terminal_slot: terminal.slot,
            terminal_kind: "block",
            observed_terminal_next_write_version: terminal_next_write,
            observed_terminal_write_counts: TerminalWriteCounts {
                pre: terminal.pre_write_count,
                transaction: terminal.transaction_write_count,
                post: terminal.post_write_count,
            },
            derived_terminal_checkpoint_write_count,
            checkpoint_write_derivation,
            observed_terminal_blockhash: blockhash.to_string(),
        },
    );
    Ok(Evidence {
        schema: SCHEMA,
        evidence_scope: "independently-decoded-edge-buckets; complete-reread-required",
        epochs,
        archive_mutations: false,
        sidecar_created: false,
        r2_mutations: false,
    })
}

fn write_evidence(path: &Path, evidence: &Evidence) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("evidence output path must be absolute".to_string());
    }
    let parent = path
        .parent()
        .ok_or_else(|| "evidence output has no parent directory".to_string())?;
    let canonical_parent = fs::canonicalize(parent).map_err(|error| {
        format!(
            "failed to resolve evidence directory {}: {error}",
            parent.display()
        )
    })?;
    if canonical_parent != parent {
        return Err(format!(
            "evidence directory must already be canonical: {}",
            canonical_parent.display()
        ));
    }
    let mut bytes = serde_json::to_vec_pretty(evidence)
        .map_err(|error| format!("failed to serialize evidence: {error}"))?;
    bytes.push(b'\n');
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| format!("failed to create {}: {error}", path.display()))?;
    output
        .write_all(&bytes)
        .and_then(|()| output.sync_all())
        .map_err(|error| format!("failed to persist {}: {error}", path.display()))?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("failed to sync {}: {error}", parent.display()))?;
    Ok(())
}

fn main() {
    let mut raw = env::args();
    let program = raw
        .next()
        .unwrap_or_else(|| "jetstreamer-archive-edge-evidence".to_string());
    let arguments = parse_arguments(raw).unwrap_or_else(|error| {
        eprintln!("error: {error}\n{}", usage(&program));
        process::exit(2);
    });
    let worker_arguments = arguments.clone();
    let evidence = std::thread::Builder::new()
        .name("archive-edge-evidence".to_string())
        .stack_size(DECODER_STACK_BYTES)
        .spawn(move || collect(&worker_arguments))
        .unwrap_or_else(|error| {
            eprintln!("error: failed to start archive decoder: {error}");
            process::exit(1);
        })
        .join()
        .unwrap_or_else(|_| {
            eprintln!("error: archive decoder panicked");
            process::exit(1);
        })
        .unwrap_or_else(|error| {
            eprintln!("error: {error}");
            process::exit(1);
        });
    write_evidence(&arguments.output, &evidence).unwrap_or_else(|error| {
        eprintln!("error: {error}");
        process::exit(1);
    });
    println!("wrote {}", arguments.output.display());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recorded_worker_digest_preserves_all_bytes_and_rejects_zero() {
        let digest = std::array::from_fn(|i| i as u8);
        assert_eq!(
            recorded_worker_digest(&digest).unwrap(),
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        );
        assert!(recorded_worker_digest(&[0; 32]).is_err());
        let mut sparse = [0; 32];
        sparse[31] = 1;
        assert_eq!(
            recorded_worker_digest(&sparse).unwrap(),
            format!("{}01", "00".repeat(31))
        );
    }

    #[test]
    fn source_identity_retains_exact_inode_metadata_in_json() {
        use std::os::unix::fs::PermissionsExt as _;
        let file = tempfile::NamedTempFile::new().unwrap();
        file.as_file().set_len(123).unwrap();
        file.as_file()
            .set_permissions(fs::Permissions::from_mode(0o440))
            .unwrap();
        let metadata = file.as_file().metadata().unwrap();
        let value = serde_json::to_value(SourceIdentity::from(&metadata)).unwrap();
        assert_eq!(value["device"].as_u64(), Some(metadata.dev()));
        assert_eq!(value["inode"].as_u64(), Some(metadata.ino()));
        assert_eq!(value["bytes"].as_u64(), Some(123));
        assert_eq!(value["uid"].as_u64(), Some(u64::from(metadata.uid())));
        assert_eq!(value["gid"].as_u64(), Some(u64::from(metadata.gid())));
        assert_eq!(value["mode"], "0440");
        assert_eq!(value["modified_seconds"].as_i64(), Some(metadata.mtime()));
        assert_eq!(
            value["modified_nanoseconds"].as_i64(),
            Some(metadata.mtime_nsec())
        );
        assert_eq!(value["changed_seconds"].as_i64(), Some(metadata.ctime()));
        assert_eq!(
            value["changed_nanoseconds"].as_i64(),
            Some(metadata.ctime_nsec())
        );
    }

    #[test]
    fn arguments_require_one_archive_and_output() {
        assert_eq!(
            parse_arguments([
                "/private/epoch-151.jet".to_string(),
                "--output".to_string(),
                "/private/edge.json".to_string(),
            ])
            .unwrap(),
            Arguments {
                archive: "/private/epoch-151.jet".into(),
                output: "/private/edge.json".into(),
                hash_source: false,
                inspect_slot: None,
            }
        );
        assert!(parse_arguments(["/private/epoch-151.jet".to_string()]).is_err());
        assert!(
            parse_arguments([
                "/private/one.jet".to_string(),
                "/private/two.jet".to_string(),
                "--output".to_string(),
                "/private/edge.json".to_string(),
            ])
            .is_err()
        );
    }

    #[test]
    fn source_hash_is_explicit_and_duplicate_flags_fail_closed() {
        let args = [
            "/private/epoch-140.jet",
            "--output",
            "/private/hash.json",
            "--hash-source",
        ];
        assert!(
            parse_arguments(args.map(str::to_owned))
                .unwrap()
                .hash_source
        );
        let mut repeated = args.map(str::to_owned).to_vec();
        repeated.push("--hash-source".into());
        assert!(parse_arguments(repeated).is_err());
    }

    #[test]
    fn inspection_requires_full_source_binding_and_exact_single_u64() {
        let base = ["/private/epoch-140.jet", "--output", "/private/cut.json"];
        let args = |tail: &[&str]| {
            base.into_iter()
                .chain(tail.iter().copied())
                .map(str::to_owned)
                .collect::<Vec<_>>()
        };
        assert_eq!(
            parse_arguments(args(&["--hash-source", "--inspect-slot", "60911751"]))
                .unwrap()
                .inspect_slot,
            Some(60911751)
        );
        for tail in [
            vec!["--inspect-slot", "60911751"],
            vec!["--hash-source", "--inspect-slot"],
            vec!["--hash-source", "--inspect-slot", "-1"],
            vec!["--hash-source", "--inspect-slot", "060911751"],
            vec!["--hash-source", "--inspect-slot", "18446744073709551616"],
            vec![
                "--hash-source",
                "--inspect-slot",
                "1",
                "--inspect-slot",
                "2",
            ],
        ] {
            assert!(parse_arguments(args(&tail)).is_err(), "accepted {tail:?}");
        }
    }

    #[test]
    fn inspected_slot_keeps_raw_phase_counts_and_does_not_invent_checkpoint_semantics() {
        let make = || EdgeVisitor {
            first_write: Some(100),
            last_write: Some(109),
            terminal: Some(TerminalSlot {
                slot: 42,
                kind: SlotKind::Block,
                blockhash: Some(Hash::default()),
                pre_write_count: 2,
                transaction_write_count: 5,
                post_write_count: 3,
            }),
            ..EdgeVisitor::default()
        };
        let evidence = inspected_slot(make(), 42).unwrap();
        assert_eq!(evidence.observed_next_write_version, Some(110));
        assert_eq!(evidence.observed_write_counts.post, 3);
        assert!(!evidence.checkpoint_drained_write_interpretation_qualified);
        assert!(!evidence.complete_prefix_verified);
        assert!(!evidence.native_consensus_comparison_passed);
        assert!(inspected_slot(make(), 43).is_err());
        assert!(inspected_slot(EdgeVisitor::default(), 42).is_err());
        let mut overflow = make();
        overflow.last_write = Some(u64::MAX);
        assert!(inspected_slot(overflow, 42).is_err());
    }

    #[test]
    fn whole_source_hash_binds_all_bytes_without_changing_cursor_or_contents() {
        use std::io::{Read as _, Seek as _, SeekFrom};
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(b"abc").unwrap();
        file.as_file_mut().seek(SeekFrom::Start(1)).unwrap();
        let identity = archive_file_identity(file.as_file()).unwrap();
        assert_eq!(
            whole_source_hash(file.as_file(), identity).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(file.as_file_mut().stream_position().unwrap(), 1);
        file.as_file_mut().seek(SeekFrom::Start(0)).unwrap();
        let mut contents = Vec::new();
        file.read_to_end(&mut contents).unwrap();
        assert_eq!(contents, b"abc");
        file.as_file().set_len(4).unwrap();
        assert!(whole_source_hash(file.as_file(), identity).is_err());
    }

    #[test]
    fn write_edges_track_minimum_maximum_and_count() {
        let mut visitor = EdgeVisitor {
            current_slot: Some(10),
            current_kind: Some(SlotKind::Block),
            ..EdgeVisitor::default()
        };
        visitor.accept_write(10, 12, WritePhase::Pre);
        visitor.accept_write(10, 10, WritePhase::Transaction);
        visitor.accept_write(10, 11, WritePhase::Post);
        assert_eq!(visitor.first_write, Some(10));
        assert_eq!(visitor.last_write, Some(12));
        assert_eq!(visitor.current_write_count, 3);
        assert_eq!(visitor.current_pre_write_count, 1);
        assert_eq!(visitor.current_transaction_write_count, 1);
        assert_eq!(visitor.current_post_write_count, 1);
        assert!(visitor.finish().is_ok());
    }

    #[test]
    fn write_for_the_wrong_slot_fails_closed() {
        let mut visitor = EdgeVisitor {
            current_slot: Some(10),
            current_kind: Some(SlotKind::Block),
            ..EdgeVisitor::default()
        };
        visitor.accept_write(11, 10, WritePhase::Pre);
        assert!(visitor.finish().is_err());
    }

    #[test]
    fn qualified_runtimes_preserve_terminal_checkpoint_derivation() {
        let mut visitor = EdgeVisitor {
            current_slot: Some(10),
            current_kind: Some(SlotKind::Block),
            ..EdgeVisitor::default()
        };
        for write_version in 10..13 {
            visitor.accept_write(10, write_version, WritePhase::Pre);
        }
        for write_version in 13..18 {
            visitor.accept_write(10, write_version, WritePhase::Transaction);
        }
        for write_version in 18..22 {
            visitor.accept_write(10, write_version, WritePhase::Post);
        }
        assert_eq!(visitor.current_pre_write_count, 3);
        assert_eq!(visitor.current_transaction_write_count, 5);
        assert_eq!(visitor.current_post_write_count, 4);
        for runtime in ["solana-v1.4.25", "solana-v1.6.16"] {
            let (count, derivation) =
                terminal_checkpoint_write_count(runtime, visitor.current_post_write_count).unwrap();
            assert_eq!(count, 3);
            assert!(derivation.starts_with(runtime));
        }
        assert!(terminal_checkpoint_write_count("solana-v1.5.19", 4).is_err());
        assert!(terminal_checkpoint_write_count("solana-v1.4.25", 0).is_err());
    }
}
