//! Bind the private epoch 168 source views for the ordinary checkpoint V4 merger.
//! Neither command creates an archive, modifies a source, or authorizes publication.
use jetstreamer_horizon::archive::{
    AccountsHashKind, ArchiveProvenance, ArchiveProvenanceV2, ArchiveProvenanceV3,
    ArchiveProvenanceV4, ArchiveReader, BootstrapStateKind, BucketHeader, BucketIndexEntry,
    FileHeader, RuntimeHandoffProvenance, RuntimeSegmentProvenance, RuntimeStateCheckpoint,
    StateCommitment, StateCommitmentKind, WriteVersionNormalization, encode_archive_provenance,
};
use lencode::prelude::*;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{self, BufReader, Read, Seek, SeekFrom},
    ops::Range,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

use super::{
    BYTES, END, FIRST, INPUT, PrefixView, invalid, original_identity,
    selected_prefix::{self as selection, Selected, hex},
};

#[path = "private_assembly.rs"]
pub(crate) mod private_assembly;
pub(super) use private_assembly::{assemble, check_plan};

const EPOCH_END: u64 = 73_008_000;
const SEAM: u64 = 72_994_766;
const TAIL_END: u64 = 73_015_142;
const RETRY6_BYTES: u64 = 5_777_373_749;
const RETRY4_SHA: &str = "cdde7f4da26d0d608f9546883aba787c903e093fc800bd570288e803c0aefc3d";
const RETRY6_SHA: &str = "4a3356c72e2216a8f0a76d0f4ce3d9272d98dadf66deba46e40fa8396e170cea";
const RETRY6: &str = "/home/sol/.jetstreamer-private/epoch168-standard-lane-20261109-v1/full-metered-20261121-v1/cold-retry6-20261126/output/epoch-168-tail.jet";
const PAYLOAD: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch168-focused-retry6-payload-20261126-v1/payload.json";
const PAYLOAD_SHA: &str = "ac732bc24feb7164f8f2454d287434895cb640704f4a01b8361fb335e2dcba88";
const SNAPSHOT: &str = "snapshot-72994766-B9ETcpnA6DWUEweDVfBTjqJjXML6GmHdbtXWZKBZEZ6J.tar.zst";
const SNAPSHOT_SHA: &str = "9b1b06509adcb48f96d5186fc946401b1c3e8c6fdda3d8366a356623ae5ec5f4";
const MAX_EVIDENCE: u64 = 1 << 20;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn require(condition: bool, error: &'static str) -> io::Result<()> {
    if condition {
        Ok(())
    } else {
        Err(invalid(error))
    }
}

fn string<'a>(doc: &'a Value, key: &str) -> io::Result<&'a str> {
    doc[key]
        .as_str()
        .ok_or_else(|| invalid("missing evidence text"))
}

fn number(doc: &Value, key: &str) -> io::Result<u64> {
    doc[key]
        .as_u64()
        .ok_or_else(|| invalid("missing evidence number"))
}

pub(super) fn digest(value: &str) -> Result<[u8; 32]> {
    require(
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "noncanonical SHA-256",
    )?;
    let mut bytes = [0; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)?;
    }
    Ok(bytes)
}

fn open(path: &Path) -> Result<File> {
    require(
        path.is_absolute() && path.canonicalize()? == path,
        "input path crosses a link",
    )?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let m = file.metadata()?;
    require(
        m.is_file() && m.nlink() == 1 && m.mode() & 0o022 == 0,
        "input is not stable private custody",
    )?;
    Ok(file)
}

fn identity(file: &File) -> io::Result<(u64, u64, u64, i64, i64, i64, i64)> {
    let m = file.metadata()?;
    Ok((
        m.dev(),
        m.ino(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    ))
}

fn read_doc(path: &Path, expected: &str, uid: u32) -> Result<Value> {
    let mut file = open(path)?;
    let before = identity(&file)?;
    require(
        file.metadata()?.uid() == uid && (1..=MAX_EVIDENCE).contains(&before.2),
        "unexpected evidence custodian or size",
    )?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take(MAX_EVIDENCE + 1)
        .read_to_end(&mut bytes)?;
    let measured: [u8; 32] = Sha256::digest(&bytes).into();
    require(
        measured == digest(expected)?
            && before == identity(&file)?
            && before == identity(&open(path)?)?,
        "evidence changed after binding",
    )?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn source_evidence(lineage: &Value) -> Result<(Value, u64)> {
    require(
        lineage["schema"] == "horizon-epoch168-private-joint-lineage-binding-v1"
            && lineage["epoch"] == 168
            && lineage["seam"] == SEAM
            && lineage["ordinary_root_slot"] == 73_007_829
            && lineage["joint_archive_sha256"]
                == "95761eb2180fc7126ac32a475ed329df2a13e039a858cdf5f31d52b43b09a6eb"
            && lineage["evidence"]["joint_terminal"]["sha256"]
                == "f9ee88c1c5eb4129638a8c0351e9d6ac1ff5debf2e6859775928488c02f59faf"
            && lineage["retry4_source_sha256"] == RETRY4_SHA
            && lineage["retry6_source_sha256"] == RETRY6_SHA
            && lineage["publication_authorized"] == false
            && lineage["assembly_authorized"] == false,
        "wrong or unsealed epoch 168 lineage authority",
    )?;
    let selected_sha = digest(string(lineage, "retry4_selected_archive_sha256")?)?;
    let semantic_sha = digest(string(lineage, "retry4_selected_semantic_sha256")?)?;
    require(
        selected_sha != [0; 32]
            && semantic_sha != [0; 32]
            && number(lineage, "retry4_selected_raw_start")?
                < number(lineage, "retry4_selected_raw_end_exclusive")?,
        "missing complete selected retry4 evidence",
    )?;
    let accepted = &lineage["evidence"]["selected_prefix"];
    let prefix = read_doc(
        Path::new(string(accepted, "path")?),
        string(accepted, "sha256")?,
        0,
    )?;
    let prefix_bytes = number(&prefix, "selected_archive_bytes")?;
    require(
        prefix["schema"] == "horizon-epoch168-private-selected-prefix-evidence-v1"
            && prefix["source_archive_sha256"] == RETRY4_SHA
            && prefix["selected_archive_sha256"] == lineage["retry4_selected_archive_sha256"]
            && prefix["selected_semantic_sha256"] == lineage["retry4_selected_semantic_sha256"]
            && prefix["raw_start"] == lineage["retry4_selected_raw_start"]
            && prefix["raw_end_exclusive"] == lineage["retry4_selected_raw_end_exclusive"]
            && prefix["first_slot"] == FIRST
            && prefix["last_slot"] == SEAM
            && prefix["independently_decoded"] == true
            && prefix["physical_archive_bytes_written"] == 0
            && prefix["terminal_blockhash"]
                == lineage["translated_v4_predecessor"]["last_blockhash"]
            && (1..BYTES).contains(&prefix_bytes),
        "selected retry4 receipt changed from the independent seam proof",
    )?;
    let retry6_manifest = Path::new(RETRY6).with_extension("jet.segment.json");
    let evidence = &lineage["evidence"]["retry6_manifest"];
    require(
        Path::new(string(evidence, "path")?) == retry6_manifest,
        "crossed retry6 manifest path",
    )?;
    let manifest = read_doc(&retry6_manifest, string(evidence, "sha256")?, 1001)?;
    require(
        manifest["archive_sha256"] == RETRY6_SHA
            && manifest["epoch"] == 168
            && manifest["output_slot_start"] == SEAM + 1
            && manifest["output_slot_count"] == TAIL_END - SEAM - 1
            && manifest["bootstrap"] == lineage["retry6_native_bootstrap"]
            && manifest["bootstrap"]["write_count"] == 0,
        "crossed retry6 manifest or restart",
    )?;
    let payload = read_doc(Path::new(PAYLOAD), PAYLOAD_SHA, 0)?;
    require(
        payload["snapshots"][SNAPSHOT]["sha256"] == SNAPSHOT_SHA
            && payload["read_only_projections"]
                .as_array()
                .is_some_and(|rows| {
                    rows.iter().any(|row| {
                        row["source"] == payload["snapshots"][SNAPSHOT]
                            && row["target"] == format!("/run/horizon-full168-cold-v6/{SNAPSHOT}")
                    })
                }),
        "retry6 checkpoint lacks the exact durable restart snapshot custody",
    )?;
    Ok((manifest, prefix_bytes))
}

pub(super) struct SourceLayout {
    pub(super) header: FileHeader,
    pub(super) provenance: ArchiveProvenanceV2,
    pub(super) buckets: Vec<BucketIndexEntry>,
}

pub(super) fn source_layout<R: Read + Seek>(
    epoch: u64,
    mut reader: ArchiveReader<R>,
    start: u64,
    selected_end: u64,
    complete: bool,
) -> Result<SourceLayout> {
    let header = reader.header().clone();
    require(
        header.epoch == epoch
            && header.slot_start == start
            && header
                .slot_start
                .checked_add(header.slot_count)
                .is_some_and(|end| selected_end < end)
            && reader.has_complete_slot_coverage()? == complete,
        "wrong source extent or container coverage",
    )?;
    let Some(ArchiveProvenance::V2(provenance)) = reader.provenance()? else {
        return Err(invalid("source lacks its original V2 provenance").into());
    };
    let buckets = reader.bucket_index();
    let selected = buckets.partition_point(|b| b.first_slot < selected_end);
    require(
        selected >= 3
            && selected_end - buckets[selected - 1].first_slot < u64::from(header.bucket_slots),
        "selected end does not cut a single indexed bucket",
    )?;
    Ok(SourceLayout {
        header,
        provenance,
        buckets: buckets[..selected].to_vec(),
    })
}

pub(super) fn checkpoint_at(doc: &Value, slot: u64) -> Result<RuntimeStateCheckpoint> {
    require(
        doc["slot"] == slot && doc["slot_complete"] == true,
        "wrong seam checkpoint",
    )?;
    Ok(RuntimeStateCheckpoint {
        slot,
        bank_hash: string(doc, "bank_hash")?.parse()?,
        accounts_hash_kind: AccountsHashKind::LegacyAccountsHash,
        accounts_hash: string(doc, "accounts_hash")?.parse()?,
        last_blockhash: string(doc, "last_blockhash")?.parse()?,
        capitalization: number(doc, "capitalization")?,
        transaction_count: number(doc, "transaction_count")?,
        tick_height: number(doc, "tick_height")?,
        slot_complete: true,
        next_write_version: number(doc, "next_write_version")?,
    })
}

fn checkpoint(doc: &Value) -> Result<RuntimeStateCheckpoint> {
    checkpoint_at(doc, SEAM)
}

pub(super) fn segment(
    source: &SourceLayout,
    slot_count: u64,
    raw: Range<u64>,
    archive_start: u64,
) -> RuntimeSegmentProvenance {
    let policy = &source.provenance.base;
    RuntimeSegmentProvenance {
        slot_start: source.header.slot_start,
        slot_count,
        generation_profile: policy.generation_profile.clone(),
        runtime_profile: policy.runtime_profile.clone(),
        runtime_admission: policy.runtime_admission,
        runtime_revision: policy.runtime_revision.clone(),
        runtime_toolchain: policy.runtime_toolchain.clone(),
        worker_executable_sha256: Some(source.provenance.worker_executable_sha256),
        write_versions: WriteVersionNormalization {
            worker_start: raw.start,
            worker_end_exclusive: raw.end,
            archive_start,
        },
    }
}

fn provenance(
    left: &SourceLayout,
    right: &SourceLayout,
    lineage: &Value,
    suffix: Range<u64>,
) -> Result<ArchiveProvenanceV4> {
    let predecessor = checkpoint(&lineage["translated_v4_predecessor"])?;
    let successor = checkpoint(&lineage["retry6_native_bootstrap"])?;
    let left_cursor = number(lineage, "retry4_selected_raw_start")?
        ..number(lineage, "retry4_selected_raw_end_exclusive")?;
    require(
        predecessor.next_write_version == left_cursor.end
            && successor.next_write_version == suffix.start,
        "selected raw cursors do not meet the independent restart",
    )?;
    let left_base = &left.provenance.base;
    let right_base = &right.provenance.base;
    require(
        left_base.bootstrap_state_kind == BootstrapStateKind::SnapshotArchive
            && left_base.genesis_hash == right_base.genesis_hash
            && left_base.transaction_metadata == right_base.transaction_metadata
            && right_base.bootstrap_slot == successor.slot
            && right_base.bootstrap_state_hash == successor.accounts_hash,
        "source runtime policy or restart differs",
    )?;
    let normalized = left_cursor.end - left_cursor.start;
    let destination = ArchiveProvenanceV4 {
        base: ArchiveProvenanceV3 {
            assembly_profile: "jetstreamer-node/epoch168-private-checkpoint-restart-v1".into(),
            genesis_hash: left_base.genesis_hash,
            bootstrap_state_kind: left_base.bootstrap_state_kind,
            bootstrap_state: StateCommitment {
                slot: left_base.bootstrap_slot,
                kind: StateCommitmentKind::LegacyAccountsHash,
                hash: left_base.bootstrap_state_hash,
            },
            requested_slot_start: FIRST,
            requested_slot_count: EPOCH_END - FIRST,
            transaction_metadata: left_base.transaction_metadata.clone(),
            runtime_segments: vec![
                segment(left, SEAM + 1 - FIRST, left_cursor, 0),
                segment(right, EPOCH_END - SEAM - 1, suffix, normalized),
            ],
            handoffs: vec![RuntimeHandoffProvenance {
                boundary_slot: SEAM + 1,
                predecessor,
                successor,
                successor_bootstrap_kind: right_base.bootstrap_state_kind,
                successor_bootstrap_archive_sha256: digest(SNAPSHOT_SHA)?,
                successor_bootstrap_write_count: 0,
            }],
        },
    };
    destination.validate()?;
    Ok(destination)
}

struct OpenSources {
    prefix: File,
    suffix: File,
    left: SourceLayout,
    right: SourceLayout,
}

fn open_sources() -> Result<OpenSources> {
    let mut prefix = open(Path::new(INPUT))?;
    original_identity(&prefix)?;
    let mut suffix = open(Path::new(RETRY6))?;
    let before_suffix = identity(&suffix)?;
    require(
        (before_suffix.0, before_suffix.1, before_suffix.2) == (64512, 109397511, RETRY6_BYTES),
        "retry6 differs from the closed producer file",
    )?;
    let left = source_layout(
        168,
        ArchiveReader::open(PrefixView::open(&mut prefix, 168, FIRST, END)?)?,
        FIRST,
        SEAM + 1,
        false,
    )?;
    let right = source_layout(
        168,
        ArchiveReader::open(BufReader::new(&mut suffix))?,
        SEAM + 1,
        EPOCH_END,
        true,
    )?;
    require(
        left.header.slot_count == EPOCH_END - FIRST
            && right.header.slot_count == TAIL_END - SEAM - 1,
        "original source header range differs",
    )?;

    let a = &left.provenance.base;
    let b = &right.provenance.base;
    require(
        a.runtime_profile == b.runtime_profile
            && a.runtime_revision == b.runtime_revision
            && a.runtime_toolchain == b.runtime_toolchain
            && a.runtime_admission == b.runtime_admission
            && a.genesis_hash == b.genesis_hash
            && a.transaction_metadata == b.transaction_metadata
            && left.provenance.worker_executable_sha256
                == right.provenance.worker_executable_sha256,
        "retry4 and retry6 lack the equal source runtime identity required by V4",
    )?;
    Ok(OpenSources {
        prefix,
        suffix,
        left,
        right,
    })
}

pub(super) fn inspect_layout() -> Result<()> {
    let sources = open_sources()?;
    let describe = |source: &SourceLayout, selected_end| {
        json!({
            "start":source.header.slot_start, "declared_slot_count":source.header.slot_count,
            "selected_end_exclusive":selected_end, "bucket_slots":source.header.bucket_slots,
            "selected_bucket_count":source.buckets.len(), "bootstrap_slot":source.provenance.base.bootstrap_slot,
            "worker_sha256":hex(&source.provenance.worker_executable_sha256),
            "runtime_revision":source.provenance.base.runtime_revision,
        })
    };
    println!(
        "{}",
        json!({"epoch":168,"prefix":describe(&sources.left,SEAM+1),
        "suffix":describe(&sources.right,EPOCH_END),"archive_payload_decoded":false,
        "physical_archive_bytes_written":0,"assembly_authorized":false,"publication_authorized":false})
    );
    Ok(())
}

pub(super) fn run(path: &str, sha256: &str, qualify: bool) -> Result<()> {
    let lineage = read_doc(Path::new(path), sha256, 0)?;
    let (retry6_manifest, prefix_bytes) = source_evidence(&lineage)?;
    let mut sources = open_sources()?;
    let OpenSources {
        prefix,
        suffix,
        left,
        right,
    } = &mut sources;
    let before_prefix = identity(prefix)?;
    let before_suffix = identity(suffix)?;
    suffix.seek(SeekFrom::Start(right.buckets[0].offset))?;
    let initial_header = BucketHeader::decode_ext(&mut *suffix, None)?;
    require(
        initial_header.first_slot == SEAM + 1
            && initial_header.poh_start_hash
                == checkpoint(&lineage["retry6_native_bootstrap"])?.last_blockhash,
        "retry6's first bucket does not start from the independently observed seam blockhash",
    )?;

    let report = if qualify {
        // The bound selector already measures and independently decodes
        // retry4. Its identity is rechecked in this pass, and the merger
        // will reconstruct and rehash its virtual input before accepting it.
        let right_view = selection::cut(
            &mut *suffix,
            &right.header,
            ArchiveProvenance::V2(right.provenance.clone()),
            &right.buckets,
            EPOCH_END,
        )?;
        selection::boundaries(
            &mut *suffix,
            &right.header,
            &right.buckets,
            &right_view,
            EPOCH_END,
        )?;
        let (original, selected, measured) = selection::hashes(&mut *suffix, &right_view)?;
        require(
            measured == RETRY6_BYTES && original == digest(RETRY6_SHA)?,
            "retry6 source bytes changed",
        )?;
        let observed =
            selection::semantic_read(Selected::new(&mut *suffix, &right_view), EPOCH_END)?;
        let first = observed
            .first_raw
            .ok_or_else(|| invalid("no selected retry6 writes"))?;
        let end = observed
            .next_raw
            .ok_or_else(|| invalid("no terminal selected retry6 cursor"))?;
        let last = observed
            .last_block
            .ok_or_else(|| invalid("no terminal selected retry6 block"))?;
        let ordinary_root_cursor =
            number(&lineage["ordinary_root_checkpoint"], "next_write_version")?
                .checked_add(number(&lineage, "joint_to_retry6_cursor_offset")?)
                .ok_or_else(|| invalid("translated ordinary-root cursor overflows"))?;
        require(
            first == number(&retry6_manifest["emitted_raw_write_versions"], "start")?
                && end >= ordinary_root_cursor
                && end <= number(&retry6_manifest["emitted_raw_write_versions"], "end")?
                && first < end
                && (73_007_829..EPOCH_END).contains(&last),
            "wrong selected retry6 terminal",
        )?;
        let v4 = provenance(left, right, &lineage, first..end)?;
        let encoded = encode_archive_provenance(&ArchiveProvenance::V4(v4))?;
        json!({"selected_retry4_archive_bytes":prefix_bytes, "selected_retry6_archive_bytes":right_view.len(),
               "selected_retry6_archive_sha256":hex(&selected),"selected_retry6_semantic_sha256":hex(&observed.semantic),
               "retry6_raw_start":first,"retry6_raw_end_exclusive":end,"retry6_last_block_slot":last,
               "retry6_last_blockhash":bs58::encode(observed.last_hash).into_string(),
               "v4_provenance_sha256":hex(&Sha256::digest(&encoded)), "v4_provenance_hex":hex(&encoded)})
    } else {
        // Check the checkpoint and startup policy without decoding a source frame.
        let writes = &retry6_manifest["emitted_raw_write_versions"];
        provenance(
            &left,
            &right,
            &lineage,
            number(writes, "start")?..number(writes, "end")?,
        )?;
        Value::Null
    };
    require(
        before_prefix == identity(prefix)?
            && before_prefix == identity(&open(Path::new(INPUT))?)?
            && before_suffix == identity(suffix)?
            && before_suffix == identity(&open(Path::new(RETRY6))?)?,
        "assembly source identity changed during qualification",
    )?;
    println!(
        "{}",
        json!({
            "schema":"horizon-epoch168-private-assembly-sources-v1","epoch":168,
            "lineage":{"path":path,"sha256":sha256},"seam":SEAM,
            "prefix_range":{"start":FIRST,"end_exclusive":SEAM+1},
            "suffix_range":{"start":SEAM+1,"end_exclusive":EPOCH_END},
            "prefix_source_bytes":BYTES,"selected_retry4_archive_bytes":prefix_bytes,"suffix_source_bytes":RETRY6_BYTES,
            "retry6_bootstrap_archive_sha256":SNAPSHOT_SHA,
            "physical_archive_bytes_written":0,"boundary_decoder_run":qualify,
            "selection":report,"assembly_authorized":false,"publication_authorized":false,
        })
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use jetstreamer_horizon::archive::{
        ArchiveProvenanceV1, ArchiveWriter, ArchiveWriterConfig, RuntimeAdmission,
        TransactionMetadataPolicy,
    };
    use std::io::Cursor;

    fn layout(start: u64, bootstrap: u64) -> SourceLayout {
        let hash = bs58::encode([1; 32]).into_string().parse().unwrap();
        let provenance = ArchiveProvenanceV2 {
            base: ArchiveProvenanceV1 {
                generation_profile: "synthetic-epoch168".into(),
                runtime_profile: "solana-v1.5.6".into(),
                runtime_revision: "synthetic".into(),
                runtime_admission: RuntimeAdmission::Candidate,
                runtime_toolchain: "synthetic".into(),
                genesis_hash: hash,
                bootstrap_state_kind: BootstrapStateKind::SnapshotArchive,
                bootstrap_slot: bootstrap,
                bootstrap_state_hash: hash,
                requested_slot_start: start,
                requested_slot_count: 1,
                transaction_metadata: TransactionMetadataPolicy::observed(),
            },
            worker_executable_sha256: [2; 32],
        };
        let mut writer = ArchiveWriter::new_with_provenance(
            Vec::new(),
            168,
            start,
            1,
            ArchiveWriterConfig::default(),
            &ArchiveProvenance::V2(provenance.clone()),
        )
        .unwrap();
        writer.write_skipped_slot(start).unwrap();
        let bytes = writer.finish().unwrap().0;
        let reader = ArchiveReader::open(Cursor::new(bytes)).unwrap();
        SourceLayout {
            header: reader.header().clone(),
            provenance,
            buckets: Vec::new(),
        }
    }

    #[test]
    fn plans_exact_epoch_extent_with_distinct_worker_cursors() {
        let left = layout(FIRST, FIRST - 1);
        let right = layout(SEAM + 1, SEAM);
        let hash = bs58::encode([1; 32]).into_string();
        let checkpoint = json!({"slot":SEAM,"bank_hash":hash,"accounts_hash":hash,
            "last_blockhash":hash,"capitalization":10,"transaction_count":11,"tick_height":12,
            "slot_complete":true,"next_write_version":2_200});
        let mut lineage = json!({"translated_v4_predecessor":checkpoint,
            "retry6_native_bootstrap":checkpoint,
            "retry4_selected_raw_start":100,"retry4_selected_raw_end_exclusive":1_200});
        lineage["translated_v4_predecessor"]["next_write_version"] = json!(1_200);
        let result = provenance(&left, &right, &lineage, 2_200..2_300).unwrap();
        assert_eq!(result.base.requested_slot_count, 432_000);
        assert_eq!(result.base.handoffs[0].boundary_slot, SEAM + 1);
        assert_eq!(
            result.base.runtime_segments[1].write_versions.archive_start,
            1_100
        );
        assert_eq!(
            result.base.runtime_segments[0].runtime_admission,
            RuntimeAdmission::Candidate
        );
        assert!(provenance(&left, &right, &lineage, 2_201..2_300).is_err());
        lineage["translated_v4_predecessor"]["capitalization"] = json!(11);
        assert!(provenance(&left, &right, &lineage, 2_200..2_300).is_err());
    }
}
