//! Derive the epoch 226 full-verifier expectation from the sealed source
//! manifests and finalized RPC boundaries, without reading the assembly output.

use std::{env, fs::File, io::Read, os::unix::fs::MetadataExt, path::Path};

use anyhow::{Context, Result, ensure};
use jetstreamer_horizon::archive::{
    AccountsHashKind, ArchiveProvenanceV3, BootstrapStateKind, RuntimeAdmission,
    RuntimeHandoffProvenance, RuntimeSegmentProvenance, RuntimeStateCheckpoint, StateCommitment,
    StateCommitmentKind, TransactionMetadataPolicy, WriteVersionNormalization,
    encode_archive_provenance,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const EPOCH: u64 = 226;
const START: u64 = 97_632_000;
const CUT: u64 = 98_063_465;
const END: u64 = 98_064_000;
const MAX_EVIDENCE_BYTES: u64 = 1 << 20;

fn sealed_json(binding: &Value) -> Result<Value> {
    let path = Path::new(text(binding, "path")?);
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "noncanonical evidence path"
    );
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.uid() == 0
            && metadata.mode() & 0o022 == 0
            && metadata.nlink() == 1
            && metadata.len() <= MAX_EVIDENCE_BYTES,
        "invalid sealed evidence at {}",
        path.display()
    );
    let mut raw = Vec::new();
    file.take(MAX_EVIDENCE_BYTES + 1).read_to_end(&mut raw)?;
    ensure!(
        raw.len() as u64 == metadata.len()
            && format!("{:x}", Sha256::digest(&raw)) == text(binding, "sha256")?,
        "evidence digest differs at {}",
        path.display()
    );
    Ok(serde_json::from_slice(&raw)?)
}

fn text<'a>(row: &'a Value, key: &str) -> Result<&'a str> {
    row[key]
        .as_str()
        .with_context(|| format!("missing text field {key}"))
}

fn number(row: &Value, key: &str) -> Result<u64> {
    row[key]
        .as_u64()
        .with_context(|| format!("missing integer field {key}"))
}

fn digest(row: &Value, key: &str) -> Result<[u8; 32]> {
    let mut bytes = [0; 32];
    hex::decode_to_slice(text(row, key)?, &mut bytes)?;
    Ok(bytes)
}

fn checkpoint(row: &Value) -> Result<RuntimeStateCheckpoint> {
    Ok(RuntimeStateCheckpoint {
        slot: number(row, "slot")?,
        bank_hash: text(row, "bank_hash")?.parse()?,
        accounts_hash_kind: AccountsHashKind::LegacyAccountsHash,
        accounts_hash: text(row, "accounts_hash")?.parse()?,
        last_blockhash: text(row, "last_blockhash")?.parse()?,
        capitalization: number(row, "capitalization")?,
        transaction_count: number(row, "transaction_count")?,
        tick_height: number(row, "tick_height")?,
        slot_complete: row["slot_complete"].as_bool().context("slot_complete")?,
        next_write_version: number(row, "next_write_version")?,
    })
}

fn segment(manifest: &Value, archive_start: u64) -> Result<RuntimeSegmentProvenance> {
    let runtime = &manifest["runtime"];
    ensure!(
        manifest["schema_version"] == 1
            && manifest["epoch"] == EPOCH
            && runtime["runtime_admission"] == "candidate"
            && runtime["runtime_profile"] == "solana-v1.6.25"
            && runtime["genesis_hash"] == "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d",
        "unexpected epoch 226 source runtime or manifest"
    );
    let writes = &manifest["emitted_raw_write_versions"];
    Ok(RuntimeSegmentProvenance {
        slot_start: number(manifest, "output_slot_start")?,
        slot_count: number(manifest, "output_slot_count")?,
        generation_profile: text(runtime, "generation_profile")?.to_owned(),
        runtime_profile: text(runtime, "runtime_profile")?.to_owned(),
        runtime_admission: RuntimeAdmission::Candidate,
        runtime_revision: text(runtime, "runtime_revision")?.to_owned(),
        runtime_toolchain: text(runtime, "runtime_toolchain")?.to_owned(),
        worker_executable_sha256: Some(digest(manifest, "worker_executable_sha256")?),
        write_versions: WriteVersionNormalization {
            worker_start: number(writes, "start")?,
            worker_end_exclusive: number(writes, "end")?,
            archive_start,
        },
    })
}

fn run() -> Result<()> {
    let args: Vec<_> = env::args().skip(1).collect();
    let [handoff, handoff_digest, boundaries, boundaries_digest] = args.as_slice() else {
        anyhow::bail!("usage: horizon226-assembly-expectation HANDOFF SHA256 BOUNDARIES SHA256");
    };
    let handoff_ref = json!({"path":handoff,"sha256":handoff_digest});
    let handoff = sealed_json(&handoff_ref)?;
    let stage = &handoff["stage"];
    ensure!(
        handoff["schema"] == "foundation-epoch226-private-assembly-source-v1"
            && handoff["epoch"] == EPOCH
            && stage["operation"] == "assemble",
        "unexpected epoch 226 assembly source packet"
    );
    let prefix = sealed_json(&stage["prefix_manifest"])?;
    let suffix = sealed_json(&stage["suffix_manifest"])?;
    let left = segment(&prefix, 0)?;
    let right = segment(
        &suffix,
        left.write_versions
            .archive_end_exclusive()
            .context("prefix write range")?,
    )?;
    ensure!(
        (
            left.slot_start,
            left.slot_count,
            right.slot_start,
            right.slot_count
        ) == (START, CUT - START, CUT, END - CUT)
            && prefix["archive_sha256"] == stage["prefix_archive"]["sha256"]
            && suffix["archive_sha256"] == stage["suffix_archive"]["sha256"]
            && left.runtime_revision == right.runtime_revision
            && left.runtime_toolchain == right.runtime_toolchain
            && left.worker_executable_sha256 != right.worker_executable_sha256,
        "wrong source coverage, archive binding, or worker transition"
    );

    let boot = &prefix["bootstrap"];
    let restored = &suffix["bootstrap"];
    let provenance = ArchiveProvenanceV3 {
        assembly_profile: "jetstreamer-private/epoch226-explicit-2dcc-to-7a-handoff-v1".into(),
        genesis_hash: text(&prefix["runtime"], "genesis_hash")?.parse()?,
        bootstrap_state_kind: BootstrapStateKind::SnapshotArchive,
        bootstrap_state: StateCommitment {
            slot: number(boot, "slot")?,
            kind: StateCommitmentKind::LegacyAccountsHash,
            hash: text(boot, "accounts_hash")?.parse()?,
        },
        requested_slot_start: START,
        requested_slot_count: END - START,
        transaction_metadata: TransactionMetadataPolicy::observed(),
        runtime_segments: vec![left, right],
        handoffs: vec![RuntimeHandoffProvenance {
            boundary_slot: CUT,
            predecessor: checkpoint(&prefix["terminal"])?,
            successor: checkpoint(restored)?,
            successor_bootstrap_kind: BootstrapStateKind::SnapshotArchive,
            successor_bootstrap_archive_sha256: digest(&suffix, "bootstrap_archive_sha256")?,
            successor_bootstrap_write_count: number(restored, "write_count")?,
        }],
    };
    // Encoding validates the V3 lineage, matching checkpoint state, zero
    // restore writes, and the independent cursors and normalization ranges.
    let encoded = encode_archive_provenance(&provenance.into())?;

    let boundary_ref = json!({"path":boundaries,"sha256":boundaries_digest});
    let mut expectation = sealed_json(&boundary_ref)?;
    ensure!(
        expectation["schema"] == "horizon-current-reader-epoch-expectation-v1"
            && expectation["epoch"] == EPOCH
            && number(&expectation, "parent_slot")? < START
            && expectation["terminal_slot"] == END - 1
            && expectation["terminal_blockhash"] == suffix["terminal"]["last_blockhash"]
            && expectation["provenance_sha256"].is_null(),
        "independent boundary does not match the sealed suffix"
    );
    expectation["provenance_sha256"] = json!(format!("{:x}", Sha256::digest(encoded)));
    let sources = expectation["independent_evidence"]
        .as_array_mut()
        .context("RPC evidence")?;
    ensure!(!sources.is_empty(), "missing independent RPC observations");
    sources.extend([
        boundary_ref,
        handoff_ref,
        stage["prefix_manifest"].clone(),
        stage["suffix_manifest"].clone(),
    ]);
    println!("{}", serde_json::to_string_pretty(&expectation)?);
    Ok(())
}

fn main() -> Result<()> {
    run()
}
