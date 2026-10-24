//! Metadata-only future223 handoff gate. Never opens an epoch archive.
use crate::evidence;

use anyhow::{Context, Result, ensure};
use jetstreamer_horizon::archive::*;
use jetstreamer_node::segment_manifest::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use solana_hash::Hash;
use std::{
    env, fs,
    path::{Path, PathBuf},
};

const PREFIX_ROOT: &str =
    "/home/ubuntu/.jetstreamer-private/qualification-223-v1620-prefix-full-root-v1";
const UNIT: &str = "horizon-qualify-223-v1620-root-prefix-resource-full-v1.service";
const IID: &str = "e70aaf097e7c4583b216aba454145910";
const WORKER20: &str = "a651b7a6ee3c0d4f8359e1ea6cfcb96becf259d440ee744beb173b264de6af20";
const REVISION20: &str = "77bdb45d4af61fc687161ec06cc0178ff79726d5";
const NODE20: &str = "99f643ff0dbbcd37d1fbc524a1c1088d7273c7fc91330df059d30d51b8b0fcd4";
const RUNNER: &str = "d18fd42956cafd34d6dccabeb2a47fbbca8c8d857ef8ed7adb39d8ad2a2b1d7d";
const RESOURCE_PLAN: &str = "c293ceb824be8b4272c969c1e2cbe1071e8e2255465d5e0c3358fda513ae2973";
const COLD_SNAPSHOT: &str = "301110cad7eb56ed68c99d31cf6769b7622e2c166f33aec084dc51592d0cd665";
const TAIL_SNAPSHOT: &str = "dc7f2ac03813bc609629885af82222ac5af070cc6187b7bce08e10944fd214e1";
const WORKER25: &str = "fde3ba53cc52012b894bac29bd7889b4cfd326fff75f4f67ec4cbdbf2ac7136c";
const REVISION25: &str = "7de8a55b54d3e11058b82f9483bb405d143b455c";
const GENESIS: &str = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d";
const TAIL_ARCHIVE: &str = "89470a1b323aa2dd0cd17eb15464f49a2971c44587112b52523e24f8cc4687dc";
const TAIL_PROOF: (&str, &str) = (
    "/var/lib/jetstreamer/horizon-223-tail-exact-capture-281b1ddd-v1/capture.json",
    "d79e374e95861e427239c9e0ba020ed5796fa6c1b076654115823965d7b96796",
);
const TAIL_MANIFEST: (&str, &str) = (
    "/var/lib/jetstreamer/horizon-223-tail-terminal-1743245a-v3/segment.json",
    "baf168cdc9f1e87aef1ab41facdfbe130ddec009d9d5f41d39b2a92d5a2572f0",
);
const LAUNCH: (&str, &str) = (
    "/var/lib/jetstreamer/horizon-native223-prefix-capture-actual-v1/launch.json",
    "a629f2a5eb1a6be5e3ec38e66769f0698841fb7ccc8d43110ac3bfd73df99ac3",
);
const START: u64 = 96336000;
const ROOT: u64 = 96767522;
const END: u64 = 96767999;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Bound {
    pub(super) path: PathBuf,
    pub(super) sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Plan {
    schema: String,
    prefix_completion: Bound,
    prefix_manifest: Bound,
    prefix_reread: Bound,
    prefix_terminal_journal: Bound,
    output: PathBuf,
}
fn sha(value: &str) -> Result<[u8; 32]> {
    ensure!(evidence::is_sha(value), "invalid digest");
    let mut result = [0; 32];
    for (index, out) in result.iter_mut().enumerate() {
        *out = u8::from_str_radix(&value[2 * index..2 * index + 2], 16)?;
    }
    Ok(result)
}
fn read(bound: &Bound) -> Result<Vec<u8>> {
    evidence::bound_file(&bound.path, &bound.sha256, 4 * 1024 * 1024, true)
}
fn checkpoint(summary: &SegmentCheckpointSummary) -> Result<RuntimeStateCheckpoint> {
    Ok(RuntimeStateCheckpoint {
        slot: summary.slot,
        bank_hash: summary.bank_hash_value()?,
        accounts_hash_kind: AccountsHashKind::LegacyAccountsHash,
        accounts_hash: summary.accounts_hash_value()?,
        last_blockhash: summary.last_blockhash_value()?,
        capitalization: summary.capitalization,
        transaction_count: summary.transaction_count,
        tick_height: summary.tick_height,
        slot_complete: summary.slot_complete,
        next_write_version: summary.next_write_version,
    })
}
fn runtime_segment(source: &HistoricalSegmentManifest, start: u64) -> RuntimeSegmentProvenance {
    RuntimeSegmentProvenance {
        slot_start: source.output_slot_start,
        slot_count: source.output_slot_count,
        generation_profile: source.runtime.generation_profile.clone(),
        runtime_profile: source.runtime.runtime_profile.clone(),
        runtime_admission: RuntimeAdmission::Candidate,
        runtime_revision: source.runtime.runtime_revision.clone(),
        runtime_toolchain: source.runtime.runtime_toolchain.clone(),
        worker_executable_sha256: Some(source.worker_executable_sha256),
        write_versions: WriteVersionNormalization {
            worker_start: source.emitted_raw_write_versions.start,
            worker_end_exclusive: source.emitted_raw_write_versions.end,
            archive_start: start,
        },
    }
}
pub(super) fn provenance(
    prefix: &HistoricalSegmentManifest,
    tail: &HistoricalSegmentManifest,
) -> Result<ArchiveProvenanceV3> {
    prefix.validate()?;
    tail.validate()?;
    ensure!(
        prefix.epoch == 223
            && prefix.output_slot_start == START
            && prefix.output_slot_count == 431523
            && prefix.bootstrap.slot == 96335538
            && prefix.terminal.slot == ROOT
            && prefix.bootstrap.accounts_hash == "Gavt9cmcj5BFXuZnz44JktRGbM9oxRkJqoWRF8PvMBTE"
            && prefix.bootstrap.bank_hash == "8LxWwzEvnAvZC6FwgcqFMxeswZD5skZ7zacYhf1eYW1F"
            && prefix.terminal.accounts_hash == "3SdyhqCuei4esVf8imz8A2rPB1z83sAK3KHbtKefJDS7"
            && prefix.terminal.bank_hash == "EWtQnBfEHcQ5hASVyH6u3LXT6WLu5MwWML6VKGg4MdxB"
            && prefix.worker_executable_sha256 == sha(WORKER20)?
            && prefix.runtime.runtime_profile == "solana-v1.6.20"
            && prefix.runtime.runtime_revision == REVISION20
            && prefix.runtime.runtime_admission == SegmentRuntimeAdmission::Candidate
            && prefix.bootstrap_archive_sha256.is_none(),
        "foreign native20 prefix"
    );
    ensure!(
        tail.epoch == 223
            && tail.output_slot_start == ROOT + 1
            && tail.output_slot_count == 477
            && tail.bootstrap.slot == ROOT
            && tail.terminal.slot == END
            && tail.worker_executable_sha256 == sha(WORKER25)?
            && tail.archive_sha256 == sha(TAIL_ARCHIVE)?
            && tail.runtime.runtime_profile == "solana-v1.6.25"
            && tail.runtime.runtime_revision == REVISION25
            && tail.runtime.runtime_admission == SegmentRuntimeAdmission::Candidate
            && tail.bootstrap_archive_sha256.is_none()
            && tail.emitted_raw_write_versions == (107266983592..107268320809)
            && tail.bootstrap.next_write_version == 107266983592
            && tail.bootstrap.write_count == 0,
        "foreign historical native25 tail"
    );
    ensure!(
        prefix.runtime.genesis_hash == GENESIS
            && tail.runtime.genesis_hash == GENESIS
            && prefix.runtime.runtime_target == "x86_64-unknown-linux-gnu"
            && tail.runtime.runtime_target == prefix.runtime.runtime_target,
        "genesis/target mismatch"
    );
    let first = runtime_segment(prefix, 0);
    let second = runtime_segment(
        tail,
        first
            .write_versions
            .archive_end_exclusive()
            .context("prefix normalization overflow")?,
    );
    let result = ArchiveProvenanceV3 {
        assembly_profile: "jetstreamer-node/epoch223-native20-native25-metadata-handoff-plan-v1"
            .into(),
        genesis_hash: GENESIS.parse::<Hash>()?,
        bootstrap_state_kind: BootstrapStateKind::SnapshotArchive,
        bootstrap_state: StateCommitment {
            slot: prefix.bootstrap.slot,
            kind: StateCommitmentKind::LegacyAccountsHash,
            hash: prefix.bootstrap.accounts_hash_value()?,
        },
        requested_slot_start: START,
        requested_slot_count: 432000,
        transaction_metadata: TransactionMetadataPolicy::observed(),
        runtime_segments: vec![first, second],
        handoffs: vec![RuntimeHandoffProvenance {
            boundary_slot: ROOT + 1,
            predecessor: checkpoint(&prefix.terminal)?,
            successor: checkpoint(&tail.bootstrap)?,
            successor_bootstrap_kind: BootstrapStateKind::SnapshotArchive,
            successor_bootstrap_archive_sha256: sha(TAIL_SNAPSHOT)?,
            successor_bootstrap_write_count: tail.bootstrap.write_count,
        }],
    };
    // Reuse the actual cross-runtime validator. V4 must continue refusing these
    // different runtimes. Never copy its same-runtime identity exception here.
    result.validate()?;
    Ok(result)
}

fn raw_terminal(raw: &[u8], terminal: &SegmentCheckpointSummary) -> Result<Value> {
    let mut checkpoints = Vec::new();
    let mut successes = Vec::new();
    for (index, line) in std::str::from_utf8(raw)?.lines().enumerate() {
        ensure!(
            index < 10000 && line.len() <= 65536,
            "terminal journal bounds exceeded"
        );
        let row: Value = serde_json::from_str(line)?;
        let msg = row["MESSAGE"].as_str().context("journal message missing")?;
        if msg.contains("Deactivated successfully.") {
            ensure!(
                row["_PID"] == "1"
                    && row["UNIT"] == UNIT
                    && row["INVOCATION_ID"] == IID
                    && msg == format!("{UNIT}: Deactivated successfully."),
                "foreign terminal manager"
            );
            successes.push((
                index + 1,
                row["__REALTIME_TIMESTAMP"]
                    .as_str()
                    .context("manager clock")?
                    .parse::<u64>()?,
            ));
        }
        let Some((_, fields)) = msg.split_once("historical checkpoint ") else {
            continue;
        };
        let mut values = std::collections::BTreeMap::new();
        for part in fields.split_whitespace() {
            let (k, v) = part.split_once('=').context("malformed checkpoint")?;
            ensure!(values.insert(k, v).is_none(), "duplicate checkpoint field");
        }
        if values.get("slot") != Some(&"96767522") {
            continue;
        }
        ensure!(
            values.len() == 10
                && row["_SYSTEMD_INVOCATION_ID"] == IID
                && row["_PID"]
                    .as_str()
                    .and_then(|p| p.parse::<u32>().ok())
                    .is_some_and(|p| p > 1),
            "foreign terminal checkpoint"
        );
        if let Some(unit) = row.get("_SYSTEMD_UNIT") {
            ensure!(unit == UNIT, "foreign checkpoint unit")
        }
        let text =
            |k| -> Result<&str> { values.get(k).copied().context("checkpoint field missing") };
        let number = |k| -> Result<u64> { Ok(text(k)?.parse()?) };
        ensure!(text("complete")? == "true", "incomplete terminal");
        let found = SegmentCheckpointSummary {
            slot: number("slot")?,
            bank_hash: text("bank_hash")?.into(),
            accounts_hash: text("accounts_hash")?.into(),
            last_blockhash: text("last_blockhash")?.into(),
            capitalization: number("capitalization")?,
            transaction_count: number("transactions")?,
            tick_height: number("tick_height")?,
            slot_complete: true,
            write_count: number("writes")?,
            next_write_version: number("next_write_version")?,
        };
        ensure!(&found == terminal, "raw terminal/manifest mismatch");
        checkpoints.push((
            index + 1,
            row["__REALTIME_TIMESTAMP"]
                .as_str()
                .context("checkpoint clock")?
                .parse::<u64>()?,
        ));
    }
    ensure!(
        checkpoints.len() == 1
            && successes.len() == 1
            && checkpoints[0].0 < successes[0].0
            && checkpoints[0].1 < successes[0].1,
        "missing/duplicate/unordered terminal proof"
    );
    Ok(
        json!({"checkpoint_line":checkpoints[0].0,"checkpoint_realtime_micros":checkpoints[0].1,
        "manager_success_line":successes[0].0,"manager_success_realtime_micros":successes[0].1,
        "unit":UNIT,"invocation_id":IID}),
    )
}

fn inputs(
    prefix: &HistoricalSegmentManifest,
    completion: &Value,
    reread: &Value,
    tail: &HistoricalSegmentManifest,
    tail_proof: &Value,
    launch: &Value,
    journal: &[u8],
) -> Result<Value> {
    let v3 = provenance(prefix, tail)?;
    ensure!(
        launch["schema"] == "jetstreamer-private-epoch223-native20-prefix-launch-v1"
            && launch["launched"] == true
            && launch["evidence"]["units"][0]["unit"] == UNIT
            && launch["evidence"]["units"][0]["invocation_id"] == IID
            && launch["worker_sha256"] == WORKER20
            && launch["resource_plan"]["sha256"] == RESOURCE_PLAN
            && launch["private_run_root"] == PREFIX_ROOT,
        "wrong actual launch"
    );
    ensure!(
        completion["schema"] == "jetstreamer-private-epoch223-v1620-root-prefix-resource-v1"
            && completion["epoch"] == 223
            && completion["unit"] == UNIT
            && completion["invocation_id"] == IID
            && completion["runner_sha256"] == RUNNER
            && completion["node_sha256"] == NODE20
            && completion["worker_sha256"] == WORKER20
            && completion["snapshot_sha256"] == COLD_SNAPSHOT
            && completion["plan"]["sha256"] == RESOURCE_PLAN
            && completion["success"] == true
            && completion["error"].is_null()
            && completion["child_return_code"] == 0
            && completion["external_signal"] == 0
            && completion["natural_parent_completion_required"] == true
            && completion["target_slot"] == ROOT
            && completion["terminal_root_slot"] == ROOT
            && completion["producer_canonical_root_prefix_present"] == true
            && completion["producer_segment_manifest"] == serde_json::to_value(prefix)?,
        "prefix did not complete under actual bound invocation"
    );
    for field in [
        "canonical_prefix_independently_qualified",
        "full_cold_epoch_peak_qualified",
        "ordinary_replay_authorized",
        "runtime_promotion_authorized",
        "canonical_sidecar_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(
            completion["authority"][field] == false,
            "unexpected producer {field} authority"
        );
    }
    ensure!(
        reread["schema"] == "jetstreamer-focused-qualification-artifact-validation-v1"
            && reread["validation"] == "pass"
            && reread["epoch"] == 223
            && reread["archive"] == format!("{PREFIX_ROOT}/output/epoch-223.jet")
            && reread["manifest"] == format!("{PREFIX_ROOT}/output/epoch-223.jet.segment.json")
            && reread["archive_sha256"] == sha256_hex_string(&prefix.archive_sha256)
            && reread["archive_bytes"].as_u64().is_some_and(|n| n > 0)
            && reread["archive_bytes"] == completion["archive_length"]
            && reread["manifest_content_encoding"] == SEGMENT_MANIFEST_CONTENT_ENCODING
            && reread["manifest_content_sha256"] == sha256_hex_string(&prefix.content_sha256()?)
            && reread["bootstrap_slot"] == 96335538
            && reread["output_slot_start"] == START
            && reread["terminal_slot"] == ROOT
            && reread["output_slot_count"] == 431523
            && reread["runtime_profile"] == "solana-v1.6.20"
            && reread["runtime_revision"] == REVISION20
            && reread["runtime_admission"] == "candidate"
            && reread["worker_executable_sha256"] == WORKER20
            && reread["canonical_checksum_sidecar_absent"] == true
            && reread["qualification_scope"]["known_root_prefix_reread"] == true
            && reread["qualification_scope"]["terminal_canonical_root_independently_known"] == true,
        "wrong independent prefix reread"
    );
    for field in [
        "canonical_prefix_qualified",
        "complete_epoch_span_covered",
        "full_cold_epoch_peak_qualified",
        "native_restart_qualified",
        "assembly_qualified",
        "runtime_promotion_authorized",
        "canonical_sidecar_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(
            reread["qualification_scope"][field] == false,
            "unexpected reread {field} authority"
        );
    }
    ensure!(
        tail_proof["schema"] == "jetstreamer-epoch223-native25-exact-historical-input-v1"
            && tail_proof["epoch"] == 223
            && tail_proof["bootstrap"] == serde_json::to_value(&tail.bootstrap)?
            && tail_proof["terminal"] == serde_json::to_value(&tail.terminal)?
            && tail_proof["snapshot_sha256"] == TAIL_SNAPSHOT
            && tail_proof["archive_sha256"] == TAIL_ARCHIVE
            && tail_proof["worker_sha256"] == WORKER25
            && tail_proof["runtime_revision"] == REVISION25
            && tail_proof["independent_tail_reread_passed"] == true
            && tail_proof["preserved_rounded_summary_authoritative_for_tuple"] == false
            && tail_proof["initialized_next_write_version"] == 107266983592u64
            && tail_proof["ticks_per_slot"] == 64,
        "missing exact corrected native25 input"
    );
    for field in [
        "handoff_qualified",
        "canonical_prefix_qualified",
        "assembly_authorized",
        "repair_closed",
        "publication_authorized",
        "runtime_promotion_authorized",
        "r2_mutations",
        "remote_mutations",
    ] {
        ensure!(
            tail_proof[field] == false,
            "unexpected tail {field} authority"
        );
    }
    let journal = raw_terminal(journal, &prefix.terminal)?;
    let mappings:Vec<_>=v3.runtime_segments.iter().map(|s|json!({"slot_start":s.slot_start,"slot_count":s.slot_count,
        "runtime_profile":s.runtime_profile,"runtime_revision":s.runtime_revision,"generation_profile":s.generation_profile,
        "worker_sha256":s.worker_executable_sha256.as_ref().map(sha256_hex_string),
        "worker_start":s.write_versions.worker_start,"worker_end_exclusive":s.write_versions.worker_end_exclusive,
        "archive_start":s.write_versions.archive_start,"archive_end_exclusive":s.write_versions.archive_end_exclusive()})).collect();
    Ok(
        json!({"schema":"jetstreamer-epoch223-cross-runtime-handoff-plan-v1","epoch":223,
        "consensus_tuple_equal":true,"planned_provenance_version":3,"planned_slot_start":START,"planned_slot_count":432000,
        "planned_mappings":mappings,"prefix_terminal":prefix.terminal,"native25_bootstrap":tail.bootstrap,
        "prefix_archive_sha256":sha256_hex_string(&prefix.archive_sha256),"tail_archive_sha256":TAIL_ARCHIVE,
        "prefix_manifest_content_sha256":sha256_hex_string(&prefix.content_sha256()?),
        "tail_manifest_content_sha256":sha256_hex_string(&tail.content_sha256()?),
        "successor_snapshot_sha256":TAIL_SNAPSHOT,"native25_bootstrap_write_count":0,"terminal_journal":journal,
        "raw_cursors_compared_for_equality":false,"metadata_only":true,"archive_scan_performed":false,
        "all_event_contiguity_verified":false,"no_event_loss_proven":false,"cursor_normalization_performed":false,
        "assembly_performed":false,"assembly_authorized":false,"handoff_qualified":false,
        "complete_epoch_span_covered":false,"runtime_promotion_authorized":false,"canonical_sidecar_authorized":false,
        "publication_authorized":false,"repair_closed":false,"replay_launch_authorized":false,"remote_mutations":false,"r2_mutations":false,
        "required_next_step":"Fresh admitted private V3 merge_runtime_segments: bind opened source digests and terminal hashes, decode all slots/events, check PoH and every contiguous raw write, normalize with these checked maps, validate output. Then independent full/plugin/boundary and upload gates."}),
    )
}

pub(super) struct Prepared {
    pub(super) prefix: HistoricalSegmentManifest,
    pub(super) tail: HistoricalSegmentManifest,
    pub(super) receipt: Value,
}

pub(super) fn prepare(plan: &Plan) -> Result<Prepared> {
    ensure!(
        plan.schema == "jetstreamer-epoch223-handoff-plan-request-v1",
        "wrong plan schema"
    );
    let manifest_raw = read(&plan.prefix_manifest)?;
    let prefix: HistoricalSegmentManifest = serde_json::from_slice(&manifest_raw)?;
    let completion: Value = serde_json::from_slice(&read(&plan.prefix_completion)?)?;
    ensure!(
        completion["producer_segment_manifest_sha256"] == evidence::sha(&manifest_raw),
        "producer receipt does not bind these exact manifest bytes"
    );
    let reread: Value = serde_json::from_slice(&read(&plan.prefix_reread)?)?;
    let journal = read(&plan.prefix_terminal_journal)?;
    let fixed = |(path, sha): (&str, &str), immutable| -> Result<Value> {
        Ok(serde_json::from_slice(&evidence::bound_file(
            Path::new(path),
            sha,
            4 * 1024 * 1024,
            immutable,
        )?)?)
    };
    let tail: HistoricalSegmentManifest = serde_json::from_value(fixed(TAIL_MANIFEST, true)?)?;
    let mut receipt = inputs(
        &prefix,
        &completion,
        &reread,
        &tail,
        &fixed(TAIL_PROOF, false)?,
        &fixed(LAUNCH, true)?,
        &journal,
    )?;
    receipt["prefix_sources"] = json!({"completion":plan.prefix_completion,"manifest":plan.prefix_manifest,
        "independent_reread":plan.prefix_reread,"terminal_journal":plan.prefix_terminal_journal});
    receipt["fixed_sources"] = json!({"launch":{"path":LAUNCH.0,"sha256":LAUNCH.1},
        "exact_corrected_tail":{"path":TAIL_PROOF.0,"sha256":TAIL_PROOF.1},"tail_manifest":{"path":TAIL_MANIFEST.0,"sha256":TAIL_MANIFEST.1}});
    Ok(Prepared {
        prefix,
        tail,
        receipt,
    })
}

fn run() -> Result<()> {
    ensure!(unsafe { libc::geteuid() } == 0, "root required");
    let args: Vec<_> = env::args().skip(1).collect();
    ensure!(args.len() == 3, "usage: PLAN PLAN_SHA256 SELF_SHA256");
    evidence::bound_file(
        &fs::read_link("/proc/self/exe")?,
        &args[2],
        128 * 1024 * 1024,
        true,
    )?;
    let plan: Plan = serde_json::from_slice(&evidence::bound_file(
        Path::new(&args[0]),
        &args[1],
        65536,
        true,
    )?)?;
    let mut receipt = prepare(&plan)?.receipt;
    receipt["plan"] = json!({"path":args[0],"sha256":args[1]});
    receipt["self_sha256"] = json!(args[2]);
    evidence::write_receipt(&plan.output, &receipt)?;
    println!(
        "{}",
        json!({"status":"metadata-handoff-plan-recorded","output":plan.output,"assembly_authorized":false,"publication_authorized":false})
    );
    Ok(())
}
pub(super) fn entry() {
    if let Err(error) = run() {
        eprintln!("epoch223 handoff plan refused: {error:#}");
        std::process::exit(1)
    }
}

#[cfg(test)]
pub(super) fn test_prepared() -> Prepared {
    let (prefix, tail) = tests::segments();
    Prepared {
        prefix,
        tail,
        receipt: serde_json::json!({"metadata_only":true,"assembly_authorized":false}),
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn segments() -> (HistoricalSegmentManifest, HistoricalSegmentManifest) {
        // Synthetic metadata only. Never written as operational evidence.
        let bootstrap = SegmentCheckpointSummary {
            slot: ROOT,
            bank_hash: "EWtQnBfEHcQ5hASVyH6u3LXT6WLu5MwWML6VKGg4MdxB".into(),
            accounts_hash: "3SdyhqCuei4esVf8imz8A2rPB1z83sAK3KHbtKefJDS7".into(),
            last_blockhash: "GQt4KimbvHnCHhz8qm98dJo91BwNeBakuKCEHYpRvXNM".into(),
            capitalization: 504095069290845150,
            transaction_count: 28219544812,
            tick_height: 6193121472,
            slot_complete: true,
            write_count: 0,
            next_write_version: 107266983592,
        };
        let mut terminal = bootstrap.clone();
        terminal.slot = END;
        terminal.next_write_version = 107268320809;
        let tail = HistoricalSegmentManifest {
            schema_version: 1,
            epoch: 223,
            output_slot_start: ROOT + 1,
            output_slot_count: 477,
            runtime: SegmentRuntimeIdentity {
                generation_profile: "native25-generation".into(),
                runtime_profile: "solana-v1.6.25".into(),
                runtime_admission: SegmentRuntimeAdmission::Candidate,
                runtime_revision: REVISION25.into(),
                runtime_toolchain: "rustc1.51".into(),
                runtime_target: "x86_64-unknown-linux-gnu".into(),
                genesis_hash: GENESIS.into(),
            },
            worker_executable_sha256: sha(WORKER25).unwrap(),
            archive_sha256: sha(TAIL_ARCHIVE).unwrap(),
            bootstrap_archive_sha256: None,
            bootstrap: bootstrap.clone(),
            terminal,
            emitted_raw_write_versions: 107266983592..107268320809,
        };
        let mut prefix = tail.clone();
        prefix.output_slot_start = START;
        prefix.output_slot_count = 431523;
        prefix.bootstrap.slot = 96335538;
        prefix.bootstrap.next_write_version = 1;
        prefix.bootstrap.accounts_hash = "Gavt9cmcj5BFXuZnz44JktRGbM9oxRkJqoWRF8PvMBTE".into();
        prefix.bootstrap.bank_hash = "8LxWwzEvnAvZC6FwgcqFMxeswZD5skZ7zacYhf1eYW1F".into();
        prefix.terminal = bootstrap;
        prefix.terminal.next_write_version = 10000;
        prefix.terminal.write_count = 42;
        prefix.runtime.runtime_profile = "solana-v1.6.20".into();
        prefix.runtime.runtime_revision = REVISION20.into();
        prefix.runtime.generation_profile = "native20-generation".into();
        prefix.worker_executable_sha256 = sha(WORKER20).unwrap();
        prefix.archive_sha256 = [0x11; 32];
        prefix.emitted_raw_write_versions = 100..10000;
        (prefix, tail)
    }
    fn journal(prefix: &HistoricalSegmentManifest) -> Vec<Value> {
        let t = &prefix.terminal;
        vec![
            json!({"MESSAGE":format!("historical checkpoint slot={} bank_hash={} accounts_hash={} last_blockhash={} capitalization={} transactions={} tick_height={} complete=true writes={} next_write_version={}",
            t.slot,t.bank_hash,t.accounts_hash,t.last_blockhash,t.capitalization,t.transaction_count,t.tick_height,t.write_count,t.next_write_version),
            "_SYSTEMD_INVOCATION_ID":IID,"_PID":"9001","__REALTIME_TIMESTAMP":"10"}),
            json!({"MESSAGE":format!("{UNIT}: Deactivated successfully."),"UNIT":UNIT,"INVOCATION_ID":IID,"_PID":"1","__REALTIME_TIMESTAMP":"11"}),
        ]
    }
    fn ndjson(rows: &[Value]) -> Vec<u8> {
        rows.iter()
            .map(|r| format!("{r}\n"))
            .collect::<String>()
            .into_bytes()
    }
    fn receipts(
        prefix: &HistoricalSegmentManifest,
        tail: &HistoricalSegmentManifest,
    ) -> [Value; 4] {
        let authority = json!({"canonical_prefix_independently_qualified":false,"full_cold_epoch_peak_qualified":false,
            "ordinary_replay_authorized":false,"runtime_promotion_authorized":false,"canonical_sidecar_authorized":false,
            "publication_authorized":false,"remote_mutations":false,"r2_mutations":false});
        let completion = json!({"schema":"jetstreamer-private-epoch223-v1620-root-prefix-resource-v1",
            "epoch":223,"unit":UNIT,"invocation_id":IID,"runner_sha256":RUNNER,"node_sha256":NODE20,
            "worker_sha256":WORKER20,"snapshot_sha256":COLD_SNAPSHOT,"plan":{"sha256":RESOURCE_PLAN},
            "success":true,"error":null,"child_return_code":0,"external_signal":0,"natural_parent_completion_required":true,
            "target_slot":ROOT,"terminal_root_slot":ROOT,"producer_canonical_root_prefix_present":true,
            "producer_segment_manifest":prefix,"archive_length":12345,"authority":authority});
        let scope = json!({"known_root_prefix_reread":true,"terminal_canonical_root_independently_known":true,
            "canonical_prefix_qualified":false,"complete_epoch_span_covered":false,"full_cold_epoch_peak_qualified":false,
            "native_restart_qualified":false,"assembly_qualified":false,"runtime_promotion_authorized":false,
            "canonical_sidecar_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false});
        let reread = json!({"schema":"jetstreamer-focused-qualification-artifact-validation-v1","validation":"pass","epoch":223,
            "archive":format!("{PREFIX_ROOT}/output/epoch-223.jet"),"manifest":format!("{PREFIX_ROOT}/output/epoch-223.jet.segment.json"),
            "archive_sha256":sha256_hex_string(&prefix.archive_sha256),"archive_bytes":12345,
            "manifest_content_encoding":SEGMENT_MANIFEST_CONTENT_ENCODING,"manifest_content_sha256":sha256_hex_string(&prefix.content_sha256().unwrap()),
            "bootstrap_slot":96335538,"output_slot_start":START,"terminal_slot":ROOT,"output_slot_count":431523,
            "runtime_profile":"solana-v1.6.20","runtime_revision":REVISION20,"runtime_admission":"candidate",
            "worker_executable_sha256":WORKER20,"canonical_checksum_sidecar_absent":true,"qualification_scope":scope});
        let proof = json!({"schema":"jetstreamer-epoch223-native25-exact-historical-input-v1","epoch":223,
            "bootstrap":tail.bootstrap,"terminal":tail.terminal,"snapshot_sha256":TAIL_SNAPSHOT,"archive_sha256":TAIL_ARCHIVE,
            "worker_sha256":WORKER25,"runtime_revision":REVISION25,"independent_tail_reread_passed":true,
            "preserved_rounded_summary_authoritative_for_tuple":false,"initialized_next_write_version":107266983592u64,"ticks_per_slot":64,
            "handoff_qualified":false,"canonical_prefix_qualified":false,"assembly_authorized":false,"repair_closed":false,
            "publication_authorized":false,"runtime_promotion_authorized":false,"r2_mutations":false,"remote_mutations":false});
        let launch = json!({"schema":"jetstreamer-private-epoch223-native20-prefix-launch-v1","launched":true,
            "evidence":{"units":[{"unit":UNIT,"invocation_id":IID}]},"worker_sha256":WORKER20,
            "resource_plan":{"sha256":RESOURCE_PLAN},"private_run_root":PREFIX_ROOT});
        [completion, reread, proof, launch]
    }
    fn gate(
        prefix: &HistoricalSegmentManifest,
        tail: &HistoricalSegmentManifest,
        receipts: &[Value; 4],
        rows: &[Value],
    ) -> Result<Value> {
        inputs(
            prefix,
            &receipts[0],
            &receipts[1],
            tail,
            &receipts[2],
            &receipts[3],
            &ndjson(rows),
        )
    }

    #[test]
    fn mixed_runtime_uses_v3_and_preserves_independent_raw_cursors() {
        let (prefix, tail) = segments();
        let v3 = provenance(&prefix, &tail).unwrap();
        assert_ne!(
            prefix.terminal.next_write_version,
            tail.bootstrap.next_write_version
        );
        assert!(ArchiveProvenanceV4 { base: v3.clone() }.validate().is_err());
        let first = v3.runtime_segments[0].write_versions;
        let second = v3.runtime_segments[1].write_versions;
        assert_eq!(first.archive_end_exclusive(), Some(9900));
        assert_eq!(second.archive_start, 9900);
        assert_eq!(second.normalize(107266983591), None);
        assert_eq!(second.normalize(107266983592), Some(9900));
        assert_eq!(second.normalize(107268320808), Some(1347116));
        assert_eq!(second.normalize(107268320809), None);
        assert_eq!(second.archive_end_exclusive(), Some(1347117));
    }
    #[test]
    fn no_early_assembly_or_event_loss_claim_from_metadata() {
        let (prefix, tail) = segments();
        let result = gate(&prefix, &tail, &receipts(&prefix, &tail), &journal(&prefix)).unwrap();
        assert_eq!(result["consensus_tuple_equal"], true);
        assert_eq!(result["planned_slot_count"], 432000);
        assert_eq!(
            result["prefix_terminal"]["capitalization"].as_u64(),
            Some(504095069290845150)
        );
        for field in [
            "assembly_performed",
            "assembly_authorized",
            "all_event_contiguity_verified",
            "no_event_loss_proven",
            "cursor_normalization_performed",
            "handoff_qualified",
            "publication_authorized",
            "repair_closed",
            "runtime_promotion_authorized",
            "archive_scan_performed",
            "remote_mutations",
            "r2_mutations",
        ] {
            assert_eq!(result[field], false, "{field}");
        }
    }
    #[test]
    fn reject_every_consensus_mismatch_including_rounded_capitalization() {
        let (prefix, tail) = segments();
        for change in 0..9 {
            let mut bad = prefix.clone();
            match change {
                0 => bad.terminal.slot -= 1,
                1 => bad.terminal.bank_hash = GENESIS.into(),
                2 => bad.terminal.accounts_hash = GENESIS.into(),
                3 => bad.terminal.last_blockhash = GENESIS.into(),
                4 => bad.terminal.capitalization = 504095069290845100,
                5 => bad.terminal.transaction_count += 1,
                6 => bad.terminal.tick_height += 1,
                7 => bad.terminal.slot_complete = false,
                _ => bad.output_slot_count -= 1,
            }
            assert!(provenance(&bad, &tail).is_err(), "{change}");
        }
        let mut bad = tail.clone();
        bad.bootstrap.write_count = 1;
        assert!(provenance(&prefix, &bad).is_err());
    }
    #[test]
    fn reject_gap_overlap_inversion_overflow_and_wrong_worker_scope() {
        let (prefix, tail) = segments();
        for change in 0..7 {
            let mut p = prefix.clone();
            let mut t = tail.clone();
            match change {
                0 => t.output_slot_start += 1,
                1 => t.output_slot_start -= 1,
                2 => p.emitted_raw_write_versions = 10001..10000,
                3 => {
                    p.bootstrap.next_write_version = 0;
                    p.terminal.next_write_version = u64::MAX - 1;
                    p.emitted_raw_write_versions = 0..u64::MAX - 1;
                }
                4 => p.worker_executable_sha256 = sha(WORKER25).unwrap(),
                5 => t.runtime.runtime_revision = REVISION20.into(),
                _ => t.terminal.next_write_version += 1,
            }
            assert!(provenance(&p, &t).is_err(), "{change}");
        }
    }
    #[test]
    fn completion_reread_and_corrected_tail_proof_are_all_mandatory() {
        let (prefix, tail) = segments();
        for (index, pointer, value) in [
            (0, "/success", json!(false)),
            (0, "/child_return_code", json!(1)),
            (0, "/invocation_id", json!("foreign")),
            (
                0,
                "/producer_segment_manifest/terminal/capitalization",
                json!(0),
            ),
            (1, "/manifest_content_sha256", json!("0".repeat(64))),
            (1, "/archive_sha256", json!(TAIL_ARCHIVE)),
            (
                1,
                "/qualification_scope/known_root_prefix_reread",
                json!(false),
            ),
            (1, "/worker_executable_sha256", json!(WORKER25)),
            (
                2,
                "/preserved_rounded_summary_authoritative_for_tuple",
                json!(true),
            ),
            (2, "/handoff_qualified", json!(true)),
            (2, "/bootstrap/capitalization", json!(504095069290845100u64)),
            (3, "/evidence/units/0/invocation_id", json!("foreign")),
        ] {
            let mut r = receipts(&prefix, &tail);
            *r[index].pointer_mut(pointer).unwrap() = value;
            assert!(
                gate(&prefix, &tail, &r, &journal(&prefix)).is_err(),
                "{pointer}"
            );
        }
        for i in 0..4 {
            let mut r = receipts(&prefix, &tail);
            r[i] = json!({});
            assert!(gate(&prefix, &tail, &r, &journal(&prefix)).is_err());
        }
    }
    #[test]
    fn original_terminal_tuple_and_manager_success_cannot_be_substituted_or_duplicated() {
        let (prefix, tail) = segments();
        let r = receipts(&prefix, &tail);
        for i in 0..2 {
            let mut rows = journal(&prefix);
            rows.push(rows[i].clone());
            assert!(gate(&prefix, &tail, &r, &rows).is_err());
            let mut rows = journal(&prefix);
            rows.remove(i);
            assert!(gate(&prefix, &tail, &r, &rows).is_err());
            let mut rows = journal(&prefix);
            rows[i]["_PID"] = json!("0");
            assert!(gate(&prefix, &tail, &r, &rows).is_err());
        }
        let mut rows = journal(&prefix);
        rows[0]["_SYSTEMD_INVOCATION_ID"] = json!("foreign");
        assert!(gate(&prefix, &tail, &r, &rows).is_err());
        let mut rows = journal(&prefix);
        rows[1]["__REALTIME_TIMESTAMP"] = json!("9");
        assert!(gate(&prefix, &tail, &r, &rows).is_err());
        let mut rows = journal(&prefix);
        rows[0]["MESSAGE"] = json!(
            rows[0]["MESSAGE"]
                .as_str()
                .unwrap()
                .replace("504095069290845150", "504095069290845100")
        );
        assert!(gate(&prefix, &tail, &r, &rows).is_err());
    }
}
