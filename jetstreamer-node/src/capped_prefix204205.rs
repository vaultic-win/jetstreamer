//! Closed metadata/native-barrier/V4 adapters for the original capped 204/205
//! prefixes. No Bank initialization, replay dispatch, file lifecycle, resource
//! admission, sidecar or publication authority is provided by this library.
use crate::segment_manifest::{
    HistoricalSegmentManifest, SEGMENT_MANIFEST_CONTENT_ENCODING, SegmentCheckpointSummary,
    SegmentRuntimeAdmission, sha256_hex_string,
};
use anyhow::{Context, Result, ensure};
use jetstreamer_horizon::archive::{
    AccountsHashKind, ArchiveProvenanceV3, ArchiveProvenanceV4, ArchiveWriterConfig,
    BootstrapStateKind, MultiSegmentMergeStats, RuntimeAdmission, RuntimeHandoffProvenance,
    RuntimeSegmentProvenance, RuntimeSegmentSource, RuntimeStateCheckpoint, StateCommitment,
    StateCommitmentKind, TransactionMetadataPolicy, WriteVersionNormalization,
    merge_checkpoint_restart_segments,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    io::{Read, Seek, Write},
    path::Path,
};

pub const WORKER_SHA256: &str = "4aeca56378a4bb2c55d0e590c1e334c4afa6a375a2c0d94894b412bea261f1cc";
pub const NODE_SHA256: &str = "025757b9b337abf05435c427f143f590d9bfa542b5e4493aae783c158b4f2d3d";
pub const GENESIS_SHA256: &str = "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945";
pub const PREFIX_GENERATION: &str =
    "jetstreamer-node/0.7.0/old-faithful-to-horizon-v2@3de96e71010a8a2f5e629f666227b137483bff7b";
pub const REVISION: &str = "86c26f843276581509c3434acc2efbf4202c44e0";

#[derive(Clone, Copy, Debug)]
pub struct Profile {
    pub epoch: u64,
    pub original_unit: &'static str,
    pub original_invocation: &'static str,
    pub original_pid: u64,
    pub original_root: &'static str,
    pub launch_path: &'static str,
    pub launch_sha256: &'static str,
    pub runner_sha256: &'static str,
    pub resource_plan_sha256: &'static str,
    pub bootstrap: u64,
    pub bootstrap_accounts: &'static str,
    pub bootstrap_snapshot_sha256: &'static str,
    pub start: u64,
    pub restart: u64,
    pub restart_accounts: &'static str,
    pub end: u64,
    pub snapshot_path: &'static str,
    pub snapshot_sha256: &'static str,
    pub snapshot_bytes: u64,
}

const PROFILES: [Profile; 2] = [
    Profile {
        epoch: 204,
        original_unit: "horizon-qualify-204-shrink-root-prefix-resource-fcbf3992-v1.service",
        original_invocation: "448da7f2a3a34217afe7e115120b3cea",
        original_pid: 3_822_861,
        original_root: "/home/ubuntu/.jetstreamer-private/shrink-root-prefix-resource-204-fcbf3992-v1",
        launch_path: "/var/lib/jetstreamer/horizon-prefix204-launch-fcbf3992-v1/launch.json",
        launch_sha256: "a1b38f09bb1314c9280ca924602bab1523d28755146919912f604c1ee9bbfdfb",
        runner_sha256: "1cd9bfe3418616add2319802adc4caf66b86e3f6fdf6c903c4be2648b10c0baa",
        resource_plan_sha256: "cc5109ed54c4b5cdc7db99a7e839708753b677cee11b7ca867c30e7a198911ba",
        bootstrap: 88_127_580,
        bootstrap_accounts: "4SeHmKHQrHot4gwifo1bnvDKXZwGELk2vSenotTx9oqf",
        bootstrap_snapshot_sha256: "d3114597ce25c3efaa4a96899ab3e9437c51cb9086d4166639f0ad2ae0613ee6",
        start: 88_128_000,
        restart: 88_559_361,
        restart_accounts: "83H83cZe1j8pnukHcZiXxKRyvCNUAZjcR43Wv9aQtnYA",
        end: 88_559_999,
        snapshot_path: "/var/lib/jetstreamer/horizon-focused-205-store8-3de96e7-v1/snapshot-88559361-83H83cZe1j8pnukHcZiXxKRyvCNUAZjcR43Wv9aQtnYA.tar.zst",
        snapshot_sha256: "24b722b37fa87462876dc05916bafa98da13f095c95aaed7159e9008efa7352e",
        snapshot_bytes: 8_225_957_010,
    },
    Profile {
        epoch: 205,
        original_unit: "horizon-qualify-205-shrink-root-prefix-resource-5c01bf93-v1.service",
        original_invocation: "373359a11aef4993a1a949e19ff617c3",
        original_pid: 3_730_044,
        original_root: "/home/ubuntu/.jetstreamer-private/shrink-root-prefix-resource-205-5c01bf93-v1",
        launch_path: "/var/lib/jetstreamer/horizon-prefix205-launch-5c01bf93-v1/launch.json",
        launch_sha256: "febbbb44b1d2b16afc3511e171dbb1f1aab732890893be1ce2f72239bc01ca9e",
        runner_sha256: "fb41a1193c86749db27ef609f487a25de334a7e58b3440093288aecc75ae4801",
        resource_plan_sha256: "7dd71710d60017224fd1f6fabd97f228642b687802da98a11f8927aea67b6485",
        bootstrap: 88_559_361,
        bootstrap_accounts: "83H83cZe1j8pnukHcZiXxKRyvCNUAZjcR43Wv9aQtnYA",
        bootstrap_snapshot_sha256: "24b722b37fa87462876dc05916bafa98da13f095c95aaed7159e9008efa7352e",
        start: 88_560_000,
        restart: 88_991_050,
        restart_accounts: "BAsq3Vn4KyLYuLqrevCL2dnE1fjLyA6NSX9qQjG7VCDp",
        end: 88_991_999,
        snapshot_path: "/var/lib/jetstreamer/horizon-terminal205-input-e94ae66-v1/snapshot-88991050-BAsq3Vn4KyLYuLqrevCL2dnE1fjLyA6NSX9qQjG7VCDp.tar.zst",
        snapshot_sha256: "1b2a41f022847dc2ba9609e5a13aadc0e79b213b5245166b06954bf8c6d9042f",
        snapshot_bytes: 8_407_269_066,
    },
];

pub fn profile(epoch: u64) -> Result<Profile> {
    PROFILES
        .into_iter()
        .find(|p| p.epoch == epoch)
        .context("only exact capped 204/205 profiles are supported")
}

impl Profile {
    pub fn prefix_path(self) -> std::path::PathBuf {
        Path::new(self.original_root).join(format!("output/epoch-{}-prefix.jet", self.epoch))
    }
    pub fn prefix_manifest_path(self) -> std::path::PathBuf {
        self.prefix_path()
            .with_file_name(format!("epoch-{}-prefix.jet.segment.json", self.epoch))
    }
}

pub fn hex_sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub fn parse_sha(value: &str) -> Result<[u8; 32]> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "noncanonical SHA-256"
    );
    let mut result = [0; 32];
    for (index, byte) in result.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)?;
    }
    Ok(result)
}

/// Preserved small primary inputs. No asserted old native-probe result is used.
pub struct MetadataInputs<'a> {
    pub launch: &'a [u8],
    pub producer_result: &'a [u8],
    pub terminal_properties: &'a [u8],
    pub manager_journal: &'a [u8],
    pub prefix_manifest: &'a [u8],
    pub prefix_validation: &'a [u8],
}

/// Qualified metadata, not resource/ownership or execution authority. No
/// Deserialize: callers must reauthenticate the original captured inputs.
#[derive(Debug, Serialize)]
pub struct InputPolicy {
    schema: &'static str,
    epoch: u64,
    original_unit: &'static str,
    original_invocation_id: &'static str,
    original_launch_sha256: &'static str,
    producer_result_sha256: String,
    terminal_properties_sha256: String,
    manager_journal_sha256: String,
    prefix_manifest_sha256: String,
    prefix_validation_sha256: String,
    prefix_manifest: HistoricalSegmentManifest,
    restart_snapshot: SnapshotBinding,
    missing_suffix_slots: u64,
    native_worker_must_rehash_full_snapshot: bool,
    actual_suffix_must_repeat_native_barrier: bool,
    current_source_idleness_proven: bool,
    resource_admission_passed: bool,
    native_initialized: bool,
    suffix_execution_authorized: bool,
    assembly_authorized: bool,
    canonical_sidecar_authorized: bool,
    publication_authorized: bool,
    r2_mutations: bool,
}

#[derive(Debug, Serialize)]
struct SnapshotBinding {
    path: &'static str,
    sha256: &'static str,
    bytes: u64,
    slot: u64,
    accounts_hash: &'static str,
}

fn prefix_scope(p: Profile, m: &HistoricalSegmentManifest) -> Result<()> {
    m.validate()?;
    ensure!(
        m.epoch == p.epoch
            && m.output_slot_start == p.start
            && m.output_slot_count == p.restart - p.start + 1
            && m.bootstrap.slot == p.bootstrap
            && m.bootstrap.accounts_hash == p.bootstrap_accounts
            && m.bootstrap.slot_complete
            && m.bootstrap.write_count == 0
            && m.bootstrap_archive_sha256.is_none()
            && m.terminal.slot == p.restart
            && m.terminal.accounts_hash == p.restart_accounts
            && m.terminal.slot_complete
            && m.worker_executable_sha256 == parse_sha(WORKER_SHA256)?
            && m.archive_sha256 != [0; 32]
            && m.runtime.generation_profile == PREFIX_GENERATION
            && m.runtime.runtime_profile == "solana-v1.6.16"
            && m.runtime.runtime_revision == REVISION
            && m.runtime.runtime_admission == SegmentRuntimeAdmission::Candidate
            && m.runtime.genesis_hash == jetstreamer_historical_protocol::MAINNET_GENESIS_HASH,
        "not the exact original capped prefix scope/runtime"
    );
    Ok(())
}

fn validate_launch(p: Profile, launch: &Value) -> Result<()> {
    ensure!(
        launch["schema"]
            == format!(
                "jetstreamer-private-epoch{}-capped-root-prefix-launch-v1",
                p.epoch
            )
            && launch["epoch"] == p.epoch
            && launch["launched"] == true
            && launch["private_run_root"] == p.original_root
            && launch["node_sha256"] == NODE_SHA256
            && launch["worker_sha256"] == WORKER_SHA256
            && launch["runner_sha256"] == p.runner_sha256
            && launch["plan_sha256"] == p.resource_plan_sha256
            && launch["snapshot_sha256"] == p.bootstrap_snapshot_sha256
            && launch["bootstrap_slot"] == p.bootstrap
            && launch["output_slot_start"] == p.start
            && launch["output_slot_count"] == p.restart - p.start + 1
            && launch["terminal_root_slot"] == p.restart
            && launch["natural_parent_completion_required"] == true,
        "original launch scope differs"
    );
    let units = launch["evidence"]["units"]
        .as_array()
        .context("launch units")?;
    ensure!(
        units.len() == 1
            && units[0]["unit"] == p.original_unit
            && units[0]["invocation_id"] == p.original_invocation
            && units[0]["main_pid"] == p.original_pid
            && units[0]["restarts"] == 0,
        "original launch identity differs"
    );
    Ok(())
}

fn validate_outcome(
    p: Profile,
    result: &Value,
    m: &HistoricalSegmentManifest,
    manifest_sha: &str,
) -> Result<()> {
    ensure!(
        result["schema"]
            == format!(
                "jetstreamer-private-epoch{}-shrink-root-prefix-resource-v1",
                p.epoch
            )
            && result["epoch"] == p.epoch
            && result["unit"] == p.original_unit
            && result["invocation_id"] == p.original_invocation
            && result["runner_sha256"] == p.runner_sha256
            && result["node_sha256"] == NODE_SHA256
            && result["worker_sha256"] == WORKER_SHA256
            && result["plan"]["sha256"] == p.resource_plan_sha256
            && result["snapshot_sha256"] == p.bootstrap_snapshot_sha256
            && result["success"] == true
            && result["error"].is_null()
            && result["natural_parent_completion_required"] == true
            && result["child_return_code"] == 0
            && result["external_signal"] == 0
            && result["target_slot"] == p.restart
            && result["terminal_root_slot"] == p.restart
            && result["producer_canonical_root_prefix_present"] == true
            && result["archive_length"].as_u64().is_some_and(|n| n > 0)
            && result["producer_segment_manifest_sha256"] == manifest_sha
            && serde_json::from_value::<HistoricalSegmentManifest>(
                result["producer_segment_manifest"].clone()
            )? == *m,
        "needs original natural-success runner output and exact typed manifest"
    );
    for flag in [
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
            result["authority"][flag] == false,
            "producer result preclaims authority: {flag}"
        );
    }
    Ok(())
}

fn command_identity(value: &str) -> Option<&str> {
    let (identity, metadata) = value.split_once(" ; start_time=")?;
    let fields = metadata
        .strip_suffix(" }")?
        .split(" ; ")
        .collect::<Vec<_>>();
    (identity.starts_with("{ path=")
        && identity.matches(" ; argv[]=").count() == 1
        && identity.ends_with(" ; ignore_errors=no")
        && value.matches(" ; start_time=").count() == 1
        && fields.len() == 5
        && fields[0].starts_with('[')
        && fields[0].ends_with(']')
        && fields[1].starts_with("stop_time=[")
        && fields[1].ends_with(']')
        && fields[2]
            .strip_prefix("pid=")
            .is_some_and(|s| s.parse::<u64>().is_ok())
        && fields[3].starts_with("code=")
        && fields[4].starts_with("status="))
    .then_some(identity)
}

fn terminal_properties(p: Profile, launch: &Value, value: &Value) -> Result<()> {
    for (key, expected) in [
        ("Id", p.original_unit),
        ("ActiveState", "inactive"),
        ("SubState", "dead"),
        ("MainPID", "0"),
        ("NRestarts", "0"),
        ("Triggers", ""),
        ("TriggeredBy", ""),
    ] {
        ensure!(
            value[key] == expected,
            "terminal owner property differs: {key}"
        );
    }
    if value["LoadState"] == "not-found" {
        ensure!(
            value["InvocationID"] == "" && value["ExecStart"] == "",
            "collected owner retains identity or commands"
        );
    } else {
        ensure!(
            value["LoadState"] == "loaded"
                && value["Result"] == "success"
                && value["ExecMainCode"] == "1"
                && value["ExecMainStatus"] == "0"
                && value["Restart"] == "no"
                && value["ExecMainPID"]
                    .as_str()
                    .and_then(|pid| pid.parse::<u64>().ok())
                    == Some(p.original_pid)
                && launch["expected_exec_start"]
                    .as_str()
                    .and_then(command_identity)
                    .zip(value["ExecStart"].as_str().and_then(command_identity))
                    .is_some_and(|(a, b)| a == b)
                && value["InvocationID"]
                    .as_str()
                    .is_some_and(|s| s.is_empty() || s == p.original_invocation),
            "owner is live, restarted, replaced or not naturally exited"
        );
    }
    Ok(())
}

#[derive(Deserialize)]
struct ManagerRecord {
    #[serde(rename = "_PID")]
    pid: String,
    #[serde(rename = "_UID")]
    uid: String,
    #[serde(rename = "UNIT")]
    unit: String,
    #[serde(rename = "INVOCATION_ID")]
    invocation: Option<String>,
    #[serde(rename = "_BOOT_ID")]
    boot: String,
    #[serde(rename = "__REALTIME_TIMESTAMP")]
    timestamp: String,
    #[serde(rename = "__CURSOR")]
    cursor: String,
    #[serde(rename = "MESSAGE_ID")]
    message_id: Option<String>,
    #[serde(rename = "MESSAGE")]
    message: String,
    #[serde(rename = "EXIT_STATUS")]
    exit_status: Option<String>,
}

fn manager_proof(p: Profile, bytes: &[u8]) -> Result<()> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= 4 << 20,
        "manager journal bound"
    );
    let mut rows = Vec::new();
    let mut cursors = BTreeSet::new();
    let mut previous = 0;
    for line in std::str::from_utf8(bytes)?.lines() {
        let r: ManagerRecord = serde_json::from_str(line)?;
        let time = r.timestamp.parse::<u64>()?;
        ensure!(
            r.pid == "1"
                && r.uid == "0"
                && r.unit == p.original_unit
                && time > 0
                && time >= previous
                && !r.cursor.is_empty()
                && cursors.insert(r.cursor.clone())
                && r.boot.len() == 32
                && r.boot
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "manager source identity/clock/cursor differs"
        );
        previous = time;
        rows.push((time, r));
        ensure!(rows.len() <= 16384, "manager record bound");
    }
    let start = rows
        .iter()
        .filter(|(_, r)| {
            r.invocation.as_deref() == Some(p.original_invocation)
                && r.message_id.as_deref() == Some("39f53479d3a045ac8e11786248231fbf")
                && r.message
                    .starts_with(&format!("Started {} -", p.original_unit))
        })
        .collect::<Vec<_>>();
    let end = rows
        .iter()
        .filter(|(_, r)| {
            r.invocation.as_deref() == Some(p.original_invocation)
                && r.message_id.as_deref() == Some("7ad2d189f7e94e70a38c781354912448")
                && r.message == format!("{}: Deactivated successfully.", p.original_unit)
        })
        .collect::<Vec<_>>();
    ensure!(
        start.len() == 1 && end.len() == 1 && end[0].0 > start[0].0,
        "missing exact original PID1 start/terminal success"
    );
    for (time, row) in &rows {
        if *time < start[0].0 {
            continue;
        }
        ensure!(
            row.invocation.as_deref() == Some(p.original_invocation)
                && row.boot == start[0].1.boot
                && !["Stopping ", "Stopped "]
                    .iter()
                    .any(|s| row.message.starts_with(s))
                && ![": Failed", ": Killing"]
                    .iter()
                    .any(|s| row.message.contains(s))
                && row.exit_status.as_deref().is_none_or(|s| s == "0"),
            "manager indicates stop/failure/replacement"
        );
    }
    Ok(())
}

fn validate_reader(
    p: Profile,
    m: &HistoricalSegmentManifest,
    outcome: &Value,
    pass: &Value,
) -> Result<()> {
    ensure!(
        pass["schema"] == "jetstreamer-focused-qualification-artifact-validation-v1"
            && pass["validation"] == "pass"
            && pass["epoch"] == p.epoch
            && pass["archive"].as_str() == p.prefix_path().to_str()
            && pass["manifest"].as_str() == p.prefix_manifest_path().to_str()
            && pass["archive_sha256"] == sha256_hex_string(&m.archive_sha256)
            && pass["archive_bytes"] == outcome["archive_length"]
            && pass["manifest_content_encoding"] == SEGMENT_MANIFEST_CONTENT_ENCODING
            && pass["manifest_content_sha256"] == sha256_hex_string(&m.content_sha256()?)
            && pass["output_slot_start"] == p.start
            && pass["output_slot_count"] == p.restart - p.start + 1
            && pass["bootstrap_slot"] == p.bootstrap
            && pass["terminal_slot"] == p.restart
            && pass["worker_executable_sha256"] == WORKER_SHA256
            && pass["runtime_profile"] == m.runtime.runtime_profile
            && pass["runtime_revision"] == REVISION
            && pass["runtime_admission"] == "candidate"
            && pass["canonical_checksum_sidecar_absent"] == true,
        "reader receipt does not bind the exact complete typed prefix manifest"
    );
    Ok(())
}

/// Hash-bound launch plus genuine future terminal and independent-reader bytes.
/// This does not open either archive or initialize any historical worker.
pub fn bind_metadata(epoch: u64, inputs: MetadataInputs<'_>) -> Result<InputPolicy> {
    let p = profile(epoch)?;
    for bytes in [
        inputs.launch,
        inputs.producer_result,
        inputs.terminal_properties,
        inputs.prefix_manifest,
        inputs.prefix_validation,
    ] {
        ensure!(bytes.len() <= 1 << 20, "metadata byte bound");
    }
    ensure!(
        hex_sha(inputs.launch) == p.launch_sha256,
        "original sealed launch bytes differ"
    );
    let launch: Value = serde_json::from_slice(inputs.launch)?;
    let outcome: Value = serde_json::from_slice(inputs.producer_result)?;
    let properties: Value = serde_json::from_slice(inputs.terminal_properties)?;
    let manifest: HistoricalSegmentManifest = serde_json::from_slice(inputs.prefix_manifest)?;
    let reader: Value = serde_json::from_slice(inputs.prefix_validation)?;
    validate_launch(p, &launch)?;
    prefix_scope(p, &manifest)?;
    validate_outcome(p, &outcome, &manifest, &hex_sha(inputs.prefix_manifest))?;
    terminal_properties(p, &launch, &properties)?;
    manager_proof(p, inputs.manager_journal)?;
    validate_reader(p, &manifest, &outcome, &reader)?;
    Ok(policy(p, manifest, &inputs))
}

fn policy(p: Profile, manifest: HistoricalSegmentManifest, i: &MetadataInputs<'_>) -> InputPolicy {
    InputPolicy {
        schema: "jetstreamer-capped204205-native-input-policy-v1",
        epoch: p.epoch,
        original_unit: p.original_unit,
        original_invocation_id: p.original_invocation,
        original_launch_sha256: p.launch_sha256,
        producer_result_sha256: hex_sha(i.producer_result),
        terminal_properties_sha256: hex_sha(i.terminal_properties),
        manager_journal_sha256: hex_sha(i.manager_journal),
        prefix_manifest_sha256: hex_sha(i.prefix_manifest),
        prefix_validation_sha256: hex_sha(i.prefix_validation),
        prefix_manifest: manifest,
        restart_snapshot: SnapshotBinding {
            path: p.snapshot_path,
            sha256: p.snapshot_sha256,
            bytes: p.snapshot_bytes,
            slot: p.restart,
            accounts_hash: p.restart_accounts,
        },
        missing_suffix_slots: p.end - p.restart,
        native_worker_must_rehash_full_snapshot: true,
        actual_suffix_must_repeat_native_barrier: true,
        current_source_idleness_proven: false,
        resource_admission_passed: false,
        native_initialized: false,
        suffix_execution_authorized: false,
        assembly_authorized: false,
        canonical_sidecar_authorized: false,
        publication_authorized: false,
        r2_mutations: false,
    }
}

fn checkpoint(c: &SegmentCheckpointSummary) -> Result<RuntimeStateCheckpoint> {
    Ok(RuntimeStateCheckpoint {
        slot: c.slot,
        bank_hash: c.bank_hash_value()?,
        accounts_hash_kind: AccountsHashKind::LegacyAccountsHash,
        accounts_hash: c.accounts_hash_value()?,
        last_blockhash: c.last_blockhash_value()?,
        capitalization: c.capitalization,
        transaction_count: c.transaction_count,
        tick_height: c.tick_height,
        slot_complete: c.slot_complete,
        next_write_version: c.next_write_version,
    })
}

fn consensus_matches(expected: RuntimeStateCheckpoint, actual: RuntimeStateCheckpoint) -> bool {
    expected.slot == actual.slot
        && expected.bank_hash == actual.bank_hash
        && expected.accounts_hash_kind == actual.accounts_hash_kind
        && expected.accounts_hash == actual.accounts_hash
        && expected.last_blockhash == actual.last_blockhash
        && expected.capitalization == actual.capitalization
        && expected.transaction_count == actual.transaction_count
        && expected.tick_height == actual.tick_height
        && expected.slot_complete
        && actual.slot_complete
}

/// Constructed at the actual executing suffix worker's pre-entry barrier. An
/// old restore-only JSON result cannot deserialize into this proof.
pub struct NativeBarrier<'a> {
    policy: &'a InputPolicy,
    initialized: RuntimeStateCheckpoint,
}

pub struct AssemblyOptions<'a> {
    pub writer: ArchiveWriterConfig,
    pub generation: &'a str,
    pub metadata: TransactionMetadataPolicy,
}

impl InputPolicy {
    /// Invoke using the exact worker's actual initialize/freeze result before
    /// sending any replay entry. Raw native and prefix cursors stay independent.
    pub fn native_barrier(
        &self,
        actual: RuntimeStateCheckpoint,
        bootstrap_writes: u64,
        worker_sha256: [u8; 32],
        initialized_cursor: u64,
        ticks_per_slot: u64,
    ) -> Result<NativeBarrier<'_>> {
        let p = profile(self.epoch)?;
        prefix_scope(p, &self.prefix_manifest)?;
        ensure!(
            worker_sha256 == parse_sha(WORKER_SHA256)?
                && ticks_per_slot == 64
                && bootstrap_writes == 0
                && actual.next_write_version == initialized_cursor
                && consensus_matches(checkpoint(&self.prefix_manifest.terminal)?, actual),
            "actual native checkpoint/worker/kind/cursor/writes/ticks differ before suffix execution"
        );
        Ok(NativeBarrier {
            policy: self,
            initialized: actual,
        })
    }
}

impl NativeBarrier<'_> {
    /// Same-runtime V4 construction uses the qualified 203 normalization and
    /// handoff algorithm with only the closed 638/949-slot suffix scopes.
    pub fn provenance(
        &self,
        suffix: &HistoricalSegmentManifest,
        assembly_generation: &str,
        metadata: TransactionMetadataPolicy,
    ) -> Result<ArchiveProvenanceV4> {
        let p = profile(self.policy.epoch)?;
        let prefix = &self.policy.prefix_manifest;
        prefix_scope(p, prefix)?;
        suffix.validate()?;
        ensure!(
            suffix.epoch == p.epoch
                && suffix.output_slot_start == p.restart + 1
                && suffix.output_slot_count == p.end - p.restart
                && suffix.terminal.slot == p.end
                && suffix.bootstrap_archive_sha256 == Some(parse_sha(p.snapshot_sha256)?)
                && suffix.worker_executable_sha256 == parse_sha(WORKER_SHA256)?
                && suffix.archive_sha256 != [0; 32]
                && suffix.bootstrap.write_count == 0
                && checkpoint(&suffix.bootstrap)? == self.initialized
                && suffix.runtime.runtime_profile == prefix.runtime.runtime_profile
                && suffix.runtime.runtime_revision == prefix.runtime.runtime_revision
                && suffix.runtime.runtime_toolchain == prefix.runtime.runtime_toolchain
                && suffix.runtime.runtime_target == prefix.runtime.runtime_target
                && suffix.runtime.runtime_admission == SegmentRuntimeAdmission::Candidate
                && suffix.runtime.genesis_hash == prefix.runtime.genesis_hash,
            "suffix does not bind this actual native barrier and exact same-worker scope"
        );
        ensure!(
            !assembly_generation.is_empty()
                && assembly_generation.len() <= 1024
                && assembly_generation.bytes().all(|b| b.is_ascii_graphic()),
            "invalid assembly generation"
        );
        let mut next = 0;
        let mut segments = Vec::new();
        for source in [prefix, suffix] {
            let mapping = WriteVersionNormalization {
                worker_start: source.emitted_raw_write_versions.start,
                worker_end_exclusive: source.emitted_raw_write_versions.end,
                archive_start: next,
            };
            next = mapping
                .archive_end_exclusive()
                .context("checked V4 normalization overflow")?;
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
        let provenance = ArchiveProvenanceV4 {
            base: ArchiveProvenanceV3 {
                assembly_profile: format!(
                    "{assembly_generation}/epoch{}-capped-checkpoint-continuation-v1",
                    p.epoch
                ),
                genesis_hash: prefix.runtime.genesis_hash.parse()?,
                bootstrap_state_kind: BootstrapStateKind::SnapshotArchive,
                bootstrap_state: StateCommitment {
                    slot: prefix.bootstrap.slot,
                    kind: StateCommitmentKind::LegacyAccountsHash,
                    hash: prefix.bootstrap.accounts_hash_value()?,
                },
                requested_slot_start: p.start,
                requested_slot_count: p.end - p.start + 1,
                transaction_metadata: metadata,
                runtime_segments: segments,
                handoffs: vec![RuntimeHandoffProvenance {
                    boundary_slot: p.restart + 1,
                    predecessor: checkpoint(&prefix.terminal)?,
                    successor: self.initialized,
                    successor_bootstrap_kind: BootstrapStateKind::SnapshotArchive,
                    successor_bootstrap_archive_sha256: parse_sha(p.snapshot_sha256)?,
                    successor_bootstrap_write_count: 0,
                }],
            },
        };
        provenance.validate()?;
        Ok(provenance)
    }

    /// Reader handles and an independently admitted/guarded sink are supplied by
    /// the future controller. Existing V4 merge validates exact source hashes,
    /// dense coverage, PoH, metadata and raw writes. No file is opened here.
    pub fn assemble<R: Read + Seek, W: Write>(
        &self,
        suffix: &HistoricalSegmentManifest,
        prefix_reader: R,
        suffix_reader: R,
        sink: W,
        options: AssemblyOptions<'_>,
    ) -> Result<(W, MultiSegmentMergeStats)> {
        let provenance = self.provenance(suffix, options.generation, options.metadata)?;
        let prefix = &self.policy.prefix_manifest;
        Ok(merge_checkpoint_restart_segments(
            vec![
                RuntimeSegmentSource::new(
                    prefix_reader,
                    prefix.archive_sha256,
                    prefix.terminal.last_blockhash_value()?,
                ),
                RuntimeSegmentSource::new(
                    suffix_reader,
                    suffix.archive_sha256,
                    suffix.terminal.last_blockhash_value()?,
                ),
            ],
            sink,
            options.writer,
            &provenance,
        )?)
    }
}

#[cfg(test)]
mod tests {
    // Synthetic metadata and in-memory archives only. These are not terminal,
    // native, admission or publication receipts for either real producer.
    use super::*;
    use crate::segment_manifest::SegmentRuntimeIdentity;
    use jetstreamer_horizon::archive::{
        ArchiveProvenance, ArchiveProvenanceV1, ArchiveProvenanceV2, ArchiveReader, ArchiveWriter,
        Compression,
    };
    use serde_json::json;
    use solana_hash::Hash;
    use std::io::Cursor;

    fn summary(slot: u64, accounts: &str, cursor: u64) -> SegmentCheckpointSummary {
        SegmentCheckpointSummary {
            slot,
            bank_hash: Hash::new_from_array([1; 32]).to_string(),
            accounts_hash: accounts.into(),
            last_blockhash: Hash::new_from_array([7; 32]).to_string(),
            capitalization: 9_007_199_254_741_111,
            transaction_count: 123,
            tick_height: slot * 64,
            slot_complete: true,
            write_count: 0,
            next_write_version: cursor,
        }
    }
    fn manifest(p: Profile) -> HistoricalSegmentManifest {
        HistoricalSegmentManifest {
            schema_version: 1,
            epoch: p.epoch,
            output_slot_start: p.start,
            output_slot_count: p.restart - p.start + 1,
            runtime: SegmentRuntimeIdentity {
                generation_profile: PREFIX_GENERATION.into(),
                runtime_profile: "solana-v1.6.16".into(),
                runtime_admission: SegmentRuntimeAdmission::Candidate,
                runtime_revision: REVISION.into(),
                runtime_toolchain: "rustc1.51.0; target=x86_64-unknown-linux-gnu".into(),
                runtime_target: "x86_64-unknown-linux-gnu".into(),
                genesis_hash: jetstreamer_historical_protocol::MAINNET_GENESIS_HASH.into(),
            },
            worker_executable_sha256: parse_sha(WORKER_SHA256).unwrap(),
            archive_sha256: [42; 32],
            bootstrap_archive_sha256: None,
            bootstrap: summary(p.bootstrap, p.bootstrap_accounts, 5),
            terminal: summary(p.restart, p.restart_accounts, 9_007_199_254_741_010),
            emitted_raw_write_versions: 9_007_199_254_741_000..9_007_199_254_741_010,
        }
    }
    fn inputs<'a>() -> MetadataInputs<'a> {
        MetadataInputs {
            launch: b"synthetic fixture",
            producer_result: b"synthetic fixture",
            terminal_properties: b"synthetic fixture",
            manager_journal: b"synthetic fixture",
            prefix_manifest: b"synthetic fixture",
            prefix_validation: b"synthetic fixture",
        }
    }
    fn fixture_policy(p: Profile) -> InputPolicy {
        policy(p, manifest(p), &inputs())
    }
    fn native(m: &HistoricalSegmentManifest, cursor: u64) -> RuntimeStateCheckpoint {
        let mut value = checkpoint(&m.terminal).unwrap();
        value.next_write_version = cursor;
        value
    }
    fn suffix(
        p: Profile,
        prefix: &HistoricalSegmentManifest,
        cursor: u64,
    ) -> HistoricalSegmentManifest {
        let mut value = prefix.clone();
        value.output_slot_start = p.restart + 1;
        value.output_slot_count = p.end - p.restart;
        value.bootstrap = prefix.terminal.clone();
        value.bootstrap.write_count = 0;
        value.bootstrap.next_write_version = cursor;
        value.bootstrap_archive_sha256 = Some(parse_sha(p.snapshot_sha256).unwrap());
        value.terminal = summary(
            p.end,
            &Hash::new_from_array([3; 32]).to_string(),
            cursor + 7,
        );
        value.emitted_raw_write_versions = cursor..cursor + 7;
        value.runtime.generation_profile = "new-private-suffix-generation".into();
        value.archive_sha256 = [43; 32];
        value
    }
    fn launch(p: Profile) -> Value {
        json!({"schema":format!("jetstreamer-private-epoch{}-capped-root-prefix-launch-v1",p.epoch),"epoch":p.epoch,
            "launched":true,"private_run_root":p.original_root,"node_sha256":NODE_SHA256,"worker_sha256":WORKER_SHA256,
            "runner_sha256":p.runner_sha256,"plan_sha256":p.resource_plan_sha256,"snapshot_sha256":p.bootstrap_snapshot_sha256,
            "bootstrap_slot":p.bootstrap,"output_slot_start":p.start,"output_slot_count":p.restart-p.start+1,
            "terminal_root_slot":p.restart,"natural_parent_completion_required":true,
            "expected_exec_start":"{ path=/fixture/runner ; argv[]=/fixture/runner /fixture/plan --plan-sha256 fixture --self-sha256 fixture ; ignore_errors=no ; start_time=[fixture] ; stop_time=[n/a] ; pid=123 ; code=(null) ; status=0/0 }",
            "evidence":{"units":[{"unit":p.original_unit,"invocation_id":p.original_invocation,"main_pid":p.original_pid,"restarts":0}]}})
    }
    fn outcome(p: Profile, m: &HistoricalSegmentManifest) -> Value {
        json!({"schema":format!("jetstreamer-private-epoch{}-shrink-root-prefix-resource-v1",p.epoch),"epoch":p.epoch,
            "unit":p.original_unit,"invocation_id":p.original_invocation,"runner_sha256":p.runner_sha256,
            "node_sha256":NODE_SHA256,"worker_sha256":WORKER_SHA256,"plan":{"sha256":p.resource_plan_sha256},
            "snapshot_sha256":p.bootstrap_snapshot_sha256,"success":true,"error":null,"natural_parent_completion_required":true,
            "child_return_code":0,"external_signal":0,"target_slot":p.restart,"terminal_root_slot":p.restart,
            "producer_canonical_root_prefix_present":true,"archive_length":123456,"producer_segment_manifest":m,
            "producer_segment_manifest_sha256":hex_sha(&serde_json::to_vec(m).unwrap()),
            "authority":{"canonical_prefix_independently_qualified":false,"full_cold_epoch_peak_qualified":false,
                "ordinary_replay_authorized":false,"runtime_promotion_authorized":false,"canonical_sidecar_authorized":false,
                "publication_authorized":false,"remote_mutations":false,"r2_mutations":false}})
    }
    fn reader(p: Profile, m: &HistoricalSegmentManifest) -> Value {
        json!({"schema":"jetstreamer-focused-qualification-artifact-validation-v1","validation":"pass","epoch":p.epoch,
            "archive":p.prefix_path(),"manifest":p.prefix_manifest_path(),"archive_sha256":sha256_hex_string(&m.archive_sha256),
            "archive_bytes":123456,"manifest_content_encoding":SEGMENT_MANIFEST_CONTENT_ENCODING,
            "manifest_content_sha256":sha256_hex_string(&m.content_sha256().unwrap()),"output_slot_start":p.start,
            "output_slot_count":p.restart-p.start+1,"bootstrap_slot":p.bootstrap,"terminal_slot":p.restart,
            "worker_executable_sha256":WORKER_SHA256,"runtime_profile":"solana-v1.6.16","runtime_revision":REVISION,
            "runtime_admission":"candidate","canonical_checksum_sidecar_absent":true})
    }
    fn properties(p: Profile, l: &Value) -> Value {
        json!({"Id":p.original_unit,"LoadState":"loaded","ActiveState":"inactive","SubState":"dead","MainPID":"0",
            "NRestarts":"0","Triggers":"","TriggeredBy":"","Result":"success","ExecMainCode":"1","ExecMainStatus":"0",
            "ExecMainPID":p.original_pid.to_string(),"Restart":"no","InvocationID":p.original_invocation,"ExecStart":l["expected_exec_start"]})
    }
    fn manager(p: Profile) -> Vec<Value> {
        vec![
            json!({"_PID":"1","_UID":"0","UNIT":p.original_unit,"INVOCATION_ID":p.original_invocation,
            "_BOOT_ID":"2".repeat(32),"__REALTIME_TIMESTAMP":"100","__CURSOR":"fixture-start",
            "MESSAGE_ID":"39f53479d3a045ac8e11786248231fbf","MESSAGE":format!("Started {} - fixture",p.original_unit)}),
            json!({"_PID":"1","_UID":"0","UNIT":p.original_unit,"INVOCATION_ID":p.original_invocation,
            "_BOOT_ID":"2".repeat(32),"__REALTIME_TIMESTAMP":"1000","__CURSOR":"fixture-end",
            "MESSAGE_ID":"7ad2d189f7e94e70a38c781354912448","MESSAGE":format!("{}: Deactivated successfully.",p.original_unit)}),
        ]
    }
    fn jsonl(rows: &[Value]) -> Vec<u8> {
        rows.iter()
            .map(|r| format!("{}\n", serde_json::to_string(r).unwrap()))
            .collect::<String>()
            .into_bytes()
    }

    #[test]
    fn closed_scopes_have_the_actual_638_and_949_slot_suffixes_and_cached_snapshot_pins() {
        for (epoch, prefix_count, tail, size) in [
            (204, 431362, 638, 8_225_957_010),
            (205, 431051, 949, 8_407_269_066),
        ] {
            let p = profile(epoch).unwrap();
            assert_eq!(p.restart - p.start + 1, prefix_count);
            assert_eq!(p.end - p.restart, tail);
            assert_eq!(p.snapshot_bytes, size);
            assert_eq!(p.end, (epoch + 1) * 432000 - 1);
            prefix_scope(p, &manifest(p)).unwrap();
        }
        assert!(profile(203).is_err());
        assert!(profile(206).is_err());
    }
    #[test]
    fn metadata_content_requires_exact_launch_natural_outcome_manager_and_reader_bindings() {
        for p in PROFILES {
            let m = manifest(p);
            let l = launch(p);
            let o = outcome(p, &m);
            let r = reader(p, &m);
            validate_launch(p, &l).unwrap();
            validate_outcome(p, &o, &m, &hex_sha(&serde_json::to_vec(&m).unwrap())).unwrap();
            terminal_properties(p, &l, &properties(p, &l)).unwrap();
            manager_proof(p, &jsonl(&manager(p))).unwrap();
            validate_reader(p, &m, &o, &r).unwrap();
            // Synthetic content can exercise policy predicates but cannot enter
            // the public path, which separately hashes the real sealed launch.
            assert!(bind_metadata(p.epoch, inputs()).is_err());
            let mut old = l.clone();
            old["worker_sha256"] =
                json!("3f5e8efec328b3e00dd9ce5ae396fc4067e6be6554e4da8831a13273186a748a");
            assert!(validate_launch(p, &old).is_err());
            let mut stopped = o.clone();
            stopped["child_return_code"] = json!(1);
            assert!(
                validate_outcome(p, &stopped, &m, &hex_sha(&serde_json::to_vec(&m).unwrap()))
                    .is_err()
            );
            let mut forged = o.clone();
            forged["external_signal"] = json!(2);
            assert!(
                validate_outcome(p, &forged, &m, &hex_sha(&serde_json::to_vec(&m).unwrap()))
                    .is_err()
            );
            let mut changed = m.clone();
            changed.terminal.capitalization += 1;
            assert!(validate_reader(p, &changed, &o, &r).is_err());
            let mut old_reader = r;
            old_reader["archive"] = json!(
                "/home/ubuntu/.jetstreamer-private/qualification-205-prefix-store8-v1/output/epoch-205-through-88991050.jet"
            );
            assert!(validate_reader(p, &m, &o, &old_reader).is_err());
        }
    }
    #[test]
    fn terminal_properties_support_collected_history_but_reject_live_restarted_or_rebound_commands()
    {
        for p in PROFILES {
            let l = launch(p);
            let v = properties(p, &l);
            for key in [
                "ActiveState",
                "SubState",
                "MainPID",
                "NRestarts",
                "Result",
                "ExecMainCode",
                "ExecMainPID",
                "InvocationID",
                "ExecStart",
                "TriggeredBy",
            ] {
                let mut bad = v.clone();
                bad[key] = json!("wrong");
                assert!(terminal_properties(p, &l, &bad).is_err(), "{key}");
            }
            let mut collected = v;
            collected["LoadState"] = json!("not-found");
            collected["InvocationID"] = json!("");
            collected["ExecStart"] = json!("");
            terminal_properties(p, &l, &collected).unwrap();
            collected["ExecStart"] = json!("another executable");
            assert!(terminal_properties(p, &l, &collected).is_err());
        }
    }
    #[test]
    fn original_manager_success_cannot_be_replaced_by_stop_failure_or_new_invocation() {
        for p in PROFILES {
            for key in [
                "_PID",
                "_UID",
                "UNIT",
                "INVOCATION_ID",
                "_BOOT_ID",
                "MESSAGE_ID",
            ] {
                let mut rows = manager(p);
                rows[1][key] = json!("wrong");
                assert!(manager_proof(p, &jsonl(&rows)).is_err(), "{key}");
            }
            let mut rows = manager(p);
            let mut stop = rows[0].clone();
            stop["__REALTIME_TIMESTAMP"] = json!("900");
            stop["__CURSOR"] = json!("fixture-stop");
            stop["MESSAGE"] = json!(format!("Stopping {} - fixture", p.original_unit));
            rows.insert(1, stop);
            assert!(manager_proof(p, &jsonl(&rows)).is_err());
            let mut rows = manager(p);
            rows[1]["EXIT_STATUS"] = json!("1");
            assert!(manager_proof(p, &jsonl(&rows)).is_err());
        }
    }
    #[test]
    fn native_barrier_compares_every_consensus_field_without_forcing_equal_raw_cursors() {
        for p in PROFILES {
            let policy = fixture_policy(p);
            let cursor = 9_007_199_254_740_997;
            let actual = native(&policy.prefix_manifest, cursor);
            policy
                .native_barrier(actual, 0, parse_sha(WORKER_SHA256).unwrap(), cursor, 64)
                .unwrap();
            assert_ne!(
                actual.next_write_version,
                policy.prefix_manifest.terminal.next_write_version
            );
            for field in 0..9 {
                let mut changed = actual;
                match field {
                    0 => changed.slot += 1,
                    1 => changed.bank_hash = Hash::new_from_array([9; 32]),
                    2 => changed.accounts_hash_kind = AccountsHashKind::AccountsLtHash,
                    3 => changed.accounts_hash = Hash::new_from_array([9; 32]),
                    4 => changed.last_blockhash = Hash::new_from_array([9; 32]),
                    5 => changed.capitalization += 1,
                    6 => changed.transaction_count += 1,
                    7 => changed.tick_height += 1,
                    _ => changed.slot_complete = false,
                }
                assert!(
                    policy
                        .native_barrier(changed, 0, parse_sha(WORKER_SHA256).unwrap(), cursor, 64)
                        .is_err(),
                    "{field}"
                );
            }
            assert!(
                policy
                    .native_barrier(actual, 1, parse_sha(WORKER_SHA256).unwrap(), cursor, 64)
                    .is_err()
            );
            assert!(
                policy
                    .native_barrier(actual, 0, [0; 32], cursor, 64)
                    .is_err()
            );
            assert!(
                policy
                    .native_barrier(actual, 0, parse_sha(WORKER_SHA256).unwrap(), cursor + 1, 64)
                    .is_err()
            );
            assert!(
                policy
                    .native_barrier(actual, 0, parse_sha(WORKER_SHA256).unwrap(), cursor, 63)
                    .is_err()
            );
        }
    }
    #[test]
    fn v4_retains_distinct_generations_and_independent_large_raw_cursors() {
        for p in PROFILES {
            let policy = fixture_policy(p);
            let cursor = 9_007_199_254_740_997;
            let barrier = policy
                .native_barrier(
                    native(&policy.prefix_manifest, cursor),
                    0,
                    parse_sha(WORKER_SHA256).unwrap(),
                    cursor,
                    64,
                )
                .unwrap();
            let suffix = suffix(p, &policy.prefix_manifest, cursor);
            let v = barrier
                .provenance(
                    &suffix,
                    "fixture-assembly",
                    TransactionMetadataPolicy::runtime_reconstructed(),
                )
                .unwrap();
            assert_eq!(v.base.requested_slot_count, 432000);
            assert_eq!(
                v.base.runtime_segments[0].write_versions.worker_start,
                9_007_199_254_741_000
            );
            assert_eq!(
                v.base.runtime_segments[1].write_versions.worker_start,
                cursor
            );
            assert_eq!(v.base.runtime_segments[1].write_versions.archive_start, 10);
            assert_ne!(
                v.base.handoffs[0].predecessor.next_write_version,
                v.base.handoffs[0].successor.next_write_version
            );
            assert_eq!(
                v.base.runtime_segments[0].generation_profile,
                PREFIX_GENERATION
            );
            assert_eq!(
                v.base.runtime_segments[1].generation_profile,
                "new-private-suffix-generation"
            );
        }
    }
    #[test]
    fn v4_rejects_foreign_workers_scopes_native_cursors_and_normalization_overflow() {
        let p = PROFILES[0];
        let policy = fixture_policy(p);
        let cursor = 1000;
        let barrier = policy
            .native_barrier(
                native(&policy.prefix_manifest, cursor),
                0,
                parse_sha(WORKER_SHA256).unwrap(),
                cursor,
                64,
            )
            .unwrap();
        for field in 0..7 {
            let mut s = suffix(p, &policy.prefix_manifest, cursor);
            match field {
                0 => s.worker_executable_sha256 = [3; 32],
                1 => s.output_slot_start += 1,
                2 => s.output_slot_count -= 1,
                3 => s.bootstrap.next_write_version += 1,
                4 => s.bootstrap.write_count = 1,
                5 => s.bootstrap_archive_sha256 = Some([3; 32]),
                _ => s.runtime.runtime_revision = "foreign".into(),
            }
            assert!(
                barrier
                    .provenance(
                        &s,
                        "fixture",
                        TransactionMetadataPolicy::runtime_reconstructed()
                    )
                    .is_err(),
                "{field}"
            );
        }
        let mut policy = fixture_policy(p);
        policy.prefix_manifest.bootstrap.next_write_version = 0;
        policy.prefix_manifest.emitted_raw_write_versions = 0..u64::MAX - 1;
        policy.prefix_manifest.terminal.next_write_version = u64::MAX - 1;
        let barrier = policy
            .native_barrier(
                native(&policy.prefix_manifest, 1),
                0,
                parse_sha(WORKER_SHA256).unwrap(),
                1,
                64,
            )
            .unwrap();
        assert!(
            barrier
                .provenance(
                    &suffix(p, &policy.prefix_manifest, 1),
                    "fixture",
                    TransactionMetadataPolicy::runtime_reconstructed()
                )
                .is_err()
        );
    }
    fn archive(m: &HistoricalSegmentManifest) -> Vec<u8> {
        let provenance = ArchiveProvenance::V2(ArchiveProvenanceV2 {
            base: ArchiveProvenanceV1 {
                generation_profile: m.runtime.generation_profile.clone(),
                runtime_profile: m.runtime.runtime_profile.clone(),
                runtime_admission: RuntimeAdmission::Candidate,
                runtime_revision: m.runtime.runtime_revision.clone(),
                runtime_toolchain: m.runtime.runtime_toolchain.clone(),
                genesis_hash: m.runtime.genesis_hash.parse().unwrap(),
                bootstrap_state_kind: BootstrapStateKind::SnapshotArchive,
                bootstrap_slot: m.bootstrap.slot,
                bootstrap_state_hash: m.bootstrap.accounts_hash_value().unwrap(),
                requested_slot_start: m.output_slot_start,
                requested_slot_count: m.output_slot_count,
                transaction_metadata: TransactionMetadataPolicy::runtime_reconstructed(),
            },
            worker_executable_sha256: m.worker_executable_sha256,
        });
        let config = ArchiveWriterConfig {
            compression: Compression::None,
            ..Default::default()
        };
        let mut writer = ArchiveWriter::new_with_provenance(
            Vec::new(),
            m.epoch,
            m.output_slot_start,
            m.output_slot_count,
            config,
            &provenance,
        )
        .unwrap();
        writer
            .preserve_initial_poh_anchor(m.output_slot_start, Hash::new_from_array([7; 32]))
            .unwrap();
        for slot in m.output_slot_start..m.output_slot_start + m.output_slot_count {
            writer.write_skipped_slot(slot).unwrap();
        }
        writer.finish().unwrap().0
    }
    #[test]
    fn real_width_same_worker_v4_assembly_covers_both_complete_epochs_and_keeps_sources() {
        for p in PROFILES {
            let mut policy = fixture_policy(p);
            policy.prefix_manifest.emitted_raw_write_versions = 10..10;
            policy.prefix_manifest.terminal.next_write_version = 10;
            let prefix_bytes = archive(&policy.prefix_manifest);
            policy.prefix_manifest.archive_sha256 = Sha256::digest(&prefix_bytes).into();
            let cursor = 9_007_199_254_740_997;
            let mut s = suffix(p, &policy.prefix_manifest, cursor);
            s.emitted_raw_write_versions = cursor..cursor;
            s.terminal.next_write_version = cursor;
            let suffix_bytes = archive(&s);
            s.archive_sha256 = Sha256::digest(&suffix_bytes).into();
            let prefix_hash = Sha256::digest(&prefix_bytes);
            let suffix_hash = Sha256::digest(&suffix_bytes);
            let barrier = policy
                .native_barrier(
                    native(&policy.prefix_manifest, cursor),
                    0,
                    parse_sha(WORKER_SHA256).unwrap(),
                    cursor,
                    64,
                )
                .unwrap();
            let (output, stats) = barrier
                .assemble(
                    &s,
                    Cursor::new(&prefix_bytes),
                    Cursor::new(&suffix_bytes),
                    Vec::new(),
                    AssemblyOptions {
                        writer: ArchiveWriterConfig {
                            compression: Compression::None,
                            ..Default::default()
                        },
                        generation: "fixture-assembly",
                        metadata: TransactionMetadataPolicy::runtime_reconstructed(),
                    },
                )
                .unwrap();
            assert_eq!(stats.slots_merged, 432000);
            let mut reader = ArchiveReader::open(Cursor::new(output)).unwrap();
            assert_eq!(reader.header().slot_start, p.start);
            assert_eq!(reader.header().slot_count, 432000);
            assert!(reader.has_complete_slot_coverage().unwrap());
            assert!(matches!(
                reader.provenance().unwrap(),
                Some(ArchiveProvenance::V4(_))
            ));
            assert_eq!(prefix_hash, Sha256::digest(&prefix_bytes));
            assert_eq!(suffix_hash, Sha256::digest(&suffix_bytes));
        }
    }
    #[test]
    fn metadata_policy_never_claims_native_admission_idleness_or_publication() {
        let value = serde_json::to_value(fixture_policy(PROFILES[0])).unwrap();
        assert_eq!(value["missing_suffix_slots"], 638);
        assert_eq!(value["actual_suffix_must_repeat_native_barrier"], true);
        for field in [
            "current_source_idleness_proven",
            "resource_admission_passed",
            "native_initialized",
            "suffix_execution_authorized",
            "assembly_authorized",
            "canonical_sidecar_authorized",
            "publication_authorized",
            "r2_mutations",
        ] {
            assert_eq!(value[field], false, "{field}");
        }
    }
}
