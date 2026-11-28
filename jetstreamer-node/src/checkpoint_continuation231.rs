//! Build-bound restart of the retained epoch 231 prefix, followed by one live
//! epoch handoff. All recordings and assembly evidence remain private.

use super::checkpoint_continuation::{
    Evidence, RestartProof, authenticate_service, available_bytes, checkpoint_matches,
    create_private_dir, require, require_no_checksum, require_retained_input, runtime_checkpoint,
    sealed_bytes, sha, write_new,
};
use super::*;
use jetstreamer_horizon::archive::{
    ArchiveProvenanceV3, RuntimeSegmentSource, merge_runtime_segments,
};
use jetstreamer_node::{
    archive_checksum::{
        archive_file_identity, measure_open_archive_cancellable, open_regular_nofollow,
        path_matches_archive_identity,
    },
    segment_manifest::{
        read_and_validate_segment_manifest_from, segment_manifest_path, sha256_hex_string,
    },
};
use serde_json::{Value, json};
use std::{
    ffi::OsStr,
    io::BufReader,
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    path::Component,
    sync::OnceLock,
};

const EPOCH: u64 = 231;
const NEXT_EPOCH: u64 = 232;
const START: u64 = 99_792_000;
const RESTORE: u64 = 99_803_089;
const END_231: u64 = 100_223_999;
const ROOT: u64 = 100_655_540;
const END_232: u64 = 100_655_999;
const RESTORE_ACCOUNTS: &str = "42P5KSaezAgfvTUMtuFUiEtjpsmagMA2UbWoWJPAKCqr";
const ROOT_ACCOUNTS: &str = "A11g8aGUD2GCEGp7qcciMSW2Lf1StGPaUUZTLP1BHrRL";
const END_231_POH: &str = "FHbb7fEfGoqicjv43j7wMBxTGJgbAxBiwiR5rKtKmjRs";
const END_232_POH: &str = "HAjd3y8fGpYRuUCykcjaAmsuwhL8CFkGG6y6vhyYjENX";
const PREFIX: &str = "89cf6cc131bdb9481b207ecdfe7b0039c82b449910b4c58e3d7c5216efd5e51e";
const PREFIX_BYTES: u64 = 3_607_959_035;
const PREFIX_MANIFEST: &str = "b760a45bc00c952fc93878480718f6b6a2333f496ac7080b1badb267dbc50fc1";
const PREFIX_WORKER: &str = "afc9739c8753f97ad0d278c2829f2808f80a612bac7b1c83852c3548ba05dc08";
const PREFIX_RUNTIME: &str = "solana-v1.6.20-epoch231-called-program-demotion-candidate";
const PREFIX_ANCHOR: &str = "b1d0ed443581ae3e1c958ad47fca6eb42962b834d922e94d7cd4b26b5f4ed799";
const NATIVE_RESTORE: &str = "1b6030be50bc370b1067637b86ba46cd5e4dac8d3afae97fd89ab24ac99c2a7f";
const NATIVE_TERMINAL: &str = "1efd0027e5f00bd486c65b998a82888b7183dac5b73882ac9ef9cdc826a8351c";
const RESTORE_SNAPSHOT: &str = "f4410a8f6710e2e55860c74501fa05255f052ca9b3c7be866b63d70e160e01fb";
const RESTORE_SNAPSHOT_BYTES: u64 = 9_930_565_789;
const RESTORE_SNAPSHOT_NAME: &str =
    "snapshot-99803089-42P5KSaezAgfvTUMtuFUiEtjpsmagMA2UbWoWJPAKCqr.tar.zst";
const WORKER: &str = "8f3e721a5ec255ffb7fd6fa848d2127740897476672eb2e8640f8bd449652859";
const GENESIS: &str = "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945";
const COHORT: &str = "ef1c66a65556d5b4431037014fb43b41a1fd75f515a6c644438fcc22f21ccbf6";
const INDEX_PROJECTION: &str = "e412f2a7f4fb255558f09813e2079e0d7d52cd5202b145549064ef489d4e4b12";
const PRIVATE_ROOT: &str = "/home/ubuntu/.jetstreamer-private";
const PLAN_SCHEMA: &str = "jetstreamer-private-epoch231-232-continuation-plan-v1";
const ADMISSION_SCHEMA: &str = "jetstreamer-epoch231-232-continuation-admission-v1";
const ASSEMBLY_PROFILE: &str = "jetstreamer-private/epoch231-explicit-worker-handoff-v1";
const WORKER_ENV: &str = "JETSTREAMER_HISTORICAL_WORKER_EPOCH231_CONTINUATION";
pub(super) const BACKEND: &str = "solana-v1.6.20-epoch231-checkpoint-continuation-candidate";

const SUFFIX: QualificationPlan = QualificationPlan {
    epoch: EPOCH,
    bootstrap_slot: RESTORE,
    replay_start: RESTORE + 1,
    output_slot_start: RESTORE + 1,
    end_inclusive: END_231,
};
// Used only to write the exact epoch 232 segment manifest after the full
// non-focused carried replay has completed.
const NEXT_MANIFEST: QualificationPlan = QualificationPlan {
    epoch: NEXT_EPOCH,
    bootstrap_slot: END_231,
    replay_start: END_231 + 1,
    output_slot_start: END_231 + 1,
    end_inclusive: END_232,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ExecutionScope {
    pub(super) epoch: u64,
    pub(super) bootstrap_slot: u64,
    pub(super) replay_start: u64,
    pub(super) output_slot_start: u64,
    pub(super) end_inclusive: u64,
    pub(super) verification_end_inclusive: Option<u64>,
    pub(super) qualification: Option<QualificationPlan>,
    pub(super) has_restart_proof: bool,
    pub(super) carried: bool,
    pub(super) retain: bool,
    pub(super) private_mode: bool,
}

const SUFFIX_SCOPE: ExecutionScope = ExecutionScope {
    epoch: EPOCH,
    bootstrap_slot: RESTORE,
    replay_start: RESTORE + 1,
    output_slot_start: RESTORE + 1,
    end_inclusive: END_231,
    verification_end_inclusive: Some(END_232),
    qualification: Some(SUFFIX),
    has_restart_proof: true,
    carried: false,
    retain: true,
    private_mode: true,
};

const CARRIED_SCOPE: ExecutionScope = ExecutionScope {
    epoch: NEXT_EPOCH,
    bootstrap_slot: END_231,
    replay_start: END_231 + 1,
    output_slot_start: END_231 + 1,
    end_inclusive: END_232,
    verification_end_inclusive: Some(END_232),
    qualification: None,
    has_restart_proof: false,
    carried: true,
    retain: false,
    private_mode: true,
};

fn descriptor() -> &'static compatibility::RuntimeDescriptor {
    static DESCRIPTOR: OnceLock<compatibility::RuntimeDescriptor> = OnceLock::new();
    DESCRIPTOR.get_or_init(|| {
        let mut descriptor = compatibility::SOLANA_V1_6_20_RUNTIME;
        descriptor.identity.name = BACKEND;
        descriptor.worker = Some(compatibility::WorkerExecutable {
            identity: "jetstreamer-historical-worker-v1-6-20",
            environment_override: WORKER_ENV,
            default_manifest_relative_path: "/nonexistent/epoch231-requires-bound-worker",
        });
        descriptor
    })
}

pub(super) fn select_execution(
    scope: ExecutionScope,
) -> Result<compatibility::RuntimeSelection, String> {
    require(
        scope == SUFFIX_SCOPE || scope == CARRIED_SCOPE,
        "epoch 231–232 build allows only its exact restored suffix and carried epoch",
    )?;
    Ok(compatibility::RuntimeSelection {
        backend: compatibility::RuntimeBackend::SolanaV1_6_20,
        descriptor: descriptor(),
        admission: compatibility::AdmissionLevel::Candidate,
    })
}

pub(super) fn worker_profile(
    selected: &compatibility::RuntimeDescriptor,
) -> Result<historical::WorkerProfile, String> {
    require(
        std::ptr::eq(selected, descriptor()),
        "epoch 231–232 worker requires its exact private descriptor",
    )?;
    Ok(historical::WorkerProfile {
        backend_id: BACKEND,
        ..historical::SOLANA_V1_6_20_CANDIDATE
    })
}

pub(super) struct Invocation {
    destination: PathBuf,
    plan: Evidence,
}

pub(super) fn parse(args: &[String]) -> Result<Invocation, String> {
    let [epoch, dest, verify, plan, digest] = args else {
        return Err("usage: 231-232 DEST --verify --checkpoint-continuation-plan=PATH --checkpoint-continuation-plan-sha256=HEX".into());
    };
    let path = plan
        .strip_prefix("--checkpoint-continuation-plan=")
        .ok_or("missing private plan")?;
    let digest = digest
        .strip_prefix("--checkpoint-continuation-plan-sha256=")
        .ok_or("missing private plan digest")?;
    require(
        epoch == "231-232"
            && verify == "--verify"
            && Path::new(dest).is_absolute()
            && Path::new(path).is_absolute()
            && sha(digest)? != [0; 32],
        "epoch 231–232 continuation requires its exact scope, private plan and explicit verification",
    )?;
    Ok(Invocation {
        destination: dest.into(),
        plan: Evidence {
            path: path.into(),
            sha256: digest.into(),
        },
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    producer_unit: String,
    node_sha256: String,
    admission: Evidence,
    run_root: PathBuf,
    minimum_free_bytes: u64,
    prefix_archive: Evidence,
    prefix_manifest: Evidence,
    prefix_anchor: Evidence,
    native_restore: Evidence,
    native_terminal: Evidence,
    snapshot: Evidence,
    worker: Evidence,
    genesis: Evidence,
    cohort: Evidence,
    index_projection: Evidence,
}

fn validate_plan(plan: &Plan, args: &Invocation) -> Result<(), String> {
    let leaf = plan
        .run_root
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    require(
        plan.schema == PLAN_SCHEMA
            && plan.run_root.parent() == Some(Path::new(PRIVATE_ROOT))
            && leaf.starts_with("checkpoint-continuation-231-")
            && leaf.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && plan.producer_unit == format!("horizon-qualify-{leaf}.service")
            && args.destination == plan.run_root.join("ledger")
            && !args.plan.path.starts_with(&plan.run_root)
            && plan.minimum_free_bytes > 0
            && sha(&plan.node_sha256)? != [0; 32],
        "epoch 231–232 continuation needs an exact private destination, owner and node digest",
    )?;
    for (source, digest) in [
        (&plan.prefix_archive, PREFIX),
        (&plan.prefix_manifest, PREFIX_MANIFEST),
        (&plan.prefix_anchor, PREFIX_ANCHOR),
        (&plan.native_restore, NATIVE_RESTORE),
        (&plan.native_terminal, NATIVE_TERMINAL),
        (&plan.snapshot, RESTORE_SNAPSHOT),
        (&plan.worker, WORKER),
        (&plan.genesis, GENESIS),
        (&plan.cohort, COHORT),
        (&plan.index_projection, INDEX_PROJECTION),
        (&plan.admission, plan.admission.sha256.as_str()),
    ] {
        require(
            source.sha256 == digest
                && sha(digest)? != [0; 32]
                && source.path.is_absolute()
                && !source.path.starts_with(&plan.run_root),
            "retained input is outside its qualified digest or path scope",
        )?;
    }
    require(
        plan.snapshot.path.file_name() == Some(OsStr::new(RESTORE_SNAPSHOT_NAME)),
        "replacement snapshot name differs from the verified epoch 231 restart",
    )
}

fn json_evidence(evidence: &Evidence) -> Result<Value, String> {
    serde_json::from_slice(&sealed_bytes(evidence, 1 << 20)?).map_err(|e| e.to_string())
}

fn admission(plan: &Plan) -> Result<(), String> {
    let record = json_evidence(&plan.admission)?;
    let age = record["recorded_unix_seconds"].as_u64().and_then(|at| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()?
            .as_secs()
            .checked_sub(at)
    });
    require(
        record["schema"] == ADMISSION_SCHEMA
            && record["epochs"] == json!([EPOCH, NEXT_EPOCH])
            && record["node_sha256"] == plan.node_sha256
            && record["producer_unit"] == plan.producer_unit
            && record["run_root"] == plan.run_root.to_string_lossy().as_ref()
            && record["minimum_free_bytes"] == plan.minimum_free_bytes
            && record["snapshot_sha256"] == RESTORE_SNAPSHOT
            && record["worker_sha256"] == WORKER
            && record["index_projection_sha256"] == INDEX_PROJECTION
            && record["admitted"] == true
            && record["complete_fleet_and_century_floor_bound"] == true
            && record["actual_guard_and_owner_qualified"] == true
            && record["full_continuation_peak_qualified"] == true
            && record["publication_authorized"] == false
            && age.is_some_and(|seconds| seconds <= 900)
            && available_bytes(&plan.run_root)? >= plan.minimum_free_bytes,
        "epoch 231–232 continuation requires fresh guarded admission for replay and V3 assembly",
    )
}

#[derive(Deserialize)]
struct IndexBinding {
    dev: u64,
    ino: u64,
    length: u64,
    producer_path_relative_to_output: PathBuf,
    role: String,
}

fn check_namespace(plan: &Plan, ledger: &Path) -> Result<(), String> {
    for (path, expected_child) in [
        (plan.run_root.as_path(), "ledger"),
        (ledger, "compact-indexes"),
    ] {
        let metadata = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
        require(
            path.canonicalize().map_err(|e| e.to_string())? == path
                && metadata.is_dir()
                && metadata.uid() == 1000
                && metadata.mode() & 0o077 == 0,
            "continuation namespace must be canonical and owner-only",
        )?;
        let mut entries = fs::read_dir(path).map_err(|e| e.to_string())?;
        require(
            entries
                .next()
                .transpose()
                .map_err(|e| e.to_string())?
                .is_some_and(|entry| entry.file_name() == expected_child)
                && entries.next().is_none(),
            "continuation root must contain only the projected ledger indices",
        )?;
    }
    let projection = json_evidence(&plan.index_projection)?;
    let bindings: Vec<IndexBinding> =
        serde_json::from_value(projection["proposed_mappings"].clone())
            .map_err(|e| e.to_string())?;
    let roles = [
        "230:slot-to-cid",
        "231:slot-to-cid",
        "231:cid-to-offset-and-size",
        "232:slot-to-cid",
        "232:cid-to-offset-and-size",
    ];
    require(
        bindings.iter().map(|b| b.role.as_str()).eq(roles),
        "compact index projection does not match the full 231–232 replay",
    )?;
    for binding in bindings {
        let relative = binding.producer_path_relative_to_output;
        require(
            relative.starts_with("compact-indexes")
                && relative
                    .components()
                    .all(|c| matches!(c, Component::Normal(_))),
            "index projection requires a safe path below the ledger cache",
        )?;
        let path = ledger.join(relative);
        let file = open_regular_nofollow(&path).map_err(|e| e.to_string())?;
        let metadata = file.metadata().map_err(|e| e.to_string())?;
        let mut mounted = std::mem::MaybeUninit::<libc::statvfs>::uninit();
        if unsafe { libc::fstatvfs(file.as_raw_fd(), mounted.as_mut_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let mounted = unsafe { mounted.assume_init() };
        require(
            path.canonicalize().map_err(|e| e.to_string())? == path
                && (metadata.dev(), metadata.ino(), metadata.len())
                    == (binding.dev, binding.ino, binding.length)
                && metadata.uid() == 0
                && metadata.mode() & 0o222 == 0
                && mounted.f_flag & libc::ST_RDONLY != 0,
            "sealed compact index is absent or not bound read-only in this service",
        )?;
    }
    Ok(())
}

fn read_prefix(plan: &Plan) -> Result<HistoricalSegmentManifest, String> {
    require_retained_input(&plan.prefix_archive.path, PREFIX_BYTES)?;
    require_no_checksum(&plan.prefix_archive.path)?;
    let sealed: HistoricalSegmentManifest =
        serde_json::from_slice(&sealed_bytes(&plan.prefix_manifest, 1 << 20)?)
            .map_err(|e| e.to_string())?;
    let decoded = read_and_validate_segment_manifest_from(
        &plan.prefix_archive.path,
        &plan.prefix_manifest.path,
    )
    .map_err(|e| e.to_string())?;
    require(
        decoded == sealed
            && decoded.epoch == EPOCH
            && decoded.output_slot_start == START
            && decoded.output_slot_count == RESTORE - START + 1
            && decoded.terminal.slot == RESTORE
            && decoded.terminal.accounts_hash == RESTORE_ACCOUNTS
            && decoded.archive_sha256 == sha(PREFIX)?
            && decoded.worker_executable_sha256 == sha(PREFIX_WORKER)?
            && decoded.runtime.runtime_profile == PREFIX_RUNTIME
            && decoded.runtime.runtime_admission == SegmentRuntimeAdmission::Candidate,
        "complete prefix reread disagrees with its independently verified recording",
    )?;
    let anchor = json_evidence(&plan.prefix_anchor)?;
    require(
        anchor["schema"] == "foundation-epoch231-finalized-prefix-anchor-v1"
            && anchor["archive_sha256"] == PREFIX
            && anchor["predecessor"]["slot"] == START - 1
            && anchor["first"]["slot"] == START
            && anchor["first"]["parent_slot"] == START - 1
            && anchor["first"]["parent_blockhash"] == anchor["predecessor"]["blockhash"],
        "retained prefix lacks its exact independently finalized initial anchor",
    )?;
    Ok(decoded)
}

fn validate_restore_and_root(
    plan: &Plan,
    prefix: &HistoricalSegmentManifest,
) -> Result<(), String> {
    let probe = json_evidence(&plan.native_restore)?;
    let terminal = json_evidence(&plan.native_terminal)?;
    let restored: SegmentCheckpointSummary =
        serde_json::from_value(probe["native_checkpoint"].clone()).map_err(|e| e.to_string())?;
    checkpoint_matches(&prefix.terminal, &restored)?;
    require(
        probe["schema"] == "jetstreamer-private-epoch231-checkpoint-restore-probe-v1"
            && probe["worker"]["sha256"] == WORKER
            && probe["prefix_manifest"]["sha256"] == PREFIX_MANIFEST
            && probe["snapshot"]["sha256"] == RESTORE_SNAPSHOT
            && probe["snapshot"]["bytes"] == RESTORE_SNAPSHOT_BYTES
            && probe["assessment"]["native_consensus_state_matches"] == true
            && probe["assessment"]["replay_entries_sent"] == 0
            && terminal["schema"] == "foundation-epoch231-native-restore-terminal-v3"
            && terminal["native_receipt"]["sha256"] == NATIVE_RESTORE
            && terminal["native_checkpoint"] == probe["native_checkpoint"]
            && terminal["verified"] == true
            && terminal["exit_status"] == 0
            && terminal["guard_timer_drained"] == true,
        "sealed native restore evidence is incomplete or disagrees with the retained checkpoint",
    )?;
    let cohort = json_evidence(&plan.cohort)?;
    let cohorts = cohort["manifest"]["verification_cohorts"]
        .as_array()
        .ok_or("missing original cohort manifest")?;
    let mut matches = cohorts.iter().filter(|c| c["first_epoch"] == EPOCH);
    let expected = matches.next().ok_or("original 231–232 cohort is absent")?;
    require(
        matches.next().is_none()
            && expected["last_epoch"] == NEXT_EPOCH
            && expected["publish_through_epoch"] == NEXT_EPOCH
            && expected["publication_gate"] == "all-archives-validated-and-final-root-verified"
            && expected["root_checkpoints"]
                .as_array()
                .is_some_and(|roots| {
                    matches!(roots.as_slice(), [root]
                    if root["slot"] == ROOT && root["accounts_hash"] == ROOT_ACCOUNTS
                        && root["generation"] == 1_634_136_853_781_030u64)
                }),
        "canonical epoch 232 obligations differ from the sealed source cohort",
    )
}

struct VerifiedRestart {
    prefix: HistoricalSegmentManifest,
    snapshot: PathBuf,
    barrier_receipt: PathBuf,
    invocation: String,
}

impl RestartProof for VerifiedRestart {
    fn snapshot_sha256(&self) -> [u8; 32] {
        sha(RESTORE_SNAPSHOT).expect("fixed snapshot digest")
    }

    fn snapshot_size(&self) -> u64 {
        RESTORE_SNAPSHOT_BYTES
    }

    fn restored_verification(&self) -> Result<historical_replay::RestoredCheckpointTrust, String> {
        // Honor the independent canonical root after the carried epoch begins.
        Ok(historical_replay::RestoredCheckpointTrust::LocalBootstrapWithCanonicalTerminal(ROOT))
    }

    fn covers_trusted_root(&self, _: u64, _: u64, _: u64, _: u64) -> bool {
        false
    }

    fn validate_invocation(
        &self,
        epoch: u64,
        bootstrap: &ReplayBootstrap,
        qualification: Option<QualificationPlan>,
        carried: bool,
        audited: bool,
        retain: bool,
    ) -> Result<(), String> {
        require(
            epoch == EPOCH
                && bootstrap.snapshot_archive() == Some(self.snapshot.as_path())
                && qualification == Some(SUFFIX)
                && !carried
                && !audited
                && retain,
            "verified restart proof is valid only for the exact epoch 231 suffix",
        )
    }

    fn verify_native_checkpoint(
        &self,
        checkpoint: &historical::HistoricalCheckpoint,
        worker: [u8; 32],
        initialized_cursor: u64,
        ticks_per_slot: u64,
    ) -> Result<(), String> {
        let actual = segment_checkpoint_summary(
            &historical_replay::HistoricalCheckpointSummary::try_from(checkpoint)?,
        );
        verify_live_checkpoint(
            &self.prefix.terminal,
            &actual,
            worker,
            initialized_cursor,
            ticks_per_slot,
        )?;
        save(
            &self.barrier_receipt,
            json!({
                "schema": "jetstreamer-private-epoch231-live-restart-v1",
                "invocation_id": self.invocation,
                "worker_sha256": WORKER,
                "snapshot_sha256": RESTORE_SNAPSHOT,
                "prefix_manifest_sha256": PREFIX_MANIFEST,
                "prefix_terminal_next_write_version": self.prefix.terminal.next_write_version,
                "actual_native_bootstrap": actual,
                "replay_entries_sent": 0,
                "publication_authorized": false,
            }),
        )
    }
}

fn verify_live_checkpoint(
    expected: &SegmentCheckpointSummary,
    actual: &SegmentCheckpointSummary,
    worker: [u8; 32],
    initialized_cursor: u64,
    ticks_per_slot: u64,
) -> Result<(), String> {
    require(
        worker == sha(WORKER)?
            && ticks_per_slot == 64
            && actual.next_write_version == initialized_cursor,
        "epoch 231 live worker digest, tick unit or own initialized cursor differs",
    )?;
    checkpoint_matches(expected, actual)
}

fn canonical_verifier(shutdown: Arc<AtomicBool>) -> Result<Arc<SnapshotVerifier>, String> {
    let expected = [(RESTORE, RESTORE_ACCOUNTS), (ROOT, ROOT_ACCOUNTS)]
        .into_iter()
        .map(|(slot, hash)| {
            hash.parse::<Hash>()
                .map(|hash| (slot, BankHashExpectation::LegacyAccountsHash(hash)))
                .map_err(|e| e.to_string())
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    Ok(Arc::new(SnapshotVerifier::new(expected, Some(shutdown))))
}

fn save(path: &Path, value: Value) -> Result<(), String> {
    let mut bytes = serde_json::to_vec_pretty(&value).map_err(|e| e.to_string())?;
    bytes.push(b'\n');
    write_new(path, &bytes)
}

fn check_terminal(result: &ReplayRunResult, slot: u64, blockhash: &str) -> Result<(), String> {
    let state = result
        .historical_evidence
        .as_ref()
        .ok_or("phase lacks historical replay evidence")?;
    require(
        std::ptr::eq(result.execution.descriptor, descriptor())
            && result.historical_worker_executable_sha256 == Some(sha(WORKER)?)
            && state.terminal.slot == slot
            && state.terminal.slot_complete
            && Hash::new_from_array(state.terminal.last_blockhash).to_string() == blockhash
            && !state.emitted_write_versions.is_empty(),
        "closed phase reports an unexpected worker, terminal block or write coverage",
    )
}

fn check_live_carry(
    first: &historical_replay::HistoricalReplayEvidence,
    second: &historical_replay::HistoricalReplayEvidence,
) -> Result<(), String> {
    require(
        second.bootstrap == first.terminal
            && first.emitted_write_versions.end == first.terminal.next_write_version
            && second.emitted_write_versions.start == second.bootstrap.next_write_version,
        "epoch 232 must start at the exact retained epoch 231 Bank and live worker cursor",
    )
}

fn publish_recording(
    plan: QualificationPlan,
    path: &Path,
    result: &ReplayRunResult,
) -> Result<(HistoricalSegmentManifest, Value), String> {
    require_no_checksum(path)?;
    let sidecar = segment_manifest_path(path).map_err(|e| e.to_string())?;
    require(
        matches!(fs::symlink_metadata(&sidecar), Err(e) if e.kind() == std::io::ErrorKind::NotFound),
        "private recording manifest already exists",
    )?;
    let manifest = publish_historical_segment_manifest(plan.epoch, plan, path, result)?;
    let file = open_regular_nofollow(&sidecar).map_err(|e| e.to_string())?;
    let validated = measure_open_archive_cancellable(&file, &AtomicBool::new(false))
        .map_err(|e| e.to_string())?;
    require(
        path_matches_archive_identity(&sidecar, validated.identity).map_err(|e| e.to_string())?,
        "private recording manifest identity changed",
    )?;
    let evidence = json!({
        "path": path,
        "sha256": sha256_hex_string(&manifest.archive_sha256),
        "manifest": { "path": sidecar, "sha256": sha256_hex_string(&validated.sha256) },
    });
    Ok((manifest, evidence))
}

fn provenance(
    prefix: &HistoricalSegmentManifest,
    suffix: &HistoricalSegmentManifest,
) -> Result<ArchiveProvenanceV3, String> {
    checkpoint_matches(&prefix.terminal, &suffix.bootstrap)?;
    require(
        prefix.epoch == EPOCH
            && prefix.output_slot_start == START
            && prefix.output_slot_count == RESTORE - START + 1
            && prefix.archive_sha256 == sha(PREFIX)?
            && prefix.worker_executable_sha256 == sha(PREFIX_WORKER)?
            && prefix.runtime.runtime_profile == PREFIX_RUNTIME
            && suffix.epoch == EPOCH
            && suffix.output_slot_start == RESTORE + 1
            && suffix.output_slot_count == END_231 - RESTORE
            && suffix.terminal.slot == END_231
            && suffix.terminal.slot_complete
            && suffix.terminal.last_blockhash == END_231_POH
            && suffix.bootstrap_archive_sha256 == Some(sha(RESTORE_SNAPSHOT)?)
            && suffix.worker_executable_sha256 == sha(WORKER)?
            && suffix.runtime.runtime_profile == BACKEND
            && prefix.runtime.runtime_revision == suffix.runtime.runtime_revision
            && prefix.runtime.runtime_toolchain == suffix.runtime.runtime_toolchain
            && prefix.runtime.runtime_target == suffix.runtime.runtime_target
            && prefix.runtime.genesis_hash == suffix.runtime.genesis_hash
            && prefix.runtime.runtime_admission == SegmentRuntimeAdmission::Candidate
            && suffix.runtime.runtime_admission == SegmentRuntimeAdmission::Candidate,
        "epoch 231 assembly requires its exact prefix and private continuation source ranges",
    )?;

    let mut next = 0;
    let mut segments = Vec::with_capacity(2);
    for source in [prefix, suffix] {
        let mapping = WriteVersionNormalization {
            worker_start: source.emitted_raw_write_versions.start,
            worker_end_exclusive: source.emitted_raw_write_versions.end,
            archive_start: next,
        };
        next = mapping
            .archive_end_exclusive()
            .ok_or("write version range overflow")?;
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
    let provenance = ArchiveProvenanceV3 {
        assembly_profile: ASSEMBLY_PROFILE.into(),
        genesis_hash: compatibility::MAINNET_GENESIS_HASH
            .parse::<Hash>()
            .map_err(|e| e.to_string())?,
        bootstrap_state_kind: BootstrapStateKind::SnapshotArchive,
        bootstrap_state: StateCommitment {
            slot: prefix.bootstrap.slot,
            kind: StateCommitmentKind::LegacyAccountsHash,
            hash: prefix
                .bootstrap
                .accounts_hash
                .parse::<Hash>()
                .map_err(|e| e.to_string())?,
        },
        requested_slot_start: START,
        requested_slot_count: END_231 - START + 1,
        transaction_metadata: archive_transaction_metadata_policy(START, END_231 - START + 1),
        runtime_segments: segments,
        handoffs: vec![RuntimeHandoffProvenance {
            boundary_slot: RESTORE + 1,
            predecessor: runtime_checkpoint(&prefix.terminal)?,
            successor: runtime_checkpoint(&suffix.bootstrap)?,
            successor_bootstrap_kind: BootstrapStateKind::SnapshotArchive,
            successor_bootstrap_archive_sha256: sha(RESTORE_SNAPSHOT)?,
            successor_bootstrap_write_count: 0,
        }],
    };
    provenance.validate().map_err(|e| e.to_string())?;
    Ok(provenance)
}

fn assemble(
    retained: (&Path, &HistoricalSegmentManifest),
    resumed: (&Path, &HistoricalSegmentManifest),
    output: &Path,
    shutdown: &AtomicBool,
) -> Result<[u8; 32], String> {
    let provenance = provenance(retained.1, resumed.1)?;
    let mut sources = Vec::with_capacity(2);
    let mut identities = Vec::with_capacity(2);
    for (path, manifest) in [retained, resumed] {
        require_no_checksum(path)?;
        let file = open_regular_nofollow(path).map_err(|e| e.to_string())?;
        identities.push((
            path,
            archive_file_identity(&file).map_err(|e| e.to_string())?,
        ));
        sources.push(RuntimeSegmentSource::new(
            BufReader::new(file),
            manifest.archive_sha256,
            manifest
                .terminal
                .last_blockhash
                .parse::<Hash>()
                .map_err(|e| e.to_string())?,
        ));
    }
    let directory = output
        .parent()
        .ok_or("missing private assembly directory")?;
    let sink = tempfile::NamedTempFile::new_in(directory).map_err(|e| e.to_string())?;
    let (sink, stats) =
        merge_runtime_segments(sources, sink, ArchiveWriterConfig::default(), &provenance)
            .map_err(|e| e.to_string())?;
    sink.as_file().sync_all().map_err(|e| e.to_string())?;
    for (path, identity) in identities {
        require(
            path_matches_archive_identity(path, identity).map_err(|e| e.to_string())?,
            "epoch 231 assembly source identity changed",
        )?;
    }
    require(
        stats.slots_merged == END_231 - START + 1,
        "epoch 231 V3 assembly coverage differs",
    )?;
    let validated =
        measure_open_archive_cancellable(sink.as_file(), shutdown).map_err(|e| e.to_string())?;
    require_no_checksum(output)?;
    sink.persist_noclobber(output).map_err(|e| e.to_string())?;
    fs::File::open(directory)
        .and_then(|dir| dir.sync_all())
        .map_err(|e| e.to_string())?;
    Ok(validated.sha256)
}

pub(super) async fn run(
    args: Invocation,
    shutdown: Arc<AtomicBool>,
    cursor: Arc<ReplayCursor>,
    tracker: Arc<RestartTracker>,
) -> Result<(), String> {
    let plan: Plan =
        serde_json::from_slice(&sealed_bytes(&args.plan, 1 << 20)?).map_err(|e| e.to_string())?;
    validate_plan(&plan, &args)?;
    require(
        unsafe { libc::geteuid() } == 1000,
        "epoch 231–232 continuation requires isolated UID 1000",
    )?;
    let invocation = authenticate_service(&plan.producer_unit)?;
    // A dev image may exceed the older probes' 256 MiB ceiling.
    verify_node(&plan.node_sha256)?;
    admission(&plan)?;
    check_namespace(&plan, &args.destination)?;
    let prefix = read_prefix(&plan)?;
    validate_restore_and_root(&plan, &prefix)?;
    require_retained_input(&plan.snapshot.path, RESTORE_SNAPSHOT_BYTES)?;
    sealed_bytes(&plan.worker, 32 << 20)?;
    let genesis = sealed_bytes(&plan.genesis, 1 << 20)?;
    require(
        configured_historical_worker_executable(descriptor())? == plan.worker.path
            && !shutdown.load(Ordering::SeqCst),
        "configured worker differs from the sealed continuation or shutdown requested",
    )?;
    admission(&plan)?;
    for leaf in ["scratch", "output", "receipts"] {
        create_private_dir(&plan.run_root.join(leaf))?;
    }
    write_new(&args.destination.join("genesis.tar.bz2"), &genesis)?;

    let receipts = plan.run_root.join("receipts");
    let scratch = plan.run_root.join("scratch");
    let output = plan.run_root.join("output");
    let suffix_path = output.join("epoch-231-suffix.jet");
    let next_path = output.join("epoch-232-private.jet");
    let assembled = output.join("epoch-231-worker-handoff-v3.jet");
    let proof = VerifiedRestart {
        prefix,
        snapshot: plan.snapshot.path.clone(),
        barrier_receipt: receipts.join("live-restart.json"),
        invocation: invocation.clone(),
    };
    let verifier = canonical_verifier(shutdown.clone())?;
    let bootstrap = ReplayBootstrap::SnapshotArchive(proof.snapshot.clone());
    let mut first = run_geyser_replay(
        EPOCH,
        true,
        &args.destination,
        &scratch,
        &bootstrap,
        shutdown.clone(),
        cursor.clone(),
        tracker.clone(),
        Some(verifier.clone()),
        suffix_path.clone(),
        Some(SUFFIX),
        None,
        None,
        None,
        None,
        Some(END_232),
        None,
        true,
        Some(&proof),
        epoch223_qualification::TailMode::Disabled,
    )
    .await?
    .completed()?;
    check_terminal(&first, END_231, END_231_POH)?;
    require(
        !shutdown.load(Ordering::SeqCst)
            && proof.barrier_receipt.is_file()
            && verifier.checkpoint_count_in_range(RESTORE, RESTORE) == 0
            && verifier.checkpoint_count_in_range(ROOT, ROOT) == 1,
        "epoch 231 must close with the native instant proved and the later root still pending",
    )?;
    let carried = first
        .carried_state
        .take()
        .ok_or("epoch 231 worker did not remain live")?;
    let observed_carry_checkpoint = segment_checkpoint_summary(
        &first
            .historical_evidence
            .as_ref()
            .ok_or("missing epoch 231 proof")?
            .terminal,
    );
    save(
        &receipts.join("epoch-231-suffix-closed.json"),
        json!({
            "schema": "jetstreamer-private-epoch231-suffix-closed-v1",
            "invocation_id": invocation,
            "archive": suffix_path,
            "first_slot": RESTORE + 1,
            "last_slot": END_231,
            "carry_checkpoint": observed_carry_checkpoint,
            "canonical_root_pending": ROOT,
            "archive_manifest_pending": true,
            "publication_authorized": false,
        }),
    )?;

    let second = run_geyser_replay(
        NEXT_EPOCH,
        true,
        &args.destination,
        &scratch,
        &bootstrap,
        shutdown.clone(),
        cursor,
        tracker,
        Some(verifier.clone()),
        next_path.clone(),
        None,
        Some(carried),
        None,
        None,
        None,
        Some(END_232),
        None,
        false,
        None,
        epoch223_qualification::TailMode::Disabled,
    )
    .await?
    .completed()?;
    check_terminal(&second, END_232, END_232_POH)?;
    check_live_carry(
        first
            .historical_evidence
            .as_ref()
            .ok_or("missing suffix evidence")?,
        second
            .historical_evidence
            .as_ref()
            .ok_or("missing carried evidence")?,
    )?;
    verifier.finish()?;
    require(
        !shutdown.load(Ordering::SeqCst),
        "private replay interrupted",
    )?;
    let (suffix, suffix_evidence) = publish_recording(SUFFIX, &suffix_path, &first)?;
    let (next, next_evidence) = publish_recording(NEXT_MANIFEST, &next_path, &second)?;
    // Retain both complete source manifests and the root evidence if the
    // independent assembly stage fails or is interrupted.
    save(
        &receipts.join("replay-complete.json"),
        json!({
            "schema": "jetstreamer-private-epoch231-232-replay-complete-v1",
            "invocation_id": invocation,
            "plan": args.plan,
            "worker_sha256": WORKER,
            "suffix_231": suffix_evidence,
            "archive_232": next_evidence,
            "canonical_root": { "slot": ROOT, "legacy_accounts_hash": ROOT_ACCOUNTS, "verified": true },
            "through_slot": END_232,
            "publication_authorized": false,
        }),
    )?;
    let archive_sha = assemble(
        (&plan.prefix_archive.path, &proof.prefix),
        (&suffix_path, &suffix),
        &assembled,
        &shutdown,
    )?;
    save(
        &receipts.join("assembled-private.json"),
        json!({
            "schema": "jetstreamer-private-epoch231-232-continuation-v1",
            "invocation_id": invocation,
            "archive_231": {
                "path": assembled,
                "sha256": sha256_hex_string(&archive_sha),
                "provenance_version": 3,
                "first_slot": START,
                "last_slot": END_231,
            },
            "archive_232": {
                "path": next_path,
                "sha256": sha256_hex_string(&next.archive_sha256),
                "provenance_version": 2,
                "first_slot": END_231 + 1,
                "last_slot": END_232,
            },
            "canonical_root_verified": ROOT,
            "current_plugin_verification_passed": false,
            "independent_final_archive_verification_passed": false,
            "canonical_sidecar_authorized": false,
            "publication_authorized": false,
            "r2_mutations": false,
        }),
    )
}

fn verify_node(expected: &str) -> Result<(), String> {
    let path = fs::read_link("/proc/self/exe").map_err(|e| e.to_string())?;
    let file = open_regular_nofollow(&path).map_err(|e| e.to_string())?;
    let metadata = file.metadata().map_err(|e| e.to_string())?;
    require(
        metadata.uid() == 0 && metadata.nlink() == 1 && metadata.mode() & 0o222 == 0,
        "continuation node must be an immutable sealed deployment",
    )?;
    let digest = measure_open_archive_cancellable(&file, &AtomicBool::new(false))
        .map_err(|e| e.to_string())?;
    require(
        digest.sha256 == sha(expected)?
            && path_matches_archive_identity(&path, digest.identity).map_err(|e| e.to_string())?,
        "running continuation node digest or identity differs",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn retained_checkpoint() -> SegmentCheckpointSummary {
        SegmentCheckpointSummary {
            slot: RESTORE,
            bank_hash: "28H3bRLLPmQFG1YZEwUQgbgVarrAw1LXTEikW4D3m7gS".into(),
            accounts_hash: RESTORE_ACCOUNTS.into(),
            last_blockhash: "ARTcvsXz3UYnyhQ9dCdUZVXm8FhmNghkfAst1mvsgwiF".into(),
            capitalization: 505_736_013_175_502_375,
            transaction_count: 31_296_423_985,
            tick_height: 6_387_397_760,
            slot_complete: true,
            write_count: 214,
            next_write_version: 117_843_706_003,
        }
    }

    fn native_checkpoint() -> SegmentCheckpointSummary {
        SegmentCheckpointSummary {
            write_count: 0,
            next_write_version: 117_843_815_773,
            ..retained_checkpoint()
        }
    }

    #[test]
    fn entrypoint_rejects_other_plans_and_routes_before_dispatch() {
        let valid = [
            "231-232",
            "/private/ledger",
            "--verify",
            "--checkpoint-continuation-plan=/sealed/plan.json",
            &format!("--checkpoint-continuation-plan-sha256={NATIVE_RESTORE}"),
        ]
        .map(String::from);
        assert!(parse(&valid).is_ok());
        for (index, replacement) in [
            (0, "231"),
            (0, "--post-update-capacity-probe"),
            (1, "relative"),
            (2, "--no-verify"),
            (3, "--snapshot-archive=/sealed/input"),
            (4, "--checkpoint-continuation-plan-sha256=bad"),
        ] {
            let mut invalid = valid.clone();
            invalid[index] = replacement.into();
            assert!(parse(&invalid).is_err(), "{replacement}");
        }
        let mut extra = valid.to_vec();
        extra.push("--root-checkpoint-cohort".into());
        assert!(parse(&extra).is_err());
    }

    #[test]
    fn dispatch_accepts_only_the_restored_suffix_and_exact_live_carry() {
        for scope in [SUFFIX_SCOPE, CARRIED_SCOPE] {
            let selected = select_execution(scope).unwrap();
            assert_eq!(selected.admission, compatibility::AdmissionLevel::Candidate);
            assert_eq!(selected.descriptor.identity.name, BACKEND);
            assert_eq!(
                worker_profile(selected.descriptor).unwrap().backend_id,
                BACKEND
            );
        }
        assert_eq!(SUFFIX.slot_count(), 420_910);
        assert_eq!(NEXT_MANIFEST.slot_count(), 432_000);
        assert_eq!(NEXT_MANIFEST.output_slot_start, SUFFIX.end_inclusive + 1);
        for scope in [
            ExecutionScope {
                verification_end_inclusive: Some(END_231),
                ..SUFFIX_SCOPE
            },
            ExecutionScope {
                retain: false,
                ..SUFFIX_SCOPE
            },
            ExecutionScope {
                has_restart_proof: false,
                ..SUFFIX_SCOPE
            },
            ExecutionScope {
                carried: false,
                ..CARRIED_SCOPE
            },
            ExecutionScope {
                qualification: Some(NEXT_MANIFEST),
                ..CARRIED_SCOPE
            },
            ExecutionScope {
                end_inclusive: ROOT,
                ..CARRIED_SCOPE
            },
            ExecutionScope {
                end_inclusive: END_232 + 1,
                ..CARRIED_SCOPE
            },
            ExecutionScope {
                private_mode: false,
                ..CARRIED_SCOPE
            },
        ] {
            assert!(select_execution(scope).is_err(), "{scope:?}");
        }
        assert!(worker_profile(&compatibility::SOLANA_V1_6_20_RUNTIME).is_err());
    }

    #[test]
    fn exact_bootstrap_leaves_the_later_root_pending() {
        let verifier = canonical_verifier(Arc::new(AtomicBool::new(false))).unwrap();
        verifier.verify_legacy_accounts_hash(RESTORE, RESTORE_ACCOUNTS.parse().unwrap());
        assert_eq!(verifier.checkpoint_count_in_range(RESTORE, END_231), 0);
        assert_eq!(verifier.checkpoint_count_in_range(END_231 + 1, END_232), 1);
        assert!(verifier.finish().is_err());
        verifier.verify_legacy_accounts_hash(ROOT, ROOT_ACCOUNTS.parse().unwrap());
        assert!(verifier.finish().is_ok());
    }

    #[test]
    fn restart_checks_native_consensus_and_uses_only_the_live_initialized_cursor() {
        let expected = retained_checkpoint();
        let native = native_checkpoint();
        let worker = sha(WORKER).unwrap();
        let cursor = native.next_write_version;
        assert_ne!(expected.next_write_version, cursor);
        assert!(verify_live_checkpoint(&expected, &native, worker, cursor, 64).is_ok());
        assert!(verify_live_checkpoint(&expected, &native, worker, cursor - 1, 64).is_err());
        assert!(verify_live_checkpoint(&expected, &native, worker, cursor, 32).is_err());
        assert!(verify_live_checkpoint(&expected, &native, [0; 32], cursor, 64).is_err());
        for invalid in [
            SegmentCheckpointSummary {
                capitalization: native.capitalization - 1,
                ..native.clone()
            },
            SegmentCheckpointSummary {
                slot_complete: false,
                ..native.clone()
            },
            SegmentCheckpointSummary {
                write_count: 1,
                ..native.clone()
            },
        ] {
            assert!(verify_live_checkpoint(&expected, &invalid, worker, cursor, 64).is_err());
        }
    }

    #[test]
    fn carried_archive_must_continue_the_actual_same_worker_bank_and_cursor() {
        let native = native_checkpoint();
        let summary =
            |slot, blockhash: &str, cursor| historical_replay::HistoricalCheckpointSummary {
                slot,
                bank_hash: native.bank_hash.parse::<Hash>().unwrap().to_bytes(),
                accounts_hash: native.accounts_hash.parse::<Hash>().unwrap().to_bytes(),
                last_blockhash: blockhash.parse::<Hash>().unwrap().to_bytes(),
                capitalization: native.capitalization,
                transaction_count: native.transaction_count,
                tick_height: native.tick_height,
                slot_complete: true,
                write_count: 0,
                next_write_version: cursor,
            };
        let first = historical_replay::HistoricalReplayEvidence {
            bootstrap: summary(RESTORE, &native.last_blockhash, 10),
            terminal: summary(END_231, END_231_POH, 30),
            emitted_write_versions: 10..30,
        };
        let mut second = historical_replay::HistoricalReplayEvidence {
            bootstrap: first.terminal.clone(),
            terminal: summary(END_232, END_232_POH, 50),
            emitted_write_versions: 30..50,
        };
        assert!(check_live_carry(&first, &second).is_ok());
        second.emitted_write_versions.start += 1;
        assert!(check_live_carry(&first, &second).is_err());
        second.emitted_write_versions.start -= 1;
        second.bootstrap.bank_hash[0] ^= 1;
        assert!(check_live_carry(&first, &second).is_err());
    }

    #[test]
    fn assembly_retains_distinct_worker_ids_and_normalizes_only_write_versions() {
        let retained = retained_checkpoint();
        let native = native_checkpoint();
        let prefix = HistoricalSegmentManifest {
            schema_version: jetstreamer_node::segment_manifest::SEGMENT_MANIFEST_SCHEMA_VERSION,
            epoch: EPOCH,
            output_slot_start: START,
            output_slot_count: RESTORE - START + 1,
            runtime: segment_runtime_identity(select_execution(SUFFIX_SCOPE).unwrap()).unwrap(),
            worker_executable_sha256: sha(PREFIX_WORKER).unwrap(),
            archive_sha256: sha(PREFIX).unwrap(),
            bootstrap_archive_sha256: None,
            bootstrap: SegmentCheckpointSummary {
                slot: START - 2,
                ..retained.clone()
            },
            emitted_raw_write_versions: retained.next_write_version - 20
                ..retained.next_write_version,
            terminal: retained,
        };
        let mut prefix = prefix;
        prefix.runtime.runtime_profile = PREFIX_RUNTIME.into();
        let suffix = HistoricalSegmentManifest {
            schema_version: prefix.schema_version,
            epoch: EPOCH,
            output_slot_start: RESTORE + 1,
            output_slot_count: END_231 - RESTORE,
            runtime: segment_runtime_identity(select_execution(SUFFIX_SCOPE).unwrap()).unwrap(),
            worker_executable_sha256: sha(WORKER).unwrap(),
            archive_sha256: [42; 32],
            bootstrap_archive_sha256: Some(sha(RESTORE_SNAPSHOT).unwrap()),
            bootstrap: native.clone(),
            terminal: SegmentCheckpointSummary {
                slot: END_231,
                last_blockhash: END_231_POH.into(),
                next_write_version: native.next_write_version + 40,
                ..native.clone()
            },
            emitted_raw_write_versions: native.next_write_version..native.next_write_version + 40,
        };
        let joined = provenance(&prefix, &suffix).unwrap();
        assert_eq!(joined.requested_slot_count, 432_000);
        assert_eq!(joined.runtime_segments[1].write_versions.archive_start, 20);
        assert_eq!(
            joined.runtime_segments[1].write_versions.worker_start,
            native.next_write_version
        );
        assert_ne!(
            joined.handoffs[0].predecessor.next_write_version,
            joined.handoffs[0].successor.next_write_version
        );
        assert!(
            jetstreamer_horizon::archive::ArchiveProvenanceV4 { base: joined }
                .validate()
                .is_err()
        );
        let mut wrong = suffix;
        wrong.output_slot_start += 1;
        assert!(provenance(&prefix, &wrong).is_err());
    }
}
