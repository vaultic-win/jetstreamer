//! Exact private203 continuation. No ordinary reuse, import, sidecar or R2 authority.
use super::checkpoint_continuation::{
    Evidence, RestartProof, assemble_sources, authenticate_service, available_bytes,
    checkpoint_matches, create_private_dir, require, require_no_checksum, require_retained_input,
    runtime_checkpoint, sealed_bytes, sha, write_new,
};
use super::*;
use jetstreamer_horizon::archive::ArchiveProvenanceV4;
use jetstreamer_node::{
    archive_checksum::{
        archive_file_identity, open_regular_nofollow, path_matches_archive_identity,
    },
    segment_manifest::read_and_validate_segment_manifest_from,
};
use serde_json::{Value, json};
use std::{
    fs::OpenOptions,
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
};

const EPOCH: u64 = 203;
const START: u64 = 87_696_000;
const ROOT: u64 = 88_127_580;
const END: u64 = 88_127_999;
const PREFIX_SHA: &str = "ba191cf1918cac8b67cb7512bd07cc1eeccb16e525e4c15c27fd7c325f6993ce";
const MANIFEST_SHA: &str = "983ecabfc9c36e261a66641b8a039e5e1834198b0c9a07552db38457e67e5722";
const NATIVE_SHA: &str = "5260d7af71ab802ca711fce706020312212d0c8cdfc01c473398b0a9a0108420";
const SNAPSHOT_SHA: &str = "d3114597ce25c3efaa4a96899ab3e9437c51cb9086d4166639f0ad2ae0613ee6";
const WORKER_SHA: &str = "4aeca56378a4bb2c55d0e590c1e334c4afa6a375a2c0d94894b412bea261f1cc";
const GENESIS_SHA: &str = "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945";
const SNAPSHOT_SIZE: u64 = 8_215_471_895;
const PREFIX_SIZE: u64 = 103_781_283_604;
const PROTECTED: u64 = 2_687_830_606_739;
// A minimum experimental envelope, not a qualified peak estimate. A separately
// sealed fresh full-path admission is mandatory and may require a larger peak.
const MINIMUM_PEAK: u64 = 256 << 30;
const PRIVATE_ROOT: &str = "/home/ubuntu/.jetstreamer-private";

#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    epoch: u64,
    producer_unit: String,
    node_sha256: String,
    prefix_archive: Evidence,
    prefix_manifest: Evidence,
    native_probe: Evidence,
    restart_snapshot: Evidence,
    worker: Evidence,
    genesis_archive: Evidence,
    admission_receipt: Evidence,
    run_root: PathBuf,
    minimum_free_bytes: u64,
}
struct ValidatedPrefix {
    manifest: HistoricalSegmentManifest,
    snapshot: PathBuf,
    runner_started: std::time::Instant,
    native_barrier_millis: std::sync::atomic::AtomicU64,
}

pub(crate) fn validate_cli(
    epochs: (u64, u64),
    verify: Option<bool>,
    count: usize,
    destination: bool,
    forbidden: bool,
) -> Result<(), String> {
    require(
        cfg!(feature = "epoch203-checkpoint-continuation-diagnostic")
            && epochs == (EPOCH, EPOCH)
            && verify == Some(true)
            && count == 1
            && destination
            && !forbidden,
        "private203 continuation requires its dedicated build, only203, one --verify, explicit private destination, and no ordinary override",
    )
}
fn validate_plan(p: &Plan, destination: &Path) -> Result<(), String> {
    require(
        p.schema == "jetstreamer-private-epoch203-checkpoint-continuation-plan-v1"
            && p.epoch == EPOCH,
        "wrong203 continuation plan",
    )?;
    require(
        p.producer_unit
            .starts_with("horizon-qualify-203-checkpoint-continuation-")
            && p.producer_unit.ends_with(".service")
            && p.producer_unit
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
            && sha(&p.node_sha256)? != [0; 32],
        "203 continuation owner/digest differs",
    )?;
    for (input, digest) in [
        (&p.prefix_archive, PREFIX_SHA),
        (&p.prefix_manifest, MANIFEST_SHA),
        (&p.native_probe, NATIVE_SHA),
        (&p.restart_snapshot, SNAPSHOT_SHA),
        (&p.worker, WORKER_SHA),
        (&p.genesis_archive, GENESIS_SHA),
    ] {
        require(
            input.sha256 == digest
                && input.path.is_absolute()
                && !input.path.starts_with(&p.run_root),
            "203 continuation input differs or overlaps output",
        )?;
    }
    let leaf = p
        .run_root
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    require(
        p.run_root.parent() == Some(Path::new(PRIVATE_ROOT))
            && leaf.starts_with("checkpoint-continuation-203-")
            && leaf.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && destination == p.run_root.join("ledger")
            && p.minimum_free_bytes
                >= PROTECTED
                    .checked_add(MINIMUM_PEAK)
                    .ok_or("203 budget overflow")?,
        "203 continuation needs isolated output and complete-path budget, not native-only192GiB",
    )?;
    require(
        p.restart_snapshot.path.file_name().and_then(|s| s.to_str())
            == Some("snapshot-88127580-4SeHmKHQrHot4gwifo1bnvDKXZwGELk2vSenotTx9oqf.tar.zst")
            && p.genesis_archive.path.file_name().and_then(|s| s.to_str())
                == Some("genesis.tar.bz2")
            && p.admission_receipt.path.is_absolute()
            && !p.admission_receipt.path.starts_with(&p.run_root),
        "203 snapshot/genesis/admission path differs",
    )
}
fn admission(p: &Plan, v: &Value, now: u64) -> Result<(), String> {
    let peak = v["candidate_incremental_peak_bytes"]
        .as_u64()
        .ok_or("203 admission peak missing")?;
    let floor = v["protected_existing_floor_bytes"]
        .as_u64()
        .ok_or("203 admission floor missing")?;
    require(
        v["schema"] == "jetstreamer-epoch203-continuation-admission-v1"
            && v["admitted"] == true
            && v["private_continuation_and_assembly_only"] == true
            && v["epoch"] == EPOCH
            && v["node_sha256"] == p.node_sha256
            && v["prefix_sha256"] == PREFIX_SHA
            && v["snapshot_sha256"] == SNAPSHOT_SHA
            && v["native_result_sha256"] == NATIVE_SHA
            && v["worker_sha256"] == WORKER_SHA
            && v["remaining_slots"] == END - ROOT
            && peak >= MINIMUM_PEAK
            && floor >= PROTECTED
            && v["required_guard_minimum_free_bytes"]
                .as_u64()
                .is_some_and(|n| n >= floor)
            && v["experimental_peak_guard_includes_other_fleet_allocations"] == true
            && floor.checked_add(peak) == Some(p.minimum_free_bytes)
            && v["recorded_unix_seconds"]
                .as_u64()
                .is_some_and(|n| n <= now && now - n <= 900),
        "203 requires fresh full-continuation/assembly admission; native-only receipt is insufficient",
    )?;
    for flag in [
        "ordinary_replay_authorized",
        "canonical_sidecar_authorized",
        "publication_authorized",
        "retirement_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        require(
            v[flag] == false,
            "203 continuation admission grants ordinary/publication authority",
        )?;
    }
    Ok(())
}

fn scope(m: &HistoricalSegmentManifest) -> bool {
    m.epoch == EPOCH
        && m.output_slot_start == START
        && m.output_slot_count == ROOT - START + 1
        && m.bootstrap.slot == 87_695_515
        && m.terminal.slot == ROOT
        && m.archive_sha256 == sha(PREFIX_SHA).unwrap()
        && m.worker_executable_sha256 == sha(WORKER_SHA).unwrap()
        && m.runtime.runtime_profile == "solana-v1.6.16"
        && m.runtime.runtime_revision == "86c26f843276581509c3434acc2efbf4202c44e0"
        && m.runtime.genesis_hash == compatibility::MAINNET_GENESIS_HASH
        && m.runtime.runtime_admission == SegmentRuntimeAdmission::Candidate
        && m.runtime.generation_profile
            == "jetstreamer-node/0.7.0/old-faithful-to-horizon-v2@3de96e71010a8a2f5e629f666227b137483bff7b"
        && m.bootstrap_archive_sha256.is_none()
        && m.bootstrap.accounts_hash == "CYEr1vEwJyh2d4SSmnmYPYYj6EPhrDWTAJJCuzF2VhLX"
        && m.terminal.accounts_hash == "4SeHmKHQrHot4gwifo1bnvDKXZwGELk2vSenotTx9oqf"
}
impl ValidatedPrefix {
    fn check_native(
        &self,
        actual: &SegmentCheckpointSummary,
        worker: [u8; 32],
        cursor: u64,
        ticks: u64,
    ) -> Result<(), String> {
        require(
            scope(&self.manifest)
                && worker == sha(WORKER_SHA)?
                && ticks == 64
                && actual.next_write_version == cursor
                && actual.write_count == 0,
            "203 actual suffix worker/cursor/ticks/bootstrap writes differ",
        )?;
        // Native cursors are validator-local; never compare this cursor with the
        // retained prefix's cursor. Consensus fields must still match exactly.
        checkpoint_matches(&self.manifest.terminal, actual)
    }
}
impl RestartProof for ValidatedPrefix {
    fn snapshot_sha256(&self) -> [u8; 32] {
        sha(SNAPSHOT_SHA).unwrap()
    }
    fn snapshot_size(&self) -> u64 {
        SNAPSHOT_SIZE
    }
    fn covers_trusted_root(&self, e: u64, b: u64, s: u64, n: u64) -> bool {
        e == EPOCH && b == ROOT && s == ROOT + 1 && n == END && scope(&self.manifest)
    }
    fn validate_invocation(
        &self,
        e: u64,
        b: &ReplayBootstrap,
        q: Option<QualificationPlan>,
        c: bool,
        a: bool,
        r: bool,
    ) -> Result<(), String> {
        require(
            cfg!(feature = "epoch203-checkpoint-continuation-diagnostic")
                && !c
                && !a
                && !r
                && b.snapshot_archive() == Some(self.snapshot.as_path())
                && q.is_some_and(|q| {
                    q.epoch == EPOCH
                        && q.replay_start == ROOT + 1
                        && self.covers_trusted_root(
                            e,
                            q.bootstrap_slot,
                            q.output_slot_start,
                            q.end_inclusive,
                        )
                }),
            "203 restart proof cannot authorize another span, runtime carry or ordinary reuse",
        )
    }
    fn verify_native_checkpoint(
        &self,
        a: &historical::HistoricalCheckpoint,
        w: [u8; 32],
        cursor: u64,
        ticks: u64,
    ) -> Result<(), String> {
        let summary = segment_checkpoint_summary(
            &historical_replay::HistoricalCheckpointSummary::try_from(a)?,
        );
        self.check_native(&summary, w, cursor, ticks)?;
        let elapsed: u64 = self
            .runner_started
            .elapsed()
            .as_millis()
            .try_into()
            .map_err(|_| "203 native timing overflow")?;
        self.native_barrier_millis
            .compare_exchange(u64::MAX, elapsed, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| "203 native restart barrier was attempted twice")?;
        info!(
            "private203 native restart barrier passed before any suffix entry; initialized cursor preserved, bootstrap writes=0, runner_to_native_barrier_millis={elapsed}"
        );
        Ok(())
    }
}
fn native_proof(v: &Value, m: &HistoricalSegmentManifest) -> Result<(), String> {
    require(
        v["schema"] == "jetstreamer-private-epoch203-native-restore-probe-v1"
            && v["passed"] == true
            && v["worker_sha256"] == WORKER_SHA
            && v["snapshot_sha256"] == SNAPSHOT_SHA
            && v["prefix_manifest_sha256"] == MANIFEST_SHA
            && v["replay_entries_sent"] == 0
            && v["snapshot_bytes"] == SNAPSHOT_SIZE
            && v["prefix_manifest_content_sha256"]
                == jetstreamer_node::segment_manifest::sha256_hex_string(
                    &m.content_sha256().map_err(|e| e.to_string())?,
                )
            && v["executing_suffix_must_repeat_native_tuple_check"] == true
            && v["native_result"]["comparison_passed"] == true
            && v["native_result"]["shutdown_passed"] == true,
        "203 native-only result is not the exact successful comparison",
    )?;
    for flag in [
        "replay_launch_authorized",
        "assembly_authorized",
        "publication_authorized",
        "local_retirement_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        require(v[flag] == false, "203 native result grants authority")?;
    }
    let mut checkpoint = v["native_result"]["native_checkpoint"].clone();
    let cursor = checkpoint["initialized_next_write_version"]
        .as_u64()
        .ok_or("native cursor missing")?;
    let ticks = checkpoint["initialized_ticks_per_slot"]
        .as_u64()
        .ok_or("native ticks missing")?;
    let fields = checkpoint
        .as_object_mut()
        .ok_or("native checkpoint missing")?;
    fields.remove("initialized_next_write_version");
    fields.remove("initialized_ticks_per_slot");
    let checkpoint: SegmentCheckpointSummary =
        serde_json::from_value(checkpoint).map_err(|e| e.to_string())?;
    ValidatedPrefix {
        manifest: m.clone(),
        snapshot: "/unused".into(),
        runner_started: std::time::Instant::now(),
        native_barrier_millis: std::sync::atomic::AtomicU64::new(u64::MAX),
    }
    .check_native(&checkpoint, sha(WORKER_SHA)?, cursor, ticks)
}
fn provenance(
    prefix: &HistoricalSegmentManifest,
    suffix: &HistoricalSegmentManifest,
) -> Result<ArchiveProvenanceV4, String> {
    prefix.validate().map_err(|e| e.to_string())?;
    suffix.validate().map_err(|e| e.to_string())?;
    require(
        scope(prefix)
            && suffix.epoch == EPOCH
            && suffix.bootstrap.slot == ROOT
            && suffix.output_slot_start == ROOT + 1
            && suffix.output_slot_count == END - ROOT
            && suffix.terminal.slot == END
            && suffix.bootstrap_archive_sha256 == Some(sha(SNAPSHOT_SHA)?)
            && suffix.worker_executable_sha256 == sha(WORKER_SHA)?
            && suffix.runtime.runtime_profile == prefix.runtime.runtime_profile
            && suffix.runtime.runtime_admission == SegmentRuntimeAdmission::Candidate
            && suffix.runtime.runtime_revision == prefix.runtime.runtime_revision
            && suffix.runtime.genesis_hash == prefix.runtime.genesis_hash
            && suffix.runtime.runtime_target == prefix.runtime.runtime_target,
        "203 assembly source scope/runtime differs",
    )?;
    checkpoint_matches(&prefix.terminal, &suffix.bootstrap)?;
    let mut start = 0;
    let mut segments = Vec::new();
    for source in [prefix, suffix] {
        let mapping = WriteVersionNormalization {
            worker_start: source.emitted_raw_write_versions.start,
            worker_end_exclusive: source.emitted_raw_write_versions.end,
            archive_start: start,
        };
        start = mapping
            .archive_end_exclusive()
            .ok_or("203 normalized cursor overflow")?;
        segments.push(RuntimeSegmentProvenance {
            slot_start: source.output_slot_start,
            slot_count: source.output_slot_count,
            generation_profile: source.runtime.generation_profile.clone(),
            runtime_profile: source.runtime.runtime_profile.clone(),
            runtime_admission: match source.runtime.runtime_admission {
                SegmentRuntimeAdmission::Verified => RuntimeAdmission::Verified,
                SegmentRuntimeAdmission::Candidate => RuntimeAdmission::Candidate,
            },
            runtime_revision: source.runtime.runtime_revision.clone(),
            runtime_toolchain: source.runtime.runtime_toolchain.clone(),
            worker_executable_sha256: Some(source.worker_executable_sha256),
            write_versions: mapping,
        });
    }
    let value = ArchiveProvenanceV4 {
        base: ArchiveProvenanceV3 {
            assembly_profile: format!(
                "{}/epoch203-checkpoint-continuation-v1",
                archive_generation_profile()
            ),
            genesis_hash: prefix
                .runtime
                .genesis_hash
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
            requested_slot_count: END - START + 1,
            transaction_metadata: archive_transaction_metadata_policy(START, END - START + 1),
            runtime_segments: segments,
            handoffs: vec![RuntimeHandoffProvenance {
                boundary_slot: ROOT + 1,
                predecessor: runtime_checkpoint(&prefix.terminal)?,
                successor: runtime_checkpoint(&suffix.bootstrap)?,
                successor_bootstrap_kind: BootstrapStateKind::SnapshotArchive,
                successor_bootstrap_archive_sha256: sha(SNAPSHOT_SHA)?,
                successor_bootstrap_write_count: suffix.bootstrap.write_count,
            }],
        },
    };
    value.validate().map_err(|e| e.to_string())?;
    Ok(value)
}
pub(crate) async fn run(
    plan_path: PathBuf,
    plan_sha: String,
    destination: PathBuf,
    shutdown: Arc<AtomicBool>,
    cursor: Arc<ReplayCursor>,
    tracker: Arc<RestartTracker>,
) -> Result<(), String> {
    require(
        cfg!(feature = "epoch203-checkpoint-continuation-diagnostic"),
        "dedicated203 continuation build required",
    )?;
    let p: Plan = serde_json::from_slice(&sealed_bytes(
        &Evidence {
            path: plan_path.clone(),
            sha256: plan_sha.clone(),
        },
        1 << 20,
    )?)
    .map_err(|e| e.to_string())?;
    validate_plan(&p, &destination)?;
    sealed_bytes(
        &Evidence {
            path: fs::read_link("/proc/self/exe").map_err(|e| e.to_string())?,
            sha256: p.node_sha256.clone(),
        },
        256 << 20,
    )?;
    require(
        unsafe { libc::geteuid() } == 1000,
        "203 continuation requires isolated UID1000",
    )?;
    let invocation = authenticate_service(&p.producer_unit)?;
    let admitted: Value = serde_json::from_slice(&sealed_bytes(&p.admission_receipt, 4 << 20)?)
        .map_err(|e| e.to_string())?;
    admission(
        &p,
        &admitted,
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_secs(),
    )?;
    let metadata = fs::symlink_metadata(&p.run_root).map_err(|e| e.to_string())?;
    require(
        p.run_root.canonicalize().map_err(|e| e.to_string())? == p.run_root
            && metadata.is_dir()
            && metadata.uid() == 1000
            && metadata.mode() & 0o077 == 0
            && fs::read_dir(&p.run_root)
                .map_err(|e| e.to_string())?
                .next()
                .is_none(),
        "203 private run root is not fresh/owner-only",
    )?;
    let lease = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(Path::new(PRIVATE_ROOT).join("checkpoint-continuation-203.lock"))
        .map_err(|e| e.to_string())?;
    let lm = lease.metadata().map_err(|e| e.to_string())?;
    require(
        lm.is_file()
            && lm.nlink() == 1
            && lm.uid() == 1000
            && lm.mode() & 0o077 == 0
            && unsafe { libc::flock(lease.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "203 continuation lease occupied or unsafe",
    )?;
    let candidate = env_truthy_default("JETSTREAMER_ALLOW_CANDIDATE_RUNTIME", false);
    let selection = select_runtime_for_invocation(ROOT + 1..END + 1, candidate, true)?;
    require(
        selection.backend == compatibility::RuntimeBackend::SolanaV1_6_16
            && configured_historical_worker_executable(selection.descriptor)? == p.worker.path,
        "203 exact registry/worker differs",
    )?;
    sealed_bytes(&p.worker, 256 << 20)?;
    sealed_bytes(&p.prefix_manifest, 1 << 20)?;
    let native: Value = serde_json::from_slice(&sealed_bytes(&p.native_probe, 4 << 20)?)
        .map_err(|e| e.to_string())?;
    let genesis = sealed_bytes(&p.genesis_archive, 10 << 20)?;
    require_retained_input(&p.prefix_archive.path, PREFIX_SIZE)?;
    require_retained_input(&p.restart_snapshot.path, SNAPSHOT_SIZE)?;
    let prefix_file = open_regular_nofollow(&p.prefix_archive.path).map_err(|e| e.to_string())?;
    let identity = archive_file_identity(&prefix_file).map_err(|e| e.to_string())?;
    require_no_checksum(&p.prefix_archive.path)?;
    require(
        available_bytes(&p.run_root)? >= p.minimum_free_bytes,
        "203 full continuation peak not admitted",
    )?;
    let archive = p.prefix_archive.path.clone();
    let manifest = p.prefix_manifest.path.clone();
    let prefix_started = std::time::Instant::now();
    info!("independently rereading complete retained203prefix before private continuation");
    let manifest = tokio::task::spawn_blocking(move || {
        read_and_validate_segment_manifest_from(archive, manifest).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())??;
    require(
        scope(&manifest)
            && path_matches_archive_identity(&p.prefix_archive.path, identity)
                .map_err(|e| e.to_string())?,
        "203 independently validated prefix changed",
    )?;
    native_proof(&native, &manifest)?;
    let prefix_validation_millis: u64 = prefix_started
        .elapsed()
        .as_millis()
        .try_into()
        .map_err(|_| "203 prefix timing overflow")?;
    info!(
        "private203 complete retained prefix reread passed; prefix_validation_millis={prefix_validation_millis}"
    );
    require_no_checksum(&p.prefix_archive.path)?;
    admission(
        &p,
        &admitted,
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_secs(),
    )?;
    require(
        !shutdown.load(Ordering::SeqCst) && available_bytes(&p.run_root)? >= p.minimum_free_bytes,
        "203 admission changed during prefix reread",
    )?;
    for name in ["ledger", "scratch", "output", "receipts"] {
        create_private_dir(&p.run_root.join(name))?;
    }
    write_new(&destination.join("genesis.tar.bz2"), &genesis)?;
    let validated = ValidatedPrefix {
        manifest,
        snapshot: p.restart_snapshot.path.clone(),
        runner_started: std::time::Instant::now(),
        native_barrier_millis: std::sync::atomic::AtomicU64::new(u64::MAX),
    };
    let suffix = p.run_root.join("output/epoch-203-suffix.jet");
    let output = p
        .run_root
        .join("output/epoch-203-checkpoint-restart-v4.jet");
    require_no_checksum(&suffix)?;
    require_no_checksum(&output)?;
    let q = QualificationPlan {
        epoch: EPOCH,
        bootstrap_slot: ROOT,
        replay_start: ROOT + 1,
        output_slot_start: ROOT + 1,
        end_inclusive: END,
    };
    let verifier = Arc::new(SnapshotVerifier::new(
        BTreeMap::from([(
            ROOT,
            BankHashExpectation::LegacyAccountsHash(
                validated
                    .manifest
                    .terminal
                    .accounts_hash
                    .parse::<Hash>()
                    .map_err(|e| e.to_string())?,
            ),
        )]),
        Some(shutdown.clone()),
    ));
    let result = run_geyser_replay(
        EPOCH,
        candidate,
        &destination,
        &p.run_root.join("scratch"),
        &ReplayBootstrap::SnapshotArchive(validated.snapshot.clone()),
        shutdown.clone(),
        cursor,
        tracker,
        Some(verifier.clone()),
        suffix.clone(),
        Some(q),
        None,
        None,
        None,
        None,
        None,
        None,
        false,
        Some(&validated),
        epoch223_qualification::TailMode::Disabled,
    )
    .await?
    .completed()?;
    let suffix_runner_millis: u64 = validated
        .runner_started
        .elapsed()
        .as_millis()
        .try_into()
        .map_err(|_| "203 suffix timing overflow")?;
    let native_barrier_millis = validated.native_barrier_millis.load(Ordering::SeqCst);
    let suffix_after_native_barrier_millis = suffix_runner_millis
        .checked_sub(native_barrier_millis)
        .ok_or("203 missing native barrier timing")?;
    info!(
        "private203 suffix replay returned; suffix_after_native_barrier_millis={suffix_after_native_barrier_millis}"
    );
    require(
        !shutdown.load(Ordering::SeqCst),
        "203 continuation interrupted",
    )?;
    verifier.finish()?;
    require(
        fs::metadata(&suffix).map_err(|e| e.to_string())?.len() <= 8u64 << 30,
        "203 suffix exceeded experimental8GiB reservation; preserve output and requalify peak before assembly",
    )?;
    publish_historical_segment_manifest(EPOCH, q, &suffix, &result, candidate)?;
    require_no_checksum(&suffix)?;
    let suffix_manifest = read_and_validate_segment_manifest(&suffix).map_err(|e| e.to_string())?;
    let provenance = provenance(&validated.manifest, &suffix_manifest)?;
    require(
        available_bytes(&p.run_root)?
            >= admitted["protected_existing_floor_bytes"]
                .as_u64()
                .ok_or("203 protected floor missing")?
                .checked_add(PREFIX_SIZE + (32 << 30))
                .ok_or("203 assembly reserve overflow")?,
        "203 assembly output reserve unavailable; preserve complete suffix",
    )?;
    let assembly_started = std::time::Instant::now();
    let assembled = assemble_sources(
        &p.prefix_archive.path,
        &validated.manifest,
        &suffix,
        &suffix_manifest,
        &output,
        &provenance,
    )?;
    let assembly_millis: u64 = assembly_started
        .elapsed()
        .as_millis()
        .try_into()
        .map_err(|_| "203 assembly timing overflow")?;
    require_no_checksum(&p.prefix_archive.path)?;
    require_no_checksum(&suffix)?;
    require_no_checksum(&output)?;
    let receipt = json!({"schema":"jetstreamer-private-epoch203-checkpoint-continuation-v1","producer_unit":p.producer_unit,
        "producer_invocation_id":invocation,"node_sha256":p.node_sha256,"plan":{"path":plan_path,"sha256":plan_sha},
        "prefix_archive_sha256":PREFIX_SHA,"restart_snapshot_sha256":SNAPSHOT_SHA,"prior_native_result_sha256":NATIVE_SHA,
        "suffix_archive_sha256":jetstreamer_node::segment_manifest::sha256_hex_string(&suffix_manifest.archive_sha256),
        "private_output":output,"assembly":assembled,"fresh_prefix_full_validation_passed":true,"fresh_native_checkpoint_matches":true,
        "timings":{"prefix_validation_millis":prefix_validation_millis,"suffix_runner_to_native_barrier_millis":native_barrier_millis,
            "suffix_after_native_barrier_millis":suffix_after_native_barrier_millis,"assembly_millis":assembly_millis},
        "canonical_root_slot":ROOT,"remaining_slots":END-ROOT,"independent_final_archive_verification_passed":false,
        "current_plugin_verification_passed":false,"initial_boundary_requires_separate_adjacent_evidence":true,
        "canonical_sidecar_authorized":false,"publication_authorized":false,"retirement_authorized":false,"r2_mutations":false});
    let mut bytes = serde_json::to_vec_pretty(&receipt).map_err(|e| e.to_string())?;
    bytes.push(b'\n');
    write_new(&p.run_root.join("receipts/continuation.json"), &bytes)?;
    info!("private203 continuation assembled; final/plugin/import/publication gates remain closed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    const NATIVE_CURSOR: u64 = 83_354_404_203;
    fn prefix() -> HistoricalSegmentManifest {
        let bytes = include_bytes!("../tests/fixtures/epoch203-capped-shrink-root.manifest.json");
        assert_eq!(
            <[u8; 32]>::from(Sha256::digest(bytes)),
            sha(MANIFEST_SHA).unwrap()
        );
        serde_json::from_slice(bytes).unwrap()
    }
    fn proof() -> ValidatedPrefix {
        ValidatedPrefix {
            manifest: prefix(),
            snapshot: "/snapshot".into(),
            runner_started: std::time::Instant::now(),
            native_barrier_millis: std::sync::atomic::AtomicU64::new(u64::MAX),
        }
    }
    fn native_summary() -> SegmentCheckpointSummary {
        let mut s = prefix().terminal;
        s.write_count = 0;
        s.next_write_version = NATIVE_CURSOR;
        s
    }
    fn plan() -> Plan {
        let b = |file: &str, hash: &str| Evidence {
            path: Path::new("/sealed").join(file),
            sha256: hash.into(),
        };
        Plan {
            schema: "jetstreamer-private-epoch203-checkpoint-continuation-plan-v1".into(),
            epoch: EPOCH,
            producer_unit: "horizon-qualify-203-checkpoint-continuation-test.service".into(),
            node_sha256: "a".repeat(64),
            prefix_archive: b("prefix.jet", PREFIX_SHA),
            prefix_manifest: b("prefix.segment.json", MANIFEST_SHA),
            native_probe: b("native.json", NATIVE_SHA),
            restart_snapshot: b(
                "snapshot-88127580-4SeHmKHQrHot4gwifo1bnvDKXZwGELk2vSenotTx9oqf.tar.zst",
                SNAPSHOT_SHA,
            ),
            worker: b("worker", WORKER_SHA),
            genesis_archive: b("genesis.tar.bz2", GENESIS_SHA),
            admission_receipt: b("admission.json", &"b".repeat(64)),
            run_root: Path::new(PRIVATE_ROOT).join("checkpoint-continuation-203-test"),
            minimum_free_bytes: PROTECTED + MINIMUM_PEAK,
        }
    }
    fn admitted(p: &Plan) -> Value {
        json!({"schema":"jetstreamer-epoch203-continuation-admission-v1","admitted":true,
            "private_continuation_and_assembly_only":true,"epoch":EPOCH,"node_sha256":p.node_sha256,
            "prefix_sha256":PREFIX_SHA,"snapshot_sha256":SNAPSHOT_SHA,"native_result_sha256":NATIVE_SHA,
            "worker_sha256":WORKER_SHA,"remaining_slots":419,"candidate_incremental_peak_bytes":MINIMUM_PEAK,
            "protected_existing_floor_bytes":PROTECTED,"recorded_unix_seconds":1000,
            "required_guard_minimum_free_bytes":PROTECTED,"experimental_peak_guard_includes_other_fleet_allocations":true,
            "ordinary_replay_authorized":false,"canonical_sidecar_authorized":false,"publication_authorized":false,
            "retirement_authorized":false,"remote_mutations":false,"r2_mutations":false})
    }
    #[test]
    fn exact203_span_keeps_canonical_root_and_rejects_other_epochs_or_holes() {
        let p = proof();
        assert_eq!(END - ROOT, 419);
        assert_eq!(END - START + 1, 432000);
        assert!(p.covers_trusted_root(EPOCH, ROOT, ROOT + 1, END));
        for (e, b, s, n) in [
            (213, ROOT, ROOT + 1, END),
            (204, ROOT, ROOT + 1, END),
            (EPOCH, ROOT - 1, ROOT + 1, END),
            (EPOCH, ROOT, ROOT + 2, END),
            (EPOCH, ROOT, ROOT + 1, END + 1),
        ] {
            assert!(!p.covers_trusted_root(e, b, s, n));
        }
        let mut p = proof();
        p.manifest.terminal.slot -= 1;
        assert!(!p.covers_trusted_root(EPOCH, ROOT, ROOT + 1, END));
        let mut p = proof();
        p.manifest.runtime.generation_profile.push('x');
        assert!(!p.covers_trusted_root(EPOCH, ROOT, ROOT + 1, END));
    }
    #[test]
    fn unpromoted_registry_remains_closed_to_ordinary203_replay() {
        assert!(select_runtime_for_invocation(ROOT + 1..END + 1, true, false).is_err());
        let selected = select_runtime_for_invocation(ROOT + 1..END + 1, true, true).unwrap();
        assert_eq!(
            selected.backend,
            compatibility::RuntimeBackend::SolanaV1_6_16
        );
        assert!(select_runtime_for_invocation(ROOT + 1..END + 1, false, true).is_err());
    }
    #[test]
    fn actual_native_receipt_is_bit_exact_and_does_not_authorize_replay() {
        let bytes = include_bytes!("../tests/fixtures/epoch203-native-root-comparison.json");
        assert_eq!(
            <[u8; 32]>::from(Sha256::digest(bytes)),
            sha(NATIVE_SHA).unwrap()
        );
        let v: Value = serde_json::from_slice(bytes).unwrap();
        native_proof(&v, &prefix()).unwrap();
        assert_eq!(
            v["native_result"]["native_checkpoint"]["capitalization"].as_u64(),
            Some(499961377837934321)
        );
        for (k, bad) in [
            ("passed", json!(false)),
            ("replay_entries_sent", json!(1)),
            ("publication_authorized", json!(true)),
            ("prefix_manifest_content_sha256", json!("f".repeat(64))),
            ("worker_sha256", json!("f".repeat(64))),
        ] {
            let mut changed = v.clone();
            changed[k] = bad;
            assert!(native_proof(&changed, &prefix()).is_err(), "{k}");
        }
    }
    #[test]
    fn actual_suffix_barrier_checks_every_consensus_field_and_preserves_native_cursor() {
        let p = proof();
        let native = native_summary();
        let worker = sha(WORKER_SHA).unwrap();
        assert_ne!(
            native.next_write_version,
            p.manifest.terminal.next_write_version
        );
        p.check_native(&native, worker, NATIVE_CURSOR, 64).unwrap();
        let changes: [fn(&mut SegmentCheckpointSummary); 10] = [
            |v| v.slot += 1,
            |v| v.bank_hash.push('x'),
            |v| v.accounts_hash.push('x'),
            |v| v.last_blockhash.push('x'),
            |v| v.capitalization += 1,
            |v| v.transaction_count += 1,
            |v| v.tick_height += 1,
            |v| v.slot_complete = false,
            |v| v.write_count = 1,
            |v| v.next_write_version += 1,
        ];
        for change in changes {
            let mut bad = native.clone();
            change(&mut bad);
            assert!(p.check_native(&bad, worker, NATIVE_CURSOR, 64).is_err());
        }
        assert!(p.check_native(&native, worker, NATIVE_CURSOR, 63).is_err());
        assert!(p.check_native(&native, [0; 32], NATIVE_CURSOR, 64).is_err());
    }
    #[test]
    fn executing_barrier_can_only_record_success_once() {
        let p = proof();
        let s = native_summary();
        let hash = |v: &str| v.parse::<Hash>().unwrap().to_bytes();
        let mut actual = historical::HistoricalCheckpoint {
            slot: s.slot,
            bank_hash: hash(&s.bank_hash),
            accounts_hash: hash(&s.accounts_hash),
            last_blockhash: hash(&s.last_blockhash),
            capitalization: s.capitalization,
            transaction_count: s.transaction_count,
            tick_height: s.tick_height,
            slot_complete: true,
            writes: vec![],
            next_write_version: NATIVE_CURSOR,
        };
        actual.capitalization += 1;
        assert!(
            p.verify_native_checkpoint(&actual, sha(WORKER_SHA).unwrap(), NATIVE_CURSOR, 64)
                .is_err()
        );
        assert_eq!(p.native_barrier_millis.load(Ordering::SeqCst), u64::MAX);
        actual.capitalization -= 1;
        p.verify_native_checkpoint(&actual, sha(WORKER_SHA).unwrap(), NATIVE_CURSOR, 64)
            .unwrap();
        assert_ne!(p.native_barrier_millis.load(Ordering::SeqCst), u64::MAX);
        assert!(
            p.verify_native_checkpoint(&actual, sha(WORKER_SHA).unwrap(), NATIVE_CURSOR, 64)
                .is_err()
        );
    }
    #[test]
    fn full_path_admission_cannot_borrow_native_only_budget_or_mutation_authority() {
        let p = plan();
        validate_plan(&p, &p.run_root.join("ledger")).unwrap();
        let v = admitted(&p);
        admission(&p, &v, 1900).unwrap();
        assert!(admission(&p, &v, 1901).is_err());
        assert!(admission(&p, &v, 999).is_err());
        for (k, bad) in [
            (
                "schema",
                json!("jetstreamer-epoch203-native-admission-receipt-v1"),
            ),
            ("candidate_incremental_peak_bytes", json!(192u64 << 30)),
            ("protected_existing_floor_bytes", json!(PROTECTED - 1)),
            ("node_sha256", json!("f".repeat(64))),
            ("remaining_slots", json!(420)),
            ("retirement_authorized", json!(true)),
            ("remote_mutations", json!(true)),
            ("publication_authorized", json!(true)),
        ] {
            let mut changed = v.clone();
            changed[k] = bad;
            assert!(admission(&p, &changed, 1000).is_err(), "{k}");
        }
        let mut smaller = plan();
        smaller.minimum_free_bytes = PROTECTED + (192 << 30);
        assert!(validate_plan(&smaller, &smaller.run_root.join("ledger")).is_err());
    }
    #[test]
    fn plan_and_cli_cannot_enable_neighbor_replay_or_canonical_output() {
        assert_eq!(
            validate_cli((203, 203), Some(true), 1, true, false).is_ok(),
            cfg!(feature = "epoch203-checkpoint-continuation-diagnostic")
        );
        for (range, verify, count, destination, forbidden) in [
            ((213, 213), Some(true), 1, true, false),
            ((203, 204), Some(true), 1, true, false),
            ((203, 203), None, 1, true, false),
            ((203, 203), Some(true), 2, true, false),
            ((203, 203), Some(true), 1, false, false),
            ((203, 203), Some(true), 1, true, true),
        ] {
            assert!(validate_cli(range, verify, count, destination, forbidden).is_err());
        }
        let mut p = plan();
        p.worker.sha256 = "f".repeat(64);
        assert!(validate_plan(&p, &p.run_root.join("ledger")).is_err());
        let mut encoded = serde_json::to_value(plan()).unwrap();
        encoded["publication_authorized"] = json!(true);
        assert!(serde_json::from_value::<Plan>(encoded).is_err());
    }
    #[test]
    fn v4_preserves_both_generations_and_only_normalizes_local_write_versions() {
        let p = prefix();
        let mut s = p.clone();
        s.bootstrap = native_summary();
        s.bootstrap_archive_sha256 = Some(sha(SNAPSHOT_SHA).unwrap());
        s.output_slot_start = ROOT + 1;
        s.output_slot_count = END - ROOT;
        s.terminal.slot = END;
        s.terminal.tick_height = (END + 1) * 64;
        s.terminal.write_count = 0;
        s.terminal.next_write_version = NATIVE_CURSOR + 100;
        s.emitted_raw_write_versions = NATIVE_CURSOR..NATIVE_CURSOR + 100;
        s.archive_sha256 = [7; 32];
        s.runtime
            .generation_profile
            .push_str("-independent-suffix-test");
        let v = provenance(&p, &s).unwrap();
        assert_eq!(v.base.requested_slot_count, 432000);
        assert_eq!(v.base.runtime_segments[1].slot_count, 419);
        assert_eq!(v.base.runtime_segments[0].write_versions.archive_start, 0);
        assert_eq!(
            v.base.runtime_segments[1].write_versions.archive_start,
            p.emitted_raw_write_versions.end - p.emitted_raw_write_versions.start
        );
        assert_ne!(
            v.base.runtime_segments[0].generation_profile,
            v.base.runtime_segments[1].generation_profile
        );
        assert_ne!(
            v.base.handoffs[0].predecessor.next_write_version,
            v.base.handoffs[0].successor.next_write_version
        );
        s.output_slot_start += 1;
        assert!(provenance(&p, &s).is_err());
        s.output_slot_start -= 1;
        s.runtime.runtime_admission = SegmentRuntimeAdmission::Verified;
        assert!(provenance(&p, &s).is_err());
    }
}
