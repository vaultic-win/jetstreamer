//! Private stock replay from the independently verified epoch 229 repair.
//! The donor includes the 310-slot verification tail. Canonical assembly must
//! select only the epoch's slots and preserve the separately witnessed tail root.

use super::checkpoint_continuation::{
    Evidence, RestartProof, authenticate_service, available_bytes, checkpoint_matches,
    create_private_dir, require, require_no_checksum, require_retained_input, sealed_bytes, sha,
    write_new,
};
use super::*;
use jetstreamer_node::segment_manifest::{
    SegmentRuntimeAdmission, read_and_validate_segment_manifest_from, sha256_hex_string,
};
use serde_json::{Value, json};
use std::os::unix::fs::MetadataExt;

const EPOCH: u64 = 229;
const START: u64 = 98_928_000;
const RESTART: u64 = 98_939_266;
const LAST_ARCHIVE_SLOT: u64 = 99_359_999;
const INTERNAL_ROOT: u64 = 99_359_376;
const TAIL_ROOT: u64 = 99_360_309;
const BOUNDARY_ROOT: &str = "61jJuhUUEDjQKbwocjURSWvzujFopxnh2hQetKKRcrp7";
const INTERNAL_HASH: &str = "CykUWyU9f91ZqjX3tbHTsU4XK1zyBjLYTkkxvb2VdsUn";
const TAIL_HASH: &str = "8sB6zTNkYnAA9H9jM2YvXMnYLUvWy1nLEhssbC27p96a";
const RETURNED_PREFIX: &str = "d59c749b2688d773cbd6188bdaf972dba6a8cfb404aae85cf36529f41a154bd1";
const PREFIX: &str = "92ae7627d57e1c75d2be8898d146fd09c76947d4b06201d8b7fc52913f296359";
const PREFIX_WORKER: &str = "e92a4c508ea5e9155f4294cb0e7e8399f3ff81821a356bb0a958da5fa49f2695";
const PREFIX_SIZE: u64 = 3_667_632_797;
const SNAPSHOT: &str = "922cf4b44ca74f311890e040ddac76d63024fec5b11a14c71f00887a14c6bcf9";
const SNAPSHOT_SIZE: u64 = 10_116_745_902;
const WORKER: &str = "f39140b9a9659e7c6e8207076a2d0c560a6b69df42cc92e19a421cf46c2b761c";
const GENESIS: &str = "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945";
const RESTORE: &str = "2ecb0c64bfbce709f7f8a5c5941a235987ca4f61c2cd58b2f4c29242e2050db8";
const PRIVATE_ROOT: &str = "/home/ubuntu/.jetstreamer-private";

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
    native_restore: Evidence,
    snapshot: Evidence,
    worker: Evidence,
    genesis: Evidence,
}

pub(crate) fn validate_entrypoint(args: &[String]) -> Result<(), String> {
    if args.is_empty() || matches!(args, [one] if one == "-h" || one == "--help") {
        return Ok(());
    }
    require(
        matches!(args, [epoch, dest, verify, plan, digest]
            if epoch == "229" && Path::new(dest).is_absolute() && verify == "--verify"
                && plan.starts_with("--checkpoint-continuation-plan=")
                && digest.starts_with("--checkpoint-continuation-plan-sha256=")),
        "private 229 build requires: 229 DEST --verify --checkpoint-continuation-plan=PATH --checkpoint-continuation-plan-sha256=HEX",
    )
}

pub(crate) fn validate_cli(
    epochs: (u64, u64),
    verify: Option<bool>,
    verify_count: usize,
    destination: bool,
    forbidden: bool,
) -> Result<(), String> {
    require(
        epochs == (EPOCH, EPOCH)
            && verify == Some(true)
            && verify_count == 1
            && destination
            && !forbidden,
        "229 private continuation requires exactly its plan, destination, and explicit verification",
    )
}

fn validate_plan(plan: &Plan, destination: &Path) -> Result<(), String> {
    let leaf = plan
        .run_root
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    require(
        plan.schema == "jetstreamer-private-epoch229-stock-continuation-plan-v1"
            && plan.run_root.parent() == Some(Path::new(PRIVATE_ROOT))
            && leaf.starts_with("checkpoint-continuation-229-")
            && leaf.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && plan.producer_unit == format!("horizon-qualify-{leaf}.service")
            && destination == plan.run_root.join("ledger")
            && sha(&plan.node_sha256)? != [0; 32],
        "229 continuation needs an exact private destination, owner and node digest",
    )?;
    for (source, digest) in [
        (&plan.prefix_archive, PREFIX),
        (&plan.prefix_manifest, RETURNED_PREFIX),
        (&plan.native_restore, RESTORE),
        (&plan.snapshot, SNAPSHOT),
        (&plan.worker, WORKER),
        (&plan.genesis, GENESIS),
    ] {
        require(
            source.sha256 == digest
                && source.path.is_absolute()
                && !source.path.starts_with(&plan.run_root),
            "229 retained input is outside the qualified digest or path scope",
        )?;
    }
    Ok(())
}

fn admission(plan: &Plan) -> Result<(), String> {
    let value: Value = serde_json::from_slice(&sealed_bytes(&plan.admission, 1 << 20)?)
        .map_err(|e| e.to_string())?;
    let age = value["recorded_unix_seconds"].as_u64().and_then(|at| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()?
            .as_secs()
            .checked_sub(at)
    });
    require(
        value["schema"] == "jetstreamer-epoch229-stock-continuation-admission-v1"
            && value["epoch"] == EPOCH
            && value["admitted"] == true
            && value["node_sha256"] == plan.node_sha256
            && value["producer_unit"] == plan.producer_unit
            && value["run_root"] == plan.run_root.to_string_lossy().as_ref()
            && value["minimum_free_bytes"] == plan.minimum_free_bytes
            && plan.minimum_free_bytes > 0
            && value["complete_fleet_and_century_floor_bound"] == true
            && value["actual_guard_and_owner_qualified"] == true
            && value["full_continuation_peak_qualified"] == true
            && value["publication_authorized"] == false
            && age.is_some_and(|seconds| seconds <= 900)
            && available_bytes(&plan.run_root)? >= plan.minimum_free_bytes,
        "229 requires fresh guarded admission for the full private continuation",
    )
}

struct ValidatedPrefix {
    manifest: HistoricalSegmentManifest,
    snapshot: PathBuf,
    verified: AtomicBool,
}

impl RestartProof for ValidatedPrefix {
    fn snapshot_sha256(&self) -> [u8; 32] {
        sha(SNAPSHOT).expect("literal digest")
    }

    fn snapshot_size(&self) -> u64 {
        SNAPSHOT_SIZE
    }

    fn covers_trusted_root(&self, _: u64, _: u64, _: u64, _: u64) -> bool {
        // This route has a trusted post-bootstrap root. It must never opt into
        // the short continuation exception for a span without one.
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
                && !carried
                && !audited
                && !retain
                && bootstrap.snapshot_archive() == Some(self.snapshot.as_path())
                && qualification.is_some_and(|plan| {
                    (
                        plan.epoch,
                        plan.bootstrap_slot,
                        plan.replay_start,
                        plan.output_slot_start,
                        plan.end_inclusive,
                    ) == (EPOCH, RESTART, RESTART + 1, RESTART + 1, TAIL_ROOT)
                }),
            "invalid invocation for the verified epoch 229 restart proof",
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
        require(
            worker == sha(WORKER)?
                && ticks_per_slot == 64
                && actual.next_write_version == initialized_cursor,
            "229 restored worker, tick unit or initial write cursor differs",
        )?;
        checkpoint_matches(&self.manifest.terminal, &actual)?;
        require(
            !self.verified.swap(true, Ordering::SeqCst),
            "229 native restart checked twice",
        )?;
        info!("verified epoch 229 stock restart at slot {RESTART} before replay entries");
        Ok(())
    }
}

pub(crate) async fn run(
    plan_path: PathBuf,
    plan_sha: String,
    destination: PathBuf,
    shutdown: Arc<AtomicBool>,
    cursor: Arc<ReplayCursor>,
    tracker: Arc<RestartTracker>,
) -> Result<(), String> {
    let plan_evidence = Evidence {
        path: plan_path,
        sha256: plan_sha,
    };
    let plan: Plan = serde_json::from_slice(&sealed_bytes(&plan_evidence, 1 << 20)?)
        .map_err(|e| e.to_string())?;
    validate_plan(&plan, &destination)?;
    require(
        unsafe { libc::geteuid() } == 1000,
        "229 requires isolated UID 1000",
    )?;
    let invocation = authenticate_service(&plan.producer_unit)?;
    let metadata = fs::symlink_metadata(&plan.run_root).map_err(|e| e.to_string())?;
    require(
        plan.run_root.canonicalize().map_err(|e| e.to_string())? == plan.run_root
            && metadata.is_dir()
            && metadata.uid() == 1000
            && metadata.mode() & 0o077 == 0
            && fs::read_dir(&plan.run_root)
                .map_err(|e| e.to_string())?
                .next()
                .is_none(),
        "229 run root must be fresh and private",
    )?;
    sealed_bytes(
        &Evidence {
            path: fs::read_link("/proc/self/exe").map_err(|e| e.to_string())?,
            sha256: plan.node_sha256.clone(),
        },
        256 << 20,
    )?;
    admission(&plan)?;
    require_retained_input(&plan.prefix_archive.path, PREFIX_SIZE)?;
    require_retained_input(&plan.snapshot.path, SNAPSHOT_SIZE)?;
    require_no_checksum(&plan.prefix_archive.path)?;
    let prefix_bytes = sealed_bytes(&plan.prefix_manifest, 1 << 20)?;
    let pinned_prefix: HistoricalSegmentManifest =
        serde_json::from_slice(&prefix_bytes).map_err(|e| e.to_string())?;
    let manifest = read_and_validate_segment_manifest_from(
        &plan.prefix_archive.path,
        &plan.prefix_manifest.path,
    )
    .map_err(|e| e.to_string())?;
    require(
        manifest == pinned_prefix
            && (
                manifest.epoch,
                manifest.output_slot_start,
                manifest.output_slot_count,
                manifest.terminal.slot,
            ) == (EPOCH, START, RESTART - START + 1, RESTART)
            && manifest.archive_sha256 == sha(PREFIX)?
            && manifest.worker_executable_sha256 == sha(PREFIX_WORKER)?
            && manifest.runtime.runtime_admission == SegmentRuntimeAdmission::Candidate
            && manifest.terminal.accounts_hash == BOUNDARY_ROOT,
        "229 prefix reread disagrees with its independently verified scope",
    )?;
    sealed_bytes(&plan.native_restore, 1 << 20)?;
    sealed_bytes(&plan.worker, 32 << 20)?;
    let genesis = sealed_bytes(&plan.genesis, 1 << 20)?;
    let selection = select_runtime_with_snapshot_warmup_for_invocation(
        RESTART + 1,
        RESTART + 1..TAIL_ROOT + 1,
        true,
        true,
    )?;
    require(
        selection.backend == compatibility::RuntimeBackend::SolanaV1_6_20
            && configured_historical_worker_executable(selection.descriptor)? == plan.worker.path,
        "229 requires the exact stock v1.6.20 worker",
    )?;
    require(
        available_bytes(&plan.run_root)? >= plan.minimum_free_bytes,
        "229 free space changed during prefix reread",
    )?;
    for leaf in ["ledger", "scratch", "output", "receipts"] {
        create_private_dir(&plan.run_root.join(leaf))?;
    }
    write_new(&destination.join("genesis.tar.bz2"), &genesis)?;
    let proof = ValidatedPrefix {
        manifest,
        snapshot: plan.snapshot.path.clone(),
        verified: AtomicBool::new(false),
    };
    let expected = [
        (RESTART, BOUNDARY_ROOT),
        (INTERNAL_ROOT, INTERNAL_HASH),
        (TAIL_ROOT, TAIL_HASH),
    ]
    .into_iter()
    .map(|(slot, hash)| {
        hash.parse::<Hash>()
            .map(|hash| (slot, BankHashExpectation::LegacyAccountsHash(hash)))
            .map_err(|e| e.to_string())
    })
    .collect::<Result<BTreeMap<_, _>, _>>()?;
    let verifier = Arc::new(SnapshotVerifier::new(expected, Some(shutdown.clone())));
    let q = QualificationPlan {
        epoch: EPOCH,
        bootstrap_slot: RESTART,
        replay_start: RESTART + 1,
        output_slot_start: RESTART + 1,
        end_inclusive: TAIL_ROOT,
    };
    let output = plan
        .run_root
        .join("output/epoch-229-stock-suffix-with-private-tail.jet");
    let result = run_geyser_replay(
        EPOCH,
        true,
        &destination,
        &plan.run_root.join("scratch"),
        &ReplayBootstrap::SnapshotArchive(proof.snapshot.clone()),
        shutdown.clone(),
        cursor,
        tracker,
        Some(verifier.clone()),
        output.clone(),
        Some(q),
        None,
        None,
        None,
        None,
        None,
        None,
        false,
        Some(&proof),
        epoch223_qualification::TailMode::Disabled,
    )
    .await?
    .completed()?;
    require(
        !shutdown.load(Ordering::Relaxed) && proof.verified.load(Ordering::SeqCst),
        "229 replay interrupted or no native restart barrier",
    )?;
    verifier.finish()?;
    let completed = publish_historical_segment_manifest(EPOCH, q, &output, &result)?;
    require(
        completed.bootstrap.slot == RESTART
            && completed.terminal.slot == TAIL_ROOT
            && completed.terminal.accounts_hash == TAIL_HASH
            && completed.worker_executable_sha256 == sha(WORKER)?,
        "229 closed donor disagrees with the stock replay scope",
    )?;
    checkpoint_matches(&proof.manifest.terminal, &completed.bootstrap)?;
    require_no_checksum(&output)?;
    let receipt = json!({"schema":"jetstreamer-private-epoch229-stock-continuation-v1", "epoch":EPOCH,
        "invocation_id":invocation, "plan":plan_evidence, "archive":output,
        "archive_sha256":sha256_hex_string(&completed.archive_sha256),
        "restart_slot":RESTART, "canonical_output_last_slot":LAST_ARCHIVE_SLOT,
        "private_tail_slots":TAIL_ROOT - LAST_ARCHIVE_SLOT, "verified_tail_slot":TAIL_ROOT,
        "actual_native_restart_verified":true, "archive_requires_exact_epoch_assembly":true,
        "canonical_sidecar_authorized":false, "publication_authorized":false, "r2_mutations":false});
    write_new(
        &plan.run_root.join("receipts/suffix.json"),
        &serde_json::to_vec_pretty(&receipt).map_err(|e| e.to_string())?,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn continuation_cli_rejects_foreign_epochs_and_output_overrides() {
        let argv = [
            "229",
            "/private/ledger",
            "--verify",
            "--checkpoint-continuation-plan=/private/plan.json",
            "--checkpoint-continuation-plan-sha256=example",
        ];
        assert!(validate_entrypoint(&argv.map(String::from)).is_ok());
        let mut changed = argv;
        changed[0] = "230";
        assert!(validate_entrypoint(&changed.map(String::from)).is_err());
        changed = argv;
        changed[3] = "--horizon-output=/private/unsupported.jet";
        assert!(validate_entrypoint(&changed.map(String::from)).is_err());
        assert!(validate_entrypoint(&["--probe-successor-boundary=99360000".into()]).is_err());
    }

    #[test]
    fn stock_selection_spans_the_canonical_suffix_and_private_tail() {
        let selection = select_runtime_with_snapshot_warmup_for_invocation(
            RESTART + 1,
            RESTART + 1..TAIL_ROOT + 1,
            true,
            true,
        )
        .unwrap();
        assert_eq!(
            selection.backend,
            compatibility::RuntimeBackend::SolanaV1_6_20
        );
        assert_eq!(LAST_ARCHIVE_SLOT - RESTART, 420_733);
        assert_eq!(TAIL_ROOT - LAST_ARCHIVE_SLOT, 310);
    }
}
