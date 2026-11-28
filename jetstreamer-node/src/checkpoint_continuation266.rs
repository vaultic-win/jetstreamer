//! Private replay from epoch 266's retained hourly checkpoint.

use super::checkpoint_continuation::{
    Evidence, RestartProof, authenticate_service, available_bytes, checkpoint_matches,
    create_private_dir, require, require_no_checksum, require_retained_input, sealed_bytes, sha,
    write_new,
};
use super::*;
use jetstreamer_horizon::archive::{ArchiveReader, SlotVisitor};
use jetstreamer_node::{
    archive_checksum::{
        measure_open_archive_cancellable, open_regular_nofollow, path_matches_archive_identity,
    },
    segment_manifest::{read_and_validate_segment_manifest_from, sha256_hex_string},
};
use serde_json::{Value, json};
use std::os::{fd::AsRawFd, unix::fs::MetadataExt as _};

const EPOCH: u64 = 266;
const FIRST: u64 = 114_912_000;
const SEAM: u64 = 114_923_430;
const BOOT: u64 = 114_929_697;
const END: u64 = 114_936_474;
const BOOT_ACCOUNTS: &str = "BevfHbX1MRE8ySXdbzp8WZB5i4W1spPhbsZ8UEUhU7di";
const END_ACCOUNTS: &str = "GqAWTNQiWMCFTZLC1N3SXe2NmykFDcMQdn4Saj4ALSCA";
const SNAPSHOT: &str = "6712b4359e3513c9fd76751e85e2fad23fb73bc55e034dec60bc77ade27c6d10";
const SNAPSHOT_BYTES: u64 = 15_514_070_431;
const WORKER: &str = "763f1aff1f752f0d9886f0f2324a73c9c66a154269d28931575744316bb2f220";
const GENESIS: &str = "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945";
const PREFIX: &str = "4567fbb6d2cf9aaa1d5286f165601f22a855eb04ebcc27904cdf3096dc93dd6f";
const PREDECESSOR: &str = "b154160e860730cf189de4edee4329d8a1796a29251b7b21380606063cae28ed";
const MANIFEST: &str = "41c8156de465034fb270ffa17f1baab18c1c68946a151238bc46c167f07b0211";
const TERMINAL: &str = "01a7855a952cd07179f08d2b44fd72dda9b5a3cde1f38c1a01ddc86ed96aa7e7";
const SCOPE: &str = "ec70d3ffac64780c46c8604896ffc0e393f4d9ba932108f979a600ee098e15e8";
const MIN_GUARD_FLOOR: u64 = 3_770_104_987_645;
const PRIVATE_ROOT: &str = "/home/ubuntu/.jetstreamer-private";

const WINDOW: QualificationPlan = QualificationPlan {
    epoch: EPOCH,
    bootstrap_slot: BOOT,
    replay_start: BOOT + 1,
    output_slot_start: BOOT + 1,
    end_inclusive: END,
};

const INDEXES: [(&str, &str, u64); 3] = [
    (
        "265/epoch-265-bafyreibgf4smruua7seioyolngrziiqsgeae3d4zmcvptg7m4xwzyafqwu-mainnet-slot-to-cid.index",
        "b7728d6947e43869b78118fe46109f8d5670af6d58ad3f0a1e2bc3261bc25f06",
        15_484_110,
    ),
    (
        "266/epoch-266-bafyreihxdx3dwzmgzbfpzo7z4n744c6cjnn63j3mg2mewkauxoa2tgxxqu-mainnet-slot-to-cid.index",
        "9be621a54768e2d22aafd0d639bbf7ae546e7e4eb6610c3dbf2723cf06c8a0b6",
        14_576_860,
    ),
    (
        "266/epoch-266-bafyreihxdx3dwzmgzbfpzo7z4n744c6cjnn63j3mg2mewkauxoa2tgxxqu-mainnet-cid-to-offset-and-size.index",
        "41c9792e0c142984a28f8f653f970223c5525d3c22bfef0df01cd3f7150ac915",
        9_348_706_694,
    ),
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    producer_unit: String,
    node_sha256: String,
    run_root: PathBuf,
    minimum_free_bytes: u64,
    admission: Evidence,
    source_window: Evidence,
    prefix: Evidence,
    predecessor: Evidence,
    predecessor_manifest: Evidence,
    predecessor_terminal: Evidence,
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
            if epoch == "266" && Path::new(dest).is_absolute() && verify == "--verify"
                && plan.starts_with("--checkpoint-continuation-plan=")
                && digest.starts_with("--checkpoint-continuation-plan-sha256=")),
        "private epoch 266 window requires: 266 DEST --verify --checkpoint-continuation-plan=PATH --checkpoint-continuation-plan-sha256=HEX",
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
        "private epoch 266 window requires its exact plan, destination and explicit verification",
    )
}

fn validate_plan(plan: &Plan, destination: &Path) -> Result<(), String> {
    let leaf = plan
        .run_root
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    require(
        plan.schema == "foundation-epoch266-private-window-plan-v1"
            && plan.run_root.parent() == Some(Path::new(PRIVATE_ROOT))
            && leaf.starts_with("checkpoint-continuation-266-")
            && leaf.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && plan.producer_unit == format!("horizon-qualify-{leaf}.service")
            && destination == plan.run_root.join("ledger")
            && sha(&plan.node_sha256)? != [0; 32]
            && plan.minimum_free_bytes >= MIN_GUARD_FLOOR,
        "epoch 266 plan has a foreign runtime, root or reserve floor",
    )?;
    for (input, expected) in [
        (&plan.source_window, SCOPE),
        (&plan.prefix, PREFIX),
        (&plan.predecessor, PREDECESSOR),
        (&plan.predecessor_manifest, MANIFEST),
        (&plan.predecessor_terminal, TERMINAL),
        (&plan.snapshot, SNAPSHOT),
        (&plan.worker, WORKER),
        (&plan.genesis, GENESIS),
    ] {
        require(
            input.path.is_absolute()
                && !input.path.starts_with(&plan.run_root)
                && input.sha256 == expected,
            "epoch 266 plan contains a foreign input path or digest",
        )?;
    }
    require(
        plan.snapshot
            .path
            .file_name()
            .and_then(|name| name.to_str())
            == Some("snapshot-114929697-BevfHbX1MRE8ySXdbzp8WZB5i4W1spPhbsZ8UEUhU7di.tar.zst"),
        "epoch 266 snapshot filename does not match the authenticated hourly checkpoint",
    )
}

fn read_json(evidence: &Evidence) -> Result<Value, String> {
    serde_json::from_slice(&sealed_bytes(evidence, 1 << 20)?).map_err(|err| err.to_string())
}

fn validate_admission(plan: &Plan) -> Result<(), String> {
    let receipt = read_json(&plan.admission)?;
    let age = receipt["recorded_unix_seconds"].as_u64().and_then(|at| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_secs()
            .checked_sub(at)
    });
    require(
        receipt["schema"] == "foundation-epoch266-private-window-admission-v1"
            && receipt["epoch"] == EPOCH
            && receipt["admitted"] == true
            && receipt["node_sha256"] == plan.node_sha256
            && receipt["producer_unit"] == plan.producer_unit
            && receipt["run_root"] == json!(plan.run_root)
            && receipt["source_window_sha256"] == SCOPE
            && receipt["minimum_free_bytes"] == plan.minimum_free_bytes
            && receipt["complete_fleet_and_century_floor_bound"] == true
            && receipt["startup_guard_qualified"] == true
            && receipt["publication_authorized"] == false
            && age.is_some_and(|seconds| seconds <= 900)
            && available_bytes(&plan.run_root)? >= plan.minimum_free_bytes,
        "epoch 266 window requires fresh guarded admission",
    )
}

fn check_readonly(file: &std::fs::File) -> Result<(), String> {
    let meta = file.metadata().map_err(|err| err.to_string())?;
    let mut stats = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    if unsafe { libc::fstatvfs(file.as_raw_fd(), stats.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let stats = unsafe { stats.assume_init() };
    require(
        meta.uid() == 0 && meta.mode() & 0o222 == 0 && stats.f_flag & libc::ST_RDONLY != 0,
        "epoch 266 runtime input is not sealed and projected read-only",
    )
}

fn validate_indexes(ledger: &Path, shutdown: &AtomicBool) -> Result<(), String> {
    for (name, digest, size) in INDEXES {
        let path = ledger.join("compact-indexes").join(name);
        require_retained_input(&path, size)?;
        let file = open_regular_nofollow(&path).map_err(|err| err.to_string())?;
        check_readonly(&file)?;
        let measured =
            measure_open_archive_cancellable(&file, shutdown).map_err(|err| err.to_string())?;
        require(
            measured.sha256 == sha(digest)?
                && path_matches_archive_identity(&path, measured.identity)
                    .map_err(|err| err.to_string())?,
            "epoch 266 compact index bytes changed",
        )?;
    }
    Ok(())
}

struct PrefixVisitor {
    next: u64,
    ordered: bool,
}

impl SlotVisitor for PrefixVisitor {
    fn on_slot_start(&mut self, slot: u64, _: jetstreamer_horizon::archive::SlotKind) {
        self.ordered &= slot == self.next;
        self.next += 1;
    }
}

fn read_prefix(plan: &Plan, shutdown: &AtomicBool) -> Result<SegmentCheckpointSummary, String> {
    require_retained_input(&plan.prefix.path, 5_060_736_774)?;
    require_no_checksum(&plan.prefix.path)?;
    let prefix = open_regular_nofollow(&plan.prefix.path).map_err(|err| err.to_string())?;
    let measured =
        measure_open_archive_cancellable(&prefix, shutdown).map_err(|err| err.to_string())?;
    require(
        measured.sha256 == sha(PREFIX)?,
        "epoch 266 retained prefix digest changed",
    )?;
    let mut reader = ArchiveReader::open(prefix).map_err(|err| err.to_string())?;
    let count = SEAM - FIRST + 1;
    require(
        reader.header().epoch == EPOCH
            && reader.header().slot_start == FIRST
            && reader.header().slot_count == count
            && reader
                .has_complete_slot_coverage()
                .map_err(|err| err.to_string())?,
        "epoch 266 retained prefix coverage changed",
    )?;
    let mut visitor = PrefixVisitor {
        next: FIRST,
        ordered: true,
    };
    let decoded = reader
        .read_slots(FIRST, count, &mut visitor)
        .map_err(|err| err.to_string())?;
    require(
        !shutdown.load(Ordering::Relaxed)
            && decoded == count
            && visitor.ordered
            && visitor.next == SEAM + 1
            && path_matches_archive_identity(&plan.prefix.path, measured.identity)
                .map_err(|err| err.to_string())?,
        "epoch 266 retained prefix failed its independent dense reread",
    )?;

    require_retained_input(&plan.predecessor.path, 2_645_271_492)?;
    require_no_checksum(&plan.predecessor.path)?;
    let sealed: HistoricalSegmentManifest =
        serde_json::from_slice(&sealed_bytes(&plan.predecessor_manifest, 1 << 20)?)
            .map_err(|err| err.to_string())?;
    let validated = read_and_validate_segment_manifest_from(
        &plan.predecessor.path,
        &plan.predecessor_manifest.path,
    )
    .map_err(|err| err.to_string())?;
    let terminal = read_json(&plan.predecessor_terminal)?;
    require(
        validated == sealed
            && validated.epoch == EPOCH
            && validated.output_slot_start == SEAM + 1
            && validated.output_slot_count == BOOT - SEAM
            && validated.archive_sha256 == sha(PREDECESSOR)?
            && validated.worker_executable_sha256 == sha(WORKER)?
            && validated.terminal.slot == BOOT
            && validated.terminal.accounts_hash == BOOT_ACCOUNTS
            && terminal["producer_drained"] == true
            && terminal["native_manifest_complete_verified"] == true
            && terminal["terminal_checkpoint"] == json!(validated.terminal),
        "epoch 266 predecessor no longer matches its verified terminal",
    )?;
    Ok(validated.terminal)
}

struct VerifiedRestart {
    terminal: SegmentCheckpointSummary,
    snapshot: PathBuf,
    verified: AtomicBool,
}

impl RestartProof for VerifiedRestart {
    fn snapshot_sha256(&self) -> [u8; 32] {
        sha(SNAPSHOT).expect("literal digest")
    }

    fn snapshot_size(&self) -> u64 {
        SNAPSHOT_BYTES
    }

    fn covers_trusted_root(&self, _: u64, _: u64, _: u64, _: u64) -> bool {
        false
    }

    fn restored_verification(&self) -> Result<historical_replay::RestoredCheckpointTrust, String> {
        // Verify the restored accounts and keep the independently authenticated
        // future accounts checkpoint pending until this worker reaches it.
        Ok(historical_replay::RestoredCheckpointTrust::LocalBootstrapWithCanonicalTerminal(END))
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
                && qualification.is_some_and(|p| {
                    (
                        p.epoch,
                        p.bootstrap_slot,
                        p.replay_start,
                        p.output_slot_start,
                        p.end_inclusive,
                    ) == (EPOCH, BOOT, BOOT + 1, BOOT + 1, END)
                }),
            "epoch 266 native restart is confined to its exact private window",
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
            "epoch 266 restored worker, tick unit or initial cursor differs",
        )?;
        checkpoint_matches(&self.terminal, &actual)?;
        require(
            !self.verified.swap(true, Ordering::SeqCst),
            "epoch 266 restart checked twice",
        )?;
        info!("verified epoch 266 native restart at slot {BOOT} before replay entries");
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
        .map_err(|err| err.to_string())?;
    validate_plan(&plan, &destination)?;
    require(
        unsafe { libc::geteuid() } == 1000,
        "epoch 266 requires isolated UID 1000",
    )?;
    let invocation = authenticate_service(&plan.producer_unit)?;
    let root = fs::symlink_metadata(&plan.run_root).map_err(|err| err.to_string())?;
    require(
        plan.run_root
            .canonicalize()
            .map_err(|err| err.to_string())?
            == plan.run_root
            && root.is_dir()
            && root.uid() == 1000
            && root.mode() & 0o077 == 0,
        "epoch 266 run root is not private",
    )?;
    let ledger_children = fs::read_dir(&destination)
        .map_err(|err| err.to_string())?
        .map(|item| item.map(|entry| entry.file_name()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| err.to_string())?;
    require(
        ledger_children == [std::ffi::OsString::from("compact-indexes")],
        "epoch 266 ledger must contain only the projected indexes",
    )?;
    sealed_bytes(
        &Evidence {
            path: fs::read_link("/proc/self/exe").map_err(|err| err.to_string())?,
            sha256: plan.node_sha256.clone(),
        },
        256 << 20,
    )?;
    validate_admission(&plan)?;
    let scope = read_json(&plan.source_window)?;
    require(
        scope["bootstrap_slot"] == BOOT
            && scope["first_slot"] == BOOT + 1
            && scope["last_slot"] == END
            && scope["original_epoch_root_still_required"] == true,
        "epoch 266 source window or root obligation differs",
    )?;
    require_retained_input(&plan.snapshot.path, SNAPSHOT_BYTES)?;
    check_readonly(&open_regular_nofollow(&plan.snapshot.path).map_err(|err| err.to_string())?)?;
    validate_indexes(&destination, &shutdown)?;
    let terminal = read_prefix(&plan, &shutdown)?;
    sealed_bytes(&plan.worker, 128 << 20)?;
    let genesis = sealed_bytes(&plan.genesis, 1 << 20)?;
    let execution = select_runtime_with_snapshot_warmup_for_invocation(
        BOOT + 1,
        BOOT + 1..END + 1,
        true,
        true,
    )?;
    require(
        execution.backend == compatibility::RuntimeBackend::SolanaV1_8_11
            && configured_historical_worker_executable(execution.descriptor)? == plan.worker.path,
        "epoch 266 requires its exact qualified v1.8.11 worker",
    )?;
    require(
        available_bytes(&plan.run_root)? >= plan.minimum_free_bytes,
        "epoch 266 protected free space changed during input reread",
    )?;
    create_private_dir(&plan.run_root.join("output"))?;
    create_private_dir(&plan.run_root.join("receipts"))?;
    write_new(&destination.join("genesis.tar.bz2"), &genesis)?;
    let proof = VerifiedRestart {
        terminal,
        snapshot: plan.snapshot.path,
        verified: AtomicBool::new(false),
    };
    let hashes = [(BOOT, BOOT_ACCOUNTS), (END, END_ACCOUNTS)]
        .into_iter()
        .map(|(slot, hash)| {
            hash.parse::<Hash>()
                .map(|hash| (slot, BankHashExpectation::LegacyAccountsHash(hash)))
                .map_err(|err| err.to_string())
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    let verifier = Arc::new(SnapshotVerifier::new(hashes, Some(shutdown.clone())));
    let output = plan
        .run_root
        .join("output/epoch-266-slots-114929698-114936474.jet");
    let replay = run_geyser_replay(
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
        Some(WINDOW),
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
        "epoch 266 replay interrupted or missed the actual native restart barrier",
    )?;
    verifier.finish()?;
    let segment = publish_historical_segment_manifest(EPOCH, WINDOW, &output, &replay)?;
    require(
        segment.bootstrap_archive_sha256 == Some(sha(SNAPSHOT)?)
            && segment.terminal.slot == END
            && segment.terminal.accounts_hash == END_ACCOUNTS
            && segment.worker_executable_sha256 == sha(WORKER)?,
        "epoch 266 completed manifest differs from the verified scope",
    )?;
    checkpoint_matches(&proof.terminal, &segment.bootstrap)?;
    require_no_checksum(&output)?;
    let receipt = json!({
        "schema":"foundation-epoch266-private-window-result-v1", "epoch":EPOCH,
        "invocation_id":invocation, "plan":plan_evidence, "first_slot":BOOT+1, "last_slot":END,
        "archive":output, "archive_sha256":sha256_hex_string(&segment.archive_sha256),
        "predecessor_terminal":proof.terminal, "native_bootstrap":segment.bootstrap,
        "native_terminal":segment.terminal, "whole_prefix_reread":true,
        "actual_native_restart_verified":true, "canonical_terminal_verified":true,
        "original_epoch_root_still_required":true, "publication_authorized":false
    });
    write_new(
        &plan.run_root.join("receipts/window.json"),
        &serde_json::to_vec_pretty(&receipt).map_err(|err| err.to_string())?,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_window_requires_both_bootstrap_and_native_terminal() {
        assert!(validate_cli((266, 266), Some(true), 1, true, false).is_ok());
        assert!(validate_cli((266, 267), Some(true), 1, true, false).is_err());
        assert!(validate_cli((266, 266), Some(true), 1, true, true).is_err());
        let native = historical::HistoricalCheckpoint {
            slot: BOOT,
            bank_hash: [42; 32],
            accounts_hash: [43; 32],
            last_blockhash: [44; 32],
            capitalization: 512_823_354_377_505_714,
            transaction_count: 49_794_308_850,
            tick_height: 7_355_500_672,
            slot_complete: true,
            writes: vec![],
            next_write_version: 187_154_775_110,
        };
        let mut predecessor = segment_checkpoint_summary(&(&native).try_into().unwrap());
        predecessor.next_write_version = 187_154_774_783;
        predecessor.write_count = 1616;
        let proof = VerifiedRestart {
            terminal: predecessor,
            snapshot: "/tmp/snapshot.tar.zst".into(),
            verified: AtomicBool::new(false),
        };
        let archive = ReplayBootstrap::SnapshotArchive(proof.snapshot.clone());
        assert!(
            proof
                .validate_invocation(EPOCH, &archive, Some(WINDOW), false, false, false)
                .is_ok()
        );
        assert!(
            proof
                .validate_invocation(
                    EPOCH,
                    &archive,
                    Some(QualificationPlan {
                        end_inclusive: END - 1,
                        ..WINDOW
                    }),
                    false,
                    false,
                    false
                )
                .is_err()
        );
        assert!(!proof.covers_trusted_root(EPOCH, BOOT, BOOT + 1, END));
        assert!(matches!(
            proof.restored_verification().unwrap(),
            historical_replay::RestoredCheckpointTrust::LocalBootstrapWithCanonicalTerminal(END)
        ));
        let mut different = native.clone();
        different.bank_hash[0] ^= 1;
        let worker = sha(WORKER).unwrap();
        assert!(
            proof
                .verify_native_checkpoint(&different, worker, native.next_write_version, 64)
                .is_err()
        );
        assert!(!proof.verified.load(Ordering::SeqCst));
        assert!(
            proof
                .verify_native_checkpoint(&native, worker, native.next_write_version, 64)
                .is_ok()
        );
        assert!(
            proof
                .verify_native_checkpoint(&native, worker, native.next_write_version, 64)
                .is_err()
        );
    }
}
