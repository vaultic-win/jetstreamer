//! Private replay of the next authenticated epoch 143 hourly window.
use super::{
    checkpoint_continuation::{
        Evidence, RestartProof, authenticate_service, available_bytes, checkpoint_matches, require,
        require_no_checksum, require_retained_input, sealed_bytes, sha,
    },
    *,
};
use jetstreamer_node::{
    archive_checksum::{
        archive_file_identity, open_regular_nofollow, path_matches_archive_identity,
    },
    segment_manifest::read_and_validate_segment_manifest_from,
};
use serde::Deserialize;
use std::os::unix::fs::MetadataExt;

const BOOT: u64 = 61_787_631;
const END: u64 = 61_794_627;
const BOOT_HASH: &str = "2y3Q8vdnvB77rU4KHomsesrMWeTPrh9hsp9shn1uEwus";
const END_HASH: &str = "F5gLqfR7HTZm7ntqYzvLuy7NXPnXHLpJSWpeuDfTRqiZ";
const SNAPSHOT: &str = "snapshot-61787631-2y3Q8vdnvB77rU4KHomsesrMWeTPrh9hsp9shn1uEwus.tar.zst";
const SNAPSHOT_BYTES: u64 = 2_350_018_921;
const SNAPSHOT_GENERATION: u64 = 1_634_786_651_485_428;
const WORKER: &str = "/usr/local/lib/jetstreamer/deploy-epochs144-147-upgradeable-loader-20261016-v1/jetstreamer-historical-worker-v1-4-25";
const WORKER_SHA: &str = "2cca500106d274ebfbbc8c5bfa0e6e8343cd5e41003f9e82c93282800732d8c8";
const FIRST_IID: &str = "4514e85834c34152ae0ecfde8a42001d";
const PREFIX: &str =
    "/home/sol/.jetstreamer-private/epoch143-first-hourly-20261127-v1/epoch-143-first-hourly.jet";
const RUN: &str = "/home/sol/.jetstreamer-private/epoch143-second-hourly-20261128-v1";
const UNIT: &str = "horizon-qualify-143-second-hourly-20261128-v2.service";
const QUALIFICATION: QualificationPlan = QualificationPlan {
    epoch: 143,
    bootstrap_slot: BOOT,
    replay_start: BOOT + 1,
    output_slot_start: BOOT + 1,
    end_inclusive: END,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    prefix_acceptance: Evidence,
    snapshot_custody: Evidence,
    minimum_free_bytes: u64,
}

#[derive(Deserialize)]
struct Acceptance {
    schema: String,
    producer_invocation_id: String,
    archive: Evidence,
    archive_bytes: u64,
    segment_manifest: Evidence,
    terminal_slot: u64,
    output_slot_start: u64,
    output_slot_count: u64,
    publication_authorized: bool,
    resource_credit_bytes: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Custody {
    schema: String,
    generation: u64,
    slot: u64,
    bytes: u64,
    snapshot: Evidence,
    crc32c: String,
    md5: String,
}

pub(super) fn parse(args: &[String]) -> Result<Evidence, String> {
    let [epoch, root, verify, plan, digest] = args else {
        return Err("expected 143 PRIVATE_ROOT --verify --epoch143-hourly-plan=PATH --epoch143-hourly-plan-sha256=SHA256".into());
    };
    let path = PathBuf::from(
        plan.strip_prefix("--epoch143-hourly-plan=")
            .ok_or("missing plan")?,
    );
    let digest = digest
        .strip_prefix("--epoch143-hourly-plan-sha256=")
        .ok_or("missing plan digest")?;
    require(
        epoch == "143"
            && root == RUN
            && verify == "--verify"
            && path.is_absolute()
            && sha(digest)? != [0; 32],
        "unexpected epoch 143 hourly command",
    )?;
    Ok(Evidence {
        path,
        sha256: digest.into(),
    })
}

struct Restart {
    terminal: SegmentCheckpointSummary,
    snapshot: PathBuf,
    snapshot_sha: [u8; 32],
}

impl RestartProof for Restart {
    fn snapshot_sha256(&self) -> [u8; 32] {
        self.snapshot_sha
    }

    fn snapshot_size(&self) -> u64 {
        SNAPSHOT_BYTES
    }

    fn restored_verification(&self) -> Result<historical_replay::RestoredCheckpointTrust, String> {
        Ok(historical_replay::RestoredCheckpointTrust::LocalBootstrapWithCanonicalTerminal(END))
    }

    fn covers_trusted_root(&self, _: u64, _: u64, _: u64, _: u64) -> bool {
        false
    }

    fn validate_invocation(
        &self,
        epoch: u64,
        bootstrap: &ReplayBootstrap,
        plan: Option<QualificationPlan>,
        carried: bool,
        audited: bool,
        retain: bool,
    ) -> Result<(), String> {
        require(
            epoch == 143
                && plan == Some(QUALIFICATION)
                && !carried
                && !audited
                && !retain
                && bootstrap.snapshot_archive() == Some(self.snapshot.as_path()),
            "hourly restart proof crossed its exact runtime window",
        )
    }

    fn verify_native_checkpoint(
        &self,
        worker_cut: &historical::HistoricalCheckpoint,
        worker: [u8; 32],
        cursor: u64,
        ticks_per_slot: u64,
    ) -> Result<(), String> {
        let current = segment_checkpoint_summary(
            &historical_replay::HistoricalCheckpointSummary::try_from(worker_cut)?,
        );
        require(
            worker == sha(WORKER_SHA)?
                && ticks_per_slot == 64
                && current.next_write_version == cursor,
            "unexpected epoch 143 worker or native write cursor",
        )?;
        checkpoint_matches(&self.terminal, &current)?;
        info!(
            "epoch 143 verified the same worker's full restored checkpoint at slot {BOOT} before replay entries"
        );
        Ok(())
    }
}

fn validated_prefix(accepted: Acceptance) -> Result<SegmentCheckpointSummary, String> {
    let archive = &accepted.archive.path;
    let manifest = &accepted.segment_manifest.path;
    require(
        accepted.schema == "horizon-143-private-first-hourly-acceptance-v1"
            && accepted.producer_invocation_id == FIRST_IID
            && archive == Path::new(PREFIX)
            && manifest == &archive.with_extension("jet.segment.json")
            && accepted.terminal_slot == BOOT
            && accepted.output_slot_start == 61_776_000
            && accepted.output_slot_count == BOOT - 61_776_000 + 1
            && !accepted.publication_authorized
            && accepted.resource_credit_bytes == 0,
        "foreign epoch 143 prefix acceptance",
    )?;
    require_retained_input(archive, accepted.archive_bytes)?;
    require_no_checksum(archive)?;
    let fd = open_regular_nofollow(archive).map_err(|err| err.to_string())?;
    let archive_id = archive_file_identity(&fd).map_err(|err| err.to_string())?;
    let bound_manifest = || -> Result<(), String> {
        let raw = fs::read(manifest).map_err(|err| err.to_string())?;
        require(
            raw.len() <= 1 << 20
                && <[u8; 32]>::from(Sha256::digest(&raw))
                    == sha(&accepted.segment_manifest.sha256)?,
            "epoch 143 prefix manifest changed",
        )
    };
    bound_manifest()?;
    let verified = read_and_validate_segment_manifest_from(archive, manifest)
        .map_err(|err| err.to_string())?;
    bound_manifest()?;
    require(
        path_matches_archive_identity(archive, archive_id).map_err(|err| err.to_string())?
            && verified.epoch == 143
            && verified.terminal.slot == BOOT
            && verified.terminal.accounts_hash == BOOT_HASH
            && verified.archive_sha256 == sha(&accepted.archive.sha256)?
            && verified.worker_executable_sha256 == sha(WORKER_SHA)?
            && verified.runtime.runtime_profile == "solana-v1.4.25"
            && verified.runtime.genesis_hash == compatibility::MAINNET_GENESIS_HASH,
        "independently reread epoch 143 prefix differs",
    )?;
    Ok(verified.terminal)
}

pub(super) async fn run(
    evidence: Evidence,
    shutdown: Arc<AtomicBool>,
    cursor: Arc<ReplayCursor>,
    tracker: Arc<RestartTracker>,
) -> Result<(), String> {
    let invocation = authenticate_service(UNIT)?;
    let root = Path::new(RUN);
    let plan: Plan = serde_json::from_slice(&sealed_bytes(&evidence, 1 << 20)?)
        .map_err(|err| err.to_string())?;
    let metadata = fs::symlink_metadata(root).map_err(|err| err.to_string())?;
    require(
        plan.schema == "horizon-143-private-second-hourly-native-plan-v1"
            && plan.minimum_free_bytes > 0
            && available_bytes(root)? >= plan.minimum_free_bytes
            && metadata.is_dir()
            && metadata.mode() & 0o077 == 0
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.uid() != 0
            && fs::canonicalize(root).map_err(|err| err.to_string())? == root
            && !inherited_epoch_lease_authorized()
            && !env_truthy("JETSTREAMER_LOAD_FROM_DIR")
            && env::var_os("JETSTREAMER_EXPORT_HANDOFF_SNAPSHOT_DIR").is_none()
            && strict_opt_in("JETSTREAMER_ALLOW_CANDIDATE_RUNTIME")?,
        "invalid epoch 143 private hourly plan, environment, or capacity",
    )?;
    let custody: Custody = serde_json::from_slice(&sealed_bytes(&plan.snapshot_custody, 1 << 20)?)
        .map_err(|err| err.to_string())?;
    require(
        custody.schema == "horizon-143-hourly-custody-v1"
            && custody.generation == SNAPSHOT_GENERATION
            && custody.slot == BOOT
            && custody.bytes == SNAPSHOT_BYTES
            && custody.crc32c == "w7Xg4w=="
            && custody.md5 == "NMBdYE4IMm4fIxcYNVPdkg=="
            && custody
                .snapshot
                .path
                .file_name()
                .and_then(|name| name.to_str())
                == Some(SNAPSHOT),
        "foreign epoch 143 GCS generation or payload",
    )?;
    require_retained_input(&custody.snapshot.path, SNAPSHOT_BYTES)?;
    let worker = configured_historical_worker_executable(&compatibility::SOLANA_V1_4_25_RUNTIME)?;
    require(
        worker == Path::new(WORKER),
        "unexpected epoch 143 worker path",
    )?;
    let proof = Restart {
        terminal: validated_prefix(
            serde_json::from_slice(&sealed_bytes(&plan.prefix_acceptance, 1 << 20)?)
                .map_err(|err| err.to_string())?,
        )?,
        snapshot: custody.snapshot.path,
        snapshot_sha: sha(&custody.snapshot.sha256)?,
    };
    require(
        !shutdown.load(Ordering::SeqCst) && available_bytes(root)? >= plan.minimum_free_bytes,
        "epoch 143 interrupted or capacity changed while validating prefix",
    )?;
    let anchors = [(BOOT, BOOT_HASH), (END, END_HASH)]
        .into_iter()
        .map(|(slot, hash)| {
            Ok((
                slot,
                BankHashExpectation::LegacyAccountsHash(
                    hash.parse::<Hash>().map_err(|err| err.to_string())?,
                ),
            ))
        })
        .collect::<Result<BTreeMap<_, _>, String>>()?;
    let verifier = Arc::new(SnapshotVerifier::new(anchors, Some(shutdown.clone())));
    let output = root.join("epoch-143-through-61794627.jet");
    require_no_checksum(&output)?;
    let manifest_path = output.with_extension("jet.segment.json");
    require(
        [&output, &manifest_path].into_iter().all(|path| {
            fs::symlink_metadata(path).is_err_and(|err| err.kind() == std::io::ErrorKind::NotFound)
        }),
        "epoch 143 hourly continuation needs empty output paths",
    )?;
    let result = run_geyser_replay(
        143,
        true,
        &root.join("ledger"),
        &root.join("scratch"),
        &ReplayBootstrap::SnapshotArchive(proof.snapshot.clone()),
        shutdown.clone(),
        cursor,
        tracker,
        Some(verifier.clone()),
        output.clone(),
        Some(QUALIFICATION),
        None,
        None,
        None,
        None,
        Some(END),
        None,
        false,
        Some(&proof),
        epoch223_qualification::TailMode::Disabled,
    )
    .await?
    .completed()?;
    verifier.finish()?;
    require(
        !shutdown.load(Ordering::SeqCst)
            && result.historical_worker_executable_sha256 == Some(sha(WORKER_SHA)?),
        "interrupted epoch 143 continuation or different native worker",
    )?;
    publish_historical_segment_manifest(143, QUALIFICATION, &output, &result)?;
    require_no_checksum(&output)?;
    info!(
        "epoch 143 private hourly continuation invocation {invocation} closed at slot {END}: {}",
        manifest_path.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_entrypoint_rejects_another_epoch_or_extra_arguments() {
        let args = [
            "143",
            RUN,
            "--verify",
            "--epoch143-hourly-plan=/run/next/plan.json",
            "--epoch143-hourly-plan-sha256=105f7fbf58843f7475eae951ec5d482cc7372204401036db01d4ef4fdbbfe95d",
        ];
        let mut args = args.into_iter().map(str::to_string).collect::<Vec<_>>();
        assert!(parse(&args).is_ok());
        args[0] = "142".into();
        assert!(parse(&args).is_err());
        args[0] = "143".into();
        args.push("--root-checkpoint-cohort".into());
        assert!(parse(&args).is_err());
    }
}
