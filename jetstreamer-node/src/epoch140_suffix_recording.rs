//! Private epoch 140 suffix recording on the live historical Bank. The later
//! canonical root is deliberately left outstanding when this recording closes.
use super::*;
use checkpoint_continuation::{
    Evidence, RestartProof, authenticate_service, available_bytes, checkpoint_matches,
    create_private_dir, require, require_no_checksum, require_retained_input, sealed_bytes, sha,
    write_new,
};
use serde_json::{Value, json};
use std::os::unix::fs::MetadataExt;

const START: u64 = 60_480_000;
const CUT: u64 = 60_911_751;
const END: u64 = 60_911_999;
const ROOT: u64 = 61_328_765;
const ORIGINAL_CURSOR: u64 = 28_029_693_043;
const NATIVE_CURSOR: u64 = 28_087_370_409;
const SOURCE_SHA: &str = "65d311f5b96b2c1f2b8ff50ecfbe5da29bcf57573b55b39c48282f6d259a6842";
const NATIVE_SHA: &str = "53f1aa88f8f5f24aed1e291ff02318c102fac3bfb8ececf5c215c9fb70c11b20";
const JOURNAL_SHA: &str = "8dfb8d6805d6b4d50ab340899447b90449c66117cc33b1af0ca6537b934a3b13";
const JOURNAL: &str = "/usr/local/lib/jetstreamer/horizon-epoch140-checkpoint-journal-outcome-20261020-v1/observation.json";
const SNAPSHOT_SHA: &str = "47d5911465901975e397c570e06ccf72296db7ecd3b3b1beda710cacd3e683a1";
const SNAPSHOT_SIZE: u64 = 2_741_858_751;
const BOOT_HASH: &str = "GyFbDnPnUWrFStHKfwWC98xJpmBQKjLyJ9sMf2m6MrWR";
const ROOT_HASH: &str = "8LfMXtdKmPEvMcBzEz2XZ56HZ8pUPGSaWGA6mYG4dAFY";
const WORKER: &str = "/usr/local/lib/jetstreamer/horizon-v1425-corrected-default-candidate-20261023-v1/jetstreamer-historical-worker-v1-4-25";
const WORKER_SHA: &str = "c536dcf360b7866b3aa99e0ff6d7d927dcf5db27bfbbb8f73887eb4bb7d87344";
const BUNDLE: &str = "/usr/local/lib/jetstreamer/horizon-epoch141-original-input-20261023-v1";
const UNIT: &str = "horizon-epoch140-suffix-recording.service";
const GENESIS_SHA: &str = "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945";
const QUALIFICATION: QualificationPlan = QualificationPlan {
    epoch: 140,
    bootstrap_slot: CUT,
    replay_start: CUT + 1,
    output_slot_start: CUT + 1,
    end_inclusive: END,
};

pub(super) struct Invocation {
    destination: PathBuf,
    plan: Evidence,
}

pub(super) fn parse(args: &[String]) -> Result<Invocation, String> {
    let [epoch, dest, verify, plan, hash] = args else {
        return Err("expected 140 PRIVATE_RUN_ROOT --verify --epoch140-suffix-plan=PATH --epoch140-suffix-plan-sha256=SHA256".into());
    };
    let plan = plan
        .strip_prefix("--epoch140-suffix-plan=")
        .ok_or("missing sealed recording plan")?;
    let hash = hash
        .strip_prefix("--epoch140-suffix-plan-sha256=")
        .ok_or("missing recording plan digest")?;
    require(
        epoch == "140"
            && verify == "--verify"
            && Path::new(plan).is_absolute()
            && Path::new(dest).is_absolute()
            && sha(hash)? != [0; 32],
        "wrong private recording invocation",
    )?;
    Ok(Invocation {
        destination: dest.into(),
        plan: Evidence {
            path: plan.into(),
            sha256: hash.into(),
        },
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    node_sha256: String,
    run_root: PathBuf,
    prefix_audit: Evidence,
    snapshot: PathBuf,
    genesis: PathBuf,
    minimum_free_bytes: u64,
}

struct Restart {
    cut: SegmentCheckpointSummary,
    snapshot: PathBuf,
}

impl RestartProof for Restart {
    fn snapshot_sha256(&self) -> [u8; 32] {
        sha(SNAPSHOT_SHA).expect("fixed digest")
    }
    fn snapshot_size(&self) -> u64 {
        SNAPSHOT_SIZE
    }
    fn restored_verification(&self) -> Result<historical_replay::RestoredCheckpointTrust, String> {
        Ok(historical_replay::RestoredCheckpointTrust::LocalBootstrapWithCanonicalTerminal(ROOT))
    }
    fn covers_trusted_root(&self, _: u64, _: u64, _: u64, _: u64) -> bool {
        false
    }
    fn validate_invocation(
        &self,
        epoch: u64,
        bootstrap: &ReplayBootstrap,
        q: Option<QualificationPlan>,
        carried: bool,
        audited: bool,
        retain: bool,
    ) -> Result<(), String> {
        require(
            epoch == 140
                && q == Some(QUALIFICATION)
                && !carried
                && !audited
                && !retain
                && bootstrap.snapshot_archive() == Some(self.snapshot.as_path()),
            "epoch 140 suffix proof requested for another range or state source",
        )
    }
    fn verify_native_checkpoint(
        &self,
        actual: &historical::HistoricalCheckpoint,
        worker: [u8; 32],
        initialized_cursor: u64,
        ticks_per_slot: u64,
    ) -> Result<(), String> {
        let actual = segment_checkpoint_summary(
            &historical_replay::HistoricalCheckpointSummary::try_from(actual)?,
        );
        self.verify_cut(&actual, worker, initialized_cursor, ticks_per_slot)
    }
}

impl Restart {
    fn verify_cut(
        &self,
        actual: &SegmentCheckpointSummary,
        worker: [u8; 32],
        cursor: u64,
        ticks: u64,
    ) -> Result<(), String> {
        require(
            worker == sha(WORKER_SHA)?
                && ticks == 64
                && cursor == NATIVE_CURSOR
                && actual.next_write_version == cursor
                && self.cut.next_write_version == ORIGINAL_CURSOR,
            "incorrect worker, clock or write cursor before first entry",
        )?;
        checkpoint_matches(&self.cut, actual)
    }
}

fn check_journal(actual: &SegmentCheckpointSummary, row: &Value) -> Result<(), String> {
    require(
        row["slot"] == actual.slot
            && row["bank_hash"] == actual.bank_hash
            && row["accounts_hash"] == actual.accounts_hash
            && row["last_blockhash"] == actual.last_blockhash
            && row["capitalization"] == actual.capitalization
            && row["transactions"] == actual.transaction_count
            && row["tick_height"] == actual.tick_height
            && row["complete"] == true
            && actual.slot_complete,
        "native consensus checkpoint differs from original epoch 140 journal",
    )
}

fn selected_cut(audit: &Value, journal: &Value) -> Result<SegmentCheckpointSummary, String> {
    require(
        audit["schema"] == "jetstreamer-epoch140-private-selected-prefix-audit-v1"
            && audit["epoch"] == 140
            && audit["status"] == "passed"
            && audit["selected_prefix_mapping_proven"] == true
            && audit["ordinary_archive_manifest"] == false
            && audit["source"]["sha256"] == SOURCE_SHA
            && audit["source"]["whole_hash_verified_before_and_after"] == true
            && audit["source_full_poh_and_anchor_proofs_preserved"] == true
            && audit["evidence"]["checkpoint"]["sha256"] == JOURNAL_SHA
            && audit["evidence"]["native"]["sha256"] == NATIVE_SHA
            && audit["native_snapshot_sha256"] == SNAPSHOT_SHA
            && audit["independent_native_cursor"] == NATIVE_CURSOR
            && audit["selection"]["first_slot"] == START
            && audit["selection"]["last_slot"] == CUT
            && audit["selection"]["slot_count"] == CUT - START + 1
            && audit["selection"]["raw_write_versions"]["end_exclusive"] == ORIGINAL_CURSOR,
        "incomplete or unrelated selected-prefix audit",
    )?;
    let cut: SegmentCheckpointSummary =
        serde_json::from_value(audit["selected_terminal"].clone()).map_err(|e| e.to_string())?;
    require(
        cut.slot == CUT
            && cut.accounts_hash == BOOT_HASH
            && cut.next_write_version == ORIGINAL_CURSOR,
        "wrong selected cut",
    )?;
    check_journal(&cut, &journal["checkpoints"][0])?;
    Ok(cut)
}

fn bound(path: &Path, digest: &str, max: u64) -> Result<Vec<u8>, String> {
    sealed_bytes(
        &Evidence {
            path: path.into(),
            sha256: digest.into(),
        },
        max,
    )
}

pub(super) async fn run(
    args: Invocation,
    shutdown: Arc<AtomicBool>,
    cursor: Arc<ReplayCursor>,
    tracker: Arc<RestartTracker>,
) -> Result<(), String> {
    let plan: Plan =
        serde_json::from_slice(&sealed_bytes(&args.plan, 1 << 20)?).map_err(|e| e.to_string())?;
    let root = &plan.run_root;
    let leaf = root.file_name().and_then(|v| v.to_str()).unwrap_or("");
    require(
        plan.schema == "jetstreamer-private-epoch140-suffix-recording-plan-v1"
            && &args.destination == root
            && root.parent() == Some(Path::new("/home/sol/.jetstreamer-private"))
            && leaf.starts_with("epoch140-suffix-recording-")
            && plan.minimum_free_bytes > 0
            && !inherited_epoch_lease_authorized()
            && !env_truthy("JETSTREAMER_LOAD_FROM_DIR")
            && env::var_os("JETSTREAMER_EXPORT_HANDOFF_SNAPSHOT_DIR").is_none()
            && strict_opt_in("JETSTREAMER_ALLOW_CANDIDATE_RUNTIME")?,
        "invalid recording plan, private path or runtime environment",
    )?;
    let invocation = authenticate_service(UNIT)?;
    let owner = unsafe { libc::geteuid() };
    let metadata = fs::symlink_metadata(root).map_err(|e| e.to_string())?;
    require(
        owner != 0
            && metadata.uid() == owner
            && metadata.mode() & 0o077 == 0
            && metadata.is_dir()
            && root.canonicalize().map_err(|e| e.to_string())? == *root,
        "unsafe private recording directory",
    )?;
    bound(
        &fs::read_link("/proc/self/exe").map_err(|e| e.to_string())?,
        &plan.node_sha256,
        256 << 20,
    )?;
    let worker = configured_historical_worker_executable(&compatibility::SOLANA_V1_4_25_RUNTIME)?;
    require(
        worker == Path::new(WORKER),
        "recording requires the qualified corrected v1.4.25 worker",
    )?;
    bound(&worker, WORKER_SHA, 64 << 20)?;
    let genesis = bound(&plan.genesis, GENESIS_SHA, 10 << 20)?;
    let journal: Value = serde_json::from_slice(&bound(Path::new(JOURNAL), JOURNAL_SHA, 1 << 20)?)
        .map_err(|e| e.to_string())?;
    let audit: Value = serde_json::from_slice(&sealed_bytes(&plan.prefix_audit, 1 << 20)?)
        .map_err(|e| e.to_string())?;
    let proof = Restart {
        cut: selected_cut(&audit, &journal)?,
        snapshot: plan.snapshot,
    };
    require_retained_input(&proof.snapshot, SNAPSHOT_SIZE)?;
    require(
        proof.snapshot.file_name() == Some(format!("snapshot-{CUT}-{BOOT_HASH}.tar.zst").as_ref()),
        "wrong restored snapshot filename",
    )?;
    require(
        available_bytes(root)? >= plan.minimum_free_bytes,
        "pre-recording disk admission failed",
    )?;
    let bundle = Path::new(BUNDLE);
    epoch141_original_entry::configure_suffix(
        bundle.join("index.json"),
        bundle.join("original-entries.data"),
    )?;
    require(
        !shutdown.load(Ordering::SeqCst) && available_bytes(root)? >= plan.minimum_free_bytes,
        "recording interrupted or disk admission expired during source authentication",
    )?;
    let work = root.join("recording");
    create_private_dir(&work)?;
    let ledger = work.join("ledger");
    let scratch = work.join("scratch");
    create_private_dir(&ledger)?;
    create_private_dir(&scratch)?;
    write_new(&ledger.join("genesis.tar.bz2"), &genesis)?;
    let output = work.join("epoch-140-suffix.jet");
    let anchors = [(CUT, BOOT_HASH), (ROOT, ROOT_HASH)]
        .into_iter()
        .map(|(slot, hash)| {
            Ok((
                slot,
                BankHashExpectation::LegacyAccountsHash(
                    hash.parse::<Hash>().map_err(|e| e.to_string())?,
                ),
            ))
        })
        .collect::<Result<BTreeMap<_, _>, String>>()?;
    let verifier = Arc::new(SnapshotVerifier::new(anchors, Some(shutdown.clone())));
    let result = run_geyser_replay(
        140,
        true,
        &ledger,
        &scratch,
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
        Some(ROOT),
        None,
        false,
        Some(&proof),
        epoch223_qualification::TailMode::Disabled,
    )
    .await?
    .completed()?;
    require(
        !shutdown.load(Ordering::SeqCst)
            && result.historical_worker_executable_sha256 == Some(sha(WORKER_SHA)?),
        "interrupted or unexpected recording worker",
    )?;
    require(
        verifier.checkpoint_count_in_range(CUT, CUT) == 0
            && verifier.checkpoint_count_in_range(ROOT, ROOT) == 1,
        "suffix must consume the restored cut and leave the later canonical root outstanding",
    )?;
    let evidence = result
        .historical_evidence
        .as_ref()
        .ok_or("suffix has no historical Bank evidence")?;
    let terminal = segment_checkpoint_summary(&evidence.terminal);
    check_journal(&terminal, &journal["checkpoints"][1])?;
    require(
        terminal.slot == END
            && evidence.emitted_write_versions.start == NATIVE_CURSOR
            && !evidence.emitted_write_versions.is_empty(),
        "suffix has incomplete account-write coverage",
    )?;
    let manifest = publish_historical_segment_manifest(140, QUALIFICATION, &output, &result)?;
    require_no_checksum(&output)?;
    let receipt = json!({"schema":"jetstreamer-private-epoch140-suffix-recording-v1","invocation_id":invocation,
        "plan":args.plan,"prefix_audit":plan.prefix_audit,"snapshot_sha256":SNAPSHOT_SHA,"worker_sha256":WORKER_SHA,
        "pre_entry_native_checkpoint":manifest.bootstrap,"original_cut_cursor":ORIGINAL_CURSOR,
        "recorded_slot_start":CUT+1,"recorded_slots":END-CUT,"terminal":manifest.terminal,
        "emitted_raw_write_versions":manifest.emitted_raw_write_versions,
        "archive":output,"archive_sha256":jetstreamer_node::segment_manifest::sha256_hex_string(&manifest.archive_sha256),
        "original_entry_gap_targets_matched":10,"pending_canonical_root_slot":ROOT,"pending_canonical_accounts_hash":ROOT_HASH,
        "canonical_root_verified":false,"assembly_authorized":false,"publication_authorized":false,"r2_mutations":false});
    write_new(
        &work.join("suffix-recording.json"),
        &serde_json::to_vec_pretty(&receipt).map_err(|e| e.to_string())?,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cut() -> SegmentCheckpointSummary {
        SegmentCheckpointSummary {
            slot: CUT,
            bank_hash: "BWG9oqUgYLKYA4sFwQRoFgcyQKTNuZaYatH9piAtGRiU".into(),
            accounts_hash: BOOT_HASH.into(),
            last_blockhash: "8yiPTGWeYzuWFQc68fvKdG6Mp16XJTAqxGUtjMdHMFij".into(),
            capitalization: 488_588_165_537_070_640,
            transaction_count: 9_398_636_535,
            tick_height: 3_898_352_128,
            slot_complete: true,
            write_count: 20,
            next_write_version: ORIGINAL_CURSOR,
        }
    }

    #[test]
    fn recording_cli_rejects_ordinary_replay_and_extra_actions() {
        let args = [
            "140",
            "/home/sol/.jetstreamer-private/epoch140-suffix-recording-test",
            "--verify",
            "--epoch140-suffix-plan=/sealed/plan.json",
            &format!("--epoch140-suffix-plan-sha256={NATIVE_SHA}"),
        ]
        .map(String::from);
        assert!(parse(&args).is_ok());
        for (index, replacement) in [
            (0, "141"),
            (0, "--failed-prefix220-recover"),
            (1, "relative"),
            (2, "--no-verify"),
            (3, "--snapshot-archive=/input"),
            (4, "--epoch140-suffix-plan-sha256=bad"),
        ] {
            let mut changed = args.clone();
            changed[index] = replacement.into();
            assert!(parse(&changed).is_err(), "{replacement}");
        }
        let mut extra = args.to_vec();
        extra.push("--root-checkpoint-cohort".into());
        assert!(parse(&extra).is_err());
    }

    #[test]
    fn same_live_worker_must_match_cut_before_the_first_entry() {
        let proof = Restart {
            cut: cut(),
            snapshot: "/fixed".into(),
        };
        let mut actual = proof.cut.clone();
        actual.write_count = 0;
        actual.next_write_version = NATIVE_CURSOR;
        let worker = sha(WORKER_SHA).unwrap();
        let check = |s: &SegmentCheckpointSummary| proof.verify_cut(s, worker, NATIVE_CURSOR, 64);
        check(&actual).unwrap();
        let native = historical::HistoricalCheckpoint {
            slot: actual.slot,
            bank_hash: actual.bank_hash.parse::<Hash>().unwrap().to_bytes(),
            accounts_hash: actual.accounts_hash.parse::<Hash>().unwrap().to_bytes(),
            last_blockhash: actual.last_blockhash.parse::<Hash>().unwrap().to_bytes(),
            capitalization: actual.capitalization,
            transaction_count: actual.transaction_count,
            tick_height: actual.tick_height,
            slot_complete: true,
            writes: Vec::new(),
            next_write_version: NATIVE_CURSOR,
        };
        proof
            .verify_native_checkpoint(&native, worker, NATIVE_CURSOR, 64)
            .unwrap();
        let mut wrong_worker_report = native;
        wrong_worker_report.accounts_hash = [0; 32];
        assert!(
            proof
                .verify_native_checkpoint(&wrong_worker_report, worker, NATIVE_CURSOR, 64)
                .is_err()
        );
        assert!(
            proof
                .verify_cut(&actual, [0; 32], NATIVE_CURSOR, 64)
                .is_err()
        );
        assert!(
            proof
                .verify_cut(&actual, worker, ORIGINAL_CURSOR, 64)
                .is_err()
        );
        assert!(
            proof
                .verify_cut(&actual, worker, NATIVE_CURSOR, 63)
                .is_err()
        );
        for key in [
            "slot",
            "bank_hash",
            "accounts_hash",
            "last_blockhash",
            "capitalization",
            "transaction_count",
            "tick_height",
            "slot_complete",
            "write_count",
            "next_write_version",
        ] {
            let mut changed = serde_json::to_value(&actual).unwrap();
            changed[key] = match &changed[key] {
                Value::String(_) => json!("other"),
                Value::Bool(_) => json!(false),
                Value::Number(n) => json!(n.as_u64().unwrap() + 1),
                _ => unreachable!(),
            };
            assert!(
                check(&serde_json::from_value(changed).unwrap()).is_err(),
                "{key}"
            );
        }
        assert!(!proof.covers_trusted_root(140, CUT, CUT + 1, END));
        assert!(matches!(
            proof.restored_verification().unwrap(),
            historical_replay::RestoredCheckpointTrust::LocalBootstrapWithCanonicalTerminal(ROOT)
        ));
        let bootstrap = ReplayBootstrap::SnapshotArchive("/fixed".into());
        proof
            .validate_invocation(140, &bootstrap, Some(QUALIFICATION), false, false, false)
            .unwrap();
        assert!(
            proof
                .validate_invocation(140, &bootstrap, Some(QUALIFICATION), false, true, false)
                .is_err()
        );
        let mut wrong = QUALIFICATION;
        wrong.output_slot_start += 1;
        assert!(
            proof
                .validate_invocation(140, &bootstrap, Some(wrong), false, false, false)
                .is_err()
        );
    }

    #[test]
    fn selected_prefix_and_original_terminal_bind_the_recording() {
        let original = cut();
        let row = json!({"slot":CUT, "bank_hash":original.bank_hash, "accounts_hash":BOOT_HASH,"last_blockhash":original.last_blockhash,
            "capitalization":original.capitalization,"transactions":original.transaction_count,"tick_height":original.tick_height,"complete":true});
        let journal = json!({"checkpoints":[row]});
        let mut report = json!({"schema":"jetstreamer-epoch140-private-selected-prefix-audit-v1","epoch":140,"status":"passed",
            "selected_prefix_mapping_proven":true,"ordinary_archive_manifest":false,"source":{"sha256":SOURCE_SHA,"whole_hash_verified_before_and_after":true},
            "source_full_poh_and_anchor_proofs_preserved":true,"evidence":{"checkpoint":{"sha256":JOURNAL_SHA},"native":{"sha256":NATIVE_SHA}},
            "native_snapshot_sha256":SNAPSHOT_SHA,"independent_native_cursor":NATIVE_CURSOR,"selected_terminal":original,
            "selection":{"first_slot":START,"last_slot":CUT,"slot_count":CUT-START+1,"raw_write_versions":{"end_exclusive":ORIGINAL_CURSOR}}});
        assert_eq!(selected_cut(&report, &journal).unwrap(), original);
        report["selected_terminal"]["accounts_hash"] = json!(ROOT_HASH);
        assert!(selected_cut(&report, &journal).is_err());
        report["selected_terminal"] = json!(original);
        report["selection"]["last_slot"] = json!(CUT - 1);
        assert!(selected_cut(&report, &journal).is_err());
        let mut mismatch = journal["checkpoints"][0].clone();
        mismatch["accounts_hash"] = json!(ROOT_HASH);
        assert!(check_journal(&original, &mismatch).is_err());
    }
}
