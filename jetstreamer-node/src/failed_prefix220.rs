//! Exact incident checkpoint qualification, separate from whole-cohort recovery.
//! Probes remain read-only. Recovery is a distinct full-validation/publication route.
use super::*;
use serde_json::{Value, json};

const PRIMARY: &str =
    "/var/lib/jetstreamer/horizon-220-prefix-primary-evidence-receipts-v1/evidence.json";
const PRIMARY_SHA: &str = "1c336e5e70aa9844de703db3eae14324f8d79eaed752844bb0e0e7fe26016004";
const PLAN: &str = "/var/lib/jetstreamer/horizon-prefix-recovery-and223-plans-1826-v1/preflight220-222-recovery-planning.json";
const PLAN_SHA: &str = "92ceef11e9ecb8ed6477c7282fdd48c7302904451be94376a25e88e309443d4d";
const FINGERPRINT: &str = "sha256:07c46b1acc5586bb368140323939a8c9b5ef7794b18107cd10592df74a6b0404";
const ROOTS: [u64; 3] = [95471337, 95903534, 96335538];

fn checkpoint(value: &Value) -> Result<cohort_publication::RootCheckpointSummary, String> {
    let fields = value["fields"]
        .as_object()
        .ok_or("checkpoint fields missing")?;
    if fields.len() != 10 || fields.get("complete").and_then(Value::as_str) != Some("true") {
        return Err("incomplete checkpoint tuple".into());
    }
    let number = |name: &str| -> Result<u64, String> {
        let text = fields
            .get(name)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("missing checkpoint {name}"))?;
        let n = text
            .parse::<u64>()
            .map_err(|e| format!("invalid checkpoint {name}: {e}"))?;
        if n.to_string() != text {
            return Err(format!("noncanonical checkpoint {name}"));
        }
        Ok(n)
    };
    let text = |name: &str| -> Result<String, String> {
        fields
            .get(name)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| format!("missing checkpoint {name}"))
    };
    let summary = UnreceiptedCheckpointSummary {
        slot: number("slot")?,
        bank_hash: text("bank_hash")?,
        accounts_hash: text("accounts_hash")?,
        last_blockhash: text("last_blockhash")?,
        capitalization: number("capitalization")?,
        transaction_count: number("transactions")?,
        tick_height: number("tick_height")?,
        slot_complete: true,
        write_count: number("writes")?,
        next_write_version: number("next_write_version")?,
    };
    let expected_ticks = summary
        .slot
        .checked_add(1)
        .and_then(|n| n.checked_mul(64))
        .ok_or("tick-height overflow")?;
    if summary.tick_height != expected_ticks {
        return Err("checkpoint tick height disagrees with complete historical slot".into());
    }
    let evidence = UnreceiptedCheckpointEvidence {
        kind: "incident-observation".into(),
        epoch: None,
        journal_message: value["message"]
            .as_str()
            .ok_or("checkpoint journal message missing")?
            .into(),
        summary,
    };
    validate_checkpoint_journal_binding(&evidence)?;
    recovery_checkpoint_summary(&evidence.summary)
}

fn gate(
    extracted: &Value,
    plan: &RootCheckpointCohortPlan,
) -> Result<cohort_publication::RootCheckpointGateEvidence, String> {
    if plan.fingerprint != FINGERPRINT
        || plan.bootstrap.slot != 95039516
        || plan.root_checkpoints.len() != 3
        || extracted["failed_slot"] != 96540992u64
    {
        return Err("foreign failed-prefix scope".into());
    }
    let bootstrap = checkpoint(&extracted["bootstrap"])?;
    let expected_bootstrap: Hash = plan
        .bootstrap
        .accounts_hash
        .parse()
        .map_err(|e| format!("bootstrap hash: {e}"))?;
    if bootstrap.slot != plan.bootstrap.slot
        || bootstrap.accounts_hash != expected_bootstrap.to_bytes()
        || bootstrap.write_count != 0
    {
        return Err("bootstrap does not bind original trusted root".into());
    }
    let prefix = extracted["complete_prefix"]
        .as_array()
        .ok_or("prefix missing")?;
    if prefix.len() != 3 {
        return Err("only complete epochs220-222 are eligible".into());
    }
    let mut carried = bootstrap;
    let mut members = Vec::new();
    let mut verified = Vec::new();
    for (index, member) in prefix.iter().enumerate() {
        let epoch = 220 + index as u64;
        let root = checkpoint(&member["observed_root"])?;
        let terminal = checkpoint(&member["terminal"])?;
        let expected = &plan.root_checkpoints[index];
        let expected_hash: Hash = expected
            .accounts_hash
            .parse()
            .map_err(|e| format!("root hash: {e}"))?;
        if member["epoch"] != epoch
            || root.slot != ROOTS[index]
            || expected.slot != root.slot
            || root.accounts_hash != expected_hash.to_bytes()
            || terminal.slot != (epoch + 1) * 432000 - 1
            || root.slot <= carried.slot
            || root.slot >= terminal.slot
            || carried.transaction_count > root.transaction_count
            || root.transaction_count > terminal.transaction_count
            || carried.next_write_version > root.next_write_version
            || root.next_write_version > terminal.next_write_version
        {
            return Err(format!(
                "epoch{epoch} root/terminal scope or progression mismatch"
            ));
        }
        if member["manifest_root"]["slot"] != expected.slot
            || member["manifest_root"]["accounts_hash"] != expected.accounts_hash
        {
            return Err(format!("epoch{epoch} trusted manifest root differs"));
        }
        verified.push(cohort_publication::VerifiedManifestCheckpoint {
            slot: root.slot,
            accounts_hash: root.accounts_hash,
        });
        members.push(cohort_publication::RootCheckpointGateMember {
            epoch,
            bootstrap: carried,
            terminal,
        });
        carried = terminal;
    }
    Ok(cohort_publication::RootCheckpointGateEvidence {
        kind: cohort_publication::ROOT_CHECKPOINT_GATE_KIND.into(),
        version: cohort_publication::ROOT_CHECKPOINT_GATE_VERSION,
        verified_manifest_checkpoints: verified,
        members,
    })
}

pub(super) fn probe() -> Result<Value, String> {
    let (primary, primary_sha) = read_bound_recovery_file(Path::new(PRIMARY), 256 * 1024, true)?;
    if primary_sha != parse_lower_sha256(PRIMARY_SHA, "primary evidence SHA")? {
        return Err("primary evidence changed".into());
    }
    let (plan_bytes, plan_sha) = read_bound_recovery_file(Path::new(PLAN), 16 * 1024 * 1024, true)?;
    if plan_sha != parse_lower_sha256(PLAN_SHA, "planning report SHA")? {
        return Err("planning report changed".into());
    }
    let primary: Value = serde_json::from_slice(&primary).map_err(|e| e.to_string())?;
    if primary["schema"] != "jetstreamer-epoch220-complete-prefix-primary-evidence-v1"
        || primary["publication_authorized"] != false
        || primary["recovery_manifest_created"] != false
    {
        return Err("foreign primary evidence authority".into());
    }
    let selection = root_checkpoint_cohort_runtime(220, 222, true)?;
    let plan = root_checkpoint_cohort_plan_from_report(
        serde_json::from_slice(&plan_bytes).map_err(|e| e.to_string())?,
        FINGERPRINT,
        220,
        222,
        selection,
    )?;
    let candidate = gate(&primary["extracted"], &plan)?;
    Ok(
        json!({"schema":"horizon-failed-prefix220-checkpoint-probe-v1","epochs":[220,222],"primary_evidence_sha256":PRIMARY_SHA,"planning_report_sha256":PLAN_SHA,"manifest_fingerprint":FINGERPRINT,"checkpoint_candidate":candidate,"complete_archive_reread_proven":false,"archive_provenance_qualified":false,"independent_boundary_anchors_proven":false,"archive_mutations":false,"recovery_manifest_created":false,"replay_launch_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false}),
    )
}

const ARCHIVES: &str = "/home/ubuntu/.jetstreamer-private/adaptive-220-223-current-9d8e964-v1/lane-a/private/destination-5af206ff1dc2bf937d80da0ea255ab459f3b370f67b1c83ed238da29f1de146e/work/root-cohort-220-223/run-2161856-1791998246210466037/archives";
const READ_IIDS: [&str; 3] = [
    "1536bf6f640d4df280f8bedf86a55094",
    "d82f8375cc184e5283a1694c48009ac4",
    "4a699212c24b43b488c87165ac4ba326",
];
const BYTES: [u64; 3] = [135699623364, 137055363091, 133175903649];
const INODES: [u64; 3] = [2259411, 2259414, 2259426];
const SOURCE_STATE_SHA: &str = "7b74a2c7b752476c1c8d284f5f7b3fa15d43abce29c6b3f93075b568ca423274";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryPlan {
    schema: String,
    primary_evidence: PathBuf,
    planning_report: PathBuf,
    recovery_receipt: PathBuf,
}

fn admitted_live_producer(name: &str, fields: &BTreeMap<String, String>) -> bool {
    let expected = match name {
        "horizon-qualify-203-shrink-root-prefix-resource-f9fc5a0-v1.service" => {
            "748ffa40e0a2408da0a10fc9e160cf0a"
        }
        "horizon-qualify-223-singleton-postcount-ad1d65a-v1.service" => {
            "04ef9d97a36446d49b452d982cb0be46"
        }
        _ => return false,
    };
    fields.get("InvocationID").is_some_and(|s| s == expected)
        && fields.get("NRestarts").is_some_and(|s| s == "0")
        && fields.get("ActiveState").is_some_and(|s| s == "active")
        && fields.get("SubState").is_some_and(|s| s == "running")
}

fn completed_restore213_shape(name: &str, fields: &BTreeMap<String, String>) -> bool {
    name == "horizon-qualify-213-native-restore-probe-4be930c-v2.service"
        && [
            ("LoadState", "loaded"),
            ("ActiveState", "active"),
            ("SubState", "exited"),
            ("InvocationID", "608650028a454c6ea9181e5607f3bd30"),
            ("MainPID", "0"),
            ("NRestarts", "0"),
            ("Result", "success"),
            ("ExecMainStatus", "0"),
        ]
        .iter()
        .all(|(key, value)| fields.get(*key).is_some_and(|s| s == value))
}

fn completed_restore213_quiescent(
    name: &str,
    fields: &BTreeMap<String, String>,
) -> Result<bool, String> {
    if !completed_restore213_shape(name, fields) {
        return Ok(false);
    }
    // Exact old RemainAfterExit oneshot: success/exited is not a live producer.
    // Still prove no residual cgroup process and stable manager identity.
    let path = PathBuf::from("/sys/fs/cgroup/system.slice")
        .join(name)
        .join("cgroup.procs");
    match fs::read_to_string(&path) {
        Ok(procs) if procs.trim().is_empty() => (),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        _ => return Err("completed213 probe still has processes or unreadable cgroup".into()),
    }
    let after = systemd_recovery_fields(name, "horizon-qualify-")?;
    if after != *fields {
        return Err("completed213 probe changed during quiescence check".into());
    }
    Ok(true)
}

/// A complete producer-manager census, not just the original two owners.
/// Unknown live or queued replacement producers block this incident import.
fn no_replacement_producers() -> Result<(), String> {
    let output = std::process::Command::new("/usr/bin/systemctl")
        .args([
            "list-units",
            "--all",
            "--type=service",
            "--plain",
            "--no-legend",
            "--no-pager",
            "--full",
        ])
        .output()
        .map_err(|e| e.to_string())?;
    if !output.status.success() {
        return Err("cannot census producer manager".into());
    }
    let text = std::str::from_utf8(&output.stdout).map_err(|e| e.to_string())?;
    let prefixes = [
        "horizon-qualify-",
        "horizon-controller-",
        "jetstreamer-root-sweep-",
    ];
    for line in text.lines().filter(|s| !s.trim().is_empty()) {
        let columns: Vec<_> = line.split_whitespace().collect();
        if columns.len() < 4 {
            return Err("malformed producer manager census".into());
        }
        let name = columns[0];
        let Some(prefix) = prefixes.iter().find(|p| name.starts_with(**p)) else {
            continue;
        };
        if matches!(columns[2], "inactive" | "failed") {
            continue;
        }
        let fields = systemd_recovery_fields(name, prefix)?;
        if !admitted_live_producer(name, &fields) && !completed_restore213_quiescent(name, &fields)?
        {
            return Err(format!("unqualified live/replacement producer {name}"));
        }
    }
    let jobs = std::process::Command::new("/usr/bin/systemctl")
        .args([
            "list-jobs",
            "--plain",
            "--no-legend",
            "--no-pager",
            "--full",
        ])
        .output()
        .map_err(|e| e.to_string())?;
    if !jobs.status.success() {
        return Err("cannot census queued producers".into());
    }
    for line in std::str::from_utf8(&jobs.stdout)
        .map_err(|e| e.to_string())?
        .lines()
        .filter(|s| !s.trim().is_empty())
    {
        let columns: Vec<_> = line.split_whitespace().collect();
        if columns.len() != 4 {
            return Err("malformed queued producer census".into());
        }
        if prefixes.iter().any(|p| columns[1].starts_with(p)) {
            return Err(format!("queued replacement {}", columns[1]));
        }
    }
    Ok(())
}

fn original_owners_terminal(primary: &Value) -> Result<(), String> {
    for (key, name, prefix) in [
        (
            "producer",
            "jetstreamer-root-sweep-horizon-220-223-current-v1-e220-223-lane-a-1.service",
            "jetstreamer-root-sweep-",
        ),
        (
            "controller",
            "horizon-controller-220-223-current-v1.service",
            "horizon-controller-",
        ),
    ] {
        let actual = systemd_recovery_fields(name, prefix)?;
        for field in [
            "LoadState",
            "ActiveState",
            "SubState",
            "Result",
            "MainPID",
            "InvocationID",
            "NRestarts",
            "ExecMainStatus",
        ] {
            if actual.get(field).map(String::as_str) != primary[key][field].as_str() {
                return Err(format!("original {key} changed at {field}"));
            }
        }
    }
    Ok(())
}

fn source_state_unchanged() -> Result<(), String> {
    let path = Path::new(ARCHIVES)
        .parent()
        .ok_or("source run missing")?
        .join(COHORT_RUN_STATE_FILE);
    let (bytes, sha) = read_bound_recovery_file(&path, MAX_COHORT_RUN_STATE_BYTES, false)?;
    if sha != parse_lower_sha256(SOURCE_STATE_SHA, "original state")? {
        return Err("original failed source state changed".into());
    }
    let state: CohortRunState = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    if state.schema != "jetstreamer-root-cohort-run-v1"
        || state.status != "running-private"
        || state.start_epoch != 220
        || state.end_epoch != 223
        || state.manifest_fingerprint
            != "sha256:155907db8b743b54af2746d949893cad0c299cda3ad8900017420bc06ff9de42"
    {
        return Err("original failed source scope changed".into());
    }
    Ok(())
}

fn trusted219_terminal() -> Result<ArchiveBlockEvidence, String> {
    let path = Path::new("/home/ubuntu/horizon/epoch-219.jet");
    let file = jetstreamer_node::archive_checksum::open_regular_nofollow(path)
        .map_err(|e| e.to_string())?;
    let measured = jetstreamer_node::archive_checksum::measure_open_archive(&file)
        .map_err(|e| e.to_string())?;
    if measured.sha256
        != parse_lower_sha256(
            "44aa425194e6ccf8848075658aa54f89f0030d43f825e16a277f697f4c38b4fd",
            "trusted219",
        )?
    {
        return Err("trusted219 content changed".into());
    }
    let reader = jetstreamer_horizon::archive::ArchiveReader::open(std::io::BufReader::new(file))
        .map_err(|e| e.to_string())?;
    let count = reader.bucket_count();
    if reader.header().epoch != 219 || count == 0 {
        return Err("trusted219 header changed".into());
    }
    let tail = verify_archive_bucket_range(path, measured.identity, count - 1, count, None)?;
    let terminal = tail
        .chain
        .terminal_block
        .ok_or("trusted219 terminal missing")?;
    if terminal.slot != 95039999
        || terminal.blockhash.to_string() != "4MaWCL7a9CgF9XrNHgt9TA5cryFkW8P7S6aCdCU8cXRW"
        || !jetstreamer_node::archive_checksum::path_matches_archive_identity(
            path,
            measured.identity,
        )
        .map_err(|e| e.to_string())?
    {
        return Err("trusted219 terminal/identity changed".into());
    }
    Ok(terminal)
}

fn bind_first_anchor(
    first: &ArchiveChainEvidence,
    prior: ArchiveBlockEvidence,
) -> Result<(), String> {
    let first_block = first.first_block.ok_or("epoch220 first block missing")?;
    if first.initial_poh_anchor != Some(prior.blockhash)
        || first_block.parent_slot != prior.slot
        || first_block.parent_blockhash != prior.blockhash
    {
        return Err("epoch220 does not continue trusted219 terminal".into());
    }
    Ok(())
}

/// Separate incident-specific import. Never uses the SIGTERM/whole-cohort exception.
/// Every archive passes normal full semantic/PoH validation and hashing again.
pub(super) fn recover(
    plan_path: &Path,
    plan_sha: &str,
    self_sha: &str,
    preflight_only: bool,
) -> Result<Value, String> {
    use std::os::unix::fs::MetadataExt;
    if effective_user_id() != 1000 || env::var_os(PRIVATE_RUN_ROOT_ENV).is_some() {
        return Err(
            "failed-prefix recovery requires original uid1000 and default shared epoch leases"
                .into(),
        );
    }
    let executable = fs::read_link("/proc/self/exe").map_err(|e| e.to_string())?;
    if hash_bound_recovery_file(&executable)? != parse_lower_sha256(self_sha, "self SHA")? {
        return Err("recovery executable differs".into());
    }
    if fs::symlink_metadata(plan_path)
        .map_err(|e| e.to_string())?
        .uid()
        != 0
    {
        return Err("recovery plan must be root-owned".into());
    }
    let (bytes, sha) = read_bound_recovery_file(plan_path, 65536, true)?;
    if sha != parse_lower_sha256(plan_sha, "plan SHA")? {
        return Err("recovery plan differs".into());
    }
    let input: RecoveryPlan = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    if input.schema != "horizon-failed-prefix220-recovery-plan-v1" {
        return Err("wrong recovery schema".into());
    }
    let receipt_parent =
        Path::new("/home/ubuntu/.jetstreamer-private/failed-prefix220-recovery-mountfix-v2");
    if input.recovery_receipt != receipt_parent.join("validation.json")
        || receipt_parent.canonicalize().map_err(|e| e.to_string())? != receipt_parent
    {
        return Err("recovery receipt escaped exact private directory".into());
    }
    let receipt_meta = fs::symlink_metadata(receipt_parent).map_err(|e| e.to_string())?;
    if !receipt_meta.is_dir() || receipt_meta.uid() != 1000 || receipt_meta.mode() & 0o077 != 0 {
        return Err("recovery receipt directory is not caller-private".into());
    }
    let (primary_bytes, primary_sha) =
        read_bound_recovery_file(&input.primary_evidence, 256 * 1024, true)?;
    let (planning_bytes, planning_sha) =
        read_bound_recovery_file(&input.planning_report, 16 * 1024 * 1024, true)?;
    if primary_sha != parse_lower_sha256(PRIMARY_SHA, "primary SHA")?
        || planning_sha != parse_lower_sha256(PLAN_SHA, "planning SHA")?
    {
        return Err("recovery inputs differ from exact audited incident".into());
    }
    let primary: Value = serde_json::from_slice(&primary_bytes).map_err(|e| e.to_string())?;
    original_owners_terminal(&primary)?;
    no_replacement_producers()?;
    source_state_unchanged()?;
    let selection = root_checkpoint_cohort_runtime(220, 222, true)?;
    let plan = root_checkpoint_cohort_plan_from_report(
        serde_json::from_slice(&planning_bytes).map_err(|e| e.to_string())?,
        FINGERPRINT,
        220,
        222,
        selection,
    )?;
    let gate = gate(&primary["extracted"], &plan)?;
    let destination = BoundDestination::bind(Path::new("/home/ubuntu/horizon"))?;
    let _leases = acquire_epoch_leases(destination.path(), 220, 222)?;
    for epoch in 220..=222 {
        require_recovery_destination_namespace_absent(
            &destination.path().join(format!("epoch-{epoch}.jet")),
        )?;
    }
    // The real publication's cross-directory rename/exchange capabilities must
    // hold in THIS sandbox before spending the full rereads. Equal st_dev is
    // insufficient when source/destination are separate bind mounts.
    jetstreamer_node::archive_publish::preflight_archive_publication(
        Path::new(ARCHIVES),
        destination.path(),
    )
    .map_err(|e| format!("failed-prefix filesystem preflight: {e}"))?;
    if preflight_only {
        return Ok(
            json!({"schema":"horizon-failed-prefix220-recovery-preflight-v1","epochs":[220,221,222],"plan_sha256":plan_sha,"self_sha256":self_sha,"original_owners_terminal":true,"source_state_unchanged":true,"no_replacement_producers":true,"shared_epoch_leases_acquired":true,"destination_namespace_absent":true,"cross_directory_rename_exchange_probe_passed":true,"private_probe_entries_created_and_removed":true,"full_validation_completed":false,"publication_authorized":false,"archive_mutations":false,"remote_mutations":false,"r2_mutations":false}),
        );
    }
    let prior = trusted219_terminal()?;
    let mut recovered = std::thread::scope(|scope| {
        let handles: Vec<_> = (220..=222)
            .map(|epoch| {
                let destination = &destination;
                scope.spawn(move || -> Result<RecoveredCohortEpoch, String> {
                    let source_archive = PathBuf::from(format!("{ARCHIVES}/epoch-{epoch}.jet"));
                    let index = (epoch - 220) as usize;
                    let meta = fs::symlink_metadata(&source_archive).map_err(|e| e.to_string())?;
                    if !meta.is_file()
                        || meta.uid() != 1000
                        || meta.gid() != 1000
                        || meta.nlink() != 1
                        || meta.dev() != 66305
                        || meta.ino() != INODES[index]
                        || meta.len() != BYTES[index]
                        || meta.mode() & 0o777 != 0o440
                    {
                        return Err(format!("epoch{epoch} original source identity changed"));
                    }
                    let mut archive_chain = ArchiveChainEvidence::default();
                    let pool = rayon::ThreadPoolBuilder::new()
                        .num_threads(8)
                        .build()
                        .map_err(|e| e.to_string())?;
                    let validated = pool
                        .install(|| {
                            validated_cohort_epoch_archive(
                                &source_archive,
                                epoch,
                                true,
                                None,
                                Some(&mut archive_chain),
                            )
                        })?
                        .ok_or_else(|| format!("epoch{epoch} incomplete"))?;
                    let provenance = read_bound_cohort_provenance(&source_archive, validated)?;
                    Ok(RecoveredCohortEpoch {
                        epoch,
                        source_archive,
                        destination_archive: destination.path().join(format!("epoch-{epoch}.jet")),
                        provenance,
                        archive_chain,
                        validated,
                    })
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| {
                h.join()
                    .map_err(|_| "failed-prefix reader panicked".to_owned())?
            })
            .collect::<Result<Vec<_>, String>>()
    })?;
    recovered.sort_by_key(|a| a.epoch);
    validate_recovered_cohort_gate(&plan, &recovered, &gate)?;
    bind_first_anchor(&recovered[0].archive_chain, prior)?;
    original_owners_terminal(&primary)?;
    no_replacement_producers()?;
    source_state_unchanged()?;
    destination.revalidate()?;
    for item in &recovered {
        require_recovery_destination_namespace_absent(&item.destination_archive)?;
    }
    let members: Vec<_> = recovered.iter().map(|a|json!({"epoch":a.epoch,"path":a.source_archive,"sha256":jetstreamer_node::segment_manifest::sha256_hex_string(&a.validated.sha256)})).collect();
    let receipt = json!({"schema":"horizon-failed-prefix220-recovery-validation-v1","plan":plan_path,"plan_sha256":plan_sha,"self_sha256":self_sha,"primary_evidence_sha256":PRIMARY_SHA,"planning_report_sha256":PLAN_SHA,"source_state_sha256":SOURCE_STATE_SHA,"epochs":[220,221,222],"validated_members":members,"root_checkpoint_gate":gate,"trusted219_terminal":prior.blockhash.to_string(),"complete_archive_reread_passed":true,"source_run_cleanup_authorized":false,"remote_mutations":false,"r2_mutations":false});
    let receipt_sha = write_or_validate_recovery_receipt(&input.recovery_receipt, &receipt)?;
    let epochs = vec![220, 221, 222];
    let fingerprint = manifest_fingerprint_digest(FINGERPRINT)?;
    let context =
        cohort_publication::encode_root_checkpoint_gate_context(fingerprint, &epochs, &gate)?;
    let items: Vec<_> = recovered
        .iter()
        .map(|a| jetstreamer_node::archive_publish::ArchiveBatchItem {
            epoch: a.epoch,
            staged_archive: a.source_archive.clone(),
            destination_archive: a.destination_archive.clone(),
            evidence: a.validated,
        })
        .collect();
    let expected: Vec<_> = recovered
        .iter()
        .map(|a| cohort_publication::ExpectedCohortArchive {
            epoch: a.epoch,
            destination_archive: &a.destination_archive,
            sha256: a.validated.sha256,
        })
        .collect();
    let receipts = cohort_batch_receipt_directory(&destination)?;
    let publication=jetstreamer_node::archive_publish::publish_verified_archive_batch_if_absent_with_context_and_lock_timeout(fingerprint,&epochs,&items,&context,COHORT_IMPORT_WRITER_LOCK_TIMEOUT).map_err(|e|format!("failed-prefix publication (state={:?}, recovery={:?}): {e}",e.commit_state(),e.recovery_directory()))?;
    let completed = cohort_publication::finish_root_checkpoint_publication(
        destination.publication_binding(),
        &receipts,
        fingerprint,
        &expected,
        &publication,
        &gate,
    )?;
    // The failed source run contains preserved partial223 and is NEVER cleaned here.
    Ok(
        json!({"schema":"horizon-failed-prefix220-recovery-completed-v1","epochs":epochs,"recovery_receipt":input.recovery_receipt,"recovery_receipt_sha256":jetstreamer_node::segment_manifest::sha256_hex_string(&receipt_sha),"publication_receipt":completed.receipt_path,"publication_transaction_id":jetstreamer_node::segment_manifest::sha256_hex_string(&completed.transaction_id),"archive_count":completed.archive_count,"source_run_preserved":true,"partial223_preserved":true,"r2_ready_pair_proven":false,"remote_mutations":false,"r2_mutations":false}),
    )
}
fn full_receipt(receipt: &Value, epoch: u64, path: &Path) -> Result<(), String> {
    let index = usize::try_from(epoch.checked_sub(220).ok_or("epoch below prefix")?)
        .map_err(|e| e.to_string())?;
    if index >= 3 {
        return Err("epoch above complete prefix".into());
    }
    if receipt["schema"] != "horizon-private-full-verification-v1"
        || receipt["status"] != "passed"
        || receipt["epoch"] != epoch
        || receipt["archive"]["path"].as_str() != path.to_str()
        || receipt["archive"]["bytes"] != BYTES[index]
        || receipt["archive"]["uid"] != 1000
        || receipt["archive"]["gid"] != 1000
        || receipt["archive"]["mode"] != "0440"
        || receipt["unit"]["invocation_id"] != READ_IIDS[index]
        || receipt["unit"]["name"]
            != format!("horizon-independent-full-read-{epoch}-retained-prefix-v1.service")
        || receipt["unit"]["result"] != "success"
        || receipt["unit"]["exec_main_status"] != 0
        || receipt["unit"]["restarts"] != 0
        || receipt["command"]["full"] != true
        || receipt["command"]["internal_full"] != true
        || receipt["command"]["threads"] != 8
        || receipt["verifier"]["sha256"]
            != "8a3c45b958bf69e6d8463d2e215cbd0ff30ec2c251c4d20ae40193a6cecae9f3"
        || receipt["collector_sha256"]
            != "ed56154c58f939b0f461dd4afc31e88986f994407d12681120e446bed236fecd"
        || receipt["publication_authorized"] != false
        || [
            "archive_mutations",
            "sidecar_created",
            "replay_launch_authorized",
            "remote_mutations",
            "r2_mutations",
        ]
        .iter()
        .any(|key| receipt[*key] != false)
    {
        return Err("private reread receipt does not bind exact original reader/archive".into());
    }
    Ok(())
}
/// Measure the preserved immutable content only after its independent reread.
/// This is a separate hash event, never an alias for a hash-bound full receipt.
pub(super) fn artifact_probe(epoch: u64) -> Result<Value, String> {
    use std::os::unix::fs::MetadataExt;
    let index = usize::try_from(epoch.checked_sub(220).ok_or("epoch below prefix")?)
        .map_err(|e| e.to_string())?;
    if index >= 3 {
        return Err("epoch above prefix".into());
    }
    let path = PathBuf::from(format!("{ARCHIVES}/epoch-{epoch}.jet"));
    let receipt_path = PathBuf::from(format!(
        "/var/lib/jetstreamer/horizon-retained220-222-full-results-v1/epoch-{epoch}.json"
    ));
    let (receipt_bytes, receipt_sha) = read_bound_recovery_file(&receipt_path, 1024 * 1024, true)?;
    full_receipt(
        &serde_json::from_slice(&receipt_bytes).map_err(|e| e.to_string())?,
        epoch,
        &path,
    )?;
    let file = jetstreamer_node::archive_checksum::open_regular_nofollow(&path)
        .map_err(|e| e.to_string())?;
    let before = file.metadata().map_err(|e| e.to_string())?;
    let initial_identity = jetstreamer_node::archive_checksum::archive_file_identity(&file)
        .map_err(|e| e.to_string())?;
    if !before.is_file()
        || before.dev() != 66305
        || before.ino() != INODES[index]
        || before.len() != BYTES[index]
        || before.uid() != 1000
        || before.gid() != 1000
        || before.mode() & 0o777 != 0o440
        || before.nlink() != 1
    {
        return Err("original archive identity changed".into());
    }
    let reader = jetstreamer_horizon::archive::ArchiveReader::open(std::io::BufReader::new(
        file.try_clone().map_err(|e| e.to_string())?,
    ))
    .map_err(|e| e.to_string())?;
    if reader.header().epoch != epoch
        || reader.header().slot_start != epoch * 432000
        || reader.header().slot_count != 432000
    {
        return Err("archive coverage changed".into());
    }
    let provenance = reader
        .provenance()
        .map_err(|e| e.to_string())?
        .ok_or("missing provenance")?;
    let encoded = jetstreamer_horizon::archive::encode_archive_provenance(&provenance)
        .map_err(|e| e.to_string())?;
    let measured = jetstreamer_node::archive_checksum::measure_open_archive(&file)
        .map_err(|e| e.to_string())?;
    if measured.identity != initial_identity
        || !jetstreamer_node::archive_checksum::path_matches_archive_identity(
            &path,
            measured.identity,
        )
        .map_err(|e| e.to_string())?
        || before.dev() != file.metadata().map_err(|e| e.to_string())?.dev()
        || before.ino() != file.metadata().map_err(|e| e.to_string())?.ino()
    {
        return Err("archive changed while measuring".into());
    }
    let (again, again_sha) = read_bound_recovery_file(&receipt_path, 1024 * 1024, true)?;
    if receipt_sha != again_sha || receipt_bytes != again {
        return Err("private reread receipt changed".into());
    }
    let hex = jetstreamer_node::segment_manifest::sha256_hex_string;
    Ok(
        json!({"schema":"horizon-failed-prefix220-artifact-probe-v1","epoch":epoch,"archive":path,"device":before.dev(),"inode":before.ino(),"bytes":before.len(),"sha256":hex(&measured.sha256),"provenance_sha256":hex(&Sha256::digest(&encoded).into()),"provenance_encoded_base64":BASE64_STANDARD.encode(&encoded),"provenance_debug":format!("{provenance:?}"),"prior_internal_reread_receipt":receipt_path,"prior_internal_reread_receipt_sha256":hex(&receipt_sha),"hash_event_separate_from_internal_reread":true,"hash_bound_full_receipt_created":false,"archive_provenance_qualified":false,"archive_mutations":false,"sidecar_created":false,"replay_launch_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn trusted_prior_must_bind_initial_anchor_and_first_parent() {
        let prior = ArchiveBlockEvidence {
            slot: 95039999,
            parent_slot: 95039998,
            parent_blockhash: Hash::new_unique(),
            blockhash: Hash::new_unique(),
        };
        let first = ArchiveBlockEvidence {
            slot: 95040000,
            parent_slot: prior.slot,
            parent_blockhash: prior.blockhash,
            blockhash: Hash::new_unique(),
        };
        let chain = ArchiveChainEvidence {
            initial_poh_anchor: Some(prior.blockhash),
            first_block: Some(first),
            terminal_block: None,
        };
        bind_first_anchor(&chain, prior).unwrap();
        let mut bad = chain;
        bad.initial_poh_anchor = Some(Hash::new_unique());
        assert!(bind_first_anchor(&bad, prior).is_err());
        let mut bad = chain;
        bad.first_block.as_mut().unwrap().parent_slot -= 1;
        assert!(bind_first_anchor(&bad, prior).is_err());
        let mut bad = chain;
        bad.first_block.as_mut().unwrap().parent_blockhash = Hash::new_unique();
        assert!(bind_first_anchor(&bad, prior).is_err());
        assert!(bind_first_anchor(&ArchiveChainEvidence::default(), prior).is_err());
    }
    #[test]
    fn producer_census_rejects_unknown_restarted_or_replaced_owners() {
        let name = "horizon-qualify-223-singleton-postcount-ad1d65a-v1.service";
        let mut fields = BTreeMap::from([
            (
                "InvocationID".into(),
                "04ef9d97a36446d49b452d982cb0be46".into(),
            ),
            ("NRestarts".into(), "0".into()),
            ("ActiveState".into(), "active".into()),
            ("SubState".into(), "running".into()),
        ]);
        assert!(admitted_live_producer(name, &fields));
        assert!(!admitted_live_producer(
            "horizon-qualify-221-replacement.service",
            &fields
        ));
        fields.insert("NRestarts".into(), "1".into());
        assert!(!admitted_live_producer(name, &fields));
        fields.insert("NRestarts".into(), "0".into());
        fields.insert("InvocationID".into(), "changed".into());
        assert!(!admitted_live_producer(name, &fields));
    }
    #[test]
    fn completed_restore_is_not_a_generic_active_exited_exception() {
        let name = "horizon-qualify-213-native-restore-probe-4be930c-v2.service";
        let fields = BTreeMap::from([
            ("LoadState".into(), "loaded".into()),
            ("ActiveState".into(), "active".into()),
            ("SubState".into(), "exited".into()),
            (
                "InvocationID".into(),
                "608650028a454c6ea9181e5607f3bd30".into(),
            ),
            ("MainPID".into(), "0".into()),
            ("NRestarts".into(), "0".into()),
            ("Result".into(), "success".into()),
            ("ExecMainStatus".into(), "0".into()),
        ]);
        assert!(completed_restore213_shape(name, &fields));
        assert!(!completed_restore213_shape(
            "horizon-qualify-221-foreign.service",
            &fields
        ));
        for key in [
            "InvocationID",
            "MainPID",
            "NRestarts",
            "SubState",
            "Result",
            "ExecMainStatus",
        ] {
            let mut bad = fields.clone();
            bad.insert(key.into(), "different".into());
            assert!(!completed_restore213_shape(name, &bad), "{key}");
        }
    }
    #[test]
    fn failed_prefix_recovery_plan_cannot_grow_scope_or_skip_validation() {
        let plan = json!({"schema":"horizon-failed-prefix220-recovery-plan-v1","primary_evidence":"/a","planning_report":"/b","recovery_receipt":"/c"});
        assert!(serde_json::from_value::<RecoveryPlan>(plan.clone()).is_ok());
        for key in [
            "epochs",
            "skip_full",
            "source_run",
            "destination",
            "delete_source",
            "publish_through_epoch",
        ] {
            let mut bad = plan.clone();
            bad[key] = json!(true);
            assert!(
                serde_json::from_value::<RecoveryPlan>(bad).is_err(),
                "{key}"
            );
        }
    }
    fn observed(slot: u64) -> Value {
        let summary = UnreceiptedCheckpointSummary {
            slot,
            bank_hash: Hash::new_from_array([1; 32]).to_string(),
            accounts_hash: Hash::new_from_array([2; 32]).to_string(),
            last_blockhash: Hash::new_from_array([3; 32]).to_string(),
            capitalization: 100,
            transaction_count: 10,
            tick_height: (slot + 1) * 64,
            slot_complete: true,
            write_count: 0,
            next_write_version: 20,
        };
        json!({"fields":{"slot":slot.to_string(),"bank_hash":summary.bank_hash,"accounts_hash":summary.accounts_hash,"last_blockhash":summary.last_blockhash,"capitalization":"100","transactions":"10","tick_height":summary.tick_height.to_string(),"complete":"true","writes":"0","next_write_version":"20"},"message":format!("[fixture INFO jetstreamer_node::historical_replay] historical checkpoint slot={slot} bank_hash={} accounts_hash={} last_blockhash={} capitalization=100 transactions=10 tick_height={} complete=true writes=0 next_write_version=20",summary.bank_hash,summary.accounts_hash,summary.last_blockhash,summary.tick_height)})
    }
    #[test]
    fn complete_tuple_is_parsed_not_transcribed() {
        let value = observed(95039516);
        let c = checkpoint(&value).unwrap();
        assert_eq!(c.slot, 95039516);
        assert_eq!(c.last_blockhash, [3; 32]);
        assert_eq!(c.next_write_version, 20);
        for name in [
            "bank_hash",
            "last_blockhash",
            "next_write_version",
            "capitalization",
        ] {
            let mut wrong = value.clone();
            wrong["fields"][name] = json!("changed");
            assert!(checkpoint(&wrong).is_err(), "{name}");
        }
    }
    #[test]
    fn incomplete_noncanonical_and_nonmatching_journal_tuples_reject() {
        for (key, new) in [
            ("complete", json!("false")),
            ("slot", json!("095039516")),
            ("tick_height", json!("1")),
            ("extra", json!("unexpected")),
        ] {
            let mut wrong = observed(95039516);
            wrong["fields"][key] = new;
            assert!(checkpoint(&wrong).is_err());
        }
        let mut wrong = observed(95039516);
        wrong["message"] = json!("historical checkpoint incomplete");
        assert!(checkpoint(&wrong).is_err());
    }
    fn fixture() -> (Value, RootCheckpointCohortPlan) {
        let root = |slot| CohortManifestSnapshot {
            accounts_hash: Hash::new_from_array([2; 32]).to_string(),
            anchor_slot: slot,
            crc32c: String::new(),
            extension: String::new(),
            generation: 1,
            md5_hash: Value::Null,
            size: 1,
            slot,
            source: String::new(),
            uri: String::new(),
            versioned_uri: String::new(),
        };
        let plan = RootCheckpointCohortPlan {
            fingerprint: FINGERPRINT.into(),
            bootstrap: root(95039516),
            root_checkpoints: ROOTS.into_iter().map(root).collect(),
        };
        let prefix:Vec<_>=ROOTS.into_iter().enumerate().map(|(i,slot)|json!({"epoch":220+i as u64,"observed_root":observed(slot),"terminal":observed((221+i as u64)*432000-1),"manifest_root":{"slot":slot,"accounts_hash":Hash::new_from_array([2;32]).to_string()}})).collect();
        (
            json!({"bootstrap":observed(95039516),"complete_prefix":prefix,"failed_slot":96540992}),
            plan,
        )
    }
    #[test]
    fn only_three_complete_prefix_members_preserve_carried_tuples() {
        let (value, plan) = fixture();
        let g = gate(&value, &plan).unwrap();
        assert_eq!(g.members.len(), 3);
        assert_eq!(g.verified_manifest_checkpoints.len(), 3);
        assert_eq!(g.members[0].bootstrap.slot, 95039516);
        assert_eq!(g.members[2].terminal.slot, 96335999);
        for pair in g.members.windows(2) {
            assert_eq!(pair[0].terminal, pair[1].bootstrap);
        }
        for (pointer, new) in [
            ("/complete_prefix/1/epoch", json!(223)),
            (
                "/complete_prefix/2/manifest_root/accounts_hash",
                json!(Hash::new_from_array([9; 32]).to_string()),
            ),
            ("/failed_slot", json!(96540991)),
        ] {
            let mut wrong = value.clone();
            *wrong.pointer_mut(pointer).unwrap() = new;
            assert!(gate(&wrong, &plan).is_err(), "{pointer}");
        }
        let mut wrong = value;
        wrong["complete_prefix"].as_array_mut().unwrap().pop();
        assert!(gate(&wrong, &plan).is_err());
    }
    #[test]
    fn changed_trusted_plan_cannot_be_substituted() {
        let (value, mut plan) = fixture();
        plan.fingerprint = "another".into();
        assert!(gate(&value, &plan).is_err());
        plan.fingerprint = FINGERPRINT.into();
        plan.root_checkpoints[1].accounts_hash = Hash::new_from_array([9; 32]).to_string();
        assert!(gate(&value, &plan).is_err());
    }
    #[test]
    fn artifact_measurement_requires_the_exact_successful_private_reader() {
        let path = PathBuf::from(format!("{ARCHIVES}/epoch-220.jet"));
        let value = json!({"schema":"horizon-private-full-verification-v1","status":"passed","epoch":220,"archive":{"path":path,"bytes":BYTES[0],"uid":1000,"gid":1000,"mode":"0440"},"unit":{"invocation_id":READ_IIDS[0],"name":"horizon-independent-full-read-220-retained-prefix-v1.service","result":"success","exec_main_status":0,"restarts":0},"command":{"full":true,"internal_full":true,"threads":8},"verifier":{"sha256":"8a3c45b958bf69e6d8463d2e215cbd0ff30ec2c251c4d20ae40193a6cecae9f3"},"collector_sha256":"ed56154c58f939b0f461dd4afc31e88986f994407d12681120e446bed236fecd","publication_authorized":false,"archive_mutations":false,"sidecar_created":false,"replay_launch_authorized":false,"remote_mutations":false,"r2_mutations":false});
        full_receipt(&value, 220, &path).unwrap();
        for (key, new) in [
            ("/unit/invocation_id", json!(READ_IIDS[1])),
            ("/archive/bytes", json!(BYTES[0] - 1)),
            ("/epoch", json!(223)),
            ("/command/internal_full", json!(false)),
            ("/unit/restarts", json!(1)),
            ("/status", json!("failed")),
            ("/publication_authorized", json!(true)),
            ("/r2_mutations", json!(true)),
        ] {
            let mut wrong = value.clone();
            *wrong.pointer_mut(key).unwrap() = new;
            assert!(full_receipt(&wrong, 220, &path).is_err(), "{key}");
        }
        assert!(full_receipt(&value, 223, &path).is_err());
        assert!(full_receipt(&value, 219, &path).is_err());
        assert!(full_receipt(&value, 220, Path::new("/different.jet")).is_err());
    }
    #[test]
    #[ignore = "root-only exact incident evidence qualification; read-only"]
    fn actual_pinned_primary_and_replanned_manifest_bind_three_complete_epochs() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let result = probe().unwrap();
        assert_eq!(result["publication_authorized"], false);
        assert_eq!(
            result["checkpoint_candidate"]["members"]
                .as_array()
                .unwrap()
                .len(),
            3
        );
        assert_eq!(
            result["checkpoint_candidate"]["members"][0]["bootstrap"]["slot"],
            95039516u64
        );
        assert_eq!(
            result["checkpoint_candidate"]["members"][2]["terminal"]["slot"],
            96335999u64
        );
        println!("{result}");
    }
}
