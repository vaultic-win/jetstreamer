//! Retire only an exact fallback-published status after its operator owner
//! explicitly releases the epoch. This never establishes archive completion.
use super::*;
use serde_json::{Value, json};
use std::{collections::BTreeSet, os::unix::fs::MetadataExt, process::Command as ProcessCommand};

const PLAN_SCHEMA: &str = "jetstreamer-r2-fallback-inactive-status-plan-v1";
const RELEASE_SCHEMA: &str = "jetstreamer-horizon-fallback-status-owner-release-v1";
const INTENT_SCHEMA: &str = "jetstreamer-r2-fallback-inactive-status-intent-v1";
const COMPLETION_SCHEMA: &str = "jetstreamer-r2-fallback-inactive-status-completion-v1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Bound {
    path: PathBuf,
    sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    bucket: String,
    epoch: u64,
    exclusive_local_epoch_ownership: bool,
    authenticated_other_host_handoffs: Vec<Value>,
    no_archive_or_sidecar_mutations: bool,
    fleet: Bound,
    fallback_plan: Bound,
    fallback_intent: Bound,
    fallback_before: Bound,
    fallback_completion: Bound,
    raw_status: Bound,
    owner_release: Bound,
    #[serde(default)]
    operator_initial_intent: Option<Bound>,
    #[serde(default)]
    operator_initial_completion: Option<Bound>,
    #[serde(default)]
    prior_intent: Option<Bound>,
    public_archive_directory: PathBuf,
    deletion_intent: PathBuf,
    deletion_receipt: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct OwnerRelease {
    schema: String,
    epoch: u64,
    key: String,
    fallback_completion: Bound,
    operator_owner: String,
    operator_work_ended: bool,
    no_active_operator_or_subagent_repair: bool,
    no_other_host_handoff: bool,
    prior_controller_invocation_id: String,
    prior_producer_invocation_id: String,
    next_repair_action: String,
    released_at_utc: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct DeleteIntent {
    schema: String,
    plan: Bound,
    bucket: String,
    epoch: u64,
    key: String,
    fleet: Bound,
    fallback_completion: Bound,
    raw_status: Bound,
    owner_release: Bound,
    prior_intent: Option<Bound>,
    status: EpochStatus,
    object_etag: String,
    archive_completion_claimed: bool,
}

fn sha(bytes: &[u8]) -> String {
    hex_lower(&Sha256::digest(bytes))
}

fn bound_bytes(bound: &Bound, limit: u64, label: &str) -> Result<Vec<u8>> {
    ensure!(
        bound.path.is_absolute()
            && bound.path.canonicalize()? == bound.path
            && bound.sha256.len() == 64
            && bound
                .sha256
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "invalid {label} binding"
    );
    let metadata = fs::symlink_metadata(&bound.path)?;
    ensure!(
        metadata.is_file()
            && metadata.uid() == 0
            && metadata.nlink() == 1
            && metadata.mode() & 0o022 == 0,
        "{label} must be immutable root-owned evidence"
    );
    let bytes = read_stable_bounded(&bound.path, limit, label)?;
    ensure!(sha(&bytes) == bound.sha256, "{label} digest changed");
    Ok(bytes)
}

fn private_paths(plan: &Plan) -> Result<()> {
    ensure!(
        plan.deletion_intent.is_absolute()
            && plan.deletion_receipt.is_absolute()
            && plan.deletion_intent != plan.deletion_receipt
            && plan.deletion_intent.parent() == plan.deletion_receipt.parent()
            && plan.deletion_intent.file_name()
                == Some(std::ffi::OsStr::new(&format!(
                    "epoch-{}.fallback-inactive-status-intent.json",
                    plan.epoch
                )))
            && plan.deletion_receipt.file_name()
                == Some(std::ffi::OsStr::new(&format!(
                    "epoch-{}.fallback-inactive-status-completion.json",
                    plan.epoch
                ))),
        "invalid fallback inactive evidence paths"
    );
    let parent = plan
        .deletion_intent
        .parent()
        .context("missing evidence parent")?;
    let metadata = fs::symlink_metadata(parent)?;
    ensure!(
        parent.canonicalize()? == parent
            && parent.starts_with("/home/ubuntu/.jetstreamer-private/")
            && metadata.is_dir()
            && metadata.uid() == 0
            && metadata.mode() & 0o077 == 0,
        "evidence parent must be canonical root-private state"
    );
    Ok(())
}

fn exact_fallback(plan: &Plan, raw: &[u8]) -> Result<(EpochStatus, String)> {
    let key = format!("epoch-{}.epoch-status.json", plan.epoch);
    let status: EpochStatus = serde_json::from_slice(raw)?;
    validate_epoch_status(&status, plan.epoch)?;
    let completion: Value = serde_json::from_slice(&bound_bytes(
        &plan.fallback_completion,
        MAX_STATUS_BYTES,
        "fallback completion",
    )?)?;
    let intent: Value = serde_json::from_slice(&bound_bytes(
        &plan.fallback_intent,
        MAX_STATUS_BYTES,
        "fallback intent",
    )?)?;
    let before = bound_bytes(&plan.fallback_before, MAX_STATUS_BYTES, "fallback before")?;
    let old: EpochStatus = serde_json::from_slice(&before)?;
    validate_epoch_status(&old, plan.epoch)?;
    let fallback_plan: Value = serde_json::from_slice(&bound_bytes(
        &plan.fallback_plan,
        MAX_STATUS_BYTES,
        "fallback plan",
    )?)?;
    let rows = fallback_plan["rows"]
        .as_array()
        .context("fallback rows absent")?;
    let row: Vec<_> = rows
        .iter()
        .filter(|row| row["epoch"] == plan.epoch)
        .collect();
    ensure!(row.len() == 1, "fallback plan lacks unique epoch row");
    let row = row[0];
    let etag = completion["new_etag"]
        .as_str()
        .context("fallback ETag absent")?;
    ensure!(
        etag.starts_with('"')
            && etag.ends_with('"')
            && etag.len() == 34
            && etag[1..33]
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "fallback ETag is invalid"
    );
    ensure!(
        fallback_plan["owner"] == "/root"
            && fallback_plan["no_archive_or_sidecar_mutation"] == true
            && row["owner"] == "/root"
            && row["key"] == key
            && row["payload"] == plan.raw_status.path.to_string_lossy().as_ref()
            && row["payload_sha256"] == sha(raw)
            && row["status"] == serde_json::to_value(&status)?
            && row["before_etag"] == completion["before_etag"]
            && row["before_sha256"] == sha(&before)
            && intent["epoch"] == plan.epoch
            && intent["key"] == key
            && intent["owner"] == "/root"
            && intent["before_etag"] == completion["before_etag"]
            && intent["before_sha256"] == sha(&before)
            && intent["replacement_sha256"] == sha(raw)
            && intent["remote_archive_mutations"] == false
            && completion["epoch"] == plan.epoch
            && completion["key"] == key
            && completion["owner"] == "/root"
            && completion["new_sha256"] == sha(raw)
            && completion["sampled_at_utc"] == status.sampled_at_utc
            && completion["authenticated_exact_byte_readback"] == true
            && completion["archive_or_sidecar_mutation"] == false,
        "fallback evidence does not bind the exact owned publication"
    );
    Ok((status, etag[1..33].into()))
}

fn validate_release(plan: &Plan, status: &EpochStatus) -> Result<OwnerRelease> {
    let release: OwnerRelease = serde_json::from_slice(&bound_bytes(
        &plan.owner_release,
        MAX_STATUS_BYTES,
        "operator release",
    )?)?;
    validate_release_fields(&release, plan.epoch, &plan.fallback_completion, status)?;
    validate_operator_initial(plan, &release)?;
    Ok(release)
}

fn validate_operator_initial(plan: &Plan, release: &OwnerRelease) -> Result<()> {
    if plan.epoch != 211 {
        ensure!(
            plan.operator_initial_intent.is_none() && plan.operator_initial_completion.is_none(),
            "unexpected operator-only origin evidence"
        );
        return Ok(());
    }
    ensure!(
        release.prior_controller_invocation_id.is_empty()
            && release.prior_producer_invocation_id.is_empty(),
        "epoch 211 has no prior native producer claim"
    );
    let intent_bound = plan
        .operator_initial_intent
        .as_ref()
        .context("epoch 211 initial operator intent is required")?;
    let completion_bound = plan
        .operator_initial_completion
        .as_ref()
        .context("epoch 211 initial operator completion is required")?;
    let intent: Value = serde_json::from_slice(&bound_bytes(
        intent_bound,
        MAX_STATUS_BYTES,
        "initial operator intent",
    )?)?;
    let completion: Value = serde_json::from_slice(&bound_bytes(
        completion_bound,
        MAX_STATUS_BYTES,
        "initial operator completion",
    )?)?;
    let key = format!("epoch-{}.epoch-status.json", plan.epoch);
    ensure!(
        intent["schema"] == "horizon1019-active211-input-qualification-initial-status-intent-v1"
            && intent["epoch"] == plan.epoch
            && intent["bucket"] == plan.bucket
            && intent["key"] == key
            && intent["only_if_absent"] == true
            && intent["no_archive_sidecar_or_other_key_mutation"] == true
            && intent["actual_owner"]["controller"] == "/root"
            && intent["actual_owner"]["native_producer_or_admission_claimed"] == false
            && completion["schema"]
                == "horizon1019-active211-input-qualification-status-completion-v1"
            && completion["epoch"] == plan.epoch
            && completion["intent"] == serde_json::to_value(intent_bound)?
            && completion["actual_owner"] == intent["actual_owner"]
            && completion["after_sha256"] == intent["replacement"]["sha256"]
            && completion["conditional_create_only"] == true
            && completion["authenticated_exact_byte_readback"] == true
            && completion["archive_or_sidecar_mutation"] == false,
        "epoch 211 did not originate as authenticated operator-only status"
    );
    Ok(())
}

fn validate_release_fields(
    release: &OwnerRelease,
    epoch: u64,
    fallback_completion: &Bound,
    status: &EpochStatus,
) -> Result<()> {
    ensure!(
        release.schema == RELEASE_SCHEMA
            && release.epoch == epoch
            && release.key == format!("epoch-{epoch}.epoch-status.json")
            && release.fallback_completion == *fallback_completion
            && release.operator_owner == "/root"
            && release.operator_work_ended
            && release.no_active_operator_or_subagent_repair
            && release.no_other_host_handoff
            && !release.next_repair_action.trim().is_empty()
            && ((epoch == 211
                && release.prior_controller_invocation_id.is_empty()
                && release.prior_producer_invocation_id.is_empty())
                || (epoch != 211
                    && release.prior_controller_invocation_id.len() == 32
                    && release.prior_producer_invocation_id.len() == 32))
            && release
                .prior_controller_invocation_id
                .bytes()
                .all(|b| b.is_ascii_hexdigit())
            && release
                .prior_producer_invocation_id
                .bytes()
                .all(|b| b.is_ascii_hexdigit())
            && fleet::utc_seconds(&release.released_at_utc)?
                > fleet::utc_seconds(&status.sampled_at_utc)?,
        "operator has not released the exact fallback status"
    );
    Ok(())
}

fn same_status(current: &MutableRemoteObject, raw: &[u8], etag: &str) -> Result<()> {
    ensure!(
        current.etag == etag && current.bytes == raw,
        "status changed from the exact fallback publication"
    );
    Ok(())
}

fn recovery_state(
    current_present: bool,
    prior_intent_matches: bool,
    completed: bool,
) -> Result<()> {
    ensure!(
        current_present || prior_intent_matches,
        "unexplained status absence"
    );
    ensure!(
        !completed || (!current_present && prior_intent_matches),
        "completion receipt changed or status reappeared"
    );
    Ok(())
}

fn validate_fleet(
    plan: &Plan,
    status: &EpochStatus,
    etag: &str,
    release: &OwnerRelease,
    recovering_absence: bool,
) -> Result<Value> {
    let fleet: Value =
        serde_json::from_slice(&bound_bytes(&plan.fleet, 32 * 1024 * 1024, "fleet")?)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let sample = fleet::utc_seconds(
        fleet["sampled_at_utc"]
            .as_str()
            .context("fleet sample absent")?,
    )?;
    let recorded = fleet["recorded_unix_seconds"]
        .as_u64()
        .context("fleet record time absent")?;
    ensure!(
        fleet["schema"] == "jetstreamer-horizon-campaign-fleet-v1"
            && fleet["first_epoch"] == 201
            && fleet["last_epoch"] == 300
            && fleet["inventory"]["anomalies"] == 0
            && sample <= recorded
            && recorded <= now
            && now - sample <= 1800
            && now - recorded <= 1800
            && fleet["remote_mutations"] == false,
        "fleet is stale, anomalous or has the wrong assignment"
    );
    fleet_epoch_claims_clear(
        &fleet,
        plan.epoch,
        status,
        etag,
        &release.next_repair_action,
        recovering_absence,
    )?;
    Ok(fleet)
}

fn fleet_epoch_claims_clear(
    fleet: &Value,
    epoch: u64,
    status: &EpochStatus,
    etag: &str,
    next_action: &str,
    recovering_absence: bool,
) -> Result<()> {
    let entry: Vec<_> = fleet["epochs"]
        .as_array()
        .context("fleet epochs absent")?
        .iter()
        .filter(|entry| entry["epoch"] == epoch)
        .collect();
    ensure!(entry.len() == 1, "fleet epoch is not unique");
    let entry = entry[0];
    let status_matches = if recovering_absence {
        entry["status"].is_null()
    } else {
        entry["status"]["payload"] == serde_json::to_value(status)?
            && entry["status"]["etag"] == etag
    };
    ensure!(
        entry["state"] == "failed-needs-repair"
            && status_matches
            && entry["next_action"] == next_action
            && !fleet["active"]
                .as_array()
                .context("fleet active absent")?
                .iter()
                .any(|claim| claim["epoch"] == epoch)
            && !fleet["pipelines"]
                .as_array()
                .context("fleet pipelines absent")?
                .iter()
                .any(|claim| claim["epoch"] == epoch),
        "fleet has active or changed epoch work"
    );
    for diagnostic in fleet["diagnostics"]
        .as_array()
        .context("fleet diagnostics absent")?
    {
        ensure!(
            diagnostic["live"] != true
                || (diagnostic["epoch"] != epoch
                    && !(diagnostic["scope_first_epoch"]
                        .as_u64()
                        .zip(diagnostic["scope_last_epoch"].as_u64())
                        .is_some_and(|(first, last)| first <= epoch && epoch <= last))),
            "epoch has active diagnostic or replacement"
        );
    }
    Ok(())
}

fn claim_census(fleet: &Value) -> Result<Value> {
    let bound = fleet["unit_census"]
        .as_object()
        .context("fleet unit census absent")?;
    let names: BTreeSet<String> = bound.keys().cloned().collect();
    let current = fleet::census(&names, 201, 300)?;
    for (name, prior) in bound {
        let actual = current.get(name).context("tracked unit disappeared")?;
        for field in [
            "InvocationID",
            "ActiveState",
            "SubState",
            "MainPID",
            "NRestarts",
        ] {
            ensure!(
                actual[field] == prior[field],
                "tracked unit identity/state changed since fleet: {name} {field}"
            );
        }
    }
    let jobs = ProcessCommand::new("systemctl")
        .args([
            "list-jobs",
            "--no-legend",
            "--no-pager",
            "--plain",
            "--full",
        ])
        .output()?;
    ensure!(jobs.status.success(), "pending job census failed");
    let pending = inactive_status::queued_job_units(&jobs.stdout)?;
    ensure!(
        !pending.iter().any(|unit| [
            "horizon-controller-",
            "jetstreamer-root-sweep-",
            "horizon-qualify-",
            "horizon-upload-",
            "horizon-publish-",
            "horizon-independent-",
            "horizon-import-",
            "horizon-recover-"
        ]
        .iter()
        .any(|prefix| unit.starts_with(prefix))),
        "a pending campaign job could claim this epoch"
    );
    Ok(serde_json::to_value(&current)?)
}

fn no_local_delivery(plan: &Plan) -> Result<()> {
    ensure!(
        plan.public_archive_directory.is_absolute()
            && plan.public_archive_directory.canonicalize()? == plan.public_archive_directory,
        "public archive directory is not canonical"
    );
    for name in [
        format!("epoch-{}.jet", plan.epoch),
        format!("epoch-{}.jet.sha256", plan.epoch),
    ] {
        match fs::symlink_metadata(plan.public_archive_directory.join(name)) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) => bail!("canonical local artifact exists; reconcile delivery"),
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

fn persist(path: &Path, value: &Value) -> Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    serde_json::to_writer_pretty(&mut file, value)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    File::open(path.parent().context("missing receipt parent")?)?.sync_all()?;
    Ok(())
}

fn existing(path: &Path) -> Result<Option<Value>> {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            ensure!(
                meta.is_file() && meta.uid() == 0 && meta.nlink() == 1 && meta.mode() & 0o077 == 0,
                "unsafe existing receipt"
            );
            Ok(Some(serde_json::from_slice(&read_stable_bounded(
                path,
                MAX_STATUS_BYTES,
                "receipt",
            )?)?))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

pub(super) async fn run() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    ensure!(
        (args.len() == 7 || (args.len() == 8 && args[7] == "--check-only"))
            && args[3] == "--plan-sha256"
            && args[5] == "--self-sha256",
        "usage: jetstreamer-r2 status-delete-fallback-inactive PLAN --plan-sha256 HEX --self-sha256 HEX [--check-only]"
    );
    ensure!(unsafe { libc::geteuid() } == 0, "root required");
    let mut executable = File::open("/proc/self/exe")?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let count = executable.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    ensure!(
        hex_lower(&hasher.finalize()) == args[6],
        "executable digest mismatch"
    );
    let plan_bound = Bound {
        path: args[2].clone().into(),
        sha256: args[4].clone(),
    };
    let plan: Plan = serde_json::from_slice(&bound_bytes(&plan_bound, MAX_STATUS_BYTES, "plan")?)?;
    ensure!(
        plan.schema == PLAN_SCHEMA
            && matches!(plan.epoch, 208 | 211 | 223 | 226 | 227 | 265)
            && plan.exclusive_local_epoch_ownership
            && plan.authenticated_other_host_handoffs.is_empty()
            && plan.no_archive_or_sidecar_mutations,
        "unsupported fallback inactive deletion scope"
    );
    private_paths(&plan)?;
    let raw = bound_bytes(&plan.raw_status, MAX_STATUS_BYTES, "raw status")?;
    let (status, etag) = exact_fallback(&plan, &raw)?;
    let release = validate_release(&plan, &status)?;
    let r2 = r2_config_from_env()?;
    ensure!(r2.bucket == plan.bucket, "R2 bucket differs from plan");
    let s3 = s3_client(&r2);
    let key = format!("epoch-{}.epoch-status.json", plan.epoch);
    let current = get_mutable_object(&s3, &r2.bucket, &key).await?;
    ensure!(
        plan.prior_intent.is_none() || current.is_none(),
        "status reappeared after an interrupted deletion"
    );
    if let Some(current) = &current {
        same_status(current, &raw, &etag)?;
    }
    let fleet = validate_fleet(&plan, &status, &etag, &release, current.is_none())?;
    let initial_census = claim_census(&fleet)?;
    no_local_delivery(&plan)?;
    status_inactive::no_remote_delivery(&s3, &r2, plan.epoch).await?;
    let intent = DeleteIntent {
        schema: INTENT_SCHEMA.into(),
        plan: plan_bound.clone(),
        bucket: r2.bucket.clone(),
        epoch: plan.epoch,
        key: key.clone(),
        fleet: plan.fleet.clone(),
        fallback_completion: plan.fallback_completion.clone(),
        raw_status: plan.raw_status.clone(),
        owner_release: plan.owner_release.clone(),
        prior_intent: plan.prior_intent.clone(),
        status,
        object_etag: etag.clone(),
        archive_completion_claimed: false,
    };
    let intent_value = serde_json::to_value(&intent)?;
    let prior_intent = existing(&plan.deletion_intent)?;
    if let Some(prior) = &prior_intent {
        ensure!(*prior == intent_value, "recovery intent differs");
    }
    let external_intent = plan
        .prior_intent
        .as_ref()
        .map(|binding| -> Result<()> {
            let prior: DeleteIntent = serde_json::from_slice(&bound_bytes(
                binding,
                MAX_STATUS_BYTES,
                "prior deletion intent",
            )?)?;
            ensure!(
                binding.path != plan.deletion_intent
                    && binding.path != plan.deletion_receipt
                    && prior.schema == INTENT_SCHEMA
                    && prior.bucket == intent.bucket
                    && prior.epoch == intent.epoch
                    && prior.key == intent.key
                    && prior.fallback_completion == intent.fallback_completion
                    && prior.raw_status == intent.raw_status
                    && prior.owner_release == intent.owner_release
                    && prior.status == intent.status
                    && prior.object_etag == intent.object_etag
                    && !prior.archive_completion_claimed,
                "prior intent does not bind the exact interrupted deletion"
            );
            Ok(())
        })
        .transpose()?;
    ensure!(
        current.is_some() || external_intent.is_some() || prior_intent.is_some(),
        "unexplained status absence"
    );
    let prior_receipt = existing(&plan.deletion_receipt)?;
    recovery_state(
        current.is_some(),
        prior_intent.is_some() || external_intent.is_some(),
        prior_receipt.is_some(),
    )?;
    if let Some(prior) = &prior_receipt {
        ensure!(
            prior_intent.is_some()
                && current.is_none()
                && prior["schema"] == COMPLETION_SCHEMA
                && prior["intent"] == intent_value
                && prior["authenticated_status_absent_after"] == true
                && prior["archive_completion_claimed"] == false,
            "completion receipt changed or status reappeared"
        );
        println!("{}", plan.deletion_receipt.display());
        return Ok(());
    }
    if args.len() == 8 {
        ensure!(
            claim_census(&fleet)? == initial_census,
            "claim census changed during preflight"
        );
        println!(
            "epoch {}: exact fallback inactive cleanup preflight passed",
            plan.epoch
        );
        return Ok(());
    }
    if prior_intent.is_none() {
        persist(&plan.deletion_intent, &intent_value)?;
    }
    ensure!(
        existing(&plan.deletion_intent)? == Some(intent_value.clone()),
        "intent changed"
    );
    validate_fleet(&plan, &intent.status, &etag, &release, current.is_none())?;
    ensure!(
        claim_census(&fleet)? == initial_census,
        "claim census changed before deletion"
    );
    no_local_delivery(&plan)?;
    status_inactive::no_remote_delivery(&s3, &r2, plan.epoch).await?;
    if current.is_some() {
        let recheck = get_mutable_object(&s3, &r2.bucket, &key).await?;
        same_status(
            recheck
                .as_ref()
                .context("status vanished before conditional delete")?,
            &raw,
            &etag,
        )?;
        conditional_delete_epoch_status(&s3, &r2.bucket, plan.epoch, &etag).await?;
    }
    ensure!(
        get_mutable_object(&s3, &r2.bucket, &key).await?.is_none(),
        "status remains after conditional deletion"
    );
    ensure!(
        claim_census(&fleet)? == initial_census,
        "new claim appeared after deletion"
    );
    no_local_delivery(&plan)?;
    status_inactive::no_remote_delivery(&s3, &r2, plan.epoch).await?;
    let receipt = json!({"schema":COMPLETION_SCHEMA,"intent":intent_value,
        "conditional_delete_request_sent_in_this_invocation":current.is_some(),
        "recovered_absence_from_matching_durable_intent":current.is_none(),
        "authenticated_status_absent_after":true,"unchanged_claim_census":true,
        "archive_completion_claimed":false,
        "verified_unix_seconds":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()});
    persist(&plan.deletion_receipt, &receipt)?;
    println!("{}", plan.deletion_receipt.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status() -> EpochStatus {
        EpochStatus {
            epoch: 223,
            jet_size_bytes: 0,
            elapsed_execution_millis: 10,
            estimated_remaining_millis: 100,
            sampled_at_utc: "2026-11-18T01:31:13Z".into(),
            phase: "verification".into(),
        }
    }

    fn release() -> OwnerRelease {
        OwnerRelease {
            schema: RELEASE_SCHEMA.into(),
            epoch: 223,
            key: "epoch-223.epoch-status.json".into(),
            fallback_completion: Bound {
                path: "/a".into(),
                sha256: "a".repeat(64),
            },
            operator_owner: "/root".into(),
            operator_work_ended: true,
            no_active_operator_or_subagent_repair: true,
            no_other_host_handoff: true,
            prior_controller_invocation_id: "a".repeat(32),
            prior_producer_invocation_id: "b".repeat(32),
            next_repair_action: "qualify input".into(),
            released_at_utc: "2026-11-18T02:00:00Z".into(),
        }
    }

    #[test]
    fn release_rejects_active_repair_newer_owner_and_ambiguous_history() {
        let expected = release();
        assert!(
            validate_release_fields(&expected, 223, &expected.fallback_completion, &status())
                .is_ok()
        );
        let mut changed = expected.clone();
        changed.no_active_operator_or_subagent_repair = false;
        assert!(
            validate_release_fields(&changed, 223, &expected.fallback_completion, &status())
                .is_err()
        );
        changed = expected.clone();
        changed.fallback_completion.sha256 = "b".repeat(64);
        assert!(
            validate_release_fields(&changed, 223, &expected.fallback_completion, &status())
                .is_err()
        );
        changed = expected.clone();
        changed.prior_producer_invocation_id.clear();
        assert!(
            validate_release_fields(&changed, 223, &expected.fallback_completion, &status())
                .is_err()
        );
        changed = expected.clone();
        changed.released_at_utc = status().sampled_at_utc;
        assert!(
            validate_release_fields(&changed, 223, &expected.fallback_completion, &status())
                .is_err()
        );
    }

    #[test]
    fn operator_only_211_release_rejects_a_fabricated_producer() {
        let mut operator_only = release();
        operator_only.epoch = 211;
        operator_only.key = "epoch-211.epoch-status.json".into();
        operator_only.prior_controller_invocation_id.clear();
        operator_only.prior_producer_invocation_id.clear();
        let mut operator_status = status();
        operator_status.epoch = 211;
        assert!(
            validate_release_fields(
                &operator_only,
                211,
                &operator_only.fallback_completion,
                &operator_status,
            )
            .is_ok()
        );
        operator_only.prior_producer_invocation_id = "a".repeat(32);
        assert!(
            validate_release_fields(
                &operator_only,
                211,
                &operator_only.fallback_completion,
                &operator_status,
            )
            .is_err()
        );
    }

    #[test]
    fn changed_payload_etag_and_recovery_without_intent_fail_closed() {
        let raw = serde_json::to_vec(&status()).unwrap();
        let current = MutableRemoteObject {
            bytes: raw.clone(),
            etag: "a".repeat(32),
        };
        assert!(same_status(&current, &raw, &"a".repeat(32)).is_ok());
        assert!(same_status(&current, &raw, &"b".repeat(32)).is_err());
        assert!(same_status(&current, b"changed", &"a".repeat(32)).is_err());
        assert!(recovery_state(false, false, false).is_err());
        assert!(recovery_state(true, true, true).is_err());
        assert!(recovery_state(false, true, false).is_ok());
        assert!(recovery_state(false, true, true).is_ok());
    }

    #[test]
    fn live_replacement_and_downstream_claims_block_cleanup() {
        let status = status();
        let mut fleet = json!({"epochs":[{"epoch":211,"state":"failed-needs-repair",
            "status":{"payload":status,"etag":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
            "next_action":"qualify input"}],"active":[],"pipelines":[],"diagnostics":[]});
        let check = |value: &Value| {
            fleet_epoch_claims_clear(
                value,
                211,
                &status,
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "qualify input",
                false,
            )
        };
        assert!(check(&fleet).is_ok());
        fleet["active"] = json!([{"epoch":211,"unit":"new.service"}]);
        assert!(check(&fleet).is_err());
        fleet["active"] = json!([]);
        fleet["pipelines"] = json!([{"epoch":211,"unit":"upload.service"}]);
        assert!(check(&fleet).is_err());
        fleet["pipelines"] = json!([]);
        fleet["diagnostics"] = json!([{"epoch":211,"live":true}]);
        assert!(check(&fleet).is_err());
        fleet["diagnostics"] = json!([]);
        fleet["epochs"][0]["status"]["etag"] = json!("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        assert!(check(&fleet).is_err());
        fleet["epochs"][0]["status"] = Value::Null;
        assert!(
            fleet_epoch_claims_clear(
                &fleet,
                211,
                &status,
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "qualify input",
                true
            )
            .is_ok()
        );
        assert!(check(&fleet).is_err());
    }
}
