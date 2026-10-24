//! Conditional status-only retirement. Never establishes archive completion.
use super::*;
use serde_json::json;
use std::{collections::BTreeMap, process::Command as ProcessCommand};

mod full210;
mod metadata_cycle;
mod missing157;
mod native207;
mod native209;
mod native210;
mod native223;
mod native227;
mod native227_v1625;
mod native228;
mod natural144;
mod preserved144;
mod publication144;
mod warmup223;
pub(super) fn prepare_publication144_preservation() -> Result<()> {
    publication144::prepare()
}

pub(super) fn private144_terminal_manager_proof(current: &Value) -> Result<()> {
    natural144::terminal_shape(current)?;
    natural144::manager_proof()?;
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Bound {
    path: PathBuf,
    sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    epoch: u64,
    fleet: Bound,
    terminal_fleet: Bound,
    publication: Bound,
    repair_backlog: Bound,
    public_archive_directory: PathBuf,
    status_receipt_directory: PathBuf,
    intent: PathBuf,
    completion: PathBuf,
    exclusive_local_epoch_ownership: bool,
    authenticated_other_host_handoffs: Vec<Value>,
    #[serde(default)]
    prior_intent: Option<Bound>,
    #[serde(default)]
    metadata_completion: Option<Bound>,
    #[serde(default)]
    preserved144_delivery: Option<Bound>,
}

fn bound_json(bound: &Bound) -> Result<Value> {
    ensure!(
        bound.path.is_absolute(),
        "inactive evidence requires absolute path"
    );
    let meta = fs::symlink_metadata(&bound.path)?;
    ensure!(
        meta.is_file() && meta.uid() == 0 && meta.mode() & 0o022 == 0,
        "inactive evidence must be root-owned and non-writable"
    );
    let bytes = read_stable_bounded(&bound.path, 16 * 1024 * 1024, "inactive evidence")?;
    ensure!(
        hex_lower(&Sha256::digest(&bytes)) == bound.sha256,
        "inactive evidence hash mismatch"
    );
    Ok(serde_json::from_slice(&bytes)?)
}

fn terminal(value: &Value, invocation: &str) -> bool {
    value["LoadState"] == "loaded"
        && value["InvocationID"] == invocation
        && ((value["ActiveState"] == "inactive" && value["SubState"] == "dead")
            || (value["ActiveState"] == "failed" && value["SubState"] == "failed"))
        && value["Result"].as_str().is_some_and(|v| !v.is_empty())
        && value["ExecMainStatus"]
            .as_str()
            .and_then(|v| v.parse::<u32>().ok())
            .is_some()
}

fn validate_terminal_owner(current: &Value, historical: &Value, invocation: &str) -> Result<()> {
    ensure!(
        terminal(historical, invocation),
        "missing exact durable terminal owner evidence"
    );
    let collected = current["LoadState"] == "not-found"
        && current["ActiveState"] == "inactive"
        && current["SubState"] == "dead"
        && current["InvocationID"] == "";
    ensure!(
        collected || terminal(current, invocation),
        "owner is live, replaced or ambiguous"
    );
    Ok(())
}

fn validate_preserved_failure(
    current: &BTreeMap<String, Value>,
    evidence: &Value,
    owners: &[(String, String)],
) -> Result<()> {
    ensure!(
        owners.len() == 2
            && evidence["schema"] == "jetstreamer-horizon-terminal-failed-replay-evidence-v1"
            && evidence["controller"]["unit"] == owners[0].0
            && evidence["controller"]["launch_invocation_id"] == owners[0].1
            && evidence["controller"]["retry_path_stopped"] == true
            && evidence["controller"]["active_state"] == "inactive"
            && evidence["controller"]["sub_state"] == "dead"
            && evidence["producer"]["unit"] == owners[1].0
            && evidence["producer"]["invocation_id"] == owners[1].1
            && evidence["producer"]["transient_unit_collected"] == true
            && evidence["producer"]["journal_entry_count"]
                .as_u64()
                .is_some_and(|n| n > 0)
            && evidence["producer"]["journal_export_sha256"]
                .as_str()
                .is_some_and(|s| s.len() == 64)
            && evidence["failure"]["kind"] == "historical-execution-mismatch"
            && evidence["failure"]["slot"].as_u64().is_some_and(|n| n > 0)
            && evidence["failure"]["message"]
                .as_str()
                .is_some_and(|s| !s.is_empty())
            && evidence["publication_authorized"] == false
            && evidence["remote_mutations"] == false
            && evidence["r2_mutations"] == false,
        "preserved failure does not bind the exact old owner"
    );
    let controller = current
        .get(&owners[0].0)
        .context("controller absent from census")?;
    let terminal_id = evidence["controller"]["observed_terminal_invocation_id"]
        .as_str()
        .context("terminal controller ID absent")?;
    ensure!(
        terminal(controller, terminal_id),
        "controller is live, replaced or lacks exact terminal evidence"
    );
    let producer = current
        .get(&owners[1].0)
        .context("producer absent from census")?;
    ensure!(
        (producer["LoadState"] == "not-found"
            && producer["ActiveState"] == "inactive"
            && producer["SubState"] == "dead"
            && producer["InvocationID"] == "")
            || terminal(producer, &owners[1].1),
        "producer is live or replaced"
    );
    Ok(())
}

fn validate_fleet(fleet: &Value, plan: &Plan, now: u64) -> Result<()> {
    ensure!(
        plan.schema == "jetstreamer-horizon-inactive-status-plan-v1"
            && plan.exclusive_local_epoch_ownership
            && plan.authenticated_other_host_handoffs.is_empty(),
        "inactive cleanup requires explicit exclusive ownership and no authenticated handoff"
    );
    let first = fleet["first_epoch"]
        .as_u64()
        .context("fleet range missing")?;
    let last = fleet["last_epoch"]
        .as_u64()
        .context("fleet range missing")?;
    let recorded = fleet["recorded_unix_seconds"]
        .as_u64()
        .context("fleet time missing")?;
    let sample = fleet::utc_seconds(
        fleet["sampled_at_utc"]
            .as_str()
            .context("fleet sample missing")?,
    )?;
    ensure!(
        fleet["schema"] == "jetstreamer-horizon-campaign-fleet-v1"
            && first <= plan.epoch
            && plan.epoch <= last
            && recorded <= now
            && now - recorded <= 1800
            && sample <= recorded
            && now - sample <= 1800,
        "inactive cleanup requires a fresh assigned fleet"
    );
    let active = fleet["active"]
        .as_array()
        .context("fleet active census missing")?;
    ensure!(
        !active.iter().any(|entry| entry["epoch"] == plan.epoch),
        "epoch has active downstream or replay work"
    );
    let epochs = fleet["epochs"].as_array().context("fleet epochs missing")?;
    let entry: Vec<_> = epochs
        .iter()
        .filter(|entry| entry["epoch"] == plan.epoch)
        .collect();
    ensure!(
        entry.len() == 1
            && matches!(
                entry[0]["state"].as_str(),
                Some("failed-needs-repair" | "blocked-qualification" | "not-yet-staged")
            ),
        "epoch is complete, staged, or has a pending delivery claim"
    );
    Ok(())
}

fn owner_units(publication: &StatusPublicationReceipt) -> Result<Vec<(String, String)>> {
    if let Some(binding) = &publication.pipeline_binding {
        binding.validate(publication.epoch, &publication.status.phase)?;
        return Ok(vec![(binding.unit.clone(), binding.invocation_id.clone())]);
    }
    if let Some(owner) = native223_status::inactive_owner(publication)? {
        return Ok(vec![owner]);
    }
    if let Some(owner) = qualification_status::inactive_owner(publication)? {
        return Ok(vec![owner]);
    }
    if let Some(owner) = fleet::full227_status_inactive_owner(publication)? {
        return Ok(vec![owner]);
    }
    if let Some(owner) = fleet::full209_status_inactive_owner(publication)? {
        return Ok(vec![owner]);
    }
    if let Some(owner) = fleet::full210_status_inactive_owner(publication)? {
        return Ok(vec![owner]);
    }
    if let Some(owner) = fleet::prefix223_native20_status_inactive_owner(publication)? {
        return Ok(vec![owner]);
    }
    let bytes = read_stable_bounded(
        &publication.observer_receipt,
        MAX_OBSERVER_RECEIPT_BYTES,
        "owner observer",
    )?;
    validate_observer_binding(
        &bytes,
        &publication.observer_receipt_sha256,
        publication.epoch,
        &publication.controller_invocation_id,
        &publication.producer_invocation_id,
    )?;
    let observer: Value = serde_json::from_slice(&bytes)?;
    let replay = observer["replays"]
        .as_array()
        .context("owner replay census missing")?
        .iter()
        .find(|r| {
            r["producer_after"]["invocation_id"] == publication.producer_invocation_id
                && r["controller_after"]["invocation_id"] == publication.controller_invocation_id
        })
        .context("owner replay missing")?;
    Ok(vec![
        (
            observer_string(replay, &["controller_after", "unit"])?.into(),
            publication.controller_invocation_id.clone(),
        ),
        (
            observer_string(replay, &["producer_after", "unit"])?.into(),
            publication.producer_invocation_id.clone(),
        ),
    ])
}

pub(super) fn queued_job_units(bytes: &[u8]) -> Result<Vec<&str>> {
    let mut names = Vec::new();
    for line in std::str::from_utf8(bytes)?
        .lines()
        .filter(|line| !line.trim().is_empty())
    {
        let columns: Vec<_> = line.split_whitespace().collect();
        ensure!(
            columns.len() == 4 && columns[0].parse::<u64>().is_ok_and(|id| id > 0),
            "unrecognized systemctl job table row"
        );
        names.push(columns[1]);
    }
    Ok(names)
}

pub(super) fn no_pending_owner_trigger(name: &str, collected: bool) -> Result<()> {
    if !collected {
        let output = ProcessCommand::new("systemctl")
            .args(["show", name, "--value", "--property=TriggeredBy"])
            .output()?;
        ensure!(output.status.success(), "cannot inspect owner triggers");
        for trigger in std::str::from_utf8(&output.stdout)?.split_whitespace() {
            let state = ProcessCommand::new("systemctl")
                .args(["show", trigger, "--value", "--property=ActiveState"])
                .output()?;
            ensure!(
                state.status.success()
                    && matches!(
                        std::str::from_utf8(&state.stdout)?.trim(),
                        "inactive" | "failed"
                    ),
                "owner still has a live or queued trigger"
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
    ensure!(jobs.status.success(), "cannot inspect queued owner jobs");
    let jobs = queued_job_units(&jobs.stdout)?;
    ensure!(
        !jobs.iter().any(|unit| *unit == name
            || [
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
        "owner has a queued systemd job"
    );
    Ok(())
}

fn fresh_census(
    plan: &Plan,
    fleet: &Value,
    terminal_fleet: &Value,
    owners: &[(String, String)],
) -> Result<BTreeMap<String, Value>> {
    let bound = fleet["unit_census"]
        .as_object()
        .context("bound fleet census missing")?;
    let names: BTreeSet<String> = bound.keys().cloned().collect();
    let current = fleet::census(
        &names,
        fleet["first_epoch"].as_u64().context("range missing")?,
        fleet["last_epoch"].as_u64().context("range missing")?,
    )?;
    metadata_cycle::validate(plan, fleet, &current)?;
    let preserved_delivery = plan
        .preserved144_delivery
        .as_ref()
        .map(bound_json)
        .transpose()?;
    if let Some(delivery) = &preserved_delivery {
        preserved144::terminal_census(plan, delivery, &current)?;
    }
    let preserved =
        terminal_fleet["schema"] == "jetstreamer-horizon-terminal-failed-replay-evidence-v1";
    if preserved {
        validate_preserved_failure(&current, terminal_fleet, owners)?;
    }
    let missing157 = missing157::recognized(terminal_fleet);
    if missing157 {
        missing157::validate_current(&current, terminal_fleet, owners)?;
    }
    let natural144 = natural144::recognized(terminal_fleet);
    if natural144 {
        natural144::validate_current(&current, terminal_fleet, owners)?;
    }
    let native223 = plan.epoch == 223 && native223::recognized(terminal_fleet, owners);
    if native223 {
        native223::validate(&current, terminal_fleet, owners)?;
    }
    let native207 = plan.epoch == 207 && native207::recognized(terminal_fleet, owners);
    if native207 {
        native207::validate(&current, terminal_fleet, owners)?;
    }
    let native209 = plan.epoch == 209 && native209::recognized(terminal_fleet, owners);
    let native210 = plan.epoch == 210 && native210::recognized(terminal_fleet, owners);
    let full210 = plan.epoch == 210 && full210::recognized(terminal_fleet, owners);
    if full210 {
        full210::validate(&current, terminal_fleet, owners)?;
    }
    let native227_v1625 = plan.epoch == 227 && native227_v1625::recognized(terminal_fleet, owners);
    if native227_v1625 {
        native227_v1625::validate(&current, terminal_fleet, owners)?;
    }
    if native210 {
        native210::validate(&current, terminal_fleet, owners)?;
    }
    if native209 {
        native209::validate(&current, terminal_fleet, owners)?;
    }
    let native228 = plan.epoch == 228 && native228::recognized(terminal_fleet, owners);
    if native228 {
        native228::validate(&current, terminal_fleet, owners)?;
    }
    let warmup223 = plan.epoch == 223 && warmup223::recognized(terminal_fleet, owners);
    if warmup223 {
        warmup223::validate(&current, terminal_fleet, owners)?;
    }
    let native227 = plan.epoch == 227 && native227::recognized(terminal_fleet, owners);
    if native227 {
        native227::validate(&current, terminal_fleet, owners)?;
    }
    let reserve = reserve_owner_evidence(terminal_fleet, owners)?;
    if let Some(stop) = &reserve {
        stop.validate(
            &current,
            0,
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        )?;
    }
    for (name, invocation) in owners {
        let value = current
            .get(name)
            .context("owner omitted from complete census")?;
        if preserved_delivery.is_some() {
            preserved144::terminal_owner(value, &terminal_fleet["unit_census"][name], invocation)?;
        } else if !preserved
            && !missing157
            && !natural144
            && !native223
            && !native207
            && !native209
            && !native210
            && !full210
            && !native227_v1625
            && !native228
            && !warmup223
            && !native227
            && reserve.is_none()
        {
            validate_terminal_owner(value, &terminal_fleet["unit_census"][name], invocation)?;
        }
        no_pending_owner_trigger(name, value["LoadState"] == "not-found")?;
    }
    Ok(current)
}

fn reserve_owner_evidence(
    fleet: &Value,
    owners: &[(String, String)],
) -> Result<Option<reserve_stop::Evidence>> {
    let mut found = None;
    if let Some(stops) = fleet.get("terminal_replays") {
        for stop in stops
            .as_array()
            .context("terminal replay evidence must be an array")?
        {
            let stop: reserve_stop::Evidence = serde_json::from_value(stop.clone())?;
            if stop.owners() == owners {
                ensure!(found.is_none(), "duplicate reserve owner evidence");
                found = Some(stop);
            }
        }
    }
    Ok(found)
}

fn same_object(bytes: &[u8], etag: &str, publication: &StatusPublicationReceipt) -> Result<()> {
    ensure!(
        etag == publication.object_etag && bytes == epoch_status_bytes(&publication.status)?,
        "current status is not the exact latest owned publication"
    );
    Ok(())
}

fn validate_recovery_intent(prior: &Value, expected: &Value) -> Result<()> {
    ensure!(
        prior["schema"] == "jetstreamer-horizon-inactive-status-intent-v1"
            && prior["archive_completion_claimed"] == false,
        "invalid prior inactive cleanup intent"
    );
    for field in [
        "epoch",
        "bucket",
        "key",
        "publication",
        "publication_sha256",
        "status",
        "etag",
        "owners",
    ] {
        ensure!(
            prior.get(field).is_some() && prior[field] == expected[field],
            "prior inactive cleanup intent changed {field}"
        );
    }
    for field in ["preserved144_delivery", "preserved_remote_archive"] {
        ensure!(
            prior.get(field) == expected.get(field),
            "prior inactive cleanup changed preserved artifact binding:{field}"
        );
    }
    Ok(())
}

fn validate_receipt_paths(plan: &Plan) -> Result<()> {
    ensure!(
        plan.intent.is_absolute()
            && plan.completion.is_absolute()
            && plan.intent != plan.completion
            && plan.intent.parent() == plan.completion.parent(),
        "invalid cleanup receipt paths"
    );
    let parent = plan.intent.parent().context("cleanup parent missing")?;
    let meta = fs::symlink_metadata(parent)?;
    ensure!(
        meta.is_dir()
            && parent.canonicalize()? == parent
            && meta.uid() == 0
            && meta.mode() & 0o077 == 0,
        "cleanup receipt directory must be canonical root-only"
    );
    for path in [&plan.intent, &plan.completion] {
        match fs::symlink_metadata(path) {
            Ok(meta) => ensure!(
                meta.is_file() && meta.uid() == 0 && meta.nlink() == 1 && meta.mode() & 0o077 == 0,
                "unsafe existing cleanup receipt"
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    if let Some(prior) = &plan.prior_intent {
        ensure!(
            prior.path != plan.intent && prior.path != plan.completion,
            "recovery intent must preserve prior receipt"
        );
    }
    Ok(())
}

fn no_local_delivery(plan: &Plan) -> Result<()> {
    if let Some(binding) = &plan.preserved144_delivery {
        return preserved144::local(plan, &bound_json(binding)?);
    }
    ensure!(
        plan.public_archive_directory.is_absolute()
            && plan.public_archive_directory.canonicalize()? == plan.public_archive_directory,
        "public archive directory must be canonical"
    );
    for name in [
        format!("epoch-{}.jet", plan.epoch),
        format!("epoch-{}.jet.sha256", plan.epoch),
    ] {
        match fs::symlink_metadata(plan.public_archive_directory.join(name)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) => bail!("local canonical artifact exists; reconcile delivery instead"),
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

async fn no_remote_delivery(s3: &Client, r2: &R2Config, plan: &Plan) -> Result<Value> {
    if let Some(binding) = &plan.preserved144_delivery {
        let proof = bound_json(binding)?;
        if publication144::recognized(&proof) {
            publication144::scope(plan, &proof)?;
        } else {
            preserved144::scope(plan, &proof)?;
        }
        return preserved144::remote(s3, r2).await;
    }
    status_inactive::no_remote_delivery(s3, r2, plan.epoch).await?;
    Ok(Value::Null)
}

pub(super) async fn run() -> Result<()> {
    let args: Vec<_> = env::args().collect();
    ensure!(
        (args.len() == 5 || (args.len() == 6 && args[5] == "--check-only"))
            && args[3] == "--plan-sha256",
        "usage: jetstreamer-r2 status-retire-inactive PLAN --plan-sha256 HEX [--check-only]"
    );
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "inactive cleanup requires root"
    );
    let plan_bound = Bound {
        path: args[2].clone().into(),
        sha256: args[4].clone(),
    };
    let plan: Plan = serde_json::from_value(bound_json(&plan_bound)?)?;
    validate_receipt_paths(&plan)?;
    let fleet = bound_json(&plan.fleet)?;
    let history = bound_json(&plan.terminal_fleet)?;
    let repair = bound_json(&plan.repair_backlog)?;
    ensure!(
        repair["schema"] == "jetstreamer-horizon-open-epoch-repair-v1"
            && repair["epoch"] == plan.epoch
            && repair["open"] == true
            && repair["close_only_after_verified_r2_ready_pair"] == true
            && repair["next_action"]
                .as_str()
                .is_some_and(|s| !s.trim().is_empty()),
        "inactive cleanup requires a preserved open repair entry and next action"
    );
    no_local_delivery(&plan)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    validate_fleet(&fleet, &plan, now)?;
    let history_time = if natural144::recognized(&history) {
        ensure!(
            plan.epoch == 144
                && plan.terminal_fleet.path
                    == Path::new(
                        "/usr/local/lib/jetstreamer/horizon-epoch144-terminal-evidence-20261021-v1/terminal.json"
                    ),
            "foreign144 terminal evidence"
        );
        natural144::time(&history)?
    } else if missing157::recognized(&history) {
        ensure!(
            plan.epoch == 157
                && plan.terminal_fleet.path
                    == Path::new(
                        "/var/lib/jetstreamer/horizon-epoch157-incident-20261021-v1/incident.json"
                    )
                && plan.terminal_fleet.sha256
                    == "00c2bbed7338c19b688a50a7ad14bdc639f98659a56de2cbe8a31abe40c47159",
            "foreign157terminal evidence"
        );
        missing157::time(&history)?
    } else if history["schema"] == "jetstreamer-horizon-terminal-failed-replay-evidence-v1" {
        ensure!(
            history["epoch"] == plan.epoch,
            "terminal evidence epoch differs"
        );
        fleet::utc_seconds(
            history["observed_at_utc"]
                .as_str()
                .context("terminal time missing")?,
        )?
    } else {
        ensure!(
            history["schema"] == fleet["schema"]
                && history["first_epoch"] == fleet["first_epoch"]
                && history["last_epoch"] == fleet["last_epoch"],
            "terminal fleet assignment differs"
        );
        history["recorded_unix_seconds"]
            .as_u64()
            .context("terminal fleet time missing")?
    };
    let r2 = r2_config_from_env()?;
    let (publication, pub_path, pub_sha) =
        latest_status_publication_receipt(&plan.status_receipt_directory, &r2.bucket, plan.epoch)?;
    ensure!(
        pub_path == plan.publication.path && pub_sha == plan.publication.sha256,
        "publication is not latest owned receipt"
    );
    ensure!(
        history_time >= publication.verified_unix_seconds && history_time <= now,
        "terminal evidence predates status publication or is future-dated"
    );
    let owners = owner_units(&publication)?;
    if let Some(binding) = &plan.preserved144_delivery {
        preserved144::owner(&plan, &bound_json(binding)?, &publication)?;
    }
    let before = fresh_census(&plan, &fleet, &history, &owners)?;
    if let Some(stop) = reserve_owner_evidence(&history, &owners)? {
        ensure!(stop.epoch == plan.epoch, "reserve stop epoch differs");
        stop.validate(&before, publication.verified_unix_seconds, now)?;
    }
    let s3 = s3_client(&r2);
    let preserved_remote = no_remote_delivery(&s3, &r2, &plan).await?;
    let key = format!("epoch-{}.epoch-status.json", plan.epoch);
    let current = get_mutable_object(&s3, &r2.bucket, &key).await?;
    if let Some(object) = current.as_ref() {
        same_object(&object.bytes, &object.etag, &publication)?;
    }
    let mut intent = json!({"schema":"jetstreamer-horizon-inactive-status-intent-v1","plan":plan_bound.path,
        "plan_sha256":plan_bound.sha256,"epoch":plan.epoch,"bucket":r2.bucket,"key":key,
        "publication":pub_path,"publication_sha256":pub_sha,"status":publication.status,"etag":publication.object_etag,
        "fleet":plan.fleet.path,"fleet_sha256":plan.fleet.sha256,"terminal_fleet":plan.terminal_fleet.path,
        "terminal_fleet_sha256":plan.terminal_fleet.sha256,"owners":owners,"archive_completion_claimed":false,
        "prior_intent":plan.prior_intent.as_ref().map(|b|json!({"path":b.path,"sha256":b.sha256})),
        "repair_backlog":{"path":plan.repair_backlog.path,"sha256":plan.repair_backlog.sha256}});
    if let Some(binding) = &plan.preserved144_delivery {
        intent["preserved144_delivery"] = json!({"path":binding.path,"sha256":binding.sha256});
        intent["preserved_remote_archive"] = preserved_remote.clone();
    }
    if missing157::recognized(&history) {
        intent["terminal_manager_journal"] = serde_json::to_value(
            status_inactive::cleared_controller_proof(&owners[0].0, &owners[0].1)?,
        )?;
    }
    if natural144::recognized(&history) {
        intent["terminal_manager_journal"] = serde_json::to_value(natural144::manager_proof()?)?;
    }
    if let Some(binding) = &plan.metadata_completion {
        intent["metadata_completion"] = json!({"path":binding.path,"sha256":binding.sha256});
    }
    if let Some(prior) = &plan.prior_intent {
        validate_recovery_intent(&bound_json(prior)?, &intent)?;
    }
    if plan.intent.exists() {
        let bytes = read_stable_bounded(&plan.intent, 1024 * 1024, "inactive intent")?;
        ensure!(
            serde_json::from_slice::<Value>(&bytes)? == intent,
            "existing cleanup intent differs"
        );
    } else {
        if let Some(object) = current.as_ref() {
            same_object(&object.bytes, &object.etag, &publication)?;
        } else {
            ensure!(
                plan.prior_intent.is_some(),
                "unexplained status absence without prior intent"
            );
        }
        if args.len() == 6 {
            ensure!(
                fresh_census(&plan, &fleet, &history, &owners)? == before,
                "census changed during preflight"
            );
            println!(
                "epoch {}: inactive cleanup preflight passed; no mutation",
                plan.epoch
            );
            return Ok(());
        }
        fleet::persist(&plan.intent, &intent)?;
    }
    if args.len() == 6 {
        println!(
            "epoch {}: exact recovery intent validated; no mutation",
            plan.epoch
        );
        return Ok(());
    }
    validate_fleet(
        &fleet,
        &plan,
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    )?;
    ensure!(
        fresh_census(&plan, &fleet, &history, &owners)? == before,
        "census changed before cleanup"
    );
    no_local_delivery(&plan)?;
    ensure!(
        no_remote_delivery(&s3, &r2, &plan).await? == preserved_remote,
        "preserved remote artifact changed before status cleanup"
    );
    if let Some(object) = current {
        same_object(&object.bytes, &object.etag, &publication)?;
        ensure!(
            !plan.completion.exists(),
            "status reappeared after completed cleanup"
        );
        conditional_delete_epoch_status(&s3, &r2.bucket, plan.epoch, &object.etag).await?;
    }
    ensure!(
        get_mutable_object(&s3, &r2.bucket, &key).await?.is_none(),
        "status remains or a new owner published; reconcile"
    );
    ensure!(
        fresh_census(&plan, &fleet, &history, &owners)? == before,
        "claim appeared after cleanup; repair live status through gated publisher"
    );
    no_local_delivery(&plan)?;
    ensure!(
        no_remote_delivery(&s3, &r2, &plan).await? == preserved_remote,
        "preserved remote artifact changed after status cleanup"
    );
    let completion = json!({"schema":"jetstreamer-horizon-inactive-status-completion-v1","intent":intent,
        "authenticated_absence":true,"unchanged_claim_census":true,"archive_completion_claimed":false});
    if plan.completion.exists() {
        ensure!(
            serde_json::from_slice::<Value>(&read_stable_bounded(
                &plan.completion,
                1024 * 1024,
                "inactive completion"
            )?)? == completion,
            "existing completion differs"
        );
    } else {
        fleet::persist(&plan.completion, &completion)?;
    }
    println!("{}", plan.completion.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reserve_history_selects_only_the_exact_owner_pair_and_rejects_duplicates() {
        let stop = json!({"epoch":185,"controller_unit":"controller.service",
            "controller_invocation_id":"a".repeat(32),"producer_unit":"producer.service",
            "producer_invocation_id":"b".repeat(32),
            "intent":{"path":"/intent.json","sha256":"c".repeat(64)},
            "completion":{"path":"/completion.json","sha256":"d".repeat(64)}});
        let owners = vec![
            ("controller.service".into(), "a".repeat(32)),
            ("producer.service".into(), "b".repeat(32)),
        ];
        let fleet = json!({"terminal_replays":[stop]});
        assert_eq!(
            reserve_owner_evidence(&fleet, &owners)
                .unwrap()
                .unwrap()
                .epoch,
            185
        );
        let mut changed = owners.clone();
        changed[1].1 = "f".repeat(32);
        assert!(reserve_owner_evidence(&fleet, &changed).unwrap().is_none());
        assert!(reserve_owner_evidence(&json!({"terminal_replays":[stop,stop]}), &owners).is_err());
        assert!(reserve_owner_evidence(&json!({"terminal_replays":{}}), &owners).is_err());
        assert!(
            reserve_owner_evidence(&json!({}), &owners)
                .unwrap()
                .is_none()
        );
    }
    #[test]
    fn queued_jobs_are_a_plain_systemctl_table_not_journal_json() {
        assert!(queued_job_units(b"").unwrap().is_empty());
        assert_eq!(queued_job_units(b"3285782 horizon-inactive-status-224.service start running\n3285783 horizon-controller-224.service start waiting\n").unwrap(),
            vec!["horizon-inactive-status-224.service","horizon-controller-224.service"]);
        assert!(queued_job_units(b"JOB UNIT TYPE STATE\n").is_err());
        assert!(queued_job_units(b"3285782 missing-columns\n").is_err());
    }
    #[test]
    fn terminal_owner_requires_positive_history_and_rejects_replacements() {
        let old = json!({"LoadState":"loaded","InvocationID":"abc","ActiveState":"failed","SubState":"failed","Result":"exit-code","ExecMainStatus":"1"});
        validate_terminal_owner(&old, &old, "abc").unwrap();
        let gone = json!({"LoadState":"not-found","InvocationID":"","ActiveState":"inactive","SubState":"dead"});
        validate_terminal_owner(&gone, &old, "abc").unwrap();
        assert!(validate_terminal_owner(&gone, &Value::Null, "abc").is_err());
        for (field, value) in [
            ("InvocationID", json!("new")),
            ("ActiveState", json!("active")),
            ("SubState", json!("auto-restart")),
        ] {
            let mut bad = old.clone();
            bad[field] = value;
            assert!(validate_terminal_owner(&bad, &old, "abc").is_err());
        }
    }
    #[test]
    fn current_status_requires_both_exact_bytes_and_etag() {
        let receipt = super::super::tests::status_publication_receipt(224);
        let bytes = epoch_status_bytes(&receipt.status).unwrap();
        same_object(&bytes, &receipt.object_etag, &receipt).unwrap();
        assert!(same_object(&bytes, "different", &receipt).is_err());
        assert!(same_object(b"{}", &receipt.object_etag, &receipt).is_err());
    }

    pub(super) fn plan_fixture() -> (Plan, Value) {
        let bound = || Bound {
            path: "/sealed/evidence".into(),
            sha256: "a".repeat(64),
        };
        let plan = Plan {
            schema: "jetstreamer-horizon-inactive-status-plan-v1".into(),
            epoch: 224,
            fleet: bound(),
            terminal_fleet: bound(),
            publication: bound(),
            repair_backlog: bound(),
            public_archive_directory: "/public".into(),
            status_receipt_directory: "/receipts".into(),
            intent: "/receipts/intent.json".into(),
            completion: "/receipts/completion.json".into(),
            exclusive_local_epoch_ownership: true,
            authenticated_other_host_handoffs: vec![],
            prior_intent: None,
            metadata_completion: None,
            preserved144_delivery: None,
        };
        let fleet = json!({"schema":"jetstreamer-horizon-campaign-fleet-v1","first_epoch":201,"last_epoch":300,
            "sampled_at_utc":"2026-10-20T04:04:42Z","recorded_unix_seconds":1792469100u64,
            "active":[],"epochs":[{"epoch":224,"state":"failed-needs-repair"}]});
        (plan, fleet)
    }

    #[test]
    fn inactive_fleet_rejects_live_downstream_handoffs_staged_and_stale_evidence() {
        let (mut plan, fleet) = plan_fixture();
        validate_fleet(&fleet, &plan, 1792469200).unwrap();
        for phase in [
            "replay",
            "private-verification",
            "local-publication",
            "upload-readback",
        ] {
            let mut bad = fleet.clone();
            bad["active"] = json!([{"epoch":224,"phase":phase}]);
            assert!(validate_fleet(&bad, &plan, 1792469200).is_err());
        }
        for state in [
            "staged-admissible",
            "post-replay-pipeline",
            "remote-ready",
            "live-replay",
        ] {
            let mut bad = fleet.clone();
            bad["epochs"][0]["state"] = json!(state);
            assert!(validate_fleet(&bad, &plan, 1792469200).is_err());
        }
        assert!(validate_fleet(&fleet, &plan, 1792472000).is_err());
        plan.authenticated_other_host_handoffs
            .push(json!({"epoch":224}));
        assert!(validate_fleet(&fleet, &plan, 1792469200).is_err());
        plan.authenticated_other_host_handoffs.clear();
        plan.exclusive_local_epoch_ownership = false;
        assert!(validate_fleet(&fleet, &plan, 1792469200).is_err());
    }

    #[test]
    fn recovery_preserves_exact_status_identity_across_fresh_plans() {
        let intent = json!({"schema":"jetstreamer-horizon-inactive-status-intent-v1","archive_completion_claimed":false,
            "epoch":224,"bucket":"b","key":"epoch-224.epoch-status.json","publication":"/receipt.json",
            "publication_sha256":"a".repeat(64),"status":{"epoch":224},"etag":"old","owners":[["owner","id"]],
            "fleet":"/old-fleet","plan":"/old-plan"});
        let mut expected = intent.clone();
        expected["fleet"] = json!("/fresh-fleet");
        expected["plan"] = json!("/fresh-plan");
        validate_recovery_intent(&intent, &expected).unwrap();
        for field in [
            "epoch",
            "bucket",
            "key",
            "publication",
            "publication_sha256",
            "status",
            "etag",
            "owners",
        ] {
            let mut bad = expected.clone();
            bad[field] = json!("substituted");
            assert!(validate_recovery_intent(&intent, &bad).is_err(), "{field}");
        }
    }

    #[test]
    fn preserved_failure_binds_original_and_stopped_controller_generations() {
        let owners = vec![
            ("controller.service".into(), "old".into()),
            ("producer.service".into(), "producer".into()),
        ];
        let evidence = json!({"schema":"jetstreamer-horizon-terminal-failed-replay-evidence-v1",
            "controller":{"unit":"controller.service","launch_invocation_id":"old","observed_terminal_invocation_id":"stopped",
                "retry_path_stopped":true,"active_state":"inactive","sub_state":"dead"},
            "producer":{"unit":"producer.service","invocation_id":"producer","transient_unit_collected":true,
                "journal_entry_count":322,"journal_export_sha256":"a".repeat(64)},
            "failure":{"kind":"historical-execution-mismatch","slot":96767526,"message":"preserved mismatch"},
            "publication_authorized":false,"remote_mutations":false,"r2_mutations":false});
        let mut current = BTreeMap::from([
            (
                "controller.service".into(),
                json!({"LoadState":"loaded","InvocationID":"stopped","ActiveState":"inactive",
                "SubState":"dead","Result":"success","ExecMainStatus":"0"}),
            ),
            (
                "producer.service".into(),
                json!({"LoadState":"not-found","InvocationID":"","ActiveState":"inactive","SubState":"dead"}),
            ),
        ]);
        validate_preserved_failure(&current, &evidence, &owners).unwrap();
        let mut bad = evidence.clone();
        bad["controller"]["launch_invocation_id"] = json!("other");
        assert!(validate_preserved_failure(&current, &bad, &owners).is_err());
        current.get_mut("producer.service").unwrap()["ActiveState"] = json!("activating");
        assert!(validate_preserved_failure(&current, &evidence, &owners).is_err());
    }

    #[test]
    fn inactive_delete_preserves_intent_before_mutation_and_never_declares_completion() {
        let source = include_str!("inactive_status.rs");
        let run = &source[source.find("pub(super) async fn run()").unwrap()
            ..source.find("#[cfg(test)]").unwrap()];
        assert!(
            run.find("fleet::persist(&plan.intent").unwrap()
                < run.find("conditional_delete_epoch_status(").unwrap()
        );
        assert!(
            run.find("conditional_delete_epoch_status(").unwrap()
                < run.find("authenticated_absence").unwrap()
        );
        assert!(
            run.contains(
                "claim appeared after cleanup; repair live status through gated publisher"
            )
        );
        assert!(run.contains("unexplained status absence without prior intent"));
        assert!(run.contains("archive_completion_claimed\":false"));
        assert!(!run.contains(".delete_object()") && !run.contains(".delete_objects()"));
    }

    #[tokio::test]
    async fn conditional_delete_race_never_falls_back_to_unconditional_request() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut bytes = Vec::new();
            let mut byte = [0u8; 1];
            while !bytes.ends_with(b"\r\n\r\n") {
                socket.read_exact(&mut byte).unwrap();
                bytes.push(byte[0]);
                assert!(bytes.len() < 16384);
            }
            let request = String::from_utf8(bytes).unwrap();
            let line: Vec<_> = request.lines().next().unwrap().split_whitespace().collect();
            assert_eq!(line[0], "DELETE");
            assert_eq!(
                line[1].split('?').next().unwrap(),
                "/fixture/epoch-224.epoch-status.json"
            );
            assert_eq!(line[2], "HTTP/1.1");
            assert!(
                request
                    .to_ascii_lowercase()
                    .contains("if-match: \"owned-etag\"\r\n")
            );
            let body = "<Error><Code>PreconditionFailed</Code><Message>changed</Message></Error>";
            write!(socket,"HTTP/1.1 412 Precondition Failed\r\nContent-Type: application/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).unwrap();
        });
        let r2 = R2Config {
            endpoint: format!("http://{address}"),
            bucket: "fixture".into(),
            access_key: "fixture".into(),
            secret_key: "fixture".into(),
        };
        let client = s3_client(&r2);
        assert!(
            conditional_delete_epoch_status(&client, "fixture", 224, "owned-etag")
                .await
                .is_err()
        );
        server.join().unwrap();
    }
}
