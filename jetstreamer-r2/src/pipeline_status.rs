//! Routine, identity-bound post-replay metadata. No archive or sidecar mutation.
use super::*;
use std::{collections::BTreeMap, process::Command};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Binding {
    pub unit: String,
    pub invocation_id: String,
    pub expected_exec_start: String,
    pub claim_phase: String,
    pub origin_unit: String,
    pub origin_invocation_id: String,
    pub model_path: PathBuf,
    pub model_sha256: String,
    pub fleet_path: PathBuf,
    pub fleet_sha256: String,
}

fn hex_id(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn unit_name(value: &str) -> bool {
    value.ends_with(".service")
        && value.len() <= 255
        && !value.starts_with('-')
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.@".contains(&b))
}

impl Binding {
    pub fn validate(&self, epoch: u64, phase: &str) -> Result<()> {
        match (self.claim_phase.as_str(), phase) {
            ("full-verification" | "plugin-verification", "verification")
            | ("local-publication", "publication")
            | ("producer-finalization", "finalization")
            | ("controller-import-handoff", "publication")
            | ("upload-readback", "upload" | "readback") => (),
            _ => bail!("pipeline and status phases disagree"),
        };
        if self.claim_phase == "producer-finalization" {
            ensure!(
                self.origin_unit == self.unit && self.origin_invocation_id == self.invocation_id,
                "producer finalization must retain the original invocation clock"
            );
        }
        if self.claim_phase == "controller-import-handoff" {
            ensure!(
                self.unit == super::cohort_finalization::CONTROLLER
                    && self.invocation_id == super::cohort_finalization::CONTROLLER_INVOCATION
                    && self.origin_unit == super::cohort_finalization::UNIT
                    && self.origin_invocation_id == super::cohort_finalization::PRODUCER_INVOCATION,
                "controller handoff must retain the exact original producer clock"
            );
        }
        ensure!(
            unit_name(&self.unit)
                && fleet::pipeline_unit_range(&self.claim_phase, &self.unit)?.contains(&epoch)
                && unit_name(&self.origin_unit)
                && hex_id(&self.invocation_id, 32)
                && hex_id(&self.origin_invocation_id, 32)
                && !self.expected_exec_start.trim().is_empty()
                && self.model_path.is_absolute()
                && self.fleet_path.is_absolute()
                && hex_id(&self.model_sha256, 64)
                && hex_id(&self.fleet_sha256, 64),
            "invalid pipeline status binding"
        );
        Ok(())
    }
    pub fn live_matches(&self, current: &Value) -> bool {
        current["Id"] == self.unit
            && current["LoadState"] == "loaded"
            && ((current["ActiveState"] == "active" && current["SubState"] == "running")
                || (current["ActiveState"] == "activating" && current["SubState"] == "start"))
            && current["InvocationID"] == self.invocation_id
            && current["NRestarts"] == "0"
            && current["ExecStart"] == self.expected_exec_start
            && current["MainPID"]
                .as_str()
                .and_then(|s| s.parse::<u64>().ok())
                .is_some_and(|p| p > 0)
    }
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
    phase: String,
    binding: Binding,
    observer: Bound,
    fleet: Bound,
    origin_launch: Bound,
    estimate_evidence: Vec<Bound>,
    estimate_basis: String,
    estimated_remaining_millis: u64,
    jet_path: PathBuf,
    expected_jet_size_bytes: u64,
    peer_units: Vec<String>,
    receipt_directory: PathBuf,
}

fn bound_bytes(bound: &Bound) -> Result<Vec<u8>> {
    ensure!(
        bound.path.is_absolute() && hex_id(&bound.sha256, 64),
        "invalid pipeline evidence binding"
    );
    let meta = fs::symlink_metadata(&bound.path)?;
    ensure!(
        meta.is_file() && meta.uid() == 0 && meta.mode() & 0o022 == 0,
        "pipeline evidence must be root-owned and non-writable"
    );
    let bytes = read_stable_bounded(&bound.path, 16 * 1024 * 1024, "pipeline status evidence")?;
    ensure!(
        hex_lower(&Sha256::digest(&bytes)) == bound.sha256,
        "pipeline status evidence hash mismatch"
    );
    Ok(bytes)
}

fn bound_json(bound: &Bound) -> Result<Value> {
    Ok(serde_json::from_slice(&bound_bytes(bound)?)?)
}

// A legacy controller need not have the newer diagnostic launch schema. Its
// authenticated replay status receipt and exact historical v2 observer prove
// the original invocation without inventing a launch event or resetting elapsed
// time to the downstream verifier's start. The manager journal remains the
// independent authoritative clock used below.
fn validate_replay_origin(
    origin_path: &Path,
    epoch: u64,
    binding: &Binding,
    receipt: &StatusPublicationReceipt,
    observer_bytes: &[u8],
) -> Result<()> {
    validate_status_publication_receipt_bytes(
        origin_path
            .parent()
            .context("origin receipt has no parent")?,
        origin_path,
        &serde_json::to_vec(receipt)?,
        &receipt.bucket,
        epoch,
    )?;
    ensure!(
        receipt.schema == STATUS_RECEIPT_SCHEMA
            && receipt.pipeline_binding.is_none()
            && receipt.status.phase == "replay"
            && receipt.producer_invocation_id == binding.origin_invocation_id,
        "elapsed-time origin is not the authenticated original replay"
    );
    let sample = validate_observer_binding(
        observer_bytes,
        &receipt.observer_receipt_sha256,
        epoch,
        &receipt.controller_invocation_id,
        &receipt.producer_invocation_id,
    )?;
    ensure!(
        receipt.status.sampled_at_utc == sample,
        "origin status and observer times differ"
    );
    let observer: Value = serde_json::from_slice(observer_bytes)?;
    let replay = observer["replays"]
        .as_array()
        .context("origin observer omits replays")?
        .iter()
        .find(|replay| {
            replay["range"]
                .as_str()
                .and_then(|range| parse_observer_claim_range(range).ok())
                .is_some_and(|range| range.contains(&epoch))
        })
        .context("origin replay claim missing")?;
    for point in ["producer_before", "producer_after"] {
        ensure!(
            observer_string(replay, &[point, "unit"])? == binding.origin_unit,
            "origin observer names a different producer unit"
        );
    }
    Ok(())
}

fn start_millis(records: &[Value], unit: &str, invocation: &str) -> Result<u64> {
    let starts: Vec<_> = records
        .iter()
        .filter(|r| {
            r["UNIT"] == unit
                && r["INVOCATION_ID"] == invocation
                && r["_PID"] == "1"
                && r["_UID"] == "0"
                && r["MESSAGE"].as_str().is_some_and(|s| {
                    s.starts_with("Starting ")
                        || (unit == super::cohort_finalization::CONTROLLER
                            && invocation == super::cohort_finalization::CONTROLLER_INVOCATION
                            && s.starts_with("Started "))
                })
        })
        .collect();
    ensure!(
        starts.len() == 1,
        "exact unique manager start event is unavailable"
    );
    let micros = starts[0]["__REALTIME_TIMESTAMP"]
        .as_str()
        .context("manager start time missing")?
        .parse::<u64>()?;
    ensure!(micros > 0, "manager start time is zero");
    Ok(micros / 1000)
}
fn manager_start(unit: &str, invocation: &str) -> Result<u64> {
    ensure!(
        unit_name(unit) && hex_id(invocation, 32),
        "invalid manager start identity"
    );
    let output = Command::new("journalctl")
        .args([
            "_PID=1",
            "_UID=0",
            &format!("UNIT={unit}"),
            &format!("INVOCATION_ID={invocation}"),
            "--no-pager",
            "-o",
            "json",
            "-n",
            "64",
        ])
        .output()?;
    ensure!(
        output.status.success() && output.stdout.len() <= 2 * 1024 * 1024,
        "manager start lookup failed"
    );
    let records = serde_json::Deserializer::from_slice(&output.stdout)
        .into_iter::<Value>()
        .collect::<std::result::Result<Vec<_>, _>>()?;
    start_millis(&records, unit, invocation)
}

fn validate_scope(plan: &Plan, observer: &Value, fleet: &Value, now: u64) -> Result<String> {
    ensure!(
        plan.schema == "jetstreamer-horizon-pipeline-status-plan-v1",
        "unsupported pipeline status plan"
    );
    plan.binding.validate(plan.epoch, &plan.phase)?;
    ensure!(
        observer["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && fleet["schema"] == "jetstreamer-horizon-campaign-fleet-v1"
            && fleet["observer_receipt"].as_str() == plan.observer.path.to_str()
            && fleet["observer_sha256"] == plan.observer.sha256
            && plan.binding.fleet_path == plan.fleet.path
            && plan.binding.fleet_sha256 == plan.fleet.sha256,
        "pipeline model does not bind the coordinated fleet and v2 observation"
    );
    let sample = observer["recorded_at_utc"]
        .as_str()
        .context("observer time missing")?;
    let seconds = fleet::utc_seconds(sample)?;
    let recorded = fleet["recorded_unix_seconds"]
        .as_u64()
        .context("fleet time missing")?;
    ensure!(
        fleet["sampled_at_utc"] == sample
            && seconds <= recorded
            && recorded <= now
            && now - seconds <= 1800,
        "pipeline status requires a fresh coordinated cycle"
    );
    ensure!(
        fleet["first_epoch"]
            .as_u64()
            .is_some_and(|n| n <= plan.epoch)
            && fleet["last_epoch"]
                .as_u64()
                .is_some_and(|n| n >= plan.epoch),
        "pipeline epoch is unassigned"
    );
    let entries = fleet["epochs"]
        .as_array()
        .context("fleet epoch census missing")?;
    let entries: Vec<_> = entries
        .iter()
        .filter(|e| e["epoch"] == plan.epoch)
        .collect();
    ensure!(
        entries.len() == 1 && entries[0]["state"] == "post-replay-pipeline",
        "epoch is not in an evidenced delivery stage"
    );
    let active = fleet["active"]
        .as_array()
        .context("fleet active census missing")?;
    ensure!(
        active
            .iter()
            .filter(|e| e["epoch"] == plan.epoch
                && e["phase"] == plan.binding.claim_phase
                && plan.binding.live_matches(&e["unit"]))
            .count()
            == 1,
        "pipeline binding is not the exact live coordinated fleet claim"
    );
    ensure!(
        !active.iter().any(|e| e["epoch"] == plan.epoch
            && !matches!(
                e["phase"].as_str(),
                Some(
                    "full-verification"
                        | "plugin-verification"
                        | "local-publication"
                        | "upload-readback"
                        | "producer-finalization"
                        | "controller-import-handoff"
                )
            )),
        "pipeline overlaps a replay or private qualification claim"
    );
    ensure!(
        plan.estimated_remaining_millis > 0
            && !plan.estimate_basis.trim().is_empty()
            && !plan.estimate_evidence.is_empty(),
        "pipeline requires a positive current best estimate with evidence"
    );
    ensure!(
        plan.jet_path.is_absolute()
            && plan.jet_path.canonicalize()? == plan.jet_path
            && plan.expected_jet_size_bytes > 0,
        "pipeline must measure its exact complete current jet file"
    );
    let name = plan
        .jet_path
        .file_name()
        .and_then(|s| s.to_str())
        .context("jet filename missing")?;
    ensure!(
        name == format!("epoch-{}.jet", plan.epoch)
            || (name.starts_with(&format!("epoch-{}-", plan.epoch)) && name.ends_with(".jet")),
        "jet filename names another epoch"
    );
    Ok(sample.into())
}

fn census(plan: &Plan, fleet: &Value) -> Result<BTreeMap<String, Value>> {
    let previous = fleet["unit_census"]
        .as_object()
        .context("fleet unit census missing")?;
    let mut names: BTreeSet<_> = previous.keys().cloned().collect();
    names.insert(plan.binding.unit.clone());
    let mut peers = BTreeSet::new();
    for peer in &plan.peer_units {
        ensure!(
            unit_name(peer)
                && [
                    "full-verification",
                    "plugin-verification",
                    "local-publication",
                    "upload-readback",
                    "producer-finalization",
                    "controller-import-handoff"
                ]
                .iter()
                .any(|phase| fleet::pipeline_unit_range(phase, peer)
                    .is_ok_and(|range| range.contains(&plan.epoch)))
                && peers.insert(peer.clone()),
            "pipeline peer is duplicate or names another epoch"
        );
        names.insert(peer.clone());
    }
    let current = fleet::census(
        &names,
        fleet["first_epoch"]
            .as_u64()
            .context("first epoch missing")?,
        fleet["last_epoch"].as_u64().context("last epoch missing")?,
    )?;
    ensure!(
        plan.binding.live_matches(&current[&plan.binding.unit]),
        "pipeline invocation or exact command is not live"
    );
    if plan.binding.claim_phase == "producer-finalization" {
        super::cohort_finalization::observe(
            &current[&plan.binding.unit],
            fleet::utc_seconds(
                fleet["sampled_at_utc"]
                    .as_str()
                    .context("fleet sample missing")?,
            )?,
        )?;
    }
    if plan.binding.claim_phase == "controller-import-handoff" {
        super::cohort_finalization::observe_handoff(
            &current[&plan.binding.unit],
            fleet::utc_seconds(
                fleet["sampled_at_utc"]
                    .as_str()
                    .context("fleet sample missing")?,
            )?,
        )?;
    }
    for (name, prior) in previous {
        if name != &plan.binding.unit && !peers.contains(name) {
            ensure!(
                current[name] == *prior,
                "fleet changed outside the explicit delivery handoff"
            );
        }
    }
    for peer in peers {
        if peer != plan.binding.unit {
            ensure!(
                matches!(
                    current[&peer]["ActiveState"].as_str(),
                    Some("inactive" | "failed")
                ),
                "another pipeline phase or replacement is live"
            );
        }
    }
    Ok(current)
}

pub(super) async fn run() -> Result<()> {
    let args: Vec<_> = env::args().collect();
    ensure!(
        (args.len() == 5 || (args.len() == 6 && args[5] == "--check-only"))
            && args[3] == "--plan-sha256",
        "usage: jetstreamer-r2 status-publish-pipeline PLAN --plan-sha256 HEX [--check-only]"
    );
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "pipeline status requires root"
    );
    let model = Bound {
        path: args[2].clone().into(),
        sha256: args[4].clone(),
    };
    let mut plan: Plan = serde_json::from_value(bound_json(&model)?)?;
    ensure!(
        plan.binding.model_path == model.path && plan.binding.model_sha256.is_empty(),
        "pipeline model path differs or reserved runtime model hash is not empty"
    );
    plan.binding.model_sha256 = model.sha256.clone();
    let observer = bound_json(&plan.observer)?;
    let fleet = bound_json(&plan.fleet)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let sample = validate_scope(&plan, &observer, &fleet, now)?;
    let origin = bound_json(&plan.origin_launch)?;
    if origin["schema"] == STATUS_RECEIPT_SCHEMA {
        let receipt: StatusPublicationReceipt = serde_json::from_value(origin)?;
        let prior_observer = bound_bytes(&Bound {
            path: receipt.observer_receipt.clone(),
            sha256: receipt.observer_receipt_sha256.clone(),
        })?;
        validate_replay_origin(
            &plan.origin_launch.path,
            plan.epoch,
            &plan.binding,
            &receipt,
            &prior_observer,
        )?;
        ensure!(
            receipt.status.sampled_at_utc <= sample && receipt.verified_unix_seconds <= now,
            "origin replay receipt is from the future"
        );
    } else {
        ensure!(
            origin["epoch"] == plan.epoch
                && origin["launched"] == true
                && origin["evidence"]["units"]
                    .as_array()
                    .is_some_and(|units| units
                        .iter()
                        .any(|u| u["unit"] == plan.binding.origin_unit
                            && u["invocation_id"] == plan.binding.origin_invocation_id)),
            "elapsed-time origin is not the exact launched epoch producer"
        );
    }
    for evidence in &plan.estimate_evidence {
        bound_json(evidence)?;
    }
    let origin_start = manager_start(
        &plan.binding.origin_unit,
        &plan.binding.origin_invocation_id,
    )?;
    let phase_start = manager_start(&plan.binding.unit, &plan.binding.invocation_id)?;
    let sample_ms = fleet::utc_seconds(&sample)?
        .checked_mul(1000)
        .context("sample time overflow")?;
    ensure!(
        phase_start <= sample_ms,
        "phase started after coordinated sample; do not backdate a status claim"
    );
    let elapsed = sample_ms
        .checked_sub(origin_start)
        .context("producer origin starts after sample")?;
    let before = census(&plan, &fleet)?;
    let identity = regular_identity(&plan.jet_path)?;
    ensure!(
        identity.length == plan.expected_jet_size_bytes,
        "pipeline jet length differs from model"
    );
    let meta = fs::symlink_metadata(&plan.jet_path)?;
    ensure!(meta.nlink() == 1, "pipeline jet has multiple links");
    let receipts = fs::symlink_metadata(&plan.receipt_directory)?;
    ensure!(
        plan.receipt_directory.is_absolute()
            && plan.receipt_directory.canonicalize()? == plan.receipt_directory
            && receipts.is_dir()
            && receipts.uid() == 0
            && receipts.mode() & 0o077 == 0,
        "pipeline status receipt directory must be root-private"
    );
    let status = EpochStatus {
        epoch: plan.epoch,
        jet_size_bytes: identity.length,
        elapsed_execution_millis: elapsed,
        estimated_remaining_millis: plan.estimated_remaining_millis,
        sampled_at_utc: sample,
        phase: plan.phase.clone(),
    };
    validate_epoch_status(&status, plan.epoch)?;
    ensure!(
        census(&plan, &fleet)? == before && regular_identity(&plan.jet_path)? == identity,
        "pipeline identity or source changed during the coordinated status sample"
    );
    if args.len() == 6 {
        println!(
            "epoch {}: pipeline status preflight passed; no mutation",
            plan.epoch
        );
        return Ok(());
    }
    let r2 = r2_config_from_env()?;
    let s3 = s3_client(&r2);
    ensure!(
        get_mutable_object(&s3, &r2.bucket, &format!("epoch-{}.jet.sha256", plan.epoch))
            .await?
            .is_none(),
        "canonical sidecar already exists; reconcile completion instead of publishing a countdown"
    );
    preflight_status_receipt_write(&plan.receipt_directory)?;
    let (object_etag, previous_object_etag) = publish_epoch_status(&s3, &r2, &status).await?;
    let receipt = StatusPublicationReceipt {
        schema: PIPELINE_STATUS_RECEIPT_SCHEMA.into(),
        bucket: r2.bucket,
        epoch: plan.epoch,
        key: format!("epoch-{}.epoch-status.json", plan.epoch),
        status,
        object_etag,
        previous_object_etag,
        observer_receipt: plan.observer.path,
        observer_receipt_sha256: plan.observer.sha256,
        controller_invocation_id: String::new(),
        producer_invocation_id: String::new(),
        authenticated_readback: true,
        verified_unix_seconds: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        pipeline_binding: Some(plan.binding),
    };
    println!(
        "{}",
        write_status_receipt(&plan.receipt_directory, &receipt)?.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn binding() -> Binding {
        Binding {
            unit: "horizon-upload-213-test.service".into(),
            invocation_id: "a".repeat(32),
            expected_exec_start: "exact command".into(),
            claim_phase: "upload-readback".into(),
            origin_unit: "horizon-qualify-213-test.service".into(),
            origin_invocation_id: "b".repeat(32),
            model_path: "/model".into(),
            model_sha256: "c".repeat(64),
            fleet_path: "/fleet".into(),
            fleet_sha256: "d".repeat(64),
        }
    }
    #[test]
    fn exact_simple_controller_uses_its_authenticated_started_manager_event() {
        let unit = super::super::cohort_finalization::CONTROLLER;
        let inv = super::super::cohort_finalization::CONTROLLER_INVOCATION;
        let r = json!({"UNIT":unit,"INVOCATION_ID":inv,"_PID":"1","_UID":"0",
            "MESSAGE":"Started controller.","__REALTIME_TIMESTAMP":"10000000"});
        assert_eq!(
            start_millis(std::slice::from_ref(&r), unit, inv).unwrap(),
            10000
        );
        assert!(start_millis(std::slice::from_ref(&r), unit, "replacement").is_err());
        let mut wrong = r.clone();
        wrong["_PID"] = json!("123");
        assert!(start_millis(&[wrong], unit, inv).is_err());
    }
    #[test]
    fn controller_handoff_keeps_original_producer_not_controller_start_clock() {
        let mut b = binding();
        b.unit = super::super::cohort_finalization::CONTROLLER.into();
        b.invocation_id = super::super::cohort_finalization::CONTROLLER_INVOCATION.into();
        b.claim_phase = "controller-import-handoff".into();
        b.origin_unit = super::super::cohort_finalization::UNIT.into();
        b.origin_invocation_id = super::super::cohort_finalization::PRODUCER_INVOCATION.into();
        b.validate(216, "publication").unwrap();
        assert!(b.validate(220, "publication").is_err());
        assert!(b.validate(216, "replay").is_err());
        b.origin_unit = b.unit.clone();
        assert!(b.validate(216, "publication").is_err());
    }
    #[test]
    fn producer_finalization_has_exact_scope_phase_and_original_clock() {
        let mut b = binding();
        b.unit = super::super::cohort_finalization::UNIT.into();
        b.claim_phase = "producer-finalization".into();
        b.origin_unit = b.unit.clone();
        b.origin_invocation_id = b.invocation_id.clone();
        b.validate(216, "finalization").unwrap();
        b.validate(219, "finalization").unwrap();
        assert!(b.validate(220, "finalization").is_err());
        assert!(b.validate(216, "replay").is_err());
        assert!(b.validate(216, "upload").is_err());
        b.origin_invocation_id = "b".repeat(32);
        assert!(b.validate(216, "finalization").is_err());
    }
    #[test]
    fn completion_cleanup_can_read_new_finalization_receipts_without_replay_ids() {
        let directory = Path::new("/private/receipts");
        let mut r = super::super::tests::status_publication_receipt(216);
        let mut b = binding();
        b.unit = super::super::cohort_finalization::UNIT.into();
        b.claim_phase = "producer-finalization".into();
        b.origin_unit = b.unit.clone();
        b.origin_invocation_id = b.invocation_id.clone();
        r.schema = PIPELINE_STATUS_RECEIPT_SCHEMA.into();
        r.status.phase = "finalization".into();
        r.controller_invocation_id.clear();
        r.producer_invocation_id.clear();
        r.pipeline_binding = Some(b);
        let path = status_receipt_path(directory, &r.status);
        assert_eq!(
            validate_status_publication_receipt_bytes(
                directory,
                &path,
                &serde_json::to_vec(&r).unwrap(),
                "bucket",
                216
            )
            .unwrap(),
            r
        );
    }
    #[test]
    fn pipeline_binding_is_not_a_replay_or_another_epoch() {
        let b = binding();
        b.validate(213, "upload").unwrap();
        b.validate(213, "readback").unwrap();
        assert!(b.validate(214, "upload").is_err());
        assert!(b.validate(213, "replay").is_err());
        assert!(b.validate(213, "publication").is_err());
        let current = json!({"Id":b.unit,"LoadState":"loaded","ActiveState":"active","SubState":"running",
            "InvocationID":b.invocation_id,"NRestarts":"0","MainPID":"123","ExecStart":b.expected_exec_start});
        assert!(b.live_matches(&current));
        for (key, value) in [
            ("InvocationID", json!("new")),
            ("NRestarts", json!("1")),
            ("MainPID", json!("0")),
            ("ExecStart", json!("different")),
            ("ActiveState", json!("inactive")),
        ] {
            let mut bad = current.clone();
            bad[key] = value;
            assert!(!b.live_matches(&bad));
        }
    }

    #[test]
    fn verifier_status_is_scoped_to_its_real_stage_and_cohort() {
        let mut b = binding();
        for (phase, unit) in [
            (
                "full-verification",
                "horizon-full-verify-216-219-test.service",
            ),
            (
                "plugin-verification",
                "horizon-plugin-verify-216-219-test.service",
            ),
        ] {
            b.claim_phase = phase.into();
            b.unit = unit.into();
            b.validate(218, "verification").unwrap();
            assert!(b.validate(215, "verification").is_err());
            assert!(b.validate(220, "verification").is_err());
            assert!(b.validate(218, "replay").is_err());
            assert!(b.validate(218, "upload").is_err());
        }
        b.unit = "horizon-full-verify-216-219-test.service".into();
        assert!(b.validate(218, "verification").is_err());
    }

    #[test]
    fn legacy_replay_origin_requires_authenticated_status_and_exact_observer() {
        let mut b = binding();
        let mut receipt = super::super::tests::status_publication_receipt(213);
        b.origin_invocation_id = receipt.producer_invocation_id.clone();
        let observer = json!({"schema":"jetstreamer-horizon-live-resource-sample-v2",
            "recorded_at_utc":receipt.status.sampled_at_utc,
            "mutation":{"producer_or_controller_signals_sent":false,"service_state_changed":false,
                "remote_mutations":false,"r2_mutations":false},
            "replays":[{"range":"213-213","invocation_binding_stable":true,
                "controller_before":{"invocation_id":receipt.controller_invocation_id,"restarts":0},
                "controller_after":{"invocation_id":receipt.controller_invocation_id,"restarts":0},
                "producer_before":{"unit":b.origin_unit,"invocation_id":receipt.producer_invocation_id,"restarts":0},
                "producer_after":{"unit":b.origin_unit,"invocation_id":receipt.producer_invocation_id,"restarts":0},
                "useful_work":{"journal_invocation_id":receipt.producer_invocation_id}}]});
        let bytes = serde_json::to_vec(&observer).unwrap();
        receipt.observer_receipt_sha256 = hex_lower(&Sha256::digest(&bytes));
        let path = status_receipt_path(Path::new("/private"), &receipt.status);
        validate_replay_origin(&path, 213, &b, &receipt, &bytes).unwrap();
        for change in [
            "authenticated",
            "invocation",
            "phase",
            "timestamp",
            "digest",
        ] {
            let mut bad = receipt.clone();
            match change {
                "authenticated" => bad.authenticated_readback = false,
                "invocation" => bad.producer_invocation_id = "a".repeat(32),
                "phase" => bad.status.phase = "verification".into(),
                "timestamp" => bad.status.sampled_at_utc = "2026-10-17T01:11:00Z".into(),
                "digest" => bad.observer_receipt_sha256 = "b".repeat(64),
                _ => unreachable!(),
            }
            assert!(
                validate_replay_origin(&path, 213, &b, &bad, &bytes).is_err(),
                "{change}"
            );
        }
        for change in ["unit", "restart", "range"] {
            let mut bad = observer.clone();
            match change {
                "unit" => bad["replays"][0]["producer_after"]["unit"] = json!("other.service"),
                "restart" => bad["replays"][0]["producer_after"]["restarts"] = json!(1),
                "range" => bad["replays"][0]["range"] = json!("214-214"),
                _ => unreachable!(),
            }
            let bytes = serde_json::to_vec(&bad).unwrap();
            let mut bad_receipt = receipt.clone();
            bad_receipt.observer_receipt_sha256 = hex_lower(&Sha256::digest(&bytes));
            assert!(
                validate_replay_origin(&path, 213, &b, &bad_receipt, &bytes).is_err(),
                "{change}"
            );
        }
        assert!(validate_replay_origin(&path, 214, &b, &receipt, &bytes).is_err());
    }

    #[test]
    fn verification_status_receipt_remains_completion_cleanup_compatible() {
        let directory = Path::new("/private/receipts");
        let mut receipt = super::super::tests::status_publication_receipt(213);
        receipt.schema = PIPELINE_STATUS_RECEIPT_SCHEMA.into();
        receipt.controller_invocation_id.clear();
        receipt.producer_invocation_id.clear();
        receipt.status.phase = "verification".into();
        let mut b = binding();
        b.claim_phase = "full-verification".into();
        b.unit = "horizon-full-verify-213-test.service".into();
        receipt.pipeline_binding = Some(b);
        let path = status_receipt_path(directory, &receipt.status);
        assert_eq!(
            validate_status_publication_receipt_bytes(
                directory,
                &path,
                &serde_json::to_vec(&receipt).unwrap(),
                "bucket",
                213
            )
            .unwrap(),
            receipt
        );
        receipt.status.phase = "replay".into();
        assert!(
            validate_status_publication_receipt_bytes(
                directory,
                &path,
                &serde_json::to_vec(&receipt).unwrap(),
                "bucket",
                213
            )
            .is_err()
        );
    }

    #[test]
    #[ignore = "read-only, root-only proof for this host's sealed epoch206 historical origin"]
    fn host_206_legacy_origin_uses_authenticated_replay_and_manager_start() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let origin = Bound {
            path: "/home/ubuntu/.jetstreamer-private/r2-status-receipts/epoch-206.status-20261020090442.json".into(),
            sha256: "1a3a8391276fc934f89fd1978720aead34f4b604e80dd7cacdddc3ea964c4ffc".into(),
        };
        let receipt: StatusPublicationReceipt =
            serde_json::from_value(bound_json(&origin).unwrap()).unwrap();
        let mut b = binding();
        b.origin_unit =
            "jetstreamer-root-sweep-horizon-206-cf9b7e9-v1-e206-206-lane-c-1.service".into();
        b.origin_invocation_id = "6581c697673e4dc4becca771e99786ac".into();
        let bytes = bound_bytes(&Bound {
            path: receipt.observer_receipt.clone(),
            sha256: receipt.observer_receipt_sha256.clone(),
        })
        .unwrap();
        validate_replay_origin(&origin.path, 206, &b, &receipt, &bytes).unwrap();
        let start = manager_start(&b.origin_unit, &b.origin_invocation_id).unwrap();
        assert!(
            start > 0 && start < fleet::utc_seconds(&receipt.status.sampled_at_utc).unwrap() * 1000
        );
    }
    #[test]
    fn elapsed_start_requires_one_exact_root_manager_event() {
        let event = json!({"UNIT":"origin.service","INVOCATION_ID":"id","_PID":"1","_UID":"0",
            "MESSAGE":"Starting original producer","__REALTIME_TIMESTAMP":"1792470000123456"});
        assert_eq!(
            start_millis(std::slice::from_ref(&event), "origin.service", "id").unwrap(),
            1792470000123
        );
        assert!(start_millis(std::slice::from_ref(&event), "origin.service", "wrong").is_err());
        assert!(start_millis(&[event.clone(), event.clone()], "origin.service", "id").is_err());
        let mut user = event;
        user["_PID"] = json!("123");
        assert!(start_millis(&[user], "origin.service", "id").is_err());
    }

    #[test]
    fn pipeline_receipt_is_distinct_and_supported_by_completion_cleanup() {
        let directory = Path::new("/private/receipts");
        let mut receipt = super::super::tests::status_publication_receipt(213);
        let legacy = serde_json::to_value(&receipt).unwrap();
        assert!(legacy.get("pipeline_binding").is_none());
        receipt.schema = PIPELINE_STATUS_RECEIPT_SCHEMA.into();
        receipt.controller_invocation_id.clear();
        receipt.producer_invocation_id.clear();
        receipt.status.phase = "upload".into();
        receipt.pipeline_binding = Some(binding());
        let path = status_receipt_path(directory, &receipt.status);
        let bytes = serde_json::to_vec(&receipt).unwrap();
        assert_eq!(
            validate_status_publication_receipt_bytes(directory, &path, &bytes, "bucket", 213)
                .unwrap(),
            receipt
        );
        let mut bad = receipt.clone();
        bad.schema = STATUS_RECEIPT_SCHEMA.into();
        assert!(
            validate_status_publication_receipt_bytes(
                directory,
                &path,
                &serde_json::to_vec(&bad).unwrap(),
                "bucket",
                213
            )
            .is_err()
        );
        let mut bad = receipt;
        bad.producer_invocation_id = "pretend-replay".into();
        assert!(
            validate_status_publication_receipt_bytes(
                directory,
                &path,
                &serde_json::to_vec(&bad).unwrap(),
                "bucket",
                213
            )
            .is_err()
        );
    }

    #[test]
    fn root_import_publication_receipt_is_completion_cleanup_compatible() {
        let directory = Path::new("/private/receipts");
        let mut receipt = super::super::tests::status_publication_receipt(206);
        receipt.schema = PIPELINE_STATUS_RECEIPT_SCHEMA.into();
        receipt.controller_invocation_id.clear();
        receipt.producer_invocation_id.clear();
        receipt.status.phase = "publication".into();
        let mut importer = binding();
        importer.unit = "jetstreamer-root-import-horizon-206-cf9b7e9-v1-e206-206-3.service".into();
        importer.claim_phase = "local-publication".into();
        receipt.pipeline_binding = Some(importer);
        let path = status_receipt_path(directory, &receipt.status);
        assert_eq!(
            validate_status_publication_receipt_bytes(
                directory,
                &path,
                &serde_json::to_vec(&receipt).unwrap(),
                "bucket",
                206
            )
            .unwrap(),
            receipt
        );
        receipt.status.phase = "upload".into();
        assert!(
            validate_status_publication_receipt_bytes(
                directory,
                &path,
                &serde_json::to_vec(&receipt).unwrap(),
                "bucket",
                206
            )
            .is_err()
        );
    }

    #[test]
    fn scope_rejects_ready_replay_stale_and_unsupported_estimates() {
        let root = tempfile::tempdir().unwrap();
        let jet = root.path().join("epoch-213.jet");
        fs::write(&jet, b"jet").unwrap();
        let bound = || Bound {
            path: "/evidence".into(),
            sha256: "e".repeat(64),
        };
        let mut plan = Plan {
            schema: "jetstreamer-horizon-pipeline-status-plan-v1".into(),
            epoch: 213,
            phase: "upload".into(),
            binding: binding(),
            observer: bound(),
            fleet: Bound {
                path: "/fleet".into(),
                sha256: "d".repeat(64),
            },
            origin_launch: bound(),
            estimate_evidence: vec![bound()],
            estimate_basis: "measured transfer allowance".into(),
            estimated_remaining_millis: 1000,
            jet_path: jet,
            expected_jet_size_bytes: 3,
            peer_units: vec![],
            receipt_directory: "/receipts".into(),
        };
        let observer = json!({"schema":"jetstreamer-horizon-live-resource-sample-v2","recorded_at_utc":"2026-10-20T05:04:42Z"});
        let t = fleet::utc_seconds("2026-10-20T05:04:42Z").unwrap();
        let fleet = json!({"schema":"jetstreamer-horizon-campaign-fleet-v1","observer_receipt":"/evidence",
            "observer_sha256":"e".repeat(64),"sampled_at_utc":"2026-10-20T05:04:42Z","recorded_unix_seconds":t+2,
            "first_epoch":201,"last_epoch":300,"active":[{"epoch":213,"phase":"upload-readback","unit":{
                "Id":plan.binding.unit,"LoadState":"loaded","ActiveState":"active","SubState":"running",
                "InvocationID":plan.binding.invocation_id,"NRestarts":"0","MainPID":"123","ExecStart":plan.binding.expected_exec_start
            }}],"epochs":[{"epoch":213,"state":"post-replay-pipeline"}]});
        validate_scope(&plan, &observer, &fleet, t + 5).unwrap();
        let mut parallel = fleet.clone();
        let mut peer = parallel["active"][0].clone();
        peer["phase"] = json!("full-verification");
        peer["unit"]["Id"] = json!("horizon-full-verify-213-test.service");
        parallel["active"].as_array_mut().unwrap().push(peer);
        validate_scope(&plan, &observer, &parallel, t + 5).unwrap();
        parallel["active"][1]["phase"] = json!("diagnostic-qualification");
        assert!(validate_scope(&plan, &observer, &parallel, t + 5).is_err());
        let mut unclaimed = fleet.clone();
        unclaimed["active"] = json!([]);
        assert!(validate_scope(&plan, &observer, &unclaimed, t + 5).is_err());
        let mut replacement = fleet.clone();
        replacement["active"][0]["unit"]["InvocationID"] = json!("f".repeat(32));
        assert!(validate_scope(&plan, &observer, &replacement, t + 5).is_err());
        assert!(validate_scope(&plan, &observer, &fleet, t + 1801).is_err());
        let mut ready = fleet.clone();
        ready["epochs"][0]["state"] = json!("remote-ready");
        assert!(validate_scope(&plan, &observer, &ready, t + 5).is_err());
        let mut replay = fleet;
        replay["active"] = json!([{"epoch":213,"phase":"replay"}]);
        assert!(validate_scope(&plan, &observer, &replay, t + 5).is_err());
        plan.estimated_remaining_millis = 0;
        assert!(validate_scope(&plan, &observer, &ready, t + 5).is_err());
    }
}
