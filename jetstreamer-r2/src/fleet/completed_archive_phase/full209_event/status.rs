//! Numeric epoch209 delivery forecasts through canonical sidecar commit.
//! Uses the common conditional authenticated status writer, never archive I/O.
use super::*;
const DELIVERY_REQUEST: &str = "jetstreamer-completed209-delivery-status-request-v1";
fn wire_phase(p: Phase) -> &'static str {
    if p == Phase::Upload {
        "upload"
    } else {
        "verification"
    }
}
const REQUEST: &str = "jetstreamer-completed209-full-status-request-v1";
const DELIVERY_POLICY: &str = "jetstreamer-completed209-delivery-sidecar-policy-v1";
const DELIVERY_ESTIMATE: &str = "jetstreamer-completed209-delivery-status-estimate-v1";
const POLICY: &str = "jetstreamer-completed209-full-sidecar-policy-v1";
const ESTIMATE: &str = "jetstreamer-completed209-full-status-estimate-v1";
const STAGES: [&str; 7] = [
    "remaining_full_verification",
    "plugin_verification",
    "boundary_checks",
    "upload",
    "readback",
    "sidecar_commit",
    "recovery",
];
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    mode: String,
    observer: BoundFile,
    fleet: BoundFile,
    launch: BoundFile,
    event: Option<BoundFile>,
    policy: BoundFile,
    estimate_receipt: PathBuf,
    receipt_directory: PathBuf,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    schema: String,
    epoch: u64,
    launch: BoundFile,
    observer: BoundFile,
    sampled_at_utc: String,
    sidecar_inclusive: bool,
    estimates_are_current_best_guesses: bool,
    remaining_stage_millis: BTreeMap<String, u64>,
    estimate_basis: String,
    evidence: Vec<BoundFile>,
}
fn forecast(p: &Policy, r: &Request, sample: &str, phase: Phase) -> Result<u64> {
    ensure!(
        matches!(p.schema.as_str(), POLICY | DELIVERY_POLICY)
            && p.epoch == 209
            && p.launch == r.launch
            && p.observer == r.observer
            && p.sampled_at_utc == sample
            && p.sidecar_inclusive
            && p.estimates_are_current_best_guesses
            && !p.estimate_basis.trim().is_empty()
            && !p.evidence.is_empty()
            && p.remaining_stage_millis
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>()
                == BTreeSet::from(STAGES),
        "completed209 forecast is not the exact current positive sidecar-inclusive model"
    );
    p.remaining_stage_millis.iter().try_fold(0u64, |sum, (stage,n)| {
        let completed = (stage == "remaining_full_verification" && phase != Phase::Full)
            || (stage == "plugin_verification" && phase == Phase::Upload);
        ensure!(if completed {*n == 0} else {*n > 0},
            "completed209 forecast changed a proved completed stage or lacks a remaining allowance");
        sum.checked_add(*n)
            .context("completed209 sidecar estimate overflow")
    })
}
fn registered(r: &Request, f: &Value, o: &Value, c: &PipelineClaim) -> Result<()> {
    ensure!(
        matches!(r.schema.as_str(), REQUEST | DELIVERY_REQUEST)
            && o["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && f["schema"] == super::super::super::SCHEMA
            && f["first_epoch"] == 201
            && f["last_epoch"] == 300
            && f["observer_receipt"].as_str() == r.observer.path.to_str()
            && f["observer_sha256"] == r.observer.sha256
            && f["sampled_at_utc"] == o["recorded_at_utc"]
            && f["inventory"]["anomalies"] == 0,
        "completed209 status lost its accepted coordinated fleet"
    );
    let p: Plan = serde_json::from_value(read(&serde_json::from_value(
        json!({"path":f["plan"],"sha256":f["plan_sha256"]}),
    )?)?)?;
    ensure!(
        p.observer == r.observer
            && p.gates
                .get(&209)
                .is_some_and(|g| g.state == "post-replay-pipeline")
            && p.pipeline_claims.iter().filter(|v| *v == c).count() == 1
            && f["active"]
                .as_array()
                .context("completed209 live roster missing")?
                .iter()
                .filter(|v| v["epoch"] == 209
                    && v["phase"] == c.phase
                    && v["live"] == true
                    && v["unit"]["Id"] == c.unit
                    && v["unit"]["InvocationID"] == c.invocation_id)
                .count()
                == 1,
        "completed209 status is not registered as its genuine generic delivery child"
    );
    peer_observation(f, o)?;
    Ok(())
}
fn sample(r: &Request, f: &Value, o: &Value, l: &Value, at: u64) -> Result<String> {
    let resource = utc_seconds(string(o, "recorded_at_utc")?)?;
    let recorded = number(f, "recorded_unix_seconds")?;
    ensure!(
        resource <= recorded && recorded <= at && at - resource <= 1800,
        "completed209 status requires a fresh coordinated fleet and observer"
    );
    match (r.mode.as_str(), &r.event) {
        ("initial", Some(b)) => {
            let e = read(b)?;
            ensure!(
                f["metadata_event"] == private157::binding(b)
                    && e["observer"] == private157::binding(&r.observer)
                    && e["launch"] == private157::binding(&r.launch),
                "completed209 initial status borrowed another handoff event"
            );
            let (_, saved, _, _) = event_launch(&e)?;
            ensure!(
                saved == *l,
                "completed209 status capture differs from event"
            );
            let previous = read(&serde_json::from_value(e["previous_fleet"].clone())?)?;
            event_clock(&previous, o, l, at)?;
            report_clock(
                "initial",
                resource,
                number(l, "captured_unix_seconds")?,
                Some(string(&e, "sampled_at_utc")?),
            )
        }
        ("observation", None) => report_clock(
            "observation",
            resource,
            number(l, "captured_unix_seconds")?,
            None,
        ),
        _ => bail!("completed209 status mode/event combination differs"),
    }
}
fn report_clock(mode: &str, resource: u64, captured: u64, event: Option<&str>) -> Result<String> {
    match (mode, event) {
        ("initial", Some(t)) => {
            ensure!(
                resource < captured && utc_seconds(t)? == captured,
                "completed209 initial report must use its exact post-sample capture clock"
            );
            Ok(t.into())
        }
        ("observation", None) => {
            ensure!(
                captured <= resource,
                "completed209 routine report cannot backdate a post-sample child"
            );
            publication203::utc(resource)
        }
        _ => bail!("completed209 report clock mode differs"),
    }
}
fn measured(admission: &Value) -> Result<(PathBuf, FileIdentity)> {
    let path = Path::new(singleton209::ROOT).join("output/epoch-209.jet");
    ensure!(
        path.canonicalize()? == path,
        "completed209 archive namespace redirected"
    );
    let m = fs::symlink_metadata(&path)?;
    ensure!(
        m.is_file() && m.nlink() == 1,
        "completed209 archive metadata unsafe"
    );
    let id = regular_identity(&path)?;
    let a = &admission["archive"];
    ensure!(
        a["path"] == serde_json::to_value(&path)?
            && a["bytes"] == id.length
            && a["device"] == id.device
            && a["inode"] == id.inode
            && a["modified_seconds"] == id.modified_seconds
            && a["modified_nanoseconds"] == id.modified_nanoseconds
            && id.length > 0,
        "completed209 current jet differs from admitted immutable archive identity"
    );
    Ok((path, id))
}
fn original_clock(s: &Spec) -> Result<(DiagnosticClaim, Value, u64)> {
    let Origin::Singleton209 { launch, .. } = &s.origin;
    let (c, l) = full209_status::claim(launch)?;
    let terminal = singleton209_delivery::source_terminal(&l)?;
    let micros = terminal["events"][0]["__REALTIME_TIMESTAMP"]
        .as_str()
        .context("completed209 original Started clock missing")?
        .parse::<u64>()?;
    ensure!(micros > 0, "completed209 original clock is zero");
    Ok((c, terminal, micros / 1000))
}
fn live_census(f: &Value, l: &Value, c: &PipelineClaim) -> Result<BTreeMap<String, Value>> {
    let names = f["unit_census"]
        .as_object()
        .context("completed209 complete census missing")?
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    let current = census(&names, 201, 300)?;
    maintenance_capacity::current_owners(f, &current)?;
    owner_shape(
        l,
        current
            .get(string(l, "unit")?)
            .context("completed209 status owner omitted")?,
    )?;
    live(c, l)?;
    Ok(current)
}
pub(in crate::fleet) async fn publish() -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0 && unsafe { libc::getegid() } == 0,
        "completed209 status publication requires root"
    );
    let (binding, self_sha) = publication203::parsed_args("status-publish-completed209-full")?;
    let r: Request = serde_json::from_value(read(&binding)?)?;
    let (c, l, s, admission) = checked_launch(&r.launch)?;
    let f = read(&r.fleet)?;
    let o = read(&r.observer)?;
    registered(&r, &f, &o, &c)?;
    let sampled = sample(&r, &f, &o, &l, now()?)?;
    let policy: Policy = serde_json::from_value(read(&r.policy)?)?;
    let remaining = forecast(&policy, &r, &sampled, s.phase)?;
    for b in &policy.evidence {
        ensure!(
            b.path.starts_with("/var/lib/jetstreamer")
                && b.path.extension().is_some_and(|e| e == "json"),
            "completed209 estimate evidence must be bound private JSON metadata"
        );
        read(b)?;
    }
    let (origin, terminal, start) = original_clock(&s)?;
    let elapsed = utc_seconds(&sampled)?
        .checked_mul(1000)
        .and_then(|n| n.checked_sub(start))
        .context("completed209 status predates its original producer")?;
    let (_, id) = measured(&admission)?;
    live_census(&f, &l, &c)?;
    let status = EpochStatus {
        epoch: 209,
        jet_size_bytes: id.length,
        elapsed_execution_millis: elapsed,
        estimated_remaining_millis: remaining,
        sampled_at_utc: sampled,
        phase: wire_phase(s.phase).into(),
    };
    validate_epoch_status(&status, 209)?;
    let pipeline = pipeline_status::Binding {
        unit: c.unit.clone(),
        invocation_id: c.invocation_id.clone(),
        expected_exec_start: c.expected_exec_start.clone(),
        claim_phase: c.phase.clone(),
        origin_unit: origin.unit,
        origin_invocation_id: origin.invocation_id,
        model_path: binding.path.clone(),
        model_sha256: binding.sha256.clone(),
        fleet_path: r.fleet.path.clone(),
        fleet_sha256: r.fleet.sha256.clone(),
    };
    pipeline.validate(209, wire_phase(s.phase))?;
    ensure!(
        r.receipt_directory == Path::new("/home/ubuntu/.jetstreamer-private/r2-status-receipts"),
        "completed209 status receipt directory differs"
    );
    let parent = r
        .estimate_receipt
        .parent()
        .context("completed209 estimate parent missing")?;
    resource_audit::private_directory(parent)?;
    ensure!(
        parent.parent() == Some(Path::new("/var/lib/jetstreamer"))
            && parent
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("horizon-generic209-full-status-")
                    || n.starts_with("horizon-generic209-delivery-status-"))
            && r.estimate_receipt
                .file_name()
                .is_some_and(|n| n == "estimate.json"),
        "completed209 estimate escaped private namespace"
    );
    let estimate = json!({"schema":if s.phase == Phase::Full {ESTIMATE} else {DELIVERY_ESTIMATE},"request":binding,"issuer_sha256":self_sha,
        "observer":r.observer,"fleet":r.fleet,"launch":r.launch,"event":r.event,"mode":r.mode,
        "policy":r.policy,"status":status,"jet_identity":id,"original_started_millis":start,
        "original_terminal_evidence":terminal,"authority":denied()});
    if r.estimate_receipt.try_exists()? {
        let old: BoundFile =
            serde_json::from_value(private157::file_binding(&r.estimate_receipt)?)?;
        let mut saved = read(&old)?;
        singleton209_delivery::same_source_terminal(
            &saved["original_terminal_evidence"],
            &estimate["original_terminal_evidence"],
        )?;
        saved["original_terminal_evidence"] = estimate["original_terminal_evidence"].clone();
        ensure!(
            saved == estimate,
            "completed209 estimate retry conflicts with immutable evidence"
        );
    } else {
        private157::immutable_receipt(&r.estimate_receipt, &estimate)?;
    }
    let estimate_binding: BoundFile =
        serde_json::from_value(private157::file_binding(&r.estimate_receipt)?)?;
    live_census(&f, &l, &c)?;
    ensure!(
        measured(&admission)?.1 == id,
        "completed209 archive changed across status checks"
    );
    let r2 = r2_config_from_env()?;
    let s3 = s3_client(&r2);
    ensure!(
        get_mutable_object(&s3, &r2.bucket, "epoch-209.jet.sha256")
            .await?
            .is_none(),
        "completed209 canonical sidecar already committed; reconcile completion"
    );
    preflight_status_receipt_write(&r.receipt_directory)?;
    let (object_etag, previous_object_etag) = publish_epoch_status(&s3, &r2, &status).await?;
    let receipt = StatusPublicationReceipt {
        schema: PIPELINE_STATUS_RECEIPT_SCHEMA.into(),
        bucket: r2.bucket,
        epoch: 209,
        key: "epoch-209.epoch-status.json".into(),
        status,
        object_etag,
        previous_object_etag,
        observer_receipt: estimate_binding.path,
        observer_receipt_sha256: estimate_binding.sha256,
        controller_invocation_id: String::new(),
        producer_invocation_id: String::new(),
        authenticated_readback: true,
        verified_unix_seconds: now()?,
        pipeline_binding: Some(pipeline),
    };
    let path = status_receipt_path(&r.receipt_directory, &receipt.status);
    if path.try_exists()? {
        let old: StatusPublicationReceipt = serde_json::from_slice(&read_stable_bounded(
            &path,
            MAX_STATUS_BYTES,
            "completed209 prior status receipt",
        )?)?;
        ensure!(
            old.status == receipt.status
                && old.object_etag == receipt.object_etag
                && old.pipeline_binding == receipt.pipeline_binding
                && old.authenticated_readback,
            "completed209 existing publication receipt conflicts"
        );
    } else {
        write_status_receipt(&r.receipt_directory, &receipt)?;
    }
    Ok(())
}
pub(in crate::fleet) fn status_matches(
    receipt: &StatusPublicationReceipt,
    epoch: u64,
    o: &Value,
    current: &BTreeMap<String, Value>,
) -> bool {
    (|| -> Result<()> {
        ensure!(
            epoch == 209
                && receipt.epoch == 209
                && receipt.schema == PIPELINE_STATUS_RECEIPT_SCHEMA
                && matches!(receipt.status.phase.as_str(), "verification" | "upload")
                && receipt.authenticated_readback,
            "not completed209 verification metadata"
        );
        let b = BoundFile {
            path: receipt.observer_receipt.clone(),
            sha256: receipt.observer_receipt_sha256.clone(),
        };
        let estimate = read(&b)?;
        ensure!(
            matches!(
                estimate["schema"].as_str(),
                Some(ESTIMATE | DELIVERY_ESTIMATE)
            ) && estimate["status"] == json!(receipt.status)
                && estimate["authority"] == denied(),
            "completed209 status is not from this immutable observation"
        );
        let model: BoundFile = serde_json::from_value(estimate["request"].clone())?;
        let r: Request = serde_json::from_value(read(&model)?)?;
        ensure!(
            matches!(r.schema.as_str(), REQUEST | DELIVERY_REQUEST)
                && estimate["launch"] == private157::binding(&r.launch)
                && estimate["policy"] == private157::binding(&r.policy)
                && estimate["observer"] == private157::binding(&r.observer)
                && estimate["fleet"] == private157::binding(&r.fleet)
                && estimate["mode"] == r.mode
                && estimate["event"] == serde_json::to_value(&r.event)?
                && read(&r.observer)? == *o,
            "completed209 status belongs to another coordinated resource sample"
        );
        let l = read(&r.launch)?;
        capture_shape(&l)?;
        let p: Policy = serde_json::from_value(read(&r.policy)?)?;
        ensure!(
            forecast(&p, &r, &receipt.status.sampled_at_utc, phase(&l)?)?
                == receipt.status.estimated_remaining_millis,
            "completed209 status forecast changed"
        );
        let binding = receipt
            .pipeline_binding
            .as_ref()
            .context("completed209 status binding absent")?;
        let child_phase = phase(&l)?;
        ensure!(
            receipt.status.phase == wire_phase(child_phase),
            "completed209 status wire phase differs from child"
        );
        binding.validate(209, wire_phase(child_phase))?;
        ensure!(
            binding.unit == l["unit"]
                && binding.invocation_id == l["invocation_id"]
                && binding.claim_phase == claim_phase(child_phase)
                && binding.model_path == model.path
                && binding.model_sha256 == model.sha256
                && binding.fleet_path == r.fleet.path
                && binding.fleet_sha256 == r.fleet.sha256
                && pipeline_status::same_exec_start(
                    &binding.expected_exec_start,
                    string(&l["effective_unit"], "ExecStart")?
                ),
            "completed209 status borrowed another owner/model"
        );
        owner_shape(
            &l,
            current
                .get(&binding.unit)
                .context("completed209 owner absent")?,
        )?;
        Ok(())
    })()
    .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn bound(name: &str) -> BoundFile {
        BoundFile {
            path: format!("/sealed/{name}.json").into(),
            sha256: "a".repeat(64),
        }
    }
    fn request() -> Request {
        Request {
            schema: REQUEST.into(),
            mode: "initial".into(),
            observer: bound("observer"),
            fleet: bound("fleet"),
            launch: bound("generic-capture"),
            event: Some(bound("event")),
            policy: bound("policy"),
            estimate_receipt:
                "/var/lib/jetstreamer/horizon-generic209-full-status-test/estimate.json".into(),
            receipt_directory: "/home/ubuntu/.jetstreamer-private/r2-status-receipts".into(),
        }
    }
    fn policy(r: &Request) -> Policy {
        Policy { schema:POLICY.into(),epoch:209,launch:r.launch.clone(),observer:r.observer.clone(),
            sampled_at_utc:"2026-10-26T05:50:00Z".into(),sidecar_inclusive:true,
            estimates_are_current_best_guesses:true,
            remaining_stage_millis:STAGES.into_iter().map(|s|(s.into(),1000)).collect(),
            estimate_basis:"Current best guess including Full, plugin, boundary, recovery, upload, readback and sidecar".into(),
            evidence:vec![bound("actual-evidence")] }
    }
    #[test]
    fn g209_status_forecast_is_numeric_positive_and_sidecar_inclusive() {
        let r = request();
        let p = policy(&r);
        assert_eq!(
            forecast(&p, &r, &p.sampled_at_utc, Phase::Full).unwrap(),
            7000
        );
        for stage in STAGES {
            let mut p = policy(&r);
            p.remaining_stage_millis.insert(stage.into(), 0);
            assert!(
                forecast(&p, &r, &p.sampled_at_utc, Phase::Full).is_err(),
                "{stage}"
            );
        }
        let mut p = policy(&r);
        p.remaining_stage_millis.remove("readback");
        assert!(forecast(&p, &r, &p.sampled_at_utc, Phase::Full).is_err());
        let mut p = policy(&r);
        p.sidecar_inclusive = false;
        assert!(forecast(&p, &r, &p.sampled_at_utc, Phase::Full).is_err());
        let mut p = policy(&r);
        p.remaining_stage_millis.insert("upload".into(), u64::MAX);
        assert!(forecast(&p, &r, &p.sampled_at_utc, Phase::Full).is_err());
    }
    #[test]
    fn g209_status_policy_cannot_reuse_stale_sample_or_foreign_capture() {
        let r = request();
        let p = policy(&r);
        assert!(forecast(&p, &r, "2026-10-26T06:20:00Z", Phase::Full).is_err());
        let mut p = policy(&r);
        p.launch = bound("legacy-replay");
        assert!(forecast(&p, &r, &p.sampled_at_utc, Phase::Full).is_err());
        let mut p = policy(&r);
        p.observer.sha256 = "b".repeat(64);
        assert!(forecast(&p, &r, &p.sampled_at_utc, Phase::Full).is_err());
        let mut p = policy(&r);
        p.epoch = 210;
        assert!(forecast(&p, &r, &p.sampled_at_utc, Phase::Full).is_err());
        let mut p = policy(&r);
        p.evidence.clear();
        assert!(forecast(&p, &r, &p.sampled_at_utc, Phase::Full).is_err());
    }
    #[test]
    fn g209_status_wire_rejects_replay_phase_and_caller_clock_overrides() {
        let b = json!({"path":"/sealed/file.json","sha256":"a".repeat(64)});
        let mut r = json!({"schema":REQUEST,"mode":"initial","observer":b,"fleet":b,
            "launch":b,"event":b,"policy":b,"estimate_receipt":"/private/estimate.json",
            "receipt_directory":"/private/receipts"});
        assert!(serde_json::from_value::<Request>(r.clone()).is_ok());
        for key in [
            "phase",
            "elapsed_execution_millis",
            "sampled_at_utc",
            "skip_live_owner",
        ] {
            r[key] = json!("replay");
            assert!(serde_json::from_value::<Request>(r.clone()).is_err());
            r.as_object_mut().unwrap().remove(key);
        }
    }
    #[test]
    fn g209_status_initial_and_routine_clocks_cannot_be_backdated_or_replayed() {
        let actual = "1970-01-01T00:15:20Z";
        assert_eq!(
            report_clock("initial", 900, 920, Some(actual)).unwrap(),
            actual
        );
        assert!(report_clock("initial", 900, 920, Some("1970-01-01T00:15:21Z")).is_err());
        assert!(report_clock("initial", 920, 920, Some(actual)).is_err());
        assert!(report_clock("observation", 900, 920, None).is_err());
        assert_eq!(
            report_clock("observation", 1000, 920, None).unwrap(),
            "1970-01-01T00:16:40Z"
        );
        assert!(report_clock("observation", 1000, 920, Some(actual)).is_err());
    }
    #[test]
    fn completed209_late_capture_initial_status_uses_new_capture_clock_then_real_observer() {
        assert_eq!(
            report_clock("initial", 9900, 10000, Some("1970-01-01T02:46:40Z")).unwrap(),
            "1970-01-01T02:46:40Z"
        );
        assert!(report_clock("observation", 9900, 10000, None).is_err());
        assert_eq!(
            report_clock("observation", 11000, 10000, None).unwrap(),
            "1970-01-01T03:03:20Z"
        );
        assert!(report_clock("initial", 9900, 10000, Some("1970-01-01T00:15:00Z")).is_err());
    }
    #[test]
    fn completed209_successor_status_zeros_completed_gates_and_binds_upload_wire_phase() {
        let r = request();
        let mut p = policy(&r);
        p.remaining_stage_millis
            .insert("remaining_full_verification".into(), 0);
        assert_eq!(
            forecast(&p, &r, &p.sampled_at_utc, Phase::Plugin).unwrap(),
            6000
        );
        assert!(forecast(&p, &r, &p.sampled_at_utc, Phase::Full).is_err());
        assert!(forecast(&p, &r, &p.sampled_at_utc, Phase::Upload).is_err());
        p.remaining_stage_millis
            .insert("plugin_verification".into(), 0);
        assert_eq!(
            forecast(&p, &r, &p.sampled_at_utc, Phase::Upload).unwrap(),
            5000
        );
        assert_eq!(wire_phase(Phase::Plugin), "verification");
        assert_eq!(wire_phase(Phase::Upload), "upload");
        p.remaining_stage_millis.insert("readback".into(), 0);
        assert!(forecast(&p, &r, &p.sampled_at_utc, Phase::Upload).is_err());
    }
    #[test]
    fn completed209_successor_status_bindings_use_the_actual_claim_phase() {
        for phase in [Phase::Plugin, Phase::Upload] {
            let mut b = pipeline_status::Binding {
                unit: format!("horizon-qualify-209-generic-{}-v12.service", phase.name()),
                invocation_id: "b".repeat(32),
                expected_exec_start: "exact admitted command".into(),
                claim_phase: claim_phase(phase).into(),
                origin_unit: singleton209::UNIT.into(),
                origin_invocation_id: "c".repeat(32),
                model_path: "/sealed/model.json".into(),
                model_sha256: "d".repeat(64),
                fleet_path: "/sealed/fleet.json".into(),
                fleet_sha256: "e".repeat(64),
            };
            b.validate(209, wire_phase(phase)).unwrap();
            b.claim_phase = "full-verification".into();
            assert!(b.validate(209, wire_phase(phase)).is_err());
        }
    }
}
