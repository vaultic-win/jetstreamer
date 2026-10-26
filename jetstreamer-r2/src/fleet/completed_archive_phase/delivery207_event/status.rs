//! Numeric207 Full/plugin/upload forecasts through canonical sidecar commit.
//! Uses the common conditional authenticated status writer, never archive I/O.
use super::*;
const REQUEST: &str = "jetstreamer-completed207-phase-status-request-v1";
const POLICY: &str = "jetstreamer-completed207-phase-sidecar-policy-v1";
const ESTIMATE: &str = "jetstreamer-completed207-phase-status-estimate-v1";
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
    phase: Phase,
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
    let stages = match phase {
        Phase::Full => BTreeSet::from(STAGES),
        Phase::Plugin => BTreeSet::from([
            "plugin_verification",
            "boundary_checks",
            "upload",
            "readback",
            "sidecar_commit",
            "recovery",
        ]),
        Phase::Upload => BTreeSet::from(["upload", "readback", "sidecar_commit", "recovery"]),
    };
    ensure!(
        p.schema == POLICY
            && p.epoch == 207
            && p.phase == phase
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
                == stages,
        "completed207 forecast is not the exact current positive sidecar-inclusive model"
    );
    p.remaining_stage_millis.values().try_fold(0u64, |sum, n| {
        ensure!(*n > 0, "completed207 forecast contains a zero allowance");
        sum.checked_add(*n)
            .context("completed207 sidecar estimate overflow")
    })
}
fn registered(r: &Request, f: &Value, o: &Value, c: &PipelineClaim) -> Result<()> {
    ensure!(
        r.schema == REQUEST
            && o["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && f["schema"] == super::super::super::SCHEMA
            && f["first_epoch"] == 201
            && f["last_epoch"] == 300
            && f["observer_receipt"].as_str() == r.observer.path.to_str()
            && f["observer_sha256"] == r.observer.sha256
            && f["sampled_at_utc"] == o["recorded_at_utc"]
            && f["inventory"]["anomalies"] == 0,
        "completed207 status lost its accepted coordinated fleet"
    );
    let p: Plan = serde_json::from_value(read(&serde_json::from_value(
        json!({"path":f["plan"],"sha256":f["plan_sha256"]}),
    )?)?)?;
    ensure!(
        p.observer == r.observer
            && p.gates
                .get(&207)
                .is_some_and(|g| g.state == "post-replay-pipeline")
            && p.pipeline_claims.iter().filter(|v| *v == c).count() == 1
            && f["active"]
                .as_array()
                .context("completed207 live roster missing")?
                .iter()
                .filter(|v| v["epoch"] == 207
                    && v["phase"] == c.phase
                    && v["live"] == true
                    && v["unit"]["Id"] == c.unit
                    && v["unit"]["InvocationID"] == c.invocation_id)
                .count()
                == 1,
        "completed207 status is not registered as its genuine captured phase child"
    );
    peer_observation(f, o)?;
    Ok(())
}
fn sample(r: &Request, f: &Value, o: &Value, l: &Value, at: u64) -> Result<String> {
    let resource = utc_seconds(string(o, "recorded_at_utc")?)?;
    let recorded = number(f, "recorded_unix_seconds")?;
    ensure!(
        resource <= recorded && recorded <= at && at - resource <= 1800,
        "completed207 status requires a fresh coordinated fleet and observer"
    );
    match (r.mode.as_str(), &r.event) {
        ("initial", Some(b)) => {
            let e = read(b)?;
            ensure!(
                f["metadata_event"] == private157::binding(b)
                    && e["observer"] == private157::binding(&r.observer)
                    && e["launch"] == private157::binding(&r.launch),
                "completed207 initial status borrowed another handoff event"
            );
            let (_, saved, _, _) = event_launch(&e)?;
            ensure!(
                saved == *l,
                "completed207 status capture differs from event"
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
        _ => bail!("completed207 status mode/event combination differs"),
    }
}
fn report_clock(mode: &str, resource: u64, captured: u64, event: Option<&str>) -> Result<String> {
    match (mode, event) {
        ("initial", Some(t)) => {
            ensure!(
                resource < captured && utc_seconds(t)? == captured,
                "completed207 initial report must use its exact post-sample capture clock"
            );
            Ok(t.into())
        }
        ("observation", None) => {
            ensure!(
                captured <= resource,
                "completed207 routine report cannot backdate a post-sample child"
            );
            publication203::utc(resource)
        }
        _ => bail!("completed207 report clock mode differs"),
    }
}
fn measured(admission: &Value) -> Result<(PathBuf, FileIdentity)> {
    let path = Path::new(singleton207::ROOT).join("output/epoch-207.jet");
    ensure!(
        path.canonicalize()? == path,
        "completed207 archive namespace redirected"
    );
    let m = fs::symlink_metadata(&path)?;
    ensure!(
        m.is_file() && m.nlink() == 1,
        "completed207 archive metadata unsafe"
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
        "completed207 current jet differs from admitted immutable archive identity"
    );
    Ok((path, id))
}
fn original_clock(s: &Spec) -> Result<(DiagnosticClaim, Value, u64)> {
    let Origin::Singleton207 {
        launch, terminal, ..
    } = &s.origin
    else {
        bail!("207 status requires its typed original source")
    };
    let (c, _) = singleton207::delivery::claim(launch)?;
    let evidence = singleton207::delivery::source_terminal(launch, terminal)?;
    let micros = evidence["events"][0]["__REALTIME_TIMESTAMP"]
        .as_str()
        .context("207 original Started clock absent")?
        .parse::<u64>()?;
    ensure!(micros > 0, "207 original clock is zero");
    Ok((c, evidence, micros / 1000))
}
fn live_census(f: &Value, l: &Value, c: &PipelineClaim) -> Result<BTreeMap<String, Value>> {
    let names = f["unit_census"]
        .as_object()
        .context("completed207 complete census missing")?
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    let current = census(&names, 201, 300)?;
    maintenance_capacity::current_owners(f, &current)?;
    owner_shape(
        l,
        current
            .get(string(l, "unit")?)
            .context("completed207 status owner omitted")?,
    )?;
    live(c, l)?;
    Ok(current)
}
pub(in crate::fleet) async fn publish() -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0 && unsafe { libc::getegid() } == 0,
        "completed207 status publication requires root"
    );
    let (binding, self_sha) = publication203::parsed_args("status-publish-completed207-phase")?;
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
            "completed207 estimate evidence must be bound private JSON metadata"
        );
        read(b)?;
    }
    let (origin, terminal, start) = original_clock(&s)?;
    let elapsed = utc_seconds(&sampled)?
        .checked_mul(1000)
        .and_then(|n| n.checked_sub(start))
        .context("completed207 status predates its original producer")?;
    let (_, id) = measured(&admission)?;
    live_census(&f, &l, &c)?;
    let status = EpochStatus {
        epoch: 207,
        jet_size_bytes: id.length,
        elapsed_execution_millis: elapsed,
        estimated_remaining_millis: remaining,
        sampled_at_utc: sampled,
        phase: status_phase(&l)?.into(),
    };
    validate_epoch_status(&status, 207)?;
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
    pipeline.validate(207, &status.phase)?;
    ensure!(
        r.receipt_directory == Path::new("/home/ubuntu/.jetstreamer-private/r2-status-receipts"),
        "completed207 status receipt directory differs"
    );
    let parent = r
        .estimate_receipt
        .parent()
        .context("completed207 estimate parent missing")?;
    resource_audit::private_directory(parent)?;
    ensure!(
        parent.parent() == Some(Path::new("/var/lib/jetstreamer"))
            && parent
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("horizon-generic207-phase-status-"))
            && r.estimate_receipt
                .file_name()
                .is_some_and(|n| n == "estimate.json"),
        "completed207 estimate escaped private namespace"
    );
    let estimate = json!({"schema":ESTIMATE,"request":binding,"issuer_sha256":self_sha,
        "observer":r.observer,"fleet":r.fleet,"launch":r.launch,"event":r.event,"mode":r.mode,
        "policy":r.policy,"status":status,"jet_identity":id,"original_started_millis":start,
        "original_terminal_evidence":terminal,"authority":denied()});
    if r.estimate_receipt.try_exists()? {
        let old: BoundFile =
            serde_json::from_value(private157::file_binding(&r.estimate_receipt)?)?;
        let mut saved = read(&old)?;
        singleton207::delivery::same_terminal(
            &saved["original_terminal_evidence"],
            &estimate["original_terminal_evidence"],
        )?;
        saved["original_terminal_evidence"] = estimate["original_terminal_evidence"].clone();
        ensure!(
            saved == estimate,
            "completed207 estimate retry conflicts with immutable evidence"
        );
    } else {
        private157::immutable_receipt(&r.estimate_receipt, &estimate)?;
    }
    let estimate_binding: BoundFile =
        serde_json::from_value(private157::file_binding(&r.estimate_receipt)?)?;
    live_census(&f, &l, &c)?;
    ensure!(
        measured(&admission)?.1 == id,
        "completed207 archive changed across status checks"
    );
    let r2 = r2_config_from_env()?;
    let s3 = s3_client(&r2);
    ensure!(
        get_mutable_object(&s3, &r2.bucket, "epoch-207.jet.sha256")
            .await?
            .is_none(),
        "completed207 canonical sidecar already committed; reconcile completion"
    );
    preflight_status_receipt_write(&r.receipt_directory)?;
    let (object_etag, previous_object_etag) = publish_epoch_status(&s3, &r2, &status).await?;
    let receipt = StatusPublicationReceipt {
        schema: PIPELINE_STATUS_RECEIPT_SCHEMA.into(),
        bucket: r2.bucket,
        epoch: 207,
        key: "epoch-207.epoch-status.json".into(),
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
            "completed207 prior status receipt",
        )?)?;
        ensure!(
            old.status == receipt.status
                && old.object_etag == receipt.object_etag
                && old.pipeline_binding == receipt.pipeline_binding
                && old.authenticated_readback,
            "completed207 existing publication receipt conflicts"
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
            epoch == 207
                && receipt.epoch == 207
                && receipt.schema == PIPELINE_STATUS_RECEIPT_SCHEMA
                && matches!(
                    receipt.status.phase.as_str(),
                    "verification" | "upload" | "readback"
                )
                && receipt.authenticated_readback,
            "not completed207 verification metadata"
        );
        let b = BoundFile {
            path: receipt.observer_receipt.clone(),
            sha256: receipt.observer_receipt_sha256.clone(),
        };
        let estimate = read(&b)?;
        ensure!(
            estimate["schema"] == ESTIMATE
                && estimate["status"] == json!(receipt.status)
                && estimate["authority"] == denied(),
            "completed207 status is not from this immutable observation"
        );
        let model: BoundFile = serde_json::from_value(estimate["request"].clone())?;
        let r: Request = serde_json::from_value(read(&model)?)?;
        ensure!(
            r.schema == REQUEST
                && estimate["launch"] == private157::binding(&r.launch)
                && estimate["policy"] == private157::binding(&r.policy)
                && estimate["observer"] == private157::binding(&r.observer)
                && estimate["fleet"] == private157::binding(&r.fleet)
                && estimate["mode"] == r.mode
                && estimate["event"] == serde_json::to_value(&r.event)?
                && read(&r.observer)? == *o,
            "completed207 status belongs to another coordinated resource sample"
        );
        let (_, l, s, _) = checked_launch(&r.launch)?;
        let p: Policy = serde_json::from_value(read(&r.policy)?)?;
        ensure!(
            forecast(&p, &r, &receipt.status.sampled_at_utc, s.phase)?
                == receipt.status.estimated_remaining_millis,
            "completed207 status forecast changed"
        );
        let binding = receipt
            .pipeline_binding
            .as_ref()
            .context("completed207 status binding absent")?;
        binding.validate(207, &receipt.status.phase)?;
        ensure!(
            binding.unit == l["unit"]
                && binding.invocation_id == l["invocation_id"]
                && binding.claim_phase == wire(&l)?
                && receipt.status.phase == status_phase(&l)?
                && binding.model_path == model.path
                && binding.model_sha256 == model.sha256
                && binding.fleet_path == r.fleet.path
                && binding.fleet_sha256 == r.fleet.sha256
                && pipeline_status::same_exec_start(
                    &binding.expected_exec_start,
                    string(&l["effective_unit"], "ExecStart")?
                ),
            "completed207 status borrowed another owner/model"
        );
        owner_shape(
            &l,
            current
                .get(&binding.unit)
                .context("completed207 owner absent")?,
        )?;
        Ok(())
    })()
    .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn bound() -> BoundFile {
        BoundFile {
            path: "/sealed/evidence.json".into(),
            sha256: "a".repeat(64),
        }
    }
    fn request() -> Request {
        Request {
            schema: REQUEST.into(),
            mode: "initial".into(),
            observer: bound(),
            fleet: bound(),
            launch: bound(),
            event: Some(bound()),
            policy: bound(),
            estimate_receipt: "/private/estimate.json".into(),
            receipt_directory: "/private/receipts".into(),
        }
    }
    fn policy(r: &Request, phase: Phase) -> Policy {
        let keys = match phase {
            Phase::Full => STAGES.to_vec(),
            Phase::Plugin => vec![
                "plugin_verification",
                "boundary_checks",
                "upload",
                "readback",
                "sidecar_commit",
                "recovery",
            ],
            Phase::Upload => vec!["upload", "readback", "sidecar_commit", "recovery"],
        };
        Policy {
            schema: POLICY.into(),
            epoch: 207,
            phase,
            launch: r.launch.clone(),
            observer: r.observer.clone(),
            sampled_at_utc: "2026-10-26T17:00:00Z".into(),
            sidecar_inclusive: true,
            estimates_are_current_best_guesses: true,
            remaining_stage_millis: keys.into_iter().map(|k| (k.into(), 1000)).collect(),
            estimate_basis: "Current stage through remote readback and sidecar".into(),
            evidence: vec![bound()],
        }
    }
    #[test]
    fn each_phase_keeps_numeric_current_sidecar_debt_without_resurrecting_completed_work() {
        let r = request();
        for (phase, total) in [
            (Phase::Full, 7000),
            (Phase::Plugin, 6000),
            (Phase::Upload, 4000),
        ] {
            let p = policy(&r, phase);
            assert_eq!(forecast(&p, &r, &p.sampled_at_utc, phase).unwrap(), total);
            for key in ["readback", "sidecar_commit", "recovery"] {
                let mut changed = policy(&r, phase);
                changed.remaining_stage_millis.remove(key);
                assert!(
                    forecast(&changed, &r, &changed.sampled_at_utc, phase).is_err(),
                    "{key}"
                );
            }
            let mut changed = policy(&r, phase);
            changed.epoch = 209;
            assert!(forecast(&changed, &r, &changed.sampled_at_utc, phase).is_err());
            changed = policy(&r, phase);
            changed.remaining_stage_millis.insert("readback".into(), 0);
            assert!(forecast(&changed, &r, &changed.sampled_at_utc, phase).is_err());
            assert!(forecast(&p, &r, "2026-10-26T17:30:00Z", phase).is_err());
        }
        let p = policy(&r, Phase::Full);
        assert!(forecast(&p, &r, &p.sampled_at_utc, Phase::Plugin).is_err());
    }
    #[test]
    fn stage_event_and_routine_clocks_keep_original_start_and_reject_backdating() {
        assert_eq!(
            report_clock("initial", 900, 920, Some("1970-01-01T00:15:20Z")).unwrap(),
            "1970-01-01T00:15:20Z"
        );
        assert!(report_clock("initial", 900, 920, Some("1970-01-01T00:15:21Z")).is_err());
        assert!(report_clock("observation", 900, 920, None).is_err());
        assert_eq!(
            report_clock("observation", 1000, 920, None).unwrap(),
            "1970-01-01T00:16:40Z"
        );
    }
}
