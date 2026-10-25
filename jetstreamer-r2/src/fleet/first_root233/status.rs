//! A sidecar-inclusive best guess for the actual private prefix owner.
//! Publication of this status never qualifies the partial archive.
use super::*;
const MODEL: &str = "jetstreamer-first-root233-status-model-v1";
const OBSERVATION: &str = "jetstreamer-first-root233-status-observation-v1";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Model {
    schema: String,
    mode: String,
    observer: BoundFile,
    fleet: BoundFile,
    launch: BoundFile,
    estimate: private_prefix::Estimate,
    estimate_basis: String,
    estimate_evidence: Vec<BoundFile>,
    estimate_receipt: PathBuf,
    receipt_directory: PathBuf,
}
fn claim(b: &BoundFile) -> Result<(DiagnosticClaim, Value)> {
    let v = native209::immutable_json(b)?;
    let invocation = v["evidence"]["units"][0]["invocation_id"]
        .as_str()
        .context("first root 233 status owner absent")?;
    let d = DiagnosticClaim {
        epoch: 233,
        unit: UNIT.into(),
        invocation_id: invocation.into(),
        scratch_path: ROOT.into(),
        launch_receipt: binding(
            b.path
                .to_str()
                .context("first root 233 launch path is not UTF-8")?,
            &b.sha256,
        ),
    };
    bindings(&d, &v)?;
    Ok((d, v))
}
fn registered(d: &DiagnosticClaim, f: &Value) -> Result<()> {
    let plan: Plan = serde_json::from_value(bound_json(&binding(
        f["plan"]
            .as_str()
            .context("first root 233 fleet plan absent")?,
        f["plan_sha256"]
            .as_str()
            .context("first root 233 fleet plan digest absent")?,
    ))?)?;
    let matches = plan
        .diagnostics
        .iter()
        .filter(|c| c.unit == UNIT)
        .collect::<Vec<_>>();
    ensure!(
        matches.len() == 1
            && matches[0].epoch == 233
            && matches[0].invocation_id == d.invocation_id
            && matches[0].scratch_path == d.scratch_path
            && matches[0].launch_receipt == d.launch_receipt,
        "first root 233 status is not the exact accepted diagnostic claim"
    );
    Ok(())
}
fn live(d: &DiagnosticClaim, f: &Value) -> Result<Value> {
    let current = unit(UNIT)?;
    let old = &f["unit_census"][UNIT];
    ensure!(
        private_prefix::owner(&current, UNIT, &d.invocation_id, &command())
            && private_prefix::owner(old, UNIT, &d.invocation_id, &command())
            && current["MainPID"] == old["MainPID"],
        "first root 233 status producer was replaced, restarted, or terminated"
    );
    validate_live(d, &current)?;
    Ok(current)
}
fn progress(o: &Value, invocation: &str) -> Result<Value> {
    let matches = o["diagnostic_replays"]
        .as_array()
        .context("first root 233 observer census absent")?
        .iter()
        .filter(|r| r["producer_unit"] == UNIT)
        .collect::<Vec<_>>();
    ensure!(
        matches.len() == 1,
        "first root 233 observer claim is absent or duplicated"
    );
    let r = matches[0];
    let row = &r["observation"];
    ensure!(
        r["status"] == "observed"
            && r["error"].is_null()
            && r["range"] == "233-233"
            && r["scratch_path"] == ROOT
            && r["expected_producer_invocation_id"] == invocation
            && row["invocation_binding_stable"] == true
            && row["useful_work"]["journal_invocation_id"] == invocation,
        "first root 233 observer does not describe the actual stable owner"
    );
    for key in [
        "controller_before",
        "controller_after",
        "producer_before",
        "producer_after",
    ] {
        ensure!(
            row[key]["unit"] == UNIT
                && row[key]["invocation_id"] == invocation
                && row[key]["restarts"] == 0
                && row[key]["active_state"] == "active"
                && row[key]["sub_state"] == "running",
            "first root 233 observer contains a changing owner"
        );
    }
    Ok(row["useful_work"].clone())
}
fn initial_progress(invocation: &str, seconds: u64) -> Result<Value> {
    let out = ProcessCommand::new("/usr/bin/journalctl")
        .args([
            &format!("_SYSTEMD_INVOCATION_ID={invocation}"),
            "--output=json",
            "--no-pager",
            "--lines=8192",
            &format!("--until=@{seconds}"),
        ])
        .output()?;
    ensure!(
        out.status.success() && out.stdout.len() <= 16 << 20,
        "first root 233 launch journal is unavailable or oversized"
    );
    let rows = out
        .stdout
        .split(|b| *b == b'\n')
        .filter(|b| !b.is_empty())
        .map(serde_json::from_slice::<Value>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(
        rows.len() < 8192,
        "first root 233 launch journal truncated; use the coordinated observation"
    );
    let mut last = None;
    for r in rows {
        ensure!(
            r["_SYSTEMD_INVOCATION_ID"] == invocation && r["_SYSTEMD_UNIT"] == UNIT,
            "first root 233 launch journal contains another owner"
        );
        let message = r["MESSAGE"]
            .as_str()
            .context("first root 233 launch message absent")?;
        if let Some((_, tail)) = message.split_once("progress slot ") {
            let (slot, end) = tail
                .split_once('/')
                .context("first root 233 malformed slot marker")?;
            let slot = slot.parse::<u64>()?;
            let n = end.bytes().take_while(u8::is_ascii_digit).count();
            let end = end[..n].parse::<u64>()?;
            ensure!(
                end == TERMINAL && (BOOTSTRAP + 1..=TERMINAL).contains(&slot),
                "first root 233 launch progress escaped its private prefix"
            );
            last = Some(json!({"slot":slot,"terminal_slot":end}));
        }
    }
    Ok(
        json!({"journal_invocation_id":invocation,"last":last,"counter_resets":0,"sufficient_for_rates":false,
        "launch_journal_sha256":hex_lower(&Sha256::digest(out.stdout))}),
    )
}
fn elapsed_at(seconds: u64, v: &Value) -> Result<u64> {
    let a = &v["clock_anchor"];
    private_prefix::elapsed(
        seconds,
        a["wall_millis"]
            .as_u64()
            .context("first root 233 wall anchor absent")?,
        a["monotonic_millis"]
            .as_u64()
            .context("first root 233 monotonic anchor absent")?,
        a["producer_start_monotonic_us"]
            .as_u64()
            .context("first root 233 original start anchor absent")?,
    )
}
fn accepted(p: &Model, f: &Value, o: &Value) -> Result<u64> {
    ensure!(
        p.schema == MODEL
            && matches!(p.mode.as_str(), "launch-event" | "observation")
            && !p.estimate_basis.trim().is_empty()
            && !p.estimate_evidence.is_empty()
            && o["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && f["schema"] == super::super::SCHEMA
            && f["first_epoch"] == 201
            && f["last_epoch"] == 300
            && f["inventory"]["anomalies"] == 0
            && f["observer_receipt"].as_str() == p.observer.path.to_str()
            && f["observer_sha256"] == p.observer.sha256
            && f["sampled_at_utc"] == o["recorded_at_utc"],
        "first root 233 status model or accepted sample differs"
    );
    for e in &p.estimate_evidence {
        native209::immutable_json(e)?;
    }
    utc_seconds(
        o["recorded_at_utc"]
            .as_str()
            .context("first root 233 observer UTC absent")?,
    )
}
fn reproduce(e: &Value, p: &Model, launch: &Value, seconds: u64) -> Result<EpochStatus> {
    ensure!(
        e["progress"]["journal_invocation_id"] == launch["evidence"]["units"][0]["invocation_id"]
            && e["clock_anchor"] == launch["clock_anchor"],
        "first root 233 frozen progress or clock belongs to another owner"
    );
    let status: EpochStatus = serde_json::from_value(e["status"].clone())?;
    let elapsed = elapsed_at(seconds, launch)?;
    let (phase, remaining) =
        private_prefix::estimate(&e["progress"], elapsed, &p.estimate, BOOTSTRAP, TERMINAL)?;
    ensure!(
        status.epoch == 233
            && status.sampled_at_utc == publication203::utc(seconds)?
            && status.elapsed_execution_millis == elapsed
            && status.phase == phase
            && status.estimated_remaining_millis == remaining
            && remaining > 0,
        "first root 233 frozen status does not reproduce its original clock and inclusive model"
    );
    validate_epoch_status(&status, 233)?;
    Ok(status)
}
fn frozen(r: &StatusPublicationReceipt) -> Result<DiagnosticClaim> {
    ensure!(
        r.epoch == 233 && r.pipeline_binding.is_none() && r.authenticated_readback,
        "first root 233 status receipt scope differs"
    );
    let e = bound_json(&binding(
        r.observer_receipt
            .to_str()
            .context("first root 233 frozen path is not UTF-8")?,
        &r.observer_receipt_sha256,
    ))?;
    ensure!(
        e["schema"] == OBSERVATION && e["status"] == json!(r.status),
        "first root 233 frozen observation differs"
    );
    let model_bound: BoundFile = serde_json::from_value(e["model"].clone())?;
    let p: Model = serde_json::from_value(native209::immutable_json(&model_bound)?)?;
    ensure!(
        p.estimate_receipt == r.observer_receipt
            && e["observer"] == private157::binding(&p.observer)
            && e["fleet"] == private157::binding(&p.fleet)
            && e["launch"] == private157::binding(&p.launch),
        "first root 233 frozen model substituted its evidence"
    );
    let (d, launch) = claim(&p.launch)?;
    let f = bound_json(&p.fleet)?;
    let o = bound_json(&p.observer)?;
    let observed = accepted(&p, &f, &o)?;
    registered(&d, &f)?;
    let captured = launch["recorded_unix_seconds"]
        .as_u64()
        .context("first root 233 launch clock absent")?;
    let seconds = if p.mode == "launch-event" {
        captured
    } else {
        observed
    };
    ensure!(
        seconds >= observed
            && seconds >= captured
            && private_prefix::owner(&f["unit_census"][UNIT], UNIT, &d.invocation_id, &command())
            && r.controller_invocation_id == d.invocation_id
            && r.producer_invocation_id == d.invocation_id,
        "first root 233 frozen owner or event clock differs"
    );
    reproduce(&e, &p, &launch, seconds)?;
    Ok(d)
}
pub(super) fn matches(
    r: &StatusPublicationReceipt,
    epoch: u64,
    _o: &Value,
    census: &BTreeMap<String, Value>,
) -> bool {
    epoch == 233
        && frozen(r).is_ok_and(|d| {
            census
                .get(UNIT)
                .is_some_and(|u| private_prefix::owner(u, UNIT, &d.invocation_id, &command()))
        })
}
pub(super) fn inactive_owner(r: &StatusPublicationReceipt) -> Result<Option<(String, String)>> {
    if r.epoch != 233 || r.pipeline_binding.is_some() {
        return Ok(None);
    }
    let bytes = read_stable_bounded(
        &r.observer_receipt,
        MAX_OBSERVER_RECEIPT_BYTES,
        "first root 233 status origin",
    )?;
    let e: Value = serde_json::from_slice(&bytes)?;
    if e["schema"] != OBSERVATION {
        return Ok(None);
    }
    let d = frozen(r)?;
    Ok(Some((UNIT.into(), d.invocation_id)))
}
pub(super) async fn run() -> Result<()> {
    let (bound, self_sha) = publication203::parsed_args("status-publish-first-root233")?;
    let p: Model = serde_json::from_value(native209::immutable_json(&bound)?)?;
    admission::output(
        &p.estimate_receipt,
        "estimate.json",
        "horizon-first-root233-status-",
    )?;
    let (d, launch) = claim(&p.launch)?;
    let f = bound_json(&p.fleet)?;
    let o = bound_json(&p.observer)?;
    let observed = accepted(&p, &f, &o)?;
    registered(&d, &f)?;
    let captured = launch["recorded_unix_seconds"]
        .as_u64()
        .context("first root 233 capture UTC absent")?;
    let seconds = if p.mode == "launch-event" {
        captured
    } else {
        observed
    };
    private_prefix::event_clock(
        seconds,
        observed,
        captured,
        now()?,
        p.mode == "launch-event",
    )?;
    let before = live(&d, &f)?;
    let evidence = if p.estimate_receipt.try_exists()? {
        let old = native209::immutable_json(&serde_json::from_value(private157::file_binding(
            &p.estimate_receipt,
        )?)?)?;
        ensure!(
            old["schema"] == OBSERVATION && old["model"] == private157::binding(&bound),
            "first root 233 status retry model changed"
        );
        old
    } else {
        let progress = if p.mode == "launch-event" {
            initial_progress(&d.invocation_id, seconds)?
        } else {
            progress(&o, &d.invocation_id)?
        };
        let elapsed = elapsed_at(seconds, &launch)?;
        let (phase, remaining) =
            private_prefix::estimate(&progress, elapsed, &p.estimate, BOOTSTRAP, TERMINAL)?;
        let size = private_prefix::private_jet(Path::new(ROOT), ARCHIVE, 1000)?;
        let status = EpochStatus {
            epoch: 233,
            jet_size_bytes: size,
            elapsed_execution_millis: elapsed,
            estimated_remaining_millis: remaining,
            sampled_at_utc: publication203::utc(seconds)?,
            phase,
        };
        let e = json!({"schema":OBSERVATION,"model":private157::binding(&bound),"helper_sha256":self_sha,
            "observer":private157::binding(&p.observer),"fleet":private157::binding(&p.fleet),
            "launch":private157::binding(&p.launch),"progress":progress,"status":status,"clock_anchor":launch["clock_anchor"],
            "estimate_basis":p.estimate_basis,"estimate_evidence":p.estimate_evidence,"resource_samples_taken":0,
            "archive_or_sidecar_mutation_authorized":false});
        private157::immutable_receipt(&p.estimate_receipt, &e)?;
        e
    };
    let status = reproduce(&evidence, &p, &launch, seconds)?;
    ensure!(
        before == live(&d, &f)?,
        "first root 233 owner changed before status publication"
    );
    preflight_status_receipt_write(&p.receipt_directory)?;
    let source: BoundFile = serde_json::from_value(private157::file_binding(&p.estimate_receipt)?)?;
    let r2 = r2_config_from_env()?;
    let s3 = s3_client(&r2);
    let (etag, previous) = publish_epoch_status(&s3, &r2, &status).await?;
    let receipt = StatusPublicationReceipt {
        schema: STATUS_RECEIPT_SCHEMA.into(),
        bucket: r2.bucket,
        epoch: 233,
        key: "epoch-233.epoch-status.json".into(),
        status,
        object_etag: etag,
        previous_object_etag: previous,
        observer_receipt: source.path,
        observer_receipt_sha256: source.sha256,
        controller_invocation_id: d.invocation_id.clone(),
        producer_invocation_id: d.invocation_id.clone(),
        authenticated_readback: true,
        verified_unix_seconds: now()?,
        pipeline_binding: None,
    };
    let path = status_receipt_path(&p.receipt_directory, &receipt.status);
    if path.try_exists()? {
        let old: StatusPublicationReceipt = serde_json::from_slice(&read_stable_bounded(
            &path,
            MAX_STATUS_BYTES,
            "first root 233 prior status receipt",
        )?)?;
        ensure!(
            old.status == receipt.status
                && old.object_etag == receipt.object_etag
                && old.observer_receipt_sha256 == receipt.observer_receipt_sha256
                && old.producer_invocation_id == receipt.producer_invocation_id
                && old.controller_invocation_id == receipt.controller_invocation_id
                && old.authenticated_readback,
            "first root 233 status retry conflicts with its owned publication"
        );
    } else {
        write_status_receipt(&p.receipt_directory, &receipt)?;
    }
    ensure!(
        before == live(&d, &f)?,
        "first root 233 owner changed during status publication"
    );
    println!("{}", path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn model() -> Model {
        let b = || binding("/sealed/example.json", &"a".repeat(64));
        Model {
            schema: MODEL.into(),
            mode: "launch-event".into(),
            observer: b(),
            fleet: b(),
            launch: b(),
            estimate: private_prefix::Estimate {
                initialization_allowance_millis: 600_000,
                fallback_slots_per_second: 2.0,
                downstream_allowance_millis: private_prefix::DOWNSTREAM
                    .iter()
                    .map(|s| (s.to_string(), 1000))
                    .collect(),
            },
            estimate_basis: "Explicit best guess including unresolved repair and suffix".into(),
            estimate_evidence: vec![b()],
            estimate_receipt: "/private/estimate.json".into(),
            receipt_directory: "/private/receipts".into(),
        }
    }
    #[test]
    fn frozen_payload_reproduces_original_start_and_keeps_delivery_after_terminal() {
        let anchor = json!({"wall_millis":1_000_400,"monotonic_millis":50_000,"producer_start_monotonic_us":40_000_000});
        let launch =
            json!({"clock_anchor":anchor,"evidence":{"units":[{"invocation_id":"c".repeat(32)}]}});
        let progress = json!({"journal_invocation_id":"c".repeat(32),"counter_resets":0,
            "sufficient_for_rates":false,"last":{"slot":TERMINAL}});
        let status = EpochStatus {
            epoch: 233,
            jet_size_bytes: 123,
            elapsed_execution_millis: 9600,
            estimated_remaining_millis: 12_000,
            sampled_at_utc: publication203::utc(1000).unwrap(),
            phase: "verification".into(),
        };
        let evidence = json!({"clock_anchor":anchor,"progress":progress,"status":status});
        reproduce(&evidence, &model(), &launch, 1000).unwrap();
        for (path, value) in [
            ("/status/elapsed_execution_millis", json!(0)),
            ("/status/estimated_remaining_millis", json!(0)),
            ("/status/phase", json!("replay")),
            (
                "/status/sampled_at_utc",
                json!(publication203::utc(999).unwrap()),
            ),
            ("/progress/journal_invocation_id", json!("d".repeat(32))),
            (
                "/clock_anchor/producer_start_monotonic_us",
                json!(50_000_000),
            ),
        ] {
            let mut bad = evidence.clone();
            *bad.pointer_mut(path).unwrap() = value;
            assert!(reproduce(&bad, &model(), &launch, 1000).is_err(), "{path}");
        }
    }
    #[test]
    fn coordinated_progress_cannot_hide_a_duplicate_or_changed_owner() {
        let invocation = "a".repeat(32);
        let owner = json!({"unit":UNIT,"invocation_id":invocation,"restarts":0,"active_state":"active","sub_state":"running"});
        let row = json!({"producer_unit":UNIT,"status":"observed","error":null,"range":"233-233","scratch_path":ROOT,
            "expected_producer_invocation_id":invocation,"observation":{"invocation_binding_stable":true,
                "controller_before":owner,"controller_after":owner,"producer_before":owner,"producer_after":owner,
                "useful_work":{"journal_invocation_id":invocation,"counter_resets":0,"sufficient_for_rates":false,"last":null}}});
        let o = json!({"diagnostic_replays":[row]});
        progress(&o, &invocation).unwrap();
        let mut duplicate = o.clone();
        duplicate["diagnostic_replays"]
            .as_array_mut()
            .unwrap()
            .push(row);
        assert!(progress(&duplicate, &invocation).is_err());
        let mut changed = o;
        changed["diagnostic_replays"][0]["observation"]["producer_after"]["invocation_id"] =
            json!("b".repeat(32));
        assert!(progress(&changed, &invocation).is_err());
    }
}
