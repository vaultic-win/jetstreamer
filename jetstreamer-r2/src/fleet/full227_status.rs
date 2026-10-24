//! Status metadata for the real full 227 diagnostic; never a pipeline impersonation.
use super::singleton227 as c;
use super::*;
mod jet;
const PLAN_SCHEMA: &str = "jetstreamer-full227-status-plan-v1";
const ESTIMATE_SCHEMA: &str = "jetstreamer-full227-status-observation-v1";
const TERMINAL: u64 = 98_495_999;
const FIRST: u64 = 98_064_000;
const WARMUP_FIRST: u64 = 98_063_465;
const STAGES: [&str; 7] = [
    "archive_close",
    "boundary",
    "full_verification",
    "plugin_verification",
    "readback",
    "sidecar_commit",
    "upload",
];
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Model {
    schema: String,
    mode: String,
    observer: BoundFile,
    fleet: BoundFile,
    launch: BoundFile,
    receipt_directory: PathBuf,
    estimate_receipt: PathBuf,
    initialization_allowance_millis: u64,
    fallback_slots_per_second: f64,
    downstream_allowance_millis: BTreeMap<String, u64>,
    estimate_basis: String,
    estimate_evidence: Vec<BoundFile>,
}
fn claim(binding: &BoundFile) -> Result<(DiagnosticClaim, Value)> {
    let launch = bound_json(binding)?;
    let rows = launch["evidence"]["units"]
        .as_array()
        .context("full 227 launch owner census")?;
    ensure!(
        launch["launched"] == true
            && rows.len() == 1
            && rows[0]["unit"] == c::UNIT
            && rows[0]["restarts"] == 0,
        "full 227 exact launch owner absent"
    );
    let iid = rows[0]["invocation_id"]
        .as_str()
        .context("full 227 launch IID")?;
    ensure!(
        iid.len() == 32
            && iid
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "full 227 launch IID invalid"
    );
    let d = DiagnosticClaim {
        epoch: 227,
        unit: c::UNIT.into(),
        invocation_id: iid.into(),
        scratch_path: c::ROOT.into(),
        launch_receipt: BoundFile {
            path: binding.path.clone(),
            sha256: binding.sha256.clone(),
        },
    };
    c::bindings(&d, &launch)?;
    let guard = bound_json(&serde_json::from_value(launch["guard"].clone())?)?;
    let plan_binding: BoundFile = serde_json::from_value(launch["guard_plan"].clone())?;
    let plan = bound_json(&plan_binding)?;
    ensure!(
        c::guard_matches(&d, &launch, &plan)
            && plan["unit"] == c::UNIT
            && plan["invocation_id"] == iid
            && guard["plan_sha256"] == plan_binding.sha256
            && guard["guard_sha256"] == c::SINGLETON_GUARD_SHA
            && guard["producer_invocation_id"] == iid
            && guard["producer"]["pid"] == rows[0]["main_pid"]
            && guard["producer_stop_enabled"] == true
            && guard["workers"].as_array().is_some_and(|v| v.len() == 1)
            && guard["workers"][0][1]
                .as_u64()
                .is_some_and(|n| n > 0 && n < 3500000)
            && [
                "trip_reason",
                "worker_observation_error",
                "root_physical_observation_error",
                "canary_target_error"
            ]
            .iter()
            .all(|k| guard.get(*k).is_some_and(Value::is_null)),
        "full 227 first actual guard differs"
    );
    let completion = &launch["guard_manager"]["manager_completion"];
    ensure!(
        completion["_PID"] == "1"
            && completion["UNIT"] == "horizon-singleton227-protective-v1.service"
            && completion["INVOCATION_ID"] == guard["guard_invocation_id"]
            && completion["MESSAGE"]
                == "horizon-singleton227-protective-v1.service: Deactivated successfully.",
        "full 227 first guard lacks exact PID1 completion"
    );
    Ok((d, launch))
}
fn registered(d: &DiagnosticClaim, f: &Value) -> Result<()> {
    let p: Plan = serde_json::from_value(bound_json(&BoundFile {
        path: f["plan"].as_str().context("full 227 accepted plan")?.into(),
        sha256: f["plan_sha256"]
            .as_str()
            .context("full 227 accepted plan SHA")?
            .into(),
    })?)?;
    let owners = p
        .diagnostics
        .iter()
        .filter(|v| v.unit == c::UNIT)
        .collect::<Vec<_>>();
    ensure!(
        owners.len() == 1
            && owners[0].epoch == 227
            && owners[0].invocation_id == d.invocation_id
            && owners[0].scratch_path == d.scratch_path
            && owners[0].launch_receipt == d.launch_receipt,
        "full 227 launch is not its accepted diagnostic owner"
    );
    Ok(())
}
fn owner(u: &Value, iid: &str) -> bool {
    u["Id"] == c::UNIT
        && u["LoadState"] == "loaded"
        && u["InvocationID"] == iid
        && u["NRestarts"] == "0"
        && u["ActiveState"] == "active"
        && u["SubState"] == "running"
        && u["MainPID"]
            .as_str()
            .and_then(|n| n.parse::<u64>().ok())
            .is_some_and(|n| n > 0)
        && c::same_command(&u["ExecStart"], &Value::Null)
}
fn live(d: &DiagnosticClaim, f: &Value) -> Result<Value> {
    let u = unit(c::UNIT)?;
    let old = &f["unit_census"][c::UNIT];
    ensure!(
        owner(&u, &d.invocation_id)
            && owner(old, &d.invocation_id)
            && u["MainPID"] == old["MainPID"],
        "full 227 live identity changed"
    );
    Ok(u)
}
fn observed<'a>(o: &'a Value, iid: &str) -> Result<&'a Value> {
    let rows = o["diagnostic_replays"]
        .as_array()
        .context("full 227 diagnostic observation census")?
        .iter()
        .filter(|r| r["producer_unit"] == c::UNIT)
        .collect::<Vec<_>>();
    ensure!(rows.len() == 1, "full 227 observation missing/duplicate");
    let r = rows[0];
    let v = &r["observation"];
    ensure!(
        r["status"] == "observed"
            && r["error"].is_null()
            && r["range"] == "227-227"
            && r["expected_producer_invocation_id"] == iid
            && v["invocation_binding_stable"] == true
            && v["useful_work"]["journal_invocation_id"] == iid,
        "full 227 observation differs"
    );
    for k in [
        "controller_before",
        "controller_after",
        "producer_before",
        "producer_after",
    ] {
        ensure!(
            v[k]["invocation_id"] == iid
                && v[k]["restarts"] == 0
                && v[k]["active_state"] == "active"
                && v[k]["sub_state"] == "running",
            "full 227 observation is not stable live work"
        );
    }
    Ok(&v["useful_work"])
}
fn elapsed(sample: u64, launch: &Value) -> Result<u64> {
    let out = ProcessCommand::new("/usr/bin/systemctl")
        .args([
            "show",
            c::UNIT,
            "--property=ExecMainStartTimestampMonotonic",
            "--value",
        ])
        .output()?;
    ensure!(
        out.status.success(),
        "full 227 invocation start unavailable"
    );
    let start_micros = std::str::from_utf8(&out.stdout)?.trim().parse::<u64>()?;
    ensure!(
        launch["sandbox"]["ExecMainStartTimestampMonotonic"]
            .as_str()
            .and_then(|n| n.parse::<u64>().ok())
            == Some(start_micros),
        "full 227 manager start differs from captured launch"
    );
    let start = start_micros / 1000;
    ensure!(start > 0, "full 227 invocation start absent");
    let mut clock = std::mem::MaybeUninit::<libc::timespec>::uninit();
    ensure!(
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, clock.as_mut_ptr()) } == 0,
        "full 227 monotonic clock unavailable"
    );
    let clock = unsafe { clock.assume_init() };
    let now = u64::try_from(clock.tv_sec)?
        .checked_mul(1000)
        .and_then(|n| n.checked_add(u64::try_from(clock.tv_nsec).ok()? / 1_000_000))
        .context("full 227 clock overflow")?;
    let age = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .checked_sub(u128::from(sample) * 1000)
        .context("full 227 future sample")?;
    now.checked_sub(start)
        .and_then(|n| n.checked_sub(u64::try_from(age).ok()?))
        .context("full 227 sample predates invocation")
}
fn decimal(message: &str, key: &str) -> Option<u64> {
    let tail = message.split_once(key)?.1;
    let n = tail.bytes().take_while(u8::is_ascii_digit).count();
    tail[..n].parse().ok()
}
fn initial_progress(iid: &str, sample: u64) -> Result<Value> {
    // One launch-lifecycle journal read, never another replay/resource sample.
    let out = ProcessCommand::new("/usr/bin/journalctl")
        .args([
            &format!("_SYSTEMD_INVOCATION_ID={iid}"),
            "--output=json",
            "--no-pager",
            "--lines=8192",
            &format!("--until=@{sample}"),
        ])
        .output()?;
    ensure!(
        out.status.success() && out.stdout.len() <= 16 << 20,
        "full 227 launch journal unavailable/oversized"
    );
    let rows = out
        .stdout
        .split(|b| *b == b'\n')
        .filter(|b| !b.is_empty())
        .map(serde_json::from_slice::<Value>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(
        rows.len() < 8192,
        "full 227 launch journal truncated; use the coordinated observation"
    );
    let mut last = None;
    let mut markers = Vec::new();
    for row in rows {
        ensure!(
            row["_SYSTEMD_INVOCATION_ID"] == iid && row["_SYSTEMD_UNIT"] == c::UNIT,
            "full 227 foreign launch journal"
        );
        let msg = row["MESSAGE"]
            .as_str()
            .context("full 227 launch journal message")?;
        if let Some(tail) = msg.split_once("progress slot ").map(|p| p.1) {
            let slot = tail
                .split_once('/')
                .context("full 227 malformed progress")?
                .0
                .parse::<u64>()?;
            let terminal = decimal(tail, "/").context("full 227 progress terminal")?;
            ensure!(
                terminal == TERMINAL && (FIRST..=TERMINAL).contains(&slot),
                "full 227 foreign progress interval"
            );
            last = Some(
                json!({"slot":slot,"terminal_slot":terminal,"transactions":decimal(msg,"txs=").context("full 227 transaction counter")?,"account_updates":decimal(msg,"accounts=").context("full 227 account counter")?}),
            );
            markers.push(row);
        }
    }
    Ok(
        json!({"journal_invocation_id":iid,"sufficient_for_rates":false,"last":last,"counter_resets":0,"launch_journal_markers":markers,"launch_journal_sha256":hex_lower(&Sha256::digest(&out.stdout))}),
    )
}
fn validate_progress_counters(progress: &Value) -> Result<()> {
    let resets = progress["counter_resets"]
        .as_u64()
        .context("full 227 reset count missing")?;
    if resets == 0 {
        return Ok(());
    }
    // The observer adds `current` after a reset instead of current-previous.
    // Its accumulated slot delta therefore equals last-first iff slots never
    // reset. Transaction/account resets need not discard that independent rate.
    let first = &progress["first"];
    let last = &progress["last"];
    let a = first["slot"]
        .as_u64()
        .context("full 227 first slot missing")?;
    let b = last["slot"]
        .as_u64()
        .context("full 227 last slot missing")?;
    let start = first["realtime_microseconds"]
        .as_u64()
        .context("full 227 first clock missing")?;
    let end = last["realtime_microseconds"]
        .as_u64()
        .context("full 227 last clock missing")?;
    let duration = end
        .checked_sub(start)
        .filter(|n| *n > 0)
        .context("full 227 invalid progress clock")?;
    let delta = b
        .checked_sub(a)
        .context("full 227 slot counter moved backwards")?;
    let rate = delta as f64 / (duration as f64 / 1_000_000.0);
    let reported = progress["slots_per_second"]
        .as_f64()
        .context("full 227 slot rate missing")?;
    ensure!(
        progress["sufficient_for_rates"] == true
            && progress["matching_markers"]
                .as_u64()
                .is_some_and(|n| n >= 2)
            && (FIRST..=TERMINAL).contains(&a)
            && (FIRST..=TERMINAL).contains(&b)
            && first["terminal_slot"] == TERMINAL
            && last["terminal_slot"] == TERMINAL
            && progress["slot_delta"] == delta
            && rate.is_finite()
            && rate > 0.0
            && reported.is_finite()
            && (reported - rate).abs() <= (rate * 1e-9).max(1e-12),
        "full 227 accounting resets lack an independently monotonic slot window"
    );
    Ok(())
}
fn estimate(progress: &Value, elapsed: u64, p: &Model) -> Result<(String, u64)> {
    ensure!(
        p.initialization_allowance_millis > 0
            && p.initialization_allowance_millis <= 86_400_000
            && p.fallback_slots_per_second.is_finite()
            && p.fallback_slots_per_second > 0.0
            && p.downstream_allowance_millis
                .keys()
                .map(String::as_str)
                .eq(STAGES)
            && p.downstream_allowance_millis
                .values()
                .all(|n| *n > 0 && *n <= 30 * 86_400_000),
        "full 227 complete inclusive model required"
    );
    let downstream = p
        .downstream_allowance_millis
        .values()
        .try_fold(0u64, |a, b| {
            a.checked_add(*b).context("full 227 downstream overflow")
        })?;
    validate_progress_counters(progress)?;
    let slot = progress["last"]["slot"].as_u64();
    let replay = slot.is_some_and(|n| n >= FIRST);
    let observed_slot = slot.unwrap_or(FIRST - 1);
    ensure!(
        (WARMUP_FIRST..=TERMINAL).contains(&observed_slot),
        "full 227 progress outside exact epoch"
    );
    let current = observed_slot.max(FIRST - 1);
    if current == TERMINAL {
        return Ok(("verification".into(), downstream));
    }
    let rate = if replay && progress["sufficient_for_rates"] == true {
        let r = progress["slots_per_second"]
            .as_f64()
            .context("full 227 rate missing")?;
        ensure!(r.is_finite() && r > 0.0, "full 227 invalid measured rate");
        r
    } else {
        p.fallback_slots_per_second
    };
    let replay_millis = ((TERMINAL - current) as f64 * 1000.0 / rate).ceil();
    ensure!(
        replay_millis.is_finite() && replay_millis >= 0.0 && replay_millis < u64::MAX as f64,
        "full 227 ETA overflow"
    );
    let initialization = if replay {
        0
    } else if elapsed < p.initialization_allowance_millis {
        p.initialization_allowance_millis - elapsed
    } else {
        elapsed
            .checked_div(2)
            .and_then(|n| n.checked_add(p.initialization_allowance_millis / 2))
            .context("full 227 overdue initialization overflow")?
    };
    let remaining = (replay_millis as u64)
        .checked_add(downstream)
        .and_then(|n| n.checked_add(initialization))
        .context("full 227 total ETA overflow")?;
    Ok((
        if replay { "replay" } else { "verification" }.into(),
        remaining,
    ))
}
fn frozen(receipt: &StatusPublicationReceipt) -> Result<(DiagnosticClaim, Value)> {
    ensure!(
        receipt.epoch == 227
            && receipt.pipeline_binding.is_none()
            && matches!(receipt.status.phase.as_str(), "verification" | "replay"),
        "not a full 227 status receipt"
    );
    let evidence = bound_json(&BoundFile {
        path: receipt.observer_receipt.clone(),
        sha256: receipt.observer_receipt_sha256.clone(),
    })?;
    ensure!(
        evidence["schema"] == ESTIMATE_SCHEMA && evidence["status"] == json!(receipt.status),
        "full 227 frozen observation differs"
    );
    let (d, _) = claim(&serde_json::from_value(evidence["launch"].clone())?)?;
    let p: Model = serde_json::from_value(bound_json(&serde_json::from_value(
        evidence["plan"].clone(),
    )?)?)?;
    ensure!(
        p.schema == PLAN_SCHEMA
            && p.estimate_receipt == receipt.observer_receipt
            && private157::binding(&p.launch) == evidence["launch"]
            && private157::binding(&p.observer) == evidence["observer"]
            && private157::binding(&p.fleet) == evidence["fleet"],
        "full 227 frozen model bindings differ"
    );
    let observer = bound_json(&p.observer)?;
    let f = bound_json(&p.fleet)?;
    registered(&d, &f)?;
    ensure!(
        owner(&f["unit_census"][c::UNIT], &d.invocation_id)
            && observer["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && f["observer_sha256"] == p.observer.sha256,
        "full 227 frozen observation lacks original owner"
    );
    let expected_clock = if p.mode == "launch-event" {
        let launch = bound_json(&p.launch)?;
        publication203::utc(
            launch["recorded_unix_seconds"]
                .as_u64()
                .context("full 227 frozen launch clock")?,
        )?
    } else {
        observer["recorded_at_utc"]
            .as_str()
            .context("full 227 frozen observer clock")?
            .into()
    };
    let (phase, remaining) = estimate(
        &evidence["progress"],
        receipt.status.elapsed_execution_millis,
        &p,
    )?;
    ensure!(
        receipt.status.sampled_at_utc == expected_clock
            && receipt.status.phase == phase
            && receipt.status.estimated_remaining_millis == remaining,
        "full 227 frozen status does not reproduce its model"
    );
    ensure!(
        receipt.controller_invocation_id == d.invocation_id
            && receipt.producer_invocation_id == d.invocation_id,
        "full 227 receipt owner differs"
    );
    Ok((d, evidence))
}
pub(super) fn matches(
    receipt: &StatusPublicationReceipt,
    epoch: u64,
    _observer: &Value,
    census: &BTreeMap<String, Value>,
) -> bool {
    epoch == 227
        && frozen(receipt).is_ok_and(|(d, _)| {
            census
                .get(c::UNIT)
                .is_some_and(|u| owner(u, &d.invocation_id))
        })
}
pub(super) fn inactive_owner(
    receipt: &StatusPublicationReceipt,
) -> Result<Option<(String, String)>> {
    if receipt.epoch != 227
        || receipt.pipeline_binding.is_some()
        || !matches!(receipt.status.phase.as_str(), "verification" | "replay")
    {
        return Ok(None);
    }
    let bytes = read_stable_bounded(
        &receipt.observer_receipt,
        MAX_OBSERVER_RECEIPT_BYTES,
        "full 227 status origin",
    )?;
    let value: Value = serde_json::from_slice(&bytes)?;
    if value["schema"] != ESTIMATE_SCHEMA {
        return Ok(None);
    }
    let (d, _) = frozen(receipt)?;
    Ok(Some((c::UNIT.into(), d.invocation_id)))
}
pub(super) async fn run() -> Result<()> {
    let args = env::args().collect::<Vec<_>>();
    ensure!(
        (args.len() == 7 || (args.len() == 8 && args[7] == "--check-only"))
            && args[3] == "--plan-sha256"
            && args[5] == "--self-sha256"
            && unsafe { libc::geteuid() } == 0,
        "status-publish-full227 PLAN --plan-sha256 SHA --self-sha256 SHA [--check-only]"
    );
    let own = fs::symlink_metadata(fs::read_link("/proc/self/exe")?)?;
    ensure!(
        own.uid() == 0
            && own.nlink() == 1
            && own.mode() & 0o222 == 0
            && hex_lower(&Sha256::digest(fs::read("/proc/self/exe")?)) == args[6],
        "full 227 status helper unsealed"
    );
    let binding = BoundFile {
        path: args[2].clone().into(),
        sha256: args[4].clone(),
    };
    let p: Model = serde_json::from_value(bound_json(&binding)?)?;
    ensure!(
        p.schema == PLAN_SCHEMA
            && matches!(p.mode.as_str(), "launch-event" | "observation")
            && !p.estimate_basis.trim().is_empty()
            && !p.estimate_evidence.is_empty(),
        "full 227 estimate scope/evidence absent"
    );
    for e in &p.estimate_evidence {
        bound_json(e)?;
    }
    let (d, launch) = claim(&p.launch)?;
    let f = bound_json(&p.fleet)?;
    let o = bound_json(&p.observer)?;
    registered(&d, &f)?;
    let observer_time = o["recorded_at_utc"]
        .as_str()
        .context("full 227 observer UTC")?;
    let observed_seconds = utc_seconds(observer_time)?;
    ensure!(
        o["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && f["schema"] == SCHEMA
            && f["first_epoch"] == 201
            && f["last_epoch"] == 300
            && f["inventory"]["anomalies"] == 0
            && f["observer_receipt"].as_str() == p.observer.path.to_str()
            && f["observer_sha256"] == p.observer.sha256
            && f["sampled_at_utc"] == observer_time,
        "full 227 unaccepted observer/fleet"
    );
    let seconds = if p.mode == "launch-event" {
        launch["recorded_unix_seconds"]
            .as_u64()
            .context("full 227 launch event clock")?
    } else {
        observed_seconds
    };
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    ensure!(
        seconds >= observed_seconds
            && seconds <= now
            && now - seconds <= 1800
            && (p.mode != "launch-event"
                || (now - seconds <= 300 && seconds - observed_seconds <= 1800)),
        "full 227 stale/future observation event"
    );
    let first = live(&d, &f)?;
    let evidence = if p.estimate_receipt.try_exists()? {
        let old: Value = serde_json::from_slice(&read_stable_bounded(
            &p.estimate_receipt,
            MAX_OBSERVER_RECEIPT_BYTES,
            "full 227 frozen estimate",
        )?)?;
        ensure!(
            old["schema"] == ESTIMATE_SCHEMA
                && old["plan_sha256"] == binding.sha256
                && old["launch"] == private157::binding(&p.launch)
                && old["observer"] == private157::binding(&p.observer)
                && old["fleet"] == private157::binding(&p.fleet),
            "full 227 retry estimate differs"
        );
        old
    } else {
        let progress = if p.mode == "launch-event" {
            initial_progress(&d.invocation_id, seconds)?
        } else {
            observed(&o, &d.invocation_id)?.clone()
        };
        let elapsed = elapsed(seconds, &launch)?;
        let (phase, remaining) = estimate(&progress, elapsed, &p)?;
        let measurement = jet::measure(
            Path::new(c::ROOT),
            launch["evidence"]["units"][0]["main_pid"]
                .as_u64()
                .context("full 227 original PID")?,
            c::FINGERPRINT,
            1000,
        )?;
        let status = EpochStatus {
            epoch: 227,
            jet_size_bytes: measurement.jet_size_bytes,
            elapsed_execution_millis: elapsed,
            estimated_remaining_millis: remaining,
            sampled_at_utc: publication203::utc(seconds)?,
            phase,
        };
        let v = json!({"schema":ESTIMATE_SCHEMA,"plan":private157::binding(&binding),"plan_sha256":binding.sha256,"launch":private157::binding(&p.launch),"observer":private157::binding(&p.observer),"fleet":private157::binding(&p.fleet),"mode":p.mode,"progress":progress,"status":status,"jet_measurement":measurement,"producer_start_monotonic_microseconds":launch["sandbox"]["ExecMainStartTimestampMonotonic"],"estimate_basis":p.estimate_basis,"estimate_evidence":p.estimate_evidence,"downstream_allowance_millis":p.downstream_allowance_millis,"initialization_allowance_millis":p.initialization_allowance_millis,"fallback_slots_per_second":p.fallback_slots_per_second,"resource_samples_taken":0,"archive_or_sidecar_mutation_authorized":false});
        if args.len() == 7 {
            validate_output_destination(&p.estimate_receipt)?;
            private157::immutable_receipt(&p.estimate_receipt, &v)?;
        }
        v
    };
    let status: EpochStatus = serde_json::from_value(evidence["status"].clone())?;
    validate_epoch_status(&status, 227)?;
    let (expected_phase, expected_remaining) =
        estimate(&evidence["progress"], status.elapsed_execution_millis, &p)?;
    ensure!(
        status.sampled_at_utc == publication203::utc(seconds)?
            && status.estimated_remaining_millis > 0
            && status.phase == expected_phase
            && status.estimated_remaining_millis == expected_remaining
            && matches!(status.phase.as_str(), "verification" | "replay"),
        "full 227 frozen payload differs"
    );
    if args.len() == 8 {
        println!("{evidence}");
        return Ok(());
    }
    ensure!(
        first == live(&d, &f)?,
        "full 227 owner changed before status publish"
    );
    preflight_status_receipt_write(&p.receipt_directory)?;
    let source: BoundFile = serde_json::from_value(private157::file_binding(&p.estimate_receipt)?)?;
    let r2 = r2_config_from_env()?;
    let s3 = s3_client(&r2);
    let (etag, previous) = publish_epoch_status(&s3, &r2, &status).await?;
    let receipt = StatusPublicationReceipt {
        schema: STATUS_RECEIPT_SCHEMA.into(),
        bucket: r2.bucket,
        epoch: 227,
        key: "epoch-227.epoch-status.json".into(),
        status,
        object_etag: etag,
        previous_object_etag: previous,
        observer_receipt: source.path,
        observer_receipt_sha256: source.sha256,
        controller_invocation_id: d.invocation_id.clone(),
        producer_invocation_id: d.invocation_id.clone(),
        authenticated_readback: true,
        verified_unix_seconds: now,
        pipeline_binding: None,
    };
    let path = status_receipt_path(&p.receipt_directory, &receipt.status);
    if path.try_exists()? {
        let old: StatusPublicationReceipt = serde_json::from_slice(&read_stable_bounded(
            &path,
            MAX_STATUS_BYTES,
            "full 227 status publication",
        )?)?;
        ensure!(
            old.status == receipt.status
                && old.object_etag == receipt.object_etag
                && old.observer_receipt_sha256 == receipt.observer_receipt_sha256
                && old.producer_invocation_id == receipt.producer_invocation_id
                && old.controller_invocation_id == receipt.controller_invocation_id
                && old.authenticated_readback,
            "full 227 prior status receipt differs"
        );
    } else {
        write_status_receipt(&p.receipt_directory, &receipt)?;
    }
    ensure!(
        first == live(&d, &f)?,
        "full 227 owner changed during status publish"
    );
    println!("{}", path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn model() -> Model {
        let b = || BoundFile {
            path: "/sealed/evidence.json".into(),
            sha256: "a".repeat(64),
        };
        Model {
            schema: PLAN_SCHEMA.into(),
            mode: "observation".into(),
            observer: b(),
            fleet: b(),
            launch: b(),
            receipt_directory: "/private/receipts".into(),
            estimate_receipt: "/private/estimate.json".into(),
            initialization_allowance_millis: 600_000,
            fallback_slots_per_second: 2.0,
            downstream_allowance_millis: STAGES.iter().map(|s| (s.to_string(), 1000)).collect(),
            estimate_basis: "bound initial best guess".into(),
            estimate_evidence: vec![b()],
        }
    }
    #[test]
    fn initialization_is_verification_and_overdue_estimates_expand() {
        let p = model();
        let progress = json!({"counter_resets":0,"last":null,"sufficient_for_rates":false});
        let (phase, remaining) = estimate(&progress, 100_000, &p).unwrap();
        assert_eq!(phase, "verification");
        assert_eq!(remaining, 500_000 + 216_000_000 + 7000);
        assert!(
            estimate(&progress, 1_200_000, &p).unwrap().1
                > estimate(&progress, 600_000, &p).unwrap().1
        );
    }
    #[test]
    fn pre_epoch_warmup_keeps_the_full_epoch_estimate_and_verification_phase() {
        let p = model();
        for slot in [WARMUP_FIRST, FIRST - 1] {
            let progress = json!({"counter_resets":0,"last":{"slot":slot},
                "sufficient_for_rates":true,"slots_per_second":100000.0});
            assert_eq!(
                estimate(&progress, 100_000, &p).unwrap(),
                ("verification".into(), 500_000 + 216_000_000 + 7000)
            );
        }
        let foreign = json!({"counter_resets":0,"last":{"slot":WARMUP_FIRST-1},
            "sufficient_for_rates":false});
        assert!(estimate(&foreign, 0, &p).is_err());
    }
    #[test]
    fn accounting_resets_retain_only_an_independently_proven_slot_rate() {
        let rate = 1253.0 / 624.033594;
        let progress = json!({"counter_resets":2,"sufficient_for_rates":true,"matching_markers":209,
            "first":{"slot":FIRST+41,"terminal_slot":TERMINAL,"realtime_microseconds":1000000},
            "last":{"slot":FIRST+1294,"terminal_slot":TERMINAL,"realtime_microseconds":625033594},
            "slot_delta":1253,"slots_per_second":rate});
        assert_eq!(
            estimate(&progress, 1_000_000, &model()).unwrap().0,
            "replay"
        );
        for (field, value) in [
            ("slot_delta", json!(1254)),
            ("slots_per_second", json!(rate * 2.0)),
            ("sufficient_for_rates", json!(false)),
            ("matching_markers", json!(1)),
        ] {
            let mut bad = progress.clone();
            bad[field] = value;
            assert!(estimate(&bad, 1_000_000, &model()).is_err(), "{field}");
        }
        let mut bad = progress.clone();
        bad["last"]["slot"] = json!(FIRST);
        assert!(estimate(&bad, 1_000_000, &model()).is_err());
        let mut bad = progress;
        bad["first"]["terminal_slot"] = json!(TERMINAL + 1);
        assert!(estimate(&bad, 1_000_000, &model()).is_err());
    }
    #[test]
    fn real_progress_switches_phase_and_includes_full_tail_and_delivery() {
        let p = model();
        let progress = json!({"counter_resets":0,"last":{"slot":TERMINAL-100,"transactions":10},"sufficient_for_rates":true,"slots_per_second":4.0});
        assert_eq!(
            estimate(&progress, 100_000, &p).unwrap(),
            ("replay".into(), 32_000)
        );
        let mut terminal = progress.clone();
        terminal["last"]["slot"] = json!(TERMINAL);
        assert_eq!(
            estimate(&terminal, 100_000, &p).unwrap(),
            ("verification".into(), 7000)
        );
        let mut bad = progress.clone();
        bad["slots_per_second"] = json!(0);
        assert!(estimate(&bad, 100_000, &p).is_err());
        bad = progress.clone();
        bad["counter_resets"] = json!(1);
        assert!(estimate(&bad, 100_000, &p).is_err());
        bad = progress;
        bad["last"]["slot"] = json!(TERMINAL + 1);
        assert!(estimate(&bad, 100_000, &p).is_err());
    }
    #[test]
    fn every_downstream_stage_and_finite_fallback_are_mandatory() {
        let progress = json!({"counter_resets":0,"last":null,"sufficient_for_rates":false});
        let mut p = model();
        p.downstream_allowance_millis.remove("readback");
        assert!(estimate(&progress, 0, &p).is_err());
        p = model();
        p.fallback_slots_per_second = f64::NAN;
        assert!(estimate(&progress, 0, &p).is_err());
        p = model();
        p.downstream_allowance_millis
            .insert("sidecar_commit".into(), 0);
        assert!(estimate(&progress, 0, &p).is_err());
    }
    #[test]
    fn owner_rejects_native_profile_restarts_and_replacement() {
        let iid = "a".repeat(32);
        let u = json!({"Id":c::UNIT,"LoadState":"loaded","InvocationID":iid,"NRestarts":"0","ActiveState":"active","SubState":"running","MainPID":"42","ExecStart":format!("{} ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }}",c::expected_command())});
        assert!(owner(&u, &iid));
        for (key, value) in [
            ("Id", json!(singleton227_admission::NATIVE_UNIT)),
            ("InvocationID", json!("b".repeat(32))),
            ("NRestarts", json!("1")),
            ("MainPID", json!("0")),
            ("ActiveState", json!("inactive")),
            ("ExecStart", json!("historical-worker")),
        ] {
            let mut bad = u.clone();
            bad[key] = value;
            assert!(!owner(&bad, &iid), "{key}");
        }
    }
}
