//! Mutable dashboard status for the exact bounded canary; never archive readiness.
use super::canary227 as c;
use super::*;
const PLAN_SCHEMA: &str = "jetstreamer-canary227-status-plan-v1";
const ESTIMATE_SCHEMA: &str = "jetstreamer-canary227-status-observation-v1";
const TERMINAL: u64 = c::TERMINAL;
const TARGET: u64 = c::TARGET;
const FIRST: u64 = c::BOOTSTRAP + 1;

const STAGES: [&str; 10] = [
    "archive_close",
    "boundary",
    "canary_qualification",
    "full_epoch_replay",
    "full_verification",
    "plugin_verification",
    "readback",
    "runtime_qualification",
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
    // Mandatory best guesses include the full epoch rerun and unresolved runtime/canary qualification.
    // Target completion never removes any of these allowances.
    downstream_allowance_millis: BTreeMap<String, u64>,
    estimate_basis: String,
    estimate_evidence: Vec<BoundFile>,
}
/// Direct private output of this bounded runner, never the canonical archive key.
fn jet_measurement(root: &Path, uid: u32) -> Result<Value> {
    let mut dirs = Vec::new();
    for path in [root.to_owned(), root.join("output")] {
        let m = fs::symlink_metadata(&path)?;
        ensure!(
            path.canonicalize()? == path && m.is_dir() && m.uid() == uid && m.mode() & 0o077 == 0,
            "canary 227 output directory is not canonical/owner-private"
        );
        dirs.push((path, m.dev(), m.ino()));
    }
    let path = root.join("output/epoch-227-canary.jet");
    let (bytes, identity) = match fs::symlink_metadata(&path) {
        Ok(m) => {
            ensure!(
                m.is_file() && m.uid() == uid && m.nlink() == 1,
                "canary 227 unsafe partial archive"
            );
            (m.len(), Some((m.dev(), m.ino())))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (0, None),
        Err(e) => return Err(e.into()),
    };
    if let Some((dev, ino)) = identity {
        let after = fs::symlink_metadata(&path)?;
        ensure!(
            after.is_file()
                && after.uid() == uid
                && after.nlink() == 1
                && after.dev() == dev
                && after.ino() == ino
                && after.len() >= bytes,
            "canary 227 partial archive replaced or shrank"
        );
    }
    for (path, dev, ino) in dirs {
        let m = fs::symlink_metadata(&path)?;
        ensure!(
            path.canonicalize()? == path
                && m.is_dir()
                && m.uid() == uid
                && m.mode() & 0o077 == 0
                && m.dev() == dev
                && m.ino() == ino,
            "canary 227 output directory changed"
        );
    }
    Ok(
        json!({"jet_size_bytes":bytes,"path":path,"source":"private-bounded-canary-output","canonical_archive":false}),
    )
}
fn valid_progress_terminal(v: &Value) -> bool {
    v["slot"].as_u64().is_some_and(|slot| {
        (FIRST..=TARGET).contains(&slot)
            && (v["terminal_slot"] == TERMINAL
                || (slot <= 98_063_999 && v["terminal_slot"] == 98_063_999))
    })
}

fn claim(binding: &BoundFile) -> Result<(DiagnosticClaim, Value)> {
    let launch = bound_json(binding)?;
    let rows = launch["evidence"]["units"]
        .as_array()
        .context("canary 227 launch owner census")?;
    ensure!(
        launch["launched"] == true
            && rows.len() == 1
            && rows[0]["unit"] == c::UNIT
            && rows[0]["restarts"] == 0,
        "canary 227 exact launch owner absent"
    );
    let iid = rows[0]["invocation_id"]
        .as_str()
        .context("canary 227 launch IID")?;
    ensure!(
        iid.len() == 32
            && iid
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "canary 227 launch IID invalid"
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
    validate_diagnostic_launch(&launch, &d)?;
    ensure!(
        c::launch_matches(&d, &launch),
        "canary 227 exact launch differs"
    );
    let guard = bound_json(&serde_json::from_value(launch["guard_sample"].clone())?)?;
    let plan_binding: BoundFile = serde_json::from_value(launch["guard_plan"].clone())?;
    let plan = bound_json(&plan_binding)?;
    ensure!(
        c::guard_matches(&d, &launch, &plan)
            && plan["unit"] == c::UNIT
            && plan["invocation_id"] == iid
            && guard["plan_sha256"] == plan_binding.sha256
            && guard["guard_sha256"] == c::GUARD_SHA
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
        "canary 227 first actual guard differs"
    );
    let completion = &launch["actual_guard_timer_proof"]["manager_completion"];
    ensure!(
        completion["_PID"] == "1"
            && completion["UNIT"] == "horizon-canary227-v1625-protective-selection-v2.service"
            && completion["INVOCATION_ID"] == guard["guard_invocation_id"]
            && completion["MESSAGE"]
                == "horizon-canary227-v1625-protective-selection-v2.service: Deactivated successfully.",
        "canary 227 first guard lacks exact PID1 completion"
    );
    let history = &launch["actual_guard_timer_proof"]["completed_guard"]["history"];
    warmup223::validate_completed_guard_history(history, &guard)?;
    Ok((d, launch))
}
fn registered(d: &DiagnosticClaim, f: &Value) -> Result<()> {
    let p: Plan = serde_json::from_value(bound_json(&BoundFile {
        path: f["plan"]
            .as_str()
            .context("canary 227 accepted plan")?
            .into(),
        sha256: f["plan_sha256"]
            .as_str()
            .context("canary 227 accepted plan SHA")?
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
        "canary 227 launch is not its accepted diagnostic owner"
    );
    Ok(())
}
fn owner(u: &Value, iid: &str, launch: &Value) -> bool {
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
        && c::same_command(&u["ExecStart"], &launch["expected_exec_start"])
        && u["MainPID"].as_str().and_then(|n| n.parse::<u64>().ok()) == launch["main_pid"].as_u64()
}
fn live(d: &DiagnosticClaim, f: &Value, launch: &Value) -> Result<Value> {
    let u = unit(c::UNIT)?;
    let old = &f["unit_census"][c::UNIT];
    ensure!(
        owner(&u, &d.invocation_id, launch)
            && owner(old, &d.invocation_id, launch)
            && u["MainPID"] == old["MainPID"],
        "canary 227 live identity changed"
    );
    Ok(u)
}
fn observed<'a>(o: &'a Value, iid: &str) -> Result<&'a Value> {
    let rows = o["diagnostic_replays"]
        .as_array()
        .context("canary 227 diagnostic observation census")?
        .iter()
        .filter(|r| r["producer_unit"] == c::UNIT)
        .collect::<Vec<_>>();
    ensure!(rows.len() == 1, "canary 227 observation missing/duplicate");
    let r = rows[0];
    let v = &r["observation"];
    ensure!(
        r["status"] == "observed"
            && r["error"].is_null()
            && r["range"] == "227-227"
            && r["expected_producer_invocation_id"] == iid
            && v["invocation_binding_stable"] == true
            && v["useful_work"]["journal_invocation_id"] == iid,
        "canary 227 observation differs"
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
            "canary 227 observation is not stable live work"
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
        "canary 227 invocation start unavailable"
    );
    let start_micros = std::str::from_utf8(&out.stdout)?.trim().parse::<u64>()?;
    ensure!(
        launch["actual_sandbox"]["ExecMainStartTimestampMonotonic"]
            .as_str()
            .and_then(|n| n.parse::<u64>().ok())
            == Some(start_micros),
        "canary 227 manager start differs from captured launch"
    );
    let start = start_micros / 1000;
    ensure!(start > 0, "canary 227 invocation start absent");
    let mut clock = std::mem::MaybeUninit::<libc::timespec>::uninit();
    ensure!(
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, clock.as_mut_ptr()) } == 0,
        "canary 227 monotonic clock unavailable"
    );
    let clock = unsafe { clock.assume_init() };
    let now = u64::try_from(clock.tv_sec)?
        .checked_mul(1000)
        .and_then(|n| n.checked_add(u64::try_from(clock.tv_nsec).ok()? / 1_000_000))
        .context("canary 227 clock overflow")?;
    let age = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .checked_sub(u128::from(sample) * 1000)
        .context("canary 227 future sample")?;
    now.checked_sub(start)
        .and_then(|n| n.checked_sub(u64::try_from(age).ok()?))
        .context("canary 227 sample predates invocation")
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
        "canary 227 launch journal unavailable/oversized"
    );
    let rows = out
        .stdout
        .split(|b| *b == b'\n')
        .filter(|b| !b.is_empty())
        .map(serde_json::from_slice::<Value>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(
        rows.len() < 8192,
        "canary 227 launch journal truncated; use the coordinated observation"
    );
    let mut last = None;
    let mut markers = Vec::new();
    for row in rows {
        ensure!(
            row["_SYSTEMD_INVOCATION_ID"] == iid && row["_SYSTEMD_UNIT"] == c::UNIT,
            "canary 227 foreign launch journal"
        );
        let msg = row["MESSAGE"]
            .as_str()
            .context("canary 227 launch journal message")?;
        if let Some(tail) = msg
            .split_once("progress slot ")
            .or_else(|| msg.split_once("warmup slot "))
            .map(|p| p.1)
        {
            let slot = tail
                .split_once('/')
                .context("canary 227 malformed progress")?
                .0
                .parse::<u64>()?;
            let terminal = decimal(tail, "/").context("canary 227 progress terminal")?;
            ensure!(
                (terminal == TERMINAL || terminal == 98_063_999)
                    && (FIRST..=TARGET).contains(&slot),
                "canary 227 foreign progress interval"
            );
            last = Some(
                json!({"slot":slot,"terminal_slot":terminal,"transactions":decimal(msg,"txs=").context("canary 227 transaction counter")?,"account_updates":decimal(msg,"accounts=").context("canary 227 account counter")?}),
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
        .context("canary 227 reset count missing")?;
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
        .context("canary 227 first slot missing")?;
    let b = last["slot"]
        .as_u64()
        .context("canary 227 last slot missing")?;
    let start = first["realtime_microseconds"]
        .as_u64()
        .context("canary 227 first clock missing")?;
    let end = last["realtime_microseconds"]
        .as_u64()
        .context("canary 227 last clock missing")?;
    let duration = end
        .checked_sub(start)
        .filter(|n| *n > 0)
        .context("canary 227 invalid progress clock")?;
    let delta = b
        .checked_sub(a)
        .context("canary 227 slot counter moved backwards")?;
    let rate = delta as f64 / (duration as f64 / 1_000_000.0);
    let reported = progress["slots_per_second"]
        .as_f64()
        .context("canary 227 slot rate missing")?;
    ensure!(
        progress["sufficient_for_rates"] == true
            && progress["matching_markers"]
                .as_u64()
                .is_some_and(|n| n >= 2)
            && (FIRST..=TARGET).contains(&a)
            && (FIRST..=TARGET).contains(&b)
            && valid_progress_terminal(first)
            && valid_progress_terminal(last)
            && progress["slot_delta"] == delta
            && rate.is_finite()
            && rate > 0.0
            && reported.is_finite()
            && (reported - rate).abs() <= (rate * 1e-9).max(1e-12),
        "canary 227 accounting resets lack an independently monotonic slot window"
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
        "canary 227 complete inclusive model required"
    );
    let downstream = p
        .downstream_allowance_millis
        .values()
        .try_fold(0u64, |a, b| {
            a.checked_add(*b).context("canary 227 downstream overflow")
        })?;
    validate_progress_counters(progress)?;
    let slot = progress["last"]["slot"].as_u64();
    ensure!(
        slot.is_none() || valid_progress_terminal(&progress["last"]),
        "canary 227 progress terminal differs"
    );
    let replay = slot.is_some();
    let observed_slot = slot.unwrap_or(FIRST - 1);
    ensure!(
        (FIRST - 1..=TARGET).contains(&observed_slot),
        "canary 227 progress outside exact epoch"
    );
    let current = observed_slot.max(FIRST - 1);
    if current == TARGET {
        return Ok(("verification".into(), downstream));
    }
    let rate = if replay && progress["sufficient_for_rates"] == true {
        let r = progress["slots_per_second"]
            .as_f64()
            .context("canary 227 rate missing")?;
        ensure!(r.is_finite() && r > 0.0, "canary 227 invalid measured rate");
        r
    } else {
        p.fallback_slots_per_second
    };
    let replay_millis = ((TARGET - current) as f64 * 1000.0 / rate).ceil();
    ensure!(
        replay_millis.is_finite() && replay_millis >= 0.0 && replay_millis < u64::MAX as f64,
        "canary 227 ETA overflow"
    );
    let initialization = if replay {
        0
    } else if elapsed < p.initialization_allowance_millis {
        p.initialization_allowance_millis - elapsed
    } else {
        elapsed
            .checked_div(2)
            .and_then(|n| n.checked_add(p.initialization_allowance_millis / 2))
            .context("canary 227 overdue initialization overflow")?
    };
    let remaining = (replay_millis as u64)
        .checked_add(downstream)
        .and_then(|n| n.checked_add(initialization))
        .context("canary 227 total ETA overflow")?;
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
        "not a canary 227 status receipt"
    );
    let evidence = bound_json(&BoundFile {
        path: receipt.observer_receipt.clone(),
        sha256: receipt.observer_receipt_sha256.clone(),
    })?;
    ensure!(
        evidence["schema"] == ESTIMATE_SCHEMA && evidence["status"] == json!(receipt.status),
        "canary 227 frozen observation differs"
    );
    let (d, launch) = claim(&serde_json::from_value(evidence["launch"].clone())?)?;
    let p: Model = serde_json::from_value(bound_json(&serde_json::from_value(
        evidence["plan"].clone(),
    )?)?)?;
    ensure!(
        p.schema == PLAN_SCHEMA
            && matches!(p.mode.as_str(), "launch-event" | "observation")
            && p.estimate_receipt == receipt.observer_receipt
            && private157::binding(&p.launch) == evidence["launch"]
            && private157::binding(&p.observer) == evidence["observer"]
            && private157::binding(&p.fleet) == evidence["fleet"],
        "canary 227 frozen model bindings differ"
    );
    ensure!(
        !p.estimate_basis.trim().is_empty() && !p.estimate_evidence.is_empty(),
        "canary 227 frozen basis missing"
    );
    for e in &p.estimate_evidence {
        bound_json(e)?;
    }
    let observer = bound_json(&p.observer)?;
    let f = bound_json(&p.fleet)?;
    registered(&d, &f)?;
    ensure!(
        owner(&f["unit_census"][c::UNIT], &d.invocation_id, &launch)
            && observer["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && f["observer_sha256"] == p.observer.sha256,
        "canary 227 frozen observation lacks original owner"
    );
    let expected_clock = if p.mode == "launch-event" {
        let launch = bound_json(&p.launch)?;
        publication203::utc(
            launch["recorded_unix_seconds"]
                .as_u64()
                .context("canary 227 frozen launch clock")?,
        )?
    } else {
        observer["recorded_at_utc"]
            .as_str()
            .context("canary 227 frozen observer clock")?
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
        "canary 227 frozen status does not reproduce its model"
    );
    ensure!(
        receipt.controller_invocation_id == d.invocation_id
            && receipt.producer_invocation_id == d.invocation_id,
        "canary 227 receipt owner differs"
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
        && frozen(receipt).is_ok_and(|(d, evidence)| {
            let Ok(launch_binding) =
                serde_json::from_value::<BoundFile>(evidence["launch"].clone())
            else {
                return false;
            };
            let Ok(launch) = bound_json(&launch_binding) else {
                return false;
            };
            census
                .get(c::UNIT)
                .is_some_and(|u| owner(u, &d.invocation_id, &launch))
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
        "canary 227 status origin",
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
        "status-publish-canary227 PLAN --plan-sha256 SHA --self-sha256 SHA [--check-only]"
    );
    let own = fs::symlink_metadata(fs::read_link("/proc/self/exe")?)?;
    ensure!(
        own.uid() == 0
            && own.nlink() == 1
            && own.mode() & 0o222 == 0
            && hex_lower(&Sha256::digest(fs::read("/proc/self/exe")?)) == args[6],
        "canary 227 status helper unsealed"
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
        "canary 227 estimate scope/evidence absent"
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
        .context("canary 227 observer UTC")?;
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
        "canary 227 unaccepted observer/fleet"
    );
    let seconds = if p.mode == "launch-event" {
        launch["recorded_unix_seconds"]
            .as_u64()
            .context("canary 227 launch event clock")?
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
        "canary 227 stale/future observation event"
    );
    let first = live(&d, &f, &launch)?;
    let evidence = if p.estimate_receipt.try_exists()? {
        let old: Value = serde_json::from_slice(&read_stable_bounded(
            &p.estimate_receipt,
            MAX_OBSERVER_RECEIPT_BYTES,
            "canary 227 frozen estimate",
        )?)?;
        ensure!(
            old["schema"] == ESTIMATE_SCHEMA
                && old["plan_sha256"] == binding.sha256
                && old["launch"] == private157::binding(&p.launch)
                && old["observer"] == private157::binding(&p.observer)
                && old["fleet"] == private157::binding(&p.fleet),
            "canary 227 retry estimate differs"
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
        let measurement = jet_measurement(Path::new(c::ROOT), 1000)?;
        let status = EpochStatus {
            epoch: 227,
            jet_size_bytes: measurement["jet_size_bytes"]
                .as_u64()
                .context("canary 227 archive size")?,
            elapsed_execution_millis: elapsed,
            estimated_remaining_millis: remaining,
            sampled_at_utc: publication203::utc(seconds)?,
            phase,
        };
        let v = json!({"schema":ESTIMATE_SCHEMA,"plan":private157::binding(&binding),"plan_sha256":binding.sha256,"launch":private157::binding(&p.launch),"observer":private157::binding(&p.observer),"fleet":private157::binding(&p.fleet),"mode":p.mode,"progress":progress,"status":status,"jet_measurement":measurement,"producer_start_monotonic_microseconds":launch["actual_sandbox"]["ExecMainStartTimestampMonotonic"],"estimate_basis":p.estimate_basis,"estimate_evidence":p.estimate_evidence,"downstream_allowance_millis":p.downstream_allowance_millis,"initialization_allowance_millis":p.initialization_allowance_millis,"fallback_slots_per_second":p.fallback_slots_per_second,"resource_samples_taken":0,"archive_or_sidecar_mutation_authorized":false,"canary_target_is_sidecar_eta":false,"includes_followup_full_epoch_and_qualification":true});
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
        "canary 227 frozen payload differs"
    );
    if args.len() == 8 {
        println!("{evidence}");
        return Ok(());
    }
    ensure!(
        first == live(&d, &f, &launch)?,
        "canary 227 owner changed before status publish"
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
            "canary 227 status publication",
        )?)?;
        ensure!(
            old.status == receipt.status
                && old.object_etag == receipt.object_etag
                && old.observer_receipt_sha256 == receipt.observer_receipt_sha256
                && old.producer_invocation_id == receipt.producer_invocation_id
                && old.controller_invocation_id == receipt.controller_invocation_id
                && old.authenticated_readback,
            "canary 227 prior status receipt differs"
        );
    } else {
        write_status_receipt(&p.receipt_directory, &receipt)?;
    }
    ensure!(
        first == live(&d, &f, &launch)?,
        "canary 227 owner changed during status publish"
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
            estimate_basis:
                "Current best guess, including full epoch replay and unresolved qualification"
                    .into(),
            estimate_evidence: vec![b()],
        }
    }
    #[test]
    fn initialization_never_confuses_bounded_target_with_sidecar_eta() {
        let p = model();
        let progress = json!({"counter_resets":0,"last":null,"sufficient_for_rates":false});
        let result = estimate(&progress, 100_000, &p).unwrap();
        assert_eq!(
            result,
            (
                "verification".into(),
                500_000 + (TARGET - c::BOOTSTRAP) * 500 + 10_000
            )
        );
        assert!(
            estimate(&progress, 1_200_000, &p).unwrap().1
                > estimate(&progress, 600_000, &p).unwrap().1
        );
        let target = json!({"counter_resets":0,"last":{"slot":TARGET,"terminal_slot":TERMINAL},"sufficient_for_rates":true,"slots_per_second":2.0});
        assert_eq!(
            estimate(&target, 10_000, &p).unwrap(),
            ("verification".into(), 10_000)
        );
        assert!(estimate(&target, 10_000, &p).unwrap().1 > 0);
    }
    #[test]
    fn observed_execution_is_replay_including_warmup_and_keeps_followup_allowances() {
        let p = model();
        let progress = json!({"counter_resets":0,"last":{"slot":FIRST,"terminal_slot":98_063_999},
            "sufficient_for_rates":true,"slots_per_second":4.0});
        assert_eq!(
            estimate(&progress, 100_000, &p).unwrap(),
            ("replay".into(), (TARGET - FIRST) * 250 + 10_000)
        );
        let progress = json!({"counter_resets":0,"last":{"slot":TARGET-100,"terminal_slot":TERMINAL},"sufficient_for_rates":true,"slots_per_second":4.0});
        assert_eq!(
            estimate(&progress, 100_000, &p).unwrap(),
            ("replay".into(), 35_000)
        );
        let mut bad = progress;
        bad["last"]["slot"] = json!(TARGET + 1);
        assert!(estimate(&bad, 100_000, &p).is_err());
    }
    #[test]
    fn every_followup_stage_and_finite_rate_are_required() {
        let progress = json!({"counter_resets":0,"last":null,"sufficient_for_rates":false});
        for stage in STAGES {
            let mut p = model();
            p.downstream_allowance_millis.remove(stage);
            assert!(estimate(&progress, 0, &p).is_err(), "{stage}");
        }
        let mut p = model();
        p.fallback_slots_per_second = f64::NAN;
        assert!(estimate(&progress, 0, &p).is_err());
        let mut p = model();
        p.downstream_allowance_millis
            .insert("full_epoch_replay".into(), 0);
        assert!(estimate(&progress, 0, &p).is_err());
    }
    #[test]
    fn accounting_resets_require_an_independent_monotonic_slot_rate() {
        let progress = json!({"counter_resets":1,"sufficient_for_rates":true,"matching_markers":3,
            "first":{"slot":FIRST+1000,"terminal_slot":TERMINAL,"realtime_microseconds":1_000_000},
            "last":{"slot":FIRST+1100,"terminal_slot":TERMINAL,"realtime_microseconds":26_000_000},
            "slot_delta":100,"slots_per_second":4.0});
        assert!(estimate(&progress, 100_000, &model()).is_ok());
        for (key, value) in [
            ("slots_per_second", json!(8.0)),
            ("slot_delta", json!(101)),
            ("sufficient_for_rates", json!(false)),
        ] {
            let mut bad = progress.clone();
            bad[key] = value;
            assert!(estimate(&bad, 100_000, &model()).is_err(), "{key}");
        }
    }
    #[test]
    fn owner_binds_exact_command_original_pid_and_zero_restart_invocation() {
        let iid = "a".repeat(32);
        let cmd="{ path=/runner ; argv[]=/runner /plan --plan-sha256 hash --self-sha256 self ; ignore_errors=no }";
        let launch = json!({"main_pid":42,"expected_exec_start":cmd});
        let u = json!({"Id":c::UNIT,"LoadState":"loaded","InvocationID":iid,"NRestarts":"0","ActiveState":"active","SubState":"running","MainPID":"42","ExecStart":cmd});
        assert!(owner(&u, &iid, &launch));
        for (key, value) in [
            ("MainPID", json!("43")),
            ("InvocationID", json!("b".repeat(32))),
            ("NRestarts", json!("1")),
            ("ExecStart", json!("other")),
        ] {
            let mut bad = u.clone();
            bad[key] = value;
            assert!(!owner(&bad, &iid, &launch), "{key}");
        }
    }
    #[test]
    fn direct_canary_size_is_zero_before_creation_and_rejects_symlinks() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let t = tempfile::tempdir().unwrap();
        fs::set_permissions(t.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let output = t.path().join("output");
        fs::create_dir(&output).unwrap();
        fs::set_permissions(&output, fs::Permissions::from_mode(0o700)).unwrap();
        let uid = unsafe { libc::geteuid() };
        assert_eq!(jet_measurement(t.path(), uid).unwrap()["jet_size_bytes"], 0);
        let path = output.join("epoch-227-canary.jet");
        fs::write(&path, b"canary").unwrap();
        assert_eq!(jet_measurement(t.path(), uid).unwrap()["jet_size_bytes"], 6);
        fs::remove_file(&path).unwrap();
        symlink("/etc/passwd", &path).unwrap();
        assert!(jet_measurement(t.path(), uid).is_err());
    }
}
