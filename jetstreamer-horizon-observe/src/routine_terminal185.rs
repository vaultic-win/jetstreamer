//! Exact guard-stopped 185 terminal transition. Metadata only; retained bytes and
//! every historical growth/floor obligation remain protected.
use super::*;
#[path = "routine_terminal185_holding.rs"]
mod holding;
const CONTROLLER: &str = "jetstreamer-epoch185-full-20261023-controller-v1-r2.service";
const PRODUCER: &str = "jetstreamer-root-sweep-e185-full-20261023-v1-r2-e185-185-lane-a-1.service";
const CID: &str = "fcc936d65490488aa95df0d1732bc40e";
const PID: &str = "0de9498a3c2f4c6dbd7350d052fc7e02";
const GUARD: &str = "/var/lib/jetstreamer-adaptive-reserve-controller-rebind-185-185-20261023-v1";
const ROOT: &str = "/var/lib/jetstreamer/horizon-terminal185-20261024-v1";
const FLOOR: u64 = 3_503_746_342_342;
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Profile {
    pub proof: Bound,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    recovery_predecessor: Option<Bound>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    holding_admission: Option<Bound>,
}
// A static classification policy may be installed before the admitted transport starts.
// Actual active ownership is independently verified each time the terminal proof is used.
pub(super) fn admit_holding(p: &mut Plan, b: &Bound) -> Result<()> {
    let _ = holding::load(b)?;
    let profile = p
        .terminal185
        .as_mut()
        .context("185 holding classification requires terminal 185 profile")?;
    if let Some(old) = &profile.holding_admission {
        ensure!(
            old.path == b.path && old.sha256 == b.sha256,
            "185 holding classification is already bound differently"
        );
    } else {
        profile.holding_admission = Some(b.clone());
    }
    Ok(())
}
pub(super) fn enabled(p: &Plan) -> bool {
    p.terminal185.is_some()
}
fn manager(name: &str) -> Result<Value> {
    let out = Command::new("/usr/bin/systemctl").args(["show",name,"--all","--no-pager","--property=Id,LoadState,ActiveState,SubState,MainPID,InvocationID,NRestarts,Job,Restart"]).output()?;
    ensure!(
        out.status.success() && out.stdout.len() < 16384,
        "185 manager read failed"
    );
    let mut m = serde_json::Map::new();
    for l in std::str::from_utf8(&out.stdout)?.lines() {
        let (k, v) = l.split_once('=').context("185 manager framing")?;
        ensure!(
            m.insert(k.into(), json!(v)).is_none(),
            "duplicate 185 manager field"
        );
    }
    Ok(Value::Object(m))
}
fn stopped(v: &Value, unit: &str, iid: &str) -> Result<()> {
    ensure!(
        v["Id"] == unit
            && v["MainPID"] == "0"
            && v["NRestarts"] == "0"
            && v["Job"] == ""
            && matches!(v["ActiveState"].as_str(), Some("inactive" | "failed"))
            && matches!(v["SubState"].as_str(), Some("dead" | "failed"))
            && (v["InvocationID"] == "" || v["InvocationID"] == iid),
        "185 owner not positively terminal"
    );
    ensure!(
        v["LoadState"] == "not-found"
            || (v["LoadState"] == "loaded"
                && v["Restart"] == "no"
                && (v["InvocationID"] == iid || v["InvocationID"] == "")),
        "185 owner replaced or restarting"
    );
    Ok(())
}
fn guard(intent: &Value, completion: &Value) -> Result<()> {
    for v in [intent, completion] {
        ensure!(
            v["controller_unit"] == CONTROLLER
                && v["producer_unit"] == PRODUCER
                && v["expected_controller_invocation_id"] == CID
                && v["expected_producer_invocation_id"] == PID
                && v["filesystem"] == "/home/sol"
                && v["minimum_free_bytes"] == FLOOR
                && v["r2_mutations"] == false
                && v["remote_mutations"] == false,
            "185 guard identity/floor differs"
        );
    }
    ensure!(
        intent["schema"] == "jetstreamer-adaptive-replay-reserve-stop-intent-v1"
            && intent["available_bytes"]
                .as_u64()
                .is_some_and(|n| n < FLOOR)
            && intent["controller_sample"]["invocation_id"] == CID
            && intent["producer_sample"]["invocation_id"] == PID
            && completion["schema"] == "jetstreamer-adaptive-replay-reserve-stop-completion-v1"
            && completion["controller_stop"]["return_code"] == 0
            && completion["producer_stop"]["return_code"] == 0
            && completion["scratch_deleted"] == false,
        "185 guard terminal completion incomplete"
    );
    for role in ["controller_final", "producer_final"] {
        ensure!(
            completion[role]["main_pid"] == 0
                && completion[role]["restarts"] == 0
                && completion[role]["active_state"] == "inactive"
                && completion[role]["sub_state"] == "dead",
            "185 guard did not prove terminal owner"
        );
    }
    Ok(())
}
fn lifecycle(rows: &[Value], unit: &str, iid: &str) -> Result<()> {
    let valid: Vec<_> = rows
        .iter()
        .filter(|v| v["UNIT"] == unit && v["_PID"] == "1" && v["_UID"] == "0")
        .collect();
    let latest_start = valid
        .iter()
        .filter(|v| {
            v["MESSAGE_ID"] == "7d4958e842da4a758f6c1cdc7b36dcc5"
                || v["MESSAGE_ID"] == "39f53479d3a045ac8e11786248231fbf"
        })
        .max_by_key(|v| v["__REALTIME_TIMESTAMP"].as_str().unwrap_or(""));
    let start = latest_start.context("185 trusted latest manager start missing")?;
    ensure!(
        start["INVOCATION_ID"] == iid,
        "185 latest manager start is a replacement"
    );
    ensure!(
        valid.iter().any(|v| v["INVOCATION_ID"] == iid
            && v["MESSAGE_ID"] == "9d1aaa27d60140bd96365438aad20286"
            && v["JOB_TYPE"] == "stop"
            && v["JOB_RESULT"] == "done"
            && v["__REALTIME_TIMESTAMP"]
                .as_str()
                .zip(start["__REALTIME_TIMESTAMP"].as_str())
                .is_some_and(|(a, b)| a >= b)),
        "185 native manager stop missing"
    );
    Ok(())
}
fn no_live185(admission: Option<&Bound>) -> Result<()> {
    let holding = admission.map(holding::load).transpose()?;
    let out = Command::new("/usr/bin/systemctl")
        .args([
            "list-units",
            "--all",
            "--type=service",
            "--state=active,activating",
            "--plain",
            "--no-legend",
            "--no-pager",
            "*185*",
        ])
        .output()?;
    ensure!(
        out.status.success() && out.stdout.len() < 1 << 20,
        "185 replacement census failed"
    );
    for l in std::str::from_utf8(&out.stdout)?.lines() {
        let f: Vec<_> = l.split_whitespace().collect();
        ensure!(f.len() >= 4, "185 replacement census malformed");
        if f[3] == "exited" {
            continue;
        }
        let v = manager(f[0])?;
        if v["MainPID"].as_str().and_then(|n| n.parse::<u32>().ok()) == Some(std::process::id()) {
            continue;
        }
        let policy = holding
            .as_ref()
            .filter(|a| a.unit == f[0])
            .context("185 has another live/activating replacement or downstream owner")?;
        holding::verify_live(policy, &v)?;
    }
    Ok(())
}
fn proof_value(v: &Value, cutoff: u64, admission: Option<&Bound>) -> Result<()> {
    ensure!(
        v["schema"] == "jetstreamer-guard-stopped185-terminal-v2"
            && v["epoch"] == 185
            && v["captured_unix_seconds"]
                .as_u64()
                .is_some_and(|n| n <= cutoff),
        "foreign/backdated185 terminal proof"
    );
    for k in [
        "replay_launch_authorized",
        "publication_authorized",
        "r2_mutations",
        "remaining_growth_released",
        "scratch_retirement_authorized",
    ] {
        ensure!(v[k] == false, "185 terminal proof grants authority");
    }
    let ib: Bound = serde_json::from_value(v["guard_intent"].clone())?;
    let cb: Bound = serde_json::from_value(v["guard_completion"].clone())?;
    ensure!(
        ib.path == Path::new(GUARD).join("intent.json")
            && cb.path == Path::new(GUARD).join("completion.json"),
        "foreign 185 guard paths"
    );
    guard(&bound_json(&ib, false)?, &bound_json(&cb, false)?)?;
    for (name, iid) in [(CONTROLLER, CID), (PRODUCER, PID)] {
        lifecycle(
            v["manager_journals"][name]
                .as_array()
                .context("185 manager evidence missing")?,
            name,
            iid,
        )?;
        stopped(&manager(name)?, name, iid)?;
    }
    no_live185(admission)
}
// Only the authenticated first transition may bridge a missed observation.
// Its exact predecessor binding persists, so later successors regain the grid.
pub(super) fn interval(p: &Plan, old_time: &str) -> Result<Option<u64>> {
    let Some(profile) = &p.terminal185 else {
        return Ok(None);
    };
    let Some(previous) = &profile.recovery_predecessor else {
        return Ok(None);
    };
    if previous.path != p.previous_observer.path || previous.sha256 != p.previous_observer.sha256 {
        return Ok(None);
    }
    let old = utc_seconds(old_time)?;
    let target = utc_seconds(scheduled_target(p)?)?;
    let gap = target
        .checked_sub(old)
        .context("185 recovery precedes predecessor")?;
    ensure!(
        (1800..=3600).contains(&gap),
        "185 recovery interval outside bounded window"
    );
    let proof = bound_json(&profile.proof, false)?;
    let captured = proof["captured_unix_seconds"]
        .as_u64()
        .context("185 capture clock missing")?;
    recovery_clocks(old, target, captured)?;
    Ok(Some(gap))
}
fn recovery_clocks(old: u64, target: u64, captured: u64) -> Result<()> {
    ensure!(
        target
            .checked_sub(old)
            .is_some_and(|gap| (1800..=3600).contains(&gap)),
        "185 recovery interval outside bounded window"
    );
    ensure!(
        captured > old && captured <= target,
        "185 capture does not follow predecessor and precede target"
    );
    Ok(())
}
pub(super) fn validate(p: &Plan) -> Result<()> {
    let Some(profile) = &p.terminal185 else {
        return Ok(());
    };
    let v = bound_json(&profile.proof, false)?;
    ensure!(
        v["historical_repair_handoff"]
            == serde_json::to_value(
                p.repair185_handoff
                    .as_ref()
                    .context("185 historical handoff missing")?
            )?,
        "185 historical launch lineage differs"
    );
    proof_value(
        &v,
        utc_seconds(&p.sample_target_utc)?,
        profile.holding_admission.as_ref(),
    )
}
pub(super) fn capture(p: &Plan, spec: &Bound, program: &Path, self_sha: &str) -> Result<()> {
    ensure!(
        is_101(p)? && p.repair185_handoff.is_some(),
        "185 capture lacks exact campaign history"
    );
    let s = bound_json(spec, true)?;
    ensure!(
        s["schema"] == "jetstreamer-guard-stopped185-capture-plan-v2"
            && s["output"]
                == Path::new(ROOT)
                    .join("terminal.json")
                    .to_string_lossy()
                    .as_ref(),
        "foreign 185 capture plan"
    );
    let ib: Bound = serde_json::from_value(s["guard_intent"].clone())?;
    let cb: Bound = serde_json::from_value(s["guard_completion"].clone())?;
    ensure!(
        ib.path == Path::new(GUARD).join("intent.json")
            && cb.path == Path::new(GUARD).join("completion.json"),
        "foreign 185 guard paths"
    );
    guard(&bound_json(&ib, false)?, &bound_json(&cb, false)?)?;
    let mut journals = serde_json::Map::new();
    for (name, iid) in [(CONTROLLER, CID), (PRODUCER, PID)] {
        stopped(&manager(name)?, name, iid)?;
        let out = Command::new("/usr/bin/journalctl")
            .args([
                "_PID=1",
                "_UID=0",
                &format!("UNIT={name}"),
                "-n",
                "64",
                "--no-pager",
                "-o",
                "json",
            ])
            .output()?;
        ensure!(
            out.status.success() && out.stdout.len() < 2 << 20,
            "185 bounded journal capture failed"
        );
        let rows = serde_json::Deserializer::from_slice(&out.stdout)
            .into_iter::<Value>()
            .collect::<std::result::Result<Vec<_>, _>>()?;
        lifecycle(&rows, name, iid)?;
        journals.insert(name.into(), json!(rows));
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let v = json!({"schema":"jetstreamer-guard-stopped185-terminal-v2","epoch":185,"capture_program":program,"capture_self_sha256":self_sha,"capture_plan":spec,"historical_repair_handoff":p.repair185_handoff,"guard_intent":ib,"guard_completion":cb,"manager_journals":journals,"captured_unix_seconds":now,"last_observed_slot":80099168u64,"canonical_terminal_slot":80351999u64,"replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false,"remaining_growth_released":false,"scratch_retirement_authorized":false});
    proof_value(&v, now, None)?;
    let output = Path::new(ROOT).join("terminal.json");
    private_dir(Path::new(ROOT))?;
    write_new(&output, &v)?;
    println!("{}", output.display());
    Ok(())
}
pub(super) fn model(p: &Plan, m: &Value) -> Result<Value> {
    if !enabled(p) {
        return Ok(m.clone());
    }
    validate(p)?;
    let mut v = m.clone();
    let rows = v["ranges"].as_array_mut().context("185 model ranges")?;
    for r in rows.iter().filter(|r| r["range"] == "185-185") {
        ensure!(
            r["epochs"] == json!([185])
                && r["expected_producer_invocation_id"] == PID
                && r["expected_controller_invocation_id"] == CID,
            "185 model original owner differs"
        );
    }
    rows.retain(|r| r["range"] != "185-185");
    if let Some(a) = v["expected_observer_ranges"].as_array_mut() {
        a.retain(|r| r != "185-185");
    }
    if let Some(a) = v["unestimated_bootstrap_epochs"].as_array_mut() {
        a.retain(|r| r != 185);
    }
    let b = serde_json::to_value(&p.terminal185.as_ref().unwrap().proof)?;
    if let Some(a) = v["evidence"].as_array_mut()
        && !a.contains(&b)
    {
        a.push(b);
    }
    Ok(v)
}
pub(super) fn config(p: &Plan, c: &mut Value) -> Result<()> {
    if !enabled(p) {
        return Ok(());
    }
    validate(p)?;
    let rows = c["replays"].as_array_mut().context("185 observer ranges")?;
    for r in rows.iter().filter(|r| r["range"] == "185-185") {
        ensure!(
            r["expected_controller_invocation_id"] == CID
                && r["expected_producer_invocation_id"] == PID,
            "185 observer binding differs"
        );
    }
    rows.retain(|r| r["range"] != "185-185");
    Ok(())
}
fn recovery_target(ordinary_next: &str, target: &str) -> Result<()> {
    let delay = utc_seconds(target)?
        .checked_sub(utc_seconds(ordinary_next)?)
        .context("185 recovery target precedes ordinary successor")?;
    ensure!(
        delay <= 1800,
        "185 recovery target exceeds one recovery window"
    );
    Ok(())
}
// An explicit sealed handoff may delay this first transition only. The accepted
// predecessor and all proof/sample clocks remain unchanged; no clock is guessed.
fn retime(p: &mut Plan, c: &mut Value, target: &str) -> Result<()> {
    recovery_target(&p.sample_target_utc, target)?;
    let new = stamp(target);
    let observer = p
        .observer
        .parent()
        .context("185 observer parent")?
        .join(format!("sample-{new}.json"));
    let estimates = p
        .estimate_output
        .parent()
        .context("185 estimate parent")?
        .join(format!(
            "horizon-r2-status-estimates-{new}-cohort-gated-v5.json"
        ));
    let fleet = p
        .fleet_output
        .parent()
        .context("185 fleet parent")?
        .join(format!("fleet-{new}.json"));
    p.observer = observer;
    p.estimate_output = estimates;
    p.fleet_output = fleet;
    p.sample_target_utc = target.into();
    c["not_before_utc"] = json!(target);
    c["output"] = json!(p.observer);
    // Caller regenerates the package, cycle and observer-config namespaces via
    // prefix157::namespaces after this authenticated transition is enabled.
    Ok(())
}
pub(super) fn enable(p: &mut Plan, c: &mut Value, spec: &Bound) -> Result<()> {
    let v = bound_json(spec, true)?;
    ensure!(
        v["schema"] == "jetstreamer-guard-stopped185-routine-handoff-v2"
            && v["replay_launch_authorized"] == false
            && v["publication_authorized"] == false
            && v["r2_mutations"] == false
            && p.terminal185.is_none(),
        "foreign 185 handoff"
    );
    if let Some(target) = v.get("sample_target_utc") {
        retime(
            p,
            c,
            target
                .as_str()
                .context("185 recovery target must be explicit UTC")?,
        )?;
    }
    p.terminal185 = Some(serde_json::from_value(v["profile"].clone())?);
    p.terminal185.as_mut().unwrap().recovery_predecessor = Some(p.previous_observer.clone());
    validate(p)?;
    config(p, c)?;
    p.expected_epochs.retain(|e| *e != 185);
    if let Some(b) = v.get("repair141_handoff").filter(|v| !v.is_null()) {
        repair141_status::enable(p, &serde_json::from_value(b.clone())?)?;
    }
    p.observer_config.sha256 = sha(&next_preparation::encoded(c)?);
    Ok(())
}
pub(super) fn derive_fleet(p: &Plan, f: &mut Value) -> Result<()> {
    if !enabled(p) {
        return Ok(());
    }
    validate(p)?;
    let g = &mut f["gates"]["185"];
    g["state"] = json!("failed-needs-repair");
    g["next_action"] = json!(
        "Controlled disk-floor stop at 80099168 before 80351999. Preserve partial/scratch/launch/guard proof; establish an actual durable native checkpoint or independently qualified cold recovery, then fresh guarded capacity admission. No resume or growth-release credit. Old 185 status is stale pending qualified lifecycle; no R2 deletion authorized."
    );
    let a = g["evidence"]
        .as_array_mut()
        .context("185 gate history missing")?;
    let b = serde_json::to_value(&p.terminal185.as_ref().unwrap().proof)?;
    if !a.contains(&b) {
        a.push(b);
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn holding_policy_defaults_absent_without_changing_old_profile_bytes() {
        let b = json!({"path":"/proof.json","sha256":"a".repeat(64)});
        let original = json!({"proof":b});
        let p: Profile = serde_json::from_value(original.clone()).unwrap();
        assert!(p.holding_admission.is_none());
        assert_eq!(serde_json::to_value(&p).unwrap(), original);
    }
    #[test]
    fn recovery_interval_requires_bounded_gap_and_between_sample_capture() {
        for gap in [1800, 2400, 3000, 3600] {
            recovery_clocks(10000, 10000 + gap, 11000).unwrap();
        }
        for target in [9999, 10000, 11799, 13601] {
            assert!(recovery_clocks(10000, target, 11000).is_err());
        }
        for captured in [9999, 10000, 12401] {
            assert!(recovery_clocks(10000, 12400, captured).is_err());
        }
    }
    #[test]
    fn explicit_recovery_target_respects_ordinary_floor_and_bounded_window() {
        for target in [
            "2026-10-24T00:56:00Z",
            "2026-10-24T01:06:00Z",
            "2026-10-24T01:26:00Z",
        ] {
            recovery_target("2026-10-24T00:56:00Z", target).unwrap();
        }
        for target in [
            "2026-10-24T00:26:00Z",
            "2026-10-24T00:55:59Z",
            "2026-10-24T01:26:01Z",
            "not-a-clock",
        ] {
            assert!(recovery_target("2026-10-24T00:56:00Z", target).is_err());
        }
    }
    #[test]
    fn recovery_retimes_only_successor_outputs_and_preserves_predecessor_and_proof() {
        let b = || json!({"path":"/evidence","sha256":"a".repeat(64)});
        let mut p: Plan = serde_json::from_value(json!({"schema":PLAN_SCHEMA,
            "sample_target_utc":"2026-10-24T00:56:00Z", "endpoint_sha256":"a".repeat(64), "bucket":BUCKET,
            "observer":"/observers/sample-20261024T005600Z.json", "observer_config":b(),
            "previous_observer":b(), "model_template":b(), "fleet_template":b(), "previous_estimates":b(), "previous_fleet":b(),
            "tools":{"sealer":b(),"estimator":b(),"r2":b()}, "expected_epochs":[152,153],
            "cycle_directory":"/cycles/original", "cycle_unit":"original.service",
            "estimate_output":"/estimates/horizon-r2-status-estimates-20261024T005600Z-cohort-gated-v5.json",
            "fleet_output":"/fleet/fleet-20261024T005600Z.json", "terminal185":{"proof":b()}})).unwrap();
        let mut c = json!({"not_before_utc":p.sample_target_utc,"output":p.observer,
            "previous_sample":"/accepted/sample-20261024T002600Z.json", "minimum_interval_seconds":1800,
            "replays":[{"range":"152-153","iid":"unchanged"}]});
        let before = serde_json::to_value(&p).unwrap();
        let old_config = c.clone();
        retime(&mut p, &mut c, "2026-10-24T01:06:00Z").unwrap();
        let mut expected = before;
        expected["sample_target_utc"] = json!("2026-10-24T01:06:00Z");
        expected["observer"] = json!("/observers/sample-20261024T010600Z.json");
        expected["estimate_output"] =
            json!("/estimates/horizon-r2-status-estimates-20261024T010600Z-cohort-gated-v5.json");
        expected["fleet_output"] = json!("/fleet/fleet-20261024T010600Z.json");
        assert_eq!(serde_json::to_value(&p).unwrap(), expected);
        let mut expected_config = old_config;
        expected_config["not_before_utc"] = json!(p.sample_target_utc);
        expected_config["output"] = json!(p.observer);
        assert_eq!(c, expected_config);
        assert!(interval(&p, "2026-10-24T00:26:00Z").unwrap().is_none());
        p.terminal185.as_mut().unwrap().recovery_predecessor = Some(Bound {
            path: "/different-predecessor".into(),
            sha256: "a".repeat(64),
        });
        assert!(interval(&p, "2026-10-24T00:26:00Z").unwrap().is_none());
        let unchanged = serde_json::to_value(&p).unwrap();
        let unchanged_config = c.clone();
        assert!(retime(&mut p, &mut c, "2026-10-24T01:05:59Z").is_err());
        assert_eq!(serde_json::to_value(&p).unwrap(), unchanged);
        assert_eq!(c, unchanged_config);
    }
    #[test]
    fn guarded_stop_never_becomes_readiness_or_capacity_credit() {
        let base = json!({"controller_unit":CONTROLLER,"producer_unit":PRODUCER,"expected_controller_invocation_id":CID,"expected_producer_invocation_id":PID,"filesystem":"/home/sol","minimum_free_bytes":FLOOR,"r2_mutations":false,"remote_mutations":false});
        let mut i = base.clone();
        i["schema"] = json!("jetstreamer-adaptive-replay-reserve-stop-intent-v1");
        i["available_bytes"] = json!(FLOOR - 1);
        i["controller_sample"] = json!({"invocation_id":CID});
        i["producer_sample"] = json!({"invocation_id":PID});
        let mut c = base;
        c["schema"] = json!("jetstreamer-adaptive-replay-reserve-stop-completion-v1");
        c["scratch_deleted"] = json!(false);
        c["controller_stop"] = json!({"return_code":0});
        c["producer_stop"] = json!({"return_code":0});
        for role in ["controller_final", "producer_final"] {
            c[role] =
                json!({"main_pid":0,"restarts":0,"active_state":"inactive","sub_state":"dead"});
        }
        guard(&i, &c).unwrap();
        let mut bad = i.clone();
        bad["available_bytes"] = json!(FLOOR);
        assert!(guard(&bad, &c).is_err());
        let mut bad = c.clone();
        bad["scratch_deleted"] = json!(true);
        assert!(guard(&i, &bad).is_err());
        let mut bad = c;
        bad["producer_final"]["main_pid"] = json!(9);
        assert!(guard(&i, &bad).is_err());
    }
    #[test]
    fn terminal_shape_rejects_live_queued_and_replacement() {
        let v = json!({"Id":PRODUCER,"MainPID":"0","NRestarts":"0","Job":"","ActiveState":"inactive","SubState":"dead","InvocationID":"","LoadState":"not-found"});
        stopped(&v, PRODUCER, PID).unwrap();
        for (k, n) in [
            ("MainPID", "2"),
            ("Job", "9"),
            ("InvocationID", "foreign"),
            ("ActiveState", "active"),
        ] {
            let mut b = v.clone();
            b[k] = json!(n);
            assert!(stopped(&b, PRODUCER, PID).is_err());
        }
    }
    #[test]
    fn manager_lifecycle_requires_exact_latest_start_and_stop() {
        let start = json!({"UNIT":PRODUCER,"_PID":"1","_UID":"0","INVOCATION_ID":PID,"MESSAGE_ID":"39f53479d3a045ac8e11786248231fbf","__REALTIME_TIMESTAMP":"100"});
        let mut stop = start.clone();
        stop["MESSAGE_ID"] = json!("9d1aaa27d60140bd96365438aad20286");
        stop["__REALTIME_TIMESTAMP"] = json!("101");
        stop["JOB_TYPE"] = json!("stop");
        stop["JOB_RESULT"] = json!("done");
        lifecycle(&[start.clone(), stop.clone()], PRODUCER, PID).unwrap();
        assert!(lifecycle(std::slice::from_ref(&start), PRODUCER, PID).is_err());
        let mut foreign = start.clone();
        foreign["INVOCATION_ID"] = json!("foreign");
        foreign["__REALTIME_TIMESTAMP"] = json!("102");
        assert!(lifecycle(&[start, stop, foreign], PRODUCER, PID).is_err());
    }
}
