//! Exact guard-stopped185 terminal transition. Metadata only; retained bytes and
//! every historical growth/floor obligation remain protected.
use super::*;
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
            "duplicate185 manager field"
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
fn no_live185() -> Result<()> {
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
        ensure!(
            v["MainPID"].as_str().and_then(|n| n.parse::<u32>().ok()) == Some(std::process::id()),
            "185 has another live/activating replacement or downstream owner"
        );
    }
    Ok(())
}
fn proof_value(v: &Value, cutoff: u64) -> Result<()> {
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
        "foreign185 guard paths"
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
    no_live185()
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
    proof_value(&v, utc_seconds(&p.sample_target_utc)?)
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
        "foreign185 capture plan"
    );
    let ib: Bound = serde_json::from_value(s["guard_intent"].clone())?;
    let cb: Bound = serde_json::from_value(s["guard_completion"].clone())?;
    ensure!(
        ib.path == Path::new(GUARD).join("intent.json")
            && cb.path == Path::new(GUARD).join("completion.json"),
        "foreign185 guard paths"
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
    proof_value(&v, now)?;
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
pub(super) fn enable(p: &mut Plan, c: &mut Value, spec: &Bound) -> Result<()> {
    let v = bound_json(spec, true)?;
    ensure!(
        v["schema"] == "jetstreamer-guard-stopped185-routine-handoff-v2"
            && v["replay_launch_authorized"] == false
            && v["publication_authorized"] == false
            && v["r2_mutations"] == false
            && p.terminal185.is_none(),
        "foreign185 handoff"
    );
    p.terminal185 = Some(serde_json::from_value(v["profile"].clone())?);
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
        "Controlled disk-floor stop at80099168 before80351999. Preserve partial/scratch/launch/guard proof; establish an actual durable native checkpoint or independently qualified cold recovery, then fresh guarded capacity admission. No resume or growth-release credit. Old185 status is stale pending qualified lifecycle; no R2 deletion authorized."
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
