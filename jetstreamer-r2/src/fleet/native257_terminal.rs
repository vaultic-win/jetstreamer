//! Independent terminal decision for the original guarded bootstrap.
use super::native257 as c;
use super::native265::{binding, deny, namespace, num, sealed, text};
use super::*;
pub(super) const SCHEMA: &str = "jetstreamer-private-epoch257-native-terminal-proof-v1";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    running_origin: BoundFile,
    observer: BoundFile,
    fleet: BoundFile,
    output: PathBuf,
}
pub(super) fn matches(unit: &Value, proof: &Value) -> Result<()> {
    let original = &proof["terminal_manager"];
    for k in [
        "Id",
        "LoadState",
        "MainPID",
        "InvocationID",
        "NRestarts",
        "ActiveState",
        "SubState",
        "Result",
        "ExecMainStatus",
    ] {
        ensure!(
            text(unit, k)? == text(original, k)?,
            "native257 terminal status owner changed {k}"
        );
    }
    ensure!(
        unit["Id"] == c::UNIT
            && unit["LoadState"] == "loaded"
            && unit["MainPID"] == "0"
            && unit["InvocationID"] == proof["invocation_id"]
            && unit["NRestarts"] == "0"
            && (unit["ActiveState"] == "inactive" && unit["SubState"] == "dead"
                || unit["ActiveState"] == "failed" && unit["SubState"] == "failed"),
        "native257 producer not terminal"
    );
    Ok(())
}
fn decision(
    rows: &[Value],
    manager: &Value,
    h: &Value,
    boot: &str,
    issued: u64,
    stop: Option<&Value>,
) -> Result<(bool, String, u64, u64)> {
    let iid = text(h, "invocation_id")?;
    let pid = num(h, "main_pid")?.to_string();
    let mut last = issued;
    let mut marker = None;
    let mut failure = None;
    let mut finished = None;
    for r in rows {
        let at = text(r, "__MONOTONIC_TIMESTAMP")?.parse::<u64>()?;
        let realtime = text(r, "__REALTIME_TIMESTAMP")?.parse::<u64>()?;
        ensure!(
            r["_BOOT_ID"] == boot.replace('-', "") && at >= last,
            "native257 terminal journal clock/boot"
        );
        last = at;
        let msg = text(r, "MESSAGE")?;
        if r["_PID"] == "1" {
            ensure!(
                r["_UID"] == "0" && r["UNIT"] == c::UNIT && r["INVOCATION_ID"] == iid,
                "native257 foreign PID1 terminal row"
            );
            let good = msg == format!("{}: Deactivated successfully.", c::UNIT);
            if good
                || msg
                    == format!(
                        "{}: Failed with result '{}'.",
                        c::UNIT,
                        text(manager, "Result")?
                    )
            {
                ensure!(
                    finished.replace((good, realtime, at)).is_none(),
                    "native257 duplicate PID1 terminal"
                );
            }
        } else {
            ensure!(
                r["_PID"] == pid
                    && r["_UID"] == "1000"
                    && r["_SYSTEMD_UNIT"] == c::UNIT
                    && r["_SYSTEMD_INVOCATION_ID"] == iid
                    && r["_EXE"] == c::TEST,
                "native257 foreign harness journal row"
            );
            if msg
                == "epoch257 exact cold input completed; native PID1 and complete guard-history acceptance remain required"
            {
                ensure!(
                    marker.replace(at).is_none(),
                    "native257 duplicate harness success"
                );
            }
            if let Some(reason) = msg.strip_prefix("epoch257 cold input failed: ") {
                ensure!(
                    !reason.trim().is_empty() && failure.replace((reason.to_owned(), at)).is_none(),
                    "native257 ambiguous harness failure"
                );
            }
        }
    }
    let (good, wall, end) = finished.context("native257 missing original PID1 terminal")?;
    ensure!(
        manager["Id"] == c::UNIT
            && manager["InvocationID"] == iid
            && manager["ExecMainPID"] == pid
            && manager["MainPID"] == "0"
            && manager["ControlPID"] == "0"
            && manager["NRestarts"] == "0"
            && manager["Restart"] == "no"
            && manager["KillMode"] == "control-group"
            && manager["Delegate"] == "no"
            && manager["Job"] == ""
            && manager["TriggeredBy"] == ""
            && manager["LoadState"] == "loaded"
            && end >= issued
            && end - issued <= 2_760_000_000
            && marker.is_none_or(|t| t < end)
            && failure.as_ref().is_none_or(|(_, t)| *t < end),
        "native257 terminal manager/clock differs"
    );
    let successful = good
        && manager["ActiveState"] == "inactive"
        && manager["SubState"] == "dead"
        && manager["Result"] == "success"
        && manager["ExecMainCode"] == "1"
        && manager["ExecMainStatus"] == "0";
    if let Some(intent) = stop {
        return Ok((
            false,
            format!("protective stop: {}", text(intent, "reason")?),
            wall,
            end,
        ));
    }
    if successful {
        ensure!(
            marker.is_some() && failure.is_none(),
            "native257 success lacks original harness completion"
        );
        return Ok((true, "bootstrap checkpoint verified".into(), wall, end));
    }
    ensure!(
        !good
            && manager["ActiveState"] == "failed"
            && manager["SubState"] == "failed"
            && manager["Result"] != "success"
            && manager["ExecMainStatus"] != "0",
        "native257 ambiguous failed terminal"
    );
    let cause = failure.map(|(cause, _)| cause).unwrap_or_else(|| {
        format!(
            "PID1 result {}, process status {}",
            manager["Result"], manager["ExecMainStatus"]
        )
    });
    Ok((false, cause, wall, end))
}
fn native_result(v: &Value, origin: &Value, h: &Value) -> Result<u64> {
    native265_history::result_for(
        v,
        origin,
        h,
        257,
        "horizon257-exact-worker-cold-input-result-v1",
        111_022_755,
        "8bRdfjkM7Lst2wWtAyv56VKTprAYt1DKPuVy2HzK1wX3",
        "3e2b236f2cba29fbfe40f39f133fe9c845df9280e3fc6dd1cb70e4e018a4744d",
        "/var/lib/jetstreamer/horizon-contiguous-257-260-current-46b4b4a-v1/snapshot-111022755-8bRdfjkM7Lst2wWtAyv56VKTprAYt1DKPuVy2HzK1wX3.tar.zst",
    )
}
fn registered(s: &Spec) -> Result<(Value, Value, Value, Value)> {
    ensure!(
        s.schema == "jetstreamer-native257-terminal-capture-spec-v1",
        "native257 terminal spec"
    );
    namespace(&s.output, "horizon-native257-terminal-proof-", "proof.json")?;
    let f = bound_json(&s.fleet)?;
    let o = bound_json(&s.observer)?;
    ensure!(
        f["schema"] == super::SCHEMA
            && f["first_epoch"] == 201
            && f["last_epoch"] == 300
            && f["observer_receipt"].as_str() == s.observer.path.to_str()
            && f["observer_sha256"] == s.observer.sha256
            && f["sampled_at_utc"] == o["recorded_at_utc"],
        "native257 terminal observer/fleet substituted"
    );
    let p = native257_event::prior(&f)?;
    let claim = native257_event::owner(&p)?
        .context("native257 terminal lacks original registered running claim")?;
    ensure!(
        claim.evidence == [s.running_origin.clone()] && p.observer == s.observer,
        "native257 registered claim/observer mismatch"
    );
    let origin = sealed(&s.running_origin)?;
    let (h, a) = c::startup(&binding(&origin["startup_handoff"])?)?;
    Ok((origin, h, a, f))
}
fn validate_parts(proof: &Value, output: &Path) -> Result<Vec<u64>> {
    let sb = binding(&proof["capture_spec"])?;
    let s: Spec = serde_json::from_value(sealed(&sb)?)?;
    let (origin, h, a, f) = registered(&s)?;
    c::helper(&a, text(proof, "capture_helper_sha256")?, false)?;
    ensure!(
        s.output == output
            && proof["schema"] == SCHEMA
            && proof["epoch"] == 257
            && proof["unit"] == c::UNIT
            && proof["main_pid"] == h["main_pid"]
            && proof["invocation_id"] == h["invocation_id"]
            && proof["boot_id"] == a["boot_id"]
            && proof["running_origin"] == private157::binding(&s.running_origin)
            && proof["fleet"] == private157::binding(&s.fleet)
            && proof["observer"] == private157::binding(&s.observer)
            && proof["sampled_at_utc"] == f["sampled_at_utc"]
            && proof["resource_samples_taken"] == 0
            && proof["ordinary_replay_claim"] == false
            && proof["resource_release_authorized"] == false,
        "native257 terminal claim or authority differs"
    );
    native265::no_authority(proof)?;
    matches(&proof["terminal_manager"], proof)?;
    let gp = sealed(&binding(&h["guard_plan"])?)?;
    let issued = num(
        &sealed(&binding(&h["startup_plan"])?)?,
        "issued_monotonic_us",
    )?;
    let records = &proof["guard_history"]["records"];
    let (clean, cause, wall, end) = decision(
        proof["producer_journal"]
            .as_array()
            .context("native257 terminal journal")?,
        &proof["terminal_manager"],
        &h,
        text(&a, "boot_id")?,
        issued,
        records.get("stop-intent.json"),
    )?;
    let worker = if clean {
        Some(native_result(&proof["native_result"], &origin, &h)?)
    } else {
        ensure!(
            proof.get("native_result") == Some(&Value::Null),
            "failed native257 counted native result"
        );
        None
    };
    let (ids, _) = native257_history::validate(
        &proof["guard_history"],
        &h,
        &gp,
        issued,
        end,
        &proof["terminal_manager"],
        clean,
        worker,
    )?;
    ensure!(
        proof["native_input_qualified"] == clean
            && proof["repair_backlog_retained"] == !clean
            && proof["cause"] == cause
            && proof["terminal_unix_microseconds"] == wall
            && proof["terminal_monotonic_microseconds"] == end
            && num(proof, "recorded_unix_seconds")? >= wall / 1_000_000
            && proof["terminal_retention"] == retention_subset(&h)?,
        "native257 terminal decision evidence differs"
    );
    Ok(ids)
}
fn retention_subset(h: &Value) -> Result<Value> {
    let r = &h["retention"];
    let mut v = serde_json::Map::new();
    for k in [
        "Id",
        "LoadState",
        "ActiveState",
        "SubState",
        "IgnoreOnIsolate",
        "DefaultDependencies",
        "DropInPaths",
        "Job",
        "Wants",
        "Requires",
        "BindsTo",
        "Upholds",
        "FragmentPath",
    ] {
        v.insert(k.to_owned(), json!(text(r, k)?));
    }
    Ok(Value::Object(v))
}
pub(super) fn validate(v: &Value, b: &BoundFile) -> Result<()> {
    ensure!(sealed(b)? == *v, "native257 terminal proof changed");
    validate_parts(v, &b.path)?;
    Ok(())
}
fn actual_journal(h: &Value) -> Result<Vec<Value>> {
    let iid = text(h, "invocation_id")?;
    native257_guard::journal(&[
        "_PID=1".into(),
        format!("UNIT={}", c::UNIT),
        format!("INVOCATION_ID={iid}"),
        "+".into(),
        format!("_SYSTEMD_UNIT={}", c::UNIT),
        format!("_SYSTEMD_INVOCATION_ID={iid}"),
        format!("_PID={}", num(h, "main_pid")?),
    ])
}
fn actual_result() -> Result<Value> {
    let path = Path::new(c::ROOT).join("native-result.json");
    let m = fs::symlink_metadata(&path)?;
    ensure!(
        m.is_file() && m.uid() == 1000 && m.nlink() == 1 && path.canonicalize()? == path,
        "native257 result custody"
    );
    Ok(serde_json::from_slice(&read_stable_bounded(
        &path,
        2 << 20,
        "native257 actual bootstrap result",
    )?)?)
}
pub(super) fn capture() -> Result<()> {
    let (b, actor) = publication203::parsed_args("capture-native257-terminal")?;
    let s: Spec = serde_json::from_value(sealed(&b)?)?;
    let (_, h, a, f) = registered(&s)?;
    c::helper(&a, &actor, true)?;
    ensure!(
        a["boot_id"] == fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim(),
        "native257 terminal boot changed"
    );
    if s.output.try_exists()? {
        let reference = binding(&private157::file_binding(&s.output)?)?;
        let old = sealed(&reference)?;
        ensure!(
            old["capture_spec"] == private157::binding(&b) && old["capture_helper_sha256"] == actor,
            "native257 terminal retry changed"
        );
        return validate(&old, &reference);
    }
    let names = f["unit_census"]
        .as_object()
        .context("native257 peer census")?
        .keys()
        .cloned()
        .collect();
    let before = census(&names, 201, 300)?;
    native265_capture::peers(&f, &before, c::UNIT)?;
    let m = c::properties()?;
    c::retention(&h)?;
    let gp = sealed(&binding(&h["guard_plan"])?)?;
    let issued = num(
        &sealed(&binding(&h["startup_plan"])?)?,
        "issued_monotonic_us",
    )?;
    let history = native257_history::actual(&h, &gp, &a, issued)?;
    let journal = actual_journal(&h)?;
    let (clean, cause, wall, end) = decision(
        &journal,
        &m,
        &h,
        text(&a, "boot_id")?,
        issued,
        history["records"].get("stop-intent.json"),
    )?;
    let result = if clean { actual_result()? } else { Value::Null };
    let mut proof = json!({"schema":SCHEMA,"epoch":257,"unit":c::UNIT,"main_pid":h["main_pid"],"invocation_id":h["invocation_id"],"boot_id":a["boot_id"],"capture_spec":private157::binding(&b),"capture_helper_sha256":actor,
        "observer":private157::binding(&s.observer),"fleet":private157::binding(&s.fleet),"running_origin":private157::binding(&s.running_origin),"sampled_at_utc":f["sampled_at_utc"],
        "resource_samples_taken":0,"ordinary_replay_claim":false,"resource_release_authorized":false,"native_input_qualified":clean,"repair_backlog_retained":!clean,"cause":cause,"recorded_unix_seconds":c::now()?,
        "terminal_unix_microseconds":wall,"terminal_monotonic_microseconds":end,"terminal_manager":m,"terminal_retention":retention_subset(&h)?,"producer_journal":journal,"guard_history":history,"native_result":result});
    deny(&mut proof);
    let ids = validate_parts(&proof, &s.output)?;
    native265_process::drained_for(c::UNIT, &ids)?;
    ensure!(
        c::properties()? == m
            && native257_history::actual(&h, &gp, &a, issued)? == history
            && actual_journal(&h)? == journal
            && (!clean || actual_result()? == result)
            && census(&names, 201, 300)? == before,
        "native257 terminal evidence changed during capture"
    );
    native265_process::drained_for(c::UNIT, &ids)?;
    private157::immutable_receipt(&s.output, &proof)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn original_harness_pid1_and_failure_cause_determine_the_terminal_decision() {
        let iid = "a".repeat(32);
        let h = json!({"invocation_id":iid,"main_pid":42});
        let mut m = json!({"Id":c::UNIT,"InvocationID":iid,"ExecMainPID":"42","MainPID":"0","ControlPID":"0","NRestarts":"0","Restart":"no","KillMode":"control-group","Delegate":"no","Job":"","TriggeredBy":"","LoadState":"loaded","ActiveState":"inactive","SubState":"dead","Result":"success","ExecMainCode":"1","ExecMainStatus":"0"});
        let harness = json!({"_PID":"42","_UID":"1000","_EXE":c::TEST,"_BOOT_ID":"boot","_SYSTEMD_UNIT":c::UNIT,"_SYSTEMD_INVOCATION_ID":iid,"__MONOTONIC_TIMESTAMP":"150","__REALTIME_TIMESTAMP":"1000000","MESSAGE":"epoch257 exact cold input completed; native PID1 and complete guard-history acceptance remain required"});
        let pid1 = json!({"_PID":"1","_UID":"0","_BOOT_ID":"boot","UNIT":c::UNIT,"INVOCATION_ID":iid,"__MONOTONIC_TIMESTAMP":"200","__REALTIME_TIMESTAMP":"1000050","MESSAGE":format!("{}: Deactivated successfully.",c::UNIT)});
        let mut rows = vec![harness, pid1];
        assert!(decision(&rows, &m, &h, "boot", 100, None).unwrap().0);
        assert!(decision(&rows[1..], &m, &h, "boot", 100, None).is_err());
        for (idx, key) in [
            (0, "_EXE"),
            (0, "_PID"),
            (0, "_SYSTEMD_INVOCATION_ID"),
            (1, "_UID"),
            (1, "UNIT"),
            (1, "INVOCATION_ID"),
        ] {
            let mut bad = rows.clone();
            bad[idx][key] = Value::Null;
            assert!(decision(&bad, &m, &h, "boot", 100, None).is_err(), "{key}");
        }
        rows[0]["MESSAGE"] = json!("epoch257 cold input failed: checkpoint mismatch");
        rows[1]["MESSAGE"] = json!(format!("{}: Failed with result 'exit-code'.", c::UNIT));
        m["ActiveState"] = json!("failed");
        m["SubState"] = json!("failed");
        m["ExecMainStatus"] = json!("1");
        m["Result"] = json!("exit-code");
        let (clean, cause, _, _) = decision(&rows, &m, &h, "boot", 100, None).unwrap();
        assert!(!clean);
        assert_eq!(cause, "checkpoint mismatch");
        let proof = json!({"invocation_id":iid,"terminal_manager":m});
        matches(&m, &proof).unwrap();
        m["InvocationID"] = json!("b".repeat(32));
        assert!(matches(&m, &proof).is_err());
    }
}
