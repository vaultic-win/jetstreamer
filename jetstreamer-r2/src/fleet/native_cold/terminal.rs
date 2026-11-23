// Independent terminal decision for the original guarded bootstrap.
use super::current as c;
use super::*;
use crate::fleet::native265::{binding, deny, namespace, num, sealed, text};
pub(in crate::fleet) const SCHEMA: &str =
    epoch_name!("jetstreamer-private-epoch", "-native-terminal-proof-v1");
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    running_origin: BoundFile,
    observer: BoundFile,
    fleet: BoundFile,
    output: PathBuf,
}
pub(in crate::fleet) fn matches(unit: &Value, proof: &Value) -> Result<()> {
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
            "native bootstrap terminal status owner changed {k}"
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
        "native bootstrap producer not terminal"
    );
    Ok(())
}
pub(super) fn decision(
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
            "native bootstrap terminal journal clock/boot"
        );
        last = at;
        let msg = text(r, "MESSAGE")?;
        if r["_PID"] == "1" {
            ensure!(
                r["_UID"] == "0" && r["UNIT"] == c::UNIT && r["INVOCATION_ID"] == iid,
                "native bootstrap foreign PID1 terminal row"
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
                    "native bootstrap duplicate PID1 terminal"
                );
            }
        } else {
            ensure!(
                r["_PID"] == pid
                    && r["_UID"] == "1000"
                    && r["_SYSTEMD_UNIT"] == c::UNIT
                    && r["_SYSTEMD_INVOCATION_ID"] == iid
                    && r["_EXE"] == c::TEST,
                "native bootstrap foreign harness journal row"
            );
            if msg
                == epoch_name!(
                    "epoch",
                    " exact cold input completed; native PID1 and complete guard-history acceptance remain required"
                )
            {
                ensure!(
                    marker.replace(at).is_none(),
                    "native bootstrap duplicate harness success"
                );
            }
            if let Some(reason) = msg.strip_prefix(epoch_name!("epoch", " cold input failed: ")) {
                ensure!(
                    !reason.trim().is_empty() && failure.replace((reason.to_owned(), at)).is_none(),
                    "native bootstrap ambiguous harness failure"
                );
            }
        }
    }
    let (good, wall, end) = finished.context("native bootstrap missing original PID1 terminal")?;
    let within_runtime = if EPOCH == 266 {
        // The epoch 266 producer template sets RuntimeMaxSec=7200 and TimeoutStopSec=30.
        let producer = &h["producer"];
        let start = text(producer, "ExecMainStartTimestampMonotonic")?.parse::<u64>()?;
        producer["RuntimeMaxUSec"] == "2h"
            && start >= issued
            && start <= end
            && end - start <= 7_230_000_000
    } else {
        end >= issued && end - issued <= 2_760_000_000
    };
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
            && within_runtime
            && marker.is_none_or(|t| t < end)
            && failure.as_ref().is_none_or(|(_, t)| *t < end),
        "native bootstrap terminal manager/clock differs"
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
            "native bootstrap success lacks original harness completion"
        );
        return Ok((true, "bootstrap checkpoint verified".into(), wall, end));
    }
    ensure!(
        !good
            && manager["ActiveState"] == "failed"
            && manager["SubState"] == "failed"
            && manager["Result"] != "success"
            && manager["ExecMainStatus"] != "0",
        "native bootstrap ambiguous failed terminal"
    );
    let cause = failure.map(|(cause, _)| cause).unwrap_or_else(|| {
        format!(
            "PID1 result {}, process status {}",
            manager["Result"], manager["ExecMainStatus"]
        )
    });
    Ok((false, cause, wall, end))
}
pub(super) fn native_result(v: &Value, origin: &Value, h: &Value) -> Result<u64> {
    if EPOCH == 266 {
        ensure!(v["handshake"]["solana_tag"] == "v1.8.11"
            && v["handshake"]["rust_toolchain"] == "rustc 1.52.1 (9bc8c42bb 2021-05-09)"
            && v["handshake"]["target"] == "x86_64-unknown-linux-gnu"
            && v["initialized"]["ticks_per_slot"] == 64
            && v["checkpoint"]["last_blockhash"] == v["initialized"]["last_blockhash"],
            "epoch 266 worker fingerprint, tick rate or blockhash changed");
    }
    native265_history::result_for(
        v,
        origin,
        h,
        EPOCH,
        epoch_name!("horizon", "-exact-worker-cold-input-result-v1"),
        c::SLOT,
        c::ACCOUNTS_HASH,
        c::SNAPSHOT_SHA,
        c::SNAPSHOT,
        c::PROFILE.worker,
    )
}
fn registered(s: &Spec) -> Result<(Value, Value, Value, Value)> {
    ensure!(
        s.schema == epoch_name!("jetstreamer-native", "-terminal-capture-spec-v1"),
        "native bootstrap terminal spec"
    );
    namespace(
        &s.output,
        epoch_name!("horizon-native", "-terminal-proof-"),
        "proof.json",
    )?;
    let f = bound_json(&s.fleet)?;
    let o = bound_json(&s.observer)?;
    ensure!(
        f["schema"] == crate::fleet::SCHEMA
            && f["first_epoch"] == 201
            && f["last_epoch"] == 300
            && f["observer_receipt"].as_str() == s.observer.path.to_str()
            && f["observer_sha256"] == s.observer.sha256
            && f["sampled_at_utc"] == o["recorded_at_utc"],
        "native bootstrap terminal observer/fleet substituted"
    );
    let p = event::prior(&f)?;
    let origin=sealed(&s.running_origin)?;
    if UNIT == native257::UNIT && native257::recovered_origin(&origin) {
        let claim = PipelineClaim {
            epoch: EPOCH, phase: c::PHASE.to_owned(), unit: UNIT.to_owned(),
            invocation_id: text(&origin,"invocation_id")?.to_owned(),
            expected_exec_start: text(&origin,"expected_exec_start")?.to_owned(),
            evidence: vec![s.running_origin.clone()],
        };
        if let Some(old) = event::owner(&p)? && old != &claim {
            c::claim(&claim)?;
            native257::verify_replacement(old, &claim, &origin, &p)?;
            let (h, a) = c::startup(&binding(&origin["startup_handoff"])?)?;
            ensure!(s.fleet == binding(&a["fleet"])? && s.observer == binding(&a["observer"])? && p.observer == s.observer,
                "replacement terminal must bind its original admission");
            return Ok((origin,h,a,f));
        }
    }
    if UNIT==native266::UNIT && origin["schema"]==native266_recovery::SCHEMA && event::owner(&p)?.is_none(){
        let claim: PipelineClaim=serde_json::from_value(json!({"epoch":EPOCH,"phase":c::PHASE,"unit":c::UNIT,"invocation_id":origin["invocation_id"],"expected_exec_start":origin["expected_exec_start"],"evidence":[private157::binding(&s.running_origin)]}))?;
        c::claim(&claim)?;
        let (h,a)=c::startup(&binding(&origin["startup_handoff"])?)?;
        ensure!(s.fleet == binding(&a["fleet"])? && s.observer==binding(&a["observer"])? && p.observer==s.observer,"direct terminal must bind admitted original fleet");
        return Ok((origin,h,a,f));
    }
    let claim = event::owner(&p)?
        .context("native bootstrap terminal lacks original registered running claim")?;
    ensure!(
        claim.evidence == [s.running_origin.clone()] && p.observer == s.observer,
        "native bootstrap registered claim/observer mismatch"
    );
    let origin = sealed(&s.running_origin)?;
    let (h, a) = c::startup(&binding(&origin["startup_handoff"])?)?;
    Ok((origin, h, a, f))
}
fn validate_parts(proof: &Value, output: &Path) -> Result<Vec<u64>> {
    let sb = binding(&proof["capture_spec"])?;
    let s: Spec = serde_json::from_value(sealed(&sb)?)?;
    let (origin, h, a, f) = registered(&s)?;
    if UNIT == native257::UNIT && native257::recovered_origin(&origin) {
        native257::terminal_helper(&origin, &a, text(proof,"capture_helper_sha256")?, false)?;
    } else if UNIT==native266::UNIT && origin["schema"]==native266_recovery::SCHEMA {
        native266_recovery::successor(&a,text(proof,"capture_helper_sha256")?,false)?;
    } else { c::helper(&a, text(proof, "capture_helper_sha256")?, false)?; }
    ensure!(
        s.output == output
            && proof["schema"] == SCHEMA
            && proof["epoch"] == EPOCH
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
        "native bootstrap terminal claim or authority differs"
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
            .context("native bootstrap terminal journal")?,
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
            "failed native bootstrap counted native result"
        );
        None
    };
    let (ids, _) = history::validate(
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
        "native bootstrap terminal decision evidence differs"
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
pub(in crate::fleet) fn validate(v: &Value, b: &BoundFile) -> Result<()> {
    ensure!(sealed(b)? == *v, "native bootstrap terminal proof changed");
    validate_parts(v, &b.path)?;
    Ok(())
}
pub(super) fn actual_journal(h: &Value) -> Result<Vec<Value>> {
    let iid = text(h, "invocation_id")?;
    guard::journal(&[
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
        "native bootstrap result custody"
    );
    Ok(serde_json::from_slice(&read_stable_bounded(
        &path,
        2 << 20,
        "native bootstrap actual bootstrap result",
    )?)?)
}
pub(in crate::fleet) fn capture() -> Result<()> {
    let (b, actor) = publication203::parsed_args(epoch_name!("capture-native", "-terminal"))?;
    let s: Spec = serde_json::from_value(sealed(&b)?)?;
    let (origin,h,a,f)=registered(&s)?;
    let recovered=UNIT==native266::UNIT && origin["schema"]==native266_recovery::SCHEMA;
    if UNIT == native257::UNIT && native257::recovered_origin(&origin) {
        native257::terminal_helper(&origin,&a,&actor,true)?;
    } else if recovered {native266_recovery::successor(&a,&actor,true)?;} else {c::helper(&a,&actor,true)?;}
    ensure!(
        a["boot_id"] == fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim(),
        "native bootstrap terminal boot changed"
    );
    if s.output.try_exists()? {
        let reference = binding(&private157::file_binding(&s.output)?)?;
        let old = sealed(&reference)?;
        ensure!(
            old["capture_spec"] == private157::binding(&b) && old["capture_helper_sha256"] == actor,
            "native bootstrap terminal retry changed"
        );
        return validate(&old, &reference);
    }
    let names = f["unit_census"]
        .as_object()
        .context("native bootstrap peer census")?
        .keys()
        .cloned()
        .collect();
    let before = census(&names, 201, 300)?;
    if recovered { native266_recovery::peers(&f,&before,c::UNIT)?; } else { native265_capture::peers(&f, &before, c::UNIT)?; }
    let m = c::properties()?;
    c::retention(&h)?;
    let gp = sealed(&binding(&h["guard_plan"])?)?;
    let issued = num(
        &sealed(&binding(&h["startup_plan"])?)?,
        "issued_monotonic_us",
    )?;
    let history = history::actual(&h, &gp, &a, issued)?;
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
    let mut proof = json!({"schema":SCHEMA,"epoch":EPOCH,"unit":c::UNIT,"main_pid":h["main_pid"],"invocation_id":h["invocation_id"],"boot_id":a["boot_id"],"capture_spec":private157::binding(&b),"capture_helper_sha256":actor,
        "observer":private157::binding(&s.observer),"fleet":private157::binding(&s.fleet),"running_origin":private157::binding(&s.running_origin),"sampled_at_utc":f["sampled_at_utc"],
        "resource_samples_taken":0,"ordinary_replay_claim":false,"resource_release_authorized":false,"native_input_qualified":clean,"repair_backlog_retained":!clean,"cause":cause,"recorded_unix_seconds":c::now()?,
        "terminal_unix_microseconds":wall,"terminal_monotonic_microseconds":end,"terminal_manager":m,"terminal_retention":retention_subset(&h)?,"producer_journal":journal,"guard_history":history,"native_result":result});
    deny(&mut proof);
    let ids = validate_parts(&proof, &s.output)?;
    native265_process::drained_for(c::UNIT, &ids)?;
    ensure!(
        c::properties()? == m
            && history::actual(&h, &gp, &a, issued)? == history
            && actual_journal(&h)? == journal
            && (!clean || actual_result()? == result)
            && census(&names, 201, 300)? == before,
        "native bootstrap terminal evidence changed during capture"
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
        let h = json!({"invocation_id":iid,"main_pid":42,"producer":{"ExecMainStartTimestampMonotonic":"120","RuntimeMaxUSec":"2h"}});
        let mut m = json!({"Id":c::UNIT,"InvocationID":iid,"ExecMainPID":"42","MainPID":"0","ControlPID":"0","NRestarts":"0","Restart":"no","KillMode":"control-group","Delegate":"no","Job":"","TriggeredBy":"","LoadState":"loaded","ActiveState":"inactive","SubState":"dead","Result":"success","ExecMainCode":"1","ExecMainStatus":"0"});
        let harness = json!({"_PID":"42","_UID":"1000","_EXE":c::TEST,"_BOOT_ID":"boot","_SYSTEMD_UNIT":c::UNIT,"_SYSTEMD_INVOCATION_ID":iid,"__MONOTONIC_TIMESTAMP":"150","__REALTIME_TIMESTAMP":"1000000","MESSAGE":epoch_name!("epoch", " exact cold input completed; native PID1 and complete guard-history acceptance remain required")});
        let pid1 = json!({"_PID":"1","_UID":"0","_BOOT_ID":"boot","UNIT":c::UNIT,"INVOCATION_ID":iid,"__MONOTONIC_TIMESTAMP":"200","__REALTIME_TIMESTAMP":"1000050","MESSAGE":format!("{}: Deactivated successfully.",c::UNIT)});
        let mut rows = vec![harness, pid1];
        assert!(decision(&rows, &m, &h, "boot", 100, None).unwrap().0);
        assert!(decision(&rows[1..], &m, &h, "boot", 100, None).is_err());
        let mut late = rows.clone();
        late[1]["__MONOTONIC_TIMESTAMP"] = json!("3600000120");
        assert_eq!(decision(&late, &m, &h, "boot", 100, None).is_ok(), EPOCH == 266);
        late[1]["__MONOTONIC_TIMESTAMP"] = json!("7230000121");
        assert!(decision(&late, &m, &h, "boot", 100, None).is_err());
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
        rows[0]["MESSAGE"] = json!(epoch_name!(
            "epoch",
            " cold input failed: checkpoint mismatch"
        ));
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
