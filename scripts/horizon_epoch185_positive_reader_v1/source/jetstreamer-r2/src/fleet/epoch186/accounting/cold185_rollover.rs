//! Exact registered epoch 185 guard rollover comparison. Every raw snapshot and
//! immutable completed receipt stays in the original complete-reader output.
use super::*;

fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v[key]
        .as_str()
        .with_context(|| format!("cold185 guard missing {key}"))
}
fn integer(v: &Value, key: &str) -> Result<u64> {
    v[key]
        .as_u64()
        .with_context(|| format!("cold185 guard missing integer {key}"))
}
fn monotonic(v: &Value, key: &str) -> Result<u64> {
    Ok(text(v, key)?.parse::<u64>()?)
}
fn timer_schedule(value: &Value) -> Result<()> {
    let mut bases = BTreeSet::new();
    for line in value.as_str().context("cold185 timer schedule")?.lines() {
        let inner = line
            .strip_prefix("{ ")
            .and_then(|s| s.strip_suffix(" }"))
            .context("cold185 timer schedule framing")?;
        let (base, deadline) = inner
            .split_once(" ; next_elapse=")
            .context("cold185 timer next deadline")?;
        ensure!(
            ["OnActiveUSec=1s", "OnUnitInactiveUSec=30s"].contains(&base)
                && !deadline.is_empty()
                && bases.insert(base),
            "cold185 guard timer cadence changed"
        );
    }
    ensure!(
        bases.len() == 2,
        "cold185 missing exact first and periodic guard schedule"
    );
    Ok(())
}

fn completed_command(native: &Value) -> Result<()> {
    let command = text(native, "ExecStart")?;
    ensure!(
        [
            " ; code=exited ; status=0/0 }",
            " ; code=exited ; status=0/SUCCESS }",
            " ; code=exited ; status=0 }"
        ]
        .iter()
        .any(|suffix| command.ends_with(suffix)),
        "cold185 completed guard command does not report genuine success"
    );
    if let Some(code) = native.get("ExecMainCode") {
        ensure!(code == "1", "cold185 completed guard did not exit normally");
    }
    Ok(())
}

/// A side's freshness is assessed at its real capture. The original finite
/// reader booking separately bounds the complete transaction. This lets two
/// genuine completed fires bracket a reader longer than the guard cadence.
fn history_values(
    history: &Value,
    actor: &str,
    actor_iid: &str,
    admission_sha: &str,
) -> Result<()> {
    let guard = text(history, "guard_unit")?;
    let timer = text(history, "timer_unit")?;
    let sampled = integer(history, "captured_at")?;
    let receipt = &history["receipt_value"];
    let native = &history["native_guard"];
    let timer_native = &history["native_timer"];
    let iid = text(native, "InvocationID")?;
    ensure!(
        digest(actor_iid, 32)
            && digest(iid, 32)
            && digest(admission_sha, 64)
            && receipt["schema"] == "horizon-epoch185-native-guard-result-v4"
            && receipt["epoch"] == 185
            && receipt["actor_unit"] == actor
            && receipt["actor_invocation_id"] == actor_iid
            && receipt["admission_sha256"] == admission_sha
            && receipt["guard_invocation_id"] == iid
            && receipt["timer_unit"] == timer
            && receipt["timer_driven"] == true
            && receipt["success"] == true
            && receipt["failure"].is_null()
            && receipt["capacity_credit_bytes"] == 0,
        "cold185 completed guard receipt has crossed owner/admission/IID, trip or credit"
    );
    let at = integer(receipt, "sampled_at")?;
    ensure!(
        at <= sampled && sampled - at <= 90,
        "cold185 successful guard was not fresh at actual side capture"
    );
    let trigger = integer(receipt, "timer_last_trigger_monotonic_micros")?;
    let started = integer(receipt, "guard_start_monotonic_micros")?;
    ensure!(
        trigger > 0
            && trigger <= started
            && started - trigger <= 5_000_000
            && monotonic(timer_native, "LastTriggerUSecMonotonic")? == trigger
            && monotonic(native, "ExecMainStartTimestampMonotonic")? == started,
        "cold185 guard receipt is not the genuine observed timer fire"
    );
    for (key, value) in [
        ("Id", guard),
        ("Type", "oneshot"),
        ("User", "root"),
        ("Group", "root"),
        ("NRestarts", "0"),
        ("Restart", "no"),
        ("MainPID", "0"),
        ("ControlPID", "0"),
        ("Job", ""),
        ("Result", "success"),
        ("ExecMainStatus", "0"),
        ("MemoryAccounting", "yes"),
        ("MemoryMax", "268435456"),
        ("MemorySwapMax", "0"),
        ("CPUQuotaPerSecUSec", "1s"),
    ] {
        ensure!(
            native[key] == value,
            "cold185 completed guard profile changed: {key}"
        );
    }
    ensure!(
        native["ActiveState"] == "inactive"
            && native["SubState"] == "dead"
            && timer_native["Id"] == timer
            && timer_native["ActiveState"] == "active"
            && timer_native["SubState"] == "waiting"
            && timer_native["Unit"] == guard
            && text(timer_native, "InvocationID").is_ok_and(|iid| digest(iid, 32)),
        "cold185 guard is incomplete or its exact protective timer is not armed"
    );
    completed_command(native)?;
    timer_schedule(&timer_native["TimersMonotonic"])?;
    Ok(())
}
fn runtime_owner(history: &Value, aggregate: &Value, observed_ticks: u64) -> Result<()> {
    let event = &aggregate["registration_value"];
    let actor = text(event, "actor_unit")?;
    let native = &aggregate["native"][actor];
    let receipt = &history["receipt_value"];
    let pid = monotonic(native, "MainPID")?;
    ensure!(
        pid > 1
            && observed_ticks > 0
            && native["InvocationID"] == event["actor_invocation_id"]
            && native["ActiveState"] == "active"
            && native["SubState"] == "running"
            && receipt["actor_pid"] == pid
            && receipt["actor_start_ticks"] == observed_ticks,
        "cold185 successful guard crossed current original actor PID, ticks or invocation"
    );
    Ok(())
}

fn authenticate(history: &Value, aggregate: &Value) -> Result<()> {
    let event = &aggregate["registration_value"];
    ensure!(
        history["guard_unit"] == event["guard_unit"]
            && history["timer_unit"] == event["timer_unit"],
        "cold185 rollover history changes the exact registered guard family"
    );
    let receipt: BoundFile = serde_json::from_value(history["receipt"].clone())?;
    let iid = text(&history["native_guard"], "InvocationID")?;
    ensure!(
        receipt.path
            == Path::new("/var/lib/jetstreamer/epoch185-cold-guard-v4")
                .join(format!("guard-{iid}.json")),
        "cold185 foreign guard receipt namespace"
    );
    // Existing driver receipts are root0600. This exact stable bound reader
    // preserves their original mode and authenticates bytes/inode before/after.
    ensure!(
        protected_generated(&receipt)? == history["receipt_value"],
        "cold185 original guard receipt bytes changed"
    );
    history_values(
        history,
        text(event, "actor_unit")?,
        text(event, "actor_invocation_id")?,
        text(event, "admission_sha256")?,
    )?;
    let actor = text(event, "actor_unit")?;
    let pid = monotonic(&aggregate["native"][actor], "MainPID")?;
    runtime_owner(history, aggregate, io::start_ticks(pid)?)
}

fn native_pair(
    before: &Value,
    after: &Value,
    left: &Value,
    right: &Value,
) -> Result<(Value, Value)> {
    ensure!(
        left["guard_unit"] == right["guard_unit"] && left["timer_unit"] == right["timer_unit"],
        "cold185 rollover switched guard family"
    );
    ensure!(
        integer(left, "captured_at")? <= integer(right, "captured_at")?,
        "cold185 completed guard capture chronology reversed"
    );
    let left_trigger = integer(
        &left["receipt_value"],
        "timer_last_trigger_monotonic_micros",
    )?;
    let right_trigger = integer(
        &right["receipt_value"],
        "timer_last_trigger_monotonic_micros",
    )?;
    let left_started = integer(&left["receipt_value"], "guard_start_monotonic_micros")?;
    let right_started = integer(&right["receipt_value"], "guard_start_monotonic_micros")?;
    let same_fire = left["native_guard"]["InvocationID"] == right["native_guard"]["InvocationID"];
    ensure!(
        if same_fire {
            left["receipt"] == right["receipt"] && left["receipt_value"] == right["receipt_value"]
        } else {
            right_trigger > left_trigger && right_started > left_started
        },
        "cold185 guard history reuses an IID for changed evidence or rolls back a completed fire"
    );
    let guard = text(left, "guard_unit")?;
    let timer = text(left, "timer_unit")?;
    let a = before.clone();
    let mut b = after.clone();
    for (map, history) in [(&a, left), (&b, right)] {
        let object = map
            .as_object()
            .context("cold185 complete native comparison map")?;
        for (unit, key) in [(guard, "native_guard"), (timer, "native_timer")] {
            let row = object
                .get(unit)
                .context("cold185 registered native owner missing")?
                .as_object()
                .context("cold185 raw owner properties")?;
            if unit == guard {
                completed_command(&map[unit])?;
            }
            let genuine = history[key]
                .as_object()
                .context("cold185 authenticated native owner")?;
            ensure!(!row.is_empty(), "cold185 empty actual native owner");
            for (field, value) in row {
                let expected = genuine.get(field).with_context(|| {
                    format!("cold185 history omits actual native property {field}")
                })?;
                let same = if field == "ExecStart" {
                    crate::pipeline_status::same_exec_start(
                        value.as_str().context("cold185 actual command")?,
                        expected.as_str().context("cold185 history command")?,
                    )
                } else {
                    value == expected
                };
                ensure!(
                    same,
                    "cold185 history differs from actual native property {unit}/{field}"
                );
            }
        }
    }
    let mut ga = a[guard]
        .as_object()
        .context("cold185 first raw guard")?
        .clone();
    let mut gb = b[guard]
        .as_object()
        .context("cold185 second raw guard")?
        .clone();
    ensure!(
        ga.keys().eq(gb.keys()) && ga.contains_key("InvocationID") && ga.contains_key("ExecStart"),
        "cold185 guard native field census changed or lost identity"
    );
    ensure!(
        crate::pipeline_status::same_exec_start(
            text(&a[guard], "ExecStart")?,
            text(&b[guard], "ExecStart")?
        ),
        "cold185 guard executable, argv or ignore_errors changed"
    );
    for key in [
        "InvocationID",
        "ExecMainPID",
        "ExecMainStartTimestamp",
        "ExecMainExitTimestamp",
        "ExecMainStartTimestampMonotonic",
        "ExecMainExitTimestampMonotonic",
        "ExecStart",
    ] {
        ga.remove(key);
        gb.remove(key);
    }
    ensure!(
        ga == gb,
        "cold185 guard changed a non-rollover native property"
    );
    let mut ta = a[timer].as_object().context("cold185 first timer")?.clone();
    let mut tb = b[timer]
        .as_object()
        .context("cold185 second timer")?
        .clone();
    ensure!(
        ta.keys().eq(tb.keys()),
        "cold185 timer native field census changed"
    );
    for key in ["TimersMonotonic", "LastTriggerUSecMonotonic"] {
        ta.remove(key);
        tb.remove(key);
    }
    ensure!(
        ta == tb,
        "cold185 timer source, invocation or protective policy changed"
    );
    b[guard] = before[guard].clone();
    b[timer] = before[timer].clone();
    Ok((a, b))
}

pub(in crate::fleet) fn compare_allocations(
    before: &Value,
    after: &Value,
) -> Result<(Value, Value)> {
    ensure!(
        before["stage"] == after["stage"]
            && before["registration"] == after["registration"]
            && before["task"] == after["task"],
        "cold185 actor stage or original enrollment changed during reader"
    );
    if before["stage"] == "start-pre" {
        ensure!(
            before["guard_pending"] == true && after["guard_pending"] == true,
            "cold185 setup lifecycle lost its original pending guard"
        );
        ensure!(
            before == after,
            "cold185 original pending guard promise changed"
        );
        return Ok((before.clone(), after.clone()));
    }
    if before["stage"] == "terminal" {
        ensure!(
            before["guard_pending"] == false && after["guard_pending"] == false,
            "cold185 terminal debt is not new setup authority"
        );
        // Terminal provenance is authenticated by the shared retained lifecycle
        // before either aggregate is returned. Its entire debt remains charged.
        ensure!(
            before == after,
            "cold185 terminal retention evidence changed during reader"
        );
        return Ok((before.clone(), after.clone()));
    }
    ensure!(
        before["stage"] == "running"
            && before["guard_pending"] == false
            && after["guard_pending"] == false,
        "cold185 unknown retained reader phase"
    );
    let left = &before["guard_history"];
    let right = &after["guard_history"];
    authenticate(left, before)?;
    authenticate(right, after)?;
    ensure!(
        integer(left, "captured_at")? <= integer(right, "captured_at")?,
        "cold185 guard capture chronology reversed"
    );
    let (ca, cb) = native_pair(&before["native"], &after["native"], left, right)?;
    let mut a = before.clone();
    let mut b = after.clone();
    a["native"] = ca;
    b["native"] = cb;
    for value in [&mut a, &mut b] {
        value
            .as_object_mut()
            .context("cold185 aggregate")?
            .remove("guard_history");
    }
    ensure!(
        a == b,
        "cold185 rollover changed actor, source, phase, memory, DATA or launch history"
    );
    Ok((a, b))
}

/// Discovery keeps its actual native rows. Only a native-authenticated mapped
/// invocation of the exact registered guard can leave the equality view; its
/// full witness stays in the complete output and its memory is already charged.
pub(super) fn discovery_view(
    raw: &Value,
    current: Option<&Value>,
    proofs: &[Value],
) -> Result<Value> {
    let mut view = raw
        .as_object()
        .context("cold185 complete discovery object")?
        .clone();
    let Some(current) = current else {
        ensure!(
            proofs.is_empty(),
            "cold185 in-flight proof without registered actor"
        );
        return Ok(Value::Object(view));
    };
    let event = &current["registration_value"];
    let guard = text(event, "guard_unit")?;
    if proofs.is_empty() {
        ensure!(
            !view.contains_key(guard),
            "cold185 actual in-flight guard has no exact mapped discovery proof"
        );
        return Ok(Value::Object(view));
    }
    ensure!(
        proofs.len() == 1 && current["stage"] == "running" && current["guard_pending"] == false,
        "cold185 duplicate or wrong-lifecycle guard discovery"
    );
    let proof = &proofs[0];
    let native = &proof["actual_native"];
    ensure!(
        proof["schema"] == "horizon-epoch185-exact-inflight-guard-discovery-v2"
            && proof["unit"] == guard
            && proof["actor_unit"] == event["actor_unit"]
            && proof["actor_invocation_id"] == event["actor_invocation_id"]
            && proof["invocation_id"] == native["InvocationID"]
            && text(proof, "invocation_id").is_ok_and(|iid| digest(iid, 32))
            && proof["last_successful_guard"] == current["guard_history"]
            && proof["guard_success_not_claimed"] == true
            && proof["existing_guard_memory_already_charged_bytes"] == 256u64 << 20
            && proof["new_allocation_bytes"] == 0
            && proof["resource_credit_bytes"] == 0,
        "cold185 guard discovery crossed original owner, history, charge or authority"
    );
    let observed = view
        .get(guard)
        .context("cold185 exact raw guard discovery missing")?
        .as_object()
        .context("cold185 raw discovery native properties")?;
    let actual = native
        .as_object()
        .context("cold185 authenticated guard native properties")?;
    ensure!(!observed.is_empty(), "cold185 empty raw discovered guard");
    for (key, value) in observed {
        let genuine = actual
            .get(key)
            .context("cold185 discovered property omitted from native proof")?;
        let same = if key == "ExecStart" {
            crate::pipeline_status::same_exec_start(
                value.as_str().context("cold185 raw discovered command")?,
                genuine
                    .as_str()
                    .context("cold185 authenticated discovered command")?,
            )
        } else {
            value == genuine
        };
        ensure!(
            same,
            "cold185 discovered property differs from exact mapped guard {key}"
        );
    }
    view.remove(guard);
    Ok(Value::Object(view))
}

pub(in crate::fleet) fn comparison_census(
    before_aggregate: Option<&Value>,
    after_aggregate: Option<&Value>,
    before: &Value,
    after: &Value,
) -> Result<(Value, Value)> {
    match (before_aggregate, after_aggregate) {
        (None, None) => Ok((before.clone(), after.clone())),
        (Some(left), Some(right)) if left["stage"] == "running" => {
            compare_allocations(left, right)?;
            native_pair(
                before,
                after,
                &left["guard_history"],
                &right["guard_history"],
            )
        }
        (Some(left), Some(right)) => {
            compare_allocations(left, right)?;
            Ok((before.clone(), after.clone()))
        }
        _ => anyhow::bail!("cold185 owner appeared or vanished during complete reader"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn history(iid: &str, at: u64, trigger: u64, started: u64, due: &str) -> Value {
        let actor = "horizon-qualify-185-capped-cold-v8.service";
        let guard = "horizon-guard-185-capped-cold-v8.service";
        let timer = "horizon-guard-185-capped-cold-v8.timer";
        let command = format!(
            "{{ path=/exact/epoch185-guarded-cold ; argv[]=/exact/epoch185-guarded-cold guard /exact/envelope.json --plan-sha256 {} --self-sha256 {} ; ignore_errors=no ; start_time=[{at}] ; stop_time=[{at}] ; pid=0 ; code=exited ; status=0/0 }}",
            "e".repeat(64),
            "f".repeat(64)
        );
        json!({"guard_unit":guard,"timer_unit":timer,"captured_at":at,
            "receipt_value":{"schema":"horizon-epoch185-native-guard-result-v4","epoch":185,
                "actor_unit":actor,"actor_invocation_id":"a".repeat(32),"admission_sha256":"d".repeat(64),
                "guard_invocation_id":iid,"timer_unit":timer,"timer_driven":true,
                "success":true,"failure":null,"capacity_credit_bytes":0,"sampled_at":at,
                "timer_last_trigger_monotonic_micros":trigger,"guard_start_monotonic_micros":started},
            "native_guard":{"Id":guard,"Type":"oneshot","User":"root","Group":"root",
                "NRestarts":"0","Restart":"no","MainPID":"0","ControlPID":"0","Job":"",
                "Result":"success","ExecMainStatus":"0","MemoryAccounting":"yes",
                "MemoryMax":"268435456","MemorySwapMax":"0","CPUQuotaPerSecUSec":"1s",
                "ActiveState":"inactive","SubState":"dead","InvocationID":iid,
                "ExecMainStartTimestampMonotonic":started.to_string(),"ExecStart":command},
            "native_timer":{"Id":timer,"ActiveState":"active","SubState":"waiting","Unit":guard,
                "InvocationID":"c".repeat(32),"LastTriggerUSecMonotonic":trigger.to_string(),
                "TimersMonotonic":format!("{{ OnActiveUSec=1s ; next_elapse=n/a }}\n{{ OnUnitInactiveUSec=30s ; next_elapse={due} }}")}})
    }
    fn validate(history: &Value) -> Result<()> {
        history_values(
            history,
            "horizon-qualify-185-capped-cold-v8.service",
            &"a".repeat(32),
            &"d".repeat(64),
        )
    }
    fn census(history: &Value) -> Value {
        json!({"horizon-qualify-185-capped-cold-v8.service":{"InvocationID":"a".repeat(32),"MainPID":"9"},
            "horizon-guard-185-capped-cold-v8.service":history["native_guard"],
            "horizon-guard-185-capped-cold-v8.timer":history["native_timer"],
            "unrelated.service":{"InvocationID":"e".repeat(32)}})
    }
    #[test]
    fn completed_fires_bracket_reader_longer_than_guard_cadence_without_resetting_clocks() {
        let first = history(&"b".repeat(32), 100, 1_000_000, 1_100_000, "2min");
        let next = history(&"f".repeat(32), 304, 205_000_000, 205_100_000, "5min");
        validate(&first).unwrap();
        validate(&next).unwrap();
        let (a, b) = native_pair(&census(&first), &census(&next), &first, &next).unwrap();
        assert_eq!(a, b);
        assert_ne!(
            first["native_guard"]["InvocationID"],
            next["native_guard"]["InvocationID"]
        );
        assert_eq!(first["captured_at"], 100);
        assert_eq!(next["captured_at"], 304);
    }
    #[test]
    fn receipt_rejects_trip_credit_wrong_actor_admission_or_actual_fire_identity() {
        let good = history(&"b".repeat(32), 100, 1_000_000, 1_100_000, "2min");
        for (pointer, bad) in [
            ("/receipt_value/success", json!(false)),
            ("/receipt_value/capacity_credit_bytes", json!(1)),
            ("/receipt_value/actor_invocation_id", json!("f".repeat(32))),
            ("/receipt_value/admission_sha256", json!("e".repeat(64))),
            ("/receipt_value/guard_invocation_id", json!("a".repeat(32))),
            ("/receipt_value/timer_driven", json!(false)),
            (
                "/receipt_value/timer_last_trigger_monotonic_micros",
                json!(999_999),
            ),
        ] {
            let mut broken = good.clone();
            *broken.pointer_mut(pointer).unwrap() = bad;
            assert!(validate(&broken).is_err(), "{pointer}");
        }
    }
    #[test]
    fn guard_receipt_binds_real_running_pid_and_start_ticks_not_old_ready_control_pid() {
        let mut history = history(&"b".repeat(32), 100, 1_000_000, 1_100_000, "2min");
        history["receipt_value"]["actor_pid"] = json!(123);
        history["receipt_value"]["actor_start_ticks"] = json!(456);
        let actor = "horizon-qualify-185-capped-cold-v8.service";
        let aggregate = json!({"registration_value":{"actor_unit":actor,"actor_invocation_id":"a".repeat(32),
                "ready_pid":100,"ready_start_ticks":200},
            "native":{"horizon-qualify-185-capped-cold-v8.service":{"MainPID":"123","InvocationID":"a".repeat(32),"ActiveState":"active","SubState":"running"}}});
        runtime_owner(&history, &aggregate, 456).unwrap();
        assert!(runtime_owner(&history, &aggregate, 457).is_err());
        for (field, bad) in [("actor_pid", json!(100)), ("actor_start_ticks", json!(200))] {
            let mut changed = history.clone();
            changed["receipt_value"][field] = bad;
            assert!(runtime_owner(&changed, &aggregate, 456).is_err());
        }
    }
    #[test]
    fn completed_guard_history_cannot_roll_back_or_reuse_an_iid_for_new_receipt() {
        let first = history(&"b".repeat(32), 100, 31_000_000, 31_100_000, "2min");
        let rollback = history(&"f".repeat(32), 130, 1_000_000, 1_100_000, "3min");
        assert!(native_pair(&census(&first), &census(&rollback), &first, &rollback).is_err());
        let reused = history(&"b".repeat(32), 130, 61_000_000, 61_100_000, "3min");
        assert!(native_pair(&census(&first), &census(&reused), &first, &reused).is_err());
        let mut unchanged = first.clone();
        unchanged["captured_at"] = json!(120);
        assert!(native_pair(&census(&first), &census(&unchanged), &first, &unchanged).is_ok());
    }
    #[test]
    fn stale_at_capture_future_receipt_and_changed_cadence_fail() {
        let good = history(&"b".repeat(32), 100, 1_000_000, 1_100_000, "2min");
        for (pointer, bad) in [
            ("/captured_at", json!(191)),
            ("/receipt_value/sampled_at", json!(101)),
            (
                "/native_timer/TimersMonotonic",
                json!(
                    "{ OnActiveUSec=1s ; next_elapse=n/a }\n{ OnUnitInactiveUSec=60s ; next_elapse=2min }"
                ),
            ),
        ] {
            let mut broken = good.clone();
            *broken.pointer_mut(pointer).unwrap() = bad;
            assert!(validate(&broken).is_err(), "{pointer}");
        }
    }
    #[test]
    fn guard_memory_command_and_timer_owner_changes_never_normalize() {
        let first = history(&"b".repeat(32), 100, 1_000_000, 1_100_000, "2min");
        let next = history(&"f".repeat(32), 130, 31_000_000, 31_100_000, "3min");
        for (pointer, bad) in [
            ("/native_guard/MemoryMax", json!("536870912")),
            (
                "/native_guard/ExecStart",
                json!("{ path=/foreign ; argv[]=/foreign ; ignore_errors=no ; start_time=n/a }"),
            ),
            ("/native_timer/InvocationID", json!("a".repeat(32))),
        ] {
            let mut broken = next.clone();
            *broken.pointer_mut(pointer).unwrap() = bad;
            assert!(
                native_pair(&census(&first), &census(&broken), &first, &broken).is_err(),
                "{pointer}"
            );
        }
    }
    #[test]
    fn changed_command_failure_display_is_not_hidden_by_identity_comparison() {
        let first = history(&"b".repeat(32), 100, 1_000_000, 1_100_000, "2min");
        let next = history(&"f".repeat(32), 130, 31_000_000, 31_100_000, "3min");
        let mut raw = census(&next);
        let guard = "horizon-guard-185-capped-cold-v8.service";
        let changed = raw[guard]["ExecStart"]
            .as_str()
            .unwrap()
            .replace("status=0/0", "status=1/FAILURE");
        raw[guard]["ExecStart"] = json!(changed);
        assert!(native_pair(&census(&first), &raw, &first, &next).is_err());
    }
    #[test]
    fn original_actor_and_unrelated_family_rows_stay_raw_in_comparison_views() {
        let first = history(&"b".repeat(32), 100, 1_000_000, 1_100_000, "2min");
        let next = history(&"f".repeat(32), 130, 31_000_000, 31_100_000, "3min");
        let before = census(&first);
        let mut after = census(&next);
        after["horizon-qualify-185-capped-cold-v8.service"]["MainPID"] = json!("10");
        let (a, b) = native_pair(&before, &after, &first, &next).unwrap();
        assert_ne!(a, b);
        assert_eq!(
            b["horizon-qualify-185-capped-cold-v8.service"]["MainPID"],
            "10"
        );
        after["unrelated.service"]["InvocationID"] = json!("f".repeat(32));
        let (a, b) = native_pair(&before, &after, &first, &next).unwrap();
        assert_ne!(a["unrelated.service"], b["unrelated.service"]);
    }
    #[test]
    fn legacy_native_subset_keeps_its_original_membership_and_authenticates_each_property() {
        let first = history(&"b".repeat(32), 100, 1_000_000, 1_100_000, "2min");
        let next = history(&"f".repeat(32), 130, 31_000_000, 31_100_000, "3min");
        let mut before = census(&first);
        let mut after = census(&next);
        let guard = "horizon-guard-185-capped-cold-v8.service";
        let timer = "horizon-guard-185-capped-cold-v8.timer";
        for map in [&mut before, &mut after] {
            map[guard]
                .as_object_mut()
                .unwrap()
                .remove("ExecMainStartTimestampMonotonic");
            map[timer]
                .as_object_mut()
                .unwrap()
                .remove("TimersMonotonic");
            map[timer]
                .as_object_mut()
                .unwrap()
                .remove("LastTriggerUSecMonotonic");
        }
        let raw_before = before.clone();
        let raw_after = after.clone();
        let (a, b) = native_pair(&before, &after, &first, &next).unwrap();
        assert_eq!(a, b);
        assert_eq!(before, raw_before);
        assert_eq!(after, raw_after);
        assert!(
            !b[guard]
                .as_object()
                .unwrap()
                .contains_key("ExecMainStartTimestampMonotonic")
        );
        after[guard]["MemoryMax"] = json!("536870912");
        assert!(native_pair(&before, &after, &first, &next).is_err());
        after = raw_after;
        after[guard]["unobserved-policy"] = json!("forged");
        assert!(native_pair(&before, &after, &first, &next).is_err());
    }
    #[test]
    fn actor_phase_or_launch_provenance_cannot_change_under_rollover_authority() {
        let before = json!({"stage":"start-pre","guard_pending":true,
            "registration":{"path":"/original/registration","sha256":"a".repeat(64)},
            "task":{"path":"/original/task","sha256":"b".repeat(64)},
            "candidate_DATA_bytes":800,"peers":[{"memory_max_bytes":1000}]});
        compare_allocations(&before, &before).unwrap();
        for (pointer, changed) in [
            ("/stage", json!("running")),
            ("/registration/sha256", json!("c".repeat(64))),
            ("/task/sha256", json!("d".repeat(64))),
            ("/candidate_DATA_bytes", json!(0)),
            ("/peers/0/memory_max_bytes", json!(0)),
        ] {
            let mut after = before.clone();
            *after.pointer_mut(pointer).unwrap() = changed;
            assert!(compare_allocations(&before, &after).is_err(), "{pointer}");
        }
    }
    #[test]
    fn only_exact_native_authenticated_inflight_guard_leaves_discovery_comparison() {
        let guard = "horizon-guard-185-capped-cold-v8.service";
        let actor = "horizon-qualify-185-capped-cold-v8.service";
        let current = json!({"stage":"running","guard_pending":false,"guard_history":{"receipt":"original"},
            "registration_value":{"guard_unit":guard,"actor_unit":actor,"actor_invocation_id":"a".repeat(32)}});
        let native = json!({"Id":guard,"InvocationID":"b".repeat(32),"MemoryMax":"268435456"});
        let proof = json!({"schema":"horizon-epoch185-exact-inflight-guard-discovery-v2","unit":guard,
            "actor_unit":actor,"actor_invocation_id":"a".repeat(32),"invocation_id":"b".repeat(32),
            "actual_native":native,"last_successful_guard":current["guard_history"],"guard_success_not_claimed":true,
            "existing_guard_memory_already_charged_bytes":256u64<<20,"new_allocation_bytes":0,"resource_credit_bytes":0});
        let mut raw = json!({"unrelated.service":{"InvocationID":"c".repeat(32)}});
        raw[guard] = native;
        let unchanged = raw.clone();
        let view = discovery_view(&raw, Some(&current), std::slice::from_ref(&proof)).unwrap();
        assert_eq!(raw, unchanged);
        assert_eq!(view["unrelated.service"], raw["unrelated.service"]);
        assert!(view.get(guard).is_none());
        assert!(discovery_view(&raw, Some(&current), &[]).is_err());
        for (key, bad) in [
            ("actor_invocation_id", json!("f".repeat(32))),
            ("resource_credit_bytes", json!(1)),
            ("guard_success_not_claimed", json!(false)),
        ] {
            let mut forged = proof.clone();
            forged[key] = bad;
            assert!(
                discovery_view(&raw, Some(&current), &[forged]).is_err(),
                "{key}"
            );
        }
        let mut changed = raw.clone();
        changed[guard]["MemoryMax"] = json!("0");
        assert!(discovery_view(&changed, Some(&current), std::slice::from_ref(&proof)).is_err());
    }
    #[test]
    fn guard_history_must_match_the_complete_actual_native_map() {
        let first = history(&"b".repeat(32), 100, 1_000_000, 1_100_000, "2min");
        let next = history(&"f".repeat(32), 130, 31_000_000, 31_100_000, "3min");
        let before = census(&first);
        let mut after = census(&next);
        after
            .as_object_mut()
            .unwrap()
            .remove("horizon-guard-185-capped-cold-v8.service");
        assert!(native_pair(&before, &after, &first, &next).is_err());
    }
}
