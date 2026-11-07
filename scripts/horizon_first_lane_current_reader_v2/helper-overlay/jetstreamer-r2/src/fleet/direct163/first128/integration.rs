//! Complete bounded ownership and prewritten common-observer handoff. No worker
//! release, timer changes, new resource observation or remote mutation.
use super::*;
pub(in crate::fleet) const REGISTER128: &str =
    "/var/lib/jetstreamer/horizon-epoch163-first-output128-enrollment-20261106-v1/enrollment.json";
pub(super) fn declared(plan: &Value) -> Result<Option<Bound>> {
    let Some(rows) = plan.get("diagnostics") else {
        return Ok(None);
    };
    let rows = rows.as_array().context("bounded diagnostic declarations")?;
    let matches = rows
        .iter()
        .filter(|r| r["unit"] == PARENT128)
        .collect::<Vec<_>>();
    ensure!(matches.len() <= 1, "duplicate bounded claim");
    let Some(row) = matches.first() else {
        return Ok(None);
    };
    ensure!(row["epoch"] == 163, "bounded wrong epoch");
    let b = to_bound(&row["launch_receipt"])?;
    ensure!(
        b.path == Path::new(REGISTER128),
        "bounded exact enrollment namespace"
    );
    Ok(Some(b))
}
pub(in crate::fleet) fn native_namespace(name: &str) -> bool {
    [PARENT128, GUARD128, STOP128, TIMER128, ADMIT128, ENROLL128, RELEASE128].contains(&name)
}
pub(in crate::fleet) fn raw_profile(n: &Value) -> Result<()> {
    ensure!(
        n["Id"] == PARENT128
            && n["LoadState"] == "loaded"
            && n["Type"] == "exec"
            && n["User"] == "sol"
            && n["Group"] == "horizon"
            && n["MemoryAccounting"] == "yes"
            && n["MemoryMax"].as_str() == Some(HARD128.to_string().as_str())
            && n["MemorySwapMax"] == "0"
            && n["CPUQuotaPerSecUSec"] == "8s"
            && n["TasksMax"] == "1024"
            && n["Restart"] == "no"
            && n["NRestarts"] == "0"
            && (n["ControlGroup"] == format!("/system.slice/{PARENT128}")
                || (matches!(n["ActiveState"].as_str(), Some("inactive" | "failed"))
                    && n["ControlGroup"] == "")),
        "bounded exact raw owner profile"
    );
    enrollment128::command(n, &enrollment128::parent_argv())
}
pub(in crate::fleet) fn launch_matches(claim: &DiagnosticClaim, receipt: &Value) -> bool {
    claim.epoch == 163
        && claim.unit == PARENT128
        && claim.scratch_path
            == Path::new(
                "/home/sol/.jetstreamer-private/epoch163-first-output128-20261106-v1/work/scratch",
            )
        && claim.launch_receipt.path == Path::new(REGISTER128)
        && receipt["schema"] == "epoch163-first-output128-fleet-enrollment-v1"
        && receipt["parent_unit"] == PARENT128
        && receipt["parent_invocation_id"] == claim.invocation_id
        && receipt["complete_current_claim_census"] == true
        && receipt["common_observer_and_fleet_handoff_qualified"] == true
        && receipt["publication_authorized"] == false
        && receipt["r2_mutations"] == false
}
pub(in crate::fleet) fn owned_owner(plan: &Value) -> Result<Option<Value>> {
    let Some(b) = declared(plan)? else {
        return Ok(None);
    };
    enrollment128::allocation(plan)?;
    let e = immutable(&b)?;
    let node = enrollment128::native(PARENT128)?;
    if !matches!(node["ActiveState"].as_str(), Some("active" | "activating")) {
        enrollment128::terminal_parent(&node, &e)?;
        return Ok(None);
    }
    let (iid, pid, ticks) = enrollment128::parent(&node)?;
    ensure!(
        iid == e["parent_invocation_id"]
            && pid == n(&e, "parent_pid")?
            && ticks == n(&e, "parent_start_ticks")?,
        "bounded enrolled owner replaced"
    );
    Ok(Some(
        json!({"unit":PARENT128,"iid":iid,"pid":pid,"start_ticks":ticks,
        "role":"diagnostic-replay","first_epoch":163,"last_epoch":163,"restarts":0,
        "identity_stable":true,"guard_required":false,"has_memory_accounting":true}),
    ))
}
pub(in crate::fleet) fn normalize_peers(a: &[Value], b: &[Value]) -> Result<bool> {
    let normalize = |rows: &[Value]| -> Result<Vec<Value>> {
        let mut rows = rows.to_vec();
        for row in &mut rows {
            if row["unit"] == GUARD128 {
                ensure!(
                    row["first163128_registration"]["path"] == REGISTER128
                        && row["included_once_in_first128_parent_claim"] == true,
                    "bounded guard row authentication"
                );
                row["invocation_id"] = Value::Null;
            }
        }
        Ok(rows)
    };
    super::super::normalize_peers(&normalize(a)?, &normalize(b)?)
}
pub(in crate::fleet) fn guard_floor(rows: &[Value]) -> Result<u64> {
    rows.iter()
        .filter(|r| r["unit"] == PARENT128)
        .try_fold(0u64, |floor, row| {
            Ok(floor.max(n(row, "guard_floor_bytes")?))
        })
}
fn static_guard(n: &mut Value) -> Result<()> {
    ensure!(
        n["Id"] == GUARD128
            && n["MemoryMax"] == "2147483648"
            && n["MemorySwapMax"] == "0"
            && n["MainPID"] == "0"
            && n["ControlPID"] == "0"
            && n["NRestarts"] == "0"
            && n["Job"] == ""
            && n["Result"] == "success"
            && n["ExecMainStatus"] == "0"
            && n["ActiveState"] == "inactive"
            && n["SubState"] == "dead",
        "bounded guard not successfully quiet"
    );
    let obj = n.as_object_mut().context("bounded guard object")?;
    for field in [
        "InvocationID",
        "MainPID",
        "ControlPID",
        "ActiveState",
        "SubState",
        "ControlGroup",
        "ExecMainCode",
        "ExecMainPID",
        "ExecMainStartTimestamp",
        "ExecMainExitTimestamp",
    ] {
        obj.remove(field);
    }
    if let Some(command) = obj.get("ExecStart").and_then(Value::as_str) {
        let id = command
            .split_once(" ; ignore_errors=")
            .context("bounded guard argv framing")?
            .0
            .to_owned();
        obj.insert("ExecStart".into(), json!(id));
    }
    Ok(())
}
pub(in crate::fleet) fn comparison_census(
    plan: &Value,
    a: &Value,
    b: &Value,
) -> Result<(Value, Value)> {
    if declared(plan)?.is_none() {
        return Ok((a.clone(), b.clone()));
    }
    let retained = enrollment128::allocation(plan)?;
    if retained.iter().any(|row| {
        row["unit"] == PARENT128 && row["state"] == "terminal-retained-private-first-output128"
    }) {
        // Terminal liabilities remain charged; no periodic-success normalization
        // is justified for a completed or failed drained guard.
        return Ok((a.clone(), b.clone()));
    }
    let mut pair = [a.clone(), b.clone()];
    for row in &mut pair {
        static_guard(&mut row[GUARD128])?;
        if let Some(timer) = row[TIMER128].as_object_mut() {
            timer.remove("TimersMonotonic");
        }
    }
    ensure!(
        pair[0][GUARD128] == pair[1][GUARD128] && pair[0][TIMER128] == pair[1][TIMER128],
        "bounded static guard/timer changed"
    );
    Ok((pair[0].clone(), pair[1].clone()))
}
/// Authenticate actual predecessor and actual native check-config completion.
/// The future config contains only a candidate identity addition, never a live
/// resource sample; original fleet capture must still execute after enrollment.
pub(super) fn observer_handoff(
    h: &Value,
    a: &Value,
    input_policy: &Bound,
    iid: &str,
) -> Result<Value> {
    ensure!(
        h["schema"] == "epoch163-first-output128-common-observer-handoff-plan-v1"
            && h["parent_unit"] == PARENT128
            && h["parent_invocation_id"] == iid
            && h["input_policy"] == json!(input_policy)
            && h["admission"] == a["original_admission_binding"]
            && h["publication_authorized"] == false
            && h["r2_mutations"] == false,
        "bounded handoff scope"
    );
    let prior = immutable(&to_bound(&h["prior_fleet"])?)?;
    immutable(&to_bound(&h["prior_fleet_plan"])?)?;
    ensure!(
        prior["plan"] == plan_binding_path(&h["prior_fleet_plan"])?
            && prior["plan_sha256"] == h["prior_fleet_plan"]["sha256"],
        "bounded handoff prior fleet plan crossed"
    );
    ensure!(
        a["memory"]["request"]["current"]["fleet"] == h["prior_fleet"]
            && a["memory"]["request"]["current"]["fleet_plan"] == h["prior_fleet_plan"],
        "bounded handoff prior admission tuple crossed"
    );
    let before = immutable(&to_bound(&h["prior_observer_config"])?)?;
    let after = immutable(&to_bound(&h["successor_observer_config"])?)?;
    observer_config(&before, &after, iid)?;
    let program = to_bound(&h["observer_program"])?;
    storage::bytes(&program, 256 << 20, true)?;
    let execution = immutable(&to_bound(&h["original_check_config_execution"])?)?;
    check_config_execution(
        &execution,
        &program,
        &h["successor_observer_config"],
        n(a, "recorded_unix_seconds")?,
        now()?,
    )?;
    let mut census = serde_json::Map::new();
    let owners = a["raw_after"]["current_unique_owner_census"]
        .as_array()
        .context("bounded complete admission owner census")?;
    for owner in owners {
        let name = owner["unit"].as_str().context("bounded prior owner unit")?;
        ensure!(
            name != PARENT128,
            "bounded held owner already present in admission"
        );
        let current = unit(name)?;
        ensure!(
            current["Id"] == name
                && current["InvocationID"] == owner["iid"]
                && current["MainPID"].as_str() == Some(n(owner, "pid")?.to_string().as_str())
                && current["NRestarts"] == "0"
                && current["ActiveState"] == "active"
                && current["SubState"] == "running",
            "bounded admission owner changed before held enrollment"
        );
        let ticks = enrollment128::process_ticks(n(owner, "pid")?)?;
        ensure!(
            ticks == n(owner, "start_ticks")?,
            "bounded old owner PID recycled"
        );
        census.insert(name.to_owned(), current);
    }
    ensure!(
        a["raw_after"]["active_peer_allocations"].is_array()
            && a["raw_after"]["native_pool_suballocations"].is_array(),
        "bounded complete retained peer/pool obligations absent"
    );
    Ok(
        json!({"prior_fleet":h["prior_fleet"],"prior_fleet_plan":h["prior_fleet_plan"],"successor_observer_config":h["successor_observer_config"],
        "actual_check_config":h["original_check_config_execution"],"actual_complete_current_claim_census":census,
        "retained_peer_allocations":a["raw_after"]["active_peer_allocations"],"native_pool_suballocations":a["raw_after"]["native_pool_suballocations"],
        "candidate_claim":candidate_observer(iid),"new_resource_samples":0,"publication_authorized":false}),
    )
}
fn check_config_execution(
    execution: &Value,
    program: &Bound,
    config: &Value,
    admitted: u64,
    t: u64,
) -> Result<()> {
    let expected = json!([program.path, config["path"], "--check-config"]);
    let j = &execution["original_PID1_success_event"];
    let native = &execution["original_native"];
    let unit = execution["unit"]
        .as_str()
        .context("bounded check-config original unit")?;
    let iid = execution["invocation_id"]
        .as_str()
        .context("bounded check-config IID")?;
    let recorded = j["__REALTIME_TIMESTAMP"]
        .as_str()
        .context("bounded check-config original time")?
        .parse::<u64>()?
        / 1_000_000;
    ensure!(
        execution["schema"] == "epoch163-first-output128-original-common-observer-check-config-v1"
            && execution["program"] == json!(program)
            && execution["configuration"] == *config
            && execution["argv"] == expected
            && execution["code"] == 0
            && execution["original_outer_reaped"] == true
            && execution["original_cgroup_empty"] == true
            && execution["original_descriptors_drained"] == true
            && unit.starts_with("horizon-first163128-observer-check-")
            && unit.ends_with(".service")
            && storage::hex(iid, 32)
            && native["Id"] == unit
            && native["InvocationID"] == iid
            && native["MainPID"] == "0"
            && native["ControlPID"] == "0"
            && native["Job"] == ""
            && native["NRestarts"] == "0"
            && native["Result"] == "success"
            && native["ExecMainStatus"] == "0"
            && j["_PID"] == "1"
            && j["_UID"] == "0"
            && j["UNIT"] == unit
            && j["INVOCATION_ID"] == iid
            && j["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448"
            && j["MESSAGE"] == format!("{unit}: Deactivated successfully.")
            && recorded >= admitted
            && t.checked_sub(recorded).is_some_and(|age| age <= 180),
        "bounded original observer check-config execution stale/crossed/incomplete"
    );
    Ok(())
}
fn plan_binding_path(v: &Value) -> Result<Value> {
    Ok(json!(to_bound(v)?.path))
}
fn candidate_observer(iid: &str) -> Value {
    json!({"controller_unit":PARENT128,"producer_unit":PARENT128,"expected_controller_invocation_id":iid,
    "expected_producer_invocation_id":iid,"range":"163","scratch_path":"/home/sol/.jetstreamer-private/epoch163-first-output128-20261106-v1/work/scratch",
    "worker_executable_basename":"historical-worker"})
}
fn observer_config(before: &Value, after: &Value, iid: &str) -> Result<()> {
    ensure!(
        storage::hex(iid, 32)
            && before["schema"] == "jetstreamer-horizon-live-resource-sample-config-v2"
            && after["schema"] == before["schema"]
            && after["minimum_interval_seconds"] == 1800
            && after["observation_reason"] == "routine",
        "bounded observer config/cadence differs"
    );
    let mut expected = before.clone();
    let rows = expected["diagnostic_replays"]
        .as_array_mut()
        .context("bounded observer diagnostics")?;
    ensure!(
        !rows
            .iter()
            .any(|r| r["range"] == "163" || r["producer_unit"] == PARENT128),
        "bounded duplicate observer claim"
    );
    rows.push(candidate_observer(iid));
    ensure!(
        expected == *after,
        "bounded observer handoff changed an unrelated source or schedule"
    );
    Ok(())
}
pub(in crate::fleet) fn validate_transition(
    previous: &Value,
    plan: &Plan,
    plan_value: &Value,
    event: &Value,
    sample: &str,
    t: u64,
) -> Result<()> {
    ensure!(
        event["schema"] == "epoch163-first-output128-fleet-enrollment-v1"
            && event["publication_authorized"] == false
            && event["admission_value"]["memory"]["request"]["current"]["observer"]
                == json!(plan.observer)
            && previous["observer_receipt"] == json!(plan.observer.path)
            && previous["observer_sha256"] == plan.observer.sha256
            && previous["sampled_at_utc"] == sample
            && n(event, "recorded_unix_seconds")? <= t
            && t - n(event, "recorded_unix_seconds")? <= 300,
        "bounded same-sample enrollment transition"
    );
    let added = plan
        .diagnostics
        .iter()
        .filter(|d| d.unit == PARENT128)
        .collect::<Vec<_>>();
    ensure!(
        added.len() == 1 && launch_matches(added[0], event),
        "bounded transition candidate claim"
    );
    let old = bound_json(&BoundFile {
        path: previous["plan"].as_str().context("prior plan path")?.into(),
        sha256: previous["plan_sha256"]
            .as_str()
            .context("prior plan sha")?
            .into(),
    })?;
    // Preserve every source, pipeline, retirement, and unrelated plan field.
    let mut prior_plan = old.clone();
    let mut next_plan = plan_value.clone();
    for key in [
        "output",
        "previous_fleet",
        "metadata_event",
        "diagnostics",
        "gates",
        "tracked_units",
    ] {
        prior_plan
            .as_object_mut()
            .context("bounded old plan object")?
            .remove(key);
        next_plan
            .as_object_mut()
            .context("bounded next plan object")?
            .remove(key);
    }
    ensure!(
        prior_plan == next_plan,
        "bounded transition changed unrelated plan/source/pipeline claims"
    );
    let old_units = old["tracked_units"]
        .as_array()
        .context("bounded prior tracked units")?;
    ensure!(
        old_units
            .iter()
            .all(|u| plan.tracked_units.iter().filter(|s| json!(s) == *u).count() == 1)
            && plan
                .tracked_units
                .iter()
                .filter(|u| !old_units.iter().any(|v| v == u.as_str()))
                .all(|u| native_namespace(u)),
        "bounded transition removed tracked source or added unrelated unit"
    );
    ensure!(
        old["gates"]
            .as_object()
            .context("bounded prior gates")?
            .len()
            == plan.gates.len(),
        "bounded transition changed gate set"
    );
    let prior = old["diagnostics"]
        .as_array()
        .context("bounded old diagnostics")?;
    ensure!(
        plan.diagnostics.len() == prior.len() + 1,
        "bounded transition adds more than one claim"
    );
    for row in prior {
        ensure!(
            plan.diagnostics
                .iter()
                .filter(|d| d.unit == row["unit"]
                    && Some(d.epoch) == row["epoch"].as_u64()
                    && d.invocation_id == row["invocation_id"]
                    && json!(d.scratch_path) == row["scratch_path"]
                    && json!(d.launch_receipt) == row["launch_receipt"])
                .count()
                == 1,
            "bounded transition changed old diagnostic"
        );
    }
    for (epoch, gate) in &plan.gates {
        if *epoch != 163 {
            let was = &old["gates"][epoch.to_string()];
            ensure!(
                gate.state == was["state"]
                    && gate.next_action == was["next_action"]
                    && json!(gate.evidence) == was["evidence"],
                "bounded transition unrelated gate"
            );
        }
    }
    let declaration = json!({"diagnostics":plan.diagnostics.iter().map(|d|json!({"epoch":d.epoch,"unit":d.unit,"launch_receipt":d.launch_receipt})).collect::<Vec<_>>()});
    enrollment128::allocation(&declaration)?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn observer_handoff_changes_only_the_exact_bounded_diagnostic() {
        let before = json!({"schema":"jetstreamer-horizon-live-resource-sample-config-v2","minimum_interval_seconds":1800,"observation_reason":"routine","diagnostic_replays":[],"previous_sample":"/real","not_before_utc":"original"});
        let iid = "a".repeat(32);
        let mut after = before.clone();
        after["diagnostic_replays"]
            .as_array_mut()
            .unwrap()
            .push(candidate_observer(&iid));
        observer_config(&before, &after, &iid).unwrap();
        for key in ["previous_sample", "not_before_utc"] {
            let mut crossed = after.clone();
            crossed[key] = json!("changed");
            assert!(observer_config(&before, &crossed, &iid).is_err());
        }
        let mut duplicate = after.clone();
        duplicate["diagnostic_replays"]
            .as_array_mut()
            .unwrap()
            .push(candidate_observer(&iid));
        assert!(observer_config(&before, &duplicate, &iid).is_err());
    }
    #[test]
    fn original_observer_handoff_rejects_stale_crossed_or_undrained_execution() {
        let program = Bound {
            path: "/usr/local/lib/jetstreamer/observer/program".into(),
            sha256: "a".repeat(64),
        };
        let config = json!({"path":"/normal/successor.json","sha256":"b".repeat(64)});
        let iid = "c".repeat(32);
        let unit = "horizon-first163128-observer-check-fixture.service";
        let receipt = json!({"schema":"epoch163-first-output128-original-common-observer-check-config-v1","program":program,"configuration":config,
            "argv":[program.path,config["path"],"--check-config"],"code":0,"unit":unit,"invocation_id":iid,
            "original_outer_reaped":true,"original_cgroup_empty":true,"original_descriptors_drained":true,
            "original_native":{"Id":unit,"InvocationID":iid,"MainPID":"0","ControlPID":"0","Job":"","NRestarts":"0","Result":"success","ExecMainStatus":"0"},
            "original_PID1_success_event":{"_PID":"1","_UID":"0","UNIT":unit,"INVOCATION_ID":iid,"MESSAGE_ID":"7ad2d189f7e94e70a38c781354912448","MESSAGE":format!("{unit}: Deactivated successfully."),"__REALTIME_TIMESTAMP":"110000000"}});
        check_config_execution(&receipt, &program, &config, 100, 120).unwrap();
        assert!(check_config_execution(&receipt, &program, &config, 111, 120).is_err());
        assert!(check_config_execution(&receipt, &program, &config, 100, 291).is_err());
        for (pointer, value) in [
            ("/original_descriptors_drained", json!(false)),
            ("/program/sha256", json!("d".repeat(64))),
            ("/configuration/sha256", json!("e".repeat(64))),
            ("/original_native/InvocationID", json!("f".repeat(32))),
            ("/original_PID1_success_event/_UID", json!("1001")),
        ] {
            let mut r = receipt.clone();
            *r.pointer_mut(pointer).unwrap() = value;
            assert!(
                check_config_execution(&r, &program, &config, 100, 120).is_err(),
                "{pointer}"
            );
        }
    }
    #[test]
    fn bounded_native_profile_cannot_borrow192_or_foreign_group_command_or_quota() {
        let argv = enrollment128::parent_argv();
        let profile = json!({"Id":PARENT128,"LoadState":"loaded","Type":"exec","User":"sol","Group":"horizon",
            "MemoryAccounting":"yes","MemoryMax":HARD128.to_string(),"MemorySwapMax":"0","CPUQuotaPerSecUSec":"8s",
            "TasksMax":"1024","Restart":"no","NRestarts":"0","ControlGroup":format!("/system.slice/{PARENT128}"),
            "ExecStart":format!("{{ path={} ; argv[]={} ; ignore_errors=no ; }}",NODE_IMAGE,argv.join(" "))});
        raw_profile(&profile).unwrap();
        for (key, value) in [
            ("MemoryMax", json!((192u64 << 30).to_string())),
            ("Group", json!("sol")),
            ("CPUQuotaPerSecUSec", json!("12s")),
            ("NRestarts", json!("1")),
            ("Id", json!(super::super::UNIT)),
            (
                "ExecStart",
                json!("{ path=/other ; argv[]=/other ; ignore_errors=no ; }"),
            ),
        ] {
            let mut changed = profile.clone();
            changed[key] = value;
            assert!(raw_profile(&changed).is_err(), "{key}");
        }
    }
    #[test]
    fn native_scope_does_not_alias_ordinary192_route() {
        for unit in [
            super::super::UNIT,
            super::super::GUARD,
            super::super::TIMER,
            super::super::STOP,
        ] {
            assert!(!native_namespace(unit));
        }
        for unit in [PARENT128, GUARD128, STOP128, TIMER128, ADMIT128, ENROLL128] {
            assert!(native_namespace(unit));
        }
    }
    #[test]
    fn foreign_epoch_and_duplicate_bounded_declaration_rejected() {
        let b = json!({"path":REGISTER128,"sha256":"a".repeat(64)});
        let row = json!({"epoch":163,"unit":PARENT128,"launch_receipt":b});
        assert!(
            declared(&json!({"diagnostics":[row.clone()]}))
                .unwrap()
                .is_some()
        );
        assert!(declared(&json!({"diagnostics":[row.clone(),row.clone()]})).is_err());
        let mut bad = row;
        bad["epoch"] = json!(164);
        assert!(declared(&json!({"diagnostics":[bad]})).is_err());
    }
}
