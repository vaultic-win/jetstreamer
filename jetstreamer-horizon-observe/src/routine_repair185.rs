//! Exact admitted repair185-185 observer/model adoption; never replay authority.
use super::*;
const CONTROLLER: &str = "jetstreamer-epoch185-full-20261023-controller-v1-r2.service";
const PRODUCER: &str = "jetstreamer-root-sweep-e185-full-20261023-v1-r2-e185-185-lane-a-1.service";
const GUARD: &str = "jetstreamer-adaptive-reserve-epoch185-full-20261023-v1.service";
const GUARD_SCRIPT: &str = "/usr/local/lib/jetstreamer/adaptive-reserve-epochs191-194-20261016-v1/guard-adaptive-replay-reserve.py";
const GUARD_SHA: &str = "b62e58f5be764935a679408e1fcc446a9768170109a6639c87fd01571b9f2b62";
const GUARD_FLOOR: u64 = 3_503_746_342_342;
const FIRST_END: u64 = 80_351_999;
const FINAL_END: u64 = 80_351_999;
const ROOT: &str =
    "/home/sol/.jetstreamer-private/epoch185-singleton-20261020-v1/lane-a/private";

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Handoff {
    schema: String,
    controller_invocation_id: String,
    producer_invocation_id: String,
    archive_directory: PathBuf,
    scratch_path: PathBuf,
    observer_before_launch: Bound,
    admission: Bound,
    guard_first_fire: Bound,
    capability: Bound,
    new_resource_samples: u64,
    replay_launch_authorized: bool,
    publication_authorized: bool,
    remote_mutations: bool,
    r2_mutations: bool,
}
fn iid(s: &str) -> bool {
    s.len() == 32
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn scope(h: &Handoff) -> Result<()> {
    ensure!(
        h.schema == "jetstreamer-horizon-repair185-live-monitor-handoff-v1"
            && iid(&h.controller_invocation_id)
            && iid(&h.producer_invocation_id)
            && h.new_resource_samples == 0
            && !h.replay_launch_authorized
            && !h.publication_authorized
            && !h.remote_mutations
            && !h.r2_mutations,
        "repair185 handoff grants authority or has invalid identities"
    );
    let scratch = &h.scratch_path;
    ensure!(
        scratch.is_absolute()
            && scratch.starts_with(ROOT)
            && scratch.components().all(|c| matches!(
                c,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            ))
            && scratch.file_name().and_then(|s| s.to_str()) == Some("scratch")
            && scratch
                .parent()
                .and_then(|p| p.file_name())
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with("run-"))
            && scratch
                .parent()
                .and_then(|p| p.parent())
                .and_then(|p| p.file_name())
                .and_then(|s| s.to_str())
                == Some("root-cohort-185-185")
            && h.archive_directory
                == scratch
                    .parent()
                    .context("repair185 run parent")?
                    .join("archives"),
        "repair185 private archive/scratch scope differs"
    );
    ensure!(
        h.capability.path
            == Path::new(
                "/usr/local/lib/jetstreamer/horizon-epoch185-package-capability-20261020-v1/capability.json"
            )
            && h.capability.sha256
                == "cf0eaedd746ed8c884e04521861364534728e94e13cd9b95e69129d7543fc0eb",
        "repair185 capability binding differs"
    );
    Ok(())
}
fn guard(h: &Handoff, v: &Value) -> Result<()> {
    let s = &v["sample"];
    ensure!(
        v["schema"] == "jetstreamer-horizon-repair185-guard-first-fire-v1"
            && v["admission"] == serde_json::to_value(&h.admission)?
            && v["unit"] == GUARD
            && iid(v["invocation_id"].as_str().unwrap_or(""))
            && v["actual_timer_fired_success"] == true
            && v["exit_status"] == 0
            && v["restarts"] == 0
            && v["stop_intent_absent"] == true
            && v["stop_completion_absent"] == true
            && s["armed"] == true
            && s["trip"] == false
            && s["controller"]["active_state"] == "active"
            && s["producer"]["active_state"] == "active"
            && s["controller"]["invocation_id"] == h.controller_invocation_id
            && s["producer"]["invocation_id"] == h.producer_invocation_id
            && s["controller"]["restarts"] == 0
            && s["producer"]["restarts"] == 0
            && s["minimum_free_bytes"] == GUARD_FLOOR
            && s["available_bytes"]
                .as_u64()
                .is_some_and(|n| n >= GUARD_FLOOR)
            && s["maximum_worker_vmas"] == 800000
            && s["producer"]["worker_count"] == 1
            && s["producer"]["worker_vmas"]
                .as_u64()
                .is_some_and(|n| n > 0 && n <= 800000),
        "repair185 guard first-fire proof differs"
    );
    for key in [
        "replay_launch_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(v[key] == false, "repair185 guard proof grants authority");
    }
    Ok(())
}
fn live_guard(h: &Handoff) -> Result<()> {
    tool_ok(&Bound {
        path: GUARD_SCRIPT.into(),
        sha256: GUARD_SHA.into(),
    })?;
    let timer = GUARD.replace(".service", ".timer");
    for (unit, is_timer) in [(GUARD, false), (timer.as_str(), true)] {
        let out=Command::new("/usr/bin/systemctl").args(["show",unit,"--property=ActiveState,SubState,Result,NRestarts,ExecMainStatus,ExecStart,Triggers"]).output()?;
        ensure!(
            out.status.success() && out.stdout.len() < 32768,
            "repair185 guard manager read failed"
        );
        let text = std::str::from_utf8(&out.stdout)?;
        let values: BTreeMap<_, _> = text.lines().filter_map(|s| s.split_once('=')).collect();
        if is_timer {
            ensure!(
                values.get("ActiveState") == Some(&"active")
                    && values.get("Triggers") == Some(&GUARD),
                "repair185 guard timer is not active for its exact service"
            );
        } else {
            ensure!(
                values.get("Result") == Some(&"success")
                    && values.get("NRestarts") == Some(&"0")
                    && values.get("ExecMainStatus") == Some(&"0"),
                "repair185 guard is not healthy"
            );
            let command = values.get("ExecStart").context("repair185 guard command")?;
            ensure!(
                command
                    .split_whitespace()
                    .filter(|w| *w == GUARD_SCRIPT)
                    .count()
                    == 1,
                "repair185 guard executable differs"
            );
            for token in [
                format!("--controller-unit={CONTROLLER}"),
                format!("--producer-unit={PRODUCER}"),
                format!(
                    "--expected-controller-invocation-id={}",
                    h.controller_invocation_id
                ),
                format!(
                    "--expected-producer-invocation-id={}",
                    h.producer_invocation_id
                ),
                format!("--minimum-free-bytes={GUARD_FLOOR}"),
                "--maximum-worker-vmas=800000".into(),
            ] {
                ensure!(
                    command.split_whitespace().filter(|w| *w == token).count() == 1,
                    "repair185 guard command binding differs"
                );
            }
        }
    }
    Ok(())
}
fn proof(p: &Plan) -> Result<Option<Handoff>> {
    let Some(b) = &p.repair185_handoff else {
        return Ok(None);
    };
    ensure!(
        is_101(p)? && p.publication144.is_some() && p.repair183_handoff.is_some(),
        "foreign repair185 profile"
    );
    ensure!(
        b.path.starts_with("/usr/local/lib/jetstreamer")
            && b.path.file_name().and_then(|s| s.to_str()) == Some("handoff.json"),
        "repair185 handoff namespace"
    );
    let h: Handoff = serde_json::from_value(bound_json(b, true)?)?;
    scope(&h)?;
    let cap = bound_json(&h.capability, true)?;
    ensure!(
        cap["epoch"] == 185 && cap["replay_launch_authorized"] == false,
        "repair185 original capability differs"
    );
    let admission = bound_json(&h.admission, false)?;
    ensure!(
        h.admission.path.starts_with("/var/lib/jetstreamer")
            && h.admission.path.file_name().and_then(|s| s.to_str())
                == Some("admission-receipt.json")
            && admission["schema"] == "jetstreamer-historical-performance-admission-receipt-v1"
            && admission["admitted"] == true
            && admission["services_started"] == false
            && admission["remote_mutations"] == false
            && admission["r2_mutations"] == false
            && admission["evidence"]["minimum_free_bytes"]
                .as_u64()
                .is_some_and(|n| n >= GUARD_FLOOR + (768u64 << 30))
            && admission["evidence"]["minimum_memory_available_bytes"]
                .as_u64()
                .is_some_and(|n| n >= 320u64 << 30)
            && admission["evidence"]["minimum_vm_max_map_count"]
                .as_u64()
                .is_some_and(|n| n >= 4194304),
        "repair185 full admission proof differs"
    );
    let manifest: Bound = serde_json::from_value(
        json!({"path":admission["manifest"],"sha256":admission["manifest_sha256"]}),
    )?;
    let m = bound_json(&manifest, true)?;
    ensure!(
        m["snapshot"]["path"]
            == "/usr/local/lib/jetstreamer/deploy-epoch185-singleton-20261020-v1/snapshot-79919283-Hozk66F2tKQuhouHceuwU9xZzWaXksnBeU1JBysRBmmf.tar.zst"
            && m["snapshot"]["size"] == 7250303600u64
            && m["snapshot"]["crc32c_base64"] == "kaWIJg=="
            && m["snapshot"]["md5_base64"] == "jP6QpLlFKYPq4AC25GQUJQ==",
        "repair185 admitted snapshot differs"
    );
    let before = bound_json(&h.observer_before_launch, false)?;
    ensure!(before["cadence"]["routine_minimum_interval_enforced"] == true
        && before["cadence"]["observed_interval_seconds"].as_u64().is_some_and(|n| n >= 1800)
        && before["replays"].as_array().is_some_and(|rs| rs.len() == 4 && rs.iter().all(|r|
            r["invocation_binding_stable"] == true && r["useful_work"]["sufficient_for_rates"] == true
            && r["worker_after"]["matching_workers"] == 1
            && r["worker_after"]["vmas"].as_u64().is_some_and(|n| n > 0 && n <= 800000)
            && r["cross_sample"]["producer_cgroup_counter_delta"]["memory_events.oom"] == 0)),
        "repair185 admission lacks the settled clean four-lane operating point");
    ensure!(
        before["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && m["json_receipts"]
                .as_array()
                .is_some_and(|rows| rows.iter().any(|r| r["path"]
                    == h.observer_before_launch.path.to_str().unwrap_or("")
                    && r["sha256"] == h.observer_before_launch.sha256)),
        "repair185 admission does not bind the exact prelaunch observer"
    );
    guard(&h, &bound_json(&h.guard_first_fire, true)?)?;
    Ok(Some(h))
}
pub(super) fn validate_live(p: &Plan) -> Result<()> {
    if let Some(h) = proof(p)? { live_guard(&h)?; }
    Ok(())
}
pub(super) fn extend_epochs(p: &Plan, epochs: &mut BTreeSet<u64>) -> Result<()> {
    if let Some(h) = proof(p)? {
        epochs.insert(185);
        scope(&h)?;
    }
    Ok(())
}
fn apply(model: &Value, h: &Handoff) -> Result<Value> {
    scope(h)?;
    let mut v = model.clone();
    if v["unestimated_bootstrap_epochs"] == json!([185]) { v.as_object_mut().unwrap().remove("unestimated_bootstrap_epochs"); }
    if let Some(census) = v.get_mut("expected_observer_ranges") {
        let census = census.as_array_mut().context("repair185 observer census")?;
        if !census.contains(&json!("185-185")) {
            census.push(json!("185-185"));
        }
    }
    let ranges = v["ranges"].as_array_mut().context("repair185 ranges")?;
    let indices: Vec<_> = ranges
        .iter()
        .enumerate()
        .filter(|(_, r)| {
            r["epochs"]
                .as_array()
                .is_some_and(|es| es.iter().any(|e| e == 185))
        })
        .map(|(i, _)| i)
        .collect();
    if indices.is_empty() {
        ensure!(
            ranges.len() == 4
                && ranges
                    .iter()
                    .map(|r| r["range"].as_str().unwrap_or(""))
                    .collect::<BTreeSet<_>>()
                    == BTreeSet::from(["152-153", "155-156", "191-194", "183-184"]),
            "repair185 baseline census differs"
        );
        ranges.push(json!({"range":"185-185","epochs":[185],"archive_directory":h.archive_directory,
            "expected_controller_invocation_id":h.controller_invocation_id,"expected_producer_invocation_id":h.producer_invocation_id,
            "terminal_slot":FIRST_END,"epoch_additional_replay_slots":{"185":0},
            "epoch_downstream_allowance_seconds":{"185":43200},
            "formula":{"185":"remaining observed epoch185 slots / observed rate +12h independent import/full/plugin/upload/readback allowance"}}));
    } else {
        ensure!(indices.len() == 1, "overlapping repair185 claims");
        let r = &ranges[indices[0]];
        ensure!(
            r["range"] == "185-185"
                && r["epochs"] == json!([185])
                && r["archive_directory"] == h.archive_directory.to_str().unwrap_or("")
                && r["expected_controller_invocation_id"] == h.controller_invocation_id
                && r["expected_producer_invocation_id"] == h.producer_invocation_id
                && r.get("elapsed_execution_millis").is_none(),
            "repair185 existing model owner/clock differs"
        );
        let terminal = r["terminal_slot"].as_u64().context("repair185 terminal")?;
        ensure!(
            terminal == FIRST_END,
            "repair185 terminal is outside exact cohort"
        );
        {
            let (e, allowance) = ("185", 43200);
            ensure!(
                r["epoch_additional_replay_slots"][e] == FINAL_END - terminal
                    && r["epoch_downstream_allowance_seconds"][e] == allowance,
                "repair185 gated work/allowance changed"
            );
        }
    }
    Ok(v)
}
pub(super) fn effective_model(p: &Plan, model: &Value) -> Result<Value> {
    let Some(h) = proof(p)? else {
        return Ok(model.clone());
    };
    let already = model["ranges"]
        .as_array()
        .context("repair185 ranges")?
        .iter()
        .any(|r| r["range"] == "185-185");
    if !already {
        let continued_bootstrap = bootstrap_model(p, model);
        if continued_bootstrap {
            let prior = bound_json(&p.previous_observer, false)?;
            let checked = observation(model, &h, &prior)?;
            ensure!(checked["unestimated_bootstrap_epochs"] == json!([185]),
                "repair185 bootstrap predecessor changed");
        }
        ensure!(
            continued_bootstrap || (h.observer_before_launch.path == p.previous_observer.path
                && h.observer_before_launch.sha256 == p.previous_observer.sha256),
            "repair185 initial predecessor differs"
        );
    }
    let mut v = apply(model, &h)?;
    let b = serde_json::to_value(p.repair185_handoff.as_ref().unwrap())?;
    let evidence = v["evidence"].as_array_mut().context("repair185 evidence")?;
    if !evidence.contains(&b) {
        evidence.push(b);
    }
    Ok(v)
}
pub(super) fn derive_fleet(p: &Plan, fleet: &mut Value) -> Result<()> {
    if proof(p)?.is_none() {
        return Ok(());
    }
    let tracked = fleet["tracked_units"]
        .as_array_mut()
        .context("repair185 fleet tracked units")?;
    for unit in [
        CONTROLLER.to_owned(),
        PRODUCER.to_owned(),
    ] {
        let value = json!(unit);
        if !tracked.contains(&value) {
            tracked.push(value);
        }
    }
    {
        let epoch = "185";
        let e = serde_json::to_value(p.repair185_handoff.as_ref().unwrap())?;
        let gate = &mut fleet["gates"][epoch];
        replacement_gate(gate)?;
        ensure!(
            gate["state"] == "failed-needs-repair",
            "repair185 original open repair gate changed"
        );
        let evidence = gate["evidence"]
            .as_array_mut()
            .context("repair185 gate evidence")?;
        if !evidence.contains(&e) {
            evidence.push(e);
        }
        gate["next_action"] = json!(
            "Track the freshly admitted, independently publishable185 singleton under exact guarded controller/producer identities. Its terminal is80351999 with no queued-cohort offset and12h downstream allowance. Keep the original reserve-stop/source repair open through canonical/full/plugin checks and authenticated ready pair; launch alone is not recovery."
        );
    }
    Ok(())
}
pub(super) fn for_observation(p: &Plan, model: &Value, observed: &Value) -> Result<Value> {
    let Some(h) = proof(p)? else {
        return Ok(model.clone());
    };
    if observed["replays"].as_array().is_some_and(|rs| rs.iter().any(|r|
        r["range"] == "185-185" && r["useful_work"]["last"].is_null())) {
        let prior = bound_json(&p.previous_observer, false)?;
        if let Some(old) = prior["replays"].as_array().and_then(|rs| rs.iter().find(|r| r["range"] == "185-185")) {
            ensure!(old["useful_work"]["last"].is_null() && old["useful_work"]["first"].is_null()
                && old["useful_work"]["matching_markers"] == 0,
                "repair185 cannot revert established replay to bootstrap");
        }
    }
    observation(model, &h, observed)
}
fn observation(model: &Value, h: &Handoff, observed: &Value) -> Result<Value> {
    let mut v = apply(model, h)?;
    let rows: Vec<_> = observed["replays"]
        .as_array()
        .context("repair185 observation census")?
        .iter()
        .filter(|r| r["range"] == "185-185")
        .collect();
    ensure!(rows.len() == 1, "repair185 missing/duplicate observation");
    let o = rows[0];
    ensure!(
        o["controller_before"]["unit"] == CONTROLLER
            && o["producer_before"]["unit"] == PRODUCER
            && o["scratch_path"] == h.scratch_path.to_str().unwrap_or(""),
        "repair185 observed paths/units differ"
    );
    ensure!(
        o["invocation_binding_stable"] == true,
        "repair185 unstable observation"
    );
    for (kind, id) in [
        ("controller", &h.controller_invocation_id),
        ("producer", &h.producer_invocation_id),
    ] {
        for point in ["before", "after"] {
            let s = &o[format!("{kind}_{point}")];
            ensure!(
                s["invocation_id"] == *id && s["restarts"] == 0 && s["active_state"] == "active",
                "repair185 observed owner changed"
            );
        }
    }
    if o["useful_work"]["last"].is_null() {
        ensure!(o["useful_work"]["first"].is_null()
            && o["useful_work"]["matching_markers"] == 0
            && o["useful_work"]["counter_resets"] == 0
            && o["useful_work"]["sufficient_for_rates"] == false
            && o["useful_work"]["slots_per_second"].is_null()
            && v["ranges"].as_array().unwrap().iter().find(|r| r["range"] == "185-185").unwrap()["terminal_slot"] == FIRST_END,
            "repair185 absent progress is not initial bootstrap");
        for point in ["before", "after"] {
            let worker = &o[format!("worker_{point}")];
            ensure!(worker["matching_workers"] == 1
                && worker["executable_beneath_bound_scratch"] == true
                && worker["vmas"].as_u64().is_some_and(|n| n > 0 && n <= 800000),
                "repair185 bootstrap worker is not protected");
        }
        v["ranges"].as_array_mut().unwrap().retain(|r| r["range"] != "185-185");
        v["unestimated_bootstrap_epochs"] = json!([185]);
        return Ok(v);
    }
    let terminal = o["useful_work"]["last"]["terminal_slot"]
        .as_u64()
        .context("repair185 observed terminal")?;
    let ranges = v["ranges"].as_array_mut().unwrap();
    let r = ranges.iter_mut().find(|r| r["range"] == "185-185").unwrap();
    let previous = r["terminal_slot"].as_u64().unwrap();
    ensure!(
        terminal == FIRST_END && terminal >= previous,
        "repair185 backward/unknown terminal"
    );
    r["terminal_slot"] = json!(terminal);
    {
        let (epoch, allowance) = ("185", 43200);
        r["epoch_additional_replay_slots"][epoch] = json!(FINAL_END - terminal);
        r["formula"][epoch] = json!(format!(
            "remaining observed slots plus{} queued gated slots / observed rate +{allowance}s downstream; independent epoch185 import gate",
            FINAL_END - terminal
        ));
    }
    Ok(v)
}

pub(super) fn bootstrap_model(p: &Plan, model: &Value) -> bool {
    p.repair185_handoff.as_ref().is_some_and(|b|
        model["unestimated_bootstrap_epochs"] == json!([185])
        && model["ranges"].as_array().is_some_and(|rs| rs.len() == 4 && !rs.iter().any(|r| r["range"] == "185-185"))
        && model["expected_observer_ranges"].as_array().is_some_and(|rs| rs.len() == 5 && rs.contains(&json!("185-185")))
        && model["evidence"].as_array().is_some_and(|es| es.contains(&serde_json::to_value(b).unwrap())))
}


pub(super) fn replacement_gate(gate: &mut Value) -> Result<()> {
    let binding = Bound { path: "/usr/local/lib/jetstreamer/horizon-epoch185-reserve-stop-history-20261023-v1/history.json".into(), sha256: "1739cdf4f724a0843d7406bd3ae904fea0421356c52f2242030bcfbba29fb8e2".into() };
    let history = bound_json(&binding, true)?;
    let source: Bound = serde_json::from_value(history["source_fleet_plan"].clone())?;
    ensure!(bound_json(&source, true)?["gates"]["185"]["reserve_stop"] == history["original_stop"],
        "repair185 historical stop differs from original immutable gate");
    replacement_gate_with(gate, &history, &binding)
}
fn replacement_gate_with(gate: &mut Value, history: &Value, binding: &Bound) -> Result<()> {
    let stop = &history["original_stop"];
    ensure!(history["schema"] == "jetstreamer-horizon-epoch185-reserve-stop-history-v1"
        && history["epoch"] == 185 && history["repair_closed"] == false
        && ["replay_launch_authorized","publication_authorized","remote_mutations","r2_mutations"].iter().all(|k| history[*k] == false)
        && stop["epoch"] == 185
        && stop["controller_unit"] == "jetstreamer-epoch185-singleton-20261020-controller-v1-r2.service"
        && stop["controller_invocation_id"] == "5aae80ffd2364f0aa984c1ae1737ca4d"
        && stop["producer_unit"] == "jetstreamer-root-sweep-e185-s1-20261020-v1-r2-e185-185-lane-a-1.service"
        && stop["producer_invocation_id"] == "557be07ab87d47fbac93afe1876a4281"
        && gate["state"] == "failed-needs-repair",
        "repair185 cannot retire a foreign stop or close the repair");
    let evidence = gate["evidence"].as_array().context("repair185 stop evidence")?;
    ensure!(["intent","completion"].iter().all(|key| evidence.contains(&stop[*key])),
        "repair185 must retain both original stop receipts");
    let value = serde_json::to_value(binding)?;
    if gate["reserve_stop"].is_null() {
        ensure!(evidence.contains(&value), "repair185 replacement lost its stop history");
        return Ok(());
    }
    ensure!(gate["reserve_stop"] == *stop, "repair185 replacement cannot remove another stop");
    gate.as_object_mut().context("repair185 gate object")?.remove("reserve_stop");
    let evidence = gate["evidence"].as_array_mut().unwrap();
    if !evidence.contains(&value) { evidence.push(value); }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn replacement_preserves_stop_as_history_without_discarding_the_new_claim() {
        let stop = json!({"epoch":185,"controller_unit":"jetstreamer-epoch185-singleton-20261020-controller-v1-r2.service",
            "controller_invocation_id":"5aae80ffd2364f0aa984c1ae1737ca4d","producer_unit":"jetstreamer-root-sweep-e185-s1-20261020-v1-r2-e185-185-lane-a-1.service",
            "producer_invocation_id":"557be07ab87d47fbac93afe1876a4281","intent":{"path":"/intent","sha256":"a".repeat(64)},"completion":{"path":"/completion","sha256":"b".repeat(64)}});
        let h = json!({"schema":"jetstreamer-horizon-epoch185-reserve-stop-history-v1","epoch":185,"original_stop":stop,"repair_closed":false,
            "replay_launch_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false});
        let bound = Bound{path:"/history".into(),sha256:"c".repeat(64)};
        let original = json!({"state":"failed-needs-repair","reserve_stop":stop,"evidence":[stop["intent"],stop["completion"]],"sentinel":u64::MAX});
        let mut fixed=original.clone(); replacement_gate_with(&mut fixed,&h,&bound).unwrap();
        assert!(fixed["reserve_stop"].is_null());assert_eq!(fixed["state"],"failed-needs-repair");assert_eq!(fixed["sentinel"],u64::MAX);
        assert_eq!(&fixed["evidence"].as_array().unwrap()[..2],original["evidence"].as_array().unwrap().as_slice());
        let repeat=fixed.clone();replacement_gate_with(&mut fixed,&h,&bound).unwrap();assert_eq!(fixed,repeat);
        for (key,value) in [("reserve_stop",json!({"epoch":186})),("state",json!("remote-ready")),("evidence",json!([]))] {
            let mut bad=original.clone();bad[key]=value;assert!(replacement_gate_with(&mut bad,&h,&bound).is_err(),"{key}");
        }
        let mut bad_history=h;bad_history["repair_closed"]=json!(true);
        assert!(replacement_gate_with(&mut original.clone(),&bad_history,&bound).is_err());
    }
    fn h() -> Handoff {
        serde_json::from_value(json!({"schema":"jetstreamer-horizon-repair185-live-monitor-handoff-v1",
            "controller_invocation_id":"a".repeat(32),"producer_invocation_id":"b".repeat(32),
            "archive_directory":format!("{ROOT}/destination-x/work/root-cohort-185-185/run-1/archives"),
            "scratch_path":format!("{ROOT}/destination-x/work/root-cohort-185-185/run-1/scratch"),
            "observer_before_launch":{"path":"/sample","sha256":"c".repeat(64)},
            "admission":{"path":"/admit","sha256":"d".repeat(64)},
            "guard_first_fire":{"path":"/guard","sha256":"e".repeat(64)},
            "capability":{"path":"/usr/local/lib/jetstreamer/horizon-epoch185-package-capability-20261020-v1/capability.json","sha256":"cf0eaedd746ed8c884e04521861364534728e94e13cd9b95e69129d7543fc0eb"},
            "new_resource_samples":0,"replay_launch_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false})).unwrap()
    }
    fn model() -> Value {
        json!({"ranges":[{"range":"152-153","epochs":[152,153]},{"range":"155-156","epochs":[155,156]},
            {"range":"191-194","epochs":[191,192,193,194]},{"range":"183-184","epochs":[183,184]}],
            "expected_observer_ranges":["152-153","155-156","191-194","183-184"],"evidence":[],"sentinel":u64::MAX})
    }
    fn observed(h: &Handoff) -> Value {
        let owner = |unit:&str,id:&str|json!({"unit":unit,"invocation_id":id,"active_state":"active","restarts":0});
        let worker=json!({"matching_workers":1,"executable_beneath_bound_scratch":true,"vmas":400000});
        json!({"replays":[{"range":"185-185","scratch_path":h.scratch_path,"invocation_binding_stable":true,
            "controller_before":owner(CONTROLLER,&h.controller_invocation_id),"controller_after":owner(CONTROLLER,&h.controller_invocation_id),
            "producer_before":owner(PRODUCER,&h.producer_invocation_id),"producer_after":owner(PRODUCER,&h.producer_invocation_id),
            "worker_before":worker,"worker_after":worker,"useful_work":{"first":null,"last":null,"matching_markers":0,"counter_resets":0,"sufficient_for_rates":false,"slots_per_second":null}}]})
    }
    #[test]
    fn singleton_adoption_preserves_all_older_work_and_independent_commit() {
        let m=model(); let a=apply(&m,&h()).unwrap();
        assert_eq!(&a["ranges"].as_array().unwrap()[..4],m["ranges"].as_array().unwrap().as_slice());
        assert_eq!(a["ranges"][4]["epochs"],json!([185]));
        assert_eq!(a["ranges"][4]["terminal_slot"],80351999);
        assert_eq!(a["ranges"][4]["epoch_additional_replay_slots"],json!({"185":0}));
        assert_eq!(a["ranges"][4]["epoch_downstream_allowance_seconds"],json!({"185":43200}));
        assert_eq!(a["expected_observer_ranges"].as_array().unwrap().len(),5);
        assert_eq!(a["sentinel"],u64::MAX);
        assert_eq!(apply(&a,&h()).unwrap(),a);
        let id=PRODUCER.strip_prefix("jetstreamer-root-sweep-").unwrap().strip_suffix("-e185-185-lane-a-1.service").unwrap();
        assert!(id.len()<=32);
    }
    #[test]
    fn wrong_scope_clock_allowance_or_authority_rejected() {
        let mut v=apply(&model(),&h()).unwrap();
        for (key,value) in [("epoch_additional_replay_slots",json!({"185":1})),("epoch_downstream_allowance_seconds",json!({"185":1})),("epochs",json!([185,186])),("elapsed_execution_millis",json!(0))] {
            let mut bad=v.clone();bad["ranges"][4][key]=value; assert!(apply(&bad,&h()).is_err(),"{key}");
        }
        v["ranges"][4]["terminal_slot"]=json!(80352000);
        assert!(apply(&v,&h()).is_err());
        let mut bad=h();bad.publication_authorized=true;assert!(apply(&model(),&bad).is_err());
        let mut bad=h();bad.scratch_path="/outside/scratch".into();assert!(apply(&model(),&bad).is_err());
    }
    #[test]
    fn bootstrap_is_unestimated_without_dropping_the_five_range_census() {
        let h=h();let o=observed(&h); let v=observation(&model(),&h,&o).unwrap();
        assert_eq!(v["ranges"],model()["ranges"]);
        assert_eq!(v["expected_observer_ranges"].as_array().unwrap().len(),5);
        assert_eq!(v["unestimated_bootstrap_epochs"],json!([185]));
        for (path,value) in [("/replays/0/worker_after/matching_workers",json!(0)),("/replays/0/worker_after/vmas",json!(800001)),("/replays/0/useful_work/matching_markers",json!(1)),("/replays/0/producer_after/restarts",json!(1))] {
            let mut bad=o.clone();*bad.pointer_mut(path).unwrap()=value; assert!(observation(&model(),&h,&bad).is_err(),"{path}");
        }
        let mut replay=o;replay["replays"][0]["useful_work"]["last"]=json!({"terminal_slot":80351999});
        let modeled=observation(&model(),&h,&replay).unwrap();
        assert_eq!(modeled["ranges"].as_array().unwrap().len(),5);
        replay["replays"][0]["useful_work"]["last"]["terminal_slot"]=json!(80352000);
        assert!(observation(&model(),&h,&replay).is_err());
    }
    #[test]
    fn guard_requires_actual_nested_output_and_all_older_growth_protection() {
        let h=h();
        let good=json!({"schema":"jetstreamer-horizon-repair185-guard-first-fire-v1","admission":h.admission,"unit":GUARD,
            "invocation_id":"f".repeat(32),"actual_timer_fired_success":true,"exit_status":0,"restarts":0,"stop_intent_absent":true,
            "stop_completion_absent":true,"replay_launch_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false,
            "sample":{"armed":true,"trip":false,"controller":{"active_state":"active","invocation_id":h.controller_invocation_id,"restarts":0},
                "producer":{"active_state":"active","invocation_id":h.producer_invocation_id,"restarts":0,"worker_count":1,"worker_vmas":1000},
                "minimum_free_bytes":GUARD_FLOOR,"available_bytes":GUARD_FLOOR+1,"maximum_worker_vmas":800000}});
        guard(&h,&good).unwrap();
        for (path,value) in [("/actual_timer_fired_success",json!(false)),("/sample/minimum_free_bytes",json!(GUARD_FLOOR-1)),
            ("/sample/producer/worker_count",json!(0)),("/sample/producer/restarts",json!(1)),("/sample/trip",json!(true)),("/replay_launch_authorized",json!(true))] {
            let mut bad=good.clone();*bad.pointer_mut(path).unwrap()=value;assert!(guard(&h,&bad).is_err(),"{path}");
        }
    }
}
