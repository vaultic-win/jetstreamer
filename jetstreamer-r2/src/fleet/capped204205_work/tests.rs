//! Synthetic captured evidence only. No fixture is an actual launch, resource
//! admission, service observation or publication receipt for either epoch.
use super::*;

fn b(name: &str) -> BoundFile {
    BoundFile {
        path: Path::new("/fixture").join(name),
        sha256: "a".repeat(64),
    }
}
fn claim(epoch: u64) -> Claim {
    Claim {
        epoch,
        producer_plan: b("producer.json"),
        admission: b("admission.json"),
        launch: b("launch.json"),
        frame: b("frame.json"),
        eta_policy: b("eta.json"),
    }
}
fn policy() -> Value {
    json!({"schema":"jetstreamer-capped204205-sidecar-estimate-policy-v1",
    "estimate_basis":"Synthetic throughput and independent complete-path planning fixtures",
    "sidecar_inclusive":true,"estimates_are_current_best_guesses":true,"current_stage_overrun_remaining_millis":50,
    "stage_allowance_millis":STAGES.into_iter().map(|s|(s.key(),100u64)).collect::<BTreeMap<_,_>>(),
    "replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false})
}
fn owner(name: &str, iid: &str, pid: u64) -> Value {
    json!({"Id":name,"LoadState":"loaded","InvocationID":iid,
    "NRestarts":"0","MainPID":pid.to_string(),"ActiveState":"active","SubState":"running"})
}
fn inactive_owner(name: &str) -> Value {
    json!({"Id":name,"LoadState":"not-found","InvocationID":"",
    "NRestarts":"0","MainPID":"0","ActiveState":"inactive","SubState":"dead"})
}
fn plan() -> Value {
    json!({"epoch":204,"producer_unit":"horizon-qualify-204-capped-continuation-fixture.service",
    "guard_unit":"horizon-guard-204-capped-continuation-fixture.service","guard_sha256":"b".repeat(64),
    "maximum_stage_millis":1000000,"maximum_process_rss_bytes":150000000000u64,
    "maximum_worker_vmas":3500000,"maximum_root_physical_bytes":300000000000u64,"protected_existing_floor_bytes":1000000000000u64})
}
fn launch() -> Value {
    json!({"invocation_id":"c".repeat(32),"guard_invocation_id":"d".repeat(32),
    "producer_plan":{"path":"/fixture/producer.json","sha256":"a".repeat(64)}})
}
fn guard(p: &Value, l: &Value) -> Value {
    json!({"schema":"jetstreamer-capped204205-guard-heartbeat-v1","epoch":204,
    "producer_unit":p["producer_unit"],"producer_invocation_id":l["invocation_id"],"guard_unit":p["guard_unit"],
    "guard_invocation_id":l["guard_invocation_id"],"guard_sha256":p["guard_sha256"],"plan_sha256":"a".repeat(64),
    "recorded_unix_millis":1000,"producer_stop_enabled":true,"trip":false,
    "phase":{"schema":"jetstreamer-capped204205-continuation-phase-v1","epoch":204,"invocation_id":l["invocation_id"],
        "plan_sha256":"a".repeat(64),"stage":"prefix_validation","started_unix_millis":500},
    "processes":{"main_pid":42,"total_process_rss_bytes":900719925474u64,"workers":[]},
    "maximum_process_rss_bytes":p["maximum_process_rss_bytes"],"maximum_worker_vmas":p["maximum_worker_vmas"],
    "maximum_root_physical_bytes":p["maximum_root_physical_bytes"],"minimum_free_bytes":p["protected_existing_floor_bytes"],
    "root_physical_observation":{"exceeds_budget":false,"conservative_physical_bytes":100000000000u64},
    "remote_mutations":false,"r2_mutations":false})
}

#[test]
fn all_stages_use_only_legal_dashboard_phases_and_include_sidecar_work() {
    for stage in STAGES {
        assert!(matches!(
            stage.public_phase(),
            "replay" | "verification" | "upload" | "readback"
        ));
    }
    assert_eq!(
        remaining(&policy(), Stage::WaitingForGuard, 0).unwrap(),
        1200
    );
    assert_eq!(remaining(&policy(), Stage::NativeRestore, 25).unwrap(), 975);
    assert_eq!(remaining(&policy(), Stage::Readback, 10).unwrap(), 190);
    assert_eq!(remaining(&policy(), Stage::SidecarCommit, 0).unwrap(), 100);
}
#[test]
fn overruns_are_reforecast_without_a_past_or_zero_countdown() {
    assert_eq!(remaining(&policy(), Stage::SidecarCommit, 100).unwrap(), 50);
    assert_eq!(
        remaining(&policy(), Stage::Readback, u64::MAX).unwrap(),
        150
    );
    let mut p = policy();
    p["current_stage_overrun_remaining_millis"] = json!(0);
    assert!(remaining(&p, Stage::Assembly, 100).is_err());
}
#[test]
fn partial_delivery_allowances_and_arithmetic_overflow_fail_closed() {
    let mut p = policy();
    p["stage_allowance_millis"]
        .as_object_mut()
        .unwrap()
        .remove("readback");
    assert!(remaining(&p, Stage::Assembly, 0).is_err());
    let mut p = policy();
    p["stage_allowance_millis"]["sidecar_commit"] = json!(u64::MAX);
    assert!(remaining(&p, Stage::Assembly, 0).is_err());
    let mut p = policy();
    p["sidecar_inclusive"] = json!(false);
    assert!(remaining(&p, Stage::Assembly, 0).is_err());
}
#[test]
fn a_workerless_valid_guard_is_active_work_not_inactivity() {
    let p = plan();
    let l = launch();
    let mut g = guard(&p, &l);
    g["processes"]["total_process_rss_bytes"] = json!(1000000000u64);
    let c = BTreeMap::from([
        (
            string(&p, "producer_unit").unwrap().into(),
            owner(string(&p, "producer_unit").unwrap(), &"c".repeat(32), 42),
        ),
        (
            string(&p, "guard_unit").unwrap().into(),
            owner(string(&p, "guard_unit").unwrap(), &"d".repeat(32), 43),
        ),
    ]);
    evidence::guard(&p, &l, &g, &c, 2000).unwrap();
    for stage in [
        "prefix_validation",
        "suffix_validation",
        "assembly",
        "complete",
    ] {
        g["phase"]["stage"] = json!(stage);
        evidence::guard(&p, &l, &g, &c, 2000).unwrap();
    }
    g["processes"]["workers"] = json!([{"vmas":100}]);
    assert!(evidence::guard(&p, &l, &g, &c, 2000).is_err());
    g["phase"]["stage"] = json!("native_restore");
    evidence::guard(&p, &l, &g, &c, 2000).unwrap();
    assert!(evidence::guard(&p, &l, &g, &c, 61001).is_err());
    g["processes"]["main_pid"] = json!(44);
    assert!(evidence::guard(&p, &l, &g, &c, 2000).is_err());
}
#[test]
fn missing_unavailable_or_replaced_units_cannot_be_called_idle() {
    assert!(!idle(&Value::Null));
    assert!(!idle(&json!({"status":"unavailable"})));
    let mut v = inactive_owner("old.service");
    assert!(idle(&v));
    for (key, value) in [
        ("ActiveState", "activating"),
        ("MainPID", "42"),
        ("NRestarts", "1"),
        ("LoadState", "error"),
    ] {
        let old = v[key].clone();
        v[key] = json!(value);
        assert!(!idle(&v));
        v[key] = old;
    }
}
#[test]
fn positive_inactivity_requires_the_complete_roster_queue_cgroups_and_references() {
    let p = plan();
    let l = launch();
    let unit = string(&p, "producer_unit").unwrap();
    let c = BTreeMap::from([(unit.into(), inactive_owner(unit))]);
    let f = json!({"sampled_at_utc":"2026-10-24T13:00:00Z"});
    let good = json!({"schema":"jetstreamer-capped204205-positive-inactivity-v1","epoch":204,
        "producer_invocation_id":l["invocation_id"],"sampled_at_utc":f["sampled_at_utc"],"unit_census":c,
        "process_reference_census":{"references":[]},"pending_job_units":[],"cgroups":{unit:{"state":"absent"}},
        "replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false});
    evidence::inactive_value(&p, &l, &f, &c, &good).unwrap();
    for (key, value) in [
        ("pending_job_units", json!([unit])),
        (
            "process_reference_census",
            json!({"references":["live process"]}),
        ),
        ("cgroups", json!({})),
        ("unit_census", json!({})),
    ] {
        let mut bad = good.clone();
        bad[key] = value;
        assert!(
            evidence::inactive_value(&p, &l, &f, &c, &bad).is_err(),
            "{key}"
        );
    }
}
#[test]
fn generated_size_uses_the_largest_real_archive_and_does_not_double_count_assembly() {
    let p = json!({"epoch":204,"run_root":"/private/run","prefix_archive":{"path":"/private/original/prefix.jet"},"prefix_bytes":100});
    let row = |path: &str, n: u64, uid: u64| json!({"path":path,"bytes":n,"uid":uid,"links":1,"inode":42,"archive_body_read":false});
    let mut f = json!({"generated_archives":[row("/private/original/prefix.jet",100,0),
        row("/private/run/output/epoch-204-suffix.jet",20,1000),row("/private/run/output/epoch-204-checkpoint-restart-v4.jet",110,1000)]});
    assert_eq!(evidence::generated_bytes(&p, &f).unwrap(), 110);
    f["generated_archives"][0]["bytes"] = json!(101);
    assert!(evidence::generated_bytes(&p, &f).is_err());
    f["generated_archives"][0]["bytes"] = json!(100);
    f["generated_archives"][1]["path"] = json!("/private/other.jet");
    assert!(evidence::generated_bytes(&p, &f).is_err());
}
#[test]
fn raw_manager_success_cannot_be_replaced_by_a_stop_or_another_invocation() {
    let unit = "horizon-qualify-204-capped-continuation-fixture.service";
    let iid = "c".repeat(32);
    let row = |time: &str, cursor: &str, message: &str, id: &str| {
        json!({"_PID":"1","_UID":"0","UNIT":unit,
        "INVOCATION_ID":iid,"__REALTIME_TIMESTAMP":time,"__CURSOR":cursor,"MESSAGE_ID":id,"MESSAGE":message})
    };
    let start = row(
        "1000000",
        "start",
        "Started real owner",
        "39f53479d3a045ac8e11786248231fbf",
    );
    let end = row(
        "2000000",
        "end",
        "Deactivated successfully",
        "7ad2d189f7e94e70a38c781354912448",
    );
    let encode = |rows: Vec<Value>| {
        rows.into_iter()
            .map(|v| serde_json::to_string(&v).unwrap())
            .collect::<Vec<_>>()
            .join("\n")
            .into_bytes()
    };
    assert_eq!(
        capture::manager_history(&encode(vec![start.clone(), end.clone()]), unit, &iid, true)
            .unwrap(),
        1000
    );
    let stop = row("1500000", "stop", "Stopping real owner", "different");
    assert!(
        capture::manager_history(
            &encode(vec![start.clone(), stop, end.clone()]),
            unit,
            &iid,
            true
        )
        .is_err()
    );
    let mut replacement = end;
    replacement["INVOCATION_ID"] = json!("d".repeat(32));
    assert!(
        capture::manager_history(&encode(vec![start, replacement]), unit, &iid, false).is_err()
    );
}
#[test]
fn continuation_binding_cannot_borrow_another_epoch_or_non_dashboard_phase() {
    let name = "horizon-qualify-204-capped-continuation-fixture.service";
    binding_scope(204, name, "replay").unwrap();
    binding_scope(204, name, "verification").unwrap();
    for phase in [
        "qualification",
        "publication",
        "finalization",
        "upload",
        "readback",
    ] {
        assert!(binding_scope(204, name, phase).is_err());
    }
    assert!(binding_scope(205, name, "verification").is_err());
    assert!(binding_scope(203, name, "verification").is_err());
    binding_scope(204, "horizon-upload-204-fixture.service", "readback").unwrap();
}

#[test]
fn derive_plan_preserves_every_unrelated_owner_and_failure_history() {
    let s = evidence::prepare_fixture(claim(204));
    let old = json!({"schema":"jetstreamer-horizon-campaign-fleet-plan-v1","first_epoch":201,"last_epoch":300,
        "tracked_units":["old-failed.service"],"diagnostics":[{"epoch":205,"counter":u64::MAX}],
        "pipeline_claims":[{"epoch":213,"history":"preserve"}],"gates":{"204":{"state":"failed-needs-repair","evidence":["original failure"]}},
        "capped204205_work":[{"epoch":204,"launch":{"path":"/old","sha256":"b".repeat(64)}}]});
    let prior = json!({"schema":SCHEMA,"first_epoch":201,"last_epoch":300,"plan":s.original_plan.path,
        "plan_sha256":s.original_plan.sha256,"unit_census":{"older-collected.service":{}}});
    let frame =
        json!({"unit_census_after":{"new.service":{}},"sampled_at_utc":"2026-10-24T13:00:00Z"});
    let (next, event) = evidence::derive_plan(&s, &old, &prior, &frame).unwrap();
    assert_eq!(next["diagnostics"], old["diagnostics"]);
    assert_eq!(next["pipeline_claims"], old["pipeline_claims"]);
    assert_eq!(next["gates"], old["gates"]);
    assert_eq!(next["capped204205_history"][0], old["capped204205_work"][0]);
    for name in [
        "old-failed.service",
        "older-collected.service",
        "new.service",
    ] {
        assert!(
            next["tracked_units"]
                .as_array()
                .unwrap()
                .contains(&json!(name))
        );
    }
    assert_eq!(event["replay_launch_authorized"], false);
    assert_eq!(event["resource_samples_taken"], 0);
}
