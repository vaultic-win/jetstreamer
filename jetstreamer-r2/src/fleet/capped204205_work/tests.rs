//! Synthetic captured evidence only. No fixture is an actual launch, resource
//! admission, service observation or publication receipt for either epoch.
use super::*;

#[test]
fn first_guard_must_precede_stage_entry_within_actual_wait_window() {
    let first = json!({"recorded_unix_millis":91_000,"phase":{"stage":"waiting_for_guard","started_unix_millis":1000},"processes":{"workers":[]}});
    lifecycle::first_guard_entry(&first, 500).unwrap();
    for (pointer, value) in [
        ("/phase/stage", json!("prefix_validation")),
        ("/processes/workers", json!([{"pid":42}])),
        ("/recorded_unix_millis", json!(91_001)),
        ("/phase/started_unix_millis", json!(499)),
        ("/phase/started_unix_millis", json!(91_001)),
    ] {
        let mut bad = first.clone();
        *bad.pointer_mut(pointer).unwrap() = value;
        assert!(
            lifecycle::first_guard_entry(&bad, 500).is_err(),
            "{pointer}"
        );
    }
    let late = json!({"recorded_unix_millis":901_001,"phase":{"stage":"waiting_for_guard","started_unix_millis":900_000},"processes":{"workers":[]}});
    assert!(lifecycle::first_guard_entry(&late, 1000).is_err());
}

#[test]
fn next_observer_registration_uses_captured_pid1_identity_and_exact_epoch() {
    let mut p = plan();
    p["run_root"] = json!("/home/ubuntu/.jetstreamer-private/checkpoint-continuation-204-fixture");
    let l = launch();
    let row = capture::observer_registration(&p, &l).unwrap();
    assert_eq!(row["range"], "204-204");
    assert_eq!(row["controller_unit"], p["producer_unit"]);
    assert_eq!(row["producer_unit"], p["producer_unit"]);
    assert_eq!(row["expected_controller_invocation_id"], l["invocation_id"]);
    assert_eq!(row["expected_producer_invocation_id"], l["invocation_id"]);
    assert_eq!(row["worker_executable_basename"], "historical-worker");
    assert_eq!(
        row["scratch_path"],
        "/home/ubuntu/.jetstreamer-private/checkpoint-continuation-204-fixture/scratch"
    );
    let mut foreign = l;
    foreign["invocation_id"] = json!("0".repeat(32));
    assert!(capture::observer_registration(&p, &foreign).is_err());
}

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
        1300
    );
    assert_eq!(
        remaining(&policy(), Stage::NativeRestore, 25).unwrap(),
        1075
    );
    assert_eq!(Stage::NativeRestore.public_phase(), "verification");
    assert_eq!(Stage::SuffixExecution.public_phase(), "replay");
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
    g["processes"]["workers"] = json!([{"vmas":100,"pid":44,"start_time":"50","rss_bytes":1000}]);
    assert!(evidence::guard(&p, &l, &g, &c, 2000).is_err());
    g["phase"]["stage"] = json!("native_restore");
    evidence::guard(&p, &l, &g, &c, 2000).unwrap();
    assert_eq!(stage_from_guard(&g).unwrap(), Stage::SuffixExecution);
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
fn worker_presence_is_required_for_suffix_execution_status() {
    let p = plan();
    let l = launch();
    let mut g = guard(&p, &l);
    g["phase"]["stage"] = json!("native_restore");
    assert_eq!(stage_from_guard(&g).unwrap(), Stage::NativeRestore);
    g["processes"]["workers"] = json!([{"pid":44}]);
    assert_eq!(stage_from_guard(&g).unwrap(), Stage::SuffixExecution);
    g["phase"]["stage"] = json!("unknown_future_stage");
    assert!(stage_from_guard(&g).is_err());
}

#[test]
fn actual_guard_worker_decimal_string_shape_is_accepted_and_noncanonical_forms_are_rejected() {
    let p = plan();
    let l = launch();
    let mut g = guard(&p, &l);
    g["phase"]["stage"] = json!("native_restore");
    g["processes"]["total_process_rss_bytes"] = json!(1_000_000_000u64);
    // Synthetic values in the exact shared guard's field types and copied
    // executable shape. This is not evidence of a real continuation launch.
    g["processes"]["workers"] = json!([{"pid":44,"rss_bytes":500_000_000u64,
        "vmas":1024,"start_time":"67133715","executable_binding_kind":"historical-private-copy",
        "executable_path":"/private/run/scratch/jetstreamer-historical-parent-Ab12cd/bound-worker/historical-worker",
        "executable_owner_uid":1000,"sealed_source":{"path":"/sealed/worker","sha256":WORKER_SHA}}]);
    let census = BTreeMap::from([
        (
            string(&p, "producer_unit").unwrap().into(),
            owner(string(&p, "producer_unit").unwrap(), &"c".repeat(32), 42),
        ),
        (
            string(&p, "guard_unit").unwrap().into(),
            owner(string(&p, "guard_unit").unwrap(), &"d".repeat(32), 43),
        ),
    ]);
    evidence::guard(&p, &l, &g, &census, 2000).unwrap();
    assert_eq!(stage_from_guard(&g).unwrap(), Stage::SuffixExecution);
    for invalid in [
        json!(67133715),
        json!(-1),
        Value::Null,
        json!(""),
        json!("0"),
        json!("-1"),
        json!("+1"),
        json!("01"),
        json!(" 1"),
        json!("1 "),
        json!("1.0"),
        json!("1e3"),
        json!("١"),
        json!("18446744073709551616"),
    ] {
        let mut bad = g.clone();
        bad["processes"]["workers"][0]["start_time"] = invalid.clone();
        assert!(
            evidence::guard(&p, &l, &bad, &census, 2000).is_err(),
            "accepted {invalid}"
        );
    }
    assert!(number(&json!({"bytes":"67133715"}), "bytes").is_err());
}

#[test]
fn unresolved_continuation_prevents_inactive_cleanup_even_with_no_running_pid() {
    for row in [
        json!({"epoch":204,"live":false,"ownership_unresolved":true}),
        json!({"epoch":204,"live":true,"positive_inactivity_confirmed":true}),
        json!({"epoch":204,"live":false,"positive_inactivity_confirmed":false}),
    ] {
        assert!(!cleanup_allowed(&json!({"capped204205_work":[row]}), 204));
    }
    assert!(cleanup_allowed(
        &json!({"capped204205_work":[{"epoch":204,
        "live":false,"positive_inactivity_confirmed":true}]}),
        204
    ));
    assert!(!cleanup_allowed(&json!({"capped204205_work":null}), 204));
    let p = plan();
    let c = BTreeMap::from([(
        string(&p, "producer_unit").unwrap().into(),
        json!({"ActiveState":"activating","MainPID":"0"}),
    )]);
    let row = lifecycle::unresolved(&claim(204), &p, &c, "synthetic changed owner");
    assert_eq!(row["live"], true);
    assert_eq!(row["positive_inactivity_confirmed"], false);
    assert_eq!(row["current_sidecar_eta_valid"], false);
}

#[test]
fn terminal_history_needs_an_actual_terminal_event_after_the_exact_start() {
    let name = "horizon-qualify-204-capped-continuation-fixture.service";
    let iid = "c".repeat(32);
    let start = json!({"_PID":"1","_UID":"0","UNIT":name,"INVOCATION_ID":iid,
        "__REALTIME_TIMESTAMP":"1000000","__CURSOR":"start","MESSAGE":"Started owner",
        "MESSAGE_ID":"39f53479d3a045ac8e11786248231fbf"});
    let mut raw = serde_json::to_vec(&start).unwrap();
    assert!(capture::manager_terminal(&raw, name, &iid).is_err());
    let terminal = json!({"_PID":"1","_UID":"0","UNIT":name,"INVOCATION_ID":iid,
        "__REALTIME_TIMESTAMP":"2000000","__CURSOR":"end",
        "MESSAGE":format!("{name}: Failed with result 'exit-code'."),
        "MESSAGE_ID":"d9b373ed55a64feb8242e02dbe79a49c"});
    raw.push(b'\n');
    raw.extend(serde_json::to_vec(&terminal).unwrap());
    capture::manager_terminal(&raw, name, &iid).unwrap();
    assert!(capture::manager_history(&raw, name, &iid, true).is_err());
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
fn generated_size_uses_only_the_current_final_output_and_zero_before_it_exists() {
    let p = json!({"epoch":204,"run_root":"/private/run","prefix_archive":{"path":"/private/original/prefix.jet"},"prefix_bytes":100});
    let row = |path: &str, n: u64, uid: u64| json!({"path":path,"bytes":n,"uid":uid,"links":1,"inode":42,"archive_body_read":false});
    let mut f = json!({"generated_archives":[row("/private/original/prefix.jet",100,0),
        row("/private/run/output/epoch-204-suffix.jet",20,1000),row("/private/run/output/epoch-204-checkpoint-restart-v4.jet",110,1000)]});
    assert_eq!(evidence::generated_bytes(&p, &f).unwrap(), 110);
    let mut absent = f.clone();
    absent["generated_archives"].as_array_mut().unwrap().pop();
    assert_eq!(evidence::generated_bytes(&p, &absent).unwrap(), 0);
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
        &format!("{unit}: Deactivated successfully."),
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

const COMPAT_JOURNAL: &[u8] =
    include_bytes!("../../../tests/fixtures/capped204-manager/complete-pid1-journal.jsonl");
const COMPAT_UNIT: &str = "horizon-qualify-204-capped-continuation-e506rss-v2.service";
const COMPAT_IID: &str = "55a098e8623b42f6bec931363172402c";
fn compat_rows() -> Vec<Value> {
    std::str::from_utf8(COMPAT_JOURNAL)
        .unwrap()
        .lines()
        .map(|s| serde_json::from_str(s).unwrap())
        .collect()
}
fn compat_encode(rows: &[Value]) -> Vec<u8> {
    rows.iter()
        .map(|v| serde_json::to_string(v).unwrap() + "\n")
        .collect::<String>()
        .into_bytes()
}
#[test]
fn actual_complete_manager_journal_retains_exact_compat_warning_and_original_start() {
    assert_eq!(
        hex_lower(&Sha256::digest(COMPAT_JOURNAL)),
        "1bc8caad92ef2c0e7c4645983577b18b9f949a5ffa8914463073d055b165f352"
    );
    let original = COMPAT_JOURNAL.to_vec();
    assert_eq!(
        capture::manager_history(COMPAT_JOURNAL, COMPAT_UNIT, COMPAT_IID, false).unwrap(),
        1_792_886_526_243
    );
    assert_eq!(original, COMPAT_JOURNAL);
    assert_eq!(compat_rows().len(), 4);
    assert!(capture::manager_history(COMPAT_JOURNAL, COMPAT_UNIT, COMPAT_IID, true).is_err());
    assert!(capture::manager_terminal(COMPAT_JOURNAL, COMPAT_UNIT, COMPAT_IID).is_err());
}
#[test]
fn compat_exception_requires_every_exact_trusted_warning_field_and_absent_iid() {
    for (key, value) in [
        ("_PID", json!("7")),
        ("_UID", json!("1000")),
        ("_COMM", json!("other")),
        ("_EXE", json!("/foreign/systemd")),
        ("_BOOT_ID", json!("f".repeat(32))),
        ("UNIT", json!("foreign.service")),
        ("MESSAGE_ID", json!("different")),
        ("CODE_FUNC", json!("different")),
        ("CODE_FILE", json!("different")),
        ("CODE_LINE", json!("21")),
        ("MESSAGE", json!("arbitrary warning")),
        ("INVOCATION_ID", Value::Null),
        ("INVOCATION_ID", json!("")),
        ("INVOCATION_ID", json!("f".repeat(32))),
        ("__CURSOR", json!("")),
        ("__REALTIME_TIMESTAMP", json!("1")),
    ] {
        let mut rows = compat_rows();
        rows[3][key] = value;
        assert!(
            capture::manager_history(&compat_encode(&rows), COMPAT_UNIT, COMPAT_IID, false)
                .is_err(),
            "{key}"
        );
    }
    let mut rows = compat_rows();
    rows[3]["MESSAGE"] = json!(format!(
        "/etc/systemd/system/{COMPAT_UNIT}:22: Support for option CPUAccounting= has been removed and it is ignored"
    ));
    assert!(
        capture::manager_history(&compat_encode(&rows), COMPAT_UNIT, COMPAT_IID, false).is_err()
    );
}
#[test]
fn compat_warning_does_not_hide_missing_iid_lifecycle_or_foreign_invocations() {
    for (message, id) in [
        ("Starting foreign owner", "7d4958e842da4a758f6c1cdc7b36dcc5"),
        (
            "Stopping original owner",
            "9d1aaa27d60140bd96365438aad20286",
        ),
        (
            "original: Failed with result 'exit-code'.",
            "d9b373ed55a64feb8242e02dbe79a49c",
        ),
    ] {
        for iid in [None, Some("ffffffffffffffffffffffffffffffff")] {
            let mut rows = compat_rows();
            rows[3]["MESSAGE"] = json!(message);
            rows[3]["MESSAGE_ID"] = json!(id);
            if let Some(iid) = iid {
                rows[3]["INVOCATION_ID"] = json!(iid);
            }
            assert!(
                capture::manager_history(&compat_encode(&rows), COMPAT_UNIT, COMPAT_IID, false)
                    .is_err()
            );
        }
    }
    let mut rows = compat_rows();
    rows[3]["__CURSOR"] = rows[2]["__CURSOR"].clone();
    assert!(
        capture::manager_history(&compat_encode(&rows), COMPAT_UNIT, COMPAT_IID, false).is_err()
    );
    let mut rows = compat_rows();
    rows[3]["INVOCATION_ID"] = json!(COMPAT_IID);
    rows[3]["MESSAGE_ID"] = json!("d9b373ed55a64feb8242e02dbe79a49c");
    rows[3]["MESSAGE"] = json!("original: Failed with result 'exit-code'.");
    assert!(
        capture::manager_history(&compat_encode(&rows), COMPAT_UNIT, COMPAT_IID, true).is_err()
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
    let frame = json!({"unit_census_after":{"new.service":{}},"sampled_at_utc":"2026-10-24T13:00:00Z",
        "previous_fleet":{"path":"/fixture/fleet.json","sha256":"a".repeat(64)}});
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

#[test]
fn observer_generation_needs_the_exact_qualified_source_tuple() {
    assert_eq!(
        observer_revision(OBSERVER_SHA),
        Some("3e9326815cf46d03ac9423d5bcf4c637774b7260")
    );
    assert!(
        observer_revision("21bd97c29d9789719ef852428ed52d3e676e5a9ee3e26e855f26966c21e123bf")
            .is_none()
    );
    assert!(observer_revision(&"a".repeat(64)).is_none());
}

#[test]
fn positive_inactivity_does_not_infer_release_from_a_failed_restarted_owner() {
    let p = plan();
    let l = launch();
    let unit = string(&p, "producer_unit").unwrap();
    let old = "horizon-qualify-204-replay.service";
    let c = BTreeMap::from([
        (unit.into(), inactive_owner(unit)),
        (old.into(), json!({"Id":old,"LoadState":"loaded","InvocationID":"2".repeat(32),"MainPID":"0","NRestarts":"2","ActiveState":"failed","SubState":"failed","Result":"exit-code","ExecMainStatus":"1"})),
    ]);
    let f = json!({"sampled_at_utc":"2026-10-24T13:00:00Z","downstream_actors":[]});
    let proof = json!({"schema":"jetstreamer-capped204205-positive-inactivity-v1","epoch":204,
        "producer_invocation_id":l["invocation_id"],"sampled_at_utc":f["sampled_at_utc"],"unit_census":c,
        "process_reference_census":{"references":[]},"pending_job_units":[],"cgroups":{unit:{"state":"absent"},old:{"state":"absent"}},
        "replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false});
    assert!(evidence::inactive_value(&p, &l, &f, &c, &proof).is_err());
    let mut foreign = f;
    foreign["historical_terminal_owners"] = json!({old:{"schema":"jetstreamer-capped204205-historical-terminal-owner-v1","epoch":205}});
    assert!(evidence::inactive_value(&p, &l, &foreign, &c, &proof).is_err());
}
