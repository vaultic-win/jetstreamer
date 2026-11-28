//! Proposed pure interface tests only; Root must compile and run these.
use super::*;
fn binding(tag: &str) -> Value {
    json!({"path":format!("/sealed/{tag}.json"),"sha256":"b".repeat(64)})
}
fn declaration() -> Value {
    json!({"epoch":166,"phase":"bootstrap","unit":"horizon-qualify-166-replacement-v1.service","invocation_id":"a".repeat(32),"main_pid":"123","original_start_unix_seconds":1794332100u64,"original_start_native":"Tue 2026-11-10 17:35:00 UTC","maximum_bootstrap_seconds":3600,"bootstrap_deadline_unix_seconds":1794335700u64,"admission":binding("admission"),"guard_protection":binding("protection"),"launch_proof":binding("launch"),"phase_event":binding("phase"),"first_guard_pid1_timer":binding("first"),"current_guard_pid1_timer":binding("current")})
}
fn fixture() -> [Value; 7] {
    let d = declaration();
    let role = json!({"Id":d["unit"],"InvocationID":d["invocation_id"],"MainPID":"123","ControlPID":"0","NRestarts":"0","ActiveState":"active","SubState":"running"});
    let a = json!({"schema":"horizon-standard-replacement-admission-v1","owner":"/root","primary_thread":"thread","epoch":166,"producer_unit":d["unit"],"producer_invocation_id":d["invocation_id"],"producer_pid":123,"original_stop_event":binding("stops"),"fresh_admission_passed":true,"all_existing_growth_and_floor_protected":true,"all_prior_promises_retained":true,"old_partial_and_inputs_preserved":true,"resource_credit_bytes":0,"memory_or_DATA_promise_ending_bytes":0,"node_sha256":NODE,"worker_sha256":WORKER,"candidate_hard_memory_bytes":73014444032u64,"remote_mutations":false,"r2_mutations":false,"guard_minimum_free_bytes":FLOOR,"recorded_unix_seconds":1794332099u64,"lane_root":"/lane"});
    let p = json!({"schema":"horizon-standard-live-peer-protection-v1","owner":"/root","epoch":166,"producer_unit":d["unit"],"producer_invocation_id":d["invocation_id"],"admission":d["admission"],"guard_unit":"horizon-guard-166-replacement.service","timer_unit":"horizon-guard-166-replacement.timer","timer_invocation_id":"c".repeat(32)});
    let launch = json!({"schema":"horizon-standard-replacement-native-launch-proof-v1","owner":"/root","primary_thread":"thread","admission":d["admission"],"guard_protection":d["guard_protection"],"original_stop_event":binding("stops"),"source_start_unix_seconds":d["original_start_unix_seconds"],"source_start_native":d["original_start_native"],"exact_input_and_capability_gates_passed":true,"fresh_effective_GCS_generation_probes_passed":true,"old_partial_path":"/lane/old/archive.jet","old_scratch_path":"/lane/old/scratch","old_output_rename_performed":false,"node_sha256":NODE,"worker_sha256":WORKER,"recorded_unix_seconds":1794332110u64,"producer_before":role,"producer_after":role,"run_directory":"/lane/new/run","archive_path":"/lane/new/run/archive.jet","scratch_path":"/lane/new/run/scratch","worker_identity":null});
    let ev = json!({"schema":"horizon-standard-replacement-phase-event-v1","owner":"/root","primary_thread":"thread","epoch":166,"phase":"bootstrap","admission":d["admission"],"launch_proof":d["launch_proof"],"guard_protection":d["guard_protection"],"source_start_unix_seconds":d["original_start_unix_seconds"],"source_log":{"stdout_append_binding_verified":true,"producer_invocation_id":d["invocation_id"]},"no_new_resource_sample":true,"replay_launch_authorized":false,"recorded_unix_seconds":1794332120u64,"producer_before":role,"producer_after":role,"transaction_replay_claimed":false,"latest_target_progress":null});
    let old = json!({"unit":"horizon-qualify-166-original.service","original_invocation_id":"d".repeat(32),"original_archive":"/lane/old/archive.jet","scratch":"/lane/old/scratch"});
    let plan = json!({"primary_thread":"thread","terminal_producer_event":binding("stops")});
    [d, a, p, launch, ev, old, plan]
}
fn accepted(v: &[Value; 7], clock: u64) -> R<()> {
    envelope(
        &Envelope {
            d: &v[0],
            a: &v[1],
            p: &v[2],
            launch: &v[3],
            event: &v[4],
            old: &v[5],
            plan: &v[6],
        },
        clock,
    )
}
#[test]
fn utc_uses_actual_clock_without_backdating() {
    assert_eq!(utc("2026-11-10T17:35:00Z").unwrap(), 1794332100);
    assert_eq!(
        utc("2024-02-29T00:00:00Z").unwrap() - utc("2024-02-28T00:00:00Z").unwrap(),
        86400
    );
}
#[test]
fn utc_rejects_invalid_calendar_and_encoding() {
    for v in [
        "2026-02-29T00:00:00Z",
        "2026-11-10T17:60:00Z",
        "2026-11-10T17:00:60Z",
        "2026-11-10 17:00:00Z",
        "2026-11-10T17:00:00+00:00",
        "éééé-éé-ééTéé:éé:ééZ",
    ] {
        assert!(utc(v).is_err(), "{v}");
    }
}
#[test]
fn declaration_requires_real_identity_and_all_bindings() {
    let d = declaration();
    declarations(&json!({"replacement_owners":[d]})).unwrap();
    for field in [
        "admission",
        "guard_protection",
        "launch_proof",
        "phase_event",
        "first_guard_pid1_timer",
        "current_guard_pid1_timer",
    ] {
        let mut d = declaration();
        d.as_object_mut().unwrap().remove(field);
        assert!(declarations(&json!({"replacement_owners":[d]})).is_err());
    }
}
#[test]
fn duplicate_or_unsupported_replacements_fail() {
    let d = declaration();
    assert!(declarations(&json!({"replacement_owners":[d,d]})).is_err());
    let mut d = declaration();
    d["epoch"] = json!(172);
    assert!(declarations(&json!({"replacement_owners":[d]})).is_err());
}
#[test]
fn zero_pid_and_placeholder_invocation_are_rejected() {
    for (k, v) in [
        ("main_pid", json!("0")),
        ("invocation_id", json!("0".repeat(32))),
        ("phase", json!("queued")),
    ] {
        let mut d = declaration();
        d[k] = v;
        assert!(declarations(&json!({"replacement_owners":[d]})).is_err());
    }
}
#[test]
fn bootstrap_envelope_preserves_originals_and_admission() {
    accepted(&fixture(), 1794332130).unwrap();
}
#[test]
fn original_native_identity_cannot_be_reused() {
    for k in ["unit", "invocation_id"] {
        let mut v = fixture();
        v[0][k] = if k == "unit" {
            v[5]["unit"].clone()
        } else {
            v[5]["original_invocation_id"].clone()
        };
        assert!(accepted(&v, 1794332130).is_err());
    }
}
#[test]
fn recovery_cannot_end_resource_promises_or_lower_floor() {
    for (k, x) in [
        ("resource_credit_bytes", json!(1)),
        ("memory_or_DATA_promise_ending_bytes", json!(1)),
        ("all_prior_promises_retained", json!(false)),
        ("guard_minimum_free_bytes", json!(FLOOR - 1)),
    ] {
        let mut v = fixture();
        v[1][k] = x;
        assert!(accepted(&v, 1794332130).is_err());
    }
}
#[test]
fn stale_authentication_or_renamed_output_cannot_pass() {
    for (k, x) in [
        ("fresh_effective_GCS_generation_probes_passed", json!(false)),
        ("old_output_rename_performed", json!(true)),
        ("archive_path", json!("/lane/old/archive.jet")),
        ("scratch_path", json!("/lane/old/scratch")),
    ] {
        let mut v = fixture();
        v[3][k] = x;
        assert!(accepted(&v, 1794332130).is_err());
    }
}
#[test]
fn bootstrap_expiry_is_fixed_to_actual_start() {
    let mut v = fixture();
    v[0]["bootstrap_deadline_unix_seconds"] = json!(1794335701u64);
    assert!(accepted(&v, 1794332130).is_err());
    assert!(accepted(&fixture(), 1794335701).is_err());
}
#[test]
fn bootstrap_never_implies_useful_transactions() {
    let mut v = fixture();
    v[4]["transaction_replay_claimed"] = json!(true);
    assert!(accepted(&v, 1794332130).is_err());
}
#[test]
fn replay_requires_actual_target_markers_and_worker() {
    let mut v = fixture();
    v[0]["phase"] = json!("replay");
    v[4]["phase"] = json!("replay");
    v[4]["transaction_replay_claimed"] = json!(true);
    v[4]["latest_target_progress"] =
        json!({"epoch":166,"transactions":1,"recorded_unix_seconds":1794332119u64});
    assert!(accepted(&v, 1794332130).is_err());
    v[3]["worker_identity"] = json!({"pid":456});
    accepted(&v, 1794332130).unwrap();
    v[4]["latest_target_progress"]["epoch"] = json!(167);
    assert!(accepted(&v, 1794332130).is_err());
}
#[test]
fn guard_command_rejects_decoy_executable_and_extra_argv() {
    let args = vec!["/sealed/guard".into(), "/sealed/plan".into()];
    let exact = "{ path=/sealed/guard ; argv[]=/sealed/guard /sealed/plan ; ignore_errors=no ; start_time= ; stop_time= ; pid=0 ; code=(null) ; status=0 }";
    command_identity(exact, "/sealed/guard", &args).unwrap();
    assert!(
        command_identity(
            &exact.replace("path=/sealed/guard", "path=/bin/echo"),
            "/sealed/guard",
            &args
        )
        .is_err()
    );
    assert!(
        command_identity(
            &exact.replace(
                "argv[]=/sealed/guard /sealed/plan",
                "argv[]=/sealed/guard /sealed/plan --other"
            ),
            "/sealed/guard",
            &args
        )
        .is_err()
    );
}
#[test]
fn failed_current_guard_is_never_covered_by_old_first_sample() {
    let p = json!({"guard_unit":"g.service","timer_unit":"g.timer","timer_invocation_id":"a".repeat(32)});
    let g = json!({"guard_invocation_id":"b".repeat(32)});
    let v = json!({"guard_service":{"Id":"g.service","InvocationID":"b".repeat(32),"LoadState":"loaded","ActiveState":"failed","SubState":"failed","MainPID":"0","ControlPID":"0","NRestarts":"0","Result":"exit-code","ExecMainStatus":"1","Job":""}});
    assert!(proof(&v, &g, &p, &declaration(), true).is_err());
}
#[test]
fn source_handoff_cannot_claim_new_admission_or_future_progress() {
    let mut v = fixture();
    v[4]["replay_launch_authorized"] = json!(true);
    assert!(accepted(&v, 1794332130).is_err());
    let mut v = fixture();
    v[4]["recorded_unix_seconds"] = json!(1794332140u64);
    assert!(accepted(&v, 1794332130).is_err());
}
