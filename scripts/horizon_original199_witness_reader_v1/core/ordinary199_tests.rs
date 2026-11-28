//! Synthetic future owners below exist only in pure tests. The numeric resource
//! fixture is a reduced view of genuine hash-bound historical/current inputs.
use super::*;
fn fixture() -> Value {
    serde_json::from_slice(include_bytes!("ordinary199-fixtures/budget.json")).unwrap()
}
fn dummy(name: &str) -> Bound {
    Bound {
        path: format!("/test-only/{name}.json").into(),
        sha256: "a".repeat(64),
    }
}
fn budget(f: &Value) -> Budget {
    let tuple: Tuple = serde_json::from_value(f["prelaunch"].clone()).unwrap();
    let start = utc(f["observer"]["recorded_at_utc"].as_str().unwrap()).unwrap() + 1;
    Budget {
        schema: "horizon-epoch199-prelaunch-budget-v1".into(),
        prelaunch: tuple,
        raw_admission: Bound {
            path: RAW_PATH.into(),
            sha256: RAW_SHA.into(),
        },
        qualified_eligibility: dummy("eligibility"),
        century_inventory: dummy("floor"),
        controller_argv: dummy("controller-argv"),
        controller_script: dummy("controller-script"),
        candidate_members: vec![],
        recorded_unix_seconds: start,
        launch_expires_unix_seconds: start + 900,
        total_reserved_memory_bytes: 794_519_830_528,
        required_initial_free_bytes: (3577u64 + 337 + 768) << 30,
        protected_data_bytes: (3577u64 + 337) << 30,
        century_floor_bytes: 205_211_459_014,
        inherited_available_memory_floor_bytes: 0,
        preserved_raw_memory_bytes: RAW_MEMORY,
        retired_peer_reduction_bytes: RETIRED_MEMORY,
        positive_uncovered_overhead_bytes: 0,
        external_serial_bytes: 6 << 30,
        parent_memory_bytes: PARENT_MEMORY,
        controller_memory_bytes: AUX_MEMORY,
        guard_memory_bytes: AUX_MEMORY,
        candidate_data_bytes: CANDIDATE_DATA,
        protected_cpu_micros: 39_000_000,
        candidate_credit_bytes: 0,
        physical_credit_bytes: 0,
        publish_through_epoch: 199,
        private_tail_epochs: vec![200],
    }
}
fn check(b: &Budget, f: &Value) -> Result<Value> {
    validate_budget_values(
        b,
        &f["raw"],
        &f["old_observer"],
        &f["observer"],
        &f["fleet"],
        &f["frame"],
        &f["eligibility"],
        &f["floor"],
    )
}
#[test]
fn authentic2058_coexistence_budget_rederives_raw_promises_without_credits_or_double_counting() {
    let f = fixture();
    let b = budget(&f);
    let before = serde_json::to_vec(&f).unwrap();
    let result = check(&b, &f).unwrap();
    assert_eq!(result["raw_memory_bytes"], RAW_MEMORY);
    assert_eq!(result["candidate_parent_bytes"], PARENT_MEMORY);
    assert_eq!(result["candidate_guard_bytes"], AUX_MEMORY);
    assert_eq!(result["candidate_controller_bytes"], AUX_MEMORY);
    assert_eq!(result["candidate_DATA_bytes"], CANDIDATE_DATA);
    assert_eq!(result["candidate_credit_bytes"], 0);
    assert_eq!(serde_json::to_vec(&f).unwrap(), before);
}
#[test]
fn budget_rejects_omitted_or_duplicated_parent_guard_data_cpu_and_retained_promises() {
    let f = fixture();
    for case in 0..17 {
        let mut b = budget(&f);
        match case {
            0 => b.preserved_raw_memory_bytes = 0,
            1 => b.retired_peer_reduction_bytes *= 2,
            2 => b.total_reserved_memory_bytes -= 1,
            3 => b.required_initial_free_bytes -= 1,
            4 => b.protected_data_bytes = 0,
            5 => b.parent_memory_bytes *= 2,
            6 => b.guard_memory_bytes = 0,
            7 => b.controller_memory_bytes = 0,
            8 => b.candidate_data_bytes = 0,
            9 => b.external_serial_bytes = 0,
            10 => b.protected_cpu_micros = 0,
            11 => b.candidate_credit_bytes = 1,
            12 => b.physical_credit_bytes = 1,
            13 => b.publish_through_epoch = 200,
            14 => b.private_tail_epochs.clear(),
            15 => b.inherited_available_memory_floor_bytes = 480 << 30,
            _ => b.launch_expires_unix_seconds += 1,
        }
        assert!(check(&b, &f).is_err(), "case {case}");
    }
}
#[test]
fn budget_rejects_crossed_tuple_retirement_floor_raw_history_or_same_end_rss() {
    for case in 0..10 {
        let mut f = fixture();
        let b = budget(&f);
        match case {
            0 => {
                f["raw"]["resource_accounting"]["active_peer_allocations"][17]["memory_max_bytes"] =
                    json!(0)
            }
            1 => f["raw"]["cpu_quota_micros"] = json!(0),
            2 => f["frame"]["bindings"]["fleet"]["sha256"] = json!("f".repeat(64)),
            3 => f["eligibility"]["current"]["observer"]["sha256"] = json!("f".repeat(64)),
            4 => {
                let x = f["eligibility"]["applied"][0].clone();
                f["eligibility"]["applied"].as_array_mut().unwrap().push(x);
            }
            5 => f["eligibility"]["DATA_credit_bytes"] = json!(1),
            6 => f["floor"]["entries"][0]["archive_length"] = json!(1),
            7 => {
                f["observer"]["host_resident_memory"]["after"]["rss"]["aggregate_rss_bytes"] =
                    json!(1)
            }
            8 => f["observer"]["diagnostic_replays"]
                .as_array_mut()
                .unwrap()
                .clear(),
            _ => f["fleet"]["inventory"]["anomalies"] = json!(1),
        }
        assert!(check(&b, &f).is_err(), "case {case}");
    }
}
fn synthetic_enrollment(b: &Budget) -> Enrollment {
    let owner = |unit: &str, ch: char| Owner {
        unit: unit.into(),
        invocation_id: ch.to_string().repeat(32),
    };
    Enrollment {
        schema: "horizon-epoch199-additive-owner-enrollment-v1".into(),
        budget: dummy("budget"),
        controller: owner(CONTROLLER, 'a'),
        producer: owner(PRODUCER, 'b'),
        guard_first_owner: owner(GUARD, 'c'),
        timer_owner: owner(TIMER, 'd'),
        guard_program: dummy("guard-program"),
        guard_argv: dummy("guard-argv"),
        first_guard_proof: dummy("first-guard"),
        producer_argv: dummy("producer-argv"),
        scratch_path: "/test-only/scratch".into(),
        worker_executable_basename: "historical-worker".into(),
        recorded_unix_seconds: b.recorded_unix_seconds + 10,
        producer_memory_bytes: PARENT_MEMORY,
        controller_memory_bytes: AUX_MEMORY,
        guard_memory_bytes: AUX_MEMORY,
        candidate_data_bytes: CANDIDATE_DATA,
        cpu_quota_micros: 8_000_000,
        candidate_credit_bytes: 0,
    }
}
fn first(e: &Enrollment, b: &Budget, a: &[String]) -> Value {
    let command = format!(
        "{} ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=exited ; status=0/0 }}",
        expected_command(a).unwrap()
    );
    let point = |o: &Owner| json!({"unit":o.unit,"invocation_id":o.invocation_id,"restarts":0,"active_state":"active","sub_state":"running"});
    json!({"schema":"horizon-epoch199-adaptive-first-sandboxed-guard-v1","recorded_unix_seconds":b.recorded_unix_seconds+5,
        "sandboxed":true,"capability_only":false,"guard_program":e.guard_program,"guard_argv":e.guard_argv,
        "service":{"Id":GUARD,"InvocationID":e.guard_first_owner.invocation_id,"Result":"success","ExecMainStatus":"0","ExecMainCode":"1","Type":"oneshot","Restart":"no","RemainAfterExit":"no","ActiveState":"inactive","SubState":"dead",
            "MainPID":"0","ControlPID":"0","NRestarts":"0","User":"root","ProtectSystem":"strict","ProtectHome":"read-only",
            "PrivateNetwork":"yes","NoNewPrivileges":"yes","MemoryMax":AUX_MEMORY.to_string(),"MemorySwapMax":"0","CPUQuotaPerSecUSec":"1s","ExecStart":command,"ExecMainStartTimestamp":"Mon 2026-11-02 20:58:12 UTC"},
        "output":{"armed":true,"trip":false,"minimum_free_bytes":RAW_DATA,"maximum_worker_vmas":3_000_000,"available_bytes":RAW_DATA+1,
            "controller":point(&e.controller),"producer":point(&e.producer)}})
}
#[test]
fn actual_first_fire_requires_exact_guard_sandbox_owner_floor_and_no_trip() {
    let f = fixture();
    let b = budget(&f);
    let e = synthetic_enrollment(&b);
    let a = vec!["/usr/bin/python3".into(), "/test-only/guard.py".into()];
    let good = first(&e, &b, &a);
    validate_first_guard(&e, &b, &a, &good).unwrap();
    for (pointer, value) in [
        ("/capability_only", json!(true)),
        ("/sandboxed", json!(false)),
        ("/service/InvocationID", json!("f".repeat(32))),
        ("/service/ExecMainStatus", json!("1")),
        ("/service/ProtectHome", json!("yes")),
        ("/service/MemoryMax", json!("1")),
        ("/service/ExecStart", json!("changed")),
        ("/guard_program/sha256", json!("f".repeat(64))),
        ("/guard_argv/sha256", json!("f".repeat(64))),
        ("/output/trip", json!(true)),
        ("/output/armed", json!(false)),
        ("/output/minimum_free_bytes", json!(1)),
        ("/output/maximum_worker_vmas", json!(0)),
        ("/output/producer/invocation_id", json!("f".repeat(32))),
        ("/output/controller/restarts", json!(1)),
    ] {
        let mut bad = good.clone();
        *bad.pointer_mut(pointer).unwrap() = value;
        assert!(validate_first_guard(&e, &b, &a, &bad).is_err(), "{pointer}");
    }
}
#[test]
fn exact_live_native_owner_rejects_restart_alias_queue_changed_limits_or_sandbox() {
    let owner = Owner {
        unit: PRODUCER.into(),
        invocation_id: "b".repeat(32),
    };
    let good = json!({"Id":PRODUCER,"InvocationID":owner.invocation_id,"LoadState":"loaded","NRestarts":"0","Restart":"no","ControlPID":"0","Job":"",
        "ActiveState":"active","SubState":"running","MainPID":"123","MemoryAccounting":"yes","MemoryMax":PARENT_MEMORY.to_string(),
        "MemorySwapMax":"0","CPUQuotaPerSecUSec":"8s","KillMode":"control-group","NoNewPrivileges":"yes","ProtectSystem":"strict","ProtectHome":"read-only","ControlGroup":format!("/system.slice/{PRODUCER}")});
    running(&good, &owner, PARENT_MEMORY, "8s").unwrap();
    for (key, value) in [
        ("Id", "foreign.service"),
        ("InvocationID", "ffffffffffffffffffffffffffffffff"),
        ("NRestarts", "1"),
        ("Restart", "on-failure"),
        ("ControlPID", "1"),
        ("Job", "42"),
        ("MemoryMax", "1"),
        ("MemorySwapMax", "infinity"),
        ("CPUQuotaPerSecUSec", "16s"),
        ("ProtectSystem", "no"),
        ("ProtectHome", "yes"),
        ("MainPID", "0"),
    ] {
        let mut bad = good.clone();
        bad[key] = json!(value);
        assert!(running(&bad, &owner, PARENT_MEMORY, "8s").is_err(), "{key}");
    }
}
