use super::*;
fn fixture() -> (Selector, model::Plan, model::Admission, Value, Value) {
    let p: model::Plan = serde_json::from_str(include_str!("fixtures/plan.json")).unwrap();
    let ready: Value = serde_json::from_str(include_str!("fixtures/ready.json")).unwrap();
    let before: Value = serde_json::from_str(include_str!("fixtures/before.json")).unwrap();
    let b = |path: &str, sha: &str| BoundFile {
        path: path.into(),
        sha256: sha.into(),
    };
    let s = Selector {
        plan: b(PLAN, PLAN_SHA),
        ready: b(
            &format!("{STATE}/ready.json"),
            "d8cd0712b4ee180fa10d3d977b6981a40846d7cd5f78698fd4a0bf9ad938457b",
        ),
        admission: b(
            &format!("{STATE}/admission.json"),
            "eecfdac8d2b968979c3bf541d75b5362d6b223b8d58da17600b7c4af25664c02",
        ),
        guard_before_source: b(
            &format!("{STATE}/guard-before-source-read.json"),
            "3410e0ea3c4fbbfe911185e893f9c79eb246a6cf419ecea7f567ac03ae79c53d",
        ),
    };
    let a:model::Admission=serde_json::from_value(json!({"schema":"horizon-epoch145-private-extraction-typed-admission-v1",
        "plan":old(&s.plan),"actor_unit":ACTOR,"actor_iid":IID,"actor_pid":2463122,"actor_start_ticks":238412403u64,
        "accepted_at":1794037470u64,"accepted_boottime_millis":2384124000u64,"memory_evidence":null,"data_evidence":null,
        "existing_memory_bytes":1,"protected_existing_data_bytes":1,"required_initial_memory_bytes":MEMORY_FLOOR,
        "required_initial_data_bytes":DATA_FLOOR,"original_native":null})).unwrap();
    (s, p, a, ready, before)
}
fn running_actor() -> Value {
    json!({"Id":ACTOR,"InvocationID":IID,"LoadState":"loaded","ActiveState":"active","SubState":"running",
        "MainPID":"2463122","NRestarts":"0","Restart":"no","Type":"exec","MemoryMax":(80u64<<30).to_string(),
        "MemorySwapMax":"0","TasksMax":"512","CPUQuotaPerSecUSec":"8s","ExecStart":format!("{} ignore_errors=no ; }}",command("extract"))})
}
fn completed_guard() -> Value {
    json!({"Id":GUARD,"InvocationID":"d".repeat(32),"LoadState":"loaded","ActiveState":"inactive","SubState":"dead",
        "MainPID":"0","NRestarts":"0","Restart":"no","Type":"exec","User":"root","MemoryMax":(256u64<<20).to_string(),
        "MemorySwapMax":"0","TasksMax":"512","CPUQuotaPerSecUSec":"1s","ExecStart":format!("{} ignore_errors=no ; code=exited ; status=0/0 }}",command("guard")),
        "ControlGroup":"","Result":"success","ExecMainCode":"1","ExecMainStatus":"0"})
}
fn capture() -> Value {
    let (s, p, _, _, before) = fixture();
    json!({"peer":peer(&s,&p,&running_actor()),"plan":binding(&s.plan),"actor_native":running_actor(),
        "captured_at":1794037500u64,"token":before["token"]})
}
#[test]
fn exact_original_selector_and_first_guard_bind_without_runtime_reads() {
    let (s, p, a, r, b) = fixture();
    exact(&s).unwrap();
    let ab: model::Bound = serde_json::from_value(r["admission"].clone()).unwrap();
    plan_shape(&p, &a, &r, &b, &old(&s.plan), &ab, 1794037500).unwrap();
}
#[test]
fn crossed_original_selector_or_mutated_program_and_deadline_fail() {
    let (mut s, p, a, r, b) = fixture();
    s.plan.sha256 = "a".repeat(64);
    assert!(exact(&s).is_err());
    let (s, _, _, _, _) = fixture();
    let ab = serde_json::from_value(r["admission"].clone()).unwrap();
    for (field, value) in [
        ("minimum_free_bytes", json!(DATA_FLOOR - 1)),
        ("minimum_available_memory_bytes", json!(0)),
        ("execution_deadline", json!(1794296896u64)),
        ("actor_memory_bytes", json!(1)),
    ] {
        let mut bad = serde_json::to_value(&p).unwrap();
        bad[field] = value;
        let bad = serde_json::from_value(bad).unwrap();
        assert!(plan_shape(&bad, &a, &r, &b, &old(&s.plan), &ab, 1794037500).is_err());
    }
    assert!(plan_shape(&p, &a, &r, &b, &old(&s.plan), &ab, p.execution_deadline + 1).is_err());
}
#[test]
fn token_monotonic_age_actor_plan_and_both_floors_fail_closed() {
    let (s, p, a, r, b) = fixture();
    let ab = serde_json::from_value(r["admission"].clone()).unwrap();
    let t: model::Token = serde_json::from_value(b["token"].clone()).unwrap();
    token(
        &t,
        &p,
        &a,
        &old(&s.plan),
        &ab,
        t.at_unix_seconds + 90,
        t.at_boottime_millis + 90000,
    )
    .unwrap();
    assert!(
        token(
            &t,
            &p,
            &a,
            &old(&s.plan),
            &ab,
            t.at_unix_seconds + 91,
            t.at_boottime_millis + 90001
        )
        .is_err()
    );
    for (k, v) in [
        ("actor_iid", json!("f".repeat(32))),
        ("protected_free_bytes", json!(DATA_FLOOR - 1)),
        ("protected_available_memory_bytes", json!(0)),
        ("actual_free_bytes", json!(0)),
        ("actor_start_ticks", json!(1)),
    ] {
        let mut bad = serde_json::to_value(&t).unwrap();
        bad[k] = v;
        let bad = serde_json::from_value(bad).unwrap();
        assert!(
            token(
                &bad,
                &p,
                &a,
                &old(&s.plan),
                &ab,
                t.at_unix_seconds,
                t.at_boottime_millis
            )
            .is_err()
        );
    }
    assert!(
        token(
            &t,
            &p,
            &a,
            &old(&s.plan),
            &ab,
            t.at_unix_seconds - 1,
            t.at_boottime_millis
        )
        .is_err()
    );
}
#[test]
fn periodic_guard_success_or_exact_running_fire_only() {
    let done = completed_guard();
    guard_native(&done).unwrap();
    let mut running = done.clone();
    running["InvocationID"] = json!("e".repeat(32));
    running["MainPID"] = json!("2464000");
    running["ActiveState"] = json!("active");
    running["SubState"] = json!("running");
    running["ControlGroup"] = json!(format!("/system.slice/{GUARD}"));
    guard_native(&running).unwrap();
    for (k, v) in [
        ("Result", json!("exit-code")),
        ("ExecMainStatus", json!("1")),
        ("NRestarts", json!("1")),
        ("MemoryMax", json!("1")),
        ("ExecStart", json!("foreign command")),
    ] {
        let mut bad = done.clone();
        bad[k] = v;
        assert!(guard_native(&bad).is_err());
    }
}
#[test]
fn timer_iid_unarmed_and_actor_restart_or_command_injection_reject() {
    let (_, _, a, _, _) = fixture();
    actor_native(&running_actor(), &a).unwrap();
    let mut bad = running_actor();
    bad["NRestarts"] = json!("1");
    assert!(actor_native(&bad, &a).is_err());
    bad = running_actor();
    bad["ExecStart"] = json!(command("extract").replace(" ;", " injected ;"));
    assert!(actor_native(&bad, &a).is_err());
    let t = json!({"Id":TIMER,"LoadState":"loaded","InvocationID":TIMER_IID,"ActiveState":"active","SubState":"running","Triggers":GUARD});
    timer_native(&t).unwrap();
    for (k, v) in [
        ("InvocationID", json!("b".repeat(32))),
        ("ActiveState", json!("inactive")),
        ("Triggers", json!("foreign.service")),
    ] {
        let mut bad = t.clone();
        bad[k] = v;
        assert!(timer_native(&bad).is_err());
    }
}
#[test]
fn independent_actor_guard_and_source_data_reach_actual_growth_and_memory_sums_once() {
    let c = capture();
    let p = c["peer"].clone();
    peer_shape(&p).unwrap();
    assert_eq!(p["memory_max_bytes"], MEMORY);
    assert_eq!(p["external_pool_charged_by_this_peer_bytes"], 0);
    assert_eq!(p["retained185_source_DATA_bytes"], 4u64 << 30);
    let old = core::Obligation {
        claim_key: "retained-other".into(),
        epoch: 199,
        producer_invocation_id: "a".repeat(32),
        outstanding_bytes: 7,
    };
    let (rows, floor) =
        super::super::protect(std::slice::from_ref(&old), 0, 0, std::slice::from_ref(&p)).unwrap();
    assert_eq!(rows[0].claim_key, old.claim_key);
    assert_eq!(rows[0].outstanding_bytes, 7);
    assert_eq!(rows[1].outstanding_bytes, DATA);
    assert!(rows[1].claim_key.starts_with("live145-prefix-export/"));
    assert!(floor >= super::super::DATA_FLOOR + DATA);
    assert_eq!(
        super::super::active_trial_memory_promises(&[Some(&p)]).unwrap(),
        MEMORY
    );
    assert!(super::super::protect(&rows, 0, 0, std::slice::from_ref(&p)).is_err());
    assert!(super::super::active_trial_memory_promises(&[Some(&p), Some(&p)]).is_err());
}
#[test]
fn zero_credit_and_independent_pool_cannot_be_relabelled() {
    let p = capture()["peer"].clone();
    for (k, v) in [
        ("credit_bytes", json!(1)),
        ("resource_release_qualified", json!(true)),
        ("native_pool_suballocation", json!(true)),
        ("memory_max_bytes", json!(80u64 << 30)),
        ("data_reservation_bytes", json!(160u64 << 30)),
        ("reserved_guard_memory_bytes", json!(0)),
    ] {
        let mut bad = p.clone();
        bad[k] = v;
        assert!(peer_shape(&bad).is_err());
    }
}
#[test]
fn rollover_comparison_preserves_raw_records_and_all_foreign_rows() {
    let c = capture();
    let mut other = c.clone();
    other["captured_at"] = json!(1794037501u64);
    other["token"]["at_boottime_millis"] =
        json!(number(&c, "/token/at_boottime_millis").unwrap() + 1);
    stable(Some(&c), Some(&other)).unwrap();
    let mut left = json!({"foreign.service":{"InvocationID":"keep raw"}});
    left[ACTOR] = running_actor();
    left[GUARD] = completed_guard();
    let mut right = left.clone();
    right[GUARD]["InvocationID"] = json!("e".repeat(32));
    let raw = (left.clone(), right.clone());
    assert_eq!(
        comparison(&left, Some(&c)).unwrap(),
        comparison(&right, Some(&other)).unwrap()
    );
    assert_eq!(raw, (left.clone(), right.clone()));
    let mut foreign = right.clone();
    foreign["foreign.service"]["InvocationID"] = json!("changed");
    assert_ne!(
        comparison(&left, Some(&c)).unwrap(),
        comparison(&foreign, Some(&other)).unwrap()
    );
    assert!(stable(Some(&c), None).is_err());
    assert!(stable(None, Some(&c)).is_err());
}
#[test]
fn positive185_enforces_live_memory_runway_and_full_new_data_floor() {
    let c = capture();
    let memory = (8u64 << 30) + (256u64 << 20);
    let candidate =
        json!({"peers":[{"memory_max_bytes":memory}],"guard_floor_bytes":DATA_FLOOR+(4u64<<30)});
    let required = MEMORY_FLOOR + MEMORY + memory + (6u64 << 30);
    // Round up to the observer's real KiB unit; one fewer KiB cannot fit.
    let kib = required.div_ceil(1024);
    let o = json!({"host_memory":{"conservative_available_kib":kib}});
    candidate_fit(Some(&candidate), Some(&c), &o).unwrap();
    let mut bad = o.clone();
    bad["host_memory"]["conservative_available_kib"] = json!(kib - 1);
    assert!(candidate_fit(Some(&candidate), Some(&c), &bad).is_err());
    let mut bad = candidate.clone();
    bad["guard_floor_bytes"] = json!(DATA_FLOOR - 1);
    assert!(candidate_fit(Some(&bad), Some(&c), &o).is_err());
    let mut bad = candidate;
    bad["peers"][0]["memory_max_bytes"] = json!(u64::MAX);
    assert!(candidate_fit(Some(&bad), Some(&c), &o).is_err());
}
#[test]
fn optional_absence_never_creates_a_peer_credit_or_current_guard() {
    assert!(peers(None).is_empty());
    assert_eq!(cpu(None), 0);
    assert_eq!(guard_floor(None), 0);
    assert_eq!(retained_data_floor(99, None).unwrap(), 99);
    required_selector(false, false).unwrap();
    required_selector(true, true).unwrap();
    assert!(required_selector(false, true).is_err());
    assert!(!guard_discovered(GUARD, &completed_guard(), None).unwrap());
}
#[test]
fn retained_data_floor_keeps_new_source_four_gib_and_never_reduces_a_larger_floor() {
    let c = capture();
    assert_eq!(
        retained_data_floor(0, Some(&c)).unwrap(),
        DATA_FLOOR + (4u64 << 30)
    );
    assert_eq!(retained_data_floor(u64::MAX, Some(&c)).unwrap(), u64::MAX);
}

#[test]
#[ignore = "requires the actual unchanged v8g1 exporter and genuine periodic guard"]
fn actual_live_v8g1_capture_and_natural_guard_rollover_preserve_all_debt() -> Result<()> {
    ensure!(unsafe { libc::geteuid() } == 0, "Root read-only native qualification required");
    let (selector, _, _, _, _) = fixture();
    let before = actual(Some(&selector), custody::now()?)?
        .context("actual live145 first native accounting capture")?;
    peer_shape(&before["peer"])?;
    ensure!(before["actor_native"]["InvocationID"] == IID
        && before["peer"]["memory_max_bytes"] == MEMORY
        && before["peer"]["data_reservation_bytes"] == DATA
        && before["archive_body_reads"] == false
        && before["memory_or_DATA_credit_bytes"] == 0,
        "first actual live145 capture changed owner, debt or authority");
    let raw_before = json!({ACTOR:before["actor_native"], GUARD:before["guard_native"]});
    // Wait for the already armed periodic guard; no service/timer operation,
    // host-resource read, publication, receipt mutation or producer action.
    std::thread::sleep(std::time::Duration::from_secs(45));
    let after = actual(Some(&selector), custody::now()?)?
        .context("actual live145 second native accounting capture")?;
    stable(Some(&before), Some(&after))?;
    ensure!(before["token"]["guard_iid"] != after["token"]["guard_iid"]
        && number(&after, "/token/at_boottime_millis")?
            > number(&before, "/token/at_boottime_millis")?,
        "qualification did not observe a genuine new guard token");
    let raw_after = json!({ACTOR:after["actor_native"], GUARD:after["guard_native"]});
    ensure!(comparison(&raw_before, Some(&before))?
        == comparison(&raw_after, Some(&after))?,
        "actual periodic guard rollover changed protected owner/debt comparison");
    println!("{}", json!({"schema":"live145-actual-readonly-native-rollover-test-v1",
        "before":before,"after":after,"original_actor_unchanged":true,
        "genuine_periodic_guard_rollover_observed":true,
        "archive_body_reads":false,"resource_credit_bytes":0,
        "service_or_timer_mutations":false,"replay_launch_authorized":false}));
    Ok(())
}

#[test]
fn historical_guard_comparison_preserves_legacy_scope_and_rejects_dropped_live_debt() {
    let current = capture();
    assert!(!comparison_scope(false, None, None).unwrap());
    assert!(comparison_scope(true, Some(&current), Some(&current)).unwrap());
    for (declared, a, b) in [
        (false, Some(&current), None), (false, None, Some(&current)),
        (false, Some(&current), Some(&current)), (true, None, None),
        (true, Some(&current), None), (true, None, Some(&current)),
    ] {
        assert!(comparison_scope(declared, a, b).is_err());
    }
    // Actual current construction has the independent deployment-presence gate.
    assert!(required_selector(false, true).is_err());
}
