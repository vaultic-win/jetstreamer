use super::*;

fn b(path: PathBuf) -> Bound {
    Bound {
        path,
        sha256: "b".repeat(64),
    }
}
fn plan() -> Plan {
    Plan {
        schema: "horizon-epoch136-actual-plan-v1".into(),
        node: b(Path::new(TOOLS).join("jetstreamer-node")),
        helper: b(Path::new(TOOLS).join("epoch136-actual-payload")),
        worker: fixed(WORKER_PATH, WORKER_SHA),
        tools_seal: b(Path::new(TOOLS).join("deployment-seal-receipt.json")),
        qualification: fixed(&format!("{TOOLS}/qualification.json"), QUALIFICATION_SHA),
        source_proof: b(Path::new(TOOLS).join("artifact-proof.json")),
        source_commit: "a".repeat(40),
        history: fixed(
            &format!("{TOOLS}/historical-accounting-review.json"),
            "dccb6e51d0b7522d8a7fedcbbbb8bb3fe194967b9452c7e97a9865f08493ed4c",
        ),
        controller: b(Path::new(BASE).join("controller/admit136")),
        barrier_version: BARRIER_VERSION.into(),
    }
}
fn admission(p: &Plan) -> Admission {
    Admission {
        schema: "horizon-epoch136-actual-admission-v1".into(),
        plan: b(Path::new(BASE).join("plan.json")),
        helper: p.helper.clone(),
        node: p.node.clone(),
        worker: p.worker.clone(),
        tools_seal: p.tools_seal.clone(),
        writer: p.controller.clone(),
        writer_invocation_id: "a".repeat(32),
        recorded_unix_seconds: 1000,
        launch_expires_unix_seconds: 1800,
        protected_existing_free_bytes: 1_000_000_000_000,
        required_initial_free_bytes: 1_000_000_000_000 + DATA,
        data_reservation_bytes: DATA,
        memory_max_bytes: MEMORY,
        cpu_quota_micros: CPU_MICROS,
        resource_accounting: b(Path::new(BASE).join("capacity.json")),
        bounded_reproduction_authorized: true,
        publication_authorized: false,
        remote_mutations: false,
        r2_mutations: false,
        full_epoch_span_proven: false,
    }
}
#[test]
fn old_worker_and_old_attempt_namespaces_cannot_be_selected() {
    let p = plan();
    contract::plan_shape(&p).unwrap();
    let mut wrong = p.clone();
    wrong.worker.sha256 = "de9998ce84d1ddc39bad58fde97614b2058d8771253105a631b71dcec658a2d3".into();
    assert!(contract::plan_shape(&wrong).is_err());
    wrong = p;
    wrong.node.path="/usr/local/lib/jetstreamer/horizon-epoch136-hourly-charge-trace-retry-0005-tools-20261102-v1/jetstreamer-node".into();
    assert!(contract::plan_shape(&wrong).is_err());
}
#[test]
fn exact_cleared_node_command_pins_inputs_worker_and_private_parent() {
    let p = plan();
    let c = configured_node_command(&p, Path::new(ROOT));
    let args = c
        .get_args()
        .map(|s| s.to_str().unwrap().to_string())
        .collect::<Vec<_>>();
    assert_eq!(
        args,
        vec![
            "136".to_string(),
            format!("{ROOT}/ledger"),
            "--verify".into(),
            format!("--qualification-end-slot={END}"),
            format!("--snapshot-archive={ROOT}/inputs/{SNAPSHOT_NAME}"),
            format!("--epoch-hashes={ROOT}/inputs/{CHECKPOINT_FILE}"),
            format!("--horizon-output={ROOT}/output/{OUTPUT}"),
            format!("--replay-scratch={ROOT}/scratch")
        ]
    );
    let vars = c
        .get_envs()
        .map(|(k, v)| (k.to_str().unwrap(), v.map(|v| v.to_str().unwrap())))
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(
        vars["JETSTREAMER_HISTORICAL_WORKER_V1_4_25"],
        Some(WORKER_PATH)
    );
    assert_eq!(
        vars[SOCKET_ENV],
        Some(format!("{ROOT}/entry.sock").as_str())
    );
    assert_eq!(
        vars["JETSTREAMER_PRIVATE_RUN_ROOT"],
        Some(format!("{ROOT}/scratch/private-run").as_str())
    );
    assert!(!vars.contains_key("HOME"));
    assert!(!vars.contains_key("JETSTREAMER_EPOCH136_CHARGE_RETRY0005_GATE"));
}
#[test]
fn new_admission_cannot_be_expired_crossed_or_claim_publication() {
    let p = plan();
    let a = admission(&p);
    contract::admission_shape(&p, &a.plan, &a, 1000).unwrap();
    assert!(contract::admission_shape(&p, &a.plan, &a, 1800).is_err());
    let mut bad = a.clone();
    bad.writer.sha256 = "c".repeat(64);
    assert!(contract::admission_shape(&p, &a.plan, &bad, 1000).is_err());
    let mut bad = a.clone();
    bad.publication_authorized = true;
    assert!(contract::admission_shape(&p, &a.plan, &bad, 1000).is_err());
}
#[test]
fn first_real_guard_requires_the_actual_worker_and_fresh_invocation() {
    let id = "a".repeat(32);
    let sha = "b".repeat(64);
    let floor = 1000;
    let v = json!({"schema":"jetstreamer-horizon-standalone-guard-sample-v1","producer_invocation_id":id,
        "producer":{"invocation_id":id,"pid":20,"restarts":0,"active":"active","sub":"running","cgroup":format!("/system.slice/{UNIT}")},
        "guard_sha256":GUARD_SHA,"plan_sha256":sha,"producer_stop_enabled":true,"minimum_free_bytes":floor,
        "maximum_root_physical_bytes":ROOT_STOP,"maximum_worker_vmas":VMA,"trip_reason":null,
        "worker_observation_error":null,"root_physical_observation_error":null,
        "root_physical_observation":{"exceeds_budget":false,"conservative_physical_bytes":42},
        "available_bytes":2000,"recorded_unix_seconds":1000,"bounded_measurement":false,"bounded_canary":null,"native_main":null,
        "workers":[[21,100]]});
    guard_fire_shape(&v, &id, &sha, 20, Some(21), floor, (999, 1000)).unwrap();
    assert!(guard_fire_shape(&v, &id, &sha, 20, Some(22), floor, (999, 1000)).is_err());
    assert!(guard_fire_shape(&v, &id, &sha, 20, Some(21), floor, (1001, 1001)).is_err());
    let mut wrong = v.clone();
    wrong["workers"] = json!([]);
    assert!(guard_fire_shape(&wrong, &id, &sha, 20, Some(21), floor, (999, 1000)).is_err());
    let mut wrong = v;
    wrong["producer_stop_enabled"] = json!(false);
    assert!(guard_fire_shape(&wrong, &id, &sha, 20, Some(21), floor, (999, 1000)).is_err());
}
#[test]
fn checkpoint_text_and_target_remain_the_exact_original_suffix() {
    let text = format!("{SNAPSHOT_NAME}\n{ROOT_NAME}\n");
    assert_eq!(hex(&Sha256::digest(text.as_bytes())), CHECKPOINT_SHA);
    assert_eq!(END - FIRST + 1, 7396);
    assert_eq!(FAILURE_SLOT - FIRST + 1, 6549);
    assert_eq!(59_183_999 - END, 55);
}
#[test]
fn published_production_qualification_does_not_qualify_an_unbuilt_node() {
    let p = plan();
    let worker = json!({"schema":"horizon-epoch136-new-charge-trace-qualification-v1",
        "verified_remote_commit":QUALIFIED_WORKER_COMMIT,"production":{"optin":{"worker":{"sha256":WORKER_SHA}}},
        "actual_epoch_replay_admitted":false,"archive_verified":false});
    let source = json!({"schema":"horizon-epoch136-actual-artifact-proof-v1","source_commit":p.source_commit,
        "source_contained_in_origin_account_updates":true,"qualified_worker_commit":QUALIFIED_WORKER_COMMIT,
        "worker":p.worker,"node":p.node,"payload":p.helper,"exact_node_cli_and_snapshot_route_qualified":true,
        "actual_worker_pre_initialize_gate_qualified":true,"tests_passed":1,"tests_failed":0,"publication_authorized":false});
    contract::qualification(&p, &worker, &source).unwrap();
    let mut wrong = source;
    wrong["actual_worker_pre_initialize_gate_qualified"] = json!(false);
    assert!(contract::qualification(&p, &worker, &wrong).is_err());
}
#[test]
fn fixed_request_never_accepts_prior_barriers_or_another_node() {
    assert_eq!(
        request(format!("{BARRIER_VERSION} 42 43\n").as_bytes(), 42).unwrap(),
        43
    );
    assert!(request(format!("{BARRIER_VERSION} 42 43\n").as_bytes(), 44).is_err());
    assert!(
        request(
            b"epoch136-hourly-charge-trace-retry-0005-before-initialize-v1 42 43\n",
            42
        )
        .is_err()
    );
}

#[test]
fn current_capacity_accepts_fresh_post_prefire_evidence_and_rejects_reused_credit() {
    let a = admission(&plan());
    let existing = 700_000_000_000u64;
    let v = json!({"schema":"horizon-epoch136-exclusive-capacity-v1","writer":a.writer,
        "writer_invocation_id":a.writer_invocation_id,"candidate_unit":UNIT,"candidate_run_root":ROOT,
        "candidate_memory_max_bytes":MEMORY,"candidate_data_bytes":DATA,"candidate_cpu_quota_micros":CPU_MICROS,
        "complete_host_ledger_checked":true,"current_native_ownership_checked":true,
        "no_overlapping_epoch136_controller":true,"guard_512MiB_hard_limit_charged_in_complete_ledger":true,
        "os_and_peer_floors_preserved":true,"all_historical_attempts_and_retained_data_preserved":true,
        "old_failed4_memory_retirement_reused_as_new_credit":false,"old_failed4_new_memory_credit_bytes":0,
        "exclusive_handoff_accepted":true,"exclusive_handoff_memory_bytes":MEMORY,
        "handoff_source_no_longer_launchable":true,"handoff_source_physically_drained":true,
        "existing_memory_promises_after_exclusive_handoff_bytes":existing,
        "total_memory_promises_including_floor_and_candidate_bytes":existing+MEMORY,
        "host_memory_bytes":810_902_843_392u64,"protected_existing_home_free_bytes":a.protected_existing_free_bytes,
        "available_home_bytes":a.required_initial_free_bytes,"actual_home_backing_device_verified":true,
        "candidate_reserved_once":true,"recorded_unix_seconds":1020});
    contract::capacity_shape(&a, &v, 1021).unwrap();
    assert!(contract::capacity_shape(&a, &v, 1141).is_err());
    for (key, value) in [
        (
            "old_failed4_memory_retirement_reused_as_new_credit",
            json!(true),
        ),
        ("old_failed4_new_memory_credit_bytes", json!(MEMORY)),
        ("handoff_source_no_longer_launchable", json!(false)),
        ("handoff_source_physically_drained", json!(false)),
        ("host_memory_bytes", json!(existing + MEMORY - 1)),
        (
            "available_home_bytes",
            json!(a.required_initial_free_bytes - 1),
        ),
    ] {
        let mut wrong = v.clone();
        wrong[key] = value;
        assert!(contract::capacity_shape(&a, &wrong, 1021).is_err(), "{key}");
    }
}

#[test]
fn unrecognized_tools_directory_cannot_supply_a_seal() {
    assert!(tools_destination(&json!(TOOLS)).is_ok());
    assert!(tools_destination(&json!("/home/sol/unrelated/tools")).is_err());
    assert!(tools_destination(&Value::Null).is_err());
}
