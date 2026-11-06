use super::*;
use serde_json::json;
pub fn fixture() -> Plan {
    let bound = |p: &str| json!({"path":p,"sha256":"a".repeat(64)});
    let id = json!({"device":1,"inode":2,"bytes":3,"mtime_ns":4,"ctime_ns":5,"mode":33024,"uid":0,"gid":0});
    serde_json::from_value(json!({
        "schema":"horizon-epoch145-private-verification-plan-v1","generation":"test-v1","stage":"full",
        "program":bound("/usr/local/lib/jetstreamer/horizon-epoch145-private-verify-tools-test/epoch145-private-verify"),
        "program_seal":bound("/usr/local/lib/jetstreamer/horizon-epoch145-private-verify-tools-test/deployment-seal-receipt.json"),
        "admission_bridge":bound("/sealed/bridge"),"admission_bridge_seal":bound("/sealed/bridge-seal"),
        "terminal":{"path":WITNESS,"sha256":WITNESS_SHA},"source":bound(SOURCE),"source_identity":id,
        "manifest":bound("/sealed/export-completion"),"manifest_identity":id,
        "export_plan":{"path":"/usr/local/lib/jetstreamer/horizon-epoch145-prefix-extractor-plan-real1328-20261106-v1/plan.json","sha256":EXPORT_PLAN_SHA},
        "export_admission":bound("/sealed/export-admission"),"export_first_guard":bound("/sealed/export-first-guard"),
        "export_original_completion":bound("/sealed/original-export-completion"),
        "incoming":{"path":INCOMING,"sha256":INCOMING_SHA},"terminal_boundary":{"path":TERMINAL,"sha256":TERMINAL_SHA},
        "verifier":{"path":"/usr/local/lib/jetstreamer/qualified/verify_archive","sha256":FULL_SHA},
        "verifier_seal":bound("/usr/local/lib/jetstreamer/qualified/deployment-seal-receipt.json"),
        "memory_request":bound("/sealed/request"),"data_policy":bound("/sealed/policy"),"data_policy_seal":bound("/sealed/policy-seal"),
        "actor_unit":"horizon-verify145-full-test-v1.service","guard_unit":"horizon-guard145-verify-full-test-v1.service",
        "timer_unit":"horizon-guard145-verify-full-test-v1.timer","output_root":Path::new(SOURCE).parent().unwrap(),
        "output_directory_identity":{"device":1,"inode":2},"state_root":"/var/lib/jetstreamer/horizon-epoch145-private-verify-full-test-v1",
        "state_directory_identity":{"device":1,"inode":3},"actor_memory_bytes":64*GIB,"guard_memory_bytes":256u64<<20,
        "external_pool_bytes":6*GIB,"actor_cpu_quota_micros":8000000,"guard_cpu_quota_micros":1000000,"tasks_max":512,
        "minimum_available_memory_bytes":700*GIB,"minimum_free_bytes":MIN_DATA_FLOOR,
        "issued_at":100,"entry_deadline":340,"execution_deadline":86740
    })).unwrap()
}
fn evidence(p: &Plan) -> [Value; 5] {
    let ep = json!({"schema":"horizon-epoch145-private-prefix-extractor-plan-v1","program":{"sha256":EXPORT_PROGRAM_SHA},
        "actor_unit":EXPORT_UNIT,"source":{"path":ORIGINAL_SOURCE,"sha256":SOURCE_SHA},"manifest":{"sha256":MANIFEST_SHA}});
    let plan = json!({"path":p.export_plan.path,"sha256":EXPORT_PLAN_SHA});
    let ea = json!({"schema":"horizon-epoch145-private-extraction-typed-admission-v1","plan":plan,
        "actor_iid":EXPORT_IID,"actor_pid":123,"actor_start_ticks":45});
    let first = json!({"schema":"horizon-epoch145-actual-pre-read-guard-v1","plan":plan,"admission":p.export_admission,
        "token":{"plan":plan,"admission":p.export_admission,"actor_iid":EXPORT_IID,"actor_pid":123,"actor_start_ticks":45}});
    let c = json!({"schema":"horizon-epoch145-guarded-private-prefix-completion-v1","plan":plan,"actor_iid":EXPORT_IID,
        "actor_pid":123,"actor_start_ticks":45,"admission":p.export_admission,"authority":admission::false_authority(),
        "extraction":{"schema":"jetstreamer-private-epoch145-canonical-prefix-extraction-v1","epoch":145,
            "source_archive":ORIGINAL_SOURCE,"source_archive_sha256":SOURCE_SHA,"source_manifest_sha256":MANIFEST_SHA,
            "source_canonical_checkpoint_slot":63072070u64,"source_canonical_accounts_hash":"DsoBNgzFVZ7j5bF2CpKnt7HAC7fRrMMwdWW9FUafRe1p",
            "worker_sha256":"2cca500106d274ebfbbc8c5bfa0e6e8343cd5e41003f9e82c93282800732d8c8",
            "archive":SOURCE,"archive_sha256":p.source.sha256,"archive_bytes":p.source_identity.bytes,
            "output_slot_start":62640000u64,"output_slot_count":432000,"retained_verification_tail_slots":71,
            "source_must_be_retained":true,"independent_output_reread_passed":true,
            "expected_output_provenance_sha256":"b".repeat(64),"output_semantic_sha256":"c".repeat(64),
            "current_plugin_verification_passed":false,"canonical_sidecar_authorized":false,
            "publication_authorized":false,"retirement_authorized":false,"r2_mutations":false}});
    let closed = json!({"schema":"horizon-epoch145-production-export-original-completion-v1","completion":p.manifest,
        "admission":p.export_admission,"unit":EXPORT_UNIT,"invocation_id":EXPORT_IID,"result":"success","exec_main_status":0,
        "original_outer_reaped":true,"original_cgroup_empty":true,"original_descriptors_drained":true,"original_export_guard_and_timer_drained":true,
        "PID1":[{"_PID":"1","_UID":"0","UNIT":EXPORT_UNIT,"INVOCATION_ID":EXPORT_IID,"MESSAGE_ID":"7ad2d189f7e94e70a38c781354912448"}]});
    [c, ep, ea, first, closed]
}
fn accepts(p: &Plan, v: &[Value; 5]) -> bool {
    admission::export_values(
        &v[0],
        &v[1],
        &v[2],
        &v[3],
        &v[4],
        &p.source,
        &p.source_identity,
        &p.manifest,
        &p.export_admission,
    )
    .is_ok()
}
#[test]
fn exact_full_and_plugin_profiles_and_commands() {
    let mut p = fixture();
    admission::plan_shape(&p, 100).unwrap();
    let e = evidence(&p);
    let args = commands(&p, &e[0]);
    assert_eq!(args.len(), 12);
    assert_eq!(args[0], SOURCE);
    assert_eq!(args[1], "--full");
    assert_eq!(args[3], "62639999");
    assert_eq!(args[6], "63071999");
    assert_eq!(args[11], "b".repeat(64));
    assert!(
        !args
            .iter()
            .any(|a| a == "--internal-full" || a == "--bench")
    );
    p.stage = Stage::Plugin;
    p.verifier.path.set_file_name("horizon_pipeline");
    p.verifier.sha256 = PLUGIN_SHA.into();
    p.actor_unit = p.actor_unit.replace("-full-", "-plugin-");
    p.guard_unit = p.guard_unit.replace("-full-", "-plugin-");
    p.timer_unit = p.timer_unit.replace("-full-", "-plugin-");
    p.state_root = p
        .state_root
        .to_string_lossy()
        .replace("-full-", "-plugin-")
        .into();
    admission::plan_shape(&p, 100).unwrap();
    assert_eq!(
        commands(&p, &e[0]),
        vec![
            "145:145",
            p.output_root.to_str().unwrap(),
            "--threads",
            "8",
            "--verify-only"
        ]
    );
}
#[test]
fn original_completed_canonical_export_is_required() {
    let p = fixture();
    assert!(accepts(&p, &evidence(&p)));
}
#[test]
fn complete_focused_container_or_wrong_canonical_range_rejected() {
    let p = fixture();
    for (ptr, value) in [
        ("/extraction/output_slot_count", json!(432071)),
        ("/extraction/output_slot_start", json!(62639491)),
        ("/extraction/retained_verification_tail_slots", json!(0)),
        (
            "/extraction/source_canonical_checkpoint_slot",
            json!(63071999),
        ),
    ] {
        let mut v = evidence(&p);
        *v[0].pointer_mut(ptr).unwrap() = value;
        assert!(!accepts(&p, &v), "{ptr}");
    }
}
#[test]
fn forged_digest_provenance_worker_or_terminal_rejected() {
    let p = fixture();
    for ptr in [
        "/extraction/archive_sha256",
        "/extraction/source_archive_sha256",
        "/extraction/source_manifest_sha256",
        "/extraction/worker_sha256",
        "/extraction/source_canonical_accounts_hash",
        "/extraction/expected_output_provenance_sha256",
        "/extraction/output_semantic_sha256",
    ] {
        let mut v = evidence(&p);
        *v[0].pointer_mut(ptr).unwrap() = json!("bad");
        assert!(!accepts(&p, &v), "{ptr}");
    }
}
#[test]
fn crossed_actor_plan_admission_guard_or_original_completion_rejected() {
    let p = fixture();
    for (index, ptr, value) in [
        (0, "/actor_iid", json!("0".repeat(32))),
        (0, "/plan/sha256", json!("b".repeat(64))),
        (0, "/admission/sha256", json!("b".repeat(64))),
        (1, "/program/sha256", json!("b".repeat(64))),
        (2, "/actor_pid", json!(999)),
        (3, "/token/actor_start_ticks", json!(999)),
        (4, "/original_descriptors_drained", json!(false)),
        (4, "/PID1/0/_PID", json!("2")),
        (4, "/PID1/0/INVOCATION_ID", json!("0".repeat(32))),
    ] {
        let mut v = evidence(&p);
        *v[index].pointer_mut(ptr).unwrap() = value;
        assert!(!accepts(&p, &v), "{index}{ptr}");
    }
}
#[test]
fn extraction_cannot_promote_itself_to_plugin_publication_or_retirement() {
    let p = fixture();
    for k in [
        "current_plugin_verification_passed",
        "canonical_sidecar_authorized",
        "publication_authorized",
        "retirement_authorized",
        "r2_mutations",
    ] {
        let mut v = evidence(&p);
        v[0]["extraction"][k] = json!(true);
        assert!(!accepts(&p, &v), "{k}");
    }
}
#[test]
fn clocks_namespace_resource_and_tool_substitutions_rejected() {
    let p = fixture();
    let v = serde_json::to_value(p).unwrap();
    for (k, x) in [
        ("entry_deadline", json!(341)),
        ("issued_at", json!(101)),
        ("execution_deadline", json!(86741)),
        ("actor_memory_bytes", json!(63 * GIB)),
        ("minimum_free_bytes", json!(MIN_DATA_FLOOR - 1)),
        ("actor_unit", json!(EXPORT_UNIT)),
        (
            "source",
            json!({"path":ORIGINAL_SOURCE,"sha256":SOURCE_SHA}),
        ),
        (
            "terminal_boundary",
            json!({"path":TERMINAL,"sha256":"a".repeat(64)}),
        ),
    ] {
        let mut bad = v.clone();
        bad[k] = x;
        let p: Plan = serde_json::from_value(bad).unwrap();
        assert!(admission::plan_shape(&p, 100).is_err(), "{k}");
    }
    let p: Plan = serde_json::from_value(v).unwrap();
    assert!(admission::plan_shape(&p, 99).is_err());
    assert!(admission::plan_shape(&p, 341).is_err());
}
#[test]
fn caller_supplied_approval_fields_are_not_a_plan() {
    let mut v = serde_json::to_value(fixture()).unwrap();
    v["approved"] = json!(true);
    assert!(serde_json::from_value::<Plan>(v).is_err());
}
#[test]
fn token_must_bind_exact_actor_admission_and_original_age() {
    let p = fixture();
    let pb = Bound {
        path: "/sealed/plan".into(),
        sha256: "d".repeat(64),
    };
    let ab = Bound {
        path: "/private/admission".into(),
        sha256: "e".repeat(64),
    };
    let a = Admission {
        schema: "test".into(),
        plan: pb.clone(),
        actor_unit: p.actor_unit.clone(),
        actor_iid: "a".repeat(32),
        actor_pid: 12,
        actor_start_ticks: 13,
        accepted_at: 100,
        accepted_boottime_millis: 1000,
        memory_evidence: json!({}),
        data_evidence: json!({}),
        existing_memory_bytes: 0,
        protected_existing_data_bytes: 0,
        required_initial_memory_bytes: 1,
        required_initial_data_bytes: 1,
        original_native: json!({}),
    };
    let token = Token {
        schema: "horizon-epoch145-private-verifier-native-guard-token-v1".into(),
        plan: pb.clone(),
        admission: ab.clone(),
        actor_iid: a.actor_iid.clone(),
        actor_pid: 12,
        actor_start_ticks: 13,
        guard_iid: "b".repeat(32),
        guard_pid: 14,
        guard_start_ticks: 15,
        at_unix_seconds: 100,
        at_boottime_millis: 1000,
        protected_free_bytes: p.minimum_free_bytes,
        protected_available_memory_bytes: p.minimum_available_memory_bytes,
        actual_free_bytes: p.minimum_free_bytes,
        actual_available_memory_bytes: p.minimum_available_memory_bytes,
    };
    token_valid(&token, &p, &pb, &ab, &a, 100, 91000).unwrap();
    assert!(token_valid(&token, &p, &pb, &ab, &a, 100, 91001).is_err());
    for (k, v) in [
        ("actor_iid", json!("c".repeat(32))),
        ("actor_pid", json!(99)),
        ("actor_start_ticks", json!(99)),
        ("actual_free_bytes", json!(p.minimum_free_bytes - 1)),
        ("at_unix_seconds", json!(101)),
    ] {
        let mut bad = serde_json::to_value(&token).unwrap();
        bad[k] = v;
        let bad: Token = serde_json::from_value(bad).unwrap();
        assert!(
            token_valid(&bad, &p, &pb, &ab, &a, 100, 1000).is_err(),
            "{k}"
        );
    }
}
