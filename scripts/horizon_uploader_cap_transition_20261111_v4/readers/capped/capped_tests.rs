use super::*;
fn legacy() -> LegacyPlan {
    serde_json::from_str(include_str!("test-plan.json")).unwrap()
}
fn bound(path: &str) -> Bound {
    Bound {
        path: path.into(),
        sha256: "a".repeat(64),
    }
}
fn plan() -> Plan {
    Plan {
        schema: "horizon-uploader-capped-census-plan-v1".into(),
        original_frozen_plan: bound("/old/frozen-plan.json"),
        original_frozen_proof: bound("/old/frozen-proof.json"),
        capped_frozen_proof: None,
        phase: Phase::CappedFrozen,
        memory_max_bytes: 1 << 30,
        minimum_unused_bytes: 64 << 20,
        runtime_cap_dropins: ["50-MemoryMax.conf", "50-MemorySwapMax.conf"]
            .map(|n| {
                bound(&format!(
                    "/run/systemd/system.control/{}.d/{n}",
                    census::UNIT
                ))
            })
            .into(),
        output: Path::new(OUTPUT).join("capped.json"),
    }
}
fn original_native(l: &LegacyPlan) -> Value {
    let mut v = json!({});
    for (key, value) in [
        ("Id", l.unit.clone()),
        ("LoadState", "loaded".into()),
        ("ActiveState", "active".into()),
        ("SubState", "running".into()),
        ("MainPID", l.main_pid.to_string()),
        ("ControlPID", "0".into()),
        ("InvocationID", l.invocation_id.clone()),
        ("NRestarts", "0".into()),
        ("ExecStart", l.expected_exec_start.clone()),
        ("ControlGroup", l.expected_control_group.clone()),
        ("Restart", "on-failure".into()),
        ("FreezerState", "frozen".into()),
        ("Triggers", "".into()),
        ("TriggeredBy", "".into()),
        ("Job", "".into()),
        ("Delegate", "no".into()),
        ("MemoryMax", "infinity".into()),
        ("KillMode", "control-group".into()),
        ("KillSignal", "15".into()),
        ("FinalKillSignal", "9".into()),
        ("SendSIGKILL", "yes".into()),
        ("RestartUSec", "30s".into()),
        ("FragmentPath", census::ORIGINAL.into()),
        ("StandardInput", "null".into()),
        ("StandardOutput", "journal".into()),
        ("StandardError", "inherit".into()),
        (
            "DropInPaths",
            l.source_files
                .iter()
                .skip(1)
                .map(|b| b.path.display().to_string())
                .collect::<Vec<_>>()
                .join(" "),
        ),
    ] {
        v[key] = json!(value);
    }
    v
}
fn capped_native(p: &Plan, l: &LegacyPlan) -> Value {
    let mut v = original_native(l);
    v["MemoryMax"] = json!(p.memory_max_bytes.to_string());
    v["DropInPaths"] = json!(
        l.source_files
            .iter()
            .skip(1)
            .chain(p.runtime_cap_dropins.iter())
            .map(|b| b.path.display().to_string())
            .collect::<Vec<_>>()
            .join(" ")
    );
    for (key, value) in [
        ("MemorySwapMax", "0"),
        ("TasksMax", "256"),
        ("MemoryAccounting", "yes"),
        ("NoNewPrivileges", "yes"),
        ("ProtectControlGroups", "yes"),
        ("User", "sol"),
        ("Group", "horizon"),
        ("OOMPolicy", "stop"),
    ] {
        v[key] = json!(value);
    }
    v
}
#[test]
fn exact_finite_profile_has_an_accepted_native_delta() {
    let p = plan();
    let l = legacy();
    shape(&p).unwrap();
    native_delta(&capped_native(&p, &l), &original_native(&l), &p, &l).unwrap();
}
#[test]
fn a_thawed_profile_must_name_the_thawed_phase() {
    let mut p = plan();
    let l = legacy();
    let old = original_native(&l);
    let mut v = capped_native(&p, &l);
    v["FreezerState"] = json!("running");
    assert!(native_delta(&v, &old, &p, &l).is_err());
    p.phase = Phase::CappedIdle;
    p.capped_frozen_proof = Some(bound("/prior/capped-frozen.json"));
    shape(&p).unwrap();
    native_delta(&v, &old, &p, &l).unwrap();
}
#[test]
fn wider_limit_swap_or_task_profile_cannot_borrow_a_cap() {
    let p = plan();
    let l = legacy();
    let old = original_native(&l);
    for (key, value) in [
        ("MemoryMax", "infinity"),
        ("MemoryMax", "2147483648"),
        ("MemorySwapMax", "1"),
        ("TasksMax", "512"),
        ("MemoryAccounting", "no"),
    ] {
        let mut v = capped_native(&p, &l);
        v[key] = json!(value);
        assert!(native_delta(&v, &old, &p, &l).is_err(), "{key}={value}");
    }
}
#[test]
fn child_job_restart_birth_or_executable_change_rejects() {
    let p = plan();
    let l = legacy();
    let old = original_native(&l);
    for (key, value) in [
        ("MainPID", "777"),
        ("InvocationID", "b"),
        ("ControlPID", "6"),
        ("Job", "55"),
        ("NRestarts", "1"),
        ("ExecStart", "other"),
        ("ControlGroup", "/other"),
        ("Delegate", "yes"),
    ] {
        let mut v = capped_native(&p, &l);
        v[key] = json!(value);
        assert!(native_delta(&v, &old, &p, &l).is_err(), "{key}");
    }
}
#[test]
fn missing_or_unknown_native_field_is_not_normalized_away() {
    let p = plan();
    let l = legacy();
    let old = original_native(&l);
    let mut v = capped_native(&p, &l);
    v.as_object_mut().unwrap().remove("NoNewPrivileges");
    assert!(native_delta(&v, &old, &p, &l).is_err());
    let mut v = capped_native(&p, &l);
    v["UnclassifiedProperty"] = json!("yes");
    assert!(native_delta(&v, &old, &p, &l).is_err());
}
#[test]
fn hardening_or_service_identity_change_rejects() {
    let p = plan();
    let l = legacy();
    let old = original_native(&l);
    for (key, value) in [
        ("NoNewPrivileges", "no"),
        ("ProtectControlGroups", "no"),
        ("User", "root"),
        ("Group", "root"),
        ("OOMPolicy", "continue"),
    ] {
        let mut v = capped_native(&p, &l);
        v[key] = json!(value);
        assert!(native_delta(&v, &old, &p, &l).is_err());
    }
}
#[test]
fn source_cover_is_exact_and_duplicate_paths_reject() {
    let p = plan();
    let l = legacy();
    let old = original_native(&l);
    for path in [
        "/other.conf",
        p.runtime_cap_dropins[0].path.to_str().unwrap(),
    ] {
        let mut v = capped_native(&p, &l);
        let text = v["DropInPaths"].as_str().unwrap();
        v["DropInPaths"] = json!(format!("{text} {path}"));
        assert!(native_delta(&v, &old, &p, &l).is_err());
    }
    let mut v = capped_native(&p, &l);
    v["DropInPaths"] = old["DropInPaths"].clone();
    assert!(native_delta(&v, &old, &p, &l).is_err());
}
#[test]
fn runtime_sources_cannot_change_non_cap_properties() {
    cap_source(
        b"# generated\n[Service]\nMemoryMax=1073741824\n",
        "MemoryMax",
        1 << 30,
    )
    .unwrap();
    for raw in [
        b"[Service]\nMemoryMax=1073741824\nExecStart=other\n".as_slice(),
        b"[Service]\nMemoryMax=infinity\n",
        b"[Service]\nMemoryMax=1073741824\nMemoryMax=1073741824\n",
        b"[Service]\nMemoryMax=1073741825\n",
        b"[Unit]\nMemoryMax=1073741824\n",
    ] {
        assert!(cap_source(raw, "MemoryMax", 1 << 30).is_err());
    }
}
#[test]
fn phase_scope_keeps_original_birth_and_source_bindings() {
    let mut p = plan();
    let initial = scope(&p).unwrap();
    p.phase = Phase::CappedIdle;
    p.capped_frozen_proof = Some(bound("/old/capped.json"));
    p.output = Path::new(OUTPUT).join("idle.json");
    assert_eq!(scope(&p).unwrap(), initial);
    p.memory_max_bytes += 1;
    assert_ne!(scope(&p).unwrap(), initial);
    p.memory_max_bytes -= 1;
    p.original_frozen_proof.sha256 = "b".repeat(64);
    assert_ne!(scope(&p).unwrap(), initial);
}
#[test]
fn cap_source_paths_are_not_arbitrary_handoff_authority() {
    let mut p = plan();
    p.runtime_cap_dropins[0].path = "/etc/systemd/system/other.service".into();
    assert!(shape(&p).is_err());
    let mut p = plan();
    p.runtime_cap_dropins.swap(0, 1);
    assert!(shape(&p).is_err());
    let mut p = plan();
    p.runtime_cap_dropins.push(p.runtime_cap_dropins[0].clone());
    assert!(shape(&p).is_err());
}
#[test]
fn future_or_stale_proof_cannot_authorize_handoff() {
    fresh(100, 160).unwrap();
    assert!(fresh(100, 161).is_err());
    assert!(fresh(101, 100).is_err());
}
#[test]
fn cap_phase_cannot_skip_frozen_predecessor() {
    let mut p = plan();
    p.phase = Phase::CappedIdle;
    assert!(shape(&p).is_err());
    let mut p = plan();
    p.capped_frozen_proof = Some(bound("/old/other.json"));
    assert!(shape(&p).is_err());
}
#[test]
fn the_cap_cannot_use_the_entire_baseline_or_exceed_shared_pool() {
    let mut p = plan();
    p.minimum_unused_bytes = p.memory_max_bytes;
    assert!(shape(&p).is_err());
    let mut p = plan();
    p.memory_max_bytes = (64 << 30) + 1;
    assert!(shape(&p).is_err());
}
const STATUS: &str = "CapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapAmb:\t0000000000000000\nNoNewPrivs:\t1\n";
const MOUNT: &str =
    "80 70 0:28 / /sys/fs/cgroup ro,nosuid,nodev,noexec,relatime - cgroup2 cgroup rw\n";
#[test]
fn read_only_cgroup_mount_and_no_privilege_gain_are_required() {
    validate_privileges(STATUS, MOUNT).unwrap();
    assert!(validate_privileges(STATUS, &MOUNT.replace("ro,nosuid", "rw,nosuid")).is_err());
    assert!(
        validate_privileges(&STATUS.replace("NoNewPrivs:\t1", "NoNewPrivs:\t0"), MOUNT).is_err()
    );
}
#[test]
fn process_capabilities_or_duplicate_mount_evidence_rejects() {
    for key in ["CapInh:", "CapPrm:", "CapEff:", "CapAmb:"] {
        assert!(
            validate_privileges(
                &STATUS.replace(
                    &format!("{key}\t0000000000000000"),
                    &format!("{key}\t0000000000000001")
                ),
                MOUNT
            )
            .is_err()
        );
    }
    assert!(validate_privileges(STATUS, &format!("{MOUNT}{MOUNT}")).is_err());
    assert!(validate_privileges(&format!("{STATUS}NoNewPrivs:\t1\n"), MOUNT).is_err());
}
#[test]
fn original_frozen_scope_cannot_be_relabelled() {
    let p = plan();
    let mut l = legacy();
    l.frozen = true;
    let v = json!({"recorded_unix_seconds":100,"schema":"horizon-uploader-freeze-census-proof-v1","self_sha256":PRE_CAP_IMAGE_SHA,"plan":p.original_frozen_plan,"scope_sha256":census::scope_hash(&l).unwrap(),"frozen":true,"idle_census_proven":true,"unit":original_native(&l),"snapshot":{"actual_memory_max":"max","cgroup_frozen":true,"no_work_descriptors_or_mappings":true}});
    original_proof(&v, &p, &l, 100).unwrap();
    for (key, value) in [
        ("self_sha256", json!("b".repeat(64))),
        ("frozen", json!(false)),
        ("scope_sha256", json!("c".repeat(64))),
    ] {
        let mut bad = v.clone();
        bad[key] = value;
        assert!(original_proof(&bad, &p, &l, 100).is_err());
    }
    let mut reused = l.clone();
    reused.start_ticks += 1;
    assert!(original_proof(&v, &p, &reused, 100).is_err());
    assert!(original_proof(&v, &p, &l, 161).is_err());
}
