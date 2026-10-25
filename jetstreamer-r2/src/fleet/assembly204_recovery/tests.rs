//! Metadata fixtures never attest to an actual epoch-204 terminal or archive.
use super::*;
fn suffix() -> Value {
    serde_json::from_str(include_str!("fixtures/suffix.json")).unwrap()
}
fn prefix() -> lineage::Manifest {
    serde_json::from_str(include_str!("fixtures/prefix_manifest.json")).unwrap()
}
#[test]
fn independent_lineage_preserves_real_native_proof_and_separate_raw_namespaces() {
    let proof = suffix();
    assert_eq!(
        hex_lower(&Sha256::digest(include_bytes!("fixtures/suffix.json"))),
        SUFFIX_PROOF
    );
    let tail: lineage::Manifest = serde_json::from_value(proof["suffix_manifest"].clone()).unwrap();
    let expected = lineage::derive(&prefix(), &tail, &proof).unwrap();
    assert_eq!(expected.provenance.base.runtime_segments.len(), 2);
    assert_eq!(expected.provenance.base.requested_slot_count, 432000);
    assert_ne!(
        expected.provenance.base.handoffs[0]
            .predecessor
            .next_write_version,
        expected.provenance.base.handoffs[0]
            .successor
            .next_write_version
    );
    assert_eq!(
        expected.provenance.base.handoffs[0]
            .successor
            .next_write_version,
        84_252_990_240
    );
    assert_eq!(
        expected.provenance.base.runtime_segments[1]
            .write_versions
            .archive_start,
        prefix().emitted_raw_write_versions.end - prefix().emitted_raw_write_versions.start
    );
    assert_eq!(expected.document["assembly_profile"], GENERATION);
}
#[test]
fn independent_lineage_rejects_changed_native_source_authority_and_partition() {
    for (pointer, value) in [
        ("/actual_suffix_native_barrier_passed", json!(false)),
        ("/producer_invocation_id", json!("a".repeat(32))),
        (
            "/native_checkpoint/initialized_next_write_version",
            json!(1),
        ),
        (
            "/native_checkpoint/accounts_hash_kind",
            json!("accounts_lt_hash"),
        ),
        ("/native_checkpoint/bootstrap_write_count", json!(1)),
        ("/native_checkpoint/initialized_ticks_per_slot", json!(63)),
        ("/suffix_manifest/archive_sha256", json!(PREFIX_SHA)),
        ("/suffix_manifest/output_slot_count", json!(637)),
        ("/suffix_manifest/bootstrap/next_write_version", json!(1)),
        ("/authority/publication_authorized", json!(true)),
    ] {
        let mut proof = suffix();
        *proof.pointer_mut(pointer).unwrap() = value;
        let tail: lineage::Manifest =
            serde_json::from_value(proof["suffix_manifest"].clone()).unwrap();
        assert!(
            lineage::derive(&prefix(), &tail, &proof).is_err(),
            "accepted {pointer}"
        );
    }
}
fn terminal_rows(unit: &str, iid: &str, id: &str, message: &str) -> Vec<Value> {
    vec![
        json!({"_PID":"1","_UID":"0","UNIT":unit,"INVOCATION_ID":iid,"__REALTIME_TIMESTAMP":"1000000","MESSAGE_ID":"39f53479d3a045ac8e11786248231fbf","MESSAGE":"Started fixture."}),
        json!({"_PID":"1","_UID":"0","UNIT":unit,"INVOCATION_ID":iid,"__REALTIME_TIMESTAMP":"2000000","MESSAGE_ID":id,"MESSAGE":message}),
    ]
}
fn raw(rows: &[Value]) -> Vec<u8> {
    rows.iter()
        .map(Value::to_string)
        .collect::<Vec<_>>()
        .join("\n")
        .into_bytes()
}
fn old_current() -> Value {
    json!({"Id":OLD_UNIT,"MainPID":"0","NRestarts":"0","ActiveState":"failed","SubState":"failed","InvocationID":OLD_IID})
}
#[test]
fn original_failure_and_new_recovery_success_are_distinct_terminal_facts() {
    let rows = terminal_rows(
        OLD_UNIT,
        OLD_IID,
        "d9b373ed55a64feb8242e02dbe79a49c",
        &format!("{OLD_UNIT}: Failed with result 'timeout'."),
    );
    assert_eq!(
        custody::terminal_shape(&old_current(), &raw(&rows)).unwrap(),
        2000
    );
    let mut live = old_current();
    live["MainPID"] = json!("42");
    live["ActiveState"] = json!("active");
    assert!(custody::terminal_shape(&live, &raw(&rows)).is_err());
    let success = terminal_rows(
        OLD_UNIT,
        OLD_IID,
        "7ad2d189f7e94e70a38c781354912448",
        &format!("{OLD_UNIT}: Deactivated successfully."),
    );
    assert!(custody::terminal_shape(&old_current(), &raw(&success)).is_err());
    assert!(ownership::manager_shape(&raw(&rows), OLD_UNIT, OLD_IID, true).is_err());
    let iid = "a".repeat(32);
    let recovered = terminal_rows(
        UNIT,
        &iid,
        "7ad2d189f7e94e70a38c781354912448",
        &format!("{UNIT}: Deactivated successfully."),
    );
    assert!(ownership::manager_shape(&raw(&recovered), UNIT, &iid, true).is_ok());
    assert!(ownership::manager_shape(&raw(&success), UNIT, &iid, true).is_err());
    for (field, value) in [
        ("_PID", json!("2")),
        ("_UID", json!("1000")),
        ("UNIT", json!("foreign.service")),
        ("INVOCATION_ID", json!("b".repeat(32))),
        ("MESSAGE_ID", Value::Null),
        (
            "MESSAGE",
            json!(format!("{OLD_UNIT}: Failed with result 'success'.")),
        ),
    ] {
        let mut changed = rows.clone();
        changed[1][field] = value;
        assert!(
            custody::terminal_shape(&old_current(), &raw(&changed)).is_err(),
            "accepted {field}"
        );
    }
    let mut reverse = rows;
    reverse.reverse();
    assert!(custody::terminal_shape(&old_current(), &raw(&reverse)).is_err());
}
fn capacity_fixture() -> Value {
    let memory = MEMORY + GUARD_MEMORY;
    let total = 2u64 << 40;
    let growth = 123;
    let required = total.div_ceil(10) + growth + memory;
    let native = json!({"schema":"jetstreamer-capped204-v4-terminal-native223-memory-v1","host_baseline_bytes":total.div_ceil(10),
        "effective_available_memory_floor_bytes":total.div_ceil(10),"candidate_stage_hard_memory_bytes":MEMORY,"candidate_guard_hard_memory_bytes":0,
        "protected_existing_hard_memory_growth_bytes":growth,"required_available_memory_bytes":required-GUARD_MEMORY,"floor_counted_once":true,
        "positive_terminal":maintenance_capacity::assembly204_native_terminal_fixture()});
    let m = json!({"host_total_memory_bytes":total,"protected_existing_memory_growth_bytes":growth,
        "protected_memory_evidence":[{"unit":"protected.service","remaining_hard_memory_growth_bytes":growth}],
        "candidate_memory_max_bytes":memory,"minimum_available_memory_bytes":required,"sampled_available_memory_bytes":required,
        "actual_available_memory_bytes":required,"assembly204_recovery_memory_policy":{
        "schema":"jetstreamer-epoch204-assembly-recovery-hard-memory-policy-v1","protected_existing_hard_memory_growth_bytes":growth,
        "candidate_hard_memory_bytes":memory,"candidate_producer_hard_memory_bytes":MEMORY,"candidate_guard_hard_memory_bytes":GUARD_MEMORY,
        "host_available_floor_bytes":total.div_ceil(10),"native223_available_floor_policy":native,"required_available_memory_bytes":required}});
    json!({"schema":"jetstreamer-horizon-maintenance-capacity-v1","first_epoch":201,"last_epoch":300,
        "additional_bytes":OUTPUT_MAX+(128u64<<20),"unit_census_before":{},"unit_census_after":{},"unit_census_after_memory_and_guard_checks":{},
        "all_live_growth_and_century_floor_protected":true,"capped_peer_accounting":{"producer_and_independent_guard_hard_memory_charged":true,"allocation_credit_bytes":0},
        "memory_before":m,"memory_after":m,"minimum_free_bytes":1000,"required_initial_free_bytes":1000+OUTPUT_MAX+(128u64<<20),
        "sampled_available_bytes":1000+OUTPUT_MAX+(128u64<<20),"actual_available_bytes":1000+OUTPUT_MAX+(128u64<<20)})
}
#[test]
fn complete_capacity_rejects_understated_owner_growth_guard_omission_and_census_races() {
    let fixture = capacity_fixture();
    let check =
        |v: &Value| capacity::validate_capacity(v, MEMORY + GUARD_MEMORY, OUTPUT_MAX + (128 << 20));
    check(&fixture).unwrap();
    for (pointer, bad) in [
        (
            "/memory_before/protected_existing_memory_growth_bytes",
            json!(0),
        ),
        (
            "/memory_after/protected_memory_evidence/0/remaining_hard_memory_growth_bytes",
            json!(124),
        ),
        ("/memory_before/candidate_memory_max_bytes", json!(MEMORY)),
        (
            "/memory_after/assembly204_recovery_memory_policy/candidate_hard_memory_bytes",
            json!(MEMORY),
        ),
        ("/unit_census_after", json!({"missing.service":{}})),
        ("/capped_peer_accounting/allocation_credit_bytes", json!(1)),
    ] {
        let mut changed = fixture.clone();
        *changed.pointer_mut(pointer).unwrap() = bad;
        assert!(check(&changed).is_err(), "accepted {pointer}");
    }
    let mut changed = fixture;
    changed["memory_before"]["protected_memory_evidence"] = json!([]);
    assert!(check(&changed).is_err());
    let c = capacity::candidate(downstream::Stage::Assembly, 0).unwrap();
    assert_eq!(c.memory_max_bytes, MEMORY + GUARD_MEMORY);
    assert_eq!(c.minimum_protected_disk_bytes, 0);
}
#[test]
fn authority_is_explicit_and_recovery_status_has_no_replay_route() {
    deny(&denied()).unwrap();
    for field in [
        "canonical_sidecar_authorized",
        "publication_authorized",
        "retirement_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        let mut changed = denied();
        changed[field] = json!(true);
        assert!(deny(&changed).is_err());
        changed.as_object_mut().unwrap().remove(field);
        assert!(deny(&changed).is_err());
    }
    assert!(
        super::super::assembly204_recovery_binding_scope(204, UNIT, UNIT, "verification").is_ok()
    );
    assert!(super::super::assembly204_recovery_binding_scope(204, UNIT, UNIT, "replay").is_err());
    assert!(
        super::super::assembly204_recovery_binding_scope(204, OLD_UNIT, UNIT, "verification")
            .is_err()
    );
    assert!(
        super::super::assembly204_recovery_binding_scope(204, UNIT, OLD_UNIT, "verification")
            .is_err()
    );
}
#[test]
fn actual_controlled_stop_keeps_exit15_as_stopped_and_never_archive_success() {
    let mut rows = terminal_rows(
        OLD_UNIT,
        OLD_IID,
        "7ad2d189f7e94e70a38c781354912448",
        &format!("{OLD_UNIT}: Deactivated successfully."),
    );
    let mut stop = rows[1].clone();
    stop["__REALTIME_TIMESTAMP"] = json!("2000001");
    stop["MESSAGE_ID"] = json!("9d1aaa27d60140bd96365438aad20286");
    stop["JOB_TYPE"] = json!("stop");
    stop["JOB_RESULT"] = json!("done");
    stop["MESSAGE"] = json!("Stopped fixture.");
    rows.push(stop);
    let mut current = old_current();
    current["Result"] = json!("success");
    current["ExecMainStatus"] = json!("15");
    current["ActiveState"] = json!("inactive");
    current["SubState"] = json!("dead");
    assert!(custody::terminal_shape(&current, &raw(&rows)).is_ok());
    assert!(ownership::manager_shape(&raw(&rows), OLD_UNIT, OLD_IID, true).is_err());
    rows[2]["JOB_TYPE"] = json!("start");
    assert!(custody::terminal_shape(&current, &raw(&rows)).is_err());
}
#[test]
fn independent_guard_requires_actual_owner_exact_source_and_unexpired_deadline() {
    let bound = BoundFile {
        path: "/sealed/plan.json".into(),
        sha256: "a".repeat(64),
    };
    let p = json!({"source_capture":{"path":"/sealed/source","sha256":"b".repeat(64)},"guard_spec":{"path":"/sealed/guard","sha256":"c".repeat(64)}});
    let launch = json!({"invocation_id":"d".repeat(32),"guard_invocation_id":"e".repeat(32)});
    let g = json!({"schema":"jetstreamer-epoch204-assembly-recovery-guard-heartbeat-v1","epoch":204,"plan_sha256":bound.sha256,
        "source_capture":p["source_capture"],"guard_spec":p["guard_spec"],"producer_unit":UNIT,"guard_unit":GUARD,
        "producer_invocation_id":launch["invocation_id"],"guard_invocation_id":launch["guard_invocation_id"],
        "recorded_unix_millis":1000000,"started_unix_millis":900000,"trip":false,"producer_stop_enabled":true,
        "source_custody_unchanged":true,"original_owner_idle":true,"kernel_memory_max_bytes":MEMORY,"kernel_memory_high_bytes":48u64<<30,
        "memory_swap_max_bytes":0,"cpu_quota_usec_per_second":8000000,"tasks_max":512,"maximum_millis":DURATION,"maximum_output_bytes":OUTPUT_MAX});
    ownership::guard_shape(&g, &p, &bound, &launch, 1000000).unwrap();
    assert!(ownership::guard_shape(&g, &p, &bound, &launch, 1015001).is_err());
    for (field, value) in [
        ("guard_invocation_id", Value::Null),
        ("producer_invocation_id", json!("f".repeat(32))),
        ("trip", json!(true)),
        ("producer_stop_enabled", json!(false)),
        ("source_custody_unchanged", json!(false)),
        ("source_capture", json!({})),
        ("kernel_memory_max_bytes", json!(MEMORY - 1)),
    ] {
        let mut changed = g.clone();
        changed[field] = value;
        assert!(
            ownership::guard_shape(&changed, &p, &bound, &launch, 1000000).is_err(),
            "accepted {field}"
        );
    }
    let mut overdue = g;
    overdue["recorded_unix_millis"] = json!(900000 + DURATION + 1);
    assert!(ownership::guard_shape(&overdue, &p, &bound, &launch, 900000 + DURATION + 1).is_err());
}
#[test]
fn source_freeze_must_follow_true_terminal_and_bind_both_exact_sources() {
    let b = |name: &str| BoundFile {
        path: Path::new("/sealed").join(name),
        sha256: "a".repeat(64),
    };
    let original = b("original");
    let terminal = b("terminal");
    let proof = b("suffix");
    let stamp = |bytes| custody::FileStamp {
        device: 1,
        inode: bytes,
        bytes,
        uid: 0,
        gid: 0,
        mode: libc::S_IFREG | 0o400,
        links: 1,
        mtime: 1,
        mtime_nanos: 0,
        ctime: 2,
        ctime_nanos: 0,
    };
    let c = json!({"schema":"jetstreamer-epoch204-assembly-recovery-source-capture-v1","epoch":204,"original_invocation_id":OLD_IID,
        "original_plan":original,"original_terminal":terminal,"suffix_proof":proof,"captured_unix_millis":2000,"original_owner_idle":true,
        "no_source_references":true,"archive_body_reads":0,"issuer":{"executable_sha256":"b".repeat(64)},"authority":denied(),
        "sources":[{"path":PREFIX_PATH,"sha256":PREFIX_SHA,"body_reads":0,"identity":stamp(103_318_151_802)},
        {"path":SUFFIX_PATH,"sha256":SUFFIX_SHA,"body_reads":0,"identity":stamp(155_545_863)}]});
    custody::validate_source_capture(&c, &original, &terminal, &proof, 2000).unwrap();
    for (pointer, value) in [
        ("/captured_unix_millis", json!(1999)),
        ("/original_owner_idle", json!(false)),
        ("/no_source_references", json!(false)),
        ("/sources/1/identity/mode", json!(libc::S_IFREG | 0o600)),
        ("/sources/1/sha256", json!(PREFIX_SHA)),
        ("/sources/0/identity/uid", json!(1000)),
    ] {
        let mut changed = c.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        assert!(
            custody::validate_source_capture(&changed, &original, &terminal, &proof, 2000).is_err(),
            "accepted {pointer}"
        );
    }
}
#[test]
fn recovery_output_cannot_borrow_native_or_final_verification_success() {
    let proof = suffix();
    let tail: lineage::Manifest = serde_json::from_value(proof["suffix_manifest"].clone()).unwrap();
    let expected = lineage::derive(&prefix(), &tail, &proof).unwrap();
    let b = |name: &str| BoundFile {
        path: Path::new("/sealed").join(name),
        sha256: "a".repeat(64),
    };
    let recipe = lineage::Recipe {
        original_plan: b("original"),
        original_terminal: b("terminal"),
        suffix_proof: b("suffix"),
        source_capture: b("capture"),
        recovery_plan: b("recovery"),
        admission: b("admission"),
        launch: b("launch"),
        outcome: b("outcome"),
        recovery_terminal: b("recovered-terminal"),
    };
    let p = json!({"executable_sha256":"b".repeat(64),"zstd_level":3});
    let launch = json!({"invocation_id":"c".repeat(32),"guard_invocation_id":"d".repeat(32)});
    let o = json!({"schema":"jetstreamer-epoch204-assembly-only-recovery-outcome-v1","epoch":204,"unit":UNIT,"invocation_id":launch["invocation_id"],
        "guard_unit":GUARD,"guard_invocation_id":launch["guard_invocation_id"],"plan_sha256":recipe.recovery_plan.sha256,"executable_sha256":p["executable_sha256"],
        "original_terminal":recipe.original_terminal,"original_outcome":"failed_or_stopped","original_invocation_id":OLD_IID,"suffix_proof":recipe.suffix_proof,
        "source_capture":recipe.source_capture,"admission_sha256":recipe.admission.sha256,"private_output":OUTPUT,"archive_bytes":123,"archive_sha256":"e".repeat(64),
        "provenance_version":4,"provenance_sha256":expected.digest,"assembly_profile":GENERATION,"source_archives":2,"slots_merged":432000,
        "writer":{"format":"V2","compression":"Zstd","diff_policy":"OuterCompressed","bucket_slots":128,"zstd_level":3},"epoch_started_unix_millis":ORIGIN,
        "no_replay":true,"new_native_initialization_performed":false,"independent_final_archive_verification_passed":false,"current_plugin_verification_passed":false,"authority":denied()});
    lineage::validate_outcome(&o, &recipe, &p, &launch, &expected).unwrap();
    for (field, value) in [
        ("original_outcome", json!("natural_success")),
        ("provenance_sha256", json!("f".repeat(64))),
        ("source_archives", json!(1)),
        ("new_native_initialization_performed", json!(true)),
        ("independent_final_archive_verification_passed", json!(true)),
        ("current_plugin_verification_passed", json!(true)),
        ("epoch_started_unix_millis", json!(ORIGIN + 1)),
        ("archive_bytes", json!(OUTPUT_MAX + 1)),
    ] {
        let mut changed = o.clone();
        changed[field] = value;
        assert!(
            lineage::validate_outcome(&changed, &recipe, &p, &launch, &expected).is_err(),
            "accepted {field}"
        );
    }
}

#[test]
fn saved_recovery_capacity_cannot_waive_native223_positive_terminal_gate() {
    let mut fixture = capacity_fixture();
    fixture["memory_before"]["assembly204_recovery_memory_policy"]["native223_available_floor_policy"] =
        Value::Null;
    assert!(
        capacity::validate_capacity(&fixture, MEMORY + GUARD_MEMORY, OUTPUT_MAX + (128 << 20))
            .is_err()
    );
    let mut fixture = capacity_fixture();
    fixture["memory_after"]["assembly204_recovery_memory_policy"]["native223_available_floor_policy"]
        ["positive_terminal"]["failure_history_preserved"] = json!(false);
    assert!(
        capacity::validate_capacity(&fixture, MEMORY + GUARD_MEMORY, OUTPUT_MAX + (128 << 20))
            .is_err()
    );
}

#[test]
fn publication_keeps_initial_anchor_but_never_waits_for_retirement_only_successor() {
    use downstream::Stage::*;
    assert_eq!(downstream::required_gates(Import).unwrap(), &[Full, Plugin]);
    assert_eq!(
        downstream::required_gates(Upload).unwrap(),
        &[Full, Plugin, Import]
    );
    assert!(
        !downstream::required_gates(Upload)
            .unwrap()
            .contains(&Boundary)
    );
    assert_eq!(downstream::retirement_neighbor_epochs(), [203, 205]);
}
