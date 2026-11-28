//! Source fixtures exercise contracts only; they do not stand in for native proof.
use crate::{fsutil as f, model::*, validate};
use serde_json::{Value, json};
use std::collections::BTreeMap;
fn b(path: &str) -> Bound {
    Bound {
        path: path.into(),
        sha256: "a".repeat(64),
    }
}
fn state() -> Value {
    json!({"schema":"jetstreamer-adaptive-root-cohort-sweep-v3","assignments":{"lane-a":{
    "phase":"failed","unit":PRODUCER,"first_epoch":199,"last_epoch":200,"attempt":1,
    "source_recovery":false,"adopt_only":false}},"attempts":{"199-200":1},"completed":{},"import_owner":null,
    "manifest_fingerprint":"sha256:581f9ef3a74fc80a8b6b2754a7f4def480c8092d20529f446784f0d73dae810b"})
}
fn policy() -> Policy {
    Policy {
        schema: "terminal199-parent-only-memory-retirement-policy-v1".into(),
        enabled: true,
        terminal_context: Bound {
            path: REGISTRY.into(),
            sha256: REGISTRY_SHA.into(),
        },
        controller_source: Bound {
            path: SCRIPT.into(),
            sha256: SCRIPT_SHA.into(),
        },
        controller_executable: b("/usr/bin/python3.12"),
        controller_argv: serde_json::from_str(include_str!(
            "../fixtures/original-controller-argv.json"
        ))
        .unwrap(),
        controller_start_ticks: 123,
        quarantined_state: Bound {
            path: STATE.into(),
            sha256: STATE_SHA.into(),
        },
        guard_source: Bound {
            path: GUARD_SCRIPT.into(),
            sha256: GUARD_SHA.into(),
        },
        census: Artifact {
            program: b("/qualified/census"),
            qualification: Some(b("/qualified/census-qa.json")),
        },
        native_units: vec![
            CONTROLLER.into(),
            PRODUCER.into(),
            GUARD.into(),
            TIMER.into(),
        ],
        census_scope_review: b("/sealed/review.json"),
        raw_memory_bytes: RAW_MEMORY,
        selected_parent_bytes: 0,
        residual_controller_guard_bytes: RESIDUAL,
        data_bytes: DATA,
    }
}
fn controller() -> Value {
    let command: Value = serde_json::from_str(include_str!(
        "../fixtures/original-controller-rendered-command.json"
    ))
    .unwrap();
    json!({"ExecStart":command,"Id":CONTROLLER,"InvocationID":CONTROLLER_IID,"MainPID":CONTROLLER_PID.to_string(),
    "ControlPID":"0","ActiveState":"active","SubState":"running","NRestarts":"0","Restart":"no","Job":"",
    "MemoryAccounting":"yes","MemoryMax":(GIB/2).to_string(),"MemorySwapMax":"0","Delegate":"no",
    "ControlGroup":format!("/system.slice/{CONTROLLER}")})
}
fn endpoint() -> (Policy, Endpoint) {
    let p = policy();
    let mut native = BTreeMap::new();
    native.insert(CONTROLLER.into(), controller());
    native.insert(
        PRODUCER.into(),
        json!({"Id":PRODUCER,"LoadState":"not-found","InvocationID":"","MainPID":"0",
        "ControlPID":"0","ActiveState":"inactive","SubState":"dead","Job":""}),
    );
    for u in [GUARD, TIMER] {
        native.insert(u.into(),json!({"Id":u,"LoadState":"not-found","MainPID":"0","ControlPID":"0","ActiveState":"inactive","Job":""}));
    }
    let process = Process {
        pid: CONTROLLER_PID,
        start_ticks: 123,
        unit: CONTROLLER.into(),
        invocation_id: CONTROLLER_IID.into(),
        executable: p.controller_executable.clone(),
        argv: p.controller_argv.clone(),
        command_source: p.controller_source.clone(),
        cwd: "/".into(),
        cgroup: format!("/system.slice/{CONTROLLER}"),
        descriptor_refs: vec![],
        mmap_refs: vec![],
        role: "quarantined-original-controller".into(),
    };
    let findings = [
        (
            CONTROLLER,
            "quarantined-original-controller",
            p.controller_source.clone(),
            Some(CONTROLLER_IID.into()),
        ),
        (
            PRODUCER,
            "original-collected-worker",
            p.controller_source.clone(),
            None,
        ),
        (
            GUARD,
            "original-stop-only-guard",
            p.guard_source.clone(),
            None,
        ),
        (
            TIMER,
            "original-stop-only-guard",
            p.guard_source.clone(),
            None,
        ),
    ]
    .into_iter()
    .map(|(unit, disposition, source, iid)| LauncherFinding {
        unit: unit.into(),
        disposition: disposition.into(),
        source,
        qualification: b("/qualified/no-retry.json"),
        current_invocation_id: iid,
        may_start_original_parent: false,
    })
    .collect();
    let e = Endpoint {
        native,
        matching_processes: vec![process],
        scanned_process_count: 37,
        scanned_dimensions: vec![
            "argv".into(),
            "cwd".into(),
            "descriptors".into(),
            "executable".into(),
            "mappings".into(),
            "source".into(),
        ],
        unresolved_processes: vec![],
        unreadable_processes: vec![],
        original_worker_cgroup: format!("/system.slice/{PRODUCER}"),
        original_worker_cgroup_members: vec![],
        original_worker_descriptor_holders: vec![],
        original_worker_mmap_holders: vec![],
        controller_state: p.quarantined_state.clone(),
        launcher_findings: findings,
        unresolved_launchers: vec![],
    };
    (p, e)
}
fn raw() -> Value {
    json!({"active_peer_allocations":[{"state":"retained-terminal-original199","unit":PRODUCER,"invocation_id":PRODUCER_IID,
    "memory_max_bytes":RAW_MEMORY,"parent_memory_bytes":PARENT,"controller_memory_bytes":GIB/2,"guard_memory_bytes":GIB/2,
    "data_reservation_bytes":DATA,"native_pool_suballocation":false,"memory_credit_bytes":0,"DATA_credit_bytes":0,"credit_bytes":0,
    "resource_release_qualified":false,"ordinary_replay_claim":false,"terminal_context":{"path":REGISTRY,"sha256":REGISTRY_SHA}}],
    "projected_obligations":[{"producer_invocation_id":PRODUCER_IID,"epoch":199,"claim_key":format!("epoch199/current-enrolled-growth/{PRODUCER_IID}"),"outstanding_bytes":DATA}],"current_owner_hard_limits":{}})
}
#[test]
fn parent_only_keeps_controller_guard_data_and_exact_legacy_context() {
    let p = policy();
    validate::policy(&p).unwrap();
    validate::failed_state(&state()).unwrap();
    let a = raw();
    let saved = a.clone();
    validate::terminal_raw_row(&a).unwrap();
    assert_eq!(a, saved);
    assert_eq!(PARENT, 206_158_430_208);
    assert_eq!(RAW_MEMORY - PARENT, RESIDUAL);
    assert_eq!(DATA, 824_633_720_832);
}
#[test]
fn explicit_registration_cannot_silently_become_full193_release_or_another_epoch() {
    for edit in 0..8 {
        let mut p = policy();
        match edit {
            0 => p.raw_memory_bytes = PARENT,
            1 => p.residual_controller_guard_bytes = 0,
            2 => p.data_bytes = 0,
            3 => p.terminal_context.sha256 = "b".repeat(64),
            4 => p.controller_source.sha256 = "b".repeat(64),
            5 => p.enabled = false,
            6 => p.selected_parent_bytes = PARENT,
            _ => {
                p.native_units.pop();
            }
        }
        assert!(validate::policy(&p).is_err(), "{edit}");
    }
}
#[test]
fn retry_flag_and_even_other_controller_argv_changes_reject() {
    for arg in [
        "--retry-failed",
        "--retry-failed=true",
        "--first-epoch=163",
        "--max-concurrency=2",
    ] {
        let mut p = policy();
        p.controller_argv.push(arg.into());
        assert!(validate::policy(&p).is_err(), "{arg}");
    }
}
#[test]
fn quarantine_cannot_be_cleared_retried_adopted_or_imported() {
    for edit in 0..8 {
        let mut s = state();
        match edit {
            0 => s["assignments"] = json!({}),
            1 => s["assignments"]["lane-a"]["phase"] = json!("producer"),
            2 => s["attempts"]["199-200"] = json!(0),
            3 => s["assignments"]["lane-a"]["attempt"] = json!(2),
            4 => s["assignments"]["lane-a"]["source_recovery"] = json!(true),
            5 => s["assignments"]["lane-a"]["adopt_only"] = json!(true),
            6 => s["import_owner"] = json!({"unit":"new.service"}),
            _ => s["assignments"]["lane-b"] = s["assignments"]["lane-a"].clone(),
        };
        assert!(validate::failed_state(&s).is_err(), "{edit}");
    }
}
#[test]
fn complete_native_and_process_scope_can_preserve_live_nonretry_controller() {
    let (p, e) = endpoint();
    validate::endpoint(&p, &e).unwrap();
}
#[test]
fn process_census_rejects_unreadable_unknown_reused_or_hidden_replay_references() {
    for edit in 0..9 {
        let (p, mut e) = endpoint();
        match edit {
            0 => e.unreadable_processes.push(json!({"pid":88})),
            1 => e.unresolved_processes.push(json!({"pid":88})),
            2 => e.matching_processes[0].start_ticks = 124,
            3 => e.matching_processes[0].argv.push("--retry-failed".into()),
            4 => e.matching_processes[0].role = "historical-worker".into(),
            5 => e.matching_processes[0]
                .descriptor_refs
                .push("AccountsDb".into()),
            6 => e.matching_processes[0]
                .mmap_refs
                .push("accounts/appendvec".into()),
            7 => {
                e.scanned_dimensions.pop();
            }
            _ => {
                e.native.remove(GUARD);
            }
        }
        assert!(validate::endpoint(&p, &e).is_err(), "{edit}");
    }
}
#[test]
fn original_worker_group_descriptor_and_future_launcher_custody_are_positive_gates() {
    for edit in 0..7 {
        let (p, mut e) = endpoint();
        match edit {
            0 => e.original_worker_cgroup_members.push(72),
            1 => e.original_worker_descriptor_holders.push(json!({"pid":72})),
            2 => e.original_worker_mmap_holders.push(json!({"pid":72})),
            3 => e.unresolved_launchers.push(json!({"unit":"retry.service"})),
            4 => e.launcher_findings[0].may_start_original_parent = true,
            5 => {
                e.launcher_findings.pop();
            }
            _ => e.native.get_mut(PRODUCER).unwrap()["Job"] = json!("42"),
        };
        assert!(validate::endpoint(&p, &e).is_err(), "{edit}");
    }
}
#[test]
fn raw_row_data_history_cannot_be_zeroed_removed_pooled_or_counted_twice() {
    for edit in 0..8 {
        let mut a = raw();
        match edit {
            0 => a["active_peer_allocations"] = json!([]),
            1 => {
                let row = a["active_peer_allocations"][0].clone();
                a["active_peer_allocations"]
                    .as_array_mut()
                    .unwrap()
                    .push(row);
            }
            2 => a["active_peer_allocations"][0]["memory_max_bytes"] = json!(RESIDUAL),
            3 => a["active_peer_allocations"][0]["native_pool_suballocation"] = json!(true),
            4 => a["active_peer_allocations"][0]["data_reservation_bytes"] = json!(0),
            5 => a["projected_obligations"][0]["outstanding_bytes"] = json!(0),
            6 => a["current_owner_hard_limits"][CONTROLLER] = json!({"MemoryMax":GIB/2}),
            _ => a["active_peer_allocations"][0]["credit_bytes"] = json!(PARENT),
        };
        assert!(validate::terminal_raw_row(&a).is_err(), "{edit}");
    }
}
#[test]
fn composition_deducts_only_parent_after_current141_once() {
    let (raw, peers) = (900 * GIB, 700 * GIB);
    let (base_total, base_peer) = (raw - 193 * GIB, peers - 193 * GIB);
    let (total, peer) = validate::compose(raw, base_total, peers, base_peer).unwrap();
    assert_eq!(total, raw - (193 + 192) * GIB);
    assert_eq!(peer, peers - (193 + 192) * GIB);
    assert_eq!(total - peer, raw - peers);
}
#[test]
fn composition_after_optional_failed4_does_not_repeat_either_prior_deduction() {
    let (raw, peers) = (1000 * GIB, 800 * GIB);
    let prior = (193 + 68) * GIB;
    let (total, peer) = validate::compose(raw, raw - prior, peers, peers - prior).unwrap();
    assert_eq!(raw - total, (193 + 68 + 192) * GIB);
    assert_eq!(raw - peers, total - peer);
}
#[test]
fn insufficient_peer_promise_underflow_and_crossed_nonpeer_terms_fail_closed() {
    for args in [
        (10, 9, 11, 10),
        (900, 700, 700, 699),
        (500, 200, 400, 100),
        (100, 101, 50, 51),
    ] {
        assert!(
            validate::compose(args.0, args.1, args.2, args.3).is_err(),
            "{args:?}"
        );
    }
}
#[test]
fn no_numeric_systemd_pid_or_changed_iid_is_accepted() {
    for (field, value) in [
        ("MainPID", json!(CONTROLLER_PID)),
        ("InvocationID", json!("b".repeat(32))),
        ("MemoryMax", json!(GIB / 2)),
        ("Restart", json!("on-failure")),
        ("Job", json!("21")),
        ("MemoryMax", json!("infinity")),
    ] {
        let mut n = controller();
        n[field] = value;
        assert!(validate::controller(&n).is_err(), "{field}");
    }
}
#[test]
fn known_controller_argv_binding_has_the_expected_canonical_array_digest() {
    assert_eq!(
        f::sha(&serde_json::to_vec(&policy().controller_argv).unwrap()),
        CONTROLLER_ARGV_SHA
    );
}
#[test]
fn stale_future_or_missing_clock_does_not_support_point_of_use() {
    assert!(f::fresh(100, 400, 300).is_ok());
    assert!(f::fresh(100, 401, 300).is_err());
    assert!(f::fresh(401, 400, 300).is_err());
    assert!(f::fresh(0, 100, 300).is_err());
}

#[test]
fn a_live_guard_cannot_spend_more_than_the_retained_half_gib_promise() {
    let (p, mut e) = endpoint();
    *e.native.get_mut(GUARD).unwrap() = json!({"Id":GUARD,"LoadState":"loaded","MainPID":"88","ControlPID":"0",
        "ActiveState":"active","Job":"","MemoryAccounting":"yes","MemoryMax":(GIB/2).to_string(),
        "MemorySwapMax":"0","Restart":"no","NRestarts":"0","InvocationID":"b".repeat(32)});
    let mut guard = e.matching_processes[0].clone();
    guard.pid = 88;
    guard.unit = GUARD.into();
    guard.invocation_id = "b".repeat(32);
    guard.role = "original-stop-only-guard".into();
    guard.command_source = p.guard_source.clone();
    guard.cgroup = format!("/system.slice/{GUARD}");
    e.matching_processes.push(guard);
    validate::endpoint(&p, &e).unwrap();
    for (field, value) in [
        ("MemoryMax", json!("infinity")),
        ("MemoryMax", json!(GIB / 2)),
        ("MemorySwapMax", json!("infinity")),
        ("Restart", json!("on-failure")),
    ] {
        let mut changed = e.clone();
        changed.native.get_mut(GUARD).unwrap()[field] = value;
        assert!(validate::endpoint(&p, &changed).is_err(), "{field}");
    }
}
