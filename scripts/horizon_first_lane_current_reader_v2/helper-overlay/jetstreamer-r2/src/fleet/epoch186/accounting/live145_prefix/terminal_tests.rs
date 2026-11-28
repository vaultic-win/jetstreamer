use super::*;
fn admission() -> model::Admission {
    serde_json::from_value(json!({"schema":"horizon-epoch145-private-extraction-typed-admission-v1",
        "plan":{"path":PLAN,"sha256":PLAN_SHA},"actor_unit":ACTOR,"actor_iid":IID,
        "actor_pid":2463122,"actor_start_ticks":238412403u64,
        "accepted_at":1794037470u64,"accepted_boottime_millis":2384124000u64,
        "memory_evidence":null,"data_evidence":null,"existing_memory_bytes":1,
        "protected_existing_data_bytes":1,"required_initial_memory_bytes":MEMORY_FLOOR,
        "required_initial_data_bytes":DATA_FLOOR,"original_native":null})).unwrap()
}
fn plan() -> model::Plan { serde_json::from_str(include_str!("fixtures/plan.json")).unwrap() }
fn selector() -> Selector {
    serde_json::from_value(json!({"plan":{"path":PLAN,"sha256":PLAN_SHA},
        "ready":{"path":format!("{STATE}/ready.json"),"sha256":"d8cd0712b4ee180fa10d3d977b6981a40846d7cd5f78698fd4a0bf9ad938457b"},
        "admission":{"path":format!("{STATE}/admission.json"),"sha256":"eecfdac8d2b968979c3bf541d75b5362d6b223b8d58da17600b7c4af25664c02"},
        "terminal_retained":true,"guard_before_source":{"path":format!("{STATE}/guard-before-source-read.json"),"sha256":"3410e0ea3c4fbbfe911185e893f9c79eb246a6cf419ecea7f567ac03ae79c53d"}})).unwrap()
}
fn failed() -> Value {
    json!({"Id":ACTOR,"InvocationID":IID,"LoadState":"loaded","ActiveState":"failed","SubState":"failed",
        "MainPID":"0","ExecMainPID":"2463122","ExecMainExitTimestamp":"Sat 2026-11-07 17:33:02 UTC",
        "Result":"exit-code","ExecMainCode":"1","ExecMainStatus":"74","ControlGroup":"",
        "ControlPID":"0","Job":"","DropInPaths":"","ExecStartPre":"","KillMode":"control-group",
        "NRestarts":"0","Restart":"no","Type":"exec","User":"root","Group":"root",
        "MemoryMax":(80u64<<30).to_string(),"MemorySwapMax":"0","TasksMax":"512","CPUQuotaPerSecUSec":"8s",
        "ExecStart":format!("{} ignore_errors=no ; code=exited ; status=74/IOERR }}",command("extract"))})
}
fn failed_guard() -> Value {
    let mut g=failed();g["Id"]=json!(GUARD);g["InvocationID"]=json!("b".repeat(32));
    g["MemoryMax"]=json!((256u64<<20).to_string());g["CPUQuotaPerSecUSec"]=json!("1s");
    g["ExecMainStatus"]=json!("1");g["ExecStart"]=json!(format!("{} ignore_errors=no ; code=exited ; status=1/FAILURE }}",command("guard")));g
}
fn drained() -> Value {
    let cg=json!({"unit":ACTOR,"absent":false,"cgroup_procs":"","cgroup_events":"populated 0\nfrozen 0\n"});
    let refs=json!({"complete_numeric_proc_scan":true,"cmdline_maps_exe_cwd_root_fd_checked":true,
        "original_actor_pid_absent":true,"unapproved_holders":[],"controller_exemptions":false,"authenticated_guard_pid":null});
    json!({"cgroup_before":cg,"cgroup_after":cg,"references_before":refs,"references_after":refs})
}
fn endpoint() -> Value {
    json!({"schema":SCHEMA,"lifecycle":PHASE,"token_is_historical_only":true,
        "live_guard_coverage_claimed":false,"memory_or_DATA_credit_bytes":0,"replay_launch_authorized":false,
        "actor_full":failed(),"token":{"guard_iid":"original last writer"},"token_sha256":"original digest",
        "terminal_evidence":{"original":"retained raw"},"drained":drained()})
}
#[test]
fn exact_original_failed74_identity_and_bounds_are_required() {
    let f=failed();failed_actor(&f,&f,&admission()).unwrap();
    for (key,value) in [("InvocationID",json!("c".repeat(32))),("ExecMainPID",json!("42")),
        ("ExecMainExitTimestamp",json!("Sat 2026-11-07 17:33:03 UTC")),("ExecMainStatus",json!("0")),
        ("Result",json!("success")),("MainPID",json!("1")),("ControlPID",json!("2")),
        ("NRestarts",json!("1")),("MemoryMax",json!("1")),("CPUQuotaPerSecUSec",json!("1s")),
        ("DropInPaths",json!("/tmp/foreign.conf")),("ExecStartPre",json!("/bin/true")),
        ("ExecStart",json!("/bin/true"))] {
        let mut b=f.clone();b[key]=value;assert!(failed_actor(&b,&b,&admission()).is_err(),"{key}");
    }
}
#[test]
fn failed_guard_is_only_accepted_by_the_terminal_consumer() {
    let f=failed_guard();guard(&f).unwrap();assert!(guard_native(&f).is_err());
    for (key,value) in [("ExecMainStatus",json!("74")),
        ("MemoryMax",json!("0")),("NRestarts",json!("1")),("ExecStart",json!("/bin/true"))] {
        let mut b=f.clone();b[key]=value;
        assert!(guard(&b).is_err(),"{key}");
    }
}
#[test]
fn old_token_is_historical_without_new_health_or_a_new_writer() {
    let p=plan();let a=admission();let b:Value=serde_json::from_str(include_str!("fixtures/before.json")).unwrap();
    let pb:model::Bound=serde_json::from_value(b["plan"].clone()).unwrap();
    let ab:model::Bound=serde_json::from_value(b["admission"].clone()).unwrap();
    let t:model::Token=serde_json::from_value(b["token"].clone()).unwrap();
    let late=t.at_boottime_millis+1_000_000;
    assert!(token(&t,&p,&a,&pb,&ab,FAILED_AT,late).is_err());
    historical_token(&b["token"],&p,&a,&pb,&ab,FAILED_AT,late).unwrap();
    for (key,value) in [("actor_iid",json!("c".repeat(32))),("actor_start_ticks",json!(1)),
        ("protected_free_bytes",json!(DATA_FLOOR-1)),("protected_available_memory_bytes",json!(0)),
        ("at_unix_seconds",json!(FAILED_AT+1))] {
        let mut bad=b["token"].clone();bad[key]=value;
        assert!(historical_token(&bad,&p,&a,&pb,&ab,FAILED_AT,late).is_err(),"{key}");
    }
}
#[test]
fn terminality_retains_actor_guard_output_source_floors_and_all_cpu() {
    let p=terminal_peer(&selector(),&plan(),&failed());peer_shape(&p).unwrap();
    assert_eq!(p["memory_max_bytes"],(80u64<<30)+(256u64<<20));
    assert_eq!(p["data_reservation_bytes"],(160u64<<30)+(128u64<<20)+(4u64<<30));
    assert_eq!(p["cpu_quota_micros_retained"],9_000_000u64);
    assert_eq!(p["guard_floor_bytes"],DATA_FLOOR);
    assert_eq!(p["minimum_available_memory_bytes"],MEMORY_FLOOR);
    assert_eq!(p["original_failed_partial_retained_bytes"],41_966_206_710u64);
    for (key,value) in [("memory_max_bytes",json!(0)),("data_reservation_bytes",json!(0)),
        ("reserved_guard_memory_bytes",json!(0)),("cpu_quota_micros_retained",json!(0)),
        ("live_guard_coverage_claimed",json!(true)),("resource_release_qualified",json!(true)),
        ("credit_bytes",json!(1))] {
        let mut b=p.clone();b[key]=value;assert!(peer_shape(&b).is_err(),"{key}");
    }
}
#[test]
fn finite_capture_cannot_cross_live_terminal_or_replace_historical_evidence() {
    let a=endpoint();same_phase(&a,&a).unwrap();
    assert!(same_phase(&a,&json!({"lifecycle":"live"})).is_err());
    assert!(same_phase(&json!({"lifecycle":"live"}),&a).is_err());
    for (key,value) in [("token",json!({"guard_iid":"new invented writer"})),
        ("terminal_evidence",json!({"new":"failure"})),("actor_full",json!({})),
        ("live_guard_coverage_claimed",json!(true)),("memory_or_DATA_credit_bytes",json!(1))] {
        let mut b=a.clone();b[key]=value;assert!(same_phase(&a,&b).is_err(),"{key}");
    }
}
#[test]
fn populated_cgroup_process_holder_or_controller_exemption_is_rejected() {
    let a=drained();native::drained_shape(&a).unwrap();
    for (pointer,value) in [("/cgroup_before/cgroup_procs",json!("42\n")),
        ("/cgroup_before/cgroup_events",json!("populated 1\n")),
        ("/references_before/unapproved_holders",json!([42])),
        ("/references_before/controller_exemptions",json!(true)),
        ("/references_before/original_actor_pid_absent",json!(false)),
        ("/references_before/complete_numeric_proc_scan",json!(false))] {
        let mut b=a.clone();*b.pointer_mut(pointer).unwrap()=value;
        assert!(native::drained_shape(&b).is_err(),"{pointer}");
    }
}
#[test]
fn watchdog_evidence_preserves_raw_bytes_and_exact_failure_instead_of_a_completion() {
    let w=json!({"schema":"horizon-epoch145-private-extractor-watchdog-failure-v1","at_unix_seconds":FAILED_AT,
        "actor_iid":IID,"error":"missing/stale/crossed native guard proof","phase":1,"charged_output_bytes":7,
        "authority":{"runtime_promotion_authorized":false,"canonical_sidecar_authorized":false,
            "publication_authorized":false,"retirement_authorized":false,"r2_mutations":false,"replay_launch_authorized":false}});
    let bytes=serde_json::to_vec(&w).unwrap();
    let e=json!({"watchdog":{"bound":{"path":format!("{STATE}/watchdog-failure.json"),"sha256":custody::sha(&bytes)},"source_bytes":bytes,"value":w},"extraction_complete_absent":true,"extraction_failure_absent":true});
    assert_eq!(evidence_shape(&e,&plan(),&admission(),FAILED_AT+1).unwrap(),FAILED_AT);
    let mut b=e.clone();b["watchdog"]["value"]["actor_iid"]=json!("c".repeat(32));assert!(evidence_shape(&b,&plan(),&admission(),FAILED_AT+1).is_err());
    let mut b=e.clone();b["extraction_complete_absent"]=json!(false);assert!(evidence_shape(&b,&plan(),&admission(),FAILED_AT+1).is_err());
    assert!(evidence_shape(&e,&plan(),&admission(),FAILED_AT-1).is_err());
}

#[test]
fn explicit_lifecycle_selection_never_auto_relabels_an_existing_live_selector() {
 selected_phase(false,false).unwrap();selected_phase(true,true).unwrap();
 assert!(selected_phase(false,true).is_err());assert!(selected_phase(true,false).is_err());
}
