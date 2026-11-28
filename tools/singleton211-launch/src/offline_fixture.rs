//! Synthetic, isolated fixture graph. Never an operational receipt generator.
//! Only compiled into the test harness; requires Main's private overlay namespace.
use super::*;
const FIX: &str = "/var/lib/jetstreamer/horizon211-offline-integration-fixture";
const BOOT: &str = "00000000-0000-0000-0000-000000000001";
fn isolated() {
    assert_eq!(unsafe { libc::geteuid() }, 0);
    assert_ne!(
        fs::read_link("/proc/self/ns/mnt").unwrap(),
        fs::read_link("/proc/1/ns/mnt").unwrap()
    );
    let mounts = fs::read_to_string("/proc/self/mountinfo").unwrap();
    assert!(mounts.lines().any(
        |l| l.split_whitespace().nth(4) == Some("/var/lib/jetstreamer")
            && l.contains(" - overlay ")
            && l.contains("upperdir=/tmp/horizon211-offline-")
    ));
    assert_eq!(
        std::env::var("HORIZON211_OFFLINE_FIXTURE_ONLY").unwrap(),
        "synthetic-not-runtime"
    );
}
fn bytes(path: impl AsRef<Path>, data: &[u8]) -> Bound {
    isolated();
    let path = path.as_ref();
    assert!(path.starts_with("/var/lib/jetstreamer"));
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut f = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o444)
        .open(path)
        .unwrap();
    f.write_all(data).unwrap();
    f.sync_all().unwrap();
    Bound::new(path, digest(data))
}
fn document(path: impl AsRef<Path>, v: &Value) -> Bound {
    bytes(path, &serde_json::to_vec_pretty(v).unwrap())
}
fn doc(name: &str, v: &Value) -> Bound {
    document(Path::new(FIX).join(name), v)
}
fn denied(mut v: Value) -> Value {
    deny_authority(&mut v);
    v
}
fn replay(mut v: Value) -> Value {
    deny_authority(&mut v);
    v["replay_launch_authorized"] = json!(true);
    v
}
fn journal(unit: &str, iid: &str, events: &[(&str, u64)]) -> Value {
    json!(events.iter().map(|(message,clock)| json!({"_PID":"1","_UID":"0","UNIT":unit,"INVOCATION_ID":iid,"_BOOT_ID":BOOT.replace('-',""),"MESSAGE":message,"__MONOTONIC_TIMESTAMP":clock.to_string()})).collect::<Vec<_>>())
}
fn producer(plan: &Bound, iid: &str, sha: &str, terminal: bool) -> Value {
    let attempt = plan
        .path
        .parent()
        .unwrap()
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .strip_prefix("horizon-singleton211-startup-plan-")
        .unwrap();
    let mut v = json!({"Id":UNIT,"FragmentPath":launch::package(attempt,"producer").join(UNIT),"InvocationID":iid,"MainPID":if terminal {"0"} else {"42"},"ControlPID":"0","Job":"","ActiveState":if terminal {"inactive"} else {"active"},"SubState":if terminal {"dead"} else {"running"},"Result":"success","ControlGroup":if terminal {String::new()} else {format!("/system.slice/{UNIT}")},"ExecMainCode":if terminal {"2"} else {"0"},"ExecMainStatus":if terminal {"15"} else {"0"},"CPUAffinity":"0-15","Environment":launch::environment().iter().map(|(k,v)|format!("{k}={v}")).collect::<Vec<_>>().join(" "),"EnvironmentFiles":format!("{} (ignore_errors=no)",plan.path.with_file_name("startup.env").display()),"PassEnvironment":"","UnsetEnvironment":"","BindReadOnlyPaths":format!("{INPUT}/genesis.tar.bz2:{ROOT}/output/genesis.tar.bz2:rbind"),"ExecStart":format!("{{ path={GATE} ; argv[]={} ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }}",launch::gate_command(&plan.path,sha))});
    for (k, val) in [
        ("Type", "exec"),
        ("User", "ubuntu"),
        ("Group", "ubuntu"),
        ("Restart", "no"),
        ("KillMode", "control-group"),
        ("Delegate", "no"),
        ("MemoryHigh", "150000000000"),
        ("MemoryMax", "225000000000"),
        ("MemorySwapMax", "0"),
        ("TasksMax", "512"),
        ("CPUQuotaPerSecUSec", "16s"),
        ("RuntimeMaxUSec", "3d"),
        ("ProtectHome", "read-only"),
        ("ProtectSystem", "strict"),
        ("PrivateNetwork", "no"),
        ("NoNewPrivileges", "yes"),
        ("CapabilityBoundingSet", ""),
        ("ReadWritePaths", ROOT),
        ("NRestarts", "0"),
        ("LoadState", "loaded"),
        ("DropInPaths", ""),
        ("Transient", "no"),
        ("RemainAfterExit", "no"),
    ] {
        v[k] = json!(val);
    }
    v
}
struct Graph {
    review: Value,
    startup: Bound,
    admission: Bound,
}
fn graph(
    attempt: &str,
    operation: &str,
    source: &Bound,
    capability: &Bound,
    prestart: Option<&Bound>,
    sha: &str,
    guard: &Bound,
) -> Graph {
    let prepared = document(
        launch::package(attempt, "prepared").join("prepared.json"),
        &denied(
            json!({"schema":"horizon-singleton211-prepared-units-v1","review":null,"operation":operation,"attempt":attempt,"gate":Bound::new(GATE,sha),"guard":guard,"cpu_affinity":(0..16).collect::<Vec<u64>>(),"source_publication":source,"boot_id":BOOT,"recorded_unix_seconds":90,"recorded_monotonic_us":100}),
        ),
    );
    let review = json!({"operation":operation,"attempt":attempt,"preparation":prepared,"guard":guard,"cpu_affinity":(0..16).collect::<Vec<u64>>(),"source_publication":source,"input_capability":capability,"prestart_qualification":prestart,"recorded_unix_seconds":91});
    let review_ref = doc(&format!("{attempt}-review.json"), &review);
    let peer = document(
        launch::package(attempt, "admission").join("peer-window.json"),
        &json!({"schema":"horizon-singleton211-original-peer-window-v1","review":review_ref,"boot_id":BOOT,"recorded_monotonic_us":200,"deadline_with_margin_monotonic_us":60_001_000}),
    );
    let placeholder = Bound::new(Path::new(FIX).join("unread-booking.json"), "1".repeat(64));
    let mut admission = json!({"schema":"horizon-singleton211-current-fleet-admission-v1","epoch":211,"mode":if operation=="launch" {"full-replay"} else {"protective-stop-qualification"},"operation":operation,"held_gate_launch_authorized":true,"unit":UNIT,"private_run_root":ROOT,"maximum_memory_bytes":MEMORY,"candidate_incremental_peak_bytes":SCRATCH,"admitted":true,"protected_existing_floor_bytes":100,"gate":Bound::new(GATE,sha),"node":Bound::new(NODE,NODE_SHA),"worker":Bound::new(WORKER,WORKER_SHA),"input_capability":capability,"native_input":Bound::new(NATIVE_PROOF,NATIVE_PROOF_SHA),"boot_id":BOOT,"guard":guard,"recorded_unix_seconds":92,"expires_unix_seconds":152,"review":review_ref,"source_publication":source,"observer":placeholder,"fleet":placeholder,"reservation_ledger":placeholder});
    admission = if operation == "launch" {
        replay(admission)
    } else {
        denied(admission)
    };
    let ar = doc(&format!("{attempt}-admission.json"), &admission);
    let plan = json!({"schema":"horizon-singleton211-startup-plan-v1","operation":operation,"epoch":211,"unit":UNIT,"guard_unit":GUARD_UNIT,"worker_root":ROOT,"token_root":TOKENS,"bootstrap_slot":91151575u64,"snapshot_sha256":SNAPSHOT_SHA,"maximum_root_physical_bytes":SCRATCH,"maximum_memory_bytes":MEMORY,"gate":Bound::new(GATE,sha),"node":Bound::new(NODE,NODE_SHA),"worker":Bound::new(WORKER,WORKER_SHA),"native_input":Bound::new(NATIVE_PROOF,NATIVE_PROOF_SHA),"boot_id":BOOT,"minimum_free_bytes":100,"guard":guard,"issued_monotonic_us":1000,"expires_monotonic_us":60_001_000,"admission":ar,"preparation":prepared,"peer_window":peer,"input_capability":capability});
    let startup = document(
        launch::package(attempt, "startup-plan").join("plan.json"),
        &plan,
    );
    bytes(
        startup.path.with_file_name("startup.env"),
        format!("HORIZON211_STARTUP_PLAN_SHA256={}\n", startup.sha256).as_bytes(),
    );
    let affinity = (0..16).map(|n| n.to_string()).collect::<Vec<_>>().join(" ");
    bytes(
        launch::package(attempt, "producer").join(UNIT),
        launch::producer_template(&startup.path, &affinity, sha).as_bytes(),
    );
    bytes(
        launch::package(attempt, "producer").join(RETENTION),
        launch::retention_template().as_bytes(),
    );
    Graph {
        review,
        startup,
        admission: ar,
    }
}
fn protective(source: &Bound, capability: &Bound, sha: &str, guard: &Bound) -> Bound {
    let attempt = "offline-protective";
    let g = graph(
        attempt,
        "qualify-guard",
        source,
        capability,
        None,
        sha,
        guard,
    );
    let (mut c, mut gp, mut sample, mut intent, mut completion) =
        qualification::tests::stop_fixture();
    let iid = "a".repeat(32);
    let gid = "b".repeat(32);
    let receipts = launch::package(attempt, "guard-receipts");
    gp["receipt_directory"] = json!(receipts);
    let gr = document(
        launch::package(attempt, "guard-binding").join("guard-plan.json"),
        &gp,
    );
    bytes(
        gr.path.with_file_name("guard.env"),
        format!("HORIZON211_GUARD_PLAN_SHA256={}\n", gr.sha256).as_bytes(),
    );
    sample["plan"] = json!(gr.path);
    sample["plan_sha256"] = json!(gr.sha256);
    sample["guard_sha256"] = json!(guard.sha256);
    let sr = document(receipts.join(format!("sample-{gid}.json")), &sample);
    intent["plan_sha256"] = json!(gr.sha256);
    intent["sample"] = sample;
    let ir = document(receipts.join("stop-intent.json"), &intent);
    completion["plan_sha256"] = json!(gr.sha256);
    completion["intent"] = json!(ir.path);
    let cr = document(receipts.join("stop-completion.json"), &completion);
    let guard_unit = bytes(
        launch::package(attempt, "guard-units").join(GUARD_UNIT),
        launch::guard_template(guard, &gr.path, &receipts).as_bytes(),
    );
    let timer_unit = bytes(
        launch::package(attempt, "guard-units").join(TIMER),
        launch::timer_template().as_bytes(),
    );
    let mut gt = c["guard_terminal"].clone();
    gt["EnvironmentFiles"] = json!(format!(
        "{} (ignore_errors=no)",
        gr.path.with_file_name("guard.env").display()
    ));
    for k in ["Environment", "PassEnvironment", "UnsetEnvironment"] {
        gt[k] = json!("");
    }
    gt["FragmentPath"] = json!(guard_unit.path);
    gt["ExecStart"] = json!(format!(
        "{{ path={} ; argv[]={} {} --plan-sha256 ${{HORIZON211_GUARD_PLAN_SHA256}} --self-sha256 {} ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }}",
        guard.path.display(),
        guard.path.display(),
        gr.path.display(),
        guard.sha256
    ));
    let timer = json!({"Id":TIMER,"LoadState":"loaded","ActiveState":"inactive","SubState":"dead","Unit":GUARD_UNIT,"Job":"","DropInPaths":"","FragmentPath":timer_unit.path});
    let pristine = json!({"root":[1,2,0,1000,16832,2,0,0,0,0],"output":[1,3,0,1000,16832,2,0,0,0,0],"genesis_placeholder":[1,4,0,1000,33024,1,0,0,0,0]});
    let held = json!({"mapped_gate":Bound::new(GATE,sha),"startup_plan":g.startup,"producer":producer(&g.startup,&iid,sha,false),"cmdline":format!("{GATE}\0gate\0{}\0{}\0{sha}\0",g.startup.path.display(),g.startup.sha256),"cgroup_members":[42],"children":[],"descendant_cgroups":[],"token_absent":true,"pristine_root":pristine,"recorded_monotonic_us":1200});
    let pj = doc(
        "protective-producer-journal.json",
        &journal(
            UNIT,
            &iid,
            &[
                (&format!("Started {UNIT} - fixture"), 1100),
                (&format!("Stopping {UNIT} - fixture"), 1400),
                (&format!("{UNIT}: Deactivated successfully."), 1500),
            ],
        ),
    );
    let gj = doc(
        "protective-guard-journal.json",
        &journal(
            GUARD_UNIT,
            &gid,
            &[
                (&format!("Starting {GUARD_UNIT} - fixture"), 1300),
                (&format!("{GUARD_UNIT}: Deactivated successfully."), 1600),
            ],
        ),
    );
    for (k,v) in json!({"schema":"horizon-singleton211-protective-stop-capture-v1","gate":Bound::new(GATE,sha),"guard":guard,"startup_plan":g.startup,"boot_id":BOOT,"held":held,"terminal_root":pristine,"producer_terminal":producer(&g.startup,&iid,sha,true),"guard_terminal":gt,"timer_terminal":timer,"sample":sr,"stop_intent":ir,"stop_completion":cr,"guard_plan":gr,"receipts":receipts,"producer_package":launch::package(attempt,"producer"),"guard_package":launch::package(attempt,"guard-units"),"producer_pid1":pj,"guard_pid1":gj,"recorded_monotonic_us":1700,"token_absent":true,"pristine_root_unchanged":true,"original_process_gone":true,"kernel_drained":true,"actual_stop_observed":true,"Main_acceptance_required":true}).as_object().unwrap(){c[k]=v.clone();}
    deny_authority(&mut c);
    let units = json!([
        [
            UNIT,
            Bound::new(
                launch::package(attempt, "producer").join(UNIT),
                digest(
                    launch::producer_template(
                        &g.startup.path,
                        &launch::cpus(&g.review).unwrap(),
                        sha
                    )
                    .as_bytes()
                )
            )
        ],
        [
            RETENTION,
            Bound::new(
                launch::package(attempt, "producer").join(RETENTION),
                digest(launch::retention_template().as_bytes())
            )
        ],
        [GUARD_UNIT, guard_unit],
        [TIMER, timer_unit]
    ]);
    c["unit_files"] = units.clone();
    let capture = doc("protective-capture.json", &c);
    let before = doc(
        "retirement-before.json",
        &json!({"capture":capture,"unit_files":units,"root":pristine,"producer":c["producer_terminal"]}),
    );
    let mut after = json!({});
    for unit in [UNIT, GUARD_UNIT, TIMER, RETENTION] {
        after[unit] = json!({"Id":unit,"LoadState":"not-found","Job":"","ActiveState":"inactive"});
    }
    let retired = doc(
        "retirement.json",
        &denied(
            json!({"schema":"horizon-singleton211-qualification-unit-retirement-v1","capture":capture,"boot_id":BOOT,"unit_files":units,"sealed_packages_and_diagnostics_preserved":true,"producer_restarted":false,"all_four_links_removed":true,"kernel_drained":true,"token_absent":true,"pristine_root_unchanged":true,"before":before,"after":after}),
        ),
    );
    let accepted = denied(
        json!({"schema":"horizon-singleton211-protective-stop-qualification-v1","Main_accepted":true,"gate":Bound::new(GATE,sha),"guard":guard,"sandbox_permissions_verified":true,"capture":capture,"retirement":retired}),
    );
    qualification::accepted(&accepted, guard, sha).unwrap();
    doc("protective-accepted.json", &accepted)
}
#[test]
#[ignore = "Main-only private overlay namespace, synthetic offline fixtures; never host /var/lib"]
fn build_complete_offline_handoff_graph() {
    isolated();
    assert!(!Path::new(FIX).exists());
    let roles: Value = serde_json::from_slice(
        &fs::read(std::env::var("HORIZON211_SOURCE_ROLE_BINDINGS").unwrap()).unwrap(),
    )
    .unwrap();
    let roles = roles.as_array().unwrap();
    let role = |name: &str| roles.iter().find(|r| r["role"] == name).unwrap();
    let sha = text(&role("launcher")["artifact"], "sha256").unwrap();
    let guard = binding(&role("guard")["artifact"]).unwrap();
    let source = doc(
        "source-publication.json",
        &json!({"schema":"horizon-singleton211-source-publication-v1","remote_ref":"refs/heads/account-updates","all_required_dependencies_in_remote":true,"exact_deployed_source_provenance_reviewed":true,"no_untracked_required_source":true,"artifacts":roles,"synthetic_fixture_only":true}),
    );
    let input_files = vec![
        (Bound::new(NODE, NODE_SHA), 0),
        (Bound::new(WORKER, WORKER_SHA), 0),
        (Bound::new(PREFLIGHT, PREFLIGHT_SHA), 0),
        (
            Bound::new(Path::new(INPUT).join(SNAPSHOT), SNAPSHOT_SHA),
            8_731_506_223u64,
        ),
        (
            Bound::new(Path::new(INPUT).join("genesis.tar.bz2"), GENESIS_SHA),
            20_144,
        ),
    ];
    let capability = doc(
        "input-capability.json",
        &denied(
            json!({"schema":"horizon-singleton211-input-capability-v1","epoch":211,"all_inputs_rehashed":true,"native_input":Bound::new(NATIVE_PROOF,NATIVE_PROOF_SHA),"manifest_fingerprint":FINGERPRINT,"files":input_files.into_iter().map(|(b,n)|json!({"binding":b,"identity":[1,1,n,0,33060,1,0,0,0,0]})).collect::<Vec<_>>(),"synthetic_fixture_only":true}),
        ),
    );
    let protective = protective(&source, &capability, sha, &guard);
    let q = doc(
        "prestart.json",
        &denied(
            json!({"schema":"horizon-singleton211-prestart-qualification-v1","gate":Bound::new(GATE,sha),"node":Bound::new(NODE,NODE_SHA),"worker":Bound::new(WORKER,WORKER_SHA),"guard":guard,"source_publication":source,"observer_complete_tuple_accepted":true,"fleet_running_and_terminal_accepted":true,"inactive_status_exact_owner_accepted":true,"terminal_retention_accepted":true,"pre_restore_gate_tests_accepted":true,"native_worker_production_equivalence_accepted":true,"actual_first_guard_required_before_snapshot":true,"actual_replay_startup_qualified":false,"launcher_artifact_sha256":sha,"protective_stop_qualification":protective,"qualification_evidence":source,"synthetic_fixture_only":true}),
        ),
    );
    let mut cases = Vec::new();
    for (attempt, iid, gid) in [
        ("offline-live-a", "c".repeat(32), "d".repeat(32)),
        ("offline-live-b", "e".repeat(32), "f".repeat(32)),
    ] {
        let g = graph(
            attempt,
            "launch",
            &source,
            &capability,
            Some(&q),
            sha,
            &guard,
        );
        let gp = json!({"schema":"jetstreamer-horizon-standalone-guard-plan-v1","unit":UNIT,"invocation_id":iid,"filesystem":"/","worker_root":ROOT,"minimum_free_bytes":100,"maximum_root_physical_bytes":SCRATCH,"maximum_worker_vmas":3500000});
        let gr = document(
            launch::package(attempt, "guard-binding").join("guard-plan.json"),
            &gp,
        );
        bytes(
            gr.path.with_file_name("guard.env"),
            format!("HORIZON211_GUARD_PLAN_SHA256={}\n", gr.sha256).as_bytes(),
        );
        let (_, _, mut sample, _, _) = qualification::tests::stop_fixture();
        sample["plan"] = json!(gr.path);
        sample["plan_sha256"] = json!(gr.sha256);
        sample["guard_sha256"] = json!(guard.sha256);
        sample["guard_invocation_id"] = json!(gid);
        sample["producer_invocation_id"] = json!(iid);
        sample["producer"]["invocation_id"] = json!(iid);
        sample["trip_reason"] = Value::Null;
        sample["minimum_free_bytes"] = json!(100);
        let sr = doc(&format!("{attempt}-sample.json"), &sample);
        let jr = doc(
            &format!("{attempt}-journal.json"),
            &journal(
                GUARD_UNIT,
                &gid,
                &[
                    (&format!("Starting {GUARD_UNIT} - fixture"), 1300),
                    (&format!("{GUARD_UNIT}: Deactivated successfully."), 1600),
                ],
            ),
        );
        let token = replay(
            json!({"schema":"horizon-singleton211-first-guard-token-v1","startup_plan_sha256":g.startup.sha256,"unit":UNIT,"invocation_id":iid,"main_pid":42,"gate":Bound::new(GATE,sha),"node":Bound::new(NODE,NODE_SHA),"worker":Bound::new(WORKER,WORKER_SHA),"guard":guard,"boot_id":BOOT,"admission":g.admission,"recorded_monotonic_us":1700,"candidate_next_elapse_monotonic_us":30_000_000,"guard_invocation_id":gid,"guard_plan":gr,"guard_sample":sr,"guard_pid1_journal":jr}),
        );
        let tr = document(
            Path::new(TOKENS).join(&iid).join("guard-admission.json"),
            &token,
        );
        let unit = Bound::new(
            launch::package(attempt, "producer").join(UNIT),
            digest(
                launch::producer_template(&g.startup.path, &launch::cpus(&g.review).unwrap(), sha)
                    .as_bytes(),
            ),
        );
        let handoff = replay(
            json!({"schema":"horizon-singleton211-guarded-startup-v1","epoch":211,"unit":UNIT,"launched":true,"private_run_root":ROOT,"node":Bound::new(NODE,NODE_SHA),"worker":Bound::new(WORKER,WORKER_SHA),"native_input":Bound::new(NATIVE_PROOF,NATIVE_PROOF_SHA),"output_slot_start":91152000u64,"terminal_slot":91583999u64,"canonical_root_slot":91583512u64,"post_root_slot_count":487,"output_slot_count":432000,"same_pid_exec_observed":true,"entry_replay_observed":false,"invocation_id":iid,"main_pid":42,"startup_plan":g.startup,"admission":g.admission,"input_capability":capability,"native_input_qualified":true,"launcher_sha256":sha,"first_guard_token":tr,"guard_plan":gr,"first_guard_sample":sr,"first_guard_pid1_journal":jr,"recorded_unix_seconds":100,"recorded_monotonic_us":1800,"unit_file":unit,"producer":producer(&g.startup,&iid,sha,false),"guard_sha256":guard.sha256,"retention":{"Id":RETENTION,"LoadState":"loaded","ActiveState":"active","SubState":"active","After":format!("{UNIT} {GUARD_UNIT} {TIMER}"),"DefaultDependencies":"no","IgnoreOnIsolate":"yes","Job":"","DropInPaths":"","Wants":"","Requires":"","BindsTo":"","Upholds":""},"synthetic_fixture_only":true}),
        );
        let hr = doc(&format!("{attempt}-handoff.json"), &handoff);
        assert_eq!(
            validate_saved_handoff(&hr.path, &hr.sha256, sha).unwrap(),
            handoff
        );
        for (field, val) in [
            ("invocation_id", json!("9".repeat(32))),
            ("main_pid", json!(43)),
            ("terminal_slot", json!(91583512u64)),
            ("worker", json!(Bound::new(WORKER, "8".repeat(64)))),
        ] {
            let mut bad = handoff.clone();
            bad[field] = val;
            let b = doc(&format!("{attempt}-bad-{field}.json"), &bad);
            assert!(
                validate_saved_handoff(&b.path, &b.sha256, sha).is_err(),
                "{field}"
            );
        }
        cases.push(json!({"handoff":hr,"value":handoff,"synthetic_fixture_only":true}));
    }
    // Both cases independently passed the entire saved graph. Substitute each
    // cross-owner graph edge separately; a valid B object cannot repair A.
    for key in [
        "startup_plan",
        "admission",
        "first_guard_token",
        "guard_plan",
        "first_guard_sample",
        "first_guard_pid1_journal",
    ] {
        let mut bad = cases[0]["value"].clone();
        bad[key] = cases[1]["value"][key].clone();
        let binding = doc(&format!("cross-owner-{key}.json"), &bad);
        assert!(
            validate_saved_handoff(&binding.path, &binding.sha256, sha).is_err(),
            "{key}"
        );
    }
    doc(
        "cases.json",
        &json!({"schema":"horizon211-synthetic-offline-integration-cases-v1","cases":cases,"runtime_qualification_claimed":false}),
    );
}
