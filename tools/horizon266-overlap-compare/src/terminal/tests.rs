use super::*;
use segment_manifest::{SEGMENT_MANIFEST_SCHEMA_VERSION, SegmentRuntimeIdentity};

const INVOCATION: &str = "0ac3661590204f69839172d75e650860";
const BOOT: &str = "3b17d0055c3a4a0e8841da097e0957b5";
const PID: u32 = 2635555;

struct Fixture {
    launch: Launch,
    profile: Profile,
    manifest: HistoricalSegmentManifest,
    manager: Vec<Value>,
    journal: Vec<Value>,
    state: UnitState,
}

fn fixture() -> Fixture {
    let reference = || Reference::new("/var/lib/fixture", &"0".repeat(64));
    let profile = Profile {
        unit: UNIT.to_string(),
        run_root: "/home/ubuntu/fixture".into(),
        node: Reference::new("/var/lib/fixture/jetstreamer-node", &"a".repeat(64)),
        worker: Reference::new("/var/lib/fixture/worker", WORKER_SHA),
        guard: reference(),
        static_guard_plan: reference(),
        argv: vec![
            "/var/lib/fixture/jetstreamer-node".to_owned(),
            EPOCH.to_string(),
        ],
        persistent_archive: SEGMENT.into(),
        persistent_segment_manifest: format!("{SEGMENT}.segment.json").into(),
    };
    let launch = Launch {
        schema: "jetstreamer-historical-performance-launch-receipt-v1".into(),
        kind: "epoch266-private-hourly-overlap".into(),
        epoch: EPOCH,
        unit: UNIT.into(),
        run_root: profile.run_root.clone(),
        invocation_id: INVOCATION.into(),
        main_pid: PID,
        node_path: profile.node.path.clone(),
        worker: Reference::new(&profile.worker.path, WORKER_SHA),
        profile: reference(),
        lossless_restore: reference(),
        admission: reference(),
        guard_plan: reference(),
        launch_token: reference(),
        active_guard: reference(),
        guard_release_fit: reference(),
        evidence: Value::Null,
        launched: true,
        diagnostic_only: true,
        canonical_epoch_publication_authorized: false,
        remote_mutations: false,
        r2_mutations: false,
    };
    let checkpoint = |slot, blockhash: &str, cursor| SegmentCheckpointSummary {
        slot,
        bank_hash: GENESIS.into(),
        accounts_hash: TERMINAL_ACCOUNTS.into(),
        last_blockhash: blockhash.into(),
        capitalization: 512823375441850375,
        transaction_count: 49_787_614_573,
        tick_height: 64 * (slot + 1),
        slot_complete: true,
        write_count: 0,
        next_write_version: cursor,
    };
    let manifest = HistoricalSegmentManifest {
        schema_version: SEGMENT_MANIFEST_SCHEMA_VERSION,
        epoch: EPOCH,
        output_slot_start: START,
        output_slot_count: SEGMENT_END - START,
        runtime: SegmentRuntimeIdentity {
            generation_profile: "jetstreamer-node/historical-replay-v1".into(),
            runtime_profile: "solana-v1.8.11".into(),
            runtime_admission: SegmentRuntimeAdmission::Candidate,
            runtime_revision: RUNTIME_REVISION.into(),
            runtime_toolchain: "fixture".into(),
            runtime_target: "x86_64-unknown-linux-gnu".into(),
            genesis_hash: GENESIS.into(),
        },
        worker_executable_sha256: fixture_worker_digest(),
        archive_sha256: [5; 32],
        bootstrap_archive_sha256: None,
        bootstrap: checkpoint(START - 1, SEAM_BLOCK, RESTART_CURSOR),
        terminal: checkpoint(SEGMENT_END - 1, TERMINAL_BLOCK, RESTART_CURSOR + 1),
        emitted_raw_write_versions: RESTART_CURSOR..RESTART_CURSOR + 1,
    };
    let description = format!("{UNIT} - [systemd-run] {}", profile.argv.join(" "));
    let manager = [
        (UNIT_STARTING, format!("Starting {description}..."), 10),
        (UNIT_STARTED, format!("Started {description}."), 20),
        (
            UNIT_SUCCESS,
            format!("{UNIT}: Deactivated successfully."),
            70,
        ),
        (UNIT_RESOURCES, format!("{UNIT}: Consumed CPU time."), 80),
    ]
    .into_iter()
    .map(|(id, message, stamp): (_, _, u64)| {
        json!({"MESSAGE_ID": id, "MESSAGE":message, "_PID":"1", "_UID":"0", "UNIT":UNIT,
            "INVOCATION_ID":INVOCATION, "_BOOT_ID":BOOT, "__MONOTONIC_TIMESTAMP":stamp.to_string()})
    })
    .collect();
    let journal = [
        checkpoint_message(&manifest.bootstrap),
        checkpoint_message(&manifest.terminal),
        "snapshot verification complete".to_owned(),
        format!("published verified historical segment evidence {}", profile.persistent_segment_manifest.display()),
    ].into_iter().enumerate().map(|(i, message)| {
        let module = if i < 2 { "jetstreamer_node::historical_replay" } else { "jetstreamer_node" };
        json!({
            "MESSAGE":format!("[2026-11-27T17:42:26.938201837Z INFO  {module}] {message}"),
            "_PID":PID.to_string(), "_UID":"1000", "_SYSTEMD_UNIT": UNIT, "_SYSTEMD_CGROUP": launch.cgroup(),
            "_SYSTEMD_INVOCATION_ID": INVOCATION, "_BOOT_ID":BOOT, "_EXE":profile.node.path,
            "__MONOTONIC_TIMESTAMP":(30 + i * 10).to_string(),
        })
    }).collect();
    let state = [
        ("Id", UNIT),
        ("LoadState", "not-found"),
        ("InvocationID", ""),
        ("MainPID", "0"),
        ("ActiveState", "inactive"),
        ("SubState", "dead"),
        ("Result", "success"),
        ("ControlPID", "0"),
        ("ControlGroup", ""),
        ("Job", ""),
        ("NRestarts", "0"),
        ("Restart", "no"),
        ("ExecMainPID", "0"),
        ("ExecMainCode", "0"),
        ("ExecMainStatus", "0"),
        ("ExecMainStartTimestampMonotonic", "0"),
        ("ExecMainExitTimestampMonotonic", "0"),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_owned(), value.to_owned()))
    .collect();
    Fixture {
        launch,
        profile,
        manifest,
        manager,
        journal,
        state,
    }
}

fn fixture_worker_digest() -> [u8; 32] {
    let mut digest = [0; 32];
    for (i, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&WORKER_SHA[2 * i..2 * i + 2], 16).unwrap();
    }
    digest
}

impl Fixture {
    fn verify(&self, drained: bool) -> Result<()> {
        let capture = retained_state(&self.state);
        let exit = (self.state["LoadState"] == "not-found").then_some(&capture);
        clean_exit(&self.state, exit, UNIT, INVOCATION, PID, drained)?;
        let (start, exit) = manager_lifecycle(&self.manager, &self.launch, &self.profile, BOOT)?;
        verify_native_events(
            &self.journal,
            &self.launch,
            &self.profile,
            &self.manifest,
            start,
            exit,
            BOOT,
        )
    }
}

fn retained_state(state: &UnitState) -> UnitState {
    let mut state = state.clone();
    for (name, value) in [
        ("LoadState", "loaded"),
        ("InvocationID", INVOCATION),
        ("ExecMainPID", &PID.to_string()),
        ("ExecMainCode", "1"),
        ("ExecMainStartTimestampMonotonic", "19"),
        ("ExecMainExitTimestampMonotonic", "69"),
    ] {
        state.insert(name.to_owned(), value.to_owned());
    }
    state
}

#[test]
fn natural_zero_exit_accepts_loaded_services_and_collected_services_with_exact_capture() {
    let mut f = fixture();
    f.verify(true).unwrap();
    assert!(clean_exit(&f.state, None, UNIT, INVOCATION, PID, true).is_err());
    let mut bad_capture = retained_state(&f.state);
    bad_capture.insert("ExecMainCode".to_owned(), "2".to_owned());
    assert!(clean_exit(&f.state, Some(&bad_capture), UNIT, INVOCATION, PID, true).is_err());
    f.state = retained_state(&f.state);
    f.verify(true).unwrap();
    f.state.insert("ExecMainCode".to_owned(), "2".to_owned());
    assert!(f.verify(true).is_err());
}

#[test]
fn running_queued_restarted_or_undrained_services_are_rejected() {
    for (name, value) in [
        ("ActiveState", "active"),
        ("Job", "42"),
        ("NRestarts", "1"),
        ("ExecMainStatus", "1"),
        ("InvocationID", "e24f74b51b3b4c3a8fe12f1767d2b186"),
    ] {
        let mut f = fixture();
        f.state.insert(name.to_owned(), value.to_owned());
        assert!(f.verify(true).is_err(), "{name}={value}");
    }
    assert!(fixture().verify(false).is_err());
}

#[test]
fn stop_failure_or_newer_invocation_cannot_pass_as_natural_exit() {
    for message in [
        "Stopping",
        "Scheduled restart job",
        "Main process exited",
        "Failed with result",
    ] {
        let mut f = fixture();
        let mut extra = f.manager[1].clone();
        extra["MESSAGE"] = json!(message);
        extra["MESSAGE_ID"] = json!("a".repeat(32));
        extra["__MONOTONIC_TIMESTAMP"] = json!("65");
        f.manager.insert(2, extra);
        assert!(f.verify(true).is_err(), "{message}");
    }
    let mut f = fixture();
    let mut newer = f.manager.clone();
    for row in &mut newer {
        row["INVOCATION_ID"] = json!("b".repeat(32));
        row["__MONOTONIC_TIMESTAMP"] = json!((timestamp(row).unwrap() + 1_000).to_string());
    }
    f.manager.extend(newer);
    assert!(f.verify(true).is_err());
}

#[test]
fn checkpoint_events_require_the_same_boot_pid_and_executable_and_exact_tuple() {
    for (field, wrong) in [
        ("_BOOT_ID", "another-boot"),
        ("_PID", "9001"),
        ("_EXE", "/tmp/other-node"),
        ("_SYSTEMD_INVOCATION_ID", "another-invocation"),
        ("_SYSTEMD_CGROUP", "/another-cgroup"),
    ] {
        let mut f = fixture();
        f.journal[2][field] = json!(wrong);
        assert!(f.verify(true).is_err(), "{field}");
    }
    let mut f = fixture();
    f.manifest.bootstrap.capitalization -= 1;
    assert!(f.verify(true).is_err());
    let mut f = fixture();
    f.profile.persistent_segment_manifest = "/tmp/foreign.segment.json".into();
    assert!(f.verify(true).is_err());
}

#[test]
fn missing_duplicate_and_misordered_native_markers_are_rejected() {
    let mut f = fixture();
    f.journal.pop();
    assert!(f.verify(true).is_err());
    let mut f = fixture();
    f.journal.push(f.journal[2].clone());
    assert!(f.verify(true).is_err());
    let mut f = fixture();
    f.journal.swap(1, 2);
    assert!(f.verify(true).is_err());
    let mut f = fixture();
    f.journal[3]["__MONOTONIC_TIMESTAMP"] = json!("71");
    assert!(f.verify(true).is_err());
}

#[test]
fn foreign_manifest_range_worker_or_terminal_checkpoint_is_rejected() {
    for change in [
        |m: &mut HistoricalSegmentManifest| m.output_slot_count -= 1,
        |m: &mut HistoricalSegmentManifest| m.worker_executable_sha256[0] ^= 1,
        |m: &mut HistoricalSegmentManifest| m.terminal.accounts_hash = GENESIS.to_owned(),
        |m: &mut HistoricalSegmentManifest| m.runtime.runtime_revision = "foreign".to_owned(),
    ] {
        let mut f = fixture();
        change(&mut f.manifest);
        assert!(
            validate_manifest(&f.manifest)
                .unwrap_err()
                .to_string()
                .contains("canonical terminal reference")
                || fixture().manifest.output_slot_count != f.manifest.output_slot_count
        );
    }
}

#[test]
fn stable_identity_rejects_same_length_path_replacement_and_hash_mismatch() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("archive.jet");
    fs::write(&path, b"first").unwrap();
    let (file, identity) = open(&path).unwrap();
    let hash = digest(b"first");
    assert!(bound_bytes(&path, &hash, JSON_LIMIT, false).is_ok());
    let replacement = dir.path().join("replacement");
    fs::write(&replacement, b"other").unwrap();
    fs::rename(replacement, &path).unwrap();
    assert!(unchanged(&path, &file, identity).is_err());
    assert!(bound_bytes(&path, &hash, JSON_LIMIT, false).is_err());
}

#[test]
fn sealed_files_and_package_install_are_read_only_and_no_clobber() {
    let dir = tempfile::tempdir().unwrap();
    let from = dir.path().join("staging");
    let to = dir.path().join("final");
    fs::create_dir(&from).unwrap();
    let path = from.join("comparison-plan.json");
    write_sealed(&path, &json!({"producer_drained":true})).unwrap();
    assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o400);
    assert!(write_sealed(&path, &json!({})).is_err());
    fs::create_dir(&to).unwrap();
    assert!(install_package(&from, &to).is_err());
    assert!(path.is_file());
    fs::remove_dir(&to).unwrap();
    install_package(&from, &to).unwrap();
    assert!(to.join("comparison-plan.json").is_file());
}
