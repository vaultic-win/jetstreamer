//! Complete synthetic graph tests. No service, process, archive or R2 observation.
use super::*;
use std::os::unix::fs::PermissionsExt;
const CASES: &str = "/var/lib/jetstreamer/horizon211-offline-integration-fixture/cases.json";
fn cases() -> Value {
    assert_eq!(
        std::env::var("HORIZON211_OFFLINE_FIXTURE_ONLY").unwrap(),
        "synthetic-not-runtime"
    );
    assert_ne!(
        fs::read_link("/proc/self/ns/mnt").unwrap(),
        fs::read_link("/proc/1/ns/mnt").unwrap()
    );
    let v: Value = serde_json::from_slice(&fs::read(CASES).unwrap()).unwrap();
    assert_eq!(
        v["schema"],
        "horizon211-synthetic-offline-integration-cases-v1"
    );
    v
}
fn put(root: &Path, name: &str, v: &Value) -> BoundFile {
    let path = root.join(name);
    let bytes = serde_json::to_vec(v).unwrap();
    let mut f = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&path)
        .unwrap();
    f.write_all(&bytes).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).unwrap();
    BoundFile {
        path,
        sha256: hex_lower(&Sha256::digest(&bytes)),
    }
}
fn claim(case: &Value) -> DiagnosticClaim {
    DiagnosticClaim {
        epoch: 211,
        unit: singleton211::UNIT.into(),
        invocation_id: case["value"]["invocation_id"].as_str().unwrap().into(),
        scratch_path: singleton211::ROOT.into(),
        launch_receipt: serde_json::from_value(case["handoff"].clone()).unwrap(),
    }
}
fn status(
    root: &Path,
    case: &Value,
    name: &str,
    registered_case: &Value,
) -> StatusPublicationReceipt {
    let c = claim(case);
    let registered = claim(registered_case);
    let launch: &Value = &case["handoff"];
    let observer = put(
        root,
        &format!("{name}-observer.json"),
        &json!({"schema":"jetstreamer-horizon-live-resource-sample-v2","recorded_at_utc":"1970-01-01T00:01:40Z","synthetic_fixture_only":true}),
    );
    let plan = put(
        root,
        &format!("{name}-fleet-plan.json"),
        &json!({"schema":SCHEMA,"first_epoch":211,"last_epoch":211,"observer":observer,"previous_fleet":null,"output":root.join("unused-output.json"),"status_receipt_directory":root,"gates":{},"tracked_units":[singleton211::UNIT],"diagnostics":[{"epoch":registered.epoch,"unit":registered.unit,"invocation_id":registered.invocation_id,"scratch_path":registered.scratch_path,"launch_receipt":registered.launch_receipt}]}),
    );
    let mut census = json!({});
    census[singleton211::UNIT] = case["value"]["producer"].clone();
    let fleet = put(
        root,
        &format!("{name}-fleet.json"),
        &json!({"plan":plan.path,"plan_sha256":plan.sha256,"unit_census":census,"observer_sha256":observer.sha256,"synthetic_fixture_only":true}),
    );
    let estimate_path = root.join(format!("{name}-estimate.json"));
    let model = put(
        root,
        &format!("{name}-model.json"),
        &json!({"schema":"jetstreamer-full211-status-plan-v1","mode":"launch-event","observer":observer,"fleet":fleet,"launch":launch,"receipt_directory":root,"estimate_receipt":estimate_path,"initialization_allowance_millis":600000,"fallback_slots_per_second":2.0,"downstream_allowance_millis":{"archive_close":1000,"boundary":1000,"full_verification":1000,"plugin_verification":1000,"readback":1000,"remote_plugin_playback":1000,"sidecar_commit":1000,"upload":1000},"estimate_basis":"synthetic offline integration fixture","estimate_evidence":[launch]}),
    );
    let s = EpochStatus {
        epoch: 211,
        jet_size_bytes: 0,
        elapsed_execution_millis: 0,
        estimated_remaining_millis: 216608000,
        sampled_at_utc: "1970-01-01T00:01:40Z".into(),
        phase: "verification".into(),
    };
    let estimate = put(
        root,
        &format!("{name}-estimate.json"),
        &json!({"schema":"jetstreamer-full211-status-observation-v1","status":s,"launch":launch,"plan":model,"observer":observer,"fleet":fleet,"progress":{"counter_resets":0,"last":null,"sufficient_for_rates":false},"synthetic_fixture_only":true}),
    );
    StatusPublicationReceipt {
        schema: STATUS_RECEIPT_SCHEMA.into(),
        bucket: "offline-no-r2".into(),
        epoch: 211,
        key: "epoch-211.epoch-status.json".into(),
        status: s,
        object_etag: "synthetic-not-remote".into(),
        previous_object_etag: None,
        observer_receipt: estimate.path,
        observer_receipt_sha256: estimate.sha256,
        controller_invocation_id: c.invocation_id.clone(),
        producer_invocation_id: c.invocation_id,
        authenticated_readback: false,
        verified_unix_seconds: 100,
        pipeline_binding: None,
    }
}
#[test]
#[ignore = "Main's isolated synthetic full211 fixture namespace only"]
fn full211_complete_fleet_live_terminal_and_inactive_owner() {
    let all = cases();
    let a = &all["cases"][0];
    let b = &all["cases"][1];
    let c = claim(a);
    let v = &a["value"];
    // Outer fleet dispatcher and actual saved-handoff validator, not a stub.
    validate_diagnostic_launch(v, &c).unwrap();
    let live = &v["producer"];
    let node = Path::new(v["node"]["path"].as_str().unwrap());
    let observed = |unit: &Value| {
        singleton211::live_with_observation(
            &c,
            unit,
            || Ok(serde_json::from_value(unit.clone())?),
            |_| Ok((node.to_path_buf(), fs::metadata(node)?, fs::metadata(node)?)),
        )
    };
    observed(live).unwrap();
    for (k, value) in [
        ("InvocationID", json!(b["value"]["invocation_id"])),
        ("NRestarts", json!("1")),
        ("MainPID", json!("43")),
        ("MemoryMax", json!("224999999999")),
        ("MemorySwapMax", json!("1")),
        ("ExecStart", b["value"]["producer"]["ExecStart"].clone()),
    ] {
        let mut bad = live.clone();
        bad[k] = value;
        assert!(observed(&bad).is_err(), "live {k}");
    }
    assert!(
        singleton211::live_with_observation(
            &c,
            live,
            || Ok(serde_json::from_value(live.clone())?),
            |_| Ok((
                PathBuf::from("/foreign/node"),
                fs::metadata(node)?,
                fs::metadata(node)?
            ))
        )
        .is_err()
    );
    let mut wrong = claim(b);
    assert!(validate_diagnostic_launch(v, &wrong).is_err());
    wrong = claim(a);
    wrong.launch_receipt = claim(b).launch_receipt;
    assert!(validate_diagnostic_launch(v, &wrong).is_err());
    for field in ["epoch", "unit", "scratch_path"] {
        let mut bad = claim(a);
        match field {
            "epoch" => bad.epoch = 210,
            "unit" => bad.unit = "horizon-singleton-211-replacement.service".into(),
            _ => bad.scratch_path = "/foreign/epoch211".into(),
        }
        assert!(
            validate_diagnostic_launch(v, &bad).is_err(),
            "claim {field}"
        );
    }
    let root = tempfile::tempdir().unwrap();
    let receipt = status(root.path(), a, "a", a);
    let mut census = BTreeMap::from([(singleton211::UNIT.to_string(), live.clone())]);
    assert!(full211_status::matches(
        &receipt,
        211,
        &Value::Null,
        &census
    ));
    let expected = vec![(singleton211::UNIT.into(), c.invocation_id.clone())];
    assert_eq!(
        crate::inactive_status::offline_full211_owner_units(&receipt).unwrap(),
        expected
    );
    // Preserve frozen original owner across clean and failed terminal states.
    for (active, sub, result, code, status) in [
        ("inactive", "dead", "success", "1", "0"),
        ("failed", "failed", "exit-code", "1", "1"),
    ] {
        let mut terminal = live.clone();
        for (k, x) in [
            ("ActiveState", active),
            ("SubState", sub),
            ("Result", result),
            ("ExecMainCode", code),
            ("ExecMainStatus", status),
            ("MainPID", "0"),
            ("ControlPID", "0"),
            ("ControlGroup", ""),
        ] {
            terminal[k] = json!(x);
        }
        assert!(!diagnostic_stage_running(&terminal));
        assert!(observed(&terminal).is_err());
        census.insert(singleton211::UNIT.into(), terminal);
        assert!(!full211_status::matches(
            &receipt,
            211,
            &Value::Null,
            &census
        ));
        assert_eq!(
            crate::inactive_status::offline_full211_owner_units(&receipt).unwrap(),
            expected
        );
    }
    // A separately valid B handoff/owner must never repair an A frozen chain.
    let foreign = status(root.path(), a, "cross-owner", b);
    assert!(crate::inactive_status::offline_full211_owner_units(&foreign).is_err());
    for field in [
        "controller_invocation_id",
        "producer_invocation_id",
        "observer_receipt_sha256",
    ] {
        let mut bad = serde_json::to_value(&receipt).unwrap();
        bad[field] = json!(if field.ends_with("sha256") {
            "0".repeat(64)
        } else {
            "e".repeat(32)
        });
        let bad: StatusPublicationReceipt = serde_json::from_value(bad).unwrap();
        assert!(
            crate::inactive_status::offline_full211_owner_units(&bad).is_err(),
            "{field}"
        );
    }
    for (k, value) in [
        ("sampled_at_utc", json!("1970-01-01T00:01:41Z")),
        ("estimated_remaining_millis", json!(216608001u64)),
        ("phase", json!("replay")),
    ] {
        let mut bad = serde_json::to_value(&receipt).unwrap();
        bad["status"][k] = value;
        let bad: StatusPublicationReceipt = serde_json::from_value(bad).unwrap();
        assert!(
            crate::inactive_status::offline_full211_owner_units(&bad).is_err(),
            "status {k}"
        );
    }
    assert!(!receipt.authenticated_readback); // Synthetic fixtures never assert remote success.
}
