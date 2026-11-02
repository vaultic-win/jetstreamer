use super::*;
use std::cell::Cell;
fn fixture() -> (tempfile::TempDir, Plan, Bound, u64) {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    fs::create_dir(root.join("attempts")).unwrap();
    fs::set_permissions(root.join("attempts"), fs::Permissions::from_mode(0o700)).unwrap();
    let now = clock().unwrap();
    let seed=write_new(&root.join("seed.json"),&json!({"schema":"jetstreamer-horizon-live-resource-sample-v2","recorded_at_utc":utc(now-1800).unwrap(),"completed_at_utc":utc(now-1799).unwrap()})).unwrap();
    let owner = json!({"range":"237-237","controller_unit":"fixed.service","producer_unit":"fixed.service","expected_controller_invocation_id":"a".repeat(32),"expected_producer_invocation_id":"a".repeat(32),"scratch_path":"/never-inspected","worker_executable_basename":"historical-worker"});
    let template=write_new(&root.join("template.json"),&json!({"schema":"jetstreamer-horizon-live-resource-sample-config-v2","minimum_interval_seconds":1800,"previous_sample":seed.path,"output":"/unused","not_before_utc":utc(now).unwrap(),"filesystem_path":"/","replays":[owner],"diagnostic_replays":[]})).unwrap();
    let p = Plan {
        schema: "jetstreamer-observer-rollover-plan-v1".into(),
        root: root.clone(),
        sampler: Bound {
            path: "/sealed/not-executed".into(),
            sha256: "b".repeat(64),
        },
        template,
        seed,
        minimum_interval_seconds: 1800,
    };
    let pb = write_new(
        &root.join("plan.json"),
        &json!({"test_fixture":"not a production plan"}),
    )
    .unwrap();
    (tmp, p, pb, now)
}
fn generated(c: &Value, now: u64) -> Value {
    let prior = bound(Path::new(c["previous_sample"].as_str().unwrap())).unwrap();
    let expected = &c["replays"][0];
    let point = |role: &str| json!({"unit":expected[format!("{role}_unit")],"invocation_id":expected[format!("expected_{role}_invocation_id")],"restarts":0,"active_state":"active","sub_state":"running"});
    json!({"schema":"jetstreamer-horizon-live-resource-sample-v2","recorded_at_utc":utc(now).unwrap(),"completed_at_utc":utc(now).unwrap(),"cadence":{"observation_reason":"routine","routine_minimum_interval_enforced":true,"previous_sample":prior.path,"previous_sample_sha256":prior.sha256,"minimum_interval_seconds":1800},"replays":[{"range":"237-237","invocation_binding_stable":true,"producer_before":point("producer"),"producer_after":point("producer"),"controller_before":point("controller"),"controller_after":point("controller")}],"diagnostic_replays":[],"mutation":{"producer_or_controller_signals_sent":false,"service_state_changed":false,"remote_mutations":false,"r2_mutations":false}})
}
fn publish(config: &Path, now: u64, change_owner: bool) {
    let c: Value = serde_json::from_slice(&stable(config, LIMIT).unwrap()).unwrap();
    let mut v = generated(&c, now);
    if change_owner {
        v["replays"][0]["producer_after"]["invocation_id"] = json!("f".repeat(32));
    }
    write_new(Path::new(c["output"].as_str().unwrap()), &v).unwrap();
}
#[test]
fn too_early_does_not_invoke_sampler_or_open_attempt() {
    let (_tmp, p, pb, now) = fixture();
    let called = Cell::new(false);
    let r = run(&p, &pb, now - 1, |_, _| {
        called.set(true);
        Ok(true)
    })
    .unwrap();
    assert_eq!(r["outcome"], "not-due");
    assert!(!called.get());
    assert_eq!(fs::read_dir(p.root.join("attempts")).unwrap().count(), 0);
}
#[test]
fn exact_predecessor_hash_mismatch_rejects_before_sampling() {
    let (_tmp, mut p, pb, now) = fixture();
    p.seed.sha256 = "c".repeat(64);
    assert!(run(&p, &pb, now, |_, _| panic!("must not sample")).is_err());
}
#[test]
fn crash_after_durable_sample_recovers_selector_without_second_observation() {
    let (_tmp, p, pb, now) = fixture();
    assert!(
        run(&p, &pb, now, |_, c| {
            publish(c, now, false);
            anyhow::bail!("synthetic owner crash")
        })
        .is_err()
    );
    let r = run(&p, &pb, now + 1, |_, _| {
        panic!("recovery must not resample")
    })
    .unwrap();
    assert_eq!(r["outcome"], "recovered-selector");
    assert_eq!(r["new_resource_samples"], 0);
    assert!(
        p.root
            .join("attempts/00000000000000000001/commit.json")
            .is_file()
    );
    let r = run(&p, &pb, now + 2, |_, _| panic!("new sample is not due")).unwrap();
    assert_eq!(r["outcome"], "not-due");
}
#[test]
fn concurrent_lease_cannot_sample_or_replace_journal() {
    let (_tmp, p, pb, now) = fixture();
    let _held = Lease::acquire(&p.root).unwrap();
    assert!(run(&p, &pb, now, |_, _| panic!("concurrent sample")).is_err());
}
#[test]
fn changed_owner_fails_without_selector_commit_and_cannot_be_adopted() {
    let (_tmp, p, pb, now) = fixture();
    assert!(
        run(&p, &pb, now, |_, c| {
            publish(c, now, true);
            Ok(true)
        })
        .is_err()
    );
    assert!(
        !p.root
            .join("attempts/00000000000000000001/commit.json")
            .exists()
    );
    assert!(
        run(&p, &pb, now + 1, |_, _| panic!(
            "cannot resample bad identity"
        ))
        .is_err()
    );
}
#[test]
fn partial_sample_is_preserved_and_failed_attempt_consumes_cadence() {
    let (_tmp, p, pb, now) = fixture();
    let partial = p.root.join("attempts/00000000000000000001/sample.json");
    assert!(
        run(&p, &pb, now, |_, c| {
            let v: Value = serde_json::from_slice(&stable(c, LIMIT)?).unwrap();
            fs::write(v["output"].as_str().unwrap(), b"{")?;
            anyhow::bail!("partial sample crash")
        })
        .is_err()
    );
    let r = run(&p, &pb, now + 1, |_, _| panic!("failed attempt is not due")).unwrap();
    assert_eq!(r["outcome"], "not-due");
    assert_eq!(fs::read(partial).unwrap(), b"{");
}
#[test]
fn committed_sample_cannot_be_replaced_and_duplicate_time_is_not_resampled() {
    let (_tmp, p, pb, now) = fixture();
    let r = run(&p, &pb, now, |_, c| {
        publish(c, now, false);
        Ok(true)
    })
    .unwrap();
    assert_eq!(r["new_resource_samples"], 1);
    let path = p.root.join("attempts/00000000000000000001/commit.json");
    let before = fs::read(&path).unwrap();
    assert!(write_new(&path, &json!({"replacement":true})).is_err());
    assert_eq!(
        run(&p, &pb, now, |_, _| panic!("duplicate sample")).unwrap()["outcome"],
        "not-due"
    );
    assert_eq!(fs::read(path).unwrap(), before);
}

#[test]
fn two_successful_rollovers_form_one_exact_predecessor_chain() {
    let (_tmp, p, pb, now) = fixture();
    let first = run(&p, &pb, now, |_, c| {
        publish(c, now, false);
        Ok(true)
    })
    .unwrap();
    let second = run(&p, &pb, now + 1800, |_, c| {
        publish(c, now + 1800, false);
        Ok(true)
    })
    .unwrap();
    assert_eq!(second["outcome"], "sample-committed");
    let sb: Bound = serde_json::from_value(second["sample"].clone()).unwrap();
    let sample = read(&sb).unwrap();
    assert_eq!(
        sample["cadence"]["previous_sample"],
        first["sample"]["path"]
    );
    assert_eq!(
        sample["cadence"]["previous_sample_sha256"],
        first["sample"]["sha256"]
    );
    assert_eq!(fs::read_dir(p.root.join("attempts")).unwrap().count(), 2);
}
