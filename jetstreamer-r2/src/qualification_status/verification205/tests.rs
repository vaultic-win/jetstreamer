use super::*;
#[test]
fn exact_existing_journal_proves_close_and_checkpoint_without_claiming_parent_terminal() {
    let bytes = include_bytes!("fixtures/phase-journal.jsonl");
    assert_eq!(hex_lower(&Sha256::digest(bytes)), JOURNAL_SHA);
    events(bytes, "2e60f44d8e484d7e91fcc2dc724d2ae6").unwrap();
    assert!(events(bytes, "ffffffffffffffffffffffffffffffff").is_err());
    let mut bad = bytes.to_vec();
    bad[0] = b' ';
    assert!(events(&bad, "2e60f44d8e484d7e91fcc2dc724d2ae6").is_err());
}
#[test]
fn exact_worker_absence_is_not_a_worker_sample_or_a_terminal_proof() {
    let p = profile(205).unwrap();
    let mut row = json!({"producer_unit":p.unit,"expected_producer_invocation_id":p.iid,"status":"unavailable","observation":null,
        "error":format!("expected exactly one historical-worker beneath {}/scratch, found 0",p.root),
        "ordinary_replay_claim":false,"current_sidecar_eta_valid":false,"replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false});
    unavailable(&json!({"diagnostic_replays":[row.clone()]})).unwrap();
    for (key, value) in [
        ("error", json!("permission denied")),
        ("observation", json!({"worker":"node"})),
        ("expected_producer_invocation_id", json!("f".repeat(32))),
        ("status", json!("observed")),
        ("publication_authorized", json!(true)),
    ] {
        let original = row[key].clone();
        row[key] = value;
        assert!(unavailable(&json!({"diagnostic_replays":[row.clone()]})).is_err());
        row[key] = original;
    }
}
#[test]
fn planning_eta_requires_every_positive_stage_through_the_canonical_sidecar() {
    let mut values = KEYS
        .into_iter()
        .map(|k| (k.to_string(), 1000))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(allowance(&values).unwrap(), 10_000);
    for key in KEYS {
        let value = values.remove(key).unwrap();
        assert!(allowance(&values).is_err());
        values.insert(key.into(), value);
    }
    values.insert("original_parent_verification".into(), 0);
    assert!(allowance(&values).is_err());
    values.insert("original_parent_verification".into(), u64::MAX);
    assert!(allowance(&values).is_err());
}
#[test]
fn capture_clock_is_actual_utc_and_not_the_old_resource_sample() {
    assert_eq!(utc(1792863240).unwrap(), "2026-10-24T17:34:00Z");
    assert_ne!(utc(1792863240).unwrap(), "2026-10-24T17:29:00Z");
}
