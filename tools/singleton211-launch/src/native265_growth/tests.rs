use super::*;
const BOOT: &str = "3b17d005-5c3a-4a0e-8841-da097e0957b5";
const SHA: &str = pins::HELPER_SHA;
fn row() -> capacity::Reservation {
    capacity::Reservation {
        unit: OLD_UNIT.into(),
        invocation_id: OLD_IID.into(),
        maximum_memory_bytes: 128_000_000_000,
        remaining_disk_growth_bytes: OLD_GROWTH,
        minimum_free_bytes: 3_216_541_534_488,
        source: Bound::new("/source", SHA),
        release: None,
    }
}
fn deny(mut v: Value) -> Value {
    deny_authority(&mut v);
    v
}
fn fixture() -> (Value, Bound, BTreeMap<PathBuf, Value>) {
    let terminal: Value =
        serde_json::from_str(include_str!("fixtures/original-terminal.json")).unwrap();
    assert_eq!(
        digest(include_bytes!("fixtures/original-terminal.json")),
        TERMINAL_SHA
    );
    let tr = Bound::new(TERMINAL, TERMINAL_SHA);
    let qr = Bound::new(pins::QUALIFICATION_PATH, pins::QUALIFICATION_SHA);
    let sr = Bound::new(pins::SEAL_PATH, pins::SEAL_SHA);
    let pr = Bound::new("/plan", SHA);
    let br = Bound::new("/booking", SHA);
    let cr = Bound::new(Path::new(STATE).join("check.json"), SHA);
    let ir = Bound::new(Path::new(STATE).join("intent.json"), SHA);
    let rr = Bound::new(Path::new(STATE).join("completion.json"), SHA);
    let ar = Bound::new(Path::new(STATE).join("absence-v1.json"), SHA);
    let qualification: Value =
        serde_json::from_str(include_str!("fixtures/source-qualification.json")).unwrap();
    let seal: Value = serde_json::from_str(include_str!("fixtures/deployment-seal.json")).unwrap();
    assert_eq!(
        digest(include_bytes!("fixtures/source-qualification.json")),
        pins::QUALIFICATION_SHA
    );
    assert_eq!(
        digest(include_bytes!("fixtures/deployment-seal.json")),
        pins::SEAL_SHA
    );
    let plan = json!({"schema":"horizon-native265-empty-scratch-retirement-plan-v1","main_accepted":true,
        "exclusive_campaign_mutation_owner":true,"no_staged_scratch_consumers_confirmed":true});
    let clock = num(&seal, "created_unix_seconds").unwrap() + 10;
    let booking = json!({"schema":"horizon-native265-runtime-retirement-booking-v1","Main_accepted":true,
        "plan":pr,"maximum_memory_bytes":268435456,"maximum_metadata_bytes":16777216,
        "maximum_wall_seconds":120,"future_growth_credit_taken_bytes":0,
        "recorded_unix_seconds":clock,"expires_unix_seconds":clock+600});
    let proofs = json!({"terminal_proof":tr,"original_evidence":terminal,"input_packet":{}});
    let mut base = json!({"recorded_unix_seconds":clock+1,"plan":pr,"helper_sha256":SHA,"booking":br,
        "preserved":{"sentinel_sha256":"original-sentinel"},"terminal":terminal["terminal_manager"],
        "replay_launch_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false});
    let mut check = base.clone();
    check["schema"] = json!("horizon-native265-empty-scratch-retirement-check-v1");
    check["proofs"] = proofs.clone();
    check["scratch"] = json!({"inode":95092622});
    check["scratch_already_empty"] = json!(true);
    check["retirement_performed"] = json!(false);
    check["resource_release_authorized"] = json!(false);
    let mut intent = base.clone();
    intent["schema"] = json!("horizon-native265-empty-scratch-retirement-intent-v1");
    intent["check"] = json!(cr);
    intent["scratch"] = check["scratch"].clone();
    intent["only_empty_scratch_directory_removal_authorized"] = json!(true);
    intent["resource_release_authorized"] = json!(false);
    base["memory_release_authorized"] = json!(false);
    base["future_growth_release_authorized"] = json!(false);
    base["physical_reclamation_credit_bytes"] = json!(0);
    base["scratch_absent"] = json!(true);
    let mut complete = base.clone();
    complete["schema"] = json!("horizon-native265-empty-scratch-retirement-completion-v1");
    complete["check"] = json!(cr);
    complete["intent"] = json!(ir);
    complete["proofs"] = proofs;
    complete["unit"] = json!(OLD_UNIT);
    complete["invocation_id"] = json!(OLD_IID);
    complete["retired_paths"] = json!([format!("{OLD_ROOT}/scratch")]);
    for k in [
        "scratch_was_already_empty",
        "ledger_tmp_result_stderr_and_input_cache_preserved",
        "original_root_preserved",
        "live_v3_not_read_or_changed",
    ] {
        complete[k] = json!(true);
    }
    let mut absence = base;
    absence["schema"] = json!("horizon-native265-empty-scratch-absence-v1");
    absence["completion"] = json!(rr);
    let release = deny(
        json!({"schema":"horizon-native265-retired-runtime-growth-release-v1","Main_accepted":true,
        "unit":OLD_UNIT,"invocation_id":OLD_IID,"boot_id":BOOT,"recorded_unix_seconds":clock+2,
        "original_remaining_disk_growth_bytes":OLD_GROWTH,"remaining_future_growth_bytes":0,
        "released_memory_bytes":0,"physical_allocation_credit_bytes":0,"inherited_floor_credit_bytes":0,
        "original_reservation_source":row().source,"terminal_proof":tr,"retirement_qualification":qr,
        "retirement_check":cr,"retirement_intent":ir,"retirement_completion":rr,"retirement_absence":ar,"retirement_deployment_seal":sr}),
    );
    let mut docs = BTreeMap::from([
        (tr.path, terminal.clone()),
        (qr.path.clone(), qualification),
        (pr.path, plan),
        (br.path, booking),
        (cr.path, check),
        (ir.path, intent),
        (rr.path, complete),
        (ar.path, absence),
        (sr.path, seal),
    ]);
    for k in [
        "native_result",
        "guard_history",
        "startup_handoff",
        "capture_spec",
        "consumer_transition",
    ] {
        docs.insert(binding(&terminal[k]).unwrap().path, json!({}));
    }
    (release, qr, docs)
}
fn accepted(v: &Value, q: &Bound, docs: &BTreeMap<PathBuf, Value>) -> Result<Value> {
    graph(v, BOOT, SHA, q, |b| {
        docs.get(&b.path).cloned().context("missing document")
    })
}
#[test]
fn exact_scratch_only_graph_requires_original_intent_and_preserved_sentinel() {
    let (v, q, docs) = fixture();
    scope(&v, &[row()]).unwrap();
    accepted(&v, &q, &docs).unwrap();
    for (leaf, pointer, bad) in [
        ("check.json", "/scratch_already_empty", json!(false)),
        (
            "intent.json",
            "/only_empty_scratch_directory_removal_authorized",
            json!(false),
        ),
        ("intent.json", "/check/sha256", json!("b".repeat(64))),
        ("intent.json", "/scratch/inode", json!(123)),
        ("completion.json", "/intent/sha256", json!("b".repeat(64))),
        (
            "completion.json",
            "/retired_paths",
            json!([format!("{OLD_ROOT}/scratch"), format!("{OLD_ROOT}/ledger")]),
        ),
        (
            "completion.json",
            "/preserved/sentinel_sha256",
            json!("replacement"),
        ),
        (
            "completion.json",
            "/physical_reclamation_credit_bytes",
            json!(4096),
        ),
        ("completion.json", "/memory_release_authorized", json!(true)),
        (
            "completion.json",
            "/future_growth_release_authorized",
            json!(true),
        ),
        (
            "completion.json",
            "/proofs/original_evidence/invocation_id",
            json!("b".repeat(32)),
        ),
        (
            "absence-v1.json",
            "/completion/sha256",
            json!("b".repeat(64)),
        ),
        ("absence-v1.json", "/scratch_absent", json!(false)),
        ("absence-v1.json", "/terminal/MainPID", json!("42")),
    ] {
        let mut changed = docs.clone();
        *changed
            .get_mut(&Path::new(STATE).join(leaf))
            .unwrap()
            .pointer_mut(pointer)
            .unwrap() = bad;
        assert!(accepted(&v, &q, &changed).is_err(), "{leaf} {pointer}");
    }
}
#[test]
fn wrong_boot_qualification_booking_and_missing_evidence_are_rejected() {
    let (v, q, docs) = fixture();
    assert!(
        graph(&v, "other-boot", SHA, &q, |b| docs
            .get(&b.path)
            .cloned()
            .context("missing"))
        .is_err()
    );
    assert!(
        graph(&v, BOOT, "UNQUALIFIED", &q, |b| docs
            .get(&b.path)
            .cloned()
            .context("missing"))
        .is_err()
    );
    for (path, pointer, bad) in [
        (
            pins::QUALIFICATION_PATH,
            "/image_sha256",
            json!("b".repeat(64)),
        ),
        (pins::QUALIFICATION_PATH, "/tests_passed", json!(11)),
        (
            pins::QUALIFICATION_PATH,
            "/strict_all_target_clippy",
            json!(false),
        ),
        (pins::SEAL_PATH, "/members/0/sha256", json!("b".repeat(64))),
        ("/booking", "/future_growth_credit_taken_bytes", json!(1)),
        ("/booking", "/expires_unix_seconds", json!(0)),
        (
            "/plan",
            "/no_staged_scratch_consumers_confirmed",
            json!(false),
        ),
    ] {
        let mut changed = docs.clone();
        *changed
            .get_mut(Path::new(path))
            .unwrap()
            .pointer_mut(pointer)
            .unwrap() = bad;
        assert!(accepted(&v, &q, &changed).is_err(), "{path} {pointer}");
    }
    for path in docs.keys() {
        let mut changed = docs.clone();
        changed.remove(path);
        assert!(accepted(&v, &q, &changed).is_err(), "{}", path.display());
    }
}
#[test]
fn growth_transition_cannot_alter_original_rows_memory_live_v3_or_inherited_floors() {
    let (v, _, _) = fixture();
    let mut live = row();
    live.unit = "horizon-265-replacement-20261119-v3.service".into();
    live.invocation_id = "182de64d33674f95b7758d410eb1812b".into();
    live.minimum_free_bytes = 3_908_104_436_088;
    let mut retained = row();
    retained.unit = "retained-other.service".into();
    retained.remaining_disk_growth_bytes = 3_121_330_840_160;
    let rows = vec![row(), live, retained];
    let original = serde_json::to_value(&rows).unwrap();
    let copy = effective(&rows, scope(&v, &rows).unwrap());
    assert_eq!(serde_json::to_value(&rows).unwrap(), original);
    let mut expected = original;
    expected[0]["remaining_disk_growth_bytes"] = json!(0);
    assert_eq!(serde_json::to_value(&copy).unwrap(), expected);
    let before = capacity::arithmetic(
        u64::MAX,
        u64::MAX,
        u64::MAX,
        280_581_611_288,
        &rows,
        &BTreeMap::new(),
        (0, 0),
    )
    .unwrap();
    let after = capacity::arithmetic(
        u64::MAX,
        u64::MAX,
        u64::MAX,
        280_581_611_288,
        &copy,
        &BTreeMap::new(),
        (0, 0),
    )
    .unwrap();
    assert_eq!(
        before["memory_obligation_after_bytes"],
        after["memory_obligation_after_bytes"]
    );
    assert_eq!(
        before["remaining_hard_growth_bytes"],
        after["remaining_hard_growth_bytes"]
    );
    assert_eq!(
        num(&before, "retained_disk_growth_bytes").unwrap()
            - num(&after, "retained_disk_growth_bytes").unwrap(),
        OLD_GROWTH
    );
    assert_eq!(
        after["protected_existing_floor_bytes"],
        3_908_104_436_088u64
    );
    assert_eq!(after["allocation_credit_taken_bytes"], 0);
    for field in [
        "released_memory_bytes",
        "physical_allocation_credit_bytes",
        "inherited_floor_credit_bytes",
    ] {
        let mut changed = v.clone();
        changed[field] = json!(1);
        assert!(scope(&changed, &rows).is_err());
    }
    assert!(scope(&v, &[]).is_err());
    assert!(scope(&v, &[row(), row()]).is_err());
    for field in [
        "maximum_memory_bytes",
        "remaining_disk_growth_bytes",
        "minimum_free_bytes",
    ] {
        let mut changed = serde_json::to_value(row()).unwrap();
        changed[field] = json!(1);
        assert!(scope(&v, &[serde_json::from_value(changed).unwrap()]).is_err());
    }
    let mut released = row();
    released.release = Some(Bound::new("/release", SHA));
    assert!(scope(&v, &[released]).is_err());
}
