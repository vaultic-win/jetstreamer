//! Source fixtures only. Synthetic native/ELF transport is never an acceptance.
use super::*;
use crate::test_support::{self as fixtures, Fixture};

fn pin(path: String, kind: &str, bytes: &[u8]) -> Pin {
    Pin {
        canonical: path.clone(),
        path,
        sha256: digest(bytes),
        kind: kind.into(),
        uid: 0,
        gid: 0,
        mode: libc::S_IFREG | 0o444,
        bytes: bytes.len() as u64,
        single_link: true,
        fixture: None,
    }
}
fn add(backend: &mut Fixture, path: String, kind: &str, bytes: Vec<u8>) -> Pin {
    let pin = pin(path, kind, &bytes);
    backend
        .files
        .insert(pin.path.clone(), fixtures::file(&pin, bytes));
    pin
}
fn guard(backend: &mut Fixture, spec: &Spec) -> GuardBinding {
    let directory = format!("/run/systemd/system/{}.d", spec.unit);
    let marker_bytes = serde_json::to_vec(&json!({"unit":spec.unit,"fixture_only":true})).unwrap();
    let marker = add(
        backend,
        format!("{directory}/{MARKER}"),
        "ConditionMarker",
        marker_bytes,
    );
    let guard = add(
        backend,
        format!("{directory}/{GUARD}"),
        "ConditionGuard",
        format!("[Unit]\nConditionPathExists=!{}\n", marker.path).into_bytes(),
    );
    let seal_bytes = serde_json::to_vec(&json!({
        "schema":"jetstreamer-sealed-deployment-receipt-v1","destination":directory,
        "sealer_sha256":SEALER,"members":[
            {"name":GUARD,"sha256":guard.sha256,"bytes":guard.bytes,"mode":"0444"},
            {"name":MARKER,"sha256":marker.sha256,"bytes":marker.bytes,"mode":"0444"}],
        "publication_authorized":false,"replay_launch_authorized":false,
        "remote_mutations":false,"r2_mutations":false}))
    .unwrap();
    let seal = add(
        backend,
        format!("{directory}/deployment-seal-receipt.json"),
        "GuardDeploymentSeal",
        seal_bytes,
    );
    let sums_bytes = format!(
        "{}  {GUARD}\n{}  deployment-seal-receipt.json\n{}  {MARKER}\n",
        guard.sha256, seal.sha256, marker.sha256
    )
    .into_bytes();
    let sums = add(
        backend,
        format!("{directory}/SHA256SUMS"),
        "GuardSHA256SUMS",
        sums_bytes,
    );
    GuardBinding {
        guard,
        marker,
        seal,
        sums,
    }
}
fn setup() -> (Fixture, ReviewBinding, Vec<Spec>) {
    let (mut backend, _, original) = fixtures::condition_blocked_setup();
    let legacy: super::super::Review =
        serde_json::from_slice(&backend.files[super::super::REVIEW].bytes).unwrap();
    let mut rows = Vec::new();
    for (spec, old) in original.iter().zip(legacy.rows) {
        let guarded = guard(&mut backend, spec);
        let potential_bytes = serde_json::to_vec(&json!({
            "schema":"horizon-old220-peer1060-potential-declared-inputs-v1",
            "unit":spec.unit,"role":spec.role,"original_specs_sha256":digest(SPEC_BYTES),
            "original_spec_sha256":digest(&serde_json::to_vec(spec).unwrap()),
            "selected_owner":OWNER,"selected_epoch":220,"selected_inodes":[20581075u64,20582466u64],
            "scope":"fixed-declared-program-inputs-with-unqualified-historical-loader",
            "application_review":"Clearly synthetic fixture for original declared-source binding only.",
            "unresolved_historical_loader_inputs":["fixture; no native loader witness"],
            "historical_loader_execution_qualified":false,"data_retirement_authorized":false,
            "global_alias_closure_qualified":false})).unwrap();
        let potential = add(
            &mut backend,
            format!(
                "/var/lib/jetstreamer/horizon-old220-peers1060-fixture/{}.json",
                spec.unit
            ),
            "PotentialProgramReview",
            potential_bytes,
        );
        let current = guarded_spec(spec, &guarded).unwrap();
        fixtures::native(&mut backend, &current, &old.origin.original_iid);
        for root in ROOTS {
            let dir = format!("{root}/{}.d", spec.unit);
            let mut expected = spec
                .dropins
                .iter()
                .filter(|p| Path::new(&p.path).parent() == Some(Path::new(&dir)))
                .map(|p| {
                    Path::new(&p.path)
                        .file_name()
                        .unwrap()
                        .to_string_lossy()
                        .into_owned()
                })
                .collect::<Vec<_>>();
            if root == "/run/systemd/system" {
                expected.extend(
                    [GUARD, MARKER, "deployment-seal-receipt.json", "SHA256SUMS"]
                        .into_iter()
                        .map(str::to_owned),
                );
            }
            if !expected.is_empty() {
                backend.directories.insert(dir, expected);
            }
        }
        rows.push(Row {
            unit: spec.unit.clone(),
            role: spec.role.clone(),
            origin: old.origin,
            bootstrap_interpreter: old.bootstrap_interpreter,
            potential_program_review: potential,
            condition_blocked_guard: guarded,
            historical_loader_execution_qualified: false,
        });
    }
    let review = Review {
        schema: REVIEW_SCHEMA.into(),
        scope: SCOPE.into(),
        source_specs_sha256: digest(SPEC_BYTES),
        selected_owner: OWNER.into(),
        selected_epoch: 220,
        selected_inodes: vec![20581075, 20582466],
        rows,
        data_retirement_authorized: false,
        global_alias_closure_qualified: false,
        historical_loader_execution_qualified: false,
    };
    let bytes = serde_json::to_vec(&review).unwrap();
    let p = add(&mut backend, REVIEW.into(), "RootReview", bytes);
    (
        backend,
        ReviewBinding {
            sha256: p.sha256,
            bytes: p.bytes,
        },
        original,
    )
}
fn rewrite(backend: &mut Fixture, binding: &mut ReviewBinding, change: impl FnOnce(&mut Value)) {
    let mut review: Value = serde_json::from_slice(&backend.files[REVIEW].bytes).unwrap();
    change(&mut review);
    let p = add(
        backend,
        REVIEW.into(),
        "RootReview",
        serde_json::to_vec(&review).unwrap(),
    );
    binding.sha256 = p.sha256;
    binding.bytes = p.bytes;
}
#[test]
fn exact_five_guarded_capture_and_full_native_summary_replay_remain_non_authoritative() {
    let (mut backend, binding, specs) = setup();
    let proof = capture_condition_blocked_specs(&mut backend, &binding, "", &specs).unwrap();
    let summary = proof.summary();
    assert_eq!(summary["schema"], SUMMARY_SCHEMA);
    assert_eq!(
        summary["currently_admitted_selected_cache_reads"],
        json!([])
    );
    assert_eq!(summary["historical_loader_execution_qualified"], false);
    assert_eq!(summary["global_alias_closure_qualified"], false);
    assert_eq!(summary["data_retirement_authorized"], false);
    proof.validate_predecessor_summary(&summary).unwrap();
    // Adding guards never loses the bootstrap's original60/70 bindings.
    assert_eq!(proof.inner.specs[4].dropins.len(), 3);
    assert_eq!(
        &proof.inner.specs[4].dropins[..2]
            .iter()
            .map(|p| p.path.clone())
            .collect::<Vec<_>>(),
        &specs[4]
            .dropins
            .iter()
            .map(|p| p.path.clone())
            .collect::<Vec<_>>()
    );
}
#[test]
fn review_rejects_overclaims_roster_substitution_wrong_order_and_selection() {
    for field in 0..7 {
        let (mut backend, mut binding, specs) = setup();
        rewrite(&mut backend, &mut binding, |v| match field {
            0 => v["historical_loader_execution_qualified"] = true.into(),
            1 => v["global_alias_closure_qualified"] = true.into(),
            2 => v["data_retirement_authorized"] = true.into(),
            3 => v["rows"].as_array_mut().unwrap().swap(0, 1),
            4 => v["selected_inodes"][0] = 0.into(),
            5 => v["scope"] = "complete-dynamic-loader-readset".into(),
            _ => v["rows"][0]["unit"] = "foreign.service".into(),
        });
        assert!(capture_condition_blocked_specs(&mut backend, &binding, "", &specs).is_err());
    }
}
#[test]
fn guard_bytes_markers_seals_rosters_and_all_command_hooks_remain_mandatory() {
    for field in 0..7 {
        let (mut backend, binding, specs) = setup();
        let review: Review = serde_json::from_slice(&backend.files[REVIEW].bytes).unwrap();
        let g = &review.rows[0].condition_blocked_guard;
        match field {
            0 => {
                backend.files.remove(&g.marker.path);
            }
            1 => {
                backend
                    .files
                    .get_mut(&g.guard.path)
                    .unwrap()
                    .bytes
                    .extend(b"ConditionPathExists=\n");
            }
            2 => {
                backend.files.get_mut(&g.seal.path).unwrap().named.ino += 1;
            }
            3 => {
                backend
                    .directories
                    .get_mut(&format!("/run/systemd/system/{}.d", specs[0].unit))
                    .unwrap()
                    .push("unexpected.conf".into());
            }
            4 => {
                let q = bus(
                    &specs[0].unit,
                    "org.freedesktop.systemd1.Unit",
                    "Conditions",
                );
                backend.answers.get_mut(&fixtures::key(&q)).unwrap().stdout =
                    json!({"type":"a(sbbsi)","data":[]}).to_string();
            }
            5 => {
                let q = show(&specs[0].unit);
                let reply = backend.answers.get_mut(&fixtures::key(&q)).unwrap();
                reply.stdout = reply.stdout.replace("MainPID=0", "MainPID=42");
            }
            _ => {
                let q = bus(
                    &specs[0].unit,
                    "org.freedesktop.systemd1.Service",
                    "ExecStopPost",
                );
                backend.answers.get_mut(&fixtures::key(&q)).unwrap().stdout=
                    json!({"type":"a(sasbttttuii)","data":[["/foreign",["/foreign"],false,0,0,0,0,0,0,0]]}).to_string();
            }
        }
        assert!(
            capture_condition_blocked_specs(&mut backend, &binding, "", &specs).is_err(),
            "{field}"
        );
    }
}
#[test]
fn guarded_predecessor_rejects_changed_guard_scope_and_complete_raw_native_envelope() {
    let (mut backend, binding, specs) = setup();
    let proof = capture_condition_blocked_specs(&mut backend, &binding, "", &specs).unwrap();
    for field in 0..5 {
        let mut value = proof.summary();
        match field {
            0 => {
                value["condition_blocked_guards"][0]["condition_blocked_guard"]["marker"]
                    ["sha256"] = "0".repeat(64).into()
            }
            1 => value["currently_admitted_selected_cache_reads"] = json!(["foreign"]),
            2 => value["historical_loader_execution_qualified"] = true.into(),
            3 => value["rows"][0]["native_raw_evidence"][0]["stdout"] = "altered".into(),
            _ => {
                value
                    .as_object_mut()
                    .unwrap()
                    .insert("arbitrary_waiver".into(), true.into());
            }
        }
        assert!(proof.validate_predecessor_summary(&value).is_err());
    }
}
#[test]
fn source_requirements_and_captured_summary_do_not_register_an_image_pair() {
    let requirements = condition_blocked_requirements().unwrap();
    assert_eq!(requirements["data_retirement_authorized"], false);
    assert_eq!(requirements["global_alias_closure_qualified"], false);
    assert_eq!(requirements["historical_loader_execution_qualified"], false);
    let (mut backend, binding, specs) = setup();
    assert!(
        capture_condition_blocked_specs(&mut backend, &binding, &specs[0].unit, &specs).is_err()
    );
    // Original semantics and its review schema remain separately fail-closed.
    assert!(super::super::capture(&mut backend, &binding, "").is_err());
}
