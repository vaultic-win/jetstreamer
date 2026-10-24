//! Append successful private audit history without inventing a live admission.
use super::*;
const UNIT: &str = "horizon-qualify-144-private-verification-20261021-v1.service";
const IID: &str = "0def5bbebbbc4d6aa8b7f6fe33d08365";
const ACTION: &str = "Private 144 retained prefix independently passed through 62639490; original producer and verifier are terminal and stale status was conditionally removed. Preserve validated109GBprefix. Qualify final 509 slots and exact native restart/assembly,complete epoch/full-plugin and R2 gates; no production ETA or cold prefix restart.";
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Profile {
    proof: Bound,
    prior_action_sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    proof: Bound,
    replay_launch_authorized: bool,
    publication_authorized: bool,
    r2_mutations: bool,
}
fn read(profile: &Profile) -> Result<(Bound, Bound, Value)> {
    let proof = bound_json(&profile.proof, true)?;
    ensure!(
        proof["schema"] == "jetstreamer-private-epoch144-completed-prefix-proof-v1"
            && proof["epoch"] == 144
            && proof["unit"] == UNIT
            && proof["new_resource_samples"] == 0
            && proof["prior_admission_event_accepted"] == false
            && proof["ordinary_replay_claim"] == false
            && proof["full_epoch_verified"] == false
            && proof["replay_launch_authorized"] == false
            && proof["canonical_sidecar_authorized"] == false
            && proof["publication_authorized"] == false
            && proof["r2_mutations"] == false,
        "144 completed proof grants authority or differs"
    );
    let lb: Bound = serde_json::from_value(proof["launch"].clone())?;
    let vb: Bound = serde_json::from_value(proof["validation"].clone())?;
    ensure!(
        lb.sha256 == "4fa98a81fd6025e562851de85493fc645917d9b68ee8068ec85183e78f3f9ad2"
            && vb.sha256 == "35b52ea28979dc8bc360afde41b1b71059a8451c801b71e65ebeac458c59f044",
        "144 completed lineage differs"
    );
    let launch = bound_json(&lb, true)?;
    let v = bound_json(&vb, false)?;
    ensure!(
        launch["schema"] == "jetstreamer-private-epoch144-prefix-verification-launch-v1"
            && launch["epoch"] == 144
            && launch["unit"] == UNIT
            && launch["invocation_id"] == IID
            && launch["full_epoch_verified"] == false
            && launch["publication_authorized"] == false
            && launch["replay_entries_authorized"] == false,
        "144 completed launch differs"
    );
    let c = &proof["terminal_unit"];
    ensure!(
        c["Id"] == UNIT
            && c["InvocationID"] == IID
            && c["ActiveState"] == "active"
            && c["SubState"] == "exited"
            && c["MainPID"] == "0"
            && c["NRestarts"] == "0"
            && c["Result"] == "success"
            && c["ExecMainStatus"] == "0"
            && c["Type"] == "exec"
            && c["ExecStart"]
                .as_str()
                .zip(launch["expected_exec_start"].as_str())
                .is_some_and(|(a, b)| a
                    .split_once(" ; ignore_errors=")
                    .zip(b.split_once(" ; ignore_errors="))
                    .is_some_and(|(a, b)| a.0 == b.0)),
        "144 completed unit is not exact clean terminal owner"
    );
    ensure!(
        proof["recorded_unix_seconds"]
            .as_u64()
            .zip(launch["recorded_unix_seconds"].as_u64())
            .is_some_and(|(a, b)| a >= b)
            && v["schema"] == "jetstreamer-focused-qualification-artifact-validation-v1"
            && v["validation"] == "pass"
            && v["epoch"] == 144
            && v["output_slot_start"] == 62208000
            && v["terminal_slot"] == 62639490
            && v["output_slot_count"] == 431491
            && v["canonical_checksum_sidecar_absent"] == true,
        "144 completed validation/time differs"
    );
    Ok((lb, vb, proof))
}
pub(super) fn validate(p: &Plan) -> Result<()> {
    let Some(profile) = &p.completed144_prefix else {
        return Ok(());
    };
    ensure!(
        is_101(p)?
            && p.prefix144_audit.is_none()
            && p.prefix157_audit.is_some()
            && p.runtime_handoff157.is_some()
            && !p.expected_epochs.contains(&144)
            && prefix144::writer(p),
        "foreign completed 144 profile"
    );
    ensure!(
        read(profile)?.2["recorded_unix_seconds"]
            .as_u64()
            .is_some_and(|n| n <= utc_seconds(&p.sample_target_utc).unwrap_or(0)),
        "144 completed proof is from future sample"
    );
    Ok(())
}
fn fold_history(
    f: &mut Value,
    claim: &Value,
    proof: &Bound,
    validation: &Bound,
    prior_action_sha: &str,
    transitions: &[&(Value, Value)],
) -> Result<()> {
    ensure!(
        f["admission_transition_guard"].is_null()
            || transitions
                .iter()
                .any(|(_, guard)| f["admission_transition_guard"] == *guard),
        "completed 144 cannot create/consume a live admission"
    );
    let rows = f["diagnostics"]
        .as_array_mut()
        .context("completed 144 diagnostic history")?;
    let found: Vec<_> = rows
        .iter()
        .filter(|d| d["epoch"] == 144 && !transitions.iter().any(|(claim, _)| *d == claim))
        .collect();
    ensure!(
        found.is_empty() || (found.len() == 1 && found[0] == claim),
        "completed 144 would replace another claim"
    );
    if found.is_empty() {
        rows.push(claim.clone());
    }
    let units = f["tracked_units"]
        .as_array_mut()
        .context("completed 144 tracked units")?;
    if !units.contains(&json!(UNIT)) {
        units.push(json!(UNIT));
    }
    let gate = &mut f["gates"]["144"];
    let action = gate["next_action"]
        .as_str()
        .context("completed 144 action")?;
    ensure!(
        matches!(
            gate["state"].as_str(),
            Some("blocked-qualification" | "failed-needs-repair")
        ) && (action == ACTION || sha(action.as_bytes()) == prior_action_sha),
        "completed 144 newer gate/action must not be overwritten"
    );
    gate["state"] = json!("blocked-qualification");
    gate["next_action"] = json!(ACTION);
    let evidence = gate["evidence"]
        .as_array_mut()
        .context("completed 144 gate evidence")?;
    for b in [proof, validation] {
        let value = serde_json::to_value(b)?;
        if !evidence.contains(&value) {
            evidence.push(value);
        }
    }
    Ok(())
}
#[cfg(test)]
fn fold(
    f: &mut Value,
    claim: &Value,
    proof: &Bound,
    validation: &Bound,
    prior_action_sha: &str,
    native: Option<&(Value, Value)>,
    continuation: Option<&(Value, Value)>,
) -> Result<()> {
    fold_history(
        f,
        claim,
        proof,
        validation,
        prior_action_sha,
        &native.into_iter().chain(continuation).collect::<Vec<_>>(),
    )
}
pub(super) fn derive_fleet(p: &Plan, f: &mut Value) -> Result<()> {
    let Some(profile) = &p.completed144_prefix else {
        return Ok(());
    };
    validate(p)?;
    let (lb, vb, proof) = read(profile)?;
    let launch = bound_json(&lb, true)?;
    let native = native144::completed_transition(p)?;
    let continuation = continuation144::completed_transition(p)?;
    let assembly = assembly144::completed_transition(p)?;
    let transitions: Vec<_> = native
        .iter()
        .chain(continuation.iter())
        .chain(assembly.iter())
        .collect();
    // Revalidate retained scan ownership before folding older prefix history.
    // Preserve its newer repair action; generic unknown actions still fail.
    let retained_action = assembly144_scans::retained_action(p, f)?;
    let retained_delivery = publication144::retained_gate(p, f)?;
    let mut history = f.clone();
    if retained_action.is_some() || retained_delivery.is_some() {
        history["gates"]["144"]["next_action"] = json!(ACTION);
    }
    if retained_delivery.is_some() {
        history["gates"]["144"]["state"] = json!("blocked-qualification");
    }
    fold_history(
        &mut history,
        &json!({"epoch":144,"unit":UNIT,"invocation_id":IID,"scratch_path":launch["private_run_root"],"launch_receipt":lb}),
        &profile.proof,
        &vb,
        &profile.prior_action_sha256,
        &transitions,
    )?;
    if let Some(action) = retained_action {
        history["gates"]["144"]["next_action"] = action;
    }
    if let Some((state, action)) = retained_delivery {
        history["gates"]["144"]["state"] = state;
        history["gates"]["144"]["next_action"] = action;
    }
    *f = history;
    ensure!(
        proof["prior_admission_event_accepted"] == false,
        "completed144 must not invent event acceptance"
    );
    Ok(())
}
pub(super) fn enable(next: &mut Plan, spec: &Bound) -> Result<()> {
    ensure!(
        is_101(next)?
            && next.completed144_prefix.is_none()
            && next.prefix144_audit.is_none()
            && next.prefix157_audit.is_some(),
        "completed144 requires original campaign history"
    );
    let s: Spec = serde_json::from_slice(&bound_bytes(spec, true)?)?;
    ensure!(
        s.schema == "jetstreamer-horizon-private-completed144-routine-spec-v1"
            && !s.replay_launch_authorized
            && !s.publication_authorized
            && !s.r2_mutations,
        "completed144 spec grants authority"
    );
    let template = bound_json(&next.fleet_template, true)?;
    let action = template["gates"]["144"]["next_action"]
        .as_str()
        .context("completed144 prior action")?;
    next.completed144_prefix = Some(Profile {
        proof: s.proof,
        prior_action_sha256: sha(action.as_bytes()),
    });
    next.tools.r2 = Bound {
        path: prefix144::WRITER.into(),
        sha256: prefix144::WRITER_SHA.into(),
    };
    validate(next)?;
    derive_fleet(next, &mut template.clone())?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "root exact sealed10:58 scans successor regression; read-only no sampling or remote access"]
    fn actual_scans_successor_preserves_newer_action_and_history_idempotently() {
        let pb=Bound{path:"/var/lib/jetstreamer/horizon-routine-plan-101-200-20261022T105800Z-native141-rejection-assembly144-scans-upload198-refresh-completed144-v1/cycle-plan.json".into(),sha256:"068340c662fce8b48356fa05c15d1fa0054186693db750752814d18f9d2e24b8".into()};
        let p: Plan = serde_json::from_value(bound_json(&pb, true).unwrap()).unwrap();
        let mut f = bound_json(&p.fleet_template, true).unwrap();
        let old = f.clone();
        derive_fleet(&p, &mut f).unwrap();
        assert_eq!(old, f);
        derive_fleet(&p, &mut f).unwrap();
        assert_eq!(old, f);
        f["gates"]["144"]["next_action"] = json!("unknown newer action");
        assert!(derive_fleet(&p, &mut f).is_err());
    }
    #[test]
    fn completed_prefix_keeps_all_three_exact_later_histories() {
        let b = Bound {
            path: "/proof".into(),
            sha256: "a".repeat(64),
        };
        let c = json!({"epoch":144,"unit":UNIT,"invocation_id":IID});
        let native = (
            json!({"epoch":144,"unit":"native","counter":u64::MAX}),
            json!({"guard":"native"}),
        );
        let original = (
            json!({"epoch":144,"unit":"original","counter":u64::MAX-1}),
            json!({"guard":"original"}),
        );
        let assembly = (
            json!({"epoch":144,"unit":"assembly","counter":u64::MAX-2}),
            json!({"guard":"assembly"}),
        );
        let mut f = json!({"admission_transition_guard":assembly.1,"diagnostics":[c,native.0,original.0,assembly.0],"tracked_units":[UNIT],
            "gates":{"144":{"state":"blocked-qualification","next_action":ACTION,"evidence":[]}}});
        let before = f.clone();
        fold_history(
            &mut f,
            &c,
            &b,
            &b,
            &sha(b"old"),
            &[&native, &original, &assembly],
        )
        .unwrap();
        assert_eq!(f["diagnostics"], before["diagnostics"]);
        assert_eq!(
            f["admission_transition_guard"],
            before["admission_transition_guard"]
        );
        assert!(
            fold_history(
                &mut before.clone(),
                &c,
                &b,
                &b,
                &sha(b"old"),
                &[&native, &assembly]
            )
            .is_err()
        );
    }
    #[test]
    fn completed_prefix_preserves_exact_native_and_continuation_histories() {
        let b = Bound {
            path: "/proof".into(),
            sha256: "a".repeat(64),
        };
        let claim = json!({"epoch":144,"unit":UNIT,"invocation_id":IID});
        let native = (
            json!({"epoch":144,"unit":native144::UNIT,"counter":u64::MAX}),
            json!({"native":"guard"}),
        );
        let continuation = (
            json!({"epoch":144,"unit":"continuation","counter":u64::MAX-1}),
            json!({"continuation":"guard"}),
        );
        let mut f = json!({"admission_transition_guard":continuation.1,"diagnostics":[claim,native.0,continuation.0],"tracked_units":[UNIT],"gates":{"144":{"state":"blocked-qualification","next_action":ACTION,"evidence":[]}}});
        let before = f.clone();
        fold(
            &mut f,
            &claim,
            &b,
            &b,
            &sha(b"old"),
            Some(&native),
            Some(&continuation),
        )
        .unwrap();
        assert_eq!(f["diagnostics"], before["diagnostics"]);
        assert_eq!(
            f["admission_transition_guard"],
            before["admission_transition_guard"]
        );
        assert!(
            fold(
                &mut before.clone(),
                &claim,
                &b,
                &b,
                &sha(b"old"),
                Some(&native),
                None
            )
            .is_err()
        );
        for key in ["owner", "guard", "duplicate"] {
            let mut bad = before.clone();
            match key {
                "owner" => bad["diagnostics"][2]["counter"] = json!(0),
                "guard" => bad["admission_transition_guard"] = json!({"foreign":"guard"}),
                _ => bad["diagnostics"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!({"epoch":144,"unit":"foreign"})),
            }
            assert!(
                fold(
                    &mut bad,
                    &claim,
                    &b,
                    &b,
                    &sha(b"old"),
                    Some(&native),
                    Some(&continuation)
                )
                .is_err()
            );
        }
    }
    #[test]
    fn completed_prefix_coexists_only_with_exact_bound_native_diagnostic() {
        let b = Bound {
            path: "/proof".into(),
            sha256: "a".repeat(64),
        };
        let claim = json!({"epoch":144,"unit":UNIT,"invocation_id":IID});
        let native = json!({"epoch":144,"unit":native144::UNIT,"invocation_id":"b".repeat(32)});
        let guard = json!({"path":"/real-guard","sha256":"c".repeat(64)});
        let pair = (native.clone(), guard.clone());
        let mut f = json!({"admission_transition_guard":guard,"diagnostics":[claim,native,{"epoch":157,"counter":u64::MAX}],
            "tracked_units":[UNIT],"gates":{"144":{"state":"blocked-qualification","next_action":ACTION,"evidence":[]}}});
        let before = f.clone();
        fold(&mut f, &claim, &b, &b, &sha(b"old"), Some(&pair), None).unwrap();
        assert_eq!(f["diagnostics"], before["diagnostics"]);
        assert_eq!(
            f["admission_transition_guard"],
            before["admission_transition_guard"]
        );
        assert!(fold(&mut f.clone(), &claim, &b, &b, &sha(b"old"), None, None).is_err());
        for key in ["owner", "guard", "action"] {
            let mut bad = f.clone();
            match key {
                "owner" => bad["diagnostics"][1]["invocation_id"] = json!("wrong"),
                "guard" => bad["admission_transition_guard"] = json!({"other":true}),
                _ => bad["gates"]["144"]["next_action"] = json!("newer action"),
            };
            assert!(
                fold(&mut bad, &claim, &b, &b, &sha(b"old"), Some(&pair), None).is_err(),
                "{key}"
            );
        }
    }
    #[test]
    fn completed_history_never_admits_replay_or_replaces_newer_action_or_claim() {
        let b = Bound {
            path: "/proof".into(),
            sha256: "a".repeat(64),
        };
        let claim = json!({"epoch":144,"unit":UNIT,"invocation_id":IID});
        let mut f = json!({"admission_transition_guard":null,"diagnostics":[{"epoch":157,"integer":u64::MAX}],"tracked_units":["old.service"],"gates":{"144":{"state":"blocked-qualification","next_action":"old","evidence":[]},"140":{"integer":u64::MAX}}});
        let old = f.clone();
        fold(&mut f, &claim, &b, &b, &sha(b"old"), None, None).unwrap();
        assert_eq!(f["gates"]["140"], old["gates"]["140"]);
        assert_eq!(f["diagnostics"][0], old["diagnostics"][0]);
        assert!(f["admission_transition_guard"].is_null());
        let once = f.clone();
        fold(&mut f, &claim, &b, &b, &sha(b"old"), None, None).unwrap();
        assert_eq!(f, once);
        for mutation in ["action", "claim", "admission"] {
            let mut bad = f.clone();
            match mutation {
                "action" => bad["gates"]["144"]["next_action"] = json!("newer action"),
                "claim" => bad["diagnostics"][1]["invocation_id"] = json!("replacement"),
                _ => bad["admission_transition_guard"] = json!({"live":true}),
            };
            assert!(fold(&mut bad, &claim, &b, &b, &sha(b"old"), None, None).is_err());
        }
    }
}
