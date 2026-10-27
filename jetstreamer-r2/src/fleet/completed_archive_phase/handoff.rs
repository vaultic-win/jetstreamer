//! Explicit phase-launcher transition; every non-launcher delivery gate is fixed.
use super::*;
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Transition {
    schema: String,
    full_terminal: BoundFile,
    from: Program,
    to: Program,
}
pub(super) fn core(prior: &Spec, next: &Spec) -> Result<()> {
    let a = serde_json::to_value(prior)?;
    let b = serde_json::to_value(next)?;
    for key in [
        "epoch",
        "origin",
        "tools",
        "decoder_capacity",
        "units",
        "guard_units",
        "state_root",
        "r2_receipt_directory",
        "upload_lock",
    ] {
        ensure!(
            a[key] == b[key],
            "completed209 handoff changed delivery core: {key}"
        );
    }
    let mut left = prior.programs.clone();
    let mut right = next.programs.clone();
    left.remove("launcher");
    right.remove("launcher");
    ensure!(
        serde_json::to_value(left)? == serde_json::to_value(right)?,
        "completed209 handoff changed a verifier, guard, script or uploader"
    );
    Ok(())
}
pub(super) fn validate(s: &Spec) -> Result<()> {
    if let Some(t) = &s.launcher_transition {
        transition_scope(s, t)?;
        let old = if s.epoch == 207 {
            original_full207(s, t)?
        } else {
            let proof = read(&t.full_terminal)?;
            terminal::validate(&proof)?.0
        };
        ensure!(
            old.phase == Phase::Full
                && old.launcher_transition.is_none()
                && serde_json::to_value(&t.from)?
                    == serde_json::to_value(&old.programs["launcher"])?,
            "completed209 transition changed its genuine original Full launcher"
        );
        core(&old, s)?;
        program(&t.from)?;
        program(&t.to)?;
    }
    Ok(())
}
fn transition_scope(s: &Spec, t: &Transition) -> Result<()> {
    ensure!(
        ((t.schema == "jetstreamer-completed209-phase-launcher-transition-v1" && s.epoch == 209)
            || (t.schema == "jetstreamer-completed207-phase-launcher-transition-v1"
                && s.epoch == 207))
            && matches!(s.phase, Phase::Plugin | Phase::Upload)
            && serde_json::to_value(&t.to)? == serde_json::to_value(&s.programs["launcher"])?
            && t.from.artifact.sha256 != t.to.artifact.sha256,
        "completed phase launcher transition scope differs"
    );
    Ok(())
}
fn full207_evidence_scope(next: &Spec, t: &Transition, proof: &Value) -> Result<BoundFile> {
    // This supplement identifies the already captured successful Full 207.
    // It does not replace the predecessor's current terminal and receipt checks.
    ensure!(
        t.full_terminal.path
            == Path::new(
                "/var/lib/jetstreamer/horizon-generic207-full-natural-terminal-cycle465-v1/terminal.json"
            )
            && t.full_terminal.sha256
                == "f89592971988cdbba68190b987b49c38edcdf5fd4aa12bb45e211f64b1a840f5",
        "completed207 transition changed its natural Full terminal supplement"
    );
    let captured_binding = BoundFile {
        path:
            "/var/lib/jetstreamer/horizon-generic207-full-capture-cycle462-808f4683-v1/launch.json"
                .into(),
        sha256: "daea3e40d63826e74a5e5538d849e51dffbd1020d64636964abd70b13126a725".into(),
    };
    ensure!(
        proof["schema"] == "horizon207-full-natural-terminal-evidence-v1"
            && proof["epoch"] == 207
            && proof["phase"] == "full-verification"
            && proof["original_invocation_id"] == "b02e0a3a4bdf4255955cc7436610929e"
            && proof["launch"] == private157::binding(&captured_binding)
            && proof["no_phase_promotion_or_R2_authority"] == true
            && next
                .prior
                .iter()
                .any(|p| p.phase == Phase::Full && p.launch == captured_binding),
        "completed207 transition lacks its exact original Full predecessor"
    );
    Ok(captured_binding)
}
fn original_full207(next: &Spec, t: &Transition) -> Result<Spec> {
    let proof = read(&t.full_terminal)?;
    let captured_binding = full207_evidence_scope(next, t, &proof)?;
    let captured = read(&captured_binding)?;
    let old_binding: BoundFile = serde_json::from_value(captured["phase_spec"].clone())?;
    let old: Spec = serde_json::from_value(read(&old_binding)?)?;
    shape(&old)?;
    ensure!(
        old.epoch == 207
            && old.phase == Phase::Full
            && old.launcher_transition.is_none()
            && captured["invocation_id"] == proof["original_invocation_id"]
            && t.from.artifact.sha256
                == "e697f8505c5908c2e71a5cc1cfe365aefe91f15f04e57bf2a1db2dcb1e77f318"
            && serde_json::to_value(&t.from)? == serde_json::to_value(&old.programs["launcher"])?,
        "completed207 transition changed its genuine original Full launcher"
    );
    launch::validate_saved(&captured, &old, Phase::Full, &t.from.artifact.sha256)?;
    core(&old, next)?;
    Ok(old)
}
pub(super) fn programs_match(prior: &Spec, next: &Spec) -> Result<()> {
    if serde_json::to_value(&prior.programs)? == serde_json::to_value(&next.programs)? {
        return Ok(());
    }
    ensure!(
        next.launcher_transition.is_some(),
        "completed phase launcher changed without an authenticated transition"
    );
    validate(next)?;
    let t = next
        .launcher_transition
        .as_ref()
        .context("completed209 transition absent")?;
    let launcher = serde_json::to_value(&prior.programs["launcher"])?;
    ensure!(
        launcher == serde_json::to_value(&t.from)? || launcher == serde_json::to_value(&t.to)?,
        "completed209 prior launcher is neither authenticated transition endpoint"
    );
    core(prior, next)
}
pub(super) fn full_terminal(s: &Spec) -> Option<&BoundFile> {
    s.launcher_transition.as_ref().map(|t| &t.full_terminal)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn completed209_launcher_handoff_preserves_all_nonlauncher_core_and_tool_gates() {
        let old = super::super::tests::fixture(Phase::Full);
        let mut next = old.clone();
        next.phase = Phase::Plugin;
        next.programs.get_mut("launcher").unwrap().artifact.sha256 = "b".repeat(64);
        core(&old, &next).unwrap();
        assert!(programs_match(&old, &next).is_err());
        for key in ["full", "plugin", "boundary", "progressive", "guard"] {
            let mut bad = next.clone();
            bad.programs.get_mut(key).unwrap().artifact.sha256 = "c".repeat(64);
            assert!(core(&old, &bad).is_err(), "{key}");
        }
        let mut bad = next.clone();
        bad.tools.get_mut("plugin").unwrap().artifact.sha256 = "c".repeat(64);
        assert!(core(&old, &bad).is_err());
        let mut bad = next.clone();
        bad.units.insert("full".into(), "foreign.service".into());
        assert!(core(&old, &bad).is_err());
        let mut bad = next;
        bad.state_root = "/private/replaced".into();
        assert!(core(&old, &bad).is_err());
    }
    #[test]
    fn completed209_optional_launcher_transition_preserves_original_sealed_spec_serialization() {
        let old = super::super::tests::fixture(Phase::Full);
        assert!(
            serde_json::to_value(old)
                .unwrap()
                .get("launcher_transition")
                .is_none()
        );
        let b = json!({"path":"/sealed/binary","sha256":"a".repeat(64)});
        let mut t = json!({"schema":"jetstreamer-completed209-phase-launcher-transition-v1","full_terminal":b,
            "from":{"artifact":b,"deployment_seal":b},"to":{"artifact":b,"deployment_seal":b}});
        assert!(serde_json::from_value::<Transition>(t.clone()).is_ok());
        t["skip_core_equality"] = json!(true);
        assert!(serde_json::from_value::<Transition>(t).is_err());
    }
    #[test]
    fn completed207_launcher_transition_requires_exact_original_full_evidence_and_prior() {
        let mut next = super::super::tests::fixture(Phase::Plugin);
        next.epoch = 207;
        let captured = BoundFile {
            path: "/var/lib/jetstreamer/horizon-generic207-full-capture-cycle462-808f4683-v1/launch.json".into(),
            sha256: "daea3e40d63826e74a5e5538d849e51dffbd1020d64636964abd70b13126a725".into(),
        };
        next.prior[0].launch = captured.clone();
        let mut from = next.programs["launcher"].clone();
        from.artifact.sha256 =
            "e697f8505c5908c2e71a5cc1cfe365aefe91f15f04e57bf2a1db2dcb1e77f318".into();
        let t = Transition {
            schema: "jetstreamer-completed207-phase-launcher-transition-v1".into(),
            full_terminal: BoundFile {
                path: "/var/lib/jetstreamer/horizon-generic207-full-natural-terminal-cycle465-v1/terminal.json".into(),
                sha256: "f89592971988cdbba68190b987b49c38edcdf5fd4aa12bb45e211f64b1a840f5".into(),
            },
            from,
            to: next.programs["launcher"].clone(),
        };
        let proof = json!({"schema":"horizon207-full-natural-terminal-evidence-v1","epoch":207,"phase":"full-verification",
            "original_invocation_id":"b02e0a3a4bdf4255955cc7436610929e","launch":private157::binding(&captured),
            "no_phase_promotion_or_R2_authority":true});
        transition_scope(&next, &t).unwrap();
        assert_eq!(full207_evidence_scope(&next, &t, &proof).unwrap(), captured);
        for (key, value) in [
            (
                "schema",
                json!("jetstreamer-completed209-phase-terminal-v1"),
            ),
            ("epoch", json!(209)),
            ("phase", json!("plugin-verification")),
            ("original_invocation_id", json!("a".repeat(32))),
            (
                "launch",
                json!({"path":"/sealed/foreign.json","sha256":"a".repeat(64)}),
            ),
            ("no_phase_promotion_or_R2_authority", json!(false)),
        ] {
            let mut bad = proof.clone();
            bad[key] = value;
            assert!(full207_evidence_scope(&next, &t, &bad).is_err(), "{key}");
        }
        let mut bad = next.clone();
        bad.prior.clear();
        assert!(full207_evidence_scope(&bad, &t, &proof).is_err());
        let mut bad = t.clone();
        bad.full_terminal.sha256 = "b".repeat(64);
        assert!(full207_evidence_scope(&next, &bad, &proof).is_err());
        bad = t.clone();
        bad.full_terminal.path = "/var/lib/jetstreamer/foreign/terminal.json".into();
        assert!(full207_evidence_scope(&next, &bad, &proof).is_err());
        for epoch in [206, 208, 209] {
            let mut bad = next.clone();
            bad.epoch = epoch;
            assert!(transition_scope(&bad, &t).is_err());
        }
        let mut bad = next.clone();
        bad.phase = Phase::Full;
        assert!(transition_scope(&bad, &t).is_err());
        let mut bad = t.clone();
        bad.schema = "jetstreamer-completed209-phase-launcher-transition-v1".into();
        assert!(transition_scope(&next, &bad).is_err());
        bad = t.clone();
        bad.from = bad.to.clone();
        assert!(transition_scope(&next, &bad).is_err());
        bad = t;
        bad.to.artifact.sha256 = "c".repeat(64);
        assert!(transition_scope(&next, &bad).is_err());
    }
}
