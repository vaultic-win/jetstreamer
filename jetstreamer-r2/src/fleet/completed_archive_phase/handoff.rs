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
        ensure!(
            t.schema == "jetstreamer-completed209-phase-launcher-transition-v1"
                && s.epoch == 209
                && matches!(s.phase, Phase::Plugin | Phase::Upload)
                && serde_json::to_value(&t.to)? == serde_json::to_value(&s.programs["launcher"])?
                && t.from.artifact.sha256 != t.to.artifact.sha256,
            "completed209 launcher transition scope differs"
        );
        let proof = read(&t.full_terminal)?;
        let (old, _) = terminal::validate(&proof)?;
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
}
