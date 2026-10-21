//! Fold one exact private144 reread event without changing replay/ETA semantics.
use super::*;
pub(super) const WRITER: &str =
    "/usr/local/lib/jetstreamer/horizon-epoch144-prefix-fleet-reader-20261021-v3/jetstreamer-r2";
pub(super) const WRITER_SHA: &str =
    "54e7d485b67964595a2326c7f7c3213b65a1bd4228cfe2b7cfaf6aec5f82dea7";
pub(super) const DELIVERY_WRITER: &str =
    "/usr/local/lib/jetstreamer/horizon-epoch198-skipped-tail-reader-20261021-v3/jetstreamer-r2";
pub(super) const DELIVERY_WRITER_SHA: &str =
    "992d06b9f4b76bd4beecfd9be9572f780131e0c57e1f5618aebaf9fb362dc398";
pub(super) const RECOVERY_WRITER: &str =
    "/usr/local/lib/jetstreamer/horizon-epoch198-start-clock-reader-20261021-v1/jetstreamer-r2";
pub(super) const RECOVERY_WRITER_SHA: &str =
    "f67c0a9e9390400e79c9b6f1f37969225a92cfeceafa8fde28e8c68ffeea26c6";
const UNIT: &str = "horizon-qualify-144-private-verification-20261021-v1.service";
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Profile {
    launch: Bound,
    admission_fleet: Bound,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    launch: Bound,
    event_fleet: Bound,
    event_plan: Bound,
    replay_launch_authorized: bool,
    publication_authorized: bool,
    r2_mutations: bool,
}
pub(super) fn writer(p: &Plan) -> bool {
    (p.prefix144_audit.is_some() || p.completed144_prefix.is_some())
        && ((p.tools.r2.path == Path::new(WRITER) && p.tools.r2.sha256 == WRITER_SHA)
            || (p.epoch198_delivery.is_some()
                && ((p.tools.r2.path == Path::new(DELIVERY_WRITER)
                    && p.tools.r2.sha256 == DELIVERY_WRITER_SHA)
                    || (p.tools.r2.path == Path::new(RECOVERY_WRITER)
                        && p.tools.r2.sha256 == RECOVERY_WRITER_SHA))))
}
pub(super) fn validate(p: &Plan) -> Result<()> {
    let Some(profile) = &p.prefix144_audit else {
        return Ok(());
    };
    ensure!(
        is_101(p)?
            && p.prefix157_audit.is_some()
            && p.runtime_handoff157.is_some()
            && !p.expected_epochs.contains(&144)
            && writer(p),
        "foreign144 prefix profile"
    );
    let r = bound_json(&profile.launch, true)?;
    ensure!(
        r["schema"] == "jetstreamer-private-epoch144-prefix-verification-launch-v1"
            && r["epoch"] == 144
            && r["unit"] == UNIT
            && r["launched"] == true
            && r["verifier_sha256"]
                == "b075d4548224cd3ca01f6f7bb441d835b7db4dd769136065d0b516fdeceac582"
            && r["output_slot_start"] == 62208000
            && r["terminal_slot"] == 62639490
            && r["output_slot_count"] == 431491
            && r["full_epoch_verified"] == false
            && r["replay_entries_authorized"] == false
            && r["publication_authorized"] == false
            && r["r2_mutations"] == false,
        "144 prefix launch differs"
    );
    let e = bound_json(&profile.admission_fleet, false)?;
    ensure!(
        e["schema"] == "jetstreamer-horizon-campaign-fleet-v1"
            && e["first_epoch"] == 101
            && e["last_epoch"] == 200
            && e["admission_transition_guard"] == serde_json::to_value(&profile.launch)?
            && e["diagnostics"]
                .as_array()
                .context("144 event diagnostics")?
                .iter()
                .filter(|d| d["epoch"] == 144
                    && d["unit"]["Id"] == UNIT
                    && d["launch_receipt_sha256"] == profile.launch.sha256
                    && d["launch_invocation_id"] == r["invocation_id"])
                .count()
                == 1,
        "144 event fleet differs"
    );
    Ok(())
}
pub(super) fn transition_template(p: &Plan, f: &Value) -> Result<bool> {
    let Some(profile) = &p.prefix144_audit else {
        return Ok(false);
    };
    validate(p)?;
    Ok(f["admission_transition_guard"] == serde_json::to_value(&profile.launch)?)
}
fn fold(f: &mut Value, expected: &Value) -> Result<()> {
    let rows = f["diagnostics"]
        .as_array()
        .context("144 template diagnostics")?;
    let found: Vec<_> = rows.iter().filter(|r| r["epoch"] == 144).collect();
    ensure!(
        found.len() == 1 && found[0] == expected,
        "144 template changed or duplicated"
    );
    f["admission_transition_guard"] = Value::Null;
    Ok(())
}
pub(super) fn derive_fleet(p: &Plan, f: &mut Value) -> Result<()> {
    let Some(profile) = &p.prefix144_audit else {
        return Ok(());
    };
    validate(p)?;
    let r = bound_json(&profile.launch, true)?;
    fold(
        f,
        &json!({"epoch":144,"unit":UNIT,"invocation_id":r["invocation_id"],"scratch_path":r["private_run_root"],"launch_receipt":profile.launch}),
    )
}
pub(super) fn enable(next: &mut Plan, spec: &Bound) -> Result<()> {
    ensure!(
        is_101(next)? && next.prefix144_audit.is_none() && next.prefix157_audit.is_some(),
        "144 prefix requires existing157 history"
    );
    let s: Spec = serde_json::from_slice(&bound_bytes(spec, true)?)?;
    ensure!(
        s.schema == "jetstreamer-horizon-private-prefix144-routine-spec-v1"
            && !s.replay_launch_authorized
            && !s.publication_authorized
            && !s.r2_mutations
            && s.event_fleet.path.parent() == Some(Path::new(FLEET_ROOT_101)),
        "144 prefix spec grants authority or foreign scope"
    );
    let e = bound_json(&s.event_fleet, false)?;
    let ep = bound_json(&s.event_plan, true)?;
    ensure!(
        e["previous_fleet"] == serde_json::to_value(&next.previous_fleet)?
            && e["observer_sha256"] == next.previous_observer.sha256
            && e["sampled_at_utc"]
                == bound_json(&next.previous_observer, false)?["recorded_at_utc"]
            && e["plan"].as_str() == s.event_plan.path.to_str()
            && e["plan_sha256"] == s.event_plan.sha256
            && ep["observer"] == serde_json::to_value(&next.previous_observer)?
            && ep["previous_fleet"] == serde_json::to_value(&next.previous_fleet)?
            && ep["admission_transition_guard"] == serde_json::to_value(&s.launch)?,
        "144 event must consume genuine completed predecessor"
    );
    next.previous_fleet = s.event_fleet.clone();
    next.fleet_template = s.event_plan;
    next.prefix144_audit = Some(Profile {
        launch: s.launch,
        admission_fleet: s.event_fleet,
    });
    next.tools.r2 = Bound {
        path: WRITER.into(),
        sha256: WRITER_SHA.into(),
    };
    validate(next)?;
    prefix157::derive_fleet(next, &mut ep.clone())?;
    derive_fleet(next, &mut ep.clone())?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn one_event_fold_preserves_all_history_and_integers() {
        let expected = json!({"epoch":144,"unit":UNIT,"invocation_id":"a".repeat(32)});
        let mut f = json!({"diagnostics":[{"epoch":157,"counter":u64::MAX},expected],"admission_transition_guard":{"proof":"event"},"gates":{"140":{"keep":u64::MAX}}});
        let before = f.clone();
        fold(&mut f, &expected).unwrap();
        assert!(f["admission_transition_guard"].is_null());
        assert_eq!(f["diagnostics"], before["diagnostics"]);
        assert_eq!(f["gates"], before["gates"]);
        f["diagnostics"][1]["invocation_id"] = json!("f".repeat(32));
        assert!(fold(&mut f, &expected).is_err());
    }
    #[test]
    fn qualified_writer_does_not_revert157_history_or_delivery_namespace() {
        let (mut p, _, _, _, _, _, _, _) = crate::tests::fixture101();
        let b = || Bound {
            path: "/fixture".into(),
            sha256: "a".repeat(64),
        };
        p.prefix144_audit = Some(Profile {
            launch: b(),
            admission_fleet: b(),
        });
        assert!(!writer(&p));
        p.tools.r2 = Bound {
            path: WRITER.into(),
            sha256: WRITER_SHA.into(),
        };
        assert!(writer(&p));
        assert_eq!(generation_101(&p), "prefix144-v1");
        let mut op = PathBuf::new();
        let mut cp = PathBuf::new();
        prefix157::namespaces(&mut p, &mut op, &mut cp).unwrap();
        assert!(p.cycle_unit.ends_with("-prefix144-v1.service"));
    }
}
