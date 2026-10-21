//! Offline folding of one authenticated private-prefix-verifier admission.
//! Never a replay claim, production ETA, archive completion or launch authority.
use super::*;
pub(super) const WRITER: &str =
    "/usr/local/lib/jetstreamer/horizon-epoch157-prefix-fleet-reader-20261021-v1/jetstreamer-r2";
pub(super) const WRITER_SHA: &str =
    "75a8398f2661893575baf4ec833031c11bdfce455c6c216bfd7741bf07a64c68";
const UNIT: &str = "horizon-qualify-157-private-verification-20261021-v1.service";
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
    p.prefix157_audit.is_some()
        && p.tools.r2.path == Path::new(WRITER)
        && p.tools.r2.sha256 == WRITER_SHA
}
pub(super) fn validate(p: &Plan) -> Result<()> {
    let Some(profile) = &p.prefix157_audit else {
        return Ok(());
    };
    ensure!(
        is_101(p)?
            && p.runtime_handoff157.is_some()
            && !p.expected_epochs.contains(&157)
            && writer(p),
        "foreign prefix157 profile"
    );
    let r = bound_json(&profile.launch, true)?;
    ensure!(
        r["schema"] == "jetstreamer-private-epoch157-prefix-verification-launch-v1"
            && r["epoch"] == 157
            && r["unit"] == UNIT
            && r["launched"] == true
            && r["verifier_sha256"]
                == "b075d4548224cd3ca01f6f7bb441d835b7db4dd769136065d0b516fdeceac582"
            && r["terminal_slot"] == 68140176
            && r["output_slot_start"] == 67824000
            && r["output_slot_count"] == 316177
            && r["full_epoch_verified"] == false
            && r["replay_entries_authorized"] == false
            && r["publication_authorized"] == false
            && r["r2_mutations"] == false,
        "prefix157 launch proof differs"
    );
    let event = bound_json(&profile.admission_fleet, false)?;
    ensure!(
        event["schema"] == "jetstreamer-horizon-campaign-fleet-v1"
            && event["first_epoch"] == 101
            && event["last_epoch"] == 200
            && event["admission_transition_guard"] == serde_json::to_value(&profile.launch)?
            && event["diagnostics"]
                .as_array()
                .context("prefix157 event diagnostics")?
                .iter()
                .filter(|d| d["epoch"] == 157
                    && d["unit"]["Id"] == UNIT
                    && d["launch_receipt_sha256"] == profile.launch.sha256
                    && d["launch_invocation_id"] == r["invocation_id"])
                .count()
                == 1,
        "prefix157 admission not an exact full fleet"
    );
    Ok(())
}
pub(super) fn transition_template(p: &Plan, fleet: &Value) -> Result<bool> {
    let Some(profile) = &p.prefix157_audit else {
        return Ok(false);
    };
    validate(p)?;
    Ok(fleet["admission_transition_guard"] == serde_json::to_value(&profile.launch)?)
}
fn claim(profile: &Profile, r: &Value) -> Value {
    json!({"epoch":157,"unit":UNIT,"invocation_id":r["invocation_id"],"scratch_path":r["private_run_root"],"launch_receipt":profile.launch})
}
pub(super) fn derive_fleet(p: &Plan, fleet: &mut Value) -> Result<()> {
    let Some(profile) = &p.prefix157_audit else {
        return Ok(());
    };
    validate(p)?;
    let r = bound_json(&profile.launch, true)?;
    let expected = claim(profile, &r);
    fold(fleet, &expected)
}
fn fold(fleet: &mut Value, expected: &Value) -> Result<()> {
    let rows = fleet["diagnostics"]
        .as_array_mut()
        .context("prefix157 diagnostic template")?;
    let found: Vec<_> = rows.iter().filter(|r| r["epoch"] == 157).collect();
    ensure!(
        found.len() == 1 && found[0] == expected,
        "prefix157 template changed or duplicated"
    );
    // The accepted event is history. A subsequent ordinary cycle must not
    // repeatedly authorize a second same-sample admission.
    fleet["admission_transition_guard"] = Value::Null;
    Ok(())
}
pub(super) fn enable(next: &mut Plan, spec: &Bound) -> Result<()> {
    ensure!(
        is_101(next)? && next.prefix157_audit.is_none() && next.runtime_handoff157.is_some(),
        "prefix157 migration requires unmigrated paused157 profile"
    );
    let spec: Spec = serde_json::from_slice(&bound_bytes(spec, true)?)?;
    ensure!(
        spec.schema == "jetstreamer-horizon-private-prefix157-routine-spec-v1"
            && !spec.replay_launch_authorized
            && !spec.publication_authorized
            && !spec.r2_mutations,
        "prefix157 spec grants authority"
    );
    ensure!(
        spec.event_fleet.path.parent() == Some(Path::new(FLEET_ROOT_101)),
        "prefix157 event outside fleet namespace"
    );
    let e = bound_json(&spec.event_fleet, false)?;
    let ep = bound_json(&spec.event_plan, true)?;
    ensure!(
        e["previous_fleet"] == serde_json::to_value(&next.previous_fleet)?
            && e["observer_sha256"] == next.previous_observer.sha256
            && e["sampled_at_utc"]
                == bound_json(&next.previous_observer, false)?["recorded_at_utc"]
            && e["plan"].as_str() == spec.event_plan.path.to_str()
            && e["plan_sha256"] == spec.event_plan.sha256
            && ep["observer"] == serde_json::to_value(&next.previous_observer)?
            && ep["previous_fleet"] == serde_json::to_value(&next.previous_fleet)?
            && ep["admission_transition_guard"] == serde_json::to_value(&spec.launch)?,
        "prefix157 event did not consume actual accepted fleet/observer"
    );
    next.previous_fleet = spec.event_fleet.clone();
    next.fleet_template = spec.event_plan;
    next.prefix157_audit = Some(Profile {
        launch: spec.launch,
        admission_fleet: spec.event_fleet,
    });
    next.tools.r2 = Bound {
        path: WRITER.into(),
        sha256: WRITER_SHA.into(),
    };
    validate(next)?;
    derive_fleet(next, &mut ep.clone())?;
    Ok(())
}
pub(super) fn namespaces(p: &mut Plan, op: &mut PathBuf, cp: &mut PathBuf) -> Result<()> {
    let stamp = stamp(&p.sample_target_utc);
    let generation = generation_101(p);
    *op = Path::new("/var/lib/jetstreamer").join(format!(
        "horizon-next-observer-101-200-{stamp}-{generation}"
    ));
    *cp = Path::new("/var/lib/jetstreamer")
        .join(format!("horizon-routine-plan-101-200-{stamp}-{generation}"));
    p.observer_config.path = op.join("observer.json");
    p.cycle_directory = Path::new("/var/lib/jetstreamer/horizon-routine-cycles-101-200-v2")
        .join(format!("{stamp}-{generation}"));
    p.cycle_unit = cycle_unit(p)?;
    p.scope_101_200
        .as_mut()
        .context("prefix157 scope")?
        .additional_tracked_units = vec![p.cycle_unit.clone()];
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn folding_consumes_event_once_without_changing_other_claims_or_u64s() {
        let expected = json!({"epoch":157,"unit":UNIT,"invocation_id":"a".repeat(32)});
        let mut f = json!({"diagnostics":[{"epoch":140,"counter":u64::MAX},expected],"admission_transition_guard":{"proof":"event"},"gates":{"140":{"keep":u64::MAX}}});
        let before = f.clone();
        fold(&mut f, &expected).unwrap();
        assert!(f["admission_transition_guard"].is_null());
        assert_eq!(f["diagnostics"], before["diagnostics"]);
        assert_eq!(f["gates"], before["gates"]);
        fold(&mut f, &expected).unwrap();
        f["diagnostics"][1]["invocation_id"] = json!("f".repeat(32));
        assert!(fold(&mut f, &expected).is_err());
    }
    #[test]
    fn prefix_generation_preserves_combined_delivery_namespace() {
        let (mut p, _, _, _, _, _, _, _) = crate::tests::fixture101();
        let b = || Bound {
            path: "/fixture".into(),
            sha256: "a".repeat(64),
        };
        p.prefix157_audit = Some(Profile {
            launch: b(),
            admission_fleet: b(),
        });
        assert_eq!(generation_101(&p), "prefix157-v1");
        assert!(!writer(&p));
        p.tools.r2 = Bound {
            path: WRITER.into(),
            sha256: WRITER_SHA.into(),
        };
        assert!(writer(&p));
        let mut op = PathBuf::new();
        let mut cp = PathBuf::new();
        namespaces(&mut p, &mut op, &mut cp).unwrap();
        assert!(p.cycle_unit.ends_with("-prefix157-v1.service"));
    }
}
