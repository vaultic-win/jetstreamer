//! Adopt only a genuinely admitted first-target raw acquisition, never replay.
use super::*;
const UNIT: &str = "horizon-epoch141-native-full-census-acquisition-first-20261022-v1.service";
const ROOT: &str = "/home/sol/.jetstreamer-private/epoch141-native-acquisition-first-20261022-v1";
const READER: &str = "/usr/local/lib/jetstreamer/horizon-native141-acquisition-fleet-reader-20261022-v2/jetstreamer-r2";
const READER_SHA: &str = "c62188f6de51d350432658a4234c97291c9f3feb57af52d4f3648afa2314d36d";
pub(super) fn reader(p: &Plan) -> bool {
    p.native141_audit
        .as_ref()
        .is_some_and(|s| s.acquisition.is_some() && s.rejection.is_some())
        && p.assembly144_scans.is_some()
        && ((p.tools.r2.path == Path::new(READER) && p.tools.r2.sha256 == READER_SHA)
            || publication144::reader(p))
        && is_sha(READER_SHA)
}
pub(super) fn evidence(b: &Bound) -> Result<Value> {
    ensure!(
        b.path == Path::new(ROOT).join("results/initial-guard.json") && is_sha(&b.sha256),
        "foreign acquisition guard"
    );
    let g = bound_json(b, false)?;
    ensure!(
        g["schema"] == "jetstreamer-epoch141-native-initial-guard-v1"
            && g["epoch"] == 141
            && g["self_sha256"]
                == "0e7f847b520a91ba033f97181023ea20f9c833653744715c9e3448fbd4de088b"
            && g["invocation_id"].as_str().is_some_and(|s| s.len() == 32
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
            && g["minimum_free_bytes"] == 4740696923590u64
            && g["available_bytes"]
                .as_u64()
                .is_some_and(|v| v >= 4740965359046)
            && g["trip"] == false
            && g["publication_authorized"] == false
            && g["remote_mutations"] == false
            && g["r2_mutations"] == false,
        "acquisition guard scope differs"
    );
    let p=bound_json(&Bound{path:"/usr/local/lib/jetstreamer/horizon-native141-acquisition-plan-20261022-v2/plan.json".into(),sha256:g["plan_sha256"].as_str().context("acquisition plan digest")?.into()},true)?;
    let a=bound_json(&Bound{path:"/var/lib/jetstreamer/horizon-native141-admission-acquisition-20261022-v1/admission.json".into(),sha256:g["admission_sha256"].as_str().context("acquisition admission digest")?.into()},false)?;
    ensure!(
        p["schema"] == "jetstreamer-epoch141-ledger-native-first-target-acquisition-plan-v1"
            && p["unit"] == UNIT
            && p["minimum_free_bytes"] == 4740696923590u64
            && p["initial_guard_receipt"].as_str() == b.path.to_str()
            && a["native_profile"] == "epoch141-read-only-first-target-acquisition-v4"
            && a["native_unit"] == UNIT
            && a["admitted"] == true,
        "acquisition plan/admission differs"
    );
    for flag in [
        "services_started",
        "services_installed",
        "native_database_opened",
        "replay_launch_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(
            a[flag] == false,
            "acquisition admission grants authority:{flag}"
        );
    }
    Ok(g)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    first_guard: Bound,
    replay_launch_authorized: bool,
    publication_authorized: bool,
    remote_mutations: bool,
    r2_mutations: bool,
}
fn spec(s: &Spec) -> Result<()> {
    ensure!(
        s.schema == "jetstreamer-native141-acquisition-monitor-handoff-v1"
            && !s.replay_launch_authorized
            && !s.publication_authorized
            && !s.remote_mutations
            && !s.r2_mutations,
        "foreign acquisition handoff"
    );
    Ok(())
}
pub(super) fn enable(p: &mut Plan, b: &Bound) -> Result<()> {
    ensure!(
        rejection_enabled(p)
            && p.assembly144_scans.is_some()
            && !acquisition_enabled(p)
            && assembly144_scans::reader(p),
        "acquisition needs exact original/rejection/scanner histories"
    );
    let s: Spec = serde_json::from_value(bound_json(b, true)?)?;
    spec(&s)?;
    evidence(&s.first_guard)?;
    p.native141_audit.as_mut().unwrap().acquisition = Some(s.first_guard);
    p.tools.r2 = Bound {
        path: READER.into(),
        sha256: READER_SHA.into(),
    };
    validate(p)
}
fn fold(f: &mut Value, claim: Value, b: &Bound) -> Result<()> {
    let ds = f["diagnostics"]
        .as_array_mut()
        .context("acquisition history")?;
    let found: Vec<_> = ds.iter().filter(|c| c["unit"] == UNIT).collect();
    ensure!(
        found.is_empty() || (found.len() == 1 && found[0] == &claim),
        "acquisition history changed"
    );
    if found.is_empty() {
        ds.push(claim);
    }
    let units = f["tracked_units"]
        .as_array_mut()
        .context("acquisition units")?;
    if !units.contains(&json!(UNIT)) {
        units.push(json!(UNIT));
    }
    let gate = &mut f["gates"]["141"];
    ensure!(
        gate["state"] == "failed-needs-repair",
        "acquisition must not close141repair"
    );
    gate["next_action"] = json!(
        "Track exact private first-target native141 acquisition and preserve both failed attempts plus post-close metadata rejection. Retain raw parent/target meta/root/dead/orphan and every original shred outcome; false connectivity remains unchanged. One queried target is not full18283target recovery, canonical ancestry, authenticated clock or PoH. Inspect genuine post-close receipt before further qualification; no ordinary ETA or publication authority."
    );
    let entries = gate["evidence"]
        .as_array_mut()
        .context("acquisition repair evidence")?;
    let v = serde_json::to_value(b)?;
    if !entries.contains(&v) {
        entries.push(v);
    }
    Ok(())
}
pub(super) fn derive_fleet(p: &Plan, f: &mut Value) -> Result<()> {
    let Some(b) = p
        .native141_audit
        .as_ref()
        .and_then(|s| s.acquisition.as_ref())
    else {
        return Ok(());
    };
    let g = evidence(b)?;
    fold(
        f,
        json!({"epoch":141,"unit":UNIT,"invocation_id":g["invocation_id"],"scratch_path":ROOT,"launch_receipt":b}),
        b,
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reader_requires_acquisition_and_both_prior_private_profiles() {
        let (p, ..) = crate::tests::fixture101();
        let mut v = serde_json::to_value(p).unwrap();
        let b = || json!({"path":"/proof","sha256":"a".repeat(64)});
        v["native141_audit"] = json!({"first_guard":b(),"rejection":b(),"acquisition":b()});
        v["assembly144_scans"] = json!({"full":b(),"plugin":b()});
        v["tools"]["r2"] = json!({"path":READER,"sha256":READER_SHA});
        let p: Plan = serde_json::from_value(v.clone()).unwrap();
        assert!(reader(&p));
        assert!(crate::generation_101(&p).starts_with("native141-acquisition-"));
        for path in [
            "/native141_audit/acquisition",
            "/native141_audit/rejection",
            "/assembly144_scans",
        ] {
            let mut bad = v.clone();
            *bad.pointer_mut(path).unwrap() = Value::Null;
            assert!(!reader(&serde_json::from_value(bad).unwrap()));
        }
        v["tools"]["r2"]["sha256"] = json!("f".repeat(64));
        assert!(!reader(&serde_json::from_value(v).unwrap()));
    }
    #[test]
    fn handoff_is_strict_non_authorizing_and_first_target_only() {
        let good = json!({"schema":"jetstreamer-native141-acquisition-monitor-handoff-v1","first_guard":{"path":format!("{ROOT}/results/initial-guard.json"),"sha256":"a".repeat(64)},"replay_launch_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false});
        spec(&serde_json::from_value(good.clone()).unwrap()).unwrap();
        for key in [
            "replay_launch_authorized",
            "publication_authorized",
            "remote_mutations",
            "r2_mutations",
        ] {
            let mut bad = good.clone();
            bad[key] = json!(true);
            assert!(spec(&serde_json::from_value(bad).unwrap()).is_err());
        }
        let mut bad = good;
        bad["extra"] = json!(true);
        assert!(serde_json::from_value::<Spec>(bad).is_err());
    }
    #[test]
    fn fold_preserves_failed_history_and_other_claims_without_closing_repair() {
        let b = Bound {
            path: "/guard".into(),
            sha256: "a".repeat(64),
        };
        let c = json!({"epoch":141,"unit":UNIT,"invocation_id":"b".repeat(32)});
        let mut f = json!({"diagnostics":[{"unit":"original"},{"unit":"rejection"}],"tracked_units":[],"gates":{"141":{"state":"failed-needs-repair","evidence":[]},"144":{"integer":u64::MAX}},"other":u64::MAX});
        fold(&mut f, c.clone(), &b).unwrap();
        let once = f.clone();
        fold(&mut f, c.clone(), &b).unwrap();
        assert_eq!(once, f);
        assert_eq!(f["diagnostics"].as_array().unwrap().len(), 3);
        assert_eq!(f["other"], u64::MAX);
        f["gates"]["141"]["state"] = json!("remote-ready");
        assert!(fold(&mut f, c, &b).is_err());
    }
}
