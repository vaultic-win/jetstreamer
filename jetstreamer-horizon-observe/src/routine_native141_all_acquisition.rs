//! Metadata adoption for one guarded all-target diagnostic, never a replay.
use super::*;
const UNIT: &str = "horizon-epoch141-native-full-census-acquisition-all-20261022-v1.service";
const ROOT: &str = "/home/sol/.jetstreamer-private/epoch141-native-acquisition-all-20261022-v1";
const NATIVE_SHA: &str = "ccf620b21f3c75cde3e9c22df058b0f3e4cefac9f7ae52c533f44bde38d757ec";
const PLAN: &str =
    "/usr/local/lib/jetstreamer/horizon-native141-all-acquisition-plan-20261022-v1/plan.json";
const ADMISSION: &str =
    "/var/lib/jetstreamer/horizon-native141-admission-all-acquisition-20261022-v1/admission.json";
const READER: &str = "/usr/local/lib/jetstreamer/horizon-native141-all-acquisition-fleet-reader-20261022-v1/jetstreamer-r2";
const READER_SHA: &str = "3fc77aac05c985be1fd8549bcb53872937c251de81fe85df2838a1668e00bca2";
pub(super) fn reader(p: &Plan) -> bool {
    p.native141_audit.as_ref().is_some_and(|s| {
        s.all_acquisition.is_some() && s.acquisition.is_some() && s.rejection.is_some()
    }) && p.assembly144_scans.is_some()
        && p.tools.r2.path == Path::new(READER)
        && p.tools.r2.sha256 == READER_SHA
        && is_sha(READER_SHA)
}
fn guard_shape(g: &Value) -> Result<()> {
    ensure!(
        g["schema"] == "jetstreamer-epoch141-native-initial-guard-v1"
            && g["epoch"] == 141
            && g["self_sha256"] == NATIVE_SHA
            && g["invocation_id"].as_str().is_some_and(|s| s.len() == 32
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
            && g["minimum_free_bytes"] == 4740696923590u64
            && g["available_bytes"]
                .as_u64()
                .is_some_and(|n| n >= 4740696923590u64 + (32u64 << 30))
            && g["trip"] == false,
        "all-target acquisition guard differs"
    );
    for flag in ["publication_authorized", "remote_mutations", "r2_mutations"] {
        ensure!(g[flag] == false, "all-target guard grants authority:{flag}");
    }
    for key in ["plan_sha256", "admission_sha256"] {
        ensure!(
            g[key].as_str().is_some_and(is_sha),
            "all-target guard lacks binding:{key}"
        );
    }
    Ok(())
}
pub(super) fn evidence(b: &Bound) -> Result<Value> {
    ensure!(
        b.path == Path::new(ROOT).join("results/initial-guard.json") && is_sha(&b.sha256),
        "foreign all-target acquisition guard"
    );
    let g = bound_json(b, false)?;
    guard_shape(&g)?;
    let plan = bound_json(
        &Bound {
            path: PLAN.into(),
            sha256: g["plan_sha256"].as_str().unwrap().into(),
        },
        true,
    )?;
    let a = bound_json(
        &Bound {
            path: ADMISSION.into(),
            sha256: g["admission_sha256"].as_str().unwrap().into(),
        },
        false,
    )?;
    ensure!(
        plan["schema"] == "jetstreamer-epoch141-ledger-native-all-target-acquisition-plan-v2"
            && plan["unit"] == UNIT
            && plan["minimum_free_bytes"] == 4740696923590u64
            && plan["initial_guard_receipt"].as_str() == b.path.to_str()
            && plan["output_receipt"] == format!("{ROOT}/results/all-target-acquisition.json")
            && a["native_profile"] == "epoch141-read-only-all-target-acquisition-v5"
            && a["native_unit"] == UNIT
            && a["admitted"] == true
            && a["evidence"]["minimum_free_bytes"]
                .as_u64()
                .is_some_and(|n| n >= 4740696923590u64 + (32u64 << 30)),
        "all-target plan/admission scope differs"
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
            "all-target admission grants authority:{flag}"
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
        s.schema == "jetstreamer-native141-all-acquisition-monitor-handoff-v1"
            && !s.replay_launch_authorized
            && !s.publication_authorized
            && !s.remote_mutations
            && !s.r2_mutations,
        "foreign or authorizing all-target handoff"
    );
    Ok(())
}
pub(super) fn enable(p: &mut Plan, b: &Bound) -> Result<()> {
    ensure!(
        acquisition_reader(p)
            && !all_acquisition_enabled(p)
            && public160_timing::enabled(p)
            && p.publication144.is_none(),
        "all-target transition needs accepted timed160 and complete earlier acquisition history"
    );
    let s: Spec = serde_json::from_value(bound_json(b, true)?)?;
    spec(&s)?;
    evidence(&s.first_guard)?;
    p.native141_audit.as_mut().unwrap().all_acquisition = Some(s.first_guard);
    p.tools.r2 = Bound {
        path: READER.into(),
        sha256: READER_SHA.into(),
    };
    validate(p)
}
fn fold(f: &mut Value, claim: Value, b: &Bound) -> Result<()> {
    let ds = f["diagnostics"]
        .as_array_mut()
        .context("all-target diagnostics missing")?;
    let found: Vec<_> = ds.iter().filter(|c| c["unit"] == UNIT).collect();
    ensure!(
        found.is_empty() || (found.len() == 1 && found[0] == &claim),
        "all-target history changed"
    );
    if found.is_empty() {
        ds.push(claim);
    }
    let units = f["tracked_units"]
        .as_array_mut()
        .context("all-target tracked units missing")?;
    if !units.contains(&json!(UNIT)) {
        units.push(json!(UNIT));
    }
    let gate = &mut f["gates"]["141"];
    ensure!(
        gate["state"] == "failed-needs-repair",
        "all-target acquisition cannot close141repair"
    );
    gate["next_action"] = json!(
        "Inspect the exact all18283target raw acquisition and its post-close source revalidation; preserve every prior failed/rejection/first-target outcome. Complete attempt coverage is distinct from raw acquisition and does not prove canonical ancestry, historical liveness, hidden PoH, roots or recovery. Preserve partial outcomes on failure and continue qualified PoH/checkpoint/full/plugin/ready-pair gates. No ordinary replay claim, dashboard ETA or publication authority."
    );
    let entries = gate["evidence"]
        .as_array_mut()
        .context("all-target repair evidence missing")?;
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
        .and_then(|s| s.all_acquisition.as_ref())
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
    fn reader_needs_every_prior_profile_and_new_generation_carries_all_history() {
        let (p, ..) = crate::tests::fixture101();
        let mut v = serde_json::to_value(p).unwrap();
        let b = || json!({"path":"/proof","sha256":"a".repeat(64)});
        v["native141_audit"] =
            json!({"first_guard":b(),"rejection":b(),"acquisition":b(),"all_acquisition":b()});
        v["assembly144_scans"] = json!({"full":b(),"plugin":b()});
        v["tools"]["r2"] = json!({"path":READER,"sha256":READER_SHA});
        let p: Plan = serde_json::from_value(v.clone()).unwrap();
        assert!(reader(&p));
        assert!(acquisition_reader(&p));
        assert!(super::super::reader(&p));
        assert!(crate::generation_101(&p).starts_with("native141-all-acquisition-"));
        for pointer in [
            "/native141_audit/all_acquisition",
            "/native141_audit/acquisition",
            "/native141_audit/rejection",
            "/assembly144_scans",
        ] {
            let mut bad = v.clone();
            *bad.pointer_mut(pointer).unwrap() = Value::Null;
            assert!(!reader(&serde_json::from_value(bad).unwrap()));
        }
        v["tools"]["r2"]["sha256"] = json!("f".repeat(64));
        assert!(!reader(&serde_json::from_value(v).unwrap()));
    }
    #[test]
    fn all_target_guard_cannot_borrow_first_target_reservation_or_authority() {
        let good = json!({"schema":"jetstreamer-epoch141-native-initial-guard-v1","epoch":141,
            "self_sha256":NATIVE_SHA,"invocation_id":"a".repeat(32),"minimum_free_bytes":4740696923590u64,
            "available_bytes":4740696923590u64 + (32u64 << 30),"trip":false,"plan_sha256":"b".repeat(64),
            "admission_sha256":"c".repeat(64),"publication_authorized":false,"remote_mutations":false,"r2_mutations":false});
        guard_shape(&good).unwrap();
        for key in good.as_object().unwrap().keys() {
            let mut bad = good.clone();
            bad[key] = Value::Null;
            assert!(guard_shape(&bad).is_err(), "accepted missing {key}");
        }
        let mut bad = good;
        bad["available_bytes"] = json!(4740696923590u64 + (1u64 << 30));
        assert!(guard_shape(&bad).is_err());
    }
    #[test]
    fn all_target_handoff_and_fold_preserve_failure_and_old_history() {
        let b = Bound {
            path: "/guard".into(),
            sha256: "a".repeat(64),
        };
        let good = json!({"schema":"jetstreamer-native141-all-acquisition-monitor-handoff-v1","first_guard":b,
            "replay_launch_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false});
        spec(&serde_json::from_value(good.clone()).unwrap()).unwrap();
        for flag in [
            "replay_launch_authorized",
            "publication_authorized",
            "remote_mutations",
            "r2_mutations",
        ] {
            let mut bad = good.clone();
            bad[flag] = json!(true);
            assert!(spec(&serde_json::from_value(bad).unwrap()).is_err());
        }
        let mut unknown = good;
        unknown["extra"] = json!(true);
        assert!(serde_json::from_value::<Spec>(unknown).is_err());
        let claim = json!({"epoch":141,"unit":UNIT,"invocation_id":"b".repeat(32)});
        let mut f = json!({"diagnostics":[{"unit":"original"},{"unit":"rejection"},{"unit":"first-target"}],
            "tracked_units":[],"gates":{"141":{"state":"failed-needs-repair","evidence":[]}},"unrelated":u64::MAX});
        fold(&mut f, claim.clone(), &b).unwrap();
        let once = f.clone();
        fold(&mut f, claim.clone(), &b).unwrap();
        assert_eq!(f, once);
        assert_eq!(f["diagnostics"].as_array().unwrap().len(), 4);
        assert_eq!(f["unrelated"], u64::MAX);
        f["gates"]["141"]["state"] = json!("remote-ready");
        assert!(fold(&mut f, claim, &b).is_err());
    }
}
