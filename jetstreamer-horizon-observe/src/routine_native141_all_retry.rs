//! Adopt one corrected all-target diagnostic without dropping its failed parent.
use super::*;
const READER: &str = "/usr/local/lib/jetstreamer/horizon-native141-all-acquisition-fleet-reader-20261022-v2/jetstreamer-r2";
const READER_SHA: &str = "1aed4a23e6d1626ee049501f449875e4077d60829ff1d5b407a5d417d83e8fd7";
const PARENT_GUARD: &str = "/home/sol/.jetstreamer-private/epoch141-native-acquisition-all-20261022-v1/results/initial-guard.json";
const PARENT_SHA: &str = "259ef91d98fac5e50704a349b08761365033b0a62df67140484ff682369f716c";
const PARENT_UNIT: &str = "horizon-epoch141-native-full-census-acquisition-all-20261022-v1.service";
const PARENT_IID: &str = "72424001726a4f7d8ef9a4f7c8658454";
pub(super) fn enabled(p: &Plan) -> bool {
    p.native141_audit
        .as_ref()
        .is_some_and(|s| s.all_retry.is_some())
}
fn parent_bound(b: &Bound) -> bool {
    b.path == Path::new(PARENT_GUARD) && b.sha256 == PARENT_SHA
}
pub(super) fn reader(p: &Plan) -> bool {
    p.native141_audit.as_ref().is_some_and(|s| {
        s.all_retry.is_some()
            && s.all_acquisition.as_ref().is_some_and(parent_bound)
            && s.acquisition.is_some()
            && s.rejection.is_some()
    }) && p.assembly144_scans.is_some()
        && ((p.tools.r2.path == Path::new(READER) && p.tools.r2.sha256 == READER_SHA)
            || census141_poh::reader(p))
        && is_sha(READER_SHA)
}
fn failed_parent(v: &Value) -> Result<()> {
    for (key, value) in [
        ("Id", PARENT_UNIT),
        ("InvocationID", PARENT_IID),
        ("NRestarts", "0"),
        ("ExecMainStatus", "1"),
        ("MainPID", "0"),
        ("ActiveState", "failed"),
        ("SubState", "failed"),
    ] {
        ensure!(v[key] == value, "all-target retry parent differs:{key}");
    }
    Ok(())
}
fn parent_terminal() -> Result<()> {
    let o = Command::new("/usr/bin/systemctl")
        .args([
            "show",
            PARENT_UNIT,
            "--no-pager",
            "--property=Id,InvocationID,NRestarts,ExecMainStatus,MainPID,ActiveState,SubState",
        ])
        .output()?;
    ensure!(
        o.status.success() && o.stdout.len() <= 16384,
        "all-target parent observation failed"
    );
    let text = std::str::from_utf8(&o.stdout)?;
    let mut values = BTreeMap::new();
    for line in text.lines() {
        let (k, v) = line.split_once('=').context("parent property shape")?;
        ensure!(values.insert(k, v).is_none(), "duplicate parent property");
    }
    failed_parent(&serde_json::to_value(values)?)
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
        s.schema == "jetstreamer-native141-all-retry-monitor-handoff-v1"
            && !s.replay_launch_authorized
            && !s.publication_authorized
            && !s.remote_mutations
            && !s.r2_mutations,
        "foreign or authorizing all-target retry handoff"
    );
    Ok(())
}
pub(super) fn enable(p: &mut Plan, b: &Bound) -> Result<()> {
    ensure!(
        all_acquisition::reader(p)
            && !enabled(p)
            && public160_timing::enabled(p)
            && p.publication144.is_none(),
        "all-target retry needs accepted original all-target profile"
    );
    let parent = p
        .native141_audit
        .as_ref()
        .and_then(|s| s.all_acquisition.as_ref())
        .context("missing failed all-target parent")?;
    ensure!(
        parent_bound(parent) && all_acquisition::evidence(parent)?["invocation_id"] == PARENT_IID,
        "all-target retry lacks exact retained failed-parent guard"
    );
    parent_terminal()?;
    let s: Spec = serde_json::from_value(bound_json(b, true)?)?;
    spec(&s)?;
    all_acquisition::evidence_at(&s.first_guard, &all_acquisition::RETRY)?;
    parent_terminal()?;
    p.native141_audit.as_mut().unwrap().all_retry = Some(s.first_guard);
    p.tools.r2 = Bound {
        path: READER.into(),
        sha256: READER_SHA.into(),
    };
    validate(p)
}
pub(super) fn derive_fleet(p: &Plan, f: &mut Value) -> Result<()> {
    let Some(b) = p
        .native141_audit
        .as_ref()
        .and_then(|s| s.all_retry.as_ref())
    else {
        return Ok(());
    };
    let a = &all_acquisition::RETRY;
    let g = all_acquisition::evidence_at(b, a)?;
    all_acquisition::fold_at(
        f,
        json!({"epoch":141,"unit":a.unit,"invocation_id":g["invocation_id"],"scratch_path":a.root,"launch_receipt":b}),
        b,
        a.unit,
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "root exact retained failed all-target v1 parent only; no new native open, resource sample, R2 request or launch"]
    fn actual_failed_parent_has_unchanged_guard_and_terminal_identity() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let b = Bound {
            path: PARENT_GUARD.into(),
            sha256: PARENT_SHA.into(),
        };
        assert!(parent_bound(&b));
        assert_eq!(
            all_acquisition::evidence(&b).unwrap()["invocation_id"],
            PARENT_IID
        );
        parent_terminal().unwrap();
    }
    #[test]
    fn failed_parent_cannot_be_live_restarted_foreign_or_clean_success() {
        let good = json!({"Id":PARENT_UNIT,"InvocationID":PARENT_IID,"NRestarts":"0",
            "ExecMainStatus":"1","MainPID":"0","ActiveState":"failed","SubState":"failed"});
        failed_parent(&good).unwrap();
        for key in good.as_object().unwrap().keys() {
            let mut bad = good.clone();
            bad[key] = Value::Null;
            assert!(failed_parent(&bad).is_err(), "accepted missing {key}");
        }
        let mut bad = good;
        bad["ExecMainStatus"] = json!("0");
        assert!(failed_parent(&bad).is_err());
    }
    #[test]
    fn retry_spec_does_not_borrow_old_handoff_or_grant_authority() {
        let good = json!({"schema":"jetstreamer-native141-all-retry-monitor-handoff-v1",
            "first_guard":{"path":"/proof","sha256":"a".repeat(64)},"replay_launch_authorized":false,
            "publication_authorized":false,"remote_mutations":false,"r2_mutations":false});
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
        bad["schema"] = json!("jetstreamer-native141-all-acquisition-monitor-handoff-v1");
        assert!(spec(&serde_json::from_value(bad).unwrap()).is_err());
    }
    #[test]
    fn retry_reader_requires_retained_original_guard_and_distinct_candidate() {
        let (p, ..) = crate::tests::fixture101();
        let mut v = serde_json::to_value(p).unwrap();
        let b = || json!({"path":"/proof","sha256":"a".repeat(64)});
        v["native141_audit"] = json!({"first_guard":b(),"rejection":b(),"acquisition":b(),
            "all_acquisition":{"path":PARENT_GUARD,"sha256":PARENT_SHA},"all_retry":b()});
        v["assembly144_scans"] = json!({"full":b(),"plugin":b()});
        v["tools"]["r2"] = json!({"path":READER,"sha256":READER_SHA});
        let p: Plan = serde_json::from_value(v.clone()).unwrap();
        assert!(reader(&p));
        assert!(all_acquisition::reader(&p));
        assert!(acquisition_reader(&p));
        assert!(crate::generation_101(&p).starts_with("native141-all-retry-"));
        for pointer in [
            "/native141_audit/all_acquisition",
            "/native141_audit/all_retry",
            "/native141_audit/rejection",
            "/native141_audit/acquisition",
            "/assembly144_scans",
        ] {
            let mut bad = v.clone();
            *bad.pointer_mut(pointer).unwrap() = Value::Null;
            assert!(!reader(&serde_json::from_value(bad).unwrap()));
        }
        v["native141_audit"]["all_acquisition"]["sha256"] = json!("f".repeat(64));
        assert!(!reader(&serde_json::from_value(v).unwrap()));
    }
}
