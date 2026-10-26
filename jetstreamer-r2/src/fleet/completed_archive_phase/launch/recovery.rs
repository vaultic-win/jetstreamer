//! One existing launch may be captured by a separately sealed repair binary.
//! This never reissues the admission or startup release and grants no execution.
use super::*;
const SCHEMA: &str = "jetstreamer-completed209-full-v12-capture-recovery-v1";
const ORIGINAL: &str = "7dc89b9bcd1b3391f970f265c698a8eea29ebd19a93ebc8efdac7b163e682ef1";
const IID: &str = "6814e0da70924c9c974cabd3274ffefb";
const RELEASE: &str = "f60a748836a15640c45dc0bd848e4efcc4eb7c10d0a5ae790bc46a0029cd2372";
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Recovery {
    schema: String,
    capturer: Program,
}
fn scope(s: &Spec, a: &Value, startup: &Value, release: &Value) -> Result<()> {
    ensure!(
        s.epoch == 209
            && s.phase == Phase::Full
            && s.units["full"] == "horizon-qualify-209-generic-full-v12.service"
            && s.guard_units["full"] == "horizon-generic209-full-protective-v12.service"
            && s.programs["launcher"].artifact.sha256 == ORIGINAL
            && s.programs["launcher"].artifact.path
                == Path::new(
                    "/var/lib/jetstreamer/horizon-r2-immediate209-6d2fb16c-v1/jetstreamer-r2"
                )
            && a["issuer_sha256"] == ORIGINAL
            && a["spec"]
                == json!({"path":"/var/lib/jetstreamer/horizon-generic209-full-spec-v12-guards-v2/phase-spec.json","sha256":"90bdbcd0a831ae5207a36eb4f1569ee5400ff35532987271517cc3007043b296"})
            && a["binding"]
                == json!({"path":"/var/lib/jetstreamer/horizon-generic209-full-admission-v12/admission.json","sha256":"bad7d0f7beaab944dfd1bd1d694770ab0324b1495a606c5a17b48ba89decbf04"})
            && release
                == &json!({"path":"/var/lib/jetstreamer/horizon-generic209-full-release-v12/release.json","sha256":RELEASE})
            && startup["invocation_id"] == IID
            && startup["process"]["pid"] == 2802657
            && startup["process"]["start_ticks"] == 199206966,
        "completed209 capture recovery escaped its original launch pins"
    );
    Ok(())
}
fn attestation(r: &Recovery, issuer: &str) -> Result<()> {
    ensure!(
        r.schema == SCHEMA
            && is_lower_hex(issuer, 64)
            && issuer != ORIGINAL
            && r.capturer.artifact.sha256 == issuer,
        "completed209 recovery capturer attestation differs"
    );
    token(&r.capturer.artifact.path)?;
    token(&r.capturer.deployment_seal.path)?;
    Ok(())
}
pub(super) fn capture_shape(
    c: &Capture,
    s: &Spec,
    a: &Value,
    issuer: &str,
    waiting: bool,
    startup: Option<&Value>,
) -> Result<()> {
    if let Some(r) = &c.capture_recovery {
        ensure!(
            !waiting,
            "completed209 capture recovery cannot release a child"
        );
        let release = c
            .startup_release
            .as_ref()
            .context("completed209 recovery needs exact startup release")?;
        scope(
            s,
            a,
            startup.context("completed209 recovery startup absent")?,
            &private157::binding(release),
        )?;
        attestation(r, issuer)?;
        program(&s.programs["launcher"])?;
        program(&r.capturer)?;
        ensure!(
            fs::read_link("/proc/self/exe")? == r.capturer.artifact.path,
            "completed209 recovery is not executing its sealed capturer"
        );
    } else {
        ensure!(
            a["issuer_sha256"] == issuer && s.programs["launcher"].artifact.sha256 == issuer,
            "completed capture issuer differs from original launcher without scoped recovery"
        );
    }
    Ok(())
}
pub(super) fn issuer_shape(v: &Value, s: &Spec, a: &Value, issuer: &str) -> Result<()> {
    if let Some(value) = v.get("capture_recovery") {
        let r: Recovery = serde_json::from_value(value.clone())?;
        scope(s, a, &v["startup_release_contents"], &v["startup_release"])?;
        attestation(&r, issuer)?;
        ensure!(
            v["issuer_sha256"] == issuer
                && v["invocation_id"] == IID
                && v["current_protection"].is_object()
                && v["child_execution_authorized"] == false,
            "completed209 recovery did not capture its protected original child"
        );
    } else {
        ensure!(
            issuer == s.programs["launcher"].artifact.sha256 && a["issuer_sha256"] == issuer,
            "completed saved issuer differs from original launcher"
        );
    }
    Ok(())
}
pub(super) fn validate_files(v: &Value) -> Result<()> {
    if let Some(value) = v.get("capture_recovery") {
        let r: Recovery = serde_json::from_value(value.clone())?;
        program(&r.capturer)?;
        let binding: BoundFile = serde_json::from_value(v["capture_spec"].clone())?;
        let c: Capture = serde_json::from_value(read(&binding)?)?;
        ensure!(
            c.schema == "jetstreamer-completed-archive-phase-capture-spec-v1"
                && serde_json::to_value(&c.capture_recovery)? == *value
                && private157::binding(&c.phase_spec) == v["phase_spec"]
                && private157::binding(&c.admission) == v["admission"]
                && private157::binding(&c.guard_plan) == v["guard_plan"]
                && c.startup_release.as_ref().map(private157::binding)
                    == Some(v["startup_release"].clone())
                && c.guard_sample
                    .as_ref()
                    .is_none_or(|b| private157::binding(b) == v["guard_sample"]),
            "completed209 recovery changed its sealed capture request"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Spec, Value, Value, String) {
        let (mut s, mut a, mut l, _) = super::super::tests::fixture();
        s.units.insert(
            "full".into(),
            "horizon-qualify-209-generic-full-v12.service".into(),
        );
        s.guard_units.insert(
            "full".into(),
            "horizon-generic209-full-protective-v12.service".into(),
        );
        let launcher = s.programs.get_mut("launcher").unwrap();
        launcher.artifact.path =
            "/var/lib/jetstreamer/horizon-r2-immediate209-6d2fb16c-v1/jetstreamer-r2".into();
        launcher.artifact.sha256 = ORIGINAL.into();
        a["issuer_sha256"] = json!(ORIGINAL);
        a["spec"] = json!({"path":"/var/lib/jetstreamer/horizon-generic209-full-spec-v12-guards-v2/phase-spec.json","sha256":"90bdbcd0a831ae5207a36eb4f1569ee5400ff35532987271517cc3007043b296"});
        a["binding"] = json!({"path":"/var/lib/jetstreamer/horizon-generic209-full-admission-v12/admission.json","sha256":"bad7d0f7beaab944dfd1bd1d694770ab0324b1495a606c5a17b48ba89decbf04"});
        l["startup_release"] = json!({"path":"/var/lib/jetstreamer/horizon-generic209-full-release-v12/release.json","sha256":RELEASE});
        l["startup_release_contents"]["invocation_id"] = json!(IID);
        l["startup_release_contents"]["process"]["pid"] = json!(2802657);
        l["startup_release_contents"]["process"]["start_ticks"] = json!(199206966);
        let issuer = "e".repeat(64);
        l["issuer_sha256"] = json!(issuer);
        l["invocation_id"] = json!(IID);
        l["child_execution_authorized"] = json!(false);
        l["current_protection"] = json!({});
        l["capture_recovery"] = json!({"schema":SCHEMA,"capturer":{
            "artifact":{"path":"/var/lib/jetstreamer/repair/jetstreamer-r2","sha256":issuer},
            "deployment_seal":{"path":"/var/lib/jetstreamer/repair/deployment-seal-receipt.json","sha256":"a".repeat(64)}}});
        (s, a, l, issuer)
    }
    #[test]
    fn completed209_recovery_keeps_original_issuer_separate_from_truthful_capturer() {
        let (s, a, l, issuer) = fixture();
        issuer_shape(&l, &s, &a, &issuer).unwrap();
        assert_ne!(a["issuer_sha256"], l["issuer_sha256"]);
        assert!(issuer_shape(&l, &s, &a, ORIGINAL).is_err());
        let mut bad = l.clone();
        bad.as_object_mut().unwrap().remove("capture_recovery");
        assert!(issuer_shape(&bad, &s, &a, &issuer).is_err());
        for (pointer, value) in [
            ("/startup_release/sha256", json!("0".repeat(64))),
            (
                "/startup_release_contents/invocation_id",
                json!("0".repeat(32)),
            ),
            ("/startup_release_contents/process/pid", json!(42)),
            ("/startup_release_contents/process/start_ticks", json!(1)),
            (
                "/capture_recovery/capturer/artifact/sha256",
                json!(ORIGINAL),
            ),
            ("/child_execution_authorized", json!(true)),
            ("/current_protection", Value::Null),
        ] {
            let mut bad = l.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(issuer_shape(&bad, &s, &a, &issuer).is_err(), "{pointer}");
        }
        let mut bad = a.clone();
        bad["issuer_sha256"] = json!(issuer);
        assert!(issuer_shape(&l, &s, &bad, &issuer).is_err());
        let mut bad = s;
        bad.epoch = 210;
        assert!(issuer_shape(&l, &bad, &a, &issuer).is_err());
    }
    #[test]
    fn completed209_recovery_attestation_rejects_unknown_bypass_fields() {
        let (_, _, l, _) = fixture();
        let mut r = l["capture_recovery"].clone();
        r["skip_original_launcher_check"] = json!(true);
        assert!(serde_json::from_value::<Recovery>(r).is_err());
    }
}
