//! A scheduled successor observation can precede its accepted fleet. Retain the
//! exact historical predecessor and actual launch; never synthesize either.
use super::*;
fn lineage(new: &BoundFile, observer: &Value, old: &BoundFile, previous: &Value) -> Result<()> {
    ensure!(
        observer["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && previous["schema"] == observer["schema"],
        "capped observer schema differs"
    );
    if new == old {
        ensure!(observer == previous, "same observer binding changed");
        return Ok(());
    }
    let at = utc_seconds(string(observer, "recorded_at_utc")?)?;
    let before = utc_seconds(string(previous, "recorded_at_utc")?)?;
    let cadence = &observer["cadence"];
    ensure!(
        new.path != old.path
            && at > before
            && cadence["previous_sample"].as_str() == old.path.to_str()
            && cadence["previous_sample_sha256"] == old.sha256
            && cadence["previous_sample_recorded_at_utc"] == previous["recorded_at_utc"]
            && cadence["minimum_interval_seconds"] == 1800
            && cadence["observed_interval_seconds"] == at - before
            && ((cadence["observation_reason"] == "routine"
                && cadence["routine_minimum_interval_enforced"] == true
                && at - before >= 1800)
                || (cadence["observation_reason"] == "user-requested-status"
                    && cadence["routine_minimum_interval_enforced"] == false)),
        "capped successor observer lost exact forward cadence lineage"
    );
    Ok(())
}
fn launch_identity(plan: &BoundFile, admission: &BoundFile, launch: &Value) -> Result<()> {
    ensure!(
        launch["schema"] == "jetstreamer-capped204205-continuation-launch-v1"
            && launch["producer_plan"] == private157::binding(plan)
            && launch["admission"] == private157::binding(admission)
            && launch["invocation_id"].as_str().is_some_and(id),
        "capped observation handoff changed actual launch/source admission"
    );
    Ok(())
}
pub(super) fn validate(
    previous: &BoundFile,
    new: &BoundFile,
    observer: &Value,
    plan: &BoundFile,
    admission: &BoundFile,
    launch: &Value,
) -> Result<()> {
    let prior = evidence::bound(previous, false)?;
    let old = BoundFile {
        path: string(&prior, "observer_receipt")?.into(),
        sha256: string(&prior, "observer_sha256")?.into(),
    };
    // Authenticate the accepted raw predecessor through the existing typed
    // historical reader. Its old sample may expire; only the new sample is used
    // as current resource context and remains subject to ordinary freshness.
    ensure!(
        assembly204_recovery::accepted_context(previous, &old)? == prior,
        "capped handoff predecessor is not the accepted fleet"
    );
    let old_observer = evidence::bound(&old, false)?;
    lineage(new, observer, &old, &old_observer)?;
    launch_identity(plan, admission, launch)?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fixtures() -> (BoundFile, Value, BoundFile, Value) {
        let old = BoundFile {
            path: "/sealed/old-observer.json".into(),
            sha256: "a".repeat(64),
        };
        let new = BoundFile {
            path: "/sealed/new-observer.json".into(),
            sha256: "b".repeat(64),
        };
        let previous = json!({"schema":"jetstreamer-horizon-live-resource-sample-v2","recorded_at_utc":"2026-10-25T21:55:00Z"});
        let current = json!({"schema":"jetstreamer-horizon-live-resource-sample-v2","recorded_at_utc":"2026-10-25T22:26:00Z",
            "cadence":{"previous_sample":old.path,"previous_sample_sha256":old.sha256,"previous_sample_recorded_at_utc":previous["recorded_at_utc"],
            "minimum_interval_seconds":1800,"observed_interval_seconds":1860,"observation_reason":"routine","routine_minimum_interval_enforced":true}});
        (new, current, old, previous)
    }
    #[test]
    fn capped_successor_observer_keeps_genuine_expired_predecessor_lineage() {
        let (new, current, old, previous) = fixtures();
        lineage(&new, &current, &old, &previous).unwrap();
        assert!(lineage(&old, &current, &old, &previous).is_err());
        for (pointer, value) in [
            ("/cadence/previous_sample_sha256", json!("f".repeat(64))),
            ("/cadence/previous_sample", json!("/other.json")),
            (
                "/cadence/previous_sample_recorded_at_utc",
                json!("2026-10-25T21:54:00Z"),
            ),
            ("/cadence/observed_interval_seconds", json!(1800)),
            ("/cadence/routine_minimum_interval_enforced", json!(false)),
        ] {
            let mut bad = current.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(lineage(&new, &bad, &old, &previous).is_err(), "{pointer}");
        }
    }
    #[test]
    fn capped_observer_handoff_preserves_explicit_user_poll_exception_only() {
        let (new, mut current, old, previous) = fixtures();
        current["recorded_at_utc"] = json!("2026-10-25T21:56:00Z");
        current["cadence"]["observed_interval_seconds"] = json!(60);
        assert!(lineage(&new, &current, &old, &previous).is_err());
        current["cadence"]["observation_reason"] = json!("user-requested-status");
        current["cadence"]["routine_minimum_interval_enforced"] = json!(false);
        lineage(&new, &current, &old, &previous).unwrap();
        current["recorded_at_utc"] = previous["recorded_at_utc"].clone();
        current["cadence"]["observed_interval_seconds"] = json!(0);
        assert!(lineage(&new, &current, &old, &previous).is_err());
    }
    #[test]
    fn capped_observer_handoff_cannot_borrow_another_launch_plan_or_admission() {
        let (plan, _, admission, _) = fixtures();
        let launch = json!({"schema":"jetstreamer-capped204205-continuation-launch-v1","producer_plan":private157::binding(&plan),"admission":private157::binding(&admission),"invocation_id":"1".repeat(32)});
        launch_identity(&plan, &admission, &launch).unwrap();
        for key in ["producer_plan", "admission", "invocation_id"] {
            let mut bad = launch.clone();
            bad[key] = Value::Null;
            assert!(launch_identity(&plan, &admission, &bad).is_err());
        }
    }
}
