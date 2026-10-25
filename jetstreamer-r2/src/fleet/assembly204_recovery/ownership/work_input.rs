//! First work capture precedes its frame and ETA policy. Those remain mandatory
//! only on the final fleet/status Claim, never as fabricated future bindings.
use super::*;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WorkInput {
    #[serde(deserialize_with = "epoch204")]
    pub epoch: u64,
    pub recovery_plan: BoundFile,
    pub admission: BoundFile,
    pub launch: BoundFile,
    pub actor_launch: BoundFile,
}
fn epoch204<'de, D: serde::Deserializer<'de>>(d: D) -> std::result::Result<u64, D::Error> {
    let epoch = u64::deserialize(d)?;
    if epoch == 204 {
        Ok(epoch)
    } else {
        Err(serde::de::Error::custom("204 work input epoch differs"))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn input() -> Value {
        let binding = |name: &str| json!({"path":format!("/sealed-fixture/{name}.json"),"sha256":"a".repeat(64)});
        json!({"epoch":204,"recovery_plan":binding("plan"),"admission":binding("admission"),
            "launch":binding("launch"),"actor_launch":binding("actor-launch")})
    }
    fn spec(claim: Value) -> Value {
        json!({"schema":"jetstreamer-epoch204-assembly-recovery-work-spec-v1","claim":claim,
            "observer":{"path":"/fixture/observer.json","sha256":"b".repeat(64)},
            "previous_fleet":{"path":"/fixture/fleet.json","sha256":"c".repeat(64)},
            "output":"/fixture/first-frame.json"})
    }
    #[test]
    fn first_work_input_requires_origin_bindings_but_no_future_frame_or_eta() {
        let first = input();
        let parsed: WorkSpec = serde_json::from_value(spec(first.clone())).unwrap();
        assert_eq!(parsed.claim.epoch, 204);
        names_for_epoch(parsed.claim.epoch).unwrap();
        assert!(serde_json::from_value::<Claim>(first.clone()).is_err());
        for key in ["recovery_plan", "admission", "launch", "actor_launch"] {
            let mut missing = first.clone();
            missing.as_object_mut().unwrap().remove(key);
            assert!(
                serde_json::from_value::<WorkSpec>(spec(missing)).is_err(),
                "accepted missing {key}"
            );
            for value in [
                Value::Null,
                json!({}),
                json!({"path":"/fixture/missing-digest.json"}),
            ] {
                let mut invalid = first.clone();
                invalid[key] = value;
                assert!(
                    serde_json::from_value::<WorkSpec>(spec(invalid)).is_err(),
                    "accepted incomplete binding {key}"
                );
            }
        }
        // Final fleet/status Claim still requires both genuine later bindings.
        let mut final_claim = first.clone();
        final_claim["frame"] = json!({"path":"/fixture/frame.json","sha256":"d".repeat(64)});
        assert!(serde_json::from_value::<Claim>(final_claim.clone()).is_err());
        final_claim["eta_policy"] = json!({"path":"/fixture/eta.json","sha256":"e".repeat(64)});
        serde_json::from_value::<Claim>(final_claim.clone()).unwrap();
        final_claim.as_object_mut().unwrap().remove("frame");
        assert!(serde_json::from_value::<Claim>(final_claim).is_err());
    }
    #[test]
    fn first_work_input_rejects_future_fields_wrong_epoch_and_unknown_fields() {
        let valid = input();
        for key in ["frame", "eta_policy", "unexpected"] {
            let mut extra = valid.clone();
            extra[key] = json!({"path":"/not-created-yet.json","sha256":"f".repeat(64)});
            assert!(
                serde_json::from_value::<WorkSpec>(spec(extra)).is_err(),
                "accepted future/extra {key}"
            );
        }
        for epoch in [json!(203), json!(205), json!(-1), json!("204"), Value::Null] {
            let mut wrong = valid.clone();
            wrong["epoch"] = epoch;
            assert!(serde_json::from_value::<WorkSpec>(spec(wrong)).is_err());
        }
        let mut extra = spec(valid);
        extra["frame"] = json!("future");
        assert!(serde_json::from_value::<WorkSpec>(extra).is_err());
    }
    #[test]
    fn refresh_spec_accepts_only_explicit_bound_intermediate_observer_history() {
        let mut refresh = spec(input());
        let initial: WorkSpec = serde_json::from_value(refresh.clone()).unwrap();
        assert!(initial.observer_history.is_empty());
        refresh["observer_history"] =
            json!([{"path":"/fixture/intermediate-observer.json","sha256":"d".repeat(64)}]);
        let parsed: WorkSpec = serde_json::from_value(refresh.clone()).unwrap();
        assert_eq!(parsed.observer_history.len(), 1);
        refresh["observer_history"] = json!([{"path":"/fixture/missing-digest.json"}]);
        assert!(serde_json::from_value::<WorkSpec>(refresh).is_err());
    }
}
