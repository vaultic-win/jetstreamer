//! Exact private continuation origin for the independently published 203 archive.
use super::*;

pub(super) fn validate(plan: &Plan, origin: &Value) -> Result<()> {
    ensure!(
        plan.epoch == 203
            && plan.origin_launch.path
                == Path::new(
                    "/var/lib/jetstreamer/horizon-continuation203-launch-state-ed66145-v1/launch.json"
                )
            && plan.origin_launch.sha256
                == "1068823c4c8f71ff78752e7319a2ff3f38c2f82c12c68df0030c98eaae7eb1f0"
            && plan.binding.origin_unit
                == "horizon-qualify-203-checkpoint-continuation-ed66145-v1.service"
            && plan.binding.origin_invocation_id == "ddf3ed2de8b040758ee7a0d696159afd"
            && origin["schema"] == "jetstreamer-private-epoch203-checkpoint-continuation-launch-v1"
            && origin["epoch"] == 203
            && origin["launched"] == true
            && origin["unit"] == plan.binding.origin_unit
            && origin["invocation_id"] == plan.binding.origin_invocation_id
            && origin["r2_mutations"] == false
            && origin["remote_mutations"] == false,
        "203 elapsed-time origin differs from the exact private continuation launch"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn private_origin_never_accepts_a_different_epoch_clock_or_unbound_receipt() {
        let mut p = super::super::tests::directory_plan();
        p.epoch = 203;
        p.origin_launch.path =
            "/var/lib/jetstreamer/horizon-continuation203-launch-state-ed66145-v1/launch.json"
                .into();
        p.origin_launch.sha256 =
            "1068823c4c8f71ff78752e7319a2ff3f38c2f82c12c68df0030c98eaae7eb1f0".into();
        p.binding.origin_unit =
            "horizon-qualify-203-checkpoint-continuation-ed66145-v1.service".into();
        p.binding.origin_invocation_id = "ddf3ed2de8b040758ee7a0d696159afd".into();
        let origin = serde_json::json!({
            "schema":"jetstreamer-private-epoch203-checkpoint-continuation-launch-v1",
            "epoch":203,"launched":true,"unit":p.binding.origin_unit,
            "invocation_id":p.binding.origin_invocation_id,"r2_mutations":false,"remote_mutations":false
        });
        validate(&p, &origin).unwrap();
        for (field, value) in [
            ("epoch", serde_json::json!(204)),
            ("launched", serde_json::json!(false)),
            ("invocation_id", serde_json::json!("a".repeat(32))),
            ("remote_mutations", serde_json::json!(true)),
        ] {
            let mut bad = origin.clone();
            bad[field] = value;
            assert!(validate(&p, &bad).is_err());
        }
        p.origin_launch.sha256 = "a".repeat(64);
        assert!(validate(&p, &origin).is_err());
    }
}
