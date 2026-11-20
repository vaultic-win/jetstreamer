//! Current post-172 topology; no closure is treated as a resource credit.
use super::*;
const CLOSURE: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch172-terminal-cadence-20261120-v1/CLOSURE.json";
const CLOSURE_SHA: &str = "854539f0d9450b388e136092567438134efaab19f0570dee7bdeb4fcf53120c7";
const UNIT172: &str = "horizon-qualify-172-trace-hourly-20261120-v1.service";
const IID172: &str = "5a691c24655a4ff489531d8d7cc50254";

fn shape(fleet: &Value, closure: &Value) -> Result<()> {
    ensure!(
        fleet["terminal172_closure"] == binding(Path::new(CLOSURE), CLOSURE_SHA)
            && closure["schema"] == "horizon-private-172-terminal-cadence-v1"
            && closure["epoch"] == 172
            && closure["original_unit"] == UNIT172
            && closure["original_invocation"] == IID172
            && closure["native_terminal"]["producer"]["InvocationID"] == IID172
            && closed(&closure["native_terminal"]["producer"])
            && closure["native_terminal"]["original_pid_absent_or_reused"] == true
            && closure["resource_credit_bytes"] == 0
            && closure["resource_promise_ending_bytes"] == 0
            && n(fleet, "recorded_unix_seconds")? >= n(closure, "observed_unix_seconds")?,
        "post-172 closure missing, stale or granting resource credit"
    );
    for key in [
        "actual_executing_replays",
        "actual_active_bootstraps",
        "actual_active_private_diagnostics",
    ] {
        for row in fleet[key].as_array().context("complete owner rows")? {
            ensure!(
                !matches!(n(row, "epoch")?, 136 | 169 | 172),
                "136 requires an exclusive window without 169/172 owners"
            );
        }
    }
    Ok(())
}

pub(super) fn exclusive_post172(fleet: &Value) -> Result<()> {
    shape(fleet, &json_pin(Path::new(CLOSURE), CLOSURE_SHA)?)?;
    // Both admission controllers hold IL_PATH. The process census in fit also
    // rejects unknown workers. These native checks cover a waiting bootstrap,
    // before it has created a worker or appeared in the replay census.
    for unit in [
        UNIT172,
        "horizon-guard-172-trace-hourly-20261120-v1.service",
        "horizon-guard-172-trace-hourly-20261120-v1.timer",
        "horizon-qualify-169-focused-20261120-v2.service",
        "horizon-guard-169-focused-20261120-v2.service",
        "horizon-guard-169-focused-20261120-v2.timer",
        "horizon-qualify-169-focused-20261120-v3.service",
        "horizon-guard-169-focused-20261120-v3.service",
        "horizon-guard-169-focused-20261120-v3.timer",
        "horizon-qualify-172-metered-hourly-20261120-g2.service",
        "horizon-guard-172-metered-hourly-20261120-g2.service",
        "horizon-guard-172-metered-hourly-20261120-g2.timer",
        "horizon-qualify-172-metered-hourly-20261120-g3.service",
        "horizon-guard-172-metered-hourly-20261120-g3.service",
        "horizon-guard-172-metered-hourly-20261120-g3.timer",
        "horizon-qualify-172-full-half-core-20261120-v1.service",
        "horizon-guard-172-full-half-core-20261120-v1.service",
        "horizon-guard-172-full-half-core-20261120-v1.timer",
    ] {
        ensure!(closed(&show(unit)?), "exclusive peer remains open: {unit}");
        cgroup_empty(unit)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Value, Value) {
        (
            json!({"terminal172_closure":binding(Path::new(CLOSURE), CLOSURE_SHA),
            "recorded_unix_seconds":1000,"actual_executing_replays":[{"epoch":166},{"epoch":167},{"epoch":170}],
            "actual_active_bootstraps":[],"actual_active_private_diagnostics":[{"epoch":168}]}),
            json!({"schema":"horizon-private-172-terminal-cadence-v1","epoch":172,
            "original_unit":UNIT172,"original_invocation":IID172,"observed_unix_seconds":999,
            "native_terminal":{"producer":{"InvocationID":IID172,"ActiveState":"failed","Job":"","MainPID":"0","ControlPID":"0"},"original_pid_absent_or_reused":true},
            "resource_credit_bytes":0,"resource_promise_ending_bytes":0}),
        )
    }
    #[test]
    fn post172_retains_current_peers_and_no_credit() {
        let (fleet, closure) = fixture();
        shape(&fleet, &closure).unwrap();
        for key in ["resource_credit_bytes", "resource_promise_ending_bytes"] {
            let mut changed = closure.clone();
            changed[key] = json!(1);
            assert!(shape(&fleet, &changed).is_err());
        }
    }
    #[test]
    fn reject_live169_or172_and_stale_or_crossed_closure() {
        let (fleet, closure) = fixture();
        for epoch in [136, 169, 172] {
            let mut changed = fleet.clone();
            changed["actual_active_private_diagnostics"]
                .as_array_mut()
                .unwrap()
                .push(json!({"epoch":epoch}));
            assert!(shape(&changed, &closure).is_err());
        }
        let mut stale = fleet.clone();
        stale["recorded_unix_seconds"] = json!(998);
        assert!(shape(&stale, &closure).is_err());
        let mut crossed = closure;
        crossed["native_terminal"]["producer"]["InvocationID"] = json!("f".repeat(32));
        assert!(shape(&fleet, &crossed).is_err());
    }
}
