//! Closed full singleton contract. Registration supplies no verification or R2 authority.
use super::*;
pub(super) const SCHEMA: &str = "jetstreamer-private-epoch227-capped-singleton-launch-v1";
pub(super) const UNIT: &str = "horizon-singleton-227-capped-710f6523-v1.service";
pub(super) const ROOT: &str = "/home/ubuntu/.jetstreamer-private/singleton-227-capped-710f6523-v1";
pub(super) const NODE: &str =
    "/var/lib/jetstreamer/horizon-stage227-bootstrap-dcaafc6-v1/jetstreamer-node";
pub(super) const NODE_SHA: &str =
    "f2c11e5b596e5a0107ddded523c310a1deb71b9206e95f3113f5ac713b920e11";
pub(super) const WORKER: &str = "/var/lib/jetstreamer/horizon-227-capped-candidate-710f6523-v1/jetstreamer-historical-worker-v1-6-20";
pub(super) const WORKER_SHA: &str =
    "710f6523d15b960f79d91935d18d581a341e04e649df26ccd0a2b31ae9bc3eeb";
pub(super) const CAPABILITY: &str =
    "/var/lib/jetstreamer/horizon-227-input-capability-result-v1/capability.json";
pub(super) const CAPABILITY_SHA: &str =
    "ecca1ab0b765e009a55897a723a8f364d3db94db4c8c2b87efd1ef102cfd2679";
pub(super) const SNAPSHOT_SHA: &str =
    "77e5b3bbb733d9ab3b2383c1ad9f1d7ef4062aedacbe9e2326927512c4b95e07";
pub(super) const INPUT: &str = "/var/lib/jetstreamer/horizon-stage227-bootstrap-dcaafc6-v1";
pub(super) const SNAPSHOT: &str =
    "snapshot-98063464-4TaJaC5esCEWtHp5Fay2aMS9XjA1o9bwQthcvBeSyYbR.tar.zst";
pub(super) const FINGERPRINT: &str =
    "sha256:99fa3de5ed1da720b76e33196d4ef4da9dda57202f12af90eaab60f84f9ecd31";
pub(super) const GUARD_SHA: &str =
    "134904cf2e28ce3ede1dd85a6878e40a407443580d4e83a50cb30efc29fd28be";
pub(super) const PEAK: u64 = 471_798_691_840;
pub(super) const SCRATCH: u64 = 300_000_000_000;
pub(super) fn namespace(c: &DiagnosticClaim) -> bool {
    c.unit.starts_with("horizon-singleton-227-")
}
pub(super) fn expected_command() -> String {
    format!(
        "{{ path={NODE} ; argv[]={NODE} 227 {ROOT}/output --verify --root-checkpoint-cohort --cohort-manifest={INPUT}/preflight227-singleton.json --cohort-manifest-fingerprint={FINGERPRINT} --snapshot-archive={INPUT}/{SNAPSHOT}"
    )
}
pub(super) fn same_command(live: &Value, _r: &Value) -> bool {
    live.as_str()
        .and_then(|s| s.split_once(" ; ignore_errors="))
        .is_some_and(|(s, _)| s == expected_command())
}
pub(super) fn launch_matches(c: &DiagnosticClaim, r: &Value) -> bool {
    c.epoch == 227
        && c.unit == UNIT
        && c.scratch_path == Path::new(ROOT)
        && r["schema"] == SCHEMA
        && r["epoch"] == 227
        && r["private_run_root"] == ROOT
        && r["node_sha256"] == NODE_SHA
        && r["worker_sha256"] == WORKER_SHA
        && r["snapshot_sha256"] == SNAPSHOT_SHA
        && r["manifest_fingerprint"] == FINGERPRINT
        && r["bootstrap_slot"] == 98063464u64
        && r["canonical_root_slot"] == 98495291u64
        && r["terminal_slot"] == 98495999u64
        && r["output_slot_start"] == 98064000u64
        && r["output_slot_count"] == 432000
        && r["runtime"] == "solana-v1.6.20"
        && r["maximum_scratch_bytes"] == SCRATCH
        && r["experimental_envelope_bytes"] == PEAK
        && r["maximum_runtime_seconds"] == 259200
        && r["upstream_shrink_budget_cap"] == true
        && r["guard_minimum_free_bytes"]
            .as_u64()
            .zip(r["required_initial_free_bytes"].as_u64())
            .is_some_and(|(f, n)| f.checked_add(PEAK) == Some(n))
        && same_command(&r["expected_exec_start"], r)
        && [
            "runtime_promotion_authorized",
            "full_epoch_qualified",
            "canonical_sidecar_authorized",
            "publication_authorized",
            "remote_mutations",
            "r2_mutations",
        ]
        .iter()
        .all(|k| r[*k] == false)
}
pub(super) fn bindings(c: &DiagnosticClaim, r: &Value) -> Result<()> {
    ensure!(launch_matches(c, r), "227 launch scope differs");
    let cap: BoundFile = serde_json::from_value(r["capability"].clone())?;
    ensure!(
        cap.path == Path::new(CAPABILITY) && cap.sha256 == CAPABILITY_SHA,
        "227 input capability differs"
    );
    let v = bound_json(&cap)?;
    ensure!(
        v["schema"] == "jetstreamer-private-epoch227-capped-input-capability-v1"
            && v["all_immutable_inputs_rehashed"] == true
            && v["worker_spawned"] == false
            && v["snapshot_restored"] == false
            && v["replay_launch_authorized"] == false,
        "227 capability authority differs"
    );
    let native = bound_json(&serde_json::from_value(r["native_input"].clone())?)?;
    native_valid(&native)?;
    let a = bound_json(&serde_json::from_value(r["admission"].clone())?)?;
    let admitted = a["recorded_unix_seconds"]
        .as_u64()
        .context("227 admission time")?;
    let launched = r["recorded_unix_seconds"]
        .as_u64()
        .context("227 launch time")?;
    ensure!(
        launched >= admitted
            && launched - admitted <= 900
            && a["schema"] == "jetstreamer-private-epoch227-singleton-admission-v1"
            && a["admitted"] == true
            && a["unit"] == UNIT
            && a["private_run_root"] == ROOT
            && a["candidate_incremental_peak_bytes"] == PEAK
            && a["capability_sha256"] == CAPABILITY_SHA
            && a["native_input"] == r["native_input"]
            && a["resource_plan"] == r["resource_plan"]
            && a["protected_existing_floor_bytes"] == r["guard_minimum_free_bytes"]
            && a["required_initial_free_bytes"] == r["required_initial_free_bytes"]
            && a["fresh_complete_census_passed"] == true
            && a["older_producers_and_guards_preserved"] == true
            && a["memory_target_percent"] == 90
            && a["publication_authorized"] == false
            && a["r2_mutations"] == false,
        "227 admission binding differs"
    );
    Ok(())
}
pub(super) fn native_valid(v: &Value) -> Result<()> {
    ensure!(
        v["schema"] == "jetstreamer-private-epoch227-native-input-qualified-v1"
            && v["epoch"] == 227
            && v["test_sha256"]
                == "229191c382de07872b8e44697f1fe2e92866fbcda06a93baac32e2c0784d3ba9"
            && v["snapshot_sha256"] == SNAPSHOT_SHA
            && v["bootstrap_slot"] == 98063464u64
            && v["accounts_hash"] == "4TaJaC5esCEWtHp5Fay2aMS9XjA1o9bwQthcvBeSyYbR"
            && v["child_success"] == true
            && v["child_exit_code"] == 0
            && v["replay_entries"] == 0
            && v["bootstrap_writes"] == 0
            && v["producer_terminal_and_zero_restarts"] == true
            && v["publication_authorized"] == false
            && v["r2_mutations"] == false,
        "227 native input proof differs"
    );
    Ok(())
}
pub(super) fn guard_matches(c: &DiagnosticClaim, r: &Value, p: &Value) -> bool {
    launch_matches(c, r)
        && p["filesystem"] == "/"
        && p["worker_root"] == ROOT
        && p["minimum_free_bytes"] == r["guard_minimum_free_bytes"]
        && p["maximum_root_physical_bytes"] == PEAK
        && p["maximum_worker_vmas"] == 3500000
        && p.get("bounded_canary").is_none_or(Value::is_null)
        && p.get("bounded_measurement").is_none_or(Value::is_null)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (DiagnosticClaim, Value) {
        let c = DiagnosticClaim {
            epoch: 227,
            unit: UNIT.into(),
            invocation_id: "a".repeat(32),
            scratch_path: ROOT.into(),
            launch_receipt: BoundFile {
                path: "/sealed/launch.json".into(),
                sha256: "b".repeat(64),
            },
        };
        let mut r = json!({"schema":SCHEMA,"epoch":227,"private_run_root":ROOT,"node_sha256":NODE_SHA,"worker_sha256":WORKER_SHA,
            "snapshot_sha256":SNAPSHOT_SHA,"manifest_fingerprint":FINGERPRINT,"bootstrap_slot":98063464u64,"canonical_root_slot":98495291u64,
            "terminal_slot":98495999u64,"output_slot_start":98064000u64,"output_slot_count":432000,"runtime":"solana-v1.6.20",
            "maximum_scratch_bytes":SCRATCH,"experimental_envelope_bytes":PEAK,"maximum_runtime_seconds":259200,
            "upstream_shrink_budget_cap":true,"guard_minimum_free_bytes":2_000_000_000_000u64,"required_initial_free_bytes":2_000_000_000_000u64+PEAK,
            "expected_exec_start":format!("{} ; ignore_errors=no }}",expected_command())});
        for k in [
            "runtime_promotion_authorized",
            "full_epoch_qualified",
            "canonical_sidecar_authorized",
            "publication_authorized",
            "remote_mutations",
            "r2_mutations",
        ] {
            r[k] = json!(false);
        }
        (c, r)
    }
    #[test]
    fn full_singleton_never_borrows_prefix_worker_runtime_or_publication_authority() {
        let (c, r) = fixture();
        assert!(launch_matches(&c, &r));
        for (k, v) in [
            (
                "worker_sha256",
                json!("f39140b9a9659e7c6e8207076a2d0c560a6b69df42cc92e19a421cf46c2b761c"),
            ),
            ("runtime", json!("solana-v1.6.25")),
            ("terminal_slot", json!(98495291)),
            ("canonical_root_slot", json!(98495999)),
            ("output_slot_count", json!(431292)),
            ("publication_authorized", json!(true)),
            ("required_initial_free_bytes", json!(1)),
        ] {
            let mut bad = r.clone();
            bad[k] = v;
            assert!(!launch_matches(&c, &bad), "{k}");
        }
        assert!(!same_command(
            &json!(format!(
                "{} --qualification-end-slot=98495291 ; ignore_errors=no }}",
                expected_command()
            )),
            &r
        ));
        let mut p = json!({"filesystem":"/","worker_root":ROOT,"minimum_free_bytes":r["guard_minimum_free_bytes"],"maximum_root_physical_bytes":PEAK,"maximum_worker_vmas":3500000});
        assert!(guard_matches(&c, &r, &p));
        p["maximum_root_physical_bytes"] = json!(SCRATCH);
        assert!(!guard_matches(&c, &r, &p));
    }
}
