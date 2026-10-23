//! Closed observation contract for one capped205 canonical-root prefix experiment.
//! Registration never supplies the missing suffix, restart or publication gate.
use super::*;
pub(super) const SCHEMA: &str = "jetstreamer-private-epoch205-capped-root-prefix-launch-v1";
pub(super) const GUARD_SHA: &str =
    "134904cf2e28ce3ede1dd85a6878e40a407443580d4e83a50cb30efc29fd28be";
const UNIT: &str = "horizon-qualify-205-shrink-root-prefix-resource-5c01bf93-v1.service";
const ROOT: &str = "/home/ubuntu/.jetstreamer-private/shrink-root-prefix-resource-205-5c01bf93-v1";
const PLAN: &str = "/var/lib/jetstreamer/horizon-prefix205-resource-5c01bf93-v1/resource-plan.json";
const RUNNER: &str = "/var/lib/jetstreamer/horizon-prefix205-input-capability-5c01bf93-v1/jetstreamer-epoch205-shrink-root-prefix-resource";
const RUNNER_SHA: &str = "fb41a1193c86749db27ef609f487a25de334a7e58b3440093288aecc75ae4801";
const NODE_SHA: &str = "025757b9b337abf05435c427f143f590d9bfa542b5e4493aae783c158b4f2d3d";
const WORKER_SHA: &str = "4aeca56378a4bb2c55d0e590c1e334c4afa6a375a2c0d94894b412bea261f1cc";
const CAPABILITY_SHA: &str = "9db9831e434d775ec41a4fd60ddeebcc97470743f22b51ea22e4b8ae9834c2b3";
const SCRATCH: u64 = 300_000_000_000;
const PEAK: u64 = SCRATCH + (160 << 30);
pub(super) fn namespace(c: &DiagnosticClaim) -> bool {
    c.unit
        .starts_with("horizon-qualify-205-shrink-root-prefix-resource-")
}
fn command(v: &Value) -> Option<&str> {
    v.as_str()?.split_once(" ; ignore_errors=").map(|(s, _)| s)
}
fn expected(r: &Value) -> Option<String> {
    canonical_digest(&r["plan_sha256"]).then_some(())?;
    Some(format!(
        "{{ path={RUNNER} ; argv[]={RUNNER} {PLAN} --plan-sha256 {} --self-sha256 {RUNNER_SHA}",
        r["plan_sha256"].as_str()?
    ))
}
pub(super) fn launch_matches(c: &DiagnosticClaim, r: &Value) -> bool {
    c.epoch == 205
        && c.unit == UNIT
        && c.scratch_path == Path::new(ROOT)
        && r["schema"] == SCHEMA
        && r["epoch"] == 205
        && r["private_run_root"] == ROOT
        && r["node_sha256"] == NODE_SHA
        && r["worker_sha256"] == WORKER_SHA
        && r["runner_sha256"] == RUNNER_SHA
        && r["snapshot_sha256"]
            == "24b722b37fa87462876dc05916bafa98da13f095c95aaed7159e9008efa7352e"
        && r["bootstrap_slot"] == 88559361u64
        && r["terminal_root_slot"] == 88991050u64
        && r["output_slot_start"] == 88560000u64
        && r["output_slot_count"] == 431051
        && r["uncovered_suffix_slots"] == 949
        && r["runtime"] == "solana-v1.6.16"
        && r["solana_rayon_threads"] == 16
        && r["maximum_runtime_seconds"] == 259200
        && r["maximum_scratch_bytes"] == SCRATCH
        && r["experimental_envelope_bytes"] == PEAK
        && r["natural_parent_completion_required"] == true
        && r["upstream_shrink_budget_cap"] == true
        && r["root_prefix_resource_attempt_authorized"] == true
        && r["plan_path"] == PLAN
        && r["guard_minimum_free_bytes"]
            .as_u64()
            .is_some_and(|f| f >= 248_289_182_611 + (896u64 << 30))
        && r["required_initial_free_bytes"]
            .as_u64()
            .zip(r["guard_minimum_free_bytes"].as_u64())
            .is_some_and(|(initial, floor)| floor.checked_add(PEAK) == Some(initial))
        && [
            "ordinary_replay_authorized",
            "canonical_prefix_independently_qualified",
            "native_restart_qualified",
            "assembly_qualified",
            "full_cold_epoch_peak_qualified",
            "runtime_promotion_authorized",
            "canonical_sidecar_authorized",
            "publication_authorized",
            "remote_mutations",
            "r2_mutations",
        ]
        .iter()
        .all(|k| r[*k] == false)
        && expected(r).is_some_and(|e| command(&r["expected_exec_start"]) == Some(e.as_str()))
}
pub(super) fn bindings(c: &DiagnosticClaim, r: &Value) -> Result<()> {
    ensure!(launch_matches(c, r), "capped205 prefix scope differs");
    let cb: BoundFile = serde_json::from_value(r["capability"].clone())?;
    ensure!(
        cb.path
            == Path::new(
                "/var/lib/jetstreamer/horizon-prefix205-input-capability-evidence-v1/capability.json"
            )
            && cb.sha256 == CAPABILITY_SHA,
        "205 capability binding differs"
    );
    let cap = bound_json(&cb)?;
    ensure!(
        cap["schema"] == "jetstreamer-private-epoch205-capped-prefix-input-capability-v1"
            && cap["runner_sha256"] == RUNNER_SHA
            && cap["node_sha256"] == NODE_SHA
            && cap["worker_sha256"] == WORKER_SHA
            && cap["all_immutable_inputs_rehashed"] == true
            && cap["worker_spawned"] == false
            && cap["replay_launch_authorized"] == false,
        "205 input capability differs"
    );
    let pb = BoundFile {
        path: PLAN.into(),
        sha256: r["plan_sha256"].as_str().context("205 plan digest")?.into(),
    };
    let p = bound_json(&pb)?;
    ensure!(
        p["schema"] == "jetstreamer-private-epoch205-shrink-root-prefix-resource-plan-v1"
            && p["unit"] == UNIT
            && p["run_root"] == ROOT
            && p["target_slot"] == 88991050u64
            && p["terminal_slot"] == 88991050u64
            && p["node"]["sha256"] == NODE_SHA
            && p["minimum_free_bytes"] == r["required_initial_free_bytes"]
            && p["maximum_runtime_seconds"] == 259200,
        "205 bound resource plan differs"
    );
    let a = bound_json(&serde_json::from_value(r["admission"].clone())?)?;
    let admitted = a["recorded_unix_seconds"]
        .as_u64()
        .context("205 admission time")?;
    let launched = r["recorded_unix_seconds"]
        .as_u64()
        .context("205 launch time")?;
    ensure!(
        launched >= admitted && launched - admitted <= 900,
        "205 launch used stale or future admission"
    );
    ensure!(
        a["schema"] == "jetstreamer-private-epoch205-capped-prefix-admission-v1"
            && a["admitted"] == true
            && a["unit"] == UNIT
            && a["private_run_root"] == ROOT
            && a["plan_sha256"] == r["plan_sha256"]
            && a["capability_sha256"] == CAPABILITY_SHA
            && a["candidate_incremental_peak_bytes"] == PEAK
            && a["maximum_scratch_bytes"] == SCRATCH
            && a["protected_existing_floor_bytes"] == r["guard_minimum_free_bytes"]
            && a["required_initial_free_bytes"] == r["required_initial_free_bytes"]
            && a["memory_target_percent"] == 90
            && a["fresh_complete_census_passed"] == true
            && a["older_producers_and_guards_preserved"] == true
            && a["publication_authorized"] == false
            && a["r2_mutations"] == false,
        "205 admission proof differs"
    );
    // Admission is a separate issuer's fresh evidence, never created by registration.
    Ok(())
}
pub(super) fn guard_matches(c: &DiagnosticClaim, r: &Value, p: &Value) -> bool {
    launch_matches(c, r)
        && p["filesystem"] == "/"
        && p["minimum_free_bytes"] == r["guard_minimum_free_bytes"]
        && p["maximum_root_physical_bytes"] == SCRATCH
        && p["maximum_worker_vmas"] == 3500000
        && p.get("bounded_canary").is_none_or(Value::is_null)
        && p.get("bounded_measurement").is_none_or(Value::is_null)
}
pub(super) fn same_command(live: &Value, r: &Value) -> bool {
    expected(r).is_some_and(|e| command(live) == Some(e.as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (DiagnosticClaim, Value) {
        let c = DiagnosticClaim {
            epoch: 205,
            unit: UNIT.into(),
            invocation_id: "a".repeat(32),
            scratch_path: ROOT.into(),
            launch_receipt: BoundFile {
                path: "/sealed/launch.json".into(),
                sha256: "b".repeat(64),
            },
        };
        let floor = 248_289_182_611 + (896u64 << 30);
        let mut r = json!({"schema":SCHEMA,"epoch":205,"private_run_root":ROOT,"node_sha256":NODE_SHA,
            "worker_sha256":WORKER_SHA,"runner_sha256":RUNNER_SHA,"snapshot_sha256":"24b722b37fa87462876dc05916bafa98da13f095c95aaed7159e9008efa7352e",
            "bootstrap_slot":88559361,"terminal_root_slot":88991050,"output_slot_start":88560000,"output_slot_count":431051,
            "uncovered_suffix_slots":949,"runtime":"solana-v1.6.16","solana_rayon_threads":16,"maximum_runtime_seconds":259200,
            "maximum_scratch_bytes":SCRATCH,"experimental_envelope_bytes":PEAK,"natural_parent_completion_required":true,
            "upstream_shrink_budget_cap":true,"root_prefix_resource_attempt_authorized":true,"plan_path":PLAN,"plan_sha256":"c".repeat(64),
            "guard_minimum_free_bytes":floor,"required_initial_free_bytes":floor+PEAK});
        for k in [
            "ordinary_replay_authorized",
            "canonical_prefix_independently_qualified",
            "native_restart_qualified",
            "assembly_qualified",
            "full_cold_epoch_peak_qualified",
            "runtime_promotion_authorized",
            "canonical_sidecar_authorized",
            "publication_authorized",
            "remote_mutations",
            "r2_mutations",
        ] {
            r[k] = json!(false);
        }
        r["expected_exec_start"] =
            json!(format!("{} ; ignore_errors=no }}", expected(&r).unwrap()));
        r["launched"] = json!(true);
        r["evidence"] = json!({"units":[{"unit":UNIT,"invocation_id":c.invocation_id,"restarts":0,
            "load_state":"loaded","result":"success","main_pid":123,"active_state":"active","sub_state":"running"}]});
        (c, r)
    }
    #[test]
    fn private_capped_prefix_rejects_canary_other_worker_and_added_authority() {
        let (c, r) = fixture();
        assert!(launch_matches(&c, &r));
        validate_diagnostic_launch(&r, &c).unwrap();
        let mut unbound = r.clone();
        unbound["evidence"]["units"][0]["invocation_id"] = json!("d".repeat(32));
        assert!(validate_diagnostic_launch(&unbound, &c).is_err());
        for (key, value) in [
            ("terminal_root_slot", json!(88584000)),
            ("output_slot_count", json!(432000)),
            (
                "worker_sha256",
                json!("3f5e8efec328b3e00dd9ce5ae396fc4067e6be6554e4da8831a13273186a748a"),
            ),
            ("maximum_scratch_bytes", json!(301_000_000_000u64)),
            ("native_restart_qualified", json!(true)),
            ("guard_minimum_free_bytes", json!(1)),
            ("publication_authorized", json!(true)),
        ] {
            let mut bad = r.clone();
            bad[key] = value;
            assert!(!launch_matches(&c, &bad), "{key}");
        }
        assert!(!same_command(
            &json!(format!(
                "{} --storage-capability ; ignore_errors=no }}",
                expected(&r).unwrap()
            )),
            &r
        ));
        let (mut foreign, _) = fixture();
        foreign.epoch = 203;
        assert!(!launch_matches(&foreign, &r));
    }
    #[test]
    fn guard_requires_independent_scratch_cap_without_stop_exemptions() {
        let (c, r) = fixture();
        let mut p = json!({"filesystem":"/","minimum_free_bytes":r["guard_minimum_free_bytes"],
            "maximum_root_physical_bytes":SCRATCH,"maximum_worker_vmas":3500000});
        assert!(guard_matches(&c, &r, &p));
        p["maximum_root_physical_bytes"] = Value::Null;
        assert!(!guard_matches(&c, &r, &p));
    }
}
