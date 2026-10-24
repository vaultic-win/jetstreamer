//! Closed full210 candidate. A launch never qualifies an archive or authorizes R2.
use super::*;
pub(super) const SCHEMA: &str = "jetstreamer-private-epoch210-capped-singleton-launch-v1";
pub(super) const UNIT: &str = "horizon-singleton-210-capped-4aeca563-v1.service";
pub(super) const ROOT: &str =
    "/home/ubuntu/.jetstreamer-private/qualification-210-singleton-capped-v1";
pub(super) const NODE: &str =
    "/var/lib/jetstreamer/horizon-singletons209-212-node-0d2856e7-v1/jetstreamer-node";
pub(super) const NODE_SHA: &str =
    "e4b1df9aa6430456e703c283a7ed3512f5b5ada489d016b98e9d47332836ec4f";
pub(super) const WORKER: &str = "/var/lib/jetstreamer/horizon-v1616-shrink-budget-worker-003fe15-v1/jetstreamer-historical-worker-v1-6-16-shrink-budget";
pub(super) const WORKER_SHA: &str =
    "4aeca56378a4bb2c55d0e590c1e334c4afa6a375a2c0d94894b412bea261f1cc";
pub(super) const INPUT: &str = native210::INPUT;
pub(super) const SNAPSHOT: &str = native210::SNAPSHOT;
pub(super) const SNAPSHOT_SHA: &str = native210::SNAPSHOT_SHA;
pub(super) const GENESIS_SHA: &str = native210::GENESIS_SHA;
pub(super) const PREFLIGHT: &str = "/var/lib/jetstreamer/horizon-singletons209-212-metadata-0d2856e7-v1/preflight210-singleton.json";
pub(super) const PREFLIGHT_SHA: &str =
    "5a3df330f13cb1bd67053ee8f3eecb1300136eeb94f0b0b7842bea7d777bfbf1";
pub(super) const FINGERPRINT: &str =
    "sha256:723578e0e7eef4daa09b68bb2a45263f61bcb19ce49daef094d3174ee1f65b6b";
pub(super) const CAPABILITY: &str =
    "/var/lib/jetstreamer/horizon-210-singleton-capability-v1/capability.json";
pub(super) const NATIVE_PROOF_SHA: &str =
    "e03e6f171b5b6eac6011ff62e172cd333290e25df1d58fb6de1009c7d532e25b";
pub(super) const GUARD: &str =
    "/var/lib/jetstreamer/horizon-210-singleton-main-guard-v1/jetstreamer-horizon-standalone-guard";
pub(super) const GUARD_SHA: &str =
    "9eb141c40202fb34616b624e2977c8fb9b4e8b30cde151a24db952ebeff919df";
pub(super) const SCRATCH: u64 = 300_000_000_000;
pub(super) const PEAK: u64 = 471_798_691_840;
pub(super) const METADATA_RESERVE: u64 = 32 << 20;
pub(super) const MEMORY: u64 = 225_000_000_000;

pub(super) fn namespace(c: &DiagnosticClaim) -> bool {
    c.unit.starts_with("horizon-singleton-210-")
}
pub(super) fn command() -> String {
    format!(
        "{{ path={NODE} ; argv[]={NODE} 210 {ROOT}/output --verify --root-checkpoint-cohort --cohort-manifest={PREFLIGHT} --cohort-manifest-fingerprint={FINGERPRINT} --snapshot-archive={INPUT}/{SNAPSHOT}"
    )
}
pub(super) fn same_command(value: &Value) -> bool {
    value
        .as_str()
        .and_then(|s| s.split_once(" ; ignore_errors="))
        .is_some_and(|(s, _)| s == command())
}
pub(super) fn no_publication(v: &Value) -> Result<()> {
    for key in [
        "runtime_promotion_authorized",
        "full_epoch_qualified",
        "canonical_sidecar_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(
            v[key] == false,
            "210 private candidate grants authority:{key}"
        );
    }
    Ok(())
}
pub(super) fn capability(v: &Value) -> Result<()> {
    ensure!(
        v["schema"] == "jetstreamer-private-epoch210-singleton-input-capability-v1"
            && v["epoch"] == 210
            && v["node_sha256"] == NODE_SHA
            && v["worker_sha256"] == WORKER_SHA
            && v["snapshot_sha256"] == SNAPSHOT_SHA
            && v["genesis_sha256"] == GENESIS_SHA
            && v["preflight_sha256"] == PREFLIGHT_SHA
            && v["manifest_fingerprint"] == FINGERPRINT
            && v["bootstrap_slot"] == 90719638u64
            && v["canonical_root_slot"] == 91151575u64
            && v["terminal_slot"] == 91151999u64
            && v["output_slot_start"] == 90720000u64
            && v["output_slot_count"] == 432000
            && v["post_root_slot_count"] == 424
            && v["all_immutable_inputs_rehashed"] == true
            && v["snapshot_restored"] == false
            && v["worker_spawned"] == false
            && v["resource_samples_taken"] == 0
            && v["native_input_qualified"] == false
            && v["replay_launch_authorized"] == false,
        "210 immutable input capability differs"
    );
    no_publication(v)
}
pub(super) fn native(binding: &BoundFile) -> Result<()> {
    ensure!(
        cfg!(feature = "native210-small"),
        "full210 must use the separately qualified small native generation"
    );
    ensure!(
        binding.path
            == Path::new(
                "/var/lib/jetstreamer/horizon-native210-terminal-proof-small-v2/proof.json"
            ),
        "210 full replay needs its own native terminal proof"
    );
    ensure!(
        binding.sha256 == NATIVE_PROOF_SHA,
        "210 full replay requires its actual qualified native attempt"
    );
    native210_terminal::validate(&native210::immutable_json(binding)?)?;
    Ok(())
}
pub(super) fn launch_matches(c: &DiagnosticClaim, v: &Value) -> bool {
    c.epoch == 210
        && c.unit == UNIT
        && c.scratch_path == Path::new(ROOT)
        && v["schema"] == SCHEMA
        && v["launched"] == true
        && v["epoch"] == 210
        && v["private_run_root"] == ROOT
        && v["node_sha256"] == NODE_SHA
        && v["worker_sha256"] == WORKER_SHA
        && v["snapshot_sha256"] == SNAPSHOT_SHA
        && v["manifest_fingerprint"] == FINGERPRINT
        && v["bootstrap_slot"] == 90719638u64
        && v["canonical_root_slot"] == 91151575u64
        && v["terminal_slot"] == 91151999u64
        && v["post_root_slot_count"] == 424
        && v["output_slot_start"] == 90720000u64
        && v["output_slot_count"] == 432000
        && v["runtime"] == "solana-v1.6.16"
        && v["maximum_scratch_bytes"] == SCRATCH
        && v["experimental_envelope_bytes"] == PEAK
        && v["phase_metadata_reservation_bytes"] == METADATA_RESERVE
        && v["maximum_runtime_seconds"] == 259200
        && v["upstream_shrink_budget_cap"] == true
        && same_command(&v["expected_exec_start"])
        && v["guard_minimum_free_bytes"]
            .as_u64()
            .zip(v["required_initial_free_bytes"].as_u64())
            .is_some_and(|(f, n)| f.checked_add(PEAK) == Some(n))
        && no_publication(v).is_ok()
}
pub(super) fn bindings(c: &DiagnosticClaim, launch: &Value) -> Result<()> {
    ensure!(
        launch_matches(c, launch),
        "210 full singleton launch scope differs"
    );
    let cap: BoundFile = serde_json::from_value(launch["capability"].clone())?;
    ensure!(
        cap.path == Path::new(CAPABILITY),
        "210 input capability path differs"
    );
    capability(&native210::immutable_json(&cap)?)?;
    native(&serde_json::from_value(launch["native_input"].clone())?)?;
    let a = native210::immutable_json(&serde_json::from_value(launch["admission"].clone())?)?;
    let admitted = a["recorded_unix_seconds"]
        .as_u64()
        .context("210 admission clock")?;
    let started = launch["recorded_unix_seconds"]
        .as_u64()
        .context("210 launch clock")?;
    ensure!(
        a["schema"] == "jetstreamer-private-epoch210-singleton-admission-v1"
            && a["mode"] == "replay"
            && a["admitted"] == true
            && a["unit"] == UNIT
            && a["private_run_root"] == ROOT
            && a["candidate_incremental_peak_bytes"] == PEAK
            && a["maximum_memory_bytes"] == MEMORY
            && a["phase_metadata_reservation_bytes"] == METADATA_RESERVE
            && a["capability"] == launch["capability"]
            && a["native_input"] == launch["native_input"]
            && a["resource_plan"] == launch["resource_plan"]
            && a["capacity"] == launch["capacity"]
            && a["protected_existing_floor_bytes"] == launch["guard_minimum_free_bytes"]
            && a["required_initial_free_bytes"] == launch["required_initial_free_bytes"]
            && a["fresh_complete_census_passed"] == true
            && a["older_producers_and_guards_preserved"] == true
            && a["memory_target_percent"] == 90
            && started >= admitted
            && started - admitted <= 900,
        "210 full singleton admission substituted or stale"
    );
    no_publication(&a)?;
    Ok(())
}
pub(super) fn guard_matches(c: &DiagnosticClaim, launch: &Value, p: &Value) -> bool {
    launch_matches(c, launch)
        && p["schema"] == "jetstreamer-horizon-standalone-guard-plan-v1"
        && p["filesystem"] == "/"
        && p["worker_root"] == ROOT
        && p["minimum_free_bytes"] == launch["guard_minimum_free_bytes"]
        && p["maximum_root_physical_bytes"] == PEAK
        && p["maximum_worker_vmas"] == 3500000
        && p.get("native_main").is_none_or(Value::is_null)
        && p.get("bounded_canary").is_none_or(Value::is_null)
        && p.get("bounded_measurement").is_none_or(Value::is_null)
}

#[cfg(test)]
pub(super) fn launch_fixture() -> (DiagnosticClaim, Value) {
    let d = DiagnosticClaim {
        epoch: 210,
        unit: UNIT.into(),
        invocation_id: "a".repeat(32),
        scratch_path: ROOT.into(),
        launch_receipt: BoundFile {
            path: "/sealed/launch.json".into(),
            sha256: "b".repeat(64),
        },
    };
    let mut v = json!({"schema":SCHEMA,"epoch":210,"launched":true,"private_run_root":ROOT,
        "node_sha256":NODE_SHA,"worker_sha256":WORKER_SHA,"snapshot_sha256":SNAPSHOT_SHA,"manifest_fingerprint":FINGERPRINT,
        "bootstrap_slot":90719638u64,"canonical_root_slot":91151575u64,"terminal_slot":91151999u64,"post_root_slot_count":424,
        "output_slot_start":90720000u64,"output_slot_count":432000,"runtime":"solana-v1.6.16","maximum_scratch_bytes":SCRATCH,
        "experimental_envelope_bytes":PEAK,"maximum_runtime_seconds":259200,"upstream_shrink_budget_cap":true,
        "phase_metadata_reservation_bytes":METADATA_RESERVE,
        "guard_minimum_free_bytes":1000,"required_initial_free_bytes":PEAK+1000,
        "expected_exec_start":format!("{} ; ignore_errors=no }}",command())});
    for key in [
        "runtime_promotion_authorized",
        "full_epoch_qualified",
        "canonical_sidecar_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        v[key] = json!(false);
    }
    (d, v)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "root-only immutable metadata validation; no Bank, resource sample, process launch or network"]
    fn root_actual_native210_proof_binds_the_full_singleton_without_reexecuting_its_bank() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let b = BoundFile {
            path: "/var/lib/jetstreamer/horizon-native210-terminal-proof-small-v2/proof.json"
                .into(),
            sha256: NATIVE_PROOF_SHA.into(),
        };
        native(&b).unwrap();
        let wrong = BoundFile {
            path: b.path.clone(),
            sha256: "a".repeat(64),
        };
        assert!(native(&wrong).is_err());
    }
    #[test]
    fn exact_singleton_keeps_every_epoch_slot_root_and_post_root_tail_without_registry_promotion() {
        let (d, v) = launch_fixture();
        assert!(launch_matches(&d, &v));
        assert_eq!(91151999u64 - 91151575, 424);
        assert_eq!(91152000u64 - 90720000, 432000);
        for key in v.as_object().unwrap().keys() {
            let mut bad = v.clone();
            bad[key] = Value::Null;
            assert!(!launch_matches(&d, &bad), "{key}");
        }
        let mut bad = v.clone();
        bad["terminal_slot"] = json!(91151575);
        assert!(!launch_matches(&d, &bad));
        let foreign = BoundFile {
            path: "/var/lib/jetstreamer/horizon-native207-terminal-proof-v1/proof.json".into(),
            sha256: "b".repeat(64),
        };
        assert!(
            native(&foreign).is_err(),
            "207 bootstrap success cannot qualify210"
        );
        let p = json!({"schema":"jetstreamer-horizon-standalone-guard-plan-v1","filesystem":"/","worker_root":ROOT,
            "minimum_free_bytes":1000,"maximum_root_physical_bytes":PEAK,"maximum_worker_vmas":3500000});
        assert!(guard_matches(&d, &v, &p));
        let mut native_guard = p;
        native_guard["native_main"] = json!({"main_pid":42});
        assert!(!guard_matches(&d, &v, &native_guard));
    }
}
