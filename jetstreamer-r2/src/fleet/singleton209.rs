//! Closed full 209 candidate. A launch never qualifies an archive or authorizes R2.
use super::*;
pub(super) const SCHEMA: &str = "jetstreamer-private-epoch209-capped-singleton-launch-v1";
pub(super) const UNIT: &str = "horizon-singleton-209-capped-4aeca563-v1.service";
pub(super) const ROOT: &str =
    "/home/ubuntu/.jetstreamer-private/qualification-209-singleton-capped-v1";
pub(super) const NODE: &str =
    "/var/lib/jetstreamer/horizon-singletons209-212-node-0d2856e7-v1/jetstreamer-node";
pub(super) const NODE_SHA: &str =
    "e4b1df9aa6430456e703c283a7ed3512f5b5ada489d016b98e9d47332836ec4f";
pub(super) const WORKER: &str = "/var/lib/jetstreamer/horizon-v1616-shrink-budget-worker-003fe15-v1/jetstreamer-historical-worker-v1-6-16-shrink-budget";
pub(super) const WORKER_SHA: &str =
    "4aeca56378a4bb2c55d0e590c1e334c4afa6a375a2c0d94894b412bea261f1cc";
pub(super) const INPUT: &str = native209::INPUT;
pub(super) const SNAPSHOT: &str = native209::SNAPSHOT;
pub(super) const SNAPSHOT_SHA: &str = native209::SNAPSHOT_SHA;
pub(super) const GENESIS_SHA: &str = native209::GENESIS_SHA;
pub(super) const PREFLIGHT: &str = "/var/lib/jetstreamer/horizon-singletons209-212-metadata-0d2856e7-v1/preflight209-singleton.json";
pub(super) const PREFLIGHT_SHA: &str =
    "cd82831678b99ea6c217e476bb6343c8f5f3f308a93dd74db325ec1f50798a75";
pub(super) const FINGERPRINT: &str =
    "sha256:00b0891f2acb9e6ea0e0fdc1b7b5f551a858760dc00b662ee6adb24b1b7d2b1f";
pub(super) const CAPABILITY: &str =
    "/var/lib/jetstreamer/horizon-209-singleton-capability-v1/capability.json";
pub(super) const NATIVE_PROOF_SHA: &str =
    "6a63cb7f95c67e9defa58cb232878cf5ebc4296c99469461e50e0ab846c5bf85";
pub(super) const GUARD: &str =
    "/var/lib/jetstreamer/horizon-209-singleton-main-guard-v1/jetstreamer-horizon-standalone-guard";
pub(super) const GUARD_SHA: &str =
    "9eb141c40202fb34616b624e2977c8fb9b4e8b30cde151a24db952ebeff919df";
pub(super) const SCRATCH: u64 = 300_000_000_000;
pub(super) const PEAK: u64 = 471_798_691_840;
pub(super) const MEMORY: u64 = 225_000_000_000;

pub(super) fn namespace(c: &DiagnosticClaim) -> bool {
    c.unit.starts_with("horizon-singleton-209-")
}
pub(super) fn command() -> String {
    format!(
        "{{ path={NODE} ; argv[]={NODE} 209 {ROOT}/output --verify --root-checkpoint-cohort --cohort-manifest={PREFLIGHT} --cohort-manifest-fingerprint={FINGERPRINT} --snapshot-archive={INPUT}/{SNAPSHOT}"
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
            "209 private candidate grants authority:{key}"
        );
    }
    Ok(())
}
pub(super) fn capability(v: &Value) -> Result<()> {
    ensure!(
        v["schema"] == "jetstreamer-private-epoch209-singleton-input-capability-v1"
            && v["epoch"] == 209
            && v["node_sha256"] == NODE_SHA
            && v["worker_sha256"] == WORKER_SHA
            && v["snapshot_sha256"] == SNAPSHOT_SHA
            && v["genesis_sha256"] == GENESIS_SHA
            && v["preflight_sha256"] == PREFLIGHT_SHA
            && v["manifest_fingerprint"] == FINGERPRINT
            && v["bootstrap_slot"] == 90287519u64
            && v["canonical_root_slot"] == 90719638u64
            && v["terminal_slot"] == 90719999u64
            && v["output_slot_start"] == 90288000u64
            && v["output_slot_count"] == 432000
            && v["post_root_slot_count"] == 361
            && v["all_immutable_inputs_rehashed"] == true
            && v["snapshot_restored"] == false
            && v["worker_spawned"] == false
            && v["resource_samples_taken"] == 0
            && v["native_input_qualified"] == false
            && v["replay_launch_authorized"] == false,
        "209 immutable input capability differs"
    );
    no_publication(v)
}
pub(super) fn native(binding: &BoundFile) -> Result<()> {
    ensure!(
        binding.path
            == Path::new("/var/lib/jetstreamer/horizon-native209-terminal-proof-v1/proof.json"),
        "209 full replay needs its own native terminal proof"
    );
    ensure!(
        binding.sha256 == NATIVE_PROOF_SHA,
        "209 full replay requires its actual qualified native attempt"
    );
    native209_terminal::validate(&native209::immutable_json(binding)?)?;
    Ok(())
}
pub(super) fn launch_matches(c: &DiagnosticClaim, v: &Value) -> bool {
    c.epoch == 209
        && c.unit == UNIT
        && c.scratch_path == Path::new(ROOT)
        && v["schema"] == SCHEMA
        && v["launched"] == true
        && v["epoch"] == 209
        && v["private_run_root"] == ROOT
        && v["node_sha256"] == NODE_SHA
        && v["worker_sha256"] == WORKER_SHA
        && v["snapshot_sha256"] == SNAPSHOT_SHA
        && v["manifest_fingerprint"] == FINGERPRINT
        && v["bootstrap_slot"] == 90287519u64
        && v["canonical_root_slot"] == 90719638u64
        && v["terminal_slot"] == 90719999u64
        && v["post_root_slot_count"] == 361
        && v["output_slot_start"] == 90288000u64
        && v["output_slot_count"] == 432000
        && v["runtime"] == "solana-v1.6.16"
        && v["maximum_scratch_bytes"] == SCRATCH
        && v["experimental_envelope_bytes"] == PEAK
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
        "209 full singleton launch scope differs"
    );
    let cap: BoundFile = serde_json::from_value(launch["capability"].clone())?;
    ensure!(
        cap.path == Path::new(CAPABILITY),
        "209 input capability path differs"
    );
    capability(&native209::immutable_json(&cap)?)?;
    native(&serde_json::from_value(launch["native_input"].clone())?)?;
    let a = native209::immutable_json(&serde_json::from_value(launch["admission"].clone())?)?;
    let admitted = a["recorded_unix_seconds"]
        .as_u64()
        .context("209 admission clock")?;
    let started = launch["recorded_unix_seconds"]
        .as_u64()
        .context("209 launch clock")?;
    ensure!(
        a["schema"] == "jetstreamer-private-epoch209-singleton-admission-v1"
            && a["mode"] == "replay"
            && a["admitted"] == true
            && a["unit"] == UNIT
            && a["private_run_root"] == ROOT
            && a["candidate_incremental_peak_bytes"] == PEAK
            && a["maximum_memory_bytes"] == MEMORY
            && a["capability"] == launch["capability"]
            && a["native_input"] == launch["native_input"]
            && a["resource_plan"] == launch["resource_plan"]
            && a["terminal223"] == launch["terminal223"]
            && a["terminal223_accounting"] == launch["terminal223_accounting"]
            && a["protected_existing_floor_bytes"] == launch["guard_minimum_free_bytes"]
            && a["required_initial_free_bytes"] == launch["required_initial_free_bytes"]
            && a["fresh_complete_census_passed"] == true
            && a["older_producers_and_guards_preserved"] == true
            && a["memory_target_percent"] == 90
            && started >= admitted
            && started - admitted <= 900,
        "209 full singleton admission substituted or stale"
    );
    no_publication(&a)?;
    if !a["terminal223"].is_null() {
        let observer: BoundFile = serde_json::from_value(a["observer"].clone())?;
        let fleet: BoundFile = serde_json::from_value(a["fleet"].clone())?;
        let terminal: BoundFile = serde_json::from_value(a["terminal223"].clone())?;
        let peer = singleton209_peer223::prepare(
            Some(&terminal),
            &bound_json(&fleet)?,
            &bound_json(&observer)?,
            &observer,
            &fleet,
        )?;
        ensure!(
            a["terminal223_accounting"] == singleton209_peer223::evidence(peer.as_ref()),
            "209 full singleton terminal 223 accounting changed"
        );
    }
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
        epoch: 209,
        unit: UNIT.into(),
        invocation_id: "a".repeat(32),
        scratch_path: ROOT.into(),
        launch_receipt: BoundFile {
            path: "/sealed/launch.json".into(),
            sha256: "b".repeat(64),
        },
    };
    let mut v = json!({"schema":SCHEMA,"epoch":209,"launched":true,"private_run_root":ROOT,
        "node_sha256":NODE_SHA,"worker_sha256":WORKER_SHA,"snapshot_sha256":SNAPSHOT_SHA,"manifest_fingerprint":FINGERPRINT,
        "bootstrap_slot":90287519u64,"canonical_root_slot":90719638u64,"terminal_slot":90719999u64,"post_root_slot_count":361,
        "output_slot_start":90288000u64,"output_slot_count":432000,"runtime":"solana-v1.6.16","maximum_scratch_bytes":SCRATCH,
        "experimental_envelope_bytes":PEAK,"maximum_runtime_seconds":259200,"upstream_shrink_budget_cap":true,
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
    fn root_actual_native209_proof_binds_the_full_singleton_without_reexecuting_its_bank() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let b = BoundFile {
            path: "/var/lib/jetstreamer/horizon-native209-terminal-proof-v1/proof.json".into(),
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
        assert_eq!(90719999u64 - 90719638, 361);
        assert_eq!(90720000u64 - 90288000, 432000);
        for key in v.as_object().unwrap().keys() {
            let mut bad = v.clone();
            bad[key] = Value::Null;
            assert!(!launch_matches(&d, &bad), "{key}");
        }
        let mut bad = v.clone();
        bad["terminal_slot"] = json!(90719638);
        assert!(!launch_matches(&d, &bad));
        let foreign = BoundFile {
            path: "/var/lib/jetstreamer/horizon-native207-terminal-proof-v1/proof.json".into(),
            sha256: "b".repeat(64),
        };
        assert!(
            native(&foreign).is_err(),
            "207 bootstrap success cannot qualify209"
        );
        let p = json!({"schema":"jetstreamer-horizon-standalone-guard-plan-v1","filesystem":"/","worker_root":ROOT,
            "minimum_free_bytes":1000,"maximum_root_physical_bytes":PEAK,"maximum_worker_vmas":3500000});
        assert!(guard_matches(&d, &v, &p));
        let mut native_guard = p;
        native_guard["native_main"] = json!({"main_pid":42});
        assert!(!guard_matches(&d, &v, &native_guard));
    }
}
