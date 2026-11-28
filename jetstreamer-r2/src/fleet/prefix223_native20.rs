//! Exact private native 20 known-root prefix. Never complete epoch/publication authority.
use super::*;
pub(super) const SCHEMA: &str = "jetstreamer-private-epoch223-native20-prefix-launch-v1";
pub(super) const UNIT: &str = "horizon-qualify-223-v1620-root-prefix-resource-full-v1.service";
pub(super) const ROOT: &str =
    "/home/ubuntu/.jetstreamer-private/qualification-223-v1620-prefix-full-root-v1";
pub(super) const RUNNER: &str = "/var/lib/jetstreamer/horizon-native223-next-root-d18fd429-v2/jetstreamer-epoch223-v1620-root-prefix-resource";
pub(super) const RUNNER_SHA: &str =
    "d18fd42956cafd34d6dccabeb2a47fbbca8c8d857ef8ed7adb39d8ad2a2b1d7d";
pub(super) const PLAN: &str =
    "/var/lib/jetstreamer/horizon-native223-next-root-d18fd429-v2/actual-plan.json";
pub(super) const PLAN_SHA: &str =
    "c293ceb824be8b4272c969c1e2cbe1071e8e2255465d5e0c3358fda513ae2973";
pub(super) const NODE_SHA: &str =
    "99f643ff0dbbcd37d1fbc524a1c1088d7273c7fc91330df059d30d51b8b0fcd4";
pub(super) const WORKER_SHA: &str =
    "a651b7a6ee3c0d4f8359e1ea6cfcb96becf259d440ee744beb173b264de6af20";
pub(super) const SNAPSHOT_SHA: &str =
    "301110cad7eb56ed68c99d31cf6769b7622e2c166f33aec084dc51592d0cd665";
pub(super) const CAPABILITY: &str =
    "/var/lib/jetstreamer/horizon-native223-full-prefix-capability-a2c01ef4-v1/capability.json";
pub(super) const CAPABILITY_SHA: &str =
    "a2c01ef4188dd2b87e172b91dd3d705b877523f89dd407eff59d64f5e4c6964a";
pub(super) const WARMUP: &str =
    "/var/lib/jetstreamer/horizon-warmup223-native20-terminal-58ab-v2/proof.json";
pub(super) const WARMUP_SHA: &str =
    "6790592b9188e7c4a3d32171a326b743f84fc6c5b5ad07f94182c104876b7028";
pub(super) const GUARD: &str = "/var/lib/jetstreamer/horizon-native223-prefix-guard-044ccba7-v1/jetstreamer-horizon-standalone-guard";
pub(super) const GUARD_SHA: &str =
    "044ccba70304c6d5690d2628c1ca08586462efdcc2d9f278903ee8bab0da6b3f";
pub(super) const PROTECTIVE: &str = "horizon-native223-prefix-protective-v1.service";
pub(super) const GUARD_RECEIPTS: &str =
    "/var/lib/jetstreamer/horizon-native223-prefix-guard-receipts-v1";
pub(super) const PEAK: u64 = 471_798_691_840;
pub(super) const MEMORY: u64 = 225_000_000_000;
pub(super) const FLOOR: u64 = 2_000_000_000_000;
pub(super) const INITIAL: u64 = FLOOR + PEAK;
pub(super) fn namespace(c: &DiagnosticClaim) -> bool {
    c.unit
        .starts_with("horizon-qualify-223-v1620-root-prefix-resource-")
}
pub(super) fn command() -> String {
    format!(
        "{{ path={RUNNER} ; argv[]={RUNNER} {PLAN} --plan-sha256 {PLAN_SHA} --self-sha256 {RUNNER_SHA}"
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
        "ordinary_replay_authorized",
        "full_cold_epoch_peak_qualified",
        "repair_closed",
        "canonical_prefix_independently_qualified",
        "native_restart_qualified",
        "suffix_qualified",
        "assembly_qualified",
        "full_epoch_qualified",
        "full_plugin_qualified",
        "runtime_promotion_authorized",
        "canonical_sidecar_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(
            v[key] == false,
            "native 20 prefix grants forbidden authority:{key}"
        );
    }
    Ok(())
}
pub(super) fn capability(v: &Value) -> Result<()> {
    ensure!(
        v["schema"] == "jetstreamer-private-epoch223-v1620-root-prefix-capability-v1"
            && v["node_sha256"] == NODE_SHA
            && v["worker_sha256"] == WORKER_SHA
            && v["snapshot_sha256"] == SNAPSHOT_SHA
            && v["bindings"]["self_sha256"] == RUNNER_SHA
            && v["entry_replay"] == false
            && v["worker_started"] == false
            && v["resource_observation_performed"] == false
            && v["replay_launch_authorized"] == false
            && v["publication_authorized"] == false
            && v["r2_mutations"] == false
            && v["prerequisites"]["warmup_terminal"] == json!({"path":WARMUP,"sha256":WARMUP_SHA}),
        "native 20 full-prefix capability differs"
    );
    let p = &v["parent_planning_report"];
    ensure!(
        p["epoch"] == 223
            && p["bootstrap_slot"] == 96335538u64
            && p["terminal_slot"] == 96767522u64
            && p["output_slot_start"] == 96336000u64
            && p["output_slot_count"] == 431523
            && p["runtime_profile"] == "solana-v1.6.20"
            && p["runtime_revision"] == "77bdb45d4af61fc687161ec06cc0178ff79726d5"
            && p["pre_worker_barrier_reached"] == true
            && p["worker_spawned"] == false
            && p["archive_created"] == false
            && p["worker_profile_validated"] == true
            && p["runtime_checkpoint_policy_validated"] == true
            && p["canonical_bootstrap_bound"] == true
            && p["canonical_terminal_required"] == true
            && p["terminal_canonical_root_independently_known"] == true
            && p["worker_environment_override"] == "JETSTREAMER_HISTORICAL_WORKER_V1_6_20"
            && p["worker_identity"] == "jetstreamer-historical-worker-v1-6-20"
            && p["canonical_prefix_qualified"] == false
            && p["runtime_promotion_authorized"] == false
            && p["publication_authorized"] == false,
        "native 20 planning barrier/span differs"
    );
    Ok(())
}
pub(super) fn prerequisites() -> Result<()> {
    capability(&native209::immutable_json(&BoundFile {
        path: CAPABILITY.into(),
        sha256: CAPABILITY_SHA.into(),
    })?)?;
    let warm = native209::immutable_json(&BoundFile {
        path: WARMUP.into(),
        sha256: WARMUP_SHA.into(),
    })?;
    let (name, iid) = warmup223::terminal_identity(&warm)?;
    ensure!(
        name == "horizon-qualify-223-v1620-warmup-resource-8457f800-v2.service"
            && iid == "58ab3d9221a6452685b8eab3ceabdb49"
            && warm["bounded_warmup_complete"] == true,
        "full prefix lacks successful exact warmup"
    );
    let p = native209::immutable_json(&BoundFile {
        path: PLAN.into(),
        sha256: PLAN_SHA.into(),
    })?;
    ensure!(
        p["unit"] == UNIT
            && p["run_root"] == ROOT
            && p["target_slot"] == 96767522u64
            && p["terminal_slot"] == 96767522u64
            && p["minimum_free_bytes"] == INITIAL
            && p["maximum_runtime_seconds"] == 259200,
        "full prefix actual plan differs"
    );
    Ok(())
}
pub(super) fn launch_matches(c: &DiagnosticClaim, v: &Value) -> bool {
    c.epoch == 223
        && c.unit == UNIT
        && c.scratch_path == Path::new(ROOT)
        && v["schema"] == SCHEMA
        && v["epoch"] == 223
        && v["private_run_root"] == ROOT
        && v["launched"] == true
        && v["entry_replay"] == true
        && v["ordinary_replay_claim"] == false
        && v["public_sidecar_countdown_authorized"] == true
        && v["runner_sha256"] == RUNNER_SHA
        && v["node_sha256"] == NODE_SHA
        && v["worker_sha256"] == WORKER_SHA
        && v["snapshot_sha256"] == SNAPSHOT_SHA
        && v["runtime"] == "solana-v1.6.20"
        && v["bootstrap_slot"] == 96335538u64
        && v["terminal_root_slot"] == 96767522u64
        && v["output_slot_start"] == 96336000u64
        && v["output_slot_count"] == 431523
        && v["uncovered_suffix_slots"] == 477
        && v["natural_parent_completion_required"] == true
        && v["maximum_scratch_bytes"] == 300_000_000_000u64
        && v["experimental_envelope_bytes"] == PEAK
        && v["maximum_memory_bytes"] == MEMORY
        && v["maximum_runtime_seconds"] == 259200
        && v["guard_minimum_free_bytes"] == FLOOR
        && v["required_initial_free_bytes"] == INITIAL
        && same_command(&v["expected_exec_start"])
        && no_publication(v).is_ok()
}
pub(super) fn guard_matches(c: &DiagnosticClaim, v: &Value, p: &Value) -> bool {
    launch_matches(c, v)
        && p["filesystem"] == "/"
        && p["unit"] == UNIT
        && p["invocation_id"] == c.invocation_id
        && p["worker_root"] == ROOT
        && p["minimum_free_bytes"] == FLOOR
        && p["maximum_root_physical_bytes"] == PEAK
        && p["maximum_worker_vmas"] == 3500000
        && p.get("native_main").is_none_or(Value::is_null)
        && p.get("bounded_canary").is_none_or(Value::is_null)
        && p.get("bounded_measurement").is_none_or(Value::is_null)
        && p["receipt_directory"] == GUARD_RECEIPTS
}
pub(super) fn bindings(c: &DiagnosticClaim, v: &Value) -> Result<()> {
    ensure!(launch_matches(c, v), "native 20 full prefix launch differs");
    prerequisites()?;
    let rows = v["evidence"]["units"]
        .as_array()
        .context("native 20 prefix captured unit evidence")?;
    ensure!(
        rows.len() == 1
            && rows[0]["unit"] == UNIT
            && rows[0]["invocation_id"] == c.invocation_id
            && rows[0]["restarts"] == 0
            && rows[0]["main_pid"].as_u64().is_some_and(|n| n > 1),
        "native 20 prefix claim is not its captured invocation"
    );
    ensure!(
        v["capability"] == json!({"path":CAPABILITY,"sha256":CAPABILITY_SHA})
            && v["warmup_terminal"] == json!({"path":WARMUP,"sha256":WARMUP_SHA})
            && v["resource_plan"] == json!({"path":PLAN,"sha256":PLAN_SHA}),
        "native 20 prefix prerequisites substituted"
    );
    let a = native209::immutable_json(&serde_json::from_value(v["admission"].clone())?)?;
    super::prefix223_native20_admission::validate_saved(&a)?;
    let started = v["recorded_unix_seconds"]
        .as_u64()
        .context("native 20 prefix launch clock")?;
    ensure!(
        a["recorded_unix_seconds"]
            .as_u64()
            .is_some_and(|t| t <= started && started - t <= 900)
            && a["observer"] == v["observer"]
            && a["fleet"] == v["fleet"]
            && a["capability"] == v["capability"]
            && a["resource_plan"] == v["resource_plan"],
        "prefix launch admission clock/bindings differ"
    );
    let guard = bound_json(&serde_json::from_value(v["guard"].clone())?)?;
    let guard_plan: BoundFile = serde_json::from_value(v["guard_plan"].clone())?;
    let plan = native209::immutable_json(&guard_plan)?;
    let guarded = super::prefix223_native20_capture::guard_valid(
        &a,
        &guard,
        &plan,
        &guard_plan.sha256,
        started,
    )?;
    ensure!(
        guarded == c.invocation_id && guard["producer"]["pid"] == rows[0]["main_pid"],
        "prefix original guard belongs to another invocation"
    );
    let selected = &v["guard_manager"]["completed_selection"];
    ensure!(
        selected["binding"] == v["guard"] && selected["history"]["unit"] == PROTECTIVE,
        "prefix first guard selection substituted"
    );
    warmup223::validate_completed_guard_history(&selected["history"], &guard)?;
    super::prefix223_native20_capture::sandbox(&serde_json::from_value(v["sandbox"].clone())?)?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual_capability_rejects_warmup_worker_later_extent_and_premature_authority() {
        let good: Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/native223-full-prefix-capability-v2.json"
        ))
        .unwrap();
        capability(&good).unwrap();
        for (pointer, value) in [
            (
                "/worker_sha256",
                json!("52d6c86a8103b8965ca68ead96af471a7899a0a0e6e69c48989b39fd5d922f0c"),
            ),
            ("/worker_started", json!(true)),
            ("/parent_planning_report/output_slot_count", json!(432000)),
            (
                "/parent_planning_report/runtime_profile",
                json!("solana-v1.6.25"),
            ),
            (
                "/parent_planning_report/canonical_prefix_qualified",
                json!(true),
            ),
            (
                "/prerequisites/warmup_terminal/sha256",
                json!("0".repeat(64)),
            ),
        ] {
            let mut bad = good.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(capability(&bad).is_err(), "{pointer}");
        }
    }
    #[test]
    fn full_prefix_command_cannot_borrow_warmup_worker_or_terminal_extent() {
        let cmd = json!(format!("{} ; ignore_errors=no ; pid=1 }}", command()));
        assert!(same_command(&cmd));
        for change in [
            command().replace(PLAN_SHA, "wrong"),
            command().replace(RUNNER, "/warmup/runner"),
            command().replace("full-v1.service", "capability-v2.service"),
        ] {
            if change != command() {
                assert!(!same_command(&json!(format!(
                    "{change} ; ignore_errors=no"
                ))));
            }
        }
        assert_eq!(96767522u64 - 96336000 + 1, 431523);
        assert_eq!(96767999u64 - 96767522, 477);
        assert_eq!(INITIAL, FLOOR + PEAK);
    }
}
