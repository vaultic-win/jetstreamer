//! Closed observational registration for the cold223 known-root prefix only.
//! Never a full epoch, a restored suffix or a publication contract.
use super::*;
pub(super) const SCHEMA: &str = "jetstreamer-private-epoch223-known-root-prefix-launch-v1";
pub(super) const GUARD_SHA: &str =
    "d039ddf0b161bc554614a862bd12987bd6a3474549a22d066ebefa5584e5dd98";
const UNIT: &str = "horizon-qualify-223-root-prefix-resource-0f7f1b6e-v1.service";
const ROOT: &str = "/home/ubuntu/.jetstreamer-private/qualification-223-v1625-prefix-0f7f1b6e-v1";
const RUNNER: &str = "/var/lib/jetstreamer/horizon-prefix223-capability-0f7f1b6e-v1/jetstreamer-epoch223-root-prefix-resource";
const RUNNER_SHA: &str = "d40d59b452fed5fb38447f497a86f9c9c4437a303a3205fb8d02b216fb00c651";
const PLAN: &str = "/var/lib/jetstreamer/horizon-prefix223-resource-0f7f1b6e-v1/resource-plan.json";
const PLAN_SHA: &str = "f8ff482d5104cd57e0aaa6fddc4ca2eb296335a79aaadaaea395c058419d3f12";
const NODE_SHA: &str = "90474659be2a4a7d1cc9d4dfe3d5ab1587adb1b388b83163b2bf16c771624f66";
const WORKER_SHA: &str = "fde3ba53cc52012b894bac29bd7889b4cfd326fff75f4f67ec4cbdbf2ac7136c";
const CAPABILITY: &str =
    "/var/lib/jetstreamer/horizon-223-prefix-capability-receipts-0f7f1b6e-v1/capability.json";
const CAPABILITY_SHA: &str = "5dcb7e009328759a4f6c13788d33ff4d33fa9ee92c1d6b49b73678c05d90bf66";
const MINIMUM_FREE: u64 = 2_584_751_391_635;
const GUARD_FLOOR: u64 = 1_004_203_426_707;
const RELEASE203: &str =
    "/var/lib/jetstreamer/horizon-prefix203-terminal-independent-evidence-v1/ready.json";
const RELEASE203_SHA: &str = "02618d6608caac667ed7f7cb9a05510768090eca4ae1612a3fdc0d894eff2ee9";
pub(super) fn namespace(c: &DiagnosticClaim) -> bool {
    c.unit
        .starts_with("horizon-qualify-223-root-prefix-resource-")
}
fn command(v: &Value) -> Option<&str> {
    v.as_str()?.split_once(" ; ignore_errors=").map(|(s, _)| s)
}
fn expected() -> String {
    format!(
        "{{ path={RUNNER} ; argv[]={RUNNER} {PLAN} --plan-sha256 {PLAN_SHA} --self-sha256 {RUNNER_SHA}"
    )
}
pub(super) fn same_command(live: &Value, launch: &Value) -> bool {
    command(live) == Some(expected().as_str()) && command(live) == command(launch)
}
pub(super) fn launch_matches(c: &DiagnosticClaim, r: &Value) -> bool {
    namespace(c)
        && c.epoch == 223
        && c.unit == UNIT
        && c.scratch_path == Path::new(ROOT)
        && r["schema"] == SCHEMA
        && r["epoch"] == 223
        && r["private_run_root"] == ROOT
        && r["node_sha256"] == NODE_SHA
        && r["worker_sha256"] == WORKER_SHA
        && r["runner_sha256"] == RUNNER_SHA
        && r["plan_path"] == PLAN
        && r["plan_sha256"] == PLAN_SHA
        && r["snapshot_slot"] == 96_335_538u64
        && r["snapshot_sha256"]
            == "301110cad7eb56ed68c99d31cf6769b7622e2c166f33aec084dc51592d0cd665"
        && r["runtime"] == "solana-v1.6.25"
        && r["solana_rayon_threads"] == 2
        && r["output_slot_start"] == 96_336_000u64
        && r["output_slot_count"] == 431_523
        && r["terminal_root_slot"] == 96_767_522u64
        && r["uncovered_suffix_slots"] == 477
        && r["maximum_terminal_scratch_bytes"] == 1280u64 << 30
        && r["experimental_envelope_bytes"] == 1536u64 << 30
        && r["maximum_runtime_seconds"] == 259200
        && r["required_initial_free_bytes"] == MINIMUM_FREE
        && r["guard_minimum_free_bytes"] == GUARD_FLOOR
        && r["capability"]["path"] == CAPABILITY
        && r["capability"]["sha256"] == CAPABILITY_SHA
        && r["released203_terminal"]["path"] == RELEASE203
        && r["released203_terminal"]["sha256"] == RELEASE203_SHA
        && r["protected203_remaining_bytes"] == 0
        && r["protected225_remaining_bytes"] == 640u64 << 30
        && r["root_prefix_resource_attempt_authorized"] == true
        && r["natural_parent_completion_required"] == true
        && [
            "ordinary_replay_authorized",
            "canonical_prefix_independently_qualified",
            "full_cold_epoch_peak_qualified",
            "native_restart_qualified",
            "assembly_qualified",
            "runtime_promotion_authorized",
            "complete_epoch_span_covered",
            "canonical_sidecar_authorized",
            "publication_authorized",
            "remote_mutations",
            "r2_mutations",
        ]
        .iter()
        .all(|key| r[*key] == false)
        && command(&r["expected_exec_start"]) == Some(expected().as_str())
}
pub(super) fn guard_matches(c: &DiagnosticClaim, r: &Value, p: &Value) -> bool {
    launch_matches(c, r)
        && p["filesystem"] == "/"
        && p["minimum_free_bytes"] == GUARD_FLOOR
        && p["worker_root"].as_str() == c.scratch_path.join("scratch").to_str()
        && p["maximum_worker_vmas"] == 3_500_000
        && p.get("bounded_canary").is_none_or(Value::is_null)
        && p.get("bounded_measurement").is_none_or(Value::is_null)
}
pub(super) fn capability(v: &Value) -> Result<()> {
    ensure!(
        v["schema"] == "jetstreamer-private-epoch223-prefix-package-capability-v1"
            && v["epoch"] == 223
            && v["self_sha256"]
                == "05bc7c27b637395d03ae311c45148b21845f86d09fe5ad7377e8abbbf9f414d4"
            && v["members"]["jetstreamer-node"]["sha256"] == NODE_SHA
            && v["members"]["jetstreamer-historical-worker-v1-6-25"]["sha256"] == WORKER_SHA,
        "prefix223 capability owner differs"
    );
    let p = &v["planning_preflight"];
    ensure!(
        p["schema"] == "jetstreamer-private-epoch223-prefix-planning-preflight-v1"
            && p["bootstrap_slot"] == 96_335_538u64
            && p["terminal_slot"] == 96_767_522u64
            && p["output_slot_start"] == 96_336_000u64
            && p["output_slot_count"] == 431_523,
        "prefix223 capability span differs"
    );
    for key in [
        "canonical_bootstrap_bound",
        "canonical_terminal_required",
        "terminal_canonical_root_independently_known",
        "pre_worker_barrier_reached",
        "worker_profile_validated",
    ] {
        ensure!(p[key] == true, "prefix capability missing {key}");
    }
    for key in [
        "fresh_resource_admission_passed",
        "replay_launch_authorized",
        "canonical_prefix_qualified",
        "native_restart_qualified",
        "assembly_qualified",
        "publication_authorized",
        "canonical_sidecar_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(v[key] == false, "prefix capability grants {key}");
    }
    ensure!(
        p["worker_spawned"] == false && p["archive_created"] == false,
        "prefix preflight ran entries"
    );
    Ok(())
}

pub(super) fn terminal203_release(r: &Value) -> Result<()> {
    let evidence: BoundFile = serde_json::from_value(r["released203_terminal"].clone())?;
    ensure!(
        evidence.path == Path::new(RELEASE203) && evidence.sha256 == RELEASE203_SHA,
        "prefix223 cannot release an unbound203owner"
    );
    let proof = bound_json(&evidence)?;
    ensure!(
        proof["schema"] == "jetstreamer-private-epoch203-prefix-reader-handoff-v1"
            && proof["producer_invocation_id"] == "748ffa40e0a2408da0a10fc9e160cf0a"
            && proof["producer_manager_success_proven"] == true
            && proof["producer_result_sha256"]
                == "b2e5d62548e88dd743f6abbc52d7883d78ae486e38523ae1426d0827d422fb05"
            && proof["reader_handoff_authorized"] == true,
        "203terminal proof differs"
    );
    Ok(())
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    pub(in crate::fleet) fn fixture() -> (DiagnosticClaim, Value) {
        let c = DiagnosticClaim {
            epoch: 223,
            unit: UNIT.into(),
            invocation_id: "a".repeat(32),
            scratch_path: ROOT.into(),
            launch_receipt: BoundFile {
                path: "/sealed/launch.json".into(),
                sha256: "b".repeat(64),
            },
        };
        let mut r = json!({"schema":SCHEMA,"launched":true,"epoch":223,"private_run_root":ROOT,
            "node_sha256":NODE_SHA,"worker_sha256":WORKER_SHA,"runner_sha256":RUNNER_SHA,"plan_path":PLAN,"plan_sha256":PLAN_SHA,
            "snapshot_slot":96335538,"snapshot_sha256":"301110cad7eb56ed68c99d31cf6769b7622e2c166f33aec084dc51592d0cd665",
            "runtime":"solana-v1.6.25","solana_rayon_threads":2,"output_slot_start":96336000,"output_slot_count":431523,
            "terminal_root_slot":96767522,"uncovered_suffix_slots":477,"maximum_terminal_scratch_bytes":1280u64<<30,
            "experimental_envelope_bytes":1536u64<<30,"maximum_runtime_seconds":259200,
            "required_initial_free_bytes":MINIMUM_FREE,"guard_minimum_free_bytes":GUARD_FLOOR,
            "capability":{"path":CAPABILITY,"sha256":CAPABILITY_SHA},"root_prefix_resource_attempt_authorized":true,
            "released203_terminal":{"path":RELEASE203,"sha256":RELEASE203_SHA},
            "protected203_remaining_bytes":0,"protected225_remaining_bytes":640u64<<30,
            "natural_parent_completion_required":true,"expected_exec_start":format!("{} ; ignore_errors=no }}",expected()),
            "evidence":{"units":[{"unit":UNIT,"invocation_id":c.invocation_id,"restarts":0,"load_state":"loaded",
                "result":"success","main_pid":123,"active_state":"active","sub_state":"running"}]}});
        for key in [
            "ordinary_replay_authorized",
            "canonical_prefix_independently_qualified",
            "full_cold_epoch_peak_qualified",
            "native_restart_qualified",
            "assembly_qualified",
            "runtime_promotion_authorized",
            "complete_epoch_span_covered",
            "canonical_sidecar_authorized",
            "publication_authorized",
            "remote_mutations",
            "r2_mutations",
        ] {
            r[key] = json!(false);
        }
        (c, r)
    }
    #[test]
    fn prefix_contract_does_not_borrow_tail_or_publication_or_smaller_resources() {
        let (c, r) = fixture();
        validate_diagnostic_launch(&r, &c).unwrap();
        for (key, val) in [
            ("schema", json!(tail223::SCHEMA)),
            ("node_sha256", json!("c".repeat(64))),
            ("output_slot_count", json!(432000)),
            ("terminal_root_slot", json!(96767999)),
            ("publication_authorized", json!(true)),
            ("required_initial_free_bytes", json!(MINIMUM_FREE - 1)),
            ("guard_minimum_free_bytes", json!(GUARD_FLOOR - 1)),
            ("natural_parent_completion_required", json!(false)),
        ] {
            let mut bad = r.clone();
            bad[key] = val;
            assert!(validate_diagnostic_launch(&bad, &c).is_err(), "{key}");
        }
        let mut bad = r.clone();
        bad["evidence"]["units"][0]["invocation_id"] = json!("c".repeat(32));
        assert!(validate_diagnostic_launch(&bad, &c).is_err());
        assert!(!same_command(
            &json!(format!("{} --extra ; ignore_errors=no }}", expected())),
            &r["expected_exec_start"]
        ));
        assert_eq!(MINIMUM_FREE, 248_289_182_611 + (640u64 + 1536) * (1 << 30));
        assert_eq!(GUARD_FLOOR, MINIMUM_FREE - (1280u64 + 192) * (1 << 30));
    }
}
