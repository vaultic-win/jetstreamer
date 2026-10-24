//! Observational-only registration of the exact first epoch 227 upstream canary.
//! Target completion is transport evidence, never a canonical checkpoint/archive.
use super::*;

pub(super) const SCHEMA: &str = "jetstreamer-private-epoch227-v1625-comparison-launch-v1";
pub(super) const UNIT: &str =
    "horizon-qualify-227-v1625-bounded-resource-d01adb19-selection-v2.service";
pub(super) const ROOT: &str =
    "/home/ubuntu/.jetstreamer-private/bounded-resource-227-v1625-d01adb19-selection-v2";
pub(super) const NODE: &str =
    "/var/lib/jetstreamer/horizon-227-v1625-selection-parent-v2/jetstreamer-node";
pub(super) const NODE_SHA: &str =
    "79963ff4872ad7470acced6b04b944a8744ec2de2acccd6d6e843584fcddcb92";
pub(super) const WORKER: &str = "/var/lib/jetstreamer/horizon-227-v1625-diagnostic-d01adb19-v1/jetstreamer-historical-worker-v1-6-25";
pub(super) const WORKER_SHA: &str =
    "d01adb1980ee52a59a7aff7a3a0496746ca325e5fc655817d9a7743a1913ef62";
pub(super) const RUNNER: &str = "/var/lib/jetstreamer/horizon-227-v1625-selection-runner-v2/jetstreamer-epoch227-v1625-bounded-resource";
pub(super) const RUNNER_SHA: &str =
    "81a804e354fdb986d46ad847f9c687131513baee7858687be85eeb65a72b8500";
pub(super) const GUARD: &str = "/var/lib/jetstreamer/horizon-227-v1625-canary-guard-90e6fe78-v1/jetstreamer-horizon-standalone-guard";
pub(super) const GUARD_SHA: &str =
    "90e6fe78049664cd4da8f62a9a02c75056d63ac73ae2edc11c200039b5079d89";
pub(super) const INPUT: &str = "/var/lib/jetstreamer/horizon-stage227-bootstrap-dcaafc6-v1";
pub(super) const SNAPSHOT: &str = "/var/lib/jetstreamer/horizon-stage227-bootstrap-dcaafc6-v1/snapshot-98063464-4TaJaC5esCEWtHp5Fay2aMS9XjA1o9bwQthcvBeSyYbR.tar.zst";
pub(super) const SNAPSHOT_SHA: &str =
    "77e5b3bbb733d9ab3b2383c1ad9f1d7ef4062aedacbe9e2326927512c4b95e07";
pub(super) const GENESIS_SHA: &str =
    "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945";
pub(super) const NATIVE: &str =
    "/var/lib/jetstreamer/horizon-native227-v1625-terminal-proof-small-v2/proof.json";
pub(super) const NATIVE_READONLY: &str =
    "/var/lib/jetstreamer/horizon-227-v1625-native-qualified-input-readonly-v1/native-proof.json";
pub(super) const NATIVE_SHA: &str =
    "da6e00906c266f5993e0332b2abb864558db4ab4c0786d765d1828e658675d7b";
pub(super) const NATIVE_ORIGIN: &str =
    "/var/lib/jetstreamer/horizon-227-v1625-native-capture-small-v2/intent.json";
pub(super) const NATIVE_ORIGIN_SHA: &str =
    "0b363d7f7f63854f69d6d6681daad0205ed9f68bc395a08aa30bf1759cca1d8f";
pub(super) const ORIGINAL_LAUNCH: &str =
    "/var/lib/jetstreamer/horizon-227-capture-full330-v1/launch.json";
pub(super) const ORIGINAL_LAUNCH_SHA: &str =
    "12eb6beb36d13e9c35c26280908f3fe6df9f2489eedfc59d4ced6a094997172d";
pub(super) const ORIGINAL_JOURNAL: &str =
    "/var/lib/jetstreamer/horizon-full227-failure-a10f37b5-v1/journal.json";
pub(super) const ORIGINAL_JOURNAL_SHA: &str =
    "97b9b039efb30bb8c209a4b60c2519908068cd905d78f313a4ee2bf7fad8cb5e";
pub(super) const ORIGINAL_IID: &str = "a10f37b57711425a81633c62c66438d5";
pub(super) const MEMORY: u64 = 225_000_000_000;
pub(super) const HIGH: u64 = 150_000_000_000;
pub(super) const SCRATCH: u64 = 300_000_000_000;
pub(super) const CONTROL_METADATA: u64 = 16 << 20;
pub(super) const CANDIDATE: u64 = SCRATCH + CONTROL_METADATA;
pub(super) const BOOTSTRAP: u64 = 98_063_464;
pub(super) const TARGET: u64 = 98_091_122;
pub(super) const TERMINAL: u64 = 98_495_291;
pub(super) const FLOOR_LOWER_BOUND: u64 = 245_383_154_903;
pub(super) const RUNTIME_MAX: u64 = 21_600;
pub(super) const ACCOUNTS: &str = "4TaJaC5esCEWtHp5Fay2aMS9XjA1o9bwQthcvBeSyYbR";

fn safe_suffix(s: &str) -> bool {
    s.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric)
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
}
fn immutable_binding(v: &Value, path: &str, sha: &str) -> bool {
    v == &json!({"path":path,"sha256":sha})
}
fn package_binding(v: &Value, prefix: &str, leaf: &str) -> bool {
    let Some(raw) = v["path"].as_str() else {
        return false;
    };
    let path = Path::new(raw);
    v.as_object().is_some_and(|m| m.len() == 2)
        && canonical_digest(&v["sha256"])
        && path.file_name().is_some_and(|n| n == leaf)
        && path.parent().and_then(Path::parent) == Some(Path::new("/var/lib/jetstreamer"))
        && path
            .parent()
            .and_then(Path::file_name)
            .and_then(|n| n.to_str())
            .and_then(|n| n.strip_prefix(prefix))
            .is_some_and(safe_suffix)
        && !raw.contains("//")
        && !raw.contains("/./")
        && !raw.contains("/../")
}
fn capability_binding(v: &Value) -> bool {
    let Some(raw) = v["path"].as_str() else {
        return false;
    };
    let path = Path::new(raw);
    let root = path.parent().and_then(Path::parent);
    v.as_object().is_some_and(|m| m.len() == 2)
        && canonical_digest(&v["sha256"])
        && path.file_name().is_some_and(|n| n == "capability.json")
        && path
            .parent()
            .and_then(Path::file_name)
            .is_some_and(|n| n == "receipts")
        && root.and_then(Path::parent) == Some(Path::new("/home/ubuntu/.jetstreamer-private"))
        && root
            .and_then(Path::file_name)
            .and_then(|n| n.to_str())
            .and_then(|n| n.strip_prefix("bounded-resource-227-v1625-"))
            .is_some_and(safe_suffix)
        && root != Some(Path::new(ROOT))
        && !raw.contains("//")
        && !raw.contains("/./")
        && !raw.contains("/../")
}
pub(super) fn namespace(c: &DiagnosticClaim) -> bool {
    c.epoch == 227 && c.unit == UNIT && c.scratch_path == Path::new(ROOT)
}
fn command(v: &Value) -> Option<&str> {
    v.as_str()?.split_once(" ; ignore_errors=").map(|(a, _)| a)
}
pub(super) fn expected_command(r: &Value) -> Option<String> {
    let b = &r["resource_plan"];
    if !package_binding(
        b,
        "horizon-227-v1625-canary-resource-",
        "resource-plan.json",
    ) {
        return None;
    }
    Some(format!(
        "{{ path={RUNNER} ; argv[]={RUNNER} {} --plan-sha256 {} --self-sha256 {RUNNER_SHA}",
        b["path"].as_str()?,
        b["sha256"].as_str()?
    ))
}
pub(super) fn same_command(a: &Value, b: &Value) -> bool {
    command(a).is_some() && command(a) == command(b)
}
pub(super) fn launch_matches(c: &DiagnosticClaim, r: &Value) -> bool {
    namespace(c)
        && r["schema"] == SCHEMA
        && r["launched"] == true
        && r["epoch"] == 227
        && r["private_run_root"] == ROOT
        && immutable_binding(&r["node"], NODE, NODE_SHA)
        && r["node_sha256"] == NODE_SHA
        && immutable_binding(&r["worker"], WORKER, WORKER_SHA)
        && r["worker_sha256"] == WORKER_SHA
        && immutable_binding(&r["runner"], RUNNER, RUNNER_SHA)
        && r["runner_sha256"] == RUNNER_SHA
        && immutable_binding(&r["guard"], GUARD, GUARD_SHA)
        && immutable_binding(&r["snapshot"], SNAPSHOT, SNAPSHOT_SHA)
        && r["snapshot_sha256"] == SNAPSHOT_SHA
        && immutable_binding(&r["native_input_proof"], NATIVE, NATIVE_SHA)
        && immutable_binding(
            &r["readonly_native_input_proof"],
            NATIVE_READONLY,
            NATIVE_SHA,
        )
        && immutable_binding(
            &r["native_running_origin"],
            NATIVE_ORIGIN,
            NATIVE_ORIGIN_SHA,
        )
        && immutable_binding(
            &r["original_failed_launch"],
            ORIGINAL_LAUNCH,
            ORIGINAL_LAUNCH_SHA,
        )
        && immutable_binding(
            &r["original_failure_journal"],
            ORIGINAL_JOURNAL,
            ORIGINAL_JOURNAL_SHA,
        )
        && r["original_failed_invocation_id"] == ORIGINAL_IID
        && r["preserve_original_failed227_history"] == true
        && r["repair_gate_state"] == "failed-needs-repair"
        && package_binding(
            &r["fresh_resource_admission"],
            "horizon-227-v1625-canary-admission-",
            "admission.json",
        )
        && capability_binding(&r["input_capability"])
        && r["fresh_complete_resource_admission_passed"] == true
        && r["input_capability_passed"] == true
        && r["native_input_qualified"] == true
        && r["runtime"] == "solana-v1.6.25"
        && r["runtime_revision"] == "7de8a55b54d3e11058b82f9483bb405d143b455c"
        && r["snapshot_slot"] == BOOTSTRAP
        && r["snapshot_accounts_hash"] == ACCOUNTS
        && r["worker_entry_start"] == BOOTSTRAP + 1
        && r["worker_entry_end_exclusive"] == TARGET + 1
        && r["output_slot_start"] == 98_064_000u64
        && r["target_slot"] == TARGET
        && r["terminal_root_slot"] == TERMINAL
        && r["canonical_checkpoint_slots"] == json!([BOOTSTRAP, TERMINAL])
        && r["controlled_target_is_checkpoint"] == false
        && r["target_stop_protocol"] == "cooperative-resume-only"
        && r["maximum_scratch_bytes"] == SCRATCH
        && r["maximum_root_physical_bytes"] == SCRATCH
        && r["control_metadata_bytes"] == CONTROL_METADATA
        && r["candidate_incremental_peak_bytes"] == CANDIDATE
        && r["experimental_envelope_bytes"] == CANDIDATE
        && r["maximum_memory_bytes"] == MEMORY
        && r["memory_high_bytes"] == HIGH
        && r["cpu_quota_cores"] == 8
        && r["solana_rayon_threads"] == 8
        && r["historical_poh_threads"] == 2
        && r["rust_min_stack_bytes"] == 67_108_864u64
        && r["maximum_runtime_seconds"] == RUNTIME_MAX
        && r["bounded_replay_authorized"] == true
        && [
            "ordinary_replay_authorized",
            "replay_launch_authorized",
            "full_epoch_qualified",
            "full_cold_epoch_peak_qualified",
            "canonical_prefix_qualified",
            "full_verification_qualified",
            "current_plugin_qualified",
            "runtime_promotion_authorized",
            "canonical_sidecar_authorized",
            "publication_authorized",
            "remote_mutations",
            "r2_mutations",
        ]
        .iter()
        .all(|key| r[*key] == false)
        && r["guard_minimum_free_bytes"].as_u64().is_some_and(|floor| {
            floor >= FLOOR_LOWER_BOUND
                && floor.checked_add(CANDIDATE) == r["required_initial_free_bytes"].as_u64()
        })
        && expected_command(r)
            .is_some_and(|expected| command(&r["expected_exec_start"]) == Some(expected.as_str()))
}
pub(super) fn guard_matches(c: &DiagnosticClaim, r: &Value, p: &Value) -> bool {
    launch_matches(c, r)
        && p["schema"] == "jetstreamer-horizon-standalone-guard-plan-v1"
        && p["unit"] == UNIT
        && p["invocation_id"] == c.invocation_id
        && p["filesystem"] == "/"
        && p["worker_root"] == ROOT
        && p["minimum_free_bytes"] == r["guard_minimum_free_bytes"]
        && p["maximum_root_physical_bytes"] == SCRATCH
        && p["maximum_worker_vmas"] == 3_500_000
        && p.get("native_main").is_none_or(Value::is_null)
        && p.get("bounded_measurement").is_none_or(Value::is_null)
        && p["bounded_canary"]["expected_uid"] == 1000
        && p["bounded_canary"]["maximum_drainage_seconds"] == 120
        && p["bounded_canary"]["target_stop_intent"]
            == Path::new(ROOT)
                .join("receipts/target-stop.json")
                .to_str()
                .unwrap()
}

#[cfg(test)]
pub(super) fn peer_fixture() -> (DiagnosticClaim, Value) {
    tests::fixture()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding(path: &str, sha: &str) -> Value {
        json!({"path":path,"sha256":sha})
    }

    pub(super) fn fixture() -> (DiagnosticClaim, Value) {
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
        let mut r = json!({"schema":SCHEMA,"launched":true,"epoch":227,"private_run_root":ROOT,
            "node_sha256":NODE_SHA,"worker_sha256":WORKER_SHA,"runner_sha256":RUNNER_SHA,
            "snapshot_sha256":SNAPSHOT_SHA,"original_failed_invocation_id":ORIGINAL_IID,
            "preserve_original_failed227_history":true,"repair_gate_state":"failed-needs-repair",
            "fresh_complete_resource_admission_passed":true,"input_capability_passed":true,
            "native_input_qualified":true,"runtime":"solana-v1.6.25",
            "runtime_revision":"7de8a55b54d3e11058b82f9483bb405d143b455c",
            "snapshot_slot":BOOTSTRAP,"snapshot_accounts_hash":ACCOUNTS,
            "worker_entry_start":BOOTSTRAP+1,"worker_entry_end_exclusive":TARGET+1,
            "output_slot_start":98_064_000u64,"target_slot":TARGET,"terminal_root_slot":TERMINAL,
            "canonical_checkpoint_slots":[BOOTSTRAP,TERMINAL],"controlled_target_is_checkpoint":false,
            "target_stop_protocol":"cooperative-resume-only","maximum_scratch_bytes":SCRATCH,
            "maximum_root_physical_bytes":SCRATCH,"control_metadata_bytes":CONTROL_METADATA,
            "candidate_incremental_peak_bytes":CANDIDATE,"experimental_envelope_bytes":CANDIDATE,
            "maximum_memory_bytes":MEMORY,"memory_high_bytes":HIGH,"cpu_quota_cores":8,
            "solana_rayon_threads":8,"historical_poh_threads":2,"rust_min_stack_bytes":67_108_864u64,
            "maximum_runtime_seconds":RUNTIME_MAX,"bounded_replay_authorized":true,
            "guard_minimum_free_bytes":FLOOR_LOWER_BOUND,
            "required_initial_free_bytes":FLOOR_LOWER_BOUND+CANDIDATE});
        for (key, path, sha) in [
            ("node", NODE, NODE_SHA),
            ("worker", WORKER, WORKER_SHA),
            ("runner", RUNNER, RUNNER_SHA),
            ("guard", GUARD, GUARD_SHA),
            ("snapshot", SNAPSHOT, SNAPSHOT_SHA),
            ("native_input_proof", NATIVE, NATIVE_SHA),
            ("readonly_native_input_proof", NATIVE_READONLY, NATIVE_SHA),
            ("native_running_origin", NATIVE_ORIGIN, NATIVE_ORIGIN_SHA),
            (
                "original_failed_launch",
                ORIGINAL_LAUNCH,
                ORIGINAL_LAUNCH_SHA,
            ),
            (
                "original_failure_journal",
                ORIGINAL_JOURNAL,
                ORIGINAL_JOURNAL_SHA,
            ),
        ] {
            r[key] = binding(path, sha);
        }
        for key in [
            "ordinary_replay_authorized",
            "replay_launch_authorized",
            "full_epoch_qualified",
            "full_cold_epoch_peak_qualified",
            "canonical_prefix_qualified",
            "full_verification_qualified",
            "current_plugin_qualified",
            "runtime_promotion_authorized",
            "canonical_sidecar_authorized",
            "publication_authorized",
            "remote_mutations",
            "r2_mutations",
        ] {
            r[key] = json!(false);
        }
        r["resource_plan"] = binding(
            "/var/lib/jetstreamer/horizon-227-v1625-canary-resource-test/resource-plan.json",
            &"c".repeat(64),
        );
        r["fresh_resource_admission"] = binding(
            "/var/lib/jetstreamer/horizon-227-v1625-canary-admission-test/admission.json",
            &"d".repeat(64),
        );
        r["input_capability"] = binding(
            "/home/ubuntu/.jetstreamer-private/bounded-resource-227-v1625-capability-test/receipts/capability.json",
            &"e".repeat(64),
        );
        r["expected_exec_start"] = json!(format!(
            "{} ; ignore_errors=no ; pid=123 }}",
            expected_command(&r).unwrap()
        ));
        (c, r)
    }

    #[test]
    fn exact_launch_requires_every_binding_and_gate() {
        let (c, r) = fixture();
        assert!(launch_matches(&c, &r));
        // Deleting any required field must fail closed, including false authority fields.
        for key in r.as_object().unwrap().keys() {
            let mut bad = r.clone();
            bad.as_object_mut().unwrap().remove(key);
            assert!(!launch_matches(&c, &bad), "missing {key}");
        }
        for (key, value) in [
            ("target_slot", json!(TARGET + 1)),
            (
                "canonical_checkpoint_slots",
                json!([BOOTSTRAP, TARGET, TERMINAL]),
            ),
            ("controlled_target_is_checkpoint", json!(true)),
            ("maximum_scratch_bytes", json!(SCRATCH + 1)),
            (
                "required_initial_free_bytes",
                json!(FLOOR_LOWER_BOUND + CANDIDATE - 1),
            ),
            ("guard_minimum_free_bytes", json!(FLOOR_LOWER_BOUND - 1)),
            ("target_stop_protocol", json!("sigint")),
            ("repair_gate_state", json!("repaired")),
            ("original_failed_invocation_id", json!("f".repeat(32))),
            ("publication_authorized", json!(true)),
            ("full_epoch_qualified", json!(true)),
        ] {
            let mut bad = r.clone();
            bad[key] = value;
            assert!(!launch_matches(&c, &bad), "{key}");
        }
        for key in [
            "node",
            "worker",
            "runner",
            "guard",
            "snapshot",
            "native_input_proof",
            "readonly_native_input_proof",
            "native_running_origin",
            "original_failed_launch",
            "original_failure_journal",
        ] {
            let mut bad = r.clone();
            bad[key]["sha256"] = json!("f".repeat(64));
            assert!(!launch_matches(&c, &bad), "{key}");
        }
    }

    #[test]
    fn private_namespace_and_package_paths_cannot_escape_or_borrow_live_root() {
        let (mut c, r) = fixture();
        c.unit = "horizon-qualify-227-v1625-bounded-resource-another.service".into();
        assert!(!launch_matches(&c, &r));
        let (mut c, r) = fixture();
        c.scratch_path = "/tmp/canary227".into();
        assert!(!launch_matches(&c, &r));
        let (c, r) = fixture();
        for (key, path) in [
            (
                "resource_plan",
                "/var/lib/jetstreamer/horizon-227-v1625-canary-resource-x/../resource-plan.json",
            ),
            (
                "resource_plan",
                "/var/lib/jetstreamer/horizon-227-v1625-canary-resource-x extra/resource-plan.json",
            ),
            (
                "fresh_resource_admission",
                "/tmp/horizon-227-v1625-canary-admission-test/admission.json",
            ),
            (
                "input_capability",
                "/home/ubuntu/.jetstreamer-private/bounded-resource-227-v1625-d01adb19-selection-v2/receipts/capability.json",
            ),
            (
                "input_capability",
                "/home/ubuntu/.jetstreamer-private/bounded-resource-227-v1625-test/./receipts/capability.json",
            ),
        ] {
            let mut bad = r.clone();
            bad[key]["path"] = json!(path);
            assert!(!launch_matches(&c, &bad), "{path}");
        }
        assert!(same_command(
            &r["expected_exec_start"],
            &json!(format!(
                "{} ; ignore_errors=no ; pid=999 }}",
                expected_command(&r).unwrap()
            ))
        ));
        assert!(!same_command(
            &r["expected_exec_start"],
            &json!(format!(
                "{} --extra ; ignore_errors=no }}",
                expected_command(&r).unwrap()
            ))
        ));
        assert!(!same_command(&Value::Null, &Value::Null));
    }

    #[test]
    fn guard_owns_exact_target_root_and_invocation_without_competing_capture() {
        let (c, r) = fixture();
        let p = json!({"schema":"jetstreamer-horizon-standalone-guard-plan-v1","unit":UNIT,
            "invocation_id":c.invocation_id,"filesystem":"/","worker_root":ROOT,
            "minimum_free_bytes":FLOOR_LOWER_BOUND,"maximum_root_physical_bytes":SCRATCH,
            "maximum_worker_vmas":3_500_000,"native_main":null,"bounded_measurement":null,
            "bounded_canary":{"expected_uid":1000,"maximum_drainage_seconds":120,
            "target_stop_intent":Path::new(ROOT).join("receipts/target-stop.json")}});
        assert!(guard_matches(&c, &r, &p));
        for (pointer, value) in [
            ("/invocation_id", json!("b".repeat(32))),
            ("/worker_root", json!("/tmp/other")),
            ("/maximum_root_physical_bytes", json!(SCRATCH + 1)),
            ("/maximum_worker_vmas", json!(3_500_001)),
            ("/native_main", json!({"uid":1000})),
            ("/bounded_measurement", json!({"uid":1000})),
            ("/bounded_canary/expected_uid", json!(0)),
            ("/bounded_canary/maximum_drainage_seconds", json!(121)),
            (
                "/bounded_canary/target_stop_intent",
                json!("/tmp/target-stop.json"),
            ),
        ] {
            let mut bad = p.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(!guard_matches(&c, &r, &bad), "{pointer}");
        }
    }
}
