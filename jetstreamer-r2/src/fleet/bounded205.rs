//! Observational-only registration of the prepared epoch-205 fixed-work probe.
//! Neither registration nor a target stop qualifies a prefix, peak, or archive.
use super::*;

pub(super) const SCHEMA: &str = "jetstreamer-private-epoch205-bounded-resource-launch-v1";
pub(super) const GUARD_SHA256: &str =
    "d039ddf0b161bc554614a862bd12987bd6a3474549a22d066ebefa5584e5dd98";
const RUNNER_SHA256: &str = "e2eda507ea8c9092516eff4b724eb79b4b3ec9a040ca443e1a4ba56ccf4e3ae2";
const RUNNER: &str = "/var/lib/jetstreamer/horizon-205-bounded-preparation-candidate-v1/jetstreamer-epoch205-bounded-resource";
const FLOOR_LOWER_BOUND: u64 = 241_589_759_373;
const EXPERIMENT_BYTES: u64 = 416 << 30;
const WORK_BYTES: u64 = (256 + 128) << 30;

fn safe_suffix(suffix: &str) -> bool {
    suffix
        .as_bytes()
        .first()
        .is_some_and(u8::is_ascii_alphanumeric)
        && suffix
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
}

pub(super) fn namespace(c: &DiagnosticClaim) -> bool {
    c.epoch == 205
        && c.unit
            .strip_prefix("horizon-qualify-205-bounded-resource-")
            .and_then(|s| s.strip_suffix(".service"))
            .is_some_and(safe_suffix)
}

fn command(v: &Value) -> Option<&str> {
    v.as_str()?.split_once(" ; ignore_errors=").map(|(a, _)| a)
}

fn expected_command(r: &Value) -> Option<String> {
    let path = Path::new(r["plan_path"].as_str()?);
    let directory = path.parent()?;
    if path.file_name()? != "resource-plan.json"
        || directory.parent()? != Path::new("/var/lib/jetstreamer")
        || directory
            .file_name()?
            .to_str()?
            .strip_prefix("horizon-205-bounded-resource-")
            .is_none_or(|suffix| !safe_suffix(suffix))
        || !canonical_digest(&r["plan_sha256"])
    {
        return None;
    }
    Some(format!(
        "{{ path={RUNNER} ; argv[]={RUNNER} {} --plan-sha256 {} --self-sha256 {RUNNER_SHA256}",
        path.display(),
        r["plan_sha256"].as_str()?
    ))
}

pub(super) fn same_command(live: &Value, receipt: &Value) -> bool {
    command(live).is_some() && command(live) == command(receipt)
}

pub(super) fn launch_matches(c: &DiagnosticClaim, r: &Value) -> bool {
    namespace(c)
        && c.scratch_path.parent() == Some(Path::new("/home/ubuntu/.jetstreamer-private"))
        && c.scratch_path.file_name().and_then(|s| s.to_str())
            .and_then(|s| s.strip_prefix("bounded-resource-205-"))
            .is_some_and(safe_suffix)
        && r["schema"] == SCHEMA
        && r["epoch"] == 205
        && r["private_run_root"].as_str() == c.scratch_path.to_str()
        && r["snapshot_slot"] == 88_559_361u64
        && r["snapshot_sha256"] == "24b722b37fa87462876dc05916bafa98da13f095c95aaed7159e9008efa7352e"
        && r["node_sha256"] == "025757b9b337abf05435c427f143f590d9bfa542b5e4493aae783c158b4f2d3d"
        && r["worker_sha256"] == "3f5e8efec328b3e00dd9ce5ae396fc4067e6be6554e4da8831a13273186a748a"
        && r["runner_sha256"] == RUNNER_SHA256
        && r["runtime"] == "solana-v1.6.16"
        && r["runtime_semantics_changed"] == false
        && r["solana_rayon_threads"] == 16
        && r["output_slot_start"] == 88_560_000u64
        && r["target_slot"] == 88_584_000u64
        && r["terminal_root_slot"] == 88_991_050u64
        && r["canonical_epoch_end"] == 88_991_999u64
        && r["uncovered_suffix_slots"] == 949
        && r["maximum_scratch_bytes"] == 256u64 << 30
        && r["maximum_runtime_seconds"] == 21_600
        && r["experimental_envelope_bytes"] == EXPERIMENT_BYTES
        && r["bounded_replay_authorized"] == true
        && ["ordinary_replay_authorized", "canonical_prefix_qualified",
            "full_cold_epoch_peak_qualified", "runtime_promotion_authorized",
            "canonical_sidecar_authorized", "publication_authorized"]
            .iter().all(|key| r[*key] == false)
        // Rejection bounds only. Actual admission must bind the current century
        // census and every older invocation's remaining-growth debt separately.
        && r["required_initial_free_bytes"].as_u64()
            .is_some_and(|n| n >= FLOOR_LOWER_BOUND + EXPERIMENT_BYTES
                && n.checked_sub(WORK_BYTES) == r["guard_minimum_free_bytes"].as_u64())
        && expected_command(r).is_some_and(|expected|
            command(&r["expected_exec_start"]) == Some(expected.as_str()))
}

pub(super) fn guard_matches(c: &DiagnosticClaim, r: &Value, p: &Value) -> bool {
    launch_matches(c, r)
        && p["filesystem"] == "/"
        && p["minimum_free_bytes"] == r["guard_minimum_free_bytes"]
        && p.get("bounded_measurement").is_none_or(Value::is_null)
        && p["bounded_canary"]["expected_uid"] == 1000
        && p["bounded_canary"]["maximum_drainage_seconds"] == 180
        && p["bounded_canary"]["target_stop_intent"].as_str()
            == c.scratch_path.join("receipts/target-stop.json").to_str()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (DiagnosticClaim, Value) {
        let c = DiagnosticClaim {
            epoch: 205,
            unit: "horizon-qualify-205-bounded-resource-test.service".into(),
            invocation_id: "a".repeat(32),
            scratch_path: "/home/ubuntu/.jetstreamer-private/bounded-resource-205-test".into(),
            launch_receipt: BoundFile {
                path: "/sealed/launch.json".into(),
                sha256: "b".repeat(64),
            },
        };
        let mut r = json!({"schema":SCHEMA,"launched":true,"epoch":205,"private_run_root":c.scratch_path,
            "snapshot_slot":88559361,"snapshot_sha256":"24b722b37fa87462876dc05916bafa98da13f095c95aaed7159e9008efa7352e",
            "node_sha256":"025757b9b337abf05435c427f143f590d9bfa542b5e4493aae783c158b4f2d3d",
            "worker_sha256":"3f5e8efec328b3e00dd9ce5ae396fc4067e6be6554e4da8831a13273186a748a",
            "runner_sha256":RUNNER_SHA256,"runtime":"solana-v1.6.16","runtime_semantics_changed":false});
        r.as_object_mut().unwrap().extend(json!({
            "solana_rayon_threads":16,"output_slot_start":88560000,"target_slot":88584000,
            "terminal_root_slot":88991050,"canonical_epoch_end":88991999,"uncovered_suffix_slots":949,
            "maximum_scratch_bytes":256u64<<30,"maximum_runtime_seconds":21600,
            "experimental_envelope_bytes":EXPERIMENT_BYTES,"bounded_replay_authorized":true
        }).as_object().unwrap().clone());
        r.as_object_mut().unwrap().extend(
            json!({
                "ordinary_replay_authorized":false,"canonical_prefix_qualified":false,
                "full_cold_epoch_peak_qualified":false,"runtime_promotion_authorized":false,
                "canonical_sidecar_authorized":false,"publication_authorized":false,
                "remote_mutations":false,"r2_mutations":false
            })
            .as_object()
            .unwrap()
            .clone(),
        );
        r.as_object_mut().unwrap().extend(json!({
            "required_initial_free_bytes":3_000_000_000_000u64,
            "guard_minimum_free_bytes":3_000_000_000_000u64-WORK_BYTES,
            "plan_path":"/var/lib/jetstreamer/horizon-205-bounded-resource-test/resource-plan.json",
            "plan_sha256":"c".repeat(64),
            "evidence":{"units":[{"unit":c.unit,"invocation_id":c.invocation_id,"restarts":0,
                "load_state":"loaded","result":"success","main_pid":123,
                "active_state":"active","sub_state":"running"}]}}
        ).as_object().unwrap().clone());
        r["expected_exec_start"] = json!(format!(
            "{} ; ignore_errors=no ; pid=123 }}",
            expected_command(&r).unwrap()
        ));
        (c, r)
    }

    #[test]
    fn exact_205_canary_is_not_prefix_peak_or_publication_evidence() {
        let (c, r) = fixture();
        validate_diagnostic_launch(&r, &c).unwrap();
        for key in [
            "snapshot_sha256",
            "worker_sha256",
            "node_sha256",
            "runner_sha256",
        ] {
            let mut bad = r.clone();
            bad[key] = json!("d".repeat(64));
            assert!(validate_diagnostic_launch(&bad, &c).is_err(), "{key}");
        }
        for (key, value) in [
            (
                "schema",
                json!("jetstreamer-private-epoch203-bounded-resource-launch-v1"),
            ),
            ("launched", json!(false)),
            ("epoch", json!(203)),
            ("snapshot_slot", json!(88559362)),
            ("target_slot", json!(88991050)),
            ("terminal_root_slot", json!(88991999)),
            ("output_slot_start", json!(88559362)),
            ("canonical_epoch_end", json!(88991050)),
            ("uncovered_suffix_slots", json!(0)),
            ("runtime", json!("solana-v1.6.25")),
            ("runtime_semantics_changed", json!(true)),
            ("solana_rayon_threads", json!(1)),
            ("maximum_scratch_bytes", json!(257u64 << 30)),
            ("maximum_runtime_seconds", json!(21601)),
            ("experimental_envelope_bytes", json!(417u64 << 30)),
            (
                "required_initial_free_bytes",
                json!(FLOOR_LOWER_BOUND + EXPERIMENT_BYTES - 1),
            ),
            ("guard_minimum_free_bytes", json!(1)),
            ("plan_sha256", json!("C".repeat(64))),
            ("publication_authorized", json!(true)),
            ("ordinary_replay_authorized", json!(true)),
            ("canonical_prefix_qualified", json!(true)),
            ("full_cold_epoch_peak_qualified", json!(true)),
            ("runtime_promotion_authorized", json!(true)),
            ("canonical_sidecar_authorized", json!(true)),
            ("remote_mutations", json!(true)),
            ("r2_mutations", json!(true)),
        ] {
            let mut bad = r.clone();
            bad[key] = value;
            assert!(validate_diagnostic_launch(&bad, &c).is_err(), "{key}");
        }
        let mut bad = r.clone();
        bad["evidence"]["units"][0]["invocation_id"] = json!("b".repeat(32));
        assert!(validate_diagnostic_launch(&bad, &c).is_err());
    }

    #[test]
    fn exact_private_root_and_command_cannot_borrow_another_probe() {
        let (mut c, r) = fixture();
        for root in [
            "/tmp/bounded-resource-205-test",
            "/home/ubuntu/.jetstreamer-private/bounded-resource-203-test",
            "/home/ubuntu/.jetstreamer-private/bounded-resource-205-",
            "/home/ubuntu/.jetstreamer-private/bounded-resource-205-test;extra",
            "/home/ubuntu/.jetstreamer-private/bounded-resource-205-test extra",
        ] {
            c.scratch_path = root.into();
            let mut bad = r.clone();
            bad["private_run_root"] = json!(root);
            assert!(validate_diagnostic_launch(&bad, &c).is_err());
        }
        let (c, r) = fixture();
        for path in [
            "/tmp/resource-plan.json",
            "/var/lib/jetstreamer/horizon-203-bounded-resource-test/resource-plan.json",
            "/var/lib/jetstreamer/horizon-205-bounded-resource-/resource-plan.json",
            "/var/lib/jetstreamer/horizon-205-bounded-resource-test/capability-plan.json",
            "/var/lib/jetstreamer/horizon-205-bounded-resource-test extra/resource-plan.json",
            "/var/lib/jetstreamer/horizon-205-bounded-resource-test;extra/resource-plan.json",
        ] {
            let mut bad = r.clone();
            bad["plan_path"] = json!(path);
            assert!(validate_diagnostic_launch(&bad, &c).is_err());
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
        let (mut bad_claim, r) = fixture();
        for unit in [
            "horizon-qualify-205-bounded-resource-.service",
            "horizon-qualify-205-bounded-resource-test extra.service",
            "horizon-qualify-205-bounded-resource-test;extra.service",
            "horizon-qualify-203-bounded-resource-test.service",
        ] {
            bad_claim.unit = unit.into();
            assert!(validate_diagnostic_launch(&r, &bad_claim).is_err());
        }
    }

    #[test]
    fn guard_is_exactly_target_scoped_and_preserves_its_launch_debt() {
        let (c, r) = fixture();
        let p = json!({"filesystem":"/","minimum_free_bytes":r["guard_minimum_free_bytes"],
            "bounded_canary":{"expected_uid":1000,"maximum_drainage_seconds":180,
                "target_stop_intent":c.scratch_path.join("receipts/target-stop.json")}});
        assert!(guard_matches(&c, &r, &p));
        for (pointer, value) in [
            ("/filesystem", json!("/home/sol")),
            ("/minimum_free_bytes", json!(1)),
            ("/bounded_canary/expected_uid", json!(0)),
            ("/bounded_canary/maximum_drainage_seconds", json!(181)),
            (
                "/bounded_canary/target_stop_intent",
                json!("/other/receipts/target-stop.json"),
            ),
            ("/bounded_measurement", json!({"expected_uid":1000})),
        ] {
            let mut bad = p.clone();
            if pointer == "/bounded_measurement" {
                bad["bounded_measurement"] = value;
            } else {
                *bad.pointer_mut(pointer).unwrap() = value;
            }
            assert!(!guard_matches(&c, &r, &bad), "{pointer}");
        }
    }

    #[test]
    fn guard_dispatch_requires_the_exact_hash_bound_launch_receipt() {
        let (mut c, r) = fixture();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("launch.json");
        let bytes = serde_json::to_vec(&r).unwrap();
        std::fs::write(&path, &bytes).unwrap();
        c.launch_receipt = BoundFile {
            path: path.clone(),
            sha256: hex_lower(&Sha256::digest(&bytes)),
        };
        let p = json!({"filesystem":"/","minimum_free_bytes":r["guard_minimum_free_bytes"],
            "bounded_canary":{"expected_uid":1000,"maximum_drainage_seconds":180,
                "target_stop_intent":c.scratch_path.join("receipts/target-stop.json")}});
        assert!(diagnostic_guard_profile_matches(&c, &p));
        let mut changed = r;
        changed["target_slot"] = json!(88_991_050);
        let bytes = serde_json::to_vec(&changed).unwrap();
        std::fs::write(&path, &bytes).unwrap();
        assert!(!diagnostic_guard_profile_matches(&c, &p));
        c.launch_receipt.sha256 = hex_lower(&Sha256::digest(&bytes));
        assert!(!diagnostic_guard_profile_matches(&c, &p));
    }
}
