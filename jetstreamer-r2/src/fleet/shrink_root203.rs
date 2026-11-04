//! Observational registration of the exact private capped-shrink root diagnostic.
use super::*;

pub(super) fn namespace(c: &DiagnosticClaim) -> bool {
    c.epoch == 203
        && c.unit
            .starts_with("horizon-qualify-203-shrink-root-prefix-resource-")
        && c.unit.ends_with(".service")
}

fn command(v: &Value) -> Option<&str> {
    // systemd's rendered execution timestamps/PID reset on daemon-reload.
    // Compare all immutable path/argv bytes, not those transient report fields.
    v.as_str()?.split_once(" ; ignore_errors=").map(|(a, _)| a)
}

fn expected_command() -> String {
    let root = "/var/lib/jetstreamer/horizon-203-shrink-root-f9fc5a0-v1";
    let binary = format!("{root}/jetstreamer-epoch203-shrink-root-prefix-resource");
    format!(
        "{{ path={binary} ; argv[]={binary} {root}/resource-plan.json --plan-sha256 41ac825f183f6e9f1888152ae36430af76cdd04e81a21475aad87bc72f67fb18 --self-sha256 7b6406fd2d0c36a1469cc3fef98cd647f54ae35764f3e82f9e2a395da8f42464"
    )
}

pub(super) fn same_command(live: &Value, receipt: &Value) -> bool {
    command(live).is_some_and(|s| s == expected_command()) && command(live) == command(receipt)
}

pub(super) fn launch_matches(c: &DiagnosticClaim, r: &Value) -> bool {
    namespace(c)
        && c.scratch_path.parent() == Some(Path::new("/home/ubuntu/.jetstreamer-private"))
        && c.scratch_path
            .file_name()
            .and_then(|s| s.to_str())
            .is_some_and(|s| s.starts_with("shrink-root-prefix-resource-203-"))
        && r["epoch"] == 203
        && r["private_run_root"].as_str() == c.scratch_path.to_str()
        && r["snapshot_slot"] == 87_695_515u64
        && r["snapshot_sha256"]
            == "e45584858d0c825f095a43ff5e5909e62a68d197d39c042a76727454525228c4"
        && r["worker_sha256"] == "4aeca56378a4bb2c55d0e590c1e334c4afa6a375a2c0d94894b412bea261f1cc"
        && r["node_sha256"] == "025757b9b337abf05435c427f143f590d9bfa542b5e4493aae783c158b4f2d3d"
        && r["runner_sha256"] == "7b6406fd2d0c36a1469cc3fef98cd647f54ae35764f3e82f9e2a395da8f42464"
        && r["plan_sha256"] == "41ac825f183f6e9f1888152ae36430af76cdd04e81a21475aad87bc72f67fb18"
        && r["runtime"] == "solana-v1.6.16"
        && r["runtime_semantics_changed"] == false
        && r["storage_maintenance_changed"] == true
        && r["upstream_shrink_budget_cap"] == true
        && r["solana_rayon_threads"] == 16
        && r["output_slot_start"] == 87_696_000u64
        && r["output_slot_count"] == 431_581u64
        && r["terminal_root_slot"] == 88_127_580u64
        && r["natural_parent_completion_required"] == true
        && r["maximum_terminal_scratch_bytes"] == 768u64 << 30
        && r["maximum_runtime_seconds"] == 259200u64
        && r["root_prefix_resource_attempt_authorized"] == true
        && [
            "canonical_prefix_independently_qualified",
            "full_cold_epoch_peak_qualified",
            "ordinary_replay_authorized",
            "runtime_promotion_authorized",
            "canonical_sidecar_authorized",
            "publication_authorized",
        ]
        .iter()
        .all(|k| r[*k] == false)
        && command(&r["expected_exec_start"]).is_some_and(|s| s == expected_command())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_new_profile_is_observational_not_a_baseline_alias_or_publication_gate() {
        let c = DiagnosticClaim {
            epoch: 203,
            unit: "horizon-qualify-203-shrink-root-prefix-resource-test.service".into(),
            invocation_id: "a".repeat(32),
            scratch_path: "/home/ubuntu/.jetstreamer-private/shrink-root-prefix-resource-203-test"
                .into(),
            launch_receipt: BoundFile {
                path: "/sealed/launch.json".into(),
                sha256: "b".repeat(64),
            },
        };
        let mut r = json!({"schema":"jetstreamer-private-epoch203-shrink-root-prefix-resource-launch-v1","launched":true,"epoch":203,
            "private_run_root":c.scratch_path,"snapshot_slot":87695515,
            "snapshot_sha256":"e45584858d0c825f095a43ff5e5909e62a68d197d39c042a76727454525228c4",
            "worker_sha256":"4aeca56378a4bb2c55d0e590c1e334c4afa6a375a2c0d94894b412bea261f1cc",
            "node_sha256":"025757b9b337abf05435c427f143f590d9bfa542b5e4493aae783c158b4f2d3d",
            "runner_sha256":"7b6406fd2d0c36a1469cc3fef98cd647f54ae35764f3e82f9e2a395da8f42464",
            "plan_sha256":"41ac825f183f6e9f1888152ae36430af76cdd04e81a21475aad87bc72f67fb18"});
        r.as_object_mut().unwrap().extend(json!({
            "runtime":"solana-v1.6.16","runtime_semantics_changed":false,"storage_maintenance_changed":true,"upstream_shrink_budget_cap":true,
            "solana_rayon_threads":16,"output_slot_start":87696000,"output_slot_count":431581,"terminal_root_slot":88127580,
            "natural_parent_completion_required":true,"maximum_terminal_scratch_bytes":768u64<<30,"maximum_runtime_seconds":259200,
            "root_prefix_resource_attempt_authorized":true,"canonical_prefix_independently_qualified":false,"full_cold_epoch_peak_qualified":false
        }).as_object().unwrap().clone());
        r.as_object_mut().unwrap().extend(json!({
            "ordinary_replay_authorized":false,"runtime_promotion_authorized":false,"canonical_sidecar_authorized":false,"publication_authorized":false,
            "remote_mutations":false,"r2_mutations":false,"expected_exec_start":format!("{} ; ignore_errors=no ; start_time=[n/a] }}",expected_command()),
            "evidence":{"units":[{"unit":c.unit,"invocation_id":c.invocation_id,"restarts":0,"load_state":"loaded","result":"success",
                "main_pid":123,"active_state":"active","sub_state":"running"}]}}).as_object().unwrap().clone());
        validate_diagnostic_launch(&r, &c).unwrap();
        for key in [
            "worker_sha256",
            "runner_sha256",
            "plan_sha256",
            "node_sha256",
            "snapshot_sha256",
        ] {
            let mut bad = r.clone();
            bad[key] = json!("c".repeat(64));
            assert!(validate_diagnostic_launch(&bad, &c).is_err(), "{key}");
        }
        for (key, value) in [
            ("publication_authorized", json!(true)),
            ("terminal_root_slot", json!(88127999)),
            ("canonical_prefix_independently_qualified", json!(true)),
            ("maximum_terminal_scratch_bytes", json!(769u64 << 30)),
            ("upstream_shrink_budget_cap", json!(false)),
            ("runtime_semantics_changed", json!(true)),
        ] {
            let mut bad = r.clone();
            bad[key] = value;
            assert!(validate_diagnostic_launch(&bad, &c).is_err(), "{key}");
        }
        let mut bad = r.clone();
        bad["schema"] = json!("jetstreamer-private-epoch203-root-prefix-resource-launch-v1");
        assert!(validate_diagnostic_launch(&bad, &c).is_err());
        assert!(same_command(
            &r["expected_exec_start"],
            &json!(format!(
                "{} ; ignore_errors=no ; pid=999 }}",
                expected_command()
            ))
        ));
        assert!(!same_command(
            &json!(format!(
                "{} --extra ; ignore_errors=no }}",
                expected_command()
            )),
            &r["expected_exec_start"]
        ));
    }
}
