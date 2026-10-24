//! Registration only of the separately pinned epoch 225 shrink-cap measurement.
use super::*;

pub(super) fn namespace(c: &DiagnosticClaim) -> bool {
    c.epoch == 225
        && c.unit
            .starts_with("horizon-qualify-225-bounded-resource-shrink-budget-")
        && c.unit.ends_with(".service")
}
fn command(v: &Value) -> Option<&str> {
    v.as_str()?.split_once(" ; ignore_errors=").map(|(a, _)| a)
}
fn expected_command() -> String {
    let root = "/var/lib/jetstreamer/horizon-225-shrink-budget-d86d4a2-v1";
    let binary = format!("{root}/jetstreamer-epoch225-shrink-budget-resource");
    format!(
        "{{ path={binary} ; argv[]={binary} {root}/resource-plan.json --plan-sha256 7c6a7866a3fb1a7e253ef2f07fc55f7d59c6127f7cf9f8971622d96baa2e06db --self-sha256 de5c798b324254f0d656702fecc1cb9602c90c1f30c1fc7b075965a1bab5cf67"
    )
}
pub(super) fn same_command(live: &Value, receipt: &Value) -> bool {
    command(live).is_some_and(|s| s == expected_command()) && command(live) == command(receipt)
}
pub(super) fn launch_matches(c: &DiagnosticClaim, r: &Value) -> bool {
    namespace(c)
        && c.scratch_path
            == Path::new(
                "/home/ubuntu/.jetstreamer-private/bounded-resource-225-shrink-budget-d86d4a2-v1",
            )
        && r["epoch"] == 225
        && r["private_run_root"].as_str() == c.scratch_path.to_str()
        && r["snapshot_slot"] == 97_199_617u64
        && r["snapshot_sha256"]
            == "094d3b28c39403580fbac083cdad67cc008b255dd375d611217103750d0f412d"
        && r["worker_sha256"] == "2dcc9b84a6ce27edba3d3b053c6e6170f66a2337f12a5aae54900c3ad9e2eedd"
        && r["node_sha256"] == "3915f57819e5822e7112ee1932dc47caf5e9812605ad56cc309976e4f681f242"
        && r["runner_sha256"] == "de5c798b324254f0d656702fecc1cb9602c90c1f30c1fc7b075965a1bab5cf67"
        && r["plan_sha256"] == "7c6a7866a3fb1a7e253ef2f07fc55f7d59c6127f7cf9f8971622d96baa2e06db"
        && r["runtime"] == "solana-v1.6.25"
        && r["runtime_semantics_changed"] == false
        && r["storage_maintenance_changed"] == true
        && r["upstream_shrink_budget_cap"] == true
        && r["solana_rayon_threads"] == 16
        && r["target_slot"] == 97_202_500u64
        && r["terminal_root_slot"] == 97_631_459u64
        && r["maximum_terminal_scratch_bytes"] == 256u64 << 30
        && r["maximum_runtime_seconds"] == 3600
        && r["minimum_start_free_bytes"] == 3_185_678_193_366u64
        && r["bounded_replay_authorized"] == true
        && [
            "ordinary_replay_authorized",
            "full_cold_epoch_peak_qualified",
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
    fn exact_candidate_is_not_a_baseline_alias_or_publication_gate() {
        let c = DiagnosticClaim {
            epoch: 225,
            unit: "horizon-qualify-225-bounded-resource-shrink-budget-d86d4a2-v1.service".into(),
            invocation_id: "a".repeat(32),
            scratch_path:
                "/home/ubuntu/.jetstreamer-private/bounded-resource-225-shrink-budget-d86d4a2-v1"
                    .into(),
            launch_receipt: BoundFile {
                path: "/sealed/launch.json".into(),
                sha256: "b".repeat(64),
            },
        };
        let r = json!({"schema":"jetstreamer-private-epoch225-shrink-budget-resource-launch-v1","launched":true,"epoch":225,"private_run_root":c.scratch_path,"snapshot_slot":97199617,"snapshot_sha256":"094d3b28c39403580fbac083cdad67cc008b255dd375d611217103750d0f412d","worker_sha256":"2dcc9b84a6ce27edba3d3b053c6e6170f66a2337f12a5aae54900c3ad9e2eedd","node_sha256":"3915f57819e5822e7112ee1932dc47caf5e9812605ad56cc309976e4f681f242","runner_sha256":"de5c798b324254f0d656702fecc1cb9602c90c1f30c1fc7b075965a1bab5cf67","plan_sha256":"7c6a7866a3fb1a7e253ef2f07fc55f7d59c6127f7cf9f8971622d96baa2e06db","runtime":"solana-v1.6.25","runtime_semantics_changed":false,"storage_maintenance_changed":true,"upstream_shrink_budget_cap":true,"solana_rayon_threads":16,"target_slot":97202500,"terminal_root_slot":97631459,"maximum_terminal_scratch_bytes":256u64<<30,"maximum_runtime_seconds":3600,"minimum_start_free_bytes":3185678193366u64,"bounded_replay_authorized":true,"ordinary_replay_authorized":false,"full_cold_epoch_peak_qualified":false,"runtime_promotion_authorized":false,"canonical_sidecar_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false,"expected_exec_start":format!("{} ; ignore_errors=no ; pid=0 }}",expected_command()),"evidence":{"units":[{"unit":c.unit,"invocation_id":c.invocation_id,"restarts":0,"load_state":"loaded","result":"success","main_pid":123,"active_state":"active","sub_state":"running"}]}});
        validate_diagnostic_launch(&r, &c).unwrap();
        for key in [
            "worker_sha256",
            "node_sha256",
            "runner_sha256",
            "plan_sha256",
            "snapshot_sha256",
        ] {
            let mut bad = r.clone();
            bad[key] = json!("c".repeat(64));
            assert!(validate_diagnostic_launch(&bad, &c).is_err(), "{key}");
        }
        for (key, value) in [
            ("target_slot", json!(97202501)),
            ("maximum_runtime_seconds", json!(3601)),
            ("maximum_terminal_scratch_bytes", json!(257u64 << 30)),
            ("publication_authorized", json!(true)),
            ("upstream_shrink_budget_cap", json!(false)),
            (
                "schema",
                json!("jetstreamer-private-epoch225-v1625-bounded-launch-v1"),
            ),
        ] {
            let mut bad = r.clone();
            bad[key] = value;
            assert!(validate_diagnostic_launch(&bad, &c).is_err(), "{key}");
        }
        let mut baseline_alias = r.clone();
        baseline_alias["schema"] = json!("jetstreamer-private-epoch225-bounded-resource-launch-v1");
        baseline_alias["worker_sha256"] =
            json!("f39140b9a9659e7c6e8207076a2d0c560a6b69df42cc92e19a421cf46c2b761c");
        assert!(validate_diagnostic_launch(&baseline_alias, &c).is_err());
        assert!(same_command(
            &r["expected_exec_start"],
            &json!(format!(
                "{} ; ignore_errors=no ; pid=99 }}",
                expected_command()
            ))
        ));
        assert!(!same_command(
            &r["expected_exec_start"],
            &json!(format!(
                "{} --extra ; ignore_errors=no }}",
                expected_command()
            ))
        ));
    }
}
