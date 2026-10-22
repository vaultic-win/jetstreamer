//! Closed observational contract for a 477-slot private comparison, never publication.
use super::*;
pub(super) const SCHEMA: &str = "jetstreamer-private-epoch223-v1625-tail-launch-v1";
pub(super) const GUARD_SHA: &str =
    "d039ddf0b161bc554614a862bd12987bd6a3474549a22d066ebefa5584e5dd98";
const PACKAGE: &str = "/var/lib/jetstreamer/horizon-focused-223-v1625-tail-bd60006d-v1";
const SNAPSHOT: &str = "snapshot-96767522-3SdyhqCuei4esVf8imz8A2rPB1z83sAK3KHbtKefJDS7.tar.zst";
const NODE: &str = "ad7204ff573ce552df57125fb82f984575585378958c9232d6c13afea2f34b01";
const WORKER: &str = "fde3ba53cc52012b894bac29bd7889b4cfd326fff75f4f67ec4cbdbf2ac7136c";
fn suffix(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}
pub(super) fn namespace(c: &DiagnosticClaim) -> bool {
    c.epoch == 223
        && c.unit
            .strip_prefix("horizon-qualify-223-v1625-tail-")
            .and_then(|s| s.strip_suffix(".service"))
            .is_some_and(suffix)
}
fn command(v: &Value) -> Option<&str> {
    v.as_str()?.split_once(" ; ignore_errors=").map(|(s, _)| s)
}
fn expected(c: &DiagnosticClaim) -> String {
    let root = c.scratch_path.display();
    format!(
        "{{ path={PACKAGE}/jetstreamer-node ; argv[]={PACKAGE}/jetstreamer-node 223 {root}/ledger --verify --qualification-end-slot=96767999 --snapshot-archive={PACKAGE}/{SNAPSHOT} --epoch-hashes={PACKAGE}/epoch-hashes-223-qualification.txt --horizon-output={root}/output/epoch-223.jet --replay-scratch={root}/scratch"
    )
}
pub(super) fn same_command(c: &DiagnosticClaim, live: &Value, launch: &Value) -> bool {
    command(live) == Some(expected(c).as_str()) && command(live) == command(launch)
}
pub(super) fn launch_matches(c: &DiagnosticClaim, r: &Value) -> bool {
    namespace(c)
        && c.scratch_path.parent() == Some(Path::new("/home/ubuntu/.jetstreamer-private"))
        && c.scratch_path
            .file_name()
            .and_then(|s| s.to_str())
            .and_then(|s| s.strip_prefix("qualification-223-v1625-tail-"))
            .is_some_and(suffix)
        && r["epoch"] == 223
        && r["private_run_root"].as_str() == c.scratch_path.to_str()
        && r["snapshot_slot"] == 96_767_522u64
        && r["snapshot_sha256"]
            == "dc7f2ac03813bc609629885af82222ac5af070cc6187b7bce08e10944fd214e1"
        && r["node_sha256"] == NODE
        && r["worker_sha256"] == WORKER
        && r["package_seal_sha256"]
            == "4ab0f74e4fc69d3bb0382242bf9c862c5274532cb991e3843258981f264b5ba3"
        && r["runtime"] == "solana-v1.6.25"
        && r["feature"] == "epoch223-v1-6-25-qualification"
        && r["restart_policy"] == "no"
        && r["solana_rayon_threads"] == 16
        && r["output_slot_start"] == 96_767_523u64
        && r["terminal_slot"] == 96_767_999u64
        && r["output_slot_count"] == 477
        && r["maximum_runtime_seconds"] == 7200
        && r["experimental_envelope_bytes"] == 416u64 << 30
        && r["required_initial_free_bytes"].as_u64().is_some_and(|n| {
            n >= 3_437_045_427_597
                && n.checked_sub(384u64 << 30) == r["guard_minimum_free_bytes"].as_u64()
        })
        && canonical_digest(&r["capability"]["sha256"])
        && r["capability"]["path"].as_str().is_some_and(|s| {
            let p = Path::new(s);
            p.file_name() == Some(std::ffi::OsStr::new("capability.json"))
                && p.parent().and_then(Path::parent) == Some(Path::new("/var/lib/jetstreamer"))
                && p.parent()
                    .and_then(Path::file_name)
                    .and_then(|s| s.to_str())
                    .and_then(|s| s.strip_prefix("horizon-223-tail-capability-receipts-"))
                    .is_some_and(suffix)
        })
        && r["bounded_replay_authorized"] == true
        && r["tail_comparison_only"] == true
        && [
            "ordinary_replay_authorized",
            "canonical_prefix_qualified",
            "full_cold_epoch_peak_qualified",
            "runtime_promotion_authorized",
            "complete_epoch_span_covered",
            "canonical_sidecar_authorized",
            "publication_authorized",
        ]
        .iter()
        .all(|k| r[*k] == false)
        && command(&r["expected_exec_start"]) == Some(expected(c).as_str())
}
pub(super) fn guard_matches(c: &DiagnosticClaim, r: &Value, p: &Value) -> bool {
    launch_matches(c, r)
        && p["filesystem"] == "/"
        && p["minimum_free_bytes"] == r["guard_minimum_free_bytes"]
        && p["worker_root"].as_str() == c.scratch_path.join("scratch").to_str()
        && p["maximum_worker_vmas"] == 3_500_000u64
        && p.get("bounded_canary").is_none_or(Value::is_null)
        && p.get("bounded_measurement").is_none_or(Value::is_null)
}
pub(super) fn capability(v: &Value) -> Result<()> {
    ensure!(
        v["schema"] == "jetstreamer-private-epoch223-tail-package-capability-v1"
            && v["epoch"] == 223
            && v["package"] == PACKAGE
            && v["self_sha256"]
                == "40db4557b0b9eb3b9805e8698db47f6a6bd7e9775f4072c7b9373e2f054657a3"
            && v["members"]["jetstreamer-node"]["sha256"] == NODE
            && v["members"]["jetstreamer-historical-worker-v1-6-25"]["sha256"] == WORKER
            && v["members"][SNAPSHOT]["sha256"]
                == "dc7f2ac03813bc609629885af82222ac5af070cc6187b7bce08e10944fd214e1"
            && v["output_slot_start"] == 96_767_523u64
            && v["terminal_slot"] == 96_767_999u64
            && v["slot_count"] == 477
            && v["tail_comparison_only"] == true,
        "tail223 capability differs from the exact private package"
    );
    for key in [
        "complete_epoch_span_covered",
        "snapshot_schema_or_contents_tested",
        "fresh_resource_admission_passed",
        "replay_launch_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(
            v[key] == false,
            "tail223 capability grants foreign authority"
        );
    }
    let probes = v["probes"].as_array().context("tail223 probes")?;
    ensure!(probes.len() == 3, "tail223 probe census");
    for (i, p) in probes.iter().enumerate() {
        ensure!(
            p["mode"] == json!(i)
                && p["exit_code"] == if i == 2 { 1 } else { 2 }
                && canonical_digest(&p["log_sha256"]),
            "tail223 capability probe binding"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (DiagnosticClaim, Value) {
        let c = DiagnosticClaim {
            epoch: 223,
            unit: "horizon-qualify-223-v1625-tail-test.service".into(),
            invocation_id: "a".repeat(32),
            scratch_path: "/home/ubuntu/.jetstreamer-private/qualification-223-v1625-tail-test"
                .into(),
            launch_receipt: BoundFile {
                path: "/sealed/launch.json".into(),
                sha256: "b".repeat(64),
            },
        };
        let mut r = json!({"schema":SCHEMA,"launched":true,"epoch":223,"private_run_root":c.scratch_path,
            "snapshot_slot":96767522,"snapshot_sha256":"dc7f2ac03813bc609629885af82222ac5af070cc6187b7bce08e10944fd214e1",
            "node_sha256":NODE,"worker_sha256":WORKER,"package_seal_sha256":"4ab0f74e4fc69d3bb0382242bf9c862c5274532cb991e3843258981f264b5ba3",
            "runtime":"solana-v1.6.25","feature":"epoch223-v1-6-25-qualification","restart_policy":"no","solana_rayon_threads":16,
            "output_slot_start":96767523,"terminal_slot":96767999,"output_slot_count":477,"maximum_runtime_seconds":7200,
            "experimental_envelope_bytes":416u64<<30,"required_initial_free_bytes":3437045427597u64,"guard_minimum_free_bytes":3024728567181u64,
            "capability":{"path":"/var/lib/jetstreamer/horizon-223-tail-capability-receipts-test/capability.json","sha256":"c".repeat(64)},
            "bounded_replay_authorized":true,"tail_comparison_only":true});
        let scope = json!({"ordinary_replay_authorized":false,
            "canonical_prefix_qualified":false,"full_cold_epoch_peak_qualified":false,"runtime_promotion_authorized":false,
            "complete_epoch_span_covered":false,"canonical_sidecar_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false,
            "expected_exec_start":format!("{} ; ignore_errors=no ; pid=1 }}",expected(&c)),
            "evidence":{"units":[{"unit":c.unit,"invocation_id":c.invocation_id,"restarts":0,"load_state":"loaded","result":"success","main_pid":1,"active_state":"active","sub_state":"running"}]}});
        r.as_object_mut()
            .unwrap()
            .extend(scope.as_object().unwrap().clone());
        (c, r)
    }
    #[test]
    fn exact_partial_scope_cannot_be_a_full_epoch_or_other_runtime() {
        let (c, r) = fixture();
        validate_diagnostic_launch(&r, &c).unwrap();
        for key in [
            "node_sha256",
            "worker_sha256",
            "snapshot_sha256",
            "package_seal_sha256",
        ] {
            let mut bad = r.clone();
            bad[key] = json!("0".repeat(64));
            assert!(validate_diagnostic_launch(&bad, &c).is_err());
        }
        for (key, value) in [
            ("terminal_slot", json!(96768000)),
            ("output_slot_count", json!(432000)),
            ("publication_authorized", json!(true)),
            ("complete_epoch_span_covered", json!(true)),
            ("schema", json!(bounded205::SCHEMA)),
            ("guard_minimum_free_bytes", json!(1)),
        ] {
            let mut bad = r.clone();
            bad[key] = value;
            assert!(validate_diagnostic_launch(&bad, &c).is_err(), "{key}");
        }
        assert!(same_command(
            &c,
            &r["expected_exec_start"],
            &r["expected_exec_start"]
        ));
        assert!(!same_command(
            &c,
            &json!(format!("{} --extra ; ignore_errors=no }}", expected(&c))),
            &r["expected_exec_start"]
        ));
    }
    #[test]
    fn ordinary_drainage_guard_has_no_target_stop_exemption() {
        let (c, r) = fixture();
        let p = json!({"filesystem":"/","minimum_free_bytes":3024728567181u64,
            "worker_root":c.scratch_path.join("scratch"),"maximum_worker_vmas":3500000});
        assert!(guard_matches(&c, &r, &p));
        let mut bad = p.clone();
        bad["bounded_canary"] = json!({"expected_uid":1000});
        assert!(!guard_matches(&c, &r, &bad));
        let mut bad = p.clone();
        bad["minimum_free_bytes"] = json!(3024728567180u64);
        assert!(!guard_matches(&c, &r, &bad));
        let mut bad = p.clone();
        bad["worker_root"] = json!("/other/scratch");
        assert!(!guard_matches(&c, &r, &bad));
    }

    #[test]
    fn capability_binds_exact_package_all_three_probes_and_denied_authority() {
        let mut v = json!({
            "schema":"jetstreamer-private-epoch223-tail-package-capability-v1",
            "epoch":223,"package":PACKAGE,
            "self_sha256":"40db4557b0b9eb3b9805e8698db47f6a6bd7e9775f4072c7b9373e2f054657a3",
            "members":{
                "jetstreamer-node":{"sha256":NODE},
                "jetstreamer-historical-worker-v1-6-25":{"sha256":WORKER}
            },
            "output_slot_start":96767523,"terminal_slot":96767999,"slot_count":477,
            "tail_comparison_only":true
        });
        v["members"][SNAPSHOT] =
            json!({"sha256":"dc7f2ac03813bc609629885af82222ac5af070cc6187b7bce08e10944fd214e1"});
        let denied = [
            "complete_epoch_span_covered",
            "snapshot_schema_or_contents_tested",
            "fresh_resource_admission_passed",
            "replay_launch_authorized",
            "publication_authorized",
            "remote_mutations",
            "r2_mutations",
        ];
        for key in denied {
            v[key] = json!(false);
        }
        v["probes"] = json!([
            {"mode":0,"exit_code":2,"log_sha256":"a".repeat(64)},
            {"mode":1,"exit_code":2,"log_sha256":"b".repeat(64)},
            {"mode":2,"exit_code":1,"log_sha256":"c".repeat(64)}
        ]);
        capability(&v).unwrap();
        for key in denied {
            let mut bad = v.clone();
            bad[key] = json!(true);
            assert!(capability(&bad).is_err(), "{key}");
        }
        for key in [
            "epoch",
            "package",
            "self_sha256",
            "terminal_slot",
            "slot_count",
        ] {
            let mut bad = v.clone();
            bad.as_object_mut().unwrap().remove(key);
            assert!(capability(&bad).is_err(), "{key}");
        }
        for index in 0..3 {
            for key in ["mode", "exit_code", "log_sha256"] {
                let mut bad = v.clone();
                bad["probes"][index][key] = Value::Null;
                assert!(capability(&bad).is_err(), "{index}/{key}");
            }
        }
        let mut bad = v.clone();
        bad["probes"].as_array_mut().unwrap().pop();
        assert!(capability(&bad).is_err());
        for name in [
            "jetstreamer-node",
            "jetstreamer-historical-worker-v1-6-25",
            SNAPSHOT,
        ] {
            let mut bad = v.clone();
            bad["members"][name]["sha256"] = json!("0".repeat(64));
            assert!(capability(&bad).is_err(), "{name}");
        }
    }
}
