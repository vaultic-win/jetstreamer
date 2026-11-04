//! Closed observational owner for the private 477 slot reread, never delivery.
use super::*;
pub(super) const UNIT: &str = "archive-223-tail-reread-1743245a-v3.service";
const ROOT: &str = "/home/ubuntu/.jetstreamer-private/qualification-223-v1625-tail-1743245a-v3";
const BINARY: &str = "/var/lib/jetstreamer/horizon-223-tail-independent-reader-1743245a-v3/jetstreamer-qualification-verify";
const READER_SHA: &str = "1cf31e38bc283b6d08d17073337eade9fe1d681ed8112efb4a0c9cf51c82481c";
const STATE: &str = "/var/lib/jetstreamer/horizon-223-tail-independent-validation-1743245a-v3";
pub(super) fn scope(phase: &str, unit: &str) -> bool {
    phase == "private-tail-verification" && unit == UNIT
}
fn command() -> String {
    format!(
        "{{ path={BINARY} ; argv[]={BINARY} {ROOT}/output/epoch-223.jet --private-root={ROOT} --expected-epoch=223 --expected-output-start-slot=96767523 --expected-bootstrap-slot=96767522 --expected-terminal-slot=96767999 --expected-runtime-profile=solana-v1.6.25 --expected-worker-sha256=fde3ba53cc52012b894bac29bd7889b4cfd326fff75f4f67ec4cbdbf2ac7136c --receipt={STATE}/epoch-223.tail.validation.json"
    )
}
fn checked(c: &PipelineClaim, launch: &Value, terminal: &Value) -> Result<()> {
    ensure!(
        c.epoch == 223
            && scope(&c.phase, &c.unit)
            && launch["schema"] == "jetstreamer-private-epoch223-tail-reread-launch-v1"
            && launch["epoch"] == 223
            && launch["unit"] == c.unit
            && launch["invocation_id"] == c.invocation_id
            && launch["reader_sha256"] == READER_SHA
            && launch["expected_exec_start"] == c.expected_exec_start
            && c.expected_exec_start
                .split_once(" ; ignore_errors=")
                .map(|(s, _)| s)
                == Some(command().as_str()),
        "private 223 reread launch or exact command differs"
    );
    ensure!(
        terminal["schema"] == "jetstreamer-private-epoch223-tail-terminal-v1"
            && terminal["epoch"] == 223
            && terminal["private_run_root"] == ROOT
            && terminal["unit"] == "horizon-qualify-223-v1625-tail-1743245a-v3.service"
            && terminal["invocation_id"] == "20dc145d1e8c41fdbc682046b6fe4289"
            && terminal["node_sha256"]
                == "4449d7e3ba116c346567996ac5205bd20b05c67bb2c1625f353555a7c0ce445c"
            && terminal["result"] == "success"
            && terminal["exit_code"] == 0
            && terminal["restarts"] == 0
            && terminal["main_pid"] == 0
            && terminal["active_state"] == "inactive"
            && terminal["sub_state"] == "dead"
            && terminal["archive"] == format!("{ROOT}/output/epoch-223.jet")
            && canonical_digest(&terminal["archive_sha256"])
            && canonical_digest(&terminal["segment_manifest_sha256"])
            && terminal["output_slot_start"] == 96_767_523u64
            && terminal["terminal_slot"] == 96_767_999u64
            && terminal["output_slot_count"] == 477
            && terminal["tail_comparison_only"] == true,
        "private 223 reread requires exact clean parent terminal evidence"
    );
    for value in [launch, terminal] {
        for flag in [
            "ordinary_replay_claim",
            "current_sidecar_eta_valid",
            "complete_epoch_span_covered",
            "canonical_prefix_qualified",
            "full_cold_epoch_peak_qualified",
            "runtime_promotion_authorized",
            "terminal_canonical_root_independently_known",
            "canonical_sidecar_authorized",
            "publication_authorized",
            "remote_mutations",
            "r2_mutations",
        ] {
            ensure!(
                value[flag] == false,
                "private 223 reread grants foreign authority:{flag}"
            );
        }
    }
    Ok(())
}
pub(super) fn validate(c: &PipelineClaim) -> Result<()> {
    ensure!(
        c.evidence.len() == 1,
        "private 223 reread needs one exact launch receipt"
    );
    let launch = bound_json(&c.evidence[0])?;
    let binding: BoundFile = serde_json::from_value(launch["producer_terminal"].clone())?;
    ensure!(
        binding.path
            == Path::new(
                "/var/lib/jetstreamer/horizon-223-tail-terminal-1743245a-v3/terminal.json"
            ),
        "private 223 terminal path differs"
    );
    checked(c, &launch, &bound_json(&binding)?)
}
pub(super) fn validate_live(c: &PipelineClaim, current: &Value) -> Result<()> {
    validate(c)?;
    ensure!(
        current["Type"] == "oneshot",
        "private 223 reread must be oneshot"
    );
    let out = ProcessCommand::new("systemctl").args(["show", &c.unit, "--property=User,Group,DynamicUser,Restart,KillMode,Delegate,MemoryHigh,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec,TasksMax,ProtectSystem,ProtectHome,PrivateNetwork,NoNewPrivileges,CapabilityBoundingSet,AmbientCapabilities,ReadWritePaths,TimeoutStartUSec"]).output()?;
    ensure!(
        out.status.success(),
        "private 223 reread sandbox unreadable"
    );
    let text = std::str::from_utf8(&out.stdout)?;
    let fields: BTreeMap<_, _> = text.lines().filter_map(|l| l.split_once('=')).collect();
    for (key, expected) in [
        ("User", "root"),
        ("Group", "root"),
        ("DynamicUser", "no"),
        ("Restart", "no"),
        ("KillMode", "control-group"),
        ("Delegate", "no"),
        ("MemoryHigh", "25769803776"),
        ("MemoryMax", "34359738368"),
        ("MemorySwapMax", "0"),
        ("CPUQuotaPerSecUSec", "2s"),
        ("TasksMax", "512"),
        ("ProtectSystem", "strict"),
        ("ProtectHome", "read-only"),
        ("PrivateNetwork", "yes"),
        ("NoNewPrivileges", "yes"),
        ("CapabilityBoundingSet", "cap_dac_override"),
        ("AmbientCapabilities", "cap_dac_override"),
        ("ReadWritePaths", STATE),
        ("TimeoutStartUSec", "2h"),
    ] {
        ensure!(
            fields.get(key) == Some(&expected),
            "private 223 reread sandbox differs:{key}"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_tail_scan_keeps_failed_repair_private_and_cannot_be_ordinary_delivery() {
        let c = PipelineClaim {
            epoch: 223,
            phase: "private-tail-verification".into(),
            unit: UNIT.into(),
            invocation_id: "a".repeat(32),
            expected_exec_start: format!("{} ; ignore_errors=no }}", command()),
            evidence: vec![],
        };
        let mut l = json!({"schema":"jetstreamer-private-epoch223-tail-reread-launch-v1", "epoch":223,"unit":UNIT,"invocation_id":c.invocation_id,"reader_sha256":READER_SHA,"expected_exec_start":c.expected_exec_start});
        let mut t = json!({"schema":"jetstreamer-private-epoch223-tail-terminal-v1","epoch":223,"private_run_root":ROOT,"unit":"horizon-qualify-223-v1625-tail-1743245a-v3.service","invocation_id":"20dc145d1e8c41fdbc682046b6fe4289","node_sha256":"4449d7e3ba116c346567996ac5205bd20b05c67bb2c1625f353555a7c0ce445c","result":"success","exit_code":0,"restarts":0,"main_pid":0,"active_state":"inactive","sub_state":"dead","archive":format!("{ROOT}/output/epoch-223.jet"),"archive_sha256":"b".repeat(64),"segment_manifest_sha256":"c".repeat(64),"output_slot_start":96767523,"terminal_slot":96767999,"output_slot_count":477,"tail_comparison_only":true});
        for value in [&mut l, &mut t] {
            for flag in [
                "ordinary_replay_claim",
                "current_sidecar_eta_valid",
                "complete_epoch_span_covered",
                "canonical_prefix_qualified",
                "full_cold_epoch_peak_qualified",
                "runtime_promotion_authorized",
                "terminal_canonical_root_independently_known",
                "canonical_sidecar_authorized",
                "publication_authorized",
                "remote_mutations",
                "r2_mutations",
            ] {
                value[flag] = json!(false);
            }
        }
        checked(&c, &l, &t).unwrap();
        assert_eq!(pipeline_unit_range(&c.phase, &c.unit).unwrap(), 223..=223);
        assert!(pipeline_unit_range("full-verification", UNIT).is_err());
        assert!(
            pipeline_unit_range(
                "private-tail-verification",
                "archive-223-tail-reread-other.service"
            )
            .is_err()
        );
        for key in t.as_object().unwrap().keys() {
            let mut bad = t.clone();
            bad[key] = Value::Null;
            assert!(checked(&c, &l, &bad).is_err(), "terminal/{key}");
        }
        for key in l.as_object().unwrap().keys() {
            let mut bad = l.clone();
            bad[key] = Value::Null;
            assert!(checked(&c, &bad, &t).is_err(), "launch/{key}");
        }
        for original in [&l, &t] {
            for (key, value) in original.as_object().unwrap() {
                if value == &json!(false) {
                    let mut bad = original.clone();
                    bad[key] = json!(true);
                    assert!(
                        if std::ptr::eq(original, &l) {
                            checked(&c, &bad, &t).is_err()
                        } else {
                            checked(&c, &l, &bad).is_err()
                        },
                        "authority/{key}"
                    );
                }
            }
        }
        for (key, value) in [
            ("result", json!("timeout")),
            ("restarts", json!(1)),
            ("main_pid", json!(123)),
            ("output_slot_count", json!(432000)),
            ("terminal_slot", json!(96768000)),
        ] {
            let mut bad = t.clone();
            bad[key] = value;
            assert!(
                checked(&c, &l, &bad).is_err(),
                "terminal substitution/{key}"
            );
        }
    }
}
