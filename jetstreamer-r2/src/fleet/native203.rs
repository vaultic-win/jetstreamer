//! Closed observational contract for the independently checked 203 restart probe.
//! A live restore comparison is never a suffix replay or a publication gate.
use super::*;

pub(super) const SCHEMA: &str = "jetstreamer-private-epoch203-native-restore-launch-v1";
pub(super) const GUARD_SHA: &str =
    "cf110b7397f4a134aaba422bb46838acc5b8d52b97cb6a6a2f1b70c6e1459a14";
const UNIT: &str = "horizon-native-203-0158-v1.service";
const ROOT: &str = "/home/ubuntu/.jetstreamer-private/epoch203-native-0158-v1";
const PROBE: &str = "/var/lib/jetstreamer/horizon-native203-profile-fixed-0154-v1/jetstreamer-epoch203-native-restore-probe";
const PROBE_SHA: &str = "a4acd558596a9f98eba4fedc20890594a5f7157a6c41a7aef208421fe4c55675";
const WORKER_SHA: &str = "4aeca56378a4bb2c55d0e590c1e334c4afa6a375a2c0d94894b412bea261f1cc";
const SNAPSHOT_SHA: &str = "d3114597ce25c3efaa4a96899ab3e9437c51cb9086d4166639f0ad2ae0613ee6";
const PLAN: &str = "/var/lib/jetstreamer/horizon-native203-launch-0158-v1/plan.json";
const EVIDENCE: &str = "/var/lib/jetstreamer/horizon-prefix203-terminal-independent-evidence-v1";
const MANIFEST_SHA: &str = "983ecabfc9c36e261a66641b8a039e5e1834198b0c9a07552db38457e67e5722";
const READER_SHA: &str = "e863adc87aed2a69949f710b3ee916b4757219d736e3c61fd132364bb143b859";
const NO_AUTHORITY: &[&str] = &[
    "ordinary_replay_claim",
    "current_sidecar_eta_valid",
    "replay_entries_authorized",
    "suffix_execution_authorized",
    "assembly_authorized",
    "canonical_sidecar_authorized",
    "runtime_promotion_authorized",
    "publication_authorized",
    "local_retirement_authorized",
    "remote_mutations",
    "r2_mutations",
];

pub(super) fn namespace(c: &DiagnosticClaim) -> bool {
    // Recognize the whole prefix so foreign/native203 names cannot borrow a
    // generic launch schema; shape() then admits exactly one sealed attempt.
    c.unit.starts_with("horizon-native-203-")
}
fn command(v: &Value) -> Option<&str> {
    v.as_str()?.split_once(" ; ignore_errors=").map(|(s, _)| s)
}
fn shape(c: &DiagnosticClaim, r: &Value) -> Result<()> {
    ensure!(
        c.epoch == 203
            && c.unit == UNIT
            && c.scratch_path == Path::new(ROOT)
            && r["schema"] == SCHEMA
            && r["epoch"] == 203
            && r["unit"] == UNIT
            && r["invocation_id"] == c.invocation_id
            && c.invocation_id.len() == 32
            && c.invocation_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && r["launched"] == true
            && r["probe_sha256"] == PROBE_SHA
            && r["worker_sha256"] == WORKER_SHA
            && r["snapshot_sha256"] == SNAPSHOT_SHA
            && r["snapshot_slot"] == 88_127_580
            && r["snapshot_bytes"] == 8_215_471_895u64
            && r["private_run_root"] == ROOT
            && r["native_plan"]["path"] == PLAN
            && canonical_digest(&r["native_plan"]["sha256"])
            && canonical_digest(&r["input_policy_sha256"])
            && r["maximum_runtime_seconds"] == 4500
            && r["maximum_memory_bytes"] == 128u64 << 30
            && r["maximum_cpu_percent"] == 800
            && r["solana_rayon_threads"] == 16
            && r["experimental_envelope_bytes"] == 192u64 << 30
            && r["protected_existing_floor_bytes"]
                .as_u64()
                .is_some_and(|n| n >= 248_289_182_611)
            && r["required_initial_free_bytes"].as_u64()
                == r["protected_existing_floor_bytes"]
                    .as_u64()
                    .and_then(|n| n.checked_add(192u64 << 30))
            && NO_AUTHORITY.iter().all(|k| r[*k] == false),
        "native 203 fixed private restore scope differs"
    );
    let expected = format!(
        "{{ path={PROBE} ; argv[]={PROBE} {PLAN} --plan-sha256 {} --self-sha256 {PROBE_SHA}",
        r["native_plan"]["sha256"]
            .as_str()
            .context("native 203 plan digest")?
    );
    ensure!(
        command(&r["expected_exec_start"]) == Some(expected.as_str()),
        "native 203 command differs"
    );
    Ok(())
}
fn inputs_match(p: &Value, r: &Value) -> bool {
    p["schema"] == "jetstreamer-epoch203-native-input-policy-v1"
        && p["probe_sha256"] == PROBE_SHA
        && p["producer_unit"] == UNIT
        && p["snapshot"].as_str().is_some_and(|s| {
            s.ends_with("/snapshot-88127580-4SeHmKHQrHot4gwifo1bnvDKXZwGELk2vSenotTx9oqf.tar.zst")
        })
        && p["scratch_directory"] == format!("{ROOT}/scratch")
        && p["output"] == format!("{ROOT}/native.json")
        && p["prefix_manifest"]["path"] == format!("{EVIDENCE}/manifest.json")
        && p["prefix_manifest"]["sha256"] == MANIFEST_SHA
        && p["prefix_validation"]["path"] == format!("{EVIDENCE}/validation.json")
        && p["prefix_validation"]["sha256"] == READER_SHA
        && p["protected_free_bytes"] == r["protected_existing_floor_bytes"]
        && p["candidate_incremental_peak_bytes"] == 192u64 << 30
        && p["minimum_free_bytes"] == r["required_initial_free_bytes"]
}
pub(super) fn launch(r: &Value, c: &DiagnosticClaim) -> Result<()> {
    shape(c, r)?;
    let plan = bound_json(&serde_json::from_value(r["native_plan"].clone())?)?;
    ensure!(
        plan["schema"] == "jetstreamer-private-epoch203-native-restore-probe-plan-v1"
            && plan["inputs"]["sha256"] == r["input_policy_sha256"],
        "native 203 outer plan differs"
    );
    let inputs = bound_json(&serde_json::from_value(plan["inputs"].clone())?)?;
    ensure!(inputs_match(&inputs, r), "native 203 inputs differ");
    // Rehash both complete independent-reader bindings, not a hand-entered
    // archive/range assertion. The probe independently checks their contents.
    for key in ["prefix_manifest", "prefix_validation"] {
        bound_json(&serde_json::from_value(inputs[key].clone())?)?;
    }
    let admission = bound_json(&serde_json::from_value(plan["admission_receipt"].clone())?)?;
    ensure!(
        admission["schema"] == "jetstreamer-epoch203-native-admission-receipt-v1"
            && admission["admitted"] == true
            && admission["restore_only"] == true
            && admission["input_policy_sha256"] == r["input_policy_sha256"]
            && admission["probe_sha256"] == PROBE_SHA
            && admission["worker_sha256"] == WORKER_SHA
            && admission["prefix_validation_sha256"] == READER_SHA
            && admission["producer_unit"] == UNIT
            && admission["protected_existing_floor_bytes"] == r["protected_existing_floor_bytes"]
            && admission["candidate_incremental_peak_bytes"] == 192u64 << 30
            && [
                "replay_launch_authorized",
                "assembly_authorized",
                "publication_authorized",
                "local_retirement_authorized",
                "remote_mutations",
                "r2_mutations"
            ]
            .iter()
            .all(|key| admission[*key] == false),
        "native 203 admission differs"
    );
    Ok(())
}
pub(super) fn guard_matches(c: &DiagnosticClaim, r: &Value, p: &Value) -> bool {
    shape(c, r).is_ok()
        && p["filesystem"] == "/"
        && p["minimum_free_bytes"] == r["protected_existing_floor_bytes"]
        && p.get("bounded_canary").is_none_or(Value::is_null)
        && p.get("bounded_measurement").is_none_or(Value::is_null)
}
pub(super) fn validate_live(c: &DiagnosticClaim, current: &Value) -> Result<()> {
    let r = checked_diagnostic_launch(c)?;
    ensure!(
        current["Type"] == "exec"
            && current["InvocationID"] == c.invocation_id
            && current["NRestarts"] == "0"
            && command(&current["ExecStart"]) == command(&r["expected_exec_start"]),
        "native 203 live command or owner differs"
    );
    let output = ProcessCommand::new("systemctl").args(["show", UNIT, "--no-pager",
        "--property=User,Group,Restart,KillMode,Delegate,TasksMax,MemoryHigh,MemoryMax,MemorySwapMax,RuntimeMaxUSec,CPUQuotaPerSecUSec,ProtectSystem,ProtectHome,PrivateNetwork,NoNewPrivileges,ReadWritePaths,CapabilityBoundingSet,AmbientCapabilities"]).output()?;
    ensure!(
        output.status.success() && output.stdout.len() < 16384,
        "native 203 sandbox unreadable"
    );
    let text = std::str::from_utf8(&output.stdout)?;
    let limits: BTreeMap<_, _> = text.lines().filter_map(|s| s.split_once('=')).collect();
    validate_limits(&limits)
}

fn validate_limits(limits: &BTreeMap<&str, &str>) -> Result<()> {
    for (key, expected) in [
        ("User", "ubuntu"),
        ("Group", "ubuntu"),
        ("Restart", "no"),
        ("KillMode", "control-group"),
        ("Delegate", "no"),
        ("TasksMax", "1024"),
        ("MemoryHigh", "103079215104"),
        ("MemoryMax", "137438953472"),
        ("MemorySwapMax", "0"),
        ("RuntimeMaxUSec", "1h 15min"),
        ("CPUQuotaPerSecUSec", "8s"),
        ("ProtectSystem", "strict"),
        ("ProtectHome", "read-only"),
        ("PrivateNetwork", "yes"),
        ("NoNewPrivileges", "yes"),
        ("CapabilityBoundingSet", ""),
        ("AmbientCapabilities", ""),
        (
            "ReadWritePaths",
            "/home/ubuntu/.jetstreamer-private/epoch203-native-0158-v1 /home/ubuntu/.jetstreamer-private/epoch203-native.lock",
        ),
    ] {
        ensure!(
            limits.get(key) == Some(&expected),
            "native 203 sandbox differs:{key}"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (DiagnosticClaim, Value) {
        let c = DiagnosticClaim {
            epoch: 203,
            unit: UNIT.into(),
            invocation_id: "a".repeat(32),
            scratch_path: ROOT.into(),
            launch_receipt: BoundFile {
                path: "/sealed/launch".into(),
                sha256: "b".repeat(64),
            },
        };
        let mut r = json!({"schema":SCHEMA,"epoch":203,"unit":UNIT,"invocation_id":c.invocation_id,
            "launched":true,"probe_sha256":PROBE_SHA,"worker_sha256":WORKER_SHA,
            "snapshot_sha256":SNAPSHOT_SHA,"snapshot_slot":88127580,"snapshot_bytes":8215471895u64,
            "private_run_root":ROOT,"native_plan":{"path":PLAN,"sha256":"c".repeat(64)},
            "input_policy_sha256":"d".repeat(64),"maximum_runtime_seconds":4500,
            "maximum_memory_bytes":128u64<<30,"maximum_cpu_percent":800,"solana_rayon_threads":16,
            "experimental_envelope_bytes":192u64<<30,"protected_existing_floor_bytes":3_031_427_990_419u64,
            "required_initial_free_bytes":3_031_427_990_419u64+(192u64<<30)});
        for k in NO_AUTHORITY {
            r[*k] = json!(false);
        }
        r["expected_exec_start"] = json!(format!(
            "{{ path={PROBE} ; argv[]={PROBE} {PLAN} --plan-sha256 {} --self-sha256 {PROBE_SHA} ; ignore_errors=no ; pid=123 }}",
            "c".repeat(64)
        ));
        (c, r)
    }
    #[test]
    fn exact_restore_cannot_grant_replay_suffix_or_sidecar_authority() {
        let (c, r) = fixture();
        shape(&c, &r).unwrap();
        for k in NO_AUTHORITY {
            let mut bad = r.clone();
            bad[*k] = json!(true);
            assert!(shape(&c, &bad).is_err(), "{k}");
        }
        for (k, v) in [
            ("worker_sha256", json!("f".repeat(64))),
            ("epoch", json!(205)),
            ("snapshot_slot", json!(88127581)),
            ("maximum_runtime_seconds", json!(4501)),
            ("experimental_envelope_bytes", json!(128u64 << 30)),
            ("required_initial_free_bytes", json!(3_031_427_990_419u64)),
        ] {
            let mut bad = r.clone();
            bad[k] = v;
            assert!(shape(&c, &bad).is_err(), "{k}");
        }
    }
    #[test]
    fn foreign_names_and_commands_fail_closed() {
        let (mut c, r) = fixture();
        c.unit = "horizon-native-203-foreign.service".into();
        assert!(namespace(&c));
        assert!(shape(&c, &r).is_err());
        let (c, mut r) = fixture();
        r["expected_exec_start"] = json!("/bin/true");
        assert!(shape(&c, &r).is_err());
    }
    #[test]
    fn guard_keeps_the_exact_protected_debt_and_no_canary_exemption() {
        let (c, r) = fixture();
        let mut p =
            json!({"filesystem":"/","minimum_free_bytes":r["protected_existing_floor_bytes"]});
        assert!(guard_matches(&c, &r, &p));
        p["minimum_free_bytes"] = json!(248_289_182_611u64);
        assert!(!guard_matches(&c, &r, &p));
        p["minimum_free_bytes"] = r["protected_existing_floor_bytes"].clone();
        p["bounded_canary"] = json!({"expected_uid":1000});
        assert!(!guard_matches(&c, &r, &p));
    }
}
