//! Exact, already-started private full-census ledger acquisition, not replay.
use super::*;
#[path = "native141_rejection.rs"]
mod rejection;
pub(super) const SCHEMA: &str = "jetstreamer-epoch141-native-initial-guard-v1";
pub(super) const UNIT: &str = "horizon-epoch141-native-full-census-20261022-v1.service";
const IID: &str = "1ca7610a4db34ceaaf2322736fa22092";
const ROOT: &str = "/home/sol/.jetstreamer-private/epoch141-native-full-census-20261022-v1";
const TOOL: &str = "/usr/local/lib/jetstreamer/horizon-epoch141-full-census-native-candidate-20261021-v1/jetstreamer-epoch141-ledger-native";
const TOOL_SHA: &str = "f1592d185a51f5d7503a8b3763e0f18899bc0aa0b62b61cd00dc5659bf985e02";
const PLAN: &str =
    "/usr/local/lib/jetstreamer/horizon-native141-full-census-plan-20261022-v1/plan.json";
const PLAN_SHA: &str = "46bebd571a2f5132418cd2fa29a6b64694cecf1ba6b3d53db13ddd954f6b5db4";
const ADMISSION: &str =
    "/var/lib/jetstreamer/horizon-native141-admission-20261022-v1/admission.json";
const ADMISSION_SHA: &str = "eff115cd9a6d0580ed0d4f286afee4bf7fdf503463b410c6b34a1c9556e33f5c";
const FLOOR: u64 = 4_740_696_923_590;
pub(super) fn unit_name(s: &str) -> bool {
    s.starts_with("horizon-epoch141-native-full-census-") && s.ends_with(".service")
}
pub(super) fn namespace(c: &DiagnosticClaim) -> bool {
    (c.epoch == 141 && c.unit == UNIT) || rejection::namespace(c)
}
fn command(v: &Value) -> Option<&str> {
    v.as_str()?.split_once(" ; ignore_errors=").map(|(s, _)| s)
}
fn expected_command() -> String {
    format!(
        "{{ path={TOOL} ; argv[]={TOOL} --plan {PLAN} --plan-sha256 {PLAN_SHA} --self-sha256 {TOOL_SHA} --admission-sha256 {ADMISSION_SHA}"
    )
}
fn shape(r: &Value, c: &DiagnosticClaim) -> Result<()> {
    ensure!(
        namespace(c)
            && c.invocation_id == IID
            && c.scratch_path == Path::new(ROOT)
            && c.launch_receipt.path == Path::new(ROOT).join("results/initial-guard.json")
            && c.launch_receipt.sha256
                == "76450b5767660b47b4da9c1e7f2afc8a843d3346bccc0b1c6d065b277e0e224a"
            && r["schema"] == SCHEMA
            && r["epoch"] == 141
            && r["invocation_id"] == IID
            && r["self_sha256"] == TOOL_SHA
            && r["plan_sha256"] == PLAN_SHA
            && r["admission_sha256"] == ADMISSION_SHA
            && r["minimum_free_bytes"] == FLOOR
            && r["available_bytes"]
                .as_u64()
                .is_some_and(|n| n >= FLOOR + (32u64 << 30))
            && r["trip"] == false,
        "foreign or unguarded native141 claim"
    );
    for flag in ["publication_authorized", "remote_mutations", "r2_mutations"] {
        ensure!(r[flag] == false, "native141 guard grants authority:{flag}");
    }
    Ok(())
}
fn bindings(p: &Value, a: &Value) -> Result<()> {
    ensure!(
        p["schema"] == "jetstreamer-epoch141-ledger-native-full-census-plan-v2"
            && p["unit"] == UNIT
            && p["minimum_free_bytes"] == FLOOR
            && p["maximum_runtime_seconds"] == 43200
            && p["database_directory"]
                == "/home/sol/.jetstreamer-private/epoch141-ledger-retention-20261020-v1/retained"
            && p["expected_families"]
                .as_array()
                .is_some_and(|s| s.len() == 16)
            && p["finalized_collection_receipt"]["sha256"]
                == "21427d5debbc22ab44c337fb32679620ec663f44c52c5ceeb7100fcb450f8fe4"
            && p["collection_receipt"]["sha256"]
                == "569df15e8ce87beca8df0a800c85e616aaf252baeb365a7c92f35b8b39b4e937"
            && p["admission_receipt"] == ADMISSION
            && p["log_directory"] == format!("{ROOT}/logs")
            && p["initial_guard_receipt"] == format!("{ROOT}/results/initial-guard.json")
            && p["output_receipt"] == format!("{ROOT}/results/candidates.json"),
        "native141 plan scope differs"
    );
    ensure!(
        a["schema"] == "jetstreamer-historical-performance-admission-receipt-v1"
            && a["native_profile"] == "epoch141-read-only-full-census-v2"
            && a["native_unit"] == UNIT
            && a["admitted"] == true
            && a["services_started"] == false
            && a["services_installed"] == false
            && a["native_database_opened"] == false
            && a["replay_launch_authorized"] == false
            && a["publication_authorized"] == false
            && a["remote_mutations"] == false
            && a["r2_mutations"] == false
            && a["evidence"]["minimum_free_bytes"]
                .as_u64()
                .is_some_and(|n| n >= FLOOR + (32u64 << 30)),
        "native141 admission differs"
    );
    Ok(())
}
pub(super) fn launch(r: &Value, c: &DiagnosticClaim) -> Result<()> {
    if rejection::namespace(c) {
        return rejection::launch(r, c);
    }
    shape(r, c)?;
    bindings(
        &bound_json(&BoundFile {
            path: PLAN.into(),
            sha256: PLAN_SHA.into(),
        })?,
        &bound_json(&BoundFile {
            path: ADMISSION.into(),
            sha256: ADMISSION_SHA.into(),
        })?,
    )
}
fn live(c: &DiagnosticClaim, v: &Value) -> Result<()> {
    ensure!(
        namespace(c)
            && v["Id"] == UNIT
            && v["InvocationID"] == IID
            && v["LoadState"] == "loaded"
            && v["ActiveState"] == "active"
            && v["SubState"] == "running"
            && v["NRestarts"] == "0"
            && v["Type"] == "exec"
            && v["MainPID"]
                .as_str()
                .and_then(|s| s.parse::<u64>().ok())
                .is_some_and(|p| p > 0)
            && command(&v["ExecStart"]) == Some(expected_command().as_str()),
        "native141 live command/owner changed"
    );
    Ok(())
}
fn common_limits(p: &BTreeMap<&str, &str>) -> Result<()> {
    for (k, v) in [
        ("Type", "exec"),
        ("Restart", "no"),
        ("KillMode", "control-group"),
        ("Delegate", "no"),
        ("RuntimeMaxUSec", "12h"),
        ("CPUQuotaPerSecUSec", "2s"),
        ("MemoryHigh", "12884901888"),
        ("MemoryMax", "17179869184"),
        ("MemorySwapMax", "0"),
        ("TasksMax", "512"),
        ("UMask", "0077"),
        ("ProtectSystem", "strict"),
        ("ProtectHome", "read-only"),
        ("PrivateNetwork", "yes"),
        ("PrivateTmp", "yes"),
        ("NoNewPrivileges", "yes"),
        ("CapabilityBoundingSet", "cap_dac_override"),
        ("AmbientCapabilities", "cap_dac_override"),
    ] {
        ensure!(p.get(k) == Some(&v), "native141 sandbox differs:{k}");
    }
    ensure!(
        p.get("User").is_some_and(|s| s.is_empty() || *s == "root")
            && p.get("Group").is_some_and(|s| s.is_empty() || *s == "root"),
        "native141 identity is not root"
    );
    Ok(())
}
fn limits(p: &BTreeMap<&str, &str>) -> Result<()> {
    common_limits(p)?;
    ensure!(
        p.get("ReadWritePaths")
            == Some(
                &"/home/sol/.jetstreamer-private/epoch141-native-full-census-20261022-v1/logs /home/sol/.jetstreamer-private/epoch141-native-full-census-20261022-v1/results"
            ),
        "native141 writable paths differ"
    );
    Ok(())
}
pub(super) fn validate_live(c: &DiagnosticClaim, v: &Value) -> Result<()> {
    if rejection::namespace(c) {
        return rejection::validate_live(c, v);
    }
    launch(&bound_json(&c.launch_receipt)?, c)?;
    live(c, v)?;
    let output=ProcessCommand::new("systemctl").args(["show",UNIT,"--no-pager","--property=Type,Restart,KillMode,Delegate,RuntimeMaxUSec,CPUQuotaPerSecUSec,MemoryHigh,MemoryMax,MemorySwapMax,TasksMax,UMask,ProtectSystem,ProtectHome,PrivateNetwork,PrivateTmp,NoNewPrivileges,CapabilityBoundingSet,AmbientCapabilities,ReadWritePaths,User,Group"]).output()?;
    ensure!(output.status.success(), "native141 sandbox read failed");
    let text = std::str::from_utf8(&output.stdout)?;
    limits(&text.lines().filter_map(|s| s.split_once('=')).collect())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn claim() -> DiagnosticClaim {
        DiagnosticClaim {
            epoch: 141,
            unit: UNIT.into(),
            invocation_id: IID.into(),
            scratch_path: ROOT.into(),
            launch_receipt: BoundFile {
                path: Path::new(ROOT).join("results/initial-guard.json"),
                sha256: "76450b5767660b47b4da9c1e7f2afc8a843d3346bccc0b1c6d065b277e0e224a".into(),
            },
        }
    }
    fn receipt() -> Value {
        json!({"schema":SCHEMA,"epoch":141,"invocation_id":IID,"self_sha256":TOOL_SHA,"plan_sha256":PLAN_SHA,"admission_sha256":ADMISSION_SHA,"minimum_free_bytes":FLOOR,"available_bytes":FLOOR+(32u64<<30),"trip":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false})
    }
    #[test]
    fn only_exact_guard_and_private_native_owner_are_accepted() {
        let c = claim();
        let r = receipt();
        shape(&r, &c).unwrap();
        for key in [
            "schema",
            "epoch",
            "invocation_id",
            "self_sha256",
            "plan_sha256",
            "admission_sha256",
            "minimum_free_bytes",
            "available_bytes",
            "trip",
            "publication_authorized",
            "remote_mutations",
            "r2_mutations",
        ] {
            let mut bad = r.clone();
            bad[key] = Value::Null;
            assert!(shape(&bad, &c).is_err(), "{key}");
        }
        let mut bad = claim();
        bad.epoch = 144;
        assert!(shape(&r, &bad).is_err());
        let mut bad = claim();
        bad.invocation_id = "a".repeat(32);
        assert!(shape(&r, &bad).is_err());
    }
    #[test]
    fn live_command_cannot_borrow_check_only_or_another_invocation() {
        let c = claim();
        let v = json!({"Id":UNIT,"InvocationID":IID,"LoadState":"loaded","ActiveState":"active","SubState":"running","NRestarts":"0","Type":"exec","MainPID":"123","ExecStart":format!("{} ; ignore_errors=no }}",expected_command())});
        live(&c, &v).unwrap();
        for (key, value) in [
            ("NRestarts", "1"),
            ("SubState", "exited"),
            ("InvocationID", "foreign"),
            ("ExecStart", "check-only"),
            ("MainPID", "0"),
        ] {
            let mut bad = v.clone();
            bad[key] = json!(value);
            assert!(live(&c, &bad).is_err(), "{key}");
        }
    }
    #[test]
    #[ignore = "requires actual root-private native141 attempt; read-only, no inventory or samples"]
    fn root_actual_native141_scope_and_sandbox() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let c = claim();
        launch(&bound_json(&c.launch_receipt).unwrap(), &c).unwrap();
        let current = unit(UNIT).unwrap();
        if current["ActiveState"] == "active" && current["SubState"] == "running" {
            validate_live(&c, &current).unwrap();
        } else {
            assert_eq!(current["InvocationID"], IID);
            assert_eq!(current["MainPID"], "0");
            println!("native141 already terminal; no live proof claimed or restart attempted");
        }
    }
}
