//! Exact private full-census PoH ownership; never a production/sidecar claim.
use super::*;
pub(super) const SCHEMA: &str = "jetstreamer-epoch141-census-poh-intent-v2";
const UNIT: &str = "horizon-epoch141-census-poh-diagnostic-20261022-v1.service";
const ROOT: &str = "/var/lib/jetstreamer/horizon-epoch141-census-poh-diagnostic-20261022-v2";
const TOOL: &str = "/usr/local/lib/jetstreamer/horizon-census141-poh-candidate-20261022-v2/jetstreamer-epoch141-census-poh-diagnostic";
const TOOL_SHA: &str = "02c267ef5ac68d24cc75d22988254bb426f7c2d2805074d7a8838e6ab27e9234";
const PLAN: &str =
    "/usr/local/lib/jetstreamer/horizon-census141-poh-candidate-20261022-v2/plan.json";
const PLAN_SHA: &str = "64334d5250d51021b8460947536a896d2bc9e7500c86aa54c1e617975aa11e98";
pub(super) fn unit_name(s: &str) -> bool {
    s == UNIT
}
fn command() -> String {
    format!(
        "{{ path={TOOL} ; argv[]={TOOL} {PLAN} --plan-sha256 {PLAN_SHA} --self-sha256 {TOOL_SHA} --run"
    )
}
fn command_matches(v: &Value) -> bool {
    v.as_str()
        .and_then(|s| s.split_once(" ; ignore_errors="))
        .is_some_and(|(c, t)| c == command() && t.starts_with("no ;"))
}
pub(super) fn namespace(c: &DiagnosticClaim) -> bool {
    c.epoch == 141 && c.unit == UNIT
}
fn shape(v: &Value, c: &DiagnosticClaim) -> Result<()> {
    ensure!(
        namespace(c)
            && c.scratch_path == Path::new(ROOT)
            && c.launch_receipt.path == Path::new(ROOT).join("intent.json")
            && c.invocation_id.len() == 32
            && c.invocation_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && v["schema"] == SCHEMA
            && v["tool_sha256"] == TOOL_SHA
            && v["plan"]["path"] == PLAN
            && v["plan"]["sha256"] == PLAN_SHA
            && v["owner"]["Id"] == UNIT
            && v["owner"]["InvocationID"] == c.invocation_id
            && v["owner"]["NRestarts"] == "0"
            && v["owner"]["Restart"] == "no"
            && v["owner"]["Type"] == "exec"
            && command_matches(&v["owner"]["ExecStart"])
            && v["owner"]["ActiveState"] == "active"
            && v["owner"]["SubState"] == "running"
            && v["target_count"] == 18283
            && v["expected_boundaries"] == 84597
            && v["acquisition"]["path"]
                == "/home/sol/.jetstreamer-private/epoch141-native-acquisition-all-20261022-v2/results/all-target-acquisition.json"
            && v["acquisition"]["sha256"]
                == "0335b1131663c0f8df77b3cddb5f79e49af2956067ebc46af74b9a08adafb949"
            && v["native_terminal"]["InvocationID"] == "4721c4110425431cbddedac185e7d6e9"
            && v["native_terminal"]["MainPID"] == "0"
            && v["native_terminal"]["NRestarts"] == "0"
            && v["native_terminal"]["Result"] == "success"
            && v["native_terminal"]["ExecMainStatus"] == "0"
            && v["memory_admission"]["admitted"] == true
            && v["memory_admission"]["protected_memory_bytes"] == 128u64 << 30
            && v["memory_admission"]["diagnostic_memory_max_bytes"] == 2u64 << 30
            && v["memory_admission"]["minimum_available_bytes"] == 130u64 << 30
            && v["memory_admission"]["available_bytes"]
                .as_u64()
                .is_some_and(|n| n >= 130u64 << 30),
        "foreign full-census141PoH launch"
    );
    for flag in [
        "publication_authorized",
        "runtime_boundary_input_authorized",
        "replay_launch_authorized",
        "runtime_promotion_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(v[flag] == false, "PoH diagnostic acquired authority:{flag}");
    }
    Ok(())
}
pub(super) fn launch(v: &Value, c: &DiagnosticClaim) -> Result<()> {
    shape(v, c)?;
    let p = bound_json(&BoundFile {
        path: PLAN.into(),
        sha256: PLAN_SHA.into(),
    })?;
    ensure!(
        p["schema"] == "jetstreamer-epoch141-census-poh-diagnostic-plan-v1"
            && p["output_directory"] == ROOT
            && p["acquisition"] == v["acquisition"],
        "PoH plan changed"
    );
    let a: BoundFile = serde_json::from_value(v["acquisition"].clone())?;
    let a = bound_json(&a)?;
    ensure!(
        a["schema"] == "jetstreamer-epoch141-native-all-target-acquisition-v2"
            && a["invocation_id"] == v["native_terminal"]["InvocationID"]
            && a["native_session_complete"] == true
            && a["complete_retained_census_revalidated_after_close"] == true
            && a["full_target_raw_acquisition_complete"] == true
            && a["raw_acquired_target_count"] == 18283
            && a["recovered_target_count"] == 0
            && a["publication_authorized"] == false
            && a["r2_mutations"] == false,
        "PoH ownership lacks exact closed acquisition"
    );
    Ok(())
}
fn live(c: &DiagnosticClaim, v: &Value) -> Result<()> {
    ensure!(
        namespace(c)
            && v["Id"] == UNIT
            && v["InvocationID"] == c.invocation_id
            && v["NRestarts"] == "0"
            && v["LoadState"] == "loaded"
            && v["Type"] == "exec"
            && v["ActiveState"] == "active"
            && v["SubState"] == "running"
            && v["MainPID"]
                .as_str()
                .and_then(|s| s.parse::<u64>().ok())
                .is_some_and(|n| n > 0)
            && command_matches(&v["ExecStart"]),
        "PoH diagnostic owner changed"
    );
    Ok(())
}
fn limits(p: &BTreeMap<&str, &str>) -> Result<()> {
    for (k, v) in [
        ("Type", "exec"),
        ("Restart", "no"),
        ("KillMode", "control-group"),
        ("Delegate", "no"),
        ("RuntimeMaxUSec", "6h"),
        ("CPUQuotaPerSecUSec", "2s"),
        ("MemoryHigh", "1073741824"),
        ("MemoryMax", "2147483648"),
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
        ("ReadWritePaths", ROOT),
        ("DynamicUser", "no"),
    ] {
        ensure!(p.get(k) == Some(&v), "PoH sandbox differs:{k}");
    }
    ensure!(
        p.get("User").is_some_and(|s| s.is_empty() || *s == "root")
            && p.get("Group").is_some_and(|s| s.is_empty() || *s == "root"),
        "PoH requires root diagnostic identity"
    );
    Ok(())
}
pub(super) fn validate_live(c: &DiagnosticClaim, v: &Value) -> Result<()> {
    launch(&bound_json(&c.launch_receipt)?, c)?;
    live(c, v)?;
    let o=ProcessCommand::new("/usr/bin/systemctl").args(["show",UNIT,"--property=Type,Restart,KillMode,Delegate,RuntimeMaxUSec,CPUQuotaPerSecUSec,MemoryHigh,MemoryMax,MemorySwapMax,TasksMax,UMask,ProtectSystem,ProtectHome,PrivateNetwork,PrivateTmp,NoNewPrivileges,CapabilityBoundingSet,AmbientCapabilities,ReadWritePaths,User,Group,DynamicUser"]).output()?;
    ensure!(o.status.success(), "PoH sandbox unreadable");
    let text = std::str::from_utf8(&o.stdout)?;
    limits(&text.lines().filter_map(|s| s.split_once('=')).collect())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "root actual live census141PoH owner/sandbox proof only; no resource sample,remote request or output"]
    fn actual_live_owner_has_exact_private_sandbox_and_closed_source() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let path = Path::new(ROOT).join("intent.json");
        let sha256 = hex_lower(&Sha256::digest(fs::read(&path).unwrap()));
        let launch_receipt = BoundFile { path, sha256 };
        let r = bound_json(&launch_receipt).unwrap();
        let c = DiagnosticClaim {
            epoch: 141,
            unit: UNIT.into(),
            invocation_id: r["owner"]["InvocationID"].as_str().unwrap().into(),
            scratch_path: ROOT.into(),
            launch_receipt,
        };
        validate_live(&c, &unit(UNIT).unwrap()).unwrap();
    }
    #[test]
    fn sandbox_preserves_hard_bounds_and_exact_os_output_only() {
        let mut p: BTreeMap<_, _> = [
            ("Type", "exec"),
            ("Restart", "no"),
            ("KillMode", "control-group"),
            ("Delegate", "no"),
            ("RuntimeMaxUSec", "6h"),
            ("CPUQuotaPerSecUSec", "2s"),
            ("MemoryHigh", "1073741824"),
            ("MemoryMax", "2147483648"),
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
            ("ReadWritePaths", ROOT),
            ("DynamicUser", "no"),
            ("User", "root"),
            ("Group", "root"),
        ]
        .into_iter()
        .collect();
        limits(&p).unwrap();
        for k in [
            "MemoryMax",
            "MemoryHigh",
            "MemorySwapMax",
            "RuntimeMaxUSec",
            "Restart",
            "CapabilityBoundingSet",
            "ReadWritePaths",
            "PrivateNetwork",
            "User",
        ] {
            let old = p.insert(k, "foreign").unwrap();
            assert!(limits(&p).is_err(), "{k}");
            p.insert(k, old);
        }
    }
    fn fixture() -> (DiagnosticClaim, Value) {
        let c = DiagnosticClaim {
            epoch: 141,
            unit: UNIT.into(),
            invocation_id: "a".repeat(32),
            scratch_path: ROOT.into(),
            launch_receipt: BoundFile {
                path: Path::new(ROOT).join("intent.json"),
                sha256: "b".repeat(64),
            },
        };
        let v = json!({"schema":SCHEMA,"tool_sha256":TOOL_SHA,"plan":{"path":PLAN,"sha256":PLAN_SHA},"owner":{"Id":UNIT,"InvocationID":c.invocation_id,"MainPID":"123","NRestarts":"0","Restart":"no","Type":"exec","ActiveState":"active","SubState":"running","ExecStart":format!("{} ; ignore_errors=no ; start_time=[now] }}",command())},"target_count":18283,"expected_boundaries":84597,"acquisition":{"path":"/home/sol/.jetstreamer-private/epoch141-native-acquisition-all-20261022-v2/results/all-target-acquisition.json","sha256":"0335b1131663c0f8df77b3cddb5f79e49af2956067ebc46af74b9a08adafb949"},"native_terminal":{"InvocationID":"4721c4110425431cbddedac185e7d6e9","MainPID":"0","NRestarts":"0","Result":"success","ExecMainStatus":"0"},"memory_admission":{"admitted":true,"protected_memory_bytes":128u64<<30,"diagnostic_memory_max_bytes":2u64<<30,"minimum_available_bytes":130u64<<30,"available_bytes":131u64<<30},"publication_authorized":false,"runtime_boundary_input_authorized":false,"replay_launch_authorized":false,"runtime_promotion_authorized":false,"remote_mutations":false,"r2_mutations":false});
        (c, v)
    }
    #[test]
    fn exact_census_owner_has_no_replay_or_publication_authority() {
        let (c, v) = fixture();
        shape(&v, &c).unwrap();
        for key in v.as_object().unwrap().keys() {
            let mut bad = v.clone();
            bad[key] = Value::Null;
            assert!(shape(&bad, &c).is_err(), "{key}");
        }
        let mut bad = v.clone();
        bad["owner"]["InvocationID"] = json!("foreign");
        assert!(shape(&bad, &c).is_err());
        let mut bad = v;
        bad["owner"]["ExecStart"] = json!("--check-only");
        assert!(shape(&bad, &c).is_err());
    }
    #[test]
    fn live_owner_cannot_borrow_terminal_or_foreign_invocation() {
        let (c, r) = fixture();
        let mut v = r["owner"].clone();
        v["LoadState"] = json!("loaded");
        live(&c, &v).unwrap();
        for (k, x) in [
            ("MainPID", "0"),
            ("InvocationID", "foreign"),
            ("NRestarts", "1"),
            ("SubState", "exited"),
            ("ExecStart", "--check-only"),
        ] {
            let mut bad = v.clone();
            bad[k] = json!(x);
            assert!(live(&c, &bad).is_err());
        }
    }
}
