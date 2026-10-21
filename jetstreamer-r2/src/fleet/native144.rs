//! Exact bounded144 native comparison; never replay, sidecar or publication.
use super::*;
mod prepare;
pub(super) fn prepare() -> Result<()> {
    prepare::run()
}
pub(super) const SCHEMA: &str = "jetstreamer-private-epoch144-native-restore-launch-v2";
pub(super) const UNIT: &str = "horizon-qualify-144-native-restore-20261021-v1.service";
const PROBE: &str = "/usr/local/lib/jetstreamer/horizon-epoch144-native-probe-tools-20261021-v2/jetstreamer-epoch144-native-restore-probe";
const PROBE_SHA: &str = "a5f8dea7cf4beed6385c1b13719fd72bee3573162c3b303282f65bd2693e7237";
const INPUTS_SHA: &str = "908cb628fc955f0ac66692d2742b34c1422b3ad06130b8fc8b28a94efaee682f";
const PLAN: &str =
    "/usr/local/lib/jetstreamer/horizon-epoch144-native-launch-plan-20261021-v1/plan.json";
const SCRATCH: &str = "/home/sol/.jetstreamer-private/epoch144-native-restore-20261021-v1/scratch";
pub(super) fn namespace(c: &DiagnosticClaim) -> bool {
    c.epoch == 144 && c.unit == UNIT
}
fn command(plan_sha: &str) -> String {
    format!(
        "{{ path={PROBE} ; argv[]={PROBE} {PLAN} --plan-sha256 {plan_sha} --self-sha256 {PROBE_SHA}"
    )
}
fn command_part(v: &Value) -> Option<&str> {
    v.as_str()?.split_once(" ; ignore_errors=").map(|(s, _)| s)
}
fn shape(r: &Value, c: &DiagnosticClaim) -> Result<()> {
    ensure!(
        namespace(c)
            && c.scratch_path == Path::new(SCRATCH)
            && r["schema"] == SCHEMA
            && r["epoch"] == 144
            && r["unit"] == UNIT
            && r["invocation_id"] == c.invocation_id
            && c.invocation_id.len() == 32
            && c.invocation_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && r["launched"] == true
            && r["native_probe_sha256"] == PROBE_SHA
            && r["input_policy_sha256"] == INPUTS_SHA
            && r["worker_sha256"]
                == "2cca500106d274ebfbbc8c5bfa0e6e8343cd5e41003f9e82c93282800732d8c8"
            && r["snapshot_sha256"]
                == "f170976b2bc3f2d55dd0fbb5a415bfeae8d0903a0ad69334d8aa993b5cab35ae"
            && r["snapshot_slot"] == 62639490
            && r["maximum_runtime_seconds"] == 1800
            && r["maximum_memory_bytes"] == 64u64 << 30
            && r["maximum_cpu_percent"] == 400
            && r["experimental_envelope_bytes"] == 40u64 << 30
            && r["protected_existing_floor_bytes"] == 4_740_696_923_590u64
            && r["native_plan"]["path"] == PLAN
            && canonical_digest(&r["native_plan"]["sha256"])
            && command_part(&r["expected_exec_start"])
                == Some(command(r["native_plan"]["sha256"].as_str().unwrap_or("")).as_str()),
        "native144 exact launch scope differs"
    );
    for flag in [
        "ordinary_replay_claim",
        "current_sidecar_eta_valid",
        "full_epoch_verified",
        "local_retirement_authorized",
        "replay_entries_authorized",
        "suffix_execution_authorized",
        "assembly_authorized",
        "canonical_sidecar_authorized",
        "runtime_promotion_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(r[flag] == false, "native144 launch grants authority:{flag}");
    }
    Ok(())
}
pub(super) fn launch(r: &Value, c: &DiagnosticClaim) -> Result<()> {
    shape(r, c)?;
    let pb: BoundFile = serde_json::from_value(r["native_plan"].clone())?;
    let plan = bound_json(&pb)?;
    let ab: BoundFile = serde_json::from_value(r["admission"].clone())?;
    let admission = bound_json(&ab)?;
    ensure!(
        plan["schema"] == "jetstreamer-private-epoch144-native-restore-probe-plan-v2"
            && plan["inputs"]["sha256"] == INPUTS_SHA
            && plan["admission_receipt"]["sha256"] == ab.sha256
            && admission["schema"] == "jetstreamer-epoch144-native-admission-receipt-v2"
            && admission["admitted"] == true
            && admission["restore_only"] == true
            && admission["input_policy_sha256"] == INPUTS_SHA
            && admission["probe_sha256"] == PROBE_SHA
            && admission["candidate_incremental_peak_bytes"] == 40u64 << 30
            && admission["protected_existing_floor_bytes"] == 4_740_696_923_590u64
            && admission["replay_launch_authorized"] == false
            && admission["publication_authorized"] == false
            && admission["r2_mutations"] == false,
        "native144 missing exact acyclic plan/admission"
    );
    let inputs: BoundFile = serde_json::from_value(plan["inputs"].clone())?;
    let inputs = bound_json(&inputs)?;
    ensure!(
        inputs["schema"] == "jetstreamer-epoch144-native-input-policy-v1"
            && inputs["probe_sha256"] == PROBE_SHA
            && inputs["scratch_directory"] == SCRATCH,
        "native144 inputs changed"
    );
    Ok(())
}
pub(super) fn validate_live(c: &DiagnosticClaim, current: &Value) -> Result<()> {
    let r = checked_diagnostic_launch(c)?;
    ensure!(
        namespace(c)
            && current["Type"] == "exec"
            && current["ActiveState"] == "active"
            && current["SubState"] == "running"
            && current["InvocationID"] == c.invocation_id
            && current["NRestarts"] == "0"
            && command_part(&current["ExecStart"]) == command_part(&r["expected_exec_start"]),
        "native144 live owner differs"
    );
    live_limits(UNIT)?;
    let old = unit("horizon-qualify-epoch144-loader-focus-20261016-v1.service")?;
    crate::inactive_status::private144_terminal_manager_proof(&old)?;
    let audit = unit("horizon-qualify-144-private-verification-20261021-v1.service")?;
    ensure!(
        audit["InvocationID"] == "0def5bbebbbc4d6aa8b7f6fe33d08365"
            && audit["ActiveState"] == "active"
            && audit["SubState"] == "exited"
            && audit["MainPID"] == "0"
            && audit["Result"] == "success"
            && audit["ExecMainStatus"] == "0",
        "native144 conflicts with original private audit"
    );
    Ok(())
}
fn live_limits(name: &str) -> Result<()> {
    ensure!(
        name == UNIT || name == "horizon-epoch144-native-limits-fixture-20261021-v1.service",
        "foreign limits unit"
    );
    let out=ProcessCommand::new("systemctl").args(["show",name,"--no-pager",
        "--property=Type,Restart,KillMode,Delegate,TasksMax,MemoryHigh,MemoryMax,MemorySwapMax,RuntimeMaxUSec,CPUQuotaPerSecUSec,ProtectSystem,ProtectHome,PrivateNetwork,PrivateMounts,NoNewPrivileges,ReadWritePaths,User,Group,UMask,CapabilityBoundingSet,AmbientCapabilities"]).output()?;
    ensure!(
        out.status.success() && out.stdout.len() < 16384,
        "native144 limits unreadable"
    );
    let mut limits = BTreeMap::new();
    for line in std::str::from_utf8(&out.stdout)?.lines() {
        let (k, v) = line.split_once('=').context("native144 limit line")?;
        ensure!(limits.insert(k, v).is_none(), "duplicate native144 limit");
    }
    validate_limits(&limits)
}
fn validate_limits(l: &BTreeMap<&str, &str>) -> Result<()> {
    for (k, v) in [
        ("Type", "exec"),
        ("Restart", "no"),
        ("KillMode", "control-group"),
        ("Delegate", "no"),
        ("TasksMax", "512"),
        ("MemoryHigh", "34359738368"),
        ("MemoryMax", "68719476736"),
        ("MemorySwapMax", "0"),
        ("RuntimeMaxUSec", "30min"),
        ("CPUQuotaPerSecUSec", "4s"),
        ("ProtectSystem", "strict"),
        ("ProtectHome", "read-only"),
        ("PrivateNetwork", "yes"),
        ("PrivateMounts", "yes"),
        ("NoNewPrivileges", "yes"),
        (
            "ReadWritePaths",
            "/home/sol/.jetstreamer-private/epoch144-native-restore-20261021-v1",
        ),
        ("User", "sol"),
        ("Group", "horizon"),
        ("UMask", "0077"),
        ("CapabilityBoundingSet", ""),
        ("AmbientCapabilities", ""),
    ] {
        ensure!(l.get(k) == Some(&v), "native144 sandbox differs:{k}");
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "root read-only actual native144 sandbox limits on harmless non-owner fixture"]
    fn root_actual_limits_fixture_matches_exact_native_contract() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        live_limits("horizon-epoch144-native-limits-fixture-20261021-v1.service").unwrap();
    }
    fn fixture() -> (DiagnosticClaim, Value) {
        let c = DiagnosticClaim {
            epoch: 144,
            unit: UNIT.into(),
            invocation_id: "a".repeat(32),
            scratch_path: SCRATCH.into(),
            launch_receipt: BoundFile {
                path: "/launch".into(),
                sha256: "b".repeat(64),
            },
        };
        let r = json!({"schema":SCHEMA,"epoch":144,"unit":UNIT,"invocation_id":c.invocation_id,"launched":true,
            "native_probe_sha256":PROBE_SHA,"input_policy_sha256":INPUTS_SHA,"worker_sha256":"2cca500106d274ebfbbc8c5bfa0e6e8343cd5e41003f9e82c93282800732d8c8",
            "snapshot_sha256":"f170976b2bc3f2d55dd0fbb5a415bfeae8d0903a0ad69334d8aa993b5cab35ae","snapshot_slot":62639490,
            "maximum_runtime_seconds":1800,"maximum_memory_bytes":64u64<<30,"maximum_cpu_percent":400,
            "experimental_envelope_bytes":40u64<<30,"protected_existing_floor_bytes":4740696923590u64,
            "native_plan":{"path":PLAN,"sha256":"c".repeat(64)},"expected_exec_start":format!("{} ; ignore_errors=no }}",command(&"c".repeat(64))),
            "replay_entries_authorized":false,"suffix_execution_authorized":false,"assembly_authorized":false,"canonical_sidecar_authorized":false,
            "runtime_promotion_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false,
            "ordinary_replay_claim":false,"current_sidecar_eta_valid":false,"full_epoch_verified":false,"local_retirement_authorized":false});
        (c, r)
    }
    #[test]
    fn exact_native_launch_never_borrows_replay_or_another_root() {
        let (c, r) = fixture();
        shape(&r, &c).unwrap();
        for (key, value) in [
            ("snapshot_slot", json!(62639999)),
            ("experimental_envelope_bytes", json!(1)),
            ("replay_entries_authorized", json!(true)),
            ("publication_authorized", json!(true)),
            ("schema", json!("old-v1")),
        ] {
            let mut bad = r.clone();
            bad[key] = value;
            assert!(shape(&bad, &c).is_err(), "{key}");
        }
    }
}
