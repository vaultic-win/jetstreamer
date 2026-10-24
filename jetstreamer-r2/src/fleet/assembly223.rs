//! Closed private 223 native 20/native 25 assembly owner; no replay/publication.
use super::*;
pub(super) const SCHEMA: &str = "jetstreamer-private223-v3-assembly-launch-v1";
pub(super) const UNIT: &str = "horizon-assemble-223-native20-native25-v1.service";
pub(super) const ROOT: &str =
    "/var/lib/jetstreamer/horizon-223-native20-native25-private-assembly-v1";
pub(super) const TOOL: &str = "/var/lib/jetstreamer/horizon-223-private-assembly-tools-529fc90f-v1/jetstreamer-epoch223-private-assemble";
pub(super) const TOOL_SHA: &str =
    "d1475bc12efb6f543c6772735c9ff08667b1ecd99660b01d6a390fbf87773eab";
pub(super) const PLAN: &str =
    "/var/lib/jetstreamer/horizon-223-private-assembly-launch-v1/plan.json";
pub(super) const STATE: &str = "/var/lib/jetstreamer/horizon-223-private-assembly-capture-v1";
pub(super) const GUARD_SHA: &str =
    "eca429932ffe9afe71aecba815ab301db46bdddbaf24b4c44af8c88bb74a6194";
pub(super) const GUARD_UNIT: &str = "horizon-assembly223-protective-v1.service";
pub(super) const GUARD_RECEIPTS: &str =
    "/var/lib/jetstreamer/horizon-assembly223-guard-receipts-v1";
pub(super) const PEAK: u64 = (160 << 30) + (32 << 20);
pub(super) const MEMORY: u64 = 64 << 30;
pub(super) fn namespace(c: &DiagnosticClaim) -> bool {
    c.epoch == 223 && c.unit == UNIT
}
fn iid(v: &str) -> bool {
    v.len() == 32
        && v.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && v.bytes().any(|b| b != b'0')
}
fn command(v: &Value) -> Option<&str> {
    v.as_str()?.split_once(" ; ignore_errors=").map(|(s, _)| s)
}
fn expected_command(sha: &str) -> String {
    format!("{{ path={TOOL} ; argv[]={TOOL} {PLAN} {sha} {TOOL_SHA}")
}
fn denied(v: &Value) -> Result<()> {
    for k in [
        "ordinary_replay_claim",
        "replay_launch_authorized",
        "canonical_sidecar_authorized",
        "publication_authorized",
        "runtime_promotion_authorized",
        "local_retirement_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(v[k] == false, "assembly 223 unexpected authority:{k}");
    }
    Ok(())
}
fn shape(r: &Value, c: &DiagnosticClaim) -> Result<()> {
    ensure!(
        namespace(c)
            && iid(&c.invocation_id)
            && c.scratch_path == Path::new(ROOT)
            && r["schema"] == SCHEMA
            && r["epoch"] == 223
            && r["unit"] == UNIT
            && r["invocation_id"] == c.invocation_id
            && r["launched"] == true
            && r["assembly_only_no_replay"] == true
            && r["assembler_sha256"] == TOOL_SHA
            && r["assembly_plan"]["path"] == PLAN
            && canonical_digest(&r["assembly_plan"]["sha256"])
            && r["output_root"] == ROOT
            && r["maximum_archive_bytes"] == (160u64 << 30)
            && r["candidate_incremental_peak_bytes"] == PEAK
            && r["maximum_memory_bytes"] == MEMORY
            && r["maximum_runtime_seconds"] == 86400
            && command(&r["expected_exec_start"])
                == Some(
                    expected_command(r["assembly_plan"]["sha256"].as_str().unwrap_or("")).as_str()
                ),
        "assembly 223 launch namespace/command/envelope differs"
    );
    denied(r)
}
fn bindings(r: &Value, p: &Value, a: &Value, ab: &BoundFile) -> Result<()> {
    ensure!(
        p["schema"] == "jetstreamer-private223-v3-assembly-plan-v1"
            && p["output_root"] == ROOT
            && p["admission"] == private157::binding(ab)
            && a["schema"] == "jetstreamer-private223-v3-assembly-admission-v1"
            && a["admitted"] == true
            && a["assembly_only_no_replay"] == true
            && a["assembler_sha256"] == TOOL_SHA
            && a["output_root"] == ROOT
            && a["maximum_archive_bytes"] == (160u64 << 30)
            && a["candidate_memory_max_bytes"] == MEMORY
            && a["candidate_memory_high_bytes"] == (48u64 << 30)
            && a["maximum_runtime_seconds"] == 86400
            && a["handoff_request_sha256"] == p["handoff_request"]["sha256"]
            && a["handoff_receipt_sha256"] == p["handoff_receipt"]["sha256"]
            && a["required_guard_minimum_free_bytes"] == r["required_guard_minimum_free_bytes"]
            && a["fleet_ledger"] == r["previous_fleet"]
            && a["observer_receipt"] == r["observer"],
        "assembly 223 actual plan/admission bindings differ"
    );
    let floor = a["required_guard_minimum_free_bytes"]
        .as_u64()
        .filter(|n| *n >= 2_000_000_000_000)
        .context("assembly 223 floor")?;
    let available = a["available_bytes"]
        .as_u64()
        .context("assembly 223 admitted disk")?;
    ensure!(
        floor.checked_add(PEAK).is_some_and(|n| available >= n),
        "assembly 223 metadata/output envelope does not fit"
    );
    let admitted = a["recorded_unix_seconds"]
        .as_u64()
        .context("assembly 223 admission clock")?;
    let launched = r["recorded_unix_seconds"]
        .as_u64()
        .context("assembly 223 launch clock")?;
    ensure!(
        admitted <= launched && launched - admitted <= 900,
        "assembly 223 admission expired/future"
    );
    for k in [
        "complete_fleet_census_passed",
        "older_producer_guards_preserved",
        "current_century_floor_preserved",
        "fresh_invocation_bound_resource_sample",
    ] {
        ensure!(a[k] == true, "assembly 223 admission omitted:{k}");
    }
    for k in [
        "replay_launch_authorized",
        "canonical_sidecar_authorized",
        "publication_authorized",
        "runtime_promotion_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(a[k] == false, "assembly 223 admission authority:{k}");
    }
    Ok(())
}
pub(super) fn launch(r: &Value, c: &DiagnosticClaim) -> Result<()> {
    shape(r, c)?;
    let p: BoundFile = serde_json::from_value(r["assembly_plan"].clone())?;
    let a: BoundFile = serde_json::from_value(r["admission"].clone())?;
    bindings(r, &bound_json(&p)?, &bound_json(&a)?, &a)?;
    let gb: BoundFile = serde_json::from_value(r["guard_plan"].clone())?;
    ensure!(
        guard_matches(c, r, &bound_json(&gb)?),
        "assembly 223 immutable guard binding differs"
    );
    Ok(())
}
pub(super) fn guard_matches(c: &DiagnosticClaim, r: &Value, p: &Value) -> bool {
    namespace(c)
        && shape(r, c).is_ok()
        && p["schema"] == "jetstreamer-horizon-standalone-guard-plan-v1"
        && p["maximum_worker_vmas"] == 3_500_000
        && p["unit"] == UNIT
        && p["invocation_id"] == c.invocation_id
        && p["filesystem"] == "/home/ubuntu"
        && p["worker_root"] == ROOT
        && p["minimum_free_bytes"] == r["required_guard_minimum_free_bytes"]
        && p["receipt_directory"] == GUARD_RECEIPTS
        && [
            "bounded_canary",
            "bounded_measurement",
            "native_main",
            "maximum_root_physical_bytes",
        ]
        .iter()
        .all(|k| p.get(*k).is_none_or(Value::is_null))
}
fn limits(p: &BTreeMap<String, String>) -> Result<()> {
    for (k, v) in [
        ("Type", "exec"),
        ("Restart", "no"),
        ("KillMode", "control-group"),
        ("Delegate", "no"),
        ("TasksMax", "512"),
        ("MemoryHigh", "51539607552"),
        ("MemoryMax", "68719476736"),
        ("MemorySwapMax", "0"),
        ("RuntimeMaxUSec", "1d"),
        ("CPUQuotaPerSecUSec", "4s"),
        ("ProtectSystem", "strict"),
        ("ProtectHome", "read-only"),
        ("PrivateNetwork", "yes"),
        ("NoNewPrivileges", "yes"),
        ("User", "root"),
        ("UMask", "0077"),
        ("ReadWritePaths", ROOT),
    ] {
        ensure!(
            p.get(k).map(String::as_str) == Some(v),
            "assembly 223 sandbox differs:{k}"
        );
    }
    for key in ["CapabilityBoundingSet", "AmbientCapabilities"] {
        ensure!(
            p.get(key)
                .map(|s| s.split_whitespace().collect::<BTreeSet<_>>())
                == Some(BTreeSet::from(["cap_dac_override", "cap_sys_ptrace"])),
            "assembly 223 capability set differs"
        );
    }
    Ok(())
}
pub(super) fn live_limits() -> Result<BTreeMap<String, String>> {
    let p = singleton227_capture::properties(
        UNIT,
        "Type,Restart,KillMode,Delegate,TasksMax,MemoryHigh,MemoryMax,MemorySwapMax,RuntimeMaxUSec,CPUQuotaPerSecUSec,ProtectSystem,ProtectHome,PrivateNetwork,NoNewPrivileges,ReadWritePaths,User,UMask,CapabilityBoundingSet,AmbientCapabilities,ControlGroup",
    )?;
    limits(&p)?;
    Ok(p)
}
fn live_owner(r: &Value, c: &DiagnosticClaim, v: &Value) -> Result<()> {
    ensure!(
        namespace(c)
            && v["Id"] == UNIT
            && v["LoadState"] == "loaded"
            && v["InvocationID"] == c.invocation_id
            && v["NRestarts"] == "0"
            && v["ActiveState"] == "active"
            && v["SubState"] == "running"
            && v["MainPID"]
                .as_str()
                .and_then(|s| s.parse::<u32>().ok())
                .is_some_and(|p| p > 1)
            && v["ControlGroup"] == format!("/system.slice/{UNIT}")
            && command(&v["ExecStart"]) == command(&r["expected_exec_start"]),
        "assembly 223 current owner differs"
    );
    Ok(())
}
pub(super) fn validate_live(c: &DiagnosticClaim, current: &Value) -> Result<()> {
    let r = checked_diagnostic_launch(c)?;
    live_owner(&r, c, current)?;
    live_limits()?;
    Ok(())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CaptureSpec {
    schema: String,
    assembly_plan: BoundFile,
    admission: BoundFile,
    guard_plan: BoundFile,
}
pub(super) fn capture() -> Result<()> {
    let (sb, self_sha) = publication203::parsed_args("capture-assembly223-launch")?;
    let s: CaptureSpec = serde_json::from_value(native209::immutable_json(&sb)?)?;
    ensure!(
        s.schema == "jetstreamer-private223-v3-assembly-capture-spec-v1"
            && s.assembly_plan.path == Path::new(PLAN),
        "assembly 223 capture scope differs"
    );
    let a = bound_json(&s.admission)?;
    let p = bound_json(&s.assembly_plan)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let before = unit(UNIT)?;
    let c = DiagnosticClaim {
        epoch: 223,
        unit: UNIT.into(),
        invocation_id: before["InvocationID"]
            .as_str()
            .context("assembly 223 actual iid")?
            .into(),
        scratch_path: ROOT.into(),
        launch_receipt: BoundFile {
            path: Path::new(STATE).join("launch.json"),
            sha256: "0".repeat(64),
        },
    };
    let mut r = json!({"schema":SCHEMA,"epoch":223,"unit":UNIT,"invocation_id":c.invocation_id,"launched":true,
        "assembly_only_no_replay":true,"assembler_sha256":TOOL_SHA,"assembly_plan":private157::binding(&s.assembly_plan),
        "admission":private157::binding(&s.admission),"guard_plan":private157::binding(&s.guard_plan),"previous_fleet":a["fleet_ledger"],"observer":a["observer_receipt"],
        "output_root":ROOT,"maximum_runtime_seconds":86400,"maximum_archive_bytes":160u64<<30,"candidate_incremental_peak_bytes":PEAK,
        "maximum_memory_bytes":MEMORY,"required_guard_minimum_free_bytes":a["required_guard_minimum_free_bytes"],
        "expected_exec_start":before["ExecStart"],"recorded_unix_seconds":now,"capture_spec":private157::binding(&sb),"capture_self_sha256":self_sha});
    for k in [
        "ordinary_replay_claim",
        "replay_launch_authorized",
        "canonical_sidecar_authorized",
        "publication_authorized",
        "runtime_promotion_authorized",
        "local_retirement_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        r[k] = json!(false);
    }
    launch(&r, &c)?;
    live_owner(&r, &c, &before)?;
    live_limits()?;
    // The actual checked assembler creates this intent only after authenticating
    // the genuine handoff, current idle sources, opened inputs and bounded owner.
    let intent_path = Path::new(ROOT).join("intent.json");
    let raw = read_stable_bounded(&intent_path, 8 << 20, "assembly 223 actual intent")?;
    let intent: Value = serde_json::from_slice(&raw)?;
    ensure!(
        intent["schema"] == "jetstreamer-private223-v3-assembly-intent-v1"
            && intent["unit"] == UNIT
            && intent["invocation_id"] == c.invocation_id
            && intent["self_sha256"] == TOOL_SHA
            && intent["plan"] == private157::binding(&s.assembly_plan)
            && intent["admission"] == private157::binding(&s.admission)
            && intent["handoff_request"] == p["handoff_request"]
            && intent["handoff_receipt"] == p["handoff_receipt"]
            && intent["publication_authorized"] == false
            && intent["r2_mutations"] == false,
        "assembly 223 actual intent differs"
    );
    r["producer_intent"] = json!({"path":intent_path,"sha256":hex_lower(&Sha256::digest(&raw))});
    let f: BoundFile = serde_json::from_value(a["fleet_ledger"].clone())?;
    let o: BoundFile = serde_json::from_value(a["observer_receipt"].clone())?;
    let fleet = bound_json(&f)?;
    let observer = bound_json(&o)?;
    ensure!(
        fleet["observer_sha256"] == o.sha256
            && fleet["observer_receipt"].as_str() == o.path.to_str()
            && fleet["sampled_at_utc"] == observer["recorded_at_utc"]
            && fleet["first_epoch"] == 201
            && fleet["last_epoch"] == 300,
        "assembly 223 accepted predecessor differs"
    );
    let mut names = fleet["unit_census"]
        .as_object()
        .context("assembly 223 older units")?
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    names.insert(UNIT.into());
    let all = census(&names, 201, 300)?;
    let mut older = all.clone();
    older.remove(UNIT);
    singleton227_admission::owners(&fleet, &older)?;
    prefix223_live_peer::current(&fleet, &older)?;
    ensure!(
        all.get(UNIT) == Some(&before) && unit(UNIT)? == before,
        "assembly 223 owner changed during capture"
    );
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().mode(0o700).create(STATE)?;
    File::open("/var/lib/jetstreamer")?.sync_all()?;
    private157::immutable_receipt(&Path::new(STATE).join("launch.json"), &r)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (DiagnosticClaim, Value, Value, Value, BoundFile) {
        let b = json!({"path":"/sealed/fixture.json","sha256":"a".repeat(64)});
        let ab = BoundFile {
            path: "/sealed/admission.json".into(),
            sha256: "b".repeat(64),
        };
        let c = DiagnosticClaim {
            epoch: 223,
            unit: UNIT.into(),
            invocation_id: "1".repeat(32),
            scratch_path: ROOT.into(),
            launch_receipt: BoundFile {
                path: "/sealed/launch.json".into(),
                sha256: "c".repeat(64),
            },
        };
        let mut r = json!({"schema":SCHEMA,"epoch":223,"unit":UNIT,"invocation_id":c.invocation_id,"launched":true,
            "assembly_only_no_replay":true,"assembler_sha256":TOOL_SHA,"assembly_plan":{"path":PLAN,"sha256":"a".repeat(64)},
            "admission":private157::binding(&ab),"observer":b,"previous_fleet":b,"output_root":ROOT,
            "maximum_archive_bytes":160u64<<30,"candidate_incremental_peak_bytes":PEAK,"maximum_memory_bytes":MEMORY,
            "maximum_runtime_seconds":86400,"expected_exec_start":format!("{} ; ignore_errors=no ; }}",expected_command(&"a".repeat(64))),
            "required_guard_minimum_free_bytes":2_000_000_000_000u64,"recorded_unix_seconds":1001});
        for k in [
            "ordinary_replay_claim",
            "replay_launch_authorized",
            "canonical_sidecar_authorized",
            "publication_authorized",
            "runtime_promotion_authorized",
            "local_retirement_authorized",
            "remote_mutations",
            "r2_mutations",
        ] {
            r[k] = json!(false);
        }
        let p = json!({"schema":"jetstreamer-private223-v3-assembly-plan-v1","output_root":ROOT,"admission":private157::binding(&ab),
            "handoff_request":b,"handoff_receipt":b});
        let a = json!({"schema":"jetstreamer-private223-v3-assembly-admission-v1","admitted":true,"assembly_only_no_replay":true,
            "assembler_sha256":TOOL_SHA,"output_root":ROOT,"maximum_archive_bytes":160u64<<30,"candidate_memory_max_bytes":MEMORY,
            "candidate_memory_high_bytes":48u64<<30,"maximum_runtime_seconds":86400,"handoff_request_sha256":"a".repeat(64),
            "handoff_receipt_sha256":"a".repeat(64),"required_guard_minimum_free_bytes":2_000_000_000_000u64,
            "fleet_ledger":b,"observer_receipt":b,"available_bytes":2_000_000_000_000u64+PEAK,"recorded_unix_seconds":1000,
            "complete_fleet_census_passed":true,"older_producer_guards_preserved":true,"current_century_floor_preserved":true,
            "fresh_invocation_bound_resource_sample":true,"replay_launch_authorized":false,"canonical_sidecar_authorized":false,
            "publication_authorized":false,"runtime_promotion_authorized":false,"remote_mutations":false,"r2_mutations":false});
        (c, r, p, a, ab)
    }
    #[test]
    fn exact_assembler_cannot_borrow_replay_144_or_tail_namespace() {
        let (c, r, _, _, _) = fixture();
        shape(&r, &c).unwrap();
        for (key, value) in [
            ("assembler_sha256", json!("d".repeat(64))),
            ("maximum_archive_bytes", json!(112u64 << 30)),
            ("output_root", json!("/another/root")),
            ("publication_authorized", json!(true)),
            ("invocation_id", json!("2".repeat(32))),
        ] {
            let mut bad = r.clone();
            bad[key] = value;
            assert!(shape(&bad, &c).is_err(), "{key}");
        }
        let mut other = c;
        other.unit = prefix223_native20::UNIT.into();
        assert!(!namespace(&other));
    }
    #[test]
    fn genuine_admission_pair_resources_clock_and_older_claims_are_required() {
        let (_, r, p, a, ab) = fixture();
        bindings(&r, &p, &a, &ab).unwrap();
        for (key, value) in [
            ("recorded_unix_seconds", json!(1002)),
            ("recorded_unix_seconds", json!(0)),
            ("handoff_request_sha256", json!("f".repeat(64))),
            ("available_bytes", json!(2_000_000_000_000u64 + PEAK - 1)),
            ("older_producer_guards_preserved", json!(false)),
            ("candidate_memory_max_bytes", json!(63u64 << 30)),
            ("canonical_sidecar_authorized", json!(true)),
        ] {
            let mut bad = a.clone();
            bad[key] = value;
            assert!(bindings(&r, &p, &bad, &ab).is_err(), "{key}");
        }
    }
    #[test]
    fn only_exact_assembly_has_natural_zero_worker_guard_profile() {
        let (c, r, _, _, _) = fixture();
        let gp = json!({"schema":"jetstreamer-horizon-standalone-guard-plan-v1","maximum_worker_vmas":3500000,"unit":UNIT,"invocation_id":c.invocation_id,"filesystem":"/home/ubuntu","worker_root":ROOT,
            "minimum_free_bytes":2_000_000_000_000u64,"receipt_directory":GUARD_RECEIPTS});
        assert!(guard_matches(&c, &r, &gp));
        assert!(diagnostic_guard_workers_match(&c, &[]));
        for key in [
            "bounded_canary",
            "bounded_measurement",
            "native_main",
            "maximum_root_physical_bytes",
        ] {
            let mut bad = gp.clone();
            bad[key] = json!(1);
            assert!(!guard_matches(&c, &r, &bad), "{key}");
        }
        let mut worker = c;
        worker.unit = prefix223_native20::UNIT.into();
        assert!(!diagnostic_guard_workers_match(&worker, &[]));
    }
}
