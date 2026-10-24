//! Exact private epoch 223 V3 verifier ownership; no replay or publication.
use super::*;
pub(super) const SCHEMA: &str = "jetstreamer-private223-v3-verification-launch-v1";
pub(super) const UNIT: &str = "horizon-verify-223-native20-native25-private-v3-v1.service";
pub(super) const STATE: &str = "/var/lib/jetstreamer/horizon-223-private-verification-capture-v1";
pub(super) const PLAN: &str =
    "/var/lib/jetstreamer/horizon-223-private-verification-launch-v1/plan.json";
pub(super) const GUARD_SHA: &str = assembly223::GUARD_SHA;
pub(super) const GUARD_UNIT: &str = "horizon-verification223-protective-v1.service";
pub(super) const GUARD_RECEIPTS: &str =
    "/var/lib/jetstreamer/horizon-verification223-guard-receipts-v1";
pub(super) const PEAK: u64 = (160 << 30) + (256 << 20);
pub(super) const MEMORY: u64 = 64 << 30;
pub(super) fn namespace(c: &DiagnosticClaim) -> bool {
    c.epoch == 223 && c.unit == UNIT
}
pub(super) fn root_scope(p: &Path) -> bool {
    p.is_absolute()
        && p.parent() == Some(Path::new("/var/lib/jetstreamer"))
        && p.file_name().and_then(|n| n.to_str()).is_some_and(|n| {
            n.starts_with("horizon-223-private-v3-scan-")
                && n.len() > "horizon-223-private-v3-scan-".len()
                && n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}
fn command(v: &Value) -> Option<&str> {
    v.as_str()?.split_once(" ; ignore_errors=").map(|(s, _)| s)
}
fn tool(r: &Value) -> Result<BoundFile> {
    let b: BoundFile = serde_json::from_value(r["verifier"].clone())?;
    ensure!(
        canonical_digest(&json!(b.sha256))
            && b.path
                .file_name()
                .is_some_and(|n| n == "jetstreamer-epoch223-private-verify")
            && b.path.parent().is_some_and(|p| p.parent()
                == Some(Path::new("/var/lib/jetstreamer"))
                && p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("horizon-223-private-v3-final-tools-"))),
        "verification 223 executable escaped its sealed tool namespace"
    );
    Ok(b)
}
fn shape(r: &Value, c: &DiagnosticClaim) -> Result<()> {
    let b = tool(r)?;
    let sha = r["verification_plan"]["sha256"]
        .as_str()
        .context("verification 223 plan digest")?;
    let expected = format!(
        "{{ path={} ; argv[]={0} {PLAN} {sha} {}",
        b.path.display(),
        b.sha256
    );
    ensure!(
        namespace(c)
            && root_scope(&c.scratch_path)
            && r["schema"] == SCHEMA
            && r["epoch"] == 223
            && r["unit"] == UNIT
            && r["invocation_id"] == c.invocation_id
            && c.invocation_id.len() == 32
            && c.invocation_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && c.invocation_id.bytes().any(|b| b != b'0')
            && r["launched"] == true
            && r["verification_only_no_replay"] == true
            && r["verifier_sha256"] == b.sha256
            && r["verification_plan"]["path"] == PLAN
            && canonical_digest(&r["verification_plan"]["sha256"])
            && r["private_directory"].as_str() == c.scratch_path.to_str()
            && r["maximum_archive_bytes"] == 160u64 << 30
            && r["candidate_incremental_peak_bytes"] == PEAK
            && r["maximum_memory_bytes"] == MEMORY
            && r["maximum_runtime_seconds"] == 86400
            && command(&r["expected_exec_start"]) == Some(expected.as_str()),
        "verification 223 owner/command/envelope differs"
    );
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
        ensure!(r[k] == false, "verification 223 acquired authority: {k}");
    }
    Ok(())
}
fn bindings(r: &Value, p: &Value, a: &Value) -> Result<()> {
    let launched = r["recorded_unix_seconds"]
        .as_u64()
        .context("verification 223 capture clock")?;
    let admitted = a["recorded_unix_seconds"]
        .as_u64()
        .context("verification 223 capacity clock")?;
    let floor = a["minimum_free_bytes"]
        .as_u64()
        .filter(|n| *n >= 2_000_000_000_000)
        .context("verification 223 disk floor")?;
    ensure!(
        p["schema"] == "jetstreamer-private-epoch223-v3-verification-plan-v1"
            && p["private_directory"] == r["private_directory"]
            && p["capacity"] == r["capacity"]
            && a["schema"] == "jetstreamer-private223-verification-capacity-v1"
            && a["self_sha256"] == p["capacity_tool_sha256"]
            && a["verification_only_no_replay"] == true
            && a["all_live_growth_and_century_floor_protected"] == true
            && a["new_resource_samples"] == 0
            && a["first_epoch"] == 201
            && a["last_epoch"] == 300
            && a["additional_bytes"] == PEAK
            && a["minimum_free_bytes"] == r["required_guard_minimum_free_bytes"]
            && a["fleet"] == r["previous_fleet"]
            && a["observer"] == r["observer"]
            && floor
                .checked_add(PEAK)
                .is_some_and(|n| a["required_initial_free_bytes"] == n
                    && a["sampled_available_bytes"]
                        .as_u64()
                        .is_some_and(|m| m >= n)
                    && a["actual_available_bytes"].as_u64().is_some_and(|m| m >= n))
            && admitted <= launched
            && launched - admitted <= 900,
        "verification 223 actual capacity/plan differs"
    );
    for k in [
        "verification_launch_authorized",
        "source_completion_authenticated",
        "replay_launch_authorized",
        "local_retirement_authorized",
        "publication_authorized",
        "r2_mutations",
    ] {
        ensure!(
            a[k] == false,
            "verification 223 capacity acquired authority: {k}"
        );
    }
    Ok(())
}
pub(super) fn launch(r: &Value, c: &DiagnosticClaim) -> Result<()> {
    shape(r, c)?;
    let p: BoundFile = serde_json::from_value(r["verification_plan"].clone())?;
    let a: BoundFile = serde_json::from_value(r["capacity"].clone())?;
    bindings(r, &bound_json(&p)?, &bound_json(&a)?)?;
    let b = tool(r)?;
    use std::os::unix::fs::MetadataExt;
    let bm = fs::symlink_metadata(&b.path)?;
    ensure!(
        bm.is_file()
            && bm.uid() == 0
            && bm.nlink() == 1
            && bm.mode() & 0o222 == 0
            && b.path.canonicalize()? == b.path
            && hex_lower(&Sha256::digest(read_stable_bounded(
                &b.path,
                128 << 20,
                "private 223 verifier binary"
            )?)) == b.sha256,
        "verification 223 sealed executable changed"
    );
    let gb: BoundFile = serde_json::from_value(r["guard_plan"].clone())?;
    ensure!(
        guard_matches(c, r, &bound_json(&gb)?),
        "verification 223 immutable guard differs"
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
        && p["worker_root"].as_str() == c.scratch_path.to_str()
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
pub(super) fn live_limits(root: &Path) -> Result<BTreeMap<String, String>> {
    ensure!(root_scope(root), "verification 223 private root differs");
    let p = singleton227_capture::properties(
        UNIT,
        "Type,Restart,KillMode,Delegate,TasksMax,MemoryHigh,MemoryMax,MemorySwapMax,RuntimeMaxUSec,CPUQuotaPerSecUSec,ProtectSystem,ProtectHome,PrivateNetwork,NoNewPrivileges,ReadWritePaths,User,UMask,CapabilityBoundingSet,AmbientCapabilities,ControlGroup,ExecMainStartTimestampMonotonic",
    )?;
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
        ("CPUQuotaPerSecUSec", "8s"),
        ("ProtectSystem", "strict"),
        ("ProtectHome", "read-only"),
        ("PrivateNetwork", "yes"),
        ("NoNewPrivileges", "yes"),
        ("User", "root"),
        ("UMask", "0077"),
        (
            "ReadWritePaths",
            root.to_str().context("non UTF8 private root")?,
        ),
    ] {
        ensure!(
            p.get(k).map(String::as_str) == Some(v),
            "verification 223 sandbox differs: {k}"
        );
    }
    for k in ["CapabilityBoundingSet", "AmbientCapabilities"] {
        ensure!(
            p.get(k)
                .map(|s| s.split_whitespace().collect::<BTreeSet<_>>())
                == Some(BTreeSet::from(["cap_dac_override", "cap_sys_ptrace"])),
            "verification 223 capabilities differ"
        );
    }
    Ok(p)
}
pub(super) fn validate_live(c: &DiagnosticClaim, current: &Value) -> Result<()> {
    let r = checked_diagnostic_launch(c)?;
    ensure!(
        current["Id"] == UNIT
            && current["InvocationID"] == c.invocation_id
            && current["LoadState"] == "loaded"
            && current["NRestarts"] == "0"
            && current["ActiveState"] == "active"
            && current["SubState"] == "running"
            && current["MainPID"]
                .as_str()
                .and_then(|s| s.parse::<u32>().ok())
                .is_some_and(|n| n > 1)
            && current["ControlGroup"] == format!("/system.slice/{UNIT}")
            && command(&current["ExecStart"]) == command(&r["expected_exec_start"]),
        "verification 223 live owner differs"
    );
    live_limits(&c.scratch_path)?;
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CaptureSpec {
    schema: String,
    verification_plan: BoundFile,
    verifier: BoundFile,
    guard_plan: BoundFile,
}
pub(super) fn capture() -> Result<()> {
    let (sb, self_sha) = publication203::parsed_args("capture-verification223-launch")?;
    let s: CaptureSpec = serde_json::from_value(native209::immutable_json(&sb)?)?;
    ensure!(
        s.schema == "jetstreamer-private223-v3-verification-capture-spec-v1"
            && s.verification_plan.path == Path::new(PLAN),
        "verification 223 capture scope differs"
    );
    let p = bound_json(&s.verification_plan)?;
    let ab: BoundFile = serde_json::from_value(p["capacity"].clone())?;
    let a = bound_json(&ab)?;
    let root = PathBuf::from(
        p["private_directory"]
            .as_str()
            .context("private 223 scan root")?,
    );
    let before = unit(UNIT)?;
    let c = DiagnosticClaim {
        epoch: 223,
        unit: UNIT.into(),
        invocation_id: before["InvocationID"]
            .as_str()
            .context("actual private 223 verifier iid")?
            .into(),
        scratch_path: root.clone(),
        launch_receipt: BoundFile {
            path: Path::new(STATE).join("launch.json"),
            sha256: "0".repeat(64),
        },
    };
    let mut r = json!({"schema":SCHEMA,"epoch":223,"unit":UNIT,"invocation_id":c.invocation_id,"launched":true,
        "verification_only_no_replay":true,"verifier":private157::binding(&s.verifier),"verifier_sha256":s.verifier.sha256,
        "verification_plan":private157::binding(&s.verification_plan),"capacity":private157::binding(&ab),
        "guard_plan":private157::binding(&s.guard_plan),"previous_fleet":a["fleet"],"observer":a["observer"],
        "private_directory":root,"maximum_runtime_seconds":86400,"maximum_archive_bytes":160u64<<30,
        "candidate_incremental_peak_bytes":PEAK,"maximum_memory_bytes":MEMORY,"required_guard_minimum_free_bytes":a["minimum_free_bytes"],
        "expected_exec_start":before["ExecStart"],"recorded_unix_seconds":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        "capture_spec":private157::binding(&sb),"capture_self_sha256":self_sha,"producer_at_capture":before});
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
    validate_live_without_receipt(&c, &r, &before)?;
    let caps = live_limits(&root)?;
    ensure!(
        caps.get("ExecMainStartTimestampMonotonic")
            .and_then(|s| s.parse::<u64>().ok())
            .is_some_and(|n| n > 0),
        "private 223 verifier monotonic invocation start missing"
    );
    r["producer_limits_at_capture"] = serde_json::to_value(&caps)?;
    let intent_path = root.join("intent.json");
    let bytes = read_stable_bounded(&intent_path, 8 << 20, "actual private 223 verifier intent")?;
    let intent: Value = serde_json::from_slice(&bytes)?;
    ensure!(
        intent["schema"] == "jetstreamer-private223-v3-verification-intent-v1"
            && intent["unit"] == UNIT
            && intent["invocation_id"] == c.invocation_id
            && intent["self_sha256"] == s.verifier.sha256
            && intent["plan"] == private157::binding(&s.verification_plan)
            && intent["capacity"] == private157::binding(&ab)
            && intent["private_directory"] == r["private_directory"]
            && intent["inputs"] == p["inputs"]
            && intent["publication_authorized"] == false
            && intent["r2_mutations"] == false,
        "private 223 verifier actual intent differs"
    );
    r["producer_intent"] = json!({"path":intent_path,"sha256":hex_lower(&Sha256::digest(&bytes))});
    let fleet = bound_json(&serde_json::from_value(a["fleet"].clone())?)?;
    let observer_binding: BoundFile = serde_json::from_value(a["observer"].clone())?;
    let observer = bound_json(&observer_binding)?;
    ensure!(
        fleet["observer_sha256"] == observer_binding.sha256
            && fleet["observer_receipt"].as_str() == observer_binding.path.to_str()
            && fleet["sampled_at_utc"] == observer["recorded_at_utc"]
            && fleet["first_epoch"] == 201
            && fleet["last_epoch"] == 300,
        "private 223 verifier accepted predecessor differs"
    );
    let mut names = fleet["unit_census"]
        .as_object()
        .context("private 223 verifier complete census")?
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
        all.get(UNIT) == Some(&before) && unit(UNIT)? == before && live_limits(&root)? == caps,
        "private 223 verifier owner/caps changed during capture"
    );
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().mode(0o700).create(STATE)?;
    File::open("/var/lib/jetstreamer")?.sync_all()?;
    private157::immutable_receipt(&Path::new(STATE).join("launch.json"), &r)
}
fn validate_live_without_receipt(c: &DiagnosticClaim, r: &Value, current: &Value) -> Result<()> {
    shape(r, c)?;
    ensure!(
        current["Id"] == UNIT
            && current["LoadState"] == "loaded"
            && current["InvocationID"] == c.invocation_id
            && current["NRestarts"] == "0"
            && current["ActiveState"] == "active"
            && current["SubState"] == "running"
            && current["MainPID"]
                .as_str()
                .and_then(|s| s.parse::<u32>().ok())
                .is_some_and(|n| n > 1)
            && current["ControlGroup"] == format!("/system.slice/{UNIT}")
            && command(&current["ExecStart"]) == command(&r["expected_exec_start"]),
        "private 223 verifier live owner differs"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (DiagnosticClaim, Value) {
        let root = "/var/lib/jetstreamer/horizon-223-private-v3-scan-fixture";
        let tool = "/var/lib/jetstreamer/horizon-223-private-v3-final-tools-fixture/jetstreamer-epoch223-private-verify";
        let sha = "a".repeat(64);
        let c = DiagnosticClaim {
            epoch: 223,
            unit: UNIT.into(),
            invocation_id: "1".repeat(32),
            scratch_path: root.into(),
            launch_receipt: BoundFile {
                path: Path::new(STATE).join("launch.json"),
                sha256: "b".repeat(64),
            },
        };
        let mut r = json!({"schema":SCHEMA,"epoch":223,"unit":UNIT,"invocation_id":c.invocation_id,"launched":true,
            "verification_only_no_replay":true,"verifier":{"path":tool,"sha256":sha},"verifier_sha256":sha,
            "verification_plan":{"path":PLAN,"sha256":sha},"private_directory":root,
            "maximum_archive_bytes":160u64<<30,"candidate_incremental_peak_bytes":PEAK,"maximum_memory_bytes":MEMORY,
            "maximum_runtime_seconds":86400,"required_guard_minimum_free_bytes":2_000_000_000_000u64,
            "expected_exec_start":format!("{{ path={tool} ; argv[]={tool} {PLAN} {sha} {sha} ; ignore_errors=no ; }}")});
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
        (c, r)
    }
    #[test]
    fn exact_verifier_does_not_accept_other_units_archives_or_authority() {
        let (c, r) = fixture();
        shape(&r, &c).unwrap();
        for (key, v) in [
            ("unit", json!(assembly223::UNIT)),
            ("verifier_sha256", json!("b".repeat(64))),
            ("maximum_archive_bytes", json!(161u64 << 30)),
            ("candidate_incremental_peak_bytes", json!(assembly223::PEAK)),
            ("publication_authorized", json!(true)),
            ("r2_mutations", json!(true)),
        ] {
            let mut bad = r.clone();
            bad[key] = v;
            assert!(shape(&bad, &c).is_err(), "{key}");
        }
        for path in [
            "/tmp/horizon-223-private-v3-scan-fixture",
            "/var/lib/jetstreamer/horizon-223-private-v3-scan-",
            "/var/lib/jetstreamer/horizon-223-private-v3-scan-../nested",
        ] {
            assert!(!root_scope(Path::new(path)), "{path}");
        }
        let mut bad = c;
        bad.unit = assembly223::UNIT.into();
        assert!(!namespace(&bad));
    }
    #[test]
    fn zero_worker_guard_is_exact_and_keeps_all_caps() {
        let (c, r) = fixture();
        let p = json!({"schema":"jetstreamer-horizon-standalone-guard-plan-v1","maximum_worker_vmas":3500000,
            "unit":UNIT,"invocation_id":c.invocation_id,"filesystem":"/home/ubuntu","worker_root":c.scratch_path,
            "minimum_free_bytes":2_000_000_000_000u64,"receipt_directory":GUARD_RECEIPTS});
        assert!(guard_matches(&c, &r, &p));
        assert!(diagnostic_guard_workers_match(&c, &[]));
        for key in [
            "bounded_canary",
            "bounded_measurement",
            "native_main",
            "maximum_root_physical_bytes",
        ] {
            let mut bad = p.clone();
            bad[key] = json!(1);
            assert!(!guard_matches(&c, &r, &bad), "{key}");
        }
    }
}
