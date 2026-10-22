//! Exact no-replay assembly recovery; never an ordinary epoch or publication claim.
use super::*;

pub(super) const SCHEMA: &str = "jetstreamer-private144-assembly-only-launch-v1";
pub(super) const UNIT: &str = "horizon-qualify-144-assembly-only-recovery-20261022-v1.service";
pub(super) const ROOT: &str = "/home/sol/.jetstreamer-private/epoch144-assembly-only-20261022-v2";
pub(super) const TOOL: &str = "/usr/local/lib/jetstreamer/horizon-epoch144-assembly-only-tools-20261022-v2/jetstreamer-epoch144-assembly-only";
pub(super) const TOOL_SHA: &str =
    "25402432882dc8fdcb7331c34be7a20056c0df13ce0eaec33f571edba9695b97";
pub(super) const PLAN: &str =
    "/usr/local/lib/jetstreamer/horizon-epoch144-assembly-only-launch-plan-20261022-v2/plan.json";
pub(super) const STATE: &str = "/var/lib/jetstreamer/horizon-assembly144-launch-20261022-v1";
const BASELINE: u64 = 3_916_063_202_758;
const PEAK: u64 = 160 << 30;

pub(super) fn namespace(c: &DiagnosticClaim) -> bool {
    c.epoch == 144 && c.unit == UNIT
}
fn command(v: &Value) -> Option<&str> {
    v.as_str()?.split_once(" ; ignore_errors=").map(|(s, _)| s)
}
fn expected_command(plan_sha: &str) -> String {
    format!(
        "{{ path={TOOL} ; argv[]={TOOL} {PLAN} --plan-sha256 {plan_sha} --self-sha256 {TOOL_SHA}"
    )
}
fn shape(r: &Value, c: &DiagnosticClaim) -> Result<()> {
    ensure!(
        namespace(c)
            && c.scratch_path == Path::new(ROOT)
            && c.invocation_id.len() == 32
            && c.invocation_id
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            && r["schema"] == SCHEMA
            && r["epoch"] == 144
            && r["unit"] == UNIT
            && r["invocation_id"] == c.invocation_id
            && r["launched"] == true
            && r["assembly_only_no_replay"] == true
            && r["assembler_sha256"] == TOOL_SHA
            && r["assembly_plan"]["path"] == PLAN
            && canonical_digest(&r["assembly_plan"]["sha256"])
            && r["output_root"] == ROOT
            && r["maximum_runtime_seconds"] == 86400
            && r["maximum_archive_bytes"] == 112u64 << 30
            && r["candidate_incremental_peak_bytes"] == PEAK
            && r["protected_existing_floor_bytes"] == BASELINE
            && command(&r["expected_exec_start"])
                == Some(
                    expected_command(r["assembly_plan"]["sha256"].as_str().unwrap_or("")).as_str()
                ),
        "assembly144 launch scope or exact command differs"
    );
    for flag in [
        "ordinary_replay_claim",
        "current_sidecar_eta_valid",
        "replay_launch_authorized",
        "full_epoch_verified",
        "local_retirement_authorized",
        "canonical_sidecar_authorized",
        "runtime_promotion_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(
            r[flag] == false,
            "assembly144 forbidden launch authority:{flag}"
        );
    }
    Ok(())
}
fn bindings(r: &Value, p: &Value, a: &Value, ab: &BoundFile) -> Result<()> {
    ensure!(
        p["schema"] == "jetstreamer-private144-assembly-only-plan-v1"
            && p["assembler_sha256"] == TOOL_SHA
            && p["output_root"] == ROOT
            && p["maximum_runtime_seconds"] == 86400
            && p["maximum_archive_bytes"] == 112u64 << 30
            && p["admission"] == private157::binding(ab)
            && a["schema"] == "jetstreamer-private144-assembly-only-admission-v1"
            && a["admitted"] == true
            && a["assembly_only_no_replay"] == true
            && a["assembler_sha256"] == TOOL_SHA
            && a["output_root"] == ROOT
            && a["output_filesystem"] == "/home/sol"
            && a["output_filesystem_device"].as_u64().is_some()
            && a["candidate_incremental_peak_bytes"] == PEAK
            && a["protected_existing_floor_bytes"] == BASELINE
            && a["maximum_runtime_seconds"] == p["maximum_runtime_seconds"]
            && a["maximum_archive_bytes"] == p["maximum_archive_bytes"]
            && a["available_bytes"]
                .as_u64()
                .is_some_and(|n| n >= BASELINE + PEAK)
            && a["required_guard_minimum_free_bytes"]
                .as_u64()
                .zip(a["available_bytes"].as_u64())
                .is_some_and(
                    |(floor, available)| floor >= BASELINE.max(available.saturating_sub(PEAK))
                )
            && a["memory_available_kib"]
                .as_u64()
                .is_some_and(|n| n >= 128 * 1024 * 1024)
            && r["required_guard_minimum_free_bytes"] == a["required_guard_minimum_free_bytes"]
            && a["observer"] == r["observer"]
            && a["fleet"] == r["previous_fleet"],
        "assembly144 exact plan/admission/resource binding differs"
    );
    for (key, digest) in [
        (
            "prefix_sha256",
            "917f700274c0ff0386cd8be2f27eb2ace9f3bc7dff38e1010d0c04bb79b8c273",
        ),
        (
            "suffix_sha256",
            "3df30cabba516ff6de39bfc236fca030e3bb75b45603d88ef7baf7a6d669a414",
        ),
        (
            "prefix_manifest_sha256",
            "691d5f3768b8c283678937b49790606b6091d4ab632372bfff38664c005b544a",
        ),
        (
            "suffix_manifest_sha256",
            "065445bef8d301a45a24ba8e14f34b2c0c06906a9cfe7a06cbfd04eeba3f15ce",
        ),
    ] {
        ensure!(
            a[key] == digest,
            "assembly144 source identity differs:{key}"
        );
    }
    for key in ["prefix_manifest", "suffix_manifest"] {
        ensure!(
            p[key]["sha256"] == a[format!("{key}_sha256")],
            "assembly144 source manifest differs"
        );
    }
    for flag in [
        "replay_launch_authorized",
        "canonical_sidecar_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(a[flag] == false, "assembly144 admission authority:{flag}");
    }
    let admitted = a["recorded_unix_seconds"]
        .as_u64()
        .context("assembly admission time")?;
    let launched = r["recorded_unix_seconds"]
        .as_u64()
        .context("assembly launch time")?;
    ensure!(
        admitted <= launched && launched - admitted <= 900,
        "assembly144 launch admission stale/future"
    );
    assembly144_admission::check_timeout(&a["original_timeout"])?;
    Ok(())
}
pub(super) fn launch(r: &Value, c: &DiagnosticClaim) -> Result<()> {
    shape(r, c)?;
    let pb: BoundFile = serde_json::from_value(r["assembly_plan"].clone())?;
    let ab: BoundFile = serde_json::from_value(r["admission"].clone())?;
    bindings(r, &bound_json(&pb)?, &bound_json(&ab)?, &ab)
}
pub(super) fn validate_live(c: &DiagnosticClaim, current: &Value) -> Result<()> {
    let r = checked_diagnostic_launch(c)?;
    live_owner(&r, c, current)?;
    live_limits()?;
    assembly144_admission::timeout_properties()?;
    Ok(())
}
fn live_owner(r: &Value, c: &DiagnosticClaim, v: &Value) -> Result<()> {
    ensure!(
        namespace(c)
            && v["Id"] == UNIT
            && v["LoadState"] == "loaded"
            && v["InvocationID"] == c.invocation_id
            && v["NRestarts"] == "0"
            && v["Type"] == "exec"
            && v["ActiveState"] == "active"
            && v["SubState"] == "running"
            && v["MainPID"]
                .as_str()
                .and_then(|s| s.parse::<u32>().ok())
                .is_some_and(|n| n > 0)
            && command(&v["ExecStart"]) == command(&r["expected_exec_start"]),
        "assembly144 live owner differs"
    );
    Ok(())
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
        ("RuntimeMaxUSec", "1d"),
        ("CPUQuotaPerSecUSec", "4s"),
        ("ProtectSystem", "strict"),
        ("ProtectHome", "read-only"),
        ("PrivateNetwork", "yes"),
        ("PrivateMounts", "yes"),
        ("NoNewPrivileges", "yes"),
        ("User", "root"),
        ("Group", "root"),
        ("UMask", "0077"),
        ("CapabilityBoundingSet", "cap_dac_override"),
        ("AmbientCapabilities", "cap_dac_override"),
        ("ReadWritePaths", ROOT),
        ("Environment", ""),
    ] {
        ensure!(l.get(k) == Some(&v), "assembly144 sandbox differs:{k}");
    }
    Ok(())
}
fn live_limits() -> Result<()> {
    let o = ProcessCommand::new("systemctl").args(["show", UNIT,
        "--property=Type,Restart,KillMode,Delegate,TasksMax,MemoryHigh,MemoryMax,MemorySwapMax,RuntimeMaxUSec,CPUQuotaPerSecUSec,ProtectSystem,ProtectHome,PrivateNetwork,PrivateMounts,NoNewPrivileges,ReadWritePaths,User,Group,UMask,CapabilityBoundingSet,AmbientCapabilities,Environment"]).output()?;
    ensure!(
        o.status.success() && o.stdout.len() < 16384,
        "assembly144 limits unreadable"
    );
    let text = std::str::from_utf8(&o.stdout)?;
    let mut fields = BTreeMap::new();
    for line in text.lines() {
        let (k, v) = line.split_once('=').context("assembly limit line")?;
        ensure!(fields.insert(k, v).is_none(), "duplicate assembly limit");
    }
    validate_limits(&fields)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CaptureSpec {
    schema: String,
    assembly_plan: BoundFile,
    admission: BoundFile,
    observer: BoundFile,
    previous_fleet: BoundFile,
}
pub(super) fn capture_launch() -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    let args: Vec<_> = env::args().collect();
    ensure!(
        args.len() == 7 && args[3] == "--spec-sha256" && args[5] == "--self-sha256",
        "usage: capture-assembly-only144-launch SPEC --spec-sha256 SHA --self-sha256 SHA"
    );
    continuation144::sealed_self(&args[6])?;
    let sb = BoundFile {
        path: args[2].clone().into(),
        sha256: args[4].clone(),
    };
    let sm = fs::symlink_metadata(&sb.path)?;
    ensure!(
        sm.is_file() && sm.uid() == 0 && sm.nlink() == 1 && sm.mode() & 0o222 == 0,
        "unsealed assembly capture spec"
    );
    let s: CaptureSpec = serde_json::from_value(bound_json(&sb)?)?;
    ensure!(
        s.schema == "jetstreamer-private144-assembly-only-capture-spec-v1"
            && s.assembly_plan.path == Path::new(PLAN),
        "foreign assembly capture spec"
    );
    let original = assembly144_admission::timeout_properties()?;
    let a = bound_json(&s.admission)?;
    let o = bound_json(&s.observer)?;
    let f = bound_json(&s.previous_fleet)?;
    ensure!(
        a["observer"] == private157::binding(&s.observer)
            && a["fleet"] == private157::binding(&s.previous_fleet)
            && o["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && f["schema"] == super::SCHEMA
            && f["observer_sha256"] == s.observer.sha256
            && f["first_epoch"] == 101
            && f["last_epoch"] == 200
            && f["sampled_at_utc"] == o["recorded_at_utc"],
        "assembly capture predecessor differs"
    );
    let before = unit(UNIT)?;
    let iid = before["InvocationID"]
        .as_str()
        .context("assembly invocation")?;
    let c = DiagnosticClaim {
        epoch: 144,
        unit: UNIT.into(),
        invocation_id: iid.into(),
        scratch_path: ROOT.into(),
        launch_receipt: BoundFile {
            path: Path::new(STATE).join("launch.json"),
            sha256: "0".repeat(64),
        },
    };
    let mut r = json!({"schema":SCHEMA,"epoch":144,"unit":UNIT,"invocation_id":iid,"launched":true,
        "assembly_only_no_replay":true,"assembler_sha256":TOOL_SHA,"assembly_plan":private157::binding(&s.assembly_plan),
        "admission":private157::binding(&s.admission),"observer":private157::binding(&s.observer),"previous_fleet":private157::binding(&s.previous_fleet),
        "output_root":ROOT,"maximum_runtime_seconds":86400,"maximum_archive_bytes":112u64<<30,
        "candidate_incremental_peak_bytes":PEAK,"protected_existing_floor_bytes":BASELINE,
        "required_guard_minimum_free_bytes":a["required_guard_minimum_free_bytes"],"expected_exec_start":before["ExecStart"],
        "recorded_unix_seconds":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),"capture_spec":private157::binding(&sb),"capture_self_sha256":args[6]});
    for flag in [
        "ordinary_replay_claim",
        "current_sidecar_eta_valid",
        "replay_launch_authorized",
        "full_epoch_verified",
        "local_retirement_authorized",
        "canonical_sidecar_authorized",
        "runtime_promotion_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        r[flag] = json!(false);
    }
    launch(&r, &c)?;
    live_owner(&r, &c, &before)?;
    live_limits()?;
    let root = fs::symlink_metadata(ROOT)?;
    ensure!(
        root.is_dir()
            && root.uid() == 0
            && root.dev() == fs::metadata("/home/sol")?.dev()
            && a["output_filesystem_device"].as_u64() == Some(root.dev())
            && root.mode() & 0o077 == 0
            && Path::new(ROOT).canonicalize()? == Path::new(ROOT),
        "unsafe assembly output root"
    );
    let tool = fs::symlink_metadata(TOOL)?;
    ensure!(
        tool.is_file()
            && tool.uid() == 0
            && tool.nlink() == 1
            && tool.mode() & 0o222 == 0
            && hex_lower(&Sha256::digest(fs::read(TOOL)?)) == TOOL_SHA,
        "assembly executable changed"
    );
    ensure!(
        unit(UNIT)? == before && assembly144_admission::timeout_properties()? == original,
        "assembly/original owner changed during capture"
    );
    fs::DirBuilder::new().mode(0o700).create(STATE)?;
    File::open(Path::new(STATE).parent().context("capture parent")?)?.sync_all()?;
    private157::immutable_receipt(&c.launch_receipt.path, &r)?;
    let guard = Path::new(STATE).join("guard-plan.json");
    persist(
        &guard,
        &json!({"schema":"jetstreamer-horizon-standalone-guard-plan-v1","unit":UNIT,"invocation_id":iid,
        "filesystem":"/home/sol","minimum_free_bytes":a["required_guard_minimum_free_bytes"],"worker_root":ROOT,
        "maximum_worker_vmas":3500000,"receipt_directory":"/var/lib/jetstreamer/horizon-assembly144-guard-20261022-v1","bounded_measurement":null}),
    )?;
    let gb = private157::file_binding(&guard)?;
    persist(
        &Path::new(STATE).join("guard-seal-plan.json"),
        &json!({"schema":"jetstreamer-sealed-deployment-plan-v1",
        "destination":"/usr/local/lib/jetstreamer/horizon-assembly144-guard-20261022-v1",
        "members":[{"source":guard,"name":"guard-plan.json","sha256":gb["sha256"],"mode":256}]}),
    )?;
    println!(
        "assembly-only owner captured; timer-bound zero-worker guard first fire and fleet transition still required"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Value, DiagnosticClaim) {
        let c = DiagnosticClaim {
            epoch: 144,
            unit: UNIT.into(),
            invocation_id: "a".repeat(32),
            scratch_path: ROOT.into(),
            launch_receipt: BoundFile {
                path: "/launch".into(),
                sha256: "b".repeat(64),
            },
        };
        let mut r = json!({"schema":SCHEMA,"epoch":144,"unit":UNIT,"invocation_id":c.invocation_id,"launched":true,
            "assembly_only_no_replay":true,"assembler_sha256":TOOL_SHA,"assembly_plan":{"path":PLAN,"sha256":"c".repeat(64)},
            "output_root":ROOT,"maximum_runtime_seconds":86400,"maximum_archive_bytes":112u64<<30,
            "candidate_incremental_peak_bytes":PEAK,"protected_existing_floor_bytes":BASELINE,
            "expected_exec_start":format!("{} ; ignore_errors=no ; pid=1 }}",expected_command(&"c".repeat(64)))});
        for flag in [
            "ordinary_replay_claim",
            "current_sidecar_eta_valid",
            "replay_launch_authorized",
            "full_epoch_verified",
            "local_retirement_authorized",
            "canonical_sidecar_authorized",
            "runtime_promotion_authorized",
            "publication_authorized",
            "remote_mutations",
            "r2_mutations",
        ] {
            r[flag] = json!(false);
        }
        (r, c)
    }
    #[test]
    fn exact_assembly_profile_cannot_borrow_original_or_replay_authority() {
        let (r, c) = fixture();
        shape(&r, &c).unwrap();
        for (k, v) in [
            ("schema", json!(continuation144::SCHEMA)),
            ("unit", json!(continuation144::UNIT)),
            ("assembler_sha256", json!(continuation144::NODE_SHA)),
            ("replay_launch_authorized", json!(true)),
            ("current_sidecar_eta_valid", json!(true)),
            ("publication_authorized", json!(true)),
            ("maximum_runtime_seconds", json!(7200)),
            ("candidate_incremental_peak_bytes", json!(192u64 << 30)),
        ] {
            let mut bad = r.clone();
            bad[k] = v;
            assert!(shape(&bad, &c).is_err(), "{k}");
        }
        let mut bad = r.clone();
        bad["expected_exec_start"] = json!(format!(
            "{} --replay ; ignore_errors=no",
            expected_command(&"c".repeat(64))
        ));
        assert!(shape(&bad, &c).is_err());
    }
    #[test]
    fn display_only_command_reset_preserves_exact_live_identity() {
        let (r, c) = fixture();
        let mut v = json!({"Id":UNIT,"LoadState":"loaded","InvocationID":c.invocation_id,"NRestarts":"0","MainPID":"123",
            "Type":"exec","ActiveState":"active","SubState":"running","ExecStart":r["expected_exec_start"]});
        live_owner(&r, &c, &v).unwrap();
        v["ExecStart"] = json!(format!(
            "{} ; ignore_errors=no ; pid=0 ; start_time=[n/a] }}",
            expected_command(&"c".repeat(64))
        ));
        live_owner(&r, &c, &v).unwrap();
        for (k, x) in [
            ("InvocationID", json!("b".repeat(32))),
            ("MainPID", json!("0")),
            ("NRestarts", json!("1")),
            ("SubState", json!("exited")),
            ("ExecStart", json!("foreign ; ignore_errors=no")),
        ] {
            let mut bad = v.clone();
            bad[k] = x;
            assert!(live_owner(&r, &c, &bad).is_err(), "{k}");
        }
    }

    #[test]
    fn zero_worker_exception_is_exclusive_to_exact_no_replay_owner() {
        let (_, mut c) = fixture();
        assert!(diagnostic_guard_workers_match(&c, &[]));
        assert!(!diagnostic_guard_workers_match(&c, &[json!([123, 400000])]));
        c.unit = continuation144::UNIT.into();
        assert!(!diagnostic_guard_workers_match(&c, &[]));
        assert!(diagnostic_guard_workers_match(&c, &[json!([123, 400000])]));
        assert!(!diagnostic_guard_workers_match(
            &c,
            &[json!([123, 3500001])]
        ));
        c.unit = UNIT.into();
        c.epoch = 145;
        assert!(!diagnostic_guard_workers_match(&c, &[]));
    }

    #[test]
    fn assembly_binding_cannot_borrow_stale_underfunded_or_original_success() {
        let (mut r, _) = fixture();
        let ab = BoundFile {
            path: "/admission".into(),
            sha256: "d".repeat(64),
        };
        let mut a = json!({"schema":"jetstreamer-private144-assembly-only-admission-v1","admitted":true,
            "assembly_only_no_replay":true,"assembler_sha256":TOOL_SHA,"candidate_incremental_peak_bytes":PEAK,
            "output_root":ROOT,"output_filesystem":"/home/sol","output_filesystem_device":123,
            "protected_existing_floor_bytes":BASELINE,"maximum_runtime_seconds":86400,"maximum_archive_bytes":112u64<<30,
            "available_bytes":BASELINE+PEAK+100,"required_guard_minimum_free_bytes":BASELINE+100,
            "memory_available_kib":128u64*1024*1024,"observer":{"path":"/observer","sha256":"e".repeat(64)},
            "fleet":{"path":"/fleet","sha256":"f".repeat(64)},"recorded_unix_seconds":1000,
            "prefix_sha256":"917f700274c0ff0386cd8be2f27eb2ace9f3bc7dff38e1010d0c04bb79b8c273",
            "suffix_sha256":"3df30cabba516ff6de39bfc236fca030e3bb75b45603d88ef7baf7a6d669a414",
            "prefix_manifest_sha256":"691d5f3768b8c283678937b49790606b6091d4ab632372bfff38664c005b544a",
            "suffix_manifest_sha256":"065445bef8d301a45a24ba8e14f34b2c0c06906a9cfe7a06cbfd04eeba3f15ce",
            "original_timeout":{"Id":continuation144::UNIT,"InvocationID":"8fddd3ef045c4fe5b12c7d25f43a4b73",
                "MainPID":"0","NRestarts":"0","Restart":"no","Result":"timeout","ActiveState":"failed",
                "SubState":"failed","RuntimeMaxUSec":"2h","ExecMainStatus":"9"}});
        for flag in [
            "replay_launch_authorized",
            "canonical_sidecar_authorized",
            "publication_authorized",
            "remote_mutations",
            "r2_mutations",
        ] {
            a[flag] = json!(false);
        }
        r["observer"] = a["observer"].clone();
        r["previous_fleet"] = a["fleet"].clone();
        r["recorded_unix_seconds"] = json!(1001);
        r["required_guard_minimum_free_bytes"] = a["required_guard_minimum_free_bytes"].clone();
        let p = json!({"schema":"jetstreamer-private144-assembly-only-plan-v1","assembler_sha256":TOOL_SHA,
            "output_root":ROOT,"maximum_runtime_seconds":86400,"maximum_archive_bytes":112u64<<30,"admission":private157::binding(&ab),
            "prefix_manifest":{"sha256":a["prefix_manifest_sha256"]},"suffix_manifest":{"sha256":a["suffix_manifest_sha256"]}});
        bindings(&r, &p, &a, &ab).unwrap();
        for (ptr, v) in [
            ("/original_timeout/Result", json!("success")),
            ("/original_timeout/MainPID", json!("123")),
            ("/original_timeout/InvocationID", json!("a".repeat(32))),
            ("/available_bytes", json!(BASELINE)),
            ("/recorded_unix_seconds", json!(0)),
            ("/recorded_unix_seconds", json!(1002)),
            ("/required_guard_minimum_free_bytes", json!(BASELINE)),
            ("/publication_authorized", json!(true)),
            ("/prefix_manifest_sha256", json!("a".repeat(64))),
            ("/maximum_runtime_seconds", json!(7200)),
        ] {
            let mut bad = a.clone();
            *bad.pointer_mut(ptr).unwrap() = v;
            assert!(bindings(&r, &p, &bad, &ab).is_err(), "{ptr}");
        }
    }
}
