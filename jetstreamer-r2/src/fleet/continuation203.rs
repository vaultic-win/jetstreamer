//! Closed observational registration for one exact private203 suffix/assembly.
//! This does not issue admission, launch a process, or qualify publication.
use super::*;

pub(super) const SCHEMA: &str = "jetstreamer-private-epoch203-checkpoint-continuation-launch-v1";
pub(super) const GUARD_SHA: &str =
    "d039ddf0b161bc554614a862bd12987bd6a3474549a22d066ebefa5584e5dd98";
const UNIT: &str = "horizon-qualify-203-checkpoint-continuation-ed66145-v1.service";
const ROOT: &str = "/home/ubuntu/.jetstreamer-private/checkpoint-continuation-203-ed66145-v1";
const NODE: &str =
    "/var/lib/jetstreamer/horizon-continuation203-parent-ed66145-v1/jetstreamer-node";
pub(super) const NODE_SHA: &str =
    "1a299ad19472906b0721555ae3bd01840cbd249724ece9c0f61e086b8ace8716";
const PLAN: &str = "/var/lib/jetstreamer/horizon-continuation203-launch-ed66145-v1/plan.json";
const WORKER: &str = "/var/lib/jetstreamer/horizon-v1616-shrink-budget-worker-003fe15-v1/jetstreamer-historical-worker-v1-6-16-shrink-budget";
pub(super) const PREFIX_SHA: &str =
    "ba191cf1918cac8b67cb7512bd07cc1eeccb16e525e4c15c27fd7c325f6993ce";
pub(super) const NATIVE_SHA: &str =
    "5260d7af71ab802ca711fce706020312212d0c8cdfc01c473398b0a9a0108420";
pub(super) const SNAPSHOT_SHA: &str =
    "d3114597ce25c3efaa4a96899ab3e9437c51cb9086d4166639f0ad2ae0613ee6";
pub(super) const WORKER_SHA: &str =
    "4aeca56378a4bb2c55d0e590c1e334c4afa6a375a2c0d94894b412bea261f1cc";
pub(super) const FLOOR_LOWER_BOUND: u64 = 2_687_830_606_739;
pub(super) const PEAK: u64 = 256 << 30;
const NO_AUTHORITY: &[&str] = &[
    "ordinary_replay_claim",
    "current_sidecar_eta_valid",
    "full_epoch_verified",
    "canonical_sidecar_authorized",
    "runtime_promotion_authorized",
    "publication_authorized",
    "local_retirement_authorized",
    "remote_mutations",
    "r2_mutations",
];

pub(super) fn namespace(c: &DiagnosticClaim) -> bool {
    // Recognize the whole namespace so other attempts cannot borrow generic schemas.
    c.unit
        .starts_with("horizon-qualify-203-checkpoint-continuation-")
}
fn command(v: &Value) -> Option<&str> {
    v.as_str()?.split_once(" ; ignore_errors=").map(|(s, _)| s)
}
fn shape(c: &DiagnosticClaim, r: &Value) -> Result<()> {
    let floor = r["protected_existing_floor_bytes"]
        .as_u64()
        .context("203 protected floor")?;
    let expected = format!(
        "{{ path={NODE} ; argv[]={NODE} 203 {ROOT}/ledger --verify --checkpoint-continuation-plan={PLAN} --checkpoint-continuation-plan-sha256={}",
        r["continuation_plan"]["sha256"]
            .as_str()
            .context("203 plan digest")?
    );
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
            && r["node_sha256"] == NODE_SHA
            && r["worker_sha256"] == WORKER_SHA
            && r["snapshot_sha256"] == SNAPSHOT_SHA
            && r["prefix_sha256"] == PREFIX_SHA
            && r["native_result_sha256"] == NATIVE_SHA
            && r["private_run_root"] == ROOT
            && r["bootstrap_slot"] == 88_127_580u64
            && r["suffix_start_slot"] == 88_127_581u64
            && r["terminal_slot"] == 88_127_999u64
            && r["remaining_slots"] == 419
            && r["maximum_runtime_seconds"] == 10800
            && r["maximum_memory_bytes"] == 128u64 << 30
            && r["maximum_cpu_percent"] == 800
            && r["solana_rayon_threads"] == 16
            && r["experimental_envelope_bytes"] == PEAK
            && floor >= FLOOR_LOWER_BOUND
            && floor.checked_add(PEAK) == r["required_initial_free_bytes"].as_u64()
            && r["required_guard_minimum_free_bytes"]
                .as_u64()
                .is_some_and(|guard| guard >= floor)
            && r["private_suffix_authorized"] == true
            && r["private_assembly_authorized"] == true
            && r["continuation_plan"]["path"] == PLAN
            && canonical_digest(&r["continuation_plan"]["sha256"])
            && command(&r["expected_exec_start"]) == Some(expected.as_str())
            && NO_AUTHORITY.iter().all(|key| r[*key] == false),
        "203 private continuation scope or authority differs"
    );
    Ok(())
}
fn bindings(c: &DiagnosticClaim, r: &Value, p: &Value, a: &Value) -> Result<()> {
    shape(c, r)?;
    ensure!(
        p["schema"] == "jetstreamer-private-epoch203-checkpoint-continuation-plan-v1"
            && p["epoch"] == 203
            && p["producer_unit"] == UNIT
            && p["node_sha256"] == NODE_SHA
            && p["run_root"] == ROOT
            && p["minimum_free_bytes"] == r["required_initial_free_bytes"]
            && p["admission_receipt"] == r["admission"]
            && a["schema"] == "jetstreamer-epoch203-continuation-admission-v1"
            && a["epoch"] == 203
            && a["admitted"] == true
            && a["private_continuation_and_assembly_only"] == true
            && a["node_sha256"] == NODE_SHA
            && a["prefix_sha256"] == PREFIX_SHA
            && a["snapshot_sha256"] == SNAPSHOT_SHA
            && a["native_result_sha256"] == NATIVE_SHA
            && a["worker_sha256"] == WORKER_SHA
            && a["remaining_slots"] == 419
            && a["candidate_incremental_peak_bytes"] == PEAK
            && a["protected_existing_floor_bytes"] == r["protected_existing_floor_bytes"]
            && a["required_guard_minimum_free_bytes"] == r["required_guard_minimum_free_bytes"]
            && a["experimental_peak_guard_includes_other_fleet_allocations"] == true,
        "203 requires exact full-path admission and parent, not native-only admission"
    );
    for (key, digest) in [
        ("prefix_archive", PREFIX_SHA),
        (
            "prefix_manifest",
            "983ecabfc9c36e261a66641b8a039e5e1834198b0c9a07552db38457e67e5722",
        ),
        ("native_probe", NATIVE_SHA),
        ("restart_snapshot", SNAPSHOT_SHA),
        ("worker", WORKER_SHA),
        (
            "genesis_archive",
            "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945",
        ),
    ] {
        let path = p[key]["path"].as_str().context("203 input path")?;
        ensure!(
            p[key]["sha256"] == digest
                && Path::new(path).is_absolute()
                && !Path::new(path).starts_with(ROOT),
            "203 continuation input differs:{key}"
        );
    }
    ensure!(p["worker"]["path"] == WORKER, "203 worker path differs");
    for key in [
        "ordinary_replay_authorized",
        "canonical_sidecar_authorized",
        "publication_authorized",
        "retirement_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(
            a[key] == false,
            "203 admission grants forbidden authority:{key}"
        );
    }
    let admitted = a["recorded_unix_seconds"]
        .as_u64()
        .context("203 admission time")?;
    let launched = r["recorded_unix_seconds"]
        .as_u64()
        .context("203 launch time")?;
    ensure!(
        admitted <= launched && launched - admitted <= 900,
        "203 stale/future admission"
    );
    Ok(())
}
pub(super) fn launch(r: &Value, c: &DiagnosticClaim) -> Result<()> {
    shape(c, r)?;
    let p = bound_json(&serde_json::from_value(r["continuation_plan"].clone())?)?;
    let a = bound_json(&serde_json::from_value(r["admission"].clone())?)?;
    bindings(c, r, &p, &a)?;
    // These are small, immutable, complete primary-source bindings. The actual
    // parent independently rereads the entire prefix and snapshot before replay.
    for key in ["prefix_manifest", "native_probe"] {
        bound_json(&serde_json::from_value(p[key].clone())?)?;
    }
    Ok(())
}
pub(super) fn guard_matches(c: &DiagnosticClaim, r: &Value, p: &Value) -> bool {
    shape(c, r).is_ok()
        && p["filesystem"] == "/"
        && p["minimum_free_bytes"] == r["required_guard_minimum_free_bytes"]
        && p.get("bounded_canary").is_none_or(Value::is_null)
        && p.get("bounded_measurement").is_none_or(Value::is_null)
}
pub(super) fn validate_live(c: &DiagnosticClaim, current: &Value) -> Result<()> {
    let r = checked_diagnostic_launch(c)?;
    ensure!(
        current["Type"] == "exec"
            && current["InvocationID"] == c.invocation_id
            && current["NRestarts"] == "0"
            && current["ActiveState"] == "active"
            && current["SubState"] == "running"
            && command(&current["ExecStart"]) == command(&r["expected_exec_start"]),
        "203 live continuation command/owner differs"
    );
    let out = ProcessCommand::new("systemctl").args(["show", UNIT, "--no-pager",
        "--property=User,Group,Type,Restart,KillMode,Delegate,TasksMax,MemoryHigh,MemoryMax,MemorySwapMax,RuntimeMaxUSec,CPUQuotaPerSecUSec,ProtectSystem,ProtectHome,PrivateNetwork,PrivateMounts,NoNewPrivileges,UMask,ReadWritePaths,CapabilityBoundingSet,AmbientCapabilities,Environment"]).output()?;
    ensure!(
        out.status.success() && out.stdout.len() < 16384,
        "203 sandbox unreadable"
    );
    let mut limits = BTreeMap::new();
    for line in std::str::from_utf8(&out.stdout)?.lines() {
        let (k, v) = line.split_once('=').context("203 limit line")?;
        ensure!(limits.insert(k, v).is_none(), "duplicate203 limit");
    }
    validate_limits(&limits)
}
fn validate_limits(l: &BTreeMap<&str, &str>) -> Result<()> {
    for (k, v) in [
        ("User", "ubuntu"),
        ("Group", "ubuntu"),
        ("Type", "exec"),
        ("Restart", "no"),
        ("KillMode", "control-group"),
        ("Delegate", "no"),
        ("TasksMax", "1024"),
        ("MemoryHigh", "103079215104"),
        ("MemoryMax", "137438953472"),
        ("MemorySwapMax", "0"),
        ("RuntimeMaxUSec", "3h"),
        ("CPUQuotaPerSecUSec", "8s"),
        ("ProtectSystem", "strict"),
        ("ProtectHome", "read-only"),
        ("PrivateNetwork", "no"),
        ("PrivateMounts", "yes"),
        ("NoNewPrivileges", "yes"),
        ("UMask", "0077"),
        ("CapabilityBoundingSet", ""),
        ("AmbientCapabilities", ""),
    ] {
        ensure!(l.get(k) == Some(&v), "203 sandbox differs:{k}");
    }
    let rw: BTreeSet<_> = l
        .get("ReadWritePaths")
        .context("203 writable paths")?
        .split_whitespace()
        .collect();
    ensure!(
        rw == BTreeSet::from([
            ROOT,
            "/home/ubuntu/.jetstreamer-private/checkpoint-continuation-203.lock"
        ]),
        "203 writable scope differs"
    );
    let worker = format!("JETSTREAMER_HISTORICAL_WORKER_V1_6_16={WORKER}");
    let e: BTreeSet<_> = l
        .get("Environment")
        .context("203 environment")?
        .split_whitespace()
        .collect();
    ensure!(
        e == BTreeSet::from([
            "SOLANA_RAYON_THREADS=16",
            "JETSTREAMER_ALLOW_CANDIDATE_RUNTIME=1",
            worker.as_str(),
            "JETSTREAMER_HISTORICAL_CONTROL_TIMEOUT_SECS=60",
            "JETSTREAMER_HISTORICAL_INITIALIZE_TIMEOUT_SECS=1800",
            "JETSTREAMER_HISTORICAL_CHECKPOINT_TIMEOUT_SECS=600",
            "JETSTREAMER_HISTORICAL_REAP_TIMEOUT_SECS=120",
        ]),
        "203 environment differs"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (DiagnosticClaim, Value, Value, Value) {
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
        let binding = json!({"path":"/sealed/admission","sha256":"d".repeat(64)});
        let mut r = json!({"schema":SCHEMA,"epoch":203,"unit":UNIT,"invocation_id":c.invocation_id,
            "launched":true,"node_sha256":NODE_SHA,"worker_sha256":WORKER_SHA,"snapshot_sha256":SNAPSHOT_SHA,
            "prefix_sha256":PREFIX_SHA,"native_result_sha256":NATIVE_SHA,"private_run_root":ROOT,
            "bootstrap_slot":88127580,"suffix_start_slot":88127581,"terminal_slot":88127999,"remaining_slots":419,
            "maximum_runtime_seconds":10800,"maximum_memory_bytes":128u64<<30,"maximum_cpu_percent":800,
            "solana_rayon_threads":16,"experimental_envelope_bytes":PEAK,"protected_existing_floor_bytes":FLOOR_LOWER_BOUND,
            "required_initial_free_bytes":FLOOR_LOWER_BOUND+PEAK,"required_guard_minimum_free_bytes":FLOOR_LOWER_BOUND,
            "private_suffix_authorized":true,"private_assembly_authorized":true,"recorded_unix_seconds":1900,
            "admission":binding,"continuation_plan":{"path":PLAN,"sha256":"c".repeat(64)}});
        for k in NO_AUTHORITY {
            r[*k] = json!(false);
        }
        r["expected_exec_start"] = json!(format!(
            "{{ path={NODE} ; argv[]={NODE} 203 {ROOT}/ledger --verify --checkpoint-continuation-plan={PLAN} --checkpoint-continuation-plan-sha256={} ; ignore_errors=no ; pid=123 }}",
            "c".repeat(64)
        ));
        let mut p = json!({"schema":"jetstreamer-private-epoch203-checkpoint-continuation-plan-v1","epoch":203,
            "producer_unit":UNIT,"node_sha256":NODE_SHA,"run_root":ROOT,"minimum_free_bytes":FLOOR_LOWER_BOUND+PEAK,
            "admission_receipt":binding});
        for (k, hash) in [
            ("prefix_archive", PREFIX_SHA),
            (
                "prefix_manifest",
                "983ecabfc9c36e261a66641b8a039e5e1834198b0c9a07552db38457e67e5722",
            ),
            ("native_probe", NATIVE_SHA),
            ("restart_snapshot", SNAPSHOT_SHA),
            ("worker", WORKER_SHA),
            (
                "genesis_archive",
                "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945",
            ),
        ] {
            p[k] = json!({"path":format!("/sealed/{k}"),"sha256":hash});
        }
        p["worker"]["path"] = json!(WORKER);
        let mut a = json!({"schema":"jetstreamer-epoch203-continuation-admission-v1","epoch":203,"admitted":true,
            "private_continuation_and_assembly_only":true,"node_sha256":NODE_SHA,"prefix_sha256":PREFIX_SHA,
            "snapshot_sha256":SNAPSHOT_SHA,"native_result_sha256":NATIVE_SHA,"worker_sha256":WORKER_SHA,
            "remaining_slots":419,"candidate_incremental_peak_bytes":PEAK,"protected_existing_floor_bytes":FLOOR_LOWER_BOUND,
            "required_guard_minimum_free_bytes":FLOOR_LOWER_BOUND,"experimental_peak_guard_includes_other_fleet_allocations":true,
            "recorded_unix_seconds":1000});
        for k in [
            "ordinary_replay_authorized",
            "canonical_sidecar_authorized",
            "publication_authorized",
            "retirement_authorized",
            "remote_mutations",
            "r2_mutations",
        ] {
            a[k] = json!(false);
        }
        (c, r, p, a)
    }
    #[test]
    fn exact203_continuation_is_not_native213_or_publication() {
        let (c, r, p, a) = fixture();
        bindings(&c, &r, &p, &a).unwrap();
        for (k, v) in [
            ("node_sha256", json!("f".repeat(64))),
            ("remaining_slots", json!(457)),
            ("bootstrap_slot", json!(88127581)),
            ("maximum_runtime_seconds", json!(10801)),
            ("experimental_envelope_bytes", json!(192u64 << 30)),
            ("publication_authorized", json!(true)),
            ("current_sidecar_eta_valid", json!(true)),
        ] {
            let mut bad = r.clone();
            bad[k] = v;
            assert!(bindings(&c, &bad, &p, &a).is_err(), "{k}");
        }
        let mut foreign = c;
        foreign.unit.push('x');
        assert!(shape(&foreign, &r).is_err());
    }
    #[test]
    fn full_path_bindings_reject_stale_or_weakened_admission() {
        let (c, r, p, a) = fixture();
        for (k, v) in [
            ("recorded_unix_seconds", json!(999)),
            ("candidate_incremental_peak_bytes", json!(192u64 << 30)),
            ("node_sha256", json!("f".repeat(64))),
            ("worker_sha256", json!("f".repeat(64))),
            (
                "required_guard_minimum_free_bytes",
                json!(FLOOR_LOWER_BOUND - 1),
            ),
            ("retirement_authorized", json!(true)),
        ] {
            let mut bad = a.clone();
            bad[k] = v;
            assert!(bindings(&c, &r, &p, &bad).is_err(), "{k}");
        }
        let mut bad = p.clone();
        bad["native_probe"]["sha256"] = json!("f".repeat(64));
        assert!(bindings(&c, &r, &bad, &a).is_err());
        bad = p;
        bad["admission_receipt"]["sha256"] = json!("f".repeat(64));
        assert!(bindings(&c, &r, &bad, &a).is_err());
    }
    #[test]
    fn generic_guard_has_no_canary_zero_worker_exemption() {
        let (c, r, _, _) = fixture();
        let p = json!({"filesystem":"/","minimum_free_bytes":FLOOR_LOWER_BOUND});
        assert!(guard_matches(&c, &r, &p));
        let mut bad = p.clone();
        bad["bounded_canary"] = json!({"target_slot":88127999});
        assert!(!guard_matches(&c, &r, &bad));
        bad = p;
        bad["minimum_free_bytes"] = json!(FLOOR_LOWER_BOUND - 1);
        assert!(!guard_matches(&c, &r, &bad));
        // The parent requires an empty run root during the full prefix reread.
        // Guard that existing root before scratch is created, then require a
        // real worker before admitting the live fleet transition.
        assert_eq!(diagnostic_guard_worker_root(&c), Path::new(ROOT));
        assert!(!diagnostic_guard_workers_match(&c, &[]));
        assert!(diagnostic_guard_workers_match(&c, &[json!([123, 350000])]));
    }
    #[test]
    fn limits_require_exact_no_restart_private_environment() {
        let (_, r, _, _) = fixture();
        // Mutation tests exercise every independently checked sandbox limiter.
        let mut l = BTreeMap::new();
        for (k, v) in [
            ("User", "ubuntu"),
            ("Group", "ubuntu"),
            ("Type", "exec"),
            ("Restart", "no"),
            ("KillMode", "control-group"),
            ("Delegate", "no"),
            ("TasksMax", "1024"),
            ("MemoryHigh", "103079215104"),
            ("MemoryMax", "137438953472"),
            ("MemorySwapMax", "0"),
            ("RuntimeMaxUSec", "3h"),
            ("CPUQuotaPerSecUSec", "8s"),
            ("ProtectSystem", "strict"),
            ("ProtectHome", "read-only"),
            ("PrivateNetwork", "no"),
            ("PrivateMounts", "yes"),
            ("NoNewPrivileges", "yes"),
            ("UMask", "0077"),
            ("CapabilityBoundingSet", ""),
            ("AmbientCapabilities", ""),
        ] {
            l.insert(k, v);
        }
        let paths =
            format!("{ROOT} /home/ubuntu/.jetstreamer-private/checkpoint-continuation-203.lock");
        let environment = format!(
            "SOLANA_RAYON_THREADS=16 JETSTREAMER_ALLOW_CANDIDATE_RUNTIME=1 JETSTREAMER_HISTORICAL_WORKER_V1_6_16={WORKER} JETSTREAMER_HISTORICAL_CONTROL_TIMEOUT_SECS=60 JETSTREAMER_HISTORICAL_INITIALIZE_TIMEOUT_SECS=1800 JETSTREAMER_HISTORICAL_CHECKPOINT_TIMEOUT_SECS=600 JETSTREAMER_HISTORICAL_REAP_TIMEOUT_SECS=120"
        );
        l.insert("ReadWritePaths", &paths);
        l.insert("Environment", &environment);
        validate_limits(&l).unwrap();
        for key in l.keys() {
            let mut bad = l.clone();
            bad.insert(key, "foreign");
            assert!(validate_limits(&bad).is_err(), "{key}");
        }
        assert_eq!(r["current_sidecar_eta_valid"], false);
    }
}
