// Shared validation for two closed, compile-bound private 141 profiles.
use super::*;
#[path = "original141_ops.rs"]
#[allow(
    clippy::duplicate_mod,
    reason = "Each closed profile compiles operations against distinct immutable constants"
)]
mod ops;
pub(super) async fn admit() -> Result<()> {
    ops::admit().await
}
pub(super) fn capture() -> Result<()> {
    ops::capture()
}
pub(super) fn prepare() -> Result<()> {
    ops::prepare()
}

const INPUT: &str = "/usr/local/lib/jetstreamer/horizon-epoch141-original-input-20261023-v1";
const SNAPSHOT: &str = "/usr/local/lib/jetstreamer/horizon-epoch140-native-restore-inputs-20261020-v1/snapshot-60911751-GyFbDnPnUWrFStHKfwWC98xJpmBQKjLyJ9sMf2m6MrWR.tar.zst";
const CHECKPOINTS: &str =
    "/usr/local/lib/jetstreamer/horizon-original141-checkpoints-20261023-v1/epoch-hashes.txt";
const CHECKPOINTS_SHA: &str = "28ff603d15cd7ff653af314887b102697403489ab31cea83708f9676fead9699";
fn admission_path(path: &Path) -> bool {
    if path == Path::new(ADMISSION) {
        return true;
    }
    if path.parent() != Path::new(ADMISSION).parent() {
        return false;
    }
    let Some(stamp) = path
        .file_name()
        .and_then(|s| s.to_str())
        .and_then(|s| s.strip_prefix("admission-"))
        .and_then(|s| s.strip_suffix(".json"))
    else {
        return false;
    };
    if stamp.len() != 16 || !stamp.is_ascii() || &stamp[8..9] != "T" || &stamp[15..16] != "Z" {
        return false;
    }
    utc_seconds(&format!(
        "{}-{}-{}T{}:{}:{}Z",
        &stamp[..4],
        &stamp[4..6],
        &stamp[6..8],
        &stamp[9..11],
        &stamp[11..13],
        &stamp[13..15]
    ))
    .is_ok()
}
const NODE_SHA: &str = "d0c784a403d65819de70a499fc4d981217fd16fc30b70fac7e5ec979d0423ff0";
const INDEX_SHA: &str = "fe38bd4ce018996349c10029720dd7f738340fb0ad30ce6b8577b9651bf87df3";
const DATA_SHA: &str = "5605dd1ba08b7e790227b0efc388a74a02cdf665220d2455c3ed39f803feada0";
const FLOOR: u64 = 3_572_465_819_078;
const DENIED: &[&str] = &[
    "replay_launch_authorized",
    "ordinary_replay_claim",
    "current_sidecar_eta_valid",
    "full_epoch_verified",
    "complete_epoch_span_covered",
    "canonical_sidecar_authorized",
    "publication_authorized",
    "local_retirement_authorized",
    "runtime_promotion_authorized",
    "remote_mutations",
    "r2_mutations",
];

pub(super) fn unit_name(s: &str) -> bool {
    s == UNIT
}
pub(super) fn namespace(c: &DiagnosticClaim) -> bool {
    unit_name(&c.unit)
}
fn invocation(s: &str) -> bool {
    s.len() == 32
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn command(v: &Value) -> Option<&str> {
    let (command, tail) = v.as_str()?.split_once(" ; ignore_errors=")?;
    tail.starts_with("no ").then_some(command)
}
fn expected_command() -> String {
    let node = format!("{PACKAGE}/jetstreamer-node");
    format!(
        "{{ path={node} ; argv[]={node} 141 {ROOT}/destination --verify --qualification-end-slot=61328765 --snapshot-archive={SNAPSHOT} --epoch-hashes={CHECKPOINTS} --horizon-output={ROOT}/output/private.jet --replay-scratch={ROOT}/scratch --epoch141-original-index={INPUT}/index.json --epoch141-original-index-sha256={INDEX_SHA} --epoch141-original-data={INPUT}/original-entries.data --epoch141-original-data-sha256={DATA_SHA}"
    )
}
fn denied(v: &Value) -> Result<()> {
    if CAPPED_SHRINK {
        ensure!(
            v["capped_shrink_candidate"] == true
                && v["capped_shrink_profile_qualified"] == false
                && v["full_cold_epoch_peak_qualified"] == false
                && v["century_200_300_planning_assumption_applied"] == false
                && v.get("worker_entry_terminal_slot").is_none()
                && v.get("worker_freeze_component_diagnostic").is_none()
                && v["resource_budget_kind"]
                    == "bounded-qualification-stop-not-adopted-full-epoch-peak",
            "capped 141 must retain its experimental budget and qualification denials"
        );
    }
    if let Some(slot) = WORKER_ENTRY_TERMINAL {
        ensure!(
            v["worker_freeze_component_diagnostic"] == true
                && v["worker_entry_terminal_slot"] == slot,
            "freeze 141 must bind its worker-enforced diagnostic terminal"
        );
    }
    if TRACE {
        ensure!(
            v["historical_trace_enabled"] == true && v["whole_root_physical_limit_bytes"] == PEAK,
            "trace 141 scope must bind trace logging and whole-root stop"
        );
    }
    for key in DENIED {
        ensure!(
            v[*key] == false,
            "original 141 grants forbidden authority:{key}"
        );
    }
    Ok(())
}
fn shape(r: &Value, c: &DiagnosticClaim) -> Result<()> {
    ensure!(
        namespace(c)
            && c.epoch == 141
            && c.unit == UNIT
            && invocation(&c.invocation_id)
            && c.scratch_path == Path::new(ROOT).join("scratch")
            && c.launch_receipt.path == Path::new(ROOT).join("receipts/launch.json")
            && r["schema"] == SCHEMA
            && r["epoch"] == 141
            && r["unit"] == UNIT
            && r["invocation_id"] == c.invocation_id
            && r["launched"] == true
            && r["private_original_entry_root_qualification"] == true
            && r["node_sha256"] == NODE_SHA
            && r["worker_sha256"] == WORKER_SHA
            && r["original_index_sha256"] == INDEX_SHA
            && r["original_data_sha256"] == DATA_SHA
            && r["checkpoints_sha256"] == CHECKPOINTS_SHA
            && r["snapshot_sha256"]
                == "47d5911465901975e397c570e06ccf72296db7ecd3b3b1beda710cacd3e683a1"
            && r["bootstrap_slot"] == 60911751
            && r["replay_start_slot"] == 60911752
            && r["terminal_root_slot"] == 61328765
            && r["run_root"] == ROOT
            && r["maximum_runtime_seconds"] == MAX_RUNTIME
            && r["actual_start_unix_seconds"].as_u64().is_some_and(
                |t| t > 0 && r["recorded_unix_seconds"].as_u64().is_some_and(|n| t <= n)
            )
            && r["candidate_incremental_peak_bytes"] == PEAK
            && r["required_guard_minimum_free_bytes"]
                .as_u64()
                .is_some_and(|n| n >= FLOOR)
            && r["plan"]["path"] == PLAN
            && canonical_digest(&r["plan"]["sha256"])
            && r["admission"]["path"]
                .as_str()
                .is_some_and(|p| admission_path(Path::new(p)))
            && canonical_digest(&r["admission"]["sha256"])
            && r["first_guard"]["path"].as_str()
                == Some(format!("{ROOT}/receipts/first-guard.json").as_str())
            && canonical_digest(&r["first_guard"]["sha256"])
            && canonical_digest(&r["observer"]["sha256"])
            && canonical_digest(&r["previous_fleet"]["sha256"])
            && command(&r["expected_exec_start"]) == Some(expected_command().as_str()),
        "original 141 launch scope, input or owner differs"
    );
    denied(r)
}
fn bindings(r: &Value, p: &Value, a: &Value) -> Result<()> {
    ensure!(
        p["schema"] == "jetstreamer-private-epoch141-original-entry-root-plan-v2"
            && p["epoch"] == 141
            && p["unit"] == UNIT
            && p["run_root"] == ROOT
            && p["node_sha256"] == NODE_SHA
            && p["worker_sha256"] == WORKER_SHA
            && p["original_index_sha256"] == INDEX_SHA
            && p["original_data_sha256"] == DATA_SHA
            && p["checkpoints"]["path"] == CHECKPOINTS
            && p["checkpoints"]["sha256"] == CHECKPOINTS_SHA
            && p["bootstrap_slot"] == 60911751
            && p["terminal_root_slot"] == 61328765
            && command(&p["expected_exec_start"]) == command(&r["expected_exec_start"])
            && p["admission"] == r["admission"]
            && p["maximum_runtime_seconds"] == MAX_RUNTIME
            && p["candidate_incremental_peak_bytes"] == PEAK
            && a["schema"] == "jetstreamer-original141-root-admission-v2"
            && a["admitted"] == true
            && a["unit"] == UNIT
            && a["node_sha256"] == NODE_SHA
            && a["candidate_incremental_peak_bytes"] == PEAK
            && a["required_guard_minimum_free_bytes"] == r["required_guard_minimum_free_bytes"]
            && a["observer"] == r["observer"]
            && a["fleet"] == r["previous_fleet"]
            && a["existing_growth_claims_protected"] == true
            && a["century_floor_protected"] == true
            && a["minimum_available_memory_bytes"] == MIN_MEMORY
            && a["required_initial_free_bytes"]
                .as_u64()
                .zip(a["required_guard_minimum_free_bytes"].as_u64())
                .is_some_and(|(free, floor)| floor.checked_add(PEAK).is_some_and(|n| free >= n)),
        "original 141 plan/admission binding differs"
    );
    let at = a["recorded_unix_seconds"]
        .as_u64()
        .context("admission clock")?;
    let lt = r["actual_start_unix_seconds"]
        .as_u64()
        .context("actual producer start clock")?;
    ensure!(
        at <= lt && lt - at <= 900 && r["recorded_unix_seconds"].as_u64().is_some_and(|n| lt <= n),
        "stale/future original 141 admission"
    );
    for value in [p, a] {
        denied(value)?;
    }
    Ok(())
}
pub(super) fn launch(r: &Value, c: &DiagnosticClaim) -> Result<()> {
    shape(r, c)?;
    let checkpoints = read_stable_bounded(Path::new(CHECKPOINTS), 1024, "original141 checkpoints")?;
    ensure!(
        hex_lower(&Sha256::digest(&checkpoints)) == CHECKPOINTS_SHA,
        "original 141 checkpoint bytes changed"
    );
    let pb: BoundFile = serde_json::from_value(r["plan"].clone())?;
    let ab: BoundFile = serde_json::from_value(r["admission"].clone())?;
    bindings(r, &bound_json(&pb)?, &bound_json(&ab)?)?;
    let gb: BoundFile = serde_json::from_value(r["first_guard"].clone())?;
    let g = bound_json(&gb)?;
    let gp: BoundFile =
        serde_json::from_value(json!({"path":g["plan"],"sha256":g["plan_sha256"]}))?;
    first_guard(c, r, &g, &bound_json(&gp)?)
}
fn first_guard(c: &DiagnosticClaim, r: &Value, g: &Value, p: &Value) -> Result<()> {
    let time = g["recorded_unix_seconds"].as_u64().context("guard clock")?;
    let launch = r["recorded_unix_seconds"]
        .as_u64()
        .context("launch clock")?;
    ensure!(
        time <= launch
            && launch - time <= 900
            && g["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && g["guard_sha256"] == GUARD_SHA
            && g["producer_invocation_id"] == c.invocation_id
            && g["producer"]["invocation_id"] == c.invocation_id
            && g["producer"]["restarts"] == 0
            && g["producer"]["active"] == "active"
            && g["producer"]["sub"] == "running"
            && g["producer"]["cgroup"] == format!("/system.slice/{UNIT}")
            && g["producer"]["pid"].as_u64().is_some_and(|n| n > 0)
            && g["producer"]["restart_policy"] == "no"
            && g["producer"]["kill_mode"] == "control-group"
            && g["producer"]["delegated"] == false
            && g["producer"]["load_state"] == "loaded"
            && g["producer"]["result"] == "success"
            && g.get("trip_reason").is_some_and(Value::is_null)
            && g.get("worker_observation_error")
                .is_some_and(Value::is_null)
            && (!TRACE
                || (g["producer_stop_enabled"] == true
                    && g["maximum_root_physical_bytes"] == PEAK
                    && g.get("root_physical_observation_error")
                        .is_some_and(Value::is_null)
                    && g["root_physical_observation"]["maximum_physical_bytes"] == PEAK
                    && g["root_physical_observation"]["exceeds_budget"] == false
                    && g["root_physical_observation"]["conservative_physical_bytes"]
                        .as_u64()
                        .is_some_and(|n| n <= PEAK)))
            && g["workers"]
                .as_array()
                .is_some_and(|w| diagnostic_guard_workers_match(c, w))
            && g["minimum_free_bytes"] == r["required_guard_minimum_free_bytes"]
            && g["available_bytes"]
                .as_u64()
                .zip(g["minimum_free_bytes"].as_u64())
                .is_some_and(|(f, m)| f >= m)
            && g["maximum_worker_vmas"] == 3500000
            && g["remote_mutations"] == false
            && g["r2_mutations"] == false
            && p["schema"] == "jetstreamer-horizon-standalone-guard-plan-v1"
            && p["unit"] == UNIT
            && p["invocation_id"] == c.invocation_id
            && guard_matches(c, r, p),
        "original 141 lacks a genuine invocation-bound one-worker guard first fire"
    );
    Ok(())
}
pub(super) fn guard_matches(c: &DiagnosticClaim, r: &Value, p: &Value) -> bool {
    shape(r, c).is_ok()
        && p["filesystem"] == "/home/sol"
        && p["minimum_free_bytes"] == r["required_guard_minimum_free_bytes"]
        && p["worker_root"].as_str()
            == if TRACE {
                Some(ROOT)
            } else {
                c.scratch_path.to_str()
            }
        && (!TRACE || p["maximum_root_physical_bytes"] == PEAK)
        && p["maximum_worker_vmas"] == 3500000
        && p.get("bounded_canary").is_none_or(Value::is_null)
        && p.get("bounded_measurement").is_none_or(Value::is_null)
}
fn live_shape(c: &DiagnosticClaim, v: &Value) -> Result<()> {
    ensure!(
        c.unit == UNIT
            && v["Id"] == UNIT
            && v["InvocationID"] == c.invocation_id
            && v["LoadState"] == "loaded"
            && v["ActiveState"] == "active"
            && v["SubState"] == "running"
            && v["NRestarts"] == "0"
            && v["Type"] == "exec"
            && v["MainPID"]
                .as_str()
                .and_then(|s| s.parse::<u64>().ok())
                .is_some_and(|n| n > 0)
            && command(&v["ExecStart"]) == Some(expected_command().as_str()),
        "original 141 live owner/command differs"
    );
    Ok(())
}
fn limits(p: &BTreeMap<&str, &str>) -> Result<()> {
    let cpu = format!("{CPU_CORES}s");
    for (key, value) in [
        ("User", "sol"),
        ("Type", "exec"),
        ("Restart", "no"),
        ("KillMode", "control-group"),
        ("Delegate", "no"),
        ("RuntimeMaxUSec", RUNTIME_DISPLAY),
        ("CPUQuotaPerSecUSec", cpu.as_str()),
        ("MemoryHigh", "137438953472"),
        ("MemoryMax", "206158430208"),
        ("MemorySwapMax", "0"),
        ("TasksMax", "512"),
        ("UMask", "0077"),
        ("ProtectSystem", "strict"),
        ("ProtectHome", "read-only"),
        ("PrivateTmp", "yes"),
        ("NoNewPrivileges", "yes"),
        ("CapabilityBoundingSet", ""),
        ("AmbientCapabilities", ""),
        ("EnvironmentFiles", ""),
    ] {
        ensure!(
            p.get(key) == Some(&value),
            "original 141 sandbox differs:{key}"
        );
    }
    let writable =
        format!("{ROOT}/destination {ROOT}/output {ROOT}/scratch {ROOT}/.jetstreamer-private");
    ensure!(
        p.get("ReadWritePaths") == Some(&writable.as_str()),
        "original 141 writable roots differ"
    );
    let env = environment();
    ensure!(
        p.get("Environment") == Some(&env.as_str()),
        "original 141 environment differs"
    );
    Ok(())
}
fn environment() -> String {
    let base = format!(
        "JETSTREAMER_ALLOW_CANDIDATE_RUNTIME=1 JETSTREAMER_HISTORICAL_WORKER_V1_4_25={PACKAGE}/jetstreamer-historical-worker-v1-4-25 SOLANA_RAYON_THREADS={CPU_CORES}"
    );
    // The wider worker shares a512-task cgroup with its parent. Bound index
    // download threads while the restored worker remains live.
    let base = if CAPPED_SHRINK {
        format!("{base} JETSTREAMER_RIPGET_THREADS=32")
    } else {
        base
    };
    if TRACE {
        format!("{base} JETSTREAMER_HISTORICAL_TRACE=1")
    } else {
        base
    }
}
fn trace_fields(v: &mut Value) {
    if CAPPED_SHRINK {
        v["capped_shrink_candidate"] = json!(true);
        v["capped_shrink_profile_qualified"] = json!(false);
        v["full_cold_epoch_peak_qualified"] = json!(false);
        v["century_200_300_planning_assumption_applied"] = json!(false);
        v["resource_budget_kind"] = json!("bounded-qualification-stop-not-adopted-full-epoch-peak");
    }
    if let Some(slot) = WORKER_ENTRY_TERMINAL {
        v["worker_freeze_component_diagnostic"] = json!(true);
        v["worker_entry_terminal_slot"] = json!(slot);
    }
    if TRACE {
        v["historical_trace_enabled"] = json!(true);
        v["whole_root_physical_limit_bytes"] = json!(PEAK);
    }
}
pub(super) fn validate_live(c: &DiagnosticClaim, v: &Value) -> Result<()> {
    launch(&bound_json(&c.launch_receipt)?, c)?;
    live_shape(c, v)?;
    let o=ProcessCommand::new("systemctl").args(["show",UNIT,"--no-pager","--property=User,Type,Restart,KillMode,Delegate,RuntimeMaxUSec,CPUQuotaPerSecUSec,MemoryHigh,MemoryMax,MemorySwapMax,TasksMax,UMask,ProtectSystem,ProtectHome,PrivateTmp,NoNewPrivileges,CapabilityBoundingSet,AmbientCapabilities,ReadWritePaths,Environment,EnvironmentFiles"]).output()?;
    ensure!(
        o.status.success() && o.stdout.len() <= 16384,
        "original 141 sandbox read failed"
    );
    let text = std::str::from_utf8(&o.stdout)?;
    let mut props = BTreeMap::new();
    for line in text.lines() {
        let (k, v) = line.split_once('=').context("sandbox property")?;
        ensure!(props.insert(k, v).is_none(), "duplicate sandbox property");
    }
    let empty_files = ops::guard_pin::empty_environment_files(UNIT)?;
    props.insert("EnvironmentFiles", &empty_files);
    limits(&props)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (DiagnosticClaim, Value, Value, Value) {
        let c = DiagnosticClaim {
            epoch: 141,
            unit: UNIT.into(),
            invocation_id: "a".repeat(32),
            scratch_path: Path::new(ROOT).join("scratch"),
            launch_receipt: BoundFile {
                path: Path::new(ROOT).join("receipts/launch.json"),
                sha256: "b".repeat(64),
            },
        };
        let mut r = json!({"schema":SCHEMA,"epoch":141,"unit":UNIT,"invocation_id":c.invocation_id,"launched":true,"private_original_entry_root_qualification":true,"node_sha256":NODE_SHA,"worker_sha256":WORKER_SHA,"original_index_sha256":INDEX_SHA,"original_data_sha256":DATA_SHA,"snapshot_sha256":"47d5911465901975e397c570e06ccf72296db7ecd3b3b1beda710cacd3e683a1","bootstrap_slot":60911751,"replay_start_slot":60911752,"terminal_root_slot":61328765,"run_root":ROOT,"maximum_runtime_seconds":MAX_RUNTIME,"candidate_incremental_peak_bytes":PEAK,"required_guard_minimum_free_bytes":FLOOR,"plan":{"path":PLAN,"sha256":"c".repeat(64)},"admission":{"path":ADMISSION,"sha256":"d".repeat(64)},"expected_exec_start":format!("{} ; ignore_errors=no ; start_time=0 }}",expected_command()),"observer":{"path":"/sample.json","sha256":"e".repeat(64)},"previous_fleet":{"path":"/fleet.json","sha256":"f".repeat(64)},"recorded_unix_seconds":1200});
        let mut p = json!({"schema":"jetstreamer-private-epoch141-original-entry-root-plan-v2","epoch":141,"unit":UNIT,"run_root":ROOT,"node_sha256":NODE_SHA,"worker_sha256":WORKER_SHA,"original_index_sha256":INDEX_SHA,"original_data_sha256":DATA_SHA,"bootstrap_slot":60911751,"terminal_root_slot":61328765,"expected_exec_start":r["expected_exec_start"],"admission":r["admission"],"maximum_runtime_seconds":MAX_RUNTIME,"candidate_incremental_peak_bytes":PEAK});
        let mut a = json!({"schema":"jetstreamer-original141-root-admission-v2","admitted":true,"unit":UNIT,"node_sha256":NODE_SHA,"candidate_incremental_peak_bytes":PEAK,"required_guard_minimum_free_bytes":FLOOR,"required_initial_free_bytes":FLOOR+PEAK,"observer":r["observer"],"fleet":r["previous_fleet"],"existing_growth_claims_protected":true,"century_floor_protected":true,"minimum_available_memory_bytes":MIN_MEMORY,"recorded_unix_seconds":1000});
        r["first_guard"] =
            json!({"path":format!("{ROOT}/receipts/first-guard.json"),"sha256":"1".repeat(64)});
        r["checkpoints_sha256"] = json!(CHECKPOINTS_SHA);
        r["actual_start_unix_seconds"] = json!(1200);
        p["checkpoints"] = json!({"path":CHECKPOINTS,"sha256":CHECKPOINTS_SHA});
        for v in [&mut r, &mut p, &mut a] {
            trace_fields(v);
            for key in DENIED {
                v[*key] = json!(false);
            }
        }
        (c, r, p, a)
    }
    #[test]
    fn exact_scope_and_every_authority_denial_are_required() {
        let (c, r, p, a) = fixture();
        shape(&r, &c).unwrap();
        bindings(&r, &p, &a).unwrap();
        for key in r.as_object().unwrap().keys().filter(|k| {
            !["observer", "previous_fleet", "recorded_unix_seconds"].contains(&k.as_str())
        }) {
            let mut bad = r.clone();
            bad[key] = Value::Null;
            assert!(shape(&bad, &c).is_err(), "launch missing {key}");
        }
        for original in [&p, &a] {
            for key in DENIED {
                let mut bad = original.clone();
                bad[*key] = json!(true);
                assert!(denied(&bad).is_err(), "{key}");
            }
        }
        for field in ["epoch", "unit", "invocation_id", "scratch_path"] {
            let (mut bad, _, _, _) = fixture();
            match field {
                "epoch" => bad.epoch = 144,
                "unit" => bad.unit = "foreign".into(),
                "invocation_id" => bad.invocation_id = "foreign".into(),
                _ => bad.scratch_path = "/foreign".into(),
            }
            assert!(shape(&r, &bad).is_err(), "{field}");
        }
    }
    #[test]
    fn partial_root_cannot_be_retargeted_promoted_or_under_reserved() {
        let (c, r, p, a) = fixture();
        for key in [
            "terminal_root_slot",
            "bootstrap_slot",
            "original_index_sha256",
            "original_data_sha256",
            "expected_exec_start",
        ] {
            let mut bad = r.clone();
            bad[key] = json!("wrong");
            assert!(shape(&bad, &c).is_err(), "{key}");
        }
        for key in [
            "observer",
            "fleet",
            "required_initial_free_bytes",
            "required_guard_minimum_free_bytes",
            "existing_growth_claims_protected",
            "century_floor_protected",
            "recorded_unix_seconds",
        ] {
            let mut bad = a.clone();
            bad[key] = Value::Null;
            assert!(bindings(&r, &p, &bad).is_err(), "{key}");
        }
        let mut bad = a.clone();
        bad["recorded_unix_seconds"] = json!(299);
        assert!(bindings(&r, &p, &bad).is_err());
        let mut bad = a;
        bad["recorded_unix_seconds"] = json!(1201);
        assert!(bindings(&r, &p, &bad).is_err());
        let mut guard = json!({"filesystem":"/home/sol","minimum_free_bytes":FLOOR,"worker_root":if TRACE {PathBuf::from(ROOT)} else {c.scratch_path.clone()},"maximum_worker_vmas":3500000});
        if TRACE {
            guard["maximum_root_physical_bytes"] = json!(PEAK);
        }
        assert!(guard_matches(&c, &r, &guard));
        for key in [
            "filesystem",
            "minimum_free_bytes",
            "worker_root",
            "maximum_worker_vmas",
        ] {
            let mut bad = guard.clone();
            bad[key] = Value::Null;
            assert!(!guard_matches(&c, &r, &bad), "{key}");
        }
        let mut bad = guard;
        bad["bounded_canary"] = json!({"expected_uid":1001});
        assert!(!guard_matches(&c, &r, &bad));
    }
    #[test]
    fn guard_requires_one_worker_exact_invocation_no_trip_and_current_floor() {
        let (c, r, _, _) = fixture();
        let mut p = json!({"schema":"jetstreamer-horizon-standalone-guard-plan-v1","unit":UNIT,"invocation_id":c.invocation_id,"filesystem":"/home/sol","minimum_free_bytes":FLOOR,"worker_root":if TRACE {PathBuf::from(ROOT)} else {c.scratch_path.clone()},"maximum_worker_vmas":3500000});
        let mut g = json!({"schema":"jetstreamer-horizon-standalone-guard-sample-v1","guard_sha256":GUARD_SHA,"producer_invocation_id":c.invocation_id,"producer":{"invocation_id":c.invocation_id,"restarts":0,"active":"active","sub":"running","load_state":"loaded","result":"success","cgroup":format!("/system.slice/{UNIT}"),"pid":100,"restart_policy":"no","kill_mode":"control-group","delegated":false},"trip_reason":null,"worker_observation_error":null,"workers":[[101,500000]],"minimum_free_bytes":FLOOR,"available_bytes":FLOOR+1,"maximum_worker_vmas":3500000,"remote_mutations":false,"r2_mutations":false,"recorded_unix_seconds":1199});
        if TRACE {
            p["maximum_root_physical_bytes"] = json!(PEAK);
            g["producer_stop_enabled"] = json!(true);
            g["maximum_root_physical_bytes"] = json!(PEAK);
            g["root_physical_observation_error"] = Value::Null;
            g["root_physical_observation"] = json!({"maximum_physical_bytes":PEAK,"exceeds_budget":false,"conservative_physical_bytes":4096});
        }
        first_guard(&c, &r, &g, &p).unwrap();
        for key in g.as_object().unwrap().keys() {
            let mut bad = g.clone();
            bad.as_object_mut().unwrap().remove(key);
            assert!(
                first_guard(&c, &r, &bad, &p).is_err(),
                "guard missing {key}"
            );
        }
        for workers in [
            json!([]),
            json!([[101, 3500001]]),
            json!([[101, 3], [102, 4]]),
        ] {
            let mut bad = g.clone();
            bad["workers"] = workers;
            assert!(first_guard(&c, &r, &bad, &p).is_err());
        }
        let mut bad = g.clone();
        bad["producer"]["invocation_id"] = json!("b".repeat(32));
        assert!(first_guard(&c, &r, &bad, &p).is_err());
        let mut bad = g.clone();
        bad["available_bytes"] = json!(FLOOR - 1);
        assert!(first_guard(&c, &r, &bad, &p).is_err());
        let mut bad = g;
        bad["trip_reason"] = json!("floor");
        assert!(first_guard(&c, &r, &bad, &p).is_err());
    }
    #[test]
    fn live_owner_cannot_hide_restart_command_or_sandbox_change() {
        let (c, r, _, _) = fixture();
        let v = json!({"Id":UNIT,"InvocationID":c.invocation_id,"LoadState":"loaded","ActiveState":"active","SubState":"running","NRestarts":"0","Type":"exec","MainPID":"100","ExecStart":r["expected_exec_start"]});
        live_shape(&c, &v).unwrap();
        for key in v.as_object().unwrap().keys() {
            let mut bad = v.clone();
            bad[key] = Value::Null;
            assert!(live_shape(&c, &bad).is_err(), "live {key}");
        }
        let writable =
            format!("{ROOT}/destination {ROOT}/output {ROOT}/scratch {ROOT}/.jetstreamer-private");
        let env = environment();
        let cpu = format!("{CPU_CORES}s");
        let props = BTreeMap::from([
            ("User", "sol"),
            ("Type", "exec"),
            ("Restart", "no"),
            ("KillMode", "control-group"),
            ("Delegate", "no"),
            ("RuntimeMaxUSec", RUNTIME_DISPLAY),
            ("CPUQuotaPerSecUSec", cpu.as_str()),
            ("MemoryHigh", "137438953472"),
            ("MemoryMax", "206158430208"),
            ("MemorySwapMax", "0"),
            ("TasksMax", "512"),
            ("UMask", "0077"),
            ("ProtectSystem", "strict"),
            ("ProtectHome", "read-only"),
            ("PrivateTmp", "yes"),
            ("NoNewPrivileges", "yes"),
            ("CapabilityBoundingSet", ""),
            ("AmbientCapabilities", ""),
            ("EnvironmentFiles", ""),
            ("ReadWritePaths", writable.as_str()),
            ("Environment", env.as_str()),
        ]);
        limits(&props).unwrap();
        for key in props.keys() {
            let mut bad = props.clone();
            bad.remove(key);
            assert!(limits(&bad).is_err(), "sandbox missing {key}");
        }
    }
    #[test]
    fn closed_profiles_cannot_borrow_namespaces_or_trace_authority() {
        let (mut c, r, p, a) = fixture();
        c.unit = if TRACE {
            super::super::original141::UNIT
        } else {
            super::super::original141_trace::UNIT
        }
        .into();
        assert!(!namespace(&c));
        assert!(shape(&r, &c).is_err());
        if TRACE {
            for value in [&r, &p, &a] {
                for key in [
                    "historical_trace_enabled",
                    "whole_root_physical_limit_bytes",
                ] {
                    let mut bad = value.clone();
                    bad[key] = Value::Null;
                    assert!(denied(&bad).is_err(), "{key}");
                }
            }
            if CAPPED_SHRINK {
                assert_eq!(MAX_RUNTIME, 432000);
                assert_eq!(PEAK, 512 << 30);
                assert_eq!(CPU_CORES, 8);
                assert!(WORKER_ENTRY_TERMINAL.is_none());
            } else {
                assert_eq!(MAX_RUNTIME, 1800);
                assert_eq!(PEAK, 256 << 30);
                assert_eq!(CPU_CORES, 2);
            }
            assert!(environment().ends_with("JETSTREAMER_HISTORICAL_TRACE=1"));
        }
    }
}
