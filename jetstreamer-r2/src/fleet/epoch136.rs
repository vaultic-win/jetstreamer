//! Closed root experiment with the corrected worker for epoch 136. Never full-epoch or delivery authority.
use super::*;
mod ops;

pub(super) const UNIT: &str = "horizon-qualify-136-capped-root-20261023-v1.service";
const ROOT: &str = "/home/sol/.jetstreamer-private/epoch136-capped-root-20261023-v1";
const PACKAGE: &str = "/usr/local/lib/jetstreamer/horizon-epoch136-capped-inputs-20261023-v1";
const PLAN: &str =
    "/usr/local/lib/jetstreamer/horizon-epoch136-capped-root-plan-20261023-v1/plan.json";
const ADMISSIONS: &str = "/var/lib/jetstreamer/horizon-epoch136-capped-root-admissions-20261023-v1";
const NODE: &str = "d0c784a403d65819de70a499fc4d981217fd16fc30b70fac7e5ec979d0423ff0";
const WORKER: &str = "fce05d551d8154ebda6ff6b3791d02f60b0e0a1e3a69982ea06fa7c31c34b759";
const SNAPSHOT: &str = "snapshot-58751483-84kyzaerEY1FbjzX898LB3cimVkrPXsiRByumLGvTy8C.tar.zst";
const SNAPSHOT_SHA: &str = "0d78ac8daa69790f984ccfaddb01b6a497eb05cc7222533b94b4353dd8abc767";
const CHECKPOINTS_SHA: &str = "5b98d81e9fc843f0a8150df5e4e948fc3dfe9c33c212eefbc797060bfa1b438c";
const CAPABILITY: &str = "/home/sol/.jetstreamer-private/epoch136-capped-input-capability-20261023-v1/receipts/capability.json";
const CAPABILITY_SHA: &str = "aaf10afade9fcb8cd86384187dc5dddc945b45bdd84b440b12a23520307b682f";
const CAPABILITY_IID: &str = "e3323cdeb18e494f8bc8a92445a88847";
pub(super) const GUARD_SHA: &str =
    "35dbd4826c8947f38d50dff049345e1c3d62450eb85e41e94e326880e1898fbc";
const GUARD_BIN: &str = "/usr/local/lib/jetstreamer/horizon-original141-trace-guard-20261023-v1/jetstreamer-horizon-standalone-guard";
const GUARD_UNIT: &str = "horizon-epoch136-capped-root-guard-20261023-v1.service";
const GUARD_ROOT: &str = "/var/lib/jetstreamer/horizon-epoch136-capped-root-guard-20261023-v1";
const GUARD_PLAN: &str =
    "/usr/local/lib/jetstreamer/horizon-epoch136-capped-root-guard-plan-20261023-v1/plan.json";
const PEAK: u64 = 512 << 30;
const MAX_RUNTIME: u64 = 432000;
const BASE_PROTECTED: u64 = 3_572_465_819_078;
pub(super) const SCHEMA: &str = "jetstreamer-private-epoch136-capped-root-launch-v2";
const DENIED: &[&str] = &[
    "replay_launch_authorized",
    "ordinary_replay_claim",
    "current_sidecar_eta_valid",
    "root_checkpoint_verified",
    "full_cold_epoch_peak_qualified",
    "century_200_300_planning_assumption_applied",
    "full_epoch_verified",
    "complete_epoch_span_covered",
    "canonical_prefix_qualified",
    "failed_transaction_reexecuted",
    "canonical_sidecar_authorized",
    "publication_authorized",
    "local_retirement_authorized",
    "runtime_promotion_authorized",
    "remote_mutations",
    "r2_mutations",
];
pub(super) async fn admit() -> Result<()> {
    ops::admit().await
}
pub(super) fn capture() -> Result<()> {
    ops::capture()
}
pub(super) fn prepare() -> Result<()> {
    ops::prepare()
}
pub(super) fn namespace(c: &DiagnosticClaim) -> bool {
    c.unit == UNIT
}
fn command(v: &Value) -> Option<&str> {
    let raw = v.as_str()?;
    if !raw.ends_with(" }") || raw.contains('\n') || raw.matches("{ path=").count() != 1 {
        return None;
    }
    let (text, tail) = raw.split_once(" ; ignore_errors=")?;
    tail.starts_with("no ").then_some(text)
}
fn expected_command() -> String {
    let node = format!("{PACKAGE}/jetstreamer-node");
    format!(
        "{{ path={node} ; argv[]={node} 136 {ROOT}/destination --verify --qualification-end-slot=59183944 --snapshot-archive={PACKAGE}/{SNAPSHOT} --epoch-hashes={PACKAGE}/epoch-hashes-136.txt --horizon-output={ROOT}/output/private.jet --replay-scratch={ROOT}/scratch"
    )
}
fn environment() -> String {
    format!(
        "JETSTREAMER_ALLOW_CANDIDATE_RUNTIME=1 JETSTREAMER_HISTORICAL_WORKER_V1_4_25={PACKAGE}/jetstreamer-historical-worker-v1-4-25 SOLANA_RAYON_THREADS=8 JETSTREAMER_RIPGET_THREADS=32 JETSTREAMER_HISTORICAL_TRACE=1"
    )
}
fn scope(v: &Value) -> Result<()> {
    ensure!(
        v["epoch"] == 136
            && v["unit"] == UNIT
            && v["run_root"] == ROOT
            && v["node_sha256"] == NODE
            && v["worker_sha256"] == WORKER
            && v["snapshot_sha256"] == SNAPSHOT_SHA
            && v["checkpoints_sha256"] == CHECKPOINTS_SHA
            && v["bootstrap_slot"] == 58751483
            && v["terminal_root_slot"] == 59183944
            && v["output_slot_start"] == 58752000
            && v["output_slot_count"] == 431945
            && v["excluded_epoch_suffix_slots"] == 55
            && v["failed_slot"] == 59183097
            && v["failed_entry"] == 197
            && v["failed_transaction"] == 113
            && v["candidate_incremental_peak_bytes"] == PEAK
            && v["maximum_runtime_seconds"] == MAX_RUNTIME
            && v["resource_budget_kind"]
                == "bounded-qualification-stop-not-adopted-full-epoch-peak"
            && v["repair_must_remain_open"] == true
            && v["capped_shrink_candidate"] == true,
        "foreign 136 runtime, input, root, failure, suffix or bounded-stop contract"
    );
    for key in DENIED {
        ensure!(
            v[*key] == false,
            "private 136 grants forbidden authority:{key}"
        );
    }
    Ok(())
}
fn fields(v: &mut Value) {
    for (key, value) in [
        ("epoch", json!(136)),
        ("unit", json!(UNIT)),
        ("run_root", json!(ROOT)),
        ("node_sha256", json!(NODE)),
        ("worker_sha256", json!(WORKER)),
        ("snapshot_sha256", json!(SNAPSHOT_SHA)),
        ("checkpoints_sha256", json!(CHECKPOINTS_SHA)),
        ("bootstrap_slot", json!(58751483)),
        ("terminal_root_slot", json!(59183944)),
        ("output_slot_start", json!(58752000)),
        ("output_slot_count", json!(431945)),
        ("excluded_epoch_suffix_slots", json!(55)),
        ("failed_slot", json!(59183097)),
        ("failed_entry", json!(197)),
        ("failed_transaction", json!(113)),
        ("candidate_incremental_peak_bytes", json!(PEAK)),
        ("maximum_runtime_seconds", json!(MAX_RUNTIME)),
        (
            "resource_budget_kind",
            json!("bounded-qualification-stop-not-adopted-full-epoch-peak"),
        ),
        ("repair_must_remain_open", json!(true)),
        ("capped_shrink_candidate", json!(true)),
    ] {
        v[key] = value;
    }
    for key in DENIED {
        v[*key] = json!(false);
    }
}
fn shape(r: &Value, c: &DiagnosticClaim) -> Result<()> {
    scope(r)?;
    ensure!(
        namespace(c)
            && c.epoch == 136
            && canonical_invocation(&c.invocation_id)
            && c.scratch_path == Path::new(ROOT).join("scratch")
            && c.launch_receipt.path == Path::new(ROOT).join("receipts/launch.json")
            && r["schema"] == SCHEMA
            && r["invocation_id"] == c.invocation_id
            && r["launched"] == true
            && r["plan"]["path"] == PLAN
            && r["capability"]["path"] == CAPABILITY
            && r["capability"]["sha256"] == CAPABILITY_SHA
            && command(&r["expected_exec_start"]) == Some(expected_command().as_str())
            && r["required_guard_minimum_free_bytes"]
                .as_u64()
                .is_some_and(|n| n >= BASE_PROTECTED),
        "private 136 launch identity or command differs"
    );
    Ok(())
}
fn canonical_invocation(s: &str) -> bool {
    s.len() == 32
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn bindings(r: &Value, p: &Value, a: &Value) -> Result<()> {
    scope(p)?;
    scope(a)?;
    ensure!(
        p["schema"] == "jetstreamer-private-epoch136-capped-root-plan-v2"
            && a["schema"] == "jetstreamer-epoch136-capped-root-admission-v2"
            && a["admitted"] == true
            && a["capability"] == r["capability"]
            && p["capability"] == r["capability"]
            && p["admission"] == r["admission"]
            && a["observer"] == r["observer"]
            && a["fleet"] == r["previous_fleet"]
            && a["existing_growth_claims_protected"] == true
            && a["live141_remaining_growth_protected"] == true
            && a["century_floor_protected"] == true
            && a["required_guard_minimum_free_bytes"] == r["required_guard_minimum_free_bytes"]
            && p["required_guard_minimum_free_bytes"] == r["required_guard_minimum_free_bytes"]
            && command(&p["expected_exec_start"]) == command(&r["expected_exec_start"])
            && a["required_initial_free_bytes"]
                .as_u64()
                .zip(a["required_guard_minimum_free_bytes"].as_u64())
                .is_some_and(|(free, floor)| floor.checked_add(PEAK).is_some_and(|n| free >= n)),
        "private 136 plan/admission or growth binding differs"
    );
    let at = a["recorded_unix_seconds"]
        .as_u64()
        .context("admission time")?;
    let start = r["actual_start_unix_seconds"]
        .as_u64()
        .context("producer start")?;
    ensure!(
        at <= start
            && start - at <= 900
            && r["recorded_unix_seconds"]
                .as_u64()
                .is_some_and(|t| start <= t),
        "private 136 admission stale or later than actual start"
    );
    Ok(())
}
fn first_guard(c: &DiagnosticClaim, r: &Value, g: &Value, p: &Value) -> Result<()> {
    ensure!(
        guard_matches(c, r, p)
            && g["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && g["guard_sha256"] == GUARD_SHA
            && g["producer_invocation_id"] == c.invocation_id
            && g["producer"]["invocation_id"] == c.invocation_id
            && g["producer"]["restarts"] == 0
            && g["producer"]["active"] == "active"
            && g["producer"]["sub"] == "running"
            && g["producer"]["cgroup"] == format!("/system.slice/{UNIT}")
            && g["producer"]["restart_policy"] == "no"
            && g["producer"]["kill_mode"] == "control-group"
            && g["producer"]["delegated"] == false
            && g["producer"]["load_state"] == "loaded"
            && g["producer"]["result"] == "success"
            && g["producer"]["pid"].as_u64().is_some_and(|n| n > 1)
            && g["producer_stop_enabled"] == true
            && g["maximum_root_physical_bytes"] == PEAK
            && g["bounded_measurement"] == false
            && g.get("bounded_canary").is_some_and(Value::is_null)
            && g.get("target_handoff").is_some_and(Value::is_null)
            && [
                "trip_reason",
                "worker_observation_error",
                "root_physical_observation_error",
                "canary_target_error",
                "target_handoff_error"
            ]
            .iter()
            .all(|key| g.get(*key).is_some_and(Value::is_null))
            && g["root_physical_observation"]["maximum_physical_bytes"] == PEAK
            && g["root_physical_observation"]["exceeds_budget"] == false
            && g["root_physical_observation"]["conservative_physical_bytes"]
                .as_u64()
                .is_some_and(|n| n <= PEAK)
            && g["workers"]
                .as_array()
                .is_some_and(|w| diagnostic_guard_workers_match(c, w))
            && g["minimum_free_bytes"] == r["required_guard_minimum_free_bytes"]
            && g["available_bytes"]
                .as_u64()
                .zip(g["minimum_free_bytes"].as_u64())
                .is_some_and(|(a, b)| a >= b)
            && g["maximum_worker_vmas"] == 3500000
            && g["remote_mutations"] == false
            && g["r2_mutations"] == false
            && p["schema"] == "jetstreamer-horizon-standalone-guard-plan-v1"
            && p["unit"] == UNIT
            && p["invocation_id"] == c.invocation_id
            && g["recorded_unix_seconds"]
                .as_u64()
                .zip(r["recorded_unix_seconds"].as_u64())
                .is_some_and(|(guard, launch)| guard <= launch && launch - guard <= 900),
        "private 136 lacks real one-worker no-trip invocation-bound root guard"
    );
    Ok(())
}
pub(super) fn guard_matches(c: &DiagnosticClaim, r: &Value, p: &Value) -> bool {
    shape(r, c).is_ok()
        && p["filesystem"] == "/home/sol"
        && p["minimum_free_bytes"] == r["required_guard_minimum_free_bytes"]
        && p["worker_root"] == ROOT
        && p["maximum_root_physical_bytes"] == PEAK
        && p["maximum_worker_vmas"] == 3500000
        && p["receipt_directory"] == GUARD_ROOT
        && p.get("bounded_canary").is_none_or(Value::is_null)
        && p.get("bounded_measurement").is_none_or(Value::is_null)
}
pub(super) fn launch(r: &Value, c: &DiagnosticClaim) -> Result<()> {
    shape(r, c)?;
    let pb: BoundFile = serde_json::from_value(r["plan"].clone())?;
    let ab: BoundFile = serde_json::from_value(r["admission"].clone())?;
    bindings(r, &bound_json(&pb)?, &bound_json(&ab)?)?;
    let gb: BoundFile = serde_json::from_value(r["first_guard"].clone())?;
    ensure!(
        gb.path == Path::new(ROOT).join("receipts/first-guard.json"),
        "foreign 136 first guard path"
    );
    let g = bound_json(&gb)?;
    let gp: BoundFile =
        serde_json::from_value(json!({"path":g["plan"],"sha256":g["plan_sha256"]}))?;
    ensure!(gp.path == Path::new(GUARD_PLAN), "foreign 136 guard plan");
    first_guard(c, r, &g, &bound_json(&gp)?)
}
fn live_shape(c: &DiagnosticClaim, v: &Value) -> Result<()> {
    ensure!(
        namespace(c)
            && v["Id"] == UNIT
            && v["InvocationID"] == c.invocation_id
            && v["LoadState"] == "loaded"
            && v["ActiveState"] == "active"
            && v["SubState"] == "running"
            && v["NRestarts"] == "0"
            && v["Type"] == "exec"
            && v["MainPID"]
                .as_str()
                .and_then(|s| s.parse::<u32>().ok())
                .is_some_and(|n| n > 1)
            && command(&v["ExecStart"]) == Some(expected_command().as_str()),
        "private 136 live owner or command differs"
    );
    Ok(())
}
fn limits(p: &BTreeMap<String, String>) -> Result<()> {
    for (key, value) in [
        ("User", "sol"),
        ("Group", "sol"),
        ("Type", "exec"),
        ("Restart", "no"),
        ("KillMode", "control-group"),
        ("Delegate", "no"),
        ("RuntimeMaxUSec", "5d"),
        ("CPUQuotaPerSecUSec", "8s"),
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
            p.get(key).map(String::as_str) == Some(value),
            "private 136 sandbox differs:{key}"
        );
    }
    ensure!(
        p.get("ReadWritePaths")
            == Some(&format!(
                "{ROOT}/destination {ROOT}/output {ROOT}/scratch {ROOT}/.jetstreamer-private"
            ))
            && p.get("Environment") == Some(&environment()),
        "private 136 writable paths/environment differ"
    );
    Ok(())
}
pub(super) fn validate_live(c: &DiagnosticClaim, v: &Value) -> Result<()> {
    launch(&bound_json(&c.launch_receipt)?, c)?;
    live_shape(c, v)?;
    limits(&ops::sandbox()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (DiagnosticClaim, Value, Value, Value, Value, Value) {
        let c = DiagnosticClaim {
            epoch: 136,
            unit: UNIT.into(),
            invocation_id: "a".repeat(32),
            scratch_path: Path::new(ROOT).join("scratch"),
            launch_receipt: BoundFile {
                path: Path::new(ROOT).join("receipts/launch.json"),
                sha256: "b".repeat(64),
            },
        };
        let mut r = json!({"schema":SCHEMA,"launched":true,"invocation_id":c.invocation_id,
            "plan":{"path":PLAN,"sha256":"c".repeat(64)},"admission":{"path":format!("{ADMISSIONS}/admission-20261023T180000Z.json"),"sha256":"d".repeat(64)},
            "capability":{"path":CAPABILITY,"sha256":CAPABILITY_SHA},"required_guard_minimum_free_bytes":BASE_PROTECTED+PEAK,
            "expected_exec_start":format!("{} ; ignore_errors=no ; start_time=0 }}",expected_command()),
            "observer":{"path":"/sample.json","sha256":"e".repeat(64)},"previous_fleet":{"path":"/fleet.json","sha256":"f".repeat(64)},
            "actual_start_unix_seconds":1100,"recorded_unix_seconds":1200});
        fields(&mut r);
        let mut p = json!({"schema":"jetstreamer-private-epoch136-capped-root-plan-v2","admission":r["admission"],"capability":r["capability"],
            "required_guard_minimum_free_bytes":r["required_guard_minimum_free_bytes"],"expected_exec_start":r["expected_exec_start"]});
        fields(&mut p);
        let mut a = json!({"schema":"jetstreamer-epoch136-capped-root-admission-v2","admitted":true,"observer":r["observer"],"fleet":r["previous_fleet"],"capability":r["capability"],
            "existing_growth_claims_protected":true,"live141_remaining_growth_protected":true,"century_floor_protected":true,
            "required_guard_minimum_free_bytes":r["required_guard_minimum_free_bytes"],"required_initial_free_bytes":BASE_PROTECTED+2*PEAK,
            "recorded_unix_seconds":1000});
        fields(&mut a);
        let gp = json!({"schema":"jetstreamer-horizon-standalone-guard-plan-v1","unit":UNIT,"invocation_id":c.invocation_id,
            "filesystem":"/home/sol","minimum_free_bytes":r["required_guard_minimum_free_bytes"],"worker_root":ROOT,
            "maximum_root_physical_bytes":PEAK,"maximum_worker_vmas":3500000,"receipt_directory":GUARD_ROOT});
        let g = json!({"schema":"jetstreamer-horizon-standalone-guard-sample-v1","guard_sha256":GUARD_SHA,"producer_invocation_id":c.invocation_id,
            "producer":{"invocation_id":c.invocation_id,"active":"active","sub":"running","cgroup":format!("/system.slice/{UNIT}"),
                "restarts":0,"restart_policy":"no","kill_mode":"control-group","delegated":false,"load_state":"loaded","result":"success","pid":10},
            "producer_stop_enabled":true,"maximum_root_physical_bytes":PEAK,"bounded_measurement":false,"bounded_canary":null,"target_handoff":null,
            "trip_reason":null,"worker_observation_error":null,"root_physical_observation_error":null,"canary_target_error":null,"target_handoff_error":null,
            "root_physical_observation":{"maximum_physical_bytes":PEAK,"exceeds_budget":false,"conservative_physical_bytes":100},
            "workers":[[11,200]],"minimum_free_bytes":r["required_guard_minimum_free_bytes"],"available_bytes":BASE_PROTECTED+2*PEAK,
            "maximum_worker_vmas":3500000,"remote_mutations":false,"r2_mutations":false,"recorded_unix_seconds":1190});
        (c, r, p, a, g, gp)
    }
    #[test]
    fn distinct136_profile_cannot_borrow141_186_root_worker_or_full_epoch_authority() {
        let (c, r, ..) = fixture();
        shape(&r, &c).unwrap();
        for (pointer, value) in [
            ("/epoch", json!(141)),
            ("/unit", json!("horizon-qualify-186-other.service")),
            (
                "/worker_sha256",
                json!("abe395d482174e490833928c7343a33d135d8572096faf873ce3103c35fe520d"),
            ),
            ("/bootstrap_slot", json!(60911751)),
            ("/terminal_root_slot", json!(59183999)),
            ("/excluded_epoch_suffix_slots", json!(0)),
            ("/failed_entry", json!(198)),
            ("/candidate_incremental_peak_bytes", json!(300000000000u64)),
            ("/maximum_runtime_seconds", json!(MAX_RUNTIME + 1)),
        ] {
            let mut bad = r.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(shape(&bad, &c).is_err(), "accepted{pointer}");
        }
        for k in DENIED {
            let mut bad = r.clone();
            bad[*k] = json!(true);
            assert!(shape(&bad, &c).is_err(), "accepted{k}");
        }
    }
    #[test]
    fn admission_must_protect_live141_floor_and_match_actual_start() {
        let (_, r, p, a, ..) = fixture();
        bindings(&r, &p, &a).unwrap();
        for (key, value) in [
            ("live141_remaining_growth_protected", json!(false)),
            ("century_floor_protected", json!(false)),
            ("existing_growth_claims_protected", json!(false)),
            ("required_initial_free_bytes", json!(BASE_PROTECTED + PEAK)),
            ("recorded_unix_seconds", json!(1101)),
        ] {
            let mut bad = a.clone();
            bad[key] = value;
            assert!(bindings(&r, &p, &bad).is_err(), "accepted{key}");
        }
        let mut stale = r.clone();
        stale["actual_start_unix_seconds"] = json!(1901);
        assert!(bindings(&stale, &p, &a).is_err());
        let mut replaced = p.clone();
        replaced["expected_exec_start"] = json!("foreign");
        assert!(bindings(&r, &replaced, &a).is_err());
    }
    #[test]
    fn firstfire_requires_real_worker_no_trip_and_whole_root_stop() {
        let (c, r, _, _, g, gp) = fixture();
        first_guard(&c, &r, &g, &gp).unwrap();
        for (pointer, value) in [
            ("/producer/invocation_id", json!("b".repeat(32))),
            ("/producer/restarts", json!(1)),
            ("/producer/delegated", json!(true)),
            ("/producer_stop_enabled", json!(false)),
            ("/workers", json!([])),
            ("/root_physical_observation/exceeds_budget", json!(true)),
            (
                "/root_physical_observation/conservative_physical_bytes",
                json!(PEAK + 1),
            ),
            ("/root_physical_observation_error", json!("scan timed out")),
            ("/bounded_measurement", json!(true)),
            ("/trip_reason", json!("filesystem-reserve")),
            ("/recorded_unix_seconds", json!(1201)),
        ] {
            let mut bad = g.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(first_guard(&c, &r, &bad, &gp).is_err(), "accepted{pointer}");
        }
        for (key, value) in [
            ("worker_root", json!(format!("{ROOT}/scratch"))),
            ("maximum_root_physical_bytes", json!(PEAK - 1)),
            ("minimum_free_bytes", json!(1)),
            ("bounded_canary", json!({})),
        ] {
            let mut bad = gp.clone();
            bad[key] = value;
            assert!(!guard_matches(&c, &r, &bad), "accepted{key}");
        }
    }
    #[test]
    fn command_binds_root_checkpoints_and_strict_verification_not_a_retry_override() {
        let text = expected_command();
        assert!(text.contains(" 136 "));
        assert!(text.contains(" --verify --qualification-end-slot=59183944 "));
        assert!(text.contains("epoch-hashes-136.txt"));
        assert!(!text.contains("--allow"));
        assert!(!text.contains("root-checkpoint-cohort"));
        assert!(!text.contains("epoch141-original"));
        assert!(!text.contains("59183999"));
        let valid = format!("{text} ; ignore_errors=no ; start_time=0 }}");
        assert_eq!(command(&json!(valid)), Some(text.as_str()));
        assert!(
            command(&json!(format!(
                "{valid} {{ path=/other ; argv[]=/other ; ignore_errors=no }}"
            )))
            .is_none()
        );
        assert!(
            command(&json!(
                valid.replace("ignore_errors=no", "ignore_errors=yes")
            ))
            .is_none()
        );
        assert!(command(&json!(format!("{valid}\n"))).is_none());
    }
}
