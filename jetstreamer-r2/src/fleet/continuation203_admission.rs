//! Exact private 203 complete-path admission issuer. Never launches a service.
use super::continuation203 as c;
use super::*;
use std::ffi::CString;

const FLOOR_SHA: &str = "b77b70205043c49d4c8ead819c7938e4eb461a43e5547d45af60ca0054e55271";
const PRIOR_ADMISSION_SHA: &str =
    "adbd9c64971f94bf63482d286ae6221671e4cec3f3450379c956e1864e4de627";
const TERMINAL205_SHA: &str = "0cd7e0223c3b10c6e5ef83b34f76a0eb2320f611960c475d2b99091dfee02637";
const LIVE225: &str = "horizon-qualify-225-natural-root-resource-shrink-budget-2f856bd-v1.service";
const IID225: &str = "4cd76ae1353a4411885b997f04306402";
const UNIT205: &str = "horizon-qualify-205-bounded-resource-0136-v1.service";
const OUTPUT_ROOT: &str = "/var/lib/jetstreamer/horizon-continuation203-admission-v1";
const MEMORY_KIB: u64 = 256 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    observer: BoundFile,
    fleet: BoundFile,
    fleet_plan: BoundFile,
    floor: BoundFile,
    prior_native_admission: BoundFile,
    terminal205: BoundFile,
    native_result: BoundFile,
    older225_guard: BoundFile,
    resource_policy: BoundFile,
    node: BoundFile,
    output: PathBuf,
}

fn policy(p: &Value, native: &Value, prior: &Value, terminal: &Value) -> Result<()> {
    ensure!(
        p["schema"] == "jetstreamer-epoch203-continuation-resource-policy-v1"
            && p["epoch"] == 203
            && p["remaining_slots"] == 419
            && p["prefix_archive_bytes"] == 103_781_283_604u64
            && p["native_result_sha256"] == c::NATIVE_SHA
            && p["candidate_incremental_peak_bytes"] == c::PEAK
            && p["protected_existing_floor_bytes"] == c::FLOOR_LOWER_BOUND
            && p["native_copy_restore_indexes_bytes"] == 64u64 << 30
            && p["suffix_archive_and_growth_bytes"] == 16u64 << 30
            && p["assembled_archive_bytes"] == 112u64 << 30
            && p["independent_verification_scratch_bytes"] == 16u64 << 30
            && p["incremental_margin_bytes"] == 48u64 << 30
            && p["minimum_available_memory_kib"] == MEMORY_KIB
            && p["older225_remaining_bytes"] == 640u64 << 30
            && p["experimental_guarded_envelope"] == true
            && p["full_cold_peak_qualified"] == false
            && p["replay_launch_authorized"] == false
            && p["publication_authorized"] == false
            && p["r2_mutations"] == false,
        "203 requires whole-path budget, not native-only/cold-peak authority"
    );
    ensure!(
        native["schema"] == "jetstreamer-private-epoch203-native-restore-probe-v1"
            && native["passed"] == true
            && native["replay_entries_sent"] == 0
            && native["native_result"]["comparison_passed"] == true
            && native["native_result"]["shutdown_passed"] == true
            && native["worker_sha256"] == c::WORKER_SHA
            && native["snapshot_sha256"] == c::SNAPSHOT_SHA,
        "203 native comparison did not pass"
    );
    ensure!(
        prior["schema"] == "jetstreamer-epoch203-native-admission-receipt-v1"
            && prior["admitted"] == true
            && prior["protected_existing_floor_bytes"] == c::FLOOR_LOWER_BOUND
            && prior["disk"]["older225_remaining_bytes"] == 640u64 << 30
            && prior["disk"]["failed223_remaining_bytes"] == 0
            && prior["disk"]["failed223_owner_still_failed_pid0_restart0_and_guard_stopped"]
                == true,
        "203 must preserve prior accounting, not invent a capacity release"
    );
    ensure!(
        terminal["schema"] == "jetstreamer-private-epoch205-bounded-resource-v1"
            && terminal["unit"] == UNIT205
            && terminal["invocation_id"] == "e03b74cf861c4d9ba2fc09c34c479537"
            && terminal["success"] == true
            && terminal["target_reached"] == true
            && terminal["observed_slot"] == 88_584_000u64
            && terminal["target_slot"] == 88_584_000u64
            && terminal["child_return_code"] == 1
            && terminal["external_signal"] == 0
            && terminal["error"].is_null()
            && terminal["authority"]["full_cold_epoch_peak_qualified"] == false
            && terminal["authority"]["publication_authorized"] == false,
        "205 future trial debt needs actual approved terminal evidence"
    );
    Ok(())
}

pub(super) fn floor(v: &Value, fleet: &Value) -> Result<u64> {
    ensure!(
        v["schema"] == "horizon-century-floor-recomputation-v1"
            && v["century_first_epoch"] == 200
            && v["century_last_epoch"] == 300,
        "wrong 203 century floor"
    );
    let rows = v["census"].as_array().context("203 floor census")?;
    let inventory = fleet["inventory"]["entries"]
        .as_array()
        .context("203 ready census")?;
    let mut seen = BTreeSet::new();
    let mut sum = 0u64;
    for row in rows {
        let e = row["epoch"].as_u64().context("203 floor epoch")?;
        let n = row["jet_size_bytes"].as_u64().context("203 floor bytes")?;
        ensure!(
            (201..=300).contains(&e)
                && seen.insert(e)
                && n > 0
                && canonical_digest(&row["archive_sha256"])
                && canonical_digest(&row["r2_receipt_sha256"])
                && canonical_digest(&row["full_receipt_sha256"])
                && canonical_digest(&row["plugin_receipt_sha256"]),
            "203 partial/duplicate/unproven floor sample"
        );
        let matches: Vec<_> = inventory.iter().filter(|r| r["epoch"] == e).collect();
        ensure!(
            matches.len() == 1
                && matches[0]["state"] == "ready-pair"
                && matches[0]["archive_length"] == n
                && matches[0]["sidecar_sha256"] == row["archive_sha256"]
                && matches[0]["archive_metadata_sha256"] == row["archive_sha256"],
            "203 floor sample differs from accepted authenticated ready pair"
        );
        sum = sum.checked_add(n).context("203 floor sum overflow")?;
    }
    let count = rows.len() as u64;
    ensure!(
        count == 13 && fleet["inventory"]["ready_pairs"] == count,
        "203 floor must be recomputed when canonical census changes"
    );
    let bytes = sum
        .checked_mul(2)
        .context("203 floor overflow")?
        .div_ceil(count);
    ensure!(
        v["sample_count"] == count
            && v["sum_jet_size_bytes"] == sum
            && v["floor_bytes"] == bytes
            && bytes
                .checked_add((640 + 64) << 30)
                .is_some_and(|n| n <= c::FLOOR_LOWER_BOUND),
        "203 floor arithmetic or protected older growth differs"
    );
    Ok(bytes)
}

fn sample(s: &Spec, o: &Value, f: &Value, p: &Value, now: u64) -> Result<()> {
    let t = utc_seconds(o["recorded_at_utc"].as_str().context("203 observer time")?)?;
    ensure!(
        s.schema == "jetstreamer-epoch203-continuation-admission-spec-v1"
            && s.floor.sha256 == FLOOR_SHA
            && s.native_result.sha256 == c::NATIVE_SHA
            && s.prior_native_admission.sha256 == PRIOR_ADMISSION_SHA
            && s.terminal205.sha256 == TERMINAL205_SHA
            && s.node.sha256 == c::NODE_SHA
            && o["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && f["schema"] == SCHEMA
            && f["first_epoch"] == 201
            && f["last_epoch"] == 300
            && f["observer_sha256"] == s.observer.sha256
            && f["sampled_at_utc"] == o["recorded_at_utc"]
            && f["plan"].as_str() == s.fleet_plan.path.to_str()
            && f["plan_sha256"] == s.fleet_plan.sha256
            && p["observer"] == private157::binding(&s.observer)
            && f["inventory"]["anomalies"] == 0
            && t <= now
            && now - t <= 1800,
        "203 admission needs fresh accepted complete fleet, not stale planning"
    );
    ensure!(
        o["filesystem"]["conservative_available_bytes"]
            .as_u64()
            .is_some_and(|n| n >= c::FLOOR_LOWER_BOUND + c::PEAK)
            && o["host_memory"]["conservative_available_kib"]
                .as_u64()
                .is_some_and(|n| n >= MEMORY_KIB)
            && o["vm_max_map_count"]
                .as_u64()
                .is_some_and(|n| n >= 4_194_304),
        "203 sampled full-path disk/memory/VMA envelope unavailable"
    );
    let active = f["active"].as_array().context("203 active census")?;
    ensure!(
        active.len() == 1
            && active[0]["epoch"] == 225
            && active[0]["producer"]["Id"] == LIVE225
            && active[0]["producer"]["InvocationID"] == IID225,
        "203 admission must reconsider changed live claims"
    );
    ensure!(
        o["replays"].as_array().is_some_and(Vec::is_empty),
        "203 unexpected ordinary replay"
    );
    let ds = o["diagnostic_replays"]
        .as_array()
        .context("203 diagnostic census")?;
    ensure!(
        ds.len() == 1
            && ds[0]["range"] == "225-226"
            && ds[0]["status"] == "observed"
            && ds[0]["error"].is_null(),
        "203 incomplete diagnostic observation"
    );
    let r = &ds[0]["observation"];
    ensure!(
        r["invocation_binding_stable"] == true
            && r["producer_after"]["invocation_id"] == IID225
            && r["producer_after"]["restarts"] == 0
            && r["controller_after"]["invocation_id"] == IID225
            && r["controller_after"]["restarts"] == 0
            && r["worker_after"]["matching_workers"] == 1
            && r["worker_after"]["vmas"]
                .as_u64()
                .is_some_and(|n| n > 0 && n < 3_500_000)
            && r["useful_work"]["sufficient_for_rates"] == true
            && r["useful_work"]["slots_per_second"]
                .as_f64()
                .is_some_and(|n| n.is_finite() && n > 0.0),
        "203 protected 225 is not stable/advancing/below VMA ceiling"
    );
    for k in [
        "memory_events.oom",
        "memory_events.oom_kill",
        "memory_events.oom_group_kill",
        "memory_events.max",
    ] {
        ensure!(
            r["cross_sample"]["producer_cgroup_counter_delta"][k] == 0,
            "203 blocked by protected 225 memory event:{k}"
        );
    }
    let psi = &o["host_global_pressure"]["cross_sample"];
    let millis = psi["elapsed_millis"]
        .as_u64()
        .context("203 host pressure window")?;
    ensure!(
        psi["status"] == "observed" && millis >= 1_800_000,
        "203 no settled host pressure window"
    );
    for (key, maximum_percent) in [
        ("io.full_total_usec", 20u64),
        ("memory.full_total_usec", 5),
        ("cpu.some_total_usec", 20),
    ] {
        let delta = psi["counter_delta_usec"][key]
            .as_u64()
            .context("203 host pressure counter")?;
        ensure!(
            delta
                .checked_mul(100)
                .zip(
                    millis
                        .checked_mul(1000)
                        .and_then(|v| v.checked_mul(maximum_percent))
                )
                .is_some_and(|(n, limit)| n <= limit),
            "203 host pressure blocks another lane:{key}"
        );
    }
    let leaf = s
        .output
        .file_name()
        .and_then(|n| n.to_str())
        .context("203 output name")?;
    ensure!(
        s.output.parent() == Some(Path::new(OUTPUT_ROOT))
            && leaf.starts_with("admission-")
            && leaf.ends_with(".json")
            && leaf
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)),
        "203 wrong private admission output"
    );
    Ok(())
}

fn guard(g: &Value, now: u64) -> Result<()> {
    ensure!(
        g["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && g["guard_sha256"]
                == "cc3536dfcc268c913feccf1603a25e3cdbdf2807289c9061e04884027d1b1560"
            && g["producer_invocation_id"] == IID225
            && g["producer"]["invocation_id"] == IID225
            && g["producer"]["active"] == "active"
            && g["producer"]["sub"] == "running"
            && g["producer"]["restarts"] == 0
            && g["producer"]["load_state"] == "loaded"
            && g["producer"]["result"] == "success"
            && g["producer"]["restart_policy"] == "no"
            && g["producer"]["kill_mode"] == "control-group"
            && g["producer"]["cgroup"] == format!("/system.slice/{LIVE225}")
            && g.get("trip_reason").is_some_and(Value::is_null)
            && g.get("worker_observation_error")
                .is_some_and(Value::is_null)
            && g["minimum_free_bytes"] == 1_347_800_810_387u64
            && g["recorded_unix_seconds"]
                .as_u64()
                .is_some_and(|t| t <= now && now - t <= 1800)
            && g["minimum_free_bytes"]
                .as_u64()
                .and_then(|n| n.checked_add(64 << 30))
                .is_some_and(|n| n <= c::FLOOR_LOWER_BOUND)
            && g["available_bytes"]
                .as_u64()
                .zip(g["minimum_free_bytes"].as_u64())
                .is_some_and(|(n, min)| n >= min),
        "203 needs fresh no-trip225 guard and must preserve its protected reserve"
    );
    let workers = g["workers"].as_array().context("203 older guard workers")?;
    ensure!(
        workers.len() == 1
            && workers[0][0].as_u64().is_some_and(|p| p > 0)
            && workers[0][1]
                .as_u64()
                .is_some_and(|v| v > 0 && v < 3_500_000),
        "203 protected 225 guard lacks a real bounded worker"
    );
    Ok(())
}

fn owners(f: &Value, current: &BTreeMap<String, Value>) -> Result<()> {
    snapshot144::check_owners(f, current)?;
    for (name, u) in current {
        ensure!(
            !diagnostic_stage_running(u) || (name == LIVE225 && u["InvocationID"] == IID225),
            "203 admission found additional live work:{name}"
        );
    }
    let stopped = current
        .get(UNIT205)
        .context("203 missing terminal 205 census")?;
    ensure!(
        stopped["MainPID"] == "0"
            && stopped["NRestarts"] == "0"
            && stopped["ActiveState"] == "inactive"
            && stopped["Result"] == "success"
            && stopped["ExecMainStatus"] == "0",
        "203 cannot release a live/replaced/failed205 trial"
    );
    Ok(())
}

fn free_bytes() -> Result<u64> {
    let path = CString::new("/")?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    ensure!(
        unsafe { libc::statvfs(path.as_ptr(), stat.as_mut_ptr()) } == 0,
        "203 statvfs failed"
    );
    let stat = unsafe { stat.assume_init() };
    stat.f_bavail
        .checked_mul(stat.f_frsize)
        .context("203 free-byte overflow")
}

pub(super) fn run() -> Result<()> {
    let args: Vec<_> = env::args().collect();
    let check = args.len() == 8 && args[7] == "--check-only";
    ensure!(
        (args.len() == 7 || check)
            && args[3] == "--spec-sha256"
            && args[5] == "--self-sha256"
            && unsafe { libc::geteuid() } == 0,
        "usage: admit-continuation203 SPEC --spec-sha256 SHA --self-sha256 SHA [--check-only] (root)"
    );
    let own = fs::read_link("/proc/self/exe")?;
    let m = fs::symlink_metadata(&own)?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o222 == 0
            && hex_lower(&Sha256::digest(fs::read("/proc/self/exe")?)) == args[6],
        "203 unsealed admission writer"
    );
    let binding = BoundFile {
        path: args[2].clone().into(),
        sha256: args[4].clone(),
    };
    let m = fs::symlink_metadata(&binding.path)?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o222 == 0
            && binding.path.canonicalize()? == binding.path,
        "203 unsealed admission specification"
    );
    let s: Spec = serde_json::from_value(bound_json(&binding)?)?;
    let o = bound_json(&s.observer)?;
    let f = bound_json(&s.fleet)?;
    let p = bound_json(&s.fleet_plan)?;
    let native = bound_json(&s.native_result)?;
    let prior = bound_json(&s.prior_native_admission)?;
    let terminal = bound_json(&s.terminal205)?;
    let resource = bound_json(&s.resource_policy)?;
    policy(&resource, &native, &prior, &terminal)?;
    let floor_bytes = floor(&bound_json(&s.floor)?, &f)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    sample(&s, &o, &f, &p, now)?;
    let older_guard = bound_json(&s.older225_guard)?;
    guard(&older_guard, now)?;
    let m = fs::symlink_metadata(&s.node.path)?;
    ensure!(
        s.node.path
            == Path::new(
                "/var/lib/jetstreamer/horizon-continuation203-parent-ed66145-v1/jetstreamer-node"
            )
            && m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o222 == 0
            && m.len() <= 256 << 20
            && hex_lower(&Sha256::digest(fs::read(&s.node.path)?)) == c::NODE_SHA,
        "203 parent identity differs"
    );
    validate_output_destination(&s.output)?;
    if check {
        println!(
            "203 full-path preflight passed; no resource/service observations, writes or launch"
        );
        return Ok(());
    }
    let invocation = env::var("INVOCATION_ID").context("203 persistent invocation required")?;
    ensure!(
        invocation.len() == 32
            && invocation
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "203 invalid admission invocation"
    );
    let names = f["unit_census"]
        .as_object()
        .context("203 accepted unit census")?
        .keys()
        .cloned()
        .collect();
    let before = census(&names, 201, 300)?;
    owners(&f, &before)?;
    let available = free_bytes()?;
    let memory = fs::read_to_string("/proc/meminfo")?
        .lines()
        .find_map(|line| {
            line.strip_prefix("MemAvailable:")
                .and_then(|v| v.split_whitespace().next())
                .and_then(|v| v.parse::<u64>().ok())
        })
        .context("203 memory available")?;
    let maps = fs::read_to_string("/proc/sys/vm/max_map_count")?
        .trim()
        .parse::<u64>()?;
    let cpus = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    ensure!(
        available >= c::FLOOR_LOWER_BOUND + c::PEAK
            && memory >= MEMORY_KIB
            && maps >= 4_194_304
            && cpus >= 16,
        "203 actual full-path disk/memory/VMA/CPU envelope unavailable"
    );
    let after = census(&names, 201, 300)?;
    owners(&f, &after)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    sample(&s, &o, &f, &p, now)?;
    guard(&older_guard, now)?;
    private157::immutable_receipt(
        &s.output,
        &json!({
            "schema":"jetstreamer-epoch203-continuation-admission-v1","epoch":203,"admitted":true,
            "private_continuation_and_assembly_only":true,"node_sha256":c::NODE_SHA,"prefix_sha256":c::PREFIX_SHA,
            "snapshot_sha256":c::SNAPSHOT_SHA,"native_result_sha256":c::NATIVE_SHA,"worker_sha256":c::WORKER_SHA,
            "remaining_slots":419,"candidate_incremental_peak_bytes":c::PEAK,"protected_existing_floor_bytes":c::FLOOR_LOWER_BOUND,
            "required_guard_minimum_free_bytes":available-c::PEAK,
            "experimental_peak_guard_includes_other_fleet_allocations":true,
            "observer":private157::binding(&s.observer),"fleet":private157::binding(&s.fleet),
            "floor":private157::binding(&s.floor),"resource_policy":private157::binding(&s.resource_policy),
            "terminal205":private157::binding(&s.terminal205),"older225_guard":private157::binding(&s.older225_guard),
            "spec":private157::binding(&binding),"self_sha256":args[6],"invocation_id":invocation,"recorded_unix_seconds":now,
            "century_floor_bytes":floor_bytes,"available_bytes":available,"memory_available_kib":memory,
            "vm_max_map_count":maps,"visible_cpus":cpus,"unit_census_before":before,"unit_census_after":after,
            "exact_node_input_capability_required":true,"real_worker_guard_first_fire_required":true,
            "new_routine_resource_samples":0,"full_cold_peak_qualified":false,"ordinary_replay_authorized":false,
            "canonical_sidecar_authorized":false,"publication_authorized":false,"retirement_authorized":false,
            "remote_mutations":false,"r2_mutations":false
        }),
    )?;
    println!(
        "203 complete-path admission recorded; input capability and real guarded launch remain separate"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn binding(path: &str, hash: &str) -> BoundFile {
        BoundFile {
            path: path.into(),
            sha256: hash.into(),
        }
    }
    fn spec() -> Spec {
        Spec {
            schema: "jetstreamer-epoch203-continuation-admission-spec-v1".into(),
            observer: binding("/sealed/observer", &"a".repeat(64)),
            fleet: binding("/sealed/fleet", &"b".repeat(64)),
            fleet_plan: binding("/sealed/fleet-plan", &"c".repeat(64)),
            floor: binding("/sealed/floor", FLOOR_SHA),
            prior_native_admission: binding("/sealed/prior", PRIOR_ADMISSION_SHA),
            terminal205: binding("/sealed/terminal205", TERMINAL205_SHA),
            native_result: binding("/sealed/native", c::NATIVE_SHA),
            older225_guard: binding("/sealed/guard", &"d".repeat(64)),
            resource_policy: binding("/sealed/policy", &"e".repeat(64)),
            node: binding("/sealed/node", c::NODE_SHA),
            output: Path::new(OUTPUT_ROOT).join("admission-test.json"),
        }
    }
    fn observations(s: &Spec) -> (Value, Value, Value) {
        let owner = json!({"Id":LIVE225,"InvocationID":IID225});
        let o = json!({"schema":"jetstreamer-horizon-live-resource-sample-v2","recorded_at_utc":"2026-10-23T03:45:52Z",
            "filesystem":{"conservative_available_bytes":c::FLOOR_LOWER_BOUND+c::PEAK},
            "host_memory":{"conservative_available_kib":MEMORY_KIB},"vm_max_map_count":4194304,"replays":[],
            "diagnostic_replays":[{"range":"225-226","status":"observed","error":null,
                "observation":{"invocation_binding_stable":true,"producer_after":{"invocation_id":IID225,"restarts":0},
                    "controller_after":{"invocation_id":IID225,"restarts":0},"worker_after":{"matching_workers":1,"vmas":420000},
                    "useful_work":{"sufficient_for_rates":true,"slots_per_second":2.1},
                    "cross_sample":{"producer_cgroup_counter_delta":{"memory_events.oom":0,"memory_events.oom_kill":0,
                        "memory_events.oom_group_kill":0,"memory_events.max":0}}}}],
            "host_global_pressure":{"cross_sample":{"status":"observed","elapsed_millis":1800000,
                "counter_delta_usec":{"io.full_total_usec":0,"memory.full_total_usec":0,"cpu.some_total_usec":0}}}});
        let f = json!({"schema":SCHEMA,"first_epoch":201,"last_epoch":300,"observer_sha256":s.observer.sha256,
            "sampled_at_utc":o["recorded_at_utc"],"plan":s.fleet_plan.path,"plan_sha256":s.fleet_plan.sha256,
            "inventory":{"anomalies":0},"active":[{"epoch":225,"producer":owner}]});
        let p = json!({"observer":private157::binding(&s.observer)});
        (o, f, p)
    }
    #[test]
    fn stale_incomplete_or_changed_fleet_cannot_issue203_admission() {
        let s = spec();
        let (o, f, p) = observations(&s);
        let t = utc_seconds("2026-10-23T03:45:52Z").unwrap();
        sample(&s, &o, &f, &p, t + 1800).unwrap();
        assert!(sample(&s, &o, &f, &p, t + 1801).is_err());
        assert!(sample(&s, &o, &f, &p, t - 1).is_err());
        for (path, value) in [
            ("/observer_sha256", json!("f".repeat(64))),
            ("/first_epoch", json!(101)),
            ("/inventory/anomalies", json!(1)),
            ("/active/0/producer/InvocationID", json!("f".repeat(32))),
        ] {
            let mut bad = f.clone();
            *bad.pointer_mut(path).unwrap() = value;
            assert!(sample(&s, &o, &bad, &p, t).is_err(), "{path}");
        }
        let mut bad = f;
        bad["active"]
            .as_array_mut()
            .unwrap()
            .push(json!({"epoch":203}));
        assert!(sample(&s, &o, &bad, &p, t).is_err());
    }
    #[test]
    fn pressure_memory_vma_and_settled_progress_are_independent_gates() {
        let s = spec();
        let (o, f, p) = observations(&s);
        let t = utc_seconds("2026-10-23T03:45:52Z").unwrap();
        for (path, value) in [
            (
                "/filesystem/conservative_available_bytes",
                json!(c::FLOOR_LOWER_BOUND + c::PEAK - 1),
            ),
            (
                "/host_memory/conservative_available_kib",
                json!(MEMORY_KIB - 1),
            ),
            ("/vm_max_map_count", json!(4194303)),
            (
                "/diagnostic_replays/0/observation/worker_after/matching_workers",
                json!(0),
            ),
            (
                "/diagnostic_replays/0/observation/useful_work/sufficient_for_rates",
                json!(false),
            ),
            (
                "/diagnostic_replays/0/observation/cross_sample/producer_cgroup_counter_delta/memory_events.oom",
                json!(1),
            ),
            (
                "/host_global_pressure/cross_sample/elapsed_millis",
                json!(1799999),
            ),
            (
                "/host_global_pressure/cross_sample/counter_delta_usec/io.full_total_usec",
                json!(360000001u64),
            ),
            (
                "/host_global_pressure/cross_sample/counter_delta_usec/memory.full_total_usec",
                json!(90000001u64),
            ),
        ] {
            let mut bad = o.clone();
            *bad.pointer_mut(path).unwrap() = value;
            assert!(sample(&s, &bad, &f, &p, t).is_err(), "{path}");
        }
    }
    fn floor_fixture() -> (Value, Value) {
        let mut rows = Vec::new();
        let mut remote = Vec::new();
        for e in [
            201, 202, 206, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222,
        ] {
            rows.push(json!({"epoch":e,"jet_size_bytes":100,"archive_sha256":"a".repeat(64),
                "r2_receipt_sha256":"b".repeat(64),"full_receipt_sha256":"c".repeat(64),"plugin_receipt_sha256":"d".repeat(64)}));
            remote.push(json!({"epoch":e,"state":"ready-pair","archive_length":100,
                "sidecar_sha256":"a".repeat(64),"archive_metadata_sha256":"a".repeat(64)}));
        }
        (
            json!({"schema":"horizon-century-floor-recomputation-v1","century_first_epoch":200,"century_last_epoch":300,
            "census":rows,"sample_count":13,"sum_jet_size_bytes":1300,"floor_bytes":200}),
            json!({"inventory":{"entries":remote,"ready_pairs":13}}),
        )
    }
    #[test]
    fn canonical_floor_rejects_duplicates_archive_only_and_unreviewed_growth() {
        let (v, f) = floor_fixture();
        assert_eq!(floor(&v, &f).unwrap(), 200);
        let mut bad = v.clone();
        bad["census"][1]["epoch"] = json!(201);
        assert!(floor(&bad, &f).is_err());
        bad = v.clone();
        bad["census"][0]
            .as_object_mut()
            .unwrap()
            .remove("plugin_receipt_sha256");
        assert!(floor(&bad, &f).is_err());
        bad = v;
        bad["floor_bytes"] = json!(201);
        assert!(floor(&bad, &f).is_err());
        let (v, mut f) = floor_fixture();
        f["inventory"]["entries"][0]["state"] = json!("archive-only");
        assert!(floor(&v, &f).is_err());
        f["inventory"]["entries"][0]["state"] = json!("ready-pair");
        f["inventory"]["ready_pairs"] = json!(14);
        assert!(floor(&v, &f).is_err());
    }
    fn policy_fixture() -> (Value, Value, Value, Value) {
        (
            json!({"schema":"jetstreamer-epoch203-continuation-resource-policy-v1","epoch":203,"remaining_slots":419,
            "prefix_archive_bytes":103781283604u64,"native_result_sha256":c::NATIVE_SHA,"candidate_incremental_peak_bytes":c::PEAK,
            "protected_existing_floor_bytes":c::FLOOR_LOWER_BOUND,"native_copy_restore_indexes_bytes":64u64<<30,
            "suffix_archive_and_growth_bytes":16u64<<30,"assembled_archive_bytes":112u64<<30,
            "independent_verification_scratch_bytes":16u64<<30,"incremental_margin_bytes":48u64<<30,
            "minimum_available_memory_kib":MEMORY_KIB,"older225_remaining_bytes":640u64<<30,
            "experimental_guarded_envelope":true,"full_cold_peak_qualified":false,"replay_launch_authorized":false,
            "publication_authorized":false,"r2_mutations":false}),
            json!({"schema":"jetstreamer-private-epoch203-native-restore-probe-v1","passed":true,"replay_entries_sent":0,
            "native_result":{"comparison_passed":true,"shutdown_passed":true},"worker_sha256":c::WORKER_SHA,"snapshot_sha256":c::SNAPSHOT_SHA}),
            json!({"schema":"jetstreamer-epoch203-native-admission-receipt-v1","admitted":true,"protected_existing_floor_bytes":c::FLOOR_LOWER_BOUND,
            "disk":{"older225_remaining_bytes":640u64<<30,"failed223_remaining_bytes":0,
                "failed223_owner_still_failed_pid0_restart0_and_guard_stopped":true}}),
            json!({"schema":"jetstreamer-private-epoch205-bounded-resource-v1","unit":UNIT205,
            "invocation_id":"e03b74cf861c4d9ba2fc09c34c479537","success":true,"target_reached":true,
            "observed_slot":88584000,"target_slot":88584000,"child_return_code":1,"external_signal":0,"error":null,
            "authority":{"full_cold_epoch_peak_qualified":false,"publication_authorized":false}}),
        )
    }
    #[test]
    fn native_only_budget_and_invented_terminal205_cannot_authorize_full_path() {
        let (p, n, prior, t) = policy_fixture();
        policy(&p, &n, &prior, &t).unwrap();
        for (k, bad) in [
            ("candidate_incremental_peak_bytes", json!(192u64 << 30)),
            ("assembled_archive_bytes", json!(0)),
            ("independent_verification_scratch_bytes", json!(0)),
            ("older225_remaining_bytes", json!(0)),
            ("full_cold_peak_qualified", json!(true)),
            ("publication_authorized", json!(true)),
        ] {
            let mut changed = p.clone();
            changed[k] = bad;
            assert!(policy(&changed, &n, &prior, &t).is_err(), "{k}");
        }
        for (k, bad) in [
            ("success", json!(false)),
            ("target_reached", json!(false)),
            ("observed_slot", json!(88583999)),
            ("external_signal", json!(15)),
            ("invocation_id", json!("f".repeat(32))),
        ] {
            let mut changed = t.clone();
            changed[k] = bad;
            assert!(policy(&p, &n, &prior, &changed).is_err(), "{k}");
        }
        let mut changed = prior;
        changed["disk"]["failed223_remaining_bytes"] = json!(1536u64 << 30);
        assert!(policy(&p, &n, &changed, &t).is_err());
    }
    fn guard_fixture() -> Value {
        json!({"schema":"jetstreamer-horizon-standalone-guard-sample-v1",
            "guard_sha256":"cc3536dfcc268c913feccf1603a25e3cdbdf2807289c9061e04884027d1b1560",
            "producer_invocation_id":IID225,"producer":{"invocation_id":IID225,"active":"active","sub":"running",
                "restarts":0,"load_state":"loaded","result":"success","restart_policy":"no","kill_mode":"control-group",
                "cgroup":format!("/system.slice/{LIVE225}")},"trip_reason":null,"worker_observation_error":null,
            "recorded_unix_seconds":1000,"minimum_free_bytes":1347800810387u64,"available_bytes":c::FLOOR_LOWER_BOUND,
            "workers":[[123,420000]]})
    }
    #[test]
    fn older_guard_must_be_fresh_exact_and_untripped_with_one_worker() {
        let g = guard_fixture();
        guard(&g, 2800).unwrap();
        assert!(guard(&g, 2801).is_err());
        assert!(guard(&g, 999).is_err());
        for (path, bad) in [
            ("/producer_invocation_id", json!("f".repeat(32))),
            ("/producer/restarts", json!(1)),
            ("/minimum_free_bytes", json!(1)),
            ("/trip_reason", json!("filesystem-floor")),
            ("/workers", json!([])),
        ] {
            let mut changed = g.clone();
            *changed.pointer_mut(path).unwrap() = bad;
            assert!(guard(&changed, 1000).is_err(), "{path}");
        }
        let mut changed = g;
        changed
            .as_object_mut()
            .unwrap()
            .remove("worker_observation_error");
        assert!(guard(&changed, 1000).is_err());
    }
    #[test]
    #[ignore = "root read-only actual sealed 203 primary inputs/accepted296; no resource or remote observations, writes or launch"]
    fn actual_sealed203_inputs_and_accepted296_match() {
        let read =
            |path: &str| -> Value { serde_json::from_slice(&fs::read(path).unwrap()).unwrap() };
        let native = read("/var/lib/jetstreamer/horizon-native203-terminal-0219-v1/native.json");
        let prior = read("/var/lib/jetstreamer/horizon-native203-launch-0158-v1/admission.json");
        let terminal = read("/var/lib/jetstreamer/horizon-205-terminal-0333-v1/resource.json");
        let (p, _, _, _) = policy_fixture();
        policy(&p, &native, &prior, &terminal).unwrap();
        let f = read(
            "/var/lib/jetstreamer/horizon-campaign-fleet/20261023T034552Z-205-terminal/fleet-ledger.json",
        );
        assert_eq!(
            floor(
                &read("/var/lib/jetstreamer/horizon-century-floor-032716-thirteen-v1/floor.json"),
                &f
            )
            .unwrap(),
            248289182611
        );
        let o = read(
            "/home/ubuntu/workspace/jetstreamer/.codex/tmp-readiness/horizon-live-resource-sample-20261023T034552Z-diagnostics-v296.json",
        );
        let p = read("/var/lib/jetstreamer/horizon-cycle034552-205-terminal-v2/fleet-plan.json");
        let mut s = spec();
        s.observer.path = "/home/ubuntu/workspace/jetstreamer/.codex/tmp-readiness/horizon-live-resource-sample-20261023T034552Z-diagnostics-v296.json".into();
        s.observer.sha256 =
            "eae352f56b8d4e1365af6f7cafc9ff6b67c3cbd5e58197963dc196daebaa7b0b".into();
        s.fleet_plan.path =
            "/var/lib/jetstreamer/horizon-cycle034552-205-terminal-v2/fleet-plan.json".into();
        s.fleet_plan.sha256 =
            "2cf80265e0bc9fae26cce8df47b469d6bf1cb6d246965a7d05b57ffcb96c6da3".into();
        sample(&s, &o, &f, &p, utc_seconds("2026-10-23T03:45:52Z").unwrap()).unwrap();
    }
}
