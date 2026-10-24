//! Issue one fresh resource admission; never starts a producer or changes R2.
use super::*;
use std::ffi::CString;
const UNIT: &str = "horizon-qualify-204-shrink-root-prefix-resource-fcbf3992-v1.service";
const ROOT: &str = "/home/ubuntu/.jetstreamer-private/shrink-root-prefix-resource-204-fcbf3992-v1";
const LIVE205: &str = "horizon-qualify-205-shrink-root-prefix-resource-5c01bf93-v1.service";
const LIVE225: &str = "horizon-qualify-225-natural-root-resource-shrink-budget-2f856bd-v1.service";
const IID205: &str = "373359a11aef4993a1a949e19ff617c3";
const IID225: &str = "4cd76ae1353a4411885b997f04306402";
const SCANNER: &str = "horizon-full-verify-203-private-v4-af051b90-v1.service";
const SCANNER_IID: &str = "96ce64ec90e24b399da3d4c1138f636d";
const PEAK: u64 = 300_000_000_000 + (160 << 30);
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    observer: BoundFile,
    fleet: BoundFile,
    floor: BoundFile,
    scan_admission: BoundFile,
    capability: BoundFile,
    guard205: BoundFile,
    guard225: BoundFile,
    resource_plan: BoundFile,
    output: PathBuf,
}
fn guard(g: &Value, epoch: u64, sample: u64, now: u64) -> Result<()> {
    ensure!(
        matches!(epoch, 205 | 225),
        "204 admission has an unsupported protected guard"
    );
    let (unit, iid, sha, plan, floor) = if epoch == 205 {
        (
            LIVE205,
            IID205,
            prefix204::GUARD_SHA,
            "2b639357a4754b914ad9f4af949fb7c38085a37b9cac7aa0b2c519950ee963e7",
            1_210_361_856_915u64,
        )
    } else {
        (
            LIVE225,
            IID225,
            "cc3536dfcc268c913feccf1603a25e3cdbdf2807289c9061e04884027d1b1560",
            "831f3eae5d4326d04ae399b4046532cda5cceb32e8e3f89b87a1de0b299a3d22",
            317_008_659_347,
        )
    };
    let time = g["recorded_unix_seconds"]
        .as_u64()
        .context("204 guard time")?;
    ensure!(
        time >= sample
            && time <= now
            && now - time <= 1800
            && g["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && g["guard_sha256"] == sha
            && g["plan_sha256"] == plan
            && g["minimum_free_bytes"] == floor
            && g["producer_invocation_id"] == iid
            && g["producer"]["invocation_id"] == iid
            && g["producer"]["cgroup"] == format!("/system.slice/{unit}")
            && g["producer"]["active"] == "active"
            && g["producer"]["sub"] == "running"
            && g["producer"]["restarts"] == 0
            && g["producer"]["result"] == "success"
            && g["producer"]["load_state"] == "loaded"
            && g["producer"]["restart_policy"] == "no"
            && g["producer"]["kill_mode"] == "control-group"
            && g["producer"]["delegated"] == false
            && g["producer"]["pid"].as_u64().is_some_and(|n| n > 0)
            && if epoch == 205 {
                g["producer_stop_enabled"] == true
            } else {
                g.get("producer_stop_enabled").is_none()
            }
            && g["maximum_worker_vmas"] == 3500000
            && [
                "trip_reason",
                "worker_observation_error",
                "canary_target_error"
            ]
            .iter()
            .all(|k| g.get(*k).is_some_and(Value::is_null))
            && g["available_bytes"].as_u64().is_some_and(|n| n >= floor)
            && g["remote_mutations"] == false
            && g["r2_mutations"] == false,
        "204 protected guard differs/stale/tripped"
    );
    let workers = g["workers"].as_array().context("204 guard worker census")?;
    ensure!(workers.len() == 1, "204 guard worker count differs");
    for w in workers {
        ensure!(
            w[0].as_u64().is_some_and(|p| p > 0)
                && w[1].as_u64().is_some_and(|n| n > 0 && n < 3500000),
            "204 protected worker exceeds VMA bound"
        );
    }
    if epoch == 205 {
        ensure!(
            g["maximum_root_physical_bytes"] == 300_000_000_000u64
                && g.get("root_physical_observation_error")
                    .is_some_and(Value::is_null),
            "204 lost 203 own-root protection"
        );
    }
    Ok(())
}
fn sample(s: &Spec, o: &Value, f: &Value, now: u64, required: u64) -> Result<(u64, u64)> {
    let sampled = utc_seconds(o["recorded_at_utc"].as_str().context("204 sample time")?)?;
    ensure!(
        sampled <= now
            && now - sampled <= 1800
            && o["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && f["schema"] == SCHEMA
            && f["first_epoch"] == 201
            && f["last_epoch"] == 300
            && f["observer_receipt"].as_str() == s.observer.path.to_str()
            && f["observer_sha256"] == s.observer.sha256
            && f["sampled_at_utc"] == o["recorded_at_utc"]
            && f["active"].as_array().is_some_and(|v| v.len() == 3)
            && f["inventory"]["ready_pairs"] == 13
            && f["inventory"]["anomalies"] == 0
            && o["filesystem"]["conservative_available_bytes"]
                .as_u64()
                .is_some_and(|n| n >= required),
        "204 admission requires fresh complete fleet and disk evidence"
    );
    let rss = o["lane_rss_history"]["200"]["maximum_observed_lane_rss_bytes"]
        .as_u64()
        .context("204 requires first valid century RSS sample")?;
    let reservation = rss.checked_mul(3).context("204 RSS allowance overflow")? / 2;
    ensure!(
        rss > 0 && o["lane_rss_history"]["200"]["reservation_ceiling_bytes"] == reservation,
        "204 RSS allowance differs"
    );
    let total = o["host_memory"]["total_kib"]
        .as_u64()
        .context("204 total memory")?
        .checked_mul(1024)
        .context("204 total memory overflow")?;
    let available = o["host_memory"]["conservative_available_kib"]
        .as_u64()
        .context("204 available memory")?
        .checked_mul(1024)
        .context("204 memory overflow")?;
    ensure!(
        available >= total / 10 + rss && available >= reservation,
        "204 host already at memory target or lacks next-lane RSS allowance"
    );
    let pressure = &o["host_global_pressure"]["cross_sample"];
    let elapsed = pressure["elapsed_millis"]
        .as_u64()
        .context("204 PSI interval")?;
    ensure!(
        pressure["status"] == "observed"
            && elapsed >= 1_800_000
            && pressure["counter_delta_usec"]["memory.full_total_usec"]
                .as_u64()
                .zip(elapsed.checked_mul(100))
                .is_some_and(|(n, bound)| n <= bound),
        "204 memory pressure window unavailable or severe"
    );
    let rows = o["diagnostic_replays"]
        .as_array()
        .context("204 observed diagnostic census")?;
    let row = rows
        .iter()
        .find(|r| r["range"] == "225-226")
        .context("204 protected 225 observation missing")?;
    ensure!(
        row["status"] == "observed"
            && row["observation"]["invocation_binding_stable"] == true
            && row["observation"]["producer_before"]["invocation_id"] == IID225
            && row["observation"]["worker_before"]["vmas"]
                .as_u64()
                .is_some_and(|n| n > 0 && n < 3500000),
        "204 protected 225 sample unhealthy"
    );
    let row = rows
        .iter()
        .find(|r| r["range"] == "205-205")
        .context("204 protected 205 observation missing")?;
    ensure!(
        row["status"] == "observed"
            && row["observation"]["invocation_binding_stable"] == true
            && row["observation"]["producer_before"]["invocation_id"] == IID205
            && row["observation"]["worker_before"]["vmas"]
                .as_u64()
                .is_some_and(|n| n > 0 && n < 3500000),
        "204 protected 205 sample unhealthy"
    );
    Ok((sampled, reservation))
}
pub(super) fn check_previous_owners(f: &Value, c: &BTreeMap<String, Value>) -> Result<()> {
    // Linking the dormant unit reloads PID1 and clears ExecStart's display-only
    // times/PID. Retain raw observations; normalize only the three exact older
    // commands in this in-memory comparison, never invocation IDs or MainPID.
    let old = f["unit_census"]
        .as_object()
        .context("204 predecessor census missing")?;
    let mut view = c.clone();
    for name in [LIVE205, LIVE225, SCANNER] {
        let previous = old.get(name).context("204 predecessor owner missing")?;
        let current = view.get_mut(name).context("204 current owner missing")?;
        let expected = previous["ExecStart"]
            .as_str()
            .context("204 previous command missing")?;
        let observed = current["ExecStart"]
            .as_str()
            .context("204 current command missing")?;
        ensure!(
            pipeline_status::same_exec_start(expected, observed),
            "204 protected command changed:{name}"
        );
        current["ExecStart"] = previous["ExecStart"].clone();
    }
    snapshot144::check_owners(f, &view)
}
fn owners(f: &Value, c: &BTreeMap<String, Value>) -> Result<()> {
    check_previous_owners(f, c)?;
    for (name, u) in c {
        if diagnostic_stage_running(u) {
            ensure!(
                (name == LIVE205 && u["InvocationID"] == IID205)
                    || (name == LIVE225 && u["InvocationID"] == IID225)
                    || (name == SCANNER && u["InvocationID"] == SCANNER_IID),
                "204 found additional live work:{name}"
            );
        }
    }
    let scan = c.get(SCANNER).context("204 protected 203 scan missing")?;
    ensure!(
        scan["ActiveState"] == "activating"
            && scan["SubState"] == "start"
            && scan["InvocationID"] == SCANNER_IID
            && scan["NRestarts"] == "0",
        "204 protected 203 scan no longer matches the admitted fleet; reconcile its terminal/handoff first"
    );
    for (name, iid) in [(LIVE205, IID205), (LIVE225, IID225)] {
        let u = c.get(name).context("204 missing protected owner")?;
        ensure!(
            u["ActiveState"] == "active"
                && u["SubState"] == "running"
                && u["InvocationID"] == iid
                && u["NRestarts"] == "0",
            "204 protected producer changed"
        );
    }
    Ok(())
}
fn protected_caps() -> Result<Value> {
    let mut result = serde_json::Map::new();
    for (unit, high, max) in [
        (LIVE225, 160u64, 192u64),
        (LIVE205, 192, 224),
        (SCANNER, 96, 128),
    ] {
        let out = ProcessCommand::new("/usr/bin/systemctl")
            .args([
                "show",
                unit,
                "--no-pager",
                "--property=MemoryHigh,MemoryMax,MemorySwapMax,ControlGroup",
            ])
            .output()?;
        ensure!(
            out.status.success() && out.stdout.len() < 16384,
            "204 protected memory limits unavailable"
        );
        let mut p = BTreeMap::new();
        for line in std::str::from_utf8(&out.stdout)?.lines() {
            let (key, value) = line
                .split_once('=')
                .context("204 protected resource property")?;
            ensure!(
                p.insert(key, value).is_none(),
                "duplicate 204 protected property"
            );
        }
        let group = format!("/system.slice/{unit}");
        ensure!(
            p.get("MemoryHigh").and_then(|s| s.parse::<u64>().ok()) == Some(high << 30)
                && p.get("MemoryMax").and_then(|s| s.parse::<u64>().ok()) == Some(max << 30)
                && p.get("MemorySwapMax") == Some(&"0")
                && p.get("ControlGroup") == Some(&group.as_str()),
            "204 protected memory configuration changed:{unit}"
        );
        let root = PathBuf::from(format!("/sys/fs/cgroup{group}"));
        for (file, expected) in [
            ("memory.high", high << 30),
            ("memory.max", max << 30),
            ("memory.swap.max", 0),
        ] {
            ensure!(
                fs::read_to_string(root.join(file))?.trim().parse::<u64>()? == expected,
                "204 protected kernel memory limit differs:{unit}/{file}"
            );
        }
        result.insert(unit.to_owned(),json!({"memory_high_bytes":high<<30,"memory_max_bytes":max<<30,"memory_swap_max_bytes":0,"cgroup":group}));
    }
    Ok(Value::Object(result))
}
pub(super) fn run() -> Result<()> {
    let args: Vec<_> = env::args().collect();
    ensure!(
        args.len() == 7
            && args[3] == "--spec-sha256"
            && args[5] == "--self-sha256"
            && unsafe { libc::geteuid() } == 0,
        "usage: admit-prefix204 SPEC --spec-sha256 SHA --self-sha256 SHA (root)"
    );
    let own = fs::symlink_metadata(fs::read_link("/proc/self/exe")?)?;
    ensure!(
        own.uid() == 0
            && own.nlink() == 1
            && own.mode() & 0o222 == 0
            && hex_lower(&Sha256::digest(fs::read("/proc/self/exe")?)) == args[6],
        "204 admission helper is unsealed"
    );
    let binding = BoundFile {
        path: args[2].clone().into(),
        sha256: args[4].clone(),
    };
    let m = fs::symlink_metadata(&binding.path)?;
    ensure!(
        m.uid() == 0 && m.nlink() == 1 && m.mode() & 0o222 == 0,
        "204 spec is unsealed"
    );
    let s: Spec = serde_json::from_value(bound_json(&binding)?)?;
    ensure!(
        s.schema == "jetstreamer-private-epoch204-capped-prefix-admission-spec-v1"
            && s.scan_admission.sha256
                == "eb3f5188415f6151fbadfff03e52d94d998e30bfe3c94a59f3c15e82f826bc09"
            && s.capability.sha256
                == "9b2c12e561660f1c7e3c0af3708fddb3240e51a83bd7ed272bc96750f9caeb85"
            && s.resource_plan.path
                == Path::new(
                    "/var/lib/jetstreamer/horizon-prefix204-resource-fcbf3992-v1/resource-plan.json"
                )
            && s.output.file_name().and_then(|n| n.to_str()) == Some("admission.json")
            && s.output.parent().and_then(Path::parent) == Some(Path::new("/var/lib/jetstreamer"))
            && s.output
                .parent()
                .and_then(Path::file_name)
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("horizon-prefix204-admission-")
                    && n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')),
        "204 exact admission scope differs"
    );
    let scan_admission = bound_json(&s.scan_admission)?;
    let cap = bound_json(&s.capability)?;
    ensure!(
        scan_admission["schema"] == "jetstreamer-private-epoch203-scan-admission-v1"
            && scan_admission["runner_sha256"]
                == "5ae7edd93d29636fd959b40698bff0897e4cb3b87245054b67636d61cc8f3be9"
            && scan_admission["unit"] == SCANNER
            && scan_admission["invocation_id"] == SCANNER_IID
            && scan_admission["scan_only_admitted"] == true
            && scan_admission["publication_authorized"] == false
            && scan_admission["r2_mutations"] == false
            && cap["all_immutable_inputs_rehashed"] == true
            && cap["worker_spawned"] == false,
        "204 prerequisite proof differs"
    );
    let o = bound_json(&s.observer)?;
    let f = bound_json(&s.fleet)?;
    let floor = continuation203_admission::floor(&bound_json(&s.floor)?, &f)?;
    let protected = floor
        .checked_add((768u64 << 30) + 300_000_000_000)
        .context("204 protected floor overflow")?;
    let required = protected
        .checked_add(PEAK)
        .context("204 required free overflow")?;
    let p = bound_json(&s.resource_plan)?;
    ensure!(
        p["schema"] == "jetstreamer-private-epoch204-shrink-root-prefix-resource-plan-v1"
            && p["unit"] == UNIT
            && p["run_root"] == ROOT
            && p["target_slot"] == 88559361u64
            && p["terminal_slot"] == 88559361u64
            && p["maximum_runtime_seconds"] == 259200
            && p["node"]["sha256"]
                == "025757b9b337abf05435c427f143f590d9bfa542b5e4493aae783c158b4f2d3d"
            && p["minimum_free_bytes"] == required,
        "204 resource plan differs"
    );
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let (sampled, reservation) = sample(&s, &o, &f, now, required)?;
    let g205 = bound_json(&s.guard205)?;
    let g225 = bound_json(&s.guard225)?;
    guard(&g205, 205, sampled, now)?;
    guard(&g225, 225, sampled, now)?;
    if s.output.try_exists()? {
        let old = bound_json(&serde_json::from_value(private157::file_binding(
            &s.output,
        )?)?)?;
        ensure!(
            old["spec_sha256"] == binding.sha256
                && old["self_sha256"] == args[6]
                && old["admitted"] == true,
            "204 conflicting prior admission"
        );
        println!(
            "Exact 204 admission already exists; caller must still enforce its original freshness"
        );
        return Ok(());
    }
    validate_output_destination(&s.output)?;
    let names = f["unit_census"]
        .as_object()
        .context("204 complete fleet census")?
        .keys()
        .cloned()
        .collect();
    let before = census(&names, 201, 300)?;
    owners(&f, &before)?;
    let limits = protected_caps()?;
    let path = CString::new("/")?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    ensure!(
        unsafe { libc::statvfs(path.as_ptr(), stat.as_mut_ptr()) } == 0,
        "204 statvfs failed"
    );
    let stat = unsafe { stat.assume_init() };
    let free = stat
        .f_bavail
        .checked_mul(stat.f_frsize)
        .context("204 free overflow")?;
    let memory = fs::read_to_string("/proc/meminfo")?
        .lines()
        .find_map(|l| {
            l.strip_prefix("MemAvailable:")
                .and_then(|v| v.split_whitespace().next())
                .and_then(|v| v.parse::<u64>().ok())
        })
        .context("204 actual memory")?
        .checked_mul(1024)
        .context("204 actual memory overflow")?;
    let maps = fs::read_to_string("/proc/sys/vm/max_map_count")?
        .trim()
        .parse::<u64>()?;
    let memory_target_headroom = o["host_memory"]["total_kib"]
        .as_u64()
        .context("204 memory total")?
        .checked_mul(1024)
        .context("204 total overflow")?
        / 10;
    let rss = o["lane_rss_history"]["200"]["maximum_observed_lane_rss_bytes"]
        .as_u64()
        .context("204 RSS missing")?;
    ensure!(
        free >= required
            && memory >= reservation
            && memory
                >= memory_target_headroom
                    .checked_add(rss)
                    .context("204 memory headroom overflow")?
            && maps >= 4194304,
        "204 actual disk/memory/VMA envelope unavailable"
    );
    let after = census(&names, 201, 300)?;
    owners(&f, &after)?;
    ensure!(
        protected_caps()? == limits,
        "204 protected memory limits changed during admission"
    );
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    sample(&s, &o, &f, now, required)?;
    guard(&g205, 205, sampled, now)?;
    guard(&g225, 225, sampled, now)?;
    private157::immutable_receipt(
        &s.output,
        &json!({"schema":"jetstreamer-private-epoch204-capped-prefix-admission-v1",
        "admitted":true,"unit":UNIT,"private_run_root":ROOT,"plan_sha256":s.resource_plan.sha256,
        "capability_sha256":s.capability.sha256,"candidate_incremental_peak_bytes":PEAK,"maximum_scratch_bytes":300_000_000_000u64,
        "protected_existing_floor_bytes":protected,"required_initial_free_bytes":required,"memory_target_percent":90,
        "lane_memory_reservation_bytes":reservation,"available_memory_bytes":memory,"available_disk_bytes":free,"vm_max_map_count":maps,
        "observer":private157::binding(&s.observer),"fleet":private157::binding(&s.fleet),"floor":private157::binding(&s.floor),
        "scan_admission":private157::binding(&s.scan_admission),"guard205":private157::binding(&s.guard205),"guard225":private157::binding(&s.guard225),
        "unit_census_before":before,"unit_census_after":after,"protected_memory_limits":limits,"fresh_complete_census_passed":true,"older_producers_and_guards_preserved":true,
        "spec_sha256":binding.sha256,"self_sha256":args[6],"recorded_unix_seconds":now,"maximum_launch_delay_seconds":900,
        "ordinary_replay_authorized":false,"full_epoch_qualified":false,"publication_authorized":false,"r2_mutations":false,
        "new_routine_resource_samples":0,"producer_started":false,"producer_signaled":false}),
    )?;
    println!(
        "Private capped204 resource admission issued; launch and first guard proof remain separate"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Spec, Value, Value, u64, u64) {
        let b = || BoundFile {
            path: "/observer.json".into(),
            sha256: "a".repeat(64),
        };
        let s = Spec {
            schema: "test".into(),
            observer: b(),
            fleet: b(),
            floor: b(),
            scan_admission: b(),
            capability: b(),
            guard205: b(),
            guard225: b(),
            resource_plan: b(),
            output: "/out/admission.json".into(),
        };
        let stamp = "2026-10-23T08:16:12Z";
        let now = utc_seconds(stamp).unwrap();
        let required = 1_682_160_068_755u64;
        let o = json!({"schema":"jetstreamer-horizon-live-resource-sample-v2","recorded_at_utc":stamp,
            "filesystem":{"conservative_available_bytes":required+1},
            "host_memory":{"total_kib":1_200_000_000u64,"conservative_available_kib":1_000_000_000u64},
            "lane_rss_history":{"200":{"maximum_observed_lane_rss_bytes":150_000_000_000u64,"reservation_ceiling_bytes":225_000_000_000u64}},
            "host_global_pressure":{"cross_sample":{"status":"observed","elapsed_millis":1800000,"counter_delta_usec":{"memory.full_total_usec":0}}},
            "diagnostic_replays":[{"range":"225-226","status":"observed","observation":{"invocation_binding_stable":true,
                "producer_before":{"invocation_id":IID225},"worker_before":{"vmas":400000}}},
                {"range":"205-205","status":"observed","observation":{"invocation_binding_stable":true,
                "producer_before":{"invocation_id":IID205},"worker_before":{"vmas":400000}}}]});
        let f = json!({"schema":SCHEMA,"first_epoch":201,"last_epoch":300,"observer_receipt":"/observer.json",
            "observer_sha256":"a".repeat(64),"sampled_at_utc":stamp,"active":[{},{},{}],"inventory":{"ready_pairs":13,"anomalies":0}});
        (s, o, f, now, required)
    }
    #[test]
    fn admission_needs_fresh_rss_and_complete_current_resource_evidence() {
        let (s, o, f, now, required) = fixture();
        assert_eq!(
            sample(&s, &o, &f, now, required).unwrap().1,
            225_000_000_000
        );
        for (pointer, value) in [
            ("/lane_rss_history", Value::Null),
            (
                "/lane_rss_history/200/reservation_ceiling_bytes",
                json!(300_000_000_000u64),
            ),
            (
                "/filesystem/conservative_available_bytes",
                json!(required - 1),
            ),
            ("/host_memory/conservative_available_kib", json!(1)),
            (
                "/diagnostic_replays/0/observation/producer_before/invocation_id",
                json!(IID205),
            ),
            (
                "/host_global_pressure/cross_sample/counter_delta_usec/memory.full_total_usec",
                json!(180_000_001u64),
            ),
        ] {
            let mut bad = o.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(sample(&s, &bad, &f, now, required).is_err(), "{pointer}");
        }
        assert!(sample(&s, &o, &f, now + 1801, required).is_err());
        assert!(sample(&s, &o, &f, now - 1, required).is_err());
        let mut bad = f.clone();
        bad["active"] = json!([{}, {}]);
        assert!(sample(&s, &o, &bad, now, required).is_err());
    }
    #[test]
    fn old_guard_proofs_cannot_borrow_epochs_or_hide_missing_trip_evidence() {
        let g = json!({"schema":"jetstreamer-horizon-standalone-guard-sample-v1","recorded_unix_seconds":1000,
            "guard_sha256":"cc3536dfcc268c913feccf1603a25e3cdbdf2807289c9061e04884027d1b1560",
            "plan_sha256":"831f3eae5d4326d04ae399b4046532cda5cceb32e8e3f89b87a1de0b299a3d22",
            "minimum_free_bytes":317008659347u64,"available_bytes":3_000_000_000_000u64,
            "producer_invocation_id":IID225,"producer":{"invocation_id":IID225,"cgroup":format!("/system.slice/{LIVE225}"),
                "active":"active","sub":"running","restarts":0,"result":"success","load_state":"loaded",
                "restart_policy":"no","kill_mode":"control-group","delegated":false,"pid":123},
            "maximum_worker_vmas":3500000,"trip_reason":null,"worker_observation_error":null,"canary_target_error":null,
            "workers":[[123,400000]],"remote_mutations":false,"r2_mutations":false});
        guard(&g, 225, 999, 1001).unwrap();
        let mut wrong_protocol = g.clone();
        wrong_protocol["producer_stop_enabled"] = json!(false);
        assert!(guard(&wrong_protocol, 225, 999, 1001).is_err());
        assert!(guard(&g, 203, 999, 1001).is_err());
        let mut bad = g.clone();
        bad.as_object_mut().unwrap().remove("trip_reason");
        assert!(guard(&bad, 225, 999, 1001).is_err());
        let mut bad = g.clone();
        bad["workers"] = json!([]);
        assert!(guard(&bad, 225, 999, 1001).is_err());
        assert!(guard(&g, 225, 1001, 1002).is_err());
        assert!(guard(&g, 225, 999, 2801).is_err());
    }
    #[test]
    fn admission_preserves_both_replays_and_the_real_scan_without_admitting_other_work() {
        let mut current = BTreeMap::new();
        for (unit, iid) in [(LIVE205, IID205), (LIVE225, IID225), (SCANNER, SCANNER_IID)] {
            current.insert(unit.to_owned(),json!({"Id":unit,"InvocationID":iid,"MainPID":"123",
                "ActiveState":if unit==SCANNER {"activating"}else{"active"},
                "SubState":if unit==SCANNER {"start"}else{"running"},"NRestarts":"0","ExecStart":"exact"}));
        }
        let fleet = json!({"unit_census":current,"active":current.values().map(|u|json!({"unit":u})).collect::<Vec<_>>()});
        owners(&fleet, &current).unwrap();
        let mut displayed = current.clone();
        let original = "{ path=/sealed/scan ; argv[]=/sealed/scan plan ; ignore_errors=no ; start_time=[Fri 2026-10-23 09:29:00 UTC] ; stop_time=[n/a] ; pid=123 ; code=(null) ; status=0/0 }";
        let cleared = "{ path=/sealed/scan ; argv[]=/sealed/scan plan ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }";
        let mut expected = fleet.clone();
        expected["unit_census"][SCANNER]["ExecStart"] = json!(original);
        for row in expected["active"].as_array_mut().unwrap() {
            if row["unit"]["Id"] == SCANNER {
                row["unit"]["ExecStart"] = json!(original);
            }
        }
        displayed.get_mut(SCANNER).unwrap()["ExecStart"] = json!(cleared);
        owners(&expected, &displayed).unwrap();
        displayed.get_mut(SCANNER).unwrap()["ExecStart"] =
            json!(cleared.replace("/sealed/scan plan", "/sealed/scan other"));
        assert!(owners(&expected, &displayed).is_err());
        let mut changed = current.clone();
        changed.get_mut(SCANNER).unwrap()["InvocationID"] = json!(IID205);
        assert!(owners(&fleet, &changed).is_err());
        let mut changed = current.clone();
        changed.get_mut(SCANNER).unwrap()["ActiveState"] = json!("inactive");
        assert!(owners(&fleet, &changed).is_err());
        let mut changed = current;
        changed.insert(
            "horizon-qualify-207-unaccounted.service".into(),
            json!({"ActiveState":"active","SubState":"running"}),
        );
        assert!(owners(&fleet, &changed).is_err());
    }
}
