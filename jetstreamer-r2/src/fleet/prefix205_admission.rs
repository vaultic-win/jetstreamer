//! Issue one fresh resource admission; never starts a producer or changes R2.
use super::*;
use std::ffi::CString;
const UNIT: &str = "horizon-qualify-205-shrink-root-prefix-resource-5c01bf93-v1.service";
const ROOT: &str = "/home/ubuntu/.jetstreamer-private/shrink-root-prefix-resource-205-5c01bf93-v1";
const LIVE203: &str = "horizon-qualify-203-checkpoint-continuation-ed66145-v1.service";
const LIVE225: &str = "horizon-qualify-225-natural-root-resource-shrink-budget-2f856bd-v1.service";
const IID203: &str = "ddf3ed2de8b040758ee7a0d696159afd";
const IID225: &str = "4cd76ae1353a4411885b997f04306402";
const PEAK: u64 = 300_000_000_000 + (160 << 30);
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    observer: BoundFile,
    fleet: BoundFile,
    floor: BoundFile,
    handoff: BoundFile,
    capability: BoundFile,
    guard203: BoundFile,
    guard225: BoundFile,
    resource_plan: BoundFile,
    output: PathBuf,
}
fn guard(g: &Value, epoch: u64, sample: u64, now: u64) -> Result<()> {
    let (unit, iid, sha, plan, floor) = if epoch == 203 {
        (
            LIVE203,
            IID203,
            prefix205::GUARD_SHA,
            "25ee85a92d7b9da49e1342ff5f6edfea6c8b4f72a22b4c97eec1f3ca36781e14",
            1_004_203_426_707u64,
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
        .context("205 guard time")?;
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
            && if epoch == 203 {
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
        "205 protected guard differs/stale/tripped"
    );
    let workers = g["workers"].as_array().context("205 guard worker census")?;
    ensure!(
        (epoch == 203 && workers.len() <= 1) || (epoch == 225 && workers.len() == 1),
        "205 guard worker count differs"
    );
    for w in workers {
        ensure!(
            w[0].as_u64().is_some_and(|p| p > 0)
                && w[1].as_u64().is_some_and(|n| n > 0 && n < 3500000),
            "205 protected worker exceeds VMA bound"
        );
    }
    if epoch == 203 {
        ensure!(
            g["maximum_root_physical_bytes"] == 256u64 << 30
                && g.get("root_physical_observation_error")
                    .is_some_and(Value::is_null),
            "205 lost 203 own-root protection"
        );
    }
    Ok(())
}
fn sample(s: &Spec, o: &Value, f: &Value, now: u64, required: u64) -> Result<(u64, u64)> {
    let sampled = utc_seconds(o["recorded_at_utc"].as_str().context("205 sample time")?)?;
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
            && f["active"].as_array().is_some_and(|v| v.len() == 2)
            && f["inventory"]["ready_pairs"] == 13
            && f["inventory"]["anomalies"] == 0
            && o["filesystem"]["conservative_available_bytes"]
                .as_u64()
                .is_some_and(|n| n >= required),
        "205 admission requires fresh complete fleet and disk evidence"
    );
    let rss = o["lane_rss_history"]["200"]["maximum_observed_lane_rss_bytes"]
        .as_u64()
        .context("205 requires first valid century RSS sample")?;
    let reservation = rss.checked_mul(3).context("205 RSS allowance overflow")? / 2;
    ensure!(
        rss > 0 && o["lane_rss_history"]["200"]["reservation_ceiling_bytes"] == reservation,
        "205 RSS allowance differs"
    );
    let total = o["host_memory"]["total_kib"]
        .as_u64()
        .context("205 total memory")?
        .checked_mul(1024)
        .context("205 total memory overflow")?;
    let available = o["host_memory"]["conservative_available_kib"]
        .as_u64()
        .context("205 available memory")?
        .checked_mul(1024)
        .context("205 memory overflow")?;
    ensure!(
        available >= total / 10 + rss && available >= reservation,
        "205 host already at memory target or lacks next-lane RSS allowance"
    );
    let pressure = &o["host_global_pressure"]["cross_sample"];
    let elapsed = pressure["elapsed_millis"]
        .as_u64()
        .context("205 PSI interval")?;
    ensure!(
        pressure["status"] == "observed"
            && elapsed >= 1_800_000
            && pressure["counter_delta_usec"]["memory.full_total_usec"]
                .as_u64()
                .zip(elapsed.checked_mul(100))
                .is_some_and(|(n, bound)| n <= bound),
        "205 memory pressure window unavailable or severe"
    );
    let rows = o["diagnostic_replays"]
        .as_array()
        .context("205 observed diagnostic census")?;
    let row = rows
        .iter()
        .find(|r| r["range"] == "225-226")
        .context("205 protected 225 observation missing")?;
    ensure!(
        row["status"] == "observed"
            && row["observation"]["invocation_binding_stable"] == true
            && row["observation"]["producer_before"]["invocation_id"] == IID225
            && row["observation"]["worker_before"]["vmas"]
                .as_u64()
                .is_some_and(|n| n > 0 && n < 3500000),
        "205 protected 225 sample unhealthy"
    );
    Ok((sampled, reservation))
}
fn owners(f: &Value, c: &BTreeMap<String, Value>) -> Result<()> {
    snapshot144::check_owners(f, c)?;
    for (name, u) in c {
        if diagnostic_stage_running(u) {
            ensure!(
                (name == LIVE203 && u["InvocationID"] == IID203)
                    || (name == LIVE225 && u["InvocationID"] == IID225),
                "205 found additional live work:{name}"
            );
        }
    }
    for (name, iid) in [(LIVE203, IID203), (LIVE225, IID225)] {
        let u = c.get(name).context("205 missing protected owner")?;
        ensure!(
            u["ActiveState"] == "active"
                && u["SubState"] == "running"
                && u["InvocationID"] == iid
                && u["NRestarts"] == "0",
            "205 protected producer changed"
        );
    }
    Ok(())
}
pub(super) fn run() -> Result<()> {
    let args: Vec<_> = env::args().collect();
    ensure!(
        args.len() == 7
            && args[3] == "--spec-sha256"
            && args[5] == "--self-sha256"
            && unsafe { libc::geteuid() } == 0,
        "usage: admit-prefix205 SPEC --spec-sha256 SHA --self-sha256 SHA (root)"
    );
    let own = fs::symlink_metadata(fs::read_link("/proc/self/exe")?)?;
    ensure!(
        own.uid() == 0
            && own.nlink() == 1
            && own.mode() & 0o222 == 0
            && hex_lower(&Sha256::digest(fs::read("/proc/self/exe")?)) == args[6],
        "205 admission helper is unsealed"
    );
    let binding = BoundFile {
        path: args[2].clone().into(),
        sha256: args[4].clone(),
    };
    let m = fs::symlink_metadata(&binding.path)?;
    ensure!(
        m.uid() == 0 && m.nlink() == 1 && m.mode() & 0o222 == 0,
        "205 spec is unsealed"
    );
    let s: Spec = serde_json::from_value(bound_json(&binding)?)?;
    ensure!(
        s.schema == "jetstreamer-private-epoch205-capped-prefix-admission-spec-v1"
            && s.handoff.sha256
                == "c02f08b19d3f8c12f64e48d39010dddacd897672954b5431753d98bf4cbb493c"
            && s.capability.sha256
                == "9db9831e434d775ec41a4fd60ddeebcc97470743f22b51ea22e4b8ae9834c2b3"
            && s.resource_plan.path
                == Path::new(
                    "/var/lib/jetstreamer/horizon-prefix205-resource-5c01bf93-v1/resource-plan.json"
                )
            && s.output.file_name().and_then(|n| n.to_str()) == Some("admission.json")
            && s.output.parent().and_then(Path::parent) == Some(Path::new("/var/lib/jetstreamer"))
            && s.output
                .parent()
                .and_then(Path::file_name)
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("horizon-prefix205-admission-")
                    && n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')),
        "205 exact admission scope differs"
    );
    let handoff = bound_json(&s.handoff)?;
    let cap = bound_json(&s.capability)?;
    ensure!(
        handoff["exact_new_protective_fires_proven"] == true
            && cap["all_immutable_inputs_rehashed"] == true
            && cap["worker_spawned"] == false,
        "205 prerequisite proof differs"
    );
    let o = bound_json(&s.observer)?;
    let f = bound_json(&s.fleet)?;
    let floor = continuation203_admission::floor(&bound_json(&s.floor)?, &f)?;
    let protected = floor
        .checked_add(896u64 << 30)
        .context("205 protected floor overflow")?;
    let required = protected
        .checked_add(PEAK)
        .context("205 required free overflow")?;
    let p = bound_json(&s.resource_plan)?;
    ensure!(
        p["schema"] == "jetstreamer-private-epoch205-shrink-root-prefix-resource-plan-v1"
            && p["unit"] == UNIT
            && p["run_root"] == ROOT
            && p["target_slot"] == 88991050u64
            && p["terminal_slot"] == 88991050u64
            && p["maximum_runtime_seconds"] == 259200
            && p["node"]["sha256"]
                == "025757b9b337abf05435c427f143f590d9bfa542b5e4493aae783c158b4f2d3d"
            && p["minimum_free_bytes"] == required,
        "205 resource plan differs"
    );
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let (sampled, reservation) = sample(&s, &o, &f, now, required)?;
    let g203 = bound_json(&s.guard203)?;
    let g225 = bound_json(&s.guard225)?;
    guard(&g203, 203, sampled, now)?;
    guard(&g225, 225, sampled, now)?;
    if s.output.try_exists()? {
        let old = bound_json(&serde_json::from_value(private157::file_binding(
            &s.output,
        )?)?)?;
        ensure!(
            old["spec_sha256"] == binding.sha256
                && old["self_sha256"] == args[6]
                && old["admitted"] == true,
            "205 conflicting prior admission"
        );
        println!(
            "Exact 205 admission already exists; caller must still enforce its original freshness"
        );
        return Ok(());
    }
    validate_output_destination(&s.output)?;
    let names = f["unit_census"]
        .as_object()
        .context("205 complete fleet census")?
        .keys()
        .cloned()
        .collect();
    let before = census(&names, 201, 300)?;
    owners(&f, &before)?;
    let path = CString::new("/")?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    ensure!(
        unsafe { libc::statvfs(path.as_ptr(), stat.as_mut_ptr()) } == 0,
        "205 statvfs failed"
    );
    let stat = unsafe { stat.assume_init() };
    let free = stat
        .f_bavail
        .checked_mul(stat.f_frsize)
        .context("205 free overflow")?;
    let memory = fs::read_to_string("/proc/meminfo")?
        .lines()
        .find_map(|l| {
            l.strip_prefix("MemAvailable:")
                .and_then(|v| v.split_whitespace().next())
                .and_then(|v| v.parse::<u64>().ok())
        })
        .context("205 actual memory")?
        .checked_mul(1024)
        .context("205 actual memory overflow")?;
    let maps = fs::read_to_string("/proc/sys/vm/max_map_count")?
        .trim()
        .parse::<u64>()?;
    let memory_target_headroom = o["host_memory"]["total_kib"]
        .as_u64()
        .context("205 memory total")?
        .checked_mul(1024)
        .context("205 total overflow")?
        / 10;
    let rss = o["lane_rss_history"]["200"]["maximum_observed_lane_rss_bytes"]
        .as_u64()
        .context("205 RSS missing")?;
    ensure!(
        free >= required
            && memory >= reservation
            && memory
                >= memory_target_headroom
                    .checked_add(rss)
                    .context("205 memory headroom overflow")?
            && maps >= 4194304,
        "205 actual disk/memory/VMA envelope unavailable"
    );
    let after = census(&names, 201, 300)?;
    owners(&f, &after)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    sample(&s, &o, &f, now, required)?;
    guard(&g203, 203, sampled, now)?;
    guard(&g225, 225, sampled, now)?;
    private157::immutable_receipt(
        &s.output,
        &json!({"schema":"jetstreamer-private-epoch205-capped-prefix-admission-v1",
        "admitted":true,"unit":UNIT,"private_run_root":ROOT,"plan_sha256":s.resource_plan.sha256,
        "capability_sha256":s.capability.sha256,"candidate_incremental_peak_bytes":PEAK,"maximum_scratch_bytes":300_000_000_000u64,
        "protected_existing_floor_bytes":protected,"required_initial_free_bytes":required,"memory_target_percent":90,
        "lane_memory_reservation_bytes":reservation,"available_memory_bytes":memory,"available_disk_bytes":free,"vm_max_map_count":maps,
        "observer":private157::binding(&s.observer),"fleet":private157::binding(&s.fleet),"floor":private157::binding(&s.floor),
        "handoff":private157::binding(&s.handoff),"guard203":private157::binding(&s.guard203),"guard225":private157::binding(&s.guard225),
        "unit_census_before":before,"unit_census_after":after,"fresh_complete_census_passed":true,"older_producers_and_guards_preserved":true,
        "spec_sha256":binding.sha256,"self_sha256":args[6],"recorded_unix_seconds":now,"maximum_launch_delay_seconds":900,
        "ordinary_replay_authorized":false,"full_epoch_qualified":false,"publication_authorized":false,"r2_mutations":false,
        "new_routine_resource_samples":0,"producer_started":false,"producer_signaled":false}),
    )?;
    println!(
        "Private capped205 resource admission issued; launch and first guard proof remain separate"
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
            handoff: b(),
            capability: b(),
            guard203: b(),
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
                "producer_before":{"invocation_id":IID225},"worker_before":{"vmas":400000}}}]});
        let f = json!({"schema":SCHEMA,"first_epoch":201,"last_epoch":300,"observer_receipt":"/observer.json",
            "observer_sha256":"a".repeat(64),"sampled_at_utc":stamp,"active":[{},{}],"inventory":{"ready_pairs":13,"anomalies":0}});
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
                json!(IID203),
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
        bad["active"] = json!([{}, {}, {}]);
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
}
