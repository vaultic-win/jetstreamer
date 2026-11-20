//! Independently revalidate the harness gate's exact historical first-fire evidence.
use super::native265::{self as c, num, text};
use super::*;
const UNIT: &str = c::UNIT;
const GUARD_UNIT: &str = c::GUARD_UNIT;
const ROOT: &str = c::ROOT;
fn require(ok: bool, message: &str) -> Result<()> {
    ensure!(ok, "{message}");
    Ok(())
}
fn hex(s: &str, n: usize) -> bool {
    c::hex(s, n)
}
fn clock(p: &Value, now: u64) -> Result<()> {
    let start = num(p, "issued_monotonic_us")?;
    let end = num(p, "expires_monotonic_us")?;
    ensure!(
        start <= now && now < end && end > start && end - start <= 60_000_000,
        "invalid original startup window"
    );
    Ok(())
}
#[allow(clippy::too_many_arguments)]
pub(super) fn token_valid(
    p: &Value,
    plan_sha: &str,
    t: &Value,
    gp: &Value,
    g: &Value,
    j: &Value,
    iid: &str,
    pid: u32,
    now: u64,
    wall: u64,
) -> Result<()> {
    clock(p, now)?;
    require(
        t["schema"] == "horizon-native265-first-guard-token-v1"
            && t["startup_plan_sha256"] == plan_sha
            && t["unit"] == UNIT
            && t["invocation_id"] == iid
            && t["main_pid"] == pid
            && t["harness"] == p["harness"]
            && t["guard"] == p["guard"]
            && t["boot_id"] == p["boot_id"]
            && t["admission"] == p["admission"]
            && num(t, "recorded_monotonic_us")? >= num(p, "issued_monotonic_us")?
            && num(t, "recorded_monotonic_us")? <= now,
        "token owner or original clock differs",
    )?;
    let gid = text(t, "guard_invocation_id")?;
    require(hex(gid, 32) && gid != iid, "invalid guard invocation")?;
    require(
        gp["schema"] == "jetstreamer-horizon-standalone-guard-plan-v1"
            && gp["unit"] == UNIT
            && gp["invocation_id"] == iid
            && gp["filesystem"] == "/"
            && gp["worker_root"] == ROOT
            && gp["minimum_free_bytes"] == p["minimum_free_bytes"]
            && gp["maximum_root_physical_bytes"] == 506_191_984_640u64
            && gp["maximum_worker_vmas"] == 3500000
            && gp["boot_id"] == p["boot_id"]
            && num(gp, "main_start_ticks")? > 0
            && gp["native_main"]["main_pid"] == pid
            && gp["native_main"]["executable"] == p["harness"]["path"]
            && gp["native_main"]["sha256"] == p["harness"]["sha256"]
            && gp.get("bounded_measurement").is_none_or(Value::is_null)
            && gp.get("bounded_canary").is_none_or(Value::is_null),
        "first guard plan differs",
    )?;
    ensure!(
        g["guard_invocation_id"] == gid,
        "first guard sample invocation differs"
    );
    sample_valid(gp, g, &t["guard_plan"], iid, pid, wall, 60)?;
    ensure!(
        g["process_observation"]["token_present"] == false
            && g["workers"].as_array().is_some_and(|v| v.len() == 1),
        "265 first guard was not pretoken"
    );
    let rows = j.as_array().context("PID1 journal must be JSON array")?;
    require(!rows.is_empty() && rows.len() <= 64, "PID1 history bound")?;
    let own: Vec<_> = rows
        .iter()
        .filter(|r| {
            r["_PID"] == "1"
                && r["_UID"] == "0"
                && r["UNIT"] == GUARD_UNIT
                && r["INVOCATION_ID"] == gid
                && r["_BOOT_ID"] == text(p, "boot_id").unwrap_or("").replace('-', "")
        })
        .collect();
    let started: Vec<_> = own
        .iter()
        .filter(|r| {
            r["MESSAGE"]
                .as_str()
                .is_some_and(|s| s.starts_with(&format!("Starting {} -", GUARD_UNIT)))
        })
        .collect();
    let finished: Vec<_> = own
        .iter()
        .filter(|r| r["MESSAGE"] == format!("{}: Deactivated successfully.", GUARD_UNIT))
        .collect();
    require(
        started.len() == 1 && finished.len() == 1,
        "missing unique first-guard PID1 events",
    )?;
    let ts = |r: &Value| -> Result<u64> { Ok(text(r, "__MONOTONIC_TIMESTAMP")?.parse()?) };
    require(
        ts(started[0])? >= num(p, "issued_monotonic_us")?
            && ts(finished[0])? > ts(started[0])?
            && ts(finished[0])? <= num(t, "recorded_monotonic_us")?,
        "first guard PID1 ordering differs",
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn sample_valid(
    gp: &Value,
    g: &Value,
    gb: &Value,
    iid: &str,
    pid: u32,
    wall: u64,
    maximum_age: u64,
) -> Result<()> {
    sample_for(gp, g, gb, iid, pid, wall, maximum_age, &PROFILE)
}
pub(super) struct SampleProfile {
    pub(super) unit: &'static str,
    pub(super) guard_sha: &'static str,
    pub(super) harness: &'static str,
    pub(super) harness_sha: &'static str,
    pub(super) worker: &'static c::WorkerProfile,
    pub(super) memory: u64,
    pub(super) scratch: u64,
}
const PROFILE: SampleProfile = SampleProfile {
    unit: UNIT,
    guard_sha: c::GUARD_SHA,
    harness: c::TEST,
    harness_sha: c::TEST_SHA,
    worker: &c::WORKER_PROFILE,
    memory: c::MEMORY,
    scratch: c::SCRATCH,
};
#[allow(clippy::too_many_arguments)]
pub(super) fn sample_for(
    gp: &Value,
    g: &Value,
    gb: &Value,
    iid: &str,
    pid: u32,
    wall: u64,
    maximum_age: u64,
    profile: &SampleProfile,
) -> Result<()> {
    require(
        g["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && g["plan"] == gb["path"]
            && g["plan_sha256"] == gb["sha256"]
            && g["guard_sha256"] == profile.guard_sha
            && hex(text(g, "guard_invocation_id")?, 32)
            && g["producer_invocation_id"] == iid
            && g["producer"]["invocation_id"] == iid
            && g["producer"]["pid"] == pid
            && g["producer"]["active"] == "active"
            && g["producer"]["sub"] == "running"
            && g["producer"]["load_state"] == "loaded"
            && g["producer"]["result"] == "success"
            && g["producer"]["restart_policy"] == "no"
            && g["producer"]["kill_mode"] == "control-group"
            && g["producer"]["delegated"] == false
            && g["producer"]["restarts"] == 0
            && g["producer"]["cgroup"] == format!("/system.slice/{}", profile.unit)
            && g["producer_stop_enabled"] == true
            && g["native_main"] == gp["native_main"]
            && g["minimum_free_bytes"] == gp["minimum_free_bytes"]
            && num(g, "available_bytes")? >= num(gp, "minimum_free_bytes")?
            && g["maximum_worker_vmas"] == 3500000
            && g["maximum_root_physical_bytes"] == profile.scratch
            && g["root_physical_observation"]["maximum_physical_bytes"] == profile.scratch
            && g["root_physical_observation"]["exceeds_budget"] == false
            && num(
                &g["root_physical_observation"],
                "conservative_physical_bytes",
            )? <= profile.scratch
            && g["workers"]
                .as_array()
                .is_some_and(|v| (1..=2).contains(&v.len()))
            && g["workers"][0][0] == pid
            && g["workers"][0][1]
                .as_u64()
                .is_some_and(|n| n > 0 && n < 3500000)
            && [
                "trip_reason",
                "memory_observation_error",
                "filesystem_observation_error",
                "worker_observation_error",
                "root_physical_observation_error",
                "canary_target_error",
                "target_handoff_error",
            ]
            .iter()
            .all(|k| g.get(*k).is_some_and(Value::is_null))
            && g["bounded_measurement"] == false
            && g.get("bounded_canary").is_some_and(Value::is_null)
            && g.get("target_handoff").is_some_and(Value::is_null)
            && g["remote_mutations"] == false
            && g["r2_mutations"] == false
            && num(g, "recorded_unix_seconds")? <= wall
            && wall - num(g, "recorded_unix_seconds")? <= maximum_age,
        "first guard sample is not a genuine no-trip native sample",
    )?;
    ensure!(
        g["process_observation"]["workers"] == g["workers"],
        "265 process/VMA sample differs"
    );
    native265_process::sample_for(
        &g["process_observation"],
        gp,
        u64::from(pid),
        profile.harness,
        profile.harness_sha,
        profile.worker,
    )?;
    let memory = &g["memory_observation"];
    ensure!(
        num(memory, "current_bytes")? <= profile.memory
            && memory["swap_bytes"] == 0
            && num(memory, "tasks")? <= 512
            && memory["events"]["oom"] == 0
            && memory["events"]["oom_kill"] == 0
            && memory["events"]["oom_group_kill"] == 0,
        "265 resource sample exceeded envelope"
    );
    Ok(())
}

#[cfg(test)]
pub(super) fn fixture() -> (Value, Value, Value, Value, Value) {
    tests::fixture()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    pub(super) fn fixture() -> (Value, Value, Value, Value, Value) {
        let iid = "a".repeat(32);
        let gid = "b".repeat(32);
        let harness = json!({"path":c::TEST,"sha256":c::TEST_SHA});
        let guard = json!({"path":c::GUARD,"sha256":c::GUARD_SHA});
        let p = json!({"schema":"horizon-native265-startup-plan-v1","epoch":265,"unit":UNIT,"guard_unit":GUARD_UNIT,
            "worker_root":ROOT,"bootstrap_slot":114_479_281u64,"snapshot_sha256":c::SNAPSHOT_SHA,
            "maximum_root_physical_bytes":506_191_984_640u64,"maximum_memory_bytes":128_000_000_000u64,
            "token_root":"/var/lib/jetstreamer/horizon-native265-startup-tokens","boot_id":"boot","harness":harness,"guard":guard,
            "minimum_free_bytes":10,"issued_monotonic_us":100,"expires_monotonic_us":200,
            "admission":{"path":"/admission","sha256":"e".repeat(64)}});
        let gp = json!({"schema":"jetstreamer-horizon-standalone-guard-plan-v1","unit":UNIT,"invocation_id":iid,
            "filesystem":"/","worker_root":ROOT,"minimum_free_bytes":10,"maximum_root_physical_bytes":506_191_984_640u64,
            "maximum_worker_vmas":3500000,"native_main":{"main_pid":42,"executable":harness["path"],"sha256":harness["sha256"]}});
        let t = json!({"schema":"horizon-native265-first-guard-token-v1","startup_plan_sha256":"f".repeat(64),
            "unit":UNIT,"invocation_id":iid,"main_pid":42,"harness":harness,"guard":guard,"boot_id":"boot",
            "admission":p["admission"],"recorded_monotonic_us":180,"guard_invocation_id":gid,
            "guard_plan":{"path":"/guardplan","sha256":"9".repeat(64)}});
        let g = json!({"schema":"jetstreamer-horizon-standalone-guard-sample-v1","plan":"/guardplan","plan_sha256":"9".repeat(64),
            "guard_sha256":guard["sha256"],"guard_invocation_id":gid,"producer_invocation_id":iid,
            "producer":{"invocation_id":iid,"pid":42,"active":"active","sub":"running","restarts":0,
                "load_state":"loaded","result":"success","restart_policy":"no","kill_mode":"control-group","delegated":false,
                "cgroup":format!("/system.slice/{}",UNIT)},"producer_stop_enabled":true,"native_main":gp["native_main"],
            "minimum_free_bytes":10,"available_bytes":20,"maximum_worker_vmas":3500000,"maximum_root_physical_bytes":506_191_984_640u64,
            "root_physical_observation":{"maximum_physical_bytes":506_191_984_640u64,"exceeds_budget":false,"conservative_physical_bytes":0},
            "workers":[[42,100]],"trip_reason":null,"worker_observation_error":null,"root_physical_observation_error":null,
            "canary_target_error":null,"target_handoff_error":null,"bounded_measurement":false,
            "bounded_canary":null,"target_handoff":null,"remote_mutations":false,"r2_mutations":false,"recorded_unix_seconds":1000});
        let j = json!([
            {"_PID":"1","_UID":"0","_BOOT_ID":"boot","UNIT":GUARD_UNIT,"INVOCATION_ID":gid,"MESSAGE":format!("Starting {} - native",GUARD_UNIT),"__MONOTONIC_TIMESTAMP":"120"},
            {"_PID":"1","_UID":"0","_BOOT_ID":"boot","UNIT":GUARD_UNIT,"INVOCATION_ID":gid,"MESSAGE":format!("{}: Deactivated successfully.",GUARD_UNIT),"__MONOTONIC_TIMESTAMP":"150"}]);
        let mut gp = gp;
        gp["boot_id"] = json!("boot");
        gp["main_start_ticks"] = json!(5);
        let mut g = g;
        g["memory_observation_error"] = Value::Null;
        g["filesystem_observation_error"] = Value::Null;
        g["memory_observation"] = json!({"current_bytes":100,"swap_bytes":0,"tasks":2,"events":{"oom":0,"oom_kill":0,"oom_group_kill":0}});
        g["process_observation"] = json!({"stable_census":true,"boot_id":"boot","token_present":false,"workers":g["workers"],"processes":[{"pid":42,"parent_pid":1,"start_ticks":5,"boot_id":"boot","executable":c::TEST,"sha256":c::TEST_SHA,"uid":0,"nlink":1,"mode":0o100555}]});
        (p, t, gp, g, j)
    }
    #[test]
    fn native265_gate_rejects_token_rebinding_missing_proof_stale_or_failed_guard() {
        let (p, t, gp, g, j) = fixture();
        let check = |token: &Value, plan: &Value, sample: &Value, journal: &Value| {
            token_valid(
                &p,
                &"f".repeat(64),
                token,
                plan,
                sample,
                journal,
                &"a".repeat(32),
                42,
                190,
                1001,
            )
        };
        check(&t, &gp, &g, &j).unwrap();
        for key in t.as_object().unwrap().keys() {
            let mut bad = t.clone();
            bad[key] = Value::Null;
            assert!(check(&bad, &gp, &g, &j).is_err(), "token {}", key);
        }
        for key in g.as_object().unwrap().keys() {
            let mut bad = g.clone();
            bad.as_object_mut().unwrap().remove(key);
            assert!(check(&t, &gp, &bad, &j).is_err(), "guard {}", key);
        }
        for (pointer, value) in &[
            ("/producer/pid", json!(43)),
            ("/producer/restarts", json!(1)),
            ("/producer/active", json!("activating")),
            ("/trip_reason", json!("reserve")),
            ("/producer_stop_enabled", json!(false)),
            ("/recorded_unix_seconds", json!(900)),
            ("/recorded_unix_seconds", json!(1002)),
            ("/root_physical_observation/exceeds_budget", json!(true)),
        ] {
            let mut bad = g.clone();
            *bad.pointer_mut(pointer).unwrap() = value.clone();
            assert!(check(&t, &gp, &bad, &j).is_err(), "{}", pointer);
        }
        assert!(check(&t, &gp, &g, &json!([])).is_err());
        let mut wrong = j.clone();
        wrong[1]["_PID"] = json!("2");
        assert!(check(&t, &gp, &g, &wrong).is_err());
        wrong = j.clone();
        wrong[1]["_BOOT_ID"] = json!("previous-boot");
        assert!(check(&t, &gp, &g, &wrong).is_err());
        wrong = j.clone();
        wrong[1]["__MONOTONIC_TIMESTAMP"] = json!("119");
        assert!(check(&t, &gp, &g, &wrong).is_err());
        let mut changed = gp.clone();
        changed["native_main"]["main_pid"] = json!(43);
        assert!(check(&t, &changed, &g, &j).is_err());
    }
}
