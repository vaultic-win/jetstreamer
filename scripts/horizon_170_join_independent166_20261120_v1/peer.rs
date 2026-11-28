//! Authenticate the admitted independent producer, its historical reservation and the closed 167 lineage.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, os::unix::fs::MetadataExt, path::Path, process::Command};
pub const UNIT: &str = "horizon-qualify-independent-cold166-20261120-v1.service";
pub const GUARD: &str = "horizon-guard-independent-cold166-20261120-v1";
pub const IID: &str = "fa16ee2f14fe44ecbc37c59e197553ac";
pub const PID: u64 = 2452922;
pub const START: u64 = 349365780;
pub const CAP: u64 = 309_237_645_312;
pub const FLOOR: u64 = 6_829_053_656_882;
pub const ACTIVE_ROOT: &str =
    "/home/sol/.jetstreamer-private/epoch166-independent-cold-20261120-v1";
const DIRECTORY: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch166-independent-cold-20261120-v1/launch-state/epoch166";
pub const STOP167: &str = "/var/lib/jetstreamer/retry3-preparation-20261113-v1/epoch167/local3retry7/guard-state/receipts/stop-completion.json";
pub const STOP167_SHA: &str = "5b51b01a57f5c717ef6397cad6bcc6b01ac72336e84d02d2b9354c99ee3fd5aa";
const INTENT167: &str = "/var/lib/jetstreamer/retry3-preparation-20261113-v1/epoch167/local3retry7/guard-state/receipts/stop-intent.json";
const INTENT167_SHA: &str = "dd5f515167b27bc1541c73d57e98c2bfab975ee0e1b6ca051be28a4b79f8f946";
const STOPPED_IID: &str = "a680103e76f546faaf469aa80c35fa3b";
pub fn pair(p: &str, h: &str) -> Value {
    json!({"path":p,"sha256":h})
}
pub fn admission() -> Value {
    pair(
        &format!("{DIRECTORY}/ACTUAL_REPLACEMENT_ADMISSION.json"),
        "06cbda4ed64f3317384e6f220304aa491d40aa1a75fbc91c1b5525e8cecdc395",
    )
}
pub fn protection() -> Value {
    pair(
        &format!("{DIRECTORY}/ACTUAL_GUARD_PROTECTION.json"),
        "4007d76ead9ed05f962867dbd84ff6f18b7f4ddcc9c97a4f448402e72c58b95b",
    )
}
pub fn bound(b: &Value) -> Result<Value> {
    let p = Path::new(b["path"].as_str().context("receipt path")?);
    let m = fs::symlink_metadata(p)?;
    ensure!(
        p.is_absolute()
            && p.canonicalize()? == p
            && m.is_file()
            && m.nlink() == 1
            && m.uid() == 0
            && m.mode() & 0o022 == 0
            && m.len() <= 32 << 20,
        "unsafe bound receipt {}",
        p.display()
    );
    let data = fs::read(p)?;
    ensure!(
        format!("{:x}", Sha256::digest(&data)) == b["sha256"].as_str().context("receipt SHA")?,
        "changed receipt {}",
        p.display()
    );
    Ok(serde_json::from_slice(&data)?)
}
pub fn owner() -> Value {
    json!({"epoch":166,"unit":UNIT,"invocation_id":IID,"main_pid":PID,"main_start_ticks":START,"admission":admission(),"guard_protection":protection()})
}
pub fn validate_ledger(v: &Value) -> Result<()> {
    let obligation = &v["independent_DATA_obligation"];
    ensure!(
        obligation["historical_complete_DATA_bytes"] == 6_794_761_027_378u64
            && obligation["retained_standard_lane_cap_bytes"] == CAP
            && obligation["independent_physical_cap_bytes"] == CAP
            && obligation["complete_replay_DATA_with_independent_cap_bytes"]
                == 7_103_998_672_690u64
            && obligation["resource_promise_ending_bytes"] == 0
            && obligation["resource_credit_bytes"] == 0,
        "independent166 or historical DATA obligation lost"
    );
    let aux = &v["auxiliary"]["retained_bookings"];
    ensure!(
        aux["maximum_concurrent_phase_memory_bytes"]
            .as_u64()
            .is_some_and(|n| n >= 6u64 << 30)
            && aux["maximum_concurrent_phase_cpu_quota_micros"]
                .as_u64()
                .is_some_and(|n| n >= 3_000_000)
            && aux["phase_admissions"].is_object()
            && v["audit_native"].is_object()
            && v["audit_additive_resources"]["all_prepared_promises_retained"] == true,
        "missing auxiliary and audit booking"
    );
    Ok(())
}
pub const NEXT167: &str = "horizon-qualify-167-replacement-local3retry8-20261110-v1.service";
const TIMER167: &str = "horizon-guard-replacement-167-local3retry8-20261110-v1.timer";
const BASE167: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch167-retry8-recovery-20261120-v1/launch-state/epoch167";
fn successor167() -> Result<Value> {
    let dir = Path::new(BASE167);
    let ap = dir.join("ACTUAL_REPLACEMENT_ADMISSION.json");
    let gp = dir.join("ACTUAL_GUARD_PROTECTION.json");
    if !ap.try_exists()? && !gp.try_exists()? {
        return Ok(Value::Null);
    }
    let binding = |p: &Path| -> Result<Value> {
        Ok(pair(
            p.to_str().context("receipt path")?,
            &format!("{:x}", Sha256::digest(fs::read(p)?)),
        ))
    };
    let ab = binding(&ap)?;
    let gb = binding(&gp)?;
    let a = bound(&ab)?;
    let g = bound(&gb)?;
    let n = bound(&a["actual_producer_native"])?;
    let plan = bound(&g["plan"])?;
    let iid = a["producer_invocation_id"].as_str().context("167 IID")?;
    let pid = a["producer_pid"].as_u64().context("167 PID")?;
    let ticks = n["MainStartTicks"].as_u64().context("167 start")?;
    ensure!(
        a["schema"] == "horizon-standard-replacement-admission-v1"
            && a["owner"] == "/root"
            && g["schema"] == "horizon-standard-live-peer-protection-v1"
            && g["owner"] == "/root"
            && g["epoch"] == 167
            && a["protected166_admission"] == admission()
            && a["protected166_guard"] == protection()
            && a["resource_credit_bytes"] == 0
            && a["memory_or_DATA_promise_ending_bytes"] == 0
            && a["candidate_root_cap_bytes"] == (512u64 << 30)
            && a["epoch"] == 167
            && a["fresh_admission_passed"] == true
            && a["all_prior_promises_retained"] == true
            && a["guard_minimum_free_bytes"] == FLOOR
            && a["producer_unit"] == NEXT167
            && iid.len() == 32
            && iid.bytes().all(|b| b.is_ascii_hexdigit())
            && pid > 1
            && ticks > 0
            && n["Id"] == NEXT167
            && n["InvocationID"] == iid
            && n["MainPID"].as_str() == Some(pid.to_string().as_str())
            && g["producer_unit"] == NEXT167
            && g["producer_invocation_id"] == iid
            && g["timer_unit"] == TIMER167
            && g["admission"] == ab
            && plan["worker_root"]
                == "/home/sol/.jetstreamer-private/epoch167-standard-lane-20261109-v1"
            && plan["maximum_root_physical_bytes"] == 512u64 << 30
            && plan["minimum_free_bytes"] == FLOOR
            && plan["maximum_worker_vmas"] == 3_500_000,
        "167 successor receipts not genuine"
    );
    let prep = bound(&a["fresh_native_Rust_preparation"])?;
    ensure!(
        prep["epoch"] == 167 && prep["attempt"] == "local3retry8",
        "foreign167 preparation"
    );
    Ok(
        json!({"epoch":167,"unit":NEXT167,"invocation_id":iid,"main_pid":pid,"main_start_ticks":ticks,"admission":ab,"guard_protection":gb}),
    )
}
pub fn owners(e: &Value) -> Vec<Value> {
    let mut v = vec![owner()];
    if !e["active167"].is_null() {
        v.push(e["active167"].clone());
    }
    v
}
pub fn evidence() -> Result<Value> {
    let a = bound(&admission())?;
    let g = bound(&protection())?;
    ensure!(
        a["epoch"] == 166
            && a["producer_unit"] == UNIT
            && a["producer_invocation_id"] == IID
            && a["producer_pid"] == PID
            && a["fresh_admission_passed"] == true
            && a["all_prior_promises_retained"] == true
            && a["independent_worker_root"] == ACTIVE_ROOT
            && a["independent_physical_cap_bytes"] == CAP
            && a["guard_minimum_free_bytes"] == FLOOR
            && a["candidate_hard_memory_bytes"] == 73_014_444_032u64
            && a["resource_credit_bytes"] == 0
            && a["memory_or_DATA_promise_ending_bytes"] == 0
            && g["admission"] == admission()
            && g["producer_invocation_id"] == IID
            && g["producer_unit"] == UNIT
            && g["guard_unit"] == format!("{GUARD}.service")
            && g["timer_unit"] == format!("{GUARD}.timer"),
        "166 producer/protection mismatch"
    );
    let native = bound(&a["actual_producer_native"])?;
    let gp = bound(&g["plan"])?;
    let prepare = bound(&a["fresh_native_Rust_preparation"])?;
    let capacity = bound(&a["post_guard_capacity"])?;
    ensure!(
        native["MainStartTicks"] == START
            && gp["unit"] == UNIT
            && gp["invocation_id"] == IID
            && gp["worker_root"] == ACTIVE_ROOT
            && gp["minimum_free_bytes"] == FLOOR
            && gp["maximum_root_physical_bytes"] == CAP
            && gp["maximum_worker_vmas"] == 3_500_000,
        "wrong active 166 limit/identity"
    );
    validate_ledger(&capacity["independent_capacity"])?;
    validate_ledger(&prepare["resource_checks"]["independent_capacity"])?;
    let stop = bound(&pair(STOP167, STOP167_SHA))?;
    let intent = bound(&pair(INTENT167, INTENT167_SHA))?;
    ensure!(
        stop["producer_invocation_id"] == STOPPED_IID
            && stop["intent"] == INTENT167
            && intent["producer_invocation_id"] == STOPPED_IID
            && stop["terminal"]["pid"] == 0
            && stop["terminal"]["active"] == "inactive"
            && stop["scratch_deleted"] == false,
        "latest167 closure mismatch"
    );
    Ok(
        json!({"active166":owner(),"active167":successor167()?,"producer_native":a["actual_producer_native"],"actual_guard_plan":g["plan"],"post_guard_capacity":a["post_guard_capacity"],"retained_admission_fleet":prepare["fleet"],"retained_capacities":capacity["independent_capacity"],"guard_timer_iid":g["timer_invocation_id"],"terminal167":pair(STOP167,STOP167_SHA),"intent167":pair(INTENT167,INTENT167_SHA)}),
    )
}
fn unit(name: &str) -> Result<BTreeMap<String, String>> {
    let r = Command::new("/usr/bin/systemctl")
        .args([
            "show",
            name,
            "-pId,LoadState,ActiveState,SubState,InvocationID,MainPID,ControlPID,NRestarts,Job",
        ])
        .output()?;
    ensure!(r.status.success(), "systemctl show {name}");
    let v = std::str::from_utf8(&r.stdout)?
        .lines()
        .filter_map(|s| s.split_once('='))
        .map(|(k, v)| (k.into(), v.into()))
        .collect::<BTreeMap<String, String>>();
    ensure!(
        v.get("Id").is_some_and(|s| s == name),
        "systemctl identity mismatch"
    );
    Ok(v)
}
pub fn live(e: &Value) -> Result<()> {
    let u = unit(UNIT)?;
    let t = unit(&format!("{GUARD}.timer"))?;
    ensure!(
        u.get("InvocationID").is_some_and(|v| v == IID)
            && u.get("MainPID").is_some_and(|v| v == &PID.to_string())
            && u.get("ActiveState").is_some_and(|v| v == "active")
            && u.get("SubState").is_some_and(|v| v == "running")
            && u.get("NRestarts").is_some_and(|v| v == "0")
            && t.get("InvocationID").map(String::as_str) == e["guard_timer_iid"].as_str()
            && t.get("ActiveState").is_some_and(|v| v == "active")
            && t.get("Job").is_some_and(String::is_empty),
        "166 invocation or guard timer changed"
    );
    let proc = fs::read_to_string(format!("/proc/{PID}/stat"))?;
    let start = proc
        .rsplit_once(')')
        .context("proc stat")?
        .1
        .split_whitespace()
        .nth(19)
        .context("start ticks")?
        .parse::<u64>()?;
    ensure!(start == START, "166 PID reused");
    for name in [
        "horizon-qualify-167-replacement-local3retry7-20261110-v1.service",
        "horizon-guard-replacement-167-local3retry7-20261110-v1.timer",
        "horizon-guard-replacement-167-local3retry7-20261110-v1.service",
        "horizon-qualify-independent-cold167-20261120-v1.service",
        "horizon-qualify-167-replacement-local3retry8-20261110-v1.service",
    ] {
        if name == NEXT167 && !e["active167"].is_null() {
            let o = &e["active167"];
            let n = unit(name)?;
            let t = unit(TIMER167)?;
            let g = bound(&o["guard_protection"])?;
            let pid = o["main_pid"].as_u64().context("167 PID")?;
            let st = fs::read_to_string(format!("/proc/{pid}/stat"))?;
            ensure!(
                n.get("InvocationID").map(String::as_str) == o["invocation_id"].as_str()
                    && n.get("MainPID") == Some(&pid.to_string())
                    && n.get("ActiveState").is_some_and(|v| v == "active")
                    && n.get("SubState").is_some_and(|v| v == "running")
                    && n.get("NRestarts").is_some_and(|v| v == "0")
                    && t.get("ActiveState").is_some_and(|v| v == "active")
                    && t.get("InvocationID").map(String::as_str)
                        == g["timer_invocation_id"].as_str()
                    && st
                        .rsplit_once(')')
                        .context("167 proc stat")?
                        .1
                        .split_whitespace()
                        .nth(19)
                        .context("167 start")?
                        .parse::<u64>()?
                        == o["main_start_ticks"].as_u64().context("167 ticks")?,
                "167 successor identity changed"
            );
            continue;
        }
        let v = unit(name)?;
        ensure!(
            v.get("ActiveState")
                .is_some_and(|s| matches!(s.as_str(), "inactive" | "failed"))
                && v.get("Job").is_some_and(String::is_empty)
                && ["MainPID", "ControlPID"].iter().all(|k| match v.get(*k) {
                    Some(x) => x == "0",
                    None => name.ends_with(".timer"),
                }),
            "167 succession changed: {name}"
        );
    }
    Ok(())
}
