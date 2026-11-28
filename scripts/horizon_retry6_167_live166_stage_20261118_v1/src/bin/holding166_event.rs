//! Add the exact new holding actor to the accepted fleet without another replay poll.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::Path,
    process::Command,
};
const ROOT: &str = "/var/lib/jetstreamer/root0832-holding166-event-20261119-v1";
const PRIOR: &str = "/var/lib/jetstreamer/root0828-live166retry8-167retry7-observation-20261119-v3/ROOT_COMPLETE_OPERATIONAL_FLEET.json";
const PRIOR_SHA: &str = "d99136b585e6764577efcabc20a71939c34ccf1082d0a53997b0ad8ec93b86ef";
const UNIT: &str = "horizon-closed166-retry6-park-20261119-v1.service";
const IID: &str = "afc04ba6096f4826836919c2020dcdc6";
const IMAGE: &str =
    "/usr/local/lib/jetstreamer/horizon-holding-candidate-20261023-v1/jetstreamer-r2";
const IMAGE_SHA: &str = "909248d8e4c1db4c3cd89e1a4f15205b4a59d442494f35b7635038152025bb7e";
fn sha(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
fn bind(p: &str) -> Result<Value> {
    Ok(json!({"path":p,"sha256":sha(&fs::read(p)?)}))
}
fn save(name: &str, v: &Value) -> Result<Value> {
    let path = format!("{ROOT}/{name}");
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)?;
    f.write_all(&serde_json::to_vec_pretty(v)?)?;
    f.sync_all()?;
    File::open(ROOT)?.sync_all()?;
    bind(&path)
}
fn native() -> Result<Value> {
    let o=Command::new("systemctl").args(["show",UNIT,"-pId,ActiveState,SubState,InvocationID,MainPID,ControlPID,NRestarts,Result,ExecMainStatus,Job,CPUQuotaPerSecUSec,MemoryMax,MemorySwapMax"]).output()?;
    ensure!(o.status.success(), "native query failed");
    let mut map = serde_json::Map::new();
    for line in std::str::from_utf8(&o.stdout)?.lines() {
        let (k, v) = line.split_once('=').context("native property")?;
        ensure!(
            map.insert(k.into(), json!(v)).is_none(),
            "duplicate native property"
        );
    }
    let v = Value::Object(map);
    for (k, w) in [
        ("Id", UNIT),
        ("InvocationID", IID),
        ("MainPID", "1905099"),
        ("ControlPID", "0"),
        ("ActiveState", "active"),
        ("SubState", "running"),
        ("NRestarts", "0"),
        ("Result", "success"),
        ("Job", ""),
        ("MemoryMax", "2147483648"),
        ("MemorySwapMax", "0"),
        ("CPUQuotaPerSecUSec", "2s"),
    ] {
        ensure!(v[k] == w, "holding identity changed: {k}");
    }
    ensure!(
        fs::read_link("/proc/1905099/exe")? == Path::new(IMAGE)
            && sha(&fs::read(IMAGE)?) == IMAGE_SHA,
        "holding image changed"
    );
    Ok(v)
}
fn main() -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0 && std::env::args().len() == 1,
        "root; no arguments"
    );
    let prior = fs::read(PRIOR)?;
    ensure!(sha(&prior) == PRIOR_SHA, "prior fleet changed");
    let mut fleet: Value = serde_json::from_slice(&prior)?;
    let before = native()?;
    let plan =
        "/usr/local/lib/jetstreamer/horizon-closed166-retry6-holding-plan-20261119-v1/plan.json";
    ensure!(
        bind(plan)?["sha256"] == "a835a7adf66726ffbdc07eb13def1b917a9de799ff3dc9062ad7441cd182c640",
        "holding plan changed"
    );
    fs::DirBuilder::new().mode(0o700).create(ROOT)?;
    let event = json!({"schema":"horizon-exact-holding166-start-event-v1","owner":"/root","primary_thread":"01a1af2a-9ce8-76a2-8939-b2112bd38f53","recorded_unix_seconds":std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs(),"native":before,"image":bind(IMAGE)?,"plan":bind(plan)?,"inspection":bind("/var/lib/jetstreamer/epoch166-retry6-holding-review-20261119-v1/INSPECTION.json")?,"additional_memory_bytes":2147483648u64,"additional_cpu_quota_micros":2000000u64,"additional_DATA_staging_bytes":0,"restore_overlap_bytes":56173984550u64,"resource_credit_bytes":0,"promise_ending_bytes":0,"custody_complete":false,"local_retirement_complete":false,"next_routine_holding_observation_not_before_utc":"2026-11-19T09:01:40Z","completion_event_may_advance_qualified_retirement":true});
    ensure!(native()? == before, "holding changed during capture");
    let b = save("EVENT.json", &event)?;
    fleet["previous_Root_operational_review"] = bind(PRIOR)?;
    fleet["current_nonreplay_transition"] = b.clone();
    fleet["continuing_holding166retry6_obligation"] = event.clone();
    fleet["actual_active_holding_transfers"] = json!([b]);
    fleet["next_lane_recovery"] = json!({"epoch":170,"source_owner":"/root","last_failed_admission":fleet["next_lane_recovery"]["last_attempt"],"last_result":"qualified holding transfer of closed166retry6 partial started; zero reclaimed bytes until full readback and retirement","qualified_preparer":bind("/usr/local/lib/jetstreamer/horizon-epoch170-retry6-live166retry8-prepare-20261119-v2/artifact-proof.json")?,"qualified_launcher":bind("/usr/local/lib/jetstreamer/horizon-retry6-single170-launch-live166retry8-20261119-v4/artifact-proof.json")?,"qualified_stage":bind("/var/lib/jetstreamer/stage170retry8-deployment-20261119-v5/artifact-proof.json")?,"measurement":bind("/var/lib/jetstreamer/retry6-170-preparation-20261118-v1/epoch170/local3retry6/physical-1795076484-1901225.json")?,"next_action":"Qualify exact closed166retry6 partial retirement while holding upload/readback runs; preserve scratch, inputs and all existing promises. After authenticated custody and actual retirement, refresh complete fit and measurement; capture a new generation witness, prepare, check and launch170 through sealed successors. Revalidate and account the new holding actor before any admission; do not reuse old169 terminal evidence for it.","scratch_retirement_blocker":"exact original node build/source-image proof not located","resource_credit_bytes":0});
    fleet["fresh_campaign_unit_census_claimed"] = json!(false);
    fleet["nonreplay_event_supplements_previous_complete_census"] = json!(true);
    println!("{}", save("ROOT_COMPLETE_OPERATIONAL_FLEET.json", &fleet)?);
    Ok(())
}
