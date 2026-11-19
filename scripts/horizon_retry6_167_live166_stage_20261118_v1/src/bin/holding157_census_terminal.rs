//! Record the real census completion; release only its temporary memory booking.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};
const UNIT: &str = "horizon-holding157-laned-consumer-census-20261119-v1.service";
const IID: &str = "9aa30a064e7d465b976489299989b66a";
const FLEET: &str = "/var/lib/jetstreamer/root1801-live166retry8-167retry7-observation-20261119-v3/ROOT_COMPLETE_OPERATIONAL_FLEET.json";
const FLEET_SHA: &str = "7e4d784c28e77eb6a9dc50b7fa35dad54a460e6964de704ddbaac71aab5bf779";
const CENSUS: &str = "/home/sol/.jetstreamer-private/r2-holding-state-dev-samjohnson-v1/receipts/retire157-laned-consumer-census-1795111717876879411.json";
const CENSUS_SHA: &str = "bc8f6e5cbbfb704a335ede104d6e4b4cf7760a40cec45c20d3433c82f42b3ece";
const ROOT: &str = "/var/lib/jetstreamer/root1818-holding157-census-terminal-20261119-v1";
fn sha(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
fn read(path: &str, expected: &str) -> Result<Value> {
    let bytes = fs::read(path)?;
    ensure!(sha(&bytes) == expected, "changed evidence: {path}");
    Ok(serde_json::from_slice(&bytes)?)
}
fn native() -> Result<Value> {
    let out = Command::new("/usr/bin/systemctl").args(["show", UNIT, "-pId,InvocationID,MainPID,ControlPID,ControlGroup,Job,ActiveState,SubState,Result,ExecMainStatus,ExecMainExitTimestamp,ExecStart,Restart,TriggeredBy,Triggers,NRestarts"]).output()?;
    ensure!(
        out.status.success() && out.stderr.is_empty(),
        "native capture failed"
    );
    let mut row = serde_json::Map::new();
    for line in std::str::from_utf8(&out.stdout)?.lines() {
        let (k, v) = line.split_once('=').context("native field")?;
        ensure!(row.insert(k.into(), json!(v)).is_none(), "duplicate field");
    }
    let row = Value::Object(row);
    for (k, v) in [
        ("Id", UNIT),
        ("InvocationID", IID),
        ("MainPID", "0"),
        ("ControlPID", "0"),
        ("ControlGroup", ""),
        ("Job", ""),
        ("ActiveState", "active"),
        ("SubState", "exited"),
        ("Result", "success"),
        ("ExecMainStatus", "0"),
        ("Restart", "no"),
        ("TriggeredBy", ""),
        ("Triggers", ""),
        ("NRestarts", "0"),
    ] {
        ensure!(row[k] == v, "terminal identity mismatch: {k}");
    }
    ensure!(
        row["ExecStart"]
            .as_str()
            .context("command")?
            .contains("holding-census157-laned-consumers"),
        "wrong operation"
    );
    Ok(row)
}
fn write(name: &str, value: &Value) -> Result<Value> {
    let path = format!("{ROOT}/{name}");
    let bytes = serde_json::to_vec_pretty(value)?;
    let mut f = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o400)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)?;
    f.write_all(&bytes)?;
    f.sync_all()?;
    File::open(ROOT)?.sync_all()?;
    Ok(json!({"path":path,"sha256":sha(&bytes)}))
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    ensure!(
        unsafe { libc::geteuid() } == 0 && args.len() == 3 && args[1] == "--self-sha256",
        "root; --self-sha256 HASH"
    );
    ensure!(
        sha(&fs::read("/proc/self/exe")?) == args[2],
        "self hash changed"
    );
    let mut fleet = read(FLEET, FLEET_SHA)?;
    let census = read(CENSUS, CENSUS_SHA)?;
    ensure!(
        fleet["owner"] == "/root"
            && fleet["primary_thread"] == "01a1af2a-9ce8-76a2-8939-b2112bd38f53"
            && fleet["complete_projected_memory_bytes"] == 795491446784u64
            && fleet["complete_DATA_bytes"] == 6794761027378u64
            && fleet["current_holding157_consumer_census"]["native"]["InvocationID"] == IID,
        "predecessor mismatch"
    );
    ensure!(
        census["schema"] == "horizon-closed157-laned-transitive-consumer-census-v1"
            && census["nodes"].as_array().context("nodes")?.len() == 643
            && census["censused_entries"] == 146479
            && census["censused_bytes"] == 15441326051u64
            && census["data_removed"] == false
            && census["local_retirement_authorized"] == false,
        "census mismatch"
    );
    let before = native()?;
    let event = json!({"schema":"horizon-holding157-census-terminal-event-v1","owner":"/root","recorded_unix_seconds":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),"native":before,"census":{"path":CENSUS,"sha256":CENSUS_SHA},"released_temporary_memory_bytes":34359738368u64,"DATA_credit_bytes":0,"resource_credit_bytes":0,"data_removed":false,"local_retirement_authorized":false,"semantic_consumer_closure_qualified":false,"replay_launch_authorized":false,"remote_mutations":false});
    ensure!(native()? == before, "terminal identity changed");
    fs::DirBuilder::new().mode(0o700).create(ROOT)?;
    let binding = write("EVENT.json", &event)?;
    fleet["previous_Root_event_fleet"] = json!({"path":FLEET,"sha256":FLEET_SHA});
    fleet["current_holding157_consumer_census"]["native"] = before;
    fleet["current_holding157_consumer_census"]["phase"] =
        json!("census-completed-semantic-review-pending");
    fleet["current_holding157_consumer_census"]["completion_event"] = binding;
    fleet["current_holding157_consumer_census"]["temporary_memory_released_bytes"] =
        json!(34359738368u64);
    fleet["complete_projected_memory_bytes"] = json!(761131708416u64);
    fleet["nonreplay_event_supplements_previous_complete_census"] = json!(true);
    fleet["fresh_campaign_unit_census_claimed"] = json!(false);
    fleet["new_resource_observations"] = json!(false);
    fleet["next_lane_recovery"]["next_action"] = json!(
        "Complete643-node semantic closure and terminal-owner normalization; qualify exact157 retirement, then fresh170 admission. No DATA credit before actual retirement."
    );
    println!("{}", write("ROOT_COMPLETE_OPERATIONAL_FLEET.json", &fleet)?);
    Ok(())
}
