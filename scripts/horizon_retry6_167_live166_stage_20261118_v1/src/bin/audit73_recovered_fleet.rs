//! Carry a genuine audit completion into the fleet without another observation.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::Path,
};
const SEALED: &str = "/usr/local/lib/jetstreamer/horizon-audit73-recovered-evidence-20261119-v1";
const ROOT: &str = "/var/lib/jetstreamer/root0858-audit73-recovery-event-20261119-v1";
fn sha(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
fn bind(path: &str) -> Result<Value> {
    Ok(json!({"path":path,"sha256":sha(&fs::read(path)?)}))
}
fn exact(name: &str, digest: &str) -> Result<Value> {
    let bytes = fs::read(format!("{SEALED}/{name}"))?;
    ensure!(sha(&bytes) == digest, "audit evidence differs");
    Ok(serde_json::from_slice(&bytes)?)
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    ensure!(
        unsafe { libc::geteuid() } == 0 && args.len() == 3,
        "root; PREVIOUS_FLEET SHA256"
    );
    ensure!(
        Path::new(&args[1]).is_absolute(),
        "absolute prior fleet required"
    );
    let bytes = fs::read(&args[1])?;
    ensure!(sha(&bytes) == args[2], "predecessor differs");
    let mut fleet: Value = serde_json::from_slice(&bytes)?;
    ensure!(
        fleet["owner"] == "/root"
            && fleet["sampled_at_utc"] == "2026-11-19T08:58:09Z"
            && fleet["live_replay_count"] == 2
            && fleet["continuing_holding166retry6_obligation"]["resource_credit_bytes"] == 0,
        "expected accepted cycle with holding allocation required"
    );
    let result = exact(
        "epoch-73.retry-1.json",
        "fe81955c789dc385a569ea78d726366837f258fb0faded2d287627cdbf7dae9f",
    )?;
    let observed = exact(
        "observed-0852.json",
        "668b0cc237c4e734725d3cf26b17d147701bd2a6e9ad768675ffc00367d2957a",
    )?;
    let cleanup = exact(
        "cleanup.json",
        "dfc7720c62b98b8fb8a8051819da121943eceb95372549e20b17636d6ef9a2f3",
    )?;
    ensure!(
        result["epoch"] == 73
            && result["status"] == "passed"
            && result["playback"]["clean_process_exit"] == true
            && result["playback"]["first_slot"] == 31536000
            && result["playback"]["last_slot"] == 31967999
            && result["playback"]["counters"]["slots"] == 432000
            && result["remote_mutations"] == false
            && cleanup["epoch"] == 73
            && cleanup["removed_only_owned_audit_copy"] == true
            && observed["summary"]["passed"] == 75
            && observed["summary"]["failed"] == 0
            && observed["progress"]["epoch"] == 75
            && observed["progress"]["phase"] == "waiting_for_capacity",
        "genuine full remote playback and cleanup required"
    );
    fleet["previous_Root_audit_event_fleet"] = bind(&args[1])?;
    fleet["historical_audit_transfer73_repair"] = fleet["audit_transfer73_repair"].clone();
    fleet["audit_transfer73_repair"] = json!({"status":"recovered-full-plugin-pass","recovery_pass_claimed":true,
        "result":bind(&format!("{SEALED}/epoch-73.retry-1.json"))?,"cleanup":bind(&format!("{SEALED}/cleanup.json"))?,
        "observation0852":bind(&format!("{SEALED}/observed-0852.json"))?,"passed":75,"failed":0,"pending":150,
        "fresh_audit_observation_claimed":false,"next_action":"Retire qualified root compiler cache after the pending holding166 build is sealed; permit the existing audit service to advance epoch75 on its own capacity check. Preserve the exact archive plus160MiB budget and32GiB floor.",
        "next_routine_observation_not_before_utc":"2026-11-19T09:23:00Z","resource_credit_bytes":0});
    fleet["audit_milestone_gent_submission"] = json!({"message_id":"c64f4553-b967-8fec-b0c9-4b651635fb93","recipient":"coordinator","durably_submitted":true,"delivery_claimed":false});
    fs::DirBuilder::new().mode(0o700).create(ROOT)?;
    let output = format!("{ROOT}/ROOT_COMPLETE_OPERATIONAL_FLEET.json");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&output)?;
    file.write_all(&serde_json::to_vec_pretty(&fleet)?)?;
    file.sync_all()?;
    File::open(Path::new(&output).parent().context("parent")?)?.sync_all()?;
    println!("{}", bind(&output)?);
    Ok(())
}
