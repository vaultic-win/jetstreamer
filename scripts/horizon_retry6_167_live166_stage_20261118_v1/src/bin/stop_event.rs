//! Preserve the exact 01:11 guard stops and reconcile the operational fleet.
//! No restart, reservation release, cleanup or remote mutation authority.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::Path,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};
const ROOT: &str = "/var/lib/jetstreamer/root0111-witness-stop-event-20261119-v1";
const PRIOR: &str = "/var/lib/jetstreamer/root0049-live166167-observation-20261119-v2/ROOT_COMPLETE_OPERATIONAL_FLEET.json";
const STATUS_ROOT: &str = "/home/sol/.jetstreamer-private/r2-status-receipts";
fn sha(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
fn bind(p: &str) -> Result<Value> {
    Ok(json!({"path":p,"sha256":sha(&fs::read(p)?)}))
}
fn read(p: &str) -> Result<Value> {
    Ok(serde_json::from_slice(&fs::read(p)?)?)
}
fn save(name: &str, v: &Value) -> Result<Value> {
    ensure!(!name.contains('/'), "leaf only");
    let path = format!("{ROOT}/{name}");
    let bytes = serde_json::to_vec_pretty(v)?;
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)?;
    f.write_all(&bytes)?;
    f.sync_all()?;
    File::open(ROOT)?.sync_all()?;
    bind(&path)
}
fn run(args: &[&str]) -> Result<String> {
    let r = Command::new(args[0]).args(&args[1..]).output()?;
    ensure!(
        r.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&r.stderr)
    );
    Ok(String::from_utf8(r.stdout)?)
}
fn main() -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0 && std::env::args().len() == 1,
        "root, no arguments"
    );
    let mut fleet = read(PRIOR)?;
    ensure!(
        fleet["owner"] == "/root"
            && fleet["primary_thread"] == "01a1af2a-9ce8-76a2-8939-b2112bd38f53",
        "fleet owner differs"
    );
    fs::DirBuilder::new().mode(0o700).create(ROOT)?;
    let mut events = Vec::new();
    for (epoch, attempt, iid, state) in [
        (
            166,
            "local3retry7",
            "03fa3ce80d8c4769a1e9dec548cdbeca",
            "/var/lib/jetstreamer/retry7-preparation-20261118-v1/epoch166/local3retry7/guard-state-recovery-v2/receipts",
        ),
        (
            167,
            "local3retry6",
            "fdfadeb7b76d4760a37983b402fd2771",
            "/var/lib/jetstreamer/retry3-preparation-20261113-v1/epoch167/local3retry6/guard-state/receipts",
        ),
    ] {
        let intent_path = format!("{state}/stop-intent.json");
        let completion_path = format!("{state}/stop-completion.json");
        let intent = read(&intent_path)?;
        let completion = read(&completion_path)?;
        ensure!(
            intent["reason"] == "DATA-fulfillment-observation-failed"
                && intent["producer_invocation_id"] == iid
                && completion["producer_invocation_id"] == iid
                && completion["intent"] == intent_path
                && completion["terminal"]["pid"] == 0
                && completion["terminal"]["active"] == "inactive"
                && completion["scratch_deleted"] == false,
            "exact completed guard stop required"
        );
        let unit = format!("horizon-qualify-{epoch}-replacement-{attempt}-20261110-v1.service");
        let native = run(&[
            "/usr/bin/systemctl",
            "show",
            &unit,
            "-pId,LoadState,ActiveState,SubState,MainPID,ControlPID,InvocationID,NRestarts,Job",
        ])?;
        for line in ["ActiveState=inactive", "MainPID=0", "ControlPID=0", "Job="] {
            ensure!(
                native.lines().any(|s| s == line),
                "owner not closed: {unit}, {line}"
            );
        }
        let journal = run(&[
            "/usr/bin/journalctl",
            "--no-pager",
            "--all",
            "-o",
            "json",
            &format!("_SYSTEMD_INVOCATION_ID={iid}"),
        ])?;
        let native_binding = save(
            &format!("epoch-{epoch}-native.json"),
            &json!({"unit":unit,"native":native,"journal":journal}),
        )?;
        events.push(json!({"epoch":epoch,"producer_unit":unit,"prior_invocation_id":iid,"stop_intent":bind(&intent_path)?,"stop_completion":bind(&completion_path)?,"terminal_native":native_binding,"scratch_preserved":true,"reservation_ending_bytes":0}));
    }
    let running = run(&[
        "/usr/bin/systemctl",
        "list-units",
        "--type=service",
        "--state=running",
        "--no-legend",
        "--plain",
        "--no-pager",
    ])?;
    let census = save("running-services.json", &json!({"raw":running}))?;
    let clock = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    fleet["previous_Root_operational_review"] = bind(PRIOR)?;
    fleet["historical_live_owners_before_0111"] = json!({"replays":fleet["actual_executing_replays"],"bootstraps":fleet["actual_active_bootstraps"]});
    fleet["actual_executing_replays"] = json!([]);
    fleet["actual_active_bootstraps"] = json!([]);
    for key in [
        "active_producer_count",
        "live_replay_count",
        "useful_replay_count",
        "bootstrap_count",
        "guarded_bootstrap_owner_count",
    ] {
        fleet[key] = json!(0);
    }
    fleet["event_recorded_unix_seconds"] = json!(clock);
    fleet["new_resource_observations"] = json!(false);
    fleet["recorded_unix_seconds"] = json!(clock);
    fleet["failure_event"] = json!({"guard_stops":events,"running_service_census":census,
        "cause":"Root created epoch170 replacement-local3retry6 at 01:11:02; the parent directory change times were included in both native DATA witnesses. Both guards correctly stopped their bound producer at 01:11:03.",
        "preserve_original_observer_clock":true,"resource_promises_ended":false});
    for row in fleet["epochs"]
        .as_array_mut()
        .context("complete epoch ledger")?
    {
        let epoch = row["epoch"].as_u64().context("epoch")?;
        if [166, 167, 170].contains(&epoch) {
            let path =
                format!("{STATUS_ROOT}/event-guard-witness-{epoch}-20261119-v1/RECEIPT.json");
            let receipt = read(&path)?;
            ensure!(
                receipt["authenticated_readback"] == true
                    && receipt["epoch"] == epoch
                    && receipt["producer_invocation_id"].is_null(),
                "fresh repair status missing"
            );
            row["current_status"] = receipt["after_status"].clone();
            row["status"] = receipt["after_status"].clone();
            row["current_authenticated_status_receipt"] = bind(&path)?;
            row["status_publication"] = bind(&path)?;
            row["historical_replay_before_0111"] = row["current_replay"].clone();
            row["current_replay"] = Value::Null;
            row["no_live_producer_claimed"] = json!(true);
            row["current_repair_owner"] = json!("/root");
            row["state"] = json!(if epoch == 170 {
                "blocked-qualification"
            } else {
                "failed-needs-repair"
            });
            row["next_action"] = json!(
                "Preserve terminal evidence; prepare disjoint recovery roots before native witness capture; qualify recovery against complete retained memory/DATA/audit obligations; prove genuine new guards before replay."
            );
        }
    }
    fleet["next_lane_recovery"] = json!({"epoch":166,"attempt":"local3retry8","source_owner":"/root/epoch170_next_lane","last_result":"Both peer producers stopped on changed owned ancestor times; two-peer170 preparation invalidated.","next_action":"Qualify exact stopped retry7 lineage and fresh retry8 preparation, source and guarded launch with all prior promises plus audit retained."});
    fleet["cycle_reconciliation_scope"] = json!(
        "Authenticated failure event using terminal receipts and current native closure. The 00:49 resource sample remains historical and is not refreshed by this event."
    );
    println!("{}", save("ROOT_COMPLETE_OPERATIONAL_FLEET.json", &fleet)?);
    Ok(())
}
