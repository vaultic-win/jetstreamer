use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
mod common;
use common::*;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
const IID: &str = "67725d9ba7aa4de994840564f44d963c";
const ATTEMPT: &str = "attempts/epoch-84-1795142703909303859";
const OLD: &str = "70d64c543ed79d8a05f3f2a9afd920ab5612133d4c6f89bfc9bffba1dcfe2ba2";
const NEW: &str = "408703e0c58c738a55d30742e01e348e3720a1ec62357f555dbc887926de7435";
const CONFIG: &str = "5d7d09bfb1ffdb08ac5aa04b228e9cd3827a6ef3bbb700723d7b777d2261e177";
const TERMINAL79: &str = "c70b0fff4cc9b463adfaef3bde19818e6ca8f1eecd5f8d46236896e4f5d40d65";
fn old_owner(n: &BTreeMap<String, String>) -> Result<()> {
    for (k, v) in [
        ("InvocationID", IID),
        ("MainPID", "2285828"),
        ("SubState", "running"),
        ("NRestarts", "0"),
        ("Job", ""),
        ("MemoryMax", "25769803776"),
        ("MemorySwapMax", "0"),
        ("TasksMax", "512"),
        ("CPUQuotaPerSecUSec", "4s"),
    ] {
        ensure!(
            n.get(k).map(String::as_str) == Some(v),
            "audit owner or limit changed at {k}"
        );
    }
    ensure!(
        sha(Path::new("/proc/2285828/exe"))? == OLD,
        "old executable differs"
    );
    Ok(())
}
fn clean_result(out: &Value, cleanup: &Value) -> Result<()> {
    ensure!(
        out["epoch"] == 84
            && out["status"] == "passed"
            && out["remote_mutations"] == false
            && out["playback"]["clean_process_exit"] == true
            && out["attempt"] == format!("{STATE}/{ATTEMPT}")
            && cleanup["epoch"] == 84
            && cleanup["removed_only_owned_audit_copy"] == true,
        "epoch 84 playback/cleanup incomplete"
    );
    Ok(())
}
fn boundary(n: &BTreeMap<String, String>) -> Result<()> {
    let state = Path::new(STATE);
    clean_result(
        &read(&state.join("results/epoch-84.json"))?,
        &read(&state.join(ATTEMPT).join("cleanup.json"))?,
    )?;
    ensure!(
        !state.join("scratch-owner.json").try_exists()?
            && state.join("scratch").read_dir()?.next().is_none(),
        "scratch in use"
    );
    let rel = n
        .get("ControlGroup")
        .context("missing control group")?
        .strip_prefix('/')
        .context("bad cgroup")?;
    let pids = fs::read_to_string(Path::new("/sys/fs/cgroup").join(rel).join("cgroup.procs"))?;
    ensure!(pids.trim() == "2285828", "audit child is running");
    ensure!(
        !state.join("results/epoch-85.json").try_exists()?
            && !state
                .join("results/epoch-79.retry-3.intent.json")
                .try_exists()?,
        "handoff slot already passed"
    );
    Ok(())
}
fn check_deployment() -> Result<()> {
    let rt = Path::new(ROOT).join("runtime-v10");
    for (k, v) in [
        ("audit", NEW),
        ("config.json", CONFIG),
        (
            "deployment-seal-receipt.json",
            "f0fe063020f459c5f44ad36f2c7629bbe198050e5105648420289ab11e618cd9",
        ),
    ] {
        ensure!(sha(&rt.join(k))? == v, "successor {k} differs");
    }
    ensure!(
        sha(&Path::new(STATE).join("results/epoch-79.retry-2.json"))? == TERMINAL79,
        "epoch 79 predecessor differs"
    );
    let status: Value = serde_json::from_str(&run(
        rt.join("audit").to_str().unwrap(),
        &["status", rt.join("config.json").to_str().unwrap()],
    )?)?;
    ensure!(
        status["summary"]["transfer_retries_pending"]
            .as_u64()
            .is_some_and(|n| n >= 1),
        "no eligible recovery"
    );
    Ok(())
}
fn main() -> Result<()> {
    let mode = std::env::args()
        .nth(1)
        .context("expected check or switch")?;
    ensure!(
        mode == "check" || mode == "switch",
        "expected check or switch"
    );
    let receipt = Path::new(ROOT).join("range-v10-transition");
    let dropin = Path::new(CFG_DIR).join("96-epoch79-range-recovery.conf");
    let old_dropin = fs::read_to_string(Path::new(CFG_DIR).join("95-sequential-range.conf"))?;
    ensure!(
        old_dropin.matches("runtime-v9").count() == 5,
        "unexpected v9 unit definition"
    );
    let dropin_bytes = old_dropin
        .replace("runtime-v9", "runtime-v10")
        .replace("ExecStartPre=/", "ExecStartPre=\nExecStartPre=/");
    let before = native()?;
    ensure!(
        before["InvocationID"] == IID && before["MainPID"] == "2285828",
        "incumbent changed"
    );
    ensure!(
        !dropin.try_exists()? && !receipt.join("STOP_INTENT.json").try_exists()?,
        "handoff already attempted"
    );
    if mode == "check" {
        old_owner(&before)?;
        check_deployment()?;
        println!("validated successor, predecessor, live owner, and pending ranged recovery");
        return Ok(());
    }
    // Freeze before reading the phase so the next download cannot race the idle check.
    run("systemctl", &["freeze", UNIT])?;
    let thaw = Frozen;
    let n = native()?;
    old_owner(&n)?;
    ensure!(n["FreezerState"] == "frozen", "freeze not complete");
    boundary(&n)?;
    check_deployment()?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let state = Path::new(STATE);
    let proof = json!({"at":now,"old":n,"successor_sha256":NEW,"epoch84_result":sha(&state.join("results/epoch-84.json"))?,
        "epoch84_cleanup":sha(&state.join(ATTEMPT).join("cleanup.json"))?,"retry2":TERMINAL79,"empty_scratch":true,"only_controller_in_cgroup":true});
    durable(
        &receipt.join("STOP_INTENT.json"),
        &serde_json::to_vec_pretty(&proof)?,
    )?;
    durable(&dropin, dropin_bytes.as_bytes())?;
    run("systemctl", &["daemon-reload"])?;
    // Deliver SIGTERM to the validated task while it is frozen. Thaw then delivers the
    // pending signal before it can enter a subsequent download.
    let rc = unsafe { libc::kill(2_285_828, libc::SIGTERM) };
    ensure!(rc == 0, "could not signal frozen incumbent");
    drop(thaw);
    run("systemctl", &["stop", UNIT])?;
    let stopped = native()?;
    ensure!(stopped["MainPID"] == "0", "old owner remains");
    durable(
        &receipt.join("STOPPED.json"),
        &serde_json::to_vec_pretty(&stopped)?,
    )?;
    run("systemctl", &["start", UNIT])?;
    let started = native()?;
    ensure!(
        started["InvocationID"] != IID
            && started["SubState"] == "running"
            && sha(&PathBuf::from(format!("/proc/{}/exe", started["MainPID"])))? == NEW,
        "new owner not proven"
    );
    durable(
        &receipt.join("STARTED.json"),
        &serde_json::to_vec_pretty(&started)?,
    )?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn switch_requires_verified_playback_and_exact_attempt_cleanup() {
        let o = json!({"epoch":84,"status":"passed","remote_mutations":false,"attempt":format!("{STATE}/{ATTEMPT}"),"playback":{"clean_process_exit":true}});
        let c = json!({"epoch":84,"removed_only_owned_audit_copy":true});
        clean_result(&o, &c).unwrap();
        let mut bad = o.clone();
        bad["status"] = json!("failed");
        assert!(clean_result(&bad, &c).is_err());
        let mut bad = o;
        bad["attempt"] = json!("/foreign");
        assert!(clean_result(&bad, &c).is_err());
    }
}
