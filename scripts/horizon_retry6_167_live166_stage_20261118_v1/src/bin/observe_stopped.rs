//! Preserve stopped producers as diagnostic rows on the existing resource cadence.
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
const ROOT: &str = "/var/lib/jetstreamer/root-stopped166167-observer-20261119-v1";
const CONFIG: &str = "/usr/local/lib/jetstreamer/horizon-live166167-observer-config-0049-20261119-v2/next-observer.json";
const EVENT: &str = "/var/lib/jetstreamer/root0111-witness-stop-event-20261119-v1/ROOT_COMPLETE_OPERATIONAL_FLEET.json";
const SEALER: &str = "/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment";
const SEALER_SHA: &str = "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3";
fn sha(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
fn read(p: &str) -> Result<Value> {
    Ok(serde_json::from_slice(&fs::read(p)?)?)
}
fn bind(p: &str) -> Result<Value> {
    Ok(json!({"path":p,"sha256":sha(&fs::read(p)?)}))
}
fn save(p: &str, v: &Value) -> Result<Value> {
    let mut f = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o400)
        .custom_flags(libc::O_NOFOLLOW)
        .open(p)?;
    f.write_all(&serde_json::to_vec_pretty(v)?)?;
    f.sync_all()?;
    File::open(Path::new(p).parent().context("parent")?)?.sync_all()?;
    bind(p)
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
fn finish(sample_path: &str, status_path: &str) -> Result<()> {
    let sample = read(sample_path)?;
    let status = read(status_path)?;
    ensure!(
        sample["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && sample["replays"] == json!([])
            && sample["cadence"]["routine_minimum_interval_enforced"] == true
            && status["observer"] == bind(sample_path)?
            && status["authenticated_readback"] == true
            && status["authenticated_status_count"] == 19
            && status["active_producer_count"] == 0,
        "complete stopped-owner cycle required"
    );
    let next = sample["cadence"]["next_routine_observation_not_before_utc"]
        .as_str()
        .context("next clock")?;
    ensure!(next == "2026-11-19T01:51:25Z", "exact next cadence");
    let root = "/var/lib/jetstreamer/root0121-stopped166167-cycle-20261119-v1";
    fs::DirBuilder::new().mode(0o700).create(root)?;
    let previous =
        "/usr/local/lib/jetstreamer/horizon-stopped166167-observer-0121-20261119-v1/observer.json";
    let mut cfg = read(previous)?;
    ensure!(
        cfg["output"] == sample_path && cfg["replays"] == json!([]),
        "predecessor config differs"
    );
    cfg["previous_sample"] = json!(sample_path);
    cfg["not_before_utc"] = json!(next);
    cfg["output"] = json!(
        "/var/lib/jetstreamer-horizon-observe-eleven-focus-20261017-v1/sample-root0151-stopped166167-20261119-v1.json"
    );
    let source = format!("{root}/observer.json");
    let c = save(&source, &cfg)?;
    let dest = "/usr/local/lib/jetstreamer/horizon-stopped166167-observer-0151-20261119-v1";
    let pp = format!("{root}/seal-plan.json");
    let p = save(
        &pp,
        &json!({"schema":"jetstreamer-sealed-deployment-plan-v1","destination":dest,"members":[{"source":source,"name":"observer.json","sha256":c["sha256"],"mode":292}]}),
    )?;
    ensure!(sha(&fs::read(SEALER)?) == SEALER_SHA, "sealer changed");
    run(&[
        SEALER,
        &pp,
        "--plan-sha256",
        p["sha256"].as_str().unwrap(),
        "--self-sha256",
        SEALER_SHA,
    ])?;
    let sealed = format!("{dest}/observer.json");
    let timer = run(&[
        "/usr/bin/systemd-run",
        "--unit=horizon-observer-root0151-stopped166167-20261119-v1",
        "--on-calendar=2026-11-19 01:51:25 UTC",
        "--timer-property=AccuracySec=1s",
        "--property=Type=oneshot",
        "--property=CPUQuota=200%",
        "--property=MemoryMax=2G",
        "--property=TasksMax=128",
        "/usr/local/lib/jetstreamer/horizon-observer-exit-census-20261107-v1/jetstreamer-horizon-observe",
        &sealed,
    ])?;
    let mut fleet = read(EVENT)?;
    fleet["previous_Root_operational_review"] = bind(EVENT)?;
    fleet["observer"] = bind(sample_path)?;
    fleet["authenticated_status_audit"] = bind(status_path)?;
    fleet["sampled_at_utc"] = sample["recorded_at_utc"].clone();
    fleet["recorded_unix_seconds"] = json!(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs()
    );
    fleet["same_sample_conservative_free_DATA_bytes"] =
        sample["filesystem"]["conservative_available_bytes"].clone();
    fleet["sole_next_observer"] = bind(&sealed)?;
    for row in fleet["epochs"].as_array_mut().context("complete fleet")? {
        let e = row["epoch"].as_u64().context("epoch")?;
        row["current_coordinated_observer"] = bind(sample_path)?;
        if let Some(binding) = status["receipts"].get(e.to_string()) {
            let path = binding["path"].as_str().context("status path")?;
            ensure!(bind(path)? == *binding, "status binding");
            let receipt = read(path)?;
            ensure!(
                receipt["authenticated_readback"] == true && receipt["epoch"] == e,
                "status authenticity"
            );
            for key in ["current_authenticated_status_receipt", "status_publication"] {
                row[key] = binding.clone();
            }
            for key in ["current_status", "status"] {
                row[key] = receipt["after_status"].clone();
            }
        }
    }
    fleet["cycle_reconciliation_scope"] = json!(
        "Accepted routine 01:21 resource sample, zero executing producers, authenticated entire-range nineteen-status audit. Exact terminal history preserved; no reservation release or launch authority."
    );
    println!(
        "{}",
        save(
            &format!("{root}/ROOT_COMPLETE_OPERATIONAL_FLEET.json"),
            &fleet
        )?
    );
    println!("{timer}");
    Ok(())
}
fn main() -> Result<()> {
    ensure!(unsafe { libc::geteuid() } == 0, "root required");
    let args: Vec<_> = std::env::args().collect();
    if args.len() == 3 {
        return finish(&args[1], &args[2]);
    }
    ensure!(
        args.len() == 1,
        "no arguments, or SAMPLE STATUS for cycle completion"
    );
    let event = read(EVENT)?;
    ensure!(
        event["active_producer_count"] == 0
            && event["failure_event"]["guard_stops"]
                .as_array()
                .is_some_and(|v| v.len() == 2),
        "exact failure event missing"
    );
    for (e, a) in [(166, "local3retry7"), (167, "local3retry6")] {
        let unit = format!("horizon-qualify-{e}-replacement-{a}-20261110-v1.service");
        let native = run(&[
            "/usr/bin/systemctl",
            "show",
            &unit,
            "-pActiveState,MainPID,ControlPID,Job",
        ])?;
        for s in ["ActiveState=inactive", "MainPID=0", "ControlPID=0", "Job="] {
            ensure!(native.lines().any(|l| l == s), "terminal owner changed");
        }
    }
    fs::DirBuilder::new().mode(0o700).create(ROOT)?;
    let mut cfg = read(CONFIG)?;
    let replays = cfg["replays"].as_array().context("old replays")?.clone();
    ensure!(
        replays.len() == 2 && replays[0]["range"] == "166" && replays[1]["range"] == "167",
        "exact old owners"
    );
    cfg["diagnostic_replays"]
        .as_array_mut()
        .context("diagnostics")?
        .extend(replays);
    cfg["replays"] = json!([]);
    cfg["output"] = json!(
        "/var/lib/jetstreamer-horizon-observe-eleven-focus-20261017-v1/sample-root0121-stopped166167-20261119-v1.json"
    );
    let source = format!("{ROOT}/observer.json");
    let binding = save(&source, &cfg)?;
    let dest = "/usr/local/lib/jetstreamer/horizon-stopped166167-observer-0121-20261119-v1";
    let plan_path = format!("{ROOT}/seal-plan.json");
    let plan = save(
        &plan_path,
        &json!({"schema":"jetstreamer-sealed-deployment-plan-v1","destination":dest,"members":[{"source":source,"name":"observer.json","sha256":binding["sha256"],"mode":292}]}),
    )?;
    ensure!(sha(&fs::read(SEALER)?) == SEALER_SHA, "sealer changed");
    run(&[
        SEALER,
        &plan_path,
        "--plan-sha256",
        plan["sha256"].as_str().unwrap(),
        "--self-sha256",
        SEALER_SHA,
    ])?;
    let sealed = format!("{dest}/observer.json");
    println!(
        "{}",
        save(
            &format!("{ROOT}/HANDOFF.json"),
            &json!({"previous_config":bind(CONFIG)?,"failure_event":bind(EVENT)?,"new_config":bind(&sealed)?,"ordinary_clock_unchanged":true,"producer_mutations":false})
        )?
    );
    println!(
        "{}",
        run(&[
            "/usr/bin/systemd-run",
            "--unit=horizon-observer-root0121-stopped166167-20261119-v1",
            "--property=Type=oneshot",
            "--property=RemainAfterExit=yes",
            "--property=CPUQuota=200%",
            "--property=MemoryMax=2G",
            "--property=TasksMax=128",
            "/usr/local/lib/jetstreamer/horizon-observer-exit-census-20261107-v1/jetstreamer-horizon-observe",
            &sealed
        ])?
    );
    Ok(())
}
