//! Restore the sole routine observer after the actual retry8 producer admission.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::Path,
    process::Command,
};
const ROOT: &str = "/var/lib/jetstreamer/observe166-retry8-20261119-v2";
const DEST: &str = "/usr/local/lib/jetstreamer/horizon-live166retry8-observer-20261119-v2";
const CONFIG: &str =
    "/usr/local/lib/jetstreamer/horizon-stopped166167-observer-0151-20261119-v1/observer.json";
const UNIT: &str = "horizon-qualify-166-replacement-local3retry8-20261110-v1.service";
const IID: &str = "4f09db5f45074244a45b06aeef932d1d";
const ADMISSION: &str = "/var/lib/jetstreamer/retry8-single166-guarded-launch-20261119-v1/epoch166/ACTUAL_REPLACEMENT_ADMISSION.json";
const PROTECTION: &str = "/var/lib/jetstreamer/retry8-single166-guarded-launch-20261119-v1/epoch166/ACTUAL_GUARD_PROTECTION.json";
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
fn save(name: &str, v: &Value) -> Result<Value> {
    let p = format!("{ROOT}/{name}");
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&p)?;
    serde_json::to_writer_pretty(&mut f, v)?;
    f.write_all(b"\n")?;
    f.sync_all()?;
    File::open(ROOT)?.sync_all()?;
    bind(&p)
}
fn run(args: &[&str]) -> Result<String> {
    let o = Command::new(args[0]).args(&args[1..]).output()?;
    ensure!(
        o.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    Ok(String::from_utf8(o.stdout)?)
}
fn native(unit: &str) -> Result<String> {
    run(&[
        "systemctl",
        "show",
        unit,
        "-pId,ActiveState,SubState,MainPID,InvocationID,NRestarts,Job",
    ])
}
fn require(s: &str, lines: &[&str]) -> Result<()> {
    for line in lines {
        ensure!(s.lines().any(|l| l == *line), "missing {line}");
    }
    Ok(())
}
fn main() -> Result<()> {
    ensure!(unsafe { libc::geteuid() } == 0, "root required");
    ensure!(
        !Path::new(ROOT).exists(),
        "immutable operation already exists"
    );
    let a = read(ADMISSION)?;
    let p = read(PROTECTION)?;
    ensure!(
        a["fresh_admission_passed"] == true
            && a["producer_invocation_id"] == IID
            && p["admission"] == bind(ADMISSION)?
            && p["producer_invocation_id"] == IID,
        "admission mismatch"
    );
    let producer = native(UNIT)?;
    require(
        &producer,
        &[
            "ActiveState=active",
            "SubState=running",
            "MainPID=1746683",
            "NRestarts=0",
            &format!("InvocationID={IID}"),
        ],
    )?;
    for suffix in ["timer", "service"] {
        require(
            &native(&format!(
                "horizon-observer-root0151-stopped166167-20261119-v1.{suffix}"
            ))?,
            &["ActiveState=inactive", "Job="],
        )?;
    }
    let log = "/home/sol/.jetstreamer-private/epoch166-standard-lane-20261109-v1/replacement-local3retry8-20261110-v1/producer.log";
    let md = fs::symlink_metadata(log)?;
    ensure!(md.is_file() && md.dev() == 64512, "log identity");
    let scratch = "/home/sol/.jetstreamer-private/epoch166-standard-lane-20261109-v1/replacement-local3retry8-20261110-v1/private/destination-f5ca2c2ad058437c08aaf6b1f7ce14a26791e7ff9d9fb375ce654c014d85a2c3/work/root-cohort-166-166/run-1746683-1795053006864315025/scratch";
    ensure!(fs::symlink_metadata(scratch)?.is_dir(), "scratch missing");
    let mut cfg = read(CONFIG)?;
    ensure!(
        cfg["replays"] == json!([])
            && cfg["minimum_interval_seconds"] == 1800
            && cfg["not_before_utc"] == "2026-11-19T01:51:25Z"
            && cfg["diagnostic_replays"]
                .as_array()
                .context("diagnostics")?
                .len()
                == 13,
        "foreign prior configuration"
    );
    // The observer rejects overlapping epoch ranges, including terminal diagnostics.
    // Preserve the superseded identity in this durable handoff, rather than pretending
    // that it is a second current observation for epoch166.
    let diagnostics = cfg["diagnostic_replays"].as_array_mut().unwrap();
    let index = diagnostics
        .iter()
        .position(|r| r["range"] == "166")
        .context("old166 diagnostic")?;
    let superseded166 = diagnostics.remove(index);
    ensure!(
        superseded166["expected_producer_invocation_id"] == "03fa3ce80d8c4769a1e9dec548cdbeca",
        "foreign predecessor"
    );
    cfg["replays"] = json!([{"range":"166", "controller_unit":UNIT, "producer_unit":UNIT,
        "expected_controller_invocation_id":IID, "expected_producer_invocation_id":IID,
        "scratch_path":scratch, "worker_executable_basename":"historical-worker",
        "append_log":{"path":log,"device":md.dev(),"inode":md.ino()}}]);
    cfg["output"] = json!(
        "/var/lib/jetstreamer-horizon-observe-eleven-focus-20261017-v1/sample-root-live166retry8-first-20261119-v2.json"
    );
    fs::DirBuilder::new().mode(0o700).create(ROOT)?;
    let cb = save("observer.json", &cfg)?;
    let plan = save(
        "seal-plan.json",
        &json!({"schema":"jetstreamer-sealed-deployment-plan-v1","destination":DEST,
        "members":[{"source":cb["path"],"name":"observer.json","sha256":cb["sha256"],"mode":292}]}),
    )?;
    ensure!(sha(&fs::read(SEALER)?) == SEALER_SHA, "sealer changed");
    run(&[
        SEALER,
        plan["path"].as_str().unwrap(),
        "--plan-sha256",
        plan["sha256"].as_str().unwrap(),
        "--self-sha256",
        SEALER_SHA,
    ])?;
    save(
        "handoff.json",
        &json!({"previous_config":bind(CONFIG)?,"new_config":bind(&format!("{DEST}/observer.json"))?,
        "admission":bind(ADMISSION)?,"protection":bind(PROTECTION)?,"producer_native":producer,
            "superseded166_diagnostic":superseded166,"current_diagnostic_rows":12,"historical_diagnostic_rows_preserved":13,"same_minimum_cadence_seconds":1800,"replay_mutations":false,"remote_mutations":false}),
    )?;
    println!(
        "{}",
        run(&[
            "systemd-run",
            "--unit=horizon-observer-live166retry8-first-20261119-v2",
            "--on-active=2s",
            "--timer-property=AccuracySec=1s",
            "--property=Type=oneshot",
            "--property=CPUQuota=200%",
            "--property=MemoryMax=2G",
            "--property=TasksMax=128",
            "/usr/local/lib/jetstreamer/horizon-observer-exit-census-20261107-v1/jetstreamer-horizon-observe",
            &format!("{DEST}/observer.json")
        ])?
    );
    Ok(())
}
