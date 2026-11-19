//! Bind a genuinely inspected closed prefix for append-only holding, without retirement.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::Path,
    process::Command,
};
const ROOT: &str = "/var/lib/jetstreamer/epoch166-retry6-holding-deployment-20261119-v1";
const DEST: &str = "/usr/local/lib/jetstreamer/horizon-closed166-retry6-holding-plan-20261119-v1";
const INSPECTION: &str =
    "/var/lib/jetstreamer/epoch166-retry6-holding-review-20261119-v1/INSPECTION.json";
const SEALER: &str = "/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment";
const SEALER_SHA: &str = "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3";
const SOURCE: &str = "/home/sol/.jetstreamer-private/epoch166-standard-lane-20261109-v1/replacement-local3retry6-20261110-v1/private/destination-d53ec84bc26887772d067cda9258daa995dc2541cb1e81e71b72376b619ffe51/work/root-cohort-166-166/run-689067-1794918104133897328/archives/epoch-166.jet";
const LENGTH: u64 = 56_173_984_550;
const SHA: &str = "c6edc4b47bb905fe8825f09155edcbc217d9ea44246a3a3b4d8deb4387384e85";
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
fn main() -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0 && std::env::args().len() == 1,
        "root; no arguments"
    );
    let bytes = fs::read(INSPECTION)?;
    let i: Value = serde_json::from_slice(&bytes)?;
    ensure!(
        i["schema"] == "horizon-epoch166-retry6-closed-prefix-inspection-v1"
            && i["source"] == SOURCE
            && i["length"] == LENGTH
            && i["sha256"] == SHA
            && i["source_stable"] == true
            && i["native_consumers_clear"] == true
            && i["local_retirement_authorized"] == false,
        "actual exact closed-source inspection required"
    );
    let m = fs::symlink_metadata(SOURCE)?;
    use std::os::unix::fs::MetadataExt;
    ensure!(
        m.is_file()
            && m.dev() == 64512
            && m.ino() == 103678035
            && m.len() == LENGTH
            && m.nlink() == 1
            && m.uid() == 1001
            && m.gid() == 1003
            && m.mode() & 0o7777 == 0o600
            && i["source_identity"][8] == m.mtime()
            && i["source_identity"][9] == m.mtime_nsec()
            && i["source_identity"][10] == m.ctime()
            && i["source_identity"][11] == m.ctime_nsec(),
        "source changed after inspection"
    );
    let eligibility = save(
        "eligibility.json",
        &json!({"schema":"jetstreamer-horizon-holding-eligibility-v2","host":"dev-samjohnson","source":SOURCE,"length":LENGTH,"sha256":SHA,"closed":true,"content_class":"public-chain-artifact","credentials_config_and_logs_excluded":true,"canonical_archive":false,"local_retirement_authorized":false,"owner":"/root","primary_thread":"01a1af2a-9ce8-76a2-8939-b2112bd38f53","inspection":bind(INSPECTION)?,"purpose":"Append-only custody of closed old166retry6 partial to qualify capacity recovery for170; preserve all bytes, no local deletion or replay authority","resource_plan":{"additional_cpu_quota_micros":2000000,"additional_memory_bytes":2147483648u64,"additional_DATA_bytes":0,"canonical_archive_mutations":false,"retirement_pending_transitive_reader_review":true,"restore_overlap_bytes":LENGTH,"restore_trigger":"Only if a separately qualified retained-prefix consumer needs the original bytes","transfer_planning_seconds":2400,"restore_planning_seconds":1200,"prior_ended_transfer_unit":"horizon-closed169-local2-park-20261119-v1.service","all_existing_replay_reservations_retained":true}}),
    )?;
    let mapping = json!({"path":"/usr/local/lib/jetstreamer/horizon-node02-holding-20261023-v1/mapping.json","sha256":"61f7601f78a7aa1f71394a020cbbb28aa9dbd85de858f139def1c989f2b2a89e"});
    ensure!(
        bind(mapping["path"].as_str().unwrap())? == mapping,
        "mapping changed"
    );
    let plan = save(
        "plan.json",
        &json!({"schema":"jetstreamer-horizon-holding-park-plan-v2","mapping":mapping,"eligibility":{"path":format!("{DEST}/eligibility.json"),"sha256":eligibility["sha256"]},"source":SOURCE,"length":LENGTH,"sha256":SHA}),
    )?;
    let members = [("eligibility.json", eligibility), ("plan.json", plan)]
        .into_iter()
        .map(|(name, b)| json!({"source":b["path"],"name":name,"sha256":b["sha256"],"mode":292}))
        .collect::<Vec<_>>();
    let seal = save(
        "holding-seal-plan.json",
        &json!({"schema":"jetstreamer-sealed-deployment-plan-v1","destination":DEST,"members":members}),
    )?;
    ensure!(sha(&fs::read(SEALER)?) == SEALER_SHA, "sealer changed");
    let o = Command::new(SEALER)
        .args([
            seal["path"].as_str().context("path")?,
            "--plan-sha256",
            seal["sha256"].as_str().unwrap(),
            "--self-sha256",
            SEALER_SHA,
        ])
        .output()?;
    ensure!(
        o.status.success(),
        "sealing failed: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    ensure!(Path::new(DEST).is_dir(), "sealed package missing");
    println!("{}", bind(&format!("{DEST}/plan.json"))?);
    Ok(())
}
