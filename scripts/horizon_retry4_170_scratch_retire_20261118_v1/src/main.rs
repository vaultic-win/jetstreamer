//! Exact, stopped epoch 170 retry4 scratch retirement. The sibling archive and
//! input directories are held and rechecked; this tool never touches R2.
mod process_references;
mod stopped_tree;

use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

const IMAGE: &str = "/usr/local/lib/jetstreamer/horizon-retry4-170-scratch-retire-20261118-v1/retire";
const BASE: &str = "/var/lib/jetstreamer/epoch170-retry5-recovery-20261117-v1/scratch-retirement-v1";
const RUN: &str = "/home/sol/.jetstreamer-private/epoch170-standard-lane-20261109-v1/replacement-local3retry3-20261110-v1/replacement-local3retry4-20261116-v1/private/destination-1ca738c33c6489c2c3198ebaf434ca50fcb2afc26d20982cc3ac9bb2018cfd68/work/root-cohort-170-170/run-392711-1794870485362475969";
const SCRATCH: &str = "/home/sol/.jetstreamer-private/epoch170-standard-lane-20261109-v1/replacement-local3retry3-20261110-v1/replacement-local3retry4-20261116-v1/private/destination-1ca738c33c6489c2c3198ebaf434ca50fcb2afc26d20982cc3ac9bb2018cfd68/work/root-cohort-170-170/run-392711-1794870485362475969/scratch";
const INTENT: &str = "/var/lib/jetstreamer/retry3-preparation-20261113-v1/epoch170/local3retry4/guard-state/receipts/stop-intent.json";
const INTENT_SHA: &str = "ce1beb74263dee307a2999ad7680438f11cfc7ef17e2096f71e6376f9958dffd";
const STOP: &str = "/var/lib/jetstreamer/retry3-preparation-20261113-v1/epoch170/local3retry4/guard-state/receipts/stop-completion.json";
const STOP_SHA: &str = "584fe719e362f4fcf3a34caa37d526b43fabcafb0255bd443592209c82c3167c";
const ADMISSION: &str = "/var/lib/jetstreamer/epoch170-retry4-live167-20261116-v1/launch-v1/epoch170/ACTUAL_REPLACEMENT_ADMISSION.json";
const ADMISSION_SHA: &str = "e45bb1a2dbcd422e430d9c435cef100a29b2feb91d04d6942e01b785afd43353";
const PROTECTION: &str = "/var/lib/jetstreamer/epoch170-retry4-live167-20261116-v1/launch-v1/epoch170/ACTUAL_GUARD_PROTECTION.json";
const PROTECTION_SHA: &str = "80ad2dc1d71a15d40540d261da68d22484f7b8a1ce171c820afcca9cd3e606c5";
const UNIT: &str = "horizon-qualify-170-replacement-local3retry4-20261110-v1.service";
const GUARD: &str = "horizon-guard-replacement-170-local3retry4-20261110-v1";
const IID: &str = "aabba5ff4c8e4c22ad18c80472713aa9";
const GUARD_PLAN_SHA: &str = "b1866173970ab0735242699936ccb8a4570d6fc6a6b2a11acbc88510b915af79";
const DEVICE: u64 = 64512;
const RUN_INODE: u64 = 105840742;
const SCRATCH_INODE: u64 = 105840748;
const UID: u32 = 1001;
const GID: u32 = 1003;

fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn raw(path: &Path, max: u64, uid: u32) -> Result<Vec<u8>> {
    let meta = fs::symlink_metadata(path)?;
    ensure!(meta.is_file() && meta.uid() == uid && meta.nlink() == 1
        && meta.mode() & 0o022 == 0 && meta.len() <= max
        && path.canonicalize()? == path, "unsafe bound file {}", path.display());
    let mut file = OpenOptions::new().read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(path)?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file).take(max + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= max
        && file.metadata()?.ino() == meta.ino()
        && fs::symlink_metadata(path)?.ino() == meta.ino(),
        "bound file changed");
    Ok(bytes)
}
fn atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("output parent")?;
    let meta = fs::symlink_metadata(parent)?;
    ensure!(meta.is_dir() && meta.uid() == 0 && meta.mode() & 0o7777 == 0o700,
        "unsafe output directory");
    let mut file = OpenOptions::new().write(true).create_new(true)
        .mode(0o600).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    File::open(parent)?.sync_all()?;
    Ok(())
}
fn identity(path: &Path, directory: bool) -> Result<Value> {
    let meta = fs::symlink_metadata(path)?;
    ensure!(meta.dev() == DEVICE && meta.uid() == UID && meta.gid() == GID
        && (if directory { meta.is_dir() } else { meta.is_file() })
        && (directory || meta.nlink() == 1), "protected sibling changed");
    Ok(json!([meta.dev(),meta.ino(),meta.uid(),meta.gid(),meta.mode(),
        meta.nlink(),meta.len(),meta.blocks(),meta.mtime(),meta.mtime_nsec(),
        meta.ctime(),meta.ctime_nsec()]))
}
fn preserved() -> Result<Value> {
    let run = Path::new(RUN);
    let m = fs::symlink_metadata(run)?;
    ensure!(m.is_dir() && m.dev() == DEVICE && m.ino() == RUN_INODE
        && m.uid() == UID && m.gid() == GID, "run directory changed");
    Ok(json!({
        "run": identity(run,true)?,
        "archives": identity(&run.join("archives"),true)?,
        "partial": identity(&run.join("archives/epoch-170.jet"),false)?,
        "inputs": identity(&run.join("inputs"),true)?
    }))
}
fn unit_closed(unit: &str) -> Result<()> {
    let output = Command::new("/usr/bin/systemctl")
        .args(["show",unit,"-pId,ActiveState,SubState,MainPID,ControlPID,NRestarts,Job"])
        .output()?;
    ensure!(output.status.success() && output.stderr.is_empty()
        && output.stdout.len() < 65_536, "native unit query failed");
    let fields: BTreeMap<_,_> = std::str::from_utf8(&output.stdout)?.lines()
        .map(|line| line.split_once('=').context("native field"))
        .collect::<Result<_>>()?;
    ensure!(fields.get("Id") == Some(&unit)
        && fields.get("ActiveState") == Some(&"inactive")
        && fields.get("SubState") == Some(&"dead")
        && fields.get("Job") == Some(&"")
        && fields.get("MainPID").is_none_or(|v| *v == "0")
        && fields.get("ControlPID").is_none_or(|v| *v == "0")
        && fields.get("NRestarts").is_none_or(|v| *v == "0"),
        "old producer or guard is active or queued: {unit}");
    Ok(())
}
fn gates() -> Result<Value> {
    unit_closed(UNIT)?;
    unit_closed(&format!("{GUARD}.service"))?;
    unit_closed(&format!("{GUARD}.timer"))?;
    unit_closed("horizon-qualify-170-replacement-local3retry5-20261110-v1.service")?;
    unit_closed("horizon-guard-replacement-170-local3retry5-20261110-v1.service")?;
    unit_closed("horizon-guard-replacement-170-local3retry5-20261110-v1.timer")?;
    let intent: Value = serde_json::from_slice(&raw(Path::new(INTENT),1<<20,0)?)?;
    let stop: Value = serde_json::from_slice(&raw(Path::new(STOP),1<<20,0)?)?;
    let admission: Value = serde_json::from_slice(&raw(Path::new(ADMISSION),1<<20,0)?)?;
    let protection: Value = serde_json::from_slice(&raw(Path::new(PROTECTION),1<<20,0)?)?;
    ensure!(sha(&raw(Path::new(INTENT),1<<20,0)?) == INTENT_SHA
        && sha(&raw(Path::new(STOP),1<<20,0)?) == STOP_SHA
        && sha(&raw(Path::new(ADMISSION),1<<20,0)?) == ADMISSION_SHA
        && sha(&raw(Path::new(PROTECTION),1<<20,0)?) == PROTECTION_SHA,
        "stop receipt digest differs");
    ensure!(intent["schema"] == "jetstreamer-horizon-standalone-stop-intent-v1"
        && intent["producer_invocation_id"] == IID
        && intent["plan_sha256"] == GUARD_PLAN_SHA
        && intent["reason"] == "DATA-fulfillment-observation-failed"
        && stop["schema"] == "jetstreamer-horizon-standalone-stop-completion-v1"
        && stop["producer_invocation_id"] == IID
        && stop["plan_sha256"] == GUARD_PLAN_SHA
        && stop["terminal"]["active"] == "inactive"
        && stop["terminal"]["sub"] == "dead"
        && stop["terminal"]["pid"] == 0
        && stop["terminal"]["restarts"] == 0
        && stop["scratch_deleted"] == false
        && stop["r2_mutations"] == false
        && admission["schema"] == "horizon-standard-replacement-admission-v1"
        && admission["epoch"] == 170
        && admission["producer_unit"] == UNIT
        && admission["producer_invocation_id"] == IID
        && admission["fresh_admission_passed"] == true
        && admission["resource_credit_bytes"] == 0
        && protection["schema"] == "horizon-standard-live-peer-protection-v1"
        && protection["epoch"] == 170
        && protection["producer_unit"] == UNIT
        && protection["producer_invocation_id"] == IID
        && protection["admission"] == json!({"path":ADMISSION,"sha256":ADMISSION_SHA}),
        "genuine exact retry4 stop proof required");
    let scan = process_references::scan(Path::new("/proc"),Path::new(SCRATCH))?;
    ensure!(scan.references.is_empty(), "live process references old scratch");
    Ok(json!({"stop_intent":{"path":INTENT,"sha256":INTENT_SHA},
        "stop_completion":{"path":STOP,"sha256":STOP_SHA},
        "admission":{"path":ADMISSION,"sha256":ADMISSION_SHA},
        "guard_protection":{"path":PROTECTION,"sha256":PROTECTION_SHA},
        "process_reference_scan":scan,
        "producer_and_guard_closed":true,
        "preserved":preserved()?}))
}
fn check(plan_sha: &str) -> Result<()> {
    let evidence = gates()?;
    let root = stopped_tree::open_root(Path::new(SCRATCH),DEVICE,SCRATCH_INODE)?;
    let first = stopped_tree::capture(&root,DEVICE,UID,GID)?;
    let second = stopped_tree::capture(&root,DEVICE,UID,GID)?;
    ensure!(first == second && first.len() > 100_000, "scratch inventory changed or is already retired");
    let bytes = serde_json::to_vec(&first)?;
    let ledger = Path::new(BASE).join("LEDGER.json");
    atomic(&ledger,&bytes)?;
    let receipt = json!({"schema":"horizon-retry4-170-scratch-retirement-check-v1",
        "owner":"/root","epoch":170,"run":RUN,"scratch":SCRATCH,
        "scratch_device":DEVICE,"scratch_inode":SCRATCH_INODE,
        "plan_sha256":plan_sha,"ledger":{"path":ledger,"sha256":sha(&bytes)},
        "entry_count":first.len(),"gates":evidence,"recorded_unix_seconds":now()?,
        "archive_deletion_authorized":false,"remote_mutations":false,
        "replay_launch_authorized":false,"resource_credit_bytes":0});
    atomic(&Path::new(BASE).join("CHECK.json"),&serde_json::to_vec_pretty(&receipt)?)?;
    println!("{}",json!({"check":Path::new(BASE).join("CHECK.json"),"entries":first.len(),
        "scratch_retired":false}));
    Ok(())
}
fn execute(plan_sha: &str) -> Result<()> {
    let check: Value = serde_json::from_slice(&raw(&Path::new(BASE).join("CHECK.json"),1<<20,0)?)?;
    ensure!(check["schema"] == "horizon-retry4-170-scratch-retirement-check-v1"
        && check["plan_sha256"] == plan_sha && check["scratch"] == SCRATCH
        && check["scratch_inode"] == SCRATCH_INODE
        && check["gates"]["preserved"] == preserved()?,
        "check receipt differs");
    let ledger_path = PathBuf::from(check["ledger"]["path"].as_str().context("ledger path")?);
    ensure!(ledger_path == Path::new(BASE).join("LEDGER.json"), "foreign ledger");
    let bytes = raw(&ledger_path,256<<20,0)?;
    ensure!(sha(&bytes) == check["ledger"]["sha256"], "ledger digest differs");
    let expected: stopped_tree::Ledger = serde_json::from_slice(&bytes)?;
    ensure!(expected.len() == check["entry_count"].as_u64().context("entry count")? as usize,
        "ledger count differs");
    let evidence = gates()?;
    ensure!(evidence["preserved"] == check["gates"]["preserved"], "protected sibling changed");
    let root = stopped_tree::open_root(Path::new(SCRATCH),DEVICE,SCRATCH_INODE)?;
    let current = stopped_tree::capture(&root,DEVICE,UID,GID)?;
    let intent_path = Path::new(BASE).join("INTENT.json");
    let resuming = intent_path.exists();
    if resuming {
        let intent: Value = serde_json::from_slice(&raw(&intent_path,1<<20,0)?)?;
        ensure!(intent["schema"] == "horizon-retry4-170-scratch-retirement-intent-v1"
            && intent["plan_sha256"] == plan_sha
            && intent["ledger"] == check["ledger"]
            && intent["scope"] == SCRATCH
            && intent["preserved"] == check["gates"]["preserved"]
            && intent["check"]["sha256"] == sha(&raw(&Path::new(BASE).join("CHECK.json"),1<<20,0)?),
            "resume intent differs");
    }
    stopped_tree::validate_remaining(&expected,&current,resuming)?;
    if !resuming {
        let intent = json!({"schema":"horizon-retry4-170-scratch-retirement-intent-v1",
            "owner":"/root","epoch":170,"plan_sha256":plan_sha,
            "check":{"path":Path::new(BASE).join("CHECK.json"),
                "sha256":sha(&raw(&Path::new(BASE).join("CHECK.json"),1<<20,0)?)},
            "ledger":check["ledger"],"preserved":check["gates"]["preserved"],
            "recorded_unix_seconds":now()?,"scope":SCRATCH,
            "resource_credit_bytes":0,"archive_deletion_authorized":false,
            "remote_mutations":false});
        atomic(&intent_path,&serde_json::to_vec_pretty(&intent)?)?;
    }
    let removed = stopped_tree::remove_contents(&root,&expected,DEVICE,UID,GID)?;
    ensure!(preserved()? == check["gates"]["preserved"], "protected sibling changed after retirement");
    let complete = json!({"schema":"horizon-retry4-170-scratch-retirement-complete-v1",
        "owner":"/root","epoch":170,"plan_sha256":plan_sha,
        "intent":{"path":intent_path,"sha256":sha(&raw(&intent_path,1<<20,0)?)},
        "scratch":SCRATCH,"scratch_inode":SCRATCH_INODE,
        "retired_entry_count":removed,"protected_artifacts_preserved":true,
        "recorded_unix_seconds":now()?,"resource_credit_bytes":0,
        "archive_deletion_authorized":false,"remote_mutations":false,
        "replay_launch_authorized":false});
    atomic(&Path::new(BASE).join("COMPLETE.json"),&serde_json::to_vec_pretty(&complete)?)?;
    println!("{}",json!({"complete":Path::new(BASE).join("COMPLETE.json"),
        "retired_entries":removed,"scratch_empty":true}));
    Ok(())
}
fn run() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    ensure!(args.len() == 7 && args[2] == "--plan-sha256"
        && args[4] == "--self-sha256"
        && matches!(args[6].as_str(),"--check-only"|"--execute"),
        "usage: retire PLAN --plan-sha256 SHA --self-sha256 SHA (--check-only|--execute)");
    ensure!(unsafe { libc::geteuid() } == 0
        && fs::read_link("/proc/self/exe")? == Path::new(IMAGE)
        && sha(&fs::read("/proc/self/exe")?) == args[5], "normally sealed root runtime required");
    let plan_bytes = raw(Path::new(&args[1]),1<<20,0)?;
    ensure!(sha(&plan_bytes) == args[3], "plan digest differs");
    let plan: Value = serde_json::from_slice(&plan_bytes)?;
    ensure!(plan["schema"] == "horizon-retry4-170-scratch-retirement-plan-v1"
        && plan["owner"] == "/root" && plan["epoch"] == 170
        && plan["run"] == RUN && plan["scratch"] == SCRATCH
        && plan["scratch_inode"] == SCRATCH_INODE
        && plan["stop_intent"] == json!({"path":INTENT,"sha256":INTENT_SHA})
        && plan["stop_completion"] == json!({"path":STOP,"sha256":STOP_SHA})
        && plan["admission"] == json!({"path":ADMISSION,"sha256":ADMISSION_SHA})
        && plan["guard_protection"] == json!({"path":PROTECTION,"sha256":PROTECTION_SHA})
        && plan["retire_scratch_contents"] == true
        && plan["preserve_archive_and_inputs"] == true
        && plan["archive_deletion_authorized"] == false
        && plan["remote_mutations"] == false
        && plan["resource_credit_bytes"] == 0,
        "exact limited scratch-retirement authority required");
    match args[6].as_str() {
        "--check-only" => check(&args[3]),
        "--execute" => execute(&args[3]),
        _ => unreachable!(),
    }
}
fn main() {
    if let Err(error) = run() {
        eprintln!("{error:#}");
        std::process::exit(1);
    }
}
