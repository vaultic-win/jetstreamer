//! Retire a stopped v1.5.6 worker's private account storage while a sibling replays.
#[path = "../horizon_retry4_170_scratch_retire_20261118_v1/src/process_references.rs"]
mod process_references;
#[path = "../horizon_retry4_170_scratch_retire_20261118_v1/src/stopped_tree.rs"]
mod stopped_tree;
mod terminal9;

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
};

const BASE: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch170-ancestor-accounts-20261121-v1";
const ORIGINAL: &str = "8d120ed88adc4afb9485fb3f61dfa29c";
const DEVICE: u64 = 64512;
const UID: u32 = 1001;
const GID: u32 = 1003;
fn sha(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
fn string<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str().with_context(|| format!("missing string {k}"))
}
fn read(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let before = f.metadata()?;
    ensure!(
        path.canonicalize()? == path
            && before.is_file()
            && before.uid() == 0
            && before.mode() & 0o022 == 0
            && before.nlink() == 1
            && before.len() <= limit,
        "unsafe root data {}",
        path.display()
    );
    let mut b = Vec::new();
    (&f).take(limit + 1).read_to_end(&mut b)?;
    let after = f.metadata()?;
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.dev() == before.dev()
            && m.ino() == before.ino()
            && before.len() == b.len() as u64
            && before.ctime() == after.ctime()
            && before.ctime_nsec() == after.ctime_nsec(),
        "root data changed"
    );
    Ok(b)
}
fn bound(v: &Value) -> Result<Value> {
    let b = read(Path::new(string(v, "path")?), 32 << 20)?;
    ensure!(
        sha(&b) == string(v, "sha256")?,
        "bound evidence digest changed"
    );
    Ok(serde_json::from_slice(&b)?)
}
fn evidence(path: &Path) -> Result<Value> {
    Ok(serde_json::from_slice(&read(path, 1 << 20)?)?)
}
fn output(dir: &Path, name: &str, b: &[u8]) -> Result<()> {
    let m = dir.symlink_metadata()?;
    ensure!(
        dir.canonicalize()? == dir && m.is_dir() && m.uid() == 0 && m.mode() & 0o7777 == 0o700,
        "unsafe receipt directory"
    );
    let temp = dir.join(format!(".{name}.{}", std::process::id()));
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)?;
    f.write_all(b)?;
    f.sync_all()?;
    drop(f);
    // The advisory lock on the target serializes check and execute. renameat2 publishes the complete, singly linked file.
    let source = std::ffi::CString::new(temp.as_os_str().as_encoded_bytes())?;
    let destination = std::ffi::CString::new(dir.join(name).as_os_str().as_encoded_bytes())?;
    if unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            source.as_ptr(),
            libc::AT_FDCWD,
            destination.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error()).context("publish immutable receipt");
    }
    File::open(dir)?.sync_all()?;
    Ok(())
}
fn unit(name: &str) -> Result<BTreeMap<String, String>> {
    let out=Command::new("/usr/bin/systemctl").args(["show","--all","--no-pager","-p","Id,ActiveState,SubState,MainPID,ControlPID,NRestarts,Job,InvocationID,ControlGroup,Triggers",name]).output()?;
    ensure!(
        out.status.success() && out.stderr.is_empty() && out.stdout.len() < 65536,
        "native query failed"
    );
    let map: BTreeMap<String, String> = std::str::from_utf8(&out.stdout)?
        .lines()
        .map(|s| {
            let (k, v) = s.split_once('=').context("invalid native row")?;
            Ok((k.into(), v.into()))
        })
        .collect::<Result<_>>()?;
    ensure!(
        map.get("Id").map(String::as_str) == Some(name) && map["Job"].is_empty(),
        "unit missing or queued"
    );
    Ok(map)
}
fn closed(name: &str) -> Result<()> {
    let u = unit(name)?;
    ensure!(
        u["ActiveState"] == "inactive"
            && u["SubState"] == "dead"
            && ["MainPID", "ControlPID", "NRestarts"]
                .iter()
                .all(|k| u.get(*k).is_none_or(|v| v == "0"))
            && !Path::new("/sys/fs/cgroup/system.slice")
                .join(name)
                .try_exists()?,
        "old owner not drained: {name}"
    );
    Ok(())
}
fn preserved(p: &Value) -> Result<()> {
    let path = Path::new(string(p, "path")?);
    let m = path.symlink_metadata()?;
    ensure!(
        m.is_file()
            && m.nlink() == 1
            && m.dev() == DEVICE
            && m.uid() == UID
            && m.gid() == GID
            && path.canonicalize()? == path
            && p["inode"] == m.ino()
            && p["mode"] == m.mode()
            && p["size"] == m.len()
            && p["mtime_ns"] == m.mtime() * 1_000_000_000 + m.mtime_nsec(),
        "protected sibling changed: {}",
        path.display()
    );
    Ok(())
}
fn gates(p: &Value, protected: &Value) -> Result<Value> {
    let target = Path::new(string(p, "target")?);
    let n = string(p, "unit")?;
    for k in ["unit", "guard", "timer"] {
        closed(string(p, k)?)?
    }
    let intent = bound(&p["intent"])?;
    let stop = bound(&p["stop"])?;
    let admit = bound(&p["admission"])?;
    let prot = bound(&p["protection"])?;
    ensure!(
        intent["schema"] == "jetstreamer-horizon-standalone-stop-intent-v1"
            && stop["schema"] == "jetstreamer-horizon-standalone-stop-completion-v1"
            && intent["producer_invocation_id"] == p["iid"]
            && stop["producer_invocation_id"] == p["iid"]
            && stop["intent"] == p["intent"]["path"]
            && stop["plan_sha256"] == p["plan_sha256"]
            && intent["plan_sha256"] == p["plan_sha256"]
            && intent["reason"] == p["stop_reason"]
            && stop["terminal"]["active"] == "inactive"
            && stop["terminal"]["sub"] == "dead"
            && stop["terminal"]["pid"] == 0
            && stop["terminal"]["restarts"] == 0
            && stop["scratch_deleted"] == false
            && stop["r2_mutations"] == false,
        "stop/intent lineage changed"
    );
    let active_admit = if p["attempt"] == "local3retry5" {
        admit["schema"] == "horizon-epoch170-retry5-postlaunch-admission-v1"
            && admit["replay_active_and_guarded"] == true
    } else {
        admit["schema"] == "horizon-standard-replacement-admission-v1"
            && admit["fresh_admission_passed"] == true
    };
    ensure!(
        active_admit
            && admit["epoch"] == 170
            && admit["producer_unit"] == n
            && admit["producer_invocation_id"] == p["iid"]
            && admit["resource_credit_bytes"] == 0
            && prot["schema"] == "horizon-standard-live-peer-protection-v1"
            && prot["admission"] == p["original_admission"]
            && prot["producer_invocation_id"] == p["iid"]
            && prot["producer_unit"] == n,
        "admission/protection lineage changed"
    );
    for s in p["preserved"]
        .as_array()
        .context("protected siblings absent")?
    {
        preserved(s)?
    }
    let a = bound(&protected["admission"])?;
    let live = unit(string(&a, "producer_unit")?)?;
    let gp = bound(&protected["guard_plan"])?;
    let w = bound(&protected["witness"])?;
    ensure!(
        a["producer_invocation_id"] == ORIGINAL
            && gp["invocation_id"] == ORIGINAL
            && gp["maximum_root_physical_bytes"] == 309237645312u64
            && gp["minimum_free_bytes"] == 6829053656882u64,
        "foreign original replay or guard plan"
    );
    let stopped = if live["ActiveState"] == "inactive" {
        Some(terminal9::verify(p, target, &a, &gp)?)
    } else {
        ensure!(
            live["InvocationID"] == ORIGINAL
                && live["ActiveState"] == "active"
                && live["SubState"] == "running"
                && live["NRestarts"] == "0"
                && Some(live["MainPID"].parse::<u64>()?) == a["producer_pid"].as_u64(),
            "original guarded worker identity changed"
        );
        let t = unit("horizon-guard-replacement-170-local3retry9-20261110-v1.timer")?;
        ensure!(
            t["ActiveState"] == "active"
                && matches!(t["SubState"].as_str(), "waiting" | "running")
                && t["Triggers"]
                    == "horizon-guard-replacement-170-local3retry9-20261110-v1.service",
            "guard timer changed"
        );
        None
    };
    let fresh = bound(&protected["fresh"])?;
    let productive = Path::new(string(&fresh["fresh_subtree"], "path")?);
    ensure!(
        target.starts_with(string(&gp, "worker_root")?)
            && !target.starts_with(productive)
            && !productive.starts_with(target)
            && !fresh["producer_argv"]
                .to_string()
                .contains(string(p, "target")?)
            && target.file_name().and_then(|x| x.to_str()) == Some("accounts-state"),
        "scope intersects productive input"
    );
    let slot = w["slots"]
        .as_array()
        .context("witness slots")?
        .iter()
        .find(|v| v["epoch"] == 170)
        .context("original 170 witness")?;
    let members = slot["members"].as_array().context("witness members")?;
    ensure!(
        members.len() == 2
            && members.iter().all(|x| x
                .as_str()
                .is_some_and(|p| !Path::new(p).starts_with(target))),
        "witness in scope"
    );
    let mut anchors = json!({"original_iid":ORIGINAL, "old_iid":p["iid"], "fresh_subtree":productive, "witnesses":members});
    if let Some(closed) = stopped {
        anchors["closed_retry9"] = closed;
    }
    Ok(anchors)
}
fn scan(target: &Path) -> Result<Value> {
    let v = process_references::scan(Path::new("/proc"), target)?;
    ensure!(
        v.references.is_empty(),
        "live tree reference: {:?}",
        v.references
    );
    Ok(serde_json::to_value(v)?)
}
fn run() -> Result<()> {
    let argv: Vec<_> = std::env::args().collect();
    ensure!(
        argv.len() == 3,
        "retire (inspect|check|execute) local3retryN"
    );
    let (mode, attempt) = (argv[1].as_str(), argv[2].as_str());
    let manifest: Value = serde_json::from_slice(include_bytes!("profiles.json"))?;
    let p = manifest["profiles"]
        .get(attempt)
        .context("unknown attempt")?;
    let anchors = gates(p, &manifest["protected"])?;
    let target = Path::new(string(p, "target")?);
    let fd = stopped_tree::open_root(target, DEVICE, p["inode"].as_u64().context("target inode")?)?;
    if mode == "inspect" {
        println!(
            "{}",
            json!({"anchors":anchors,"target":target,"scope_only":true})
        );
        return Ok(());
    }
    ensure!(
        matches!(mode, "check" | "execute") && unsafe { libc::geteuid() } == 0,
        "invalid mode/owner"
    );
    let base = Path::new(BASE);
    let post_stop = anchors.get("closed_retry9").is_some();
    let elf = base.join(if post_stop {
        "post-stop-tools/retire"
    } else {
        "tools/retire"
    });
    let image = sha(&read(&elf, 32 << 20)?);
    ensure!(
        fs::read_link("/proc/self/exe")? == elf && image == sha(&fs::read("/proc/self/exe")?),
        "sealed image required"
    );
    let conf = sha(include_bytes!("profiles.json"));
    let dir: PathBuf = base
        .join(if post_stop {
            "post-stop-state"
        } else {
            "state"
        })
        .join(attempt);
    let checkpath = dir.join("CHECK.json");
    let ledgerpath = dir.join("LEDGER.json");
    let process = scan(target)?;
    if mode == "check" {
        let first = stopped_tree::capture(&fd, DEVICE, UID, GID)?;
        let second = stopped_tree::capture(&fd, DEVICE, UID, GID)?;
        ensure!(
            first == second && first.len() > 350_000 && first.len() < 450_000,
            "old accounts inventory changed"
        );
        drop(second);
        let bytes = serde_json::to_vec(&first)?;
        let count = first.len();
        drop(first);
        let hash = sha(&bytes);
        if ledgerpath.try_exists()? {
            ensure!(
                sha(&read(&ledgerpath, 220 << 20)?) == hash,
                "staged ledger differs"
            )
        } else {
            output(&dir, "LEDGER.json", &bytes)?
        }
        let check = json!({"schema":"horizon170-closed-accounts-check-v1","attempt":attempt,"target":target,"inode":p["inode"],"manifest":conf,"elf":image,"anchors":anchors,"ledger_sha256":hash,"entries":count,"references":process,"resource_credit_bytes":0});
        output(&dir, "CHECK.json", &serde_json::to_vec_pretty(&check)?)?;
        println!("{}", check);
        return Ok(());
    }
    let prior = evidence(&checkpath)?;
    let bytes = read(&ledgerpath, 220 << 20)?;
    ensure!(
        prior["schema"] == "horizon170-closed-accounts-check-v1"
            && prior["attempt"] == attempt
            && prior["target"] == string(p, "target")?
            && prior["inode"] == p["inode"]
            && prior["elf"] == image
            && prior["manifest"] == conf
            && prior["anchors"] == anchors
            && prior["ledger_sha256"] == sha(&bytes),
        "root check differs"
    );
    let ledger: stopped_tree::Ledger = serde_json::from_slice(&bytes)?;
    drop(bytes);
    ensure!(
        Some(ledger.len() as u64) == prior["entries"].as_u64(),
        "ledger count differs"
    );
    let intent = json!({"check_sha256":sha(&read(&checkpath,1<<20)?),"scope":target,"inode":p["inode"],"original_iid":ORIGINAL,"ledger_sha256":prior["ledger_sha256"],"resource_credit_bytes":0});
    let ip = dir.join("INTENT.json");
    let resuming = ip.try_exists()?;
    if resuming {
        ensure!(evidence(&ip)? == intent, "prior intent differs")
    }
    let current = stopped_tree::capture(&fd, DEVICE, UID, GID)?;
    stopped_tree::validate_remaining(&ledger, &current, resuming)?;
    drop(current);
    if !resuming {
        output(&dir, "INTENT.json", &serde_json::to_vec_pretty(&intent)?)?
    }
    let removed = stopped_tree::remove_contents(&fd, &ledger, DEVICE, UID, GID)?;
    let after = gates(p, &manifest["protected"])?;
    ensure!(after == anchors, "post-retirement bindings changed");
    let complete = json!({"schema":"horizon170-closed-accounts-complete-v1","attempt":attempt,"scope":target,"original_iid":ORIGINAL,"scope_empty":true,"entries_removed_this_invocation":removed,"check_sha256":intent["check_sha256"],"intent_sha256":sha(&read(&ip,1<<20)?),"retired_tree_before_bytes":p["expected_bytes"],"scope_root_remaining_bytes":fd.metadata()?.blocks()*512,"archive_or_snapshot_removed":false,"resource_credit_bytes":0});
    if dir.join("COMPLETE.json").try_exists()? {
        let old = evidence(&dir.join("COMPLETE.json"))?;
        ensure!(
            old["intent_sha256"] == complete["intent_sha256"]
                && old["scope_empty"] == true
                && removed == 0,
            "retry completion differs"
        );
        println!("{}", old)
    } else {
        output(
            &dir,
            "COMPLETE.json",
            &serde_json::to_vec_pretty(&complete)?,
        )?;
        println!("{}", complete)
    }
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("{e:#}");
        std::process::exit(1)
    }
}
