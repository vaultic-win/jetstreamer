//! Retire private AccountsDb scratch from the two stopped historical epoch 167 runs.
#[path = "../horizon_retry4_170_scratch_retire_20261118_v1/src/process_references.rs"]
mod process_references;
#[path = "../horizon_retry4_170_scratch_retire_20261118_v1/src/stopped_tree.rs"]
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
};

#[cfg(any(
    all(feature = "independent166", feature = "standard170"),
    all(
        feature = "metered170_full",
        any(
            feature = "independent166",
            feature = "standard170",
            feature = "metered168",
            feature = "metered168_retry4"
        )
    ),
    all(
        feature = "metered168_retry4",
        any(
            feature = "independent166",
            feature = "standard170",
            feature = "metered168"
        )
    ),
    all(
        feature = "metered168",
        any(feature = "independent166", feature = "standard170")
    )
))]
compile_error!("select one epoch profile");

#[cfg(not(any(
    feature = "independent166",
    feature = "standard170",
    feature = "metered168",
    feature = "metered168_retry4",
    feature = "metered170_full"
)))]
const BASE: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch167-ancestor-accounts-20261122-v2";

#[cfg(any(feature = "independent166", feature = "standard170"))]
mod cold166;
#[cfg(any(feature = "independent166", feature = "standard170"))]
use cold166 as specific;
#[cfg(feature = "metered168")]
#[path = "closed168.rs"]
mod specific;

#[cfg(any(feature = "metered168_retry4", feature = "metered170_full"))]
mod retirement_evidence;
#[cfg(feature = "metered168_retry4")]
#[path = "closed168_retry4.rs"]
mod specific;
#[cfg(feature = "metered170_full")]
#[path = "closed170_metered.rs"]
mod specific;

#[cfg(any(
    feature = "independent166",
    feature = "standard170",
    feature = "metered168",
    feature = "metered168_retry4",
    feature = "metered170_full"
))]
use specific::{BASE, CHECK_SCHEMA, COMPLETE_SCHEMA, PROFILE, gates};
#[cfg(not(any(
    feature = "independent166",
    feature = "standard170",
    feature = "metered168",
    feature = "metered168_retry4",
    feature = "metered170_full"
)))]
const PROFILE: &[u8] = include_bytes!("profiles.json");
#[cfg(not(any(
    feature = "independent166",
    feature = "standard170",
    feature = "metered168",
    feature = "metered168_retry4",
    feature = "metered170_full"
)))]
const CHECK_SCHEMA: &str = "horizon167-closed-accounts-check-v1";
#[cfg(not(any(
    feature = "independent166",
    feature = "standard170",
    feature = "metered168",
    feature = "metered168_retry4",
    feature = "metered170_full"
)))]
const COMPLETE_SCHEMA: &str = "horizon167-closed-accounts-complete-v1";

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
#[cfg(not(any(
    feature = "independent166",
    feature = "standard170",
    feature = "metered168",
    feature = "metered168_retry4",
    feature = "metered170_full"
)))]
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
/// Check the two incomplete runs against their original stop, reservation and present owner.
#[cfg(not(any(
    feature = "independent166",
    feature = "standard170",
    feature = "metered168",
    feature = "metered168_retry4",
    feature = "metered170_full"
)))]
fn gates(p: &Value, manifest: &Value) -> Result<Value> {
    let target = Path::new(string(p, "target")?);
    let attempt = string(p, "attempt")?;
    let lane = Path::new("/home/sol/.jetstreamer-private/epoch167-standard-lane-20261109-v1");
    let old_run = lane.join(format!("replacement-{attempt}-20261110-v1"));
    ensure!(
        matches!(attempt, "local3retry5" | "local3retry7")
            && target.starts_with(old_run.join("private"))
            && target.file_name().is_some_and(|n| n == "accounts-state"),
        "unauthorized accounts subtree"
    );
    for k in ["unit", "guard", "timer"] {
        closed(string(p, k)?)?;
    }
    closed("horizon-qualify-167-source-index-v1-20261121.service")?;
    let latest = bound(&manifest["latest_stop"])?;
    ensure!(
        latest["terminal"]["pid"] == 0
            && latest["producer_invocation_id"] == "0876e9944c784b41afeff1b666539ead"
            && latest["scratch_deleted"] == false,
        "different latest stop"
    );
    let admission = bound(&p["admission"])?;
    let guard = bound(&p["protection"])?;
    let plan = bound(&p["plan"])?;
    let stop = bound(&p["stop"])?;
    let intent = bound(&p["intent"])?;
    ensure!(
        admission["schema"] == "horizon-standard-replacement-admission-v1"
            && admission["epoch"] == 167
            && admission["fresh_admission_passed"] == true
            && admission["producer_unit"] == p["unit"]
            && admission["producer_invocation_id"] == p["iid"]
            && guard["admission"] == p["admission"]
            && guard["producer_invocation_id"] == p["iid"]
            && guard["plan"] == p["plan"]
            && plan["unit"] == p["unit"]
            && plan["invocation_id"] == p["iid"]
            && plan["worker_root"] == json!(lane)
            && stop["schema"] == "jetstreamer-horizon-standalone-stop-completion-v1"
            && stop["intent"] == p["intent"]["path"]
            && stop["producer_invocation_id"] == p["iid"]
            && intent["producer_invocation_id"] == p["iid"]
            && stop["plan_sha256"] == p["plan"]["sha256"]
            && intent["plan_sha256"] == stop["plan_sha256"]
            && intent["reason"] == "DATA-fulfillment-observation-failed"
            && stop["terminal"]["pid"] == 0
            && stop["terminal"]["restarts"] == 0
            && stop["terminal"]["active"] == "inactive"
            && stop["scratch_deleted"] == false
            && stop["remote_mutations"] == false,
        "original owner or stop lineage changed"
    );
    let protected = p["preserved"].as_array().context("missing siblings")?;
    ensure!(
        protected.len() == 3,
        "incomplete archive/bootstrap/Bank inventory"
    );
    for v in protected.iter().chain([&p["cohort_file"]]) {
        let path = Path::new(string(v, "path")?);
        ensure!(
            path.starts_with(&old_run) && !path.starts_with(target),
            "retained input overlaps removal"
        );
        preserved(v)?;
    }
    let state = Path::new(string(&p["cohort_file"], "path")?);
    ensure!(state.metadata()?.len() < 16384, "oversize cohort state");
    let bytes = fs::read(state)?;
    let cohort: Value = serde_json::from_slice(&bytes)?;
    ensure!(
        sha(&bytes) == p["cohort_sha256"]
            && cohort["status"] == "running-private"
            && cohort["start_epoch"] == 167
            && cohort["end_epoch"] == 167,
        "changed cohort evidence"
    );
    let runtime = target.parent().context("runtime parent")?;
    let children = |p: &Path| -> Result<Vec<String>> {
        let mut result = Vec::new();
        for entry in fs::read_dir(p)? {
            result.push(
                entry?
                    .file_name()
                    .into_string()
                    .map_err(|_| anyhow::anyhow!("non-UTF8 member"))?,
            );
        }
        result.sort();
        Ok(result)
    };
    ensure!(
        json!(children(runtime)?) == p["runtime_entries"]
            && children(&runtime.join("unpacked/snapshots"))? == ["72143703", "status_cache"]
            && children(&runtime.join("unpacked/snapshots/72143703"))? == ["72143703"],
        "additional retained Bank or runtime present"
    );
    witness_disjoint(target, &manifest["witness"])?;
    Ok(
        json!({"owner":p["iid"],"scope":p["target"],"retained":protected,"stop":p["stop"],"bootstrap_slot":72143703,"witness":manifest["witness"]}),
    )
}
fn witness_disjoint(target: &Path, reference: &Value) -> Result<()> {
    let witness = bound(reference)?;
    let rows = witness["allocation"]["first"]
        .as_array()
        .context("witness schedule")?;
    ensure!(rows.len() == 12, "incomplete native DATA set");
    for v in rows {
        let path = Path::new(string(v, "path")?);
        ensure!(!path.starts_with(target), "DATA member intersects accounts");
        let m = fs::symlink_metadata(path)?;
        ensure!(
            path.canonicalize()? == path
                && v["ino"] == m.ino()
                && v["dev"] == m.dev()
                && v["allocated_blocks512"] == m.blocks()
                && v["ctime"] == m.ctime()
                && v["ctime_nsec"] == m.ctime_nsec(),
            "DATA witness changed"
        );
        for anc in v["ancestors"].as_array().context("witness ancestry")? {
            let path = Path::new(string(anc, "path")?);
            let m = fs::symlink_metadata(path)?;
            ensure!(
                !path.starts_with(target)
                    && m.is_dir()
                    && anc["ino"] == m.ino()
                    && anc["dev"] == m.dev()
                    && (anc["owned_change_times"].is_null()
                        || anc["owned_change_times"]
                            == json!([m.mtime(), m.mtime_nsec(), m.ctime(), m.ctime_nsec()])),
                "DATA ancestor changed"
            );
        }
    }
    Ok(())
}
#[cfg(any(
    feature = "independent166",
    feature = "standard170",
    feature = "metered168",
    feature = "metered168_retry4",
    feature = "metered170_full"
))]
fn appendvec_name(path: &str, directory: bool) -> bool {
    let shard = |s: &str| matches!(s, "0" | "1" | "2" | "3");
    let number = |s: &str| !s.is_empty() && s.bytes().all(|v| v.is_ascii_digit());
    if directory {
        return path.is_empty() || shard(path);
    }
    path.split_once('/').is_some_and(|(s, base)| {
        shard(s)
            && base
                .split_once('.')
                .is_some_and(|(slot, index)| number(slot) && number(index))
    })
}
#[cfg(any(
    feature = "independent166",
    feature = "standard170",
    feature = "metered168",
    feature = "metered168_retry4",
    feature = "metered170_full"
))]
fn check_appendvecs(
    p: &Value,
    ledger: &stopped_tree::Ledger,
    allocated: u64,
    cap: u64,
) -> Result<()> {
    let target = Path::new(string(p, "target")?);
    let mut total = 0u64;
    for (name, entry) in ledger {
        let m = serde_json::to_value(entry)?;
        let directory = m["directory"].as_bool().context("missing entry type")?;
        ensure!(
            appendvec_name(name, directory),
            "foreign account file or directory: {name}"
        );
        if directory {
            let inode = if name.is_empty() {
                &p["inode"]
            } else {
                &p["shards"][name]
            };
            ensure!(m["inode"] == *inode, "changed account shard {name}");
            total += fs::symlink_metadata(target.join(name))?.blocks() * 512;
        } else {
            total += m["blocks"].as_u64().context("missing file allocation")? * 512;
        }
    }
    ensure!(
        ledger.len() > 5
            && ["0", "1", "2", "3"].iter().all(|n| ledger.contains_key(*n))
            && (0..=cap).contains(&allocated)
            && total == allocated,
        "incomplete accounts inventory"
    );
    Ok(())
}

fn scan(target: &Path) -> Result<Value> {
    // A same-device bind inside the target could expose unrelated files with valid uid/gid.
    // Bind aliases of the target can also hide consumers from process pathname matching.
    let home_relative = target.strip_prefix("/home/sol")?;
    let root_in_fs = Path::new("/").join(home_relative);
    let mut seen = std::collections::BTreeSet::new();
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        if !entry
            .file_name()
            .as_encoded_bytes()
            .iter()
            .all(u8::is_ascii_digit)
        {
            continue;
        }
        let proc = entry.path();
        let ns = match fs::metadata(proc.join("ns/mnt")) {
            Ok(m) => (m.dev(), m.ino()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e.into()),
        };
        if seen.contains(&ns) {
            continue;
        }
        let mounts = match fs::read_to_string(proc.join("mountinfo")) {
            Ok(data) => data,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e.into()),
        };
        for line in mounts.lines() {
            let v: Vec<_> = line.split_ascii_whitespace().collect();
            ensure!(v.len() >= 10, "invalid mountinfo");
            let root = Path::new(v[3]);
            let point = Path::new(v[4]);
            ensure!(
                !point.starts_with(target),
                "mount inside target {}",
                point.display()
            );
            if v[2] == "252:0" && root != Path::new("/") {
                let traverses_target =
                    root_in_fs.starts_with(root) || root.starts_with(&root_in_fs);
                let ordinary = point == Path::new("/home/sol").join(root.strip_prefix("/")?);
                ensure!(
                    !traverses_target || ordinary,
                    "consuming bind alias {} {}",
                    root.display(),
                    point.display()
                );
            }
        }
        seen.insert(ns);
    }
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
    let manifest: Value = serde_json::from_slice(PROFILE)?;
    let p = manifest["profiles"]
        .get(attempt)
        .context("unknown attempt")?;
    let epoch_lock = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open("/run/horizon-epoch171-to136-g1.operation.lock")?;
    use std::os::fd::AsRawFd;
    #[cfg(any(feature = "metered168_retry4", feature = "metered170_full"))]
    specific::verify_campaign_lock(&epoch_lock, &manifest)?;
    ensure!(
        unsafe { libc::flock(epoch_lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "campaign operation is occupied"
    );
    #[cfg(any(
        feature = "independent166",
        feature = "standard170",
        feature = "metered168",
        feature = "metered168_retry4",
        feature = "metered170_full"
    ))]
    let _leases = specific::leases(&manifest)?;
    #[cfg(not(any(feature = "metered168_retry4", feature = "metered170_full")))]
    let anchors = gates(p, &manifest)?;
    let target = Path::new(string(p, "target")?);
    let fd = stopped_tree::open_root(target, DEVICE, p["inode"].as_u64().context("target inode")?)?;
    #[cfg(any(feature = "metered168_retry4", feature = "metered170_full"))]
    let anchors = gates(p, &manifest)?;
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
    let elf = base.join("tools/retire");
    let image = sha(&read(&elf, 32 << 20)?);
    ensure!(
        fs::read_link("/proc/self/exe")? == elf && image == sha(&fs::read("/proc/self/exe")?),
        "sealed image required"
    );
    #[cfg(any(feature = "metered168_retry4", feature = "metered170_full"))]
    specific::verify_image(base, &image)?;
    let conf = sha(PROFILE);
    let dir: PathBuf = base.join("state").join(attempt);
    let checkpath = dir.join("CHECK.json");
    let ledgerpath = dir.join("LEDGER.json");
    let process = scan(target)?;
    if mode == "check" {
        let du = Command::new("/usr/bin/du")
            .args(["--summarize", "--one-file-system", "--block-size=1", "--"])
            .arg(target)
            .output()?;
        ensure!(
            du.status.success() && du.stderr.is_empty(),
            "allocation observation failed"
        );
        let allocated = std::str::from_utf8(&du.stdout)?
            .split_whitespace()
            .next()
            .context("missing allocation")?
            .parse::<u64>()?;
        let first = stopped_tree::capture(&fd, DEVICE, UID, GID)?;
        let second = stopped_tree::capture(&fd, DEVICE, UID, GID)?;
        ensure!(
            first == second && first.contains_key(""),
            "old accounts inventory changed"
        );
        #[cfg(not(any(
            feature = "independent166",
            feature = "standard170",
            feature = "metered168",
            feature = "metered168_retry4",
            feature = "metered170_full"
        )))]
        ensure!(
            p["expected_bytes"] == allocated && p["expected_entries"] == (first.len() - 1) as u64,
            "retained allocation or old accounts inventory differs"
        );
        #[cfg(any(
            feature = "independent166",
            feature = "standard170",
            feature = "metered168",
            feature = "metered168_retry4",
            feature = "metered170_full"
        ))]
        specific::check_inventory(p, &manifest, &first, allocated)?;
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
        let process = if cfg!(any(
            feature = "metered168_retry4",
            feature = "metered170_full"
        )) {
            ensure!(gates(p, &manifest)? == anchors, "pre-check anchors changed");
            scan(target)?
        } else {
            process
        };
        let check = json!({"schema":CHECK_SCHEMA,"attempt":attempt,"target":target,"inode":p["inode"],"manifest":conf,"elf":image,"anchors":anchors,"ledger_sha256":hash,"entries":count,"references":process,"resource_credit_bytes":0});
        #[cfg(any(
            feature = "independent166",
            feature = "standard170",
            feature = "metered168",
            feature = "metered168_retry4",
            feature = "metered170_full"
        ))]
        let check = {
            let mut measured = check;
            measured["allocated_bytes"] = json!(allocated);
            measured
        };
        output(&dir, "CHECK.json", &serde_json::to_vec_pretty(&check)?)?;
        println!("{}", check);
        return Ok(());
    }
    let prior = evidence(&checkpath)?;
    let bytes = read(&ledgerpath, 220 << 20)?;
    ensure!(
        prior["schema"] == CHECK_SCHEMA
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
    let intent = json!({"check_sha256":sha(&read(&checkpath,1<<20)?),"scope":target,"inode":p["inode"],"original_iid":p["iid"],"ledger_sha256":prior["ledger_sha256"],"resource_credit_bytes":0});
    let ip = dir.join("INTENT.json");
    let resuming = ip.try_exists()?;
    if resuming {
        ensure!(evidence(&ip)? == intent, "prior intent differs")
    }
    let current = stopped_tree::capture(&fd, DEVICE, UID, GID)?;
    stopped_tree::validate_remaining(&ledger, &current, resuming)?;
    drop(current);
    #[cfg(not(any(feature = "metered168_retry4", feature = "metered170_full")))]
    if !resuming {
        output(&dir, "INTENT.json", &serde_json::to_vec_pretty(&intent)?)?
    }
    #[cfg(any(feature = "metered168_retry4", feature = "metered170_full"))]
    ensure!(
        gates(p, &manifest)? == anchors,
        "pre-execute anchors changed"
    );
    let _ = scan(target)?;
    #[cfg(any(feature = "metered168_retry4", feature = "metered170_full"))]
    if !resuming {
        output(&dir, "INTENT.json", &serde_json::to_vec_pretty(&intent)?)?
    }
    let removed = stopped_tree::remove_contents(&fd, &ledger, DEVICE, UID, GID)?;
    let after = gates(p, &manifest)?;
    ensure!(after == anchors, "post-retirement bindings changed");
    #[cfg(any(
        feature = "independent166",
        feature = "standard170",
        feature = "metered168",
        feature = "metered168_retry4",
        feature = "metered170_full"
    ))]
    let allocated = &prior["allocated_bytes"];
    #[cfg(not(any(
        feature = "independent166",
        feature = "standard170",
        feature = "metered168",
        feature = "metered168_retry4",
        feature = "metered170_full"
    )))]
    let allocated = &p["expected_bytes"];
    let complete = json!({"schema":COMPLETE_SCHEMA,"attempt":attempt,"scope":target,"original_iid":p["iid"],"scope_empty":true,"entries_removed_this_invocation":removed,"check_sha256":intent["check_sha256"],"intent_sha256":sha(&read(&ip,1<<20)?),"retired_tree_before_bytes":allocated,"scope_root_remaining_bytes":fd.metadata()?.blocks()*512,"archive_or_snapshot_removed":false,"resource_credit_bytes":0});
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
