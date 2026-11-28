//! Retire a stopped v1.5.6 worker's private account storage while a sibling replays.
#[path = "../horizon_retry4_170_scratch_retire_20261118_v1/src/process_references.rs"]
mod process_references;
#[path = "../horizon_retry4_170_scratch_retire_20261118_v1/src/stopped_tree.rs"]
mod stopped_tree;

use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::Command,
};

const BASE: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/standard166-old8-accounts-20261121-v1";
const ORIGINAL: &str = "4f09db5f45074244a45b06aeef932d1d";
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
fn scan(target: &Path) -> Result<Value> {
    let v = process_references::scan(Path::new("/proc"), target)?;
    ensure!(
        v.references.is_empty(),
        "live tree reference: {:?}",
        v.references
    );
    Ok(serde_json::to_value(v)?)
}
fn native_gates(witness: &Path) -> Result<Value> {
    let output = Command::new("/usr/bin/python3")
        .arg("-IB")
        .arg(witness)
        .output()?;
    ensure!(
        output.status.success(),
        "ownership gates: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(serde_json::from_slice(&output.stdout)?)
}

fn only_appendvecs(ledger: &stopped_tree::Ledger) -> bool {
    let shard = |v: &str| matches!(v, "0" | "1" | "2" | "3");
    let number = |v: &str| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit());
    ["0", "1", "2", "3"].iter().all(|k| ledger.contains_key(*k))
        && ledger.iter().all(|(key, entry)| {
            let directory = serde_json::to_value(entry)
                .ok()
                .and_then(|e| e["directory"].as_bool());
            if shard(key) {
                return directory == Some(true);
            }
            directory == Some(false)
                && key.split_once('/').is_some_and(|(dir, name)| {
                    shard(dir)
                        && name
                            .split_once('.')
                            .is_some_and(|(slot, index)| number(slot) && number(index))
                })
        })
}

fn run() -> Result<()> {
    let argv: Vec<_> = std::env::args().collect();
    ensure!(
        argv.len() == 3,
        "retire (inspect|check|execute) local3retryN"
    );
    let (mode, attempt) = (argv[1].as_str(), argv[2].as_str());
    ensure!(attempt == "local3retry8", "foreign closed generation");
    let witness = Path::new(BASE).join("tools/gates.py");
    let contents = read(&witness, 1 << 20)?;
    ensure!(
        contents == include_bytes!("gates.py"),
        "unsealed gate module"
    );
    ensure!(
        matches!(mode, "inspect" | "check" | "execute") && unsafe { libc::geteuid() } == 0,
        "invalid mode/owner"
    );
    let anchors = native_gates(&witness)?;
    let p = &anchors["scope"];
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

    let elf = base.join("tools/retire");
    let image = sha(&read(&elf, 32 << 20)?);
    ensure!(
        fs::read_link("/proc/self/exe")? == elf && image == sha(&fs::read("/proc/self/exe")?),
        "sealed image required"
    );
    let conf = sha(&contents);
    let dir: PathBuf = base.join("state");
    let checkpath = dir.join("CHECK.json");
    let ledgerpath = dir.join("LEDGER.json");
    let process = scan(target)?;
    if mode == "check" {
        let allocation = Command::new("/usr/bin/du")
            .args(["--summarize", "--one-file-system", "--block-size=1", "--"])
            .arg(target)
            .output()?;
        ensure!(
            allocation.status.success() && allocation.stderr.is_empty(),
            "account allocation walk failed"
        );
        let raw = std::str::from_utf8(&allocation.stdout)?.trim_end();
        let (bytes, path) = raw.split_once('\t').context("malformed allocation")?;
        ensure!(
            Path::new(path) == target
                && Some(bytes.parse::<u64>()?) == p["expected_bytes"].as_u64(),
            "stopped allocation changed"
        );
        let first = stopped_tree::capture(&fd, DEVICE, UID, GID)?;
        let second = stopped_tree::capture(&fd, DEVICE, UID, GID)?;
        ensure!(
            first == second && first.len() == 398_554 && only_appendvecs(&first),
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
        let check = json!({"schema":"horizon-standard166-closed-accounts-check-v1","attempt":attempt,"target":target,"inode":p["inode"],"manifest":conf,"elf":image,"anchors":anchors,"ledger_sha256":hash,"entries":count,"references":process,"resource_credit_bytes":0});
        output(&dir, "CHECK.json", &serde_json::to_vec_pretty(&check)?)?;
        println!("{}", check);
        return Ok(());
    }
    let prior = evidence(&checkpath)?;
    let bytes = read(&ledgerpath, 220 << 20)?;
    ensure!(
        prior["schema"] == "horizon-standard166-closed-accounts-check-v1"
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
    let after = native_gates(&witness)?;
    ensure!(after == anchors, "post-retirement bindings changed");
    let complete = json!({"schema":"horizon-standard166-closed-accounts-complete-v1","attempt":attempt,"scope":target,"original_iid":ORIGINAL,"scope_empty":true,"entries_removed_this_invocation":removed,"check_sha256":intent["check_sha256"],"intent_sha256":sha(&read(&ip,1<<20)?),"retired_tree_before_bytes":p["expected_bytes"],"scope_root_remaining_bytes":fd.metadata()?.blocks()*512,"archive_or_snapshot_removed":false,"resource_credit_bytes":0});
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

#[cfg(test)]
mod appendvec_tests {
    use super::*;

    #[test]
    fn only_four_directories_and_regular_numeric_appendvecs() {
        let temp = tempfile::tempdir().unwrap();
        for n in ["0", "1", "2", "3"] {
            fs::create_dir(temp.path().join(n)).unwrap();
        }
        let root = File::open(temp.path()).unwrap();
        let m = root.metadata().unwrap();
        let accepts =
            || only_appendvecs(&stopped_tree::capture(&root, m.dev(), m.uid(), m.gid()).unwrap());
        fs::write(temp.path().join("1/71500000.412"), b"appendvec").unwrap();
        assert!(accepts());
        fs::create_dir(temp.path().join("2/71501000.508")).unwrap();
        assert!(!accepts());
        fs::remove_dir(temp.path().join("2/71501000.508")).unwrap();
        fs::write(temp.path().join("2/bank"), b"retain").unwrap();
        assert!(!accepts());
        fs::remove_file(temp.path().join("2/bank")).unwrap();
        fs::remove_dir(temp.path().join("3")).unwrap();
        fs::write(temp.path().join("3"), b"regular").unwrap();
        assert!(!accepts());
    }
}
