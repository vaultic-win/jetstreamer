//! This binary has one host, collection, local evidence set and shared mutation lock.
//! No command accepts a corpus path or an R2 mutation.
#[allow(dead_code)]
#[path = "../../horizon_cold130_backed_retire_20261110_v4/source/atomic_fs.rs"]
mod atomic_fs;
#[cfg(test)]
mod tests;
mod tree;

use anyhow::{Context, Result, bail, ensure};
use atomic_fs::{AnchoredParent, open_at};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    fs::{self, File, OpenOptions},
    io::Read,
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::Path,
    process::Command,
};
use tree::{Signature, Table, Transaction, allocation, census, signature};
const PARENT: &str = "/home/sol/.jetstreamer-private/epoch141-ledger-retention-20261020-v1";
const LOCK: &str = "/home/sol/.jetstreamer-private/r2-receipts/local-mutation.lock";
const STATE: &str = "/home/sol/.jetstreamer-private/horizon-root-runtime-data/held141-collection-retirement-20261120-v1/state";
const PREFIX: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch172-full-replay-20261120-v1/held141-local-census-v2";
const TABLE: &str = "0a623fd77b45bc4ce501aed595e4a95fb68b34362de364a6a0bca2b293854477";
const CENSUS: &str = "72e4690afd894da77fa72157a641c7a19b08d00af03bc8e664f0b3952c277548";
const COLLECTION: &str = "569df15e8ce87beca8df0a800c85e616aaf252baeb365a7c92f35b8b39b4e937";
const COUNT: usize = 6094;
const LOGICAL: u64 = 539_418_911_425;
const PHYSICAL: u64 = 539_456_057_344;
const DEVICE: u64 = 64512;

fn sha_file(path: &Path) -> Result<String> {
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file() && m.uid() == 0 && m.nlink() == 1 && m.mode() & 0o022 == 0,
        "unsafe proof: {}",
        path.display()
    );
    let mut h = Sha256::new();
    std::io::copy(&mut f, &mut h)?;
    Ok(format!("{:x}", h.finalize()))
}
fn read_checked(path: &Path, expected: &str) -> Result<Vec<u8>> {
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file() && m.uid() == 0 && m.mode() & 0o022 == 0 && m.len() <= 4 * 1024 * 1024,
        "unsafe proof data"
    );
    let mut data = Vec::new();
    f.read_to_end(&mut data)?;
    ensure!(
        format!("{:x}", Sha256::digest(&data)) == expected,
        "wrong proof digest for {}",
        path.display()
    );
    Ok(data)
}
fn local() -> Result<(Table, Signature)> {
    let base = Path::new(PREFIX);
    let rows: Vec<(String, Signature, String)> =
        serde_json::from_slice(&read_checked(&base.join("ALL_MEMBERS.json"), TABLE)?)?;
    let old: Value = serde_json::from_slice(&read_checked(&base.join("COMPLETE.json"), CENSUS)?)?;
    ensure!(
        old["member_table_sha256"] == TABLE
            && old["collection_sha256"] == COLLECTION
            && old["checked_files"] == COUNT
            && old["checked_bytes"] == LOGICAL
            && old["live_member_references"] == json!([]),
        "wrong local census"
    );
    let dir: Signature = serde_json::from_value(old["directory_identity"].clone())?;
    ensure!(
        dir[0] == DEVICE && dir[1] == 105578544,
        "wrong retained inode"
    );
    let mut table = BTreeMap::new();
    let mut seen = BTreeSet::new();
    for (name, sig, sha) in rows {
        ensure!(
            !name.is_empty()
                && name != "."
                && name != ".."
                && !name.contains('/')
                && sig[0] == DEVICE
                && sig[5] == 0
                && sig[6] == 0
                && sig[7] & libc::S_IFMT as u64 == libc::S_IFREG as u64
                && sig[7] & 0o222 == 0
                && sig[8] == 1
                && valid_sha(&sha)
                && seen.insert(sig[1]),
            "invalid census member: {name}"
        );
        ensure!(
            table.insert(name, (sig, sha)).is_none(),
            "duplicate source member"
        );
    }
    ensure!(
        table.len() == COUNT
            && table.values().map(|(sig, _)| sig[2]).sum::<u64>() == LOGICAL
            && allocation(&table)? == PHYSICAL,
        "wrong local corpus"
    );
    Ok((table, dir))
}
fn valid_sha(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn lock() -> Result<File> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(LOCK)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file()
            && m.dev() == DEVICE
            && m.ino() == 101135013
            && m.len() == 0
            && m.nlink() == 1
            && m.uid() == 1001
            && m.gid() == 1003
            && m.mode() & 0o7777 == 0o600,
        "shared lock changed"
    );
    ensure!(
        unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "shared campaign mutation lock occupied"
    );
    Ok(f)
}
fn pinned_parent(path: &Path, kind: &str) -> Result<AnchoredParent> {
    let chains: Value = serde_json::from_str(include_str!("anchor_chains.json"))?;
    AnchoredParent::open(path, &chains[kind])
}
// renameat2 rejects two bind views even when st_dev is identical. Resolve both
// parents through HOME, then verify their kernel mount IDs before authorizing capture.
fn mount_id(f: &File) -> Result<u64> {
    let info = fs::read_to_string(format!("/proc/self/fdinfo/{}", f.as_raw_fd()))?;
    Ok(info
        .lines()
        .find_map(|l| l.strip_prefix("mnt_id:"))
        .context("missing kernel mount id")?
        .trim()
        .parse()?)
}
fn run() -> Result<Value> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "host evidence requires privileged read"
    );
    let args: Vec<_> = env::args_os().skip(1).collect();
    let (table, dir) = local()?;
    let _held = lock()?;
    let parent = pinned_parent(Path::new(PARENT), "source")?;
    let state_path = Path::new(STATE);
    let state = pinned_parent(state_path, "state")?;
    let mount = mount_id(&parent.directory)?;
    ensure!(
        mount_id(&state.directory)? == mount,
        "cross-mount directory rename would fail"
    );
    if args.len() == 1 && args[0] == "--check-local" {
        let file = open_at(
            &parent.directory,
            "retained",
            libc::O_RDONLY | libc::O_DIRECTORY,
        )?;
        ensure!(
            signature(&file.metadata()?)? == dir,
            "retained directory changed"
        );
        census(&file, &table, true)?;
        parent.recheck()?;
        return Ok(
            json!({"mode":"check-local","epoch":141,"members":table.len(),"logical_bytes":LOGICAL,"member_allocated_bytes":PHYSICAL,"directory":dir,"common_kernel_mount_id":mount,"state_directory":atomic_fs::dir_identity(&state.directory.metadata()?),"table_sha256":TABLE,"remote_complete_required_for_retirement":true,"mutation":false}),
        );
    }
    if args.len() != 2 || args[0] != "--retire" {
        bail!("usage: --check-local | --retire ROOT_RELEASE_SHA256");
    }
    let approval = args[1].to_str().context("non-UTF8 approval digest")?;
    ensure!(valid_sha(approval), "invalid root coordination digest");
    let release: Value = serde_json::from_slice(&read_checked(
        &state_path.join("ROOT_RELEASE.json"),
        approval,
    )?)?;
    ensure!(
        release["operation"] == "retire-local-held141-collection"
            && release["owner"] == "/root"
            && release["source"] == format!("{PARENT}/retained")
            && release["member_table_sha256"] == TABLE,
        "wrong owner release"
    );
    ensure!(
        atomic_fs::dir_identity(&state.directory.metadata()?) == release["state_directory"],
        "state directory release mismatch"
    );
    let sm = state.directory.metadata()?;
    ensure!(
        sm.dev() == DEVICE && sm.uid() == 0 && sm.gid() == 0 && sm.mode() & 0o7777 == 0o700,
        "unsafe private state"
    );
    let exe = env::current_exe()?;
    let pkg = exe.parent().context("missing executable directory")?;
    ensure!(
        sha_file(&exe)? == release["binary_sha256"],
        "native image not approved"
    );
    let py = pkg.join("evidence_gate.py");
    let consumers = pkg.join("consumer_gate.py");
    ensure!(
        sha_file(&py)? == release["evidence_gate_sha256"]
            && sha_file(&consumers)? == release["consumer_gate_sha256"],
        "wrong production gates"
    );
    let tx = Transaction {
        parent: &parent,
        state: &state,
        table: &table,
        dir_id: &dir,
        admission: approval,
        table_sha: TABLE,
    };
    let gate = |phase: &str| -> Result<()> {
        let s = Command::new("/usr/bin/python3")
            .arg("-IB")
            .arg(&py)
            .arg(phase)
            .arg(approval)
            .stdin(std::process::Stdio::null())
            .status()?;
        ensure!(
            s.success(),
            "current evidence/consumer gate rejected {phase}"
        );
        Ok(())
    };
    tx.retire(gate)
}
fn main() -> Result<()> {
    println!("{}", run()?);
    Ok(())
}
