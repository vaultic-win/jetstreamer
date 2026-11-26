//! Source, capacity and native guard checks for epoch 186.
mod guard;
mod price;
mod source;
mod tail_index;
mod tail_source;

use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, Metadata, OpenOptions},
    io::{self, Read},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

const EPOCH: u64 = 186;
const FIRST_SLOT: u64 = 80_352_000;
const END_SLOT: u64 = 80_783_539;
const LAST_EPOCH_SLOT: u64 = 80_783_999;
const UNIT: &str = "horizon-qualify-186-bounded-source-20261125-v1.service";
const GUARD_UNIT: &str = "horizon-guard-186-bounded-source-20261125-v1.service";
const TIMER: &str = "horizon-guard-186-bounded-source-20261125-v1.timer";
const ROOT: &str = "/home/sol/.jetstreamer-private/epoch186-bounded-source-20261125-v1";
const STATE: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch186-bounded-source-20261125-v1";
const TREE_CAP: u64 = 128 << 30;
const TREE_BOOKING: u64 = 138 << 30;
const MEMORY: u64 = 96 << 30;
const GUARD_MEMORY: u64 = 1 << 30;
const CPU: u64 = 8_000_000;
const GUARD_CPU: u64 = 1_000_000;
const TASKS: u64 = 512;
const VMAS: u64 = 3_500_000;
const RUNTIME_SECS: u64 = 3_780;

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value[key]
        .as_str()
        .with_context(|| format!("missing string {key}"))
}

fn number(value: &Value, key: &str) -> Result<u64> {
    value[key]
        .as_u64()
        .with_context(|| format!("missing integer {key}"))
}

fn binding(path: impl AsRef<Path>, sha256: &str) -> Value {
    json!({"path": path.as_ref(), "sha256": sha256})
}

fn lower_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes * 2
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

fn iid(value: &str) -> bool {
    lower_hex(value, 16) && value.bytes().any(|c| c != b'0')
}

fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn fresh(value: &Value, key: &str, now: u64, maximum_age: u64) -> Result<()> {
    ensure!(
        now.checked_sub(number(value, key)?)
            .is_some_and(|age| age <= maximum_age),
        "stale or future {key}"
    );
    Ok(())
}

fn open_root_file(path: &Path, mode: u32) -> Result<(File, Metadata)> {
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "indirect root-bound file {}",
        path.display()
    );
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let m = file.metadata()?;
    ensure!(
        m.is_file() && m.uid() == 0 && m.gid() == 0 && m.nlink() == 1 && m.mode() & 0o7777 == mode,
        "unsafe root-bound file {}",
        path.display()
    );
    stable(path, &file, &m)?;
    Ok((file, m))
}

fn stamp(m: &Metadata) -> (u64, u64, u64, u32, u32, u32, u64, i64, i64, i64, i64) {
    (
        m.dev(),
        m.ino(),
        m.len(),
        m.uid(),
        m.gid(),
        m.mode(),
        m.nlink(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}

fn stable(path: &Path, file: &File, before: &Metadata) -> Result<()> {
    ensure!(
        stamp(before) == stamp(&file.metadata()?)
            && stamp(before) == stamp(&fs::symlink_metadata(path)?),
        "root-bound file changed {}",
        path.display()
    );
    Ok(())
}

fn document(path: &Path, sha: &str, mode: u32) -> Result<Value> {
    let (mut file, m) = open_root_file(path, mode)?;
    const MAX_JSON: u64 = 64 << 20;
    ensure!(m.len() <= MAX_JSON, "oversized receipt {}", path.display());
    let mut contents = Vec::new();
    (&mut file).take(MAX_JSON + 1).read_to_end(&mut contents)?;
    stable(path, &file, &m)?;
    ensure!(
        lower_hex(sha, 32) && format!("{:x}", Sha256::digest(&contents)) == sha,
        "receipt digest changed {}",
        path.display()
    );
    serde_json::from_slice(&contents).with_context(|| format!("parsing {}", path.display()))
}

fn hash(file: &mut File) -> Result<String> {
    let mut digest = Sha256::new();
    io::copy(file, &mut digest)?;
    Ok(format!("{:x}", digest.finalize()))
}

fn verify_file(path: &Path, sha: &str, bytes: u64, mode: u32) -> Result<()> {
    let (mut file, m) = open_root_file(path, mode)?;
    ensure!(
        m.len() == bytes && hash(&mut file)? == sha,
        "input changed {}",
        path.display()
    );
    stable(path, &file, &m)
}

fn seal(path: &Path, sha: &str) -> Result<Value> {
    let value = document(&path.join("deployment-seal-receipt.json"), sha, 0o444)?;
    ensure!(
        value["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && value["destination"] == json!(path)
            && value["replay_launch_authorized"] == false,
        "different deployment seal {}",
        path.display()
    );
    Ok(value)
}

fn seal_member(seal: &Value, name: &str, sha: &str, bytes: u64, mode: &str) -> Result<()> {
    let mut rows = seal["members"]
        .as_array()
        .context("missing seal members")?
        .iter()
        .filter(|row| row["name"] == name);
    let row = rows.next().context("missing expected seal member")?;
    ensure!(
        rows.next().is_none()
            && row["sha256"] == sha
            && row["bytes"] == bytes
            && row["mode"] == mode,
        "changed sealed member {name}"
    );
    Ok(())
}

fn run() -> Result<Value> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [mode] if mode == "source" => source::inspect(false),
        [mode] if mode == "rehash-source" => source::inspect(true),
        [mode] if mode == "tail-source" => tail_source::inspect(),
        [mode, fleet, sha] if mode == "quote" => price::inspect(Path::new(fleet), sha),
        [mode, index, report, output] if mode == "repair-tail-index" => {
            tail_index::repair(Path::new(index), Path::new(report), Path::new(output))
        }
        [mode] if mode == "static-guard-plan" => Ok(guard::plan(
            "0123456789abcdef0123456789abcdef",
            price::PUBLICATION_COPY + TREE_BOOKING,
        )?),
        [mode, stage, plan, plan_sha, sample, sample_sha, quote_sha] if mode == "check-guard" => {
            guard::inspect(
                stage,
                Path::new(plan),
                plan_sha,
                Path::new(sample),
                sample_sha,
                quote_sha,
            )
        }
        _ => bail!(
            "usage: horizon-epoch186-bounded-entry source | rehash-source | tail-source | quote FLEET SHA256 | repair-tail-index INDEX NATIVE_REPORT OUTPUT | static-guard-plan | check-guard held|adopted PLAN PLAN_SHA256 SAMPLE SAMPLE_SHA256 QUOTE_SHA256"
        ),
    }
}

fn main() -> Result<()> {
    println!("{}", serde_json::to_string_pretty(&run()?)?);
    Ok(())
}
