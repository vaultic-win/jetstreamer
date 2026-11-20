//! Private payload for the guarded historical epoch-169 replay. The admission controller
//! supplies the sandbox and the verified HOME-backed checkpoint directory before executing this binary.

use anyhow::{Context, Result, ensure};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const LANE: &str = "/home/sol/.jetstreamer-private/epoch169-focused-diagnostic-20261117-v1";
const NODE: &str = "/run/horizon-169-focused-node";
const WORKER: &str = "/run/horizon-169-focused-worker";
const NODE_SHA: &str = "7cd290140ae1097fb8caa573a4afcffd55d4a279dc07fefe6e9299936d39c71e";
const TRACE_SHA: &str = "44f39109586d7e2cabdb03e3b781949d64ed0c2a3591067b382a6eb590f77cf4";
const SNAP: &str = "snapshot-73007829-AgJkU9ZTLnhbCHK54yWFCG4N9sxbtLPRgkCZqwpdWF9R.tar.zst";
const TERMINAL: &str = "snapshot-73245218-5aXCD1ZXBe3fPYtrxvFkDvSvz8x68XiRmWfoEnLVLPif.tar.zst";
const SNAP_SHA: &str = "6e48d311c0f3b5e95f40968d46aac3919d6b7f84f5b63ad0d2a81c0b0ee51ab0";
const GENESIS_SHA: &str = "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945";
const SNAP_BYTES: u64 = 2_109_034_648;
const UNIT: &str = guard169::UNIT;
fn run_dir() -> PathBuf {
    PathBuf::from(guard169::DEST)
}
fn verify_actor() -> Result<String> {
    ensure!(
        unsafe { libc::geteuid() } == 1001 && unsafe { libc::getegid() } == 1003,
        "requires sol:horizon"
    );
    let membership = fs::read_to_string("/proc/self/cgroup")?;
    let cgroup = membership
        .lines()
        .find_map(|s| s.strip_prefix("0::/"))
        .context("missing unified cgroup")?;
    ensure!(
        Path::new(cgroup).file_name().is_some_and(|s| s == UNIT),
        "wrong actor"
    );
    let path = Path::new("/sys/fs/cgroup").join(cgroup);
    for (property, expected) in [
        ("memory.max", "73014444032"),
        ("memory.high", "68719476736"),
        ("memory.swap.max", "0"),
        ("pids.max", "1024"),
    ] {
        ensure!(
            fs::read_to_string(path.join(property))?.trim() == expected,
            "changed {property}"
        );
    }
    let limits = fs::read_to_string(path.join("cpu.max"))?;
    let fields = limits
        .split_whitespace()
        .map(str::parse::<u64>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(
        fields.len() == 2 && fields[1] > 0 && fields[1].checked_mul(3) == Some(fields[0]),
        "changed CPU quota"
    );
    let id = std::env::var("INVOCATION_ID")?;
    ensure!(
        id.len() == 32
            && id.bytes().all(|b| b.is_ascii_hexdigit())
            && id.bytes().any(|b| b != b'0'),
        "invalid invocation"
    );
    Ok(id)
}

fn root_dir(dir: &Path) -> Result<()> {
    let m = fs::symlink_metadata(dir)?;
    ensure!(
        dir.canonicalize()? == dir
            && m.is_dir()
            && m.uid() == 1001
            && m.gid() == 1003
            && m.mode() & 0o7777 == 0o700
            && m.dev() == fs::metadata("/home/sol")?.dev(),
        "unsafe {}",
        dir.display()
    );
    Ok(())
}

fn fresh_file(p: &Path) -> Result<File> {
    Ok(OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(p)?)
}

fn stable_file(path: &Path) -> Result<File> {
    ensure!(path.canonicalize()? == path, "noncanonical input");
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file() && m.nlink() == 1 && m.mode() & 0o022 == 0,
        "unsafe input {}",
        path.display()
    );
    Ok(f)
}

fn identity(f: &File) -> Result<(u64, u64, u64, i64, i64, i64, i64)> {
    let m = f.metadata()?;
    Ok((
        m.dev(),
        m.ino(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    ))
}

fn transfer(src: &Path, len: u64, expected: &str, mut dst: Option<&mut File>) -> Result<()> {
    let mut file = stable_file(src)?;
    let before = identity(&file)?;
    ensure!(before.2 == len, "input size {}", src.display());
    let mut h = Sha256::new();
    let mut count = 0u64;
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        count = count.checked_add(n as u64).context("input length")?;
        ensure!(count <= len, "oversize input");
        h.update(&buf[..n]);
        if let Some(out) = dst.as_deref_mut() {
            out.write_all(&buf[..n])?;
        }
    }
    ensure!(
        count == len
            && format!("{:x}", h.finalize()) == expected
            && before == identity(&file)?
            && before == identity(&stable_file(src)?)?,
        "input binding {}",
        src.display()
    );
    if let Some(out) = dst {
        out.set_permissions(fs::Permissions::from_mode(0o400))?;
        out.sync_all()?;
    }
    Ok(())
}

fn text_file(path: &Path, contents: &[u8]) -> Result<()> {
    let mut f = fresh_file(path)?;
    f.write_all(contents)?;
    f.set_permissions(fs::Permissions::from_mode(0o400))?;
    f.sync_all()?;
    Ok(())
}

fn stage_and_exec() -> Result<()> {
    let iid = verify_actor()?;
    let lane = Path::new(LANE);
    let dir = run_dir();

    root_dir(lane)?;

    root_dir(&dir)?;
    // The controller binds a fresh subtree and redirects stdout/stderr to its producer.log.
    let entries = fs::read_dir(&dir)?
        .map(|e| e.map(|e| e.file_name()))
        .collect::<io::Result<Vec<_>>>()?;
    ensure!(
        entries.len() == 2
            && entries.iter().any(|n| n == "producer.log")
            && entries.iter().any(|n| n == "epoch-hashes-169-focused.txt"),
        "requires only the original checkpoint and empty producer log"
    );
    let log = stable_file(&dir.join("producer.log"))?;
    ensure!(log.metadata()?.len() == 0, "producer log already populated");
    for fd in ["1", "2"] {
        let md = fs::metadata(Path::new("/proc/self/fd").join(fd))?;
        ensure!(
            (md.dev(), md.ino()) == (log.metadata()?.dev(), log.metadata()?.ino()),
            "private log binding"
        );
    }
    let node = Path::new(NODE);
    let worker = Path::new(WORKER);

    transfer(node, 65_267_392, NODE_SHA, None)?;
    // Both executable aliases must resolve to the exact sealed diagnostic artifacts.
    transfer(worker, 8_686_656, TRACE_SHA, None)?;

    let ledger = &dir;
    let scratch = dir.join("scratch");
    let tmp = dir.join("tmp");
    for p in [&scratch, &tmp] {
        fs::DirBuilder::new().mode(0o700).create(p)?;
    }
    let snap = dir.join(SNAP);
    transfer(
        Path::new("/run/horizon-169-incident-snapshot"),
        SNAP_BYTES,
        SNAP_SHA,
        Some(&mut fresh_file(&snap)?),
    )?;
    transfer(
        Path::new("/run/horizon-169-genesis"),
        20_144,
        GENESIS_SHA,
        Some(&mut fresh_file(&ledger.join("genesis.tar.bz2"))?),
    )?;
    let checkpoints = dir.join("epoch-hashes-169-focused.txt");
    ensure!(
        fs::read(&checkpoints)? == format!("{SNAP}\n{TERMINAL}\n").as_bytes(),
        "canonical checkpoints changed"
    );
    let receipt = json!({"schema":"epoch169-private-trace-inputs-v1","invocation_id":iid,"node_sha256":NODE_SHA,"worker_sha256":TRACE_SHA,"bootstrap_sha256":SNAP_SHA,"bootstrap_bytes":SNAP_BYTES,"target_slot":73239086,"target_entry":164,"target_transaction":205,"terminal_checkpoint":73245218,"bootstrap_generation":"1634787450103391","checkpoint_generation":"1634787429412044","publication_authorized":false});
    text_file(
        &dir.join("inputs.json"),
        &serde_json::to_vec_pretty(&receipt)?,
    )?;
    File::open(ledger)?.sync_all()?;
    File::open(&dir)?.sync_all()?;
    let mut cmd = Command::new(node);
    cmd.env_clear();
    let env = [
        ("HOME", "/home/sol"),
        ("LANG", "C"),
        ("PATH", "/usr/bin:/bin"),
        ("SOLANA_RAYON_THREADS", "3"),
        ("RAYON_NUM_THREADS", "3"),
        ("JETSTREAMER_HISTORICAL_POH_THREADS", "3"),
        ("JETSTREAMER_HISTORICAL_REAP_TIMEOUT_SECS", "600"),
        ("JETSTREAMER_ALLOW_CANDIDATE_RUNTIME", "1"),
        ("JETSTREAMER_ARCHIVE_BACKEND", "http"),
        (
            "JETSTREAMER_HTTP_BASE_URL",
            "https://files.old-faithful.net/",
        ),
        (
            "JETSTREAMER_COMPACT_INDEX_BASE_URL",
            "https://files.old-faithful.net/",
        ),
        ("JETSTREAMER_NETWORK_CAPACITY_MB", "1024"),
        ("JETSTREAMER_THREADS", "12"),
        ("JETSTREAMER_RIPGET_THREADS", "12"),
        ("JETSTREAMER_VERIFY_SNAPSHOTS", "1"),
        ("JETSTREAMER_SKIP_SNAPSHOT_VERIFY", "0"),
        ("JETSTREAMER_LOAD_FROM_DIR", "0"),
        ("JETSTREAMER_ENFORCE_ARCHIVE_HASH", "1"),
        ("JETSTREAMER_PRUNE_EPOCH_SNAPSHOTS", "0"),
        (
            "RUST_LOG",
            "info,solana_metrics=off,solana_runtime::bank=warn,solana_runtime::accounts_db=warn",
        ),
    ];
    cmd.envs(env)
        .env("JETSTREAMER_HISTORICAL_WORKER_V1_5_8", worker)
        .env("JETSTREAMER_PRIVATE_RUN_ROOT", dir.join("private"))
        .env("TMPDIR", tmp)
        .env("INVOCATION_ID", iid)
        .current_dir(&dir)
        .arg("169")
        .arg(ledger)
        .arg("--verify")
        .arg(format!("--epoch-hashes={}", checkpoints.display()))
        .arg(format!("--snapshot-archive={}", snap.display()))
        .arg(format!(
            "--horizon-output={}",
            dir.join("epoch-169-through-73245218.jet").display()
        ))
        .arg(format!("--replay-scratch={}", scratch.display()))
        .arg("--qualification-end-slot=73245218");
    Err(cmd.exec().into())
}

fn main() -> Result<()> {
    ensure!(
        std::env::args().skip(1).collect::<Vec<_>>() == ["run"],
        "expected run"
    );
    stage_and_exec()
}
