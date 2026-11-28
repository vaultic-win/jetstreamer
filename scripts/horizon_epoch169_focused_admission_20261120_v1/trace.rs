//! Private payload for the guarded historical epoch-169 replay. The admission controller
//! supplies the sandbox and the verified HOME-backed checkpoint directory before executing this binary.

use anyhow::{Context, Result, ensure};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
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

fn verify_file(src: &Path, len: u64, expected: &str) -> Result<()> {
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
    }
    ensure!(
        count == len
            && format!("{:x}", h.finalize()) == expected
            && before == identity(&file)?
            && before == identity(&stable_file(src)?)?,
        "input binding {}",
        src.display()
    );
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
    let attempt = Path::new(guard169::ATTEMPT);
    root_dir(attempt)?;
    ensure!(
        attempt.parent() == Some(lane) && dir.parent() == Some(lane) && !attempt.starts_with(&dir),
        "private receipts must be a sibling of destination"
    );
    ensure!(
        fs::read_dir(attempt)?.count() == 1,
        "attempt directory already populated"
    );
    let log = stable_file(&attempt.join("producer.log"))?;
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

    verify_file(node, 65_267_392, NODE_SHA)?;
    // Both executable aliases must resolve to the exact sealed diagnostic artifacts.
    verify_file(worker, 8_686_656, TRACE_SHA)?;

    let scratch = dir.join("scratch");
    root_dir(&scratch)?;
    guard169::cache::scratch(&scratch)?;
    guard169::cache::projected(Path::new(guard169::cache::DESTINATION))?;
    for sub in ["private", "tmp"] {
        fs::DirBuilder::new()
            .mode(0o700)
            .create(attempt.join(sub))?;
    }
    let snap = dir.join(SNAP);
    verify_file(&snap, SNAP_BYTES, SNAP_SHA)?;
    verify_file(&dir.join("genesis.tar.bz2"), 20_144, GENESIS_SHA)?;
    let checkpoints = dir.join("epoch-hashes-169-focused.txt");
    ensure!(
        fs::read(&checkpoints)? == format!("{SNAP}\n{TERMINAL}\n").as_bytes(),
        "canonical checkpoints changed"
    );
    let receipt = json!({"schema":"epoch169-private-trace-inputs-v1","invocation_id":iid,"node_sha256":NODE_SHA,"worker_sha256":TRACE_SHA,"bootstrap_sha256":SNAP_SHA,"bootstrap_bytes":SNAP_BYTES,"target_slot":73239086,"target_entry":164,"target_transaction":205,"terminal_checkpoint":73245218,"bootstrap_generation":"1634787450103391","checkpoint_generation":"1634787429412044","private_run_root":attempt.join("private"),"reused_staging":true,"publication_authorized":false});
    text_file(
        &attempt.join("inputs.json"),
        &serde_json::to_vec_pretty(&receipt)?,
    )?;
    File::open(attempt)?.sync_all()?;
    Err(node_command(&iid).exec().into())
}

fn node_command(iid: &str) -> Command {
    let dir = run_dir();
    let scratch = dir.join("scratch");
    let checkpoints = dir.join("epoch-hashes-169-focused.txt");
    let snap = dir.join(SNAP);
    let attempt = Path::new(guard169::ATTEMPT);
    let mut cmd = Command::new(NODE);
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
        .env("JETSTREAMER_HISTORICAL_WORKER_V1_5_8", WORKER)
        .env("JETSTREAMER_PRIVATE_RUN_ROOT", attempt.join("private"))
        .env("TMPDIR", attempt.join("tmp"))
        .env("INVOCATION_ID", iid)
        .current_dir(&dir)
        .arg("169")
        .arg(&dir)
        .arg("--verify")
        .arg(format!("--epoch-hashes={}", checkpoints.display()))
        .arg(format!("--snapshot-archive={}", snap.display()))
        .arg(format!(
            "--horizon-output={}",
            dir.join("epoch-169-through-73245218.jet").display()
        ))
        .arg(format!("--replay-scratch={}", scratch.display()))
        .arg("--qualification-end-slot=73245218");
    cmd
}

fn main() -> Result<()> {
    ensure!(
        std::env::args().skip(1).collect::<Vec<_>>() == ["run"],
        "expected run"
    );
    stage_and_exec()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn real_node_contract_keeps_receipts_outside_destination() {
        let command = node_command("0123456789abcdef0123456789abcdef");
        let env = command
            .get_envs()
            .collect::<std::collections::BTreeMap<_, _>>();
        let root = Path::new(env[std::ffi::OsStr::new("JETSTREAMER_PRIVATE_RUN_ROOT")].unwrap());
        let dest = run_dir();
        assert!(root.starts_with(LANE) && !root.starts_with(&dest));
        assert_eq!(
            env[std::ffi::OsStr::new("JETSTREAMER_HISTORICAL_WORKER_V1_5_8")],
            Some(std::ffi::OsStr::new(WORKER))
        );
        assert_eq!(
            command
                .get_args()
                .map(|s| s.to_str().unwrap())
                .collect::<Vec<_>>(),
            vec![
                "169".to_owned(),
                dest.display().to_string(),
                "--verify".into(),
                format!(
                    "--epoch-hashes={}/epoch-hashes-169-focused.txt",
                    dest.display()
                ),
                format!("--snapshot-archive={}/{}", dest.display(), SNAP),
                format!(
                    "--horizon-output={}/epoch-169-through-73245218.jet",
                    dest.display()
                ),
                format!("--replay-scratch={}/scratch", dest.display()),
                "--qualification-end-slot=73245218".into()
            ]
        );
    }

    #[test]
    #[ignore = "requires disposable mount and network namespaces and intentionally absent worker"]
    fn native_node_path_control() {
        let dir = run_dir();
        let attempt = Path::new(guard169::ATTEMPT);
        // This test refuses the real mounted campaign tree, real snapshot and any worker.
        assert_eq!(
            fs::read(attempt.join("OFFLINE_FIXTURE")).unwrap(),
            b"native-node-path-fixture"
        );
        assert_ne!(dir.metadata().unwrap().ino(), 111744588);
        let mode = std::env::var("FIXTURE_RECEIPTS").unwrap();
        assert_eq!(dir.join(SNAP).exists(), mode == "preworker");
        assert!(!Path::new(WORKER).exists());
        let enclosed = mode == "enclosed";
        let mut cmd = node_command("0123456789abcdef0123456789abcdef");
        if enclosed {
            cmd.env("JETSTREAMER_PRIVATE_RUN_ROOT", dir.join("private"));
        }
        let output = cmd.output().unwrap();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        println!("{text}");
        assert!(!output.status.success());
        assert!(text.contains("acquired 1 epoch publication lease"));
        if enclosed {
            assert!(
                text.contains(
                    "archive batch receipts must not be stored in the public destination"
                )
            );
        } else {
            assert!(
                text.contains("epoch 169: selected execution profile") && text.contains("snapshot"),
                "{text}"
            );
            assert!(!text.contains("archive batch state remains closed"));
            if mode == "preworker" {
                assert!(
                    text.contains(
                        "starting isolated solana-v1.5.8 worker /run/horizon-169-focused-worker"
                    ) && text.contains("historical worker startup failed")
                        && text.contains("No such file or directory"),
                    "{text}"
                );
                assert!(!text.contains("historical worker initialized at slot"));
            } else {
                assert!(text.contains("failed to read snapshot"));
            }
        }
        assert!(!dir.join("epoch-169-through-73245218.jet").exists());
    }
}
