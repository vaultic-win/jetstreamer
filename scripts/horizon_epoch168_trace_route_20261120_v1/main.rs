//! Private payload for the guarded historical epoch-168 trace. The admission controller
//! supplies the sandbox and an empty HOME-backed run root before executing this binary.
mod inventory;

use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const LANE: &str = "/home/sol/.jetstreamer-private/epoch168-standard-lane-20261109-v1";
const RUN_PARENT: &str = "replacement-local1-20261110-v1";
const RUN: &str = "trace-local3-20261120-v1";
const PKG: &str = "/usr/local/lib/jetstreamer/horizon-independent168-singleton-package-20261109-v1";
const UNIT: &str = "horizon-qualify-168-trace-local3-20261120-v1.service";
const WORKER: &str = "jetstreamer-historical-worker-v1-5-6";
const TRACE_SHA: &str = "97f6bd75e7d9a7ec44931172d2e7ce8e585ecd4434372c57b2dce44a770bfda6";
const NODE_SHA: &str = "a09b8e5aa9426beaf42e6b5f2a469a5a147436bab8b7bf79f268758b60aa2e65";
const MANIFEST_SHA: &str = "27b7a803c39d7cf42407e46bc9fe5033761f471f668545460a1bcbde007ee196";
const SNAP: &str = "snapshot-72575704-Grdro3ninCQfmShQL6ypGv2y1gUzhPPB7xbj9M4UHJnx.tar.zst";
const TERMINAL: &str = "snapshot-73007829-AgJkU9ZTLnhbCHK54yWFCG4N9sxbtLPRgkCZqwpdWF9R.tar.zst";
const SNAP_DIR: &str = "private/destination-38f108e9d00d485f8ed68d9e7caaeb0a1570f35891271acc1ddc6e75b942e5ad/work/root-cohort-168-168/run-14201-1794247152158421923/inputs";
const SNAP_SHA: &str = "f1a8902dcb00eb59266a2f688d05f7d406af1999eb78956bfd0c46056571ad04";
const GENESIS_SHA: &str = "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945";
const SIGNATURE: &str =
    "3qysw2HZ4pE11jjL3HpXA9UJ6kxqPkY2se93agYERfzDNoweP6sxqvhPGPjBkmwmD2m9SrRB96y75Vbi3mACtrpz";
const SNAP_BYTES: u64 = 2_029_219_745;

fn run_dir() -> PathBuf {
    Path::new(LANE).join(RUN_PARENT).join(RUN)
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
        fields.len() == 2 && fields[1] > 0 && fields[1].checked_mul(9) == Some(fields[0]),
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
    if expected == SNAP_SHA {
        ensure!(
            (before.0, before.1) == (64512, 104141334),
            "bootstrap identity changed"
        );
    }
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

fn manifest_terms(data: &Value) -> Result<()> {
    let epochs = data["manifest"]["epochs"].as_array().context("epochs")?;
    ensure!(
        epochs.len() == 1 && epochs[0]["epoch"] == 168 && epochs[0]["runtime"] == "solana-v1.5.6",
        "wrong route"
    );
    let roots = epochs[0]["post_bootstrap_root_checkpoints"]
        .as_array()
        .context("checkpoints")?;
    ensure!(roots.len() == 1, "wrong checkpoint count");
    for (entry, slot, generation, name) in [
        (
            &epochs[0]["bootstrap"],
            72_575_704u64,
            1_634_787_413_893_700u64,
            SNAP,
        ),
        (&roots[0], 73_007_829, 1_634_787_450_103_391, TERMINAL),
    ] {
        ensure!(
            entry["slot"] == slot
                && entry["generation"] == generation
                && entry["uri"] == format!("gs://mainnet-beta-ledger-us-ny5/{slot}/{name}"),
            "canonical checkpoint changed"
        );
    }
    Ok(())
}

fn stage_and_exec() -> Result<()> {
    let iid = verify_actor()?;
    let lane = Path::new(LANE);
    let dir = run_dir();
    let package = Path::new(PKG);
    root_dir(lane)?;
    root_dir(&lane.join(RUN_PARENT))?;
    root_dir(&dir)?;
    // The controller binds a fresh subtree and redirects stdout/stderr to its producer.log.
    let entries = fs::read_dir(&dir)?
        .map(|e| e.map(|e| e.file_name()))
        .collect::<io::Result<Vec<_>>>()?;
    ensure!(
        entries.len() == 1 && entries[0] == "producer.log",
        "requires a fresh log-only directory"
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
    let node = package.join("jetstreamer-node");
    let worker = package.join(WORKER);
    let manifest = package.join("preflight-168-v4.json");
    transfer(&node, 47_753_136, NODE_SHA, None)?;
    // The service has a read-only file bind of the sealed trace worker onto its original
    // worker pathname. The unmodified production worker fails this hash check.
    transfer(&worker, 9_370_256, TRACE_SHA, None)?;
    transfer(&manifest, 11_742, MANIFEST_SHA, None)?;
    manifest_terms(&serde_json::from_reader(stable_file(&manifest)?)?)?;
    let ledger = dir.join("ledger");
    let scratch = dir.join("scratch");
    let tmp = dir.join("tmp");
    for p in [&ledger, &scratch, &tmp] {
        fs::DirBuilder::new().mode(0o700).create(p)?;
    }
    let snap = dir.join(SNAP);
    transfer(
        &lane.join(SNAP_DIR).join(SNAP),
        SNAP_BYTES,
        SNAP_SHA,
        Some(&mut fresh_file(&snap)?),
    )?;
    transfer(
        &lane.join("output/genesis.tar.bz2"),
        20_144,
        GENESIS_SHA,
        Some(&mut fresh_file(&ledger.join("genesis.tar.bz2"))?),
    )?;
    let checkpoints = dir.join("canonical-hashes.txt");
    text_file(&checkpoints, format!("{SNAP}\n{TERMINAL}\n").as_bytes())?;
    let receipt = json!({"schema":"epoch168-private-trace-inputs-v1","invocation_id":iid,"node_sha256":NODE_SHA,"worker_sha256":TRACE_SHA,"bootstrap_sha256":SNAP_SHA,"bootstrap_bytes":SNAP_BYTES,"target_slot":72728191,"target_entry":433,"target_transaction":532,"target_signature":SIGNATURE,"terminal_checkpoint":73007829,"account_state_verified":false,"publication_authorized":false});
    text_file(
        &dir.join("inputs.json"),
        &serde_json::to_vec_pretty(&receipt)?,
    )?;
    File::open(&ledger)?.sync_all()?;
    File::open(&dir)?.sync_all()?;
    let mut cmd = Command::new(&node);
    cmd.env_clear();
    let env = [
        ("HOME", "/home/sol"),
        ("LANG", "C"),
        ("PATH", "/usr/bin:/bin"),
        ("SOLANA_RAYON_THREADS", "32"),
        ("RAYON_NUM_THREADS", "10"),
        ("JETSTREAMER_HISTORICAL_POH_THREADS", "10"),
        ("JETSTREAMER_HISTORICAL_REAP_TIMEOUT_SECS", "600"),
        ("JETSTREAMER_ALLOW_CANDIDATE_RUNTIME", "1"),
        ("JETSTREAMER_HISTORICAL_TRACE_EPOCH168", "1"),
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
        .env("JETSTREAMER_HISTORICAL_WORKER_V1_5_6", worker)
        .env("JETSTREAMER_PRIVATE_RUN_ROOT", dir.join("private"))
        .env("TMPDIR", tmp)
        .env("INVOCATION_ID", iid)
        .current_dir(&dir)
        .arg("168")
        .arg(&ledger)
        .arg("--verify")
        .arg(format!("--epoch-hashes={}", checkpoints.display()))
        .arg(format!("--snapshot-archive={}", snap.display()))
        .arg(format!(
            "--horizon-output={}",
            dir.join("epoch-168.diagnostic.jet").display()
        ))
        .arg(format!("--replay-scratch={}", scratch.display()))
        .arg("--qualification-end-slot=73007829");
    Err(cmd.exec().into())
}

fn read_trace(log: impl BufRead) -> Result<Value> {
    let restored = "historical worker initialized at slot 72575704 (";
    let key = format!(
        "epoch168 trace slot=72728191 entry=433 transaction=532 signature={SIGNATURE} execution="
    );
    let mut saw_restore = false;
    let mut trace = None;
    // Bound each diagnostic line before allocation. The reader may be called again after EOF.
    let mut reader = log;
    let mut line = Vec::new();
    loop {
        line.clear();
        let n = reader.by_ref().take(1 << 20).read_until(b'\n', &mut line)?;
        if n == 0 {
            break;
        }
        ensure!(n < 1 << 20, "overlong log line");
        if line.last() != Some(&b'\n') {
            break;
        }
        let text = std::str::from_utf8(&line)?;
        if text.contains(restored) {
            ensure!(!saw_restore, "duplicate worker initialization");
            saw_restore = true;
        }
        if let Some(payload) = text.trim_end().strip_prefix(&key) {
            ensure!(saw_restore && trace.is_none(), "unbound or duplicate trace");
            let (execution, logs) = payload.split_once(" logs=").context("incomplete trace")?;
            ensure!(
                execution.starts_with("Some(")
                    && execution.ends_with(')')
                    && logs.starts_with("Some(")
                    && logs.ends_with(')'),
                "missing execution or VM logs"
            );
            trace = Some(json!({"execution":execution,"logs":logs}));
        }
    }
    Ok(
        json!({"schema":"epoch168-private-trace-observation-v1","bootstrap_initialization_seen":saw_restore,"target_slot":72728191,"entry":433,"transaction":532,"signature":SIGNATURE,"trace":trace.context("target trace pending or absent")?,"archive_verified":false,"publication_authorized":false}),
    )
}

fn run() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [a] if a == "inspect" => {
            serde_json::to_writer_pretty(io::stdout().lock(), &inventory::inspect()?)?;
            println!();
            Ok(())
        }
        [a] if a == "run" => stage_and_exec(),
        [a] if a == "trace" => {
            let dir = run_dir();
            root_dir(&dir)?;
            let f = stable_file(&dir.join("producer.log"))?;
            let mut v = read_trace(BufReader::new(&f))?;
            let inputs = stable_file(&dir.join("inputs.json"))?;
            ensure!(inputs.metadata()?.len() < 8192, "oversize inputs receipt");
            let r: Value = serde_json::from_reader(inputs)?;
            ensure!(
                r["worker_sha256"] == TRACE_SHA
                    && r["node_sha256"] == NODE_SHA
                    && r["bootstrap_sha256"] == SNAP_SHA
                    && r["target_signature"] == SIGNATURE
                    && r["publication_authorized"] == false,
                "wrong private receipt"
            );
            v["producer_invocation_id"] = r["invocation_id"].clone();
            v["log_inode"] = json!(f.metadata()?.ino());
            serde_json::to_writer_pretty(io::stdout().lock(), &v)?;
            println!();
            Ok(())
        }
        _ => anyhow::bail!("expected inspect, run, or trace"),
    }
}
fn main() -> Result<()> {
    run()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn target() -> String {
        format!(
            "epoch168 trace slot=72728191 entry=433 transaction=532 signature={SIGNATURE} execution=Some(Err(InstructionError(0, ProgramFailedToComplete))) logs=Some([\"test VM log\"])\n"
        )
    }
    const INIT: &str =
        "[INFO] historical worker initialized at slot 72575704 (last_blockhash=example)\n";
    #[test]
    fn checkpoint_manifest_rejects_substituted_terminal_and_bootstrap_generations() {
        let checkpoint = |slot, generation, name: &str| {
            json!({
                "slot":slot, "generation":generation,
                "uri":format!("gs://mainnet-beta-ledger-us-ny5/{slot}/{name}")
            })
        };
        let data = json!({"manifest":{"epochs":[{"epoch":168,"runtime":"solana-v1.5.6",
            "bootstrap":checkpoint(72_575_704u64,1_634_787_413_893_700u64,SNAP),
            "post_bootstrap_root_checkpoints":[checkpoint(73_007_829u64,1_634_787_450_103_391u64,TERMINAL)]
        }]}});
        assert!(manifest_terms(&data).is_ok());
        let mut changed = data.clone();
        changed["manifest"]["epochs"][0]["bootstrap"]["generation"] = json!(1);
        assert!(manifest_terms(&changed).is_err());
        let mut changed = data;
        changed["manifest"]["epochs"][0]["post_bootstrap_root_checkpoints"][0]["slot"] =
            json!(72_728_191);
        assert!(manifest_terms(&changed).is_err());
    }

    #[test]
    fn exact_trace_needs_restored_worker_and_single_identity() {
        let t = target();
        assert!(read_trace(t.as_bytes()).is_err());
        assert!(read_trace(format!("{INIT}{t}{t}").as_bytes()).is_err());
        assert!(
            read_trace(format!("{INIT}{}", t.replace("entry=433", "entry=434")).as_bytes())
                .is_err()
        );
        assert!(read_trace(format!("{INIT}{}", t.trim_end()).as_bytes()).is_err());
        let v = read_trace(format!("{INIT}{t}").as_bytes()).unwrap();
        assert_eq!(v["archive_verified"], false);
        assert!(
            v["trace"]["execution"]
                .as_str()
                .unwrap()
                .contains("ProgramFailedToComplete")
        );
    }
}
