//! Private payload for a guarded historical metering trace. The admission controller
//! supplies the sandbox and an empty HOME-backed run root before executing this binary.

use anyhow::{Context, Result, ensure};
use guard172::route::*;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const RUN_PARENT: &str = "metadata-probes";
const WORKER: &str = "jetstreamer-historical-worker-v1-5-6";
const TRACE_SHA: &str = guard172::WORKER_SHA;
const NODE_SHA: &str = "a09b8e5aa9426beaf42e6b5f2a469a5a147436bab8b7bf79f268758b60aa2e65";
const GENESIS_SHA: &str = "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945";

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

fn route_terms(v: &Value) -> Result<()> {
    let expected: Value = serde_json::from_slice(HOURLY)?;
    ensure!(
        v == &expected
            && v["epoch"] == EPOCH
            && v["target"] == TARGET
            && v["full_archive_verified"] == false
            && v["bank_restored"] == false,
        "hourly route metadata differs"
    );
    for (key, name, slot, generation) in [
        ("bootstrap", SNAP, SNAP_SLOT, SNAP_GENERATION),
        ("checkpoint", TERMINAL, TERMINAL_SLOT, TERMINAL_GENERATION),
    ] {
        ensure!(
            v[key]["slot"] == slot
                && v[key]["generation"] == generation
                && v[key]["name"].as_str().and_then(|s| s.rsplit('/').next()) == Some(name),
            "wrong hourly generation or checkpoint"
        );
    }
    Ok(())
}
fn stage_and_exec() -> Result<()> {
    let iid = verify_actor()?;
    let lane = Path::new(LANE);
    let dir = run_dir();
    let package = Path::new(NODE_PACKAGE);
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

    transfer(&node, 47_753_136, NODE_SHA, None)?;
    // The service has a read-only file bind of the sealed trace worker onto its original
    // worker pathname. The unmodified production worker fails this hash check.
    transfer(&worker, guard172::WORKER_BYTES, TRACE_SHA, None)?;
    route_terms(&serde_json::from_slice(HOURLY)?)?;
    let ledger = dir.join("ledger");
    let scratch = dir.join("scratch");
    let tmp = dir.join("tmp");
    for p in [&ledger, &scratch, &tmp] {
        fs::DirBuilder::new().mode(0o700).create(p)?;
    }
    let snap = dir.join(SNAP);
    transfer(
        Path::new(SNAP_ALIAS),
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
    let receipt = json!({"schema":format!("epoch{EPOCH}-private-metered-inputs-v2"),"invocation_id":iid,"node_sha256":NODE_SHA,"worker_sha256":TRACE_SHA,"worker_source_commit":guard172::WORKER_SOURCE,"worker_feature":guard172::WORKER_FEATURE,"bootstrap_sha256":SNAP_SHA,"bootstrap_bytes":SNAP_BYTES,"target_slot":TARGET,"target_entry":ENTRY,"target_transaction":ORDINAL,"target_signature":SIGNATURE,"terminal_checkpoint":TERMINAL_SLOT,"bootstrap_generation":SNAP_GENERATION,"checkpoint_generation":TERMINAL_GENERATION,"terminal_checkpoint_name":TERMINAL,"canonical_error":format!("instruction2 {CANONICAL_ERROR}"),"original_local_error":format!("instruction2 {LOCAL_ERROR}"),"account_state_verified":false,"publication_authorized":false});
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
        ("SOLANA_RAYON_THREADS", "3"),
        ("RAYON_NUM_THREADS", "3"),
        ("JETSTREAMER_HISTORICAL_POH_THREADS", "3"),
        ("JETSTREAMER_HISTORICAL_REAP_TIMEOUT_SECS", "600"),
        ("JETSTREAMER_ALLOW_CANDIDATE_RUNTIME", "1"),
        (TRACE_SWITCH, "1"),
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
        .arg(EPOCH_KEY)
        .arg(&ledger)
        .arg("--verify")
        .arg(format!("--epoch-hashes={}", checkpoints.display()))
        .arg(format!("--snapshot-archive={}", snap.display()))
        .arg(format!(
            "--horizon-output={}",
            dir.join(format!("epoch-{EPOCH}.diagnostic.jet")).display()
        ))
        .arg(format!("--replay-scratch={}", scratch.display()))
        .arg(format!("--qualification-end-slot={TERMINAL_SLOT}"));
    Err(cmd.exec().into())
}

fn read_trace(log: impl BufRead) -> Result<Value> {
    let restored = format!("historical worker initialized at slot {SNAP_SLOT} (");
    let key = format!(
        "epoch{EPOCH} trace slot={TARGET} entry={ENTRY} transaction={ORDINAL} signature={SIGNATURE} execution="
    );
    let feature_tag = format!(
        "historical per-byte logging feature at restored bank slot {SNAP_SLOT}: activated_at="
    );
    let bootstrap_tag = format!("historical checkpoint slot={SNAP_SLOT} bank_hash=");
    let terminal_tag = format!("historical checkpoint slot={TERMINAL_SLOT} bank_hash=");
    let mut activation = None;
    let mut bootstrap_hash = None;
    let mut saw_restore = false;
    let mut trace = None;
    let mut checkpoint: Option<Value> = None;
    let mut verifier_finished = false;
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
        if let Some(value) = text.trim_end().strip_prefix(&feature_tag) {
            ensure!(
                activation.is_none() && !saw_restore,
                "duplicate or late restored feature"
            );
            activation = Some(value.to_owned());
        }
        if text.contains(&bootstrap_tag) {
            ensure!(
                saw_restore
                    && trace.is_none()
                    && text.split_whitespace().any(|s| s == "complete=true"),
                "bootstrap checkpoint incomplete or out of order"
            );
            let observed = text
                .split_whitespace()
                .find_map(|s| s.strip_prefix("accounts_hash="))
                .context("bootstrap accounts hash")?
                .to_owned();
            ensure!(
                bootstrap_hash
                    .as_ref()
                    .is_none_or(|prior| prior == &observed),
                "conflicting bootstrap checkpoint"
            );
            bootstrap_hash = Some(observed);
        }
        if text.contains(&restored) {
            ensure!(!saw_restore, "duplicate worker initialization");
            saw_restore = true;
        }
        if let Some((_, rest)) = text.trim_end().split_once(&terminal_tag) {
            ensure!(trace.is_some(), "terminal checkpoint before target");
            let fields = rest.split_whitespace().collect::<Vec<_>>();
            let field = |prefix: &str| -> Result<&str> {
                let mut v = fields.iter().filter_map(|s| s.strip_prefix(prefix));
                let first = v.next().context("missing checkpoint field")?;
                ensure!(v.next().is_none(), "duplicate checkpoint field");
                Ok(first)
            };
            let actual = field("accounts_hash=")?;
            let observed = json!({"slot":TERMINAL_SLOT,"accounts_hash":actual,"route_hash_matches":actual==TERMINAL_HASH,"slot_complete":field("complete=")?=="true"});
            ensure!(
                checkpoint.as_ref().is_none_or(|c| *c == observed),
                "conflicting terminal observations"
            );
            checkpoint = Some(observed);
        }
        if checkpoint.is_some() && text.trim_end().ends_with("snapshot verification complete") {
            verifier_finished = true;
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
            let encoded = logs
                .strip_prefix("Some(")
                .and_then(|v| v.strip_suffix(')'))
                .context("VM log record")?;
            let observed: Vec<String> =
                serde_json::from_str(encoded).context("parse historical VM log vector")?;
            let canonical: Vec<String> = serde_json::from_slice(CANONICAL_LOGS)?;
            let difference=(0..canonical.len().max(observed.len())).find(|&n|canonical.get(n)!=observed.get(n)).map(|n|json!({"log_index_zero_based":n,"canonical":canonical.get(n),"observed":observed.get(n)}));
            let baseline: Vec<String> = serde_json::from_slice(UNPATCHED_LOGS)?;
            let mut meter_rows = Vec::new();
            for (i, expected) in canonical
                .iter()
                .enumerate()
                .filter(|(_, s)| s.ends_with(" compute units"))
            {
                meter_rows.push(
                    json!({"index":i, "unpatched":baseline.get(i), "metered":observed.get(i),
                    "finalized":expected, "matches_finalized":observed.get(i)==Some(expected)}),
                );
            }
            trace = Some(
                json!({"execution":execution,"matches_canonical_execution":execution==format!("Some(Err(InstructionError(2, {CANONICAL_ERROR})))"),"matches_original_execution":execution==format!("Some(Err(InstructionError(2, {LOCAL_ERROR})))"),"meter_rows":meter_rows,"all_logs_match":observed==canonical,"observed_log_count":observed.len(),"canonical_log_count":canonical.len(),"first_differing_log":difference,"logs":observed}),
            );
        }
    }
    let feature_matches = activation.as_deref() == Some("Some(66528004)");
    let bootstrap_matches = bootstrap_hash.as_deref() == Some(SNAP_HASH);
    let signed_match = trace
        .as_ref()
        .is_some_and(|t| t["all_logs_match"] == true && t["matches_canonical_execution"] == true);
    let terminal_matches = checkpoint
        .as_ref()
        .is_some_and(|c| c["route_hash_matches"] == true && c["slot_complete"] == true);
    Ok(
        json!({"schema":format!("epoch{EPOCH}-private-metered-observation-v2"),"bootstrap_initialization_seen":saw_restore,
        "restored_bank_feature":activation, "restored_feature_matches_finalized":feature_matches,
        "bootstrap_accounts_hash":bootstrap_hash,"bootstrap_hash_matches":bootstrap_matches,
        "target_slot":TARGET,"entry":ENTRY,"transaction":ORDINAL,"signature":SIGNATURE,
        "canonical_error":format!("instruction2 {CANONICAL_ERROR}"),"original_local_error":format!("instruction2 {LOCAL_ERROR}"),
        "checkpoint_slot":TERMINAL_SLOT,"terminal_worker_checkpoint":checkpoint,"node_verifier_finished_after_target":verifier_finished,
        "trace":trace, "focused_checks_passed":saw_restore && feature_matches && bootstrap_matches && signed_match && terminal_matches && verifier_finished,
        "archive_verified":false,"publication_authorized":false}),
    )
}

fn run() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [a] if a == "run" => stage_and_exec(),
        [a] if a == "trace" || a == "progress" => {
            let dir = run_dir();
            root_dir(&dir)?;
            let f = stable_file(&dir.join("producer.log"))?;
            let mut v = read_trace(BufReader::new(&f))?;
            ensure!(
                a == "progress" || !v["trace"].is_null(),
                "target trace pending or absent"
            );
            let inputs = stable_file(&dir.join("inputs.json"))?;
            ensure!(inputs.metadata()?.len() < 8192, "oversize inputs receipt");
            let r: Value = serde_json::from_reader(inputs)?;
            ensure!(
                r["worker_sha256"] == TRACE_SHA
                    && r["worker_source_commit"] == guard172::WORKER_SOURCE
                    && r["worker_feature"] == guard172::WORKER_FEATURE
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
        _ => anyhow::bail!("expected run, trace or progress"),
    }
}
fn main() -> Result<()> {
    run()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn init() -> String {
        format!(
            "[INFO] historical worker initialized at slot {SNAP_SLOT} (last_blockhash=example)\n"
        )
    }
    fn trace(error: &str, logs: &Value) -> String {
        format!(
            "epoch{EPOCH} trace slot={TARGET} entry={ENTRY} transaction={ORDINAL} signature={SIGNATURE} execution=Some(Err(InstructionError(2, {error}))) logs=Some({logs})\n"
        )
    }
    #[test]
    fn route_must_bind_both_exact_hourly_generations() {
        let v: Value = serde_json::from_slice(HOURLY).unwrap();
        route_terms(&v).unwrap();
        for key in ["bootstrap", "checkpoint"] {
            let mut changed = v.clone();
            changed[key]["generation"] = json!("wrong");
            assert!(route_terms(&changed).is_err());
        }
    }
    #[test]
    fn canonical_transcript_has_no_differing_line() {
        let logs: Value = serde_json::from_slice(CANONICAL_LOGS).unwrap();
        let r =
            read_trace(format!("{}{}", init(), trace(CANONICAL_ERROR, &logs)).as_bytes()).unwrap();
        assert_eq!(r["trace"]["matches_canonical_execution"], true);
        assert_eq!(r["trace"]["all_logs_match"], true);
        assert_eq!(r["trace"]["canonical_log_count"], CANONICAL_LOG_COUNT);
        assert!(r["trace"]["first_differing_log"].is_null());
        assert_eq!(r["focused_checks_passed"], false);
    }
    #[test]
    fn exact_trace_needs_restored_worker_and_single_identity() {
        let t = trace(LOCAL_ERROR, &json!(["test VM log"]));
        let init = init();
        assert!(read_trace(t.as_bytes()).is_err());
        assert!(read_trace(format!("{init}{t}{t}").as_bytes()).is_err());
        let bad = t.replace(&format!("entry={ENTRY}"), "entry=0");
        assert!(read_trace(format!("{init}{bad}").as_bytes()).unwrap()["trace"].is_null());
        assert!(
            read_trace(format!("{init}{}", t.trim_end()).as_bytes()).unwrap()["trace"].is_null()
        );
        let r = read_trace(format!("{init}{t}").as_bytes()).unwrap();
        assert_eq!(r["trace"]["matches_original_execution"], true);
        assert_eq!(r["trace"]["matches_canonical_execution"], false);
        assert_eq!(r["archive_verified"], false);
        assert_eq!(r["trace"]["first_differing_log"]["log_index_zero_based"], 0);
    }
    #[test]
    fn success_requires_the_real_feature_and_every_terminal_phase() {
        let logs: Value = serde_json::from_slice(CANONICAL_LOGS).unwrap();
        let target = trace(CANONICAL_ERROR, &logs);
        let activated = format!(
            "historical per-byte logging feature at restored bank slot {SNAP_SLOT}: activated_at=Some(66528004)\n"
        );
        let bootstrap = format!(
            "historical checkpoint slot={SNAP_SLOT} bank_hash=b accounts_hash={SNAP_HASH} complete=true\n"
        );
        let terminal = format!(
            "historical checkpoint slot={TERMINAL_SLOT} bank_hash=b accounts_hash={TERMINAL_HASH} complete=true\n"
        );
        let finish = "[INFO] snapshot verification complete\n";
        let complete = format!("{activated}{}{bootstrap}{target}{terminal}{finish}", init());
        let good = read_trace(complete.as_bytes()).unwrap();
        assert_eq!(good["focused_checks_passed"], true);
        let rows = good["trace"]["meter_rows"].as_array().unwrap();
        assert_eq!(rows.len(), METER_ROWS);
        if EPOCH == 171 {
            assert!(rows.iter().all(|r| r["unpatched"].is_null()));
            assert!(rows.iter().any(|r| {
                r["finalized"]
                    .as_str()
                    .unwrap()
                    .contains("consumed 27 of 27 compute units")
            }));
        } else {
            assert_ne!(rows[0]["unpatched"], rows[0]["finalized"]);
        }
        for field in [&activated[..], &bootstrap, &terminal, finish] {
            assert_eq!(
                read_trace(complete.replace(field, "").as_bytes()).unwrap()["focused_checks_passed"],
                false
            );
        }
        for (a, b) in [
            ("66528004", "1"),
            ("4429", "4499"),
            (TERMINAL_HASH, "wrong"),
        ] {
            assert_eq!(
                read_trace(complete.replace(a, b).as_bytes()).unwrap()["focused_checks_passed"],
                false
            );
        }
    }
}
