//! Private payload for the guarded historical epoch-172 trace. The admission controller
//! supplies the sandbox and an empty HOME-backed run root before executing this binary.

use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const LANE: &str = "/home/sol/.jetstreamer-private/epoch172-standard-lane-20261110-v1";
const RUN_PARENT: &str = "metadata-probes";
const RUN: &str = "metered-hourly-20261120-g2";
const PKG: &str = "/usr/local/lib/jetstreamer/horizon-independent172-singleton-package-20261110-v1";
const UNIT: &str = "horizon-qualify-172-metered-hourly-20261120-g2.service";
const WORKER: &str = "jetstreamer-historical-worker-v1-5-6";
const TRACE_SHA: &str = guard172::WORKER_SHA;
const NODE_SHA: &str = "a09b8e5aa9426beaf42e6b5f2a469a5a147436bab8b7bf79f268758b60aa2e65";
const SNAP: &str = "snapshot-74379198-7sUN98jiB8FuSu3nkpCm1gLBbPbFH1HtfocPKPV7asPj.tar.zst";
const TERMINAL: &str = "snapshot-74382131-oFYTx673sc7Sq4Dw74vsAby6SHVAbin3QtT8dmGzaLo.tar.zst";
const SNAP_SHA: &str = "fa7936328f4a4898ce9f35fd2892d9ba8f8ba03df345f8bc282ee6e913b2cc5f";
const GENESIS_SHA: &str = "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945";
const SIGNATURE: &str =
    "4Mc3qYm8t2AewCC1pax3hp11X7krbVmeWrAzcq8KqB2xtdut6i9fxo8XiMYU31jURU926HunHN2UZo7cQwdQ1chV";
const SNAP_BYTES: u64 = 2_110_486_214;

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

const ROUTE: &[u8] = include_bytes!("hourly-route.json");
fn route_terms(v: &Value) -> Result<()> {
    ensure!(
        v["epoch"] == 172
            && v["target"] == 74380784
            && v["prefix_sha256"]
                == "9c5cbe9cf367ec22aea17523e0b0fe7c1cb44c1e4160087dc5b886c9ec599e83"
            && v["full_archive_verified"] == false
            && v["bank_restored"] == false,
        "wrong metadata provenance"
    );
    for (key, name, slot, bucket, object, generation, bytes, md5, crc) in [
        (
            "bootstrap",
            SNAP,
            74379198,
            "mainnet-beta-ledger-asia-sg1",
            "74303803",
            "1634786215364147",
            "2110486214",
            "rOc4FiXjMYrupror5w4K1w==",
            "yysMog==",
        ),
        (
            "checkpoint",
            TERMINAL,
            74382131,
            "mainnet-beta-ledger-europe-fr2",
            "74303701",
            "1634787172918779",
            "2120937600",
            "HqRG8MQkwBGOPI0yF2GC8w==",
            "j/dYeA==",
        ),
    ] {
        let r = &v[key];
        ensure!(
            r["name"] == format!("{object}/hourly/{name}")
                && r["slot"] == slot
                && r["bucket"] == bucket
                && r["generation"] == generation
                && r["size"] == bytes
                && r["md5Hash"] == md5
                && r["crc32c"] == crc,
            "wrong {key} generation/checkpoint"
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

    transfer(&node, 47_753_136, NODE_SHA, None)?;
    // The service has a read-only file bind of the sealed trace worker onto its original
    // worker pathname. The unmodified production worker fails this hash check.
    transfer(&worker, guard172::WORKER_BYTES, TRACE_SHA, None)?;
    route_terms(&serde_json::from_slice(ROUTE)?)?;
    let ledger = dir.join("ledger");
    let scratch = dir.join("scratch");
    let tmp = dir.join("tmp");
    for p in [&ledger, &scratch, &tmp] {
        fs::DirBuilder::new().mode(0o700).create(p)?;
    }
    let snap = dir.join(SNAP);
    transfer(
        Path::new("/run/horizon-172-incident-snapshot"),
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
    let receipt = json!({"schema":"epoch172-private-metered-inputs-v2","invocation_id":iid,"node_sha256":NODE_SHA,"worker_sha256":TRACE_SHA,"worker_source_commit":guard172::WORKER_SOURCE,"worker_feature":guard172::WORKER_FEATURE,"bootstrap_sha256":SNAP_SHA,"bootstrap_bytes":SNAP_BYTES,"target_slot":74380784,"target_entry":645,"target_transaction":984,"target_signature":SIGNATURE,"terminal_checkpoint":74382131,"bootstrap_generation":"1634786215364147","checkpoint_generation":"1634787172918779","terminal_checkpoint_name":TERMINAL,"canonical_error":"instruction2 ComputationalBudgetExceeded","original_local_error":"instruction2 ProgramFailedToComplete","account_state_verified":false,"publication_authorized":false});
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
        ("JETSTREAMER_HISTORICAL_TRACE_EPOCH172", "1"),
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
        .arg("172")
        .arg(&ledger)
        .arg("--verify")
        .arg(format!("--epoch-hashes={}", checkpoints.display()))
        .arg(format!("--snapshot-archive={}", snap.display()))
        .arg(format!(
            "--horizon-output={}",
            dir.join("epoch-172.diagnostic.jet").display()
        ))
        .arg(format!("--replay-scratch={}", scratch.display()))
        .arg("--qualification-end-slot=74382131");
    Err(cmd.exec().into())
}

fn read_trace(log: impl BufRead) -> Result<Value> {
    let restored = "historical worker initialized at slot 74379198 (";
    let key = format!(
        "epoch172 trace slot=74380784 entry=645 transaction=984 signature={SIGNATURE} execution="
    );
    let feature_tag =
        "historical per-byte logging feature at restored bank slot 74379198: activated_at=";
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
        if let Some(value) = text.trim_end().strip_prefix(feature_tag) {
            ensure!(
                activation.is_none() && !saw_restore,
                "duplicate or late restored feature"
            );
            activation = Some(value.to_owned());
        }
        if text.contains("historical checkpoint slot=74379198 bank_hash=") {
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
        if text.contains(restored) {
            ensure!(!saw_restore, "duplicate worker initialization");
            saw_restore = true;
        }
        if let Some((_, rest)) = text
            .trim_end()
            .split_once("historical checkpoint slot=74382131 bank_hash=")
        {
            ensure!(trace.is_some(), "terminal checkpoint before target");
            let fields = rest.split_whitespace().collect::<Vec<_>>();
            let field = |prefix: &str| -> Result<&str> {
                let mut v = fields.iter().filter_map(|s| s.strip_prefix(prefix));
                let first = v.next().context("missing checkpoint field")?;
                ensure!(v.next().is_none(), "duplicate checkpoint field");
                Ok(first)
            };
            let actual = field("accounts_hash=")?;
            let observed = json!({"slot":74382131,"accounts_hash":actual,"route_hash_matches":actual=="oFYTx673sc7Sq4Dw74vsAby6SHVAbin3QtT8dmGzaLo","slot_complete":field("complete=")?=="true"});
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
            let canonical: Vec<String> =
                serde_json::from_slice(include_bytes!("canonical-logs.json"))?;
            let difference=(0..canonical.len().max(observed.len())).find(|&n|canonical.get(n)!=observed.get(n)).map(|n|json!({"log_index_zero_based":n,"canonical":canonical.get(n),"observed":observed.get(n)}));
            let baseline: Vec<String> =
                serde_json::from_slice(include_bytes!("unpatched-logs.json"))?;
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
                json!({"execution":execution,"matches_canonical_execution":execution=="Some(Err(InstructionError(2, ComputationalBudgetExceeded)))","matches_original_execution":execution=="Some(Err(InstructionError(2, ProgramFailedToComplete)))","meter_rows":meter_rows,"all_logs_match":observed==canonical,"observed_log_count":observed.len(),"canonical_log_count":canonical.len(),"first_differing_log":difference,"logs":observed}),
            );
        }
    }
    let feature_matches = activation.as_deref() == Some("Some(66528004)");
    let bootstrap_matches =
        bootstrap_hash.as_deref() == Some("7sUN98jiB8FuSu3nkpCm1gLBbPbFH1HtfocPKPV7asPj");
    let signed_match = trace
        .as_ref()
        .is_some_and(|t| t["all_logs_match"] == true && t["matches_canonical_execution"] == true);
    let terminal_matches = checkpoint
        .as_ref()
        .is_some_and(|c| c["route_hash_matches"] == true && c["slot_complete"] == true);
    Ok(
        json!({"schema":"epoch172-private-metered-observation-v2","bootstrap_initialization_seen":saw_restore,
        "restored_bank_feature":activation, "restored_feature_matches_finalized":feature_matches,
        "bootstrap_accounts_hash":bootstrap_hash,"bootstrap_hash_matches":bootstrap_matches,
        "target_slot":74380784,"entry":645,"transaction":984,"signature":SIGNATURE,
        "canonical_error":"instruction2 ComputationalBudgetExceeded","original_local_error":"instruction2 ProgramFailedToComplete",
        "checkpoint_slot":74382131,"terminal_worker_checkpoint":checkpoint,"node_verifier_finished_after_target":verifier_finished,
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
    fn target() -> String {
        format!(
            "epoch172 trace slot=74380784 entry=645 transaction=984 signature={SIGNATURE} execution=Some(Err(InstructionError(2, ProgramFailedToComplete))) logs=Some([\"test VM log\"])\n"
        )
    }
    const INIT: &str =
        "[INFO] historical worker initialized at slot 74379198 (last_blockhash=example)\n";
    #[test]
    fn route_must_bind_both_exact_hourly_generations() {
        let v: Value = serde_json::from_slice(ROUTE).unwrap();
        route_terms(&v).unwrap();
        let mut changed = v.clone();
        changed["checkpoint"]["slot"] = json!(74380784);
        assert!(route_terms(&changed).is_err());
        let mut changed = v;
        changed["bootstrap"]["generation"] = json!("different");
        assert!(route_terms(&changed).is_err());
    }
    #[test]
    fn canonical_transcript_has_no_differing_line() {
        let logs: Vec<String> =
            serde_json::from_slice(include_bytes!("canonical-logs.json")).unwrap();
        let line = target()
            .replace("ProgramFailedToComplete", "ComputationalBudgetExceeded")
            .replace("[\"test VM log\"]", &serde_json::to_string(&logs).unwrap());
        let v = read_trace(format!("{INIT}{line}").as_bytes()).unwrap();
        assert_eq!(v["trace"]["matches_canonical_execution"], true);
        assert!(v["trace"]["first_differing_log"].is_null());
        assert_eq!(v["trace"]["canonical_log_count"], 45);
    }
    #[test]
    fn exact_trace_needs_restored_worker_and_single_identity() {
        let t = target();
        assert!(read_trace(t.as_bytes()).is_err());
        assert!(read_trace(format!("{INIT}{t}{t}").as_bytes()).is_err());
        assert!(
            read_trace(format!("{INIT}{}", t.replace("entry=645", "entry=646")).as_bytes())
                .unwrap()["trace"]
                .is_null()
        );
        assert!(
            read_trace(format!("{INIT}{}", t.trim_end()).as_bytes()).unwrap()["trace"].is_null()
        );
        let v = read_trace(format!("{INIT}{t}").as_bytes()).unwrap();
        assert_eq!(v["archive_verified"], false);
        assert_eq!(v["trace"]["first_differing_log"]["log_index_zero_based"], 0);
        assert_eq!(v["trace"]["matches_original_execution"], true);
        assert_eq!(v["trace"]["matches_canonical_execution"], false);
        assert!(
            v["trace"]["execution"]
                .as_str()
                .unwrap()
                .contains("ProgramFailedToComplete")
        );
    }
    #[test]
    fn success_requires_the_real_feature_and_every_terminal_phase() {
        let logs: Vec<String> =
            serde_json::from_slice(include_bytes!("canonical-logs.json")).unwrap();
        let line = target()
            .replace("ProgramFailedToComplete", "ComputationalBudgetExceeded")
            .replace("[\"test VM log\"]", &serde_json::to_string(&logs).unwrap());
        let activated = "historical per-byte logging feature at restored bank slot 74379198: activated_at=Some(66528004)\n";
        let bootstrap = "historical checkpoint slot=74379198 bank_hash=b accounts_hash=7sUN98jiB8FuSu3nkpCm1gLBbPbFH1HtfocPKPV7asPj complete=true\n";
        let terminal = "historical checkpoint slot=74382131 bank_hash=b accounts_hash=oFYTx673sc7Sq4Dw74vsAby6SHVAbin3QtT8dmGzaLo complete=true\n";
        let finished = "[INFO] snapshot verification complete\n";
        let complete = format!("{activated}{INIT}{bootstrap}{line}{terminal}{finished}");
        let good = read_trace(complete.as_bytes()).unwrap();
        assert_eq!(good["focused_checks_passed"], true);
        assert_eq!(good["trace"]["meter_rows"].as_array().unwrap().len(), 10);
        assert_ne!(
            good["trace"]["meter_rows"][0]["unpatched"],
            good["trace"]["meter_rows"][0]["finalized"]
        );
        for field in [activated, bootstrap, terminal, finished] {
            assert_eq!(
                read_trace(complete.replace(field, "").as_bytes()).unwrap()["focused_checks_passed"],
                false
            );
        }
        for (a, b) in [
            ("66528004", "1"),
            ("4429", "4499"),
            ("oFYTx673sc7Sq4Dw74vsAby6SHVAbin3QtT8dmGzaLo", "wrong"),
        ] {
            assert_eq!(
                read_trace(complete.replace(a, b).as_bytes()).unwrap()["focused_checks_passed"],
                false
            );
        }
    }
}
