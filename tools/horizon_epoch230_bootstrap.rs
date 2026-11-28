//! Compare the capped v1.6.20 restart at slot 99,383,572 with the replayed prefix.
#[allow(dead_code)]
#[path = "../jetstreamer-node/src/historical.rs"]
mod historical;

use anyhow::{Context, Result, ensure};
use historical::{
    HistoricalInitialization, HistoricalRuntimeClient, SOLANA_V1_6_20_CANDIDATE,
    SnapshotInitialization, WorkerSpawn,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use solana_hash::Hash;
use std::{
    fs::{self, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    time::{Duration, Instant},
};

const UNIT: &str = "foundation-230-capped-bootstrap-v1.service";
const SCRATCH: &str = "/tmp/foundation-230-bootstrap";
const PACKAGE: &str = "/var/lib/jetstreamer/horizon230-native-restart-tools-v1";
const STATE: &str = "/var/lib/jetstreamer/horizon230-native-restart-v1";
const SLOT: u64 = 99_383_572;
const GENERATION: u64 = 1_633_495_957_369_677;
const SNAPSHOT: &str = "/var/lib/jetstreamer/horizon230-successor-99383572-input-v1/snapshot-99383572-HAsyNGf1oLCESAqbCQ8K445g2aw9paY5QScx9maA4wbz.tar.zst";
const SNAPSHOT_SIZE: u64 = 10_147_321_177;
const SNAPSHOT_SHA: &str = "e3ca153da1b76720cad5bd8fa8469e9b98bbaab151149da416119fcb2058db3a";
const PREFIX_SHA: &str = "8a8526835aec9e23dd3d83959ec464f6c04d0afd6489f50369023f699d439438";
const GENESIS_SHA: &str = "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945";
const WORKER: &str = "/var/lib/jetstreamer/horizon231-232-capped-worker-d1d48400-v1/jetstreamer-historical-worker-v1-6-20";
const WORKER_SHA: &str = "d80b5245de0366e744440a31298f1ebe5ce63fad4322cdf45b72a183b654ca62";

#[derive(Deserialize)]
struct PrefixManifest {
    epoch: u64,
    output_slot_start: u64,
    output_slot_count: u64,
    terminal: Terminal,
}

#[derive(Deserialize, Serialize)]
struct Terminal {
    slot: u64,
    accounts_hash: String,
    bank_hash: String,
    last_blockhash: String,
    capitalization: u64,
    transaction_count: u64,
    tick_height: u64,
    slot_complete: bool,
    next_write_version: u64,
}

fn read_sealed(path: &Path, limit: u64) -> Result<Vec<u8>> {
    ensure!(path.canonicalize()? == path, "aliased input {path:?}");
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.uid() == 0
            && metadata.nlink() == 1
            && metadata.mode() & 0o222 == 0
            && metadata.len() <= limit,
        "unsealed input {path:?}"
    );
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == metadata.len(),
        "input changed {path:?}"
    );
    Ok(bytes)
}

fn bound(path: &Path, digest: &str, limit: u64) -> Result<Vec<u8>> {
    let bytes = read_sealed(path, limit)?;
    ensure!(
        format!("{:x}", Sha256::digest(&bytes)) == digest,
        "digest differs for {path:?}"
    );
    Ok(bytes)
}

fn sha(hex: &str) -> Result<[u8; 32]> {
    ensure!(hex.len() == 64, "invalid SHA-256");
    let mut result = [0; 32];
    for (byte, chunk) in result.iter_mut().zip(hex.as_bytes().chunks_exact(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(chunk)?, 16)?;
    }
    Ok(result)
}

fn authenticate() -> Result<(String, std::path::PathBuf)> {
    let invocation = std::env::var("INVOCATION_ID")?;
    let group_name = format!("/system.slice/{UNIT}");
    ensure!(
        std::env::args_os().len() == 1
            && unsafe { libc::geteuid() } == 1000
            && invocation.len() == 32
            && invocation.bytes().all(|byte| byte.is_ascii_hexdigit())
            && fs::read_to_string("/proc/self/cgroup")?.trim() == format!("0::{group_name}"),
        "wrong bootstrap invocation"
    );
    let group = Path::new("/sys/fs/cgroup").join(group_name.trim_start_matches('/'));
    for (file, expected) in [
        ("memory.max", "171798691840"),
        ("memory.swap.max", "0"),
        ("cpuset.cpus.effective", "118-121"),
    ] {
        ensure!(
            fs::read_to_string(group.join(file))?.trim() == expected,
            "unexpected {file}"
        );
    }
    let start = Path::new(STATE).join("start.json");
    let deadline = Instant::now() + Duration::from_secs(30);
    while !start.try_exists()? {
        ensure!(
            Instant::now() < deadline,
            "admitted invocation was not recorded"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    let receipt: Value = serde_json::from_slice(&read_sealed(&start, 1 << 20)?)?;
    ensure!(
        receipt["schema"] == "foundation-epoch230-capped-bootstrap-start-v1"
            && receipt["owner"]["Id"] == UNIT
            && receipt["owner"]["InvocationID"] == invocation
            && receipt["owner"]["MainPID"] == std::process::id().to_string()
            && receipt["owner"]["ControlGroup"] == group_name
            && receipt["replay_launch_authorized"] == false,
        "start receipt differs"
    );
    Ok((invocation, group))
}

fn main() -> Result<()> {
    let (invocation, group) = authenticate()?;
    let root = Path::new(SCRATCH);
    ensure!(
        root.canonicalize()? == root
            && root.metadata()?.uid() == 1000
            && fs::read_dir(root)?.next().is_none(),
        "expected a fresh scratch mount"
    );
    let mountinfo = fs::read_to_string("/proc/self/mountinfo")?;
    ensure!(
        mountinfo
            .lines()
            .any(|row| row.split_once(" - ").is_some_and(|(front, back)| {
                let mut fields = front.split_whitespace().skip(4);
                fields.next() == Some(SCRATCH)
                    && fields
                        .next()
                        .is_some_and(|options| !options.split(',').any(|o| o == "noexec"))
                    && back.starts_with("tmpfs ")
                    && back
                        .split_whitespace()
                        .nth(2)
                        .is_some_and(|opts| opts.split(',').any(|o| o == "noswap"))
            })),
        "expected an executable no-swap tmpfs"
    );
    let package = Path::new(PACKAGE);
    bound(&package.join("genesis.tar.bz2"), GENESIS_SHA, 1 << 20)?;
    bound(Path::new(WORKER), WORKER_SHA, 32 << 20)?;
    let manifest: PrefixManifest =
        serde_json::from_slice(&bound(&package.join("prefix.json"), PREFIX_SHA, 1 << 20)?)?;
    ensure!(
        (
            manifest.epoch,
            manifest.output_slot_start,
            manifest.output_slot_count,
            manifest.terminal.slot
        ) == (230, 99_375_856, 7_717, SLOT)
            && manifest.terminal.slot_complete,
        "unexpected replayed prefix"
    );
    let expected = manifest.terminal;
    let accounts_hash = expected.accounts_hash.parse::<Hash>()?.to_bytes();
    let bank_hash = expected.bank_hash.parse::<Hash>()?.to_bytes();
    let last_blockhash = expected.last_blockhash.parse::<Hash>()?.to_bytes();
    let started = Instant::now();
    let mut worker = HistoricalRuntimeClient::spawn(
        SOLANA_V1_6_20_CANDIDATE,
        WorkerSpawn {
            executable: WORKER.into(),
            initialization: HistoricalInitialization::SnapshotArchive(SnapshotInitialization {
                ledger_path: package.into(),
                archive_path: SNAPSHOT.into(),
                expected_slot: SLOT,
                expected_accounts_hash: accounts_hash,
                expected_archive_sha256: Some(sha(SNAPSHOT_SHA)?),
                expected_archive_size: Some(SNAPSHOT_SIZE),
                scratch_parent: Some(root.into()),
            }),
        },
    )?;
    ensure!(
        worker.executable_sha256() == sha(WORKER_SHA)?,
        "resolved capped worker differs"
    );
    let cursor = worker.initialized().next_write_version;
    let tick_unit = worker.initialized().ticks_per_slot;
    let checkpoint = worker
        .freeze_checkpoint(SLOT)
        .context("freeze restored checkpoint")?;
    let actual = json!({"slot":checkpoint.slot,"bank_hash":Hash::new_from_array(checkpoint.bank_hash).to_string(),
        "accounts_hash":Hash::new_from_array(checkpoint.accounts_hash).to_string(),
        "last_blockhash":Hash::new_from_array(checkpoint.last_blockhash).to_string(),
        "capitalization":checkpoint.capitalization,"transaction_count":checkpoint.transaction_count,
        "tick_height":checkpoint.tick_height,"next_write_version":checkpoint.next_write_version});
    let matches = checkpoint.slot == SLOT
        && checkpoint.accounts_hash == accounts_hash
        && checkpoint.bank_hash == bank_hash
        && checkpoint.last_blockhash == last_blockhash
        && checkpoint.capitalization == expected.capitalization
        && checkpoint.transaction_count == expected.transaction_count
        && checkpoint.tick_height == expected.tick_height
        && checkpoint.slot_complete
        && checkpoint.writes.is_empty()
        && checkpoint.next_write_version == cursor
        && tick_unit == 64;
    worker.shutdown()?;
    ensure!(
        fs::read_dir(root)?.next().is_none(),
        "worker scratch remains after shutdown"
    );
    let peak = fs::read_to_string(group.join("memory.peak"))?
        .trim()
        .parse::<u64>()?;
    println!(
        "{}",
        json!({"schema":"foundation-epoch230-capped-bootstrap-v1","epoch":230,"invocation_id":invocation,
        "expected":expected,"actual":actual,"worker_sha256":WORKER_SHA,
        "snapshot_generation":GENERATION,"snapshot_sha256":SNAPSHOT_SHA,"prefix_sha256":PREFIX_SHA,
        "cgroup_memory_peak_bytes":peak,"elapsed_millis":started.elapsed().as_millis(),"checkpoint_matched":matches,
        "worker_shutdown_succeeded":true,"replay_entries_sent":0,"full_continuation_peak_qualified":false,
        "publication_authorized":false})
    );
    ensure!(
        matches,
        "restored capped worker differs from the replayed checkpoint"
    );
    Ok(())
}
