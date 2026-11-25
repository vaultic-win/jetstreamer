//! Compare exact stock and capped v1.6.20 cold restores at the epoch 231 bootstrap.
#[allow(dead_code)]
#[path = "../jetstreamer-node/src/historical.rs"]
mod historical;

use anyhow::{Context, Result, ensure};
use historical::{
    HistoricalInitialization, HistoricalRuntimeClient, SOLANA_V1_6_20_CANDIDATE,
    SnapshotInitialization, WorkerSpawn,
};
use jetstreamer_node::archive_checksum::open_regular_nofollow;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use solana_hash::Hash;
use std::{fs, io::Read, os::unix::fs::MetadataExt, path::Path, time::Instant};

const UNIT: &str = "foundation-231-capped-bootstrap-parity-v1.service";
const SCRATCH: &str = "/tmp/foundation-231-bootstrap";
const PACKAGE: &str = "/var/lib/jetstreamer/horizon231-capped-bootstrap-parity-v1";
const SLOT: u64 = 99_791_404;
const ACCOUNTS: &str = "Hn6PFpfb4b63XELLfqGYLbFk8c8hJtujeQbFR1WmNW84";
const SNAPSHOT: &str = "/var/lib/jetstreamer/horizon-contiguous-231-232-current-46b4b4a-v1/snapshot-99791404-Hn6PFpfb4b63XELLfqGYLbFk8c8hJtujeQbFR1WmNW84.tar.zst";
const SNAPSHOT_SIZE: u64 = 10_615_540_172;
const SNAPSHOT_SHA: &str = "2992a8234c790c0feb836b933b68665b223107b0838c23eee32219ce5dc4f9ca";
const GENESIS_SHA: &str = "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945";
const STOCK: &str = "/var/lib/jetstreamer/horizon-supported-231-232-target1-46b4b4a-v1/jetstreamer-historical-worker-v1-6-20";
const STOCK_SHA: &str = "f39140b9a9659e7c6e8207076a2d0c560a6b69df42cc92e19a421cf46c2b761c";
const CAPPED: &str = "/var/lib/jetstreamer/horizon231-232-capped-worker-d1d48400-v1/jetstreamer-historical-worker-v1-6-20";
const CAPPED_SHA: &str = "d80b5245de0366e744440a31298f1ebe5ce63fad4322cdf45b72a183b654ca62";
const MEMORY_MAX: u64 = 160 << 30;

fn verify_file(path: &Path, expected: &str, limit: u64) -> Result<()> {
    ensure!(
        path.canonicalize()? == path,
        "aliased input {}",
        path.display()
    );
    let file = open_regular_nofollow(path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.uid() == 0 && metadata.mode() & 0o222 == 0 && metadata.len() <= limit,
        "unsealed input {}",
        path.display()
    );
    let mut digest = Sha256::new();
    let length = std::io::copy(&mut file.take(limit + 1), &mut digest)?;
    ensure!(
        length == metadata.len() && format!("{:x}", digest.finalize()) == expected,
        "input digest or length differs at {}",
        path.display()
    );
    Ok(())
}

fn decode(value: &str) -> Result<[u8; 32]> {
    ensure!(value.len() == 64, "invalid SHA-256 hex length");
    let mut bytes = [0; 32];
    for (offset, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[2 * offset..2 * offset + 2], 16)?;
    }
    Ok(bytes)
}

fn restore(executable: &str, digest: &str, ledger: &Path, scratch: &Path) -> Result<(Value, u128)> {
    verify_file(Path::new(executable), digest, 32 << 20)?;
    let expected_hash = ACCOUNTS
        .parse::<Hash>()
        .context("invalid expected AccountsDb root")?;
    let started = Instant::now();
    let mut worker = HistoricalRuntimeClient::spawn(
        SOLANA_V1_6_20_CANDIDATE,
        WorkerSpawn {
            executable: executable.into(),
            initialization: HistoricalInitialization::SnapshotArchive(SnapshotInitialization {
                ledger_path: ledger.to_path_buf(),
                archive_path: SNAPSHOT.into(),
                expected_slot: SLOT,
                expected_accounts_hash: expected_hash.to_bytes(),
                expected_archive_sha256: Some(decode(SNAPSHOT_SHA)?),
                expected_archive_size: Some(SNAPSHOT_SIZE),
                scratch_parent: Some(scratch.into()),
            }),
        },
    )?;
    ensure!(
        worker.executable_sha256() == decode(digest)?,
        "resolved worker differs"
    );
    let initial_cursor = worker.initialized().next_write_version;
    let ticks_per_slot = worker.initialized().ticks_per_slot;
    let checkpoint = worker.freeze_checkpoint(SLOT)?;
    ensure!(
        checkpoint.slot == SLOT
            && checkpoint.accounts_hash == expected_hash.to_bytes()
            && checkpoint.slot_complete
            && checkpoint.writes.is_empty()
            && checkpoint.next_write_version == initial_cursor
            && ticks_per_slot == 64,
        "restored checkpoint or cursor differs from the generation-pinned bootstrap"
    );
    let evidence = json!({
        "slot":checkpoint.slot,"accounts_hash":ACCOUNTS,
        "bank_hash":Hash::new_from_array(checkpoint.bank_hash).to_string(),
        "last_blockhash":Hash::new_from_array(checkpoint.last_blockhash).to_string(),
        "capitalization":checkpoint.capitalization,"transaction_count":checkpoint.transaction_count,
        "tick_height":checkpoint.tick_height,"next_write_version":initial_cursor,"ticks_per_slot":ticks_per_slot,
    });
    worker.shutdown()?;
    ensure!(
        fs::read_dir(scratch)?.next().is_none(),
        "worker scratch remains after shutdown"
    );
    Ok((evidence, started.elapsed().as_millis()))
}

fn main() -> Result<()> {
    ensure!(
        std::env::args_os().len() == 1 && unsafe { libc::geteuid() } == 1000,
        "wrong probe invocation"
    );
    let group_name = format!("/system.slice/{UNIT}");
    let invocation = std::env::var("INVOCATION_ID")?;
    ensure!(
        invocation.len() == 32
            && invocation.bytes().all(|byte| byte.is_ascii_hexdigit())
            && fs::read_to_string("/proc/self/cgroup")?.trim() == format!("0::{group_name}"),
        "probe is outside its admitted service"
    );
    let group = Path::new("/sys/fs/cgroup").join(group_name.trim_start_matches('/'));
    ensure!(
        fs::read_to_string(group.join("memory.max"))?
            .trim()
            .parse::<u64>()?
            == MEMORY_MAX
            && fs::read_to_string(group.join("memory.swap.max"))?.trim() == "0",
        "unexpected memory limit"
    );
    let root = Path::new(SCRATCH);
    let mounts = fs::read_to_string("/proc/self/mountinfo")?;
    ensure!(
        mounts.lines().any(
            |row| row.split_once(" - ").is_some_and(|(front, back)| front
                .split_whitespace()
                .nth(4)
                == Some(SCRATCH)
                && back.starts_with("tmpfs ")
                && back
                    .split_whitespace()
                    .nth(2)
                    .is_some_and(|options| options.split(',').any(|value| value == "noswap")))
        ) && root.metadata()?.uid() == 1000
            && fs::read_dir(root)?.next().is_none(),
        "probe requires fresh private no-swap tmpfs"
    );
    let ledger = Path::new(PACKAGE).join("ledger");
    ensure!(
        !ledger.join("genesis.bin").try_exists()?,
        "unexpected genesis binary"
    );
    verify_file(&ledger.join("genesis.tar.bz2"), GENESIS_SHA, 1 << 20)?;
    let archive = Path::new(SNAPSHOT);
    ensure!(
        archive.canonicalize()? == archive
            && archive.metadata()?.len() == SNAPSHOT_SIZE
            && archive.metadata()?.uid() == 0
            && archive.metadata()?.mode() & 0o222 == 0,
        "unexpected pinned bootstrap file"
    );
    let (stock, stock_millis) = restore(STOCK, STOCK_SHA, &ledger, root)?;
    let (capped, capped_millis) = restore(CAPPED, CAPPED_SHA, &ledger, root)?;
    ensure!(
        stock == capped,
        "capped worker bootstrap differs from the stock checkpoint"
    );
    let peak = fs::read_to_string(group.join("memory.peak"))?
        .trim()
        .parse::<u64>()?;
    println!(
        "{}",
        json!({
            "schema":"foundation-epoch231-capped-bootstrap-parity-v1","invocation_id":invocation,
            "checkpoint":stock,"stock_worker_sha256":STOCK_SHA,"capped_worker_sha256":CAPPED_SHA,
            "snapshot_generation":1633715445119997u64,"snapshot_sha256":SNAPSHOT_SHA,
            "stock_elapsed_millis":stock_millis,"capped_elapsed_millis":capped_millis,
            "cgroup_memory_peak_bytes":peak,"checkpoint_parity":true,"replay_entries_sent":0,
            "full_cohort_resource_qualified":false,"publication_authorized":false
        })
    );
    Ok(())
}
