//! Inspect a pinned Foundation bootstrap without replaying entries.
#[allow(dead_code)]
#[path = "../jetstreamer-node/src/historical.rs"]
mod historical;

use anyhow::{Context, Result, ensure};
use historical::{
    HistoricalInitialization, HistoricalRuntimeClient, SOLANA_V1_7_15_CANDIDATE,
    SnapshotInitialization, WorkerSpawn,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use solana_hash::Hash;
use std::{env, fs, path::Path, time::Instant};

struct Profile {
    epoch: u64,
    schema: &'static str,
    unit: &'static str,
    root: &'static str,
    snapshot_name: &'static str,
    snapshot_sha: &'static str,
    accounts_hash: &'static str,
    snapshot_bytes: u64,
    slot: u64,
    generation: u64,
}

const EPOCH_258: Profile = Profile {
    epoch: 258,
    schema: "foundation-epoch258-native-restore-result-v1",
    unit: "horizon-qualify-258-native-restore-v1.service",
    root: "/home/ubuntu/.jetstreamer-private/qualification-258-native-restore-v1",
    snapshot_name: "snapshot-111455044-9fBFznYNWvfgN5i29pPiGMZqxLhLXuDgdJa2VNremRvt.tar.zst",
    snapshot_sha: "64760a1a400dfa568561c85049703dc41ca085fbd90c04c4c87b3c713ebfcccd",
    accounts_hash: "9fBFznYNWvfgN5i29pPiGMZqxLhLXuDgdJa2VNremRvt",
    snapshot_bytes: 15_229_544_507,
    slot: 111_455_044,
    generation: 1_639_820_713_469_582,
};
const EPOCH_260: Profile = Profile {
    epoch: 260,
    schema: "foundation-epoch260-native-restore-result-v1",
    unit: "horizon-qualify-260-native-restore-v1.service",
    root: "/home/ubuntu/.jetstreamer-private/qualification-260-native-restore-v1",
    snapshot_name: "snapshot-112316757-7bFgHyuoXhyvqhxdZ9bog5i6MrQanLNakePzbmhCLivi.tar.zst",
    snapshot_sha: "13da2e1b74ae44e2e6fc154cc9a74a1252820b668a4c668c94e3e4710a700704",
    accounts_hash: "7bFgHyuoXhyvqhxdZ9bog5i6MrQanLNakePzbmhCLivi",
    snapshot_bytes: 15_521_275_444,
    slot: 112_316_757,
    generation: 1_640_052_082_141_103,
};

const WORKER: &str = "/var/lib/jetstreamer/horizon-supported235-shrink-debt-e3f15eb2-v1/jetstreamer-historical-worker-v1-7-15";
const WORKER_SHA: &str = "c3b2c33420bcf6b6809d7f0b43309e7d57d2791a88e2d4074d21d4f636c521e4";
const GENESIS_SHA: &str = "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945";

fn sha(hex: &str) -> Result<[u8; 32]> {
    ensure!(hex.len() == 64 && hex.is_ascii(), "invalid SHA-256");
    let mut digest = [0; 32];
    for (index, part) in hex.as_bytes().chunks_exact(2).enumerate() {
        digest[index] = u8::from_str_radix(std::str::from_utf8(part)?, 16)?;
    }
    Ok(digest)
}

fn main() -> Result<()> {
    let args: Vec<_> = env::args_os().skip(1).collect();
    let profile = match args.as_slice() {
        [] => &EPOCH_258,
        [flag] if flag == "--epoch260" => &EPOCH_260,
        _ => anyhow::bail!("usage: horizon_epoch258_native_restore [--epoch260]"),
    };
    let group = format!("/system.slice/{}", profile.unit);
    let invocation = env::var("INVOCATION_ID").context("exact systemd invocation required")?;
    ensure!(
        unsafe { libc::geteuid() } == 1000
            && invocation.len() == 32
            && invocation.bytes().all(|byte| byte.is_ascii_hexdigit())
            && fs::read_to_string("/proc/self/cgroup")?.trim() == format!("0::{group}"),
        "wrong native restore invocation"
    );
    let cgroup = Path::new("/sys/fs/cgroup").join(group.trim_start_matches('/'));
    for (file, expected) in [
        ("memory.max", "171798691840"),
        ("memory.swap.max", "0"),
        ("cpuset.cpus.effective", "56-63"),
    ] {
        ensure!(
            fs::read_to_string(cgroup.join(file))?.trim() == expected,
            "native restore resource scope changed: {file}"
        );
    }
    let root = Path::new(profile.root);
    let ledger = root.join("work/ledger");
    let scratch = root.join("work/scratch");
    ensure!(scratch.canonicalize()? == scratch, "aliased scratch");
    ensure!(
        fs::read_dir(&scratch)?.next().is_none(),
        "scratch is not empty"
    );
    let genesis = fs::read(ledger.join("genesis.tar.bz2"))?;
    ensure!(
        genesis.len() == 20_144 && <[u8; 32]>::from(Sha256::digest(&genesis)) == sha(GENESIS_SHA)?,
        "genesis archive changed"
    );
    let account_hash = profile.accounts_hash.parse::<Hash>()?.to_bytes();
    let started = Instant::now();
    let mut worker = HistoricalRuntimeClient::spawn(
        SOLANA_V1_7_15_CANDIDATE,
        WorkerSpawn {
            executable: WORKER.into(),
            initialization: HistoricalInitialization::SnapshotArchive(SnapshotInitialization {
                ledger_path: ledger,
                archive_path: root.join("input").join(profile.snapshot_name),
                expected_slot: profile.slot,
                expected_accounts_hash: account_hash,
                expected_archive_sha256: Some(sha(profile.snapshot_sha)?),
                expected_archive_size: Some(profile.snapshot_bytes),
                scratch_parent: Some(scratch.clone()),
            }),
        },
    )?;
    ensure!(
        worker.executable_sha256() == sha(WORKER_SHA)?,
        "worker digest changed"
    );
    let initial_cursor = worker.initialized().next_write_version;
    let ticks_per_slot = worker.initialized().ticks_per_slot;
    let actual = worker
        .freeze_checkpoint(profile.slot)
        .context("freeze restored checkpoint")?;
    let matches = actual.slot == profile.slot
        && actual.accounts_hash == account_hash
        && actual.slot_complete
        && actual.writes.is_empty()
        && actual.next_write_version == initial_cursor
        && ticks_per_slot == 64;
    worker.shutdown().context("shut down restore worker")?;
    ensure!(
        fs::read_dir(&scratch)?.next().is_none(),
        "scratch remains after shutdown"
    );
    let peak_memory = fs::read_to_string(cgroup.join("memory.peak"))?
        .trim()
        .parse::<u64>()?;
    println!(
        "{}",
        json!({"schema":profile.schema,"epoch":profile.epoch,"invocation_id":invocation,
            "slot":actual.slot,"accounts_hash":Hash::new_from_array(actual.accounts_hash).to_string(),
            "bank_hash":Hash::new_from_array(actual.bank_hash).to_string(),
            "last_blockhash":Hash::new_from_array(actual.last_blockhash).to_string(),
            "transactions_at_root":actual.transaction_count,"capitalization":actual.capitalization,
            "tick_height":actual.tick_height,"next_write_version":actual.next_write_version,
            "worker_sha256":WORKER_SHA,"snapshot_sha256":profile.snapshot_sha,"snapshot_generation":profile.generation,
            "matched_pinned_accounts_root":matches,"replay_entries_sent":0,"worker_shutdown_succeeded":true,
            "cgroup_memory_peak_bytes":peak_memory,"elapsed_millis":started.elapsed().as_millis(),
            "publication_authorized":false})
    );
    ensure!(
        matches,
        "restored checkpoint did not match the pinned accounts root"
    );
    Ok(())
}
