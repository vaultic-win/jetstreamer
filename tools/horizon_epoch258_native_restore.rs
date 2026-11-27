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
use std::{env, fs, os::unix::fs::MetadataExt, path::Path, time::Instant};

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
    cpus: &'static str,
    ram_work: Option<(&'static str, u64)>,
}

const EPOCH_256: Profile = Profile {
    epoch: 256,
    schema: "foundation-epoch256-native-restore-result-v1",
    unit: "horizon-qualify-256-native-restore-ram-v1.service",
    root: "/home/ubuntu/.jetstreamer-private/qualification-256-native-restore-ram-v1",
    snapshot_name: "snapshot-110591110-4ZsAGhNebPhgWuUjYNuW13gXAAW95aRqiM6DuoVP5csd.tar.zst",
    snapshot_sha: "647b95bebd0a2ebe6f66c3d7822b9bd6e2c40c5357edabf729848cd3a2766f63",
    accounts_hash: "4ZsAGhNebPhgWuUjYNuW13gXAAW95aRqiM6DuoVP5csd",
    snapshot_bytes: 14_976_597_716,
    slot: 110_591_110,
    generation: 1_639_314_144_411_280,
    cpus: "48-55",
    ram_work: Some(("/tmp/foundation-256-native-restore", 96 << 30)),
};

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
    cpus: "56-63",
    ram_work: None,
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
    cpus: "56-63",
    ram_work: None,
};

const WORKER: &str = "/var/lib/jetstreamer/horizon-supported235-shrink-debt-e3f15eb2-v1/jetstreamer-historical-worker-v1-7-15";
const WORKER_SHA: &str = "c3b2c33420bcf6b6809d7f0b43309e7d57d2791a88e2d4074d21d4f636c521e4";
const GENESIS_SHA: &str = "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945";
const GENESIS_SOURCE: &str =
    "/var/lib/jetstreamer/horizon-foundation-holding-probe-input-v1/genesis.tar.bz2";

fn sha(hex: &str) -> Result<[u8; 32]> {
    ensure!(hex.len() == 64 && hex.is_ascii(), "invalid SHA-256");
    let mut digest = [0; 32];
    for (index, part) in hex.as_bytes().chunks_exact(2).enumerate() {
        digest[index] = u8::from_str_radix(std::str::from_utf8(part)?, 16)?;
    }
    Ok(digest)
}

fn prepare_ram_work(work: &Path, capacity: u64) -> Result<()> {
    let work_path = work.to_str().context("non-UTF-8 RAM work path")?;
    let mounts = fs::read_to_string("/proc/self/mountinfo")?;
    let mut matching = mounts.lines().filter_map(|line| {
        let (mount, source) = line.split_once(" - ")?;
        let mut fields = mount.split_whitespace().skip(4);
        (fields.next()? == work_path).then(|| (fields.next(), source))
    });
    let (vfs, source) = matching.next().context("RAM work mount missing")?;
    ensure!(matching.next().is_none(), "ambiguous RAM work mount");
    let mut source = source.split_whitespace();
    ensure!(
        source.next() == Some("tmpfs") && source.next().is_some(),
        "RAM work mount is not tmpfs"
    );
    let vfs = vfs.context("missing RAM work VFS options")?;
    let options = source.next().context("missing tmpfs options")?;
    ensure!(
        ["rw", "nosuid", "nodev"]
            .iter()
            .all(|flag| vfs.split(',').any(|option| option == *flag))
            && options.split(',').any(|option| option == "noswap"),
        "RAM work mount protections differ"
    );
    // The historical client executes a digest-bound worker copy from its private scratch.
    ensure!(
        !vfs.split(',').any(|option| option == "noexec"),
        "RAM work mount cannot execute the bound worker"
    );
    let path = std::ffi::CString::new(work_path)?;
    let mut info = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    ensure!(
        unsafe { libc::statvfs(path.as_ptr(), info.as_mut_ptr()) } == 0,
        "could not measure tmpfs capacity"
    );
    let info = unsafe { info.assume_init() };
    ensure!(
        info.f_blocks.checked_mul(info.f_frsize) == Some(capacity),
        "RAM work volume capacity differs"
    );
    let metadata = fs::metadata(work)?;
    ensure!(
        metadata.uid() == 1000
            && metadata.gid() == 1000
            && metadata.mode() & 0o777 == 0o700
            && fs::read_dir(work)?.next().is_none(),
        "RAM work volume has unexpected ownership or existing data"
    );
    for directory in ["ledger", "scratch", "tmp"] {
        fs::create_dir(work.join(directory))?;
    }
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<_> = env::args_os().skip(1).collect();
    let profile = match args.as_slice() {
        [] => &EPOCH_258,
        [flag] if flag == "--epoch256" => &EPOCH_256,
        [flag] if flag == "--epoch260" => &EPOCH_260,
        _ => anyhow::bail!("usage: horizon_epoch258_native_restore [--epoch256|--epoch260]"),
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
        ("cpuset.cpus.effective", profile.cpus),
    ] {
        ensure!(
            fs::read_to_string(cgroup.join(file))?.trim() == expected,
            "native restore resource scope changed: {file}"
        );
    }
    let root = Path::new(profile.root);
    let work = match profile.ram_work {
        Some((path, capacity)) => {
            let work = Path::new(path);
            prepare_ram_work(work, capacity)?;
            work.to_path_buf()
        }
        None => root.join("work"),
    };
    let ledger = work.join("ledger");
    let scratch = work.join("scratch");
    ensure!(scratch.canonicalize()? == scratch, "aliased scratch");
    ensure!(
        fs::read_dir(&scratch)?.next().is_none(),
        "scratch is not empty"
    );
    let genesis_path = ledger.join("genesis.tar.bz2");
    let genesis = if profile.ram_work.is_some() {
        fs::read(GENESIS_SOURCE)?
    } else {
        fs::read(&genesis_path)?
    };
    ensure!(
        genesis.len() == 20_144 && <[u8; 32]>::from(Sha256::digest(&genesis)) == sha(GENESIS_SHA)?,
        "genesis archive changed"
    );
    if profile.ram_work.is_some() {
        fs::write(&genesis_path, genesis)?;
    }
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
    if profile.ram_work.is_some() {
        let events = fs::read_to_string(cgroup.join("memory.events"))?;
        for event in ["max", "oom", "oom_kill"] {
            ensure!(
                events
                    .lines()
                    .any(|line| line.split_once(' ') == Some((event, "0"))),
                "RAM restore reached the {event} limit"
            );
        }
    }
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
