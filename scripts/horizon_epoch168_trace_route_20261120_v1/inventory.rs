//! Read-only measurements for the parent admission, including allocations in closed siblings.
use super::*;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;

const BASE_CAPACITY: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch170-retry7-recovery-20261120-v1/launch-state/epoch170/POST_GUARD_CAPACITY.json";
const BASE_SHA: &str = "b66c665624dd0a4f2e6bde63412ff1373b22eb561fad289021d3d306f8cf1cf5";
const STANDARD_CAP: u64 = 288 << 30;
const ACTIVE_166: &str = "horizon-qualify-independent-cold166-20261120-v1.service";
const ACTIVE_167: &str = "horizon-qualify-167-replacement-local3retry8-20261110-v1.service";
const POSSIBLE_170: &str = "horizon-qualify-170-replacement-local3retry8-20261110-v1.service";

fn tree_bytes(path: &Path, dev: u64, seen: &mut BTreeSet<(u64, u64)>) -> Result<u64> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.dev() == dev,
        "unexpected nested mount: {}",
        path.display()
    );
    if !seen.insert((m.dev(), m.ino())) {
        return Ok(0);
    }
    let mut n = m.blocks().checked_mul(512).context("block count")?;
    if m.is_dir() {
        for e in fs::read_dir(path)? {
            n = n
                .checked_add(tree_bytes(&e?.path(), dev, seen)?)
                .context("tree sum")?;
        }
    }
    Ok(n)
}

fn capacity(dir: &Path) -> Result<(u64, u64)> {
    let name = CString::new(dir.as_os_str().as_bytes())?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    if unsafe { libc::statvfs(name.as_ptr(), stat.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    let stat = unsafe { stat.assume_init() };
    Ok((
        stat.f_frsize
            .checked_mul(stat.f_bavail)
            .context("filesystem size")?,
        tree_bytes(dir, fs::metadata("/home/sol")?.dev(), &mut BTreeSet::new())?,
    ))
}

fn census() -> Result<BTreeMap<String, BTreeMap<String, u32>>> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "host process inventory requires root"
    );
    let mut owners: BTreeMap<String, BTreeMap<String, u32>> = BTreeMap::new();
    for e in fs::read_dir("/proc")? {
        let dir = e?.path();
        let Some(pid) = dir
            .file_name()
            .and_then(|v| v.to_str())
            .and_then(|v| v.parse::<u32>().ok())
        else {
            continue;
        };
        let exe = match fs::read_link(dir.join("exe")) {
            Ok(p) => p,
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => continue,
            Err(e) => return Err(e.into()),
        };
        let Some(name) = exe.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        let role = match name.trim_end_matches(" (deleted)") {
            "jetstreamer-node" => "node",
            "historical-worker" => "worker",
            n if n.starts_with("jetstreamer-historical-worker-") => "worker",
            _ => continue,
        };
        let member = fs::read_to_string(dir.join("cgroup"))?;
        let unit = member
            .trim()
            .strip_prefix("0::/system.slice/")
            .context("unexpected replay cgroup")?;
        ensure!(
            [ACTIVE_166, ACTIVE_167, POSSIBLE_170].contains(&unit),
            "unaccounted live replay actor {unit}"
        );
        let peers = owners.entry(unit.to_owned()).or_default();
        ensure!(
            peers.insert(role.to_owned(), pid).is_none(),
            "duplicate {role} under {unit}"
        );
        if role == "node" {
            // Only parse the fixed public epoch operand; never print or record argv or environment.
            let argv = fs::read(dir.join("cmdline"))?;
            let expected = match unit {
                ACTIVE_166 => "166",
                ACTIVE_167 => "167",
                _ => "170",
            };
            ensure!(
                argv.split(|b| *b == 0).nth(1) == Some(expected.as_bytes()),
                "wrong peer epoch operand"
            );
        }
    }
    for peer in [ACTIVE_166, ACTIVE_167] {
        ensure!(
            owners
                .get(peer)
                .is_some_and(|p| p.contains_key("node") && p.contains_key("worker")),
            "peer {peer} no longer matches accepted topology"
        );
    }
    if let Some(owner) = owners.get(POSSIBLE_170) {
        ensure!(owner.contains_key("node"), "orphan 170 worker");
    }
    Ok(owners)
}

fn memory(key: &str) -> Result<u64> {
    let s = fs::read_to_string("/proc/meminfo")?;
    let line = s
        .lines()
        .find_map(|l| l.strip_prefix(key))
        .context("meminfo key")?;
    let mut vals = line.split_whitespace();
    let v = vals.next().context("meminfo value")?.parse::<u64>()?;
    ensure!(
        vals.next() == Some("kB") && vals.next().is_none(),
        "meminfo unit"
    );
    v.checked_mul(1024).context("memory overflow")
}

pub fn inspect() -> Result<Value> {
    let lane = Path::new(LANE);
    root_dir(lane)?;
    ensure!(fs::metadata(lane)?.ino() == 103878482, "old lane replaced");
    ensure!(
        matches!(fs::symlink_metadata(run_dir()),Err(e) if e.kind()==io::ErrorKind::NotFound),
        "unexpected existing experiment"
    );
    let old = fs::read(BASE_CAPACITY)?;
    ensure!(
        format!("{:x}", Sha256::digest(&old)) == BASE_SHA,
        "retained whole-host comparison changed"
    );
    let base: Value = serde_json::from_slice(&old)?;
    let (disk, allocated) = capacity(lane)?;
    let total = memory("MemTotal:")?;
    let available = memory("MemAvailable:")?;
    let combined = &base["combined_additive_resources"];
    let disk_needed = base["required_DATA_bytes"]
        .as_u64()
        .context("full DATA baseline")?;
    let committed = combined["complete_memory_plus_reserve_bytes"]
        .as_u64()
        .context("aggregate memory baseline")?;
    let available_needed = combined["required_available_memory_bytes"]
        .as_u64()
        .context("available memory baseline")?;
    let headroom = STANDARD_CAP
        .checked_sub(allocated)
        .context("standard root exceeds 288 GiB")?;
    ensure!(
        disk >= disk_needed
            && total >= committed
            && available >= available_needed
            && headroom >= SNAP_BYTES,
        "retained full-host fit or private input copy fails"
    );
    let owners = census()?;
    Ok(
        json!({"schema":"epoch168-private-trace-preparation-measurement-v1","time_unix":std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs(),"source_baseline":BASE_CAPACITY,"source_baseline_sha256":BASE_SHA,"historical_combined_DATA_bytes":disk_needed,"historical_committed_memory_bytes":committed,"historical_required_available_memory_bytes":available_needed,"available_DATA_bytes":disk,"total_memory_bytes":total,"available_memory_bytes":available,"standard_root":LANE,"standard_root_allocated_bytes":allocated,"standard_root_cap":STANDARD_CAP,"remaining_standard_root_growth":headroom,"bootstrap_copy_bytes":SNAP_BYTES,"root_guard_must_cover":LANE,"actor_memory_max_bytes":68u64<<30,"additional_actor_memory_bytes":0,"additional_actor_DATA_bytes":0,"live_nodes_and_workers":owners,"fresh_complete_admission":false,"resource_credit_bytes":0,"launch_authorized":false}),
    )
}
