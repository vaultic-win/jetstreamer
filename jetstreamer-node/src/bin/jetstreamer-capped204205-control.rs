//! Root source capture and independent persistent guard for closed 204/205.
//! Source-only preparation does not run this tool against live producers.
use anyhow::{Context, Result, ensure};
use jetstreamer_node::{
    archive_checksum::{
        ArchiveFileIdentity, archive_file_identity, open_regular_nofollow,
        path_matches_archive_identity,
    },
    capped_control204205::{self as control, Bound, KernelLimits, Metadata, Phase, Plan, Stage},
    capped_prefix204205::{self as capped, hex_sha},
    segment_manifest::sha256_hex_string,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    env,
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Read},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    process::Command,
    thread,
    time::Duration,
};

// Reuse the reviewed descriptor-relative physical-budget algorithm verbatim.
// This does not change or broaden the existing standalone guard's profiles.
#[path = "../../../jetstreamer-utils/src/horizon_standalone_guard_root.rs"]
mod root_budget;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CapturePlan {
    schema: String,
    epoch: u64,
    metadata: Metadata,
    prefix_archive: Bound,
    prefix_bytes: u64,
    output: PathBuf,
}

fn retained_identity(path: &Path, bytes: u64) -> Result<Value> {
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "noncanonical retained input"
    );
    let file = open_regular_nofollow(path)?;
    let identity = archive_file_identity(&file)?;
    let m = file.metadata()?;
    ensure!(
        m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o222 == 0
            && m.len() == bytes
            && path_matches_archive_identity(path, identity)?,
        "retained input is not exact immutable root-owned file"
    );
    Ok(
        json!({"device":m.dev(),"inode":m.ino(),"bytes":m.len(),"mtime":m.mtime(),
        "mtime_nanos":m.mtime_nsec(),"ctime":m.ctime(),"ctime_nanos":m.ctime_nsec(),
        "uid":m.uid(),"mode":m.mode(),"links":m.nlink()}),
    )
}

fn no_checksum(path: &Path) -> Result<()> {
    let sidecar = jetstreamer_node::archive_checksum::archive_checksum_path(path)?;
    ensure!(
        matches!(fs::symlink_metadata(sidecar),Err(e) if e.kind()==std::io::ErrorKind::NotFound),
        "private capped source unexpectedly has a canonical checksum"
    );
    Ok(())
}

fn validate_admission_inputs(p: Plan, plan_sha: &str, self_sha: &str) -> Result<()> {
    p.validate(&p.run_root.join("ledger"))?;
    for evidence in p.metadata.bounds().into_iter().chain([
        &p.source_capture,
        &p.prefix_archive,
        &p.restart_snapshot,
        &p.worker,
        &p.genesis_archive,
    ]) {
        control::require_uid1000_readable(&evidence.path)?;
    }
    control::require_uid1000_traversable(
        p.admission_receipt
            .parent()
            .context("future admission receipt parent")?,
    )?;
    control::require_uid1000_traversable(&p.guard_directory)?;
    ensure!(
        p.guard_sha256 == self_sha,
        "planned independent guard differs from the validating control binary"
    );
    let profile = capped::profile(p.epoch)?;
    let (policy, manifest) = p.metadata.authenticate(p.epoch)?;
    let capture: Value = serde_json::from_slice(&control::sealed(&p.source_capture, 4 << 20)?)?;
    control::validate_capture(&p, &capture, &manifest, control::now_millis()?)?;
    let archive = retained_identity(&p.prefix_archive.path, p.prefix_bytes)?;
    no_checksum(&p.prefix_archive.path)?;
    for key in [
        "device",
        "inode",
        "bytes",
        "mtime",
        "mtime_nanos",
        "ctime",
        "ctime_nanos",
    ] {
        ensure!(
            archive[key] == capture["archive_identity"][key],
            "frozen capture identity differs: {key}"
        );
    }
    let snapshot = retained_identity(&p.restart_snapshot.path, profile.snapshot_bytes)?;
    control::sealed(&p.worker, 256 << 20)?;
    control::sealed(&p.genesis_archive, 10 << 20)?;
    // This is an admission lifecycle closure check. It is never a periodic
    // campaign resource poll, and performs no Bank or archive-body operation.
    let idle = jetstreamer_horizon_observe::source_idle223::observe_capped204205(p.epoch)?;
    no_checksum(&p.prefix_archive.path)?;
    ensure!(
        retained_identity(&p.prefix_archive.path, p.prefix_bytes)? == archive
            && retained_identity(&p.restart_snapshot.path, profile.snapshot_bytes)? == snapshot,
        "retained identities changed during source closure census"
    );
    let output = json!({"schema":"jetstreamer-capped204205-admission-inputs-v1","validated":true,
        "epoch":p.epoch,"plan_sha256":plan_sha,"self_sha256":self_sha,"proposal":p,"input_policy":policy,
        "source_capture_sha256":p.source_capture.sha256,"manifest_content_sha256":sha256_hex_string(&manifest.content_sha256()?),
        "source_idle":idle,"archive_identity":archive,"retained_snapshot_identity":snapshot,
        "resource_samples_taken":0,"source_idle_censuses_taken":1,"archive_body_read":false,"snapshot_body_read":false,
        "native_initialized":false,"fresh_admission_passed":false,"guard_proven":false,"suffix_execution_authorized":false,
        "canonical_sidecar_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false});
    let bytes = serde_json::to_vec(&output)?;
    ensure!(
        bytes.len() <= 64 << 10,
        "admission input policy response exceeds64KiB"
    );
    println!("{}", std::str::from_utf8(&bytes)?);
    Ok(())
}

fn capture(p: CapturePlan) -> Result<()> {
    let profile = capped::profile(p.epoch)?;
    ensure!(
        p.schema == "jetstreamer-capped204205-source-capture-plan-v1"
            && p.prefix_archive.path == profile.prefix_path()
            && p.metadata.original_launch.path == Path::new(profile.launch_path)
            && p.metadata.original_launch.sha256 == profile.launch_sha256
            && p.output
                .file_name()
                .is_some_and(|s| s == "source-capture.json")
            && p.output.parent().and_then(Path::parent) == Some(Path::new("/var/lib/jetstreamer"))
            && p.output
                .parent()
                .and_then(Path::file_name)
                .and_then(|s| s.to_str())
                .and_then(|s| s.strip_prefix(&format!("horizon-capped-capture-{}-", p.epoch)))
                .is_some_and(
                    |s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                ),
        "invalid source capture scope/output"
    );
    // Mandatory genuine natural-success/reader/PID1 evidence comes first.
    let (_, manifest) = p.metadata.authenticate(p.epoch)?;
    no_checksum(&p.prefix_archive.path)?;
    ensure!(
        manifest.archive_sha256 == capped::parse_sha(&p.prefix_archive.sha256)?
            && p.prefix_bytes > 0,
        "capture archive differs from actual producer manifest"
    );
    for evidence in p.metadata.bounds() {
        ensure!(
            !evidence.path.starts_with(p.output.parent().unwrap()),
            "capture overlaps metadata input"
        );
    }
    let idle_before = jetstreamer_horizon_observe::source_idle223::observe_capped204205(p.epoch)?;
    let file = open_regular_nofollow(&p.prefix_archive.path)?;
    let original = file.metadata()?;
    ensure!(
        p.prefix_archive.path.canonicalize()? == p.prefix_archive.path
            && original.nlink() == 1
            && original.len() == p.prefix_bytes
            && matches!(original.uid(), 0 | 1000)
            && original.mode() & 0o022 == 0,
        "source is not the exact original regular retained prefix"
    );
    ensure!(
        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "source archive is still locked"
    );
    let manifest_file = open_regular_nofollow(&profile.prefix_manifest_path())?;
    let original_manifest = manifest_file.metadata()?;
    ensure!(
        original_manifest.nlink() == 1
            && original_manifest.len() <= 1 << 20
            && matches!(original_manifest.uid(), 0 | 1000)
            && original_manifest.mode() & 0o022 == 0,
        "unsafe original manifest"
    );
    let mut bytes = Vec::new();
    (&manifest_file)
        .take((1 << 20) + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        hex_sha(&bytes) == p.metadata.prefix_manifest.sha256,
        "original manifest differs from independently read and captured metadata"
    );
    // Content is never rewritten. Freeze only after genuine terminal success,
    // current whole-root idleness and exact original-source identity checks.
    for source in [&file, &manifest_file] {
        ensure!(
            unsafe { libc::fchown(source.as_raw_fd(), 0, 0) } == 0,
            "cannot freeze source owner"
        );
        source.set_permissions(fs::Permissions::from_mode(0o444))?;
        source.sync_all()?;
    }
    File::open(p.prefix_archive.path.parent().context("source parent")?)?.sync_all()?;
    let frozen = archive_file_identity(&file)?;
    let frozen_manifest = archive_file_identity(&manifest_file)?;
    let idle_after = jetstreamer_horizon_observe::source_idle223::observe_capped204205(p.epoch)?;
    no_checksum(&p.prefix_archive.path)?;
    ensure!(
        path_matches_archive_identity(&p.prefix_archive.path, frozen)?
            && archive_file_identity(&file)? == frozen
            && path_matches_archive_identity(&profile.prefix_manifest_path(), frozen_manifest)?
            && archive_file_identity(&manifest_file)? == frozen_manifest,
        "source changed during freeze/idle capture"
    );
    let m = file.metadata()?;
    let value = json!({"schema":"jetstreamer-capped204205-source-capture-v1","epoch":p.epoch,
        "recorded_unix_millis":control::now_millis()?,"original_unit":profile.original_unit,
        "original_invocation_id":profile.original_invocation,"prefix_archive":p.prefix_archive,
        "prefix_bytes":p.prefix_bytes,"prefix_manifest_sha256":p.metadata.prefix_manifest.sha256,
        "manifest_content_sha256":sha256_hex_string(&manifest.content_sha256()?),
        "archive_identity":{"device":m.dev(),"inode":m.ino(),"bytes":m.len(),"mtime":m.mtime(),
            "mtime_nanos":m.mtime_nsec(),"ctime":m.ctime(),"ctime_nanos":m.ctime_nsec()},
        "frozen_root_owned_readonly":true,"metadata_policy_rederived":true,
        "idle_before":idle_before,"idle_after":idle_after,"archive_body_read":false,
        "publication_authorized":false,"r2_mutations":false});
    control::atomic_json(&p.output, &value, 0, false)?;
    println!(
        "{}",
        json!({"capture":p.output,"sha256":hex_sha(&control::json_bytes(&value)?),"r2_mutations":false})
    );
    Ok(())
}

fn state(unit: &str) -> Result<BTreeMap<String, String>> {
    let output = Command::new("/usr/bin/systemctl").env("LC_ALL", "C").args([
        "show", unit, "--property=Id,LoadState,InvocationID,ActiveState,SubState,MainPID,NRestarts,Restart,KillMode,Delegate,ControlGroup,User,MemoryMax,MemoryHigh,MemorySwapMax,TasksMax,Result,ExecMainStatus",
    ]).output()?;
    ensure!(
        output.status.success() && output.stdout.len() <= 16384,
        "guard service query failed"
    );
    let mut fields = BTreeMap::new();
    for line in std::str::from_utf8(&output.stdout)?.lines() {
        let (k, v) = line.split_once('=').context("malformed service property")?;
        ensure!(
            fields.insert(k.into(), v.into()).is_none(),
            "duplicate service property"
        );
    }
    ensure!(
        fields.get("Id").is_some_and(|s| s == unit),
        "wrong unit identity"
    );
    Ok(fields)
}

fn authenticate(s: &BTreeMap<String, String>, iid: &str, uid: &str) -> Result<u32> {
    let get = |k| s.get(k).map(String::as_str).unwrap_or("");
    ensure!(
        control::invocation(iid)
            && get("LoadState") == "loaded"
            && get("InvocationID") == iid
            && get("NRestarts") == "0"
            && get("Restart") == "no"
            && get("KillMode") == "control-group"
            && get("Delegate") == "no"
            && get("User") == uid,
        "wrong standalone owner/invocation/restart/control-group/UID"
    );
    let pid = get("MainPID").parse::<u32>()?;
    ensure!(
        pid > 1 && pid <= i32::MAX as u32 && matches!(get("ActiveState"), "active" | "activating"),
        "guard owner is not active"
    );
    Ok(pid)
}

fn cgroup_processes(path: &Path, out: &mut Vec<u32>, depth: usize) -> Result<()> {
    ensure!(
        depth <= 64 && path.canonicalize()? == path && fs::symlink_metadata(path)?.is_dir(),
        "unsafe guard cgroup"
    );
    for line in fs::read_to_string(path.join("cgroup.procs"))?.lines() {
        out.push(line.parse()?);
        ensure!(out.len() <= 1024, "oversized continuation cgroup");
    }
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            cgroup_processes(&entry.path(), out, depth + 1)?;
        }
    }
    Ok(())
}

fn free_bytes(path: &Path) -> Result<u64> {
    let path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())?;
    let mut value: libc::statvfs = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe { libc::statvfs(path.as_ptr(), &mut value) } == 0,
        "statvfs failed"
    );
    value
        .f_bavail
        .checked_mul(value.f_frsize)
        .context("free bytes overflow")
}

fn bus_unit_path(unit: &str) -> String {
    let mut path = String::from("/org/freedesktop/systemd1/unit/");
    for byte in unit.bytes() {
        if byte.is_ascii_alphanumeric() {
            path.push(byte as char);
        } else {
            path.push_str(&format!("_{byte:02x}"));
        }
    }
    path
}
fn manager_usec(unit: &str, property: &str) -> Result<u64> {
    let output = Command::new("/usr/bin/busctl")
        .args([
            "--system",
            "get-property",
            "org.freedesktop.systemd1",
            &bus_unit_path(unit),
            "org.freedesktop.systemd1.Service",
            property,
        ])
        .output()?;
    ensure!(
        output.status.success() && output.stdout.len() <= 1024,
        "cannot obtain exact raw manager microseconds"
    );
    let text = std::str::from_utf8(&output.stdout)?;
    let parts: Vec<_> = text.split_whitespace().collect();
    ensure!(
        parts.len() == 2 && parts[0] == "t",
        "malformed raw manager microsecond property"
    );
    Ok(parts[1].parse()?)
}
fn kernel_number(root: &Path, name: &str) -> Result<u64> {
    let text = fs::read_to_string(root.join(name))?;
    ensure!(text.len() <= 1024, "oversized kernel cgroup property");
    Ok(text.trim().parse()?)
}
#[derive(Clone, Copy)]
struct KernelValues<'a> {
    page: u64,
    maximum: u64,
    high: u64,
    swap: u64,
    tasks: u64,
    cpu: &'a str,
    runtime: u64,
    quota_usec: u64,
}
fn validate_kernel_values(
    limits: &KernelLimits,
    manager: &BTreeMap<String, String>,
    actual: &KernelValues<'_>,
) -> Result<()> {
    let KernelValues {
        page,
        maximum,
        high,
        swap,
        tasks,
        cpu,
        runtime,
        quota_usec,
    } = *actual;
    ensure!(
        page.is_power_of_two() && page >= 4096,
        "invalid host page size"
    );
    for (key, expected) in [
        ("MemoryMax", limits.requested_memory_max_bytes),
        ("MemoryHigh", limits.requested_memory_high_bytes),
        ("MemorySwapMax", limits.memory_swap_max_bytes),
        ("TasksMax", limits.tasks_max),
    ] {
        ensure!(
            manager.get(key).and_then(|s| s.parse::<u64>().ok()) == Some(expected),
            "requested manager limit changed: {key}"
        );
    }
    ensure!(
        maximum == limits.requested_memory_max_bytes / page * page
            && maximum > 0
            && high == limits.requested_memory_high_bytes / page * page
            && high > 0
            && swap == 0
            && tasks == limits.tasks_max
            && runtime == limits.runtime_max_usec
            && quota_usec == limits.cpu_quota_usec_per_second,
        "effective kernel/runtime limits differ from actual admitted proposal"
    );
    let fields: Vec<_> = cpu.split_whitespace().collect();
    ensure!(fields.len() == 2, "malformed kernel CPU quota/period");
    let quota = fields[0].parse::<u64>()?;
    let period = fields[1].parse::<u64>()?;
    ensure!(
        period > 0
            && u128::from(quota) * 1_000_000
                == u128::from(limits.cpu_quota_usec_per_second) * u128::from(period),
        "effective CPU quota/period ratio differs"
    );
    Ok(())
}
fn kernel_sample(p: &Plan, s: &BTreeMap<String, String>, limits: &KernelLimits) -> Result<Value> {
    let root = Path::new("/sys/fs/cgroup/system.slice").join(&p.producer_unit);
    ensure!(
        root.canonicalize()? == root && fs::symlink_metadata(&root)?.is_dir(),
        "unsafe exact producer cgroup"
    );
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    ensure!(page > 0, "cannot determine kernel page size");
    let page = page as u64;
    let maximum = kernel_number(&root, "memory.max")?;
    let high = kernel_number(&root, "memory.high")?;
    let swap = kernel_number(&root, "memory.swap.max")?;
    let tasks = kernel_number(&root, "pids.max")?;
    let cpu = fs::read_to_string(root.join("cpu.max"))?;
    ensure!(cpu.len() <= 1024, "oversized kernel CPU limit");
    let runtime = manager_usec(&p.producer_unit, "RuntimeMaxUSec")?;
    let quota_usec = manager_usec(&p.producer_unit, "CPUQuotaPerSecUSec")?;
    validate_kernel_values(
        limits,
        s,
        &KernelValues {
            page,
            maximum,
            high,
            swap,
            tasks,
            cpu: &cpu,
            runtime,
            quota_usec,
        },
    )?;
    Ok(
        json!({"kernel_memory_max_bytes":maximum,"kernel_memory_high_bytes":high,
        "memory_swap_max_bytes":swap,"tasks_max":tasks,"cpu_max":cpu.trim(),
        "runtime_max_usec":runtime,"cpu_quota_usec_per_second":quota_usec,"host_page_size_bytes":page}),
    )
}

fn rss(pid: u32) -> Result<u64> {
    let text = fs::read_to_string(format!("/proc/{pid}/status"))?;
    ensure!(text.len() <= 65536, "oversized process status");
    let value = text
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))
        .context("RSS missing")?;
    let fields: Vec<_> = value.split_whitespace().collect();
    ensure!(fields.len() == 2 && fields[1] == "kB", "malformed RSS");
    fields[0]
        .parse::<u64>()?
        .checked_mul(1024)
        .context("RSS overflow")
}

fn start_time(pid: u32) -> Result<String> {
    let text = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    ensure!(text.len() <= 65536, "oversized process stat");
    Ok(text
        .rsplit_once(')')
        .context("malformed process stat")?
        .1
        .split_whitespace()
        .nth(19)
        .context("process starttime missing")?
        .to_owned())
}

#[derive(Debug)]
struct CensusChurn;
impl std::fmt::Display for CensusChurn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("complete process census or final identity changed")
    }
}
impl std::error::Error for CensusChurn {}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProcessIdentity {
    pid: u32,
    start: String,
    executable: PathBuf,
    mapped: ArchiveFileIdentity,
}

fn final_process_identity(pid: u32) -> Result<ProcessIdentity> {
    let value = ProcessIdentity {
        pid,
        start: start_time(pid)?,
        executable: fs::read_link(format!("/proc/{pid}/exe"))?,
        mapped: archive_file_identity(&File::open(format!("/proc/{pid}/exe"))?)?,
    };
    if start_time(pid)? != value.start
        || fs::read_link(format!("/proc/{pid}/exe"))? != value.executable
    {
        return Err(CensusChurn.into());
    }
    Ok(value)
}

fn close_census<F>(
    before: &[u32],
    after: &[u32],
    records: &[ProcessIdentity],
    mut current: F,
) -> Result<()>
where
    F: FnMut(u32) -> Result<ProcessIdentity>,
{
    if before != after || records.iter().map(|v| v.pid).collect::<Vec<_>>() != before {
        return Err(CensusChurn.into());
    }
    for record in records {
        if current(record.pid)? != *record {
            return Err(CensusChurn.into());
        }
    }
    Ok(())
}

fn process_sample(
    p: &Plan,
    s: &BTreeMap<String, String>,
    pid: u32,
    executables: &mut BTreeMap<PathBuf, ArchiveFileIdentity>,
) -> Result<Value> {
    let expected_group = format!("/system.slice/{}", p.producer_unit);
    ensure!(
        s.get("ControlGroup") == Some(&expected_group),
        "guard producer escaped exact cgroup"
    );
    let mut pids = Vec::new();
    cgroup_processes(
        &Path::new("/sys/fs/cgroup").join(&expected_group[1..]),
        &mut pids,
        0,
    )?;
    pids.sort_unstable();
    pids.dedup();
    let before_pids = pids.clone();
    let mut records = Vec::new();
    let mut executable_handles = Vec::new();
    ensure!(
        pids.contains(&pid),
        "main PID absent from exact producer cgroup"
    );
    let mut workers = Vec::new();
    let mut total_rss = 0u64;
    for process in pids {
        let start = start_time(process)?;
        let exe = fs::read_link(format!("/proc/{process}/exe"))?;
        let expected = if process == pid {
            &p.node_sha256
        } else {
            ensure!(
                exe == p.worker.path,
                "unqualified process in continuation cgroup"
            );
            &p.worker.sha256
        };
        // Executables are small retained immutable inputs, not archive bodies.
        // Revalidate the actual mapped inode as well as its canonical pathname.
        let pinned = open_regular_nofollow(&exe)?;
        let identity = archive_file_identity(&pinned)?;
        if let Some(known) = executables.get(&exe) {
            ensure!(
                *known == identity,
                "pinned executable changed after initial full hash"
            );
        } else {
            let bytes = control::stable_read(&exe, 256 << 20, 0, true)?;
            ensure!(
                hex_sha(&bytes) == *expected
                    && archive_file_identity(&pinned)? == identity
                    && path_matches_archive_identity(&exe, identity)?,
                "running node/worker executable differs"
            );
            executables.insert(exe.clone(), identity);
        }
        let actual = File::open(format!("/proc/{process}/exe"))?;
        let mapped = archive_file_identity(&actual)?;
        ensure!(
            path_matches_archive_identity(&exe, mapped)?,
            "mapped executable differs from pinned path"
        );
        let resident = rss(process)?;
        total_rss = total_rss
            .checked_add(resident)
            .context("lane RSS overflow")?;
        if process != pid {
            let mut count = 0u64;
            for line in BufReader::new(File::open(format!("/proc/{process}/maps"))?).lines() {
                line?;
                count += 1;
                ensure!(count <= p.maximum_worker_vmas, "worker VMA ceiling");
            }
            workers
                .push(json!({"pid":process,"rss_bytes":resident,"vmas":count,"start_time":start}));
        }
        if start_time(process)? != start
            || fs::read_link(format!("/proc/{process}/exe"))? != exe
            || archive_file_identity(&actual)? != mapped
        {
            return Err(CensusChurn.into());
        }
        records.push(ProcessIdentity {
            pid: process,
            start,
            executable: exe,
            mapped,
        });
        executable_handles.push(actual);
    }
    let mut after_pids = Vec::new();
    cgroup_processes(
        &Path::new("/sys/fs/cgroup").join(&expected_group[1..]),
        &mut after_pids,
        0,
    )?;
    after_pids.sort_unstable();
    after_pids.dedup();
    close_census(&before_pids, &after_pids, &records, final_process_identity)?;
    for (handle, record) in executable_handles.iter().zip(&records) {
        ensure!(
            archive_file_identity(handle)? == record.mapped,
            "retained executable descriptor changed after full census"
        );
    }
    ensure!(
        workers.len() <= 1 && total_rss <= p.maximum_process_rss_bytes,
        "multiple workers or complete lane RSS ceiling"
    );
    Ok(json!({"workers":workers,"total_process_rss_bytes":total_rss,"main_pid":pid}))
}

fn validate_stage(previous: Option<&Phase>, next: &Phase, workers: usize) -> Result<()> {
    if let Some(previous) = previous {
        ensure!(
            next.stage >= previous.stage
                && if next.stage == previous.stage {
                    next.started_unix_millis == previous.started_unix_millis
                } else {
                    next.started_unix_millis >= previous.started_unix_millis
                },
            "continuation phase rewound or deadline renewed"
        );
    }
    // NativeRestore includes the persistent suffix worker's complete lifecycle.
    // Its pre-entry barrier remains in the producer; this is no authorization
    // to skip it. Zero workers is expected only in finite pinned phases.
    ensure!(
        workers <= 1 && (next.stage == Stage::NativeRestore || workers == 0),
        "worker running outside exact restore/suffix phase"
    );
    Ok(())
}

fn completed_owner(
    p: &Plan,
    plan_sha: &str,
    iid: &str,
    s: &BTreeMap<String, String>,
) -> Result<bool> {
    for (key, value) in [
        ("LoadState", "loaded"),
        ("InvocationID", iid),
        ("MainPID", "0"),
        ("ActiveState", "inactive"),
        ("SubState", "dead"),
        ("NRestarts", "0"),
        ("Restart", "no"),
        ("Result", "success"),
        ("ExecMainStatus", "0"),
    ] {
        if s.get(key).map(String::as_str) != Some(value) {
            return Ok(false);
        }
    }
    let phase: Phase =
        serde_json::from_slice(&control::stable_read(&p.phase_path(), 16384, 1000, true)?)?;
    Ok(phase.stage == Stage::Complete
        && phase
            .validate(p, plan_sha, iid, control::now_millis()?)
            .is_ok())
}

fn guard(p: Plan, plan_sha: &str, producer_iid: &str) -> Result<()> {
    let admission: Value = serde_json::from_slice(&control::stable_read(
        &p.admission_receipt,
        4 << 20,
        0,
        true,
    )?)?;
    control::validate_admission(&p, plan_sha, &admission, control::now_millis()?)?;
    let limits: KernelLimits = serde_json::from_value(admission["kernel_limits"].clone())?;
    let resource_proposal: Bound = serde_json::from_value(admission["resource_proposal"].clone())?;
    let proposal: Value = serde_json::from_slice(&control::sealed(&resource_proposal, 8 << 20)?)?;
    let guard_memory = proposal["guard_memory_max_bytes"]
        .as_u64()
        .context("independent guard memory reservation")?;
    ensure!(
        (1..=1 << 30).contains(&guard_memory),
        "invalid independent guard memory cap"
    );
    ensure!(
        proposal["kernel_limits"] == admission["kernel_limits"]
            && proposal["producer_plan"]["sha256"] == plan_sha,
        "admitted resource proposal does not bind actual plan/kernel limits"
    );
    let guard_iid =
        env::var("INVOCATION_ID").context("guard must run in independent systemd service")?;
    ensure!(
        authenticate(&state(&p.guard_unit)?, &guard_iid, "root")? == std::process::id(),
        "wrong independent guard process"
    );
    ensure!(
        control::invocation(producer_iid),
        "invalid actual producer invocation"
    );
    let directory = fs::symlink_metadata(&p.guard_directory)?;
    ensure!(
        p.guard_directory.canonicalize()? == p.guard_directory
            && directory.is_dir()
            && directory.uid() == 0
            && directory.mode() & 0o022 == 0,
        "unsafe guard evidence directory"
    );
    let lease = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(p.guard_directory.join("guard.lock"))?;
    let lock = lease.metadata()?;
    ensure!(
        lock.uid() == 0
            && lock.nlink() == 1
            && lock.mode() & 0o077 == 0
            && unsafe { libc::flock(lease.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "guard lease occupied or unsafe"
    );
    let intent = p.guard_directory.join("stop-intent.json");
    ensure!(
        matches!(fs::symlink_metadata(&intent), Err(e) if e.kind() == std::io::ErrorKind::NotFound),
        "prior guard trip is terminal and cannot be renewed"
    );
    let mut previous: Option<Phase> = None;
    let mut executables = BTreeMap::new();
    loop {
        let before = state(&p.producer_unit)?;
        // Natural completed phase may be observed before or after PID1 reaps
        // the producer. This guard never calls success a publication receipt.
        if completed_owner(&p, plan_sha, producer_iid, &before)? {
            return Ok(());
        }
        let pid = authenticate(&before, producer_iid, "ubuntu")?;
        let observed = (|| -> Result<(Phase, Value, u64, root_budget::Observation, Value)> {
            let guard_state = state(&p.guard_unit)?;
            ensure!(
                authenticate(&guard_state, &guard_iid, "root")? == std::process::id()
                    && guard_state
                        .get("MemoryMax")
                        .and_then(|s| s.parse::<u64>().ok())
                        == Some(guard_memory),
                "independent guard owner or admitted hard memory cap changed"
            );
            let guard_group = format!("/system.slice/{}", p.guard_unit);
            ensure!(
                guard_state.get("ControlGroup") == Some(&guard_group),
                "independent guard cgroup differs"
            );
            let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
            ensure!(page > 0, "guard kernel page size unavailable");
            let page = page as u64;
            ensure!(
                kernel_number(
                    &Path::new("/sys/fs/cgroup").join(&guard_group[1..]),
                    "memory.max"
                )? == guard_memory / page * page
                    && guard_memory / page > 0,
                "independent guard kernel memory cap differs"
            );
            let mut observation = None;
            for attempt in 0..3 {
                let phase: Phase = serde_json::from_slice(&control::stable_read(
                    &p.phase_path(),
                    16384,
                    1000,
                    true,
                )?)?;
                phase.validate(&p, plan_sha, producer_iid, control::now_millis()?)?;
                match process_sample(&p, &before, pid, &mut executables) {
                    Ok(value) => {
                        let after: Phase = serde_json::from_slice(&control::stable_read(
                            &p.phase_path(),
                            16384,
                            1000,
                            true,
                        )?)?;
                        if phase == after {
                            observation = Some((phase, value));
                            break;
                        }
                        ensure!(
                            attempt < 2,
                            "phase kept changing across complete process censuses"
                        );
                    }
                    Err(error)
                        if attempt < 2
                            && (error.downcast_ref::<CensusChurn>().is_some()
                                || error.downcast_ref::<std::io::Error>().is_some_and(|e| {
                                    matches!(e.raw_os_error(), Some(libc::ENOENT | libc::ESRCH))
                                })) =>
                    {
                        thread::sleep(Duration::from_millis(20));
                    }
                    Err(error) => return Err(error),
                }
            }
            let (phase, processes) =
                observation.context("stable phase/process census did not complete")?;
            validate_stage(
                previous.as_ref(),
                &phase,
                processes["workers"]
                    .as_array()
                    .context("worker sample")?
                    .len(),
            )?;
            let free = free_bytes(&p.run_root)?;
            ensure!(
                free >= p.protected_existing_floor_bytes,
                "protected filesystem floor"
            );
            let physical = root_budget::observe(&p.run_root, p.maximum_root_physical_bytes)?;
            ensure!(
                !physical.exceeds_budget,
                "complete continuation root physical ceiling"
            );
            ensure!(
                state(&p.producer_unit)? == before,
                "producer changed during guard sample"
            );
            let kernel = kernel_sample(&p, &before, &limits)?;
            Ok((phase, processes, free, physical, kernel))
        })();
        let now = control::now_millis()?;
        match observed {
            Ok((phase, processes, free, physical, kernel)) => {
                let heartbeat = json!({"schema":"jetstreamer-capped204205-guard-heartbeat-v1",
                    "epoch":p.epoch,"plan_sha256":plan_sha,"recorded_unix_millis":now,
                    "producer_unit":p.producer_unit,"producer_invocation_id":producer_iid,
                    "guard_unit":p.guard_unit,"guard_invocation_id":guard_iid,"guard_sha256":p.guard_sha256,
                    "producer_stop_enabled":true,"trip":false,"available_bytes":free,
                    "minimum_free_bytes":p.protected_existing_floor_bytes,"maximum_root_physical_bytes":p.maximum_root_physical_bytes,
                    "maximum_process_rss_bytes":p.maximum_process_rss_bytes,"maximum_worker_vmas":p.maximum_worker_vmas,
                    "phase":phase,"processes":processes,"root_physical_observation":physical,
                    "kernel_limits":limits,"actual_kernel_limits":kernel,"resource_proposal":resource_proposal,
                    "guard_memory_max_bytes":guard_memory,
                    "remote_mutations":false,"r2_mutations":false});
                control::atomic_json(&p.heartbeat_path(), &heartbeat, 0, true)?;
                if previous.is_none() {
                    control::atomic_json(
                        &p.guard_directory.join("first-fire.json"),
                        &heartbeat,
                        0,
                        false,
                    )?;
                }
                previous = Some(phase);
            }
            Err(error) => {
                let current = state(&p.producer_unit)?;
                if completed_owner(&p, plan_sha, producer_iid, &current)? {
                    return Ok(());
                }
                ensure!(
                    authenticate(&current, producer_iid, "ubuntu")? == pid,
                    "guard refuses stop intent or signal for a terminal/replacement owner"
                );
                let value = json!({"schema":"jetstreamer-capped204205-guard-stop-intent-v1","epoch":p.epoch,
                    "plan_sha256":plan_sha,"producer_invocation_id":producer_iid,"guard_invocation_id":guard_iid,
                    "recorded_unix_millis":now,"reason":error.to_string(),"r2_mutations":false});
                control::atomic_json(&intent, &value, 0, false)?;
                let current = state(&p.producer_unit)?;
                ensure!(
                    authenticate(&current, producer_iid, "ubuntu")? == pid,
                    "guard refuses to stop a replacement owner"
                );
                let stopped = Command::new("/usr/bin/systemctl")
                    .args(["stop", &p.producer_unit])
                    .output()?;
                ensure!(
                    stopped.status.success(),
                    "cannot stop exact tripped producer"
                );
                anyhow::bail!("guard stopped bound producer: {error}");
            }
        }
        thread::sleep(Duration::from_secs(5));
    }
}

fn run() -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "root lifecycle control required"
    );
    let args: Vec<String> = env::args().skip(1).collect();
    ensure!(
        (args.len() == 6 || args.len() == 8)
            && args[2] == "--plan-sha256"
            && args[4] == "--self-sha256",
        "usage: control capture|validate-plan|guard PLAN --plan-sha256 SHA --self-sha256 SHA [--producer-iid IID]"
    );
    ensure!(
        hex_sha(&fs::read("/proc/self/exe")?) == args[5],
        "control executable differs"
    );
    let bytes = control::sealed(
        &Bound {
            path: args[1].clone().into(),
            sha256: args[3].clone(),
        },
        4 << 20,
    )?;
    match args[0].as_str() {
        "validate-plan" => {
            ensure!(
                args.len() == 6,
                "validate-plan does not accept guard arguments"
            );
            control::require_uid1000_readable(Path::new(&args[1]))?;
            validate_admission_inputs(serde_json::from_slice(&bytes)?, &args[3], &args[5])
        }
        "capture" => {
            ensure!(args.len() == 6, "capture does not accept guard arguments");
            capture(serde_json::from_slice(&bytes)?)
        }
        "guard" => {
            ensure!(
                args.len() == 8 && args[6] == "--producer-iid",
                "guard requires actual producer IID"
            );
            let p: Plan = serde_json::from_slice(&bytes)?;
            p.validate(&p.run_root.join("ledger"))?;
            ensure!(p.guard_sha256 == args[5], "wrong planned guard executable");
            guard(p, &args[3], &args[7])
        }
        _ => anyhow::bail!("only explicit capture and guard modes are admitted"),
    }
}
fn main() {
    if let Err(error) = run() {
        eprintln!("capped 204/205 lifecycle: {error:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn phase(stage: Stage, time: u64) -> Phase {
        Phase {
            schema: "jetstreamer-capped204205-continuation-phase-v1".into(),
            epoch: 204,
            plan_sha256: "a".repeat(64),
            invocation_id: "b".repeat(32),
            stage,
            started_unix_millis: time,
        }
    }
    #[test]
    fn workerless_stages_are_finite_and_cannot_be_renewed_or_rewound() {
        let previous = phase(Stage::PrefixValidation, 100);
        validate_stage(Some(&previous), &previous, 0).unwrap();
        assert!(validate_stage(Some(&previous), &phase(Stage::PrefixValidation, 101), 0).is_err());
        assert!(validate_stage(Some(&previous), &phase(Stage::WaitingForGuard, 100), 0).is_err());
        assert!(validate_stage(Some(&previous), &previous, 1).is_err());
        validate_stage(Some(&previous), &phase(Stage::NativeRestore, 101), 1).unwrap();
        assert!(validate_stage(None, &phase(Stage::NativeRestore, 101), 2).is_err());
        assert!(validate_stage(None, &phase(Stage::Assembly, 101), 1).is_err());
    }
    #[test]
    fn exact_service_authentication_rejects_restarts_foreign_users_and_replacement_owners() {
        let mut good = BTreeMap::new();
        for (key, value) in [
            ("LoadState", "loaded"),
            ("NRestarts", "0"),
            ("Restart", "no"),
            ("KillMode", "control-group"),
            ("Delegate", "no"),
            ("User", "ubuntu"),
            ("MainPID", "4242"),
            ("ActiveState", "active"),
        ] {
            good.insert(key.into(), value.into());
        }
        good.insert("InvocationID".into(), "b".repeat(32));
        assert_eq!(
            authenticate(&good, &"b".repeat(32), "ubuntu").unwrap(),
            4242
        );
        for (key, value) in [
            ("LoadState", "not-found"),
            ("NRestarts", "1"),
            ("Restart", "on-failure"),
            ("KillMode", "process"),
            ("Delegate", "yes"),
            ("User", "root"),
            ("MainPID", "0"),
            ("MainPID", "1"),
            ("ActiveState", "inactive"),
            ("InvocationID", "foreign"),
        ] {
            let mut bad = good.clone();
            bad.insert(key.into(), value.into());
            assert!(
                authenticate(&bad, &"b".repeat(32), "ubuntu").is_err(),
                "{key}"
            );
        }
        assert!(authenticate(&good, &"c".repeat(32), "ubuntu").is_err());
    }
    #[test]
    fn kernel_limits_match_requested_values_page_rounding_cpu_ratio_and_runtime() {
        let limits = KernelLimits {
            requested_memory_max_bytes: 225_000_000_000,
            requested_memory_high_bytes: 150_000_000_000,
            memory_swap_max_bytes: 0,
            tasks_max: 512,
            cpu_quota_usec_per_second: 8_000_000,
            runtime_max_usec: 86_400_000_000,
        };
        let manager = BTreeMap::from([
            (
                "MemoryMax".into(),
                limits.requested_memory_max_bytes.to_string(),
            ),
            (
                "MemoryHigh".into(),
                limits.requested_memory_high_bytes.to_string(),
            ),
            ("MemorySwapMax".into(), "0".into()),
            ("TasksMax".into(), "512".into()),
        ]);
        let good = KernelValues {
            page: 4096,
            maximum: 225_000_000_000 / 4096 * 4096,
            high: 150_000_000_000 / 4096 * 4096,
            swap: 0,
            tasks: 512,
            cpu: "800000 100000",
            runtime: 86_400_000_000,
            quota_usec: 8_000_000,
        };
        validate_kernel_values(&limits, &manager, &good).unwrap();
        for bad in [
            KernelValues {
                maximum: good.maximum + 4096,
                ..good
            },
            KernelValues {
                high: good.high + 4096,
                ..good
            },
            KernelValues { swap: 1, ..good },
            KernelValues { tasks: 513, ..good },
            KernelValues {
                cpu: "max 100000",
                ..good
            },
            KernelValues {
                cpu: "800001 100000",
                ..good
            },
            KernelValues { cpu: "0 0", ..good },
            KernelValues {
                runtime: good.runtime - 1,
                ..good
            },
            KernelValues {
                quota_usec: 1,
                ..good
            },
        ] {
            assert!(validate_kernel_values(&limits, &manager, &bad).is_err());
        }
        let mut changed = manager.clone();
        changed.insert("MemoryMax".into(), good.maximum.to_string());
        assert!(validate_kernel_values(&limits, &changed, &good).is_err());
        assert_eq!(
            bus_unit_path("horizon-test_x.service"),
            "/org/freedesktop/systemd1/unit/horizon_2dtest_5fx_2eservice"
        );
    }
    #[test]
    fn complete_census_catches_new_workers_and_reuse_of_an_earlier_sampled_pid() {
        let exe = tempfile::NamedTempFile::new().unwrap();
        let other = tempfile::NamedTempFile::new().unwrap();
        let pin = archive_file_identity(exe.as_file()).unwrap();
        let replacement = archive_file_identity(other.as_file()).unwrap();
        let records = vec![
            ProcessIdentity {
                pid: 42,
                start: "100".into(),
                executable: "/sealed/node".into(),
                mapped: pin,
            },
            ProcessIdentity {
                pid: 43,
                start: "101".into(),
                executable: "/sealed/worker".into(),
                mapped: pin,
            },
        ];
        let before = [42, 43];
        let current = |pid| Ok(records.iter().find(|v| v.pid == pid).unwrap().clone());
        close_census(&before, &before, &records, current).unwrap();
        // A worker appearing after the last per-process read is still caught.
        assert!(close_census(&before, &[42, 43, 44], &records, current).is_err());
        assert!(close_census(&before, &[42], &records, current).is_err());
        assert!(close_census(&before, &before, &records[..1], current).is_err());
        // PID42 already passed its own before/after check. Reuse while43 was
        // being read must fail the final all-record identity pass.
        let reused = |pid| {
            let mut value = current(pid)?;
            if pid == 42 {
                value.start = "999".into();
            }
            Ok(value)
        };
        assert!(close_census(&before, &before, &records, reused).is_err());
        let replaced = |pid| {
            let mut value = current(pid)?;
            if pid == 42 {
                value.mapped = replacement;
            }
            Ok(value)
        };
        assert!(close_census(&before, &before, &records, replaced).is_err());
    }
}
