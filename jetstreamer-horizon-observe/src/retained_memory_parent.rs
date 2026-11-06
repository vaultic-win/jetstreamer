//! Fixed retained-parent telemetry in the ordinary observer window. These are
//! asynchronous kernel counters, never resident-page evidence or capacity credit.
use super::*;
use std::collections::BTreeSet;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

const UNIT: &str = "horizonprefix205ram883v2.slice";
const GROUP: &str = "/horizonprefix205ram883v2.slice";
const PARENT: &str = "/sys/fs/cgroup/horizonprefix205ram883v2.slice";
const OUTER: &str = "/run/jetstreamer-prefix205-build-ram883-v2";
const INNER: &str = "/run/jetstreamer-prefix205-build-ram883-v2/metadata-bootstrap892-v2";
const LIMIT: u64 = 70_866_960_384;
const KERNEL: &str = "7.0.0-38-generic";
const KERNEL_CONFIG: &str = "/boot/config-7.0.0-38-generic";
const KERNEL_CONFIG_SHA: &str = "6cb18717c6914d4947489eedf8cb69ac23db3faa8ef9b9f563ff02c346dcd32d";
const CONTRACTS: [(&str, &str); 5] = [
    (
        "/var/lib/jetstreamer/horizon-prefix205-RAM-support885-Main-v1/support-admission.json",
        "ff4f2299000d80f00b0e721d319ecb3898c77c734eb1654a122e33ab1ea3e71e",
    ),
    (
        "/var/lib/jetstreamer/horizon-prefix205-RAM-mount885-Main-v1/mount-proof-v2.json",
        "03519d7f3faf9334b5362515973e9448f859b1b0315ba4c6a0fb739c9bf1c737",
    ),
    (
        "/var/lib/jetstreamer/horizon-prefix205-RAM-leaves885-Main-v1/leaf-proof.json",
        "ed5cc8885e1ab4957a5025f8d592f7b7f51ca9680cc2ddc15e0ddf26a8ba2046",
    ),
    (
        "/var/lib/jetstreamer/horizon-metadata-bootstrap892-v2-Main-evidence-v1/RAM-kernel-containment903-amendment.json",
        "066d1f881266b8eb62197185728960737b102f4aac76358d6d82cd818260c3b9",
    ),
    (
        "/var/lib/jetstreamer/horizon-metadata-bootstrap892-v2-Main-evidence-v1/setup903-v3/setup-acceptance.json",
        "304b271f04a4bbf8a5918832c547685612d49634e0dadc7e50c8f58ca97254eb",
    ),
];
const FILES: [&str; 12] = [
    "memory.max",
    "memory.swap.max",
    "memory.current",
    "memory.swap.current",
    "memory.stat",
    "memory.events",
    "cgroup.type",
    "cgroup.controllers",
    "cgroup.subtree_control",
    "cgroup.events",
    "cgroup.stat",
    "cgroup.procs",
];

pub(super) fn validate_config(config: &Config) -> Result<()> {
    settings(
        config.retained_prefix205_ram,
        config.observation_reason,
        config.minimum_interval_seconds,
    )
}
fn settings(enabled: bool, reason: ObservationReason, interval: u64) -> Result<()> {
    ensure!(
        !enabled || (reason == ObservationReason::Routine && interval >= 1800),
        "retained RAM telemetry requires the ordinary 1800-second observer cadence"
    );
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct Identity {
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
}
fn identity(file: &File) -> Result<Identity> {
    let m = file.metadata()?;
    Ok(Identity {
        device: m.dev(),
        inode: m.ino(),
        uid: m.uid(),
        gid: m.gid(),
        mode: m.mode(),
    })
}
fn directory(file: &File, magic: i64) -> Result<Identity> {
    ensure!(
        file.metadata()?.is_dir(),
        "retained RAM input is not a directory"
    );
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
    ensure!(
        unsafe { libc::fstatfs(file.as_raw_fd(), stat.as_mut_ptr()) } == 0,
        "cannot identify retained RAM filesystem"
    );
    ensure!(
        unsafe { stat.assume_init() }.f_type as i64 == magic,
        "retained RAM filesystem type changed"
    );
    identity(file)
}

fn child(parent: &File, name: &str, dir: bool) -> Result<File> {
    ensure!(
        !name.is_empty() && name != "." && name != ".." && !name.contains('/'),
        "unsafe retained input component"
    );
    let name = CString::new(name)?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY
                | libc::O_CLOEXEC
                | libc::O_NOFOLLOW
                | libc::O_NONBLOCK
                | if dir { libc::O_DIRECTORY } else { 0 },
        )
    };
    ensure!(
        fd >= 0,
        "cannot open retained input: {}",
        std::io::Error::last_os_error()
    );
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn anchored(path: &str, dir: bool) -> Result<File> {
    ensure!(
        path.starts_with('/') && path.len() <= 4096,
        "invalid retained input path"
    );
    let parts = path[1..].split('/').collect::<Vec<_>>();
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")?;
    for (i, part) in parts.iter().enumerate() {
        file = child(&file, part, dir || i + 1 < parts.len())?;
    }
    Ok(file)
}
fn bytes(mut file: File, maximum: u64) -> Result<Vec<u8>> {
    let before = identity(&file)?;
    ensure!(
        file.metadata()?.is_file(),
        "retained input is not a regular file"
    );
    let mut data = Vec::new();
    (&mut file).take(maximum + 1).read_to_end(&mut data)?;
    ensure!(
        data.len() as u64 <= maximum && identity(&file)? == before,
        "retained input oversized or replaced"
    );
    Ok(data)
}
fn fixed(path: &str, expected: &str, immutable: bool) -> Result<String> {
    let file = anchored(path, false)?;
    let m = file.metadata()?;
    let id = identity(&file)?;
    ensure!(
        m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o022 == 0
            && (!immutable || m.mode() & 0o222 == 0),
        "retained contract custody changed"
    );
    let data = bytes(file, 1 << 20)?;
    ensure!(
        sha256(&data) == expected && identity(&anchored(path, false)?)? == id,
        "retained contract digest/identity changed"
    );
    Ok(expected.into())
}
fn text(path: &str, maximum: u64) -> Result<String> {
    Ok(String::from_utf8(bytes(anchored(path, false)?, maximum)?)?)
}
fn manager() -> Result<BTreeMap<String, String>> {
    // One bounded lookup, with no discovery retry, PID census, reload or signal
    // to a retained actor. timeout can terminate only its own systemctl child.
    let mut command = Command::new("/usr/bin/timeout").args(["--signal=KILL", "2s", "/usr/bin/systemctl",
        "--no-pager", "--no-ask-password", "show", UNIT,
        "--property=Id,LoadState,ActiveState,SubState,InvocationID,ControlGroup,Delegate,MemoryMax,MemorySwapMax,DropInPaths,Job,FragmentPath"])
        .stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::null())
        .spawn().context("retained parent manager read failed")?;
    let mut stdout = command
        .stdout
        .take()
        .context("retained manager stdout missing")?;
    let mut output = Vec::new();
    let read = (&mut stdout).take(65537).read_to_end(&mut output);
    drop(stdout); // Oversized output cannot grow our allocation or block wait.
    let status = command.wait()?;
    read?;
    ensure!(
        status.success() && output.len() <= 65536,
        "retained parent manager read unavailable"
    );
    parse_systemctl_properties(&output, UNIT)
}
fn millis() -> Result<u64> {
    Ok(u64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
    )?)
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct Snapshot {
    started_unix_millis: u64,
    completed_unix_millis: u64,
    parent: Identity,
    outer_tmpfs: Identity,
    inner_tmpfs: Identity,
    manager: BTreeMap<String, String>,
    raw: BTreeMap<String, String>,
    boot_id: String,
    kernel_release: String,
    kernel_config_sha256: String,
    contracts: BTreeMap<String, String>,
}
pub(super) fn capture() -> Result<Snapshot> {
    let started_unix_millis = millis()?;
    let mut contracts = BTreeMap::new();
    for (path, sha) in CONTRACTS {
        contracts.insert(path.into(), fixed(path, sha, true)?);
    }
    let kernel_config_sha256 = fixed(KERNEL_CONFIG, KERNEL_CONFIG_SHA, false)?;
    let kernel_release = text("/proc/sys/kernel/osrelease", 256)?.trim().to_owned();
    let boot_id = text("/proc/sys/kernel/random/boot_id", 128)?
        .trim()
        .to_owned();
    let manager_before = manager()?;
    let parent = anchored(PARENT, true)?;
    let parent_id = directory(&parent, 0x63677270)?;
    let outer = anchored(OUTER, true)?;
    let outer_id = directory(&outer, 0x01021994)?;
    let inner = anchored(INNER, true)?;
    let inner_id = directory(&inner, 0x01021994)?;
    let mut raw = BTreeMap::new();
    for name in FILES {
        raw.insert(
            name.into(),
            String::from_utf8(bytes(child(&parent, name, false)?, 65536)?)?,
        );
    }
    ensure!(
        raw.values().map(String::len).sum::<usize>() <= 131072,
        "retained raw endpoint exceeds receipt budget"
    );
    ensure!(
        identity(&parent)? == parent_id
            && identity(&anchored(PARENT, true)?)? == parent_id
            && identity(&outer)? == outer_id
            && identity(&anchored(OUTER, true)?)? == outer_id
            && identity(&inner)? == inner_id
            && identity(&anchored(INNER, true)?)? == inner_id
            && manager()? == manager_before,
        "retained owner/cgroup/mount identity changed during read"
    );
    Ok(Snapshot {
        started_unix_millis,
        completed_unix_millis: millis()?,
        parent: parent_id,
        outer_tmpfs: outer_id,
        inner_tmpfs: inner_id,
        manager: manager_before,
        raw,
        boot_id,
        kernel_release,
        kernel_config_sha256,
        contracts,
    })
}

fn pairs(text: &str) -> Result<BTreeMap<String, u64>> {
    let mut values = BTreeMap::new();
    for line in text.lines() {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        ensure!(
            fields.len() == 2
                && fields[0]
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_'),
            "invalid retained counter row"
        );
        ensure!(
            values
                .insert(fields[0].into(), fields[1].parse()?)
                .is_none(),
            "duplicate retained counter"
        );
    }
    ensure!(!values.is_empty(), "empty retained counters");
    Ok(values)
}
fn number(text: &str) -> Result<u64> {
    let value = text.trim();
    ensure!(
        !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()),
        "invalid retained integer"
    );
    Ok(value.parse()?)
}
fn validate(snapshot: &Snapshot) -> Result<()> {
    ensure!(
        snapshot.raw.values().map(String::len).sum::<usize>() <= 131072
            && snapshot
                .manager
                .iter()
                .map(|(k, v)| k.len() + v.len())
                .sum::<usize>()
                <= 16384,
        "retained endpoint exceeds receipt budget"
    );
    ensure!(
        snapshot.parent.device == 29
            && snapshot.parent.inode == 6_781_920
            && snapshot.parent.uid == 0
            && snapshot.parent.mode & 0o022 == 0
            && snapshot.outer_tmpfs.device == 63
            && snapshot.outer_tmpfs.inode == 1
            && snapshot.outer_tmpfs.uid == 0
            && snapshot.inner_tmpfs.device == 58
            && snapshot.inner_tmpfs.uid == 0,
        "retained parent or nested mount differs from bound history"
    );
    ensure!(
        snapshot.kernel_release == KERNEL
            && snapshot.kernel_config_sha256 == KERNEL_CONFIG_SHA
            && snapshot.boot_id.len() == 36
            && snapshot.boot_id.bytes().enumerate().all(|(i, b)| {
                if matches!(i, 8 | 13 | 18 | 23) {
                    b == b'-'
                } else {
                    b.is_ascii_hexdigit()
                }
            })
            && snapshot.contracts
                == CONTRACTS
                    .iter()
                    .map(|(p, s)| (p.to_string(), s.to_string()))
                    .collect()
            && snapshot.started_unix_millis <= snapshot.completed_unix_millis,
        "retained kernel/contract binding changed"
    );
    for (key, value) in [
        ("Id", UNIT),
        ("LoadState", "loaded"),
        ("ActiveState", "active"),
        ("SubState", "active"),
        ("ControlGroup", GROUP),
        ("Delegate", "no"),
        ("MemoryMax", "70866960384"),
        ("MemorySwapMax", "0"),
        ("DropInPaths", ""),
        ("Job", ""),
    ] {
        ensure!(
            snapshot.manager.get(key).map(String::as_str) == Some(value),
            "retained manager policy changed: {key}"
        );
    }
    ensure!(
        snapshot
            .manager
            .get("InvocationID")
            .is_some_and(|s| is_invocation_id(s)),
        "retained parent has no valid owner IID"
    );
    let get = |name: &str| {
        snapshot
            .raw
            .get(name)
            .with_context(|| format!("missing retained input {name}"))
    };
    ensure!(
        get("cgroup.type")?.trim() == "domain"
            && number(get("memory.max")?)? == LIMIT
            && number(get("memory.swap.max")?)? == 0,
        "retained kernel policy changed"
    );
    number(get("memory.current")?)?;
    number(get("memory.swap.current")?)?;
    let stat = pairs(get("memory.stat")?)?;
    ensure!(
        ["anon", "file", "shmem", "kernel"]
            .iter()
            .all(|k| stat.contains_key(*k)),
        "retained memory categories missing"
    );
    pairs(get("memory.events")?)?;
    let events = pairs(get("cgroup.events")?)?;
    ensure!(
        events.get("populated").is_some_and(|v| *v <= 1)
            && events.get("frozen").is_some_and(|v| *v <= 1),
        "retained cgroup flags missing"
    );
    let stat = pairs(get("cgroup.stat")?)?;
    ensure!(
        stat.contains_key("nr_descendants") && stat.contains_key("nr_dying_descendants"),
        "retained descendant counters missing"
    );
    for pid in get("cgroup.procs")?.split_whitespace() {
        number(pid)?;
    }
    for (name, expected) in [
        ("cgroup.controllers", "cpuset cpu io memory pids"),
        ("cgroup.subtree_control", "cpu io memory pids"),
    ] {
        let tokens = get(name)?.split_whitespace().collect::<Vec<_>>();
        let actual = tokens.iter().copied().collect::<BTreeSet<_>>();
        ensure!(
            actual.len() == tokens.len() && actual == expected.split_whitespace().collect(),
            "retained controller policy changed"
        );
    }
    Ok(())
}
fn stable(before: &Snapshot, after: &Snapshot) -> Result<()> {
    validate(before)?;
    validate(after)?;
    ensure!(
        before.parent == after.parent
            && before.outer_tmpfs == after.outer_tmpfs
            && before.inner_tmpfs == after.inner_tmpfs
            && before.manager == after.manager
            && before.boot_id == after.boot_id
            && before.completed_unix_millis <= after.started_unix_millis,
        "retained owner/cgroup/mount/boot changed across ordinary window"
    );
    for name in [
        "cgroup.type",
        "cgroup.controllers",
        "cgroup.subtree_control",
        "memory.max",
        "memory.swap.max",
    ] {
        ensure!(
            before.raw.get(name) == after.raw.get(name),
            "retained kernel policy changed across ordinary window"
        );
    }
    // Neither changing occupancy nor counters disappearing from memory.stat
    // earn credit. Keep raw generations; no subtraction, category sum or min.
    Ok(())
}
pub(super) fn report(before: Result<Snapshot>, after: Result<Snapshot>) -> Value {
    let error = match (&before, &after) {
        (Ok(a), Ok(b)) => stable(a, b).err().map(|e| format!("{e:#}")),
        _ => Some(format!(
            "retained endpoint unavailable: before={:?}; after={:?}",
            before.as_ref().err(),
            after.as_ref().err()
        )),
    };
    serde_json::json!({"schema":"jetstreamer-retained-prefix205-ram-telemetry-v1",
        "status":if error.is_some() { "unavailable" } else { "observed" }, "error":error,
        "before":before.ok(),"after":after.ok(),"parent_unit":UNIT,"parent_cgroup":PARENT,
        "retained_reservation_bytes":LIMIT,"capacity_credit_bytes":0,"future_growth_released_bytes":0,
        "resident_physical_lower_bound_bytes":null,"complete_writer_or_charge_ownership_proven":false,
        "coherent_physical_snapshot_proven":false,"counter_batching_error_bound_proven":false,
        "accounting":{"parent_counters_are_hierarchical":true,"descendant_counters_not_added":true,
            "shmem_is_subset_of_file_not_added":true,"kernel_and_slab_children_not_added":true,
            "outer_tmpfs_data_quota_bytes":34359738368u64,"separate_inner_tmpfs_data_quota_bytes":67108864u64,
            "nested_mount_quotas_are_not_usage_or_parent_charge_summands":true,
            "per_mount_shmem_attribution_proven":false,"raw_endpoints_are_asynchronous":true},
        "ordinary_replay_claim":false,"admission_authorized":false,"publication_authorized":false,
        "quota_or_swap_or_permissions_changed":false,"freeze_or_reclaim_performed":false,"r2_mutations":false})
}

#[cfg(test)]
#[path = "retained_memory_parent_tests.rs"]
mod tests;
