//! Exact v1.6.16 snapshot load/freeze tests, not an entry replay or publisher.
#[cfg(feature = "epoch225-shrink-snapshot-tests")]
mod ram_snapshot225;
#[cfg(feature = "epoch225-shrink-snapshot-tests")]
use ram_snapshot225::{validate_fleet, validate_observer, validate_plan};
use {
    anyhow::{Context, Result, ensure},
    serde::Deserialize,
    serde_json::{Value, json},
    sha2::{Digest, Sha256},
    std::{
        env,
        fs::{self, File, OpenOptions},
        io::{Read, Write},
        os::unix::{
            fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
            process::CommandExt,
        },
        path::{Path, PathBuf},
        process::{Child, Command},
        sync::atomic::{AtomicI32, Ordering},
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    },
};

const GIB: u64 = 1 << 30;
// Separate diagnostic envelope, never a change to a live replay or old sandbox.
// The 64-GiB experiment stalled at ~65 GB including unreclaimable tmpfs pages.
const MEMORY_MAX: u64 = 128 * GIB;
const MEMORY_HIGH: u64 = 112 * GIB;
const TMPFS_SIZE: u64 = 512 * GIB;
const FLOOR: u64 = if PROFILE225 {
    // Seven verified campaign samples after epoch216's sidecar commit.
    235_600_351_300
} else {
    231_874_716_783
};
const STOP_MEMORY: u64 = 448 * GIB;
// Reserve the complete diagnostic cap above the unchanged host stop reserve.
const START_MEMORY: u64 = STOP_MEMORY + MEMORY_MAX;
const RELEASED_225: bool = cfg!(all(
    feature = "ram-snapshot-eight-core-stopped225",
    not(feature = "epoch225-shrink-snapshot-tests")
));
const CPU_CORES: u64 = if RELEASED_225 || PROFILE225 { 8 } else { 2 };
const PROFILE225: bool = cfg!(feature = "epoch225-shrink-snapshot-tests");
const TMPFS_OPTIONS: &str = if PROFILE225 {
    "/tmp:rw,size=512G,nr_inodes=1048576,nosuid,nodev,mode=1777"
} else {
    "/tmp:rw,size=512G,nosuid,nodev,mode=1777"
};
const SNAPSHOT_SHA: &str = if PROFILE225 {
    "094d3b28c39403580fbac083cdad67cc008b255dd375d611217103750d0f412d"
} else {
    "348cba573c9e737e77c512d2c7ceda7bc81db61be6f4dc02838d168a10103043"
};
const SNAPSHOT_SIZE: u64 = if PROFILE225 {
    10_177_204_112
} else {
    8_046_142_592
};
const GENESIS_SHA: &str = "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945";
const TEST_SHA: &str = if PROFILE225 {
    "207c0d2d4735eb745570686f7323ed63a8b4caed6536219d0529467e7036329d"
} else {
    "bfa7aadf5be9d895747b379c18354ecc312e50ba895341a5e46a21a6a085fd64"
};
const FILTER: &str = if PROFILE225 {
    "_v1_6_25_boundary_snapshot"
} else {
    "_v1_6_16_boundary_snapshot"
};
const RESOURCE_FILES: [&str; 12] = [
    "cpu.stat",
    "cpu.max",
    "cpu.pressure",
    "memory.current",
    "memory.peak",
    "memory.high",
    "memory.max",
    "memory.events",
    "memory.stat",
    "memory.pressure",
    "io.stat",
    "io.pressure",
];
const TEST_NAMES: [&str; 2] = if PROFILE225 {
    [
        "runtime::tests::initializes_and_checkpoints_v1_6_25_boundary_snapshot: test",
        "snapshot::tests::loads_and_verifies_v1_6_25_boundary_snapshot: test",
    ]
} else {
    [
        "runtime::tests::initializes_and_checkpoints_v1_6_16_boundary_snapshot: test",
        "snapshot::tests::loads_and_verifies_v1_6_16_boundary_snapshot: test",
    ]
};
static SIGNAL: AtomicI32 = AtomicI32::new(0);

struct OwnedChild(Child, bool);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if !self.1 {
            unsafe {
                libc::kill(-(self.0.id() as i32), libc::SIGKILL);
            }
            let _ = self.0.wait();
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Bound {
    path: PathBuf,
    sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    mode: String,
    unit: String,
    test_binary: Bound,
    snapshot: Bound,
    genesis: Bound,
    observer: Bound,
    fleet: Bound,
    receipt_directory: PathBuf,
    maximum_runtime_seconds: u64,
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|n| format!("{n:02x}")).collect()
}
fn receipt_schema(kind: &str) -> String {
    format!(
        "jetstreamer-private-{}-ram-snapshot-{kind}-v1",
        if PROFILE225 { "v1625" } else { "v1616" }
    )
}
fn is_sha(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn identity(m: &fs::Metadata) -> (u64, u64, u64, i64, i64, i64, i64) {
    (
        m.dev(),
        m.ino(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}
fn immutable(path: &Path, expected: &str, maximum: u64) -> Result<fs::Metadata> {
    checked_input(path, expected, maximum, true)
}
fn checked_input(
    path: &Path,
    expected: &str,
    maximum: u64,
    immutable_mode: bool,
) -> Result<fs::Metadata> {
    ensure!(
        is_sha(expected) && path.is_absolute() && path.canonicalize()? == path,
        "invalid input path/hash"
    );
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & if immutable_mode { 0o222 } else { 0o022 } == 0
            && m.len() <= maximum,
        "unsafe immutable input"
    );
    let mut digest = Sha256::new();
    let mut buf = [0u8; 131072];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        digest.update(&buf[..n]);
    }
    ensure!(
        hex(&digest.finalize()) == expected
            && identity(&m) == identity(&f.metadata()?)
            && identity(&m) == identity(&fs::symlink_metadata(path)?),
        "input hash/identity changed"
    );
    Ok(m)
}
fn private_dir(p: &Path) -> Result<()> {
    let m = fs::symlink_metadata(p)?;
    ensure!(
        p.is_absolute()
            && p.canonicalize()? == p
            && m.is_dir()
            && m.uid() == 0
            && m.mode() & 0o077 == 0,
        "unsafe receipt directory"
    );
    Ok(())
}
fn write_new(dir: &Path, name: &str, value: &Value) -> Result<()> {
    private_dir(dir)?;
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(dir.join(name))?;
    serde_json::to_writer_pretty(&mut f, value)?;
    f.write_all(b"\n")?;
    f.sync_all()?;
    File::open(dir)?.sync_all()?;
    Ok(())
}
#[cfg(not(feature = "epoch225-shrink-snapshot-tests"))]
fn validate_plan(p: &Plan) -> Result<()> {
    ensure!(
        p.schema == "jetstreamer-private-v1616-ram-snapshot-test-plan-v1"
            && matches!(p.mode.as_str(), "capability" | "snapshot-tests"),
        "wrong plan mode/schema"
    );
    ensure!(
        p.unit.starts_with("horizon-v1616-snapshot-test-")
            && p.unit.ends_with(".service")
            && p.unit
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)),
        "wrong unit scope"
    );
    ensure!(
        p.test_binary.sha256 == TEST_SHA
            && p.snapshot.sha256 == SNAPSHOT_SHA
            && p.genesis.sha256 == GENESIS_SHA,
        "foreign fixture/test build"
    );
    ensure!(
        p.snapshot.path.file_name().and_then(|n| n.to_str())
            == Some("snapshot-86831488-ADFPkz1fATPmpkDdL8ZZAUtjfa4EwUfn1J2WeSrsDWFk.tar.zst")
            && p.genesis.path.file_name().and_then(|n| n.to_str()) == Some("genesis.tar.bz2"),
        "foreign fixture name"
    );
    ensure!(
        p.receipt_directory.parent()
            == Some(Path::new("/var/lib/jetstreamer/horizon-ram-snapshot-tests"))
            && p.receipt_directory
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("ram-snapshot-test-"))
            && (60..=1800).contains(&p.maximum_runtime_seconds),
        "wrong receipt/time scope"
    );
    validate_reserves(TMPFS_SIZE, MEMORY_MAX, FLOOR, STOP_MEMORY)?;
    Ok(())
}
fn memory_available(text: &str) -> Result<u64> {
    let lines: Vec<_> = text
        .lines()
        .filter(|s| s.starts_with("MemAvailable:"))
        .collect();
    ensure!(lines.len() == 1, "missing/duplicate MemAvailable");
    let parts: Vec<_> = lines[0].split_whitespace().collect();
    ensure!(
        parts.len() == 3 && parts[2] == "kB",
        "bad MemAvailable units"
    );
    parts[1]
        .parse::<u64>()?
        .checked_mul(1024)
        .context("memory overflow")
}
fn host_memory() -> Result<u64> {
    memory_available(&fs::read_to_string("/proc/meminfo")?)
}
fn resource_counters_at(cgroup: &Path) -> Result<Value> {
    let mut counters = serde_json::Map::new();
    for name in RESOURCE_FILES {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(cgroup.join(name))?;
        let mut bytes = Vec::new();
        file.take(65_537).read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 65_536, "oversized cgroup counter {name}");
        counters.insert(name.into(), json!(String::from_utf8(bytes)?));
    }
    Ok(Value::Object(counters))
}
fn resource_snapshot(p: &Plan) -> Result<Value> {
    ensure!(
        fs::read_to_string("/proc/self/cgroup")?.trim() == format!("0::/system.slice/{}", p.unit),
        "foreign resource-counter cgroup"
    );
    resource_counters_at(&Path::new("/sys/fs/cgroup/system.slice").join(&p.unit))
}
fn ram_geometry() -> Result<u64> {
    let mut s: libc::statfs = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe { libc::statfs(c"/tmp".as_ptr(), &mut s) } == 0 && s.f_type == 0x01021994,
        "/tmp is not private tmpfs"
    );
    let mut v: libc::statvfs = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe { libc::statvfs(c"/tmp".as_ptr(), &mut v) } == 0,
        "tmpfs stat failed"
    );
    ensure!(
        v.f_blocks.checked_mul(v.f_frsize) == Some(TMPFS_SIZE),
        "wrong tmpfs size"
    );
    validate_inode_geometry(v.f_files)?;
    v.f_bavail
        .checked_mul(v.f_frsize)
        .context("tmpfs free overflow")
}
fn validate_inode_geometry(files: u64) -> Result<()> {
    ensure!(
        !PROFILE225 || files == 1_048_576,
        "wrong225 tmpfs inode limit"
    );
    Ok(())
}
fn authenticate(p: &Plan) -> Result<String> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "run as bounded root supervisor; child must drop privileges"
    );
    let status = fs::read_to_string("/proc/self/status")?;
    let caps = status
        .lines()
        .find_map(|s| s.strip_prefix("CapEff:\t"))
        .context("missing effective capabilities")?;
    ensure!(
        u64::from_str_radix(caps, 16)? == 0xe2,
        "effective capabilities must be exactly DAC_OVERRIDE,KILL,SETGID,SETUID"
    );
    let inv = env::var("INVOCATION_ID")?;
    ensure!(
        inv.len() == 32
            && inv
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "bad invocation"
    );
    ensure!(
        fs::read_to_string("/proc/self/cgroup")?.trim() == format!("0::/system.slice/{}", p.unit),
        "foreign cgroup"
    );
    let cg = Path::new("/sys/fs/cgroup/system.slice").join(&p.unit);
    for (file, expected) in [
        ("memory.max", MEMORY_MAX),
        ("memory.high", MEMORY_HIGH),
        ("memory.swap.max", 0),
        ("memory.oom.group", 1),
        ("pids.max", 512),
    ] {
        ensure!(
            fs::read_to_string(cg.join(file))?.trim().parse::<u64>()? == expected,
            "wrong cgroup {file}"
        );
    }
    let cpu = fs::read_to_string(cg.join("cpu.max"))?;
    let words: Vec<_> = cpu.split_whitespace().collect();
    ensure!(
        words.len() == 2
            && words[0].parse::<u64>()?
                == words[1]
                    .parse::<u64>()?
                    .checked_mul(CPU_CORES)
                    .context("quota overflow")?,
        "wrong CPU quota"
    );
    ensure!(
        env::var("TMPDIR").as_deref() == Ok("/tmp"),
        "TMPDIR must be isolated tmpfs"
    );
    let output = Command::new("/usr/bin/systemctl")
        .args([
            "show",
            &p.unit,
            "--no-pager",
            "--no-ask-password",
        "--property=Id,InvocationID,MainPID,NRestarts,Restart,KillMode,Delegate,Type,NoNewPrivileges,ProtectSystem,ProtectHome,ProtectControlGroups,PrivateNetwork,TemporaryFileSystem,ReadWritePaths,CapabilityBoundingSet,OOMPolicy,OOMScoreAdjust",
        ])
        .output()?;
    ensure!(
        output.status.success() && output.stdout.len() < 16384,
        "cannot authenticate test unit"
    );
    let text = std::str::from_utf8(&output.stdout)?;
    for (key, value) in [
        ("Id", p.unit.as_str()),
        ("InvocationID", inv.as_str()),
        ("NRestarts", "0"),
        ("Restart", "no"),
        ("KillMode", "control-group"),
        ("Delegate", "no"),
        ("Type", "oneshot"),
    ] {
        ensure!(
            text.lines()
                .filter(|s| *s == format!("{key}={value}"))
                .count()
                == 1,
            "wrong unit {key}"
        );
    }
    ensure!(
        text.lines()
            .any(|s| s == format!("MainPID={}", std::process::id())),
        "not the exact main process"
    );
    validate_sandbox(text, &p.receipt_directory)?;
    Ok(inv)
}
fn validate_sandbox(text: &str, receipts: &Path) -> Result<()> {
    for (key, value) in [
        ("NoNewPrivileges", "yes"),
        ("ProtectSystem", "strict"),
        ("ProtectHome", "read-only"),
        ("ProtectControlGroups", "yes"),
        ("PrivateNetwork", "yes"),
        ("OOMPolicy", "kill"),
        ("OOMScoreAdjust", "1000"),
        ("TemporaryFileSystem", TMPFS_OPTIONS),
    ] {
        ensure!(
            text.lines()
                .filter(|s| *s == format!("{key}={value}"))
                .count()
                == 1,
            "wrong sandbox {key}"
        );
    }
    ensure!(
        text.lines()
            .filter(|s| *s == format!("ReadWritePaths={}", receipts.display()))
            .count()
            == 1,
        "wrong writable scope"
    );
    let lines: Vec<_> = text
        .lines()
        .filter_map(|s| s.strip_prefix("CapabilityBoundingSet="))
        .collect();
    ensure!(lines.len() == 1, "missing/duplicate capability bound");
    let mut caps: Vec<_> = lines[0].split_whitespace().collect();
    caps.sort_unstable();
    ensure!(
        caps == ["cap_dac_override", "cap_kill", "cap_setgid", "cap_setuid"],
        "excess/missing capabilities"
    );
    Ok(())
}
fn utc(s: &str) -> Result<u64> {
    ensure!(s.len() == 20 && s.is_ascii(), "bad UTC");
    let input = std::ffi::CString::new(s)?;
    let mut t: libc::tm = unsafe { std::mem::zeroed() };
    let end = unsafe { libc::strptime(input.as_ptr(), c"%Y-%m-%dT%H:%M:%SZ".as_ptr(), &mut t) };
    ensure!(!end.is_null() && unsafe { *end } == 0, "bad UTC");
    let n = unsafe { libc::timegm(&mut t) };
    let mut out = [0i8; 32];
    ensure!(
        unsafe {
            libc::strftime(
                out.as_mut_ptr(),
                out.len(),
                c"%Y-%m-%dT%H:%M:%SZ".as_ptr(),
                &t,
            )
        } == 20
            && unsafe { std::ffi::CStr::from_ptr(out.as_ptr()) }.to_bytes() == s.as_bytes(),
        "noncanonical UTC"
    );
    Ok(u64::try_from(n)?)
}
#[cfg(not(feature = "epoch225-shrink-snapshot-tests"))]
fn validate_observer(v: &Value, now: u64) -> Result<()> {
    ensure!(
        v["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && v["cadence"]["routine_minimum_interval_enforced"] == true
            && v["cadence"]["observation_reason"] == "routine"
            && v["cadence"]["minimum_interval_seconds"] == 1800,
        "not routine v2 evidence"
    );
    for key in [
        "producer_or_controller_signals_sent",
        "service_state_changed",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(v["mutation"][key] == false, "mutating resource observation");
    }
    let at = utc(v["recorded_at_utc"]
        .as_str()
        .context("sample time missing")?)?;
    ensure!(
        at <= now && now - at <= 1800,
        "stale/future admission sample"
    );
    ensure!(
        v["host_memory"]["conservative_available_kib"]
            .as_u64()
            .and_then(|n| n.checked_mul(1024))
            .is_some_and(|n| n >= START_MEMORY),
        "sample memory admission failed"
    );
    let ordinary = v["replays"].as_array().context("ordinary census missing")?;
    let diagnostic = v["diagnostic_replays"]
        .as_array()
        .context("diagnostic census missing")?;
    ensure!(
        ordinary.len() == 2 && diagnostic.len() == 2,
        "changed fleet census"
    );
    let expected = [
        (
            "216-219",
            "2b6ded8d8baf4f72a5c8a91385f7c278",
            "95fb05d1b78349bcb907c1e930e7682e",
        ),
        (
            "220-223",
            "0b69b5009dc74bbda94b94d059a3daa7",
            "c2adebaad0cb42b385156631156813fe",
        ),
        (
            "203-203",
            "92e367eb7cf944a1825fe5a20d9243ca",
            "92e367eb7cf944a1825fe5a20d9243ca",
        ),
        (
            "225-226",
            "ac9aee3d47eb41e483a5e008ed43d030",
            "ac9aee3d47eb41e483a5e008ed43d030",
        ),
    ];
    for (range, controller, id) in expected.into_iter().take(if RELEASED_225 { 3 } else { 4 }) {
        let matches: Vec<_> = ordinary
            .iter()
            .chain(diagnostic)
            .filter(|x| x["range"] == range)
            .collect();
        ensure!(matches.len() == 1, "missing/duplicate claim");
        let outer = matches[0];
        let r = if outer.get("observation").is_some() {
            &outer["observation"]
        } else {
            outer
        };
        ensure!(r["invocation_binding_stable"] == true, "unstable claim");
        for point in ["producer_before", "producer_after"] {
            ensure!(
                r[point]["invocation_id"] == id
                    && r[point]["restarts"] == 0
                    && r[point]["active_state"] == "active",
                "claim changed"
            );
        }
        for point in ["controller_before", "controller_after"] {
            ensure!(
                r[point]["invocation_id"] == controller
                    && r[point]["restarts"] == 0
                    && r[point]["active_state"] == "active",
                "controller changed"
            );
        }
    }
    if RELEASED_225 {
        let stopped: Vec<_> = diagnostic
            .iter()
            .filter(|d| d["range"] == "225-226")
            .collect();
        ensure!(stopped.len() == 1, "missing stopped225 census entry");
        let d = stopped[0];
        ensure!(
            d["status"] == "unavailable"
                && d["observation"].is_null()
                && d["producer_unit"]
                    == "horizon-qualify-225-natural-root-resource-63a2717-v1.service"
                && d["expected_producer_invocation_id"] == "ac9aee3d47eb41e483a5e008ed43d030"
                && d["ordinary_replay_claim"] == false
                && d["replay_launch_authorized"] == false,
            "sample still has live or foreign225 claim"
        );
        // Unavailability is never proof of a stop: the fixed guard receipt and
        // actual terminal unit are independently checked before child launch.
    }
    Ok(())
}
fn validate_reserves(tmpfs: u64, maximum: u64, floor: u64, stop: u64) -> Result<()> {
    ensure!(
        tmpfs.checked_sub(maximum).is_some_and(|n| n > floor)
            && stop.checked_sub(maximum).is_some_and(|n| n >= 224 * GIB),
        "reserve geometry invalid"
    );
    Ok(())
}
#[cfg(not(feature = "epoch225-shrink-snapshot-tests"))]
fn validate_fleet(f: &Value, observer: &Value, observer_hash: &str) -> Result<()> {
    ensure!(
        f["schema"] == "jetstreamer-horizon-campaign-fleet-v1"
            && f["observer_sha256"] == observer_hash
            && f["sampled_at_utc"] == observer["recorded_at_utc"]
            && f["first_epoch"] == 201
            && f["last_epoch"] == 300
            && f["producer_mutations"] == false
            && f["remote_mutations"] == false,
        "unbound fleet census"
    );
    let active = f["active"]
        .as_array()
        .context("active fleet census missing")?;
    ensure!(
        active.len() == if RELEASED_225 { 9 } else { 10 },
        "changed active fleet census"
    );
    let expected = [
        "95fb05d1b78349bcb907c1e930e7682e",
        "c2adebaad0cb42b385156631156813fe",
        "92e367eb7cf944a1825fe5a20d9243ca",
        "ac9aee3d47eb41e483a5e008ed43d030",
    ];
    let mut counts = [0; 4];
    for entry in active {
        let id = entry["producer"]["InvocationID"]
            .as_str()
            .context("missing fleet producer")?;
        let index = expected
            .iter()
            .position(|v| *v == id)
            .context("foreign fleet producer")?;
        counts[index] += 1;
        ensure!(
            entry["producer"]["ActiveState"] == "active" && entry["producer"]["NRestarts"] == "0",
            "inactive/restarted fleet producer"
        );
    }
    ensure!(
        counts == [4, 4, 1, if RELEASED_225 { 0 } else { 1 }],
        "changed producer claim multiplicity"
    );
    ensure!(
        f["inventory"]["ready_pairs"] == 6,
        "century sample census changed"
    );
    let ready: Vec<_> = f["inventory"]["entries"]
        .as_array()
        .context("inventory entries missing")?
        .iter()
        .filter(|e| e["state"] == "ready-pair")
        .collect();
    let epochs: Vec<_> = ready.iter().filter_map(|e| e["epoch"].as_u64()).collect();
    ensure!(
        epochs == [201, 202, 206, 213, 214, 215],
        "century epoch census changed"
    );
    let sum = ready
        .iter()
        .try_fold(0u64, |total, e| {
            total.checked_add(e["archive_length"].as_u64()?)
        })
        .context("century size overflow/missing")?;
    ensure!(
        sum == 695_624_150_347 && (2 * sum).div_ceil(6) == FLOOR,
        "century floor changed"
    );
    Ok(())
}

#[cfg(all(
    feature = "ram-snapshot-eight-core-stopped225",
    not(feature = "epoch225-shrink-snapshot-tests")
))]
fn validate_released_225(completion: &Value, launch: &Value) -> Result<()> {
    let id = "ac9aee3d47eb41e483a5e008ed43d030";
    ensure!(
        completion["schema"] == "jetstreamer-horizon-standalone-stop-completion-v1"
            && completion["producer_invocation_id"] == id
            && completion["plan_sha256"]
                == "0179bdba5b7d6536d5037b4b195baeca61bd74afd018a0f1a5db43355b9cede5"
            && completion["terminal"]["invocation_id"] == id
            && completion["terminal"]["active"] == "failed"
            && completion["terminal"]["pid"] == 0
            && completion["terminal"]["restarts"] == 0
            && completion["terminal"]["cgroup"] == ""
            && completion["scratch_deleted"] == false
            && completion["remote_mutations"] == false
            && completion["r2_mutations"] == false
            && launch["schema"] == "jetstreamer-private-epoch225-natural-root-resource-launch-v1"
            && launch["launched"] == true
            && launch["epoch"] == 225
            && launch["hard_limits"]["cpu_quota_cores"] == 16
            && launch["hard_limits"]["restart_policy"] == "no",
        "CPU release is not the exact terminal225 guard/launch chain"
    );
    Ok(())
}

#[cfg(all(
    feature = "ram-snapshot-eight-core-stopped225",
    not(feature = "epoch225-shrink-snapshot-tests")
))]
fn verify_released_225() -> Result<()> {
    let completion = Path::new(
        "/var/lib/jetstreamer/horizon-natural-root225-guard-receipts-v1/stop-completion.json",
    );
    let launch = Path::new(
        "/var/lib/jetstreamer/horizon-225-natural-root-launch-20261020T190442Z-v1/launch.json",
    );
    checked_input(
        completion,
        "407169f6ef6da54c5ffdab36a3664f7c7a21cba25bec489e73f0857bc2aaffa0",
        1 << 20,
        false,
    )?;
    checked_input(
        launch,
        "66b9ce5c324bcf5cc2ffb3c56330809b6b831262133d4f4bccdcc1b030ca39e3",
        1 << 20,
        false,
    )?;
    let completion_bytes = fs::read(completion)?;
    let launch_bytes = fs::read(launch)?;
    ensure!(
        hex(&Sha256::digest(&completion_bytes))
            == "407169f6ef6da54c5ffdab36a3664f7c7a21cba25bec489e73f0857bc2aaffa0"
            && hex(&Sha256::digest(&launch_bytes))
                == "66b9ce5c324bcf5cc2ffb3c56330809b6b831262133d4f4bccdcc1b030ca39e3",
        "CPU release input changed"
    );
    validate_released_225(
        &serde_json::from_slice(&completion_bytes)?,
        &serde_json::from_slice(&launch_bytes)?,
    )?;
    let output = Command::new("/usr/bin/systemctl").args([
        "show", "horizon-qualify-225-natural-root-resource-63a2717-v1.service", "--no-pager",
        "--property=Id,InvocationID,ActiveState,SubState,MainPID,NRestarts,ControlGroup,Restart,KillMode,Delegate",
    ]).output()?;
    ensure!(
        output.status.success() && output.stdout.len() < 16_384,
        "cannot authenticate released225"
    );
    let text = std::str::from_utf8(&output.stdout)?;
    for (key, expected) in [
        (
            "Id",
            "horizon-qualify-225-natural-root-resource-63a2717-v1.service",
        ),
        ("InvocationID", "ac9aee3d47eb41e483a5e008ed43d030"),
        ("ActiveState", "failed"),
        ("SubState", "failed"),
        ("MainPID", "0"),
        ("NRestarts", "0"),
        ("ControlGroup", ""),
        ("Restart", "no"),
        ("KillMode", "control-group"),
        ("Delegate", "no"),
    ] {
        ensure!(
            text.lines()
                .filter(|line| *line == format!("{key}={expected}"))
                .count()
                == 1,
            "released225 unit changed: {key}"
        );
    }
    Ok(())
}
fn drop_child_credentials(command: &mut Command) {
    // Only async-signal-safe libc calls between fork and exec; no inherited
    // supplementary groups or root capabilities in the snapshot test.
    unsafe {
        command.pre_exec(|| {
            if libc::setgroups(0, std::ptr::null()) != 0
                || libc::setgid(1000) != 0
                || libc::setuid(1000) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}
fn credential_probe() -> Result<()> {
    let mut c = Command::new(fs::read_link("/proc/self/exe")?);
    c.arg("--credential-probe").env_clear();
    drop_child_credentials(&mut c);
    let output = c.output()?;
    ensure!(
        output.status.success() && output.stdout == b"credential-drop-ok\n",
        "sandbox credential drop failed"
    );
    Ok(())
}
fn validate_test_list(s: &str) -> Result<()> {
    let names: Vec<_> = s.lines().filter(|l| l.ends_with(": test")).collect();
    ensure!(
        names == TEST_NAMES && s.lines().any(|l| l == "2 tests, 0 benchmarks"),
        "wrong ignored-test census"
    );
    Ok(())
}
extern "C" fn signal(n: i32) {
    SIGNAL.store(n, Ordering::SeqCst);
}
fn execute(p: &Plan, plan_hash: &str, self_hash: &str) -> Result<()> {
    validate_plan(p)?;
    private_dir(&p.receipt_directory)?;
    let inv = authenticate(p)?;
    let available = ram_geometry()?;
    ensure!(
        available >= FLOOR + MEMORY_MAX,
        "tmpfs floor admission failed"
    );
    credential_probe()?;
    #[cfg(all(
        feature = "ram-snapshot-eight-core-stopped225",
        not(feature = "epoch225-shrink-snapshot-tests")
    ))]
    verify_released_225()?;
    if p.mode == "capability" {
        write_new(
            &p.receipt_directory,
            "capability.json",
            &json!({"schema":receipt_schema("capability"),"invocation_id":inv,"plan_sha256":plan_hash,"self_sha256":self_hash,"tmpfs_bytes":TMPFS_SIZE,"available_bytes":available,"maximum_cgroup_memory_bytes":MEMORY_MAX,"worst_case_tmpfs_free_bytes":TMPFS_SIZE-MEMORY_MAX,"century_floor_bytes":FLOOR,"host_memory_sample_taken":false,"snapshot_tests_run":false,"replay_launch_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false}),
        )?;
        return Ok(());
    }
    checked_input(&p.observer.path, &p.observer.sha256, 16 << 20, false)?;
    let observer: Value = serde_json::from_slice(&fs::read(&p.observer.path)?)?;
    validate_observer(
        &observer,
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    )?;
    checked_input(&p.fleet.path, &p.fleet.sha256, 16 << 20, false)?;
    let fleet: Value = serde_json::from_slice(&fs::read(&p.fleet.path)?)?;
    validate_fleet(&fleet, &observer, &p.observer.sha256)?;
    ensure!(
        host_memory()? >= START_MEMORY,
        "fresh memory admission failed"
    );
    let test = immutable(
        &p.test_binary.path,
        &p.test_binary.sha256,
        if PROFILE225 { 256 << 20 } else { 64 << 20 },
    )?;
    let snapshot = immutable(&p.snapshot.path, &p.snapshot.sha256, SNAPSHOT_SIZE)?;
    ensure!(snapshot.len() == SNAPSHOT_SIZE, "wrong snapshot size");
    let genesis = immutable(&p.genesis.path, &p.genesis.sha256, 10 << 20)?;
    let mut list_command = Command::new(&p.test_binary.path);
    list_command
        .args(["--ignored", "--list", FILTER])
        .env_clear();
    drop_child_credentials(&mut list_command);
    let list = list_command.output()?;
    ensure!(list.status.success(), "test listing failed");
    validate_test_list(std::str::from_utf8(&list.stdout)?)?;
    ensure!(
        host_memory()? >= START_MEMORY,
        "post-hash memory admission failed"
    );
    #[cfg(feature = "epoch225-shrink-snapshot-tests")]
    validate_fleet(&fleet, &observer, &p.observer.sha256)?;
    #[cfg(all(
        feature = "ram-snapshot-eight-core-stopped225",
        not(feature = "epoch225-shrink-snapshot-tests")
    ))]
    verify_released_225()?;
    let resources_before = resource_snapshot(p)?;
    write_new(
        &p.receipt_directory,
        "intent.json",
        &json!({"schema":receipt_schema("intent"),"invocation_id":inv,"plan_sha256":plan_hash,"self_sha256":self_hash,"test_sha256":TEST_SHA,"snapshot_sha256":SNAPSHOT_SHA,"genesis_sha256":GENESIS_SHA,"maximum_memory_bytes":MEMORY_MAX,"tmpfs_bytes":TMPFS_SIZE,"resources_before":resources_before,"entry_replay":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false}),
    )?;
    unsafe {
        libc::signal(libc::SIGTERM, signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT, signal as *const () as libc::sighandler_t);
    }
    let mut command = Command::new(&p.test_binary.path);
    drop_child_credentials(&mut command);
    let mut child = OwnedChild(
        command
            .args(["--ignored", "--nocapture", "--test-threads=1", FILTER])
            .env_clear()
            .env("TMPDIR", "/tmp")
            .env("RUST_MIN_STACK", "134217728")
            .env("SOLANA_RAYON_THREADS", "16")
            .env(
                if PROFILE225 {
                    "JETSTREAMER_V1_6_25_BOUNDARY_SNAPSHOT"
                } else {
                    "JETSTREAMER_SNAPSHOT_86831488"
                },
                &p.snapshot.path,
            )
            .env(
                "JETSTREAMER_MAINNET_LEDGER",
                p.genesis.path.parent().unwrap(),
            )
            .current_dir("/tmp")
            .process_group(0)
            .spawn()?,
        false,
    );
    let started = Instant::now();
    let mut next_guard = Instant::now();
    let mut trip = None;
    let status = loop {
        if let Some(s) = child.0.try_wait()? {
            child.1 = true;
            break s;
        }
        if Instant::now() >= next_guard {
            let memory = host_memory()?;
            let free = ram_geometry()?;
            let reason = if SIGNAL.load(Ordering::SeqCst) != 0 {
                Some("external-signal")
            } else if started.elapsed().as_secs() >= p.maximum_runtime_seconds {
                Some("runtime-bound")
            } else if memory < STOP_MEMORY {
                Some("host-memory-reserve")
            } else if free < FLOOR {
                Some("tmpfs-floor")
            } else {
                None
            };
            if let Some(reason) = reason {
                write_new(
                    &p.receipt_directory,
                    "stop-intent.json",
                    &json!({"invocation_id":inv,"child_pid":child.0.id(),"reason":reason,"memory_available_bytes":memory,"tmpfs_free_bytes":free,"cgroup_resources":resource_snapshot(p).ok(),"producer_signals_sent":false}),
                )?;
                ensure!(
                    unsafe { libc::kill(-(child.0.id() as i32), libc::SIGKILL) } == 0,
                    "cannot stop owned test group"
                );
                trip = Some(reason);
                let status = child.0.wait()?;
                child.1 = true;
                break status;
            }
            next_guard = Instant::now() + Duration::from_secs(15);
        }
        std::thread::sleep(Duration::from_millis(200));
    };
    if SIGNAL.load(Ordering::SeqCst) != 0 {
        trip.get_or_insert("external-signal");
    }
    // Capture before this supervisor exits: systemd may remove the cgroup
    // immediately afterwards. Preserve test failure even if telemetry fails.
    let resources_after = resource_snapshot(p);
    for (path, m) in [
        (&p.test_binary.path, &test),
        (&p.snapshot.path, &snapshot),
        (&p.genesis.path, &genesis),
    ] {
        ensure!(
            identity(m) == identity(&fs::symlink_metadata(path)?),
            "input changed during tests"
        );
    }
    write_new(
        &p.receipt_directory,
        "result.json",
        &json!({"schema":receipt_schema("result"),"invocation_id":inv,"plan_sha256":plan_hash,"self_sha256":self_hash,"test_sha256":TEST_SHA,"snapshot_sha256":SNAPSHOT_SHA,"genesis_sha256":GENESIS_SHA,"elapsed_millis":started.elapsed().as_millis(),"child_exit_code":status.code(),"child_success":status.success(),"trip":trip,"resources_before":resources_before,"resources_after":resources_after.as_ref().ok(),"resource_capture_error":resources_after.as_ref().err().map(|e|format!("{e:#}")),"exact_ignored_test_count":2,"entry_replay":false,"full_peak_qualified":false,"runtime_promotion_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false}),
    )?;
    resources_after?;
    ensure!(
        status.success() && trip.is_none(),
        "snapshot tests failed or resource guard tripped"
    );
    Ok(())
}
fn main() {
    let r = (|| -> Result<()> {
        let args: Vec<_> = env::args().collect();
        if args.len() == 2 && args[1] == "--credential-probe" {
            ensure!(
                unsafe { libc::geteuid() } == 1000
                    && unsafe { libc::getegid() } == 1000
                    && unsafe { libc::getgroups(0, std::ptr::null_mut()) } == 0,
                "wrong child credentials"
            );
            ensure!(
                fs::read_to_string("/proc/self/status")?
                    .lines()
                    .any(|s| s == "CapEff:\t0000000000000000"),
                "child retains capabilities"
            );
            let dir = PathBuf::from(format!(
                "/tmp/horizon-ram-credential-{}",
                std::process::id()
            ));
            fs::DirBuilder::new().mode(0o700).create(&dir)?;
            let file = dir.join("probe");
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&file)?;
            f.write_all(b"ram-only\n")?;
            f.sync_all()?;
            drop(f);
            fs::remove_file(&file)?;
            fs::remove_dir(&dir)?;
            println!("credential-drop-ok");
            return Ok(());
        }
        ensure!(
            args.len() == 6 && args[2] == "--plan-sha256" && args[4] == "--self-sha256",
            "usage: ram-snapshot-test PLAN --plan-sha256 HEX --self-sha256 HEX"
        );
        immutable(&fs::read_link("/proc/self/exe")?, &args[5], 64 << 20)?;
        immutable(Path::new(&args[1]), &args[3], 1 << 20)?;
        let p: Plan = serde_json::from_slice(&fs::read(&args[1])?)?;
        execute(&p, &args[3], &args[5])
    })();
    if let Err(e) = r {
        eprintln!("RAM snapshot test failed closed: {e:#}");
        std::process::exit(1);
    }
}

#[cfg(all(test, not(feature = "epoch225-shrink-snapshot-tests")))]
mod tests {
    use super::*;

    #[cfg(feature = "ram-snapshot-eight-core-stopped225")]
    #[test]
    fn released_cpu_requires_exact_guard_and_original_allocation() {
        let id = "ac9aee3d47eb41e483a5e008ed43d030";
        let completion = json!({"schema":"jetstreamer-horizon-standalone-stop-completion-v1",
            "producer_invocation_id":id,"plan_sha256":"0179bdba5b7d6536d5037b4b195baeca61bd74afd018a0f1a5db43355b9cede5",
            "terminal":{"invocation_id":id,"active":"failed","pid":0,"restarts":0,"cgroup":""},
            "scratch_deleted":false,"remote_mutations":false,"r2_mutations":false});
        let launch = json!({"schema":"jetstreamer-private-epoch225-natural-root-resource-launch-v1",
            "launched":true,"epoch":225,"hard_limits":{"cpu_quota_cores":16,"restart_policy":"no"}});
        validate_released_225(&completion, &launch).unwrap();
        for (ptr, value) in [
            ("/terminal/active", json!("active")),
            ("/terminal/pid", json!(1)),
            ("/terminal/restarts", json!(1)),
            ("/terminal/cgroup", json!("/live")),
            ("/terminal/invocation_id", json!("d".repeat(32))),
            ("/r2_mutations", json!(true)),
        ] {
            let mut bad = completion.clone();
            *bad.pointer_mut(ptr).unwrap() = value;
            assert!(validate_released_225(&bad, &launch).is_err(), "{ptr}");
        }
        let mut bad = launch;
        bad["hard_limits"]["cpu_quota_cores"] = json!(2);
        assert!(validate_released_225(&completion, &bad).is_err());
        assert_eq!(CPU_CORES, 8);
    }

    #[cfg(feature = "ram-snapshot-eight-core-stopped225")]
    #[test]
    fn released_cpu_observer_cannot_reclassify_live_225_as_free_capacity() {
        let mut v = fixture();
        v["diagnostic_replays"][1]["status"] = json!("observed");
        assert!(validate_observer(&v, utc("2026-10-21T00:05:00Z").unwrap()).is_err());
    }

    #[test]
    fn terminal_resources_preserve_exact_kernel_counters_and_require_all_files() {
        let dir = tempfile::tempdir().unwrap();
        for name in RESOURCE_FILES {
            fs::write(dir.path().join(name), "high 123\noom 0\n").unwrap();
        }
        let counters = resource_counters_at(dir.path()).unwrap();
        assert_eq!(counters.as_object().unwrap().len(), RESOURCE_FILES.len());
        assert_eq!(counters["memory.events"], "high 123\noom 0\n");
        fs::remove_file(dir.path().join("cpu.stat")).unwrap();
        assert!(resource_counters_at(dir.path()).is_err());
    }

    #[test]
    fn resource_capture_rejects_symlinks_and_oversized_files() {
        let dir = tempfile::tempdir().unwrap();
        for name in RESOURCE_FILES {
            fs::write(dir.path().join(name), "0\n").unwrap();
        }
        fs::write(dir.path().join("memory.stat"), vec![b'x'; 65_537]).unwrap();
        assert!(resource_counters_at(dir.path()).is_err());
        fs::remove_file(dir.path().join("memory.stat")).unwrap();
        std::os::unix::fs::symlink("memory.events", dir.path().join("memory.stat")).unwrap();
        assert!(resource_counters_at(dir.path()).is_err());
    }
    #[test]
    fn plan_cannot_change_fixture_scope_or_grant_another_mode() {
        let value = json!({"schema":"jetstreamer-private-v1616-ram-snapshot-test-plan-v1","mode":"capability",
            "unit":"horizon-v1616-snapshot-test-fixture.service",
            "test_binary":{"path":"/sealed/tests","sha256":TEST_SHA},
            "snapshot":{"path":"/sealed/snapshot-86831488-ADFPkz1fATPmpkDdL8ZZAUtjfa4EwUfn1J2WeSrsDWFk.tar.zst","sha256":SNAPSHOT_SHA},
            "genesis":{"path":"/sealed/genesis.tar.bz2","sha256":GENESIS_SHA},
            "observer":{"path":"/private/observer.json","sha256":"a".repeat(64)},
            "fleet":{"path":"/private/fleet.json","sha256":"b".repeat(64)},
            "receipt_directory":"/var/lib/jetstreamer/horizon-ram-snapshot-tests/ram-snapshot-test-fixture",
            "maximum_runtime_seconds":1800});
        validate_plan(&serde_json::from_value(value.clone()).unwrap()).unwrap();
        for (pointer, changed) in [
            ("/mode", json!("replay")),
            ("/unit", json!("foreign.service")),
            ("/test_binary/sha256", json!("c".repeat(64))),
            (
                "/snapshot/path",
                json!("/sealed/snapshot-87695515-other.tar.zst"),
            ),
            ("/genesis/sha256", json!("d".repeat(64))),
            (
                "/receipt_directory",
                json!("/tmp/ram-snapshot-test-fixture"),
            ),
            ("/maximum_runtime_seconds", json!(1801)),
        ] {
            let mut bad = value.clone();
            *bad.pointer_mut(pointer).unwrap() = changed;
            assert!(
                validate_plan(&serde_json::from_value(bad).unwrap()).is_err(),
                "{pointer}"
            );
        }
        let mut unknown = value;
        unknown["publication_authorized"] = json!(true);
        assert!(serde_json::from_value::<Plan>(unknown).is_err());
    }
    #[test]
    fn sandbox_is_private_ram_only_and_minimally_privileged() {
        let path =
            Path::new("/var/lib/jetstreamer/horizon-ram-snapshot-tests/ram-snapshot-test-fixture");
        let s = format!(
            "NoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=read-only\nProtectControlGroups=yes\nPrivateNetwork=yes\nOOMPolicy=kill\nOOMScoreAdjust=1000\nTemporaryFileSystem={}\nReadWritePaths={}\nCapabilityBoundingSet=cap_dac_override cap_kill cap_setgid cap_setuid\n",
            TMPFS_OPTIONS,
            path.display()
        );
        validate_sandbox(&s, path).unwrap();
        if PROFILE225 {
            assert!(validate_sandbox(&s.replace("nr_inodes=1048576,", ""), path).is_err());
            assert!(
                validate_sandbox(&s.replace("nr_inodes=1048576", "nr_inodes=409600"), path)
                    .is_err()
            );
            validate_inode_geometry(1_048_576).unwrap();
            assert!(validate_inode_geometry(409_600).is_err());
            assert!(validate_inode_geometry(1_048_575).is_err());
            assert!(validate_inode_geometry(1_048_577).is_err());
        } else {
            validate_inode_geometry(409_600).unwrap();
        }
        for (from, to) in [
            ("cap_setuid", "cap_sys_admin"),
            ("ProtectHome=read-only", "ProtectHome=no"),
            ("size=512G", "size=64G"),
            ("ReadWritePaths=/var/lib", "ReadWritePaths=/other"),
            ("OOMPolicy=kill", "OOMPolicy=continue"),
        ] {
            assert!(
                validate_sandbox(&s.replace(from, to), path).is_err(),
                "{from}"
            );
        }
    }
    fn fixture() -> Value {
        let mut ranges = Vec::new();
        for (range, ctrl, prod) in [
            (
                "216-219",
                "2b6ded8d8baf4f72a5c8a91385f7c278",
                "95fb05d1b78349bcb907c1e930e7682e",
            ),
            (
                "220-223",
                "0b69b5009dc74bbda94b94d059a3daa7",
                "c2adebaad0cb42b385156631156813fe",
            ),
            (
                "203-203",
                "92e367eb7cf944a1825fe5a20d9243ca",
                "92e367eb7cf944a1825fe5a20d9243ca",
            ),
            (
                "225-226",
                "ac9aee3d47eb41e483a5e008ed43d030",
                "ac9aee3d47eb41e483a5e008ed43d030",
            ),
        ] {
            ranges.push(json!({"range":range,"invocation_binding_stable":true,
                "controller_before":{"invocation_id":ctrl,"restarts":0,"active_state":"active"},
                "controller_after":{"invocation_id":ctrl,"restarts":0,"active_state":"active"},
                "producer_before":{"invocation_id":prod,"restarts":0,"active_state":"active"},
                "producer_after":{"invocation_id":prod,"restarts":0,"active_state":"active"}}));
        }
        let stopped = if RELEASED_225 {
            json!({"range":"225-226","status":"unavailable","observation":null,
                "producer_unit":"horizon-qualify-225-natural-root-resource-63a2717-v1.service",
                "expected_producer_invocation_id":"ac9aee3d47eb41e483a5e008ed43d030",
                "ordinary_replay_claim":false,"replay_launch_authorized":false})
        } else {
            json!({"range":"225-226","observation":ranges[3]})
        };
        json!({"schema":"jetstreamer-horizon-live-resource-sample-v2","recorded_at_utc":"2026-10-21T00:04:42Z",
            "cadence":{"routine_minimum_interval_enforced":true,"observation_reason":"routine","minimum_interval_seconds":1800},
            "mutation":{"producer_or_controller_signals_sent":false,"service_state_changed":false,"remote_mutations":false,"r2_mutations":false},
            "host_memory":{"conservative_available_kib":START_MEMORY/1024},
            "replays":[ranges[0],ranges[1]],"diagnostic_replays":[{"range":"203-203","observation":ranges[2]},stopped]})
    }
    #[test]
    fn observer_admission_binds_every_controller_producer_and_memory() {
        let good = fixture();
        let now = utc("2026-10-21T00:05:00Z").unwrap();
        validate_observer(&good, now).unwrap();
        for (ptr, value) in [
            (
                "/replays/0/controller_after/invocation_id",
                json!("a".repeat(32)),
            ),
            ("/replays/1/producer_before/restarts", json!(1)),
            (
                "/diagnostic_replays/0/observation/producer_after/active_state",
                json!("failed"),
            ),
            (
                if RELEASED_225 {
                    "/diagnostic_replays/1/expected_producer_invocation_id"
                } else {
                    "/diagnostic_replays/1/observation/invocation_binding_stable"
                },
                if RELEASED_225 {
                    json!("d".repeat(32))
                } else {
                    json!(false)
                },
            ),
            (
                "/host_memory/conservative_available_kib",
                json!((START_MEMORY / 1024) - 1),
            ),
            (
                "/cadence/observation_reason",
                json!("user-requested-status"),
            ),
            ("/mutation/r2_mutations", json!(true)),
        ] {
            let mut bad = good.clone();
            *bad.pointer_mut(ptr).unwrap() = value;
            assert!(validate_observer(&bad, now).is_err(), "{ptr}");
        }
        assert!(validate_observer(&good, now + 1800).is_err());
        assert!(validate_observer(&good, now - 60).is_err());
        let mut bad = good;
        bad["replays"].as_array_mut().unwrap().pop();
        assert!(validate_observer(&bad, now).is_err());
    }
    #[test]
    fn fleet_admission_requires_exact_complete_claims_and_century() {
        let observer = fixture();
        let mut active = Vec::new();
        for (id, count) in [
            ("95fb05d1b78349bcb907c1e930e7682e", 4),
            ("c2adebaad0cb42b385156631156813fe", 4),
            ("92e367eb7cf944a1825fe5a20d9243ca", 1),
            (
                "ac9aee3d47eb41e483a5e008ed43d030",
                if RELEASED_225 { 0 } else { 1 },
            ),
        ] {
            for _ in 0..count {
                active.push(
                    json!({"producer":{"InvocationID":id,"ActiveState":"active","NRestarts":"0"}}),
                );
            }
        }
        let entries: Vec<_> = [
            (201, 102605729507u64),
            (202, 101842225683),
            (206, 108774749680),
            (213, 125368013231),
            (214, 128213350837),
            (215, 128820081409),
        ]
        .into_iter()
        .map(|(epoch, len)| json!({"epoch":epoch,"archive_length":len,"state":"ready-pair"}))
        .collect();
        let f = json!({"schema":"jetstreamer-horizon-campaign-fleet-v1","observer_sha256":"b".repeat(64),
            "sampled_at_utc":observer["recorded_at_utc"],"first_epoch":201,"last_epoch":300,
            "producer_mutations":false,"remote_mutations":false,"active":active,
            "inventory":{"ready_pairs":6,"entries":entries}});
        validate_fleet(&f, &observer, &"b".repeat(64)).unwrap();
        for (ptr, value) in [
            ("/observer_sha256", json!("c".repeat(64))),
            ("/active/0/producer/InvocationID", json!("d".repeat(32))),
            ("/active/0/producer/NRestarts", json!("1")),
            ("/inventory/ready_pairs", json!(7)),
            ("/inventory/entries/0/archive_length", json!(1)),
        ] {
            let mut bad = f.clone();
            *bad.pointer_mut(ptr).unwrap() = value;
            assert!(
                validate_fleet(&bad, &observer, &"b".repeat(64)).is_err(),
                "{ptr}"
            );
        }
    }
    #[test]
    fn child_error_cleanup_kills_only_the_owned_process_group() {
        let child = Command::new("/usr/bin/sleep")
            .arg("30")
            .process_group(0)
            .spawn()
            .unwrap();
        let pid = child.id();
        drop(OwnedChild(child, false));
        assert_eq!(unsafe { libc::kill(pid as i32, 0) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ESRCH)
        );
    }
    #[test]
    fn tmpfs_cgroup_bound_preserves_century_floor_even_at_limit() {
        assert_eq!(MEMORY_HIGH, 112 * GIB);
        assert_eq!(MEMORY_MAX - MEMORY_HIGH, 16 * GIB);
        assert_eq!(START_MEMORY, 576 * GIB);
        assert_eq!(START_MEMORY - MEMORY_MAX, STOP_MEMORY);
        assert_eq!(TMPFS_SIZE - MEMORY_MAX, 384 * GIB);
        validate_reserves(TMPFS_SIZE, MEMORY_MAX, FLOOR, STOP_MEMORY).unwrap();
        assert!(validate_reserves(64 * GIB, MEMORY_MAX, FLOOR, STOP_MEMORY).is_err());
        assert!(validate_reserves(TMPFS_SIZE, MEMORY_MAX, FLOOR, 64 * GIB).is_err());
    }
    #[test]
    fn memory_parser_is_exact_and_overflow_checked() {
        assert_eq!(
            memory_available("MemTotal: 1 kB\nMemAvailable: 123 kB\n").unwrap(),
            123 * 1024
        );
        for s in [
            "",
            "MemAvailable: 1 MB",
            "MemAvailable: 1 kB\nMemAvailable: 2 kB",
            "MemAvailable: 18446744073709551615 kB",
        ] {
            assert!(memory_available(s).is_err());
        }
    }
    #[test]
    fn exact_two_ignored_tests_are_required() {
        let s = format!(
            "{}\n{}\n\n2 tests, 0 benchmarks\n",
            TEST_NAMES[0], TEST_NAMES[1]
        );
        validate_test_list(&s).unwrap();
        assert!(validate_test_list(&s.replace("2 tests", "0 tests")).is_err());
        assert!(validate_test_list(&s.replace(TEST_NAMES[1], "other: test")).is_err());
    }
    #[test]
    fn utc_rejects_normalized_or_noncanonical_dates() {
        assert_eq!(utc("2026-10-21T00:04:42Z").unwrap(), 1792541082);
        for s in [
            "2026-02-30T00:00:00Z",
            "2026-10-21T0:04:42Z",
            "2026-10-21T00:04:42+00:00",
        ] {
            assert!(utc(s).is_err());
        }
    }
}
