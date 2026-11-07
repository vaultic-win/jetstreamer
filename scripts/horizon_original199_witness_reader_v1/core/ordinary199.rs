//! Exact additive 199/200 owner. Immutable evidence is read before projection;
//! projected values are exclusively inputs to the retained legacy validators.
#![allow(dead_code)] // Identical read-only module is shared by fleet and Frame callers.
use anyhow::{Context, Result, ensure};
use original199_input_witness_consumer as witness;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::Read,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt},
        },
    },
    path::{Component, Path, PathBuf},
};

pub const FIELD: &str = "epoch199_enrollment";
pub const TERMINAL_FIELD: &str = "epoch199_terminal_context";
pub const CONTROLLER: &str = "jetstreamer-epoch199-backfill-20261102-controller-v1-r2.service";
pub const PRODUCER: &str =
    "jetstreamer-root-sweep-e199-backfill-20261102-v1-e199-200-lane-a-1.service";
pub const GUARD: &str = "jetstreamer-adaptive-reserve-epoch199-backfill-20261102-v1.service";
pub const TIMER: &str = "jetstreamer-adaptive-reserve-epoch199-backfill-20261102-v1.timer";
pub const FAMILY: [&str; 4] = [CONTROLLER, PRODUCER, GUARD, TIMER];
const NODE: &str =
    "/usr/local/lib/jetstreamer/deploy-epoch199-singleton-20261017-v1/jetstreamer-node";
const WORKER: &str = "/usr/local/lib/jetstreamer/deploy-epoch199-singleton-20261017-v1/jetstreamer-historical-worker-v1-6-15";
const MANIFEST: &str = "/usr/local/lib/jetstreamer/deploy-epoch199-singleton-20261017-v1/preflight-199-with-private-200-tail-v4.json";
const SNAPSHOT: &str = "/usr/local/lib/jetstreamer/deploy-epoch199-singleton-20261017-v1/snapshot-85967282-BQvC7FcQTSguJkWHeLnpkVSFv32ZKRqUbgHKxVF97o3x.tar.zst";
const RAW_PATH: &str = "/var/lib/jetstreamer/epoch136-hourly-charge-trace-20261029-v1/attempts/retry-0004/admission.json";
const RAW_SHA: &str = "6bc2f22464de9291b5413ae252121f85c0b54fddfbd9a0021b5de485c0827d2f";
const RAW_MEMORY: u64 = 788_077_379_584;
const RAW_DATA: u64 = 4_202_184_371_152;
const RETIRED_MEMORY: u64 = 207_232_172_032;
const PARENT_MEMORY: u64 = 192 << 30;
const AUX_MEMORY: u64 = 512 << 20;
const CANDIDATE_DATA: u64 = 768 << 30;
const OVERHEAD_BASE: u64 = 37_818_572_800;
const ELIGIBILITY_PROGRAM: &str = "/usr/local/lib/jetstreamer/horizon-backfill-memory-eligibility-tools-20261102-v1/jetstreamer-backfill-memory-eligibility";
const ELIGIBILITY_SHA: &str = "c54cb39e1d7d12e620f89b4d7f348746841cdcea46ac12391f3e4b0e762e0ff0";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bound {
    pub path: PathBuf,
    pub sha256: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tuple {
    pub observer: Bound,
    pub fleet: Bound,
    pub fleet_plan: Bound,
    pub frame: Bound,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Owner {
    pub unit: String,
    pub invocation_id: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Budget {
    pub schema: String,
    pub prelaunch: Tuple,
    pub raw_admission: Bound,
    pub qualified_eligibility: Bound,
    pub century_inventory: Bound,
    pub controller_argv: Bound,
    pub controller_script: Bound,
    pub candidate_members: Vec<Bound>,
    pub recorded_unix_seconds: u64,
    pub launch_expires_unix_seconds: u64,
    pub total_reserved_memory_bytes: u64,
    pub required_initial_free_bytes: u64,
    pub protected_data_bytes: u64,
    pub century_floor_bytes: u64,
    pub inherited_available_memory_floor_bytes: u64,
    pub preserved_raw_memory_bytes: u64,
    pub retired_peer_reduction_bytes: u64,
    pub positive_uncovered_overhead_bytes: u64,
    pub external_serial_bytes: u64,
    pub parent_memory_bytes: u64,
    pub controller_memory_bytes: u64,
    pub guard_memory_bytes: u64,
    pub candidate_data_bytes: u64,
    pub protected_cpu_micros: u64,
    pub candidate_credit_bytes: u64,
    pub physical_credit_bytes: u64,
    pub publish_through_epoch: u64,
    pub private_tail_epochs: Vec<u64>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Enrollment {
    pub schema: String,
    pub budget: Bound,
    pub controller: Owner,
    pub producer: Owner,
    pub guard_first_owner: Owner,
    pub timer_owner: Owner,
    pub guard_program: Bound,
    pub guard_argv: Bound,
    pub first_guard_proof: Bound,
    pub producer_argv: Bound,
    pub scratch_path: PathBuf,
    pub worker_executable_basename: String,
    pub recorded_unix_seconds: u64,
    pub producer_memory_bytes: u64,
    pub controller_memory_bytes: u64,
    pub guard_memory_bytes: u64,
    pub candidate_data_bytes: u64,
    pub cpu_quota_micros: u64,
    pub candidate_credit_bytes: u64,
}
#[derive(Clone)]
pub struct Proof {
    pub binding: Bound,
    pub enrollment: Enrollment,
    pub budget: Budget,
    pub budget_binding: Bound,
    selected_inputs: Option<witness::SelectedInputs>,
}
fn native_memory_matches(value: &Value, expected_bytes: u64) -> bool {
    let expected = expected_bytes.to_string();
    value.as_str() == Some(expected.as_str())
}
fn n(v: &Value, k: &str) -> Result<u64> {
    v[k].as_u64().with_context(|| format!("199 integer {k}"))
}
fn sum(values: impl IntoIterator<Item = u64>) -> Result<u64> {
    values.into_iter().try_fold(0u64, |a, b| {
        a.checked_add(b).context("199 arithmetic overflow")
    })
}
fn hex(s: &str, length: usize) -> bool {
    s.len() == length
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn id(m: &fs::Metadata) -> (u64, u64, u64, u32, u32, u64, i64, i64, i64, i64) {
    (
        m.dev(),
        m.ino(),
        m.len(),
        m.uid(),
        m.mode(),
        m.nlink(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}
/// Same descriptor-relative, no-symlink custody algorithm as retained::io::open.
fn open(path: &Path) -> Result<File> {
    ensure!(path.is_absolute(), "199 nonabsolute input");
    let mut parent = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")?;
    let parts = path.components().collect::<Vec<_>>();
    ensure!(parts.len() > 1, "199 root input");
    for (i, part) in parts.iter().enumerate().skip(1) {
        let Component::Normal(name) = part else {
            anyhow::bail!("199 noncanonical input component")
        };
        let c = std::ffi::CString::new(name.as_bytes())?;
        let flags = libc::O_RDONLY
            | libc::O_NOFOLLOW
            | libc::O_CLOEXEC
            | libc::O_NONBLOCK
            | if i + 1 < parts.len() {
                libc::O_DIRECTORY
            } else {
                0
            };
        let fd = unsafe { libc::openat(parent.as_raw_fd(), c.as_ptr(), flags) };
        ensure!(
            fd >= 0,
            "199 cannot open evidence component: {}",
            std::io::Error::last_os_error()
        );
        let next = unsafe { File::from_raw_fd(fd) };
        let m = next.metadata()?;
        ensure!(
            m.mode() & 0o022 == 0,
            "199 writable evidence ancestor/member"
        );
        parent = next;
    }
    Ok(parent)
}
pub fn bytes(b: &Bound, maximum: u64) -> Result<Vec<u8>> {
    ensure!(hex(&b.sha256, 64), "199 malformed digest");
    let mut f = open(&b.path)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o222 == 0
            && m.len() > 0
            && m.len() <= maximum,
        "199 immutable root custody/size"
    );
    let mut raw = Vec::new();
    Read::by_ref(&mut f)
        .take(maximum + 1)
        .read_to_end(&mut raw)?;
    ensure!(
        raw.len() as u64 == m.len()
            && format!("{:x}", Sha256::digest(&raw)) == b.sha256
            && id(&m) == id(&f.metadata()?)
            && id(&m) == id(&open(&b.path)?.metadata()?),
        "199 changed bytes/path"
    );
    Ok(raw)
}
pub fn read(b: &Bound) -> Result<Value> {
    Ok(serde_json::from_slice(&bytes(b, 16 << 20)?)?)
}
fn hash_member(b: &Bound, maximum: u64) -> Result<()> {
    ensure!(hex(&b.sha256, 64), "199 member digest");
    let mut f = open(&b.path)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o222 == 0
            && m.len() > 0
            && m.len() <= maximum,
        "199 member custody"
    );
    let mut hash = Sha256::new();
    let mut buffer = vec![0u8; 1 << 20];
    let mut count = 0u64;
    loop {
        let length = f.read(&mut buffer)?;
        if length == 0 {
            break;
        }
        count = sum([count, length as u64])?;
        ensure!(count <= maximum, "199 member grew");
        hash.update(&buffer[..length]);
    }
    ensure!(
        count == m.len()
            && format!("{:x}", hash.finalize()) == b.sha256
            && id(&m) == id(&f.metadata()?)
            && id(&m) == id(&open(&b.path)?.metadata()?),
        "199 member bytes/identity changed"
    );
    Ok(())
}
fn member_set(b: &Budget, selected: Option<&witness::SelectedInputs>) -> Result<()> {
    let expected = [
        (
            NODE,
            "a09b8e5aa9426beaf42e6b5f2a469a5a147436bab8b7bf79f268758b60aa2e65",
        ),
        (
            WORKER,
            "9339aa0ee5c39e91ec446bfa561c0e81280a0ddc474a03cf5bb0ce07a3674893",
        ),
        (
            MANIFEST,
            "9a975243f50d37ed71329b5f3cd0f5e4a4c83faf2e8018f6db41ed9170ac1de9",
        ),
        (
            SNAPSHOT,
            "d4a74f54f44258fd4b078d8d3304a6cb6a7911a87883160e1579727dafbf9e6d",
        ),
    ];
    ensure!(
        b.candidate_members.len() == expected.len(),
        "199 input census"
    );
    for (path, sha) in expected {
        let members = b
            .candidate_members
            .iter()
            .filter(|m| m.path == Path::new(path) && m.sha256 == sha)
            .collect::<Vec<_>>();
        ensure!(members.len() == 1, "199 immutable input crossed");
        let maximum = if path == SNAPSHOT {
            8_000_000_000
        } else {
            128 << 20
        };
        if let Some(selected) = selected {
            selected.verify_member(&witness_bound(members[0]), maximum)?;
        } else {
            hash_member(members[0], maximum)?;
        }
    }
    ensure!(
        b.controller_script.sha256
            == "62592209a3fc2b659ea4bfb924bbcf34435b4228c87e56232eb6b962b907023e",
        "199 controller source changed"
    );
    hash_member(&b.controller_script, 1 << 20)?;
    Ok(())
}
fn rss(v: &Value) -> Result<BTreeMap<u64, (u64, u64)>> {
    ensure!(
        v["census_stable"] == true && v["error"].is_null(),
        "199 unstable RSS census"
    );
    let mut rows = BTreeMap::new();
    for r in v["processes"].as_array().context("199 RSS members")? {
        let pid = n(r, "pid")?;
        let start = n(r, "start_ticks")?;
        ensure!(
            pid > 0 && start > 0 && rows.insert(pid, (start, n(r, "rss_bytes")?)).is_none(),
            "199 duplicate/reused RSS PID"
        );
    }
    ensure!(
        sum(rows.values().map(|x| x.1))? == n(v, "aggregate_rss_bytes")?,
        "199 RSS aggregate"
    );
    Ok(rows)
}
fn kernel(v: &Value) -> Result<u64> {
    let k = &v["kernel_components_bytes"];
    ensure!(
        k.as_object().is_some_and(|m| m.len() == 4),
        "199 kernel census"
    );
    sum(["Slab", "KernelStack", "PageTables", "Percpu"]
        .into_iter()
        .map(|key| n(k, key))
        .collect::<Result<Vec<_>>>()?)
}
fn utc(s: &str) -> Result<u64> {
    ensure!(
        s.len() == 20 && s.is_ascii() && s.ends_with('Z'),
        "199 UTC shape"
    );
    let input = std::ffi::CString::new(&s[..19])?;
    let format = std::ffi::CString::new("%Y-%m-%dT%H:%M:%S")?;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    ensure!(
        !unsafe { libc::strptime(input.as_ptr(), format.as_ptr(), &mut tm) }.is_null(),
        "199 UTC parse"
    );
    let seconds = unsafe { libc::timegm(&mut tm) };
    ensure!(
        seconds >= 0
            && format!(
                "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
                tm.tm_year + 1900,
                tm.tm_mon + 1,
                tm.tm_mday,
                tm.tm_hour,
                tm.tm_min,
                tm.tm_sec
            ) == s,
        "199 normalized UTC"
    );
    Ok(seconds as u64)
}
fn old_raw_memory(raw: &Value, old_observer: &Value) -> Result<u64> {
    ensure!(
        old_observer["replays"]
            .as_array()
            .is_some_and(Vec::is_empty),
        "199 original raw ordinary census changed"
    );
    let peers = raw["resource_accounting"]["active_peer_allocations"]
        .as_array()
        .context("199 original raw peers")?;
    let mut seen = BTreeSet::new();
    let mut peer = 0;
    for p in peers {
        ensure!(
            seen.insert((
                p["unit"].clone().to_string(),
                p["invocation_id"].clone().to_string()
            )),
            "199 duplicate original raw peer"
        );
        if p["native_pool_suballocation"] == false {
            peer = sum([peer, n(p, "memory_max_bytes")?])?;
        }
    }
    let mut existing = 264_486_256_640u64;
    for end in ["before", "after"] {
        let h = &old_observer["host_resident_memory"][end];
        ensure!(
            h["status"] == "observed",
            "199 original raw host unavailable"
        );
        rss(&h["rss"])?;
        existing = existing.max(sum([
            n(&h["rss"], "aggregate_rss_bytes")?,
            kernel(h)?,
            128 << 30,
            16 << 30,
            64 << 30,
            512 << 20,
        ])?);
    }
    sum([existing, peer, 68 << 30])
}
fn current_overhead(o: &Value) -> Result<u64> {
    ensure!(
        o["replays"].as_array().is_some_and(Vec::is_empty),
        "199 prelaunch has another ordinary replay"
    );
    let mut maximum = 0;
    let rows = o["diagnostic_replays"]
        .as_array()
        .context("199 prelaunch diagnostics")?;
    let live = rows
        .iter()
        .filter(|r| {
            r["status"] == "observed"
                && r["observation"]["producer_after"]["active_state"] == "active"
                && r["observation"]["producer_after"]["sub_state"] == "running"
        })
        .collect::<Vec<_>>();
    ensure!(
        live.len() == 1
            && live[0]["range"] == "145"
            && live[0]["observation"]["invocation_binding_stable"] == true,
        "199 prelaunch must retain exactly cached145 replay"
    );
    for end in ["before", "after"] {
        let h = &o["host_resident_memory"][end];
        ensure!(h["status"] == "observed", "199 current host unavailable");
        let host = rss(&h["rss"])?;
        let mut covered = BTreeMap::new();
        for role in ["producer", "controller"] {
            let p = &live[0]["observation"][format!("{role}_{end}")];
            ensure!(
                p["invocation_id"] == "15ddd220e2144aaa8d7418f73f60768f" && p["restarts"] == 0,
                "199 cached145 owner changed"
            );
            for (pid, (start, _)) in rss(&p["rss"])? {
                let actual = host
                    .get(&pid)
                    .context("199 lane absent from same-end host")?;
                ensure!(actual.0 == start, "199 reused lane PID");
                covered.insert(pid, *actual);
            }
        }
        let other = n(&h["rss"], "aggregate_rss_bytes")?
            .checked_sub(sum(covered.values().map(|x| x.1))?)
            .context("199 double RSS subtraction")?;
        maximum = maximum.max(sum([other, kernel(h)?])?);
    }
    Ok(maximum)
}
fn argv(b: &Bound) -> Result<Vec<String>> {
    Ok(serde_json::from_value(read(b)?)?)
}
fn exact_option(a: &[String], name: &str, value: &str) -> Result<()> {
    let prefix = format!("--{name}=");
    let found = a
        .iter()
        .filter_map(|x| x.strip_prefix(&prefix))
        .collect::<Vec<_>>();
    ensure!(
        found == [value],
        "199 controller/guard option missing, duplicate or changed: {name}"
    );
    Ok(())
}
fn controller_argv(b: &Budget) -> Result<Vec<String>> {
    let a = argv(&b.controller_argv)?;
    ensure!(
        a.len() > 2
            && a[0] == "/usr/bin/python3"
            && a[1]
                == b.controller_script
                    .path
                    .to_str()
                    .context("199 script UTF8")?,
        "199 controller executable"
    );
    for (k, v) in [
        ("controller-id", "e199-backfill-20261102-v1"),
        (
            "state-dir",
            "/var/lib/jetstreamer-root-sweep-epoch199-backfill-20261102-v1",
        ),
        ("first-epoch", "199"),
        ("last-epoch", "200"),
        ("initial-concurrency", "1"),
        ("target-concurrency", "1"),
        ("max-concurrency", "1"),
        ("memory-high-gib", "128"),
        ("memory-max-gib", "192"),
        ("memory-admission-gib", "181"),
        ("memory-reserve-gib", "64"),
        ("protected-memory-gib", "285"),
        ("disk-reserve-gib", "3577"),
        ("disk-budget-per-worker-gib", "768"),
        ("cpu-quota-percent", "800"),
        ("solana-rayon-threads", "8"),
        ("manifest", MANIFEST),
        (
            "external-disk-growth-claim-gib",
            "horizon-qualify-145-cached-b2a09f57de39c384.service=15ddd220e2144aaa8d7418f73f60768f:337",
        ),
        (
            "manifest-fingerprint",
            "sha256:581f9ef3a74fc80a8b6b2754a7f4def480c8092d20529f446784f0d73dae810b",
        ),
    ] {
        exact_option(&a, k, v)?;
    }
    ensure!(
        a.iter().filter(|s| s.as_str() == "--execute").count() == 1
            && !a.iter().any(|s| s == "--retry-failed"),
        "199 execute/retry contract"
    );
    Ok(a)
}
#[allow(clippy::too_many_arguments)] // Eight independent immutable evidence roles remain explicit.
pub fn validate_budget_values(
    b: &Budget,
    raw: &Value,
    old: &Value,
    o: &Value,
    fleet: &Value,
    frame: &Value,
    eligible: &Value,
    floor: &Value,
) -> Result<Value> {
    ensure!(
        b.schema == "horizon-epoch199-prelaunch-budget-v1"
            && b.raw_admission.path == Path::new(RAW_PATH)
            && b.raw_admission.sha256 == RAW_SHA,
        "199 raw admission lineage"
    );
    let raw_memory = old_raw_memory(raw, old)?;
    ensure!(
        raw_memory == RAW_MEMORY
            && raw["memory_evidence"]["captured141_memory_retirement"]["raw_total_memory_promises_bytes"]
                == raw_memory,
        "199 raw memory not independently reproduced"
    );
    let accounting = &raw["resource_accounting"];
    let protected = [
        "protected_existing_DATA_bytes",
        "standing_frontier_bytes",
        "inherited_live_guard_maximum_bytes",
        "confirmed_DATA_floor_bytes",
    ]
    .into_iter()
    .map(|k| n(accounting, k))
    .collect::<Result<Vec<_>>>()?
    .into_iter()
    .max()
    .context("199 DATA maximum")?;
    ensure!(protected == RAW_DATA, "199 preserved DATA changed");
    ensure!(
        o["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && fleet["schema"] == "jetstreamer-horizon-campaign-fleet-v1"
            && fleet["first_epoch"] == 101
            && fleet["last_epoch"] == 200
            && fleet["inventory"]["anomalies"] == 0
            && fleet["observer_receipt"] == json!(b.prelaunch.observer.path)
            && fleet["observer_sha256"] == b.prelaunch.observer.sha256
            && fleet["sampled_at_utc"] == o["recorded_at_utc"]
            && frame["accepted_resource_lineage"] == true
            && frame["bindings"]["observer"] == json!(b.prelaunch.observer)
            && frame["bindings"]["fleet"] == json!(b.prelaunch.fleet)
            && frame["bindings"]["fleet_plan"] == json!(b.prelaunch.fleet_plan),
        "199 accepted prelaunch tuple crossed"
    );
    ensure!(
        eligible["schema"] == "horizon-registered-retired-peer-current-eligibility-v1"
            && eligible["current"] == json!(b.prelaunch)
            && eligible["running_image"]
                == json!({"path":ELIGIBILITY_PROGRAM,"sha256":ELIGIBILITY_SHA})
            && eligible["eligible_memory_reduction_bytes"] == RETIRED_MEMORY
            && eligible["retained_DATA_bytes"] == 155_692_564_480u64
            && eligible["DATA_credit_bytes"] == 0
            && eligible["physical_credit_bytes"] == 0
            && eligible["guard_changes"] == false
            && eligible["full_host_admission_authorized"] == false
            && eligible["applied"].as_array().is_some_and(|r| r.len() == 1)
            && eligible["applied"][0]["effective_peer_reduction_bytes"] == RETIRED_MEMORY
            && eligible["applied"][0]["claim_key"]
                == "captured141-memory/3e00e27647d74143a8af7e2328379e06"
            && eligible["applied"][0]["receipt"]
                == json!({"path":"/var/lib/jetstreamer/horizon-captured141-memory-only-retirement-3e00e27647d74143a8af7e2328379e06-v1/memory-only-retirement.receipt.json","sha256":"a81bc59fb79574067724b0dec745f5d4047c219b40aaa40fd10a52a9b9594c6b"})
            && eligible["complete_peer_census_claimed"] == false
            && eligible["complete_host_memory_total_claimed"] == false
            && eligible["replay_launch_authorized"] == false
            && eligible["archive_or_R2_mutations"] == false,
        "199 qualified current retirement crossed or double credit"
    );
    ensure!(
        floor["schema"] == "jetstreamer-horizon-r2-inventory-v1"
            && floor["first_epoch"] == 201
            && floor["last_epoch"] == 201
            && floor["ready_pairs"] == 1
            && floor["anomalies"] == 0
            && floor["entries"].as_array().is_some_and(|r| r.len() == 1),
        "199 current floor inventory"
    );
    let sample = &floor["entries"][0];
    ensure!(
        sample == &accounting["authenticated_floor_inventory"][0]
            && sample["state"] == "ready-pair"
            && sample["epoch"] == 201
            && sample["archive_metadata_sha256"] == sample["sidecar_sha256"],
        "199 verified201 floor evidence changed"
    );
    let century_floor = n(sample, "archive_length")?
        .checked_mul(2)
        .context("199 floor overflow")?;
    let positive = current_overhead(o)?.saturating_sub(OVERHEAD_BASE);
    let sample_clock = utc(o["recorded_at_utc"]
        .as_str()
        .context("199 prelaunch sample clock")?)?;
    ensure!(
        n(o, "vm_max_map_count")? >= 4_194_304,
        "199 prelaunch VMA capability is insufficient"
    );
    ensure!(
        b.recorded_unix_seconds >= sample_clock && b.recorded_unix_seconds - sample_clock <= 1800,
        "199 budget is outside accepted sample freshness"
    );
    let total = sum([
        raw_memory
            .checked_sub(RETIRED_MEMORY)
            .context("199 retirement underflow")?,
        PARENT_MEMORY,
        AUX_MEMORY,
        AUX_MEMORY,
        6 << 30,
        positive,
    ])?;
    // Reproduce the actual controller's whole-GiB reserve arithmetic, including
    // its separately bound older145 growth claim exactly once.
    let controller_protected = protected.max(sum([3577u64 << 30, 337u64 << 30])?);
    let required = sum([controller_protected, CANDIDATE_DATA])?;
    ensure!(
        b.preserved_raw_memory_bytes == raw_memory
            && b.retired_peer_reduction_bytes == RETIRED_MEMORY
            && b.positive_uncovered_overhead_bytes == positive
            && b.external_serial_bytes == 6 << 30
            && b.parent_memory_bytes == PARENT_MEMORY
            && b.controller_memory_bytes == AUX_MEMORY
            && b.guard_memory_bytes == AUX_MEMORY
            && b.candidate_data_bytes == CANDIDATE_DATA
            && b.total_reserved_memory_bytes == total
            && b.protected_data_bytes == controller_protected
            && b.required_initial_free_bytes == required
            && b.century_floor_bytes == century_floor
            && b.inherited_available_memory_floor_bytes == 0
            && b.candidate_credit_bytes == 0
            && b.physical_credit_bytes == 0
            && b.publish_through_epoch == 199
            && b.private_tail_epochs == [200],
        "199 budget omits, credits, duplicates or changes a promise"
    );
    ensure!(
        n(&o["host_memory"], "total_kib")?
            .checked_mul(1024)
            .context("199 host total")?
            >= total
            && n(&o["filesystem"], "conservative_available_bytes")? >= required,
        "199 sampled complete budget does not fit"
    );
    // Historical CPU: 16 cores cached145, 2 captured141 retained, 3 failed4 and
    // the original independent 8-core verification/native allowance. All stay.
    ensure!(
        accounting["current_replay_cpu_quota_micros"] == 16_000_000u64
            && raw["cpu_quota_micros"] == 3_000_000u64
            && raw["memory_evidence"]["captured141_memory_retirement"]["historical_CPU_charge_microseconds"]
                == 2_000_000u64,
        "199 historical CPU changed"
    );
    let cpu = sum([
        16_000_000, 2_000_000, 3_000_000, 8_000_000, 8_000_000, 1_000_000, 1_000_000,
    ])?;
    ensure!(
        b.protected_cpu_micros == cpu
            && b.launch_expires_unix_seconds >= b.recorded_unix_seconds
            && b.launch_expires_unix_seconds - b.recorded_unix_seconds <= 900,
        "199 CPU or launch horizon changed"
    );
    Ok(
        json!({"raw_memory_bytes":raw_memory,"retired_peer_memory_bytes":RETIRED_MEMORY,"candidate_parent_bytes":PARENT_MEMORY,"candidate_controller_bytes":AUX_MEMORY,"candidate_guard_bytes":AUX_MEMORY,"candidate_DATA_bytes":CANDIDATE_DATA,"total_memory_bytes":total,"required_initial_free_bytes":required,"century_floor_bytes":century_floor,"protected_CPU_micros":cpu,"candidate_credit_bytes":0,"physical_credit_bytes":0}),
    )
}
fn validate_budget(b: &Budget, selected: Option<&witness::SelectedInputs>) -> Result<()> {
    let raw = read(&b.raw_admission)?;
    let old = read(&serde_json::from_value(
        raw["resource_accounting"]["observer"].clone(),
    )?)?;
    let o = read(&b.prelaunch.observer)?;
    let fleet = read(&b.prelaunch.fleet)?;
    let frame = read(&b.prelaunch.frame)?;
    read(&b.prelaunch.fleet_plan)?;
    validate_budget_values(
        b,
        &raw,
        &old,
        &o,
        &fleet,
        &frame,
        &read(&b.qualified_eligibility)?,
        &read(&b.century_inventory)?,
    )?;
    ensure!(
        frame["publication_authorized"] == false && frame["replay_launch_authorized"] == false,
        "199 resource Frame is not admission"
    );
    let mut affinity: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe {
            libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut affinity)
        } == 0,
        "199 actual CPU affinity unavailable"
    );
    let cpu = u64::try_from(unsafe { libc::CPU_COUNT(&affinity) })?
        .checked_mul(1_000_000)
        .context("199 actual CPU capacity overflow")?;
    ensure!(
        b.protected_cpu_micros <= cpu,
        "199 complete CPU promises do not fit actual affinity"
    );
    ensure!(
        fs::read_to_string("/proc/sys/vm/max_map_count")?
            .trim()
            .parse::<u64>()?
            >= 4_194_304,
        "199 actual VMA capability changed"
    );
    member_set(b, selected)?;
    controller_argv(b)?;
    Ok(())
}
fn command(v: &Value) -> Result<&str> {
    let s = v.as_str().context("199 native ExecStart")?;
    let (identity, _) = s
        .split_once(" ; start_time=")
        .context("199 native command framing")?;
    ensure!(
        identity.starts_with("{ path=")
            && identity.ends_with(" ; ignore_errors=no")
            && identity.matches(" ; argv[]=").count() == 1,
        "199 native command ambiguous"
    );
    Ok(identity)
}
fn expected_command(a: &[String]) -> Result<String> {
    ensure!(
        !a.is_empty()
            && a.iter()
                .all(|s| !s.is_empty() && !s.chars().any(char::is_whitespace)),
        "199 argv requires unambiguous tokens"
    );
    Ok(format!(
        "{{ path={} ; argv[]={} ; ignore_errors=no",
        a[0],
        a.join(" ")
    ))
}
fn native_owner(n: &Value, o: &Owner) -> Result<()> {
    ensure!(
        hex(&o.invocation_id, 32)
            && n["Id"] == o.unit
            && n["InvocationID"] == o.invocation_id
            && n["LoadState"] == "loaded"
            && n["NRestarts"] == "0"
            && n["Restart"] == "no"
            && n["ControlPID"] == "0"
            && n["Job"] == "",
        "199 native owner changed or queued"
    );
    Ok(())
}
fn running(n: &Value, o: &Owner, memory: u64, cpu: &str) -> Result<()> {
    native_owner(n, o)?;
    ensure!(
        n["ActiveState"] == "active"
            && n["SubState"] == "running"
            && n["MainPID"]
                .as_str()
                .and_then(|s| s.parse::<u64>().ok())
                .is_some_and(|p| p > 0)
            && n["MemoryAccounting"] == "yes"
            && native_memory_matches(&n["MemoryMax"], memory)
            && n["MemorySwapMax"] == "0"
            && n["CPUQuotaPerSecUSec"] == cpu
            && n["KillMode"] == "control-group"
            && n["NoNewPrivileges"] == "yes"
            && n["ProtectSystem"] == "strict"
            && n["ProtectHome"] == "read-only"
            && n["ControlGroup"] == format!("/system.slice/{}", o.unit),
        "199 native caps/sandbox/phase differ"
    );
    Ok(())
}
fn actual_image(native: &Value, expected: &Path) -> Result<()> {
    let pid = native["MainPID"]
        .as_str()
        .context("199 native PID string")?
        .parse::<u64>()?;
    ensure!(pid > 0, "199 actual executable has no PID");
    let path = PathBuf::from(format!("/proc/{pid}/exe"));
    ensure!(
        fs::read_link(&path)? == expected.canonicalize()?,
        "199 actual mapped executable differs"
    );
    let actual = File::open(path)?.metadata()?;
    let sealed = fs::metadata(expected)?;
    ensure!(
        actual.is_file()
            && actual.uid() == 0
            && actual.mode() & 0o022 == 0
            && actual.dev() == sealed.dev()
            && actual.ino() == sealed.ino(),
        "199 mapped executable inode or custody differs"
    );
    Ok(())
}
fn launch_clock(native: &Value, budget: &Budget) -> Result<()> {
    let text = native["ExecMainStartTimestamp"]
        .as_str()
        .context("199 actual native start timestamp")?;
    ensure!(
        text.ends_with(" UTC") && text.len() <= 64,
        "199 native launch timestamp zone/length"
    );
    let input = std::ffi::CString::new(text)?;
    let format = std::ffi::CString::new("%a %Y-%m-%d %H:%M:%S UTC")?;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    ensure!(
        !unsafe { libc::strptime(input.as_ptr(), format.as_ptr(), &mut tm) }.is_null(),
        "199 native launch clock parse"
    );
    let at = unsafe { libc::timegm(&mut tm) };
    ensure!(
        at >= 0
            && (at as u64) >= budget.recorded_unix_seconds
            && (at as u64) <= budget.launch_expires_unix_seconds,
        "199 actual launch occurred outside fresh budget window"
    );
    Ok(())
}
fn actual_worker(proof: &Proof, row: &Value) -> Result<()> {
    let before = &row["worker_before"];
    let after = &row["worker_after"];
    ensure!(
        before["pid"] == after["pid"] && before["executable"] == after["executable"],
        "199 worker changed inside sample"
    );
    for worker in [before, after] {
        ensure!(
            worker["matching_workers"] == 1
                && worker["executable_beneath_bound_scratch"] == true
                && n(worker, "vmas")? > 0
                && n(worker, "vmas")? <= 3_000_000,
            "199 worker identity/VMA bound unavailable"
        );
    }
    let pid = n(after, "pid")?;
    let expected = PathBuf::from(
        after["executable"]
            .as_str()
            .context("199 sampled worker executable")?,
    );
    ensure!(
        expected.starts_with(&proof.enrollment.scratch_path)
            && expected
                .file_name()
                .is_some_and(|s| s == proof.enrollment.worker_executable_basename.as_str()),
        "199 worker path is outside exact scratch"
    );
    let image = PathBuf::from(format!("/proc/{pid}/exe"));
    ensure!(
        fs::read_link(&image)? == expected,
        "199 actual worker image path differs"
    );
    let mut file = File::open(image)?;
    let meta = file.metadata()?;
    ensure!(
        meta.is_file() && meta.len() > 0 && meta.len() <= 128 << 20,
        "199 worker image size/type"
    );
    let mut raw = Vec::new();
    Read::by_ref(&mut file)
        .take((128 << 20) + 1)
        .read_to_end(&mut raw)?;
    ensure!(
        raw.len() as u64 == meta.len()
            && format!("{:x}", Sha256::digest(raw))
                == "9339aa0ee5c39e91ec446bfa561c0e81280a0ddc474a03cf5bb0ce07a3674893"
            && id(&meta) == id(&file.metadata()?),
        "199 actual worker image differs from immutable input"
    );
    let source = row["producer_after"]["rss"]["processes"]
        .as_array()
        .context("199 worker process RSS")?
        .iter()
        .filter(|p| p["pid"] == pid)
        .collect::<Vec<_>>();
    ensure!(
        source.len() == 1,
        "199 worker omitted or duplicated in producer RSS"
    );
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    ensure!(stat.len() <= 65536, "199 worker stat bound");
    let (_, tail) = stat.rsplit_once(") ").context("199 worker stat framing")?;
    let ticks = tail
        .split_whitespace()
        .nth(19)
        .context("199 worker start ticks")?
        .parse::<u64>()?;
    ensure!(
        source[0]["start_ticks"] == ticks,
        "199 worker PID was reused since observer"
    );
    Ok(())
}
fn validate_first_guard(
    e: &Enrollment,
    budget: &Budget,
    guard_argv: &[String],
    first: &Value,
) -> Result<()> {
    ensure!(
        first["schema"] == "horizon-epoch199-adaptive-first-sandboxed-guard-v1"
            && first["service"]["Id"] == GUARD
            && first["service"]["InvocationID"] == e.guard_first_owner.invocation_id
            && first["service"]["Result"] == "success"
            && first["service"]["ExecMainStatus"] == "0"
            && first["service"]["ExecMainCode"] == "1"
            && first["service"]["Type"] == "oneshot"
            && first["service"]["Restart"] == "no"
            && first["service"]["RemainAfterExit"] == "no"
            && first["service"]["ActiveState"] == "inactive"
            && first["service"]["SubState"] == "dead"
            && first["service"]["MainPID"] == "0"
            && first["service"]["ControlPID"] == "0"
            && first["service"]["NRestarts"] == "0"
            && first["sandboxed"] == true
            && first["capability_only"] == false
            && first["guard_program"] == json!(e.guard_program)
            && first["guard_argv"] == json!(e.guard_argv),
        "199 first guard not actual successful sandboxed invocation"
    );
    ensure!(
        first["service"]["User"] == "root"
            && first["service"]["ProtectSystem"] == "strict"
            && first["service"]["ProtectHome"] == "read-only"
            && first["service"]["PrivateNetwork"] == "yes"
            && first["service"]["NoNewPrivileges"] == "yes"
            && native_memory_matches(&first["service"]["MemoryMax"], AUX_MEMORY)
            && first["service"]["MemorySwapMax"] == "0"
            && first["service"]["CPUQuotaPerSecUSec"] == "1s"
            && command(&first["service"]["ExecStart"])? == expected_command(guard_argv)?,
        "199 first guard lacks actual installed sandbox/command/caps"
    );
    launch_clock(&first["service"], budget)?;
    ensure!(
        n(first, "recorded_unix_seconds")? >= budget.recorded_unix_seconds
            && n(first, "recorded_unix_seconds")? <= e.recorded_unix_seconds,
        "199 first guard chronology crossed"
    );
    let output = &first["output"];
    ensure!(
        output["armed"] == true
            && output["trip"] == false
            && output["minimum_free_bytes"] == RAW_DATA
            && output["maximum_worker_vmas"] == 3_000_000u64
            && n(output, "available_bytes")? >= RAW_DATA,
        "199 first guard not armed/no-trip"
    );
    for (role, owner) in [("controller", &e.controller), ("producer", &e.producer)] {
        ensure!(
            output[role]["unit"] == owner.unit
                && output[role]["invocation_id"] == owner.invocation_id
                && output[role]["restarts"] == 0
                && output[role]["active_state"] == "active"
                && output[role]["sub_state"] == "running",
            "199 first guard crossed actual owner"
        );
    }
    Ok(())
}
fn witness_bound(binding: &Bound) -> witness::Bound {
    witness::Bound {
        path: binding.path.clone(),
        sha256: binding.sha256.clone(),
    }
}
fn cache_key(binding: &Bound, selected: Option<&witness::Bound>) -> Result<String> {
    Ok(serde_json::to_string(&(binding, selected))?)
}
fn require_context_selection(
    binding: &Bound,
    selected: Option<&witness::Bound>,
    context: &super::terminal199_context::Retained,
) -> Result<()> {
    require_context_bindings(
        binding,
        selected,
        context.original_enrollment(),
        context
            .selected_inputs()
            .map(witness::SelectedInputs::selection),
    )
}
fn require_context_bindings(
    binding: &Bound,
    selected: Option<&witness::Bound>,
    context_enrollment: &super::terminal199_context::Bound,
    context_selection: Option<&witness::Bound>,
) -> Result<()> {
    ensure!(
        binding.path == context_enrollment.path && binding.sha256 == context_enrollment.sha256,
        "199 terminal context crosses enrollment"
    );
    ensure!(
        selected == context_selection,
        "199 proof and retained context cross explicit selection"
    );
    Ok(())
}
/// Legacy callers retain full original-input verification and never discover witnesses.
pub fn load(binding: &Value) -> Result<Option<Proof>> {
    load_inner(binding, None)
}
/// The current request supplies the retained context explicitly.
pub fn load_for_context(
    binding: &Value,
    context: &super::terminal199_context::Retained,
) -> Result<Option<Proof>> {
    context.revalidate_inputs()?;
    ensure!(
        !binding.is_null() || context.selected_inputs().is_none(),
        "selected witness context requires an explicit enrollment"
    );
    if !binding.is_null() {
        let bound: Bound = serde_json::from_value(binding.clone())?;
        require_context_selection(
            &bound,
            context
                .selected_inputs()
                .map(witness::SelectedInputs::selection),
            context,
        )?;
    }
    let proof = load_inner(binding, context.selected_inputs().cloned())?;
    if let Some(proof) = &proof {
        proof.context_enrollment(context)?;
    }
    Ok(proof)
}
/// Read the selection only from the supplied current plan.
pub fn load_for_plan(binding: &Value, plan: &Value) -> Result<Option<Proof>> {
    match terminal_context(plan)? {
        Some(context) => load_for_context(binding, &context),
        None => load(binding),
    }
}
fn load_inner(
    binding: &Value,
    selected_inputs: Option<witness::SelectedInputs>,
) -> Result<Option<Proof>> {
    if binding.is_null() {
        return Ok(None);
    }
    let binding: Bound = serde_json::from_value(binding.clone())?;
    // One finite invocation authenticates large immutable inputs once. Every
    // use still rechecks the exact immutable enrollment and budget bytes.
    static CACHE: std::sync::OnceLock<std::sync::Mutex<BTreeMap<String, Proof>>> =
        std::sync::OnceLock::new();
    let cache = CACHE.get_or_init(|| std::sync::Mutex::new(BTreeMap::new()));
    if let Some(selected) = &selected_inputs {
        selected.require_context(&witness_bound(&binding), selected.original_context())?;
        selected.revalidate()?;
    }
    let key = cache_key(
        &binding,
        selected_inputs
            .as_ref()
            .map(witness::SelectedInputs::selection),
    )?;
    let cached = cache
        .lock()
        .map_err(|_| anyhow::anyhow!("199 reader cache poisoned"))?
        .get(&key)
        .cloned();
    if let Some(p) = cached {
        p.revalidate_inputs()?;
        return Ok(Some(p));
    }
    let e: Enrollment = serde_json::from_value(read(&binding)?)?;
    let budget: Budget = serde_json::from_value(read(&e.budget)?)?;
    ensure!(
        e.schema == "horizon-epoch199-additive-owner-enrollment-v1"
            && e.controller.unit == CONTROLLER
            && e.producer.unit == PRODUCER
            && e.guard_first_owner.unit == GUARD
            && e.timer_owner.unit == TIMER,
        "199 enrollment family changed"
    );
    for o in [
        &e.controller,
        &e.producer,
        &e.guard_first_owner,
        &e.timer_owner,
    ] {
        ensure!(hex(&o.invocation_id, 32), "199 enrollment lacks real IID");
    }
    ensure!(
        e.producer_memory_bytes == PARENT_MEMORY
            && e.controller_memory_bytes == AUX_MEMORY
            && e.guard_memory_bytes == AUX_MEMORY
            && e.candidate_data_bytes == CANDIDATE_DATA
            && e.cpu_quota_micros == 8_000_000
            && e.candidate_credit_bytes == 0
            && e.recorded_unix_seconds >= budget.recorded_unix_seconds
            && e.recorded_unix_seconds <= budget.launch_expires_unix_seconds,
        "199 enrollment timing or promises changed"
    );
    validate_budget(&budget, selected_inputs.as_ref())?;
    ensure!(
        e.guard_program.sha256
            == "b62e58f5be764935a679408e1fcc446a9768170109a6639c87fd01571b9f2b62",
        "199 guard source is not the reviewed adaptive guard"
    );
    hash_member(&e.guard_program, 1 << 20)?;
    let guard_argv = argv(&e.guard_argv)?;
    ensure!(
        guard_argv.len() > 2
            && guard_argv[0] == "/usr/bin/python3"
            && guard_argv[1]
                == e.guard_program
                    .path
                    .to_str()
                    .context("199 guard path UTF8")?,
        "199 guard executable changed"
    );
    // Existing reviewed guard uses split option/value tokens. Require one exact
    // value for each actual native owner/floor; no invented memory-floor flag.
    for (key, want) in [
        ("--controller-unit", CONTROLLER),
        (
            "--expected-controller-invocation-id",
            &e.controller.invocation_id,
        ),
        ("--producer-unit", PRODUCER),
        (
            "--expected-producer-invocation-id",
            &e.producer.invocation_id,
        ),
        ("--filesystem", "/home/sol"),
        ("--minimum-free-bytes", "4202184371152"),
        ("--maximum-worker-vmas", "3000000"),
        ("--guard-timer", TIMER),
    ] {
        let positions = guard_argv
            .iter()
            .enumerate()
            .filter(|(_, s)| s.as_str() == key)
            .collect::<Vec<_>>();
        ensure!(
            positions.len() == 1
                && guard_argv
                    .get(positions[0].0 + 1)
                    .is_some_and(|s| s == want),
            "199 guard argument crossed: {key}"
        );
    }
    ensure!(
        !guard_argv
            .iter()
            .any(|s| s.contains("minimum-available-memory")),
        "199 invented available-memory floor"
    );
    let first = read(&e.first_guard_proof)?;
    validate_first_guard(&e, &budget, &guard_argv, &first)?;
    ensure!(
        e.scratch_path.is_absolute()
            && e.scratch_path.starts_with(
                "/home/sol/.jetstreamer-private/epoch199-private-tail-20261017-v1/lane-a/private"
            )
            && ["historical-worker", "jetstreamer-historical-worker-v1-6-15"]
                .contains(&e.worker_executable_basename.as_str()),
        "199 scratch/worker namespace crossed"
    );
    let p = Proof {
        binding,
        enrollment: e.clone(),
        budget,
        budget_binding: e.budget,
        selected_inputs,
    };
    p.revalidate_inputs()?;
    let mut c = cache
        .lock()
        .map_err(|_| anyhow::anyhow!("199 reader cache poisoned"))?;
    ensure!(c.len() < 4, "199 reader cache bound");
    c.insert(key, p.clone());
    Ok(Some(p))
}
impl Proof {
    pub fn revalidate_inputs(&self) -> Result<()> {
        if let Some(selected) = &self.selected_inputs {
            selected.require_context(&witness_bound(&self.binding), selected.original_context())?;
            selected.revalidate()?;
        }
        ensure!(
            serde_json::to_value(&self.enrollment)? == read(&self.binding)?
                && serde_json::to_value(&self.budget)? == read(&self.budget_binding)?,
            "199 enrollment/budget changed"
        );
        Ok(())
    }
    pub fn validate_native(&self, n: &Value) -> Result<()> {
        self.validate_native_inner(n, None)
    }
    pub fn validate_native_retained(
        &self,
        n: &Value,
        context: &super::terminal199_context::Retained,
    ) -> Result<()> {
        self.context_enrollment(context)?;
        if context.historical_native(n)? {
            return self.validate_native_inner(n, Some((context, true)));
        }
        context.validate_current_membership(n)?;
        running(
            &n[CONTROLLER],
            &self.enrollment.controller,
            AUX_MEMORY,
            "1s",
        )?;
        actual_image(&n[CONTROLLER], Path::new("/usr/bin/python3"))?;
        launch_clock(&n[CONTROLLER], &self.budget)?;
        ensure!(
            command(&n[CONTROLLER]["ExecStart"])?
                == expected_command(&controller_argv(&self.budget)?)?,
            "199 terminal controller command changed"
        );
        // The collected original has no live process or native cap fields.
        // Its immutable enrollment retains every original hard promise.
        ensure!(
            self.enrollment.producer_memory_bytes == PARENT_MEMORY
                && self.enrollment.controller_memory_bytes == AUX_MEMORY
                && self.enrollment.guard_memory_bytes == AUX_MEMORY
                && self.enrollment.candidate_data_bytes == CANDIDATE_DATA,
            "199 terminal original promises changed"
        );
        self.validate_guard_family(n)
    }
    fn context_enrollment(&self, context: &super::terminal199_context::Retained) -> Result<()> {
        context.revalidate_inputs()?;
        require_context_selection(
            &self.binding,
            self.selected_inputs
                .as_ref()
                .map(witness::SelectedInputs::selection),
            context,
        )?;
        if let Some(selected) = &self.selected_inputs {
            let original = context.original_context();
            selected.require_context(
                &witness_bound(&self.binding),
                &witness::Bound {
                    path: original.path.clone(),
                    sha256: original.sha256.clone(),
                },
            )?;
        }
        self.revalidate_inputs()
    }
    fn validate_native_inner(
        &self,
        n: &Value,
        historical: Option<(&super::terminal199_context::Retained, bool)>,
    ) -> Result<()> {
        let e = &self.enrollment;
        let objects = n.as_object().context("199 complete native census")?;
        ensure!(
            FAMILY.into_iter().all(|u| objects.contains_key(u)),
            "199 full census missing added role"
        );
        running(&objects[CONTROLLER], &e.controller, AUX_MEMORY, "1s")?;
        running(&objects[PRODUCER], &e.producer, PARENT_MEMORY, "8s")?;
        ensure!(
            native_memory_matches(&objects[PRODUCER]["MemoryHigh"], 128u64 << 30),
            "199 parent soft memory cap changed"
        );
        if let Some((context, require_complete_census)) = historical {
            self.context_enrollment(context)?;
            ensure!(
                (!require_complete_census || context.historical_native(n)?)
                    && context.historical_producer_image(&objects[PRODUCER])?,
                "199 historical native/image lacks exact captured acceptance"
            );
            // A recorded-producer guard comparison still proves the actual
            // unchanged controller image. Only the original vanished producer's
            // exact accepted role is read historically in this narrower route.
            if !require_complete_census {
                actual_image(&objects[CONTROLLER], Path::new("/usr/bin/python3"))?;
            }
        } else {
            actual_image(&objects[CONTROLLER], Path::new("/usr/bin/python3"))?;
            actual_image(&objects[PRODUCER], Path::new(NODE))?;
        }
        launch_clock(&objects[CONTROLLER], &self.budget)?;
        launch_clock(&objects[PRODUCER], &self.budget)?;
        ensure!(
            command(&objects[CONTROLLER]["ExecStart"])?
                == expected_command(&controller_argv(&self.budget)?)?,
            "199 controller argv changed"
        );
        let producer_argv = argv(&e.producer_argv)?;
        let expected=vec![NODE.to_owned(),"199-200".into(),"/home/sol/.jetstreamer-private/epoch199-private-tail-20261017-v1/lane-a/output".into(),"--verify".into(),"--root-checkpoint-cohort".into(),format!("--cohort-manifest={MANIFEST}"),"--cohort-manifest-fingerprint=sha256:581f9ef3a74fc80a8b6b2754a7f4def480c8092d20529f446784f0d73dae810b".into(),format!("--snapshot-archive={SNAPSHOT}")];
        ensure!(
            producer_argv == expected
                && command(&objects[PRODUCER]["ExecStart"])? == expected_command(&producer_argv)?,
            "199 producer command changed"
        );
        self.validate_guard_family(n)
    }
    fn validate_guard_family(&self, n: &Value) -> Result<()> {
        let e = &self.enrollment;
        let objects = n.as_object().context("199 guard complete native census")?;
        let g = &objects[GUARD];
        ensure!(
            g["Id"] == GUARD
                && g["LoadState"] == "loaded"
                && hex(g["InvocationID"].as_str().unwrap_or(""), 32)
                && g["MainPID"] == "0"
                && g["ControlPID"] == "0"
                && g["NRestarts"] == "0"
                && g["Result"] == "success"
                && g["ExecMainStatus"] == "0"
                && g["Restart"] == "no"
                && g["Job"] == ""
                && native_memory_matches(&g["MemoryMax"], AUX_MEMORY)
                && g["MemorySwapMax"] == "0"
                && g["CPUQuotaPerSecUSec"] == "1s"
                && matches!(
                    (g["ActiveState"].as_str(), g["SubState"].as_str()),
                    (Some("inactive"), Some("dead")) | (Some("active"), Some("exited"))
                )
                && command(&g["ExecStart"])? == expected_command(&argv(&e.guard_argv)?)?,
            "199 guard native/command/cap changed or not drained"
        );
        let t = &objects[TIMER];
        ensure!(
            g["Type"] == "oneshot"
                && g["RemainAfterExit"] == "no"
                && g["User"] == "root"
                && g["ProtectSystem"] == "strict"
                && g["ProtectHome"] == "read-only"
                && g["PrivateNetwork"] == "yes"
                && g["NoNewPrivileges"] == "yes"
                && g["ControlGroup"] == ""
                && g["Delegate"] == "no",
            "199 guard installed sandbox or one-shot lifecycle changed"
        );
        ensure!(
            t["Id"] == TIMER
                && t["InvocationID"] == e.timer_owner.invocation_id
                && t["LoadState"] == "loaded"
                && t["ActiveState"] == "active"
                && t["SubState"] == "waiting"
                && t["Unit"] == GUARD,
            "199 bound guard timer not armed"
        );
        Ok(())
    }
    pub fn validate_observer(&self, o: &Value) -> Result<()> {
        self.validate_observer_inner(o, None)
    }
    pub fn validate_observer_retained(
        &self,
        o: &Value,
        context: &super::terminal199_context::Retained,
    ) -> Result<()> {
        self.context_enrollment(context)?;
        let rows = o["replays"]
            .as_array()
            .context("199 retained ordinary rows")?;
        if !rows.iter().any(|r| r["range"] == "199-200") {
            return context.validate_current_observer(o);
        }
        self.validate_observer_inner(o, Some(context))
    }
    fn validate_observer_inner(
        &self,
        o: &Value,
        historical: Option<&super::terminal199_context::Retained>,
    ) -> Result<()> {
        let rows = o["replays"]
            .as_array()
            .context("199 genuine ordinary rows")?;
        ensure!(rows.len() == 1, "199 must be the only added ordinary row");
        let r = &rows[0];
        ensure!(
            r["range"] == "199-200"
                && r["invocation_binding_stable"] == true
                && r["scratch_path"] == json!(self.enrollment.scratch_path),
            "199 observer scope/scratch changed"
        );
        for end in ["before", "after"] {
            for (role, owner) in [
                ("controller", &self.enrollment.controller),
                ("producer", &self.enrollment.producer),
            ] {
                let p = &r[format!("{role}_{end}")];
                ensure!(
                    p["unit"] == owner.unit
                        && p["invocation_id"] == owner.invocation_id
                        && p["restarts"] == 0
                        && p["active_state"] == "active"
                        && p["sub_state"] == "running",
                    "199 observer owner changed"
                );
            }
        }
        if let Some(context) = historical {
            ensure!(
                context.historical_worker(r)?,
                "199 historical worker row lacks exact captured acceptance"
            );
        } else {
            actual_worker(self, r)?;
        }
        Ok(())
    }
    pub fn accounting(&self) -> Value {
        json!({"schema":"horizon-epoch199-independent-protected-promises-v1","enrollment":self.binding,"budget":self.budget_binding,"controller":self.enrollment.controller,"producer":self.enrollment.producer,"parent_memory_bytes":PARENT_MEMORY,"controller_memory_bytes":AUX_MEMORY,"guard_memory_bytes":AUX_MEMORY,"DATA_bytes":CANDIDATE_DATA,"CPU_micros":10_000_000,"native_pool_suballocation":false,"candidate_credit_bytes":0,"physical_credit_bytes":0,"publish_through_epoch":199,"private_tail_epochs":[200],"replay_launch_authorized":false,"publication_authorized":false})
    }
    /// Permit only a completed successful fire of this exact guard. Retain raw
    /// observations separately; no controller/producer field is normalized.
    pub fn normalize_guard_for_plan(
        &self,
        expected: &Value,
        actual: &Value,
        plan: &Value,
    ) -> Result<Value> {
        if let Some(context) = terminal_context(plan)? {
            self.normalize_guard_retained(expected, actual, &context)
        } else {
            self.normalize_guard(expected, actual)
        }
    }
    pub fn normalize_guard(&self, expected: &Value, actual: &Value) -> Result<Value> {
        self.validate_native(expected)?;
        self.validate_native(actual)?;
        for key in [
            "Id",
            "LoadState",
            "Type",
            "ActiveState",
            "SubState",
            "MainPID",
            "NRestarts",
            "Result",
            "ExecMainStatus",
            "ControlGroup",
            "ControlPID",
            "Job",
            "Restart",
            "MemoryAccounting",
            "MemoryMax",
            "MemoryHigh",
            "MemorySwapMax",
            "CPUQuotaPerSecUSec",
            "User",
            "Group",
            "ProtectSystem",
            "ProtectHome",
            "PrivateNetwork",
            "NoNewPrivileges",
            "ReadWritePaths",
            "CapabilityBoundingSet",
            "AmbientCapabilities",
            "KillMode",
            "Delegate",
        ] {
            ensure!(
                expected[GUARD][key].as_str().is_some()
                    && expected[GUARD][key] == actual[GUARD][key],
                "199 periodic guard changed another property: {key}"
            );
        }
        ensure!(
            command(&expected[GUARD]["ExecStart"])? == command(&actual[GUARD]["ExecStart"])?,
            "199 periodic guard command changed"
        );
        let mut view = actual.clone();
        view[GUARD] = expected[GUARD].clone();
        for key in [
            "Id",
            "LoadState",
            "InvocationID",
            "ActiveState",
            "SubState",
            "Unit",
        ] {
            ensure!(
                expected[TIMER][key].as_str().is_some()
                    && expected[TIMER][key] == actual[TIMER][key],
                "199 timer control changed: {key}"
            );
        }
        for value in [
            &expected[TIMER]["TimersMonotonic"],
            &actual[TIMER]["TimersMonotonic"],
        ] {
            let lines = value
                .as_str()
                .context("199 guard timer schedule")?
                .lines()
                .collect::<Vec<_>>();
            let mut bases = BTreeSet::new();
            for line in lines {
                let inner = line
                    .strip_prefix("{ ")
                    .and_then(|x| x.strip_suffix(" }"))
                    .context("199 timer vector framing")?;
                let (base, due) = inner
                    .split_once(" ; next_elapse=")
                    .context("199 timer deadline")?;
                ensure!(
                    ["OnActiveUSec=1s", "OnUnitActiveUSec=30s"].contains(&base)
                        && !due.is_empty()
                        && bases.insert(base),
                    "199 changed/duplicate timer base"
                );
            }
            ensure!(bases.len() == 2, "199 missing protective timer schedule");
        }
        view[TIMER]["TimersMonotonic"] = expected[TIMER]["TimersMonotonic"].clone();
        Ok(view)
    }
    pub fn normalize_guard_retained(
        &self,
        expected: &Value,
        actual: &Value,
        context: &super::terminal199_context::Retained,
    ) -> Result<Value> {
        self.validate_native_retained(expected, context)?;
        self.validate_native_retained(actual, context)?;
        for key in [
            "Id",
            "LoadState",
            "Type",
            "ActiveState",
            "SubState",
            "MainPID",
            "NRestarts",
            "Result",
            "ExecMainStatus",
            "ControlGroup",
            "ControlPID",
            "Job",
            "Restart",
            "MemoryAccounting",
            "MemoryMax",
            "MemoryHigh",
            "MemorySwapMax",
            "CPUQuotaPerSecUSec",
            "User",
            "Group",
            "ProtectSystem",
            "ProtectHome",
            "PrivateNetwork",
            "NoNewPrivileges",
            "ReadWritePaths",
            "CapabilityBoundingSet",
            "AmbientCapabilities",
            "KillMode",
            "Delegate",
        ] {
            ensure!(
                expected[GUARD][key].as_str().is_some()
                    && expected[GUARD][key] == actual[GUARD][key],
                "199 periodic guard changed another property: {key}"
            );
        }
        ensure!(
            command(&expected[GUARD]["ExecStart"])? == command(&actual[GUARD]["ExecStart"])?,
            "199 periodic guard command changed"
        );
        let mut view = actual.clone();
        view[GUARD] = expected[GUARD].clone();
        for key in [
            "Id",
            "LoadState",
            "InvocationID",
            "ActiveState",
            "SubState",
            "Unit",
        ] {
            ensure!(
                expected[TIMER][key].as_str().is_some()
                    && expected[TIMER][key] == actual[TIMER][key],
                "199 timer control changed: {key}"
            );
        }
        for value in [
            &expected[TIMER]["TimersMonotonic"],
            &actual[TIMER]["TimersMonotonic"],
        ] {
            let lines = value
                .as_str()
                .context("199 guard timer schedule")?
                .lines()
                .collect::<Vec<_>>();
            let mut bases = BTreeSet::new();
            for line in lines {
                let inner = line
                    .strip_prefix("{ ")
                    .and_then(|x| x.strip_suffix(" }"))
                    .context("199 timer vector framing")?;
                let (base, due) = inner
                    .split_once(" ; next_elapse=")
                    .context("199 timer deadline")?;
                ensure!(
                    ["OnActiveUSec=1s", "OnUnitActiveUSec=30s"].contains(&base)
                        && !due.is_empty()
                        && bases.insert(base),
                    "199 changed/duplicate timer base"
                );
            }
            ensure!(bases.len() == 2, "199 missing protective timer schedule");
        }
        view[TIMER]["TimersMonotonic"] = expected[TIMER]["TimersMonotonic"].clone();
        Ok(view)
    }
    /// Explicit historical guard comparison: retain every numeric, command,
    /// guard and timer check; authenticate the original producer role by the
    /// qualified terminal context rather than reopening its vanished PID.
    pub fn normalize_guard_recorded_producer(
        &self,
        expected: &Value,
        actual: &Value,
        context: &super::terminal199_context::Retained,
    ) -> Result<Value> {
        self.context_enrollment(context)?;
        self.validate_native_inner(expected, Some((context, false)))?;
        self.validate_native_inner(actual, Some((context, false)))?;
        for key in [
            "Id",
            "LoadState",
            "Type",
            "ActiveState",
            "SubState",
            "MainPID",
            "NRestarts",
            "Result",
            "ExecMainStatus",
            "ControlGroup",
            "ControlPID",
            "Job",
            "Restart",
            "MemoryAccounting",
            "MemoryMax",
            "MemoryHigh",
            "MemorySwapMax",
            "CPUQuotaPerSecUSec",
            "User",
            "Group",
            "ProtectSystem",
            "ProtectHome",
            "PrivateNetwork",
            "NoNewPrivileges",
            "ReadWritePaths",
            "CapabilityBoundingSet",
            "AmbientCapabilities",
            "KillMode",
            "Delegate",
        ] {
            ensure!(
                expected[GUARD][key].as_str().is_some()
                    && expected[GUARD][key] == actual[GUARD][key],
                "199 periodic guard changed another property: {key}"
            );
        }
        ensure!(
            command(&expected[GUARD]["ExecStart"])? == command(&actual[GUARD]["ExecStart"])?,
            "199 periodic guard command changed"
        );
        let mut view = actual.clone();
        view[GUARD] = expected[GUARD].clone();
        for key in [
            "Id",
            "LoadState",
            "InvocationID",
            "ActiveState",
            "SubState",
            "Unit",
        ] {
            ensure!(
                expected[TIMER][key].as_str().is_some()
                    && expected[TIMER][key] == actual[TIMER][key],
                "199 timer control changed: {key}"
            );
        }
        for value in [
            &expected[TIMER]["TimersMonotonic"],
            &actual[TIMER]["TimersMonotonic"],
        ] {
            let lines = value
                .as_str()
                .context("199 guard timer schedule")?
                .lines()
                .collect::<Vec<_>>();
            let mut bases = BTreeSet::new();
            for line in lines {
                let inner = line
                    .strip_prefix("{ ")
                    .and_then(|x| x.strip_suffix(" }"))
                    .context("199 timer vector framing")?;
                let (base, due) = inner
                    .split_once(" ; next_elapse=")
                    .context("199 timer deadline")?;
                ensure!(
                    ["OnActiveUSec=1s", "OnUnitActiveUSec=30s"].contains(&base)
                        && !due.is_empty()
                        && bases.insert(base),
                    "199 changed/duplicate timer base"
                );
            }
            ensure!(bases.len() == 2, "199 missing protective timer schedule");
        }
        view[TIMER]["TimersMonotonic"] = expected[TIMER]["TimersMonotonic"].clone();
        Ok(view)
    }
}
pub fn project_plan(v: &Value) -> Result<Value> {
    let mut p = v.clone();
    if let Some(selected) = p.get(TERMINAL_FIELD).filter(|v| !v.is_null()) {
        let context =
            super::terminal199_context::Retained::load(&serde_json::from_value(selected.clone())?)?;
        context.revalidate_inputs()?;
    }
    p.as_object_mut()
        .context("199 plan object")?
        .remove(TERMINAL_FIELD);
    let Some(binding) = p.get(FIELD) else {
        return Ok(p);
    };
    if binding.is_null() {
        p.as_object_mut().context("199 plan")?.remove(FIELD);
        return Ok(p);
    }
    load_for_plan(binding, v)?;
    p.as_object_mut().context("199 plan")?.remove(FIELD);
    if let Some(names) = p["tracked_units"].as_array_mut() {
        names.retain(|u| !FAMILY.iter().any(|name| u == name));
    }
    Ok(p)
}
pub fn project_census(v: &Value) -> Result<Value> {
    let mut p = v.as_object().context("199 full census projection")?.clone();
    for unit in FAMILY {
        ensure!(
            p.remove(unit).is_some(),
            "199 projection missing a real role"
        );
    }
    Ok(Value::Object(p))
}
pub fn project_observer(v: &Value) -> Result<Value> {
    let mut p = v.clone();
    let rows = p["replays"]
        .as_array_mut()
        .context("199 observer projection")?;
    ensure!(
        rows.len() == 1 && rows[0]["range"] == "199-200",
        "199 cannot project another ordinary owner"
    );
    rows.clear();
    Ok(p)
}
pub fn project_fleet(v: &Value) -> Result<Value> {
    if v.get(FIELD).is_none_or(Value::is_null) {
        return Ok(v.clone());
    }
    let mut p = v.clone();
    let proof = load(&v[FIELD])?.context("199 fleet proof")?;
    proof.validate_native(&v["unit_census"])?;
    ensure!(
        v["epoch199_promises"] == proof.accounting(),
        "199 final full promises missing/duplicated"
    );
    p["unit_census"] = project_census(&v["unit_census"])?;
    p.as_object_mut().context("199 fleet object")?.remove(FIELD);
    p.as_object_mut().unwrap().remove("epoch199_promises");
    p.as_object_mut()
        .unwrap()
        .remove("epoch199_guard_census_before");
    if let Some(active) = p["active"].as_array_mut() {
        active.retain(|r| r["producer"]["Id"] != PRODUCER);
    }
    // Restore only gate-derived planning rows for this exact added claim. Ready
    // pairs are never projected away; archive publication remains independent.
    let plan = read(&serde_json::from_value(
        json!({"path":v["plan"],"sha256":v["plan_sha256"]}),
    )?)?;
    if let Some(epochs) = p["epochs"].as_array_mut() {
        for row in epochs {
            if row["epoch"] == 199 || row["epoch"] == 200 {
                ensure!(
                    row["state"] != "remote-ready",
                    "199 active contract cannot hide completed publication"
                );
                let key = row["epoch"].as_u64().context("199 epoch row")?.to_string();
                row["state"] = plan["gates"][&key]["state"].clone();
                row["next_action"] = plan["gates"][&key]["next_action"].clone();
            }
        }
    }
    Ok(p)
}
pub fn project_frame(v: &Value) -> Result<Value> {
    if v.get(FIELD).is_none_or(Value::is_null) {
        return Ok(v.clone());
    }
    let proof = load(&v[FIELD])?.context("199 Frame proof")?;
    ensure!(
        v["epoch199_promises"] == proof.accounting(),
        "199 Frame omitted promises"
    );
    let mut p = v.clone();
    for key in ["native_census_before", "native_census_after"] {
        proof.validate_native(&v[key])?;
        p[key] = project_census(&v[key])?;
    }
    p.as_object_mut().context("199 Frame object")?.remove(FIELD);
    p.as_object_mut().unwrap().remove("epoch199_promises");
    Ok(p)
}

pub fn project_fleet_retained(
    v: &Value,
    context: &super::terminal199_context::Retained,
) -> Result<Value> {
    if v.get(FIELD).is_none_or(Value::is_null) {
        return Ok(v.clone());
    }
    let mut p = v.clone();
    let proof = load_for_context(&v[FIELD], context)?.context("199 fleet proof")?;
    if context.historical_value(v)? {
        ensure!(
            context.historical_native(&v["unit_census"])?,
            "registered historical fleet lacks its authenticated native census"
        );
    }
    proof.validate_native_retained(&v["unit_census"], context)?;
    ensure!(
        v["epoch199_promises"] == proof.accounting(),
        "199 final full promises missing/duplicated"
    );
    p["unit_census"] = project_census(&v["unit_census"])?;
    p.as_object_mut().context("199 fleet object")?.remove(FIELD);
    p.as_object_mut().unwrap().remove("epoch199_promises");
    p.as_object_mut()
        .unwrap()
        .remove("epoch199_guard_census_before");
    if let Some(active) = p["active"].as_array_mut() {
        active.retain(|r| r["producer"]["Id"] != PRODUCER);
    }
    // Restore only gate-derived planning rows for this exact added claim. Ready
    // pairs are never projected away; archive publication remains independent.
    let plan = read(&serde_json::from_value(
        json!({"path":v["plan"],"sha256":v["plan_sha256"]}),
    )?)?;
    if let Some(epochs) = p["epochs"].as_array_mut() {
        for row in epochs {
            if row["epoch"] == 199 || row["epoch"] == 200 {
                ensure!(
                    row["state"] != "remote-ready",
                    "199 active contract cannot hide completed publication"
                );
                let key = row["epoch"].as_u64().context("199 epoch row")?.to_string();
                row["state"] = plan["gates"][&key]["state"].clone();
                row["next_action"] = plan["gates"][&key]["next_action"].clone();
            }
        }
    }
    Ok(p)
}
pub fn project_frame_retained(
    v: &Value,
    context: &super::terminal199_context::Retained,
) -> Result<Value> {
    if v.get(FIELD).is_none_or(Value::is_null) {
        return Ok(v.clone());
    }
    let proof = load_for_context(&v[FIELD], context)?.context("199 Frame proof")?;
    ensure!(
        v["epoch199_promises"] == proof.accounting(),
        "199 Frame omitted promises"
    );
    let mut p = v.clone();
    for key in ["native_census_before", "native_census_after"] {
        proof.validate_native_retained(&v[key], context)?;
        p[key] = project_census(&v[key])?;
    }
    p.as_object_mut().context("199 Frame object")?.remove(FIELD);
    p.as_object_mut().unwrap().remove("epoch199_promises");
    Ok(p)
}

pub fn project_observer_retained(
    v: &Value,
    proof: &Proof,
    context: &super::terminal199_context::Retained,
) -> Result<Value> {
    proof.validate_observer_retained(v, context)?;
    if v["replays"]
        .as_array()
        .context("199 retained ordinary rows")?
        .iter()
        .any(|r| r["range"] == "199-200")
    {
        return project_observer(v);
    }
    let mut projected = v.clone();
    let rows = projected["diagnostic_replays"]
        .as_array_mut()
        .context("199 retained diagnostic rows")?;
    let at = rows
        .iter()
        .position(|r| r["range"] == "199-200")
        .context("199 retained diagnostic missing after validation")?;
    rows.remove(at);
    Ok(projected)
}

/// Caller supplies the explicit current plan; no ambient receipt discovery.
pub fn terminal_context(plan: &Value) -> Result<Option<super::terminal199_context::Retained>> {
    plan.get(TERMINAL_FIELD)
        .filter(|v| !v.is_null())
        .map(|v| super::terminal199_context::Retained::load(&serde_json::from_value(v.clone())?))
        .transpose()
}

#[cfg(test)]
#[path = "ordinary199_tests.rs"]
mod extended_tests;
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn immutable_scope_cannot_alias_or_escape() {
        for path in ["relative", "/tmp/../escape", "/tmp/link"] {
            let b = Bound {
                path: path.into(),
                sha256: "0".repeat(64),
            };
            assert!(bytes(&b, 16).is_err());
        }
    }
    #[test]
    fn command_metadata_is_ignored_but_real_argv_is_exact() {
        let a = vec!["/immutable/program".into(), "--value=1".into()];
        let raw = json!(
            "{ path=/immutable/program ; argv[]=/immutable/program --value=1 ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }"
        );
        assert_eq!(command(&raw).unwrap(), expected_command(&a).unwrap());
        assert_ne!(
            command(&raw).unwrap(),
            expected_command(&["/immutable/program".into(), "--value=2".into()]).unwrap()
        );
    }
    #[test]
    fn projection_cannot_silently_omit_a_family_or_other_replay() {
        assert!(project_census(&json!({})).is_err());
        assert!(project_observer(&json!({"replays":[{"range":"198-200"}]})).is_err());
        assert!(
            project_observer(&json!({"replays":[{"range":"199-200"},{"range":"145"}]})).is_err()
        );
    }
    #[test]
    fn census_projection_retains_all_unrelated_historical_rows() {
        let mut full = json!({"old.service":{"memory_max_bytes":68u64<<30,"DATA_bytes":72u64<<30,"cpu_micros":3_000_000}});
        for unit in FAMILY {
            full[unit] = json!({"actual":true});
        }
        let before = full.clone();
        let p = project_census(&full).unwrap();
        assert_eq!(p.as_object().unwrap().len(), 1);
        assert_eq!(p["old.service"], before["old.service"]);
        assert_eq!(full, before);
    }
}

#[cfg(test)]
mod explicit_witness_selection_tests {
    use super::*;

    fn enrollment() -> Bound {
        Bound {
            path: "/explicit/enrollment.json".into(),
            sha256: "a".repeat(64),
        }
    }
    fn retained_enrollment(binding: &Bound) -> super::super::terminal199_context::Bound {
        super::super::terminal199_context::Bound {
            path: binding.path.clone(),
            sha256: binding.sha256.clone(),
        }
    }
    fn selection() -> witness::Bound {
        witness::Bound {
            path: "/explicit/selection.json".into(),
            sha256: "b".repeat(64),
        }
    }
    #[test]
    fn legacy_cache_and_context_keep_selection_absent() {
        let enrollment = enrollment();
        require_context_bindings(&enrollment, None, &retained_enrollment(&enrollment), None)
            .unwrap();
        assert_ne!(
            cache_key(&enrollment, None).unwrap(),
            cache_key(&enrollment, Some(&selection())).unwrap()
        );
    }
    #[test]
    fn selected_context_rejects_missing_or_crossed_proof_selection() {
        let enrollment = enrollment();
        let context_enrollment = retained_enrollment(&enrollment);
        let selected = selection();
        assert!(
            require_context_bindings(&enrollment, None, &context_enrollment, Some(&selected))
                .is_err()
        );
        assert!(
            require_context_bindings(&enrollment, Some(&selected), &context_enrollment, None)
                .is_err()
        );
        let mut crossed = selected.clone();
        crossed.sha256 = "c".repeat(64);
        assert!(
            require_context_bindings(
                &enrollment,
                Some(&crossed),
                &context_enrollment,
                Some(&selected)
            )
            .is_err()
        );
        assert_ne!(
            cache_key(&enrollment, Some(&selected)).unwrap(),
            cache_key(&enrollment, Some(&crossed)).unwrap()
        );
    }
    #[test]
    fn retained_selection_remains_coupled_to_exact_enrollment() {
        let enrollment = enrollment();
        let context_enrollment = retained_enrollment(&enrollment);
        let selected = selection();
        require_context_bindings(
            &enrollment,
            Some(&selected),
            &context_enrollment,
            Some(&selected),
        )
        .unwrap();
        let mut crossed = enrollment.clone();
        crossed.path = "/another/enrollment.json".into();
        assert!(
            require_context_bindings(
                &crossed,
                Some(&selected),
                &context_enrollment,
                Some(&selected)
            )
            .is_err()
        );
        crossed = enrollment;
        crossed.sha256 = "d".repeat(64);
        assert!(
            require_context_bindings(
                &crossed,
                Some(&selected),
                &context_enrollment,
                Some(&selected)
            )
            .is_err()
        );
    }
}

/// Project a historical plan under the caller's explicit authenticated context.
/// An old registry name does not disable the current request's witness selection.
pub fn project_plan_for_context(v: &Value, context: &super::terminal199_context::Retained) -> Result<Value> {
    context.revalidate_inputs()?;
    if let Some(selector) = v.get(TERMINAL_FIELD).filter(|v| !v.is_null()) {
        let bound: super::terminal199_context::Bound = serde_json::from_value(selector.clone())?;
        let selected = context.selected_inputs();
        let exact_selected = selected.is_some_and(|_| witness::is_selected_context(&witness_bound(&Bound {
            path: bound.path.clone(), sha256: bound.sha256.clone(),
        })));
        ensure!(bound == *context.original_context() || exact_selected || context.historical_value(v)?,
            "historical plan crosses the explicit original context");
    }
    let mut projected = v.clone();
    let Some(binding) = v.get(FIELD).filter(|v| !v.is_null()) else {
        projected.as_object_mut().context("199 plan object")?.remove(TERMINAL_FIELD);
        projected.as_object_mut().unwrap().remove(FIELD);
        return Ok(projected);
    };
    load_for_context(binding, context)?;
    let object = projected.as_object_mut().context("199 plan object")?;
    object.remove(TERMINAL_FIELD);
    object.remove(FIELD);
    if let Some(names) = projected["tracked_units"].as_array_mut() {
        names.retain(|u| !FAMILY.iter().any(|name| u == name));
    }
    Ok(projected)
}
