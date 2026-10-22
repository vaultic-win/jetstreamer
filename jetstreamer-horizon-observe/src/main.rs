//! Read-only, invocation-bound resource samples for live Horizon replays.
//!
//! This tool deliberately does not signal, restart, or otherwise mutate a
//! producer. It observes each configured controller and producer before and
//! after two physical scratch scans, then publishes one no-clobber JSON
//! receipt only if every invocation remained stable and healthy.

use {
    anyhow::{Context, Result, anyhow, ensure},
    serde::{Deserialize, Serialize},
    serde_json::Value,
    sha2::{Digest as _, Sha256},
    std::{
        collections::BTreeMap,
        env,
        ffi::CString,
        fs::{self, File, OpenOptions},
        io::{Read, Write},
        os::unix::fs::{MetadataExt as _, OpenOptionsExt as _},
        path::{Path, PathBuf},
        process::Command,
        thread,
        time::{Duration, SystemTime, UNIX_EPOCH},
    },
};

const CONFIG_SCHEMA: &str = "jetstreamer-horizon-live-resource-sample-config-v2";
mod append_log;
mod host_pressure;
const OUTPUT_SCHEMA: &str = "jetstreamer-horizon-live-resource-sample-v2";
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
const MAX_PREVIOUS_SAMPLE_BYTES: u64 = 4 * 1024 * 1024;
const SYSTEMCTL_DISCOVERY_ATTEMPTS: usize = 11;
const SYSTEMCTL_DISCOVERY_RETRY_DELAY: Duration = Duration::from_millis(500);
const MONOTONIC_MEMORY_STAT_COUNTERS: &[&str] = &[
    "numa_pages_migrated",
    "numa_pte_updates",
    "numa_hint_faults",
    "pgactivate",
    "pgdeactivate",
    "pgdemote_direct",
    "pgdemote_khugepaged",
    "pgdemote_kswapd",
    "pgfault",
    "pglazyfree",
    "pglazyfreed",
    "pgmajfault",
    "pgpromote_success",
    "pgrefill",
    "pgscan_direct",
    "pgscan_khugepaged",
    "pgscan_kswapd",
    "pgsteal_direct",
    "pgsteal_khugepaged",
    "pgsteal_kswapd",
    "swpin_zero",
    "swpout_zero",
    "thp_collapse_alloc",
    "thp_fault_alloc",
    "thp_swpout",
    "thp_swpout_fallback",
    "workingset_activate_anon",
    "workingset_activate_file",
    "workingset_nodereclaim",
    "workingset_refault_anon",
    "workingset_refault_file",
    "workingset_restore_anon",
    "workingset_restore_file",
    "zswpin",
    "zswpout",
    "zswpwb",
];

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum ObservationReason {
    #[default]
    Routine,
    UserRequestedStatus,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    schema: String,
    previous_sample: PathBuf,
    minimum_interval_seconds: u64,
    not_before_utc: String,
    #[serde(default)]
    observation_reason: ObservationReason,
    filesystem_path: PathBuf,
    output: PathBuf,
    replays: Vec<ReplayConfig>,
    // Private bounded experiments are measured in this same control cycle,
    // never promoted to ordinary replay/status claims. Terminal diagnostics
    // must not suppress healthy ordinary observations.
    #[serde(default)]
    diagnostic_replays: Vec<ReplayConfig>,
    // A separate, tightly scoped private benchmark is not a publication claim.
    // Its predecessor namespace must not collide with the primary epoch203.
    #[serde(default)]
    epoch203_ram_auxiliary: Option<RamAuxiliaryConfig>,
    // Telemetry only, sampled inside this same cadence. Never changes admission.
    #[serde(default)]
    host_global_pressure: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RamAuxiliaryConfig {
    replay: ReplayConfig,
    supervisor_profile: String,
    worker_sha256: String,
    target_slot: u64,
    terminal_root_slot: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplayConfig {
    range: String,
    controller_unit: String,
    expected_controller_invocation_id: String,
    producer_unit: String,
    expected_producer_invocation_id: String,
    scratch_path: PathBuf,
    worker_executable_basename: String,
    #[serde(default)]
    append_log: Option<append_log::Config>,
}

#[derive(Clone, Debug, Serialize)]
struct UnitObservation {
    unit: String,
    invocation_id: String,
    load_state: String,
    active_state: String,
    sub_state: String,
    result: String,
    restarts: u64,
    main_pid: u64,
    memory_current_bytes: u64,
    memory_peak_bytes: u64,
    control_group: PathBuf,
    cgroup: CgroupObservation,
}

#[derive(Clone, Debug, Serialize)]
struct CgroupObservation {
    path: PathBuf,
    io_counters_available: bool,
    gauges: BTreeMap<String, Option<u64>>,
    counters: BTreeMap<String, u64>,
}

#[derive(Clone, Debug, Serialize)]
struct ProgressPoint {
    realtime_microseconds: u64,
    slot: u64,
    terminal_slot: u64,
    transactions: u64,
    account_updates: u64,
}

#[derive(Debug, Serialize)]
struct ProgressWindow {
    #[serde(skip_serializing_if = "Option::is_none")]
    append_log_evidence: Option<append_log::Evidence>,
    journal_invocation_id: String,
    since_unix_seconds: u64,
    until_unix_seconds: u64,
    matching_markers: usize,
    first: Option<ProgressPoint>,
    last: Option<ProgressPoint>,
    counter_resets: u64,
    elapsed_seconds: Option<f64>,
    slot_delta: Option<u64>,
    transaction_delta: Option<u64>,
    account_update_delta: Option<u64>,
    slots_per_second: Option<f64>,
    transactions_per_second: Option<f64>,
    account_updates_per_second: Option<f64>,
    sufficient_for_rates: bool,
}

#[derive(Debug, Serialize)]
struct CrossSampleObservation {
    previous_sample_schema: String,
    previous_completed_at_utc: String,
    elapsed_seconds: u64,
    producer_cgroup_counter_delta: BTreeMap<String, u64>,
    producer_io_counter_delta_available: bool,
    effective_cpu_cores: Option<f64>,
    physical_scratch_delta_bytes: i128,
    worker_vma_delta: i128,
    physical_scratch_bytes_per_million_transactions: Option<f64>,
    worker_vmas_per_million_transactions: Option<f64>,
}

#[derive(Debug)]
struct PreviousReplayObservation {
    schema: String,
    completed_at_utc: String,
    completed_unix: u64,
    producer_cgroup_counters: BTreeMap<String, u64>,
    producer_io_counters_available: bool,
    physical_scratch_bytes: u64,
    worker_vmas: u64,
}

#[derive(Clone, Debug, Serialize)]
struct ScratchScan {
    physical_bytes: u64,
    apparent_bytes: u64,
    entries: u64,
    regular_files: u64,
    directories: u64,
    symlinks: u64,
    vanished_entries: u64,
}

#[derive(Debug, Serialize)]
struct WorkerObservation {
    pid: u64,
    executable: PathBuf,
    executable_beneath_bound_scratch: bool,
    vmas: u64,
    matching_workers: usize,
}

#[derive(Debug, Serialize)]
struct ReplayObservation {
    range: String,
    controller_before: UnitObservation,
    producer_before: UnitObservation,
    worker_before: WorkerObservation,
    scratch_path: PathBuf,
    scratch_measurement_method: &'static str,
    scratch_pass_1: ScratchScan,
    scratch_pass_2: ScratchScan,
    conservative_observed_physical_bytes: u64,
    within_sample_physical_delta_bytes: i128,
    controller_after: UnitObservation,
    producer_after: UnitObservation,
    worker_after: WorkerObservation,
    producer_cgroup_counter_delta: BTreeMap<String, u64>,
    producer_io_counter_delta_available: bool,
    useful_work: ProgressWindow,
    cross_sample: Option<CrossSampleObservation>,
    invocation_binding_stable: bool,
}

fn usage() -> ! {
    eprintln!("usage: jetstreamer-horizon-observe CONFIG.json [--check-config]");
    std::process::exit(2);
}

fn read_bounded(path: &Path, maximum: u64, label: &str) -> Result<Vec<u8>> {
    ensure!(path.is_absolute(), "{label} path must be absolute");
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("failed to open {label} {}", path.display()))?;
    let before = file.metadata()?;
    ensure!(before.is_file(), "{label} is not a regular file");
    ensure!(before.nlink() == 1, "{label} has multiple hard links");
    ensure!(before.len() <= maximum, "{label} exceeds size bound");
    let mut bytes = Vec::with_capacity(before.len() as usize);
    (&mut file).take(maximum + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= maximum, "{label} exceeds size bound");
    let after = file.metadata()?;
    ensure!(
        before.dev() == after.dev() && before.ino() == after.ino() && before.len() == after.len(),
        "{label} changed while it was read"
    );
    let current = fs::symlink_metadata(path)
        .with_context(|| format!("failed to re-inspect {label} {}", path.display()))?;
    ensure!(
        after.dev() == current.dev() && after.ino() == current.ino(),
        "{label} namespace changed while it was read"
    );
    Ok(bytes)
}

fn parse_cli(mut args: impl Iterator<Item = std::ffi::OsString>) -> Result<(PathBuf, bool)> {
    let path = args
        .next()
        .map(PathBuf::from)
        .context("missing config path")?;
    let check_config = match args.next() {
        None => false,
        Some(flag) if flag == "--check-config" => true,
        Some(_) => anyhow::bail!("unexpected argument; only --check-config is supported"),
    };
    ensure!(args.next().is_none(), "unexpected extra argument");
    Ok((path, check_config))
}

fn load_config(path: &Path) -> Result<(Config, String)> {
    let bytes = read_bounded(path, MAX_CONFIG_BYTES, "config")?;
    let config: Config = serde_json::from_slice(&bytes).context("invalid config JSON")?;
    ensure!(config.schema == CONFIG_SCHEMA, "unsupported config schema");
    ensure!(
        config.minimum_interval_seconds >= 1800,
        "minimum interval must be at least 1800 seconds"
    );
    parse_utc(&config.not_before_utc).context("invalid configured not-before timestamp")?;
    ensure!(
        !config.replays.is_empty() || !config.diagnostic_replays.is_empty(),
        "at least one replay is required"
    );
    ensure!(config.output.is_absolute(), "output path must be absolute");
    ensure!(
        !config.output.exists(),
        "output already exists: {}",
        config.output.display()
    );
    let parent = config
        .output
        .parent()
        .ok_or_else(|| anyhow!("output has no parent"))?;
    ensure!(parent.is_dir(), "output parent is not a directory");
    ensure!(
        config.filesystem_path.is_absolute(),
        "filesystem path must be absolute"
    );
    validate_replay_configs(&config.replays, &config.diagnostic_replays)?;
    validate_ram_auxiliary(&config)?;
    Ok((config, sha256(&bytes)))
}

// This branch is deliberately outside run(): it must not look up units, read
// /proc/cgroups or the predecessor, scan scratch, consume cadence, or write a
// sample. Both modes still use exactly the same static config validation.
fn dispatch(path: &Path, check_config: bool) -> Result<Option<Value>> {
    let (config, digest) = load_config(path)?;
    if check_config {
        return Ok(Some(serde_json::json!({
            "schema": "jetstreamer-horizon-observer-config-preflight-v1",
            "config_path": path,
            "config_sha256": digest,
            "ordinary_replay_count": config.replays.len(),
            "diagnostic_replay_count": config.diagnostic_replays.len(),
            "configuration_validated": true,
            "resource_observation_performed": false,
            "live_invocations_verified": false,
            "cadence_predecessor_verified": false,
            "sample_written": false,
            "replay_launch_authorized": false,
            "publication_authorized": false,
            "remote_mutations": false,
            "r2_mutations": false
        })));
    }
    run(config)?;
    Ok(None)
}

fn validate_ram_auxiliary(config: &Config) -> Result<()> {
    let Some(auxiliary) = &config.epoch203_ram_auxiliary else {
        return Ok(());
    };
    let replay = &auxiliary.replay;
    // Preserve the ordinary/diagnostic validator unchanged. Only this explicit
    // role may share epoch203, never a controller, invocation or mutable tree.
    validate_replay_configs(&[], std::slice::from_ref(replay))?;
    ensure!(
        replay.range == "203-203"
            && auxiliary.supervisor_profile
                == "jetstreamer-private-epoch203-ram-bounded-runner-plan-v1"
            && auxiliary.target_slot == 87_720_000
            && auxiliary.terminal_root_slot == 88_127_580,
        "wrong private RAM auxiliary scope"
    );
    let family = match auxiliary.worker_sha256.as_str() {
        "3f5e8efec328b3e00dd9ce5ae396fc4067e6be6554e4da8831a13273186a748a" => "baseline",
        "4aeca56378a4bb2c55d0e590c1e334c4afa6a375a2c0d94894b412bea261f1cc" => "shrink",
        _ => anyhow::bail!("unbound RAM auxiliary worker"),
    };
    let root = replay
        .scratch_path
        .parent()
        .context("auxiliary scratch has no root")?;
    ensure!(
        replay.controller_unit == replay.producer_unit
            && replay.expected_controller_invocation_id == replay.expected_producer_invocation_id
            && replay
                .producer_unit
                .starts_with(&format!("horizon-203-ram-resource-{family}-"))
            && replay.worker_executable_basename == "historical-worker"
            && replay.append_log.is_none()
            && replay
                .scratch_path
                .file_name()
                .is_some_and(|name| name == "scratch")
            && root.parent() == Some(Path::new("/home/ubuntu/.jetstreamer-private"))
            && root
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| { s.starts_with(&format!("ram-resource-203-{family}-")) }),
        "RAM auxiliary owner or mutable namespace differs"
    );
    let owners = config.replays.iter().chain(&config.diagnostic_replays);
    let mut primary = 0;
    for owner in owners {
        ensure!(
            owner.controller_unit != replay.controller_unit
                && owner.producer_unit != replay.producer_unit
                && owner.expected_controller_invocation_id
                    != replay.expected_controller_invocation_id
                && owner.expected_producer_invocation_id != replay.expected_producer_invocation_id
                && !owner.scratch_path.starts_with(root)
                && !root.starts_with(&owner.scratch_path),
            "RAM auxiliary aliases a primary owner or scratch tree"
        );
        let (start, end) = owner
            .range
            .split_once('-')
            .unwrap_or((&owner.range, &owner.range));
        let (start, end) = (start.parse::<u64>()?, end.parse::<u64>()?);
        if start <= 203 && end >= 203 {
            ensure!(
                owner.range == "203-203"
                    && owner.producer_unit == "horizon-qualify-203-root-prefix-resource-v1.service"
                    && owner.controller_unit == owner.producer_unit
                    && owner.expected_controller_invocation_id
                        == owner.expected_producer_invocation_id
                    && config
                        .diagnostic_replays
                        .iter()
                        .any(|d| std::ptr::eq(d, owner)),
                "auxiliary overlaps an ordinary or unsupported primary claim"
            );
            primary += 1;
        }
    }
    ensure!(
        primary == 1,
        "RAM auxiliary requires its explicit primary diagnostic owner"
    );
    Ok(())
}

fn validate_replay_configs(
    replays: &[ReplayConfig],
    diagnostic_replays: &[ReplayConfig],
) -> Result<()> {
    let mut ranges = std::collections::BTreeSet::new();
    let mut intervals = Vec::new();
    for replay in replays.iter().chain(diagnostic_replays) {
        ensure!(!replay.range.is_empty(), "replay range is empty");
        ensure!(
            ranges.insert(&replay.range),
            "duplicate replay/diagnostic range"
        );
        let (first, last) = replay
            .range
            .split_once('-')
            .unwrap_or((&replay.range, &replay.range));
        let first: u64 = first.parse().context("invalid first epoch")?;
        let last: u64 = last.parse().context("invalid last epoch")?;
        ensure!(first <= last, "reversed replay/diagnostic range");
        ensure!(
            intervals
                .iter()
                .all(|&(start, end)| last < start || first > end),
            "overlapping replay/diagnostic ranges"
        );
        intervals.push((first, last));
        ensure!(
            replay.controller_unit.ends_with(".service"),
            "controller unit must end in .service"
        );
        ensure!(
            replay.producer_unit.ends_with(".service"),
            "producer unit must end in .service"
        );
        ensure!(
            is_invocation_id(&replay.expected_controller_invocation_id),
            "invalid expected controller invocation ID"
        );
        ensure!(
            is_invocation_id(&replay.expected_producer_invocation_id),
            "invalid expected producer invocation ID"
        );
        ensure!(
            replay.scratch_path.is_absolute(),
            "scratch path must be absolute"
        );
        ensure!(
            !replay.worker_executable_basename.is_empty()
                && !replay.worker_executable_basename.contains('/'),
            "invalid worker executable basename"
        );
    }
    Ok(())
}

fn is_invocation_id(value: &str) -> bool {
    value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn now_unix() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock predates Unix epoch")?
        .as_secs())
}

fn effective_not_before(
    cadence_not_before: u64,
    configured_not_before: u64,
    observation_reason: ObservationReason,
) -> u64 {
    match observation_reason {
        ObservationReason::Routine => cadence_not_before.max(configured_not_before),
        ObservationReason::UserRequestedStatus => configured_not_before,
    }
}

fn format_utc(unix: u64) -> Result<String> {
    let seconds: libc::time_t = unix
        .try_into()
        .map_err(|_| anyhow!("timestamp is outside time_t"))?;
    let mut broken_down = std::mem::MaybeUninit::<libc::tm>::uninit();
    let result = unsafe { libc::gmtime_r(&seconds, broken_down.as_mut_ptr()) };
    ensure!(!result.is_null(), "gmtime_r failed");
    let broken_down = unsafe { broken_down.assume_init() };
    Ok(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        broken_down.tm_year + 1900,
        broken_down.tm_mon + 1,
        broken_down.tm_mday,
        broken_down.tm_hour,
        broken_down.tm_min,
        broken_down.tm_sec
    ))
}

// Civil-date conversion adapted from Howard Hinnant's public-domain algorithm.
fn parse_utc(value: &str) -> Result<u64> {
    ensure!(value.len() == 20, "timestamp must use YYYY-MM-DDTHH:MM:SSZ");
    let bytes = value.as_bytes();
    ensure!(
        bytes[4] == b'-'
            && bytes[7] == b'-'
            && bytes[10] == b'T'
            && bytes[13] == b':'
            && bytes[16] == b':'
            && bytes[19] == b'Z',
        "timestamp must use YYYY-MM-DDTHH:MM:SSZ"
    );
    let number = |start: usize, end: usize| -> Result<i64> {
        value[start..end]
            .parse::<i64>()
            .context("timestamp contains a non-number")
    };
    let year = number(0, 4)?;
    let month = number(5, 7)?;
    let day = number(8, 10)?;
    let hour = number(11, 13)?;
    let minute = number(14, 16)?;
    let second = number(17, 19)?;
    ensure!((1..=12).contains(&month), "timestamp month is invalid");
    ensure!((1..=31).contains(&day), "timestamp day is invalid");
    ensure!(
        hour <= 23 && minute <= 59 && second <= 59,
        "timestamp time is invalid"
    );
    let adjusted_year = year - i64::from(month <= 2);
    let era = if adjusted_year >= 0 {
        adjusted_year
    } else {
        adjusted_year - 399
    } / 400;
    let year_of_era = adjusted_year - era * 400;
    let adjusted_month = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * adjusted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146097 + day_of_era - 719468;
    ensure!(days >= 0, "timestamp predates Unix epoch");
    let unix = days
        .checked_mul(86400)
        .and_then(|value| value.checked_add(hour * 3600 + minute * 60 + second))
        .ok_or_else(|| anyhow!("timestamp overflow"))?;
    let unix: u64 = unix
        .try_into()
        .map_err(|_| anyhow!("timestamp is negative"))?;
    ensure!(format_utc(unix)? == value, "timestamp date is invalid");
    Ok(unix)
}

fn parse_receipt_utc(value: &str) -> Result<u64> {
    if value.len() > 20 && value.as_bytes().get(19) == Some(&b'.') && value.ends_with('Z') {
        let fractional = &value[20..value.len() - 1];
        ensure!(
            !fractional.is_empty() && fractional.bytes().all(|byte| byte.is_ascii_digit()),
            "fractional timestamp is invalid"
        );
        return parse_utc(&format!("{}Z", &value[..19]));
    }
    parse_utc(value)
}

fn receipt_timestamp(value: &Value) -> Result<&str> {
    let recorded = value.get("recorded_at_utc").and_then(Value::as_str);
    let observed = value.get("observed_at_utc").and_then(Value::as_str);
    match (recorded, observed) {
        (Some(recorded), None) => Ok(recorded),
        (None, Some(observed)) => Ok(observed),
        (Some(recorded), Some(observed)) if recorded == observed => Ok(recorded),
        (Some(_), Some(_)) => Err(anyhow!("previous sample has conflicting timestamps")),
        (None, None) => Err(anyhow!(
            "previous sample lacks recorded_at_utc or observed_at_utc"
        )),
    }
}

fn previous_sample(path: &Path) -> Result<(Vec<u8>, Value, String, u64)> {
    let bytes = read_bounded(path, MAX_PREVIOUS_SAMPLE_BYTES, "previous sample")?;
    let value: Value = serde_json::from_slice(&bytes).context("invalid previous sample JSON")?;
    let timestamp = receipt_timestamp(&value)?;
    let unix = parse_receipt_utc(timestamp)?;
    let timestamp = timestamp.to_owned();
    Ok((bytes, value, timestamp, unix))
}

fn progress_window_start(previous: &Value, fallback_unix: u64) -> Result<u64> {
    if previous.get("schema").and_then(Value::as_str) != Some(OUTPUT_SCHEMA) {
        return Ok(fallback_unix);
    }
    let completed_at_utc = previous
        .get("completed_at_utc")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("previous v2 sample lacks completed_at_utc"))?;
    parse_receipt_utc(completed_at_utc)
        .context("previous v2 sample has invalid completion timestamp")
}

fn parse_systemctl_properties(stdout: &[u8], unit: &str) -> Result<BTreeMap<String, String>> {
    let stdout = std::str::from_utf8(stdout).context("systemctl output is not UTF-8")?;
    let mut properties = BTreeMap::new();
    for line in stdout.lines() {
        let (name, value) = line
            .split_once('=')
            .ok_or_else(|| anyhow!("malformed systemctl property for {unit}"))?;
        ensure!(
            properties
                .insert(name.to_owned(), value.to_owned())
                .is_none(),
            "duplicate systemctl property {name} for {unit}"
        );
    }
    Ok(properties)
}

fn should_retry_systemctl_discovery(properties: &BTreeMap<String, String>, attempt: usize) -> bool {
    properties.get("LoadState").map(String::as_str) == Some("not-found")
        && attempt + 1 < SYSTEMCTL_DISCOVERY_ATTEMPTS
}

fn cgroup_belongs_to_system_unit(cgroup: &[u8], unit: &str) -> Result<bool> {
    let cgroup = std::str::from_utf8(cgroup).context("process cgroup is not UTF-8")?;
    let expected = format!("/system.slice/{unit}");
    Ok(cgroup.lines().any(|line| {
        line.rsplit_once(':')
            .map(|(_, path)| path == expected)
            .unwrap_or(false)
    }))
}

fn systemctl_whoami_matches(stdout: &[u8], unit: &str) -> Result<bool> {
    let stdout = std::str::from_utf8(stdout).context("systemctl whoami output is not UTF-8")?;
    Ok(stdout.trim() == unit)
}

fn rediscover_systemctl_unit_via_cgroup(unit: &str) -> Result<bool> {
    for entry in fs::read_dir("/proc").context("failed to read /proc for systemd discovery")? {
        let entry = entry?;
        let Some(pid) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if !pid.bytes().all(|byte| byte.is_ascii_digit()) {
            continue;
        }
        let cgroup = match fs::read(entry.path().join("cgroup")) {
            Ok(cgroup) => cgroup,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to read cgroup for process {pid}"));
            }
        };
        if !cgroup_belongs_to_system_unit(&cgroup, unit)? {
            continue;
        }
        let output = Command::new("systemctl")
            .args(["whoami", &pid])
            .output()
            .with_context(|| format!("failed to rediscover {unit} through process {pid}"))?;
        if output.status.success() && systemctl_whoami_matches(&output.stdout, unit)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn systemctl_properties(unit: &str) -> Result<BTreeMap<String, String>> {
    for attempt in 0..SYSTEMCTL_DISCOVERY_ATTEMPTS {
        let output = Command::new("systemctl")
            .args([
                "show",
                unit,
                "--property=Id,LoadState,Type,ActiveState,SubState,Result,MainPID,InvocationID,NRestarts,MemoryCurrent,MemoryPeak,ControlGroup",
            ])
            .output()
            .with_context(|| format!("failed to run systemctl for {unit}"))?;
        ensure!(
            output.status.success(),
            "systemctl failed for {unit}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
        let properties = parse_systemctl_properties(&output.stdout, unit)?;
        if !should_retry_systemctl_discovery(&properties, attempt) {
            if properties.get("LoadState").map(String::as_str) != Some("not-found") {
                ensure!(
                    required_property(&properties, "Id", unit)? == unit,
                    "systemctl returned a different unit while observing {unit}"
                );
            }
            return Ok(properties);
        }
        // A transient service can remain alive in its exact cgroup while a
        // name-based systemd lookup briefly reports LoadState=not-found.
        // Querying the manager by a PID from that exact cgroup refreshes unit
        // discovery without signaling or otherwise changing the service.
        let _ = rediscover_systemctl_unit_via_cgroup(unit)?;
        thread::sleep(SYSTEMCTL_DISCOVERY_RETRY_DELAY);
    }
    unreachable!("systemctl discovery loop always returns")
}

fn required_property<'a>(
    properties: &'a BTreeMap<String, String>,
    name: &str,
    unit: &str,
) -> Result<&'a str> {
    properties
        .get(name)
        .map(String::as_str)
        .ok_or_else(|| anyhow!("systemctl omitted {name} for {unit}"))
}

fn numeric_property(properties: &BTreeMap<String, String>, name: &str, unit: &str) -> Result<u64> {
    let value = required_property(properties, name, unit)?;
    if value == "[not set]" {
        return Ok(0);
    }
    value
        .parse()
        .with_context(|| format!("invalid {name} for {unit}"))
}

fn resolve_cgroup(control_group: &str) -> Result<PathBuf> {
    let relative = Path::new(control_group)
        .strip_prefix("/")
        .context("systemd control group is not absolute")?;
    ensure!(
        relative
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_))),
        "systemd control group contains an unsafe component"
    );
    let root = fs::canonicalize("/sys/fs/cgroup").context("failed to resolve cgroup root")?;
    let resolved = fs::canonicalize(root.join(relative))
        .with_context(|| format!("failed to resolve control group {control_group}"))?;
    ensure!(
        resolved.starts_with(&root) && resolved != root,
        "systemd control group escaped the cgroup root"
    );
    Ok(resolved)
}

fn parse_integer_file(path: &Path) -> Result<Option<u64>> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read cgroup gauge {}", path.display()))?;
    let value = text.trim();
    if value == "max" {
        return Ok(None);
    }
    Ok(Some(value.parse().with_context(|| {
        format!("invalid cgroup gauge {}", path.display())
    })?))
}

fn parse_counter_file(path: &Path, prefix: &str) -> Result<BTreeMap<String, u64>> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read cgroup counters {}", path.display()))?;
    let mut counters = BTreeMap::new();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let name = fields
            .next()
            .ok_or_else(|| anyhow!("empty cgroup counter line in {}", path.display()))?;
        let value: u64 = fields
            .next()
            .ok_or_else(|| anyhow!("missing cgroup counter value in {}", path.display()))?
            .parse()
            .with_context(|| format!("invalid cgroup counter in {}", path.display()))?;
        ensure!(
            fields.next().is_none(),
            "extra cgroup counter fields in {}",
            path.display()
        );
        ensure!(
            counters.insert(format!("{prefix}.{name}"), value).is_none(),
            "duplicate cgroup counter {name} in {}",
            path.display()
        );
    }
    Ok(counters)
}

fn parse_pressure_file(path: &Path, prefix: &str) -> Result<BTreeMap<String, u64>> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read cgroup pressure {}", path.display()))?;
    let mut counters = BTreeMap::new();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let class = fields
            .next()
            .ok_or_else(|| anyhow!("empty cgroup pressure line in {}", path.display()))?;
        let mut total = None;
        for field in fields {
            if let Some(value) = field.strip_prefix("total=") {
                ensure!(
                    total.is_none(),
                    "duplicate pressure total in {}",
                    path.display()
                );
                total =
                    Some(value.parse().with_context(|| {
                        format!("invalid pressure total in {}", path.display())
                    })?);
            }
        }
        let total = total.ok_or_else(|| anyhow!("pressure total missing in {}", path.display()))?;
        ensure!(
            counters
                .insert(format!("{prefix}.{class}_total_usec"), total)
                .is_none(),
            "duplicate pressure class {class} in {}",
            path.display()
        );
    }
    Ok(counters)
}

fn parse_io_stat(path: &Path) -> Result<BTreeMap<String, u64>> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read cgroup I/O counters {}", path.display()))?;
    let mut counters = BTreeMap::new();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let _device = fields
            .next()
            .ok_or_else(|| anyhow!("empty cgroup I/O line in {}", path.display()))?;
        for field in fields {
            let (name, value) = field
                .split_once('=')
                .ok_or_else(|| anyhow!("invalid cgroup I/O field in {}", path.display()))?;
            let value: u64 = value
                .parse()
                .with_context(|| format!("invalid cgroup I/O value in {}", path.display()))?;
            let key = format!("io.{name}");
            let current = counters.entry(key).or_insert(0_u64);
            *current = current
                .checked_add(value)
                .ok_or_else(|| anyhow!("cgroup I/O counter overflow"))?;
        }
    }
    Ok(counters)
}

fn observe_io_counters(cgroup: &Path) -> Result<(bool, BTreeMap<String, u64>)> {
    let path = cgroup.join("io.stat");
    match fs::symlink_metadata(&path) {
        Ok(metadata) => {
            ensure!(
                metadata.is_file(),
                "cgroup I/O counters are not a regular file"
            );
            Ok((true, parse_io_stat(&path)?))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let parent = cgroup
                .parent()
                .ok_or_else(|| anyhow!("cgroup has no parent"))?;
            let subtree_control = fs::read_to_string(parent.join("cgroup.subtree_control"))
                .with_context(|| {
                    format!(
                        "failed to read parent cgroup controller delegation for {}",
                        cgroup.display()
                    )
                })?;
            ensure!(
                !subtree_control
                    .split_whitespace()
                    .any(|value| value == "io"),
                "cgroup I/O controller is delegated but io.stat is missing"
            );
            Ok((false, BTreeMap::new()))
        }
        Err(error) => Err(error)
            .with_context(|| format!("failed to inspect cgroup I/O counters {}", path.display())),
    }
}

fn split_memory_stat(
    values: BTreeMap<String, u64>,
) -> (BTreeMap<String, Option<u64>>, BTreeMap<String, u64>) {
    let mut gauges = BTreeMap::new();
    let mut counters = BTreeMap::new();
    for (name, value) in values {
        let field = name
            .strip_prefix("memory_stat.")
            .expect("memory.stat parser applies the prefix");
        gauges.insert(name.clone(), Some(value));
        if MONOTONIC_MEMORY_STAT_COUNTERS.contains(&field) {
            counters.insert(name, value);
        }
    }
    (gauges, counters)
}

fn observe_cgroup(control_group: &str) -> Result<CgroupObservation> {
    let path = resolve_cgroup(control_group)?;
    let mut gauges = BTreeMap::new();
    for name in ["memory.current", "memory.peak", "pids.current", "pids.peak"] {
        gauges.insert(name.to_owned(), parse_integer_file(&path.join(name))?);
    }
    let memory_stat = parse_counter_file(&path.join("memory.stat"), "memory_stat")?;
    let (memory_stat_gauges, memory_stat_counters) = split_memory_stat(memory_stat);
    gauges.extend(memory_stat_gauges);
    let mut counters = BTreeMap::new();
    for (filename, prefix) in [("cpu.stat", "cpu"), ("memory.events", "memory_events")] {
        counters.extend(parse_counter_file(&path.join(filename), prefix)?);
    }
    counters.extend(memory_stat_counters);
    for (filename, prefix) in [
        ("cpu.pressure", "cpu_pressure"),
        ("memory.pressure", "memory_pressure"),
        ("io.pressure", "io_pressure"),
    ] {
        counters.extend(parse_pressure_file(&path.join(filename), prefix)?);
    }
    let (io_counters_available, io_counters) = observe_io_counters(&path)?;
    counters.extend(io_counters);
    Ok(CgroupObservation {
        path,
        io_counters_available,
        gauges,
        counters,
    })
}

#[derive(Debug, Eq, PartialEq)]
struct CounterDeltas {
    counters: BTreeMap<String, u64>,
    io_counters_comparable: bool,
}

fn counter_deltas(
    before: &BTreeMap<String, u64>,
    after: &BTreeMap<String, u64>,
) -> Result<CounterDeltas> {
    // cgroup v2 can add an optional io.stat field when that operation is
    // first observed.  Identity and cgroup-path stability are checked
    // independently, so a newly materialized monotonic counter has a valid
    // zero baseline.  The kernel may also remove an io.stat device row after
    // its I/O completes, which makes the aggregate I/O fields disappear or
    // decrease even though the cgroup itself is stable.  In that case omit
    // only the incomparable I/O delta and retain every required counter gate.
    for (name, before_value) in before {
        if !name.starts_with("io.") {
            let after_value = after
                .get(name)
                .ok_or_else(|| anyhow!("cgroup counter {name} disappeared during observation"))?;
            ensure!(
                *after_value >= *before_value,
                "cgroup counter {name} decreased during observation"
            );
        }
    }
    let io_counters_comparable = before
        .iter()
        .filter(|(name, _)| name.starts_with("io."))
        .all(|(name, before_value)| {
            after
                .get(name)
                .is_some_and(|after_value| after_value >= before_value)
        });
    let counters = after
        .iter()
        .filter(|(name, _)| io_counters_comparable || !name.starts_with("io."))
        .map(|(name, after_value)| {
            let before_value = before.get(name).copied().unwrap_or(0);
            ensure!(
                *after_value >= before_value,
                "cgroup counter {name} decreased during observation"
            );
            Ok((name.clone(), *after_value - before_value))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    Ok(CounterDeltas {
        counters,
        io_counters_comparable,
    })
}

fn json_u64(value: &Value, field: &str) -> Result<u64> {
    value
        .as_u64()
        .ok_or_else(|| anyhow!("previous sample has invalid {field}"))
}

fn json_counter_map(value: &Value, field: &str) -> Result<BTreeMap<String, u64>> {
    let object = value
        .as_object()
        .ok_or_else(|| anyhow!("previous sample has invalid {field}"))?;
    object
        .iter()
        .map(|(name, value)| Ok((name.clone(), json_u64(value, field)?)))
        .collect()
}

fn previous_replay_observation(
    previous: &Value,
    range: &str,
    expected_producer_invocation_id: &str,
) -> Result<Option<PreviousReplayObservation>> {
    let Some(schema) = previous.get("schema").and_then(Value::as_str) else {
        return Ok(None);
    };
    if schema != OUTPUT_SCHEMA {
        return Ok(None);
    }
    let completed_at_utc = previous
        .get("completed_at_utc")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("previous v2 sample lacks completed_at_utc"))?;
    let completed_unix = parse_receipt_utc(completed_at_utc)
        .context("previous v2 sample has invalid completion timestamp")?;
    let replays = previous
        .get("replays")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("previous v2 sample lacks replay observations"))?;
    let mut matches = replays
        .iter()
        .filter(|replay| replay.get("range").and_then(Value::as_str) == Some(range));
    let Some(replay) = matches.next() else {
        return Ok(None);
    };
    ensure!(
        matches.next().is_none(),
        "previous v2 sample has duplicate observations for range {range}"
    );
    let producer_after = replay
        .get("producer_after")
        .ok_or_else(|| anyhow!("previous v2 sample lacks producer_after for {range}"))?;
    if producer_after.get("invocation_id").and_then(Value::as_str)
        != Some(expected_producer_invocation_id)
    {
        return Ok(None);
    }
    let counters = producer_after
        .pointer("/cgroup/counters")
        .ok_or_else(|| anyhow!("previous v2 sample lacks cgroup counters for {range}"))?;
    let io_counters_available = producer_after
        .pointer("/cgroup/io_counters_available")
        .and_then(Value::as_bool)
        .ok_or_else(|| anyhow!("previous v2 sample lacks I/O counter availability for {range}"))?;
    let physical_scratch_bytes = replay
        .get("conservative_observed_physical_bytes")
        .ok_or_else(|| anyhow!("previous v2 sample lacks scratch bytes for {range}"))?;
    let worker_vmas = replay
        .pointer("/worker_after/vmas")
        .ok_or_else(|| anyhow!("previous v2 sample lacks worker VMAs for {range}"))?;
    Ok(Some(PreviousReplayObservation {
        schema: schema.to_owned(),
        completed_at_utc: completed_at_utc.to_owned(),
        completed_unix,
        producer_cgroup_counters: json_counter_map(counters, "cgroup counters")?,
        producer_io_counters_available: io_counters_available,
        physical_scratch_bytes: json_u64(physical_scratch_bytes, "scratch bytes")?,
        worker_vmas: json_u64(worker_vmas, "worker VMAs")?,
    }))
}

fn cross_sample_observation(
    previous: &Value,
    replay: &ReplayConfig,
    started_unix: u64,
    producer_before: &UnitObservation,
    worker_before: &WorkerObservation,
    conservative_physical_scratch_bytes: u64,
    useful_work: &ProgressWindow,
) -> Result<Option<CrossSampleObservation>> {
    let Some(previous) = previous_replay_observation(
        previous,
        &replay.range,
        &replay.expected_producer_invocation_id,
    )?
    else {
        return Ok(None);
    };
    ensure!(
        started_unix > previous.completed_unix,
        "current sample does not follow previous completion for {}",
        replay.range
    );
    let elapsed_seconds = started_unix - previous.completed_unix;
    let producer_cgroup_counter_delta = counter_deltas(
        &previous.producer_cgroup_counters,
        &producer_before.cgroup.counters,
    )?;
    let producer_io_counter_delta_available = previous.producer_io_counters_available
        && producer_before.cgroup.io_counters_available
        && producer_cgroup_counter_delta.io_counters_comparable;
    let effective_cpu_cores = producer_cgroup_counter_delta
        .counters
        .get("cpu.usage_usec")
        .map(|usage| *usage as f64 / (elapsed_seconds as f64 * 1_000_000.0));
    let physical_scratch_delta_bytes = i128::from(conservative_physical_scratch_bytes)
        - i128::from(previous.physical_scratch_bytes);
    let worker_vma_delta = i128::from(worker_before.vmas) - i128::from(previous.worker_vmas);
    let transaction_delta = useful_work.transaction_delta.filter(|delta| *delta > 0);
    let per_million = |delta: i128| {
        transaction_delta.map(|transactions| delta as f64 * 1_000_000.0 / transactions as f64)
    };
    Ok(Some(CrossSampleObservation {
        previous_sample_schema: previous.schema,
        previous_completed_at_utc: previous.completed_at_utc,
        elapsed_seconds,
        producer_cgroup_counter_delta: producer_cgroup_counter_delta.counters,
        producer_io_counter_delta_available,
        effective_cpu_cores,
        physical_scratch_delta_bytes,
        worker_vma_delta,
        physical_scratch_bytes_per_million_transactions: per_million(physical_scratch_delta_bytes),
        worker_vmas_per_million_transactions: per_million(worker_vma_delta),
    }))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReplayRole {
    Primary,
    PrivateRamAuxiliary,
}

fn accepted_unit_phase(
    active: &str,
    sub: &str,
    service_type: &str,
    pid: u64,
    role: ReplayRole,
) -> bool {
    (role == ReplayRole::Primary || pid > 0)
        && ((active == "active" && sub == "running")
            || (role == ReplayRole::PrivateRamAuxiliary
                && service_type == "oneshot"
                && active == "activating"
                && sub == "start"))
}

fn observe_unit(unit: &str, expected_invocation: &str) -> Result<UnitObservation> {
    observe_unit_for_role(unit, expected_invocation, ReplayRole::Primary)
}

fn observe_unit_for_role(
    unit: &str,
    expected_invocation: &str,
    role: ReplayRole,
) -> Result<UnitObservation> {
    let properties = systemctl_properties(unit)?;
    let control_group = PathBuf::from(required_property(&properties, "ControlGroup", unit)?);
    let cgroup = observe_cgroup(
        control_group
            .to_str()
            .ok_or_else(|| anyhow!("non-UTF-8 control group for {unit}"))?,
    )?;
    let observation = UnitObservation {
        unit: unit.to_owned(),
        invocation_id: required_property(&properties, "InvocationID", unit)?.to_owned(),
        load_state: required_property(&properties, "LoadState", unit)?.to_owned(),
        active_state: required_property(&properties, "ActiveState", unit)?.to_owned(),
        sub_state: required_property(&properties, "SubState", unit)?.to_owned(),
        result: required_property(&properties, "Result", unit)?.to_owned(),
        restarts: numeric_property(&properties, "NRestarts", unit)?,
        main_pid: numeric_property(&properties, "MainPID", unit)?,
        memory_current_bytes: numeric_property(&properties, "MemoryCurrent", unit)?,
        memory_peak_bytes: numeric_property(&properties, "MemoryPeak", unit)?,
        control_group,
        cgroup,
    };
    ensure!(observation.load_state == "loaded", "{unit} is not loaded");
    ensure!(
        accepted_unit_phase(
            &observation.active_state,
            &observation.sub_state,
            required_property(&properties, "Type", unit)?,
            observation.main_pid,
            role,
        ),
        "{unit} is not in the permitted live phase"
    );
    ensure!(observation.restarts == 0, "{unit} has restarted");
    ensure!(
        observation.invocation_id == expected_invocation,
        "{unit} invocation changed"
    );
    Ok(observation)
}

fn path_is_beneath(path: &Path, root: &Path) -> bool {
    path == root || path.starts_with(root)
}

fn observe_worker(scratch: &Path, executable_basename: &str) -> Result<WorkerObservation> {
    let mut matches = Vec::new();
    for entry in fs::read_dir("/proc").context("failed to read /proc")? {
        let entry = entry?;
        let Some(pid_text) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Ok(pid) = pid_text.parse::<u64>() else {
            continue;
        };
        let executable = match fs::read_link(entry.path().join("exe")) {
            Ok(path) => path,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => continue,
            Err(error) => return Err(error).context("failed to inspect process executable"),
        };
        let basename_matches =
            executable.file_name().and_then(|name| name.to_str()) == Some(executable_basename);
        if basename_matches && path_is_beneath(&executable, scratch) {
            matches.push((pid, executable));
        }
    }
    ensure!(
        matches.len() == 1,
        "expected exactly one {executable_basename} beneath {}, found {}",
        scratch.display(),
        matches.len()
    );
    let (pid, executable) = matches.pop().expect("length checked");
    let maps = fs::read_to_string(format!("/proc/{pid}/maps"))
        .with_context(|| format!("failed to read maps for worker {pid}"))?;
    Ok(WorkerObservation {
        pid,
        executable_beneath_bound_scratch: path_is_beneath(&executable, scratch),
        executable,
        vmas: maps.lines().count() as u64,
        matching_workers: 1,
    })
}

fn add_checked(target: &mut u64, value: u64, label: &str) -> Result<()> {
    *target = target
        .checked_add(value)
        .ok_or_else(|| anyhow!("{label} overflow"))?;
    Ok(())
}

fn scan_scratch(root: &Path) -> Result<ScratchScan> {
    let root_metadata = fs::symlink_metadata(root)
        .with_context(|| format!("failed to inspect scratch {}", root.display()))?;
    ensure!(root_metadata.is_dir(), "scratch is not a directory");
    let root_device = root_metadata.dev();
    let mut scan = ScratchScan {
        physical_bytes: root_metadata
            .blocks()
            .checked_mul(512)
            .ok_or_else(|| anyhow!("root block count overflow"))?,
        apparent_bytes: root_metadata.len(),
        entries: 1,
        regular_files: 0,
        directories: 1,
        symlinks: 0,
        vanished_entries: 0,
    };
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                scan.vanished_entries += 1;
                continue;
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to read {}", directory.display()));
            }
        };
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    scan.vanished_entries += 1;
                    continue;
                }
                Err(error) => return Err(error).context("failed to read scratch entry"),
            };
            let metadata = match fs::symlink_metadata(entry.path()) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    scan.vanished_entries += 1;
                    continue;
                }
                Err(error) => return Err(error).context("failed to inspect scratch entry"),
            };
            ensure!(
                metadata.dev() == root_device,
                "scratch entry crosses a filesystem boundary: {}",
                entry.path().display()
            );
            add_checked(&mut scan.entries, 1, "entry count")?;
            add_checked(
                &mut scan.physical_bytes,
                metadata
                    .blocks()
                    .checked_mul(512)
                    .ok_or_else(|| anyhow!("block count overflow"))?,
                "physical byte count",
            )?;
            add_checked(
                &mut scan.apparent_bytes,
                metadata.len(),
                "apparent byte count",
            )?;
            if metadata.file_type().is_symlink() {
                add_checked(&mut scan.symlinks, 1, "symlink count")?;
            } else if metadata.is_dir() {
                add_checked(&mut scan.directories, 1, "directory count")?;
                pending.push(entry.path());
            } else if metadata.is_file() {
                add_checked(&mut scan.regular_files, 1, "regular-file count")?;
            }
        }
    }
    Ok(scan)
}

// statvfs field widths differ across Unix platforms.
#[allow(clippy::unnecessary_cast)]
fn filesystem_available_bytes(path: &Path) -> Result<u64> {
    let path = CString::new(path.as_os_str().as_encoded_bytes())
        .context("filesystem path contains NUL")?;
    let mut stats = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    let result = unsafe { libc::statvfs(path.as_ptr(), stats.as_mut_ptr()) };
    ensure!(
        result == 0,
        "statvfs failed: {}",
        std::io::Error::last_os_error()
    );
    let stats = unsafe { stats.assume_init() };
    (stats.f_bavail as u64)
        .checked_mul(stats.f_frsize as u64)
        .ok_or_else(|| anyhow!("available-byte count overflow"))
}

fn host_memory() -> Result<(u64, u64)> {
    let text = fs::read_to_string("/proc/meminfo").context("failed to read /proc/meminfo")?;
    let mut total = None;
    let mut available = None;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("MemTotal:") {
            total = Some(parse_meminfo_kib(value, "MemTotal")?);
        } else if let Some(value) = line.strip_prefix("MemAvailable:") {
            available = Some(parse_meminfo_kib(value, "MemAvailable")?);
        }
    }
    Ok((
        total.ok_or_else(|| anyhow!("MemTotal is missing"))?,
        available.ok_or_else(|| anyhow!("MemAvailable is missing"))?,
    ))
}

fn parse_meminfo_kib(value: &str, label: &str) -> Result<u64> {
    let mut fields = value.split_whitespace();
    let number: u64 = fields
        .next()
        .ok_or_else(|| anyhow!("{label} has no value"))?
        .parse()
        .with_context(|| format!("invalid {label}"))?;
    ensure!(fields.next() == Some("kB"), "{label} has unexpected unit");
    ensure!(fields.next().is_none(), "{label} has extra fields");
    Ok(number)
}

fn vm_max_map_count() -> Result<u64> {
    fs::read_to_string("/proc/sys/vm/max_map_count")?
        .trim()
        .parse()
        .context("invalid vm.max_map_count")
}

fn stable_unit(before: &UnitObservation, after: &UnitObservation) -> bool {
    stable_unit_for_role(before, after, ReplayRole::Primary)
}

fn stable_unit_for_role(
    before: &UnitObservation,
    after: &UnitObservation,
    role: ReplayRole,
) -> bool {
    before.invocation_id == after.invocation_id
        && before.control_group == after.control_group
        && before.cgroup.path == after.cgroup.path
        && before.cgroup.io_counters_available == after.cgroup.io_counters_available
        && before.restarts == 0
        && after.restarts == 0
        && after.load_state == "loaded"
        && (role == ReplayRole::Primary
            || before.main_pid > 0
                && before.main_pid == after.main_pid
                && before.active_state == after.active_state
                && before.sub_state == after.sub_state)
        // Both captures independently authenticate Type=oneshot before accepting
        // the private role's activating/start phase. No primary gate changes.
        && (after.active_state == "active" && after.sub_state == "running"
            || role == ReplayRole::PrivateRamAuxiliary
                && before.active_state == "activating"
                && after.active_state == "activating"
                && before.sub_state == "start"
                && after.sub_state == "start"
                && before.main_pid > 0
                && before.main_pid == after.main_pid)
}

fn stable_worker(before: &WorkerObservation, after: &WorkerObservation) -> bool {
    before.pid == after.pid
        && before.executable == after.executable
        && before.matching_workers == 1
        && after.matching_workers == 1
        && before.executable_beneath_bound_scratch
        && after.executable_beneath_bound_scratch
}

fn decimal_after(message: &str, prefix: &str) -> Option<u64> {
    let start = message.find(prefix)?.checked_add(prefix.len())?;
    let digits = message[start..]
        .bytes()
        .take_while(u8::is_ascii_digit)
        .count();
    if digits == 0 {
        return None;
    }
    message[start..start + digits].parse().ok()
}

fn parse_progress_point(message: &str, realtime_microseconds: u64) -> Option<ProgressPoint> {
    let marker = "progress slot ";
    let slot_start = message.find(marker)?.checked_add(marker.len())?;
    let remaining = &message[slot_start..];
    let slash = remaining.find('/')?;
    let slot = remaining[..slash].parse().ok()?;
    let terminal_digits = remaining[slash + 1..]
        .bytes()
        .take_while(u8::is_ascii_digit)
        .count();
    if terminal_digits == 0 {
        return None;
    }
    let terminal_slot = remaining[slash + 1..slash + 1 + terminal_digits]
        .parse()
        .ok()?;
    Some(ProgressPoint {
        realtime_microseconds,
        slot,
        terminal_slot,
        transactions: decimal_after(message, "txs=")?,
        account_updates: decimal_after(message, "accounts=")?,
    })
}

fn accumulate_counter(previous: u64, current: u64, total: &mut u64) -> Result<bool> {
    let (delta, reset) = if current >= previous {
        (current - previous, false)
    } else {
        (current, true)
    };
    *total = total
        .checked_add(delta)
        .ok_or_else(|| anyhow!("progress counter delta overflow"))?;
    Ok(reset)
}

fn progress_window_from_points(
    invocation_id: &str,
    since_unix_seconds: u64,
    until_unix_seconds: u64,
    mut points: Vec<ProgressPoint>,
) -> Result<ProgressWindow> {
    points.sort_by_key(|point| point.realtime_microseconds);
    let matching_markers = points.len();
    let first = points.first().cloned();
    let last = points.last().cloned();
    let mut counter_resets = 0_u64;
    let mut slot_delta = 0_u64;
    let mut transaction_delta = 0_u64;
    let mut account_update_delta = 0_u64;
    for pair in points.windows(2) {
        ensure!(
            pair[1].realtime_microseconds >= pair[0].realtime_microseconds,
            "journal progress timestamps moved backwards"
        );
        counter_resets += u64::from(accumulate_counter(
            pair[0].slot,
            pair[1].slot,
            &mut slot_delta,
        )?);
        counter_resets += u64::from(accumulate_counter(
            pair[0].transactions,
            pair[1].transactions,
            &mut transaction_delta,
        )?);
        counter_resets += u64::from(accumulate_counter(
            pair[0].account_updates,
            pair[1].account_updates,
            &mut account_update_delta,
        )?);
    }
    let elapsed_seconds = match (&first, &last) {
        (Some(first), Some(last)) if matching_markers >= 2 => {
            Some((last.realtime_microseconds - first.realtime_microseconds) as f64 / 1_000_000.0)
        }
        _ => None,
    };
    let sufficient_for_rates = elapsed_seconds.is_some_and(|elapsed| elapsed > 0.0);
    let rate = |delta: u64| {
        elapsed_seconds
            .filter(|elapsed| *elapsed > 0.0)
            .map(|elapsed| delta as f64 / elapsed)
    };
    Ok(ProgressWindow {
        append_log_evidence: None,
        journal_invocation_id: invocation_id.to_owned(),
        since_unix_seconds,
        until_unix_seconds,
        matching_markers,
        first,
        last,
        counter_resets,
        elapsed_seconds,
        slot_delta: sufficient_for_rates.then_some(slot_delta),
        transaction_delta: sufficient_for_rates.then_some(transaction_delta),
        account_update_delta: sufficient_for_rates.then_some(account_update_delta),
        slots_per_second: rate(slot_delta),
        transactions_per_second: rate(transaction_delta),
        account_updates_per_second: rate(account_update_delta),
        sufficient_for_rates,
    })
}

fn observe_progress(
    invocation_id: &str,
    since_unix_seconds: u64,
    until_unix_seconds: u64,
) -> Result<ProgressWindow> {
    let output = Command::new("journalctl")
        .args([
            "--no-pager",
            "--output=json",
            "--output-fields=MESSAGE,__REALTIME_TIMESTAMP",
            "--grep=progress slot ",
            &format!("--since=@{since_unix_seconds}"),
            &format!("--until=@{until_unix_seconds}"),
            &format!("_SYSTEMD_INVOCATION_ID={invocation_id}"),
        ])
        .output()
        .context("failed to query invocation-bound replay progress")?;
    let clean_no_match =
        output.status.code() == Some(1) && output.stdout.is_empty() && output.stderr.is_empty();
    ensure!(
        output.status.success() || clean_no_match,
        "journalctl progress query failed with status {:?}: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr).trim()
    );
    ensure!(
        output.stdout.len() <= 16 * 1024 * 1024,
        "journalctl progress output exceeds size bound"
    );
    let text = std::str::from_utf8(&output.stdout).context("journal output is not UTF-8")?;
    let mut points = Vec::new();
    for line in text.lines() {
        let value: Value = serde_json::from_str(line).context("invalid journal JSON")?;
        let Some(message) = value.get("MESSAGE").and_then(Value::as_str) else {
            continue;
        };
        let Some(timestamp) = value
            .get("__REALTIME_TIMESTAMP")
            .and_then(Value::as_str)
            .and_then(|timestamp| timestamp.parse::<u64>().ok())
        else {
            continue;
        };
        if let Some(point) = parse_progress_point(message, timestamp) {
            points.push(point);
        }
    }
    progress_window_from_points(
        invocation_id,
        since_unix_seconds,
        until_unix_seconds,
        points,
    )
}

fn write_no_clobber(path: &Path, value: &Value) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(path)
        .with_context(|| format!("failed to create output {}", path.display()))?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    drop(file);
    File::open(path.parent().expect("validated output parent"))?.sync_all()?;
    Ok(())
}

fn observe_replay(
    replay: &ReplayConfig,
    previous_value: &Value,
    started_unix: u64,
    progress_since_unix: u64,
) -> Result<ReplayObservation> {
    observe_replay_for_role(
        replay,
        previous_value,
        started_unix,
        progress_since_unix,
        ReplayRole::Primary,
    )
}

fn observe_replay_for_role(
    replay: &ReplayConfig,
    previous_value: &Value,
    started_unix: u64,
    progress_since_unix: u64,
    role: ReplayRole,
) -> Result<ReplayObservation> {
    let controller_before = observe_unit_for_role(
        &replay.controller_unit,
        &replay.expected_controller_invocation_id,
        role,
    )?;
    let producer_before = observe_unit_for_role(
        &replay.producer_unit,
        &replay.expected_producer_invocation_id,
        role,
    )?;
    let worker_before = observe_worker(&replay.scratch_path, &replay.worker_executable_basename)?;
    let scratch_pass_1 = scan_scratch(&replay.scratch_path)?;
    let scratch_pass_2 = scan_scratch(&replay.scratch_path)?;
    let controller_after = observe_unit_for_role(
        &replay.controller_unit,
        &replay.expected_controller_invocation_id,
        role,
    )?;
    let producer_after = observe_unit_for_role(
        &replay.producer_unit,
        &replay.expected_producer_invocation_id,
        role,
    )?;
    let worker_after = observe_worker(&replay.scratch_path, &replay.worker_executable_basename)?;
    let producer_cgroup_counter_delta = counter_deltas(
        &producer_before.cgroup.counters,
        &producer_after.cgroup.counters,
    )?;
    let producer_io_counter_delta_available = producer_before.cgroup.io_counters_available
        && producer_after.cgroup.io_counters_available
        && producer_cgroup_counter_delta.io_counters_comparable;
    let useful_work = if let Some(log) = &replay.append_log {
        append_log::observe(log, &producer_before, progress_since_unix, started_unix)?
    } else {
        observe_progress(
            &replay.expected_producer_invocation_id,
            progress_since_unix,
            started_unix,
        )?
    };
    let conservative_observed_physical_bytes = scratch_pass_1
        .physical_bytes
        .max(scratch_pass_2.physical_bytes);
    let cross_sample = cross_sample_observation(
        previous_value,
        replay,
        started_unix,
        &producer_before,
        &worker_before,
        conservative_observed_physical_bytes,
        &useful_work,
    )?;
    let invocation_binding_stable =
        stable_unit_for_role(&controller_before, &controller_after, role)
            && stable_unit_for_role(&producer_before, &producer_after, role)
            && stable_worker(&worker_before, &worker_after);
    ensure!(
        invocation_binding_stable,
        "{} invocation or worker changed during observation",
        replay.range
    );
    let within_sample_physical_delta_bytes =
        i128::from(scratch_pass_2.physical_bytes) - i128::from(scratch_pass_1.physical_bytes);
    Ok(ReplayObservation {
        range: replay.range.clone(),
        controller_before,
        producer_before,
        worker_before,
        scratch_path: replay.scratch_path.clone(),
        scratch_measurement_method: "two race-tolerant non-symlink-following physical-block scans",
        scratch_pass_1,
        scratch_pass_2,
        conservative_observed_physical_bytes,
        within_sample_physical_delta_bytes,
        controller_after,
        producer_after,
        worker_after,
        producer_cgroup_counter_delta: producer_cgroup_counter_delta.counters,
        producer_io_counter_delta_available,
        useful_work,
        cross_sample,
        invocation_binding_stable,
    })
}

fn private_predecessor(previous: &Value, role: &str) -> Value {
    let observations: Vec<Value> = previous
        .get(role)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|entry| entry["status"] == "observed")
        .filter_map(|entry| entry.get("observation").cloned())
        .collect();
    serde_json::json!({
        "schema": previous["schema"],
        "completed_at_utc": previous["completed_at_utc"],
        "replays": observations
    })
}

fn observe_diagnostics(
    replays: &[ReplayConfig],
    previous: &Value,
    sample: impl FnMut(&ReplayConfig, &Value) -> Result<Value>,
) -> Vec<Value> {
    observe_private(replays, previous, "diagnostic_replays", sample)
}

fn observe_private(
    replays: &[ReplayConfig],
    previous: &Value,
    role: &str,
    mut sample: impl FnMut(&ReplayConfig, &Value) -> Result<Value>,
) -> Vec<Value> {
    let predecessor = private_predecessor(previous, role);
    replays
        .iter()
        .map(|replay| {
            let result = sample(replay, &predecessor);
            let (status, observation, error) = match result {
                Ok(value) => ("observed", Some(value), None),
                Err(error) => ("unavailable", None, Some(format!("{error:#}"))),
            };
            serde_json::json!({
                "range": replay.range,
                "producer_unit": replay.producer_unit,
                "expected_producer_invocation_id": replay.expected_producer_invocation_id,
                "scratch_path": replay.scratch_path,
                "status": status,
                "observation": observation,
                "error": error,
                "ordinary_replay_claim": false,
                "current_sidecar_eta_valid": false,
                "replay_launch_authorized": false,
                "publication_authorized": false,
                "r2_mutations": false
            })
        })
        .collect()
}

fn run(config: Config) -> Result<()> {
    validate_replay_configs(&config.replays, &config.diagnostic_replays)?;
    validate_ram_auxiliary(&config)?;
    let (previous_bytes, previous_value, previous_timestamp, previous_unix) =
        previous_sample(&config.previous_sample)?;
    let started_unix = now_unix()?;
    ensure!(
        started_unix >= previous_unix,
        "current clock predates previous sample"
    );
    let interval = started_unix - previous_unix;
    let cadence_not_before = previous_unix
        .checked_add(config.minimum_interval_seconds)
        .ok_or_else(|| anyhow!("cadence timestamp overflow"))?;
    let configured_not_before = parse_utc(&config.not_before_utc)?;
    let effective_not_before = effective_not_before(
        cadence_not_before,
        configured_not_before,
        config.observation_reason,
    );
    ensure!(
        started_unix >= effective_not_before,
        "observation attempted before {}; previous successful sample interval is {interval} seconds",
        format_utc(effective_not_before)?
    );

    let available_before = filesystem_available_bytes(&config.filesystem_path)?;
    let (memory_total_kib, memory_available_before_kib) = host_memory()?;
    let host_pressure_before = config
        .host_global_pressure
        .then(|| host_pressure::capture(Path::new("/proc")));
    let progress_since_unix = progress_window_start(&previous_value, previous_unix)?;
    ensure!(
        started_unix >= progress_since_unix,
        "current clock predates previous sample completion"
    );
    let mut observations = Vec::with_capacity(config.replays.len());
    for replay in &config.replays {
        observations.push(observe_replay(
            replay,
            &previous_value,
            started_unix,
            progress_since_unix,
        )?);
    }
    let diagnostic_observations = observe_diagnostics(
        &config.diagnostic_replays,
        &previous_value,
        |replay, previous| {
            serde_json::to_value(observe_replay(
                replay,
                previous,
                started_unix,
                progress_since_unix,
            )?)
            .map_err(Into::into)
        },
    );
    let auxiliary_observations = if let Some(auxiliary) = &config.epoch203_ram_auxiliary {
        let mut rows = observe_private(
            std::slice::from_ref(&auxiliary.replay),
            &previous_value,
            "epoch203_ram_auxiliary",
            |replay, previous| {
                let observation = observe_replay_for_role(
                    replay,
                    previous,
                    started_unix,
                    progress_since_unix,
                    ReplayRole::PrivateRamAuxiliary,
                )?;
                for worker in [&observation.worker_before, &observation.worker_after] {
                    let bytes =
                        read_bounded(&worker.executable, 256 << 20, "RAM auxiliary worker")?;
                    ensure!(
                        sha256(&bytes) == auxiliary.worker_sha256,
                        "RAM auxiliary worker digest differs"
                    );
                }
                serde_json::to_value(observation).map_err(Into::into)
            },
        );
        for row in &mut rows {
            row["role"] = serde_json::json!("epoch203-private-ram-comparison");
            row["supervisor_profile"] = serde_json::json!(auxiliary.supervisor_profile);
            row["worker_sha256"] = serde_json::json!(auxiliary.worker_sha256);
            row["target_slot"] = serde_json::json!(auxiliary.target_slot);
            row["terminal_root_slot"] = serde_json::json!(auxiliary.terminal_root_slot);
        }
        rows
    } else {
        Vec::new()
    };
    // This is only the successfully observed subset, not admission or a full
    // service census: unavailable diagnostics remain explicitly unresolved.
    let observed_entries = observations.len()
        + diagnostic_observations
            .iter()
            .filter(|r| r["status"] == "observed")
            .count()
        + auxiliary_observations
            .iter()
            .filter(|r| r["status"] == "observed")
            .count();
    if config.epoch203_ram_auxiliary.is_some() {
        ensure!(
            observed_entries <= 4,
            "more than four entry replays observed"
        );
    }
    let available_after = filesystem_available_bytes(&config.filesystem_path)?;
    let (_, memory_available_after_kib) = host_memory()?;
    let host_pressure = host_pressure_before.map(|before| {
        host_pressure::report(
            before,
            host_pressure::capture(Path::new("/proc")),
            &previous_value["host_global_pressure"]["after"],
        )
    });
    let completed_unix = now_unix()?;
    let next_observation = started_unix
        .checked_add(config.minimum_interval_seconds)
        .ok_or_else(|| anyhow!("next-observation timestamp overflow"))?;
    let value = serde_json::json!({
        "schema": OUTPUT_SCHEMA,
        "recorded_at_utc": format_utc(started_unix)?,
        "completed_at_utc": format_utc(completed_unix)?,
        "cadence": {
            "observation_reason": config.observation_reason,
            "routine_minimum_interval_enforced": config.observation_reason == ObservationReason::Routine,
            "previous_sample": config.previous_sample,
            "previous_sample_recorded_at_utc": previous_timestamp,
            "previous_sample_sha256": sha256(&previous_bytes),
            "minimum_interval_seconds": config.minimum_interval_seconds,
            "observed_interval_seconds": interval,
            "configured_not_before_utc": config.not_before_utc,
            "effective_not_before_utc": format_utc(effective_not_before)?,
            "next_routine_observation_not_before_utc": format_utc(next_observation)?,
        },
        "filesystem": {
            "path": config.filesystem_path,
            "available_bytes_before": available_before,
            "available_bytes_after": available_after,
            "conservative_available_bytes": available_before.min(available_after),
        },
        "host_memory": {
            "total_kib": memory_total_kib,
            "available_kib_before": memory_available_before_kib,
            "available_kib_after": memory_available_after_kib,
            "conservative_available_kib": memory_available_before_kib.min(memory_available_after_kib),
        },
        "host_global_pressure": host_pressure,
        "vm_max_map_count": vm_max_map_count()?,
        "replays": observations,
        "diagnostic_replays": diagnostic_observations,
        "epoch203_ram_auxiliary": auxiliary_observations,
        "auxiliary_policy": {
            "configured": config.epoch203_ram_auxiliary.is_some(),
            "observed_entry_replays": observed_entries,
            "maximum_entry_replays": 4,
            "maximum_auxiliary_diagnostics": 1,
            "complete_live_census_verified": false,
            "fresh_admission_passed": false,
            "ordinary_replay_authorized": false,
            "publication_authorized": false,
            "r2_mutations": false
        },
        "mutation": {
            "producer_or_controller_signals_sent": false,
            "service_state_changed": false,
            "remote_mutations": false,
            "r2_mutations": false,
        }
    });
    write_no_clobber(&config.output, &value)
}

fn main() -> Result<()> {
    let mut args = env::args_os().skip(1).peekable();
    if args.peek().is_none() {
        usage();
    }
    let (path, check_config) = parse_cli(args)?;
    if let Some(result) = dispatch(&path, check_config)? {
        println!("{}", serde_json::to_string(&result)?);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn preflight_fixture(root: &Path) -> Value {
        serde_json::json!({
            "schema": CONFIG_SCHEMA,
            "previous_sample": root.join("absent-predecessor.json"),
            "minimum_interval_seconds": 1800,
            "not_before_utc": "2099-01-01T00:00:00Z",
            "filesystem_path": root.join("absent-filesystem"),
            "output": root.join("sample.json"),
            "replays": [{
                "range":"220-223", "controller_unit":"absent-controller.service",
                "producer_unit":"absent-producer.service",
                "expected_controller_invocation_id":"a".repeat(32),
                "expected_producer_invocation_id":"b".repeat(32),
                "scratch_path":root.join("absent-scratch"),
                "worker_executable_basename":"historical-worker"
            }],
            "diagnostic_replays": []
        })
    }

    #[test]
    fn config_only_preflight_does_not_observe_or_consume_cadence() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("config.json");
        let bytes = serde_json::to_vec(&preflight_fixture(temp.path())).unwrap();
        fs::write(&path, &bytes).unwrap();
        // Future not-before plus absent predecessor, units, filesystem and
        // scratch would all prevent a real observation. Static preflight must
        // succeed without touching any of those live-resource inputs.
        let report = dispatch(&path, true).unwrap().unwrap();
        assert_eq!(report["config_sha256"], sha256(&bytes));
        assert_eq!(report["ordinary_replay_count"], 1);
        assert_eq!(report["configuration_validated"], true);
        for flag in [
            "resource_observation_performed",
            "live_invocations_verified",
            "cadence_predecessor_verified",
            "sample_written",
            "replay_launch_authorized",
            "publication_authorized",
            "remote_mutations",
            "r2_mutations",
        ] {
            assert_eq!(report[flag], false, "{flag}");
        }
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 1);
        assert_eq!(fs::read(&path).unwrap(), bytes);
    }

    #[test]
    fn config_only_preflight_accepts_diagnostic_only_fleet_without_promoting_it() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("config.json");
        let mut config = preflight_fixture(temp.path());
        config["diagnostic_replays"] = config["replays"].clone();
        config["replays"] = serde_json::json!([]);
        fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
        let report = dispatch(&path, true).unwrap().unwrap();
        assert_eq!(report["ordinary_replay_count"], 0);
        assert_eq!(report["configuration_validated"], true);
        assert_eq!(report["resource_observation_performed"], false);
        assert_eq!(report["replay_launch_authorized"], false);
        assert_eq!(report["publication_authorized"], false);
        assert!(!temp.path().join("sample.json").exists());
    }

    #[test]
    fn host_pressure_is_optional_and_static_preflight_reads_no_telemetry() {
        let temp = tempfile::tempdir().unwrap();
        let mut value = preflight_fixture(temp.path());
        let config: Config = serde_json::from_value(value.clone()).unwrap();
        assert!(!config.host_global_pressure);
        value["host_global_pressure"] = serde_json::json!(true);
        let path = temp.path().join("config.json");
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        let report = dispatch(&path, true).unwrap().unwrap();
        assert_eq!(report["resource_observation_performed"], false);
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 1);
        value["host_global_pressure"] = serde_json::json!("true");
        assert!(serde_json::from_value::<Config>(value).is_err());
    }

    #[test]
    fn config_only_preflight_rejects_duplicate_terminal_and_current_diagnostic_ranges() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("config.json");
        let mut config = preflight_fixture(temp.path());
        let mut old = config["replays"][0].clone();
        old["range"] = serde_json::json!("203-203");
        let mut replacement = old.clone();
        replacement["producer_unit"] = serde_json::json!("replacement.service");
        replacement["expected_producer_invocation_id"] = serde_json::json!("c".repeat(32));
        config["diagnostic_replays"] = serde_json::json!([old, replacement]);
        fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
        let error = dispatch(&path, true).unwrap_err().to_string();
        assert!(
            error.contains("duplicate replay/diagnostic range"),
            "{error}"
        );
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 1);
    }

    #[test]
    fn config_only_preflight_retains_normal_schema_scope_and_cadence_gates() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("config.json");
        for (key, value) in [
            ("schema", serde_json::json!("old-schema")),
            ("minimum_interval_seconds", serde_json::json!(1799)),
            ("not_before_utc", serde_json::json!("invalid-time")),
            ("replays", serde_json::json!([])),
            ("output", serde_json::json!("relative.json")),
            ("unexpected_field", serde_json::json!(true)),
        ] {
            let mut config = preflight_fixture(temp.path());
            config[key] = value;
            fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
            assert!(dispatch(&path, true).is_err(), "accepted {key}");
            assert!(!temp.path().join("sample.json").exists());
        }
    }

    #[test]
    fn observer_cli_keeps_default_sampling_and_requires_explicit_config_only_flag() {
        let args = |values: &[&str]| {
            values
                .iter()
                .map(std::ffi::OsString::from)
                .collect::<Vec<_>>()
                .into_iter()
        };
        assert!(!parse_cli(args(&["/config.json"])).unwrap().1);
        assert!(
            parse_cli(args(&["/config.json", "--check-config"]))
                .unwrap()
                .1
        );
        for values in [
            vec![],
            vec!["/config.json", "--sample-now"],
            vec!["/config.json", "--check-config", "extra"],
            vec!["/config.json", "--check-config", "--check-config"],
        ] {
            assert!(parse_cli(args(&values)).is_err());
        }
    }

    #[test]
    fn oneshot_start_is_explicit_private_auxiliary_only() {
        use ReplayRole::{Primary, PrivateRamAuxiliary};
        assert!(accepted_unit_phase(
            "activating",
            "start",
            "oneshot",
            42,
            PrivateRamAuxiliary
        ));
        assert!(!accepted_unit_phase(
            "activating",
            "start",
            "oneshot",
            42,
            Primary
        ));
        assert!(accepted_unit_phase(
            "active", "running", "simple", 42, Primary
        ));
        for (active, sub, ty, pid) in [
            ("activating", "start", "simple", 42),
            ("activating", "start-pre", "oneshot", 42),
            ("activating", "start-post", "oneshot", 42),
            ("activating", "start", "oneshot", 0),
            ("active", "exited", "oneshot", 0),
            ("active", "running", "simple", 0),
            ("deactivating", "stop", "oneshot", 42),
        ] {
            assert!(!accepted_unit_phase(
                active,
                sub,
                ty,
                pid,
                PrivateRamAuxiliary
            ));
        }
    }

    #[test]
    fn private_oneshot_stability_requires_same_pid_phase_identity_and_cgroup() {
        let before = UnitObservation {
            unit: "horizon-203-ram-resource-baseline-test.service".into(),
            invocation_id: "a".repeat(32),
            load_state: "loaded".into(),
            active_state: "activating".into(),
            sub_state: "start".into(),
            result: "success".into(),
            restarts: 0,
            main_pid: 42,
            memory_current_bytes: 0,
            memory_peak_bytes: 0,
            control_group: "/system.slice/test.service".into(),
            cgroup: CgroupObservation {
                path: "/sys/fs/cgroup/system.slice/test.service".into(),
                io_counters_available: true,
                gauges: BTreeMap::new(),
                counters: BTreeMap::new(),
            },
        };
        assert!(stable_unit_for_role(
            &before,
            &before,
            ReplayRole::PrivateRamAuxiliary
        ));
        assert!(!stable_unit(&before, &before));
        for i in 0..8 {
            let mut wrong = before.clone();
            match i {
                0 => wrong.main_pid = 43,
                1 => wrong.main_pid = 0,
                2 => wrong.invocation_id = "b".repeat(32),
                3 => wrong.restarts = 1,
                4 => wrong.control_group = "/different".into(),
                5 => wrong.cgroup.path = "/different".into(),
                6 => wrong.sub_state = "start-post".into(),
                _ => {
                    wrong.active_state = "active".into();
                    wrong.sub_state = "running".into();
                }
            }
            assert!(
                !stable_unit_for_role(&before, &wrong, ReplayRole::PrivateRamAuxiliary),
                "case{i}"
            );
        }
    }

    #[test]
    fn observer_config_and_output_schemas_are_v2() {
        assert_eq!(
            CONFIG_SCHEMA,
            "jetstreamer-horizon-live-resource-sample-config-v2"
        );
        assert_eq!(OUTPUT_SCHEMA, "jetstreamer-horizon-live-resource-sample-v2");
    }

    #[test]
    fn routine_observation_enforces_the_cadence_floor() {
        assert_eq!(
            effective_not_before(2_800, 2_100, ObservationReason::Routine),
            2_800
        );
        assert_eq!(
            effective_not_before(2_800, 3_000, ObservationReason::Routine),
            3_000
        );
    }

    #[test]
    fn explicit_user_status_observation_uses_only_its_not_before_gate() {
        assert_eq!(
            effective_not_before(2_800, 2_100, ObservationReason::UserRequestedStatus),
            2_100
        );
    }

    #[test]
    fn observation_reason_defaults_to_routine_and_rejects_unknown_values() {
        let base = serde_json::json!({
            "schema": CONFIG_SCHEMA,
            "previous_sample": "/tmp/previous.json",
            "minimum_interval_seconds": 1800,
            "not_before_utc": "2026-10-17T07:00:00Z",
            "filesystem_path": "/",
            "output": "/tmp/output.json",
            "replays": []
        });
        let config: Config = serde_json::from_value(base.clone()).unwrap();
        assert_eq!(config.observation_reason, ObservationReason::Routine);
        assert!(config.diagnostic_replays.is_empty());

        let mut explicit = base.clone();
        explicit["observation_reason"] = serde_json::json!("user-requested-status");
        let config: Config = serde_json::from_value(explicit).unwrap();
        assert_eq!(
            config.observation_reason,
            ObservationReason::UserRequestedStatus
        );

        let mut invalid = base;
        invalid["observation_reason"] = serde_json::json!("automatic-bypass");
        assert!(serde_json::from_value::<Config>(invalid).is_err());
    }

    fn diagnostic_config(range: &str) -> ReplayConfig {
        ReplayConfig {
            range: range.into(),
            controller_unit: "horizon-qualify-test.service".into(),
            expected_controller_invocation_id: "a".repeat(32),
            producer_unit: "horizon-qualify-test.service".into(),
            expected_producer_invocation_id: "a".repeat(32),
            scratch_path: "/private/diagnostic/scratch".into(),
            worker_executable_basename: "historical-worker".into(),
            append_log: None,
        }
    }

    fn auxiliary_config() -> Config {
        let mut primary = diagnostic_config("203-203");
        primary.controller_unit = "horizon-qualify-203-root-prefix-resource-v1.service".into();
        primary.producer_unit = primary.controller_unit.clone();
        let mut replay = diagnostic_config("203-203");
        replay.controller_unit = "horizon-203-ram-resource-baseline-test.service".into();
        replay.producer_unit = replay.controller_unit.clone();
        replay.expected_controller_invocation_id = "b".repeat(32);
        replay.expected_producer_invocation_id = "b".repeat(32);
        replay.scratch_path =
            "/home/ubuntu/.jetstreamer-private/ram-resource-203-baseline-test/scratch".into();
        Config {
            schema: CONFIG_SCHEMA.into(),
            previous_sample: "/previous.json".into(),
            minimum_interval_seconds: 1800,
            not_before_utc: "2026-10-21T05:29:36Z".into(),
            observation_reason: ObservationReason::Routine,
            filesystem_path: "/".into(),
            output: "/output.json".into(),
            replays: Vec::new(),
            diagnostic_replays: vec![primary],
            host_global_pressure: false,
            epoch203_ram_auxiliary: Some(RamAuxiliaryConfig {
                replay,
                supervisor_profile: "jetstreamer-private-epoch203-ram-bounded-runner-plan-v1"
                    .into(),
                worker_sha256: "3f5e8efec328b3e00dd9ce5ae396fc4067e6be6554e4da8831a13273186a748a"
                    .into(),
                target_slot: 87_720_000,
                terminal_root_slot: 88_127_580,
            }),
        }
    }

    #[test]
    fn ram_auxiliary_is_explicit_bounded_and_never_an_ordinary_overlap_exception() {
        let mut config = auxiliary_config();
        validate_ram_auxiliary(&config).unwrap();
        validate_replay_configs(&config.replays, &config.diagnostic_replays).unwrap();
        config.replays.push(config.diagnostic_replays.remove(0));
        assert!(validate_ram_auxiliary(&config).is_err());
        let mut config = auxiliary_config();
        config.diagnostic_replays[0].range = "202-204".into();
        assert!(validate_ram_auxiliary(&config).is_err());
        let mut config = auxiliary_config();
        config.diagnostic_replays.clear();
        assert!(validate_ram_auxiliary(&config).is_err());
    }

    #[test]
    fn ram_auxiliary_rejects_scope_identity_worker_and_tree_substitution() {
        for mutation in 0..10 {
            let mut config = auxiliary_config();
            let auxiliary = config.epoch203_ram_auxiliary.as_mut().unwrap();
            match mutation {
                0 => auxiliary.replay.range = "204-204".into(),
                1 => auxiliary.target_slot += 1,
                2 => auxiliary.terminal_root_slot += 1,
                3 => auxiliary.worker_sha256 = "0".repeat(64),
                4 => auxiliary.replay.expected_producer_invocation_id = "c".repeat(32),
                5 => auxiliary.replay.scratch_path = "/private/scratch".into(),
                6 => auxiliary.replay.controller_unit = "foreign.service".into(),
                7 => auxiliary.replay.expected_controller_invocation_id = "a".repeat(32),
                8 => {
                    config.diagnostic_replays[0].scratch_path =
                        auxiliary.replay.scratch_path.clone()
                }
                9 => {
                    auxiliary.worker_sha256 =
                        "4aeca56378a4bb2c55d0e590c1e334c4afa6a375a2c0d94894b412bea261f1cc".into()
                }
                _ => unreachable!(),
            }
            assert!(
                validate_ram_auxiliary(&config).is_err(),
                "mutation {mutation}"
            );
        }
    }

    #[test]
    fn ram_auxiliary_history_does_not_borrow_same_epoch_primary_counters() {
        let previous = serde_json::json!({
            "schema":OUTPUT_SCHEMA,"completed_at_utc":"2026-10-21T05:29:36Z",
            "diagnostic_replays":[{"status":"observed","observation":{"range":"203-203","source":"primary"}}],
            "epoch203_ram_auxiliary":[{"status":"observed","observation":{"range":"203-203","source":"auxiliary"}}]
        });
        let config = auxiliary_config();
        let results = observe_private(
            &[config.epoch203_ram_auxiliary.unwrap().replay],
            &previous,
            "epoch203_ram_auxiliary",
            |_, history| {
                assert_eq!(history["replays"][0]["source"], "auxiliary");
                Ok(serde_json::json!({"range":"203-203"}))
            },
        );
        assert_eq!(results[0]["status"], "observed");
        assert_eq!(results[0]["ordinary_replay_claim"], false);
        assert_eq!(results[0]["current_sidecar_eta_valid"], false);
        assert_eq!(results[0]["publication_authorized"], false);
        let empty = private_predecessor(&previous, "missing-role");
        assert!(empty["replays"].as_array().unwrap().is_empty());
    }

    #[test]
    fn diagnostic_failure_is_explicit_and_does_not_suppress_other_samples() {
        let configs = [diagnostic_config("203-203"), diagnostic_config("225-225")];
        let mut calls = 0;
        let results = observe_diagnostics(&configs, &serde_json::json!({}), |config, _| {
            calls += 1;
            if config.range == "203-203" {
                anyhow::bail!("terminal or identity-changing diagnostic");
            }
            Ok(serde_json::json!({"range": config.range, "invocation_binding_stable": true}))
        });
        assert_eq!(calls, 2);
        assert_eq!(results[0]["status"], "unavailable");
        assert!(results[0]["observation"].is_null());
        assert!(
            results[0]["error"]
                .as_str()
                .unwrap()
                .contains("identity-changing")
        );
        assert_eq!(results[1]["status"], "observed");
        assert!(results[1]["error"].is_null());
        for result in results {
            for field in [
                "ordinary_replay_claim",
                "current_sidecar_eta_valid",
                "replay_launch_authorized",
                "publication_authorized",
                "r2_mutations",
            ] {
                assert_eq!(result[field], false, "{field}");
            }
        }
    }

    #[test]
    fn diagnostic_history_is_separate_and_excludes_failed_observations() {
        let previous = serde_json::json!({
            "schema": OUTPUT_SCHEMA,
            "completed_at_utc": "2026-10-20T03:04:42Z",
            "replays": [{"range":"206-206"}],
            "diagnostic_replays": [
                {"status":"unavailable", "observation":null},
                {"status":"observed", "observation":{"range":"203-203"}}
            ]
        });
        let selected = private_predecessor(&previous, "diagnostic_replays");
        assert_eq!(selected["schema"], OUTPUT_SCHEMA);
        assert_eq!(selected["completed_at_utc"], previous["completed_at_utc"]);
        assert_eq!(
            selected["replays"],
            serde_json::json!([{"range":"203-203"}])
        );
        assert!(
            private_predecessor(&serde_json::json!({}), "diagnostic_replays")["replays"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn diagnostic_and_ordinary_ranges_cannot_overlap_and_both_are_validated() {
        validate_replay_configs(
            &[diagnostic_config("206-206")],
            &[diagnostic_config("203-203")],
        )
        .unwrap();
        assert!(
            validate_replay_configs(
                &[diagnostic_config("203-203")],
                &[diagnostic_config("203-203")]
            )
            .is_err()
        );
        assert!(
            validate_replay_configs(
                &[diagnostic_config("202-204")],
                &[diagnostic_config("203-205")]
            )
            .is_err()
        );
        assert!(validate_replay_configs(&[], &[diagnostic_config("205-203")]).is_err());
        validate_replay_configs(&[diagnostic_config("206")], &[diagnostic_config("203")]).unwrap();
        assert!(
            validate_replay_configs(&[diagnostic_config("203")], &[diagnostic_config("203-203")])
                .is_err()
        );
        let mut invalid = diagnostic_config("203-203");
        invalid.expected_producer_invocation_id = "foreign".into();
        assert!(validate_replay_configs(&[], &[invalid]).is_err());
    }

    #[test]
    fn timestamp_round_trip_known_values() {
        for (text, unix) in [
            ("1970-01-01T00:00:00Z", 0),
            ("2000-02-29T12:34:56Z", 951_827_696),
            ("2026-10-13T16:13:20Z", 1_791_908_000),
        ] {
            assert_eq!(parse_utc(text).unwrap(), unix);
            assert_eq!(format_utc(unix).unwrap(), text);
        }
    }

    #[test]
    fn predecessor_receipt_timestamp_compatibility() {
        let recorded = serde_json::json!({"recorded_at_utc": "2026-10-14T14:18:11Z"});
        assert_eq!(
            parse_receipt_utc(receipt_timestamp(&recorded).unwrap()).unwrap(),
            1_791_987_491
        );
        let observed = serde_json::json!({"observed_at_utc": "2026-10-14T14:18:11.818627220Z"});
        assert_eq!(
            parse_receipt_utc(receipt_timestamp(&observed).unwrap()).unwrap(),
            1_791_987_491
        );
        let conflicting = serde_json::json!({
            "recorded_at_utc": "2026-10-14T14:18:11Z",
            "observed_at_utc": "2026-10-14T14:18:12Z"
        });
        assert!(receipt_timestamp(&conflicting).is_err());
    }

    #[test]
    fn scratch_scan_does_not_follow_symlinks() {
        let directory = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("large"), vec![7_u8; 64 * 1024]).unwrap();
        fs::create_dir(directory.path().join("inside")).unwrap();
        fs::write(directory.path().join("inside/file"), b"sample").unwrap();
        std::os::unix::fs::symlink(outside.path(), directory.path().join("link")).unwrap();
        let scan = scan_scratch(directory.path()).unwrap();
        assert_eq!(scan.regular_files, 1);
        assert_eq!(scan.directories, 2);
        assert_eq!(scan.symlinks, 1);
        assert_eq!(scan.entries, 4);
    }

    #[test]
    fn no_clobber_writer_refuses_existing_output() {
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("receipt.json");
        fs::write(&output, b"preserve me").unwrap();
        assert!(write_no_clobber(&output, &serde_json::json!({"new": true})).is_err());
        assert_eq!(fs::read(&output).unwrap(), b"preserve me");
    }

    #[test]
    fn systemctl_property_parser_exposes_transient_not_found_state() {
        let properties = parse_systemctl_properties(
            b"LoadState=not-found\nActiveState=inactive\nInvocationID=\n",
            "example.service",
        )
        .unwrap();
        assert_eq!(
            properties.get("LoadState").map(String::as_str),
            Some("not-found")
        );
        assert_eq!(properties.get("InvocationID").map(String::as_str), Some(""));
        assert!(should_retry_systemctl_discovery(&properties, 0));
        assert!(should_retry_systemctl_discovery(&properties, 9));
        assert!(!should_retry_systemctl_discovery(&properties, 10));
    }

    #[test]
    fn cgroup_discovery_requires_the_exact_system_service() {
        let unit = "jetstreamer-example.service";
        assert!(
            cgroup_belongs_to_system_unit(b"0::/system.slice/jetstreamer-example.service\n", unit,)
                .unwrap()
        );
        assert!(
            !cgroup_belongs_to_system_unit(
                b"0::/system.slice/jetstreamer-example.service-child\n",
                unit,
            )
            .unwrap()
        );
        assert!(
            !cgroup_belongs_to_system_unit(b"0::/user.slice/jetstreamer-example.service\n", unit,)
                .unwrap()
        );
    }

    #[test]
    fn pid_discovery_requires_exact_systemctl_identity() {
        let unit = "jetstreamer-example.service";
        assert!(systemctl_whoami_matches(b"jetstreamer-example.service\n", unit).unwrap());
        assert!(!systemctl_whoami_matches(b"jetstreamer-other.service\n", unit).unwrap());
    }

    #[test]
    fn cgroup_parsers_preserve_pressure_fault_and_io_counters() {
        let directory = tempfile::tempdir().unwrap();
        let memory = directory.path().join("memory.stat");
        let pressure = directory.path().join("memory.pressure");
        let io = directory.path().join("io.stat");
        fs::write(&memory, "anon 12\nactive_anon 9\npgmajfault 7\n").unwrap();
        fs::write(
            &pressure,
            "some avg10=0.00 avg60=0.01 avg300=0.02 total=41\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=3\n",
        )
        .unwrap();
        fs::write(
            &io,
            "8:0 rbytes=10 wbytes=20 rios=1 wios=2\n8:1 rbytes=30 wbytes=40 rios=3 wios=4\n",
        )
        .unwrap();
        let memory = parse_counter_file(&memory, "memory_stat").unwrap();
        let (memory_gauges, memory_counters) = split_memory_stat(memory);
        let pressure = parse_pressure_file(&pressure, "memory_pressure").unwrap();
        let io = parse_io_stat(&io).unwrap();
        assert_eq!(memory_gauges["memory_stat.active_anon"], Some(9));
        assert_eq!(memory_gauges["memory_stat.pgmajfault"], Some(7));
        assert!(!memory_counters.contains_key("memory_stat.active_anon"));
        assert_eq!(memory_counters["memory_stat.pgmajfault"], 7);
        assert_eq!(pressure["memory_pressure.some_total_usec"], 41);
        assert_eq!(pressure["memory_pressure.full_total_usec"], 3);
        assert_eq!(io["io.rbytes"], 40);
        assert_eq!(io["io.wbytes"], 60);
        assert_eq!(io["io.rios"], 4);
        assert_eq!(io["io.wios"], 6);
    }

    #[test]
    fn cgroup_deltas_omit_only_incomparable_io_counters() {
        let before = BTreeMap::from([
            ("cpu.usage_usec".to_owned(), 100),
            ("io.dbytes".to_owned(), 0),
            ("io.dios".to_owned(), 0),
            ("io.rbytes".to_owned(), 20),
        ]);
        let after = BTreeMap::from([
            ("cpu.usage_usec".to_owned(), 130),
            ("io.rbytes".to_owned(), 25),
        ]);
        let deltas = counter_deltas(&before, &after).unwrap();
        assert_eq!(deltas.counters["cpu.usage_usec"], 30);
        assert!(!deltas.io_counters_comparable);
        assert!(!deltas.counters.keys().any(|name| name.starts_with("io.")));

        let newly_materialized = BTreeMap::from([
            ("cpu.usage_usec".to_owned(), 130),
            ("io.dbytes".to_owned(), 7),
            ("io.rbytes".to_owned(), 25),
        ]);
        let deltas = counter_deltas(
            &BTreeMap::from([
                ("cpu.usage_usec".to_owned(), 100),
                ("io.rbytes".to_owned(), 20),
            ]),
            &newly_materialized,
        )
        .unwrap();
        assert_eq!(deltas.counters["io.dbytes"], 7);
        assert_eq!(deltas.counters["io.rbytes"], 5);
        assert!(deltas.io_counters_comparable);

        let disappeared = BTreeMap::from([("cpu.usage_usec".to_owned(), 140)]);
        let deltas = counter_deltas(&before, &disappeared).unwrap();
        assert_eq!(deltas.counters["cpu.usage_usec"], 40);
        assert!(!deltas.io_counters_comparable);
        assert!(!deltas.counters.keys().any(|name| name.starts_with("io.")));

        let nonzero_discard = BTreeMap::from([
            ("cpu.usage_usec".to_owned(), 100),
            ("io.dbytes".to_owned(), 1),
        ]);
        let deltas = counter_deltas(&nonzero_discard, &disappeared).unwrap();
        assert!(!deltas.io_counters_comparable);

        let zero_required = BTreeMap::from([
            ("cpu.usage_usec".to_owned(), 100),
            ("memory_events.oom".to_owned(), 0),
        ]);
        assert!(
            counter_deltas(&zero_required, &disappeared)
                .unwrap_err()
                .to_string()
                .contains("memory_events.oom disappeared")
        );

        let decreased_required = BTreeMap::from([("cpu.usage_usec".to_owned(), 99)]);
        assert!(
            counter_deltas(
                &BTreeMap::from([("cpu.usage_usec".to_owned(), 100)]),
                &decreased_required,
            )
            .unwrap_err()
            .to_string()
            .contains("cpu.usage_usec decreased")
        );
    }

    #[test]
    fn absent_io_stat_is_allowed_only_without_parent_delegation() {
        let directory = tempfile::tempdir().unwrap();
        let parent = directory.path().join("parent");
        let cgroup = parent.join("service");
        fs::create_dir_all(&cgroup).unwrap();
        fs::write(parent.join("cgroup.subtree_control"), "cpu memory pids\n").unwrap();
        let (available, counters) = observe_io_counters(&cgroup).unwrap();
        assert!(!available);
        assert!(counters.is_empty());

        fs::write(
            parent.join("cgroup.subtree_control"),
            "cpu io memory pids\n",
        )
        .unwrap();
        assert!(
            observe_io_counters(&cgroup)
                .unwrap_err()
                .to_string()
                .contains("delegated but io.stat is missing")
        );
    }

    #[test]
    fn progress_window_reports_useful_work_and_counter_resets() {
        let points = vec![
            parse_progress_point(
                "progress slot 100/199 (10.0%) txs=1000 accounts=2000",
                1_000_000,
            )
            .unwrap(),
            parse_progress_point(
                "progress slot 150/199 (20.0%) txs=1500 accounts=2800",
                3_000_000,
            )
            .unwrap(),
            parse_progress_point("progress slot 200/299 (0.1%) txs=25 accounts=40", 5_000_000)
                .unwrap(),
        ];
        let window =
            progress_window_from_points("0123456789abcdef0123456789abcdef", 1, 5, points).unwrap();
        assert!(window.sufficient_for_rates);
        assert_eq!(window.slot_delta, Some(100));
        assert_eq!(window.transaction_delta, Some(525));
        assert_eq!(window.account_update_delta, Some(840));
        assert_eq!(window.counter_resets, 2);
        assert_eq!(window.transactions_per_second, Some(131.25));
        assert_eq!(window.account_updates_per_second, Some(210.0));
    }

    #[test]
    fn progress_parser_rejects_non_progress_messages() {
        assert!(parse_progress_point("slot 10 txs=2 accounts=3", 1).is_none());
        assert!(parse_progress_point("progress slot 10/20 txs=x accounts=3", 1).is_none());
    }

    #[test]
    fn v2_progress_window_begins_after_the_previous_scan() {
        let previous = serde_json::json!({
            "schema": OUTPUT_SCHEMA,
            "recorded_at_utc": "2026-10-16T08:35:59Z",
            "completed_at_utc": "2026-10-16T08:36:07Z"
        });
        assert_eq!(
            progress_window_start(&previous, parse_utc("2026-10-16T08:35:59Z").unwrap()).unwrap(),
            parse_utc("2026-10-16T08:36:07Z").unwrap()
        );

        let legacy = serde_json::json!({"recorded_at_utc": "2026-10-16T08:35:59Z"});
        assert_eq!(progress_window_start(&legacy, 42).unwrap(), 42);
    }

    #[test]
    fn cross_sample_reports_invocation_bound_resource_efficiency() {
        let invocation = "0123456789abcdef0123456789abcdef";
        let previous = serde_json::json!({
            "schema": OUTPUT_SCHEMA,
            "recorded_at_utc": "2026-10-16T08:35:59Z",
            "completed_at_utc": "2026-10-16T08:36:00Z",
            "replays": [{
                "range": "216-219",
                "producer_after": {
                    "invocation_id": invocation,
                    "cgroup": {
                        "io_counters_available": true,
                        "counters": {
                            "cpu.usage_usec": 1_000_000,
                            "io.rbytes": 100
                        }
                    }
                },
                "conservative_observed_physical_bytes": 1_000,
                "worker_after": {"vmas": 100}
            }]
        });
        let replay = ReplayConfig {
            range: "216-219".to_owned(),
            controller_unit: "controller.service".to_owned(),
            expected_controller_invocation_id: invocation.to_owned(),
            producer_unit: "producer.service".to_owned(),
            expected_producer_invocation_id: invocation.to_owned(),
            scratch_path: PathBuf::from("/scratch"),
            worker_executable_basename: "worker".to_owned(),
            append_log: None,
        };
        let producer_before = UnitObservation {
            unit: "producer.service".to_owned(),
            invocation_id: invocation.to_owned(),
            load_state: "loaded".to_owned(),
            active_state: "active".to_owned(),
            sub_state: "running".to_owned(),
            result: "success".to_owned(),
            restarts: 0,
            main_pid: 1,
            memory_current_bytes: 0,
            memory_peak_bytes: 0,
            control_group: PathBuf::from("/system.slice/producer.service"),
            cgroup: CgroupObservation {
                path: PathBuf::from("/sys/fs/cgroup/system.slice/producer.service"),
                io_counters_available: true,
                gauges: BTreeMap::new(),
                counters: BTreeMap::from([
                    ("cpu.usage_usec".to_owned(), 3_601_000_000),
                    ("io.rbytes".to_owned(), 300),
                ]),
            },
        };
        let worker_before = WorkerObservation {
            pid: 2,
            executable: PathBuf::from("/scratch/worker"),
            executable_beneath_bound_scratch: true,
            vmas: 120,
            matching_workers: 1,
        };
        let useful_work = ProgressWindow {
            append_log_evidence: None,
            journal_invocation_id: invocation.to_owned(),
            since_unix_seconds: parse_utc("2026-10-16T08:36:00Z").unwrap(),
            until_unix_seconds: parse_utc("2026-10-16T09:06:00Z").unwrap(),
            matching_markers: 2,
            first: None,
            last: None,
            counter_resets: 0,
            elapsed_seconds: Some(1_800.0),
            slot_delta: Some(1),
            transaction_delta: Some(2_000_000),
            account_update_delta: Some(3_000_000),
            slots_per_second: Some(1.0 / 1_800.0),
            transactions_per_second: Some(2_000_000.0 / 1_800.0),
            account_updates_per_second: Some(3_000_000.0 / 1_800.0),
            sufficient_for_rates: true,
        };
        let observation = cross_sample_observation(
            &previous,
            &replay,
            parse_utc("2026-10-16T09:06:00Z").unwrap(),
            &producer_before,
            &worker_before,
            1_500,
            &useful_work,
        )
        .unwrap()
        .unwrap();
        assert_eq!(observation.elapsed_seconds, 1_800);
        assert_eq!(
            observation.producer_cgroup_counter_delta["cpu.usage_usec"],
            3_600_000_000
        );
        assert_eq!(observation.effective_cpu_cores, Some(2.0));
        assert!(observation.producer_io_counter_delta_available);
        assert_eq!(observation.physical_scratch_delta_bytes, 500);
        assert_eq!(observation.worker_vma_delta, 20);
        assert_eq!(
            observation.physical_scratch_bytes_per_million_transactions,
            Some(250.0)
        );
        assert_eq!(observation.worker_vmas_per_million_transactions, Some(10.0));

        let missing = ReplayConfig {
            range: "220-223".to_owned(),
            ..replay
        };
        assert!(
            cross_sample_observation(
                &previous,
                &missing,
                parse_utc("2026-10-16T09:06:00Z").unwrap(),
                &producer_before,
                &worker_before,
                1_500,
                &useful_work,
            )
            .unwrap()
            .is_none()
        );
    }
}
