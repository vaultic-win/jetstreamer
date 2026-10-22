//! One routine metadata cycle, never a sampler, replay controller or uploader.
use {
    anyhow::{Context, Result, ensure},
    serde::{Deserialize, Serialize},
    serde_json::{Value, json},
    sha2::{Digest, Sha256},
    std::{
        collections::{BTreeMap, BTreeSet},
        env,
        fs::{self, File, OpenOptions},
        io::{Read, Write},
        os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        path::{Path, PathBuf},
        process::{Command, Stdio},
        time::{SystemTime, UNIX_EPOCH},
    },
};

const PLAN_SCHEMA: &str = "jetstreamer-horizon-routine-cycle-plan-v1";
const PLAN_SCHEMA_101: &str = "jetstreamer-horizon-routine-cycle-101-200-plan-v2";
const FLEET_ROOT_101: &str = "/var/lib/jetstreamer-horizon-fleet-101-200-20261019-v1";
const LIMIT: u64 = 16 << 20;
const BUCKET: &str = "solana-archive-with-accounts-data";

#[path = "routine_next.rs"]
mod next_preparation;

#[path = "routine_terminal.rs"]
mod terminal_handoff;

#[path = "routine_delivery160.rs"]
mod delivery160;
#[path = "routine_delivery198.rs"]
mod delivery198;
#[path = "routine_delivery198_recover.rs"]
mod delivery198_recover;
#[path = "routine_public160.rs"]
mod public160;
#[path = "routine_public160_recovery.rs"]
mod public160_recovery;
#[path = "routine_public160_timing.rs"]
mod public160_timing;
#[path = "routine_public198.rs"]
mod public198;

#[path = "routine_private144.rs"]
mod private144;

#[path = "routine_recovery.rs"]
mod controller_recovery;

#[path = "routine_runtime157.rs"]
mod runtime157;

#[path = "routine_assembly144.rs"]
mod assembly144;
#[path = "routine_assembly144_scans.rs"]
mod assembly144_scans;
#[path = "routine_assembly144_scans_recover.rs"]
mod assembly144_scans_recover;
#[path = "routine_cohort191.rs"]
mod cohort191;
#[path = "routine_completed144.rs"]
mod completed144;
#[path = "routine_continuation144.rs"]
mod continuation144;
#[path = "routine_native141.rs"]
mod native141;
#[path = "routine_native144.rs"]
mod native144;
#[path = "routine_native144_recovery.rs"]
mod native144_recovery;
#[path = "routine_prefix144.rs"]
mod prefix144;
#[path = "routine_prefix157.rs"]
mod prefix157;
#[path = "routine_publication144.rs"]
mod publication144;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Bound {
    path: PathBuf,
    sha256: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Tools {
    sealer: Bound,
    estimator: Bound,
    r2: Bound,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    sample_target_utc: String,
    endpoint_sha256: String,
    bucket: String,
    observer: PathBuf,
    observer_config: Bound,
    previous_observer: Bound,
    model_template: Bound,
    fleet_template: Bound,
    previous_estimates: Bound,
    previous_fleet: Bound,
    tools: Tools,
    expected_epochs: Vec<u64>,
    cycle_directory: PathBuf,
    cycle_unit: String,
    estimate_output: PathBuf,
    fleet_output: PathBuf,
    #[serde(default)]
    additional_gate_evidence: BTreeMap<String, Vec<Bound>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    scope_101_200: Option<Scope101200>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    epoch157_terminal_handoff: Option<Bound>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    epoch198_delivery: Option<delivery198::Profile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    epoch160_delivery: Option<delivery160::Profile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    public198_delivery: Option<public198::Profile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    package_controller_recovery: Option<Bound>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    runtime_handoff157: Option<Bound>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    prefix157_audit: Option<prefix157::Profile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    prefix144_audit: Option<prefix144::Profile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    completed144_prefix: Option<completed144::Profile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    native144_restore: Option<native144::Profile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    continuation144: Option<continuation144::Profile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    assembly144_recovery: Option<assembly144::Profile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    native141_audit: Option<native141::Profile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    assembly144_scans: Option<assembly144_scans::Profile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    publication144: Option<publication144::Profile>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Scope101200 {
    diagnostic_ranges: Vec<DiagnosticClaim>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    private144_observer: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    additional_tracked_units: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DiagnosticClaim {
    range: String,
    controller_unit: String,
    producer_unit: String,
    expected_controller_invocation_id: String,
    expected_producer_invocation_id: String,
}

fn is_101(p: &Plan) -> Result<bool> {
    match (p.schema.as_str(), &p.scope_101_200) {
        (PLAN_SCHEMA, None) => Ok(false),
        (PLAN_SCHEMA_101, Some(scope)) => {
            ensure!(
                scope.diagnostic_ranges.len() <= 1,
                "unsupported diagnostic census"
            );
            let unique: BTreeSet<_> = scope.additional_tracked_units.iter().collect();
            ensure!(
                unique.len() == scope.additional_tracked_units.len()
                    && unique.len() <= 128
                    && unique.iter().all(|s| (s.starts_with("horizon-")
                        || s.starts_with("jetstreamer-"))
                        && s.ends_with(".service")
                        && s.len() <= 255
                        && s.bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))),
                "invalid additional observational unit census"
            );
            for d in &scope.diagnostic_ranges {
                ensure!(
                    d.range == "144"
                        && (d.controller_unit
                            == "horizon-qualify-epoch144-loader-focus-20261016-v1.service"
                            && p.native144_restore.is_none()
                            || native144::owner(p, d)
                            || continuation144::owner(p, d)
                            || assembly144::owner(p, d))
                        && d.producer_unit == d.controller_unit
                        && d.expected_controller_invocation_id == d.expected_producer_invocation_id,
                    "unsupported private diagnostic owner/scope"
                );
                for id in [
                    &d.expected_controller_invocation_id,
                    &d.expected_producer_invocation_id,
                ] {
                    ensure!(
                        id.len() == 32
                            && id
                                .bytes()
                                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                        "invalid diagnostic invocation"
                    );
                }
            }
            if scope.private144_observer {
                ensure!(
                    scope.diagnostic_ranges.len() == 1
                        && (scope.diagnostic_ranges[0].expected_producer_invocation_id
                            == private144::INVOCATION
                            && p.native144_restore.is_none()
                            || native144::owner(p, &scope.diagnostic_ranges[0])
                            || continuation144::owner(p, &scope.diagnostic_ranges[0])
                            || assembly144::owner(p, &scope.diagnostic_ranges[0])),
                    "private144 observer requires exact retained diagnostic owner"
                );
            }
            Ok(true)
        }
        _ => anyhow::bail!("routine schema/profile mismatch"),
    }
}

fn campaign_bounds(p: &Plan) -> Result<(u64, u64)> {
    Ok(if is_101(p)? { (101, 200) } else { (201, 300) })
}
fn generation_101(p: &Plan) -> &'static str {
    if native141::all_acquisition_enabled(p) {
        return "native141-all-acquisition-public160-timed-scans-upload198-v1";
    }
    if p.publication144.is_some() && public160_timing::enabled(p) {
        return "publication144-public160-timed-native141-acquisition-scans-upload198-v1";
    }
    if public160_timing::enabled(p) {
        return "public160-timed-native141-acquisition-scans-upload198-v1";
    }
    if public160::enabled(p) {
        return "public160-native141-acquisition-scans-upload198-v1";
    }
    if p.epoch160_delivery.is_some() {
        return "delivery160-native141-acquisition-scans-upload198-v1";
    }
    if p.publication144.is_some() {
        return "publication144-native141-acquisition-scans-upload198-v1";
    }
    if native141::acquisition_enabled(p) {
        return "native141-acquisition-assembly144-scans-upload198-refresh-completed144-v1";
    }
    if p.assembly144_scans.is_some() {
        return "native141-rejection-assembly144-scans-upload198-refresh-completed144-v1";
    }
    if native141::rejection_enabled(p) {
        return "native141-rejection-assembly144-upload198-refresh-completed144-v1";
    }
    if p.native141_audit.is_some() {
        return "native141-assembly144-upload198-refresh-completed144-v1";
    }
    if p.assembly144_recovery.is_some() {
        if assembly144::reader_v2(p) {
            "assembly144-upload198-refresh-completed144-v2"
        } else {
            "assembly144-upload198-refresh-completed144-v1"
        }
    } else if p.continuation144.is_some() {
        "continuation144-upload198-refresh-completed144-v2"
    } else if p.native144_restore.is_some() && public198::upload(p) {
        "native144-upload198-refresh-completed144-v1"
    } else if p.native144_restore.is_some() {
        "native144-native198-refresh-completed144-v1"
    } else if public198::upload(p) {
        "upload198-refresh-completed144-v1"
    } else if public198::refreshed(p) {
        "native198-refresh-completed144-v1"
    } else if public198::native(p) {
        "native198-completed144-v1"
    } else if p.public198_delivery.is_some() {
        "public198-completed144-v1"
    } else if p.completed144_prefix.is_some() && p.epoch198_delivery.is_some() {
        "delivery198-completed144-v1"
    } else if p.completed144_prefix.is_some() {
        "completed144-v1"
    } else if p.prefix144_audit.is_some() && p.epoch198_delivery.is_some() {
        "delivery198-prefix144-v1"
    } else if p.prefix144_audit.is_some() {
        "prefix144-v1"
    } else if p.prefix157_audit.is_some() && p.epoch198_delivery.is_some() {
        "delivery198-prefix157-v1"
    } else if p.prefix157_audit.is_some() {
        "prefix157-v1"
    } else if p.epoch198_delivery.is_some() {
        "delivery198-v1"
    } else {
        "v2"
    }
}
fn cycle_unit(p: &Plan) -> Result<String> {
    Ok(if is_101(p)? {
        format!(
            "horizon-routine-cycle-101-200-{}-{}.service",
            stamp(&p.sample_target_utc),
            generation_101(p)
        )
    } else {
        format!(
            "horizon-routine-cycle-{}-v1.service",
            stamp(&p.sample_target_utc)
        )
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn sha(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}
fn is_sha(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn utc_seconds(s: &str) -> Result<u64> {
    ensure!(s.len() == 20 && s.is_ascii(), "noncanonical UTC");
    for (i, b) in s.bytes().enumerate() {
        let expected = match i {
            4 | 7 => Some(b'-'),
            10 => Some(b'T'),
            13 | 16 => Some(b':'),
            19 => Some(b'Z'),
            _ => None,
        };
        ensure!(
            expected.map_or_else(|| b.is_ascii_digit(), |e| b == e),
            "noncanonical UTC"
        );
    }
    let n = |a, b| s[a..b].parse::<i32>();
    let mut t: libc::tm = unsafe { std::mem::zeroed() };
    t.tm_year = n(0, 4)? - 1900;
    t.tm_mon = n(5, 7)? - 1;
    t.tm_mday = n(8, 10)?;
    t.tm_hour = n(11, 13)?;
    t.tm_min = n(14, 16)?;
    t.tm_sec = n(17, 19)?;
    let fields = (
        t.tm_year, t.tm_mon, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec,
    );
    let result = unsafe { libc::timegm(&mut t) };
    ensure!(
        fields
            == (
                t.tm_year, t.tm_mon, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec
            ),
        "nonexistent UTC"
    );
    Ok(u64::try_from(result)?)
}
fn stamp(s: &str) -> String {
    s.chars().filter(|c| *c != '-' && *c != ':').collect()
}

fn read_checked(path: &Path, max: u64, owner: u32, immutable: bool) -> Result<Vec<u8>> {
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "noncanonical input path"
    );
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let a = f.metadata()?;
    ensure!(
        a.is_file()
            && a.nlink() == 1
            && a.uid() == owner
            && a.mode() & if immutable { 0o222 } else { 0o022 } == 0
            && a.len() <= max,
        "unsafe input ownership, mode, links or length"
    );
    let mut bytes = Vec::new();
    (&mut f).take(max + 1).read_to_end(&mut bytes)?;
    let b = f.metadata()?;
    let named = fs::symlink_metadata(path)?;
    ensure!(
        bytes.len() as u64 == a.len()
            && a.dev() == b.dev()
            && a.ino() == b.ino()
            && a.len() == b.len()
            && a.mtime() == b.mtime()
            && a.mtime_nsec() == b.mtime_nsec()
            && a.ctime() == b.ctime()
            && a.ctime_nsec() == b.ctime_nsec()
            && !named.file_type().is_symlink()
            && named.dev() == a.dev()
            && named.ino() == a.ino(),
        "input changed"
    );
    Ok(bytes)
}
fn bound_bytes(b: &Bound, immutable: bool) -> Result<Vec<u8>> {
    ensure!(is_sha(&b.sha256), "invalid input digest");
    let bytes = read_checked(&b.path, LIMIT, 0, immutable)?;
    ensure!(sha(&bytes) == b.sha256, "input digest mismatch");
    Ok(bytes)
}
fn bound_json(b: &Bound, immutable: bool) -> Result<Value> {
    Ok(serde_json::from_slice(&bound_bytes(b, immutable)?)?)
}
fn tool_ok(b: &Bound) -> Result<()> {
    ensure!(
        is_sha(&b.sha256) && b.path.is_absolute() && b.path.canonicalize()? == b.path,
        "invalid tool binding"
    );
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&b.path)?;
    let a = f.metadata()?;
    ensure!(
        a.is_file()
            && a.nlink() == 1
            && a.uid() == 0
            && a.mode() & 0o222 == 0
            && a.mode() & 0o111 != 0
            && a.len() <= 512 << 20,
        "unsafe executable"
    );
    let mut hash = Sha256::new();
    let mut buf = [0; 128 << 10];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hash.update(&buf[..n]);
    }
    let z = f.metadata()?;
    let named = fs::symlink_metadata(&b.path)?;
    ensure!(
        hex(&hash.finalize()) == b.sha256
            && a.dev() == z.dev()
            && a.ino() == z.ino()
            && a.len() == z.len()
            && a.mtime() == z.mtime()
            && a.mtime_nsec() == z.mtime_nsec()
            && a.ctime() == z.ctime()
            && a.ctime_nsec() == z.ctime_nsec()
            && !named.file_type().is_symlink()
            && a.dev() == named.dev()
            && a.ino() == named.ino(),
        "tool digest or identity changed"
    );
    Ok(())
}
fn private_dir(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "noncanonical private directory"
    );
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_dir() && m.uid() == 0 && m.mode() & 0o6077 == 0,
        "directory must be root-private"
    );
    Ok(())
}
fn absent(path: &Path) -> Result<()> {
    ensure!(
        fs::symlink_metadata(path).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        "output already exists or is unreadable"
    );
    Ok(())
}

fn newer_fleet(candidate: &Value, previous: &Value) -> Result<bool> {
    newer_fleet_in_scope(candidate, previous, 201, 300)
}
fn newer_fleet_in_scope(
    candidate: &Value,
    previous: &Value,
    first: u64,
    last: u64,
) -> Result<bool> {
    if candidate["first_epoch"] != first || candidate["last_epoch"] != last {
        return Ok(false);
    }
    ensure!(
        candidate["schema"] == "jetstreamer-horizon-campaign-fleet-v1",
        "unknown in-scope fleet schema"
    );
    let sample = utc_seconds(
        candidate["sampled_at_utc"]
            .as_str()
            .context("fleet time missing")?,
    )?;
    let prior = utc_seconds(
        previous["sampled_at_utc"]
            .as_str()
            .context("predecessor fleet time missing")?,
    )?;
    Ok(sample > prior
        || (sample == prior
            && candidate["recorded_unix_seconds"]
                .as_u64()
                .context("fleet recording time missing")?
                > previous["recorded_unix_seconds"]
                    .as_u64()
                    .context("predecessor recording time missing")?))
}

fn latest_fleet_unchanged(p: &Plan, previous: &Value) -> Result<()> {
    if is_101(p)? {
        let root = Path::new(FLEET_ROOT_101);
        private_dir(root)?;
        ensure!(
            p.previous_fleet.path.parent() == Some(root),
            "foreign101fleet predecessor namespace"
        );
        for entry in fs::read_dir(root)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                anyhow::bail!("non-UTF8 fleet member")
            };
            if !name.starts_with("fleet-") || !name.ends_with(".json") {
                continue;
            }
            ensure!(entry.file_type()?.is_file(), "unsafe101fleet census member");
            let value: Value =
                serde_json::from_slice(&read_checked(&entry.path(), LIMIT, 0, false)?)?;
            ensure!(
                value["first_epoch"] == 101 && value["last_epoch"] == 200,
                "foreign fleet inside101namespace"
            );
            if entry.path() == p.previous_fleet.path {
                ensure!(
                    sha(&read_checked(&entry.path(), LIMIT, 0, false)?) == p.previous_fleet.sha256,
                    "fleet predecessor changed during census"
                );
                continue;
            }
            let tied = value["sampled_at_utc"] == previous["sampled_at_utc"]
                && value["recorded_unix_seconds"] == previous["recorded_unix_seconds"];
            ensure!(
                !tied && !newer_fleet_in_scope(&value, previous, 101, 200)?,
                "newer campaign fleet exists;regenerate pending cycle"
            );
        }
        return Ok(());
    }
    // A user-requested cycle or an event-driven admission invalidates this
    // pending one-shot. Never silently fork the authoritative fleet chain.
    let root = Path::new("/var/lib/jetstreamer/horizon-campaign-fleet");
    private_dir(root)?;
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        ensure!(!kind.is_symlink(), "fleet census contains a symlink");
        if !kind.is_dir() {
            continue;
        }
        let path = entry.path().join("fleet-ledger.json");
        match fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e.into()),
            Ok(_) => (),
        }
        let value: Value = serde_json::from_slice(&read_checked(&path, LIMIT, 0, false)?)?;
        ensure!(
            !newer_fleet(&value, previous)?,
            "newer campaign fleet exists; regenerate pending cycle"
        );
    }
    Ok(())
}
fn write_new(path: &Path, value: &Value) -> Result<Bound> {
    private_dir(path.parent().context("output parent missing")?)?;
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    f.write_all(&bytes)?;
    f.sync_all()?;
    File::open(path.parent().unwrap())?.sync_all()?;
    Ok(Bound {
        path: path.into(),
        sha256: sha(&bytes),
    })
}

fn validate_templates(
    p: &Plan,
    model: &Value,
    fleet: &Value,
    previous: &Value,
    estimates: &Value,
    old_observer: &Value,
) -> Result<()> {
    let host101 = is_101(p)?;
    let (first, last) = campaign_bounds(p)?;
    ensure!(
        p.bucket == BUCKET && is_sha(&p.endpoint_sha256),
        "invalid cycle scope"
    );
    ensure!(p.cycle_unit == cycle_unit(p)?, "routine unit name mismatch");
    let target = utc_seconds(&p.sample_target_utc)?;
    let old_time = old_observer["recorded_at_utc"]
        .as_str()
        .context("old observer time missing")?;
    ensure!(
        target.checked_sub(utc_seconds(old_time)?) == Some(controller_recovery::interval(p)?),
        "routine target must follow its qualified predecessor interval"
    );
    ensure!(
        old_observer["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && model["schema"] == "jetstreamer-horizon-r2-status-eta-model-v5"
            && model["phase"] == "replay"
            && model["sample_target_utc"] == old_time
            && (host101
                || (model["evidence"][1]["path"]
                    == p.previous_observer.path.to_str().unwrap_or("")
                    && model["evidence"][1]["sha256"] == p.previous_observer.sha256)),
        "model does not bind exact predecessor"
    );
    ensure!(
        previous["schema"] == "jetstreamer-horizon-campaign-fleet-v1"
            && previous["sampled_at_utc"] == old_time
            && previous["plan"].as_str() == p.fleet_template.path.to_str()
            && previous["plan_sha256"] == p.fleet_template.sha256
            && previous["observer_sha256"] == p.previous_observer.sha256,
        "fleet predecessor mismatch"
    );
    if host101 {
        ensure!(
            previous["first_epoch"] == 101
                && previous["last_epoch"] == 200
                && p.previous_fleet.path.parent() == Some(Path::new(FLEET_ROOT_101)),
            "foreign101fleet predecessor"
        );
    }
    ensure!(
        fleet["schema"] == "jetstreamer-horizon-campaign-fleet-plan-v1"
            && fleet["first_epoch"] == first
            && fleet["last_epoch"] == last
            && fleet["observer"]["path"].as_str() == p.previous_observer.path.to_str()
            && fleet["observer"]["sha256"] == p.previous_observer.sha256
            && (fleet["admission_transition_guard"].is_null()
                || prefix157::transition_template(p, fleet)?
                || prefix144::transition_template(p, fleet)?
                || native144::transition_template(p, fleet)?
                || continuation144::transition_template(p, fleet)?
                || assembly144::transition_template(p, fleet)?),
        "fleet template scope or transition mismatch"
    );
    ensure!(
        estimates["schema"] == "jetstreamer-horizon-r2-status-estimates-v5"
            && estimates["model_sha256"] == p.model_template.sha256
            && estimates["observer_sha256"] == p.previous_observer.sha256
            && estimates["sampled_at_utc"] == old_time,
        "estimate predecessor mismatch"
    );
    let mut epochs = BTreeSet::new();
    for range in model["ranges"].as_array().context("model ranges missing")? {
        ensure!(
            range.get("elapsed_execution_millis").is_none(),
            "manual elapsed values are forbidden"
        );
        for e in range["epochs"].as_array().context("model epochs missing")? {
            let e = e.as_u64().context("invalid model epoch")?;
            ensure!(
                (first..=last).contains(&e) && epochs.insert(e),
                "overlapping or out-of-scope epoch"
            );
        }
    }
    if p.epoch198_delivery.is_some() {
        ensure!(
            host101 && !p.expected_epochs.contains(&198),
            "foreign198 delivery census"
        );
        epochs.remove(&198);
    }
    if p.epoch160_delivery.is_some() {
        ensure!(
            host101 && !p.expected_epochs.contains(&160),
            "foreign160 delivery census"
        );
        epochs.remove(&160);
    }
    if p.runtime_handoff157.is_some() {
        runtime157::validate(p)?;
        epochs.remove(&157);
    }
    prefix157::validate(p)?;
    prefix144::validate(p)?;
    completed144::validate(p)?;
    native144::validate(p)?;
    continuation144::validate(p)?;
    assembly144::validate(p)?;
    native141::validate(p)?;
    assembly144_scans::validate(p)?;
    publication144::validate(p)?;
    ensure!(
        p.expected_epochs.iter().copied().collect::<BTreeSet<_>>() == epochs
            && p.expected_epochs.len() == epochs.len()
            && !epochs.is_empty(),
        "explicit cycle epoch census differs"
    );
    for (epoch, evidence) in &p.additional_gate_evidence {
        let n = epoch.parse::<u64>()?;
        ensure!(
            (first..=last).contains(&n)
                && n.to_string() == *epoch
                && fleet["gates"][epoch]["evidence"].is_array()
                && !evidence.is_empty(),
            "invalid additional gate evidence"
        );
    }
    ensure!(
        p.estimate_output.parent().and_then(Path::to_str)
            == model["estimate_receipt_directory"].as_str(),
        "estimate output parent differs"
    );
    let expected_cycle = if host101 {
        Path::new("/var/lib/jetstreamer/horizon-routine-cycles-101-200-v2").join(format!(
            "{}-{}",
            stamp(&p.sample_target_utc),
            generation_101(p)
        ))
    } else {
        Path::new("/var/lib/jetstreamer/horizon-routine-cycles-v1")
            .join(format!("{}-v1", stamp(&p.sample_target_utc)))
    };
    ensure!(
        p.cycle_directory == expected_cycle,
        "cycle path is outside bounded namespace"
    );
    let expected_fleet_output = if host101 {
        Path::new(FLEET_ROOT_101).join(format!("fleet-{}.json", stamp(&p.sample_target_utc)))
    } else {
        Path::new("/var/lib/jetstreamer/horizon-campaign-fleet")
            .join(format!("{}-rust-v1", stamp(&p.sample_target_utc)))
            .join("fleet-ledger.json")
    };
    ensure!(
        p.fleet_output == expected_fleet_output,
        "fleet output mismatch"
    );
    if host101 {
        ensure!(
            model["status_receipt_directory"]
                == "/home/sol/.jetstreamer-private/r2-status-receipts"
                && model["status_receipt_directory_uid"] == 1001,
            "wrong101status reader/directory ownership policy"
        );
    }
    ensure!(
        p.estimate_output.file_name().and_then(|s| s.to_str())
            == Some(&format!(
                "horizon-r2-status-estimates-{}-cohort-gated-v5.json",
                stamp(&p.sample_target_utc)
            )),
        "estimate output mismatch"
    );
    Ok(())
}

fn validate_observation(p: &Plan, model: &Value, observer: &Value, now: u64) -> Result<()> {
    let target = utc_seconds(&p.sample_target_utc)?;
    ensure!(
        target <= now && now - target <= 1800,
        "cycle observation is stale or future"
    );
    ensure!(
        observer["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && observer["recorded_at_utc"] == p.sample_target_utc
            && observer["cadence"]["previous_sample"].as_str() == p.previous_observer.path.to_str()
            && observer["cadence"]["previous_sample_sha256"] == p.previous_observer.sha256
            && observer["cadence"]["routine_minimum_interval_enforced"] == true
            && observer["cadence"]["minimum_interval_seconds"] == 1800
            && observer["cadence"]["previous_sample_recorded_at_utc"] == model["sample_target_utc"]
            && observer["cadence"]["observed_interval_seconds"]
                .as_u64()
                .is_some_and(|n| n >= 1800)
            && observer["cadence"]["observation_reason"] == "routine",
        "observer scope, cadence or predecessor mismatch"
    );
    let observed = observer["replays"]
        .as_array()
        .context("observer census missing")?;
    let modeled = model["ranges"].as_array().context("model census missing")?;
    ensure!(
        observed.len()
            == modeled.len()
                + p.scope_101_200
                    .as_ref()
                    .map_or(0, |s| if s.private144_observer {
                        0
                    } else {
                        s.diagnostic_ranges.len()
                    }),
        "ordinary claim census changed"
    );
    for m in modeled {
        let matches: Vec<_> = observed
            .iter()
            .filter(|r| r["range"] == m["range"])
            .collect();
        ensure!(
            matches.len() == 1,
            "ordinary range is missing or duplicated"
        );
        let r = matches[0];
        ensure!(
            r["invocation_binding_stable"] == true,
            "observer identities are unstable"
        );
        for (kind, field) in [
            ("controller", "expected_controller_invocation_id"),
            ("producer", "expected_producer_invocation_id"),
        ] {
            for point in ["before", "after"] {
                let v = &r[format!("{kind}_{point}")];
                ensure!(
                    v["invocation_id"] == m[field]
                        && v["restarts"] == 0
                        && v["active_state"] == "active",
                    "ordinary owner changed or stopped"
                );
            }
        }
        ensure!(
            r["useful_work"]["last"]["terminal_slot"] == m["terminal_slot"],
            "epoch terminal changed; require reviewed model handoff"
        );
    }
    validate_diagnostics(p, model, observer, true)?;
    Ok(())
}

fn validate_diagnostics(p: &Plan, model: &Value, value: &Value, observed: bool) -> Result<()> {
    is_101(p)?;
    let Some(scope) = &p.scope_101_200 else {
        return Ok(());
    };
    if scope.private144_observer {
        return private144::validate(p, model, value, observed);
    }
    for d in &scope.diagnostic_ranges {
        ensure!(
            !model["ranges"]
                .as_array()
                .context("model ranges")?
                .iter()
                .any(|r| r["range"] == d.range)
                && !p.expected_epochs.contains(&144),
            "private diagnostic cannot publish production ETA"
        );
        let matches: Vec<_> = value["replays"]
            .as_array()
            .context("diagnostic census")?
            .iter()
            .filter(|r| r["range"] == d.range)
            .collect();
        ensure!(matches.len() == 1, "diagnostic owner missing or duplicate");
        let r = matches[0];
        if observed {
            ensure!(
                r["invocation_binding_stable"] == true,
                "diagnostic identity unstable"
            );
            for (kind, id) in [
                ("controller", &d.expected_controller_invocation_id),
                ("producer", &d.expected_producer_invocation_id),
            ] {
                for point in ["before", "after"] {
                    let v = &r[format!("{kind}_{point}")];
                    ensure!(
                        v["invocation_id"] == *id
                            && v["restarts"] == 0
                            && matches!(v["active_state"].as_str(), Some("active" | "activating")),
                        "diagnostic owner changed/stopped"
                    );
                }
            }
        } else {
            ensure!(
                r["controller_unit"] == d.controller_unit
                    && r["producer_unit"] == d.producer_unit
                    && r["expected_controller_invocation_id"]
                        == d.expected_controller_invocation_id
                    && r["expected_producer_invocation_id"] == d.expected_producer_invocation_id,
                "diagnostic configured identity differs"
            );
        }
    }
    Ok(())
}

fn validate_observer_config(p: &Plan, model: &Value, config: &Value) -> Result<()> {
    ensure!(
        config["schema"] == "jetstreamer-horizon-live-resource-sample-config-v2"
            && config["output"].as_str() == p.observer.to_str()
            && config["not_before_utc"] == p.sample_target_utc
            && config["minimum_interval_seconds"] == 1800
            && config["previous_sample"].as_str() == p.previous_observer.path.to_str()
            && (config["observation_reason"].is_null()
                || config["observation_reason"] == "routine"),
        "scheduled observer config differs from the pinned routine scope"
    );
    let ranges = config["replays"]
        .as_array()
        .context("configured replay census missing")?;
    let modeled = model["ranges"].as_array().context("model census missing")?;
    ensure!(
        ranges.len()
            == modeled.len()
                + p.scope_101_200
                    .as_ref()
                    .map_or(0, |s| if s.private144_observer {
                        0
                    } else {
                        s.diagnostic_ranges.len()
                    }),
        "scheduled observer census changed"
    );
    for m in modeled {
        let found: Vec<_> = ranges.iter().filter(|r| r["range"] == m["range"]).collect();
        ensure!(
            found.len() == 1,
            "scheduled observer range is missing or duplicate"
        );
        for field in [
            "expected_controller_invocation_id",
            "expected_producer_invocation_id",
        ] {
            ensure!(
                found[0][field] == m[field],
                "scheduled observer owner differs"
            );
        }
    }
    validate_diagnostics(p, model, config, false)?;
    Ok(())
}

const INCIDENT_225_SHA: &str = "fc51f75a6424fe41b0aaca503279f0e8a29a457c87c83579227c863e47101916";
const STALE_225_ACTION_SHA: &str =
    "31b7234d02f074a61910c8f0bd99553990af2ed24788fc5d36c07f9ed9bc78ca";
const CORRECTED_225_ACTION: &str = "Keep epoch225 repair open after the exact reserve stop ac9aee3d47eb41e483a5e008ed43d030. The parent already reclaimed material scratch; only8192B scaffolding remains. No scratch deletion or new retirement tool is needed or authorized. Preserve the20.2GiB partial archive, immutable bootstrap/genesis, guard chain and failed unit. Qualify a fresh admissible recovery resource envelope before any restart; require natural parent success at the canonical root, independent full/current-plugin verification and separate225-only publication gates. The226diagnostic tail remains private. No automatic restart, newdiskadmission, canonicalsidecar, runtimepromotion or publication is authorized by this narrative correction.";

/// Correct exactly one known stale task, not arbitrary gates or repair state.
/// The immutable predecessor is retained and the incident stays open.
fn correct_stale_225_action(fleet: &mut Value, evidence: &Bound, incident: &Value) -> Result<bool> {
    if evidence.sha256 != INCIDENT_225_SHA
        || evidence.path
            != Path::new(
                "/var/lib/jetstreamer/horizon-225-reserve-stop-incident-20261021-v1/incident.json",
            )
        || fleet["gates"]["225"]["state"] != "failed-needs-repair"
        || fleet["gates"]["225"]["next_action"]
            .as_str()
            .map(|s| sha(s.as_bytes()))
            .as_deref()
            != Some(STALE_225_ACTION_SHA)
    {
        return Ok(false);
    }
    ensure!(
        incident["schema"] == "jetstreamer-private-epoch225-reserve-stop-incident-v1"
            && incident["epoch"] == 225
            && incident["producer_invocation_id"] == "ac9aee3d47eb41e483a5e008ed43d030"
            && incident["scratch"]["observed_physical_bytes_after_parent_exit"] == 8192
            && incident["archive_deletion_authorized"] == false
            && incident["scratch_deletion_authorized"] == false
            && incident["replay_launch_authorized"] == false
            && incident["publication_authorized"] == false
            && incident["remote_mutations"] == false
            && incident["r2_mutations"] == false,
        "bound225incident does not support the non-destructive task correction"
    );
    fleet["gates"]["225"]["next_action"] = json!(CORRECTED_225_ACTION);
    Ok(true)
}

const INCIDENT_203_SHA: &str = "216f090a859f5136c131e43ae378da6646c16b32b982f5d5ee39474f67a866dc";
const INCIDENT_203_PATH: &str =
    "/var/lib/jetstreamer/horizon-203-reserve-stop-incident-20261021-v1/incident.json";
const STALE_203_ACTION_SHA: &str =
    "9ae0af8421923b885d590d795614bd6308cd874c6289a91e5da716d0e4e2c35a";

/// Record one independently retained terminal capacity incident. This changes
/// only its stale task/state; it cannot grant cleanup, retry or publication.
fn record_exact_203_stop(fleet: &mut Value, evidence: &Bound, incident: &Value) -> Result<bool> {
    if evidence.sha256 != INCIDENT_203_SHA || evidence.path != Path::new(INCIDENT_203_PATH) {
        return Ok(false);
    }
    ensure!(
        incident["schema"] == "jetstreamer-private-epoch203-reserve-stop-incident-v1"
            && incident["epoch"] == 203
            && incident["producer_invocation_id"] == "92e367eb7cf944a1825fe5a20d9243ca"
            && incident["producer_unit"] == "horizon-qualify-203-root-prefix-resource-v1.service"
            && incident["guard_invocation_id"] == "3ff59266284844d18f15b2978714e187"
            && incident["guard_stop_reason"] == "filesystem-floor"
            && incident["failure_error"] == "external signal"
            && incident["failure_external_signal"] == 15
            && incident["last_progress_slot"] == 88_036_553u64
            && incident["required_terminal_slot"] == 88_127_580u64
            && incident["producer_terminal"]["main_pid"] == 0
            && incident["producer_terminal"]["restarts"] == 0
            && incident["producer_terminal"]["active_state"] == "failed"
            && incident["producer_terminal"]["exec_main_status"] == 1
            && incident["partial_archive"]["preserve"] == true
            && incident["partial_archive"]["complete_archive"] == false
            && incident["repair_closed"] == false,
        "bound203incident does not establish the exact terminal capacity stop"
    );
    for field in [
        "archive_deletion_authorized",
        "scratch_deletion_authorized",
        "replay_launch_authorized",
        "runtime_promotion_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
        "natural_parent_success",
        "canonical_root_reached",
        "independent_prefix_qualified",
    ] {
        ensure!(
            incident[field] == false,
            "203incident grants unrelated authority: {field}"
        );
    }
    let next = incident["next_action"]
        .as_str()
        .context("203repair action missing")?;
    ensure!(!next.trim().is_empty(), "203repair action empty");
    if fleet["gates"]["203"]["state"] == "failed-needs-repair"
        && fleet["gates"]["203"]["next_action"] == next
    {
        return Ok(false);
    }
    if fleet["gates"]["203"]["state"] != "blocked-qualification"
        || fleet["gates"]["203"]["next_action"]
            .as_str()
            .map(|s| sha(s.as_bytes()))
            .as_deref()
            != Some(STALE_203_ACTION_SHA)
    {
        return Ok(false);
    }
    fleet["gates"]["203"]["state"] = json!("failed-needs-repair");
    fleet["gates"]["203"]["next_action"] = json!(next);
    Ok(true)
}

const OCT22_ACTION_REVIEW_SHA: &str =
    "2b9df8cb36a4b0d4a939fcad5ea121298743ea8d5ad0f42ccb5e6cf91a789d64";
const OCT22_ACTION_REVIEW_PATH: &str =
    "/var/lib/jetstreamer/horizon-fleet-next-action-review-20261022T1540Z-v1/review.json";
const OCT22_ACTION_REVIEW: &str = include_str!("fixtures/fleet-action-review-20261022.json");

/// A fixed narrative-only transition applied after authenticating the original
/// predecessor template. Never substitute a template or rewrite prior receipts.
fn correct_oct22_action(
    fleet: &mut Value,
    epoch: &str,
    evidence: &Bound,
    review: &Value,
) -> Result<bool> {
    if !matches!(epoch, "203" | "205" | "227")
        || evidence.sha256 != OCT22_ACTION_REVIEW_SHA
        || evidence.path != Path::new(OCT22_ACTION_REVIEW_PATH)
    {
        return Ok(false);
    }
    let expected: Value = serde_json::from_str(OCT22_ACTION_REVIEW)?;
    ensure!(
        sha(OCT22_ACTION_REVIEW.as_bytes()) == OCT22_ACTION_REVIEW_SHA && review == &expected,
        "Oct22 action review differs from the exact non-authorizing correction"
    );
    let gate = &fleet["gates"][epoch];
    let eligible = gate["state"] == "blocked-qualification"
        || (epoch == "203" && gate["state"] == "failed-needs-repair");
    if !eligible || gate["next_action"] != review["changes"][epoch]["old_next_action"] {
        // Preserve idempotent results, newer reviews, and every operational state.
        return Ok(false);
    }
    fleet["gates"][epoch]["next_action"] = review["changes"][epoch]["new_next_action"].clone();
    Ok(true)
}

fn apply_known_action_corrections(p: &Plan, fleet: &mut Value) -> Result<()> {
    for epoch in ["203", "205", "227"] {
        if let Some(evidence) = p.additional_gate_evidence.get(epoch) {
            for e in evidence
                .iter()
                .filter(|e| e.sha256 == OCT22_ACTION_REVIEW_SHA)
            {
                correct_oct22_action(fleet, epoch, e, &bound_json(e, true)?)?;
            }
        }
    }
    if let Some(evidence) = p.additional_gate_evidence.get("203") {
        for e in evidence.iter().filter(|e| e.sha256 == INCIDENT_203_SHA) {
            record_exact_203_stop(fleet, e, &bound_json(e, false)?)?;
        }
    }
    if let Some(evidence) = p.additional_gate_evidence.get("225") {
        for e in evidence.iter().filter(|e| e.sha256 == INCIDENT_225_SHA) {
            correct_stale_225_action(fleet, e, &bound_json(e, false)?)?;
        }
    }
    Ok(())
}

fn derive(p: &Plan, model: &Value, fleet: &Value, observer: &Bound) -> Result<(Value, Value)> {
    let mut model = model.clone();
    let mut fleet = fleet.clone();
    model["sample_target_utc"] = json!(p.sample_target_utc);
    if is_101(p)? {
        let evidence = model["evidence"].as_array_mut().context("model evidence")?;
        for binding in [&p.previous_estimates, observer] {
            let value = serde_json::to_value(binding)?;
            if !evidence.contains(&value) {
                evidence.push(value);
            }
        }
    } else {
        model["evidence"][0] = serde_json::to_value(&p.previous_estimates)?;
        model["evidence"][1] = serde_json::to_value(observer)?;
    }
    fleet["observer"] = serde_json::to_value(observer)?;
    fleet["previous_fleet"] = serde_json::to_value(&p.previous_fleet)?;
    fleet["output"] = json!(p.fleet_output);
    if let Some(scope) = &p.scope_101_200
        && !scope.additional_tracked_units.is_empty()
    {
        let tracked = fleet["tracked_units"]
            .as_array_mut()
            .context("missing tracked-unit template census")?;
        for unit in &scope.additional_tracked_units {
            let value = json!(unit);
            if !tracked.contains(&value) {
                tracked.push(value);
            }
        }
    }
    for (epoch, evidence) in &p.additional_gate_evidence {
        let entries = fleet["gates"][epoch]["evidence"]
            .as_array_mut()
            .context("gate evidence missing")?;
        for e in evidence {
            let e = serde_json::to_value(e)?;
            if !entries.contains(&e) {
                entries.push(e);
            }
        }
    }
    apply_known_action_corrections(p, &mut fleet)?;
    delivery198::derive_fleet(p, &mut fleet)?;
    delivery160::derive_fleet(p, &mut fleet)?;
    public198::derive_fleet(p, &mut fleet)?;
    runtime157::derive_fleet(p, &mut fleet)?;
    prefix157::derive_fleet(p, &mut fleet)?;
    prefix144::derive_fleet(p, &mut fleet)?;
    completed144::derive_fleet(p, &mut fleet)?;
    native144::derive_fleet(p, &mut fleet)?;
    continuation144::derive_fleet(p, &mut fleet)?;
    native141::derive_fleet(p, &mut fleet)?;
    assembly144_scans::derive_fleet(p, &mut fleet)?;
    publication144::derive_fleet(p, &mut fleet)?;
    Ok((model, fleet))
}

fn record_child_output(
    tool: &Bound,
    output: &std::process::Output,
    receipt_path: &Path,
) -> Result<()> {
    record_child_output_with(tool, output, receipt_path, write_new)
}

fn record_child_output_with(
    tool: &Bound,
    output: &std::process::Output,
    receipt_path: &Path,
    persist: impl FnOnce(&Path, &Value) -> Result<Bound>,
) -> Result<()> {
    use std::os::unix::process::ExitStatusExt;
    const OUTPUT_LIMIT: usize = 1 << 20;
    let stream = |bytes: &[u8]| {
        json!({"length":bytes.len(),"sha256":sha(bytes),
            "truncated":bytes.len()>OUTPUT_LIMIT,
            "text":String::from_utf8_lossy(&bytes[..bytes.len().min(OUTPUT_LIMIT)])})
    };
    // Preserve bounded private diagnostics before rejecting a failed child.
    // Never record the inherited environment (which may contain R2 credentials).
    persist(
        receipt_path,
        &json!({"schema":"jetstreamer-horizon-routine-child-result-v1",
            "tool":tool,"exit_code":output.status.code(),"signal":output.status.signal(),
            "success":output.status.success(),"stdout":stream(&output.stdout),
            "stderr":stream(&output.stderr),"automatic_retry_authorized":false,
            "replay_launch_authorized":false,"archive_mutations_authorized":false}),
    )?;
    ensure!(
        output.status.success(),
        "bound child {} failed with {}; private result: {}",
        tool.path.display(),
        output.status,
        receipt_path.display()
    );
    ensure!(
        output.stdout.len() <= OUTPUT_LIMIT && output.stderr.len() <= OUTPUT_LIMIT,
        "oversized child output; private result: {}",
        receipt_path.display()
    );
    Ok(())
}

fn child(tool: &Bound, args: &[String], credentials: bool, receipt_path: &Path) -> Result<()> {
    tool_ok(tool)?;
    let mut cmd = Command::new(&tool.path);
    cmd.args(args).stdin(Stdio::null());
    if !credentials {
        for key in [
            "HORIZON_S3_ENDPOINT",
            "HORIZON_ACCESS_KEY_ID",
            "HORIZON_SECRET_ACCESS_KEY",
        ] {
            cmd.env_remove(key);
        }
    }
    // The enclosing non-restarting oneshot owns the bounded runtime and kills
    // only this metadata tool tree; no replay belongs to its cgroup.
    let output = cmd
        .output()
        .with_context(|| format!("failed to execute bound child {}", tool.path.display()))?;
    record_child_output(tool, &output, receipt_path)
}

fn validate_service(
    properties: &BTreeMap<String, String>,
    unit: &str,
    invocation: &str,
    pid: u32,
) -> Result<()> {
    ensure!(
        invocation.len() == 32
            && invocation
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid invocation ID"
    );
    for (key, value) in [
        ("Id", unit),
        ("InvocationID", invocation),
        ("NRestarts", "0"),
        ("Restart", "no"),
        ("KillMode", "control-group"),
        ("Delegate", "no"),
        ("Type", "oneshot"),
        ("TimeoutStartUSec", "10min"),
    ] {
        ensure!(
            properties.get(key).is_some_and(|v| v == value),
            "routine service property {key} differs"
        );
    }
    ensure!(
        properties.get("MainPID") == Some(&pid.to_string())
            && properties
                .get("ActiveState")
                .is_some_and(|v| v == "activating" || v == "active"),
        "not the exact active routine service"
    );
    Ok(())
}

fn authenticate_service(p: &Plan) -> Result<String> {
    ensure!(p.cycle_unit == cycle_unit(p)?, "routine unit name mismatch");
    authenticate_named_service(&p.cycle_unit)
}
fn authenticate_named_service(unit: &str) -> Result<String> {
    let invocation = env::var("INVOCATION_ID")
        .context("actual cycle requires its bounded persistent oneshot")?;
    let output=Command::new("/usr/bin/systemctl").args(["show",unit,"--no-pager","--no-ask-password",
        "--property=Id,InvocationID,MainPID,NRestarts,Restart,KillMode,Delegate,ActiveState,Type,TimeoutStartUSec"]).output()?;
    ensure!(
        output.status.success() && output.stdout.len() < 16384,
        "cannot authenticate routine service"
    );
    let mut fields = BTreeMap::new();
    for line in std::str::from_utf8(&output.stdout)?.lines() {
        let (key, value) = line.split_once('=').context("malformed service property")?;
        ensure!(
            fields.insert(key.into(), value.into()).is_none(),
            "duplicate service property"
        );
    }
    validate_service(&fields, unit, &invocation, std::process::id())?;
    Ok(invocation)
}

fn verify_estimates(
    p: &Plan,
    model: &Value,
    observer: &Bound,
    estimates: &Value,
) -> Result<Vec<Value>> {
    ensure!(
        estimates["schema"] == "jetstreamer-horizon-r2-status-estimates-v5"
            && estimates["observer_sha256"] == observer.sha256
            && estimates["sampled_at_utc"] == p.sample_target_utc,
        "new estimates are unbound"
    );
    let entries = estimates["estimates"]
        .as_array()
        .context("estimates missing")?;
    let mut seen = BTreeSet::new();
    for e in entries {
        let n = e["epoch"].as_u64().context("estimate epoch missing")?;
        ensure!(
            p.expected_epochs.contains(&n) && seen.insert(n),
            "unexpected or duplicate estimate epoch"
        );
        let m = model["ranges"]
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["epochs"].as_array().unwrap().contains(&json!(n)))
            .context("estimate range missing")?;
        for field in [
            "archive_directory",
            "expected_controller_invocation_id",
            "expected_producer_invocation_id",
        ] {
            ensure!(e[field] == m[field], "estimate owner or directory changed");
        }
        ensure!(
            e["elapsed_execution_millis"].as_u64().is_some()
                && e["estimated_remaining_millis"]
                    .as_u64()
                    .is_some_and(|n| n > 0),
            "invalid estimate integers"
        );
    }
    ensure!(
        seen.len() == p.expected_epochs.len(),
        "estimate census incomplete"
    );
    Ok(entries.clone())
}

fn execute(p: &Plan, plan_bound: &Bound, self_sha: &str, check_only: bool) -> Result<()> {
    let model = bound_json(&p.model_template, true)?;
    let fleet = bound_json(&p.fleet_template, true)?;
    let previous = bound_json(&p.previous_fleet, false)?;
    let estimates = bound_json(&p.previous_estimates, false)?;
    let old_observer = bound_json(&p.previous_observer, false)?;
    validate_templates(p, &model, &fleet, &previous, &estimates, &old_observer)?;
    terminal_handoff::preflight(p, &model)?;
    let model = private144::effective_model(
        p,
        &delivery160::effective_model(
            p,
            &delivery198::effective_model(p, &controller_recovery::model(p, &model)?)?,
        )?,
    )?;
    latest_fleet_unchanged(p, &previous)?;
    validate_observer_config(p, &model, &bound_json(&p.observer_config, true)?)?;
    for t in [&p.tools.sealer, &p.tools.estimator, &p.tools.r2] {
        tool_ok(t)?;
    }
    for values in p.additional_gate_evidence.values() {
        for b in values {
            bound_json(b, false)?;
        }
    }
    // Validate the exact correction evidence during check-only as well; this
    // is an in-memory preview, not a new fleet receipt or resource poll.
    apply_known_action_corrections(p, &mut fleet.clone())?;
    delivery198::derive_fleet(p, &mut fleet.clone())?;
    delivery160::derive_fleet(p, &mut fleet.clone())?;
    runtime157::derive_fleet(p, &mut fleet.clone())?;
    prefix157::derive_fleet(p, &mut fleet.clone())?;
    prefix144::derive_fleet(p, &mut fleet.clone())?;
    completed144::derive_fleet(p, &mut fleet.clone())?;
    native144::derive_fleet(p, &mut fleet.clone())?;
    continuation144::derive_fleet(p, &mut fleet.clone())?;
    native141::derive_fleet(p, &mut fleet.clone())?;
    assembly144_scans::derive_fleet(p, &mut fleet.clone())?;
    publication144::derive_fleet(p, &mut fleet.clone())?;
    private_dir(p.cycle_directory.parent().context("cycle parent missing")?)?;
    private_dir(
        p.estimate_output
            .parent()
            .context("estimate parent missing")?,
    )?;
    let status_path = Path::new(
        model["status_receipt_directory"]
            .as_str()
            .context("status receipt parent missing")?,
    );
    if is_101(p)? {
        let m = fs::symlink_metadata(status_path)?;
        ensure!(
            status_path.canonicalize()? == status_path
                && m.is_dir()
                && m.uid() == 1001
                && m.mode() & 0o6077 == 0,
            "unsafe101status receipt directory"
        );
    } else {
        private_dir(status_path)?;
    }
    absent(&p.cycle_directory)?;
    absent(&p.estimate_output)?;
    absent(&p.fleet_output)?;
    let endpoint = env::var("HORIZON_S3_ENDPOINT").context("storage endpoint missing")?;
    ensure!(
        sha(endpoint.as_bytes()) == p.endpoint_sha256
            && endpoint
                .trim_end_matches('/')
                .ends_with(&format!("/{BUCKET}")),
        "storage endpoint scope differs"
    );
    for key in ["HORIZON_ACCESS_KEY_ID", "HORIZON_SECRET_ACCESS_KEY"] {
        ensure!(
            env::var(key).is_ok_and(|v| !v.is_empty()),
            "storage credential missing"
        );
    }
    if check_only {
        // A scheduled sample may already exist after an early metadata-only
        // rejection. Validate it without taking another resource observation
        // or claiming the cycle, before a reviewed recovery invocation.
        if p.observer.try_exists()? {
            let observed: Value =
                serde_json::from_slice(&read_checked(&p.observer, LIMIT, 0, false)?)?;
            let checked = terminal_handoff::for_observation(p, &model, &observed)?;
            let checked = cohort191::for_observation(p, &checked, &observed)?;
            validate_observation(
                p,
                &checked,
                &observed,
                SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            )?;
        }
        println!("routine cycle preflight passed; no sampling, remote access or mutation");
        return Ok(());
    }
    let invocation = authenticate_service(p)?;
    let bytes = read_checked(&p.observer, LIMIT, 0, false)?;
    let observer = Bound {
        path: p.observer.clone(),
        sha256: sha(&bytes),
    };
    let observed: Value = serde_json::from_slice(&bytes)?;
    // Keep the genuine predecessor intact. Only an explicitly qualified,
    // manifest-bound runtime transition may change the next derived model.
    let model = terminal_handoff::for_observation(p, &model, &observed)?;
    let model = cohort191::for_observation(p, &model, &observed)?;
    validate_observation(
        p,
        &model,
        &observed,
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    )?;
    fs::create_dir(&p.cycle_directory)?;
    fs::set_permissions(&p.cycle_directory, fs::Permissions::from_mode(0o700))?;
    File::open(p.cycle_directory.parent().unwrap())?.sync_all()?;
    write_new(
        &p.cycle_directory.join("intent.json"),
        &json!({"schema":"jetstreamer-horizon-routine-cycle-intent-v1",
        "plan":plan_bound,"self_sha256":self_sha,"observer":observer,"sampled_at_utc":p.sample_target_utc,"invocation_id":invocation,
        "replay_launch_authorized":false,"archive_mutations":false}),
    )?;
    let result = (|| -> Result<Value> {
        let (model, fleet) = derive(p, &model, &fleet, &observer)?;
        let model_source = write_new(&p.cycle_directory.join("model-source.json"), &model)?;
        let fleet_source = write_new(&p.cycle_directory.join("fleet-source.json"), &fleet)?;
        let sealed = p.cycle_directory.join("sealed");
        let seal_plan = write_new(
            &p.cycle_directory.join("seal-plan.json"),
            &json!({"schema":"jetstreamer-sealed-deployment-plan-v1",
            "destination":sealed,"members":[{"source":model_source.path,"name":"eta-model.json","sha256":model_source.sha256,"mode":292},
            {"source":fleet_source.path,"name":"fleet-plan.json","sha256":fleet_source.sha256,"mode":292}]}),
        )?;
        child(
            &p.tools.sealer,
            &[
                seal_plan.path.display().to_string(),
                "--plan-sha256".into(),
                seal_plan.sha256,
                "--self-sha256".into(),
                p.tools.sealer.sha256.clone(),
            ],
            false,
            &p.cycle_directory.join("child-sealer.json"),
        )?;
        let model_bound = Bound {
            path: sealed.join("eta-model.json"),
            sha256: model_source.sha256,
        };
        let fleet_bound = Bound {
            path: sealed.join("fleet-plan.json"),
            sha256: fleet_source.sha256,
        };
        bound_json(&model_bound, true)?;
        bound_json(&fleet_bound, true)?;
        child(
            &p.tools.estimator,
            &[
                "--model".into(),
                model_bound.path.display().to_string(),
                "--model-sha256".into(),
                model_bound.sha256.clone(),
                "--observer".into(),
                observer.path.display().to_string(),
                "--observer-sha256".into(),
                observer.sha256.clone(),
                "--self-sha256".into(),
                p.tools.estimator.sha256.clone(),
                "--output".into(),
                p.estimate_output.display().to_string(),
            ],
            false,
            &p.cycle_directory.join("child-estimator.json"),
        )?;
        let bytes = read_checked(&p.estimate_output, LIMIT, 0, false)?;
        let new_estimates: Value = serde_json::from_slice(&bytes)?;
        ensure!(
            new_estimates["model_sha256"] == model_bound.sha256,
            "new estimate model mismatch"
        );
        let entries = verify_estimates(p, &model, &observer, &new_estimates)?;
        let estimate_bound = Bound {
            path: p.estimate_output.clone(),
            sha256: sha(&bytes),
        };
        let status_dir = Path::new(
            model["status_receipt_directory"]
                .as_str()
                .context("status parent missing")?,
        );
        let mut receipts = Vec::new();
        let digits: String = p
            .sample_target_utc
            .chars()
            .filter(char::is_ascii_digit)
            .collect();
        for e in entries {
            let epoch = e["epoch"].as_u64().unwrap();
            let string = |key: &str| -> Result<String> {
                Ok(e[key]
                    .as_str()
                    .context("estimate string missing")?
                    .to_string())
            };
            child(
                &p.tools.r2,
                &[
                    "status-publish".into(),
                    string("archive_directory")?,
                    "--epochs".into(),
                    format!("{epoch}-{epoch}"),
                    "--receipt-directory".into(),
                    status_dir.display().to_string(),
                    "--observer-receipt".into(),
                    observer.path.display().to_string(),
                    "--observer-sha256".into(),
                    observer.sha256.clone(),
                    "--expected-controller-invocation-id".into(),
                    string("expected_controller_invocation_id")?,
                    "--expected-producer-invocation-id".into(),
                    string("expected_producer_invocation_id")?,
                    "--elapsed-execution-millis".into(),
                    e["elapsed_execution_millis"].to_string(),
                    "--estimated-remaining-millis".into(),
                    e["estimated_remaining_millis"].to_string(),
                    "--phase".into(),
                    "replay".into(),
                ],
                true,
                &p.cycle_directory.join(format!("child-status-{epoch}.json")),
            )?;
            let path = status_dir.join(format!("epoch-{epoch}.status-{digits}.json"));
            let bytes = read_checked(&path, LIMIT, 0, false)?;
            let receipt: Value = serde_json::from_slice(&bytes)?;
            ensure!(
                receipt["epoch"] == epoch
                    && receipt["bucket"] == p.bucket
                    && receipt["schema"]
                        == "jetstreamer-horizon-r2-status-authenticated-publication-receipt-v1"
                    && receipt["key"] == format!("epoch-{epoch}.epoch-status.json")
                    && receipt["status"]["epoch"] == epoch
                    && receipt["status"]["phase"] == "replay"
                    && receipt["controller_invocation_id"]
                        == e["expected_controller_invocation_id"]
                    && receipt["producer_invocation_id"] == e["expected_producer_invocation_id"]
                    && receipt["pipeline_binding"].is_null()
                    && receipt["authenticated_readback"] == true
                    && receipt["observer_receipt"].as_str() == observer.path.to_str()
                    && receipt["observer_receipt_sha256"] == observer.sha256
                    && receipt["status"]["sampled_at_utc"] == p.sample_target_utc
                    && receipt["status"]["elapsed_execution_millis"]
                        == e["elapsed_execution_millis"]
                    && receipt["status"]["estimated_remaining_millis"]
                        == e["estimated_remaining_millis"],
                "status receipt differs from cycle"
            );
            receipts.push(Bound {
                path,
                sha256: sha(&bytes),
            });
        }
        let pipeline = if p.public198_delivery.is_some() {
            public198::publish(p, &fleet, &observer)?
        } else {
            delivery198::publish(p, &model, &fleet, &observer)?
        };
        let publication144_status = publication144::publish(p, &pipeline, &observer)?;
        let delivery160_status = delivery160::publish(p, &pipeline, &observer)?;
        let parent = p.fleet_output.parent().context("fleet parent missing")?;
        if !parent.exists() {
            private_dir(parent.parent().context("fleet ancestor missing")?)?;
            fs::create_dir(parent)?;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
            File::open(parent.parent().unwrap())?.sync_all()?;
        }
        private_dir(parent)?;
        latest_fleet_unchanged(p, &previous)?;
        child(
            &p.tools.r2,
            &[
                "fleet-reconcile".into(),
                fleet_bound.path.display().to_string(),
                "--plan-sha256".into(),
                fleet_bound.sha256.clone(),
            ],
            true,
            &p.cycle_directory.join("child-fleet.json"),
        )?;
        let bytes = read_checked(&p.fleet_output, LIMIT, 0, false)?;
        let ledger: Value = serde_json::from_slice(&bytes)?;
        ensure!(
            ledger["plan_sha256"] == fleet_bound.sha256
                && ledger["observer_sha256"] == observer.sha256
                && ledger["sampled_at_utc"] == p.sample_target_utc,
            "new fleet receipt mismatch"
        );
        ensure!(
            ledger["inventory"]["anomalies"] == 0,
            "fleet reports remote anomalies; operator investigation required"
        );
        Ok(
            json!({"schema":"jetstreamer-horizon-routine-cycle-completion-v1","plan":plan_bound,"self_sha256":self_sha,
            "sampled_at_utc":p.sample_target_utc,"observer":observer,"model":model_bound,"estimates":estimate_bound,"invocation_id":invocation,
            "fleet_plan":fleet_bound,"fleet":{"path":p.fleet_output,"sha256":sha(&bytes)},"status_publications":receipts,
            "inventory":ledger["inventory"],"epoch198_delivery":pipeline,"epoch144_delivery":publication144_status,"epoch160_delivery":delivery160_status,"replay_launch_authorized":false,"archive_mutations":false,
            "sidecar_mutations":false,"deletions":false,"new_resource_samples":0}),
        )
    })();
    match result {
        Ok(value) => {
            let b = write_new(&p.cycle_directory.join("completion.json"), &value)?;
            println!("{}", b.path.display());
            Ok(())
        }
        Err(error) => {
            write_new(
                &p.cycle_directory.join("failure.json"),
                &json!({"schema":"jetstreamer-horizon-routine-cycle-failure-v1",
            "plan":plan_bound,"observer":observer,"error":format!("{error:#}"),"partial_status_publications_possible":true,
            "automatic_retry_authorized":false,"replay_launch_authorized":false,"archive_mutations":false}),
            )?;
            Err(error)
        }
    }
}

// Call only after the strict argument allowlist above. Every accepted prepare
//mode must remain offline; a newly added mode must never fall through to execute.
fn preparation_mode(arg: &str) -> bool {
    arg.starts_with("--prepare-")
}
fn main() {
    let result = (|| -> Result<()> {
        let args: Vec<_> = env::args().collect();
        ensure!(
            (args.len() == 6
                || (args.len() == 10
                    && matches!(
                        args[6].as_str(),
                        "--prepare-next-delivery198"
                            | "--prepare-next-native141-all-acquisition"
                            | "--prepare-next-publication144"
                            | "--prepare-next-native141-rejection"
                            | "--prepare-next-native141-acquisition"
                            | "--prepare-next-assembly144-scans"
                            | "--prepare-next-native198"
                            | "--prepare-next-native144"
                            | "--prepare-next-continuation144"
                            | "--prepare-next-assembly144"
                            | "--publish-native198-event"
                            | "--refresh-native198-launches"
                            | "--prepare-next-prefix157"
                            | "--prepare-next-prefix144"
                            | "--prepare-next-completed144"
                    )
                    && args[8] == "--handoff-sha256")
                || (args.len() == 7
                    && matches!(
                        args[6].as_str(),
                        "--check-only"
                            | "--check-assembly144-scans-recovery"
                            | "--recover-assembly144-scans"
                            | "--check-assembly144-scans-tail"
                            | "--recover-assembly144-scans-tail"
                            | "--recover-delivery198"
                            | "--promote-partial2018"
                            | "--prepare-next"
                            | "--prepare-next-upload198"
                            | "--prepare-next-delivery160"
                            | "--prepare-next-public160"
                            | "--prepare-next-public160-timing"
                            | "--check-public160-upload-timing"
                            | "--prepare-next-assembly144-reader"
                            | "--prepare-next-native141"
                            | "--publish-upload198-event"
                            | "--recover-native144-observer"
                            | "--check-native144-recovery"
                            | "--recover-public160"
                            | "--check-public160-recovery"
                            | "--prepare-next-terminal157"
                            | "--prepare-next-private144"
                            | "--prepare-package-recovery"
                            | "--prepare-runtime157-pause"
                    )))
                && args[2] == "--plan-sha256"
                && args[4] == "--self-sha256",
            "usage: jetstreamer-horizon-routine-cycle PLAN --plan-sha256 HEX --self-sha256 HEX [--check-only|--prepare-next|--prepare-next-terminal157|--prepare-next-private144|--prepare-package-recovery|--prepare-next-delivery198 SPEC --handoff-sha256 HEX]"
        );
        ensure!(
            unsafe { libc::geteuid() } == 0,
            "routine cycle requires root"
        );
        tool_ok(&Bound {
            path: fs::read_link("/proc/self/exe")?,
            sha256: args[5].clone(),
        })?;
        let bound = Bound {
            path: args[1].clone().into(),
            sha256: args[3].clone(),
        };
        let plan: Plan = serde_json::from_slice(&bound_bytes(&bound, true)?)?;
        if args
            .get(6)
            .is_some_and(|a| a == "--check-public160-upload-timing")
        {
            println!("{}", public160_timing::preview(&plan)?);
            return Ok(());
        }
        if args
            .get(6)
            .is_some_and(|a| a == "--recover-public160" || a == "--check-public160-recovery")
        {
            return public160_recovery::run(
                &plan,
                &bound,
                &args[5],
                args[6] == "--check-public160-recovery",
            );
        }
        if args.get(6).is_some_and(|a| {
            matches!(
                a.as_str(),
                "--recover-assembly144-scans"
                    | "--check-assembly144-scans-recovery"
                    | "--check-assembly144-scans-tail"
                    | "--recover-assembly144-scans-tail"
            )
        }) {
            return assembly144_scans_recover::run(
                &plan,
                &bound,
                &args[5],
                args[6] == "--check-assembly144-scans-recovery"
                    || args[6] == "--check-assembly144-scans-tail",
                args[6].ends_with("-tail"),
            );
        }
        if args.get(6).is_some_and(|a| {
            a == "--recover-native144-observer" || a == "--check-native144-recovery"
        }) {
            return native144_recovery::run(
                &plan,
                &bound,
                &args[5],
                args[6] == "--check-native144-recovery",
            );
        }
        if args
            .get(6)
            .is_some_and(|a| a == "--publish-upload198-event")
        {
            return public198::upload_event(&plan, &bound, &args[5]);
        }
        if args
            .get(6)
            .is_some_and(|arg| arg == "--refresh-native198-launches")
        {
            return public198::refresh_managers(
                &plan,
                &Bound {
                    path: args[7].clone().into(),
                    sha256: args[9].clone(),
                },
            );
        }
        if args
            .get(6)
            .is_some_and(|arg| arg == "--publish-native198-event")
        {
            return public198::native_event(
                &plan,
                &bound,
                &Bound {
                    path: args[7].clone().into(),
                    sha256: args[9].clone(),
                },
                &args[5],
            );
        }
        if args
            .get(6)
            .is_some_and(|arg| arg == "--promote-partial2018")
        {
            return public198::promote(&plan, &bound, &args[5]);
        }
        if args
            .get(6)
            .is_some_and(|arg| arg == "--recover-delivery198")
        {
            return delivery198_recover::run(&plan, &bound, &args[5]);
        }
        if args.get(6).is_some_and(|arg| preparation_mode(arg)) {
            let spec = if args.len() == 10 {
                Some(Bound {
                    path: args[7].clone().into(),
                    sha256: args[9].clone(),
                })
            } else {
                None
            };
            return next_preparation::prepare(&plan, &bound, &args[5], &args[6], spec.as_ref());
        }
        execute(&plan, &bound, &args[5], args.len() == 7)
    })();
    if let Err(error) = result {
        eprintln!("routine cycle failed closed: {error:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn accepted_all_target_preparation_cannot_fall_through_to_live_execution() {
        assert!(super::preparation_mode(
            "--prepare-next-native141-all-acquisition"
        ));
        assert!(super::preparation_mode("--prepare-next"));
        assert!(super::preparation_mode("--prepare-package-recovery"));
        for mode in [
            "--check-only",
            "--recover-public160",
            "--publish-upload198-event",
        ] {
            assert!(!super::preparation_mode(mode));
        }
        assert!(
            include_str!("routine_cycle.rs")
                .contains("if args.get(6).is_some_and(|arg| preparation_mode(arg))")
        );
    }
    fn oct22_action_fixture() -> (Bound, Value, Value) {
        let evidence = Bound {
            path: OCT22_ACTION_REVIEW_PATH.into(),
            sha256: OCT22_ACTION_REVIEW_SHA.into(),
        };
        let review: Value = serde_json::from_str(OCT22_ACTION_REVIEW).unwrap();
        let mut fleet = json!({"gates":{},"tracked_units":["preserved-owner"],
            "diagnostics":[{"epoch":203}],"first_epoch":201,"last_epoch":300,
            "previous_fleet":{"path":"preserved-predecessor","sha256":"preserved-digest"}});
        for epoch in ["203", "205", "227"] {
            fleet["gates"][epoch] = json!({"state":"blocked-qualification",
                "next_action":review["changes"][epoch]["old_next_action"],
                "evidence":[{"path":OCT22_ACTION_REVIEW_PATH,"sha256":OCT22_ACTION_REVIEW_SHA}]});
        }
        (evidence, review, fleet)
    }

    #[test]
    fn oct22_action_changes_only_exact_narrative_and_is_idempotent() {
        let (evidence, review, original) = oct22_action_fixture();
        assert_eq!(sha(OCT22_ACTION_REVIEW.as_bytes()), OCT22_ACTION_REVIEW_SHA);
        for epoch in ["203", "205", "227"] {
            let mut fleet = original.clone();
            assert!(correct_oct22_action(&mut fleet, epoch, &evidence, &review).unwrap());
            let mut expected = original.clone();
            expected["gates"][epoch]["next_action"] =
                review["changes"][epoch]["new_next_action"].clone();
            assert_eq!(fleet, expected);
            assert!(!correct_oct22_action(&mut fleet, epoch, &evidence, &review).unwrap());
            assert_eq!(fleet, expected);
        }
    }

    #[test]
    fn oct22_action_rejects_changed_review_without_mutating_fleet() {
        let (evidence, review, original) = oct22_action_fixture();
        for (key, value) in [
            ("launch_authorized", json!(true)),
            ("resource_claims_changed", json!(true)),
            ("remote_mutations", json!(true)),
            ("schema", json!("foreign")),
        ] {
            let mut bad = review.clone();
            bad[key] = value;
            let mut fleet = original.clone();
            assert!(correct_oct22_action(&mut fleet, "205", &evidence, &bad).is_err());
            assert_eq!(fleet, original);
        }
        let mut bad = review;
        bad["changes"]["205"]["new_next_action"] = json!("launch now");
        let mut fleet = original.clone();
        assert!(correct_oct22_action(&mut fleet, "205", &evidence, &bad).is_err());
        assert_eq!(fleet, original);
    }

    #[test]
    fn oct22_action_preserves_foreign_bindings_newer_actions_and_states() {
        let (evidence, review, original) = oct22_action_fixture();
        for epoch in ["203", "205", "227"] {
            for (key, value) in [
                ("next_action", json!("newer reviewed action")),
                ("state", json!("remote-ready")),
                ("state", json!("live-replay")),
                ("state", json!("post-replay-pipeline")),
            ] {
                let mut fleet = original.clone();
                fleet["gates"][epoch][key] = value;
                let before = fleet.clone();
                assert!(!correct_oct22_action(&mut fleet, epoch, &evidence, &review).unwrap());
                assert_eq!(fleet, before);
            }
        }
        let mut foreign = evidence.clone();
        foreign.path = "/foreign/review.json".into();
        let mut fleet = original.clone();
        assert!(!correct_oct22_action(&mut fleet, "205", &foreign, &review).unwrap());
        assert_eq!(fleet, original);
        let mut foreign = evidence.clone();
        foreign.sha256 = "0".repeat(64);
        let mut fleet = original.clone();
        assert!(!correct_oct22_action(&mut fleet, "205", &foreign, &review).unwrap());
        assert!(!correct_oct22_action(&mut fleet, "301", &evidence, &review).unwrap());
        assert_eq!(fleet, original);
    }

    fn incident203_fixture() -> (Bound, Value, Value) {
        let old = "Continue exact guarded natural-root prefix qualification; no independent full prefix or full epoch is qualified yet. Independent native validator now supports literal prefix203filename and no-clobber fsynced private --receipt;6tests passed,source pushed and reader sealed. On natural parent success and exact431581slot segment, freshly admit independent complete reread. No prefix sidecar/public countdown; native restart,419slot suffix,assembly,current plugin and publication remain separate.";
        assert_eq!(sha(old.as_bytes()), STALE_203_ACTION_SHA);
        let evidence = Bound {
            path: INCIDENT_203_PATH.into(),
            sha256: INCIDENT_203_SHA.into(),
        };
        let mut incident = json!({"schema":"jetstreamer-private-epoch203-reserve-stop-incident-v1",
            "epoch":203,"producer_invocation_id":"92e367eb7cf944a1825fe5a20d9243ca",
            "producer_unit":"horizon-qualify-203-root-prefix-resource-v1.service",
            "guard_invocation_id":"3ff59266284844d18f15b2978714e187",
            "guard_stop_reason":"filesystem-floor","failure_error":"external signal",
            "failure_external_signal":15,"last_progress_slot":88036553,"required_terminal_slot":88127580,
            "producer_terminal":{"main_pid":0,"restarts":0,"active_state":"failed","exec_main_status":1},
            "partial_archive":{"preserve":true,"complete_archive":false},
            "repair_closed":false,"next_action":"Retain partial and inputs; qualify exact cleanup and fresh recovery admission."});
        for field in [
            "archive_deletion_authorized",
            "scratch_deletion_authorized",
            "replay_launch_authorized",
            "runtime_promotion_authorized",
            "publication_authorized",
            "remote_mutations",
            "r2_mutations",
            "natural_parent_success",
            "canonical_root_reached",
            "independent_prefix_qualified",
        ] {
            incident[field] = json!(false);
        }
        let fleet = json!({"gates":{"203":{"state":"blocked-qualification","next_action":old,
            "evidence":[{"path":INCIDENT_203_PATH,"sha256":INCIDENT_203_SHA}]},
            "225":{"state":"failed-needs-repair","next_action":"preserve225"}},
            "diagnostics":[{"epoch":203}],"tracked_units":["preserved-failed-unit"]});
        (evidence, incident, fleet)
    }

    #[test]
    fn exact203stop_records_open_repair_without_weakening_other_gates() {
        let (evidence, incident, original) = incident203_fixture();
        let mut fleet = original.clone();
        assert!(record_exact_203_stop(&mut fleet, &evidence, &incident).unwrap());
        let mut expected = original;
        expected["gates"]["203"]["state"] = json!("failed-needs-repair");
        expected["gates"]["203"]["next_action"] = incident["next_action"].clone();
        assert_eq!(fleet, expected);
        assert!(!record_exact_203_stop(&mut fleet, &evidence, &incident).unwrap());
        assert_eq!(fleet, expected);
    }

    #[test]
    fn exact203stop_rejects_wrong_owner_or_any_unrelated_authority() {
        let (evidence, incident, original) = incident203_fixture();
        for (field, value) in [
            ("producer_invocation_id", json!("foreign")),
            ("guard_stop_reason", json!("unknown")),
            ("last_progress_slot", json!(88127580)),
            ("archive_deletion_authorized", json!(true)),
            ("scratch_deletion_authorized", json!(true)),
            ("replay_launch_authorized", json!(true)),
            ("publication_authorized", json!(true)),
            ("r2_mutations", json!(true)),
            ("natural_parent_success", json!(true)),
            ("repair_closed", json!(true)),
        ] {
            let mut bad = incident.clone();
            bad[field] = value;
            let mut fleet = original.clone();
            assert!(record_exact_203_stop(&mut fleet, &evidence, &bad).is_err());
            assert_eq!(fleet, original);
        }
    }

    #[test]
    fn exact203stop_never_rewrites_a_newer_review_or_foreign_binding() {
        let (evidence, incident, original) = incident203_fixture();
        let mut newer = original.clone();
        newer["gates"]["203"]["next_action"] = json!("newer reviewed recovery");
        let before = newer.clone();
        assert!(!record_exact_203_stop(&mut newer, &evidence, &incident).unwrap());
        assert_eq!(newer, before);
        let mut foreign = evidence;
        foreign.path = "/foreign/incident.json".into();
        let mut fleet = original.clone();
        assert!(!record_exact_203_stop(&mut fleet, &foreign, &incident).unwrap());
        assert_eq!(fleet, original);
    }

    #[test]
    fn exact225scratch_task_correction_preserves_all_gates_and_open_repair() {
        use super::*;
        let old = "Reserve guard stopped exact ac9aee3d47eb41e483a5e008ed43d030 at filesystem2019662348288 below protected2019796866159 on2026-10-21T02:31:42Z; terminalexit1 at02:32:04. EOF followed guardSIGINT and is not new canonical divergence. Lastslot97274295; partial20.2GiB archive and retainedinputs preserved. Keeprepair open. Bind guardstopchain and source-review cursor-free bootstrap restart; qualify exact natural225 scratch retirement profile before cleanup. No existing generic/epoch213/singleton profile authorizes this layout. No automatic restart, newdiskadmission,canonicalsidecar,promotionorpublication; natural-parent0/fullspan never reached.";
        assert_eq!(sha(old.as_bytes()), STALE_225_ACTION_SHA);
        let evidence = Bound {
            path:
                "/var/lib/jetstreamer/horizon-225-reserve-stop-incident-20261021-v1/incident.json"
                    .into(),
            sha256: INCIDENT_225_SHA.into(),
        };
        let incident = json!({"schema":"jetstreamer-private-epoch225-reserve-stop-incident-v1","epoch":225,
            "producer_invocation_id":"ac9aee3d47eb41e483a5e008ed43d030",
            "scratch":{"observed_physical_bytes_after_parent_exit":8192},"archive_deletion_authorized":false,
            "scratch_deletion_authorized":false,"replay_launch_authorized":false,"publication_authorized":false,
            "remote_mutations":false,"r2_mutations":false});
        let original = json!({"gates":{"203":{"state":"blocked-qualification"},"225":{
            "state":"failed-needs-repair","next_action":old,"evidence":[{"sha256":INCIDENT_225_SHA}]}},
            "tracked_units":["preserved-failed-unit"],"diagnostics":[{"epoch":203}],"first_epoch":201,"last_epoch":300});
        let mut corrected = original.clone();
        assert!(correct_stale_225_action(&mut corrected, &evidence, &incident).unwrap());
        let mut expected = original.clone();
        expected["gates"]["225"]["next_action"] = json!(CORRECTED_225_ACTION);
        assert_eq!(corrected, expected);
        assert!(!correct_stale_225_action(&mut corrected, &evidence, &incident).unwrap());
        for (key, value) in [
            ("epoch", json!(226)),
            ("producer_invocation_id", json!("foreign")),
            ("scratch_deletion_authorized", json!(true)),
            ("replay_launch_authorized", json!(true)),
        ] {
            let mut bad = incident.clone();
            bad[key] = value;
            let mut fleet = original.clone();
            assert!(correct_stale_225_action(&mut fleet, &evidence, &bad).is_err());
            assert_eq!(fleet, original);
        }
        for (key, value) in [
            ("state", json!("remote-ready")),
            ("next_action", json!("newer reviewed action")),
        ] {
            let mut fleet = original.clone();
            fleet["gates"]["225"][key] = value;
            let before = fleet.clone();
            assert!(!correct_stale_225_action(&mut fleet, &evidence, &incident).unwrap());
            assert_eq!(fleet, before);
        }
    }
    use super::*;

    #[test]
    #[ignore = "requires a sealed root test binary, pinned sealer and private sandbox probe root"]
    fn privileged_real_sealer_child_records_success_and_failures() {
        ensure_root_probe().unwrap();
    }

    fn ensure_root_probe() -> Result<()> {
        ensure!(unsafe { libc::geteuid() } == 0, "probe requires root");
        let root = Path::new("/var/lib/jetstreamer/horizon-routine-child-probes");
        private_dir(root)?;
        let directory = tempfile::Builder::new()
            .prefix("attempt-")
            .tempdir_in(root)?
            .keep();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
        // Keep all positive and negative child evidence; never remove the probe.
        eprintln!("private child probe evidence: {}", directory.display());
        let tool = Bound {
            path: env::var("HORIZON_PROBE_SEALER")?.into(),
            sha256: env::var("HORIZON_PROBE_SEALER_SHA256")?,
        };
        let member = write_new(
            &directory.join("marker.json"),
            &json!({"probe":true,
            "replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false}),
        )?;
        let destination = directory.join("sealed");
        let plan = write_new(
            &directory.join("plan.json"),
            &json!({
            "schema":"jetstreamer-sealed-deployment-plan-v1","destination":destination,
            "members":[{"source":member.path,"name":"marker.json","sha256":member.sha256,"mode":292}]}),
        )?;
        let mut args = vec![
            plan.path.display().to_string(),
            "--plan-sha256".into(),
            "0".repeat(64),
            "--self-sha256".into(),
            tool.sha256.clone(),
        ];
        let negative = directory.join("child-wrong-plan.json");
        ensure!(
            child(&tool, &args, false, &negative).is_err(),
            "wrong digest accepted"
        );
        ensure!(!destination.exists(), "negative probe published deployment");
        let failed: Value = serde_json::from_slice(&fs::read(&negative)?)?;
        ensure!(
            failed["success"] == false
                && failed["stderr"]["length"].as_u64().is_some_and(|n| n > 0),
            "missing private child failure detail"
        );
        args[2] = plan.sha256;
        child(&tool, &args, false, &directory.join("child-success.json"))?;
        ensure!(
            sha(&fs::read(destination.join("marker.json"))?) == member.sha256,
            "sealed marker mismatch"
        );
        let positive: Value =
            serde_json::from_slice(&fs::read(directory.join("child-success.json"))?)?;
        ensure!(positive["success"] == true, "successful child not recorded");
        ensure!(
            child(
                &tool,
                &args,
                false,
                &directory.join("child-no-clobber.json")
            )
            .is_err(),
            "sealer unexpectedly replaced existing deployment"
        );
        ensure!(
            sha(&fs::read(destination.join("marker.json"))?) == member.sha256,
            "no-clobber probe changed member"
        );
        Ok(())
    }

    fn write_test_child_result(path: &Path, value: &Value) -> Result<Bound> {
        // Exercise the actual root-private writer in the privileged suite, and
        // the same no-clobber/durability contract in ordinary unprivileged CI.
        if unsafe { libc::geteuid() } == 0 {
            return write_new(path, value);
        }
        let bytes = serde_json::to_vec(value)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        File::open(path.parent().unwrap())?.sync_all()?;
        Ok(Bound {
            path: path.into(),
            sha256: sha(&bytes),
        })
    }

    #[test]
    fn failed_child_keeps_stderr_before_error_and_never_clobbers_receipt() {
        use std::os::unix::process::ExitStatusExt;
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.path().join("child.json");
        let tool = Bound {
            path: "/sealed/sealer".into(),
            sha256: "a".repeat(64),
        };
        let output = std::process::Output {
            status: std::process::ExitStatus::from_raw(1 << 8),
            stdout: b"partial diagnostic".to_vec(),
            stderr: b"exact child failure".to_vec(),
        };
        let result =
            record_child_output_with(&tool, &output, &path, write_test_child_result).unwrap_err();
        assert!(result.to_string().contains("private result:"));
        let original = fs::read(&path).unwrap();
        let receipt: Value = serde_json::from_slice(&original).unwrap();
        assert_eq!(receipt["exit_code"], 1);
        assert_eq!(receipt["success"], false);
        assert_eq!(receipt["stderr"]["text"], "exact child failure");
        assert_eq!(receipt["stderr"]["sha256"], sha(&output.stderr));
        assert_eq!(receipt["automatic_retry_authorized"], false);
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        assert!(record_child_output_with(&tool, &output, &path, write_test_child_result).is_err());
        assert_eq!(fs::read(&path).unwrap(), original);
    }

    #[test]
    fn oversized_or_signaled_child_is_private_bounded_and_fatal() {
        use std::os::unix::process::ExitStatusExt;
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let tool = Bound {
            path: "/sealed/tool".into(),
            sha256: "a".repeat(64),
        };
        for (name, raw_status, bytes) in [
            ("oversized", 0, vec![b'x'; (1 << 20) + 1]),
            ("signaled", 9, vec![0xff]),
        ] {
            let path = directory.path().join(format!("{name}.json"));
            let output = std::process::Output {
                status: std::process::ExitStatus::from_raw(raw_status),
                stdout: vec![],
                stderr: bytes,
            };
            assert!(
                record_child_output_with(&tool, &output, &path, write_test_child_result).is_err()
            );
            let receipt: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
            assert_eq!(receipt["stderr"]["sha256"], sha(&output.stderr));
            assert_eq!(receipt["stderr"]["length"], output.stderr.len());
            if name == "oversized" {
                assert_eq!(receipt["stderr"]["truncated"], true);
                assert_eq!(receipt["stderr"]["text"].as_str().unwrap().len(), 1 << 20);
            } else {
                assert_eq!(receipt["signal"], 9);
            }
        }
    }

    #[test]
    fn successful_child_also_has_durable_result() {
        use std::os::unix::process::ExitStatusExt;
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.path().join("success.json");
        let tool = Bound {
            path: "/sealed/tool".into(),
            sha256: "a".repeat(64),
        };
        let output = std::process::Output {
            status: std::process::ExitStatus::from_raw(0),
            stdout: b"ok".to_vec(),
            stderr: vec![],
        };
        record_child_output_with(&tool, &output, &path, write_test_child_result).unwrap();
        let receipt: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        assert_eq!(receipt["success"], true);
        assert_eq!(receipt["stdout"]["text"], "ok");
        assert_eq!(receipt["stderr"]["truncated"], false);
    }

    fn fixture() -> (Plan, Value, Value, Value, Value, Value, Value, Value) {
        let b = |name: &str| json!({"path":format!("/sealed/{name}"),"sha256":"a".repeat(64)});
        let p:Plan=serde_json::from_value(json!({"schema":PLAN_SCHEMA,"sample_target_utc":"2026-10-20T10:34:42Z",
            "endpoint_sha256":"a".repeat(64),"bucket":BUCKET,"observer":"/private/next-observer.json",
            "observer_config":b("observer-config"),"previous_observer":b("old-observer"),
            "model_template":b("model"),"fleet_template":b("fleet-plan"),"previous_estimates":b("estimates"),
            "previous_fleet":b("fleet"),"tools":{"sealer":b("sealer"),"estimator":b("estimator"),"r2":b("r2")},
            "expected_epochs":[206],"cycle_directory":"/var/lib/jetstreamer/horizon-routine-cycles-v1/20261020T103442Z-v1",
            "cycle_unit":"horizon-routine-cycle-20261020T103442Z-v1.service",
            "estimate_output":"/private/estimates/horizon-r2-status-estimates-20261020T103442Z-cohort-gated-v5.json",
            "fleet_output":"/var/lib/jetstreamer/horizon-campaign-fleet/20261020T103442Z-rust-v1/fleet-ledger.json"})).unwrap();
        let range = json!({"range":"206-206","epochs":[206],"archive_directory":"/private/archives",
            "expected_controller_invocation_id":"b".repeat(32),"expected_producer_invocation_id":"c".repeat(32),
            "terminal_slot":89423999,"epoch_additional_replay_slots":{"206":0},
            "epoch_downstream_allowance_seconds":{"206":10230},"formula":{"206":"retained formula"}});
        let model = json!({"schema":"jetstreamer-horizon-r2-status-eta-model-v5","phase":"replay",
            "sample_target_utc":"2026-10-20T10:04:42Z","evidence":[b("older-estimates"),b("old-observer")],
            "estimate_receipt_directory":"/private/estimates","status_receipt_directory":"/private/status","ranges":[range]});
        let fleet = json!({"schema":"jetstreamer-horizon-campaign-fleet-plan-v1","first_epoch":201,"last_epoch":300,
            "observer":b("old-observer"),"previous_fleet":b("older-fleet"),"output":"/old/output",
            "gates":{"224":{"state":"blocked-qualification","next_action":"repair remains open","evidence":[]}},
            "diagnostics":[{"epoch":203,"unit":"exact-private-unit"}],"pipeline_claims":[{"epoch":213,"unit":"completed-uploader"}]});
        let previous = json!({"schema":"jetstreamer-horizon-campaign-fleet-v1","sampled_at_utc":"2026-10-20T10:04:42Z",
            "plan":"/sealed/fleet-plan","plan_sha256":"a".repeat(64),"observer_sha256":"a".repeat(64)});
        let estimates = json!({"schema":"jetstreamer-horizon-r2-status-estimates-v5","model_sha256":"a".repeat(64),
            "observer_sha256":"a".repeat(64),"sampled_at_utc":"2026-10-20T10:04:42Z"});
        let old = json!({"schema":"jetstreamer-horizon-live-resource-sample-v2","recorded_at_utc":"2026-10-20T10:04:42Z"});
        let config = json!({"schema":"jetstreamer-horizon-live-resource-sample-config-v2","output":p.observer,
            "not_before_utc":p.sample_target_utc,"minimum_interval_seconds":1800,"previous_sample":p.previous_observer.path,
            "replays":[model["ranges"][0]]});
        let point =
            |id: &str| json!({"invocation_id":id.repeat(32),"restarts":0,"active_state":"active"});
        let observer = json!({"schema":"jetstreamer-horizon-live-resource-sample-v2","recorded_at_utc":p.sample_target_utc,
            "cadence":{"previous_sample":p.previous_observer.path,"previous_sample_sha256":p.previous_observer.sha256,
                "previous_sample_recorded_at_utc":"2026-10-20T10:04:42Z","routine_minimum_interval_enforced":true,
                "minimum_interval_seconds":1800,"observed_interval_seconds":1800,"observation_reason":"routine"},
            "replays":[{"range":"206-206","invocation_binding_stable":true,"controller_before":point("b"),
                "controller_after":point("b"),"producer_before":point("c"),"producer_after":point("c"),
                "useful_work":{"last":{"terminal_slot":89423999}}}]});
        (p, model, fleet, previous, estimates, old, config, observer)
    }

    #[test]
    fn strict_utc_rejects_nonexistent_and_noncanonical_dates() {
        assert_eq!(utc_seconds("1970-01-01T00:00:00Z").unwrap(), 0);
        assert!(utc_seconds("2026-02-29T00:00:00Z").is_err());
        assert!(utc_seconds("2026-10-20T25:00:00Z").is_err());
        assert!(utc_seconds("2026-10-20 10:34:42Z").is_err());
        assert!(utc_seconds("2026-10-20T10:34:42.0Z").is_err());
    }

    pub(super) fn fixture101() -> (Plan, Value, Value, Value, Value, Value, Value, Value) {
        let (mut p, mut model, mut fleet, mut prior, est, old, mut config, mut observer) =
            fixture();
        p.schema = PLAN_SCHEMA_101.into();
        p.scope_101_200 = Some(Scope101200 {
            private144_observer: false,
            additional_tracked_units: vec![
                "horizon-routine101-root-sealer-probe-20261021-v2.service".into(),
            ],
            diagnostic_ranges: vec![DiagnosticClaim {
                range: "144".into(),
                controller_unit: "horizon-qualify-epoch144-loader-focus-20261016-v1.service".into(),
                producer_unit: "horizon-qualify-epoch144-loader-focus-20261016-v1.service".into(),
                expected_controller_invocation_id: "d".repeat(32),
                expected_producer_invocation_id: "d".repeat(32),
            }],
        });
        p.cycle_unit = cycle_unit(&p).unwrap();
        p.cycle_directory =
            "/var/lib/jetstreamer/horizon-routine-cycles-101-200-v2/20261020T103442Z-v2".into();
        p.fleet_output = Path::new(FLEET_ROOT_101).join("fleet-20261020T103442Z.json");
        p.previous_fleet.path = Path::new(FLEET_ROOT_101).join("fleet-20261020T100442Z.json");
        p.expected_epochs = vec![198];
        model["status_receipt_directory"] =
            json!("/home/sol/.jetstreamer-private/r2-status-receipts");
        model["status_receipt_directory_uid"] = json!(1001);
        model["ranges"][0]["range"] = json!("198");
        model["ranges"][0]["epochs"] = json!([198]);
        model["ranges"][0]["terminal_slot"] = json!(85967999);
        model["evidence"] = json!([{"path":"/proof/retained-proof.json","sha256":"f".repeat(64)}]);
        config["replays"][0] = model["ranges"][0].clone();
        config["replays"].as_array_mut().unwrap().push(
            serde_json::to_value(&p.scope_101_200.as_ref().unwrap().diagnostic_ranges[0]).unwrap(),
        );
        observer["replays"][0]["range"] = json!("198");
        observer["replays"][0]["useful_work"]["last"]["terminal_slot"] = json!(85967999);
        let point =
            json!({"invocation_id":"d".repeat(32),"restarts":0,"active_state":"activating"});
        observer["replays"].as_array_mut().unwrap().push(json!({"range":"144","invocation_binding_stable":true,
            "controller_before":point,"controller_after":point,"producer_before":point,"producer_after":point}));
        fleet["first_epoch"] = json!(101);
        fleet["last_epoch"] = json!(200);
        fleet["gates"] = json!({"140":{"state":"blocked-qualification","evidence":[]}});
        fleet["tracked_units"] = json!(["horizon-preserved-private.service"]);
        prior["first_epoch"] = json!(101);
        prior["last_epoch"] = json!(200);
        (p, model, fleet, prior, est, old, config, observer)
    }

    #[test]
    fn explicit101_profile_keeps_private_diagnostic_and_all_old_model_proofs() {
        let (p, model, fleet, prior, est, old, config, observer) = fixture101();
        validate_templates(&p, &model, &fleet, &prior, &est, &old).unwrap();
        validate_observer_config(&p, &model, &config).unwrap();
        validate_observation(
            &p,
            &model,
            &observer,
            utc_seconds(&p.sample_target_utc).unwrap() + 60,
        )
        .unwrap();
        let bound = Bound {
            path: p.observer.clone(),
            sha256: "b".repeat(64),
        };
        let (derived, updated) = derive(&p, &model, &fleet, &bound).unwrap();
        assert_eq!(derived["evidence"][0], model["evidence"][0]);
        assert_eq!(derived["evidence"].as_array().unwrap().len(), 3);
        assert_eq!(derived["ranges"], model["ranges"]);
        assert_eq!(updated["gates"], fleet["gates"]);
        assert_eq!(
            updated["tracked_units"],
            json!([
                "horizon-preserved-private.service",
                "horizon-routine101-root-sealer-probe-20261021-v2.service"
            ])
        );
        assert_eq!(p.expected_epochs, vec![198]);
    }

    #[test]
    fn profiles_cannot_cross_campaign_or_receipt_namespaces() {
        let (p, model, fleet, prior, est, old, _, _) = fixture101();
        for change in 0..7 {
            let mut p: Plan = serde_json::from_value(serde_json::to_value(&p).unwrap()).unwrap();
            match change {
                0 => p.schema = PLAN_SCHEMA.into(),
                1 => p.scope_101_200 = None,
                2 => p.expected_epochs = vec![206],
                3 => p.cycle_unit = "horizon-routine-cycle-20261020T103442Z-v1.service".into(),
                4 => {
                    p.fleet_output =
                        "/var/lib/jetstreamer/horizon-campaign-fleet/foreign/fleet-ledger.json"
                            .into()
                }
                5 => p.previous_fleet.path = "/foreign/fleet.json".into(),
                _ => {
                    p.cycle_directory =
                        "/var/lib/jetstreamer/horizon-routine-cycles-v1/20261020T103442Z-v1".into()
                }
            }
            assert!(
                validate_templates(&p, &model, &fleet, &prior, &est, &old).is_err(),
                "accepted {change}"
            );
        }
        let mut wrong = prior.clone();
        wrong["first_epoch"] = json!(201);
        assert!(validate_templates(&p, &model, &fleet, &wrong, &est, &old).is_err());
        let mut wrong = model.clone();
        wrong["status_receipt_directory_uid"] = json!(0);
        assert!(validate_templates(&p, &wrong, &fleet, &prior, &est, &old).is_err());
        let (mut legacy, ..) = fixture();
        legacy.scope_101_200 = p.scope_101_200;
        assert!(is_101(&legacy).is_err());
    }

    #[test]
    fn diagnostic_exclusions_are_exact_and_never_production_status_claims() {
        let (p, model, _, _, _, _, config, observer) = fixture101();
        let now = utc_seconds(&p.sample_target_utc).unwrap() + 60;
        for change in 0..5 {
            let mut bad = observer.clone();
            match change {
                0 => {
                    bad["replays"].as_array_mut().unwrap().pop();
                }
                1 => bad["replays"][1]["producer_after"]["invocation_id"] = json!("e".repeat(32)),
                2 => bad["replays"][1]["controller_after"]["restarts"] = json!(1),
                3 => bad["replays"][1]["producer_before"]["active_state"] = json!("failed"),
                _ => bad["replays"][1]["range"] = json!("145"),
            }
            assert!(
                validate_observation(&p, &model, &bad, now).is_err(),
                "accepted diagnostic {change}"
            );
        }
        let mut bad = config.clone();
        bad["replays"][1]["producer_unit"] = json!("foreign.service");
        assert!(validate_observer_config(&p, &model, &bad).is_err());
        let mut bad_model = model;
        bad_model["ranges"][0]["range"] = json!("144");
        assert!(validate_observer_config(&p, &bad_model, &config).is_err());
        assert!(
            !newer_fleet_in_scope(
                &json!({"first_epoch":201,"last_epoch":300}),
                &json!({}),
                101,
                200
            )
            .unwrap()
        );
    }

    #[test]
    fn observational_additions_are_bounded_and_integer_evidence_is_lossless() {
        let (mut p, model, mut fleet, _, _, _, _, _) = fixture101();
        fleet["diagnostics"][0]["consensus_integer_fixture"] = json!(u64::MAX);
        let bound = Bound {
            path: p.observer.clone(),
            sha256: "b".repeat(64),
        };
        let (_, derived) = derive(&p, &model, &fleet, &bound).unwrap();
        let restored: Value =
            serde_json::from_slice(&serde_json::to_vec(&derived).unwrap()).unwrap();
        assert_eq!(
            restored["diagnostics"][0]["consensus_integer_fixture"].as_u64(),
            Some(u64::MAX)
        );
        for units in [
            vec!["foreign.service".into()],
            vec!["horizon-/escape.service".into()],
            vec!["horizon-one.service".into(), "horizon-one.service".into()],
        ] {
            p.scope_101_200.as_mut().unwrap().additional_tracked_units = units;
            assert!(is_101(&p).is_err());
        }
    }

    #[test]
    fn templates_bind_exact_predecessors_scope_and_thirty_minute_advance() {
        let (mut p, model, fleet, prior, est, old, config, _) = fixture();
        validate_templates(&p, &model, &fleet, &prior, &est, &old).unwrap();
        validate_observer_config(&p, &model, &config).unwrap();
        p.sample_target_utc = "2026-10-20T10:34:41Z".into();
        assert!(validate_templates(&p, &model, &fleet, &prior, &est, &old).is_err());
        p.sample_target_utc = "2026-10-20T10:34:42Z".into();
        p.expected_epochs.push(301);
        assert!(validate_templates(&p, &model, &fleet, &prior, &est, &old).is_err());
        p.expected_epochs = vec![206, 206];
        assert!(validate_templates(&p, &model, &fleet, &prior, &est, &old).is_err());
    }

    #[test]
    fn changed_history_elapsed_or_admission_transition_is_not_a_routine_cycle() {
        let (p, model, fleet, prior, est, old, _, _) = fixture();
        for field in ["elapsed", "model-observer", "range-epoch"] {
            let mut bad = model.clone();
            match field {
                "elapsed" => bad["ranges"][0]["elapsed_execution_millis"] = json!(1),
                "model-observer" => bad["evidence"][1]["sha256"] = json!("f".repeat(64)),
                _ => bad["ranges"][0]["epochs"] = json!([301]),
            }
            assert!(
                validate_templates(&p, &bad, &fleet, &prior, &est, &old).is_err(),
                "{field}"
            );
        }
        let mut bad = fleet.clone();
        bad["admission_transition_guard"] = json!({"path":"/guard"});
        assert!(validate_templates(&p, &model, &bad, &prior, &est, &old).is_err());
        bad = fleet;
        bad["last_epoch"] = json!(301);
        assert!(validate_templates(&p, &model, &bad, &prior, &est, &old).is_err());
        let mut bad = est;
        bad["model_sha256"] = json!("f".repeat(64));
        assert!(validate_templates(&p, &model, &fixture().2, &prior, &bad, &old).is_err());
    }

    #[test]
    fn routine_observation_rejects_early_stale_replaced_or_handed_off_owners() {
        let (p, model, _, _, _, _, _, observer) = fixture();
        let t = utc_seconds(&p.sample_target_utc).unwrap();
        validate_observation(&p, &model, &observer, t + 60).unwrap();
        assert!(validate_observation(&p, &model, &observer, t - 1).is_err());
        assert!(validate_observation(&p, &model, &observer, t + 1801).is_err());
        for field in [
            "restart",
            "owner",
            "terminal",
            "stopped",
            "unstable",
            "extra-range",
            "reason",
            "cadence",
        ] {
            let mut bad = observer.clone();
            match field {
                "restart" => bad["replays"][0]["producer_after"]["restarts"] = json!(1),
                "owner" => {
                    bad["replays"][0]["controller_after"]["invocation_id"] = json!("f".repeat(32))
                }
                "terminal" => {
                    bad["replays"][0]["useful_work"]["last"]["terminal_slot"] = json!(89424000)
                }
                "stopped" => {
                    bad["replays"][0]["producer_after"]["active_state"] = json!("inactive")
                }
                "unstable" => bad["replays"][0]["invocation_binding_stable"] = json!(false),
                "extra-range" => {
                    let entry = bad["replays"][0].clone();
                    bad["replays"].as_array_mut().unwrap().push(entry);
                }
                "reason" => bad["cadence"]["observation_reason"] = json!("user-requested-status"),
                _ => bad["cadence"]["observed_interval_seconds"] = json!(1799),
            }
            assert!(
                validate_observation(&p, &model, &bad, t + 60).is_err(),
                "{field}"
            );
        }
    }

    #[test]
    fn scheduled_observer_cannot_change_scope_or_owner() {
        let (p, model, _, _, _, _, config, _) = fixture();
        for field in ["output", "owner", "reason", "cadence"] {
            let mut bad = config.clone();
            match field {
                "output" => bad["output"] = json!("/different"),
                "owner" => {
                    bad["replays"][0]["expected_producer_invocation_id"] = json!("f".repeat(32))
                }
                "reason" => bad["observation_reason"] = json!("user-requested-status"),
                _ => bad["minimum_interval_seconds"] = json!(1),
            }
            assert!(
                validate_observer_config(&p, &model, &bad).is_err(),
                "{field}"
            );
        }
    }

    #[test]
    fn derivation_preserves_all_gates_diagnostics_completed_pipelines_and_formulae() {
        let (mut p, model, fleet, _, _, _, _, _) = fixture();
        p.additional_gate_evidence.insert(
            "224".into(),
            vec![Bound {
                path: "/sealed/new-repair".into(),
                sha256: "b".repeat(64),
            }],
        );
        let observer = Bound {
            path: p.observer.clone(),
            sha256: "c".repeat(64),
        };
        let (next, next_fleet) = derive(&p, &model, &fleet, &observer).unwrap();
        assert_eq!(next["ranges"], model["ranges"]);
        assert_eq!(next_fleet["diagnostics"], fleet["diagnostics"]);
        assert_eq!(next_fleet["pipeline_claims"], fleet["pipeline_claims"]);
        assert_eq!(next_fleet["gates"]["224"]["state"], "blocked-qualification");
        assert_eq!(
            next_fleet["gates"]["224"]["evidence"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            next["evidence"][0],
            serde_json::to_value(&p.previous_estimates).unwrap()
        );
        assert_eq!(
            next_fleet["previous_fleet"],
            serde_json::to_value(&p.previous_fleet).unwrap()
        );
    }

    #[test]
    fn estimate_census_and_identity_cannot_be_substituted() {
        let (p, model, _, _, _, _, _, _) = fixture();
        let obs = Bound {
            path: p.observer.clone(),
            sha256: "d".repeat(64),
        };
        let entry = json!({"epoch":206,"archive_directory":"/private/archives","expected_controller_invocation_id":"b".repeat(32),
            "expected_producer_invocation_id":"c".repeat(32),"elapsed_execution_millis":100,"estimated_remaining_millis":200});
        let estimates = json!({"schema":"jetstreamer-horizon-r2-status-estimates-v5","observer_sha256":obs.sha256,
            "sampled_at_utc":p.sample_target_utc,"estimates":[entry]});
        verify_estimates(&p, &model, &obs, &estimates).unwrap();
        for field in ["epoch", "owner", "remaining", "elapsed", "missing"] {
            let mut bad = estimates.clone();
            match field {
                "epoch" => bad["estimates"][0]["epoch"] = json!(301),
                "owner" => {
                    bad["estimates"][0]["expected_producer_invocation_id"] = json!("f".repeat(32))
                }
                "remaining" => bad["estimates"][0]["estimated_remaining_millis"] = json!(0),
                "elapsed" => bad["estimates"][0]["elapsed_execution_millis"] = json!("100"),
                _ => bad["estimates"] = json!([]),
            }
            assert!(verify_estimates(&p, &model, &obs, &bad).is_err(), "{field}");
        }
    }

    #[test]
    fn input_reader_rejects_links_writable_immutable_files_and_wrong_owner() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("input.json");
        fs::write(&file, b"{}").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o444)).unwrap();
        let uid = unsafe { libc::geteuid() };
        assert_eq!(read_checked(&file, 20, uid, true).unwrap(), b"{}");
        assert!(read_checked(&file, 1, uid, true).is_err());
        assert!(read_checked(&file, 20, uid.wrapping_add(1), true).is_err());
        let link = root.path().join("link");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        assert!(read_checked(&link, 20, uid, true).is_err());
        let hard = root.path().join("hard");
        fs::hard_link(&file, &hard).unwrap();
        assert!(read_checked(&file, 20, uid, true).is_err());
        assert!(absent(&file).is_err());
    }

    #[test]
    fn occupied_cycle_cannot_be_claimed_twice() {
        let root = tempfile::tempdir().unwrap();
        let cycle = root.path().join("cycle");
        absent(&cycle).unwrap();
        fs::create_dir(&cycle).unwrap();
        assert!(absent(&cycle).is_err());
        assert!(fs::create_dir(&cycle).is_err());
    }

    #[test]
    fn newer_routine_or_same_sample_admission_fleet_invalidates_pending_cycle() {
        let old = json!({"schema":"jetstreamer-horizon-campaign-fleet-v1","first_epoch":201,"last_epoch":300,
            "sampled_at_utc":"2026-10-20T10:04:42Z","recorded_unix_seconds":1792490800u64});
        assert!(!newer_fleet(&old, &old).unwrap());
        let mut next = old.clone();
        next["sampled_at_utc"] = json!("2026-10-20T10:20:00Z");
        assert!(newer_fleet(&next, &old).unwrap());
        next = old.clone();
        next["recorded_unix_seconds"] = json!(1792490801u64);
        assert!(newer_fleet(&next, &old).unwrap());
        next["first_epoch"] = json!(1);
        next["last_epoch"] = json!(200);
        assert!(!newer_fleet(&next, &old).unwrap());
        next = old.clone();
        next["schema"] = json!("unknown");
        assert!(newer_fleet(&next, &old).is_err());
    }

    #[test]
    fn source_executes_only_fixed_metadata_subcommands_not_replay_or_delete() {
        let source = include_str!("routine_cycle.rs");
        let implementation = source.split("#[cfg(test)]").next().unwrap();
        assert!(!implementation.contains("\"start\".into()"));
        assert!(!implementation.contains("\"sync\".into()"));
        assert!(!implementation.contains("\"status-delete\""));
        assert!(!implementation.contains("remove_file("));
        assert!(!implementation.contains("remove_dir("));
        assert!(implementation.contains("\"status-publish\".into()"));
        assert!(implementation.contains("\"fleet-reconcile\".into()"));
    }

    #[test]
    fn real_cycle_requires_exact_nonrestarting_bounded_oneshot_identity() {
        let id = "a".repeat(32);
        let unit = "horizon-routine-cycle-20261020T103442Z-v1.service";
        let fields = BTreeMap::from([
            ("Id".into(), unit.into()),
            ("InvocationID".into(), id.clone()),
            ("MainPID".into(), "123".into()),
            ("NRestarts".into(), "0".into()),
            ("Restart".into(), "no".into()),
            ("KillMode".into(), "control-group".into()),
            ("Delegate".into(), "no".into()),
            ("Type".into(), "oneshot".into()),
            ("TimeoutStartUSec".into(), "10min".into()),
            ("ActiveState".into(), "activating".into()),
        ]);
        validate_service(&fields, unit, &id, 123).unwrap();
        for (key, value) in [
            ("Id", "wrong.service"),
            ("InvocationID", "different"),
            ("MainPID", "124"),
            ("NRestarts", "1"),
            ("Restart", "always"),
            ("KillMode", "process"),
            ("Delegate", "yes"),
            ("Type", "simple"),
            ("TimeoutStartUSec", "infinity"),
            ("ActiveState", "inactive"),
        ] {
            let mut bad = fields.clone();
            bad.insert(key.into(), value.into());
            assert!(validate_service(&bad, unit, &id, 123).is_err(), "{key}");
        }
    }
}
