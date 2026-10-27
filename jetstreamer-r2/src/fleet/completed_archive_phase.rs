//! Metadata admission for a qualified, guarded completed-archive delivery phase.
//! The downstream core has no epoch/tool pins. Origin variants retain their own
//! native provenance gates. This command never launches a verifier or uploader.
use super::*;
mod barrier;
mod capacity;
mod decoder_capacity;
mod delivery207_event;
mod empty_properties;
mod full209_event;
pub(super) use delivery207_event::{
    event_census as delivery207_event_census, event_predecessor as delivery207_event_predecessor,
    prepare as prepare_delivery207_event, publish as publish_delivery207_status,
    status_matches as delivery207_event_status_matches,
};
pub(super) const DELIVERY207_EVENT_SCHEMA: &str = delivery207_event::EVENT_SCHEMA;
pub(super) use full209_event::{
    prepare as prepare_full209_event, publish as publish_full209_status,
    status_matches as full209_event_status_matches,
};
pub(super) fn delivery209_predecessor_guard_names(
    previous: &Value,
    event: &Value,
) -> Result<BTreeSet<String>> {
    if full209_event::is_event(event) {
        full209_event::event_census_names(previous, event)
    } else {
        ensure!(
            event["schema"] == terminal_event::SCHEMA,
            "completed209 event name request has foreign schema"
        );
        Ok(BTreeSet::new())
    }
}
pub(super) fn is_delivery209_event(v: &Value) -> bool {
    full209_event::is_event(v) || v["schema"] == terminal_event::SCHEMA
}
pub(super) fn full209_event_predecessor(
    previous: &Value,
    p: &Plan,
    pb: &BoundFile,
    event: &Value,
    sample: &str,
    at: u64,
) -> Result<()> {
    if event["schema"] == terminal_event::SCHEMA {
        terminal_event::predecessor(previous, p, pb, event, sample, at)
    } else {
        full209_event::event_predecessor(previous, p, pb, event, sample, at)
    }
}
pub(super) fn full209_event_census(
    previous: &Value,
    current: &BTreeMap<String, Value>,
    event: &Value,
) -> Result<()> {
    if event["schema"] == terminal_event::SCHEMA {
        terminal_event::census_check(previous, current, event)
    } else {
        full209_event::event_census(previous, current, event)
    }
}
pub(super) fn prepare_terminal_event() -> Result<()> {
    terminal_event::prepare()
}
pub(super) fn epoch225_extraction_guard_timer(service: &str) -> Result<()> {
    ensure!(
        service.starts_with("horizon-qualify-225-prefix-extract-")
            && service.ends_with("-guard.service"),
        "epoch 225 extraction timer namespace differs"
    );
    validate_guard_timer(&barrier::guard_timer_properties(service)?, service)
}
pub(super) fn epoch225_extraction_empty_controls(service: &str, guard: bool) -> Result<()> {
    empty_properties::extraction225_properties(service, guard)?;
    Ok(())
}
// Scope-limited metadata reuse for the separate Full 210 JIT issuer. These
// helpers confer no generic completed-archive origin or execution authority.
pub(super) fn jit210_properties(name: &str, fields: &str) -> Result<BTreeMap<String, String>> {
    empty_properties::jit210_properties(name, fields)
}
pub(super) fn jit210_start_ticks(raw: &str) -> Result<u64> {
    launch::start_ticks(raw)
}
pub(super) fn jit210_start_clock(ticks: u64) -> Result<Value> {
    launch::native_start_clock(ticks)
}
pub(super) fn jit210_native_text(path: impl AsRef<Path>, maximum: u64) -> Result<String> {
    barrier::native_text(path, maximum)
}

mod handoff;
mod launch;
mod peer;
mod terminal;
mod terminal_event;
pub(super) fn root205_properties(name: &str, fields: &str) -> Result<BTreeMap<String, String>> {
    ensure!(
        continuation205_delivery::scope(name) || continuation205_delivery::guard_scope(name),
        "205 manager query escaped typed namespace"
    );
    empty_properties::delivery_properties(name, fields)
}
pub(super) fn root205_guard_timer(name: &str) -> Result<Value> {
    ensure!(
        continuation205_delivery::guard_scope(name),
        "205 guard timer namespace differs"
    );
    let p = barrier::guard_timer_properties(name)?;
    validate_guard_timer(&p, name)?;
    Ok(serde_json::to_value(p)?)
}
pub(super) fn root205_guard_controls(p: &BTreeMap<String, String>) -> Result<()> {
    validate_guard_controls(p)
}
pub(super) fn root205_start_ticks(raw: &str) -> Result<u64> {
    launch::start_ticks(raw)
}
pub(super) fn root205_start_clock(ticks: u64) -> Result<Value> {
    launch::native_start_clock(ticks)
}
pub(super) fn root205_environment(
    p: &BTreeMap<String, String>,
    file: Option<&BoundFile>,
) -> Result<()> {
    root204_environment(p, file)
}
pub(super) fn root205_credential_digest(
    actual: &str,
    file: Option<&BoundFile>,
) -> Result<Option<String>> {
    root204_credential_digest(actual, file)
}
pub(super) fn root205_bound_log(b: &BoundFile) -> Result<Vec<u8>> {
    bound_bytes(b, 64 << 20, 0)
}
/// Use the already qualified covering-mount and writable-descendant checks for
/// both new delivery routes; systemd may elide a redundant child bind mount.
pub(super) fn delivery_source_readonly_mount(source: &Path, raw: &str) -> Result<Value> {
    barrier::archive_readonly_mount(source, raw)
}
pub(super) fn root204_bound_log(binding: &BoundFile) -> Result<Vec<u8>> {
    bound_bytes(binding, 64 << 20, 0)
}
pub(super) fn root204_properties(name: &str, fields: &str) -> Result<BTreeMap<String, String>> {
    ensure!(
        assembly204_recovery::scope(name, 204, 204) || guard_scope(name, 204, 204),
        "204 manager query escaped typed actor/guard namespace"
    );
    empty_properties::delivery_properties(name, fields)
}
// Reuse low-level manager/native checks without admitting a204 generic origin.
pub(super) fn root204_guard_timer(name: &str) -> Result<Value> {
    ensure!(
        guard_scope(name, 204, 204),
        "204 guard timer namespace differs"
    );
    let p = barrier::guard_timer_properties(name)?;
    validate_guard_timer(&p, name)?;
    Ok(serde_json::to_value(p)?)
}
pub(super) fn root204_guard_controls(p: &BTreeMap<String, String>) -> Result<()> {
    validate_guard_controls(p)
}
pub(super) fn root204_start_ticks(raw: &str) -> Result<u64> {
    launch::start_ticks(raw)
}
pub(super) fn root204_start_clock(ticks: u64) -> Result<Value> {
    launch::native_start_clock(ticks)
}
pub(super) fn root204_environment(
    p: &BTreeMap<String, String>,
    file: Option<&BoundFile>,
) -> Result<()> {
    validate_environment_sources(p, file)?;
    if let Some(b) = file {
        validate_credential_bytes(&bound_bytes(b, 64 << 10, 0)?)?;
    }
    Ok(())
}
fn normalized_credential_digest(
    expected: &BTreeMap<String, String>,
    actual: &str,
) -> Result<String> {
    let mut values = BTreeMap::new();
    for entry in actual.split('\0').filter(|e| !e.is_empty()) {
        let (key, value) = entry
            .split_once('=')
            .context("204 process environment assignment differs")?;
        ensure!(
            values.insert(key, value).is_none(),
            "204 process environment repeats a key"
        );
    }
    ensure!(
        expected
            .iter()
            .all(|(k, v)| values.get(k.as_str()).copied() == Some(v.as_str())),
        "204 process credential environment differs from bound file"
    );
    Ok(hex_lower(&Sha256::digest(serde_json::to_vec(expected)?)))
}
pub(super) fn root204_credential_digest(
    actual: &str,
    file: Option<&BoundFile>,
) -> Result<Option<String>> {
    if let Some(file) = file {
        let expected = credential_values(&bound_bytes(file, 64 << 10, 0)?)?;
        Ok(Some(normalized_credential_digest(&expected, actual)?))
    } else {
        ensure!(
            actual
                .split('\0')
                .all(|e| !e.starts_with("HORIZON_S3_ENDPOINT=")
                    && !e.starts_with("HORIZON_ACCESS_KEY_ID=")
                    && !e.starts_with("HORIZON_SECRET_ACCESS_KEY=")),
            "204 non-upload process inherited unbound R2 credentials"
        );
        Ok(None)
    }
}
pub(super) use peer::{
    GuardSelectionProfile, authenticated_guard_rollover_brackets, authenticated_guard_rollovers,
    claim_names, guard_rollover_endpoints, peer_current, peer_guard_rollover_endpoints,
    peer_guard_selection_profiles, peer_guards, peer_limits, peer_memory_views, peer_names,
    peer_observation, peer_resources, peer_view, peer_window_names,
};

const SCHEMA: &str = "jetstreamer-completed-archive-phase-spec-v1";
const RECEIPT: &str = "jetstreamer-completed-archive-phase-admission-v1";
const METADATA: u64 = 1 << 30;
const UNSAFE_ENVIRONMENT: [&str; 10] = [
    "LD_PRELOAD",
    "LD_AUDIT",
    "LD_LIBRARY_PATH",
    "BASH_ENV",
    "ENV",
    "PYTHONPATH",
    "PYTHONHOME",
    "RUBYOPT",
    "PERL5OPT",
    "GCONV_PATH",
];

fn credential_values(raw: &[u8]) -> Result<BTreeMap<String, String>> {
    let text = std::str::from_utf8(raw).context("R2 environment file is not UTF-8")?;
    let allowed = BTreeSet::from([
        "HORIZON_S3_ENDPOINT",
        "HORIZON_ACCESS_KEY_ID",
        "HORIZON_SECRET_ACCESS_KEY",
    ]);
    let mut seen = BTreeSet::new();
    let mut values = BTreeMap::new();
    for line in text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let (key, value) = line
            .split_once('=')
            .context("R2 environment file has an invalid assignment")?;
        ensure!(
            allowed.contains(key) && seen.insert(key),
            "R2 environment file has an unsupported or repeated key"
        );
        let value = value.trim();
        let unquoted = if value.starts_with('"') || value.starts_with('\'') {
            ensure!(
                value.len() >= 2 && value.as_bytes().first() == value.as_bytes().last(),
                "R2 environment value has unmatched quoting"
            );
            &value[1..value.len() - 1]
        } else {
            value
        };
        ensure!(
            !unquoted.is_empty()
                && unquoted
                    .bytes()
                    .all(|b| b.is_ascii_graphic() && !b"\\\"'".contains(&b)),
            "R2 environment value has unsupported encoding"
        );
        values.insert(key.to_owned(), unquoted.to_owned());
    }
    ensure!(seen == allowed, "R2 environment file omits a required key");
    Ok(values)
}
fn validate_credential_bytes(raw: &[u8]) -> Result<()> {
    credential_values(raw).map(|_| ())
}
fn validate_environment_sources(
    p: &BTreeMap<String, String>,
    file: Option<&BoundFile>,
) -> Result<()> {
    let expected = file
        .map(|b| format!("{} (ignore_errors=no)", b.path.display()))
        .unwrap_or_default();
    ensure!(
        p.get("EnvironmentFiles") == Some(&expected)
            && p.get("PassEnvironment").is_some_and(String::is_empty),
        "completed phase has an unexpected effective environment source"
    );
    ensure!(
        p.get("UnsetEnvironment")
            .map(|v| v.split_whitespace().collect::<BTreeSet<_>>())
            == Some(BTreeSet::from(UNSAFE_ENVIRONMENT)),
        "completed phase does not exclude unsafe inherited variables"
    );
    Ok(())
}
fn validate_guard_controls(p: &BTreeMap<String, String>) -> Result<()> {
    validate_environment_sources(p, None)?;
    for key in [
        "ExecCondition",
        "ExecStartPre",
        "ExecStartPost",
        "ExecReload",
        "ExecStop",
        "ExecStopPost",
        "OnSuccess",
        "OnFailure",
        "Environment",
    ] {
        ensure!(
            p.get(key).is_some_and(String::is_empty),
            "completed guard has an unqualified hook or environment source: {key}"
        );
    }
    Ok(())
}

const GUARD_TIMER_FIELDS: &str = "Id,LoadState,InvocationID,ActiveState,SubState,Triggers,TimersMonotonic,TimersCalendar,AccuracyUSec,RandomizedDelayUSec,Persistent,WakeSystem,OnClockChange,OnTimezoneChange,DropInPaths,NeedDaemonReload,Transient";
fn validate_guard_timer(p: &BTreeMap<String, String>, service: &str) -> Result<()> {
    singleton227_capture::require(
        p,
        &[
            ("Id", &service.replace(".service", ".timer")),
            ("LoadState", "loaded"),
            ("ActiveState", "active"),
            ("SubState", "waiting"),
            ("Triggers", service),
            ("TimersCalendar", ""),
            ("TimersCalendarTypedReply", "a(sst) 0"),
            ("AccuracyUSec", "1s"),
            ("RandomizedDelayUSec", "0"),
            ("Persistent", "no"),
            ("WakeSystem", "no"),
            ("OnClockChange", "no"),
            ("OnTimezoneChange", "no"),
            ("DropInPaths", ""),
            ("NeedDaemonReload", "no"),
            ("Transient", "no"),
        ],
    )?;
    let next = p
        .get("TimersMonotonic")
        .and_then(|v| v.strip_prefix("{ OnUnitActiveUSec=30s ; next_elapse="))
        .and_then(|v| v.strip_suffix(" }"))
        .context("completed guard timer lacks its sole approved 30-second recurrence")?;
    ensure!(
        p.get("InvocationID")
            .is_some_and(|v| is_lower_hex(v, 32) && v.bytes().any(|b| b != b'0'))
            && !next.is_empty()
            && next.split(' ').all(|part| {
                ["month", "min", "us", "ms", "s", "h", "d", "w", "y"]
                    .iter()
                    .find_map(|suffix| part.strip_suffix(*suffix))
                    .is_some_and(|number| {
                        let digits =
                            |v: &str| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit());
                        match number.split_once('.') {
                            Some((whole, fraction)) => digits(whole) && digits(fraction),
                            None => digits(number),
                        }
                    })
            })
            && next.bytes().any(|b| matches!(b, b'1'..=b'9')),
        "completed guard timer invocation or next elapse is missing/unsupported"
    );
    Ok(())
}

pub(super) fn pipeline_scope(phase: &str, unit: &str) -> Option<u64> {
    let role = match phase {
        "full-verification" => "full",
        "plugin-verification" => "plugin",
        "upload-readback" => "upload",
        _ => return None,
    };
    let rest = unit.strip_prefix("horizon-qualify-")?;
    let (number, suffix) = rest.split_once('-')?;
    let epoch = number.parse::<u64>().ok()?;
    let tail = suffix
        .strip_prefix(&format!("generic-{role}-"))?
        .strip_suffix(".service")?;
    (number == epoch.to_string()
        && (201..=300).contains(&epoch)
        && !tail.is_empty()
        && tail
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)))
    .then_some(epoch)
}
pub(super) fn guard_scope(unit: &str, first: u64, last: u64) -> bool {
    let Some(rest) = unit.strip_prefix("horizon-generic") else {
        return false;
    };
    let Some((number, tail)) = rest.split_once('-') else {
        return false;
    };
    let Ok(epoch) = number.parse::<u64>() else {
        return false;
    };
    number == epoch.to_string()
        && (first..=last).contains(&epoch)
        && ["full", "plugin", "upload"].iter().any(|role| {
            tail.strip_prefix(&format!("{role}-protective-"))
                .and_then(|suffix| suffix.strip_suffix(".service"))
                .is_some_and(|suffix| {
                    !suffix.is_empty()
                        && suffix
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
                })
        })
}
pub(super) fn capture_terminal() -> Result<()> {
    terminal::capture()
}
pub(super) fn capture() -> Result<()> {
    launch::run()
}
pub(super) fn release() -> Result<()> {
    launch::release()
}
pub(super) fn run_guarded() -> Result<()> {
    barrier::run()
}
pub(super) fn capture_plugin_capacity() -> Result<()> {
    capacity::run()
}

/// Decoder evidence only. The caller supplies its independently authenticated
/// producer identity; this never establishes archive or launch authority.
pub(in crate::fleet) fn validate_decoder_capacity(
    full_capacity: &BoundFile,
    plugin_capacity: &BoundFile,
    full_tool: &BoundFile,
    full_qualification: &BoundFile,
    plugin_tool: &BoundFile,
    plugin_qualification: &BoundFile,
    producer: &Value,
) -> Result<()> {
    assembly204_recovery::qualified_delivery_tool("full", full_tool, full_qualification)?;
    assembly204_recovery::qualified_delivery_tool("plugin", plugin_tool, plugin_qualification)?;
    let required =
        decoder_capacity::full_requirement(full_capacity, full_tool, full_qualification, producer)?;
    decoder_capacity::validate_plugin_child(&read(plugin_capacity)?, plugin_tool, required)
}

#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum Phase {
    Full,
    Plugin,
    Upload,
}
impl Phase {
    fn name(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Plugin => "plugin",
            Self::Upload => "upload",
        }
    }
    fn profile(self) -> (u64, u64, u64) {
        match self {
            Self::Full => (16 << 30, 32 << 30, 86400),
            Self::Plugin => (32 << 30, 64 << 30, 86400),
            Self::Upload => (8 << 30, 16 << 30, 172800),
        }
    }
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Origin {
    Singleton207 {
        launch: BoundFile,
        native_input: BoundFile,
        terminal: BoundFile,
        cohort_publication: BoundFile,
    },
    Singleton209 {
        launch: BoundFile,
        native_input: BoundFile,
        cohort_publication: BoundFile,
    },
}
impl Origin {
    fn epoch(&self) -> u64 {
        match self {
            Self::Singleton207 { .. } => 207,
            Self::Singleton209 { .. } => 209,
        }
    }
    fn root(&self) -> &'static Path {
        Path::new(match self {
            Self::Singleton207 { .. } => singleton207::ROOT,
            Self::Singleton209 { .. } => singleton209::ROOT,
        })
    }
    fn parts(&self) -> (&BoundFile, &BoundFile, &BoundFile) {
        match self {
            Self::Singleton207 {
                launch,
                native_input,
                cohort_publication,
                ..
            }
            | Self::Singleton209 {
                launch,
                native_input,
                cohort_publication,
            } => (launch, native_input, cohort_publication),
        }
    }
    fn manifest(&self) -> BoundFile {
        match self {
            Self::Singleton207 { .. } => singleton207::delivery::manifest_binding(),
            Self::Singleton209 { .. } => BoundFile {
                path: singleton209::PREFLIGHT.into(),
                sha256: singleton209::PREFLIGHT_SHA.into(),
            },
        }
    }
    fn same_terminal(&self, a: &Value, b: &Value) -> Result<()> {
        match self {
            Self::Singleton207 { .. } => singleton207::delivery::same_terminal(a, b),
            Self::Singleton209 { .. } => singleton209_delivery::same_source_terminal(a, b),
        }
    }
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Tool {
    artifact: BoundFile,
    qualification: BoundFile,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Program {
    artifact: BoundFile,
    deployment_seal: BoundFile,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DecoderCapacity {
    full: BoundFile,
    plugin: BoundFile,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Prior {
    phase: Phase,
    launch: BoundFile,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    epoch: u64,
    phase: Phase,
    origin: Origin,
    tools: BTreeMap<String, Tool>,
    decoder_capacity: DecoderCapacity,
    programs: BTreeMap<String, Program>,
    startup_plan: BoundFile,
    units: BTreeMap<String, String>,
    guard_units: BTreeMap<String, String>,
    state_root: PathBuf,
    r2_receipt_directory: PathBuf,
    upload_lock: PathBuf,
    environment_file: Option<BoundFile>,
    interpreter: Option<BoundFile>,
    unit_file: BoundFile,
    resource_basis: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    launcher_transition: Option<handoff::Transition>,
    prior: Vec<Prior>,
    output: PathBuf,
}
fn token(path: &Path) -> Result<&str> {
    let p = path.to_str().context("completed phase path is not UTF-8")?;
    ensure!(
        path.is_absolute()
            && p.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/-_.".contains(&b)),
        "completed phase path is unsafe"
    );
    Ok(p)
}
fn read(b: &BoundFile) -> Result<Value> {
    native209::immutable_json(b)
}
fn program(p: &Program) -> Result<()> {
    assembly204_recovery::deployed_delivery_member(&p.deployment_seal, &p.artifact, 256 << 20)
}
fn bound_bytes(b: &BoundFile, max: u64, uid: u32) -> Result<Vec<u8>> {
    let m = fs::symlink_metadata(&b.path)?;
    ensure!(
        b.path.canonicalize()? == b.path
            && m.is_file()
            && m.nlink() == 1
            && m.uid() == uid
            && m.mode() & 0o022 == 0,
        "completed phase evidence custody differs"
    );
    let raw = read_stable_bounded(&b.path, max, "completed phase evidence")?;
    ensure!(
        is_lower_hex(&b.sha256, 64)
            && hex_lower(&Sha256::digest(&raw)) == b.sha256
            && identity(&m) == identity(&fs::symlink_metadata(&b.path)?),
        "completed phase evidence changed"
    );
    Ok(raw)
}
fn shape(s: &Spec) -> Result<()> {
    ensure!(
        s.schema == SCHEMA && s.epoch == s.origin.epoch(),
        "completed phase scope differs"
    );
    ensure!(
        s.tools.keys().map(String::as_str).collect::<BTreeSet<_>>()
            == BTreeSet::from(["full", "plugin", "boundary", "upload"])
            && s.programs
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>()
                == BTreeSet::from([
                    "full",
                    "plugin",
                    "boundary",
                    "progressive",
                    "guard",
                    "launcher"
                ])
            && s.units.keys().map(String::as_str).collect::<BTreeSet<_>>()
                == BTreeSet::from(["full", "plugin", "upload"])
            && s.guard_units
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>()
                == BTreeSet::from(["full", "plugin", "upload"]),
        "completed phase tool/program/unit census differs"
    );
    for tool in s.tools.values() {
        token(&tool.artifact.path)?;
        token(&tool.qualification.path)?;
    }
    for program in s.programs.values() {
        token(&program.artifact.path)?;
        token(&program.deployment_seal.path)?;
    }
    token(&s.startup_plan.path)?;
    if let Some(environment) = &s.environment_file {
        token(&environment.path)?;
    }
    let mut names = BTreeSet::new();
    for (phase, name) in &s.units {
        ensure!(
            name.starts_with(&format!("horizon-qualify-{}-generic-{phase}-", s.epoch))
                && name.ends_with(".service")
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
                && names.insert(name),
            "completed phase unit namespace differs"
        );
        let wire = match phase.as_str() {
            "full" => "full-verification",
            "plugin" => "plugin-verification",
            "upload" => "upload-readback",
            _ => bail!("invalid completed phase role"),
        };
        ensure!(
            pipeline_scope(wire, name) == Some(s.epoch),
            "completed phase is outside its observational namespace"
        );
        ensure!(
            matches!(phase.as_str(), "full" | "plugin" | "upload"),
            "completed phase unit role differs"
        );
    }
    for (phase, name) in &s.guard_units {
        ensure!(
            name.starts_with(&format!("horizon-generic{}-{phase}-protective-", s.epoch))
                && guard_scope(name, s.epoch, s.epoch)
                && name.ends_with(".service")
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
                && names.insert(name),
            "completed phase guard namespace differs"
        );
    }
    for path in [
        &s.state_root,
        &s.r2_receipt_directory,
        &s.upload_lock,
        &s.output,
    ] {
        token(path)?;
    }
    ensure!(
        s.state_root
            .starts_with("/home/ubuntu/.jetstreamer-private")
            && s.state_root.parent() == Some(Path::new("/home/ubuntu/.jetstreamer-private"))
            && s.r2_receipt_directory == Path::new("/home/ubuntu/.jetstreamer-private/r2-receipts")
            && s.upload_lock == s.r2_receipt_directory.join("local-mutation.lock")
            && s.output.file_name().is_some_and(|p| p == "admission.json")
            && s.output.starts_with("/var/lib/jetstreamer")
            && !s.output.starts_with(&s.state_root),
        "completed phase directory scope differs"
    );
    ensure!(
        (s.phase == Phase::Upload) == s.environment_file.is_some(),
        "completed phase credentials differ"
    );
    ensure!(
        if s.phase == Phase::Upload {
            s.interpreter.is_none()
        } else {
            s.interpreter.as_ref().is_some_and(|b| {
                b.path == Path::new("/usr/bin/bash") && is_lower_hex(&b.sha256, 64)
            })
        },
        "completed phase interpreter binding differs"
    );
    let expected = match s.phase {
        Phase::Full => vec![],
        Phase::Plugin => vec![Phase::Full],
        Phase::Upload => vec![Phase::Full, Phase::Plugin],
    };
    ensure!(
        s.prior.iter().map(|p| p.phase).collect::<Vec<_>>() == expected,
        "completed phase predecessor order differs"
    );
    Ok(())
}
fn origin(s: &Spec) -> Result<(LocalArchive, Value)> {
    match &s.origin {
        Origin::Singleton207 {
            launch,
            native_input,
            terminal,
            cohort_publication,
        } => {
            ensure!(
                s.epoch == 207,
                "207 completed origin cannot qualify another epoch"
            );
            let (producer, terminal) = singleton207::delivery::custody(
                launch,
                native_input,
                terminal,
                cohort_publication,
            )?;
            let root = s.origin.root();
            let references =
                jetstreamer_horizon_observe::process_references::scan(Path::new("/proc"), root)?;
            ensure!(
                references.references.is_empty(),
                "207 completed source still has process references"
            );
            let dir = root.join("output");
            ensure!(
                dir.canonicalize()? == dir && !s.state_root.starts_with(root),
                "207 completed source/state namespace differs"
            );
            let a = read_local_archive(&dir, 207)?;
            ensure!(
                fs::metadata(&s.state_root)?.dev() == a.identity.device
                    && fs::metadata("/")?.dev() == a.identity.device,
                "207 completed source filesystem differs"
            );
            singleton207::delivery::cohort(&read(cohort_publication)?, &a)?;
            let cgroup = capped204205_work::empty_terminal_cgroup(singleton207::UNIT)?;
            Ok((
                a,
                json!({"origin":s.origin,"terminal":terminal,"producer":producer,"process_reference_census":references,"cgroup":cgroup}),
            ))
        }
        Origin::Singleton209 {
            launch,
            native_input,
            cohort_publication,
        } => {
            ensure!(s.epoch == 209, "origin variant does not qualify this epoch");
            let (_, l) = full209_status::claim(launch)?;
            ensure!(
                l["native_input"] == private157::binding(native_input),
                "completed phase changed native origin"
            );
            let native = read(native_input)?;
            ensure!(
                native["epoch"] == s.epoch && native["native_input_qualified"] == true,
                "completed phase native origin unqualified"
            );
            let terminal = singleton209_delivery::source_terminal(&l)?;
            let cgroup = capped204205_work::empty_terminal_cgroup(singleton209::UNIT)?;
            inactive_status::no_pending_owner_trigger(singleton209::UNIT, false)?;
            let root = Path::new(singleton209::ROOT);
            let references =
                jetstreamer_horizon_observe::process_references::scan(Path::new("/proc"), root)?;
            ensure!(
                references.references.is_empty(),
                "completed archive still has process references"
            );
            let dir = root.join("output");
            ensure!(
                dir.canonicalize()? == dir && !s.state_root.starts_with(root),
                "completed phase source redirected or writable"
            );
            let a = read_local_archive(&dir, s.epoch)?;
            ensure!(
                fs::metadata(&s.state_root)?.dev() == a.identity.device
                    && fs::metadata("/")?.dev() == a.identity.device,
                "completed phase source/state filesystem differs"
            );
            singleton209_delivery::cohort(&read(cohort_publication)?, &a)?;
            Ok((
                a,
                json!({"origin":s.origin,"terminal":terminal,"process_reference_census":references,"cgroup":cgroup,"producer":{"node_sha256":l["node_sha256"],"worker_sha256":l["worker_sha256"],"manifest_sha256":singleton209::PREFLIGHT_SHA,"manifest_fingerprint":l["manifest_fingerprint"]}}),
            ))
        }
    }
}
fn command(s: &Spec, archive: &Path) -> Result<Vec<String>> {
    let state = |p: &str| s.state_root.join(p).display().to_string();
    let tool = |p: &str| s.tools[p].artifact.path.display().to_string();
    let script = |p: &str| s.programs[p].artifact.path.display().to_string();
    let e = s.epoch.to_string();
    let dir = token(archive)?.to_owned();
    let argv = match s.phase {
        Phase::Full => vec![
            script("full"),
            tool("full"),
            dir,
            state("full"),
            e.clone(),
            e,
            "1".into(),
            "8".into(),
            "8".into(),
        ],
        Phase::Plugin => vec![
            script("plugin"),
            tool("plugin"),
            dir,
            state("plugin"),
            e.clone(),
            e,
            "8".into(),
            "1800".into(),
        ],
        Phase::Upload => vec![
            script("progressive"),
            tool("upload"),
            dir,
            s.r2_receipt_directory.display().to_string(),
            e.clone(),
            e,
            "--poll-seconds".into(),
            "1800".into(),
            "--concurrency".into(),
            "1".into(),
            "--local-mutation-lock".into(),
            s.upload_lock.display().to_string(),
            "--full-receipt-directory".into(),
            state("full/receipts"),
            "--full-verifier-sha256".into(),
            s.tools["full"].artifact.sha256.clone(),
            "--full-verifier-script-sha256".into(),
            s.programs["full"].artifact.sha256.clone(),
            "--plugin-receipt-directory".into(),
            state("plugin/receipts"),
            "--plugin-pipeline-sha256".into(),
            s.tools["plugin"].artifact.sha256.clone(),
            "--plugin-verifier-script-sha256".into(),
            s.programs["plugin"].artifact.sha256.clone(),
            "--boundary-receipt-directory".into(),
            state("boundary/receipts"),
            "--boundary-verifier-sha256".into(),
            s.tools["boundary"].artifact.sha256.clone(),
            "--boundary-verifier-script-sha256".into(),
            s.programs["boundary"].artifact.sha256.clone(),
            "--defer-epochs".into(),
            format!("{}-{}", s.epoch, s.epoch),
        ],
    };
    for arg in &argv {
        ensure!(
            !arg.is_empty() && !arg.bytes().any(|b| b.is_ascii_whitespace() || b == b'%'),
            "unsafe completed phase argument"
        );
    }
    Ok(argv)
}
fn idle(row: &Value) -> Result<()> {
    ensure!(
        row["MainPID"] == "0"
            && row["NRestarts"] == "0"
            && matches!(row["ActiveState"].as_str(), Some("inactive" | "failed"))
            && matches!(row["SubState"].as_str(), Some("dead" | "failed")),
        "completed phase owner is running/restarted"
    );
    Ok(())
}
fn check_unit(s: &Spec, argv: &[String]) -> Result<Value> {
    barrier::validate_plan(s, argv)?;
    let unit_argv = barrier::launcher_argv(s);
    let name = &s.units[s.phase.name()];
    ensure!(
        s.unit_file.path == Path::new("/etc/systemd/system").join(name),
        "completed phase unit fragment differs"
    );
    let raw = bound_bytes(&s.unit_file, 64 << 10, 0)?;
    let text = std::str::from_utf8(&raw)?;
    ensure!(
        text.lines()
            .filter(|l| l.starts_with("ExecStart="))
            .collect::<Vec<_>>()
            == vec![format!("ExecStart={}", unit_argv.join(" "))],
        "completed phase command differs"
    );
    let fields = "Id,LoadState,Type,User,Group,Restart,KillMode,Delegate,FragmentPath,DropInPaths,NeedDaemonReload,Transient,MemoryHigh,MemoryMax,MemorySwapMax,TasksMax,CPUQuotaPerSecUSec,RuntimeMaxUSec,LimitFSIZE,LimitFSIZESoft,LimitCORE,LimitCORESoft,NoNewPrivileges,ProtectSystem,ProtectHome,PrivateTmp,PrivateDevices,PrivateNetwork,InaccessiblePaths,CapabilityBoundingSet,AmbientCapabilities,Environment,EnvironmentFiles,PassEnvironment,UnsetEnvironment,ReadWritePaths,OnSuccess,OnFailure,ExecStart,ExecCondition,ExecStartPre,ExecStartPost,ExecReload,ExecStop,ExecStopPost";
    let p = empty_properties::properties(s, false, fields)?;
    let (high, max, runtime) = s.phase.profile();
    for (k, v) in [
        ("Id", name.clone()),
        ("LoadState", "loaded".into()),
        ("Type", "exec".into()),
        ("User", "ubuntu".into()),
        ("Group", "ubuntu".into()),
        ("Restart", "no".into()),
        ("KillMode", "control-group".into()),
        ("Delegate", "no".into()),
        ("FragmentPath", s.unit_file.path.display().to_string()),
        ("DropInPaths", String::new()),
        ("NeedDaemonReload", "no".into()),
        ("Transient", "no".into()),
        ("MemoryHigh", high.to_string()),
        ("MemoryMax", max.to_string()),
        ("MemorySwapMax", "0".into()),
        ("TasksMax", "512".into()),
        ("CPUQuotaPerSecUSec", "8s".into()),
        (
            "RuntimeMaxUSec",
            if runtime == 86400 { "1d" } else { "2d" }.into(),
        ),
        ("LimitFSIZE", "67108864".into()),
        ("LimitFSIZESoft", "67108864".into()),
        ("LimitCORE", "0".into()),
        ("LimitCORESoft", "0".into()),
        ("NoNewPrivileges", "yes".into()),
        ("ProtectSystem", "strict".into()),
        ("ProtectHome", "read-only".into()),
        ("PrivateTmp", "yes".into()),
        ("PrivateDevices", "yes".into()),
    ] {
        ensure!(
            p.get(k) == Some(&v),
            "completed phase effective property differs: {k}"
        );
    }
    for k in ["CapabilityBoundingSet", "AmbientCapabilities"] {
        ensure!(
            p.get(k).is_some_and(String::is_empty),
            "completed phase has extra capabilities"
        );
    }
    ensure!(
        p.get("InaccessiblePaths")
            .map(|v| v.split_whitespace().collect::<BTreeSet<_>>())
            == Some(BTreeSet::from(["/tmp", "/var/tmp"])),
        "completed phase has writable temporary paths outside its guarded metadata namespace"
    );
    let environments = BTreeSet::from([
        "PATH=/usr/bin:/bin",
        "LC_ALL=C",
        "TOKIO_WORKER_THREADS=8",
        "RAYON_NUM_THREADS=8",
        "SOLANA_RAYON_THREADS=8",
    ]);
    ensure!(
        p.get("Environment")
            .map(|v| v.split_whitespace().collect::<BTreeSet<_>>())
            == Some(environments),
        "completed phase environment differs"
    );
    validate_environment_sources(&p, s.environment_file.as_ref())?;
    let environment_lines = text
        .lines()
        .filter(|l| l.starts_with("EnvironmentFile="))
        .collect::<Vec<_>>();
    let expected_environment = s
        .environment_file
        .as_ref()
        .map(|b| format!("EnvironmentFile={}", b.path.display()))
        .into_iter()
        .collect::<Vec<_>>();
    ensure!(
        environment_lines == expected_environment,
        "completed phase environment file differs"
    );
    for k in [
        "OnSuccess",
        "OnFailure",
        "ExecCondition",
        "ExecStartPre",
        "ExecStartPost",
        "ExecReload",
        "ExecStop",
        "ExecStopPost",
    ] {
        ensure!(
            p.get(k).is_some_and(String::is_empty),
            "completed phase has an extra command: {k}"
        );
    }
    if s.phase != Phase::Upload {
        ensure!(
            p.get("PrivateNetwork").map(String::as_str) == Some("yes"),
            "verification has network access"
        );
    }
    let mut writable = BTreeSet::from([s.state_root.join(s.phase.name()).display().to_string()]);
    if s.phase == Phase::Upload {
        writable.insert(s.r2_receipt_directory.display().to_string());
    }
    ensure!(
        p.get("ReadWritePaths").map(|s| s
            .split_whitespace()
            .map(str::to_owned)
            .collect::<BTreeSet<_>>())
            == Some(writable),
        "completed phase writable namespace differs"
    );
    let log = format!(
        "StandardOutput=append:{}/{}/coordinator.log",
        s.state_root.display(),
        s.phase.name()
    );
    ensure!(
        text.lines()
            .filter(|l| l.starts_with("StandardOutput="))
            .collect::<Vec<_>>()
            == vec![log],
        "completed phase log destination differs"
    );
    ensure!(
        text.lines()
            .filter(|l| l.starts_with("StandardError="))
            .collect::<Vec<_>>()
            == vec!["StandardError=inherit"],
        "completed phase errors escape its bounded metadata log"
    );
    let expected = format!(
        "{{ path={} ; argv[]={} ; ignore_errors=no }}",
        unit_argv[0],
        unit_argv.join(" ")
    );
    ensure!(
        assembly204_recovery::delivery_command_matches(
            p.get("ExecStart")
                .context("completed phase command missing")?,
            &expected
        ),
        "completed phase actual argv differs"
    );
    Ok(serde_json::to_value(p)?)
}
fn receipt_words(raw: &[u8], wanted: &[&str]) -> Result<()> {
    let text = std::str::from_utf8(raw)?;
    ensure!(
        text == format!("{}\n", wanted.join(" ")),
        "completed phase verification receipt differs"
    );
    Ok(())
}
fn launch_terminal_order(launch: &Value, events: &[Value], admission: &Value) -> Result<()> {
    ensure!(
        events.len() == 2,
        "completed phase terminal event count differs"
    );
    let clock = |v: &Value| -> Result<u64> {
        Ok(v["__REALTIME_TIMESTAMP"]
            .as_str()
            .context("completed phase manager timestamp absent")?
            .parse::<u64>()?
            / 1_000_000)
    };
    let captured = launch["captured_unix_seconds"]
        .as_u64()
        .context("completed phase capture time absent")?;
    let guarded = launch["guard_sample_contents"]["recorded_unix_seconds"]
        .as_u64()
        .context("completed phase first guard time absent")?;
    let admitted = admission["recorded_unix_seconds"]
        .as_u64()
        .context("completed phase admission time absent")?;
    ensure!(
        admitted <= clock(&events[0])?
            && clock(&events[0])? <= guarded
            && guarded <= captured
            && captured <= clock(&events[1])?,
        "completed phase actual launch/first guard lies outside its terminal invocation"
    );
    Ok(())
}
fn predecessor(s: &Spec, p: &Prior, archive: &LocalArchive, self_sha: &str) -> Result<Value> {
    let value = read(&p.launch)?;
    if value["schema"] == terminal::SCHEMA {
        return terminal::predecessor(&value, s, p, archive, self_sha);
    }
    let captured = launch::validate_saved(&value, s, p.phase, self_sha)?;
    let admission: BoundFile = serde_json::from_value(captured["admission"].clone())?;
    let iid = captured["invocation_id"]
        .as_str()
        .context("completed phase captured IID missing")?;
    let v = read(&admission)?;
    ensure!(
        v["schema"] == RECEIPT
            && v["admitted"] == true
            && v["epoch"] == s.epoch
            && v["phase"] == p.phase.name()
            && v["origin"] == serde_json::to_value(&s.origin)?
            && v["tools"] == serde_json::to_value(&s.tools)?
            && v["decoder_capacity"] == serde_json::to_value(&s.decoder_capacity)?
            && v["state_root"] == serde_json::to_value(&s.state_root)?
            && v["units"] == serde_json::to_value(&s.units)?
            && v["guard_units"] == serde_json::to_value(&s.guard_units)?
            && v["archive"] == singleton209_delivery::pair_identity(archive),
        "completed phase predecessor admission differs"
    );
    let old_spec: BoundFile = serde_json::from_value(v["spec"].clone())?;
    let prior: Spec = serde_json::from_value(read(&old_spec)?)?;
    shape(&prior)?;
    handoff::programs_match(&prior, s)?;
    ensure!(
        v["issuer_sha256"] == prior.programs["launcher"].artifact.sha256
            && v["programs"] == serde_json::to_value(&prior.programs)?
            && v["interpreter"] == serde_json::to_value(&prior.interpreter)?,
        "completed phase predecessor interpreter differs"
    );
    ensure!(
        prior.phase == p.phase,
        "completed phase predecessor spec differs"
    );
    check_unit(
        &prior,
        &command(
            &prior,
            archive.archive_path.parent().context("archive parent")?,
        )?,
    )?;
    let name = &s.units[p.phase.name()];
    let current = unit(name)?;
    idle(&current)?;
    ensure!(
        current["LoadState"] == "loaded"
            && current["ActiveState"] == "inactive"
            && current["SubState"] == "dead"
            && current["Result"] == "success"
            && current["ExecMainStatus"] == "0"
            && (current["InvocationID"] == iid || current["InvocationID"] == ""),
        "completed phase predecessor is not natural success"
    );
    let out = ProcessCommand::new("/usr/bin/journalctl")
        .args([
            "--unit",
            name,
            "_PID=1",
            "--output=json",
            "--no-pager",
            "--lines=256",
        ])
        .output()?;
    ensure!(
        out.status.success() && out.stdout.len() <= 2 << 20,
        "completed phase predecessor journal unavailable"
    );
    let rows = serde_json::Deserializer::from_slice(&out.stdout)
        .into_iter::<Value>()
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let events = singleton209_delivery::terminal_history_for(&rows, name, iid)?;
    launch_terminal_order(&captured, &events, &v)?;
    let state = s.state_root.join(p.phase.name());
    let path = state
        .join("receipts")
        .join(format!("epoch-{}.{}.ok", s.epoch, p.phase.name()));
    let raw = read_stable_bounded(&path, 4096, "completed phase verification receipt")?;
    let m = fs::symlink_metadata(&path)?;
    ensure!(
        path.canonicalize()? == path
            && m.is_file()
            && m.nlink() == 1
            && m.uid() == 1000
            && m.mode() & 0o077 == 0,
        "completed phase receipt custody differs"
    );
    receipt_words(
        &raw,
        &[
            &archive.sha256_hex,
            &s.tools[p.phase.name()].artifact.sha256,
            &s.programs[p.phase.name()].artifact.sha256,
        ],
    )?;
    if p.phase == Phase::Full {
        let manifest = format!("{}  epoch-{}.jet\n", archive.sha256_hex, s.epoch);
        ensure!(
            read_stable_bounded(
                &state.join("archive-manifest.sha256"),
                4096,
                "completed full manifest"
            )? == manifest.as_bytes(),
            "completed full manifest differs"
        );
        let chain = read_stable_bounded(
            &state.join("receipts/ordered-chain.ok"),
            4096,
            "completed ordered receipt",
        )?;
        receipt_words(
            &chain,
            &[
                &hex_lower(&Sha256::digest(manifest.as_bytes())),
                &s.tools["full"].artifact.sha256,
                &s.programs["full"].artifact.sha256,
            ],
        )?;
    }
    Ok(
        json!({"admission":private157::binding(&admission),"launch":private157::binding(&p.launch),"invocation_id":iid,"unit":current,"manager_events":events,"manager_journal_sha256":hex_lower(&Sha256::digest(&out.stdout)),"receipt_path":path,"receipt_sha256":hex_lower(&Sha256::digest(&raw))}),
    )
}
pub(super) fn run() -> Result<()> {
    let (binding, self_sha) = publication203::parsed_args("admit-completed-archive-phase")?;
    let s: Spec = serde_json::from_value(read(&binding)?)?;
    shape(&s)?;
    validate_output_destination(&s.output)?;
    handoff::validate(&s)?;
    let state = fs::symlink_metadata(&s.state_root)?;
    ensure!(
        s.state_root.canonicalize()? == s.state_root
            && state.is_dir()
            && state.uid() == 1000
            && state.mode() & 0o077 == 0,
        "completed phase state root unsafe"
    );
    for phase in ["full", "plugin", "boundary", "upload"] {
        let path = s.state_root.join(phase);
        let m = fs::symlink_metadata(&path)?;
        ensure!(
            path.canonicalize()? == path && m.is_dir() && m.uid() == 1000 && m.mode() & 0o077 == 0,
            "completed phase child state namespace unsafe"
        );
        if phase == s.phase.name() {
            ensure!(
                fs::read_dir(&path)?.next().is_none(),
                "completed phase attempt must be empty"
            );
        }
    }
    if let Some(interpreter) = &s.interpreter {
        bound_bytes(interpreter, 32 << 20, 0)?;
    }
    for (role, t) in &s.tools {
        assembly204_recovery::qualified_delivery_tool(role, &t.artifact, &t.qualification)?;
    }
    for p in s.programs.values() {
        program(p)?;
    }
    if let Some(e) = &s.environment_file {
        validate_credential_bytes(&bound_bytes(e, 64 << 10, 0)?)?;
        ensure!(
            fs::symlink_metadata(&e.path)?.mode() & 0o077 == 0,
            "completed phase credentials are not private"
        );
    }
    let (archive, original) = origin(&s)?;
    decoder_capacity::validate(&s, &original["producer"])?;
    let argv = command(&s, archive.archive_path.parent().context("archive parent")?)?;
    ensure!(
        s.programs["launcher"].artifact.sha256 == self_sha,
        "completed phase launcher differs from admitting helper"
    );
    barrier::before_admission(&s, &argv)?;
    let effective = check_unit(&s, &argv)?;
    let mut names =
        bound_json(&serde_json::from_value(s.resource_basis["fleet"].clone())?)?["unit_census"]
            .as_object()
            .context("completed phase complete census missing")?
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
    names.extend(s.units.values().cloned());
    let before = census(&names, 201, 300)?;
    for name in s.units.values() {
        idle(before.get(name).context("completed phase owner missing")?)?;
        inactive_status::no_pending_owner_trigger(name, false)?;
    }
    let prior = s
        .prior
        .iter()
        .map(|p| predecessor(&s, p, &archive, &self_sha))
        .collect::<Result<Vec<_>>>()?;
    let _upload_lock = if s.phase == Phase::Upload {
        Some(singleton209_delivery::lock()?)
    } else {
        None
    };
    let capacity_check = if matches!(&s.origin, Origin::Singleton207 { .. }) {
        maintenance_capacity::check_completed_archive207_phase
    } else {
        maintenance_capacity::check_completed_archive_phase
    };
    let capacity = capacity_check(
        &s.resource_basis,
        maintenance_capacity::Candidate {
            additional_bytes: METADATA,
            memory_max_bytes: s.phase.profile().1,
            minimum_protected_disk_bytes: 1,
        },
    )?;
    let after = census(&names, 201, 300)?;
    let (archive_after, origin_after) = origin(&s)?;
    s.origin
        .same_terminal(&original["terminal"], &origin_after["terminal"])?;
    ensure!(
        before == after
            && effective == check_unit(&s, &argv)?
            && origin_after["origin"] == original["origin"]
            && origin_after["cgroup"] == original["cgroup"]
            && singleton209_delivery::pair_identity(&archive_after)
                == singleton209_delivery::pair_identity(&archive),
        "completed phase origin/owners/unit changed during admission"
    );
    for name in s.units.values() {
        inactive_status::no_pending_owner_trigger(name, false)?;
    }
    ensure!(
        prior
            == s.prior
                .iter()
                .map(|p| predecessor(&s, p, &archive, &self_sha))
                .collect::<Result<Vec<_>>>()?,
        "completed phase predecessor changed during admission"
    );
    if let Some(interpreter) = &s.interpreter {
        bound_bytes(interpreter, 32 << 20, 0)?;
    }
    for (role, t) in &s.tools {
        assembly204_recovery::qualified_delivery_tool(role, &t.artifact, &t.qualification)?;
    }
    for p in s.programs.values() {
        program(p)?;
    }
    if let Some(e) = &s.environment_file {
        validate_credential_bytes(&bound_bytes(e, 64 << 10, 0)?)?;
    }
    decoder_capacity::validate(&s, &original["producer"])?;
    private157::immutable_receipt(
        &s.output,
        &json!({"schema":RECEIPT,"epoch":s.epoch,"phase":s.phase,"admitted":true,"spec":private157::binding(&binding),"issuer_sha256":self_sha,"origin":s.origin,"origin_evidence":original,"origin_evidence_after":origin_after,"archive":singleton209_delivery::pair_identity(&archive),"tools":s.tools,"decoder_capacity":s.decoder_capacity,"programs":s.programs,"launcher_transition":s.launcher_transition,"startup_plan":s.startup_plan,"units":s.units,"guard_units":s.guard_units,"state_root":s.state_root,"interpreter":s.interpreter,"unit_file":s.unit_file,"effective_unit":effective,"argv":argv,"prior":prior,"capacity":capacity,"unit_census_before":before,"unit_census_after":after,"recorded_unix_seconds":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),"maximum_age_seconds":900,"new_stage_IID_and_first_guard_fire_pending":true,"replay_launch_authorized":false,"publication_authorized":false,"local_retirement_authorized":false,"archive_body_reads":0,"remote_mutations":false,"r2_mutations":false}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn typed207_consumers_use_its_archive_namespace_and_preserve_independent_stage_order() {
        for phase in [Phase::Full, Phase::Plugin, Phase::Upload] {
            let mut s = fixture(phase);
            s.epoch = 207;
            s.origin = Origin::Singleton207 {
                launch: b("launch207"),
                native_input: b("native207"),
                terminal: b("terminal207"),
                cohort_publication: b("cohort207"),
            };
            s.state_root = "/home/ubuntu/.jetstreamer-private/generic-delivery207".into();
            for unit in s.units.values_mut() {
                *unit = unit.replace("209", "207");
            }
            for unit in s.guard_units.values_mut() {
                *unit = unit.replace("209", "207");
            }
            shape(&s).unwrap();
            let directory = s.origin.root().join("output");
            assert_eq!(directory, Path::new(singleton207::ROOT).join("output"));
            let argv = command(&s, &directory).unwrap();
            assert!(argv.iter().any(|arg| arg == directory.to_str().unwrap()));
            assert!(argv.iter().any(|arg| arg == "207"));
            assert!(
                !argv
                    .iter()
                    .any(|arg| arg == "209" || arg.starts_with(singleton209::ROOT))
            );
            let mut changed = s.clone();
            changed.epoch = 209;
            assert!(shape(&changed).is_err());
            if phase != Phase::Full {
                let mut changed = s;
                changed.prior.clear();
                assert!(shape(&changed).is_err());
            }
        }
    }
    fn b(name: &str) -> BoundFile {
        BoundFile {
            path: Path::new("/sealed").join(name),
            sha256: "a".repeat(64),
        }
    }
    pub(super) fn fixture(phase: Phase) -> Spec {
        Spec {
            schema: SCHEMA.into(),
            epoch: 209,
            phase,
            origin: Origin::Singleton209 {
                launch: b("launch"),
                native_input: b("native"),
                cohort_publication: b("cohort"),
            },
            tools: ["full", "plugin", "boundary", "upload"]
                .into_iter()
                .map(|r| {
                    (
                        r.into(),
                        Tool {
                            artifact: b(r),
                            qualification: b(&format!("{r}-qualification")),
                        },
                    )
                })
                .collect(),
            decoder_capacity: DecoderCapacity {
                full: b("full-capacity"),
                plugin: b("plugin-capacity"),
            },
            programs: [
                "full",
                "plugin",
                "boundary",
                "progressive",
                "guard",
                "launcher",
            ]
            .into_iter()
            .map(|r| {
                (
                    r.into(),
                    Program {
                        artifact: b(&format!("{r}-program")),
                        deployment_seal: b("seal"),
                    },
                )
            })
            .collect(),
            startup_plan: b("startup-plan"),
            units: ["full", "plugin", "upload"]
                .into_iter()
                .map(|r| {
                    (
                        r.into(),
                        format!("horizon-qualify-209-generic-{r}-v1.service"),
                    )
                })
                .collect(),
            guard_units: ["full", "plugin", "upload"]
                .into_iter()
                .map(|r| {
                    (
                        r.into(),
                        format!("horizon-generic209-{r}-protective-v1.service"),
                    )
                })
                .collect(),
            state_root: "/home/ubuntu/.jetstreamer-private/generic-delivery209".into(),
            r2_receipt_directory: "/home/ubuntu/.jetstreamer-private/r2-receipts".into(),
            upload_lock: "/home/ubuntu/.jetstreamer-private/r2-receipts/local-mutation.lock".into(),
            environment_file: (phase == Phase::Upload).then(|| b("credentials")),
            interpreter: (phase != Phase::Upload).then(|| BoundFile {
                path: "/usr/bin/bash".into(),
                sha256: "a".repeat(64),
            }),
            unit_file: b("unit"),
            resource_basis: json!({}),
            launcher_transition: None,
            prior: match phase {
                Phase::Full => vec![],
                Phase::Plugin => vec![Phase::Full],
                Phase::Upload => vec![Phase::Full, Phase::Plugin],
            }
            .into_iter()
            .map(|p| Prior {
                phase: p,
                launch: b("prior"),
            })
            .collect(),
            output: "/var/lib/jetstreamer/completed-phase-test/admission.json".into(),
        }
    }
    #[test]
    fn completed_phase_core_binds_actual_tools_and_preserves_serial_no_retirement_upload() {
        for phase in [Phase::Full, Phase::Plugin, Phase::Upload] {
            let mut s = fixture(phase);
            shape(&s).unwrap();
            let original = command(&s, Path::new("/private/output")).unwrap();
            let selected = if phase == Phase::Upload {
                "upload"
            } else {
                phase.name()
            };
            s.tools.get_mut(selected).unwrap().artifact.path = "/sealed/new-qualified-tool".into();
            let changed = command(&s, Path::new("/private/output")).unwrap();
            assert_ne!(original, changed);
            assert!(changed.contains(&"/sealed/new-qualified-tool".into()));
            assert!(!changed.iter().any(|a| matches!(
                a.as_str(),
                "--delete-local" | "--overwrite-existing" | "--repair-orphaned-archive"
            )));
            if phase == Phase::Upload {
                assert!(changed.windows(2).any(|a| a == ["--concurrency", "1"]));
                assert!(
                    changed
                        .windows(2)
                        .any(|a| a == ["--defer-epochs", "209-209"])
                );
                assert!(changed.iter().any(|a| a.ends_with("/full/receipts")));
                s.tools.get_mut("full").unwrap().artifact.sha256 = "c".repeat(64);
                assert!(
                    command(&s, Path::new("/private/output"))
                        .unwrap()
                        .contains(&"c".repeat(64))
                );
            }
        }
    }
    #[test]
    fn completed_phase_scope_rejects_missing_tools_shared_units_and_borrowed_future_receipts() {
        let good = fixture(Phase::Full);
        let mut bad = good.clone();
        bad.tools.remove("full");
        assert!(shape(&bad).is_err());
        let mut bad = good.clone();
        bad.units.insert("plugin".into(), bad.units["full"].clone());
        assert!(shape(&bad).is_err());
        let mut bad = good.clone();
        bad.units.insert(
            "full".into(),
            "horizon-qualify-210-generic-full-v1.service".into(),
        );
        assert!(shape(&bad).is_err());
        let mut bad = good.clone();
        bad.state_root = "/home/ubuntu/.jetstreamer-private".into();
        assert!(shape(&bad).is_err());
        let mut bad = good.clone();
        bad.prior = fixture(Phase::Plugin).prior;
        assert!(shape(&bad).is_err());
        let mut bad = fixture(Phase::Upload);
        bad.prior.reverse();
        assert!(shape(&bad).is_err());
        let mut bad = good;
        bad.environment_file = Some(b("credentials"));
        assert!(shape(&bad).is_err());
    }
    #[test]
    fn completed_phase_receipts_reject_changed_archive_tool_script_and_partial_ordered_gate() {
        let words = ["a".repeat(64), "b".repeat(64), "c".repeat(64)];
        let wanted = words.iter().map(String::as_str).collect::<Vec<_>>();
        let good = format!("{}\n", wanted.join(" "));
        receipt_words(good.as_bytes(), &wanted).unwrap();
        for i in 0..3 {
            let mut changed = words.clone();
            changed[i] = "d".repeat(64);
            assert!(receipt_words(format!("{}\n", changed.join(" ")).as_bytes(), &wanted).is_err());
        }
        for bad in [
            wanted[..2].join(" "),
            format!("{} extra\n", wanted.join(" ")),
            format!("{}\n\n", wanted.join(" ")),
        ] {
            assert!(receipt_words(bad.as_bytes(), &wanted).is_err());
        }
    }
    #[test]
    fn completed_phase_terminal_history_rejects_foreign_restart_and_partial_success() {
        let name = "horizon-qualify-209-generic-full-v1.service";
        let iid = "a".repeat(32);
        let rows = vec![
            json!({"_PID":"1","_UID":"0","UNIT":name,"INVOCATION_ID":iid,"__REALTIME_TIMESTAMP":"1000","MESSAGE":format!("Started {name} - Full verification.")}),
            json!({"_PID":"1","_UID":"0","UNIT":name,"INVOCATION_ID":iid,"__REALTIME_TIMESTAMP":"2000","MESSAGE":format!("{name}: Deactivated successfully.")}),
        ];
        singleton209_delivery::terminal_history_for(&rows, name, &iid).unwrap();
        assert!(singleton209_delivery::terminal_history_for(&rows[..1], name, &iid).is_err());
        assert!(singleton209_delivery::terminal_history_for(&rows, "other.service", &iid).is_err());
        let mut changed = rows.clone();
        changed[1]["INVOCATION_ID"] = json!("b".repeat(32));
        assert!(singleton209_delivery::terminal_history_for(&changed, name, &iid).is_err());
        let mut changed = rows.clone();
        changed.push(json!({"_PID":"1","_UID":"0","UNIT":name,"INVOCATION_ID":"b".repeat(32),"__REALTIME_TIMESTAMP":"3000"}));
        assert!(singleton209_delivery::terminal_history_for(&changed, name, &iid).is_err());
    }
    #[test]
    fn completed_phase_terminal_history_accepts_only_exact_unscoped_cpu_accounting_warning() {
        let name = "horizon-qualify-207-generic-full-cycle462-808f4683-v1.service";
        let iid = "b02e0a3a4bdf4255955cc7436610929e";
        let mut rows = vec![
            json!({"_PID":"1","_UID":"0","UNIT":name,"INVOCATION_ID":iid,"__REALTIME_TIMESTAMP":"1000","MESSAGE":format!("Started {name} - Full verification.")}),
            json!({"_PID":"1","_UID":"0","UNIT":name,"INVOCATION_ID":iid,"__REALTIME_TIMESTAMP":"2000","MESSAGE":format!("{name}: Deactivated successfully.")}),
            json!({"_PID":"1","_UID":"0","UNIT":name,"__REALTIME_TIMESTAMP":"3000",
                "MESSAGE_ID":"c772d24e9a884cbeb9ea12625c306c01","CODE_FILE":"src/shared/conf-parser.c",
                "CODE_FUNC":"config_parse_warn_compat","CONFIG_FILE":format!("/etc/systemd/system/{name}"),"CONFIG_LINE":"22",
                "MESSAGE":format!("/etc/systemd/system/{name}:22: Support for option CPUAccounting= has been removed and it is ignored")}),
        ];
        let accepted = singleton209_delivery::terminal_history_for(&rows, name, iid).unwrap();
        assert_eq!(accepted, rows[..2]);
        for (key, value) in [
            ("INVOCATION_ID", json!("a".repeat(32))),
            ("MESSAGE_ID", json!("39f53479d3a045ac8e11786248231fbf")),
            ("CODE_FILE", json!("src/core/unit.c")),
            ("CODE_FUNC", json!("unit_log_success")),
            ("CONFIG_FILE", json!("/etc/systemd/system/foreign.service")),
            ("CONFIG_LINE", json!("022")),
            ("CONFIG_LINE", json!("0")),
            ("CONFIG_LINE", json!(null)),
            (
                "MESSAGE",
                json!(format!("Started {name} - Replaced Full verifier.")),
            ),
            (
                "MESSAGE",
                json!(format!("{name}: Failed with result 'exit-code'.")),
            ),
            ("__REALTIME_TIMESTAMP", json!("not-a-clock")),
        ] {
            let mut changed = rows.clone();
            changed[2][key] = value;
            assert!(
                singleton209_delivery::terminal_history_for(&changed, name, iid).is_err(),
                "{key}"
            );
        }
        rows.push(rows[0].clone());
        assert!(singleton209_delivery::terminal_history_for(&rows, name, iid).is_err());
        rows.pop();
        rows.push(rows[1].clone());
        assert!(singleton209_delivery::terminal_history_for(&rows, name, iid).is_err());
        rows.pop();
        rows[0]["INVOCATION_ID"] = json!(null);
        assert!(singleton209_delivery::terminal_history_for(&rows, name, iid).is_err());
        rows[0]["INVOCATION_ID"] = json!(iid);
        rows[1]["INVOCATION_ID"] = json!(null);
        assert!(singleton209_delivery::terminal_history_for(&rows, name, iid).is_err());
    }
    #[test]
    fn completed_phase_spec_rejects_unknown_authority_and_unimplemented_origin() {
        let s = serde_json::to_value(fixture(Phase::Full)).unwrap();
        for key in [
            "publication_authorized",
            "ignore_peer",
            "memory_max_bytes",
            "skip_native",
        ] {
            let mut bad = s.clone();
            bad[key] = json!(true);
            assert!(serde_json::from_value::<Spec>(bad).is_err());
        }
        let mut bad = s;
        bad["origin"]["kind"] = json!("unqualified_epoch");
        assert!(serde_json::from_value::<Spec>(bad).is_err());
        let artifact = b("tool");
        assert!(
            assembly204_recovery::qualified_delivery_tool("assembly", &artifact, &b("proof"))
                .is_err()
        );
    }
    #[test]
    fn completed_phase_credentials_reject_execution_variables_and_never_report_values() {
        let good = "HORIZON_S3_ENDPOINT=https://example.invalid/bucket\nHORIZON_ACCESS_KEY_ID=id\nHORIZON_SECRET_ACCESS_KEY='test-secret'\n";
        validate_credential_bytes(good.as_bytes()).unwrap();
        for addition in [
            "LD_PRELOAD=/private-sensitive.so\n",
            "PATH=/unsafe\n",
            "BASH_ENV=/unsafe\n",
            "PYTHONPATH=/unsafe\n",
            "HORIZON_SECRET_ACCESS_KEY=duplicate\n",
        ] {
            let error = validate_credential_bytes(format!("{good}{addition}").as_bytes())
                .unwrap_err()
                .to_string();
            assert!(!error.contains("private-sensitive") && !error.contains("test-secret"));
        }
        for bad in [
            "HORIZON_S3_ENDPOINT=x\n",
            "HORIZON_SECRET_ACCESS_KEY=bad\\\nPATH=/unsafe\n",
            "export HORIZON_S3_ENDPOINT=x\n",
        ] {
            assert!(validate_credential_bytes(bad.as_bytes()).is_err());
        }
    }
    #[test]
    fn completed_phase_effective_environment_rejects_extra_files_passed_and_unset_variables() {
        let file = b("r2.env");
        let mut props = BTreeMap::from([
            (
                "EnvironmentFiles".into(),
                format!("{} (ignore_errors=no)", file.path.display()),
            ),
            ("PassEnvironment".into(), String::new()),
            ("UnsetEnvironment".into(), UNSAFE_ENVIRONMENT.join(" ")),
        ]);
        validate_environment_sources(&props, Some(&file)).unwrap();
        for (key, value) in [
            ("EnvironmentFiles", "/foreign.env (ignore_errors=no)"),
            ("PassEnvironment", "LD_PRELOAD"),
            ("UnsetEnvironment", "BASH_ENV"),
        ] {
            let mut bad = props.clone();
            bad.insert(key.into(), value.into());
            assert!(validate_environment_sources(&bad, Some(&file)).is_err());
        }
        props.insert("EnvironmentFiles".into(), String::new());
        validate_environment_sources(&props, None).unwrap();
        assert!(validate_environment_sources(&props, Some(&file)).is_err());
    }
    #[test]
    fn completed_phase_guard_controls_reject_extra_hooks_and_execution_environment() {
        let mut props = BTreeMap::new();
        for key in [
            "ExecCondition",
            "ExecStartPre",
            "ExecStartPost",
            "ExecReload",
            "ExecStop",
            "ExecStopPost",
            "OnSuccess",
            "OnFailure",
            "Environment",
            "EnvironmentFiles",
            "PassEnvironment",
        ] {
            props.insert(key.into(), String::new());
        }
        props.insert("UnsetEnvironment".into(), UNSAFE_ENVIRONMENT.join(" "));
        validate_guard_controls(&props).unwrap();
        for (key, value) in [
            ("ExecCondition", "/sealed/pre-guard-read"),
            ("ExecStartPost", "/sealed/unqualified"),
            ("OnSuccess", "unbound.service"),
            ("Environment", "LD_PRELOAD=/sensitive.so"),
            ("EnvironmentFiles", "/foreign.env (ignore_errors=no)"),
            ("PassEnvironment", "LD_PRELOAD"),
            ("UnsetEnvironment", ""),
        ] {
            let mut changed = props.clone();
            changed.insert(key.into(), value.into());
            let error = validate_guard_controls(&changed).unwrap_err().to_string();
            assert!(!error.contains("sensitive.so"));
        }
    }
    #[test]
    fn completed_phase_guard_timer_requires_exact_recurring_schedule_and_service_target() {
        let service = "horizon-generic209-full-protective-v3.service";
        let props = BTreeMap::from([
            ("Id".into(), service.replace(".service", ".timer")),
            ("LoadState".into(), "loaded".into()),
            ("InvocationID".into(), "1".repeat(32)),
            ("ActiveState".into(), "active".into()),
            ("SubState".into(), "waiting".into()),
            ("Triggers".into(), service.into()),
            (
                "TimersMonotonic".into(),
                "{ OnUnitActiveUSec=30s ; next_elapse=3d 2h 17min 30s }".into(),
            ),
            ("TimersCalendar".into(), String::new()),
            ("TimersCalendarTypedReply".into(), "a(sst) 0".into()),
            ("AccuracyUSec".into(), "1s".into()),
            ("RandomizedDelayUSec".into(), "0".into()),
            ("Persistent".into(), "no".into()),
            ("WakeSystem".into(), "no".into()),
            ("OnClockChange".into(), "no".into()),
            ("OnTimezoneChange".into(), "no".into()),
            ("DropInPaths".into(), String::new()),
            ("NeedDaemonReload".into(), "no".into()),
            ("Transient".into(), "no".into()),
        ]);
        validate_guard_timer(&props, service).unwrap();
        for (key, value) in [
            (
                "TimersMonotonic",
                "{ OnUnitActiveUSec=1d ; next_elapse=4d }",
            ),
            (
                "TimersMonotonic",
                "{ OnUnitInactiveUSec=30s ; next_elapse=4d }",
            ),
            (
                "TimersMonotonic",
                "{ OnUnitActiveUSec=30s ; next_elapse=4d } { OnBootUSec=1s ; next_elapse=4d }",
            ),
            (
                "TimersMonotonic",
                "{ OnUnitActiveUSec=30s ; next_elapse=0 }",
            ),
            (
                "TimersMonotonic",
                "{ OnUnitActiveUSec=30s ; next_elapse=infinity }",
            ),
            ("TimersMonotonic", "unsupported"),
            (
                "TimersMonotonic",
                "{ OnUnitActiveUSec=30s ; next_elapse=1unsupported }",
            ),
            (
                "Triggers",
                "horizon-generic209-plugin-protective-v3.service",
            ),
            (
                "TimersCalendar",
                "{ OnCalendar=daily ; next_elapse=tomorrow }",
            ),
            ("TimersCalendarTypedReply", "a(stt) 0"),
            ("InvocationID", "00000000000000000000000000000000"),
            ("AccuracyUSec", "1d"),
            ("RandomizedDelayUSec", "1d"),
            ("OnClockChange", "yes"),
            ("DropInPaths", "/etc/systemd/system/foreign.conf"),
            ("SubState", "elapsed"),
        ] {
            let mut changed = props.clone();
            changed.insert(key.into(), value.into());
            assert!(
                validate_guard_timer(&changed, service).is_err(),
                "accepted {key}: {value}"
            );
        }
        for key in props.keys() {
            let mut missing = props.clone();
            missing.remove(key);
            assert!(
                validate_guard_timer(&missing, service).is_err(),
                "accepted missing {key}"
            );
        }
    }
    #[test]
    fn completed_phase_pipeline_namespace_remains_observational_and_phase_exact() {
        assert!(guard_scope(
            "horizon-generic209-full-protective-v1.service",
            201,
            300
        ));
        for name in [
            "horizon-generic0209-full-protective-v1.service",
            "horizon-generic209-full-protective-.service",
            "horizon-generic209-replay-protective-v1.service",
        ] {
            assert!(!guard_scope(name, 201, 300));
        }
        assert_eq!(
            pipeline_scope(
                "full-verification",
                "horizon-qualify-209-generic-full-v1.service"
            ),
            Some(209)
        );
        assert_eq!(
            pipeline_scope(
                "plugin-verification",
                "horizon-qualify-210-generic-plugin-attempt2.service"
            ),
            Some(210)
        );
        for (phase, name) in [
            (
                "upload-readback",
                "horizon-qualify-209-generic-full-v1.service",
            ),
            (
                "full-verification",
                "horizon-qualify-0209-generic-full-v1.service",
            ),
            ("full-verification", "horizon-qualify-209-replay-v1.service"),
            ("replay", "horizon-qualify-209-generic-full-v1.service"),
        ] {
            assert_eq!(pipeline_scope(phase, name), None);
        }
    }
    #[test]
    fn completed_phase_live_owner_blocks_unmodeled_concurrent_resource_admission() {
        let empty = json!({"active":[],"unit_census":{}});
        assert!(prefix223_live_peer::roster(&empty).unwrap().is_empty());
        for phase in [Phase::Full, Phase::Plugin, Phase::Upload] {
            let spec = fixture(phase);
            let name = &spec.units[phase.name()];
            let owner = json!({"Id":name,"InvocationID":"b".repeat(32),"NRestarts":"0"});
            let fleet = json!({"active":[{"epoch":209,"phase":phase.name(),"ordinary_replay_claim":false,"unit":owner}],"unit_census":{name:owner}});
            let error = prefix223_live_peer::roster(&fleet).unwrap_err().to_string();
            assert!(error.contains("unmodeled full-prefix peer"), "{error}");
        }
    }
    #[test]
    fn completed_phase_terminal_cannot_precede_actual_launch_or_first_guard() {
        let launch = json!({"captured_unix_seconds":920,"guard_sample_contents":{"recorded_unix_seconds":910}});
        let admission = json!({"recorded_unix_seconds":900});
        let events = [
            json!({"__REALTIME_TIMESTAMP":"901000000"}),
            json!({"__REALTIME_TIMESTAMP":"1000000000"}),
        ];
        launch_terminal_order(&launch, &events, &admission).unwrap();
        for finish in ["909000000", "919000000"] {
            let mut bad = events.clone();
            bad[1]["__REALTIME_TIMESTAMP"] = json!(finish);
            assert!(launch_terminal_order(&launch, &bad, &admission).is_err());
        }
        let mut bad = events;
        bad[0]["__REALTIME_TIMESTAMP"] = json!("899000000");
        assert!(launch_terminal_order(&launch, &bad, &admission).is_err());
    }
}

#[cfg(test)]
mod root204_credential_tests {
    use super::*;
    #[test]
    fn root204_upload_credentials_bind_actual_values_without_disclosing_them() {
        let expected = BTreeMap::from([
            ("HORIZON_S3_ENDPOINT".into(), "fake-endpoint".into()),
            ("HORIZON_ACCESS_KEY_ID".into(), "fake-access".into()),
            ("HORIZON_SECRET_ACCESS_KEY".into(), "fake-secret".into()),
        ]);
        let actual = "HORIZON_S3_ENDPOINT=fake-endpoint\0HORIZON_ACCESS_KEY_ID=fake-access\0HORIZON_SECRET_ACCESS_KEY=fake-secret\0TOKIO_WORKER_THREADS=4\0";
        let digest = normalized_credential_digest(&expected, actual).unwrap();
        assert!(is_lower_hex(&digest, 64));
        for changed in [
            actual.replace("fake-secret", "wrong-secret"),
            actual.replace("HORIZON_ACCESS_KEY_ID=fake-access\0", ""),
        ] {
            let error = normalized_credential_digest(&expected, &changed)
                .unwrap_err()
                .to_string();
            assert!(!error.contains("fake-secret") && !error.contains("wrong-secret"));
        }
        assert!(root204_credential_digest(actual, None).is_err());
        assert!(
            root204_credential_digest("TOKIO_WORKER_THREADS=4\0", None)
                .unwrap()
                .is_none()
        );
    }
}

#[cfg(test)]
mod delivery_mount_integration_tests {
    use super::*;
    #[test]
    fn root204_and205_delivery_mounts_reuse_covering_readonly_checks_without_writable_source_exemption()
     {
        for source in [
            "/var/lib/jetstreamer/horizon-204-assembly-only-recovery-v2",
            "/home/ubuntu/.jetstreamer-private/checkpoint-continuation-205-bounded8-refresh421-v1",
        ] {
            let root = "1 0 8:1 / / ro - ext4 /dev/root rw\n";
            let writable_sibling = format!(
                "{root}2 1 8:1 / /var/lib/jetstreamer/metadata-state rw - ext4 /dev/root rw\n"
            );
            let proof =
                delivery_source_readonly_mount(Path::new(source), &writable_sibling).unwrap();
            assert_eq!(proof["covering_mountpoint"], "/");
            let writable_source = format!("{root}2 1 8:1 / {source} rw - ext4 /dev/root rw\n");
            assert!(delivery_source_readonly_mount(Path::new(source), &writable_source).is_err());
            let writable_file =
                format!("{root}2 1 8:1 / {source}/epoch.jet rw - ext4 /dev/root rw\n");
            assert!(delivery_source_readonly_mount(Path::new(source), &writable_file).is_err());
        }
    }
}
