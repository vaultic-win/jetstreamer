//! Validate an invocation-bound remaining-growth claim from coordinated Horizon samples.
//!
//! The output is evidence for a later admission manifest. It never launches replay or
//! authorizes local, remote, or R2 mutation.

use {
    serde::{Deserialize, Serialize},
    serde_json::Value,
    sha2::{Digest as _, Sha256},
    std::{
        collections::BTreeSet,
        env,
        ffi::OsStr,
        fs::{self, File, OpenOptions},
        io::{Read, Write},
        os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    },
};

const PLAN_SCHEMA: &str = "jetstreamer-horizon-growth-claim-plan-v1";
const RECEIPT_SCHEMA: &str = "jetstreamer-horizon-growth-claim-v1";
const OBSERVER_SCHEMA: &str = "jetstreamer-horizon-live-resource-sample-v2";
const FLOOR_SCHEMA: &str = "jetstreamer-horizon-century-jet-floor-v1";
const MAX_JSON_BYTES: u64 = 16 * 1024 * 1024;
const GIB: u64 = 1024 * 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    range: String,
    expected_controller_invocation_id: String,
    expected_producer_invocation_id: String,
    observations: Vec<Evidence>,
    /// Explicit, hash-bound links in the same chain; never count as routine windows.
    #[serde(default)]
    user_requested_bridges: Vec<Evidence>,
    century_floor_evidence: Evidence,
    scratch_multiplier: u64,
    max_jet_multiplier: u64,
    requested_claim_gib: u64,
    output_receipt: PathBuf,
    authority: Authority,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Evidence {
    path: PathBuf,
    sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Authority {
    replay_launch_authorized: bool,
    local_deletion_authorized: bool,
    remote_mutations: bool,
    r2_mutations: bool,
}

#[derive(Debug)]
struct Arguments {
    plan: PathBuf,
    plan_sha256: String,
    self_sha256: String,
}

#[derive(Debug, Serialize)]
struct ObservationReceipt {
    path: String,
    sha256: String,
    recorded_at_utc: String,
    scratch_bytes: u64,
    slot: u64,
    terminal_slot: u64,
    slots_per_second: f64,
}

#[derive(Debug, Serialize)]
struct BridgeReceipt {
    path: String,
    sha256: String,
    recorded_at_utc: String,
    scratch_bytes: u64,
    counts_as_routine_growth_window: bool,
}

#[derive(Debug, Serialize)]
struct Receipt {
    schema: &'static str,
    recorded_at_unix_seconds: u64,
    plan: String,
    plan_sha256: String,
    verifier_sha256: String,
    range: String,
    controller_invocation_id: String,
    producer_invocation_id: String,
    observations: Vec<ObservationReceipt>,
    user_requested_bridges: Vec<BridgeReceipt>,
    maximum_observed_scratch_bytes: u64,
    maximum_verified_jet_bytes: u64,
    scratch_multiplier: u64,
    max_jet_multiplier: u64,
    formula_minimum_bytes: u64,
    requested_claim_gib: u64,
    requested_claim_bytes: u64,
    replay_launch_authorized: bool,
    local_deletion_authorized: bool,
    remote_mutations: bool,
    r2_mutations: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Identity {
    device: u64,
    inode: u64,
    size: u64,
    mtime_seconds: i64,
    mtime_nanoseconds: i64,
}

fn identity(metadata: &fs::Metadata) -> Identity {
    Identity {
        device: metadata.dev(),
        inode: metadata.ino(),
        size: metadata.size(),
        mtime_seconds: metadata.mtime(),
        mtime_nanoseconds: metadata.mtime_nsec(),
    }
}

fn lowercase_sha256(value: &str, field: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("{field} must contain 64 lowercase hex digits"));
    }
    Ok(())
}

fn lowercase_invocation_id(value: &str, field: &str) -> Result<(), String> {
    if value.len() != 32
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("{field} must contain 32 lowercase hex digits"));
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[usize::from(byte >> 4)] as char);
        output.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    output
}

fn usage(program: &str) -> String {
    format!("usage: {program} PLAN.json --plan-sha256 HEX --self-sha256 HEX")
}

fn parse_arguments() -> Result<Arguments, String> {
    let mut arguments = env::args_os();
    let program = arguments
        .next()
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_else(|| "jetstreamer-horizon-growth-claim".to_string());
    let plan = arguments.next().ok_or_else(|| usage(&program))?;
    if arguments.next().as_deref() != Some(OsStr::new("--plan-sha256")) {
        return Err(usage(&program));
    }
    let plan_sha256 = arguments
        .next()
        .ok_or_else(|| usage(&program))?
        .into_string()
        .map_err(|_| "plan SHA-256 is not UTF-8".to_string())?;
    if arguments.next().as_deref() != Some(OsStr::new("--self-sha256")) {
        return Err(usage(&program));
    }
    let self_sha256 = arguments
        .next()
        .ok_or_else(|| usage(&program))?
        .into_string()
        .map_err(|_| "self SHA-256 is not UTF-8".to_string())?;
    if arguments.next().is_some() {
        return Err(usage(&program));
    }
    Ok(Arguments {
        plan: PathBuf::from(plan),
        plan_sha256,
        self_sha256,
    })
}

fn open_regular_nofollow(path: &Path, max_bytes: u64) -> Result<(File, Identity), String> {
    if !path.is_absolute() {
        return Err(format!("path must be absolute: {}", path.display()));
    }
    let before =
        fs::symlink_metadata(path).map_err(|error| format!("stat {}: {error}", path.display()))?;
    if !before.is_file() || before.nlink() != 1 || before.size() > max_bytes {
        return Err(format!("unsafe regular file identity: {}", path.display()));
    }
    let canonical = path
        .canonicalize()
        .map_err(|error| format!("canonicalize {}: {error}", path.display()))?;
    if canonical != path {
        return Err(format!("path is not canonical: {}", path.display()));
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| format!("open {}: {error}", path.display()))?;
    let opened = file
        .metadata()
        .map_err(|error| format!("fstat {}: {error}", path.display()))?;
    if identity(&before) != identity(&opened) {
        return Err(format!("file changed while opening: {}", path.display()));
    }
    Ok((file, identity(&opened)))
}

fn read_hashed_bytes_with_policy(
    path: &Path,
    expected_sha256: &str,
    require_sealed_plan: bool,
) -> Result<Vec<u8>, String> {
    lowercase_sha256(expected_sha256, &format!("{} SHA-256", path.display()))?;
    let (mut file, before) = open_regular_nofollow(path, MAX_JSON_BYTES)?;
    if require_sealed_plan {
        let metadata = file
            .metadata()
            .map_err(|error| format!("fstat plan {}: {error}", path.display()))?;
        let mode = metadata.permissions().mode();
        if metadata.uid() != 0 || metadata.nlink() != 1 || mode & 0o400 == 0 || mode & 0o222 != 0 {
            return Err(
                "plan must be root-owned, singly linked, owner-readable, and non-writable"
                    .to_string(),
            );
        }
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|error| format!("read {}: {error}", path.display()))?;
    let observed = hex(&Sha256::digest(&bytes));
    if observed != expected_sha256 {
        return Err(format!(
            "SHA-256 mismatch for {}: expected {expected_sha256}, observed {observed}",
            path.display()
        ));
    }
    let after = fs::symlink_metadata(path)
        .map_err(|error| format!("restat {}: {error}", path.display()))?;
    if identity(&after) != before {
        return Err(format!("file changed while reading: {}", path.display()));
    }
    Ok(bytes)
}

fn read_hashed_bytes(path: &Path, expected_sha256: &str) -> Result<Vec<u8>, String> {
    read_hashed_bytes_with_policy(path, expected_sha256, false)
}

fn read_sealed_plan_bytes(path: &Path, expected_sha256: &str) -> Result<Vec<u8>, String> {
    read_hashed_bytes_with_policy(path, expected_sha256, true)
}

fn read_json(path: &Path, expected_sha256: &str) -> Result<Value, String> {
    serde_json::from_slice(&read_hashed_bytes(path, expected_sha256)?)
        .map_err(|error| format!("decode {}: {error}", path.display()))
}

fn value_str<'a>(value: &'a Value, pointer: &str) -> Result<&'a str, String> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing string {pointer}"))
}

fn value_u64(value: &Value, pointer: &str) -> Result<u64, String> {
    value
        .pointer(pointer)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("missing integer {pointer}"))
}

fn value_f64(value: &Value, pointer: &str) -> Result<f64, String> {
    let number = value
        .pointer(pointer)
        .and_then(Value::as_f64)
        .ok_or_else(|| format!("missing number {pointer}"))?;
    if !number.is_finite() || number <= 0.0 {
        return Err(format!("{pointer} must be a positive finite number"));
    }
    Ok(number)
}

fn value_bool(value: &Value, pointer: &str) -> Result<bool, String> {
    value
        .pointer(pointer)
        .and_then(Value::as_bool)
        .ok_or_else(|| format!("missing boolean {pointer}"))
}

fn validate_unit_binding(
    replay: &Value,
    prefix: &str,
    expected_invocation: &str,
) -> Result<(), String> {
    for phase in ["before", "after"] {
        let base = format!("/{prefix}_{phase}");
        if value_str(replay, &format!("{base}/invocation_id"))? != expected_invocation
            || value_u64(replay, &format!("{base}/restarts"))? != 0
            || value_str(replay, &format!("{base}/load_state"))? != "loaded"
            || value_str(replay, &format!("{base}/active_state"))? != "active"
            || value_str(replay, &format!("{base}/result"))? != "success"
        {
            return Err(format!("unstable or unhealthy {prefix} {phase} binding"));
        }
    }
    Ok(())
}

fn utc_seconds(value: &str) -> Result<i64, String> {
    if value.len() != 20 {
        return Err("observer timestamp must be canonical UTC".to_string());
    }
    let input = std::ffi::CString::new(value).map_err(|error| error.to_string())?;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let format = c"%Y-%m-%dT%H:%M:%SZ";
    let end = unsafe { libc::strptime(input.as_ptr(), format.as_ptr(), &mut tm) };
    if end.is_null() || unsafe { *end } != 0 {
        return Err("observer timestamp is invalid".to_string());
    }
    let seconds = unsafe { libc::timegm(&mut tm) };
    let mut rendered = [0_i8; 32];
    let count =
        unsafe { libc::strftime(rendered.as_mut_ptr(), rendered.len(), format.as_ptr(), &tm) };
    let canonical = unsafe { std::ffi::CStr::from_ptr(rendered.as_ptr()) };
    if seconds < 0 || count != 20 || canonical.to_bytes() != value.as_bytes() {
        return Err("observer timestamp is noncanonical or out of range".to_string());
    }
    Ok(seconds)
}

type ValidatedObservations = (Vec<ObservationReceipt>, Vec<BridgeReceipt>, u64);

fn validate_observations(plan: &Plan) -> Result<ValidatedObservations, String> {
    if plan.observations.len() < 6 {
        return Err("at least six contiguous routine observations are required".to_string());
    }
    if plan.user_requested_bridges.len() > 32 || plan.observations.len() > 256 {
        return Err("too many growth observations or user-requested bridges".to_string());
    }
    let mut values = Vec::new();
    for (evidences, routine) in [
        (&plan.observations, true),
        (&plan.user_requested_bridges, false),
    ] {
        for evidence in evidences {
            values.push((
                evidence,
                read_json(&evidence.path, &evidence.sha256)?,
                routine,
            ));
        }
    }
    validate_observation_values(plan, values)
}

fn validate_observation_values(
    plan: &Plan,
    mut values: Vec<(&Evidence, Value, bool)>,
) -> Result<ValidatedObservations, String> {
    if values.iter().filter(|(_, _, routine)| *routine).count() < 6 {
        return Err(
            "at least six routine observations are required; bridges do not count".to_string(),
        );
    }
    // Sort only after authenticating the complete declared file set. Never discover,
    // skip or invent an intervening receipt to repair a broken chain.
    let mut paths = BTreeSet::new();
    let mut group_times = [None, None];
    for (evidence, value, routine) in &values {
        if !paths.insert(&evidence.path) {
            return Err("duplicate routine/bridge evidence path".to_string());
        }
        let timestamp = utc_seconds(value_str(value, "/recorded_at_utc")?)?;
        let group = usize::from(*routine);
        if group_times[group].is_some_and(|prior| timestamp <= prior) {
            return Err("each declared observation list must be chronological".to_string());
        }
        group_times[group] = Some(timestamp);
    }
    values.sort_by(|(_, a, _), (_, b, _)| {
        a["recorded_at_utc"]
            .as_str()
            .cmp(&b["recorded_at_utc"].as_str())
    });
    if values.first().is_none_or(|(_, _, routine)| !routine)
        || values.last().is_none_or(|(_, _, routine)| !routine)
    {
        return Err(
            "user-requested bridges must lie between selected routine observations".to_string(),
        );
    }
    let mut receipts = Vec::with_capacity(plan.observations.len());
    let mut bridges = Vec::new();
    let mut maximum_scratch = 0_u64;
    let mut prior_path: Option<&Path> = None;
    let mut prior_sha: Option<&str> = None;
    let mut prior_recorded: Option<String> = None;
    let mut prior_unix = None;
    let mut prior_routine_unix = None;
    let mut prior_slot: Option<u64> = None;
    let mut terminal_slot: Option<u64> = None;
    for (evidence, value, routine) in values {
        let reason = if routine {
            "routine"
        } else {
            "user-requested-status"
        };
        let declared_interval = value_u64(&value, "/cadence/observed_interval_seconds")?;
        if value_str(&value, "/schema")? != OBSERVER_SCHEMA
            || value_str(&value, "/cadence/observation_reason")? != reason
            || value_u64(&value, "/cadence/minimum_interval_seconds")? != 1800
            || (routine && declared_interval < 1800)
            || value_bool(&value, "/cadence/routine_minimum_interval_enforced")? != routine
            || value_bool(&value, "/mutation/producer_or_controller_signals_sent")?
            || value_bool(&value, "/mutation/service_state_changed")?
            || value_bool(&value, "/mutation/remote_mutations")?
            || value_bool(&value, "/mutation/r2_mutations")?
        {
            return Err(format!(
                "observer cadence or mutation gate failed: {}",
                evidence.path.display()
            ));
        }
        if let (Some(path), Some(sha)) = (prior_path, prior_sha)
            && (value_str(&value, "/cadence/previous_sample")? != path.to_string_lossy()
                || value_str(&value, "/cadence/previous_sample_sha256")? != sha)
        {
            return Err("observer evidence is not one complete routine/bridge chain".to_string());
        }
        let recorded = value_str(&value, "/recorded_at_utc")?.to_string();
        let unix = utc_seconds(&recorded)?;
        if prior_recorded
            .as_ref()
            .is_some_and(|prior| recorded <= *prior)
        {
            return Err("observer timestamps are not strictly increasing".to_string());
        }
        if let Some(prior) = prior_unix
            && (u64::try_from(unix - prior).map_err(|_| "negative observer interval")?
                != declared_interval
                || value_str(&value, "/cadence/previous_sample_recorded_at_utc")?
                    != prior_recorded
                        .as_deref()
                        .expect("prior timestamp accompanies prior unix"))
        {
            return Err("observer timestamp/interval binding mismatch".to_string());
        }
        if routine && prior_routine_unix.is_some_and(|prior| unix - prior < 1800) {
            return Err(
                "routine growth windows must remain at least 1800 seconds apart".to_string(),
            );
        }
        let replays = value
            .pointer("/replays")
            .and_then(Value::as_array)
            .ok_or_else(|| "observer replays must be an array".to_string())?;
        let matches: Vec<&Value> = replays
            .iter()
            .filter(|replay| replay.get("range").and_then(Value::as_str) == Some(&plan.range))
            .collect();
        if matches.len() != 1 {
            return Err(format!(
                "observer must contain exactly one {} replay",
                plan.range
            ));
        }
        let replay = matches[0];
        if !value_bool(replay, "/invocation_binding_stable")? {
            return Err("observer invocation binding is not stable".to_string());
        }
        validate_unit_binding(
            replay,
            "controller",
            &plan.expected_controller_invocation_id,
        )?;
        validate_unit_binding(replay, "producer", &plan.expected_producer_invocation_id)?;
        if routine && !value_bool(replay, "/useful_work/sufficient_for_rates")? {
            return Err("observer lacks sufficient useful-work rates".to_string());
        }
        let scratch = value_u64(replay, "/conservative_observed_physical_bytes")?;
        maximum_scratch = maximum_scratch.max(scratch);
        let last = replay.pointer("/useful_work/last");
        if routine || last.is_some_and(|last| !last.is_null()) {
            let slot = value_u64(replay, "/useful_work/last/slot")?;
            let observed_terminal = value_u64(replay, "/useful_work/last/terminal_slot")?;
            if slot > observed_terminal
                || prior_slot
                    .is_some_and(|prior| if routine { slot <= prior } else { slot < prior })
                || terminal_slot.is_some_and(|prior| observed_terminal != prior)
            {
                return Err("observer slot sequence or terminal slot is invalid".to_string());
            }
            if routine {
                receipts.push(ObservationReceipt {
                    path: evidence.path.display().to_string(),
                    sha256: evidence.sha256.clone(),
                    recorded_at_utc: recorded.clone(),
                    scratch_bytes: scratch,
                    slot,
                    terminal_slot: observed_terminal,
                    slots_per_second: value_f64(replay, "/useful_work/slots_per_second")?,
                });
            }
            prior_slot = Some(slot);
            terminal_slot = Some(observed_terminal);
        }
        if routine {
            prior_routine_unix = Some(unix);
        } else {
            bridges.push(BridgeReceipt {
                path: evidence.path.display().to_string(),
                sha256: evidence.sha256.clone(),
                recorded_at_utc: recorded.clone(),
                scratch_bytes: scratch,
                counts_as_routine_growth_window: false,
            });
        }
        prior_path = Some(&evidence.path);
        prior_sha = Some(&evidence.sha256);
        prior_recorded = Some(recorded);
        prior_unix = Some(unix);
    }
    Ok((receipts, bridges, maximum_scratch))
}

fn maximum_verified_jet(plan: &Plan) -> Result<u64, String> {
    let value = read_json(
        &plan.century_floor_evidence.path,
        &plan.century_floor_evidence.sha256,
    )?;
    if value_str(&value, "/schema")? != FLOOR_SCHEMA {
        return Err("century floor evidence schema mismatch".to_string());
    }
    if value_u64(&value, "/century/first_epoch")? != 200
        || value_u64(&value, "/century/last_epoch")? != 300
        || value_str(&value, "/selection_policy")?
            != "one canonical complete jet per epoch with normal full/plugin evidence and an authenticated R2 ready-pair receipt; exclude partial, diagnostic, verification-tail, archive-only, and growing files"
        || value_bool(&value, "/remote_mutations")?
        || value_bool(&value, "/r2_mutations")?
    {
        return Err("century floor scope, policy, or mutation declaration mismatch".to_string());
    }
    let samples = value
        .pointer("/samples")
        .and_then(Value::as_array)
        .ok_or_else(|| "century floor samples must be an array".to_string())?;
    if samples.is_empty() {
        return Err("century floor evidence has no verified jets".to_string());
    }
    let mut sum = 0_u64;
    let mut maximum = 0_u64;
    let mut epochs = BTreeSet::new();
    for sample in samples {
        let epoch = value_u64(sample, "/epoch")?;
        if !(200..=300).contains(&epoch) || !epochs.insert(epoch) {
            return Err("century floor sample epoch is out of range or duplicated".to_string());
        }
        let size = value_u64(sample, "/jet_size_bytes")?;
        let archive_sha = value_str(sample, "/archive_sha256")?;
        lowercase_sha256(archive_sha, "archive SHA-256")?;
        let receipt_path = PathBuf::from(value_str(sample, "/r2_receipt")?);
        let receipt_sha = value_str(sample, "/r2_receipt_sha256")?;
        lowercase_sha256(receipt_sha, "R2 receipt SHA-256")?;
        let receipt = read_json(&receipt_path, receipt_sha)?;
        let receipt_schema = value_str(&receipt, "/schema")?;
        if receipt_schema == "jetstreamer-horizon-private-resource-audit-receipt-v1" {
            let verification_path =
                PathBuf::from(value_str(sample, "/private_resource_verification")?);
            let verification_sha = value_str(sample, "/private_resource_verification_sha256")?;
            lowercase_sha256(verification_sha, "private full/plugin verification SHA-256")?;
            let verification = read_json(&verification_path, verification_sha)?;
            validate_private_floor_verification(
                &receipt,
                &verification,
                epoch,
                size,
                archive_sha,
                &receipt_path,
                receipt_sha,
            )?;
        } else if receipt_schema != "jetstreamer-horizon-r2-receipt-v1" {
            return Err("unsupported century-floor ready-pair receipt schema".to_string());
        }
        if value_u64(&receipt, "/epoch")? != epoch
            || value_str(&receipt, "/archive_key")? != format!("epoch-{epoch}.jet")
            || value_str(&receipt, "/checksum_key")? != format!("epoch-{epoch}.jet.sha256")
            || value_u64(&receipt, "/archive_length")? != size
            || value_str(&receipt, "/archive_sha256")? != archive_sha
            || !value_bool(&receipt, "/remote_sha256_readback")?
        {
            return Err(format!("R2 ready-pair receipt mismatch for epoch {epoch}"));
        }
        sum = sum
            .checked_add(size)
            .ok_or_else(|| "jet size sum overflow".to_string())?;
        maximum = maximum.max(size);
    }
    let count = u64::try_from(samples.len()).map_err(|_| "sample count overflow".to_string())?;
    let expected_floor = sum
        .checked_mul(2)
        .and_then(|twice| twice.checked_add(count - 1))
        .map(|rounded| rounded / count)
        .ok_or_else(|| "century floor arithmetic overflow".to_string())?;
    if value_u64(&value, "/arithmetic/sample_count")? != count
        || value_u64(&value, "/arithmetic/sum_jet_size_bytes")? != sum
        || value_u64(&value, "/arithmetic/floor_bytes")? != expected_floor
    {
        return Err("century floor arithmetic does not reproduce".to_string());
    }
    Ok(maximum)
}

fn validate_private_floor_verification(
    audit: &Value,
    verification: &Value,
    epoch: u64,
    size: u64,
    archive_sha: &str,
    receipt_path: &Path,
    receipt_sha: &str,
) -> Result<(), String> {
    if value_str(audit, "/purpose")? != "century-floor-resource-audit-only"
        || !value_bool(audit, "/local_sha256_and_etag_verified")?
        || !value_bool(audit, "/authenticated_ready_pair_revalidated")?
        || value_str(verification, "/schema")?
            != "jetstreamer-horizon-private-resource-verification-v1"
        || value_str(verification, "/status")? != "passed"
        || value_u64(verification, "/epoch")? != epoch
        || value_u64(verification, "/archive_length")? != size
        || value_str(verification, "/archive_sha256")? != archive_sha
        || value_str(verification, "/resource_audit")? != receipt_path.to_string_lossy()
        || value_str(verification, "/resource_audit_sha256")? != receipt_sha
        || !value_bool(verification, "/archive_sha256_before_after_verified")?
        || value_str(verification, "/archive_path")? != value_str(audit, "/archive_path")?
        || value_u64(verification, "/archive_device")? != value_u64(audit, "/archive_device")?
        || value_u64(verification, "/archive_inode")? != value_u64(audit, "/archive_inode")?
    {
        return Err("private century-floor audit/full/plugin binding mismatch".to_string());
    }
    for value in [audit, verification] {
        for field in [
            "/production_completion_authorized",
            "/publication_authorized",
            "/local_retirement_authorized",
            "/remote_mutations",
            "/r2_mutations",
        ] {
            if value_bool(value, field)? {
                return Err("private century-floor evidence grants forbidden authority".to_string());
            }
        }
    }
    for field in ["/full_verifier", "/ordered_verifier", "/current_plugin"] {
        if value_str(verification, &format!("{field}/status"))? != "passed"
            || value_u64(verification, &format!("{field}/exit_code"))? != 0
        {
            return Err("private century-floor verification stage failed".to_string());
        }
        lowercase_sha256(
            value_str(verification, &format!("{field}/sha256"))?,
            "verifier SHA-256",
        )?;
        lowercase_sha256(
            value_str(verification, &format!("{field}/log_sha256"))?,
            "verification log SHA-256",
        )?;
    }
    Ok(())
}

fn compute_formula_minimum(
    maximum_scratch: u64,
    maximum_jet: u64,
    scratch_multiplier: u64,
    max_jet_multiplier: u64,
) -> Result<u64, String> {
    maximum_scratch
        .checked_mul(scratch_multiplier)
        .and_then(|scratch| {
            maximum_jet
                .checked_mul(max_jet_multiplier)
                .and_then(|jet| scratch.checked_add(jet))
        })
        .ok_or_else(|| "growth claim arithmetic overflow".to_string())
}

fn verify_running_executable(expected_sha256: &str) -> Result<String, String> {
    lowercase_sha256(expected_sha256, "self SHA-256")?;
    let mut executable = File::open("/proc/self/exe")
        .map_err(|error| format!("open running executable: {error}"))?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let read = executable
            .read(&mut buffer)
            .map_err(|error| format!("read running executable: {error}"))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    let observed = hex(&digest.finalize());
    if observed != expected_sha256 {
        return Err(format!(
            "self SHA-256 mismatch: expected {expected_sha256}, observed {observed}"
        ));
    }
    Ok(observed)
}

fn validate_output_path(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("output receipt must be absolute".to_string());
    }
    let parent = path
        .parent()
        .ok_or_else(|| "output receipt has no parent".to_string())?;
    let metadata = fs::symlink_metadata(parent)
        .map_err(|error| format!("stat output parent {}: {error}", parent.display()))?;
    if parent.canonicalize().map_err(|error| error.to_string())? != parent
        || !metadata.is_dir()
        || metadata.uid() != 0
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err("output parent must be canonical, root-owned, and owner-only".to_string());
    }
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err("output receipt already exists".to_string()),
        Err(error) => Err(format!("inspect output receipt: {error}")),
    }
}

fn fsync_directory(path: &Path) -> Result<(), String> {
    let directory =
        File::open(path).map_err(|error| format!("open {}: {error}", path.display()))?;
    directory
        .sync_all()
        .map_err(|error| format!("fsync {}: {error}", path.display()))
}

fn write_receipt(path: &Path, receipt: &Receipt) -> Result<(), String> {
    validate_output_path(path)?;
    let bytes =
        serde_json::to_vec_pretty(receipt).map_err(|error| format!("encode receipt: {error}"))?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| format!("create {}: {error}", path.display()))?;
    file.write_all(&bytes)
        .and_then(|_| file.write_all(b"\n"))
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("write {}: {error}", path.display()))?;
    fsync_directory(path.parent().expect("validated output parent"))
}

fn run(arguments: &Arguments) -> Result<Receipt, String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("growth claim verification must run as root".to_string());
    }
    lowercase_sha256(&arguments.plan_sha256, "plan SHA-256")?;
    let plan_bytes = read_sealed_plan_bytes(&arguments.plan, &arguments.plan_sha256)?;
    let plan: Plan =
        serde_json::from_slice(&plan_bytes).map_err(|error| format!("decode plan: {error}"))?;
    if plan.schema != PLAN_SCHEMA
        || plan.range.is_empty()
        || plan.scratch_multiplier < 1
        || plan.max_jet_multiplier < 1
        || plan.requested_claim_gib < 1
        || plan.authority.replay_launch_authorized
        || plan.authority.local_deletion_authorized
        || plan.authority.remote_mutations
        || plan.authority.r2_mutations
    {
        return Err("plan schema, multipliers, claim, or authority is invalid".to_string());
    }
    lowercase_invocation_id(
        &plan.expected_controller_invocation_id,
        "controller invocation ID",
    )?;
    lowercase_invocation_id(
        &plan.expected_producer_invocation_id,
        "producer invocation ID",
    )?;
    let verifier_sha256 = verify_running_executable(&arguments.self_sha256)?;
    let (observations, user_requested_bridges, maximum_scratch) = validate_observations(&plan)?;
    let maximum_jet = maximum_verified_jet(&plan)?;
    let formula_minimum = compute_formula_minimum(
        maximum_scratch,
        maximum_jet,
        plan.scratch_multiplier,
        plan.max_jet_multiplier,
    )?;
    let requested_claim_bytes = plan
        .requested_claim_gib
        .checked_mul(GIB)
        .ok_or_else(|| "requested claim overflow".to_string())?;
    if requested_claim_bytes < formula_minimum {
        return Err(format!(
            "requested claim {requested_claim_bytes} is below formula minimum {formula_minimum}"
        ));
    }
    validate_output_path(&plan.output_receipt)?;
    let recorded_at_unix_seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("clock before Unix epoch: {error}"))?
        .as_secs();
    Ok(Receipt {
        schema: RECEIPT_SCHEMA,
        recorded_at_unix_seconds,
        plan: arguments.plan.display().to_string(),
        plan_sha256: arguments.plan_sha256.clone(),
        verifier_sha256,
        range: plan.range,
        controller_invocation_id: plan.expected_controller_invocation_id,
        producer_invocation_id: plan.expected_producer_invocation_id,
        observations,
        user_requested_bridges,
        maximum_observed_scratch_bytes: maximum_scratch,
        maximum_verified_jet_bytes: maximum_jet,
        scratch_multiplier: plan.scratch_multiplier,
        max_jet_multiplier: plan.max_jet_multiplier,
        formula_minimum_bytes: formula_minimum,
        requested_claim_gib: plan.requested_claim_gib,
        requested_claim_bytes,
        replay_launch_authorized: false,
        local_deletion_authorized: false,
        remote_mutations: false,
        r2_mutations: false,
    })
}

fn main() {
    let result = parse_arguments().and_then(|arguments| {
        let receipt = run(&arguments)?;
        let plan_bytes = read_sealed_plan_bytes(&arguments.plan, &arguments.plan_sha256)?;
        let plan: Plan = serde_json::from_slice(&plan_bytes)
            .map_err(|error| format!("decode plan before publication: {error}"))?;
        write_receipt(&plan.output_receipt, &receipt)?;
        println!(
            "{}",
            serde_json::to_string(&receipt).map_err(|error| error.to_string())?
        );
        Ok(())
    });
    if let Err(error) = result {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(bridge: bool) -> (Plan, Vec<(Value, bool)>) {
        let routine_times = [0, 30, 60, 90, 120, 153];
        let mut times: Vec<(u64, bool)> = routine_times.into_iter().map(|t| (t, true)).collect();
        if bridge {
            times.insert(5, (123, false));
        }
        let mut observations = Vec::new();
        let mut bridges = Vec::new();
        let mut values = Vec::new();
        for (index, (minutes, routine)) in times.iter().enumerate() {
            let stamp = |m: u64| format!("2026-10-19T{:02}:{:02}:00Z", m / 60, m % 60);
            let evidence = Evidence {
                path: PathBuf::from(format!("/evidence/sample-{index}.json")),
                sha256: format!("{index:064x}"),
            };
            let unit = serde_json::json!({"invocation_id":"a".repeat(32),
                "restarts":0,"load_state":"loaded","active_state":"active","result":"success"});
            let mut value = serde_json::json!({
                "schema":OBSERVER_SCHEMA,"recorded_at_utc":stamp(*minutes),
                "cadence":{"observation_reason":if *routine {"routine"} else {"user-requested-status"},
                    "minimum_interval_seconds":1800,"routine_minimum_interval_enforced":routine,
                    "observed_interval_seconds":if index==0 {1800} else {(minutes-times[index-1].0)*60}},
                "mutation":{"producer_or_controller_signals_sent":false,"service_state_changed":false,
                    "remote_mutations":false,"r2_mutations":false},
                "replays":[{"range":"154","invocation_binding_stable":true,
                    "controller_before":unit,"controller_after":unit,"producer_before":unit,"producer_after":unit,
                    "conservative_observed_physical_bytes":if *routine {100} else {900},
                    "useful_work":{"sufficient_for_rates":true,"slots_per_second":1.0,
                        "last":{"slot":100+minutes,"terminal_slot":1000}}}]
            });
            if index > 0 {
                value["cadence"]["previous_sample"] =
                    serde_json::json!(format!("/evidence/sample-{}.json", index - 1));
                value["cadence"]["previous_sample_sha256"] =
                    serde_json::json!(format!("{:064x}", index - 1));
                value["cadence"]["previous_sample_recorded_at_utc"] =
                    serde_json::json!(stamp(times[index - 1].0));
            }
            if *routine {
                observations.push(evidence);
            } else {
                bridges.push(evidence);
            }
            values.push((value, *routine));
        }
        let plan = Plan {
            schema: PLAN_SCHEMA.into(),
            range: "154".into(),
            expected_controller_invocation_id: "a".repeat(32),
            expected_producer_invocation_id: "a".repeat(32),
            observations,
            user_requested_bridges: bridges,
            century_floor_evidence: Evidence {
                path: "/floor.json".into(),
                sha256: "b".repeat(64),
            },
            scratch_multiplier: 2,
            max_jet_multiplier: 2,
            requested_claim_gib: 512,
            output_receipt: "/receipt.json".into(),
            authority: Authority {
                replay_launch_authorized: false,
                local_deletion_authorized: false,
                remote_mutations: false,
                r2_mutations: false,
            },
        };
        (plan, values)
    }

    fn check_fixture(
        plan: &Plan,
        values: &[(Value, bool)],
    ) -> Result<ValidatedObservations, String> {
        let mut routine_index = 0;
        let mut bridge_index = 0;
        let inputs = values
            .iter()
            .map(|(value, routine)| {
                let evidence = if *routine {
                    let evidence = &plan.observations[routine_index];
                    routine_index += 1;
                    evidence
                } else {
                    let evidence = &plan.user_requested_bridges[bridge_index];
                    bridge_index += 1;
                    evidence
                };
                (evidence, value.clone(), *routine)
            })
            .collect();
        validate_observation_values(plan, inputs)
    }

    #[test]
    fn six_routine_windows_with_optional_noncounting_bridge() {
        for bridge in [false, true] {
            let (plan, values) = fixture(bridge);
            let (routine, bridges, peak) = check_fixture(&plan, &values).unwrap();
            assert_eq!(routine.len(), 6);
            assert_eq!(bridges.len(), usize::from(bridge));
            assert_eq!(peak, if bridge { 900 } else { 100 });
            assert!(bridges.iter().all(|b| !b.counts_as_routine_growth_window));
        }
        let (plan, mut values) = fixture(true);
        values[5].0["replays"][0]["useful_work"] =
            serde_json::json!({"sufficient_for_rates":false});
        assert_eq!(check_fixture(&plan, &values).unwrap().0.len(), 6);
        values.pop();
        assert!(check_fixture(&plan, &values).is_err());
    }

    #[test]
    fn rejects_broken_bridge_chain_and_unsafe_evidence() {
        let (plan, values) = fixture(true);
        for (index, pointer, replacement) in [
            (
                6,
                "/cadence/previous_sample",
                serde_json::json!("/wrong.json"),
            ),
            (
                6,
                "/cadence/previous_sample_sha256",
                serde_json::json!("f".repeat(64)),
            ),
            (
                5,
                "/cadence/observation_reason",
                serde_json::json!("routine"),
            ),
            (
                5,
                "/cadence/routine_minimum_interval_enforced",
                serde_json::json!(true),
            ),
            (5, "/mutation/r2_mutations", serde_json::json!(true)),
            (
                5,
                "/mutation/service_state_changed",
                serde_json::json!(true),
            ),
            (
                5,
                "/replays/0/producer_after/invocation_id",
                serde_json::json!("c".repeat(32)),
            ),
            (
                5,
                "/replays/0/controller_before/restarts",
                serde_json::json!(1),
            ),
            (
                5,
                "/replays/0/invocation_binding_stable",
                serde_json::json!(false),
            ),
            (
                6,
                "/cadence/observed_interval_seconds",
                serde_json::json!(1799),
            ),
            (
                6,
                "/cadence/previous_sample_recorded_at_utc",
                serde_json::json!("2026-10-19T02:00:00Z"),
            ),
            (
                5,
                "/replays/0/useful_work/last/terminal_slot",
                serde_json::json!(1001),
            ),
            (5, "/replays/0/useful_work/last/slot", serde_json::json!(1)),
            (
                6,
                "/replays/0/useful_work/last/slot",
                serde_json::json!(223),
            ),
            (
                6,
                "/replays/0/useful_work/slots_per_second",
                serde_json::json!(0),
            ),
            (
                6,
                "/recorded_at_utc",
                serde_json::json!("2026-10-19T02:32:00Z"),
            ),
        ] {
            let mut bad = values.clone();
            *bad[index].0.pointer_mut(pointer).unwrap() = replacement;
            assert!(check_fixture(&plan, &bad).is_err(), "accepted {pointer}");
        }
        let mut inputs: Vec<_> = plan
            .observations
            .iter()
            .zip(values.iter().filter(|(_, r)| *r))
            .map(|(e, (v, r))| (e, v.clone(), *r))
            .collect();
        // Omitting the declared bridge cannot silently repair the chain.
        assert!(validate_observation_values(&plan, inputs.clone()).is_err());
        inputs.swap(0, 1);
        assert!(validate_observation_values(&plan, inputs).is_err());
    }

    #[test]
    fn rejects_duplicate_and_leading_or_trailing_bridges() {
        let (plan, values) = fixture(true);
        let mut inputs: Vec<_> = plan
            .observations
            .iter()
            .zip(values.iter().filter(|(_, r)| *r))
            .map(|(e, (v, r))| (e, v.clone(), *r))
            .collect();
        inputs.push((&plan.observations[0], values[5].0.clone(), false));
        assert!(validate_observation_values(&plan, inputs).is_err());
        for timestamp in ["2026-10-18T23:59:00Z", "2026-10-19T03:00:00Z"] {
            let mut bad = values.clone();
            bad[5].0["recorded_at_utc"] = serde_json::json!(timestamp);
            assert!(check_fixture(&plan, &bad).is_err());
        }
    }

    #[test]
    fn utc_dates_are_canonical_and_real() {
        assert!(utc_seconds("2024-02-29T00:00:00Z").is_ok());
        for value in [
            "2026-02-29T00:00:00Z",
            "2026-04-31T00:00:00Z",
            "2026-10-19T24:00:00Z",
            "2026-10-19T00:00:60Z",
            "2026-10-19T0:00:00Z",
        ] {
            assert!(utc_seconds(value).is_err(), "accepted {value}");
        }
    }

    #[test]
    fn rejects_reordered_routine_list_even_if_chain_could_be_sorted() {
        let (plan, values) = fixture(false);
        let mut inputs: Vec<_> = plan
            .observations
            .iter()
            .zip(values)
            .map(|(e, (v, r))| (e, v, r))
            .collect();
        inputs.swap(1, 2);
        assert!(
            validate_observation_values(&plan, inputs)
                .unwrap_err()
                .contains("chronological")
        );
    }

    #[test]
    fn declared_file_digest_is_actually_authenticated() {
        let root = std::env::temp_dir().join(format!(
            "horizon-growth-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        let path = root.join("sample.json");
        let bytes = b"{\"schema\":\"test\"}";
        fs::write(&path, bytes).unwrap();
        let sha = hex(&Sha256::digest(bytes));
        assert!(read_json(&path, &sha).is_ok());
        assert!(read_json(&path, &"0".repeat(64)).is_err());
        fs::remove_file(path).unwrap();
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn formula_is_checked_and_conservative() {
        let minimum = compute_formula_minimum(90_878_533_632, 128_820_081_409, 2, 2).unwrap();
        assert_eq!(minimum, 439_397_230_082);
        assert!(512_u64 * GIB > minimum);
    }

    #[test]
    fn rejects_overflow() {
        assert!(compute_formula_minimum(u64::MAX, 1, 2, 2).is_err());
    }

    #[test]
    fn private_floor_requires_separate_full_ordered_and_plugin_proof() {
        let sha = "a".repeat(64);
        let receipt_sha = "b".repeat(64);
        let audit = serde_json::json!({"purpose":"century-floor-resource-audit-only",
            "local_sha256_and_etag_verified":true,"authenticated_ready_pair_revalidated":true,
            "archive_path":"/private/epoch-201.jet","archive_device":1,"archive_inode":2,
            "production_completion_authorized":false,"publication_authorized":false,
            "local_retirement_authorized":false,"remote_mutations":false,"r2_mutations":false});
        let stage =
            serde_json::json!({"status":"passed","exit_code":0,"sha256":sha,"log_sha256":sha});
        let verification = serde_json::json!({"schema":"jetstreamer-horizon-private-resource-verification-v1",
            "status":"passed","epoch":201,"archive_length":10,"archive_sha256":sha,
            "archive_path":"/private/epoch-201.jet","archive_device":1,"archive_inode":2,
            "resource_audit":"/private/resource-audit.json","resource_audit_sha256":receipt_sha,
            "archive_sha256_before_after_verified":true,"full_verifier":stage,
            "ordered_verifier":stage,"current_plugin":stage,
            "production_completion_authorized":false,"publication_authorized":false,
            "local_retirement_authorized":false,"remote_mutations":false,"r2_mutations":false});
        let check = |a: &Value, v: &Value| {
            validate_private_floor_verification(
                a,
                v,
                201,
                10,
                &sha,
                Path::new("/private/resource-audit.json"),
                &receipt_sha,
            )
        };
        check(&audit, &verification).unwrap();
        for key in ["full_verifier", "ordered_verifier", "current_plugin"] {
            let mut bad = verification.clone();
            bad[key]["status"] = serde_json::json!("failed");
            assert!(check(&audit, &bad).is_err());
        }
        for key in [
            "production_completion_authorized",
            "publication_authorized",
            "local_retirement_authorized",
            "r2_mutations",
            "remote_mutations",
        ] {
            let mut bad = verification.clone();
            bad[key] = serde_json::json!(true);
            assert!(check(&audit, &bad).is_err());
        }
        let mut bad = verification.clone();
        bad["archive_inode"] = serde_json::json!(3);
        assert!(check(&audit, &bad).is_err());
        let mut bad = audit.clone();
        bad["authenticated_ready_pair_revalidated"] = serde_json::json!(false);
        assert!(check(&bad, &verification).is_err());
    }

    #[test]
    fn invocation_ids_are_32_lowercase_hex_digits() {
        assert!(lowercase_invocation_id("0123456789abcdef0123456789abcdef", "invocation").is_ok());
        assert!(
            lowercase_invocation_id(
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "invocation"
            )
            .is_err()
        );
        assert!(lowercase_invocation_id("0123456789ABCDEF0123456789abcdef", "invocation").is_err());
    }
}
