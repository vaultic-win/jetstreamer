//! Derive deterministic Horizon sidecar ETAs from one identity-stable observer receipt.

use {
    anyhow::{Context, Result, ensure},
    serde::{Deserialize, Serialize},
    sha2::{Digest, Sha256},
    std::{
        collections::{BTreeMap, BTreeSet},
        env,
        fs::{self, OpenOptions},
        io::{Read, Write},
        os::unix::fs::{MetadataExt, OpenOptionsExt},
        path::{Path, PathBuf},
    },
};

const MODEL_SCHEMA_V1: &str = "jetstreamer-horizon-r2-status-eta-model-v1";
const MODEL_SCHEMA_V2: &str = "jetstreamer-horizon-r2-status-eta-model-v2";
const MODEL_SCHEMA_V3: &str = "jetstreamer-horizon-r2-status-eta-model-v3";
const MODEL_SCHEMA_V4: &str = "jetstreamer-horizon-r2-status-eta-model-v4";
const OBSERVER_SCHEMA: &str = "jetstreamer-horizon-live-resource-sample-v2";
const OUTPUT_SCHEMA_V1: &str = "jetstreamer-horizon-r2-status-estimates-v1";
const OUTPUT_SCHEMA_V2: &str = "jetstreamer-horizon-r2-status-estimates-v2";
const OUTPUT_SCHEMA_V3: &str = "jetstreamer-horizon-r2-status-estimates-v3";
const OUTPUT_SCHEMA_V4: &str = "jetstreamer-horizon-r2-status-estimates-v4";
const MAX_INPUT_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Debug)]
struct Arguments {
    model: PathBuf,
    model_sha256: String,
    observer: PathBuf,
    observer_sha256: String,
    self_sha256: String,
    output: PathBuf,
}

#[derive(Debug, Deserialize)]
struct Model {
    schema: String,
    sample_target_utc: String,
    phase: String,
    status_receipt_directory: PathBuf,
    #[serde(default)]
    status_receipt_directory_uid: Option<u32>,
    #[serde(default)]
    estimate_receipt_directory: Option<PathBuf>,
    #[serde(default)]
    expected_observer_ranges: Vec<String>,
    evidence: Vec<Evidence>,
    rounding: String,
    ranges: Vec<RangeModel>,
    validation: Validation,
    authority: Authority,
}

#[derive(Debug, Deserialize)]
struct Evidence {
    path: PathBuf,
    sha256: String,
}

#[derive(Debug, Deserialize)]
struct RangeModel {
    range: String,
    expected_controller_invocation_id: String,
    expected_producer_invocation_id: String,
    archive_directory: PathBuf,
    epochs: Vec<u64>,
    elapsed_execution_millis: u64,
    terminal_slot: u64,
    #[serde(default)]
    current_completion_overhead_seconds: Option<u64>,
    #[serde(default)]
    second_epoch_commit_offset_seconds: Option<u64>,
    #[serde(default)]
    next_pair_replay_seconds: Option<u64>,
    #[serde(default)]
    downstream_allowance_seconds: Option<u64>,
    #[serde(default)]
    epoch_additional_replay_slots: BTreeMap<String, u64>,
    #[serde(default)]
    epoch_downstream_allowance_seconds: BTreeMap<String, u64>,
    formula: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct Authority {
    publication_authorized_only_after_bound_v2_observer_receipt: bool,
    replay_launch_authorized: bool,
    archive_publication_authorized: bool,
    r2_archive_mutations_authorized: bool,
}

#[derive(Debug, Deserialize)]
struct Validation {
    #[serde(default)]
    prior_status_receipts_reproduced: bool,
    #[serde(default)]
    cohort_gate_evidence_validated: bool,
    #[serde(default)]
    prior_downstream_allowances_reused: bool,
    #[serde(default)]
    #[serde(rename = "matches_2026_10_17T04_17_00Z_statuses_within_one_second")]
    matches_2026_10_17_t04_17_00_z_statuses_within_one_second: bool,
    #[serde(default)]
    #[serde(rename = "reproduces_2026_10_17T04_47_00Z_statuses_exactly")]
    reproduces_2026_10_17_t04_47_00_z_statuses_exactly: bool,
}

#[derive(Debug, Deserialize)]
struct Observer {
    schema: String,
    recorded_at_utc: String,
    replays: Vec<Replay>,
}

#[derive(Debug, Deserialize)]
struct Replay {
    range: String,
    controller_after: Unit,
    producer_after: Unit,
    useful_work: UsefulWork,
    invocation_binding_stable: bool,
}

#[derive(Debug, Deserialize)]
struct Unit {
    invocation_id: String,
    restarts: u64,
    active_state: String,
    sub_state: String,
}

#[derive(Debug, Deserialize)]
struct UsefulWork {
    last: Option<ProgressPoint>,
    slots_per_second: Option<f64>,
    sufficient_for_rates: bool,
}

#[derive(Debug, Deserialize)]
struct ProgressPoint {
    slot: u64,
    terminal_slot: u64,
}

#[derive(Debug, Serialize)]
struct Output {
    schema: &'static str,
    sampled_at_utc: String,
    observer_path: String,
    observer_sha256: String,
    model_path: String,
    model_sha256: String,
    estimator_sha256: String,
    phase: String,
    status_receipt_directory: String,
    ranges: Vec<RangeOutput>,
    estimates: Vec<EpochEstimate>,
    mutations: Mutations,
}

#[derive(Debug, Serialize)]
struct RangeOutput {
    range: String,
    observed_last_slot: u64,
    terminal_slot: u64,
    slots_per_second: f64,
    current_completion_seconds: u64,
}

#[derive(Debug, Serialize)]
struct EpochEstimate {
    epoch: u64,
    archive_directory: String,
    expected_controller_invocation_id: String,
    expected_producer_invocation_id: String,
    elapsed_execution_millis: u64,
    estimated_remaining_millis: u64,
}

#[derive(Debug, Serialize)]
struct Mutations {
    replay_state_changed: bool,
    remote_mutations: bool,
    r2_mutations: bool,
}

fn usage(program: &str) -> String {
    format!(
        "usage: {program} --model PATH --model-sha256 HEX --observer PATH --observer-sha256 HEX --self-sha256 HEX --output PATH"
    )
}

fn parse_args() -> Result<Arguments> {
    let mut args = env::args_os();
    let program = args
        .next()
        .unwrap_or_else(|| "jetstreamer-horizon-status-estimate".into());
    let mut values = BTreeMap::<String, PathBuf>::new();
    while let Some(flag) = args.next() {
        let flag = flag
            .to_str()
            .context("arguments must be UTF-8")?
            .to_string();
        ensure!(
            matches!(
                flag.as_str(),
                "--model"
                    | "--model-sha256"
                    | "--observer"
                    | "--observer-sha256"
                    | "--self-sha256"
                    | "--output"
            ),
            "{}\nunknown option {flag}",
            usage(&program.to_string_lossy())
        );
        let value = args
            .next()
            .with_context(|| format!("missing value for {flag}"))?;
        ensure!(
            values.insert(flag, value.into()).is_none(),
            "duplicate option"
        );
    }
    let take = |name: &str| -> Result<PathBuf> {
        values
            .get(name)
            .cloned()
            .with_context(|| format!("missing {name}"))
    };
    Ok(Arguments {
        model: take("--model")?,
        model_sha256: take("--model-sha256")?.to_string_lossy().into_owned(),
        observer: take("--observer")?,
        observer_sha256: take("--observer-sha256")?.to_string_lossy().into_owned(),
        self_sha256: take("--self-sha256")?.to_string_lossy().into_owned(),
        output: take("--output")?,
    })
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn parse_range(value: &str) -> Result<BTreeSet<u64>> {
    let (start, end) = if let Some((start, end)) = value.split_once('-') {
        (start.parse::<u64>()?, end.parse::<u64>()?)
    } else {
        let epoch = value.parse::<u64>()?;
        (epoch, epoch)
    };
    ensure!(start <= end, "invalid modeled range");
    Ok((start..=end).collect())
}

fn read_exact(path: &Path, expected_sha256: &str, immutable_root_owned: bool) -> Result<Vec<u8>> {
    ensure!(
        path.is_absolute(),
        "path is not absolute: {}",
        path.display()
    );
    ensure!(
        path.canonicalize()? == path,
        "path is not exact: {}",
        path.display()
    );
    ensure!(valid_sha256(expected_sha256), "invalid expected SHA-256");
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("cannot open {}", path.display()))?;
    let before = file.metadata()?;
    ensure!(before.is_file(), "input is not a regular file");
    ensure!(before.nlink() == 1, "input is not singly linked");
    ensure!(before.len() <= MAX_INPUT_BYTES, "input exceeds size bound");
    if immutable_root_owned {
        ensure!(before.uid() == 0, "input is not root-owned");
        ensure!(before.mode() & 0o222 == 0, "input is writable");
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    (&mut file)
        .take(MAX_INPUT_BYTES + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 == before.len(), "input length changed");
    let after = file.metadata()?;
    let current = fs::symlink_metadata(path)?;
    let identity = |metadata: &fs::Metadata| {
        (
            metadata.dev(),
            metadata.ino(),
            metadata.len(),
            metadata.mtime(),
            metadata.mtime_nsec(),
        )
    };
    ensure!(
        current.is_file()
            && !current.file_type().is_symlink()
            && identity(&before) == identity(&after)
            && identity(&before) == identity(&current),
        "input changed while reading"
    );
    let actual = format!("{:x}", Sha256::digest(&bytes));
    ensure!(actual == expected_sha256, "input SHA-256 mismatch");
    Ok(bytes)
}

fn validate_model(model: &Model) -> Result<()> {
    ensure!(
        matches!(
            model.schema.as_str(),
            MODEL_SCHEMA_V1 | MODEL_SCHEMA_V2 | MODEL_SCHEMA_V3 | MODEL_SCHEMA_V4
        ),
        "model schema mismatch"
    );
    ensure!(model.phase == "replay", "model phase mismatch");
    ensure!(
        model.status_receipt_directory.is_absolute(),
        "status receipt directory is not absolute"
    );
    ensure!(
        model.rounding
            == "round each estimated total to the nearest whole second, then multiply by 1000",
        "model rounding policy mismatch"
    );
    ensure!(!model.evidence.is_empty(), "model lacks evidence");
    for evidence in &model.evidence {
        ensure!(
            evidence.path.is_absolute(),
            "model evidence path is not absolute"
        );
        ensure!(
            valid_sha256(&evidence.sha256),
            "model evidence SHA-256 is invalid"
        );
    }
    let legacy_validation = model
        .validation
        .matches_2026_10_17_t04_17_00_z_statuses_within_one_second
        && model
            .validation
            .reproduces_2026_10_17_t04_47_00_z_statuses_exactly;
    ensure!(
        if matches!(model.schema.as_str(), MODEL_SCHEMA_V2 | MODEL_SCHEMA_V3) {
            model.validation.prior_status_receipts_reproduced
        } else if model.schema == MODEL_SCHEMA_V4 {
            model.validation.cohort_gate_evidence_validated
                && model.validation.prior_downstream_allowances_reused
        } else {
            legacy_validation
        },
        "model validation evidence is incomplete"
    );
    ensure!(
        model
            .authority
            .publication_authorized_only_after_bound_v2_observer_receipt
            && !model.authority.replay_launch_authorized
            && !model.authority.archive_publication_authorized
            && !model.authority.r2_archive_mutations_authorized,
        "model authority is unsafe"
    );
    ensure!(!model.ranges.is_empty(), "model has no public ranges");
    if matches!(
        model.schema.as_str(),
        MODEL_SCHEMA_V2 | MODEL_SCHEMA_V3 | MODEL_SCHEMA_V4
    ) {
        let estimate_directory = model
            .estimate_receipt_directory
            .as_ref()
            .context("v2 model lacks estimate receipt directory")?;
        ensure!(
            estimate_directory.is_absolute(),
            "estimate receipt directory is not absolute"
        );
        ensure!(
            model.status_receipt_directory_uid.is_some(),
            "v2 model lacks status receipt directory owner"
        );
        ensure!(
            !model.expected_observer_ranges.is_empty(),
            "v2 model lacks observer census"
        );
        let expected: BTreeSet<_> = model
            .expected_observer_ranges
            .iter()
            .map(String::as_str)
            .collect();
        ensure!(
            expected.len() == model.expected_observer_ranges.len(),
            "v2 model observer census contains duplicates"
        );
    } else {
        ensure!(
            model.ranges.len() == 2,
            "expected exactly two public ranges"
        );
    }
    let mut ranges = BTreeSet::new();
    let mut epochs = BTreeSet::new();
    for range in &model.ranges {
        ensure!(
            ranges.insert(range.range.as_str()),
            "duplicate modeled range"
        );
        ensure!(!range.epochs.is_empty(), "modeled range has no epochs");
        ensure!(
            parse_range(&range.range)? == range.epochs.iter().copied().collect(),
            "modeled range does not match its epochs"
        );
        ensure!(
            range.archive_directory.is_absolute(),
            "modeled archive directory is not absolute"
        );
        if model.schema == MODEL_SCHEMA_V2 {
            ensure!(
                range.formula.len() == range.epochs.len(),
                "modeled range lacks formulas"
            );
            ensure!(
                range.downstream_allowance_seconds.is_some(),
                "modeled range lacks downstream allowance"
            );
            ensure!(
                range.epoch_additional_replay_slots.len() == range.epochs.len(),
                "modeled range lacks per-epoch replay offsets"
            );
            ensure!(
                range.current_completion_overhead_seconds.is_none()
                    && range.second_epoch_commit_offset_seconds.is_none()
                    && range.next_pair_replay_seconds.is_none(),
                "v2 model mixes legacy ETA fields"
            );
            ensure!(
                range.epoch_downstream_allowance_seconds.is_empty(),
                "v2 model mixes per-epoch downstream allowances"
            );
        } else if model.schema == MODEL_SCHEMA_V4 {
            ensure!(
                range.formula.len() == range.epochs.len(),
                "v4 modeled range lacks formulas"
            );
            ensure!(
                range.epoch_additional_replay_slots.len() == range.epochs.len(),
                "v4 modeled range lacks per-epoch replay offsets"
            );
            ensure!(
                range.epoch_downstream_allowance_seconds.len() == range.epochs.len(),
                "v4 modeled range lacks per-epoch downstream allowances"
            );
            ensure!(
                range.current_completion_overhead_seconds.is_none()
                    && range.second_epoch_commit_offset_seconds.is_none()
                    && range.next_pair_replay_seconds.is_none()
                    && range.downstream_allowance_seconds.is_none(),
                "v4 model mixes legacy or shared ETA fields"
            );
        } else {
            ensure!(
                range.epochs.len() == 4,
                "legacy range must contain four epochs"
            );
            ensure!(
                range.current_completion_overhead_seconds.is_some()
                    && range.second_epoch_commit_offset_seconds.is_some()
                    && range.next_pair_replay_seconds.is_some()
                    && range.downstream_allowance_seconds.is_none()
                    && range.epoch_additional_replay_slots.is_empty()
                    && range.epoch_downstream_allowance_seconds.is_empty(),
                "legacy modeled range lacks ETA fields"
            );
        }
        ensure!(
            range.expected_controller_invocation_id.len() == 32
                && range
                    .expected_controller_invocation_id
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit())
                && range.expected_producer_invocation_id.len() == 32
                && range
                    .expected_producer_invocation_id
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit()),
            "invalid modeled invocation ID"
        );
        for epoch in &range.epochs {
            ensure!(epochs.insert(*epoch), "duplicate modeled epoch");
            ensure!(
                range.formula.contains_key(&epoch.to_string()),
                "missing epoch formula"
            );
            if matches!(model.schema.as_str(), MODEL_SCHEMA_V2 | MODEL_SCHEMA_V4) {
                ensure!(
                    range
                        .epoch_additional_replay_slots
                        .contains_key(&epoch.to_string()),
                    "missing epoch replay offset"
                );
            }
            if model.schema == MODEL_SCHEMA_V4 {
                ensure!(
                    range
                        .epoch_downstream_allowance_seconds
                        .contains_key(&epoch.to_string()),
                    "missing epoch downstream allowance"
                );
            }
        }
    }
    if model.schema == MODEL_SCHEMA_V1 {
        ensure!(
            epochs == (216..=223).collect(),
            "model does not cover exactly epochs 216-223"
        );
    }
    if matches!(
        model.schema.as_str(),
        MODEL_SCHEMA_V2 | MODEL_SCHEMA_V3 | MODEL_SCHEMA_V4
    ) {
        let expected: BTreeSet<_> = model
            .expected_observer_ranges
            .iter()
            .map(String::as_str)
            .collect();
        ensure!(
            ranges.iter().all(|range| expected.contains(range)),
            "modeled range is absent from observer census"
        );
    }
    Ok(())
}

fn estimate_range(
    model: &RangeModel,
    replay: &Replay,
    model_schema: &str,
) -> Result<(RangeOutput, Vec<EpochEstimate>)> {
    ensure!(replay.range == model.range, "range mismatch");
    ensure!(
        replay.invocation_binding_stable,
        "observer binding is not stable"
    );
    for unit in [&replay.controller_after, &replay.producer_after] {
        ensure!(unit.restarts == 0, "observed unit restarted");
        ensure!(
            unit.active_state == "active" && unit.sub_state == "running",
            "observed unit is not running"
        );
    }
    ensure!(
        replay.controller_after.invocation_id == model.expected_controller_invocation_id,
        "controller invocation mismatch"
    );
    ensure!(
        replay.producer_after.invocation_id == model.expected_producer_invocation_id,
        "producer invocation mismatch"
    );
    ensure!(
        replay.useful_work.sufficient_for_rates,
        "observer rate is insufficient"
    );
    let last = replay
        .useful_work
        .last
        .as_ref()
        .context("observer lacks last progress point")?;
    let rate = replay
        .useful_work
        .slots_per_second
        .context("observer lacks slot rate")?;
    ensure!(
        rate.is_finite() && rate > 0.0,
        "observer slot rate is invalid"
    );
    ensure!(
        last.terminal_slot == model.terminal_slot,
        "terminal slot mismatch"
    );
    ensure!(
        last.slot <= model.terminal_slot,
        "observed slot exceeds terminal"
    );
    let remaining_slots = model.terminal_slot - last.slot;
    let values = if model_schema == MODEL_SCHEMA_V2 {
        model
            .epochs
            .iter()
            .map(|epoch| {
                let additional_slots = model
                    .epoch_additional_replay_slots
                    .get(&epoch.to_string())
                    .copied()
                    .context("missing epoch replay offset")?;
                let seconds = (((remaining_slots
                    .checked_add(additional_slots)
                    .context("slot ETA overflow")?) as f64
                    / rate)
                    + model
                        .downstream_allowance_seconds
                        .context("missing downstream allowance")? as f64)
                    .round();
                ensure!(seconds.is_finite() && seconds >= 0.0, "ETA is invalid");
                Ok(seconds as u64)
            })
            .collect::<Result<Vec<_>>>()?
    } else if model_schema == MODEL_SCHEMA_V4 {
        model
            .epochs
            .iter()
            .map(|epoch| {
                let key = epoch.to_string();
                let additional_slots = model
                    .epoch_additional_replay_slots
                    .get(&key)
                    .copied()
                    .context("missing epoch replay offset")?;
                let downstream_seconds = model
                    .epoch_downstream_allowance_seconds
                    .get(&key)
                    .copied()
                    .context("missing epoch downstream allowance")?;
                let seconds = (((remaining_slots
                    .checked_add(additional_slots)
                    .context("slot ETA overflow")?) as f64
                    / rate)
                    + downstream_seconds as f64)
                    .round();
                ensure!(seconds.is_finite() && seconds >= 0.0, "ETA is invalid");
                Ok(seconds as u64)
            })
            .collect::<Result<Vec<_>>>()?
    } else {
        let first_seconds = ((remaining_slots as f64 / rate)
            + model
                .current_completion_overhead_seconds
                .context("missing current completion overhead")? as f64)
            .round();
        ensure!(
            first_seconds.is_finite() && first_seconds >= 0.0,
            "ETA is invalid"
        );
        let first = first_seconds as u64;
        vec![
            first,
            first
                .checked_add(
                    model
                        .second_epoch_commit_offset_seconds
                        .context("missing second epoch offset")?,
                )
                .context("ETA overflow")?,
            first
                .checked_add(
                    model
                        .next_pair_replay_seconds
                        .context("missing next pair replay time")?,
                )
                .context("ETA overflow")?,
            first
                .checked_add(
                    model
                        .next_pair_replay_seconds
                        .context("missing next pair replay time")?,
                )
                .and_then(|value| value.checked_add(model.second_epoch_commit_offset_seconds?))
                .context("ETA overflow")?,
        ]
    };
    let first = values
        .first()
        .copied()
        .context("modeled range has no ETA")?;
    let estimates = model
        .epochs
        .iter()
        .zip(values)
        .map(|(epoch, seconds)| {
            Ok(EpochEstimate {
                epoch: *epoch,
                archive_directory: model.archive_directory.display().to_string(),
                expected_controller_invocation_id: model.expected_controller_invocation_id.clone(),
                expected_producer_invocation_id: model.expected_producer_invocation_id.clone(),
                elapsed_execution_millis: model.elapsed_execution_millis,
                estimated_remaining_millis: seconds
                    .checked_mul(1000)
                    .context("millisecond overflow")?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok((
        RangeOutput {
            range: model.range.clone(),
            observed_last_slot: last.slot,
            terminal_slot: model.terminal_slot,
            slots_per_second: rate,
            current_completion_seconds: first,
        },
        estimates,
    ))
}

fn validate_output_path(path: &Path, model: &Model) -> Result<()> {
    let expected_parent = model
        .estimate_receipt_directory
        .as_deref()
        .unwrap_or_else(|| Path::new("/home/ubuntu/workspace/jetstreamer/.codex/tmp-readiness"));
    ensure!(
        path.parent() == Some(expected_parent),
        "unexpected output parent"
    );
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("invalid output filename")?;
    ensure!(
        name.starts_with("horizon-r2-status-estimates-") && name.ends_with(".json"),
        "unexpected output filename"
    );
    Ok(())
}

fn fsync_directory(path: &Path) -> Result<()> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY)
        .open(path)?
        .sync_all()?;
    Ok(())
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("cannot create {}", path.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fsync_directory(path.parent().context("output has no parent")?)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn run() -> Result<()> {
    let arguments = parse_args()?;
    let executable = fs::read_link("/proc/self/exe")?;
    read_exact(&executable, &arguments.self_sha256, true)?;
    let model_bytes = read_exact(&arguments.model, &arguments.model_sha256, true)?;
    let observer_bytes = read_exact(&arguments.observer, &arguments.observer_sha256, false)?;
    let model: Model = serde_json::from_slice(&model_bytes).context("invalid model JSON")?;
    let observer: Observer =
        serde_json::from_slice(&observer_bytes).context("invalid observer JSON")?;
    validate_model(&model)?;
    validate_output_path(&arguments.output, &model)?;
    if let Some(estimate_directory) = &model.estimate_receipt_directory {
        ensure!(
            estimate_directory.canonicalize()? == *estimate_directory,
            "estimate receipt directory path is not exact"
        );
        let metadata = fs::symlink_metadata(estimate_directory)?;
        ensure!(
            metadata.is_dir() && metadata.uid() == 0 && metadata.mode() & 0o7777 == 0o700,
            "estimate receipt directory identity or mode mismatch"
        );
    }
    ensure!(
        model.status_receipt_directory.canonicalize()? == model.status_receipt_directory,
        "status receipt directory path is not exact"
    );
    let receipt_directory_metadata = fs::symlink_metadata(&model.status_receipt_directory)?;
    let expected_receipt_uid = if matches!(
        model.schema.as_str(),
        MODEL_SCHEMA_V2 | MODEL_SCHEMA_V3 | MODEL_SCHEMA_V4
    ) {
        model
            .status_receipt_directory_uid
            .context("missing status receipt directory owner")?
    } else {
        0
    };
    ensure!(
        receipt_directory_metadata.is_dir()
            && receipt_directory_metadata.uid() == expected_receipt_uid
            && receipt_directory_metadata.mode() & 0o7777 == 0o700,
        "status receipt directory identity or mode mismatch"
    );
    for evidence in &model.evidence {
        read_exact(&evidence.path, &evidence.sha256, false)
            .with_context(|| format!("model evidence failed: {}", evidence.path.display()))?;
    }
    ensure!(
        observer.schema == OBSERVER_SCHEMA,
        "observer schema mismatch"
    );
    ensure!(
        observer.recorded_at_utc == model.sample_target_utc,
        "observer timestamp mismatch"
    );
    if matches!(
        model.schema.as_str(),
        MODEL_SCHEMA_V2 | MODEL_SCHEMA_V3 | MODEL_SCHEMA_V4
    ) {
        let expected: BTreeSet<_> = model.expected_observer_ranges.iter().collect();
        let observed: BTreeSet<_> = observer
            .replays
            .iter()
            .map(|replay| &replay.range)
            .collect();
        ensure!(
            expected.len() == model.expected_observer_ranges.len() && expected == observed,
            "observer replay census mismatch"
        );
    } else {
        ensure!(
            observer.replays.len() == 3,
            "observer replay census mismatch"
        );
    }

    let mut ranges = Vec::new();
    let mut estimates = Vec::new();
    for range_model in &model.ranges {
        ensure!(
            range_model.archive_directory.canonicalize()? == range_model.archive_directory,
            "archive directory path is not exact"
        );
        ensure!(
            fs::symlink_metadata(&range_model.archive_directory)?.is_dir(),
            "archive directory is not a directory"
        );
        let matches: Vec<_> = observer
            .replays
            .iter()
            .filter(|replay| replay.range == range_model.range)
            .collect();
        ensure!(
            matches.len() == 1,
            "observer range is missing or duplicated"
        );
        let (range, mut range_estimates) = estimate_range(range_model, matches[0], &model.schema)?;
        ranges.push(range);
        estimates.append(&mut range_estimates);
    }
    estimates.sort_by_key(|item| item.epoch);
    let output = Output {
        schema: match model.schema.as_str() {
            MODEL_SCHEMA_V2 => OUTPUT_SCHEMA_V2,
            MODEL_SCHEMA_V3 => OUTPUT_SCHEMA_V3,
            MODEL_SCHEMA_V4 => OUTPUT_SCHEMA_V4,
            _ => OUTPUT_SCHEMA_V1,
        },
        sampled_at_utc: observer.recorded_at_utc,
        observer_path: arguments.observer.display().to_string(),
        observer_sha256: arguments.observer_sha256,
        model_path: arguments.model.display().to_string(),
        model_sha256: arguments.model_sha256,
        estimator_sha256: arguments.self_sha256,
        phase: model.phase,
        status_receipt_directory: model.status_receipt_directory.display().to_string(),
        ranges,
        estimates,
        mutations: Mutations {
            replay_state_changed: false,
            remote_mutations: false,
            r2_mutations: false,
        },
    };
    let mut bytes = serde_json::to_vec_pretty(&output)?;
    bytes.push(b'\n');
    let digest = write_new(&arguments.output, &bytes)?;
    println!(
        "{}",
        serde_json::json!({"path": arguments.output, "sha256": digest})
    );
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unit(invocation_id: &str) -> Unit {
        Unit {
            invocation_id: invocation_id.to_string(),
            restarts: 0,
            active_state: "active".to_string(),
            sub_state: "running".to_string(),
        }
    }

    #[test]
    fn reproduces_latest_lane_216_estimates() {
        let controller = "2b6ded8d8baf4f72a5c8a91385f7c278";
        let producer = "95fb05d1b78349bcb907c1e930e7682e";
        let model = RangeModel {
            range: "216-219".to_string(),
            expected_controller_invocation_id: controller.to_string(),
            expected_producer_invocation_id: producer.to_string(),
            archive_directory: "/tmp/lane-216-output".into(),
            epochs: vec![216, 217, 218, 219],
            elapsed_execution_millis: 336_638_000,
            terminal_slot: 94_175_999,
            current_completion_overhead_seconds: Some(10_230),
            second_epoch_commit_offset_seconds: Some(2_442),
            next_pair_replay_seconds: Some(347_843),
            downstream_allowance_seconds: None,
            epoch_additional_replay_slots: BTreeMap::new(),
            epoch_downstream_allowance_seconds: BTreeMap::new(),
            formula: (216..=219)
                .map(|epoch| (epoch.to_string(), "bound".to_string()))
                .collect(),
        };
        let replay = Replay {
            range: model.range.clone(),
            controller_after: unit(controller),
            producer_after: unit(producer),
            useful_work: UsefulWork {
                last: Some(ProgressPoint {
                    slot: 94_145_814,
                    terminal_slot: 94_175_999,
                }),
                slots_per_second: Some(2.8857456247679627),
                sufficient_for_rates: true,
            },
            invocation_binding_stable: true,
        };
        let (_, estimates) = estimate_range(&model, &replay, MODEL_SCHEMA_V1).unwrap();
        assert!(
            estimates
                .iter()
                .all(|item| item.elapsed_execution_millis == 336_638_000)
        );
        assert!(estimates.iter().all(|item| {
            item.archive_directory == "/tmp/lane-216-output"
                && item.expected_controller_invocation_id == controller
                && item.expected_producer_invocation_id == producer
        }));
        assert_eq!(
            estimates
                .iter()
                .map(|item| item.estimated_remaining_millis)
                .collect::<Vec<_>>(),
            vec![20_690_000, 23_132_000, 368_533_000, 370_975_000]
        );
    }

    #[test]
    fn rejects_identity_change() {
        let model = RangeModel {
            range: "220-223".to_string(),
            expected_controller_invocation_id: "0".repeat(32),
            expected_producer_invocation_id: "1".repeat(32),
            archive_directory: "/tmp/lane-220-output".into(),
            epochs: vec![220, 221, 222, 223],
            elapsed_execution_millis: 214_176_000,
            terminal_slot: 95_903_999,
            current_completion_overhead_seconds: Some(8_779),
            second_epoch_commit_offset_seconds: Some(2_442),
            next_pair_replay_seconds: Some(334_084),
            downstream_allowance_seconds: None,
            epoch_additional_replay_slots: BTreeMap::new(),
            epoch_downstream_allowance_seconds: BTreeMap::new(),
            formula: (220..=223)
                .map(|epoch| (epoch.to_string(), "bound".to_string()))
                .collect(),
        };
        let replay = Replay {
            range: model.range.clone(),
            controller_after: unit(&"f".repeat(32)),
            producer_after: unit(&"1".repeat(32)),
            useful_work: UsefulWork {
                last: Some(ProgressPoint {
                    slot: 95_592_968,
                    terminal_slot: 95_903_999,
                }),
                slots_per_second: Some(2.5149505547550577),
                sufficient_for_rates: true,
            },
            invocation_binding_stable: true,
        };
        assert!(estimate_range(&model, &replay, MODEL_SCHEMA_V1).is_err());
    }

    #[test]
    fn reproduces_latest_lane_220_estimates() {
        let controller = "0b69b5009dc74bbda94b94d059a3daa7";
        let producer = "c2adebaad0cb42b385156631156813fe";
        let model = RangeModel {
            range: "220-223".to_string(),
            expected_controller_invocation_id: controller.to_string(),
            expected_producer_invocation_id: producer.to_string(),
            archive_directory: "/tmp/lane-220-output".into(),
            epochs: vec![220, 221, 222, 223],
            elapsed_execution_millis: 214_176_000,
            terminal_slot: 95_903_999,
            current_completion_overhead_seconds: Some(8_779),
            second_epoch_commit_offset_seconds: Some(2_442),
            next_pair_replay_seconds: Some(334_084),
            downstream_allowance_seconds: None,
            epoch_additional_replay_slots: BTreeMap::new(),
            epoch_downstream_allowance_seconds: BTreeMap::new(),
            formula: (220..=223)
                .map(|epoch| (epoch.to_string(), "bound".to_string()))
                .collect(),
        };
        let replay = Replay {
            range: model.range.clone(),
            controller_after: unit(controller),
            producer_after: unit(producer),
            useful_work: UsefulWork {
                last: Some(ProgressPoint {
                    slot: 95_592_968,
                    terminal_slot: 95_903_999,
                }),
                slots_per_second: Some(2.5149505547550577),
                sufficient_for_rates: true,
            },
            invocation_binding_stable: true,
        };
        let (_, estimates) = estimate_range(&model, &replay, MODEL_SCHEMA_V1).unwrap();
        assert_eq!(
            estimates
                .iter()
                .map(|item| item.estimated_remaining_millis)
                .collect::<Vec<_>>(),
            vec![132_452_000, 134_894_000, 466_536_000, 468_978_000]
        );
    }

    #[test]
    fn derives_variable_length_v2_range_from_bound_slot_offsets() {
        let controller = "2".repeat(32);
        let producer = "3".repeat(32);
        let model = RangeModel {
            range: "136-138".to_string(),
            expected_controller_invocation_id: controller.clone(),
            expected_producer_invocation_id: producer.clone(),
            archive_directory: "/tmp/lane-output".into(),
            epochs: vec![136, 137, 138],
            elapsed_execution_millis: 1_000,
            terminal_slot: 2_000,
            current_completion_overhead_seconds: None,
            second_epoch_commit_offset_seconds: None,
            next_pair_replay_seconds: None,
            downstream_allowance_seconds: Some(100),
            epoch_additional_replay_slots: [
                ("136".to_string(), 0),
                ("137".to_string(), 432_000),
                ("138".to_string(), 864_000),
            ]
            .into_iter()
            .collect(),
            epoch_downstream_allowance_seconds: BTreeMap::new(),
            formula: (136..=138)
                .map(|epoch| (epoch.to_string(), "bound".to_string()))
                .collect(),
        };
        let replay = Replay {
            range: model.range.clone(),
            controller_after: unit(&controller),
            producer_after: unit(&producer),
            useful_work: UsefulWork {
                last: Some(ProgressPoint {
                    slot: 1_800,
                    terminal_slot: 2_000,
                }),
                slots_per_second: Some(2.0),
                sufficient_for_rates: true,
            },
            invocation_binding_stable: true,
        };
        let (range, estimates) = estimate_range(&model, &replay, MODEL_SCHEMA_V2).unwrap();
        assert_eq!(range.current_completion_seconds, 200);
        assert_eq!(
            estimates
                .iter()
                .map(|estimate| estimate.estimated_remaining_millis)
                .collect::<Vec<_>>(),
            vec![200_000, 216_200_000, 432_200_000]
        );
    }

    #[test]
    fn v4_keeps_completed_prefix_epochs_behind_the_cohort_gate() {
        let controller = "4".repeat(32);
        let producer = "5".repeat(32);
        let model = RangeModel {
            range: "216-219".to_string(),
            expected_controller_invocation_id: controller.clone(),
            expected_producer_invocation_id: producer.clone(),
            archive_directory: "/tmp/lane-output".into(),
            epochs: vec![216, 217, 218, 219],
            elapsed_execution_millis: 1_000,
            terminal_slot: 2_000,
            current_completion_overhead_seconds: None,
            second_epoch_commit_offset_seconds: None,
            next_pair_replay_seconds: None,
            downstream_allowance_seconds: None,
            epoch_additional_replay_slots: (216..=219)
                .map(|epoch| (epoch.to_string(), 1_000))
                .collect(),
            epoch_downstream_allowance_seconds: [
                ("216".to_string(), 100),
                ("217".to_string(), 110),
                ("218".to_string(), 120),
                ("219".to_string(), 130),
            ]
            .into_iter()
            .collect(),
            formula: (216..=219)
                .map(|epoch| (epoch.to_string(), "cohort-gated".to_string()))
                .collect(),
        };
        let replay = Replay {
            range: model.range.clone(),
            controller_after: unit(&controller),
            producer_after: unit(&producer),
            useful_work: UsefulWork {
                last: Some(ProgressPoint {
                    slot: 1_800,
                    terminal_slot: 2_000,
                }),
                slots_per_second: Some(2.0),
                sufficient_for_rates: true,
            },
            invocation_binding_stable: true,
        };
        let (range, estimates) = estimate_range(&model, &replay, MODEL_SCHEMA_V4).unwrap();
        assert_eq!(range.current_completion_seconds, 700);
        assert_eq!(
            estimates
                .iter()
                .map(|estimate| estimate.estimated_remaining_millis)
                .collect::<Vec<_>>(),
            vec![700_000, 710_000, 720_000, 730_000]
        );
    }

    #[test]
    fn v4_validation_requires_complete_per_epoch_allowances() {
        let range = RangeModel {
            range: "216-219".to_string(),
            expected_controller_invocation_id: "4".repeat(32),
            expected_producer_invocation_id: "5".repeat(32),
            archive_directory: "/tmp/lane-output".into(),
            epochs: vec![216, 217, 218, 219],
            elapsed_execution_millis: 1_000,
            terminal_slot: 2_000,
            current_completion_overhead_seconds: None,
            second_epoch_commit_offset_seconds: None,
            next_pair_replay_seconds: None,
            downstream_allowance_seconds: None,
            epoch_additional_replay_slots: (216..=219)
                .map(|epoch| (epoch.to_string(), 1_000))
                .collect(),
            epoch_downstream_allowance_seconds: (216..=219)
                .map(|epoch| (epoch.to_string(), 100))
                .collect(),
            formula: (216..=219)
                .map(|epoch| (epoch.to_string(), "cohort-gated".to_string()))
                .collect(),
        };
        let mut model = Model {
            schema: MODEL_SCHEMA_V4.to_string(),
            sample_target_utc: "2026-10-17T08:47:00Z".to_string(),
            phase: "replay".to_string(),
            status_receipt_directory: "/tmp/status-receipts".into(),
            status_receipt_directory_uid: Some(0),
            estimate_receipt_directory: Some("/tmp/estimate-receipts".into()),
            expected_observer_ranges: vec![
                "216-219".to_string(),
                "220-223".to_string(),
                "206-206".to_string(),
            ],
            evidence: vec![Evidence {
                path: "/tmp/previous-estimate.json".into(),
                sha256: "a".repeat(64),
            }],
            rounding:
                "round each estimated total to the nearest whole second, then multiply by 1000"
                    .to_string(),
            ranges: vec![range],
            validation: Validation {
                prior_status_receipts_reproduced: true,
                cohort_gate_evidence_validated: true,
                prior_downstream_allowances_reused: true,
                matches_2026_10_17_t04_17_00_z_statuses_within_one_second: false,
                reproduces_2026_10_17_t04_47_00_z_statuses_exactly: false,
            },
            authority: Authority {
                publication_authorized_only_after_bound_v2_observer_receipt: true,
                replay_launch_authorized: false,
                archive_publication_authorized: false,
                r2_archive_mutations_authorized: false,
            },
        };
        validate_model(&model).unwrap();
        model.ranges[0]
            .epoch_downstream_allowance_seconds
            .remove("219");
        assert!(validate_model(&model).is_err());
    }

    #[test]
    fn reproduces_previous_sample_for_both_lanes() {
        let cases = [
            (
                RangeModel {
                    range: "216-219".to_string(),
                    expected_controller_invocation_id: "2b6ded8d8baf4f72a5c8a91385f7c278"
                        .to_string(),
                    expected_producer_invocation_id: "95fb05d1b78349bcb907c1e930e7682e".to_string(),
                    archive_directory: "/tmp/lane-216-output".into(),
                    epochs: vec![216, 217, 218, 219],
                    elapsed_execution_millis: 334_838_000,
                    terminal_slot: 94_175_999,
                    current_completion_overhead_seconds: Some(10_230),
                    second_epoch_commit_offset_seconds: Some(2_442),
                    next_pair_replay_seconds: Some(347_843),
                    downstream_allowance_seconds: None,
                    epoch_additional_replay_slots: BTreeMap::new(),
                    epoch_downstream_allowance_seconds: BTreeMap::new(),
                    formula: (216..=219)
                        .map(|epoch| (epoch.to_string(), "bound".to_string()))
                        .collect(),
                },
                94_140_628,
                2.759349388074035,
                vec![23_048_000, 25_490_000, 370_891_000, 373_333_000],
            ),
            (
                RangeModel {
                    range: "220-223".to_string(),
                    expected_controller_invocation_id: "0b69b5009dc74bbda94b94d059a3daa7"
                        .to_string(),
                    expected_producer_invocation_id: "c2adebaad0cb42b385156631156813fe".to_string(),
                    archive_directory: "/tmp/lane-220-output".into(),
                    epochs: vec![220, 221, 222, 223],
                    elapsed_execution_millis: 212_376_000,
                    terminal_slot: 95_903_999,
                    current_completion_overhead_seconds: Some(8_779),
                    second_epoch_commit_offset_seconds: Some(2_442),
                    next_pair_replay_seconds: Some(334_084),
                    downstream_allowance_seconds: None,
                    epoch_additional_replay_slots: BTreeMap::new(),
                    epoch_downstream_allowance_seconds: BTreeMap::new(),
                    formula: (220..=223)
                        .map(|epoch| (epoch.to_string(), "bound".to_string()))
                        .collect(),
                },
                95_588_448,
                2.5660109198403633,
                vec![131_752_000, 134_194_000, 465_836_000, 468_278_000],
            ),
        ];
        for (model, slot, rate, expected) in cases {
            let replay = Replay {
                range: model.range.clone(),
                controller_after: unit(&model.expected_controller_invocation_id),
                producer_after: unit(&model.expected_producer_invocation_id),
                useful_work: UsefulWork {
                    last: Some(ProgressPoint {
                        slot,
                        terminal_slot: model.terminal_slot,
                    }),
                    slots_per_second: Some(rate),
                    sufficient_for_rates: true,
                },
                invocation_binding_stable: true,
            };
            let (_, estimates) = estimate_range(&model, &replay, MODEL_SCHEMA_V1).unwrap();
            for (actual, expected) in estimates
                .iter()
                .map(|item| item.estimated_remaining_millis)
                .zip(expected)
            {
                assert!(actual.abs_diff(expected) <= 1_000);
            }
        }
    }

    #[test]
    fn v3_accepts_one_healthy_legacy_range_with_complete_observer_census() {
        let model = Model {
            schema: MODEL_SCHEMA_V3.to_owned(),
            sample_target_utc: "2026-10-17T08:17:00Z".to_owned(),
            phase: "replay".to_owned(),
            status_receipt_directory: "/tmp/status-receipts".into(),
            status_receipt_directory_uid: Some(0),
            estimate_receipt_directory: Some("/tmp/estimate-receipts".into()),
            expected_observer_ranges: vec![
                "216-219".to_owned(),
                "220-223".to_owned(),
                "206-206".to_owned(),
            ],
            evidence: vec![Evidence {
                path: "/tmp/previous-observer.json".into(),
                sha256: "a".repeat(64),
            }],
            rounding:
                "round each estimated total to the nearest whole second, then multiply by 1000"
                    .to_owned(),
            ranges: vec![RangeModel {
                range: "220-223".to_owned(),
                expected_controller_invocation_id: "b".repeat(32),
                expected_producer_invocation_id: "c".repeat(32),
                archive_directory: "/tmp/lane-output".into(),
                epochs: vec![220, 221, 222, 223],
                elapsed_execution_millis: 1,
                terminal_slot: 95_903_999,
                current_completion_overhead_seconds: Some(8_779),
                second_epoch_commit_offset_seconds: Some(2_442),
                next_pair_replay_seconds: Some(334_084),
                downstream_allowance_seconds: None,
                epoch_additional_replay_slots: BTreeMap::new(),
                epoch_downstream_allowance_seconds: BTreeMap::new(),
                formula: (220..=223)
                    .map(|epoch| (epoch.to_string(), "bound".to_owned()))
                    .collect(),
            }],
            validation: Validation {
                prior_status_receipts_reproduced: true,
                cohort_gate_evidence_validated: false,
                prior_downstream_allowances_reused: false,
                matches_2026_10_17_t04_17_00_z_statuses_within_one_second: false,
                reproduces_2026_10_17_t04_47_00_z_statuses_exactly: false,
            },
            authority: Authority {
                publication_authorized_only_after_bound_v2_observer_receipt: true,
                replay_launch_authorized: false,
                archive_publication_authorized: false,
                r2_archive_mutations_authorized: false,
            },
        };
        validate_model(&model).unwrap();
    }

    #[test]
    fn v3_rejects_modeled_range_absent_from_observer_census() {
        let model = Model {
            schema: MODEL_SCHEMA_V3.to_owned(),
            sample_target_utc: "2026-10-17T08:17:00Z".to_owned(),
            phase: "replay".to_owned(),
            status_receipt_directory: "/tmp/status-receipts".into(),
            status_receipt_directory_uid: Some(0),
            estimate_receipt_directory: Some("/tmp/estimate-receipts".into()),
            expected_observer_ranges: vec!["216-219".to_owned(), "206-206".to_owned()],
            evidence: vec![Evidence {
                path: "/tmp/previous-observer.json".into(),
                sha256: "a".repeat(64),
            }],
            rounding:
                "round each estimated total to the nearest whole second, then multiply by 1000"
                    .to_owned(),
            ranges: vec![RangeModel {
                range: "220-223".to_owned(),
                expected_controller_invocation_id: "b".repeat(32),
                expected_producer_invocation_id: "c".repeat(32),
                archive_directory: "/tmp/lane-output".into(),
                epochs: vec![220, 221, 222, 223],
                elapsed_execution_millis: 1,
                terminal_slot: 95_903_999,
                current_completion_overhead_seconds: Some(8_779),
                second_epoch_commit_offset_seconds: Some(2_442),
                next_pair_replay_seconds: Some(334_084),
                downstream_allowance_seconds: None,
                epoch_additional_replay_slots: BTreeMap::new(),
                epoch_downstream_allowance_seconds: BTreeMap::new(),
                formula: (220..=223)
                    .map(|epoch| (epoch.to_string(), "bound".to_owned()))
                    .collect(),
            }],
            validation: Validation {
                prior_status_receipts_reproduced: true,
                cohort_gate_evidence_validated: false,
                prior_downstream_allowances_reused: false,
                matches_2026_10_17_t04_17_00_z_statuses_within_one_second: false,
                reproduces_2026_10_17_t04_47_00_z_statuses_exactly: false,
            },
            authority: Authority {
                publication_authorized_only_after_bound_v2_observer_receipt: true,
                replay_launch_authorized: false,
                archive_publication_authorized: false,
                r2_archive_mutations_authorized: false,
            },
        };
        assert!(validate_model(&model).is_err());
    }

    #[test]
    fn output_writer_is_private_durable_and_no_clobber() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("estimate.json");
        let bytes = b"{\"ok\":true}\n";
        let digest = write_new(&path, bytes).unwrap();
        assert_eq!(digest, format!("{:x}", Sha256::digest(bytes)));
        let metadata = fs::symlink_metadata(&path).unwrap();
        assert!(metadata.is_file());
        assert_eq!(metadata.mode() & 0o7777, 0o400);
        assert!(write_new(&path, b"replacement\n").is_err());
        assert_eq!(fs::read(path).unwrap(), bytes);
    }
}
