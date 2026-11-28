use super::*;
mod exit;
mod predecessor;
mod window230;
mod window266;
use anyhow::bail;
use jetstreamer_horizon::archive::{BlockNotification, Consumption, EntryRecord, SlotVisitor};
use segment_manifest::{SegmentManifestError, read_and_validate_seekable_segment_manifest};
use std::{
    collections::BTreeMap,
    ffi::CString,
    fs::{self, OpenOptions},
    io::{BufReader, Write},
    num::NonZeroUsize,
    os::unix::{
        ffi::OsStrExt,
        fs::{OpenOptionsExt, PermissionsExt},
    },
    process::Command,
};

const PROFILE_SHA: &str = "494849a05eb8b63f1770c5ae54dc63a1cc1dfadbd09b235c3938ee28393d08ea";
const PREFLIGHT_SHA: &str = "1e014dac29ed075242cccd2d226c75a3088712540a90a7358b1cecee4df04b65";
const TOKEN_ROOT: &str = "/var/lib/jetstreamer/horizon266-hourly-overlap-114929697-tokens-v1";
const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const UNIT_STARTING: &str = "7d4958e842da4a758f6c1cdc7b36dcc5";
const UNIT_STARTED: &str = "39f53479d3a045ac8e11786248231fbf";
const UNIT_SUCCESS: &str = "7ad2d189f7e94e70a38c781354912448";
const UNIT_RESOURCES: &str = "ae8f7b866b0347b9af31fe1c80b127c0";

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Reference {
    path: PathBuf,
    sha256: String,
}

impl Reference {
    fn new(path: impl Into<PathBuf>, sha256: &str) -> Self {
        Self {
            path: path.into(),
            sha256: sha256.to_owned(),
        }
    }

    fn read(&self) -> Result<Value> {
        Ok(serde_json::from_slice(&bound_bytes(
            &self.path,
            &self.sha256,
            JSON_LIMIT,
            true,
        )?)?)
    }

    fn read_guard_sample(&self, directory: &Path) -> Result<Value> {
        let name = format!(
            "sample-{}.json",
            self.path
                .file_stem()
                .and_then(|name| name.to_str())
                .and_then(|name| name.strip_prefix("sample-"))
                .filter(|iid| hex(iid, 32))
                .context("invalid guard sample filename")?
        );
        ensure!(
            self.path == directory.join(name),
            "guard sample is outside the admitted receipt directory"
        );
        let (file, identity) = open(&self.path)?;
        let meta = file.metadata()?;
        ensure!(
            meta.uid() == 0 && meta.mode() & 0o022 == 0,
            "unsafe guard sample ownership"
        );
        let bytes = read_small(&file, identity)?;
        ensure!(digest(&bytes) == self.sha256, "guard sample digest changed");
        unchanged(&self.path, &file, identity)?;
        let sample: Value = serde_json::from_slice(&bytes)?;
        let iid = string(&sample, "guard_invocation_id")?;
        ensure!(
            hex(iid, 32) && self.path == directory.join(format!("sample-{iid}.json")),
            "guard sample invocation does not match its filename"
        );
        Ok(sample)
    }
}

#[derive(Deserialize)]
struct Launch {
    schema: String,
    kind: String,
    epoch: u64,
    unit: String,
    run_root: PathBuf,
    invocation_id: String,
    main_pid: u32,
    node_path: PathBuf,
    worker: Reference,
    profile: Reference,
    lossless_restore: Reference,
    admission: Reference,
    guard_plan: Reference,
    launch_token: Reference,
    active_guard: Reference,
    guard_release_fit: Reference,
    evidence: Value,
    launched: bool,
    diagnostic_only: bool,
    canonical_epoch_publication_authorized: bool,
    remote_mutations: bool,
    r2_mutations: bool,
}

impl Launch {
    fn cgroup(&self) -> String {
        format!("/system.slice/{}", self.unit)
    }

    fn validate(&self, state: &Path) -> Result<Profile> {
        ensure!(
            self.schema == "jetstreamer-historical-performance-launch-receipt-v1"
                && self.kind == "epoch266-private-hourly-overlap"
                && self.epoch == EPOCH
                && self.unit == UNIT
                && hex(&self.invocation_id, 32)
                && self.main_pid > 1
                && self.launched
                && self.diagnostic_only
                && !self.canonical_epoch_publication_authorized
                && !self.remote_mutations
                && !self.r2_mutations,
            "foreign or unauthorized producer launch"
        );
        ensure!(
            self.profile == Reference::new(state.join("profile.json"), PROFILE_SHA)
                && self.lossless_restore == Reference::new(RESTORE, RESTORE_SHA)
                && self.admission.path == state.join("admission.json")
                && self.guard_plan.path == state.join("guard-plan.json")
                && self.guard_release_fit.path == state.join("guard-release-fit.json")
                && self.launch_token.path
                    == Path::new(TOKEN_ROOT)
                        .join(&self.invocation_id)
                        .join("guard-admission.json"),
            "launch does not bind the selected profile, restore and guard paths"
        );
        let profile: Profile = serde_json::from_value(self.profile.read()?)?;
        ensure!(
            profile.unit == self.unit
                && profile.run_root == self.run_root
                && profile.node.path == self.node_path
                && profile.worker == self.worker
                && profile.worker.sha256 == WORKER_SHA
                && profile.persistent_archive == Path::new(SEGMENT)
                && profile.persistent_segment_manifest
                    == PathBuf::from(format!("{SEGMENT}.segment.json")),
            "launch paths or worker differ from the sealed profile"
        );
        ensure!(
            self.evidence["units"]
                == json!([{
                    "unit": self.unit, "invocation_id": self.invocation_id, "main_pid": self.main_pid,
                    "active_state": "active", "sub_state": "running", "load_state": "loaded",
                    "result": "success", "restarts": 0,
                }]),
            "launch lacks the admitted running producer"
        );
        let admission = self.admission.read()?;
        let preflight = Reference::new(state.join("preflight.json"), PREFLIGHT_SHA);
        ensure!(
            admission["schema"] == "foundation-epoch266-focused-admission-v1"
                && admission["epoch"] == EPOCH
                && admission["profile"] == json!(self.profile)
                && admission["preflight"] == json!(preflight)
                && admission["admitted"] == true
                && admission["publication_authorized"] == false,
            "foreign or incomplete admission"
        );
        preflight.read()?;
        let mut expected_guard = profile.static_guard_plan.read()?;
        expected_guard["invocation_id"] = json!(self.invocation_id);
        let guard = self.guard_plan.read()?;
        ensure!(
            guard == expected_guard,
            "guard plan differs from the invocation-bound profile"
        );
        let receipt_dir = state.join("guard-receipts");
        ensure!(
            guard["receipt_directory"] == json!(receipt_dir),
            "foreign guard receipt directory"
        );
        let token = self.launch_token.read()?;
        let release = self.guard_release_fit.read()?;
        ensure!(
            token["epoch"] == EPOCH
                && token["unit"] == self.unit
                && token["invocation_id"] == self.invocation_id
                && token["guard_plan"] == json!(self.guard_plan)
                && token["admission"] == json!(self.admission)
                && token["publication_authorized"] == false
                && hex(string(&token, "guard_timer_invocation")?, 32)
                && token["next_guard_monotonic_usec"]
                    .as_u64()
                    .is_some_and(|stamp| stamp > 0)
                && release["schema"] == "foundation-epoch266-hourly-overlap-guard-release-fit-v1"
                && release["invocation_id"] == self.invocation_id
                && release["guard_plan"] == json!(self.guard_plan)
                && !admission["roster"].is_null()
                && release["roster"] == admission["roster"]
                && release["publication_authorized"] == false,
            "guard release is not bound to the admitted invocation and roster"
        );
        let first: Reference = serde_json::from_value(token["first_guard"].clone())?;
        let first = first.read_guard_sample(&receipt_dir)?;
        let active = self.active_guard.read_guard_sample(&receipt_dir)?;
        self.validate_guard_sample(&profile, &first, "activating", "start-pre", 0)?;
        self.validate_guard_sample(&profile, &active, "active", "running", self.main_pid)?;
        ensure!(
            token["completed_guard"]
                == json!({
                    "ActiveState": "inactive", "InvocationID": first["guard_invocation_id"],
                    "Result": "success", "ExecMainStatus": "0", "MainPID": "0",
                }),
            "first guard did not complete successfully before release"
        );
        for image in [&profile.node, &profile.worker] {
            bound_bytes(&image.path, &image.sha256, 64 << 20, true)?;
        }
        Ok(profile)
    }

    fn validate_guard_sample(
        &self,
        profile: &Profile,
        sample: &Value,
        state: &str,
        sub: &str,
        pid: u32,
    ) -> Result<()> {
        let producer = &sample["producer"];
        ensure!(
            sample["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
                && sample["producer_invocation_id"] == self.invocation_id
                && sample["plan"] == json!(self.guard_plan.path)
                && sample["plan_sha256"] == self.guard_plan.sha256
                && sample["guard_sha256"] == profile.guard.sha256
                && sample["trip_reason"] == Value::Null
                && sample.get("trip_reason").is_some()
                && sample["producer_stop_enabled"] == true
                && sample.get("root_physical_observation_error") == Some(&Value::Null)
                && (pid == 0 || sample.get("worker_observation_error") == Some(&Value::Null))
                && producer["invocation_id"] == self.invocation_id
                && producer["cgroup"] == self.cgroup()
                && producer["active"] == state
                && producer["sub"] == sub
                && producer["pid"] == pid
                && producer["restart_policy"] == "no"
                && producer["restarts"] == 0
                && producer["kill_mode"] == "control-group"
                && producer["delegated"] == false,
            "guard sample does not bind the exact protected producer"
        );
        Ok(())
    }
}

#[derive(Deserialize)]
struct Profile {
    unit: String,
    run_root: PathBuf,
    node: Reference,
    worker: Reference,
    guard: Reference,
    static_guard_plan: Reference,
    argv: Vec<String>,
    persistent_archive: PathBuf,
    persistent_segment_manifest: PathBuf,
}

fn digest(bytes: &[u8]) -> String {
    sha256_hex_string(&Sha256::digest(bytes).into())
}

fn string<'a>(row: &'a Value, field: &str) -> Result<&'a str> {
    row[field]
        .as_str()
        .with_context(|| format!("missing text field {field}"))
}

fn command(program: &str, args: &[&str]) -> Result<Vec<u8>> {
    let result = Command::new(program)
        .args(args)
        .env_clear()
        .env("LC_ALL", "C")
        .output()?;
    ensure!(
        result.status.success(),
        "{program} failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    Ok(result.stdout)
}

type UnitState = BTreeMap<String, String>;

fn unit_state(unit: &str) -> Result<UnitState> {
    let output = command(
        "/usr/bin/systemctl",
        &[
            "--system",
            "show",
            "--no-pager",
            unit,
            "--property=Id,LoadState,ActiveState,SubState,InvocationID,MainPID,ControlPID,ControlGroup,Job,Result,NRestarts,Restart,ExecMainPID,ExecMainCode,ExecMainStatus,ExecMainStartTimestampMonotonic,ExecMainExitTimestampMonotonic",
        ],
    )?;
    Ok(std::str::from_utf8(&output)?
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(name, value)| (name.to_owned(), value.to_owned()))
        .collect())
}

fn clean_exit<'a>(
    state: &'a UnitState,
    captured: Option<&'a UnitState>,
    unit: &str,
    invocation: &str,
    pid: u32,
    drained: bool,
) -> Result<&'a UnitState> {
    clean_state(state, unit)?;
    ensure!(drained, "producer cgroup has not physically drained");
    let retained = match state.get("LoadState").map(String::as_str) {
        Some("loaded") => {
            ensure!(
                captured.is_none_or(|capture| capture == state),
                "PID1 capture differs from the retained unit state"
            );
            state
        }
        Some("not-found") => {
            for (key, value) in [
                ("InvocationID", ""),
                ("ExecMainPID", "0"),
                ("ExecMainCode", "0"),
                ("ExecMainStartTimestampMonotonic", "0"),
                ("ExecMainExitTimestampMonotonic", "0"),
            ] {
                ensure!(
                    state.get(key).is_some_and(|actual| actual == value),
                    "collected unit has foreign exit state"
                );
            }
            captured.context("systemd collected the unit; a SHA-bound capture-exit receipt is required for the exact exit status")?
        }
        _ => bail!("unknown producer load state"),
    };
    clean_state(retained, unit)?;
    ensure!(
        retained
            .get("LoadState")
            .is_some_and(|value| value == "loaded")
            && retained
                .get("InvocationID")
                .is_some_and(|value| value == invocation)
            && retained
                .get("ExecMainPID")
                .is_some_and(|value| value == &pid.to_string())
            && retained
                .get("ExecMainCode")
                .is_some_and(|value| value == "1")
            && state_timestamp(retained, "ExecMainStartTimestampMonotonic")?
                < state_timestamp(retained, "ExecMainExitTimestampMonotonic")?,
        "PID1 does not prove a normal zero exit for this producer"
    );
    Ok(retained)
}

fn state_timestamp(state: &UnitState, key: &str) -> Result<u64> {
    let timestamp = state
        .get(key)
        .with_context(|| format!("missing {key}"))?
        .parse()?;
    ensure!(timestamp > 0, "nonpositive {key}");
    Ok(timestamp)
}

fn clean_state(state: &UnitState, unit: &str) -> Result<()> {
    let field = |key: &str| state.get(key).map(String::as_str);
    for (key, value) in [
        ("Id", unit),
        ("ActiveState", "inactive"),
        ("SubState", "dead"),
        ("Result", "success"),
        ("MainPID", "0"),
        ("ControlPID", "0"),
        ("ControlGroup", ""),
        ("Job", ""),
        ("NRestarts", "0"),
        ("Restart", "no"),
        ("ExecMainStatus", "0"),
    ] {
        ensure!(
            field(key) == Some(value),
            "producer {key} is {:?}; expected {value:?}",
            field(key)
        );
    }
    Ok(())
}

fn producer_drained(cgroup: &str) -> Result<bool> {
    let mount = Path::new(CGROUP_ROOT);
    ensure!(
        mount.join("cgroup.controllers").is_file()
            && mount.join("system.slice/cgroup.events").is_file(),
        "system cgroup v2 hierarchy is unavailable"
    );
    Ok(!mount.join(cgroup.trim_start_matches('/')).try_exists()?)
}

fn timestamp(event: &Value) -> Result<u64> {
    let stamp = string(event, "__MONOTONIC_TIMESTAMP")?.parse()?;
    ensure!(stamp > 0, "missing positive journal timestamp");
    Ok(stamp)
}

fn journal_rows(args: &[&str]) -> Result<Vec<Value>> {
    let mut options = vec![
        "--no-pager",
        "--quiet",
        "--boot=0",
        "--output=json",
    ];
    options.extend_from_slice(args);
    let bytes = command("/usr/bin/journalctl", &options)?;
    let mut rows = std::str::from_utf8(&bytes)?
        .lines()
        .map(|line| {
            let row = serde_json::from_str(line)?;
            Ok((timestamp(&row)?, row))
        })
        .collect::<Result<Vec<_>>>()?;
    rows.sort_by_key(|(stamp, _)| *stamp);
    Ok(rows.into_iter().map(|(_, row)| row).collect())
}

fn manager_events(unit: &str) -> Result<Vec<Value>> {
    // Search the unit across invocations so a later collected run invalidates
    // an earlier success. Never select only the expected invocation here.
    journal_rows(&[
        "--system",
        "--lines=32",
        "--output-fields=MESSAGE,MESSAGE_ID,UNIT,INVOCATION_ID,_PID,_UID,_BOOT_ID,UNIT_RESULT",
        "_PID=1",
        &format!("UNIT={unit}"),
    ])
}

fn manager_lifecycle<'a>(
    rows: &'a [Value],
    launch: &Launch,
    profile: &Profile,
    boot: &str,
) -> Result<(&'a Value, &'a Value)> {
    let index = rows
        .iter()
        .position(|row| row["INVOCATION_ID"] == launch.invocation_id)
        .context("PID1 has no start evidence for the admitted invocation")?;
    let (starting, started, terminal, resources) = match &rows[index..] {
        [start, started, exit] => (start, started, exit, None),
        [start, started, exit, resources] => (start, started, exit, Some(resources)),
        _ => bail!("PID1 has additional, stale, or incomplete producer lifecycle evidence"),
    };
    for row in &rows[index..] {
        ensure!(
            row["_PID"] == "1"
                && row["_UID"] == "0"
                && row["UNIT"] == launch.unit
                && row["INVOCATION_ID"] == launch.invocation_id
                && row["_BOOT_ID"] == boot,
            "PID1 lifecycle belongs to a different boot, unit or invocation"
        );
    }
    let description = format!("{} - [systemd-run] {}", launch.unit, profile.argv.join(" "));
    ensure!(
        starting["MESSAGE_ID"] == UNIT_STARTING
            && starting["MESSAGE"] == format!("Starting {description}...")
            && started["MESSAGE_ID"] == UNIT_STARTED
            && started["MESSAGE"] == format!("Started {description}.")
            && terminal["MESSAGE_ID"] == UNIT_SUCCESS
            && terminal["MESSAGE"] == format!("{}: Deactivated successfully.", launch.unit)
            && terminal
                .get("UNIT_RESULT")
                .is_none_or(|value| value == "success")
            && timestamp(starting)? < timestamp(started)?
            && timestamp(started)? < timestamp(terminal)?,
        "PID1 does not prove a natural, restart-free successful exit"
    );
    if let Some(resources) = resources {
        ensure!(
            resources["MESSAGE_ID"] == UNIT_RESOURCES
                && timestamp(terminal)? < timestamp(resources)?,
            "PID1 recorded activity after terminal deactivation"
        );
    }
    Ok((started, terminal))
}

fn checkpoint_message(checkpoint: &SegmentCheckpointSummary) -> String {
    format!(
        "historical checkpoint slot={} bank_hash={} accounts_hash={} last_blockhash={} capitalization={} transactions={} tick_height={} complete=true writes={} next_write_version={}",
        checkpoint.slot,
        checkpoint.bank_hash,
        checkpoint.accounts_hash,
        checkpoint.last_blockhash,
        checkpoint.capitalization,
        checkpoint.transaction_count,
        checkpoint.tick_height,
        checkpoint.write_count,
        checkpoint.next_write_version,
    )
}

fn native_events(launch: &Launch) -> Result<Vec<Value>> {
    producer_events(&launch.unit, &launch.invocation_id, START - 1, SEGMENT_END - 1)
}

fn producer_events(unit: &str, invocation: &str, bootstrap: u64, last: u64) -> Result<Vec<Value>> {
    // UID 1000 may log to the user's journal. Keep both exact source matches.
    journal_rows(&[
        "--lines=5",
        "--output-fields=MESSAGE,_SYSTEMD_INVOCATION_ID,_SYSTEMD_UNIT,_SYSTEMD_CGROUP,_PID,_UID,_EXE,_BOOT_ID",
        &format!(
            "--grep=historical checkpoint slot=({bootstrap}|{last}) |snapshot verification complete|published verified historical segment evidence ",
        ),
        &format!("_SYSTEMD_UNIT={unit}"),
        &format!("_SYSTEMD_INVOCATION_ID={invocation}"),
    ])
}

fn verify_native_events(
    rows: &[Value],
    launch: &Launch,
    profile: &Profile,
    manifest: &HistoricalSegmentManifest,
    started: &Value,
    terminal: &Value,
    boot: &str,
) -> Result<()> {
    let [_, _, _, _] = rows else {
        bail!("expected four unique producer verification markers");
    };
    let markers = [
        (
            "jetstreamer_node::historical_replay",
            checkpoint_message(&manifest.bootstrap),
        ),
        (
            "jetstreamer_node::historical_replay",
            checkpoint_message(&manifest.terminal),
        ),
        (
            "jetstreamer_node",
            "snapshot verification complete".to_owned(),
        ),
        (
            "jetstreamer_node",
            format!(
                "published verified historical segment evidence {}",
                profile.persistent_segment_manifest.display()
            ),
        ),
    ];
    let mut prior = timestamp(started)?;
    let end = timestamp(terminal)?;
    for ((module, message), row) in markers.into_iter().zip(rows) {
        let stamp = timestamp(row)?;
        let logged_message = string(row, "MESSAGE")?;
        let (prefix, body) = logged_message
            .split_once("] ")
            .context("missing native log prefix")?;
        ensure!(
            row["_SYSTEMD_INVOCATION_ID"] == launch.invocation_id
                && row["_SYSTEMD_UNIT"] == launch.unit
                && row["_SYSTEMD_CGROUP"] == launch.cgroup()
                && row["_PID"] == launch.main_pid.to_string()
                && row["_UID"] == "1000"
                && row["_EXE"] == json!(launch.node_path)
                && row["_BOOT_ID"] == boot
                && prior < stamp
                && stamp < end
                && prefix.starts_with('[')
                && prefix.ends_with(&format!(" INFO  {module}"))
                && body == message,
            "foreign, out-of-order or mismatching native marker: {message}"
        );
        prior = stamp;
    }
    Ok(())
}

fn read_small(file: &File, identity: FileIdentity) -> Result<Vec<u8>> {
    ensure!(
        identity.bytes > 0 && identity.bytes <= JSON_LIMIT,
        "invalid evidence length"
    );
    let mut bytes = Vec::with_capacity(identity.bytes as usize);
    file.take(JSON_LIMIT + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == identity.bytes,
        "evidence length changed"
    );
    Ok(bytes)
}

fn open_source(path: &Path) -> Result<(File, FileIdentity)> {
    let (file, identity) = open(path)?;
    let meta = file.metadata()?;
    ensure!(
        meta.uid() == 1000 && meta.mode() & 0o022 == 0 && identity.bytes > 0,
        "unsafe producer output {}",
        path.display()
    );
    Ok((file, identity))
}

fn native_archive(
    archive_path: &Path,
    manifest_path: &Path,
    archive: &File,
    identity: FileIdentity,
    manifest_file: &File,
    manifest_identity: FileIdentity,
) -> Result<HistoricalSegmentManifest> {
    let native_error = |error: anyhow::Error| SegmentManifestError::Invalid(format!("{error:#}"));
    Ok(read_and_validate_seekable_segment_manifest(
        archive_path,
        manifest_path,
        NonZeroUsize::MIN,
        || {
            let (opened, reopened) = open_source(archive_path).map_err(native_error)?;
            if reopened != identity {
                return Err(SegmentManifestError::Invalid(
                    "archive identity changed while reopening a native validator descriptor"
                        .to_owned(),
                ));
            }
            Ok(BufReader::with_capacity(8 << 20, opened))
        },
        || {
            unchanged(archive_path, archive, identity).map_err(native_error)?;
            unchanged(manifest_path, manifest_file, manifest_identity).map_err(native_error)
        },
    )?)
}

#[derive(Default)]
struct TerminalBlock(Option<String>);

impl SlotVisitor for TerminalBlock {
    fn on_block(&mut self, notification: &BlockNotification, _entries: &[EntryRecord]) {
        if let BlockNotification::Block(block) = notification {
            self.0 = Some(block.blockhash.to_string());
        }
    }

    fn consumption(&self) -> Consumption {
        Consumption::all()
            .without_account_update_data()
            .without_block_account_update_arenas()
    }
}

fn verify_archive_terminal(archive: &File, manifest: &HistoricalSegmentManifest) -> Result<()> {
    let mut reader = ArchiveReader::open(BufReader::new(archive))?;
    validate_provenance(&mut reader, manifest)?;
    let mut block = TerminalBlock::default();
    ensure!(
        reader.read_slots(manifest.terminal.slot, 1, &mut block)? == 1
            && block.0.as_deref() == Some(&manifest.terminal.last_blockhash),
        "archive terminal block differs from the authenticated checkpoint"
    );
    Ok(())
}

fn destination_parent(destination: &Path) -> Result<&Path> {
    let parent = destination
        .parent()
        .context("output directory needs an absolute parent")?;
    let name = destination
        .file_name()
        .context("output directory needs a new name")?;
    ensure!(
        parent.is_absolute()
            && parent.canonicalize()? == parent
            && destination == parent.join(name),
        "output directory must have a direct absolute path"
    );
    for ancestor in parent.ancestors() {
        let meta = fs::symlink_metadata(ancestor)?;
        ensure!(
            meta.is_dir() && meta.uid() == 0 && meta.mode() & 0o022 == 0,
            "output ancestor is not a protected root directory: {}",
            ancestor.display()
        );
    }
    match fs::symlink_metadata(destination) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(parent),
        Err(error) => Err(error.into()),
        Ok(_) => bail!("output directory already exists"),
    }
}

fn write_sealed(path: &Path, value: &impl Serialize) -> Result<Reference> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .open(path)?;
    file.set_permissions(fs::Permissions::from_mode(0o400))?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(Reference::new(path, &digest(&bytes)))
}

fn install_package(staged: &Path, destination: &Path) -> Result<()> {
    let from = CString::new(staged.as_os_str().as_bytes())?;
    let to = CString::new(destination.as_os_str().as_bytes())?;
    // SAFETY: both C paths live across the call. RENAME_NOREPLACE preserves
    // any concurrent caller's result and makes both sealed files visible together.
    if unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            from.as_ptr(),
            libc::AT_FDCWD,
            to.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    } != 0
    {
        return Err(io::Error::last_os_error()).context("installing terminal evidence directory");
    }
    Ok(())
}

fn require_root() -> Result<()> {
    // SAFETY: geteuid takes no arguments and does not change process state.
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "root is required for native terminal evidence"
    );
    Ok(())
}

struct Admitted {
    reference: Reference,
    file: File,
    identity: FileIdentity,
    boot: String,
    launch: Launch,
    profile: Profile,
}

impl Admitted {
    fn load(launch_sha: &str) -> Result<Self> {
        let path = Path::new(LAUNCH);
        let reference = Reference::new(path, launch_sha);
        let (file, identity) = open(path).context("opening the real guarded launch receipt")?;
        let launch: Launch = serde_json::from_value(reference.read()?)?;
        unchanged(path, &file, identity)?;
        let profile = launch.validate(path.parent().context("launch state directory")?)?;
        let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?
            .trim()
            .replace('-', "");
        ensure!(hex(&boot, 32), "invalid running boot ID");
        Ok(Self {
            reference,
            file,
            identity,
            boot,
            launch,
            profile,
        })
    }

    fn unchanged(&self) -> Result<()> {
        unchanged(&self.reference.path, &self.file, self.identity)
    }
}

fn stage_package(parent: &Path) -> Result<tempfile::TempDir> {
    let staging = tempfile::Builder::new()
        .prefix(".epoch266-terminal-")
        .tempdir_in(parent)?;
    fs::set_permissions(staging.path(), fs::Permissions::from_mode(0o700))?;
    Ok(staging)
}

fn persist_package(staging: tempfile::TempDir, destination: &Path, parent: &Path) -> Result<()> {
    File::open(staging.path())?.sync_all()?;
    install_package(staging.path(), destination)?;
    drop(staging);
    File::open(parent)?.sync_all()?;
    Ok(())
}

pub(super) fn capture_exit(launch_sha: &str, destination: &Path) -> Result<Value> {
    exit::capture(launch_sha, destination)
}

pub(super) fn capture_adjacent230_exit(launch_sha: &str, destination: &Path) -> Result<Value> {
    exit::capture_adjacent230(launch_sha, destination)
}

pub(super) fn capture_v1627_exit(launch_sha: &str, destination: &Path) -> Result<Value> {
    exit::capture_v1627(launch_sha, destination)
}

pub(super) fn capture_next_v1627_exit(
    launch_sha: &str,
    invocation: &str,
    destination: &Path,
) -> Result<Value> {
    exit::capture_next_v1627(launch_sha, invocation, destination)
}

pub(super) fn collect_next_v1627_terminal(
    launch_sha: &str,
    invocation: &str,
    exit: &Path,
    digest: &str,
    destination: &Path,
) -> Result<Value> {
    window230::collect(&window230::next_v1627(launch_sha, invocation)?, exit, digest, destination)
}

pub(super) fn capture_retry_next_v1627_exit(
    launch_sha: &str,
    invocation: &str,
    destination: &Path,
) -> Result<Value> {
    let window = window230::retry_next_v1627(launch_sha, invocation)?;
    exit::capture_window230(&window, launch_sha, destination)
}

pub(super) fn collect_retry_next_v1627_terminal(
    launch_sha: &str,
    invocation: &str,
    exit: &Path,
    digest: &str,
    destination: &Path,
) -> Result<Value> {
    let window = window230::retry_next_v1627(launch_sha, invocation)?;
    window230::collect(&window, exit, digest, destination)
}

pub(super) fn capture_predecessor_exit(launch_sha: &str, destination: &Path) -> Result<Value> {
    exit::capture_predecessor(launch_sha, destination)
}

pub(super) fn collect_predecessor_account_histories(
    launch_sha: &str,
    exit_sha: &str,
    destination: &Path,
) -> Result<Value> {
    predecessor::collect(launch_sha, exit_sha, destination, true)
}

pub(super) fn collect_predecessor(
    launch_sha: &str,
    exit_sha: &str,
    destination: &Path,
) -> Result<Value> {
    predecessor::collect(launch_sha, exit_sha, destination, false)
}

pub(super) fn drain_failed_predecessor(launch_sha: &str) -> Result<Value> {
    predecessor::finish(launch_sha, true)
}

pub(super) fn finish_predecessor(launch_sha: &str) -> Result<Value> {
    predecessor::finish(launch_sha, false)
}

pub(super) fn collect_adjacent230_terminal(exit: &Path, digest: &str, destination: &Path) -> Result<Value> {
    window230::collect(&window230::ADJACENT, exit, digest, destination)
}

fn window266_scope(successor: bool) -> &'static window266::Window {
    if successor { &window266::SUCCESSOR } else { &window266::WINDOW }
}

pub(super) fn capture_window266_exit(launch_sha: &str, destination: &Path, successor: bool) -> Result<Value> {
    exit::capture_window266(window266_scope(successor), launch_sha, destination)
}

pub(super) fn finish_window266_terminal(launch_sha: &str, successor: bool) -> Result<Value> {
    window266::finish(window266_scope(successor), launch_sha)
}

pub(super) fn finish_retry_next_v1627_terminal(launch_sha: &str, invocation: &str) -> Result<Value> {
    window230::finish_retry(&window230::retry_next_v1627(launch_sha, invocation)?)
}

pub(super) fn collect_window266_terminal(
    launch_sha: &str,
    exit_sha: &str,
    destination: &Path,
    successor: bool,
) -> Result<Value> {
    window266::collect(window266_scope(successor), launch_sha, exit_sha, destination)
}

pub(super) fn collect_v1627_terminal(exit: &Path, digest: &str, destination: &Path) -> Result<Value> {
    window230::collect(&window230::V1627, exit, digest, destination)
}

pub(super) fn collect(
    launch_sha: &str,
    destination: &Path,
    capture: Option<(&Path, &str)>,
) -> Result<Value> {
    require_root()?;
    let parent = destination_parent(destination)?;
    let admitted = Admitted::load(launch_sha)?;
    let Admitted {
        launch,
        profile,
        boot,
        ..
    } = &admitted;
    let capture = capture.map(|(path, digest)| Reference::new(path, digest));
    let exact_exit = capture
        .as_ref()
        .map(|capture| exit::read(capture, &admitted))
        .transpose()?;
    let state = unit_state(&launch.unit)?;
    let cgroup = launch.cgroup();
    let retained = clean_exit(
        &state,
        exact_exit.as_ref(),
        &launch.unit,
        &launch.invocation_id,
        launch.main_pid,
        producer_drained(&cgroup)?,
    )?;
    let manager = manager_events(&launch.unit)?;
    let (started, terminal) = manager_lifecycle(&manager, launch, profile, boot)?;
    ensure!(
        state_timestamp(retained, "ExecMainStartTimestampMonotonic")? <= timestamp(started)?
            && state_timestamp(retained, "ExecMainExitTimestampMonotonic")? <= timestamp(terminal)?,
        "PID1 process times are outside the native lifecycle"
    );

    let manifest_path = &profile.persistent_segment_manifest;
    let archive_path = &profile.persistent_archive;
    let (manifest_file, manifest_identity) = open_source(manifest_path)?;
    let manifest_bytes = read_small(&manifest_file, manifest_identity)?;
    let manifest: HistoricalSegmentManifest = serde_json::from_slice(&manifest_bytes)?;
    validate_manifest(&manifest)?;
    let events = native_events(&launch)?;
    verify_native_events(&events, launch, profile, &manifest, started, terminal, boot)?;

    let (archive, identity) = open_source(archive_path)?;
    let verified = native_archive(
        archive_path,
        manifest_path,
        &archive,
        identity,
        &manifest_file,
        manifest_identity,
    )?;
    ensure!(
        verified == manifest,
        "native validator read a different manifest"
    );
    verify_archive_terminal(&archive, &manifest)?;
    let manifest_sha = digest(&manifest_bytes);
    bound_bytes(manifest_path, &manifest_sha, JSON_LIMIT, false)?;
    unchanged(manifest_path, &manifest_file, manifest_identity)?;
    unchanged(archive_path, &archive, identity)?;
    admitted.unchanged()?;
    ensure!(
        state == unit_state(&launch.unit)?
            && producer_drained(&cgroup)?
            && manager == manager_events(&launch.unit)?
            && events == native_events(&launch)?,
        "producer terminal evidence changed during native verification"
    );
    unchanged(archive_path, &archive, identity)?;
    unchanged(manifest_path, &manifest_file, manifest_identity)?;

    let plan = ComparePlan {
        schema: "foundation-epoch266-private-overlap-comparison-plan-v1".to_owned(),
        producer_invocation: launch.invocation_id.clone(),
        launch_sha256: launch_sha.to_owned(),
        segment_manifest_sha256: manifest_sha,
        segment_sha256: sha256_hex_string(&verified.archive_sha256),
        segment_identity: identity,
        producer_exit_status: 0,
        producer_drained: true,
        native_manifest_complete_verified: true,
        publication_authorized: false,
    };
    let staging = stage_package(parent)?;
    let plan_ref = write_sealed(&staging.path().join("comparison-plan.json"), &plan)?;
    let plan_ref = Reference::new(destination.join("comparison-plan.json"), &plan_ref.sha256);
    let receipt = json!({
        "schema": "foundation-epoch266-private-overlap-terminal-evidence-v1",
        "epoch": EPOCH, "first_slot": START, "last_slot": SEGMENT_END - 1,
        "slots": SEGMENT_END - START, "unit": launch.unit, "producer_invocation": plan.producer_invocation,
        "producer_pid": launch.main_pid, "boot_id": boot, "producer_state": state,
        "pid1_exit_properties": retained, "pid1_exit_capture": capture,
        "producer_exit_status": plan.producer_exit_status, "producer_drained": plan.producer_drained,
        "producer_cgroup": cgroup, "launch": admitted.reference, "profile": launch.profile,
        "worker": launch.worker, "node": profile.node, "lossless_restore": launch.lossless_restore,
        "admission": launch.admission, "guard_plan": launch.guard_plan, "launch_token": launch.launch_token,
        "active_guard": launch.active_guard, "guard_release_fit": launch.guard_release_fit,
        "manager_events": manager, "native_events": events,
        "archive": {"path": archive_path, "sha256": plan.segment_sha256, "identity": identity},
        "segment_manifest": {"path": manifest_path, "sha256": plan.segment_manifest_sha256, "identity": manifest_identity},
        "bootstrap_checkpoint": manifest.bootstrap, "terminal_checkpoint": manifest.terminal,
        "native_manifest_complete_verified": plan.native_manifest_complete_verified,
        "native_decoder_limit": 1, "comparison_plan": plan_ref,
        "guard_drain_required": false, "publication_authorized": false,
    });
    let receipt_ref = write_sealed(&staging.path().join("terminal-evidence.json"), &receipt)?;
    persist_package(staging, destination, parent)?;
    Ok(json!({
        "comparison_plan": plan_ref,
        "terminal_evidence": Reference::new(destination.join("terminal-evidence.json"), &receipt_ref.sha256),
        "producer_invocation": plan.producer_invocation,
        "publication_authorized": false,
    }))
}

#[cfg(test)]
mod tests;
