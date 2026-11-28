//! Retire the exact closed lane-k partial once its private copy has durable custody.
use super::*;
use std::{
    io::{BufRead, BufReader, ErrorKind},
    os::fd::AsRawFd,
};

const SOURCE: &str = "/home/sol/.jetstreamer-private/epochs175-200-20260922-v1/lane-k/private/destination-16846c94af4b82e80535dc5708f1da16a10dd2ec60011ca6aa20fc96a2b8a7ff/work/root-cohort-185-185/run-3765125-1791245177146692195/archives/epoch-185.jet";
const ELIGIBILITY: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch185-lanek-holding-20261125-v1/package/eligibility.json";
const ELIGIBILITY_SHA: &str = "4c758605f01775a2b2a893e44d09478aa11a093a3fdefc220c79c54609c8cfa7";
const PARK_START: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch185-lanek-holding-20261125-v1/PARK_START.json";
const PARK: &str = "horizon-closed185-lanek-park-20261127-v1.service";
const PARK_PLAN: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch185-lanek-holding-20261125-v1/package/plan.json";
const PARK_PLAN_SHA: &str = "929fd063b6776b525699f504dd6e83835a34ce6a08f8e690b3c6ff407dd9ea95";
const SIBLING_REVIEW: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch185-lanek-holding-20261125-v1/pre-custody-review-20261127-v1/HISTORICAL_CONSUMER_RECHECK.json";
const SIBLING_REVIEW_SHA: &str = "c1ec037b0cb159e9529f0c5b747e559bf05a75f140f240814a19e17dc5e41c3b";
const CREATOR: &str =
    "jetstreamer-root-sweep-historical-182-200-v117-r2-e185-185-lane-k-11.service";
const SHA: &str = "91e8053f4aeecc44555bffd3b4581e6dbed5e60e18a7b6535de4c76524777a15";
const MANIFEST: &str = "c62a2eec03efacb86947eac6c8c123b0d51476dad3cc019cb277b5643924c5e7";
const LENGTH: u64 = 66_545_963_870;
const ALLOCATED: u64 = 66_546_122_752;
const SOURCE_TIME: (i64, i64) = (1_791_375_909, 408_879_604);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Retire {
    schema: String,
    mapping: Bound,
    custody: Bound,
    park_start: Bound,
}

fn local_mutation_lock() -> Result<File> {
    let path = Path::new("/home/sol/.jetstreamer-private/r2-receipts/local-mutation.lock");
    ensure!(path.canonicalize()? == path, "aliased local mutation lock");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let md = file.metadata()?;
    ensure!(
        md.is_file()
            && md.dev() == 64512
            && md.ino() == 101135013
            && md.uid() == 1001
            && md.gid() == 1003
            && md.mode() & 0o7777 == 0o600
            && md.nlink() == 1
            && identity(&md) == regular_identity(path)?,
        "local mutation lock changed"
    );
    ensure!(
        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "local mutation lock is occupied"
    );
    Ok(file)
}

fn present(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}

fn source_identity(path: &Path, original: bool) -> Result<FileIdentity> {
    ensure!(path.canonicalize()? == path, "aliased lane-k artifact");
    let md = fs::symlink_metadata(path)?;
    let id = regular_identity(path)?;
    ensure!(
        id == identity(&md)
            && id.device == 64512
            && id.inode == 102_105_427
            && id.length == LENGTH
            && md.uid() == 1001
            && md.gid() == 1003
            && md.mode() & 0o7777 == 0o600
            && md.nlink() == 1
            && md.blocks().checked_mul(512) == Some(ALLOCATED)
            && (md.mtime(), md.mtime_nsec()) == SOURCE_TIME
            && (!original || (md.ctime(), md.ctime_nsec()) == SOURCE_TIME),
        "lane-k artifact identity changed"
    );
    Ok(id)
}

fn manager_fields(unit: &str) -> Result<Value> {
    let output = std::process::Command::new("/usr/bin/systemctl")
        .args(["show", unit, "-pId,LoadState,ActiveState,SubState,InvocationID,MainPID,ControlPID,Job,Result,ExecMainStatus,ExecMainPID,ExecMainStartTimestampMonotonic,Restart,TriggeredBy,ExecStart,FragmentPath,DropInPaths,NRestarts,RemainAfterExit,Type,ControlGroup,Transient,User,NoNewPrivileges,ReadWritePaths,ProtectHome,ProtectSystem,ExecCondition,ExecStartPre,ExecStartPost,ExecReload,ExecStop,ExecStopPost,OnSuccess,OnFailure"])
        .output()?;
    ensure!(
        output.status.success() || output.status.code() == Some(4),
        "cannot read native unit {unit}"
    );
    let mut fields = serde_json::Map::new();
    for line in std::str::from_utf8(&output.stdout)?.lines() {
        let (key, value) = line.split_once('=').context("invalid native property")?;
        ensure!(
            fields.insert(key.into(), json!(value)).is_none(),
            "duplicate native property"
        );
    }
    let row = Value::Object(fields);
    ensure!(row["Id"] == unit, "foreign native unit");
    Ok(row)
}

fn manager(unit: &str) -> Result<Value> {
    let row = manager_fields(unit)?;
    ensure!(
        row["Id"] == unit
            && row["MainPID"] == "0"
            && row["ControlPID"] == "0"
            && row["Job"] == ""
            && row["TriggeredBy"] == "",
        "unit still has execution or launch ownership: {unit}"
    );
    Ok(row)
}

fn valid_invocation(s: &str) -> bool {
    s.len() == 32
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        && s.bytes().any(|b| b != b'0')
}

fn original_plan() -> Bound {
    Bound {
        path: PARK_PLAN.into(),
        sha256: PARK_PLAN_SHA.into(),
    }
}

fn eligible() -> Bound {
    Bound {
        path: ELIGIBILITY.into(),
        sha256: ELIGIBILITY_SHA.into(),
    }
}

fn validate_start(start: &Value) -> Result<()> {
    let root = Path::new(PARK_START)
        .parent()
        .context("park start parent")?;
    let admission: Bound = serde_json::from_value(start["admission"].clone())?;
    ensure!(
        admission.path == root.join("PARK_ADMISSION.json"),
        "foreign park admission path"
    );
    let admitted = bound(&admission)?;
    ensure!(
        admitted["unit"] == PARK && admitted["plan"] == serde_json::to_value(original_plan())?,
        "different admitted park operation"
    );
    let plan: Park = serde_json::from_value(bound(&original_plan())?)?;
    source_scope(&plan, &bound(&eligible())?)?;
    let n = &start["native"];
    ensure!(
        n["Id"] == PARK
            && n["Restart"] == "no"
            && n["Type"] == "oneshot"
            && n["RemainAfterExit"] == "yes"
            && n["NRestarts"] == "0"
            && n["ExecMainPID"]
                .as_str()
                .and_then(|p| p.parse::<u32>().ok())
                .is_some_and(|p| p > 1)
            && n["ExecMainStartTimestampMonotonic"]
                .as_str()
                .and_then(|p| p.parse::<u64>().ok())
                .is_some_and(|p| p > 0)
            && start["start_ticks"].as_u64().is_some_and(|p| p > 0)
            && n["ControlGroup"] == format!("/system.slice/{PARK}"),
        "invalid original park start"
    );
    Ok(())
}

fn nonoverlapping(a: &Path, b: &Path) -> bool {
    a.is_absolute() && b.is_absolute() && !a.starts_with(b) && !b.starts_with(a)
}

/// A systemd service with an exact writable archive-parent mount necessarily
/// appears in the staged census. Account solely for this running process and
/// its transient fragment, with an empty stop/restart/follow-up command set.
fn current_writer_fragment() -> Result<Option<PathBuf>> {
    const UNIT: &str = "horizon-exact-185-lanek-retirement.service";
    let cgroup = format!("/system.slice/{UNIT}");
    if fs::read_to_string("/proc/self/cgroup")?.trim() != format!("0::{cgroup}") {
        return Ok(None);
    }
    let iid = env::var("INVOCATION_ID")?;
    let n = manager_fields(UNIT)?;
    let fragment = Path::new("/run/systemd/transient").join(UNIT);
    let expected_paths = BTreeSet::from([
        Path::new(SOURCE)
            .parent()
            .context("selected archive parent")?
            .to_path_buf(),
        Path::new(STATE).join("retirements"),
        Path::new(STATE).join("transition.lock"),
        PathBuf::from("/home/sol/.jetstreamer-private/r2-receipts/local-mutation.lock"),
    ]);
    let writable: BTreeSet<_> = n["ReadWritePaths"]
        .as_str()
        .context("write paths")?
        .split_ascii_whitespace()
        .map(PathBuf::from)
        .collect();
    ensure!(
        valid_invocation(&iid)
            && n["InvocationID"] == iid
            && n["Type"] == "exec"
            && n["ActiveState"] == "active"
            && n["SubState"] == "running"
            && n["User"] == "root"
            && n["MainPID"] == std::process::id().to_string()
            && n["ExecMainPID"] == n["MainPID"]
            && n["ControlGroup"] == cgroup
            && n["FragmentPath"] == fragment.to_str().unwrap_or_default()
            && n["DropInPaths"] == ""
            && n["ControlPID"] == "0"
            && n["Job"] == ""
            && n["RemainAfterExit"] == "no"
            && n["Restart"] == "no"
            && n["Transient"] == "yes"
            && n["NoNewPrivileges"] == "yes"
            && n["ProtectHome"] == "read-only"
            && n["ProtectSystem"] == "strict"
            && ["TriggeredBy", "OnSuccess", "OnFailure"]
                .iter()
                .all(|key| n[*key] == "")
            && writable == expected_paths,
        "unexpected current retirement unit or writable scope"
    );
    // systemctl omits empty command-array properties even with --all.
    let commands = [
        "ExecCondition",
        "ExecStartPre",
        "ExecStartPost",
        "ExecReload",
        "ExecStop",
        "ExecStopPost",
    ];
    let output = std::process::Command::new("/usr/bin/busctl")
        .args([
            "--json=short",
            "get-property",
            "org.freedesktop.systemd1",
            "/org/freedesktop/systemd1/unit/horizon_2dexact_2d185_2dlanek_2dretirement_2eservice",
            "org.freedesktop.systemd1.Service",
        ])
        .args(commands)
        .output()?;
    ensure!(
        output.status.success(),
        "could not read typed retirement command arrays"
    );
    let arrays = serde_json::Deserializer::from_slice(&output.stdout)
        .into_iter::<Value>()
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(
        arrays.len() == commands.len()
            && arrays
                .iter()
                .all(|item| item["type"] == "a(sasbttttuii)" && item["data"] == json!([])),
        "current retirement service contains another command"
    );
    Ok(Some(fragment))
}

/// This probe has no holding-state, custody or source operations. It can
/// qualify the exact execution namespace while the serial transfer owns its lock.
pub(super) fn check_namespace(spec: &Bound) -> Result<()> {
    ensure!(
        spec.path == Path::new(PARK_PLAN) && spec.sha256 == PARK_PLAN_SHA,
        "foreign namespace plan"
    );
    let own = current_writer_fragment()?.context("requires exact running transient unit")?;
    let run = Path::new(SOURCE)
        .parent()
        .and_then(Path::parent)
        .context("run")?;
    let staged = jetstreamer_horizon_observe::dev_cache_check::sol_staged_path_references(run)?;
    ensure!(
        staged["references"] == json!([own]),
        "foreign exact-run owner during namespace qualification"
    );
    println!(
        "{}",
        json!({"fragment":own,"native_pid":std::process::id(),"invocation":env::var("INVOCATION_ID")?,
        "checked_writable_scope":true,"data_removed":false,"custody_or_admission_proved":false})
    );
    Ok(())
}

fn scoped_staged(run: &Path) -> Result<()> {
    let inspect = jetstreamer_horizon_observe::dev_cache_check::sol_staged_path_references;
    let review = bound(&Bound {
        path: SIBLING_REVIEW.into(),
        sha256: SIBLING_REVIEW_SHA.into(),
    })?;
    let rows = review["checked_historical_units"]
        .as_array()
        .context("historical owner rows")?;
    ensure!(
        rows.len() == 13
            && review["source"] == SOURCE
            && review["plan"] == serde_json::to_value(original_plan())?,
        "unexpected sibling review"
    );
    let mut siblings = BTreeSet::new();
    for row in rows {
        let unit = row["unit"].as_str().context("historical owner unit")?;
        let fragment: Bound = serde_json::from_value(row["fragment"].clone())?;
        let plan: Bound = serde_json::from_value(row["plan"].clone())?;
        bound(&plan)?;
        let original = &row["native"];
        let native = manager(unit)?;
        let targets = row["original_targets"]
            .as_array()
            .context("reviewed sibling targets")?;
        ensure!(
            !targets.is_empty()
                && targets.iter().all(|p| p
                    .as_str()
                    .is_some_and(|s| nonoverlapping(Path::new(s), run))),
            "sibling has overlapping retirement scope: {unit}"
        );
        let md = fs::symlink_metadata(&fragment.path)?;
        ensure!(
            fragment.path == Path::new("/run/systemd/transient").join(unit)
                && fragment.path.canonicalize()? == fragment.path
                && md.is_file()
                && md.uid() == 0
                && md.mode() & 0o022 == 0
                && md.nlink() == 1
                && md.len() <= 1 << 20
                && hex_lower(&Sha256::digest(read_stable_bounded(
                    &fragment.path,
                    1 << 20,
                    "sibling unit"
                )?)) == fragment.sha256
                && native["FragmentPath"] == original["FragmentPath"]
                && native["FragmentPath"] == fragment.path.to_str().unwrap_or_default()
                && native["ActiveState"] == original["ActiveState"]
                && native["SubState"] == original["SubState"]
                && native["Restart"] == "no"
                && native["DropInPaths"] == ""
                && siblings.insert(fragment.path),
            "historical ownership changed: {unit}"
        );
    }
    let own = current_writer_fragment()?;
    if let Some(fragment) = &own {
        siblings.insert(fragment.clone());
    }
    let lane = run
        .ancestors()
        .find(|p| p.file_name().is_some_and(|part| part == "lane-k"))
        .context("lane-k root")?;
    let found = inspect(lane)?;
    ensure!(
        found["references"]
            .as_array()
            .context("lane-k staged references")?
            .iter()
            .all(|v| v.as_str().is_some_and(|p| siblings.contains(Path::new(p)))),
        "unknown staged lane-k owner"
    );
    let run_owners = inspect(run)?;
    let expected: Vec<_> = own.into_iter().collect();
    ensure!(
        run_owners["references"] == json!(expected),
        "old run has foreign staged consumers"
    );
    Ok(())
}

fn no_inode_references(device: u64, inode: u64) -> Result<()> {
    let dev = format!("{:02x}:{:02x}", libc::major(device), libc::minor(device));
    let lock_identity = format!("{dev}:{inode}");
    ensure!(
        !fs::read_to_string("/proc/locks")?
            .split_ascii_whitespace()
            .any(|s| s == lock_identity),
        "kernel lock still covers selected inode"
    );
    for row in fs::read_dir("/proc")? {
        let p = row?.path();
        let Some(pid) = p
            .file_name()
            .and_then(|s| s.to_str())
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };
        let result = (|| -> Result<()> {
            for fd in fs::read_dir(p.join("fd"))? {
                let fd = fd?.path();
                match fs::metadata(&fd) {
                    Ok(md) => ensure!(
                        (md.dev(), md.ino()) != (device, inode),
                        "pid {pid} holds selected inode"
                    ),
                    Err(e) if e.kind() == ErrorKind::NotFound => (),
                    Err(e) => return Err(e.into()),
                }
            }
            let mut input = BufReader::new(File::open(p.join("maps"))?);
            let mut line = String::new();
            while input.read_line(&mut line)? != 0 {
                let mut fields = line.split_ascii_whitespace().skip(3);
                let mapped_dev = fields.next().context("process maps device")?;
                let mapped_inode = fields
                    .next()
                    .context("process maps inode")?
                    .parse::<u64>()?;
                ensure!(
                    mapped_dev != dev || mapped_inode != inode,
                    "pid {pid} maps selected inode"
                );
                line.clear();
            }
            Ok(())
        })();
        if result
            .as_ref()
            .err()
            .and_then(|e| e.downcast_ref::<std::io::Error>())
            .is_some_and(|e| e.kind() == ErrorKind::NotFound)
            && !p.try_exists()?
        {
            continue;
        }
        result.with_context(|| format!("incomplete inode check for pid {pid}"))?;
    }
    Ok(())
}

fn check_consumers(inode_present: bool) -> Result<()> {
    let creator = manager(CREATOR)?;
    ensure!(
        creator["LoadState"] == "not-found"
            && creator["ActiveState"] == "inactive"
            && creator["SubState"] == "dead"
            && creator["InvocationID"] == ""
            && creator["ExecStart"].as_str().unwrap_or_default().is_empty(),
        "old lane-k producer is launchable"
    );
    let run = Path::new(SOURCE)
        .parent()
        .and_then(Path::parent)
        .context("run path")?;
    no_references(run)?;
    scoped_staged(run)?;
    if inode_present {
        no_inode_references(64512, 102_105_427)?;
    }
    Ok(())
}

pub(super) fn inspect(spec: &Bound) -> Result<()> {
    let _lock = local_mutation_lock()?;
    ensure!(
        spec.path == Path::new(PARK_PLAN) && spec.sha256 == PARK_PLAN_SHA,
        "unexpected inspection plan"
    );
    let plan: Park = serde_json::from_value(bound(spec)?)?;
    let e = bound(&eligible())?;
    source(&plan, &e)?;
    source_identity(Path::new(SOURCE), true)?;
    check_consumers(true)?;
    println!(
        "{}",
        json!({"source":SOURCE,"inode":102_105_427,"allocated":ALLOCATED,"historical_siblings":13,
        "checked_local_owners":true,"holding_transition_lock":true,"local_mutation_lock":true,
        "custody_checked":false,"retirement_authorized":false,"data_removed":false})
    );
    Ok(())
}

fn closure(start: &Value, inode_present: bool) -> Result<()> {
    validate_start(start)?;
    let terminal = manager(PARK)?;
    let earlier = &start["native"];
    ensure!(
        terminal["LoadState"] == "loaded"
            && terminal["ActiveState"] == "active"
            && terminal["SubState"] == "exited"
            && terminal["Restart"] == "no"
            && terminal["Type"] == "oneshot"
            && terminal["RemainAfterExit"] == "yes"
            && terminal["DropInPaths"] == ""
            && terminal["NRestarts"] == "0"
            && terminal["FragmentPath"] == earlier["FragmentPath"]
            && (terminal["ControlGroup"] == ""
                || terminal["ControlGroup"] == earlier["ControlGroup"])
            && terminal["Result"] == "success"
            && terminal["ExecMainStatus"] == "0"
            && earlier["Id"] == PARK
            && earlier["InvocationID"]
                .as_str()
                .is_some_and(valid_invocation)
            && terminal["InvocationID"] == earlier["InvocationID"]
            && terminal["ExecMainPID"] == earlier["ExecMainPID"]
            && terminal["ExecMainStartTimestampMonotonic"]
                == earlier["ExecMainStartTimestampMonotonic"],
        "park invocation has no exact clean exit"
    );
    check_consumers(inode_present)
}

async fn remote(client: &Client, m: &Mapping, c: &Value) -> Result<()> {
    let (key, etag, sha, length) = custody(c, m)?;
    let owner = owner_bytes(m)?;
    ensure!(
        get_mutable_object(client, BUCKET, &format!("{}owner.json", m.prefix))
            .await?
            .is_some_and(|entry| entry.bytes == owner),
        "holding prefix owner changed"
    );
    let manifest = get_mutable_object(
        client,
        BUCKET,
        c["manifest_key"].as_str().context("manifest key")?,
    )
    .await?
    .context("holding manifest absent")?;
    ensure!(
        hex_lower(&Sha256::digest(&manifest.bytes)) == MANIFEST
            && serde_json::from_slice::<Value>(&manifest.bytes)? == c["manifest"],
        "holding manifest bytes changed"
    );
    let blob = head_archive(client, BUCKET, &key)
        .await?
        .context("holding blob absent")?;
    remote_matches(&blob, &key, length, &sha, Some(&etag))
}

pub(super) async fn run(client: &Client, m: &Mapping, p: &Retire, check: bool) -> Result<()> {
    ensure!(
        p.schema == "jetstreamer-horizon-holding-retire185-lanek-plan-v1"
            && p.custody.path
                == Path::new(STATE)
                    .join("receipts")
                    .join(format!("custody-{MANIFEST}.json"))
            && p.park_start.path == Path::new(PARK_START),
        "foreign lane-k retirement scope"
    );
    let _local_lock = local_mutation_lock()?;
    let eligibility = eligible();
    let e = bound(&eligibility)?;
    let c = bound(&p.custody)?;
    let (blob_key, blob_etag, sha, length) = custody(&c, m)?;
    let package = bound(&original_plan())?;
    ensure!(
        package["mapping"] == serde_json::to_value(&p.mapping)? && m.prefix == "node_02/",
        "different prefix mapping"
    );
    ensure!(
        e["source"] == SOURCE
            && e["closed"] == true
            && e["canonical_archive"] == false
            && e["epoch"] == 185
            && e["sha256"] == SHA
            && e["length"] == LENGTH
            && c["source"] == SOURCE
            && sha == SHA
            && length == LENGTH
            && c["manifest_sha256"] == MANIFEST
            && c["manifest"]["uid"] == 1001
            && c["manifest"]["gid"] == 1003
            && c["manifest"]["mode"] == 0o600
            && c["eligibility"] == serde_json::to_value(&eligibility)?
            && c["mapping"] == serde_json::to_value(&p.mapping)?,
        "custody or eligibility differs from this closed lane-k artifact"
    );
    let start = bound(&p.park_start)?;
    let dir = Path::new(STATE).join("retirements");
    private(&dir)?;
    ensure!(
        dir.canonicalize()? == dir && fs::metadata(&dir)?.dev() == 64512,
        "retirement filesystem changed"
    );
    let source = Path::new(SOURCE);
    let source_parent = source.parent().context("archive parent")?;
    let quarantine = source_parent.join(format!(".epoch185-lanek-retiring-{SHA}.jet"));
    let intent = dir.join("epoch185-lanek-intent.json");
    let unlink = dir.join("epoch185-lanek-unlink-intent.json");
    let complete = dir.join("epoch185-lanek-complete.json");
    let descriptor = json!({"source":source,"quarantine":quarantine,"sha256":SHA,"length":LENGTH,
        "custody":p.custody,"eligibility":eligibility,"park_start":p.park_start,"mapping":p.mapping});
    let intent_record =
        json!({"schema":"jetstreamer-holding-retire185-lanek-intent-v1","operation":descriptor});

    let source_present = present(source)?;
    let quarantine_present = present(&quarantine)?;
    let intention = present(&intent)?;
    let unlinked = present(&unlink)?;
    let completed = present(&complete)?;
    ensure!(
        !(source_present && quarantine_present)
            && (!quarantine_present || intention)
            && (!unlinked || intention && !source_present)
            && (!completed || unlinked && !quarantine_present)
            && (source_present || quarantine_present || unlinked),
        "unrecognized local retirement state"
    );
    let verify_record = |path: &Path, value: &Value| -> Result<()> {
        let bytes = read_stable_bounded(path, 1 << 20, "lane-k retirement record")?;
        let reference = Bound {
            path: path.to_path_buf(),
            sha256: hex_lower(&Sha256::digest(&bytes)),
        };
        ensure!(
            bound(&reference)? == *value,
            "foreign local retirement record"
        );
        Ok(())
    };
    if intention {
        verify_record(&intent, &intent_record)?;
    }
    let recorded_unlink = if unlinked {
        let bytes = read_stable_bounded(&unlink, 1 << 20, "original unlink intent")?;
        let record: Value = serde_json::from_slice(&bytes)?;
        let before = record["free_before_unlink_bytes"]
            .as_u64()
            .context("missing original free-space baseline")?;
        verify_record(
            &unlink,
            &json!({"schema":"jetstreamer-holding-retire185-lanek-unlink-v1",
            "operation":descriptor,"free_before_unlink_bytes":before}),
        )?;
        Some(before)
    } else {
        None
    };
    let current = if source_present {
        Some(source)
    } else if quarantine_present {
        Some(quarantine.as_path())
    } else {
        None
    };
    if let Some(path) = current {
        source_identity(path, source_present)?;
    }
    closure(&start, current.is_some())?;
    remote(client, m, &c).await?;
    if check {
        ensure!(
            source_present && !intention,
            "check requires the original closed artifact"
        );
        println!(
            "{}",
            json!({"operation":descriptor,"checked":true,"data_removed":false,
            "local_allocated_bytes":ALLOCATED,"authenticated_custody_revalidated":true})
        );
        return Ok(());
    }
    if completed {
        let bytes = read_stable_bounded(&complete, 1 << 20, "lane-k completion")?;
        let data: Value = serde_json::from_slice(&bytes)?;
        ensure!(
            data["operation"] == descriptor
                && data["source_absent"] == true
                && data["quarantine_absent"] == true,
            "foreign completed retirement"
        );
        println!("{}", complete.display());
        return Ok(());
    }
    if let Some(path) = current {
        let id = source_identity(path, source_present)?;
        ensure!(
            hash_and_etag(path, id, DEFAULT_PART_SIZE)?.sha256_hex == SHA,
            "local payload changed"
        );
        verify_remote_sha256(client, BUCKET, &blob_key, &blob_etag, LENGTH, SHA, 1).await?;
        remote(client, m, &c).await?;
        closure(&start, current.is_some())?;
    }
    if source_present {
        persist(&intent, &intent_record)?;
        source_identity(source, true)?;
        rename_noreplace(source, &quarantine)?;
        File::open(source_parent)?.sync_all()?;
    }
    let free_before;
    if present(&quarantine)? {
        let identity = source_identity(&quarantine, false)?;
        closure(&start, current.is_some())?;
        remote(client, m, &c).await?;
        free_before = match recorded_unlink {
            Some(before) => before,
            None => available(source_parent)?,
        };
        persist(
            &unlink,
            &json!({"schema":"jetstreamer-holding-retire185-lanek-unlink-v1",
            "operation":descriptor,"free_before_unlink_bytes":free_before}),
        )?;
        ensure!(
            !present(source)? && source_identity(&quarantine, false)? == identity,
            "retirement target changed before unlink"
        );
        fs::remove_file(&quarantine)?;
        File::open(source_parent)?.sync_all()?;
    } else {
        free_before = recorded_unlink.context("missing durable unlink baseline")?;
        File::open(source_parent)?.sync_all()?;
    }
    ensure!(
        !present(source)? && !present(&quarantine)?,
        "retirement target remains"
    );
    let free_after = available(source_parent)?;
    remote(client, m, &c).await?;
    persist(
        &complete,
        &json!({"schema":"jetstreamer-holding-retire185-lanek-complete-v1",
        "operation":descriptor,"source_absent":true,"quarantine_absent":true,
        "retired_physical_bytes":ALLOCATED,"free_bytes_before":free_before,"free_bytes_after":free_after,
        "free_delta_bytes":i128::from(free_after)-i128::from(free_before),"resource_credit_bytes":0,
        "authenticated_custody_revalidated":true,"whole_readback_before_retirement":true,"remote_mutations":false}),
    )?;
    println!("{}", complete.display());
    Ok(())
}
