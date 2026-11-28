mod cached145_closed_guard;
mod cached145_guard_sample_ready;
mod retry0005_failed4_custody;
use anyhow::{Context, Result, ensure};
use horizon_recovered_resource_frame_recovery199::{
    Bound, Evidence, SCHEMA, observer_collected_terminal, validate_evidence, validate_frame,
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    env,
    fs::{self, File, OpenOptions},
    io::{BufWriter, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use horizon_recovered_resource_frame_recovery199::recovery199_contract as recovery199;
use horizon_recovered_resource_frame_recovery199::live145_frame;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    observer: Bound,
    fleet: Bound,
    fleet_plan: Bound,
    prior_parent: Bound,
    prior_completion: Bound,
    prior_fleet_plan: Bound,
    correction191: Bound,
    transition: Bound,
    #[serde(default)]
    prior_recovery: Option<Bound>,
    #[serde(default)]
    fleet_transition: Option<Bound>,
    #[serde(default)]
    native154_transition: Option<Bound>,
    #[serde(default)]
    cohort183_transition: Option<Bound>,
    #[serde(default)]
    observer_collected_terminal: Option<Bound>,
    observer_owner: Owner,
    fleet_owner: Owner,
    output: PathBuf,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Owner {
    unit: String,
    invocation_id: String,
}

fn sha(raw: &[u8]) -> String {
    format!("{:x}", Sha256::digest(raw))
}
fn identity(m: &fs::Metadata) -> (u64, u64, u64, u32, u64, i64, i64, i64, i64) {
    (
        m.dev(),
        m.ino(),
        m.len(),
        m.mode(),
        m.nlink(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}
fn read(b: &Bound) -> Result<Vec<u8>> {
    ensure!(
        b.path.is_absolute()
            && b.path
                .canonicalize()
                .with_context(|| format!("canonicalize bound source {}", b.path.display()))?
                == b.path,
        "noncanonical bound source"
    );
    let m = fs::symlink_metadata(&b.path)
        .with_context(|| format!("stat bound source {}", b.path.display()))?;
    let parent = fs::symlink_metadata(b.path.parent().context("source parent")?)
        .with_context(|| format!("stat parent of bound source {}", b.path.display()))?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o022 == 0
            && m.len() <= 16 << 20
            && parent.is_dir()
            && parent.uid() == 0
            && parent.mode() & 0o022 == 0,
        "source lacks root custody or bounded regular-file shape"
    );
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&b.path)
        .with_context(|| format!("open bound source {}", b.path.display()))?;
    ensure!(
        identity(&m) == identity(&f.metadata()?),
        "source changed before read"
    );
    let mut raw = Vec::new();
    Read::by_ref(&mut f)
        .take((16 << 20) + 1)
        .read_to_end(&mut raw)
        .with_context(|| format!("read bound source {}", b.path.display()))?;
    ensure!(
        raw.len() <= 16 << 20
            && identity(&m) == identity(&f.metadata()?)
            && identity(&m)
                == identity(
                    &fs::symlink_metadata(&b.path)
                        .with_context(|| format!("restat bound source {}", b.path.display()))?
                )
            && sha(&raw) == b.sha256,
        "source changed or digest differs"
    );
    Ok(raw)
}
fn json_read(b: &Bound) -> Result<Value> {
    serde_json::from_slice(&read(b)?).context("bound source JSON")
}
fn native154_sources(transition: Option<&Value>) -> Result<BTreeMap<String, Value>> {
    let mut values = BTreeMap::new();
    if let Some(t) = transition {
        for (stage, members) in [
            ("entry", &["origin", "fleet", "fleet_plan"][..]),
            ("terminal", &["proof", "fleet", "fleet_plan"][..]),
        ] {
            if t[stage].is_null() {
                continue;
            }
            for member in members {
                let bound: Bound = serde_json::from_value(t[stage][member].clone())?;
                values.insert(format!("{stage}.{member}"), json_read(&bound)?);
            }
        }
    }
    Ok(values)
}
fn cohort183_sources(transition: Option<&Value>) -> Result<BTreeMap<String, Value>> {
    let mut sources = BTreeMap::new();
    if let Some(t) = transition.filter(|t| !t[horizon_recovered_resource_frame_recovery199::cached145_inactive_timer_reload::FIELD].is_null()) {
        use horizon_recovered_resource_frame_recovery199::cached145_inactive_timer_reload as reload;
        reload::descriptor_matches(&t[reload::FIELD])?;
        for source in reload::SOURCES {let bound=Bound{path:source.path.into(),sha256:source.sha256.into()};sources.insert(source.key.into(),json_read(&bound)?);}
    }

    if let Some(t) = transition.filter(|t| {
        !t[horizon_recovered_resource_frame_recovery199::cached145_terminal_observer::FIELD]
            .is_null()
    }) {
        use horizon_recovered_resource_frame_recovery199::cached145_terminal_observer as terminal;
        terminal::Witness::descriptor_matches(&t[terminal::FIELD])?;
        for (key, source) in [
            ("terminal145.capture", terminal::CAPTURE),
            ("terminal145.terminal", terminal::TERMINAL),
        ] {
            let bound = Bound {
                path: source.path.into(),
                sha256: source.sha256.into(),
            };
            sources.insert(key.into(), json_read(&bound)?);
        }
    }
    if let Some(t) = transition {
        for member in [
            "canonical_import",
            "source_batch_snapshot",
            "canonical_batch_snapshot",
        ] {
            if t[member].is_null() {
                continue;
            }
            let bound: Bound = serde_json::from_value(t[member].clone())?;
            sources.insert(member.to_owned(), json_read(&bound)?);
        }
    }
    if let Some(rows) = transition.and_then(|t| t["observation_bridge"].as_array()) {
        ensure!(rows.len() <= 16, "observation bridge too long");
        for (index, row) in rows.iter().enumerate() {
            for member in ["observer", "fleet", "fleet_plan"] {
                if row[member].is_null() {
                    continue;
                }
                let bound: Bound = serde_json::from_value(row[member].clone())?;
                sources.insert(format!("bridge.{index}.{member}"), json_read(&bound)?);
            }
        }
    }
    if let Some(t) = transition.filter(|t| !t["verifier183"].is_null()) {
        for member in [
            "event",
            "full_launch",
            "plugin_launch",
            "previous_fleet",
            "previous_plan",
            "entry_fleet",
            "entry_plan",
            "declared_plan",
        ] {
            if t["verifier183"][member].is_null() {
                continue;
            }
            let bound: Bound = serde_json::from_value(t["verifier183"][member].clone())?;
            sources.insert(format!("verifier183.{member}"), json_read(&bound)?);
        }
    }
    if let Some(t) = transition.filter(|t| !t["delivery_owner_delta"].is_null()) {
        for (section, prefix) in [
            ("delivery_owner_delta", "delivery"),
            ("g5_entry", "g5_entry"),
            ("terminal154", "terminal154"),
            ("completed184", "completed184"),
            ("private154_scan_launch", "private154_scans"),
            ("private154_scan_combined", "private154_combined"),
            ("private154_plugin_terminal", "private154_plugin"),
            ("private154_downstream_roles", "private154_downstream"),
            ("charge136_retry0003", "new136"),
            ("charge136_retry0004", "new136_retry0004"),
            ("durable_prefix141", "native141"),
            ("input161_retry6", "g6"),
            ("input161_retry7", "g7"),
            ("input161_retry6_pre_ready", "g6_pre_ready"),
            ("cached145", "cached145"),
        ] {
            if t[section].is_null() {
                continue;
            }
            let members = t[section]["sources"]
                .as_object()
                .context("metadata history source map")?;
            ensure!(members.len() <= 32, "metadata history has too many sources");
            for (name, pair) in members {
                let bound: Bound = serde_json::from_value(pair["preserved"].clone())?;
                ensure!(
                    fs::symlink_metadata(&bound.path)?.mode() & 0o222 == 0,
                    "metadata history preserved source is writable"
                );
                let value = if section == "completed184" && name.ends_with(".receipt") {
                    json!(String::from_utf8(read(&bound)?)?)
                } else {
                    horizon_recovered_resource_frame_recovery199::delivery_history::source_value(
                        section,
                        name,
                        json_read(&bound)?,
                    )?
                };
                sources.insert(format!("{prefix}.{name}"), value);
            }
        }
        if t["delivery_owner_delta"]["mode"] == "retained" {
            let bound: Bound = serde_json::from_value(t["previous_cohort183_transition"].clone())?;
            sources.insert("delivery.previous_transition".into(), json_read(&bound)?);
        }
    }
    if let Some(t) = transition.filter(|t| !t["cached145"].is_null()) {
        let pb: Bound = serde_json::from_value(t["previous_recovery"].clone())?;
        let prior = json_read(&pb)?;
        let fb: Bound = serde_json::from_value(prior["bindings"]["fleet"].clone())?;
        sources.insert("cached145.current_previous_fleet".into(), json_read(&fb)?);
    }
    let retry5 = horizon_recovered_resource_frame_recovery199::retry0005_source_loader::load(
        transition,
        |b| {
            read_input137_source(b,horizon_recovered_resource_frame_recovery199::input137_source_loader::Custody::ImmutablePreserved)
        },
        retry0005_failed4_custody::actual,
    )?;
    for (key, value) in retry5 {
        ensure!(
            sources.insert(key, value).is_none(),
            "retry 0005 source overwrote preserved history"
        );
    }
    let input137 = horizon_recovered_resource_frame_recovery199::input137_source_loader::load(
        transition,
        read_input137_source,
    )?;
    for (k, v) in input137 {
        ensure!(
            sources.insert(k, v).is_none(),
            "input 137 loader duplicated a source role"
        );
    }
    Ok(sources)
}

fn read_input137_source(
    bound: &Bound,
    custody: horizon_recovered_resource_frame_recovery199::input137_source_loader::Custody,
) -> Result<Value> {
    use horizon_recovered_resource_frame_recovery199::input137_source_loader::Custody;
    if custody == Custody::ImmutablePreserved {
        ensure!(
            fs::symlink_metadata(&bound.path)
                .with_context(|| format!(
                    "stat input 137 preserved source {}",
                    bound.path.display()
                ))?
                .mode()
                & 0o222
                == 0,
            "input 137 preserved source is writable: {}",
            bound.path.display()
        );
    }
    let value = json_read(bound)?;
    if custody == Custody::ImmutablePreserved {
        ensure!(
            fs::symlink_metadata(&bound.path)?.mode() & 0o222 == 0,
            "input 137 preserved source became writable"
        );
    }
    Ok(value)
}

fn early_terminal141_capture(e: &Evidence<'_>) -> Result<Value> {
    use horizon_recovered_resource_frame_recovery199::early_terminal141_history as early;
    if !early::selected(e) {
        return Ok(Value::Null);
    }
    let proof = json_read(&Bound {
        path: early::PATH.into(),
        sha256: early::SHA.into(),
    })?;
    early::terminal::validate(&proof)?;
    let units = [
        early::terminal::UNIT,
        early::terminal::GUARD,
        early::terminal::STOP,
        early::terminal::TIMER,
        early::terminal::QUEUE,
    ]
    .map(String::from);
    let keys = [
        "Id",
        "LoadState",
        "ActiveState",
        "SubState",
        "InvocationID",
        "MainPID",
        "ControlPID",
        "NRestarts",
        "Result",
        "ExecMainStatus",
        "ControlGroup",
        "Job",
        "ExecStart",
    ];
    let census = native(&units, &keys)?;
    for name in ["release.json", "first-guard.json", "guard-terminal.json"] {
        let p = Path::new(early::terminal::ROOT)
            .join("guard-logs")
            .join(name);
        ensure!(
            fs::symlink_metadata(&p).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
            "early terminal execution evidence appeared:{}",
            p.display()
        );
    }
    let failed = proof["values"]["failed_fleet_plan"]["output"]
        .as_str()
        .context("early terminal failed output path")?;
    ensure!(
        fs::symlink_metadata(failed).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        "early terminal failed metadata output appeared"
    );
    match fs::read_to_string(format!("/proc/{}/stat", early::terminal::PID)) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Ok(s) => {
            let ticks: u64 = s
                .rsplit_once(") ")
                .context("early terminal process stat")?
                .1
                .split_whitespace()
                .nth(19)
                .context("early terminal process ticks")?
                .parse()?;
            ensure!(
                ticks != early::terminal::TICKS,
                "original early terminal process still live"
            );
        }
        Err(e) => return Err(e.into()),
    }
    let current = json!({"terminal":{"path":early::PATH,"sha256":early::SHA},
        "current_native":census,"old_process_identity_absent":true,
        "absence_checks":{"release":true,"first_guard":true,"guard_terminal":true,"failed_metadata_output":true}});
    early::validate_current(e, &current, &current)?;
    Ok(current)
}

mod native_census;
mod rollover_sources;
fn native(units: &[String], keys: &[&str]) -> Result<BTreeMap<String, Value>> {
    native_census::capture(units, keys)
}
fn authenticate_rollover_sources(e: &Evidence<'_>) -> Result<()> {
    rollover_sources::authenticate(e.fleet, read)?;
    for source in e.cohort183_sources.values() {
        rollover_sources::authenticate(source, read)?;
    }
    Ok(())
}
fn authenticate_guard_history(frame: &Value) -> Result<()> {
    let Some(history) = frame.get("cached145_guard_history") else {
        return Ok(());
    };
    let rows = history
        .as_object()
        .context("cached145 guard history object")?;
    ensure!(rows.len() <= 6, "cached145 guard history exceeds bound");
    for (iid, row) in rows {
        ensure!(
            iid.len() == 32
                && iid
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "invalid guard history IID"
        );
        let bound: Bound = serde_json::from_value(row["binding"].clone())?;
        ensure!(
            fs::symlink_metadata(&bound.path)?.len() <= 1 << 20,
            "guard sample exceeds bound"
        );
        ensure!(
            json_read(&bound)? == row["value"],
            "guard history source bytes differ"
        );
    }
    Ok(())
}
fn cached145_guard_history(e: &Evidence<'_>, censuses: &[&Value]) -> Result<Value> {
    use horizon_recovered_resource_frame_recovery199::cached145_frame as cached;
    let mut result = serde_json::Map::new();
    if !cached::selected(e) {
        return Ok(Value::Object(result));
    }
    if cached145_closed_guard::unchanged(e, censuses)? {
        return Ok(Value::Object(result));
    }
    let plan = e
        .cohort183_sources
        .get("cached145.first_guard_plan")
        .context("cached145 guard plan source")?;
    let directory = Path::new(
        plan["receipt_directory"]
            .as_str()
            .context("guard receipt directory")?,
    );
    for census in censuses {
        for (name, native) in census.as_object().context("guard census object")? {
            if !cached::guard::guard_unit(e, name) {
                continue;
            }
            let iid = native["InvocationID"]
                .as_str()
                .context("guard census IID")?;
            if iid.is_empty() {
                let cap = e
                    .cohort183_sources
                    .get("cached145.capture")
                    .context("cached145 capture source")?;
                let producer = cap["owner"]["unit"]
                    .as_str()
                    .context("cached145 captured unit")?;
                let owner = &e.fleet["unit_census"][producer];
                ensure!(
                    owner["MainPID"] == "0"
                        && owner["ControlPID"] == "0"
                        && owner["ControlGroup"] == ""
                        && matches!(owner["ActiveState"].as_str(), Some("inactive" | "failed"))
                        && native["MainPID"] == "0"
                        && native["ControlPID"] == "0"
                        && native["ControlGroup"] == ""
                        && native["ActiveState"] == "inactive"
                        && native["SubState"] == "dead"
                        && native["Job"]
                            .as_str()
                            .is_some_and(|v| v.is_empty() || v == "0"),
                    "cached145 unidentified guard is not terminal and drained"
                );
                continue;
            }
            ensure!(
                iid.len() == 32
                    && iid
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "invalid guard IID"
            );
            if result.contains_key(iid) {
                continue;
            }
            let path = directory.join(format!("sample-{iid}.json"));
            let mut raw = Vec::new();
            cached145_guard_sample_ready::open(&path, name, iid, native)?
                .take((1 << 20) + 1)
                .read_to_end(&mut raw)
                .with_context(|| format!("read cached145 guard sample {}", path.display()))?;
            ensure!(raw.len() <= 1 << 20, "guard sample exceeds byte bound");
            let bound = Bound {
                path,
                sha256: sha(&raw),
            };
            let value = json_read(&bound)?;
            result.insert(iid.to_owned(), json!({"binding":bound,"value":value}));
        }
    }
    ensure!(result.len() <= 6, "cached145 history exceeds sample bound");
    Ok(Value::Object(result))
}
fn cached145_validate_census(
    e: &Evidence<'_>,
    current: &BTreeMap<String, Value>,
    history: &Value,
    live145: Option<&Value>,
) -> Result<()> {
    let live_fleet=live145_frame::comparison_fleet(e.fleet_plan,e.fleet,live145)?;
    let live_current=live145_frame::comparison_native(e.fleet_plan,current,live145)?;
    let live_e=Evidence {fleet:&live_fleet,..*e};
    let e=&live_e;
    let current=&live_current;
    use horizon_recovered_resource_frame_recovery199::cached145_frame as cached;
    let recovery_view: BTreeMap<String, Value> =
        if let Some(p) = recovery199::load_plan(e.fleet_plan)? {
            serde_json::from_value(
                p.normalize_guard(&e.fleet["unit_census"], &serde_json::to_value(current)?)?,
            )?
        } else {
            current.clone()
        };
    let current = &recovery_view;
    let current: BTreeMap<String, Value> = if let Some(proof) =
        horizon_recovered_resource_frame_recovery199::ordinary199::load(
            &e.fleet_plan["epoch199_enrollment"],
        )? {
        serde_json::from_value(proof.normalize_guard_for_plan(
            &e.fleet["unit_census"],
            &serde_json::to_value(current)?,
            e.fleet_plan,
        )?)?
    } else {
        current.clone()
    };
    if !cached::selected(e) {
        return validate_census(e.fleet, &current);
    }
    let actual = current
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let expected = e.fleet["unit_census"]
        .as_object()
        .context("fleet native census")?;
    let projected = cached::guard::project(e, expected, &actual, history)?;
    validate_census(e.fleet, &projected.into_iter().collect())
}
fn command_identity(value: &Value) -> Result<String> {
    let raw = value.as_str().unwrap_or("");
    if raw.is_empty() {
        return Ok(String::new());
    }
    let (prefix, _) = raw
        .split_once(" ; start_time=")
        .context("native command structure")?;
    Ok(prefix.into())
}
fn validate_census(fleet: &Value, current: &BTreeMap<String, Value>) -> Result<()> {
    let rows = fleet["unit_census"]
        .as_object()
        .context("fleet census missing")?;
    ensure!(rows.len() == current.len(), "native census count differs");
    for (unit, prior) in rows {
        let actual = &current[unit];
        for key in [
            "Id",
            "LoadState",
            "InvocationID",
            "ActiveState",
            "SubState",
            "MainPID",
            "NRestarts",
            "Result",
            "ExecMainStatus",
            "ControlGroup",
            "Type",
        ] {
            ensure!(
                prior[key].as_str().unwrap_or("") == actual[key].as_str().unwrap_or(""),
                "native owner changed: {unit}/{key}"
            );
        }
        ensure!(
            command_identity(&prior["ExecStart"])? == command_identity(&actual["ExecStart"])?,
            "native command changed: {unit}"
        );
    }
    Ok(())
}
fn owner(o: &Owner) -> Result<Value> {
    let rows = native(
        std::slice::from_ref(&o.unit),
        &[
            "Id",
            "InvocationID",
            "ActiveState",
            "SubState",
            "MainPID",
            "NRestarts",
            "Result",
            "ExecMainCode",
            "ExecMainStatus",
        ],
    )?;
    let v = rows[&o.unit].clone();
    ensure!(
        v["InvocationID"] == o.invocation_id
            && v["ActiveState"] == "active"
            && v["SubState"] == "exited"
            && v["MainPID"] == "0"
            && v["NRestarts"] == "0"
            && v["Result"] == "success"
            && v["ExecMainCode"] == "1"
            && v["ExecMainStatus"] == "0",
        "observer/fleet producer is not exact successful native invocation"
    );
    Ok(v)
}
fn collected_observer_absent(unit: &str) -> Result<Value> {
    let out = Command::new("/usr/bin/systemctl")
        .args(["show", unit, "--no-pager"])
        .arg(format!(
            "--property={}",
            observer_collected_terminal::ABSENT_PROPERTIES.join(",")
        ))
        .env("LC_ALL", "C")
        .output()?;
    // PID 1 may return code 1 for a genuinely collected unit. No existing
    // native-owner query is relaxed; the full not-found row below is mandatory.
    ensure!(
        matches!(out.status.code(), Some(0 | 1))
            && out.stdout.len() <= 16 << 10
            && out.stderr.len() <= 16 << 10,
        "collected observer absence query failed or exceeded bound"
    );
    let mut row = serde_json::Map::new();
    for line in std::str::from_utf8(&out.stdout)?.lines() {
        let (key, value) = line
            .split_once('=')
            .context("collected observer native property shape")?;
        ensure!(
            row.insert(key.to_owned(), json!(value)).is_none(),
            "duplicate collected observer native property"
        );
    }
    let actual = Value::Object(row);
    observer_collected_terminal::validate_absent(&actual)?;
    let cgroup = Path::new("/sys/fs/cgroup/system.slice").join(unit);
    ensure!(
        fs::symlink_metadata(&cgroup).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        "collected observer cgroup remains or its absence is unproven"
    );
    Ok(actual)
}
fn observed_observer_owner(
    o: &Owner,
    proof: Option<&Bound>,
    sample: &Bound,
    value: &Value,
) -> Result<Value> {
    let Some(proof) = proof else {
        return owner(o);
    };
    let plan = json_read(proof)?;
    let observer_binding = serde_json::to_value(sample)?;
    observer_collected_terminal::validate_plan(
        &plan,
        &observer_binding,
        &o.unit,
        &o.invocation_id,
    )?;
    let before = collected_observer_absent(&o.unit)?;
    let mut raw = BTreeMap::new();
    for (name, path, sha256) in observer_collected_terminal::SOURCES {
        let bound = Bound {
            path: path.into(),
            sha256: sha256.into(),
        };
        let bytes = read(&bound)?;
        // The actual sealed executable is rehashed through the same bound-file
        // reader, without embedding executable bytes into historical evidence.
        if name != "image" {
            raw.insert(name.to_string(), bytes);
        }
    }
    let mut witness = observer_collected_terminal::validate_material(&raw, value)?;
    let after = collected_observer_absent(&o.unit)?;
    ensure!(
        before == after && json_read(proof)? == plan,
        "collected observer sources or actual absence changed"
    );
    witness["proof_plan"] = serde_json::to_value(proof)?;
    witness["current_native_before"] = before;
    witness["current_native_after"] = after;
    Ok(witness)
}
fn write_buffered_json<W: Write>(sink: W, value: &Value) -> Result<()> {
    let mut writer = BufWriter::with_capacity(1024 * 1024, sink);
    serde_json::to_writer_pretty(&mut writer, value)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}

fn persist(path: &Path, value: &Value) -> Result<()> {
    let parent = path.parent().context("output parent")?;
    let meta = fs::symlink_metadata(parent)?;
    ensure!(
        path.is_absolute()
            && parent.canonicalize()? == parent
            && meta.uid() == 0
            && meta.is_dir()
            && meta.mode() & 0o077 == 0,
        "output directory is not root-private"
    );
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    write_buffered_json(&mut f, value)?;
    f.sync_all()?;
    File::open(parent)?.sync_all()?;
    Ok(())
}
fn run() -> Result<()> {
    let mut args = env::args().collect::<Vec<_>>();
    let historical_regression = args
        .get(1)
        .is_some_and(|s| s == "--historical-accepted-regression");
    if historical_regression {
        args.remove(1);
    }
    let capability_probe = args.get(1).is_some_and(|s| s == "--capability-probe");
    if capability_probe {
        args.remove(1);
    }
    ensure!(
        args.len() == 6
            && args[2] == "--plan-sha256"
            && args[4] == "--self-sha256"
            && unsafe { libc::geteuid() } == 0,
        "usage: PLAN --plan-sha256 HEX --self-sha256 HEX (root)"
    );
    let executable = fs::read_link("/proc/self/exe")?;
    ensure!(
        fs::symlink_metadata(&executable)?.mode() & 0o222 == 0
            && sha(&fs::read(&executable)?) == args[5],
        "running frame executable differs or is writable"
    );
    let plan_bound = Bound {
        path: args[1].clone().into(),
        sha256: args[3].clone(),
    };
    let p: Plan = serde_json::from_slice(&read(&plan_bound)?)?;
    ensure!(
        p.schema == "jetstreamer-horizon-recovered-resource-frame-plan-v1",
        "unsupported frame plan"
    );
    let mut bindings = json!({"observer":p.observer,"fleet":p.fleet,"fleet_plan":p.fleet_plan,"prior_parent":p.prior_parent,"prior_completion":p.prior_completion,"prior_fleet_plan":p.prior_fleet_plan,"correction191":p.correction191,"transition":p.transition});
    if let Some(b) = &p.prior_recovery {
        bindings["prior_recovery"] = serde_json::to_value(b)?;
    }
    if let Some(b) = &p.fleet_transition {
        bindings["fleet_transition"] = serde_json::to_value(b)?;
    }
    if let Some(b) = &p.native154_transition {
        bindings["native154_transition"] = serde_json::to_value(b)?;
    }
    if let Some(b) = &p.cohort183_transition {
        bindings["cohort183_transition"] = serde_json::to_value(b)?;
    }
    let cohort183_before = p.cohort183_transition.as_ref().map(json_read).transpose()?;
    let cohort183_sources_before = cohort183_sources(cohort183_before.as_ref())?;
    let prior_recovery_before = p.prior_recovery.as_ref().map(json_read).transpose()?;
    let fleet_transition_before = p.fleet_transition.as_ref().map(json_read).transpose()?;
    let native_transition_before = p.native154_transition.as_ref().map(json_read).transpose()?;
    let native_sources_before = native154_sources(native_transition_before.as_ref())?;
    let before = [
        &p.observer,
        &p.fleet,
        &p.fleet_plan,
        &p.prior_parent,
        &p.prior_completion,
        &p.prior_fleet_plan,
        &p.correction191,
        &p.transition,
    ]
    .into_iter()
    .map(json_read)
    .collect::<Result<Vec<_>>>()?;
    let historical_frame = if historical_regression {
        let exact=Bound{path:"/var/lib/jetstreamer/horizon-recovered-resource-frames-20261029-v1/frame20261101T041809-private154-delivery-terminal-retained-g6-g7-debt-v19.json".into(),sha256:"d3112f147a5fb0577511066263c55dd0b16eebd1a62f6578395245d08b5b176f".into()};
        ensure!(
            p.output == exact.path,
            "historical regression is fixed to authentic accepted0418 Frame19"
        );
        Some(json_read(&exact)?)
    } else {
        None
    };
    let capture_sha = historical_frame
        .as_ref()
        .map(|f| f["self_sha256"].as_str().context("historical artifact SHA"))
        .transpose()?
        .unwrap_or(&args[5]);
    let e = Evidence {
        observer: &before[0],
        fleet: &before[1],
        fleet_plan: &before[2],
        prior_parent: &before[3],
        prior_completion: &before[4],
        prior_fleet_plan: &before[5],
        transition: &before[7],
        prior_recovery: prior_recovery_before.as_ref(),
        fleet_transition: fleet_transition_before.as_ref(),
        capture_tool_sha: capture_sha,
        native154_transition: native_transition_before.as_ref(),
        cohort183_transition: cohort183_before.as_ref(),
        cohort183_sources: &cohort183_sources_before,
        native154_sources: &native_sources_before,
    };
    if let Some(frame) = historical_frame.as_ref() {
        let at = frame["recorded_unix_seconds"]
            .as_u64()
            .context("historical capture time")?;
        validate_frame(frame, &e, &bindings, at)?;
        println!(
            "{}",
            json!({"schema":"cached145-producer20-authentic-accepted0418-regression-v1","historical_frame_sha256":"d3112f147a5fb0577511066263c55dd0b16eebd1a62f6578395245d08b5b176f","passed":true,"original_clock_used_only_for_historical_validation":true,"new_resource_samples":0,"current_native_observations":0,"frame_written":false,"replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false})
        );
        return Ok(());
    }
    authenticate_rollover_sources(&e)?;
    if let Some(previous) = e.prior_recovery {
        authenticate_guard_history(previous)?;
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    validate_evidence(&e, &bindings, now)?;
    let units = e.fleet["unit_census"]
        .as_object()
        .context("unit census")?
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    let keys = [
        "Id",
        "LoadState",
        "InvocationID",
        "ActiveState",
        "SubState",
        "MainPID",
        "NRestarts",
        "Result",
        "ExecMainStatus",
        "ControlGroup",
        "Type",
        "ExecStart",
        "ControlPID",
        "Job",
        "Restart",
        "MemoryAccounting",
        "MemoryHigh",
        "MemoryMax",
        "MemorySwapMax",
        "CPUQuotaPerSecUSec",
        "TasksMax",
        "User",
        "ProtectSystem",
        "ProtectHome",
        "PrivateNetwork",
        "NoNewPrivileges",
        "ReadWritePaths",
        "CapabilityBoundingSet",
        "DropInPaths",
        "PrivateTmp",
        "Group",
        "KillMode",
        "Delegate",
        "AmbientCapabilities",
        "RuntimeMaxUSec",
        "ExecMainCode",
        "ExecMainPID",
        "ExecMainStartTimestamp",
        "ExecMainExitTimestamp",
        "RemainAfterExit",
        "Triggers",
        "TriggeredBy",
    ];
    let early_terminal141_before = early_terminal141_capture(&e)?;
    let native_before = native(&units, &keys)?;
    let live145_before=live145_frame::capture(e.fleet_plan,SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;
    let recovery_guard_before = if let Some(p) = recovery199::load_plan(e.fleet_plan)? {
        if p.terminal.is_none() {
            let h = recovery199::guard::capture(&p, now)?;
            ensure!(
                recovery199::FAMILY
                    .iter()
                    .all(|u| h["full_family"][*u] == native_before[*u]),
                "recovery199 Frame before native/guard crossed"
            );
            Some(h)
        } else {
            None
        }
    } else {
        None
    };
    let initial_guard_history = cached145_guard_history(
        &e,
        &[
            &e.fleet["unit_census"],
            &serde_json::to_value(&native_before)?,
        ],
    )?;
    cached145_validate_census(&e, &native_before, &initial_guard_history,live145_before.as_ref())?;
    let observer_owner = observed_observer_owner(
        &p.observer_owner,
        p.observer_collected_terminal.as_ref(),
        &p.observer,
        e.observer,
    )?;
    let fleet_owner = owner(&p.fleet_owner)?;
    let after = [
        &p.observer,
        &p.fleet,
        &p.fleet_plan,
        &p.prior_parent,
        &p.prior_completion,
        &p.prior_fleet_plan,
        &p.correction191,
        &p.transition,
    ]
    .into_iter()
    .map(json_read)
    .collect::<Result<Vec<_>>>()?;
    ensure!(before == after, "frame evidence changed during acceptance");
    ensure!(
        prior_recovery_before == p.prior_recovery.as_ref().map(json_read).transpose()?
            && fleet_transition_before == p.fleet_transition.as_ref().map(json_read).transpose()?,
        "recovery predecessor or fleet delta changed during acceptance"
    );
    ensure!(
        native_transition_before == p.native154_transition.as_ref().map(json_read).transpose()?
            && native_sources_before == native154_sources(native_transition_before.as_ref())?,
        "native154 transition changed during capture"
    );
    ensure!(
        cohort183_before == p.cohort183_transition.as_ref().map(json_read).transpose()?
            && cohort183_sources_before == cohort183_sources(cohort183_before.as_ref())?,
        "183 transition changed during capture"
    );
    authenticate_rollover_sources(&e)?;
    let native_after = native(&units, &keys)?;
    let live145_after=live145_frame::capture(e.fleet_plan,SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;
    let recovery_guard_after = if let Some(p) = recovery199::load_plan(e.fleet_plan)? {
        if p.terminal.is_none() {
            let h = recovery199::guard::capture(
                &p,
                SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            )?;
            ensure!(
                recovery199::FAMILY
                    .iter()
                    .all(|u| h["full_family"][*u] == native_after[*u]),
                "recovery199 Frame after native/guard crossed"
            );
            recovery199::guard::compare(
                &p,
                recovery_guard_before
                    .as_ref()
                    .context("recovery199 first Frame guard history")?,
                &h,
            )?;
            Some(h)
        } else {
            None
        }
    } else {
        None
    };
    let early_terminal141_after = early_terminal141_capture(&e)?;
    let guard_history = cached145_guard_history(
        &e,
        &[
            &e.fleet["unit_census"],
            &serde_json::to_value(&native_before)?,
            &serde_json::to_value(&native_after)?,
        ],
    )?;
    cached145_validate_census(&e, &native_after, &guard_history,live145_after.as_ref())?;
    let recovery_comparison_after = if let Some(p) = recovery199::load_plan(e.fleet_plan)? {
        p.normalize_guard(
            &serde_json::to_value(&native_before)?,
            &serde_json::to_value(&native_after)?,
        )?
    } else {
        serde_json::to_value(&native_after)?
    };
    let comparison_after = if let Some(proof) =
        horizon_recovered_resource_frame_recovery199::ordinary199::load(
            &e.fleet_plan["epoch199_enrollment"],
        )? {
        proof.normalize_guard_for_plan(
            &serde_json::to_value(&native_before)?,
            &recovery_comparison_after,
            e.fleet_plan,
        )?
    } else {
        recovery_comparison_after
    };
    let comparison_before=live145_frame::census_view(e.fleet_plan,&serde_json::to_value(&native_before)?,live145_before.as_ref())?;
    let comparison_after=live145_frame::census_view(e.fleet_plan,&comparison_after,live145_after.as_ref())?;
    ensure!(
        comparison_before == comparison_after || (horizon_recovered_resource_frame_recovery199::cached145_frame::selected(&e)
            && horizon_recovered_resource_frame_recovery199::cached145_frame::guard::census_stable(&e, &comparison_before, &comparison_after, &guard_history)?),
        "native census changed during acceptance"
    );
    if p.observer_collected_terminal.is_some() {
        ensure!(
            observer_owner
                == observed_observer_owner(
                    &p.observer_owner,
                    p.observer_collected_terminal.as_ref(),
                    &p.observer,
                    e.observer
                )?,
            "collected observer historical witness or actual absence changed during capture"
        );
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    validate_evidence(&e, &bindings, now)?;
    let mut frame = json!({"schema":SCHEMA,"accepted_resource_lineage":true,"bindings":bindings,"plan":plan_bound,"self_sha256":args[5],"recorded_unix_seconds":now,"sampled_at_utc":e.observer["recorded_at_utc"],"observer_owner":observer_owner,"fleet_owner":fleet_owner,"early_terminal141_before":early_terminal141_before,"early_terminal141_after":early_terminal141_after,"native_census_before":native_before,"native_census_after":native_after,"cached145_guard_history":guard_history,"replay_launch_authorized":false,"publication_authorized":false,"remote_mutations":false,"remaining_growth_released":false,"new191_closure_incremental_DATA_credit_bytes":0,"archive_mutations":false,"sidecar_mutations":false,"full_routine_completion_claimed":false,"new_resource_observations":0});
    if let Some(history)=live145_frame::history(&live145_before,&live145_after)? {
        frame[live145_frame::FIELD]=history;
    }
    if let Some(proof) = horizon_recovered_resource_frame_recovery199::ordinary199::load(
        &e.fleet_plan["epoch199_enrollment"],
    )? {
        frame["epoch199_enrollment"] = serde_json::to_value(&proof.binding)?;
        frame["epoch199_promises"] = proof.accounting();
        if !e.fleet_plan["epoch199_terminal_context"].is_null() {
            frame["epoch199_terminal_context"] = e.fleet_plan["epoch199_terminal_context"].clone();
        }
    }
    if !e.fleet_plan["epoch199_http500_capture_registration"].is_null() {
        frame["epoch199_http500_capture_registration"] =
            e.fleet_plan["epoch199_http500_capture_registration"].clone();
    }
    if let Some(p) = recovery199::load_plan(e.fleet_plan)? {
        frame[recovery199::FIELD] = json!(p.binding);
        frame[recovery199::PROMISES_FIELD] = p.accounting();
        if let Some(t) = &p.terminal {
            frame[recovery199::TERMINAL_FIELD] = json!(t.binding);
            frame["epoch199_http500_guard_history"] =
                json!({"terminal_context":t.binding,"memory_or_DATA_credit_bytes":0});
        } else {
            frame["epoch199_http500_guard_history"] = json!([
                recovery_guard_before.context("recovery199 first guard history")?,
                recovery_guard_after.context("recovery199 second guard history")?
            ]);
        }
    }
    validate_frame(&frame, &e, &bindings, now)?;
    if capability_probe {
        println!(
            "{}",
            json!({"schema":"jetstreamer-private154-resource-frame-capability-v1","self_sha256":args[5],"plan":plan_bound,
            "accepted_resource_lineage":false,"capability_proven":true,"native_census_unchanged":true,
            "new_resource_observations":0,"resource_frame_written":false,"replay_launch_authorized":false,
            "publication_authorized":false,"r2_mutations":false})
        );
    } else {
        persist(&p.output, &frame)?;
        println!("{}", p.output.display());
    }
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("{error:#}");
        std::process::exit(1)
    }
}

#[cfg(test)]
mod bound_source_error_tests {
    use super::*;
    #[test]
    fn missing_bound_source_retains_path_and_underlying_error() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = env::temp_dir()
            .join(format!("frame-missing-{}-{suffix}", std::process::id()))
            .join("source.json");
        let error = read(&Bound {
            path: path.clone(),
            sha256: "a".repeat(64),
        })
        .unwrap_err();
        let detail = format!("{error:#}");
        assert!(detail.contains("canonicalize bound source"));
        assert!(detail.contains(&path.display().to_string()));
        assert!(detail.contains("No such file or directory"));
    }
}

#[cfg(test)]
mod input137_producer_io_tests;

#[cfg(test)]
mod buffered_json_writer_tests {
    use super::*;

    #[derive(Default)]
    struct CountedSink {
        bytes: Vec<u8>,
        calls: usize,
    }
    impl Write for CountedSink {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.calls += 1;
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn pretty_json_bytes_are_identical_while_small_writes_are_coalesced() {
        let points: Vec<_> = (0..20000)
            .map(|i| {
                json!({
                    "path": format!("/private/source-{i:05}.json"),
                    "sha256": "a".repeat(64), "pid": i,
                })
            })
            .collect();
        let value = json!({"fixture": true, "points": points});
        let mut expected = serde_json::to_vec_pretty(&value).unwrap();
        expected.push(b'\n');
        let mut sink = CountedSink::default();
        write_buffered_json(&mut sink, &value).unwrap();
        assert_eq!(sink.bytes, expected);
        assert!(sink.calls > 0);
        assert!(sink.calls <= expected.len().div_ceil(1024 * 1024) + 2);
    }

    struct FailingSink;
    impl Write for FailingSink {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("fixture sink write failed"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    #[test]
    fn final_buffer_flush_failure_is_propagated() {
        let error = write_buffered_json(FailingSink, &json!({"fixture": true})).unwrap_err();
        assert!(error.to_string().contains("fixture sink write failed"));
    }
}

#[cfg(test)]
mod genuine0728_complete_validator_tests;
