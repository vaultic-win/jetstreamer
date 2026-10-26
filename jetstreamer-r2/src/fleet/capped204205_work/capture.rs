//! Future coordinated metadata capture. No resource counters, Bank, archive
//! contents, service mutations or remote operations are sampled here.
use super::*;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    producer_plan: BoundFile,
    admission: BoundFile,
    observer: BoundFile,
    observer_executable: BoundFile,
    previous_fleet: BoundFile,
    launch: Option<BoundFile>,
    downstream_actors: Vec<Actor>,
    authenticated_other_host_handoffs: Vec<BoundFile>,
    output_directory: PathBuf,
}

pub(super) fn file_sha(path: &Path) -> Result<String> {
    Ok(hex_lower(&Sha256::digest(read_stable_bounded(
        path,
        16 << 20,
        "captured metadata digest",
    )?)))
}
fn binding(path: &Path) -> Result<BoundFile> {
    Ok(BoundFile {
        path: path.into(),
        sha256: file_sha(path)?,
    })
}
pub(super) fn write_sealed(path: &Path, value: &Value) -> Result<()> {
    let parent = path.parent().context("capped metadata parent")?;
    let m = fs::symlink_metadata(parent)?;
    ensure!(
        parent.canonicalize()? == parent && m.is_dir() && m.uid() == 0 && m.mode() & 0o077 == 0,
        "capped metadata needs a canonical root-private output directory"
    );
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    serde_json::to_writer_pretty(file.as_file_mut(), value)?;
    file.as_file_mut().write_all(b"\n")?;
    file.as_file()
        .set_permissions(fs::Permissions::from_mode(0o400))?;
    file.as_file().sync_all()?;
    file.persist_noclobber(path)
        .map_err(|e| anyhow!("capped metadata publication conflict: {e}"))?;
    File::open(parent)?.sync_all()?;
    Ok(())
}
fn write_raw(path: &Path, raw: &[u8]) -> Result<()> {
    let parent = path.parent().context("raw metadata parent")?;
    let m = fs::symlink_metadata(parent)?;
    ensure!(
        parent.canonicalize()? == parent && m.uid() == 0 && m.is_dir() && m.mode() & 0o077 == 0,
        "unsafe raw metadata parent"
    );
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.write_all(raw)?;
    file.as_file()
        .set_permissions(fs::Permissions::from_mode(0o400))?;
    file.as_file().sync_all()?;
    file.persist_noclobber(path)
        .map_err(|e| anyhow!("raw metadata already exists: {e}"))?;
    File::open(parent)?.sync_all()?;
    Ok(())
}
fn source_bytes(path: &Path, owner: u32) -> Result<Vec<u8>> {
    ensure!(
        path.canonicalize()? == path,
        "noncanonical actual metadata source"
    );
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_file() && m.uid() == owner && m.nlink() == 1 && m.mode() & 0o222 == 0,
        "actual metadata source is not owner-readonly and singly linked"
    );
    read_stable_bounded(path, 4 << 20, "actual capped metadata source")
}
fn command_output(program: &str, args: &[&str]) -> Result<Vec<u8>> {
    let result = ProcessCommand::new(program)
        .env("LC_ALL", "C")
        .args(args)
        .output()?;
    ensure!(
        result.status.success() && result.stdout.len() <= 4 << 20,
        "complete capped metadata query failed/oversized"
    );
    Ok(result.stdout)
}
pub(super) fn journal(unit: &str) -> Result<Vec<u8>> {
    command_output(
        "/usr/bin/journalctl",
        &[
            "--no-pager",
            "--output=json",
            "_PID=1",
            &format!("UNIT={unit}"),
        ],
    )
}
// This exact PID 1 parser diagnostic can follow Started during a reload. It
// describes the installed configuration, not an invocation lifecycle event.
// Keep the raw record and every ordinary journal check; never generalize this
// to arbitrary missing-IID records or configuration warnings.
fn exact_cpu_accounting_warning(v: &Value, unit: &str, start_boot: Option<&str>) -> bool {
    const UNIT: &str = "horizon-qualify-204-capped-continuation-e506rss-v2.service";
    unit == UNIT
        && v["UNIT"] == UNIT
        && v["_PID"] == "1"
        && v["_UID"] == "0"
        && v["_COMM"] == "systemd"
        && v["_EXE"] == "/usr/lib/systemd/systemd"
        && v.get("INVOCATION_ID").is_none()
        && v["__CURSOR"].as_str().is_some_and(|s| !s.is_empty())
        && start_boot.is_some_and(|boot| {
            boot.len() == 32
                && boot
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
                && v["_BOOT_ID"] == boot
        })
        && v["MESSAGE_ID"] == "c772d24e9a884cbeb9ea12625c306c01"
        && v["CODE_FUNC"] == "config_parse_warn_compat"
        && v["CODE_FILE"] == "src/shared/conf-parser.c"
        && v["CODE_LINE"] == "1391"
        && v["MESSAGE"]
            == "/etc/systemd/system/horizon-qualify-204-capped-continuation-e506rss-v2.service:21: Support for option CPUAccounting= has been removed and it is ignored"
}
pub(super) fn manager_history(raw: &[u8], unit: &str, iid: &str, success: bool) -> Result<u64> {
    let mut starts = Vec::new();
    let mut ends = Vec::new();
    let mut rows = Vec::new();
    let mut cursors = BTreeSet::new();
    let mut last = 0u64;
    for line in std::str::from_utf8(raw)?.lines() {
        let v: Value = serde_json::from_str(line)?;
        let time = string(&v, "__REALTIME_TIMESTAMP")?.parse::<u64>()?;
        ensure!(
            v["_PID"] == "1"
                && v["_UID"] == "0"
                && v["UNIT"] == unit
                && time >= last
                && cursors.insert(string(&v, "__CURSOR")?.to_owned()),
            "capped PID 1 journal identity/order differs"
        );
        last = time;
        if v["INVOCATION_ID"] == iid && v["MESSAGE_ID"] == "39f53479d3a045ac8e11786248231fbf" {
            starts.push(time);
        }
        if v["INVOCATION_ID"] == iid && v["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448" {
            ensure!(
                v["MESSAGE"] == format!("{unit}: Deactivated successfully."),
                "manager success marker has a different message"
            );
            ends.push(time);
        }
        rows.push((time, v));
        ensure!(rows.len() <= 16384, "capped manager history exceeds bound");
    }
    ensure!(
        starts.len() == 1 && starts[0] > 0,
        "exact actual PID 1 start missing/duplicate"
    );
    if success {
        ensure!(
            ends.len() == 1 && ends[0] > starts[0],
            "actual natural PID 1 success missing"
        );
    }
    let start_boot = rows
        .iter()
        .find(|(time, v)| {
            *time == starts[0]
                && v["INVOCATION_ID"] == iid
                && v["MESSAGE_ID"] == "39f53479d3a045ac8e11786248231fbf"
        })
        .and_then(|(_, v)| v["_BOOT_ID"].as_str())
        .map(str::to_owned);
    for (time, v) in rows.into_iter().filter(|(time, _)| *time >= starts[0]) {
        ensure!(
            v["INVOCATION_ID"] == iid
                || exact_cpu_accounting_warning(&v, unit, start_boot.as_deref()),
            "replacement invocation follows original start"
        );
        if success {
            let message = string(&v, "MESSAGE")?;
            ensure!(
                !message.starts_with("Stopping ")
                    && !message.starts_with("Stopped ")
                    && !message.contains(": Failed")
                    && !message.contains(": Killing")
                    && v.get("EXIT_STATUS")
                        .and_then(Value::as_str)
                        .is_none_or(|s| s == "0"),
                "manager reports stop/failure"
            );
        }
        ensure!(time >= starts[0], "journal order changed");
    }
    Ok(starts[0] / 1000)
}

pub(super) fn manager_terminal(raw: &[u8], unit: &str, iid: &str) -> Result<()> {
    let start = manager_history(raw, unit, iid, false)?
        .checked_mul(1000)
        .context("manager terminal clock overflow")?;
    let mut terminal = false;
    for line in std::str::from_utf8(raw)?.lines() {
        let row: Value = serde_json::from_str(line)?;
        let at = string(&row, "__REALTIME_TIMESTAMP")?.parse::<u64>()?;
        if at < start || row["INVOCATION_ID"] != iid {
            continue;
        }
        let message = string(&row, "MESSAGE")?;
        terminal |= (row["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448"
            && message == format!("{unit}: Deactivated successfully."))
            || (row["MESSAGE_ID"] == "be02cf6855d2428ba40df7e9d022f03d"
                && message.starts_with(&format!("{unit}: Failed with result '"))
                && message.ends_with("'."))
            || (row["MESSAGE_ID"] == "9d1aaa27d60140bd96365438aad20286"
                && row["JOB_TYPE"] == "stop"
                && row["JOB_RESULT"] == "done");
    }
    ensure!(
        terminal,
        "exact PID 1 terminal event missing for unit {unit}, invocation {iid}; disappearance alone is not inactivity"
    );
    Ok(())
}
pub(super) fn epoch_scope(epoch: u64, name: &str) -> bool {
    namespace(epoch, name)
        || name.starts_with(&format!("horizon-guard-{epoch}-capped-continuation-"))
        || name.starts_with(&format!("horizon-qualify-{epoch}-"))
        || [
            "horizon-full-verify-",
            "horizon-plugin-verify-",
            "horizon-publish-",
            "horizon-upload-",
            "horizon-independent-full-read-",
        ]
        .iter()
        .any(|prefix| {
            name.strip_prefix(prefix).and_then(|s| s.split('-').next())
                == Some(epoch.to_string().as_str())
        })
}
fn current_stamp() -> Result<(String, u64)> {
    let ms: u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?;
    let secs: libc::time_t = (ms / 1000).try_into()?;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    ensure!(
        !unsafe { libc::gmtime_r(&secs, &mut tm) }.is_null(),
        "cannot format capped sample time"
    );
    Ok((
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            tm.tm_year + 1900,
            tm.tm_mon + 1,
            tm.tm_mday,
            tm.tm_hour,
            tm.tm_min,
            tm.tm_sec
        ),
        ms,
    ))
}
fn archive(path: &Path) -> Result<Option<Value>> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
        Ok(_) => (),
    }
    ensure!(
        path.canonicalize()? == path,
        "redirected private archive metadata path"
    );
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let m = file.metadata()?;
    ensure!(
        m.is_file() && m.nlink() == 1 && matches!(m.uid(), 0 | 1000) && m.mode() & 0o022 == 0,
        "unqualified private archive metadata identity"
    );
    let after = fs::symlink_metadata(path)?;
    ensure!(
        m.dev() == after.dev() && m.ino() == after.ino(),
        "archive identity changed during metadata-only stat"
    );
    Ok(Some(
        json!({"path":path,"bytes":m.len(),"device":m.dev(),"inode":m.ino(),"uid":m.uid(),"links":m.nlink(),"archive_body_read":false}),
    ))
}
pub(super) fn group(unit: &str) -> Result<Value> {
    let path = Path::new("/sys/fs/cgroup/system.slice").join(unit);
    let m = match fs::symlink_metadata(&path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(json!({"state":"absent","path":path}));
        }
        Err(e) => return Err(e.into()),
    };
    ensure!(
        m.is_dir() && path.canonicalize()? == path,
        "unsafe terminal cgroup path"
    );
    let raw = fs::read_to_string(path.join("cgroup.events"))?;
    let fields: BTreeMap<_, _> = raw
        .lines()
        .map(|line| line.split_once(' ').context("malformed cgroup events"))
        .collect::<Result<_>>()?;
    ensure!(
        fields.get("populated") == Some(&"0"),
        "capped terminal cgroup or descendant remains populated"
    );
    let after = fs::symlink_metadata(&path)?;
    ensure!(
        m.dev() == after.dev() && m.ino() == after.ino(),
        "cgroup changed during terminal check"
    );
    Ok(
        json!({"state":"unpopulated","path":path,"events_sha256":hex_lower(&Sha256::digest(raw.as_bytes()))}),
    )
}
fn launch(s: &Spec, p: &Value, a: &Value, before: &BTreeMap<String, Value>) -> Result<BoundFile> {
    if let Some(b) = &s.launch {
        evidence::bound(b, true)?;
        return Ok(BoundFile {
            path: b.path.clone(),
            sha256: b.sha256.clone(),
        });
    }
    let current = before
        .get(string(p, "producer_unit")?)
        .context("actual launch owner missing")?;
    ensure!(
        live(current),
        "initial launch capture requires a real live owner; collected history cannot invent its command"
    );
    let expected = evidence::expected_command(p, a, &s.producer_plan)?;
    ensure!(
        evidence::command_matches(&expected, string(current, "ExecStart")?),
        "actual capped launch command differs from sealed plan"
    );
    let first_path = Path::new(string(p, "guard_directory")?).join("first-fire.json");
    let raw = source_bytes(&first_path, 0)?;
    let first: Value = serde_json::from_slice(&raw)?;
    ensure!(
        first["schema"] == "jetstreamer-capped204205-guard-heartbeat-v1"
            && first["plan_sha256"] == s.producer_plan.sha256
            && first["producer_invocation_id"] == current["InvocationID"]
            && first["guard_sha256"] == p["guard_sha256"]
            && first["trip"] == false
            && first["producer_stop_enabled"] == true,
        "actual first guard fire missing"
    );
    let epoch = number(p, "epoch")?;
    let (old, old_iid, restart, end) = profile(epoch)?;
    let manager: BoundFile = serde_json::from_value(p["metadata"]["manager_journal"].clone())?;
    let origin = manager_history(&evidence::bytes(&manager, true)?, old, old_iid, true)?;
    let first_copy = s.output_directory.join("first-guard.json");
    write_raw(&first_copy, &raw)?;
    let name = string(p, "producer_unit")?;
    let launch_journal = journal(name)?;
    let actual_start = manager_history(
        &launch_journal,
        name,
        string(current, "InvocationID")?,
        false,
    )?;
    lifecycle::first_guard_entry(&first, actual_start)?;
    let guard_owner = before
        .get(string(p, "guard_unit")?)
        .context("launch omitted independent guard")?;
    ensure!(
        live(guard_owner)
            && guard_owner["InvocationID"] == first["guard_invocation_id"]
            && evidence::command_matches(
                &evidence::expected_guard_command(
                    p,
                    a,
                    &s.producer_plan,
                    string(current, "InvocationID")?
                )?,
                string(guard_owner, "ExecStart")?
            ),
        "first launch guard has another executable, command or invocation"
    );
    let launch_manager = s.output_directory.join("launch-manager.jsonl");
    write_raw(&launch_manager, &launch_journal)?;
    let value = json!({"schema":"jetstreamer-capped204205-continuation-launch-v1","epoch":epoch,"unit":p["producer_unit"],
        "invocation_id":current["InvocationID"],"guard_unit":p["guard_unit"],"guard_invocation_id":first["guard_invocation_id"],
        "producer_plan":private157::binding(&s.producer_plan),"admission":private157::binding(&s.admission),
        "node_sha256":p["node_sha256"],"guard_sha256":p["guard_sha256"],"recorded_unix_millis":first["recorded_unix_millis"],
        "epoch_started_unix_millis":origin,"expected_exec_start":current["ExecStart"],"restart_slot":restart,"terminal_slot":end,
        "main_pid":string(current,"MainPID")?.parse::<u64>()?,"unit_census":before,
        "first_guard":private157::binding(&binding(&first_copy)?),"manager_journal":private157::binding(&binding(&launch_manager)?),
        "first_fire_source":{"path":first_path,"sha256":hex_lower(&Sha256::digest(raw))},
        "accepted_observer_context":private157::binding(&s.observer),"accepted_fleet_context":private157::binding(&s.previous_fleet),
        "accepted_observer_context_does_not_assert_new_producer_was_sampled":true,
        "replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false});
    let path = s.output_directory.join("launch.json");
    write_sealed(&path, &value)?;
    binding(&path)
}

pub(super) fn observer_registration(p: &Value, l: &Value) -> Result<Value> {
    let epoch = number(p, "epoch")?;
    profile(epoch)?;
    let name = string(p, "producer_unit")?;
    let iid = string(l, "invocation_id")?;
    ensure!(
        namespace(epoch, name) && id(iid),
        "observer registration needs exact captured producer identity"
    );
    Ok(
        json!({"range":format!("{epoch}-{epoch}"),"controller_unit":name,"expected_controller_invocation_id":iid,
        "producer_unit":name,"expected_producer_invocation_id":iid,
        "scratch_path":Path::new(string(p,"run_root")?).join("scratch"),"worker_executable_basename":"historical-worker"}),
    )
}

pub(super) fn run() -> Result<()> {
    let args: Vec<_> = env::args().collect();
    ensure!(
        args.len() == 7
            && args[3] == "--spec-sha256"
            && args[5] == "--self-sha256"
            && unsafe { libc::geteuid() } == 0,
        "usage: capture-capped204205-work SPEC --spec-sha256 SHA --self-sha256 SHA"
    );
    ensure!(
        hex_lower(&Sha256::digest(fs::read("/proc/self/exe")?)) == args[6],
        "capped metadata capture binary differs"
    );
    let s: Spec = serde_json::from_value(evidence::bound(
        &BoundFile {
            path: args[2].clone().into(),
            sha256: args[4].clone(),
        },
        true,
    )?)?;
    ensure!(
        s.schema == "jetstreamer-capped204205-work-capture-spec-v1",
        "wrong capped metadata capture spec"
    );
    let p = evidence::bound(&s.producer_plan, true)?;
    lifecycle::plan_scope(&p)?;
    let a = evidence::bound(&s.admission, true)?;
    for handoff in &s.authenticated_other_host_handoffs {
        evidence::bound(handoff, true)?;
    }
    let epoch = number(&p, "epoch")?;
    profile(epoch)?;
    let observer = evidence::bound(&s.observer, false)?;
    let prior = evidence::bound(&s.previous_fleet, false)?;
    let observer_source_revision = observer_revision(&s.observer_executable.sha256)
        .context("observer executable is not a qualified corrected generation")?;
    evidence::executable(&s.observer_executable)?;
    ensure!(
        prior["schema"] == SCHEMA
            && prior["first_epoch"] == 201
            && prior["last_epoch"] == 300
            && observer["schema"] == "jetstreamer-horizon-live-resource-sample-v2",
        "capped capture lacks the accepted coordinated observation"
    );
    let mut names: BTreeSet<String> = prior["unit_census"]
        .as_object()
        .context("prior complete unit census")?
        .keys()
        .cloned()
        .collect();
    names.insert(string(&p, "producer_unit")?.into());
    names.insert(string(&p, "guard_unit")?.into());
    names.insert(profile(epoch)?.0.into());
    names.extend(s.downstream_actors.iter().map(|a| a.unit.clone()));
    let before = census(&names, 201, 300)?;
    original_capped204205::idle_for_plan(&before[profile(epoch)?.0], &p)?;
    let launched = launch(&s, &p, &a, &before)?;
    let l = evidence::bound(&launched, true)?;
    ensure!(
        s.launch.is_some()
            || (prior["observer_sha256"] == s.observer.sha256
                && prior["observer_receipt"].as_str() == s.observer.path.to_str()),
        "successor observation requires an existing actual launch capture"
    );
    observer_handoff::validate(
        &s.previous_fleet,
        &s.observer,
        &observer,
        &s.producer_plan,
        &s.admission,
        &l,
    )?;
    let registration = observer_registration(&p, &l)?;
    let registration_path = s.output_directory.join("next-observer-registration.json");
    write_sealed(
        &registration_path,
        &json!({"schema":"jetstreamer-capped204205-next-observer-registration-v1",
        "epoch":epoch,"origin_launch":private157::binding(&launched),"diagnostic_replay":registration,
        "replace_overlapping_epoch_diagnostic":true,"preserve_all_other_config_fields":true,
        "next_sole_30_minute_observer_must_include_producer":true,"observer_config_modified":false,
        "replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false}),
    )?;
    peer::captured_registration(
        &p,
        &l,
        &evidence::bound(&binding(&registration_path)?, true)?,
        &observer,
    )?;
    let mut actors = s.downstream_actors;
    for actor in &mut actors {
        if actor.evidence.is_empty() {
            let current = &before[&actor.unit];
            ensure!(
                live(current)
                    && current["InvocationID"] == actor.invocation_id
                    && pipeline_status::same_exec_start(
                        &actor.expected_exec_start,
                        string(current, "ExecStart")?
                    ),
                "downstream launch capture needs actual live exact owner"
            );
            let raw = journal(&actor.unit)?;
            let start = manager_history(&raw, &actor.unit, &actor.invocation_id, false)?;
            ensure!(
                actor.started_unix_millis == start,
                "downstream stage clock is not actual PID 1 start"
            );
            let path = s
                .output_directory
                .join(format!("downstream-{}.json", actor.invocation_id));
            let manager_path = s
                .output_directory
                .join(format!("downstream-{}-manager.jsonl", actor.invocation_id));
            write_raw(&manager_path, &raw)?;
            write_sealed(
                &path,
                &json!({"schema":"jetstreamer-capped204205-downstream-launch-v1","epoch":epoch,
                "origin_launch":private157::binding(&launched),"origin_invocation_id":l["invocation_id"],
                "unit":actor.unit,"invocation_id":actor.invocation_id,"expected_exec_start":actor.expected_exec_start,
                "main_pid":string(current,"MainPID")?.parse::<u64>()?,"manager_journal":private157::binding(&binding(&manager_path)?),
                "started_unix_millis":start,"replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false}),
            )?;
            actor.evidence.push(binding(&path)?);
        }
    }
    let historical_terminal =
        historical_terminal::capture(epoch, &p, &actors, &before, &s.output_directory)?;
    let producer = &before[string(&p, "producer_unit")?];
    let mut guard_binding = Value::Null;
    if live(producer) {
        let raw = source_bytes(
            &Path::new(string(&p, "guard_directory")?).join("heartbeat.json"),
            0,
        )?;
        let path = s.output_directory.join("guard-snapshot.json");
        write_raw(&path, &raw)?;
        guard_binding = private157::binding(&binding(&path)?);
    }
    let root = Path::new(string(&p, "run_root")?);
    let mut artifacts = Vec::new();
    for path in [
        PathBuf::from(string(&p["prefix_archive"], "path")?),
        root.join(format!("output/epoch-{epoch}-suffix.jet")),
        root.join(format!("output/epoch-{epoch}-checkpoint-restart-v4.jet")),
    ] {
        if let Some(value) = archive(&path)? {
            artifacts.push(value);
        }
    }
    let mut inactivity = Value::Null;
    let (stamp, ms) = current_stamp()?;
    let mut terminal_binding = Value::Null;
    if idle(producer) {
        let owner_name = string(&p, "producer_unit")?;
        let raw = journal(owner_name)?;
        let iid = string(&l, "invocation_id")?;
        let result = root.join("receipts/continuation.json");
        let success = result.is_file()
            && manager_history(&raw, owner_name, iid, true).is_ok()
            && (producer["LoadState"] == "not-found"
                || (producer["Result"] == "success" && producer["ExecMainStatus"] == "0"));
        manager_history(&raw, owner_name, iid, success)?;
        manager_terminal(&raw, owner_name, iid)?;
        let journal_path = s.output_directory.join("terminal-manager.jsonl");
        write_raw(&journal_path, &raw)?;
        let result_binding = if success {
            let path = s.output_directory.join("continuation-result.json");
            let original = source_bytes(&result, 1000)?;
            write_raw(&path, &original)?;
            private157::binding(&binding(&path)?)
        } else {
            Value::Null
        };
        let terminal_path = s.output_directory.join("terminal.json");
        write_sealed(
            &terminal_path,
            &json!({"schema":"jetstreamer-capped204205-terminal-v1","epoch":epoch,"unit":owner_name,
            "invocation_id":iid,"current_unit":producer,"manager_journal_complete":true,"manager_journal":private157::binding(&binding(&journal_path)?),
            "outcome":if success{"natural_success"}else{"failed_or_stopped"},"continuation_result":result_binding,
            "replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false}),
        )?;
        terminal_binding = private157::binding(&binding(&terminal_path)?);
    }
    let terminal_guard = producer_terminal_guard::capture(
        &p,
        &l,
        &before,
        &terminal_binding,
        &actors,
        &s.authenticated_other_host_handoffs,
        &s.output_directory,
    )?;
    let all_idle = names.iter().filter(|n| epoch_scope(epoch, n)).all(|n| {
        if p["epoch"] == 205
            && n == string(&p, "guard_unit").unwrap_or("")
            && before[n]["ActiveState"] == "failed"
        {
            !terminal_guard.is_null()
        } else {
            idle(&before[n]) || historical_terminal.get(n.as_str()).is_some()
        }
    });
    if all_idle && s.authenticated_other_host_handoffs.is_empty() {
        let iid = string(&l, "invocation_id")?;
        let mut downstream_terminals = serde_json::Map::new();
        for actor in &actors {
            let raw = journal(&actor.unit)?;
            manager_terminal(&raw, &actor.unit, &actor.invocation_id)?;
            let manager_path = s
                .output_directory
                .join(format!("downstream-{}-terminal.jsonl", actor.invocation_id));
            write_raw(&manager_path, &raw)?;
            downstream_terminals.insert(actor.unit.clone(), json!({"invocation_id":actor.invocation_id,
                "current_unit":before[&actor.unit],"manager_journal":private157::binding(&binding(&manager_path)?)}));
        }
        let mut groups = serde_json::Map::new();
        for name in names.iter().filter(|n| epoch_scope(epoch, n)) {
            inactive_status::no_pending_owner_trigger(
                name,
                before[name]["LoadState"] == "not-found",
            )?;
            groups.insert(name.clone(), group(name)?);
        }
        let jobs = command_output(
            "/usr/bin/systemctl",
            &[
                "list-jobs",
                "--no-legend",
                "--no-pager",
                "--plain",
                "--full",
            ],
        )?;
        let pending = inactive_status::queued_job_units(&jobs)?
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let references =
            jetstreamer_horizon_observe::process_references::scan(Path::new("/proc"), root)?;
        ensure!(
            references.references.is_empty(),
            "capped root still has a process reference"
        );
        let proof_path = s.output_directory.join("inactive.json");
        write_sealed(
            &proof_path,
            &json!({"schema":"jetstreamer-capped204205-positive-inactivity-v1","epoch":epoch,
            "producer_invocation_id":iid,"sampled_at_utc":stamp,"unit_census":before,"pending_job_units":pending,
            "cgroups":groups,"process_reference_census":references,"terminal_snapshot":terminal_binding,"downstream_terminals":downstream_terminals,
            "replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false}),
        )?;
        inactivity = private157::binding(&binding(&proof_path)?);
    }
    let after = census(&names, 201, 300)?;
    ensure!(
        after == before,
        "capped metadata census changed; preserve artifacts and retry next permitted observation"
    );
    let frame = json!({"schema":"jetstreamer-capped204205-work-frame-v1","epoch":epoch,"sampled_at_utc":stamp,"sampled_unix_millis":ms,
        "observer":private157::binding(&s.observer),"observer_executable_sha256":s.observer_executable.sha256,"producer_plan_sha256":s.producer_plan.sha256,
        "observer_executable":private157::binding(&s.observer_executable),"observer_source_revision":observer_source_revision,
        "launch":private157::binding(&launched),"unit_census_before":before,"unit_census_after":after,
        "previous_fleet":private157::binding(&s.previous_fleet),
        "next_observer_registration":private157::binding(&binding(&registration_path)?),
        "accepted_observer_is_context_not_new_producer_measurement":true,
        "historical_terminal_owners":historical_terminal,"producer_terminal_guard":terminal_guard,"guard_snapshot":guard_binding,"downstream_actors":actors,"generated_archives":artifacts,"inactivity_snapshot":inactivity,
        "terminal_snapshot":terminal_binding,
        "authenticated_other_host_handoffs":s.authenticated_other_host_handoffs,
        "resource_samples_taken":0,"archive_body_reads":0,"replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false});
    write_sealed(&s.output_directory.join("frame.json"), &frame)?;
    Ok(())
}
