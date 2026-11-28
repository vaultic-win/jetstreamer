//! Deliberately narrow inactive-status cleanup profile: dropped 183, 184, 186
//! on dev-samjohnson. Never handles archives, sidecars, prefixes, or live work.
//! Extending the profile requires source review and new qualification evidence.
use super::*;
use serde_json::json;
use std::{collections::BTreeMap, os::unix::ffi::OsStrExt, process::Command};

const INCIDENT_SHA: &str = "960943ad5242e96ff56635d773703f1c00a34e0704b8c2bca2487d68edd378ec";
const CONTROLLER_ID: &str = "4734b0f6e8214f7ba794fc228654bfe8";
const PRODUCER_ID: &str = "180f132f59cf4477a36a48f905985262";
const INTENT_SCHEMA: &str = "jetstreamer-r2-inactive-status-intent-v1";

fn profile_epoch(epoch: u64) -> bool {
    matches!(epoch, 183 | 184 | 186)
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Bound {
    path: PathBuf,
    sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PassiveWatcher {
    unit: String,
    invocation_id: String,
    exec_start: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    host: String,
    epoch: u64,
    bucket: String,
    exclusive_local_epoch_ownership: bool,
    authenticated_other_host_handoffs: Vec<Value>,
    status_receipt_directory: PathBuf,
    publication: Bound,
    incident: Bound,
    fleet: Bound,
    repair_backlog: Bound,
    controller: String,
    producer: String,
    // Explicitly authenticated idle receipt watchers are not a delivery claim.
    // Their exact invocation/command must match, and the process scan still
    // rejects any actual epoch archive reference, including one held by them.
    passive_watchers: Vec<PassiveWatcher>,
    public_archive_directory: PathBuf,
    intent: PathBuf,
    completion: PathBuf,
}

fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn immutable(bound: &Bound) -> Result<Value> {
    ensure!(
        bound.path.is_absolute() && fs::canonicalize(&bound.path)? == bound.path,
        "evidence must have a canonical absolute path"
    );
    let m = fs::symlink_metadata(&bound.path)?;
    ensure!(
        m.is_file() && m.uid() == 0 && m.nlink() == 1 && m.mode() & 0o022 == 0,
        "evidence must be root-owned, singly linked and non-writable"
    );
    let bytes = read_stable_bounded(&bound.path, 16 * 1024 * 1024, "inactive evidence")?;
    ensure!(
        hex_lower(&Sha256::digest(&bytes)) == bound.sha256,
        "inactive evidence digest mismatch"
    );
    Ok(serde_json::from_slice(&bytes)?)
}

fn private_destination(path: &Path) -> Result<()> {
    ensure!(path.is_absolute(), "receipt path must be absolute");
    let parent = path.parent().context("receipt parent missing")?;
    let m = fs::symlink_metadata(parent)?;
    ensure!(
        fs::canonicalize(parent)? == parent && m.is_dir() && m.uid() == 0 && m.mode() & 0o077 == 0,
        "receipt parent must be canonical root-private directory"
    );
    Ok(())
}

fn persist(path: &Path, value: &Value) -> Result<()> {
    private_destination(path)?;
    let parent = path.parent().context("missing parent")?;
    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
    tmp.as_file()
        .set_permissions(std::os::unix::fs::PermissionsExt::from_mode(0o400))?;
    serde_json::to_writer_pretty(tmp.as_file_mut(), value)?;
    tmp.write_all(b"\n")?;
    tmp.as_file().sync_all()?;
    tmp.persist_noclobber(path)
        .map_err(|e| anyhow!("no-clobber receipt: {}", e.error))?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn owner_matches(publication: &StatusPublicationReceipt, epoch: u64) -> Result<()> {
    ensure!(
        profile_epoch(epoch)
            && publication.epoch == epoch
            && publication.controller_invocation_id == CONTROLLER_ID
            && publication.producer_invocation_id == PRODUCER_ID
            && publication.authenticated_readback
            && publication.key == format!("epoch-{epoch}.epoch-status.json"),
        "unsupported epoch or ambiguous previous owner"
    );
    Ok(())
}

fn object_matches(
    object: &MutableRemoteObject,
    publication: &StatusPublicationReceipt,
) -> Result<()> {
    ensure!(
        object.etag == publication.object_etag
            && object.bytes == epoch_status_bytes(&publication.status)?,
        "status payload/ETag changed; reconcile instead of deleting"
    );
    Ok(())
}

fn validate_absence_recovery(
    current_present: bool,
    intent_matches: bool,
    completed: bool,
) -> Result<()> {
    ensure!(
        current_present || intent_matches,
        "unexplained status absence is not cleanup success"
    );
    ensure!(
        !completed || (!current_present && intent_matches),
        "status reappeared or completion lacks its matching durable intent"
    );
    Ok(())
}

pub(super) async fn no_remote_delivery(s3: &Client, r2: &R2Config, epoch: u64) -> Result<()> {
    ensure!(
        inventory_epoch(s3, r2, epoch).await?.state == InventoryState::Missing,
        "remote pair/staged archive exists; reconcile delivery rather than deleting status"
    );
    let key = format!("epoch-{epoch}.jet");
    let uploads = s3
        .list_multipart_uploads()
        .bucket(&r2.bucket)
        .prefix(&key)
        .max_uploads(1000)
        .send()
        .await?;
    ensure!(
        uploads.is_truncated() != Some(true)
            && !uploads
                .uploads()
                .iter()
                .any(|u| u.key() == Some(key.as_str())),
        "remote multipart transfer/ambiguous upload census exists"
    );
    Ok(())
}

async fn conditional_status_delete(
    s3: &Client,
    r2: &R2Config,
    publication: &StatusPublicationReceipt,
) -> Result<()> {
    owner_matches(publication, publication.epoch)?;
    // The shared boundary derives the sole authorized key; callers cannot pass
    // an archive, sidecar, prefix, or arbitrary object name.
    conditional_delete_epoch_status(s3, &r2.bucket, publication.epoch, &publication.object_etag)
        .await
}

fn terminal(value: &Value) -> bool {
    matches!(value["ActiveState"].as_str(), Some("inactive" | "failed"))
        && matches!(value["SubState"].as_str(), Some("dead" | "failed"))
        && value["MainPID"] == "0"
}

fn journal_proves_terminal(records: &[Value], name: &str, invocation: &str) -> Result<()> {
    let records: Vec<_> = records
        .iter()
        .filter(|r| {
            r["UNIT"] == name
                && r["_PID"] == "1"
                && r["_UID"] == "0"
                && r["INVOCATION_ID"].as_str().is_some_and(|s| !s.is_empty())
        })
        .collect();
    ensure!(
        records
            .last()
            .is_some_and(|r| r["INVOCATION_ID"] == invocation),
        "latest manager lifecycle is not the old owner"
    );
    let last_start = records.iter().rposition(|r| {
        r["MESSAGE"]
            .as_str()
            .is_some_and(|s| s.starts_with("Starting "))
    });
    let stopped = records.iter().rposition(|r| {
        r["INVOCATION_ID"] == invocation
            && r["JOB_RESULT"] == "done"
            && r["MESSAGE"]
                .as_str()
                .is_some_and(|s| s.starts_with("Stopped "))
    });
    ensure!(
        stopped.is_some()
            && last_start.is_none_or(|start| stopped.is_some_and(|stop| stop > start)),
        "no exact terminal stop after latest manager start"
    );
    Ok(())
}

pub(super) fn cleared_controller_proof(name: &str, invocation: &str) -> Result<Vec<Value>> {
    let output = Command::new("journalctl")
        .args(["-u", name, "--no-pager", "-n", "128", "-o", "json"])
        .output()?;
    ensure!(
        output.status.success() && output.stdout.len() <= 16 * 1024 * 1024,
        "terminal journal probe failed"
    );
    let records = serde_json::Deserializer::from_slice(&output.stdout)
        .into_iter::<Value>()
        .collect::<std::result::Result<Vec<_>, _>>()?;
    journal_proves_terminal(&records, name, invocation)?;
    Ok(records
        .into_iter()
        .filter(|r| r["UNIT"] == name && r["INVOCATION_ID"] == invocation)
        .collect())
}

fn valid_unit_name(name: &str) -> bool {
    if !name.ends_with(".service") || name.starts_with('-') || name.len() > 255 {
        return false;
    }
    let bytes = name.as_bytes();
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'\\' {
            if at + 3 >= bytes.len()
                || bytes[at + 1] != b'x'
                || !bytes[at + 2].is_ascii_hexdigit()
                || !bytes[at + 3].is_ascii_hexdigit()
            {
                return false;
            }
            at += 4;
        } else {
            if !bytes[at].is_ascii_alphanumeric() && !b"-_.@:".contains(&bytes[at]) {
                return false;
            }
            at += 1;
        }
    }
    true
}

fn unit(name: &str) -> Result<Value> {
    ensure!(valid_unit_name(name), "invalid unit name");
    let out = Command::new("systemctl").args(["show", name, "--no-pager",
        "--property=Id,LoadState,ActiveState,SubState,InvocationID,NRestarts,MainPID,ExecStart,ExecStartPre,ExecStartPost,TriggeredBy,Result"]).output()?;
    let v = parse_unit_properties(&out.stdout)
        .with_context(|| format!("invalid properties for {name}"))?;
    ensure!(
        v["Id"] == name
            && (out.status.success() || (v["LoadState"] == "not-found" && terminal(&v))),
        "failed unit probe"
    );
    Ok(v)
}

fn parse_unit_properties(bytes: &[u8]) -> Result<Value> {
    let mut values = serde_json::Map::<String, Value>::new();
    for line in std::str::from_utf8(bytes)?.lines() {
        let (key, value) = line.split_once('=').context("invalid systemctl property")?;
        if let Some(old) = values.get_mut(key) {
            ensure!(
                matches!(key, "ExecStart" | "ExecStartPre" | "ExecStartPost"),
                "ambiguous duplicate non-command property {key}"
            );
            *old = json!(format!(
                "{}\n{value}",
                old.as_str().context("command must be text")?
            ));
        } else {
            values.insert(key.into(), json!(value));
        }
    }
    Ok(Value::Object(values))
}

// Match whole numeric epoch tokens/ranges in unit namespaces, not dates or
// arbitrary decimal substrings. Example: epochs182-200, e183-184, epoch 183.
fn names_epoch(text: &str, epoch: u64) -> bool {
    for (index, _) in text.match_indices(|c: char| c.is_ascii_digit()) {
        if index > 0 && text.as_bytes()[index - 1].is_ascii_digit() {
            continue;
        }
        let prefix = &text[..index];
        if !(prefix.ends_with("epoch")
            || prefix.ends_with("epochs")
            || prefix.ends_with("-e")
            || prefix.ends_with("publish-")
            || prefix.ends_with("upload-"))
        {
            continue;
        }
        let tail = &text[index..];
        let n = tail.bytes().take_while(u8::is_ascii_digit).count();
        let Ok(first) = tail[..n].parse::<u64>() else {
            continue;
        };
        let last = tail[n..]
            .strip_prefix('-')
            .and_then(|t| {
                let n = t.bytes().take_while(u8::is_ascii_digit).count();
                t[..n].parse::<u64>().ok()
            })
            .unwrap_or(first);
        if first <= epoch && epoch <= last {
            return true;
        }
    }
    false
}

fn start_commands(value: &Value) -> Result<String> {
    let mut commands = Vec::new();
    for field in ["ExecStartPre", "ExecStart", "ExecStartPost"] {
        if let Some(command) = value[field].as_str() {
            commands.push(command);
        }
    }
    if commands.iter().all(|command| command.trim().is_empty()) {
        // Valid stop-only oneshots such as blk-availability have no start
        // command and remain active/exited with no PID. Do not mistake that
        // explicit inert shape for an unreadable live command.
        ensure!(
            terminal(value)
                || (value["MainPID"] == "0"
                    && value["ActiveState"] == "active"
                    && value["SubState"] == "exited"),
            "unit command missing for non-inert state"
        );
    }
    Ok(commands.join(" "))
}

fn validate_fleet(
    fleet: &Value,
    epoch: u64,
    publication: &StatusPublicationReceipt,
    time: u64,
) -> Result<()> {
    ensure!(
        fleet["schema"] == "jetstreamer-horizon-campaign-fleet-v1"
            && fleet["first_epoch"] == 101
            && fleet["last_epoch"] == 200
            && fleet["inventory"]["anomalies"] == 0,
        "invalid fleet scope or anomalous inventory"
    );
    let recorded = fleet["recorded_unix_seconds"]
        .as_u64()
        .context("fleet time missing")?;
    ensure!(
        recorded <= time && time - recorded <= 1800,
        "stale fleet census"
    );
    let sampled = fleet::utc_seconds(
        fleet["sampled_at_utc"]
            .as_str()
            .context("fleet sample missing")?,
    )?;
    ensure!(
        sampled <= recorded && time - sampled <= 1800,
        "stale fleet observation"
    );
    let entries = fleet["epochs"].as_array().context("fleet epochs missing")?;
    let entries: Vec<_> = entries.iter().filter(|e| e["epoch"] == epoch).collect();
    ensure!(
        entries.len() == 1
            && (entries[0]["state"] == "failed-needs-repair"
                || (epoch == 186 && entries[0]["state"] == "blocked-qualification"))
            && entries[0]["status"]["classification"] == "stale-or-orphaned"
            && entries[0]["status"]["etag"] == publication.object_etag
            && entries[0]["status"]["payload"] == serde_json::to_value(&publication.status)?,
        "fleet does not prove this exact stale failed status"
    );
    for a in fleet["active"]
        .as_array()
        .context("fleet active census missing")?
    {
        ensure!(
            a["epoch"] != epoch,
            "fleet contains an active replacement or downstream stage"
        );
    }
    Ok(())
}

fn live_census(plan: &Plan, fleet: &Value) -> Result<Value> {
    for w in &plan.passive_watchers {
        ensure!(
            matches!(
                w.unit.as_str(),
                "horizon-r2-progressive-epochs101-200-v21-rust-authenticated.service"
                    | "jetstreamer-horizon-audit-epochs182-200-v5.service"
                    | "jetstreamer-horizon-boundary-audit-181-200-v7-fsync.service"
            ),
            "only independently reviewed idle receipt watchers may be excepted"
        );
    }
    let controller = unit(&plan.controller)?;
    let producer = unit(&plan.producer)?;
    let mut controller_terminal_journal = Vec::new();
    for (v, id) in [(&controller, CONTROLLER_ID), (&producer, PRODUCER_ID)] {
        ensure!(terminal(v), "previous owner not terminal");
        let controller_cleared = std::ptr::eq(v, &controller)
            && v["LoadState"] == "loaded"
            && v["InvocationID"] == ""
            && v["Result"] == "success"
            && v["NRestarts"] == "0";
        if controller_cleared {
            controller_terminal_journal = cleared_controller_proof(&plan.controller, id)?;
        }
        ensure!(
            v["LoadState"] == "not-found" || v["InvocationID"] == id || controller_cleared,
            "owner unit now has a different invocation"
        );
        ensure!(
            v["TriggeredBy"] == "",
            "old owner still has an automatic trigger"
        );
    }
    let listing = Command::new("systemctl")
        .args([
            "list-units",
            "--all",
            "--type=service",
            "--output=json",
            "--no-pager",
        ])
        .output()?;
    ensure!(listing.status.success(), "full service census failed");
    let discovered: Vec<Value> = serde_json::from_slice(&listing.stdout)?;
    let mut claims = BTreeMap::new();
    for d in discovered {
        let name = d["unit"].as_str().context("unit discovery omits name")?;
        let current = unit(name)?;
        let command = start_commands(&current)?;
        let command_bytes = command
            .split_ascii_whitespace()
            .collect::<Vec<_>>()
            .join("\0");
        if !names_epoch(name, plan.epoch)
            && !replay_command_claims(command_bytes.as_bytes(), plan.epoch)
            && !command.contains(&format!("epoch-{}.jet", plan.epoch))
        {
            continue;
        }
        if !terminal(&current) {
            let watcher = plan
                .passive_watchers
                .iter()
                .find(|w| w.unit == name)
                .context("replacement/activating/downstream epoch claim present")?;
            ensure!(
                current["InvocationID"] == watcher.invocation_id
                    && current["NRestarts"] == "0"
                    && current["ExecStart"] == watcher.exec_start
                    && current["ActiveState"] == "active"
                    && fleet["unit_census"][name]["InvocationID"] == watcher.invocation_id
                    && fleet["unit_census"][name]["ExecStart"] == watcher.exec_start,
                "idle watcher identity changed"
            );
        } else {
            ensure!(
                current["TriggeredBy"] == "",
                "staged epoch claim has an automatic trigger"
            );
        }
        claims.insert(name.to_string(), current);
    }
    let jobs = Command::new("systemctl")
        .args([
            "list-jobs",
            "--no-legend",
            "--no-pager",
            "--plain",
            "--full",
        ])
        .output()?;
    ensure!(jobs.status.success(), "queued-job census failed");
    let queued = inactive_status::queued_job_units(&jobs.stdout)?;
    for j in &queued {
        let name = *j;
        if !name.ends_with(".service") {
            ensure!(
                !names_epoch(name, plan.epoch),
                "queued non-service epoch trigger present"
            );
            continue;
        }
        let command = unit(name)?;
        let command = start_commands(&command)?;
        let command_bytes = command
            .split_ascii_whitespace()
            .collect::<Vec<_>>()
            .join("\0");
        ensure!(
            !names_epoch(name, plan.epoch)
                && !replay_command_claims(command_bytes.as_bytes(), plan.epoch)
                && !command.contains(&format!("epoch-{}.jet", plan.epoch)),
            "queued epoch replacement/handoff"
        );
    }
    let archive = plan
        .public_archive_directory
        .join(format!("epoch-{}.jet", plan.epoch));
    let sidecar = plan
        .public_archive_directory
        .join(format!("epoch-{}.jet.sha256", plan.epoch));
    for path in [&archive, &sidecar] {
        match fs::symlink_metadata(path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            _ => bail!(
                "canonical local artifact exists or cannot be observed; delivery ownership uncertain"
            ),
        }
    }
    scan_processes(Path::new("/proc"), plan.epoch)?;
    Ok(
        json!({"controller":controller,"controller_terminal_journal":controller_terminal_journal,"producer":producer,"epoch_units":claims,
        "queued_jobs":queued,"process_reference_scan":"command/maps/cwd/root/exe/fd complete",
        "canonical_local_pair_absent":true}),
    )
}

fn relevant_bytes(bytes: &[u8], epoch: u64) -> bool {
    let text = String::from_utf8_lossy(bytes);
    let archive = format!("epoch-{epoch}.jet");
    // Archive paths match the exact basename (also .sha256), not epoch-1830.
    text.split(|c: char| c == '\0' || c.is_ascii_whitespace() || c == '/')
        .any(|v| {
            v == archive || v == format!("{archive}.sha256") || v == format!("{archive} (deleted)")
        })
}

fn proc_read(path: &Path) -> Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(b) => Ok(Some(b)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("incomplete process scan: {}", path.display())),
    }
}

fn replay_command_claims(bytes: &[u8], epoch: u64) -> bool {
    let text = String::from_utf8_lossy(bytes);
    let args: Vec<_> = text.split('\0').collect();
    let operational = args.iter().any(|a| {
        a.ends_with("jetstreamer-node")
            || a.ends_with("jetstreamer-r2")
            || a.contains("historical-worker")
            || a.ends_with("adaptive-root-cohort-sweep.py")
    });
    if !operational {
        return false;
    }
    let mut first = None;
    let mut last = None;
    for (i, a) in args.iter().enumerate() {
        let value = |name: &str| {
            a.strip_prefix(&format!("{name}="))
                .or_else(|| (*a == name).then(|| args.get(i + 1).copied()).flatten())
        };
        if let Some(v) = value("--first-epoch") {
            first = v.parse::<u64>().ok();
        }
        if let Some(v) = value("--last-epoch") {
            last = v.parse::<u64>().ok();
        }
        for flag in ["--epoch", "--epochs"] {
            if value(flag).is_some_and(|v| {
                v.parse::<u64>().ok() == Some(epoch)
                    || parse_observer_claim_range(v).is_ok_and(|r| r.contains(&epoch))
            }) {
                return true;
            }
        }
        if a.parse::<u64>().ok() == Some(epoch)
            || parse_observer_claim_range(a).is_ok_and(|r| r.contains(&epoch))
        {
            return true;
        }
    }
    first
        .zip(last)
        .is_some_and(|(first, last)| first <= epoch && epoch <= last)
}

fn scan_processes(root: &Path, epoch: u64) -> Result<()> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        if pid == std::process::id() {
            continue;
        }
        let path = entry.path();
        // Kernel workers have empty cmdline/maps and no exe; disappearance is
        // allowed, permission failures are not. Do not suppress arbitrary PIDs.
        for file in ["cmdline", "maps"] {
            if let Some(bytes) = proc_read(&path.join(file))? {
                // Unit/profile names in long-lived watcher argv are not active
                // archive references. Numeric positional replay claims are checked below.
                let text = String::from_utf8_lossy(&bytes);
                let archive = format!("epoch-{epoch}.jet");
                ensure!(
                    !text.contains(&archive),
                    "pid {pid} retains epoch archive in {file}"
                );
                ensure!(
                    file != "cmdline" || !replay_command_claims(&bytes, epoch),
                    "pid {pid} has an epoch replay/controller claim"
                );
            }
        }
        for link in ["cwd", "root", "exe"] {
            match fs::read_link(path.join(link)) {
                Ok(target) => ensure!(
                    !relevant_bytes(target.as_os_str().as_bytes(), epoch),
                    "pid {pid} retains epoch {link}"
                ),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                Err(e) => return Err(e).context("incomplete process link scan"),
            }
        }
        match fs::read_dir(path.join("fd")) {
            Ok(fds) => {
                for fd in fds {
                    match fs::read_link(fd?.path()) {
                        Ok(target) => ensure!(
                            !relevant_bytes(target.as_os_str().as_bytes(), epoch),
                            "pid {pid} retains epoch descriptor"
                        ),
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                        Err(e) => return Err(e).context("incomplete descriptor scan"),
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(e).context("incomplete fd directory scan"),
        }
    }
    Ok(())
}

pub(super) async fn run() -> Result<()> {
    let args: Vec<_> = env::args().collect();
    ensure!(
        (args.len() == 7 || (args.len() == 8 && args[7] == "--check-only"))
            && args[3] == "--plan-sha256"
            && args[5] == "--self-sha256",
        "usage: jetstreamer-r2 status-delete-inactive PLAN --plan-sha256 HEX --self-sha256 HEX [--check-only]"
    );
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "inactive cleanup requires root"
    );
    let mut executable = File::open("/proc/self/exe")?;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let n = executable.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        digest.update(&buffer[..n]);
    }
    ensure!(
        hex_lower(&digest.finalize()) == args[6],
        "inactive cleanup executable digest mismatch"
    );
    let plan_bound = Bound {
        path: args[2].clone().into(),
        sha256: args[4].clone(),
    };
    let plan: Plan = serde_json::from_value(immutable(&plan_bound)?)?;
    ensure!(
        plan.schema == "jetstreamer-r2-inactive-status-plan-v1"
            && plan.host == "dev-samjohnson"
            && plan.exclusive_local_epoch_ownership
            && plan.authenticated_other_host_handoffs.is_empty()
            && profile_epoch(plan.epoch),
        "unsupported inactive-cleanup profile"
    );
    ensure!(
        plan.public_archive_directory == Path::new("/home/sol/horizon")
            && plan.status_receipt_directory
                == Path::new("/home/sol/.jetstreamer-private/r2-status-receipts"),
        "profile must use actual campaign archive and status-receipt paths"
    );
    let host = fs::read_to_string("/proc/sys/kernel/hostname")?;
    ensure!(host.trim() == plan.host, "wrong cleanup host");
    ensure!(
        plan.controller == "jetstreamer-epochs183-186-target4-controller-v3-r2.service"
            && plan.producer
                == "jetstreamer-root-sweep-e183-186-t4-20261016-v3-r2-e183-186-lane-a-1.service",
        "unsupported terminal owner units"
    );
    ensure!(
        plan.incident.sha256 == INCIDENT_SHA,
        "terminal incident not qualified"
    );
    let incident = immutable(&plan.incident)?;
    ensure!(
        incident["schema"] == "jetstreamer-horizon-boundary-reader-incident-v1"
            && incident["host"] == plan.host
            && incident["failures"][0]["producer_invocation_id"] == PRODUCER_ID
            && incident["failures"][0]["last_replayed_slot"] == 79487995,
        "terminal incident does not bind failed owner"
    );
    let backlog = immutable(&plan.repair_backlog)?;
    ensure!(
        backlog["host"] == plan.host
            && backlog["incidents"]
                .as_array()
                .context("repair backlog absent")?
                .iter()
                .any(|i| i["open"] == true
                    && i["failed_producer_invocation_id"] == PRODUCER_ID
                    && i["affected_epochs"]
                        .as_array()
                        .is_some_and(|e| e.contains(&json!(plan.epoch)))),
        "failed epoch must remain in open repair backlog"
    );
    for p in [&plan.intent, &plan.completion] {
        private_destination(p)?;
    }
    ensure!(
        plan.intent != plan.completion
            && plan.intent != plan.publication.path
            && plan.completion != plan.publication.path,
        "receipt paths must be distinct"
    );
    let r2 = r2_config_from_env()?;
    ensure!(r2.bucket == plan.bucket, "wrong bucket");
    let s3 = s3_client(&r2);
    let (publication, _) = read_bound_status_publication_receipt(
        &plan.status_receipt_directory,
        &plan.publication.path,
        &plan.publication.sha256,
        &r2.bucket,
        plan.epoch,
    )?;
    owner_matches(&publication, plan.epoch)?;
    let (latest, latest_path, latest_digest) =
        latest_status_publication_receipt(&plan.status_receipt_directory, &r2.bucket, plan.epoch)?;
    ensure!(
        latest == publication
            && latest_path == plan.publication.path
            && latest_digest == plan.publication.sha256,
        "a newer publication exists"
    );
    let observer = read_stable_bounded(
        &publication.observer_receipt,
        MAX_OBSERVER_RECEIPT_BYTES,
        "owner observer",
    )?;
    validate_observer_binding(
        &observer,
        &publication.observer_receipt_sha256,
        plan.epoch,
        CONTROLLER_ID,
        PRODUCER_ID,
    )?;
    let fleet = immutable(&plan.fleet)?;
    validate_fleet(&fleet, plan.epoch, &publication, now()?)?;
    let before = live_census(&plan, &fleet)?;
    let current = get_mutable_object(&s3, &r2.bucket, &publication.key).await?;
    let intent_binding = json!({"schema":INTENT_SCHEMA,"plan":plan_bound,"self_sha256":args[6],
        "epoch":plan.epoch,"bucket":r2.bucket,"key":publication.key,"publication":plan.publication,
        "deleted_status":publication.status,"deleted_object_etag":publication.object_etag,
        "repair_incident_still_open":true,"archive_mutations_authorized":false});
    let prior_intent = match fs::symlink_metadata(&plan.intent) {
        Ok(_) => {
            let v: Value = serde_json::from_slice(&read_stable_bounded(
                &plan.intent,
                16 * 1024 * 1024,
                "cleanup intent",
            )?)?;
            ensure!(
                v["binding"] == intent_binding,
                "existing intent binds different evidence"
            );
            Some(v)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e).context("intent observation failed"),
    };
    let existing_completion = match fs::symlink_metadata(&plan.completion) {
        Ok(_) => {
            let v: Value = serde_json::from_slice(&read_stable_bounded(
                &plan.completion,
                16 * 1024 * 1024,
                "cleanup completion",
            )?)?;
            ensure!(
                v["binding"] == intent_binding && v["authenticated_status_absent_after"] == true,
                "existing completion binds different evidence"
            );
            true
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => return Err(e).context("completion preflight failed"),
    };
    validate_absence_recovery(
        current.is_some(),
        prior_intent.is_some(),
        existing_completion,
    )?;
    if let Some(current) = &current {
        object_matches(current, &publication)?;
    }
    no_remote_delivery(&s3, &r2, plan.epoch).await?;
    if args.len() == 8 {
        println!(
            "{}",
            json!({"check_only":true,"epoch":plan.epoch,"key":publication.key,
            "remote_mutations":false,"census":before})
        );
        return Ok(());
    }
    // Recheck all claims after network read and just before durable intent/CAS.
    live_census(&plan, &fleet)?;
    validate_fleet(&fleet, plan.epoch, &publication, now()?)?;
    let (latest, path, digest) =
        latest_status_publication_receipt(&plan.status_receipt_directory, &r2.bucket, plan.epoch)?;
    ensure!(
        latest == publication && path == plan.publication.path && digest == plan.publication.sha256,
        "publication owner changed during cleanup preflight"
    );
    if prior_intent.is_none() {
        persist(
            &plan.intent,
            &json!({"binding":intent_binding,"before":before,"recorded_unix_seconds":now()?}),
        )?;
    }
    if current.is_some() {
        conditional_status_delete(&s3, &r2, &publication).await?;
    }
    ensure!(
        get_mutable_object(&s3, &r2.bucket, &publication.key)
            .await?
            .is_none(),
        "status remains/reappeared"
    );
    let after = live_census(&plan, &fleet).context("claim appeared after deletion; preserve intent, reconcile and publish replacement through normal gates")?;
    no_remote_delivery(&s3, &r2, plan.epoch).await?;
    let receipt = json!({"schema":"jetstreamer-r2-inactive-status-completion-v1","binding":intent_binding,
        "intent":plan.intent,"after":after,"authenticated_status_absent_after":true,
        "archive_mutations":false,"incident_closed":false});
    match fs::symlink_metadata(&plan.completion) {
        Ok(_) => {
            let old: Value = serde_json::from_slice(&read_stable_bounded(
                &plan.completion,
                16 * 1024 * 1024,
                "completion",
            )?)?;
            ensure!(
                old["binding"] == intent_binding
                    && old["authenticated_status_absent_after"] == true,
                "completion binds different cleanup"
            );
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => persist(&plan.completion, &receipt)?,
        Err(e) => return Err(e).context("completion observation failed"),
    }
    println!("{}", plan.completion.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn original_queued_186_is_supported_but_live_185_and_other_owners_are_protected() {
        let mut p = publication();
        p.epoch = 186;
        p.status.epoch = 186;
        p.key = "epoch-186.epoch-status.json".into();
        owner_matches(&p, 186).unwrap();
        p.producer_invocation_id = "c".repeat(32);
        assert!(owner_matches(&p, 186).is_err());
        p.producer_invocation_id = PRODUCER_ID.into();
        p.epoch = 185;
        p.status.epoch = 185;
        p.key = "epoch-185.epoch-status.json".into();
        assert!(owner_matches(&p, 185).is_err());
        assert!(!profile_epoch(182));
        assert!(!profile_epoch(187));
        p.epoch = 186;
        p.status.epoch = 186;
        p.key = "epoch-186.epoch-status.json".into();
        let mut current = json!({"schema":"jetstreamer-horizon-campaign-fleet-v1","first_epoch":101,"last_epoch":200,
            "inventory":{"anomalies":0},"recorded_unix_seconds":1000,"sampled_at_utc":"1970-01-01T00:16:40Z",
            "active":[],"epochs":[{"epoch":186,"state":"blocked-qualification","status":{
                "classification":"stale-or-orphaned","etag":p.object_etag,"payload":p.status}}]});
        validate_fleet(&current, 186, &p, 1000).unwrap();
        current["active"] = json!([{"epoch":186,"phase":"replay"}]);
        assert!(validate_fleet(&current, 186, &p, 1000).is_err());
        current["active"] = json!([]);
        current["epochs"][0]["state"] = json!("staged-admissible");
        assert!(validate_fleet(&current, 186, &p, 1000).is_err());
    }

    #[test]
    fn repeated_start_hooks_are_all_checked_but_duplicate_identity_is_rejected() {
        let v=parse_unit_properties(b"Id=unit.service\nExecStartPre=/bin/true\nExecStartPre=/sealed/jetstreamer-node 183 /output\n").unwrap();
        let command = start_commands(&v)
            .unwrap()
            .split_ascii_whitespace()
            .collect::<Vec<_>>()
            .join("\0");
        assert!(replay_command_claims(command.as_bytes(), 183));
        assert!(parse_unit_properties(b"Id=one.service\nId=two.service\n").is_err());
        assert!(parse_unit_properties(b"MainPID=0\nMainPID=123\n").is_err());
    }

    #[test]
    fn complete_census_accepts_real_systemd_hex_escapes_without_options_or_paths() {
        assert!(valid_unit_name(
            r"systemd-fsck@dev-disk-by\x2duuid-4227\x2d4B65.service"
        ));
        for invalid in [
            "--foo.service",
            "../foo.service",
            r"foo\x.service",
            r"foo\xzz.service",
            "foo\n.service",
        ] {
            assert!(!valid_unit_name(invalid), "{invalid:?}");
        }
    }

    #[test]
    fn stop_only_inert_services_are_not_unreadable_live_commands() {
        let mut value = json!({"MainPID":"0","ActiveState":"active","SubState":"exited"});
        assert_eq!(start_commands(&value).unwrap(), "");
        value["MainPID"] = json!("123");
        assert!(start_commands(&value).is_err());
        value["ExecStart"] = json!("");
        assert!(start_commands(&value).is_err());
        value["ExecStartPre"] = json!("/sealed/jetstreamer-node 183 /output");
        let command = start_commands(&value)
            .unwrap()
            .split_ascii_whitespace()
            .collect::<Vec<_>>()
            .join("\0");
        assert!(replay_command_claims(command.as_bytes(), 183));
    }

    #[test]
    fn cleared_controller_id_requires_exact_last_manager_lifecycle_and_stop() {
        let event = |message: &str, id: &str| {
            json!({"UNIT":"controller.service","_PID":"1","_UID":"0",
            "INVOCATION_ID":id,"MESSAGE":message,"JOB_RESULT":"done"})
        };
        let records = vec![
            event("Starting controller.service", CONTROLLER_ID),
            event("Stopped controller.service", CONTROLLER_ID),
        ];
        journal_proves_terminal(&records, "controller.service", CONTROLLER_ID).unwrap();
        assert!(
            journal_proves_terminal(&records[..1], "controller.service", CONTROLLER_ID).is_err()
        );
        let mut changed = records.clone();
        changed.push(event("Starting controller.service", "new-owner"));
        assert!(journal_proves_terminal(&changed, "controller.service", CONTROLLER_ID).is_err());
        let mut spoofed = records;
        spoofed[1]["_PID"] = json!("123");
        assert!(journal_proves_terminal(&spoofed, "controller.service", CONTROLLER_ID).is_err());
    }

    fn publication() -> StatusPublicationReceipt {
        StatusPublicationReceipt {
            pipeline_binding: None,
            schema: STATUS_RECEIPT_SCHEMA.into(),
            bucket: "test-bucket".into(),
            epoch: 183,
            key: "epoch-183.epoch-status.json".into(),
            status: EpochStatus {
                epoch: 183,
                jet_size_bytes: 0,
                elapsed_execution_millis: 1000,
                estimated_remaining_millis: 1000,
                sampled_at_utc: "2026-10-19T05:50:00Z".into(),
                phase: "replay".into(),
            },
            object_etag: "abc123".into(),
            previous_object_etag: None,
            observer_receipt: "/old-observer.json".into(),
            observer_receipt_sha256: "a".repeat(64),
            controller_invocation_id: CONTROLLER_ID.into(),
            producer_invocation_id: PRODUCER_ID.into(),
            authenticated_readback: true,
            verified_unix_seconds: 1000,
        }
    }

    #[test]
    fn changed_payload_etag_and_ambiguous_owner_never_pass() {
        let p = publication();
        owner_matches(&p, 183).unwrap();
        let mut o = MutableRemoteObject {
            bytes: epoch_status_bytes(&p.status).unwrap(),
            etag: p.object_etag.clone(),
        };
        object_matches(&o, &p).unwrap();
        o.etag.push('0');
        assert!(object_matches(&o, &p).is_err());
        o.etag = p.object_etag.clone();
        o.bytes.push(b' ');
        assert!(object_matches(&o, &p).is_err());
        let mut bad = p.clone();
        bad.producer_invocation_id = "b".repeat(32);
        assert!(owner_matches(&bad, 183).is_err());
        bad = p.clone();
        bad.key = "epoch-183.jet".into();
        assert!(owner_matches(&bad, 183).is_err());
        assert!(owner_matches(&p, 185).is_err());
    }

    #[test]
    fn missing_status_only_recovers_from_exact_durable_intent() {
        assert!(validate_absence_recovery(false, false, false).is_err());
        assert!(validate_absence_recovery(false, true, false).is_ok());
        assert!(validate_absence_recovery(false, true, true).is_ok());
        assert!(validate_absence_recovery(true, true, true).is_err());
        assert!(validate_absence_recovery(true, false, false).is_ok());
    }

    #[test]
    fn fleet_rejects_live_replacement_downstream_and_stale_census() {
        let p = publication();
        let f = json!({"schema":"jetstreamer-horizon-campaign-fleet-v1","first_epoch":101,"last_epoch":200,
            "inventory":{"anomalies":0},"recorded_unix_seconds":1000,"sampled_at_utc":"1970-01-01T00:16:40Z","active":[],
            "epochs":[{"epoch":183,"state":"failed-needs-repair","status":{
                "classification":"stale-or-orphaned","etag":p.object_etag,"payload":p.status}}]});
        validate_fleet(&f, 183, &p, 1000).unwrap();
        assert!(validate_fleet(&f, 183, &p, 2801).is_err());
        for phase in ["replay", "upload-readback", "verification", "handoff"] {
            let mut other = f.clone();
            other["active"] = json!([{"epoch":183,"phase":phase}]);
            assert!(validate_fleet(&other, 183, &p, 1000).is_err());
        }
        let mut other = f;
        other["epochs"][0]["status"]["etag"] = json!("different");
        assert!(validate_fleet(&other, 183, &p, 1000).is_err());
    }

    #[test]
    fn controller_and_named_epoch_arguments_cannot_hide_replacement() {
        for command in [
            "jetstreamer-node\0--epoch=183\0",
            "jetstreamer-node\0--epochs\x00183-184\0",
            "python3\0/sealed/adaptive-root-cohort-sweep.py\0--first-epoch=180\0--last-epoch=190\0",
        ] {
            assert!(
                replay_command_claims(command.as_bytes(), 183),
                "{command:?}"
            );
        }
        assert!(!replay_command_claims(b"jetstreamer-node\x00185\0", 183));
        assert!(!replay_command_claims(b"idle-watcher\x00183\0", 183));
    }

    #[tokio::test]
    async fn real_sdk_delete_keeps_if_match_and_fails_closed_on_412() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let start = std::time::Instant::now();
            let mut stream = loop {
                match listener.accept() {
                    Ok((s, _)) => break s,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(start.elapsed() < Duration::from_secs(10));
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(e) => panic!("{e}"),
                }
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut request = Vec::new();
            let mut b = [0u8; 4096];
            while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = stream.read(&mut b).unwrap();
                assert!(n > 0);
                request.extend_from_slice(&b[..n]);
            }
            let body =
                "<Error><Code>PreconditionFailed</Code><Message>ETag changed</Message></Error>";
            write!(stream,"HTTP/1.1 412 Precondition Failed\r\ncontent-type: application/xml\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",body.len(),body).unwrap();
            String::from_utf8(request).unwrap()
        });
        let r2 = R2Config {
            endpoint,
            bucket: "test-bucket".into(),
            access_key: "test".into(),
            secret_key: "test".into(),
        };
        assert!(
            conditional_status_delete(&s3_client(&r2), &r2, &publication())
                .await
                .is_err()
        );
        let request = server.join().unwrap().to_lowercase();
        let line = request.lines().next().unwrap();
        assert!(
            line.starts_with("delete /test-bucket/epoch-183.epoch-status.json"),
            "{line}"
        );
        assert!(request.contains("if-match: \"abc123\"\r\n"));
    }

    #[test]
    #[ignore = "requires root; run in qualification sandbox"]
    fn root_private_receipts_are_durable_and_never_clobbered() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let t = tempfile::tempdir().unwrap();
        fs::set_permissions(
            t.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let p = t.path().join("intent.json");
        let v = json!({"binding":"test"});
        persist(&p, &v).unwrap();
        assert!(persist(&p, &json!({"different":true})).is_err());
        assert_eq!(
            serde_json::from_slice::<Value>(&fs::read(&p).unwrap()).unwrap(),
            v
        );
        assert_eq!(fs::metadata(&p).unwrap().mode() & 0o777, 0o400);
    }

    #[test]
    fn epoch_namespace_range_and_decimal_boundaries() {
        for name in [
            "jetstreamer-epochs183-186-controller.service",
            "jetstreamer-root-sweep-e183-184-x.service",
            "horizon-publish-183-v1.service",
            "horizon-epoch183-foo.service",
        ] {
            assert!(names_epoch(name, 183), "{name}");
        }
        for name in [
            "horizon-epoch1830-foo.service",
            "horizon-epoch185-foo.service",
            "horizon-v20261020.service",
        ] {
            assert!(!names_epoch(name, 183), "{name}");
        }
    }

    #[test]
    fn only_terminal_shapes_allow_owner_retirement() {
        let mut v = json!({"ActiveState":"inactive","SubState":"dead","MainPID":"0"});
        assert!(terminal(&v));
        for (k, val) in [
            ("ActiveState", "activating"),
            ("SubState", "running"),
            ("MainPID", "123"),
        ] {
            let mut other = v.clone();
            other[k] = json!(val);
            assert!(!terminal(&other));
        }
        v["ActiveState"] = json!("failed");
        v["SubState"] = json!("failed");
        assert!(terminal(&v));
    }

    #[test]
    fn process_references_detect_archives_and_avoid_numeric_siblings() {
        assert!(relevant_bytes(b"/private/epoch-183.jet", 183));
        assert!(relevant_bytes(b"/private/epoch-183.jet.sha256", 183));
        assert!(!relevant_bytes(b"/private/epoch-1830.jet", 183));
        // A broad idle watcher's log/directory is not an active epoch archive.
        assert!(!relevant_bytes(
            b"/var/lib/audit-epochs182-200/service.log",
            183
        ));
    }

    #[test]
    fn fake_proc_catches_downstream_descriptor_and_live_replay() {
        let temp = tempfile::tempdir().unwrap();
        let p = temp.path().join("123");
        fs::create_dir_all(p.join("fd")).unwrap();
        fs::write(
            p.join("cmdline"),
            b"jetstreamer-node\x00183\0/private/output\0",
        )
        .unwrap();
        assert!(scan_processes(temp.path(), 183).is_err());
        fs::write(p.join("cmdline"), b"idle-watcher\0").unwrap();
        assert!(scan_processes(temp.path(), 183).is_ok());
        std::os::unix::fs::symlink("/archive/epoch-183.jet", p.join("fd/4")).unwrap();
        assert!(scan_processes(temp.path(), 183).is_err());
    }
}
