//! Exact, contents-only retirement of one failed local1 replacement scratch166–168.
//! Source proposal only. Root separately owns qualification and admission.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::CString,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        },
    },
    path::{Component, Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};
mod process_references;
mod stopped_tree;

const IMAGE: &str =
    "/usr/local/lib/jetstreamer/horizon-local1-scratch-retire-tools-20261110-v1/retire";
const EVENT: &str = "/var/lib/jetstreamer/seven-standard-reserve-stop-20261110-v1/ORIGINAL_SEVEN_RESERVE_STOPS_AND_REPAIR_MODEL.json";
const EVENT_SHA: &str = "b3bff5d44d24dc507313d8dfdb8e5cd5bec50a7732b288327106ee20b7a7b0eb";
const SOURCE_REVIEW: &str =
    "/usr/local/lib/jetstreamer/horizon-local1-scratch-retire-source-20261110-v1/source-review.md";
const SOURCE_REVIEW_SHA: &str = "c5f2353626f954c9556312c1e5f927a0ce99d80610d4de3b86f51b30c3bf9845";
const NODE_SHA: &str = "a09b8e5aa9426beaf42e6b5f2a469a5a147436bab8b7bf79f268758b60aa2e65";
const WORKER_SHA: &str = "cf5fa883df75b23de82af52dc0e90c013f8e83397b445027e510a1137decc819";
const BATCH_EVIDENCE: &str = "/var/lib/jetstreamer/cached-standard-input-qualification-20261110-v1/actual-three-local-launch-v1/ROOT_THREE_GUARDED_LOCAL_PRODUCER_LAUNCH_RESULT.json";
const BATCH_SHA: &str = "9c53581c64b7a9b304520cb48e1640f7aebf7f56a7d86675a5ab97848580d328";
const STOP_REQUEST_SHA: &str = "b8155bc7dc340db60f4819d65af7d615dafffe12803c3e98c1200e8ed22bc79e";
const MACHINE: &str = "59498204047045e4a428419acee7df19";
const BOOT: &str = "763ea84ca81f4dddad364b1ea2ba36dd";
mod profiles;
use profiles::{Profile, profile};
const MAX_JSON: u64 = 32 << 20;
const MAX_LEDGER: u64 = 1 << 30;
const DEFINITION_ROOTS: &[&str] = &[
    "/etc/systemd/system",
    "/run/systemd/system",
    "/run/systemd/transient",
    "/usr/lib/systemd/system",
    "/run/systemd/generator",
    "/run/systemd/generator.early",
    "/run/systemd/generator.late",
    "/home/sol/.config/systemd/user",
    "/etc/crontab",
    "/etc/cron.d",
    "/var/spool/cron/crontabs",
    "/etc/cron.hourly",
    "/etc/cron.daily",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
];

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Bound {
    path: PathBuf,
    sha256: String,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Directory {
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    owner: String,
    epoch: u64,
    run_directory: PathBuf,
    scratch: PathBuf,
    run_identity: Directory,
    scratch_identity: Directory,
    source_review: Bound,
    stop_event: Bound,
    terminal_journal: Bound,
    fleet: Bound,
    dependency_review: Bound,
    closed_units: Vec<String>,
    preserve_partial_archive_and_inputs: bool,
    preserve_scratch_inode: bool,
    local_contents_retirement_authorized: bool,
    resource_promise_ending_authorized: bool,
    replay_launch_authorized: bool,
    archive_deletion_authorized: bool,
    remote_mutations: bool,
    r2_mutations: bool,
}
fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn lower_sha(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn scratch(pr: &Profile) -> PathBuf {
    Path::new(pr.run).join("scratch")
}
fn directory(m: &fs::Metadata) -> Directory {
    Directory {
        device: m.dev(),
        inode: m.ino(),
        uid: m.uid(),
        gid: m.gid(),
        mode: m.mode() & 0o7777,
    }
}
fn identity(m: &fs::Metadata) -> Value {
    json!([
        m.dev(),
        m.ino(),
        m.uid(),
        m.gid(),
        m.mode(),
        m.nlink(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec()
    ])
}
fn exists(p: &Path) -> Result<bool> {
    match fs::symlink_metadata(p) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}
// Traverse every component through a directory descriptor, never a symlink.
fn open_directory(p: &Path) -> Result<File> {
    ensure!(p.is_absolute(), "absolute directory required");
    let mut dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")?;
    for c in p.components() {
        match c {
            Component::RootDir => (),
            Component::Normal(name) => {
                let name = CString::new(name.as_bytes())?;
                let fd = unsafe {
                    libc::openat(
                        dir.as_raw_fd(),
                        name.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                ensure!(
                    fd >= 0,
                    "directory component could not be anchored: {}",
                    p.display()
                );
                dir = unsafe { File::from_raw_fd(fd) };
            }
            _ => anyhow::bail!("noncanonical directory component"),
        }
    }
    ensure!(p.canonicalize()? == p, "directory alias");
    Ok(dir)
}
fn raw(p: &Path, limit: u64, root: bool, immutable: bool) -> Result<Vec<u8>> {
    ensure!(
        p.is_absolute() && p.canonicalize()? == p,
        "evidence path alias"
    );
    let _parent = open_directory(p.parent().context("evidence parent")?)?;
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(p)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file()
            && m.nlink() == 1
            && m.len() <= limit
            && m.mode() & 0o022 == 0
            && (!root || m.uid() == 0)
            && (!immutable || m.mode() & 0o222 == 0),
        "unsafe evidence file: {}",
        p.display()
    );
    let mut bytes = Vec::new();
    Read::by_ref(&mut f)
        .take(limit + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == m.len()
            && identity(&m) == identity(&f.metadata()?)
            && identity(&m) == identity(&fs::symlink_metadata(p)?),
        "evidence changed while read"
    );
    Ok(bytes)
}
fn json_bound(b: &Bound) -> Result<Value> {
    ensure!(lower_sha(&b.sha256), "invalid bound digest");
    let bytes = raw(&b.path, MAX_JSON, true, false)?;
    ensure!(
        sha(&bytes) == b.sha256,
        "bound evidence differs: {}",
        b.path.display()
    );
    Ok(serde_json::from_slice(&bytes)?)
}
fn stable_file(p: &Path, expected_sha: &str, limit: u64) -> Result<Value> {
    let bytes = raw(p, limit, true, true)?;
    ensure!(
        sha(&bytes) == expected_sha,
        "immutable package member changed"
    );
    Ok(json!({"path":p,"sha256":expected_sha,"identity":identity(&fs::symlink_metadata(p)?)}))
}
fn scope(p: &Plan) -> Result<()> {
    let pr = profile(p.epoch)?;
    ensure!(
        p.schema == "jetstreamer-local1-scratch-retirement-plan-v1"
            && p.owner == "/root"
            && p.run_directory == Path::new(pr.run)
            && p.scratch == scratch(pr),
        "foreign failed-local1 scope"
    );
    ensure!(
        p.preserve_partial_archive_and_inputs
            && p.preserve_scratch_inode
            && p.local_contents_retirement_authorized
            && !p.resource_promise_ending_authorized
            && !p.replay_launch_authorized
            && !p.archive_deletion_authorized
            && !p.remote_mutations
            && !p.r2_mutations,
        "forbidden authority"
    );
    ensure!(
        p.run_identity
            == Directory {
                device: 64512,
                inode: pr.run_inode,
                uid: 1001,
                gid: 1003,
                mode: 0o700
            }
            && p.scratch_identity
                == Directory {
                    device: 64512,
                    inode: pr.scratch_inode,
                    uid: 1001,
                    gid: 1003,
                    mode: 0o700
                },
        "saved exact directory identity differs"
    );
    ensure!(
        p.source_review.path == Path::new(SOURCE_REVIEW)
            && p.source_review.sha256 == SOURCE_REVIEW_SHA
            && p.stop_event.path == Path::new(EVENT)
            && p.stop_event.sha256 == EVENT_SHA
            && p.terminal_journal.path == pr.out().join("original-invocation-terminal.json")
            && lower_sha(&p.terminal_journal.sha256),
        "source/event/terminal identity differs"
    );
    let actual: BTreeSet<_> = p.closed_units.iter().cloned().collect();
    let expected = BTreeSet::from([
        pr.unit.to_owned(),
        format!("{}.service", pr.guard),
        format!("{}.timer", pr.guard),
    ]);
    ensure!(
        actual.len() == 3 && p.closed_units.len() == 3 && actual == expected,
        "only exact local1 owner and guards may be closed"
    );
    Ok(())
}
// Only fresh fleet/dependency evidence may advance while an intent is retried.
fn scope_sha(p: &Plan) -> Result<String> {
    let mut v = serde_json::to_value(p)?;
    let o = v.as_object_mut().context("plan object")?;
    o.remove("fleet");
    o.remove("dependency_review");
    Ok(sha(&serde_json::to_vec(&v)?))
}
fn original_evidence(p: &Plan) -> Result<Value> {
    let pr = profile(p.epoch)?;
    let review = raw(&p.source_review.path, MAX_JSON, true, true)?;
    ensure!(
        sha(&review) == SOURCE_REVIEW_SHA,
        "exact source review changed"
    );
    let event = json_bound(&p.stop_event)?;
    event_rows(&event)?;
    let batch_binding = Bound {
        path: BATCH_EVIDENCE.into(),
        sha256: BATCH_SHA.into(),
    };
    let batch = json_bound(&batch_binding)?;
    validate_failed_batch(&batch)?;
    let mut bindings = BTreeMap::new();
    let mut values = BTreeMap::new();
    for (name, digest) in [
        ("ACTUAL_PRODUCER_NATIVE.json", pr.native_sha),
        ("ORIGINAL_PRODUCER_ARGV.json", pr.argv_sha),
        ("ORIGINAL_PRODUCER_START.json", pr.start_sha),
        ("FAILED_SETUP.json", pr.failure_sha),
        ("FAILED_NEW_SCOPE_STOP_REQUEST.json", STOP_REQUEST_SHA),
        ("FAILED_SETUP_TERMINAL_NATIVE.json", pr.terminal_sha),
    ] {
        let binding = Bound {
            path: pr.evidence().join(name),
            sha256: digest.into(),
        };
        values.insert(name, json_bound(&binding)?);
        bindings.insert(name, binding);
    }
    validate_failed_launch(&values, pr)?;
    let bytes = raw(&p.terminal_journal.path, MAX_JSON, true, true)?;
    ensure!(
        sha(&bytes) == p.terminal_journal.sha256,
        "original terminal journal changed"
    );
    validate_terminal_journal_bytes(&bytes, pr)?;
    Ok(
        json!({"historical_original_seven_event":p.stop_event,"source_review":p.source_review,"failed_local1_batch":batch_binding,"failed_local1_launch":bindings,"authentic_original_invocation_terminal_journal":p.terminal_journal,"guard_stop_chain_claimed":false}),
    )
}
fn validate_failed_batch(batch: &Value) -> Result<()> {
    let failed=(166..=168).map(|e|json!({"epoch":e,"error":format!("('genuine first guard did not succeed by original25second deadline', {e})")})).collect::<Vec<_>>();
    ensure!(
        *batch
            == json!({"recorded_unix_seconds":1794337157u64,"protected":[],"failed":failed,"bootstrap_count":0,"useful_transaction_replay_count":0,"full_native_replacement_fleet_status_and_observer_integration_next":true}),
        "exact original failed local1 batch evidence differs"
    );
    Ok(())
}
fn validate_failed_launch(values: &BTreeMap<&str, Value>, pr: &Profile) -> Result<()> {
    let v = &values["ACTUAL_PRODUCER_NATIVE.json"];
    ensure!(
        v["Id"] == pr.unit
            && v["InvocationID"] == pr.iid
            && v["MainPID"].as_str().and_then(|s| s.parse::<u64>().ok()) == Some(pr.pid)
            && v["ActiveState"] == "active"
            && v["SubState"] == "running"
            && v["LoadState"] == "loaded"
            && v["ControlPID"] == "0"
            && v["NRestarts"] == "0"
            && v["Job"] == ""
            && v["Restart"] == "no"
            && v["ControlGroup"] == format!("/system.slice/{}", pr.unit)
            && v["ExecMainStartTimestampMonotonic"].as_str().and_then(|s| s.parse::<u64>().ok()) == Some(pr.start_monotonic_usecs),
        "failed original launch identity differs"
    );
    let start = &values["ORIGINAL_PRODUCER_START.json"];
    ensure!(
        *start
            == json!({"code":0,"stdout":"","stderr":format!("Running as unit: {}; invocation ID: {}\n",pr.unit,pr.iid)}),
        "original launch acknowledgement differs"
    );
    ensure!(
        values["FAILED_SETUP.json"]
            == json!({"error":format!("('genuine first guard did not succeed by original25second deadline', {})",pr.epoch),"originals_preserved":true,"old_or_other_producers_not_signalled":true}),
        "original guard setup failure differs"
    );
    ensure!(
        values["FAILED_NEW_SCOPE_STOP_REQUEST.json"] == json!({"code":0,"stdout":"","stderr":""}),
        "failed local1 explicit stop request differs"
    );
    closed(&values["FAILED_SETUP_TERMINAL_NATIVE.json"], true, pr)?;
    Ok(())
}
// Accept actual manager records, never a handwritten terminal envelope or a
// collected native snapshot with an empty invocation ID. Root exports the
// original PID1 records as immutable native JSON array or JSONL with native field names.
#[derive(Deserialize, Serialize)]
struct JournalRecord {
    #[serde(rename = "_PID")]
    pid: String,
    #[serde(rename = "_UID")]
    uid: String,
    #[serde(rename = "_COMM")]
    comm: String,
    #[serde(rename = "_EXE")]
    exe: String,
    #[serde(rename = "SYSLOG_IDENTIFIER")]
    identifier: String,
    #[serde(rename = "UNIT")]
    unit: String,
    #[serde(rename = "INVOCATION_ID")]
    invocation_id: String,
    #[serde(rename = "_BOOT_ID")]
    boot: String,
    #[serde(rename = "_MACHINE_ID")]
    machine: String,
    #[serde(rename = "__CURSOR")]
    cursor: String,
    #[serde(rename = "__REALTIME_TIMESTAMP")]
    realtime: String,
    #[serde(rename = "__MONOTONIC_TIMESTAMP")]
    monotonic: String,
    #[serde(rename = "MESSAGE_ID")]
    message_id: Option<String>,
    #[serde(rename = "MESSAGE")]
    message: String,
    #[serde(rename = "JOB_TYPE")]
    job_type: Option<String>,
    #[serde(rename = "JOB_RESULT")]
    job_result: Option<String>,
}
fn validate_terminal_journal_bytes(bytes: &[u8], pr: &Profile) -> Result<()> {
    // Deserialize known native fields before Value conversion: repeated fields
    // and array-valued identity substitutions must fail, rather than be lost.
    let rows: Vec<JournalRecord> =
        if bytes.iter().copied().find(|b| !b.is_ascii_whitespace()) == Some(b'[') {
            serde_json::from_slice(bytes)?
        } else {
            let mut rows = Vec::new();
            for row in serde_json::Deserializer::from_slice(bytes).into_iter::<JournalRecord>() {
                ensure!(rows.len() < 256, "terminal journal record budget");
                rows.push(row?);
            }
            rows
        };
    validate_terminal_journal(&serde_json::to_value(rows)?, pr)
}
fn native_decimal(row: &Value, key: &str) -> Result<u64> {
    let s = row[key].as_str().context("native journal decimal string")?;
    ensure!(
        !s.is_empty() && s.len() <= 20 && s.bytes().all(|b| b.is_ascii_digit()),
        "malformed native journal decimal"
    );
    Ok(s.parse()?)
}
fn validate_terminal_journal(v: &Value, pr: &Profile) -> Result<()> {
    let rows = v
        .as_array()
        .context("native terminal journal must be a JSON array")?;
    ensure!(
        !rows.is_empty() && rows.len() <= 256,
        "terminal journal record budget"
    );
    let mut deactivated = None;
    let mut stopped = None;
    let mut cursors = BTreeSet::new();
    for row in rows {
        ensure!(
            row["_PID"] == "1"
                && row["_UID"] == "0"
                && row["_COMM"] == "systemd"
                && row["_EXE"] == "/usr/lib/systemd/systemd"
                && row["SYSLOG_IDENTIFIER"] == "systemd"
                && row["UNIT"] == pr.unit
                && row["INVOCATION_ID"] == pr.iid
                && row["_BOOT_ID"] == BOOT
                && row["_MACHINE_ID"] == MACHINE,
            "foreign PID1 journal identity"
        );
        let cursor = row["__CURSOR"].as_str().context("native journal cursor")?;
        ensure!(
            !cursor.is_empty() && cursor.len() <= 1024 && cursors.insert(cursor),
            "missing or duplicate journal cursor"
        );
        let realtime = native_decimal(row, "__REALTIME_TIMESTAMP")?;
        let mono = native_decimal(row, "__MONOTONIC_TIMESTAMP")?;
        ensure!(
            realtime >= pr.start_unix * 1_000_000
                && realtime < 1_794_337_158_000_000
                && mono >= pr.start_monotonic_usecs
                && mono - pr.start_monotonic_usecs <= (1_794_337_158 - pr.start_unix) * 1_000_000,
            "terminal record outside original failed batch lifetime"
        );
        if row["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448" {
            ensure!(
                row["MESSAGE"] == format!("{}: Deactivated successfully.", pr.unit)
                    && deactivated.replace(mono).is_none(),
                "ambiguous deactivation record"
            );
        }
        if row["MESSAGE_ID"] == "9d1aaa27d60140bd96365438aad20286" {
            ensure!(
                row["JOB_TYPE"] == "stop"
                    && row["JOB_RESULT"] == "done"
                    && row["MESSAGE"]
                        .as_str()
                        .is_some_and(|s| s.starts_with(&format!("Stopped {}", pr.unit)))
                    && stopped.replace(mono).is_none(),
                "ambiguous successful stop record"
            );
        }
    }
    ensure!(
        deactivated.is_some(),
        "same-record original-IID PID1 deactivation required"
    );
    if let Some(stopped) = stopped {
        ensure!(
            deactivated.is_some_and(|a| a <= stopped),
            "terminal native event order differs"
        );
    }
    Ok(())
}
fn retained_walk(
    pr: &Profile,
    p: &Path,
    out: &mut BTreeMap<String, Value>,
    depth: usize,
) -> Result<()> {
    ensure!(
        depth <= 16 && out.len() < 128,
        "retained closure exceeds exact run budget"
    );
    let m = fs::symlink_metadata(p)?;
    ensure!(
        m.uid() == 1001
            && m.gid() == 1003
            && m.mode() & 0o022 == 0
            && (m.is_dir() || m.is_file())
            && (!m.is_file() || m.nlink() == 1),
        "foreign or aliased retained artifact"
    );
    let relative = p
        .strip_prefix(pr.run)?
        .to_str()
        .context("retained UTF8")?
        .to_owned();
    let mut v = json!({"identity":identity(&m)});
    if m.is_file() && m.len() <= 2 << 20 {
        v["sha256"] = json!(sha(&raw(p, 2 << 20, false, false)?));
    }
    out.insert(relative, v);
    if m.is_dir() {
        for e in fs::read_dir(p)? {
            retained_walk(pr, &e?.path(), out, depth + 1)?;
        }
    }
    Ok(())
}
fn empty_retained(run: &Path) -> Result<()> {
    for name in ["archives", "inputs"] {
        ensure!(
            fs::read_dir(run.join(name))?.next().is_none(),
            "new archive/input arrived in failed local1 run"
        );
    }
    Ok(())
}
fn preserved(p: &Plan) -> Result<Value> {
    let pr = profile(p.epoch)?;
    let dir = open_directory(Path::new(pr.run))?;
    ensure!(
        directory(&dir.metadata()?) == p.run_identity,
        "original run changed"
    );
    let names: BTreeSet<_> = fs::read_dir(pr.run)?
        .map(|e| {
            e?.file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("nonUTF8 run member"))
        })
        .collect::<Result<_>>()?;
    ensure!(
        names
            == BTreeSet::from([
                "archives".into(),
                "inputs".into(),
                "scratch".into(),
                "cohort-state.json".into()
            ]),
        "unknown or missing retained run member"
    );
    let mut files = BTreeMap::new();
    for name in ["archives", "inputs", "cohort-state.json"] {
        retained_walk(pr, &Path::new(pr.run).join(name), &mut files, 0)?;
    }
    empty_retained(Path::new(pr.run))?;
    let state: Value = serde_json::from_slice(&raw(
        &Path::new(pr.run).join("cohort-state.json"),
        65536,
        false,
        false,
    )?)?;
    validate_cohort_state(&state, pr)?;
    let node = stable_file(
        &pr.package().as_path().join("jetstreamer-node"),
        NODE_SHA,
        64 << 20,
    )?;
    let worker = stable_file(
        &pr.package()
            .as_path()
            .join("jetstreamer-historical-worker-v1-5-6"),
        WORKER_SHA,
        32 << 20,
    )?;
    let manifest = stable_file(
        &pr.package()
            .as_path()
            .join(format!("preflight-{}-v4.json", pr.epoch)),
        pr.manifest_sha,
        MAX_JSON,
    )?;
    Ok(
        json!({"run_identity":p.run_identity,"files":files,"node":node,"worker":worker,"manifest":manifest}),
    )
}
fn validate_cohort_state(state: &Value, pr: &Profile) -> Result<()> {
    ensure!(
        *state
            == json!({"schema":"jetstreamer-root-cohort-run-v1","start_epoch":pr.epoch,"end_epoch":pr.epoch,"status":"running-private","manifest_fingerprint":pr.fingerprint}),
        "cohort state/cursor changed"
    );
    Ok(())
}
fn native(unit: &str) -> Result<Value> {
    let output=Command::new("/usr/bin/systemctl").env_remove("DBUS_SYSTEM_BUS_ADDRESS").env_remove("SYSTEMD_BUS_ADDRESS").env_remove("DBUS_SESSION_BUS_ADDRESS").env_remove("SYSTEMD_HOST").args(["show",unit,"-pId,LoadState,ActiveState,SubState,MainPID,ControlPID,Job,InvocationID,NRestarts,MemoryMax,MemorySwapMax,TasksMax,RuntimeMaxUSec,ExecStart"]).output()?;
    ensure!(
        output.stdout.len() < 131072 && output.stderr.is_empty(),
        "native query incomplete"
    );
    let mut fields = serde_json::Map::new();
    for line in std::str::from_utf8(&output.stdout)?.lines() {
        let (k, v) = line.split_once('=').context("native delimiter")?;
        ensure!(
            fields.insert(k.to_owned(), json!(v)).is_none(),
            "native duplicate"
        );
    }
    let value = Value::Object(fields);
    ensure!(
        (output.status.success() || value["LoadState"] == "not-found") && value["Id"] == unit,
        "native query failed"
    );
    Ok(value)
}
fn closed(v: &Value, original: bool, pr: &Profile) -> Result<()> {
    let absent_properties =
        v["LoadState"] == "not-found" || v["Id"].as_str().is_some_and(|s| s.ends_with(".timer"));
    let zero = |key: &str| v[key] == "0" || (absent_properties && v.get(key).is_none());
    ensure!(
        zero("MainPID")
            && zero("ControlPID")
            && v["Job"] == ""
            && zero("NRestarts")
            && ["dead", "failed"].iter().any(|s| v["SubState"] == *s)
            && ["inactive", "failed"]
                .iter()
                .any(|s| v["ActiveState"] == *s),
        "owner or guard is not terminal"
    );
    if original {
        ensure!(
            v["Id"] == pr.unit
                && (v["InvocationID"] == pr.iid
                    || (v["LoadState"] == "not-found" && v["InvocationID"] == "")),
            "original invocation was replaced"
        );
    }
    Ok(())
}
fn own(execute: bool, pr: &Profile) -> Result<Value> {
    let unit = format!(
        "horizon-local1-scratch-retire-{}-{}-20261110-v1.service",
        pr.epoch,
        if execute { "execute" } else { "check" }
    );
    let v = native(&unit)?;
    ensure!(
        v["LoadState"] == "loaded"
            && v["ActiveState"] == "active"
            && v["SubState"] == "running"
            && v["MainPID"].as_str().and_then(|s| s.parse::<u32>().ok())
                == Some(std::process::id())
            && v["ControlPID"] == "0"
            && v["NRestarts"] == "0"
            && v["InvocationID"] == std::env::var("INVOCATION_ID")?
            && v["MemorySwapMax"] == "0",
        "native lifecycle scope differs"
    );
    for (key, minimum, maximum) in [
        ("MemoryMax", 268435456u64, 2147483648u64),
        ("TasksMax", 1, 256),
    ] {
        let x = v[key].as_str().context("native integer")?.parse::<u64>()?;
        ensure!(
            (minimum..=maximum).contains(&x),
            "unbounded native lifecycle limit"
        );
    }
    ensure!(
        [
            "1h",
            "30min",
            "20min",
            "15min",
            "10min",
            "5min",
            "2min",
            "1min",
            "3600000000",
            "1800000000",
            "120000000"
        ]
        .iter()
        .any(|x| v["RuntimeMaxUSec"] == *x),
        "unqualified lifecycle runtime limit"
    );
    ensure!(
        fs::read_to_string("/proc/self/cgroup")?.trim() == format!("0::/system.slice/{unit}"),
        "foreign lifecycle cgroup"
    );
    Ok(v)
}
fn event_rows(event: &Value) -> Result<&serde_json::Map<String, Value>> {
    ensure!(
        event["schema"] == "horizon-seven-standard-reserve-stop-repair-event-v1"
            && event["owner"] == "/root"
            && event["resource_promises_released"] == false
            && event["repair_open"] == true,
        "foreign historical original-seven event"
    );
    let rows = event["rows"]
        .as_object()
        .context("seven original histories must remain keyed")?;
    ensure!(
        rows.len() == 7 && (166..=172).all(|e| rows.contains_key(&e.to_string())),
        "all seven original terminal histories required"
    );
    Ok(rows)
}
fn references_local1(v: &Value, pr: &Profile) -> bool {
    match v {
        Value::String(s) => {
            s == pr.unit
                || s == pr.iid
                || process_references::encoded_reference(
                    s.as_bytes(),
                    pr.local1_root.as_bytes(),
                    true,
                )
        }
        Value::Array(a) => a.iter().any(|v| references_local1(v, pr)),
        Value::Object(m) => m
            .iter()
            .any(|(k, v)| k == pr.unit || references_local1(v, pr)),
        _ => false,
    }
}
fn fleet_view(f: &Value, event: &Bound, current: u64, pr: &Profile) -> Result<()> {
    let t = f["recorded_unix_seconds"]
        .as_u64()
        .context("fleet timestamp")?;
    ensure!(
        f["schema"] == "horizon-Root-complete-fleet-operational-review-v1"
            && f["owner"] == "/root"
            && f["primary_thread"] == "01a1af2a-9ce8-76a2-8939-b2112bd38f53"
            && f["terminal_producer_event"] == serde_json::to_value(event)?
            && t <= current
            && current - t <= 1800,
        "fresh accepted Root fleet required"
    );
    let rows = f["epochs"].as_array().context("complete Root epoch rows")?;
    let epochs: BTreeSet<_> = rows
        .iter()
        .map(|r| r["epoch"].as_u64().context("fleet epoch"))
        .collect::<Result<_>>()?;
    ensure!(
        rows.len() == 100 && epochs == (101..=200).collect(),
        "complete assigned range required"
    );
    let terminal = f["terminal_producers"]
        .as_array()
        .context("retained original terminal histories")?;
    let terminal_epochs: BTreeSet<_> = terminal
        .iter()
        .map(|r| r["epoch"].as_u64().context("terminal epoch"))
        .collect::<Result<_>>()?;
    ensure!(
        terminal.len() == 7
            && terminal_epochs == (166..=172).collect()
            && f["terminal_producer_count"] == 7
            && f["authenticated_status_count"] == 19
            && f["resource_credit_bytes"] == 0
            && f["replay_launch_authorized"] == false,
        "original histories/status/no-credit scope required"
    );
    let replays = f["actual_executing_replays"]
        .as_array()
        .context("actual replay owners")?;
    let bootstraps = f["actual_active_bootstraps"]
        .as_array()
        .context("actual bootstrap owners")?;
    ensure!(
        f["live_replay_count"].as_u64() == Some(replays.len() as u64)
            && f["active_producer_count"].as_u64()
                == Some((replays.len() + bootstraps.len()) as u64),
        "fleet active counts disagree"
    );
    let mut active_epochs = BTreeSet::new();
    for (owners, phase, state) in [
        (replays, "replay", "live-replay"),
        (bootstraps, "bootstrap", "staged-admissible"),
    ] {
        for owner in owners {
            let e = owner["epoch"].as_u64().context("active owner epoch")?;
            ensure!(
                (101..=200).contains(&e)
                    && active_epochs.insert(e)
                    && owner["phase"] == phase
                    && !references_local1(owner, pr),
                "active or staged owner claims failed local1"
            );
            let native = &owner["unit"];
            let declaration = &owner["declaration"];
            ensure!(
                native["Id"] == declaration["unit"]
                    && native["InvocationID"] == declaration["invocation_id"]
                    && declaration["epoch"] == e
                    && declaration["phase"] == phase
                    && native["LoadState"] == "loaded"
                    && native["ActiveState"] == "active"
                    && native["SubState"] == "running"
                    && native["MainPID"]
                        .as_str()
                        .and_then(|s| s.parse::<u64>().ok())
                        .is_some_and(|p| p > 0)
                    && native["ControlPID"] == "0"
                    && native["NRestarts"] == "0"
                    && native["Job"] == "",
                "genuine disjoint current owner required"
            );
            let row = rows
                .iter()
                .find(|r| r["epoch"] == e)
                .context("active epoch row")?;
            ensure!(
                row["state"] == state && row["current_live_producer"] == *native,
                "active fleet row does not match owner"
            );
        }
    }
    for row in rows {
        for key in [
            "current_live_producer",
            "replacement_evidence",
            "queued_producer",
            "queued_replay",
            "admitted_continuation",
            "active_owner",
        ] {
            ensure!(
                !references_local1(&row[key], pr),
                "failed local1 current or queued epoch-row owner"
            );
        }
    }
    for key in [
        "replacement_owner_declarations",
        "queued_producers",
        "queued_replays",
        "admitted_continuations",
    ] {
        ensure!(
            !references_local1(&f[key], pr),
            "failed local1 future claim in fleet"
        );
    }
    if let Some(census) = f["metadata_unit_census"].as_object() {
        for unit in [
            pr.unit.to_owned(),
            format!("{}.service", pr.guard),
            format!("{}.timer", pr.guard),
        ] {
            if let Some(v) = census.get(&unit) {
                closed(v, unit == pr.unit, pr)?;
            }
        }
    }
    Ok(())
}
fn fleet_histories(f: &Value, event: &Value) -> Result<()> {
    let originals = event_rows(event)?;
    let terminals = f["terminal_producers"]
        .as_array()
        .context("terminal original histories")?;
    for (e, old) in originals {
        let epoch = e.parse::<u64>()?;
        let row = terminals
            .iter()
            .find(|r| r["epoch"] == epoch)
            .context("missing terminal history")?;
        ensure!(
            row["original_invocation_id"] == old["original_invocation_id"]
                && row["stop_intent"] == old["stop_intent"]
                && row["stop_completion"] == old["stop_completion"]
                && row["original_PID1_journal"] == old["journal"]
                && row["partial_archive_preserved"] == old["original_archive"]
                && row["scratch_preserved"] == old["scratch"]
                && row["repair_open"] == true
                && row["resource_release_bytes"] == 0,
            "original terminal history was altered"
        );
        for (key, value) in old["native"]
            .as_object()
            .context("original terminal native history")?
        {
            ensure!(
                row["terminal_native"][key] == *value,
                "original terminal native field changed"
            );
        }
    }
    Ok(())
}
fn fleet(p: &Plan) -> Result<Value> {
    let f = json_bound(&p.fleet)?;
    fleet_view(&f, &p.stop_event, now()?, profile(p.epoch)?)?;
    fleet_histories(&f, &json_bound(&p.stop_event)?)?;
    Ok(f)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AllowedDefinition {
    unit: String,
    binding: Bound,
}
fn dependency(p: &Plan) -> Result<(Value, Vec<AllowedDefinition>)> {
    let pr = profile(p.epoch)?;
    let r = json_bound(&p.dependency_review)?;
    let t = r["recorded_unix_seconds"]
        .as_u64()
        .context("dependency time")?;
    let current = now()?;
    ensure!(
        r["schema"] == "jetstreamer-local1-scratch-dependency-review-v1"
            && r["owner"] == "/root"
            && r["epoch"] == pr.epoch
            && r["run_directory"] == pr.run
            && r["scratch"] == scratch(pr).to_str().unwrap()
            && r["source_review"] == serde_json::to_value(&p.source_review)?
            && r["fleet"] == serde_json::to_value(&p.fleet)?
            && r["terminal_journal"] == serde_json::to_value(&p.terminal_journal)?
            && t <= current
            && current - t <= 1800,
        "fresh dependency review differs"
    );
    for k in [
        "failed_local1_explicit_stop_and_original_PID1_terminal_reviewed",
        "live_local2_siblings_and_original_artifacts_preserved",
        "no_active_or_staged_consumer_requires_scratch_contents",
        "compiled_and_indirect_readers_reviewed",
        "all_future_reopening_excluded_during_transition",
        "scratch_is_not_an_admitted_continuation_cursor",
        "preserve_exact_scratch_inode",
    ] {
        ensure!(r[k] == true, "dependency gate not qualified: {k}");
    }
    ensure!(
        r["reviewed_definition_roots"] == json!(DEFINITION_ROOTS),
        "incomplete staged scope review"
    );
    let evidence: Vec<Bound> = serde_json::from_value(r["evidence"].clone())?;
    ensure!(
        !evidence.is_empty() && evidence.len() <= 128,
        "dependency evidence required"
    );
    for b in evidence {
        let bytes = raw(&b.path, MAX_JSON, true, true)?;
        ensure!(sha(&bytes) == b.sha256, "indirect source/evidence changed");
    }
    let allowed: Vec<AllowedDefinition> =
        serde_json::from_value(r["allowed_terminal_definitions"].clone())?;
    ensure!(allowed.len() <= 64, "definition allowance exceeds bound");
    let mut paths = BTreeSet::new();
    for a in &allowed {
        ensure!(
            p.closed_units.contains(&a.unit) && paths.insert(a.binding.path.clone()),
            "definition not bound to terminal owner"
        );
        let bytes = raw(&a.binding.path, 16 << 20, true, false)?;
        ensure!(
            sha(&bytes) == a.binding.sha256,
            "allowed definition changed"
        );
    }
    Ok((r, allowed))
}
fn masked_unit_definition(path: &Path) -> Result<bool> {
    let m = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e.into()),
    };
    let unit = path.file_name().and_then(|s| s.to_str()).is_some_and(|s| {
        [
            ".service",
            ".timer",
            ".socket",
            ".path",
            ".target",
            ".slice",
            ".scope",
            ".mount",
            ".automount",
            ".swap",
        ]
        .iter()
        .any(|suffix| s.ends_with(suffix))
    });
    Ok(unit
        && m.uid() == 0
        && m.file_type().is_symlink()
        && fs::read_link(path)? == Path::new("/dev/null"))
}
fn dependency_link(path: &Path) -> Result<bool> {
    let m = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e.into()),
    };
    if !m.file_type().is_symlink() || m.uid() != 0 {
        return Ok(false);
    }
    let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
        return Ok(false);
    };
    let wanted = path
        .parent()
        .and_then(Path::file_name)
        .and_then(|s| s.to_str())
        .is_some_and(|s| s.ends_with(".wants") || s.ends_with(".requires"));
    let unit = name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"-_@.\\x".contains(&b))
        && [
            ".service",
            ".timer",
            ".socket",
            ".path",
            ".target",
            ".mount",
            ".automount",
            ".slice",
            ".scope",
            ".swap",
        ]
        .iter()
        .any(|s| name.ends_with(s));
    Ok(wanted && unit && fs::read_link(path)? == Path::new("..").join(name))
}
fn staged_walk(
    pr: &Profile,
    path: &Path,
    depth: usize,
    visited: &mut BTreeSet<PathBuf>,
    count: &mut u64,
    total: &mut u64,
    allowed: &[AllowedDefinition],
) -> Result<()> {
    ensure!(
        depth <= 24 && *count < 100000 && *total <= 512 << 20,
        "staged definition budget exceeded"
    );
    if masked_unit_definition(path)? {
        *count = count
            .checked_add(1)
            .context("masked definition count overflow")?;
        return Ok(());
    }
    let m = match fs::metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if exists(path)? {
                ensure!(
                    dependency_link(path)?,
                    "dangling staged definition: {}",
                    path.display()
                );
                *count = count
                    .checked_add(1)
                    .context("dependency reference count overflow")?;
            }
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    };
    if m.is_dir() {
        let canonical = path.canonicalize()?;
        if !visited.insert(canonical) {
            return Ok(());
        }
        for e in fs::read_dir(path)? {
            staged_walk(pr, &e?.path(), depth + 1, visited, count, total, allowed)?;
        }
    } else if m.is_file() {
        ensure!(m.len() <= 16 << 20, "staged definition too large");
        let canonical = path.canonicalize()?;
        let bytes = raw(&canonical, 16 << 20, false, false)?;
        *count += 1;
        *total = total
            .checked_add(bytes.len() as u64)
            .context("staged byte overflow")?;
        if [pr.local1_root, pr.run]
            .iter()
            .any(|s| process_references::encoded_reference(&bytes, s.as_bytes(), true))
        {
            ensure!(
                allowed
                    .iter()
                    .any(|a| a.binding.path == canonical && a.binding.sha256 == sha(&bytes)),
                "unreviewed staged definition references run: {}",
                path.display()
            );
        }
    } else {
        anyhow::bail!("unexpected staged definition type: {}", path.display());
    }
    Ok(())
}
fn gates(p: &Plan, execute: bool) -> Result<Value> {
    let pr = profile(p.epoch)?;
    let native_self = own(execute, pr)?;
    let _ = fleet(p)?;
    let (review, allowed) = dependency(p)?;
    let mut owners = BTreeMap::new();
    for unit in &p.closed_units {
        let v = native(unit)?;
        closed(&v, unit == pr.unit, pr)?;
        owners.insert(unit, v);
    }
    no_scratch_mounts(&fs::read_to_string("/proc/self/mountinfo")?, &scratch(pr))?;
    let processes = process_references::scan(Path::new("/proc"), Path::new(pr.local1_root))?;
    ensure!(
        processes.references.is_empty(),
        "active run references: {:?}",
        processes.references
    );
    let (mut count, mut total) = (0, 0);
    let mut visited = BTreeSet::new();
    for root in DEFINITION_ROOTS {
        staged_walk(
            pr,
            Path::new(root),
            0,
            &mut visited,
            &mut count,
            &mut total,
            &allowed,
        )?;
    }
    // Close the process-census window with a second exact terminal observation.
    for unit in &p.closed_units {
        let after = native(unit)?;
        closed(&after, unit == pr.unit, pr)?;
        ensure!(
            owners.get(unit) == Some(&after),
            "terminal identity changed during reference check"
        );
    }
    ensure!(
        own(execute, pr)? == native_self,
        "lifecycle identity changed"
    );
    Ok(
        json!({"own":native_self,"terminal":owners,"fleet":p.fleet,"dependency_review":p.dependency_review,"dependency_recorded_unix_seconds":review["recorded_unix_seconds"],"processes":processes,"staged_definitions":count,"staged_bytes":total}),
    )
}
fn no_scratch_mounts(text: &str, target: &Path) -> Result<()> {
    for line in text.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        ensure!(fields.len() >= 10, "mountinfo shape");
        ensure!(
            !Path::new(fields[4]).starts_with(target),
            "scratch is or contains a mount"
        );
    }
    Ok(())
}
fn private_out(pr: &Profile) -> Result<File> {
    let dir = open_directory(pr.out().as_path())?;
    let m = dir.metadata()?;
    ensure!(
        m.uid() == 0 && m.mode() & 0o7777 == 0o700,
        "private root-only receipt directory required"
    );
    ensure!(
        unsafe { libc::flock(dir.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "lifecycle receipt lock busy"
    );
    Ok(dir)
}
fn shared_lock() -> Result<File> {
    let p = Path::new("/home/sol/.jetstreamer-private/r2-receipts/local-mutation.lock");
    let _parent = open_directory(p.parent().unwrap())?;
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(p)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file()
            && m.nlink() == 1
            && [0, 1001].contains(&m.uid())
            && m.mode() & 0o7777 == 0o600
            && unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "shared mutation lock unavailable"
    );
    Ok(f)
}
// No partial final receipt name can become visible. Interruption leaves only a
// disposable private temporary file; final publication is no-clobber.
fn persist(pr: &Profile, path: &Path, value: &Value) -> Result<Bound> {
    ensure!(
        path.parent() == Some(pr.out().as_path()),
        "receipt outside fixed namespace"
    );
    atomic_record(path, value)
}
fn atomic_record(path: &Path, value: &Value) -> Result<Bound> {
    let parent = path.parent().context("receipt parent missing")?;
    let dir = open_directory(parent)?;
    let m = dir.metadata()?;
    ensure!(
        m.uid() == unsafe { libc::geteuid() } && m.mode() & 0o7777 == 0o700,
        "receipt parent custody differs"
    );
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    temp.as_file()
        .set_permissions(fs::Permissions::from_mode(0o400))?;
    serde_json::to_writer(&mut temp, value)?;
    temp.write_all(b"\n")?;
    ensure!(
        temp.as_file().metadata()?.len() <= MAX_LEDGER,
        "receipt exceeds bound"
    );
    temp.as_file().sync_all()?;
    temp.persist_noclobber(path)
        .map_err(|e| anyhow::anyhow!("receipt conflict: {e}"))?;
    dir.sync_all()?;
    let bytes = raw(path, MAX_LEDGER, false, true)?;
    Ok(Bound {
        path: path.to_path_buf(),
        sha256: sha(&bytes),
    })
}
fn read_record(path: &Path, limit: u64) -> Result<(Value, Bound)> {
    let bytes = raw(path, limit, true, true)?;
    Ok((
        serde_json::from_slice(&bytes)?,
        Bound {
            path: path.to_path_buf(),
            sha256: sha(&bytes),
        },
    ))
}
fn persist_or_equal(pr: &Profile, path: &Path, value: &Value) -> Result<Bound> {
    if exists(path)? {
        let (prior, b) = read_record(path, MAX_LEDGER)?;
        ensure!(prior == *value, "existing receipt conflicts");
        Ok(b)
    } else {
        persist(pr, path, value)
    }
}
fn validate_binding(v: &Value, schema: &str, basis: &Value) -> Result<()> {
    ensure!(
        v["schema"] == schema && v["basis"] == *basis,
        "lifecycle scope or retained artifacts changed"
    );
    Ok(())
}
fn execute_tree(
    root: &File,
    ledger: &stopped_tree::Ledger,
    device: u64,
    uid: u32,
    gid: u32,
    resuming: bool,
) -> Result<u64> {
    let current = stopped_tree::capture(root, device, uid, gid)?;
    stopped_tree::validate_remaining(ledger, &current, resuming)?;
    let n = stopped_tree::remove_contents(root, ledger, device, uid, gid)?;
    root.sync_all()?;
    Ok(n)
}
fn run(p: &Plan, self_sha: &str, execute: bool) -> Result<()> {
    let pr = profile(p.epoch)?;
    scope(p)?;
    let _shared = shared_lock()?;
    let _out = private_out(pr)?;
    let source = original_evidence(p)?;
    let retained = preserved(p)?;
    let before = gates(p, execute)?;
    let anchored = open_directory(&p.scratch)?;
    ensure!(
        directory(&anchored.metadata()?) == p.scratch_identity,
        "scratch root replacement"
    );
    let root = stopped_tree::open_root(
        &p.scratch,
        p.scratch_identity.device,
        p.scratch_identity.inode,
    )?;
    ensure!(
        directory(&root.metadata()?) == p.scratch_identity,
        "scratch ownership changed"
    );
    let output = pr.out();
    let base = output.as_path();
    let lp = base.join("ledger.json");
    let cp = base.join("check.json");
    let ip = base.join("intent.json");
    let done = base.join("completion.json");
    let basis = json!({"scope_sha256":scope_sha(p)?,"tool_sha256":self_sha,"source":source,"preserved":retained,"scratch_identity":p.scratch_identity});
    if !execute {
        ensure!(
            !exists(&ip)? && !exists(&done)?,
            "lifecycle already executed; use reconciliation mode"
        );
        let ledger = stopped_tree::capture(&root, p.scratch_identity.device, 1001, 1003)?;
        let lb = persist_or_equal(pr, &lp, &serde_json::to_value(&ledger)?)?;
        let after = gates(p, false)?;
        ensure!(
            preserved(p)? == retained,
            "retained bytes/identity changed during check"
        );
        ensure!(
            directory(&open_directory(&p.scratch)?.metadata()?) == p.scratch_identity,
            "scratch path changed during check"
        );
        if exists(&cp)? {
            let (v, _) = read_record(&cp, MAX_JSON)?;
            validate_binding(&v, "jetstreamer-local1-scratch-check-v1", &basis)?;
            ensure!(
                v["ledger"] == serde_json::to_value(&lb)? && v["local_removal_performed"] == false,
                "prior check conflict"
            );
        } else {
            persist(
                pr,
                &cp,
                &json!({"schema":"jetstreamer-local1-scratch-check-v1","basis":basis,"ledger":lb,"first_gates":before,"final_gates":after,"local_removal_performed":false,"resource_credit_bytes":0,"resource_promise_ending_authorized":false,"replay_launch_authorized":false}),
            )?;
        }
        return Ok(());
    }
    let (check, cb) = read_record(&cp, MAX_JSON)?;
    validate_binding(&check, "jetstreamer-local1-scratch-check-v1", &basis)?;
    ensure!(
        check["local_removal_performed"] == false,
        "not a genuine check-only receipt"
    );
    let lv: Bound = serde_json::from_value(check["ledger"].clone())?;
    ensure!(lv.path == lp, "foreign ledger path");
    let bytes = raw(&lv.path, MAX_LEDGER, true, true)?;
    ensure!(sha(&bytes) == lv.sha256, "ledger changed");
    let ledger: stopped_tree::Ledger = serde_json::from_slice(&bytes)?;
    let resuming = exists(&ip)?;
    ensure!(!exists(&done)? || resuming, "completion without intent");
    let intent = json!({"schema":"jetstreamer-local1-scratch-intent-v1","basis":basis,"ledger":lv,"check":cb,"preserve_scratch_inode":true,"resource_promise_ending_authorized":false,"replay_launch_authorized":false});
    let ib = if resuming {
        let (v, b) = read_record(&ip, MAX_JSON)?;
        ensure!(v == intent, "original durable intent differs");
        b
    } else {
        let current = stopped_tree::capture(&root, p.scratch_identity.device, 1001, 1003)?;
        stopped_tree::validate_remaining(&ledger, &current, false)?;
        persist(pr, &ip, &intent)?
    };
    if exists(&done)? {
        let (v, _) = read_record(&done, MAX_JSON)?;
        validate_binding(&v, "jetstreamer-local1-scratch-complete-v1", &basis)?;
        ensure!(
            v["intent"] == serde_json::to_value(&ib)?
                && v["scratch_empty"] == true
                && v["scratch_root_preserved"] == true,
            "completion conflict"
        );
        let current = stopped_tree::capture(&root, p.scratch_identity.device, 1001, 1003)?;
        stopped_tree::validate_remaining(&ledger, &current, true)?;
        ensure!(current.len() == 1, "new entries after completion");
        root.sync_all()?;
        let _ = gates(p, true)?;
        ensure!(
            preserved(p)? == retained,
            "retained closure changed after completion"
        );
        return Ok(());
    }
    let final_gate = gates(p, true)?;
    ensure!(
        preserved(p)? == retained,
        "retained closure changed before retirement"
    );
    ensure!(
        directory(&open_directory(&p.scratch)?.metadata()?) == p.scratch_identity,
        "scratch path replaced at retirement"
    );
    let removed = execute_tree(
        &root,
        &ledger,
        p.scratch_identity.device,
        1001,
        1003,
        resuming,
    )?;
    let after = gates(p, true)?;
    ensure!(
        directory(&open_directory(&p.scratch)?.metadata()?) == p.scratch_identity
            && preserved(p)? == retained,
        "namespace/retained evidence changed during retirement"
    );
    let current = stopped_tree::capture(&root, p.scratch_identity.device, 1001, 1003)?;
    stopped_tree::validate_remaining(&ledger, &current, true)?;
    ensure!(current.len() == 1, "scratch not empty");
    root.sync_all()?;
    persist(
        pr,
        &done,
        &json!({"schema":"jetstreamer-local1-scratch-complete-v1","basis":basis,"intent":ib,"first_gates":before,"pre_remove_gates":final_gate,"final_gates":after,"removed_entries_this_invocation":removed,"resumed":resuming,"scratch_empty":true,"scratch_root_preserved":true,"partial_archive_and_all_inputs_preserved":true,"physical_reclamation_accounting_separately_required":true,"resource_credit_bytes":0,"resource_promise_ending_authorized":false,"replay_launch_authorized":false,"archive_deletion_authorized":false,"remote_mutations":false,"r2_mutations":false}),
    )?;
    Ok(())
}
fn main() -> Result<()> {
    let a = std::env::args().collect::<Vec<_>>();
    ensure!(
        a.len() == 7
            && a[2] == "--plan-sha256"
            && a[4] == "--self-sha256"
            && ["--check-only", "--execute"].contains(&a[6].as_str())
            && lower_sha(&a[3])
            && lower_sha(&a[5]),
        "exact argv required"
    );
    ensure!(
        unsafe { libc::geteuid() } == 0 && fs::read_link("/proc/self/exe")? == Path::new(IMAGE),
        "normally sealed root image required"
    );
    let image = raw(Path::new(IMAGE), 64 << 20, true, true)?;
    ensure!(sha(&image) == a[5], "self image changed");
    let p: Plan = serde_json::from_value(json_bound(&Bound {
        path: a[1].clone().into(),
        sha256: a[3].clone(),
    })?)?;
    run(&p, &a[5], a[6] == "--execute")
}

#[cfg(test)]
mod tests;
