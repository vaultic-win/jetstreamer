// Exact, contents-only retirement of one exact guard-stopped standard scratch.
// Source proposal only. Root separately owns qualification and admission.
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

mod mixed;
mod specs;
use mixed::OtherLive;
const SPEC: &specs::Spec = &specs::SPECS[PROFILE_INDEX];
const EPOCH: u64 = SPEC.epoch;
const IMAGE: &str = SPEC.image;
const LANE: &str = SPEC.lane;
const RUN: &str = SPEC.run;
const UNIT: &str = SPEC.unit;
const IID: &str = SPEC.iid;
const GUARD: &str = SPEC.guard;
const GUARD_PLAN: &str = SPEC.guard_plan;
const GUARD_PLAN_SHA: &str = SPEC.guard_plan_sha;
const STOP_INTENT_SHA: &str = SPEC.stop_intent_sha;
const STOP_COMPLETE_SHA: &str = SPEC.stop_complete_sha;
const GUARD_RECEIPTS: &str = SPEC.guard_receipts;
const EVENT: &str = "/var/lib/jetstreamer/seven-standard-reserve-stop-20261110-v1/ORIGINAL_SEVEN_RESERVE_STOPS_AND_REPAIR_MODEL.json";
const SOURCE_REVIEW_SHA: &str = specs::SOURCE_REVIEW_SHA;
const NODE_SHA: &str = "a09b8e5aa9426beaf42e6b5f2a469a5a147436bab8b7bf79f268758b60aa2e65";
const WORKER_SHA: &str = "cf5fa883df75b23de82af52dc0e90c013f8e83397b445027e510a1137decc819";
const PACKAGE: &str = SPEC.package;
const MANIFEST_SHA: &str = SPEC.manifest_sha;
const FINGERPRINT: &str = SPEC.fingerprint;
const OUT: &str = SPEC.out;
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
    fleet: Bound,
    dependency_review: Bound,
    closed_units: Vec<String>,
    other_live_replays: Vec<OtherLive>,
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
fn scratch() -> PathBuf {
    Path::new(RUN).join("scratch")
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
    ensure!(
        p.schema == "jetstreamer-standard-stopped-scratch-retirement-plan-v1"
            && p.owner == "/root"
            && (167..=172).contains(&EPOCH)
            && p.epoch == EPOCH
            && p.run_directory == Path::new(RUN)
            && p.scratch == scratch(),
        "foreign selected standard scope"
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
    for d in [&p.run_identity, &p.scratch_identity] {
        ensure!(
            d.uid == 1001 && d.gid == 1003 && d.device > 0 && d.inode > 0 && d.mode == 0o700,
            "unbound original directory identity"
        );
    }
    ensure!(
        p.run_identity.device == p.scratch_identity.device
            && p.source_review.sha256 == SOURCE_REVIEW_SHA
            && p.stop_event.path == Path::new(EVENT)
            && p.stop_event.sha256 == specs::EVENT_SHA,
        "source/event identity differs"
    );
    let units: BTreeSet<_> = p.closed_units.iter().map(String::as_str).collect();
    ensure!(
        units.len() == p.closed_units.len()
            && units.len() <= 32
            && units.contains(UNIT)
            && units.contains(format!("{GUARD}.service").as_str())
            && units.contains(format!("{GUARD}.timer").as_str()),
        "missing original closed owner/guard"
    );
    ensure!(
        units
            .iter()
            .all(|s| s.len() <= 255 && (s.ends_with(".service") || s.ends_with(".timer"))),
        "invalid closed unit kind"
    );
    ensure!(
        units.iter().all(|s| s
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.@".contains(&b))),
        "unsafe unit spelling"
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
    let r = raw(&p.source_review.path, MAX_JSON, true, true)?;
    ensure!(sha(&r) == SOURCE_REVIEW_SHA, "exact source review changed");
    let event = json_bound(&p.stop_event)?;
    ensure!(
        event["schema"] == "horizon-seven-standard-reserve-stop-repair-event-v1"
            && event["owner"] == "/root"
            && event["resource_promises_released"] == false
            && event["repair_open"] == true,
        "foreign stop event"
    );
    for (path, digest) in [
        (SPEC.argv, SPEC.argv_sha),
        (SPEC.seal, SPEC.seal_sha),
        (SPEC.capability, SPEC.capability_sha),
    ] {
        let bytes = raw(Path::new(path), MAX_JSON, true, false)?;
        ensure!(
            sha(&bytes) == digest,
            "exact original argv/package/capability changed"
        );
    }
    let r = selected_event(&event)?;
    ensure!(
        r["unit"] == UNIT
            && r["original_invocation_id"] == IID
            && r["scratch"] == scratch().to_str().unwrap()
            && r["original_archive"]
                == Path::new(RUN)
                    .join(format!("archives/epoch-{EPOCH}.jet"))
                    .to_str()
                    .unwrap()
            && r["no_resource_release"] == true
            && r["preserve_partial_and_inputs"] == true,
        "original stop row differs"
    );
    let ib: Bound = serde_json::from_value(r["stop_intent"].clone())?;
    let cb: Bound = serde_json::from_value(r["stop_completion"].clone())?;
    ensure!(
        ib.path == Path::new(GUARD_RECEIPTS).join("stop-intent.json")
            && ib.sha256 == STOP_INTENT_SHA
            && cb.path == Path::new(GUARD_RECEIPTS).join("stop-completion.json")
            && cb.sha256 == STOP_COMPLETE_SHA,
        "foreign guard stop chain"
    );
    let intent = json_bound(&ib)?;
    let completion = json_bound(&cb)?;
    validate_stop(&intent, &completion)?;
    let plan: Value = serde_json::from_slice(&raw(Path::new(GUARD_PLAN), MAX_JSON, true, true)?)?;
    ensure!(
        sha(&raw(Path::new(GUARD_PLAN), MAX_JSON, true, true)?) == GUARD_PLAN_SHA
            && plan["schema"] == "jetstreamer-horizon-standalone-guard-plan-v1"
            && plan["unit"] == UNIT
            && plan["invocation_id"] == IID
            && plan["worker_root"] == LANE
            && plan["minimum_free_bytes"] == intent["sample"]["minimum_free_bytes"],
        "original guard plan differs"
    );
    let journal: Bound = serde_json::from_value(r["journal"].clone())?;
    let _ = json_bound(&journal)?;
    Ok(
        json!({"event":p.stop_event,"source_review":p.source_review,"stop_intent":ib,"stop_completion":cb,"guard_plan_sha256":GUARD_PLAN_SHA,"journal":journal}),
    )
}
fn validate_stop(i: &Value, c: &Value) -> Result<()> {
    let s = &i["sample"];
    ensure!(
        i["schema"] == "jetstreamer-horizon-standalone-stop-intent-v1"
            && c["schema"] == "jetstreamer-horizon-standalone-stop-completion-v1"
            && i["producer_invocation_id"] == IID
            && c["producer_invocation_id"] == IID
            && i["plan_sha256"] == GUARD_PLAN_SHA
            && c["plan_sha256"] == GUARD_PLAN_SHA
            && c["intent"]
                == Path::new(GUARD_RECEIPTS)
                    .join("stop-intent.json")
                    .to_str()
                    .unwrap(),
        "guard stop binding differs"
    );
    ensure!(
        i["reason"] == "filesystem-floor"
            && s["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && s["producer_invocation_id"] == IID
            && s["plan_sha256"] == GUARD_PLAN_SHA
            && s["guard_sha256"]
                == "35dbd4826c8947f38d50dff049345e1c3d62450eb85e41e94e326880e1898fbc"
            && s["producer"]["pid"] == SPEC.pid
            && s["producer"]["invocation_id"] == IID
            && s["producer"]["restarts"] == 0
            && s["producer_stop_enabled"] == true
            && s["available_bytes"]
                .as_u64()
                .zip(s["minimum_free_bytes"].as_u64())
                .is_some_and(|(a, b)| a < b),
        "not the original protected filesystem stop"
    );
    ensure!(
        c["terminal"]["invocation_id"] == IID
            && c["terminal"]["pid"] == 0
            && c["terminal"]["active"] == "inactive"
            && c["terminal"]["sub"] == "dead"
            && c["terminal"]["restarts"] == 0
            && c["scratch_deleted"] == false
            && c["remote_mutations"] == false
            && c["r2_mutations"] == false,
        "original stop incomplete"
    );
    Ok(())
}
fn retained_walk(p: &Path, out: &mut BTreeMap<String, Value>, depth: usize) -> Result<()> {
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
        .strip_prefix(RUN)?
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
            retained_walk(&e?.path(), out, depth + 1)?;
        }
    }
    Ok(())
}
fn preserved(p: &Plan) -> Result<Value> {
    let dir = open_directory(Path::new(RUN))?;
    ensure!(
        directory(&dir.metadata()?) == p.run_identity,
        "original run changed"
    );
    let names: BTreeSet<_> = fs::read_dir(RUN)?
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
        retained_walk(&Path::new(RUN).join(name), &mut files, 0)?;
    }
    let archive_names: Vec<_> = fs::read_dir(Path::new(RUN).join("archives"))?
        .map(|e| Ok(e?.file_name()))
        .collect::<Result<_>>()?;
    ensure!(
        archive_names == [std::ffi::OsString::from(format!("epoch-{EPOCH}.jet"))],
        "partial archive census differs"
    );
    let state: Value = serde_json::from_slice(&raw(
        &Path::new(RUN).join("cohort-state.json"),
        65536,
        false,
        false,
    )?)?;
    ensure!(
        sha(&raw(
            &Path::new(RUN).join("cohort-state.json"),
            65536,
            false,
            false
        )?) == SPEC.state_sha,
        "original state digest changed"
    );
    validate_cohort_state(&state)?;
    let node = stable_file(
        &Path::new(PACKAGE).join("jetstreamer-node"),
        NODE_SHA,
        64 << 20,
    )?;
    let worker = stable_file(
        &Path::new(PACKAGE).join("jetstreamer-historical-worker-v1-5-6"),
        WORKER_SHA,
        32 << 20,
    )?;
    let manifest = stable_file(
        &Path::new(PACKAGE).join(format!("preflight-{EPOCH}-v4.json")),
        MANIFEST_SHA,
        MAX_JSON,
    )?;
    Ok(
        json!({"run_identity":p.run_identity,"files":files,"node":node,"worker":worker,"manifest":manifest}),
    )
}
fn validate_cohort_state(state: &Value) -> Result<()> {
    ensure!(
        *state
            == json!({"schema":"jetstreamer-root-cohort-run-v1","start_epoch":EPOCH,"end_epoch":EPOCH,"status":"running-private","manifest_fingerprint":FINGERPRINT}),
        "cohort state/cursor changed"
    );
    Ok(())
}
fn native(unit: &str) -> Result<Value> {
    let output=Command::new("/usr/bin/systemctl").env_remove("DBUS_SYSTEM_BUS_ADDRESS").env_remove("SYSTEMD_BUS_ADDRESS").env_remove("DBUS_SESSION_BUS_ADDRESS").env_remove("SYSTEMD_HOST").args(["show",unit,"-pId,LoadState,ActiveState,SubState,MainPID,ControlPID,Job,InvocationID,NRestarts,MemoryMax,MemorySwapMax,TasksMax,RuntimeMaxUSec,ExecStart,Restart,Triggers"]).output()?;
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
fn closed(v: &Value, original: bool) -> Result<()> {
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
            v["Id"] == UNIT
                && (v["InvocationID"] == IID
                    || (v["LoadState"] == "not-found" && v["InvocationID"] == "")),
            "original invocation was replaced"
        );
    }
    Ok(())
}
fn own(execute: bool) -> Result<Value> {
    let unit = if execute {
        SPEC.execute_unit
    } else {
        SPEC.check_unit
    };
    let v = native(unit)?;
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
fn covers_target(v: &Value) -> bool {
    match v {
        Value::Object(m) => {
            m.get("epoch") == Some(&json!(EPOCH))
                || m.get("range")
                    .and_then(Value::as_str)
                    .and_then(|s| s.parse::<u64>().ok())
                    == Some(EPOCH)
                || [
                    ("first_epoch", "last_epoch"),
                    ("scope_first_epoch", "scope_last_epoch"),
                    ("start_epoch", "end_epoch"),
                ]
                .iter()
                .any(|(first, last)| {
                    m.get(*first)
                        .and_then(Value::as_u64)
                        .zip(m.get(*last).and_then(Value::as_u64))
                        .is_some_and(|(a, b)| a <= EPOCH && EPOCH <= b)
                })
                || m.get("range").and_then(Value::as_str).is_some_and(|s| {
                    s.split(',').any(|part| {
                        part.split_once('-')
                            .and_then(|(a, b)| {
                                Some((a.parse::<u64>().ok()?, b.parse::<u64>().ok()?))
                            })
                            .is_some_and(|(a, b)| a <= EPOCH && EPOCH <= b)
                    })
                })
                || m.values().any(covers_target)
        }
        Value::Array(a) => a.iter().any(covers_target),
        _ => false,
    }
}
fn selected_event(event: &Value) -> Result<&Value> {
    let rows = event["rows"]
        .as_object()
        .context("stop event must contain keyed rows")?;
    ensure!(
        rows.len() == 7 && (166..=172).all(|e| rows.contains_key(&e.to_string())),
        "complete seven original keyed stop rows required"
    );
    rows.get(&EPOCH.to_string())
        .context("selected original stop row absent")
}
fn fleet_view(f: &Value, event: &Bound, current: u64, peers: &[OtherLive]) -> Result<()> {
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
        "fresh accepted Root terminal fleet required"
    );
    let rows = f["epochs"].as_array().context("complete Root epoch rows")?;
    let epochs: BTreeSet<_> = rows
        .iter()
        .map(|r| r["epoch"].as_u64().context("fleet epoch"))
        .collect::<Result<_>>()?;
    ensure!(
        rows.len() == 100
            && epochs == (101..=200).collect()
            && rows
                .iter()
                .any(|r| r["epoch"] == EPOCH && r["state"] == "failed-needs-repair"),
        "complete range and failed target required"
    );
    ensure!(
        f["authenticated_status_count"] == 19
            && f["resource_credit_bytes"] == 0
            && f["replay_launch_authorized"] == false,
        "fleet must retain no-credit/no-launch scope"
    );
    mixed::fleet_shape(f, peers, EPOCH)?;
    Ok(())
}
fn fleet(p: &Plan) -> Result<Value> {
    let f = json_bound(&p.fleet)?;
    fleet_view(&f, &p.stop_event, now()?, &p.other_live_replays)?;
    Ok(f)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AllowedDefinition {
    unit: String,
    binding: Bound,
}
fn dependency(p: &Plan) -> Result<(Value, Vec<AllowedDefinition>)> {
    let r = json_bound(&p.dependency_review)?;
    let t = r["recorded_unix_seconds"]
        .as_u64()
        .context("dependency time")?;
    let current = now()?;
    ensure!(
        r["schema"] == "jetstreamer-standard-stopped-scratch-dependency-review-v1"
            && r["owner"] == "/root"
            && r["epoch"] == EPOCH
            && r["run_directory"] == RUN
            && r["scratch"] == scratch().to_str().unwrap()
            && r["source_review"] == serde_json::to_value(&p.source_review)?
            && r["fleet"] == serde_json::to_value(&p.fleet)?
            && t <= current
            && current - t <= 1800,
        "fresh dependency review differs"
    );
    for k in [
        "original_terminal_chain_reviewed",
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
            staged_walk(&e?.path(), depth + 1, visited, count, total, allowed)?;
        }
    } else if m.is_file() {
        ensure!(m.len() <= 16 << 20, "staged definition too large");
        let canonical = path.canonicalize()?;
        let bytes = raw(&canonical, 16 << 20, false, false)?;
        *count += 1;
        *total = total
            .checked_add(bytes.len() as u64)
            .context("staged byte overflow")?;
        if [LANE, RUN]
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
    let native_self = own(execute)?;
    let fleet_value = fleet(p)?;
    let peer_before = mixed::live_peers(&p.other_live_replays, &fleet_value, &p.stop_event)?;
    let (review, allowed) = dependency(p)?;
    let mut owners = BTreeMap::new();
    for unit in &p.closed_units {
        let v = native(unit)?;
        closed(&v, unit == UNIT)?;
        owners.insert(unit, v);
    }
    no_scratch_mounts(&fs::read_to_string("/proc/self/mountinfo")?, &scratch())?;
    let processes = process_references::scan(Path::new("/proc"), Path::new(LANE))?;
    ensure!(
        processes.references.is_empty(),
        "active run references: {:?}",
        processes.references
    );
    let (mut count, mut total) = (0, 0);
    let mut visited = BTreeSet::new();
    for root in DEFINITION_ROOTS {
        staged_walk(
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
        closed(&after, unit == UNIT)?;
        ensure!(
            owners.get(unit) == Some(&after),
            "terminal identity changed during reference check"
        );
    }
    let peer_after = mixed::live_peers(&p.other_live_replays, &fleet_value, &p.stop_event)?;
    mixed::same_peers(&peer_before, &peer_after)?;
    ensure!(own(execute)? == native_self, "lifecycle identity changed");
    Ok(
        json!({"own":native_self,"terminal":owners,"fleet":p.fleet,"dependency_review":p.dependency_review,"dependency_recorded_unix_seconds":review["recorded_unix_seconds"],"processes":processes,"staged_definitions":count,"staged_bytes":total,"protected_other_replays_before":peer_before,"protected_other_replays_after":peer_after}),
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
fn private_out() -> Result<File> {
    let dir = open_directory(Path::new(OUT))?;
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
fn persist(path: &Path, value: &Value) -> Result<Bound> {
    ensure!(
        path.parent() == Some(Path::new(OUT)),
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
fn persist_or_equal(path: &Path, value: &Value) -> Result<Bound> {
    if exists(path)? {
        let (prior, b) = read_record(path, MAX_LEDGER)?;
        ensure!(prior == *value, "existing receipt conflicts");
        Ok(b)
    } else {
        persist(path, value)
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
    scope(p)?;
    let _shared = shared_lock()?;
    let _out = private_out()?;
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
    let base = Path::new(OUT);
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
        let lb = persist_or_equal(&lp, &serde_json::to_value(&ledger)?)?;
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
            validate_binding(&v, "jetstreamer-standard-stopped-scratch-check-v1", &basis)?;
            ensure!(
                v["ledger"] == serde_json::to_value(&lb)? && v["local_removal_performed"] == false,
                "prior check conflict"
            );
        } else {
            persist(
                &cp,
                &json!({"schema":"jetstreamer-standard-stopped-scratch-check-v1","basis":basis,"ledger":lb,"first_gates":before,"final_gates":after,"local_removal_performed":false,"resource_credit_bytes":0,"resource_promise_ending_authorized":false,"replay_launch_authorized":false}),
            )?;
        }
        return Ok(());
    }
    let (check, cb) = read_record(&cp, MAX_JSON)?;
    validate_binding(
        &check,
        "jetstreamer-standard-stopped-scratch-check-v1",
        &basis,
    )?;
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
    let intent = json!({"schema":"jetstreamer-standard-stopped-scratch-intent-v1","basis":basis,"ledger":lv,"check":cb,"preserve_scratch_inode":true,"resource_promise_ending_authorized":false,"replay_launch_authorized":false});
    let ib = if resuming {
        let (v, b) = read_record(&ip, MAX_JSON)?;
        ensure!(v == intent, "original durable intent differs");
        b
    } else {
        let current = stopped_tree::capture(&root, p.scratch_identity.device, 1001, 1003)?;
        stopped_tree::validate_remaining(&ledger, &current, false)?;
        persist(&ip, &intent)?
    };
    if exists(&done)? {
        let (v, _) = read_record(&done, MAX_JSON)?;
        validate_binding(
            &v,
            "jetstreamer-standard-stopped-scratch-complete-v1",
            &basis,
        )?;
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
        &done,
        &json!({"schema":"jetstreamer-standard-stopped-scratch-complete-v1","basis":basis,"intent":ib,"first_gates":before,"pre_remove_gates":final_gate,"final_gates":after,"removed_entries_this_invocation":removed,"resumed":resuming,"scratch_empty":true,"scratch_root_preserved":true,"partial_archive_and_all_inputs_preserved":true,"physical_reclamation_accounting_separately_required":true,"resource_credit_bytes":0,"resource_promise_ending_authorized":false,"replay_launch_authorized":false,"archive_deletion_authorized":false,"remote_mutations":false,"r2_mutations":false}),
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
