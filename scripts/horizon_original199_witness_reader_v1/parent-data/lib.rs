//! Explicit old 183–184 future-growth closure, separate from raw DATA and memory.
#![deny(warnings)]
#[allow(dead_code)]
mod fsutil;
#[allow(dead_code)]
#[path = "/home/sol/.jetstreamer-private/retained199-census-family-continuity-source-20261105-v1/shared-source/jetstreamer-r2/src/fleet/terminal_legacy_memory.rs"]
mod legacy;
mod process_references;
mod projection;
mod selection_clock;
#[cfg(test)]
use anyhow::bail;
#[cfg(test)]
use base64::{Engine as _, prelude::BASE64_STANDARD};
#[cfg(test)]
use std::time::{SystemTime, UNIX_EPOCH};
#[cfg(test)]
mod fleet;
#[cfg(test)]
use sha2::{Digest, Sha256};
#[cfg(test)]
mod test_host;
#[cfg(test)]
use test_host::{hex_lower, read_stable_bounded};
#[cfg(test)]
#[allow(dead_code)]
#[path = "/home/sol/.jetstreamer-private/retained199-census-family-continuity-source-20261105-v1/shared-source/jetstreamer-r2/src/completed_coordinator.rs"]
mod completed_coordinator;
mod model {
    pub use horizon_original199_parent_memory::model::Bound;
}
use anyhow::{Context, Result, ensure};
use fsutil as f;
use horizon_original199_parent_memory::VerifiedParentMemory;
use model::Bound;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::Command,
};
const PRODUCER: &str =
    "jetstreamer-root-sweep-e183-184-full-20261023-v2-r2-e183-184-lane-a-1.service";
const CONTROLLER: &str =
    "jetstreamer-epochs183-184-readerfix-full-20261023-controller-v2-r2.service";
const ROOT: &str = "/home/sol/.jetstreamer-private/epochs183-184-readerfix-20261020-v1/lane-a";
const TERMINAL: &str = "/usr/local/lib/jetstreamer/horizon-cohort183-canonical-import-evidence-20261029-v1/terminal.json";
const TERMINAL_SHA: &str = "5d0fcb753e3b2b984958657a2cee8e3eea7c6000bd6c375ba68aa8793dc14395";
const ABSENT_SERVICE_FIELDS: [&str; 5] = [
    "ExecStart",
    "ExecStartPre",
    "ExecStartPost",
    "ExecStop",
    "ExecStopPost",
];
const FIELDS: &str = "Id,LoadState,InvocationID,MainPID,ControlPID,ControlGroup,ActiveState,SubState,Restart,Result,ExecMainStatus,NRestarts,Job,TriggeredBy,Triggers,FragmentPath,DropInPaths,ExecStart,ExecStartPre,ExecStartPost,ExecStop,ExecStopPost,OnSuccess,OnFailure";
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    schema: String,
    current: horizon_original199_parent_memory::model::Current,
    recorded_unix_seconds: u64,
    terminal_legacy_closure: Bound,
    authenticated_inventory: Bound,
    ready_receipts: [Bound; 2],
    claim_key: String,
    original_growth_bytes: u64,
    physical_credit_bytes: u64,
    memory_credit_bytes: u64,
}
/// Private fields: a raw JSON projection or arithmetic cannot construct this view.
#[derive(Debug)]
pub struct VerifiedData {
    raw_protected_bytes: u64,
    effective_protected_bytes: u64,
    evidence: Value,
}
impl VerifiedData {
    pub fn raw_protected_bytes(&self) -> u64 {
        self.raw_protected_bytes
    }
    pub fn effective_protected_bytes(&self) -> u64 {
        self.effective_protected_bytes
    }
    pub fn evidence(&self) -> &Value {
        &self.evidence
    }
}
fn validate_policy(p: &Policy) -> Result<()> {
    ensure!(
        p.schema == "epoch183-explicit-ended-growth-DATA-policy-v1"
            && p.claim_key == "epoch183/489e219d38d14d4594d8649ff698f666"
            && p.original_growth_bytes == 768 << 30
            && p.physical_credit_bytes == 0
            && p.memory_credit_bytes == 0
            && p.terminal_legacy_closure.path == Path::new(legacy::CLOSURE_PATH),
        "explicit exact ended183 DATA policy differs"
    );
    for (r, path) in p.ready_receipts.iter().zip([
        "/home/sol/.jetstreamer-private/r2-receipts/epoch-183.r2.json",
        "/home/sol/.jetstreamer-private/r2-receipts/epoch-184.r2.json",
    ]) {
        ensure!(r.path == Path::new(path), "foreign ready receipt path");
    }
    Ok(())
}
fn registered(bound: &Bound, seal: &Bound) -> Result<Policy> {
    let root = bound.path.parent().context("DATA policy parent")?;
    ensure!(
        root.parent() == Some(Path::new("/usr/local/lib/jetstreamer"))
            && root
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with("horizon-ended183-DATA-policy-"))
            && bound.path.file_name().is_some_and(|s| s == "policy.json")
            && seal.path == root.join("deployment-seal-receipt.json"),
        "DATA policy namespace"
    );
    let s = f::immutable(seal)?;
    ensure!(
        s["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && s["destination"] == root.to_string_lossy().as_ref()
            && s["replay_launch_authorized"] == false
            && s["publication_authorized"] == false
            && s["remote_mutations"] == false
            && s["r2_mutations"] == false
            && s["members"].as_array().is_some_and(|a| a
                .iter()
                .filter(|r| r["name"] == "policy.json"
                    && r["sha256"] == bound.sha256
                    && r["mode"] == "0444")
                .count()
                == 1),
        "DATA policy normal seal differs"
    );
    let p: Policy = serde_json::from_value(f::immutable(bound)?)?;
    validate_policy(&p)?;
    Ok(p)
}
fn terminal_native(v: &Value, unit: &str) -> Result<()> {
    ensure!(
        v["Id"] == unit
            && v["LoadState"] == "not-found"
            && v["InvocationID"] == ""
            && v["MainPID"] == "0"
            && v["ControlPID"] == "0"
            && v["ControlGroup"] == ""
            && v["ActiveState"] == "inactive"
            && v["SubState"] == "dead"
            && v["Restart"] == "no"
            && v["Result"] == "success"
            && v["ExecMainStatus"] == "0"
            && v["NRestarts"] == "0"
            && v["Job"] == ""
            && v["TriggeredBy"] == ""
            && v["Triggers"] == ""
            && ["FragmentPath", "DropInPaths", "OnSuccess", "OnFailure"]
                .iter()
                .all(|k| v[*k] == "")
            && ABSENT_SERVICE_FIELDS.iter().all(|k| v.get(*k).is_none()),
        "original183 owner is live, replaced or has future launch authority"
    );
    Ok(())
}
fn native() -> Result<Value> {
    let mut rows = BTreeMap::new();
    for unit in [PRODUCER, CONTROLLER] {
        let o = Command::new("/usr/bin/systemctl")
            .args([
                "--system",
                "show",
                unit,
                "--no-pager",
                &format!("--property={FIELDS}"),
            ])
            .env_remove("DBUS_SYSTEM_BUS_ADDRESS")
            .env_remove("DBUS_SESSION_BUS_ADDRESS")
            .env_remove("SYSTEMD_BUS_ADDRESS")
            .env_remove("SYSTEMD_HOST")
            .output()?;
        ensure!(
            o.status.success() && o.stderr.is_empty() && o.stdout.len() <= 65536,
            "bounded original183 native query failed"
        );
        let mut row = serde_json::Map::new();
        for line in std::str::from_utf8(&o.stdout)?.lines() {
            let (k, v) = line.split_once('=').context("native DATA framing")?;
            ensure!(
                FIELDS.split(',').any(|x| x == k) && row.insert(k.into(), json!(v)).is_none(),
                "unexpected/duplicate DATA native field"
            );
        }
        ensure!(
            row.len() == FIELDS.split(',').count() - ABSENT_SERVICE_FIELDS.len(),
            "incomplete DATA native fields"
        );
        let row = Value::Object(row);
        terminal_native(&row, unit)?;
        rows.insert(unit, row);
    }
    Ok(json!(rows))
}
fn receipts(b: &Bound) -> Result<Value> {
    // Only the two exact normal private R2 receipt paths are accepted by policy.
    ensure!(
        b.path.is_absolute() && b.path.canonicalize()? == b.path && f::hex(&b.sha256, 64),
        "ready receipt path/digest"
    );
    let mut prefix = PathBuf::from("/");
    for part in b
        .path
        .parent()
        .context("receipt parent")?
        .components()
        .skip(1)
    {
        prefix.push(part);
        let m = fs::symlink_metadata(&prefix)?;
        ensure!(
            m.is_dir() && m.mode() & 0o022 == 0 && (m.uid() == 0 || m.uid() == 1001),
            "receipt ancestor changed"
        );
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&b.path)?;
    let m = file.metadata()?;
    ensure!(
        m.is_file()
            && m.nlink() == 1
            && [0, 1001].contains(&m.uid())
            && m.mode() & 0o077 == 0
            && m.len() > 0
            && m.len() <= 65536,
        "normal ready receipt custody"
    );
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(65537)
        .read_to_end(&mut bytes)?;
    let z = file.metadata()?;
    let n = fs::symlink_metadata(&b.path)?;
    let id = |m: &fs::Metadata| {
        (
            m.dev(),
            m.ino(),
            m.len(),
            m.uid(),
            m.gid(),
            m.mode(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
        )
    };
    ensure!(
        bytes.len() as u64 == m.len()
            && f::sha(&bytes) == b.sha256
            && id(&m) == id(&z)
            && id(&m) == id(&n),
        "ready receipt replaced/changed"
    );
    Ok(serde_json::from_slice(&bytes)?)
}
fn validate_ready(inventory: &Value, receipts: &[Value; 2], terminal: &Value) -> Result<()> {
    ensure!(
        inventory["schema"] == "jetstreamer-horizon-r2-inventory-v1"
            && inventory["first_epoch"] == 101
            && inventory["last_epoch"] == 200
            && inventory["requested_epochs"] == 100
            && inventory["anomalies"] == 0,
        "complete authenticated ready inventory differs"
    );
    let rows = inventory["entries"]
        .as_array()
        .context("ready inventory entries")?;
    ensure!(rows.len() == 100, "incomplete ready inventory");
    let mut epochs = std::collections::BTreeSet::new();
    for r in rows {
        let e = f::n(r, "epoch")?;
        ensure!(
            (101..=200).contains(&e) && epochs.insert(e),
            "duplicate/foreign inventory epoch"
        );
    }
    let members = terminal["canonical_batch"]["outcome"]["members"]
        .as_array()
        .context("original183 committed members")?;
    for (receipt, epoch) in receipts.iter().zip([183, 184]) {
        let matching = rows
            .iter()
            .filter(|r| r["epoch"] == epoch)
            .collect::<Vec<_>>();
        let committed = members
            .iter()
            .filter(|r| r["epoch"] == epoch)
            .collect::<Vec<_>>();
        ensure!(
            matching.len() == 1 && committed.len() == 1,
            "ready/committed183 membership differs"
        );
        let row = matching[0];
        let canonical = committed[0];
        ensure!(
            receipt["schema"] == "jetstreamer-horizon-r2-receipt-v1"
                && receipt["bucket"] == "solana-archive-with-accounts-data"
                && receipt["epoch"] == epoch
                && receipt["archive_key"] == format!("epoch-{epoch}.jet")
                && receipt["checksum_key"] == format!("epoch-{epoch}.jet.sha256")
                && receipt["remote_sha256_readback"] == true
                && f::n(receipt, "verified_unix_seconds")? > 0
                && row["state"] == "ready-pair"
                && receipt["archive_length"] == row["archive_length"]
                && receipt["archive_etag"] == row["archive_etag"]
                && receipt["archive_sha256"] == row["sidecar_sha256"]
                && row["sidecar_sha256"] == row["archive_metadata_sha256"]
                && row["sidecar_sha256"] == canonical["archive_sha256"]
                && row["archive_length"] == canonical["committed_archive"]["length"]
                && row["sidecar_sha256"]
                    .as_str()
                    .is_some_and(|s| f::hex(s, 64)),
            "old183 verified ready pair/source bytes differ"
        );
    }
    Ok(())
}

fn overlaps(first: u64, last: u64) -> bool {
    first <= last && first <= 184 && last >= 183
}
fn range_token(s: &str) -> bool {
    let s = s.trim_matches(|c: char| !c.is_ascii_digit() && c != '-');
    let p = s.split('-').collect::<Vec<_>>();
    match p.as_slice() {
        [one] => one.parse::<u64>().is_ok_and(|n| overlaps(n, n)),
        [first, last] => first
            .parse::<u64>()
            .ok()
            .zip(last.parse::<u64>().ok())
            .is_some_and(|(a, b)| overlaps(a, b)),
        _ => false,
    }
}
fn competing_argv(args: &[String]) -> bool {
    let image = args
        .first()
        .and_then(|a| Path::new(a).file_name())
        .and_then(|a| a.to_str())
        .unwrap_or("");
    let script = args
        .get(1)
        .and_then(|a| Path::new(a).file_name())
        .and_then(|a| a.to_str())
        .unwrap_or("");
    let producer = image == "jetstreamer-node"
        || image.contains("historical-worker")
        || script == "adaptive-root-cohort-sweep.py";
    if !producer {
        return false;
    }
    let mut first = None;
    let mut last = None;
    for (i, arg) in args.iter().enumerate().skip(1) {
        for (flag, target) in [("--first-epoch", &mut first), ("--last-epoch", &mut last)] {
            let value = arg.strip_prefix(&format!("{flag}=")).or_else(|| {
                (arg == flag)
                    .then(|| args.get(i + 1).map(String::as_str))
                    .flatten()
            });
            if let Some(value) = value {
                *target = value.parse::<u64>().ok();
            }
        }
    }
    if first.zip(last).is_some_and(|(a, b)| overlaps(a, b)) {
        return true;
    }
    args.iter().skip(1).any(|arg| {
        range_token(arg)
            || arg.contains("root-cohort-183-")
            || arg.contains("root-cohort-184-")
            || arg.contains("e183-184-full-20261023")
    })
}
fn competing_processes() -> Result<usize> {
    let mut inspected = 0;
    for proc in fs::read_dir("/proc")? {
        let proc = proc?;
        let name = proc.file_name();
        if !name
            .to_str()
            .is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
        {
            continue;
        }
        let path = proc.path();
        let read = |q: &Path| -> Result<Vec<u8>> {
            let mut b = Vec::new();
            File::open(q)?.take((1 << 20) + 1).read_to_end(&mut b)?;
            ensure!(b.len() <= 1 << 20, "bounded original183 process source");
            Ok(b)
        };
        let before = match read(&path.join("stat")) {
            Ok(b) => b,
            Err(e) if !path.exists() => {
                let _ = e;
                continue;
            }
            Err(e) => return Err(e),
        };
        let ticks = |raw: &[u8]| -> Result<u64> {
            Ok(std::str::from_utf8(raw)?
                .rsplit_once(')')
                .context("proc stat framing")?
                .1
                .split_whitespace()
                .nth(19)
                .context("proc start ticks")?
                .parse()?)
        };
        let bytes = match read(&path.join("cmdline")) {
            Ok(b) => b,
            Err(e) if !path.exists() => {
                let _ = e;
                continue;
            }
            Err(e) => return Err(e),
        };
        if bytes.is_empty() {
            let text = std::str::from_utf8(&before)?;
            let fields = text
                .rsplit_once(')')
                .context("empty proc stat")?
                .1
                .split_whitespace()
                .collect::<Vec<_>>();
            ensure!(
                fields.first() == Some(&"Z")
                    || fields
                        .get(6)
                        .and_then(|s| s.parse::<u64>().ok())
                        .is_some_and(|n| n & 0x20_0000 != 0),
                "live userspace process has no command"
            );
        } else {
            ensure!(bytes.last() == Some(&0), "unterminated process argv");
            let args = bytes[..bytes.len() - 1]
                .split(|b| *b == 0)
                .map(|b| Ok(std::str::from_utf8(b)?.to_owned()))
                .collect::<Result<Vec<String>>>()?;
            ensure!(
                !competing_argv(&args),
                "competing original183 scope process"
            );
        }
        match read(&path.join("stat")) {
            Ok(after) => ensure!(
                ticks(&before)? == ticks(&after)?,
                "PID reused across DATA claim census"
            ),
            Err(e) if !path.exists() => {
                let _ = e;
                continue;
            }
            Err(e) => return Err(e),
        };
        inspected += 1;
    }
    ensure!(inspected > 0, "empty original183 process census");
    Ok(inspected)
}

fn decode_native_jobs(v: &Value) -> Result<Value> {
    ensure!(
        v["type"] == "a(usssoo)",
        "original183 native ListJobs signature differs"
    );
    let returns = v["data"]
        .as_array()
        .context("original183 native ListJobs method returns")?;
    ensure!(
        returns.len() == 1,
        "original183 native ListJobs return count differs"
    );
    let jobs = returns[0]
        .as_array()
        .context("original183 native ListJobs job array")?;
    let mut rows = Vec::new();
    let mut ids = std::collections::BTreeSet::new();
    for value in jobs {
        let job = value
            .as_array()
            .context("original183 native ListJobs tuple")?;
        ensure!(
            job.len() == 6,
            "original183 native ListJobs tuple arity differs"
        );
        let id = job[0]
            .as_u64()
            .filter(|id| *id > 0 && *id <= u64::from(u32::MAX))
            .context("original183 native ListJobs job ID")?;
        let unit = job[1]
            .as_str()
            .filter(|unit| {
                !unit.is_empty()
                    && unit.len() <= 255
                    && !unit
                        .bytes()
                        .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
            })
            .context("original183 native ListJobs unit")?;
        let mut unit_object = String::from("/org/freedesktop/systemd1/unit/");
        for b in unit.bytes() {
            if b.is_ascii_alphanumeric() {
                unit_object.push(char::from(b));
            } else {
                unit_object.push_str(&format!("_{b:02x}"));
            }
        }
        ensure!(
            ids.insert(id)
                && job[2].as_str().is_some_and(|s| !s.is_empty())
                && matches!(job[3].as_str(), Some("waiting" | "running"))
                && job[4] == format!("/org/freedesktop/systemd1/job/{id}")
                && job[5] == unit_object,
            "original183 native ListJobs identity, state or object path differs"
        );
        rows.push(json!({"unit":unit}));
    }
    Ok(Value::Array(rows))
}

fn queued_claims() -> Result<Value> {
    let o = Command::new("/usr/bin/busctl")
        .args([
            "--system",
            "--json=short",
            "call",
            "org.freedesktop.systemd1",
            "/org/freedesktop/systemd1",
            "org.freedesktop.systemd1.Manager",
            "ListJobs",
        ])
        .env_remove("DBUS_SYSTEM_BUS_ADDRESS")
        .env_remove("DBUS_SESSION_BUS_ADDRESS")
        .env_remove("SYSTEMD_BUS_ADDRESS")
        .env_remove("SYSTEMD_HOST")
        .output()?;
    ensure!(
        o.status.success() && o.stdout.len() <= 1 << 20 && o.stderr.is_empty(),
        "bounded typed DATA Manager ListJobs failed"
    );
    let typed: Value = serde_json::from_slice(&o.stdout).context("typed Manager ListJobs JSON")?;
    let jobs = decode_native_jobs(&typed)?;
    let mut actual = Vec::new();
    for row in jobs.as_array().context("queued job array")? {
        let name = row["unit"].as_str().context("queued job unit")?;
        ensure!(
            name != PRODUCER
                && name != CONTROLLER
                && !name.starts_with('-')
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.@".contains(&b)),
            "original183 queued job or malformed alias"
        );
        let n = Command::new("/usr/bin/systemctl")
            .args([
                "--system",
                "show",
                name,
                "--no-pager",
                "--property=ExecStart,ExecStartPre,ExecStartPost",
            ])
            .output()?;
        ensure!(
            n.status.success() && n.stdout.len() <= 65536 && n.stderr.is_empty(),
            "queued DATA command census failed"
        );
        let text = std::str::from_utf8(&n.stdout)?;
        let words = text
            .split_whitespace()
            .map(|s| s.trim_matches(|c: char| "{};[]".contains(c)).to_owned())
            .collect::<Vec<_>>();
        let runtime = text.contains("jetstreamer-node")
            || text.contains("historical-worker")
            || text.contains("adaptive-root-cohort-sweep.py");
        ensure!(
            !runtime
                || !words
                    .iter()
                    .enumerate()
                    .any(|(i, _)| competing_argv(&words[i..]))
                    && !words.iter().any(|w| w.contains("root-cohort-183-")
                        || w.contains("root-cohort-184-")
                        || w.contains("e183-184-full-20261023")),
            "queued competing183 launch authority"
        );
        actual.push(json!({"unit":name,"actual_commands":text,"job":row}));
    }
    Ok(
        json!({"actual_jobs":actual,"raw_job_census_sha256":f::sha(&o.stdout),"actual_typed_Manager_ListJobs":typed}),
    )
}
fn closure_sources(p: &Policy) -> Result<(Value, Value)> {
    let old: legacy::Bound = serde_json::from_value(json!(p.terminal_legacy_closure))?;
    let proof = legacy::static_proof(&old)?;
    let closure = f::immutable(&p.terminal_legacy_closure)?;
    ensure!(
        closure["terminal183184"]
            == json!(Bound {
                path: TERMINAL.into(),
                sha256: TERMINAL_SHA.into()
            }),
        "original183 terminal source changed"
    );
    Ok((proof, closure))
}
/// Current typed constructor; never modifies raw accounting, archives or guards.
pub fn select(
    view: &VerifiedParentMemory,
    policy: &Bound,
    seal: &Bound,
    now: u64,
) -> Result<VerifiedData> {
    ensure!(
        view.selected_parent_retirement_bytes() == 192 << 30,
        "actual typed memory view required"
    );
    let p = registered(policy, seal)?;
    f::fresh(p.recorded_unix_seconds, now, 300)?;
    ensure!(
        json!(p.current) == view.evidence()["request"]["current"],
        "DATA and memory current tuples crossed"
    );
    let (_, closure) = closure_sources(&p)?;
    let prior = f::immutable(&f::bound(&closure["prior_memory"])?)?;
    let reader = f::immutable(&f::bound(&view.evidence()["request"]["current_reader"])?)?;
    let accounting = f::immutable(&f::bound(&reader["accounting"])?)?;
    ensure!(
        f::sha(&serde_json::to_vec(&accounting)?)
            == view.evidence()["raw_accounting_serde_json_sha256"],
        "DATA raw accounting differs from genuine memory reader"
    );
    let old: legacy::Bound = serde_json::from_value(json!(p.terminal_legacy_closure))?;
    legacy::minimum(&old, &accounting, &prior)?;
    let terminal = f::immutable(&Bound {
        path: TERMINAL.into(),
        sha256: TERMINAL_SHA.into(),
    })?;
    let inventory = f::immutable(&p.authenticated_inventory)?;
    let ready = [
        receipts(&p.ready_receipts[0])?,
        receipts(&p.ready_receipts[1])?,
    ];
    validate_ready(&inventory, &ready, &terminal)?;
    let before = native()?;
    let process_claims_before = competing_processes()?;
    let queued_before = queued_claims()?;
    let scan = process_references::scan(Path::new("/proc"), Path::new(ROOT))?;
    ensure!(
        scan.inspected_processes > 0 && scan.references.is_empty(),
        "old183 tree remains referenced; no future-growth closure"
    );
    let projection = projection::planning_projection(&accounting)?;
    let process_claims_after = competing_processes()?;
    let queued_after = queued_claims()?;
    let after = native()?;
    ensure!(
        before == after,
        "original183 authority changed across DATA selection"
    );
    ensure!(
        inventory == f::immutable(&p.authenticated_inventory)?
            && ready
                == [
                    receipts(&p.ready_receipts[0])?,
                    receipts(&p.ready_receipts[1])?
                ],
        "ready DATA sources changed during selection"
    );
    closure_sources(&p)?;
    let mut evidence = json!({"schema":"epoch183-current-typed-ended-growth-DATA-selection-v1","policy":policy,"policy_seal":seal,"current":p.current,
        "recorded_unix_seconds":now,"genuine_memory_view_evidence_sha256":f::sha(&serde_json::to_vec(view.evidence())?),
        "original_terminal_memory_proof_reused_only_as_source_authentication":true,"projection":projection,"native_before":before,"native_after":after,"process_reference_census":scan,"process_claims_before":process_claims_before,"process_claims_after":process_claims_after,"queued_before":queued_before,"queued_after":queued_after,
        "raw_accounting":reader["accounting"],"raw_accounting_unchanged":true,"all_other_growth_rows_and_guards_unchanged":true,
        "selected_ended_original183_future_growth_bytes":768u64<<30,"physical_credit_bytes":0,"memory_credit_bytes":0,
        "archive_retirement_authorized":false,"replay_launch_authorized":false,"admission_authorized":false});
    if let Some(context) = view.input_verification_context() {
        evidence["original199_input_verification_context"] = context.clone();
    }
    Ok(VerifiedData {
        raw_protected_bytes: f::n(&projection, "raw_protected_existing_DATA_bytes")?,
        effective_protected_bytes: f::n(&projection, "proposed_protected_existing_DATA_bytes")?,
        evidence,
    })
}

/// Running-guard continuity only: this type has no memory or DATA getters.
#[derive(Debug)]
pub struct GuardContinuity {
    _checked: (),
}
fn guard_shape(e: &Value, now: u64) -> Result<u64> {
    let at = f::n(e, "recorded_unix_seconds")?;
    ensure!(
        at > 0
            && at <= now
            && e["schema"] == "epoch183-current-typed-ended-growth-DATA-selection-v1"
            && e["raw_accounting_unchanged"] == true
            && e["all_other_growth_rows_and_guards_unchanged"] == true
            && e["selected_ended_original183_future_growth_bytes"] == 768u64 << 30
            && e["physical_credit_bytes"] == 0
            && e["memory_credit_bytes"] == 0
            && e["archive_retirement_authorized"] == false
            && e["replay_launch_authorized"] == false
            && e["admission_authorized"] == false
            && e["original_terminal_memory_proof_reused_only_as_source_authentication"] == true,
        "running guard DATA evidence scope or clock differs"
    );
    let _ = f::bound(&e["policy"])?;
    let _ = f::bound(&e["policy_seal"])?;
    ensure!(
        e["genuine_memory_view_evidence_sha256"]
            .as_str()
            .is_some_and(|s| f::hex(s, 64)),
        "guard memory evidence digest"
    );
    Ok(at)
}
/// Authenticate the accepted selection at its original clock and redo actual
/// original183 source/native/process/job/ready custody now. No fresh budget is returned.
pub fn revalidate_running_guard(e: &Value, memory: &Value, now: u64) -> Result<GuardContinuity> {
    let accepted = guard_shape(e, now)?;
    let request: horizon_original199_parent_memory::model::Request =
        serde_json::from_value(memory["request"].clone())?;
    let view = horizon_original199_parent_memory::admission_bridge::from_current_reader(
        &request, accepted,
    )?;
    selection_clock::validate(memory, view.evidence(), accepted)?;
    ensure!(
        f::sha(&serde_json::to_vec(view.evidence())?) == e["genuine_memory_view_evidence_sha256"],
        "guard DATA/memory selections crossed"
    );
    let current = select(
        &view,
        &f::bound(&e["policy"])?,
        &f::bound(&e["policy_seal"])?,
        accepted,
    )?;
    validate_guard_immutable_evidence(e, current.evidence())?;
    Ok(GuardContinuity { _checked: () })
}
fn validate_guard_immutable_evidence(e: &Value, current: &Value) -> Result<()> {
    for key in [
        "current",
        "policy",
        "policy_seal",
        "raw_accounting",
        "projection",
        "genuine_memory_view_evidence_sha256",
        "original199_input_verification_context",
        "raw_accounting_unchanged",
        "all_other_growth_rows_and_guards_unchanged",
        "selected_ended_original183_future_growth_bytes",
        "physical_credit_bytes",
        "memory_credit_bytes",
        "archive_retirement_authorized",
        "replay_launch_authorized",
        "admission_authorized",
    ] {
        ensure!(
            current[key] == e[key],
            "running guard DATA immutable evidence changed at {key}"
        );
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn terminal() -> Value {
        let mut v = serde_json::Map::new();
        for k in FIELDS
            .split(',')
            .filter(|k| !ABSENT_SERVICE_FIELDS.contains(k))
        {
            v.insert(k.into(), json!(""));
        }
        for (k, s) in [
            ("Id", PRODUCER),
            ("LoadState", "not-found"),
            ("MainPID", "0"),
            ("ControlPID", "0"),
            ("ActiveState", "inactive"),
            ("SubState", "dead"),
            ("Restart", "no"),
            ("Result", "success"),
            ("ExecMainStatus", "0"),
            ("NRestarts", "0"),
        ] {
            v.insert(k.into(), json!(s));
        }
        Value::Object(v)
    }
    fn continuity_fixture() -> Value {
        json!({"schema":"epoch183-current-typed-ended-growth-DATA-selection-v1","recorded_unix_seconds":100,
            "raw_accounting_unchanged":true,"all_other_growth_rows_and_guards_unchanged":true,
            "selected_ended_original183_future_growth_bytes":768u64<<30,"physical_credit_bytes":0,"memory_credit_bytes":0,
            "archive_retirement_authorized":false,"replay_launch_authorized":false,"admission_authorized":false,
            "original_terminal_memory_proof_reused_only_as_source_authentication":true,
            "policy":{"path":"/policy.json","sha256":"a".repeat(64)},"policy_seal":{"path":"/seal.json","sha256":"b".repeat(64)},
            "genuine_memory_view_evidence_sha256":"c".repeat(64)})
    }
    #[test]
    fn guard_continuity_preserves_complete_actual_residual_projection() {
        let raw: Value =
            serde_json::from_str(include_str!("../fixtures/actual0458-raw-accounting.json"))
                .unwrap();
        let mut original = continuity_fixture();
        original["projection"] = projection::planning_projection(&raw).unwrap();
        validate_guard_immutable_evidence(&original, &original).unwrap();
        for key in [
            "unchanged_conservative_residual_bytes",
            "reconstructed_before_protected_bytes",
            "proposed_growth_with_unchanged_residual_bytes",
            "confirmed_DATA_floor_bytes",
            "standing_frontier_bytes",
            "inherited_live_guard_maximum_bytes",
        ] {
            let mut changed = original.clone();
            changed["projection"][key] = json!(0);
            assert!(
                validate_guard_immutable_evidence(&original, &changed).is_err(),
                "{key}"
            );
        }
        let mut changed = original.clone();
        changed["projection"]["proposed_obligations"][0]["outstanding_bytes"] = json!(1);
        assert!(validate_guard_immutable_evidence(&original, &changed).is_err());
    }
    #[test]
    fn guard_continuity_keeps_explicit_original199_selection() {
        let legacy = continuity_fixture();
        validate_guard_immutable_evidence(&legacy, &legacy).unwrap();
        let mut selected = legacy.clone();
        selected["original199_input_verification_context"] =
            json!({"path":"/selected/context.json","sha256":"a".repeat(64)});
        validate_guard_immutable_evidence(&selected, &selected).unwrap();
        assert!(validate_guard_immutable_evidence(&selected, &legacy).is_err());
        assert!(validate_guard_immutable_evidence(&legacy, &selected).is_err());
        let mut crossed = selected.clone();
        crossed["original199_input_verification_context"]["sha256"] = json!("b".repeat(64));
        assert!(validate_guard_immutable_evidence(&selected, &crossed).is_err());
    }
    #[test]
    fn guard_continuity_acceptance_clock_never_grants_fresh_budget() {
        assert_eq!(guard_shape(&continuity_fixture(), 1000).unwrap(), 100);
        assert!(guard_shape(&continuity_fixture(), 99).is_err());
        let mut e = continuity_fixture();
        e["recorded_unix_seconds"] = json!(0);
        assert!(guard_shape(&e, 1000).is_err());
        assert!(revalidate_running_guard(&continuity_fixture(), &json!({}), 1000).is_err());
    }
    #[test]
    fn guard_continuity_rejects_credit_scope_authority_or_hash_changes() {
        for (key, value) in [
            ("raw_accounting_unchanged", json!(false)),
            ("physical_credit_bytes", json!(1)),
            ("memory_credit_bytes", json!(1)),
            ("selected_ended_original183_future_growth_bytes", json!(1)),
            ("admission_authorized", json!(true)),
            ("replay_launch_authorized", json!(true)),
            ("archive_retirement_authorized", json!(true)),
            ("genuine_memory_view_evidence_sha256", json!("bad")),
        ] {
            let mut e = continuity_fixture();
            e[key] = value;
            assert!(guard_shape(&e, 1000).is_err(), "{key}");
        }
    }
    #[test]
    fn actual_empty_manager_jobs_is_a_typed_array_not_empty_untyped_json() {
        let v: Value = serde_json::from_str(include_str!(
            "../fixtures/actual-empty-Manager-ListJobs.json"
        ))
        .unwrap();
        assert_eq!(decode_native_jobs(&v).unwrap(), json!([]));
        assert!(decode_native_jobs(&json!({})).is_err());
        assert!(decode_native_jobs(&json!({"type":"a(usssoo)","data":[]})).is_err());
    }
    #[test]
    fn queued_job_decoder_rejects_aliases_duplicates_and_malformed_shapes() {
        let row = json!([
            17,
            "other.service",
            "start",
            "waiting",
            "/org/freedesktop/systemd1/job/17",
            "/org/freedesktop/systemd1/unit/other_2eservice"
        ]);
        assert_eq!(
            decode_native_jobs(&json!({"type":"a(usssoo)","data":[[row.clone()]]})).unwrap(),
            json!([{"unit":"other.service"}])
        );
        assert!(
            decode_native_jobs(&json!({"type":"a(usssoo)","data":[[row.clone(),row.clone()]]}))
                .is_err()
        );
        for (index, value) in [
            (0, json!(0)),
            (1, json!("alias.service")),
            (3, json!("unknown")),
            (4, json!("/foreign")),
            (5, json!("/foreign")),
        ] {
            let mut changed = row.clone();
            changed[index] = value;
            assert!(decode_native_jobs(&json!({"type":"a(usssoo)","data":[[changed]]})).is_err());
        }
    }
    #[test]
    fn actual_collected_units_keep_service_property_absence_explicit() {
        let v: Value =
            serde_json::from_str(include_str!("../fixtures/actual-collected-unit.json")).unwrap();
        terminal_native(&v, PRODUCER).unwrap();
        assert_eq!(v.as_object().unwrap().len(), 19);
        for name in ABSENT_SERVICE_FIELDS {
            assert!(v.get(name).is_none());
            let mut changed = v.clone();
            changed[name] = json!("");
            assert!(terminal_native(&changed, PRODUCER).is_err(), "{name}");
        }
    }
    #[test]
    fn absence_of_any_real_unit_field_is_not_collected_service_absence() {
        let v: Value =
            serde_json::from_str(include_str!("../fixtures/actual-collected-unit.json")).unwrap();
        for key in v.as_object().unwrap().keys() {
            let mut changed = v.clone();
            changed.as_object_mut().unwrap().remove(key);
            assert!(terminal_native(&changed, PRODUCER).is_err(), "{key}");
        }
    }
    #[test]
    fn only_completely_collected_no_authority_original_is_accepted() {
        let v = terminal();
        terminal_native(&v, PRODUCER).unwrap();
        for (k, x) in [
            ("LoadState", "loaded"),
            ("InvocationID", "replacement"),
            ("MainPID", "10"),
            ("ControlPID", "12"),
            ("ControlGroup", "/foreign"),
            ("ActiveState", "active"),
            ("SubState", "running"),
            ("Restart", "always"),
            ("Result", "exit-code"),
            ("ExecMainStatus", "1"),
            ("Job", "99"),
            ("TriggeredBy", "future.timer"),
            ("Triggers", "future.service"),
            ("ExecStart", "node"),
            ("OnSuccess", "future.service"),
            ("DropInPaths", "/new.conf"),
        ] {
            let mut changed = v.clone();
            changed[k] = json!(x);
            assert!(terminal_native(&changed, PRODUCER).is_err(), "{k}");
        }
    }
    #[test]
    fn exact_scope_and_spanning_replay_ranges_are_competing() {
        let words = |a: &[&str]| a.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        for a in [
            vec!["/sealed/jetstreamer-node", "183-184", "out"],
            vec!["/sealed/jetstreamer-node", "100-200", "out"],
            vec!["/sealed/jetstreamer-node", "184", "out"],
            vec![
                "python3",
                "/sealed/adaptive-root-cohort-sweep.py",
                "--first-epoch=101",
                "--last-epoch=200",
            ],
            vec![
                "python3",
                "/sealed/adaptive-root-cohort-sweep.py",
                "--first-epoch",
                "183",
                "--last-epoch",
                "184",
            ],
            vec!["/sealed/historical-worker", "/private/root-cohort-183-184"],
        ] {
            assert!(competing_argv(&words(&a)));
        }
        for a in [
            vec!["/sealed/jetstreamer-node", "145", "out"],
            vec!["/sealed/jetstreamer-node", "199-200", "out"],
            vec!["/sealed/data183-probe", "183-184"],
            vec!["python3", "/source/prepare183.py"],
        ] {
            assert!(!competing_argv(&words(&a)));
        }
    }
    fn actual_ready() -> (Value, [Value; 2], Value) {
        (
            serde_json::from_str(include_str!("../fixtures/inventory0358.json")).unwrap(),
            [
                serde_json::from_str(include_str!("../fixtures/epoch183-r2.json")).unwrap(),
                serde_json::from_str(include_str!("../fixtures/epoch184-r2.json")).unwrap(),
            ],
            serde_json::from_str(include_str!("../fixtures/terminal183184.json")).unwrap(),
        )
    }
    #[test]
    fn genuine_ready_inventory_matches_both_original_committed_members() {
        let (i, r, t) = actual_ready();
        validate_ready(&i, &r, &t).unwrap();
    }
    #[test]
    fn incomplete_duplicate_or_staged_ready_evidence_is_rejected() {
        let (i, r, t) = actual_ready();
        for mutate in 0..4 {
            let mut v = i.clone();
            match mutate {
                0 => {
                    v["entries"].as_array_mut().unwrap().pop();
                }
                1 => {
                    let row = v["entries"][0].clone();
                    v["entries"][1] = row;
                }
                2 => {
                    v["entries"]
                        .as_array_mut()
                        .unwrap()
                        .iter_mut()
                        .find(|x| x["epoch"] == 183)
                        .unwrap()["state"] = json!("archive-only");
                }
                _ => {
                    v["anomalies"] = json!(1);
                }
            }
            assert!(validate_ready(&v, &r, &t).is_err());
        }
    }
    #[test]
    fn readback_bucket_key_hash_length_and_original_source_are_all_required() {
        let (i, r, t) = actual_ready();
        for (k, v) in [
            ("remote_sha256_readback", json!(false)),
            ("bucket", json!("foreign")),
            ("epoch", json!(184)),
            ("archive_key", json!("alias")),
            ("checksum_key", json!("alias")),
            ("archive_sha256", json!("0".repeat(64))),
            ("archive_length", json!(1)),
            ("archive_etag", json!("foreign")),
        ] {
            let mut changed = r.clone();
            changed[0][k] = v;
            assert!(validate_ready(&i, &changed, &t).is_err(), "{k}");
        }
        let mut t = t;
        t["canonical_batch"]["outcome"]["members"][0]["archive_sha256"] = json!("f".repeat(64));
        assert!(validate_ready(&i, &r, &t).is_err());
    }
}
