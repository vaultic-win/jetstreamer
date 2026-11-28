//! Close only the historical 152/155/183 replay hard-cap minimum.
//! Current RSS/kernel/caps, pools, guards and all DATA claims stay independent.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::PathBuf,
    process::Command,
};

pub const OLD_MINIMUM: u64 = 616_673_574_912;
pub const CLOSED_HARD_CAPS: u64 = 352_187_318_272;
pub const NEW_MINIMUM: u64 = 264_486_256_640;
pub const CLOSURE_PATH: &str =
    "/usr/local/lib/jetstreamer/horizon-terminal-legacy-memory-closure-20261030-v1/closure.json";
pub const PRIOR_SHA: &str = "7b6e9a72fe89964d94ba22afe2a5320ed9ae401d2a624eaa01be9a57c772568a";
const PRODUCERS: [(&str, &str, u64, u64, u64); 3] = [
    (
        "jetstreamer-root-sweep-e152-153-t3-20261014-v1-r2-e152-153-lane-l-1.service",
        "1a7e8cde872b45f786979150d5639ab4",
        68u64 << 30,
        152,
        153,
    ),
    (
        "jetstreamer-root-sweep-e155-156-t3-20261014-v1-r2-e155-156-lane-m-1.service",
        "518ff0bf0bbb4413a155a63f95907163",
        68u64 << 30,
        155,
        156,
    ),
    (
        "jetstreamer-root-sweep-e183-184-full-20261023-v2-r2-e183-184-lane-a-1.service",
        "489e219d38d14d4594d8649ff698f666",
        192u64 << 30,
        183,
        184,
    ),
];
const CONTROLLERS: [(&str, &str); 3] = [
    (
        "jetstreamer-epochs152-153-target3-controller-v1-r2.service",
        "4b6e30004fcf4d34a2d6b98568f3ab1a",
    ),
    (
        "jetstreamer-epochs155-156-target3-controller-v1-r2.service",
        "5c0c6dc3faa14a6d8a639af8a1c76774",
    ),
    (
        "jetstreamer-epochs183-184-readerfix-full-20261023-controller-v2-r2.service",
        "a4a903998b45470a9315861f986a2b1d",
    ),
];
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Bound {
    pub path: PathBuf,
    pub sha256: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ClosedPromise {
    unit: String,
    invocation_id: String,
    memory_max_bytes: u64,
    first_epoch: u64,
    last_epoch: u64,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Closure {
    schema: String,
    prior_memory: Bound,
    success152: Bound,
    batch152: Bound,
    journal155156: Bound,
    batch155156: Bound,
    closure155156: Bound,
    terminal183184: Bound,
    closed_promises: Vec<ClosedPromise>,
    previous_minimum_bytes: u64,
    closed_historical_hard_caps_bytes: u64,
    replacement_minimum_bytes: u64,
    pools_preserved: bool,
    current_dynamic_memory_recalculation_required: bool,
    physical_free_space_credit_bytes: u64,
    data_credit_bytes: u64,
    guard_changes: bool,
    replay_launch_authorized: bool,
    publication_authorized: bool,
    r2_mutations: bool,
}
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn is_sha(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn raw(b: &Bound) -> Result<Vec<u8>> {
    ensure!(
        is_sha(&b.sha256) && b.path.is_absolute() && b.path.canonicalize()? == b.path,
        "terminal memory evidence path/digest differs"
    );
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(&b.path)?;
    let first = f.metadata()?;
    let identity = |m: &fs::Metadata| {
        (
            m.dev(),
            m.ino(),
            m.len(),
            m.uid(),
            m.mode(),
            m.nlink(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
        )
    };
    ensure!(
        first.is_file()
            && first.uid() == 0
            && first.mode() & 0o222 == 0
            && first.nlink() == 1
            && first.len() > 0
            && first.len() <= 16 << 20,
        "terminal memory evidence custody differs"
    );
    let mut bytes = Vec::new();
    (&mut f).take((16 << 20) + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == first.len()
            && hash(&bytes) == b.sha256
            && identity(&first) == identity(&f.metadata()?)
            && identity(&first) == identity(&fs::symlink_metadata(&b.path)?),
        "terminal memory evidence changed"
    );
    Ok(bytes)
}
fn value(b: &Bound) -> Result<Value> {
    Ok(serde_json::from_slice(&raw(b)?)?)
}
fn exact_proofs(c: &Closure) -> Result<()> {
    for (b, sha) in [
        (&c.prior_memory, PRIOR_SHA),
        (
            &c.success152,
            "555a47d0a10e70e2c1a8601c603c86621b9f7756589613d7f8499f982e14fd90",
        ),
        (
            &c.batch152,
            "5530f897ff89c325749edac919de4c778e4851312fd2ee674af01373c7dcca59",
        ),
        (
            &c.journal155156,
            "da7c2f7ba70aa93952433f84736e5a493d5e2a5685abb2c8226ee1391250540b",
        ),
        (
            &c.batch155156,
            "71dc88b303e9aa2c6d7f2e8410da6c012468c058a7df4abf7e8fdc62c56a1452",
        ),
        (
            &c.closure155156,
            "f4ca21d29d65afc69c9aa26b8f97b08f35ee89a2612c51bf392c607c0f64914e",
        ),
        (
            &c.terminal183184,
            "5d0fcb753e3b2b984958657a2cee8e3eea7c6000bd6c375ba68aa8793dc14395",
        ),
    ] {
        ensure!(b.sha256 == sha, "terminal memory proof binding changed");
    }
    Ok(())
}
fn shape(c: &Closure, prior: &Value) -> Result<()> {
    ensure!(
        c.schema == "jetstreamer-terminal-legacy-memory-closure-v1"
            && c.previous_minimum_bytes == OLD_MINIMUM
            && c.closed_historical_hard_caps_bytes == CLOSED_HARD_CAPS
            && c.replacement_minimum_bytes == NEW_MINIMUM
            && c.previous_minimum_bytes
                .checked_sub(c.closed_historical_hard_caps_bytes)
                == Some(c.replacement_minimum_bytes)
            && c.pools_preserved
            && c.current_dynamic_memory_recalculation_required
            && c.physical_free_space_credit_bytes == 0
            && c.data_credit_bytes == 0
            && !c.guard_changes
            && !c.replay_launch_authorized
            && !c.publication_authorized
            && !c.r2_mutations,
        "terminal memory closure authority/arithmetic differs"
    );
    exact_proofs(c)?;
    ensure!(
        prior["schema"] == "jetstreamer-epoch186-small64-memory160-admission-facts-v2"
            && prior["protected_existing_reservation_bytes"] == OLD_MINIMUM
            && prior["existing_pools_bytes"]["replay_hard_caps"] == CLOSED_HARD_CAPS,
        "terminal memory prior generation differs"
    );
    for (key, bytes) in [
        ("plugin128GiB", 128u64 << 30),
        ("compiler_and_native16GiB", 16u64 << 30),
        ("shared64GiB", 64u64 << 30),
        ("cadence_maintainer512MiB", 512u64 << 20),
    ] {
        ensure!(
            prior["existing_pools_bytes"][key] == bytes,
            "terminal memory pool promise changed:{key}"
        );
    }
    ensure!(
        c.closed_promises.len() == PRODUCERS.len(),
        "terminal memory closure must name all three exact original promises once"
    );
    let mut seen = BTreeSet::new();
    let mut total = 0u64;
    for row in &c.closed_promises {
        ensure!(
            seen.insert(row.unit.as_str()),
            "duplicate terminal memory credit"
        );
        let expected = PRODUCERS
            .iter()
            .find(|r| r.0 == row.unit)
            .context("unrelated terminal memory credit")?;
        ensure!(
            (
                row.invocation_id.as_str(),
                row.memory_max_bytes,
                row.first_epoch,
                row.last_epoch
            ) == (expected.1, expected.2, expected.3, expected.4),
            "terminal memory promise changed"
        );
        let old = prior["live_owner_identity_and_caps"]
            .as_array()
            .context("missing historical hard cap census")?
            .iter()
            .filter(|o| o["Id"] == row.unit)
            .collect::<Vec<_>>();
        ensure!(
            old.len() == 1
                && old[0]["InvocationID"] == row.invocation_id
                && old[0]["NRestarts"] == "0"
                && old[0]["MemoryMax"]
                    .as_str()
                    .and_then(|s| s.parse::<u64>().ok())
                    == Some(row.memory_max_bytes),
            "terminal memory credit not bound to prior native cap"
        );
        total = total
            .checked_add(row.memory_max_bytes)
            .context("terminal memory cap sum overflow")?;
    }
    ensure!(total == CLOSED_HARD_CAPS, "terminal memory cap sum differs");
    Ok(())
}
fn rows(bytes: &[u8]) -> Result<Vec<Value>> {
    ensure!(bytes.len() <= 1 << 20, "terminal memory journal too large");
    let result = std::str::from_utf8(bytes)?
        .lines()
        .filter(|s| !s.is_empty())
        .map(serde_json::from_str)
        .collect::<std::result::Result<Vec<Value>, _>>()?;
    ensure!(
        !result.is_empty() && result.len() <= 1024,
        "terminal memory journal census differs"
    );
    Ok(result)
}
fn success(rows: &[Value], unit: &str, iid: &str) -> Result<()> {
    let exact = rows
        .iter()
        .filter(|r| r["UNIT"] == unit && r["INVOCATION_ID"] == iid)
        .collect::<Vec<_>>();
    let terminal = exact
        .iter()
        .filter(|r| r["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448")
        .collect::<Vec<_>>();
    ensure!(
        terminal.len() == 1,
        "terminal memory needs exactly one genuine terminal success"
    );
    let r = terminal[0];
    ensure!(
        r["_PID"] == "1"
            && r["_UID"] == "0"
            && r["_EXE"] == "/usr/lib/systemd/systemd"
            && r["MESSAGE"] == format!("{unit}: Deactivated successfully.")
            && r["__REALTIME_TIMESTAMP"]
                .as_str()
                .and_then(|n| n.parse::<u64>().ok())
                .is_some_and(|n| n > 0),
        "terminal memory PID1 success identity differs"
    );
    ensure!(
        !exact
            .iter()
            .any(|r| r["MESSAGE_ID"] == "be02cf6855d2428ba40df7e9d022f03d"
                || r["MESSAGE"]
                    .as_str()
                    .is_some_and(|s| s.contains("Failed with result"))),
        "terminal memory journal also reports failure"
    );
    Ok(())
}
fn batch(v: &Value, epochs: [u64; 2], tx: &str, last: u64) -> Result<()> {
    ensure!(
        v["schema"] == "jetstreamer-root-cohort-publication-receipt-v2"
            && v["transaction_id"] == tx
            && v["epochs"] == json!(epochs)
            && v["outcome"]["kind"] == "committed"
            && v["root_checkpoint_gate"]["kind"] == "sealed-root-checkpoint-cohort"
            && v["root_checkpoint_gate"]["members"][1]["terminal"]["slot"] == last,
        "terminal memory source batch is not the exact committed cohort"
    );
    let members = v["outcome"]["members"]
        .as_array()
        .context("terminal memory committed members absent")?;
    ensure!(
        members.len() == 2
            && members
                .iter()
                .map(|v| v["epoch"].as_u64())
                .eq(epochs.into_iter().map(Some)),
        "terminal memory batch member census differs"
    );
    Ok(())
}
fn source_proofs(c: &Closure) -> Result<Value> {
    let prior = value(&c.prior_memory)?;
    shape(c, &prior)?;
    success(&rows(&raw(&c.success152)?)?, PRODUCERS[0].0, PRODUCERS[0].1)?;
    batch(
        &value(&c.batch152)?,
        [152, 153],
        "2810e5410a03a8be16f97ed055e7f78a89d1001ca99579f320e8c554a5cff3c9",
        66527999,
    )?;
    let j155 = rows(&raw(&c.journal155156)?)?;
    success(&j155, PRODUCERS[1].0, PRODUCERS[1].1)?;
    success(&j155, CONTROLLERS[1].0, CONTROLLERS[1].1)?;
    batch(
        &value(&c.batch155156)?,
        [155, 156],
        "69567fec575bffea6d6cbe7bcada1e101c8ba0f1aed97e3a46823d415a172c31",
        67823999,
    )?;
    let closure = value(&c.closure155156)?;
    ensure!(
        closure["schema"] == "jetstreamer-terminal155156-future-growth-closure-v1"
            && closure["retained_artifacts_unchanged"] == true
            && closure["physical_free_space_credit_bytes"] == 0
            && closure["guard_changes"] == false
            && closure["projection"]["producer_invocation_id"] == PRODUCERS[1].1
            && closure["replay_launch_authorized"] == false
            && closure["admission_authorized"] == false,
        "terminal memory 155 source closure differs"
    );
    let t183 = value(&c.terminal183184)?;
    ensure!(
        t183["schema"] == "jetstreamer-cohort183-canonical-import-handoff-v1"
            && t183["import_complete"] == true
            && t183["replay_finished"] == true
            && t183["resource_credit_bytes"] == 0
            && t183["replay_launch_authorized"] == false
            && t183["publication_authorized"] == false
            && t183["r2_mutations"] == false,
        "terminal memory 183 handoff differs"
    );
    success(
        &[t183["producer_terminal_manager"].clone()],
        PRODUCERS[2].0,
        PRODUCERS[2].1,
    )?;
    success(
        &[t183["controller_terminal_manager"].clone()],
        CONTROLLERS[2].0,
        CONTROLLERS[2].1,
    )?;
    for (key, transaction) in [
        (
            "source_batch",
            "1e009cb9b1bbf09e1211769f8964e925364d56f2cc60a10de39df2666647bec8",
        ),
        (
            "canonical_batch",
            "4615a4858539575a8e3e76cddb74e03da38b1fe1af239528175fdb59e1aeeb44",
        ),
    ] {
        batch(&t183[key], [183, 184], transaction, 79919999)?;
    }
    Ok(prior)
}

fn same_native_snapshot(name: &str, basic: &Value, detailed: &Value) -> Result<()> {
    let basic = basic
        .as_object()
        .context("terminal memory ordinary native snapshot missing")?;
    ensure!(
        basic.get("Id").and_then(Value::as_str) == Some(name) && detailed["Id"] == name,
        "terminal memory native enrichment unit differs"
    );
    for field in [
        "Id",
        "LoadState",
        "Type",
        "ActiveState",
        "SubState",
        "MainPID",
        "ControlGroup",
        "InvocationID",
        "NRestarts",
        "Result",
        "ExecMainStatus",
    ] {
        ensure!(
            basic.get(field).and_then(Value::as_str).is_some(),
            "terminal memory ordinary native field missing: {name}:{field}"
        );
    }
    // Compare every original field, including any later addition to the
    // ordinary census. A second query cannot replace its identity or state.
    for (field, value) in basic {
        ensure!(
            detailed.get(field) == Some(value),
            "terminal memory native changed during enrichment: {name}:{field}"
        );
    }
    for field in ["TriggeredBy", "Triggers", "ControlPID", "Job"] {
        ensure!(
            detailed[field].is_string(),
            "terminal memory genuine native control/trigger field missing: {name}:{field}"
        );
    }
    Ok(())
}

fn read_native_snapshot(name: &str, basic: &Value) -> Result<Value> {
    let mut fields = basic
        .as_object()
        .context("terminal memory ordinary native object missing")?
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    fields.extend(["TriggeredBy", "Triggers", "ControlPID", "Job"]);
    ensure!(
        fields
            .iter()
            .all(|field| !field.is_empty() && field.bytes().all(|c| c.is_ascii_alphanumeric())),
        "terminal memory malformed native property name"
    );
    let selector = format!(
        "--property={}",
        fields.into_iter().collect::<Vec<_>>().join(",")
    );
    let output = Command::new("/usr/bin/systemctl")
        .args(["show", name, "--no-pager", &selector])
        .output()?;
    ensure!(
        output.stdout.len() <= 1 << 20,
        "terminal memory native snapshot exceeds bound"
    );
    let mut values = serde_json::Map::new();
    for line in std::str::from_utf8(&output.stdout)?.lines() {
        let (field, value) = line
            .split_once('=')
            .context("terminal memory malformed native property")?;
        ensure!(
            values.insert(field.into(), json!(value)).is_none(),
            "terminal memory duplicate genuine native property"
        );
    }
    let detailed = Value::Object(values);
    ensure!(
        detailed["Id"] == name
            && (output.status.success()
                || (detailed["LoadState"] == "not-found" && detailed["MainPID"] == "0")),
        "terminal memory genuine native query failed"
    );
    Ok(detailed)
}

fn enrich_native_census_with(
    native: &mut BTreeMap<String, Value>,
    mut read: impl FnMut(&str, &Value) -> Result<Value>,
) -> Result<()> {
    let mut enriched = Vec::new();
    for name in PRODUCERS
        .iter()
        .map(|r| r.0)
        .chain(CONTROLLERS.iter().map(|r| r.0))
    {
        let basic = native
            .get(name)
            .context("terminal memory closed unit omitted from complete census")?;
        let detailed = read(name, basic)?;
        same_native_snapshot(name, basic, &detailed)?;
        enriched.push((name.to_owned(), detailed));
    }
    // Publish no partial replacement if any identity/state comparison fails.
    for (name, detailed) in enriched {
        native.insert(name, detailed);
    }
    Ok(())
}

/// Collect real trigger/control/job fields for precisely the six historical
/// closure units in each complete accounting pass. This does not assert that
/// any unit is drained, close a promise, select a minimum or authorize work.
pub fn enrich_native_census(native: &mut BTreeMap<String, Value>) -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "terminal memory native census requires root"
    );
    enrich_native_census_with(native, read_native_snapshot)
}

// Keep whole-JSON ordinary coordinator validation ahead of the additive fields.
// This ordering is shared by both complete accounting passes and tested with
// the real recovered-frame completion/fleet pairing below.
fn compare_then_enrich_with(
    native: &mut BTreeMap<String, Value>,
    compare: impl FnOnce(&BTreeMap<String, Value>) -> Result<Value>,
    enrich: impl FnOnce(&mut BTreeMap<String, Value>) -> Result<()>,
) -> Result<Value> {
    let coordinator = compare(native)?;
    enrich(native)?;
    Ok(coordinator)
}

/// Preserve strict ordinary comparison, then retain every genuinely collected
/// control/trigger/job field in the complete before/after accounting basis.
pub fn compare_then_enrich_native_census(
    native: &mut BTreeMap<String, Value>,
    compare: impl FnOnce(&BTreeMap<String, Value>) -> Result<Value>,
) -> Result<Value> {
    compare_then_enrich_with(native, compare, enrich_native_census)
}

fn drained(v: &Value, unit: &str, old_iid: &str) -> Result<()> {
    ensure!(
        v["Id"] == unit
            && matches!(v["LoadState"].as_str(), Some("loaded" | "not-found"))
            && v["MainPID"] == "0"
            && v["NRestarts"] == "0"
            && v["ControlGroup"] == ""
            && v["Result"] == "success"
            && v["ExecMainStatus"] == "0"
            && ((v["ActiveState"] == "inactive" && v["SubState"] == "dead")
                || (v["ActiveState"] == "active" && v["SubState"] == "exited"))
            && v["InvocationID"]
                .as_str()
                .is_some_and(|s| s.is_empty() || s == old_iid),
        "terminal memory old owner is live, failed, restarted or replaced:{unit}"
    );
    for key in ["TriggeredBy", "Triggers"] {
        ensure!(
            v[key].as_str() == Some(""),
            "terminal memory old owner remains triggerable:{unit}"
        );
    }
    ensure!(
        v["ControlPID"] == "0" && matches!(v["Job"].as_str(), Some("" | "0")),
        "terminal memory old owner has a missing or outstanding control/job:{unit}"
    );
    Ok(())
}
fn current(b: &Value) -> Result<()> {
    ensure!(
        b["schema"] == "jetstreamer-current-protected-data-accounting-v1"
            && b["new_allocation_authorized"] == false
            && b["physical_retirement_credit_bytes"] == 0,
        "terminal memory needs complete current accounting"
    );
    for end in ["before", "after"] {
        let native = b[format!("native_{end}")]
            .as_object()
            .context("terminal memory complete native census absent")?;
        let discovery = b[format!("workload_discovery_{end}")]
            .as_object()
            .context("terminal memory workload discovery absent")?;
        for (unit, iid) in PRODUCERS.iter().map(|r| (r.0, r.1)).chain(CONTROLLERS) {
            drained(
                native
                    .get(unit)
                    .context("terminal memory old owner omitted from census")?,
                unit,
                iid,
            )?;
            ensure!(
                !discovery.contains_key(unit),
                "terminal memory old owner still discovered live"
            );
        }
    }
    ensure!(
        super::epoch186::accounting::terminal_memory_discovery_stable(b)?,
        "terminal memory workload discovery changed"
    );
    for owner in b["current_unique_owner_census"]
        .as_array()
        .context("terminal memory complete owner claims absent")?
    {
        let role = owner["role"]
            .as_str()
            .context("terminal memory owner role absent")?;
        ensure!(
            [
                "replay-producer",
                "replay-controller",
                "diagnostic-replay",
                "delivery",
                "repair",
                "native-park"
            ]
            .contains(&role),
            "terminal memory unknown owner role"
        );
        if ["replay-producer", "replay-controller", "diagnostic-replay"].contains(&role) {
            let first = owner["first_epoch"]
                .as_u64()
                .context("terminal memory owner start absent")?;
            let last = owner["last_epoch"]
                .as_u64()
                .context("terminal memory owner end absent")?;
            ensure!(
                first <= last && !PRODUCERS.iter().any(|p| first <= p.4 && last >= p.3),
                "terminal memory replacement replay overlaps a closed scope"
            );
        }
    }
    Ok(())
}
/// Verify immutable old terminal/import sources only. No native/resource polling.
pub fn static_proof(bound: &Bound) -> Result<Value> {
    ensure!(
        bound.path.as_path() == std::path::Path::new(CLOSURE_PATH),
        "unreviewed terminal memory closure namespace"
    );
    let closure: Closure = serde_json::from_slice(&raw(bound)?)?;
    source_proofs(&closure)?;
    Ok(
        json!({"schema":"jetstreamer-terminal-legacy-memory-static-proof-v1","closure":bound,
        "previous_minimum_bytes":OLD_MINIMUM,"closed_historical_hard_caps_bytes":CLOSED_HARD_CAPS,"replacement_minimum_bytes":NEW_MINIMUM,
        "genuine_terminal_and_committed_batch_sources_validated":true,"fresh_current_accounting_still_required":true,
        "physical_free_space_credit_bytes":0,"data_credit_bytes":0,"guard_changes":false,"replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false}),
    )
}
/// Only the max-with-history minimum changes. Caller retains its full dynamic sum.
pub fn minimum(bound: &Bound, basis: &Value, prior: &Value) -> Result<u64> {
    static_proof(bound)?;
    let closure: Closure = serde_json::from_slice(&raw(bound)?)?;
    shape(&closure, prior)?;
    current(basis)?;
    Ok(NEW_MINIMUM)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn success_row(unit: &str, iid: &str) -> Value {
        json!({"UNIT":unit,"INVOCATION_ID":iid,"_PID":"1","_UID":"0","_EXE":"/usr/lib/systemd/systemd","MESSAGE_ID":"7ad2d189f7e94e70a38c781354912448","MESSAGE":format!("{unit}: Deactivated successfully."),"__REALTIME_TIMESTAMP":"1000"})
    }
    fn basis() -> Value {
        let mut native = serde_json::Map::new();
        for (unit, iid) in PRODUCERS.iter().map(|p| (p.0, p.1)).chain(CONTROLLERS) {
            native.insert(unit.into(),json!({"Id":unit,"LoadState":"not-found","MainPID":"0","NRestarts":"0","ControlGroup":"","Result":"success","ExecMainStatus":"0","ActiveState":"inactive","SubState":"dead","InvocationID":iid,"TriggeredBy":"","Triggers":"","ControlPID":"0","Job":""}));
        }
        json!({"schema":"jetstreamer-current-protected-data-accounting-v1","new_allocation_authorized":false,"physical_retirement_credit_bytes":0,"native_before":native,"native_after":native,"workload_discovery_before":{},"workload_discovery_after":{},"current_unique_owner_census":[{"role":"delivery","first_epoch":184,"last_epoch":184},{"role":"repair","first_epoch":141,"last_epoch":141}]})
    }
    fn ordinary_native() -> BTreeMap<String, Value> {
        let mut result = BTreeMap::new();
        for (name, value) in basis()["native_before"].as_object().unwrap() {
            let mut value = value.clone();
            for field in ["TriggeredBy", "Triggers", "ControlPID", "Job"] {
                value.as_object_mut().unwrap().remove(field);
            }
            value["Type"] = json!("");
            result.insert(name.clone(), value);
        }
        result
    }
    fn detailed_native(basic: &Value) -> Value {
        let mut result = basic.clone();
        for (field, value) in [
            ("TriggeredBy", ""),
            ("Triggers", ""),
            ("ControlPID", "0"),
            ("Job", ""),
        ] {
            result[field] = json!(value);
        }
        result
    }

    fn ordinary2048_fixture() -> Value {
        serde_json::from_str(include_str!(
            "fixtures/terminal-legacy-memory-ordinary2048-census.json"
        ))
        .unwrap()
    }
    fn ordinary2048_native(fixture: &Value) -> BTreeMap<String, Value> {
        serde_json::from_value(fixture["ordinary_six_unit_census"].clone()).unwrap()
    }
    fn compare_ordinary2048(fixture: &Value, native: &BTreeMap<String, Value>) -> Result<Value> {
        let completion = serde_json::from_value(fixture["original_completion_binding"].clone())?;
        let fleet = serde_json::from_value(fixture["ordinary_fleet_binding"].clone())?;
        crate::completed_coordinator::compare_census(
            &completion,
            &fixture["original_completion"],
            &fleet,
            &fixture["ordinary_fleet"],
            fixture["ordinary_six_unit_census"].as_object().unwrap(),
            native,
        )
    }
    // ControlPID/Job are projected from the genuine frame. Trigger strings are
    // explicitly injected test values, not a claim about an unrecorded native
    // snapshot. The ignored root test below uses the real reader instead.
    fn detailed2048_fixture(fixture: &Value, name: &str, basic: &Value) -> Value {
        let mut detailed = basic.clone();
        for source in [
            &fixture["recorded_frame_control_fields"][name],
            &fixture["test_only_trigger_fields"],
        ] {
            for (key, value) in source.as_object().unwrap() {
                detailed[key] = value.clone();
            }
        }
        detailed
    }
    fn closure_basis_from_native(native: &BTreeMap<String, Value>) -> Value {
        let mut complete = basis();
        complete["native_before"] = serde_json::to_value(native).unwrap();
        complete["native_after"] = serde_json::to_value(native).unwrap();
        complete
    }

    #[test]
    fn ordinary2048_comparison_precedes_enrichment_and_both_bases_retain_every_field() {
        let fixture = ordinary2048_fixture();
        assert_ne!(
            fixture["original_completion"]["fleet"], fixture["ordinary_fleet_binding"],
            "the real recovered lineage must not be replaced by a same-cycle fixture"
        );
        let mut complete = basis();
        for end in ["before", "after"] {
            let mut native = ordinary2048_native(&fixture);
            let ordinary = native.clone();
            let mut queried = BTreeSet::new();
            let proof = compare_then_enrich_with(
                &mut native,
                |raw| compare_ordinary2048(&fixture, raw),
                |raw| {
                    enrich_native_census_with(raw, |name, basic| {
                        assert!(queried.insert(name.to_owned()));
                        Ok(detailed2048_fixture(&fixture, name, basic))
                    })
                },
            )
            .unwrap();
            assert!(proof.is_null());
            assert_eq!(queried.len(), 6);
            for (name, original) in &ordinary {
                for (key, value) in original.as_object().unwrap() {
                    assert_eq!(&native[name][key], value);
                }
                for field in ["TriggeredBy", "Triggers", "ControlPID", "Job"] {
                    assert!(native[name][field].is_string(), "{end}:{name}:{field}");
                }
            }
            complete[format!("native_{end}")] = serde_json::to_value(&native).unwrap();
            // The prior A2 ordering is an explicit counterexample: adding the
            // four fields before whole-object comparison cannot be unchanged.
            assert!(
                crate::completed_coordinator::verify_ordinary_census_for_test(
                    fixture["ordinary_six_unit_census"].as_object().unwrap(),
                    &native,
                )
                .is_err()
            );
        }
        current(&complete).unwrap();
    }

    #[test]
    fn original_native_field_drift_rejects_before_any_enrichment() {
        let fixture = ordinary2048_fixture();
        for (field, changed) in [
            ("Id", "foreign.service"),
            ("InvocationID", "foreign"),
            ("MainPID", "42"),
            ("NRestarts", "1"),
            ("ActiveState", "active"),
            ("ControlGroup", "/foreign"),
            ("Result", "exit-code"),
        ] {
            let mut native = ordinary2048_native(&fixture);
            native.get_mut(CONTROLLERS[2].0).unwrap()[field] = json!(changed);
            let before = native.clone();
            let mut enrichment_called = false;
            let result = compare_then_enrich_with(
                &mut native,
                |raw| {
                    crate::completed_coordinator::verify_ordinary_census_for_test(
                        fixture["ordinary_six_unit_census"].as_object().unwrap(),
                        raw,
                    )?;
                    Ok(Value::Null)
                },
                |_| {
                    enrichment_called = true;
                    Ok(())
                },
            );
            assert!(result.is_err(), "{field}");
            assert!(!enrichment_called, "{field}");
            assert_eq!(native, before, "{field}");
        }
    }

    #[test]
    fn second_native_query_drift_or_missing_trigger_never_publishes_partial_basis() {
        let fixture = ordinary2048_fixture();
        for field in [
            "InvocationID",
            "MainPID",
            "TriggeredBy",
            "Triggers",
            "ControlPID",
            "Job",
        ] {
            let mut native = ordinary2048_native(&fixture);
            let before = native.clone();
            let result = compare_then_enrich_with(
                &mut native,
                |raw| compare_ordinary2048(&fixture, raw),
                |raw| {
                    enrich_native_census_with(raw, |name, basic| {
                        let mut detailed = detailed2048_fixture(&fixture, name, basic);
                        if name == CONTROLLERS[2].0 {
                            if matches!(field, "InvocationID" | "MainPID") {
                                detailed[field] = json!("changed");
                            } else {
                                detailed.as_object_mut().unwrap().remove(field);
                            }
                        }
                        Ok(detailed)
                    })
                },
            );
            assert!(result.is_err(), "{field}");
            assert_eq!(native, before, "{field}");
        }
    }

    #[test]
    fn positive_control_field_is_retained_and_rejects_at_closure_gate() {
        let fixture = ordinary2048_fixture();
        for (field, value) in [
            ("TriggeredBy", "future.timer"),
            ("Triggers", "future.service"),
            ("ControlPID", "42"),
            ("Job", "43"),
        ] {
            let mut native = ordinary2048_native(&fixture);
            compare_then_enrich_with(
                &mut native,
                |raw| compare_ordinary2048(&fixture, raw),
                |raw| {
                    enrich_native_census_with(raw, |name, basic| {
                        let mut detailed = detailed2048_fixture(&fixture, name, basic);
                        if name == CONTROLLERS[2].0 {
                            detailed[field] = json!(value);
                        }
                        Ok(detailed)
                    })
                },
            )
            .unwrap();
            assert_eq!(native[CONTROLLERS[2].0][field], value);
            assert!(
                current(&closure_basis_from_native(&native)).is_err(),
                "{field}"
            );
        }
    }

    #[test]
    #[ignore = "root; real six-unit reader against frozen ordinary2048 fixture; no archive or R2"]
    fn original_ordinary2048_with_genuine_six_unit_snapshots_preserves_strict_closure() {
        let fixture = ordinary2048_fixture();
        let mut native = ordinary2048_native(&fixture);
        let coordinator = compare_then_enrich_native_census(&mut native, |raw| {
            compare_ordinary2048(&fixture, raw)
        })
        .unwrap();
        assert!(coordinator.is_null());
        current(&closure_basis_from_native(&native)).unwrap();
    }
    #[test]
    fn enrichment_collects_exact_six_units_and_leaves_other_owners_unchanged() {
        let mut native = ordinary_native();
        let other =
            json!({"Id":"later-independent.service","InvocationID":"b".repeat(32),"MainPID":"99"});
        native.insert("later-independent.service".into(), other.clone());
        let mut queried = BTreeSet::new();
        enrich_native_census_with(&mut native, |name, basic| {
            assert!(queried.insert(name.to_owned()));
            Ok(detailed_native(basic))
        })
        .unwrap();
        assert_eq!(queried.len(), 6);
        assert_eq!(native.len(), 7);
        assert_eq!(native["later-independent.service"], other);
        for name in queried {
            assert_eq!(native[&name]["ControlPID"], "0");
            assert_eq!(native[&name]["TriggeredBy"], "");
            assert_eq!(native[&name]["Triggers"], "");
            assert_eq!(native[&name]["Job"], "");
        }
    }
    #[test]
    fn enrichment_rejects_changed_identity_or_state_without_partial_replacement() {
        for field in [
            "Id",
            "InvocationID",
            "MainPID",
            "NRestarts",
            "ActiveState",
            "ControlGroup",
            "Result",
        ] {
            let mut native = ordinary_native();
            let before = native.clone();
            let result = enrich_native_census_with(&mut native, |name, basic| {
                let mut value = detailed_native(basic);
                if name == CONTROLLERS[2].0 {
                    value[field] = json!("changed");
                }
                Ok(value)
            });
            assert!(result.is_err(), "{field}");
            assert_eq!(native, before, "{field}");
        }
    }
    #[test]
    fn enrichment_requires_all_trigger_job_fields_and_all_original_fields() {
        for field in ["TriggeredBy", "Triggers", "ControlPID", "Job", "Type"] {
            let mut native = ordinary_native();
            let before = native.clone();
            assert!(
                enrich_native_census_with(&mut native, |_, basic| {
                    let mut value = detailed_native(basic);
                    value.as_object_mut().unwrap().remove(field);
                    Ok(value)
                })
                .is_err(),
                "{field}"
            );
            assert_eq!(native, before);
        }
        let mut missing = ordinary_native();
        missing.remove(PRODUCERS[0].0);
        assert!(
            enrich_native_census_with(&mut missing, |_, basic| Ok(detailed_native(basic))).is_err()
        );
    }
    #[test]
    fn genuine_positive_trigger_or_job_is_recorded_and_still_rejects_closure() {
        for (field, value) in [
            ("TriggeredBy", "future.timer"),
            ("Triggers", "future.service"),
            ("ControlPID", "42"),
            ("Job", "43"),
        ] {
            let mut native = ordinary_native();
            enrich_native_census_with(&mut native, |_, basic| {
                let mut detailed = detailed_native(basic);
                detailed[field] = json!(value);
                Ok(detailed)
            })
            .unwrap();
            assert_eq!(native[PRODUCERS[0].0][field], value);
            assert!(drained(&native[PRODUCERS[0].0], PRODUCERS[0].0, PRODUCERS[0].1).is_err());
        }
    }
    #[test]
    fn missing_control_or_job_never_becomes_a_drained_default() {
        for field in ["ControlPID", "Job"] {
            let mut value = basis()["native_before"][PRODUCERS[0].0].clone();
            value.as_object_mut().unwrap().remove(field);
            assert!(
                drained(&value, PRODUCERS[0].0, PRODUCERS[0].1).is_err(),
                "{field}"
            );
        }
    }
    #[test]
    fn terminal_requires_original_pid1_and_unique_success() {
        let r = success_row(PRODUCERS[0].0, PRODUCERS[0].1);
        success(std::slice::from_ref(&r), PRODUCERS[0].0, PRODUCERS[0].1).unwrap();
        assert!(success(&[r.clone(), r.clone()], PRODUCERS[0].0, PRODUCERS[0].1).is_err());
        for key in ["_PID", "_UID", "_EXE", "MESSAGE_ID", "INVOCATION_ID"] {
            let mut bad = r.clone();
            bad[key] = json!("wrong");
            assert!(
                success(&[bad], PRODUCERS[0].0, PRODUCERS[0].1).is_err(),
                "{key}"
            );
        }
    }
    #[test]
    fn closure_keeps_delivery_but_rejects_running_restarted_replaced_or_triggered_old_owners() {
        let b = basis();
        current(&b).unwrap();
        for (key, v) in [
            ("MainPID", json!("123")),
            ("NRestarts", json!("1")),
            ("InvocationID", json!("b".repeat(32))),
            ("Triggers", json!("future.service")),
            ("Result", json!("failed")),
            ("ControlGroup", json!("/system.slice/old.service")),
        ] {
            let mut bad = b.clone();
            bad["native_after"][PRODUCERS[0].0][key] = v;
            assert!(current(&bad).is_err(), "{key}");
        }
        let mut missing = b.clone();
        missing["native_after"]
            .as_object_mut()
            .unwrap()
            .remove(PRODUCERS[0].0);
        assert!(current(&missing).is_err());
        let mut renamed = b;
        renamed["current_unique_owner_census"]
            .as_array_mut()
            .unwrap()
            .push(json!({"role":"diagnostic-replay","first_epoch":153,"last_epoch":154}));
        assert!(current(&renamed).is_err());
    }
    #[test]
    fn current_dynamic_owner_census_cannot_be_omitted_or_lie_about_discovery() {
        let b = basis();
        for key in [
            "current_unique_owner_census",
            "workload_discovery_before",
            "native_before",
        ] {
            let mut bad = b.clone();
            bad.as_object_mut().unwrap().remove(key);
            assert!(current(&bad).is_err(), "{key}");
        }
        let mut bad = b;
        bad["workload_discovery_before"][PRODUCERS[1].0] = json!({"MainPID":"99"});
        assert!(current(&bad).is_err());
    }
    #[test]
    fn reduction_closes_only_three_historical_caps() {
        assert_eq!((68u64 + 68 + 192) << 30, CLOSED_HARD_CAPS);
        assert_eq!(OLD_MINIMUM.checked_sub(CLOSED_HARD_CAPS), Some(NEW_MINIMUM));
        const {
            assert!(NEW_MINIMUM > (128u64 + 16 + 64) << 30);
        }
    }
    #[test]
    fn private_source_and_canonical_import_keep_their_distinct_committed_transactions() {
        let make = |tx: &str| {
            json!({"schema":"jetstreamer-root-cohort-publication-receipt-v2","transaction_id":tx,"epochs":[183,184],
            "outcome":{"kind":"committed","members":[{"epoch":183},{"epoch":184}]},
            "root_checkpoint_gate":{"kind":"sealed-root-checkpoint-cohort","members":[{}, {"terminal":{"slot":79919999}}]}})
        };
        let source = "1e009cb9b1bbf09e1211769f8964e925364d56f2cc60a10de39df2666647bec8";
        let canonical = "4615a4858539575a8e3e76cddb74e03da38b1fe1af239528175fdb59e1aeeb44";
        batch(&make(source), [183, 184], source, 79919999).unwrap();
        batch(&make(canonical), [183, 184], canonical, 79919999).unwrap();
        assert!(batch(&make(canonical), [183, 184], source, 79919999).is_err());
    }
    #[test]
    fn exact_closed_promises_cannot_duplicate_credit_or_change_pool_prior_or_cap() {
        let closure: Value =
            serde_json::from_str(include_str!("terminal_legacy_memory_fixtures/closure.json"))
                .unwrap();
        let prior: Value =
            serde_json::from_str(include_str!("terminal_legacy_memory_fixtures/prior.json"))
                .unwrap();
        let good: Closure = serde_json::from_value(closure.clone()).unwrap();
        shape(&good, &prior).unwrap();
        for (pointer, value) in [
            ("/replacement_minimum_bytes", json!(NEW_MINIMUM - 1)),
            (
                "/closed_historical_hard_caps_bytes",
                json!(CLOSED_HARD_CAPS + 1),
            ),
            ("/closed_promises/0/invocation_id", json!("b".repeat(32))),
            ("/closed_promises/0/memory_max_bytes", json!(1)),
            ("/physical_free_space_credit_bytes", json!(1)),
            ("/data_credit_bytes", json!(1)),
            ("/guard_changes", json!(true)),
            ("/pools_preserved", json!(false)),
            (
                "/current_dynamic_memory_recalculation_required",
                json!(false),
            ),
            ("/replay_launch_authorized", json!(true)),
            ("/batch155156/sha256", json!("b".repeat(64))),
        ] {
            let mut bad = closure.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            let bad: Closure = serde_json::from_value(bad).unwrap();
            assert!(shape(&bad, &prior).is_err(), "{pointer}");
        }
        let mut bad = closure;
        bad["closed_promises"][1] = bad["closed_promises"][0].clone();
        assert!(shape(&serde_json::from_value(bad).unwrap(), &prior).is_err());
        for pointer in [
            "/existing_pools_bytes/plugin128GiB",
            "/existing_pools_bytes/compiler_and_native16GiB",
            "/existing_pools_bytes/shared64GiB",
            "/existing_pools_bytes/cadence_maintainer512MiB",
            "/existing_pools_bytes/replay_hard_caps",
        ] {
            let mut bad = prior.clone();
            *bad.pointer_mut(pointer).unwrap() = json!(0);
            assert!(shape(&good, &bad).is_err(), "{pointer}");
        }
    }
}

#[cfg(test)]
mod actual_live145_discovery_control {
    use super::*;
    #[test]
    #[ignore = "Root must bind original2130 failed reader's genuine readonly raw report"]
    fn actual_saved_full_builder_accepts_only_authenticated145_discovery_rollover() -> Result<()> {
        let binding: crate::fleet::BoundFile = serde_json::from_str(&std::env::var("JETSTREAMER_TERMINAL_MEMORY_REAL_REPORT_BINDING")?)?;
        let report = crate::fleet::input136::protected_json(&binding)?;
        ensure!(report["workload_discovery_before"]!=report["workload_discovery_after"],"actual original failure must be reproduced");
        current(&report)?;
        let original = report.clone();
        let mut omitted=report.clone();omitted.as_object_mut().context("original raw object")?.remove("live145_prefix_export_after");
        ensure!(current(&omitted).is_err(),"omitted original145 scope must reject");
        let mut foreign=report.clone();foreign["workload_discovery_after"]["unqualified-foreign.service"]=serde_json::json!({"InvocationID":"changed"});
        ensure!(current(&foreign).is_err(),"foreign discovery change cannot borrow145 scope");
        let mut crossed=report.clone();crossed["live145_prefix_export_after"]["peer"]["invocation_id"]=serde_json::json!("f".repeat(32));
        ensure!(current(&crossed).is_err(),"crossed original actor must reject");
        ensure!(report==original,"original raw report changed");
        println!("{}",serde_json::json!({"schema":"actual-terminal-memory-145-discovery-control-v1","original_report":binding,"original_raw_discovery_inequality_reproduced":true,"actual_original_sources_and_current_phase_reauthenticated":true,"raw_report_unchanged":true,"unknown_owner_and_missing_scope_rejected":true,"memory_credit_bytes":0,"DATA_credit_bytes":0,"replay_launch_authorized":false}));
        Ok(())
    }
}
