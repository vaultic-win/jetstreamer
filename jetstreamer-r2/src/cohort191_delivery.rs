//! Closed 191–194 native metadata custody. Never creates a ready/archive receipt.
use super::*;
#[path = "cohort191_import_pending.rs"]
mod import_pending;
#[path = "cohort191_terminal.rs"]
mod terminal_transition;
use serde_json::json;
mod queue;
use std::{
    collections::{BTreeMap, BTreeSet},
    os::unix::fs::PermissionsExt,
    process::Command,
};
pub(super) const UNIT: &str =
    "jetstreamer-root-sweep-e191-194-t5-20261016-v2-r2-e191-194-lane-a-1.service";
pub(super) const IID: &str = "ea93199ed2fa470d99de248c2a10b246";
pub(super) const CONTROLLER: &str = "jetstreamer-epochs191-194-target5-controller-v2-r2.service";
pub(super) const CID: &str = "c741f57764384e07a08484e6451f8f0c";
const DEPLOY: &str = "/usr/local/lib/jetstreamer/deploy-epochs191-194-target5-20261016-v1";
const NODE_SHA: &str = "a09b8e5aa9426beaf42e6b5f2a469a5a147436bab8b7bf79f268758b60aa2e65";
const MANIFEST_SHA: &str = "8e16ef3a6f8ae1b2ea3614fbafcb18be34136a8c976e63a386c0fc7c176ce6d0";
const FINGERPRINT: &str = "sha256:0294b1813c7d9cdd3266af2705602e1e2a8920d2159944e0a26b498f58f653f9";
const SCRIPT: &str = "/usr/local/lib/jetstreamer/controller-epochs191-194-target5-20261016-v2/adaptive-root-cohort-sweep.py";
const SCRIPT_SHA: &str = "62592209a3fc2b659ea4bfb924bbcf34435b4228c87e56232eb6b962b907023e";
const REBIND: &str =
    "/usr/local/lib/jetstreamer/horizon-controller-rebind-proof-20261023-v1/unit-bindings.json";
const REBIND_SHA: &str = "a4ce1f8dd91853e8837fb8bf17b923fa4874c726ed551e84dc7b4ae720f2fab2";
const LANE: &str = "/home/sol/.jetstreamer-private/epochs-191-194-v4-20261009-v1/lane-a";
const RUN: &str = "/home/sol/.jetstreamer-private/epochs-191-194-v4-20261009-v1/lane-a/private/destination-a1c8ba888df3256ab55ded6e75ce724aba84a1ed586599353a73fa1d60696cfa/work/root-cohort-191-194/run-2189644-1792144444502274289";
const STATE: &str = "/var/lib/jetstreamer-root-sweep-epochs191-194-target5-20261016-v2/state.json";
const IMPORT_ROOT: &str = "/home/sol/.jetstreamer-private/epochs191-194-target5-20261016-v2-import";
pub(super) const EVENT_SCHEMA: &str = "jetstreamer-cohort191-delivery-event-v2";
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Bound {
    pub path: PathBuf,
    pub sha256: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Claim {
    pub epoch: u64,
    pub phase: String,
    pub unit: String,
    pub invocation_id: String,
    pub expected_exec_start: String,
    pub program: Option<Bound>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct GateTool {
    verifier: Bound,
    wrapper: Bound,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Capture {
    schema: String,
    observer: Bound,
    forecast: Bound,
    origins: BTreeMap<u64, Bound>,
    claims: Vec<Claim>,
    source_batch: Option<Bound>,
    public_batch: Option<Bound>,
    gate_receipts: BTreeMap<u64, BTreeMap<String, Bound>>,
    gate_tools: BTreeMap<String, GateTool>,
    ready_receipts: BTreeMap<u64, Bound>,
    #[serde(default)]
    queue: Option<queue::Binding>,
    #[serde(default)]
    source_revalidation_policy: Option<Bound>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    native_pending_proof: Option<Bound>,
    output: PathBuf,
}
pub(super) fn bound(b: &Bound, sealed: bool) -> Result<Value> {
    let m = fs::symlink_metadata(&b.path)?;
    ensure!(
        b.path.is_absolute()
            && b.path.canonicalize()? == b.path
            && m.is_file()
            && m.nlink() == 1
            && m.uid() == 0
            && m.mode() & 0o022 == 0
            && (!sealed || m.mode() & 0o222 == 0),
        "unsafe 191 bound evidence"
    );
    let bytes = read_stable_bounded(&b.path, 16 << 20, "191 evidence")?;
    ensure!(
        is_lower_hex(&b.sha256, 64) && hex_lower(&Sha256::digest(&bytes)) == b.sha256,
        "191 evidence changed"
    );
    Ok(serde_json::from_slice(&bytes)?)
}
fn member(path: &Path, digest: &str) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        path.canonicalize()? == path
            && m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o222 == 0,
        "unsealed 191 tool"
    );
    ensure!(
        hex_lower(&Sha256::digest(read_stable_bounded(
            path,
            512 << 20,
            "191 pinned tool"
        )?)) == digest,
        "191 tool digest differs"
    );
    Ok(())
}
fn inputs() -> Result<Value> {
    member(&Path::new(DEPLOY).join("jetstreamer-node"), NODE_SHA)?;
    member(
        &Path::new(DEPLOY).join("preflight-191-194-v4.json"),
        MANIFEST_SHA,
    )?;
    member(Path::new(SCRIPT), SCRIPT_SHA)?;
    bound(
        &Bound {
            path: REBIND.into(),
            sha256: REBIND_SHA.into(),
        },
        true,
    )
}
fn prefix(v: &Value) -> Option<&str> {
    v.as_str()?
        .split_once(" ; ignore_errors=")
        .map(|(a, b)| if b.starts_with("no ;") { a } else { "" })
}
fn live(v: &Value, c: &Claim) -> Result<()> {
    ensure!(
        v["Id"] == c.unit
            && v["InvocationID"] == c.invocation_id
            && v["LoadState"] == "loaded"
            && v["ActiveState"] == "active"
            && v["SubState"] == "running"
            && v["NRestarts"] == "0"
            && v["MainPID"]
                .as_str()
                .is_some_and(|s| s.parse::<u64>().is_ok_and(|n| n > 0))
            && pipeline_status::same_exec_start(
                &c.expected_exec_start,
                v["ExecStart"].as_str().unwrap_or("")
            ),
        "191 owner changed or not active"
    );
    Ok(())
}
pub(super) fn scope(phase: &str, unit: &str) -> bool {
    (phase == "producer-finalization" && unit == UNIT)
        || (phase == "controller-import-handoff" && unit == CONTROLLER)
}
pub(super) fn binding(unit: &str, iid: &str, origin: &str, oid: &str) -> bool {
    unit == CONTROLLER && iid == CID && origin == UNIT && oid == IID
}
pub(super) fn origin(epoch: u64, unit: &str, iid: &str) -> bool {
    (191..=194).contains(&epoch) && unit == UNIT && iid == IID
}
pub(super) fn archives(epoch: u64, phase: &str) -> PathBuf {
    match phase {
        "producer-finalization" => Path::new(RUN).join(format!("archives/epoch-{epoch}.jet")),
        "controller-import-handoff" | "local-publication" => {
            Path::new(LANE).join(format!("output/epoch-{epoch}.jet"))
        }
        _ => Path::new("/home/sol/horizon").join(format!("epoch-{epoch}.jet")),
    }
}
fn roots(records: &[Value], cutoff: u64) -> Result<Value> {
    let r = records
        .iter()
        .filter(|r| {
            r["MESSAGE"]
                .as_str()
                .is_some_and(|s| s.contains("historical checkpoint slot=84239250 "))
        })
        .collect::<Vec<_>>();
    ensure!(r.len() == 1, "191 final canonical root absent or ambiguous");
    for row in records {
        ensure!(
            row["_SYSTEMD_UNIT"] == UNIT
                && row["_SYSTEMD_INVOCATION_ID"] == IID
                && row["_PID"] == "2189644"
                && row["_UID"] == "1001",
            "191 native journal owner differs"
        );
        let t = row["__REALTIME_TIMESTAMP"]
            .as_str()
            .context("191 journal timestamp")?
            .parse::<u64>()?;
        ensure!(
            t > 0
                && t <= cutoff
                    .checked_mul(1_000_000)
                    .context("191 cutoff overflow")?,
            "191 event after cutoff"
        );
    }
    cohort198_finalization::checkpoint(r[0]["MESSAGE"].as_str().unwrap(), 84239250)?;
    let f = cohort198_finalization::fields(
        r[0]["MESSAGE"].as_str().unwrap(),
        "historical checkpoint ",
    )?;
    ensure!(
        f["accounts_hash"] == "GCANVakrcunYu9VRe1WdNd7xAPKGdoZNFgpQbagdB9zq",
        "191 manifest root mismatch"
    );
    let mut closes = records
        .iter()
        .filter(|r| {
            r["MESSAGE"]
                .as_str()
                .is_some_and(|s| s.contains("horizon archive complete:"))
        })
        .collect::<Vec<_>>();
    closes.sort_by_key(|r| {
        r["__REALTIME_TIMESTAMP"]
            .as_str()
            .unwrap()
            .parse::<u64>()
            .unwrap()
    });
    ensure!(
        closes.len() == 4,
        "191 complete cohort archive closes absent/ambiguous"
    );
    for row in &closes {
        let f = cohort198_finalization::fields(
            row["MESSAGE"].as_str().unwrap(),
            "horizon archive complete: ",
        )?;
        ensure!(
            cohort198_finalization::integer(&f, "slots")? == 432000
                && cohort198_finalization::integer(&f, "epochs")? == 1
                && cohort198_finalization::integer(&f, "buckets")? == 3375
                && cohort198_finalization::integer(&f, "bytes")? > 0,
            "191 archive close scope differs"
        );
    }
    ensure!(
        r[0]["__REALTIME_TIMESTAMP"]
            .as_str()
            .unwrap()
            .parse::<u64>()?
            < closes[3]["__REALTIME_TIMESTAMP"]
                .as_str()
                .unwrap()
                .parse::<u64>()?,
        "191 final archive precedes trusted root"
    );
    Ok(
        json!({"trusted_root_slot":84239250,"archive_terminal_slot":84239999,"root":r[0],"closes":closes}),
    )
}
fn native_events(cutoff: u64) -> Result<Value> {
    let out = Command::new("/usr/bin/journalctl")
        .args([
            &format!("_SYSTEMD_UNIT={UNIT}"),
            &format!("_SYSTEMD_INVOCATION_ID={IID}"),
            "--grep=historical checkpoint slot=84239250 |horizon archive complete:",
            "--no-pager",
            "-n",
            "32",
            "-o",
            "json",
        ])
        .output()?;
    ensure!(
        out.status.success() && out.stdout.len() <= 2 << 20,
        "191 native journal failed"
    );
    let rows = serde_json::Deserializer::from_slice(&out.stdout)
        .into_iter::<Value>()
        .collect::<std::result::Result<Vec<_>, _>>()?;
    roots(&rows, cutoff)
}
fn manager_terminal(cutoff: u64) -> Result<Value> {
    let out = Command::new("/usr/bin/journalctl")
        .args([
            "_PID=1",
            "_UID=0",
            &format!("UNIT={UNIT}"),
            "--no-pager",
            "-n",
            "64",
            "-o",
            "json",
        ])
        .output()?;
    ensure!(
        out.status.success() && out.stdout.len() <= 2 << 20,
        "191 terminal manager unavailable"
    );
    let rows = serde_json::Deserializer::from_slice(&out.stdout)
        .into_iter::<Value>()
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let own = rows
        .iter()
        .filter(|r| {
            r["UNIT"] == UNIT
                && r["_PID"] == "1"
                && r["_UID"] == "0"
                && r["INVOCATION_ID"].as_str().is_some_and(|s| !s.is_empty())
        })
        .collect::<Vec<_>>();
    ensure!(
        own.last().is_some_and(|r| r["INVOCATION_ID"] == IID),
        "191 producer replaced since original invocation"
    );
    let end = own
        .iter()
        .rposition(|r| {
            r["INVOCATION_ID"] == IID
                && r["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448"
                && r["MESSAGE"] == format!("{UNIT}: Deactivated successfully.")
        })
        .context("191 clean manager terminal missing")?;
    ensure!(
        !own[end + 1..].iter().any(|r| r["MESSAGE"]
            .as_str()
            .is_some_and(|s| s.starts_with("Starting ") || s.starts_with("Started "))),
        "191 producer restarted"
    );
    ensure!(
        own[end]["__REALTIME_TIMESTAMP"]
            .as_str()
            .context("191 terminal time")?
            .parse::<u64>()?
            <= cutoff
                .checked_mul(1_000_000)
                .context("191 cutoff overflow")?,
        "191 terminal after sample"
    );
    Ok(own[end].clone())
}
const CONTROLLER_TERMINAL: &str =
    "/var/lib/jetstreamer/horizon-cohort191-controller-terminal-20261023-v1/terminal.json";
fn no_manager_job(v: &Value) -> bool {
    matches!(v.as_str(), Some("" | "0"))
}
fn terminal_controller_shape(v: &Value, history: &Value) -> Result<()> {
    ensure!(
        v["Id"] == CONTROLLER
            && v["LoadState"] == "loaded"
            && v["InvocationID"] == CID
            && v["NRestarts"] == "0"
            && v["ActiveState"] == "inactive"
            && v["SubState"] == "dead"
            && v["MainPID"] == "0"
            && v["Result"] == "success"
            && v["ExecMainStatus"] == "0"
            && matches!(v["ExecMainCode"].as_str(), Some("1" | "exited"))
            && no_manager_job(&v["Job"])
            && v["ControlGroup"] == ""
            && v["SuccessExitStatus"] == ""
            && prefix(&v["ExecStart"])
                == prefix(&history["current_units"][CONTROLLER]["ExecStart"]),
        "191 controller is not its exact retained natural exit0/no-job/no-cgroup lifecycle"
    );
    Ok(())
}
fn cleared_controller_shape(v: &Value, history: &Value) -> Result<()> {
    ensure!(
        v["Id"] == CONTROLLER
            && v["ActiveState"] == "inactive"
            && v["SubState"] == "dead"
            && v["MainPID"] == "0"
            && v["NRestarts"] == "0"
            && no_manager_job(&v["Job"])
            && v["ControlGroup"] == ""
            && v["Result"] == "success"
            && v["ExecMainStatus"] == "0",
        "191 inactive controller has failure/restart/job/cgroup ambiguity"
    );
    ensure!(
        (v["LoadState"] == "not-found" && v["InvocationID"] == "")
            || (v["LoadState"] == "loaded"
                && v["InvocationID"] == CID
                && matches!(v["ExecMainCode"].as_str(), Some("0" | ""))
                && v["SuccessExitStatus"] == ""
                && prefix(&v["ExecStart"])
                    == prefix(&history["current_units"][CONTROLLER]["ExecStart"])),
        "191 inactive controller is not a collected/cleared original invocation"
    );
    Ok(())
}
fn controller_properties() -> Result<Value> {
    let mut current = fleet::unit(CONTROLLER)?;
    let result = Command::new("/usr/bin/systemctl")
        .args([
            "show",
            CONTROLLER,
            "--no-pager",
            "--property=Job,ExecMainCode,SuccessExitStatus",
        ])
        .output()?;
    ensure!(
        result.status.success() && result.stdout.len() <= 8192,
        "191 controller terminal properties unavailable"
    );
    let mut keys = BTreeSet::new();
    for line in std::str::from_utf8(&result.stdout)?.lines() {
        let (key, value) = line.split_once('=').context("191 controller property")?;
        ensure!(
            ["Job", "ExecMainCode", "SuccessExitStatus"].contains(&key) && keys.insert(key),
            "191 duplicate/foreign controller terminal property"
        );
        current[key] = json!(value);
    }
    ensure!(
        keys.len() == 3,
        "191 controller terminal properties incomplete"
    );
    Ok(current)
}
fn controller_manager_end(rows: &[Value], cutoff: u64) -> Result<Value> {
    let own: Vec<_> = rows
        .iter()
        .filter(|r| r["UNIT"] == CONTROLLER && r["_PID"] == "1" && r["_UID"] == "0")
        .collect();
    let end: Vec<_> = own
        .iter()
        .copied()
        .filter(|r| {
            r["INVOCATION_ID"] == CID
                && r["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448"
                && r["MESSAGE"] == format!("{CONTROLLER}: Deactivated successfully.")
        })
        .collect();
    ensure!(
        end.len() == 1,
        "191 controller clean PID1 terminal missing/duplicated"
    );
    let time: u64 = end[0]["__REALTIME_TIMESTAMP"]
        .as_str()
        .context("191 controller end clock")?
        .parse()?;
    ensure!(
        time > 0
            && time
                <= cutoff
                    .checked_mul(1_000_000)
                    .context("191 controller cutoff overflow")?,
        "191 controller terminal after sample"
    );
    for row in own {
        let t: u64 = row["__REALTIME_TIMESTAMP"]
            .as_str()
            .context("191 controller manager clock")?
            .parse()?;
        if t >= time {
            ensure!(
                row["INVOCATION_ID"].as_str().is_none_or(|s| s == CID)
                    && !row["MESSAGE"]
                        .as_str()
                        .is_some_and(|s| s.starts_with("Starting ")
                            || s.starts_with("Started ")
                            || s.contains("Failed")
                            || s.contains("Main process exited")),
                "191 controller failed/replaced/restarted after completion"
            );
        }
    }
    Ok((*end[0]).clone())
}
fn controller_terminal_events(history: &Value, cutoff: u64) -> Result<Value> {
    let result = Command::new("/usr/bin/journalctl")
        .args([
            "_PID=1",
            "_UID=0",
            &format!("UNIT={CONTROLLER}"),
            "--no-pager",
            "-o",
            "json",
            "-n",
            "128",
        ])
        .output()?;
    ensure!(
        result.status.success() && result.stdout.len() <= 2 << 20,
        "191 controller manager history unavailable"
    );
    let rows = serde_json::Deserializer::from_slice(&result.stdout)
        .into_iter::<Value>()
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let end = controller_manager_end(&rows, cutoff)?;
    let pid = history["current_units"][CONTROLLER]["MainPID"]
        .as_str()
        .context("191 original controller PID")?;
    let result = Command::new("/usr/bin/journalctl")
        .args([
            "--no-pager",
            "-o",
            "json",
            &format!("_SYSTEMD_UNIT={CONTROLLER}"),
            &format!("_SYSTEMD_INVOCATION_ID={CID}"),
            &format!("_PID={pid}"),
            "_UID=0",
            "--grep=^all sealed cohorts 191-194 are public$",
            "-n",
            "8",
        ])
        .output()?;
    ensure!(
        result.status.success() && result.stdout.len() <= 65536,
        "191 natural completion journal unavailable"
    );
    let messages = serde_json::Deserializer::from_slice(&result.stdout)
        .into_iter::<Value>()
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(
        messages.len() == 1,
        "191 natural all-public controller message absent/ambiguous"
    );
    let message = &messages[0];
    let time: u64 = message["__REALTIME_TIMESTAMP"]
        .as_str()
        .context("191 all-public clock")?
        .parse()?;
    let start = pipeline_status::manager_start(CONTROLLER, CID)?;
    let end_time: u64 = end["__REALTIME_TIMESTAMP"].as_str().unwrap().parse()?;
    ensure!(
        message["_SYSTEMD_UNIT"] == CONTROLLER
            && message["_SYSTEMD_INVOCATION_ID"] == CID
            && message["_PID"] == pid
            && message["_UID"] == "0"
            && message["MESSAGE"] == "all sealed cohorts 191-194 are public"
            && start
                .checked_mul(1000)
                .context("191 controller start overflow")?
                <= time
            && time < end_time,
        "191 natural completion message is not the exact original controller before exit"
    );
    Ok(json!({"manager_start_unix_millis":start,"all_public":message,"terminal":end}))
}
fn controller_lifecycle(
    current: &Value,
    history: &Value,
    cutoff: u64,
    require_live: bool,
) -> Result<Value> {
    if current["LoadState"] == "loaded" && current["ActiveState"] == "active" {
        ensure!(
            current["InvocationID"] == CID
                && current["NRestarts"] == "0"
                && current["SubState"] == "running"
                && current["MainPID"]
                    .as_str()
                    .is_some_and(|s| s.parse::<u64>().is_ok_and(|n| n > 0))
                && prefix(&current["ExecStart"])
                    == prefix(&history["current_units"][CONTROLLER]["ExecStart"]),
            "191 active import controller/rebind changed"
        );
        let actual = controller_properties()?;
        ensure!(
            no_manager_job(&actual["Job"]) && fleet::unit(CONTROLLER)? == *current,
            "191 live controller has a queued job/replacement"
        );
        return Ok(json!({"kind":"live-original-controller","unit":actual}));
    }
    ensure!(
        !require_live,
        "191 pending import has no live original controller"
    );
    let events = controller_terminal_events(history, cutoff)?;
    let actual = controller_properties()?;
    ensure!(
        fleet::unit(CONTROLLER)? == *current,
        "191 controller changed while checking terminal lifecycle"
    );
    if terminal_controller_shape(&actual, history).is_ok() {
        return Ok(
            json!({"kind":"retained-natural-terminal-controller","unit":actual,"events":events}),
        );
    }
    cleared_controller_shape(&actual, history)?;
    let path = Path::new(CONTROLLER_TERMINAL);
    let bytes = read_stable_bounded(path, 2 << 20, "191 previously captured terminal controller")?;
    let b = Bound {
        path: path.into(),
        sha256: hex_lower(&Sha256::digest(&bytes)),
    };
    let proof = bound(&b, false)?;
    ensure!(
        proof["schema"] == "jetstreamer-cohort191-controller-terminal-v2"
            && proof["events"] == events
            && proof["root_controller_state_sha256"]
                == hex_lower(&Sha256::digest(&state_bytes()?.0))
            && proof["publication_authorized"] == false
            && proof["launch_authorized"] == false
            && proof["r2_mutations"] == false
            && proof["resource_samples"] == 0
            && proof["capture_program"]
                == "/usr/local/lib/jetstreamer/horizon-cohort191-delivery-tools-20261023-v1/jetstreamer-r2",
        "191 collected controller lacks a real exact terminal capture"
    );
    member(
        Path::new(proof["capture_program"].as_str().unwrap()),
        proof["capture_self_sha256"]
            .as_str()
            .context("191 terminal capture digest")?,
    )?;
    terminal_controller_shape(&proof["manager_snapshot"], history)?;
    Ok(
        json!({"kind":"collected-natural-terminal-controller","unit":actual,"events":events,"terminal_capture":b}),
    )
}
/// Capture actual retained manager exit 0 properties before PID1 collects them.
/// Never invent this receipt from controller state or a completion message alone.
pub(super) fn capture_controller_terminal() -> Result<()> {
    let a: Vec<_> = env::args().collect();
    ensure!(
        a.len() == 4 && a[2] == "--self-sha256" && unsafe { libc::geteuid() } == 0,
        "capture-controller-terminal-191 --self-sha256 SHA"
    );
    let executable = fs::read_link("/proc/self/exe")?;
    ensure!(
        executable
            == Path::new(
                "/usr/local/lib/jetstreamer/horizon-cohort191-delivery-tools-20261023-v1/jetstreamer-r2"
            ),
        "191 terminal capture must use qualified deployed reader"
    );
    member(&executable, &a[3])?;
    let history = inputs()?;
    let before = controller_properties()?;
    terminal_controller_shape(&before, &history)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let events = controller_terminal_events(&history, now)?;
    let (bytes, state) = state_bytes()?;
    ensure!(
        state["completed"]["191-194"]["first_epoch"] == 191
            && state["completed"]["191-194"]["last_epoch"] == 194
            && state["assignments"]
                .as_object()
                .is_some_and(|a| a.is_empty())
            && state["import_owner"].is_null(),
        "191 natural terminal controller lacks its completed import state"
    );
    ensure!(
        controller_properties()? == before && state_bytes()?.0 == bytes,
        "191 terminal capture raced owner/state"
    );
    let output = Path::new(CONTROLLER_TERMINAL);
    let parent = output.parent().unwrap();
    if !parent.try_exists()? {
        fs::create_dir(parent)?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        File::open(parent.parent().unwrap())?.sync_all()?;
    }
    let metadata = fs::symlink_metadata(parent)?;
    ensure!(
        metadata.is_dir() && metadata.uid() == 0 && metadata.mode() & 0o077 == 0,
        "191 terminal capture output directory is not root-private"
    );
    fleet::persist(
        output,
        &json!({"schema":"jetstreamer-cohort191-controller-terminal-v2",
        "manager_snapshot":before,"events":events,"capture_program":executable,"capture_self_sha256":a[3],
        "root_controller_state_sha256":hex_lower(&Sha256::digest(&bytes)),"publication_authorized":false,
        "launch_authorized":false,"r2_mutations":false,"resource_samples":0}),
    )?;
    println!("{}", output.display());
    Ok(())
}
fn state_bytes() -> Result<(Vec<u8>, Value)> {
    let m = fs::symlink_metadata(STATE)?;
    ensure!(
        m.is_file() && m.uid() == 0 && m.nlink() == 1 && m.mode() & 0o077 == 0,
        "unsafe 191 controller state"
    );
    let bytes = read_stable_bounded(Path::new(STATE), 2 << 20, "191 state")?;
    let v: Value = serde_json::from_slice(&bytes)?;
    ensure!(
        v["schema"] == "jetstreamer-adaptive-root-cohort-sweep-v3",
        "191 state schema changed"
    );
    Ok((bytes, v))
}
fn decoded_path(v: &Value) -> Result<PathBuf> {
    Ok(String::from_utf8(BASE64_STANDARD.decode(v.as_str().context("191 encoded path")?)?)?.into())
}
fn hash_bytes(text: &str) -> Result<[u8; 32]> {
    ensure!((32..=44).contains(&text.len()), "191 manifest hash length");
    let alphabet = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut result = [0u8; 32];
    for byte in text.bytes() {
        let mut carry = alphabet
            .iter()
            .position(|b| *b == byte)
            .context("191 manifest hash alphabet")? as u32;
        for n in result.iter_mut().rev() {
            carry += u32::from(*n) * 58;
            *n = (carry & 255) as u8;
            carry >>= 8;
        }
        ensure!(carry == 0, "191 manifest hash overflow");
    }
    Ok(result)
}
fn root_gate(v: &Value) -> Result<()> {
    let manifest = bound(
        &Bound {
            path: Path::new(DEPLOY).join("preflight-191-194-v4.json"),
            sha256: MANIFEST_SHA.into(),
        },
        true,
    )?;
    let cohorts = manifest["manifest"]["verification_cohorts"]
        .as_array()
        .context("191 sealed manifest cohorts")?;
    let selected: Vec<_> = cohorts
        .iter()
        .filter(|c| c["first_epoch"] == 191 && c["last_epoch"] == 194)
        .collect();
    ensure!(selected.len() == 1, "191 manifest cohort ambiguous");
    let expected: Vec<_> = selected[0]["root_checkpoints"].as_array().context("191 manifest checkpoints")?
        .iter().map(|r| Ok(json!({"slot":r["slot"],"accounts_hash":hash_bytes(r["accounts_hash"].as_str().context("191 manifest accounts hash")?)?})))
        .collect::<Result<_>>()?;
    let gate = &v["root_checkpoint_gate"];
    ensure!(
        gate["kind"] == "sealed-root-checkpoint-cohort"
            && gate["version"] == 1
            && gate["verified_manifest_checkpoints"] == json!(expected),
        "191 native root gate differs from sealed manifest"
    );
    let members = gate["members"]
        .as_array()
        .context("191 root gate members")?;
    ensure!(
        members
            .iter()
            .map(|m| m["epoch"].as_u64())
            .eq((191..=194).map(Some)),
        "191 root gate member census"
    );
    for m in members {
        for name in ["bootstrap", "terminal"] {
            let row = &m[name];
            let slot = row["slot"].as_u64().context("191 gate checkpoint slot")?;
            ensure!(
                row["slot_complete"] == true
                    && row["tick_height"]
                        == slot
                            .checked_add(1)
                            .and_then(|n| n.checked_mul(64))
                            .context("191 gate tick overflow")?,
                "191 native member checkpoint incomplete"
            );
            for hash in ["bank_hash", "accounts_hash", "last_blockhash"] {
                let _: [u8; 32] = serde_json::from_value(row[hash].clone())?;
            }
        }
        ensure!(
            m["bootstrap"]["slot"].as_u64() <= m["terminal"]["slot"].as_u64(),
            "191 reversed native root member"
        );
    }
    Ok(())
}
fn batch(b: &Bound, public: bool, materialized: &BTreeSet<u64>) -> Result<Value> {
    let allowed = if public {
        PathBuf::from(IMPORT_ROOT)
    } else {
        Path::new(LANE).join("private")
    };
    ensure!(
        b.path.starts_with(&allowed)
            && b.path
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with("batch-") && s.ends_with(".json")),
        "191 foreign batch receipt"
    );
    let m = fs::symlink_metadata(&b.path)?;
    ensure!(
        b.path.is_absolute()
            && b.path.canonicalize()? == b.path
            && m.is_file()
            && m.uid() == 1001
            && m.nlink() == 1
            && m.mode() & 0o022 == 0,
        "191 batch ownership differs"
    );
    let bytes = read_stable_bounded(&b.path, 4 << 20, "191 native committed batch")?;
    ensure!(
        hex_lower(&Sha256::digest(&bytes)) == b.sha256,
        "191 batch digest changed"
    );
    let v: Value = serde_json::from_slice(&bytes)?;
    ensure!(
        v["schema"] == "jetstreamer-root-cohort-publication-receipt-v2"
            && v["epochs"] == json!([191, 192, 193, 194])
            && v["manifest_fingerprint"] == FINGERPRINT
            && v["outcome"]["kind"] == "committed"
            && v["root_checkpoint_gate"]["kind"] == "sealed-root-checkpoint-cohort"
            && v["root_checkpoint_gate"]["members"]
                .as_array()
                .is_some_and(|a| a
                    .iter()
                    .map(|m| m["epoch"].as_u64())
                    .eq((191..=194).map(Some)))
            && v["outcome"]["members"].as_array().is_some_and(|a| a
                .iter()
                .map(|m| m["epoch"].as_u64())
                .eq((191..=194).map(Some))),
        "191 native batch scope/commit gate differs"
    );
    root_gate(&v)?;
    let destination = if public {
        PathBuf::from("/home/sol/horizon")
    } else {
        Path::new(LANE).join("output")
    };
    ensure!(
        decoded_path(&v["destination"]["path_base64"])? == destination,
        "191 batch destination changed"
    );
    for row in v["outcome"]["members"].as_array().unwrap() {
        let epoch = row["epoch"].as_u64().unwrap();
        let path = destination.join(format!("epoch-{epoch}.jet"));
        ensure!(
            decoded_path(&row["archive_path_base64"])? == path
                && is_lower_hex(row["archive_sha256"].as_str().unwrap_or(""), 64),
            "191 batch archive binding differs"
        );
        if !materialized.contains(&epoch) {
            continue;
        }
        let i = regular_identity(&path)?;
        ensure!(
            row["committed_archive"]["device"] == i.device
                && row["committed_archive"]["inode"] == i.inode
                && row["committed_archive"]["length"] == i.length
                && row["committed_archive"]["modified_seconds"] == i.modified_seconds
                && row["committed_archive"]["modified_nanoseconds"] == i.modified_nanoseconds,
            "191 batch artifact changed"
        );
        let checksum = read_stable_bounded(
            &destination.join(format!("epoch-{epoch}.jet.sha256")),
            512,
            "191 sidecar",
        )?;
        ensure!(
            parse_canonical_sidecar(epoch, &checksum).as_deref() == row["archive_sha256"].as_str(),
            "191 local sidecar changed"
        );
    }
    Ok(v)
}
fn phase_scope(c: &Claim) -> Result<()> {
    if c.phase == queue::PHASE {
        return queue::claim(c);
    }
    ensure!(
        (191..=194).contains(&c.epoch) && is_lower_hex(&c.invocation_id, 32),
        "foreign 191 claim"
    );
    if scope(&c.phase, &c.unit) {
        ensure!(
            (c.unit == UNIT && c.invocation_id == IID)
                || (c.unit == CONTROLLER && c.invocation_id == CID),
            "191 fixed owner mismatch"
        );
    } else {
        ensure!(
            matches!(
                c.phase.as_str(),
                "local-publication"
                    | "full-verification"
                    | "plugin-verification"
                    | "upload-readback"
            ) && fleet::pipeline_unit_range_for_epoch(&c.phase, &c.unit, c.epoch)?
                .contains(&c.epoch),
            "foreign 191 stage"
        );
        if c.phase == "local-publication" {
            ensure!(
                c.unit
                    .starts_with("jetstreamer-root-import-e191-194-t5-20261016-v2-r2-e191-194-"),
                "191 importer owner differs"
            );
        } else {
            ensure!(
                c.program.as_ref().is_some_and(|b| {
                    if matches!(c.phase.as_str(),"full-verification"|"plugin-verification") {
                        b.path == Path::new("/usr/local/lib/jetstreamer/horizon-cohort191-delivery-tools-20261023-v1/jetstreamer-horizon-verify-pair")
                    } else {b.path.file_name().and_then(|s|s.to_str()) == Some("jetstreamer-r2")}
                }),
                "191 downstream stage lacks the pinned native verifier/uploader program"
            );
        }
    }
    Ok(())
}
fn program(c: &Claim, u: &Value) -> Result<()> {
    if let Some(b) = &c.program {
        ensure!(
            b.path.starts_with("/usr/local/lib/jetstreamer"),
            "191 downstream program is not deployed"
        );
        member(&b.path, &b.sha256)?;
        let pid = u["MainPID"].as_str().context("191 downstream PID")?;
        ensure!(
            fs::read_link(format!("/proc/{pid}/exe"))? == b.path,
            "191 watcher wrapper is not its actual native verifier/uploader"
        );
    }
    Ok(())
}
// Receipt bytes may be written by the archive operator. Do not weaken the
// root-only capture/model/program policy to read these separate native records.
fn receipt_bytes(b: &Bound, uid: u32, limit: u64) -> Result<Vec<u8>> {
    let m = fs::symlink_metadata(&b.path)?;
    ensure!(
        b.path.is_absolute()
            && b.path.canonicalize()? == b.path
            && m.is_file()
            && m.nlink() == 1
            && m.uid() == uid
            && m.mode() & 0o022 == 0,
        "unsafe 191 operator receipt"
    );
    let bytes = read_stable_bounded(&b.path, limit, "191 operator receipt")?;
    ensure!(
        is_lower_hex(&b.sha256, 64) && hex_lower(&Sha256::digest(&bytes)) == b.sha256,
        "191 operator receipt changed"
    );
    Ok(bytes)
}
fn original(b: &Bound, epoch: u64, cutoff: u64) -> Result<StatusPublicationReceipt> {
    let bytes = receipt_bytes(b, 0, 1 << 20)?;
    let receipt = validate_status_publication_receipt_bytes(
        b.path.parent().context("191 origin parent")?,
        &b.path,
        &bytes,
        "solana-archive-with-accounts-data",
        epoch,
    )?;
    ensure!(
        receipt.schema == STATUS_RECEIPT_SCHEMA
            && receipt.pipeline_binding.is_none()
            && receipt.status.phase == "replay"
            && receipt.producer_invocation_id == IID
            && receipt.controller_invocation_id == CID
            && receipt.verified_unix_seconds <= cutoff,
        "191 origin is not the authenticated original invocation/rebind"
    );
    let observer = Bound {
        path: receipt.observer_receipt.clone(),
        sha256: receipt.observer_receipt_sha256.clone(),
    };
    let bytes = receipt_bytes(&observer, 0, 16 << 20)?;
    let sample = validate_observer_binding(&bytes, &observer.sha256, epoch, CID, IID)?;
    ensure!(
        sample == receipt.status.sampled_at_utc && fleet::utc_seconds(&sample)? <= cutoff,
        "191 original observer/sample changed"
    );
    Ok(receipt)
}
fn ready(b: &Bound, epoch: u64, cutoff: u64) -> Result<Receipt> {
    // Use the same canonical receipt validator as authenticated restore. The
    // receipt is historical remote proof; the fleet must still re-observe the
    // ready pair. It grants neither archive publication nor local retirement.
    let uid = fs::symlink_metadata(&b.path)?.uid();
    ensure!(
        matches!(uid, 0 | 1001),
        "191 unexpected durable R2 receipt owner"
    );
    let bytes = receipt_bytes(b, uid, 16 << 10)?;
    ensure!(
        b.path
            == receipt_path(
                Path::new("/home/sol/.jetstreamer-private/r2-receipts"),
                epoch
            ),
        "191 noncanonical ready receipt"
    );
    let r = read_restore_receipt(
        b.path.parent().context("191 ready parent")?,
        "solana-archive-with-accounts-data",
        epoch,
    )?;
    ensure!(
        serde_json::from_slice::<Receipt>(&bytes)? == r
            && r.remote_sha256_readback
            && !r.archive_etag.is_empty()
            && r.verified_unix_seconds <= cutoff,
        "191 zero ETA lacks durable whole-object readback"
    );
    Ok(r)
}
fn ready_import_binding(r: &Receipt, public: &Value) -> Result<()> {
    let rows = public["outcome"]["members"]
        .as_array()
        .context("191 ready import member census")?;
    let matches = rows
        .iter()
        .filter(|m| m["epoch"] == r.epoch)
        .collect::<Vec<_>>();
    ensure!(
        matches.len() == 1
            && matches[0]["archive_sha256"] == r.archive_sha256
            && matches[0]["committed_archive"]["length"] == r.archive_length,
        "191 ready receipt does not match the native imported archive"
    );
    Ok(())
}
fn gate(b: &Bound, epoch: u64, stage: &str, tool: &GateTool, digest: &str) -> Result<()> {
    let qualified = match stage {
        "full" => Some((
            "verify_archive",
            "5fc5640254f6a065e96bf73ad951c9dacd57aa963b87a4379e1f27c6ebeb3574",
        )),
        "plugin" => Some((
            "horizon_pipeline",
            "e20892a111f8e26c8e25561a939eaf171771789753059100510c936d92092137",
        )),
        _ => None,
    };
    if let Some((name, sha)) = qualified {
        ensure!(
            tool.verifier.path
                == Path::new(
                    "/usr/local/lib/jetstreamer/horizon-epoch198-compatible-verifiers-20261021-v1"
                )
                .join(name)
                && tool.verifier.sha256 == sha
                && tool.wrapper.path
                    == Path::new(
                        "/usr/local/lib/jetstreamer/horizon-cohort191-delivery-tools-20261023-v1/jetstreamer-horizon-verify-pair"
                    ),
            "191 verification receipt borrows an unqualified reader or native wrapper"
        );
    }
    for t in [&tool.verifier, &tool.wrapper] {
        ensure!(
            t.path.starts_with("/usr/local/lib/jetstreamer"),
            "191 undeployed gate tool"
        );
        member(&t.path, &t.sha256)?;
    }
    let directory = match stage {
        "full" => "/home/sol/.jetstreamer-private/final-audits/epochs-101-200-parallel-v1/receipts",
        "plugin" => "/home/sol/.jetstreamer-private/horizon-plugin-current-101-200-v2/receipts",
        "boundary" => "/home/sol/.jetstreamer-private/boundary-audits/receipts",
        _ => bail!("191 unknown verification gate"),
    };
    ensure!(
        b.path == Path::new(directory).join(format!("epoch-{epoch}.{stage}.ok")),
        "191 foreign gate receipt path"
    );
    let uid = fs::symlink_metadata(&b.path)?.uid();
    ensure!(matches!(uid, 0 | 1001), "191 gate writer differs");
    let bytes = receipt_bytes(b, uid, 512)?;
    let expected = format!(
        "{digest} {} {}\n",
        tool.verifier.sha256, tool.wrapper.sha256
    );
    ensure!(
        bytes == expected.as_bytes(),
        "191 independent {stage} receipt differs"
    );
    Ok(())
}
fn validate_claim_set(claims: &[Claim], eta: &BTreeMap<u64, u64>) -> Result<BTreeSet<u64>> {
    let working: BTreeSet<_> = eta
        .iter()
        .filter(|(_, n)| **n > 0)
        .map(|(e, _)| *e)
        .collect();
    ensure!(
        claims.iter().map(|c| c.epoch).eq(working.iter().copied()),
        "191 missing/duplicate/reordered active owner or owner for ready member"
    );
    for c in claims {
        phase_scope(c)?;
    }
    Ok(working)
}
fn validate_inputs(
    p: &Capture,
    forecast: &jetstreamer_horizon_observe::cohort191_delivery_model::Plan,
    eta: &BTreeMap<u64, u64>,
    cutoff: u64,
) -> Result<BTreeSet<u64>> {
    use jetstreamer_horizon_observe::cohort191_delivery_model::Work;
    ensure!(
        !forecast.boundary_gates_sidecar,
        "191 boundary dispatch must remain separate from publication"
    );
    let working = validate_claim_set(&p.claims, eta)?;
    ensure!(
        p.origins.keys().copied().eq(191..=194),
        "191 original cohort census differs"
    );
    ensure!(
        p.ready_receipts
            .keys()
            .copied()
            .eq(eta.iter().filter(|(_, n)| **n == 0).map(|(e, _)| *e)),
        "191 ready receipt/zero ETA census differs"
    );
    ensure!(
        p.gate_receipts.keys().all(|e| (191..=194).contains(e))
            && p.gate_tools
                .keys()
                .all(|s| matches!(s.as_str(), "full" | "plugin" | "boundary")),
        "191 foreign gate census"
    );
    for e in &forecast.epochs {
        original(&p.origins[&e.epoch], e.epoch, cutoff)?;
        if e.authenticated_ready_pair {
            ready(&p.ready_receipts[&e.epoch], e.epoch, cutoff)?;
            continue;
        }
        // Completed verification claims require actual independent receipts,
        // even when the owner is already uploading or waiting on another gate.
        let digest = if let Some(b) = &p.public_batch {
            let bytes = receipt_bytes(b, 1001, 4 << 20)?;
            let v: Value = serde_json::from_slice(&bytes)?;
            v["outcome"]["members"]
                .as_array()
                .context("191 public member digests")?
                .iter()
                .find(|m| m["epoch"] == e.epoch)
                .context("191 missing public digest")?["archive_sha256"]
                .as_str()
                .context("191 public digest")?
                .to_owned()
        } else {
            String::new()
        };
        for (stage, work, required) in [
            ("full", &e.full, true),
            ("plugin", &e.plugin, true),
            ("boundary", &e.boundary, forecast.boundary_gates_sidecar),
        ] {
            if required && matches!(work, Work::Complete) {
                ensure!(
                    is_lower_hex(&digest, 64),
                    "191 completed gate without imported digest"
                );
                gate(
                    p.gate_receipts
                        .get(&e.epoch)
                        .and_then(|m| m.get(stage))
                        .context("191 gate receipt absent")?,
                    e.epoch,
                    stage,
                    p.gate_tools.get(stage).context("191 gate tool absent")?,
                    &digest,
                )?;
            }
        }
        let c = p
            .claims
            .iter()
            .find(|c| c.epoch == e.epoch)
            .context("191 working owner")?;
        match c.phase.as_str() {
            "producer-finalization" => ensure!(
                matches!(forecast.finalization, Work::Active { .. })
                    && matches!(forecast.import, Work::Queued { .. }),
                "191 finalization forecast owner differs"
            ),
            "controller-import-handoff" => ensure!(
                matches!(forecast.finalization, Work::Complete)
                    && matches!(forecast.import, Work::Queued { .. }),
                "191 pending import forecast differs"
            ),
            "local-publication" => ensure!(
                matches!(forecast.finalization, Work::Complete)
                    && matches!(forecast.import, Work::Active { .. }),
                "191 import forecast owner differs"
            ),
            "full-verification" | "plugin-verification" => {
                let (stage, work) = if c.phase == "full-verification" {
                    ("full", &e.full)
                } else {
                    ("plugin", &e.plugin)
                };
                ensure!(
                    matches!(forecast.import, Work::Complete)
                        && matches!(work, Work::Active { .. })
                        && c.program
                            .as_ref()
                            .is_some_and(|b| p.gate_tools.get(stage).is_some_and(|t| t
                                .wrapper
                                .path
                                == b.path
                                && t.wrapper.sha256 == b.sha256)),
                    "191 verifier forecast/program differs"
                );
            }
            "upload-readback" => ensure!(
                matches!(forecast.import, Work::Complete)
                    && matches!(e.full, Work::Complete)
                    && matches!(e.plugin, Work::Complete)
                    && (matches!(e.upload, Work::Active { .. })
                        || matches!(e.readback, Work::Active { .. })
                        || matches!(e.source_revalidation_and_sidecar, Work::Active { .. })),
                "191 uploader forecast lacks independent gates or actual active sync"
            ),
            "cohort191-delivery" => ensure!(
                p.queue.is_some()
                    && matches!(forecast.finalization, Work::Complete)
                    && matches!(forecast.import, Work::Complete),
                "191 live queue has not inherited authenticated completed import"
            ),
            _ => bail!("191 unsupported queued/legacy owner"),
        }
    }
    Ok(working)
}
pub(super) fn validate_event(v: &Value, cutoff: u64) -> Result<()> {
    ensure!(
        v["schema"] == EVENT_SCHEMA
            && v["first_epoch"] == 191
            && v["last_epoch"] == 194
            && v["sample_unix_seconds"] == cutoff
            && v["resource_samples"] == 0,
        "191 event scope/time changed"
    );
    for flag in [
        "publication_authorized",
        "replay_launch_authorized",
        "r2_mutations",
        "archive_readiness_claimed",
    ] {
        ensure!(v[flag] == false, "191 event grants {flag}");
    }
    let plan: Bound = serde_json::from_value(v["capture_plan"].clone())?;
    let p: Capture = serde_json::from_value(bound(&plan, true)?)?;
    let program: PathBuf = serde_json::from_value(v["capture_program"].clone())?;
    member(
        &program,
        v["capture_self_sha256"]
            .as_str()
            .context("191 capture executable digest")?,
    )?;
    for (name, expected) in [
        ("observer", json!(p.observer)),
        ("forecast", json!(p.forecast)),
        ("origins", json!(p.origins)),
        ("claims", json!(p.claims)),
        ("source_batch", json!(p.source_batch)),
        ("public_batch", json!(p.public_batch)),
        ("gate_receipts", json!(p.gate_receipts)),
        ("gate_tools", json!(p.gate_tools)),
        ("ready_receipts", json!(p.ready_receipts)),
        ("queue", json!(p.queue)),
        (
            "source_revalidation_policy",
            json!(p.source_revalidation_policy),
        ),
    ] {
        ensure!(
            v[name] == expected,
            "191 event differs from sealed capture plan:{name}"
        );
    }
    let observer = bound(&p.observer, false)?;
    ensure!(
        v["sampled_at_utc"] == observer["recorded_at_utc"]
            && observer["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && fleet::utc_seconds(v["sampled_at_utc"].as_str().context("191 event time")?)?
                == cutoff,
        "191 event does not bind its real coordinated sample"
    );
    let forecast = serde_json::from_value(bound(&p.forecast, true)?)?;
    let eta = jetstreamer_horizon_observe::cohort191_delivery_model::forecast(&forecast)?;
    ensure!(
        v["estimated_remaining_millis"] == json!(eta),
        "191 event ETA differs from bound forecast"
    );
    validate_inputs(&p, &forecast, &eta, cutoff)?;
    jetstreamer_horizon_observe::cohort191_delivery_model::validate_native_terminal(
        &v["native_events"],
        cutoff,
    )?;
    let mut records = vec![v["native_events"]["root"].clone()];
    records.extend(
        v["native_events"]["closes"]
            .as_array()
            .context("191 event closes")?
            .iter()
            .cloned(),
    );
    ensure!(
        roots(&records, cutoff)? == v["native_events"],
        "191 native terminal proof differs"
    );
    ensure!(
        p.schema == "jetstreamer-cohort191-delivery-capture-plan-v2",
        "191 capture plan schema differs"
    );
    let all_final =
        !p.claims.is_empty() && p.claims.iter().all(|c| c.phase == "producer-finalization");
    if all_final {
        ensure!(
            v["controller_handoff"].is_null()
                && p.source_batch.is_none()
                && p.public_batch.is_none(),
            "191 closing parent acquired a fabricated batch"
        );
    } else {
        let (bytes, state) = state_bytes()?;
        ensure!(
            v["controller_handoff"]["state"] == state
                && v["controller_handoff"]["sha256"] == hex_lower(&Sha256::digest(&bytes))
                && v["controller_handoff"]["producer_terminal"] == manager_terminal(cutoff)?,
            "191 captured terminal/custody state changed"
        );
    }
    let regenerated = capture(&p)?;
    for (key, expected) in regenerated.as_object().context("191 regenerated event")? {
        if key == "queue_observation" && !expected.is_null() {
            let mut actual = expected.clone();
            let mut prior = v[key].clone();
            for name in ["current_head", "post_cutoff_transition", "metadata_clients"] {
                actual
                    .as_object_mut()
                    .context("191 current queue proof")?
                    .remove(name);
                prior
                    .as_object_mut()
                    .context("191 captured queue proof")?
                    .remove(name);
            }
            ensure!(
                actual == prior,
                "191 cutoff queue revision/owner/task proof changed"
            );
        } else {
            ensure!(
                v[key] == *expected,
                "191 native event differs from bound capture:{key}"
            );
        }
    }
    Ok(())
}
fn tail_budget(allowance: u64, minimum: u64, elapsed: u64) -> Result<u64> {
    ensure!(
        allowance > 0 && minimum > 0 && minimum <= allowance,
        "191 tail policy has invalid positive budgets"
    );
    if elapsed < allowance {
        Ok((allowance - elapsed).max(minimum))
    } else {
        minimum
            .checked_add(elapsed - allowance)
            .context("191 overdue tail estimate overflow")
    }
}
fn provisional_tail(b: &Bound, started: u64, cutoff: u64) -> Result<u64> {
    let policy = bound(b, true)?;
    ensure!(
        policy["schema"] == "jetstreamer-cohort191-source-revalidation-policy-v2"
            && policy["epochs"] == json!([191, 192, 193, 194])
            && policy["publication_authorized"] == false
            && policy["r2_mutations"] == false
            && policy["estimate_basis"]
                .as_str()
                .is_some_and(|s| !s.trim().is_empty()),
        "191 source-revalidation policy is foreign or authorizing"
    );
    let evidence: Vec<Bound> = serde_json::from_value(policy["evidence"].clone())?;
    ensure!(
        !evidence.is_empty() && evidence.len() <= 16,
        "191 source tail has no qualified evidence"
    );
    for b in evidence {
        bound(&b, false)?;
    }
    tail_budget(
        policy["provisional_allowance_millis"]
            .as_u64()
            .context("191 tail allowance")?,
        policy["minimum_remaining_millis"]
            .as_u64()
            .context("191 tail floor")?,
        cutoff
            .checked_sub(started)
            .context("191 source-revalidation starts after cutoff")?,
    )
}
fn progress_remaining(rows: &[(u64, u64, u64)], total: u64, cutoff_millis: u64) -> Result<u64> {
    ensure!(
        rows.len() >= 2 && total > 0,
        "191 sync has insufficient own-phase progress"
    );
    for pair in rows.windows(2) {
        ensure!(
            pair[0].0 < pair[1].0
                && pair[0].1 < pair[1].1
                && pair[0].2 < pair[1].2
                && pair[1].1 <= total,
            "191 sync progress reset, duplicate or impossible byte count"
        );
    }
    let first = rows[rows.len() - 2];
    let last = rows[rows.len() - 1];
    let dt = last.2 - first.2;
    let bytes = last.1 - first.1;
    let left = total
        .checked_sub(last.1)
        .context("191 progress exceeds archive")?;
    let estimate = (u128::from(left) * u128::from(dt)).div_ceil(u128::from(bytes));
    let estimate: u64 = estimate
        .try_into()
        .context("191 progress projection overflow")?;
    let stall = cutoff_millis
        .checked_sub(last.0)
        .context("191 progress after cutoff")?;
    estimate
        .max(1)
        .checked_add(stall)
        .context("191 stall projection overflow")
}
fn sync_observation(
    c: &Claim,
    u: &Value,
    e: &jetstreamer_horizon_observe::cohort191_delivery_model::Epoch,
    cutoff: u64,
    tail_policy: Option<&Bound>,
) -> Result<Value> {
    use jetstreamer_horizon_observe::cohort191_delivery_model::Work;
    let stage = if matches!(e.upload, Work::Active { .. }) {
        "upload"
    } else if matches!(e.readback, Work::Active { .. }) {
        "readback"
    } else if matches!(e.source_revalidation_and_sidecar, Work::Active { .. }) {
        "source-revalidation"
    } else {
        bail!("191 sync phase has no actual active work");
    };
    let result = Command::new("/usr/bin/journalctl")
        .args([
            "--no-pager",
            "--output=json",
            "-u",
            &c.unit,
            &format!("_SYSTEMD_INVOCATION_ID={}", c.invocation_id),
            "--until",
            &format!("@{cutoff}"),
        ])
        .output()?;
    ensure!(
        result.status.success() && result.stdout.len() <= 8 << 20,
        "191 sync journal unavailable/oversized"
    );
    let archive = archives(c.epoch, "upload-readback");
    let length = regular_identity(&archive)?.length;
    let key = format!("epoch-{}.jet", c.epoch);
    let event = match stage {
        "upload" => "r2-upload-progress",
        "readback" => "r2-readback-progress",
        _ => "r2-readback-verified",
    };
    let bytes = if stage == "upload" {
        "acknowledged_bytes"
    } else {
        "hashed_bytes"
    };
    let pid = u["MainPID"].as_str().context("191 native sync PID")?;
    let uid = fs::symlink_metadata(format!("/proc/{pid}"))?
        .uid()
        .to_string();
    let mut selected = Vec::new();
    let mut progress = Vec::new();
    for line in result
        .stdout
        .split(|b| *b == b'\n')
        .filter(|b| !b.is_empty())
    {
        let row: Value = serde_json::from_slice(line)?;
        let Some(message) = row["MESSAGE"].as_str() else {
            continue;
        };
        let Ok(v) = serde_json::from_str::<Value>(message) else {
            continue;
        };
        if v["key"] != key {
            continue;
        }
        if stage == "upload"
            && matches!(
                v["event"].as_str(),
                Some("r2-readback-start" | "r2-readback-progress" | "r2-readback-verified")
            )
        {
            bail!("191 upload forecast ignored an actual readback handoff");
        }
        if stage == "readback" && v["event"] == "r2-readback-verified" {
            bail!("191 readback forecast ignored actual source-revalidation handoff");
        }
        if v["event"] != event {
            continue;
        }
        ensure!(
            row["_SYSTEMD_UNIT"] == c.unit
                && row["_SYSTEMD_INVOCATION_ID"] == c.invocation_id
                && row["_PID"] == pid
                && row["_UID"] == uid
                && v["total_bytes"] == length
                && v["whole_file_sha256_verified"] == (stage == "source-revalidation"),
            "191 sync journal belongs to another process/object"
        );
        let time = row["__REALTIME_TIMESTAMP"]
            .as_str()
            .context("191 sync timestamp")?
            .parse::<u64>()?;
        ensure!(
            time > 0
                && time
                    <= cutoff
                        .checked_mul(1_000_000)
                        .context("191 progress cutoff")?,
            "191 future progress"
        );
        progress.push((
            time / 1000,
            v[bytes].as_u64().context("191 sync byte progress")?,
            v["elapsed_millis"].as_u64().context("191 sync elapsed")?,
        ));
        selected.push(row);
    }
    let cutoff_ms = cutoff.checked_mul(1000).context("191 sync clock")?;
    let remaining = if stage == "source-revalidation" {
        ensure!(
            progress.len() == 1 && progress[0].1 == length,
            "191 tail lacks one whole-object verified readback marker"
        );
        provisional_tail(
            tail_policy.context("191 tail requires qualified provisional policy")?,
            progress[0].0,
            cutoff_ms,
        )?
    } else {
        progress_remaining(&progress, length, cutoff_ms)?
    };
    let expected = match stage {
        "upload" => &e.upload,
        "readback" => &e.readback,
        _ => &e.source_revalidation_and_sidecar,
    };
    ensure!(
        matches!(expected,Work::Active {remaining_millis} if *remaining_millis == remaining),
        "191 sync forecast is not its own measured phase rate plus stall age"
    );
    Ok(
        json!({"phase":stage,"unit":c.unit,"invocation_id":c.invocation_id,"pid":pid,
        "key":key,"total_bytes":length,"remaining_millis":remaining,"markers":selected,
        "resource_samples":0,"integrity_receipt":false}),
    )
}
fn capture(p: &Capture) -> Result<Value> {
    let o = bound(&p.observer, false)?;
    let sample = o["recorded_at_utc"]
        .as_str()
        .context("191 coordinated sample")?;
    let cutoff = fleet::utc_seconds(sample)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    ensure!(
        p.schema == "jetstreamer-cohort191-delivery-capture-plan-v2"
            && cutoff <= now
            && now - cutoff <= 1800
            && p.origins.keys().copied().eq(191..=194),
        "191 capture scope/staleness"
    );
    let history = inputs()?;
    let events = if let Some(proof) = &p.native_pending_proof {
        import_pending::retained_events(proof, p, cutoff)?
    } else {
        native_events(cutoff)?
    };
    let forecast: jetstreamer_horizon_observe::cohort191_delivery_model::Plan =
        serde_json::from_value(bound(&p.forecast, true)?)?;
    let eta = jetstreamer_horizon_observe::cohort191_delivery_model::forecast(&forecast)?;
    let working = validate_inputs(p, &forecast, &eta, cutoff)?;
    let mut census = BTreeMap::new();
    let mut sync_observations = BTreeMap::new();
    for c in &p.claims {
        phase_scope(c)?;
        let u = fleet::unit(&c.unit)?;
        live(&u, c)?;
        program(c, &u)?;
        ensure!(
            pipeline_status::manager_start(&c.unit, &c.invocation_id)?
                <= cutoff
                    .checked_mul(1000)
                    .context("191 phase clock overflow")?,
            "191 phase began after coordinated sample; do not backdate"
        );
        if c.phase == "upload-readback" {
            let e = forecast
                .epochs
                .iter()
                .find(|e| e.epoch == c.epoch)
                .context("191 sync forecast row")?;
            sync_observations.insert(
                c.epoch,
                sync_observation(c, &u, e, cutoff, p.source_revalidation_policy.as_ref())?,
            );
        }
        census.insert(c.unit.clone(), u);
    }
    let queue_observation = queue::observe(p, &forecast, &census, cutoff)?;
    let producer = fleet::unit(UNIT)?;
    let controller = fleet::unit(CONTROLLER)?;

    let all_final =
        !p.claims.is_empty() && p.claims.iter().all(|c| c.phase == "producer-finalization");
    let require_live_controller = all_final
        || p.claims.iter().any(|c| {
            matches!(
                c.phase.as_str(),
                "controller-import-handoff" | "local-publication"
            )
        });
    let controller_history =
        controller_lifecycle(&controller, &history, cutoff, require_live_controller)?;
    let state = if all_final {
        ensure!(
            producer["MainPID"] == "2189644"
                && prefix(&producer["ExecStart"])
                    == prefix(&history["current_units"][UNIT]["ExecStart"]),
            "191 original parent changed"
        );
        for (i, row) in events["closes"].as_array().unwrap().iter().enumerate() {
            let f = cohort198_finalization::fields(
                row["MESSAGE"].as_str().unwrap(),
                "horizon archive complete: ",
            )?;
            ensure!(
                regular_identity(&archives(191 + i as u64, "producer-finalization"))?.length
                    == cohort198_finalization::integer(&f, "bytes")?,
                "191 closing file changed"
            );
        }
        Value::Null
    } else {
        let terminal = manager_terminal(cutoff)?;
        ensure!(
            producer["MainPID"] == "0"
                && matches!(producer["ActiveState"].as_str(), Some("inactive"))
                && (producer["InvocationID"] == IID
                    || (producer["LoadState"] == "not-found" && producer["InvocationID"] == "")),
            "191 producer not cleanly terminal"
        );
        let (bytes, s) = state_bytes()?;
        let a = &s["assignments"]["lane-a"];
        let pending = p.claims.iter().any(|c| {
            matches!(
                c.phase.as_str(),
                "controller-import-handoff" | "local-publication"
            )
        });
        let source = batch(
            p.source_batch
                .as_ref()
                .context("191 source batch required")?,
            false,
            &if pending {
                working.clone()
            } else {
                BTreeSet::new()
            },
        )?;
        if pending {
            ensure!(
                a["first_epoch"] == 191
                    && a["last_epoch"] == 194
                    && a["unit"] == UNIT
                    && a["pid"] == 2189644
                    && a["source_recovery"] != true
                    && a["failure"].is_null()
                    && a["receipt"].as_str() == p.source_batch.as_ref().unwrap().path.to_str()
                    && matches!(a["phase"].as_str(), Some("staged" | "importing")),
                "191 pending/import assignment changed"
            );
            for c in &p.claims {
                if c.phase == "local-publication" {
                    ensure!(
                        a["phase"] == "importing"
                            && a["import_unit"] == c.unit
                            && s["import_owner"] == "lane-a",
                        "191 actual importer missing from root state"
                    );
                    let expected = format!(
                        "{{ path={DEPLOY}/jetstreamer-node ; argv[]={DEPLOY}/jetstreamer-node 191-194 /home/sol/horizon --verify --recover-staged-cohort-only --cohort-manifest={DEPLOY}/preflight-191-194-v4.json --cohort-manifest-fingerprint={FINGERPRINT} --source-cohort-receipt={} --publish-through-epoch=194",
                        p.source_batch.as_ref().unwrap().path.display()
                    );
                    ensure!(
                        prefix(&Value::String(c.expected_exec_start.clone()))
                            == Some(expected.as_str()),
                        "191 importer command differs"
                    );
                }
            }
        } else {
            let public = batch(
                p.public_batch
                    .as_ref()
                    .context("191 imported public batch required")?,
                true,
                &working,
            )?;
            // Once an epoch has actual ready evidence, its bytes may be
            // absent only under a separately qualified retirement policy. Its
            // durable proof must still match this exact original native import;
            // a canonical receipt for another payload never substitutes for it.
            for (epoch, receipt) in &p.ready_receipts {
                ready_import_binding(&ready(receipt, *epoch, cutoff)?, &public)?;
            }
            let complete = &s["completed"]["191-194"];
            ensure!(
                complete["receipt"].as_str() == p.public_batch.as_ref().unwrap().path.to_str()
                    && complete["receipt_sha256"] == p.public_batch.as_ref().unwrap().sha256,
                "191 public root attestation missing"
            );
            for n in 0..4 {
                ensure!(
                    source["outcome"]["members"][n]["archive_sha256"]
                        == public["outcome"]["members"][n]["archive_sha256"],
                    "191 import semantics changed"
                );
            }
            for name in [
                ".jetstreamer-archive-batch",
                ".jetstreamer-archive-batch-outcome",
            ] {
                ensure!(
                    fs::symlink_metadata(Path::new("/home/sol/horizon").join(name))
                        .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
                    "191 public transaction pending"
                );
            }
        }
        ensure!(
            read_stable_bounded(Path::new(STATE), 2 << 20, "191 state recheck")? == bytes,
            "191 controller assignment changed"
        );
        json!({"state":s,"sha256":hex_lower(&Sha256::digest(&bytes)),"producer_terminal":terminal})
    };
    for c in &p.claims {
        ensure!(
            fleet::unit(&c.unit)? == census[&c.unit],
            "191 owner changed during capture"
        );
    }
    let origin_start = pipeline_status::manager_start(UNIT, IID)?;
    let elapsed = cutoff
        .checked_mul(1000)
        .context("191 sample clock overflow")?
        .checked_sub(origin_start)
        .context("191 original producer starts after sample")?;
    let mut artifacts = BTreeMap::new();
    for c in &p.claims {
        let path = archives(c.epoch, &c.phase);
        let identity = regular_identity(&path)?;
        artifacts.insert(
            c.epoch,
            json!({"path":path,"length":identity.length,"identity":identity}),
        );
    }
    let v = json!({"schema":EVENT_SCHEMA,"first_epoch":191,"last_epoch":194,"sampled_at_utc":sample,"sample_unix_seconds":cutoff,
        "observer":p.observer,"origins":p.origins,"forecast":p.forecast,"estimated_remaining_millis":eta,"claims":p.claims,"unit_census":census,
        "sync_observations":sync_observations,"origin_start_unix_millis":origin_start,"elapsed_execution_millis":elapsed,"archives":artifacts,"native_events":events,"controller":controller,"controller_lifecycle":controller_history,"producer":producer,"controller_handoff":state,"source_batch":p.source_batch,"public_batch":p.public_batch,
        "gate_receipts":p.gate_receipts,"gate_tools":p.gate_tools,"ready_receipts":p.ready_receipts,
        "queue":p.queue,"queue_observation":queue_observation,"source_revalidation_policy":p.source_revalidation_policy,"resource_samples":0,"publication_authorized":false,"replay_launch_authorized":false,"r2_mutations":false,"archive_readiness_claimed":false});
    Ok(v)
}
pub(super) fn run() -> Result<()> {
    let a: Vec<_> = env::args().collect();
    ensure!(
        (a.len() == 7 || (a.len() == 8 && a[7] == "--check-only"))
            && a[3] == "--plan-sha256"
            && a[5] == "--self-sha256"
            && unsafe { libc::geteuid() } == 0,
        "observe-delivery-191 PLAN --plan-sha256 SHA --self-sha256 SHA [--check-only]"
    );
    member(&fs::read_link("/proc/self/exe")?, &a[6])?;
    let b = Bound {
        path: a[2].clone().into(),
        sha256: a[4].clone(),
    };
    let p: Capture = serde_json::from_value(bound(&b, true)?)?;
    ensure!(
        p.output.parent().and_then(Path::parent) == Some(Path::new("/var/lib/jetstreamer"))
            && p.output
                .parent()
                .and_then(Path::file_name)
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with("horizon-cohort191-delivery-")),
        "191 output namespace differs"
    );
    let mut v = capture(&p)?;
    v["capture_plan"] = json!(b);
    v["capture_self_sha256"] = json!(a[6]);
    v["capture_program"] = json!(fs::read_link("/proc/self/exe")?);
    validate_event(
        &v,
        fleet::utc_seconds(v["sampled_at_utc"].as_str().context("191 sample")?)?,
    )?;
    if a.len() == 8 {
        println!("191 capture preflight passed; no writes");
        return Ok(());
    }
    fleet::persist(&p.output, &v)?;
    println!("{}", p.output.display());
    Ok(())
}

pub(super) fn fleet_proof(
    epoch: u64,
    phase: &str,
    unit: &str,
    iid: &str,
    evidence: &Value,
    census: &BTreeMap<String, Value>,
    sample: u64,
) -> Result<Option<Value>> {
    if !(191..=194).contains(&epoch) || evidence["schema"] != EVENT_SCHEMA {
        return Ok(None);
    }
    validate_event(evidence, sample)?;
    let claims: Vec<Claim> = serde_json::from_value(evidence["claims"].clone())?;
    let c = claims
        .iter()
        .find(|c| c.epoch == epoch)
        .context("191 claim missing")?;
    ensure!(
        c.phase == phase
            && c.unit == unit
            && c.invocation_id == iid
            && evidence["unit_census"][unit] == census[unit],
        "191 event/live fleet differs"
    );
    live(&census[unit], c)?;
    program(c, &census[unit])?;
    Ok(Some(evidence.clone()))
}

pub(super) fn check() -> Result<()> {
    let a: Vec<_> = env::args().collect();
    ensure!(
        a.len() == 5 && a[3] == "--event-sha256" && unsafe { libc::geteuid() } == 0,
        "check-delivery-191 EVENT --event-sha256 SHA"
    );
    let v = bound(
        &Bound {
            path: a[2].clone().into(),
            sha256: a[4].clone(),
        },
        false,
    )?;
    let cutoff = fleet::utc_seconds(v["sampled_at_utc"].as_str().context("191 event sample")?)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    ensure!(
        cutoff <= now && now - cutoff <= 1800,
        "191 event is stale/future"
    );
    validate_event(&v, cutoff)?;
    let claims: Vec<Claim> = serde_json::from_value(v["claims"].clone())?;
    for c in claims {
        let u = fleet::unit(&c.unit)?;
        live(&u, &c)?;
        program(&c, &u)?;
        ensure!(u == v["unit_census"][&c.unit], "191 event owner changed");
    }
    println!("191 native delivery custody passed; no writes");
    Ok(())
}

/// Pre-launch custody gate for the independent 191 full/plugin dispatcher.
/// Does not launch, reserve resources, mint verifier receipts, or mutate R2.
pub(super) fn dispatch_import_check(
    source_batch: &Bound,
    public_batch: &Bound,
    materialized: &BTreeSet<u64>,
) -> Result<Value> {
    ensure!(
        !materialized.is_empty() && materialized.iter().all(|e| (191..=194).contains(e)),
        "191 dispatch materialized epoch scope differs"
    );
    let history = inputs()?;
    let controller = fleet::unit(CONTROLLER)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let lifecycle = controller_lifecycle(&controller, &history, now, false)?;
    let (bytes, state) = state_bytes()?;
    let source = batch(source_batch, false, &BTreeSet::new())?;
    let public = batch(public_batch, true, materialized)?;
    ensure!(
        source["root_checkpoint_gate"] == public["root_checkpoint_gate"],
        "191 import changed native root-checkpoint semantics"
    );
    for n in 0..4 {
        ensure!(
            source["outcome"]["members"][n]["archive_sha256"]
                == public["outcome"]["members"][n]["archive_sha256"],
            "191 import changed archive semantics"
        );
    }
    let complete = &state["completed"]["191-194"];
    let destination = fs::symlink_metadata("/home/sol/horizon")?;
    let receipt = fs::symlink_metadata(&public_batch.path)?;
    ensure!(
        complete["first_epoch"] == 191
            && complete["last_epoch"] == 194
            && complete["epochs"] == json!([191, 192, 193, 194])
            && complete["receipt"].as_str() == public_batch.path.to_str()
            && complete["receipt_sha256"] == public_batch.sha256
            && complete["destination_identity"]["device"] == destination.dev()
            && complete["destination_identity"]["inode"] == destination.ino()
            && complete["receipt_identity"]["device"] == receipt.dev()
            && complete["receipt_identity"]["inode"] == receipt.ino()
            && complete["receipt_identity"]["length"] == receipt.len()
            && complete["receipt_identity"]["modified_seconds"] == receipt.mtime()
            && complete["receipt_identity"]["modified_nanoseconds"] == receipt.mtime_nsec(),
        "191 public import lacks the exact native root-controller attestation"
    );
    for name in [
        ".jetstreamer-archive-batch",
        ".jetstreamer-archive-batch-outcome",
    ] {
        ensure!(
            fs::symlink_metadata(Path::new("/home/sol/horizon").join(name))
                .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
            "191 public transaction pending"
        );
    }
    ensure!(
        state_bytes()?.0 == bytes
            && fleet::unit(CONTROLLER)? == controller
            && controller_properties()? == lifecycle["unit"],
        "191 import custody changed during dispatch admission"
    );
    Ok(
        json!({"schema":"jetstreamer-cohort191-import-custody-v2","source_batch":source_batch,
        "public_batch":public_batch,"materialized_epochs":materialized,"public_members":public["outcome"]["members"],
        "controller":controller,"controller_lifecycle":lifecycle,"controller_state_sha256":hex_lower(&Sha256::digest(&bytes)),
        "native_import_attestation":complete,"publication_authorized":false,"launch_authorized":false,
        "r2_mutations":false,"new_resource_samples":0}),
    )
}

pub(super) fn capture_terminal_transition() -> Result<()> {
    terminal_transition::run()
}
pub(super) fn capture_import_pending() -> Result<()> {
    import_pending::run(false)
}
pub(super) fn observe_import_pending() -> Result<()> {
    import_pending::run(true)
}
pub(super) fn queue_scope(phase: &str, unit: &str) -> bool {
    queue::scope(phase, unit)
}
pub(super) fn queue_plan_check(plan: &Bound, materialized: &BTreeSet<u64>) -> Result<Value> {
    queue::plan_check(plan, materialized)
}
pub(super) fn queue_admission_check(
    admission: &Bound,
    plan: &Bound,
    iid: &str,
    epoch: u64,
    stage: &str,
) -> Result<Value> {
    queue::admission_check(admission, plan, iid, epoch, stage)
}
pub(super) fn queue_gate(
    receipt: &Bound,
    epoch: u64,
    stage: &str,
    wrapper: &Bound,
    verifier: &Bound,
    digest: &str,
) -> Result<()> {
    gate(
        receipt,
        epoch,
        stage,
        &GateTool {
            verifier: verifier.clone(),
            wrapper: wrapper.clone(),
        },
        digest,
    )
}
pub(super) fn queue_ready(receipt: &Bound, epoch: u64, cutoff: u64) -> Result<Receipt> {
    ready(receipt, epoch, cutoff)
}

pub(super) fn queue_sync_epoch(phase: &str, unit: &str) -> Option<u64> {
    queue::sync_epoch(phase, unit)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn claim(epoch: u64) -> Claim {
        Claim {
            epoch,
            phase: "producer-finalization".into(),
            unit: UNIT.into(),
            invocation_id: IID.into(),
            expected_exec_start: "bound command".into(),
            program: None,
        }
    }
    #[test]
    fn remaining_member_census_cannot_hide_queued_or_claim_ready_epochs() {
        let eta = BTreeMap::from([(191, 0), (192, 1), (193, 2), (194, 3)]);
        let good = vec![claim(192), claim(193), claim(194)];
        assert_eq!(
            validate_claim_set(&good, &eta).unwrap(),
            BTreeSet::from([192, 193, 194])
        );
        let mut bad = good.clone();
        bad.pop();
        assert!(validate_claim_set(&bad, &eta).is_err());
        let mut bad = good.clone();
        bad.insert(0, claim(191));
        assert!(validate_claim_set(&bad, &eta).is_err());
        let mut bad = good.clone();
        bad[1] = bad[0].clone();
        assert!(validate_claim_set(&bad, &eta).is_err());
        let mut bad = good;
        bad.swap(0, 1);
        assert!(validate_claim_set(&bad, &eta).is_err());
    }
    #[test]
    fn unfinished_native_import_tracks_retained_source_without_claiming_public_custody() {
        for e in 191..=194 {
            assert_eq!(
                archives(e, "local-publication"),
                archives(e, "controller-import-handoff")
            );
            assert!(archives(e, "local-publication").starts_with(LANE));
            assert_ne!(
                archives(e, "local-publication"),
                archives(e, "full-verification")
            );
            assert_eq!(
                archives(e, "full-verification"),
                Path::new("/home/sol/horizon").join(format!("epoch-{e}.jet"))
            );
            assert_eq!(
                archives(e, "upload-readback"),
                archives(e, "full-verification")
            );
        }
    }
    #[test]
    fn a_failed_legacy_watcher_is_not_a_native191_verifier() {
        let mut c = claim(191);
        c.phase = "full-verification".into();
        c.unit = "jetstreamer-horizon-audit-epochs182-200-v5.service".into();
        assert!(phase_scope(&c).is_err());
        c.unit = "horizon-full-verify-191-native191-20261023-v1.service".into();
        assert!(phase_scope(&c).is_err()); // No native-program binding.
        c.program = Some(Bound {
            path: "/usr/local/lib/jetstreamer/horizon-cohort191-delivery-tools-20261023-v1/jetstreamer-horizon-verify-pair".into(),
            sha256: "a".repeat(64),
        });
        phase_scope(&c).unwrap();
        c.invocation_id = "unknown".into();
        assert!(phase_scope(&c).is_err());
    }
    #[test]
    fn source_tail_provisional_allowance_never_silently_zeroes_or_hides_overrun() {
        assert_eq!(tail_budget(10000, 1000, 5000).unwrap(), 5000);
        assert_eq!(tail_budget(10000, 1000, 9500).unwrap(), 1000);
        assert_eq!(tail_budget(10000, 1000, 10000).unwrap(), 1000);
        assert_eq!(tail_budget(10000, 1000, 15000).unwrap(), 6000);
        assert!(tail_budget(0, 1000, 0).is_err());
        assert!(tail_budget(1000, 1001, 0).is_err());
    }
    #[test]
    fn upload_and_readback_have_independent_rates_and_stall_age() {
        let upload = [(1000, 10, 1000), (2000, 20, 2000)];
        let readback = [(1000, 10, 1000), (3000, 20, 3000)];
        assert_eq!(progress_remaining(&upload, 100, 2500).unwrap(), 8500);
        assert_eq!(progress_remaining(&readback, 100, 3500).unwrap(), 16500);
        assert_eq!(progress_remaining(&readback, 100, 5500).unwrap(), 18500);
        assert!(progress_remaining(&upload[..1], 100, 2500).is_err());
        assert!(progress_remaining(&[(1000, 20, 1000), (2000, 10, 2000)], 100, 2500).is_err());
        assert!(progress_remaining(&[(1000, 10, 1000), (2000, 110, 2000)], 100, 2500).is_err());
        assert!(progress_remaining(&readback, 100, 2999).is_err());
    }
    #[test]
    fn capture_cannot_grant_publication_or_fabricate_current_time() {
        let base = json!({"schema":EVENT_SCHEMA,"first_epoch":191,"last_epoch":194,
            "sample_unix_seconds":1,"resource_samples":0,"publication_authorized":false,
            "replay_launch_authorized":false,"r2_mutations":false,"archive_readiness_claimed":false});
        for flag in [
            "publication_authorized",
            "replay_launch_authorized",
            "r2_mutations",
            "archive_readiness_claimed",
        ] {
            let mut bad = base.clone();
            bad[flag] = json!(true);
            assert!(format!("{:#}", validate_event(&bad, 1).unwrap_err()).contains(flag));
        }
        assert!(validate_event(&base, 2).is_err());
    }
    fn terminal_controller_fixture() -> (Value, Value) {
        let command = "{ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 /sealed/controller --execute ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0 }";
        (
            json!({"Id":CONTROLLER,"LoadState":"loaded","InvocationID":CID,"NRestarts":"0",
            "ActiveState":"inactive","SubState":"dead","MainPID":"0","Result":"success","ExecMainStatus":"0",
            "ExecMainCode":"1","Job":"0","ControlGroup":"","SuccessExitStatus":"","ExecStart":command}),
            json!({"current_units":{CONTROLLER:{"ExecStart":command}}}),
        )
    }
    #[test]
    fn natural_terminal_controller_needs_real_exit0_and_exact_retained_identity() {
        let (good, history) = terminal_controller_fixture();
        terminal_controller_shape(&good, &history).unwrap();
        for (key, value) in [
            ("InvocationID", "replacement"),
            ("NRestarts", "1"),
            ("Result", "exit-code"),
            ("ExecMainStatus", "1"),
            ("ExecMainCode", "0"),
            ("Job", "23"),
            ("ControlGroup", "/new/job"),
            ("ActiveState", "failed"),
            ("ExecStart", "changed"),
            ("SuccessExitStatus", "1"),
        ] {
            let mut bad = good.clone();
            bad[key] = json!(value);
            assert!(terminal_controller_shape(&bad, &history).is_err(), "{key}");
        }
        let mut collected = good.clone();
        collected["LoadState"] = json!("not-found");
        collected["InvocationID"] = json!("");
        assert!(terminal_controller_shape(&collected, &history).is_err());
        cleared_controller_shape(&collected, &history).unwrap(); // Shape alone is NOT terminal proof.
        let mut cleared = good;
        cleared["ExecMainCode"] = json!("0");
        assert!(terminal_controller_shape(&cleared, &history).is_err());
        cleared_controller_shape(&cleared, &history).unwrap(); // Requires the prior actual capture as well.
    }
    #[test]
    fn natural_controller_pid1_proof_rejects_missing_duplicate_failed_and_restarted_history() {
        let event = json!({"UNIT":CONTROLLER,"_PID":"1","_UID":"0","INVOCATION_ID":CID,
            "MESSAGE_ID":"7ad2d189f7e94e70a38c781354912448","MESSAGE":format!("{CONTROLLER}: Deactivated successfully."),
            "__REALTIME_TIMESTAMP":"1000000"});
        assert_eq!(
            controller_manager_end(std::slice::from_ref(&event), 2).unwrap(),
            event
        );
        assert!(controller_manager_end(&[], 2).is_err());
        assert!(controller_manager_end(&[event.clone(), event.clone()], 2).is_err());
        assert!(controller_manager_end(std::slice::from_ref(&event), 0).is_err());
        for (key, value) in [
            ("_PID", "2"),
            ("_UID", "1001"),
            ("INVOCATION_ID", "replacement"),
            ("MESSAGE", "failed"),
        ] {
            let mut bad = event.clone();
            bad[key] = json!(value);
            assert!(controller_manager_end(&[bad], 2).is_err(), "{key}");
        }
        let mut restarted = event.clone();
        restarted["MESSAGE"] = json!("Started replacement");
        restarted["MESSAGE_ID"] = json!("other");
        restarted["__REALTIME_TIMESTAMP"] = json!("1500000");
        assert!(controller_manager_end(&[event, restarted], 2).is_err());
    }
    #[test]
    fn manifest_hash_decoder_rejects_invalid_alphabet_and_overflow() {
        assert_eq!(hash_bytes(&"1".repeat(32)).unwrap(), [0; 32]);
        assert!(hash_bytes(&"0".repeat(32)).is_err());
        assert!(hash_bytes(&"z".repeat(44)).is_err());
    }
    #[test]
    fn durable_ready_proof_cannot_borrow_another_imported_payload_after_local_retirement() {
        let r:Receipt=serde_json::from_value(json!({"schema":RECEIPT_SCHEMA,"bucket":"solana-archive-with-accounts-data","epoch":191,"archive_key":"epoch-191.jet","checksum_key":"epoch-191.jet.sha256","archive_length":123,"archive_sha256":"a".repeat(64),"archive_etag":"etag","r2_composite_sha256":null,"remote_sha256_readback":true,"multipart_part_size":64<<20,"verified_unix_seconds":1})).unwrap();
        let public = json!({"outcome":{"members":[{"epoch":191,"archive_sha256":"a".repeat(64),"committed_archive":{"length":123}}]}});
        // These are authenticated retained proof values, not paths to a local
        // archive: ongoing epochs still independently require materialization.
        ready_import_binding(&r, &public).unwrap();
        for (pointer, value) in [
            ("/outcome/members/0/archive_sha256", json!("b".repeat(64))),
            ("/outcome/members/0/committed_archive/length", json!(124)),
            ("/outcome/members/0/epoch", json!(192)),
        ] {
            let mut bad = public.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(ready_import_binding(&r, &bad).is_err());
        }
        let mut duplicate = public;
        let row = duplicate["outcome"]["members"][0].clone();
        duplicate["outcome"]["members"]
            .as_array_mut()
            .unwrap()
            .push(row);
        assert!(ready_import_binding(&r, &duplicate).is_err());
    }
}
