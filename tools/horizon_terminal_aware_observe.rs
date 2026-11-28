//! Preserve healthy singleton observations when a peer has become terminal.
//! Omission is telemetry only: never release resources or claim archive success.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

#[allow(dead_code)]
#[path = "../jetstreamer-horizon-observe/src/full265.rs"]
mod full265;
#[path = "../jetstreamer-horizon-observe/src/singleton247_phase.rs"]
mod singleton247_phase;

const OBSERVER: &str = "/var/lib/jetstreamer/horizon-full265-attempt3-consumers-20261120-v1/jetstreamer-horizon-observe";
const OBSERVER_SHA: &str = "673f779a402c8f6d4f7e957614e9583252f8d1d741f2fe0cb86e1627972c5107";
fn observer_image(qualified_native: bool) -> Result<(&'static str, &'static str)> {
    match (
        option_env!("HORIZON257_OBSERVER_PATH"),
        option_env!("HORIZON257_OBSERVER_SHA256"),
    ) {
        (Some(path), Some(sha))
            if Path::new(path).starts_with("/var/lib/jetstreamer")
                && sha.len() == 64
                && sha
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) =>
        {
            Ok((path, sha))
        }
        (None, None) if !qualified_native => Ok((OBSERVER, OBSERVER_SHA)),
        _ => anyhow::bail!("missing or invalid qualified observer binding"),
    }
}
fn staged_delivery_selected(config: &Value) -> Result<bool> {
    ensure!(
        config["successor247_claim"].is_null() || config["staged247_resource_only"] == true,
        "successor claim requires staged resource collection"
    );
    let Some(flag) = config.get("staged247_resource_only") else {
        return Ok(false);
    };
    let on = flag.as_bool().context("invalid staged247_resource_only")?;
    ensure!(
        !on || config["delivery247_resource_only"] != true,
        "duplicate delivery selections"
    );
    Ok(on)
}
#[path="horizon266_entry_registration.rs"]
mod full266;
const SEALER: &str =
    "/var/lib/jetstreamer/horizon251-published-sealer-20261118-v1/horizon251-sealer";
const SEALER_SHA: &str = "faf7aa8270b3472969bf394d4486cdf94445e30e4f15bc6acd38bed56880877a";
const PROPS: &str = "Id,LoadState,ActiveState,SubState,InvocationID,MainPID,ControlPID,NRestarts,Result,ExecMainCode,ExecMainStatus,ExecStart,ControlGroup";

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Bound {
    path: PathBuf,
    sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    config: Bound,
    handoff_plans: Vec<Bound>,
    #[serde(default)]
    native211_handoff: Option<Bound>,
    #[serde(default)]
    native265_handoff: Option<Bound>,
    #[serde(default)]
    native257_handoff: Option<Bound>,
    #[serde(default)]
    native266_handoff: Option<Bound>,
    #[serde(default)]
    native212_handoff: Option<Bound>,
    #[serde(default)]
    native261_handoff: Option<Bound>,
    #[serde(default)]
    singleton211_handoff: Option<Bound>,
    #[serde(default)]
    full266_entries: Option<Bound>,
    #[serde(default)]
    full228_entries: Option<Bound>,
    #[serde(default)]
    instruction266_registration: Option<Bound>,
    state_directory: PathBuf,
    deployment: PathBuf,
}
impl Plan {
    fn entry_pilots(&self) -> [(&full266::Pilot, Option<&Bound>); 3] {
        let instruction_pilot = self.instruction266_registration.as_ref()
            .map(|registration| full266::instruction_profile(&registration.path))
            .unwrap_or(&full266::SUCCESSOR266);
        [
            (&full266::FULL228, self.full228_entries.as_ref()),
            (&full266::FULL266, self.full266_entries.as_ref()),
            (instruction_pilot, self.instruction266_registration.as_ref()),
        ]
    }
}
fn sha(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
fn raw(p: &Path, limit: u64) -> Result<Vec<u8>> {
    ensure!(
        p.is_absolute() && p.canonicalize()? == p,
        "noncanonical input"
    );
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(p)?;
    let m = f.metadata()?;
    let identity = |m: &fs::Metadata| {
        (
            m.dev(),
            m.ino(),
            m.len(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
            m.mode(),
            m.nlink(),
        )
    };
    ensure!(
        m.is_file() && m.uid() == 0 && m.nlink() == 1 && m.mode() & 0o022 == 0 && m.len() <= limit,
        "unsafe input"
    );
    let mut b = Vec::new();
    (&mut f).take(limit + 1).read_to_end(&mut b)?;
    ensure!(
        b.len() as u64 <= limit
            && identity(&m) == identity(&f.metadata()?)
            && identity(&m) == identity(&fs::symlink_metadata(p)?),
        "input changed"
    );
    Ok(b)
}
fn bound(b: &Bound) -> Result<Value> {
    let bytes = raw(&b.path, 32 << 20)?;
    ensure!(sha(&bytes) == b.sha256, "bound input differs");
    Ok(serde_json::from_slice(&bytes)?)
}
fn save(dir: &Path, name: &str, value: &Value) -> Result<Bound> {
    let path = dir.join(name);
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    File::open(dir)?.sync_all()?;
    Ok(Bound {
        path,
        sha256: sha(&bytes),
    })
}
fn string<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str().with_context(|| format!("missing {k}"))
}
fn timestamp(s: &str) -> Result<u64> {
    ensure!(s.len() == 20 && s.is_ascii(), "noncanonical UTC timestamp");
    let s = std::ffi::CString::new(s)?;
    let format = c"%Y-%m-%dT%H:%M:%SZ";
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let end = unsafe { libc::strptime(s.as_ptr(), format.as_ptr(), &mut tm) };
    ensure!(
        !end.is_null() && unsafe { *end } == 0,
        "invalid UTC timestamp"
    );
    let seconds = unsafe { libc::timegm(&mut tm) };
    ensure!(seconds >= 0, "negative UTC timestamp");
    let mut result = [0_i8; 32];
    let n = unsafe { libc::strftime(result.as_mut_ptr(), result.len(), format.as_ptr(), &tm) };
    ensure!(
        n == 20 && unsafe { std::ffi::CStr::from_ptr(result.as_ptr()) } == s.as_c_str(),
        "normalized UTC timestamp differs"
    );
    Ok(seconds as u64)
}
fn due(config: &Value, previous: &Value, now: u64) -> Result<()> {
    ensure!(
        config["minimum_interval_seconds"] == 1800 && config["observation_reason"] == "routine",
        "only the existing routine cadence is supported"
    );
    let prior = timestamp(string(previous, "recorded_at_utc")?)?;
    let earliest = prior
        .checked_add(1800)
        .context("cadence overflow")?
        .max(timestamp(string(config, "not_before_utc")?)?);
    ensure!(now >= earliest, "routine observation is not due");
    Ok(())
}
fn properties(unit: &str) -> Result<Value> {
    let out = Command::new("/usr/bin/systemctl")
        .args(["show", unit, "--property", PROPS])
        .output()?;
    ensure!(out.status.success(), "unit observation failed");
    let mut map = BTreeMap::new();
    for line in std::str::from_utf8(&out.stdout)?.lines() {
        let (key, value) = line.split_once('=').context("invalid property")?;
        ensure!(map.insert(key, value).is_none(), "duplicate property");
    }
    Ok(serde_json::to_value(map)?)
}
#[derive(Debug, PartialEq)]
enum State {
    Live,
    Terminal,
}
fn classify(row: &Value, handoff: &Value, unit: &Value) -> Result<State> {
    ensure!(
        row["controller_unit"] == row["producer_unit"]
            && row["expected_controller_invocation_id"] == row["expected_producer_invocation_id"],
        "only exact singleton owners are supported"
    );
    ensure!(
        unit["LoadState"] == "loaded"
            && unit["Id"] == row["producer_unit"]
            && unit["InvocationID"] == row["expected_producer_invocation_id"]
            && unit["NRestarts"] == "0",
        "owner missing, replaced or restarted"
    );
    let prefix = string(handoff, "expected_exec_prefix")?;
    ensure!(
        string(unit, "ExecStart")?
            .starts_with(&format!("{prefix} ; ignore_errors=no ; start_time=")),
        "producer command differs"
    );
    if unit["ActiveState"] == "active" && unit["SubState"] == "running" {
        ensure!(
            string(unit, "MainPID")?.parse::<u64>()? > 1,
            "live owner lacks PID"
        );
        return Ok(State::Live);
    }
    ensure!(
        (unit["ActiveState"] == "inactive" && unit["SubState"] == "dead")
            || (unit["ActiveState"] == "failed" && unit["SubState"] == "failed"),
        "owner is transitioning, not terminal"
    );
    ensure!(
        unit["MainPID"] == "0" && unit["ControlPID"] == "0",
        "terminal owner still has a manager process"
    );
    // Result/code/status remain raw evidence, not a clean-completion claim.
    for field in ["Result", "ExecMainCode", "ExecMainStatus", "ControlGroup"] {
        string(unit, field)?;
    }
    Ok(State::Terminal)
}
const NATIVE211_UNIT: &str = "archive-211-v1616-native-input-actual-v1.service";
const NATIVE211_IID: &str = "9267f2c2c64949c29b9da7c27a46df94";
const NATIVE211_PID: u64 = 1264515;
const NATIVE211_HANDOFF: &str =
    "/var/lib/jetstreamer/horizon-native211-execution-launch1810-v3/guarded-startup-handoff.json";
const NATIVE211_HANDOFF_SHA: &str =
    "409b5692303d4e6b59d463806ad447dfe84cd0e4e01733fd739f843d2622ce07";
fn native211_row() -> Value {
    json!({"epoch":211,"unit":NATIVE211_UNIT,"expected_invocation_id":NATIVE211_IID,"main_pid":NATIVE211_PID,
        "scratch_path":"/home/ubuntu/.jetstreamer-private/native-input211-v1616-capped-v1/scratch",
        "executable":"/var/lib/jetstreamer/horizon-211-native-input-gated-20261119-v1/native-input-test",
        "executable_sha256":"2b1c0dd8b8cfcf0bbb80e52864c4b78a8348b1bc96dc97cbdfc4fee1094b8773"})
}
fn native211_pass_through(
    config: &Value,
    reference: Option<&Bound>,
    handoff: Option<&Value>,
) -> Result<()> {
    // Native cold-input observation has its own closed consumer. Never put this
    // owner into diagnostic_replays, which has different replay tuple semantics.
    let native = config
        .get("native_input_diagnostics")
        .cloned()
        .unwrap_or_else(|| json!([]));
    if native == json!([]) {
        ensure!(
            reference.is_none() && handoff.is_none(),
            "unused native211 handoff"
        );
        return Ok(());
    }
    ensure!(
        native == json!([native211_row()]),
        "only the exact admitted native211 diagnostic is supported"
    );
    let b = reference.context("native211 handoff binding required")?;
    ensure!(
        b.path == Path::new(NATIVE211_HANDOFF) && b.sha256 == NATIVE211_HANDOFF_SHA,
        "native211 handoff substitution"
    );
    let h = handoff.context("native211 handoff evidence required")?;
    ensure!(
        h["schema"] == "horizon-native211-guarded-startup-v1"
            && h["unit"] == NATIVE211_UNIT
            && h["invocation_id"] == NATIVE211_IID
            && h["main_pid"] == NATIVE211_PID
            && h["producer"]["Id"] == NATIVE211_UNIT
            && h["producer"]["InvocationID"] == NATIVE211_IID
            && h["producer"]["MainPID"].as_str() == Some("1264515"),
        "native211 handoff owner differs"
    );
    for k in [
        "native_input_qualified",
        "entry_replay",
        "replay_launch_authorized",
        "runtime_promotion_authorized",
        "full_epoch_qualified",
        "canonical_sidecar_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(h[k] == false, "native211 handoff grants unexpected {k}");
    }
    for row in config["replays"].as_array().context("replay census")? {
        ensure!(
            row["producer_unit"] != NATIVE211_UNIT && row["controller_unit"] != NATIVE211_UNIT,
            "native211 duplicated as ordinary replay"
        );
        let scratch = Path::new(string(row, "scratch_path")?);
        let native_scratch =
            Path::new("/home/ubuntu/.jetstreamer-private/native-input211-v1616-capped-v1/scratch");
        ensure!(
            !scratch.starts_with(native_scratch) && !native_scratch.starts_with(scratch),
            "native211 scratch overlaps replay"
        );
    }
    Ok(())
}
fn native265_pass_through(
    config: &Value,
    reference: Option<&Bound>,
    handoff: Option<&Value>,
) -> Result<Value> {
    let mut filtered = config.clone();
    let rows = config
        .get("native_input_diagnostics")
        .cloned()
        .unwrap_or_else(|| json!([]));
    let rows = rows.as_array().context("native diagnostics array")?;
    let selected = rows
        .iter()
        .filter(|r| r["epoch"] == 265)
        .collect::<Vec<_>>();
    ensure!(selected.len() <= 1, "duplicate native265 diagnostic");
    let Some(row) = selected.first() else {
        ensure!(
            reference.is_none() && handoff.is_none(),
            "unused native265 handoff"
        );
        return Ok(filtered);
    };
    let b = reference.context("native265 handoff required")?;
    ensure!(
        b.path.parent().and_then(Path::parent) == Some(Path::new("/var/lib/jetstreamer"))
            && b.path
                .parent()
                .and_then(Path::file_name)
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("horizon-native265-execution-"))
            && b.path
                .file_name()
                .is_some_and(|n| n == "guarded-startup-handoff.json"),
        "native265 handoff namespace"
    );
    let h = handoff.context("native265 handoff evidence required")?;
    let unit = "horizon-265-native-input-20261119-v1.service";
    let iid = string(h, "invocation_id")?;
    let pid = h["main_pid"].as_u64().context("native265 PID")?;
    ensure!(
        iid.len() == 32
            && iid
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
            && pid > 1
            && pid <= i32::MAX as u64
            && h["schema"] == "horizon-native265-guarded-startup-v1"
            && h["unit"] == unit
            && h["producer"]["Id"] == unit
            && h["producer"]["InvocationID"] == iid
            && h["producer"]["MainPID"] == pid.to_string().as_str(),
        "native265 handoff identity"
    );
    let root = "/home/ubuntu/.jetstreamer-private/native-input265-selected-20261119-v1";
    let expected = json!({"epoch":265,"unit":unit,"expected_invocation_id":iid,"main_pid":pid,"scratch_path":root,
        "executable":"/var/lib/jetstreamer/horizon265-native-input-daa786c0-20261119-v1/horizon265-native-input",
        "executable_sha256":"0dbcd28e231f7158b88701666bff89cbdf36cc2033c0e5e826e54a8c87db76e9"});
    ensure!(
        **row == expected,
        "native265 complete diagnostic tuple differs"
    );
    for k in [
        "native_input_qualified",
        "entry_replay",
        "replay_launch_authorized",
        "runtime_promotion_authorized",
        "full_epoch_qualified",
        "canonical_sidecar_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(h[k] == false, "native265 unexpected authority {k}");
    }
    for field in ["replays", "diagnostic_replays"] {
        if let Some(replays) = config[field].as_array() {
            for r in replays {
                ensure!(
                    r["producer_unit"] != unit && r["controller_unit"] != unit,
                    "native265 duplicate replay owner"
                );
                let scratch = Path::new(string(r, "scratch_path")?);
                ensure!(
                    !scratch.starts_with(root) && !Path::new(root).starts_with(scratch),
                    "native265 overlapping scratch"
                );
            }
        }
    }
    filtered["native_input_diagnostics"] = json!(
        rows.iter()
            .filter(|r| r["epoch"] != 265)
            .collect::<Vec<_>>()
    );
    Ok(filtered)
}
fn cold_pass_through(config: &Value, binding: Option<&Bound>, epoch: u64) -> Result<Value> {
    let mut filtered = config.clone();
    let rows = config
        .get("native_input_diagnostics")
        .cloned()
        .unwrap_or_else(|| json!([]));
    let rows = rows.as_array().context("native diagnostics array")?;
    let mut candidates = rows.iter().filter(|row| row["epoch"] == epoch);
    let Some(row) = candidates.next() else {
        ensure!(binding.is_none(), "unused cold input handoff");
        return Ok(filtered);
    };
    ensure!(
        candidates.next().is_none(),
        "duplicate cold input diagnostic"
    );
    let b = binding.context("cold input handoff required")?;
    match epoch {
        257 => {
            horizon_singleton211_launch::native257::validate_saved_handoff(&b.path, &b.sha256)?;
        }
        266 if row["unit"]=="horizon-266-capped-native-input-v1.service" => {
            horizon_singleton211_launch::native266_capped::validate_saved_handoff(&b.path,&b.sha256)?;
        }
        266 => {
            horizon_singleton211_launch::native266::validate_saved_handoff(&b.path, &b.sha256)?;
        }

        212 => {
            horizon_singleton211_launch::native212::validate_saved_handoff(&b.path, &b.sha256)?;
        }
        261 => {
            horizon_singleton211_launch::native261::validate_saved_handoff(&b.path, &b.sha256)?;
        }
        _ => anyhow::bail!("unregistered cold input"),
    }
    // The wrapper and launcher have separately qualified serde_json builds.
    // Reopen the same digest-bound bytes with the wrapper's reader.
    cold_owner(config, row, &bound(b)?, epoch)?;
    filtered["native_input_diagnostics"] = json!(
        rows.iter()
            .filter(|r| r["epoch"] != epoch)
            .collect::<Vec<_>>()
    );
    Ok(filtered)
}
fn cold_owner(config: &Value, row: &Value, handoff: &Value, epoch: u64) -> Result<()> {
    let root = Path::new(match epoch {
        257 => "/home/ubuntu/.jetstreamer-private/native-input257-selected-20261120-v1",
        266 if handoff["unit"]=="horizon-266-capped-native-input-v1.service" => "/run/horizon266-capped-native-cold-v1",
        266 => "/run/horizon266-native-cold-v1",
        212 => "/run/horizon212-native-cold-v1",
        261 => "/run/horizon261-native-cold-v1",
        _ => anyhow::bail!("unregistered cold input"),
    });
    let unit = string(handoff, "unit")?;
    let expected = json!({"epoch":epoch,"unit":unit,"expected_invocation_id":string(handoff, "invocation_id")?,
        "main_pid":handoff["main_pid"].as_u64().context("cold input handoff PID")?,"scratch_path":root,
        "executable":string(&handoff["harness"],"path")?,"executable_sha256":string(&handoff["harness"],"sha256")?});
    ensure!(
        row == &expected,
        "cold input resource tuple differs from original handoff"
    );
    for replay in ["replays", "diagnostic_replays"]
        .iter()
        .flat_map(|field| config[*field].as_array().into_iter().flatten())
    {
        let range = string(replay, "range")?;
        let (first, last) = range.split_once('-').unwrap_or((range, range));
        let (first, last) = (first.parse::<u64>()?, last.parse::<u64>()?);
        let scratch = Path::new(string(replay, "scratch_path")?);
        ensure!(
            first <= last
                && !(first..=last).contains(&epoch)
                && replay["producer_unit"] != unit
                && replay["controller_unit"] != unit
                && !scratch.starts_with(root)
                && !root.starts_with(scratch),
            "cold input replay owner overlaps"
        );
    }
    Ok(())
}
fn singleton211_pass_through(p: &Plan, config: &Value) -> Result<()> {
    let rows = config
        .get("diagnostic_replays")
        .cloned()
        .unwrap_or_else(|| json!([]));
    let Some(b) = &p.singleton211_handoff else {
        ensure!(
            rows == json!([]),
            "full211 diagnostic needs its own startup handoff"
        );
        return Ok(());
    };
    let h = bound(b)?;
    let sha = string(&h, "launcher_sha256")?;
    horizon_singleton211_launch::validate_saved_handoff(&b.path, &b.sha256, sha)?;
    let unit = "horizon-singleton-211-capped-4aeca563-v1.service";
    let iid = string(&h, "invocation_id")?;
    let expected = json!([{"range":"211-211","controller_unit":unit,"expected_controller_invocation_id":iid,
        "producer_unit":unit,"expected_producer_invocation_id":iid,
        "scratch_path":"/home/ubuntu/.jetstreamer-private/qualification-211-singleton-capped-v1",
        "worker_executable_basename":"historical-worker"}]);
    ensure!(rows == expected, "full211 diagnostic tuple changed");
    for key in ["replays", "native_input_diagnostics"] {
        for row in config[key].as_array().into_iter().flatten() {
            ensure!(
                row["range"] != "211-211"
                    && row["epoch"] != 211
                    && row["unit"] != unit
                    && row["producer_unit"] != unit,
                "duplicate full211/native211 owner"
            );
        }
    }
    Ok(())
}
fn validate(p: &Plan, config: &Value, handoffs: &[Value]) -> Result<()> {
    ensure!(
        p.schema == "horizon-terminal-aware-observation-plan-v1"
            && config["schema"] == "jetstreamer-horizon-live-resource-sample-config-v2",
        "unknown schema"
    );
    ensure!(
        p.deployment.parent() == Some(Path::new("/var/lib/jetstreamer"))
            && p.deployment
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with("horizon-terminal-aware-cycle-")
                    && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')),
        "deployment scope differs"
    );
    let rows = config["replays"]
        .as_array()
        .context("missing replay census")?;
    ensure!(
        (!rows.is_empty()
            || p.full228_entries.is_some() || p.full266_entries.is_some() || p.instruction266_registration.is_some()
            || p.native257_handoff.is_some()
            || p.native261_handoff.is_some()
            || p.native212_handoff.is_some() || p.native266_handoff.is_some())
            && rows.len() == handoffs.len(),
        "handoff census differs"
    );
    let mut seen = std::collections::BTreeSet::new();
    for (row, h) in rows.iter().zip(handoffs) {
        let epoch = h["epoch"].as_u64().context("missing epoch")?;
        if epoch == 265 {
            full265::validate_delivery(
                epoch,
                string(h, "producer_unit")?,
                string(h, "producer_invocation_id")?,
                string(h, "expected_exec_prefix")?,
                Path::new(string(h, "output_directory")?),
                &h["manifest"],
                &h["startup_handoff"],
            )?;
            full265::telemetry_tuple(
                string(row, "range")?,
                string(row, "producer_unit")?,
                string(row, "controller_unit")?,
                string(row, "expected_producer_invocation_id")?,
                string(row, "expected_controller_invocation_id")?,
                Path::new(string(row, "scratch_path")?),
            )?;
        }
        ensure!(
            ((247..=251).contains(&epoch) || epoch == 265)
                && seen.insert(epoch)
                && h["schema"] == "horizon-singleton-delivery-handoff-plan-v1"
                && row["range"] == format!("{epoch}-{epoch}")
                && row["producer_unit"] == h["producer_unit"]
                && row["expected_producer_invocation_id"] == h["producer_invocation_id"],
            "handoff owner/range differs"
        );
    }
    let mut peers = config.clone();
    for (pilot, evidence) in p.entry_pilots() {
        let Some(b) = evidence else { continue };
        let proof = pilot.validate(&json!(b))?;
        let range = format!("{0}-{0}", pilot.epoch);
        let rows = peers["diagnostic_replays"].as_array().context("missing entry diagnostics")?;
        let mut matching = rows.iter().filter(|row| row["range"] == range);
        ensure!(matching.next() == Some(&proof["tuple"]) && matching.next().is_none()
            && (pilot.epoch != 266 || p.native266_handoff.is_none()), "original entry claim differs");
        for row in ["replays", "native_input_diagnostics"].iter()
            .flat_map(|field| config[*field].as_array().into_iter().flatten())
            .chain(config["diagnostic_replays"].as_array().into_iter().flatten().filter(|row| *row != &proof["tuple"])) {
            let scratch = Path::new(string(row,"scratch_path")?);
            if let Some(range) = row["range"].as_str() {
                let (first,last) = range.split_once('-').unwrap_or((range,range));
                ensure!(!(first.parse::<u64>()?..=last.parse::<u64>()?).contains(&pilot.epoch), "overlapping entry range");
            }
            ensure!(row["epoch"] != pilot.epoch && row["producer_unit"] != pilot.unit
                && row["controller_unit"] != pilot.unit && row["unit"] != pilot.unit
                && !scratch.starts_with(pilot.root) && !Path::new(pilot.root).starts_with(scratch),
                "duplicate original entry owner");
        }
        let remaining: Vec<_> = rows.iter().filter(|row| row["range"] != range).cloned().collect();
        peers["diagnostic_replays"] = Value::Array(remaining);
    }
    singleton211_pass_through(p, &peers)?;
    ensure!(
        config
            .get("singleton247_finalization")
            .is_none_or(|v| v == &json!(false)),
        "finalization route is selected only by authenticated cadence prescreen"
    );
    ensure!(
        config
            .get("singleton_finalization_epochs")
            .is_none_or(|v| v == &json!([])),
        "finalization epochs are selected only by authenticated cadence prescreen"
    );
    let m = fs::symlink_metadata(&p.state_directory)?;
    ensure!(
        m.is_dir()
            && m.uid() == 0
            && m.mode() & 0o7777 == 0o700
            && p.state_directory.canonicalize()? == p.state_directory,
        "unsafe state directory"
    );
    Ok(())
}
fn run(args: &[String]) -> Result<()> {
    ensure!(
        args.len() == 6
            && matches!(args[0].as_str(), "check-plan" | "observe")
            && args[2] == "--plan-sha256"
            && args[4] == "--self-sha256",
        "usage: terminal-aware-observe check-plan|observe PLAN --plan-sha256 HEX --self-sha256 HEX"
    );
    ensure!(unsafe { libc::geteuid() } == 0, "root required");
    ensure!(
        sha(&fs::read("/proc/self/exe")?) == args[5],
        "running image differs"
    );
    let plan_ref = Bound {
        path: args[1].clone().into(),
        sha256: args[3].clone(),
    };
    let p: Plan = serde_json::from_value(bound(&plan_ref)?)?;
    let mut config = bound(&p.config)?;
    let handoffs = p
        .handoff_plans
        .iter()
        .map(bound)
        .collect::<Result<Vec<_>>>()?;
    validate(&p, &config, &handoffs)?;
    let native_handoff = p.native211_handoff.as_ref().map(bound).transpose()?;
    let native265_handoff = p.native265_handoff.as_ref().map(bound).transpose()?;
    let without257 = cold_pass_through(&config, p.native257_handoff.as_ref(), 257)?;
    let without261 = cold_pass_through(&without257, p.native261_handoff.as_ref(), 261)?;
    let without212 = cold_pass_through(&without261, p.native212_handoff.as_ref(), 212)?;
    let without266 = cold_pass_through(&without212, p.native266_handoff.as_ref(), 266)?;
    let other_native = native265_pass_through(
        &without266,
        p.native265_handoff.as_ref(),
        native265_handoff.as_ref(),
    )?;
    native211_pass_through(
        &other_native,
        p.native211_handoff.as_ref(),
        native_handoff.as_ref(),
    )?;
    let successor = config.get("successor247_claim").cloned();
    let staged_delivery = config.get("staged247_resource_only").cloned();
    let staged = staged_delivery_selected(&config)?;
    let (observer, observer_sha) = observer_image(
        staged
            || p.native257_handoff.is_some()
            || p.native261_handoff.is_some()
            || p.native212_handoff.is_some() || p.native266_handoff.is_some(),
    )?;
    ensure!(
        sha(&raw(Path::new(observer), 64 << 20)?) == observer_sha
            && sha(&raw(Path::new(SEALER), 64 << 20)?) == SEALER_SHA,
        "dependency image differs"
    );
    if args[0] == "check-plan" {
        println!(
            "{}",
            json!({"configuration_validated":true,"producer_observed":false,"admission_authorized":false})
        );
        return Ok(());
    }
    let previous_path = Path::new(string(&config, "previous_sample")?);
    let previous_bytes = raw(previous_path, 32 << 20)?;
    let previous: Value = serde_json::from_slice(&previous_bytes)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    due(&config, &previous, now)?; // No unit/resource reads before the original clock.
    for (pilot, evidence) in p.entry_pilots() {
        let Some(b) = evidence else { continue };
        let proof = pilot.validate(&json!(b))?;
        let m = properties(pilot.unit)?;
        if m["ActiveState"] == "active" {
            let pid = proof["pid"].as_u64().context("original replay PID")?;
            ensure!(m["InvocationID"] == proof["iid"] && m["MainPID"].as_str().and_then(|s|s.parse::<u64>().ok()) == Some(pid)
                && m["NRestarts"] == "0", "due replay owner changed");
            pilot.mapped_node(pid)?;
        }
    }
    let mut live = Vec::new();
    let mut omitted = Vec::new();
    let mut census = Vec::new();
    let mut finalization = Vec::new();
    for (row, handoff) in config["replays"].as_array().unwrap().iter().zip(&handoffs) {
        let unit = properties(string(row, "producer_unit")?)?;
        census.push(unit.clone());
        match classify(row, handoff, &unit)? {
            State::Live => {
                let epoch = handoff["epoch"].as_u64().context("missing epoch")?;
                let phase = if epoch == 265 {
                    full265::capture_phase(&unit, now)?
                } else {
                    singleton247_phase::capture(singleton247_phase::profile(epoch)?, &unit, now)?
                };
                if let Some(proof) = phase {
                    finalization.push(json!({"configuration":row,"unit":unit,"phase_evidence":proof,"reservations_retained":true,"resource_release_authorized":false}));
                    continue;
                }
                live.push(row.clone());
            },
            State::Terminal => omitted.push(json!({"configuration":row,"unit":unit,"terminal_handoff_required":true,"archive_completion_proven":false,"resource_release_authorized":false})),
        }
    }
    let prescreen = save(
        &p.state_directory,
        "prescreen.json",
        &json!({"schema":"horizon-terminal-aware-prescreen-v1","plan":plan_ref,"tool_sha256":args[5],"recorded_unix_seconds":now,"previous_sample_sha256":sha(&previous_bytes),"unit_census":census,"instruction266_registration":p.instruction266_registration,"full228_entries":p.full228_entries,"full266_entries":p.full266_entries,"native211_handoff":p.native211_handoff,"native265_handoff":p.native265_handoff,"native257_handoff":p.native257_handoff,"native261_handoff":p.native261_handoff,"native212_handoff":p.native212_handoff,"native266_handoff":p.native266_handoff,"native_input_diagnostics":config.get("native_input_diagnostics"),"omitted":omitted,"finalization":finalization,"active_range_count":live.len(),"resource_release_authorized":false,"publication_authorized":false,"replay_launch_authorized":false}),
    )?;
    ensure!(
        !live.is_empty()
            || !finalization.is_empty()
            || p.singleton211_handoff.is_some()
            || p.full228_entries.is_some() || p.full266_entries.is_some() || p.instruction266_registration.is_some()
            || p.native257_handoff.is_some()
            || p.native261_handoff.is_some()
            || p.native212_handoff.is_some() || p.native266_handoff.is_some(),
        "all configured owners are terminal; prescreen retained, use the full terminal fleet transition"
    );
    let original_delivery = config.get("delivery247_resource_only").cloned();
    let original_native = config.get("native_input_diagnostics").cloned();
    config["replays"] = json!(live);
    config["singleton247_finalization"] = json!(false);
    config["singleton_finalization_epochs"] = json!(
        finalization
            .iter()
            .map(|e| e["phase_evidence"]["epoch"].clone())
            .collect::<Vec<_>>()
    );
    ensure!(
        config.get("native_input_diagnostics") == original_native.as_ref(),
        "native diagnostic altered during prescreen"
    );
    ensure!(
        config.get("delivery247_resource_only") == original_delivery.as_ref()
            && config.get("staged247_resource_only") == staged_delivery.as_ref()
            && config.get("successor247_claim")==successor.as_ref(),
        "delivery RSS selection changed during prescreen"
    );
    let effective = save(&p.state_directory, "effective-config.json", &config)?;
    let seal = save(
        &p.state_directory,
        "seal-plan.json",
        &json!({"schema":"jetstreamer-sealed-deployment-plan-v1","destination":p.deployment,"members":[{"source":effective.path,"name":"config.json","sha256":effective.sha256,"mode":292}]}),
    )?;
    let sealed = Command::new(SEALER)
        .arg(&seal.path)
        .args(["--plan-sha256", &seal.sha256, "--self-sha256", SEALER_SHA])
        .status()?;
    ensure!(sealed.success(), "effective config seal failed");
    let result = Command::new(observer)
        .arg(p.deployment.join("config.json"))
        .status()?;
    let mut still_terminal = true;
    for entry in omitted.iter().chain(&finalization) {
        let old = &entry["unit"];
        let current = properties(string(old, "Id")?)?;
        still_terminal &= current == *old;
    }
    save(
        &p.state_directory,
        "completion.json",
        &json!({"schema":"horizon-terminal-aware-observation-v1","prescreen":prescreen,"effective_config":effective,"observer_exit_code":result.code(),"omitted_owners_unchanged":still_terminal,"observer_output":config["output"],"instruction266_registration":p.instruction266_registration,"full228_entries":p.full228_entries,"full266_entries":p.full266_entries,"native211_handoff":p.native211_handoff,"native265_handoff":p.native265_handoff,"native257_handoff":p.native257_handoff,"native261_handoff":p.native261_handoff,"native212_handoff":p.native212_handoff,"native266_handoff":p.native266_handoff,"native_input_diagnostics":config.get("native_input_diagnostics"),"full_fleet_reconciliation_required":true,"omitted_owner_reservations_retained":true,"finalization_owner_reservations_retained":true,"resource_release_authorized":false,"publication_authorized":false,"replay_launch_authorized":false}),
    )?;
    ensure!(
        result.success() && still_terminal,
        "observer failed or omitted owner changed; preserve attempt and reconcile original identities"
    );
    Ok(())
}
fn main() {
    if let Err(e) = run(&std::env::args().skip(1).collect::<Vec<_>>()) {
        eprintln!("terminal-aware observation rejected: {e:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn staged_delivery_prescreen_selects_paired_observer_without_changing_predecessor() {
        let cfg = json!({"staged247_resource_only":true,"delivery247_resource_only":false,"previous_sample":"/sealed/v145.json","minimum_interval_seconds":1800});
        let saved = cfg.clone();
        assert!(staged_delivery_selected(&cfg).unwrap());
        assert_eq!(cfg, saved);
        assert!(!staged_delivery_selected(&json!({"delivery247_resource_only":true})).unwrap());
        assert!(!staged_delivery_selected(&json!({"successor247_claim":null})).unwrap());
        assert!(staged_delivery_selected(&json!({"successor247_claim":{"path":"/foreign"}})).is_err());
        assert!(
            staged_delivery_selected(
                &json!({"delivery247_resource_only":true,"staged247_resource_only":true})
            )
            .is_err()
        );
        assert!(staged_delivery_selected(&json!({"staged247_resource_only":"next"})).is_err());
    }
    #[test]
    fn cold_diagnostics_need_the_original_resource_tuple_and_exclusive_range() {
        for (epoch, root, overlap) in [
            (
                257,
                "/home/ubuntu/.jetstreamer-private/native-input257-selected-20261120-v1",
                "/home/ubuntu/.jetstreamer-private",
            ),
            (261, "/run/horizon261-native-cold-v1", "/run"),
            (212, "/run/horizon212-native-cold-v1", "/run"),
            (266, "/run/horizon266-native-cold-v1", "/run"),
        ] {
            let h = json!({"unit":"native.service","invocation_id":"a".repeat(32),"main_pid":42,
            "harness":{"path":"/harness","sha256":"b".repeat(64)}});
            let row = json!({"epoch":epoch,"unit":h["unit"],"expected_invocation_id":h["invocation_id"],"main_pid":42,
            "scratch_path":root,
            "executable":h["harness"]["path"],"executable_sha256":h["harness"]["sha256"]});
            let replay = json!({"range":"211-211","producer_unit":"other","controller_unit":"other","scratch_path":"/unrelated"});
            let mut config =
                json!({"diagnostic_replays":[replay],"native_input_diagnostics":[row]});
            cold_owner(&config, &row, &h, epoch).unwrap();
            for key in row.as_object().unwrap().keys() {
                let mut changed = row.clone();
                changed[key] = Value::Null;
                assert!(cold_owner(&config, &changed, &h, epoch).is_err(), "{key}");
            }
            for (key, value) in [
                ("range", json!(format!("{epoch}-{epoch}"))),
                ("producer_unit", h["unit"].clone()),
                ("controller_unit", h["unit"].clone()),
                ("scratch_path", json!(overlap)),
            ] {
                let mut changed = config.clone();
                changed["diagnostic_replays"][0][key] = value;
                assert!(cold_owner(&changed, &row, &h, epoch).is_err(), "{key}");
            }
            assert!(cold_pass_through(&config, None, epoch).is_err());
            config["native_input_diagnostics"]
                .as_array_mut()
                .unwrap()
                .push(row);
            assert!(cold_pass_through(&config, None, epoch).is_err());
        }
    }
    #[test]
    fn native265_prescreen_preserves_diagnostic_and_refuses_partial_owner() {
        let unit = "horizon-265-native-input-20261119-v1.service";
        let iid = "a".repeat(32);
        let row = json!({"epoch":265,"unit":unit,"expected_invocation_id":iid,"main_pid":42,
            "scratch_path":"/home/ubuntu/.jetstreamer-private/native-input265-selected-20261119-v1",
            "executable":"/var/lib/jetstreamer/horizon265-native-input-daa786c0-20261119-v1/horizon265-native-input",
            "executable_sha256":"0dbcd28e231f7158b88701666bff89cbdf36cc2033c0e5e826e54a8c87db76e9"});
        let config = json!({"replays":[],"native_input_diagnostics":[row]});
        let b = Bound {
            path:
                "/var/lib/jetstreamer/horizon-native265-execution-test/guarded-startup-handoff.json"
                    .into(),
            sha256: "b".repeat(64),
        };
        let mut h = json!({"schema":"horizon-native265-guarded-startup-v1","unit":unit,"invocation_id":iid,"main_pid":42,"producer":{"Id":unit,"InvocationID":iid,"MainPID":"42"}});
        for k in [
            "native_input_qualified",
            "entry_replay",
            "replay_launch_authorized",
            "runtime_promotion_authorized",
            "full_epoch_qualified",
            "canonical_sidecar_authorized",
            "publication_authorized",
            "remote_mutations",
            "r2_mutations",
        ] {
            h[k] = json!(false);
        }
        let filtered = native265_pass_through(&config, Some(&b), Some(&h)).unwrap();
        native211_pass_through(&filtered, None, None).unwrap();
        assert_eq!(
            config["native_input_diagnostics"].as_array().unwrap().len(),
            1
        );
        assert!(native265_pass_through(&config, None, Some(&h)).is_err());
        h["main_pid"] = json!(43);
        assert!(native265_pass_through(&config, Some(&b), Some(&h)).is_err());
    }
    #[test]
    #[ignore = "root native systemd owner transition, no campaign producer reads"]
    fn native_live_to_terminal_keeps_the_original_identity() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let name = format!("horizon-terminal-observer-native-{}", std::process::id());
        struct Cleanup(String);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                for suffix in ["service", "timer"] {
                    let _ = Command::new("/usr/bin/systemctl")
                        .args(["stop", &format!("{}.{suffix}", self.0)])
                        .status();
                }
            }
        }
        let _cleanup = Cleanup(name.clone());
        assert!(
            Command::new("/usr/bin/systemd-run")
                .args([
                    &format!("--unit={name}"),
                    "--on-active=1h",
                    "--property=MemoryMax=16777216",
                    "--property=MemorySwapMax=0",
                    "--property=TasksMax=8",
                    "--property=CPUQuota=100%",
                    "/usr/bin/sleep",
                    "2"
                ])
                .status()
                .unwrap()
                .success()
        );
        let unit = format!("{name}.service");
        assert!(
            Command::new("/usr/bin/systemctl")
                .args(["start", &unit])
                .status()
                .unwrap()
                .success()
        );
        let live = properties(&unit).unwrap();
        let row = json!({"controller_unit":unit,"producer_unit":unit,"expected_controller_invocation_id":live["InvocationID"],"expected_producer_invocation_id":live["InvocationID"]});
        let handoff =
            json!({"expected_exec_prefix":"{ path=/usr/bin/sleep ; argv[]=/usr/bin/sleep 2"});
        assert_eq!(classify(&row, &handoff, &live).unwrap(), State::Live);
        assert!(
            Command::new("/usr/bin/systemctl")
                .args(["start", "--wait", &unit])
                .status()
                .unwrap()
                .success()
        );
        let terminal = properties(&unit).unwrap();
        assert_eq!(terminal["InvocationID"], live["InvocationID"]);
        assert_eq!(
            classify(&row, &handoff, &terminal).unwrap(),
            State::Terminal
        );
        assert_eq!(terminal["Result"], "success");
        let mut other = row;
        other["expected_controller_invocation_id"] = json!("0".repeat(32));
        other["expected_producer_invocation_id"] = json!("0".repeat(32));
        assert!(classify(&other, &handoff, &terminal).is_err());
    }
    fn fixture() -> (Value, Value, Value) {
        (
            json!({"controller_unit":"a.service","producer_unit":"a.service","expected_controller_invocation_id":"a".repeat(32),"expected_producer_invocation_id":"a".repeat(32)}),
            json!({"expected_exec_prefix":"{ path=/node ; argv[]=/node 247"}),
            json!({"Id":"a.service","LoadState":"loaded","ActiveState":"active","SubState":"running","InvocationID":"a".repeat(32),"MainPID":"123","ControlPID":"0","NRestarts":"0","ExecStart":"{ path=/node ; argv[]=/node 247 ; ignore_errors=no ; start_time=[x] ; stop_time=[n/a] ; pid=123 ; code=(null) ; status=0/0 }","Result":"success","ExecMainCode":"0","ExecMainStatus":"0","ControlGroup":"/system.slice/a.service"}),
        )
    }
    #[test]
    fn clean_and_failed_terminal_are_omitted_without_claiming_completion() {
        let (r, h, mut u) = fixture();
        assert_eq!(classify(&r, &h, &u).unwrap(), State::Live);
        u["ActiveState"] = json!("inactive");
        u["SubState"] = json!("dead");
        u["MainPID"] = json!("0");
        assert_eq!(classify(&r, &h, &u).unwrap(), State::Terminal);
        u["ActiveState"] = json!("failed");
        u["SubState"] = json!("failed");
        u["Result"] = json!("exit-code");
        u["ExecMainStatus"] = json!("1");
        assert_eq!(classify(&r, &h, &u).unwrap(), State::Terminal);
    }
    #[test]
    fn changed_missing_restarted_and_transitioning_owners_are_not_terminal() {
        let (r, h, u) = fixture();
        for (key, value) in [
            ("InvocationID", "b"),
            ("LoadState", "not-found"),
            ("Id", "other.service"),
            ("NRestarts", "1"),
            ("MainPID", "0"),
            ("ActiveState", "deactivating"),
            ("ExecStart", "different"),
        ] {
            let mut bad = u.clone();
            bad[key] = json!(value);
            assert!(classify(&r, &h, &bad).is_err(), "{key}");
        }
        let mut terminal = u;
        terminal["ActiveState"] = json!("inactive");
        terminal["SubState"] = json!("dead");
        assert!(classify(&r, &h, &terminal).is_err());
        terminal["MainPID"] = json!("0");
        terminal["ControlPID"] = json!("42");
        assert!(classify(&r, &h, &terminal).is_err());
    }
    #[test]
    fn original_cadence_precedes_any_prescreen() {
        let previous = json!({"recorded_at_utc":"2026-11-19T12:28:00Z"});
        let mut config = json!({"not_before_utc":"2026-11-19T12:58:30Z","minimum_interval_seconds":1800,"observation_reason":"routine"});
        assert!(
            due(
                &config,
                &previous,
                timestamp("2026-11-19T12:58:29Z").unwrap()
            )
            .is_err()
        );
        due(
            &config,
            &previous,
            timestamp("2026-11-19T12:58:30Z").unwrap(),
        )
        .unwrap();
        config["not_before_utc"] = json!("2026-11-19T12:28:01Z");
        assert!(
            due(
                &config,
                &previous,
                timestamp("2026-11-19T12:57:59Z").unwrap()
            )
            .is_err()
        );
        config["observation_reason"] = json!("user-requested-status");
        assert!(due(&config, &previous, u64::MAX).is_err());
    }
    #[test]
    fn timestamps_reject_normalization_and_non_ascii() {
        for bad in [
            "2026-02-30T12:00:00Z",
            "2026-11-19T24:00:00Z",
            "2026-11-19T12:00:60Z",
            "2026-11-19T12:00:00+0000",
            "２０２６-11-19T12:00:00Z",
        ] {
            assert!(timestamp(bad).is_err(), "{bad}");
        }
    }
    fn native_fixture() -> (Value, Bound, Value) {
        let config = json!({"replays":[{"range":"249-249","producer_unit":"original249.service","controller_unit":"original249.service","scratch_path":"/home/ubuntu/.jetstreamer-private/qualification-249-reboot-20261117-v1"}],"native_input_diagnostics":[native211_row()]});
        let reference = Bound {
            path: NATIVE211_HANDOFF.into(),
            sha256: NATIVE211_HANDOFF_SHA.into(),
        };
        let handoff = json!({"schema":"horizon-native211-guarded-startup-v1","unit":NATIVE211_UNIT,"invocation_id":NATIVE211_IID,"main_pid":NATIVE211_PID,"producer":{"Id":NATIVE211_UNIT,"InvocationID":NATIVE211_IID,"MainPID":NATIVE211_PID.to_string()},"native_input_qualified":false,"entry_replay":false,"replay_launch_authorized":false,"runtime_promotion_authorized":false,"full_epoch_qualified":false,"canonical_sidecar_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false});
        (config, reference, handoff)
    }
    #[test]
    fn native211_diagnostic_passes_unchanged_without_replay_claim() {
        let (mut config, b, h) = native_fixture();
        let original = config["native_input_diagnostics"].clone();
        native211_pass_through(&config, Some(&b), Some(&h)).unwrap();
        config["replays"] = json!([]);
        config["singleton_finalization_epochs"] = json!([249]);
        native211_pass_through(&config, Some(&b), Some(&h)).unwrap();
        assert_eq!(config["native_input_diagnostics"], original);
        assert!(config.get("diagnostic_replays").is_none());
        let empty = json!({"replays":[]});
        native211_pass_through(&empty, None, None).unwrap();
        assert!(native211_pass_through(&empty, Some(&b), Some(&h)).is_err());
    }
    #[test]
    fn native211_pass_through_rejects_other_owners_duplicate_or_authorizing_shapes() {
        let (config, b, h) = native_fixture();
        assert!(native211_pass_through(&config, None, Some(&h)).is_err());
        assert!(native211_pass_through(&config, Some(&b), None).is_err());
        for key in [
            "epoch",
            "unit",
            "expected_invocation_id",
            "main_pid",
            "scratch_path",
            "executable",
            "executable_sha256",
        ] {
            let mut bad = config.clone();
            bad["native_input_diagnostics"][0][key] = Value::Null;
            assert!(
                native211_pass_through(&bad, Some(&b), Some(&h)).is_err(),
                "{key}"
            );
        }
        let mut bad = config.clone();
        bad["native_input_diagnostics"][0]["entry_replay"] = json!(true);
        assert!(native211_pass_through(&bad, Some(&b), Some(&h)).is_err());
        bad = config.clone();
        bad["native_input_diagnostics"]
            .as_array_mut()
            .unwrap()
            .push(native211_row());
        assert!(native211_pass_through(&bad, Some(&b), Some(&h)).is_err());
        bad = config.clone();
        bad["replays"][0]["producer_unit"] = json!(NATIVE211_UNIT);
        assert!(native211_pass_through(&bad, Some(&b), Some(&h)).is_err());
        bad = config.clone();
        bad["replays"][0]["scratch_path"] = json!("/home/ubuntu/.jetstreamer-private");
        assert!(native211_pass_through(&bad, Some(&b), Some(&h)).is_err());
        let wrong = Bound {
            path: b.path.clone(),
            sha256: "0".repeat(64),
        };
        assert!(native211_pass_through(&config, Some(&wrong), Some(&h)).is_err());
        for key in [
            "native_input_qualified",
            "entry_replay",
            "replay_launch_authorized",
            "runtime_promotion_authorized",
            "full_epoch_qualified",
            "canonical_sidecar_authorized",
            "publication_authorized",
            "remote_mutations",
            "r2_mutations",
        ] {
            let mut bad = h.clone();
            bad[key] = json!(true);
            assert!(
                native211_pass_through(&config, Some(&b), Some(&bad)).is_err(),
                "{key}"
            );
        }
        let mut bad = h;
        bad["producer"]["MainPID"] = json!("1");
        assert!(native211_pass_through(&config, Some(&b), Some(&bad)).is_err());
    }
}

#[cfg(test)]
mod full211_offline_integration {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    #[ignore = "Main's isolated synthetic full211 fixture namespace only"]
    fn complete_wrapper_rejects_independently_substituted_full211_tuples() {
        assert_eq!(
            std::env::var("HORIZON211_OFFLINE_FIXTURE_ONLY").unwrap(),
            "synthetic-not-runtime"
        );
        assert_ne!(
            fs::read_link("/proc/self/ns/mnt").unwrap(),
            fs::read_link("/proc/1/ns/mnt").unwrap()
        );
        let cases: Value = serde_json::from_slice(
            &fs::read("/var/lib/jetstreamer/horizon211-offline-integration-fixture/cases.json")
                .unwrap(),
        )
        .unwrap();
        let a = &cases["cases"][0];
        let b = &cases["cases"][1];
        let iid = a["value"]["invocation_id"].as_str().unwrap();
        let state = tempfile::tempdir().unwrap();
        fs::set_permissions(state.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let unused = Bound {
            path: "/unused".into(),
            sha256: "1".repeat(64),
        };
        let mut p = Plan {
            schema: "horizon-terminal-aware-observation-plan-v1".into(),
            config: unused,
            handoff_plans: vec![],
            native211_handoff: None,
            native265_handoff: None,
            native257_handoff: None,
            native261_handoff: None,
            native212_handoff: None,
            native266_handoff: None,
            full266_entries: None,
            full228_entries: None,
            instruction266_registration: None,
            singleton211_handoff: Some(serde_json::from_value(a["handoff"].clone()).unwrap()),
            state_directory: state.path().into(),
            deployment: "/var/lib/jetstreamer/horizon-terminal-aware-cycle-offline-fixture".into(),
        };
        let peer = json!({"schema":"horizon-singleton-delivery-handoff-plan-v1","epoch":247,"producer_unit":"horizon-offline-peer247.service","producer_invocation_id":"7".repeat(32)});
        let row = json!({"range":"211-211","controller_unit":"horizon-singleton-211-capped-4aeca563-v1.service","producer_unit":"horizon-singleton-211-capped-4aeca563-v1.service","expected_controller_invocation_id":iid,"expected_producer_invocation_id":iid,"scratch_path":"/home/ubuntu/.jetstreamer-private/qualification-211-singleton-capped-v1","worker_executable_basename":"historical-worker"});
        let config = json!({"schema":"jetstreamer-horizon-live-resource-sample-config-v2","replays":[{"range":"247-247","producer_unit":peer["producer_unit"],"expected_producer_invocation_id":peer["producer_invocation_id"]}],"diagnostic_replays":[row],"native_input_diagnostics":[]});
        validate(&p, &config, std::slice::from_ref(&peer)).unwrap();
        for (key, value) in [
            ("range", json!("210-211")),
            ("controller_unit", json!("replacement.service")),
            (
                "producer_unit",
                json!("archive-211-v1616-native-input-actual-v1.service"),
            ),
            (
                "expected_controller_invocation_id",
                b["value"]["invocation_id"].clone(),
            ),
            (
                "expected_producer_invocation_id",
                b["value"]["invocation_id"].clone(),
            ),
            ("scratch_path", json!("/foreign")),
            ("worker_executable_basename", json!("native-input-test")),
        ] {
            let mut bad = config.clone();
            bad["diagnostic_replays"][0][key] = value;
            assert!(
                validate(&p, &bad, std::slice::from_ref(&peer)).is_err(),
                "{key}"
            );
        }
        p.singleton211_handoff = Some(serde_json::from_value(b["handoff"].clone()).unwrap());
        assert!(validate(&p, &config, std::slice::from_ref(&peer)).is_err());
        p.singleton211_handoff = Some(serde_json::from_value(a["handoff"].clone()).unwrap());
        let mut bad = config.clone();
        bad["native_input_diagnostics"] = json!([{"epoch":211}]);
        assert!(validate(&p, &bad, std::slice::from_ref(&peer)).is_err());
        let mut bad = config.clone();
        bad["diagnostic_replays"].as_array_mut().unwrap().push(row);
        assert!(validate(&p, &bad, std::slice::from_ref(&peer)).is_err());
        p.singleton211_handoff = None;
        assert!(validate(&p, &config, std::slice::from_ref(&peer)).is_err());
    }
}
