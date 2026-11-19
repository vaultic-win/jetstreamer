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

#[path = "../jetstreamer-horizon-observe/src/singleton247_phase.rs"]
mod singleton247_phase;

const OBSERVER: &str =
    "/var/lib/jetstreamer/horizon-finalization247251-observer-20261119-v1/jetstreamer-horizon-observe";
const OBSERVER_SHA: &str = "a9dd50adcaeb91b33d3e796557fd1f2aadbe9a55e002f416afa69b4d88685b7d";
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
    state_directory: PathBuf,
    deployment: PathBuf,
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
        !rows.is_empty() && rows.len() == handoffs.len(),
        "handoff census differs"
    );
    let mut seen = std::collections::BTreeSet::new();
    for (row, h) in rows.iter().zip(handoffs) {
        let epoch = h["epoch"].as_u64().context("missing epoch")?;
        ensure!(
            (247..=251).contains(&epoch)
                && seen.insert(epoch)
                && h["schema"] == "horizon-singleton-delivery-handoff-plan-v1"
                && row["range"] == format!("{epoch}-{epoch}")
                && row["producer_unit"] == h["producer_unit"]
                && row["expected_producer_invocation_id"] == h["producer_invocation_id"],
            "handoff owner/range differs"
        );
    }
    ensure!(
        config
            .get("diagnostic_replays")
            .is_none_or(|v| v == &json!([])),
        "diagnostic owners need their own unchanged route"
    );
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
    ensure!(
        sha(&raw(Path::new(OBSERVER), 64 << 20)?) == OBSERVER_SHA
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
    let mut live = Vec::new();
    let mut omitted = Vec::new();
    let mut census = Vec::new();
    let mut finalization = Vec::new();
    for (row, handoff) in config["replays"].as_array().unwrap().iter().zip(&handoffs) {
        let unit = properties(string(row, "producer_unit")?)?;
        census.push(unit.clone());
        match classify(row, handoff, &unit)? {
            State::Live => {
                let profile = singleton247_phase::profile(handoff["epoch"].as_u64().context("missing epoch")?)?;
                if let Some(proof) = singleton247_phase::capture(profile, &unit, now)?
                {
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
        &json!({"schema":"horizon-terminal-aware-prescreen-v1","plan":plan_ref,"tool_sha256":args[5],"recorded_unix_seconds":now,"previous_sample_sha256":sha(&previous_bytes),"unit_census":census,"omitted":omitted,"finalization":finalization,"active_range_count":live.len(),"resource_release_authorized":false,"publication_authorized":false,"replay_launch_authorized":false}),
    )?;
    ensure!(
        !live.is_empty() || !finalization.is_empty(),
        "all configured owners are terminal; prescreen retained, use the full terminal fleet transition"
    );
    config["replays"] = json!(live);
    config["singleton247_finalization"] = json!(false);
    config["singleton_finalization_epochs"] = json!(
        finalization
            .iter()
            .map(|e| e["phase_evidence"]["epoch"].clone())
            .collect::<Vec<_>>()
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
    let result = Command::new(OBSERVER)
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
        &json!({"schema":"horizon-terminal-aware-observation-v1","prescreen":prescreen,"effective_config":effective,"observer_exit_code":result.code(),"omitted_owners_unchanged":still_terminal,"observer_output":config["output"],"full_fleet_reconciliation_required":true,"omitted_owner_reservations_retained":true,"finalization_owner_reservations_retained":true,"resource_release_authorized":false,"publication_authorized":false,"replay_launch_authorized":false}),
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
}
