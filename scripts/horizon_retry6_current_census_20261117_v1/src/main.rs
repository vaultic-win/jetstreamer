use anyhow::{ensure, Context, Result};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const THREAD: &str = "01a1af2a-9ce8-76a2-8939-b2112bd38f53";
const TEMPLATE: &str =
    "/usr/local/lib/jetstreamer/horizon-retry6-166-template-20261117-v2/template.json";
const TEMPLATE_SHA: &str = "761be1d5b2cffd4f01522f949165315a405a11156d27c784e9f280874d11cb70";
const PROPERTIES: &str = "Id,LoadState,ActiveState,SubState,MainPID,ControlPID,InvocationID,NRestarts,Job,Triggers,TriggeredBy,ExecStart,CPUQuotaPerSecUSec,MemoryMax";

fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn read_bound(path: &Path, expected: &str) -> Result<Value> {
    let bytes = fs::read(path)?;
    ensure!(
        sha(&bytes) == expected,
        "binding mismatch: {}",
        path.display()
    );
    Ok(serde_json::from_slice(&bytes)?)
}
fn binding(path: &Path) -> Result<Value> {
    Ok(json!({"path":path,"sha256":sha(&fs::read(path)?)}))
}
fn bound(value: &Value) -> Result<Value> {
    let path = Path::new(value["path"].as_str().context("bound path")?);
    read_bound(path, value["sha256"].as_str().context("bound SHA")?)
}
fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn utc_now() -> Result<String> {
    let seconds = libc::time_t::try_from(now()?)?;
    let mut tm = unsafe { std::mem::zeroed::<libc::tm>() };
    ensure!(
        !unsafe { libc::gmtime_r(&seconds, &mut tm) }.is_null(),
        "UTC conversion"
    );
    Ok(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec
    ))
}
fn write(root: &Path, name: &str, value: &Value) -> Result<PathBuf> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    let path = root.join(name);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .mode(0o600)
        .open(&path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    File::open(root)?.sync_all()?;
    Ok(path)
}
fn output(command: &mut Command) -> Result<String> {
    let result = command.output()?;
    ensure!(
        result.status.success(),
        "command failed: {:?}: {}",
        command,
        String::from_utf8_lossy(&result.stderr)
    );
    Ok(String::from_utf8(result.stdout)?)
}
fn unit_names(previous: &Value, template: &Value) -> Result<BTreeSet<String>> {
    let list = output(Command::new("/usr/bin/systemctl").args([
        "list-units",
        "--all",
        "--type=service",
        "--type=timer",
        "--no-legend",
        "--plain",
        "--no-pager",
    ]))?;
    let mut names: BTreeSet<String> = list
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter(|name| name.ends_with(".service") || name.ends_with(".timer"))
        .map(str::to_owned)
        .collect();
    for key in previous["complete_metadata_unit_census"]
        .as_object()
        .context("old full census")?
        .keys()
    {
        names.insert(key.clone());
    }
    for value in template["closed_units"]
        .as_array()
        .context("closed units")?
    {
        names.insert(value.as_str().context("closed unit name")?.to_owned());
    }
    names.insert(
        template["producer_unit"]
            .as_str()
            .context("producer unit")?
            .to_owned(),
    );
    for suffix in ["service", "timer"] {
        names.insert(format!(
            "horizon-guard-replacement-166-local3retry6-20261110-v1.{suffix}"
        ));
    }
    for epoch in [166, 167, 169, 170] {
        names.insert(format!(
            "horizon-qualify-{epoch}-replacement-local3retry3-20261110-v1.service"
        ));
    }
    for epoch in [166, 167, 170] {
        names.insert(format!(
            "horizon-qualify-{epoch}-replacement-local3retry4-20261110-v1.service"
        ));
    }
    names.insert("horizon-qualify-166-replacement-local3retry5-20261110-v1.service".to_owned());
    Ok(names)
}
fn native(names: &BTreeSet<String>) -> Result<BTreeMap<String, Value>> {
    let names: Vec<_> = names.iter().collect();
    let mut rows = BTreeMap::new();
    for chunk in names.chunks(100) {
        let mut command = Command::new("/usr/bin/systemctl");
        command
            .arg("show")
            .args(chunk)
            .arg(format!("-p{PROPERTIES}"));
        let text = output(&mut command)?;
        for (id, row) in parse_blocks(&text)? {
            ensure!(
                rows.insert(id.clone(), row).is_none(),
                "duplicate native unit: {id}"
            );
        }
    }
    ensure!(
        names.iter().all(|name| rows.contains_key(name.as_str())),
        "incomplete native unit census"
    );
    Ok(rows)
}
fn parse_blocks(text: &str) -> Result<BTreeMap<String, Value>> {
    let mut rows = BTreeMap::new();
    for block in text.trim().split("\n\n") {
        let mut row = Map::new();
        for line in block.lines() {
            if let Some((key, value)) = line.split_once('=') {
                row.insert(key.to_owned(), Value::String(value.to_owned()));
            }
        }
        let Some(id) = row.get("Id").and_then(Value::as_str).map(str::to_owned) else {
            continue;
        };
        if id.ends_with(".timer") {
            let mut absent = Vec::new();
            for key in ["MainPID", "ControlPID"] {
                if !row.contains_key(key) {
                    row.insert(key.to_owned(), Value::String("0".to_owned()));
                    absent.push(key);
                }
            }
            row.insert(
                "native_timer_absent_PID_properties_interpreted_as_zero".to_owned(),
                json!(absent),
            );
        }
        ensure!(
            rows.insert(id.clone(), Value::Object(row)).is_none(),
            "duplicate native unit: {id}"
        );
    }
    Ok(rows)
}
fn closed(row: &Value) -> bool {
    matches!(row["ActiveState"].as_str(), Some("inactive" | "failed"))
        && row["Job"] == ""
        && row["MainPID"] == "0"
        && row["ControlPID"] == "0"
}
fn process_claims() -> Result<Vec<Value>> {
    let images = [
        "/usr/local/lib/jetstreamer/horizon-independent166-singleton-package-20261109-v1/jetstreamer-node",
        "/usr/local/lib/jetstreamer/horizon-independent166-singleton-package-20261109-v1/jetstreamer-historical-worker-v1-5-6",
    ];
    let mut claims = Vec::new();
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Ok(pid) = name.parse::<u32>() else {
            continue;
        };
        let path = entry.path();
        let Ok(exe) = fs::read_link(path.join("exe")) else {
            continue;
        };
        let Ok(args) = fs::read(path.join("cmdline")) else {
            continue;
        };
        let exe = exe.to_string_lossy().to_string();
        let argv: Vec<String> = args
            .split(|b| *b == 0)
            .filter(|s| !s.is_empty())
            .map(|s| String::from_utf8_lossy(s).to_string())
            .collect();
        if images.contains(&exe.as_str()) || argv.iter().any(|arg| images.contains(&arg.as_str())) {
            claims.push(json!({"pid":pid,"executable":exe,"argv":argv}));
        }
    }
    Ok(claims)
}
fn main() {
    if let Err(error) = main_inner() {
        eprintln!("Error: {error:#}");
        std::process::exit(1);
    }
}
fn main_inner() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    ensure!(args.len() == 13 && args[11] == "--self-sha256", "usage: census OLD_CONTROL OLD_SHA EVENT EVENT_SHA OBSERVER OBS_SHA STATUS STATUS_SHA OUTPUT_DIR NEXT NEXT_SHA --self-sha256 SHA");
    ensure!(unsafe { libc::geteuid() } == 0, "root required");
    ensure!(
        sha(&fs::read("/proc/self/exe")?) == args[12],
        "self hash mismatch"
    );
    let old = read_bound(Path::new(&args[0]), &args[1])?;
    let event = read_bound(Path::new(&args[2]), &args[3])?;
    let observer = read_bound(Path::new(&args[4]), &args[5])?;
    let statuses = read_bound(Path::new(&args[6]), &args[7])?;
    let root = Path::new(&args[8]);
    let next = read_bound(Path::new(&args[9]), &args[10])?;
    ensure!(
        old["owner"] == "/root"
            && old["primary_thread"] == THREAD
            && old["selected_epoch"] == 166
            && old["attempt"] == "local3retry6",
        "old control identity"
    );
    ensure!(
        event["owner"] == "/root"
            && event["primary_thread"] == THREAD
            && event["active_replay_invocations"] == json!([])
            && event["active_bootstrap_invocations"] == json!([]),
        "event owner coverage"
    );
    ensure!(
        observer["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && observer["replays"] == json!([])
            && observer["cadence"]["routine_minimum_interval_enforced"] == true,
        "fresh zero-owner observer"
    );
    ensure!(
        statuses["authenticated_readback"] == true
            && statuses["authenticated_status_count"] == 19
            && statuses["observer"] == binding(Path::new(&args[4]))?,
        "status readback"
    );
    ensure!(
        event["last_complete_sample"] == binding(Path::new(&args[4]))?
            && event["authenticated_event_status_acceptance"] == binding(Path::new(&args[6]))?,
        "event binding"
    );
    ensure!(
        next["previous_sample"] == args[4]
            && event["sole_next_observer"] == binding(Path::new(&args[9]))?,
        "next observer binding"
    );
    let utc = utc_now()?;
    let sampled = observer["recorded_at_utc"]
        .as_str()
        .context("observer timestamp")?;
    let expires = observer["cadence"]["next_routine_observation_not_before_utc"]
        .as_str()
        .context("observer next cadence")?;
    ensure!(
        sampled <= utc.as_str() && utc.as_str() < expires,
        "observer freshness"
    );
    let meta = fs::symlink_metadata(root)?;
    ensure!(
        meta.is_dir() && meta.uid() == 0 && meta.mode() & 0o7777 == 0o700,
        "private output root"
    );
    ensure!(
        fs::read_dir(root)?.next().is_none(),
        "output root must be empty"
    );
    let template = read_bound(Path::new(TEMPLATE), TEMPLATE_SHA)?;
    ensure!(
        template["attempt"] == "local3retry6" && template["epoch"] == 166,
        "exact template"
    );
    let previous = bound(&old["current_census"])?;
    let names = unit_names(&previous, &template)?;
    let native = native(&names)?;
    for value in template["closed_units"]
        .as_array()
        .context("closed units")?
    {
        let unit = value.as_str().context("unit")?;
        ensure!(
            closed(&native[unit]),
            "selected old unit still live or queued: {unit}"
        );
    }
    for (name, row) in &native {
        if name.starts_with("horizon-qualify-166-")
            || name.starts_with("horizon-guard-replacement-166-local3retry6")
        {
            ensure!(
                closed(row),
                "epoch166 target or old producer still live: {name}"
            );
        }
    }
    let claims = process_claims()?;
    ensure!(
        claims.is_empty(),
        "selected node/worker process still present"
    );
    let selected: BTreeSet<String> = template["closed_units"]
        .as_array()
        .context("closed units")?
        .iter()
        .map(|value| value.as_str().context("unit").map(str::to_owned))
        .collect::<Result<_>>()?;
    let mut recheck = selected;
    recheck.insert(
        template["producer_unit"]
            .as_str()
            .context("producer unit")?
            .to_owned(),
    );
    recheck.insert("jetstreamer-epoch199-backfill-20261102-controller-v1-r2.service".to_owned());
    let after = self::native(&recheck)?;
    for name in &recheck {
        ensure!(
            native[name] == after[name],
            "selected or 199 native identity changed during census: {name}"
        );
    }
    ensure!(
        process_claims()?.is_empty(),
        "selected process appeared during census"
    );
    let raw_path = write(root, "CURRENT_NATIVE_RAW.json", &json!(native))?;
    let raw_binding = binding(&raw_path)?;
    let mut summary = BTreeMap::new();
    for (unit, original) in &native {
        let mut row = original.as_object().context("native row")?.clone();
        let exec = row
            .remove("ExecStart")
            .unwrap_or(Value::String(String::new()));
        let exec = exec.as_str().context("ExecStart string")?;
        row.insert("ExecStart_sha256".to_owned(), json!(sha(exec.as_bytes())));
        row.insert("ExecStart_utf8_bytes".to_owned(), json!(exec.len()));
        row.insert("full_raw_native_census".to_owned(), raw_binding.clone());
        summary.insert(unit.clone(), Value::Object(row));
    }
    let mut explicit = Map::new();
    for value in template["closed_units"]
        .as_array()
        .context("closed units")?
    {
        let name = value.as_str().context("unit")?;
        explicit.insert(name.to_owned(), native[name].clone());
    }
    let census = json!({"schema":"horizon-standard-replacement-Root-current-unit-and-proc-census-v1","owner":"/root","sole_primary_thread":THREAD,"recorded_unix_seconds":now()?,"explicit_closed_units":explicit,"exact_selected_node_and_worker_process_claims":claims,"no_new_target_owner_or_queued_launch":true,"complete_metadata_unit_census":summary,"full_raw_native_metadata_census":raw_binding,"metadata_unit_count":native.len(),"current199_controller_and_FD9_not_signalled_or_modified":true});
    let census_path = write(root, "CURRENT_CENSUS.json", &census)?;
    let mut control = old;
    control["current_census"] = binding(&census_path)?;
    control["event_fleet"] = binding(Path::new(&args[2]))?;
    control["observer"] = binding(Path::new(&args[4]))?;
    control["status_audit_result"] = binding(Path::new(&args[6]))?;
    control["sole_next_observer"] = binding(Path::new(&args[9]))?;
    control["output_root"] = json!(root);
    control["recorded_unix_seconds"] = json!(now()?);
    control["measure_plans"] = json!({});
    control["measurements"] = json!({});
    control["generated_operational_fleet"] = Value::Null;
    let control_path = write(root, "MEASURE_CONTROL.json", &control)?;
    println!(
        "{}",
        json!({"census":binding(&census_path)?,"control":binding(&control_path)?,"unit_count":native.len(),"selected_process_claims":0,"replay_launch_authorized":false})
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timer_missing_pid_fields_are_explicit_zero() {
        let rows = parse_blocks("Id=x.timer\nActiveState=inactive\nJob=\n\nId=y.service\nActiveState=active\nMainPID=4\nControlPID=0\nJob=\n").unwrap();
        assert_eq!(rows["x.timer"]["MainPID"], "0");
        assert_eq!(rows["x.timer"]["ControlPID"], "0");
        assert_eq!(
            rows["x.timer"]["native_timer_absent_PID_properties_interpreted_as_zero"],
            json!(["MainPID", "ControlPID"])
        );
        assert!(!closed(&rows["y.service"]));
    }

    #[test]
    fn duplicate_unit_blocks_are_rejected() {
        assert!(parse_blocks("Id=x.service\n\nId=x.service\n").is_err());
    }
}
