//! Shared read-only identity and config checks for the admitted epoch170 join.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::Command,
};

pub const PREFIX: &str =
    "/var/lib/jetstreamer/retry6-single170-guarded-launch-20261119-v1/epoch170";
pub const UNIT: &str = "horizon-qualify-170-replacement-local3retry6-20261110-v1.service";
const GUARD: &str = "horizon-guard-replacement-170-local3retry6-20261110-v1";
const NODE: &str = "/usr/local/lib/jetstreamer/horizon-independent170-singleton-package-20261109-v1/jetstreamer-node";
const NODE_SHA: &str = "a09b8e5aa9426beaf42e6b5f2a469a5a147436bab8b7bf79f268758b60aa2e65";
const WORKER_SHA: &str = "cf5fa883df75b23de82af52dc0e90c013f8e83397b445027e510a1137decc819";
const GUARD_IMAGE: &str =
    "/usr/local/lib/jetstreamer/horizon-epoch170-retry6-live166retry7-data-guard-20261118-v1/guard";
const GUARD_SHA: &str = "2572c20c10b1473a9438e8d08d4aaf6ccb06fa9aa47e3508fe90e6bcaddddc6b";
const LANE: &str = "/home/sol/.jetstreamer-private/epoch170-standard-lane-20261109-v1/replacement-local3retry6-20261110-v1";
pub const HOME_RUNTIME: &str = "/var/lib/jetstreamer/horizon_runtime_data";

pub fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
pub fn string<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v[key].as_str().with_context(|| format!("missing {key}"))
}
pub fn integer(v: &Value, key: &str) -> Result<u64> {
    v[key]
        .as_u64()
        .with_context(|| format!("missing integer {key}"))
}
fn identity(m: &fs::Metadata) -> [u64; 10] {
    [
        m.dev(),
        m.ino(),
        m.uid().into(),
        m.mode().into(),
        m.nlink(),
        m.len(),
        m.mtime() as u64,
        m.mtime_nsec() as u64,
        m.ctime() as u64,
        m.ctime_nsec() as u64,
    ]
}
pub fn home(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute()
            && path.canonicalize()? == path
            && fs::metadata(path)?.dev() == fs::metadata("/home/sol")?.dev(),
        "path is not home-backed: {}",
        path.display()
    );
    Ok(())
}
pub fn read(path: &str) -> Result<(Value, Value)> {
    read_owned(path, 0)
}
fn read_owned(path: &str, owner: u32) -> Result<(Value, Value)> {
    let p = Path::new(path);
    ensure!(
        p.is_absolute() && p.canonicalize()? == p,
        "noncanonical evidence"
    );
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(p)?;
    let m = file.metadata()?;
    ensure!(
        m.is_file()
            && m.uid() == owner
            && m.nlink() == 1
            && m.mode() & 0o022 == 0
            && m.len() <= 32 << 20,
        "unsafe join evidence"
    );
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take((32 << 20) + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == m.len()
            && identity(&m) == identity(&file.metadata()?)
            && identity(&m) == identity(&fs::symlink_metadata(p)?),
        "join evidence changed"
    );
    Ok((
        serde_json::from_slice(&bytes)?,
        json!({"path":path,"sha256":sha(&bytes)}),
    ))
}
pub fn bound(binding: &Value) -> Result<Value> {
    let (v, actual) = read(string(binding, "path")?)?;
    ensure!(actual == *binding, "join evidence digest differs");
    Ok(v)
}
pub fn run(command: &mut Command) -> Result<String> {
    let out = command.output()?;
    ensure!(
        out.status.success(),
        "native command failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    Ok(String::from_utf8(out.stdout)?)
}
pub fn native(unit: &str) -> Result<Value> {
    ensure!(
        unit.ends_with(".service") || unit.ends_with(".timer"),
        "native unit required"
    );
    let out=run(Command::new("/usr/bin/systemctl").args(["show",unit,"-pId,LoadState,ActiveState,SubState,MainPID,ControlPID,InvocationID,NRestarts,Job,Result,ExecMainStatus,ExecStart,ExecMainStartTimestampMonotonic,ControlGroup,NextElapseUSecRealtime,Triggers,TriggeredBy"]))?;
    let mut result = serde_json::Map::new();
    for line in out.lines() {
        let (key, value) = line.split_once('=').context("native property")?;
        ensure!(
            result.insert(key.into(), json!(value)).is_none(),
            "duplicate native property"
        );
    }
    Ok(Value::Object(result))
}
fn process(pid: u64) -> Result<(u64, u64)> {
    let raw = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let fields: Vec<_> = raw
        .rsplit_once(')')
        .context("proc stat")?
        .1
        .split_whitespace()
        .collect();
    Ok((
        fields.get(1).context("ppid")?.parse()?,
        fields.get(19).context("start ticks")?.parse()?,
    ))
}
fn in_cgroup(pid: u64, group: &str) -> Result<()> {
    ensure!(
        fs::read_to_string(format!("/proc/{pid}/cgroup"))?
            .lines()
            .any(|line| line == format!("0::{group}")),
        "process escaped producer cgroup"
    );
    Ok(())
}
fn descendant(mut pid: u64, producer: u64) -> Result<()> {
    for _ in 0..32 {
        if pid == producer {
            return Ok(());
        }
        ensure!(pid > 1, "worker not descended from producer");
        pid = process(pid)?.0;
    }
    anyhow::bail!("worker ancestry exceeds bound")
}
fn scratch_from_executable(exe: &Path, producer: u64) -> Result<PathBuf> {
    ensure!(
        exe.is_absolute()
            && exe.starts_with(LANE)
            && exe.file_name().is_some_and(|v| v == "historical-worker"),
        "foreign worker executable"
    );
    let bound = exe.parent().context("bound worker")?;
    let private = bound.parent().context("private worker")?;
    let runtime = private.parent().context("private runtime")?;
    let scratch = runtime.parent().context("scratch")?;
    let run = scratch.parent().context("run")?;
    let run_name = run
        .file_name()
        .and_then(|v| v.to_str())
        .context("run name")?;
    let run_prefix = format!("run-{producer}-");
    ensure!(
        bound.file_name().is_some_and(|v| v == "bound-worker")
            && private
                .file_name()
                .and_then(|v| v.to_str())
                .is_some_and(|v| v.starts_with("jetstreamer-historical-parent-"))
            && runtime
                .file_name()
                .is_some_and(|v| v == ".historical-runtime")
            && scratch.file_name().is_some_and(|v| v == "scratch")
            && run_name
                .strip_prefix(&run_prefix)
                .is_some_and(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))
            && run
                .parent()
                .and_then(Path::file_name)
                .is_some_and(|v| v == "root-cohort-170-170"),
        "worker path is not this producer's epoch170 scratch"
    );
    Ok(scratch.to_owned())
}
fn discover_worker(producer: u64, group: &str) -> Result<(PathBuf, Value)> {
    let mut workers = Vec::new();
    for line in fs::read_to_string(format!("/sys/fs/cgroup{group}/cgroup.procs"))?.lines() {
        let pid = line.parse::<u64>()?;
        let exe = match fs::read_link(format!("/proc/{pid}/exe")) {
            Ok(v) => v,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e.into()),
        };
        if exe.file_name().is_some_and(|v| v == "historical-worker") {
            workers.push((pid, exe));
        }
    }
    ensure!(
        workers.len() == 1,
        "join requires exactly one actual epoch170 worker; no scratch is guessed"
    );
    let (pid, exe) = workers.pop().context("worker")?;
    let start = process(pid)?.1;
    in_cgroup(pid, group)?;
    descendant(pid, producer)?;
    let scratch = scratch_from_executable(&exe, producer)?;
    home(&scratch)?;
    let m = fs::symlink_metadata(&scratch)?;
    let producer_uid = fs::metadata(format!("/proc/{producer}"))?.uid();
    ensure!(
        producer_uid == 1001 && m.is_dir() && m.uid() == producer_uid && m.mode() & 0o7777 == 0o700,
        "unsafe scratch directory"
    );
    let worker = fs::read(format!("/proc/{pid}/exe"))?;
    ensure!(
        sha(&worker) == WORKER_SHA
            && fs::read_link(format!("/proc/{pid}/exe"))? == exe
            && process(pid)?.1 == start,
        "worker image or start changed"
    );
    let (cohort, _) = read_owned(
        scratch
            .parent()
            .context("run")?
            .join("cohort-state.json")
            .to_str()
            .context("cohort path")?,
        producer_uid,
    )?;
    ensure!(
        cohort["schema"] == "jetstreamer-root-cohort-run-v1"
            && cohort["start_epoch"] == 170
            && cohort["end_epoch"] == 170,
        "cohort differs"
    );
    Ok((
        scratch.clone(),
        json!({"pid":pid,"start_ticks":start,"executable":exe,"sha256":WORKER_SHA,"cgroup":group,
        "scratch_path":scratch,"scratch_device":m.dev(),"scratch_inode":m.ino(),"producer_ancestry_verified":true}),
    ))
}
fn producer_shape(
    a: &Value,
    p: &Value,
    original: &Value,
    current: &Value,
) -> Result<(u64, String)> {
    let pid = integer(a, "producer_pid")?;
    let iid = string(a, "producer_invocation_id")?;
    ensure!(
        pid > 1
            && iid.len() == 32
            && iid.bytes().all(|b| b.is_ascii_hexdigit())
            && a["schema"] == "horizon-standard-replacement-admission-v1"
            && a["epoch"] == 170
            && a["owner"] == "/root"
            && a["producer_unit"] == UNIT
            && a["fresh_admission_passed"] == true
            && a["all_prior_promises_retained"] == true
            && p["schema"] == "horizon-standard-live-peer-protection-v1"
            && p["epoch"] == 170
            && p["producer_unit"] == UNIT
            && p["producer_invocation_id"] == iid
            && current["Id"] == UNIT
            && current["InvocationID"] == iid
            && current["MainPID"]
                .as_str()
                .and_then(|s| s.parse::<u64>().ok())
                == Some(pid)
            && current["ActiveState"] == "active"
            && current["SubState"] == "running"
            && current["NRestarts"] == "0"
            && current["ControlPID"] == "0"
            && current["Job"] == ""
            && current["Result"] == "success"
            && original["InvocationID"] == iid
            && original["MainPID"]
                .as_str()
                .and_then(|s| s.parse::<u64>().ok())
                == Some(pid)
            && current["ExecMainStartTimestampMonotonic"]
                == original["ExecMainStartTimestampMonotonic"],
        "actual guarded epoch170 identity differs"
    );
    Ok((pid, iid.to_owned()))
}
/// Read only. Returned owner is a guarded join event, never a measured replay rate.
pub fn joined() -> Result<(Value, Value)> {
    let (a, ab) = read(&format!("{PREFIX}/ACTUAL_REPLACEMENT_ADMISSION.json"))?;
    let (p, pb) = read(&format!("{PREFIX}/ACTUAL_GUARD_PROTECTION.json"))?;
    ensure!(
        p["admission"] == ab,
        "guard protection does not bind admission"
    );
    let original = bound(&a["actual_producer_native"])?;
    let current = native(UNIT)?;
    let (pid, iid) = producer_shape(&a, &p, &original, &current)?;
    let start = process(pid)?.1;
    ensure!(original["MainStartTicks"] == start, "producer PID reused");
    let group = format!("/system.slice/{UNIT}");
    ensure!(current["ControlGroup"] == group, "producer cgroup differs");
    in_cgroup(pid, &group)?;
    ensure!(
        fs::read_link(format!("/proc/{pid}/exe"))? == Path::new(NODE)
            && sha(&fs::read(format!("/proc/{pid}/exe"))?) == NODE_SHA,
        "producer executable differs"
    );
    let prepared = bound(&a["fresh_native_Rust_preparation"])?;
    let argv: Vec<String> = serde_json::from_value(prepared["producer_argv"].clone())?;
    let node = argv
        .iter()
        .position(|v| v == NODE)
        .context("prepared node command")?;
    let actual: Vec<String> = fs::read(format!("/proc/{pid}/cmdline"))?
        .split(|b| *b == 0)
        .filter(|b| !b.is_empty())
        .map(|b| String::from_utf8(b.to_vec()))
        .collect::<std::result::Result<_, _>>()?;
    ensure!(
        actual == argv[node..],
        "producer command differs from genuine preparation"
    );
    let log = format!("{LANE}/producer.log");
    ensure!(
        argv.iter()
            .filter(|v| *v == &format!("--property=StandardOutput=append:{log}"))
            .count()
            == 1,
        "prepared append log differs"
    );
    let log_m = fs::symlink_metadata(&log)?;
    home(Path::new(&log))?;
    ensure!(
        log_m.is_file() && log_m.uid() == 0 && log_m.nlink() == 1,
        "unsafe producer log"
    );
    ensure!(
        p["timer_unit"] == format!("{GUARD}.timer")
            && p["guard_unit"] == format!("{GUARD}.service"),
        "guard units differ"
    );
    let timer = native(&format!("{GUARD}.timer"))?;
    let service = native(&format!("{GUARD}.service"))?;
    ensure!(
        timer["ActiveState"] == "active"
            && timer["InvocationID"] == p["timer_invocation_id"]
            && timer["Triggers"] == format!("{GUARD}.service")
            && timer["Job"] == ""
            && service["Result"] == "success"
            && service["ExecMainStatus"] == "0",
        "native guard protection differs"
    );
    let plan = bound(&p["plan"])?;
    let first = bound(&a["first_guard"])?;
    let sample = bound(&p["first_guard_sample"])?;
    ensure!(
        first["genuine_first_timer_driven_success"] == true
            && first["continuous_Root_supervision"] == true
            && first["receipt"] == p["first_guard_sample"]
            && first["actual_producer"]["InvocationID"] == iid
            && plan["unit"] == UNIT
            && plan["invocation_id"] == iid
            && sample["producer_invocation_id"] == iid
            && sample["trip_reason"].is_null()
            && sample["worker_observation_error"].is_null()
            && sample["plan_sha256"] == p["plan"]["sha256"]
            && sample["guard_sha256"] == GUARD_SHA
            && sample["producer_stop_enabled"] == true,
        "genuine guard proof differs"
    );
    let guard_command = string(&service, "ExecStart")?;
    for word in [
        GUARD_IMAGE,
        GUARD_SHA,
        string(&p["plan"], "path")?,
        string(&p["plan"], "sha256")?,
    ] {
        ensure!(guard_command.contains(word), "native guard command differs");
    }
    ensure!(
        sha(&fs::read(GUARD_IMAGE)?) == GUARD_SHA,
        "guard executable differs"
    );
    let (scratch, worker) = discover_worker(pid, &group)?;
    let after = native(UNIT)?;
    producer_shape(&a, &p, &original, &after)?;
    ensure!(
        process(pid)?.1 == start
            && read(string(&ab, "path")?)?.1 == ab
            && read(string(&pb, "path")?)?.1 == pb,
        "join owner changed"
    );
    let worker_pid = integer(&worker, "pid")?;
    ensure!(
        process(worker_pid)?.1 == integer(&worker, "start_ticks")?
            && fs::read_link(format!("/proc/{worker_pid}/exe"))?
                == Path::new(string(&worker, "executable")?),
        "worker changed during join"
    );
    let final_log = fs::symlink_metadata(&log)?;
    ensure!(
        final_log.is_file()
            && final_log.dev() == log_m.dev()
            && final_log.ino() == log_m.ino()
            && final_log.uid() == 0
            && final_log.nlink() == 1,
        "append log changed during join"
    );
    let observer = json!({"controller_unit":UNIT,"producer_unit":UNIT,"expected_controller_invocation_id":iid,
        "expected_producer_invocation_id":iid,"range":"170","scratch_path":scratch,"worker_executable_basename":"historical-worker",
        "append_log":{"path":log,"device":log_m.dev(),"inode":log_m.ino()}});
    let owner = json!({"epoch":170,"unit":after,"in_current_observer":false,"observer":null,"phase":"bootstrap","progress":null,
        "scratch_path":scratch,"admission":ab,"guard_protection":pb,"native_identity_source":a["actual_producer_native"],
        "worker_identity":worker,"guard_timer_native":timer,"guard_service_native":service,
        "current_identity_from_same_observation":false,"event_driven_guarded_join":true,"transaction_replay_claimed":false,
        "resource_credit_bytes":0,"replay_launch_authorized":false});
    Ok((owner, observer))
}
pub fn merge_config(config: &mut Value, observer: &Value) -> Result<Value> {
    ensure!(
        config["minimum_interval_seconds"] == 1800,
        "observer cadence differs"
    );
    let rows = config["replays"].as_array_mut().context("replays")?;
    ensure!(
        (rows.len() == 2 || rows.len() == 3)
            && rows[0]["range"] == "166"
            && rows[1]["range"] == "167",
        "both original peers required"
    );
    if rows.len() == 2 {
        rows.push(observer.clone());
    }
    ensure!(
        rows[2] == *observer,
        "existing170 observer identity differs"
    );
    let diagnostics = config["diagnostic_replays"]
        .as_array_mut()
        .context("diagnostics")?;
    let mut retired = Vec::new();
    for row in diagnostics.iter().filter(|r| r["range"] == "170") {
        let unit = string(row, "producer_unit")?;
        ensure!(unit != UNIT, "live170 cannot also be diagnostic");
        let old = native(unit)?;
        ensure!(
            old["InvocationID"] == row["expected_producer_invocation_id"]
                && old["MainPID"] == "0"
                && old["ControlPID"] == "0"
                && old["Job"] == ""
                && (old["ActiveState"] == "inactive" || old["ActiveState"] == "failed"),
            "old170 diagnostic owner is not terminal"
        );
        retired.push(json!({"observer_row":row,"terminal_native":old}));
    }
    diagnostics.retain(|row| row["range"] != "170");
    Ok(json!(retired))
}
pub fn validate_sample(row: &Value, owner: &Value) -> Result<()> {
    ensure!(
        row["range"] == "170"
            && row["invocation_binding_stable"] == true
            && row["producer_after"]["unit"] == UNIT
            && row["producer_after"]["invocation_id"] == owner["unit"]["InvocationID"]
            && owner["unit"]["MainPID"]
                .as_str()
                .and_then(|s| s.parse::<u64>().ok())
                == Some(
                    row["producer_after"]["main_pid"]
                        .as_u64()
                        .context("sample PID")?
                )
            && row["producer_after"]["active_state"] == "active"
            && row["producer_after"]["restarts"] == 0
            && row["scratch_path"] == owner["scratch_path"],
        "sample170 owner or scratch differs"
    );
    Ok(())
}
pub fn preserve_fleet_obligations(before: &Value, after: &Value) -> Result<()> {
    for (key, value) in before.as_object().context("fleet")? {
        if key.starts_with("continuing_")
            || key.starts_with("complete_")
            || key.starts_with("retained_")
        {
            ensure!(
                after[key] == *value,
                "join changed prebooked obligation: {key}"
            );
        }
    }
    ensure!(
        before["epochs"]
            .as_array()
            .context("epochs")?
            .iter()
            .map(|v| integer(v, "epoch"))
            .collect::<Result<BTreeSet<_>>>()?
            == after["epochs"]
                .as_array()
                .context("epochs")?
                .iter()
                .map(|v| integer(v, "epoch"))
                .collect::<Result<BTreeSet<_>>>()?,
        "join changed assigned range"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn worker_metadata_owner_does_not_relax_root_evidence() {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "observer-owner-{}-{nonce}.json",
            std::process::id()
        ));
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        file.write_all(b"{\"worker\":true}").unwrap();
        file.sync_all().unwrap();
        let owner = file.metadata().unwrap().uid();
        let name = path.to_str().unwrap();
        assert_eq!(read_owned(name, owner).unwrap().0, json!({"worker":true}));
        assert!(read_owned(name, owner + 1).is_err());
        if owner != 0 {
            assert!(read(name).is_err());
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(0o622)).unwrap();
        assert!(read_owned(name, owner).is_err());
        fs::remove_file(path).unwrap();
    }
    #[test]
    fn scratch_requires_actual_producer_run_and_worker_layout() {
        let base = format!(
            "{LANE}/private/destination-owned/work/root-cohort-170-170/run-123-456/scratch/.historical-runtime/jetstreamer-historical-parent-abc/bound-worker/historical-worker"
        );
        assert!(scratch_from_executable(Path::new(&base), 123).is_ok());
        assert!(scratch_from_executable(Path::new(&base), 124).is_err());
        for bad in [
            base.replace("root-cohort-170-170", "root-cohort-169-169"),
            base.replace("/scratch/", "/ledger/"),
            base.replace("/.historical-runtime/", "/"),
            base.replace("/.historical-runtime/", "/foreign-runtime/"),
            base.replace("run-123-456", "run-123-guessed"),
            base.replace("historical-parent-abc", "foreign-abc"),
        ] {
            assert!(scratch_from_executable(Path::new(&bad), 123).is_err());
        }
    }
    #[test]
    fn joining_preserves_peers_clock_and_all_other_config_fields() {
        let mut config = json!({"minimum_interval_seconds":1800,"not_before_utc":"unchanged","previous_sample":"same",
            "replays":[{"range":"166","owner":"a"},{"range":"167","owner":"b"}],"diagnostic_replays":[],"other":"preserve"});
        let prior = config.clone();
        let observer = json!({"range":"170","owner":"actual"});
        merge_config(&mut config, &observer).unwrap();
        assert_eq!(config["replays"][0], prior["replays"][0]);
        assert_eq!(config["replays"][1], prior["replays"][1]);
        for key in ["not_before_utc", "previous_sample", "other"] {
            assert_eq!(config[key], prior[key]);
        }
        merge_config(&mut config, &observer).unwrap();
        assert!(merge_config(&mut config, &json!({"range":"170","owner":"different"})).is_err());
    }
    #[test]
    fn fleet_join_cannot_drop_an_existing_obligation() {
        let before = json!({"continuing_audit_obligation":{"bytes":42},"complete_DATA_bytes":99,"retained_old":12,"epochs":[{"epoch":170}]});
        preserve_fleet_obligations(&before, &before).unwrap();
        for key in [
            "continuing_audit_obligation",
            "complete_DATA_bytes",
            "retained_old",
        ] {
            let mut after = before.clone();
            after[key] = Value::Null;
            assert!(preserve_fleet_obligations(&before, &after).is_err());
        }
    }
}
