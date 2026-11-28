//! Read-only controller exit proof for a hash-bound pressure checkpoint report.
//! Does not signal workers, validate archive bodies, release reservations or resume.
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
};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Evidence {
    path: PathBuf,
    sha256: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    unit: String,
    invocation_id: String,
    producer_pid: i32,
    epoch: u64,
    report: Evidence,
    output: PathBuf,
}
fn require(ok: bool, message: &str) -> Result<()> {
    if ok { Ok(()) } else { Err(message.into()) }
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn valid_hex(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn identity(m: &fs::Metadata) -> (u64, u64, u64, i64, i64, i64, i64) {
    (
        m.dev(),
        m.ino(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}
fn bound_bytes(e: &Evidence, sealed: bool) -> Result<Vec<u8>> {
    require(valid_hex(&e.sha256, 64), "invalid evidence digest")?;
    require(
        e.path.is_absolute() && e.path.canonicalize()? == e.path,
        "noncanonical evidence path",
    )?;
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&e.path)?;
    let before = f.metadata()?;
    require(
        before.is_file() && before.uid() == 0 && before.nlink() == 1 && before.len() <= 4 << 20,
        "evidence must be bounded, root-owned and singly linked",
    )?;
    require(
        if sealed {
            before.mode() & 0o222 == 0
        } else {
            before.mode() & 0o077 == 0
        },
        "invalid evidence custody",
    )?;
    let mut bytes = Vec::new();
    (&mut f).take((4 << 20) + 1).read_to_end(&mut bytes)?;
    require(
        digest(&bytes) == e.sha256
            && identity(&before) == identity(&f.metadata()?)
            && identity(&before) == identity(&fs::symlink_metadata(&e.path)?),
        "evidence changed or digest differs",
    )?;
    Ok(bytes)
}
fn validate_plan(p: &Plan) -> Result<()> {
    require(
        p.schema == "horizon-pressure-exit-plan-v1",
        "unknown exit plan schema",
    )?;
    require(
        p.unit.starts_with("horizon-")
            && p.unit.ends_with(".service")
            && p.unit.len() < 200
            && p.unit
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
            && !p.unit.contains(".."),
        "invalid service name",
    )?;
    require(
        valid_hex(&p.invocation_id, 32) && p.producer_pid > 1,
        "invalid producer identity",
    )?;
    require(
        p.output.is_absolute() && p.output.file_name().is_some(),
        "invalid output path",
    )
}
const PROPERTIES: &str = "Id,LoadState,ActiveState,SubState,InvocationID,MainPID,ControlPID,ExecMainPID,ExecMainCode,ExecMainStatus,Result,NRestarts,Restart,KillMode,Delegate,ControlGroup";
fn inspect(unit: &str) -> Result<BTreeMap<String, String>> {
    let output = Command::new("/usr/bin/systemctl")
        .args([
            "--system",
            "show",
            unit,
            "--no-pager",
            "--property",
            PROPERTIES,
        ])
        .env_clear()
        .env("LC_ALL", "C")
        .output()?;
    require(output.status.success(), "systemd inspection failed")?;
    let mut properties = BTreeMap::new();
    for line in std::str::from_utf8(&output.stdout)?.lines() {
        let (k, v) = line.split_once('=').ok_or("invalid systemd property")?;
        require(
            properties.insert(k.into(), v.into()).is_none(),
            "duplicate systemd property",
        )?;
    }
    Ok(properties)
}
fn validate_terminal(p: &Plan, s: &BTreeMap<String, String>) -> Result<()> {
    let get = |key: &str| s.get(key).map(String::as_str).unwrap_or("");
    require(
        get("Id") == p.unit
            && get("LoadState") == "loaded"
            && get("InvocationID") == p.invocation_id
            && get("ExecMainPID") == p.producer_pid.to_string(),
        "terminal service identity differs or was collected",
    )?;
    require(
        matches!(
            (get("ActiveState"), get("SubState")),
            ("inactive", "dead") | ("active", "exited")
        ) && get("MainPID") == "0"
            && get("ControlPID") == "0"
            && get("ExecMainCode") == "1"
            && get("ExecMainStatus") == "0"
            && get("Result") == "success"
            && get("NRestarts") == "0"
            && get("Restart") == "no"
            && get("KillMode") == "control-group"
            && get("Delegate") == "no",
        "producer is not a clean, unrestarted, nondelegated terminal invocation",
    )?;
    require(
        get("ControlGroup").is_empty()
            || get("ControlGroup") == format!("/system.slice/{}", p.unit),
        "unexpected producer cgroup",
    )
}
fn validate_report(p: &Plan, r: &Value) -> Result<()> {
    worker_pid(r, p.producer_pid)?;
    require(
        r["schema"] == "horizon-pressure-checkpoint-paused-v3"
            && r["epoch"] == p.epoch
            && r["producer_pid"] == p.producer_pid
            && r["producer_invocation_id"] == p.invocation_id
            && r["worker_shutdown_acknowledged"] == true
            && r["worker_reap_verified"] == true
            && r["worker_shutdown"]["state"] == "reaped"
            && r["full_range_completed"] == false
            && r["resume_authorized"] == false
            && r["resource_release_authorized"] == false
            && r["publication_authorized"] == false,
        "paused report identity, reap outcome or authority differs",
    )?;
    require(
        r["selected_source_slot"]
            .as_u64()
            .zip(r["intended_terminal_slot"].as_u64())
            .is_some_and(|(s, e)| s < e),
        "report is not a proper paused prefix",
    )
}
fn worker_pid(report: &Value, producer: i32) -> Result<i32> {
    let pid: i32 = report["worker_shutdown"]["worker_pid"]
        .as_u64()
        .ok_or("missing reaped worker PID")?
        .try_into()?;
    require(
        pid > 1 && pid != producer && report["worker_shutdown"]["forced"].is_boolean(),
        "invalid reaped worker identity",
    )?;
    Ok(pid)
}
fn absent_pid(pid: i32) -> Result<()> {
    require(
        unsafe { libc::kill(pid, 0) } == -1
            && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH),
        "recorded producer PID still exists or absence cannot be proven",
    )
}
fn cgroup_empty(unit: &str) -> Result<Value> {
    let path = PathBuf::from("/sys/fs/cgroup/system.slice").join(unit);
    match fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Ok(json!({"path":path,"state":"absent"}))
        }
        Err(e) => Err(e.into()),
        Ok(m) => {
            require(
                m.is_dir() && path.canonicalize()? == path,
                "unexpected cgroup custody",
            )?;
            let events = fs::read_to_string(path.join("cgroup.events"))?;
            require(
                events
                    .lines()
                    .filter(|line| line.starts_with("populated "))
                    .collect::<Vec<_>>()
                    == vec!["populated 0"],
                "producer cgroup remains populated or has invalid events",
            )?;
            Ok(json!({"path":path,"state":"empty","events":events}))
        }
    }
}

// Repeating a completed observation must not overwrite its receipt. This also
// covers a controller dying after the no-clobber rename but before directory
// fsync. The caller always repeats every live identity/absence check first.
fn persist_receipt(path: &Path, receipt: &Value) -> Result<bool> {
    let directory = path.parent().ok_or("receipt parent absent")?;
    let mut bytes = serde_json::to_vec_pretty(receipt)?;
    bytes.push(b'\n');
    let mut output = tempfile::NamedTempFile::new_in(directory)?;
    output.write_all(&bytes)?;
    output.as_file().sync_all()?;
    match output.persist_noclobber(path) {
        Ok(_) => {
            File::open(directory)?.sync_all()?;
            Ok(false)
        }
        Err(e) if e.error.kind() == std::io::ErrorKind::AlreadyExists => {
            // bound_bytes checks owner, mode, regular-file/no-follow custody,
            // link count, size, exact bytes and stable path/file identity.
            let binding = Evidence {
                path: path.into(),
                sha256: digest(&bytes),
            };
            require(
                bound_bytes(&binding, false)? == bytes,
                "existing exit receipt differs from the fresh observation",
            )?;
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(path)?;
            let before = identity(&file.metadata()?);
            file.sync_all()?;
            File::open(directory)?.sync_all()?;
            require(
                before == identity(&fs::symlink_metadata(path)?)
                    && bound_bytes(&binding, false)? == bytes,
                "existing exit receipt changed during durability recovery",
            )?;
            Ok(true)
        }
        Err(e) => Err(e.error.into()),
    }
}
fn run(args: &[String]) -> Result<()> {
    require(
        args.len() == 5 && args[1] == "--plan-sha256" && args[3] == "--self-sha256",
        "usage: pressure-checkpoint-exit PLAN --plan-sha256 HEX --self-sha256 HEX",
    )?;
    require(unsafe { libc::geteuid() } == 0, "exit proof requires root")?;
    require(
        valid_hex(&args[4], 64) && digest(&fs::read("/proc/self/exe")?) == args[4],
        "tool digest differs",
    )?;
    let binding = Evidence {
        path: args[0].clone().into(),
        sha256: args[2].clone(),
    };
    let bytes = bound_bytes(&binding, true)?;
    let p: Plan = serde_json::from_slice(&bytes)?;
    validate_plan(&p)?;
    let directory = p.output.parent().ok_or("output parent absent")?;
    let parent = fs::symlink_metadata(directory)?;
    require(
        parent.is_dir()
            && parent.uid() == 0
            && parent.mode() & 0o077 == 0
            && directory.canonicalize()? == directory,
        "output requires root-private canonical parent",
    )?;
    let before = inspect(&p.unit)?;
    validate_terminal(&p, &before)?;
    let report_bytes = bound_bytes(&p.report, false)?;
    let report: Value = serde_json::from_slice(&report_bytes)?;
    validate_report(&p, &report)?;
    let worker_pid = worker_pid(&report, p.producer_pid)?;
    absent_pid(p.producer_pid)?;
    absent_pid(worker_pid)?;
    let cgroup_before = cgroup_empty(&p.unit)?;
    let after = inspect(&p.unit)?;
    validate_terminal(&p, &after)?;
    require(
        before == after,
        "producer identity changed during exit proof",
    )?;
    absent_pid(p.producer_pid)?;
    absent_pid(worker_pid)?;
    let cgroup_after = cgroup_empty(&p.unit)?;
    require(
        bound_bytes(&p.report, false)? == report_bytes && bound_bytes(&binding, true)? == bytes,
        "exit input changed during observation",
    )?;
    let receipt = json!({"schema":"horizon-pressure-exit-proof-v1","plan":binding,"tool_sha256":args[4],
        "producer_before":before,"producer_after":after,"report":p.report,"epoch":p.epoch,
        "cgroup_before":cgroup_before,"cgroup_after":cgroup_after,"producer_pid_absent":true,"worker_pid_absent":true,
        "checkpoint_bundle_validation_required":true,"full_parent_firehose_qualified":false,
        "resource_release_authorized":false,"resume_authorized":false,"publication_authorized":false});
    let reused = persist_receipt(&p.output, &receipt)?;
    println!(
        "{}",
        json!({"outcome":"exit-proven","receipt":p.output,"receipt_reused":reused,"resource_release_authorized":false,"resume_authorized":false})
    );
    Ok(())
}
fn main() {
    if let Err(e) = run(&std::env::args().skip(1).collect::<Vec<_>>()) {
        eprintln!("pressure exit proof rejected: {e}");
        std::process::exit(1)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn plan() -> Plan {
        Plan {
            schema: "horizon-pressure-exit-plan-v1".into(),
            unit: "horizon-test.service".into(),
            invocation_id: "a".repeat(32),
            producer_pid: 1234,
            epoch: 252,
            report: Evidence {
                path: "/private/paused.json".into(),
                sha256: "b".repeat(64),
            },
            output: "/private/exit.json".into(),
        }
    }
    fn terminal(p: &Plan) -> BTreeMap<String, String> {
        [
            ("Id", p.unit.clone()),
            ("LoadState", "loaded".into()),
            ("InvocationID", p.invocation_id.clone()),
            ("ExecMainPID", p.producer_pid.to_string()),
            ("ActiveState", "active".into()),
            ("SubState", "exited".into()),
            ("MainPID", "0".into()),
            ("ControlPID", "0".into()),
            ("ExecMainCode", "1".into()),
            ("ExecMainStatus", "0".into()),
            ("Result", "success".into()),
            ("NRestarts", "0".into()),
            ("Restart", "no".into()),
            ("KillMode", "control-group".into()),
            ("Delegate", "no".into()),
            ("ControlGroup", format!("/system.slice/{}", p.unit)),
        ]
        .into_iter()
        .map(|(k, v)| (k.into(), v))
        .collect()
    }
    #[test]
    fn rejects_live_failed_restarted_or_replaced_producers() {
        let p = plan();
        let good = terminal(&p);
        validate_plan(&p).unwrap();
        validate_terminal(&p, &good).unwrap();
        for (key, bad) in [
            ("InvocationID", "b"),
            ("ExecMainPID", "4321"),
            ("LoadState", "not-found"),
            ("MainPID", "1"),
            ("ControlPID", "1"),
            ("ExecMainStatus", "1"),
            ("ExecMainCode", "2"),
            ("NRestarts", "1"),
            ("Result", "signal"),
            ("Restart", "always"),
            ("KillMode", "process"),
            ("Delegate", "yes"),
            ("ControlGroup", "/system.slice/other.service"),
            ("SubState", "running"),
        ] {
            let mut s = good.clone();
            s.insert(key.into(), bad.into());
            assert!(validate_terminal(&p, &s).is_err(), "{key}");
        }
    }
    #[test]
    fn report_cannot_claim_completion_or_release() {
        let p = plan();
        let good = json!({"schema":"horizon-pressure-checkpoint-paused-v3","epoch":252,"producer_pid":1234,"producer_invocation_id":p.invocation_id,
        "worker_shutdown_acknowledged":true,"worker_reap_verified":true,"worker_shutdown":{"state":"reaped","worker_pid":1240,"forced":false},"selected_source_slot":10,"intended_terminal_slot":20,
        "full_range_completed":false,"resume_authorized":false,"resource_release_authorized":false,"publication_authorized":false});
        validate_report(&p, &good).unwrap();
        for key in [
            "full_range_completed",
            "resume_authorized",
            "resource_release_authorized",
            "publication_authorized",
        ] {
            let mut bad = good.clone();
            bad[key] = json!(true);
            assert!(validate_report(&p, &bad).is_err());
        }
        for (key, value) in [
            ("worker_reap_verified", json!(false)),
            ("producer_pid", json!(4321)),
            ("producer_invocation_id", json!("b")),
            ("selected_source_slot", json!(20)),
        ] {
            let mut bad = good.clone();
            bad[key] = value;
            assert!(validate_report(&p, &bad).is_err());
        }
    }
    #[test]
    fn rejects_bad_unit_names_and_existing_pid() {
        for unit in [
            "../horizon-test.service",
            "horizon-a/child.service",
            "horizon-..service",
            "horizon-a@x.service",
            "other.service",
        ] {
            let mut p = plan();
            p.unit = unit.into();
            assert!(validate_plan(&p).is_err());
        }
        let mut p = plan();
        p.invocation_id = "A".repeat(32);
        assert!(validate_plan(&p).is_err());
        assert!(absent_pid(std::process::id() as i32).is_err());
    }

    #[test]
    #[ignore = "root-private receipt recovery; run the sealed test as root"]
    fn receipt_retry_preserves_original_and_rejects_conflicts_and_links() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("proof.json");
        let receipt = json!({"producer":1234,"publication_authorized":false});
        assert!(!persist_receipt(&path, &receipt).unwrap());
        let before = identity(&fs::metadata(&path).unwrap());
        let bytes = fs::read(&path).unwrap();
        // A second process after publication must reuse the exact inode/bytes.
        assert!(persist_receipt(&path, &receipt).unwrap());
        assert_eq!(before, identity(&fs::metadata(&path).unwrap()));
        assert_eq!(bytes, fs::read(&path).unwrap());
        let changed = json!({"producer":4321,"publication_authorized":false});
        assert!(persist_receipt(&path, &changed).is_err());
        assert_eq!(bytes, fs::read(&path).unwrap());
        let link = temp.path().join("linked.json");
        symlink(&path, &link).unwrap();
        assert!(persist_receipt(&link, &receipt).is_err());
        fs::remove_file(&link).unwrap();
        fs::hard_link(&path, &link).unwrap();
        assert!(persist_receipt(&path, &receipt).is_err());
        fs::remove_file(link).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(persist_receipt(&path, &receipt).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&path, b"truncated").unwrap();
        assert!(persist_receipt(&path, &receipt).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"truncated");
    }

    // This fixture validates controller/systemd mechanics only. It deliberately
    // creates no archive or checkpoint bundle and cannot qualify replay recovery.
    #[test]
    #[ignore = "isolated controller crash after exit-proof publication"]
    fn exit_fixture_controller_interrupted_after_receipt() {
        let tool = std::env::var("HORIZON_EXIT_FIXTURE_TOOL").unwrap();
        let plan = std::env::var("HORIZON_EXIT_FIXTURE_PLAN").unwrap();
        let plan_sha = std::env::var("HORIZON_EXIT_FIXTURE_PLAN_SHA256").unwrap();
        let tool_sha = std::env::var("HORIZON_EXIT_FIXTURE_TOOL_SHA256").unwrap();
        assert!(
            Command::new(tool)
                .args([
                    plan,
                    "--plan-sha256".into(),
                    plan_sha,
                    "--self-sha256".into(),
                    tool_sha
                ])
                .status()
                .unwrap()
                .success()
        );
        // No controller completion receipt or successful process exit. A fresh
        // controller must discover and revalidate the actual durable result.
        unsafe { libc::_exit(86) }
    }

    #[test]
    #[ignore = "isolated systemd exit-proof fixture; no archive/recovery authority"]
    fn exit_fixture_producer() {
        let directory = PathBuf::from(std::env::var_os("HORIZON_EXIT_FIXTURE_DIRECTORY").unwrap());
        let mut worker = Command::new("/usr/bin/true").spawn().unwrap();
        let pid = worker.id();
        assert!(worker.wait().unwrap().success());
        if std::env::var_os("HORIZON_EXIT_FIXTURE_LINGER").is_some() {
            // Intentionally leave one descendant in this isolated fixture's
            // cgroup. The real exit-proof command must reject it.
            Command::new("/usr/bin/sleep")
                .arg("60")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap();
        }
        let report = json!({"schema":"horizon-pressure-checkpoint-paused-v3","epoch":252,
            "producer_pid":std::process::id(),"producer_invocation_id":std::env::var("INVOCATION_ID").unwrap(),
            "worker_shutdown_acknowledged":true,"worker_reap_verified":true,
            "worker_shutdown":{"state":"reaped","worker_pid":pid,"forced":false},
            "selected_source_slot":10,"intended_terminal_slot":20,
            "full_range_completed":false,"resume_authorized":false,"resource_release_authorized":false,
            "publication_authorized":false,"synthetic_exit_fixture_only":true});
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(directory.join("paused.json"))
            .unwrap();
        serde_json::to_writer_pretty(&mut f, &report).unwrap();
        f.sync_all().unwrap();
        File::open(directory).unwrap().sync_all().unwrap();
    }
}
