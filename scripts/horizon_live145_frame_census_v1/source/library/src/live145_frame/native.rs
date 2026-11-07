//! Actual native identities and kernel limits, with bounded systemd queries.
use super::{custody as f, model::*};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    ffi::CString,
    fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    process::Command,
};
const FIELDS: &str = "Id,LoadState,ActiveState,SubState,InvocationID,MainPID,ControlPID,NRestarts,Job,ExecStart,ExecStartPre,Restart,Type,KillMode,ControlGroup,DropInPaths,User,Group,MemoryMax,MemorySwapMax,TasksMax,Triggers,TimersMonotonic";

fn parse(unit: &str, text: &str) -> Result<Value> {
    let mut rows = BTreeMap::<String, String>::new();
    for line in text.lines() {
        let (k, v) = line.split_once('=').context("native property framing")?;
        ensure!(
            FIELDS.split(',').any(|f| f == k),
            "unexpected native property"
        );
        if k == "TimersMonotonic" && unit.ends_with(".timer") {
            let previous = rows.entry(k.into()).or_default();
            ensure!(previous.lines().all(|l| l != v), "duplicate timer schedule");
            if !previous.is_empty() {
                previous.push('\n');
            }
            previous.push_str(v);
        } else {
            ensure!(
                rows.insert(k.into(), v.into()).is_none(),
                "duplicate native property"
            );
        }
    }
    let v = json!(rows);
    ensure!(v["Id"] == unit, "native identity crossed");
    Ok(v)
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeExecStartPre {
    #[serde(rename = "type")]
    kind: String,
    data: Vec<Value>,
}
fn empty_exec_start_pre(bytes: &[u8]) -> Result<()> {
    ensure!(bytes.len() <= 1 << 20, "bounded native pre-start property");
    let typed: NativeExecStartPre = serde_json::from_slice(bytes)?;
    ensure!(
        typed.kind == "a(sasbttttuii)" && typed.data.is_empty(),
        "actual typed pre-start array is not empty"
    );
    Ok(())
}
fn dbus_unit_path(unit: &str) -> String {
    let escaped = unit
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() {
                char::from(b).to_string()
            } else {
                format!("_{b:02x}")
            }
        })
        .collect::<String>();
    format!("/org/freedesktop/systemd1/unit/{escaped}")
}
pub fn show(unit: &str) -> Result<Value> {
    ensure!(
        unit.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
            && unit.len() <= 160,
        "unit syntax"
    );
    let out = Command::new("/usr/bin/timeout")
        .args([
            "--signal=TERM",
            "--kill-after=2s",
            "8s",
            "/usr/bin/systemctl",
            "--system",
            "show",
            unit,
            "--no-pager",
            &format!("--property={FIELDS}"),
        ])
        .env_remove("SYSTEMD_HOST")
        .env_remove("SYSTEMD_BUS_ADDRESS")
        .env_remove("DBUS_SYSTEM_BUS_ADDRESS")
        .env("LC_ALL", "C")
        .output()?;
    ensure!(out.status.success(), "bounded native query failed: {unit}");
    let mut parsed = parse(unit, std::str::from_utf8(&out.stdout)?)?;
    if unit.ends_with(".service") && parsed.get("ExecStartPre").is_none() {
        let object = dbus_unit_path(unit);
        let property = Command::new("/usr/bin/timeout")
            .args([
                "--signal=TERM",
                "--kill-after=2s",
                "8s",
                "/usr/bin/busctl",
                "--system",
                "--json=short",
                "get-property",
                "org.freedesktop.systemd1",
                object.as_str(),
                "org.freedesktop.systemd1.Service",
                "ExecStartPre",
            ])
            .env_remove("SYSTEMD_HOST")
            .env_remove("SYSTEMD_BUS_ADDRESS")
            .env_remove("DBUS_SYSTEM_BUS_ADDRESS")
            .env("LC_ALL", "C")
            .output()?;
        ensure!(
            property.status.success(),
            "bounded typed native pre-start query failed"
        );
        empty_exec_start_pre(&property.stdout)?;
        #[cfg(test)]
        eprintln!(
            "fixture typed pre-start proof unit={unit} object={object} reply={}",
            std::str::from_utf8(&property.stdout)?
        );
        parsed
            .as_object_mut()
            .context("native property object")?
            .insert("ExecStartPre".into(), json!(""));
    }
    Ok(parsed)
}
pub fn ticks(pid: u32) -> Result<u64> {
    let s = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    Ok(s.rsplit_once(") ")
        .context("process framing")?
        .1
        .split_whitespace()
        .nth(19)
        .context("start ticks")?
        .parse()?)
}
fn safe_path(p: &Path) -> Result<&str> {
    let s = p.to_str().context("path utf8")?;
    ensure!(
        p.is_absolute()
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b)),
        "native argv path syntax"
    );
    Ok(s)
}
fn process(pid: u32, start: u64, program: &Bound, cgroup: &str) -> Result<()> {
    ensure!(
        pid > 1
            && ticks(pid)? == start
            && fs::read_link(format!("/proc/{pid}/exe"))? == program.path,
        "process identity changed"
    );
    let status = fs::read_to_string(format!("/proc/{pid}/status"))?;
    let uids = status
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .context("process UIDs")?;
    ensure!(
        uids.split_whitespace().collect::<Vec<_>>() == ["0", "0", "0", "0"],
        "Root actor/guard identity"
    );
    ensure!(
        fs::read_to_string(format!("/proc/{pid}/cgroup"))?.trim() == format!("0::{cgroup}"),
        "exact cgroup membership"
    );
    Ok(())
}
pub fn owner(p: &Plan, pb: &Bound, guard: bool, pid: u32, iid: &str, start: u64) -> Result<Value> {
    ensure!(f::hex(iid, 32), "native IID syntax");
    let unit = if guard { &p.guard_unit } else { &p.actor_unit };
    let v = show(unit)?;
    #[cfg(test)]
    eprintln!(
        "fixture native owner snapshot {}",
        json!({"expected_unit":unit,"expected_iid":iid,"expected_pid":pid,"expected_start_ticks":start,"guard_role":guard,"native":v})
    );
    let group = format!("/system.slice/{unit}");
    let prefix = format!(
        "{{ path={} ; argv[]={} {} {} --plan-sha256 {} --self-sha256 {} ;",
        safe_path(&p.program.path)?,
        safe_path(&p.program.path)?,
        if guard { "guard" } else { "extract" },
        safe_path(&pb.path)?,
        pb.sha256,
        p.program.sha256
    );
    ensure!(
        v["LoadState"] == "loaded"
            && v["ActiveState"] == "active"
            && v["SubState"] == "running"
            && v["InvocationID"] == iid
            && v["MainPID"].as_str().and_then(|s| s.parse::<u32>().ok()) == Some(pid)
            && v["ControlPID"] == "0"
            && v["NRestarts"] == "0"
            && v["Job"] == ""
            && v["Restart"] == "no"
            && v["Type"] == "exec"
            && v["KillMode"] == "control-group"
            && v["ControlGroup"] == group
            && v["DropInPaths"] == ""
            && v["ExecStartPre"] == ""
            && v["User"] == "root"
            && v["Group"] == "root"
            && v["ExecStart"]
                .as_str()
                .is_some_and(|s| s.starts_with(&prefix) && s.matches("argv[]=").count() == 1),
        "exact running native actor/guard"
    );
    process(pid, start, &p.program, &group)?;
    let cg = PathBuf::from("/sys/fs/cgroup").join(group.trim_start_matches('/'));
    ensure!(cg.canonicalize()? == cg, "cgroup path alias");
    let memory = if guard {
        p.guard_memory_bytes
    } else {
        p.actor_memory_bytes
    };
    let cpu = if guard {
        p.guard_cpu_quota_micros
    } else {
        p.actor_cpu_quota_micros
    };
    ensure!(
        fs::read_to_string(cg.join("memory.max"))?.trim() == memory.to_string()
            && fs::read_to_string(cg.join("memory.swap.max"))?.trim() == "0"
            && fs::read_to_string(cg.join("pids.max"))?.trim() == p.tasks_max.to_string(),
        "kernel memory/swap/task bounds"
    );
    let cp = fs::read_to_string(cg.join("cpu.max"))?;
    let parts = cp.split_whitespace().collect::<Vec<_>>();
    ensure!(
        parts.len() == 2 && parts[0] != "max",
        "kernel CPU quota missing"
    );
    let quota: u64 = parts[0].parse()?;
    let period: u64 = parts[1].parse()?;
    ensure!(
        quota.checked_mul(1_000_000) == cpu.checked_mul(period),
        "kernel CPU quota differs"
    );
    Ok(v)
}
pub fn original() -> Result<Value> {
    let v = show(ORIGINAL_UNIT)?;
    ensure!(
        v["ActiveState"] == "inactive"
            && v["SubState"] == "dead"
            && v["InvocationID"] == ""
            && v["MainPID"] == "0"
            && v["ControlPID"] == "0"
            && v["NRestarts"] == "0"
            && v["Job"] == "",
        "original145 owner revived"
    );
    let cg = Path::new("/sys/fs/cgroup/system.slice").join(ORIGINAL_UNIT);
    if cg.exists() {
        ensure!(
            fs::read_to_string(cg.join("cgroup.procs"))?
                .trim()
                .is_empty()
                && fs::read_to_string(cg.join("cgroup.events"))?
                    .lines()
                    .any(|l| l == "populated 0"),
            "original145 cgroup not drained"
        );
    }
    Ok(v)
}
pub fn timer(p: &Plan) -> Result<Value> {
    let v = show(&p.timer_unit)?;
    ensure!(
        v["LoadState"] == "loaded"
            && v["ActiveState"] == "active"
            && matches!(v["SubState"].as_str(), Some("waiting" | "running"))
            && v["Triggers"] == p.guard_unit
            && v["DropInPaths"] == "",
        "native guard timer not armed"
    );
    let schedules = v["TimersMonotonic"]
        .as_str()
        .context("native timer schedules")?
        .lines()
        .collect::<Vec<_>>();
    ensure!(
        schedules.len() == 2
            && schedules
                .iter()
                .filter(|s| s.starts_with("{ OnActiveUSec=1s ; next_elapse=") && s.ends_with(" }"))
                .count()
                == 1
            && schedules
                .iter()
                .filter(
                    |s| s.starts_with("{ OnUnitActiveUSec=30s ; next_elapse=") && s.ends_with(" }")
                )
                .count()
                == 1,
        "native original guard cadence"
    );
    Ok(v)
}
pub fn resources(p: &Plan, a: &Admission) -> Result<(u64, u64)> {
    directories(p)?;
    let c = CString::new("/home/sol")?;
    let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe { libc::statvfs(c.as_ptr(), &mut s) } == 0,
        "free-space statvfs"
    );
    let free = s
        .f_bavail
        .checked_mul(s.f_frsize)
        .context("free-space overflow")?;
    let text = fs::read_to_string("/proc/meminfo")?;
    let avail = text
        .lines()
        .find_map(|l| l.strip_prefix("MemAvailable:"))
        .context("MemAvailable")?
        .split_whitespace()
        .next()
        .context("MemAvailable integer")?
        .parse::<u64>()?
        .checked_mul(1024)
        .context("memory overflow")?;
    ensure!(
        free >= a.required_initial_data_bytes.max(p.minimum_free_bytes)
            && avail
                >= a.required_initial_memory_bytes
                    .max(p.minimum_available_memory_bytes),
        "protected DATA/memory floor breached"
    );
    ensure!(
        f::now()? <= p.execution_deadline,
        "original execution deadline expired"
    );
    Ok((free, avail))
}
pub fn directories(p: &Plan) -> Result<()> {
    let home = fs::metadata("/home/sol")?;
    for (path, expected) in [
        (&p.output_root, &p.output_directory_identity),
        (&p.state_root, &p.state_directory_identity),
    ] {
        f::private_directory(path)?;
        let m = fs::symlink_metadata(path)?;
        ensure!(
            m.dev() == expected.device && m.ino() == expected.inode && m.dev() == home.dev(),
            "admitted directory inode or budget filesystem changed"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn duplicate_native_identity_cannot_hide_restart() {
        assert!(parse("x.service", "Id=x.service\nNRestarts=0\nNRestarts=1\n").is_err());
    }
    #[test]
    fn timer_parser_preserves_both_native_schedules_without_duplicate_loss() {
        let v=parse("x.timer","Id=x.timer\nTimersMonotonic={ OnActiveUSec=1s ; next_elapse=1s }\nTimersMonotonic={ OnUnitActiveUSec=30s ; next_elapse=30s }\n").unwrap();
        assert_eq!(v["TimersMonotonic"].as_str().unwrap().lines().count(), 2);
        assert!(
            parse(
                "x.timer",
                "Id=x.timer\nTimersMonotonic=a\nTimersMonotonic=a\n"
            )
            .is_err()
        );
    }
    #[test]
    fn native_argv_cannot_inject_additional_arguments() {
        assert!(safe_path(Path::new("/a --flag")).is_err());
    }
    #[test]
    fn typed_empty_prestart_requires_exact_actual_empty_array() {
        empty_exec_start_pre(br#"{"type":"a(sasbttttuii)","data":[]}"#).unwrap();
        for raw in [
            br#"{}"#.as_slice(),
            br#"{"type":"s","data":[]}"#,
            br#"{"type":"a(sasbttttuii)","data":[["/bin/true"]]}"#,
            br#"{"type":"a(sasbttttuii)","data":null}"#,
            br#"{"type":"a(sasbttttuii)","data":[],"extra":true}"#,
            br#"{"type":"s","type":"a(sasbttttuii)","data":[]}"#,
        ] {
            assert!(empty_exec_start_pre(raw).is_err());
        }
    }
    #[test]
    fn native_dbus_unit_path_escapes_underscore_dash_and_dot_exactly() {
        assert_eq!(
            dbus_unit_path("horizon-actor_1.service"),
            "/org/freedesktop/systemd1/unit/horizon_2dactor_5f1_2eservice"
        );
    }
}
