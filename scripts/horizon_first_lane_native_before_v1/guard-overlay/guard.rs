//! One direct epoch 163 parent, original-199 memory continuity, filesystem floor and VMAs.
//! The only stop target is the new epoch 163 parent. No controller, importer or archive mutation.
#![deny(warnings)]
mod bounded_profile;
#[allow(dead_code)]
mod fsutil;
mod qualified_node;
use anyhow::{Context, Result, ensure};
use fsutil as f;
use horizon_original199_parent_memory as parent_memory;
use horizon_terminal183_ended_data as selected_data;
use model::Bound;
pub use parent_memory::model;
use qualified_node::NODE_SHA;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    env,
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Read, Write},
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};
const IMAGE: &str = "/usr/local/lib/jetstreamer/horizon-first-lane-witness-first163128-guard-tools-20261107-v2/first163128-guard";
const DATA_IMAGE: &str = "/usr/local/lib/jetstreamer/horizon-first-lane-witness-ended183-DATA-selector-tools-20261107-v4/ended183-data";
const DATA_SHA: &str = "85f374198bd5418bfa269faf01c9751b50f30a94a0cb0c0cc9a9b8b18133d243";
const DATA_UNIT: &str = "horizon-epoch183-ended-DATA-select-20261105-v1.service";
const UNIT: &str = "horizon-epoch163-first-output128-20261106-v1.service";
const GUARD: &str = "horizon-guard-epoch163-first-output128-20261106-v1.service";
const STOPPER: &str = "horizon-stop-epoch163-first-output128-20261106-v1.service";
const TIMER: &str = "horizon-guard-epoch163-first-output128-20261106-v1.timer";
const OUT: &str = "/var/lib/jetstreamer/epoch163-first-output128-20261106-v1/guard";
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    parent_unit: String,
    parent_invocation_id: String,
    parent_program: Bound,
    parent_argv: Vec<String>,
    parent_start_ticks: u64,
    input_policy: Bound,
    admission: Bound,
    selected_memory_receipt: Bound,
    selected_memory_original_completion: Bound,
    selected_data_receipt: Bound,
    selected_data_original_completion: Bound,
    filesystem: PathBuf,
    minimum_free_bytes: u64,
    maximum_worker_vmas: u64,
    guard_timer: String,
    output_directory: PathBuf,
}
fn scope(p: &Plan) -> Result<()> {
    ensure!(
        p.schema == "epoch163-first-output128-memory-DATA-reserve-vma-guard-plan-v1"
            && p.parent_unit == UNIT
            && f::hex(&p.parent_invocation_id, 32)
            && p.filesystem == Path::new("/home/sol")
            && p.minimum_free_bytes > 0
            && f::hex(&p.selected_data_receipt.sha256, 64)
            && f::hex(&p.selected_data_original_completion.sha256, 64)
            && p.maximum_worker_vmas > 0
            && p.guard_timer == TIMER
            && p.output_directory == Path::new(OUT)
            && p.parent_program.path
                == Path::new(
                    "/usr/local/lib/jetstreamer/horizon-first-lane-witness-first163128-node-tools-20261107-v2/jetstreamer-node"
                )
            && p.parent_program.sha256 == NODE_SHA
            && p.parent_start_ticks > 0
            && p.parent_argv == bounded_profile::node_argv(),
        "guard exact direct singleton scope differs"
    );
    Ok(())
}
fn systemctl(args: &[&str]) -> Result<std::process::Output> {
    Ok(Command::new("/usr/bin/systemctl")
        .arg("--system")
        .args(args)
        .env("LC_ALL", "C")
        .env("TZ", "UTC")
        .env_remove("DBUS_SYSTEM_BUS_ADDRESS")
        .env_remove("DBUS_SESSION_BUS_ADDRESS")
        .env_remove("SYSTEMD_BUS_ADDRESS")
        .env_remove("SYSTEMD_HOST")
        .output()?)
}
fn native(unit: &str) -> Result<Value> {
    ensure!(
        [UNIT, GUARD, STOPPER, TIMER].contains(&unit),
        "unbound native query target"
    );
    let o = systemctl(&[
        "show",
        unit,
        "--no-pager",
        "--property=Id,LoadState,InvocationID,MainPID,ControlPID,NRestarts,Restart,ActiveState,SubState,ControlGroup,MemoryAccounting,MemoryMax,MemorySwapMax,Job,User,NoNewPrivileges,RuntimeMaxUSec",
    ])?;
    ensure!(
        o.status.success() && o.stderr.is_empty() && o.stdout.len() <= 65536,
        "guard native read failed"
    );
    let mut m = serde_json::Map::new();
    for line in std::str::from_utf8(&o.stdout)?.lines() {
        let (k, v) = line.split_once('=').context("native framing")?;
        ensure!(
            m.insert(k.into(), json!(v)).is_none(),
            "duplicate native field"
        );
    }
    Ok(Value::Object(m))
}
fn active(n: &Value) -> bool {
    matches!(n["ActiveState"].as_str(), Some("active" | "activating"))
}
fn owned(n: &Value, p: &Plan) -> Result<()> {
    ensure!(
        n["Id"] == UNIT
            && n["InvocationID"] == p.parent_invocation_id
            && n["NRestarts"] == "0"
            && n["Restart"] == "no"
            && n["Job"] == ""
            && n["MainPID"]
                .as_str()
                .and_then(|s| s.parse::<u64>().ok())
                .is_some_and(|n| n > 1)
            && active(n)
            && n["ControlGroup"] == format!("/system.slice/{UNIT}")
            && n["MemoryAccounting"] == "yes"
            && n["MemoryMax"] == "137438953472"
            && n["MemorySwapMax"] == "0"
            && n["RuntimeMaxUSec"] == "1h",
        "direct parent identity, cap or restart state differs; replacement must not be stopped"
    );
    Ok(())
}
fn terminal(n: &Value, p: &Plan) -> Result<()> {
    ensure!(
        n["Id"] == UNIT
            && n["MainPID"] == "0"
            && n["ControlPID"] == "0"
            && n["NRestarts"] == "0"
            && n["Job"] == ""
            && !active(n)
            && (n["InvocationID"] == p.parent_invocation_id || n["InvocationID"] == ""),
        "parent is neither exact live owner nor positively terminal"
    );
    Ok(())
}
fn same_program(pid: u64, p: &Plan) -> Result<()> {
    let proc = PathBuf::from(format!("/proc/{pid}"));
    let actual = File::open(proc.join("exe"))?;
    let a = actual.metadata()?;
    let m = fs::metadata(&p.parent_program.path)?;
    ensure!(
        a.dev() == m.dev() && a.ino() == m.ino(),
        "parent mapped executable inode changed"
    );
    f::bytes(&p.parent_program, 128 << 20, true)?;
    let raw = fs::read(proc.join("cmdline"))?;
    ensure!(
        raw.len() <= 1 << 20 && raw.last() == Some(&0),
        "parent argv source framing"
    );
    let args = raw[..raw.len() - 1]
        .split(|b| *b == 0)
        .map(|b| Ok(std::str::from_utf8(b)?.to_owned()))
        .collect::<Result<Vec<_>>>()?;
    ensure!(args == p.parent_argv, "parent argv changed");
    let stat = fs::read_to_string(proc.join("stat"))?;
    let ticks: u64 = stat
        .rsplit_once(") ")
        .context("parent stat framing")?
        .1
        .split_whitespace()
        .nth(19)
        .context("parent start ticks")?
        .parse()?;
    ensure!(ticks == p.parent_start_ticks, "bounded parent PID reused");
    Ok(())
}
fn free(path: &Path) -> Result<u64> {
    let path = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe { libc::statvfs(path.as_ptr(), &mut s) } == 0,
        "guard filesystem stat failed"
    );
    s.f_bavail
        .checked_mul(s.f_frsize)
        .context("free bytes overflow")
}
fn vmas(group: &str, maximum: u64) -> Result<Option<u64>> {
    ensure!(
        group == format!("/system.slice/{UNIT}"),
        "foreign parent cgroup"
    );
    let root = Path::new("/sys/fs/cgroup").join(group.trim_start_matches('/'));
    ensure!(root.is_dir(), "live parent cgroup missing");
    let mut stack = vec![root];
    let mut pids = std::collections::BTreeSet::new();
    let mut dirs = 0;
    while let Some(d) = stack.pop() {
        dirs += 1;
        ensure!(dirs <= 1024, "parent cgroup subtree bound");
        for line in fs::read_to_string(d.join("cgroup.procs"))?.lines() {
            pids.insert(line.parse::<u64>()?);
        }
        for e in fs::read_dir(d)? {
            let e = e?;
            if e.file_type()?.is_dir() {
                stack.push(e.path());
            }
        }
    }
    let mut workers = Vec::new();
    for pid in pids {
        let cmd = match fs::read(format!("/proc/{pid}/cmdline")) {
            Ok(v) => v,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e.into()),
        };
        if let Some(first) = cmd.split(|b| *b == 0).next() {
            let base = first.rsplit(|b| *b == b'/').next().unwrap_or(first);
            if base.starts_with(b"jetstreamer-historical-worker-v")
                || first.ends_with(b"/bound-worker/historical-worker")
            {
                workers.push(pid);
            }
        }
    }
    ensure!(
        workers.len() <= 1,
        "multiple historical workers in singleton parent"
    );
    let Some(pid) = workers.first() else {
        return Ok(None);
    };
    let mut lines = BufReader::new(File::open(format!("/proc/{pid}/maps"))?);
    let mut line = Vec::new();
    let mut count = 0u64;
    loop {
        line.clear();
        if lines.read_until(b'\n', &mut line)? == 0 {
            break;
        }
        ensure!(line.len() <= 1 << 20, "oversized maps record");
        count = count.checked_add(1).context("VMA count overflow")?;
        ensure!(count <= 16_000_000, "maps census exceeds absolute bound");
        if count > maximum {
            return Ok(Some(count));
        }
    }
    Ok(Some(count))
}
fn selection_shape(p: &Plan, outer: &Value, completion: &Value) -> Result<()> {
    ensure!(
        outer["schema"] == "terminal199-parent-memory-selector-original-execution-v1"
            && outer["capability_only"] == false
            && outer["selection"]["original199_parent_retirement_bytes"] == (192u64 << 30)
            && outer["selection"]["completed_cached145_parent_retirement_bytes"] == (192u64 << 30)
            && completion["schema"] == "epoch163-parent-memory-selector-original-completion-v1"
            && completion["receipt"] == json!(p.selected_memory_receipt)
            && completion["invocation_id"] == outer["invocation_id"]
            && completion["result"] == "success"
            && completion["exec_main_status"] == 0
            && completion["original_outer_reaped"] == true
            && completion["original_cgroup_empty"] == true
            && completion["original_descriptors_drained"] == true,
        "memory selection is not a genuine completed original execution"
    );
    Ok(())
}

fn data_selection_shape(p: &Plan, outer: &Value, done: &Value, memory: &Value) -> Result<()> {
    let image = Bound {
        path: DATA_IMAGE.into(),
        sha256: DATA_SHA.into(),
    };
    ensure!(
        outer["schema"] == "epoch183-native-ended-DATA-selector-original-execution-v1"
            && outer["program"] == json!(image)
            && outer["unit"] == DATA_UNIT
            && outer["actual_native_capability_passed"] == true
            && outer["memory_selection"] == json!(p.selected_memory_receipt)
            && outer["data_selection"]["current"] == memory["selection"]["request"]["current"]
            && outer["physical_credit_bytes"] == 0
            && outer["memory_credit_bytes"] == 0
            && outer["replay_launch_authorized"] == false
            && outer["admission_authorized"] == false
            && outer["archive_retirement_authorized"] == false
            && outer["r2_mutations"] == false
            && done["schema"] == "epoch163-ended183-DATA-selector-original-completion-v1"
            && done["receipt"] == json!(p.selected_data_receipt)
            && done["program"] == json!(image)
            && done["unit"] == DATA_UNIT
            && done["invocation_id"] == outer["invocation_id"]
            && done["result"] == "success"
            && done["exec_main_status"] == 0
            && done["original_outer_reaped"] == true
            && done["original_cgroup_empty"] == true
            && done["original_descriptors_drained"] == true,
        "DATA selection is not a genuine exact completed execution"
    );
    ensure!(
        outer["invocation_id"]
            .as_str()
            .is_some_and(|s| f::hex(s, 32)),
        "DATA original IID"
    );
    for end in ["native_before", "native_after"] {
        ensure!(
            outer[end]["Id"] == DATA_UNIT
                && outer[end]["InvocationID"] == outer["invocation_id"]
                && outer[end]["MemoryMax"] == "2147483648"
                && outer[end]["MemorySwapMax"] == "0"
                && outer[end]["MainPID"]
                    .as_str()
                    .and_then(|s| s.parse::<u64>().ok())
                    .is_some_and(|n| n > 1)
                && outer[end]["ControlPID"] == "0"
                && outer[end]["NRestarts"] == "0"
                && outer[end]["Restart"] == "no"
                && outer[end]["ActiveState"] == "active"
                && outer[end]["SubState"] == "running"
                && outer[end]["Job"] == "",
            "DATA original native profile differs"
        );
    }
    Ok(())
}
fn selection(p: &Plan, now: u64) -> Result<()> {
    let outer = f::immutable(&p.selected_memory_receipt)?;
    let completion = f::immutable(&p.selected_memory_original_completion)?;
    selection_shape(p, &outer, &completion)?;
    let data = f::immutable(&p.selected_data_receipt)?;
    let completed = f::immutable(&p.selected_data_original_completion)?;
    data_selection_shape(p, &data, &completed, &outer)?;
    f::bytes(
        &Bound {
            path: DATA_IMAGE.into(),
            sha256: DATA_SHA.into(),
        },
        128 << 20,
        true,
    )?;
    // This constructor reauthenticates the original memory view and current DATA
    // custody together. It returns continuity only, with no fresh resource view.
    selected_data::revalidate_running_guard(&data["data_selection"], &outer["selection"], now)?;
    Ok(())
}
fn save(p: &Plan, name: &str, value: &Value) -> Result<()> {
    let dir = f::open(&p.output_directory)?;
    let m = dir.metadata()?;
    ensure!(
        m.is_dir() && m.uid() == 0 && m.mode() & 0o777 == 0o700,
        "guard receipt directory root0700"
    );
    let path = p.output_directory.join(name);
    let mut raw = serde_json::to_vec_pretty(value)?;
    raw.push(b'\n');
    ensure!(raw.len() <= 1 << 20, "guard receipt bound");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    file.write_all(&raw)?;
    file.set_permissions(fs::Permissions::from_mode(0o400))?;
    file.sync_all()?;
    dir.sync_all()?;
    Ok(())
}
fn group_empty() -> Result<bool> {
    let root = PathBuf::from(format!("/sys/fs/cgroup/system.slice/{UNIT}"));
    ensure!(
        Path::new("/sys/fs/cgroup/system.slice").is_dir(),
        "cgroup parent unavailable"
    );
    if !root.try_exists()? {
        return Ok(true);
    }
    let mut dirs = vec![root];
    let mut count = 0;
    while let Some(d) = dirs.pop() {
        count += 1;
        ensure!(count <= 1024, "cgroup drain subtree bound");
        if !fs::read_to_string(d.join("cgroup.procs"))?
            .trim()
            .is_empty()
        {
            return Ok(false);
        }
        for e in fs::read_dir(d)? {
            let e = e?;
            if e.file_type()?.is_dir() {
                dirs.push(e.path());
            }
        }
    }
    Ok(true)
}
fn stop(p: &Plan, plan: &Bound, reason: &str, now: u64) -> Result<()> {
    let before = native(UNIT)?;
    if !active(&before) {
        terminal(&before, p)?;
        let timer_stop = systemctl(&["stop", TIMER])?;
        ensure!(timer_stop.status.success(), "guard timer stop failed");
        return Ok(());
    }
    owned(&before, p)?;
    let intent = json!({"schema":"epoch163-first-output128-guard-stop-intent-v1","plan":plan,"parent_unit":UNIT,
        "parent_invocation_id":p.parent_invocation_id,"before":before,"reason":reason,"recorded_unix_seconds":now,
        "stop_order":[UNIT],"archives_mutated":false,"R2_mutations":false});
    let intent_error = save(p, "stop-intent.json", &intent)
        .err()
        .map(|e| e.to_string());
    let current = native(UNIT)?;
    owned(&current, p)?;
    let o = systemctl(&["stop", UNIT])?;
    ensure!(
        o.status.success() && o.stdout.len() <= 65536 && o.stderr.len() <= 65536,
        "exact parent stop failed"
    );
    let after = native(UNIT)?;
    terminal(&after, p)?;
    ensure!(
        group_empty()?,
        "exact parent cgroup still has processes after stop"
    );
    save(
        p,
        "stop-completion.json",
        &json!({"schema":"epoch163-first-output128-guard-stop-completion-v1","plan":plan,
        "parent_invocation_id":p.parent_invocation_id,"after":after,"intent_write_error":intent_error,
        "stop_exit_code":o.status.code(),"original_cgroup_empty":true,"memory_retirement_authorized":false,"recorded_unix_seconds":now,"archives_mutated":false,"R2_mutations":false}),
    )?;
    let o = systemctl(&["stop", TIMER])?;
    ensure!(o.status.success(), "guard timer stop failed");
    Ok(())
}
fn limits(available: u64, floor: u64, maps: Option<u64>, maximum: u64) -> Result<()> {
    ensure!(
        floor > 0 && maximum > 0 && available >= floor,
        "filesystem floor tripped"
    );
    ensure!(
        maps.is_none_or(|v| v <= maximum),
        "worker VMA limit tripped"
    );
    Ok(())
}
fn check(p: &Plan, now: u64) -> Result<Value> {
    let n = native(UNIT)?;
    if !active(&n) {
        terminal(&n, p)?;
        return Ok(json!({"parent_terminal":true}));
    }
    owned(&n, p)?;
    same_program(n["MainPID"].as_str().context("parent PID")?.parse()?, p)?;
    selection(p, now)?;
    bounded_profile::continuity(p, now)?;
    let available = free(&p.filesystem)?;
    let maps = vmas(
        n["ControlGroup"].as_str().context("parent cgroup")?,
        p.maximum_worker_vmas,
    )?;
    limits(available, p.minimum_free_bytes, maps, p.maximum_worker_vmas)?;
    owned(&native(UNIT)?, p)?;
    Ok(
        json!({"armed":true,"parent_invocation_id":p.parent_invocation_id,"available_bytes":available,"worker_vmas":maps,"memory_continuity_validated":true}),
    )
}
fn run() -> Result<()> {
    ensure!(unsafe { libc::geteuid() } == 0, "root guard required");
    ensure!(
        !env::vars_os()
            .any(|(k, _)| k.to_string_lossy().starts_with("LD_") || k == "GLIBC_TUNABLES"),
        "loader override forbidden"
    );
    let a = env::args().skip(1).collect::<Vec<_>>();
    ensure!(
        a.len() == 6
            && matches!(a[0].as_str(), "check" | "stop")
            && a[2] == "--plan-sha256"
            && a[4] == "--self-sha256",
        "check|stop PLAN --plan-sha256 SHA --self-sha256 SHA"
    );
    let image = Bound {
        path: fs::read_link("/proc/self/exe")?,
        sha256: a[5].clone(),
    };
    ensure!(image.path == Path::new(IMAGE), "guard normal namespace");
    let mut actual = Vec::new();
    Read::by_ref(&mut File::open("/proc/self/exe")?)
        .take((128 << 20) + 1)
        .read_to_end(&mut actual)?;
    ensure!(
        actual.len() <= 128 << 20
            && f::sha(&actual) == image.sha256
            && f::bytes(&image, 128 << 20, true)? == actual,
        "mapped guard bytes differ"
    );
    let pb = Bound {
        path: a[1].clone().into(),
        sha256: a[3].clone(),
    };
    let p: Plan = serde_json::from_value(f::immutable(&pb)?)?;
    scope(&p)?;
    let iid = env::var("INVOCATION_ID")?;
    ensure!(f::hex(&iid, 32), "actual guard invocation missing");
    let actor = native(if a[0] == "check" { GUARD } else { STOPPER })?;
    let expected_main_pid = std::process::id().to_string();
    let cap = if a[0] == "check" {
        "2147483648"
    } else {
        "536870912"
    };
    ensure!(
        actor["Id"] == (if a[0] == "check" { GUARD } else { STOPPER })
            && actor["InvocationID"] == iid
            && actor["MainPID"] == expected_main_pid
            && actor["MemoryMax"] == cap
            && actor["MemorySwapMax"] == "0"
            && actor["NRestarts"] == "0"
            && actor["Restart"] == "no",
        "guard/stopper actual booking differs"
    );
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    if a[0] == "stop" {
        stop(&p, &pb, "guard service failed or timed out", now)?;
        return Ok(());
    }
    match check(&p, now) {
        Ok(v) => {
            if v["parent_terminal"] == true {
                let timer_stop = systemctl(&["stop", TIMER])?;
                ensure!(timer_stop.status.success(), "guard timer stop failed");
            }
            println!("{}", v);
            Ok(())
        }
        Err(e) => {
            let reason = format!("{e:#}");
            stop(&p, &pb, &reason, now)?;
            anyhow::bail!("epoch163 guard stopped its exact parent: {reason}")
        }
    }
}
fn main() {
    if let Err(e) = run() {
        eprintln!("epoch163 guard: {e:#}");
        std::process::exit(1);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn p() -> Plan {
        Plan{schema:"epoch163-first-output128-memory-DATA-reserve-vma-guard-plan-v1".into(),parent_unit:UNIT.into(),parent_invocation_id:"a".repeat(32),
        parent_program:Bound{path:"/usr/local/lib/jetstreamer/horizon-first-lane-witness-first163128-node-tools-20261107-v2/jetstreamer-node".into(),sha256:NODE_SHA.into()},
        parent_argv:bounded_profile::node_argv(),parent_start_ticks:1,
        input_policy:Bound{path:"/input-policy.json".into(),sha256:"f".repeat(64)},admission:Bound{path:"/admission.json".into(),sha256:"a".repeat(64)},
        selected_memory_receipt:Bound{path:"/selection.json".into(),sha256:"b".repeat(64)},selected_memory_original_completion:Bound{path:"/completion.json".into(),sha256:"c".repeat(64)},selected_data_receipt:Bound{path:"/data-selection.json".into(),sha256:"d".repeat(64)},selected_data_original_completion:Bound{path:"/data-completion.json".into(),sha256:"e".repeat(64)},filesystem:"/home/sol".into(),minimum_free_bytes:1,maximum_worker_vmas:3_000_000,guard_timer:TIMER.into(),output_directory:OUT.into()}
    }
    fn n() -> Value {
        json!({"Id":UNIT,"InvocationID":"a".repeat(32),"MainPID":"22","ControlPID":"0","NRestarts":"0","Restart":"no","Job":"","ActiveState":"active","SubState":"running","ControlGroup":format!("/system.slice/{UNIT}"),"MemoryAccounting":"yes","MemoryMax":"137438953472","MemorySwapMax":"0","RuntimeMaxUSec":"1h"})
    }
    #[test]
    fn scope_and_live_owner_are_exact() {
        scope(&p()).unwrap();
        owned(&n(), &p()).unwrap();
    }
    #[test]
    fn original199_or_healthy145_can_never_be_stop_targets() {
        for u in [
            model::PRODUCER,
            "horizon-qualify-145-cached-b2a09f57de39c384.service",
        ] {
            let mut plan = p();
            plan.parent_unit = u.into();
            assert!(scope(&plan).is_err());
            let mut row = n();
            row["Id"] = json!(u);
            assert!(owned(&row, &p()).is_err());
        }
    }
    #[test]
    fn replacement_restart_unbounded_memory_and_foreign_cgroup_fail() {
        for (k, v) in [
            ("InvocationID", json!("b".repeat(32))),
            ("NRestarts", json!("1")),
            ("Restart", json!("on-failure")),
            ("MemoryMax", json!("infinity")),
            ("ControlGroup", json!("/system.slice/other.service")),
        ] {
            let mut row = n();
            row[k] = v;
            assert!(owned(&row, &p()).is_err(), "{k}");
        }
    }
    #[test]
    fn only_original_or_collected_terminal_identity_is_accepted() {
        let mut row = n();
        row["MainPID"] = json!("0");
        row["ActiveState"] = json!("inactive");
        row["SubState"] = json!("dead");
        row["Job"] = json!("");
        terminal(&row, &p()).unwrap();
        row["InvocationID"] = json!("");
        terminal(&row, &p()).unwrap();
        row["InvocationID"] = json!("b".repeat(32));
        assert!(terminal(&row, &p()).is_err());
    }
    #[test]
    fn zero_floor_bad_epoch_or_another_timer_are_rejected() {
        for edit in 0..4 {
            let mut plan = p();
            match edit {
                0 => plan.minimum_free_bytes = 0,
                1 => plan.maximum_worker_vmas = 0,
                2 => plan.parent_argv[1] = "164-164".into(),
                _ => plan.guard_timer = "other.timer".into(),
            };
            assert!(scope(&plan).is_err());
        }
    }

    #[test]
    fn pressure_and_vma_boundaries_are_real_stop_conditions() {
        limits(100, 100, Some(3_000_000), 3_000_000).unwrap();
        limits(100, 100, None, 3_000_000).unwrap();
        assert!(limits(99, 100, None, 3_000_000).is_err());
        assert!(limits(100, 100, Some(3_000_001), 3_000_000).is_err());
        assert!(limits(100, 0, None, 3_000_000).is_err());
    }
    #[test]
    fn capability_or_failed_or_undrained_selector_is_not_a_memory_basis() {
        let plan = p();
        let outer = json!({"schema":"terminal199-parent-memory-selector-original-execution-v1","capability_only":false,
            "invocation_id":"d".repeat(32),"selection":{"original199_parent_retirement_bytes":192u64<<30,"completed_cached145_parent_retirement_bytes":192u64<<30}});
        let done = json!({"schema":"epoch163-parent-memory-selector-original-completion-v1","receipt":plan.selected_memory_receipt,
            "invocation_id":"d".repeat(32),"result":"success","exec_main_status":0,"original_outer_reaped":true,
            "original_cgroup_empty":true,"original_descriptors_drained":true});
        selection_shape(&plan, &outer, &done).unwrap();
        let mut cap = outer.clone();
        cap["capability_only"] = json!(true);
        assert!(selection_shape(&plan, &cap, &done).is_err());
        for (field, value) in [
            ("result", json!("exit-code")),
            ("exec_main_status", json!(1)),
            ("invocation_id", json!("e".repeat(32))),
            ("original_cgroup_empty", json!(false)),
            ("original_descriptors_drained", json!(false)),
        ] {
            let mut changed = done.clone();
            changed[field] = value;
            assert!(selection_shape(&plan, &outer, &changed).is_err(), "{field}");
        }
    }
    fn data_fixture(p: &Plan) -> (Value, Value, Value) {
        let image = json!({"path":DATA_IMAGE,"sha256":DATA_SHA});
        let iid = "f".repeat(32);
        let current = json!({"tuple":"test-only-same-tuple"});
        let native = json!({"Id":DATA_UNIT,"InvocationID":iid,"MemoryMax":"2147483648","MemorySwapMax":"0","MainPID":"42","ControlPID":"0","NRestarts":"0","Restart":"no","ActiveState":"active","SubState":"running","Job":""});
        let data = json!({"schema":"epoch183-native-ended-DATA-selector-original-execution-v1","program":image,"unit":DATA_UNIT,"invocation_id":iid,
            "native_before":native,"native_after":native,"actual_native_capability_passed":true,"memory_selection":p.selected_memory_receipt,
            "data_selection":{"current":current},"physical_credit_bytes":0,"memory_credit_bytes":0,"replay_launch_authorized":false,
            "admission_authorized":false,"archive_retirement_authorized":false,"r2_mutations":false});
        let done = json!({"schema":"epoch163-ended183-DATA-selector-original-completion-v1","receipt":p.selected_data_receipt,"program":image,"unit":DATA_UNIT,
            "invocation_id":iid,"result":"success","exec_main_status":0,"original_outer_reaped":true,"original_cgroup_empty":true,"original_descriptors_drained":true});
        (
            data,
            done,
            json!({"selection":{"request":{"current":current}}}),
        )
    }
    #[test]
    fn data_hook_requires_same_original_memory_and_successful_native_execution() {
        let p = p();
        let (data, done, memory) = data_fixture(&p);
        data_selection_shape(&p, &data, &done, &memory).unwrap();
        for (key, value) in [
            ("invocation_id", json!("crossed")),
            ("original_outer_reaped", json!(false)),
            ("original_cgroup_empty", json!(false)),
            ("original_descriptors_drained", json!(false)),
            ("result", json!("failed")),
        ] {
            let mut changed = done.clone();
            changed[key] = value;
            assert!(
                data_selection_shape(&p, &data, &changed, &memory).is_err(),
                "{key}"
            );
        }
    }
    #[test]
    fn data_hook_never_accepts_another_actor_tuple_or_resource_credit() {
        let p = p();
        let (data, done, memory) = data_fixture(&p);
        for (key, value) in [
            ("physical_credit_bytes", json!(1)),
            ("memory_credit_bytes", json!(1)),
            ("admission_authorized", json!(true)),
            ("unit", json!("foreign.service")),
        ] {
            let mut changed = data.clone();
            changed[key] = value;
            assert!(
                data_selection_shape(&p, &changed, &done, &memory).is_err(),
                "{key}"
            );
        }
        let mut changed = data;
        changed["data_selection"]["current"] = json!({"foreign":"tuple"});
        assert!(data_selection_shape(&p, &changed, &done, &memory).is_err());
    }
    #[test]
    fn completed145_guard_rejects_old_or_crossed_data_executable_bindings() {
        let p = p();
        let (data, done, memory) = data_fixture(&p);
        for image in [
            json!({"path":"/usr/local/lib/jetstreamer/horizon-ended183-DATA-selector-tools-20261105-v5/ended183-data",
                "sha256":"5d44a1c2aad60c04dbad32b736a853c7ff40036e3f8c0f6c03d3cb98a6442a7c"}),
            json!({"path":DATA_IMAGE,"sha256":"0".repeat(64)}),
        ] {
            let mut crossed = data.clone();
            crossed["program"] = image.clone();
            assert!(data_selection_shape(&p, &crossed, &done, &memory).is_err());
            let mut crossed_done = done.clone();
            crossed_done["program"] = image;
            assert!(data_selection_shape(&p, &data, &crossed_done, &memory).is_err());
        }
    }
    #[test]
    fn selected_witness_raw_context_data_image_and_crossed_generations_are_distinct() {
        let plan=p();
        let (data,done,memory)=data_fixture(&plan);
        assert_eq!(DATA_IMAGE,"/usr/local/lib/jetstreamer/horizon-first-lane-witness-ended183-DATA-selector-tools-20261107-v4/ended183-data");
        data_selection_shape(&plan,&data,&done,&memory).unwrap();
        for image in [
            json!({"path":"/usr/local/lib/jetstreamer/horizon-first-lane-witness-ended183-DATA-selector-tools-20261107-v1/ended183-data","sha256":"f6cc28d59cb227ccc5999a39d8038907b2f284632746a62977f35b93fa9795cb"}),
            json!({"path":"/usr/local/lib/jetstreamer/horizon-completed145-ended183-DATA-selector-tools-20261106-v3/ended183-data","sha256":"4835b9eb84a290c2f938556e0f5235bd92d6be201677543374c94f1abf8a58ae"}),
            json!({"path":DATA_IMAGE,"sha256":"f6cc28d59cb227ccc5999a39d8038907b2f284632746a62977f35b93fa9795cb"}),
        ] {
            let mut crossed=data.clone();crossed["program"]=image.clone();
            let mut crossed_done=done.clone();crossed_done["program"]=image;
            assert!(data_selection_shape(&plan,&crossed,&crossed_done,&memory).is_err());
        }
    }
    #[test]
    #[ignore = "Root binds actual immutable current witness memory/DATA receipts and original completions; no fabricated fixture"]
    fn actual_selected_witness_data_reaches_running_continuity_and_rejects_crossed_context() -> Result<()> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Fixture {
            schema:String,
            memory_receipt:Bound,
            memory_original_completion:Bound,
            #[serde(rename="DATA_receipt")]
            data_receipt:Bound,
            #[serde(rename="DATA_original_completion")]
            data_original_completion:Bound,
        }
        let binding:Bound=serde_json::from_str(&env::var("JETSTREAMER_FIRST128_SELECTED_WITNESS_GUARD_FIXTURE_BINDING")?)?;
        let fixture:Fixture=serde_json::from_value(f::immutable(&binding)?)?;
        ensure!(fixture.schema=="first128-actual-selected-witness-guard-fixture-v1","actual witness fixture scope");
        let mut plan=p();
        plan.selected_memory_receipt=fixture.memory_receipt;
        plan.selected_memory_original_completion=fixture.memory_original_completion;
        plan.selected_data_receipt=fixture.data_receipt;
        plan.selected_data_original_completion=fixture.data_original_completion;
        let now=SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        selection(&plan,now)?;
        let memory=f::immutable(&plan.selected_memory_receipt)?;
        let data=f::immutable(&plan.selected_data_receipt)?;
        let done=f::immutable(&plan.selected_data_original_completion)?;
        ensure!(!data["data_selection"]["original199_input_verification_context"].is_null(),"actual selected witness context missing");
        let mut crossed=data.clone();
        crossed["program"]=json!({"path":DATA_IMAGE,"sha256":"0".repeat(64)});
        ensure!(data_selection_shape(&plan,&crossed,&done,&memory).is_err(),"crossed program accepted");
        let mut omitted=data["data_selection"].clone();
        omitted.as_object_mut().context("actual DATA object")?.remove("original199_input_verification_context");
        ensure!(selected_data::revalidate_running_guard(&omitted,&memory["selection"],now).is_err(),"omitted witness context accepted");
        let mut foreign=data["data_selection"].clone();
        foreign["original199_input_verification_context"]["sha256"]=json!("0".repeat(64));
        ensure!(selected_data::revalidate_running_guard(&foreign,&memory["selection"],now).is_err(),"crossed witness context accepted");
        ensure!(f::immutable(&plan.selected_data_receipt)?==data && f::immutable(&plan.selected_memory_receipt)?==memory,"actual original receipts changed");
        Ok(())
    }

}
