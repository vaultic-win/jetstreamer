//! Invocation-adjacent process RSS telemetry; never an admission or stop action.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};
use std::{fmt, io};

#[derive(Deserialize, Serialize)]
struct Maximum {
    maximum_observed_lane_rss_bytes: u64,
    reservation_ceiling_bytes: u64,
    evidence: Value,
}
fn lane_rss(row: &Value, suffix: &str) -> Option<u64> {
    let producer = &row[format!("producer_{suffix}")];
    let controller = &row[format!("controller_{suffix}")];
    let bytes = |v: &Value| {
        (v["rss"]["census_stable"] == true && v["rss"]["error"].is_null())
            .then(|| v["rss"]["aggregate_rss_bytes"].as_u64())
            .flatten()
    };
    let p = Path::new(producer["control_group"].as_str()?);
    let c = Path::new(controller["control_group"].as_str()?);
    if p == c {
        Some(bytes(producer)?.max(bytes(controller)?))
    } else if p.starts_with(c) {
        bytes(controller)
    } else if c.starts_with(p) {
        bytes(producer)
    } else {
        bytes(producer)?.checked_add(bytes(controller)?)
    }
}
/// Carry maxima through the hash-bound predecessor chain. No seed is mislabeled
/// as observed RSS, and a missing/failed current census never reduces a maximum.
pub(crate) fn history(previous: &Value, current: &Value) -> Result<Value> {
    let mut maxima: BTreeMap<String, Maximum> = match previous.get("lane_rss_history") {
        None | Some(Value::Null) => BTreeMap::new(),
        Some(v) => serde_json::from_value(v.clone())?,
    };
    let mut rows = Vec::new();
    if let Some(v) = current["replays"].as_array() {
        rows.extend(v.iter());
    }
    if let Some(v) = current["diagnostic_replays"].as_array() {
        rows.extend(
            v.iter()
                .filter(|r| r["status"] == "observed")
                .map(|r| &r["observation"]),
        );
    }
    for row in rows {
        if row["invocation_binding_stable"] != true || row["resource_only"] == true {
            continue;
        }
        let Some((first, last)) = row["range"].as_str().and_then(|r| r.split_once('-')) else {
            continue;
        };
        let first: u64 = first.parse()?;
        let last: u64 = last.parse()?;
        let century = if (200..=300).contains(&first) && (first..=300).contains(&last) {
            200
        } else if first <= last && first / 100 == last / 100 {
            first / 100 * 100
        } else {
            continue;
        };
        let Some(bytes) = lane_rss(row, "before")
            .zip(lane_rss(row, "after"))
            .map(|(a, b)| a.max(b))
        else {
            continue;
        };
        if bytes == 0
            || maxima
                .get(&century.to_string())
                .is_some_and(|r| r.maximum_observed_lane_rss_bytes >= bytes)
        {
            continue;
        }
        let reserve = bytes.checked_mul(3).context("RSS reservation overflow")? / 2;
        maxima.insert(century.to_string(),Maximum {
            maximum_observed_lane_rss_bytes:bytes,reservation_ceiling_bytes:reserve,
            evidence:serde_json::json!({"sampled_at_utc":current["recorded_at_utc"],"range":row["range"],
                "producer_unit":row["producer_before"]["unit"],"producer_invocation_id":row["producer_before"]["invocation_id"],
                "producer_rss_before":row["producer_before"]["rss"],"producer_rss_after":row["producer_after"]["rss"],
                "controller_rss_before":row["controller_before"]["rss"],"controller_rss_after":row["controller_after"]["rss"],
                "shared_resident_pages_may_be_counted_in_each_process":true,
                "sum_of_process_high_water_marks_used":false,"admission_authorized":false})
        });
    }
    Ok(serde_json::to_value(maxima)?)
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct Process {
    pid: u32,
    start_ticks: u64,
    rss_bytes: u64,
    rss_high_water_bytes: u64,
}
#[derive(Clone, Debug, Default, Serialize)]
pub(crate) struct Report {
    pub aggregate_rss_bytes: Option<u64>,
    processes: Vec<Process>,
    census_stable: bool,
    error: Option<String>,
}
#[derive(Debug)]
struct CensusChurn(&'static str);
impl fmt::Display for CensusChurn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for CensusChurn {}

fn members(root: &Path) -> Result<BTreeSet<u32>> {
    let mut pending = vec![root.to_path_buf()];
    let mut pids = BTreeSet::new();
    let mut visited = 0;
    while let Some(dir) = pending.pop() {
        visited += 1;
        ensure!(visited <= 4096, "RSS cgroup tree exceeds bound");
        ensure!(
            fs::symlink_metadata(&dir)
                .with_context(|| format!("RSS cgroup metadata {}", dir.display()))?
                .file_type()
                .is_dir(),
            "RSS cgroup is not a directory"
        );
        for pid in fs::read_to_string(dir.join("cgroup.procs"))
            .with_context(|| format!("RSS cgroup members {}", dir.display()))?
            .split_whitespace()
        {
            let pid: u32 = pid.parse()?;
            ensure!(pid > 0, "zero RSS process ID");
            pids.insert(pid);
            ensure!(pids.len() <= 65536, "RSS process census exceeds bound");
        }
        for entry in
            fs::read_dir(&dir).with_context(|| format!("RSS cgroup children {}", dir.display()))?
        {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                pending.push(entry.path());
            }
        }
    }
    ensure!(!pids.is_empty(), "empty RSS process census");
    Ok(pids)
}
fn start_ticks(stat: &str, pid: u32) -> Result<u64> {
    ensure!(
        stat.starts_with(&format!("{pid} (")),
        "RSS PID identity differs"
    );
    // comm may contain spaces and parentheses; fields after its last ')' are numeric/state.
    stat.rsplit_once(')')
        .context("RSS stat comm")?
        .1
        .split_whitespace()
        .nth(19)
        .context("RSS start time missing")?
        .parse()
        .map_err(Into::into)
}
fn status(text: &str, pid: u32) -> Result<(u64, u64)> {
    let mut rss = None;
    let mut high = None;
    let mut found_pid = false;
    let mut found_tgid = false;
    for line in text.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        match key {
            "Pid" => {
                ensure!(
                    !found_pid && value.trim().parse::<u32>()? == pid,
                    "RSS PID mismatch"
                );
                found_pid = true;
            }
            "Tgid" => {
                ensure!(
                    !found_tgid && value.trim().parse::<u32>()? == pid,
                    "RSS process is not a TGID"
                );
                found_tgid = true;
            }
            "VmRSS" | "VmHWM" => {
                let mut parts = value.split_whitespace();
                let bytes = parts
                    .next()
                    .context("RSS value missing")?
                    .parse::<u64>()?
                    .checked_mul(1024)
                    .context("RSS byte overflow")?;
                ensure!(
                    parts.next() == Some("kB") && parts.next().is_none(),
                    "RSS units differ"
                );
                let target = if key == "VmRSS" { &mut rss } else { &mut high };
                ensure!(target.replace(bytes).is_none(), "duplicate RSS field");
            }
            _ => {}
        }
    }
    let rss = rss.context("VmRSS missing")?;
    let high = high.context("VmHWM missing")?;
    ensure!(
        found_pid && found_tgid && high >= rss,
        "incomplete/inconsistent RSS process status"
    );
    Ok((rss, high))
}
fn checked_capture(cgroup: &Path, group: &Path, proc_root: &Path) -> Result<Report> {
    capture_processes(cgroup, group, proc_root, false)
}
fn capture_processes(
    cgroup: &Path,
    group: &Path,
    proc_root: &Path,
    allow_kernel: bool,
) -> Result<Report> {
    let before = members(cgroup)?;
    let mut processes = Vec::new();
    let mut aggregate = 0u64;
    for pid in &before {
        let root = proc_root.join(pid.to_string());
        let read = |name: &str| {
            fs::read_to_string(root.join(name)).with_context(|| format!("RSS process {pid} {name}"))
        };
        let stat = read("stat")?;
        let start = start_ticks(&stat, *pid)?;
        let kernel = stat
            .rsplit_once(')')
            .context("RSS stat comm")?
            .1
            .split_whitespace()
            .nth(6)
            .context("RSS flags")?
            .parse::<u64>()?
            & 0x0020_0000
            != 0;
        let (rss, high) = if allow_kernel && kernel {
            (0, 0)
        } else {
            status(&read("status")?, *pid)?
        };
        let membership = read("cgroup")?;
        let current = membership
            .lines()
            .find_map(|s| s.strip_prefix("0::"))
            .context("RSS unified cgroup missing")?;
        ensure!(
            Path::new(current).starts_with(group),
            "RSS process left its lane"
        );
        if start_ticks(&read("stat")?, *pid)? != start {
            return Err(CensusChurn("RSS PID reused").into());
        }
        aggregate = aggregate.checked_add(rss).context("lane RSS overflow")?;
        processes.push(Process {
            pid: *pid,
            start_ticks: start,
            rss_bytes: rss,
            rss_high_water_bytes: high,
        });
    }
    if members(cgroup)? != before {
        return Err(CensusChurn("RSS process census changed").into());
    }
    if allow_kernel {
        // Recheck every measured identity, not just the numeric PID set: a PID
        // can be recycled after its individual read and before the end census.
        validate_host_identities(proc_root, &processes)?;
        if members(cgroup)? != before {
            return Err(CensusChurn("RSS final process census changed").into());
        }
    }
    Ok(Report {
        aggregate_rss_bytes: Some(aggregate),
        processes,
        census_stable: true,
        error: None,
    })
}
fn validate_host_identities(proc_root: &Path, processes: &[Process]) -> Result<()> {
    for process in processes {
        let path = proc_root.join(process.pid.to_string()).join("stat");
        let stat = fs::read_to_string(&path)
            .with_context(|| format!("RSS final identity {}", path.display()))?;
        if start_ticks(&stat, process.pid)? != process.start_ticks {
            return Err(CensusChurn("RSS final PID identity changed").into());
        }
    }
    Ok(())
}

pub(crate) fn capture(cgroup: &Path, group: &Path) -> Report {
    checked_capture(cgroup, group, Path::new("/proc")).unwrap_or_else(|e| Report {
        error: Some(format!("{e:#}")),
        ..Report::default()
    })
}

/// System process RSS and kernel allocations use a resident-byte basis. Keep
/// MemAvailable separate: reclaimable file mappings are present in both RSS
/// and MemAvailable and cannot be subtracted to infer non-lane use.
// Retry a complete host census only for transient disappearance or positively
// detected identity/membership churn. Failed attempts contribute no partial sum.
// This is bounded work inside one observation, never a new campaign sample.
fn host_resident_attempts(mut attempt: impl FnMut() -> Result<Value>) -> Value {
    const MAX_ATTEMPTS: usize = 3;
    let mut failures = Vec::new();
    for number in 1..=MAX_ATTEMPTS {
        match attempt() {
            Ok(mut value) => {
                value["census_attempts"] = Value::from(number);
                value["discarded_attempt_errors"] = serde_json::json!(failures);
                return value;
            }
            Err(error) => {
                let retryable = error.downcast_ref::<CensusChurn>().is_some()
                    || error
                        .downcast_ref::<io::Error>()
                        .is_some_and(|e| e.kind() == io::ErrorKind::NotFound);
                failures.push(format!("{error:#}"));
                if !retryable || number == MAX_ATTEMPTS {
                    return serde_json::json!({"status":"unavailable",
                        "error":failures.last(),"census_attempts":number,
                        "discarded_attempt_errors":failures});
                }
            }
        }
    }
    unreachable!("bounded census attempts always return")
}

pub(crate) fn host_resident() -> Value {
    host_resident_attempts(|| {
        let report = capture_processes(
            Path::new("/sys/fs/cgroup"),
            Path::new("/"),
            Path::new("/proc"),
            true,
        )?;
        let kernel = kernel_bytes(&fs::read_to_string("/proc/meminfo")?)?;
        Ok(serde_json::json!({"status":"observed","rss":report,
            "kernel_components_bytes":kernel,"scope":"entire visible cgroup hierarchy",
            "accounting_basis":"process RSS plus Slab,KernelStack,PageTables,Percpu; unmapped file cache excluded",
            "shared_pages_may_be_counted_per_process":true,"admission_authorized":false}))
    })
}

fn kernel_bytes(text: &str) -> Result<BTreeMap<String, u64>> {
    let mut components = BTreeMap::new();
    for line in text.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        if !["Slab", "KernelStack", "PageTables", "Percpu"].contains(&key) {
            continue;
        }
        let mut fields = value.split_whitespace();
        let bytes = fields
            .next()
            .context("kernel memory value")?
            .parse::<u64>()?
            .checked_mul(1024)
            .context("kernel memory overflow")?;
        ensure!(
            fields.next() == Some("kB") && fields.next().is_none(),
            "kernel memory units"
        );
        ensure!(
            components.insert(key.into(), bytes).is_none(),
            "duplicate kernel component"
        );
    }
    ensure!(
        components.len() == 4,
        "incomplete kernel resident accounting"
    );
    Ok(components)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture_process(proc_root: &Path, pid: u32, start: u64) {
        let root = proc_root.join(pid.to_string());
        fs::create_dir_all(&root).unwrap();
        let mut fields = vec!["0".to_string(); 20];
        fields[0] = "S".into();
        fields[19] = start.to_string();
        fs::write(
            root.join("stat"),
            format!("{pid} (fixture) {}", fields.join(" ")),
        )
        .unwrap();
        fs::write(
            root.join("status"),
            format!("Pid: {pid}\nTgid: {pid}\nVmRSS: 100 kB\nVmHWM: 300 kB\n"),
        )
        .unwrap();
        fs::write(root.join("cgroup"), "0::/\n").unwrap();
    }

    #[test]
    fn host_restarts_whole_census_after_disappearance_never_omits_pid() {
        let temp = tempfile::tempdir().unwrap();
        let cg = temp.path().join("cg");
        let proc_root = temp.path().join("proc");
        fs::create_dir_all(&cg).unwrap();
        fs::write(cg.join("cgroup.procs"), "7\n8\n").unwrap();
        fixture_process(&proc_root, 7, 10);
        let mut calls = 0;
        let result = host_resident_attempts(|| {
            calls += 1;
            if calls == 2 {
                // Simulate a now-complete new census: the retry must read both
                // processes, never keep the first attempt's partial aggregate.
                fixture_process(&proc_root, 8, 11);
            }
            let rss = capture_processes(&cg, Path::new("/"), &proc_root, true)?;
            Ok(serde_json::json!({"status":"observed", "rss":rss}))
        });
        assert_eq!(calls, 2);
        assert_eq!(result["rss"]["aggregate_rss_bytes"], 204800);
        assert_eq!(result["rss"]["processes"].as_array().unwrap().len(), 2);
        assert_eq!(result["census_attempts"], 2);
        assert!(
            result["discarded_attempt_errors"][0]
                .as_str()
                .unwrap()
                .contains("RSS process 8 stat")
        );
    }

    #[test]
    fn host_churn_retry_is_bounded_and_keeps_every_failure() {
        let mut calls = 0;
        let result = host_resident_attempts(|| {
            calls += 1;
            Err(CensusChurn("RSS process census changed").into())
        });
        assert_eq!(calls, 3);
        assert_eq!(result["status"], "unavailable");
        assert_eq!(
            result["discarded_attempt_errors"].as_array().unwrap().len(),
            3
        );
        assert!(result.get("rss").is_none());
        let result = host_resident_attempts(|| {
            Err(io::Error::from(io::ErrorKind::NotFound)).context("fixture missing stat")
        });
        assert_eq!(result["census_attempts"], 3);
        assert_eq!(result["status"], "unavailable");
    }

    #[test]
    fn host_does_not_retry_permission_parse_or_membership_errors() {
        for error in [
            anyhow::Error::from(io::Error::from(io::ErrorKind::PermissionDenied)),
            anyhow::anyhow!("RSS PID mismatch"),
            anyhow::anyhow!("RSS process left its lane"),
        ] {
            let mut error = Some(error);
            let result = host_resident_attempts(|| Err(error.take().expect("must not retry")));
            assert_eq!(result["census_attempts"], 1);
            assert_eq!(result["status"], "unavailable");
        }
    }

    #[test]
    fn host_rechecks_start_identity_even_with_same_numeric_pid_census() {
        let temp = tempfile::tempdir().unwrap();
        fixture_process(temp.path(), 7, 10);
        let processes = vec![Process {
            pid: 7,
            start_ticks: 10,
            rss_bytes: 102400,
            rss_high_water_bytes: 307200,
        }];
        validate_host_identities(temp.path(), &processes).unwrap();
        fixture_process(temp.path(), 7, 11);
        let error = validate_host_identities(temp.path(), &processes).unwrap_err();
        assert!(error.downcast_ref::<CensusChurn>().is_some());
    }

    #[test]
    fn kernel_resident_components_do_not_double_count_slab_children() {
        let text = "Slab: 10 kB\nSReclaimable: 7 kB\nSUnreclaim: 3 kB\nKernelStack: 2 kB\nPageTables: 3 kB\nPercpu: 1 kB\n";
        let parsed = kernel_bytes(text).unwrap();
        assert_eq!(parsed.values().sum::<u64>(), 16 * 1024);
        assert!(kernel_bytes("Slab: 1 kB\n").is_err());
        assert!(kernel_bytes(&format!("{text}Slab: 1 kB\n")).is_err());
    }
    #[test]
    fn kernel_threads_have_zero_process_rss_only_in_host_census() {
        let temp = tempfile::tempdir().unwrap();
        let cg = temp.path().join("cg");
        let proc = temp.path().join("proc");
        fs::create_dir_all(&cg).unwrap();
        fs::create_dir_all(proc.join("2")).unwrap();
        fs::write(cg.join("cgroup.procs"), "2\n").unwrap();
        let mut fields = vec!["0"; 20];
        fields[0] = "S";
        fields[6] = "2097152"; // PF_KTHREAD; valid start_ticks may be zero at boot
        fs::write(
            proc.join("2/stat"),
            format!("2 (kthreadd) {}", fields.join(" ")),
        )
        .unwrap();
        fs::write(proc.join("2/cgroup"), "0::/\n").unwrap();
        let host = capture_processes(&cg, Path::new("/"), &proc, true).unwrap();
        assert_eq!(host.aggregate_rss_bytes, Some(0));
        assert_eq!(host.processes[0].start_ticks, 0);
        assert!(checked_capture(&cg, Path::new("/"), &proc).is_err());
        fields[6] = "0";
        fs::write(
            proc.join("2/stat"),
            format!("2 (user) {}", fields.join(" ")),
        )
        .unwrap();
        assert!(capture_processes(&cg, Path::new("/"), &proc, true).is_err());
    }
    #[test]
    fn century_maxima_survive_smaller_missing_and_cross_century_samples() {
        let unit = serde_json::json!({"unit":"lane.service","invocation_id":"a".repeat(32),
            "control_group":"/system.slice/lane.service",
            "rss":{"census_stable":true,"error":null,"aggregate_rss_bytes":101}});
        let row = serde_json::json!({"range":"225-226","invocation_binding_stable":true,
            "producer_before":unit,"producer_after":unit,"controller_before":unit,"controller_after":unit});
        let current = serde_json::json!({"recorded_at_utc":"2026-10-23T08:00:00Z","replays":[row]});
        let first = history(&Value::Null, &current).unwrap();
        assert_eq!(first["200"]["maximum_observed_lane_rss_bytes"], 101);
        assert_eq!(first["200"]["reservation_ceiling_bytes"], 151); // integer floor, no double-counting same unit
        let mut asymmetric = current.clone();
        asymmetric["replays"][0]["producer_after"]["rss"]["aggregate_rss_bytes"] = Value::from(121);
        assert_eq!(
            history(&Value::Null, &asymmetric).unwrap()["200"]["maximum_observed_lane_rss_bytes"],
            121
        );
        let previous = serde_json::json!({"lane_rss_history":first});
        let mut native = current.clone();
        native["replays"][0]["resource_only"] = Value::Bool(true);
        native["replays"][0]["producer_after"]["rss"]["aggregate_rss_bytes"] = Value::from(999999);
        assert!(
            history(&Value::Null, &native)
                .unwrap()
                .as_object()
                .unwrap()
                .is_empty(),
            "native cold-input RSS is not an executing lane maximum"
        );
        assert_eq!(
            history(&previous, &Value::Null).unwrap(),
            previous["lane_rss_history"]
        );
        let mut invalid = current.clone();
        invalid["replays"][0]["invocation_binding_stable"] = Value::Bool(false);
        assert!(
            history(&Value::Null, &invalid)
                .unwrap()
                .as_object()
                .unwrap()
                .is_empty()
        );
        let mut later = current.clone();
        later["replays"][0]["range"] = Value::String("925-926".into());
        let next = history(&previous, &later).unwrap();
        assert_eq!(next["200"]["maximum_observed_lane_rss_bytes"], 101);
        assert_eq!(next["900"]["maximum_observed_lane_rss_bytes"], 101);
    }
    #[test]
    fn rss_is_bytes_not_cgroup_memory_or_process_peak_sum() {
        assert_eq!(
            status("Pid: 7\nTgid: 7\nVmRSS: 100 kB\nVmHWM: 300 kB\n", 7).unwrap(),
            (102400, 307200)
        );
        for bad in [
            "Pid: 7\nTgid: 8\nVmRSS: 1 kB\nVmHWM: 2 kB\n",
            "Pid: 7\nTgid: 7\nVmRSS: 1 MB\nVmHWM: 2 kB\n",
            "Pid: 7\nTgid: 7\nVmRSS: 3 kB\nVmHWM: 2 kB\n",
            "Pid: 7\nTgid: 7\nVmRSS: 1 kB\nVmRSS: 1 kB\nVmHWM: 2 kB\n",
        ] {
            assert!(status(bad, 7).is_err());
        }
    }
    #[test]
    fn sums_unique_processes_and_rejects_foreign_membership() {
        let temp = tempfile::tempdir().unwrap();
        let cg = temp.path().join("cg");
        let proc = temp.path().join("proc");
        fs::create_dir_all(cg.join("child")).unwrap();
        fs::write(cg.join("cgroup.procs"), "7\n8\n").unwrap();
        fs::write(cg.join("child/cgroup.procs"), "8\n").unwrap();
        for pid in [7, 8] {
            let root = proc.join(pid.to_string());
            fs::create_dir_all(&root).unwrap();
            let tail = std::iter::once("S")
                .chain(std::iter::repeat_n("0", 18))
                .chain(std::iter::once("123"))
                .collect::<Vec<_>>()
                .join(" ");
            fs::write(root.join("stat"), format!("{pid} (worker ) name) {tail}")).unwrap();
            fs::write(
                root.join("status"),
                format!("Pid: {pid}\nTgid: {pid}\nVmRSS: 100 kB\nVmHWM: 300 kB\n"),
            )
            .unwrap();
            fs::write(root.join("cgroup"), "0::/system.slice/lane.service\n").unwrap();
        }
        let r = checked_capture(&cg, Path::new("/system.slice/lane.service"), &proc).unwrap();
        assert_eq!(r.aggregate_rss_bytes, Some(204800));
        assert_eq!(r.processes.len(), 2);
        fs::write(
            proc.join("8/cgroup"),
            "0::/system.slice/lane.service-foreign\n",
        )
        .unwrap();
        assert!(checked_capture(&cg, Path::new("/system.slice/lane.service"), &proc).is_err());
    }
}
