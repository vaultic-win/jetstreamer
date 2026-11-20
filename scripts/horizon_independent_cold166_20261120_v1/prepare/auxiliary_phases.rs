//! Both queues retain their maximum *concurrent phase*, including after either worker exits.
use super::{n, sum};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    process::Command,
};

const ROOT: &str = "/var/lib/jetstreamer/horizon_runtime_data/root0245-zero-recovery-20261120-v1";
const ADMISSIONS: [(&str, &str); 4] = [
    (
        "BOUNDED_CENSUS_BUILD_ADMISSION",
        "abe1786e69a9eb2334e3df2a008fb3c56b327dc5ab19330044eb3a2f7477ac94",
    ),
    (
        "BOUNDED_CENSUS_ADMISSION",
        "9d2000049f7673b65edd7801d8281a36ba041f8e4c679237988e0c9f84945f07",
    ),
    (
        "FLEET_BUILD_ADMISSION",
        "69b596f5b1d8c22f7b0cfeee4ae74dc669e764713a49a6e18b659a9975380f7c",
    ),
    (
        "AUDIT79_HANDOFF",
        "3607504df7749884023d51c90026babd2fad9dec23f48af38b68ea72b8130c78",
    ),
];

fn phase_peak(a: &Value, build: &Value, census: &Value, fleet_build: &Value) -> Result<(u64, u64)> {
    let build_mem = n(build, "memory_max")?;
    let park_mem = n(build, "concurrent_park_bytes")?;
    let census_mem = n(census, "memory_max_bytes")?;
    let fleet_mem = n(fleet_build, "memory_max")?;
    let census_cpu = n(census, "cpu_quota_micros")?;
    let compiler_cpu = n(census, "maximum_compiler_cpu_micros")?;
    ensure!(
        build_mem >= 4 << 30
            && park_mem >= 2 << 30
            && census_mem >= 4 << 30
            && fleet_mem >= 2 << 30
            && n(fleet_build, "concurrent_holding_or_census_max")? == census_mem
            && n(census, "additional_optional_serial_compiler_bytes")? == fleet_mem
            && census_cpu >= 2_000_000
            && compiler_cpu >= 1_000_000
            && census["holding_exclusive_lock_enforced"] == true
            && fleet_build["census_booking"] == ADMISSIONS[1].1,
        "incomplete auxiliary phase booking"
    );
    let old_build = n(a, "build_memory_bytes")?;
    let old_holding = n(a, "holding_memory_bytes")?;
    let park_and_compile = sum(old_build.max(build_mem), old_holding.max(park_mem))?;
    let census_and_compile = sum(old_build.max(fleet_mem), old_holding.max(census_mem))?;
    let cpu = sum(
        n(a, "build_cpu_quota_micros")?.max(compiler_cpu),
        n(a, "holding_cpu_quota_micros")?.max(census_cpu),
    )?;
    Ok((park_and_compile.max(census_and_compile), cpu))
}

pub(super) fn load(fleet: &Value) -> Result<(Value, u64, u64)> {
    let mut receipts = Vec::new();
    let mut bindings = json!({});
    for (name, hash) in ADMISSIONS {
        let path = if name == "AUDIT79_HANDOFF" {
            Path::new("/var/lib/jetstreamer/horizon_runtime_data/r2-audit-storage-20261119-v1/epoch79-clean-handoff-v1/proof.json").to_owned()
        } else {
            Path::new(ROOT).join(format!("{name}.json"))
        };
        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&path)?;
        let m = file.metadata()?;
        ensure!(
            path.canonicalize()? == path
                && m.is_file()
                && m.uid() == 0
                && m.mode() & 0o022 == 0
                && m.nlink() == 1
                && m.len() <= 65536,
            "unsafe auxiliary receipt {name}"
        );
        let mut data = Vec::new();
        file.take(65537).read_to_end(&mut data)?;
        ensure!(
            data.len() as u64 == m.len() && format!("{:x}", Sha256::digest(&data)) == hash,
            "changed auxiliary receipt {name}"
        );
        receipts.push(serde_json::from_slice::<Value>(&data)?);
        bindings[name] = json!({"path":path,"sha256":hash});
    }
    let latest = &fleet["retained_terminal_recovery_commitments"]["latest_build_booking"];
    ensure!(
        latest.is_null()
            || latest == &bindings[ADMISSIONS[0].0]
            || latest == &bindings[ADMISSIONS[2].0],
        "unreviewed additional compiler booking"
    );
    let (memory, cpu) = phase_peak(
        &fleet["retry9_auxiliary_commitments"],
        &receipts[0],
        &receipts[1],
        &receipts[2],
    )?;
    let handoff = &receipts[3];
    ensure!(
        n(handoff, "handoff_memory")? == 128 << 20 && handoff["handoff_cpu_quota"] == "25%",
        "unexpected audit handoff envelope"
    );
    Ok((
        bindings,
        sum(memory, n(handoff, "handoff_memory")?)?,
        sum(cpu, 250_000)?,
    ))
}

fn active_units() -> Result<Vec<String>> {
    let output = Command::new("/usr/bin/systemctl")
        .args([
            "list-units",
            "--plain",
            "--no-legend",
            "--no-pager",
            "--output=json",
            "--state=running,activating,reloading,deactivating",
            "horizon-*build*.service",
            "horizon-audit79-after84-cleanup-20261120-v1.service",
            "horizon-*holding*.service",
            "horizon-*park*.service",
            "horizon-*census*.service",
        ])
        .output()?;
    ensure!(
        output.status.success(),
        "cannot enumerate working auxiliary units"
    );
    let mut units = Vec::new();
    for row in serde_json::from_slice::<Vec<Value>>(&output.stdout)? {
        let name = row["unit"].as_str().context("auxiliary unit name")?;
        ensure!(
            name.starts_with("horizon-")
                && name.ends_with(".service")
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-._".contains(&b)),
            "invalid auxiliary unit"
        );
        units.push(name.to_string());
    }
    units.sort();
    Ok(units)
}

fn quota_micros(text: &str) -> Result<u64> {
    let mut fields = text.split_whitespace();
    let quota = fields.next().context("quota")?.parse::<u64>()?;
    let period = fields.next().context("quota period")?.parse::<u64>()?;
    ensure!(
        quota > 0 && period > 0 && fields.next().is_none(),
        "invalid auxiliary CPU quota"
    );
    Ok(quota
        .checked_mul(1_000_000)
        .context("quota overflow")?
        .div_ceil(period))
}

pub(super) fn native(memory: u64, cpu: u64) -> Result<Value> {
    let units = active_units()?;
    let mut rows = Vec::new();
    let mut live_mem = 0;
    let mut live_cpu = 0;
    for name in &units {
        let out = Command::new("/usr/bin/systemctl")
            .args([
                "show",
                name,
                "-pId,InvocationID,ControlGroup,MainPID,ControlPID",
            ])
            .output()?;
        ensure!(
            out.status.success(),
            "cannot inspect auxiliary worker {name}"
        );
        let text = std::str::from_utf8(&out.stdout)?;
        let v: BTreeMap<_, _> = text.lines().filter_map(|l| l.split_once('=')).collect();
        let cgroup = format!("/system.slice/{name}");
        let iid = v.get("InvocationID").context("auxiliary invocation")?;
        ensure!(
            v.get("Id") == Some(&name.as_str())
                && iid.len() == 32
                && iid.bytes().all(|b| b.is_ascii_hexdigit())
                && v.get("ControlGroup") == Some(&cgroup.as_str()),
            "auxiliary identity changed: {name}"
        );
        let props = Path::new("/sys/fs/cgroup/system.slice").join(name);
        let mem = fs::read_to_string(props.join("memory.max"))?
            .trim()
            .parse::<u64>()?;
        let quota = quota_micros(&fs::read_to_string(props.join("cpu.max"))?)?;
        ensure!(
            mem > 0 && fs::read_to_string(props.join("memory.swap.max"))?.trim() == "0",
            "unbounded auxiliary swap or invalid memory"
        );
        live_mem = sum(live_mem, mem)?;
        live_cpu = sum(live_cpu, quota)?;
        rows.push(json!({"unit":name,"invocation_id":iid,"main_pid":v.get("MainPID"),"control_pid":v.get("ControlPID"),"memory_max_bytes":mem,"cpu_quota_micros":quota}));
    }
    ensure!(
        live_mem <= memory && live_cpu <= cpu && active_units()? == units,
        "live auxiliary workers exceed or changed across the booked phase"
    );
    Ok(
        json!({"workers":rows,"working_memory_max_bytes":live_mem,"working_cpu_quota_micros":live_cpu}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn independent_queues_retain_the_concurrent_phase_peak() {
        let a = json!({"build_memory_bytes":2u64<<30,"holding_memory_bytes":2u64<<30,"build_cpu_quota_micros":1_000_000,"holding_cpu_quota_micros":2_000_000});
        let b = json!({"memory_max":4u64<<30,"concurrent_park_bytes":2u64<<30});
        let c = json!({"memory_max_bytes":4u64<<30,"additional_optional_serial_compiler_bytes":2u64<<30,"cpu_quota_micros":2_000_000,"maximum_compiler_cpu_micros":1_000_000,"holding_exclusive_lock_enforced":true});
        let mut f = json!({"memory_max":2u64<<30,"concurrent_holding_or_census_max":4u64<<30,"census_booking":ADMISSIONS[1].1});
        assert_eq!(phase_peak(&a, &b, &c, &f).unwrap(), (6u64 << 30, 3_000_000));
        f["concurrent_holding_or_census_max"] = json!((4u64 << 30) - 1);
        assert!(phase_peak(&a, &b, &c, &f).is_err());
    }
}
