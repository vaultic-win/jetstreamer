//! Add the audit's complete cgroup reservation to the historical preparation.
use super::*;
const AUDIT_UNIT: &str = "horizon-r2-chronological-plugin-audit-20261118-v1.service";
const AUDIT_IMAGE: &str =
    "/usr/local/lib/jetstreamer/horizon-r2-chronological-plugin-audit-20261119-v5/audit";
const AUDIT_SHA: &str = "8d44decb416578cefdea457ddd3fdccdc64689a5f57de33f64eb0aa286c9984b";
const AUDIT_CONFIG: &str =
    "/usr/local/lib/jetstreamer/horizon-r2-chronological-plugin-audit-20261119-v5/config.json";
const AUDIT_CONFIG_SHA: &str = "eff84b96fe9e1ba8ffbb16b706887052b2229fdf934ac7a49799d9c6539101ba";
const HANDOFF: &str =
    "/usr/local/lib/jetstreamer/horizon-audit-exact-budget-handoff-20261119-v1/handoff.json";
const HANDOFF_SHA: &str = "8e9df42acb7784416775361be5b2f2ca7304ff76aeb61cc6ebb1e971ca6cc0f6";
const ALLOCATION: &str =
    "/var/lib/jetstreamer/r2-audit-additive-budget-20261118-v1/allocation.json";
const ALLOCATION_SHA: &str = "f99e0d79b062a86f13d808eafed4cb4d53c7325c154934b0c2b59f4f78fa8a46";
const MEMORY: u64 = 24 << 30;
const CPU: u64 = 4_000_000;

fn config_shape(cfg: &Value, handoff: &Value) -> Result<()> {
    ensure!(
        cfg["state_directory"] == "/var/lib/jetstreamer/r2-chronological-plugin-audit-20261118-v1"
            && cfg["reserve_bytes"] == 32u64 << 30
            && cfg["max_archive_bytes"] == 385_290_386_716u64
            && cfg["build_reserve_bytes"] == 16u64 << 30
            && cfg["threads"] == 4
            && cfg["build_jobs"] == 2
            && cfg["external_scratch"].is_null(),
        "audit filesystem reservation differs"
    );
    ensure!(
        handoff["schema"] == "horizon-r2-audit-exact-budget-handoff-v1"
            && handoff["runtime"] == AUDIT_IMAGE
            && handoff["runtime_sha256"] == AUDIT_SHA
            && handoff["DATA_reservation_bytes"] == 0
            && handoff["root_floor_bytes"] == 32u64 << 30
            && handoff["metadata_growth_limit_bytes"] == 160u64 << 20
            && handoff["archive_acceptance_ceiling_bytes"] == cfg["max_archive_bytes"]
            && handoff["ceiling_is_not_a_capacity_reservation"] == true
            && handoff["actual_capacity_rechecked_per_archive"] == true
            && handoff["unused_compiler_allowance_not_reserved_for_playback"] == true,
        "exact-size audit handoff differs"
    );
    Ok(())
}

fn shape(v: &Value) -> Result<()> {
    ensure!(
        v["Id"] == AUDIT_UNIT
            && v["ActiveState"] == "active"
            && v["SubState"] == "running"
            && v["MainPID"]
                .as_str()
                .and_then(|n| n.parse::<u64>().ok())
                .is_some_and(|n| n > 0)
            && v["InvocationID"]
                .as_str()
                .is_some_and(|s| s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit()))
            && v["MemoryMax"].as_str().and_then(|s| s.parse::<u64>().ok()) == Some(MEMORY)
            && v["MemoryHigh"].as_str().and_then(|s| s.parse::<u64>().ok()) == Some(20u64 << 30)
            && v["MemorySwapMax"] == "0"
            && v["CPUQuotaPerSecUSec"] == "4s"
            && v["ControlGroup"] == format!("/system.slice/{AUDIT_UNIT}"),
        "audit identity or additive resource limits differ"
    );
    Ok(())
}
pub(super) fn observe() -> Result<Value> {
    fixed(ALLOCATION, ALLOCATION_SHA, 1 << 20)?;
    fixed(AUDIT_IMAGE, AUDIT_SHA, 128 << 20)?;
    fixed(AUDIT_CONFIG, AUDIT_CONFIG_SHA, 1 << 20)?;
    fixed(HANDOFF, HANDOFF_SHA, 1 << 20)?;
    let allocation: Value =
        serde_json::from_slice(&read_regular(Path::new(ALLOCATION), 1 << 20, true)?)?;
    ensure!(
        allocation["schema"] == "horizon-r2-audit-additive-allocation-v1"
            && allocation["original_complete_projected_memory_bytes"] == 761_131_708_416u64
            && allocation["additional_audit_memory_bytes"] == MEMORY
            && allocation["additional_audit_cpu_quota_micros"] == CPU
            && allocation["audit_DATA_reservation_bytes"] == 0
            && allocation["resource_credit_bytes"] == 0,
        "audit allocation differs"
    );
    let out = Command::new("/usr/bin/systemctl").args(["show", AUDIT_UNIT,
        "-pId,ActiveState,SubState,MainPID,InvocationID,MemoryMax,MemoryHigh,MemorySwapMax,CPUQuotaPerSecUSec,ControlGroup"]).output()?;
    ensure!(out.status.success(), "audit native query failed");
    let mut row = serde_json::Map::new();
    for line in String::from_utf8(out.stdout)?.lines() {
        let (k, v) = line.split_once('=').context("audit native row")?;
        ensure!(
            row.insert(k.into(), json!(v)).is_none(),
            "duplicate audit native property"
        );
    }
    let row = Value::Object(row);
    shape(&row)?;
    let pid = string(&row, "MainPID")?.parse::<u64>()?;
    let start = process_start_ticks(pid)?;
    ensure!(
        fs::read_link(format!("/proc/{pid}/exe"))? == Path::new(AUDIT_IMAGE),
        "audit PID executable differs"
    );
    let config_path = AUDIT_CONFIG;
    let config_bytes = read_regular(Path::new(config_path), 1 << 20, true)?;
    let cfg: Value = serde_json::from_slice(&config_bytes)?;
    let handoff: Value = serde_json::from_slice(&read_regular(Path::new(HANDOFF), 1 << 20, true)?)?;
    config_shape(&cfg, &handoff)?;
    ensure!(process_start_ticks(pid)? == start, "audit PID reused");
    Ok(
        json!({"native":row,"start_ticks":start,"image":{"path":AUDIT_IMAGE,"sha256":AUDIT_SHA},
        "config":{"path":config_path,"sha256":digest(&config_bytes)},
        "allocation":{"path":ALLOCATION,"sha256":ALLOCATION_SHA},
        "exact_archive_budget_handoff":{"path":HANDOFF,"sha256":HANDOFF_SHA}}),
    )
}
pub(super) fn requirements(
    prepared: &Value,
    total: u64,
    available: u64,
    cores: u64,
) -> Result<Value> {
    let r = &prepared["resource_checks"];
    let required = number(&r["memory_accounting"], "required_available_bytes")?
        .checked_add(MEMORY)
        .context("audit available memory overflow")?;
    let full = number(r, "complete_memory_plus_reserve_bytes")?
        .checked_add(MEMORY)
        .context("audit total memory overflow")?;
    let cpu = number(r, "booked_cpu_quota_micros")?
        .checked_add(CPU)
        .context("audit CPU overflow")?;
    ensure!(
        total >= full && available >= required,
        "additional audit memory does not fit"
    );
    ensure!(
        cores > 0 && cpu <= cores.checked_mul(1_000_000).context("host CPU overflow")?,
        "additional audit CPU does not fit"
    );
    Ok(
        json!({"required_available_memory_bytes":required,"complete_memory_plus_reserve_bytes":full,
        "complete_cpu_quota_micros":cpu,"additional_memory_bytes":MEMORY,"additional_cpu_quota_micros":CPU,
        "actual_online_cpus":cores,"resource_credit_bytes":0,"all_prepared_promises_retained":true}),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_size_audit_handoff_keeps_root_only_storage_and_all_limits() {
        let cfg = json!({"state_directory":"/var/lib/jetstreamer/r2-chronological-plugin-audit-20261118-v1",
            "reserve_bytes":32u64<<30,"max_archive_bytes":385_290_386_716u64,
            "build_reserve_bytes":16u64<<30,"threads":4,"build_jobs":2});
        let handoff = json!({"schema":"horizon-r2-audit-exact-budget-handoff-v1",
            "runtime":AUDIT_IMAGE,"runtime_sha256":AUDIT_SHA,"DATA_reservation_bytes":0,
            "root_floor_bytes":32u64<<30,"metadata_growth_limit_bytes":160u64<<20,
            "archive_acceptance_ceiling_bytes":385_290_386_716u64,
            "ceiling_is_not_a_capacity_reservation":true,"actual_capacity_rechecked_per_archive":true,
            "unused_compiler_allowance_not_reserved_for_playback":true});
        config_shape(&cfg, &handoff).unwrap();
        for (key, value) in [
            ("external_scratch", json!({"directory":"/home/sol/scratch"})),
            ("reserve_bytes", json!(1)),
            ("max_archive_bytes", json!(16u64 << 30)),
            ("threads", json!(5)),
        ] {
            let mut changed = cfg.clone();
            changed[key] = value;
            assert!(config_shape(&changed, &handoff).is_err());
        }
        for (key, value) in [
            ("DATA_reservation_bytes", json!(1)),
            ("runtime_sha256", json!("0".repeat(64))),
            ("actual_capacity_rechecked_per_archive", json!(false)),
        ] {
            let mut changed = handoff.clone();
            changed[key] = value;
            assert!(config_shape(&cfg, &changed).is_err());
        }
    }
    #[test]
    #[ignore = "requires the genuine sealed audit v5 service on this host"]
    fn actual_current_audit_preserves_additive_booking() {
        let result = observe().unwrap();
        assert_eq!(result["image"]["sha256"], AUDIT_SHA);
        assert_eq!(
            result["exact_archive_budget_handoff"]["sha256"],
            HANDOFF_SHA
        );
    }
    #[test]
    fn complete_audit_reservation_is_additive_and_fails_closed() {
        let p = json!({"resource_checks":{"memory_accounting":{"required_available_bytes":600u64<<30},
            "complete_memory_plus_reserve_bytes":700u64<<30,"booked_cpu_quota_micros":43_000_000}});
        let r = requirements(&p, 724u64 << 30, 624u64 << 30, 47).unwrap();
        assert_eq!(r["complete_cpu_quota_micros"], 47_000_000u64);
        assert!(requirements(&p, (724u64 << 30) - 1, 624u64 << 30, 47).is_err());
        assert!(requirements(&p, 724u64 << 30, (624u64 << 30) - 1, 47).is_err());
        assert!(requirements(&p, 724u64 << 30, 624u64 << 30, 46).is_err());
        assert!(requirements(&json!({}), u64::MAX, u64::MAX, 128).is_err());
    }
    #[test]
    fn changed_audit_caps_or_owner_are_rejected() {
        let p = json!({"Id":AUDIT_UNIT,"ActiveState":"active","SubState":"running","MainPID":"123",
            "InvocationID":"a".repeat(32),"MemoryMax":MEMORY.to_string(),"MemoryHigh":(20u64<<30).to_string(),
            "MemorySwapMax":"0","CPUQuotaPerSecUSec":"4s","ControlGroup":format!("/system.slice/{AUDIT_UNIT}")});
        shape(&p).unwrap();
        for (key, value) in [
            ("MemoryMax", "34359738368"),
            ("MemorySwapMax", "infinity"),
            ("CPUQuotaPerSecUSec", "5s"),
            ("MainPID", "0"),
            ("ActiveState", "inactive"),
        ] {
            let mut changed = p.clone();
            changed[key] = json!(value);
            assert!(shape(&changed).is_err());
        }
    }
}
