//! Manager configuration is not the kernel allocation after an FD cap update.
use super::*;
use std::os::fd::{AsRawFd, FromRawFd};
fn target(kind: &str) -> Result<(u64, u64, u64)> {
    if kind == "native-input" {
        return Ok((112u64 << 30, 128u64 << 30, 128u64 << 30));
    }
    ensure!(kind == "bracket", "223 resource role differs");
    let page = u64::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })?;
    ensure!(page > 0 && page.is_power_of_two(), "223 resource page size");
    Ok((
        150_000_000_000 / page * page,
        225_000_000_000 / page * page,
        225_000_000_000,
    ))
}
fn classification(
    kind: &str,
    manager_high: u64,
    manager_max: u64,
    high: u64,
    max: u64,
    proof: bool,
    committed: bool,
) -> Result<(String, u64)> {
    ensure!(
        manager_high == 14u64 << 30 && manager_max == 16u64 << 30,
        "223 configured manager policy changed without a qualified transition"
    );
    let (target_high, target_max, declared) = target(kind)?;
    ensure!(
        matches!(high,h if h==14u64<<30 || h==target_high)
            && matches!(max,m if m==16u64<<30 || m==target_max),
        "223 unexpected kernel envelope"
    );
    let full = high == target_high && max == target_max;
    ensure!(
        !committed || (proof && full),
        "223 committed spawn lacks matching immutable allocation and actual kernel caps"
    );
    let state = if committed {
        "native-allocation-committed"
    } else if full {
        "full-cap-update-uncommitted"
    } else if high != 14u64 << 30 || max != 16u64 << 30 {
        "partial-cap-update"
    } else if proof {
        "allocation-not-effective"
    } else {
        "control-only"
    };
    let producer = if state == "control-only" {
        16u64 << 30
    } else {
        declared
    };
    Ok((
        state.into(),
        producer
            .checked_add(2u64 << 30)
            .context("223 actor budget overflow")?,
    ))
}
fn kernel(actor: &Actor) -> Result<Value> {
    let path = Path::new("/sys/fs/cgroup").join(actor.cgroup.trim_start_matches('/'));
    ensure!(
        path.canonicalize()? == path,
        "223 resource cgroup redirected"
    );
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(&path)?;
    let before = directory.metadata()?;
    let read = |name: &str| -> Result<u64> {
        let name = std::ffi::CString::new(name)?;
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        ensure!(fd >= 0, "223 kernel control unavailable");
        let mut bytes = String::new();
        unsafe { File::from_raw_fd(fd) }
            .take(128)
            .read_to_string(&mut bytes)?;
        Ok(bytes.trim().parse()?)
    };
    let value = json!({"high":read("memory.high")?,"max":read("memory.max")?,"swap":read("memory.swap.max")?,
        "current":read("memory.current")?,"device":before.dev(),"inode":before.ino()});
    let after = fs::symlink_metadata(&path)?;
    ensure!(
        before.dev() == after.dev() && before.ino() == after.ino(),
        "223 kernel cgroup was replaced"
    );
    Ok(value)
}
fn allocation(t: &Task, path: &Path) -> Result<Option<(BoundFile, Value)>> {
    if !path.try_exists()? {
        return Ok(None);
    }
    let binding: BoundFile = serde_json::from_value(private157::file_binding(path)?)?;
    let value = bound_json(&binding)?;
    let expected = if t.job_kind == "native-input" {
        "jetstreamer-epoch223-demotion-native-allocation-proof-v1"
    } else {
        "jetstreamer-epoch223-demotion-allocation-proof-v1"
    };
    let (high, max, _) = target(&t.job_kind)?;
    ensure!(
        value["schema"] == expected
            && value["runner"] == serde_json::to_value(&t.actor)?
            && value["effective_memory_high_bytes"] == high
            && value["effective_memory_max_bytes"] == max
            && value["publication_authorized"] == false
            && value["r2_mutations"] == false,
        "223 immutable allocation does not bind actual actor/kernel envelope"
    );
    let capture: Capture = serde_json::from_value(bound_json(&t.capture_spec)?)?;
    let task_binding: BoundFile =
        serde_json::from_value(private157::file_binding(&capture.output)?)?;
    ensure!(
        value["status_task"] == private157::binding(&task_binding),
        "223 allocation belongs to another captured task"
    );
    let result = bound_json(&serde_json::from_value(value["capacity_result"].clone())?)?;
    ensure!(
        result["schema"] == "jetstreamer-epoch223-demotion-capacity-result-v1"
            && result["context"]["producer"] == serde_json::to_value(&t.actor)?
            && result["context"]["phase"] == "spawn"
            && result["context"]["job_kind"] == t.job_kind
            && result["context"]["runtime_plan"] == private157::binding(&t.runtime_plan)
            && result["capacity"]["all_live_growth_and_century_floor_protected"] == true,
        "223 allocation has no exact complete-accounting result"
    );
    Ok(Some((binding, value)))
}
pub(super) fn sample(t: &Task, manager: &Value) -> Result<Value> {
    let actor = kernel(&t.actor)?;
    let g = guard_for(t)?;
    let guard = kernel(&g)?;
    ensure!(
        actor["device"] == t.cgroup_device
            && actor["inode"] == t.cgroup_inode
            && actor["swap"] == 0
            && guard["max"] == 1u64 << 30
            && guard["high"] == (768u64 << 20)
            && guard["swap"] == 0
            && actor["current"]
                .as_u64()
                .zip(actor["max"].as_u64())
                .is_some_and(|(c, m)| c <= m)
            && guard["current"].as_u64().is_some_and(|c| c <= 1u64 << 30),
        "223 original kernel/independent guard envelope differs"
    );
    let path = if t.job_kind == "native-input" {
        t.run_root.join("native-spawn-allocation.json")
    } else {
        t.run_root.join("receipts/spawn-allocation.json")
    };
    let proof = allocation(t, &path)?;
    let marker = if t.job_kind == "native-input" {
        t.run_root.join("native-spawn-grant.json")
    } else {
        t.run_root.join("receipts/spawn-ready.json")
    };
    let committed = marker.try_exists()?;
    if committed {
        let token: BoundFile = serde_json::from_value(private157::file_binding(&marker)?)?;
        let token = bound_json(&token)?;
        let grant = if t.job_kind == "native-input" {
            token
        } else {
            bound_json(&serde_json::from_value(token["grant"].clone())?)?
        };
        ensure!(
            grant["runner"] == serde_json::to_value(&t.actor)?
                && grant["runtime_plan"] == private157::binding(&t.runtime_plan)
                && proof.as_ref().is_some_and(
                    |(binding, _)| grant["allocation_proof"] == private157::binding(binding)
                ),
            "223 committed spawn borrows another immutable allocation"
        );
    }
    let high = actor["high"].as_u64().context("223 actual high")?;
    let max = actor["max"].as_u64().context("223 actual max")?;
    let configured_high = manager["MemoryHigh"]
        .as_str()
        .context("223 configured high")?
        .parse()?;
    let configured_max = manager["MemoryMax"]
        .as_str()
        .context("223 configured max")?
        .parse()?;
    let (state, reserved) = classification(
        &t.job_kind,
        configured_high,
        configured_max,
        high,
        max,
        proof.is_some(),
        committed,
    )?;
    Ok(
        json!({"schema":"jetstreamer-epoch223-demotion-actual-resource-contract-v1","observed_unix_millis":millis()?,"actor":t.actor,"guard_actor":g,
        "manager_configured_memory_high_bytes":configured_high,"manager_configured_memory_max_bytes":configured_max,
        "kernel":actor,"guard_kernel":guard,"allocation_state":state,"allocation_receipt":proof.map(|(b,_)|b),
        "spawn_permission_committed":committed,"complete_actor_memory_reservation_bytes":reserved,
        "manager_policy_was_not_updated_by_fd_cap_write":true,"issuer_budget_retained_conservatively":true,
        "native_execution_authorized":false,"publication_authorized":false,"r2_mutations":false}),
    )
}
pub(super) fn validate_saved(t: &Task, value: &Value) -> Result<()> {
    let u = |key: &str| {
        value[key]
            .as_u64()
            .with_context(|| format!("223 saved {key}"))
    };
    let kernel = &value["kernel"];
    let proof: Option<BoundFile> = serde_json::from_value(value["allocation_receipt"].clone())?;
    if let Some(binding) = &proof {
        let actual = allocation(t, &binding.path)?.context("223 frozen allocation disappeared")?;
        ensure!(actual.0 == *binding, "223 frozen allocation bytes changed");
    }
    let (state, reserved) = classification(
        &t.job_kind,
        u("manager_configured_memory_high_bytes")?,
        u("manager_configured_memory_max_bytes")?,
        kernel["high"].as_u64().context("223 saved high")?,
        kernel["max"].as_u64().context("223 saved max")?,
        proof.is_some(),
        value["spawn_permission_committed"]
            .as_bool()
            .context("223 commit state")?,
    )?;
    ensure!(
        value["schema"] == "jetstreamer-epoch223-demotion-actual-resource-contract-v1"
            && value["actor"] == serde_json::to_value(&t.actor)?
            && value["guard_actor"] == serde_json::to_value(guard_for(t)?)?
            && kernel["device"] == t.cgroup_device
            && kernel["inode"] == t.cgroup_inode
            && value["allocation_state"] == state
            && value["complete_actor_memory_reservation_bytes"] == reserved
            && value["manager_policy_was_not_updated_by_fd_cap_write"] == true
            && kernel["swap"] == 0
            && value["guard_kernel"]["max"] == 1u64 << 30
            && value["guard_kernel"]["high"] == 768u64 << 20
            && value["guard_kernel"]["swap"] == 0
            && kernel["current"]
                .as_u64()
                .zip(kernel["max"].as_u64())
                .is_some_and(|(c, m)| c <= m)
            && value["guard_kernel"]["current"]
                .as_u64()
                .is_some_and(|c| c <= 1u64 << 30),
        "223 saved resource accounting undercounts or changes kernel/manager policy"
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn configured_sixteen_gib_never_replaces_full_native_kernel_reservation() {
        let (state, bytes) = classification(
            "native-input",
            14 << 30,
            16 << 30,
            112 << 30,
            128 << 30,
            true,
            true,
        )
        .unwrap();
        assert_eq!(state, "native-allocation-committed");
        assert_eq!(bytes, 130 << 30);
        let (high, max, _) = target("bracket").unwrap();
        assert_eq!(
            classification("bracket", 14 << 30, 16 << 30, high, max, true, true)
                .unwrap()
                .1,
            225_000_000_000 + (2u64 << 30)
        );
    }
    #[test]
    fn partial_cap_failure_retains_full_reservation_without_launch_permission() {
        let (_, max, _) = target("bracket").unwrap();
        let (state, bytes) =
            classification("bracket", 14 << 30, 16 << 30, 14 << 30, max, false, false).unwrap();
        assert_eq!(state, "partial-cap-update");
        assert_eq!(bytes, 225_000_000_000 + (2u64 << 30));
        assert!(classification("bracket", 14 << 30, 16 << 30, 14 << 30, max, false, true).is_err());
        assert!(
            classification(
                "native-input",
                14 << 30,
                16 << 30,
                14 << 30,
                16 << 30,
                true,
                true
            )
            .is_err()
        );
    }
    #[test]
    fn malformed_or_understated_manager_and_kernel_limits_fail_closed() {
        for kind in ["bracket", "native-input"] {
            for (manager_high, manager_max, high, max) in [
                (14u64 << 30, 16u64 << 30, 14u64 << 30, 15u64 << 30),
                (13u64 << 30, 16u64 << 30, 14u64 << 30, 16u64 << 30),
                (14u64 << 30, 15u64 << 30, 14u64 << 30, 16u64 << 30),
                (14u64 << 30, 16u64 << 30, 0, 16u64 << 30),
                (14u64 << 30, 16u64 << 30, 14u64 << 30, u64::MAX),
            ] {
                assert!(
                    classification(kind, manager_high, manager_max, high, max, false, false)
                        .is_err()
                );
            }
        }
        assert!(
            classification(
                "foreign",
                14 << 30,
                16 << 30,
                14 << 30,
                16 << 30,
                false,
                false
            )
            .is_err()
        );
    }
}
