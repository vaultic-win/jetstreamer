//! Fixed private assembly/final-verification capacity contracts.
use crate::evidence;
use anyhow::{Context, Result, ensure};
use serde_json::Value;
#[derive(Clone, Copy)]
pub(super) enum Kind {
    Assembly,
    Verification,
}
pub(super) fn validate(c: &Value, tool: &str, now: u64, kind: Kind) -> Result<(u64, u64)> {
    let (schema, only_flag, launch_flag, additional) = match kind {
        Kind::Assembly => (
            "jetstreamer-private223-assembly-capacity-v1",
            "assembly_only_no_replay",
            "assembly_launch_authorized",
            (160u64 << 30) + (32 << 20),
        ),
        Kind::Verification => (
            "jetstreamer-private223-verification-capacity-v1",
            "verification_only_no_replay",
            "verification_launch_authorized",
            (160u64 << 30) + (256 << 20),
        ),
    };
    ensure!(
        evidence::is_sha(tool)
            && c["schema"] == schema
            && c["self_sha256"] == tool
            && c[only_flag] == true
            && c["all_live_growth_and_century_floor_protected"] == true
            && c["first_epoch"] == 201
            && c["last_epoch"] == 300
            && c["new_resource_samples"] == 0
            && c["additional_bytes"] == additional
            && c["recorded_unix_seconds"]
                .as_u64()
                .is_some_and(|t| t <= now && now - t <= 900),
        "private 223 capacity identity/scope/freshness differs"
    );
    for key in [
        "replay_launch_authorized",
        "local_retirement_authorized",
        "publication_authorized",
        "r2_mutations",
        launch_flag,
        "source_completion_authenticated",
    ] {
        ensure!(
            c[key] == false,
            "capacity claimed unexpected authority:{key}"
        );
    }
    let floor = c["minimum_free_bytes"]
        .as_u64()
        .filter(|n| *n >= 2_000_000_000_000)
        .context("private 223 protected disk floor")?;
    let required = floor
        .checked_add(additional)
        .context("private 223 capacity disk overflow")?;
    ensure!(
        c["required_initial_free_bytes"] == required
            && c["sampled_available_bytes"]
                .as_u64()
                .is_some_and(|n| n >= required)
            && c["actual_available_bytes"]
                .as_u64()
                .is_some_and(|n| n >= required),
        "private 223 capacity disk does not fit"
    );
    let mut required_memory = 0;
    for key in ["memory_before", "memory_after"] {
        let m = &c[key];
        let total = m["host_total_memory_bytes"]
            .as_u64()
            .filter(|n| *n > 0)
            .context("private 223 total memory")?;
        let growth = m["protected_existing_memory_growth_bytes"]
            .as_u64()
            .context("private 223 protected memory growth")?;
        let required = total
            .div_ceil(10)
            .checked_add(growth)
            .and_then(|n| n.checked_add(64 << 30))
            .context("private 223 memory overflow")?;
        ensure!(
            m["candidate_memory_max_bytes"] == (64u64 << 30)
                && m["memory_target_percent"] == 90
                && m["minimum_available_memory_bytes"] == required
                && m["sampled_available_memory_bytes"]
                    .as_u64()
                    .is_some_and(|n| n >= required)
                && m["actual_available_memory_bytes"]
                    .as_u64()
                    .is_some_and(|n| n >= required),
            "private 223 candidate memory does not fit"
        );
        required_memory = required_memory.max(required);
    }
    Ok((floor, required_memory))
}
