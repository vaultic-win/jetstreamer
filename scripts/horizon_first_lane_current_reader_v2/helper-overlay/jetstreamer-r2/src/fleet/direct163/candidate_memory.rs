//! New singleton scheduling allowance follows the accepted century RSS policy.
//! The parent cgroup hard limit is separate; baseline overhead is already charged.
use super::storage as f;
use anyhow::{Context, Result, ensure};
use horizon_original199_parent_memory::VerifiedParentMemory;
use horizon_original199_parent_memory::model::Bound;
use serde_json::{Value, json};
use std::collections::BTreeMap;
const HARD: u64 = 192 << 30;
const GUARD: u64 = 2 << 30;
const STOPPER: u64 = 512 << 20;
#[derive(Debug)]
pub struct Budget {
    value: Value,
}
impl Budget {
    pub fn evidence(&self) -> &Value {
        &self.value
    }
}
fn processes(v: &Value) -> Result<BTreeMap<u64, (u64, u64)>> {
    ensure!(
        v["census_stable"] == true && v["error"].is_null(),
        "century RSS process census unavailable"
    );
    let mut p = BTreeMap::new();
    let mut sum = 0u64;
    for r in v["processes"].as_array().context("RSS processes")? {
        let pid = f::n(r, "pid")?;
        let start = f::n(r, "start_ticks")?;
        let rss = f::n(r, "rss_bytes")?;
        ensure!(
            pid > 1 && start > 0 && p.insert(pid, (start, rss)).is_none(),
            "duplicate/invalid RSS process identity"
        );
        sum = sum.checked_add(rss).context("RSS sum overflow")?;
    }
    ensure!(
        sum == f::n(v, "aggregate_rss_bytes")?,
        "RSS aggregate mismatch"
    );
    Ok(p)
}
fn peak(history: &Value) -> Result<u64> {
    let e = &history["evidence"];
    ensure!(
        e["sum_of_process_high_water_marks_used"] == false
            && f::hex(
                e["producer_invocation_id"]
                    .as_str()
                    .context("RSS producer IID")?,
                32
            ),
        "invalid century RSS basis"
    );
    let range = e["range"].as_str().context("RSS epoch range")?;
    let bounds = range
        .split('-')
        .map(str::parse::<u64>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(
        !bounds.is_empty()
            && bounds.len() <= 2
            && bounds.iter().all(|n| *n >= 100 && *n <= 200)
            && bounds.first() <= bounds.last(),
        "RSS history outside current century"
    );
    let mut maximum = 0u64;
    for end in ["before", "after"] {
        let mut union = BTreeMap::new();
        for role in ["producer", "controller"] {
            for (pid, row) in processes(&e[format!("{role}_rss_{end}")])? {
                if let Some(prior) = union.insert(pid, row) {
                    ensure!(prior == row, "same PID has inconsistent RSS/start time");
                }
            }
        }
        let total = union.values().try_fold(0u64, |a, row| {
            a.checked_add(row.1).context("RSS union overflow")
        })?;
        maximum = maximum.max(total);
    }
    ensure!(
        maximum > 0 && maximum == f::n(history, "maximum_observed_lane_rss_bytes")?,
        "claimed maximum is not actual same-end process RSS"
    );
    Ok(maximum)
}
fn compose_values(baseline: u64, host: u64, maximum: u64) -> Result<Value> {
    let allowance = maximum
        .checked_mul(3)
        .context("RSS reservation multiplication overflow")?
        / 2;
    let extra = GUARD.checked_add(STOPPER).context("guard sum overflow")?;
    let scheduling = baseline
        .checked_add(allowance)
        .and_then(|n| n.checked_add(extra))
        .context("scheduling total overflow")?;
    let hard = baseline
        .checked_add(HARD)
        .and_then(|n| n.checked_add(extra))
        .context("hard exposure total overflow")?;
    ensure!(
        maximum > 0 && scheduling <= host,
        "fresh singleton scheduling promises do not fit"
    );
    Ok(
        json!({"schema":"epoch163-RSS-policy-candidate-memory-budget-v1","selected_existing_baseline_bytes":baseline,
        "century100_maximum_observed_lane_RSS_bytes":maximum,"parent_scheduling_allowance_bytes":allowance,
        "parent_hard_cgroup_limit_bytes":HARD,"guard_memory_bytes":GUARD,"failure_stop_memory_bytes":STOPPER,
        "candidate_scheduling_total_bytes":allowance+extra,"candidate_conservative_hard_exposure_bytes":HARD+extra,
        "total_scheduling_reserved_bytes":scheduling,"total_conservative_hard_exposure_bytes":hard,
        "scheduling_headroom_bytes":host-scheduling,"conservative_hard_exposure_fits":hard<=host,
        "host_total_bytes":host,"existing_nonlane_and_kernel_overhead_added_again_bytes":0,
        "old_parent_retirement_already_applied_by_typed_view":true,"new_extra_parent_retirement_bytes":0,
        "DATA_credit_bytes":0,"CPU_credit_micros":0,"replay_admission_authorized":false,
        "replay_launch_authorized":false,"full_current_DATA_CPU_VMA_floor_and_guard_admission_still_required":true}),
    )
}
pub fn compose(view: &VerifiedParentMemory) -> Result<Budget> {
    ensure!(
        view.selected_parent_retirement_bytes() == 192 << 30,
        "genuine original parent-only view required"
    );
    let observer: Bound =
        serde_json::from_value(view.evidence()["request"]["current"]["observer"].clone())?;
    let frame_bound: Bound =
        serde_json::from_value(view.evidence()["request"]["current"]["frame"].clone())?;
    let frame = f::json(&frame_bound)?;
    let unit = "jetstreamer-root-sweep-e163-singleton-20261104-v1-e163-163-lane-a-1.service";
    for end in ["before", "after"] {
        let row = &frame[format!("native_census_{end}")][unit];
        ensure!(
            !matches!(
                row["ActiveState"].as_str(),
                Some("active" | "activating" | "reloading" | "deactivating")
            ) && (row.is_null()
                || (row["MainPID"] == "0" && row["ControlPID"] == "0" && row["Job"] == "")),
            "candidate163 is already active/queued in baseline; adding it again would double count"
        );
    }
    let o = f::json(&observer)?;
    ensure!(
        o["schema"] == "jetstreamer-horizon-live-resource-sample-v2",
        "RSS observer schema differs"
    );
    let h = &o["lane_rss_history"]["100"];
    let maximum = peak(h)?;
    let expected = maximum.checked_mul(3).context("RSS ceiling overflow")? / 2;
    ensure!(
        f::n(h, "reservation_ceiling_bytes")? == expected,
        "observer RSS ceiling differs from exact 1.5 policy"
    );
    let host = f::n(&o["host_memory"], "total_kib")?
        .checked_mul(1024)
        .context("host total overflow")?;
    let mut value = compose_values(view.effective_total_bytes(), host, maximum)?;
    value["observer"] = json!(observer);
    value["unchanged_raw_total_bytes"] = json!(view.raw_total_bytes());
    value["parent_only_memory_evidence_serde_sha256"] =
        json!(f::sha(&serde_json::to_vec(view.evidence())?));
    Ok(Budget { value })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn current_policy_allowance_is_separate_from_larger_hard_stop() {
        let v = compose_values(400 << 30, 810902843392, 130056269824).unwrap();
        assert_eq!(v["parent_scheduling_allowance_bytes"], 195084404736u64);
        assert_eq!(v["parent_hard_cgroup_limit_bytes"], 206158430208u64);
        assert_eq!(v["candidate_scheduling_total_bytes"], 197768759296u64);
        assert_eq!(
            v["candidate_conservative_hard_exposure_bytes"],
            208842784768u64
        );
    }
    #[test]
    fn guard_and_fallback_are_charged_once_and_overhead_is_not_repeated() {
        let v = compose_values(500 << 30, 810902843392, 130056269824).unwrap();
        assert_eq!(
            v["total_scheduling_reserved_bytes"],
            (500u64 << 30) + 197768759296
        );
        assert_eq!(
            v["existing_nonlane_and_kernel_overhead_added_again_bytes"],
            0
        );
        assert_eq!(v["guard_memory_bytes"], 2u64 << 30);
        assert_eq!(v["failure_stop_memory_bytes"], 512u64 << 20);
        assert_eq!(v["new_extra_parent_retirement_bytes"], 0);
    }
    #[test]
    fn missing_overflow_or_nonfitting_rss_does_not_create_admission() {
        assert!(compose_values(1, 100, 0).is_err());
        assert!(compose_values(u64::MAX, 100, 1).is_err());
        assert!(compose_values(1, u64::MAX, u64::MAX).is_err());
        assert!(compose_values(900 << 30, 810902843392, 130056269824).is_err());
    }
    #[test]
    fn genuine_accepted_budget_above_resident_usage_target_keeps_physical_headroom() {
        let budget = compose_values(547954098176, 810902843392, 130056269824).unwrap();
        assert_eq!(budget["total_scheduling_reserved_bytes"], 745722857472u64);
        assert_eq!(budget["scheduling_headroom_bytes"], 65179985920u64);
        assert_eq!(
            budget["total_conservative_hard_exposure_bytes"],
            756796882944u64
        );
        assert_eq!(budget["conservative_hard_exposure_fits"], true);
        assert!(
            u128::from(budget["total_scheduling_reserved_bytes"].as_u64().unwrap())
                > u128::from(budget["host_total_bytes"].as_u64().unwrap()) * 90 / 100
        );
        assert_eq!(budget["candidate_scheduling_total_bytes"], 197768759296u64);
        assert_eq!(
            budget["candidate_conservative_hard_exposure_bytes"],
            208842784768u64
        );
    }
}
