//! Independently recompute admission arithmetic from the bound observation.
use super::*;

fn add(a: u64, b: u64) -> Result<u64> {
    a.checked_add(b).context("capacity overflow")
}
fn mul(a: u64, b: u64) -> Result<u64> {
    a.checked_mul(b).context("capacity overflow")
}
fn memory(
    total: u64,
    available: u64,
    retained_current: u64,
    non_lane: u64,
    ceiling: u64,
) -> Result<u64> {
    ensure!(
        MAX <= ceiling,
        "candidate exceeds century RSS reservation ceiling"
    );
    ensure!(
        add(non_lane, 5 * 1073741824)? <= HOST_RESERVE,
        "non-lane usage and guards exceed host reserve"
    );
    let obligation = add(add(4 * LIVE_MAX, MAX)?, add(HOST_RESERVE, CONTROL)?)?;
    ensure!(
        obligation <= total && retained_current <= 4 * LIVE_MAX,
        "hard memory obligations exceed host"
    );
    ensure!(
        available >= obligation - retained_current,
        "available memory cannot cover all remaining hard growth"
    );
    Ok(obligation)
}
pub(super) fn floor(rows: &Value) -> Result<u64> {
    let rows = rows.as_array().context("century census")?;
    ensure!(!rows.is_empty(), "no qualified century samples");
    let mut seen = BTreeSet::new();
    let mut sum = 0;
    for r in rows {
        let epoch = number(r, "epoch")?;
        ensure!(
            (200..=300).contains(&epoch) && seen.insert(epoch),
            "duplicate or foreign century epoch"
        );
        let length = number(r, "canonical_jet_bytes")?;
        ensure!(
            length > 0 && r["normal_full_plugin_and_remote_gates_accepted"] == true,
            "unqualified canonical length"
        );
        sum = add(sum, length)?;
    }
    Ok(mul(sum, 2)?.div_ceil(rows.len() as u64))
}
pub(super) fn validate(a: &Value, docs: &BTreeMap<String, Value>) -> Result<()> {
    let normalized = &docs["observer"];
    let obs = bound(&normalized["source_sample"])?;
    let fleet = bound(&docs["fleet"]["source_fleet"])?;
    ensure!(
        fleet["observer_receipt"] == normalized["source_sample"]["path"]
            && fleet["observer_sha256"] == normalized["source_sample"]["sha256"]
            && fleet["sampled_at_utc"] == obs["recorded_at_utc"],
        "fleet not bound to admission observation"
    );
    ensure!(
        obs["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && obs["cadence"]["routine_minimum_interval_enforced"] == true
            && number(&obs["cadence"], "observed_interval_seconds")? >= 1800,
        "not a clean cadence observation"
    );
    let rows = obs["replays"].as_array().context("observed replays")?;
    ensure!(
        rows.len() == 4
            && obs["diagnostic_replays"] == json!([])
            && obs["epoch203_ram_auxiliary"] == json!([]),
        "unbooked observer owners"
    );
    let mut current = 0;
    for o in &live::OWNERS {
        let r = rows
            .iter()
            .find(|r| r["range"] == format!("{}-{}", o.epoch, o.epoch))
            .context("missing observed live owner")?;
        ensure!(
            r["invocation_binding_stable"] == true
                && r["useful_work"]["sufficient_for_rates"] == true
                && r["useful_work"]["counter_resets"] == 0
                && r["useful_work"]["until_unix_seconds"] == a["observer_unix_seconds"],
            "unstable or mistimed replay observation"
        );
        for suffix in ["before", "after"] {
            for role in ["producer", "controller"] {
                let v = &r[format!("{role}_{suffix}")];
                ensure!(
                    v["unit"] == o.unit
                        && v["invocation_id"] == o.iid
                        && v["active_state"] == "active",
                    "observed owner changed"
                );
            }
        }
        for event in [
            "memory_events.max",
            "memory_events.oom",
            "memory_events.oom_kill",
            "memory_events.oom_group_kill",
        ] {
            ensure!(
                r["producer_cgroup_counter_delta"][event] == 0,
                "hard memory event during sample"
            );
        }
        let low = number(&r["producer_before"], "memory_current_bytes")?
            .min(number(&r["producer_after"], "memory_current_bytes")?);
        ensure!(low <= LIVE_MAX, "retained current exceeds hard cap");
        current = add(current, low)?;
    }
    let target = &fleet["memory_target"];
    ensure!(
        target["valid"] == true
            && target["executing_lanes"] == 4
            && target["desired_lanes"] == a["desired_replay_lanes"],
        "invalid fleet memory target"
    );
    let total = mul(number(&obs["host_memory"], "total_kib")?, 1024)?;
    let available = mul(
        number(&obs["host_memory"], "conservative_available_kib")?,
        1024,
    )?;
    let ceiling = number(&obs["lane_rss_history"]["200"], "reservation_ceiling_bytes")?;
    let obligation = memory(
        total,
        available,
        current,
        number(target, "non_lane_resident_planning_bytes")?,
        ceiling,
    )?;
    ensure!(
        a["host_memory_total_bytes"] == total
            && a["memory_obligation_after_bytes"] == obligation
            && target["host_total_bytes"] == total
            && target["reservation_ceiling_bytes"] == ceiling,
        "memory admission disagrees with native evidence"
    );
    let c = &docs["capacity"];
    ensure!(
        c["source_observer"] == normalized["source_sample"]
            && c["allocation_credit_taken_bytes"] == 0
            && c["retained_full_root_claims_bytes"] == 4 * CAP,
        "unbound disk booking or allocation credit"
    );
    let century = floor(&c["century_floor_census"])?;
    for r in c["century_floor_census"].as_array().unwrap() {
        // Main adjudicates heterogeneous historical verifier schemas; every
        // selected canonical size must retain digest-bound gate documents.
        for k in ["full_verification", "current_plugin", "remote_readback"] {
            bound(&r[k])?;
        }
    }
    let guards = c["guard_receipts"]
        .as_array()
        .context("current guard receipts")?;
    ensure!(guards.len() == 4, "missing guard owner");
    let clock = now()?;
    let mut inherited = RETAINED_ROOT_OBLIGATION;
    for o in &live::OWNERS {
        let entry = guards
            .iter()
            .find(|e| e["epoch"] == o.epoch)
            .context("guard owner absent")?;
        let g = bound(entry)?;
        let timestamp = number(&g, "recorded_unix_seconds")?;
        ensure!(
            timestamp <= clock && clock - timestamp <= 120,
            "stale/future guard receipt"
        );
        ensure!(
            g["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
                && g["producer_invocation_id"] == o.iid
                && g["producer_stop_enabled"] == true
                && g["guard_sha256"] == RETAINED_GUARD_SHA
                && g["maximum_root_physical_bytes"] == CAP
                && g["maximum_worker_vmas"] == 3500000,
            "guard envelope changed"
        );
        for k in [
            "trip_reason",
            "worker_observation_error",
            "root_physical_observation_error",
            "target_handoff_error",
            "canary_target_error",
        ] {
            ensure!(g.get(k) == Some(&Value::Null), "guard reported {k}");
        }
        let handoff = bound(&json!({"path":o.handoff,"sha256":o.handoff_sha}))?;
        ensure!(
            g["plan"] == handoff["guard_plan"]["path"]
                && g["plan_sha256"] == handoff["guard_plan"]["sha256"],
            "guard plan changed"
        );
        let plan = bound(&handoff["guard_plan"])?;
        ensure!(
            plan["minimum_free_bytes"] == g["minimum_free_bytes"]
                && plan["unit"] == o.unit
                && plan["invocation_id"] == o.iid,
            "guard ownership/floor differs"
        );
        inherited = inherited.max(number(&g, "minimum_free_bytes")?);
    }
    let guard_floor = inherited.max(add(4 * CAP, century)?);
    let required = add(guard_floor, CAP)?;
    ensure!(
        a["century_floor_bytes"] == century
            && a["guard_minimum_free_bytes"] == guard_floor
            && a["required_initial_free_bytes"] == required
            && a["observed_available_bytes"] == obs["filesystem"]["conservative_available_bytes"]
            && number(a, "observed_available_bytes")? >= required,
        "full disk growth and inherited floor do not fit"
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn memory_requires_full_hard_growth_and_host_reserve() {
        assert_eq!(
            memory(
                1212136964096,
                900000000000,
                600000000000,
                32464052224,
                223779342336
            )
            .unwrap(),
            1202496454656
        );
        assert!(
            memory(
                1200000000000,
                900000000000,
                600000000000,
                32464052224,
                223779342336
            )
            .is_err()
        );
        assert!(
            memory(
                1212136964096,
                600000000000,
                600000000000,
                32464052224,
                223779342336
            )
            .is_err()
        );
        assert!(
            memory(
                1212136964096,
                900000000000,
                600000000000,
                HOST_RESERVE,
                223779342336
            )
            .is_err()
        );
        assert!(
            memory(
                1212136964096,
                900000000000,
                600000000000,
                32464052224,
                MAX - 1
            )
            .is_err()
        );
    }
    #[test]
    fn century_floor_rejects_duplicate_foreign_and_unqualified_samples() {
        let a = json!({"epoch":201,"canonical_jet_bytes":100,"normal_full_plugin_and_remote_gates_accepted":true});
        let b = json!({"epoch":202,"canonical_jet_bytes":101,"normal_full_plugin_and_remote_gates_accepted":true});
        assert_eq!(floor(&json!([a, b])).unwrap(), 201);
        assert!(floor(&json!([a, a])).is_err());
        for (k, v) in [
            ("epoch", json!(301)),
            ("canonical_jet_bytes", json!(0)),
            ("normal_full_plugin_and_remote_gates_accepted", json!(false)),
        ] {
            let mut wrong = a.clone();
            wrong[k] = v;
            assert!(floor(&json!([wrong])).is_err());
        }
        assert!(floor(&json!([])).is_err());
    }
}
