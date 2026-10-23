//! Memory-only planning from one observer receipt; never admission authority.
use super::*;

type Census = BTreeMap<u64, (u64, u64)>;

fn census(row: &Value, suffix: &str) -> Result<Census> {
    let mut result = Census::new();
    for role in ["controller", "producer"] {
        let unit = &row[format!("{role}_{suffix}")];
        let report = &unit["rss"];
        ensure!(
            report["census_stable"] == true && report["error"].is_null(),
            "missing or unstable lane RSS census"
        );
        let processes = report["processes"].as_array().context("RSS processes")?;
        ensure!(
            !processes.is_empty() && processes.len() <= 65536,
            "RSS census size"
        );
        let mut local = Census::new();
        let mut sum = 0u64;
        for process in processes {
            let pid = process["pid"].as_u64().context("RSS PID")?;
            let start = process["start_ticks"].as_u64().context("RSS start")?;
            let rss = process["rss_bytes"].as_u64().context("RSS bytes")?;
            ensure!(pid > 0 && start > 0, "invalid RSS process identity");
            ensure!(
                local.insert(pid, (start, rss)).is_none(),
                "duplicate RSS PID"
            );
            sum = sum.checked_add(rss).context("RSS sum overflow")?;
            if let Some((old_start, old_rss)) = result.insert(pid, (start, rss)) {
                ensure!(old_start == start, "RSS PID reused between role reads");
                // Nested or identical controller/producer cgroups include the
                // same process. Count it once at the larger observed RSS.
                result.insert(pid, (start, rss.max(old_rss)));
            }
        }
        ensure!(
            report["aggregate_rss_bytes"].as_u64() == Some(sum),
            "RSS sum differs"
        );
    }
    Ok(result)
}

fn checked(o: &Value, live: usize, diagnostics: usize) -> Result<Value> {
    ensure!(
        diagnostics == 0,
        "active diagnostics need explicit RSS accounting"
    );
    let rows = o["replays"].as_array().context("memory lane census")?;
    ensure!(
        live > 0 && rows.len() == live && live <= 64,
        "memory lane count differs"
    );
    let mut processes = BTreeSet::new();
    let mut sum = 0u64;
    let mut largest = 0u64;
    for row in rows {
        ensure!(
            row["invocation_binding_stable"] == true,
            "unstable lane identity"
        );
        let before = census(row, "before")?;
        let after = census(row, "after")?;
        ensure!(
            before
                .iter()
                .map(|(pid, (start, _))| (pid, start))
                .eq(after.iter().map(|(pid, (start, _))| (pid, start))),
            "RSS process census changed across observation"
        );
        let mut lane = 0u64;
        for (pid, (start, rss)) in after {
            ensure!(
                processes.insert((pid, start)),
                "process belongs to two lanes"
            );
            lane = lane.checked_add(rss).context("lane RSS overflow")?;
        }
        ensure!(lane > 0, "empty lane RSS");
        sum = sum.checked_add(lane).context("fleet RSS overflow")?;
        largest = largest.max(lane);
    }
    let total = o["host_memory"]["total_kib"]
        .as_u64()
        .context("host memory total")?
        .checked_mul(1024)
        .context("host total overflow")?;
    let available = o["host_memory"]["conservative_available_kib"]
        .as_u64()
        .context("host available memory")?
        .checked_mul(1024)
        .context("host available overflow")?;
    let used = total
        .checked_sub(available)
        .context("host available exceeds total")?;
    // MemAvailable excludes reclaimable memory while RSS includes resident
    // mapped pages. If these accounting views do not reconcile, report the gap
    // rather than inventing negative non-lane usage or granting capacity.
    let non_lane = used
        .checked_sub(sum)
        .context("RSS exceeds effective host use; non-lane accounting unresolved")?;
    let maximum = o["lane_rss_history"]["100"]["maximum_observed_lane_rss_bytes"]
        .as_u64()
        .context("missing century100 RSS history")?;
    let reservation = maximum.checked_mul(3).context("RSS reservation overflow")? / 2;
    ensure!(
        maximum >= largest
            && o["lane_rss_history"]["100"]["reservation_ceiling_bytes"] == reservation,
        "invalid century RSS maximum or reservation"
    );
    let target = u64::try_from(u128::from(total) * 9 / 10)?;
    let marginal = sum.div_ceil(u64::try_from(live)?);
    let desired = target.saturating_sub(non_lane).div_ceil(marginal);
    Ok(
        json!({"valid":true,"target_percent":90,"desired_lanes":desired,
        "executing_lanes":live,"lane_gap":i128::from(desired)-i128::try_from(live)?,
        "host_total_bytes":total,"host_effective_used_bytes":used,
        "host_usage_basis":"total minus conservative MemAvailable; reclaimable cache excluded",
        "aggregate_lane_rss_bytes":sum,"non_lane_effective_used_bytes":non_lane,
        "marginal_lane_rss_bytes":marginal,"marginal_basis":"mean current lane RSS, rounded up",
        "century_maximum_observed_lane_rss_bytes":maximum,"reservation_ceiling_bytes":reservation,
        "target_used_bytes":target,"rounding":"ceil desired lane count toward target",
        "disk_or_cpu_used_to_lower_desired_count":false,"admission_authorized":false,
        "next_action":"Use fresh admission and qualified pressure relief for execution; beyond proven count add one experimental lane, then require a clean expanded sample."}),
    )
}

pub(super) fn report(o: &Value, live: usize, diagnostics: usize) -> Value {
    checked(o, live, diagnostics).unwrap_or_else(|error| json!({
        "valid":false,"target_percent":90,"executing_lanes":live,
        "limiting_gate":format!("{error:#}"),"admission_authorized":false,
        "next_action":"Resolve RSS/host accounting from the coordinated observer; retain prior qualified scheduling evidence and all live protections."}))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Value {
        let role = |pid, rss| {
            json!({"rss":{"census_stable":true,"error":null,
            "aggregate_rss_bytes":rss,"processes":[{"pid":pid,"start_ticks":10,"rss_bytes":rss}]}})
        };
        let a = role(1, 100 * 1024);
        let b = role(2, 100 * 1024);
        json!({"host_memory":{"total_kib":1000,"conservative_available_kib":700},
            "lane_rss_history":{"100":{"maximum_observed_lane_rss_bytes":100*1024,"reservation_ceiling_bytes":150*1024}},
            "replays":[
                {"invocation_binding_stable":true,"controller_before":a,"producer_before":a,"controller_after":a,"producer_after":a},
                {"invocation_binding_stable":true,"controller_before":b,"producer_before":b,"controller_after":b,"producer_after":b}]})
    }
    #[test]
    fn target_uses_memory_and_counts_shared_role_process_once() {
        let mut o = fixture();
        o["filesystem"] = json!({"conservative_available_bytes":0});
        let r = report(&o, 2, 0);
        assert_eq!(r["valid"], true);
        assert_eq!(r["aggregate_lane_rss_bytes"], 200 * 1024);
        assert_eq!(r["non_lane_effective_used_bytes"], 100 * 1024);
        assert_eq!(r["desired_lanes"], 8);
        assert_eq!(r["reservation_ceiling_bytes"], 150 * 1024);
        assert_eq!(r["admission_authorized"], false);
    }
    #[test]
    fn accounting_and_identity_gaps_never_create_a_target() {
        let mut o = fixture();
        o["replays"][0]["producer_after"]["rss"]["processes"][0]["start_ticks"] = json!(11);
        assert_eq!(report(&o, 2, 0)["valid"], false);
        let mut o = fixture();
        o["host_memory"]["conservative_available_kib"] = json!(900);
        assert_eq!(report(&o, 2, 0)["valid"], false);
        let mut o = fixture();
        o["lane_rss_history"] = Value::Null;
        assert_eq!(report(&o, 2, 0)["valid"], false);
        assert_eq!(report(&fixture(), 2, 1)["valid"], false);
    }
}
