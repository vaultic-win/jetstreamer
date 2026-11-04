//! Conservative next-candidate budget from accepted bytes. Never admission.
//! Keep the five original growth claims and subtract only already consumed
//! physical bytes from the live private 141 whole-root stop.
use super::*;

const GIB: u64 = 1 << 30;
const PRIVATE_PEAK: u64 = 512 * GIB;
const RANGES: [&str; 5] = ["152-153", "155-156", "191-194", "183-184", "185-185"];

fn arithmetic(base: u64, consumed: u64, free: u64) -> Result<Value> {
    ensure!(consumed <= PRIVATE_PEAK, "live 141 stop already exceeded");
    let remaining = PRIVATE_PEAK - consumed;
    let protected = base.checked_add(remaining).context("protection overflow")?;
    let required = protected
        .checked_add(PRIVATE_PEAK)
        .context("candidate budget overflow")?;
    Ok(json!({"five_production_protected_bytes":base,
        "live141_whole_root_stop_bytes":PRIVATE_PEAK,
        "live141_consumed_physical_lower_bound_bytes":consumed,
        "live141_remaining_growth_bytes":remaining,
        "all_current_protected_bytes":protected,
        "candidate_incremental_whole_root_stop_bytes":PRIVATE_PEAK,
        "required_initial_free_bytes":required,"sampled_free_bytes":free,
        "disk_deficit_bytes":required.saturating_sub(free),
        "disk_headroom_bytes":free.saturating_sub(required),
        "prospective_disk_fit":free>=required,
        "resource_budget_kind":"bounded-qualification-stop-not-adopted-full-epoch-peak"}))
}

fn checked(p: &Plan, o: &Value) -> Result<Value> {
    ensure!(
        original141::capped_enabled(p),
        "capped 141 profile not active"
    );
    let invocation = original141::invocation(p).context("private 141 identity")?;
    let launch = bound_json(
        original141::launch_binding(p).context("private 141 launch")?,
        false,
    )?;
    ensure!(
        launch["invocation_id"] == invocation,
        "private 141 launch identity differs"
    );
    let admission: Bound = serde_json::from_value(launch["admission"].clone())?;
    let base = bound_json(&admission, false)?;
    ensure!(
        base["schema"] == "jetstreamer-original141-root-admission-v2"
            && base["epoch"] == 141
            && base["admitted"] == true
            && base["candidate_incremental_peak_bytes"] == PRIVATE_PEAK
            && base["existing_growth_claims_protected"] == true
            && base["century_floor_protected"] == true,
        "private 141 admission has foreign growth basis"
    );
    let rows = o["replays"]
        .as_array()
        .context("production observations missing")?;
    ensure!(
        rows.len() == RANGES.len(),
        "five production growth basis changed"
    );
    let mut growth = serde_json::Map::new();
    for range in RANGES {
        let matching: Vec<_> = rows.iter().filter(|r| r["range"] == range).collect();
        ensure!(matching.len() == 1, "production range missing/duplicated");
        let row = matching[0];
        let owner = &base["cpu_budget"]["units"][range];
        ensure!(
            row["invocation_binding_stable"] == true
                && row["producer_after"]["invocation_id"] == owner["invocation_id"]
                && owner["invocation_id"].is_string()
                && row["producer_after"]["unit"] == owner["unit"]
                && row["producer_after"]["active_state"] == "active"
                && row["producer_after"]["sub_state"] == "running"
                && row["producer_after"]["restarts"] == 0,
            "production growth owner changed"
        );
        let claim = if matches!(range, "183-184" | "185-185") {
            768 * GIB
        } else {
            let prior = &base["growth_extension"]["ranges"][range];
            ensure!(
                prior["requested_claim_bytes"] == 512 * GIB,
                "unreviewed prior growth claim"
            );
            let maximum = prior["maximum_observed_scratch_bytes"]
                .as_u64()
                .context("prior maximum missing")?
                .max(
                    row["conservative_observed_physical_bytes"]
                        .as_u64()
                        .context("current scratch missing")?,
                );
            let jet = prior["maximum_verified_jet_bytes"]
                .as_u64()
                .context("prior verified jet missing")?;
            let formula = maximum
                .checked_mul(2)
                .and_then(|n| jet.checked_mul(2).and_then(|j| n.checked_add(j)))
                .context("growth formula overflow")?;
            ensure!(
                formula <= 512 * GIB,
                "current scratch requires a larger production claim"
            );
            growth.insert(range.into(),json!({"maximum_observed_scratch_bytes":maximum,
                "maximum_verified_jet_bytes":jet,"formula_minimum_bytes":formula,"requested_claim_bytes":512*GIB}));
            512 * GIB
        };
        growth.entry(range).or_insert(json!({"requested_claim_bytes":claim,"basis":"unchanged conservative cold-replay claim"}));
    }
    let private: Vec<_> = o["diagnostic_replays"]
        .as_array()
        .context("private observations missing")?
        .iter()
        .filter(|r| r["status"] == "observed")
        .filter_map(|r| r.get("observation"))
        .filter(|r| {
            r["producer_after"]["active_state"] == "active"
                && r["producer_after"]["sub_state"] == "running"
        })
        .collect();
    ensure!(private.len() == 1, "private growth census changed");
    let private = private[0];
    ensure!(
        private["invocation_binding_stable"] == true
            && private["producer_after"]["invocation_id"] == invocation
            && private["producer_after"]["restarts"] == 0
            && private["range"] == "141",
        "private 141 growth owner changed"
    );
    let consumed = private["scratch_pass_1"]["physical_bytes"]
        .as_u64()
        .context("first scratch pass missing")?
        .min(
            private["scratch_pass_2"]["physical_bytes"]
                .as_u64()
                .context("second scratch pass missing")?,
        );
    let floor = base["century_floor_bytes"]
        .as_u64()
        .context("century floor missing")?;
    let formula = growth
        .values()
        .try_fold(floor, |sum, v| {
            sum.checked_add(
                v["requested_claim_bytes"]
                    .as_u64()
                    .context("growth bytes missing")?,
            )
            .context("growth sum overflow")
        })?
        .checked_add(32 * GIB)
        .context("growth margin overflow")?;
    let protected = base["required_guard_minimum_free_bytes"]
        .as_u64()
        .context("protected baseline missing")?
        .max(formula);
    let free = o["filesystem"]["conservative_available_bytes"]
        .as_u64()
        .context("free disk missing")?;
    let mut result = arithmetic(protected, consumed, free)?;
    result["initial141_admission"] = serde_json::to_value(&admission)?;
    result["production_growth"] = json!(growth);
    result["century_floor_bytes"] = json!(floor);
    result["basis"] = json!(
        "Retains prior five producer reservations and maxima. Uses smaller of two scratch measurements as consumed bytes; archive/indices excluded from consumption credit, so their remaining growth stays protected. No claims or live guards changed."
    );
    Ok(result)
}

pub(super) fn report(p: &Plan, o: &Value) -> Value {
    if !original141::capped_enabled(p) {
        return Value::Null;
    }
    let mut result = match checked(p, o) {
        Ok(v) => v,
        Err(e) => json!({"valid":false,"limiting_gate":e.to_string()}),
    };
    if result.get("valid").is_none() {
        result["valid"] = json!(true);
    }
    result["schema"] = json!("jetstreamer-horizon-capped186-budget-v2");
    result["admission_eligible"] = json!(false);
    result["replay_launch_authorized"] = json!(false);
    result["new_resource_samples"] = json!(0);
    result["full_cold_epoch_peak_qualified"] = json!(false);
    result["next_action"] = json!(
        "Recheck current growth maxima, actual guards, latest century floor and live resource envelope during fresh admission. If disk does not fit, qualify verified cold offload or a separately bounded resource experiment; never subtract live 141 remaining growth or lower the memory-selected concurrency target."
    );
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "root exact sealed 1456 plan and accepted observer; immutable evidence reads only, no sampling"]
    fn actual_accepted1456_budget_preserves_all_live_growth() {
        let plan = Bound {
            path: "/var/lib/jetstreamer/horizon-routine-plan-101-200-20261023T145600Z-controller-rebind-capped141-repair185-repair183-upload144-census141-boundaries-native141-all-retry-public160-timed-scans-upload198-v1/cycle-plan.json".into(),
            sha256: "958b13b102042acd0adfb259fa5390a03540b44a31e16eed81427463f8308d36".into(),
        };
        let p: Plan = serde_json::from_value(bound_json(&plan, true).unwrap()).unwrap();
        let completion = Bound {
            path: "/var/lib/jetstreamer/horizon-routine-cycles-101-200-v2/20261023T145600Z-controller-rebind-capped141-repair185-repair183-upload144-census141-boundaries-native141-all-retry-public160-timed-scans-upload198-v1/completion.json".into(),
            sha256: "f902ce62ed19b40a6c27ac2a156b5cb2ede23437d99ff3bd932194fd324fee5f".into(),
        };
        let c = bound_json(&completion, false).unwrap();
        let observer: Bound = serde_json::from_value(c["observer"].clone()).unwrap();
        let o = bound_json(&observer, false).unwrap();
        let b = checked(&p, &o).unwrap();
        assert_eq!(b["five_production_protected_bytes"], 3_572_465_819_078u64);
        assert_eq!(b["live141_remaining_growth_bytes"], 531_032_023_040u64);
        assert_eq!(b["disk_deficit_bytes"], 477_952_441_798u64);
        assert_eq!(b["prospective_disk_fit"], false);
        for range in RANGES {
            assert!(
                b["production_growth"][range]["requested_claim_bytes"]
                    .as_u64()
                    .unwrap()
                    > 0
            );
        }
    }
    #[test]
    fn full_candidate_counts_live141_remaining_growth_and_does_not_double_count_consumed_bytes() {
        let base = 3_572_465_819_078;
        let consumed = 18_723_790_848;
        let free = 4_175_301_214_208;
        let b = arithmetic(base, consumed, free).unwrap();
        assert_eq!(b["live141_remaining_growth_bytes"], PRIVATE_PEAK - consumed);
        assert_eq!(
            b["required_initial_free_bytes"],
            base + 2 * PRIVATE_PEAK - consumed
        );
        assert_eq!(b["prospective_disk_fit"], false);
        assert_eq!(b["disk_deficit_bytes"], 477952441798u64);
    }
    #[test]
    fn zero_full_and_overrun_consumption_never_erase_older_claims_or_wrap() {
        let base = 3_572_465_819_078;
        assert_eq!(
            arithmetic(base, 0, 0).unwrap()["all_current_protected_bytes"],
            base + PRIVATE_PEAK
        );
        assert_eq!(
            arithmetic(base, PRIVATE_PEAK, 0).unwrap()["all_current_protected_bytes"],
            base
        );
        assert!(arithmetic(base, PRIVATE_PEAK + 1, 0).is_err());
        assert!(arithmetic(u64::MAX, 0, 0).is_err());
        let exact = arithmetic(base, 0, base + 2 * PRIVATE_PEAK).unwrap();
        assert_eq!(exact["prospective_disk_fit"], true);
        assert_eq!(exact["disk_deficit_bytes"], 0);
        assert_eq!(exact["disk_headroom_bytes"], 0);
    }
}
