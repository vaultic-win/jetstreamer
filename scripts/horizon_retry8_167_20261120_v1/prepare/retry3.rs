//! Fresh retry3 requires exact retry2 retirement and enough free space for full
//! concurrent future growth above the unchanged live guard floor.
use super::*;
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Request {
    pub stopped_event: Bound,
    pub concurrent_working_set: Bound,
}
fn selected(p: &Plan) -> bool {
    p.attempt == "local3retry3" || crate::retry4::selected(p) || crate::retry167::selected(p)
}
fn stopped(epoch: u64) -> Result<Value> {
    let rows: Vec<Value> = serde_json::from_str(include_str!(
        "../../horizon_retry7_167_20261119_v1/prepare/dep_b4d024aaefdc_retry2-stopped-profiles.json"
    ))?;
    rows.into_iter()
        .find(|r| r["epoch"] == epoch)
        .context("exact stopped retry2 profile")
}
pub(super) fn shape(p: &Plan, s: &Profile) -> Result<()> {
    if !selected(p) {
        ensure!(p.retry3.is_none(), "retry3 proof on foreign generation");
        return Ok(());
    }
    let r = p
        .retry3
        .as_ref()
        .context("retry3 stop and working-set proof required")?;
    let old = stopped(p.epoch)?;
    ensure!(
        [166, 167, 169, 170].contains(&p.epoch)
            && p.existing_preparation.is_none()
            && p.fresh_subtree
                == Path::new(s.lane).join(format!("replacement-{}-20261110-v1", p.attempt))
            && r.stopped_event.path
                == Path::new(&format!(
                    "/var/lib/jetstreamer/root1857-retry2-stop-evidence-20261113-v1/ORIGINAL_EPOCH{}_RESERVE_STOP_EVIDENCE.json",
                    p.epoch
                ))
            && r.stopped_event.sha256 == old["event_sha"],
        "exact fresh retry3 source and stopped lineage required"
    );
    for unit in [
        old["unit"].as_str().context("old producer")?.to_owned(),
        format!("{}.service", old["guard"].as_str().context("old guard")?),
        format!("{}.timer", old["guard"].as_str().context("old guard")?),
    ] {
        ensure!(
            p.closed_units.contains(&unit),
            "stopped retry2 producer/guard omitted"
        );
    }
    Ok(())
}
pub(super) fn retirement(p: &Plan, wrapper: &Value, c: &Value) -> Result<Value> {
    if !selected(p) {
        return Ok(Value::Null);
    }
    let req = p.retry3.as_ref().context("retry3 request")?;
    let old = stopped(p.epoch)?;
    let event = bound(&req.stopped_event)?;
    ensure!(
        event["epoch"] == p.epoch
            && event["original_claim"]["expected_producer_invocation_id"] == old["iid"]
            && event["original_invocation_children"] == json!([])
            && event["reason"] == "filesystem-floor"
            && event["all_original_promises_retained"] == true,
        "genuine stopped retry2 event differs"
    );
    let terminal_proof = crate::retirement_terminal::authenticate(p.epoch, wrapper, c)?;
    let retry4_lineage = crate::retry4::authenticate(p)?;
    ensure!(
        wrapper["owner"] == "/root"
            && wrapper["epoch"] == p.epoch
            && wrapper["completion"]["path"]
                == format!(
                    "/var/lib/jetstreamer/retry2-scratch-retirement-20261113-v1/epoch{}/completion.json",
                    p.epoch
                )
            && wrapper["scratch_empty"] == true
            && wrapper["scratch_root_preserved"] == true
            && wrapper["all_original_promises_retained"] == true
            && wrapper["reservation_ending_bytes"] == 0
            && wrapper["resource_credit_bytes"] == 0
            && wrapper["no_replay_launch_authority"] == true,
        "genuine completed retry2 scratch retirement required"
    );
    ensure!(
        c["schema"] == "jetstreamer-retry2-scratch-complete-v1"
            && c["basis"]["source"]["original_retry2_stop_event"]
                == serde_json::to_value(&req.stopped_event)?
            && c["basis"]["scratch_identity"]["inode"] == old["scratch_inode"]
            && c["basis"]["scratch_identity"]["device"] == 64512
            && c["scratch_empty"] == true
            && c["scratch_root_preserved"] == true
            && c["partial_archive_and_all_inputs_preserved"] == true
            && c["remote_mutations"] == false
            && c["r2_mutations"] == false
            && c["archive_deletion_authorized"] == false
            && c["replay_launch_authorized"] == false
            && c["resource_credit_bytes"] == 0
            && c["resource_promise_ending_authorized"] == false,
        "retry2 retirement scope, preservation or authority differs"
    );
    Ok(
        json!({"stop_event":req.stopped_event,"retirement":wrapper["completion"],"native_terminal_proof":terminal_proof,"new_attempt":p.attempt,"continuation_or_partial_reuse":false,"retry4_lineage":retry4_lineage}),
    )
}
fn n(v: &Value, k: &str) -> Result<u64> {
    v[k].as_u64()
        .with_context(|| format!("working-set integer {k}"))
}
pub(super) fn peer_preparation(epoch: u64, row: &Value, prep: &Value, retained: u64) -> Result<()> {
    ensure!([166, 167, 169, 170].contains(&epoch), "foreign peer epoch");
    let unit = row["producer_unit"]
        .as_str()
        .context("peer producer unit")?;
    let attempt = if unit
        == format!("horizon-qualify-{epoch}-replacement-local3retry3-20261110-v1.service")
    {
        "local3retry3"
    } else if epoch == 166 && unit == retry167::NEW_PEER_UNIT {
        "local3retry9"
    } else if epoch == 166
        && unit == "horizon-qualify-166-replacement-local3retry6-20261110-v1.service"
    {
        "local3retry6"
    } else {
        ensure!(
            epoch == 166
                && unit == "horizon-qualify-166-replacement-local3retry4-20261110-v1.service",
            "unknown peer generation"
        );
        "local3retry4"
    };
    let valid_baseline = if epoch == 166 && unit == retry167::NEW_PEER_UNIT {
        // The physical ledger measured the stopped standard lane. Charge the
        // independent lane's entire cap from its empty admission baseline.
        retained == 0
            && prep["independent_physical_cap_bytes"] == ROOT_CAP
            && prep["independent_worker_root"]
                == "/home/sol/.jetstreamer-private/epoch166-independent-cold-20261120-v1"
    } else {
        prep["actual_full_lane_ledger"]["physical_bytes"] == retained
    };
    ensure!(
        prep["epoch"] == epoch
            && prep["attempt"] == attempt
            && valid_baseline
            && prep["retry2_retirement"]["new_attempt"] == attempt,
        "peer retained baseline must come from genuine attempt-matched preparation"
    );
    Ok(())
}
fn forecast(
    v: &Value,
    r: &Review,
    p: &Plan,
    fleet: &Value,
    raw: u64,
    fulfilled: u64,
    at: u64,
) -> Result<Value> {
    let t = n(v, "recorded_unix_seconds")?;
    ensure!(
        v["schema"] == "horizon-retry3-concurrent-working-set-v1"
            && v["owner"] == "/root"
            && v["fleet"] == serde_json::to_value(&p.fleet)?
            && t <= at
            && at - t <= 120
            && v["immutable_raw_guard_floor_bytes"] == current_budget::CURRENT_FLOOR
            && v["retained_promises_released_bytes"] == 0
            && v["forecast_offloads_credited_bytes"] == 0,
        "fresh full concurrent growth forecast required"
    );
    let rows = v["lanes"].as_array().context("concurrent lanes")?;
    let mut seen = BTreeSet::new();
    let mut growth = 0u64;
    let mut candidate = false;
    for row in rows {
        let epoch = n(row, "epoch")?;
        ensure!(
            [166, 167, 169, 170].contains(&epoch) && seen.insert(epoch),
            "foreign/duplicate lane growth"
        );
        let retained = n(row, "retained_lane_physical_bytes")?;
        let remaining = n(row, "remaining_growth_bytes")?;
        ensure!(
            retained <= ROOT_CAP && remaining > 0 && remaining == ROOT_CAP - retained,
            "lane cap/growth differs"
        );
        if epoch == p.epoch {
            candidate = true;
            ensure!(
                retained == r.retained_lane_physical_bytes
                    && remaining == r.proposed_fresh_working_maximum_bytes
                    && row["producer_unit"] == p.producer_unit
                    && row["state"] == "candidate",
                "candidate full working set differs from exact slot ledger"
            );
        } else {
            // Entire remaining cap is reserved for a peer, never just recent rate.
            ensure!(
                remaining == ROOT_CAP - retained,
                "peer future growth underestimated"
            );
            let live = ["actual_executing_replays", "actual_active_bootstraps"]
                .iter()
                .any(|k| {
                    fleet[*k].as_array().is_some_and(|a| {
                        a.iter().any(|o| {
                            o["epoch"] == epoch
                                && o["unit"]["Id"] == row["producer_unit"]
                                && o["unit"]["InvocationID"] == row["invocation_id"]
                        })
                    })
                });
            ensure!(
                live && row["state"] == "active",
                "growth peer lacks genuine fleet identity"
            );
            let live_row = ["actual_executing_replays", "actual_active_bootstraps"]
                .iter()
                .flat_map(|k| fleet[*k].as_array().into_iter().flatten())
                .find(|o| o["epoch"] == epoch)
                .context("live peer record")?;
            let admission = bound(&serde_json::from_value::<Bound>(
                live_row["admission"].clone(),
            )?)?;
            ensure!(
                admission["producer_unit"] == row["producer_unit"]
                    && admission["producer_invocation_id"] == row["invocation_id"]
                    && admission["fresh_admission_passed"] == true,
                "actual peer admission identity differs"
            );
            let prep = bound(&serde_json::from_value::<Bound>(
                admission["fresh_native_Rust_preparation"].clone(),
            )?)?;
            peer_preparation(epoch, row, &prep, retained)?;
        }
        growth = growth
            .checked_add(remaining)
            .context("concurrent growth overflow")?;
    }
    ensure!(candidate, "candidate omitted from growth forecast");
    for key in ["actual_executing_replays", "actual_active_bootstraps"] {
        for peer in fleet[key]
            .as_array()
            .context("complete active peer list required")?
        {
            ensure!(
                seen.contains(&n(peer, "epoch")?),
                "active peer omitted from growth forecast"
            );
        }
    }
    let margin = n(v, "unrelated_growth_margin_bytes")?;
    ensure!(
        margin >= 10 << 30,
        "retained unrelated growth margin missing"
    );
    ensure!(
        fulfilled > 0 && fulfilled <= 241_482_399_744,
        "actual qualified DATA fulfillment required"
    );
    let floor = current_budget::CURRENT_FLOOR
        .checked_sub(fulfilled)
        .context("guard floor underflow")?;
    let required = floor
        .checked_add(growth)
        .and_then(|x| x.checked_add(r.fresh_subtree_overlap_booked_bytes))
        .and_then(|x| x.checked_add(margin))
        .context("working set total overflow")?;
    ensure!(
        raw >= required,
        "raw free space cannot sustain concurrent working sets above immutable guard floor"
    );
    Ok(
        json!({"conservative_raw_available_bytes":raw,"immutable_effective_guard_floor_bytes":floor,
        "complete_concurrent_remaining_growth_bytes":growth,"unrelated_growth_margin_bytes":margin,
        "fresh_subtree_overlap_bytes":r.fresh_subtree_overlap_booked_bytes,"required_raw_available_bytes":required,
        "headroom_after_full_growth_bytes":raw-required,"forecast_offloads_credited_bytes":0,"resource_credit_bytes":0}),
    )
}
pub(super) fn working_set(
    r: &Review,
    p: &Plan,
    fleet: &Value,
    accounting: &Value,
    raw: u64,
    at: u64,
) -> Result<Value> {
    if !selected(p) {
        return Ok(Value::Null);
    }
    let req = p.retry3.as_ref().context("retry3 request")?;
    let v = bound(&req.concurrent_working_set)?;
    let fit = &accounting["current_fit"];
    forecast(
        &v,
        r,
        p,
        fleet,
        raw.min(n(fit, "conservative_raw_available_bytes")?),
        n(fit, "fulfilled_existing_DATA_bytes")?,
        at,
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mixed_peer_preparation_rejects_crossed_attempt_and_baseline() {
        for epoch in [166, 167, 169, 170] {
            for attempt in ["local3retry3", "local3retry4", "local3retry6"] {
                let row = json!({"producer_unit":format!("horizon-qualify-{epoch}-replacement-{attempt}-20261110-v1.service")});
                let prep = json!({"epoch":epoch,"attempt":attempt,"actual_full_lane_ledger":{"physical_bytes":123},"retry2_retirement":{"new_attempt":attempt}});
                let allowed = attempt == "local3retry3" || epoch == 166;
                assert_eq!(peer_preparation(epoch, &row, &prep, 123).is_ok(), allowed);
                assert!(peer_preparation(epoch, &row, &prep, 124).is_err());
                for key in ["attempt", "new_attempt"] {
                    let mut bad = prep.clone();
                    if key == "attempt" {
                        bad[key] = json!("local3retry5");
                    } else {
                        bad["retry2_retirement"][key] = json!("local3retry5");
                    }
                    assert!(peer_preparation(epoch, &row, &bad, 123).is_err());
                }
            }
        }
    }
    #[test]
    fn actual_three_owner_forecast_retains_full_growth_and_one_byte_gate() {
        let actual: Value =
            serde_json::from_str(include_str!("../../horizon_retry7_167_20261119_v1/prepare/dep_05d3c4e05078_actual-three-owner-native.json")).unwrap();
        let (mut p, mut r, mut f, mut v) = fixture();
        p.epoch = 170;
        p.producer_unit = "horizon-qualify-170-replacement-local3retry3-20261110-v1.service".into();
        r.epoch = 170;
        v["lanes"][0]["epoch"] = json!(170);
        v["lanes"][0]["producer_unit"] = json!(p.producer_unit);
        for (event_key, fleet_key) in [
            ("active_replay_invocations", "actual_executing_replays"),
            ("active_bootstrap_invocations", "actual_active_bootstraps"),
        ] {
            for original in actual["event"][event_key].as_array().unwrap() {
                let mut peer = original.clone();
                let unit = original["unit"]["unit"].as_str().unwrap();
                peer["unit"] = actual["current"]["complete_metadata_unit_census"][unit].clone();
                let admission =
                    bound(&serde_json::from_value::<Bound>(peer["admission"].clone()).unwrap())
                        .unwrap();
                let prep = bound(
                    &serde_json::from_value::<Bound>(
                        admission["fresh_native_Rust_preparation"].clone(),
                    )
                    .unwrap(),
                )
                .unwrap();
                let retained = prep["actual_full_lane_ledger"]["physical_bytes"]
                    .as_u64()
                    .unwrap();
                v["lanes"].as_array_mut().unwrap().push(json!({"epoch":peer["epoch"],"state":"active","producer_unit":unit,"invocation_id":peer["unit"]["InvocationID"],"retained_lane_physical_bytes":retained,"remaining_growth_bytes":ROOT_CAP-retained}));
                f[fleet_key].as_array_mut().unwrap().push(peer);
            }
        }
        let fulfilled = 241_482_399_744;
        let fit = forecast(&v, &r, &p, &f, u64::MAX, fulfilled, 1000).unwrap();
        let required = fit["required_raw_available_bytes"].as_u64().unwrap();
        forecast(&v, &r, &p, &f, required, fulfilled, 1000).unwrap();
        assert!(forecast(&v, &r, &p, &f, required - 1, fulfilled, 1000).is_err());
        let mut omitted = v.clone();
        omitted["lanes"].as_array_mut().unwrap().pop();
        assert!(forecast(&omitted, &r, &p, &f, required, fulfilled, 1000).is_err());
        let mut crossed = v.clone();
        crossed["lanes"][3]["producer_unit"] =
            json!("horizon-qualify-166-replacement-local3retry3-20261110-v1.service");
        assert!(forecast(&crossed, &r, &p, &f, required, fulfilled, 1000).is_err());
    }
    fn fixture() -> (Plan, Review, Value, Value) {
        let mut p = crate::tests::plan();
        p.attempt = "local3retry3".into();
        p.producer_unit = "horizon-qualify-166-replacement-local3retry3-20261110-v1.service".into();
        p.guard_base = "horizon-guard-replacement-166-local3retry3-20261110-v1".into();
        p.fresh_subtree =
            Path::new(profile(166).unwrap().lane).join("replacement-local3retry3-20261110-v1");
        let old = stopped(166).unwrap();
        for unit in [
            old["unit"].as_str().unwrap().to_owned(),
            format!("{}.service", old["guard"].as_str().unwrap()),
            format!("{}.timer", old["guard"].as_str().unwrap()),
        ] {
            p.closed_units.push(unit);
        }
        p.retry3=Some(Request{stopped_event:Bound{path:"/var/lib/jetstreamer/root1857-retry2-stop-evidence-20261113-v1/ORIGINAL_EPOCH166_RESERVE_STOP_EVIDENCE.json".into(),sha256:old["event_sha"].as_str().unwrap().into()},concurrent_working_set:p.review.clone()});
        let mut r = crate::tests::review(&p);
        r.retained_lane_physical_bytes = 100 << 30;
        r.proposed_fresh_working_maximum_bytes = ROOT_CAP - r.retained_lane_physical_bytes;
        r.fresh_subtree_overlap_booked_bytes = 64 << 20;
        let f = json!({"actual_executing_replays":[],"actual_active_bootstraps":[]});
        let v = json!({"schema":"horizon-retry3-concurrent-working-set-v1","owner":"/root","fleet":p.fleet,"recorded_unix_seconds":1000,"immutable_raw_guard_floor_bytes":current_budget::CURRENT_FLOOR,"retained_promises_released_bytes":0,"forecast_offloads_credited_bytes":0,"unrelated_growth_margin_bytes":10u64<<30,"lanes":[{"epoch":166,"state":"candidate","producer_unit":p.producer_unit,"retained_lane_physical_bytes":r.retained_lane_physical_bytes,"remaining_growth_bytes":r.proposed_fresh_working_maximum_bytes}]});
        (p, r, f, v)
    }
    #[test]
    fn retry3_rejects_reuse_wrong_stop_and_old_generation_paths() {
        let (mut p, _, _, _) = fixture();
        shape(&p, profile(166).unwrap()).unwrap();
        p.existing_preparation = Some(p.review.clone());
        assert!(shape(&p, profile(166).unwrap()).is_err());
        p.existing_preparation = None;
        p.fresh_subtree =
            Path::new(profile(166).unwrap().lane).join("replacement-local3retry2-20261110-v1");
        assert!(shape(&p, profile(166).unwrap()).is_err());
        let (mut p, _, _, _) = fixture();
        p.retry3.as_mut().unwrap().stopped_event.sha256 = "a".repeat(64);
        assert!(shape(&p, profile(166).unwrap()).is_err());
    }
    #[test]
    fn full_growth_boundary_rejects_old_just_above_floor_admission() {
        let (p, r, f, v) = fixture();
        let fulfilled = 241_482_399_744;
        let effective = current_budget::CURRENT_FLOOR - fulfilled;
        let required = effective + r.proposed_fresh_working_maximum_bytes + (10 << 30) + (64 << 20);
        forecast(&v, &r, &p, &f, required, fulfilled, 1000).unwrap();
        assert!(forecast(&v, &r, &p, &f, required - 1, fulfilled, 1000).is_err());
        assert!(forecast(&v, &r, &p, &f, effective + (64 << 20), fulfilled, 1000).is_err());
        assert!(forecast(&v, &r, &p, &f, required, fulfilled, 1121).is_err());
    }
    #[test]
    fn growth_forecast_rejects_omitted_peer_duplicate_and_future_offload_credit() {
        let (p, r, mut f, v) = fixture();
        f["actual_active_bootstraps"] = json!([{"epoch":167}]);
        assert!(forecast(&v, &r, &p, &f, u64::MAX, 241_482_399_744, 1000).is_err());
        let (p, r, f, mut v) = fixture();
        v["forecast_offloads_credited_bytes"] = json!(1);
        assert!(forecast(&v, &r, &p, &f, u64::MAX, 241_482_399_744, 1000).is_err());
        v["forecast_offloads_credited_bytes"] = json!(0);
        let duplicate = v["lanes"][0].clone();
        v["lanes"].as_array_mut().unwrap().push(duplicate);
        assert!(forecast(&v, &r, &p, &f, u64::MAX, 241_482_399_744, 1000).is_err());
    }
}
