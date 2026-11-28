//! Native current allocation route. Serialized declarations choose a route but
//! cannot supply realized bytes. Only held, freshly checked descriptors do so.
use super::*;
use std::time::{Duration, Instant};

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Request {
    pub schema: String,
}
pub(super) fn shape(p: &Plan) -> Result<()> {
    terminal169::shape(p)?;
    completed167::route_shape(p)?;
    if retry167::selected(p) {
        return retry167::shape(p);
    }
    if retry170::selected(p) {
        return retry170::shape(p);
    }
    if let Some(r) = &p.current_allocation {
        ensure!(
            r.schema
                == if terminal169::selected(p) {
                    terminal169::SCHEMA
                } else {
                    "horizon-current-allocation-request-v1"
                }
                && p.epoch == 170
                && p.attempt == "local3retry3"
                && p.existing_preparation.is_none()
                && p.retry3.is_some()
                && p.data_fulfillment.is_some()
                && p.resident_memory
                    .as_ref()
                    .is_some_and(|r| r.admission_only_capture),
            "current allocation is restricted to exact fresh170 admission"
        );
    }
    Ok(())
}

fn declaration(v: &Value, p: &Plan, r: &Review, fleet: &Value, at: u64) -> Result<()> {
    let t = v["recorded_unix_seconds"]
        .as_u64()
        .context("allocation declaration clock")?;
    ensure!(
        v["schema"]
            == if terminal167::selected(p) || retry170::selected(p) {
                completed167::working_set_schema(p)
            } else if terminal169::selected(p) {
                "horizon-retry3-terminal169-working-set-v3"
            } else {
                "horizon-retry3-concurrent-working-set-v2"
            }
            && v["allocation_mode"] == "native-common-window"
            && v["native_preparer_image"] == IMAGE
            && v["owner"] == "/root"
            && v["fleet"] == serde_json::to_value(&p.fleet)?
            && t <= at
            && at - t <= 120
            && v["immutable_raw_guard_floor_bytes"] == terminal169::floor(p)
            && v["retained_promises_released_bytes"] == 0
            && v["forecast_offloads_credited_bytes"] == 0
            && v["unrelated_growth_margin_bytes"] == 10u64 << 30,
        "exact fresh v2 native declaration required"
    );
    completed167::declaration(v, p)?;
    retry167::declaration(v, p)?;
    retry170::declaration(v, p)?;
    let rows = v["lanes"].as_array().context("declared native lane set")?;
    ensure!(rows.len() == 4, "exact complete four-lane declaration");
    let peers: Vec<_> = ["actual_executing_replays", "actual_active_bootstraps"]
        .iter()
        .flat_map(|k| fleet[*k].as_array().into_iter().flatten())
        .collect();
    if terminal169::selected(p) {
        let request = p
            .resident_memory
            .as_ref()
            .context("terminal resident request")?;
        terminal169::memory_scope(request, p.epoch)?;
        let expected_peers: BTreeSet<u64> = if retry167::selected(p) {
            BTreeSet::from([166])
        } else if terminal166::selected(p) {
            BTreeSet::new()
        } else if terminal167::selected(p) {
            BTreeSet::from([166])
        } else {
            BTreeSet::from([166, 167])
        };
        ensure!(
            peers.len() == expected_peers.len()
                && peers
                    .iter()
                    .map(|r| r["epoch"].as_u64().unwrap_or(0))
                    .collect::<BTreeSet<_>>()
                    == expected_peers,
            "exact166/167 live fleet required"
        );
        let terminal = request.terminal169.as_ref().context("terminal request")?;
        ensure!(
            v["additive_data_booking"] == serde_json::to_value(&terminal.additive_data_booking)?
                && v["complete_DATA_bytes"] == terminal169::data(p),
            "terminal route additive DATA declaration missing"
        );
    } else {
        ensure!(peers.len() == 3, "exact complete three-peer fleet");
    }
    let mut seen = BTreeSet::new();
    for row in rows {
        let e = row["epoch"].as_u64().context("declared epoch")?;
        ensure!(
            [166, 167, 169, 170].contains(&e) && seen.insert(e),
            "foreign/duplicate declaration"
        );
        // These remain authenticated historical baselines, never current credit.
        let baseline = row["retained_lane_physical_bytes"]
            .as_u64()
            .context("historical baseline")?;
        ensure!(
            baseline > 0
                && baseline < ROOT_CAP
                && row["remaining_growth_bytes"]
                    == retry170::root_cap(p, e).max(retry167::root_cap(p, e)) - baseline,
            "historical baseline equation"
        );
        if e == p.epoch {
            ensure!(
                row["state"] == "candidate"
                    && row["producer_unit"] == p.producer_unit
                    && baseline == r.retained_lane_physical_bytes,
                "candidate original ledger differs"
            );
        } else if e == 166 && terminal166::selected(p) {
            terminal166::declaration(
                row,
                p.resident_memory
                    .as_ref()
                    .and_then(|r| r.terminal166.as_ref())
                    .context("terminal166 request")?,
            )?;
        } else if e == 167 && terminal167::selected(p) {
            terminal167::declaration(
                row,
                p.resident_memory
                    .as_ref()
                    .and_then(|r| r.terminal167.as_ref())
                    .context("terminal167 request")?,
            )?;
        } else if e == 169 && terminal169::selected(p) {
            terminal169::declaration(
                row,
                p.resident_memory
                    .as_ref()
                    .and_then(|r| r.terminal169.as_ref())
                    .context("terminal169 request")?,
            )?;
        } else if e == 170 && retry167::selected(p) {
            terminal170::declaration(
                row,
                p.resident_memory
                    .as_ref()
                    .and_then(|r| r.terminal170.as_ref())
                    .context("terminal170 request")?,
            )?;
        } else {
            let peer = peers
                .iter()
                .find(|x| x["epoch"] == e)
                .context("missing actual peer")?;
            ensure!(
                row["state"] == "active"
                    && row["producer_unit"] == peer["unit"]["Id"]
                    && row["invocation_id"] == peer["unit"]["InvocationID"],
                "declared peer identity differs"
            );
            let admission = bound(&serde_json::from_value::<Bound>(peer["admission"].clone())?)?;
            ensure!(
                admission["producer_unit"] == row["producer_unit"]
                    && admission["producer_invocation_id"] == row["invocation_id"]
                    && admission["fresh_admission_passed"] == true,
                "genuine peer admission differs"
            );
            let prep = bound(&serde_json::from_value::<Bound>(
                admission["fresh_native_Rust_preparation"].clone(),
            )?)?;
            retry3::peer_preparation(e, row, &prep, baseline)?;
        }
    }
    ensure!(
        seen == BTreeSet::from([166, 167, 169, 170]),
        "complete exact lane set required"
    );
    Ok(())
}

#[cfg(test)]
fn fit(
    raw: u64,
    fulfilled: u64,
    totals: &BTreeMap<u64, u64>,
    staging: u64,
    extra: u64,
) -> Result<Value> {
    fit_with_floor(
        raw,
        fulfilled,
        totals,
        staging,
        extra,
        current_budget::CURRENT_FLOOR,
    )
}
fn fit_with_floor(
    raw: u64,
    fulfilled: u64,
    totals: &BTreeMap<u64, u64>,
    staging: u64,
    extra: u64,
    raw_floor: u64,
) -> Result<Value> {
    fit_with_caps(
        raw,
        fulfilled,
        totals,
        staging,
        extra,
        raw_floor,
        0,
        &BTreeMap::from([
            (166, ROOT_CAP),
            (167, ROOT_CAP),
            (169, ROOT_CAP),
            (170, ROOT_CAP),
        ]),
    )
}
// Keep the independently charged floor, growth, cap and staging quantities explicit.
#[allow(clippy::too_many_arguments)]
fn fit_with_caps(
    raw: u64,
    fulfilled: u64,
    totals: &BTreeMap<u64, u64>,
    staging: u64,
    extra: u64,
    raw_floor: u64,
    booked_growth: u64,
    caps: &BTreeMap<u64, u64>,
) -> Result<Value> {
    ensure!(
        raw_floor == current_budget::CURRENT_FLOOR
            || raw_floor == terminal169::RAW_FLOOR
            || raw_floor == completed167::RAW_FLOOR
            || ([retry167::RAW_FLOOR, retry170::RAW_FLOOR].contains(&raw_floor)
                && caps.get(&167) == Some(&retry167::CANDIDATE_CAP)
                && booked_growth == retry167::CAP_DELTA),
        "unknown fit floor"
    );
    ensure!(
        totals.keys().copied().collect::<BTreeSet<_>>() == BTreeSet::from([166, 167, 169, 170])
            && caps.keys().copied().collect::<BTreeSet<_>>()
                == BTreeSet::from([166, 167, 169, 170])
            && totals.iter().all(|(epoch, n)| *n > 0 && *n < caps[epoch])
            && fulfilled > 0
            && fulfilled <= 241_482_399_744
            && staging >= 64 << 20,
        "complete native allocation/floor/staging required"
    );
    let growth = totals.iter().try_fold(0u64, |sum, (epoch, n)| {
        sum.checked_add(caps[epoch] - n)
            .context("native growth overflow")
    })?;
    let growth_outside_floor = growth
        .checked_sub(booked_growth)
        .context("booked growth exceeds complete remaining growth")?;
    let floor = raw_floor
        .checked_sub(fulfilled)
        .context("native floor underflow")?;
    let required = floor
        .checked_add(growth_outside_floor)
        .and_then(|v| v.checked_add(staging))
        .and_then(|v| v.checked_add(10 << 30))
        .and_then(|v| v.checked_add(extra))
        .context("native fit overflow")?;
    ensure!(
        raw >= required,
        "current complete native working sets do not fit: free={raw}, required={required}"
    );
    let mut point = json!({"conservative_raw_available_bytes":raw,"fulfilled_existing_DATA_bytes":fulfilled,
        "immutable_effective_guard_floor_bytes":floor,"complete_concurrent_remaining_growth_bytes":growth,
        "fresh_subtree_overlap_bytes":staging,"additional_growth_not_covered_by_existing_promise_bytes":extra,
        "unrelated_growth_margin_bytes":10u64<<30,"required_raw_available_bytes":required,
        "headroom_after_full_growth_bytes":raw-required,"forecast_offloads_credited_bytes":0,
        "resource_credit_bytes":0,"promise_ending_bytes":0});
    if booked_growth > 0 {
        point["booked_growth_inside_guard_floor_bytes"] = json!(booked_growth);
        point["remaining_growth_outside_guard_floor_bytes"] = json!(growth_outside_floor);
    }
    Ok(point)
}

pub(super) fn observe(r: &Review, p: &Plan, fleet: &Value, initial_free: u64) -> Result<Value> {
    shape(p)?;
    ensure!(
        p.current_allocation.is_some(),
        "explicit native opt-in required"
    );
    let started = now()?;
    let declaration_binding = &p
        .retry3
        .as_ref()
        .context("retry3 request")?
        .concurrent_working_set;
    let declared = bound(declaration_binding)?;
    declaration(&declared, p, r, fleet, started)?;
    let request = p.resident_memory.as_ref().context("exact peers")?;
    let terminal166_before = request
        .terminal166
        .as_ref()
        .map(terminal166::endpoint)
        .transpose()?;
    let terminal170_before = request
        .terminal170
        .as_ref()
        .map(terminal170::endpoint)
        .transpose()?;
    let completed167_output_before = completed167::observe(p)?;
    let terminal167_before = request
        .terminal167
        .as_ref()
        .map(terminal167::endpoint)
        .transpose()?;
    let terminal_before = request
        .terminal169
        .as_ref()
        .map(terminal169::endpoint)
        .transpose()?;
    let before = resident_memory::allocation_endpoint(request, p, fleet)?;
    let roles: Vec<_> = [166, 167, 169, 170]
        .into_iter()
        .map(|epoch| {
            Ok(allocation_window::Role {
                epoch,
                root: PathBuf::from(profile(epoch)?.lane),
            })
        })
        .collect::<Result<_>>()?;
    let discovery: allocation_window::Discovery = allocation_window::discover(
        &roles,
        &allocation_window::Limits {
            total_files: 32768,
            entries_per_role: 1_000_000,
            directories_per_role: 1024,
            timeout: Duration::from_secs(30),
            minimum_file_bytes: 64 << 10,
            // Actual169 account changed after79seconds and was soon collected.
            // Prefer an older subset; full held-descriptor mutation gates remain.
            minimum_age_seconds: 3600,
        },
    )?;
    let witness = p.data_fulfillment.as_ref().context("original witnesses")?;
    prelaunch_data::authenticate(witness)?;
    let mut held = None;
    let clock = Instant::now();
    // Original witness descriptors exist before inner peer capture starts. The
    // returned peer handles remain held over the outer witness midpoint.
    let original = data_fulfillment::observe_preparation_with(
        &serde_json::to_value(&witness.contract)?,
        Path::new("/home/sol"),
        initial_free,
        &data_fulfillment::Bound {
            path: witness.runtime.path.clone(),
            sha256: witness.runtime.sha256.clone(),
        },
        || {
            held = Some(allocation_window::capture(
                Path::new("/home/sol"),
                &discovery.selections,
                Duration::from_secs(30),
                || Ok(()),
            )?);
            Ok(())
        },
    )?;
    let held = held.context("native descriptors were not captured")?;
    held.revalidate()?;
    held.require_minimum_age(now()?, 3600)?;
    ensure!(
        clock.elapsed() <= Duration::from_secs(30),
        "combined native allocation window expired"
    );
    prelaunch_data::freshness(&original.evidence, now()?)?;
    let after = resident_memory::allocation_endpoint(request, p, fleet)?;
    let terminal167_after = request
        .terminal167
        .as_ref()
        .map(terminal167::endpoint)
        .transpose()?;
    ensure!(
        terminal167_before == terminal167_after,
        "terminal167 changed across shared allocation window"
    );
    let terminal_after = request
        .terminal169
        .as_ref()
        .map(terminal169::endpoint)
        .transpose()?;
    ensure!(
        terminal_before == terminal_after,
        "terminal169 changed across shared allocation window"
    );
    let completed167_output_after = completed167::observe(p)?;
    completed167::equal_reports(p, &completed167_output_before, &completed167_output_after)?;
    ensure!(
        before == after,
        "peer process/image/guard changed across shared allocation window"
    );
    held.revalidate()?;
    ensure!(
        held.current_unique_bytes()[&p.epoch] <= r.retained_lane_physical_bytes,
        "candidate subset exceeds separately captured complete candidate ledger"
    );
    let conservative = initial_free
        .min(original.conservative_available_bytes)
        .min(held.conservative_available_bytes());
    let point = if retry167::selected(p) {
        retry167::fit(
            conservative,
            original.fulfilled_bytes,
            held.current_unique_bytes(),
            r.fresh_subtree_overlap_booked_bytes,
            r.additional_growth_not_covered_by_existing_promise_bytes,
        )?
    } else if retry170::selected(p) {
        fit_with_caps(
            conservative,
            original.fulfilled_bytes,
            held.current_unique_bytes(),
            r.fresh_subtree_overlap_booked_bytes,
            r.additional_growth_not_covered_by_existing_promise_bytes,
            retry170::RAW_FLOOR,
            retry167::CAP_DELTA,
            &BTreeMap::from([
                (166, ROOT_CAP),
                (167, retry167::CANDIDATE_CAP),
                (169, ROOT_CAP),
                (170, ROOT_CAP),
            ]),
        )?
    } else {
        fit_with_floor(
            conservative,
            original.fulfilled_bytes,
            held.current_unique_bytes(),
            r.fresh_subtree_overlap_booked_bytes,
            r.additional_growth_not_covered_by_existing_promise_bytes,
            terminal169::floor(p),
        )?
    };
    let (fb, fm, fa) = held.free_points();
    let free_json = |v: &allocation_window::FreePoint| json!({"device":v.device,"mount_id":v.mount_id,"available_bytes":v.available_bytes});
    let facts:Vec<_>=held.files().iter().map(|v|json!({"epoch":v.epoch,"path":v.path,"identity":v.identity,"birth":v.birth,"mount_id":v.mount_id})).collect();
    let terminal166_after = request
        .terminal166
        .as_ref()
        .map(terminal166::endpoint)
        .transpose()?;
    terminal166::equal_endpoints(&terminal166_before, &terminal166_after)?;
    let terminal170_after = request
        .terminal170
        .as_ref()
        .map(terminal170::endpoint)
        .transpose()?;
    ensure!(
        terminal170_before == terminal170_after,
        "terminal170 changed across shared allocation window"
    );
    let completed = now()?;
    ensure!(
        started <= completed && completed - started <= 120,
        "native preparation transaction expired"
    );
    Ok(
        json!({"schema":"horizon-current-shared-allocation-accounting-v1","current_fit":point,
        "completed167_output_before":completed167_output_before,"completed167_output_after":completed167_output_after,
        "terminal166_before":terminal166_before,"terminal166_after":terminal166_after,"terminal167_before":terminal167_before,"terminal167_after":terminal167_after,"terminal169_before":terminal_before,"terminal169_after":terminal_after,"terminal170_before":terminal170_before,"terminal170_after":terminal170_after,"complete_DATA_bytes":terminal169::data(p),"additional_holding_DATA_bytes":if terminal169::selected(p){terminal169::EXTRA_DATA}else{0},"declaration":declaration_binding,"native_preparer_image":IMAGE,"native_process_id":std::process::id(),
        "started_unix_seconds":started,"completed_unix_seconds":completed,"original_witness_observation":original.evidence,
        "peer_identity_before":before,"peer_identity_after":after,"native_files":facts,
        "current_unique_bytes":held.current_unique_bytes(),"peer_capture_elapsed_millis":held.elapsed().as_millis(),
        "peer_free_before":free_json(fb),"peer_free_midpoint":free_json(fm),"peer_free_after":free_json(fa),
        "discovery":{"inspected_entries":discovery.inspected_entries,"opened_directories":discovery.opened_directories,
            "skipped_nonqualifying":discovery.skipped_nonqualifying,"traversal_truncated":discovery.traversal_truncated},
        "peer_handles_retained_across_original_witness_midpoint":true,"peer_handles_revalidated_after_original_witness_capture":true,
        "historical_baseline_used_as_current_credit":false,"resource_credit_bytes":0,"promise_ending_bytes":0}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn actual_declaration_fixture() -> (Plan, Review, Value, Value) {
        let actual: Value =
            serde_json::from_str(include_str!("dep_0a865083b7b5_actual-three-owner-native.json")).unwrap();
        let mut p = crate::tests::plan();
        p.epoch = 170;
        p.attempt = "local3retry3".into();
        p.producer_unit = "horizon-qualify-170-replacement-local3retry3-20261110-v1.service".into();
        let r = crate::tests::review(&p);
        let mut fleet = json!({"actual_executing_replays":[],"actual_active_bootstraps":[]});
        let mut rows = vec![
            json!({"epoch":170,"state":"candidate","producer_unit":p.producer_unit,
            "retained_lane_physical_bytes":r.retained_lane_physical_bytes,
            "remaining_growth_bytes":ROOT_CAP-r.retained_lane_physical_bytes}),
        ];
        for key in ["active_replay_invocations", "active_bootstrap_invocations"] {
            for original in actual["event"][key].as_array().unwrap() {
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
                let baseline = prep["actual_full_lane_ledger"]["physical_bytes"]
                    .as_u64()
                    .unwrap();
                rows.push(json!({"epoch":peer["epoch"],"state":"active","producer_unit":unit,
                    "invocation_id":peer["unit"]["InvocationID"],"retained_lane_physical_bytes":baseline,
                    "remaining_growth_bytes":ROOT_CAP-baseline}));
                fleet["actual_executing_replays"]
                    .as_array_mut()
                    .unwrap()
                    .push(peer);
            }
        }
        let v = json!({"schema":"horizon-retry3-concurrent-working-set-v2","allocation_mode":"native-common-window",
            "native_preparer_image":IMAGE,"owner":"/root","fleet":p.fleet,"recorded_unix_seconds":1000,
            "immutable_raw_guard_floor_bytes":current_budget::CURRENT_FLOOR,"retained_promises_released_bytes":0,
            "forecast_offloads_credited_bytes":0,"unrelated_growth_margin_bytes":10u64<<30,"lanes":rows});
        (p, r, fleet, v)
    }
    #[test]
    fn actual_three_peer_declaration_is_authenticated_before_native_capture() {
        let (p, r, f, v) = actual_declaration_fixture();
        declaration(&v, &p, &r, &f, 1000).unwrap();
        for key in [
            "schema",
            "allocation_mode",
            "native_preparer_image",
            "owner",
        ] {
            let mut bad = v.clone();
            bad[key] = json!("unknown");
            assert!(declaration(&bad, &p, &r, &f, 1000).is_err());
        }
        assert!(declaration(&v, &p, &r, &f, 1121).is_err());
        assert!(declaration(&v, &p, &r, &f, 999).is_err());
        let mut bad = v.clone();
        bad["lanes"].as_array_mut().unwrap().pop();
        assert!(declaration(&bad, &p, &r, &f, 1000).is_err());
        let mut bad = v.clone();
        bad["lanes"][1]["invocation_id"] = json!("f".repeat(32));
        assert!(declaration(&bad, &p, &r, &f, 1000).is_err());
        let mut bad = v.clone();
        bad["lanes"][1]["retained_lane_physical_bytes"] = json!(1);
        bad["lanes"][1]["remaining_growth_bytes"] = json!(ROOT_CAP - 1);
        assert!(declaration(&bad, &p, &r, &f, 1000).is_err());
        let mut bad = f.clone();
        bad["actual_executing_replays"]
            .as_array_mut()
            .unwrap()
            .pop();
        assert!(declaration(&v, &p, &r, &bad, 1000).is_err());
    }
    fn totals() -> BTreeMap<u64, u64> {
        BTreeMap::from([
            (166, 200 << 30),
            (167, 240 << 30),
            (169, 230 << 30),
            (170, 120 << 30),
        ])
    }
    #[test]
    fn exact_current_fit_and_one_byte_failure_keep_all_growth_and_margins() {
        let t = totals();
        let r = fit(u64::MAX, 241_482_399_744, &t, 64 << 20, 7).unwrap();
        let required = r["required_raw_available_bytes"].as_u64().unwrap();
        fit(required, 241_482_399_744, &t, 64 << 20, 7).unwrap();
        assert!(fit(required - 1, 241_482_399_744, &t, 64 << 20, 7).is_err());
        assert!(fit(required, 241_482_399_744, &t, 64 << 20, 8).is_err());
        assert_eq!(
            r["complete_concurrent_remaining_growth_bytes"],
            4 * ROOT_CAP - t.values().sum::<u64>()
        );
        assert_eq!(r["resource_credit_bytes"], 0);
    }
    #[test]
    fn retry6_170_fit_retains_additional166_cap_at_exact_byte_boundary() {
        let t=totals();
        let caps=BTreeMap::from([(166,ROOT_CAP),(167,retry167::CANDIDATE_CAP),(169,ROOT_CAP),(170,ROOT_CAP)]);
        let old=fit_with_caps(u64::MAX,241_482_399_744,&t,64<<20,0,retry167::RAW_FLOOR,retry167::CAP_DELTA,&caps).unwrap();
        let required=old["required_raw_available_bytes"].as_u64().unwrap()+ROOT_CAP;
        fit_with_caps(required,241_482_399_744,&t,64<<20,0,retry170::RAW_FLOOR,retry167::CAP_DELTA,&caps).unwrap();
        assert!(fit_with_caps(required-1,241_482_399_744,&t,64<<20,0,retry170::RAW_FLOOR,retry167::CAP_DELTA,&caps).is_err());
    }
    #[test]
    fn retry170_fit_counts_retained167_cap_booking_once() {
        let t = totals();
        let caps = BTreeMap::from([
            (166, ROOT_CAP),
            (167, retry167::CANDIDATE_CAP),
            (169, ROOT_CAP),
            (170, ROOT_CAP),
        ]);
        let fulfilled = 241_482_399_744;
        let staging = 64 << 20;
        let extra = 7;
        let point = fit_with_caps(
            u64::MAX,
            fulfilled,
            &t,
            staging,
            extra,
            retry167::RAW_FLOOR,
            retry167::CAP_DELTA,
            &caps,
        )
        .unwrap();
        let required = point["required_raw_available_bytes"].as_u64().unwrap();
        let growth = caps.values().sum::<u64>() - t.values().sum::<u64>();
        assert_eq!(point["complete_concurrent_remaining_growth_bytes"], growth);
        assert_eq!(
            point["booked_growth_inside_guard_floor_bytes"],
            retry167::CAP_DELTA
        );
        assert_eq!(
            point["remaining_growth_outside_guard_floor_bytes"],
            growth - retry167::CAP_DELTA
        );
        assert_eq!(
            required,
            retry167::RAW_FLOOR - fulfilled + growth - retry167::CAP_DELTA
                + staging
                + (10u64 << 30)
                + extra
        );
        fit_with_caps(
            required,
            fulfilled,
            &t,
            staging,
            extra,
            retry167::RAW_FLOOR,
            retry167::CAP_DELTA,
            &caps,
        )
        .unwrap();
        assert!(
            fit_with_caps(
                required - 1,
                fulfilled,
                &t,
                staging,
                extra,
                retry167::RAW_FLOOR,
                retry167::CAP_DELTA,
                &caps
            )
            .is_err()
        );
        assert!(
            fit_with_caps(
                required,
                fulfilled,
                &t,
                staging,
                extra,
                retry167::RAW_FLOOR,
                retry167::CAP_DELTA - 1,
                &caps
            )
            .is_err()
        );
        assert_eq!(point["resource_credit_bytes"], 0);
        assert_eq!(point["promise_ending_bytes"], 0);
    }
    #[test]
    fn missing_foreign_zero_and_over_cap_allocations_fail() {
        let mut t = totals();
        t.remove(&166);
        assert!(fit(u64::MAX, 1, &t, 64 << 20, 0).is_err());
        t.insert(168, 1);
        assert!(fit(u64::MAX, 1, &t, 64 << 20, 0).is_err());
        for n in [0, ROOT_CAP, ROOT_CAP + 1] {
            let mut t = totals();
            t.insert(166, n);
            assert!(fit(u64::MAX, 1, &t, 64 << 20, 0).is_err());
        }
        assert!(fit(u64::MAX, 241_482_399_745, &totals(), 64 << 20, 0).is_err());
        assert!(fit(u64::MAX, 1, &totals(), (64 << 20) - 1, 0).is_err());
        assert!(fit(u64::MAX, 1, &totals(), 64 << 20, u64::MAX).is_err());
    }
    #[test]
    fn current_route_cannot_open_other_attempts_or_legacy_plans() {
        let mut p = crate::tests::plan();
        p.current_allocation = Some(Request {
            schema: "horizon-current-allocation-request-v1".into(),
        });
        assert!(shape(&p).is_err());
        p.epoch = 170;
        p.attempt = "local3retry3".into();
        assert!(shape(&p).is_err());
        p.current_allocation = None;
        shape(&p).unwrap();
    }
    #[test]
    fn terminal169_keeps_four_roots_but_requires_two_live_peers_and_genuine_history() {
        let (mut p, r, mut f, mut v) = actual_declaration_fixture();
        p.resident_memory = Some(crate::terminal169::tests::request());
        p.current_allocation = Some(Request {
            schema: terminal169::SCHEMA.into(),
        });
        let rows = f["actual_executing_replays"].as_array_mut().unwrap();
        rows.retain(|r| r["epoch"] != 169);
        v["schema"] = json!("horizon-retry3-terminal169-working-set-v3");
        v["immutable_raw_guard_floor_bytes"] = json!(terminal169::RAW_FLOOR);
        v["complete_DATA_bytes"] = json!(terminal169::COMPLETE_DATA);
        v["additive_data_booking"] = json!(terminal169::exact().additive_data_booking);
        let t = v["lanes"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|r| r["epoch"] == 169)
            .unwrap();
        t["state"] = json!("terminal-retained");
        t["terminal_event"] = json!(terminal169::exact().terminal_event);
        t["retained_memory_promise_bytes"] = json!(73_014_444_032u64);
        t["memory_resident_deduction_bytes"] = json!(0);
        t["promise_ending_bytes"] = json!(0);
        declaration(&v, &p, &r, &f, 1000).unwrap();
        for (key, value) in [
            ("state", json!("active")),
            ("invocation_id", json!("f".repeat(32))),
            ("memory_resident_deduction_bytes", json!(1)),
            ("retained_memory_promise_bytes", json!(0)),
        ] {
            let mut bad = v.clone();
            let t = bad["lanes"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|r| r["epoch"] == 169)
                .unwrap();
            t[key] = value;
            assert!(declaration(&bad, &p, &r, &f, 1000).is_err(), "{key}");
        }
        let mut bad = v.clone();
        bad["lanes"]
            .as_array_mut()
            .unwrap()
            .retain(|r| r["epoch"] != 169);
        assert!(declaration(&bad, &p, &r, &f, 1000).is_err());
        let mut bad = v.clone();
        bad["complete_DATA_bytes"] = json!(current_budget::CURRENT_DATA);
        assert!(declaration(&bad, &p, &r, &f, 1000).is_err());
        assert!(declaration(&v, &p, &r, &f, 1121).is_err());
    }
    #[test]
    fn terminal_fit_preserves_all_four_future_growths_and_adds_exact_four_gib() {
        let t = totals();
        let legacy = fit(u64::MAX, 241_482_399_744, &t, 64 << 20, 7).unwrap();
        let new = fit_with_floor(
            u64::MAX,
            241_482_399_744,
            &t,
            64 << 20,
            7,
            terminal169::RAW_FLOOR,
        )
        .unwrap();
        let need = new["required_raw_available_bytes"].as_u64().unwrap();
        assert_eq!(
            need,
            legacy["required_raw_available_bytes"].as_u64().unwrap() + terminal169::EXTRA_DATA
        );
        assert_eq!(
            new["complete_concurrent_remaining_growth_bytes"],
            4 * ROOT_CAP - t.values().sum::<u64>()
        );
        fit_with_floor(
            need,
            241_482_399_744,
            &t,
            64 << 20,
            7,
            terminal169::RAW_FLOOR,
        )
        .unwrap();
        assert!(
            fit_with_floor(
                need - 1,
                241_482_399_744,
                &t,
                64 << 20,
                7,
                terminal169::RAW_FLOOR
            )
            .is_err()
        );
        let mut missing = t;
        missing.remove(&169);
        assert!(
            fit_with_floor(u64::MAX, 1, &missing, 64 << 20, 0, terminal169::RAW_FLOOR).is_err()
        );
    }

    #[test]
    fn completed167_full_declaration_authenticates_retained_roots_and_new_metadata() {
        let (mut p, r, mut f, mut v) = actual_declaration_fixture();
        let mut resident = crate::terminal169::tests::request();
        resident.terminal167 = Some(terminal167::exact());
        resident
            .owners
            .retain(|o| serde_json::to_value(o).unwrap()["epoch"] == 166);
        p.resident_memory = Some(resident);
        p.current_allocation = Some(Request {
            schema: terminal169::SCHEMA.into(),
        });
        f["actual_executing_replays"]
            .as_array_mut()
            .unwrap()
            .retain(|r| r["epoch"] == 166);
        v["schema"] = json!(completed167::WORKING_SET_SCHEMA);
        v["immutable_raw_guard_floor_bytes"] = json!(completed167::RAW_FLOOR);
        v["complete_DATA_bytes"] = json!(completed167::COMPLETE_DATA);
        v["additive_data_booking"] = json!(terminal169::exact().additive_data_booking);
        v["completed167_output_review"] = completed167::review_binding();
        v["completed167_retained_output_cap_bytes"] = json!(completed_output_report::RETAINED_CAP);
        for (epoch, event) in [
            (167, terminal167::exact().terminal_event),
            (169, terminal169::exact().terminal_event),
        ] {
            let row = v["lanes"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|r| r["epoch"] == epoch)
                .unwrap();
            row["state"] = json!("terminal-retained");
            row["terminal_event"] = json!(event);
            row["retained_memory_promise_bytes"] = json!(73_014_444_032u64);
            row["memory_resident_deduction_bytes"] = json!(0);
            row["promise_ending_bytes"] = json!(0);
        }
        declaration(&v, &p, &r, &f, 1000).unwrap();
        for key in [
            "completed167_output_review",
            "completed167_retained_output_cap_bytes",
            "additive_data_booking",
        ] {
            let mut bad = v.clone();
            bad[key] = Value::Null;
            assert!(declaration(&bad, &p, &r, &f, 1000).is_err(), "{key}");
        }
        for (key, value) in [
            ("complete_DATA_bytes", json!(terminal169::COMPLETE_DATA)),
            (
                "immutable_raw_guard_floor_bytes",
                json!(terminal169::RAW_FLOOR),
            ),
            ("schema", json!("horizon-retry3-terminal169-working-set-v3")),
        ] {
            let mut bad = v.clone();
            bad[key] = value;
            assert!(declaration(&bad, &p, &r, &f, 1000).is_err(), "{key}");
        }
        let mut bad = v;
        bad["lanes"]
            .as_array_mut()
            .unwrap()
            .retain(|r| r["epoch"] != 167);
        assert!(declaration(&bad, &p, &r, &f, 1000).is_err());
    }
    #[test]
    fn completed167_fit_adds_retained_cap_and_rejects_one_byte_shortfall() {
        let t = totals();
        let old = fit_with_floor(
            u64::MAX,
            241_482_399_744,
            &t,
            64 << 20,
            7,
            terminal169::RAW_FLOOR,
        )
        .unwrap();
        let new = fit_with_floor(
            u64::MAX,
            241_482_399_744,
            &t,
            64 << 20,
            7,
            completed167::RAW_FLOOR,
        )
        .unwrap();
        let required = new["required_raw_available_bytes"].as_u64().unwrap();
        assert_eq!(
            required,
            old["required_raw_available_bytes"].as_u64().unwrap()
                + completed_output_report::RETAINED_CAP
        );
        assert_eq!(
            new["complete_concurrent_remaining_growth_bytes"],
            old["complete_concurrent_remaining_growth_bytes"]
        );
        assert_eq!(new["resource_credit_bytes"], 0);
        fit_with_floor(
            required,
            241_482_399_744,
            &t,
            64 << 20,
            7,
            completed167::RAW_FLOOR,
        )
        .unwrap();
        assert!(
            fit_with_floor(
                required - 1,
                241_482_399_744,
                &t,
                64 << 20,
                7,
                completed167::RAW_FLOOR
            )
            .is_err()
        );
        assert!(
            fit_with_floor(
                u64::MAX,
                241_482_399_744,
                &t,
                64 << 20,
                7,
                completed167::RAW_FLOOR - 1
            )
            .is_err()
        );
    }
    fn zero166_declaration_fixture() -> (Plan, Review, Value, Value) {
        let (mut p, r, mut f, mut v) = actual_declaration_fixture();
        let mut resident = crate::terminal169::tests::request();
        resident.terminal167 = Some(terminal167::exact());
        resident.terminal166 = Some(terminal166::exact());
        resident.owners.clear();
        p.resident_memory = Some(resident);
        p.current_allocation = Some(Request {
            schema: terminal169::SCHEMA.into(),
        });
        f["actual_executing_replays"] = json!([]);
        f["actual_active_bootstraps"] = json!([]);
        v["schema"] = json!(completed167::ZERO166_WORKING_SET_SCHEMA);
        v["immutable_raw_guard_floor_bytes"] = json!(completed167::RAW_FLOOR);
        v["complete_DATA_bytes"] = json!(completed167::COMPLETE_DATA);
        v["additive_data_booking"] = json!(terminal169::exact().additive_data_booking);
        v["completed167_output_review"] = completed167::review_binding();
        v["completed167_retained_output_cap_bytes"] = json!(completed_output_report::RETAINED_CAP);
        for (epoch, event) in [
            (166, terminal166::exact().terminal_event),
            (167, terminal167::exact().terminal_event),
            (169, terminal169::exact().terminal_event),
        ] {
            let row = v["lanes"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|r| r["epoch"] == epoch)
                .unwrap();
            row["state"] = json!("terminal-retained");
            row["terminal_event"] = json!(event);
            row["retained_memory_promise_bytes"] = json!(73_014_444_032u64);
            row["memory_resident_deduction_bytes"] = json!(0);
            row["promise_ending_bytes"] = json!(0);
        }
        (p, r, f, v)
    }
    #[test]
    fn zero166_declaration_keeps_all_four_roots_and_authenticates_original_admissions() {
        let (p, r, f, v) = zero166_declaration_fixture();
        declaration(&v, &p, &r, &f, 1000).unwrap();
        for schema in [
            completed167::WORKING_SET_SCHEMA,
            "horizon-retry3-terminal169-working-set-v3",
        ] {
            let mut bad = v.clone();
            bad["schema"] = json!(schema);
            assert!(declaration(&bad, &p, &r, &f, 1000).is_err());
        }
        for epoch in [166, 167, 169, 170] {
            let mut bad = v.clone();
            bad["lanes"]
                .as_array_mut()
                .unwrap()
                .retain(|r| r["epoch"] != epoch);
            assert!(declaration(&bad, &p, &r, &f, 1000).is_err());
        }
        for (key, value) in [
            ("state", json!("active")),
            ("invocation_id", json!("f".repeat(32))),
            ("terminal_event", Value::Null),
            ("retained_memory_promise_bytes", json!(0)),
            ("memory_resident_deduction_bytes", json!(1)),
            ("promise_ending_bytes", json!(1)),
            ("remaining_growth_bytes", json!(0)),
            ("retained_lane_physical_bytes", json!(ROOT_CAP)),
        ] {
            let mut bad = v.clone();
            let row = bad["lanes"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|r| r["epoch"] == 166)
                .unwrap();
            row[key] = value;
            assert!(declaration(&bad, &p, &r, &f, 1000).is_err(), "{key}");
        }
        let mut bad = f.clone();
        bad["actual_executing_replays"] = json!([{"epoch":166}]);
        assert!(declaration(&v, &p, &r, &bad, 1000).is_err());
        for key in [
            "complete_DATA_bytes",
            "immutable_raw_guard_floor_bytes",
            "completed167_retained_output_cap_bytes",
        ] {
            let mut bad = v.clone();
            bad[key] = json!(bad[key].as_u64().unwrap() - 1);
            assert!(declaration(&bad, &p, &r, &f, 1000).is_err());
        }
    }
}
