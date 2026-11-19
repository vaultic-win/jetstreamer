//! Reuse one coordinated sample for the 201–300 resident-memory target.
//! Private long-running prefix qualifications are comparable replay lanes;
//! restore/repair/delivery stages consume RSS separately. No admission authority.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::collections::BTreeMap;

fn checked(o: &Value, ledger: &Value) -> Result<Value> {
    ensure!(
        ledger["first_epoch"] == 201
            && ledger["last_epoch"] == 300
            && ledger["sampled_at_utc"] == o["recorded_at_utc"],
        "memory target requires same-sample 201–300 fleet"
    );
    let mut owners = BTreeMap::new();
    for active in ledger["active"].as_array().context("fleet active census")? {
        let unit = if active["producer"].is_object() {
            &active["producer"]
        } else {
            &active["unit"]
        };
        let name = unit["Id"].as_str().context("active unit name")?;
        let iid = unit["InvocationID"].as_str().context("active invocation")?;
        ensure!(
            unit["ActiveState"] == "active"
                && unit["SubState"] == "running"
                && unit["NRestarts"] == "0",
            "memory owner not stable/running"
        );
        let comparable = matches!(
            active["phase"].as_str(),
            Some(
                "replay"
                    | "qualification"
                    | "private-known-root-prefix"
                    | "diagnostic-qualification"
            )
        );
        if let Some(old) = owners.insert(name.to_string(), (iid.to_string(), comparable)) {
            ensure!(
                old == (iid.to_string(), comparable),
                "duplicate memory owner conflicts"
            );
        }
    }
    let mut ordinary = Vec::new();
    let mut private = Vec::new();
    let mut seen = BTreeMap::new();
    let mut historical = Vec::new();
    let mut rows = o["replays"]
        .as_array()
        .context("ordinary memory census")?
        .iter()
        .collect::<Vec<_>>();
    if let Some(diagnostics) = o["diagnostic_replays"].as_array() {
        for diagnostic in diagnostics {
            if diagnostic["status"] == "observed" {
                rows.push(&diagnostic["observation"]);
            }
        }
    }
    for row in rows {
        let name = row["producer_after"]["unit"]
            .as_str()
            .context("observed memory owner")?;
        if !owners.contains_key(name) && super::fleet::terminal247::historical_row(ledger, row)? {
            ensure!(
                seen.insert(name.to_string(), ()).is_none(),
                "duplicate historical memory owner"
            );
            historical.push(name.to_string());
            private.push(row.clone());
            continue;
        }
        let Some((iid, comparable)) = owners.get(name) else {
            // No silently unaccounted observed owner, including a terminal race.
            anyhow::bail!("observed owner absent from current fleet: {name}");
        };
        ensure!(
            row["producer_after"]["invocation_id"] == *iid
                && row["invocation_binding_stable"] == true,
            "observed memory owner changed"
        );
        ensure!(
            seen.insert(name.to_string(), ()).is_none(),
            "duplicate memory observation"
        );
        if *comparable {
            ensure!(
                row["useful_work"]["sufficient_for_rates"] == true,
                "comparable lane lacks settled execution evidence"
            );
            // The generic calculator's diagnostic validation is also required
            // for these promoted qualifications, even though they are replay-sized.
            for role in ["controller", "producer"] {
                let before = &row[format!("{role}_before")];
                let after = &row[format!("{role}_after")];
                ensure!(
                    before["invocation_id"]
                        .as_str()
                        .is_some_and(|s| !s.is_empty())
                        && before["invocation_id"] == after["invocation_id"]
                        && before["restarts"] == 0
                        && after["restarts"] == 0
                        && before["active_state"] == "active"
                        && after["active_state"] == "active"
                        && before["sub_state"] == "running"
                        && after["sub_state"] == "running",
                    "settled memory owner unstable"
                );
            }
            ordinary.push(row.clone());
        } else {
            private.push(row.clone());
        }
    }
    ensure!(
        seen.len() == owners.len() + historical.len(),
        "active fleet owner missing from coordinated RSS telemetry"
    );
    let mut normalized = o.clone();
    normalized["replays"] = json!(ordinary);
    normalized["diagnostic_replays"] = json!(private);
    let mut report = jetstreamer_horizon_observe::routine_memory_target::report_for_century(
        &normalized,
        ordinary.len(),
        private.len(),
        200,
    );
    if report["valid"] == true {
        // The generic calculator calls every diagnostic a private lane. Here
        // comparable qualifications already live in `ordinary`; `private`
        // contains only restore/delivery/finalization owners. Preserve their
        // resident charge while removing their credit toward replay throughput.
        let desired = report["desired_production_lanes"]
            .as_u64()
            .context("replay target")?;
        let non_replay = report["aggregate_private_lane_rss_bytes"]
            .as_u64()
            .context("non-replay RSS")?;
        let overhead = report["non_lane_resident_planning_bytes"]
            .as_u64()
            .context("host overhead")?;
        report["desired_lanes"] = json!(desired);
        report["executing_lanes"] = json!(ordinary.len());
        report["executing_private_lanes"] = json!(0);
        report["lane_gap"] = json!(i128::from(desired) - i128::try_from(ordinary.len())?);
        report["non_replay_owner_count"] = json!(private.len());
        report["non_replay_resident_bytes"] = json!(non_replay);
        report["host_overhead_resident_bytes"] = json!(overhead);
        report["non_lane_resident_planning_bytes"] = json!(
            overhead
                .checked_add(non_replay)
                .context("non-lane RSS overflow")?
        );
        report["aggregate_lane_rss_bytes"] = report["aggregate_production_lane_rss_bytes"].clone();
        report["aggregate_private_lane_rss_bytes"] = json!(0);
    }
    report["sampled_at_utc"] = o["recorded_at_utc"].clone();
    report["owner_census"] = json!(owners.keys().collect::<Vec<_>>());
    report["historical_non_replay_owner_census"] = json!(historical);
    report["historical_rss_released"] = json!(false);
    report["qualification_replays_in_marginal_average"] = json!(true);
    Ok(report)
}

pub(super) fn report(o: &Value, ledger: &Value) -> Value {
    checked(o, ledger).unwrap_or_else(|e| json!({"valid":false,"target_percent":90,
        "admission_authorized":false,"limiting_gate":format!("{e:#}"),
        "next_action":"Account every live replay, qualification and delivery owner in the same coordinated RSS sample; preserve all healthy work."}))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn proven_terminal_transition_retains_historical_rss_and_raw_sample() {
        let (mut o, mut ledger) = fixture();
        let unit = super::super::fleet::terminal247::UNIT;
        let iid = super::super::fleet::terminal247::IID;
        super::super::fleet::terminal247::test_historical_ledger(&mut ledger);
        o["recorded_at_utc"] = ledger["sampled_at_utc"].clone();
        for role in [
            "controller_before",
            "controller_after",
            "producer_before",
            "producer_after",
        ] {
            o["diagnostic_replays"][0]["observation"][role]["unit"] = json!(unit);
            o["diagnostic_replays"][0]["observation"][role]["invocation_id"] = json!(iid);
        }
        o["diagnostic_replays"][0]["observation"]["range"] = json!("247-247");
        o["diagnostic_replays"][0]["observation"]["post_replay_finalization"] = json!(true);
        o["diagnostic_replays"][0]["observation"]["resource_only"] = json!(true);
        ledger["active"].as_array_mut().unwrap().remove(0);
        let original = o.clone();
        let r = report(&o, &ledger);
        assert_eq!(r["valid"], true, "{r}");
        assert_eq!(r["executing_lanes"], 2);
        assert_eq!(r["non_replay_resident_bytes"], 142_216_388_608_u64);
        assert_eq!(r["historical_non_replay_owner_census"], json!([unit]));
        assert_eq!(r["owner_census"].as_array().unwrap().len(), 2);
        assert_eq!(r["admission_authorized"], false);
        assert_eq!(o, original);
        for key in [
            "observer_sha256",
            "sampled_at_utc",
            "terminal247_conservative_rss",
        ] {
            let mut bad = ledger.clone();
            bad[key] = Value::Null;
            assert_eq!(report(&o, &bad)["valid"], false);
        }
        let mut bad = ledger.clone();
        bad["unit_census"][unit]["InvocationID"] = json!("replacement");
        assert_eq!(report(&o, &bad)["valid"], false);
        let mut duplicate = o.clone();
        let row = duplicate["diagnostic_replays"][0].clone();
        duplicate["diagnostic_replays"]
            .as_array_mut()
            .unwrap()
            .push(row);
        assert_eq!(report(&duplicate, &ledger)["valid"], false);
    }
    fn fixture() -> (Value, Value) {
        let mut observations = Vec::new();
        let mut active = Vec::new();
        let mut host_processes = Vec::new();
        for (pid, rss, phase) in [
            (1u64, 142_216_388_608u64, "diagnostic-qualification"),
            (2, 133_364_101_120, "private-known-root-prefix"),
            (3, 128_705_048_576, "private-known-root-prefix"),
        ] {
            let name = format!("replay-{pid}.service");
            let iid = format!("{pid:032x}");
            let process = json!({"pid":pid,"start_ticks":10,"rss_bytes":rss});
            host_processes.push(process.clone());
            let role = json!({"unit":name,"invocation_id":iid,"restarts":0,"active_state":"active","sub_state":"running",
                "rss":{"census_stable":true,"aggregate_rss_bytes":rss,"error":null,"processes":[process]}});
            let row = json!({"invocation_binding_stable":true,"producer_before":role,"controller_before":role,
                "producer_after":role,"controller_after":role,"useful_work":{"sufficient_for_rates":true}});
            observations.push(json!({"status":"observed","observation":row}));
            active.push(json!({"phase":phase,"producer":{"Id":name,"InvocationID":iid,"NRestarts":"0","ActiveState":"active","SubState":"running"}}));
        }
        let lane_sum = 142_216_388_608u64 + 133_364_101_120 + 128_705_048_576;
        let host_sum = 407_235_731_456u64;
        host_processes.push(json!({"pid":4,"start_ticks":20,"rss_bytes":host_sum-lane_sum}));
        let o = json!({"recorded_at_utc":"2026-10-23T16:43:44Z","replays":[],"diagnostic_replays":observations,
            "host_memory":{"total_kib":1_183_727_512u64},
            "host_resident_memory":{"after":{"status":"observed","rss":{"census_stable":true,"error":null,"aggregate_rss_bytes":host_sum,"processes":host_processes},
                "kernel_components_bytes":{"Slab":27_448_233_984u64,"PageTables":1_434_058_752u64,"Percpu":426_770_432,"KernelStack":36_012_032}}},
            "lane_rss_history":{"200":{"maximum_observed_lane_rss_bytes":151_000_739_840u64,"reservation_ceiling_bytes":226_501_109_760u64}}});
        let ledger = json!({"first_epoch":201,"last_epoch":300,"sampled_at_utc":o["recorded_at_utc"],"active":active});
        (o, ledger)
    }
    #[test]
    fn settled_qualifications_have_own_century_target_and_deduplicate_cohort_owners() {
        let (o, mut ledger) = fixture();
        let first = ledger["active"][0].clone();
        ledger["active"].as_array_mut().unwrap().push(first);
        let r = report(&o, &ledger);
        assert_eq!(r["valid"], true, "{r}");
        assert_eq!(r["desired_lanes"], 8);
        assert_eq!(r["executing_lanes"], 3);
        assert_eq!(r["reservation_ceiling_bytes"], 226_501_109_760u64);
        assert_eq!(r["admission_authorized"], false);
        let mut bad = o.clone();
        bad["diagnostic_replays"][0]["observation"]["producer_before"]["restarts"] = json!(1);
        assert_eq!(report(&bad, &ledger)["valid"], false);
        let mut bad = o.clone();
        bad["diagnostic_replays"].as_array_mut().unwrap().pop();
        assert_eq!(report(&bad, &ledger)["valid"], false);
    }
    #[test]
    fn missing_new_repair_owner_never_reuses_old_fleet_capacity() {
        let o =
            json!({"recorded_at_utc":"2026-10-23T16:43:44Z","replays":[],"diagnostic_replays":[]});
        let ledger = json!({"first_epoch":201,"last_epoch":300,"sampled_at_utc":o["recorded_at_utc"],
            "active":[{"phase":"private-cold-snapshot-verification","unit":{"Id":"repair.service","InvocationID":"a","ActiveState":"active","SubState":"running","NRestarts":"0"}}]});
        let result = report(&o, &ledger);
        assert_eq!(result["valid"], false);
        assert!(
            result["limiting_gate"]
                .as_str()
                .unwrap()
                .contains("missing from coordinated RSS")
        );
    }
    #[test]
    fn finalization_owner_retains_rss_without_counting_as_replay() {
        let (mut o, mut ledger) = fixture();
        o["diagnostic_replays"][0]["post_replay_resource_only"] = json!(true);
        o["diagnostic_replays"][0]["observation"]["useful_work"]["sufficient_for_rates"] =
            json!(false);
        let finalization = o["diagnostic_replays"][0].clone();
        ledger["active"][0]["phase"] = json!("producer-finalization");
        let report = report(&o, &ledger);
        assert_eq!(report["valid"], true, "{report}");
        assert_eq!(report["executing_lanes"], 2);
        assert_eq!(report["non_replay_owner_count"], 1);
        assert_eq!(report["non_replay_resident_bytes"], 142_216_388_608u64);
        assert_eq!(report["desired_lanes"], report["desired_production_lanes"]);
        assert_eq!(
            report["aggregate_lane_rss_bytes"].as_u64().unwrap()
                + report["non_lane_resident_planning_bytes"].as_u64().unwrap(),
            report["host_resident_planning_bytes"].as_u64().unwrap()
        );
        assert_eq!(report["owner_census"].as_array().unwrap().len(), 3);
        let mut bad = o.clone();
        bad["diagnostic_replays"].as_array_mut().unwrap().remove(0);
        assert_eq!(super::report(&bad, &ledger)["valid"], false);
        let mut duplicate = o.clone();
        duplicate["diagnostic_replays"]
            .as_array_mut()
            .unwrap()
            .push(finalization);
        assert_eq!(super::report(&duplicate, &ledger)["valid"], false);
        let mut unavailable = o.clone();
        unavailable["diagnostic_replays"][0]["status"] = json!("unavailable");
        unavailable["diagnostic_replays"][0]["observation"] = Value::Null;
        assert_eq!(super::report(&unavailable, &ledger)["valid"], false);
        ledger["active"][0]["phase"] = json!("replay");
        assert_eq!(super::report(&o, &ledger)["valid"], false);
    }
}
