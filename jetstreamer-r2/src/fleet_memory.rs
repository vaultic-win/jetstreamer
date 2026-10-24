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
        seen.len() == owners.len(),
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
    report["sampled_at_utc"] = o["recorded_at_utc"].clone();
    report["owner_census"] = json!(owners.keys().collect::<Vec<_>>());
    report["qualification_replays_in_marginal_average"] = json!(true);
    Ok(report)
}

pub(super) fn report(o: &Value, ledger: &Value) -> Value {
    (|| -> Result<Value> {
        let accounting=crate::fleet::native227_terminal_observer_view(ledger,o)?;
        let mut result=checked(&accounting,ledger)?;
        if let Some(evidence)=accounting.get("terminal_observation_accounting") {
            result["terminal_observation_accounting"]=evidence.clone();
        }
        Ok(result)
    })().unwrap_or_else(|e| json!({"valid":false,"target_percent":90,
        "admission_authorized":false,"limiting_gate":format!("{e:#}"),
        "next_action":"Account every live replay, qualification and delivery owner in the same coordinated RSS sample; preserve all healthy work."}))
}

#[cfg(test)]
mod tests {
    use super::*;
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
    fn terminal_native_rss_retained_in_raw_host_snapshot_stays_non_lane_once() {
        let (mut o, ledger) = fixture();
        let baseline = checked(&o, &ledger).unwrap();
        let old_native_rss = 64_493_019_136u64;
        let host = &mut o["host_resident_memory"]["after"]["rss"];
        let old = host["aggregate_rss_bytes"].as_u64().unwrap();
        host["aggregate_rss_bytes"] = json!(old + old_native_rss);
        host["processes"]
            .as_array_mut()
            .unwrap()
            .push(json!({"pid":456026,"start_ticks":176783891,"rss_bytes":old_native_rss}));
        let report = checked(&o, &ledger).unwrap();
        assert_eq!(report["valid"], true, "{report}");
        assert_eq!(report["executing_lanes"], baseline["executing_lanes"]);
        assert_eq!(
            report["non_lane_resident_planning_bytes"].as_u64().unwrap(),
            baseline["non_lane_resident_planning_bytes"]
                .as_u64()
                .unwrap()
                + old_native_rss
        );
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
}
