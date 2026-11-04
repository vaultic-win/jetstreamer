//! Evidence for leaving the expanded-fleet observation hold; never admission
//! or operating-point promotion authority. Only accepted observer bytes enter.
use super::*;

const EVENTS: [&str; 4] = [
    "memory_events.oom",
    "memory_events.oom_kill",
    "memory_events.oom_group_kill",
    "memory_events.max",
];

fn rows(o: &Value) -> Result<BTreeMap<String, &Value>> {
    let ordinary = o["replays"].as_array().context("ordinary census missing")?;
    let private = o["diagnostic_replays"]
        .as_array()
        .context("private census missing")?;
    let mut result = BTreeMap::new();
    for row in ordinary.iter().chain(private.iter().filter_map(|row| {
        if row["status"] == "observed" {
            row.get("observation")
        } else if row.get("status").is_none() {
            Some(row)
        } else {
            None
        }
    })) {
        let after = &row["producer_after"];
        // A terminal retained diagnostic is history, not an executing lane.
        if after["active_state"] != "active" || after["sub_state"] != "running" {
            continue;
        }
        let id = after["invocation_id"]
            .as_str()
            .context("lane identity missing")?;
        ensure!(
            id.len() == 32 && id.bytes().all(|c| c.is_ascii_hexdigit()),
            "invalid lane identity"
        );
        ensure!(
            result.insert(id.to_owned(), row).is_none(),
            "duplicate lane identity"
        );
    }
    Ok(result)
}

fn checked(
    current: &Value,
    previous: &Value,
    production: &BTreeMap<String, Value>,
    private: &BTreeSet<&str>,
    production_clean: bool,
    memory: &Value,
) -> Result<Value> {
    ensure!(
        production_clean && memory["valid"] == true,
        "production or RSS census not clean"
    );
    ensure!(!private.is_empty(), "no expanded fleet");
    for o in [current, previous] {
        ensure!(
            o["schema"] == "jetstreamer-horizon-live-resource-sample-v2",
            "observer schema differs"
        );
    }
    let clock = |o: &Value| -> Result<u64> {
        utc_seconds(
            o["recorded_at_utc"]
                .as_str()
                .context("observation clock missing")?,
        )
    };
    let interval = clock(current)?
        .checked_sub(clock(previous)?)
        .context("observation clock regressed")?;
    ensure!(
        interval >= 1800,
        "expanded window shorter than 1800 seconds"
    );
    let old = rows(previous)?;
    let new = rows(current)?;
    let expected: BTreeSet<_> = production
        .keys()
        .map(String::as_str)
        .chain(private.iter().copied())
        .collect();
    ensure!(
        new.keys().map(String::as_str).collect::<BTreeSet<_>>() == expected
            && old.keys().map(String::as_str).collect::<BTreeSet<_>>() == expected,
        "expanded owner census differs between accepted observations"
    );
    for (id, row) in &new {
        let prior = old[id];
        for sample in [prior, *row] {
            ensure!(
                sample["invocation_binding_stable"] == true,
                "unstable lane invocation"
            );
            for role in ["controller", "producer"] {
                let before = &sample[format!("{role}_before")];
                let after = &sample[format!("{role}_after")];
                ensure!(
                    before["invocation_id"].is_string()
                        && before["invocation_id"] == after["invocation_id"]
                        && before["restarts"] == 0
                        && after["restarts"] == 0
                        && before["active_state"] == "active"
                        && after["active_state"] == "active"
                        && before["sub_state"] == "running"
                        && after["sub_state"] == "running",
                    "lane changed phase, identity or restarted"
                );
            }
            ensure!(
                sample["worker_before"]["matching_workers"] == 1
                    && sample["worker_after"]["matching_workers"] == 1
                    && sample["worker_before"]["pid"]
                        .as_u64()
                        .is_some_and(|v| v > 0)
                    && sample["worker_before"]["pid"] == sample["worker_after"]["pid"],
                "worker changed within observation"
            );
        }
        for role in ["controller", "producer"] {
            for key in ["invocation_id", "unit", "main_pid"] {
                ensure!(
                    !row[format!("{role}_after")][key].is_null()
                        && row[format!("{role}_after")][key] == prior[format!("{role}_after")][key],
                    "lane owner changed across window"
                );
            }
        }
        ensure!(
            row["scratch_path"].is_string() && row["scratch_path"] == prior["scratch_path"],
            "scratch claim changed"
        );
        for key in ["pid", "executable"] {
            ensure!(
                !row["worker_after"][key].is_null()
                    && row["worker_after"][key] == prior["worker_after"][key],
                "worker changed across window"
            );
        }
        for sample in [prior, *row] {
            let vmas = sample["worker_after"]["vmas"]
                .as_u64()
                .context("VMA census missing")?;
            // Production's existing comparison bound is tighter. A private
            // profile still requires its own actual guard stop in promotion.
            let ceiling = if private.contains(id.as_str()) {
                3_500_000
            } else {
                800_000
            };
            ensure!(vmas > 0 && vmas < ceiling, "VMA comparison bound exceeded");
        }
        ensure!(
            row["useful_work"]["sufficient_for_rates"] == true
                && row["useful_work"]["transaction_delta"]
                    .as_u64()
                    .is_some_and(|v| v > 0)
                && row["useful_work"]["slot_delta"]
                    .as_u64()
                    .is_some_and(|v| v > 0),
            "lane lacks useful progress"
        );
        for key in EVENTS {
            // Comparing cumulative counters also covers the whole interval;
            // an absent/null cross-sample delta cannot masquerade as zero.
            let counter = |s: &Value, point: &str| -> Result<u64> {
                s[format!("producer_{point}")]["cgroup"]["counters"][key]
                    .as_u64()
                    .context("memory event counter missing")
            };
            let baseline = counter(prior, "before")?;
            ensure!(
                counter(prior, "after")? == baseline
                    && counter(row, "before")? == baseline
                    && counter(row, "after")? == baseline,
                "memory limit or OOM event in expanded window"
            );
        }
    }
    Ok(
        json!({"qualified":true,"interval_seconds":interval,"stable_lane_count":new.len(),
        "previous_sampled_at_utc":previous["recorded_at_utc"],"sampled_at_utc":current["recorded_at_utc"],
        "owners":expected,"remaining_gate":"Current no-trip guards, century floor and protected growth must be bound in explicit operating-point promotion; candidate still requires fresh admission."}),
    )
}

pub(super) fn report(
    current: &Value,
    previous: &Value,
    production: &BTreeMap<String, Value>,
    private: &BTreeSet<&str>,
    production_clean: bool,
    memory: &Value,
) -> Value {
    let mut result = match checked(
        current,
        previous,
        production,
        private,
        production_clean,
        memory,
    ) {
        Ok(value) => value,
        Err(error) => json!({"qualified":false,"limiting_gate":error.to_string()}),
    };
    result["schema"] = json!("jetstreamer-horizon-expanded-fleet-window-v2");
    result["operating_point_promoted"] = json!(false);
    result["replay_launch_authorized"] = json!(false);
    result["new_resource_samples"] = json!(0);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lane(id: &str, pid: u64) -> Value {
        let unit = json!({"invocation_id":id,"unit":format!("lane-{pid}.service"),
            "main_pid":pid,"active_state":"active","sub_state":"running","restarts":0,
            "cgroup":{"counters":EVENTS.into_iter().map(|key| (key.to_owned(),json!(0))).collect::<serde_json::Map<_,_>>()}});
        let worker =
            json!({"matching_workers":1,"pid":pid+1,"executable":"/scratch/worker","vmas":400000});
        json!({"invocation_binding_stable":true,"controller_before":unit,"controller_after":unit,
            "producer_before":unit,"producer_after":unit,"scratch_path":format!("/scratch/{pid}"),
            "worker_before":worker,"worker_after":worker,
            "useful_work":{"sufficient_for_rates":true,"slot_delta":100,"transaction_delta":1000}})
    }

    fn sample(clock: &str) -> Value {
        json!({"schema":"jetstreamer-horizon-live-resource-sample-v2","recorded_at_utc":clock,
            "replays":[lane(&"a".repeat(32),100)],
            "diagnostic_replays":[{"status":"observed","observation":lane(&"b".repeat(32),200)}]})
    }

    fn check(current: &Value, previous: &Value) -> Value {
        report(
            current,
            previous,
            &BTreeMap::from([("a".repeat(32), Value::Null)]),
            &BTreeSet::from(["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]),
            true,
            &json!({"valid":true}),
        )
    }

    #[test]
    fn full_expanded_window_advances_gate_without_granting_promotion_or_launch() {
        let previous = sample("2026-10-23T14:56:00Z");
        let current = sample("2026-10-23T15:26:00Z");
        let report = check(&current, &previous);
        assert_eq!(report["qualified"], true);
        assert_eq!(report["stable_lane_count"], 2);
        assert_eq!(report["interval_seconds"], 1800);
        assert_eq!(report["operating_point_promoted"], false);
        assert_eq!(report["replay_launch_authorized"], false);
        assert_eq!(report["new_resource_samples"], 0);
    }

    #[test]
    fn short_first_expanded_sample_and_missing_private_predecessor_do_not_qualify() {
        let current = sample("2026-10-23T15:26:00Z");
        let mut previous = sample("2026-10-23T14:56:01Z");
        assert_eq!(check(&current, &previous)["qualified"], false);
        previous["recorded_at_utc"] = json!("2026-10-23T14:56:00Z");
        previous["diagnostic_replays"] = json!([]);
        assert_eq!(check(&current, &previous)["qualified"], false);
    }

    #[test]
    fn same_lane_count_cannot_hide_replacement_restart_missing_rss_or_stalled_work() {
        let previous = sample("2026-10-23T14:56:00Z");
        let current = sample("2026-10-23T15:26:00Z");
        for (pointer, value) in [
            ("/diagnostic_replays/0/status", json!("unavailable")),
            (
                "/diagnostic_replays/0/observation/producer_after/invocation_id",
                json!("c".repeat(32)),
            ),
            (
                "/diagnostic_replays/0/observation/controller_after/restarts",
                json!(1),
            ),
            (
                "/diagnostic_replays/0/observation/worker_after/pid",
                json!(999),
            ),
            ("/replays/0/producer_after/main_pid", json!(999)),
            (
                "/diagnostic_replays/0/observation/useful_work/slot_delta",
                json!(0),
            ),
            (
                "/diagnostic_replays/0/observation/worker_after/vmas",
                json!(3500000),
            ),
        ] {
            let mut wrong = current.clone();
            *wrong.pointer_mut(pointer).unwrap() = value;
            assert_eq!(check(&wrong, &previous)["qualified"], false, "{pointer}");
        }
        assert_eq!(
            report(
                &current,
                &previous,
                &BTreeMap::new(),
                &BTreeSet::new(),
                true,
                &json!({"valid":false})
            )["qualified"],
            false
        );
    }

    #[test]
    fn memory_events_missing_counters_and_duplicate_owners_fail_closed() {
        let previous = sample("2026-10-23T14:56:00Z");
        let current = sample("2026-10-23T15:26:00Z");
        for event in EVENTS {
            for value in [json!(1), Value::Null, json!("0")] {
                let mut wrong = current.clone();
                wrong["diagnostic_replays"][0]["observation"]["producer_after"]["cgroup"]["counters"]
                    [event] = value;
                assert_eq!(check(&wrong, &previous)["qualified"], false, "{event}");
            }
        }
        let mut wrong = current.clone();
        wrong["diagnostic_replays"]
            .as_array_mut()
            .unwrap()
            .push(current["diagnostic_replays"][0].clone());
        assert_eq!(check(&wrong, &previous)["qualified"], false);
    }
}
