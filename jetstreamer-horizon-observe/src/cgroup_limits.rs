//! Actual cgroup limits from the existing observation, independent of RSS-based
//! planning ceilings. This is a scoped census, never a host admission decision.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{collections::BTreeMap, path::Path};

fn limit(gauges: &Value, name: &str) -> Result<Option<u64>> {
    let value = gauges.get(name).context("missing cgroup memory limit")?;
    if value.is_null() {
        Ok(None) // Kernel's literal `max`, not zero and not a missing field.
    } else {
        Ok(Some(value.as_u64().context("invalid cgroup memory limit")?))
    }
}

#[derive(Debug, PartialEq)]
struct Owner {
    unit: String,
    invocation: String,
    maximum: Option<u64>,
    high: Option<u64>,
    swap_maximum: Option<u64>,
    minimum_current: u64,
}

fn checked(sample: &Value) -> Result<Value> {
    let mut rows: Vec<&Value> = sample["replays"]
        .as_array()
        .context("missing replay census")?
        .iter()
        .collect();
    let mut unresolved = 0;
    for key in [
        "diagnostic_replays",
        "epoch203_ram_auxiliary",
        "delivery_resources",
    ] {
        for row in sample[key].as_array().into_iter().flatten() {
            if row["status"] == "observed" && row["native_resource_only"] != true {
                rows.push(&row["observation"]);
            } else {
                unresolved += 1;
            }
        }
    }
    let mut owners: BTreeMap<String, Owner> = BTreeMap::new();
    let mut units: BTreeMap<String, String> = BTreeMap::new();
    for row in rows {
        ensure!(
            row["invocation_binding_stable"] == true,
            "unstable limit owner"
        );
        for role in ["controller", "producer"] {
            let before = &row[format!("{role}_before")];
            let after = &row[format!("{role}_after")];
            let name = after["unit"].as_str().context("missing limit unit")?;
            let invocation = after["invocation_id"]
                .as_str()
                .context("missing limit invocation")?;
            let path = after["cgroup"]["path"]
                .as_str()
                .context("missing cgroup path")?;
            ensure!(
                !name.is_empty()
                    && !invocation.is_empty()
                    && Path::new(path).starts_with("/sys/fs/cgroup")
                    && path != "/sys/fs/cgroup"
                    && !Path::new(path)
                        .components()
                        .any(|c| matches!(c, std::path::Component::ParentDir)),
                "invalid limit identity/path"
            );
            for endpoint in [before, after] {
                ensure!(
                    endpoint["unit"] == name
                        && endpoint["invocation_id"] == invocation
                        && endpoint["cgroup"]["path"] == path
                        && endpoint["restarts"] == 0
                        && endpoint["active_state"] == "active"
                        && endpoint["sub_state"] == "running",
                    "cgroup limit identity changed or is not running"
                );
            }
            let a = &before["cgroup"]["gauges"];
            let b = &after["cgroup"]["gauges"];
            for key in ["memory.max", "memory.high", "memory.swap.max"] {
                ensure!(
                    limit(a, key)? == limit(b, key)?,
                    "cgroup limit changed during observation"
                );
            }
            let mut owner = Owner {
                unit: name.into(),
                invocation: invocation.into(),
                maximum: limit(b, "memory.max")?,
                high: limit(b, "memory.high")?,
                swap_maximum: limit(b, "memory.swap.max")?,
                minimum_current: a["memory.current"]
                    .as_u64()
                    .context("missing memory current")?
                    .min(
                        b["memory.current"]
                            .as_u64()
                            .context("missing memory current")?,
                    ),
            };
            if let Some(old_path) = units.insert(name.into(), path.into()) {
                ensure!(old_path == path, "unit appears in two cgroups");
            }
            if let Some(old) = owners.get(path) {
                // Identical controller/producer or cohort owners count once.
                // Reads occur at different instants; retain the lower current
                // value so remaining hard growth is never understated.
                let current = old.minimum_current.min(owner.minimum_current);
                owner.minimum_current = old.minimum_current;
                ensure!(*old == owner, "conflicting owners or limits for cgroup");
                owner.minimum_current = current;
            }
            owners.insert(path.into(), owner);
        }
    }
    ensure!(!owners.is_empty(), "no observed limit owners");
    for path in owners.keys() {
        ensure!(
            !owners
                .keys()
                .any(|other| path != other && Path::new(path).starts_with(other)),
            "nested cgroups require a separate hierarchy-aware admission calculation"
        );
    }
    let mut maximum = Some(0u64);
    let mut growth = Some(0u64);
    let mut current = 0u64;
    let mut entries = Vec::new();
    for (path, owner) in owners {
        current = current
            .checked_add(owner.minimum_current)
            .context("current sum overflow")?;
        let remaining = owner
            .maximum
            .map(|m| m.saturating_sub(owner.minimum_current));
        maximum = match (maximum, owner.maximum) {
            (Some(a), Some(b)) => Some(a.checked_add(b).context("hard limit sum overflow")?),
            _ => None,
        };
        growth = match (growth, remaining) {
            (Some(a), Some(b)) => Some(a.checked_add(b).context("hard growth sum overflow")?),
            _ => None,
        };
        entries.push(json!({"unit":owner.unit,"invocation_id":owner.invocation,"cgroup":path,
            "memory_max_bytes":owner.maximum,"memory_high_bytes":owner.high,
            "memory_swap_max_bytes":owner.swap_maximum,"minimum_observed_current_bytes":owner.minimum_current,
            "remaining_hard_growth_bytes":remaining}));
    }
    Ok(
        json!({"status":"observed","owners":entries,"distinct_cgroup_count":entries.len(),
        "sum_memory_max_bytes":maximum,"sum_remaining_hard_growth_bytes":growth,
        "sum_minimum_observed_current_bytes":current,"unresolved_diagnostic_count":unresolved,
        "all_configured_limits_finite_and_observed":maximum.is_some() && unresolved == 0}),
    )
}

pub fn report(sample: &Value) -> Value {
    let mut value = match checked(sample) {
        Ok(value) => value,
        Err(error) => json!({"status":"unavailable","error":format!("{error:#}")}),
    };
    value["scope"] =
        json!("configured observed controller/producer cgroups only; not the whole host");
    value["rss_reservation_ceiling_is_existing_hard_limit"] = json!(false);
    value["host_and_unobserved_auxiliary_reservations_included"] = json!(false);
    value["admission_authorized"] = json!(false);
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    fn row(name: &str, maximum: Value, current: u64) -> Value {
        let role = json!({"unit":name,"invocation_id":"a","restarts":0,
            "active_state":"active","sub_state":"running","cgroup":{
            "path":format!("/sys/fs/cgroup/system.slice/{name}"),"gauges":{
            "memory.max":maximum,"memory.high":null,"memory.swap.max":0,"memory.current":current}}});
        json!({"invocation_binding_stable":true,"controller_before":role,"producer_before":role,
            "controller_after":role,"producer_after":role})
    }
    fn sample() -> Value {
        json!({"replays":[row("a.service",json!(251),100),row("b.service",json!(128),60)],
            "diagnostic_replays":[],"epoch203_ram_auxiliary":[],
            "lane_rss_history":{"200":{"reservation_ceiling_bytes":223}}})
    }
    #[test]
    fn counts_actual_distinct_caps_and_minimum_current_not_rss_ceiling() {
        let mut s = sample();
        s["replays"][0]["producer_after"]["cgroup"]["gauges"]["memory.current"] = json!(90);
        let duplicate = s["replays"][0].clone();
        s["replays"].as_array_mut().unwrap().push(duplicate);
        let r = report(&s);
        assert_eq!(r["status"], "observed");
        assert_eq!(r["distinct_cgroup_count"], 2);
        assert_eq!(r["sum_memory_max_bytes"], 379);
        assert_eq!(r["sum_remaining_hard_growth_bytes"], 229);
        assert_eq!(r["admission_authorized"], false);
    }
    #[test]
    fn unlimited_missing_changed_and_overflow_never_make_finite_capacity() {
        let mut s = sample();
        s["replays"][0] = row("a.service", Value::Null, 100);
        let r = report(&s);
        assert_eq!(r["status"], "observed");
        assert!(r["sum_memory_max_bytes"].is_null());
        assert_eq!(r["all_configured_limits_finite_and_observed"], false);
        for pointer in [
            "/replays/0/producer_after/cgroup/gauges/memory.max",
            "/replays/0/producer_after/invocation_id",
            "/replays/0/producer_after/cgroup/path",
        ] {
            let mut s = sample();
            *s.pointer_mut(pointer).unwrap() = json!("changed");
            assert_eq!(report(&s)["status"], "unavailable");
        }
        let mut s = sample();
        s["replays"][0]["producer_before"]["cgroup"]["gauges"]
            .as_object_mut()
            .unwrap()
            .remove("memory.max");
        assert_eq!(report(&s)["status"], "unavailable");
        let mut s = sample();
        s["replays"][0] = row("a.service", json!(u64::MAX), 0);
        assert_eq!(report(&s)["status"], "unavailable");
    }
    #[test]
    fn nested_cgroups_conflicts_and_unobserved_diagnostics_are_explicit() {
        let mut s = sample();
        s["replays"][1] = row("a.service/child", json!(128), 60);
        assert_eq!(report(&s)["status"], "unavailable");
        let mut s = sample();
        s["replays"][1] = row("a.service", json!(128), 60);
        assert_eq!(report(&s)["status"], "unavailable");
        let mut s = sample();
        s["diagnostic_replays"] = json!([{"status":"unavailable"}]);
        let r = report(&s);
        assert_eq!(r["unresolved_diagnostic_count"], 1);
        assert_eq!(r["all_configured_limits_finite_and_observed"], false);
        let mut s = sample();
        s["diagnostic_replays"] =
            json!([{"status":"observed","observation":row("c.service",json!(7),3)}]);
        assert_eq!(report(&s)["sum_memory_max_bytes"], 386);
    }
}
