//! Pure complete-census gates over an already accepted coordinated observation.
use super::*;

pub(super) fn validate(
    s: &Spec,
    p: &Value,
    proposal: &Value,
    o: &Value,
    f: &Value,
    now: u64,
) -> Result<u64> {
    let t = utc_seconds(string(o, "recorded_at_utc")?)?;
    ensure!(
        t <= now
            && now - t <= 1800
            && o["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && f["schema"] == SCHEMA
            && f["first_epoch"] == 201
            && f["last_epoch"] == 300
            && f["observer_receipt"].as_str() == s.observer.path.to_str()
            && f["observer_sha256"] == s.observer.sha256
            && f["sampled_at_utc"] == o["recorded_at_utc"]
            && f["inventory"]["anomalies"] == 0
            && number(o, "vm_max_map_count")? >= 4194304,
        "capped stale/unaccepted/incomplete coordinated sample"
    );
    let epoch = number(p, "epoch")?;
    let (old, iid) = original(epoch)?;
    let old_owner = f["unit_census"]
        .get(old)
        .context("capped original owner absent from raw accepted census")?;
    original_idle(old_owner, epoch)?;
    ensure!(
        !f["active"]
            .as_array()
            .context("capped active census missing")?
            .iter()
            .any(|row| row["epoch"] == epoch),
        "capped epoch already has a live accepted owner"
    );
    let names = prefix223_live_peer::roster(f)?;
    let mut seen = BTreeSet::new();
    for row in o["diagnostic_replays"]
        .as_array()
        .context("capped diagnostic observation census missing")?
    {
        let name = string(row, "producer_unit")?;
        if row["status"] != "observed" {
            ensure!(
                !names.contains(name),
                "capped active owner has no successful coordinated observation"
            );
            if name == old {
                ensure!(
                    row["expected_producer_invocation_id"] == iid,
                    "capped unavailable original source has another invocation"
                );
            } else {
                native209_admission::unavailable_is_inactive(row, f)?;
            }
            continue;
        }
        ensure!(
            names.contains(name) && seen.insert(name.to_owned()) && row["error"].is_null(),
            "capped extra/duplicate/failed observed owner"
        );
        let owner = &f["unit_census"][name];
        let obs = &row["observation"];
        ensure!(
            obs["invocation_binding_stable"] == true,
            "capped sampled invocation unstable"
        );
        let pid = string(owner, "MainPID")?.parse::<u64>()?;
        ensure!(pid > 1, "capped protected owner PID invalid");
        for phase in ["producer_before", "producer_after"] {
            let u = &obs[phase];
            ensure!(
                u["unit"] == name
                    && u["invocation_id"] == owner["InvocationID"]
                    && u["main_pid"] == pid
                    && u["restarts"] == 0
                    && u["control_group"] == owner["ControlGroup"]
                    && u["active_state"] == "active"
                    && u["sub_state"] == "running"
                    && u["rss"]["census_stable"] == true,
                "capped sampled owner identity/RSS census changed:{name}:{phase}"
            );
        }
        for phase in ["worker_before", "worker_after"] {
            let w = &obs[phase];
            ensure!(
                w["matching_workers"] == 1
                    && w["executable_beneath_bound_scratch"] == true
                    && number(w, "vmas")? > 0
                    && number(w, "vmas")? < 3_500_000,
                "capped protected worker VMA/scope/count unqualified:{name}:{phase}"
            );
        }
    }
    ensure!(
        seen == names && o["replays"].as_array().is_some_and(Vec::is_empty),
        "capped coordinated observation omitted an owner or includes ordinary replay"
    );
    let history = &o["lane_rss_history"]["200"];
    let rss = number(history, "maximum_observed_lane_rss_bytes")?;
    let ceiling = rss.checked_mul(3).context("capped century RSS overflow")? / 2;
    ensure!(
        rss > 0
            && history["reservation_ceiling_bytes"] == ceiling
            && number(&proposal["kernel_limits"], "requested_memory_max_bytes")? <= ceiling,
        "capped hard-memory envelope exceeds century 1.5x RSS ceiling"
    );
    let psi = &o["host_global_pressure"]["cross_sample"];
    let elapsed = number(psi, "elapsed_millis")?;
    ensure!(
        psi["status"] == "observed" && elapsed > 0,
        "capped pressure has no measured interval"
    );
    for (counter, fraction) in [
        ("memory.full_total_usec", 100u64),
        ("cpu.some_total_usec", 500),
        ("io.full_total_usec", 100),
    ] {
        let max = elapsed
            .checked_mul(fraction)
            .context("capped pressure interval overflow")?;
        ensure!(
            number(&psi["counter_delta_usec"], counter)? <= max,
            "capped resource pressure exceeds headroom:{counter}"
        );
    }
    Ok(t)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn bound(path: &str) -> BoundFile {
        BoundFile {
            path: path.into(),
            sha256: "a".repeat(64),
        }
    }
    pub(super) fn spec() -> Spec {
        Spec {
            schema: "jetstreamer-capped204205-continuation-admission-spec-v1".into(),
            producer_plan: bound("/sealed/plan.json"),
            resource_proposal: bound("/sealed/proposal.json"),
            resource_capability: bound("/sealed/capability.json"),
            source_closure: bound("/sealed/source.json"),
            producer: bound("/sealed/node"),
            control: bound("/sealed/control"),
            observer: bound("/sealed/observer.json"),
            fleet: bound("/sealed/fleet.json"),
            fleet_observation_readable_mirror: "/sealed/fleet-observation.json".into(),
            protected_guards: BTreeMap::new(),
            output: "/sealed/admission.json".into(),
        }
    }
    fn fixture() -> (Spec, Value, Value, Value, Value, u64) {
        let s = spec();
        let (old, old_iid) = original(204).unwrap();
        let (peer, iid) = original(205).unwrap();
        let owner = json!({"Id":peer,"InvocationID":iid,"MainPID":"42","NRestarts":"0",
            "LoadState":"loaded","ActiveState":"active","SubState":"running","ControlGroup":format!("/system.slice/{peer}")});
        let unit = json!({"unit":peer,"invocation_id":iid,"main_pid":42,"restarts":0,
            "control_group":owner["ControlGroup"],"active_state":"active","sub_state":"running","rss":{"census_stable":true}});
        let w = json!({"matching_workers":1,"executable_beneath_bound_scratch":true,"vmas":123});
        let f = json!({"schema":SCHEMA,"first_epoch":201,"last_epoch":300,
            "sampled_at_utc":"2026-10-24T10:00:00Z","observer_receipt":s.observer.path,"observer_sha256":s.observer.sha256,
            "unit_census":{old:{"Id":old,"InvocationID":old_iid,"Result":"success","ExecMainStatus":"0","MainPID":"0","NRestarts":"0","ControlGroup":"","LoadState":"loaded","ActiveState":"inactive","SubState":"dead"},peer:owner},
            "inventory":{"anomalies":0},"active":[{"epoch":205,"unit":owner}]});
        let o = json!({"schema":"jetstreamer-horizon-live-resource-sample-v2","recorded_at_utc":"2026-10-24T10:00:00Z",
            "vm_max_map_count":4194304,"lane_rss_history":{"200":{"maximum_observed_lane_rss_bytes":1000,"reservation_ceiling_bytes":1500}},
            "host_global_pressure":{"cross_sample":{"status":"observed","elapsed_millis":1800000,
                "counter_delta_usec":{"memory.full_total_usec":0,"cpu.some_total_usec":0,"io.full_total_usec":0}}},
            "replays":[],"diagnostic_replays":[{"producer_unit":peer,"status":"observed","error":null,
                "observation":{"invocation_binding_stable":true,"producer_before":unit,"producer_after":unit,"worker_before":w,"worker_after":w}}]});
        let p = json!({"epoch":204});
        let r = json!({"kernel_limits":{"requested_memory_max_bytes":1500}});
        let now = utc_seconds("2026-10-24T10:00:00Z").unwrap();
        (s, p, r, o, f, now)
    }
    #[test]
    fn complete_sample_and_missing_changed_or_extra_owners() {
        let (s, p, r, o, f, now) = fixture();
        validate(&s, &p, &r, &o, &f, now).unwrap();
        let mut missing = o.clone();
        missing["diagnostic_replays"] = json!([]);
        assert!(validate(&s, &p, &r, &missing, &f, now).is_err());
        let mut omitted = f.clone();
        omitted["active"] = json!([]);
        assert!(validate(&s, &p, &r, &o, &omitted, now).is_err());
        let mut changed = o.clone();
        changed["diagnostic_replays"][0]["observation"]["producer_after"]["main_pid"] = json!(43);
        assert!(validate(&s, &p, &r, &changed, &f, now).is_err());
        let mut extra = o.clone();
        let row = extra["diagnostic_replays"][0].clone();
        extra["diagnostic_replays"]
            .as_array_mut()
            .unwrap()
            .push(row);
        assert!(validate(&s, &p, &r, &extra, &f, now).is_err());
    }
    #[test]
    fn active_old_producer_stale_sample_and_underreserved_memory_fail() {
        let (s, p, r, o, f, now) = fixture();
        let mut active = f.clone();
        let (old, _) = original(204).unwrap();
        active["unit_census"][old]["ActiveState"] = json!("active");
        active["unit_census"][old]["SubState"] = json!("running");
        active["unit_census"][old]["MainPID"] = json!("99");
        assert!(validate(&s, &p, &r, &o, &active, now).is_err());
        assert!(validate(&s, &p, &r, &o, &f, now + 1801).is_err());
        assert!(validate(&s, &p, &r, &o, &f, now - 1).is_err());
        let mut cap = r.clone();
        cap["kernel_limits"]["requested_memory_max_bytes"] = json!(1501);
        assert!(validate(&s, &p, &cap, &o, &f, now).is_err());
        let mut pressure = o.clone();
        pressure["host_global_pressure"]["cross_sample"]["counter_delta_usec"]["memory.full_total_usec"] =
            json!(180000001);
        assert!(validate(&s, &p, &r, &pressure, &f, now).is_err());
        let mut missing = f;
        missing["unit_census"].as_object_mut().unwrap().remove(old);
        assert!(validate(&s, &p, &r, &o, &missing, now).is_err());
    }
}
