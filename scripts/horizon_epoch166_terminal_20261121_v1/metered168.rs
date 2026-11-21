//! Replay registration of the independent normal 168 after its earlier diagnostic closed.
use super::*;
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::path::Path;

pub(super) fn roster(f: &Value, cfg: &Value) -> Result<(bool, bool)> {
    from_root(f, cfg, Path::new(BASE))
}
fn from_root(f: &Value, cfg: &Value, base: &Path) -> Result<(bool, bool)> {
    const UNIT: &str = "horizon-qualify-168-full-metered-20261121-v1.service";
    let selections = rows(cfg, "replays")?
        .iter()
        .filter(|r| r["range"] == "168")
        .collect::<Vec<_>>();
    let replays = rows(f, "actual_executing_replays")?
        .iter()
        .filter(|r| r["epoch"] == 168)
        .collect::<Vec<_>>();
    let boots = rows(f, "actual_active_bootstraps")?
        .iter()
        .filter(|r| r["epoch"] == 168)
        .collect::<Vec<_>>();
    let Some(reference) = f.get("current_metered168_observation") else {
        ensure!(
            selections.is_empty() && replays.is_empty() && boots.is_empty(),
            "168 has no normal admission capture"
        );
        return Ok((false, false));
    };
    let root = base.join("epoch168-full-metered-20261121-v1");
    let dir = Path::new(s(&f["sole_next_observer"]["path"])?)
        .parent()
        .and_then(Path::parent)
        .context("168 fleet path")?;
    let capture = bound(reference)?;
    let state = &capture["state"];
    ensure!(
        reference["path"] == json!(dir.join("METERED168_OBSERVATION.json"))
            && capture["schema"] == "horizon-normal168-scheduled-capture-v1"
            && capture["sample"] == f["observer"]
            && capture["fleet"] == f["previous_Root_operational_review"]
            && state["prior_trace_terminal"] == f["terminal168_trace_mismatch"]
            && state["prior_trace_terminal"]["sha256"]
                == "29672efbaff97d23a9a9d45a824840cb2d4cf43c6f5e8427ed3b532b41a38de2"
            && state["epoch"] == 168
            && state["private_diagnostic"] == false
            && state["resource_credit_bytes"] == 0,
        "foreign normal 168 capture"
    );
    let intent = bound(&state["intent"])?;
    ensure!(
        state["intent"]["path"] == json!(root.join("START_INTENT.json"))
            && intent["producer_unit"] == UNIT
            && intent["timer_unit"] == "horizon-guard-168-full-metered-20261121-v1.timer"
            && intent["prior_trace_terminal"] == state["prior_trace_terminal"]
            && intent["prepared"]
                == json!({"path":root.join("PREPARED.json"),"sha256":"27e3588b8c8a13c8eb4f1dd83133c17a777abbf7d8e8c32960600ac6e0af20d0"}),
        "different 168 intent"
    );
    if matches!(state["stage"].as_str(), Some("intent" | "gated")) {
        ensure!(
            state["ordinary_canonical"] == false
                && state["observer_row"].is_null()
                && replays.is_empty()
                && boots.is_empty()
                && selections.is_empty(),
            "pending 168 counted as a producer"
        );
        return Ok((false, false));
    }
    let worker = state["stage"] == "protected-worker";
    ensure!(
        worker || state["stage"] == "protected-bootstrap",
        "unknown normal 168 stage"
    );
    let row = if worker {
        ensure!(
            boots.is_empty() && replays.len() == 1 && selections == [&state["observer_row"]],
            "foreign 168 worker registration"
        );
        replays[0]
    } else {
        ensure!(
            replays.is_empty()
                && boots.len() == 1
                && selections.is_empty()
                && state["observer_row"].is_null(),
            "foreign 168 bootstrap registration"
        );
        boots[0]
    };
    let admission = bound(&state["admission"])?;
    let actor = &state["actor"];
    let guard = bound(&state["current_guard"]["receipt"])?;
    ensure!(
        state["ordinary_canonical"] == true
            && state["actual_active_bootstrap"] == !worker
            && state["admission"]["path"]
                == json!(root.join("ACTUAL_ADMISSION_AND_PROTECTION.json"))
            && admission["epoch"] == 168
            && admission["bootstrap_only"] == true
            && admission["producer_unit"] == UNIT
            && admission["prior_trace_terminal"] == state["prior_trace_terminal"]
            && actor["producer_unit"] == UNIT
            && actor["producer_invocation_id"] == admission["producer_invocation_id"]
            && actor["producer_pid"] == admission["producer_pid"]
            && actor["start_ticks"] == admission["start_ticks"]
            && row["capture"] == *reference
            && row["admission"] == state["admission"]
            && row["observer_config"] == state["observer_row"]
            && row["first_worker"] == state["first_worker"]
            && row["unit"]["Id"] == UNIT
            && row["unit"]["InvocationID"] == actor["producer_invocation_id"]
            && row["start_ticks"] == actor["start_ticks"]
            && s(&row["unit"]["MainPID"])?.parse::<u64>()?
                == actor["producer_pid"].as_u64().context("normal 168 PID")?
            && row["guard_protection"] == state["current_guard"]["receipt"]
            && guard["producer_invocation_id"] == actor["producer_invocation_id"]
            && guard["producer"]["pid"] == actor["producer_pid"]
            && guard["guard_invocation_id"] == state["current_guard"]["guard_invocation"]
            && guard["plan_sha256"] == admission["actual_guard_plan"]["sha256"]
            && guard["trip_reason"].is_null(),
        "different normal 168 producer or guard"
    );
    if worker {
        let first = bound(&state["first_worker"])?;
        ensure!(
            state["first_worker"]["path"] == json!(root.join("FIRST_PROTECTED_WORKER.json"))
                && first["admission"] == state["admission"]
                && first["observer_row"] == state["observer_row"]
                && first["worker_sha256"]
                    == "b0219574172b54b251b4f2feda6285ca3b6bee5f2830a0d46e69ee8ea2275541"
                && first["producer_invocation_id"] == actor["producer_invocation_id"]
                && first["worker_pid"].as_u64().is_some_and(|p| p > 1)
                && first["worker_start_ticks"].as_u64().is_some_and(|t| t > 0),
            "foreign first normal worker"
        );
    }
    Ok((!worker, worker))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture_ref(path: &Path, value: &Value) -> Result<Value> {
        let bytes = serde_json::to_vec(value)?;
        fs::write(path, &bytes)?;
        Ok(binding(path, &bytes))
    }

    #[test]
    fn unregistered_168_never_becomes_a_scheduled_producer() {
        let f = json!({"actual_executing_replays":[],"actual_active_bootstraps":[]});
        assert_eq!(roster(&f, &json!({"replays":[]})).unwrap(), (false, false));
        assert!(roster(&f, &json!({"replays":[{"range":"168"}]})).is_err());
    }

    #[test]
    #[ignore = "requires a root-owned private fixture"]
    fn pending_bootstrap_and_first_worker_have_distinct_ownership() -> Result<()> {
        let base = PathBuf::from(std::env::var("NORMAL168_ROSTER_FIXTURE")?);
        fs::create_dir(&base)?;
        let root = base.join("epoch168-full-metered-20261121-v1");
        fs::create_dir(&root)?;
        let uut = "horizon-qualify-168-full-metered-20261121-v1.service";
        let trace = json!({"path":"/fixture/trace","sha256":"29672efbaff97d23a9a9d45a824840cb2d4cf43c6f5e8427ed3b532b41a38de2"});
        let token = "2".repeat(32);
        let actor = json!({"producer_pid":27,"start_ticks":19,"producer_invocation_id":token,"producer_unit":uut});
        let intent = fixture_ref(
            &root.join("START_INTENT.json"),
            &json!({"producer_unit":uut,"timer_unit":"horizon-guard-168-full-metered-20261121-v1.timer",
            "prepared":{"path":root.join("PREPARED.json"),"sha256":"27e3588b8c8a13c8eb4f1dd83133c17a777abbf7d8e8c32960600ac6e0af20d0"},"prior_trace_terminal":trace}),
        )?;
        let ad = fixture_ref(
            &root.join("ACTUAL_ADMISSION_AND_PROTECTION.json"),
            &json!({"epoch":168,"bootstrap_only":true,"producer_unit":uut,"producer_invocation_id":token,
            "producer_pid":27,"start_ticks":19,"prior_trace_terminal":trace,"actual_guard_plan":{"sha256":"34".repeat(32)}}),
        )?;
        let guard = fixture_ref(
            &root.join("guard.json"),
            &json!({"producer_invocation_id":token,"producer":{"pid":27},
            "guard_invocation_id":"5".repeat(32),"plan_sha256":"34".repeat(32),"trip_reason":null}),
        )?;
        let row = json!({"range":"168","producer_unit":uut,"expected_producer_invocation_id":token,"scratch_path":"/home/sol/fixture"});
        let first = fixture_ref(
            &root.join("FIRST_PROTECTED_WORKER.json"),
            &json!({"worker_sha256":"b0219574172b54b251b4f2feda6285ca3b6bee5f2830a0d46e69ee8ea2275541",
            "worker_pid":28,"worker_start_ticks":36,"producer_invocation_id":token,"observer_row":row,"admission":ad}),
        )?;
        for (i, stage) in ["intent", "gated", "protected-bootstrap", "protected-worker"]
            .iter()
            .enumerate()
        {
            let dir = base.join(stage);
            fs::create_dir(&dir)?;
            let normal = i >= 2;
            let worker = i == 3;
            let mut f = json!({"sole_next_observer":{"path":dir.join("sealed-next/observer.json")},"observer":{"sha256":"19".repeat(32)},
                "previous_Root_operational_review":{"path":"/fixture/fleet"},"terminal168_trace_mismatch":trace,"actual_active_bootstraps":[],"actual_executing_replays":[]});
            let mut cap = json!({"schema":"horizon-normal168-scheduled-capture-v1","sample":f["observer"],"fleet":f["previous_Root_operational_review"],
                "state":{"epoch":168,"stage":stage,"prior_trace_terminal":trace,"intent":intent,"resource_credit_bytes":0,"private_diagnostic":false,
                "ordinary_canonical":normal,"actual_active_bootstrap":i==2,"actor":actor,"admission":ad,"current_guard":{"guard_invocation":"5".repeat(32),"receipt":guard}}});
            if worker {
                cap["state"]["observer_row"] = row.clone();
                cap["state"]["first_worker"] = first.clone();
            }
            let hold = fixture_ref(&dir.join("METERED168_OBSERVATION.json"), &cap)?;
            f["current_metered168_observation"] = hold.clone();
            let mut cfg = json!({"replays":[]});
            if normal {
                let key = if worker {
                    "actual_executing_replays"
                } else {
                    "actual_active_bootstraps"
                };
                f[key] = json!([{"epoch":168,"capture":hold,"admission":ad,"start_ticks":19,"unit":{"Id":uut,"InvocationID":token,"MainPID":"27"},
                    "guard_protection":guard,"observer_config":cap["state"]["observer_row"],"first_worker":cap["state"]["first_worker"]}]);
            }
            if worker {
                cfg["replays"] = json!([row]);
            }
            assert_eq!(from_root(&f, &cfg, &base)?, (i == 2, worker));
            let mut bad = cfg.clone();
            bad["replays"] = json!([{"range":"168","producer_unit":"unrelated.service"}]);
            assert!(from_root(&f, &bad, &base).is_err());
            f["observer"] = json!({"sha256":"different"});
            assert!(from_root(&f, &cfg, &base).is_err());
        }
        Ok(())
    }
}
