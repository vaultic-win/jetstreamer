//! Exact retained cohort's epoch193 -> epoch194 ETA handoff, not replay authority.
use super::*;
const OLD: u64 = 83_807_999;
const NEW: u64 = 84_239_999;
const MANIFEST: &str =
    "/usr/local/lib/jetstreamer/deploy-epochs191-194-target5-20261016-v1/preflight-191-194-v4.json";
const MANIFEST_SHA: &str = "8e16ef3a6f8ae1b2ea3614fbafcb18be34136a8c976e63a386c0fc7c176ce6d0";
const DIRECTORY: &str = "/home/sol/.jetstreamer-private/epochs-191-194-v4-20261009-v1/lane-a/private/destination-a1c8ba888df3256ab55ded6e75ce724aba84a1ed586599353a73fa1d60696cfa/work/root-cohort-191-194/run-2189644-1792144444502274289/archives";
const CONTROLLER: &str = "21da099d82964bb69f6b2bdeca6579fd";
const PRODUCER: &str = "ea93199ed2fa470d99de248c2a10b246";

fn apply(model: &Value, observed: &Value, manifest: &Value) -> Result<Value> {
    let ranges = model["ranges"].as_array().context("cohort191 ranges")?;
    let indices: Vec<_> = ranges
        .iter()
        .enumerate()
        .filter(|(_, r)| r["range"] == "191-194")
        .map(|(i, _)| i)
        .collect();
    ensure!(indices.len() == 1, "cohort191 missing/duplicate range");
    let index = indices[0];
    let r = &ranges[index];
    let old = r["terminal_slot"]
        .as_u64()
        .context("cohort191 model terminal")?;
    ensure!(
        model["schema"] == "jetstreamer-horizon-r2-status-eta-model-v5"
            && model["phase"] == "replay"
            && r["epochs"] == json!([191, 192, 193, 194])
            && r["archive_directory"] == DIRECTORY
            && r["expected_controller_invocation_id"] == CONTROLLER
            && r["expected_producer_invocation_id"] == PRODUCER
            && matches!(old, OLD | NEW)
            && r.get("elapsed_execution_millis").is_none()
            && manifest["manifest"]["schema"] == "jetstreamer-gcs-snapshot-preflight-v4"
            && manifest["manifest"]["first_epoch"] == 191
            && manifest["manifest"]["last_epoch"] == 194
            && manifest["manifest"]["publication_boundary_epoch"] == 194
            && manifest["manifest"]["epoch_slots"] == 432000,
        "cohort191 model/manifest scope differs"
    );
    let offsets = &r["epoch_additional_replay_slots"];
    let allowances = &r["epoch_downstream_allowance_seconds"];
    ensure!(
        offsets.as_object().is_some_and(|o| o.len() == 4)
            && allowances.as_object().is_some_and(|o| o.len() == 4),
        "cohort191 map census differs"
    );
    for epoch in 191..=194 {
        let key = epoch.to_string();
        ensure!(
            offsets[&key] == NEW - old && allowances[&key] == (epoch - 190) * 43200,
            "cohort191 lost queued work or delivery allowance"
        );
    }
    let matches: Vec<_> = observed["replays"]
        .as_array()
        .context("cohort191 observations")?
        .iter()
        .filter(|o| o["range"] == "191-194")
        .collect();
    ensure!(
        matches.len() == 1,
        "cohort191 missing/duplicate observation"
    );
    let o = matches[0];
    let w = &o["useful_work"];
    let terminal = w["last"]["terminal_slot"]
        .as_u64()
        .context("cohort191 observed terminal")?;
    ensure!(
        matches!(terminal, OLD | NEW) && terminal >= old,
        "cohort191 unknown/backward terminal"
    );
    if terminal == old {
        return Ok(model.clone());
    }
    let first = w["first"]["slot"]
        .as_u64()
        .context("cohort191 first slot")?;
    let last = w["last"]["slot"].as_u64().context("cohort191 last slot")?;
    let first_terminal = w["first"]["terminal_slot"]
        .as_u64()
        .context("cohort191 first terminal")?;
    let elapsed = w["elapsed_seconds"].as_f64().context("cohort191 elapsed")?;
    let rate = w["slots_per_second"].as_f64().context("cohort191 rate")?;
    ensure!(
        first >= OLD + 1 - 432000
            && first < last
            && last > OLD
            && last <= NEW
            && ((first_terminal == OLD && first <= OLD) || (first_terminal == NEW && first > OLD))
            && w["sufficient_for_rates"] == true
            && w["slot_delta"].as_u64() == Some(last - first)
            && elapsed.is_finite()
            && elapsed > 0.0
            && rate.is_finite()
            && rate > 0.0
            && (rate - (last - first) as f64 / elapsed).abs() <= rate.abs() * 1e-12,
        "cohort191 reset/inconsistent rate or progress"
    );
    let before = &o["worker_before"];
    let after = &o["worker_after"];
    ensure!(
        o["invocation_binding_stable"] == true
            && o["controller_before"]["invocation_id"] == CONTROLLER
            && o["controller_after"]["invocation_id"] == CONTROLLER
            && o["producer_before"]["invocation_id"] == PRODUCER
            && o["producer_after"]["invocation_id"] == PRODUCER
            && before["matching_workers"] == 1
            && after["matching_workers"] == 1
            && before["pid"].as_u64().is_some_and(|p| p > 0)
            && before["pid"] == after["pid"]
            && before["executable"].as_str().is_some_and(|s| !s.is_empty())
            && before["executable"] == after["executable"]
            && before["executable_beneath_bound_scratch"] == true
            && after["executable_beneath_bound_scratch"] == true,
        "cohort191 owner/worker changed"
    );
    let mut result = model.clone();
    let next = &mut result["ranges"][index];
    next["terminal_slot"] = json!(NEW);
    for epoch in 191..=194 {
        let key = epoch.to_string();
        next["epoch_additional_replay_slots"][&key] = json!(0);
        next["formula"][&key] = json!(format!(
            "round((84239999-last_slot)/observed_slots_per_second+{}); shared cohort import gate remains epoch194",
            (epoch - 190) * 43200
        ));
    }
    let evidence = result["evidence"]
        .as_array_mut()
        .context("cohort191 model evidence")?;
    let binding = json!({"path":MANIFEST,"sha256":MANIFEST_SHA});
    if !evidence.contains(&binding) {
        evidence.push(binding);
    }
    Ok(result)
}

pub(super) fn for_observation(p: &Plan, model: &Value, observer: &Value) -> Result<Value> {
    let ranges = model["ranges"].as_array().context("model ranges")?;
    if !ranges.iter().any(|r| r["range"] == "191-194") {
        return Ok(model.clone());
    }
    ensure!(is_101(p)?, "cohort191 unsupported campaign");
    let manifest = bound_json(
        &Bound {
            path: MANIFEST.into(),
            sha256: MANIFEST_SHA.into(),
        },
        true,
    )?;
    apply(model, observer, &manifest)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Value, Value, Value) {
        let r = json!({"range":"191-194","epochs":[191,192,193,194],"archive_directory":DIRECTORY,
            "expected_controller_invocation_id":CONTROLLER,"expected_producer_invocation_id":PRODUCER,
            "terminal_slot":OLD,"epoch_additional_replay_slots":{"191":432000,"192":432000,"193":432000,"194":432000},
            "epoch_downstream_allowance_seconds":{"191":43200,"192":86400,"193":129600,"194":172800},
            "formula":{"191":"old","192":"old","193":"old","194":"old"}});
        let m = json!({"schema":"jetstreamer-horizon-r2-status-eta-model-v5","phase":"replay","ranges":[r,{"counter":u64::MAX}],"evidence":[],"sample_target_utc":"keep"});
        let worker = json!({"matching_workers":1,"pid":123,"executable":"/bound/worker","executable_beneath_bound_scratch":true});
        let o = json!({"replays":[{"range":"191-194","invocation_binding_stable":true,
            "controller_before":{"invocation_id":CONTROLLER},"controller_after":{"invocation_id":CONTROLLER},
            "producer_before":{"invocation_id":PRODUCER},"producer_after":{"invocation_id":PRODUCER},
            "worker_before":worker,"worker_after":worker,
            "useful_work":{"first":{"slot":OLD-10,"terminal_slot":OLD},"last":{"slot":OLD+90,"terminal_slot":NEW},
                "sufficient_for_rates":true,"slot_delta":100,"elapsed_seconds":200.0,"slots_per_second":0.5,"counter_resets":1}}]});
        let f = json!({"manifest":{"schema":"jetstreamer-gcs-snapshot-preflight-v4","first_epoch":191,"last_epoch":194,"publication_boundary_epoch":194,"epoch_slots":432000}});
        (m, o, f)
    }
    #[test]
    fn crossing_window_keeps_all_work_delivery_order_clocks_and_other_ranges() {
        let (m, o, f) = fixture();
        let next = apply(&m, &o, &f).unwrap();
        assert_eq!(next["ranges"][1], m["ranges"][1]);
        assert_eq!(next["sample_target_utc"], m["sample_target_utc"]);
        assert_eq!(
            next["ranges"][0]["epoch_downstream_allowance_seconds"],
            m["ranges"][0]["epoch_downstream_allowance_seconds"]
        );
        assert_eq!(next["ranges"][0]["terminal_slot"], NEW);
        for epoch in 191..=194 {
            let k = epoch.to_string();
            assert_eq!(
                m["ranges"][0]["terminal_slot"].as_u64().unwrap()
                    + m["ranges"][0]["epoch_additional_replay_slots"][&k]
                        .as_u64()
                        .unwrap(),
                next["ranges"][0]["terminal_slot"].as_u64().unwrap()
                    + next["ranges"][0]["epoch_additional_replay_slots"][&k]
                        .as_u64()
                        .unwrap()
            );
        }
        assert_eq!(apply(&next, &o, &f).unwrap(), next);
    }
    #[test]
    fn handoff_rejects_resets_wrong_owner_worker_and_invented_rate() {
        let (m, o, f) = fixture();
        for (ptr, v) in [
            ("/replays/0/useful_work/slot_delta", json!(101)),
            ("/replays/0/useful_work/slots_per_second", json!(1.0)),
            ("/replays/0/useful_work/last/terminal_slot", json!(NEW + 1)),
            (
                "/replays/0/producer_after/invocation_id",
                json!("different"),
            ),
            ("/replays/0/worker_after/pid", json!(124)),
            ("/replays/0/worker_before/matching_workers", json!(0)),
        ] {
            let mut bad = o.clone();
            *bad.pointer_mut(ptr).unwrap() = v;
            assert!(apply(&m, &bad, &f).is_err(), "{ptr}");
        }
        for (ptr, v) in [
            ("/ranges/0/epoch_additional_replay_slots/191", json!(0)),
            ("/ranges/0/epoch_downstream_allowance_seconds/192", json!(0)),
            (
                "/ranges/0/expected_controller_invocation_id",
                json!("different"),
            ),
        ] {
            let mut bad = m.clone();
            *bad.pointer_mut(ptr).unwrap() = v;
            assert!(apply(&bad, &o, &f).is_err(), "{ptr}");
        }
        let mut bad = f;
        bad["manifest"]["publication_boundary_epoch"] = json!(195);
        assert!(apply(&m, &o, &bad).is_err());
    }

    #[test]
    fn fully_successor_window_and_pre_handoff_samples_keep_the_same_total() {
        let (m, mut o, f) = fixture();
        let work = &mut o["replays"][0]["useful_work"];
        work["first"] = json!({"slot":OLD+1,"terminal_slot":NEW});
        work["last"] = json!({"slot":OLD+101,"terminal_slot":NEW});
        let next = apply(&m, &o, &f).unwrap();
        assert_eq!(next["ranges"][0]["terminal_slot"], NEW);
        let work = &mut o["replays"][0]["useful_work"];
        work["first"] = json!({"slot":OLD-101,"terminal_slot":OLD});
        work["last"] = json!({"slot":OLD-1,"terminal_slot":OLD});
        assert_eq!(apply(&m, &o, &f).unwrap(), m);
        assert!(apply(&next, &o, &f).is_err());
    }
}
