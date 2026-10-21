//! Exact epoch157 v1.5.6 -> v1.5.8 ETA handoff. No replay/runtime authority.
use super::*;

const MANIFEST: &str = "/usr/local/lib/jetstreamer/deploy-epochs155-157-runtime-boundaries-md5-20261012-v1/preflight-157-v4.json";
const MANIFEST_SHA: &str = "c8b9a9195cd07f2ab40e58f448b7ef2419a77ffb9c75231e1a525183dbea3624";
// compatibility.rs: handoff snapshot and v1.5.8 transition end (exclusive)-1.
const OLD: u64 = 68_140_176;
const NEW: u64 = 68_255_999;
const DIRECTORY: &str = "/home/sol/.jetstreamer-private/epochs150-173-20260923-v2/lane-j/output";

fn range(model: &Value) -> Result<&Value> {
    let ranges = model["ranges"].as_array().context("missing ranges")?;
    let matches: Vec<_> = ranges.iter().filter(|r| r["range"] == "157").collect();
    ensure!(matches.len() == 1, "157 handoff requires one exact range");
    Ok(matches[0])
}

fn validate(p: &Plan, model: &Value, manifest: &Value) -> Result<()> {
    let binding = p
        .epoch157_terminal_handoff
        .as_ref()
        .context("missing157 binding")?;
    ensure!(
        is_101(p)? && binding.path == Path::new(MANIFEST) && binding.sha256 == MANIFEST_SHA,
        "unsupported157 manifest/profile"
    );
    ensure!(
        manifest["manifest"]["schema"] == "jetstreamer-gcs-snapshot-preflight-v4"
            && manifest["manifest"]["first_epoch"] == 157
            && manifest["manifest"]["last_epoch"] == 157
            && manifest["manifest"]["publication_boundary_epoch"] == 157
            && manifest["manifest"]["epoch_slots"] == 432_000,
        "157 manifest scope changed"
    );
    let r = range(model)?;
    ensure!(
        model["schema"] == "jetstreamer-horizon-r2-status-eta-model-v5"
            && model["phase"] == "replay"
            && r["epochs"] == json!([157])
            && r["archive_directory"] == DIRECTORY
            && r["terminal_slot"] == OLD
            && r["epoch_additional_replay_slots"] == json!({"157": NEW - OLD})
            && r["epoch_downstream_allowance_seconds"] == json!({"157":43_200})
            && r.get("elapsed_execution_millis").is_none(),
        "157 predecessor is not the qualified pre-handoff model"
    );
    Ok(())
}

pub(super) fn preflight(p: &Plan, model: &Value) -> Result<()> {
    if let Some(binding) = &p.epoch157_terminal_handoff {
        validate(p, model, &bound_json(binding, true)?)?;
    }
    Ok(())
}

pub(super) fn enable(next: &mut Plan, model: &Value) -> Result<()> {
    ensure!(
        next.epoch157_terminal_handoff.is_none(),
        "157 handoff already enabled"
    );
    next.epoch157_terminal_handoff = Some(Bound {
        path: MANIFEST.into(),
        sha256: MANIFEST_SHA.into(),
    });
    preflight(next, model)
}

fn apply(p: &Plan, model: &Value, observer: &Value) -> Result<Value> {
    let mut result = model.clone();
    let Some(binding) = &p.epoch157_terminal_handoff else {
        return Ok(result);
    };
    let observations = observer["replays"]
        .as_array()
        .context("missing observations")?;
    let matches: Vec<_> = observations
        .iter()
        .filter(|r| r["range"] == "157")
        .collect();
    ensure!(matches.len() == 1, "157 observation missing/duplicate");
    let observed = matches[0];
    let work = &observed["useful_work"];
    let terminal = work["last"]["terminal_slot"]
        .as_u64()
        .context("157 terminal missing")?;
    ensure!(
        terminal == OLD || terminal == NEW,
        "unqualified157 terminal"
    );
    ensure!(
        work["sufficient_for_rates"] == true,
        "157 missing rate window"
    );
    if terminal == OLD {
        ensure!(
            work["first"]["terminal_slot"] == OLD,
            "157 backward runtime transition"
        );
        return Ok(result);
    }
    let first_terminal = work["first"]["terminal_slot"]
        .as_u64()
        .context("157 first terminal")?;
    let first_slot = work["first"]["slot"].as_u64().context("157 first slot")?;
    let last_slot = work["last"]["slot"].as_u64().context("157 last slot")?;
    ensure!(
        ((first_terminal == OLD && first_slot <= OLD)
            || (first_terminal == NEW && first_slot > OLD))
            && first_slot >= 67_824_000
            && last_slot > OLD
            && last_slot <= NEW
            && last_slot > first_slot,
        "157 successor progress outside qualified interval"
    );
    // Transaction/update counters legitimately reset at the runtime handoff.
    // Slot counters must not: the observer's accumulated delta must equal the
    // global first/last difference. A crossing window includes handoff latency
    // in its measured wall-time rate; never splice or synthesize a faster rate.
    let delta = last_slot - first_slot;
    let elapsed = work["elapsed_seconds"]
        .as_f64()
        .context("157 elapsed missing")?;
    let rate = work["slots_per_second"]
        .as_f64()
        .context("157 slot rate missing")?;
    let expected_rate = delta as f64 / elapsed;
    ensure!(
        work["slot_delta"].as_u64() == Some(delta)
            && elapsed.is_finite()
            && elapsed > 0.0
            && rate.is_finite()
            && rate > 0.0
            && (rate - expected_rate).abs() <= expected_rate.abs() * 1e-12,
        "157 reset or inconsistent slot-rate evidence"
    );
    let before = &observed["worker_before"];
    let after = &observed["worker_after"];
    ensure!(
        before["matching_workers"] == 1
            && after["matching_workers"] == 1
            && before["pid"].as_u64().is_some_and(|pid| pid > 0)
            && before["pid"] == after["pid"]
            && before["executable"].as_str().is_some_and(|s| !s.is_empty())
            && before["executable"] == after["executable"]
            && before["executable_beneath_bound_scratch"] == true
            && after["executable_beneath_bound_scratch"] == true,
        "157 worker changed during handoff sample"
    );
    let r = result["ranges"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|r| r["range"] == "157")
        .unwrap();
    // OLD-last + (NEW-OLD) == NEW-last. Preserve all queued-slot work,
    // downstream allowance, owner identities and original elapsed clock.
    r["terminal_slot"] = json!(NEW);
    r["epoch_additional_replay_slots"] = json!({"157":0});
    r["formula"]["157"] = json!("round((68255999-last_slot)/observed_slots_per_second+43200)");
    result["evidence"]
        .as_array_mut()
        .context("missing evidence")?
        .push(serde_json::to_value(binding)?);
    Ok(result)
}

pub(super) fn for_observation(p: &Plan, model: &Value, observer: &Value) -> Result<Value> {
    preflight(p, model)?;
    apply(p, model, observer)
}

pub(super) fn consume(next: &mut Plan, accepted_model: &Value) -> Result<()> {
    if next.epoch157_terminal_handoff.is_some() && range(accepted_model)?["terminal_slot"] == NEW {
        next.epoch157_terminal_handoff = None;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (Plan, Value, Value, Value) {
        let (mut p, mut model, _, _, _, _, _, mut observer) = crate::tests::fixture101();
        p.expected_epochs = vec![157];
        p.epoch157_terminal_handoff = Some(Bound {
            path: MANIFEST.into(),
            sha256: MANIFEST_SHA.into(),
        });
        let r = &mut model["ranges"][0];
        r["range"] = json!("157");
        r["epochs"] = json!([157]);
        r["archive_directory"] = json!(DIRECTORY);
        r["terminal_slot"] = json!(OLD);
        r["epoch_additional_replay_slots"] = json!({"157":NEW-OLD});
        r["epoch_downstream_allowance_seconds"] = json!({"157":43_200});
        r["formula"] = json!({"157":"prior formula"});
        let o = &mut observer["replays"][0];
        o["range"] = json!("157");
        o["useful_work"] = json!({"first":{"terminal_slot":NEW,"slot":OLD+10},
            "last":{"terminal_slot":NEW,"slot":OLD+100},"counter_resets":0,
            "sufficient_for_rates":true,"slots_per_second":1.5,"slot_delta":90,"elapsed_seconds":60.0});
        let worker = json!({"pid":123,"matching_workers":1,"executable":"/bound/worker",
            "executable_beneath_bound_scratch":true});
        o["worker_before"] = worker.clone();
        o["worker_after"] = worker;
        let manifest = json!({"manifest":{"schema":"jetstreamer-gcs-snapshot-preflight-v4",
            "first_epoch":157,"last_epoch":157,"publication_boundary_epoch":157,"epoch_slots":432000}});
        (p, model, observer, manifest)
    }

    #[test]
    fn exact_handoff_preserves_work_clock_allowance_and_other_ranges() {
        let (p, model, observer, manifest) = fixture();
        validate(&p, &model, &manifest).unwrap();
        let original = model.clone();
        let next = apply(&p, &model, &observer).unwrap();
        assert_eq!(model, original);
        let old = range(&model).unwrap();
        let new = range(&next).unwrap();
        let slot = observer["replays"][0]["useful_work"]["last"]["slot"]
            .as_u64()
            .unwrap();
        assert_eq!(
            OLD + old["epoch_additional_replay_slots"]["157"]
                .as_u64()
                .unwrap()
                - slot,
            NEW - slot
                + new["epoch_additional_replay_slots"]["157"]
                    .as_u64()
                    .unwrap()
        );
        let mut expected = old.clone();
        expected["terminal_slot"] = new["terminal_slot"].clone();
        expected["epoch_additional_replay_slots"] = new["epoch_additional_replay_slots"].clone();
        expected["formula"] = new["formula"].clone();
        assert_eq!(new, &expected);
        assert!(new.get("elapsed_execution_millis").is_none());
        assert_eq!(next["sample_target_utc"], model["sample_target_utc"]);
        validate_observation(
            &p,
            &next,
            &observer,
            utc_seconds(&p.sample_target_utc).unwrap() + 60,
        )
        .unwrap();
    }

    #[test]
    fn pending_handoff_does_not_change_old_terminal_model() {
        let (p, model, mut observer, _) = fixture();
        let work = &mut observer["replays"][0]["useful_work"];
        work["first"]["terminal_slot"] = json!(OLD);
        work["last"]["terminal_slot"] = json!(OLD);
        assert_eq!(apply(&p, &model, &observer).unwrap(), model);
    }

    #[test]
    fn slot_resets_worker_races_and_unknown_terminals_fail_closed() {
        let (p, model, observer, _) = fixture();
        for (pointer, value) in [
            ("/replays/0/useful_work/first/terminal_slot", json!(OLD - 1)),
            ("/replays/0/useful_work/slot_delta", json!(91)),
            ("/replays/0/useful_work/slots_per_second", json!(2.0)),
            ("/replays/0/useful_work/elapsed_seconds", json!(0.0)),
            ("/replays/0/useful_work/sufficient_for_rates", json!(false)),
            ("/replays/0/useful_work/last/terminal_slot", json!(NEW + 1)),
            ("/replays/0/useful_work/first/slot", json!(OLD)),
            ("/replays/0/useful_work/first/slot", json!(NEW)),
            ("/replays/0/worker_after/pid", json!(124)),
            ("/replays/0/worker_before/matching_workers", json!(2)),
            ("/replays/0/worker_after/executable", json!("/other/worker")),
            (
                "/replays/0/worker_after/executable_beneath_bound_scratch",
                json!(false),
            ),
        ] {
            let mut bad = observer.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(apply(&p, &model, &bad).is_err(), "accepted {pointer}");
        }
    }

    #[test]
    fn crossing_window_includes_handoff_latency_but_never_borrows_reset_counters() {
        let (p, model, mut observer, _) = fixture();
        let work = &mut observer["replays"][0]["useful_work"];
        work["first"]["terminal_slot"] = json!(OLD);
        work["first"]["slot"] = json!(OLD - 20);
        work["slot_delta"] = json!(120);
        work["elapsed_seconds"] = json!(240.0);
        work["slots_per_second"] = json!(0.5);
        work["counter_resets"] = json!(2);
        assert_eq!(
            range(&apply(&p, &model, &observer).unwrap()).unwrap()["terminal_slot"],
            NEW
        );
        // A replayed slot counter reset would add a huge absolute slot to the
        // observer accumulator even if first/last looked monotone.
        observer["replays"][0]["useful_work"]["slot_delta"] = json!(OLD + 120);
        assert!(apply(&p, &model, &observer).is_err());
    }

    #[test]
    fn changed_owner_is_not_hidden_by_model_transition() {
        let (p, model, mut observer, _) = fixture();
        observer["replays"][0]["producer_after"]["invocation_id"] = json!("e".repeat(32));
        let next = apply(&p, &model, &observer).unwrap();
        assert!(
            validate_observation(
                &p,
                &next,
                &observer,
                utc_seconds(&p.sample_target_utc).unwrap() + 60
            )
            .is_err()
        );
    }

    #[test]
    fn scope_offsets_allowances_manual_clocks_and_wrong_proof_are_rejected() {
        let (p, model, _, manifest) = fixture();
        for (pointer, value) in [
            ("/ranges/0/epochs", json!([157, 158])),
            ("/ranges/0/terminal_slot", json!(NEW)),
            ("/ranges/0/archive_directory", json!("/other")),
            (
                "/ranges/0/epoch_additional_replay_slots/157",
                json!(NEW - OLD - 1),
            ),
            ("/ranges/0/epoch_downstream_allowance_seconds/157", json!(0)),
        ] {
            let mut bad = model.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(validate(&p, &bad, &manifest).is_err(), "accepted {pointer}");
        }
        let mut bad = model.clone();
        bad["ranges"][0]["elapsed_execution_millis"] = json!(0);
        assert!(validate(&p, &bad, &manifest).is_err());
        let mut bad_manifest = manifest.clone();
        bad_manifest["manifest"]["publication_boundary_epoch"] = json!(158);
        assert!(validate(&p, &model, &bad_manifest).is_err());
        let mut bad_plan = p;
        bad_plan.epoch157_terminal_handoff.as_mut().unwrap().sha256 = "f".repeat(64);
        assert!(validate(&bad_plan, &model, &manifest).is_err());
    }

    #[test]
    fn successor_drops_only_consumed_handoff_and_keeps_pending_one() {
        let (mut p, model, observer, _) = fixture();
        consume(&mut p, &model).unwrap();
        assert!(p.epoch157_terminal_handoff.is_some());
        let accepted = apply(&p, &model, &observer).unwrap();
        consume(&mut p, &accepted).unwrap();
        assert!(p.epoch157_terminal_handoff.is_none());
        assert_eq!(apply(&p, &accepted, &observer).unwrap(), accepted);
    }

    #[test]
    fn missing_or_changed_manifest_cannot_preflight() {
        let (mut p, model, _, _) = fixture();
        p.epoch157_terminal_handoff.as_mut().unwrap().path = "/does-not-exist/manifest.json".into();
        assert!(preflight(&p, &model).is_err());
    }

    #[test]
    #[ignore = "requires root and exact immutable host manifest plus separately bound accepted model"]
    fn host_manifest_and_predecessor_preflight() {
        let (mut p, _, _, _) = fixture();
        p.epoch157_terminal_handoff = None;
        let model = bound_json(
            &Bound {
                path: env::var("HORIZON_TERMINAL157_MODEL_PATH").unwrap().into(),
                sha256: env::var("HORIZON_TERMINAL157_MODEL_SHA256").unwrap(),
            },
            true,
        )
        .unwrap();
        enable(&mut p, &model).unwrap();
        assert!(p.epoch157_terminal_handoff.is_some());
        assert!(enable(&mut p, &model).is_err());
    }
}
