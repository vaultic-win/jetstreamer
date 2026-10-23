//! Same-sample capacity decisions. This receipt is never launch authority.
use super::*;
const PROVEN: u64 = 5;
const ROOT141_PEAK: u64 = 768 << 30;
const ROOT141_PROTECTED: u64 = 3_572_465_819_078;

pub(super) fn decision(p: &Plan, o: &Value, ledger: &Value) -> Result<Value> {
    if !is_101(p)? {
        return Ok(Value::Null);
    }
    let mut live = BTreeMap::new();
    for a in ledger["active"]
        .as_array()
        .context("capacity active census")?
    {
        if a["phase"] != "replay" {
            continue;
        }
        let id = a["producer"]["InvocationID"]
            .as_str()
            .context("capacity producer identity")?;
        ensure!(
            a["producer"]["ActiveState"] == "active"
                && a["producer"]["SubState"] == "running"
                && a["producer"]["NRestarts"] == "0",
            "capacity active owner is not live"
        );
        let owner =
            json!({"unit":a["producer"]["Id"],"invocation_id":id,"scratch_path":a["scratch_path"]});
        if let Some(old) = live.insert(id.to_string(), owner.clone()) {
            ensure!(old == owner, "capacity duplicate owner conflicts");
        }
    }
    let rows = o["replays"]
        .as_array()
        .context("capacity observer census")?;
    let clean = !rows.is_empty()
        && rows.len() == live.len()
        && rows.iter().all(|r| {
            r["invocation_binding_stable"] == true
                && r["producer_after"]["invocation_id"]
                    .as_str()
                    .is_some_and(|id| live.contains_key(id))
                && r["producer_after"]["restarts"] == 0
                && r["controller_after"]["restarts"] == 0
                && r["worker_after"]["matching_workers"] == 1
                && r["worker_after"]["vmas"]
                    .as_u64()
                    .is_some_and(|v| v > 0 && v < 800000)
                && r["useful_work"]["sufficient_for_rates"] == true
                && [
                    "memory_events.oom",
                    "memory_events.oom_kill",
                    "memory_events.oom_group_kill",
                    "memory_events.max",
                ]
                .iter()
                .all(|k| r["cross_sample"]["producer_cgroup_counter_delta"][*k] == 0)
        });
    let free = o["filesystem"]["conservative_available_bytes"]
        .as_u64()
        .context("capacity free bytes")?;
    let memory = o["host_memory"]["conservative_available_kib"]
        .as_u64()
        .context("capacity memory")?;
    // This candidate envelope retains all five protected growth reservations.
    // It is only a preliminary fit: the independent admission recomputes the
    // century floor, extends growth maxima, observes guards and checks races.
    let required = ROOT141_PROTECTED
        .checked_add(ROOT141_PEAK)
        .context("capacity arithmetic")?;
    let original = original141::enabled(p);
    let terminal_repair = terminal141::failure_recorded(ledger);
    let diagnostic_live: BTreeSet<_> = o["diagnostic_replays"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|r| {
            r["invocation_binding_stable"] == true
                && r["producer_after"]["active_state"] == "active"
                && r["producer_after"]["sub_state"] == "running"
                && r["producer_after"]["restarts"] == 0
        })
        .filter_map(|r| r["producer_after"]["invocation_id"].as_str())
        .collect();
    let preliminary = !original
        && clean
        && live.len() == 5
        && free >= required
        && memory >= 192 * 1024 * 1024
        && o["vm_max_map_count"].as_u64().is_some_and(|v| v >= 4194304);
    let (gate, action) = if original {
        (
            "expanded-fleet qualification and next disjoint runtime/resource bound",
            "Accept a clean expanded-fleet coordinated window before considering another experimental lane; stage the next disjoint repair/singleton meanwhile.",
        )
    } else if !clean {
        (
            "current-fleet stability/progress/pressure gate",
            "Diagnose the exact failing observation before further scaling; preserve healthy owners and repair failed work.",
        )
    } else if live.len() != 5 {
        (
            "changed live-owner census invalidates the five-lane candidate envelope",
            "Recompute invocation-bound growth from the authenticated terminal/handoff event and promptly backfill qualified capacity.",
        )
    } else if !preliminary {
        (
            "candidate disk/memory/VMA envelope",
            "Recompute current growth maxima and exact limiting resource; qualify the smallest bounded alternative that fits without reducing reserves.",
        )
    } else if terminal_repair {
        (
            "epoch186 runtime/input readiness and fresh guarded admission; epoch141 execution mismatch remains a priority repair",
            "Extract and diagnose the sealed failed141 transaction/account evidence. Freshly qualify/admit the disjoint compatible186 singleton while repairing141; do not blindly rerun the failed141 worker or scale another experimental lane before a clean expanded sample.",
        )
    } else {
        (
            "private141 fresh admission, actual one-worker guard fire, and fleet handoff",
            "Finish and test the Rust growth-adoption/guard-capture path, seal it, run fresh admission, then launch the guarded private141 root experiment; no seventh lane before a clean expanded sample.",
        )
    };
    Ok(
        json!({"schema":"jetstreamer-horizon-capacity-decision-v2","question":"Can I fit another disjoint lane now?",
        "sampled_at_utc":p.sample_target_utc,"candidate":if original {"next disjoint qualified repair/singleton"} else if terminal_repair {"epoch186 compatible disjoint singleton, subject to fresh claim census"} else {"private epoch141 original-entry partial-root qualification"},
        "live_production_lanes":live.len(),"proven_production_lanes":PROVEN,"live_owners":live,
        "live_private_qualification_lanes":diagnostic_live.len(),"live_total_replay_lanes":live.len()+diagnostic_live.len(),
        "proven_point_evidence":{"path":"/var/lib/jetstreamer-horizon-observe-eleven-focus-20261017-v1/sample-20261023T063958Z.json","sha256":"87d714a3652649a2bcf2bd0f0629d3638785e76e45c9286bfd62fb7aeb0d1b99"},
        "private141_profile_adopted":original,"current_production_sample_clean":clean,"sampled_free_bytes":free,"sampled_memory_available_kib":memory,
        "vm_max_map_count":o["vm_max_map_count"],"candidate_incremental_peak_bytes":if original {Value::Null} else {json!(ROOT141_PEAK)},
        "prospective_protected_bytes":if original {Value::Null} else {json!(ROOT141_PROTECTED)},
        "prospective_required_initial_free_bytes":if original {Value::Null} else {json!(required)},
        "prospective_disk_headroom_bytes":if original {Value::Null} else {json!(i128::from(free)-i128::from(required))},
        "preliminary_resource_fit":preliminary,"admission_eligible":false,"limiting_gate":gate,"next_action":action,
        "source":"same accepted observer and authenticated fleet; prospective bounds require separate fresh admission",
        "new_resource_samples":0,"replay_launch_authorized":false,"remote_mutations":false} ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "root exact accepted0639 evidence; immutable reads only, no resource observation"]
    fn actual_five_lane_capacity_is_explicit_and_not_admission() {
        let (p, ..) = crate::tests::fixture101();
        let o = bound_json(&Bound { path:"/var/lib/jetstreamer-horizon-observe-eleven-focus-20261017-v1/sample-20261023T063958Z.json".into(),sha256:"87d714a3652649a2bcf2bd0f0629d3638785e76e45c9286bfd62fb7aeb0d1b99".into() },false).unwrap();
        let f = bound_json(&Bound { path:"/var/lib/jetstreamer-horizon-fleet-101-200-20261019-v1/fleet-20261023T063958Z.json".into(),sha256:"3ebc5a6e97556ece0ec5d4b64753086cbb6ff0a1a9479d2963ce54dce44a656a".into() },false).unwrap();
        let d = decision(&p, &o, &f).unwrap();
        assert_eq!(d["live_production_lanes"], 5);
        assert_eq!(d["current_production_sample_clean"], true);
        assert_eq!(d["preliminary_resource_fit"], true);
        assert_eq!(d["prospective_disk_headroom_bytes"], 75522720314u64);
        assert_eq!(d["admission_eligible"], false);
    }
    #[test]
    fn counts_invocations_not_cohort_epochs_and_never_grants_admission() {
        let (p, ..) = crate::tests::fixture101();
        let owner = json!({"epoch":152,"phase":"replay","producer":{"Id":"owner.service","InvocationID":"a".repeat(32),"ActiveState":"active","SubState":"running","NRestarts":"0"},"scratch_path":"/scratch"});
        let mut queued = owner.clone();
        queued["epoch"] = json!(153);
        let o = json!({"replays":[],"filesystem":{"conservative_available_bytes":5u64<<40},"host_memory":{"conservative_available_kib":600u64<<20},"vm_max_map_count":4194304});
        let d = decision(&p, &o, &json!({"active":[owner,queued]})).unwrap();
        assert_eq!(d["live_production_lanes"], 1);
        assert_eq!(d["proven_production_lanes"], 5);
        assert_eq!(d["admission_eligible"], false);
        assert_eq!(d["preliminary_resource_fit"], false);
        assert!(d["limiting_gate"].as_str().unwrap().contains("stability"));
    }
}
