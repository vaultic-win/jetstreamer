//! One hash-bound narrative successor; no repair, claim or integrity transition.
use super::*;

const CONTROL_PATH: &str =
    "/usr/local/lib/jetstreamer/horizon-repair-control-20261024-v247/backlog.json";
const CONTROL_SHA: &str = "a3d9c5a7b6fed49aa8d5634de108700963746e1837433cdf6b21acb03515451c";
const OLD_141: &str = "Advance the freshly built corrected/capped v1.4.25 worker to canonical root61328765 under its512GiB whole-root and5day experimental stops. Preserve all prior diagnostic roots and the strictly passed60912005vote evidence. Reassess actual growth/RSS/pressure at each coordinated sample; this budget is not an adopted full-cold peak. Root success qualifies only the416766slot prefix;15234epoch141suffix slots and independent complete-span/full/plugin/delivery gates remain before a ready pair.";
const OLD_185: &str = "Controlled disk-floor stop at80099168 before80351999. Preserve partial/scratch/launch/guard proof; establish an actual durable native checkpoint or independently qualified cold recovery, then fresh guarded capacity admission. No resume or growth-release credit. Old185 status is stale pending qualified lifecycle; no R2 deletion authorized.";
const OLD_185_SPACED: &str = "Controlled disk-floor stop at 80099168 before 80351999. Preserve partial/scratch/launch/guard proof; establish an actual durable native checkpoint or independently qualified cold recovery, then fresh guarded capacity admission. No resume or growth-release credit. Old 185 status is stale pending qualified lifecycle; no R2 deletion authorized.";
const NEXT_141: &str = "Keep epoch 141 failed and its repair open. The hash-bound v247 snapshot recorded bounded native export and durable first-prefix qualification: synthetic worker suites and fresh-child export fixtures passed, while production restore, the canonical root and a complete epoch remained unqualified. That snapshot recorded the compiled durable node suite and a passed output-parent permission test, with 22 EROFS failures from temporary-directory creation in read-only source; it is not a statement of the latest rerun result. Advance from newer authenticated completion evidence and address the next outstanding gate. If the durable suite remains unqualified, review the sealed exact-binary rerun from a private target working directory with source read-only, a serialized lease and fresh guard/resource admission. Preserve prior failed attempts, diagnostic roots and data reservations. Mainnet restore/replay, continuation, canonical-root proof, full/current-plugin/boundary checks, delivery and publication require their own evidence and admission; this note authorizes none.";
const NEXT_185: &str = "Keep epoch 185 failed and its repair open. The hash-bound v247 snapshot recorded diagnostic custody, original future-growth closure, authenticated status cleanup and retirement of the failed partial; none established replay recovery or a ready archive. At that snapshot, scratch and its root inode were retained and no scratch deletion was recorded. Determine the latest disposition from newer authenticated completion evidence rather than treating this historical retention statement as current. If cleanup remains outstanding, finish any required bounded fleet-reader qualification, obtain a fresh contents-only CHECK, review its exact ledger and separately admit execution; do not repeat completed cleanup. Preserve custody, closure, retirement and failed-owner evidence, all surviving reservations and guard floors. No physical-space credit, resume, new replay, scratch deletion, canonical delivery, R2 mutation or further retirement is authorized by this note.";

#[derive(Clone, Copy)]
enum Note {
    Epoch141,
    Epoch185,
}
impl Note {
    fn key(self) -> &'static str {
        match self {
            Self::Epoch141 => "141",
            Self::Epoch185 => "185",
        }
    }
    fn stale(self, action: &Value) -> bool {
        match self {
            Self::Epoch141 => action == OLD_141,
            Self::Epoch185 => action == OLD_185 || action == OLD_185_SPACED,
        }
    }
    fn next(self) -> &'static str {
        match self {
            Self::Epoch141 => NEXT_141,
            Self::Epoch185 => NEXT_185,
        }
    }
}

fn matches(binding: &Bound) -> bool {
    binding.path == Path::new(CONTROL_PATH) && binding.sha256 == CONTROL_SHA
}

fn validate_control(v: &Value) -> Result<()> {
    ensure!(
        v["schema"] == "jetstreamer-horizon-repair-control-v2"
            && v["host"] == "dev-samjohnson"
            && v["assigned_range"] == "101-200"
            && v["goal_complete"] == false
            && v["canonical_remote_archive_overwrite_or_deletion"] == false,
        "repair gate-note control scope differs"
    );
    let a = &v["epoch141"];
    ensure!(
        a["state"] == "active-repair; bounded isolated native export qualification"
            && a["mainnet_probe_not_admitted"] == true
            && a["failed_attempts_preserved"] == true
            && a["synthetic_results"]["old_data_claim_released"] == false
            && a["synthetic_results"]["all_three_dispatch_fresh_child_fixtures_passed"] == true
            && a["durable_suite"]["passed"] == 335
            && a["durable_suite"]["failed"] == 22
            && a["durable_suite"]["ignored"] == 5
            && a["durable_suite"]["invocation_id"] == "ad5e2f9874db468699663ea76a0a71c0"
            && a["durable_suite"]["failure_preserved"] == true
            && a["rerun_proposal"]["path"]
                == "/usr/local/lib/jetstreamer/horizon-epoch141-first-prefix-durable-tests-package-20261024-v1/rerun-proposal.json"
            && a["rerun_proposal"]["sha256"]
                == "a9de10f8da413df72dbb87d4cd6894e0e805d97a25599d1ade01c4b0cdb6b0ce",
        "repair gate-note control does not preserve bounded 141 qualification"
    );
    let b = &v["epoch185"];
    let closure = &b["original_future_growth_disposition"];
    let retirement = &b["archive_retirement"];
    ensure!(
        b["state"] == "failed-needs-repair; authorized diagnostic holding only"
            && b["custody_completion_not_yet_verified"] == false
            && b["status_authenticated_absent_without_canonical_delivery_owner"] == true
            && b["custody"]["sha256"]
                == "1b33b74b22f4c7a1f67e3439fc97a1e1be674e5f4291d40cc815e26c139951fb"
            && b["custody"]["noncanonical_diagnostic_only"] == true
            && closure["closure"]["sha256"]
                == "7a57f946c5e6cb08bc9a99e8a6b76a6ed33fffb013a673715924192a327d0553"
            && closure["native_success_and_empty_cgroup_verified"] == true
            && closure["original_claim_after_bytes"] == 0
            && closure["physical_space_credit_bytes"] == 0
            && closure["guards_changed"] == false
            && closure["source_scratch_inputs_retained"] == true
            && closure["repair_still_open"] == true
            && retirement["completion"]["sha256"]
                == "3b28d55ad611bb7dedc1965ddc7f497c417444c3c80d959be62f85f09d6e13bb"
            && retirement["native_success_pid0_empty_cgroup"] == true
            && retirement["actual_free_space_delta_claimed"] == false
            && retirement["source_absent"] == true
            && retirement["quarantine_absent"] == true
            && retirement["r2_mutations"] == false
            && retirement["failure_repaired"] == false
            && b["scratch_cleanup"]["deletion_performed"] == false
            && b["scratch_cleanup"]["scratch_inode_to_preserve"] == 100270084,
        "repair gate-note control does not preserve terminal 185 disposition"
    );
    Ok(())
}

fn correct(fleet: &mut Value, note: Note, binding: &Bound, control: &Value) -> Result<bool> {
    if !matches(binding) {
        return Ok(false);
    }
    validate_control(control)?;
    let gate = &fleet["gates"][note.key()];
    if gate["state"] != "failed-needs-repair" || !note.stale(&gate["next_action"]) {
        return Ok(false);
    }
    ensure!(
        gate["evidence"]
            .as_array()
            .is_some_and(|e| e.contains(&json!({"path":binding.path,"sha256":binding.sha256}))),
        "repair gate-note control must remain in gate evidence"
    );
    fleet["gates"][note.key()]["next_action"] = json!(note.next());
    Ok(true)
}

/// Run after terminal/original derivations so they cannot restore obsolete text.
/// This is opt-in through the existing immutable additional-gate-evidence map.
pub(super) fn apply(p: &Plan, fleet: &mut Value) -> Result<()> {
    for note in [Note::Epoch141, Note::Epoch185] {
        if let Some(evidence) = p.additional_gate_evidence.get(note.key()) {
            for binding in evidence.iter().filter(|b| matches(b)) {
                correct(fleet, note, binding, &bound_json(binding, true)?)?;
            }
        }
    }
    Ok(())
}

/// Preflight authenticates the opt-in control before derive appends its binding.
pub(super) fn validate(p: &Plan) -> Result<()> {
    for epoch in ["141", "185"] {
        if let Some(evidence) = p.additional_gate_evidence.get(epoch) {
            for binding in evidence.iter().filter(|b| matches(b)) {
                validate_control(&bound_json(binding, true)?)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Predicate fixture only; production always rehashes the genuine root-owned
    // v247 bytes through bound_json. This fixture is not an operational receipt.
    fn control() -> Value {
        json!({
            "schema":"jetstreamer-horizon-repair-control-v2","host":"dev-samjohnson",
            "assigned_range":"101-200","goal_complete":false,
            "canonical_remote_archive_overwrite_or_deletion":false,
            "epoch141":{
                "state":"active-repair; bounded isolated native export qualification",
                "mainnet_probe_not_admitted":true,"failed_attempts_preserved":true,
                "synthetic_results":{"old_data_claim_released":false,
                    "all_three_dispatch_fresh_child_fixtures_passed":true},
                "durable_suite":{"passed":335,"failed":22,"ignored":5,
                    "invocation_id":"ad5e2f9874db468699663ea76a0a71c0","failure_preserved":true},
                "rerun_proposal":{
                    "path":"/usr/local/lib/jetstreamer/horizon-epoch141-first-prefix-durable-tests-package-20261024-v1/rerun-proposal.json",
                    "sha256":"a9de10f8da413df72dbb87d4cd6894e0e805d97a25599d1ade01c4b0cdb6b0ce"}},
            "epoch185":{
                "state":"failed-needs-repair; authorized diagnostic holding only",
                "custody_completion_not_yet_verified":false,
                "status_authenticated_absent_without_canonical_delivery_owner":true,
                "custody":{"sha256":"1b33b74b22f4c7a1f67e3439fc97a1e1be674e5f4291d40cc815e26c139951fb",
                    "noncanonical_diagnostic_only":true},
                "original_future_growth_disposition":{
                    "closure":{"sha256":"7a57f946c5e6cb08bc9a99e8a6b76a6ed33fffb013a673715924192a327d0553"},
                    "native_success_and_empty_cgroup_verified":true,"original_claim_after_bytes":0,
                    "physical_space_credit_bytes":0,"guards_changed":false,
                    "source_scratch_inputs_retained":true,"repair_still_open":true},
                "archive_retirement":{
                    "completion":{"sha256":"3b28d55ad611bb7dedc1965ddc7f497c417444c3c80d959be62f85f09d6e13bb"},
                    "native_success_pid0_empty_cgroup":true,"actual_free_space_delta_claimed":false,
                    "source_absent":true,"quarantine_absent":true,"r2_mutations":false,
                    "failure_repaired":false},
                "scratch_cleanup":{"deletion_performed":false,"scratch_inode_to_preserve":100270084}}
        })
    }
    fn binding() -> Bound {
        Bound {
            path: CONTROL_PATH.into(),
            sha256: CONTROL_SHA.into(),
        }
    }
    fn fleet() -> Value {
        let evidence = json!([{"path":"/preserved/incident","sha256":"preserved"},
            {"path":CONTROL_PATH,"sha256":CONTROL_SHA}]);
        json!({"gates":{
            "141":{"state":"failed-needs-repair","next_action":OLD_141,
                "evidence":evidence,"integrity_gate":"unchanged","growth_claim":512},
            "185":{"state":"failed-needs-repair","next_action":OLD_185,
                "evidence":evidence,"integrity_gate":"unchanged","growth_claim":0},
            "191":{"state":"post-replay-pipeline","next_action":"keep delivery"}},
            "tracked_units":["preserved-owner"],"diagnostics":[{"epoch":144}],
            "previous_fleet":{"path":"immutable-history","sha256":"unchanged"},
            "resource_claims":{"guard_floor":3503746342342u64,"scratch_retained":true},
            "publication_authorized":false})
    }
    #[test]
    fn changes_only_each_known_action_and_is_idempotent() {
        let control = control();
        for note in [Note::Epoch141, Note::Epoch185] {
            let original = fleet();
            let mut actual = original.clone();
            assert!(correct(&mut actual, note, &binding(), &control).unwrap());
            let mut expected = original;
            expected["gates"][note.key()]["next_action"] = json!(note.next());
            assert_eq!(actual, expected);
            assert!(!correct(&mut actual, note, &binding(), &control).unwrap());
            assert_eq!(actual, expected);
        }
        let mut spaced = fleet();
        spaced["gates"]["185"]["next_action"] = json!(OLD_185_SPACED);
        assert!(correct(&mut spaced, Note::Epoch185, &binding(), &control).unwrap());
        assert_eq!(spaced["gates"]["185"]["next_action"], NEXT_185);
    }
    #[test]
    fn preserves_newer_actions_states_and_foreign_bindings() {
        for note in [Note::Epoch141, Note::Epoch185] {
            for (field, value) in [
                ("state", "remote-ready"),
                ("state", "live-replay"),
                ("state", "blocked-qualification"),
                ("state", "post-replay-pipeline"),
                ("next_action", "a later independently reviewed action"),
            ] {
                let mut actual = fleet();
                actual["gates"][note.key()][field] = json!(value);
                let original = actual.clone();
                assert!(!correct(&mut actual, note, &binding(), &control()).unwrap());
                assert_eq!(actual, original);
            }
            for foreign in [
                Bound {
                    path: "/foreign/backlog.json".into(),
                    sha256: CONTROL_SHA.into(),
                },
                Bound {
                    path: CONTROL_PATH.into(),
                    sha256: "0".repeat(64),
                },
            ] {
                let mut actual = fleet();
                let original = actual.clone();
                assert!(!correct(&mut actual, note, &foreign, &control()).unwrap());
                assert_eq!(actual, original);
            }
        }
    }
    #[test]
    fn rejects_disposition_or_authority_changes_before_any_note_mutation() {
        for (pointer, value) in [
            ("/schema", json!("foreign")),
            ("/host", json!("other-node")),
            ("/goal_complete", json!(true)),
            (
                "/canonical_remote_archive_overwrite_or_deletion",
                json!(true),
            ),
            ("/epoch141/mainnet_probe_not_admitted", json!(false)),
            ("/epoch141/failed_attempts_preserved", json!(false)),
            (
                "/epoch141/synthetic_results/old_data_claim_released",
                json!(true),
            ),
            ("/epoch141/durable_suite/failed", json!(0)),
            ("/epoch141/rerun_proposal/sha256", json!("foreign")),
            (
                "/epoch185/status_authenticated_absent_without_canonical_delivery_owner",
                json!(false),
            ),
            (
                "/epoch185/custody/noncanonical_diagnostic_only",
                json!(false),
            ),
            (
                "/epoch185/original_future_growth_disposition/original_claim_after_bytes",
                json!(1),
            ),
            (
                "/epoch185/original_future_growth_disposition/physical_space_credit_bytes",
                json!(1),
            ),
            (
                "/epoch185/original_future_growth_disposition/guards_changed",
                json!(true),
            ),
            (
                "/epoch185/original_future_growth_disposition/repair_still_open",
                json!(false),
            ),
            ("/epoch185/archive_retirement/failure_repaired", json!(true)),
            ("/epoch185/archive_retirement/r2_mutations", json!(true)),
            (
                "/epoch185/archive_retirement/actual_free_space_delta_claimed",
                json!(true),
            ),
            ("/epoch185/scratch_cleanup/deletion_performed", json!(true)),
            (
                "/epoch185/scratch_cleanup/scratch_inode_to_preserve",
                json!(1),
            ),
        ] {
            let mut changed = control();
            *changed.pointer_mut(pointer).unwrap() = value;
            for note in [Note::Epoch141, Note::Epoch185] {
                let mut actual = fleet();
                let original = actual.clone();
                assert!(
                    correct(&mut actual, note, &binding(), &changed).is_err(),
                    "{pointer}"
                );
                assert_eq!(actual, original);
            }
        }
    }
    #[test]
    fn missing_gate_history_binding_cannot_acquire_a_new_narrative() {
        for note in [Note::Epoch141, Note::Epoch185] {
            let mut actual = fleet();
            actual["gates"][note.key()]["evidence"] = json!([]);
            let original = actual.clone();
            assert!(correct(&mut actual, note, &binding(), &control()).is_err());
            assert_eq!(actual, original);
        }
    }
}
