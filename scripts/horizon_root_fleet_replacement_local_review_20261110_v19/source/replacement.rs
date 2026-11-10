//! Complete original terminal history plus explicit independently admitted fresh replacements.
//! Metadata-only: no resource admission, launch, archive publication or promise release.
use super::*;
const EPOCHS: [u64; 7] = [166, 167, 168, 169, 170, 171, 172];
const FLOOR: u64 = 6_264_131_239_730;
const GUARD: &str = "35dbd4826c8947f38d50dff049345e1c3d62450eb85e41e94e326880e1898fbc";
fn terminal_native(v: &Value, unit: &str) -> R<()> {
    need(
        v["Id"] == unit
            && v["ActiveState"] == "inactive"
            && v["SubState"] == "dead"
            && v["MainPID"] == "0"
            && v["ControlPID"] == "0"
            && v["NRestarts"] == "0"
            && v["ControlGroup"] == ""
            && v["Job"] == "",
        "original reserve-stopped producer is not drained",
    )?;
    need(
        matches!(v["LoadState"].as_str(), Some("loaded" | "not-found")),
        "unknown terminal native load state",
    )
}
fn event_shape(event: &Value) -> R<()> {
    need(
        event["schema"] == "horizon-seven-standard-reserve-stop-repair-event-v1"
            && event["owner"] == "/root"
            && event["primary_thread"] == "01a1af2a-9ce8-76a2-8939-b2112bd38f53"
            && event["current_live_replay_count"] == 0
            && event["last_proven_operating_point"] == 7
            && event["memory_selected_target_retained"] == 13
            && event["repair_open"] == true
            && event["resource_promises_released"] == false,
        "exact seven-terminal event/no-credit contract required",
    )?;
    let rows = event["rows"].as_object().ok_or("terminal event rows")?;
    need(
        rows.keys()
            .map(|k| k.parse::<u64>())
            .collect::<Result<BTreeSet<_>, _>>()?
            == BTreeSet::from(EPOCHS),
        "complete exact166-172 terminal set required",
    )
}
fn stop_chain(
    row: &Value,
    historical: &Value,
    intent: &Value,
    completion: &Value,
    journal: &Value,
) -> R<()> {
    let unit = s(row, "unit")?;
    let iid = s(row, "original_invocation_id")?;
    need(
        row["epoch"] == historical["epoch"]
            && historical["unit"]["Id"] == unit
            && historical["unit"]["InvocationID"] == iid
            && row["no_resource_release"] == true
            && row["preserve_partial_and_inputs"] == true,
        "terminal row must preserve exact original replay claim",
    )?;
    need(
        intent["schema"] == "jetstreamer-horizon-standalone-stop-intent-v1"
            && completion["schema"] == "jetstreamer-horizon-standalone-stop-completion-v1"
            && intent["reason"] == "filesystem-floor"
            && intent["producer_invocation_id"] == iid
            && completion["producer_invocation_id"] == iid
            && completion["intent"] == row["stop_intent"]["path"]
            && intent["plan_sha256"] == completion["plan_sha256"],
        "exact guard stop-intent/completion lineage required",
    )?;
    let sample = &intent["sample"];
    need(
        sample["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && sample["guard_sha256"] == GUARD
            && sample["producer_invocation_id"] == iid
            && sample["producer"]["invocation_id"] == iid
            && sample["producer_stop_enabled"] == true
            && sample["trip_reason"] == "filesystem-floor"
            && n(sample, "available_bytes")? < FLOOR
            && sample["minimum_free_bytes"] == FLOOR
            && sample["root_physical_observation_error"].is_null()
            && sample["worker_observation_error"].is_null()
            && sample["scratch_deleted"] == false
            && completion["scratch_deleted"] == false
            && completion["terminal"]["active"] == "inactive"
            && completion["terminal"]["pid"] == 0
            && completion["terminal"]["invocation_id"] == iid
            && completion["terminal"]["restarts"] == 0,
        "genuine original reserve stop/drain, retained scratch and unchanged floor required",
    )?;
    need(
        journal
            .as_array()
            .ok_or("original PID1 stop journal")?
            .iter()
            .any(|e| {
                e["_PID"] == "1"
                    && e["UNIT"] == unit
                    && (e["MESSAGE_ID"] == "9d1aaa27d60140bd96365438aad20286"
                        || e["MESSAGE"]
                            .as_str()
                            .is_some_and(|m| m.starts_with(&format!("Stopped {unit}"))))
            }),
        "original unit PID1 stop event required; default not-found is insufficient",
    )?;
    terminal_native(&row["native"], unit)
}
fn observer_mode(
    obs: &Value,
    historical: &Value,
    rows: &serde_json::Map<String, Value>,
    replacements: &[Value],
) -> R<bool> {
    if obs == historical {
        return Ok(true);
    }
    need(
        obs["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && obs["cadence"]["routine_minimum_interval_enforced"] == true
            && n(&obs["cadence"], "observed_interval_seconds")? >= 1800
            && s(obs, "recorded_at_utc")? > s(historical, "recorded_at_utc")?
            && obs["replays"].is_array(),
        "poststop routine sample must retain the coordinated observer contract",
    )?;
    let diag = obs["diagnostic_replays"]
        .as_array()
        .ok_or("explicit retained terminal diagnostics")?;
    for epoch in EPOCHS {
        let row = &rows[&epoch.to_string()];
        let matches = diag
            .iter()
            .filter(|d| d["range"].as_str().and_then(|s| s.parse::<u64>().ok()) == Some(epoch))
            .collect::<Vec<_>>();
        let observed = obs["replays"]
            .as_array()
            .ok_or("explicit ordinary replay rows")?
            .iter()
            .filter(|d| d["range"].as_str().and_then(|s| s.parse::<u64>().ok()) == Some(epoch))
            .collect::<Vec<_>>();
        if !observed.is_empty() {
            let owners = replacements
                .iter()
                .filter(|d| d["epoch"] == epoch)
                .collect::<Vec<_>>();
            need(
                matches.is_empty() && observed.len() == 1 && owners.len() == 1,
                "observed replacement must have one declared owner and no overlapping diagnostic",
            )?;
            let current = observed[0];
            let owner = owners[0];
            owner_identity_observation(current, owner)?;
            // Original ownership remains authenticated by the complete stop chain below.
            continue;
        }
        need(
            matches.len() == 1,
            "each terminal original must remain in diagnostic history",
        )?;
        let d = matches[0];
        need(
            d["producer_unit"] == row["unit"]
                && d["expected_producer_invocation_id"] == row["original_invocation_id"]
                && d["status"] == "unavailable"
                && d["observation"].is_null()
                && d["error"].as_str().is_some_and(|s| !s.is_empty())
                && d["ordinary_replay_claim"] == false,
            "unavailable diagnostic is terminal only through the separate exact stop chain",
        )?;
    }
    Ok(false)
}
fn status_owner(pr: &Value, row: &Value, event_binding: &Value) -> R<()> {
    let owner = &pr["owner_evidence"];
    need(
        pr["after_status"]["phase"] == "verification"
            && owner["current_operator"] == "/root"
            && owner["no_live_producer_claimed"] == true
            && owner["original_producer_invocation_id"] == row["original_invocation_id"]
            && owner["reserve_stop_event"] == *event_binding
            && owner["original_stop_intent"] == row["stop_intent"]
            && owner["original_stop_completion"] == row["stop_completion"],
        "terminal producer needs current authenticated Root-recovery status, never replay status",
    )
}
fn repair_row(
    old: &Value,
    row: &Value,
    pr: &Value,
    binding: &Value,
    event_binding: &Value,
    historical_live: &Value,
) -> Value {
    let mut next = old.clone();
    next["previous_operational_state"] = old["state"].clone();
    next["state"] = json!("failed-needs-repair");
    next["current_operator"] = json!("/root");
    next["current_phase"] = json!("verification");
    next["active_owner_kind"] = json!("Root-reserve-stop-recovery");
    next["useful_transaction_replay"] = json!(false);
    next["current_live_producer"] = Value::Null;
    next["original_live_replay_history"] = historical_live.clone();
    next["original_producer_invocation_id"] = row["original_invocation_id"].clone();
    next["actual_terminal_producer"] = row["native"].clone();
    next["reserve_stop_event"] = event_binding.clone();
    next["original_stop_intent"] = row["stop_intent"].clone();
    next["original_stop_completion"] = row["stop_completion"].clone();
    next["previous_status_publication"] = old["status_publication"].clone();
    next["status_publication"] = binding.clone();
    next["current_task"] = pr["owner_evidence"]["current_task"].clone();
    next["next_action"] = json!(
        "Preserve the original partial archive, scratch and inputs. Recover qualified filesystem capacity, then use an independently qualified continuation or fresh bootstrap/admission and a new invocation-bound guard. No blind restart, scratch deletion, lowered floor or reservation release."
    );
    next["status"] = json!({"classification":"authenticated-active-Root-reserve-stop-recovery","current_eta_valid":true,"owner_binding_matches":true,"payload":pr["after_status"],"etag":pr["after_etag"],"sha256":pr["after_sha256"],"production_claim_eligible":false,"freshness_basis":"Authenticated current Root repair status; original replay is terminal and retained only as history"});
    next
}
/// A metadata event adapter. It consumes existing samples/receipts; only native owner/unit
/// metadata is reconciled. It never creates a resource observation or changes a producer.
pub(super) fn run(plan: &Value) -> R<()> {
    let declarations = replacement_validation::declarations(plan)?;
    for key in [
        "replays",
        "supplemental_live_replays",
        "guarded_bootstrap_owners",
    ] {
        need(
            plan[key].as_array().is_some_and(Vec::is_empty),
            "terminal route requires explicit zero live and bootstrap declarations",
        )?;
    }
    need(
        plan["proven_replay_count"] == 7,
        "historical seven-point count must be retained explicitly",
    )?;
    let event = bound(&plan["terminal_producer_event"])?;
    event_shape(&event)?;
    let previous = bound(&plan["previous_review"])?;
    let history = bound(&event["previous_fleet"])?;
    let historical_obs = bound(&event["previous_observer"])?;
    let obs = bound(&plan["observer"])?;
    let audit = bound(&plan["status_audit"])?;
    let inv = bound(&plan["inventory"])?;
    let resource = bound(&plan["complete_DATA_authority"])?;
    need(
        previous["schema"] == "horizon-Root-complete-fleet-operational-review-v1"
            && previous["owner"] == "/root"
            && previous["primary_thread"] == plan["primary_thread"]
            && history["proven_replay_count"] == 7
            && history["last_qualified_memory_selected_target"] == 13,
        "authenticated full historical fleet/proven point/target required",
    )?;
    need(
        plan["previous_review"] == event["previous_fleet"]
            || (previous["terminal_producer_event"] == plan["terminal_producer_event"]
                && previous["pre_stop_complete_fleet"] == event["previous_fleet"]
                && (previous["live_replay_count"] == 0
                    || previous["replacement_reconciliation"] == true)),
        "event must extend its original fleet or an accepted exact-event terminal review",
    )?;
    need(
        resource["owner"] == "/root"
            && resource["primary_thread"] == plan["primary_thread"]
            && resource["complete_DATA_bytes"] == plan["complete_DATA_bytes"]
            && resource["complete_projected_memory_bytes"]
                == plan["complete_projected_memory_bytes"]
            && resource["normal_pool_bytes"] == plan["normal_pool_bytes"],
        "current complete resource authority is retained unchanged",
    )?;
    need(
        historical_obs["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && historical_obs["cadence"]["routine_minimum_interval_enforced"] == true
            && n(&historical_obs["cadence"], "observed_interval_seconds")? >= 1800
            && s(&event, "recorded_at_utc")? >= s(&historical_obs, "recorded_at_utc")?,
        "actual pre-stop coordinated observation and event clock required",
    )?;
    let event_rows = event["rows"].as_object().ok_or("event rows")?;
    let pre_stop = observer_mode(&obs, &historical_obs, event_rows, &declarations)?;
    need(
        s(&audit, "sampled_at_utc")? >= s(&event, "recorded_at_utc")?
            && audit["sampled_at_utc"] == plan["status_sampled_at_utc"],
        "current repair-status audit must postdate reserve-stop event",
    )?;
    need(
        if pre_stop {
            plan["observer"] == event["previous_observer"]
        } else {
            s(&obs, "recorded_at_utc")? >= s(&event, "recorded_at_utc")?
        },
        "observer/event clock relation",
    )?;
    let ready = inventory(&inv)?;
    let status = statuses(&audit, &plan["observer"])?;
    need(
        status.len() == 19
            && plan["expected_status_count"] == 19
            && n(&inv, "ready_pairs")? == n(plan, "expected_ready_pairs")?
            && n(&inv, "missing")? == n(plan, "expected_missing")?
            && status.keys().all(|e| !ready.contains(e)),
        "complete nineteen authenticated statuses/inventory required",
    )?;
    let rows = previous["epochs"]
        .as_array()
        .ok_or("previous complete epoch rows")?;
    full_epochs(rows)?;
    let historical_live = history["actual_executing_replays"]
        .as_array()
        .ok_or("original executing replay history")?;
    need(
        historical_live.len() == 7,
        "complete original seven producer histories required",
    )?;
    let mut terminal_before = BTreeMap::new();
    let mut terminal_records = BTreeMap::new();
    for epoch in EPOCHS {
        need(
            !ready.contains(&epoch),
            "reserve-stop event cannot qualify a ready pair",
        )?;
        let row = &event_rows[&epoch.to_string()];
        let live_rows = historical_live
            .iter()
            .filter(|r| r["epoch"] == epoch)
            .collect::<Vec<_>>();
        need(
            live_rows.len() == 1,
            "one original replay per stopped epoch",
        )?;
        let obs_rows = historical_obs["replays"]
            .as_array()
            .ok_or("pre-stop replay sample")?
            .iter()
            .filter(|r| r["range"].as_str().and_then(|s| s.parse::<u64>().ok()) == Some(epoch))
            .collect::<Vec<_>>();
        need(
            obs_rows.len() == 1,
            "one pre-stop observation per original epoch",
        )?;
        let expected = json!({"epoch":epoch,"unit":row["unit"],"invocation_id":row["original_invocation_id"],"main_pid":live_rows[0]["unit"]["MainPID"]});
        owner_observation(obs_rows[0], &expected)?;
        stop_chain(
            row,
            live_rows[0],
            &bound(&row["stop_intent"])?,
            &bound(&row["stop_completion"])?,
            &bound(&row["journal"])?,
        )?;
        let native_now = native(s(row, "unit")?)?;
        terminal_native(&native_now, s(row, "unit")?)?;
        for (key, value) in row["native"]
            .as_object()
            .ok_or("terminal event native shape")?
        {
            need(
                native_now[key] == *value,
                "terminal owner changed since authenticated event",
            )?;
        }
        need(
            !Path::new("/sys/fs/cgroup/system.slice")
                .join(s(row, "unit")?)
                .try_exists()?,
            "original producer cgroup must be absent",
        )?;
        let (pr, _) = status.get(&epoch).ok_or("terminal Root status missing")?;
        if !declarations.iter().any(|d| d["epoch"] == epoch) {
            status_owner(pr, row, &plan["terminal_producer_event"])?;
        }
        terminal_before.insert(s(row, "unit")?.to_string(), native_now.clone());
        terminal_records.insert(epoch,json!({"epoch":epoch,"original_invocation_id":row["original_invocation_id"],"original_live_replay":live_rows[0],"last_replay_observer":event["previous_observer"],"last_useful_work":obs_rows[0]["useful_work"],"terminal_native":native_now,"stop_intent":row["stop_intent"],"stop_completion":row["stop_completion"],"original_PID1_journal":row["journal"],"partial_archive_preserved":row["original_archive"],"scratch_preserved":row["scratch"],"repair_open":true,"resource_release_bytes":0}));
    }
    let mut replacement_records = BTreeMap::new();
    let mut replacement_units = BTreeMap::new();
    for d in &declarations {
        let epoch = n(d, "epoch")?;
        need(
            !ready.contains(&epoch),
            "replacement cannot claim an already-ready epoch",
        )?;
        let original = &event_rows[&epoch.to_string()];
        let pr = &status.get(&epoch).ok_or("replacement status missing")?.0;
        let record = replacement_validation::load(d, original, plan, &obs, pr, now()?)?;
        need(
            replacement_units
                .insert(s(d, "unit")?.to_string(), record["unit"].clone())
                .is_none(),
            "duplicate replacement unit",
        )?;
        replacement_records.insert(epoch, record);
    }
    let sampled_epochs = obs["replays"]
        .as_array()
        .ok_or("replacement sample rows")?
        .iter()
        .map(|r| s(r, "range")?.parse::<u64>().map_err(Into::into))
        .collect::<R<Vec<_>>>()?;
    need(
        sampled_epochs
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
            .len()
            == sampled_epochs.len()
            && sampled_epochs.iter().all(|e| {
                replacement_records
                    .get(e)
                    .is_some_and(|r| r["in_current_observer"] == true)
            }),
        "every sampled owner must be an exact declared replacement",
    )?;
    let mut stable_controls = BTreeMap::new();
    for (name, expected) in history["stable_non_replay_owners"]
        .as_object()
        .ok_or("historical protected background owners")?
    {
        let actual = native(name)?;
        let expected = json!({"unit":name,"invocation_id":expected["InvocationID"],"main_pid":expected["MainPID"]});
        owner_matches(&actual, &expected)?;
        stable_controls.insert(name.clone(), actual);
    }
    need(
        stable_controls.len() >= 2,
        "preserve uploader and original199 controller identities",
    )?;
    for expected in plan["stable_non_replay_owners"]
        .as_array()
        .ok_or("explicit current protected controls")?
    {
        let actual = native(s(expected, "unit")?)?;
        owner_matches(&actual, expected)?;
        stable_controls.insert(s(expected, "unit")?.to_string(), actual);
    }
    let mut names = discover()?;
    names.extend(
        previous["metadata_unit_census"]
            .as_object()
            .ok_or("previous full unit census")?
            .keys()
            .cloned(),
    );
    names.extend(terminal_before.keys().cloned());
    names.extend(stable_controls.keys().cloned());
    names.extend(replacement_units.keys().cloned());
    let mut census = BTreeMap::new();
    let mut background = Vec::new();
    for name in &names {
        let actual = native(name)?;
        if potential_replay_claim(name)
            && (live(&actual)
                || actual["ActiveState"] == "activating"
                || actual["Job"].as_str().is_some_and(|j| !j.is_empty())
                || (actual["ActiveState"] == "failed"
                    && previous["metadata_unit_census"].get(name) != Some(&actual)))
        {
            need(
                stable_controls.contains_key(name) || replacement_units.contains_key(name),
                "unclaimed running replay/controller appeared during terminal reconciliation",
            )?;
        }
        if live(&actual) && !replacement_units.contains_key(name) {
            background
                .push(json!({"requested_unit":name,"unit":actual,"not_counted_as_replay":true}));
        }
        census.insert(name.clone(), actual);
    }
    need(
        discover()?.is_subset(&names),
        "new Horizon unit appeared during terminal census",
    )?;
    let mut updated = Vec::new();
    let mut backlog = Vec::new();
    for old in rows {
        let e = n(old, "epoch")?;
        let mut row = old.clone();
        if let Some(event_row) = event_rows.get(&e.to_string()) {
            let (pr, binding) = status.get(&e).ok_or("stopped status missing")?;
            let history = historical_live
                .iter()
                .find(|r| r["epoch"] == e)
                .ok_or("stopped history missing")?;
            row = repair_row(
                old,
                event_row,
                pr,
                binding,
                &plan["terminal_producer_event"],
                history,
            );
            if let Some(replacement) = replacement_records.get(&e) {
                let bootstrap = replacement["phase"] == "bootstrap";
                row["state"] = json!(if bootstrap {
                    "staged-admissible"
                } else {
                    "live-replay"
                });
                row["current_phase"] = json!(if bootstrap { "verification" } else { "replay" });
                row["active_owner_kind"] = json!(if bootstrap {
                    "fresh-guarded-bootstrap"
                } else {
                    "fresh-guarded-replay"
                });
                row["useful_transaction_replay"] = json!(!bootstrap);
                row["current_live_producer"] = replacement["unit"].clone();
                row["replacement_admission"] = replacement["admission"].clone();
                row["guard_protection"] = replacement["guard_protection"].clone();
                row["replacement_evidence"] = replacement.clone();
                row["next_action"] = json!(if bootstrap {
                    "Preserve the new guarded bootstrap inside its original fixed deadline. Authenticate actual first target transactions before classifying useful replay; never reset startup lifetime or reuse an original native identity."
                } else {
                    "Preserve new useful replay and its genuine current protective guard. On genuine archive close, retain full/current-plugin/canonical/boundary/R2 delivery gates; the original partial remains protected history."
                });
                row["status"]["classification"] = json!(if bootstrap {
                    "authenticated-fresh-guarded-bootstrap"
                } else {
                    "authenticated-fresh-live-replay"
                });
                row["status"]["production_claim_eligible"] = json!(!bootstrap);
            }
        } else if ready.contains(&e) {
            row["previous_operational_state"] = old["state"].clone();
            row["state"] = json!("remote-ready");
            row["status"] = Value::Null;
            row["status_publication"] = Value::Null;
        } else if let Some((pr, binding)) = status.get(&e) {
            row["previous_status_publication"] = old["status_publication"].clone();
            row["status_publication"] = binding.clone();
            row["current_operator"] = json!("/root");
            row["current_task"] = pr["owner_evidence"]["current_task"].clone();
            row["status"] = json!({"classification":"authenticated-active-Root-repair-or-preparation","current_eta_valid":true,"owner_binding_matches":true,"payload":pr["after_status"],"etag":pr["after_etag"],"sha256":pr["after_sha256"],"production_claim_eligible":false});
        }
        if let Some(action) = plan["next_actions_by_epoch"].get(e.to_string().as_str()) {
            need(
                !ready.contains(&e) && action.as_str().is_some_and(|s| !s.is_empty()),
                "invalid current next-action override",
            )?;
            row["next_action"] = action.clone();
        }
        if !ready.contains(&e) {
            backlog.push(json!({"epoch":e,"state":row["state"],"next_action":row["next_action"],"current_task":row["current_task"],"gate_evidence":row["gate_evidence"],"repair_closed":false,"prior_history_preserved_by":plan["previous_review"],"terminal_event":if EPOCHS.contains(&e){plan["terminal_producer_event"].clone()}else{Value::Null}}));
        }
        updated.push(row);
    }
    full_epochs(&updated)?;
    for (name, before) in terminal_before
        .iter()
        .chain(stable_controls.iter())
        .chain(replacement_units.iter())
    {
        need(
            native(name)? == *before,
            "terminal or protected owner changed during review",
        )?;
    }
    for epoch in EPOCHS {
        let row = &event_rows[&epoch.to_string()];
        for key in ["stop_intent", "stop_completion", "journal"] {
            bound(&row[key])?;
        }
    }
    for key in [
        "previous_review",
        "observer",
        "status_audit",
        "inventory",
        "complete_DATA_authority",
        "terminal_producer_event",
    ] {
        bound(&plan[key])?;
    }
    for (_, binding) in status.values() {
        bound(binding)?;
    }
    for d in &declarations {
        let epoch = n(d, "epoch")?;
        let current = replacement_validation::finish(d, &replacement_records[&epoch])?;
        replacement_records
            .get_mut(&epoch)
            .ok_or("accepted replacement vanished")?["final_guard_capture"] = current;
    }
    let timer = bound(&plan["next_observer_receipt"])?;
    need(
        timer["next_utc"] == plan["next_observer_utc"]
            && s(plan, "next_observer_utc")? > s(&audit, "sampled_at_utc")?,
        "current sole future observer receipt required",
    )?;
    let mut report = previous.clone();
    report["sampled_at_utc"] = obs["recorded_at_utc"].clone();
    report["state_reconciled_at_utc"] = audit["sampled_at_utc"].clone();
    report["phase_event_recorded_at_utc"] = event["recorded_at_utc"].clone();
    report["recorded_unix_seconds"] = json!(now()?);
    report["previous_Root_operational_review"] = plan["previous_review"].clone();
    report["observer"] = plan["observer"].clone();
    report["authenticated_inventory"] = plan["inventory"].clone();
    report["authenticated_status_audit"] = plan["status_audit"].clone();
    report["terminal_producer_event"] = plan["terminal_producer_event"].clone();
    report["pre_stop_complete_fleet"] = event["previous_fleet"].clone();
    report["pre_stop_observer"] = event["previous_observer"].clone();
    report["pre_stop_observer_is_history_only"] = json!(true);
    report["current_observer_is_pre_stop_history"] = json!(pre_stop);
    for key in [
        "complete_DATA_authority",
        "complete_DATA_bytes",
        "complete_projected_memory_bytes",
        "normal_pool_bytes",
        "next_capacity_action",
        "next_observer_utc",
        "next_observer_receipt",
    ] {
        report[key] = plan[key].clone();
    }
    let active = replacement_records
        .values()
        .filter(|r| r["phase"] == "replay")
        .cloned()
        .collect::<Vec<_>>();
    let bootstraps = replacement_records
        .values()
        .filter(|r| r["phase"] == "bootstrap")
        .cloned()
        .collect::<Vec<_>>();
    report["live_replay_count"] = json!(active.len());
    report["useful_replay_count"] = json!(active.len());
    report["active_producer_count"] = json!(replacement_records.len());
    report["guarded_bootstrap_owner_count"] = json!(bootstraps.len());
    report["actual_executing_replays"] = json!(active);
    report["actual_active_bootstraps"] = json!(bootstraps);
    report["replacement_reconciliation"] = json!(true);
    report["replacement_owner_declarations"] = json!(declarations);
    report["replacement_event_does_not_backdate_observer"] = json!(true);
    report["terminal_producer_count"] = json!(7);
    report["terminal_producers"] = json!(terminal_records.into_values().collect::<Vec<_>>());
    report["proven_replay_count"] = json!(7);
    report["last_qualified_memory_selected_target"] = json!(13);
    report["previous_qualified_memory_selected_target"] =
        previous["last_qualified_memory_selected_target"].clone();
    report["current_memory_selected_target"] = json!({"valid":false,"retained_last_qualified_target":13,"current_live_replay_count":active.len(),"current_active_producer_count":replacement_records.len(),"reason":"Retain historical target13; mixed bootstrap/event replacement telemetry does not establish a new complete RSS target or admission.","admission_authorized":false});
    report["expanded_fleet_window"] = json!({"qualified":false,"terminal_originals":7,"current_live_replays":active.len(),"current_bootstrap_owners":bootstraps.len(),"historical_operating_point_retained":7,"replay_admission_authorized":false});
    report["ready_pairs"] = json!(ready.len());
    report["remaining_epochs"] = json!(100 - ready.len());
    report["epochs"] = json!(updated);
    report["open_repair_backlog"] = json!(backlog);
    report["metadata_unit_census"] = json!(census);
    report["currently_running_background_control_services"] = json!(background);
    report["stable_non_replay_owners"] = json!(stable_controls);
    report["authenticated_status_count"] = json!(19);
    report["all_active_status_reports_authenticated_readback"] = json!(true);
    report["new_resource_observations"] = json!(false);
    report["producer_mutations"] = json!(false);
    report["remote_mutations"] = json!(false);
    report["resource_credit_bytes"] = json!(0);
    report["holding_bytes_credited"] = json!(0);
    report["replay_launch_authorized"] = json!(false);
    report["same_sample_conservative_free_DATA_bytes"] =
        obs["filesystem"]["conservative_available_bytes"].clone();
    report["resource_sample_is_pre_stop_history"] = json!(pre_stop);
    durable(Path::new(s(plan, "output")?), &report)?;
    println!(
        "{}",
        json!({"output":plan["output"],"live_replay_count":active.len(),"guarded_bootstrap_owner_count":bootstraps.len(),"terminal_producer_count":7,"authenticated_status_count":19,"last_proven_operating_point":7,"historical_target":13,"resource_credit_bytes":0})
    );
    Ok(())
}

#[cfg(test)]
mod observer_handoff_tests {
    use super::*;
    fn fixture() -> (Value, Value, serde_json::Map<String, Value>, Vec<Value>) {
        let rows = EPOCHS.into_iter().map(|e| (e.to_string(), json!({"unit":format!("old-{e}.service"),"original_invocation_id":format!("old-{e}")}))).collect::<serde_json::Map<_,_>>();
        let diagnostics=EPOCHS.into_iter().map(|e|json!({"range":e.to_string(),"producer_unit":format!("old-{e}.service"),"expected_producer_invocation_id":format!("old-{e}"),"status":"unavailable","observation":null,"error":"terminal original","ordinary_replay_claim":false})).collect::<Vec<_>>();
        let historical = json!({"recorded_at_utc":"2026-11-10T15:30:22Z"});
        let obs = json!({"schema":"jetstreamer-horizon-live-resource-sample-v2","recorded_at_utc":"2026-11-10T20:00:22Z","cadence":{"routine_minimum_interval_enforced":true,"observed_interval_seconds":1800},"replays":[],"diagnostic_replays":diagnostics});
        let replacement = json!({"epoch":166,"unit":"new-166.service","invocation_id":"actual-new166","main_pid":"123"});
        (obs, historical, rows, vec![replacement])
    }
    fn observed(obs: &mut Value) {
        obs["diagnostic_replays"].as_array_mut().unwrap().remove(0);
        let role = json!({"unit":"new-166.service","invocation_id":"actual-new166","main_pid":123,"active_state":"active","sub_state":"running","restarts":0});
        obs["replays"] = json!([{"range":"166","invocation_binding_stable":true,"controller_before":role,"controller_after":role,"producer_before":role,"producer_after":role}]);
    }
    #[test]
    fn accepts_later_observed_owner_without_duplicate_original_diagnostic() {
        let (mut o, h, r, d) = fixture();
        assert!(!observer_mode(&o, &h, &r, &d).unwrap());
        observed(&mut o);
        assert!(!observer_mode(&o, &h, &r, &d).unwrap());
    }
    #[test]
    fn rejects_wrong_or_undeclared_observed_owner() {
        let (mut o, h, r, d) = fixture();
        observed(&mut o);
        assert!(observer_mode(&o, &h, &r, &[]).is_err());
        for role in [
            "producer_before",
            "producer_after",
            "controller_before",
            "controller_after",
        ] {
            for (key, value) in [
                ("unit", json!("wrong")),
                ("invocation_id", json!("wrong")),
                ("main_pid", json!(124)),
                ("restarts", json!(1)),
            ] {
                let mut bad = o.clone();
                bad["replays"][0][role][key] = value;
                assert!(observer_mode(&bad, &h, &r, &d).is_err(), "{role}.{key}");
            }
        }
    }
    #[test]
    fn rejects_overlap_duplicate_owner_or_missing_unreplaced_history() {
        let (mut o, h, r, d) = fixture();
        let old = o["diagnostic_replays"][0].clone();
        observed(&mut o);
        let mut overlap = o.clone();
        overlap["diagnostic_replays"]
            .as_array_mut()
            .unwrap()
            .push(old);
        assert!(observer_mode(&overlap, &h, &r, &d).is_err());
        let mut duplicate = o.clone();
        duplicate["replays"]
            .as_array_mut()
            .unwrap()
            .push(o["replays"][0].clone());
        assert!(observer_mode(&duplicate, &h, &r, &d).is_err());
        let mut missing = o.clone();
        missing["diagnostic_replays"]
            .as_array_mut()
            .unwrap()
            .remove(0);
        assert!(observer_mode(&missing, &h, &r, &d).is_err());
    }
}
