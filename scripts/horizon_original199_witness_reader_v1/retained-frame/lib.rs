//! A resource-only recovery frame. This is not a full routine completion,
//! a growth-closure receipt, or an admission decision.
pub mod cached145_frame;
mod cached145_timer;
mod charge136_retry0005_frame;
mod charge136_retry0005_frame_view;
mod charge136_retry0005_history;
mod charge136_retry0005_history_pure;
pub mod ordinary199;
mod ordinary199_frame;
mod retry0005_memory_shape;
pub mod retry0005_source_loader;
pub mod terminal199_context;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
mod charge136_retry0003_history;
mod charge136_retry0004_frame;
mod charge136_retry0004_frame_view;
mod charge136_retry0004_history;
mod charge136_retry0004_history_pure;
pub mod cohort183_canonical_import;
pub mod delivery_history;
#[cfg(test)]
mod delivery_history_tests;
pub mod delivery_owner_delta;
mod durable_prefix141_history;
pub mod early_terminal141_history;
mod g6_history_pure;
mod g7_history_pure;
mod g7_normal_chain;
mod input161_retry6_history;
mod input161_retry6_pre_ready_history;
mod input161_retry7_history;
pub mod retained_g6_debt;
mod retry0004_memory_shape;
pub use durable_prefix141_history::pure as original_capture;
pub mod observer_collected_terminal;
mod private154_combined_history;
#[cfg(test)]
mod private154_downstream_bridge_tests;
mod private154_downstream_history;
pub mod private154_downstream_roles_pure;
pub mod private154_full_terminal_pure;
#[cfg(test)]
mod private154_full_terminal_tests;
mod private154_plugin_history;
pub mod private154_plugin_terminal_pure;
#[cfg(test)]
mod private154_plugin_tests;
pub mod private154_scan_event_pure;
mod private154_scan_history;
#[cfg(test)]
mod private154_scan_tests;
pub mod queue183_successor;
pub mod suffix154;
mod terminal154_history;
pub mod verifier183;
#[cfg(test)]
mod verifier183_tests;

pub const SCHEMA: &str = "jetstreamer-horizon-recovered-resource-frame-v1";
pub const FIRST_CAPTURE_SHA: &str =
    "f719fb3566fbaa09098eadac7390a0587c5aa74727d792d4a10b305643e194eb";
pub const CHAIN_CAPTURE_SHA: &str =
    "14ba6123094523d41a4193aa9018f810ca62ac5237832ec8cce1af36bb5ff365";
pub const NATIVE154_CAPTURE_SHA: &str =
    "3f91bd309693f462008f3fcc559ef20ffdeb676eb1a3617dc88c64be379e8a96";
pub const NATIVE154_UNIT: &str = "horizon-qualify-154-native-restore-20261028-v1.service";
pub const CONTROLLER: &str = "jetstreamer-epochs155-156-target3-controller-v1-r2.service";
pub const PRODUCER: &str =
    "jetstreamer-root-sweep-e155-156-t3-20261014-v1-r2-e155-156-lane-m-1.service";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Bound {
    pub path: std::path::PathBuf,
    pub sha256: String,
}

pub struct Evidence<'a> {
    pub observer: &'a Value,
    pub fleet: &'a Value,
    pub fleet_plan: &'a Value,
    pub prior_parent: &'a Value,
    pub prior_completion: &'a Value,
    pub prior_fleet_plan: &'a Value,
    pub transition: &'a Value,
    pub prior_recovery: Option<&'a Value>,
    pub fleet_transition: Option<&'a Value>,
    pub capture_tool_sha: &'a str,
    pub cohort183_transition: Option<&'a Value>,
    pub cohort183_sources: &'a std::collections::BTreeMap<String, Value>,
    pub native154_transition: Option<&'a Value>,
    pub native154_sources: &'a std::collections::BTreeMap<String, Value>,
}

fn exec_start_identity(value: &str) -> Option<&str> {
    let (identity, metadata) = value.split_once(" ; start_time=")?;
    if !identity.starts_with("{ path=")
        || identity.matches(" ; argv[]=").count() != 1
        || !identity.ends_with(" ; ignore_errors=no")
        || value.matches(" ; start_time=").count() != 1
    {
        return None;
    }
    let fields: Vec<_> = metadata.strip_suffix(" }")?.split(" ; ").collect();
    if fields.len() != 5
        || !fields[0].starts_with('[')
        || !fields[0].ends_with(']')
        || !fields[1].starts_with("stop_time=[")
        || !fields[1].ends_with(']')
        || fields[2].strip_prefix("pid=")?.parse::<u32>().is_err()
        || !fields[3].strip_prefix("code=").is_some_and(|v| {
            !v.is_empty()
                && v.bytes()
                    .all(|b| b.is_ascii_alphabetic() || b"()_-".contains(&b))
        })
        || !fields[4].strip_prefix("status=").is_some_and(|v| {
            !v.is_empty()
                && v.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"/_+-".contains(&b))
        })
    {
        return None;
    }
    Some(identity)
}

fn same_exec_start_text(expected: &str, current: &str) -> bool {
    expected == current
        || exec_start_identity(expected)
            .zip(exec_start_identity(current))
            .is_some_and(|(left, right)| left == right)
}

fn same_exec_start(expected: &Value, current: &Value) -> bool {
    expected
        .as_str()
        .zip(current.as_str())
        .is_some_and(|(a, b)| same_exec_start_text(a, b))
}

fn native154_history(
    e: &Evidence<'_>,
    bindings: &Value,
    predecessor: &Value,
) -> Result<Option<Value>> {
    let Some(t) = e.native154_transition else {
        ensure!(
            bindings["native154_transition"].is_null() && e.native154_sources.is_empty(),
            "native154 transition binding lacks evidence"
        );
        return Ok(None);
    };
    ensure!(
        e.prior_recovery.is_some()
            && !bindings["native154_transition"].is_null()
            && t["schema"] == "jetstreamer-horizon-native154-recovered-frame-transition-v1"
            && t["previous_recovery"] == bindings["prior_recovery"],
        "native154 recovery transition crossed ancestry"
    );
    authority_denied(t)?;
    ensure!(
        e.native154_sources.len()
            == usize::from(!t["entry"].is_null()) * 3 + usize::from(!t["terminal"].is_null()) * 3,
        "native154 source census differs"
    );
    let mut expected = e.prior_fleet_plan.clone();
    let mut head = predecessor["fleet"].clone();
    let mut sample = e.prior_recovery.context("native predecessor")?["sampled_at_utc"].clone();
    let source = |key: &str| -> Result<&Value> {
        e.native154_sources
            .get(key)
            .with_context(|| format!("native154 source missing: {key}"))
    };
    let mut claim = expected["pipeline_claims"]
        .as_array()
        .context("prior pipeline list")?
        .iter()
        .find(|c| c["epoch"] == 154)
        .cloned();
    if !t["entry"].is_null() {
        let origin = source("entry.origin")?;
        let fleet = source("entry.fleet")?;
        let plan = source("entry.fleet_plan")?;
        ensure!(
            origin["schema"] == "jetstreamer-private-epoch154-native-input-running-v1"
                && origin["epoch"] == 154
                && origin["unit"] == NATIVE154_UNIT
                && origin["private_qualification_only"] == true
                && origin["entry_replay"] == false
                && origin["replay_entries"] == 0
                && origin["worker_spawned"] == false
                && origin["resource_samples_taken"] == 0
                && origin["observer"] == predecessor["observer"]
                && origin["sampled_at_utc"] == sample
                && origin["probe"]["sha256"]
                    == "3f2678a065bac34a6fdbdfeff49e8e5239ca7f70ff71c3a1fff2ee9ffd686fb8"
                && origin["worker"]["sha256"]
                    == "aaa8758961d8de5790f7fa3979b126d8cb40975da438ce046c0b8bf223cfc615",
            "native154 entry is not the qualified zero-entry route"
        );
        for key in [
            "replay_launch_authorized",
            "assembly_authorized",
            "publication_authorized",
            "remote_mutations",
            "r2_mutations",
        ] {
            ensure!(
                origin[key] == false,
                "native154 entry grants authority: {key}"
            );
        }
        let iid = origin["invocation_id"]
            .as_str()
            .context("native154 entry IID")?;
        ensure!(
            iid.len() == 32
                && iid
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
            "native154 IID shape"
        );
        ensure!(
            claim.is_none()
                && !expected["tracked_units"]
                    .as_array()
                    .context("tracked history")?
                    .iter()
                    .any(|u| u == NATIVE154_UNIT),
            "native154 entry attempts to replace a retained owner"
        );
        let rows = plan["pipeline_claims"].as_array().context("entry claims")?;
        let c = rows
            .iter()
            .find(|c| c["epoch"] == 154)
            .context("entry claim missing")?
            .clone();
        ensure!(
            c["phase"] == "private-cold-snapshot-verification"
                && c["unit"] == NATIVE154_UNIT
                && c["invocation_id"] == iid
                && c["evidence"] == json!([t["entry"]["origin"]]),
            "native154 entry claim differs"
        );
        expected["tracked_units"]
            .as_array_mut()
            .context("prior tracked units")?
            .push(json!(NATIVE154_UNIT));
        expected["pipeline_claims"]
            .as_array_mut()
            .context("prior claims")?
            .push(c.clone());
        validate_native154_event(
            fleet,
            plan,
            &head,
            &predecessor["observer"],
            &sample,
            &t["entry"]["fleet_plan"],
            &t["entry"]["origin"],
        )?;
        for key in [
            "tracked_units",
            "pipeline_claims",
            "diagnostics",
            "runtime_handoff157",
            "admission_transition_guard",
            "gates",
        ] {
            ensure!(
                plan[key] == expected[key],
                "native154 entry changed retained policy: {key}"
            );
        }
        let native = &fleet["unit_census"][NATIVE154_UNIT];
        ensure!(
            native["InvocationID"] == iid
                && native["ActiveState"] == "active"
                && native["SubState"] == "running"
                && native["NRestarts"] == "0"
                && same_exec_start(&native["ExecStart"], &c["expected_exec_start"]),
            "native154 entry native identity differs"
        );
        head = t["entry"]["fleet"].clone();
        sample = fleet["sampled_at_utc"].clone();
        claim = Some(c);
    }
    if !t["terminal"].is_null() {
        let c = claim
            .as_ref()
            .context("native154 terminal lacks retained entry")?;
        let proof = source("terminal.proof")?;
        let fleet = source("terminal.fleet")?;
        let plan = source("terminal.fleet_plan")?;
        ensure!(
            proof["schema"] == "jetstreamer-epoch154-native-terminal-v2"
                && proof["epoch"] == 154
                && proof["unit"] == NATIVE154_UNIT
                && proof["claim"] == *c
                && proof["invocation_id"] == c["invocation_id"]
                && proof["previous_fleet"] == head
                && proof["repair_backlog_open"] == true
                && proof["resource_samples_taken"] == 0,
            "native154 terminal proof crosses owner or predecessor"
        );
        for key in [
            "replay_launch_authorized",
            "archive_completion_claimed",
            "publication_authorized",
            "local_retirement_authorized",
            "remote_mutations",
            "r2_mutations",
        ] {
            ensure!(
                proof[key] == false,
                "native154 terminal grants authority: {key}"
            );
        }
        let native = &proof["terminal_manager"];
        ensure!(
            native["InvocationID"] == c["invocation_id"]
                && native["MainPID"] == "0"
                && native["ControlPID"] == "0"
                && native["NRestarts"] == "0"
                && same_exec_start(&native["ExecStart"], &c["expected_exec_start"])
                && ((native["ActiveState"] == "active" && native["SubState"] == "exited")
                    || (native["ActiveState"] == "failed" && native["SubState"] == "failed")),
            "native154 terminal owner is live or replaced"
        );
        for key in [
            "InvocationID",
            "MainPID",
            "ControlPID",
            "NRestarts",
            "ExecStart",
            "ActiveState",
            "SubState",
        ] {
            ensure!(
                fleet["unit_census"][NATIVE154_UNIT][key] == native[key],
                "native154 terminal fleet differs from proof: {key}"
            );
        }
        expected["admission_transition_guard"] = Value::Null;
        validate_native154_event(
            fleet,
            plan,
            &head,
            &predecessor["observer"],
            &sample,
            &t["terminal"]["fleet_plan"],
            &t["terminal"]["proof"],
        )?;
        for key in [
            "tracked_units",
            "pipeline_claims",
            "diagnostics",
            "runtime_handoff157",
            "admission_transition_guard",
            "gates",
        ] {
            ensure!(
                plan[key] == expected[key],
                "native154 terminal changed retained policy: {key}"
            );
        }
        head = t["terminal"]["fleet"].clone();
    }
    ensure!(
        !t["entry"].is_null() || !t["terminal"].is_null(),
        "empty native154 transition"
    );
    let claim = claim.context("native154 transition lacks exact claim")?;
    let native = &e.fleet["unit_census"][NATIVE154_UNIT];
    ensure!(
        native["InvocationID"] == claim["invocation_id"]
            && native["NRestarts"] == "0"
            && same_exec_start(&native["ExecStart"], &claim["expected_exec_start"])
            && e.fleet_plan["gates"]["154"]["state"] == "blocked-qualification",
        "current native154 owner, command, or blocked gate differs"
    );
    for key in [
        "tracked_units",
        "pipeline_claims",
        "diagnostics",
        "runtime_handoff157",
        "admission_transition_guard",
    ] {
        ensure!(
            cohort183_retained_plan(e)?[key] == expected[key],
            "native154 recovery changed retained history: {key}"
        );
    }
    Ok(Some(head))
}

fn validate_native154_event(
    fleet: &Value,
    plan: &Value,
    previous: &Value,
    observer: &Value,
    sample: &Value,
    plan_binding: &Value,
    event_binding: &Value,
) -> Result<()> {
    ensure!(
        fleet["schema"] == "jetstreamer-horizon-campaign-fleet-v1"
            && fleet["first_epoch"] == 101
            && fleet["last_epoch"] == 200
            && fleet["inventory"]["anomalies"] == 0
            && fleet["previous_fleet"] == *previous
            && plan["previous_fleet"] == *previous
            && fleet["observer_receipt"] == observer["path"]
            && fleet["observer_sha256"] == observer["sha256"]
            && fleet["sampled_at_utc"] == *sample
            && plan["observer"] == *observer
            && fleet["plan"] == plan_binding["path"]
            && fleet["plan_sha256"] == plan_binding["sha256"]
            && fleet["metadata_event"] == *event_binding
            && plan["metadata_event"] == *event_binding,
        "native154 event lacks exact authenticated fleet/observer/proof binding"
    );
    Ok(())
}

fn authority_denied(frame: &Value) -> Result<()> {
    for key in [
        "replay_launch_authorized",
        "publication_authorized",
        "remote_mutations",
        "remaining_growth_released",
        "new191_closure_incremental_DATA_credit_bytes",
        "archive_mutations",
        "sidecar_mutations",
    ] {
        ensure!(
            frame[key]
                == if key.ends_with("_bytes") {
                    json!(0)
                } else {
                    json!(false)
                },
            "resource lineage grants authority or credit: {key}"
        );
    }
    Ok(())
}

pub const COHORT183_CONTROLLER: &str =
    "jetstreamer-epochs183-184-readerfix-full-20261023-controller-v2-r2.service";
pub const COHORT183_PRODUCER: &str =
    "jetstreamer-root-sweep-e183-184-full-20261023-v2-r2-e183-184-lane-a-1.service";
pub const COHORT183_IMPORTER: &str =
    "jetstreamer-root-import-e183-184-full-20261023-v2-r2-e183-184-2.service";
pub const COHORT183_CAPTURE_SHA: &str =
    "a3c716f7f810d21d433539794d2e44729b761539624c373a66b3a79fb051d824";
pub const REFRESH_SCHEMA: &str = "jetstreamer-horizon-cohort183-recovered-frame-refresh-v1";
const COHORT183_CONTROLLER_IID: &str = "a4a903998b45470a9315861f986a2b1d";
const COHORT183_IMPORTER_IID: &str = "911492dba9114891a95f168383a0da7f";
const COHORT183_BATCH_SHA: &str =
    "433f668b7efee917040c65f214bf6a476ac0bcd96a1160addce765c5ab4a47e6";
const COHORT183_BATCH: &str = "/home/sol/.jetstreamer-private/epochs183-184-readerfix-20261020-v1/lane-a/private/destination-5fad4af8232cf109b3de38ce6f2e8b0b5de809152d314dc95d1a6ab7f168b90c/evidence/archive-batches/destination-000000000000fc00-00000000064b03fa/batch-1e009cb9b1bbf09e1211769f8964e925364d56f2cc60a10de39df2666647bec8.json";

// Remove only the explicitly declared, independently checked handoff additions
// before comparing the retained native154 and original fleet policy lineage.
fn cohort183_retained_plan(e: &Evidence<'_>) -> Result<Value> {
    let mut plan = e.fleet_plan.clone();
    let Some(t) = e.cohort183_transition else {
        return Ok(plan);
    };
    if t["schema"] == REFRESH_SCHEMA {
        return Ok(plan);
    }
    ensure!(
        t["schema"] == "jetstreamer-horizon-cohort183-recovered-frame-transition-v1",
        "foreign 183 transition"
    );
    ensure!(
        t["added_tracked_units"] == json!([COHORT183_IMPORTER]),
        "183 transition adds unrelated units"
    );
    let units = plan["tracked_units"]
        .as_array_mut()
        .context("183 tracked units")?;
    ensure!(
        units.iter().filter(|u| **u == COHORT183_IMPORTER).count() == 1,
        "183 importer missing or duplicated"
    );
    units.retain(|u| *u != COHORT183_IMPORTER);
    let added = t["added_pipeline_claims"]
        .as_array()
        .context("183 added claims")?;
    ensure!(added.len() == 2, "183 handoff requires exactly two claims");
    let claims = plan["pipeline_claims"]
        .as_array_mut()
        .context("183 pipeline claims")?;
    for epoch in [183, 184] {
        let selected: Vec<_> = added.iter().filter(|c| c["epoch"] == epoch).collect();
        ensure!(selected.len() == 1, "183 handoff claim census differs");
        let c = selected[0];
        ensure!(
            c["unit"] == COHORT183_CONTROLLER
                && c["invocation_id"] == COHORT183_CONTROLLER_IID
                && c["phase"] == "controller-import-handoff",
            "183 handoff crosses original owner"
        );
        ensure!(
            claims.iter().filter(|v| *v == c).count() == 1,
            "declared 183 handoff claim missing or duplicated"
        );
        claims.retain(|v| v != c);
    }
    Ok(plan)
}

fn observation_bridge(
    e: &Evidence<'_>,
    predecessor: &Value,
    initial_fleet: &Value,
) -> Result<(Value, Value)> {
    let mut fleet_head = initial_fleet.clone();
    let mut observer_head = predecessor["observer"].clone();
    let Some(rows) = e
        .cohort183_transition
        .and_then(|t| t["observation_bridge"].as_array())
    else {
        ensure!(
            e.cohort183_sources.keys().all(|key| {
                [
                    "canonical_import",
                    "source_batch_snapshot",
                    "canonical_batch_snapshot",
                ]
                .contains(&key.as_str())
            }) && (!e.cohort183_sources.is_empty())
                == e.cohort183_transition
                    .is_some_and(|t| !t["canonical_import"].is_null()),
            "undeclared observation bridge sources"
        );
        return Ok((fleet_head, observer_head));
    };
    ensure!(
        !rows.is_empty() && rows.len() <= 16,
        "invalid observation bridge length"
    );
    let mut previous_time = utc_seconds(
        e.prior_recovery.context("observation bridge predecessor")?["sampled_at_utc"]
            .as_str()
            .context("bridge prior clock")?,
    )?;
    let mut expected_sources = 0;
    for (index, row) in rows.iter().enumerate() {
        let source = |member: &str| {
            e.cohort183_sources
                .get(&format!("bridge.{index}.{member}"))
                .context("bridge source missing")
        };
        let observer = source("observer")?;
        expected_sources += 1;
        let sample = utc_seconds(
            observer["recorded_at_utc"]
                .as_str()
                .context("bridge sample clock")?,
        )?;
        ensure!(
            observer["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
                && observer["cadence"]["routine_minimum_interval_enforced"] == true
                && observer["cadence"]["minimum_interval_seconds"] == 1800
                && observer["cadence"]["observed_interval_seconds"]
                    .as_u64()
                    .is_some_and(|n| n >= 1800)
                && observer["cadence"]["previous_sample"] == observer_head["path"]
                && observer["cadence"]["previous_sample_sha256"] == observer_head["sha256"]
                && sample >= previous_time + 1800,
            "observation bridge lost genuine cadence or predecessor"
        );
        if !row["fleet"].is_null() {
            let fleet = source("fleet")?;
            let plan = source("fleet_plan")?;
            expected_sources += 2;
            ensure!(
                fleet["schema"] == "jetstreamer-horizon-campaign-fleet-v1"
                    && fleet["first_epoch"] == 101
                    && fleet["last_epoch"] == 200
                    && fleet["inventory"]["anomalies"] == 0
                    && fleet["previous_fleet"] == fleet_head
                    && plan["previous_fleet"] == fleet_head
                    && fleet["observer_receipt"] == row["observer"]["path"]
                    && fleet["observer_sha256"] == row["observer"]["sha256"]
                    && fleet["sampled_at_utc"] == observer["recorded_at_utc"]
                    && fleet["plan"] == row["fleet_plan"]["path"]
                    && fleet["plan_sha256"] == row["fleet_plan"]["sha256"]
                    && plan["observer"] == row["observer"]
                    && fleet["metadata_event"].is_null(),
                "observation bridge invents a metadata event or crosses fleet ancestry"
            );
            let retained = cohort183_retained_plan(e)?;
            for key in [
                "tracked_units",
                "pipeline_claims",
                "diagnostics",
                "runtime_handoff157",
                "admission_transition_guard",
            ] {
                ensure!(
                    plan[key] == retained[key],
                    "observation bridge changed retained policy: {key}"
                );
            }
            let units = plan["tracked_units"]
                .as_array()
                .context("bridge tracked units")?;
            let census = fleet["unit_census"].as_object().context("bridge census")?;
            ensure!(
                units.len() >= 531
                    && units
                        .iter()
                        .all(|u| u.as_str().is_some_and(|s| census.contains_key(s))),
                "bridge lost historical census"
            );
            let native = &fleet["unit_census"][NATIVE154_UNIT];
            ensure!(
                native["InvocationID"] == "d72e8d32d0a24087b7e239f300439ebf"
                    && native["MainPID"] == "0"
                    && native["NRestarts"] == "0"
                    && native["ActiveState"] == "active"
                    && native["SubState"] == "exited"
                    && native["Result"] == "success"
                    && native["ExecMainStatus"] == "0",
                "bridge154 census is not the genuine successful exited probe"
            );
            fleet_head = row["fleet"].clone();
        } else {
            ensure!(
                row["fleet_plan"].is_null(),
                "bridge plan lacks observed fleet"
            );
        }
        observer_head = row["observer"].clone();
        previous_time = sample;
    }
    ensure!(
        e.cohort183_sources.len()
            == expected_sources
                + usize::from(
                    e.cohort183_transition
                        .is_some_and(|t| !t["canonical_import"].is_null())
                ) * 3,
        "observation bridge source census differs"
    );
    ensure!(
        utc_seconds(
            e.observer["recorded_at_utc"]
                .as_str()
                .context("current sample clock")?
        )? >= previous_time + 1800,
        "current sample does not advance the final observation bridge clock"
    );
    Ok((fleet_head, observer_head))
}

fn validate_cohort183(e: &Evidence<'_>, bindings: &Value, sample: u64) -> Result<()> {
    let t = e.cohort183_transition.context("183 transition missing")?;
    ensure!(
        e.prior_recovery.is_some()
            && !bindings["cohort183_transition"].is_null()
            && t["previous_recovery"] == bindings["prior_recovery"]
            && t["prior_fleet_plan"] == bindings["prior_fleet_plan"]
            && t["fleet_plan"] == bindings["fleet_plan"]
            && t["repair_incident_remains_open"] == true,
        "183 handoff lost ancestry or closed the repair incident"
    );
    authority_denied(t)?;
    ensure!(
        t["gate_updates"]
            .as_object()
            .is_some_and(|m| m.len() == 2 && m.contains_key("183") && m.contains_key("184")),
        "183 gate update scope differs"
    );
    validate_cohort183_owners(e, &t["added_pipeline_claims"], sample)
}

fn validate_cohort183_owners(e: &Evidence<'_>, claims: &Value, sample: u64) -> Result<()> {
    let pipelines = e.fleet["pipelines"]
        .as_array()
        .context("183 fleet pipelines")?;
    let mut handoff = None;
    for epoch in [183, 184] {
        let selected: Vec<_> = pipelines
            .iter()
            .filter(|v| v["epoch"] == epoch && v["phase"] == "controller-import-handoff")
            .collect();
        ensure!(selected.len() == 1, "183 pipeline missing or duplicated");
        let row = selected[0];
        let proof = &row["finalization_evidence"];
        let c = claims
            .as_array()
            .context("183 claims")?
            .iter()
            .find(|c| c["epoch"] == epoch)
            .context("183 claim")?;
        ensure!(
            row["live"] == true
                && row["phase"] == "controller-import-handoff"
                && row["expected_invocation_id"] == COHORT183_CONTROLLER_IID
                && row["unit"] == e.fleet["unit_census"][COHORT183_CONTROLLER]
                && row["evidence"] == c["evidence"]
                && row["sampled_at_utc"] == e.observer["recorded_at_utc"]
                && row["ordinary_replay_claim"] == false
                && row["grants_launch_or_publication_authority"] == false
                && same_exec_start(&c["expected_exec_start"], &row["unit"]["ExecStart"]),
            "183 pipeline owner or evidence differs"
        );
        ensure!(
            handoff.is_none_or(|old: &Value| old == proof),
            "183 handoff proofs differ across the cohort"
        );
        handoff = Some(proof);
    }
    let p = handoff.context("183 handoff proof")?;
    ensure!(
        p["schema"] == "jetstreamer-cohort183-controller-import-handoff-v1"
            && p["controller"] == e.fleet["unit_census"][COHORT183_CONTROLLER]
            && p["producer"] == e.fleet["unit_census"][COHORT183_PRODUCER]
            && p["importer"] == e.fleet["unit_census"][COHORT183_IMPORTER]
            && p["source_batch"] == json!({"path":COHORT183_BATCH,"sha256":COHORT183_BATCH_SHA})
            && p["replay_finished"] == true
            && p["resource_credit_bytes"] == 0
            && p["archive_hash_performed"] == false
            && p["verification_complete"] == false
            && p["publication_authorized"] == false
            && p["replay_launch_authorized"] == false
            && p["r2_mutations"] == false,
        "183 handoff lacks exact native census or grants credit/authority"
    );
    for (key, value) in [
        ("Id", COHORT183_CONTROLLER),
        ("InvocationID", COHORT183_CONTROLLER_IID),
        ("MainPID", "514397"),
        ("LoadState", "loaded"),
        ("ActiveState", "active"),
        ("SubState", "running"),
        ("NRestarts", "0"),
    ] {
        ensure!(
            p["controller"][key] == value,
            "183 controller differs: {key}"
        );
    }
    let command = p["controller"]["ExecStart"]
        .as_str()
        .and_then(|s| s.split_once(" ; ignore_errors="))
        .context("183 controller command")?
        .0;
    ensure!(
        format!("{:x}", Sha256::digest(command.as_bytes()))
            == "b35320ea3cc7395b3d8a01d566379441fa093d3105a3cb6e9936a11ab1f3bec8",
        "183 controller command changed"
    );
    let producer = &p["producer"];
    ensure!(
        producer["Id"] == COHORT183_PRODUCER
            && producer["MainPID"] == "0"
            && producer["NRestarts"] == "0"
            && producer["ActiveState"] == "inactive"
            && producer["SubState"] == "dead"
            && producer["Result"] == "success"
            && producer["ExecMainStatus"] == "0"
            && ((producer["LoadState"] == "not-found" && producer["InvocationID"] == "")
                || (producer["LoadState"] == "loaded"
                    && (producer["InvocationID"] == ""
                        || producer["InvocationID"] == "489e219d38d14d4594d8649ff698f666"))),
        "183 producer not cleanly terminal"
    );
    let terminal = &p["producer_terminal_manager"];
    for (key, value) in [
        ("UNIT", COHORT183_PRODUCER),
        ("INVOCATION_ID", "489e219d38d14d4594d8649ff698f666"),
        ("_PID", "1"),
        ("_UID", "0"),
        ("MESSAGE_ID", "7ad2d189f7e94e70a38c781354912448"),
        ("__REALTIME_TIMESTAMP", "1793312662979294"),
    ] {
        ensure!(
            terminal[key] == value,
            "183 terminal manager differs: {key}"
        );
    }
    ensure!(
        terminal["MESSAGE"] == format!("{COHORT183_PRODUCER}: Deactivated successfully.")
            && sample >= 1793312663,
        "183 terminal event is future or not success"
    );
    let state = &p["controller_state"];
    let a = &state["assignments"]["lane-a"];
    ensure!(
        state["schema"] == "jetstreamer-adaptive-root-cohort-sweep-v3"
            && state["configuration_sha256"]
                == "85b2f382af78b0fb722ff60dc3069d8c9844ae1a0a5a6816230ac66e432248b4"
            && state["manifest_fingerprint"]
                == "sha256:e74726a897764d53bb6f11858e5a732366fba5d6be54a15dc87c71fca3ea3a64"
            && state["public_dir"] == "/home/sol/horizon"
            && state["assignments"]
                .as_object()
                .is_some_and(|m| m.len() == 1)
            && state["import_owner"] == "lane-a"
            && a["phase"] == "importing"
            && a["first_epoch"] == 183
            && a["last_epoch"] == 184
            && a["attempt"] == 1
            && a["unit"] == COHORT183_PRODUCER
            && a["pid"] == 293448
            && a["pid_start_time"] == 106887499
            && a["receipt"] == COHORT183_BATCH
            && a["failure"].is_null()
            && a["source_recovery"] != true
            && a["import_unit"] == COHORT183_IMPORTER,
        "183 original controller import assignment differs"
    );
    let importer = &p["importer"];
    for (key, value) in [
        ("Id", COHORT183_IMPORTER),
        ("InvocationID", COHORT183_IMPORTER_IID),
        ("LoadState", "loaded"),
        ("ActiveState", "active"),
        ("SubState", "running"),
        ("NRestarts", "0"),
    ] {
        ensure!(importer[key] == value, "183 importer differs: {key}");
    }
    ensure!(
        importer["MainPID"]
            .as_str()
            .is_some_and(|s| s.parse::<u32>().is_ok_and(|p| p > 0)),
        "183 importer PID missing"
    );
    let command = importer["ExecStart"]
        .as_str()
        .and_then(exec_start_identity)
        .context("183 importer command")?;
    ensure!(command.contains("jetstreamer-node 183-184 /home/sol/horizon --verify --recover-staged-cohort-only ")
        && command.contains(&format!(" --source-cohort-receipt={COHORT183_BATCH} --publish-through-epoch=184 ; ignore_errors=no")), "183 importer command crossed source or scope");
    Ok(())
}

// A refresh retains the accepted import policy. It does not repeat the original
// replay-to-import delta, release growth, or invent a routine completion.
fn verifier_source<'a>(e: &'a Evidence<'_>, name: &str) -> Result<&'a Value> {
    e.cohort183_sources
        .get(&format!("verifier183.{name}"))
        .with_context(|| format!("183 verifier source missing: {name}"))
}

fn retained_policy(plan: &Value) -> Result<Value> {
    let mut policy = plan
        .as_object()
        .context("verifier history plan object")?
        .clone();
    for key in ["observer", "output", "previous_fleet", "metadata_event"] {
        policy.remove(key);
    }
    Ok(Value::Object(policy))
}

fn fleet_binding(fleet: &Value, plan: &Value, plan_bound: &Value, observer: &Value) -> Result<()> {
    ensure!(
        fleet["schema"] == "jetstreamer-horizon-campaign-fleet-v1"
            && fleet["first_epoch"] == 101
            && fleet["last_epoch"] == 200
            && fleet["inventory"]["anomalies"] == 0
            && fleet["plan"] == plan_bound["path"]
            && fleet["plan_sha256"] == plan_bound["sha256"]
            && fleet["observer_receipt"] == observer["path"]
            && fleet["observer_sha256"] == observer["sha256"]
            && plan["observer"] == *observer,
        "183 metadata fleet/plan/resource binding differs"
    );
    for key in [
        "producer_mutations",
        "publication_authorized",
        "remote_mutations",
    ] {
        ensure!(
            fleet[key] == false,
            "183 metadata fleet grants authority: {key}"
        );
    }
    Ok(())
}

// Intermediate observations retain their real clocks without inventing a fleet.
fn verifier183_observer_bridge(
    e: &Evidence<'_>,
    previous: &Value,
    sample: u64,
) -> Result<(Value, usize)> {
    let mut head = previous["bindings"]["observer"].clone();
    let mut clock = utc_seconds(
        previous["sampled_at_utc"]
            .as_str()
            .context("183 prior observer clock")?,
    )?;
    let t = e
        .cohort183_transition
        .context("183 observer bridge transition")?;
    let Some(rows) = t["observation_bridge"].as_array() else {
        ensure!(
            t["observation_bridge"].is_null(),
            "183 observer bridge is not an array"
        );
        return Ok((head, 0));
    };
    ensure!(
        !rows.is_empty() && rows.len() <= 16,
        "183 observer bridge length differs"
    );
    for (i, row) in rows.iter().enumerate() {
        let observer_only = row
            .as_object()
            .is_some_and(|o| o.len() == 1 && o.contains_key("observer"));
        ensure!(
            observer_only
                || (row["schema"] == private154_downstream_history::FLEET_BRIDGE_SCHEMA
                    && private154_downstream_history::retained_observation_head(e)?.1 > 0),
            "183 bridge lacks an observer-only row or exact retained downstream fleet proof"
        );
        let observer = e
            .cohort183_sources
            .get(&format!("bridge.{i}.observer"))
            .context("183 intermediate observer missing")?;
        let next = utc_seconds(
            observer["recorded_at_utc"]
                .as_str()
                .context("183 intermediate clock")?,
        )?;
        ensure!(
            observer["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
                && observer["cadence"]["routine_minimum_interval_enforced"] == true
                && observer["cadence"]["minimum_interval_seconds"] == 1800
                && observer["cadence"]["previous_sample"] == head["path"]
                && observer["cadence"]["previous_sample_sha256"] == head["sha256"]
                && next >= clock + 1800
                && observer["cadence"]["observed_interval_seconds"] == next - clock,
            "183 intermediate observer lost genuine cadence or ancestry"
        );
        head = row["observer"].clone();
        clock = next;
    }
    ensure!(
        sample >= clock + 1800,
        "183 current observer does not advance the bridge"
    );
    Ok((head, rows.len()))
}

fn validate_verifier183_refresh(
    e: &Evidence<'_>,
    bindings: &Value,
    sample: u64,
    now: u64,
) -> Result<()> {
    let t = e
        .cohort183_transition
        .context("verifier refresh transition")?;
    let previous = e.prior_recovery.context("verifier refresh predecessor")?;
    let history = &t["verifier183"];
    authority_denied(t)?;
    ensure!(
        t["schema"] == REFRESH_SCHEMA
            && t["previous_recovery"] == bindings["prior_recovery"]
            && t["prior_fleet_plan"] == bindings["prior_fleet_plan"]
            && t["fleet_plan"] == bindings["fleet_plan"]
            && t["previous_cohort183_transition"] == previous["bindings"]["cohort183_transition"]
            && t["repair_incident_remains_open"] == true
            && t["gate_updates"].is_null()
            && e.fleet_transition.is_none()
            && bindings["fleet_transition"].is_null()
            && e.native154_transition.is_none()
            && bindings["native154_transition"].is_null()
            && e.native154_sources.is_empty(),
        "183 refresh mixes undeclared transitions or crosses ancestry"
    );
    let allowed = [
        "schema",
        "previous_recovery",
        "prior_fleet_plan",
        "fleet_plan",
        "previous_cohort183_transition",
        "repair_incident_remains_open",
        "replay_launch_authorized",
        "publication_authorized",
        "remote_mutations",
        "remaining_growth_released",
        "new191_closure_incremental_DATA_credit_bytes",
        "archive_mutations",
        "sidecar_mutations",
        "canonical_import",
        "source_batch_snapshot",
        "canonical_batch_snapshot",
        "verifier183",
        "observation_bridge",
    ];
    ensure!(
        t.as_object()
            .context("verifier transition object")?
            .keys()
            .all(|k| allowed.contains(&k.as_str())),
        "183 refresh contains an undeclared field"
    );
    ensure!(
        history["schema"] == "jetstreamer-recovered-verifier183-history-v1"
            && history["full_launch"] == verifier183::launch_binding("full")?
            && history["plugin_launch"] == verifier183::launch_binding("plugin")?
            && history["event"]["path"] == verifier183::EVENT_PATH,
        "foreign 183 verifier history"
    );
    let event = verifier_source(e, "event")?;
    let full = verifier_source(e, "full_launch")?;
    let plugin = verifier_source(e, "plugin_launch")?;
    let event_clock = verifier183::validate_event(event, full, plugin, now, false)?;
    let (observer_head, bridge_count) = verifier183_observer_bridge(e, previous, sample)?;
    let same_observer = bindings["observer"] == previous["bindings"]["observer"];
    let mut expected_previous = previous["bindings"]["fleet"].clone();
    let policy = if history["mode"] == "deferred-entry" {
        let base = verifier_source(e, "previous_fleet")?;
        let old = verifier_source(e, "previous_plan")?;
        let declared = verifier_source(e, "declared_plan")?;
        let registered = !history["entry_fleet"].is_null();
        ensure!(
            history
                .as_object()
                .context("183 deferred entry history")?
                .len()
                == if registered { 10 } else { 8 }
                && !same_observer
                && bridge_count > 0
                && history["previous_fleet"] == previous["bindings"]["fleet"]
                && history["previous_plan"] == bindings["prior_fleet_plan"]
                && old == e.prior_fleet_plan
                && event["previous_fleet"] == history["previous_fleet"]
                && event["previous_plan"] == history["previous_plan"]
                && declared["observer"] == event["resource_observer"]
                && t["observation_bridge"]
                    .as_array()
                    .context("183 declaration observation")?
                    .iter()
                    .any(|row| row["observer"] == event["resource_observer"])
                && declared["metadata_event"] == history["event"]
                && event_clock
                    >= base["recorded_unix_seconds"]
                        .as_u64()
                        .context("183 accepted base clock")?
                && event_clock <= sample,
            "183 deferred entry crossed the accepted head or genuine declared observer"
        );
        fleet_binding(base, old, &history["previous_plan"], &old["observer"])?;
        // This validates the sealed historical declaration, not a historical fleet.
        // Current resources and all current native policies are checked independently.
        verifier183::validate_delta(old, declared, base, event, full, plugin, event_clock)?;
        if registered {
            let entry = verifier_source(e, "entry_fleet")?;
            let entry_plan = verifier_source(e, "entry_plan")?;
            fleet_binding(
                entry,
                entry_plan,
                &history["entry_plan"],
                &entry_plan["observer"],
            )?;
            let observed = t["observation_bridge"]
                .as_array()
                .context("183 registered observer bridge")?;
            ensure!(
                entry["previous_fleet"] == history["previous_fleet"]
                    && entry_plan["previous_fleet"] == history["previous_fleet"]
                    && entry["metadata_event"] == history["event"]
                    && entry_plan["metadata_event"] == history["event"]
                    && retained_policy(entry_plan)? == retained_policy(declared)?
                    && observed
                        .iter()
                        .any(|row| row["observer"] == entry_plan["observer"])
                    && entry["recorded_unix_seconds"]
                        .as_u64()
                        .is_some_and(|clock| utc_seconds(
                            entry["sampled_at_utc"].as_str().unwrap_or("")
                        )
                        .is_ok_and(
                            |sample| clock >= sample && clock <= sample.saturating_add(1800)
                        ))
                    && e.fleet["previous_fleet"] == history["entry_fleet"],
                "183 deferred registration lost its actual fleet, observer, or policy"
            );
            expected_previous = history["entry_fleet"].clone();
        }
        declared
    } else if history["mode"] == "entry" {
        let base = verifier_source(e, "previous_fleet")?;
        let old = verifier_source(e, "previous_plan")?;
        let entry = verifier_source(e, "entry_fleet")?;
        let next = verifier_source(e, "entry_plan")?;
        ensure!(
            history.as_object().context("183 entry history")?.len() == 9
                && event["previous_fleet"] == history["previous_fleet"]
                && event["previous_plan"] == history["previous_plan"]
                && retained_policy(old)? == retained_policy(e.prior_fleet_plan)?
                && old["metadata_event"] == e.prior_fleet_plan["metadata_event"],
            "183 entry changed unregistered predecessor policy"
        );
        fleet_binding(base, old, &history["previous_plan"], &old["observer"])?;
        fleet_binding(entry, next, &history["entry_plan"], &next["observer"])?;
        ensure!(
            entry["previous_fleet"] == history["previous_fleet"]
                && entry["metadata_event"] == history["event"]
                && next["metadata_event"] == history["event"]
                && ((next["observer"] == bindings["observer"]
                    && entry["sampled_at_utc"] == e.observer["recorded_at_utc"])
                    || (next["observer"] == previous["bindings"]["observer"]
                        && entry["sampled_at_utc"] == previous["sampled_at_utc"]))
                && entry["metadata_event_sampled_at_utc"] == event["sampled_at_utc"]
                && event_clock
                    >= base["recorded_unix_seconds"]
                        .as_u64()
                        .context("183 base clock")?,
            "183 entry lost its actual metadata clock or resource predecessor"
        );
        verifier183::validate_delta(old, next, base, event, full, plugin, now)?;
        let direct = history["previous_fleet"] == previous["bindings"]["fleet"]
            && history["previous_plan"] == bindings["prior_fleet_plan"]
            && old == e.prior_fleet_plan;
        let fresh_base = !same_observer
            && base["previous_fleet"] == previous["bindings"]["fleet"]
            && old["previous_fleet"] == previous["bindings"]["fleet"]
            && old["observer"] == bindings["observer"]
            && base["sampled_at_utc"] == e.observer["recorded_at_utc"];
        ensure!(
            direct || fresh_base,
            "183 entry crossed an accepted fleet or genuine fresh base"
        );
        let current_entry = bindings["fleet"] == history["entry_fleet"];
        if current_entry {
            ensure!(
                bindings["fleet_plan"] == history["entry_plan"]
                    && e.fleet == entry
                    && e.fleet_plan == next
                    && next["observer"] == bindings["observer"],
                "183 current event differs from exact authenticated metadata fleet"
            );
            expected_previous = history["previous_fleet"].clone();
        } else {
            ensure!(
                !same_observer && next["observer"] == previous["bindings"]["observer"],
                "183 historical entry crossed its resource observer"
            );
            expected_previous = history["entry_fleet"].clone();
        }
        if same_observer {
            ensure!(
                direct
                    && current_entry
                    && event_clock
                        > previous["recorded_unix_seconds"]
                            .as_u64()
                            .context("prior capture clock")?
                    && e.observer["recorded_at_utc"] == previous["sampled_at_utc"],
                "same-sample 183 transition invents a new resource observation"
            );
        }
        next
    } else {
        ensure!(
            history["mode"] == "retained"
                && history.as_object().context("retained 183 history")?.len() == 5
                && !same_observer,
            "retained183 history cannot repeat a resource sample"
        );
        e.prior_fleet_plan
    };
    ensure!(
        retained_policy(e.fleet_plan)? == retained_policy(policy)?
            && e.fleet_plan["metadata_event"] == history["event"]
            && e.fleet["metadata_event"] == history["event"]
            && e.fleet_plan["previous_fleet"] == expected_previous
            && e.fleet["previous_fleet"] == expected_previous,
        "183 recovery changed retained policy or metadata ancestry"
    );
    if !same_observer {
        ensure!(
            e.observer["cadence"]["previous_sample"] == observer_head["path"]
                && e.observer["cadence"]["previous_sample_sha256"] == observer_head["sha256"],
            "183 recovery lost genuine scheduled observation ancestry"
        );
    }
    for (stage, launch) in [("full", full), ("plugin", plugin)] {
        let claims = e.fleet_plan["pipeline_claims"]
            .as_array()
            .context("183 current claims")?;
        ensure!(
            claims.iter().filter(|c| **c == launch["claim"]).count() == 1
                && launch["unit"]["Id"] == verifier183::unit(stage)?,
            "183 retained verifier claim missing or duplicated"
        );
    }
    let count = match history["mode"].as_str() {
        Some("entry") => 7,
        Some("deferred-entry") => {
            if history["entry_fleet"].is_null() {
                6
            } else {
                8
            }
        }
        _ => 3,
    };
    ensure!(
        !t["canonical_import"].is_null() && e.cohort183_sources.len() == count + 3 + bridge_count,
        "183 recovery source census differs"
    );
    validate_refresh_owners(e, sample)
}

fn verifier_row_clock(e: &Evidence<'_>, claim: &Value, row: &Value, sample: u64) -> Result<bool> {
    if let Some(valid) = private154_downstream_history::row_clock(e, claim, row)? {
        return Ok(valid);
    };
    if let Some(valid) = private154_combined_history::row_clock(e, claim, row)? {
        return Ok(valid);
    }
    if let Some(valid) = private154_scan_history::row_clock(e, claim, row)? {
        return Ok(valid);
    }
    if let Some(valid) = delivery_history::row_clock(e, claim, row, sample)? {
        return Ok(valid);
    }
    let stage = if claim["unit"] == verifier183::unit("full")? {
        Some("full")
    } else if claim["unit"] == verifier183::unit("plugin")? {
        Some("plugin")
    } else {
        None
    };
    let Some(stage) = stage else {
        return Ok(row["sampled_at_utc"] == e.observer["recorded_at_utc"]);
    };
    let t = e.cohort183_transition.context("183 row refresh")?;
    let history = &t["verifier183"];
    ensure!(!history.is_null(), "183 verifier row lacks typed lineage");
    let launch = verifier_source(e, &format!("{stage}_launch"))?;
    verifier183::validate_launch(stage, launch)?;
    let event = verifier_source(e, "event")?;
    let clock =
        verifier183::projection_clock(sample, event["recorded_unix_seconds"].as_u64(), launch)?;
    Ok(*claim == launch["claim"]
        && row["sampled_at_utc"] == verifier183::utc(clock)?
        && row["resource_sampled_at_utc"] == e.observer["recorded_at_utc"]
        && row["actual_native_launch"] == history[format!("{stage}_launch")]
        && row["phase_started_unix_seconds"] == launch["recorded_unix_seconds"]
        && row["new_resource_samples"] == 0)
}

fn validate_refresh(e: &Evidence<'_>, bindings: &Value, sample: u64) -> Result<()> {
    let t = e
        .cohort183_transition
        .context("refresh transition missing")?;
    let previous = e.prior_recovery.context("refresh predecessor missing")?;
    ensure!(
        t["schema"] == REFRESH_SCHEMA
            && !bindings["cohort183_transition"].is_null()
            && t["previous_recovery"] == bindings["prior_recovery"]
            && t["prior_fleet_plan"] == bindings["prior_fleet_plan"]
            && t["fleet_plan"] == bindings["fleet_plan"]
            && t["previous_cohort183_transition"] == previous["bindings"]["cohort183_transition"]
            && !t["previous_cohort183_transition"].is_null()
            && t["repair_incident_remains_open"] == true
            && e.fleet_transition.is_none()
            && bindings["fleet_transition"].is_null()
            && e.native154_transition.is_none()
            && bindings["native154_transition"].is_null()
            && e.native154_sources.is_empty(),
        "refresh crossed accepted ancestry or combined undeclared policy changes"
    );
    authority_denied(t)?;
    let allowed = [
        "schema",
        "previous_recovery",
        "prior_fleet_plan",
        "fleet_plan",
        "previous_cohort183_transition",
        "repair_incident_remains_open",
        "observation_bridge",
        "replay_launch_authorized",
        "publication_authorized",
        "remote_mutations",
        "remaining_growth_released",
        "new191_closure_incremental_DATA_credit_bytes",
        "archive_mutations",
        "sidecar_mutations",
        "canonical_import",
        "source_batch_snapshot",
        "canonical_batch_snapshot",
        "gate_updates",
    ];
    ensure!(
        t.as_object()
            .context("refresh transition object")?
            .keys()
            .all(|key| allowed.contains(&key.as_str())),
        "refresh includes an undeclared transition field"
    );
    for key in [
        "schema",
        "first_epoch",
        "last_epoch",
        "tracked_units",
        "diagnostics",
        "pipeline_claims",
        "runtime_handoff157",
        "admission_transition_guard",
    ] {
        ensure!(
            e.fleet_plan[key] == e.prior_fleet_plan[key],
            "refresh changed retained policy: {key}"
        );
    }
    let retained_policy = |plan: &Value| -> Result<Value> {
        let mut policy = plan.as_object().context("refresh plan object")?.clone();
        for key in [
            "observer",
            "output",
            "previous_fleet",
            "metadata_event",
            "gates",
        ] {
            policy.remove(key);
        }
        Ok(Value::Object(policy))
    };
    ensure!(
        retained_policy(e.fleet_plan)? == retained_policy(e.prior_fleet_plan)?,
        "refresh changed undeclared retained plan policy"
    );
    let mut expected_gates = e.prior_fleet_plan["gates"].clone();
    if !t["gate_updates"].is_null() {
        let updates = t["gate_updates"]
            .as_object()
            .context("refresh gate updates")?;
        ensure!(
            !t["canonical_import"].is_null()
                && updates.len() == 2
                && updates.keys().all(|k| ["183", "184"].contains(&k.as_str())),
            "refresh gate delta lacks exact terminal cohort scope"
        );
        for epoch in ["183", "184"] {
            let old = &e.prior_fleet_plan["gates"][epoch];
            let new = &e.fleet_plan["gates"][epoch];
            ensure!(
                updates[epoch]["previous_gate"] == *old
                    && updates[epoch]["current_gate"] == *new
                    && old["state"] == "post-replay-pipeline"
                    && new["state"] == old["state"],
                "refresh terminal gate changed state or crossed declared source"
            );
            let before = old["evidence"]
                .as_array()
                .context("refresh prior gate evidence")?;
            let after = new["evidence"]
                .as_array()
                .context("refresh current gate evidence")?;
            ensure!(
                after.len() > before.len()
                    && after[..before.len()] == before[..]
                    && (after.contains(&t["canonical_import"])
                        || after.contains(&json!({"path":cohort183_canonical_import::IMPORT,
                        "sha256":cohort183_canonical_import::IMPORT_SHA})))
                    && new["next_action"].as_str().is_some_and(|s| !s.is_empty()),
                "refresh terminal gate lacks append-only actual import evidence"
            );
            expected_gates[epoch]["evidence"] = new["evidence"].clone();
            expected_gates[epoch]["next_action"] = new["next_action"].clone();
        }
    }
    ensure!(
        e.fleet_plan["gates"] == expected_gates,
        "refresh changed an undeclared gate field"
    );
    let (fleet_head, observer_head) =
        observation_bridge(e, &previous["bindings"], &previous["bindings"]["fleet"])?;
    ensure!(
        e.observer["cadence"]["previous_sample"] == observer_head["path"]
            && e.observer["cadence"]["previous_sample_sha256"] == observer_head["sha256"]
            && e.fleet["previous_fleet"] == fleet_head
            && e.fleet_plan["previous_fleet"] == fleet_head
            && e.fleet["metadata_event"].is_null()
            && e.fleet_plan["metadata_event"].is_null(),
        "refresh lost immediate observed ancestry or introduced a metadata event"
    );
    validate_refresh_owners(e, sample)
}

fn validate_refresh_owners(e: &Evidence<'_>, sample: u64) -> Result<()> {
    let t = e
        .cohort183_transition
        .context("refresh transition missing")?;
    for key in [
        "producer_mutations",
        "publication_authorized",
        "remote_mutations",
    ] {
        ensure!(
            e.fleet[key] == false,
            "refresh fleet grants authority: {key}"
        );
    }
    let units = e.fleet_plan["tracked_units"]
        .as_array()
        .context("refresh tracked units")?;
    let census = e.fleet["unit_census"]
        .as_object()
        .context("refresh native census")?;
    let mut seen = std::collections::BTreeSet::new();
    ensure!(
        units.len() >= 533
            && units.len() == census.len()
            && units.iter().all(|u| u
                .as_str()
                .is_some_and(|s| seen.insert(s) && census.get(s).is_some_and(|n| n["Id"] == s))),
        "refresh native census is incomplete, duplicated, or foreign"
    );
    let claims = e.fleet_plan["pipeline_claims"]
        .as_array()
        .context("refresh pipeline claims")?;
    let pipelines = e.fleet["pipelines"]
        .as_array()
        .context("refresh pipelines")?;
    ensure!(
        claims.len() == pipelines.len(),
        "refresh pipeline census differs"
    );
    let mut seen = std::collections::BTreeSet::new();
    for claim in claims {
        let unit = claim["unit"].as_str().context("refresh claim unit")?;
        let epoch = claim["epoch"].as_u64().context("refresh claim epoch")?;
        let phase = claim["phase"].as_str().context("refresh claim phase")?;
        ensure!(
            seen.insert((epoch, phase, unit)),
            "refresh duplicated a pipeline claim"
        );
        let rows: Vec<_> = pipelines
            .iter()
            .filter(|r| r["epoch"] == epoch && r["phase"] == phase && r["unit"]["Id"] == unit)
            .collect();
        ensure!(rows.len() == 1, "refresh pipeline missing or duplicated");
        let row = rows[0];
        let native = census.get(unit).context("refresh pipeline native owner")?;
        ensure!(
            row["unit"] == *native
                && row["expected_invocation_id"] == claim["invocation_id"]
                && row["evidence"] == claim["evidence"]
                && verifier_row_clock(e, claim, row, sample)?
                && row["ordinary_replay_claim"] == false
                && row["grants_launch_or_publication_authority"] == false
                && row["live"].as_bool().is_some()
                && (native["InvocationID"] == claim["invocation_id"]
                    || (native["InvocationID"] == "" && row["live"] == false))
                && (native["ExecStart"].as_str().unwrap_or("").is_empty()
                    || same_exec_start(&claim["expected_exec_start"], &native["ExecStart"])),
            "refresh pipeline owner, command, or retained evidence differs"
        );
        if row["live"] == true {
            ensure!(
                native["ActiveState"] == "active"
                    && native["SubState"] == "running"
                    && native["NRestarts"] == "0"
                    && native["MainPID"]
                        .as_str()
                        .is_some_and(|s| s.parse::<u32>().is_ok_and(|p| p > 0)),
                "refresh pipeline claims a non-running owner"
            );
        }
    }
    let claims = e.fleet_plan["diagnostics"]
        .as_array()
        .context("refresh diagnostic claims")?;
    let diagnostics = e.fleet["diagnostics"]
        .as_array()
        .context("refresh diagnostics")?;
    ensure!(
        claims.len() == diagnostics.len(),
        "refresh diagnostic census differs"
    );
    let mut seen = std::collections::BTreeSet::new();
    for claim in claims {
        let unit = claim["unit"].as_str().context("refresh diagnostic unit")?;
        ensure!(seen.insert(unit), "refresh duplicated a diagnostic claim");
        let rows: Vec<_> = diagnostics
            .iter()
            .filter(|r| r["unit"]["Id"] == unit)
            .collect();
        ensure!(rows.len() == 1, "refresh diagnostic missing or duplicated");
        let row = rows[0];
        let native = census
            .get(unit)
            .context("refresh diagnostic native owner")?;
        ensure!(
            row["epoch"] == claim["epoch"]
                && row["unit"] == *native
                && row["launch_invocation_id"] == claim["invocation_id"]
                && row["launch_receipt"] == claim["launch_receipt"]["path"]
                && row["launch_receipt_sha256"] == claim["launch_receipt"]["sha256"]
                && row["terminal_outcome_requires_canary_receipt"] == true
                && row["live"].as_bool().is_some()
                && (native["InvocationID"] == claim["invocation_id"]
                    || (native["InvocationID"] == "" && row["live"] == false)),
            "refresh diagnostic owner or launch evidence differs"
        );
    }
    for unit in [CONTROLLER, PRODUCER] {
        let native = &e.fleet["unit_census"][unit];
        ensure!(
            native["MainPID"] == "0"
                && native["NRestarts"] == "0"
                && native["ControlGroup"] == ""
                && native["ActiveState"] == "inactive"
                && native["SubState"] == "dead"
                && native["Result"] == "success",
            "refresh restored a terminal replay owner"
        );
    }
    for epoch in [155, 156] {
        ensure!(
            e.fleet["epochs"]
                .as_array()
                .context("refresh epochs")?
                .iter()
                .any(|r| r["epoch"] == epoch && r["state"] == "remote-ready"),
            "refresh lost terminal ready-pair census"
        );
    }
    ensure!(
        e.observer["replays"]
            .as_array()
            .is_some_and(|r| r.is_empty()),
        "refresh invented an ordinary replay owner"
    );
    if !t["canonical_import"].is_null() {
        return validate_terminal_import_refresh(e, t, sample);
    }
    ensure!(
        t["source_batch_snapshot"].is_null() && t["canonical_batch_snapshot"].is_null(),
        "refresh batch snapshots lack terminal import proof"
    );
    validate_cohort183_owners(e, &e.fleet_plan["pipeline_claims"], sample)
}

fn validate_terminal_import_refresh(e: &Evidence<'_>, t: &Value, sample: u64) -> Result<()> {
    let source = |name: &str| -> Result<&Value> {
        e.cohort183_sources
            .get(name)
            .with_context(|| format!("terminal refresh source missing: {name}"))
    };
    let proof = source("canonical_import")?;
    ensure!(
        t["source_batch_snapshot"]["sha256"] == cohort183_canonical_import::SOURCE_SHA
            && t["canonical_batch_snapshot"]["sha256"] == cohort183_canonical_import::IMPORT_SHA
            && *source("source_batch_snapshot")? == proof["source_batch"]
            && *source("canonical_batch_snapshot")? == proof["canonical_batch"],
        "terminal refresh raw batch snapshots crossed canonical provenance"
    );
    cohort183_canonical_import::validate(proof, sample)?;
    for (kind, unit) in [
        ("controller", COHORT183_CONTROLLER),
        ("producer", COHORT183_PRODUCER),
        ("importer", COHORT183_IMPORTER),
    ] {
        let expected = &e.fleet["unit_census"][unit];
        for key in [
            "Id",
            "LoadState",
            "InvocationID",
            "ActiveState",
            "SubState",
            "MainPID",
            "NRestarts",
            "Result",
            "ExecMainStatus",
            "ControlGroup",
            "Type",
        ] {
            ensure!(
                expected[key].as_str().unwrap_or("") == proof[kind][key].as_str().unwrap_or(""),
                "terminal refresh proof crossed current census: {kind}/{key}"
            );
        }
        ensure!(
            expected["ExecStart"].as_str().unwrap_or("")
                == proof[kind]["ExecStart"].as_str().unwrap_or("")
                || same_exec_start(&expected["ExecStart"], &proof[kind]["ExecStart"]),
            "terminal refresh proof changed native command: {kind}"
        );
    }
    let pipelines = e.fleet["pipelines"]
        .as_array()
        .context("terminal refresh pipelines")?;
    for epoch in [183, 184] {
        let rows: Vec<_> = pipelines
            .iter()
            .filter(|r| r["epoch"] == epoch && r["phase"] == "controller-import-handoff")
            .collect();
        ensure!(
            rows.len() == 1
                && rows[0]["live"] == false
                && rows[0]["phase"] == "controller-import-handoff"
                && rows[0]["finalization_evidence"] == *proof,
            "terminal refresh retains a live import claim or crossed proof"
        );
    }
    Ok(())
}

fn validate_gate_delta(e: &Evidence<'_>, bindings: &Value, epoch: i32) -> Result<()> {
    let name = epoch.to_string();
    let old = &e.prior_fleet_plan["gates"][&name];
    let new = &e.fleet_plan["gates"][&name];
    let cohort = [183, 184].contains(&epoch) && e.cohort183_transition.is_some();
    let delta = if cohort {
        e.cohort183_transition
    } else {
        e.fleet_transition
    };
    let Some(delta) = delta else {
        ensure!(old == new, "unrelated epoch gate changed");
        return Ok(());
    };
    let update = &delta["gate_updates"][&name];
    if update.is_null() {
        ensure!(old == new, "undeclared epoch gate changed");
        return Ok(());
    }
    ensure!(
        ([136, 154].contains(&epoch) || cohort)
            && update["previous_gate"] == *old
            && update["current_gate"] == *new
            && if cohort {
                old["state"] == "failed-needs-repair" && new["state"] == "post-replay-pipeline"
            } else {
                old["state"] == "blocked-qualification" && new["state"] == old["state"]
            },
        "gate repair crossed scope, state, or declared source"
    );
    let mut expected = old.clone();
    if cohort {
        expected["state"] = json!("post-replay-pipeline");
    }
    expected["next_action"] = new["next_action"].clone();
    expected["evidence"] = new["evidence"].clone();
    let before = old["evidence"]
        .as_array()
        .context("prior gate evidence missing")?;
    let after = new["evidence"]
        .as_array()
        .context("current gate evidence missing")?;
    ensure!(
        expected == *new
            && new["next_action"].as_str().is_some_and(|s| !s.is_empty())
            && after.len() > before.len()
            && after[..before.len()] == before[..],
        "gate repair changed policy or failed append-only evidence"
    );
    ensure!(
        delta["prior_fleet_plan"] == bindings["prior_fleet_plan"]
            && delta["fleet_plan"] == bindings["fleet_plan"],
        "gate delta crossed plan binding"
    );
    Ok(())
}

pub fn utc_seconds(value: &str) -> Result<u64> {
    ensure!(
        value.len() == 20 && value.is_ascii(),
        "noncanonical UTC time"
    );
    let raw = std::ffi::CString::new(value)?;
    let mut parsed: libc::tm = unsafe { std::mem::zeroed() };
    let end = unsafe { libc::strptime(raw.as_ptr(), c"%Y-%m-%dT%H:%M:%SZ".as_ptr(), &mut parsed) };
    ensure!(!end.is_null() && unsafe { *end } == 0, "invalid UTC time");
    let seconds = u64::try_from(unsafe { libc::timegm(&mut parsed) })?;
    let mut normalized: libc::tm = unsafe { std::mem::zeroed() };
    let raw_time: libc::time_t = seconds.try_into()?;
    ensure!(
        !unsafe { libc::gmtime_r(&raw_time, &mut normalized) }.is_null(),
        "UTC conversion failed"
    );
    let canonical = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        normalized.tm_year + 1900,
        normalized.tm_mon + 1,
        normalized.tm_mday,
        normalized.tm_hour,
        normalized.tm_min,
        normalized.tm_sec
    );
    ensure!(canonical == value, "normalized UTC time rejected");
    Ok(seconds)
}

mod input137_frame;
pub mod input137_source_loader;
/// Explicit typed terminal profile; historical wrappers and pins stay unchanged.
pub fn validate_evidence_retained199(
    e: &Evidence<'_>,
    bindings: &Value,
    now: u64,
    context: &terminal199_context::Retained,
) -> Result<()> {
    let proof = ordinary199_frame::proof_for_context(e, context)?
        .context("retained199 explicit enrollment absent")?;
    let views = ordinary199_frame::Views::prepare_retained(e, &proof, context)?;
    validate_evidence_without199(&views.evidence(e), bindings, now)
}
pub fn validate_evidence(e: &Evidence<'_>, bindings: &Value, now: u64) -> Result<()> {
    if let Some(context) = ordinary199::terminal_context(e.fleet_plan)? {
        return validate_evidence_retained199(e, bindings, now, &context);
    }
    if let Some(proof) = ordinary199_frame::proof(e)? {
        let views = ordinary199_frame::Views::prepare(e, &proof)?;
        return validate_evidence_without199(&views.evidence(e), bindings, now);
    }
    validate_evidence_without199(e, bindings, now)
}
fn validate_evidence_without199(e: &Evidence<'_>, bindings: &Value, now: u64) -> Result<()> {
    if charge136_retry0005_frame::selected(e) {
        charge136_retry0005_frame::validate(e, bindings, now)
    } else {
        validate_evidence_without_retry0005(e, bindings, now)
    }
}
fn validate_evidence_without_retry0005(e: &Evidence<'_>, bindings: &Value, now: u64) -> Result<()> {
    if input137_frame::selected(e) {
        input137_frame::validate(e, bindings, now)
    } else {
        validate_evidence_without137(e, bindings, now)
    }
}
fn validate_evidence_without137(e: &Evidence<'_>, bindings: &Value, now: u64) -> Result<()> {
    if charge136_retry0004_frame::selected(e) {
        charge136_retry0004_frame::validate(e, bindings, now)
    } else {
        validate_evidence_without_retry0004(e, bindings, now)
    }
}
fn validate_evidence_without_retry0004(e: &Evidence<'_>, bindings: &Value, now: u64) -> Result<()> {
    if cached145_frame::selected(e) {
        cached145_frame::validate(e, bindings, now)
    } else {
        validate_evidence_without_cached145(e, bindings, now)
    }
}

// Exact independently qualified and normally sealed ordinary199 Frame v5.
// Its real package/proof/acceptance bytes are bound by regression fixtures.
const QUALIFIED_ORDINARY199_FRAME_V5_CAPTURE_SHA: &str =
    "79d4b08d0fb9a17363e85fb4b6b7462fab0a871d46fbd39ce2112240a8414acb";

// Already qualified canonical helper-v4 capture retained as a predecessor.
// The final writer's existing exact registered capture pin supplies this value.
const QUALIFIED_HELPER_V4_FRAME_CAPTURE_SHA: &str =
    "9981800180cabf7b6ccecb590dc460b0499cb44266becc6709f46c0525f60384";

fn qualified_previous_recovery_envelope(
    previous: &Value,
    binding: &Value,
    current: &str,
) -> Result<()> {
    ensure!(
        !binding.is_null()
            && previous["schema"] == SCHEMA
            && previous["accepted_resource_lineage"] == true
            && previous["full_routine_completion_claimed"] == false
            && previous["new_resource_observations"] == 0
            && previous["native_census_before"] == previous["native_census_after"]
            && [
                FIRST_CAPTURE_SHA,
                "14ad24282b0620a70dae5f80bf4fd9803d0b1deea59a37a56e442cfcb5a97ecf",
                CHAIN_CAPTURE_SHA,
                NATIVE154_CAPTURE_SHA,
                COHORT183_CAPTURE_SHA,
                "2742167e7fb1fe011de54b9f03323b20504c7c515f608391c612cca3a9ff9d89",
                "f46dc4f18b3f553439370c41c0267b692ded168fcd2fef3f95591ff003a643df",
                "989f90ecdc28a89fcf62b6f810c9201ac2eace0542c36c71472d9be440ae2058",
                "e63ead589a336bb5713755c77dc8326689ca6171a4c0668202bdf6fb624272cb",
                "af3ba92c1f67530c33a9d96ffc466145f73f07f08cc1488de9fb3eb00a33dce5",
                "ca5e1d576320d409731232b471d87b1c5eab3b82cfe16d871dd17c56890d7ef6",
                "1778a5b4405622710d17f981a68fbd6ac8d67f0ab200e986533b265a5fd567f7",
                "2c57a8422795bf9401215a5c3640d47786635e3b8b2cb9cda9bca842f1f2929d",
                "4d54ac9b4e72f558a06dbf9c9d93f8f53dd7adffb5f52637941ffd8bed19a84c",
                "d4d7ade1a587f320369af33217312767c7cbbd3043322e4ea09e303943540f30",
                "38c5b390af0ea4321fb3ecce45a4f74999db882958fbdd05611a4ba0e7454d48",
                "e273ef29773a79140de8320e22966afd0f8d80cf32fe6185aae32bfd0b6b99ac",
                "523360108ec4724660a39a2b9d0ff83b3fd4e9320614302f594446ee0945df98",
                "11ad91050994fc279370f4fd63433927dfd9aded46f2dba074b6b0cffd543b82",
                "026383f2da0fb854b22cda73aa3ca51a7eef32e572da883c860d5944e30c0831",
                "da2ba86ab133f388d0579008d37602ff49067f7df5b8fcbeacb3d4b47d616647",
                "f1e9728c8d7420571e0840a4c7aad7df15b90a7e376c23fe38605fab215324a4",
                "18db4e154af9b7733a6200441dd5983a30a7a441a890644486dbabab299a1919",
                "7ded52f2ef1f322491d7819d5b16ea96ed9891314d962f01ec1cdb5a8fccd45d",
                "8fe92508bd29e1372cce6b88d6c283c5b2cc3bb7c3d3f31e0977e25b784c612f",
                "4ddd0d7735e968d7561bd2bbad76199403fca43fed7b59e4a087eed760573dcf",
                "9526cb9110d1a08608f44b7b2e1f0334baba153ac2cae8c59ad237871d2583f5",
                "473b13ca865f879802d93d577aea052f0d6becc19469123392a1be763ab9a3b4",
                "3fa515037d632bfd7410d6b561ccb2302193ceafe73e4f64e75e3625f262931e",
                "9dd1c2b42e0ee9e99f8d575838d33347d69b3659d24340e23b14605942d16e1e",
                "c97d413ab065c1a3455de336dd4009644e3eeaa0b8fb6e6559ed9a542225c377",
                // These exact predecessor images have preserved qualification/seal proofs.
                "6465811554ccbc97664f796d9bcce0baa361bb82febd9111ee287fdb84d32744",
                "7d320b8a4f4d7e87f4fa53d5c614cf13d032760533c84db5e4802928eff8e6de",
                QUALIFIED_ORDINARY199_FRAME_V5_CAPTURE_SHA,
                QUALIFIED_HELPER_V4_FRAME_CAPTURE_SHA,
                current
            ]
            .iter()
            .any(|s| previous["self_sha256"] == *s),
        "previous recovery envelope or qualified capture artifact differs"
    );
    Ok(())
}

#[cfg(test)]
#[path = "qualified_previous_v6_tests.rs"]
mod qualified_previous_v6_tests;

fn validate_evidence_without_cached145(e: &Evidence<'_>, bindings: &Value, now: u64) -> Result<()> {
    let sample = utc_seconds(
        e.observer["recorded_at_utc"]
            .as_str()
            .context("sample time missing")?,
    )?;
    ensure!(
        sample <= now && now - sample <= 1800,
        "resource frame is stale or future"
    );
    ensure!(
        e.observer["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && e.observer["cadence"]["routine_minimum_interval_enforced"] == true
            && e.observer["cadence"]["minimum_interval_seconds"] == 1800
            && e.observer["cadence"]["observed_interval_seconds"]
                .as_u64()
                .is_some_and(|n| n >= 1800),
        "resource sample is not the coordinated routine observation"
    );
    ensure!(
        e.fleet["schema"] == "jetstreamer-horizon-campaign-fleet-v1"
            && e.fleet["first_epoch"] == 101
            && e.fleet["last_epoch"] == 200
            && e.fleet["observer_receipt"] == bindings["observer"]["path"]
            && e.fleet["observer_sha256"] == bindings["observer"]["sha256"]
            && e.fleet["sampled_at_utc"] == e.observer["recorded_at_utc"]
            && e.fleet["plan"] == bindings["fleet_plan"]["path"]
            && e.fleet["plan_sha256"] == bindings["fleet_plan"]["sha256"]
            && e.fleet_plan["observer"] == bindings["observer"]
            && e.fleet["inventory"]["anomalies"] == 0,
        "resource frame fleet/sample/plan binding differs"
    );
    let rows = e.fleet["epochs"]
        .as_array()
        .context("complete epoch census missing")?;
    ensure!(
        rows.len() == 100
            && (101..=200).all(|n| rows.iter().filter(|r| r["epoch"] == n).count() == 1),
        "complete range census missing or duplicated"
    );
    ensure!(
        e.prior_parent["schema"] == "jetstreamer-normal-routine-frame-parent-acceptance-v1"
            && e.prior_parent["accepted"] == true
            && e.prior_parent["completion"] == bindings["prior_completion"]
            && e.prior_parent["mandatory_cohort191_zero_credit_correction"]
                == bindings["correction191"]
            && e.prior_parent["new191_closure_incremental_DATA_credit_bytes"] == 0
            && e.prior_completion["schema"] == "jetstreamer-horizon-routine-cycle-completion-v1"
            && e.prior_completion["observer"] == e.prior_parent["observer"]
            && e.prior_completion["fleet"] == e.prior_parent["fleet"],
        "genuine predecessor completion/parent or mandatory zero-credit correction differs"
    );
    let predecessor = if let Some(previous) = e.prior_recovery {
        qualified_previous_recovery_envelope(
            previous,
            &bindings["prior_recovery"],
            e.capture_tool_sha,
        )?;
        authority_denied(previous)?;
        for key in [
            "prior_parent",
            "prior_completion",
            "correction191",
            "transition",
        ] {
            ensure!(
                previous["bindings"][key] == bindings[key],
                "recovery chain changed original authority: {key}"
            );
        }
        ensure!(
            previous["bindings"]["fleet_plan"] == bindings["prior_fleet_plan"],
            "previous fleet plan is not immediate recovered predecessor"
        );
        let previous_sample = utc_seconds(
            previous["sampled_at_utc"]
                .as_str()
                .context("previous sample clock missing")?,
        )?;
        let previous_capture = previous["recorded_unix_seconds"]
            .as_u64()
            .context("previous capture clock missing")?;
        ensure!(
            (sample >= previous_sample + 1800
                || (e
                    .cohort183_transition
                    .is_some_and(|t| t["verifier183"]["mode"] == "entry")
                    && sample == previous_sample
                    && bindings["observer"] == previous["bindings"]["observer"]))
                && previous_capture >= previous_sample
                && previous_capture <= previous_sample + 1800
                && previous_capture < now,
            "recovered chain does not advance the genuine cadence"
        );
        &previous["bindings"]
    } else {
        ensure!(
            bindings["prior_recovery"].is_null()
                && e.prior_completion["fleet_plan"] == bindings["prior_fleet_plan"],
            "first recovery lacks original fleet-plan binding"
        );
        e.prior_parent
    };
    if e.cohort183_transition
        .is_some_and(|t| t["schema"] == REFRESH_SCHEMA)
    {
        return if e
            .cohort183_transition
            .is_some_and(|t| !t["delivery_owner_delta"].is_null())
        {
            delivery_history::validate(e, bindings, sample, now)
        } else if e
            .cohort183_transition
            .is_some_and(|t| !t["verifier183"].is_null())
        {
            validate_verifier183_refresh(e, bindings, sample, now)
        } else {
            validate_refresh(e, bindings, sample)
        };
    }
    let native154_head = native154_history(e, bindings, predecessor)?;
    let fleet_predecessor = native154_head.as_ref().unwrap_or(&predecessor["fleet"]);
    let (bridged_fleet, bridged_observer) = observation_bridge(e, predecessor, fleet_predecessor)?;
    let fleet_predecessor = &bridged_fleet;
    ensure!(
        e.observer["cadence"]["previous_sample"] == bridged_observer["path"]
            && e.observer["cadence"]["previous_sample_sha256"] == bridged_observer["sha256"]
            && e.fleet["previous_fleet"] == *fleet_predecessor
            && e.fleet_plan["previous_fleet"] == *fleet_predecessor,
        "recovered frame lost its immediate accepted predecessor"
    );
    let history_source = match e.native154_transition {
        Some(t) if !t["terminal"].is_null() => e
            .native154_sources
            .get("terminal.fleet_plan")
            .context("terminal history source")?,
        Some(_) => e
            .native154_sources
            .get("entry.fleet_plan")
            .context("entry history source")?,
        None => e.prior_fleet_plan,
    };
    for key in [
        "tracked_units",
        "diagnostics",
        "pipeline_claims",
        "runtime_handoff157",
        "admission_transition_guard",
    ] {
        ensure!(
            cohort183_retained_plan(e)?[key] == history_source[key],
            "recovery changed retained history or policy: {key}"
        );
    }
    let units = e.fleet_plan["tracked_units"]
        .as_array()
        .context("tracked history missing")?;
    let census = e.fleet["unit_census"]
        .as_object()
        .context("native census missing")?;
    ensure!(
        units.len() >= 531
            && units
                .iter()
                .all(|u| u.as_str().is_some_and(|s| census.contains_key(s))),
        "complete historical unit census lost"
    );
    let transition_binding = &bindings["transition"];
    for epoch in [155, 156] {
        let name = epoch.to_string();
        let old = &e.prior_fleet_plan["gates"][&name];
        let new = &e.fleet_plan["gates"][&name];
        let mut expected = old.clone();
        let evidence = expected["evidence"]
            .as_array_mut()
            .context("prior gate evidence missing")?;
        if !evidence.contains(transition_binding) {
            evidence.push(transition_binding.clone());
        }
        ensure!(
            expected == *new,
            "terminal reconciliation changed another gate"
        );
        ensure!(
            rows.iter()
                .find(|r| r["epoch"] == epoch)
                .is_some_and(|r| r["state"] == "remote-ready"),
            "terminal epoch lacks authenticated ready-pair census"
        );
    }
    if let Some(delta) = e.fleet_transition {
        ensure!(
            e.prior_recovery.is_some()
                && !bindings["fleet_transition"].is_null()
                && delta["schema"] == "jetstreamer-horizon-recovered-fleet-delta-v1",
            "fleet delta lacks typed recovered predecessor"
        );
        authority_denied(delta)?;
        let updates = delta["gate_updates"]
            .as_object()
            .context("delta gate updates missing")?;
        ensure!(
            !updates.is_empty() && updates.keys().all(|s| ["136", "154"].contains(&s.as_str())),
            "delta contains unsupported gate updates"
        );
    } else {
        ensure!(
            bindings["fleet_transition"].is_null(),
            "fleet delta binding lacks evidence"
        );
    }
    for epoch in (101..=200).filter(|n| ![155, 156].contains(n)) {
        validate_gate_delta(e, bindings, epoch)?;
    }
    ensure!(
        e.transition["schema"] == "jetstreamer-horizon-terminal-owner-observer-reconciliation-v1"
            && e.transition["terminal_range"] == "155-156"
            && e.transition["previous_controller_invocation_id"]
                == "5c0c6dc3faa14a6d8a639af8a1c76774"
            && e.transition["previous_producer_invocation_id"]
                == "518ff0bf0bbb4413a155a63f95907163"
            && e.transition["remaining_growth_released"] == false,
        "terminal transition is foreign or releases standing growth"
    );
    for unit in [CONTROLLER, PRODUCER] {
        let native = &e.fleet["unit_census"][unit];
        ensure!(
            native["MainPID"] == "0"
                && native["NRestarts"] == "0"
                && native["ControlGroup"] == ""
                && native["ActiveState"] == "inactive"
                && native["SubState"] == "dead"
                && native["Result"] == "success",
            "terminal cohort still has a live or ambiguous owner"
        );
    }
    let replays = e.observer["replays"]
        .as_array()
        .context("live replay list missing")?;
    if e.cohort183_transition.is_some() {
        validate_cohort183(e, bindings, sample)?;
        ensure!(
            replays.is_empty(),
            "completed cohort retained a primary replay"
        );
        return Ok(());
    }
    ensure!(
        bindings["cohort183_transition"].is_null(),
        "183 transition binding lacks evidence"
    );
    ensure!(
        replays.len() == 1
            && replays[0]["range"] == "183-184"
            && replays[0]["invocation_binding_stable"] == true,
        "recovery lost or added an ordinary owner"
    );
    for kind in ["controller", "producer"] {
        let before = &replays[0][format!("{kind}_before")];
        let after = &replays[0][format!("{kind}_after")];
        for field in [
            "unit",
            "invocation_id",
            "main_pid",
            "restarts",
            "active_state",
            "sub_state",
            "control_group",
        ] {
            ensure!(
                before[field] == after[field],
                "replay identity changed across sample"
            );
        }
        ensure!(
            after["active_state"] == "active"
                && after["sub_state"] == "running"
                && after["restarts"] == 0,
            "replay is not healthy"
        );
        let native =
            &e.fleet["unit_census"][after["unit"].as_str().context("sample unit missing")?];
        ensure!(
            native["InvocationID"] == after["invocation_id"]
                && native["MainPID"]
                    .as_str()
                    .and_then(|s| s.parse::<u64>().ok())
                    == after["main_pid"].as_u64()
                && native["ActiveState"] == "active"
                && native["NRestarts"] == "0",
            "fleet owner differs from sampled owner"
        );
    }
    Ok(())
}

/// Validate the complete raw frame under the caller's explicit retained profile.
pub fn validate_frame_retained199(
    frame: &Value,
    e: &Evidence<'_>,
    bindings: &Value,
    now: u64,
    context: &terminal199_context::Retained,
) -> Result<()> {
    let proof = ordinary199_frame::proof_for_context(e, context)?
        .context("retained199 explicit enrollment absent")?;
    ordinary199_frame::validate_full_frame_retained(frame, e, &proof, context)?;
    let views = ordinary199_frame::Views::prepare_retained(e, &proof, context)?;
    validate_frame_without199(
        &ordinary199::project_frame_retained(frame, context)?,
        &views.evidence(e),
        bindings,
        now,
    )
}
pub fn validate_frame(frame: &Value, e: &Evidence<'_>, bindings: &Value, now: u64) -> Result<()> {
    if let Some(context) = ordinary199::terminal_context(e.fleet_plan)? {
        return validate_frame_retained199(frame, e, bindings, now, &context);
    }
    if let Some(proof) = ordinary199_frame::proof(e)? {
        ordinary199_frame::validate_full_frame(frame, e, &proof)?;
        let views = ordinary199_frame::Views::prepare(e, &proof)?;
        return validate_frame_without199(
            &ordinary199::project_frame(frame)?,
            &views.evidence(e),
            bindings,
            now,
        );
    }
    validate_frame_without199(frame, e, bindings, now)
}
fn validate_frame_without199(
    frame: &Value,
    e: &Evidence<'_>,
    bindings: &Value,
    now: u64,
) -> Result<()> {
    ensure!(
        frame["schema"] == SCHEMA
            && frame["accepted_resource_lineage"] == true
            && frame["bindings"] == *bindings
            && frame["sampled_at_utc"] == e.observer["recorded_at_utc"]
            && frame["self_sha256"] == e.capture_tool_sha,
        "recovered resource frame envelope differs"
    );
    for key in [
        "replay_launch_authorized",
        "publication_authorized",
        "remote_mutations",
        "remaining_growth_released",
        "new191_closure_incremental_DATA_credit_bytes",
        "archive_mutations",
        "sidecar_mutations",
    ] {
        ensure!(
            frame[key]
                == if key.ends_with("_bytes") {
                    json!(0)
                } else {
                    json!(false)
                },
            "recovered frame grants authority or credit: {key}"
        );
    }
    ensure!(
        frame["full_routine_completion_claimed"] == false
            && frame["new_resource_observations"] == 0
            && (frame["native_census_before"] == frame["native_census_after"]
                || (cached145_frame::selected(e)
                    && cached145_frame::guard::census_stable(
                        e,
                        &frame["native_census_before"],
                        &frame["native_census_after"],
                        &frame["cached145_guard_history"]
                    )?)),
        "recovered frame fabricates completion or has a changing native census"
    );
    let actual = frame["native_census_before"]
        .as_object()
        .context("frame native census missing")?;
    let expected = e.fleet["unit_census"]
        .as_object()
        .context("fleet census missing")?;
    ensure!(
        actual.len() == expected.len(),
        "frame native census count differs"
    );
    for (unit, old) in expected {
        let native = actual.get(unit).context("frame dropped a tracked unit")?;
        if cached145_frame::selected(e)
            && cached145_frame::guard::guard_unit(e, unit)
            && old != native
            && !cached145_frame::guard::same_observation(old, native)?
        {
            cached145_frame::guard::pair(e, unit, old, native, &frame["cached145_guard_history"])?;
            continue;
        }
        for key in [
            "Id",
            "LoadState",
            "InvocationID",
            "ActiveState",
            "SubState",
            "MainPID",
            "NRestarts",
            "Result",
            "ExecMainStatus",
            "ControlGroup",
            "Type",
        ] {
            ensure!(
                old[key].as_str().unwrap_or("") == native[key].as_str().unwrap_or(""),
                "frame census owner differs: {unit}/{key}"
            );
        }
        ensure!(
            old["ExecStart"].as_str().unwrap_or("") == native["ExecStart"].as_str().unwrap_or("")
                || same_exec_start(&old["ExecStart"], &native["ExecStart"]),
            "frame census command differs: {unit}"
        );
    }
    if e.cohort183_transition
        .is_some_and(|t| !t["canonical_import"].is_null())
    {
        for unit in [COHORT183_CONTROLLER, COHORT183_PRODUCER, COHORT183_IMPORTER] {
            ensure!(
                actual[unit]["ControlPID"] == "0" && actual[unit]["Job"] == "",
                "terminal frame retains a control process or queued job: {unit}"
            );
        }
    }
    if e.cohort183_transition
        .is_some_and(|t| !t["verifier183"].is_null())
    {
        for stage in ["full", "plugin"] {
            let native = &actual[verifier183::unit(stage)?];
            let launch = verifier_source(e, &format!("{stage}_launch"))?;
            if native["ActiveState"] == "active" && native["SubState"] == "running" {
                verifier183::validate_native(stage, native, launch)?;
            }
        }
    }
    if e.cohort183_transition
        .is_some_and(|t| !t["delivery_owner_delta"].is_null())
    {
        delivery_history::validate_native(e, actual)?;
    }
    cached145_frame::validate_native(e, actual)?;
    input137_frame::validate_native(e, actual)?;
    private154_combined_history::validate_actual_native(e, actual)?;
    durable_prefix141_history::validate_native(e, actual)?;
    early_terminal141_history::validate_current(
        e,
        &frame["early_terminal141_before"],
        &frame["early_terminal141_after"],
    )?;
    early_terminal141_history::bind_service_census(
        e,
        &frame["early_terminal141_before"],
        &frame["native_census_before"],
    )?;
    early_terminal141_history::bind_service_census(
        e,
        &frame["early_terminal141_after"],
        &frame["native_census_after"],
    )?;
    charge136_retry0003_history::validate_native(e, actual)?;
    charge136_retry0004_history::validate_native(e, actual)?;
    charge136_retry0005_history::validate_native(e, actual)?;
    input161_retry6_history::validate_native(e, actual)?;
    input161_retry7_history::validate_native(e, actual)?;
    input161_retry6_pre_ready_history::validate_native(e, actual)?;
    let captured = frame["recorded_unix_seconds"]
        .as_u64()
        .context("frame clock missing")?;
    ensure!(
        captured <= now
            && now - captured <= 1800
            && captured
                >= utc_seconds(
                    e.observer["recorded_at_utc"]
                        .as_str()
                        .context("frame sample clock")?
                )?,
        "frame capture clock is stale or future"
    );
    validate_evidence(e, bindings, now)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn refresh_fixture() -> (Vec<Value>, Value, Value, Value, u64) {
        let raw = [
            include_str!("../fixtures/refresh-prior-observer.json"),
            include_str!("../fixtures/refresh-prior-fleet.json"),
            include_str!("../fixtures/refresh-prior-plan.json"),
            include_str!("../fixtures/refresh-parent.json"),
            include_str!("../fixtures/refresh-completion.json"),
            include_str!("../fixtures/refresh-prior-plan.json"),
            include_str!("../fixtures/refresh-original-transition.json"),
        ];
        let mut d: Vec<Value> = raw
            .into_iter()
            .map(|s| serde_json::from_str(s).unwrap())
            .collect();
        let previous: Value =
            serde_json::from_str(include_str!("../fixtures/refresh-prior-frame.json")).unwrap();
        let mut b = previous["bindings"].clone();
        for (key, letter) in [
            ("prior_recovery", "a"),
            ("observer", "b"),
            ("fleet", "c"),
            ("fleet_plan", "d"),
            ("cohort183_transition", "e"),
        ] {
            b[key] = json!({"path":format!("/test/refresh-{key}.json"),"sha256":letter.repeat(64)});
        }
        b["prior_fleet_plan"] = previous["bindings"]["fleet_plan"].clone();
        b.as_object_mut().unwrap().remove("fleet_transition");
        b.as_object_mut().unwrap().remove("native154_transition");
        d[0]["recorded_at_utc"] = json!("2026-10-29T23:23:15Z");
        d[0]["cadence"]["previous_sample"] = previous["bindings"]["observer"]["path"].clone();
        d[0]["cadence"]["previous_sample_sha256"] =
            previous["bindings"]["observer"]["sha256"].clone();
        d[0]["cadence"]["observed_interval_seconds"] = json!(1800);
        d[1]["observer_receipt"] = b["observer"]["path"].clone();
        d[1]["observer_sha256"] = b["observer"]["sha256"].clone();
        d[1]["sampled_at_utc"] = d[0]["recorded_at_utc"].clone();
        d[1]["plan"] = b["fleet_plan"]["path"].clone();
        d[1]["plan_sha256"] = b["fleet_plan"]["sha256"].clone();
        d[1]["previous_fleet"] = previous["bindings"]["fleet"].clone();
        d[1]["metadata_event"] = Value::Null;
        for row in d[1]["pipelines"].as_array_mut().unwrap() {
            row["sampled_at_utc"] = json!("2026-10-29T23:23:15Z");
        }
        d[2]["observer"] = b["observer"].clone();
        d[2]["previous_fleet"] = previous["bindings"]["fleet"].clone();
        let t = json!({"schema":REFRESH_SCHEMA,"previous_recovery":b["prior_recovery"],
            "prior_fleet_plan":b["prior_fleet_plan"],"fleet_plan":b["fleet_plan"],
            "previous_cohort183_transition":previous["bindings"]["cohort183_transition"],
            "repair_incident_remains_open":true,"replay_launch_authorized":false,
            "publication_authorized":false,"remote_mutations":false,"remaining_growth_released":false,
            "new191_closure_incremental_DATA_credit_bytes":0,"archive_mutations":false,"sidecar_mutations":false});
        let now = utc_seconds("2026-10-29T23:25:15Z").unwrap();
        (d, b, previous, t, now)
    }
    fn refresh_check(
        d: &[Value],
        b: &Value,
        p: &Value,
        transition: &Value,
        now: u64,
    ) -> Result<()> {
        refresh_check_sources(d, b, p, transition, &std::collections::BTreeMap::new(), now)
    }
    fn refresh_check_sources(
        d: &[Value],
        b: &Value,
        p: &Value,
        transition: &Value,
        sources: &std::collections::BTreeMap<String, Value>,
        now: u64,
    ) -> Result<()> {
        validate_evidence(
            &Evidence {
                observer: &d[0],
                fleet: &d[1],
                fleet_plan: &d[2],
                prior_parent: &d[3],
                prior_completion: &d[4],
                prior_fleet_plan: &d[5],
                transition: &d[6],
                prior_recovery: Some(p),
                fleet_transition: None,
                capture_tool_sha: COHORT183_CAPTURE_SHA,
                cohort183_transition: Some(transition),
                cohort183_sources: sources,
                native154_transition: None,
                native154_sources: &std::collections::BTreeMap::new(),
            },
            b,
            now,
        )
    }
    #[test]
    fn terminal_import_refresh_preserves_claims_and_accepts_only_bound_terminal_proof() {
        let (mut d, b, p, mut t, now) = refresh_fixture();
        let proof: Value =
            serde_json::from_str(include_str!("../fixtures/canonical-terminal-proof.json"))
                .unwrap();
        d[0]["recorded_at_utc"] = json!("2026-10-29T23:53:15Z");
        d[0]["cadence"]["observed_interval_seconds"] = json!(3600);
        d[1]["sampled_at_utc"] = d[0]["recorded_at_utc"].clone();
        for row in d[1]["pipelines"].as_array_mut().unwrap() {
            row["sampled_at_utc"] = json!("2026-10-29T23:53:15Z");
        }
        for (kind, unit) in [
            ("controller", COHORT183_CONTROLLER),
            ("producer", COHORT183_PRODUCER),
            ("importer", COHORT183_IMPORTER),
        ] {
            d[1]["unit_census"][unit] = proof[kind].clone();
        }
        for row in d[1]["pipelines"].as_array_mut().unwrap() {
            if [json!(183), json!(184)].contains(&row["epoch"]) {
                row["unit"] = proof["controller"].clone();
                row["live"] = json!(false);
                row["finalization_evidence"] = proof.clone();
            }
        }
        t["canonical_import"] = json!({"path":"/test/canonical-terminal-proof.json","sha256":"5d0fcb753e3b2b984958657a2cee8e3eea7c6000bd6c375ba68aa8793dc14395"});
        t["source_batch_snapshot"] = json!({"path":"/test/source-batch.json","sha256":cohort183_canonical_import::SOURCE_SHA});
        t["canonical_batch_snapshot"] = json!({"path":"/test/canonical-batch.json","sha256":cohort183_canonical_import::IMPORT_SHA});
        let mut sources = std::collections::BTreeMap::from([
            ("canonical_import".into(), proof.clone()),
            (
                "source_batch_snapshot".into(),
                proof["source_batch"].clone(),
            ),
            (
                "canonical_batch_snapshot".into(),
                proof["canonical_batch"].clone(),
            ),
        ]);
        refresh_check_sources(&d, &b, &p, &t, &sources, now + 1800).unwrap();
        let empty = std::collections::BTreeMap::new();
        let evidence = Evidence {
            observer: &d[0],
            fleet: &d[1],
            fleet_plan: &d[2],
            prior_parent: &d[3],
            prior_completion: &d[4],
            prior_fleet_plan: &d[5],
            transition: &d[6],
            prior_recovery: Some(&p),
            fleet_transition: None,
            capture_tool_sha: COHORT183_CAPTURE_SHA,
            cohort183_transition: Some(&t),
            cohort183_sources: &sources,
            native154_transition: None,
            native154_sources: &empty,
        };
        let mut frame = json!({"schema":SCHEMA,"accepted_resource_lineage":true,"bindings":b,
            "sampled_at_utc":d[0]["recorded_at_utc"],"self_sha256":COHORT183_CAPTURE_SHA,
            "replay_launch_authorized":false,"publication_authorized":false,"remote_mutations":false,
            "remaining_growth_released":false,"new191_closure_incremental_DATA_credit_bytes":0,
            "archive_mutations":false,"sidecar_mutations":false,"full_routine_completion_claimed":false,
            "new_resource_observations":0,"native_census_before":d[1]["unit_census"],
            "native_census_after":d[1]["unit_census"],"recorded_unix_seconds":now+1800});
        validate_frame(&frame, &evidence, &b, now + 1800).unwrap();
        frame["native_census_before"][COHORT183_IMPORTER]["Job"] = json!("123 start");
        frame["native_census_after"] = frame["native_census_before"].clone();
        assert!(validate_frame(&frame, &evidence, &b, now + 1800).is_err());
        for epoch in ["183", "184"] {
            let old = d[2]["gates"][epoch].clone();
            let mut new = old.clone();
            new["evidence"]
                .as_array_mut()
                .unwrap()
                .push(t["canonical_import"].clone());
            new["next_action"] =
                json!("Complete independent verification and authenticated delivery.");
            t["gate_updates"][epoch] = json!({"previous_gate":old,"current_gate":new});
            d[2]["gates"][epoch] = new;
        }
        refresh_check_sources(&d, &b, &p, &t, &sources, now + 1800).unwrap();
        for (pointer, value) in [
            ("/importer/MainPID", json!("42")),
            (
                "/controller_terminal_manager/INVOCATION_ID",
                json!("foreign"),
            ),
            ("/canonical_batch/outcome/kind", json!("prepared")),
            ("/resource_credit_bytes", json!(1)),
            ("/importer/Job", json!("123 start")),
        ] {
            let mut changed = proof.clone();
            *changed.pointer_mut(pointer).unwrap() = value;
            sources.insert("canonical_import".into(), changed);
            assert!(
                refresh_check_sources(&d, &b, &p, &t, &sources, now + 1800).is_err(),
                "{pointer}"
            );
        }
        sources.insert("canonical_import".into(), proof);
        let mut changed = d.clone();
        changed[1]["pipelines"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|r| r["epoch"] == 183)
            .unwrap()["live"] = json!(true);
        assert!(refresh_check_sources(&changed, &b, &p, &t, &sources, now + 1800).is_err());
        let mut changed = t.clone();
        changed["source_batch_snapshot"]["sha256"] = json!("f".repeat(64));
        assert!(refresh_check_sources(&d, &b, &p, &changed, &sources, now + 1800).is_err());
        sources.remove("canonical_batch_snapshot");
        assert!(refresh_check_sources(&d, &b, &p, &t, &sources, now + 1800).is_err());
    }
    #[test]
    fn unchanged_post_import_refresh_accepts_preserved_policy() {
        let (d, b, p, t, now) = refresh_fixture();
        refresh_check(&d, &b, &p, &t, now).unwrap();
    }
    #[test]
    fn qualified_immediate_e63_predecessor_is_accepted_and_unknown_images_are_rejected() {
        let (d, b, mut p, t, now) = refresh_fixture();
        p["self_sha256"] =
            json!("e63ead589a336bb5713755c77dc8326689ca6171a4c0668202bdf6fb624272cb");
        refresh_check(&d, &b, &p, &t, now).unwrap();
        p["self_sha256"] =
            json!("af3ba92c1f67530c33a9d96ffc466145f73f07f08cc1488de9fb3eb00a33dce5");
        refresh_check(&d, &b, &p, &t, now).unwrap();
        p["self_sha256"] =
            json!("1778a5b4405622710d17f981a68fbd6ac8d67f0ab200e986533b265a5fd567f7");
        refresh_check(&d, &b, &p, &t, now).unwrap();
        p["self_sha256"] =
            json!("2c57a8422795bf9401215a5c3640d47786635e3b8b2cb9cda9bca842f1f2929d");
        refresh_check(&d, &b, &p, &t, now).unwrap();
        p["self_sha256"] =
            json!("4d54ac9b4e72f558a06dbf9c9d93f8f53dd7adffb5f52637941ffd8bed19a84c");
        refresh_check(&d, &b, &p, &t, now).unwrap();
        p["self_sha256"] = json!("f".repeat(64));
        assert!(refresh_check(&d, &b, &p, &t, now).is_err());
    }
    #[test]
    fn post_import_refresh_can_repeat_without_replaying_one_time_gate_delta() {
        let (mut d, mut b, mut p, mut t, now) = refresh_fixture();
        refresh_check(&d, &b, &p, &t, now).unwrap();
        p["bindings"] = b.clone();
        p["sampled_at_utc"] = d[0]["recorded_at_utc"].clone();
        p["recorded_unix_seconds"] = json!(now);
        d[5] = d[2].clone();
        b["prior_fleet_plan"] = p["bindings"]["fleet_plan"].clone();
        for (key, letter) in [
            ("prior_recovery", "f"),
            ("observer", "1"),
            ("fleet", "2"),
            ("fleet_plan", "3"),
            ("cohort183_transition", "4"),
        ] {
            b[key] = json!({"path":format!("/test/second-{key}.json"),"sha256":letter.repeat(64)});
        }
        t["previous_recovery"] = b["prior_recovery"].clone();
        t["prior_fleet_plan"] = b["prior_fleet_plan"].clone();
        t["fleet_plan"] = b["fleet_plan"].clone();
        t["previous_cohort183_transition"] = p["bindings"]["cohort183_transition"].clone();
        d[0]["recorded_at_utc"] = json!("2026-10-29T23:53:15Z");
        d[0]["cadence"]["previous_sample"] = p["bindings"]["observer"]["path"].clone();
        d[0]["cadence"]["previous_sample_sha256"] = p["bindings"]["observer"]["sha256"].clone();
        d[1]["observer_receipt"] = b["observer"]["path"].clone();
        d[1]["observer_sha256"] = b["observer"]["sha256"].clone();
        d[1]["sampled_at_utc"] = d[0]["recorded_at_utc"].clone();
        d[1]["plan"] = b["fleet_plan"]["path"].clone();
        d[1]["plan_sha256"] = b["fleet_plan"]["sha256"].clone();
        d[1]["previous_fleet"] = p["bindings"]["fleet"].clone();
        for row in d[1]["pipelines"].as_array_mut().unwrap() {
            row["sampled_at_utc"] = json!("2026-10-29T23:53:15Z");
        }
        d[2]["observer"] = b["observer"].clone();
        d[2]["previous_fleet"] = p["bindings"]["fleet"].clone();
        refresh_check(&d, &b, &p, &t, now + 1800).unwrap();
    }
    #[test]
    fn refresh_rejects_crossed_predecessors_policy_census_and_authority() {
        let (d, b, p, t, now) = refresh_fixture();
        for (pointer, value) in [
            ("/0/cadence/previous_sample_sha256", json!("f".repeat(64))),
            ("/1/previous_fleet/sha256", json!("f".repeat(64))),
            ("/2/previous_fleet/sha256", json!("f".repeat(64))),
            ("/1/metadata_event", json!({"schema":"foreign"})),
            ("/2/gates/183/state", json!("remote-ready")),
            ("/2/pipeline_claims/0/invocation_id", json!("foreign")),
            ("/2/tracked_units/0", json!("foreign.service")),
            ("/1/pipelines/0/evidence", json!([])),
            (
                "/1/pipelines/0/grants_launch_or_publication_authority",
                json!(true),
            ),
            ("/1/diagnostics/0/launch_receipt_sha256", json!("foreign")),
            (
                "/1/unit_census/jetstreamer-root-import-e183-184-full-20261023-v2-r2-e183-184-2.service/InvocationID",
                json!("foreign"),
            ),
        ] {
            let mut changed = json!(d);
            *changed.pointer_mut(pointer).unwrap() = value;
            assert!(
                refresh_check(changed.as_array().unwrap(), &b, &p, &t, now).is_err(),
                "{pointer}"
            );
        }
        for key in ["tracked_units", "pipeline_claims", "diagnostics"] {
            let mut changed = d.clone();
            let row = changed[2][key][0].clone();
            changed[2][key].as_array_mut().unwrap().push(row);
            assert!(
                refresh_check(&changed, &b, &p, &t, now).is_err(),
                "duplicate {key}"
            );
        }
        for key in ["pipelines", "diagnostics"] {
            let mut changed = d.clone();
            changed[1][key].as_array_mut().unwrap().pop();
            assert!(
                refresh_check(&changed, &b, &p, &t, now).is_err(),
                "missing {key}"
            );
        }
        for (key, value) in [
            ("replay_launch_authorized", json!(true)),
            ("new191_closure_incremental_DATA_credit_bytes", json!(1)),
            ("previous_cohort183_transition", json!(null)),
            ("added_pipeline_claims", json!([])),
        ] {
            let mut changed = t.clone();
            changed[key] = value;
            assert!(refresh_check(&d, &b, &p, &changed, now).is_err(), "{key}");
        }
        assert!(refresh_check(&d, &b, &p, &t, now + 1801).is_err());
        assert!(refresh_check(&d, &b, &p, &t, now - 121).is_err());
    }
    fn fixture() -> (Vec<Value>, Value, u64) {
        let data = [
            include_str!("../fixtures/observer.json"),
            include_str!("../fixtures/fleet.json"),
            include_str!("../fixtures/fleet-plan.json"),
            include_str!("../fixtures/prior-parent.json"),
            include_str!("../fixtures/prior-completion.json"),
            include_str!("../fixtures/prior-plan.json"),
            include_str!("../fixtures/transition.json"),
        ]
        .into_iter()
        .map(|s| serde_json::from_str::<Value>(s).unwrap())
        .collect::<Vec<_>>();
        let b = json!({"observer":data[2]["observer"],"fleet_plan":{"path":data[1]["plan"],"sha256":data[1]["plan_sha256"]},"prior_completion":data[3]["completion"],"prior_fleet_plan":data[4]["fleet_plan"],"correction191":data[3]["mandatory_cohort191_zero_credit_correction"],"transition":data[2]["gates"]["155"]["evidence"].as_array().unwrap().last().unwrap()});
        (data, b, 1793302800 + 120)
    }
    fn check(data: &[Value], b: &Value, t: u64) -> Result<()> {
        validate_evidence(
            &Evidence {
                observer: &data[0],
                fleet: &data[1],
                fleet_plan: &data[2],
                prior_parent: &data[3],
                prior_completion: &data[4],
                prior_fleet_plan: &data[5],
                transition: &data[6],
                prior_recovery: None,
                fleet_transition: None,
                capture_tool_sha: FIRST_CAPTURE_SHA,
                cohort183_transition: None,
                cohort183_sources: &std::collections::BTreeMap::new(),
                native154_transition: None,
                native154_sources: &std::collections::BTreeMap::new(),
            },
            b,
            t,
        )
    }
    #[test]
    fn preserved_actual_host_fixtures_validate() {
        let (d, b, t) = fixture();
        check(&d, &b, t).unwrap();
    }
    #[test]
    fn stale_or_future_clock_rejected() {
        let (d, b, t) = fixture();
        assert!(check(&d, &b, t + 1801).is_err());
        assert!(check(&d, &b, t - 121).is_err());
    }
    #[test]
    fn crossed_owner_missing_epoch_and_history_rejected() {
        let (d, b, t) = fixture();
        for (pointer, value) in [
            ("/1/epochs/0/epoch", json!(102)),
            (
                "/1/unit_census/jetstreamer-root-sweep-e183-184-full-20261023-v2-r2-e183-184-lane-a-1.service/InvocationID",
                json!("foreign"),
            ),
            ("/2/tracked_units", json!([])),
            ("/3/new191_closure_incremental_DATA_credit_bytes", json!(1)),
            ("/6/remaining_growth_released", json!(true)),
            ("/2/gates/154/state", json!("staged-admissible")),
        ] {
            let mut x = json!(d);
            *x.pointer_mut(pointer).unwrap() = value;
            assert!(check(x.as_array().unwrap(), &b, t).is_err(), "{pointer}");
        }
    }
    #[test]
    fn reclaimed_or_replaced_terminal_owner_rejected() {
        let (d, b, t) = fixture();
        let mut x = d.clone();
        x[1]["unit_census"][CONTROLLER]["MainPID"] = json!("123");
        assert!(check(&x, &b, t).is_err());
    }
    #[test]
    fn dates_do_not_normalize() {
        assert!(utc_seconds("2026-02-30T00:00:00Z").is_err());
        assert!(utc_seconds("2026-10-29T19:40:00Z").is_ok());
    }

    // Derived future samples are test fixtures only. The deployment captures
    // actual observer/fleet receipts and native census independently.
    fn chain_fixture() -> (Vec<Value>, Value, Value, u64) {
        let (mut d, _, _) = fixture();
        let previous: Value = serde_json::from_str(include_str!("../fixtures/frame.json")).unwrap();
        let mut b = previous["bindings"].clone();
        d[5] = d[2].clone();
        b["prior_fleet_plan"] = previous["bindings"]["fleet_plan"].clone();
        b["prior_recovery"] = json!({"path":"/test/previous-frame.json","sha256":"a".repeat(64)});
        b["observer"] = json!({"path":"/test/next-observer.json","sha256":"b".repeat(64)});
        b["fleet"] = json!({"path":"/test/next-fleet.json","sha256":"c".repeat(64)});
        b["fleet_plan"] = json!({"path":"/test/next-plan.json","sha256":"d".repeat(64)});
        d[0]["recorded_at_utc"] = json!("2026-10-29T20:10:00Z");
        d[0]["cadence"]["previous_sample"] = previous["bindings"]["observer"]["path"].clone();
        d[0]["cadence"]["previous_sample_sha256"] =
            previous["bindings"]["observer"]["sha256"].clone();
        d[0]["cadence"]["observed_interval_seconds"] = json!(1800);
        d[1]["observer_receipt"] = b["observer"]["path"].clone();
        d[1]["observer_sha256"] = b["observer"]["sha256"].clone();
        d[1]["sampled_at_utc"] = d[0]["recorded_at_utc"].clone();
        d[1]["plan"] = b["fleet_plan"]["path"].clone();
        d[1]["plan_sha256"] = b["fleet_plan"]["sha256"].clone();
        d[1]["previous_fleet"] = previous["bindings"]["fleet"].clone();
        d[2]["observer"] = b["observer"].clone();
        d[2]["previous_fleet"] = previous["bindings"]["fleet"].clone();
        (d, b, previous, 1793304720)
    }
    fn chain_check(
        d: &[Value],
        b: &Value,
        previous: &Value,
        delta: Option<&Value>,
        t: u64,
    ) -> Result<()> {
        validate_evidence(
            &Evidence {
                observer: &d[0],
                fleet: &d[1],
                fleet_plan: &d[2],
                prior_parent: &d[3],
                prior_completion: &d[4],
                prior_fleet_plan: &d[5],
                transition: &d[6],
                prior_recovery: Some(previous),
                fleet_transition: delta,
                capture_tool_sha: FIRST_CAPTURE_SHA,
                cohort183_transition: None,
                cohort183_sources: &std::collections::BTreeMap::new(),
                native154_transition: None,
                native154_sources: &std::collections::BTreeMap::new(),
            },
            b,
            t,
        )
    }
    #[test]
    fn coordinated_chain_keeps_genuine_original_parent() {
        let (d, b, p, t) = chain_fixture();
        chain_check(&d, &b, &p, None, t).unwrap();
        for (pointer, value) in [
            ("/bindings/prior_completion/sha256", json!("0".repeat(64))),
            ("/self_sha256", json!("0".repeat(64))),
            ("/new191_closure_incremental_DATA_credit_bytes", json!(1)),
            ("/sampled_at_utc", json!("2026-10-29T20:10:00Z")),
        ] {
            let mut wrong = p.clone();
            *wrong.pointer_mut(pointer).unwrap() = value;
            assert!(chain_check(&d, &b, &wrong, None, t).is_err(), "{pointer}");
        }
        let mut wrong = d.clone();
        wrong[0]["cadence"]["previous_sample_sha256"] = json!("0".repeat(64));
        assert!(chain_check(&wrong, &b, &p, None, t).is_err());
        let mut wrong = b.clone();
        wrong["prior_fleet_plan"]["sha256"] = json!("0".repeat(64));
        assert!(chain_check(&d, &wrong, &p, None, t).is_err());
    }
    #[test]
    fn exact_repair_delta_appends_evidence_without_gate_promotion() {
        let (mut d, mut b, p, t) = chain_fixture();
        d[2]["gates"]["136"]["next_action"] = json!("Continue exact registered compiler repair.");
        d[2]["gates"]["136"]["evidence"]
            .as_array_mut()
            .unwrap()
            .push(json!({"path":"/test/repair.json","sha256":"e".repeat(64)}));
        b["fleet_transition"] = json!({"path":"/test/delta.json","sha256":"f".repeat(64)});
        let delta = json!({"schema":"jetstreamer-horizon-recovered-fleet-delta-v1",
            "prior_fleet_plan":b["prior_fleet_plan"],"fleet_plan":b["fleet_plan"],
            "gate_updates":{"136":{"previous_gate":d[5]["gates"]["136"],"current_gate":d[2]["gates"]["136"]}},
            "replay_launch_authorized":false,"publication_authorized":false,"remote_mutations":false,
            "remaining_growth_released":false,"new191_closure_incremental_DATA_credit_bytes":0,
            "archive_mutations":false,"sidecar_mutations":false});
        chain_check(&d, &b, &p, Some(&delta), t).unwrap();
        assert!(chain_check(&d, &b, &p, None, t).is_err());
        for pointer in ["/gates/136/state", "/gates/154/next_action"] {
            let mut bad = d.clone();
            *bad[2].pointer_mut(pointer).unwrap() = json!("changed");
            assert!(
                chain_check(&bad, &b, &p, Some(&delta), t).is_err(),
                "{pointer}"
            );
        }
        let mut bad = d.clone();
        bad[2]["gates"]["136"]["evidence"]
            .as_array_mut()
            .unwrap()
            .remove(0);
        let mut bad_delta = delta.clone();
        bad_delta["gate_updates"]["136"]["current_gate"] = bad[2]["gates"]["136"].clone();
        assert!(chain_check(&bad, &b, &p, Some(&bad_delta), t).is_err());
        let mut bad_delta = delta.clone();
        bad_delta["replay_launch_authorized"] = json!(true);
        assert!(chain_check(&d, &b, &p, Some(&bad_delta), t).is_err());
    }
    type NativeFixture = (
        Vec<Value>,
        Value,
        Value,
        Value,
        std::collections::BTreeMap<String, Value>,
        u64,
    );
    fn native_fixture(terminal: bool) -> NativeFixture {
        let (mut d, mut b, p, t) = chain_fixture();
        let bind = |s: &str| json!({"path":format!("/test/{s}.json"),"sha256":"a".repeat(64)});
        let mut transition = json!({"schema":"jetstreamer-horizon-native154-recovered-frame-transition-v1",
            "previous_recovery":b["prior_recovery"],"entry":{"origin":bind("origin"),"fleet":bind("entry-fleet"),"fleet_plan":bind("entry-plan")},
            "replay_launch_authorized":false,"publication_authorized":false,"remote_mutations":false,
            "remaining_growth_released":false,"new191_closure_incremental_DATA_credit_bytes":0,"archive_mutations":false,"sidecar_mutations":false});
        let origin = json!({"schema":"jetstreamer-private-epoch154-native-input-running-v1","epoch":154,"unit":NATIVE154_UNIT,
            "invocation_id":"1".repeat(32),"private_qualification_only":true,"entry_replay":false,"replay_entries":0,"worker_spawned":false,
            "resource_samples_taken":0,"observer":p["bindings"]["observer"],"sampled_at_utc":p["sampled_at_utc"],"probe":{"sha256":"3f2678a065bac34a6fdbdfeff49e8e5239ca7f70ff71c3a1fff2ee9ffd686fb8"},
            "worker":{"sha256":"aaa8758961d8de5790f7fa3979b126d8cb40975da438ce046c0b8bf223cfc615"},
            "replay_launch_authorized":false,"assembly_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false});
        let claim = json!({"epoch":154,"phase":"private-cold-snapshot-verification","unit":NATIVE154_UNIT,
            "invocation_id":"1".repeat(32),"expected_exec_start":"test exact command","evidence":[transition["entry"]["origin"]]});
        let mut plan = d[5].clone();
        plan["pipeline_claims"]
            .as_array_mut()
            .unwrap()
            .push(claim.clone());
        plan["tracked_units"]
            .as_array_mut()
            .unwrap()
            .push(json!(NATIVE154_UNIT));
        plan["metadata_event"] = transition["entry"]["origin"].clone();
        plan["previous_fleet"] = p["bindings"]["fleet"].clone();
        plan["observer"] = p["bindings"]["observer"].clone();
        let mut fleet = d[1].clone();
        fleet["sampled_at_utc"] = p["sampled_at_utc"].clone();
        fleet["previous_fleet"] = p["bindings"]["fleet"].clone();
        fleet["observer_receipt"] = p["bindings"]["observer"]["path"].clone();
        fleet["observer_sha256"] = p["bindings"]["observer"]["sha256"].clone();
        fleet["plan"] = transition["entry"]["fleet_plan"]["path"].clone();
        fleet["plan_sha256"] = transition["entry"]["fleet_plan"]["sha256"].clone();
        fleet["metadata_event"] = transition["entry"]["origin"].clone();
        let native = json!({"Id":NATIVE154_UNIT,"InvocationID":"1".repeat(32),"MainPID":"42","ControlPID":"0","ActiveState":"active","SubState":"running","NRestarts":"0","ExecStart":"test exact command"});
        fleet["unit_census"][NATIVE154_UNIT] = native.clone();
        d[1]["unit_census"][NATIVE154_UNIT] = native;
        for key in ["tracked_units", "pipeline_claims"] {
            d[2][key] = plan[key].clone();
        }
        d[1]["previous_fleet"] = transition["entry"]["fleet"].clone();
        d[2]["previous_fleet"] = transition["entry"]["fleet"].clone();
        let mut sources = std::collections::BTreeMap::from([
            ("entry.origin".into(), origin),
            ("entry.fleet".into(), fleet.clone()),
            ("entry.fleet_plan".into(), plan.clone()),
        ]);
        b["native154_transition"] = bind("native-transition");
        if terminal {
            transition["terminal"] = json!({"proof":bind("terminal-proof"),"fleet":bind("terminal-fleet"),"fleet_plan":bind("terminal-plan")});
            let mut native = fleet["unit_census"][NATIVE154_UNIT].clone();
            native["MainPID"] = json!("0");
            native["SubState"] = json!("exited");
            let proof = json!({"schema":"jetstreamer-epoch154-native-terminal-v2","epoch":154,"unit":NATIVE154_UNIT,"claim":claim,
                "invocation_id":"1".repeat(32),"previous_fleet":transition["entry"]["fleet"],"terminal_manager":native,
                "repair_backlog_open":true,"resource_samples_taken":0,"replay_launch_authorized":false,"archive_completion_claimed":false,
                "publication_authorized":false,"local_retirement_authorized":false,"remote_mutations":false,"r2_mutations":false});
            plan["previous_fleet"] = transition["entry"]["fleet"].clone();
            plan["metadata_event"] = transition["terminal"]["proof"].clone();
            plan["admission_transition_guard"] = Value::Null;
            fleet["previous_fleet"] = transition["entry"]["fleet"].clone();
            fleet["metadata_event"] = transition["terminal"]["proof"].clone();
            fleet["plan"] = transition["terminal"]["fleet_plan"]["path"].clone();
            fleet["plan_sha256"] = transition["terminal"]["fleet_plan"]["sha256"].clone();
            fleet["unit_census"][NATIVE154_UNIT] = native.clone();
            d[1]["unit_census"][NATIVE154_UNIT] = native;
            d[2]["admission_transition_guard"] = Value::Null;
            d[1]["previous_fleet"] = transition["terminal"]["fleet"].clone();
            d[2]["previous_fleet"] = transition["terminal"]["fleet"].clone();
            sources.extend([
                ("terminal.proof".into(), proof),
                ("terminal.fleet".into(), fleet),
                ("terminal.fleet_plan".into(), plan),
            ]);
        }
        (d, b, p, transition, sources, t)
    }
    fn native_check(x: &NativeFixture) -> Result<()> {
        let (d, b, p, tr, s, t) = x;
        validate_evidence(
            &Evidence {
                observer: &d[0],
                fleet: &d[1],
                fleet_plan: &d[2],
                prior_parent: &d[3],
                prior_completion: &d[4],
                prior_fleet_plan: &d[5],
                transition: &d[6],
                prior_recovery: Some(p),
                fleet_transition: None,
                capture_tool_sha: CHAIN_CAPTURE_SHA,
                cohort183_transition: None,
                cohort183_sources: &std::collections::BTreeMap::new(),
                native154_transition: Some(tr),
                native154_sources: s,
            },
            b,
            *t,
        )
    }
    #[test]
    fn additive_actual_frame10_through14_predecessors_pass_and_foreign_capture_rejects() {
        for sha in [
            "38c5b390af0ea4321fb3ecce45a4f74999db882958fbdd05611a4ba0e7454d48",
            "e273ef29773a79140de8320e22966afd0f8d80cf32fe6185aae32bfd0b6b99ac",
            "523360108ec4724660a39a2b9d0ff83b3fd4e9320614302f594446ee0945df98",
            "11ad91050994fc279370f4fd63433927dfd9aded46f2dba074b6b0cffd543b82",
            "026383f2da0fb854b22cda73aa3ca51a7eef32e572da883c860d5944e30c0831",
        ] {
            let mut x = native_fixture(false);
            x.2["self_sha256"] = json!(sha);
            native_check(&x).unwrap();
        }
        let mut crossed = native_fixture(false);
        crossed.2["self_sha256"] = json!("0".repeat(64));
        assert!(native_check(&crossed).is_err());
    }
    #[test]
    fn exact_native154_entry_preserves_every_previous_claim_and_owner() {
        let x = native_fixture(false);
        native_check(&x).unwrap();
        for (key, pointer, value) in [
            ("entry.origin", "/worker/sha256", json!("0".repeat(64))),
            ("entry.origin", "/replay_entries", json!(1)),
            ("entry.fleet_plan", "/pipeline_claims/0/epoch", json!(154)),
            (
                "entry.fleet",
                "/previous_fleet/sha256",
                json!("0".repeat(64)),
            ),
        ] {
            let mut bad = x.clone();
            *bad.4.get_mut(key).unwrap().pointer_mut(pointer).unwrap() = value;
            assert!(native_check(&bad).is_err(), "{key}{pointer}");
        }
        let mut bad = x.clone();
        bad.0[2]["tracked_units"].as_array_mut().unwrap().remove(0);
        assert!(native_check(&bad).is_err());
        let mut bad = x.clone();
        bad.3["remaining_growth_released"] = json!(true);
        assert!(native_check(&bad).is_err());
    }
    #[test]
    fn exact_native154_terminal_never_claims_archive_completion_or_physical_credit() {
        let x = native_fixture(true);
        native_check(&x).unwrap();
        for (pointer, value) in [
            ("/terminal_manager/MainPID", json!("42")),
            ("/claim/invocation_id", json!("2".repeat(32))),
            ("/archive_completion_claimed", json!(true)),
            ("/previous_fleet/sha256", json!("0".repeat(64))),
        ] {
            let mut bad = x.clone();
            *bad.4
                .get_mut("terminal.proof")
                .unwrap()
                .pointer_mut(pointer)
                .unwrap() = value;
            assert!(native_check(&bad).is_err(), "{pointer}");
        }
        let mut bad = x.clone();
        bad.4.get_mut("terminal.fleet_plan").unwrap()["pipeline_claims"]
            .as_array_mut()
            .unwrap()
            .remove(0);
        assert!(native_check(&bad).is_err());
    }
    #[test]
    fn native154_command_identity_keeps_argv_exact_across_legitimate_exit_metadata() {
        let old = json!(
            "{ path=/probe ; argv[]=/probe --plan exact ; ignore_errors=no ; start_time=[old] ; stop_time=[n/a] ; pid=42 ; code=(null) ; status=0 }"
        );
        let exited = json!(
            "{ path=/probe ; argv[]=/probe --plan exact ; ignore_errors=no ; start_time=[old] ; stop_time=[later] ; pid=42 ; code=exited ; status=0 }"
        );
        assert!(same_exec_start(&old, &exited));
        let changed = json!(
            "{ path=/probe ; argv[]=/probe --plan different ; ignore_errors=no ; start_time=[old] ; stop_time=[later] ; pid=42 ; code=exited ; status=0 }"
        );
        assert!(!same_exec_start(&old, &changed));
        let changed = json!(
            "{ path=/probe ; argv[]=/probe --plan exact ; ignore_errors=yes ; start_time=[old] ; stop_time=[later] ; pid=42 ; code=exited ; status=0 }"
        );
        assert!(!same_exec_start(&old, &changed));
    }
    fn handoff_fixture() -> (NativeFixture, Value) {
        let mut x = native_fixture(true);
        x.0[0]["recorded_at_utc"] = json!("2026-10-29T22:53:15Z");
        x.0[0]["replays"] = json!([]);
        x.0[1]["sampled_at_utc"] = x.0[0]["recorded_at_utc"].clone();
        x.5 = 1793314515;
        let census = &mut x.0[1]["unit_census"];
        let mut producer = census[COHORT183_PRODUCER].clone();
        for (k, v) in [
            ("MainPID", "0"),
            ("ControlGroup", ""),
            ("ActiveState", "inactive"),
            ("SubState", "dead"),
            ("LoadState", "not-found"),
            ("InvocationID", ""),
            ("Result", "success"),
            ("ExecMainStatus", "0"),
            ("NRestarts", "0"),
        ] {
            producer[k] = json!(v);
        }
        census[COHORT183_PRODUCER] = producer.clone();
        let importer = json!({"Id":COHORT183_IMPORTER,"InvocationID":COHORT183_IMPORTER_IID,"MainPID":"3006484","LoadState":"loaded","ActiveState":"active","SubState":"running","NRestarts":"0","ExecStart":format!("{{ path=/test/jetstreamer-node ; argv[]=/test/jetstreamer-node 183-184 /home/sol/horizon --verify --recover-staged-cohort-only --source-cohort-receipt={COHORT183_BATCH} --publish-through-epoch=184 ; ignore_errors=no ; start_time=[time] ; stop_time=[n/a] ; pid=3006484 ; code=(null) ; status=0/0 }}")});
        census[COHORT183_IMPORTER] = importer.clone();
        let controller = census[COHORT183_CONTROLLER].clone();
        let proof = json!({"schema":"jetstreamer-cohort183-controller-import-handoff-v1","controller":controller,"producer":producer,"importer":importer,
            "producer_terminal_manager":{"UNIT":COHORT183_PRODUCER,"INVOCATION_ID":"489e219d38d14d4594d8649ff698f666","_PID":"1","_UID":"0","MESSAGE_ID":"7ad2d189f7e94e70a38c781354912448","__REALTIME_TIMESTAMP":"1793312662979294","MESSAGE":format!("{COHORT183_PRODUCER}: Deactivated successfully.")},
            "controller_state":{"schema":"jetstreamer-adaptive-root-cohort-sweep-v3","configuration_sha256":"85b2f382af78b0fb722ff60dc3069d8c9844ae1a0a5a6816230ac66e432248b4","manifest_fingerprint":"sha256:e74726a897764d53bb6f11858e5a732366fba5d6be54a15dc87c71fca3ea3a64","public_dir":"/home/sol/horizon","import_owner":"lane-a","assignments":{"lane-a":{"first_epoch":183,"last_epoch":184,"attempt":1,"phase":"importing","unit":COHORT183_PRODUCER,"pid":293448,"pid_start_time":106887499,"receipt":COHORT183_BATCH,"import_unit":COHORT183_IMPORTER}}},
            "source_batch":{"path":COHORT183_BATCH,"sha256":COHORT183_BATCH_SHA},"replay_finished":true,"resource_credit_bytes":0,"archive_hash_performed":false,"verification_complete":false,"publication_authorized":false,"replay_launch_authorized":false,"r2_mutations":false});
        let mut added = vec![];
        let evidence = json!({"path":"/test/cohort183-batch.json","sha256":COHORT183_BATCH_SHA});
        for epoch in [183, 184] {
            let claim = json!({"epoch":epoch,"phase":"controller-import-handoff","unit":COHORT183_CONTROLLER,"invocation_id":COHORT183_CONTROLLER_IID,"expected_exec_start":controller["ExecStart"],"evidence":[evidence]});
            x.0[2]["pipeline_claims"]
                .as_array_mut()
                .unwrap()
                .push(claim.clone());
            added.push(claim);
            x.0[2]["gates"][epoch.to_string()]["state"] = json!("post-replay-pipeline");
            x.0[2]["gates"][epoch.to_string()]["next_action"] = json!(
                "Continue import; original repair incident remains open until verified R2 pairs."
            );
            x.0[2]["gates"][epoch.to_string()]["evidence"]
                .as_array_mut()
                .unwrap()
                .push(evidence.clone());
        }
        x.0[2]["tracked_units"]
            .as_array_mut()
            .unwrap()
            .push(json!(COHORT183_IMPORTER));
        let pipelines = added.iter().map(|c|json!({"epoch":c["epoch"],"phase":c["phase"],"unit":controller,"expected_invocation_id":COHORT183_CONTROLLER_IID,"evidence":c["evidence"],"finalization_evidence":proof,"live":true,"ordinary_replay_claim":false,"grants_launch_or_publication_authority":false,"sampled_at_utc":x.0[0]["recorded_at_utc"]})).collect::<Vec<_>>();
        x.0[1]["pipelines"] = json!(pipelines);
        x.1["cohort183_transition"] =
            json!({"path":"/test/cohort183-transition.json","sha256":"e".repeat(64)});
        let t = json!({"schema":"jetstreamer-horizon-cohort183-recovered-frame-transition-v1","previous_recovery":x.1["prior_recovery"],"prior_fleet_plan":x.1["prior_fleet_plan"],"fleet_plan":x.1["fleet_plan"],"added_tracked_units":[COHORT183_IMPORTER],"added_pipeline_claims":added,
            "gate_updates":{"183":{"previous_gate":x.0[5]["gates"]["183"],"current_gate":x.0[2]["gates"]["183"]},"184":{"previous_gate":x.0[5]["gates"]["184"],"current_gate":x.0[2]["gates"]["184"]}},"repair_incident_remains_open":true,"replay_launch_authorized":false,"publication_authorized":false,"remote_mutations":false,"remaining_growth_released":false,"new191_closure_incremental_DATA_credit_bytes":0,"archive_mutations":false,"sidecar_mutations":false});
        (x, t)
    }
    fn handoff_check(x: &(NativeFixture, Value)) -> Result<()> {
        let ((d, b, p, tr, s, t), cohort) = x;
        validate_evidence(
            &Evidence {
                observer: &d[0],
                fleet: &d[1],
                fleet_plan: &d[2],
                prior_parent: &d[3],
                prior_completion: &d[4],
                prior_fleet_plan: &d[5],
                transition: &d[6],
                prior_recovery: Some(p),
                fleet_transition: None,
                capture_tool_sha: CHAIN_CAPTURE_SHA,
                native154_transition: Some(tr),
                native154_sources: s,
                cohort183_transition: Some(cohort),
                cohort183_sources: &std::collections::BTreeMap::new(),
            },
            b,
            *t,
        )
    }
    #[test]
    fn completed183_handoff_preserves_native154_and_original_lineage_without_credit() {
        let x = handoff_fixture();
        handoff_check(&x).unwrap();
        for (pointer, value) in [
            (
                "/0/0/1/pipelines/0/finalization_evidence/resource_credit_bytes",
                json!(1),
            ),
            (
                "/0/0/1/pipelines/1/finalization_evidence/importer/InvocationID",
                json!("foreign"),
            ),
            (
                "/0/0/1/pipelines/0/finalization_evidence/producer_terminal_manager/_PID",
                json!("2"),
            ),
            ("/0/0/2/gates/154/state", json!("post-replay-pipeline")),
            ("/1/repair_incident_remains_open", json!(false)),
            ("/1/remaining_growth_released", json!(true)),
            ("/1/previous_recovery/sha256", json!("0".repeat(64))),
        ] {
            let mut bad = serde_json::to_value(&x).unwrap();
            *bad.pointer_mut(pointer).unwrap() = value;
            let bad: (NativeFixture, Value) = serde_json::from_value(bad).unwrap();
            assert!(handoff_check(&bad).is_err(), "{pointer}");
        }
    }
    #[test]
    fn completed183_requires_zero_primary_census_and_exact_additions() {
        let x = handoff_fixture();
        let mut bad = x.clone();
        bad.0.0[0]["replays"] = json!([{"range":"183-184"}]);
        assert!(handoff_check(&bad).is_err());
        let mut bad = x.clone();
        bad.0.0[2]["pipeline_claims"]
            .as_array_mut()
            .unwrap()
            .remove(0);
        assert!(handoff_check(&bad).is_err());
        let mut bad = x.clone();
        bad.0.0[2]["tracked_units"]
            .as_array_mut()
            .unwrap()
            .push(json!("foreign.service"));
        assert!(handoff_check(&bad).is_err());
        let mut bad = x;
        bad.0.5 = 1793312662;
        assert!(handoff_check(&bad).is_err());
    }

    #[test]
    fn actual2110_entry2140_and2223_bridge_validate_without_fictional_completion() {
        let a: Value =
            serde_json::from_str(include_str!("../fixtures/actual-lineage.json")).unwrap();
        let tr: Value = serde_json::from_str(include_str!(
            "../fixtures/retained-original/native154-entry-only-transition.json"
        ))
        .unwrap();
        let bridge: Value = serde_json::from_str(include_str!(
            "../fixtures/retained-original/observation-bridge.json"
        ))
        .unwrap();
        let ((synthetic, _, _, _, _, _), mut cohort) = handoff_fixture();
        let mut observer = a["last_observer"].clone();
        observer["recorded_at_utc"] = json!("2026-10-29T22:53:15Z");
        observer["replays"] = json!([]);
        observer["cadence"]["previous_sample"] = a["bindings"]["last_observer"]["path"].clone();
        observer["cadence"]["previous_sample_sha256"] =
            a["bindings"]["last_observer"]["sha256"].clone();
        observer["cadence"]["observed_interval_seconds"] = json!(1800);
        let mut plan = a["draft"].clone();
        let mut b = a["previous"]["bindings"].clone();
        b["prior_recovery"] = a["bindings"]["previous"].clone();
        b["prior_fleet_plan"] = a["bindings"]["prior_plan"].clone();
        b["observer"] = json!({"path":"/test/derived-observer2253.json","sha256":"a".repeat(64)});
        b["fleet_plan"] = json!({"path":"/test/derived-plan2253.json","sha256":"b".repeat(64)});
        b["native154_transition"] =
            json!({"path":"/test/native154-entry.json","sha256":"c".repeat(64)});
        b["cohort183_transition"] =
            json!({"path":"/test/cohort183-transition.json","sha256":"d".repeat(64)});
        plan["observer"] = b["observer"].clone();
        let mut fleet = a["bridge_fleet"].clone();
        fleet["sampled_at_utc"] = observer["recorded_at_utc"].clone();
        fleet["observer_receipt"] = b["observer"]["path"].clone();
        fleet["observer_sha256"] = b["observer"]["sha256"].clone();
        fleet["plan"] = b["fleet_plan"]["path"].clone();
        fleet["plan_sha256"] = b["fleet_plan"]["sha256"].clone();
        fleet["previous_fleet"] = a["bindings"]["bridge_fleet"].clone();
        let proof = synthetic[1]["pipelines"][0]["finalization_evidence"].clone();
        for unit in [COHORT183_CONTROLLER, COHORT183_PRODUCER, COHORT183_IMPORTER] {
            let key = if unit == COHORT183_CONTROLLER {
                "controller"
            } else if unit == COHORT183_PRODUCER {
                "producer"
            } else {
                "importer"
            };
            fleet["unit_census"][unit] = proof[key].clone();
        }
        let claims = plan["pipeline_claims"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|c| c["epoch"] == 183 || c["epoch"] == 184)
            .cloned()
            .collect::<Vec<_>>();
        fleet["pipelines"] = json!(claims.iter().map(|c|json!({"epoch":c["epoch"],"phase":c["phase"],"unit":proof["controller"],"expected_invocation_id":COHORT183_CONTROLLER_IID,"evidence":c["evidence"],"finalization_evidence":proof,"live":true,"ordinary_replay_claim":false,"grants_launch_or_publication_authority":false,"sampled_at_utc":observer["recorded_at_utc"]})).collect::<Vec<_>>());
        cohort["previous_recovery"] = b["prior_recovery"].clone();
        cohort["prior_fleet_plan"] = b["prior_fleet_plan"].clone();
        cohort["fleet_plan"] = b["fleet_plan"].clone();
        cohort["added_pipeline_claims"] = json!(claims);
        cohort["observation_bridge"] = bridge;
        for epoch in ["183", "184"] {
            cohort["gate_updates"][epoch] = json!({"previous_gate":a["prior_plan"]["gates"][epoch],"current_gate":plan["gates"][epoch]});
        }
        let mut updates = serde_json::Map::new();
        for epoch in ["136", "154"] {
            if a["prior_plan"]["gates"][epoch] != plan["gates"][epoch] {
                updates.insert(epoch.into(),json!({"previous_gate":a["prior_plan"]["gates"][epoch],"current_gate":plan["gates"][epoch]}));
            }
        }
        let delta = if updates.is_empty() {
            None
        } else {
            b["fleet_transition"] = json!({"path":"/test/delta2253.json","sha256":"e".repeat(64)});
            Some(
                json!({"schema":"jetstreamer-horizon-recovered-fleet-delta-v1","prior_fleet_plan":b["prior_fleet_plan"],"fleet_plan":b["fleet_plan"],"gate_updates":updates,"replay_launch_authorized":false,"publication_authorized":false,"remote_mutations":false,"remaining_growth_released":false,"new191_closure_incremental_DATA_credit_bytes":0,"archive_mutations":false,"sidecar_mutations":false}),
            )
        };
        let native = std::collections::BTreeMap::from([
            ("entry.origin".into(), a["entry_origin"].clone()),
            ("entry.fleet".into(), a["entry_fleet"].clone()),
            ("entry.fleet_plan".into(), a["entry_plan"].clone()),
        ]);
        let sources = std::collections::BTreeMap::from([
            ("bridge.0.observer".into(), a["bridge_observer"].clone()),
            ("bridge.0.fleet".into(), a["bridge_fleet"].clone()),
            ("bridge.0.fleet_plan".into(), a["bridge_plan"].clone()),
            ("bridge.1.observer".into(), a["last_observer"].clone()),
        ]);
        let e = Evidence {
            observer: &observer,
            fleet: &fleet,
            fleet_plan: &plan,
            prior_parent: &a["parent"],
            prior_completion: &a["completion"],
            prior_fleet_plan: &a["prior_plan"],
            transition: &a["transition"],
            prior_recovery: Some(&a["previous"]),
            fleet_transition: delta.as_ref(),
            capture_tool_sha: CHAIN_CAPTURE_SHA,
            native154_transition: Some(&tr),
            native154_sources: &native,
            cohort183_transition: Some(&cohort),
            cohort183_sources: &sources,
        };
        validate_evidence(&e, &b, 1793314515).unwrap();
        let mut broken = sources.clone();
        broken.get_mut("bridge.1.observer").unwrap()["cadence"]["previous_sample_sha256"] =
            json!("0".repeat(64));
        let e = Evidence {
            cohort183_sources: &broken,
            ..e
        };
        assert!(validate_evidence(&e, &b, 1793314515).is_err());
    }
}

#[cfg(test)]
#[path = "g6_outer_frame_tests.rs"]
mod g6_outer_frame_tests;

#[cfg(test)]
mod g7_outer_frame_tests;

#[cfg(test)]
mod retry0005_outer_tests;

mod cached145_observer_recovery;
mod retained_observer_chain;

#[cfg(test)]
#[path = "observer_recovery_outer_tests.rs"]
mod observer_recovery_outer_tests;

#[cfg(test)]
mod canonical_v5_previous_capture_tests {
    use super::*;
    #[test]
    fn known_v4_capture_remains_a_strict_predecessor_for_a_new_canonical_capture() {
        // TEST ONLY closed envelope; never runtime receipt or resource credit.
        let previous = json!({"self_sha256":QUALIFIED_HELPER_V4_FRAME_CAPTURE_SHA,
            "schema":SCHEMA,"accepted_resource_lineage":true,
            "full_routine_completion_claimed":false,"new_resource_observations":0,
            "native_census_before":{},"native_census_after":{}});
        let binding = json!({"path":"/test/previous.json","sha256":"a".repeat(64)});
        let current = "b".repeat(64);
        qualified_previous_recovery_envelope(&previous, &binding, &current).unwrap();
        for (key, value) in [
            ("self_sha256", json!("0".repeat(64))),
            ("accepted_resource_lineage", json!(false)),
            ("full_routine_completion_claimed", json!(true)),
            ("new_resource_observations", json!(1)),
            ("native_census_after", json!({"foreign":true})),
        ] {
            let mut bad = previous.clone();
            bad[key] = value;
            assert!(
                qualified_previous_recovery_envelope(&bad, &binding, &current).is_err(),
                "{key}"
            );
        }
    }
}
