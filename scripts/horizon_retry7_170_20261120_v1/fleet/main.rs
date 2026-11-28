//! Reconcile retained observations and a genuine terminal transition. No native queries.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

const THREAD: &str = "01a1af2a-9ce8-76a2-8939-b2112bd38f53";
const HOME: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch170-retry7-recovery-20261120-v1";
const PREVIOUS: &str = "/var/lib/jetstreamer/horizon_runtime_data/root2325-live166retry8-167retry7-170retry6-homeaudit-observation-20261119-v1/ROOT_COMPLETE_OPERATIONAL_FLEET.json";
const PREVIOUS_SHA: &str = "a845ae7e977b6e3b6cd0fc0e5d675d15212f115f1d87bf2f8ec13f5811be404e";
const RECOVERY: &str = "/var/lib/jetstreamer/horizon_runtime_data/root0040-recovery-20261120-v1/ROOT_OPERATIONAL_RECOVERY_EVENT.json";
const RECOVERY_SHA: &str = "e8fedd5fc957649318a9b3d5aca84761cb0f394c0bb215d557577c8b887e8eba";
const ORIGINAL_RECOVERY_SHA: &str =
    "1f39376d798cc8811878037eb2590ac9f4a38dff14d14e5de05213e845682127";
const STOP: &str = "/var/lib/jetstreamer/retry6-170-preparation-20261118-v1/epoch170/local3retry6/guard-state/receipts/stop-completion.json";
const STOP_SHA: &str = "3601e2dabb55f7c3ca9ed8f91c253588f301b51a87c42ba9ece18f73fab48264";
const INTENT: &str = "/var/lib/jetstreamer/retry6-170-preparation-20261118-v1/epoch170/local3retry6/guard-state/receipts/stop-intent.json";
const INTENT_SHA: &str = "22344407c7f7f034eae858791636fc0275c7b12c2bee1a5326e18dd1560700fb";
const STOP_IID: &str = "ebd212d2045145259449d1d5c3d65353";
const STOP_UNIT: &str = "horizon-qualify-170-replacement-local3retry6-20261110-v1.service";
const STOP_PLAN_SHA: &str = "6f689ea9a9ab92bf0ab4b3d6fe1a0a585282f0bad7be7bbb975f583dccea217f";
const STATUS_EPOCHS: [u64; 19] = [
    136, 137, 141, 145, 159, 161, 163, 166, 167, 168, 169, 170, 171, 172, 173, 185, 186, 199, 200,
];

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Bound {
    path: PathBuf,
    sha256: String,
}
impl Bound {
    fn exact(path: &str, sha256: &str) -> Self {
        Self {
            path: path.into(),
            sha256: sha256.into(),
        }
    }
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    owner: String,
    primary_thread: String,
    previous_fleet: Bound,
    recovery_overlay: Bound,
    previous_observer: Bound,
    observer: Bound,
    authenticated_status_audit: Bound,
    sole_next_observer: Bound,
    output_directory: PathBuf,
}
fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn read_bound(binding: &Bound) -> Result<Value> {
    ensure!(
        binding.path.is_absolute() && hex(&binding.sha256),
        "absolute hash-bound source required"
    );
    let path = &binding.path;
    let before = fs::symlink_metadata(path)?;
    ensure!(
        path.canonicalize()? == *path
            && before.is_file()
            && before.uid() == 0
            && before.nlink() == 1
            && before.mode() & 0o022 == 0
            && before.len() <= 32 << 20,
        "unsafe source custody: {}",
        path.display()
    );
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let identity = |m: &fs::Metadata| {
        (
            m.dev(),
            m.ino(),
            m.len(),
            m.mode(),
            m.uid(),
            m.nlink(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
        )
    };
    ensure!(
        identity(&before) == identity(&file.metadata()?),
        "source changed during open"
    );
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take((32 << 20) + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        sha(&bytes) == binding.sha256
            && identity(&before) == identity(&file.metadata()?)
            && identity(&before) == identity(&fs::symlink_metadata(path)?),
        "source digest or custody changed"
    );
    Ok(serde_json::from_slice(&bytes)?)
}
fn load(value: &Value) -> Result<Value> {
    read_bound(&serde_json::from_value(value.clone())?)
}
fn number(value: &Value, key: &str) -> Result<u64> {
    value[key]
        .as_u64()
        .with_context(|| format!("missing integer {key}"))
}
fn one<'a>(rows: &'a Value, key: &str, expected: &Value) -> Result<&'a Value> {
    let found: Vec<_> = rows
        .as_array()
        .context("row array")?
        .iter()
        .filter(|r| &r[key] == expected)
        .collect();
    ensure!(found.len() == 1, "missing or duplicate {key}: {expected}");
    Ok(found[0])
}
fn peer(epoch: u64) -> (&'static str, &'static str, u64, u64) {
    match epoch {
        166 => (
            "horizon-qualify-166-replacement-local3retry8-20261110-v1.service",
            "4f09db5f45074244a45b06aeef932d1d",
            1746683,
            339966412,
        ),
        167 => (
            "horizon-qualify-167-replacement-local3retry7-20261110-v1.service",
            "a680103e76f546faaf469aa80c35fa3b",
            1871809,
            341800795,
        ),
        _ => unreachable!("fixed peer set"),
    }
}
fn observed_peer(sample: &Value, epoch: u64) -> Result<&Value> {
    let row = one(&sample["replays"], "range", &json!(epoch.to_string()))?;
    let (unit, iid, pid, ticks) = peer(epoch);
    ensure!(
        row["invocation_binding_stable"] == true,
        "peer invocation unstable"
    );
    for side in [
        "producer_before",
        "producer_after",
        "controller_before",
        "controller_after",
    ] {
        let n = &row[side];
        ensure!(
            n["unit"] == unit
                && n["invocation_id"] == iid
                && n["main_pid"] == pid
                && n["restarts"] == 0
                && n["active_state"] == "active"
                && n["sub_state"] == "running"
                && n["load_state"] == "loaded"
                && n["result"] == "success",
            "peer identity or live state differs: {epoch}/{side}"
        );
        let process = one(&n["rss"]["processes"], "pid", &json!(pid))?;
        ensure!(
            process["start_ticks"] == ticks,
            "peer PID generation differs"
        );
    }
    let progress = &row["useful_work"];
    ensure!(
        progress["sufficient_for_rates"] == true
            && progress["journal_invocation_id"] == iid
            && progress["counter_resets"] == 0
            && number(progress, "slot_delta")? > 0
            && number(progress, "transaction_delta")? > 0
            && number(progress, "account_update_delta")? > 0
            && progress["append_log_evidence"]["stdout_append_binding_verified"] == true
            && progress["append_log_evidence"]["producer_main_pid"] == pid
            && progress["last"]["terminal_slot"] == (epoch + 1) * 432000 - 1
            && number(&progress["last"], "slot")? >= epoch * 432000
            && number(&progress["last"], "slot")? < (epoch + 1) * 432000,
        "advancing full-epoch peer evidence required"
    );
    for (counter, delta) in [
        ("slot", "slot_delta"),
        ("transactions", "transaction_delta"),
        ("account_updates", "account_update_delta"),
    ] {
        ensure!(
            number(&progress["last"], counter)?.checked_sub(number(&progress["first"], counter)?)
                == Some(number(progress, delta)?),
            "progress counters disagree"
        );
    }
    Ok(row)
}
fn sample_shape(sample: &Value) -> Result<()> {
    ensure!(
        sample["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && sample["replays"].as_array().is_some_and(|r| r.len() == 2)
            && sample["cadence"]["routine_minimum_interval_enforced"] == true
            && sample["cadence"]["minimum_interval_seconds"] == 1800,
        "accepted two-peer observation required"
    );
    for key in [
        "producer_or_controller_signals_sent",
        "r2_mutations",
        "remote_mutations",
        "service_state_changed",
    ] {
        ensure!(
            sample["mutation"][key] == false,
            "observation mutated {key}"
        );
    }
    for epoch in [166, 167] {
        observed_peer(sample, epoch)?;
    }
    let stopped = one(&sample["diagnostic_replays"], "range", &json!("170"))?;
    ensure!(
        stopped["producer_unit"] == STOP_UNIT
            && stopped["expected_producer_invocation_id"] == STOP_IID
            && stopped["ordinary_replay_claim"] == false
            && stopped["replay_launch_authorized"] == false,
        "terminal170 must remain diagnostic, not an ordinary lane"
    );
    Ok(())
}
fn stop_shape(stop: &Value, intent: &Value) -> Result<()> {
    ensure!(
        stop["schema"] == "jetstreamer-horizon-standalone-stop-completion-v1"
            && stop["producer_invocation_id"] == STOP_IID
            && stop["intent"] == INTENT
            && stop["plan_sha256"] == STOP_PLAN_SHA
            && stop["terminal"]["invocation_id"] == STOP_IID
            && stop["terminal"]["pid"] == 0
            && stop["terminal"]["active"] == "inactive"
            && stop["terminal"]["sub"] == "dead"
            && stop["terminal"]["restarts"] == 0
            && stop["terminal"]["result"] == "success"
            && stop["scratch_deleted"] == false
            && stop["remote_mutations"] == false
            && stop["r2_mutations"] == false
            && intent["schema"] == "jetstreamer-horizon-standalone-stop-intent-v1"
            && intent["producer_invocation_id"] == STOP_IID
            && intent["plan_sha256"] == STOP_PLAN_SHA
            && intent["reason"] == "DATA-fulfillment-observation-failed"
            && intent["sample"]["producer_invocation_id"] == STOP_IID
            && intent["sample"]["producer"]["invocation_id"] == STOP_IID
            && intent["sample"]["plan_sha256"] == STOP_PLAN_SHA
            && intent["sample"]["producer_stop_enabled"] == true
            && intent["sample"]["DATA_fulfillment_observation_error"] == "bounded writer query",
        "genuine consumed retry6 terminal lineage required"
    );
    Ok(())
}

struct Evidence {
    previous: Value,
    recovery: Value,
    previous_sample: Value,
    sample: Value,
    status: Value,
    next: Value,
    stop: Value,
    intent: Value,
    receipts: BTreeMap<u64, Value>,
}
fn read_evidence(p: &Plan) -> Result<Evidence> {
    ensure!(
        p.schema == "horizon-Root-terminal-fleet-reconcile-plan-v1"
            && p.owner == "/root"
            && p.primary_thread == THREAD
            && p.previous_fleet == Bound::exact(PREVIOUS, PREVIOUS_SHA)
            && p.recovery_overlay == Bound::exact(RECOVERY, RECOVERY_SHA),
        "exact historical predecessor and recovery overlay required"
    );
    let previous = read_bound(&p.previous_fleet)?;
    let recovery = read_bound(&p.recovery_overlay)?;
    ensure!(
        recovery["previous_recovery_event"]["sha256"] == ORIGINAL_RECOVERY_SHA,
        "original stop overlay differs"
    );
    let original = load(&recovery["previous_recovery_event"])?;
    ensure!(
        original["previous_complete_fleet"] == serde_json::to_value(&p.previous_fleet)?
            && original["active_repair_epoch"] == 170
            && original["live_replay_count"] == 2
            && original["resource_credit_bytes"] == 0,
        "original stop overlay missing"
    );
    load(&recovery["additional_retained_build_allocation"])?;
    load(&previous["authenticated_inventory"])?;
    let status = read_bound(&p.authenticated_status_audit)?;
    let mut receipts = BTreeMap::new();
    for epoch in STATUS_EPOCHS {
        receipts.insert(epoch, load(&status["receipts"][epoch.to_string()])?);
    }
    for epoch in [166, 167, 170] {
        let owner = one(
            &previous["actual_executing_replays"],
            "epoch",
            &json!(epoch),
        )?;
        let admission = load(&owner["admission"])?;
        let protection = load(&owner["guard_protection"])?;
        ensure!(
            admission["producer_unit"] == owner["unit"]["Id"]
                && admission["producer_invocation_id"] == owner["unit"]["InvocationID"]
                && admission["fresh_admission_passed"] == true
                && admission["all_prior_promises_retained"] == true
                && protection["admission"] == owner["admission"],
            "prior genuine owner binding differs"
        );
    }
    Ok(Evidence {
        previous,
        recovery,
        previous_sample: read_bound(&p.previous_observer)?,
        sample: read_bound(&p.observer)?,
        status,
        next: read_bound(&p.sole_next_observer)?,
        stop: read_bound(&Bound::exact(STOP, STOP_SHA))?,
        intent: read_bound(&Bound::exact(INTENT, INTENT_SHA))?,
        receipts,
    })
}

fn reconcile(p: &Plan, e: &Evidence, recorded: u64) -> Result<Value> {
    let old = &e.previous;
    ensure!(
        old["schema"] == "horizon-Root-complete-fleet-operational-review-v1"
            && old["owner"] == "/root"
            && old["primary_thread"] == THREAD
            && old["live_replay_count"] == 3
            && old["active_producer_count"] == 3
            && old["actual_executing_replays"]
                .as_array()
                .is_some_and(|r| r.len() == 3)
            && old["actual_active_bootstraps"] == json!([])
            && old["complete_DATA_bytes"] == 6_794_761_027_378u64
            && old["complete_projected_memory_bytes"] == 761_131_708_416u64
            && old["retained_retry6_166_DATA_bytes"] == 309_237_645_312u64
            && old["all_existing_memory_DATA_OS_native_transport_promises_retained"] == true,
        "actual three-owner predecessor and every retained base promise required"
    );
    for key in [
        "continuing_audit_obligation",
        "complete_DATA_authority",
        "full_current_proc_and_unit_census",
        "authenticated_inventory",
    ] {
        ensure!(old[key].is_object(), "missing retained {key}");
    }
    let terminal_owner = one(&old["actual_executing_replays"], "epoch", &json!(170))?;
    ensure!(
        terminal_owner["unit"]["Id"] == STOP_UNIT
            && terminal_owner["unit"]["InvocationID"] == STOP_IID,
        "unrelated historical170 owner"
    );
    stop_shape(&e.stop, &e.intent)?;
    ensure!(
        e.recovery["schema"] == "horizon-Root-terminal-observation-recovery-event-v1"
            && e.recovery["previous_complete_fleet"] == serde_json::to_value(&p.previous_fleet)?
            && e.recovery["active_replay_epochs"] == json!([166, 167])
            && e.recovery["live_replay_count"] == 2
            && e.recovery["active_repair_epoch"] == 170
            && e.recovery["all_reservation_ending_bytes"] == 0
            && e.recovery["resource_credit_bytes"] == 0
            && e.recovery["resource_limits_changed"] == false
            && e.recovery["all_existing_memory_DATA_OS_native_transport_promises_retained"] == true,
        "recovery obligations differ"
    );
    sample_shape(&e.previous_sample)?;
    sample_shape(&e.sample)?;
    ensure!(
        e.sample["cadence"]["previous_sample"] == json!(p.previous_observer.path)
            && e.sample["cadence"]["previous_sample_sha256"] == p.previous_observer.sha256
            && e.sample["cadence"]["previous_sample_recorded_at_utc"]
                == e.previous_sample["recorded_at_utc"]
            && e.sample["recorded_at_utc"]
                .as_str()
                .context("current observation clock")?
                > e.previous_sample["completed_at_utc"]
                    .as_str()
                    .context("previous observation clock")?,
        "observations not linked in chronological order"
    );
    let observer = serde_json::to_value(&p.observer)?;
    ensure!(
        e.status["schema"] == "horizon-status-full-range-audit-v1"
            && e.status["owner"] == "/root"
            && e.status["primary_thread"] == THREAD
            && e.status["observer"] == observer
            && e.status["authenticated_readback"] == true
            && e.status["authenticated_status_count"] == 19
            && e.status["all_nineteen_existing_statuses_authenticated"] == true
            && e.status["active_producer_count"] == 2
            && e.status["replay_lanes"] == 2
            && e.status["active_bootstraps"] == 0
            && e.status["status_epochs"] == json!(STATUS_EPOCHS)
            && e.status["receipts"]
                .as_object()
                .is_some_and(|v| v.len() == 19)
            && e.status["inventory"] == old["authenticated_inventory"]
            && e.status["sampled_at_utc"] == e.sample["recorded_at_utc"],
        "same-observation nineteen-status audit required"
    );
    for epoch in STATUS_EPOCHS {
        let r = e
            .receipts
            .get(&epoch)
            .context("missing authenticated receipt")?;
        ensure!(
            r["epoch"] == epoch
                && r["authenticated_readback"] == true
                && r["sampled_at_utc"] == e.sample["recorded_at_utc"]
                && r["after_status"]["epoch"] == epoch,
            "status receipt differs: {epoch}"
        );
    }
    let terminal_status = &e.receipts[&170];
    let terminal = &terminal_status["terminal170_native"];
    ensure!(
        terminal["InvocationID"] == STOP_IID
            && terminal["ActiveState"] == "inactive"
            && terminal["SubState"] == "dead"
            && terminal["MainPID"] == "0"
            && terminal["NRestarts"] == "0"
            && terminal["Job"] == ""
            && terminal_status["current_repair_owner"] == "/root"
            && terminal_status["after_status"]["phase"] != "replay",
        "current status still claims terminal170 replay"
    );
    ensure!(
        e.next["previous_sample"] == json!(p.observer.path)
            && e.next["minimum_interval_seconds"] == 1800
            && e.next["not_before_utc"]
                == e.sample["cadence"]["next_routine_observation_not_before_utc"]
            && e.next["replays"].as_array().is_some_and(|r| r.len() == 2),
        "next cadence differs"
    );
    let mut owners = Vec::new();
    for epoch in [166, 167] {
        let observed = observed_peer(&e.sample, epoch)?;
        let prior = observed_peer(&e.previous_sample, epoch)?;
        let (unit, iid, pid, _) = peer(epoch);
        let next = one(&e.next["replays"], "range", &json!(epoch.to_string()))?;
        ensure!(
            next["producer_unit"] == unit
                && next["expected_producer_invocation_id"] == iid
                && next["controller_unit"] == unit
                && next["expected_controller_invocation_id"] == iid
                && next["scratch_path"] == observed["scratch_path"],
            "next observer changes live owner"
        );
        ensure!(
            number(&observed["useful_work"]["last"], "slot")?
                > number(&prior["useful_work"]["last"], "slot")?,
            "peer failed to advance between observations"
        );
        let pid_text = pid.to_string();
        let mut owner = one(&old["actual_executing_replays"], "epoch", &json!(epoch))?.clone();
        ensure!(
            owner["unit"]["Id"] == unit
                && owner["unit"]["InvocationID"] == iid
                && owner["unit"]["MainPID"].as_str() == Some(pid_text.as_str()),
            "prior peer generation differs"
        );
        for (native, observed_key) in [
            ("ActiveState", "active_state"),
            ("SubState", "sub_state"),
            ("InvocationID", "invocation_id"),
            ("Id", "unit"),
        ] {
            owner["unit"][native] = observed["producer_after"][observed_key].clone();
        }
        owner["unit"]["MainPID"] = json!(pid_text);
        owner["unit"]["NRestarts"] = json!("0");
        owner["observer"] = observer.clone();
        owner["progress"] = observed["useful_work"].clone();
        owner["scratch_path"] = observed["scratch_path"].clone();
        owner["phase"] = json!("replay");
        owner["in_current_observer"] = json!(true);
        owner["current_identity_from_same_observation"] = json!(true);
        owners.push(owner);
    }
    // Clone the entire predecessor: unknown future commitment fields survive unchanged.
    let mut fleet = old.clone();
    let transition = json!({"schema":"horizon-epoch170-retry6-terminal-fleet-transition-v1","epoch":170,"attempt":"local3retry6",
        "producer_unit":STOP_UNIT,"producer_invocation_id":STOP_IID,"stop_completion":Bound::exact(STOP,STOP_SHA),
        "stop_intent":Bound::exact(INTENT,INTENT_SHA),"terminal":e.stop["terminal"],"historical_live_owner":terminal_owner,
        "current_status_receipt":e.status["receipts"]["170"],"retained_history":true,"resource_promise_ending_bytes":0,
        "resource_credit_bytes":0,"scratch_deleted":false,"replay_launch_authorized":false});
    fleet["terminal_producers"]
        .as_array_mut()
        .context("terminal history")?
        .push(transition.clone());
    fleet["terminal170_transition"] = transition.clone();
    fleet["historical_epoch170_join_identity"] = fleet["epoch170_join_identity"].clone();
    fleet["epoch170_join_identity"] = Value::Null;
    fleet["historical_pre170_terminal_recovery"] = fleet["next_lane_recovery"].clone();
    fleet["next_lane_recovery"] = e.recovery["next_lane_recovery"].clone();
    fleet["previous_Root_operational_review"] = serde_json::to_value(&p.previous_fleet)?;
    fleet["terminal_recovery_overlay"] = serde_json::to_value(&p.recovery_overlay)?;
    fleet["retained_terminal_recovery_commitments"] = e.recovery.clone();
    for key in [
        "additional_retained_build_allocation",
        "build_allocation_rule",
    ] {
        fleet[key] = e.recovery[key].clone();
    }
    fleet["observer"] = observer.clone();
    fleet["authenticated_status_audit"] = serde_json::to_value(&p.authenticated_status_audit)?;
    fleet["sole_next_observer"] = serde_json::to_value(&p.sole_next_observer)?;
    fleet["sampled_at_utc"] = e.sample["recorded_at_utc"].clone();
    fleet["recorded_unix_seconds"] = json!(recorded);
    fleet["actual_executing_replays"] = json!(owners);
    fleet["actual_active_bootstraps"] = json!([]);
    for k in [
        "active_producer_count",
        "live_replay_count",
        "useful_replay_count",
    ] {
        fleet[k] = json!(2);
    }
    for k in ["bootstrap_count", "guarded_bootstrap_owner_count"] {
        fleet[k] = json!(0);
    }
    fleet["same_sample_conservative_free_DATA_bytes"] =
        e.sample["filesystem"]["conservative_available_bytes"].clone();
    fleet["historical_complete_cycle_conservative_available_DATA_bytes"] =
        old["complete_cycle_conservative_available_DATA_bytes"].clone();
    fleet["complete_cycle_conservative_available_DATA_bytes"] = json!(
        number(old, "complete_cycle_conservative_available_DATA_bytes")?.min(number(
            &e.sample["filesystem"],
            "conservative_available_bytes"
        )?)
    );
    fleet["retained_native_census_is_historical"] = json!(true);
    for row in fleet["epochs"].as_array_mut().context("epoch inventory")? {
        let epoch = number(row, "epoch")?;
        if let Some(receipt) = e.receipts.get(&epoch) {
            let binding = &e.status["receipts"][epoch.to_string()];
            row["status_publication"] = binding.clone();
            row["current_authenticated_status_receipt"] = binding.clone();
            row["status"] = receipt["after_status"].clone();
            row["current_status"] = receipt["after_status"].clone();
        }
        row["current_coordinated_observer"] = observer.clone();
        if let Some(owner) = owners.iter().find(|r| r["epoch"] == epoch) {
            row["current_replay"] = owner.clone();
            row["no_live_producer_claimed"] = json!(false);
            row["state"] = json!("replay");
            row["current_repair_owner"] = Value::Null;
        } else if epoch == 170 {
            row["historical_retry6_replay"] = row["current_replay"].clone();
            row["current_replay"] = Value::Null;
            row["state"] = json!("repair");
            row["no_live_producer_claimed"] = json!(true);
            row["repair_open"] = json!(true);
            row["current_repair_owner"] = json!("/root");
            row["terminal_transition"] = transition.clone();
            row["next_action"] = e.recovery["next_lane_recovery"]["next_action"].clone();
        }
    }
    for k in [
        "new_resource_observations",
        "fresh_campaign_unit_census_claimed",
        "replay_launch_authorized",
        "producer_mutations",
        "remote_mutations",
        "r2_mutations",
        "resource_limits_changed",
        "archive_publication_authorized",
    ] {
        fleet[k] = json!(false);
    }
    fleet["resource_credit_bytes"] = json!(0);
    fleet["all_reservation_ending_bytes"] = json!(0);
    fleet["review_is_not_a_native_Frame_or_admission_receipt"] = json!(true);
    fleet["cycle_reconciliation_scope"] = json!(
        "Read-only reconciliation of linked observations, nineteen authenticated status receipts and the genuine retry6 stop. Prior complete native census and all commitments are retained as historical evidence; stage must capture a fresh native census and admission."
    );
    Ok(fleet)
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    ensure!(
        unsafe { libc::geteuid() } == 0
            && (args.len() == 6 || (args.len() == 7 && args[6] == "--check"))
            && args[2] == "--plan-sha256"
            && args[4] == "--self-sha256",
        "root; PLAN --plan-sha256 SHA --self-sha256 SHA [--check]"
    );
    ensure!(
        hex(&args[5]) && sha(&fs::read("/proc/self/exe")?) == args[5],
        "running image differs"
    );
    let p: Plan = serde_json::from_value(read_bound(&Bound::exact(&args[1], &args[3]))?)?;
    let evidence = read_evidence(&p)?;
    let fleet = reconcile(
        &p,
        &evidence,
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    )?;
    if args.len() == 7 {
        println!(
            "{}",
            json!({"check_passed":true,"output_written":false,"replay_launch_authorized":false})
        );
        return Ok(());
    }
    let dir = &p.output_directory;
    let m = fs::symlink_metadata(dir)?;
    ensure!(
        dir.starts_with(HOME)
            && dir != Path::new(HOME)
            && dir.canonicalize()? == *dir
            && m.is_dir()
            && m.uid() == 0
            && m.mode() & 0o7777 == 0o700,
        "private canonical output directory required"
    );
    let path = dir.join("ROOT_COMPLETE_OPERATIONAL_FLEET.json");
    let mut bytes = serde_json::to_vec_pretty(&fleet)?;
    bytes.push(b'\n');
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)?;
    f.write_all(&bytes)?;
    f.sync_all()?;
    File::open(dir)?.sync_all()?;
    println!("{}", json!({"path":path,"sha256":sha(&bytes)}));
    Ok(())
}

#[cfg(test)]
mod tests;
