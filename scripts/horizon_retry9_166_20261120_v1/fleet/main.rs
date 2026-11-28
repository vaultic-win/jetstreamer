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
const HOME: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch166-retry9-recovery-20261120-v1";
const PREVIOUS: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch170-retry7-recovery-20261120-v1/fleet0115-v1/ROOT_COMPLETE_OPERATIONAL_FLEET.json";
const PREVIOUS_SHA: &str = "0542829040ba09f4876adce3cc4a6e36932bd2ed9e208ac8c66f44dd4475be2d";
const DIR: &str = "/var/lib/jetstreamer/horizon_runtime_data/root0145-zero-recovery-20261120-v1";
const FIRST_SHA: &str = "e29f3b71e0214cd69611cabf28a3c095ff5aeb69e228ecd8ae5bc3ba8e36cd9b";
const OBS0215: &str = "31dc553c5dda6c9da5059c5feae275403c3f57c4312d54e2dab917eaa8ec9217";

const STOPPED: [(u64, u64, &str); 3] = [
    (166, 8, "4f09db5f45074244a45b06aeef932d1d"),
    (167, 7, "a680103e76f546faaf469aa80c35fa3b"),
    (170, 6, "ebd212d2045145259449d1d5c3d65353"),
];

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
    recovery_events: Vec<Bound>,
    #[serde(default)]
    later_cycles: Vec<Cycle>,
    output_directory: PathBuf,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Cycle {
    observer: Bound,
    authenticated_status_audit: Bound,
    sole_next_observer: Bound,
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
fn binding(v: &Value) -> Result<Bound> {
    Ok(serde_json::from_value(v.clone())?)
}

fn booking(name: &str, digest: &str) -> Bound {
    Bound::exact(&format!("{DIR}/{name}.json"), digest)
}

fn unit(epoch: u64, generation: u64) -> String {
    format!("horizon-qualify-{epoch}-replacement-local3retry{generation}-20261110-v1.service")
}

fn zero_sample(s: &Value) -> Result<()> {
    ensure!(
        s["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && s["replays"] == json!([])
            && s["cadence"]["routine_minimum_interval_enforced"] == true
            && s["cadence"]["minimum_interval_seconds"] == 1800,
        "expected a zero-replay routine observation"
    );
    for key in [
        "producer_or_controller_signals_sent",
        "r2_mutations",
        "remote_mutations",
        "service_state_changed",
    ] {
        ensure!(s["mutation"][key] == false, "sample mutated {key}");
    }
    for (epoch, generation, iid) in STOPPED {
        let row = one(&s["diagnostic_replays"], "range", &json!(epoch.to_string()))?;
        ensure!(
            row["producer_unit"] == unit(epoch, generation)
                && row["expected_producer_invocation_id"] == iid
                && row["ordinary_replay_claim"] == false
                && row["replay_launch_authorized"] == false,
            "stopped epoch {epoch} has a different identity or an ordinary claim"
        );
    }
    Ok(())
}

fn linked(prior_binding: &Bound, prior: &Value, s: &Value) -> Result<()> {
    let cadence = &s["cadence"];
    ensure!(
        cadence["previous_sample"] == json!(prior_binding.path)
            && cadence["previous_sample_sha256"] == prior_binding.sha256
            && cadence["previous_sample_recorded_at_utc"] == prior["recorded_at_utc"]
            && s["recorded_at_utc"].as_str().context("sample time")?
                > prior["completed_at_utc"]
                    .as_str()
                    .context("prior completed time")?,
        "broken observation ancestry"
    );
    Ok(())
}

fn terminal(raw: &str, iid: &str) -> Result<()> {
    let mut fields = BTreeMap::new();
    for line in raw.lines() {
        let (key, value) = line.split_once('=').context("terminal native key")?;
        ensure!(fields.insert(key, value).is_none(), "duplicate native key");
    }
    let val = |k| fields.get(k).copied();
    let closed_id = match (val("LoadState"), val("InvocationID")) {
        (Some("not-found"), Some("")) => true,
        (Some("loaded"), Some(value)) => value == iid,
        _ => false,
    };
    ensure!(
        closed_id
            && val("MainPID") == Some("0")
            && val("NRestarts") == Some("0")
            && val("ActiveState") == Some("inactive")
            && val("SubState") == Some("dead")
            && val("Job") == Some(""),
        "terminal owner is running, queued or has a foreign invocation"
    );
    Ok(())
}

fn status_receipts(event: &Value, s: &Value, old: &Value) -> Result<(Value, BTreeMap<u64, Value>)> {
    let audit = load(&event["authenticated_status_audit"])?;
    ensure!(
        audit["schema"] == "horizon-status-full-range-audit-v1"
            && audit["owner"] == "/root"
            && audit["primary_thread"] == THREAD
            && audit["observer"] == event["observer"]
            && audit["archive_or_sidecar_mutations"] == false
            && audit["authenticated_readback"] == true
            && audit["authenticated_status_count"] == 19
            && audit["all_nineteen_existing_statuses_authenticated"] == true
            && audit["active_producer_count"] == 0
            && audit["replay_lanes"] == 0
            && audit["active_bootstraps"] == 0
            && audit["status_epochs"] == json!(STATUS_EPOCHS)
            && audit["inventory"] == old["authenticated_inventory"]
            && audit["sampled_at_utc"] == s["recorded_at_utc"]
            && audit["receipts"].as_object().is_some_and(|r| r.len() == 19),
        "missing zero-owner authenticated current statuses"
    );
    let mut receipts = BTreeMap::new();
    for epoch in STATUS_EPOCHS {
        let r = load(&audit["receipts"][epoch.to_string()])?;
        ensure!(
            r["epoch"] == epoch
                && r["after_status"]["epoch"] == epoch
                && r["authenticated_readback"] == true
                && r["sampled_at_utc"] == s["recorded_at_utc"]
                && r["observer"] == event["observer"]
                && r["current_replay_lanes"] == 0
                && r["active_bootstraps"] == 0,
            "wrong status for {epoch}"
        );
        if let Some((_, _, iid)) = STOPPED.iter().find(|(e, _, _)| *e == epoch) {
            ensure!(
                r["current_repair_owner"] == "/root"
                    && r["after_status"]["phase"] != "replay"
                    && r["terminal_status_events"] == event["terminal_status_events"],
                "stopped epoch claims replay or lost its event"
            );
            terminal(
                r["terminal_systemd"][epoch.to_string()]
                    .as_str()
                    .context("terminal native observation")?,
                iid,
            )?;
        }
        receipts.insert(epoch, r);
    }
    Ok((audit, receipts))
}

fn stop_transition(
    event: &Value,
    old: &Value,
    epoch: u64,
    generation: u64,
    iid: &str,
) -> Result<Value> {
    let b = &event["terminal_status_events"][epoch.to_string()];
    let r = load(b)?;
    let stop = load(&r["guard_stop_completion"])?;
    let intent = load(&r["guard_stop_intent"])?;
    let terminal = &stop["terminal"];
    ensure!(
        r["epoch"] == epoch
            && r["authenticated_readback"] == true
            && r["terminal_producer_invocation_id"] == iid
            && stop["producer_invocation_id"] == iid
            && terminal["invocation_id"] == iid
            && terminal["active"] == "inactive"
            && terminal["sub"] == "dead"
            && terminal["pid"] == 0
            && terminal["restarts"] == 0
            && stop["intent"] == r["guard_stop_intent"]["path"]
            && stop["scratch_deleted"] == false
            && intent["producer_invocation_id"] == iid
            && intent["reason"] == "DATA-fulfillment-observation-failed",
        "stop event differs from its closed generation"
    );
    if epoch == 170 {
        ensure!(
            old["terminal170_transition"]["producer_invocation_id"] == iid,
            "lost 170 history"
        );
        return Ok(old["terminal170_transition"].clone());
    }
    let owner = one(&old["actual_executing_replays"], "epoch", &json!(epoch))?;
    let admit = load(&owner["admission"])?;
    let protect = load(&owner["guard_protection"])?;
    ensure!(
        owner["unit"]["Id"] == unit(epoch, generation)
            && owner["unit"]["InvocationID"] == iid
            && admit["producer_invocation_id"] == iid
            && admit["fresh_admission_passed"] == true
            && admit["all_prior_promises_retained"] == true
            && protect["admission"] == owner["admission"],
        "previous owner mismatch"
    );
    Ok(
        json!({"epoch":epoch,"attempt":format!("local3retry{generation}"),"producer_invocation_id":iid,
        "producer_unit":unit(epoch,generation),"historical_live_owner":owner,"terminal":terminal,
        "terminal_status_event":b,"stop_completion":r["guard_stop_completion"],"stop_intent":r["guard_stop_intent"],
        "scratch_deleted":false,"resource_credit_bytes":0,"resource_promise_ending_bytes":0}),
    )
}

fn bookings(event: &Value) -> Result<Value> {
    let auxiliary = [
        (
            "BUILD_ADMISSION",
            "9eab68db85a3e2899a631fe1a7eda009ef0936f471ac44ef585e081d3977f8f9",
        ),
        (
            "NATIVE_CHECK_ADMISSION",
            "bfba12e2e22520a904203598612d7b04a1cac1973801b582819fdabec69e2bcc",
        ),
        (
            "HOLDING_INSPECTION_ADMISSION",
            "32816582534de00d55412a647a6a1e8a71de29cc189f74e53da3286d06dd11d9",
        ),
        (
            "PARK_SERIAL_ADMISSION",
            "6a9ec7435903516e7c0f8a4531fd6d6de184e0f16eccb40d01cc32c0cd6918a1",
        ),
        (
            "RETRY9_BUILD_ADMISSION",
            "613f3dfdb39b97c43de2647fd6826443ebf59d1d42e0f9967c1f1a35052d04f6",
        ),
        (
            "RETRY9_BUILD_COMMAND_CORRECTION",
            "0572f8c3ed813572d471fa12d51b00f2bf1ed402c212ccce1a5444df31dab41b",
        ),
        (
            "RETRY7_PARK_START",
            "7b877184cc0437b53cfdf19aedf92ba715de382c7348d8d4d74da4c63d8f42cd",
        ),
        (
            "RETRY9_NATIVE_TEST_ADMISSION",
            "02a2f8bc022de893d00faa9c20ca1e94fbb150985b83354388d97d43929ebb3e",
        ),
    ];
    let mut proofs = json!({});
    let mut values = json!({});
    for (name, hash) in auxiliary {
        let b = booking(name, hash);
        values[name] = read_bound(&b)?;
        proofs[name] = json!(b);
    }
    let build = &values["BUILD_ADMISSION"];
    let holding = &values["PARK_SERIAL_ADMISSION"];
    let retry = &values["RETRY9_BUILD_ADMISSION"];
    let start = &values["RETRY7_PARK_START"];
    ensure!(
        event["active_serial_holding_authority"] == proofs["PARK_SERIAL_ADMISSION"]
            && event["holding_retry7_start"] == proofs["RETRY7_PARK_START"]
            && event["additional_retained_build_allocation"] == build["base_build"]
            && retry["holding_booking"] == proofs["PARK_SERIAL_ADMISSION"]["sha256"]
            && retry["root_event"] == FIRST_SHA
            && holding["earlier_fleet"]["sha256"] == FIRST_SHA
            && start["booking"] == proofs["PARK_SERIAL_ADMISSION"]
            && start["local_credit_bytes"] == 0
            && values["RETRY9_NATIVE_TEST_ADMISSION"]["prior_build_admission"]
                == proofs["RETRY9_BUILD_ADMISSION"]["sha256"]
            && retry["build_memory"] == build["memory_max"]
            && retry["concurrent_holding_memory"] == holding["additional_memory_bytes"]
            && holding["resource_credit_bytes"] == 0
            && holding["second_attempt_requires_first_terminal"] == true,
        "serial holding/build commitments lost"
    );
    Ok(
        json!({"receipt_bindings":proofs,"build_memory_bytes":build["memory_max"],
        "build_cpu_quota_micros":number(build,"cpu_percent")?.checked_mul(10_000).context("build CPU overflow")?,
        "build_fixed_image_bytes":build["fixed_image_bytes"],"build_outside_allowance_bytes":build["outside_allowance_bytes"],
        "holding_memory_bytes":holding["additional_memory_bytes"],"holding_cpu_quota_micros":holding["additional_cpu_quota_micros"],
        "holding_restore_overlap_bytes":holding["restore_overlap_bytes"],"holding_staging_bytes":holding["additional_DATA_staging_bytes"],
        "holding_serial":true,"build_and_native_qualification_serial":true,"holding_and_build_may_overlap":true,
        "resource_credit_bytes":0,"reservation_ending_bytes":0}),
    )
}

fn check_next(view: &Value, sample: &Value) -> Result<()> {
    let next = load(&view["next_observer"])?;
    ensure!(
        next["replays"] == json!([])
            && next["previous_sample"] == view["observer"]["path"]
            && next["minimum_interval_seconds"] == 1800
            && next["not_before_utc"]
                == sample["cadence"]["next_routine_observation_not_before_utc"],
        "next observer does not follow this zero sample"
    );
    for (ep, generation, iid) in STOPPED {
        let row = one(&next["diagnostic_replays"], "range", &json!(ep.to_string()))?;
        ensure!(
            row["producer_unit"] == unit(ep, generation)
                && row["expected_producer_invocation_id"] == iid,
            "next diagnostic observer no longer follows closed owner {ep}"
        );
    }
    Ok(())
}

fn reconcile(p: &Plan, at: u64) -> Result<Value> {
    ensure!(
        p.schema == "horizon-zero-replay-fleet-reconcile-plan-v1"
            && p.owner == "/root"
            && p.primary_thread == THREAD
            && p.previous_fleet == Bound::exact(PREVIOUS, PREVIOUS_SHA)
            && p.recovery_events.len() >= 2
            && p.recovery_events[0] == booking("ROOT_OPERATIONAL_RECOVERY_EVENT", FIRST_SHA),
        "wrong zero-replay origin"
    );
    let old = read_bound(&p.previous_fleet)?;
    ensure!(
        old["schema"] == "horizon-Root-complete-fleet-operational-review-v1"
            && old["owner"] == "/root"
            && old["primary_thread"] == THREAD
            && old["active_producer_count"] == 2
            && old["live_replay_count"] == 2
            && old["actual_executing_replays"]
                .as_array()
                .is_some_and(|a| a.len() == 2)
            && old["actual_active_bootstraps"] == json!([])
            && old["epochs"].as_array().is_some_and(
                |a| a.len() == 100 && a.iter().enumerate().all(|(i, r)| r["epoch"] == 101 + i)
            )
            && old["complete_DATA_bytes"] == 6_794_761_027_378u64
            && old["complete_projected_memory_bytes"] == 761_131_708_416u64
            && old["retained_retry6_166_DATA_bytes"] == 309_237_645_312u64
            && old["all_existing_memory_DATA_OS_native_transport_promises_retained"] == true
            && old["continuing_audit_obligation"]["per_epoch_capacity_reserves_exact_archive_bytes"]
                == true,
        "invalid 01:15 full fleet"
    );
    load(&old["authenticated_inventory"])?;
    let mut previous_sample = binding(&old["observer"])?;
    let mut sample = read_bound(&previous_sample)?;
    let mut event = Value::Null;
    let mut anchor = Value::Null;
    for (i, b) in p.recovery_events.iter().enumerate() {
        let next = read_bound(b)?;
        ensure!(
            next["schema"] == "horizon-root-recovery-fleet-event-v1"
                && next["owner"] == "/root"
                && next["primary_thread"] == THREAD
                && next["previous_complete_fleet"] == json!(p.previous_fleet)
                && next["active_repair_epochs"] == json!([166, 167, 170])
                && next["active_replay_epochs"] == json!([])
                && next["live_replay_count"] == 0
                && next["resource_credit_bytes"] == 0
                && next["all_reservation_ending_bytes"] == 0
                && next["replay_launch_authorized"] == false
                && next["retained_replay_DATA_bytes"] == old["complete_DATA_bytes"]
                && next["retained_fleet_projected_memory_bytes"]
                    == old["complete_projected_memory_bytes"]
                && next["additional_retained_build_allocation"]
                    == old["additional_retained_build_allocation"]
                && next["all_existing_memory_DATA_OS_native_transport_promises_retained"] == true,
            "zero recovery overlay changed obligations"
        );
        if i == 0 {
            anchor = next.clone();
            load(&next["successor_roots"])?;
            load(&next["terminal_timer_closure"])?;
            load(&next["additional_retained_build_allocation"])?;
        } else {
            ensure!(
                next["previous_recovery_event"] == json!(p.recovery_events[i - 1])
                    && next["terminal_status_events"] == anchor["terminal_status_events"]
                    && next["successor_roots"] == anchor["successor_roots"]
                    && next["terminal_timer_closure"] == anchor["terminal_timer_closure"],
                "broken recovery ancestry"
            );
        }
        let current = binding(&next["observer"])?;
        if i == 1 {
            ensure!(
                current.sha256 == OBS0215,
                "first post-stop cycle must cover the actual 02:15 observer"
            );
        }
        let after = read_bound(&current)?;
        zero_sample(&after)?;
        linked(&previous_sample, &sample, &after)?;
        ensure!(
            next["sampled_at_utc"] == after["recorded_at_utc"],
            "overlay timestamp differs"
        );
        check_next(&next, &after)?;
        previous_sample = current;
        sample = after;
        event = next;
    }
    let fixed_bookings = bookings(&event)?;
    let mut view = event.clone();
    for (i, cycle) in p.later_cycles.iter().enumerate() {
        let later = read_bound(&cycle.observer)?;
        zero_sample(&later)?;
        linked(&previous_sample, &sample, &later)?;
        view["observer"] = json!(cycle.observer);
        view["authenticated_status_audit"] = json!(cycle.authenticated_status_audit);
        view["next_observer"] = json!(cycle.sole_next_observer);
        check_next(&view, &later)?;
        if i + 1 < p.later_cycles.len() {
            status_receipts(&view, &later, &old)?;
        }
        previous_sample = cycle.observer.clone();
        sample = later;
    }
    let (status, receipts) = status_receipts(&view, &sample, &old)?;
    let mut fleet = old.clone();
    let mut transitions = BTreeMap::new();
    for (ep, generation, iid) in STOPPED {
        let transition = stop_transition(&anchor, &old, ep, generation, iid)?;
        if ep != 170 {
            fleet["terminal_producers"]
                .as_array_mut()
                .context("terminal history")?
                .push(transition.clone());
        }
        transitions.insert(ep, transition);
    }
    let observer = &view["observer"];
    for row in fleet["epochs"].as_array_mut().context("inventory")? {
        let ep = number(row, "epoch")?;
        row["current_coordinated_observer"] = observer.clone();
        if let Some(receipt) = receipts.get(&ep) {
            let status_binding = &status["receipts"][ep.to_string()];
            row["status_publication"] = status_binding.clone();
            row["current_authenticated_status_receipt"] = status_binding.clone();
            row["status"] = receipt["after_status"].clone();
            row["current_status"] = receipt["after_status"].clone();
        }
        if let Some(transition) = transitions.get(&ep) {
            if ep != 170 {
                row["historical_replay_before_zero166167"] = row["current_replay"].take();
            }
            row["current_replay"] = Value::Null;
            row["terminal_transition"] = transition.clone();
            row["state"] = json!("repair");
            row["no_live_producer_claimed"] = json!(true);
            row["repair_open"] = json!(true);
            row["current_repair_owner"] = json!("/root");
            row["next_action"] = event["next_lane_recovery"].clone();
        }
    }
    for key in ["actual_executing_replays", "actual_active_bootstraps"] {
        fleet[key] = json!([]);
    }
    for key in [
        "active_producer_count",
        "live_replay_count",
        "useful_replay_count",
        "bootstrap_count",
        "guarded_bootstrap_owner_count",
    ] {
        fleet[key] = json!(0);
    }
    fleet["observed_01_15_holding_transfers"] = old["actual_active_holding_transfers"].clone();
    let parked = event["recorded_running_units"]
        .as_array()
        .context("observed running units")?;
    let mut observed_transfers = Vec::new();
    for row in parked {
        let text = row.as_str().context("native unit row")?;
        let name = text
            .split_whitespace()
            .next()
            .context("empty native unit row")?;
        if [
            "horizon-closed166-retry7-park-20261120-v1.service",
            "horizon-closed166-retry8-park-20261120-v1.service",
        ]
        .contains(&name)
        {
            observed_transfers.push(json!({"unit": name, "native_row": text,
                "observed_in": p.recovery_events.last(), "recorded_unix_seconds":event["recorded_unix_seconds"]}));
        }
    }
    fleet["actual_active_holding_transfers"] = json!(observed_transfers);
    // This receipt records a genuine start. Later samples observe replay workers only.
    // Keep the booking until separately reconciled terminal evidence is available.
    fleet["last_recorded_serial_holding_start"] = event["holding_retry7_start"].clone();
    fleet["current_native_holding_census_claimed"] = json!(false);
    fleet["retry9_auxiliary_commitments"] = fixed_bookings;
    fleet["active_serial_holding_authority"] = event["active_serial_holding_authority"].clone();
    fleet["retry9_recovery_chain"] = json!(p.recovery_events);
    fleet["subsequent_zero_cycles"] = json!(p.later_cycles);
    fleet["retained_terminal_recovery_commitments"] = event.clone();
    fleet["terminal_recovery_overlay"] =
        json!(p.recovery_events.last().context("recovery overlay")?);
    fleet["previous_Root_operational_review"] = json!(p.previous_fleet);
    fleet["next_lane_recovery"] = event["next_lane_recovery"].clone();
    fleet["additional_retained_build_allocation"] =
        event["additional_retained_build_allocation"].clone();
    fleet["build_allocation_rule"] = event["build_allocation_rule"].clone();
    fleet["audit_progress_at_recovery_overlay"] = event["audit_progress"].clone();
    fleet["audit_summary_at_recovery_overlay"] = event["audit_summary"].clone();
    fleet["audit_progress_capture_unix_at_recovery_overlay"] =
        event["latest_audit_progress_capture_unix"].clone();
    fleet["observer"] = observer.clone();
    fleet["authenticated_status_audit"] = view["authenticated_status_audit"].clone();
    fleet["sole_next_observer"] = view["next_observer"].clone();
    fleet["sampled_at_utc"] = sample["recorded_at_utc"].clone();
    fleet["recorded_unix_seconds"] = json!(at);
    let free = number(&sample["filesystem"], "conservative_available_bytes")?;
    fleet["same_sample_conservative_free_DATA_bytes"] = json!(free);
    fleet["historical_complete_cycle_conservative_available_DATA_bytes"] =
        old["complete_cycle_conservative_available_DATA_bytes"].clone();
    fleet["complete_cycle_conservative_available_DATA_bytes"] = json!(free.min(number(
        &old,
        "complete_cycle_conservative_available_DATA_bytes"
    )?));
    fleet["retained_native_census_is_historical"] = json!(true);
    fleet["cycle_reconciliation_scope"] = json!(
        "Two stopped generations, zero replay and bootstrap owners, linked observations, serial holding and build commitments, and 19 authenticated statuses. A fresh native census and capacity checks are required at admission."
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
    let fleet = reconcile(&p, SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;
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
