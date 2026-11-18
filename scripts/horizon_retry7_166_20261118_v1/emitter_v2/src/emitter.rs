#![recursion_limit = "256"]
//! Metadata-only continuation for the already qualified v14 replacement recipe.
//! No process creation, native sampling, network access, deletion, or launch authority.
//! Root must qualify this source and normally seal it before production execution.
use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Component, Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
const IMAGE: &str = "/usr/local/lib/jetstreamer/horizon-retry7-166-emitter-20261118-v1/emitter";
const THREAD: &str = "01a1af2a-9ce8-76a2-8939-b2112bd38f53";
const DATA: u64 = 6_229_838_610_226;
const MEMORY: u64 = 759_789_531_136;
const FLOOR: u64 = 6_264_131_239_730;
const CURRENT_DATA: u64 = 6_240_576_028_466;
const CURRENT_MEMORY: u64 = 761_131_708_416;
const CURRENT_FLOOR: u64 = 6_274_868_657_970;
const CAP: u64 = 309_237_645_312;
const EPOCHS: [u64; 4] = [166, 167, 169, 170];
const AUTHORITY: &str = "/usr/local/lib/jetstreamer/horizon-original154-future-data-current-authority-20261110-v1/authority.json";
const AUTHORITY_SHA: &str = "2f88b7f91cc6df70804cd96027efbd0e18cb6452a48e76d813673b556d727caa";
fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn sha(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
fn number(v: &Value, k: &str) -> Result<u64> {
    v[k].as_u64()
        .with_context(|| format!("missing integer {k}"))
}
fn text<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str().with_context(|| format!("missing string {k}"))
}
fn hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn identity(m: &fs::Metadata) -> Value {
    json!({"device":m.dev(),"inode":m.ino(),"length":m.len(),"mtime":m.mtime(),"mtime_nsec":m.mtime_nsec(),"ctime":m.ctime(),"ctime_nsec":m.ctime_nsec(),"nlink":m.nlink(),"uid":m.uid(),"gid":m.gid(),"mode":m.mode()})
}

fn safe_ancestors(p: &Path) -> Result<()> {
    ensure!(p.is_absolute(), "absolute path required");
    let mut q = PathBuf::from("/");
    for c in p.components() {
        match c {
            Component::RootDir => (),
            Component::Normal(n) => {
                q.push(n);
                let m = fs::symlink_metadata(&q)?;
                ensure!(
                    !m.file_type().is_symlink(),
                    "symlink ancestor {}",
                    q.display()
                );
            }
            _ => anyhow::bail!("unsafe path component"),
        }
    }
    Ok(())
}
fn raw(p: &Path) -> Result<Vec<u8>> {
    safe_ancestors(p)?;
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(p)?;
    let a = f.metadata()?;
    ensure!(
        a.is_file()
            && a.nlink() == 1
            && a.uid() == 0
            && a.mode() & 0o022 == 0
            && a.len() <= 32 << 20,
        "unsafe/big Root evidence {}",
        p.display()
    );
    let mut b = Vec::new();
    f.read_to_end(&mut b)?;
    let z = f.metadata()?;
    let at = fs::symlink_metadata(p)?;
    ensure!(
        identity(&a) == identity(&z) && identity(&a) == identity(&at) && b.len() as u64 == a.len(),
        "evidence changed {}",
        p.display()
    );
    Ok(b)
}
fn bound(v: &Value) -> Result<Value> {
    let p = Path::new(text(v, "path")?);
    let h = text(v, "sha256")?;
    ensure!(hex(h), "bound digest spelling");
    let b = raw(p)?;
    ensure!(sha(&b) == h, "bound digest changed {}", p.display());
    Ok(serde_json::from_slice(&b)?)
}
fn write(root: &Path, name: &str, v: &Value) -> Result<Value> {
    ensure!(
        !name.is_empty() && !name.contains('/') && name != "." && name != "..",
        "output leaf"
    );
    safe_ancestors(root)?;
    let m = fs::symlink_metadata(root)?;
    ensure!(
        m.is_dir() && m.uid() == 0 && m.mode() & 0o7777 == 0o700,
        "private Root output"
    );
    let p = root.join(name);
    let mut b = serde_json::to_vec_pretty(v)?;
    b.push(b'\n');
    ensure!(b.len() <= 8 << 20, "output exceeds charged8MiB bound");
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .mode(0o600)
        .open(&p)?;
    f.write_all(&b)?;
    f.sync_all()?;
    File::open(root)?.sync_all()?;
    Ok(json!({"path":p,"sha256":sha(&b)}))
}
fn owner(v: &Value) -> Result<()> {
    ensure!(
        v["owner"] == "/root" && v["primary_thread"] == THREAD,
        "foreign owner/thread"
    );
    Ok(())
}
fn age(at: u64, t: u64, max: u64) -> Result<()> {
    ensure!(
        t <= at && at - t <= max,
        "stale/future evidence: at{at} evidence{t} max{max}"
    );
    Ok(())
}
fn utc(s: &str) -> Result<u64> {
    ensure!(
        s.is_ascii()
            && s.len() == 20
            && &s[4..5] == "-"
            && &s[7..8] == "-"
            && &s[10..11] == "T"
            && &s[13..14] == ":"
            && &s[16..17] == ":"
            && &s[19..20] == "Z",
        "UTC format"
    );
    let y = s[0..4].parse::<i64>()?;
    let m = s[5..7].parse::<i64>()?;
    let d = s[8..10].parse::<i64>()?;
    let hh = s[11..13].parse::<u64>()?;
    let mm = s[14..16].parse::<u64>()?;
    let ss = s[17..19].parse::<u64>()?;
    ensure!(
        (2026..=2099).contains(&y)
            && (1..=12).contains(&m)
            && (1..=31).contains(&d)
            && hh < 24
            && mm < 60
            && ss < 60,
        "UTC range"
    );
    let yy = y - if m <= 2 { 1 } else { 0 };
    let era = yy / 400;
    let yoe = yy - era * 400;
    let mp = m + if m > 2 { -3 } else { 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    Ok(u64::try_from(days)? * 86400 + hh * 3600 + mm * 60 + ss)
}
fn epochs(v: &Value) -> Result<()> {
    let r = v["epochs"].as_array().context("complete epochs")?;
    ensure!(
        r.len() == 100 && r.iter().enumerate().all(|(i, x)| x["epoch"] == 101 + i),
        "incomplete/misordered fleet"
    );
    Ok(())
}
fn closed(v: &Value) -> Result<()> {
    ensure!(
        matches!(v["ActiveState"].as_str(), Some("inactive" | "failed"))
            && v["Job"] == ""
            && v["MainPID"] == "0"
            && v["ControlPID"] == "0",
        "live/queued owner cannot be replaced"
    );
    Ok(())
}
fn template(epoch: u64) -> Result<Value> {
    let s = match epoch {
        166 => include_str!("epoch166.PLAN.SOURCE_TEMPLATE.json"),
        167 => include_str!("epoch167.PLAN.SOURCE_TEMPLATE.json"),
        169 => include_str!("epoch169.PLAN.SOURCE_TEMPLATE.json"),
        170 => include_str!("epoch170.PLAN.SOURCE_TEMPLATE.json"),
        _ => anyhow::bail!("only166167169170"),
    };
    Ok(serde_json::from_str(s)?)
}
fn candidate_template(c: &Value, epoch: u64) -> Result<Value> {
    match c["attempt"].as_str() {
        None | Some("local3retry3") => template(epoch),
        Some("local3retry4") => {
            ensure!(epoch == 166, "retry4 is exact166 only");
            Ok(serde_json::from_str(include_str!(
                "epoch166.RETRY4_PLAN.SOURCE_TEMPLATE.json"
            ))?)
        }
        Some("local3retry5") => {
            ensure!(epoch == 166, "retry5 is exact166 only");
            Ok(serde_json::from_str(include_str!(
                "epoch166.RETRY5_PLAN.SOURCE_TEMPLATE.json"
            ))?)
        }
        Some("local3retry6") => {
            ensure!(epoch == 166, "retry6 is exact166 only");
            Ok(serde_json::from_str(include_str!(
                "epoch166.RETRY6_PLAN.SOURCE_TEMPLATE.json"
            ))?)
        }
        Some("local3retry7") => {
            ensure!(epoch == 166, "retry7 is exact166 only");
            Ok(serde_json::from_str(include_str!(
                "epoch166.RETRY7_PLAN.SOURCE_TEMPLATE.json"
            ))?)
        }
        _ => anyhow::bail!("unqualified attempt"),
    }
}
fn control(path: &str, hash: &str) -> Result<Value> {
    let b = raw(Path::new(path))?;
    ensure!(hex(hash) && sha(&b) == hash, "separately bound control");
    let c: Value = serde_json::from_slice(&b)?;
    owner(&c)?;
    ensure!(
        c["schema"] == "horizon-Root-retry3-preparation-control-v1"
            && c["all_four_retry2_retirements_completed_before_any_retry3_launch"] == true
            && c["Root_current_census_review_complete"] == true
            && c["all_existing_promises_retained"] == true,
        "Root reviewed control required"
    );
    age(now()?, number(&c, "recorded_unix_seconds")?, 120)?;
    let allocation = bound(&c["output_allocation"])?;
    ensure!(
        number(&allocation, "maximum_output_bytes")? >= 16 << 20
            && allocation["all_original_promises_retained"] == true
            && allocation["replay_launch_authorized"] == false,
        "outputs must be charged independently"
    );
    ensure!(
        c["data_fulfillment"].is_object(),
        "actual typed DATA request required"
    );
    selected(&c)?;
    for epoch in EPOCHS {
        cleanup(&c, epoch)?;
    }
    Ok(c)
}
fn selected(c: &Value) -> Result<u64> {
    let e = number(c, "selected_epoch")?;
    ensure!(
        EPOCHS.contains(&e) && c["selected_epochs"] == json!([e]),
        "exactly one candidate per fresh fleet and preparation required"
    );
    candidate_template(c, e)?;
    Ok(e)
}
fn census(c: &Value, epoch: u64) -> Result<Value> {
    let v = bound(&c["current_census"])?;
    ensure!(
        v["owner"] == "/root"
            && v["sole_primary_thread"] == THREAD
            && v["no_new_target_owner_or_queued_launch"] == true,
        "Root current census"
    );
    age(now()?, number(&v, "recorded_unix_seconds")?, 120)?;
    ensure!(
        v["complete_metadata_unit_census"]
            .as_object()
            .is_some_and(|m| !m.is_empty()),
        "complete metadata census required"
    );
    let claims = v["exact_selected_node_and_worker_process_claims"]
        .as_array()
        .context("explicit selected process claims")?;
    ensure!(claims.is_empty(), "target process exists");
    let t = candidate_template(c, epoch)?;
    for u in t["closed_units"]
        .as_array()
        .context("template closed units")?
    {
        closed(&v["explicit_closed_units"][u.as_str().context("unit")?])?;
    }
    Ok(v)
}
fn cleanup(c: &Value, epoch: u64) -> Result<Value> {
    let b = &c["completed_retry2_retirements"][epoch.to_string()];
    ensure!(
        b["path"]
            == format!(
                "/var/lib/jetstreamer/retry2-scratch-native-retirement-20261113-v1/epoch{epoch}/execute-qualified/ROOT_ACTUAL_CONTENTS_RETIREMENT_COMPLETE.json"
            ),
        "exact actual retry2 cleanup wrapper required"
    );
    let summary = bound(b)?;
    ensure!(
        summary["completion"]["path"]
            == format!(
                "/var/lib/jetstreamer/retry2-scratch-retirement-20261113-v1/epoch{epoch}/completion.json"
            )
            && summary["owner"] == "/root"
            && summary["scratch_empty"] == true
            && summary["scratch_root_preserved"] == true
            && summary["all_original_promises_retained"] == true
            && summary["resource_credit_bytes"] == 0
            && summary["no_replay_launch_authority"] == true,
        "actual retry2 cleanup wrapper preservation differs"
    );
    let t = template(epoch)?;
    ensure!(
        c["original_retry2_terminal_evidence"][epoch.to_string()] == t["retry3"]["stopped_event"],
        "exact Root1857 event required"
    );
    ensure!(
        summary["epoch"] == epoch && summary["reservation_ending_bytes"] == 0,
        "cleanup cannot end promise"
    );
    let done = bound(&summary["completion"])?;
    ensure!(
        done["schema"] == "jetstreamer-retry2-scratch-complete-v1"
            && done["basis"]["source"]["original_retry2_stop_event"]
                == c["original_retry2_terminal_evidence"][epoch.to_string()]
            && done["scratch_empty"] == true
            && done["scratch_root_preserved"] == true
            && done["partial_archive_and_all_inputs_preserved"] == true
            && done["resource_promise_ending_authorized"] == false
            && done["resource_credit_bytes"] == 0
            && done["archive_deletion_authorized"] == false
            && done["remote_mutations"] == false
            && done["r2_mutations"] == false
            && done["replay_launch_authorized"] == false,
        "qualified exact completion required"
    );
    Ok(b.clone())
}
fn count_ready_pairs(inv: &Value) -> Result<usize> {
    let entries = inv["entries"].as_array().context("inventory entries")?;
    ensure!(entries.len() == 100, "complete assigned inventory required");
    let mut ready = 0;
    for (i, row) in entries.iter().enumerate() {
        ensure!(row["epoch"] == 101 + i, "inventory order");
        match row["state"].as_str() {
            Some("ready-pair") => ready += 1,
            Some("missing") => {}
            _ => anyhow::bail!("unsupported or anomalous inventory entry state"),
        }
    }
    ensure!(
        inv["ready_pairs"] == ready && inv["missing"] == 100 - ready,
        "inventory totals differ from entries"
    );
    Ok(ready)
}
fn make_fleet(c: &Value, at: u64) -> Result<Value> {
    let event = bound(&c["event_fleet"])?;
    owner(&event)?;
    epochs(&event)?;
    ensure!(
        event["schema"] == "horizon-root-authoritative-campaign-event-ledger-v1"
            && event["all_existing_memory_DATA_OS_native_transport_promises_retained"] == true,
        "not the genuine campaign event"
    );
    let obs = bound(&c["observer"])?;
    ensure!(
        obs["schema"] == "jetstreamer-horizon-live-resource-sample-v2" && obs["replays"].is_array(),
        "actual coordinated sample required"
    );
    age(at, utc(text(&obs, "recorded_at_utc")?)?, 1800)?;
    let inv = bound(&c["inventory"])?;
    let entries = inv["entries"].as_array().context("inventory entries")?;
    ensure!(
        entries.len() == 100 && inv["anomalies"] == 0 && inv["archive_only"] == 0,
        "inventory incomplete/anomalous"
    );
    let ready = count_ready_pairs(&inv)?;
    let status = bound(&c["status_audit_result"])?;
    ensure!(
        status["authenticated_readback"] == true
            && status["all_nineteen_existing_statuses_authenticated"] == true
            && status["observer"] == c["observer"]
            && status["inventory"] == c["inventory"]
            && event["authenticated_event_status_acceptance"] == c["status_audit_result"]
            && event["last_complete_sample"] == c["observer"]
            && event["authenticated_inventory"] == c["inventory"]
            && event["complete_DATA_bytes"] == CURRENT_DATA
            && event["complete_projected_memory_bytes"] == CURRENT_MEMORY,
        "same sample current-total event/status required"
    );
    let statuses = status["receipts"].as_object().context("status receipts")?;
    ensure!(
        statuses.len() == 19,
        "all nineteen status receipts required"
    );
    let authority = bound(&json!({"path":AUTHORITY,"sha256":AUTHORITY_SHA}))?;
    ensure!(
        authority["complete_DATA_bytes"] == DATA
            && authority["complete_projected_memory_bytes"] == MEMORY
            && authority["actual_guard_floor_bytes_unchanged"] == FLOOR,
        "retained authority mismatch"
    );
    let current = census(c, selected(c)?)?;
    let (replays, bootstraps) = live_peers(&event, &current, selected(c)?)?;
    for peer in replays.iter().chain(&bootstraps) {
        peer_baseline(peer)?;
    }
    let mut es = event["epochs"].clone();
    for (epoch, receipt_b) in statuses {
        let e = epoch.parse::<u64>()?;
        ensure!((101..=200).contains(&e), "status outside range");
        let receipt = bound(receipt_b)?;
        ensure!(
            receipt["epoch"] == e && receipt["authenticated_readback"] == true,
            "status receipt not authenticated"
        );
        let row = &mut es[(e - 101) as usize];
        row["status_publication"] = receipt_b.clone();
        row["status"] = receipt["after_status"].clone();
        row["current_coordinated_observer"] = c["observer"].clone();
    }
    let mut terminal = vec![];
    for e in EPOCHS {
        let original = bound(&c["original_retry2_terminal_evidence"][e.to_string()])?;
        ensure!(
            original["epoch"] == e
                && original["all_original_promises_retained"] == true
                && original["resource_credit_bytes"] == 0,
            "original retry2 terminal evidence mismatch"
        );
        closed(&original["actual_native"])?;
        terminal.push(json!({"epoch":e,"original_evidence":c["original_retry2_terminal_evidence"][e.to_string()],"current_completion":cleanup(c,e)?,"retained_history":true,"resource_promise_ending_bytes":0}));
    }
    Ok(
        json!({"schema":"horizon-Root-complete-fleet-operational-review-v1","owner":"/root","primary_thread":THREAD,"recorded_unix_seconds":at,"sampled_at_utc":obs["recorded_at_utc"],"observer":c["observer"],"previous_Root_event_fleet":c["event_fleet"],"authenticated_inventory":c["inventory"],"authenticated_status_audit":c["status_audit_result"],"complete_DATA_authority":{"path":AUTHORITY,"sha256":AUTHORITY_SHA},"complete_DATA_bytes":CURRENT_DATA,"complete_projected_memory_bytes":CURRENT_MEMORY,"normal_pool_bytes":10u64<<30,"same_sample_conservative_free_DATA_bytes":obs["filesystem"]["conservative_available_bytes"],"ready_pairs":ready,"remaining_epochs":100-ready,"actual_executing_replays":replays,"actual_active_bootstraps":bootstraps,"live_replay_count":replays.len(),"useful_replay_count":replays.len(),"active_producer_count":replays.len()+bootstraps.len(),"guarded_bootstrap_owner_count":bootstraps.len(),"proven_replay_count":7,"proven_count_is_historical":true,"last_qualified_memory_selected_target":13,"current_memory_target_is_retained":true,"epochs":es,"metadata_unit_census":current["complete_metadata_unit_census"],"full_current_proc_and_unit_census":c["current_census"],"terminal_producers":terminal,"other_terminal_history_retained_in_event":c["event_fleet"],"authenticated_status_count":19,"all_active_status_reports_authenticated_readback":true,"all_existing_memory_DATA_OS_native_transport_promises_retained":true,"sole_next_observer":c["sole_next_observer"],"current_native_Frame_and_full_reader_acceptance_pending":true,"review_is_not_a_native_Frame_or_admission_receipt":true,"latest_genuinely_accepted_native_fleet":event["latest_genuinely_accepted_native_fleet"],"resource_credit_bytes":0,"holding_bytes_credited":0,"holding_prefix":"node_02/","replay_launch_authorized":false,"producer_mutations":false,"new_resource_observations":false,"remote_mutations":false}),
    )
}
fn measure(c: &Value, root: &Path, epoch: u64, fleet: &Value) -> Result<Value> {
    let mut t = candidate_template(c, epoch)?;
    let cleaned = cleanup(c, epoch)?;
    let _ = census(c, epoch)?;
    let request = json!({"schema":"horizon-standard-local-input-route-request-v1","owner":"/root","primary_thread":THREAD,"epoch":epoch,"recorded_unix_seconds":now()?,"authentication_qualified":false,"network_GCS_probe_performed":false,"local_inputs":t["local_inputs"],"normal_local_cache_seal":t["local_inputs"]["deployment_seal"],"original_sources_preserved":true,"local_Rust_manifest_validation_still_required":true});
    let req = write(
        root,
        &format!("epoch{epoch}-LOCAL_INPUT_REQUEST.json"),
        &request,
    )?;
    t["data_fulfillment"] = c["data_fulfillment"].clone();
    t["resident_memory"] = c["resident_memory"][epoch.to_string()].clone();
    t["fleet"] = fleet.clone();
    t["inventory"] = c["inventory"].clone();
    t["input_proof"] = req;
    t["cleanup_completion"] = cleaned;
    t["retry3"]["stopped_event"] =
        c["original_retry2_terminal_evidence"][epoch.to_string()].clone();
    // Measure-only never reads Review. Keep an explicitly unresolved, non-authorizing field.
    let b = write(root, &format!("epoch{epoch}-MEASURE_PLAN.json"), &t)?;
    Ok(b)
}
fn review(c: &Value, root: &Path, epoch: u64) -> Result<Value> {
    let fleet_b = &c["generated_operational_fleet"];
    let fleet = bound(fleet_b)?;
    owner(&fleet)?;
    epochs(&fleet)?;
    age(now()?, number(&fleet, "recorded_unix_seconds")?, 120)?;
    ensure!(selected(c)? == epoch, "review only selected candidate");
    let event = bound(&c["event_fleet"])?;
    let current = census(c, epoch)?;
    let (replays, bootstraps) = live_peers(&event, &current, epoch)?;
    ensure!(
        fleet["observer"] == c["observer"]
            && fleet["previous_Root_event_fleet"] == c["event_fleet"]
            && fleet["actual_executing_replays"] == json!(replays)
            && fleet["actual_active_bootstraps"] == json!(bootstraps)
            && fleet["active_producer_count"] == replays.len() + bootstraps.len(),
        "fresh current fleet differs/target live"
    );
    let mut p = bound(&c["measure_plans"][epoch.to_string()])?;
    ensure!(
        p["epoch"] == epoch
            && p["attempt"] == candidate_template(c, epoch)?["attempt"]
            && p["retry4"] == candidate_template(c, epoch)?["retry4"]
            && p["retry5"] == candidate_template(c, epoch)?["retry5"]
            && p["fleet"] == *fleet_b,
        "measure plan mismatch"
    );
    p["data_fulfillment"] = c["data_fulfillment"].clone();
    let physical_b = &c["measurements"][epoch.to_string()];
    let physical = bound(physical_b)?;
    ensure!(
        physical["epoch"] == epoch
            && physical["fleet"] == *fleet_b
            && physical["read_only"] == true
            && physical["resource_credit_bytes"] == 0,
        "actual measure receipt mismatch"
    );
    age(now()?, number(&physical, "recorded_unix_seconds")?, 120)?;
    let retained = number(&physical["physical"], "physical_bytes")?;
    let working = CAP
        .checked_sub(retained)
        .context("retained tree exceeds unchanged cap")?;
    ensure!(retained > 0 && working > 0, "retained/working allowance");
    let mut working_set = working_set(&fleet, fleet_b, epoch, retained, now()?)?;
    working_set["lanes"][0]["producer_unit"] = p["producer_unit"].clone();
    p["retry3"]["concurrent_working_set"] = write(
        root,
        &format!("epoch{epoch}-CONCURRENT_WORKING_SET.json"),
        &working_set,
    )?;
    ensure!(
        p["retry3"]["stopped_event"] == c["original_retry2_terminal_evidence"][epoch.to_string()],
        "stopped event changed after measure"
    );
    let local2 = bound(&c["original_retry2_terminal_evidence"][epoch.to_string()])?;
    let slot = json!({"schema":"horizon-standard-replacement-exclusive-slot-mapping-v1","owner":"/root","epoch":epoch,"recorded_unix_seconds":now()?,"physical_ledger":physical_b,"old_original_unit":format!("horizon-qualify-{epoch}-standard-20261109-v1.service"),"same_original_lane_root":format!("/home/sol/.jetstreamer-private/epoch{epoch}-standard-lane-20261109-v1"),"latest_stopped_retry2_claim":local2["original_claim"],"latest_stopped_retry2_evidence":c["original_retry2_terminal_evidence"][epoch.to_string()],"actual_retry2_contents_retirement":cleanup(c,epoch)?,"retained_lane_physical_bytes":retained,"combined_original_lane_cap_bytes":CAP,"old_remaining_future_promise_bytes":working,"proposed_fresh_working_maximum_bytes":working,"new_memory_or_DATA_promise_bytes":0,"all_original_promises_retained":true,"no_completion_capacity_guarantee":true,"guard_root_remains_whole_original_lane":true});
    let slot_b = write(
        root,
        &format!("epoch{epoch}-EXCLUSIVE_SLOT_MAPPING.json"),
        &slot,
    )?;
    let r = json!({"schema":"horizon-standard-replacement-prelaunch-review-v1","owner":"/root","primary_thread":THREAD,"epoch":epoch,"attempt":p["attempt"],"recorded_unix_seconds":now()?,"source_fleet":fleet_b,"source_inventory":c["inventory"],"input_proof":p["input_proof"],"cleanup_completion":p["cleanup_completion"],"complete_authority":{"path":AUTHORITY,"sha256":AUTHORITY_SHA},"full_current_proc_and_unit_census":c["current_census"],"all_original_and_replacement_launchers_in_closed_units":true,"no_target_active_or_queued_claim":true,"old_partial_and_inputs_preserved":true,"all_prior_promises_retained":true,"exclusive_original_slot_replacement":true,"complete_projected_memory_bytes":MEMORY,"complete_data_bytes":DATA,"minimum_initial_available_data_bytes":required_before_fulfillment(&working_set)?,"current_budget":current_budget(),"data_fulfillment":c["data_fulfillment"],"candidate_remaining_growth_bytes":working,"fresh_subtree_overlap_booked_bytes":64u64<<20,"retained_lane_physical_bytes":retained,"existing_original_slot_future_growth_bytes":working,"proposed_fresh_working_maximum_bytes":working,"additional_growth_not_covered_by_existing_promise_bytes":0,"exact_slot_mapping_and_physical_ledger":slot_b,"normal_pool_bytes":10u64<<30,"verifier_pool_bytes":96u64<<30,"native_pool_bytes":16u64<<30,"shared_pool_bytes":64u64<<30,"complete_booked_cpu_quota_micros":number(c,"complete_booked_cpu_quota_micros")?,"resource_credit_bytes":0,"memory_or_data_promise_ending_bytes":0,"ordinary_full_plugin_boundary_gates_retained":true});
    p["review"] = write(root, &format!("epoch{epoch}-PRELAUNCH_REVIEW.json"), &r)?;
    write(root, &format!("epoch{epoch}-PREPARE_PLAN.json"), &p)
}
// Normalize only identities present in the authoritative event; census cannot
// promote a bootstrap into replay. The same event/observer/status ancestry is
// checked by make_fleet before any operational fleet is emitted.
fn live_peers(event: &Value, current: &Value, candidate: u64) -> Result<(Vec<Value>, Vec<Value>)> {
    let replay = event["active_replay_invocations"]
        .as_array()
        .context("explicit replay list")?;
    ensure!(
        event["current_event_live_replay_count"] == replay.len(),
        "replay coverage differs"
    );
    let empty = Vec::new();
    let bootstrap = if event["active_bootstrap_invocations"].is_null()
        && event["current_event_active_bootstrap_count"].is_null()
    {
        &empty
    } else {
        event["active_bootstrap_invocations"]
            .as_array()
            .context("explicit bootstrap list")?
    };
    ensure!(
        (event["current_event_active_bootstrap_count"].is_null() && bootstrap.is_empty())
            || event["current_event_active_bootstrap_count"] == bootstrap.len(),
        "bootstrap coverage differs"
    );
    let mut seen = std::collections::BTreeSet::new();
    let mut result = [Vec::new(), Vec::new()];
    for (kind, list) in [replay, bootstrap].iter().enumerate() {
        for peer in *list {
            let e = number(peer, "epoch")?;
            ensure!(
                EPOCHS.contains(&e) && e != candidate && seen.insert(e),
                "foreign/duplicate/live candidate"
            );
            let expected = peer_unit(e);
            let source_unit = &peer["unit"];
            let id = source_unit["Id"]
                .as_str()
                .or_else(|| source_unit["unit"].as_str())
                .context("event unit")?;
            let iid = source_unit["InvocationID"]
                .as_str()
                .or_else(|| source_unit["invocation_id"].as_str())
                .context("event IID")?;
            ensure!(
                id == expected && iid.len() == 32 && iid.bytes().all(|b| b.is_ascii_hexdigit()),
                "event identity differs"
            );
            let native = &current["complete_metadata_unit_census"][&expected];
            ensure!(
                native["Id"] == expected
                    && native["InvocationID"] == iid
                    && native["ActiveState"] == "active"
                    && native["SubState"] == "running"
                    && native["NRestarts"] == "0"
                    && native["Job"] == ""
                    && text(native, "MainPID")?.parse::<u64>()? > 0,
                "genuine current peer identity differs"
            );
            let mut normalized = peer.clone();
            normalized["unit"] = native.clone();
            result[kind].push(normalized);
        }
    }
    // A missing event row cannot hide another running or queued producer. The
    // retry3 services remain independently closed when their retry4 successors
    // execute.
    for e in EPOCHS {
        let unit = format!("horizon-qualify-{e}-replacement-local3retry3-20261110-v1.service");
        let native = &current["complete_metadata_unit_census"][&unit];
        ensure!(
            native.is_object(),
            "complete four candidate native coverage required"
        );
        if !seen.contains(&e) || peer_unit(e) != unit {
            closed(native)?;
        }
    }
    for e in [166, 167, 170] {
        let unit = peer_unit(e);
        let native = &current["complete_metadata_unit_census"][&unit];
        ensure!(
            native.is_object(),
            "complete retry4 peer native coverage required"
        );
        if !seen.contains(&e) {
            closed(native)?;
        }
    }
    if current["complete_metadata_unit_census"].is_object() {
        for unit in [
            "horizon-qualify-166-replacement-local3retry5-20261110-v1.service",
            "horizon-guard-replacement-166-local3retry5-20261110-v1.service",
            "horizon-guard-replacement-166-local3retry5-20261110-v1.timer",
            "horizon-qualify-166-replacement-local3retry6-20261110-v1.service",
            "horizon-guard-replacement-166-local3retry6-20261110-v1.service",
            "horizon-guard-replacement-166-local3retry6-20261110-v1.timer",
            "horizon-qualify-166-replacement-local3retry7-20261110-v1.service",
            "horizon-guard-replacement-166-local3retry7-20261110-v1.service",
            "horizon-guard-replacement-166-local3retry7-20261110-v1.timer",
        ] {
            if let Some(native) = current["complete_metadata_unit_census"].get(unit) {
                closed(native)?;
            }
        }
    }
    let [replays, bootstraps] = result;
    Ok((replays, bootstraps))
}
fn peer_unit(epoch: u64) -> String {
    let attempt = if [166, 167, 170].contains(&epoch) {
        "local3retry4"
    } else {
        "local3retry3"
    };
    format!("horizon-qualify-{epoch}-replacement-{attempt}-20261110-v1.service")
}
fn peer_baseline(peer: &Value) -> Result<u64> {
    let admission = bound(&peer["admission"])?;
    let protection = bound(&peer["guard_protection"])?;
    let prep = bound(&admission["fresh_native_Rust_preparation"])?;
    let e = number(peer, "epoch")?;
    ensure!(
        admission["epoch"] == e
            && admission["producer_unit"] == peer["unit"]["Id"]
            && admission["producer_invocation_id"] == peer["unit"]["InvocationID"]
            && admission["fresh_admission_passed"] == true
            && protection["epoch"] == e
            && protection["producer_unit"] == peer["unit"]["Id"]
            && protection["producer_invocation_id"] == peer["unit"]["InvocationID"]
            && protection["admission"] == peer["admission"]
            && prep["epoch"] == e
            && prep["attempt"]
                == if [166, 167, 170].contains(&e) {
                    "local3retry4"
                } else {
                    "local3retry3"
                }
            && prep["retry2_retirement"]["new_attempt"] == prep["attempt"],
        "actual current peer admission/protection/preparation required"
    );
    let retained = number(&prep["actual_full_lane_ledger"], "physical_bytes")?;
    ensure!(retained > 0 && retained < CAP, "peer full cap exhausted");
    Ok(retained)
}
fn growth_row(epoch: u64, retained: u64, peer: Option<&Value>) -> Result<Value> {
    ensure!(
        EPOCHS.contains(&epoch) && retained > 0 && retained < CAP,
        "candidate/peer baseline outside full cap"
    );
    let mut row = json!({"epoch":epoch,"producer_unit":peer_unit(epoch),"state":"candidate","retained_lane_physical_bytes":retained,"remaining_growth_bytes":CAP-retained});
    if let Some(peer) = peer {
        ensure!(
            peer["epoch"] == epoch && peer["unit"]["Id"] == row["producer_unit"],
            "growth peer identity differs"
        );
        row["state"] = json!("active");
        row["invocation_id"] = peer["unit"]["InvocationID"].clone();
    }
    Ok(row)
}
fn working_set(
    fleet: &Value,
    fleet_b: &Value,
    epoch: u64,
    retained: u64,
    at: u64,
) -> Result<Value> {
    let mut rows = vec![growth_row(epoch, retained, None)?];
    let mut seen = std::collections::BTreeSet::from([epoch]);
    for key in ["actual_executing_replays", "actual_active_bootstraps"] {
        for peer in fleet[key].as_array().context("complete active peer list")? {
            let e = number(peer, "epoch")?;
            ensure!(seen.insert(e), "candidate live or duplicate peer");
            rows.push(growth_row(e, peer_baseline(peer)?, Some(peer))?);
        }
    }
    Ok(
        json!({"schema":"horizon-retry3-concurrent-working-set-v1","owner":"/root","fleet":fleet_b,"recorded_unix_seconds":at,"immutable_raw_guard_floor_bytes":CURRENT_FLOOR,"retained_promises_released_bytes":0,"forecast_offloads_credited_bytes":0,"unrelated_growth_margin_bytes":10u64<<30,"lanes":rows}),
    )
}
fn required_before_fulfillment(forecast: &Value) -> Result<u64> {
    let mut required = CURRENT_FLOOR
        .checked_add(64u64 << 20)
        .and_then(|n| n.checked_add(10u64 << 30))
        .context("initial requirement overflow")?;
    for row in forecast["lanes"]
        .as_array()
        .context("complete growth rows")?
    {
        required = required
            .checked_add(number(row, "remaining_growth_bytes")?)
            .context("growth overflow")?;
    }
    // Qualified Rust preparer subtracts only its genuine fresh DATA fulfillment.
    Ok(required)
}
fn current_budget() -> Value {
    json!({"historical_memory_bytes":MEMORY,"historical_data_bytes":DATA,
        "additional_memory_bytes":1_342_177_280u64,"additional_data_bytes":10_737_418_240u64,
        "complete_memory_bytes":CURRENT_MEMORY,"complete_data_bytes":CURRENT_DATA,
        "raw_floor_bytes":CURRENT_FLOOR,"promise_ending_bytes":0,"resource_credit_bytes":0})
}
fn run() -> Result<()> {
    let a: Vec<String> = std::env::args().collect();
    ensure!(
        a.len() == 6 || a.len() == 7,
        "usage: local3_prepare (measure-plans|review) CONTROL CONTROL_SHA --self-sha256 SHA [EPOCH]"
    );
    ensure!(unsafe { libc::geteuid() } == 0, "Root required");
    ensure!(
        a[4] == "--self-sha256" && hex(&a[5]),
        "separate self hash required"
    );
    ensure!(
        fs::read_link("/proc/self/exe")? == Path::new(IMAGE)
            && sha(&raw(Path::new(IMAGE))?) == a[5],
        "normally sealed exact self image required"
    );
    let c = control(&a[2], &a[3])?;
    let root = Path::new(text(&c, "output_root")?);
    let result = match a[1].as_str() {
        "measure-plans" => {
            ensure!(a.len() == 6, "measure plans args");
            let fleet = write(
                root,
                "ROOT_COMPLETE_OPERATIONAL_FLEET.json",
                &make_fleet(&c, now()?)?,
            )?;
            let mut plans = serde_json::Map::new();
            let e = selected(&c)?;
            plans.insert(e.to_string(), measure(&c, root, e, &fleet)?);
            json!({"fleet":fleet,"measure_plans":plans,"preparation_authorized":false,"launch_authorized":false,"next":"Normally seal measure plans, precreate fresh sol:horizon0700 subtrees and exact OUT directories, run qualified retry3 --measure-only; bind results in fresh review control."})
        }
        "review" => {
            ensure!(a.len() == 7, "review needs epoch");
            let e = a[6].parse()?;
            ensure!(EPOCHS.contains(&e), "epoch outside exact four");
            json!({"prepare_plan":review(&c,root,e)?,"launch_authorized":false,"next":"Normally seal plan, run qualified retry3 --check-only and --prepare serially within fresh120s review; Root still owns guarded launch."})
        }
        _ => anyhow::bail!("unknown action"),
    };
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("{e:#}");
        std::process::exit(1)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn utc_actual_sample() {
        assert_eq!(utc("2026-11-12T16:15:00Z").unwrap(), 1794500100);
    }
    #[test]
    fn utc_reject_unknown_format() {
        assert!(utc("2026-11-12 16:15:00Z").is_err());
        assert!(utc("2026-13-12T16:15:00Z").is_err());
    }
    #[test]
    fn current_clock_cannot_be_relabelled() {
        assert!(age(2000, 0, 1800).is_err());
        assert!(age(10, 11, 1800).is_err());
        assert!(age(1800, 0, 1800).is_ok());
    }
    #[test]
    fn templates_are_disjoint_and_retain_local2_fences() {
        for e in EPOCHS {
            let t = template(e).unwrap();
            assert_eq!(t["epoch"], e);
            assert_eq!(t["attempt"], "local3retry3");
            assert!(t["resident_memory"].is_object());
            assert!(u32::try_from(e).is_ok());
            let u = t["closed_units"].as_array().unwrap();
            assert!(u.contains(&json!(format!(
                "horizon-qualify-{e}-replacement-local2-20261110-v1.service"
            ))));
            assert!(u.contains(&json!(format!(
                "horizon-guard-replacement-{e}-local2-DATA-20261110-v1.timer"
            ))));
            assert!(u.contains(&t["producer_unit"]));
            assert_eq!(t["replay_launch_authorized"], false);
        }
    }
    #[test]
    fn rejects_foreign_epoch() {
        assert!(template(168).is_err());
    }
    #[test]
    fn queued_or_running_owner_never_closed() {
        let mut v = json!({"ActiveState":"inactive","Job":"","MainPID":"0","ControlPID":"0"});
        assert!(closed(&v).is_ok());
        v["Job"] = json!("18");
        assert!(closed(&v).is_err());
        v["Job"] = json!("");
        v["MainPID"] = json!("42");
        assert!(closed(&v).is_err());
    }
    #[test]
    fn complete_epoch_order_required() {
        let mut v = json!({"epochs":(101..=200).map(|e|json!({"epoch":e})).collect::<Vec<_>>()});
        assert!(epochs(&v).is_ok());
        v["epochs"][4]["epoch"] = json!(166);
        assert!(epochs(&v).is_err());
    }
    #[test]
    fn no_broadened_resource_promises() {
        assert_eq!(FLOOR + (64u64 << 20), 6264198348594);
        assert_eq!(MEMORY + (16u64 << 30), 776969400320);
        assert_eq!(CAP, 288u64 << 30);
    }
    #[test]
    fn only_one_selected_candidate_per_current_fleet() {
        for epoch in EPOCHS {
            assert_eq!(
                selected(&json!({"selected_epoch":epoch,"selected_epochs":[epoch]})).unwrap(),
                epoch
            );
        }
        for selection in [
            json!([]),
            json!([167, 169]),
            json!([167, 169, 170]),
            json!([167, 167]),
            json!([166]),
        ] {
            assert!(selected(&json!({"selected_epoch":167,"selected_epochs":selection})).is_err());
        }
    }
    fn native_fixture(epoch: u64, active: bool) -> Value {
        json!({"Id":peer_unit(epoch),
            "InvocationID":if active {"1234567890abcdef1234567890abcdef"} else {""},
            "ActiveState":if active {"active"} else {"inactive"},"SubState":if active {"running"} else {"dead"},
            "MainPID":if active {"42"} else {"0"},"ControlPID":"0","NRestarts":"0","Job":""})
    }
    fn census_fixture(active: Option<u64>) -> Value {
        let mut rows = serde_json::Map::new();
        for epoch in EPOCHS {
            let v = native_fixture(epoch, active == Some(epoch));
            rows.insert(v["Id"].as_str().unwrap().to_owned(), v);
            let old =
                format!("horizon-qualify-{epoch}-replacement-local3retry3-20261110-v1.service");
            if old != peer_unit(epoch) {
                let mut closed_old = native_fixture(epoch, false);
                closed_old["Id"] = json!(old);
                rows.insert(old, closed_old);
            }
        }
        json!({"complete_metadata_unit_census":rows})
    }
    #[test]
    fn first166_requires_genuine_zero_owner_event_and_census() {
        let event = json!({"active_replay_invocations":[],"current_event_live_replay_count":0});
        let zero = census_fixture(None);
        let (replays, boots) = live_peers(&event, &zero, 166).unwrap();
        assert!(replays.is_empty() && boots.is_empty());
        assert!(live_peers(&event, &census_fixture(Some(169)), 166).is_err());
        let mut queued = zero.clone();
        queued["complete_metadata_unit_census"]
            [native_fixture(170, false)["Id"].as_str().unwrap()]["Job"] = json!("job1");
        assert!(live_peers(&event, &queued, 166).is_err());
    }
    #[test]
    fn actual_bootstrap_normalizes_without_promoting_to_replay_and_rejects_omissions() {
        let peer = json!({"epoch":166,"unit":native_fixture(166,true)});
        let mut event = json!({"active_replay_invocations":[],"current_event_live_replay_count":0,"active_bootstrap_invocations":[peer],"current_event_active_bootstrap_count":1});
        let current = census_fixture(Some(166));
        let (replays, boots) = live_peers(&event, &current, 167).unwrap();
        assert!(replays.is_empty());
        assert_eq!(boots.len(), 1);
        assert!(live_peers(&event, &current, 166).is_err());
        event["active_bootstrap_invocations"] = json!([]);
        assert!(live_peers(&event, &current, 167).is_err());
        event["current_event_active_bootstrap_count"] = json!(0);
        assert!(live_peers(&event, &current, 167).is_err());
    }
    #[test]
    fn full_cap_runway_includes_candidate_and_peer_staging_and_margin() {
        let first = growth_row(167, 100, None).unwrap();
        let peer = json!({"epoch":166,"unit":native_fixture(166,true)});
        let second = growth_row(166, 200, Some(&peer)).unwrap();
        assert_eq!(first["remaining_growth_bytes"], CAP - 100);
        assert_eq!(second["remaining_growth_bytes"], CAP - 200);
        let need = required_before_fulfillment(&json!({"lanes":[first,second]})).unwrap();
        assert_eq!(
            need,
            CURRENT_FLOOR + 2 * CAP - 300 + (64u64 << 20) + (10u64 << 30)
        );
        assert!(growth_row(167, CAP, None).is_err());
        assert!(growth_row(167, 0, None).is_err());
        assert!(growth_row(169, 100, Some(&peer)).is_err());
    }
    #[test]
    fn all_templates_bind_retry2_stop_but_fresh_retry3_working_set() {
        let fixture: Vec<Value> =
            serde_json::from_str(include_str!("retry2-stopped-profiles.json")).unwrap();
        for epoch in EPOCHS {
            let t = template(epoch).unwrap();
            let old = fixture.iter().find(|r| r["epoch"] == epoch).unwrap();
            assert_eq!(t["retry3"]["stopped_event"]["sha256"], old["event_sha"]);
            assert_eq!(
                t["retry3"]["stopped_event"]["path"],
                format!(
                    "/var/lib/jetstreamer/root1857-retry2-stop-evidence-20261113-v1/ORIGINAL_EPOCH{epoch}_RESERVE_STOP_EVIDENCE.json"
                )
            );
            assert_eq!(
                t["fresh_subtree"],
                format!(
                    "/home/sol/.jetstreamer-private/epoch{epoch}-standard-lane-20261109-v1/replacement-local3retry3-20261110-v1"
                )
            );
            assert!(t["retry3"]["concurrent_working_set"]["sha256"]
                .as_str()
                .unwrap()
                .starts_with("REPLACE_"));
            assert_eq!(t["replay_launch_authorized"], false);
        }
    }
    #[test]
    fn actual_authenticated_inventory_counts_ready_pair_state() {
        let inv: Value =
            serde_json::from_str(include_str!("inventory-count-regression.json")).unwrap();
        assert_eq!(count_ready_pairs(&inv).unwrap(), 70);
        let mut stale = inv.clone();
        stale["ready_pairs"] = json!(0);
        assert!(count_ready_pairs(&stale).is_err());
        let mut wrong = inv.clone();
        wrong["entries"][0]["state"] = json!("ready");
        assert!(count_ready_pairs(&wrong).is_err());
        let mut duplicate = inv;
        duplicate["entries"][1]["epoch"] = json!(101);
        assert!(count_ready_pairs(&duplicate).is_err());
    }
}

#[cfg(test)]
mod retry4_tests {
    use super::*;
    #[test]
    fn exact166_retry4_keeps_original_template_and_closes_previous_owner() {
        let c = json!({"attempt":"local3retry4","selected_epoch":166,"selected_epochs":[166]});
        let t = candidate_template(&c, 166).unwrap();
        assert_eq!(t["attempt"], "local3retry4");
        assert_eq!(template(166).unwrap()["attempt"], "local3retry3");
        assert_eq!(
            t["retry4"]["stopped_event"]["sha256"],
            "afc574421f324d5895627709b1cfa8bfa4dbfb724264236eb18879d40b13a544"
        );
        for generation in ["local3retry3", "local3retry4"] {
            assert!(t["closed_units"]
                .as_array()
                .unwrap()
                .contains(&json!(format!(
                    "horizon-qualify-166-replacement-{generation}-20261110-v1.service"
                ))));
        }
    }
    #[test]
    fn foreign_retry4_and_retry5_attempts_reject() {
        for e in [167, 169, 170] {
            assert!(candidate_template(&json!({"attempt":"local3retry4"}), e).is_err());
        }
        for e in [167, 169, 170] {
            assert!(candidate_template(&json!({"attempt":"local3retry5"}), e).is_err());
        }
        assert_eq!(
            candidate_template(&json!({"attempt":"local3retry5"}), 166).unwrap()["attempt"],
            "local3retry5"
        );
        for e in EPOCHS {
            assert_eq!(
                candidate_template(&json!({}), e).unwrap(),
                template(e).unwrap()
            );
        }
    }
    #[test]
    fn retry5_template_retains_exact_lineage_and_current_peer_units() {
        let t = candidate_template(&json!({"attempt":"local3retry5"}), 166).unwrap();
        assert!(t["retry4"].is_null());
        assert_eq!(
            t["retry5"]["retired_retry4"]["sha256"],
            "92dd1eeec86a8289bc7cc23a59e8dac2eb1e0814dd6623ff321095db3363992e"
        );
        assert_eq!(
            t["data_fulfillment"]["runtime"]["path"],
            "/usr/local/lib/jetstreamer/horizon-retry5-166-data-guard-20261117-v1/guard"
        );
        assert_eq!(
            peer_unit(167),
            "horizon-qualify-167-replacement-local3retry4-20261110-v1.service"
        );
        assert_eq!(
            peer_unit(170),
            "horizon-qualify-170-replacement-local3retry4-20261110-v1.service"
        );
        assert_eq!(
            peer_unit(169),
            "horizon-qualify-169-replacement-local3retry3-20261110-v1.service"
        );
    }

    #[test]
    fn retry6_template_is_disjoint_and_binds_failed_retry5() {
        let t = candidate_template(&json!({"attempt":"local3retry6"}), 166).unwrap();
        assert_eq!(t["attempt"], "local3retry6");
        assert_eq!(
            t["retry5"]["failed_retry5"]["sha256"],
            "04b669f00269fa7995e8fb8175fd4a8a226279f224a06bae16600ae8d6927b9e"
        );
        assert_eq!(
            t["data_fulfillment"]["runtime"]["sha256"],
            "f38032a7655503fe39d62a17507d0e8dd30e286491612ea69f32ffbb97943258"
        );
        assert!(t["fresh_subtree"]
            .as_str()
            .unwrap()
            .contains("local3retry6"));
        let closed: std::collections::BTreeSet<&str> = t["closed_units"]
            .as_array()
            .unwrap()
            .iter()
            .map(|unit| unit.as_str().unwrap())
            .collect();
        assert_eq!(closed.len(), t["closed_units"].as_array().unwrap().len());
        assert_eq!(closed.len(), 36);
        assert!(closed.contains(t["producer_unit"].as_str().unwrap()));
        assert!(closed.contains("horizon-guard-replacement-166-local3retry6-20261110-v1.service"));
        assert!(closed.contains("horizon-guard-replacement-166-local3retry6-20261110-v1.timer"));
        assert!(candidate_template(&json!({"attempt":"local3retry6"}), 167).is_err());
    }
    #[test]
    fn retry7_template_binds_stopped_retry6_and_new_guard() {
        let t = candidate_template(&json!({"attempt":"local3retry7"}), 166).unwrap();
        assert_eq!(t["attempt"], "local3retry7");
        assert_eq!(t["retry5"]["failed_retry6"]["sha256"], "3901e732145152e22372c63c32c3744833cfc1c10f45d11e9e7a9c34fed25074");
        assert_eq!(t["data_fulfillment"]["runtime"]["sha256"], "e2e7525e54f43aa4745501cd4d7ef69543f4e3bcf49ac5bc7f4474be73e51e0c");
        assert!(t["fresh_subtree"].as_str().unwrap().contains("local3retry7"));
        let closed: std::collections::BTreeSet<&str> = t["closed_units"].as_array().unwrap().iter().map(|unit| unit.as_str().unwrap()).collect();
        assert_eq!(closed.len(), t["closed_units"].as_array().unwrap().len());
        assert!(closed.contains(t["producer_unit"].as_str().unwrap()));
        assert!(closed.contains("horizon-guard-replacement-166-local3retry7-20261110-v1.timer"));
        assert!(candidate_template(&json!({"attempt":"local3retry7"}), 167).is_err());
    }
}
