use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

#[path = "price_entry143.rs"]
#[allow(dead_code)]
mod prior;
use prior::{command, number, property, protected, read, state, string, usage};

const HOME_CAP: u64 = (24 << 30) + (64 << 20);
const RETRY_HOME_CAP: u64 = (56 << 30) + (64 << 20);
const RETRY2_HOME_CAP: u64 = (44 << 30) + (64 << 20);

fn retry_holding(fleet: &Value, transfers: &[Value]) -> Result<(Value, u64, u64)> {
    let start_ref = json!({
        "path":"/var/lib/jetstreamer/horizon_runtime_data/epoch185-lanek-holding-20261125-v1/PARK_START.json",
        "sha256":"75cb59704be9c9007b03a82553bbc69689139c046400bfafcb9339fa3da4e5fd"
    });
    let start = read(&start_ref)?;
    let admission = read(&start["admission"])?;
    let fit = read(&admission["fit"])?;
    let old140 = &fit["epoch140"];
    for key in ["booking", "cpu_loan", "held_owner"] {
        read(&old140[key])?;
    }
    let unit = string(&admission["unit"])?;
    let live = state(unit)?;
    let status = property(&live, "ActiveState")?;
    ensure!(
        unit == "horizon-closed185-lanek-park-20261127-v1.service"
            && admission["resource_credit_bytes"] == 0
            && fit["resource_credit_bytes"] == 0
            && admission["archive_staging_bytes"] == 0
            && number(&admission["restore_overlap_bytes"])?
                <= number(&admission["serial_restore_slot_bytes"])?
            && admission["serial_restore_enlargement_bytes"] == 0
            && property(&live, "InvocationID")? == string(&start["native"]["InvocationID"])?
            && property(&live, "CPUQuotaPerSecUSec")? == "2s"
            && property(&live, "MemoryMax")? == (2u64 << 30).to_string()
            && property(&live, "MemorySwapMax")? == "0"
            && matches!(status, "active" | "activating"),
        "the exact 185 lane-K holding owner or charge changed"
    );
    let accepted_event = &fleet["epoch185_lanek_holding"];
    if accepted_event.is_null() {
        ensure!(
            transfers.is_empty(),
            "another holding owner changed the fleet"
        );
    } else {
        let event = read(accepted_event)?;
        ensure!(
            event["schema"] == "horizon-epoch185-lanek-cadence-event-v1"
                && event["result"]["holding_reservation"]["admission"] == start["admission"]
                && event["result"]["holding_reservation"]["start"] == start_ref
                && (transfers.is_empty() || transfers == std::slice::from_ref(accepted_event)),
            "the writer enrolled a different holding owner"
        );
    }
    Ok((
        start_ref,
        number(&admission["metadata_allowance_bytes"])?,
        number(&admission["memory"])?,
    ))
}
fn lane_k_retirement_charge() -> Result<(Value, u64)> {
    let unit = "horizon-exact-185-lanek-retirement.service";
    let live = state(unit)?;
    let active = property(&live, "ActiveState")?;
    if matches!(active, "inactive" | "failed") {
        ensure!(
            property(&live, "MainPID")? == "0" && property(&live, "Job")?.is_empty(),
            "lane-K retirement is changing state"
        );
        return Ok((Value::Null, 0));
    }
    let main: u32 = property(&live, "MainPID")?.parse()?;
    ensure!(
        active == "active"
            && main > 1
            && property(&live, "ControlGroup")? == format!("/system.slice/{unit}")
            && property(&live, "MemoryMax")? == "1073741824"
            && property(&live, "MemorySwapMax")? == "0"
            && property(&live, "CPUQuotaPerSecUSec")? == "1s",
        "retirement owner or complete hard limits changed"
    );
    let executable = "/var/lib/jetstreamer/horizon_runtime_data/epoch185-lanek-holding-20261125-v1/retirement-tools-v3/retire-lanek185";
    let observed = fs::metadata(format!("/proc/{main}/exe"))?;
    let selected = fs::metadata(executable)?;
    ensure!(
        (observed.dev(), observed.ino()) == (selected.dev(), selected.ino()),
        "different live lane-K retirement executable"
    );
    let command = fs::read(format!("/proc/{main}/cmdline"))?;
    let mut arguments = command.split(|byte| *byte == 0);
    let requested_executable = arguments.next().context("missing lane-K executable")?;
    let mode = arguments.next().context("missing lane-K mode")?;
    let plan = arguments.next().context("missing lane-K plan")?;
    ensure!(
        requested_executable == executable.as_bytes()
            && matches!(mode, b"holding-check-retire185-lanek" | b"holding-retire185-lanek")
            && plan == b"/var/lib/jetstreamer/horizon_runtime_data/epoch185-lanek-holding-20261125-v1/RETIREMENT_PLAN_AFTER_CUSTODY.json"
            && state(unit)? == live,
        "unexpected live lane-K retirement operation"
    );
    Ok((
        json!({"native":live,"mode":String::from_utf8_lossy(mode),"executable":executable}),
        1 << 30,
    ))
}

fn bridge_exit_capture_charge() -> Result<(Value, u64, u64)> {
    let unit = "horizon-170-bridge-exit-capture-20261127-v1.service";
    let live = state(unit)?;
    let active = property(&live, "ActiveState")?;
    if matches!(active, "inactive" | "failed") {
        ensure!(
            property(&live, "MainPID")? == "0" && property(&live, "Job")?.is_empty(),
            "170 exit capture is changing state"
        );
        return Ok((Value::Null, 0, 0));
    }
    ensure!(
        active == "active"
            && property(&live, "MainPID")?.parse::<u32>()? > 1
            && property(&live, "InvocationID")? == "5d32e9177b714a528ceddb18b63d22ea"
            && property(&live, "ControlGroup")? == format!("/system.slice/{unit}")
            && property(&live, "MemoryMax")? == "33554432"
            && property(&live, "MemorySwapMax")? == "0"
            && property(&live, "CPUQuotaPerSecUSec")? == "150ms",
        "170 exit capture owner or charge changed"
    );
    Ok((json!(live), 2 << 20, 32 << 20))
}

const RAM_CAP: u64 = 27 << 30;

fn sample_lower(reference: &Value) -> Result<u64> {
    let sample = read(reference)?;
    let walk = &sample["root_physical_observation"];
    Ok(number(&walk["first"]["physical_bytes"])?.min(number(&walk["second"]["physical_bytes"])?))
}

fn retire_uplift(fleet_ref: &Value, digest: &str) -> Result<(Value, u64)> {
    let fleet_path = Path::new(string(&fleet_ref["path"])?);
    let fleet_cycle = fleet_path
        .parent()
        .and_then(Path::file_name)
        .and_then(|name| name.to_str())
        .context("missing exact fleet generation")?;
    let (relative_path, schema, paths): (_, _, &[&str]) = match fleet_cycle {
        "root091808-live166167170-20261127-v1" => (
            "retry1/CACHE_RETIREMENT_AFTER_091808.json",
            "horizon-epoch140-post-census-cache-retirement-v1",
            &[
                "/home/sol/.jetstreamer-private/compiler-targets/queue193-20261024-v1/cache-stage/debug/deps",
                "/home/sol/.jetstreamer-private/compiler-targets/queue193-20261024-v1/cache-stage/release/deps",
            ],
        ),
        "root094808-live166167170-20261127-v1" => (
            "retry1/CACHE_RETIREMENT_AFTER_094808.json",
            "horizon-epoch140-post-census-cache-retirement-v1",
            &[
                "/home/sol/.jetstreamer-private/compiler-targets/queue193-20261024-v1/cache-stage/debug/build",
                "/home/sol/.jetstreamer-private/compiler-targets/queue193-20261024-v1/cache-stage/release/build",
                "/home/sol/.jetstreamer-private/cold-retirement-dev-20261026-v1/target/release/build",
            ],
        ),
        "root101808-live166167170-20261127-v1" => (
            "retry2/CLOSED_140_RETRY1_SCRATCH_RETIREMENT.json",
            "horizon-epoch140-post-census-scratch-retirement-v1",
            &[
                "/home/sol/.jetstreamer-private/epoch140-suffix-recording-20261127-retry1/recording/scratch",
            ],
        ),
        _ => anyhow::bail!("cache retirement does not belong to this accepted fleet"),
    };
    let reference = json!({
        "path":format!("/var/lib/jetstreamer/horizon_runtime_data/epoch140-suffix-recording-20261127-{relative_path}"),
        "sha256":digest
    });
    let receipt = read(&reference)?;
    let intent = read(&receipt["intent"])?;
    ensure!(
        receipt["schema"] == schema
            && receipt["fleet"] == *fleet_ref
            && intent["fleet"] == *fleet_ref
            && receipt["trees_absent"] == true
            && receipt["r2_mutations"] == false
            && intent["live_or_staged_references"] == json!([]),
        "cache retirement does not belong to this accepted fleet"
    );
    let retired_trees = intent["trees"]
        .as_array()
        .context("missing retired trees")?;
    ensure!(
        retired_trees.len() == paths.len(),
        "extra compiler cache path"
    );
    for (path, retired) in paths.iter().zip(retired_trees) {
        ensure!(
            retired["path"] == *path && !Path::new(path).try_exists()?,
            "retirement used a different cache or it has been recreated"
        );
    }
    let before = number(&receipt["home_available_before_bytes"])?;
    let after = number(&receipt["home_available_after_bytes"])?;
    let exclusive = number(&receipt["exclusive_allocated_bytes_retired"])?;
    let released = after.saturating_sub(before).min(exclusive);
    ensure!(
        released > 0,
        "cache retirement released no verified capacity"
    );
    Ok((reference, released))
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let profile = args.get(2).map(String::as_str);
    let retry = matches!(profile, Some("--retry1" | "--retry2"));
    let cache_digest = match args.as_slice() {
        [_, _] | [_, _, _] if args.len() == 2 || retry => None,
        [_, _, _, flag, digest] if retry && flag == "--cache-retirement-sha" => Some(digest),
        _ => anyhow::bail!(
            "usage: price_epoch140 FLEET FLEET_SHA256 [--retry1|--retry2 [--cache-retirement-sha HEX]]"
        ),
    };
    let home_cap = match profile {
        Some("--retry2") => RETRY2_HOME_CAP,
        Some("--retry1") => RETRY_HOME_CAP,
        _ => HOME_CAP,
    };
    let fleet_ref = json!({"path":args[0],"sha256":args[1]});
    let fleet = read(&fleet_ref)?;
    let (cache_retirement, confirmed_reclaimed_home) = if let Some(digest) = cache_digest {
        retire_uplift(&fleet_ref, digest)?
    } else {
        (Value::Null, 0)
    };
    let transfers = fleet["actual_active_holding_transfers"]
        .as_array()
        .context("missing transfer roster")?;
    let (exit_capture, exit_capture_home, exit_capture_ram) = if retry {
        bridge_exit_capture_charge()?
    } else {
        (Value::Null, 0, 0)
    };
    let (retirement, retirement_ram) = if retry {
        lane_k_retirement_charge()?
    } else {
        (Value::Null, 0)
    };
    let (lane_k, extra_home, extra_ram) = if retry {
        retry_holding(&fleet, transfers)?
    } else {
        ensure!(
            transfers.is_empty(),
            "active 185 holding requires retry pricing"
        );
        (Value::Null, 0, 0)
    };
    ensure!(
        fleet["all_active_status_reports_authenticated_readback"] == true
            && fleet["all_reservation_ending_bytes"] == 0
            && fleet["resource_credit_bytes"] == 0
            && fleet["actual_active_bootstraps"] == json!([])
            && fleet["actual_active_retirements"] == json!([])
            && fleet["actual_active_retirement_checks"] == json!([]),
        "another transition changes the current fleet obligations"
    );
    let progress_ref = json!({
        "path":"/var/lib/jetstreamer/horizon_runtime_data/epoch167-checkpoint-tail-20261127-v1/FIRST_PROTECTED_PROGRESS.json",
        "sha256":"753ade79e4e3873c18eb0cec83d17f879d8e0e08fa45b97c740e8f6c3a6a5fe6"
    });
    let progress = read(&progress_ref)?;
    let release = read(&progress["release"])?;
    let intent = read(&release["intent"])?;
    let post = read(&release["post_guard_capacity"])?;
    let base = &intent["quote"]["exact_native_fit"];
    ensure!(
        intent["archive_publication_authorized"] == false
            && release["actor"] == progress["actor"]
            && release["actor"] == post["actor"]
            && base["fleet"] == intent["quote"]["fleet"]
            && post["phase"] == "post-guard"
            && post["required_home_bytes"] == intent["quote"]["required_home_bytes"]
            && post["resource_credit_bytes"] == 0
            && intent["run_guard_cap_bytes"] == 80u64 << 30,
        "changed 167 replacement charge"
    );
    let admission_fleet = read(&base["fleet"])?;
    let mut cursor = fleet["previous_Root_operational_review"].clone();
    let mut same_lineage = fleet_ref == base["fleet"];
    for _ in 0..if retry { 8 } else { 2 } {
        if same_lineage || cursor == base["fleet"] {
            same_lineage = true;
            break;
        }
        cursor = read(&cursor)?["previous_Root_operational_review"].clone();
    }
    ensure!(
        same_lineage,
        "140 quote needs the current successor of the 167 admission"
    );
    for key in [
        "actual_executing_replays",
        "current_private170_checkpoint_bridge",
    ] {
        ensure!(fleet[key] != Value::Null, "current fleet lacks {key}");
    }
    let old_holding = read(&admission_fleet["epoch185_lanel_holding"])?;
    let holding = read(&fleet["epoch185_lanel_holding"])?;
    ensure!(
        old_holding["result"] == holding["result"],
        "185 holding changed"
    );
    for key in [
        "additional_cpu_quota_micros",
        "additional_memory_bytes",
        "maximum_output_allocation_bytes",
    ] {
        ensure!(
            fleet["active_ready_range_audit_obligation"][key]
                == admission_fleet["active_ready_range_audit_obligation"][key],
            "ready audit changed {key}"
        );
    }
    let bridge_ref = json!({
        "path":"/var/lib/jetstreamer/horizon_runtime_data/epoch170-storage-witness-recovery-20261127-v1/suffix-run-v1/FIRST_PROTECTED_WORKER.json",
        "sha256":"289289ccd5dc7c30542d961dfcec2f1e29708944797f53e5d1c66c39b8212ca4"
    });
    let bridge = read(&bridge_ref)?;
    let base170 = read(&base["prior_fit"])?;
    let mut rosters = base170["native"]["released_167"]["tracked_processes"]
        .as_object()
        .context("missing native roster")?
        .clone();
    let tail_unit = string(&progress["actor"]["unit"])?;
    let bridge_unit = string(&bridge["actor"]["unit"])?;
    rosters.remove("horizon-qualify-167-checkpoint-bounded-20261127-v2.service");
    rosters.insert(tail_unit.into(), progress["processes"].clone());
    rosters.insert(bridge_unit.into(), bridge["actor"]["processes"].clone());
    let units = command(&[
        "list-units",
        "--type=service",
        "--state=running,activating,deactivating",
        "--plain",
        "--no-legend",
        "horizon-qualify-*",
    ])?;
    ensure!(
        units
            .lines()
            .filter_map(|line| line.split_ascii_whitespace().next())
            .collect::<BTreeSet<_>>()
            == rosters.keys().map(String::as_str).collect(),
        "another replay owns resources"
    );
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let before = usage()?;
    let mut growth_loss = 0;
    let mut resident = 0;
    let mut current_guards = BTreeMap::new();
    let peers = fleet["actual_executing_replays"]
        .as_array()
        .context("missing full replay roster")?;
    ensure!(peers.len() == 2, "full replay roster changed");
    for peer in peers {
        let unit = string(&peer["unit"]["Id"])?;
        let anchor = &base["live_guards"][unit];
        let (sample, physical, lower) = protected(
            anchor,
            &rosters[unit],
            &peer["guard_timer"]["InvocationID"],
            now,
        )?;
        growth_loss += sample_lower(anchor)?.saturating_sub(physical);
        resident += lower;
        current_guards.insert(unit, sample);
    }
    let (bridge_sample, bridge_physical, _) = protected(
        &base["live_guards"][bridge_unit],
        &rosters[bridge_unit],
        &bridge["guard"]["timer_invocation_id"],
        now,
    )?;
    growth_loss += sample_lower(&base["live_guards"][bridge_unit])?.saturating_sub(bridge_physical);
    current_guards.insert(bridge_unit, bridge_sample);
    let (tail_sample, tail_physical, _) = protected(
        &progress["guard"]["sample"],
        &rosters[tail_unit],
        &progress["guard"]["timer_invocation_id"],
        now,
    )?;
    current_guards.insert(tail_unit, tail_sample);
    let after = usage()?;
    let census_availability = number(&fleet["complete_cycle_conservative_available_DATA_bytes"])?;
    let eligible_availability = census_availability
        .checked_add(confirmed_reclaimed_home)
        .context("disk availability overflow")?;
    let home_available = before.0.min(after.0).min(eligible_availability);
    let ram_available = before.1.min(after.1);
    let retained_required_home = number(&post["required_home_bytes"])?
        .checked_sub(tail_physical)
        .context("tail allocation crosses initial protected charge")?
        .checked_add(growth_loss)
        .and_then(|bytes| bytes.checked_add(extra_home))
        .and_then(|bytes| bytes.checked_add(exit_capture_home))
        .context("disk commitment overflow")?;
    let retained_required_ram = (number(&post["required_ram_bytes"])?
        + number(&base["resident_lower_bound_bytes"])?)
    .checked_sub(resident)
    .and_then(|bytes| bytes.checked_add(extra_ram))
    .and_then(|bytes| bytes.checked_add(retirement_ram))
    .and_then(|bytes| bytes.checked_add(exit_capture_ram))
    .context("resident measurement or explicit RAM charge invalid")?;
    let expected = state("horizon-epoch140-suffix-recording.service")?;
    ensure!(
        matches!(property(&expected, "ActiveState")?, "inactive" | "failed")
            || (property(&expected, "MemoryMax")? == (26u64 << 30).to_string()
                && property(&expected, "MemorySwapMax")? == "0"
                && property(&expected, "CPUQuotaPerSecUSec")? == "2s"),
        "140 has a different active commitment"
    );
    println!(
        "{}",
        json!({
            "schema":"horizon-epoch140-bounded-recording-resource-screen-v1",
            "recorded_unix_seconds":now,"fleet":fleet_ref,"incumbent_167_progress":progress_ref,
            "guard_samples":current_guards,"incumbent_167_cap_bytes":80u64<<30,
            "incumbent_167_paid_lower_bound_bytes":tail_physical,
            "retained_required_home_bytes":retained_required_home,"available_home_bytes":home_available,
            "retained_required_ram_bytes":retained_required_ram,"available_ram_bytes":ram_available,
            "candidate_home_bytes":home_cap,"retained_185_lanek":lane_k,
            "verified_cache_retirement":cache_retirement,"confirmed_reclaimed_home_bytes":confirmed_reclaimed_home,
             "additional_185_lanek_home_bytes":extra_home,"additional_185_lanek_ram_bytes":extra_ram,
            "live_185_retirement":retirement,"additional_185_retirement_ram_bytes":retirement_ram,
            "live_170_exit_capture":exit_capture,"additional_170_exit_capture_home_bytes":exit_capture_home,
            "additional_170_exit_capture_ram_bytes":exit_capture_ram,"candidate_ram_bytes":RAM_CAP,
            "candidate_cpu_quota_micros":3_000_000,
            "disk_fits":home_available >= retained_required_home + home_cap,
            "memory_fits":ram_available >= retained_required_ram + RAM_CAP,
            "cpu_admission_proven":false,"replay_launch_authorized":false,
            "resource_credit_bytes":0
        })
    );
    Ok(())
}
