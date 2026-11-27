use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::time::{SystemTime, UNIX_EPOCH};

#[path = "price_entry143.rs"]
#[allow(dead_code)]
mod prior;
use prior::{command, number, property, protected, read, state, string, usage};

const HOME_CAP: u64 = (24 << 30) + (64 << 20);
const RAM_CAP: u64 = 27 << 30;

fn sample_lower(reference: &Value) -> Result<u64> {
    let sample = read(reference)?;
    let walk = &sample["root_physical_observation"];
    Ok(number(&walk["first"]["physical_bytes"])?.min(number(&walk["second"]["physical_bytes"])?))
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    ensure!(args.len() == 2, "usage: price_epoch140 FLEET FLEET_SHA256");
    let fleet_ref = json!({"path":args[0],"sha256":args[1]});
    let fleet = read(&fleet_ref)?;
    ensure!(
        fleet["all_active_status_reports_authenticated_readback"] == true
            && fleet["all_reservation_ending_bytes"] == 0
            && fleet["resource_credit_bytes"] == 0
            && fleet["actual_active_bootstraps"] == json!([])
            && fleet["actual_active_holding_transfers"] == json!([])
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
    ensure!(
        fleet_ref == base["fleet"] || fleet["previous_Root_operational_review"] == base["fleet"],
        "140 quote needs the direct current successor of the 167 admission"
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
    let home_available = before.0.min(after.0).min(number(
        &fleet["complete_cycle_conservative_available_DATA_bytes"],
    )?);
    let ram_available = before.1.min(after.1);
    let retained_required_home = number(&post["required_home_bytes"])?
        .checked_sub(tail_physical)
        .context("tail allocation crosses initial protected charge")?
        .checked_add(growth_loss)
        .context("disk commitment overflow")?;
    let retained_required_ram = (number(&post["required_ram_bytes"])?
        + number(&base["resident_lower_bound_bytes"])?)
    .checked_sub(resident)
    .context("resident measurement exceeds inherited RAM")?;
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
            "candidate_home_bytes": HOME_CAP,"candidate_ram_bytes":RAM_CAP,
            "candidate_cpu_quota_micros":3_000_000,
            "disk_fits":home_available >= retained_required_home + HOME_CAP,
            "memory_fits":ram_available >= retained_required_ram + RAM_CAP,
            "cpu_admission_proven":false,"replay_launch_authorized":false,
            "resource_credit_bytes":0
        })
    );
    Ok(())
}
