use super::*;
use std::{os::fd::AsRawFd, path::PathBuf, process::Command};

const PROVIDER_DIR: &str = "/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1/tools-homefloor-145-post-v9-build-v1";
const PROVIDER_SEAL: &str = "f650a4acb3f901ba82fe36e6014d6b48176c9365d4750ba80d71debeaa3942c6";
const PROVIDER_SHA: &str = "512a70862c19f662d900955adeaa37587c129912d9847a64beb1e910ecdb8004";
const PROVIDER_BYTES: u64 = 149_523;
const TRANSITION_LOCK: &str =
    "/home/sol/.jetstreamer-private/r2-holding-state-dev-samjohnson-v1/transition.lock";
const V9_IID: &str = "ebdfc34db47c4e7699ea5ccbada5d604";
const V9_UNIT: &str = "horizon-holding-export145-20261121-v1.service";
const V9_COMPLETION: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch145-semantic-continuity-20261121-v1/v9-census-name-handoff/SEMANTIC_COMPLETION.json";
const V12_CONSUMER_SHA: &str = "6899ee7708ca74e9bf2a04cb932ce2fc75dff18e16866149b1dbeea3887496ac";
const V12_UNIT: &str = "horizon-archive-status-cadence-after172-20261120-v1.service";

pub const PUBLICATION_COPY: u64 = 206_474_468_136;
const HOST_MEMORY_WITH_RESERVE: u64 = 810_658_050_048;
const HOST_CPU: u64 = 64_000_000;
const MAX_QUOTE_AGE: u64 = 120;
const RUNTIME: &str = "/var/lib/jetstreamer/horizon_runtime_data";

fn current_fleet(path: &Path, sha: &str) -> Result<Value> {
    let dir = path.parent().context("missing fleet directory")?;
    let name = dir
        .file_name()
        .and_then(|n| n.to_str())
        .context("missing fleet directory name")?;
    ensure!(
        dir.parent() == Some(Path::new(RUNTIME))
            && name.starts_with("root")
            && name.contains("-live166167170-")
            && path
                .file_name()
                .is_some_and(|n| n == "ROOT_COMPLETE_OPERATIONAL_FLEET.json"),
        "different current fleet path"
    );
    let fleet = document(path, sha, 0o600)?;
    let mut rows = fleet["epochs"]
        .as_array()
        .context("missing campaign rows")?
        .iter()
        .filter(|row| row["epoch"] == EPOCH);
    let row = rows
        .next()
        .context("epoch 186 absent from the current fleet")?;
    ensure!(
        fleet["schema"] == "horizon-Root-complete-fleet-operational-review-v1"
            && fleet["owner"] == "/root"
            && fleet["all_active_status_reports_authenticated_readback"] == true
            && fleet["all_existing_memory_DATA_OS_native_transport_promises_retained"] == true
            && rows.next().is_none()
            && row["inventory_state"] == "missing"
            && row["no_live_producer_claimed"] == true
            && row["current_replay"].is_null()
            && row["current_bootstrap"].is_null()
            && row["state"] == "blocked-qualification",
        "current fleet does not allow a vacant epoch 186 qualification"
    );
    ensure!(
        fleet["actual_executing_replays"]
            .as_array()
            .context("missing live replay census")?
            .iter()
            .all(|op| op["epoch"] != EPOCH),
        "epoch 186 has a live fleet claim"
    );
    fresh(&fleet, "recorded_unix_seconds", now()?, 2_400)?;
    Ok(fleet)
}

fn validate_baseline(fit: &Value, fleet: &Value, incumbent_iid: &str, clock: u64) -> Result<()> {
    let phase = &fit["phase145"];
    let status = &fit["status_registration"];
    let donor = &fit["epoch159_donor_cover"];
    let retry5 = &fit["retry5_complete_booking"];
    ensure!(
        fit["schema"] == "horizon-incident-replay-fit-v1"
            && fit["epoch"] == 145
            && fit["fleet"] == *fleet
            && fit["resource_credit_bytes"] == 0
            && fit["stopped_generation_resident_credit_bytes"] == 0
            && fit["replay_launch_authorized"] == false
            && fit["candidate"].is_null()
            && fit["bounded_qualification"].is_null()
            && fit["bookings"].get("186").is_none()
            && fit["replacements"].get("186").is_none()
            && fit["complete_cpu_quota_micros"] == HOST_CPU
            && fit["complete_memory_plus_reserve_bytes"] == HOST_MEMORY_WITH_RESERVE,
        "different full incumbent quote, candidate or retained resource authority"
    );
    fresh(fit, "recorded_unix_seconds", clock, MAX_QUOTE_AGE)?;
    ensure!(
        phase["stage"] == "v9-semantic-complete-drained"
            && phase["completed_invocation_id"] == V9_IID
            && phase["Id"] == V9_UNIT
            && phase["MainPID"] == "0"
            && phase["semantic_receipt"]["path"] == V9_COMPLETION
            && lower_hex(text(&phase["semantic_receipt"], "sha256")?, 32)
            && status["invocation_id"] == incumbent_iid
            && iid(incumbent_iid)
            && status["consumer_seal"]["sha256"] == V12_CONSUMER_SHA
            && donor["fleet"] == *fleet
            && donor["native_recorded_unix_seconds"] == fit["recorded_unix_seconds"]
            && donor["schema"] == "horizon-145-drained-159-donor-cover-v1"
            && donor["credited_retirement_bytes"] == 0
            && retry5["schema"] == "horizon-168-retry5-complete-booking-v1"
            && retry5["complete_required_HOME_bytes"] == fit["complete_required_HOME_bytes"]
            && retry5["resource_credit_bytes"] == 0,
        "different drained V9, V12 status writer or incumbent booking"
    );
    Ok(())
}

fn budget(fit: &Value) -> Result<Value> {
    let incumbent_floor = number(fit, "protected_raw_floor_bytes")?
        .max(number(fit, "complete_required_HOME_bytes")?)
        .max(number(
            &fit["epoch159_donor_cover"],
            "native_home_required",
        )?);
    let guard_floor = incumbent_floor
        .checked_add(PUBLICATION_COPY)
        .context("epoch 186 protected HOME floor overflow")?;
    let home_required = guard_floor
        .checked_add(TREE_BOOKING)
        .context("epoch 186 complete HOME requirement overflow")?;
    let home_available = number(fit, "available_HOME_bytes")?;
    let memory_required = number(fit, "required_available_memory_bytes")?
        .checked_add(MEMORY + GUARD_MEMORY)
        .context("epoch 186 memory requirement overflow")?;
    let memory_available = number(fit, "available_memory_bytes")?;
    let disk_shortfall = home_required.saturating_sub(home_available);
    let ram_shortfall = memory_required.saturating_sub(memory_available);

    Ok(json!({
        "incumbent_home_floor_bytes":incumbent_floor,
        "guard_minimum_free_bytes":guard_floor,
        "retained_publication_copy_bytes":PUBLICATION_COPY,
        "added_tree_reservation_bytes":TREE_BOOKING,
        "complete_required_home_bytes":home_required,"available_home_bytes":home_available,
        "home_shortfall_bytes":disk_shortfall,
        "added_memory_bytes":MEMORY+GUARD_MEMORY,
        "required_available_memory_bytes":memory_required,
        "available_memory_bytes":memory_available,"memory_shortfall_bytes":ram_shortfall,
        "incumbent_cpu_quota_micros":HOST_CPU,"new_cpu_quota_micros":CPU+GUARD_CPU,
        "cpu_booking_verified":false,"needed_cpu_booking_micros":CPU+GUARD_CPU,
        "home_and_memory_fit":fit["fits"] == true && disk_shortfall == 0 && ram_shortfall == 0,
        "admission_fits":false,"credited_retirement_bytes":0
    }))
}

fn vacant() -> Result<Value> {
    let timeout = Command::new("/usr/bin/timeout")
        .args([
            "10",
            "/usr/bin/systemctl",
            "list-units",
            "--no-legend",
            "--plain",
            "--no-pager",
            "--state=running,activating,reloading,deactivating,waiting",
            "*epoch186*",
            "*lane-186*",
            "*qualify-186*",
            "*guard-186*",
        ])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .output()?;
    ensure!(
        timeout.status.success() && timeout.stderr.is_empty() && timeout.stdout.is_empty(),
        "epoch 186 service, timer, or native claim is already present"
    );
    for unit in [UNIT, GUARD_UNIT] {
        ensure!(
            !Path::new("/sys/fs/cgroup/system.slice").join(unit).exists(),
            "epoch 186 retained cgroup {unit}"
        );
    }
    let status = guard::properties(V12_UNIT)?;
    ensure!(
        status["ActiveState"] == "active"
            && status["SubState"] == "running"
            && status["Job"] == ""
            && status["NRestarts"] == "0"
            && iid(text(&status, "InvocationID")?),
        "missing current V12 incumbent identity"
    );
    let v9 = guard::properties(V9_UNIT)?;
    ensure!(
        v9["ActiveState"] == "inactive"
            && v9["SubState"] == "dead"
            && v9["MainPID"] == "0"
            && v9["ControlPID"] == "0"
            && v9["ControlGroup"] == ""
            && v9["Job"] == ""
            && !Path::new("/sys/fs/cgroup/system.slice")
                .join(V9_UNIT)
                .exists(),
        "epoch 145 V9 must drain before epoch 186 pricing"
    );
    Ok(status)
}

pub fn inspect(fleet_path: &Path, fleet_sha: &str) -> Result<Value> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "native quote requires root read access"
    );
    let (lock, lock_identity) = open_root_file(Path::new(TRANSITION_LOCK), 0o600)?;
    ensure!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "serial transition lock is busy"
    );
    let status = vacant()?;
    let fleet = current_fleet(fleet_path, fleet_sha)?;
    let provider_dir = Path::new(PROVIDER_DIR);
    let image = provider_dir.join("post-stop-fit");
    let image_seal = seal(provider_dir, PROVIDER_SEAL)?;
    seal_member(
        &image_seal,
        "post-stop-fit",
        PROVIDER_SHA,
        PROVIDER_BYTES,
        "0555",
    )?;
    verify_file(&image, PROVIDER_SHA, PROVIDER_BYTES, 0o555)?;
    let source = source::inspect(false)?;
    let output = Command::new("/usr/bin/timeout")
        .args(["150", "/usr/bin/python3", "-IB"])
        .arg(&image)
        .arg("145")
        .arg(fleet_path)
        .arg(fleet_sha)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .output()?;
    ensure!(
        output.status.success() && output.stderr.is_empty(),
        "post-V9 incumbent provider refused: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    let fit: Value = serde_json::from_slice(&output.stdout)?;
    let fleet_ref = binding(fleet_path, fleet_sha);
    let clock = now()?;
    validate_baseline(&fit, &fleet_ref, text(&status, "InvocationID")?, clock)?;
    let completion = &fit["phase145"]["semantic_receipt"];
    let semantic = document(Path::new(V9_COMPLETION), text(completion, "sha256")?, 0o400)?;
    ensure!(
        semantic["schema"] == "horizon-epoch145-v8-census-successor-semantic-completion-v1"
            && semantic["invocation_id"] == V9_IID
            && semantic["native_success"]["_PID"] == "1"
            && semantic["native_success"]["UNIT"] == V9_UNIT
            && semantic["native_success"]["INVOCATION_ID"] == V9_IID
            && semantic["native_success"]["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448"
            && semantic["publication_authorized"] == false
            && semantic["r2_mutations"] == false,
        "foreign native epoch 145 V9 completion"
    );
    ensure!(
        vacant()? == status && current_fleet(fleet_path, fleet_sha)? == fleet,
        "fleet or native owner changed during quote"
    );
    stable(Path::new(TRANSITION_LOCK), &lock, &lock_identity)?;
    Ok(json!({
        "schema":"horizon-epoch186-post-v9-source-capacity-v1","recorded_unix_seconds":clock,
        "fleet":fleet_ref,"incumbent_writer_invocation":status["InvocationID"],
        "incumbent_price_provider":binding(image,PROVIDER_SHA),
        "incumbent_price_seal":binding(PathBuf::from(PROVIDER_DIR).join("deployment-seal-receipt.json"),PROVIDER_SEAL),
        "incumbent_price_stdout_sha256":format!("{:x}",Sha256::digest(&output.stdout)),
        "incumbent_v9_completion":completion,"source_entry":source,"resource_screen":budget(&fit)?,
        "replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Value {
        json!({"schema":"horizon-incident-replay-fit-v1","epoch":145,"fleet":{"sha256":"bound"},
            "phase145":{"stage":"v9-semantic-complete-drained","completed_invocation_id":V9_IID,
                "Id":V9_UNIT,"MainPID":"0","semantic_receipt":{"path":V9_COMPLETION,"sha256":"1".repeat(64)}},
            "status_registration":{"invocation_id":"1".repeat(32),"consumer_seal":{"sha256":V12_CONSUMER_SHA}},
            "resource_credit_bytes":0,"stopped_generation_resident_credit_bytes":0,
            "replay_launch_authorized":false,"candidate":null,"bounded_qualification":null,
            "bookings":{},"replacements":{},"fits":true,
            "complete_cpu_quota_micros":HOST_CPU,"complete_memory_plus_reserve_bytes":HOST_MEMORY_WITH_RESERVE,
            "recorded_unix_seconds":100,"complete_required_HOME_bytes":1000,"protected_raw_floor_bytes":999,
            "available_HOME_bytes":1_000_000_000_000_u64,"required_available_memory_bytes":1_000,
            "available_memory_bytes":690_000_000_000_u64,
            "epoch159_donor_cover":{"schema":"horizon-145-drained-159-donor-cover-v1","fleet":{"sha256":"bound"},
                "native_recorded_unix_seconds":100,"credited_retirement_bytes":0,"native_home_required":1001},
            "retry5_complete_booking":{"schema":"horizon-168-retry5-complete-booking-v1",
                "complete_required_HOME_bytes":1000,"resource_credit_bytes":0}})
    }

    #[test]
    fn requires_exact_drained_v9_current_writer_and_fresh_scope() {
        let quote = fixture();
        let check = |q: &Value, time| validate_baseline(q, &quote["fleet"], &"1".repeat(32), time);
        check(&quote, 220).unwrap();
        assert!(check(&quote, 221).is_err());
        assert!(check(&quote, 99).is_err());
        for (path, changed) in [
            ("/phase145/stage", json!("leased-worker")),
            ("/phase145/completed_invocation_id", json!("different")),
            ("/status_registration/consumer_seal/sha256", json!("v7")),
            ("/bookings", json!({"186":{"remaining":42}})),
            ("/bounded_qualification", json!({"unit":UNIT})),
            (
                "/retry5_complete_booking/complete_required_HOME_bytes",
                json!(999),
            ),
            ("/resource_credit_bytes", json!(1)),
        ] {
            let mut bad = quote.clone();
            *bad.pointer_mut(path).unwrap() = changed;
            assert!(check(&bad, 109).is_err(), "{path}");
        }
    }

    #[test]
    fn preserves_incumbent_floors_and_requires_a_distinct_cpu_booking() {
        let mut quote = fixture();
        let screen = budget(&quote).unwrap();
        assert_eq!(screen["guard_minimum_free_bytes"], 1001 + PUBLICATION_COPY);
        assert_eq!(
            screen["complete_required_home_bytes"],
            1001 + PUBLICATION_COPY + TREE_BOOKING
        );
        assert_eq!(
            screen["required_available_memory_bytes"],
            1000 + MEMORY + GUARD_MEMORY
        );
        assert_eq!(screen["home_and_memory_fit"], true);
        assert_eq!(screen["admission_fits"], false);
        assert_eq!(screen["needed_cpu_booking_micros"], CPU + GUARD_CPU);
        quote["available_memory_bytes"] = json!(MEMORY);
        quote["available_HOME_bytes"] = json!(1001 + PUBLICATION_COPY + TREE_BOOKING - 19);
        let screen = budget(&quote).unwrap();
        assert_eq!(screen["memory_shortfall_bytes"], 1000 + GUARD_MEMORY);
        assert_eq!(screen["home_shortfall_bytes"], 19);
        assert_eq!(screen["home_and_memory_fit"], false);
        quote["protected_raw_floor_bytes"] = json!(u64::MAX);
        assert!(budget(&quote).is_err());
    }
}
