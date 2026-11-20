//! Shared actual prelaunch check. The audit, build and holding bookings are additive to the
//! historical fleet. The cold lane's full cap occurs once in concurrent replay growth.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{fs, os::unix::fs::MetadataExt, path::Path};

#[allow(dead_code)]
#[path = "../../horizon_retry9_166_20261120_v1/audit_budget.rs"]
mod audit_budget;
#[path = "auxiliary_phases.rs"]
mod auxiliary_phases;

const CAP: u64 = 309_237_645_312;
const BASE: u64 = 6_794_761_027_378;
const FLOOR: u64 = 6_829_053_656_882;
const BUILD_IMAGE: &str =
    "/home/sol/.jetstreamer-private/epoch168-source-diagnostic-build-20261119-v1/build.ext4";

fn n(v: &Value, k: &str) -> Result<u64> {
    v[k].as_u64()
        .with_context(|| format!("missing unsigned {k}"))
}
fn sum(a: u64, b: u64) -> Result<u64> {
    a.checked_add(b).context("independent capacity overflow")
}

fn auxiliary(fleet: &Value, allocated: u64) -> Result<Value> {
    let a = &fleet["retry9_auxiliary_commitments"];
    ensure!(
        fleet["complete_DATA_bytes"] == BASE
            && fleet["retained_retry6_166_DATA_bytes"] == CAP
            && fleet["actual_executing_replays"] == json!([])
            && fleet["actual_active_bootstraps"] == json!([])
            && fleet["all_existing_memory_DATA_OS_native_transport_promises_retained"] == true
            && fleet["additional_retained_build_allocation"]["sha256"]
                == "b9a50965b779c994278a0d6aa55132c69c043da39d6ddbec21b50caf9f2b9d85"
            && a["receipt_bindings"]["PARK_SERIAL_ADMISSION"]["sha256"]
                == "6a9ec7435903516e7c0f8a4531fd6d6de184e0f16eccb40d01cc32c0cd6918a1"
            && a["receipt_bindings"]["BUILD_ADMISSION"]["sha256"]
                == "9eab68db85a3e2899a631fe1a7eda009ef0936f471ac44ef585e081d3977f8f9"
            && a["holding_serial"] == true
            && a["build_and_native_qualification_serial"] == true
            && a["holding_and_build_may_overlap"] == true
            && a["resource_credit_bytes"] == 0
            && a["reservation_ending_bytes"] == 0,
        "missing complete historical fleet, fixed build or serial holding obligations"
    );
    for (key, min) in [
        ("build_memory_bytes", 2u64 << 30),
        ("build_cpu_quota_micros", 1_000_000),
        ("build_fixed_image_bytes", 4u64 << 30),
        ("build_outside_allowance_bytes", 16u64 << 20),
        ("holding_memory_bytes", 2u64 << 30),
        ("holding_cpu_quota_micros", 2_000_000),
        ("holding_restore_overlap_bytes", 69_333_973_781),
    ] {
        ensure!(n(a, key)? >= min, "under-booked {key}");
    }
    let (phase_bindings, memory, cpu) = auxiliary_phases::load(fleet)?;
    let native = auxiliary_phases::native(memory, cpu)?;
    let mut retained = a.clone();
    retained["phase_admissions"] = phase_bindings;
    retained["maximum_concurrent_phase_memory_bytes"] = json!(memory);
    retained["maximum_concurrent_phase_cpu_quota_micros"] = json!(cpu);
    let image = n(a, "build_fixed_image_bytes")?;
    let image_remaining = image.saturating_sub(allocated);
    let staging = sum(
        n(a, "holding_staging_bytes")?,
        n(a, "holding_restore_overlap_bytes")?,
    )?;
    let data = sum(
        sum(staging, n(a, "build_outside_allowance_bytes")?)?,
        image_remaining,
    )?;
    // Keep the priority ranged-reader qualification's additional HOME allocation.
    let data = sum(data, 1 << 30)?;
    Ok(
        json!({"retained_bookings":retained,"native":native,"additional_memory_bytes":memory,"additional_cpu_quota_micros":cpu,
        "remaining_DATA_bytes":data,"fixed_build_image_bytes":image,"resident_fixed_build_image_bytes":allocated.min(image),
        "remaining_fixed_build_image_bytes":image_remaining,"resource_credit_bytes":0,"promise_ending_bytes":0}),
    )
}

fn combined_fit(checks: &Value, aux: &Value) -> Result<Value> {
    let fit = &checks["retry3_working_set"];
    let old = n(
        &checks["data_accounting"]["current_fit"],
        "fulfilled_existing_DATA_bytes",
    )?;
    let floor = FLOOR
        .checked_sub(old)
        .context("qualified fulfillment above floor")?;
    let growth = n(fit, "complete_concurrent_remaining_growth_bytes")?;
    let staging = n(fit, "fresh_subtree_overlap_bytes")?;
    let margin = n(fit, "unrelated_growth_margin_bytes")?;
    ensure!(
        growth == CAP
            && staging >= 64 << 20
            && margin >= 10 << 30
            && fit["forecast_offloads_credited_bytes"] == 0
            && fit["resource_credit_bytes"] == 0
            && fit["immutable_effective_guard_floor_bytes"] == floor
            && n(fit, "required_raw_available_bytes")?
                == sum(sum(sum(floor, growth)?, staging)?, margin)?,
        "old fleet floor plus full new cap, staging and margin required"
    );
    let aux_data = n(aux, "remaining_DATA_bytes")?;
    let mut combined = fit.clone();
    // Both the historical fit and the independent audit-continuity constraint must
    // preserve these bytes. The inherited auditor takes the maximum of those fits.
    combined["required_raw_available_bytes"] =
        json!(sum(n(fit, "required_raw_available_bytes")?, aux_data)?);
    combined["unrelated_growth_margin_bytes"] = json!(sum(margin, aux_data)?);
    // CAP is already in complete_concurrent_remaining_growth_bytes. No second
    // growth term is needed for this lane in the shared audit floor calculation.
    combined["additional_growth_not_covered_by_existing_promise_bytes"] = json!(0);
    combined["independent_cap_in_concurrent_growth_bytes"] = json!(CAP);
    combined["retained_auxiliary_remaining_DATA_bytes"] = json!(aux_data);
    Ok(combined)
}

pub(crate) fn check(
    fleet: &Value,
    checks: &Value,
    available_data: u64,
    total_memory: u64,
    available_memory: u64,
    cores: u64,
) -> Result<Value> {
    audit_budget::validate_fleet_obligation(&fleet["continuing_audit_obligation"])?;
    let path = Path::new(BUILD_IMAGE);
    let image = fs::symlink_metadata(path)?;
    ensure!(
        path.canonicalize()? == path
            && image.is_file()
            && image.nlink() == 1
            && image.dev() == fs::metadata("/home/sol")?.dev()
            && image.len() == 4u64 << 30,
        "retained fixed build image is not the regular HOME backing file"
    );
    let alloc = image
        .blocks()
        .checked_mul(512)
        .context("build allocation overflow")?;
    let aux = auxiliary(fleet, alloc)?;
    let adjusted = combined_fit(checks, &aux)?;
    let native = audit_budget::observe()?;
    let data = audit_budget::data_requirements(&adjusted, available_data)?;
    let mut with_aux = checks.clone();
    let mem = n(&aux, "additional_memory_bytes")?;
    with_aux["complete_memory_plus_reserve_bytes"] =
        json!(sum(n(checks, "complete_memory_plus_reserve_bytes")?, mem)?);
    with_aux["memory_accounting"]["required_available_bytes"] = json!(sum(
        n(&checks["memory_accounting"], "required_available_bytes")?,
        mem
    )?);
    with_aux["booked_cpu_quota_micros"] = json!(sum(
        n(checks, "booked_cpu_quota_micros")?,
        n(&aux, "additional_cpu_quota_micros")?
    )?);
    let resources = audit_budget::requirements(
        &json!({"resource_checks":with_aux}),
        total_memory,
        available_memory,
        cores,
    )?;
    let obligation = json!({"historical_complete_DATA_bytes":BASE,"retained_standard_lane_cap_bytes":CAP,
        "independent_physical_cap_bytes":CAP,"complete_replay_DATA_with_independent_cap_bytes":BASE+CAP,
        "resource_credit_bytes":0,"resource_promise_ending_bytes":0});
    Ok(
        json!({"audit_native":native,"audit_home_DATA":data,"audit_fit":adjusted,
       "audit_additive_resources":resources,"auxiliary":aux,"independent_DATA_obligation":obligation}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cap_is_charged_once_alongside_auxiliary_and_historical_floor() {
        let staging = 64u64 << 20;
        let margin = 10u64 << 30;
        let fulfilled = 100_000_000_000u64;
        let mut checks = json!({"data_accounting":{"current_fit":{"fulfilled_existing_DATA_bytes":fulfilled}},
          "retry3_working_set":{"immutable_effective_guard_floor_bytes":FLOOR-fulfilled,
          "complete_concurrent_remaining_growth_bytes":CAP,"unrelated_growth_margin_bytes":margin,
          "fresh_subtree_overlap_bytes":staging,"required_raw_available_bytes":FLOOR-fulfilled+CAP+margin+staging,
          "forecast_offloads_credited_bytes":0,"resource_credit_bytes":0}});
        let a = json!({"remaining_DATA_bytes":69_350_750_997u64});
        let fit = combined_fit(&checks, &a).unwrap();
        assert_eq!(fit["complete_concurrent_remaining_growth_bytes"], CAP);
        assert_eq!(
            fit["additional_growth_not_covered_by_existing_promise_bytes"],
            0
        );
        assert_eq!(
            fit["required_raw_available_bytes"],
            FLOOR - fulfilled + CAP + margin + staging + 69_350_750_997u64
        );
        checks["retry3_working_set"]["complete_concurrent_remaining_growth_bytes"] = json!(CAP - 1);
        assert!(combined_fit(&checks, &a).is_err());
    }
}
