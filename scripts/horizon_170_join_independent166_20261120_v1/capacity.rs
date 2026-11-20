//! Preserve the old four-root allocation fit and fund the independent 166 root separately.
use crate::audit_budget;
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{fs, os::unix::fs::MetadataExt, path::Path};
#[path = "../horizon_independent_cold166_20261120_v1/prepare/auxiliary_phases.rs"]
mod auxiliary_phases;
fn n(v: &Value, k: &str) -> Result<u64> {
    v[k].as_u64().with_context(|| format!("missing {k}"))
}
fn sum(a: u64, b: u64) -> Result<u64> {
    a.checked_add(b).context("overflow")
}
pub fn check(
    fleet: &Value,
    checks: &Value,
    free: u64,
    total: u64,
    available: u64,
    cores: u64,
) -> Result<Value> {
    let e = crate::peer::evidence()?;
    crate::peer::live(&e)?;
    ensure!(
        fleet["complete_DATA_bytes"] == 6_794_761_027_378u64
            && fleet["admitted_independent166_capacity"] == e["post_guard_capacity"],
        "fleet omits independent166 or historical DATA"
    );
    let owners = crate::peer::owners(&e);
    let actual = fleet["actual_executing_replays"]
        .as_array()
        .context("live lanes")?
        .iter()
        .chain(
            fleet["actual_active_bootstraps"]
                .as_array()
                .context("bootstraps")?,
        )
        .collect::<Vec<_>>();
    ensure!(
        actual.len() == owners.len()
            && owners
                .iter()
                .all(|o| actual.iter().any(|r| r["epoch"] == o["epoch"]
                    && r["unit"]["Id"] == o["unit"]
                    && r["unit"]["InvocationID"] == o["invocation_id"]
                    && r["admission"] == o["admission"]
                    && r["guard_protection"] == o["guard_protection"])),
        "native work differs from admitted fleet"
    );
    let retained = &e["retained_capacities"]["auxiliary"]["retained_bookings"];
    let a = &fleet["retry9_auxiliary_commitments"];
    ensure!(a.is_object(), "missing retained build/holding");
    for (k, v) in a.as_object().context("auxiliary")? {
        ensure!(retained[k] == *v, "auxiliary changed {k}");
    }
    for k in [
        "receipt_bindings",
        "build_memory_bytes",
        "build_cpu_quota_micros",
        "holding_memory_bytes",
        "holding_cpu_quota_micros",
        "build_fixed_image_bytes",
        "build_outside_allowance_bytes",
        "holding_staging_bytes",
        "holding_restore_overlap_bytes",
        "holding_serial",
        "build_and_native_qualification_serial",
        "holding_and_build_may_overlap",
        "resource_credit_bytes",
        "reservation_ending_bytes",
    ] {
        ensure!(a[k] == retained[k] && !a[k].is_null(), "lost {k}");
    }
    let (bindings, mem, cpu) = auxiliary_phases::load(fleet)?;
    ensure!(
        retained["phase_admissions"] == bindings
            && mem >= n(retained, "maximum_concurrent_phase_memory_bytes")?
            && cpu >= n(retained, "maximum_concurrent_phase_cpu_quota_micros")?,
        "lost auxiliary phases"
    );
    let native = auxiliary_phases::native(mem, cpu)?;
    let image = Path::new(
        "/home/sol/.jetstreamer-private/epoch168-source-diagnostic-build-20261119-v1/build.ext4",
    );
    let md = fs::symlink_metadata(image)?;
    ensure!(
        image.canonicalize()? == image
            && md.is_file()
            && md.nlink() == 1
            && md.dev() == fs::metadata("/home/sol")?.dev()
            && md.len() == n(a, "build_fixed_image_bytes")?,
        "fixed HOME image changed"
    );
    let remaining = md
        .len()
        .saturating_sub(md.blocks().checked_mul(512).context("image allocation")?);
    let extra_aux = sum(
        sum(
            n(a, "holding_restore_overlap_bytes")?,
            n(a, "holding_staging_bytes")?,
        )?,
        sum(n(a, "build_outside_allowance_bytes")?, remaining)?,
    )?;
    let mut fit = checks["data_accounting"]["current_fit"].clone();
    ensure!(
        fit["retained_growth_already_booked_in_raw_floor_bytes"].is_u64()
            || fit["complete_concurrent_remaining_growth_bytes"].is_u64(),
        "four-lane current fit required"
    );
    // The old allocation scan measures the historical four roots. No byte of active166's disjoint
    // root is used as realized storage. Both admission fits retain the entire independent cap.
    let additional = sum(crate::peer::CAP, extra_aux)?;
    fit["required_raw_available_bytes"] =
        json!(sum(n(&fit, "required_raw_available_bytes")?, additional)?);
    fit["unrelated_growth_margin_bytes"] =
        json!(sum(n(&fit, "unrelated_growth_margin_bytes")?, extra_aux)?);
    fit["additional_growth_not_covered_by_existing_promise_bytes"] = json!(sum(
        n(
            &fit,
            "additional_growth_not_covered_by_existing_promise_bytes"
        )?,
        crate::peer::CAP
    )?);
    audit_budget::validate_fleet_obligation(&fleet["continuing_audit_obligation"])?;
    let audit = audit_budget::observe()?;
    let data = audit_budget::data_requirements(&fit, free)?;
    let mut augmented = checks.clone();
    augmented["complete_memory_plus_reserve_bytes"] =
        json!(sum(n(checks, "complete_memory_plus_reserve_bytes")?, mem)?);
    augmented["memory_accounting"]["required_available_bytes"] = json!(sum(
        n(&checks["memory_accounting"], "required_available_bytes")?,
        mem
    )?);
    augmented["booked_cpu_quota_micros"] = json!(sum(n(checks, "booked_cpu_quota_micros")?, cpu)?);
    let resources = audit_budget::requirements(
        &json!({"resource_checks":augmented}),
        total,
        available,
        cores,
    )?;
    Ok(
        json!({"active166":e["active166"],"active167":e["active167"],"post_guard_capacity166":e["post_guard_capacity"],"retained_167_stop":e["terminal167"],"independent_166_cap_charged_bytes":crate::peer::CAP,"retained_auxiliary":retained,"auxiliary_native":native,"additional_auxiliary_DATA":extra_aux,"audit_native":audit,"audit_home_DATA":data,"audit_additive_resources":resources,"shared_fit":fit,"resource_credit_bytes":0,"promise_ending_bytes":0}),
    )
}
