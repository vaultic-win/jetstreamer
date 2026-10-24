//! Full210 candidate admission from the complete current fleet, never native-only.
use super::{singleton210 as c, *};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    resource_basis: Value,
    resource_plan: BoundFile,
    capability: BoundFile,
    native_input: BoundFile,
    output: PathBuf,
}
pub(super) fn owners(f: &Value, current: &BTreeMap<String, Value>) -> Result<()> {
    native210_peer_history::current(f, current)?;
    prefix223_live_peer::current(f, current)?;
    singleton227_admission::owners(f, current)
}
fn memory(o: &Value) -> Result<()> {
    let m = &o["lane_rss_history"]["200"];
    let observed = m["maximum_observed_lane_rss_bytes"]
        .as_u64()
        .filter(|n| *n > 0)
        .context("210 century RSS missing")?;
    let ceiling = observed
        .checked_mul(3)
        .context("210 century RSS overflow")?
        / 2;
    ensure!(
        m["reservation_ceiling_bytes"] == ceiling && c::MEMORY <= ceiling,
        "210 full memory cap exceeds1.5x maximum observed century RSS"
    );
    ensure!(
        o["vm_max_map_count"].as_u64().is_some_and(|n| n >= 4194304),
        "210 VMA system floor missing"
    );
    let pressure = &o["host_global_pressure"]["cross_sample"];
    let elapsed = pressure["elapsed_millis"]
        .as_u64()
        .filter(|n| *n > 0)
        .context("210 pressure interval missing")?;
    ensure!(pressure["status"] == "observed", "210 pressure unobserved");
    for (counter, fraction) in [
        ("memory.full_total_usec", 100u64),
        ("cpu.some_total_usec", 500),
        ("io.full_total_usec", 100),
    ] {
        ensure!(
            pressure["counter_delta_usec"][counter]
                .as_u64()
                .is_some_and(|n| n <= elapsed.saturating_mul(fraction)),
            "210 pressure gate failed:{counter}"
        );
    }
    Ok(())
}
pub(super) fn run() -> Result<()> {
    let (binding, self_sha) = publication203::parsed_args("admit-singleton210")?;
    let s: Spec = serde_json::from_value(native210::immutable_json(&binding)?)?;
    ensure!(
        s.schema == "jetstreamer-private-epoch210-singleton-admission-spec-v1"
            && s.output.parent().and_then(Path::parent) == Some(Path::new("/var/lib/jetstreamer"))
            && s.output
                .parent()
                .and_then(Path::file_name)
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("horizon-210-singleton-admission-"))
            && s.output.file_name().is_some_and(|n| n == "admission.json")
            && s.capability.path == Path::new(c::CAPABILITY),
        "210 full admission namespace differs"
    );
    c::capability(&native210::immutable_json(&s.capability)?)?;
    c::native(&s.native_input)?;
    singleton210_capability::inputs()?;
    let resource = native210::immutable_json(&s.resource_plan)?;
    ensure!(
        resource["schema"] == "jetstreamer-private-epoch210-singleton-resource-plan-v1"
            && resource["epoch"] == 210
            && resource["mode"] == "replay"
            && resource["unit"] == c::UNIT
            && resource["run_root"] == c::ROOT
            && resource["candidate_incremental_peak_bytes"] == c::PEAK
            && resource["maximum_scratch_bytes"] == c::SCRATCH
            && resource["phase_metadata_reservation_bytes"] == c::METADATA_RESERVE
            && resource["memory_max_bytes"] == c::MEMORY
            && resource["memory_high_bytes"] == 150000000000u64
            && resource["node_sha256"] == c::NODE_SHA
            && resource["worker_sha256"] == c::WORKER_SHA
            && resource["manifest_fingerprint"] == c::FINGERPRINT,
        "210 resource plan is not the sealed full-epoch envelope"
    );
    c::no_publication(&resource)?;
    let observer: BoundFile = serde_json::from_value(s.resource_basis["observer"].clone())?;
    let fleet: BoundFile = serde_json::from_value(s.resource_basis["fleet"].clone())?;
    let o = bound_json(&observer)?;
    let f = bound_json(&fleet)?;
    ensure!(
        !f["active"]
            .as_array()
            .context("210 complete active census")?
            .iter()
            .any(|r| r["epoch"] == 210),
        "210 already has active work; do not launch a duplicate"
    );
    memory(&o)?;
    let capacity = maintenance_capacity::check_singleton210(
        &s.resource_basis,
        singleton227_admission::century_floor_for(&f, 210)?,
    )?;
    let names = f["unit_census"]
        .as_object()
        .context("210 complete unit census")?
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    let before = census(&names, 201, 300)?;
    owners(&f, &before)?;
    let candidate = unit(c::UNIT)?;
    ensure!(
        candidate["MainPID"] == "0"
            && candidate["NRestarts"] == "0"
            && matches!(
                candidate["ActiveState"].as_str(),
                Some("inactive" | "failed")
            )
            && matches!(candidate["SubState"].as_str(), Some("dead" | "failed")),
        "210 candidate is already live or has restart history"
    );
    let pending = ProcessCommand::new("/usr/bin/systemctl")
        .args(["list-jobs", "--no-legend", "--plain", "--no-pager"])
        .output()?;
    ensure!(
        pending.status.success()
            && pending.stdout.len() <= 1 << 20
            && !std::str::from_utf8(&pending.stdout)?
                .split_whitespace()
                .any(|w| w == c::UNIT),
        "210 candidate has a pending job"
    );
    ensure!(
        before == census(&names, 201, 300)? && candidate == unit(c::UNIT)?,
        "210 admission owners changed"
    );
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let guarded_floor = capacity["minimum_free_bytes"]
        .as_u64()
        .context("210 protected capacity floor")?
        .checked_add(c::METADATA_RESERVE)
        .context("210 guarded metadata overflow")?;
    let mut receipt = json!({"schema":"jetstreamer-private-epoch210-singleton-admission-v1","epoch":210,"mode":"replay",
        "admitted":true,"unit":c::UNIT,"private_run_root":c::ROOT,"candidate_incremental_peak_bytes":c::PEAK,
        "maximum_scratch_bytes":c::SCRATCH,"maximum_memory_bytes":c::MEMORY,"memory_target_percent":90,
        "phase_metadata_reservation_bytes":c::METADATA_RESERVE,
        "capability":private157::binding(&s.capability),"native_input":private157::binding(&s.native_input),
        "resource_plan":private157::binding(&s.resource_plan),"resource_basis":s.resource_basis,"capacity":capacity,"observer":private157::binding(&observer),"fleet":private157::binding(&fleet),
        "protected_existing_floor_bytes":guarded_floor,"protected_live_floor_bytes":capacity["minimum_free_bytes"],
        "required_initial_free_bytes":capacity["required_initial_free_bytes"],
        "fresh_complete_census_passed":true,"older_producers_and_guards_preserved":true,"unit_census_before":before,
        "recorded_unix_seconds":now,"sampled_at_utc":o["recorded_at_utc"],"resource_samples_taken":0,
        "spec":private157::binding(&binding),"helper_sha256":self_sha,"guard_first_fire_required":true});
    for flag in [
        "runtime_promotion_authorized",
        "full_epoch_qualified",
        "canonical_sidecar_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        receipt[flag] = json!(false);
    }
    c::no_publication(&receipt)?;
    if s.output.try_exists()? {
        let old = native210::immutable_json(&serde_json::from_value(private157::file_binding(
            &s.output,
        )?)?)?;
        let recorded = old["recorded_unix_seconds"]
            .as_u64()
            .context("210 prior admission clock")?;
        ensure!(
            old["schema"] == receipt["schema"]
                && old["spec"] == receipt["spec"]
                && old["helper_sha256"] == receipt["helper_sha256"]
                && old["capability"] == receipt["capability"]
                && old["native_input"] == receipt["native_input"]
                && old["resource_plan"] == receipt["resource_plan"]
                && old["phase_metadata_reservation_bytes"] == c::METADATA_RESERVE
                && recorded <= now
                && now - recorded <= 900
                && old["protected_existing_floor_bytes"]
                    .as_u64()
                    .is_some_and(|n| n >= guarded_floor)
                && old["required_initial_free_bytes"]
                    .as_u64()
                    .is_some_and(|n| capacity["actual_available_bytes"]
                        .as_u64()
                        .is_some_and(|free| free >= n)
                        && capacity["sampled_available_bytes"]
                            .as_u64()
                            .is_some_and(|free| free >= n)),
            "210 prior admission is stale, conflicting or no longer fits; use a fresh sealed plan"
        );
        c::no_publication(&old)?;
        return Ok(());
    }
    validate_output_destination(&s.output)?;
    private157::immutable_receipt(&s.output, &receipt)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn full210_memory_uses_observed_century_ceiling_and_separate_pressure_vma_gates() {
        let mut o = json!({"lane_rss_history":{"200":{"maximum_observed_lane_rss_bytes":150000000000u64,"reservation_ceiling_bytes":225000000000u64}},
            "vm_max_map_count":4194304,"host_global_pressure":{"cross_sample":{"status":"observed","elapsed_millis":1000,
                "counter_delta_usec":{"memory.full_total_usec":0,"cpu.some_total_usec":0,"io.full_total_usec":0}}}});
        memory(&o).unwrap();
        o["lane_rss_history"]["200"]["reservation_ceiling_bytes"] = json!(300000000000u64);
        assert!(memory(&o).is_err());
        o["lane_rss_history"]["200"]["reservation_ceiling_bytes"] = json!(225000000000u64);
        o["host_global_pressure"]["cross_sample"]["counter_delta_usec"]["memory.full_total_usec"] =
            json!(100001);
        assert!(memory(&o).is_err());
    }
    #[test]
    fn plan_cannot_choose_a_smaller_native_budget_or_skip_the_complete_peer_census() {
        let b = json!({"path":"/sealed/evidence.json","sha256":"a".repeat(64)});
        let good = json!({"schema":"jetstreamer-private-epoch210-singleton-admission-spec-v1","resource_basis":{},"resource_plan":b,"capability":b,"native_input":b,"output":"/private/admission.json"});
        assert!(serde_json::from_value::<Spec>(good.clone()).is_ok());
        for field in [
            "scratch_bytes",
            "memory_max_bytes",
            "ignore_peer",
            "skip_native",
            "launch",
        ] {
            let mut bad = good.clone();
            bad[field] = json!(true);
            assert!(serde_json::from_value::<Spec>(bad).is_err(), "{field}");
        }
    }
}
