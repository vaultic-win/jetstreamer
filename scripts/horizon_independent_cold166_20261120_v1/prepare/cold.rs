//! The original lane stays charged in the historical fleet, with a distinct empty cold lane.
use super::*;

pub(super) const LANE: &str =
    "/home/sol/.jetstreamer-private/epoch166-independent-cold-20261120-v1";
pub(super) const ATTEMPT: &str = "replacement-local3retry9-20261110-v1";
pub(super) const UNIT: &str = "horizon-qualify-independent-cold166-20261120-v1.service";
const GUARD: &str = "horizon-guard-independent-cold166-20261120-v1";
const ROOTS: &str = "/var/lib/jetstreamer/horizon_runtime_data/root0245-zero-recovery-20261120-v1/INDEPENDENT_COLD_ROOTS_BEFORE_WITNESS.json";
const ROOTS_SHA: &str = "40bd46800a52705e1dcb485edb09f36d8122adb541e430a4b549caa92f13c7fa";

pub(super) fn roots_binding() -> Bound {
    Bound {
        path: ROOTS.into(),
        sha256: ROOTS_SHA.into(),
    }
}
pub(super) fn selected(p: &Plan) -> bool {
    p.epoch == 166 && p.attempt == "local3retry9" && p.producer_unit == UNIT
}
pub(super) fn validate_plan(p: &Plan) -> Result<()> {
    ensure!(
        selected(p)
            && p.guard_base == GUARD
            && p.fresh_subtree == Path::new(LANE).join(ATTEMPT)
            && p.existing_preparation.is_none()
            && p.local_inputs.is_some(),
        "wrong independent route or missing local inputs"
    );
    for unit in [
        "horizon-qualify-166-replacement-local3retry9-20261110-v1.service",
        "horizon-guard-replacement-166-local3retry9-20261110-v1.timer",
        "horizon-guard-replacement-166-local3retry9-20261110-v1.service",
    ] {
        ensure!(
            p.closed_units.iter().any(|s| s == unit),
            "old unlaunched shared-slot route missing from census: {unit}"
        );
    }
    let proof = bound(&roots_binding())?;
    ensure!(
        proof["schema"] == "horizon-independent-cold-roots-before-witness-v1"
            && proof["owner"] == "/root"
            && proof["primary_thread"] == THREAD
            && proof["existing_attempts_retained"] == true
            && proof["resource_credit_bytes"] == 0
            && proof["replay_admission"] == false,
        "wrong independent root provenance"
    );
    let home = fs::metadata("/home/sol")?;
    let rows = proof["roots"].as_array().context("independent roots")?;
    ensure!(rows.len() == 3, "missing independent roots");
    for ((e, g), row) in [(166u64, 9), (167, 8), (170, 7)].into_iter().zip(rows) {
        let lane = PathBuf::from(format!(
            "/home/sol/.jetstreamer-private/epoch{e}-independent-cold-20261120-v1"
        ));
        let attempt = lane.join(format!("replacement-local3retry{g}-20261110-v1"));
        ensure!(
            row["epoch"] == e
                && row["lane"] == json!(lane)
                && row["attempt_root"] == json!(attempt)
                && row["empty_attempt"] == true,
            "wrong accepted independent root {e}"
        );
        for (field, path) in [("lane_inode", &lane), ("attempt_inode", &attempt)] {
            let m = directory(path)?.metadata()?;
            ensure!(
                m.is_dir()
                    && m.dev() == home.dev()
                    && row["device"] == m.dev()
                    && row[field] == m.ino()
                    && m.uid() == 1001
                    && m.gid() == 1003
                    && m.mode() & 0o7777 == 0o700,
                "independent root changed: {}",
                path.display()
            );
        }
    }
    let mut members = fs::read_dir(LANE)?;
    let entry = members.next().context("missing independent attempt")??;
    ensure!(
        entry.path() == p.fresh_subtree && members.next().is_none(),
        "cold lane has other occupants"
    );
    let contract = &p
        .data_fulfillment
        .as_ref()
        .context("independent guard binding")?
        .contract
        .contract;
    let c = bound(&Bound {
        path: contract.path.clone(),
        sha256: contract.sha256.clone(),
    })?;
    let w = bound(&serde_json::from_value(
        c["qualified_native_witness"].clone(),
    )?)?;
    ensure!(
        w["recorded_unix_seconds"]
            .as_u64()
            .context("witness clock")?
            >= proof["at"].as_u64().context("root clock")?,
        "guard witness predates independent roots"
    );
    Ok(())
}

pub(super) fn review(r: &Review) -> Result<()> {
    let remaining = ROOT_CAP
        .checked_sub(r.retained_lane_physical_bytes)
        .context("historical lane exceeds retained cap")?;
    ensure!(
        r.retained_lane_physical_bytes > 0
            && !r.exclusive_original_slot_replacement
            && r.existing_original_slot_future_growth_bytes == remaining
            && r.proposed_fresh_working_maximum_bytes == ROOT_CAP
            && r.candidate_remaining_growth_bytes == ROOT_CAP
            && r.additional_growth_not_covered_by_existing_promise_bytes == ROOT_CAP,
        "independent cold admission must retain the original allowance and fund a full separate cap"
    );
    Ok(())
}

pub(super) fn validate_retained_ledger(mapping: &Value, p: &Plan, r: &Review) -> Result<()> {
    ensure!(
        mapping["schema"] == "horizon-independent-cold166-DATA-mapping-v1"
            && mapping["owner"] == "/root"
            && mapping["epoch"] == 166
            && mapping["fleet"] == json!(p.fleet)
            && mapping["historical_lane"] == profile(166)?.lane
            && mapping["independent_lane"] == LANE
            && mapping["retained_original_cap_bytes"] == ROOT_CAP
            && mapping["new_independent_cap_bytes"] == ROOT_CAP
            && mapping["retained_lane_physical_bytes"] == r.retained_lane_physical_bytes
            && mapping["resource_credit_bytes"] == 0
            && mapping["resource_promise_ending_bytes"] == 0,
        "expected independent mapping with both whole-lane obligations"
    );
    let ledger = bound(&serde_json::from_value(mapping["physical_ledger"].clone())?)?;
    ensure!(
        ledger["schema"] == "horizon-standard-replacement-local-physical-ledger-v1"
            && ledger["lane_root"] == profile(166)?.lane
            && ledger["fleet"] == json!(p.fleet)
            && ledger["physical"]["physical_bytes"] == r.retained_lane_physical_bytes
            && ledger["read_only"] == true
            && ledger["resource_credit_bytes"] == 0
            && ledger["replay_launch_authorized"] == false,
        "wrong retained historical lane measurement"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cold_producer_routes_the_authenticated_original_argv_to_its_own_writable_root() {
        let mut plan = crate::tests::plan();
        plan.attempt = "local3retry9".into();
        plan.producer_unit = UNIT.into();
        plan.guard_base = GUARD.into();
        plan.fresh_subtree = Path::new(LANE).join(ATTEMPT);
        let source = profile(166).unwrap();
        let original: Vec<String> = serde_json::from_value(
            bound(&Bound {
                path: source.argv.into(),
                sha256: source.argv_sha.into(),
            })
            .unwrap(),
        )
        .unwrap();
        let args = producer_recipe(&original, &plan, source).unwrap();
        for (prefix, expected) in [
            ("--property=ReadWritePaths=", LANE.to_owned()),
            (
                "--property=ExecPaths=",
                format!(
                    "{0}/jetstreamer-node {0}/jetstreamer-historical-worker-v1-5-6 {LANE}",
                    source.package
                ),
            ),
            (
                "--setenv=XDG_CONFIG_HOME=",
                format!("{}/config", source.lane),
            ),
            (
                "--setenv=CLOUDSDK_CONFIG=",
                format!("{}/config/gcloud", source.lane),
            ),
            ("--property=MemoryMax=", "73014444032".to_owned()),
        ] {
            assert_eq!(
                args.iter()
                    .filter_map(|arg| arg.strip_prefix(prefix))
                    .collect::<Vec<_>>(),
                vec![expected.as_str()]
            );
        }
    }

    #[test]
    fn disjoint_lane_preserves_old_slot_and_funds_the_new_cap_whole() {
        let p = crate::tests::plan();
        let mut r = crate::tests::review(&p);
        r.exclusive_original_slot_replacement = false;
        r.retained_lane_physical_bytes = 269_184_225_280;
        r.existing_original_slot_future_growth_bytes = ROOT_CAP - r.retained_lane_physical_bytes;
        r.proposed_fresh_working_maximum_bytes = ROOT_CAP;
        r.candidate_remaining_growth_bytes = ROOT_CAP;
        r.additional_growth_not_covered_by_existing_promise_bytes = ROOT_CAP;
        review(&r).unwrap();
        r.additional_growth_not_covered_by_existing_promise_bytes -= 1;
        assert!(review(&r).is_err());
    }
}
