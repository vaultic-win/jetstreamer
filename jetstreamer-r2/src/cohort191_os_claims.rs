//! Count the authenticated old epoch 141 OS reservations in their successor exactly once.
use super::*;

const TRANSFER: &str =
    "/usr/local/lib/jetstreamer/horizon-cohort191-os-claim-transfer-20261024-v1/transfer.json";
const SUCCESSOR: (&str, &str) = (
    "/usr/local/lib/jetstreamer/horizon-epoch141-export-resource-budget-20261024-v1/budget.json",
    "69512a989f12e722eee4f45f4ca14f8d33ab383e1f791b9f62705e7fb8fcaa9d",
);
const PARENT: (&str, &str) = (
    "/usr/local/lib/jetstreamer/horizon-parent141-export-transfer-20261024-v1/admission.json",
    "8950bd36a8751a536611c541c1251a7c4414ab4bdb33a8f728b778ca73488cf4",
);
const FLOOR: u64 = 205_211_459_014;
const LEGACY_REMAINING: u64 = 8_196_014_080;
const OTHER_MINIMUM: u64 = 23_505_223_680;

fn binding(v: &Value, expected: (&str, &str)) -> Result<Bound> {
    ensure!(
        v.as_object()
            .is_some_and(|m| m.len() == 2 && m.contains_key("path") && m.contains_key("sha256")),
        "191 OS transfer binding shape differs"
    );
    let b: Bound = serde_json::from_value(v.clone())?;
    ensure!(
        b.path == Path::new(expected.0) && b.sha256 == expected.1,
        "191 OS transfer input differs"
    );
    Ok(b)
}

fn documents(t: &Value, old: &Value, next: &Value, parent: &Value, other: u64) -> Result<u64> {
    let fields = [
        "schema",
        "host",
        "mode",
        "original_budget",
        "successor_budget",
        "parent_transfer",
        "physical_free_bytes_credited",
        "reservation_release_authorized",
        "new_execution_authorized",
        "r2_mutations",
    ];
    ensure!(
        t.as_object().is_some_and(
            |m| m.len() == fields.len() && m.keys().all(|k| fields.contains(&k.as_str()))
        ),
        "191 OS transfer has missing/unknown fields"
    );
    ensure!(
        t["schema"] == "jetstreamer-cohort191-os-claim-transfer-v1"
            && t["host"] == "dev-samjohnson"
            && t["mode"] == "same-reservations-counted-once"
            && t["physical_free_bytes_credited"] == 0
            && t["reservation_release_authorized"] == false
            && t["new_execution_authorized"] == false
            && t["r2_mutations"] == false,
        "191 OS transfer grants unrelated authority"
    );
    binding(&t["original_budget"], OS_BUDGET)?;
    binding(&t["successor_budget"], SUCCESSOR)?;
    binding(&t["parent_transfer"], PARENT)?;
    ensure!(
        old["schema"] == "jetstreamer-v1425-portability-os-experiment-budget-v2"
            && old["host"] == "dev-samjohnson"
            && old["minimum_retained_free_bytes"] == FLOOR
            && old["required_initial_free_bytes"] == OLD_OS_PROTECTED
            && old["reservations"]["modern_builder_remaining_bytes"] == 4 * GIB
            && old["reservations"]["legacy_build_and_artifact_staging_increment_bytes"] == 8 * GIB
            && old["reservations"]["fixture_maximum_physical_bytes"] == 10 * GIB
            && old["legacy_target_maximum_physical_bytes"] == 11_232_206_848_u64
            && FLOOR + 22 * GIB == OLD_OS_PROTECTED,
        "191 original OS floor/reservations changed"
    );
    ensure!(
        next["schema"] == "jetstreamer-epoch141-native-export-resource-budget-v3"
            && next["host"] == "dev-samjohnson"
            && next["base_budget"] == t["original_budget"]
            && next["minimum_retained_free_bytes"] == FLOOR
            && next["maximum_aggregate_legacy_and_new_artifacts_physical_bytes"]
                == old["legacy_target_maximum_physical_bytes"]
            && next["legacy_compiler_and_artifact_remaining_bytes"] == LEGACY_REMAINING
            && next["maximum_aggregate_fixture_physical_bytes"] == 10 * GIB
            && next["other_remaining_reservations"]["modern_builder_and_helpers_shared_bytes"]
                == 4 * GIB
            && next["other_remaining_reservations"]["held136_bootstrap_claim_bytes"]
                == (256_u64 << 20)
            && next["other_remaining_reservations"]["held136_saved_decode_claim_bytes"]
                == (8_u64 << 20),
        "191 successor did not retain the same OS obligations"
    );
    ensure!(
        parent["schema"] == "jetstreamer-parent141-export-successor-transfer-v1"
            && parent["host"] == "dev-samjohnson"
            && parent["budget"] == t["successor_budget"]
            && parent["transfer"]["legacy_aggregate_cap_bytes"] == 11_232_206_848_u64
            && parent["transfer"]["legacy_already_consumed_bytes"] == 3_036_209_152_u64
            && parent["transfer"]["legacy_remaining_bytes"] == 8_195_997_696_u64
            && parent["transfer"]["aggregate_fixture_cap_bytes"] == 10 * GIB
            && parent["transfer"]["physical_free_space_credit"] == 0
            && parent["transfer"]["old_files_preserved"] == true
            && parent["transfer"]["epoch141_repair_closed"] == false
            && parent["transfer"]["all_original_production_claims_and_guard_floors_retained"]
                == true
            && parent["mainnet_or_production_replay_authorized"] == false
            && parent["r2_mutations_authorized"] == false
            && parent["local_archive_retirement_authorized"] == false,
        "191 lacks the exact parent-authorized successor transfer"
    );
    ensure!(
        LEGACY_REMAINING + 14 * GIB + (264_u64 << 20) == OTHER_MINIMUM && other >= OTHER_MINIMUM,
        "191 transferred OS obligations were dropped or counted as free space"
    );
    // Only the base changes: other retains modern 4 GiB, original full legacy
    // remaining allowance, fixture 10 GiB and both epoch 136 claims. No consumed credit.
    Ok(FLOOR)
}

pub(super) fn base(transfer: Option<&Bound>, other: u64) -> Result<u64> {
    let Some(t) = transfer else {
        return Ok(OLD_OS_PROTECTED);
    };
    ensure!(
        t.path == Path::new(TRANSFER),
        "foreign191 OS transfer policy"
    );
    let t = custody::bound(t, true)?;
    let old = custody::bound(&binding(&t["original_budget"], OS_BUDGET)?, true)?;
    let next = custody::bound(&binding(&t["successor_budget"], SUCCESSOR)?, true)?;
    let parent = custody::bound(&binding(&t["parent_transfer"], PARENT)?, true)?;
    documents(&t, &old, &next, &parent, other)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Value, Value, Value, Value) {
        let b = |x: (&str, &str)| json!({"path":x.0,"sha256":x.1});
        let t = json!({"schema":"jetstreamer-cohort191-os-claim-transfer-v1","host":"dev-samjohnson","mode":"same-reservations-counted-once","original_budget":b(OS_BUDGET),"successor_budget":b(SUCCESSOR),"parent_transfer":b(PARENT),"physical_free_bytes_credited":0,"reservation_release_authorized":false,"new_execution_authorized":false,"r2_mutations":false});
        let old = json!({"schema":"jetstreamer-v1425-portability-os-experiment-budget-v2","host":"dev-samjohnson","minimum_retained_free_bytes":FLOOR,"required_initial_free_bytes":OLD_OS_PROTECTED,"legacy_target_maximum_physical_bytes":11_232_206_848_u64,"reservations":{"modern_builder_remaining_bytes":4*GIB,"legacy_build_and_artifact_staging_increment_bytes":8*GIB,"fixture_maximum_physical_bytes":10*GIB}});
        let next = json!({"schema":"jetstreamer-epoch141-native-export-resource-budget-v3","host":"dev-samjohnson","base_budget":b(OS_BUDGET),"minimum_retained_free_bytes":FLOOR,"maximum_aggregate_legacy_and_new_artifacts_physical_bytes":11_232_206_848_u64,"legacy_compiler_and_artifact_remaining_bytes":LEGACY_REMAINING,"maximum_aggregate_fixture_physical_bytes":10*GIB,"other_remaining_reservations":{"modern_builder_and_helpers_shared_bytes":4*GIB,"held136_bootstrap_claim_bytes":256_u64<<20,"held136_saved_decode_claim_bytes":8_u64<<20}});
        let parent = json!({"schema":"jetstreamer-parent141-export-successor-transfer-v1","host":"dev-samjohnson","budget":b(SUCCESSOR),"transfer":{"legacy_aggregate_cap_bytes":11_232_206_848_u64,"legacy_already_consumed_bytes":3_036_209_152_u64,"legacy_remaining_bytes":8_195_997_696_u64,"aggregate_fixture_cap_bytes":10*GIB,"physical_free_space_credit":0,"old_files_preserved":true,"epoch141_repair_closed":false,"all_original_production_claims_and_guard_floors_retained":true},"mainnet_or_production_replay_authorized":false,"r2_mutations_authorized":false,"local_archive_retirement_authorized":false});
        (t, old, next, parent)
    }
    #[test]
    fn single_count_preserves_floor_all_claims_and_extra_allowances() {
        let (t, o, n, p) = fixture();
        assert_eq!(documents(&t, &o, &n, &p, OTHER_MINIMUM).unwrap(), FLOOR);
        assert_eq!(
            documents(&t, &o, &n, &p, OTHER_MINIMUM + GIB).unwrap(),
            FLOOR
        );
        assert_eq!(FLOOR + OTHER_MINIMUM + OS_ALLOWANCE, 229_261_942_214);
        assert_eq!(base(None, OTHER_MINIMUM).unwrap(), OLD_OS_PROTECTED);
        assert!(documents(&t, &o, &n, &p, OTHER_MINIMUM - 1).is_err());
    }
    #[test]
    fn rejects_release_authority_foreign_sources_and_weakened_obligations() {
        let (t, o, n, p) = fixture();
        let mut unknown = t.clone();
        unknown["archive_publication_authorized"] = json!(true);
        assert!(documents(&unknown, &o, &n, &p, OTHER_MINIMUM).is_err());
        let mut alias = t.clone();
        alias["original_budget"]["extra"] = json!(true);
        assert!(documents(&alias, &o, &n, &p, OTHER_MINIMUM).is_err());
        for pointer in [
            "/reservation_release_authorized",
            "/new_execution_authorized",
            "/r2_mutations",
        ] {
            let mut bad = t.clone();
            *bad.pointer_mut(pointer).unwrap() = json!(true);
            assert!(documents(&bad, &o, &n, &p, OTHER_MINIMUM).is_err());
        }
        for pointer in [
            "/original_budget/sha256",
            "/successor_budget/path",
            "/parent_transfer/sha256",
        ] {
            let mut bad = t.clone();
            *bad.pointer_mut(pointer).unwrap() = json!("foreign");
            assert!(documents(&bad, &o, &n, &p, OTHER_MINIMUM).is_err());
        }
        for pointer in [
            "/minimum_retained_free_bytes",
            "/reservations/fixture_maximum_physical_bytes",
            "/legacy_target_maximum_physical_bytes",
        ] {
            let mut bad = o.clone();
            *bad.pointer_mut(pointer).unwrap() = json!(1);
            assert!(documents(&t, &bad, &n, &p, OTHER_MINIMUM).is_err());
        }
        for pointer in [
            "/minimum_retained_free_bytes",
            "/maximum_aggregate_legacy_and_new_artifacts_physical_bytes",
            "/other_remaining_reservations/modern_builder_and_helpers_shared_bytes",
            "/other_remaining_reservations/held136_bootstrap_claim_bytes",
        ] {
            let mut bad = n.clone();
            *bad.pointer_mut(pointer).unwrap() = json!(0);
            assert!(documents(&t, &o, &bad, &p, OTHER_MINIMUM).is_err());
        }
        for pointer in [
            "/transfer/old_files_preserved",
            "/transfer/all_original_production_claims_and_guard_floors_retained",
        ] {
            let mut bad = p.clone();
            *bad.pointer_mut(pointer).unwrap() = json!(false);
            assert!(documents(&t, &o, &n, &bad, OTHER_MINIMUM).is_err());
        }
    }
}
