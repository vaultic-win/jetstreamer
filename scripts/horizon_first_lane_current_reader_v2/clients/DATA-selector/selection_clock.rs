//! Compare the fully reconstructed current selection with its immutable original.
//! Only the newly reconstructed top-level evaluation clock varies. Every original
//! timestamp and every request, source, census, baseline and budget field stays exact.
use crate::fsutil as f;
use anyhow::{Result, ensure};
use serde_json::{Value, json};

pub fn validate(original: &Value, current: &Value, now: u64) -> Result<()> {
    let accepted = f::n(original, "recorded_unix_seconds")?;
    f::fresh(accepted, now, 300)?;
    ensure!(
        f::n(current, "recorded_unix_seconds")? == now,
        "reconstructed selection is not from the actual current evaluation clock"
    );
    ensure!(
        original["schema"] == "terminal199-parent-only-effective-memory-selection-v1",
        "original selector evidence schema differs"
    );
    // This is a disposable comparison copy. Neither source receipt nor the
    // genuinely current opaque view is modified or re-stamped.
    let mut comparable = current.clone();
    comparable["recorded_unix_seconds"] = json!(accepted);
    ensure!(
        comparable == *original,
        "current parent-only view differs from original selection beyond its evaluation clock"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn selected(at: u64) -> Value {
        json!({"schema":"terminal199-parent-only-effective-memory-selection-v1",
        "recorded_unix_seconds":at,"current_census_recorded_unix_seconds":90,
        "request":{"current":{"observer":{"path":"/observer","sha256":"unchanged"}},
            "census":{"path":"/census","sha256":"unchanged"}},
        "baseline_evidence":{"recorded_unix_seconds":89,"effective_total":400},
        "raw_original199_memory_bytes":207232172032u64,
        "original199_parent_retirement_bytes":206158430208u64,
        "retained_original199_DATA_bytes":824633720832u64})
    }
    #[test]
    fn later_current_clock_preserves_every_original_timestamp_and_view() {
        let original = selected(100);
        let current = selected(105);
        let original_bytes = serde_json::to_vec(&original).unwrap();
        let current_bytes = serde_json::to_vec(&current).unwrap();
        validate(&original, &current, 105).unwrap();
        assert_eq!(serde_json::to_vec(&original).unwrap(), original_bytes);
        assert_eq!(serde_json::to_vec(&current).unwrap(), current_bytes);
        assert_ne!(original, current); // Reproduces the old whole-evidence failure.
    }
    #[test]
    fn stale_future_zero_or_noncurrent_evaluation_clock_is_rejected() {
        assert!(validate(&selected(100), &selected(400), 400).is_ok());
        assert!(validate(&selected(100), &selected(401), 401).is_err());
        assert!(validate(&selected(106), &selected(105), 105).is_err());
        assert!(validate(&selected(0), &selected(105), 105).is_err());
        assert!(validate(&selected(100), &selected(104), 105).is_err());
    }
    #[test]
    fn nested_source_and_census_timestamps_are_never_normalized() {
        let original = selected(100);
        let mut current = selected(105);
        current["baseline_evidence"]["recorded_unix_seconds"] = json!(105);
        assert!(validate(&original, &current, 105).is_err());
        let mut current = selected(105);
        current["current_census_recorded_unix_seconds"] = json!(105);
        assert!(validate(&original, &current, 105).is_err());
    }
    #[test]
    fn current_request_census_raw_memory_or_retirement_mutation_is_rejected() {
        let original = selected(100);
        for key in [
            "raw_original199_memory_bytes",
            "original199_parent_retirement_bytes",
            "retained_original199_DATA_bytes",
        ] {
            let mut current = selected(105);
            current[key] = json!(0);
            assert!(validate(&original, &current, 105).is_err());
        }
        let mut current = selected(105);
        current["request"]["census"]["sha256"] = json!("changed");
        assert!(validate(&original, &current, 105).is_err());
        let mut current = selected(105);
        current["request"]["current"]["observer"]["sha256"] = json!("changed");
        assert!(validate(&original, &current, 105).is_err());
    }
}

#[cfg(test)]
mod completed145_tests {
    use super::*;
    fn selected(at: u64) -> Value {
        json!({"schema":"terminal199-parent-only-effective-memory-selection-v1",
            "recorded_unix_seconds":at,"original199_parent_retirement_bytes":192u64<<30,
            "completed_cached145_parent_retirement_bytes":192u64<<30,
            "completed_cached145_selection":{"request":{"registration":{"path":"/test/registration","sha256":"a".repeat(64)},
                "census":{"path":"/test/census","sha256":"b".repeat(64)}},
                "retained_guard_bytes":512u64<<20,"retained_DATA_bytes":337u64<<30,"physical_credit_bytes":0,"DATA_credit_bytes":0},
            "effective_total_memory_promises_bytes":341795667968u64})
    }
    #[test]
    fn completed145_extension_is_preserved_across_only_the_top_level_clock_change() {
        let original = selected(100);
        let current = selected(105);
        let original_before = original.clone();
        let current_before = current.clone();
        validate(&original, &current, 105).unwrap();
        assert_eq!(original, original_before);
        assert_eq!(current, current_before);
    }
    #[test]
    fn completed145_census_parent_guard_data_or_effective_budget_cannot_drift() {
        let original = selected(100);
        for pointer in [
            "/completed_cached145_parent_retirement_bytes",
            "/completed_cached145_selection/retained_guard_bytes",
            "/completed_cached145_selection/retained_DATA_bytes",
            "/completed_cached145_selection/physical_credit_bytes",
            "/effective_total_memory_promises_bytes",
        ] {
            let mut current = selected(105);
            *current.pointer_mut(pointer).unwrap() = json!(7);
            assert!(validate(&original, &current, 105).is_err(), "{pointer}");
        }
        let mut current = selected(105);
        current["completed_cached145_selection"]["request"]["census"]["sha256"] =
            json!("c".repeat(64));
        assert!(validate(&original, &current, 105).is_err());
    }
}
