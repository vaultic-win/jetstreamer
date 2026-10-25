//! Audit the existing late admission decision without changing its policy.
use super::*;
use std::os::unix::fs::PermissionsExt;

#[derive(Debug, Serialize)]
pub(super) struct LateValues {
    pub growth_before: u64,
    pub growth_after: u64,
    pub auxiliary_before: u64,
    pub auxiliary_after: u64,
    pub required_memory_before: u64,
    pub required_memory_after: u64,
    pub required_disk: u64,
    pub sampled_disk_available: u64,
    pub sampled_memory_available: u64,
    pub disk_before: u64,
    pub disk_after: u64,
    pub memory_before: u64,
    pub memory_after: u64,
}

#[derive(Debug, Serialize)]
pub(super) struct Predicates {
    pub exact_census_unchanged: bool,
    pub exact_caps_unchanged: bool,
    pub growth_nonincreasing: bool,
    pub auxiliary_nonincreasing: bool,
    pub required_memory_nonincreasing: bool,
    pub disk_fits: bool,
    pub memory_fits: bool,
}
impl Predicates {
    pub fn passed(&self) -> bool {
        self.exact_census_unchanged
            && self.exact_caps_unchanged
            && self.growth_nonincreasing
            && self.auxiliary_nonincreasing
            && self.required_memory_nonincreasing
            && self.disk_fits
            && self.memory_fits
    }
}
pub(super) fn predicates(v: &LateValues, same_census: bool, same_caps: bool) -> Predicates {
    Predicates {
        exact_census_unchanged: same_census,
        exact_caps_unchanged: same_caps,
        growth_nonincreasing: v.growth_after <= v.growth_before,
        auxiliary_nonincreasing: v.auxiliary_after <= v.auxiliary_before,
        required_memory_nonincreasing: v.required_memory_after <= v.required_memory_before,
        disk_fits: v.disk_before.min(v.disk_after) >= v.required_disk,
        memory_fits: v.memory_before.min(v.memory_after) >= v.required_memory_before,
    }
}

/// Maxima of complete, independently checked obligations. The caller must
/// recompute disk floors and memory policy using max(before, after) peer growth
/// first; this helper cannot replace native223/canary floor accounting.
pub(in crate::fleet) fn bracketed_requirements(
    disk_before: u64,
    disk_after_max_growth_recompute: u64,
    memory_before: u64,
    memory_after: u64,
    memory_after_max_auxiliary_recompute: u64,
) -> (u64, u64) {
    (
        disk_before.max(disk_after_max_growth_recompute),
        memory_before
            .max(memory_after)
            .max(memory_after_max_auxiliary_recompute),
    )
}

/// Explicitly include the accepted observation as well as both current brackets.
/// A higher recomputed obligation must not borrow capacity that existed only in
/// one bracket or appeared after the accepted resource observation.
pub(in crate::fleet) fn bracketed_fit(
    same_census: bool,
    same_caps: bool,
    disk_required: u64,
    memory_required: u64,
    disk_available: [u64; 3],
    memory_available: [u64; 3],
) -> bool {
    same_census
        && same_caps
        && disk_available[0]
            .min(disk_available[1])
            .min(disk_available[2])
            >= disk_required
        && memory_available[0]
            .min(memory_available[1])
            .min(memory_available[2])
            >= memory_required
}

/// Caller has already refused admission. A private durable diagnostic never
/// constitutes a positive admission, resource observation or launch receipt.
pub(super) fn persist_failure(output: &Path, at: u64, pid: u32, value: &Value) -> Result<PathBuf> {
    let parent = output_destination(output)?;
    let before = ancestry(output)?;
    let path = parent.join(format!("admission-failure-{at}-{pid}.json"));
    let mut data = serde_json::to_vec_pretty(value)?;
    data.push(b'\n');
    ensure!(
        data.len() <= 4 << 20,
        "failed-admission audit exceeds metadata bound"
    );
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.as_file()
        .set_permissions(fs::Permissions::from_mode(0o400))?;
    file.as_file_mut().write_all(&data)?;
    file.as_file().sync_all()?;
    ensure!(
        ancestry(output)? == before,
        "failed-admission audit parent changed"
    );
    file.persist_noclobber(&path)
        .map_err(|e| anyhow!("failed-admission audit conflict: {e}"))?;
    File::open(parent)?.sync_all()?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> LateValues {
        LateValues {
            growth_before: 100,
            growth_after: 90,
            auxiliary_before: 200,
            auxiliary_after: 190,
            required_memory_before: 700,
            required_memory_after: 690,
            required_disk: 800,
            sampled_disk_available: 1000,
            sampled_memory_available: 1000,
            disk_before: 1000,
            disk_after: 990,
            memory_before: 1000,
            memory_after: 990,
        }
    }
    #[test]
    fn every_late_failure_term_is_separately_identified_without_changing_the_gate() {
        let value = fixture();
        assert!(predicates(&value, true, true).passed());
        assert!(!predicates(&value, false, true).exact_census_unchanged);
        assert!(!predicates(&value, true, false).exact_caps_unchanged);
        let bad = LateValues {
            growth_after: 101,
            ..fixture()
        };
        let p = predicates(&bad, true, true);
        assert!(!p.passed());
        assert!(!p.growth_nonincreasing);
        assert!(p.disk_fits && p.memory_fits);
        let bad = LateValues {
            auxiliary_after: 201,
            ..fixture()
        };
        assert!(!predicates(&bad, true, true).auxiliary_nonincreasing);
        let bad = LateValues {
            required_memory_after: 701,
            ..fixture()
        };
        assert!(!predicates(&bad, true, true).required_memory_nonincreasing);
        let bad = LateValues {
            disk_after: 799,
            ..fixture()
        };
        assert!(!predicates(&bad, true, true).disk_fits);
        let bad = LateValues {
            memory_after: 699,
            ..fixture()
        };
        assert!(!predicates(&bad, true, true).memory_fits);
    }
    #[test]
    fn cache_shrink_is_diagnosed_as_remaining_growth_increase_even_when_capacity_fits() {
        let hard_cap = 1000u64;
        let charge_before = 800u64;
        let charge_after = 700u64;
        let before = hard_cap.checked_sub(charge_before).unwrap();
        let after = hard_cap.checked_sub(charge_after).unwrap();
        let value = LateValues {
            auxiliary_before: before,
            auxiliary_after: after,
            required_memory_before: 500 + before,
            required_memory_after: 500 + after,
            ..fixture()
        };
        let p = predicates(&value, true, true);
        assert!(p.exact_census_unchanged && p.exact_caps_unchanged && p.memory_fits);
        assert!(!p.auxiliary_nonincreasing && !p.required_memory_nonincreasing && !p.passed());
        let serialized = serde_json::to_value(&p).unwrap();
        assert_eq!(serialized["auxiliary_nonincreasing"], false);
        assert_eq!(serialized["required_memory_nonincreasing"], false);
        let (disk, memory) = bracketed_requirements(800, 800, 700, 800, 800);
        assert!(bracketed_fit(
            true,
            true,
            disk,
            memory,
            [1000, 1000, 990],
            [1000, 1000, 990]
        ));
    }
    #[test]
    fn proposed_bracket_reserves_normal_growth_and_every_availability_and_identity_gate() {
        let (disk, memory) = bracketed_requirements(800, 850, 700, 800, 820);
        assert_eq!((disk, memory), (850, 820));
        assert!(bracketed_fit(
            true,
            true,
            disk,
            memory,
            [1000, 990, 980],
            [1000, 990, 980]
        ));
        assert!(!bracketed_fit(
            false, true, disk, memory, [1000; 3], [1000; 3]
        ));
        assert!(!bracketed_fit(
            true, false, disk, memory, [1000; 3], [1000; 3]
        ));
        // An earlier accepted observation cannot be discarded just because
        // current memory became available after a cache was released.
        for index in 0..3 {
            let mut available = [1000; 3];
            available[index] = 819;
            assert!(!bracketed_fit(
                true, true, disk, memory, [1000; 3], available
            ));
            let mut available = [1000; 3];
            available[index] = 849;
            assert!(!bracketed_fit(
                true, true, disk, memory, available, [1000; 3]
            ));
        }
        // A changed floor/top-up represented in either complete requirement
        // is retained; max(auxiliary) alone must not lose that policy.
        assert_eq!(
            bracketed_requirements(900, 850, 1000, 800, 820),
            (900, 1000)
        );
    }
    #[test]
    #[ignore = "root-only isolated metadata fixture beneath /var/lib/jetstreamer; no campaign or remote operations"]
    fn failed_audit_is_private_durable_no_clobber_and_never_a_positive_receipt() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let directory = tempfile::Builder::new()
            .prefix("admission-failure-test-")
            .tempdir_in("/var/lib/jetstreamer")
            .unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let output = directory.path().join("admission.json");
        let value = json!({"admitted":false,"predicates":{"memory_fits":false}});
        let path = persist_failure(&output, 1, 2, &value).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o400);
        assert_eq!(
            serde_json::from_slice::<Value>(&fs::read(&path).unwrap()).unwrap(),
            value
        );
        assert!(!output.exists());
        assert!(persist_failure(&output, 1, 2, &json!({"different":true})).is_err());
        assert_eq!(
            serde_json::from_slice::<Value>(&fs::read(&path).unwrap()).unwrap(),
            value
        );
    }
}
