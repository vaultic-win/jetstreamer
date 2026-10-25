//! Conservative complete obligations and exact admission failure evidence.
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
    #[cfg(test)]
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

pub(super) struct BracketInputs<'a> {
    pub plan: &'a Value,
    pub fleet: &'a Value,
    pub observer: &'a Value,
    pub proposal: &'a Value,
    pub guards: &'a BTreeMap<String, BoundFile>,
    pub century: u64,
    pub protected_before: u64,
    pub guard_floor_before: u64,
    pub growth_before: u64,
    pub growth_after: u64,
    pub auxiliary_before: u64,
    pub auxiliary_after: u64,
    pub disk_required_before: u64,
    pub memory_required_before: u64,
    pub memory_required_after: u64,
    pub memory_evidence_after: &'a [Value],
}
#[derive(Debug, Serialize)]
pub(super) struct ResolvedBracket {
    pub growth_max: u64,
    pub auxiliary_max: u64,
    pub protected_floor_before: u64,
    pub protected_floor_after: u64,
    pub protected_floor_recomputed: u64,
    pub protected_floor_max: u64,
    pub existing_guard_floor_max: u64,
    pub disk_required_before: u64,
    pub disk_required_after: u64,
    pub disk_required_recomputed: u64,
    pub disk_required_max: u64,
    pub memory_required_before: u64,
    pub memory_required_after: u64,
    pub memory_required_recomputed: u64,
    pub memory_required_max: u64,
    pub memory_policy_after_max_auxiliary_recompute: Value,
}
pub(super) fn resolve(i: &BracketInputs<'_>) -> Result<ResolvedBracket> {
    let growth_max = i.growth_before.max(i.growth_after);
    let auxiliary_max = i.auxiliary_before.max(i.auxiliary_after);
    let (protected_after, guard_after) =
        native228_admission::protected_floor(i.century, i.growth_after, i.guards)?;
    let disk_after = disk_requirement(i.plan, protected_after)?;
    let (protected_recomputed, guard_recomputed) =
        native228_admission::protected_floor(i.century, growth_max, i.guards)?;
    // Even when helper policies are non-monotone, no complete bracket floor
    // may disappear behind the maximum of the partial growth operands.
    let protected_max = i
        .protected_before
        .max(protected_after)
        .max(protected_recomputed);
    let disk_recomputed = disk_requirement(i.plan, protected_max)?;
    let (memory_recomputed, memory_policy) = memory_requirement(
        i.fleet,
        i.observer,
        i.proposal,
        auxiliary_max,
        i.memory_evidence_after,
    )?;
    let (disk_max, memory_max) = super::bracketed_requirements(
        i.disk_required_before.max(disk_after),
        disk_recomputed,
        i.memory_required_before,
        i.memory_required_after,
        memory_recomputed,
    );
    Ok(ResolvedBracket {
        growth_max,
        auxiliary_max,
        protected_floor_before: i.protected_before,
        protected_floor_after: protected_after,
        protected_floor_recomputed: protected_recomputed,
        protected_floor_max: protected_max,
        existing_guard_floor_max: i.guard_floor_before.max(guard_after).max(guard_recomputed),
        disk_required_before: i.disk_required_before,
        disk_required_after: disk_after,
        disk_required_recomputed: disk_recomputed,
        disk_required_max: disk_max,
        memory_required_before: i.memory_required_before,
        memory_required_after: i.memory_required_after,
        memory_required_recomputed: memory_recomputed,
        memory_required_max: memory_max,
        memory_policy_after_max_auxiliary_recompute: memory_policy,
    })
}

pub(super) fn refuse(output: &Path, phase: &str, mut evidence: Value) -> Result<()> {
    let at = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
    let at = u64::try_from(at).context("failed admission audit clock overflow")?;
    evidence["recorded_unix_millis"] = json!(at);
    evidence["failure_phase"] = json!(phase);
    let path = persist_failure(output, at, std::process::id(), &evidence).with_context(|| {
        format!("capped admission refused at {phase}; failed to persist detailed diagnostic")
    })?;
    bail!(
        "capped admission refused at {phase}; diagnostic={}",
        path.display()
    );
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
    fn recomputation_fixture(native223: bool) -> (Value, Value, Value, Value) {
        let mut fleet = json!({"active":[],"unit_census":{}});
        if native223 {
            let row = prefix223_live_peer::fixture_row();
            fleet["unit_census"][prefix223_native20::UNIT] =
                singleton227_admission::active_owner(&row).unwrap().clone();
            fleet["active"].as_array_mut().unwrap().push(row);
        }
        (
            json!({"protected_existing_floor_bytes":1000,"candidate_incremental_peak_bytes":500}),
            fleet,
            json!({"host_memory":{"total_kib":976562500u64}}),
            json!({"kernel_limits":{"requested_memory_max_bytes":100},"guard_memory_max_bytes":10}),
        )
    }
    fn recompute<'a>(
        p: &'a Value,
        f: &'a Value,
        o: &'a Value,
        r: &'a Value,
        guards: &'a BTreeMap<String, BoundFile>,
    ) -> BracketInputs<'a> {
        let (protected, guard_floor) =
            native228_admission::protected_floor(80, 100, guards).unwrap();
        BracketInputs {
            plan: p,
            fleet: f,
            observer: o,
            proposal: r,
            guards,
            century: 80,
            protected_before: protected,
            guard_floor_before: guard_floor,
            growth_before: 100,
            growth_after: 120,
            auxiliary_before: 200,
            auxiliary_after: 300,
            disk_required_before: disk_requirement(p, protected).unwrap(),
            memory_required_before: memory_requirement(f, o, r, 200, &[]).unwrap().0,
            memory_required_after: memory_requirement(f, o, r, 300, &[]).unwrap().0,
            memory_evidence_after: &[],
        }
    }
    #[test]
    fn actual_recomputation_admits_cache_release_and_disk_growth_only_when_all_brackets_fit() {
        let (p, f, o, r) = recomputation_fixture(false);
        let guards = BTreeMap::new();
        let input = recompute(&p, &f, &o, &r, &guards);
        let bracket = resolve(&input).unwrap();
        assert_eq!(bracket.growth_max, 120);
        assert_eq!(bracket.auxiliary_max, 300);
        assert!(bracket.protected_floor_after > bracket.protected_floor_before);
        assert!(bracket.memory_required_after > bracket.memory_required_before);
        let disk = bracket.disk_required_max;
        let memory = bracket.memory_required_max;
        assert!(bracketed_fit(
            true,
            true,
            disk,
            memory,
            [disk; 3],
            [memory; 3]
        ));
        assert!(!bracketed_fit(
            false,
            true,
            disk,
            memory,
            [disk; 3],
            [memory; 3]
        ));
        assert!(!bracketed_fit(
            true,
            false,
            disk,
            memory,
            [disk; 3],
            [memory; 3]
        ));
        for index in 0..3 {
            let mut values = [memory; 3];
            values[index] = memory - 1;
            assert!(!bracketed_fit(true, true, disk, memory, [disk; 3], values));
            let mut values = [disk; 3];
            values[index] = disk - 1;
            assert!(!bracketed_fit(
                true,
                true,
                disk,
                memory,
                values,
                [memory; 3]
            ));
        }
    }
    #[test]
    fn actual_recomputation_retains_live_native223_floor_and_checked_declared_disk_reserve() {
        let (p, f, o, r) = recomputation_fixture(true);
        let guards = BTreeMap::new();
        let input = recompute(&p, &f, &o, &r, &guards);
        let bracket = resolve(&input).unwrap();
        let floor = 480u64 << 30;
        assert_eq!(
            bracket.memory_policy_after_max_auxiliary_recompute["floor_policy"]["native223_available_memory_floor_bytes"],
            floor
        );
        assert_eq!(bracket.memory_required_max, floor + 110 + 300);
        // Ample free disk never authorizes exceeding the immutable declared floor.
        let small =
            json!({"protected_existing_floor_bytes":190,"candidate_incremental_peak_bytes":500});
        let input = recompute(&small, &f, &o, &r, &guards);
        assert!(resolve(&input).is_err());
        let mut input = recompute(&p, &f, &o, &r, &guards);
        input.century = u64::MAX;
        assert!(resolve(&input).is_err());
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
