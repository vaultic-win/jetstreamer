//! The issuer calls complete maintenance admission; it never accepts available
//! memory, growth, omitted owners or a caller's boolean as resource evidence.
use super::*;
const METADATA: u64 = 128 << 20;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdmissionSpec {
    schema: String,
    recovery_plan: BoundFile,
    plan_issuance: BoundFile,
    assembler: BoundFile,
    producer_unit_file: BoundFile,
    guard_unit_file: BoundFile,
    resource_basis: Value,
    capacity_output: PathBuf,
}
pub(super) fn candidate(
    stage: downstream::Stage,
    bytes: u64,
) -> Result<maintenance_capacity::Candidate> {
    let (additional, memory) = match stage {
        downstream::Stage::Assembly => (
            OUTPUT_MAX
                .checked_add(METADATA)
                .context("204 assembly disk overflow")?,
            MEMORY + GUARD_MEMORY,
        ),
        downstream::Stage::Full => (
            OUTPUT_MAX
                .checked_add(METADATA)
                .context("204 scan disk overflow")?,
            MEMORY,
        ),
        downstream::Stage::Plugin => (128 << 20, MEMORY),
        downstream::Stage::Boundary => (128 << 20, 16 << 30),
        downstream::Stage::Import => (
            bytes
                .checked_add(METADATA)
                .context("204 import disk overflow")?,
            16 << 30,
        ),
        downstream::Stage::Upload => (1 << 30, 16 << 30),
    };
    ensure!(bytes <= OUTPUT_MAX, "204 candidate bounds missing");
    Ok(maintenance_capacity::Candidate {
        additional_bytes: additional,
        memory_max_bytes: memory,
        minimum_protected_disk_bytes: 0,
    })
}
fn unit_file(
    b: &BoundFile,
    p: &Value,
    plan: &BoundFile,
    assembler: &BoundFile,
    guard: bool,
) -> Result<()> {
    let text = String::from_utf8(sealed(b, 1 << 20)?)?;
    let name = if guard { GUARD } else { UNIT };
    ensure!(
        b.path == Path::new("/etc/systemd/system").join(name),
        "204 assembly unit fragment scope"
    );
    let expected = format!(
        "{} {} --plan-sha256 {} --self-sha256 {}{}",
        assembler.path.display(),
        plan.path.display(),
        plan.sha256,
        assembler.sha256,
        if guard { " --guard" } else { "" }
    );
    let mut keys = BTreeMap::new();
    for line in text
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty() && !s.starts_with('#') && !s.starts_with('['))
    {
        let (key, value) = line
            .split_once('=')
            .context("204 malformed unit fragment")?;
        ensure!(
            keys.insert(key, value).is_none(),
            "204 duplicate unit directive"
        );
    }
    for (key, value) in [
        ("ExecStart", expected.as_str()),
        ("Type", "exec"),
        ("User", "root"),
        ("Restart", "no"),
        ("ProtectSystem", "strict"),
        ("ProtectHome", "read-only"),
        ("PrivateNetwork", "yes"),
        ("ReadWritePaths", ROOT),
        ("NoNewPrivileges", "yes"),
        ("MemorySwapMax", "0"),
        ("CapabilityBoundingSet", "CAP_DAC_OVERRIDE CAP_SYS_PTRACE"),
        ("AmbientCapabilities", "CAP_DAC_OVERRIDE CAP_SYS_PTRACE"),
    ] {
        ensure!(
            keys.get(key) == Some(&value),
            "204 effective fragment differs: {key}"
        );
    }
    let max = if guard { GUARD_MEMORY } else { MEMORY }.to_string();
    ensure!(
        keys.get("MemoryMax") == Some(&max.as_str()) && p["executable_sha256"] == assembler.sha256,
        "204 unit hard memory or assembler digest differs"
    );
    let actual = singleton227_capture::properties(
        name,
        "Id,FragmentPath,DropInPaths,NeedDaemonReload,Transient,ExecStart,MemoryMax,MemorySwapMax,Restart,Type,User,ProtectHome,ProtectSystem,PrivateNetwork,NoNewPrivileges",
    )?;
    ensure!(
        actual
            .get("FragmentPath")
            .is_some_and(|s| s == &b.path.to_string_lossy())
            && actual.get("DropInPaths").is_some_and(String::is_empty)
            && actual.get("NeedDaemonReload").map(String::as_str) == Some("no")
            && actual.get("Transient").map(String::as_str) == Some("no"),
        "204 effective unit is not this installed sealed fragment"
    );
    for key in [
        "MemoryMax",
        "MemorySwapMax",
        "Restart",
        "Type",
        "User",
        "ProtectHome",
        "ProtectSystem",
        "PrivateNetwork",
        "NoNewPrivileges",
    ] {
        ensure!(
            actual.get(key).map(String::as_str) == keys.get(key).copied(),
            "204 effective property differs: {key}"
        );
    }
    ensure!(
        ownership::command_matches(
            actual.get("ExecStart").context("204 command")?,
            &format!(
                "{{ path={} ; argv[]={expected} ; ignore_errors=no }}",
                assembler.path.display()
            )
        ),
        "204 installed command differs"
    );
    Ok(())
}
pub(super) fn admit(v: &Value, spec: &BoundFile, self_sha: &str) -> Result<()> {
    let a: AdmissionSpec = serde_json::from_value(v.clone())?;
    ensure!(
        a.schema == "jetstreamer-epoch204-assembly-recovery-admission-spec-v1",
        "204 admission spec"
    );
    let context = AcceptedContext::from_basis(&a.resource_basis)?;
    let p = read(&a.recovery_plan)?;
    custody::plan_scope(&p)?;
    let issuance = read(&a.plan_issuance)?;
    ensure!(
        issuance["schema"] == "jetstreamer-epoch204-assembly-recovery-plan-issuance-v1"
            && issuance["plan"] == private157::binding(&a.recovery_plan)
            && issuance["assembler"] == private157::binding(&a.assembler),
        "204 admission plan was not issued by the closed Rust adapter"
    );
    let old: BoundFile = serde_json::from_value(p["original_terminal"].clone())?;
    custody::validate_terminal_saved(&read(&old)?)?;
    let capture = read(&serde_json::from_value(p["source_capture"].clone())?)?;
    custody::old_idle(&context)?;
    ownership::no_overlap(&context, None)?;
    ensure!(
        fs::metadata(ROOT)?.dev() == fs::metadata(CANONICAL)?.dev(),
        "204 recovery output is outside the admitted filesystem"
    );
    custody::check_source_names(&capture)?;
    sealed(&a.assembler, 128 << 20)?;
    let current = unit(UNIT)?;
    ensure!(
        is_idle(&current) && is_idle(&unit(GUARD)?),
        "204 recovery owner already active or pending"
    );
    inactive_status::no_pending_owner_trigger(UNIT, false)?;
    inactive_status::no_pending_owner_trigger(GUARD, false)?;
    unit_file(
        &a.producer_unit_file,
        &p,
        &a.recovery_plan,
        &a.assembler,
        false,
    )?;
    unit_file(&a.guard_unit_file, &p, &a.recovery_plan, &a.assembler, true)?;
    let c = candidate(downstream::Stage::Assembly, 0)?;
    let capacity = maintenance_capacity::check_assembly204_recovery(&a.resource_basis, c)?;
    validate_capacity(&capacity, c.memory_max_bytes, c.additional_bytes)?;
    validate_provenance(&capacity)?;
    custody::old_idle(&context)?;
    ownership::no_overlap(&context, None)?;
    custody::check_source_names(&capture)?;
    ensure!(
        unit(UNIT)? == current && is_idle(&unit(GUARD)?),
        "204 new owner changed across admission"
    );
    let cap = write(&a.capacity_output, &capacity)?;
    let compact = compact_admission(&p, &a.recovery_plan, &capacity, &cap, spec, self_sha)?;
    write(Path::new(s(&p, "admission_receipt")?), &compact)?;
    Ok(())
}
pub(super) fn validate_capacity(v: &Value, candidate_memory: u64, additional: u64) -> Result<()> {
    ensure!(
        v["schema"] == "jetstreamer-horizon-maintenance-capacity-v1"
            && v["first_epoch"] == 201
            && v["last_epoch"] == 300
            && v["additional_bytes"] == additional
            && v["unit_census_before"] == v["unit_census_after"]
            && v["unit_census_before"] == v["unit_census_after_memory_and_guard_checks"]
            && v["all_live_growth_and_century_floor_protected"] == true
            && v["capped_peer_accounting"]["producer_and_independent_guard_hard_memory_charged"]
                == true
            && v["capped_peer_accounting"]["allocation_credit_bytes"] == 0,
        "204 incomplete capacity primary evidence"
    );
    for phase in ["memory_before", "memory_after"] {
        let m = &v[phase];
        let policy = &m["assembly204_recovery_memory_policy"];
        let growth = n(m, "protected_existing_memory_growth_bytes")?;
        let mut names = BTreeSet::new();
        let mut complete = 0u64;
        for owner in m["protected_memory_evidence"]
            .as_array()
            .context("204 complete hard-memory owner evidence missing")?
        {
            ensure!(
                names.insert(s(owner, "unit")?.to_owned()),
                "204 duplicate protected hard-memory owner"
            );
            complete = complete
                .checked_add(n(owner, "remaining_hard_memory_growth_bytes")?)
                .context("204 complete protected memory overflow")?;
        }
        ensure!(
            complete == growth,
            "204 protected hard-memory growth understates owner evidence"
        );
        let total = n(m, "host_total_memory_bytes")?;
        let required = maintenance_capacity::validate_assembly204_recovery_memory_policy(
            policy,
            total,
            growth,
            candidate_memory,
        )?;
        ensure!(
            policy["schema"] == "jetstreamer-epoch204-assembly-recovery-hard-memory-policy-v1"
                && policy["protected_existing_hard_memory_growth_bytes"] == growth
                && policy["candidate_hard_memory_bytes"] == candidate_memory
                && policy["required_available_memory_bytes"] == required
                && m["candidate_memory_max_bytes"] == candidate_memory
                && m["minimum_available_memory_bytes"] == required
                && n(m, "sampled_available_memory_bytes")? >= required
                && n(m, "actual_available_memory_bytes")? >= required,
            "204 capacity understates complete hard-memory growth or candidate guard"
        );
    }
    let disk = n(v, "minimum_free_bytes")?
        .checked_add(additional)
        .context("204 disk reserve overflow")?;
    ensure!(
        v["required_initial_free_bytes"] == disk
            && n(v, "sampled_available_bytes")? >= disk
            && n(v, "actual_available_bytes")? >= disk,
        "204 capacity spends existing disk growth/floor"
    );
    Ok(())
}
pub(super) fn compact_admission(
    p: &Value,
    plan: &BoundFile,
    c: &Value,
    cap: &BoundFile,
    spec: &BoundFile,
    self_sha: &str,
) -> Result<Value> {
    let floor = n(c, "minimum_free_bytes")?;
    let memory = c["memory_before"]["candidate_memory_max_bytes"]
        .as_u64()
        .context("candidate memory")?;
    Ok(
        json!({"schema":"jetstreamer-epoch204-assembly-recovery-admission-v1","admitted":true,"epoch":204,
        "plan_sha256":plan.sha256,"executable_sha256":p["executable_sha256"],"source_capture":p["source_capture"],
        "original_terminal":p["original_terminal"],"guard_spec":p["guard_spec"],"output_root":ROOT,"unit":UNIT,"guard_unit":GUARD,
        "original_partial_preserved":true,"complete_live_claims_accounted":true,"verification_import_overlap_accounted":true,
        "zstd_level":p["zstd_level"],"maximum_output_bytes":OUTPUT_MAX,"maximum_millis":DURATION,
        "reserved_memory_bytes":memory,"incremental_disk_reserve_bytes":c["additional_bytes"],
        "sampled_unix_millis":n(c,"recorded_unix_seconds")?.checked_mul(1000).context("204 admission clock overflow")?,
        "observer_sampled_at_utc":c["sampled_at_utc"],"minimum_free_bytes":floor,"filesystem_device":fs::metadata(ROOT)?.dev(),
        "available_bytes":c["actual_available_bytes"],"live_remaining_growth_bytes":0,
        "verification_import_overlap_bytes":n(c,"additional_bytes")?.checked_sub(OUTPUT_MAX).context("204 overlap reserve")?,
        "memory_available_bytes":c["memory_before"]["actual_available_memory_bytes"],"capacity":private157::binding(cap),
        "protected_growth_included_in_minimum_free_bytes":true,"issuer":issuer(spec,self_sha),"authority":denied()}),
    )
}
pub(super) fn validate_issued(v: &Value, plan: &BoundFile, p: &Value) -> Result<()> {
    ensure!(
        v["schema"] == "jetstreamer-epoch204-assembly-recovery-admission-v1"
            && v["epoch"] == 204
            && v["admitted"] == true
            && v["plan_sha256"] == plan.sha256
            && v["source_capture"] == p["source_capture"]
            && v["original_terminal"] == p["original_terminal"]
            && v["guard_spec"] == p["guard_spec"]
            && v["reserved_memory_bytes"] == MEMORY + GUARD_MEMORY
            && is_lower_hex(s(&v["issuer"], "executable_sha256")?, 64),
        "204 admission is not the closed Rust issue"
    );
    deny(&v["authority"])?;
    let c = read(&serde_json::from_value(v["capacity"].clone())?)?;
    validate_capacity(&c, MEMORY + GUARD_MEMORY, OUTPUT_MAX + METADATA)?;
    validate_provenance(&c)?;
    ensure!(
        v["minimum_free_bytes"] == c["minimum_free_bytes"]
            && v["available_bytes"] == c["actual_available_bytes"]
            && v["memory_available_bytes"] == c["memory_before"]["actual_available_memory_bytes"]
            && n(v, "sampled_unix_millis")?
                == n(&c, "recorded_unix_seconds")?
                    .checked_mul(1000)
                    .context("204 capacity time overflow")?,
        "204 compact admission does not reproduce capacity proof"
    );
    Ok(())
}
pub(super) fn stage_capacity(basis: &Value, stage: downstream::Stage, bytes: u64) -> Result<Value> {
    let c = candidate(stage, bytes)?;
    let result = maintenance_capacity::check_assembly204_recovery(basis, c)?;
    validate_capacity(&result, c.memory_max_bytes, c.additional_bytes)?;
    validate_provenance(&result)?;
    Ok(result)
}
fn owner_sets(
    expected: &BTreeSet<String>,
    guards: &BTreeSet<String>,
    memory: &Value,
) -> Result<()> {
    let mut seen = BTreeSet::new();
    for e in memory["protected_memory_evidence"]
        .as_array()
        .context("204 memory owner roster missing")?
    {
        ensure!(
            seen.insert(s(e, "unit")?.to_owned()),
            "204 duplicate protected memory owner"
        );
        prefix223_live_peer::validate_saved_row(e)?;
    }
    ensure!(
        expected == guards && expected == &seen,
        "204 saved capacity omits/adds protected owner or guard"
    );
    Ok(())
}
/// Replay the actual accepted primary roster, rather than trusting an issuer's
/// compact complete-live-claims flag or an available-memory scalar.
pub(super) fn validate_provenance(v: &Value) -> Result<()> {
    let basis = &v["resource_basis"];
    let fleet: BoundFile = serde_json::from_value(basis["fleet"].clone())?;
    let observer: BoundFile = serde_json::from_value(basis["observer"].clone())?;
    ensure!(
        v["fleet"] == private157::binding(&fleet)
            && v["observer"] == private157::binding(&observer),
        "204 saved capacity primary bindings differ"
    );
    let f = bound_json(&fleet)?;
    let o = bound_json(&observer)?;
    ensure!(
        f["observer_receipt"] == observer.path.to_string_lossy().as_ref()
            && f["observer_sha256"] == observer.sha256
            && f["sampled_at_utc"] == o["recorded_at_utc"]
            && v["sampled_at_utc"] == f["sampled_at_utc"],
        "204 capacity is not the accepted coordinated frame"
    );
    let mut expected = BTreeSet::new();
    for active in f["active"]
        .as_array()
        .context("204 saved capacity accepted roster")?
    {
        let owner = singleton227_admission::active_owner(active)?;
        let name = s(owner, "Id")?;
        ensure!(
            expected.insert(name.to_owned()),
            "204 saved capacity duplicate accepted owner"
        );
        same_owner(owner, &v["unit_census_before"][name])?;
    }
    let guard_names = basis["protected_guards"]
        .as_object()
        .context("204 saved guard roster")?
        .keys()
        .cloned()
        .collect();
    for phase in ["memory_before", "memory_after"] {
        owner_sets(&expected, &guard_names, &v[phase])?;
        for row in v[phase]["protected_memory_evidence"].as_array().unwrap() {
            let name = s(row, "unit")?;
            ensure!(
                row["invocation_id"] == v["unit_census_before"][name]["InvocationID"],
                "204 saved memory evidence belongs to another invocation"
            );
        }
    }
    for bound in basis["protected_guards"]
        .as_object()
        .context("204 saved guard bindings")?
        .values()
    {
        bound_json(&serde_json::from_value(bound.clone())?)?;
    }
    Ok(())
}
#[cfg(test)]
mod roster_tests {
    use super::*;
    #[test]
    fn actual399_incomplete_saved_capacity_is_not_retroactively_promoted() {
        let saved: Value =
            serde_json::from_str(include_str!("fixtures/actual399_incomplete_memory.json"))
                .unwrap();
        let expected = saved["accepted_primary_names"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect();
        let guards = saved["protected_guard_names"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect();
        for phase in ["memory_before", "memory_after"] {
            assert!(owner_sets(&expected, &guards, &saved[phase]).is_err());
        }
    }
    #[test]
    fn complete399_roster_still_requires_every_independent_guard_reservation() {
        let saved: Value =
            serde_json::from_str(include_str!("fixtures/actual399_incomplete_memory.json"))
                .unwrap();
        let expected: BTreeSet<String> = saved["accepted_primary_names"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect();
        for phase in ["memory_before", "memory_after"] {
            // Keep genuine399 rows, and label the extra225 observation synthetic.
            // This tests the gate; it never repairs the historical receipt.
            let mut memory = saved[phase].clone();
            let rows = memory["protected_memory_evidence"].as_array_mut().unwrap();
            let full209 = rows
                .iter_mut()
                .find(|r| r["unit"] == singleton209::UNIT)
                .unwrap();
            let producer = full209["remaining_hard_memory_growth_bytes"]
                .as_u64()
                .unwrap();
            full209["memory_swap_max_bytes"] = json!(0);
            full209["guard_hard_memory_reserved_bytes"] = json!(1u64 << 30);
            full209["remaining_hard_memory_growth_bytes"] = json!(producer + (1u64 << 30));
            rows.push(json!({
                "unit":"horizon-qualify-225-natural-root-resource-shrink-budget-2f856bd-v1.service",
                "invocation_id":"4cd76ae1353a4411885b997f04306402",
                "hard_memory_cap_bytes":192u64 << 30,"memory_high_bytes":160u64 << 30,
                "current_cgroup_charge_bytes":160u64 << 30,"memory_swap_max_bytes":0,
                "guard_hard_memory_reserved_bytes":1u64 << 30,
                "remaining_hard_memory_growth_bytes":33u64 << 30,
                "fixture_scope":"synthetic225 observation; never historical capacity authority"
            }));
            owner_sets(&expected, &expected, &memory).unwrap();
            for name in &expected {
                let mut missing = memory.clone();
                missing["protected_memory_evidence"]
                    .as_array_mut()
                    .unwrap()
                    .retain(|row| row["unit"] != *name);
                assert!(owner_sets(&expected, &expected, &missing).is_err());
                let mut guards = expected.clone();
                guards.remove(name);
                assert!(owner_sets(&expected, &guards, &memory).is_err());
            }
            for name in [
                singleton209::UNIT,
                "horizon-qualify-225-natural-root-resource-shrink-budget-2f856bd-v1.service",
            ] {
                let mut missing = memory.clone();
                let row = missing["protected_memory_evidence"]
                    .as_array_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|row| row["unit"] == name)
                    .unwrap();
                row["guard_hard_memory_reserved_bytes"] = json!(0);
                assert!(owner_sets(&expected, &expected, &missing).is_err());
            }
            let mut duplicate = memory.clone();
            let row = duplicate["protected_memory_evidence"][0].clone();
            duplicate["protected_memory_evidence"]
                .as_array_mut()
                .unwrap()
                .push(row);
            assert!(owner_sets(&expected, &expected, &duplicate).is_err());
        }
    }
    #[test]
    fn missing_primary_or_independent_guard_never_replays_as_complete_capacity() {
        let expected = BTreeSet::from(["primary.service".into(), "sibling.service".into()]);
        let memory = json!({"protected_memory_evidence":[{"unit":"primary.service"},{"unit":"sibling.service"}]});
        owner_sets(&expected, &expected, &memory).unwrap();
        let missing_guard = BTreeSet::from(["primary.service".into()]);
        assert!(owner_sets(&expected, &missing_guard, &memory).is_err());
        let missing_owner = json!({"protected_memory_evidence":[{"unit":"primary.service"}]});
        assert!(owner_sets(&expected, &expected, &missing_owner).is_err());
        let changed = json!({"protected_memory_evidence":[{"unit":"primary.service"},{"unit":"replacement.service"}]});
        assert!(owner_sets(&expected, &expected, &changed).is_err());
    }
}
