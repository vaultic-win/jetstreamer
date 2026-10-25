//! Fresh capacity uses the neutral owner/guard accounting transaction.
use super::*;
const SCHEMA: &str = "jetstreamer-private-first-root233-admission-v1";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    resources: Value,
    readiness: BoundFile,
    output: PathBuf,
}

pub(super) fn roster(f: &Value) -> Result<()> {
    let mut allowed = prefix223_live_peer::roster(&capped204205_work::peer_legacy_view(f)?)?;
    allowed.extend(capped204205_work::peer_names(f)?);
    let mut seen = BTreeSet::new();
    for a in f["active"]
        .as_array()
        .context("first root 233 complete active census absent")?
    {
        let owner = singleton227_admission::active_owner(a)?;
        let name = owner["Id"]
            .as_str()
            .context("first root 233 peer unit absent")?;
        ensure!(
            allowed.contains(name) && seen.insert(name) && f["unit_census"][name] == *owner,
            "first root 233 peer is unknown, unresolved, replaced, or differs from its raw census"
        );
    }
    ensure!(
        f["unit_census"]
            .get(UNIT)
            .is_none_or(|v| v["ActiveState"] != "active" && v["SubState"] != "running"),
        "first root 233 already has an active claim"
    );
    Ok(())
}

pub(super) fn clean_expanded_window(f: &Value, o: &Value) -> Result<()> {
    ensure!(
        o["cadence"]["observed_interval_seconds"]
            .as_u64()
            .is_some_and(|n| n >= 1800),
        "first root 233 needs a clean coordinated expanded-fleet window"
    );
    let pressure = &o["host_global_pressure"]["cross_sample"];
    let elapsed = pressure["elapsed_millis"]
        .as_u64()
        .filter(|n| *n >= 1_800_000)
        .context("first root 233 host pressure window is incomplete")?;
    ensure!(
        pressure["status"] == "observed",
        "first root 233 host pressure window is unavailable"
    );
    for (counter, fraction) in [
        ("memory.full_total_usec", 100u64),
        ("cpu.some_total_usec", 500),
        ("io.full_total_usec", 100),
    ] {
        ensure!(
            pressure["counter_delta_usec"][counter]
                .as_u64()
                .is_some_and(|n| n <= elapsed.saturating_mul(fraction)),
            "first root 233 expanded fleet has excessive pressure: {counter}"
        );
    }
    let mut rows = o["replays"]
        .as_array()
        .context("first root 233 ordinary observer census absent")?
        .iter()
        .collect::<Vec<_>>();
    for row in o["diagnostic_replays"]
        .as_array()
        .context("first root 233 diagnostic observer census absent")?
    {
        if row["status"] == "observed" {
            rows.push(&row["observation"]);
        }
    }
    for row in f["active"]
        .as_array()
        .context("first root 233 active census absent")?
    {
        let owner = singleton227_admission::active_owner(row)?;
        let name = owner["Id"]
            .as_str()
            .context("first root 233 expanded owner absent")?;
        let selected = rows
            .iter()
            .filter(|r| r["producer_after"]["unit"] == name)
            .collect::<Vec<_>>();
        ensure!(
            selected.len() == 1,
            "first root 233 expanded owner was omitted or duplicated"
        );
        let r = selected[0];
        ensure!(
            r["invocation_binding_stable"] == true
                && r["producer_before"]["invocation_id"] == owner["InvocationID"]
                && r["producer_after"]["invocation_id"] == owner["InvocationID"]
                && r["producer_before"]["restarts"] == 0
                && r["producer_after"]["restarts"] == 0
                && r["cross_sample"]["elapsed_seconds"]
                    .as_u64()
                    .is_some_and(|n| n >= 1800)
                && r["worker_before"]["pid"] == r["worker_after"]["pid"]
                && r["worker_after"]["pid"].as_u64().is_some_and(|n| n > 1)
                && ["worker_before", "worker_after"]
                    .iter()
                    .all(|k| r[*k]["matching_workers"] == 1
                        && r[*k]["executable_beneath_bound_scratch"] == true
                        && r[*k]["vmas"].as_u64().is_some_and(|n| n > 0 && n < 3500000)),
            "first root 233 expanded owner has not completed a stable guarded window"
        );
        for counter in [
            "memory_events.max",
            "memory_events.oom",
            "memory_events.oom_kill",
            "memory_events.oom_group_kill",
        ] {
            ensure!(
                r["cross_sample"]["producer_cgroup_counter_delta"][counter] == 0,
                "first root 233 expanded owner had a hard-memory event: {counter}"
            );
        }
    }
    Ok(())
}

fn readiness(b: &BoundFile, helper_sha: &str) -> Result<()> {
    let r = native209::immutable_json(b)?;
    ensure!(
        r["schema"] == "jetstreamer-first-root233-readiness-v1"
            && scope_matches(&r)
            && r["r2_sha256"] == helper_sha
            && r["source_review_passed"] == true
            && r["disposable_sandbox_passed"] == true
            && r["allowed_cpus"] == "8-15"
            && r["cpu_affinity"] == "8-15"
            && r["cpu_assignment_owner_census_authenticated"] == true
            && r["node_rebuilt"] == false
            && r["worker_rebuilt"] == false
            && r["observer_rebuilt"] == false
            && r["native_snapshot_tests_repeated"] == false
            && r["producer_started"] == false,
        "first root 233 source/sandbox readiness proof is incomplete"
    );
    for key in ["source_review", "sandbox_proof", "cpu_assignment_evidence"] {
        let evidence: BoundFile = serde_json::from_value(r[key].clone())?;
        native209::immutable_json(&evidence)?;
    }
    let validation = &r["guard_static_validation"];
    ensure!(
        validation["schema"] == "jetstreamer-horizon-standalone-static-plan-validation-v1"
            && validation["validated"] == true
            && validation["unit"] == UNIT
            && validation["self_sha256"] == GUARD_SHA
            && validation["resource_samples_taken"] == 0
            && validation["protective_guard_proven"] == false
            && validation["replay_launch_authorized"] == false,
        "first root 233 exact outer guard profile was not statically validated"
    );
    deny_authority(&r)
}

fn prepared_root() -> Result<()> {
    for name in ["", "ledger", "scratch", "output", "receipts"] {
        let p = Path::new(ROOT).join(name);
        let m = fs::symlink_metadata(&p)?;
        ensure!(
            m.is_dir() && m.uid() == 1000 && m.mode() & 0o077 == 0 && p.canonicalize()? == p,
            "first root 233 prepared directory is not canonical and owner-private"
        );
        if matches!(name, "scratch" | "output" | "receipts") {
            ensure!(
                fs::read_dir(&p)?.next().is_none(),
                "first root 233 cold generation is already occupied; preserve it"
            );
        }
    }
    let genesis = Path::new(ROOT).join("ledger/genesis.tar.bz2");
    let m = fs::symlink_metadata(&genesis)?;
    ensure!(
        m.is_file()
            && m.uid() == 1000
            && m.nlink() == 1
            && m.mode() & 0o077 == 0
            && m.len() == 20144,
        "first root 233 private genesis metadata differs"
    );
    let bytes = read_stable_bounded(&genesis, 20144, "first root 233 prepared genesis")?;
    ensure!(
        hex_lower(&Sha256::digest(&bytes))
            == "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945",
        "first root 233 prepared genesis digest differs"
    );
    let snapshot = Path::new(PACKAGE).join(SNAPSHOT);
    let m = fs::symlink_metadata(&snapshot)?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o222 == 0
            && m.len() == 10738664792
            && snapshot.canonicalize()? == snapshot,
        "first root 233 cached immutable snapshot metadata differs"
    );
    Ok(())
}

pub(super) fn validate_saved(a: &Value) -> Result<()> {
    ensure!(
        a["schema"] == SCHEMA
            && scope_matches(a)
            && a["admitted"] == true
            && a["producer_started"] == false
            && a["resource_samples_taken"] == 0,
        "first root 233 saved admission profile differs"
    );
    deny_authority(a)?;
    let capacity = &a["capacity"];
    let minimum = capacity["minimum_free_bytes"]
        .as_u64()
        .filter(|n| *n >= FLOOR)
        .context("first root 233 protected disk floor absent")?;
    let required = minimum
        .checked_add(DISK_RESERVATION)
        .context("first root 233 disk overflow")?;
    let calculated = capacity["century_floor_bytes"]
        .as_u64()
        .context("first root 233 century floor absent")?
        .checked_add(
            capacity["protected_remaining_growth_bytes"]
                .as_u64()
                .context("first root 233 protected disk growth absent")?,
        )
        .context("first root 233 protected disk floor overflow")?
        .max(
            capacity["maximum_existing_guard_floor_bytes"]
                .as_u64()
                .context("first root 233 inherited guard floor absent")?,
        )
        .max(FLOOR);
    ensure!(
        capacity["schema"] == "jetstreamer-horizon-maintenance-capacity-v1"
            && minimum == calculated
            && capacity["additional_bytes"] == DISK_RESERVATION
            && capacity["required_initial_free_bytes"] == required
            && capacity["sampled_available_bytes"]
                .as_u64()
                .is_some_and(|n| n >= required)
            && capacity["actual_available_bytes"]
                .as_u64()
                .is_some_and(|n| n >= required)
            && capacity["all_live_growth_and_century_floor_protected"] == true
            && capacity["capped_peer_accounting"]["producer_and_independent_guard_hard_memory_charged"]
                == true
            && capacity["capped_peer_accounting"]["allocation_credit_bytes"] == 0
            && a["guard_minimum_free_bytes"]
                == minimum
                    .checked_add(DRAINAGE)
                    .context("first root 233 drainage floor overflow")?
            && a["observer"] == capacity["observer"]
            && a["fleet"] == capacity["fleet"],
        "first root 233 disk capacity dropped a floor, guard, or reservation"
    );
    for key in ["memory_before", "memory_after"] {
        let row = &capacity[key];
        let total = row["host_total_memory_bytes"]
            .as_u64()
            .context("first root 233 host total absent")?;
        let growth = row["protected_existing_memory_growth_bytes"]
            .as_u64()
            .context("first root 233 protected memory growth absent")?;
        let policy = &row["first_root233_memory_policy"];
        let floor = maintenance_capacity::first_root233_saved_memory_floor(policy, total)?;
        let needed = floor
            .checked_add(growth)
            .and_then(|n| n.checked_add(MEMORY))
            .and_then(|n| n.checked_add(2u64 << 30))
            .context("first root 233 protected memory overflow")?;
        ensure!(
            row["candidate_memory_max_bytes"] == MEMORY
                && row["minimum_available_memory_bytes"] == needed
                && row["sampled_available_memory_bytes"]
                    .as_u64()
                    .is_some_and(|n| n >= needed)
                && row["actual_available_memory_bytes"]
                    .as_u64()
                    .is_some_and(|n| n >= needed)
                && policy["schema"] == "jetstreamer-first-root233-native223-memory-policy-v1"
                && policy["native223_unit"] == prefix223_native20::UNIT
                && policy["native223_invocation_id"] == "e70aaf097e7c4583b216aba454145910"
                && policy["effective_available_memory_floor_bytes"] == floor
                && policy["candidate_producer_hard_memory_bytes"] == MEMORY
                && policy["candidate_guard_and_metadata_hard_memory_bytes"] == (2u64 << 30)
                && policy["protected_existing_hard_memory_growth_bytes"] == growth
                && policy["required_available_memory_bytes"] == needed
                && policy["floor_counted_once"] == true,
            "first root 233 memory capacity lost native 223's floor or remaining hard growth"
        );
    }
    let b = &capacity["bracketed_obligations"];
    let disk_before = b["disk_growth_before_bytes"]
        .as_u64()
        .context("first root 233 first disk bracket absent")?;
    let disk_after = b["disk_growth_after_bytes"]
        .as_u64()
        .context("first root 233 final disk bracket absent")?;
    let memory_before = b["hard_memory_growth_before_bytes"]
        .as_u64()
        .context("first root 233 first memory bracket absent")?;
    let memory_after = b["hard_memory_growth_after_bytes"]
        .as_u64()
        .context("first root 233 final memory bracket absent")?;
    let max_required = capacity["memory_before"]["minimum_available_memory_bytes"]
        .as_u64()
        .context("first root 233 first bracket requirement absent")?
        .max(
            capacity["memory_after"]["minimum_available_memory_bytes"]
                .as_u64()
                .context("first root 233 final bracket requirement absent")?,
        );
    ensure!(
        b["protected_disk_growth_bytes"] == disk_before.max(disk_after)
            && capacity["protected_remaining_growth_bytes"] == disk_before.max(disk_after)
            && b["protected_hard_memory_growth_bytes"] == memory_before.max(memory_after)
            && capacity["memory_before"]["protected_existing_memory_growth_bytes"] == memory_before
            && capacity["memory_after"]["protected_existing_memory_growth_bytes"] == memory_after
            && b["complete_policy"]["complete_required_memory_bytes"] == max_required,
        "first root 233 admission did not retain the safe maximum of both obligation brackets"
    );
    for key in ["memory_before", "memory_after"] {
        ensure!(
            capacity[key]["sampled_available_memory_bytes"]
                .as_u64()
                .is_some_and(|n| n >= max_required)
                && capacity[key]["actual_available_memory_bytes"]
                    .as_u64()
                    .is_some_and(|n| n >= max_required),
            "first root 233 maximum memory obligation does not fit both brackets"
        );
    }
    ensure!(
        capacity["unit_census_before"] == capacity["unit_census_after"]
            && capacity["unit_census_before"]
                == capacity["unit_census_after_memory_and_guard_checks"]
            && a["recorded_unix_seconds"]
                .as_u64()
                .zip(capacity["recorded_unix_seconds"].as_u64())
                .is_some_and(|(a, c)| a >= c && a - c <= 60),
        "first root 233 admission owner census or final clock changed"
    );
    Ok(())
}

pub(super) fn run() -> Result<()> {
    let (bound, self_sha) = publication203::parsed_args("admit-first-root233")?;
    let s: Spec = serde_json::from_value(native209::immutable_json(&bound)?)?;
    ensure!(
        s.schema == "jetstreamer-first-root233-admission-spec-v1",
        "first root 233 admission spec differs"
    );
    output(
        &s.output,
        "admission.json",
        "horizon-first-root233-admission-",
    )?;
    prerequisites()?;
    readiness(&s.readiness, &self_sha)?;
    prepared_root()?;
    let fleet_binding: BoundFile = serde_json::from_value(s.resources["fleet"].clone())?;
    let observer_binding: BoundFile = serde_json::from_value(s.resources["observer"].clone())?;
    let f = bound_json(&fleet_binding)?;
    let o = bound_json(&observer_binding)?;
    roster(&f)?;
    capped204205_work::peer_observation(&f, &o)?;
    clean_expanded_window(&f, &o)?;
    private_prefix::assigned_cpus_available(&fs::read_to_string(
        "/sys/fs/cgroup/cpuset.cpus.effective",
    )?)?;
    ensure!(
        f["memory_target"]["valid"] == true
            && f["memory_target"]["reservation_ceiling_bytes"]
                .as_u64()
                .is_some_and(|n| MEMORY <= n)
            && o["vm_max_map_count"].as_u64().is_some_and(|n| n >= 4194304),
        "first root 233 lacks valid RSS ceiling or VMA headroom"
    );
    let capacity = maintenance_capacity::check_first_root233(&s.resources)?;
    let mut a = scope();
    a["schema"] = json!(SCHEMA);
    a["admitted"] = json!(true);
    a["producer_started"] = json!(false);
    a["capacity"] = capacity;
    a["observer"] = private157::binding(&observer_binding);
    a["fleet"] = private157::binding(&fleet_binding);
    a["guard_minimum_free_bytes"] = json!(
        a["capacity"]["minimum_free_bytes"]
            .as_u64()
            .context("first root 233 disk floor missing")?
            .checked_add(DRAINAGE)
            .context("first root 233 guard floor overflow")?
    );
    a["recorded_unix_seconds"] = json!(now()?);
    a["resource_samples_taken"] = json!(0);
    a["readiness"] = private157::binding(&s.readiness);
    a["admission_spec"] = private157::binding(&bound);
    a["admission_helper_sha256"] = json!(self_sha);
    deny_fields(&mut a);
    validate_saved(&a)?;
    private157::immutable_receipt(&s.output, &a)
}

pub(super) fn output(path: &Path, filename: &str, prefix: &str) -> Result<()> {
    ensure!(
        path.file_name().is_some_and(|s| s == filename)
            && path.parent().and_then(Path::parent) == Some(Path::new("/var/lib/jetstreamer"))
            && path
                .parent()
                .and_then(Path::file_name)
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with(prefix)),
        "first root 233 output is outside its closed private evidence namespace"
    );
    if path.try_exists()? {
        let m = fs::symlink_metadata(path)?;
        ensure!(
            m.is_file()
                && m.uid() == 0
                && m.nlink() == 1
                && m.mode() & 0o222 == 0
                && path.canonicalize()? == path,
            "first root 233 retry output is not immutable"
        );
        Ok(())
    } else {
        validate_output_destination(path).map(|_| ())
    }
}
