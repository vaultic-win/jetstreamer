//! Read-only admission controls against one already accepted coordinated sample.
//! A report is never an admission, launch, plan transition, or replay observation.
use super::*;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanningSpec {
    schema: String,
    observer: BoundFile,
    fleet: BoundFile,
    protected_guards: BTreeMap<String, BoundFile>,
}

fn requirements(
    century: u64,
    growth: u64,
    inherited: u64,
    auxiliary: u64,
    total: u64,
) -> Result<(u64, u64, u64)> {
    let floor = century
        .checked_add(growth)
        .context("prefix planning protected-floor overflow")?
        .max(inherited)
        // A new generation never lowers the existing sealed baseline.
        .max(c::FLOOR);
    let initial = floor
        .checked_add(c::PEAK)
        .context("prefix planning initial-free overflow")?;
    let memory = (480u64 << 30)
        .max(total / 10)
        .checked_add(c::MEMORY)
        .and_then(|n| n.checked_add(auxiliary))
        .context("prefix planning memory overflow")?;
    Ok((floor, initial, memory))
}

pub(super) fn run() -> Result<()> {
    let (binding, self_sha) = publication203::parsed_args("plan-prefix223-native20")?;
    let requested: PlanningSpec = serde_json::from_value(native209::immutable_json(&binding)?)?;
    ensure!(
        requested.schema == "jetstreamer-private-epoch223-native20-prefix-planning-spec-v1",
        "prefix read-only planning schema differs"
    );
    let s = Spec {
        schema: requested.schema,
        observer: requested.observer,
        fleet: requested.fleet,
        protected_guards: requested.protected_guards,
        // This command has no output-file or mutation path.
        output: PathBuf::new(),
    };
    c::prerequisites()?;
    let o = bound_json(&s.observer)?;
    let f = bound_json(&s.fleet)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let (sample_time, century, sampled_memory) = sample_for_plan(&s, &o, &f, now, false)?;
    let guard_history = completed_guards(&f, &s.protected_guards, sample_time, now)?;
    let names = names(&f)?;
    let before = census(&names, 201, 300)?;
    owners(&f, &before, false)?;
    let free_before = singleton227_admission::disk_free()?;
    let memory_before = native209_admission::actual_memory()?;
    let (growth_before, disk_before) =
        prefix223_native20_peer228::disk(&f, &o, &s.protected_guards, sample_time, now)?;
    let (aux_before, memory_evidence_before) = prefix223_native20_peer228::memory(&f)?;
    let inherited = s
        .protected_guards
        .values()
        .map(bound_json)
        .collect::<Result<Vec<_>>>()?
        .iter()
        .map(|v| {
            v["minimum_free_bytes"]
                .as_u64()
                .filter(|n| *n > 0)
                .context("prefix planning inherited guard floor missing")
        })
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .max()
        .unwrap_or(0);
    let (growth_after, disk_after) =
        prefix223_native20_peer228::disk(&f, &o, &s.protected_guards, sample_time, now)?;
    let (aux_after, memory_evidence_after) = prefix223_native20_peer228::memory(&f)?;
    let after = census(&names, 201, 300)?;
    owners(&f, &after, false)?;
    let free_after = singleton227_admission::disk_free()?;
    let memory_after = native209_admission::actual_memory()?;
    let total = o["host_memory"]["total_kib"]
        .as_u64()
        .and_then(|n| n.checked_mul(1024))
        .context("prefix planning host memory")?;
    let growth = growth_before.max(growth_after);
    let auxiliary = aux_before.max(aux_after);
    let (floor, required_free, required_memory) =
        requirements(century, growth, inherited, auxiliary, total)?;
    let sampled_free = o["filesystem"]["conservative_available_bytes"]
        .as_u64()
        .context("prefix planning sampled free disk")?;
    let actual_free = free_before.min(free_after);
    let actual_memory = memory_before.min(memory_after);
    let all_free = sampled_free.min(actual_free);
    let all_memory = sampled_memory.min(actual_memory);
    let mut report = json!({
        "schema":"jetstreamer-private-epoch223-native20-prefix-resource-planning-v1",
        "epoch":223,"unit":c::UNIT,"private_run_root":c::ROOT,
        "recorded_unix_seconds":now,"accepted_sample_unix_seconds":sample_time,
        "century_floor_bytes":century,"protected_remaining_growth_bytes":growth,
        "maximum_existing_guard_floor_bytes":inherited,
        "minimum_proposed_guard_floor_bytes":floor,
        "candidate_incremental_peak_bytes":c::PEAK,
        "minimum_proposed_initial_free_bytes":required_free,
        "sampled_free_bytes":sampled_free,"actual_free_before_bytes":free_before,
        "actual_free_after_bytes":free_after,
        "actual_disk_shortfall_bytes":required_free.saturating_sub(actual_free),
        "sample_and_actual_disk_shortfall_bytes":required_free.saturating_sub(all_free),
        "host_total_memory_bytes":total,"auxiliary_memory_growth_bytes":auxiliary,
        "required_available_memory_bytes":required_memory,
        "sampled_available_memory_bytes":sampled_memory,
        "actual_available_memory_before_bytes":memory_before,
        "actual_available_memory_after_bytes":memory_after,
        "actual_memory_shortfall_bytes":required_memory.saturating_sub(actual_memory),
        "sample_and_actual_memory_shortfall_bytes":required_memory.saturating_sub(all_memory)
    });
    let capacity = json!({
        "new_floor_generation_required":floor>c::FLOOR,
        "current_actual_capacity_fits_proposed_envelope":actual_free>=required_free && actual_memory>=required_memory,
        "sample_and_actual_capacity_fit_proposed_envelope":all_free>=required_free && all_memory>=required_memory,
        "sealed_generation_capacity_fits":floor==c::FLOOR && all_free>=c::INITIAL && all_memory>=required_memory,
        "protected_growth_increased_during_checks":growth_after>growth_before,
        "auxiliary_memory_growth_increased_during_checks":aux_after>aux_before,
        "repair_closed":false,"full_epoch_qualified":false,
        "ordinary_replay_authorized":false
    });
    let evidence = json!({
        "spec":private157::binding(&binding),"helper_sha256":self_sha,
        "observer":private157::binding(&s.observer),"fleet":private157::binding(&s.fleet),
        "protected_guards":s.protected_guards,"protected_guard_history":guard_history,
        "capability":{"path":c::CAPABILITY,"sha256":c::CAPABILITY_SHA},
        "resource_plan":{"path":c::PLAN,"sha256":c::PLAN_SHA},
        "protected_growth_evidence_before":disk_before,"protected_growth_evidence_after":disk_after,
        "protected_memory_evidence_before":memory_evidence_before,
        "protected_memory_evidence_after":memory_evidence_after,
        "unit_census_before":before,"unit_census_after":after,
        "admission_control_checks_performed":true,"new_replay_poll_performed":false,
        "older_producers_and_guards_preserved":true,"admitted":false,
        "replay_launch_authorized":false,"plan_transition_authorized":false,
        "publication_authorized":false,"remote_mutations":false,"r2_mutations":false
    });
    for object in [&capacity, &evidence] {
        for (key, field) in object.as_object().context("prefix planning evidence")? {
            ensure!(
                report.get(key).is_none(),
                "duplicate prefix planning field:{key}"
            );
            report[key] = field.clone();
        }
    }
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reporting_above_sealed_floor_never_lowers_inherited_reservations() {
        // Saved 337 optimistic growth already makes the old 2 TB plan impossible.
        let (floor, initial, _) =
            requirements(245_383_154_903, 1_841_658_544_128, c::FLOOR, 0, 1).unwrap();
        assert_eq!(floor, 2_087_041_699_031);
        assert_eq!(initial, 2_558_840_390_871);
        assert!(
            super::super::arithmetic(245_383_154_903, 1_841_658_544_128, c::FLOOR, 0, 1).is_err()
        );
        assert_eq!(requirements(1, 1, floor + 1, 0, 1).unwrap().0, floor + 1);
        assert_eq!(requirements(1, 1, 1, 0, 1).unwrap().0, c::FLOOR);
        assert!(requirements(u64::MAX, 1, 0, 0, 1).is_err());
        assert!(requirements(1, 1, u64::MAX, 0, 1).is_err());
        assert!(requirements(1, 1, 1, u64::MAX, 1).is_err());
    }
}
