//! Admit a cold native20 prefix without hiding another running repair owner.
use super::{prefix223_native20 as c, *};
mod planning;
pub(super) fn plan() -> Result<()> {
    planning::run()
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    observer: BoundFile,
    fleet: BoundFile,
    protected_guards: BTreeMap<String, BoundFile>,
    output: PathBuf,
}
const LEGACY: [(&str, &str); 4] = [
    (
        "horizon-qualify-225-natural-root-resource-shrink-budget-2f856bd-v1.service",
        "4cd76ae1353a4411885b997f04306402",
    ),
    (
        "horizon-qualify-205-shrink-root-prefix-resource-5c01bf93-v1.service",
        "373359a11aef4993a1a949e19ff617c3",
    ),
    (
        "horizon-qualify-204-shrink-root-prefix-resource-fcbf3992-v1.service",
        "448da7f2a3a34217afe7e115120b3cea",
    ),
    (singleton227::UNIT, "a10f37b57711425a81633c62c66438d5"),
];
pub(super) fn roster(f: &Value) -> Result<BTreeSet<String>> {
    canary227_peer::roster(f)?;
    let mut names = BTreeSet::new();
    for row in f["active"]
        .as_array()
        .context("prefix complete active census")?
    {
        let u = singleton227_admission::active_owner(row)?;
        let name = u["Id"].as_str().context("prefix active owner name")?;
        ensure!(
            names.insert(name.to_owned()) && u["NRestarts"] == "0",
            "duplicate/restarted prefix peer"
        );
        if let Some((_, iid)) = LEGACY.iter().find(|(n, _)| *n == name) {
            ensure!(
                u["InvocationID"] == *iid,
                "prefix protected legacy invocation changed"
            );
        } else if name == canary227::UNIT {
            canary227_peer::row_scope(row)?;
        } else if name == native228::UNIT {
            ensure!(
                row["epoch"] == 228
                    && row["phase"] == "private-cold-snapshot-verification"
                    && row["ordinary_replay_claim"] == false,
                "native228 peer scope differs"
            );
        } else if name == singleton209::UNIT {
            ensure!(
                row["epoch"] == 209
                    && row["phase"] == "diagnostic-qualification"
                    && row["ordinary_replay_claim"] == false,
                "full209 peer scope differs"
            );
        } else {
            anyhow::bail!("unmodeled full-prefix peer:{name}");
        }
        ensure!(row["epoch"] != 223, "another active223 owner exists");
    }
    Ok(names)
}
fn names(f: &Value) -> Result<BTreeSet<String>> {
    let mut names = f["unit_census"]
        .as_object()
        .context("prefix full unit census")?
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    names.insert(c::UNIT.into());
    Ok(names)
}
pub(super) fn owners(f: &Value, current: &BTreeMap<String, Value>, candidate: bool) -> Result<()> {
    roster(f)?;
    let mut peers = current.clone();
    peers.remove(c::UNIT);
    singleton227_admission::owners(f, &peers)?;
    let own = current
        .get(c::UNIT)
        .context("prefix candidate census missing")?;
    if !candidate {
        ensure!(
            own["MainPID"] == "0"
                && matches!(own["ActiveState"].as_str(), Some("inactive" | "failed")),
            "full prefix already active"
        );
    }
    Ok(())
}
pub(super) fn guard_selector(name: &str) -> Result<(&'static str, &'static str)> {
    Ok(match name {
        "horizon-qualify-225-natural-root-resource-shrink-budget-2f856bd-v1.service" => (
            "horizon-ownroot225-protective-v1.service",
            "/var/lib/jetstreamer/horizon-ownroot225-rebased-guard-receipts-v1",
        ),
        "horizon-qualify-205-shrink-root-prefix-resource-5c01bf93-v1.service" => (
            "horizon-prefix205-protective-v1.service",
            "/var/lib/jetstreamer/horizon-prefix205-guard-receipts-v1",
        ),
        "horizon-qualify-204-shrink-root-prefix-resource-fcbf3992-v1.service" => (
            "horizon-prefix204-protective-v1.service",
            "/var/lib/jetstreamer/horizon-prefix204-guard-receipts-v1",
        ),
        singleton227::UNIT => (
            "horizon-singleton227-protective-v1.service",
            "/var/lib/jetstreamer/horizon-singleton227-guard-receipts-v1",
        ),
        singleton209::UNIT => (
            "horizon-singleton209-protective-v1.service",
            "/var/lib/jetstreamer/horizon-singleton209-guard-receipts-v1",
        ),
        canary227::UNIT => (canary227_peer::PROTECTIVE, ""),
        native228::UNIT => (
            "horizon-native228-protective-v1.service",
            "/var/lib/jetstreamer/horizon-native228-guard-receipts-v1",
        ),
        _ => anyhow::bail!("unmodeled protective selector:{name}"),
    })
}
fn completed_guards(
    f: &Value,
    guards: &BTreeMap<String, BoundFile>,
    sample: u64,
    now: u64,
) -> Result<Value> {
    let expected = roster(f)?;
    ensure!(
        expected == guards.keys().cloned().collect(),
        "prefix guard set must cover the whole active census exactly"
    );
    let mut history = BTreeMap::new();
    for (name, bound) in guards {
        let (unit, dir) = guard_selector(name)?;
        let dir = if name == singleton209::UNIT || name == canary227::UNIT {
            let parent = bound.path.parent().context("full209 bound guard parent")?;
            ensure!(
                parent.starts_with("/var/lib/jetstreamer"),
                "full209 guard receipt escaped private evidence"
            );
            parent
        } else {
            Path::new(dir)
        };
        let selected = warmup223::completed_guard_binding(unit, dir, sample, now)?;
        ensure!(
            selected["binding"] == private157::binding(bound),
            "prefix guard is not latest completed protective fire:{name}"
        );
        let timer = singleton227_capture::properties(
            &unit.replace(".service", ".timer"),
            "ActiveState,SubState",
        )?;
        ensure!(
            timer.get("ActiveState").is_some_and(|s| s == "active"),
            "prefix protected timer is not active:{name}"
        );
        history.insert(name.clone(), selected);
    }
    Ok(json!(history))
}
fn sample(s: &Spec, o: &Value, f: &Value, now: u64) -> Result<(u64, u64, u64)> {
    sample_for_plan(s, o, f, now, true)
}
fn sample_for_plan(
    s: &Spec,
    o: &Value,
    f: &Value,
    now: u64,
    require_memory_fit: bool,
) -> Result<(u64, u64, u64)> {
    let t = utc_seconds(
        o["recorded_at_utc"]
            .as_str()
            .context("prefix observer time")?,
    )?;
    ensure!(
        t <= now
            && now - t <= 1800
            && o["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && f["schema"] == SCHEMA
            && f["first_epoch"] == 201
            && f["last_epoch"] == 300
            && f["sampled_at_utc"] == o["recorded_at_utc"]
            && f["observer_receipt"].as_str() == s.observer.path.to_str()
            && f["observer_sha256"] == s.observer.sha256
            && f["inventory"]["anomalies"] == 0
            && o["vm_max_map_count"].as_u64().is_some_and(|n| n >= 4194304),
        "prefix requires a fresh accepted complete observation"
    );
    let floor = singleton227_admission::century_floor_for(f, 223)?;
    let total = o["host_memory"]["total_kib"]
        .as_u64()
        .and_then(|n| n.checked_mul(1024))
        .context("prefix total memory")?;
    let available = o["host_memory"]["conservative_available_kib"]
        .as_u64()
        .and_then(|n| n.checked_mul(1024))
        .context("prefix available memory")?;
    let rss = o["lane_rss_history"]["200"]["maximum_observed_lane_rss_bytes"]
        .as_u64()
        .filter(|n| *n > 0)
        .context("prefix century RSS history")?;
    let ceiling = rss.checked_mul(3).context("prefix RSS overflow")? / 2;
    ensure!(
        o["lane_rss_history"]["200"]["reservation_ceiling_bytes"] == ceiling
            && c::MEMORY <= ceiling,
        "prefix memory cap exceeds century1.5x observed RSS"
    );
    let psi = &o["host_global_pressure"]["cross_sample"];
    ensure!(
        psi["status"] == "observed" && psi["elapsed_millis"].as_u64().is_some_and(|n| n > 0),
        "prefix unobserved pressure"
    );
    for (counter, fraction) in [
        ("memory.full_total_usec", 100),
        ("cpu.some_total_usec", 500),
        ("io.full_total_usec", 100),
    ] {
        ensure!(
            psi["counter_delta_usec"][counter]
                .as_u64()
                .zip(psi["elapsed_millis"].as_u64())
                .is_some_and(|(v, ms)| v <= ms.saturating_mul(fraction)),
            "prefix pressure:{counter}"
        );
    }
    let names = roster(f)?;
    let mut seen = BTreeSet::new();
    for row in o["diagnostic_replays"]
        .as_array()
        .context("prefix diagnostic resource census")?
    {
        let name = row["producer_unit"]
            .as_str()
            .context("prefix sampled unit")?;
        if row["status"] != "observed" {
            ensure!(
                !names.contains(name),
                "prefix active owner lacks observation"
            );
            continue;
        }
        ensure!(
            names.contains(name) && seen.insert(name.to_owned()),
            "prefix has extra/duplicate observed owner"
        );
        let obs = &row["observation"];
        let owner = &f["unit_census"][name];
        ensure!(
            obs["invocation_binding_stable"] == true && row["error"].is_null(),
            "prefix unstable observation"
        );
        for phase in ["producer_before", "producer_after"] {
            ensure!(
                obs[phase]["unit"] == name
                    && obs[phase]["invocation_id"] == owner["InvocationID"]
                    && obs[phase]["restarts"] == 0,
                "prefix sampled peer identity differs"
            );
        }
    }
    ensure!(
        seen == names && o["replays"].as_array().is_some_and(Vec::is_empty),
        "prefix sample is not complete private owner census"
    );
    ensure!(
        !require_memory_fit || available >= total / 10 + c::MEMORY,
        "prefix candidate exceeds90percent memory target"
    );
    Ok((t, floor, available))
}
fn arithmetic(
    floor: u64,
    growth: u64,
    guard_floor: u64,
    auxiliary: u64,
    total: u64,
) -> Result<(u64, u64)> {
    let protected = floor
        .checked_add(growth)
        .context("prefix disk overflow")?
        .max(guard_floor);
    ensure!(
        protected <= c::FLOOR,
        "prefix protected growth/unchanged guard floor exceeds sealed2TB plan; new generation required"
    );
    let base = (480u64 << 30)
        .max(total / 10)
        .checked_add(c::MEMORY)
        .context("prefix baseline memory overflow")?;
    Ok((
        protected,
        base.checked_add(auxiliary)
            .context("prefix auxiliary memory overflow")?,
    ))
}
pub(super) fn validate_saved(a: &Value) -> Result<()> {
    ensure!(
        a["schema"] == "jetstreamer-private-epoch223-native20-prefix-admission-v1"
            && a["admitted"] == true
            && a["epoch"] == 223
            && a["mode"] == "prefix"
            && a["unit"] == c::UNIT
            && a["private_run_root"] == c::ROOT
            && a["candidate_incremental_peak_bytes"] == c::PEAK
            && a["maximum_memory_bytes"] == c::MEMORY
            && a["protected_existing_floor_bytes"] == c::FLOOR
            && a["required_initial_free_bytes"] == c::INITIAL
            && a["fresh_complete_census_passed"] == true
            && a["older_producers_and_guards_preserved"] == true
            && a["memory_target_percent"] == 90
            && a["replay_launch_authorized"] == false
            && a["capability"] == json!({"path":c::CAPABILITY,"sha256":c::CAPABILITY_SHA})
            && a["warmup_terminal"] == json!({"path":c::WARMUP,"sha256":c::WARMUP_SHA})
            && a["resource_plan"] == json!({"path":c::PLAN,"sha256":c::PLAN_SHA}),
        "native20 prefix saved admission scope differs"
    );
    let (computed, memory) = arithmetic(
        a["century_floor_bytes"]
            .as_u64()
            .context("prefix saved floor")?,
        a["protected_remaining_growth_bytes"]
            .as_u64()
            .context("prefix saved growth")?,
        a["maximum_existing_guard_floor_bytes"]
            .as_u64()
            .context("prefix saved guard floor")?,
        a["auxiliary_memory_growth_bytes"]
            .as_u64()
            .context("prefix saved auxiliary memory")?,
        a["host_total_memory_bytes"]
            .as_u64()
            .context("prefix saved host total")?,
    )?;
    ensure!(
        a["computed_existing_floor_bytes"] == computed
            && a["required_available_memory_bytes"] == memory
            && [
                "sampled_available_memory_bytes",
                "actual_available_memory_before_bytes",
                "actual_available_memory_after_bytes"
            ]
            .iter()
            .all(|k| a[*k].as_u64().is_some_and(|n| n >= memory))
            && [
                "sampled_free_bytes",
                "actual_free_before_bytes",
                "actual_free_after_bytes"
            ]
            .iter()
            .all(|k| a[*k].as_u64().is_some_and(|n| n >= c::INITIAL)),
        "prefix saved resource arithmetic differs"
    );
    let f = bound_json(&serde_json::from_value(a["fleet"].clone())?)?;
    let before: BTreeMap<String, Value> = serde_json::from_value(a["unit_census_before"].clone())?;
    let after: BTreeMap<String, Value> = serde_json::from_value(a["unit_census_after"].clone())?;
    owners(&f, &before, false)?;
    owners(&f, &after, false)?;
    let guards: BTreeMap<String, BoundFile> =
        serde_json::from_value(a["protected_guards"].clone())?;
    ensure!(
        guards.keys().cloned().collect::<BTreeSet<_>>() == roster(&f)?,
        "prefix saved guard census differs"
    );
    let mut maximum = 0;
    for (name, binding) in guards {
        let guard = bound_json(&binding)?;
        maximum = maximum.max(
            guard["minimum_free_bytes"]
                .as_u64()
                .filter(|n| *n > 0)
                .context("saved prefix guard floor missing")?,
        );
        let selected = &a["protected_guard_history"][&name];
        ensure!(
            selected["binding"] == private157::binding(&binding)
                && selected["history"]["unit"] == guard_selector(&name)?.0,
            "prefix saved guard selection differs"
        );
        warmup223::validate_completed_guard_history(&selected["history"], &guard)?;
    }
    ensure!(
        a["maximum_existing_guard_floor_bytes"] == maximum,
        "saved prefix existing guard maximum differs"
    );
    c::no_publication(a)
}
pub(super) fn run() -> Result<()> {
    let (binding, self_sha) = publication203::parsed_args("admit-prefix223-native20")?;
    let s: Spec = serde_json::from_value(native209::immutable_json(&binding)?)?;
    ensure!(
        s.schema == "jetstreamer-private-epoch223-native20-prefix-admission-spec-v1"
            && s.output.parent().and_then(Path::parent) == Some(Path::new("/var/lib/jetstreamer"))
            && s.output
                .parent()
                .and_then(Path::file_name)
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("horizon-native223-prefix-admission-"))
            && s.output.file_name().is_some_and(|n| n == "admission.json"),
        "prefix admission spec/output scope differs"
    );
    if s.output.try_exists()? {
        let old = native209::immutable_json(&serde_json::from_value(private157::file_binding(
            &s.output,
        )?)?)?;
        validate_saved(&old)?;
        ensure!(
            old["spec"] == private157::binding(&binding) && old["self_sha256"] == self_sha,
            "prefix admission retry conflicts"
        );
        return Ok(());
    }
    validate_output_destination(&s.output)?;
    c::prerequisites()?;
    let o = bound_json(&s.observer)?;
    let f = bound_json(&s.fleet)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let (t, floor, available) = sample(&s, &o, &f, now)?;
    let guard_history = completed_guards(&f, &s.protected_guards, t, now)?;
    let names = names(&f)?;
    let before = census(&names, 201, 300)?;
    owners(&f, &before, false)?;
    let free_before = singleton227_admission::disk_free()?;
    let memory_before = native209_admission::actual_memory()?;
    let (growth, measurements) =
        prefix223_native20_peer228::disk(&f, &o, &s.protected_guards, t, now)?;
    let (auxiliary, memory_evidence) = prefix223_native20_peer228::memory(&f)?;
    let maximum_guard = s
        .protected_guards
        .values()
        .map(bound_json)
        .collect::<Result<Vec<_>>>()?
        .iter()
        .map(|g| {
            g["minimum_free_bytes"]
                .as_u64()
                .filter(|n| *n > 0)
                .context("prefix protected guard floor")
        })
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .max()
        .unwrap_or(0);
    let total = o["host_memory"]["total_kib"]
        .as_u64()
        .and_then(|n| n.checked_mul(1024))
        .context("prefix host memory")?;
    let (computed, required_memory) = arithmetic(floor, growth, maximum_guard, auxiliary, total)?;
    let sampled_free = o["filesystem"]["conservative_available_bytes"]
        .as_u64()
        .context("prefix sampled free disk")?;
    let (after_growth, after_measurements) =
        prefix223_native20_peer228::disk(&f, &o, &s.protected_guards, t, now)?;
    let (after_memory, _) = prefix223_native20_peer228::memory(&f)?;
    let after = census(&names, 201, 300)?;
    owners(&f, &after, false)?;
    let free_after = singleton227_admission::disk_free()?;
    let memory_after = native209_admission::actual_memory()?;
    ensure!(
        after_growth <= growth
            && after_memory <= auxiliary
            && [sampled_free, free_before, free_after]
                .into_iter()
                .all(|n| n >= c::INITIAL)
            && [available, memory_before, memory_after]
                .into_iter()
                .all(|n| n >= required_memory),
        "prefix current/observed expanded envelope does not fit"
    );
    let mut value = json!({"schema":"jetstreamer-private-epoch223-native20-prefix-admission-v1","epoch":223,"mode":"prefix","admitted":true,"unit":c::UNIT,"private_run_root":c::ROOT,
        "candidate_incremental_peak_bytes":c::PEAK,"maximum_memory_bytes":c::MEMORY,"protected_existing_floor_bytes":c::FLOOR,"required_initial_free_bytes":c::INITIAL,
        "century_floor_bytes":floor,"protected_remaining_growth_bytes":growth,"maximum_existing_guard_floor_bytes":maximum_guard,"computed_existing_floor_bytes":computed,
        "auxiliary_memory_growth_bytes":auxiliary,"host_total_memory_bytes":total,"required_available_memory_bytes":required_memory,
        "sampled_available_memory_bytes":available,"actual_available_memory_before_bytes":memory_before,"actual_available_memory_after_bytes":memory_after,
        "sampled_free_bytes":sampled_free,"actual_free_before_bytes":free_before,"actual_free_after_bytes":free_after,
        "protected_growth_evidence":measurements,"protected_growth_evidence_after":after_measurements,"protected_memory_evidence":memory_evidence});
    let provenance = json!({"capability":{"path":c::CAPABILITY,"sha256":c::CAPABILITY_SHA},"warmup_terminal":{"path":c::WARMUP,"sha256":c::WARMUP_SHA},"resource_plan":{"path":c::PLAN,"sha256":c::PLAN_SHA},
        "spec":private157::binding(&binding),"self_sha256":self_sha,"observer":private157::binding(&s.observer),"fleet":private157::binding(&s.fleet),"protected_guards":s.protected_guards,"protected_guard_history":guard_history,
        "unit_census_before":before,"unit_census_after":after,"fresh_complete_census_passed":true,"older_producers_and_guards_preserved":true,"memory_target_percent":90,
        "recorded_unix_seconds":now,"replay_launch_authorized":false});
    for (key, field) in provenance
        .as_object()
        .context("prefix admission provenance")?
    {
        ensure!(
            value.get(key).is_none(),
            "duplicate prefix admission field:{key}"
        );
        value[key] = field.clone();
    }
    for key in [
        "ordinary_replay_authorized",
        "full_cold_epoch_peak_qualified",
        "repair_closed",
        "canonical_prefix_independently_qualified",
        "native_restart_qualified",
        "suffix_qualified",
        "assembly_qualified",
        "full_epoch_qualified",
        "full_plugin_qualified",
        "runtime_promotion_authorized",
        "canonical_sidecar_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        value[key] = json!(false);
    }
    validate_saved(&value)?;
    private157::immutable_receipt(&s.output, &value)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sealed_floor_preserves_larger_live_guard_baselines_and_checked_math() {
        assert_eq!(
            arithmetic(100, 200, c::FLOOR, 50, 1000).unwrap().0,
            c::FLOOR
        );
        assert!(arithmetic(100, 200, c::FLOOR + 1, 50, 1000).is_err());
        assert!(arithmetic(u64::MAX, 1, 0, 0, 1).is_err());
        assert!(arithmetic(1, 1, 1, u64::MAX, 1).is_err());
        assert_eq!(
            arithmetic(1, 1, 1, 50, 1000).unwrap().1,
            (480u64 << 30) + c::MEMORY + 50
        );
    }
    #[test]
    fn complete_roster_rejects_unknown_duplicate_restarted_and_old223_owners() {
        let good = json!({"unit_census":{},"active":[{"epoch":227,"unit":{"Id":singleton227::UNIT,"InvocationID":LEGACY[3].1,"NRestarts":"0"}}]});
        assert_eq!(roster(&good).unwrap().len(), 1);
        for (key, value) in [
            ("Id", json!("unaccounted.service")),
            ("NRestarts", json!("1")),
            ("InvocationID", json!("0".repeat(32))),
        ] {
            let mut bad = good.clone();
            bad["active"][0]["unit"][key] = value;
            assert!(roster(&bad).is_err());
        }
        let mut bad = good.clone();
        bad["active"][0]["epoch"] = json!(223);
        assert!(roster(&bad).is_err());
        let mut bad = good.clone();
        let row = bad["active"][0].clone();
        bad["active"].as_array_mut().unwrap().push(row);
        assert!(roster(&bad).is_err());
        for (name, epoch, phase) in [
            (native228::UNIT, 228, "private-cold-snapshot-verification"),
            (singleton209::UNIT, 209, "diagnostic-qualification"),
        ] {
            let mut extended = good.clone();
            extended["active"].as_array_mut().unwrap().push(json!({"epoch":epoch,"phase":phase,"ordinary_replay_claim":false,"unit":{"Id":name,"InvocationID":"a".repeat(32),"NRestarts":"0"}}));
            assert_eq!(roster(&extended).unwrap().len(), 2);
        }
    }
}
