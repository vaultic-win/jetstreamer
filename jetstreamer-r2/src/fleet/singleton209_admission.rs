//! Fresh full209 admission using the complete existing observation and native proof.
use super::{singleton209 as c, *};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    mode: String,
    observer: BoundFile,
    fleet: BoundFile,
    capability: BoundFile,
    native_input: BoundFile,
    #[serde(default)]
    terminal223: Option<BoundFile>,
    resource_plan: BoundFile,
    protected_guards: BTreeMap<String, BoundFile>,
    output: PathBuf,
}
fn supported_peer(active: &Value) -> Result<()> {
    let owner = singleton227_admission::active_owner(active)?;
    ensure!(
        active["epoch"] != 223
            || owner["Id"] == "archive-223-v1620-native-input-release-actual-v1.service",
        "209 full admission does not account for this live223 repair envelope; bind its exact resource model or terminal proof first"
    );
    Ok(())
}
fn guard_floor_values(guards: &[Value]) -> Result<u64> {
    let mut maximum = 0;
    for g in guards {
        ensure!(
            g["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1",
            "209 protected guard floor schema differs"
        );
        let floor = g["minimum_free_bytes"]
            .as_u64()
            .filter(|n| *n > 0)
            .context("209 protected guard baseline missing")?;
        maximum = maximum.max(floor);
    }
    Ok(maximum)
}
pub(super) fn protected_guard_floor(guards: &BTreeMap<String, BoundFile>) -> Result<u64> {
    guard_floor_values(
        &guards
            .values()
            .map(bound_json)
            .collect::<Result<Vec<_>>>()?,
    )
}
fn sample(
    s: &Spec,
    o: &Value,
    f: &Value,
    native: &Value,
    now: u64,
    required: u64,
) -> Result<(u64, u64)> {
    let t = utc_seconds(o["recorded_at_utc"].as_str().context("209 sample time")?)?;
    ensure!(
        s.mode == "replay"
            && t <= now
            && now - t <= 1800
            && o["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && f["schema"] == SCHEMA
            && f["first_epoch"] == 201
            && f["last_epoch"] == 300
            && f["observer_receipt"].as_str() == s.observer.path.to_str()
            && f["observer_sha256"] == s.observer.sha256
            && f["sampled_at_utc"] == o["recorded_at_utc"]
            && f["inventory"]["anomalies"] == 0
            && o["filesystem"]["conservative_available_bytes"]
                .as_u64()
                .is_some_and(|n| n >= required)
            && o["vm_max_map_count"].as_u64().is_some_and(|n| n >= 4194304),
        "209 stale/incomplete resource sample"
    );
    let total = o["host_memory"]["total_kib"]
        .as_u64()
        .context("209 total memory")?
        .checked_mul(1024)
        .context("209 memory overflow")?;
    let available = o["host_memory"]["conservative_available_kib"]
        .as_u64()
        .context("209 available memory")?
        .checked_mul(1024)
        .context("209 memory overflow")?;
    let required_memory = (total / 10)
        .checked_add(c::MEMORY)
        .context("209 memory target overflow")?;
    ensure!(
        available >= required_memory,
        "209 native cap exceeds 90 percent memory target"
    );
    let rss = o["lane_rss_history"]["200"]["maximum_observed_lane_rss_bytes"]
        .as_u64()
        .filter(|n| *n > 0)
        .context("209 century RSS")?;
    ensure!(
        o["lane_rss_history"]["200"]["reservation_ceiling_bytes"]
            == rss.checked_mul(3).context("209 RSS overflow")? / 2,
        "209 century RSS reservation differs"
    );
    ensure!(
        o["lane_rss_history"]["200"]["reservation_ceiling_bytes"]
            .as_u64()
            .is_some_and(|n| c::MEMORY <= n),
        "209 full memory reservation exceeds1.5x observed century RSS"
    );
    let psi = &o["host_global_pressure"]["cross_sample"];
    ensure!(
        psi["status"] == "observed" && psi["elapsed_millis"].as_u64().is_some_and(|n| n > 0),
        "209 pressure unobserved"
    );
    for (counter, fraction) in [
        ("memory.full_total_usec", 100u64),
        ("cpu.some_total_usec", 500),
        ("io.full_total_usec", 100),
    ] {
        ensure!(
            psi["counter_delta_usec"][counter]
                .as_u64()
                .zip(psi["elapsed_millis"].as_u64())
                .is_some_and(|(n, t)| n <= t.saturating_mul(fraction)),
            "209 resource pressure:{counter}"
        );
    }
    let mut rows = o["replays"]
        .as_array()
        .context("209 ordinary sample census")?
        .iter()
        .collect::<Vec<_>>();
    for diagnostic in o["diagnostic_replays"]
        .as_array()
        .context("209 diagnostic census")?
    {
        if diagnostic["producer_unit"] == native209::UNIT {
            let iid = native["invocation_id"]
                .as_str()
                .context("209 prior native IID")?;
            native209_terminal::terminal_shape(&f["unit_census"][native209::UNIT], iid)?;
            ensure!(
                diagnostic["status"] == "unavailable"
                    || (diagnostic["status"] == "observed"
                        && diagnostic["observation"]["invocation_binding_stable"] == true
                        && diagnostic["observation"]["scratch_path"]
                            == format!("{}/scratch", native209::ROOT)
                        && diagnostic["observation"]["producer_before"]["invocation_id"] == iid
                        && diagnostic["observation"]["producer_after"]["invocation_id"] == iid),
                "209 obsolete native sample does not match the independently qualified terminal owner"
            );
            continue;
        }
        if diagnostic["status"] != "observed" {
            native209_admission::unavailable_is_inactive(diagnostic, f)?;
            continue;
        }
        ensure!(
            diagnostic["error"].is_null(),
            "209 observed diagnostic has error"
        );
        rows.push(&diagnostic["observation"]);
    }
    let mut seen = BTreeSet::new();
    for active in f["active"].as_array().context("209 active census")? {
        supported_peer(active)?;
        let owner = singleton227_admission::active_owner(active)?;
        let unit = owner["Id"].as_str().context("209 owner name")?;
        ensure!(
            unit != c::UNIT && active["epoch"] != 209,
            "209 already has active work"
        );
        if !seen.insert(unit.to_owned()) {
            continue;
        }
        let observed = rows
            .iter()
            .filter(|r| r["producer_after"]["unit"] == unit)
            .collect::<Vec<_>>();
        ensure!(
            observed.len() == 1,
            "209 every owner needs exactly one coordinated observation"
        );
        let row = observed[0];
        ensure!(
            row["invocation_binding_stable"] == true
                && row["producer_before"]["invocation_id"] == owner["InvocationID"]
                && row["producer_after"]["invocation_id"] == owner["InvocationID"]
                && row["producer_after"]["restarts"] == 0
                && row["producer_after"]["rss"]["census_stable"] == true,
            "209 live memory/identity sample differs"
        );
    }
    ensure!(
        rows.len() == seen.len(),
        "209 resource census has an unaccounted owner"
    );
    Ok((t, required_memory))
}

fn candidate(p: &Value, protected: u64, required: u64) -> Result<()> {
    ensure!(
        p["schema"] == "jetstreamer-private-epoch209-singleton-resource-plan-v1"
            && p["epoch"] == 209
            && p["mode"] == "replay"
            && p["unit"] == c::UNIT
            && p["run_root"] == c::ROOT
            && p["candidate_incremental_peak_bytes"] == c::PEAK
            && p["maximum_scratch_bytes"] == c::SCRATCH
            && p["memory_max_bytes"] == c::MEMORY
            && p["memory_high_bytes"] == 150000000000u64
            && p["guard_minimum_free_bytes"] == protected
            && p["required_initial_free_bytes"] == required
            && p["node_sha256"] == c::NODE_SHA
            && p["guard_sha256"] == c::GUARD_SHA
            && p["maximum_runtime_seconds"] == 259200
            && p["worker_sha256"] == c::WORKER_SHA
            && p["snapshot_sha256"] == c::SNAPSHOT_SHA
            && p["manifest_fingerprint"] == c::FINGERPRINT,
        "209 full candidate profile or envelope differs"
    );
    c::no_publication(p)
}
fn empty_root() -> Result<()> {
    let root = Path::new(c::ROOT);
    let output = root.join("output");
    for path in [root, &output] {
        let m = fs::symlink_metadata(path)?;
        ensure!(
            path.canonicalize()? == path && m.is_dir() && m.uid() == 1000 && m.mode() & 0o077 == 0,
            "209 full root/output must be canonical current-owner0700directories"
        );
    }
    ensure!(
        fs::read_dir(&output)?.next().is_none(),
        "209 full output is occupied"
    );
    let entries = fs::read_dir(root)?
        .map(|r| r.map(|e| e.file_name()))
        .collect::<std::io::Result<Vec<_>>>()?;
    ensure!(
        entries.len() == 1 && entries[0] == "output",
        "209 full root contains prior attempt state"
    );
    Ok(())
}
pub(super) fn run() -> Result<()> {
    let (binding, self_sha) = publication203::parsed_args("admit-singleton209")?;
    let s: Spec = serde_json::from_value(native209::immutable_json(&binding)?)?;
    ensure!(
        s.schema == "jetstreamer-private-epoch209-singleton-admission-spec-v1"
            && s.mode == "replay"
            && s.capability.path == Path::new(c::CAPABILITY)
            && s.output.parent().and_then(Path::parent) == Some(Path::new("/var/lib/jetstreamer"))
            && s.output
                .parent()
                .and_then(Path::file_name)
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("horizon-209-singleton-admission-"))
            && s.output.file_name().is_some_and(|n| n == "admission.json"),
        "209 full admission spec/output differs"
    );
    c::native(&s.native_input)?;
    let native = native209::immutable_json(&s.native_input)?;
    c::capability(&native209::immutable_json(&s.capability)?)?;
    if s.output.try_exists()? {
        let old = native209::immutable_json(&serde_json::from_value(private157::file_binding(
            &s.output,
        )?)?)?;
        ensure!(
            old["spec_sha256"] == binding.sha256
                && old["self_sha256"] == self_sha
                && old["admitted"] == true,
            "209 full admission retry conflicts"
        );
        return Ok(());
    }
    validate_output_destination(&s.output)?;
    singleton209_capability::inputs()?;
    empty_root()?;
    let o = bound_json(&s.observer)?;
    let f = bound_json(&s.fleet)?;
    let peer223 =
        singleton209_peer223::prepare(s.terminal223.as_ref(), &f, &o, &s.observer, &s.fleet)?;
    let (arithmetic_fleet, arithmetic_observer) =
        singleton209_peer223::arithmetic(&f, &o, peer223.as_ref())?;
    let arithmetic_guards = singleton209_peer223::guards(&s.protected_guards, peer223.as_ref());
    let p = native209::immutable_json(&s.resource_plan)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let t = utc_seconds(
        o["recorded_at_utc"]
            .as_str()
            .context("209 full sample clock")?,
    )?;
    let floor = singleton227_admission::century_floor_for(&f, 209)?;
    let free_before = singleton227_admission::disk_free()?;
    let (growth, measurements) = native209_admission::protected_growth(
        &arithmetic_fleet,
        &arithmetic_observer,
        &arithmetic_guards,
        t,
        now,
    )?;
    let computed = floor
        .checked_add(growth)
        .context("209 full protected growth overflow")?;
    let guard_baseline = protected_guard_floor(&arithmetic_guards)?;
    let protected = p["guard_minimum_free_bytes"]
        .as_u64()
        .context("209 full floor")?;
    ensure!(
        protected >= computed.max(guard_baseline),
        "209 full plan under-reserves protected growth or an existing guard's minimum-free baseline"
    );
    let required = protected
        .checked_add(c::PEAK)
        .context("209 full initial free overflow")?;
    candidate(&p, protected, required)?;
    let (_, required_memory) = sample(
        &s,
        &arithmetic_observer,
        &arithmetic_fleet,
        &native,
        now,
        required,
    )?;
    let (aux, aux_evidence) = native209_admission::auxiliary_memory(&arithmetic_fleet)?;
    let required_memory = required_memory
        .checked_add(aux)
        .context("209 full protected memory overflow")?;
    ensure!(
        o["host_memory"]["conservative_available_kib"]
            .as_u64()
            .and_then(|n| n.checked_mul(1024))
            .is_some_and(|n| n >= required_memory),
        "209 full sampled memory omits protected hard growth"
    );
    let mut names = f["unit_census"]
        .as_object()
        .context("209 full prior census")?
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    names.insert(c::UNIT.into());
    names.insert(native209::UNIT.into());
    let before = census(&names, 201, 300)?;
    singleton209_peer223::owners(&f, &before, peer223.as_ref())?;
    let iid = native["invocation_id"]
        .as_str()
        .context("209 full native IID")?;
    native209_terminal::terminal_shape(
        before
            .get(native209::UNIT)
            .context("209 full native owner missing")?,
        iid,
    )?;
    ensure!(
        before
            .get(c::UNIT)
            .is_some_and(|u| !diagnostic_stage_running(u)),
        "209 full owner already live"
    );
    let caps = singleton227_admission::limits(&arithmetic_fleet)?;
    let memory = native209_admission::actual_memory()?;
    let free = free_before.min(singleton227_admission::disk_free()?);
    ensure!(
        free >= required
            && memory >= required_memory
            && fs::read_to_string("/proc/sys/vm/max_map_count")?
                .trim()
                .parse::<u64>()?
                >= 4194304,
        "209 full actual envelope unavailable"
    );
    let after = census(&names, 201, 300)?;
    singleton209_peer223::owners(&f, &after, peer223.as_ref())?;
    native209_terminal::terminal_shape(
        after
            .get(native209::UNIT)
            .context("209 native owner missing after admission")?,
        iid,
    )?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    sample(
        &s,
        &arithmetic_observer,
        &arithmetic_fleet,
        &native,
        now,
        required,
    )?;
    let (after_growth, after_measurements) = native209_admission::protected_growth(
        &arithmetic_fleet,
        &arithmetic_observer,
        &arithmetic_guards,
        t,
        now,
    )?;
    let (after_aux, after_aux_evidence) = native209_admission::auxiliary_memory(&arithmetic_fleet)?;
    ensure!(
        before == after
            && caps == singleton227_admission::limits(&arithmetic_fleet)?
            && after_growth <= growth
            && after_aux <= aux
            && singleton227_admission::disk_free()? >= required
            && native209_admission::actual_memory()? >= required_memory,
        "209 full owners/caps/growth changed during admission"
    );
    let mut v = json!({"schema":"jetstreamer-private-epoch209-singleton-admission-v1","epoch":209,"mode":"replay","admitted":true,
        "unit":c::UNIT,"private_run_root":c::ROOT,"candidate_incremental_peak_bytes":c::PEAK,"maximum_scratch_bytes":c::SCRATCH,
        "maximum_memory_bytes":c::MEMORY,"protected_existing_floor_bytes":protected,"required_initial_free_bytes":required,
        "century_floor_bytes":floor,"protected_remaining_growth_bytes":growth,"computed_existing_floor_bytes":computed,
        "preserved_guard_baseline_floor_bytes":guard_baseline,
        "protected_growth_measurements_before":measurements,"protected_growth_measurements_after":after_measurements,
        "auxiliary_remaining_memory_growth_bytes":aux,"auxiliary_memory_before":aux_evidence,"auxiliary_memory_after":after_aux_evidence,
        "protected_memory_limits":caps,"unit_census_before":before,"unit_census_after":after,"memory_target_percent":90,
        "available_memory_bytes":memory,"available_disk_bytes":free});
    let evidence = json!({"observer":private157::binding(&s.observer),"fleet":private157::binding(&s.fleet),
        "capability":private157::binding(&s.capability),"native_input":private157::binding(&s.native_input),"resource_plan":private157::binding(&s.resource_plan),
        "protected_guards":s.protected_guards,"terminal223":s.terminal223.as_ref().map(private157::binding),
        "terminal223_accounting":singleton209_peer223::evidence(peer223.as_ref()),"fresh_complete_census_passed":true,"older_producers_and_guards_preserved":true,
        "all_immutable_inputs_rehashed":true,"snapshot_restored":false,"producer_started":false,"resource_samples_taken":0,
        "recorded_unix_seconds":now,"maximum_launch_delay_seconds":900,"spec_sha256":binding.sha256,"self_sha256":self_sha});
    for (key, value) in evidence
        .as_object()
        .context("209 full admission evidence")?
    {
        ensure!(v.get(key).is_none(), "209 full admission field collision");
        v[key] = value.clone();
    }
    for key in [
        "runtime_promotion_authorized",
        "full_epoch_qualified",
        "canonical_sidecar_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        v[key] = json!(false);
    }
    private157::immutable_receipt(&s.output, &v)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn candidate_must_preserve_the_largest_existing_guard_baseline_without_summing_it_per_lane() {
        let guard = |n: u64| json!({"schema":"jetstreamer-horizon-standalone-guard-sample-v1","minimum_free_bytes":n});
        let floor = guard_floor_values(&[
            guard(2_000_000_000_000),
            guard(1_372_922_903_443),
            guard(1_210_361_856_915),
        ])
        .unwrap();
        assert_eq!(floor, 2_000_000_000_000);
        assert_eq!(floor + c::PEAK, 2_471_798_691_840);
        assert_eq!(floor + c::PEAK - 2_420_007_051_264, 51_791_640_576);
        assert!(guard_floor_values(&[guard(0)]).is_err());
        assert!(guard_floor_values(&[json!({"minimum_free_bytes":floor})]).is_err());
    }
    #[test]
    fn live223_repair_cannot_borrow_the_older_native_only_envelope() {
        supported_peer(&json!({"epoch":204,"producer":{"Id":"full204"}})).unwrap();
        supported_peer(&json!({"epoch":223,"unit":{"Id":"archive-223-v1620-native-input-release-actual-v1.service"}})).unwrap();
        let repair = json!({"epoch":223,"unit":{"Id":"horizon-warmup223-native20-v2.service","InvocationID":"58ab3d9221a6452685b8eab3ceabdb49"}});
        assert!(supported_peer(&repair).is_err());
        assert!(supported_peer(&json!({"epoch":223,"controller":{"Id":"repair"}})).is_err());
    }
    #[test]
    #[ignore = "root-only accepted333 metadata reader proof; no resource poll, admission, Bank, process or network"]
    fn root_terminal_native209_sample_preserves_four_live_owners_without_a_new_poll() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let fleet=BoundFile {path:"/var/lib/jetstreamer/horizon-campaign-fleet/native209-terminal-from333-v1/fleet-ledger.json".into(),
            sha256:"2a8fc411fe86ffd16b75ff1ee9d386d3f0f77c1426a9ac44607c2c35b1a98bc4".into()};
        let f = bound_json(&fleet).unwrap();
        let observer = BoundFile {
            path: f["observer_receipt"].as_str().unwrap().into(),
            sha256: f["observer_sha256"].as_str().unwrap().into(),
        };
        let o = bound_json(&observer).unwrap();
        let native_input = BoundFile {
            path: "/var/lib/jetstreamer/horizon-native209-terminal-proof-v1/proof.json".into(),
            sha256: c::NATIVE_PROOF_SHA.into(),
        };
        let native = native209::immutable_json(&native_input).unwrap();
        let empty = || BoundFile {
            path: "/unused-metadata-test-only".into(),
            sha256: "0".repeat(64),
        };
        let s = Spec {
            schema: "jetstreamer-private-epoch209-singleton-admission-spec-v1".into(),
            mode: "replay".into(),
            observer,
            fleet,
            capability: empty(),
            native_input,
            terminal223: None,
            resource_plan: empty(),
            protected_guards: BTreeMap::new(),
            output: "/unused-metadata-test-only".into(),
        };
        let now = f["recorded_unix_seconds"].as_u64().unwrap();
        assert_eq!(f["active"].as_array().unwrap().len(), 4);
        sample(&s, &o, &f, &native, now, 1).unwrap();
        let mut bad = f.clone();
        bad["unit_census"][native209::UNIT]["ActiveState"] = json!("active");
        assert!(sample(&s, &o, &bad, &native, now, 1).is_err());
    }
    #[test]
    fn full_candidate_cannot_borrow_native_cold_budget_or_drop_publication_gates() {
        let mut p = json!({"schema":"jetstreamer-private-epoch209-singleton-resource-plan-v1","epoch":209,"mode":"replay","unit":c::UNIT,"run_root":c::ROOT,
            "candidate_incremental_peak_bytes":c::PEAK,"maximum_scratch_bytes":c::SCRATCH,"memory_max_bytes":c::MEMORY,"memory_high_bytes":150000000000u64,
            "guard_minimum_free_bytes":1000,"required_initial_free_bytes":c::PEAK+1000,"node_sha256":c::NODE_SHA,"guard_sha256":c::GUARD_SHA,
            "maximum_runtime_seconds":259200,"worker_sha256":c::WORKER_SHA,"snapshot_sha256":c::SNAPSHOT_SHA,"manifest_fingerprint":c::FINGERPRINT});
        for key in [
            "runtime_promotion_authorized",
            "full_epoch_qualified",
            "canonical_sidecar_authorized",
            "publication_authorized",
            "remote_mutations",
            "r2_mutations",
        ] {
            p[key] = json!(false);
        }
        candidate(&p, 1000, c::PEAK + 1000).unwrap();
        for key in p.as_object().unwrap().keys() {
            let mut bad = p.clone();
            bad[key] = Value::Null;
            assert!(candidate(&bad, 1000, c::PEAK + 1000).is_err(), "{key}");
        }
        let mut bad = p;
        bad["candidate_incremental_peak_bytes"] = json!(c::SCRATCH);
        assert!(candidate(&bad, 1000, c::PEAK + 1000).is_err());
    }
}
