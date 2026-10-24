//! Admit only the cached bootstrap-only native 227 check, never start it.
use super::native209_admission::{actual_memory, sealed_file, unavailable_is_inactive};
use super::native227_v1625 as c;
use super::*;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    mode: String,
    observer: BoundFile,
    fleet: BoundFile,
    cold_plan: BoundFile,
    resource_plan: BoundFile,
    protected_guards: BTreeMap<String, BoundFile>,
    output: PathBuf,
}
fn candidate(p: &Value, protected: u64, required: u64) -> Result<()> {
    ensure!(
        p["schema"] == "jetstreamer-private-epoch227-v1625-native-resource-plan-v1"
            && p["epoch"] == 227
            && p["mode"] == "native-cold"
            && p["unit"] == c::UNIT
            && p["run_root"] == c::ROOT
            && p["candidate_incremental_peak_bytes"] == c::SCRATCH
            && p["maximum_scratch_bytes"] == c::SCRATCH
            && p["maximum_memory_bytes"] == c::MEMORY
            && p["test_sha256"] == c::TEST_SHA
            && p["snapshot_sha256"] == c::SNAPSHOT_SHA
            && p["genesis_sha256"] == c::GENESIS_SHA
            && p["guard_sha256"] == c::GUARD_SHA
            && p["cold_plan"] == json!({"path":c::PLAN,"sha256":c::PLAN_SHA})
            && p["guard_minimum_free_bytes"] == protected
            && p["required_initial_free_bytes"] == required,
        "227 candidate fingerprint, envelope or native-only mode differs"
    );
    c::no_authority(p)
}
fn sample(s: &Spec, o: &Value, f: &Value, now: u64, required: u64) -> Result<(u64, u64)> {
    native210_peer_history::validate(f)?;
    let t = utc_seconds(o["recorded_at_utc"].as_str().context("227 sample time")?)?;
    ensure!(
        s.mode == "native-cold"
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
        "227 stale/incomplete resource sample"
    );
    let total = o["host_memory"]["total_kib"]
        .as_u64()
        .context("227 total memory")?
        .checked_mul(1024)
        .context("227 memory overflow")?;
    let available = o["host_memory"]["conservative_available_kib"]
        .as_u64()
        .context("227 available memory")?
        .checked_mul(1024)
        .context("227 memory overflow")?;
    let required_memory = (total / 10)
        .checked_add(c::MEMORY)
        .context("227 memory target overflow")?;
    ensure!(
        available >= required_memory,
        "227 native cap exceeds 90 percent memory target"
    );
    let rss = o["lane_rss_history"]["200"]["maximum_observed_lane_rss_bytes"]
        .as_u64()
        .filter(|n| *n > 0)
        .context("227 century RSS")?;
    ensure!(
        o["lane_rss_history"]["200"]["reservation_ceiling_bytes"]
            == rss.checked_mul(3).context("227 RSS overflow")? / 2
            && c::MEMORY <= rss.checked_mul(3).context("227 RSS overflow")? / 2,
        "227 century RSS reservation differs"
    );
    let psi = &o["host_global_pressure"]["cross_sample"];
    ensure!(
        psi["status"] == "observed" && psi["elapsed_millis"].as_u64().is_some_and(|n| n > 0),
        "227 pressure unobserved"
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
            "227 resource pressure:{counter}"
        );
    }
    let mut rows = o["replays"]
        .as_array()
        .context("227 ordinary sample census")?
        .iter()
        .collect::<Vec<_>>();
    for diagnostic in o["diagnostic_replays"]
        .as_array()
        .context("227 diagnostic census")?
    {
        if diagnostic["status"] != "observed" {
            unavailable_is_inactive(diagnostic, f)?;
            continue;
        }
        ensure!(
            diagnostic["error"].is_null(),
            "227 observed diagnostic has error"
        );
        rows.push(&diagnostic["observation"]);
    }
    prefix223_live_peer::roster(f)?;
    let mut seen = BTreeSet::new();
    for active in f["active"].as_array().context("227 active census")? {
        let owner = singleton227_admission::active_owner(active)?;
        let unit = owner["Id"].as_str().context("227 owner name")?;
        ensure!(
            unit != c::UNIT && active["epoch"] != 227,
            "227 already has active work"
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
            "227 every owner needs exactly one coordinated observation"
        );
        let row = observed[0];
        ensure!(
            row["invocation_binding_stable"] == true
                && row["producer_before"]["invocation_id"] == owner["InvocationID"]
                && row["producer_after"]["invocation_id"] == owner["InvocationID"]
                && row["producer_after"]["restarts"] == 0
                && row["producer_after"]["rss"]["census_stable"] == true,
            "227 live memory/identity sample differs"
        );
    }
    ensure!(
        rows.len() == seen.len(),
        "227 resource census has an unaccounted owner"
    );
    Ok((t, required_memory))
}
pub(super) fn run() -> Result<()> {
    let (binding, self_sha) = publication203::parsed_args("admit-native227-v1625-input")?;
    let s: Spec = serde_json::from_value(bound_json(&binding)?)?;
    ensure!(
        s.schema == "jetstreamer-private-epoch227-v1625-native-admission-spec-v1"
            && s.mode == "native-cold"
            && s.cold_plan.path == Path::new(c::PLAN)
            && s.cold_plan.sha256 == c::PLAN_SHA
            && s.output.parent().and_then(Path::parent) == Some(Path::new("/var/lib/jetstreamer"))
            && s.output
                .parent()
                .and_then(Path::file_name)
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("horizon-227-v1625-native-admission-"))
            && s.output.file_name().is_some_and(|n| n == "admission.json"),
        "227 admission spec or output scope differs"
    );
    if s.output.try_exists()? {
        let old = bound_json(&serde_json::from_value(private157::file_binding(
            &s.output,
        )?)?)?;
        ensure!(
            old["spec_sha256"] == binding.sha256
                && old["self_sha256"] == self_sha
                && old["admitted"] == true,
            "227 admission conflicts"
        );
        return Ok(());
    }
    validate_output_destination(&s.output)?;
    let cold = c::immutable_json(&s.cold_plan)?;
    c::no_authority(&cold)?;
    c::small_envelope(&cold)?;
    ensure!(
        cold["native_main"]["sha256"] == c::TEST_SHA
            && cold["snapshot"]["sha256"] == c::SNAPSHOT_SHA
            && cold["full_worker"]["executable"] == c::WORKER
            && cold["full_worker"]["sha256"] == c::WORKER_SHA
            && cold["full_worker"]["worker_started"] == false
            && cold["runtime"] == "solana-v1.6.25"
            && cold["runtime_revision"] == "7de8a55b54d3e11058b82f9483bb405d143b455c"
            && cold["replay_entries"] == 0,
        "227 sealed cold plan differs"
    );
    for (path, sha, len) in [
        (PathBuf::from(c::TEST), c::TEST_SHA, None),
        (PathBuf::from(c::GUARD), c::GUARD_SHA, None),
        (PathBuf::from(c::WORKER), c::WORKER_SHA, None),
        (
            Path::new(c::INPUT).join(c::SNAPSHOT),
            c::SNAPSHOT_SHA,
            Some(10_261_480_487),
        ),
        (
            Path::new(c::INPUT).join("genesis.tar.bz2"),
            c::GENESIS_SHA,
            Some(20144),
        ),
    ] {
        sealed_file(&path, sha, len)?;
    }
    let root = Path::new(c::ROOT);
    let scratch = root.join("scratch");
    for path in [root, &scratch] {
        let m = fs::symlink_metadata(path)?;
        ensure!(
            path.canonicalize()? == path && m.is_dir() && m.uid() == 1000 && m.mode() & 0o077 == 0,
            "227 unsafe scratch root"
        );
    }
    ensure!(
        fs::read_dir(&scratch)?.next().is_none(),
        "227 native scratch must be empty"
    );
    let o = bound_json(&s.observer)?;
    let f = bound_json(&s.fleet)?;
    let p = bound_json(&s.resource_plan)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let t = utc_seconds(o["recorded_at_utc"].as_str().context("227 sample clock")?)?;
    let floor = singleton227_admission::century_floor_for(&f, 227)?;
    let free_before = singleton227_admission::disk_free()?;
    let (growth, measurements) = prefix223_live_peer::disk(&f, &o, &s.protected_guards, t, now)?;
    let (computed, existing_guard_floor) =
        native228_admission::protected_floor(floor, growth, &s.protected_guards)?;
    let protected = p["guard_minimum_free_bytes"]
        .as_u64()
        .context("227 guard floor")?;
    ensure!(
        protected >= computed,
        "227 plan under-reserves protected growth"
    );
    let required = protected
        .checked_add(c::SCRATCH)
        .context("227 free overflow")?;
    candidate(&p, protected, required)?;
    let (_, memory_required) = sample(&s, &o, &f, now, required)?;
    let (auxiliary_growth, auxiliary_measurements) = prefix223_live_peer::memory(&f)?;
    let memory_required = memory_required
        .checked_add(auxiliary_growth)
        .context("227 memory claim overflow")?;
    ensure!(
        o["host_memory"]["conservative_available_kib"]
            .as_u64()
            .and_then(|n| n.checked_mul(1024))
            .is_some_and(|n| n >= memory_required),
        "227 sampled memory omits auxiliary remaining hard growth"
    );
    let mut names = f["unit_census"]
        .as_object()
        .context("227 fleet unit census")?
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    names.insert(c::UNIT.into());
    let before = census(&names, 201, 300)?;
    native210_peer_history::current(&f, &before)?;
    prefix223_live_peer::current(&f, &before)?;
    singleton227_admission::owners(&f, &before)?;
    ensure!(
        before
            .get(c::UNIT)
            .is_some_and(|u| !diagnostic_stage_running(u)),
        "227 native owner already live"
    );
    let caps = prefix223_live_peer::limits(&f)?;
    let memory = actual_memory()?;
    let free = free_before.min(singleton227_admission::disk_free()?);
    ensure!(
        memory >= memory_required
            && free >= required
            && fs::read_to_string("/proc/sys/vm/max_map_count")?
                .trim()
                .parse::<u64>()?
                >= 4194304,
        "227 actual envelope unavailable"
    );
    let after = census(&names, 201, 300)?;
    native210_peer_history::current(&f, &after)?;
    prefix223_live_peer::current(&f, &after)?;
    singleton227_admission::owners(&f, &after)?;
    ensure!(
        before == after && caps == prefix223_live_peer::limits(&f)?,
        "227 owners/caps changed during admission"
    );
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    sample(&s, &o, &f, now, required)?;
    let (after_growth, after_measurements) =
        prefix223_live_peer::disk(&f, &o, &s.protected_guards, t, now)?;
    let (after_auxiliary, after_auxiliary_measurements) = prefix223_live_peer::memory(&f)?;
    ensure!(
        after_growth <= growth
            && after_auxiliary <= auxiliary_growth
            && singleton227_admission::disk_free()? >= required
            && actual_memory()? >= memory_required,
        "227 capacity changed during admission"
    );
    let mut r = json!({"schema":"jetstreamer-private-epoch227-v1625-native-admission-v1","epoch":227,"mode":"native-cold","admitted":true,
        "unit":c::UNIT,"private_run_root":c::ROOT,"candidate_incremental_peak_bytes":c::SCRATCH,"maximum_scratch_bytes":c::SCRATCH,"maximum_memory_bytes":c::MEMORY,
        "protected_existing_floor_bytes":protected,"required_initial_free_bytes":required,"century_floor_bytes":floor,"protected_remaining_growth_bytes":growth,
        "computed_existing_floor_bytes":computed,"maximum_existing_bound_guard_floor_bytes":existing_guard_floor,"protected_growth_measurements_before":measurements,"protected_growth_measurements_after":after_measurements,
        "auxiliary_remaining_memory_growth_bytes":auxiliary_growth,"auxiliary_memory_before":auxiliary_measurements,"auxiliary_memory_after":after_auxiliary_measurements,
        "protected_memory_limits":caps,"unit_census_before":before,"unit_census_after":after,"memory_target_percent":90,
        "available_memory_bytes":memory,"available_disk_bytes":free,"observer":private157::binding(&s.observer),"fleet":private157::binding(&s.fleet),
        "cold_plan":private157::binding(&s.cold_plan),"resource_plan":private157::binding(&s.resource_plan),"protected_guards":s.protected_guards,
        "fresh_complete_census_passed":true,"older_producers_and_guards_preserved":true,"all_immutable_inputs_rehashed":true,"snapshot_restored":false,
        "producer_started":false,"resource_samples_taken":0,"recorded_unix_seconds":now,"maximum_launch_delay_seconds":900,
        "spec_sha256":binding.sha256,"self_sha256":self_sha});
    for flag in [
        "entry_replay",
        "replay_launch_authorized",
        "runtime_promotion_authorized",
        "full_epoch_qualified",
        "canonical_sidecar_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        r[flag] = json!(false);
    }
    private157::immutable_receipt(&s.output, &r)?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn complete_sample() -> (Spec, Value, Value) {
        let s: Spec = serde_json::from_value(json!({
            "schema":"jetstreamer-private-epoch227-v1625-native-admission-spec-v1","mode":"native-cold",
            "observer":{"path":"/observer.json","sha256":"a".repeat(64)},
            "fleet":{"path":"/fleet.json","sha256":"b".repeat(64)},
            "cold_plan":{"path":c::PLAN,"sha256":c::PLAN_SHA},
            "resource_plan":{"path":"/resource.json","sha256":"c".repeat(64)},
            "protected_guards":{},"output":"/admission.json"
        }))
        .unwrap();
        let peers = [
            (
                204,
                "horizon-qualify-204-shrink-root-prefix-resource-fcbf3992-v1.service",
                "448da7f2a3a34217afe7e115120b3cea",
            ),
            (
                205,
                "horizon-qualify-205-shrink-root-prefix-resource-5c01bf93-v1.service",
                "373359a11aef4993a1a949e19ff617c3",
            ),
            (
                225,
                "horizon-qualify-225-natural-root-resource-shrink-budget-2f856bd-v1.service",
                "4cd76ae1353a4411885b997f04306402",
            ),
            (227, singleton227::UNIT, "a10f37b57711425a81633c62c66438d5"),
            (209, singleton209::UNIT, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
        ];
        let active=peers.iter().map(|(epoch,name,iid)|json!({"epoch":epoch,"phase":"diagnostic-qualification","ordinary_replay_claim":false,
            "unit":{"Id":name,"InvocationID":iid,"NRestarts":"0"}})).collect::<Vec<_>>();
        let observed=peers.iter().map(|(_,name,iid)|json!({"invocation_binding_stable":true,
            "producer_before":{"unit":name,"invocation_id":iid},
            "producer_after":{"unit":name,"invocation_id":iid,"restarts":0,"rss":{"census_stable":true}}})).collect::<Vec<_>>();
        let o = json!({"schema":"jetstreamer-horizon-live-resource-sample-v2","recorded_at_utc":"2026-10-23T18:00:00Z",
            "filesystem":{"conservative_available_bytes":4_000_000_000_000u64},"vm_max_map_count":4194304,
            "host_memory":{"total_kib":480u64<<20,"conservative_available_kib":400u64<<20},
            "lane_rss_history":{"200":{"maximum_observed_lane_rss_bytes":150_000_000_000u64,"reservation_ceiling_bytes":225_000_000_000u64}},
            "host_global_pressure":{"cross_sample":{"status":"observed","elapsed_millis":1000,"counter_delta_usec":{
                "memory.full_total_usec":0,"cpu.some_total_usec":0,"io.full_total_usec":0}}},"replays":observed,"diagnostic_replays":[]});
        let mut f = json!({"schema":SCHEMA,"first_epoch":201,"last_epoch":300,"observer_receipt":"/observer.json","observer_sha256":"a".repeat(64),
            "sampled_at_utc":o["recorded_at_utc"],"inventory":{"anomalies":0},"active":active});
        let history = native210_peer_history::fixture(true);
        for field in ["diagnostics", "unit_census", "epochs"] {
            f[field] = history[field].clone();
        }
        f["active"][3]["unit"] = history["unit_census"][singleton227::UNIT].clone();
        (s, o, f)
    }
    #[test]
    fn fresh_four_peer_sample_retains_real_terminal227_but_never_hides_a_stale_owner() {
        let (s, mut o, mut f) = complete_sample();
        let old = f.clone();
        let history = native210_peer_history::fixture(false);
        for field in ["diagnostics", "unit_census", "epochs"] {
            f[field] = history[field].clone();
        }
        f["active"].as_array_mut().unwrap().remove(3);
        o["replays"].as_array_mut().unwrap().remove(3);
        o["diagnostic_replays"] =
            json!([{"producer_unit":singleton227::UNIT,"status":"unavailable","observation":null}]);
        sample(&s, &o, &f, 1792778410, 1).unwrap();
        assert_eq!(f["active"].as_array().unwrap().len(), 4);
        assert_eq!(
            f["diagnostics"][0]["launch_invocation_id"],
            old["diagnostics"][0]["launch_invocation_id"]
        );
        let mut unexplained = f.clone();
        unexplained["diagnostics"] = json!([]);
        assert!(sample(&s, &o, &unexplained, 1792778410, 1).is_err());
        let mut replaced = f.clone();
        replaced["diagnostics"][0]["unit"]["InvocationID"] = json!("f".repeat(32));
        replaced["unit_census"][singleton227::UNIT] = replaced["diagnostics"][0]["unit"].clone();
        assert!(sample(&s, &o, &replaced, 1792778410, 1).is_err());
        let mut stale = o.clone();
        stale["replays"]
            .as_array_mut()
            .unwrap()
            .push(json!({"producer_after":{"unit":singleton227::UNIT}}));
        assert!(sample(&s, &stale, &f, 1792778410, 1).is_err());
        assert!(sample(&s, &o, &old, 1792778410, 1).is_err());
    }
    #[test]
    fn observed_exact_live223_peer_is_counted_without_dropping_failed227_history() {
        let (s, mut o, mut f) = complete_sample();
        let history = native210_peer_history::fixture(false);
        for field in ["diagnostics", "unit_census", "epochs"] {
            f[field] = history[field].clone();
        }
        f["active"].as_array_mut().unwrap().remove(3);
        o["replays"].as_array_mut().unwrap().remove(3);
        let peer = prefix223_live_peer::fixture_row();
        let owner = singleton227_admission::active_owner(&peer).unwrap();
        let observed = json!({"unit":owner["Id"],"invocation_id":owner["InvocationID"],"restarts":0,"rss":{"census_stable":true}});
        o["diagnostic_replays"] = json!([{"producer_unit":owner["Id"],"status":"observed","error":null,
            "observation":{"invocation_binding_stable":true,"producer_before":observed,"producer_after":observed}}]);
        f["active"].as_array_mut().unwrap().push(peer);
        let before = f.clone();
        sample(&s, &o, &f, 1792778410, 1).unwrap();
        assert_eq!(f, before);
        assert_eq!(f["active"].as_array().unwrap().len(), 5);
        assert_eq!(f["epochs"][0]["state"], "failed-needs-repair");
        o["diagnostic_replays"] = json!([]);
        assert!(sample(&s, &o, &f, 1792778410, 1).is_err());
    }

    #[test]
    fn all_four_actual_peers_are_retained_and_every_observation_is_required() {
        let (s, mut o, mut f) = complete_sample();
        let history = native210_peer_history::fixture(false);
        for field in ["diagnostics", "unit_census", "epochs"] {
            f[field] = history[field].clone();
        }
        f["active"].as_array_mut().unwrap().remove(3);
        o["replays"].as_array_mut().unwrap().remove(3);
        let before = f.clone();
        sample(&s, &o, &f, 1792778410, 300_000_000_000).unwrap();
        assert_eq!(f, before);
        assert_eq!(f["active"].as_array().unwrap().len(), 4);
        for index in 0..4 {
            let mut missing = o.clone();
            missing["replays"].as_array_mut().unwrap().remove(index);
            assert!(
                sample(&s, &missing, &f, 1792778410, 1).is_err(),
                "missing peer {index}"
            );
            let mut hidden = f.clone();
            hidden["active"].as_array_mut().unwrap().remove(index);
            assert!(
                sample(&s, &o, &hidden, 1792778410, 1).is_err(),
                "hidden peer {index}"
            );
            let mut changed = o.clone();
            changed["replays"][index]["producer_after"]["invocation_id"] = json!("f".repeat(32));
            assert!(
                sample(&s, &changed, &f, 1792778410, 1).is_err(),
                "changed peer {index}"
            );
        }
        let mut unknown = f.clone();
        unknown["active"][3]["unit"]["Id"] = json!("unknown.service");
        assert!(sample(&s, &o, &unknown, 1792778410, 1).is_err());
        assert!(sample(&s, &o, &f, 1792780300, 1).is_err());
    }
    #[test]
    fn unavailable_terminal_diagnostic_is_ignored_only_outside_the_complete_live_census() {
        let d = json!({"producer_unit":singleton227_admission::NATIVE_UNIT,"status":"unavailable","observation":null});
        unavailable_is_inactive(&d, &json!({"active":[]})).unwrap();
        assert!(
            unavailable_is_inactive(
                &d,
                &json!({"active":[{"unit":{"Id":singleton227_admission::NATIVE_UNIT}}]})
            )
            .is_err()
        );
        assert!(unavailable_is_inactive(&d, &json!({"active":[{"unrecognized":true}]})).is_err());
    }
    #[test]
    fn candidate_cannot_borrow_replay_or_another_profile_fingerprint() {
        let mut p = json!({"schema":"jetstreamer-private-epoch227-v1625-native-resource-plan-v1","epoch":227,"mode":"native-cold","unit":c::UNIT,"run_root":c::ROOT,
            "candidate_incremental_peak_bytes":c::SCRATCH,"maximum_scratch_bytes":c::SCRATCH,"maximum_memory_bytes":c::MEMORY,"test_sha256":c::TEST_SHA,
            "snapshot_sha256":c::SNAPSHOT_SHA,"genesis_sha256":c::GENESIS_SHA,"guard_sha256":c::GUARD_SHA,"cold_plan":{"path":c::PLAN,"sha256":c::PLAN_SHA},"guard_minimum_free_bytes":100,"required_initial_free_bytes":c::SCRATCH+100});
        for flag in [
            "entry_replay",
            "replay_launch_authorized",
            "runtime_promotion_authorized",
            "full_epoch_qualified",
            "canonical_sidecar_authorized",
            "publication_authorized",
            "remote_mutations",
            "r2_mutations",
        ] {
            p[flag] = json!(false);
        }
        candidate(&p, 100, c::SCRATCH + 100).unwrap();
        for key in p.as_object().unwrap().keys() {
            let mut bad = p.clone();
            bad[key] = Value::Null;
            assert!(candidate(&bad, 100, c::SCRATCH + 100).is_err(), "{key}");
        }
        let mut bad = p;
        bad["mode"] = json!("replay");
        assert!(candidate(&bad, 100, c::SCRATCH + 100).is_err());
    }
}
