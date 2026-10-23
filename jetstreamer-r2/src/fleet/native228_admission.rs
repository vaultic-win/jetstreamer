//! Admit only the cached bootstrap-only native 228 check, never start it.
use super::native228 as c;
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
fn sealed_file(path: &Path, sha: &str, bytes: Option<u64>) -> Result<()> {
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "228 noncanonical input"
    );
    let before = fs::symlink_metadata(path)?;
    ensure!(
        before.is_file()
            && before.uid() == 0
            && before.nlink() == 1
            && before.mode() & 0o222 == 0
            && bytes.is_none_or(|n| before.len() == n),
        "228 unsafe input"
    );
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let opened = file.metadata()?;
    ensure!(
        before.dev() == opened.dev() && before.ino() == opened.ino(),
        "228 input replaced"
    );
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 128 * 1024];
    let mut count = 0u64;
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        count = count
            .checked_add(n as u64)
            .context("228 input size overflow")?;
        hash.update(&buffer[..n]);
    }
    let after = fs::symlink_metadata(path)?;
    ensure!(
        count == before.len()
            && before.dev() == after.dev()
            && before.ino() == after.ino()
            && before.len() == after.len()
            && before.mtime() == after.mtime()
            && before.mtime_nsec() == after.mtime_nsec()
            && hex_lower(&hash.finalize()) == sha,
        "228 input changed or digest differs"
    );
    Ok(())
}
fn candidate(p: &Value, protected: u64, required: u64) -> Result<()> {
    ensure!(
        p["schema"] == "jetstreamer-private-epoch228-native-resource-plan-v1"
            && p["epoch"] == 228
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
        "228 candidate fingerprint, envelope or native-only mode differs"
    );
    c::no_authority(p)
}
fn sample(s: &Spec, o: &Value, f: &Value, now: u64, required: u64) -> Result<(u64, u64)> {
    let t = utc_seconds(o["recorded_at_utc"].as_str().context("228 sample time")?)?;
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
        "228 stale/incomplete resource sample"
    );
    let total = o["host_memory"]["total_kib"]
        .as_u64()
        .context("228 total memory")?
        .checked_mul(1024)
        .context("228 memory overflow")?;
    let available = o["host_memory"]["conservative_available_kib"]
        .as_u64()
        .context("228 available memory")?
        .checked_mul(1024)
        .context("228 memory overflow")?;
    let required_memory = (total / 10)
        .checked_add(c::MEMORY)
        .context("228 memory target overflow")?;
    ensure!(
        available >= required_memory,
        "228 native cap exceeds 90 percent memory target"
    );
    let rss = o["lane_rss_history"]["200"]["maximum_observed_lane_rss_bytes"]
        .as_u64()
        .filter(|n| *n > 0)
        .context("228 century RSS")?;
    ensure!(
        o["lane_rss_history"]["200"]["reservation_ceiling_bytes"]
            == rss.checked_mul(3).context("228 RSS overflow")? / 2,
        "228 century RSS reservation differs"
    );
    let psi = &o["host_global_pressure"]["cross_sample"];
    ensure!(
        psi["status"] == "observed" && psi["elapsed_millis"].as_u64().is_some_and(|n| n > 0),
        "228 pressure unobserved"
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
            "228 resource pressure:{counter}"
        );
    }
    let mut rows = o["replays"]
        .as_array()
        .context("228 ordinary sample census")?
        .iter()
        .collect::<Vec<_>>();
    for diagnostic in o["diagnostic_replays"]
        .as_array()
        .context("228 diagnostic census")?
    {
        if diagnostic["status"] != "observed" {
            unavailable_is_inactive(diagnostic, f)?;
            continue;
        }
        ensure!(
            diagnostic["error"].is_null(),
            "228 observed diagnostic has error"
        );
        rows.push(&diagnostic["observation"]);
    }
    let mut seen = BTreeSet::new();
    for active in f["active"].as_array().context("228 active census")? {
        let owner = singleton227_admission::active_owner(active)?;
        let unit = owner["Id"].as_str().context("228 owner name")?;
        ensure!(
            unit != c::UNIT && active["epoch"] != 228,
            "228 already has active work"
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
            "228 every owner needs exactly one coordinated observation"
        );
        let row = observed[0];
        ensure!(
            row["invocation_binding_stable"] == true
                && row["producer_before"]["invocation_id"] == owner["InvocationID"]
                && row["producer_after"]["invocation_id"] == owner["InvocationID"]
                && row["producer_after"]["restarts"] == 0
                && row["producer_after"]["rss"]["census_stable"] == true,
            "228 live memory/identity sample differs"
        );
    }
    ensure!(
        rows.len() == seen.len(),
        "228 resource census has an unaccounted owner"
    );
    Ok((t, required_memory))
}
fn unavailable_is_inactive(d: &Value, f: &Value) -> Result<()> {
    let name = d["producer_unit"]
        .as_str()
        .context("228 unavailable owner")?;
    ensure!(
        d["status"] == "unavailable"
            && d["observation"].is_null()
            && !f["active"]
                .as_array()
                .context("228 complete active census")?
                .iter()
                .any(|r| {
                    singleton227_admission::active_owner(r).map_or(true, |u| u["Id"] == name)
                }),
        "228 unobserved diagnostic still owns live capacity"
    );
    Ok(())
}
fn actual_memory() -> Result<u64> {
    fs::read_to_string("/proc/meminfo")?
        .lines()
        .find_map(|l| {
            l.strip_prefix("MemAvailable:")
                .and_then(|v| v.split_whitespace().next())
                .and_then(|v| v.parse::<u64>().ok())
        })
        .context("228 actual memory")?
        .checked_mul(1024)
        .context("228 actual memory overflow")
}
fn auxiliary_memory(f: &Value) -> Result<(u64, Vec<Value>)> {
    super::native228_peer209::memory(f)
}
fn protected_growth(
    f: &Value,
    o: &Value,
    guards: &BTreeMap<String, BoundFile>,
    sample: u64,
    now: u64,
) -> Result<(u64, Vec<Value>)> {
    super::native228_peer209::disk(f, o, guards, sample, now)
}
pub(super) fn run() -> Result<()> {
    let (binding, self_sha) = publication203::parsed_args("admit-native228-input")?;
    let s: Spec = serde_json::from_value(bound_json(&binding)?)?;
    ensure!(
        s.schema == "jetstreamer-private-epoch228-native-admission-spec-v1"
            && s.mode == "native-cold"
            && s.cold_plan.path == Path::new(c::PLAN)
            && s.cold_plan.sha256 == c::PLAN_SHA
            && s.output.parent().and_then(Path::parent) == Some(Path::new("/var/lib/jetstreamer"))
            && s.output
                .parent()
                .and_then(Path::file_name)
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("horizon-228-native-admission-"))
            && s.output.file_name().is_some_and(|n| n == "admission.json"),
        "228 admission spec or output scope differs"
    );
    if s.output.try_exists()? {
        let old = bound_json(&serde_json::from_value(private157::file_binding(
            &s.output,
        )?)?)?;
        ensure!(
            old["spec_sha256"] == binding.sha256
                && old["self_sha256"] == self_sha
                && old["admitted"] == true,
            "228 admission conflicts"
        );
        return Ok(());
    }
    validate_output_destination(&s.output)?;
    let cold = bound_json(&s.cold_plan)?;
    ensure!(
        cold["native_main"]["sha256"] == c::TEST_SHA
            && cold["snapshot"]["sha256"] == c::SNAPSHOT_SHA
            && cold["replay_entries"] == 0,
        "228 sealed cold plan differs"
    );
    for (path, sha, len) in [
        (PathBuf::from(c::TEST), c::TEST_SHA, None),
        (PathBuf::from(c::GUARD), c::GUARD_SHA, None),
        (
            Path::new(c::INPUT).join(c::SNAPSHOT),
            c::SNAPSHOT_SHA,
            Some(10_510_540_911),
        ),
        (PathBuf::from(c::GENESIS), c::GENESIS_SHA, Some(20144)),
    ] {
        sealed_file(&path, sha, len)?;
    }
    let root = Path::new(c::ROOT);
    let scratch = root.join("scratch");
    for path in [root, &scratch] {
        let m = fs::symlink_metadata(path)?;
        ensure!(
            path.canonicalize()? == path && m.is_dir() && m.uid() == 1000 && m.mode() & 0o077 == 0,
            "228 unsafe scratch root"
        );
    }
    ensure!(
        fs::read_dir(&scratch)?.next().is_none(),
        "228 native scratch must be empty"
    );
    let o = bound_json(&s.observer)?;
    let f = bound_json(&s.fleet)?;
    let p = bound_json(&s.resource_plan)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let t = utc_seconds(o["recorded_at_utc"].as_str().context("228 sample clock")?)?;
    let floor = singleton227_admission::century_floor_for(&f, 228)?;
    let free_before = singleton227_admission::disk_free()?;
    let (growth, measurements) = protected_growth(&f, &o, &s.protected_guards, t, now)?;
    let computed = floor.checked_add(growth).context("228 floor overflow")?;
    let protected = p["guard_minimum_free_bytes"]
        .as_u64()
        .context("228 guard floor")?;
    ensure!(
        protected >= computed,
        "228 plan under-reserves protected growth"
    );
    let required = protected
        .checked_add(c::SCRATCH)
        .context("228 free overflow")?;
    candidate(&p, protected, required)?;
    let (_, memory_required) = sample(&s, &o, &f, now, required)?;
    let (auxiliary_growth, auxiliary_measurements) = auxiliary_memory(&f)?;
    let memory_required = memory_required
        .checked_add(auxiliary_growth)
        .context("228 memory claim overflow")?;
    ensure!(
        o["host_memory"]["conservative_available_kib"]
            .as_u64()
            .and_then(|n| n.checked_mul(1024))
            .is_some_and(|n| n >= memory_required),
        "228 sampled memory omits auxiliary remaining hard growth"
    );
    let mut names = f["unit_census"]
        .as_object()
        .context("228 fleet unit census")?
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    names.insert(c::UNIT.into());
    let before = census(&names, 201, 300)?;
    singleton227_admission::owners(&f, &before)?;
    ensure!(
        before
            .get(c::UNIT)
            .is_some_and(|u| !diagnostic_stage_running(u)),
        "228 native owner already live"
    );
    let caps = singleton227_admission::limits(&f)?;
    let memory = actual_memory()?;
    let free = free_before.min(singleton227_admission::disk_free()?);
    ensure!(
        memory >= memory_required
            && free >= required
            && fs::read_to_string("/proc/sys/vm/max_map_count")?
                .trim()
                .parse::<u64>()?
                >= 4194304,
        "228 actual envelope unavailable"
    );
    let after = census(&names, 201, 300)?;
    singleton227_admission::owners(&f, &after)?;
    ensure!(
        before == after && caps == singleton227_admission::limits(&f)?,
        "228 owners/caps changed during admission"
    );
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    sample(&s, &o, &f, now, required)?;
    let (after_growth, after_measurements) = protected_growth(&f, &o, &s.protected_guards, t, now)?;
    let (after_auxiliary, after_auxiliary_measurements) = auxiliary_memory(&f)?;
    ensure!(
        after_growth <= growth
            && after_auxiliary <= auxiliary_growth
            && singleton227_admission::disk_free()? >= required
            && actual_memory()? >= memory_required,
        "228 capacity changed during admission"
    );
    let mut r = json!({"schema":"jetstreamer-private-epoch228-native-admission-v1","epoch":228,"mode":"native-cold","admitted":true,
        "unit":c::UNIT,"private_run_root":c::ROOT,"candidate_incremental_peak_bytes":c::SCRATCH,"maximum_scratch_bytes":c::SCRATCH,"maximum_memory_bytes":c::MEMORY,
        "protected_existing_floor_bytes":protected,"required_initial_free_bytes":required,"century_floor_bytes":floor,"protected_remaining_growth_bytes":growth,
        "computed_existing_floor_bytes":computed,"protected_growth_measurements_before":measurements,"protected_growth_measurements_after":after_measurements,
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
        let mut p = json!({"schema":"jetstreamer-private-epoch228-native-resource-plan-v1","epoch":228,"mode":"native-cold","unit":c::UNIT,"run_root":c::ROOT,
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
