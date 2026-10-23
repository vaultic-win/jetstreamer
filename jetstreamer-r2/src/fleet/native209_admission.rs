//! Admit only the cached bootstrap-only native 209 check, never start it.
use super::native209 as c;
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
        "209 noncanonical input"
    );
    let before = fs::symlink_metadata(path)?;
    ensure!(
        before.is_file()
            && before.uid() == 0
            && before.nlink() == 1
            && before.mode() & 0o222 == 0
            && bytes.is_none_or(|n| before.len() == n),
        "209 unsafe input"
    );
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let opened = file.metadata()?;
    ensure!(
        before.dev() == opened.dev() && before.ino() == opened.ino(),
        "209 input replaced"
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
            .context("209 input size overflow")?;
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
        "209 input changed or digest differs"
    );
    Ok(())
}
fn candidate(p: &Value, protected: u64, required: u64) -> Result<()> {
    ensure!(
        p["schema"] == "jetstreamer-private-epoch209-native-resource-plan-v1"
            && p["epoch"] == 209
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
        "209 candidate fingerprint, envelope or native-only mode differs"
    );
    c::no_authority(p)
}
fn sample(s: &Spec, o: &Value, f: &Value, now: u64, required: u64) -> Result<(u64, u64)> {
    let t = utc_seconds(o["recorded_at_utc"].as_str().context("209 sample time")?)?;
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
        if diagnostic["status"] != "observed" {
            unavailable_is_inactive(diagnostic, f)?;
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
fn unavailable_is_inactive(d: &Value, f: &Value) -> Result<()> {
    let name = d["producer_unit"]
        .as_str()
        .context("209 unavailable owner")?;
    ensure!(
        d["status"] == "unavailable"
            && d["observation"].is_null()
            && !f["active"]
                .as_array()
                .context("209 complete active census")?
                .iter()
                .any(|r| {
                    singleton227_admission::active_owner(r).map_or(true, |u| u["Id"] == name)
                }),
        "209 unobserved diagnostic still owns live capacity"
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
        .context("209 actual memory")?
        .checked_mul(1024)
        .context("209 actual memory overflow")
}
fn native227_claim(f: &Value, row: &Value) -> Result<PipelineClaim> {
    let owner = singleton227_admission::active_owner(row)?;
    ensure!(
        row["epoch"] == 227
            && row["phase"] == "private-cold-snapshot-verification"
            && row["ordinary_replay_claim"] == false
            && owner["Id"] == singleton227_admission::NATIVE_UNIT,
        "209 unknown native227 auxiliary"
    );
    let plan = bound_json(&BoundFile {
        path: f["plan"].as_str().context("209 prior plan")?.into(),
        sha256: f["plan_sha256"]
            .as_str()
            .context("209 prior plan digest")?
            .into(),
    })?;
    let claims = plan["pipeline_claims"]
        .as_array()
        .context("209 prior claims")?
        .iter()
        .filter(|v| v["unit"] == owner["Id"])
        .collect::<Vec<_>>();
    ensure!(
        claims.len() == 1,
        "209 native227 needs one registered claim"
    );
    let claim: PipelineClaim = serde_json::from_value(claims[0].clone())?;
    ensure!(
        claim.invocation_id == owner["InvocationID"]
            && claim.evidence == serde_json::from_value::<Vec<BoundFile>>(row["evidence"].clone())?,
        "209 native227 origin changed"
    );
    singleton227::native_live(&claim, owner)?;
    Ok(claim)
}
fn auxiliary_memory(f: &Value) -> Result<(u64, Vec<Value>)> {
    let (mut total, mut evidence) = singleton227_admission::auxiliary_memory(f)?;
    let (full_growth, full_evidence) = native209_full227::memory(f)?;
    total = total
        .checked_add(full_growth)
        .context("209 full227 memory overflow")?;
    evidence.extend(full_evidence);
    for row in f["active"]
        .as_array()
        .context("209 auxiliary memory census")?
        .iter()
        .filter(|r| {
            r["epoch"] == 227
                && singleton227_admission::active_owner(r)
                    .is_ok_and(|u| u["Id"] == singleton227_admission::NATIVE_UNIT)
        })
    {
        let claim = native227_claim(f, row)?;
        let owner = singleton227_admission::active_owner(row)?;
        let group = owner["ControlGroup"]
            .as_str()
            .context("209 native227 cgroup")?;
        ensure!(
            group == format!("/system.slice/{}", claim.unit),
            "209 native227 cgroup escaped"
        );
        let root = Path::new("/sys/fs/cgroup").join(&group[1..]);
        let read = |name: &str| -> Result<u64> {
            Ok(fs::read_to_string(root.join(name))?.trim().parse::<u64>()?)
        };
        let cap = read("memory.max")?;
        let high = read("memory.high")?;
        let charge = read("memory.current")?;
        ensure!(
            cap == c::MEMORY
                && high == 112u64 << 30
                && read("memory.swap.max")? == 0
                && charge <= cap,
            "209 native227 hard memory controls differ"
        );
        let remaining = cap - charge;
        total = total
            .checked_add(remaining)
            .context("209 native memory growth overflow")?;
        evidence.push(json!({"epoch":227,"unit":claim.unit,"invocation_id":claim.invocation_id,"hard_memory_cap_bytes":cap,"current_cgroup_charge_bytes":charge,"remaining_hard_memory_growth_bytes":remaining,"origin":private157::binding(&claim.evidence[0])}));
    }
    Ok((total, evidence))
}
fn protected_growth(
    f: &Value,
    o: &Value,
    guards: &BTreeMap<String, BoundFile>,
    sample: u64,
    now: u64,
) -> Result<(u64, Vec<Value>)> {
    let (mut reduced, mut reduced_guards, mut extra, mut native_measurements) =
        native209_full227::split(f, o, guards, sample, now)?;
    let mut seen = BTreeSet::new();
    for row in f["active"]
        .as_array()
        .context("209 protected native census")?
        .iter()
        .filter(|r| {
            r["epoch"] == 227
                && singleton227_admission::active_owner(r)
                    .is_ok_and(|u| u["Id"] == singleton227_admission::NATIVE_UNIT)
        })
    {
        let claim = native227_claim(f, row)?;
        ensure!(
            seen.insert(claim.unit.clone()),
            "209 duplicate native227 owner"
        );
        let guard = reduced_guards
            .remove(&claim.unit)
            .context("209 native227 needs its latest protective guard")?;
        let g = bound_json(&guard)?;
        let origin = bound_json(&claim.evidence[0])?;
        let plan: BoundFile = serde_json::from_value(origin["guard_plan"].clone())?;
        let time = g["recorded_unix_seconds"]
            .as_u64()
            .context("209 native227 guard clock")?;
        ensure!(
            time >= sample
                && time <= now
                && now - time <= 1800
                && g["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
                && g["guard_sha256"] == singleton227::NATIVE_GUARD_SHA
                && g["plan_sha256"] == plan.sha256
                && g["producer_invocation_id"] == claim.invocation_id
                && g["producer"]["invocation_id"] == claim.invocation_id
                && g["producer"]["pid"] == origin["main_pid"]
                && g["producer"]["cgroup"] == format!("/system.slice/{}", claim.unit)
                && g["producer"]["active"] == "active"
                && g["producer"]["sub"] == "running"
                && g["producer"]["restarts"] == 0
                && g["native_main"]["sha256"] == origin["test_sha256"]
                && g["native_main"]["main_pid"] == origin["main_pid"]
                && g["maximum_root_physical_bytes"] == c::SCRATCH
                && g["root_physical_observation"]["exceeds_budget"] == false
                && g["maximum_worker_vmas"] == 3500000
                && g["producer_stop_enabled"] == true
                && g["workers"].as_array().is_some_and(|v| v.len() == 1)
                && g["workers"][0][0] == origin["main_pid"]
                && g["workers"][0][1]
                    .as_u64()
                    .is_some_and(|n| n > 0 && n < 3500000)
                && [
                    "trip_reason",
                    "worker_observation_error",
                    "root_physical_observation_error",
                    "canary_target_error"
                ]
                .iter()
                .all(|k| g.get(*k).is_some_and(Value::is_null))
                && g["available_bytes"]
                    .as_u64()
                    .zip(g["minimum_free_bytes"].as_u64())
                    .is_some_and(|(a, b)| a >= b)
                && g["remote_mutations"] == false
                && g["r2_mutations"] == false,
            "209 protected native227 guard differs"
        );
        let physical = g["root_physical_observation"]["conservative_physical_bytes"]
            .as_u64()
            .filter(|n| *n <= c::SCRATCH)
            .context("209 native227 physical bound")?;
        let rows = o["diagnostic_replays"]
            .as_array()
            .context("209 native227 sample")?;
        let observed = rows
            .iter()
            .filter(|r| r["observation"]["producer_after"]["invocation_id"] == claim.invocation_id)
            .collect::<Vec<_>>();
        ensure!(
            observed.len() == 1
                && observed[0]["status"] == "observed"
                && observed[0]["observation"]["invocation_binding_stable"] == true,
            "209 native227 sample identity differs"
        );
        let allocated = observed[0]["observation"]["conservative_observed_physical_bytes"]
            .as_u64()
            .filter(|n| *n <= c::SCRATCH)
            .context("209 native227 scratch allocation")?
            .min(physical);
        let remaining = c::SCRATCH - allocated;
        extra = extra
            .checked_add(remaining)
            .context("209 native disk growth overflow")?;
        native_measurements.push(json!({"epoch":227,"unit":claim.unit,"invocation_id":claim.invocation_id,"sampled_and_guarded_occupied_bytes":allocated,"remaining_growth_bytes":remaining,"guard":private157::binding(&guard),"ordinary_replay_claim":false}));
    }
    reduced["active"]
        .as_array_mut()
        .context("209 reduced active census")?
        .retain(|r| r["epoch"] != 227);
    let (mut base, mut measurements) =
        singleton227_admission::protected_growth(&reduced, o, &reduced_guards, sample, now)?;
    base = base
        .checked_add(extra)
        .context("209 total remaining growth overflow")?;
    measurements.extend(native_measurements);
    Ok((base, measurements))
}
pub(super) fn run() -> Result<()> {
    let (binding, self_sha) = publication203::parsed_args("admit-native209-input")?;
    let s: Spec = serde_json::from_value(bound_json(&binding)?)?;
    ensure!(
        s.schema == "jetstreamer-private-epoch209-native-admission-spec-v1"
            && s.mode == "native-cold"
            && s.cold_plan.path == Path::new(c::PLAN)
            && s.cold_plan.sha256 == c::PLAN_SHA
            && s.output.parent().and_then(Path::parent) == Some(Path::new("/var/lib/jetstreamer"))
            && s.output
                .parent()
                .and_then(Path::file_name)
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("horizon-209-native-admission-"))
            && s.output.file_name().is_some_and(|n| n == "admission.json"),
        "209 admission spec or output scope differs"
    );
    if s.output.try_exists()? {
        let old = bound_json(&serde_json::from_value(private157::file_binding(
            &s.output,
        )?)?)?;
        ensure!(
            old["spec_sha256"] == binding.sha256
                && old["self_sha256"] == self_sha
                && old["admitted"] == true,
            "209 admission conflicts"
        );
        return Ok(());
    }
    validate_output_destination(&s.output)?;
    let cold = bound_json(&s.cold_plan)?;
    ensure!(
        cold["native_main"]["sha256"] == c::TEST_SHA
            && cold["snapshot"]["sha256"] == c::SNAPSHOT_SHA
            && cold["replay_entries"] == 0,
        "209 sealed cold plan differs"
    );
    for (path, sha, len) in [
        (PathBuf::from(c::TEST), c::TEST_SHA, None),
        (PathBuf::from(c::GUARD), c::GUARD_SHA, None),
        (
            Path::new(c::INPUT).join(c::SNAPSHOT),
            c::SNAPSHOT_SHA,
            Some(8_543_246_873),
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
            "209 unsafe scratch root"
        );
    }
    ensure!(
        fs::read_dir(&scratch)?.next().is_none(),
        "209 native scratch must be empty"
    );
    let o = bound_json(&s.observer)?;
    let f = bound_json(&s.fleet)?;
    let p = bound_json(&s.resource_plan)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let t = utc_seconds(o["recorded_at_utc"].as_str().context("209 sample clock")?)?;
    let floor = singleton227_admission::century_floor_for(&f, 209)?;
    let free_before = singleton227_admission::disk_free()?;
    let (growth, measurements) = protected_growth(&f, &o, &s.protected_guards, t, now)?;
    let computed = floor.checked_add(growth).context("209 floor overflow")?;
    let protected = p["guard_minimum_free_bytes"]
        .as_u64()
        .context("209 guard floor")?;
    ensure!(
        protected >= computed,
        "209 plan under-reserves protected growth"
    );
    let required = protected
        .checked_add(c::SCRATCH)
        .context("209 free overflow")?;
    candidate(&p, protected, required)?;
    let (_, memory_required) = sample(&s, &o, &f, now, required)?;
    let (auxiliary_growth, auxiliary_measurements) = auxiliary_memory(&f)?;
    let memory_required = memory_required
        .checked_add(auxiliary_growth)
        .context("209 memory claim overflow")?;
    ensure!(
        o["host_memory"]["conservative_available_kib"]
            .as_u64()
            .and_then(|n| n.checked_mul(1024))
            .is_some_and(|n| n >= memory_required),
        "209 sampled memory omits auxiliary remaining hard growth"
    );
    let mut names = f["unit_census"]
        .as_object()
        .context("209 fleet unit census")?
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
        "209 native owner already live"
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
        "209 actual envelope unavailable"
    );
    let after = census(&names, 201, 300)?;
    singleton227_admission::owners(&f, &after)?;
    ensure!(
        before == after && caps == singleton227_admission::limits(&f)?,
        "209 owners/caps changed during admission"
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
        "209 capacity changed during admission"
    );
    let mut r = json!({"schema":"jetstreamer-private-epoch209-native-admission-v1","epoch":209,"mode":"native-cold","admitted":true,
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
        let mut p = json!({"schema":"jetstreamer-private-epoch209-native-resource-plan-v1","epoch":209,"mode":"native-cold","unit":c::UNIT,"run_root":c::ROOT,
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
