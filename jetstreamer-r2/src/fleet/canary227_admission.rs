//! Admit the exact bounded 227 comparison canary; never launch it.
use super::canary227 as c;
use super::native209_admission::{actual_memory, sealed_file, unavailable_is_inactive};
use super::*;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    mode: String,
    observer: BoundFile,
    fleet: BoundFile,
    canary_plan: BoundFile,
    input_capability: BoundFile,
    resource_proposal: BoundFile,
    protected_guards: BTreeMap<String, BoundFile>,
    output: PathBuf,
}
fn candidate(
    p: &Value,
    canary: &Value,
    binding: &BoundFile,
    protected: u64,
    required: u64,
) -> Result<()> {
    ensure!(
        p["schema"] == "jetstreamer-private-epoch227-v1625-canary-resource-proposal-v1"
            && p["epoch"] == 227
            && p["mode"] == "bounded-canary"
            && p["unit"] == c::UNIT
            && p["run_root"] == c::ROOT
            && p["candidate_incremental_peak_bytes"] == c::CANDIDATE
            && p["maximum_scratch_bytes"] == c::SCRATCH
            && p["maximum_memory_bytes"] == c::MEMORY
            && p["memory_high_bytes"] == c::HIGH
            && p["maximum_runtime_seconds"] == 21600
            && p["cpu_quota_cores"] == 8
            && p["guard_minimum_free_bytes"] == protected
            && p["required_initial_free_bytes"] == required
            && p["canary_plan"] == private157::binding(binding),
        "227 canary resource proposal differs"
    );
    ensure!(
        canary["schema"] == "jetstreamer-private-epoch227-v1625-comparison-plan-v1"
            && canary["unit"] == c::UNIT
            && canary["node"] == json!({"path":c::NODE,"sha256":c::NODE_SHA})
            && canary["worker"] == c::WORKER
            && canary["snapshot"] == c::SNAPSHOT
            && canary["ledger_directory"]
                == "/var/lib/jetstreamer/horizon-stage227-bootstrap-dcaafc6-v1"
            && canary["epoch_hashes"]
                == json!({"path":"/var/lib/jetstreamer/horizon-227-v1625-canary-checkpoints-v1/epoch-hashes.txt","sha256":"3bd4ef68b42990e6e7c278630f62fda71fa9bd45f5e5abd81f6a66b851921cfe"})
            && canary["run_root"] == c::ROOT
            && canary["target_slot"] == c::TARGET
            && canary["terminal_slot"] == c::TERMINAL
            && canary["minimum_free_bytes"] == protected
            && canary["maximum_runtime_seconds"] == 21600,
        "227 actual private parent plan differs"
    );
    native227_v1625::no_authority(p)
}
fn capability(v: &Value) -> Result<()> {
    ensure!(
        v["schema"] == "jetstreamer-private-epoch227-v1625-comparison-capability-v1"
            && v["node_sha256"] == c::NODE_SHA
            && v["worker_sha256"] == c::WORKER_SHA
            && v["snapshot_sha256"] == c::SNAPSHOT_SHA
            && v["bindings"]["self_sha256"] == c::RUNNER_SHA
            && v["worker_started"] == false
            && v["entry_replay"] == false
            && v["parent_planning_report"]["pre_worker_barrier_reached"] == true
            && v["parent_planning_report"]["runtime_checkpoint_policy_validated"] == true
            && v["parent_planning_report"]["worker_spawned"] == false
            && v["parent_planning_report"]["archive_created"] == false
            && v["parent_planning_report"]["worker_entry_start"] == c::BOOTSTRAP + 1
            && v["parent_planning_report"]["worker_entry_end_exclusive"] == c::TARGET + 1
            && v["canonical_checkpoint_slots"] == json!([c::BOOTSTRAP, c::TERMINAL])
            && v["target_slot"] == c::TARGET
            && v["target_is_checkpoint"] == false
            && v["target_stop_protocol"] == "cooperative-resume-only"
            && v["native_input"]["sha256"]
                == "da6e00906c266f5993e0332b2abb864558db4ab4c0786d765d1828e658675d7b",
        "227 capability lacks the exact real no-worker private barrier"
    );
    native227_v1625::no_authority(v)
}
fn sample(s: &Spec, o: &Value, f: &Value, now: u64, required: u64) -> Result<(u64, u64)> {
    native210_peer_history::validate(f)?;
    let t = utc_seconds(o["recorded_at_utc"].as_str().context("227 sample time")?)?;
    ensure!(
        s.mode == "bounded-canary"
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
    let required_memory = total
        .div_ceil(10)
        .checked_add(c::MEMORY)
        .context("227 memory target overflow")?;
    ensure!(
        available >= required_memory,
        "227 canary cap exceeds 90 percent memory target"
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
    run_profile(false)
}
pub(super) fn run_output_metadata() -> Result<()> {
    run_profile(true)
}
fn parse_spec(mut raw: Value, sampled: bool) -> Result<Spec> {
    if sampled {
        ensure!(
            raw.as_object_mut()
                .context("sampled output spec must be an object")?
                .remove("output_metadata_profile")
                == Some(json!(output_credit204205::PROFILE)),
            "new output metadata profile missing or unsupported"
        );
    }
    let spec: Spec = serde_json::from_value(raw)?;
    ensure!(
        spec.schema
            == if sampled {
                "jetstreamer-private-epoch227-v1625-canary-admission-output-spec-v1"
            } else {
                "jetstreamer-private-epoch227-v1625-canary-admission-spec-v1"
            },
        "canary spec/profile mismatch"
    );
    Ok(spec)
}
fn run_profile(sampled: bool) -> Result<()> {
    let command = if sampled {
        "admit-canary227-v1625-output-metadata-v1"
    } else {
        "admit-canary227-v1625"
    };
    let (binding, self_sha) = publication203::parsed_args(command)?;
    let s = parse_spec(bound_json(&binding)?, sampled)?;
    ensure!(
        s.mode == "bounded-canary"
            && s.canary_plan.path.parent().and_then(Path::parent)
                == Some(Path::new("/var/lib/jetstreamer"))
            && s.canary_plan
                .path
                .file_name()
                .is_some_and(|n| n == "resource-plan.json")
            && s.output.parent().and_then(Path::parent) == Some(Path::new("/var/lib/jetstreamer"))
            && s.output
                .parent()
                .and_then(Path::file_name)
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("horizon-227-v1625-canary-admission-"))
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
                && old["admitted"] == true
                && if sampled {
                    old["output_credit_profile"] == output_credit204205::PROFILE
                } else {
                    old.get("output_credit_profile").is_none()
                },
            "227 admission conflicts"
        );
        return Ok(());
    }
    validate_output_destination(&s.output)?;
    let canary = native227_v1625::immutable_json(&s.canary_plan)?;
    let native = native227_v1625::immutable_json(&BoundFile {
        path: "/var/lib/jetstreamer/horizon-native227-v1625-terminal-proof-small-v2/proof.json"
            .into(),
        sha256: "da6e00906c266f5993e0332b2abb864558db4ab4c0786d765d1828e658675d7b".into(),
    })?;
    ensure!(
        native227_v1625_terminal::validate(&native)? == "36b96647e20e41a4a82c92b77b1bb290",
        "227 native input proof changed"
    );
    let input_capability = bound_json(&s.input_capability)?;
    capability(&input_capability)?;
    let capability_origin = canary227_capability::validate(&s.input_capability, &input_capability)?;
    for (path, sha, len) in [
        (PathBuf::from(c::NODE), c::NODE_SHA, None),
        (PathBuf::from(c::RUNNER), c::RUNNER_SHA, None),
        (PathBuf::from(c::GUARD), c::GUARD_SHA, None),
        (PathBuf::from(c::WORKER), c::WORKER_SHA, None),
        (
            PathBuf::from(c::SNAPSHOT),
            c::SNAPSHOT_SHA,
            Some(10_261_480_487),
        ),
        (
            PathBuf::from(
                "/var/lib/jetstreamer/horizon-stage227-bootstrap-dcaafc6-v1/genesis.tar.bz2",
            ),
            c::GENESIS_SHA,
            Some(20144),
        ),
    ] {
        sealed_file(&path, sha, len)?;
    }
    let root = Path::new(c::ROOT);
    let scratch = root.join("scratch");
    for path in [
        root,
        &scratch,
        &root.join("output"),
        &root.join("receipts"),
        &root.join("ledger"),
    ] {
        let m = fs::symlink_metadata(path)?;
        ensure!(
            path.canonicalize()? == path && m.is_dir() && m.uid() == 1000 && m.mode() & 0o077 == 0,
            "227 unsafe scratch root"
        );
    }
    ensure!(
        ["scratch", "output", "receipts", "ledger"]
            .iter()
            .all(|n| fs::read_dir(root.join(n)).is_ok_and(|mut d| d.next().is_none())),
        "227 canary scratch must be empty"
    );
    let o = bound_json(&s.observer)?;
    let f = bound_json(&s.fleet)?;
    let p = bound_json(&s.resource_proposal)?;
    if sampled {
        output_credit204205::maintenance_idle(&f)?;
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let t = utc_seconds(o["recorded_at_utc"].as_str().context("227 sample clock")?)?;
    let floor = singleton227_admission::century_floor_for(&f, 227)?;
    let free_before = singleton227_admission::disk_free()?;
    let (growth, measurements) = prefix223_live_peer::disk(&f, &o, &s.protected_guards, t, now)?;
    let (growth, measurements, output_credit_before) = if sampled {
        output_credit204205::apply(&f, &o, t, now, growth, measurements)?
    } else {
        (growth, measurements, Value::Null)
    };
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
        .checked_add(c::CANDIDATE)
        .context("227 free overflow")?;
    candidate(&p, &canary, &s.canary_plan, protected, required)?;
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
        "227 canary owner already live"
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
    let (after_growth, after_measurements, output_credit_after) = if sampled {
        output_credit204205::apply(&f, &o, t, now, after_growth, after_measurements)?
    } else {
        (after_growth, after_measurements, Value::Null)
    };
    let (after_auxiliary, after_auxiliary_measurements) = prefix223_live_peer::memory(&f)?;
    ensure!(
        after_growth <= growth
            && after_auxiliary <= auxiliary_growth
            && singleton227_admission::disk_free()? >= required
            && actual_memory()? >= memory_required,
        "227 capacity changed during admission"
    );
    let mut r = json!({"schema":"jetstreamer-private-epoch227-v1625-canary-admission-v1","epoch":227,"mode":"bounded-canary","admitted":true,
        "unit":c::UNIT,"private_run_root":c::ROOT,"candidate_incremental_peak_bytes":c::CANDIDATE,"maximum_scratch_bytes":c::SCRATCH,"maximum_memory_bytes":c::MEMORY,
        "protected_existing_floor_bytes":protected,"required_initial_free_bytes":required,"century_floor_bytes":floor,"protected_remaining_growth_bytes":growth,
        "computed_existing_floor_bytes":computed,"maximum_existing_bound_guard_floor_bytes":existing_guard_floor,"protected_growth_measurements_before":measurements,"protected_growth_measurements_after":after_measurements,
        "auxiliary_remaining_memory_growth_bytes":auxiliary_growth,"auxiliary_memory_before":auxiliary_measurements,"auxiliary_memory_after":after_auxiliary_measurements,
        "protected_memory_limits":caps,"unit_census_before":before,"unit_census_after":after,"memory_target_percent":90,
        "available_memory_bytes":memory,"available_disk_bytes":free,"observer":private157::binding(&s.observer),"fleet":private157::binding(&s.fleet),
        "canary_plan":private157::binding(&s.canary_plan),"resource_proposal":private157::binding(&s.resource_proposal),"protected_guards":s.protected_guards,
        "fresh_complete_census_passed":true,"older_producers_and_guards_preserved":true,"all_immutable_inputs_rehashed":true,"snapshot_restored":false,
        "producer_started":false,"resource_samples_taken":0,"recorded_unix_seconds":now,"maximum_launch_delay_seconds":900,
        "spec_sha256":binding.sha256,"self_sha256":self_sha});
    if sampled {
        r["output_credit_profile"] = json!(output_credit204205::PROFILE);
        r["output_credit_evidence_before"] = output_credit_before;
        r["output_credit_evidence_after"] = output_credit_after;
        r["park_maintenance_idle_required"] = json!(true);
    }
    r["input_capability"] = private157::binding(&s.input_capability);
    r["capability_origin"] = capability_origin;
    r["bounded_replay_resource_admitted"] = json!(true);
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
    fn new_metadata_route_is_explicit_and_legacy_spec_stays_strict() {
        let b = json!({"path":"/private/file.json","sha256":"a".repeat(64)});
        let legacy = json!({"schema":"jetstreamer-private-epoch227-v1625-canary-admission-spec-v1",
            "mode":"bounded-canary","observer":b,"fleet":b,"canary_plan":b,"input_capability":b,
            "resource_proposal":b,"protected_guards":{},"output":"/private/admission.json"});
        parse_spec(legacy.clone(), false).unwrap();
        assert!(parse_spec(legacy.clone(), true).is_err());
        let mut sampled = legacy.clone();
        sampled["schema"] =
            json!("jetstreamer-private-epoch227-v1625-canary-admission-output-spec-v1");
        sampled["output_metadata_profile"] = json!(output_credit204205::PROFILE);
        parse_spec(sampled.clone(), true).unwrap();
        assert!(parse_spec(sampled.clone(), false).is_err());
        sampled["output_metadata_profile"] = json!("logical-size-fallback");
        assert!(parse_spec(sampled, true).is_err());
    }
    #[test]
    fn native_capability_cannot_claim_replay_or_substitute_checkpoint() {
        let mut v = json!({"schema":"jetstreamer-private-epoch227-v1625-comparison-capability-v1","node_sha256":c::NODE_SHA,"worker_sha256":c::WORKER_SHA,"snapshot_sha256":c::SNAPSHOT_SHA,"bindings":{"self_sha256":c::RUNNER_SHA},"worker_started":false,"entry_replay":false,"parent_planning_report":{"pre_worker_barrier_reached":true,"runtime_checkpoint_policy_validated":true,"worker_spawned":false,"archive_created":false,"worker_entry_start":c::BOOTSTRAP+1,"worker_entry_end_exclusive":c::TARGET+1},"canonical_checkpoint_slots":[c::BOOTSTRAP,c::TERMINAL],"target_slot":c::TARGET,"target_is_checkpoint":false,"target_stop_protocol":"cooperative-resume-only","native_input":{"sha256":c::NATIVE_SHA}});
        for k in [
            "replay_launch_authorized",
            "runtime_promotion_authorized",
            "full_epoch_qualified",
            "canonical_sidecar_authorized",
            "publication_authorized",
            "remote_mutations",
            "r2_mutations",
        ] {
            v[k] = json!(false);
        }
        capability(&v).unwrap();
        for (k, value) in [
            ("worker_started", json!(true)),
            ("entry_replay", json!(true)),
            ("target_is_checkpoint", json!(true)),
            (
                "canonical_checkpoint_slots",
                json!([c::BOOTSTRAP, c::TARGET, c::TERMINAL]),
            ),
            ("target_slot", json!(c::TERMINAL)),
            ("publication_authorized", json!(true)),
            ("target_stop_protocol", json!("resume-and-interrupt")),
        ] {
            let mut bad = v.clone();
            bad[k] = value;
            assert!(capability(&bad).is_err(), "{k}");
        }
    }
    #[test]
    fn resource_proposal_reserves_full_replay_scratch_and_control_metadata() {
        let b = BoundFile {
            path: "/var/lib/jetstreamer/horizon-227-v1625-canary-resource-v1/resource-plan.json"
                .into(),
            sha256: "b".repeat(64),
        };
        let protected = 2_350_000_000_000u64;
        let mut p = json!({"schema":"jetstreamer-private-epoch227-v1625-canary-resource-proposal-v1","epoch":227,"mode":"bounded-canary","unit":c::UNIT,"run_root":c::ROOT,"candidate_incremental_peak_bytes":c::CANDIDATE,"maximum_scratch_bytes":c::SCRATCH,"maximum_memory_bytes":c::MEMORY,"memory_high_bytes":c::HIGH,"maximum_runtime_seconds":21600,"cpu_quota_cores":8,"guard_minimum_free_bytes":protected,"required_initial_free_bytes":protected+c::CANDIDATE,"canary_plan":private157::binding(&b)});
        for k in [
            "entry_replay",
            "replay_launch_authorized",
            "runtime_promotion_authorized",
            "full_epoch_qualified",
            "canonical_sidecar_authorized",
            "publication_authorized",
            "remote_mutations",
            "r2_mutations",
        ] {
            p[k] = json!(false);
        }
        let plan = json!({"schema":"jetstreamer-private-epoch227-v1625-comparison-plan-v1","unit":c::UNIT,"node":{"path":c::NODE,"sha256":c::NODE_SHA},"worker":c::WORKER,"snapshot":c::SNAPSHOT,"ledger_directory":c::INPUT,"epoch_hashes":{"path":"/var/lib/jetstreamer/horizon-227-v1625-canary-checkpoints-v1/epoch-hashes.txt","sha256":"3bd4ef68b42990e6e7c278630f62fda71fa9bd45f5e5abd81f6a66b851921cfe"},"run_root":c::ROOT,"target_slot":c::TARGET,"terminal_slot":c::TERMINAL,"minimum_free_bytes":protected,"maximum_runtime_seconds":21600});
        candidate(&p, &plan, &b, protected, protected + c::CANDIDATE).unwrap();
        for (k, value) in [
            ("maximum_scratch_bytes", json!(96_000_000_000u64)),
            ("candidate_incremental_peak_bytes", json!(c::SCRATCH)),
            ("maximum_memory_bytes", json!(150_000_000_000u64)),
            ("required_initial_free_bytes", json!(protected + c::SCRATCH)),
            ("publication_authorized", json!(true)),
        ] {
            let mut bad = p.clone();
            bad[k] = value;
            assert!(
                candidate(&bad, &plan, &b, protected, protected + c::CANDIDATE).is_err(),
                "{k}"
            );
        }
        let mut bad = plan.clone();
        bad["target_slot"] = json!(c::TERMINAL);
        assert!(candidate(&p, &bad, &b, protected, protected + c::CANDIDATE).is_err());
    }
}
