//! Admission preparation only: saved observation, completed guards, bounded file stats.
use super::{singleton209 as c, *};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    observer: BoundFile,
    fleet: BoundFile,
    capability: BoundFile,
    native_input: BoundFile,
    terminal223: Option<BoundFile>,
    output_directory: PathBuf,
    admission_output: PathBuf,
}
const GUARDS: [(&str, &str, &str); 4] = [
    (
        "horizon-qualify-225-natural-root-resource-shrink-budget-2f856bd-v1.service",
        "horizon-ownroot225-protective-v1.service",
        "/var/lib/jetstreamer/horizon-ownroot225-rebased-guard-receipts-v1",
    ),
    (
        "horizon-qualify-205-shrink-root-prefix-resource-5c01bf93-v1.service",
        "horizon-prefix205-protective-v1.service",
        "/var/lib/jetstreamer/horizon-prefix205-guard-receipts-v1",
    ),
    (
        "horizon-qualify-204-shrink-root-prefix-resource-fcbf3992-v1.service",
        "horizon-prefix204-protective-v1.service",
        "/var/lib/jetstreamer/horizon-prefix204-guard-receipts-v1",
    ),
    (
        "horizon-singleton-227-capped-710f6523-v1.service",
        "horizon-singleton227-protective-v1.service",
        "/var/lib/jetstreamer/horizon-singleton227-guard-receipts-v1",
    ),
];
pub(super) fn run() -> Result<()> {
    let (binding, self_sha) = publication203::parsed_args("prepare-singleton209-admission-spec")?;
    let s: Spec = serde_json::from_value(native209::immutable_json(&binding)?)?;
    ensure!(
        s.schema == "jetstreamer-private-epoch209-singleton-admission-preparation-spec-v1"
            && s.output_directory.parent() == Some(Path::new("/var/lib/jetstreamer"))
            && s.output_directory
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("horizon-209-singleton-admission-specs-")),
        "209 admission preparation scope differs"
    );
    let resource_path = s.output_directory.join("resource-plan.json");
    let admission_path = s.output_directory.join("admission-spec.json");
    let report_path = s.output_directory.join("preparation.json");
    for path in [&resource_path, &admission_path, &report_path] {
        validate_output_destination(path)?;
    }
    ensure!(
        s.capability.path == Path::new(c::CAPABILITY),
        "209 prepared capability path differs"
    );
    c::capability(&native209::immutable_json(&s.capability)?)?;
    c::native(&s.native_input)?;
    let f = bound_json(&s.fleet)?;
    let o = bound_json(&s.observer)?;
    let peer =
        singleton209_peer223::prepare(s.terminal223.as_ref(), &f, &o, &s.observer, &s.fleet)?;
    let (af, ao) = singleton209_peer223::arithmetic(&f, &o, peer.as_ref())?;
    let sample = utc_seconds(
        o["recorded_at_utc"]
            .as_str()
            .context("209 preparation observation time")?,
    )?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    ensure!(
        sample <= now && now - sample <= 1800,
        "209 preparation sample stale"
    );
    let mut guards = BTreeMap::new();
    let mut histories = BTreeMap::new();
    for (owner, guard, dir) in GUARDS {
        let selected = warmup223::completed_guard_binding(guard, Path::new(dir), sample, now)?;
        guards.insert(
            owner.to_owned(),
            serde_json::from_value::<BoundFile>(selected["binding"].clone())?,
        );
        histories.insert(owner.to_owned(), selected["history"].clone());
    }
    let floor = singleton227_admission::century_floor_for(&f, 209)?;
    // Exactly the reviewed accounting: two bounded stats per204/205 output.
    // No scratch scan, replay/host resource observation, admission or worker.
    let (growth, measurements) =
        native209_admission::protected_growth(&af, &ao, &guards, sample, now)?;
    let (growth_after, measurements_after) =
        native209_admission::protected_growth(&af, &ao, &guards, sample, now)?;
    let growth = growth.max(growth_after);
    let guard_baseline = singleton209_admission::protected_guard_floor(&guards)?;
    let protected = floor
        .checked_add(growth)
        .context("209 prepared floor overflow")?
        .max(guard_baseline);
    let required = protected
        .checked_add(c::PEAK)
        .context("209 prepared free overflow")?;
    let mut resource = json!({"schema":"jetstreamer-private-epoch209-singleton-resource-plan-v1","epoch":209,"mode":"replay","unit":c::UNIT,"run_root":c::ROOT,
        "candidate_incremental_peak_bytes":c::PEAK,"maximum_scratch_bytes":c::SCRATCH,"memory_max_bytes":c::MEMORY,"memory_high_bytes":150000000000u64,
        "guard_minimum_free_bytes":protected,"required_initial_free_bytes":required,"node_sha256":c::NODE_SHA,"worker_sha256":c::WORKER_SHA,
        "snapshot_sha256":c::SNAPSHOT_SHA,"guard_sha256":c::GUARD_SHA,"manifest_fingerprint":c::FINGERPRINT,"maximum_runtime_seconds":259200});
    for flag in [
        "runtime_promotion_authorized",
        "full_epoch_qualified",
        "canonical_sidecar_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        resource[flag] = json!(false);
    }
    private157::immutable_receipt(&resource_path, &resource)?;
    let resource_binding = private157::file_binding(&resource_path)?;
    let admission = json!({"schema":"jetstreamer-private-epoch209-singleton-admission-spec-v1","mode":"replay",
        "observer":private157::binding(&s.observer),"fleet":private157::binding(&s.fleet),"capability":private157::binding(&s.capability),"native_input":private157::binding(&s.native_input),
        "terminal223":s.terminal223.as_ref().map(private157::binding),"resource_plan":resource_binding,"protected_guards":guards,"output":s.admission_output});
    private157::immutable_receipt(&admission_path, &admission)?;
    let saved = o["filesystem"]["conservative_available_bytes"]
        .as_u64()
        .context("209 prepared saved free")?;
    let report = json!({"schema":"jetstreamer-private-epoch209-singleton-admission-preparation-v1","epoch":209,"preparation_spec":private157::binding(&binding),"self_sha256":self_sha,
        "observer":private157::binding(&s.observer),"fleet":private157::binding(&s.fleet),"guard_selection_history":histories,
        "century_floor_bytes":floor,"protected_remaining_growth_bytes":growth,"protected_growth_before":measurements,"protected_growth_after":measurements_after,
        "preserved_guard_baseline_floor_bytes":guard_baseline,
        "protected_floor_bytes":protected,"required_initial_free_bytes":required,"saved_available_bytes":saved,"fits_saved_available_disk":saved>=required,
        "resource_plan":resource_binding,"admission_spec":private157::file_binding(&admission_path)?,"terminal223_accounting":singleton209_peer223::evidence(peer.as_ref()),
        "resource_samples_taken":0,"scratch_scans_performed":0,"bounded_output_metadata_accounting":true,"admission_executed":false,"producer_started":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false});
    private157::immutable_receipt(&report_path, &report)?;
    println!(
        "{}",
        serde_json::to_string(
            &json!({"resource_plan":resource_binding,"admission_spec":private157::file_binding(&admission_path)?,"preparation":private157::file_binding(&report_path)?})
        )?
    );
    Ok(())
}
