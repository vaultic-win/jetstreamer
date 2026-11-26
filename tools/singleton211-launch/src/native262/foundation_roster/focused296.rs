//! Bind the bounded epoch 296 loader diagnostic to the ordinary fleet reserves.
use super::*;

pub(super) const UNIT: &str = "horizon-qualify-296-loader-upgrade-focused-v2.service";
pub(super) const GUARD: &str = "horizon-296-loader-upgrade-focused-protective-v2";
pub(super) const GUARD_SERVICE: &str = "horizon-296-loader-upgrade-focused-protective-v2.service";
pub(super) const SCRATCH_CAP: u64 = 160 << 30;
pub(super) const RECEIPT_DISK: u64 = 64 << 20;
pub(super) const PRODUCER_MEMORY: u64 = 173_207_977_984;
const ROOT: &str = "/home/ubuntu/.jetstreamer-private/qualification-296-loader-upgrade-focused-v2";
const PREFLIGHT: (&str, &str) = (
    "/var/lib/jetstreamer/horizon296-loader-upgrade-focused-v2/preflight.json",
    "d93ae64c1058439379dafd6e9ffe3c1622ffaa9c8bbf8f16c8d505704c54e260",
);
const PROFILE: (&str, &str) = (
    "/var/lib/jetstreamer/horizon296-loader-upgrade-focused-v2/profile.json",
    "f6318333fc088dee3c6109cb6434eba0fddb916ed6ed143bfd7ffca27a59beba",
);
const REGISTRATION: &str =
    "/var/lib/jetstreamer/horizon296-loader-upgrade-focused-v2/cadence-registration.json";

pub(super) fn preflight() -> Result<Bound> {
    let reference = Bound::new(PREFLIGHT.0, PREFLIGHT.1);
    let receipt = reference.sealed()?;
    let profile = Bound::new(PROFILE.0, PROFILE.1).sealed()?;
    ensure!(
        receipt["schema"] == "foundation-epoch296-focused-loader-preflight-v1"
            && receipt["epoch"] == 296
            && receipt["first_slot"] == 127_953_994
            && receipt["last_slot"] == 127_961_108
            && receipt["snapshot_sha256_rechecked"] == true
            && receipt["private_namespace_validated"] == true
            && receipt["static_guard_validated"] == true
            && receipt["writable_private_state_validated"] == true
            && receipt["publication_authorized"] == false
            && profile["unit"] == UNIT
            && profile["run_root"] == ROOT
            && profile["guarded_whole_tree_cap_bytes"] == SCRATCH_CAP
            && profile["properties"]["AllowedCPUs"] == "56-63"
            && profile["properties"]["MemoryMax"] == PRODUCER_MEMORY.to_string()
            && profile["guard"]["path"] == STANDARD_GUARD,
        "epoch 296 focused preflight or profile differs from the measured scope"
    );
    Ok(reference)
}

pub(super) fn live(n: &mut Native) -> Result<LiveReplay> {
    let preflight = preflight()?;
    let reference = Bound::new(REGISTRATION, hash(Path::new(REGISTRATION))?);
    let launch = reference.sealed()?;
    let profile_ref = binding(&launch["profile"])?;
    let profile = profile_ref.sealed()?;
    let admission = binding(&launch["admission"])?.sealed()?;
    let quote = binding(&admission["roster"])?.sealed()?;
    let plan = binding(&launch["guard_plan"])?;
    let body = plan.sealed()?;
    let sample_ref = binding(&launch["active_guard"])?;
    let sample = sample_ref.json()?;
    let node = binding(&profile["node"])?;
    node.artifact()?;
    let owner = n.show_fields(UNIT, OWNER_FIELDS)?;
    let invocation = text(&launch, "invocation_id")?;
    let pid = text(&owner, "MainPID")?.parse::<u64>()?;
    let ticks = process_ticks(pid)?;
    let running = fs::metadata(format!("/proc/{pid}/exe"))?;
    let sealed = fs::metadata(&node.path)?;
    let floor = num(&body, "minimum_free_bytes")?;
    ensure!(
        launch["schema"] == "jetstreamer-historical-performance-launch-receipt-v1"
            && launch["kind"] == "epoch296-private-loader-upgrade-diagnostic"
            && launch["epoch"] == 296
            && launch["unit"] == UNIT
            && launch["run_root"] == ROOT
            && launch["launched"] == true
            && launch["canonical_epoch_publication_authorized"] == false
            && launch["node_path"] == json!(node.path)
            && launch["worker"] == profile["worker"]
            && launch["main_pid"] == pid
            && profile_ref.path == Path::new(PROFILE.0)
            && profile_ref.sha256 == PROFILE.1
            && admission["schema"] == "foundation-epoch296-focused-admission-v1"
            && admission["profile"] == launch["profile"]
            && admission["admitted"] == true
            && admission["publication_authorized"] == false
            && quote["focused_296_quote"]["preflight"] == json!(preflight)
            && quote["capacity"]["fits"] == true
            && quote["capacity"]["candidate_disk_bytes"] == SCRATCH_CAP + RECEIPT_DISK
            && quote["capacity"]["candidate_total_memory_bytes"]
                == PRODUCER_MEMORY + CONTROLLER_MEMORY + (1 << 30)
            && quote["capacity"]["guard_floor_bytes"] == floor
            && body["filesystem"] == "/"
            && body["worker_root"] == ROOT
            && body["unit"] == UNIT
            && body["invocation_id"] == invocation
            && body["maximum_root_physical_bytes"] == SCRATCH_CAP
            && sample["plan"] == json!(plan.path)
            && sample["plan_sha256"] == plan.sha256
            && sample["guard_sha256"] == profile["guard"]["sha256"]
            && owner["AllowedCPUs"] == profile["properties"]["AllowedCPUs"]
            && (running.dev(), running.ino()) == (sealed.dev(), sealed.ino()),
        "epoch 296 focused diagnostic booking or invocation changed"
    );
    let memory = super::live::finite_owner(&owner, UNIT, invocation, PRODUCER_MEMORY)?;
    Ok(LiveReplay {
        reference,
        unit: UNIT,
        owner,
        memory,
        ticks,
        guard_booking: json!({"sample":sample_ref,"floor_bytes":floor,"cap_bytes":SCRATCH_CAP}),
        receipt_disk: RECEIPT_DISK,
    })
}
