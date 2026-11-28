//! Bind the active epoch 230 diagnostic and its memory-backed guard.
use super::*;
use std::ffi::CString;

pub(super) const UNIT: &str = "horizon-perf-epoch230-vote-boundary@v1.service";
pub(super) const GUARD: &str = "horizon-230-vote-boundary-protective-v1";
pub(super) const GUARD_SERVICE: &str = "horizon-230-vote-boundary-protective-v1.service";
pub(super) const GUARD_BINARY: &str =
    "/var/lib/jetstreamer/horizon230-vote-boundary-guard-310cd206-v1/guard";
const REGISTRATION: &str =
    "/var/lib/jetstreamer/horizon230-vote-boundary-runtime-v1/cadence-registration.json";
const REGISTRATION_SHA: &str = "a6bcf5bb5ca6e375331b22ae246f1130d9515ef3c24adff528828f28ddc73a05";
const PRODUCER_MEMORY: u64 = 200 << 30;
const SCRATCH_CAP: u64 = 150_000_000_000;
const RECEIPT_DISK: u64 = 256 << 20;

pub(super) fn live(n: &mut Native) -> Result<LiveReplay> {
    let reference = Bound::new(REGISTRATION, REGISTRATION_SHA);
    let registration = reference.sealed()?;
    let admission = binding(&registration["admission"])?.sealed()?;
    let profile = binding(&admission["profile"])?.sealed()?;
    let plan = binding(&registration["guard_plan"])?;
    let body = plan.sealed()?;
    let sample_ref = binding(&registration["active_guard"])?;
    let sample = sample_ref.json()?;
    let node = binding(&profile["node"])?;
    node.artifact()?;
    let owner = n.show_fields(UNIT, OWNER_FIELDS)?;
    let invocation = text(&registration, "invocation_id")?;
    let pid = text(&owner, "MainPID")?.parse::<u64>()?;
    let ticks = process_ticks(pid)?;
    let running = fs::metadata(format!("/proc/{pid}/exe"))?;
    let sealed = fs::metadata(&node.path)?;
    ensure!(
        registration["schema"] == "jetstreamer-historical-performance-launch-receipt-v1"
            && registration["kind"] == "epoch230-vote-boundary-demotion"
            && registration["epoch"] == 230
            && registration["unit"] == UNIT
            && registration["launched"] == true
            && registration["canonical_epoch_publication_authorized"] == false
            && registration["main_pid"] == pid
            && registration["run_root"] == profile["run_root"]
            && registration["run_root"] == body["worker_root"]
            && registration["node_path"] == json!(node.path)
            && registration["worker_sha256"] == profile["worker"]["sha256"]
            && admission["schema"] == "foundation-epoch230-vote-boundary-admission-v1"
            && admission["admitted"] == true
            && admission["publication_authorized"] == false
            && admission["fit"]["candidate_memory_bytes"]
                == PRODUCER_MEMORY + CONTROLLER_MEMORY + (1 << 30)
            && admission["properties"]["MemoryMax"] == PRODUCER_MEMORY
            && profile["memory_max_bytes"] == PRODUCER_MEMORY
            && profile["root_receipt_reservation_bytes"] == RECEIPT_DISK
            && profile["ram_scratch_cap_bytes"] == SCRATCH_CAP
            && profile["guard_unit"] == GUARD_SERVICE
            && profile["guard"]["path"] == GUARD_BINARY
            && profile["guard"]["sha256"] == sample["guard_sha256"]
            && sample["plan"] == json!(plan.path)
            && sample["plan_sha256"] == plan.sha256
            && body["maximum_root_physical_bytes"] == SCRATCH_CAP
            && owner["AllowedCPUs"] == profile["allowed_cpus"]
            && (running.dev(), running.ino()) == (sealed.dev(), sealed.ino()),
        "epoch 230 vote-boundary booking or live invocation changed"
    );
    let memory = super::live::finite_owner(&owner, UNIT, invocation, PRODUCER_MEMORY)?;
    let guard_booking = json!({
        "sample": sample_ref,
        "floor_bytes": num(&body, "minimum_free_bytes")?,
        "cap_bytes": SCRATCH_CAP,
        "filesystem": body["filesystem"],
    });
    Ok(LiveReplay {
        reference,
        unit: UNIT,
        owner,
        memory,
        ticks,
        guard_booking,
        receipt_disk: RECEIPT_DISK,
    })
}

pub(super) fn guard(n: &mut Native, replay: &LiveReplay, disk_device: u64) -> Result<Value> {
    let filesystem = text(&replay.guard_booking, "filesystem")?;
    let scratch_device = fs::metadata(filesystem)?.dev();
    let path = CString::new(filesystem)?;
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    ensure!(
        scratch_device != disk_device
            && unsafe { libc::statfs(path.as_ptr(), &mut stat) } == 0
            && stat.f_type == libc::TMPFS_MAGIC,
        "epoch 230 diagnostic scratch is not a distinct tmpfs"
    );
    guard_binding(
        n,
        230,
        GUARD,
        &replay.guard_booking,
        &replay.owner,
        scratch_device,
    )
}
