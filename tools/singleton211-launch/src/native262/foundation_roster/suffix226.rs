//! Price the guarded 226 suffix after its extraction and broker have drained.
use super::*;

pub(super) const UNIT: &str = "horizon-qualify-226-checkpoint-continuation-suffix-v1.service";
pub(super) const GUARD: &str = "horizon-guard-226-checkpoint-continuation-suffix-v1";
pub(super) const GUARD_SERVICE: &str =
    "horizon-guard-226-checkpoint-continuation-suffix-v1.service";
const TIMER: &str = "horizon-guard-226-checkpoint-continuation-suffix-v1.timer";
const ROOT: &str = "/home/ubuntu/.jetstreamer-private/checkpoint-continuation-226-suffix-v1";
const NODE: (&str, &str) = (
    "/run/foundation-epoch226-release.y35rokj7/jetstreamer-node",
    "7e17105ad9429fccbeb53dcd38650adb3f469bc1d3fe797360afff2cc7379ded",
);
const WORKER_SHA: &str = "7a831420bb1498ddb0268309ce69f615c7f0c6d90cfab940896a03dc38b5336a";

pub(super) fn live(n: &mut Native) -> Result<LiveReplay> {
    let registration = Path::new(SUFFIX_226_ROOT).join("cadence-registration.json");
    let reference = Bound::new(&registration, hash(&registration)?);
    let row = reference.sealed()?;
    let admission_ref = binding(&row["admission"])?;
    let admission = admission_ref.sealed()?;
    let plan = binding(&row["plan"])?.sealed()?;
    let handoff = binding(&admission["handoff"])?;
    let drain = Bound::new(DRAIN_226, hash(Path::new(DRAIN_226))?).sealed()?;
    let guard_ref = binding(&row["guard_plan"])?;
    let guard = guard_ref.sealed()?;
    let sample_ref = binding(&row["active_guard"])?;
    let sample = sample_ref.json()?;
    let floor = num(&guard, "minimum_free_bytes")?;
    let owner = n.show_fields(UNIT, OWNER_FIELDS)?;
    let timer = n.show_fields(TIMER, "ActiveState,InvocationID,Unit")?;
    let pid = text(&owner, "MainPID")?.parse::<u64>()?;
    let invocation = text(&row, "invocation_id")?;
    let memory = live::finite_owner(&owner, UNIT, invocation, SUFFIX_226_CAP)?;
    let ticks = process_ticks(pid)?;
    let node = Bound::new(NODE.0, NODE.1);
    node.artifact()?;
    let mapped = fs::metadata(format!("/proc/{pid}/exe"))?;
    let sealed = fs::metadata(&node.path)?;
    ensure!(
        row["schema"] == "jetstreamer-historical-performance-launch-receipt-v1"
            && row["kind"] == "epoch226-checkpoint-suffix"
            && row["epoch"] == 226
            && row["unit"] == UNIT
            && row["main_pid"] == pid
            && row["node_path"] == NODE.0
            && row["run_root"] == ROOT
            && guard["worker_root"] == ROOT
            && plan["run_root"] == ROOT
            && row["bootstrap_slot"] == 98_063_464
            && row["first_slot"] == 98_063_465
            && row["last_slot"] == 98_063_999
            && row["worker_sha256"] == WORKER_SHA
            && row["launched"] == true
            && row["source_prefix_retained"] == true
            && row["canonical_epoch_publication_authorized"] == false
            && admission["schema"] == "jetstreamer-epoch226-scoped-repair-admission-v1"
            && admission["epoch"] == 226
            && admission["producer_unit"] == UNIT
            && admission["admitted"] == true
            && admission["run_root"] == row["run_root"]
            && admission["candidate_incremental_peak_bytes"] == SUFFIX_226_CAP
            && admission["publication_authorized"] == false
            && drain["handoff"] == json!(handoff)
            && plan["admission"] == json!(admission_ref)
            && plan["stage"]["worker"]["sha256"] == WORKER_SHA
            && guard["maximum_root_physical_bytes"] == SUFFIX_226_CAP
            && sample["plan"] == json!(guard_ref.path)
            && sample["plan_sha256"] == guard_ref.sha256
            && timer["ActiveState"] == "active"
            && timer["Unit"] == GUARD_SERVICE
            && timer["InvocationID"] == row["launch_token"]["guard_timer_invocation"]
            && owner["AllowedCPUs"] == "16-23"
            && (mapped.dev(), mapped.ino()) == (sealed.dev(), sealed.ino()),
        "epoch 226 suffix differs from its admitted handoff or guard"
    );
    Ok(LiveReplay {
        reference,
        unit: UNIT,
        owner,
        memory,
        ticks,
        guard_booking: json!({"sample":sample_ref,"floor_bytes":floor,"cap_bytes":SUFFIX_226_CAP}),
        receipt_disk: DISK_RECEIPTS,
    })
}

pub(super) fn reserve_for_overlap(shares_suffix: bool, suffix_quote: bool, suffix_active: bool) -> bool {
    shares_suffix && !suffix_quote && !suffix_active
}

/// Reserve the complete suffix across extraction, drain and admission. Its own active
/// guard and cgroup take over the booking once it is running. Only a verified, drained
/// suffix with a sealed assembly handoff can relinquish a pending booking.
pub(super) fn pending_reservation(n: &mut Native) -> Result<(u64, u64)> {
    let state = Path::new(SUFFIX_226_ROOT);
    let handoff = state.join("assembly-source-handoff.json");
    if !handoff.try_exists()? {
        return Ok((
            capacity::add(SUFFIX_226_CAP, DISK_RECEIPTS)?,
            capacity::add(SUFFIX_226_CAP, capacity::add(CONTROLLER_MEMORY, 1 << 30)?)?,
        ));
    }
    let document = Bound::new(&handoff, hash(&handoff)?).sealed()?;
    let registration = state.join("cadence-registration.json");
    let reference = Bound::new(&registration, hash(&registration)?);
    let launch = reference.sealed()?;
    let replay = binding(&document["stage"]["replay"])?.sealed()?;
    let manifest = binding(&document["stage"]["suffix_manifest"])?.sealed()?;
    ensure!(
        document["schema"] == "foundation-epoch226-private-assembly-source-v1"
            && document["epoch"] == 226
            && document["suffix_launch"] == json!(reference)
            && document["terminal"]["manager"]["Result"] == "success"
            && document["stage"]["operation"] == "assemble"
            && document["publication_authorized"] == false
            && launch["kind"] == "epoch226-checkpoint-suffix"
            && launch["unit"] == UNIT
            && launch["worker_sha256"] == WORKER_SHA
            && replay["remaining_slots_replayed"] == 535
            && replay["suffix_complete"] == true
            && replay["actual_native_checkpoint_matches"] == true
            && manifest["epoch"] == 226
            && manifest["output_slot_start"] == 98_063_465
            && manifest["output_slot_count"] == 535
            && manifest["terminal"]["slot"] == 98_063_999
            && manifest["archive_sha256"] == replay["suffix_archive_sha256"],
        "epoch 226 suffix reservation has no complete assembly handoff"
    );
    focused::drained(n, UNIT, GUARD, text(&launch, "invocation_id")?)?;
    Ok((0, 0))
}

#[cfg(test)]
mod overlap_tests {
    use super::*;

    #[test]
    fn pending_suffix_is_charged_once_for_overlapping_users() {
        assert!(reserve_for_overlap(true, false, false));
        for already_charged in [(true, false), (false, true), (true, true)] {
            assert!(!reserve_for_overlap(true, already_charged.0, already_charged.1));
        }
        assert!(!reserve_for_overlap(false, false, false));
        assert_eq!(SUFFIX_226_CAP + DISK_RECEIPTS, 172_067_127_296);
        assert_eq!(SUFFIX_226_CAP + CONTROLLER_MEMORY + (1 << 30), 173_140_869_120);
    }
}
