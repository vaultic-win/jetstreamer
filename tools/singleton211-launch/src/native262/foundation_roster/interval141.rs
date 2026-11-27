//! Account for the delegated private epoch 141 interval during Foundation admissions.
use super::*;

pub(super) const UNIT: &str = "horizon-qualify-141-foundation-interval2-v1.service";
pub(super) const GUARD: &str = "horizon-141-foundation-interval2-guard-v1.service";
const TIMER: &str = "horizon-141-foundation-interval2-guard-v1.timer";
const STATE: &str = "/var/lib/jetstreamer/horizon141-foundation-interval2-runtime-v1";
const NODE: &str =
    "/var/lib/jetstreamer/horizon141-foundation-interval2-package-v1/jetstreamer-node";
const NODE_SHA: &str = "e69ca5d94b97c1ab25c5c4908ab8dfd6aab4c44a8dbf99bf7f40e7a83939cdd8";
const HANDOFF: &str = "bb57a2c745321a50b3273bcd428953e0e2d74348fcb790a23e4b49f2f8c30384";
const MEMORY: u64 = 74 << 30;
pub(super) const GUARD_MEMORY: u64 = 1 << 30;
pub(super) const DISK: u64 = (4 << 30) + (320 << 20);

pub(super) struct Active {
    pub(super) launch: Bound,
    pub(super) owner: Value,
    pub(super) memory: u64,
    pub(super) ticks: u64,
}

pub(super) fn require_disjoint(cpus: &BTreeSet<u64>) -> Result<()> {
    let selected = units::parse_cpu_list("24-26")?;
    let mut physical = BTreeSet::new();
    for cpu in selected {
        let siblings = fs::read_to_string(format!(
            "/sys/devices/system/cpu/cpu{cpu}/topology/thread_siblings_list"
        ))?;
        physical.extend(units::parse_cpu_list(siblings.trim())?);
    }
    ensure!(
        cpus.is_disjoint(&physical),
        "candidate shares a physical core with epoch 141"
    );
    Ok(())
}

pub(super) fn active(n: &mut Native) -> Result<Active> {
    let owner = n.show_fields(UNIT, OWNER_FIELDS)?;
    let iid = text(&owner, "InvocationID")?;
    let memory = live::finite_owner(&owner, UNIT, iid, MEMORY)?;
    ensure!(owner["AllowedCPUs"] == "24-25", "epoch 141 CPU set changed");
    let state = Path::new(STATE);
    let path = state.join("replay-launch.json");
    let launch = Bound::new(&path, hash(&path)?);
    let record = launch.sealed()?;
    let admission = binding(&record["admission"])?;
    ensure!(
        admission.path == state.join("replay-admission.json"),
        "foreign epoch 141 admission path"
    );
    let fit = admission.sealed()?;
    ensure!(
        record["schema"] == "foundation-epoch141-interval2-replay-launch-v1"
            && record["unit"] == UNIT
            && record["invocation_id"] == iid
            && record["canonical_publication_authorized"] == false
            && fit["schema"] == "foundation-epoch141-interval2-replay-admission-v1"
            && fit["handoff"]["sha256"] == HANDOFF
            && fit["producer_memory_bytes"] == MEMORY
            && fit["guard_memory_bytes"] == GUARD_MEMORY
            && fit["future_home_bytes"] == DISK
            && fit["producer_cpus"] == json!([24, 25])
            && fit["guard_cpu"] == 26,
        "unregistered epoch 141 replay envelope"
    );
    let timer = n.show_fields(TIMER, "Id,ActiveState,InvocationID,Unit")?;
    ensure!(
        timer["Id"] == TIMER
            && timer["ActiveState"] == "active"
            && timer["Unit"] == GUARD
            && timer["InvocationID"] == record["guard_timer_invocation_id"],
        "epoch 141 guard timer changed"
    );
    let guard_plan = binding(&record["guard_plan"])?;
    ensure!(
        guard_plan.path == state.join("guard-plan.json"),
        "foreign epoch 141 guard plan"
    );
    let guard = guard_plan.sealed()?;
    ensure!(
        guard["schema"] == "jetstreamer-horizon-standalone-guard-plan-v1"
            && guard["unit"] == UNIT
            && guard["invocation_id"] == iid
            && guard["maximum_root_physical_bytes"] == 44u64 << 30,
        "epoch 141 guard scope differs"
    );
    Bound::new(NODE, NODE_SHA).artifact()?;
    let pid = text(&owner, "MainPID")?.parse()?;
    let ticks = process_ticks(pid)?;
    ensure!(
        metadata_identity(&fs::metadata(format!("/proc/{pid}/exe"))?) == identity(Path::new(NODE))?
            && process_ticks(pid)? == ticks,
        "live epoch 141 core process differs from the sealed node"
    );
    Ok(Active {
        launch,
        owner,
        memory,
        ticks,
    })
}
