//! Account for sequential delegated private epoch 141 intervals.
use super::*;

const NODE: &str =
    "/var/lib/jetstreamer/horizon141-foundation-interval2-package-v1/jetstreamer-node";
const NODE_SHA: &str = "e69ca5d94b97c1ab25c5c4908ab8dfd6aab4c44a8dbf99bf7f40e7a83939cdd8";
const MEMORY: u64 = 74 << 30;
pub(super) const GUARD_MEMORY: u64 = 1 << 30;
pub(super) const DISK: u64 = (4 << 30) + (320 << 20);

struct Scope {
    ordinal: u8,
    unit: &'static str,
    guard: &'static str,
    timer: &'static str,
    state: &'static str,
    handoff: &'static str,
}

const SECOND: Scope = Scope {
    ordinal: 2,
    unit: "horizon-qualify-141-foundation-interval2-v1.service",
    guard: "horizon-141-foundation-interval2-guard-v1.service",
    timer: "horizon-141-foundation-interval2-guard-v1.timer",
    state: "/var/lib/jetstreamer/horizon141-foundation-interval2-runtime-v1",
    handoff: "bb57a2c745321a50b3273bcd428953e0e2d74348fcb790a23e4b49f2f8c30384",
};
const THIRD: Scope = Scope {
    ordinal: 3,
    unit: "horizon-qualify-141-foundation-interval3-v1.service",
    guard: "horizon-141-foundation-interval3-guard-v1.service",
    timer: "horizon-141-foundation-interval3-guard-v1.timer",
    state: "/var/lib/jetstreamer/horizon141-foundation-interval3-runtime-v1",
    handoff: "dda2a0a0f919c7c277281f43d46d8ed2c2b6fab71ee4b08c466d1c6db4069e18",
};

pub(super) struct Active {
    pub(super) unit: &'static str,
    pub(super) launch: Bound,
    pub(super) owner: Value,
    pub(super) memory: u64,
    pub(super) ticks: u64,
}

pub(super) fn is_guard(unit: &str) -> bool {
    [SECOND.guard, THIRD.guard].contains(&unit)
}

pub(super) fn enrolled(n: &mut Native, running: &BTreeSet<String>) -> Result<Option<Active>> {
    match (running.contains(SECOND.unit), running.contains(THIRD.unit)) {
        (false, false) => Ok(None),
        (true, false) => active(n, &SECOND).map(Some),
        (false, true) => active(n, &THIRD).map(Some),
        (true, true) => anyhow::bail!("delegated epoch 141 intervals overlap"),
    }
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

fn active(n: &mut Native, scope: &Scope) -> Result<Active> {
    let owner = n.show_fields(scope.unit, OWNER_FIELDS)?;
    let iid = text(&owner, "InvocationID")?;
    let memory = live::finite_owner(&owner, scope.unit, iid, MEMORY)?;
    ensure!(owner["AllowedCPUs"] == "24-25", "epoch 141 CPU set changed");
    let state = Path::new(scope.state);
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
        record["schema"]
            == format!(
                "foundation-epoch141-interval{}-replay-launch-v1",
                scope.ordinal
            )
            && record["unit"] == scope.unit
            && record["invocation_id"] == iid
            && record["canonical_publication_authorized"] == false
            && fit["schema"]
                == format!(
                    "foundation-epoch141-interval{}-replay-admission-v1",
                    scope.ordinal
                )
            && fit["handoff"]["sha256"] == scope.handoff
            && fit["producer_memory_bytes"] == MEMORY
            && fit["guard_memory_bytes"] == GUARD_MEMORY
            && fit["future_home_bytes"] == DISK
            && fit["producer_cpus"] == json!([24, 25])
            && fit["guard_cpu"] == 26,
        "unregistered epoch 141 replay envelope"
    );
    if scope.ordinal == 3 {
        successor_evidence(state, &fit)?;
    }
    let timer = n.show_fields(scope.timer, "Id,ActiveState,InvocationID,Unit")?;
    ensure!(
        timer["Id"] == scope.timer
            && timer["ActiveState"] == "active"
            && timer["Unit"] == scope.guard
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
            && guard["unit"] == scope.unit
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
        unit: scope.unit,
        launch,
        owner,
        memory,
        ticks,
    })
}

fn successor_evidence(state: &Path, fit: &Value) -> Result<()> {
    const STATIC_SHA: &str = "ad6164296a4f56f8cc96b45f6ba24bc67f26d653c47e1969a7c6c8b1a3aa1666";
    const PREDECESSOR: &str = "94e2a4715b3a454eb3e7b0462863515e";
    let inputs = binding(&fit["static_inputs"])?;
    let terminal = binding(&fit["predecessor_terminal"])?;
    let drain = binding(&fit["predecessor_drain"])?;
    ensure!(
        inputs.path == state.join("static-inputs.json")
            && inputs.sha256 == STATIC_SHA
            && terminal.path == Path::new(SECOND.state).join("replay-terminal.json")
            && drain.path == Path::new(SECOND.state).join("post-custody-drain.json"),
        "unregistered epoch 141 successor inputs or predecessor evidence"
    );
    let source = inputs.sealed()?;
    let terminal_result = terminal.sealed()?;
    let released = drain.sealed()?;
    ensure!(
        source["source_packet"]["sha256"]
            == "7cf9ec0c89f1f4959ebc6f310ff491f862902f229cf79614d6d1fb4ad023519b"
            && source["interval"]["bootstrap"] == 60_928_493
            && source["interval"]["endpoint"] == 60_935_310
            && source["original_target_count"] == 330
            && terminal_result["schema"] == "foundation-epoch141-interval2-terminal-v1"
            && terminal_result["invocation_id"] == PREDECESSOR
            && terminal_result["terminal_checkpoint"]["slot"] == 60_928_493
            && terminal_result["original_entry_slots_verified"] == 288
            && terminal_result["private_custody"]["no_clobber"] == true
            && released["schema"] == "foundation-epoch141-interval2-post-custody-drain-v1"
            && released["invocation_id"] == PREDECESSOR
            && binding(&released["terminal"])?.sha256 == terminal.sha256
            && binding(&released["terminal"])?.path == terminal.path
            && released["guard_drained"] == true
            && released["tmpfs_drained"] == true,
        "epoch 141 third interval lacks the exact verified input or predecessor drain"
    );
    Ok(())
}
