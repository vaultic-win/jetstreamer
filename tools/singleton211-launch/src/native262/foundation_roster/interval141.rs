//! Account for delegated private epoch 141 intervals and their disjoint owners.
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
    producer_cpus: [u64; 2],
    affinity: &'static str,
    guard_cpu: u64,
}

const SECOND: Scope = Scope {
    ordinal: 2,
    unit: "horizon-qualify-141-foundation-interval2-v1.service",
    guard: "horizon-141-foundation-interval2-guard-v1.service",
    timer: "horizon-141-foundation-interval2-guard-v1.timer",
    state: "/var/lib/jetstreamer/horizon141-foundation-interval2-runtime-v1",
    handoff: "bb57a2c745321a50b3273bcd428953e0e2d74348fcb790a23e4b49f2f8c30384",
    producer_cpus: [24, 25],
    affinity: "24-25",
    guard_cpu: 26,
};
const THIRD: Scope = Scope {
    ordinal: 3,
    unit: "horizon-qualify-141-foundation-interval3-v1.service",
    guard: "horizon-141-foundation-interval3-guard-v1.service",
    timer: "horizon-141-foundation-interval3-guard-v1.timer",
    state: "/var/lib/jetstreamer/horizon141-foundation-interval3-runtime-v1",
    handoff: "dda2a0a0f919c7c277281f43d46d8ed2c2b6fab71ee4b08c466d1c6db4069e18",
    producer_cpus: [24, 25],
    affinity: "24-25",
    guard_cpu: 26,
};
const FOURTH: Scope = Scope {
    ordinal: 4,
    unit: "horizon-qualify-141-foundation-interval4-v1.service",
    guard: "horizon-141-foundation-interval4-guard-v1.service",
    timer: "horizon-141-foundation-interval4-guard-v1.timer",
    state: "/var/lib/jetstreamer/horizon141-foundation-interval4-runtime-v1",
    handoff: "f56969445eb933d4ff9ea3eb3ec8a218d999ce9a63c1d1c2da063c154cebbf8e",
    producer_cpus: [27, 28],
    affinity: "27-28",
    guard_cpu: 29,
};
const FOURTH_PACKET: &str = "f7c8bebfa2a6e838f3f39f46ac4d32a18948192331fa29b46425268ed8592772";

pub(super) struct Active {
    scope: &'static Scope,
    pub(super) unit: &'static str,
    pub(super) launch: Bound,
    pub(super) owner: Value,
    pub(super) memory: u64,
    pub(super) ticks: u64,
}

impl Active {
    pub(super) fn is_fourth(&self) -> bool {
        self.scope.ordinal == 4
    }
    pub(super) fn require_disjoint(&self, cpus: &BTreeSet<u64>) -> Result<()> {
        let peer = placement(self.scope)?;
        ensure!(
            cpus.is_disjoint(&peer),
            "candidate shares a physical core with epoch 141 interval {}",
            self.scope.ordinal
        );
        Ok(())
    }
}

pub(super) fn is_guard(unit: &str) -> bool {
    [SECOND.guard, THIRD.guard, FOURTH.guard].contains(&unit)
}

pub(super) fn enrolled(n: &mut Native, running: &BTreeSet<String>) -> Result<Vec<Active>> {
    ensure!(
        !(running.contains(SECOND.unit) && running.contains(THIRD.unit)),
        "sequential epoch 141 intervals overlap"
    );
    [&SECOND, &THIRD, &FOURTH]
        .into_iter()
        .filter(|scope| running.contains(scope.unit))
        .map(|scope| active(n, scope))
        .collect()
}

fn placement(scope: &Scope) -> Result<BTreeSet<u64>> {
    let mut physical = BTreeSet::new();
    for cpu in scope.producer_cpus.into_iter().chain([scope.guard_cpu]) {
        let siblings = fs::read_to_string(format!(
            "/sys/devices/system/cpu/cpu{cpu}/topology/thread_siblings_list"
        ))?;
        physical.extend(units::parse_cpu_list(siblings.trim())?);
    }
    Ok(physical)
}

fn active(n: &mut Native, scope: &'static Scope) -> Result<Active> {
    let owner = n.show_fields(scope.unit, OWNER_FIELDS)?;
    let iid = text(&owner, "InvocationID")?;
    let memory = live::finite_owner(&owner, scope.unit, iid, MEMORY)?;
    ensure!(
        owner["AllowedCPUs"] == scope.affinity,
        "epoch 141 CPU set changed"
    );
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
            && fit["producer_cpus"] == json!(scope.producer_cpus)
            && fit["guard_cpu"] == scope.guard_cpu,
        "unregistered epoch 141 replay envelope"
    );
    if scope.ordinal == 3 {
        successor_evidence(state, &fit)?;
    }
    if scope.ordinal == 4 {
        fourth_evidence(state, &fit)?;
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
        scope,
        unit: scope.unit,
        launch,
        owner,
        memory,
        ticks,
    })
}

pub(super) struct Candidate {
    scope: &'static Scope,
    pub(super) inputs: Value,
}

impl Candidate {
    pub(super) fn cpus(&self) -> BTreeSet<u64> {
        self.scope
            .producer_cpus
            .into_iter()
            .chain([self.scope.guard_cpu])
            .collect()
    }

    pub(super) fn exclusive(&self) -> Result<BTreeSet<u64>> {
        placement(self.scope)
    }

    pub(super) fn resources(&self) -> Result<(u64, u64)> {
        Ok((
            DISK,
            capacity::add(MEMORY, capacity::add(GUARD_MEMORY, CONTROLLER_MEMORY)?)?,
        ))
    }

    pub(super) fn schema(&self) -> String {
        format!(
            "foundation-epoch141-interval{}-roster-binding-v1",
            self.scope.ordinal
        )
    }
}

pub(super) fn candidate(ordinal: u8, before: &BTreeSet<String>) -> Result<Candidate> {
    let scope = match ordinal {
        3 => &THIRD,
        4 => &FOURTH,
        _ => anyhow::bail!("unknown epoch 141 candidate"),
    };
    ensure!(
        !before.contains(scope.unit) && (ordinal != 3 || !before.contains(SECOND.unit)),
        "epoch 141 candidate overlaps a live owner"
    );
    let state = Path::new(scope.state);
    let inputs = local_ref(&state.join("static-inputs.json"))?;
    let proof = if ordinal == 3 {
        let previous = Path::new(SECOND.state);
        let proof = json!({
            "static_inputs": inputs,
            "predecessor_terminal": local_ref(&previous.join("replay-terminal.json"))?,
            "predecessor_drain": local_ref(&previous.join("post-custody-drain.json"))?,
        });
        successor_evidence(state, &proof)?;
        proof
    } else {
        let assignment = state.join("inputs/foundation-assignment.json");
        let proof = json!({"static_inputs":inputs,"handoff":local_ref(&assignment)?});
        fourth_evidence(state, &proof)?;
        proof
    };
    Ok(Candidate {
        scope,
        inputs: proof,
    })
}

fn local_ref(path: &Path) -> Result<Bound> {
    Ok(Bound::new(path, hash(path)?))
}

fn fourth_evidence(state: &Path, fit: &Value) -> Result<()> {
    const BOOT: &str = "snapshot-60935310-FU1VdL2RPr4Ubn2SGE727jU8TQscWYn1gWbBE6peiC6r.tar.zst";
    let inputs = binding(&fit["static_inputs"])?;
    let assignment = binding(&fit["handoff"])?;
    ensure!(
        inputs.path == state.join("static-inputs.json")
            && assignment.path == state.join("inputs/foundation-assignment.json")
            && assignment.sha256 == FOURTH.handoff,
        "unregistered fourth-interval input or assignment"
    );
    let assignment = assignment.sealed()?;
    let source = inputs.sealed()?;
    let packet = binding(&source["source_packet"])?;
    let execution = binding(&source["execution_packet"])?;
    let boot = binding(&source["bootstrap_intake"])?;
    ensure!(
        packet.path == state.join("inputs/FOURTH_INTERVAL_SOURCES.json")
            && packet.sha256 == FOURTH_PACKET
            && boot.path == state.join("bootstrap-intake.json")
            && execution.path == state.join("inputs/141-fourth-execution-inputs.json")
            && execution.sha256
                == "6cbe8287993a9970d181fe500e8ae5c245a922e86414d09ece59ff7d9eddf501",
        "unregistered fourth-interval source or bootstrap"
    );
    packet.sealed()?;
    let execution = execution.sealed()?;
    let boot = boot.sealed()?;
    let installed = state.join("payloads").join(BOOT);
    let metadata = fs::symlink_metadata(&installed)?;
    ensure!(
        assignment["schema"] == "foundation-epoch141-fourth-assignment-v1"
            && assignment["canonical_publication_authorized"] == false
            && source["schema"] == "foundation-epoch141-interval4-static-inputs-v1"
            && source["interval"] == assignment["interval"]
            && source["interval"] == execution["interval"]
            && source["original_target_count"] == 340
            && source["reused_files"]["jetstreamer-node"]["sha256"] == NODE_SHA
            && source["reused_files"]["jetstreamer-historical-worker-v1-4-25"]["sha256"]
                == "fce05d551d8154ebda6ff6b3791d02f60b0e0a1e3a69982ea06fa7c31c34b759"
            && boot["schema"] == "foundation-epoch141-interval4-private-object-intake-v1"
            && boot["pinned_authenticated_get"] == true
            && boot["single_physical_copy"] == true
            && boot["gcs_generation_checksums_match"] == true
            && boot["generation"] == 1_634_786_585_263_892u64
            && boot["sha256"] == "9944c752006ccd77def013750035b90cbb5c1cd0ef96f8ae4548436323d98d57"
            && boot["remote_manifest_sha256"]
                == "19086d7d15039c4b064442caf9a09f6b3e64292a0afabe9e0f352d2ca501d6be"
            && boot["installed_path"] == json!(installed)
            && boot["bytes"] == 2_201_713_062u64
            && boot["inode"] == metadata.ino()
            && boot["device"] == metadata.dev()
            && metadata.is_file()
            && metadata.len() == 2_201_713_062
            && metadata.uid() == 0
            && metadata.mode() & 0o222 == 0
            && metadata.nlink() == 1,
        "fourth-interval assignment, verified inputs or bootstrap identity differ"
    );
    Ok(())
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
