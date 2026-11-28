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

const FIFTH: Scope = Scope {
    ordinal: 5,
    unit: "horizon-qualify-141-foundation-interval5-v1.service",
    guard: "horizon-141-foundation-interval5-guard-v1.service",
    timer: "horizon-141-foundation-interval5-guard-v1.timer",
    state: "/var/lib/jetstreamer/horizon141-foundation-interval5-runtime-v1",
    handoff: "c024321f48da115b98ed2a25a91a81655aab4ca74728a4517aa4b8d4976a6455",
    producer_cpus: [27, 28],
    affinity: "27-28",
    guard_cpu: 29,
};
const SIXTH: Scope = Scope {
    ordinal: 6,
    unit: "horizon-qualify-141-foundation-interval6-v1.service",
    guard: "horizon-141-foundation-interval6-guard-v1.service",
    timer: "horizon-141-foundation-interval6-guard-v1.timer",
    state: "/var/lib/jetstreamer/horizon141-foundation-interval6-runtime-v1",
    handoff: "61c9e7e51df008bffb04388b9430eced562c73835c72f6b098d3a915e4a3da14",
    producer_cpus: [24, 25],
    affinity: "24-25",
    guard_cpu: 26,
};
const SEVENTH: Scope = Scope {
    ordinal: 7,
    unit: "horizon-qualify-141-foundation-interval7-v1.service",
    guard: "horizon-141-foundation-interval7-guard-v1.service",
    timer: "horizon-141-foundation-interval7-guard-v1.timer",
    state: "/var/lib/jetstreamer/horizon141-foundation-interval7-runtime-v1",
    handoff: "c20773d1c9708ca00aa38aee4239c05255bb465d277934d7d714d28f2ee4aaee",
    producer_cpus: [27, 28],
    affinity: "27-28",
    guard_cpu: 29,
};
const SCOPES: [&Scope; 6] = [&SECOND, &THIRD, &FOURTH, &FIFTH, &SIXTH, &SEVENTH];
const SEVENTH_SOURCE: &str = "9a90d6fae54742f2451a78f7af78915895fde767d45df5f01491723e3578824b";
const SEVENTH_EXECUTION: &str = "a350bdc8bfcd4abd22ac35c32bce2906581e11e8179d72915f0341f5fcc95ee1";
const SEVENTH_SCOPE: &str = "c6acd7bd872f4bf53165c9be56cc67bf2b2affc8fa0bbead565c2271d2c2ca4e";
const SEVENTH_VALIDATION: &str = "1842dc30d21be15094460dc8208612346aed7a0d55c57fcbdd007853d71ca334";
const SIXTH_SOURCE: &str = "47fadfc2b7072a1ac74eed185a6dee7c37ad1535c58e4cd32f42cbe7da713509";
const SIXTH_EXECUTION: &str = "3d76221e466bc27251740fc8319a96701eaeb0f895d41df392438384f29a63a1";
const SIXTH_SCOPE: &str = "f201ca9c60be597b88938be7ab92e13fd7413cf380910c5b81c9ceac12365ddd";
const SIXTH_VALIDATION: &str = "d072f1535e90b58b69ed3691d25c51db9ac4a6a4afc9108fc3811f3c73e8650f";
const FIFTH_SOURCE: &str = "cd204d101e4aaa51a946c96db3745ab8b599edd05c45cabd2a5abc7a7d830525";
const FIFTH_EXECUTION: &str = "e452a16accc13f9916d4052f1e67212a47cf5cb675648c8008e3aa3348343e95";
const FIFTH_SCOPE: &str = "9188755bc441de30ed4e7c646c2c80889872b4d0cfb8a8f0c34c67847866337e";
const FIFTH_CUSTODY: &str = "2193c11c736af4396f266d788325e02f87eeb857efdc98fa90137a7c22ba243f";
const FOURTH_INVOCATION: &str = "e8ddd3cf18c64dba954e84604afc70b1";

pub(super) struct Active {
    scope: &'static Scope,
    pub(super) unit: &'static str,
    pub(super) launch: Bound,
    pub(super) owner: Value,
    pub(super) memory: u64,
    pub(super) ticks: u64,
}

impl Active {
    pub(super) fn ordinal(&self) -> u8 {
        self.scope.ordinal
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
    SCOPES.iter().any(|scope| scope.guard == unit)
}

pub(super) fn enrolled(n: &mut Native, running: &BTreeSet<String>) -> Result<Vec<Active>> {
    let mut occupied = BTreeSet::new();
    let mut enrolled = Vec::new();
    for scope in SCOPES
        .into_iter()
        .filter(|scope| running.contains(scope.unit))
    {
        ensure!(
            occupied.insert(scope.affinity),
            "sequential epoch 141 intervals overlap"
        );
        enrolled.push(active(n, scope)?);
    }
    Ok(enrolled)
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
    if scope.ordinal == 5 {
        fifth_evidence(state, &fit)?;
    }
    if scope.ordinal == 6 {
        sixth_evidence(state, &fit)?;
    }
    if scope.ordinal == 7 {
        seventh_evidence(state, &fit)?;
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
        5 => &FIFTH,
        6 => &SIXTH,
        7 => &SEVENTH,
        _ => anyhow::bail!("unknown epoch 141 candidate"),
    };
    let predecessor = match ordinal {
        3 => Some(&SECOND),
        5 => Some(&FOURTH),
        6 => Some(&THIRD),
        7 => Some(&FIFTH),
        _ => None,
    };
    ensure!(
        !SCOPES
            .into_iter()
            .any(|peer| peer.affinity == scope.affinity && before.contains(peer.unit)),
        "epoch 141 candidate overlaps a live owner"
    );
    let state = Path::new(scope.state);
    let inputs = local_ref(&state.join("static-inputs.json"))?;
    let mut proof = json!({"static_inputs":inputs});
    if let Some(prior) = predecessor {
        let previous = Path::new(prior.state);
        proof["predecessor_terminal"] = json!(local_ref(&previous.join("replay-terminal.json"))?);
        proof["predecessor_drain"] = json!(local_ref(&previous.join("post-custody-drain.json"))?);
    }
    if ordinal >= 4 {
        proof["handoff"] = json!(local_ref(&state.join("inputs/foundation-assignment.json"))?);
    }
    match ordinal {
        3 => successor_evidence(state, &proof)?,
        4 => fourth_evidence(state, &proof)?,
        5 => fifth_evidence(state, &proof)?,
        6 => sixth_evidence(state, &proof)?,
        7 => seventh_evidence(state, &proof)?,
        _ => unreachable!(),
    }
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

fn fifth_evidence(state: &Path, fit: &Value) -> Result<()> {
    const BOOT: &str = "snapshot-60942184-EMsXJsestzPAfJtGfNdQdeji3JmuvaCKDAMPcD8hW3ZT.tar.zst";
    const PAYLOAD: &str = "47e9df6780b20eb6663f1bcb175600ec20a24ba004f67628169b1eefc1f0892d";
    const MANIFEST: &str = "bdc1247ad453394100e2ab9346df03a973ba5cda4029e7d89a4532fe028bdf19";
    const ETAG: &str = "51c697688661fd9c6c34d13dc7f734ac-33";
    let previous = Path::new(FOURTH.state);
    let terminal = binding(&fit["predecessor_terminal"])?;
    let drain = binding(&fit["predecessor_drain"])?;
    ensure!(
        terminal.path == previous.join("replay-terminal.json")
            && drain.path == previous.join("post-custody-drain.json"),
        "foreign fourth predecessor evidence"
    );
    let closed = terminal.sealed()?;
    let drained = drain.sealed()?;
    ensure!(
        closed["schema"] == "foundation-epoch141-interval4-terminal-v1"
            && closed["invocation_id"] == FOURTH_INVOCATION
            && closed["terminal_checkpoint"]["slot"] == 60_942_184
            && closed["terminal_checkpoint"]["accounts_hash"]
                == "EMsXJsestzPAfJtGfNdQdeji3JmuvaCKDAMPcD8hW3ZT"
            && closed["original_entry_slots_verified"] == 340
            && closed["private_custody"]["no_clobber"] == true
            && drained["schema"] == "foundation-epoch141-interval4-post-custody-drain-v1"
            && drained["invocation_id"] == FOURTH_INVOCATION
            && drained["terminal"] == fit["predecessor_terminal"]
            && drained["container"] == closed["private_custody"]["container"]
            && drained["guard_drained"] == true
            && drained["tmpfs_drained"] == true,
        "the assigned fourth invocation has no verified output custody and drain"
    );

    let inputs = binding(&fit["static_inputs"])?;
    let handoff = binding(&fit["handoff"])?;
    ensure!(
        inputs.path == state.join("static-inputs.json")
            && inputs.sha256 == "01f4fd805577c45082dc567d02843ea9c0e27515def45f55130be62364af5e44"
            && handoff.path == state.join("inputs/foundation-assignment.json")
            && handoff.sha256 == FIFTH.handoff,
        "foreign fifth inputs or assignment"
    );
    let source = inputs.sealed()?;
    let handoff = handoff.sealed()?;
    let packet = binding(&source["source_packet"])?;
    let execution = binding(&source["execution_packet"])?;
    let scope = binding(&source["scope"])?;
    let boot = binding(&source["bootstrap_intake"])?;
    ensure!(
        packet.path == state.join("inputs/epoch141-fifth-source.json")
            && packet.sha256 == FIFTH_SOURCE
            && execution.path == state.join("inputs/epoch141-fifth-execution-inputs.json")
            && execution.sha256 == FIFTH_EXECUTION
            && scope.path == state.join("runtime-scope.json")
            && scope.sha256 == FIFTH_SCOPE
            && boot.path == state.join("bootstrap-intake.json"),
        "foreign fifth scope, input packet or intake path"
    );
    let packet = packet.sealed()?;
    let execution = execution.sealed()?;
    let scope = scope.sealed()?;
    let boot = boot.sealed()?;
    let custody = binding(&boot["custody"])?;
    ensure!(
        custody.path == state.join("inputs/bootstrap-r2-custody.json")
            && custody.sha256 == FIFTH_CUSTODY,
        "foreign fifth remote custody receipt"
    );
    let custody = custody.sealed()?;
    let installed = state.join("payloads").join(BOOT);
    let metadata = fs::symlink_metadata(&installed)?;
    ensure!(
        handoff["schema"] == "foundation-epoch141-fifth-assignment-v1"
            && handoff["canonical_publication_authorized"] == false
            && handoff["predecessor_invocation"] == FOURTH_INVOCATION
            && source["schema"] == "foundation-epoch141-interval5-static-inputs-v1"
            && source["interval"] == handoff["interval"]
            && source["interval"] == packet["interval"]
            && source["interval"] == execution["interval"]
            && source["interval"] == scope["interval"]
            && source["original_target_count"] == 307
            && scope["node"]["sha256"] == NODE_SHA
            && scope["worker"]["sha256"] == execution["image_source"]["worker_sha256"]
            && custody["object_etag"] == ETAG
            && custody["manifest_sha256"] == MANIFEST
            && custody["sha256"] == PAYLOAD
            && boot["schema"] == "foundation-epoch141-interval5-private-object-intake-v1"
            && boot["pinned_authenticated_get"] == true
            && boot["single_physical_copy"] == true
            && boot["gcs_generation_checksums_match"] == true
            && boot["generation"] == 1_634_786_582_060_703u64
            && boot["sha256"] == PAYLOAD
            && boot["etag"] == ETAG
            && boot["remote_manifest_sha256"] == MANIFEST
            && boot["installed_path"] == json!(installed)
            && boot["bytes"] == 2_209_515_703u64
            && boot["inode"] == metadata.ino()
            && boot["device"] == metadata.dev()
            && metadata.is_file()
            && metadata.len() == 2_209_515_703
            && metadata.uid() == 0
            && metadata.mode() & 0o222 == 0
            && metadata.nlink() == 1,
        "fifth interval lacks its exact verified bootstrap or execution scope"
    );
    Ok(())
}

fn sixth_evidence(state: &Path, fit: &Value) -> Result<()> {
    const BOOT: &str = "snapshot-60948885-2EsJDSWGzZUaPKtjefUMfFnE2TWAn8ba5hAvDZbGaFfa.tar.zst";
    const CUSTODY: &str = "4c8edb81d72670651eba603fc4e47a55b2411f9641d8ffc740e6af6e95df27fa";
    const PAYLOAD: &str = "1024b6cce42b2a8e16c553056821d43f812dde0984481a4d1ad2d7fc1061c96f";
    const MANIFEST: &str = "cbbec3909a24cf2afa31c2fdd9e3991abd16a6f3e52ebb103ce7dfd91f9dd01d";
    const ETAG: &str = "c4b2d61a7b2271db50533414942fd208-38";
    turnover_after(
        fit,
        &THIRD,
        60_935_310,
        "FU1VdL2RPr4Ubn2SGE727jU8TQscWYn1gWbBE6peiC6r",
        330,
    )?;

    let inputs = binding(&fit["static_inputs"])?;
    let assignment = binding(&fit["handoff"])?;
    ensure!(
        inputs.path == state.join("static-inputs.json")
            && assignment.path == state.join("inputs/foundation-assignment.json")
            && assignment.sha256 == SIXTH.handoff,
        "foreign sixth inputs or assignment"
    );
    let inputs = inputs.sealed()?;
    let assignment = assignment.sealed()?;
    let validation = binding(&inputs["source_validation"])?;
    let boot = binding(&inputs["bootstrap_intake"])?;
    ensure!(
        validation.path == state.join("source-validation.json")
            && validation.sha256 == SIXTH_VALIDATION
            && boot.path == state.join("bootstrap-intake.json"),
        "foreign sixth source validation or intake path"
    );
    let validation = validation.sealed()?;
    let boot = boot.sealed()?;
    let custody = binding(&boot["custody"])?;
    ensure!(
        custody.path == state.join("inputs/bootstrap-r2-custody.json") && custody.sha256 == CUSTODY,
        "foreign sixth custody path"
    );
    let custody = custody.sealed()?;
    let installed = state.join("payloads").join(BOOT);
    let metadata = fs::symlink_metadata(&installed)?;
    ensure!(
        assignment["schema"] == "foundation-epoch141-sixth-assignment-v1"
            && assignment["predecessor_handoff_sha256"] == THIRD.handoff
            && assignment["canonical_publication_authorized"] == false
            && inputs["schema"] == "foundation-epoch141-interval6-static-inputs-v1"
            && inputs["interval"] == assignment["interval"]
            && validation["interval"] == inputs["interval"]
            && validation["scope"]["sha256"] == SIXTH_SCOPE
            && validation["source_packet"]["sha256"] == SIXTH_SOURCE
            && validation["execution_packet"]["sha256"] == SIXTH_EXECUTION
            && validation["original_target_count"] == 309
            && boot["schema"] == "foundation-epoch141-interval6-private-object-intake-v1"
            && boot["pinned_authenticated_get"] == true
            && boot["single_physical_copy"] == true
            && boot["gcs_generation_checksums_match"] == true
            && boot["generation"] == 1_634_786_591_609_884u64
            && boot["installed_path"] == json!(installed)
            && boot["bytes"] == 2_529_738_702u64
            && boot["sha256"] == PAYLOAD
            && boot["remote_manifest_sha256"] == MANIFEST
            && boot["etag"] == ETAG
            && custody["bytes"] == boot["bytes"]
            && custody["source_packet"]["sha256"] == SIXTH_SOURCE
            && custody["sha256"] == PAYLOAD
            && custody["manifest_sha256"] == MANIFEST
            && custody["object_etag"] == ETAG
            && custody["object_key"] == format!("node_02/objects/{PAYLOAD}.blob")
            && custody["manifest_key"] == format!("node_02/manifests/{MANIFEST}.json")
            && custody["authenticated_post_readback"]["authenticated"] == true
            && custody["authenticated_post_readback"]["conditional_final_identity"] == true
            && boot["inode"] == metadata.ino()
            && boot["device"] == metadata.dev()
            && metadata.is_file()
            && metadata.len() == 2_529_738_702
            && metadata.uid() == 0
            && metadata.mode() & 0o222 == 0
            && metadata.nlink() == 1,
        "sixth interval lacks its exact verified bootstrap or execution scope"
    );
    Ok(())
}

fn turnover_after(
    fit: &Value,
    predecessor: &Scope,
    checkpoint_slot: u64,
    checkpoint_hash: &str,
    targets: u64,
) -> Result<()> {
    let prior = Path::new(predecessor.state);
    let terminal = binding(&fit["predecessor_terminal"])?;
    let drain = binding(&fit["predecessor_drain"])?;
    ensure!(
        terminal.path == prior.join("replay-terminal.json")
            && drain.path == prior.join("post-custody-drain.json"),
        "foreign predecessor predecessor evidence"
    );
    let terminal = terminal.sealed()?;
    let drain = drain.sealed()?;
    let launch = binding(&terminal["launch"])?;
    ensure!(
        launch.path == prior.join("replay-launch.json"),
        "foreign predecessor launch"
    );
    let launch = launch.sealed()?;
    let admission = binding(&launch["admission"])?;
    ensure!(
        admission.path == prior.join("replay-admission.json"),
        "foreign predecessor admission"
    );
    let third = admission.sealed()?;
    ensure!(
        third["handoff"]["sha256"] == predecessor.handoff
            && launch["unit"] == predecessor.unit
            && terminal["schema"]
                == format!(
                    "foundation-epoch141-interval{}-terminal-v1",
                    predecessor.ordinal
                )
            && terminal["invocation_id"] == launch["invocation_id"]
            && terminal["terminal_checkpoint"]["slot"] == checkpoint_slot
            && terminal["terminal_checkpoint"]["accounts_hash"] == checkpoint_hash
            && terminal["original_entry_slots_verified"] == targets
            && terminal["private_custody"]["no_clobber"] == true
            && drain["schema"]
                == format!(
                    "foundation-epoch141-interval{}-post-custody-drain-v1",
                    predecessor.ordinal
                )
            && drain["invocation_id"] == launch["invocation_id"]
            && drain["terminal"] == fit["predecessor_terminal"]
            && drain["container"] == terminal["private_custody"]["container"]
            && drain["guard_drained"] == true
            && drain["tmpfs_drained"] == true,
        "the assigned predecessor invocation has no verified output custody and drain"
    );

    Ok(())
}

fn seventh_evidence(state: &Path, fit: &Value) -> Result<()> {
    const BOOT: &str = "snapshot-60955832-B6F9ztw7sVcNeY2Sa1nKh9c2EpC5SjuVSLgoLTi4Zxo2.tar.zst";
    turnover_after(
        fit,
        &FIFTH,
        60_948_885,
        "2EsJDSWGzZUaPKtjefUMfFnE2TWAn8ba5hAvDZbGaFfa",
        307,
    )?;
    let inputs = binding(&fit["static_inputs"])?;
    let assignment = binding(&fit["handoff"])?;
    ensure!(
        inputs.path == state.join("static-inputs.json")
            && assignment.path == state.join("inputs/foundation-assignment.json")
            && assignment.sha256 == SEVENTH.handoff,
        "foreign seventh inputs or assignment"
    );
    let inputs = inputs.sealed()?;
    let assignment = assignment.sealed()?;
    let validation = binding(&inputs["source_validation"])?;
    let boot = binding(&inputs["bootstrap_intake"])?;
    let transfer = binding(&inputs["transfer_completion"])?;
    ensure!(
        validation.path == state.join("source-validation.json")
            && validation.sha256 == SEVENTH_VALIDATION
            && boot.path == state.join("bootstrap-intake.json")
            && transfer.path == state.join("transfer-completion.json"),
        "foreign seventh source validation or intake path"
    );
    let validation = validation.sealed()?;
    let boot = boot.sealed()?;
    let transfer = transfer.sealed()?;
    let custody = binding(&boot["custody"])?;
    ensure!(
        custody.path == state.join("inputs/bootstrap-r2-custody.json"),
        "foreign seventh custody path"
    );
    let custody = custody.sealed()?;
    let installed = state.join("payloads").join(BOOT);
    let metadata = fs::symlink_metadata(&installed)?;
    let payload = text(&boot, "sha256")?;
    let manifest = text(&boot, "remote_manifest_sha256")?;
    ensure!(
        assignment["schema"] == "foundation-epoch141-seventh-assignment-v1"
            && assignment["predecessor_handoff_sha256"] == FIFTH.handoff
            && assignment["canonical_publication_authorized"] == false
            && inputs["schema"] == "foundation-epoch141-interval7-static-inputs-v1"
            && inputs["interval"] == assignment["interval"]
            && validation["interval"] == inputs["interval"]
            && validation["scope"]["sha256"] == SEVENTH_SCOPE
            && validation["source_packet"]["sha256"] == SEVENTH_SOURCE
            && validation["execution_packet"]["sha256"] == SEVENTH_EXECUTION
            && validation["original_target_count"] == 304
            && transfer["schema"] == "foundation-epoch141-interval7-intake-completion-v1"
            && transfer["bootstrap"] == inputs["bootstrap_intake"]
            && transfer["handoff"] == fit["handoff"]
            && transfer["replay_launched"] == false
            && boot["schema"] == "foundation-epoch141-interval7-private-object-intake-v1"
            && boot["pinned_authenticated_get"] == true
            && boot["single_physical_copy"] == true
            && boot["gcs_generation_checksums_match"] == true
            && boot["generation"] == 1_634_786_592_035_540u64
            && boot["installed_path"] == json!(installed)
            && boot["bytes"] == 2_588_354_467u64
            && custody["bytes"] == boot["bytes"]
            && custody["sha256"] == payload
            && custody["manifest_sha256"] == manifest
            && custody["object_etag"] == boot["etag"]
            && custody["source_packet"]["sha256"] == SEVENTH_SOURCE
            && custody["object_key"] == format!("node_02/objects/{payload}.blob")
            && custody["manifest_key"] == format!("node_02/manifests/{manifest}.json")
            && custody["authenticated_post_readback"]["authenticated"] == true
            && custody["authenticated_post_readback"]["conditional_final_identity"] == true
            && boot["inode"] == metadata.ino()
            && boot["device"] == metadata.dev()
            && metadata.is_file()
            && metadata.len() == 2_588_354_467
            && metadata.uid() == 0
            && metadata.mode() & 0o222 == 0
            && metadata.nlink() == 1,
        "seventh interval lacks its exact verified bootstrap or execution scope"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sixth_candidate_refuses_both_live_predecessors_on_its_cpu_group() {
        for occupied in [SECOND.unit, THIRD.unit, SIXTH.unit] {
            let before = BTreeSet::from([occupied.to_owned()]);
            let error = candidate(6, &before).err().unwrap();
            assert_eq!(
                error.to_string(),
                "epoch 141 candidate overlaps a live owner"
            );
        }
    }
}
