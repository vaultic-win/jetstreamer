//! Bind the live Foundation cohort for replay funding and guard qualification.
use super::*;
mod allocation;
mod delivery252;
mod focused;
mod holding296;
mod restore266;
mod interval141;
mod replay256;
mod replay258;
mod replay260;
mod replay296;
use focused::{
    ADJACENT_230, FEATURE_296, FIRST_7871_230, GAP_230, HOURLY_230, LOADER_296, NEXT_V1627_230, OVERLAP_266,
    OVERLAP_266_EXCLUSIVE, PREDECESSOR_266, RESTORE_258, RESTORE_260, RETRY_NEXT_V1627_230, SCOPES, SECOND_HOURLY_230,
    WINDOW_266,
    TRACE_296, V1627_230,
};
mod suffix226;
mod vote_boundary;

struct AuxiliaryOwner {
    launch: Bound,
    owner: Value,
    memory: u64,
    ticks: u64,
}

const FLEET_ROOT: &str = "/home/ubuntu/.codex/diagnostics";
const FLEET_PREFIX: &str = "horizon-foundation-seven-lane-v";
const REPLAY_BOOKING: (&str, &str) = (
    "/var/lib/jetstreamer/horizon262-native-bootstrap-build-v1/cold-fit-v342.json",
    "9ff35b7b5902e65b23bf2e862692cce959948183fefd42537e2a9fa63107f36c",
);
const DELIVERY_BOOKING: (&str, &str) = (
    "/var/lib/jetstreamer/horizon257-current-reader-delivery-v2/booking.json",
    "fe90d6ab3c352bf4f6f903457b16edb48c8a10d1a836941df5c8aa9544f51d13",
);
const UPLOAD_257: &str = "horizon-upload-257-current-reader-v2.service";
const TERMINAL_UPLOAD_257: (&str, &str) = (
    "/var/lib/jetstreamer/horizon257-current-reader-delivery-v2/publication/completion.json",
    "ac5480340fabbafd8b80244ef95b7d3ad4a0ee1bbc51ad9bf5abb6de8bd29775",
);
const HANDOFF_UPLOAD_257: (&str, &str) = (
    "/var/lib/jetstreamer/horizon257-current-reader-delivery-v2/publication/handoff-intent.json",
    "be7f556c4871522139f33c1c16b678e34a3b2871d1e098c20300e52b311c3e2e",
);
const OWNER_FIELDS: &str = "Id,LoadState,ActiveState,SubState,InvocationID,MainPID,NRestarts,Result,Job,Restart,KillMode,Delegate,ControlGroup,MemoryMax,MemorySwapMax,ExecStart,AllowedCPUs";
const GUARD_FIELDS: &str =
    "Id,LoadState,ActiveState,SubState,InvocationID,Unit,MemoryMax,ExecStart";
const KNOWN_GUARDS: [(u64, &str); 10] = [
    (226, "horizon-guard-226-checkpoint-continuation-extract-v3"),
    (230, "horizon-230-middle-protective-v1"),
    (252, "horizon-252-regional-singleton-protective-v1"),
    (258, replay258::GUARD),
    (260, replay260::GUARD),
    (261, "horizon-261-singleton-protective-v1"),
    (262, "horizon-262-singleton-protective-v1"),
    (266, OVERLAP_266.guard),
    (288, "horizon-288-full-shrink-debt-protective-v1"),
    (296, "horizon-296-full-retry-protective-v1"),
];
const AUXILIARY: [&str; 2] = [
    BROKER_226,
    "foundation-public-audit-epoch148-256-cap1-v1.service",
];
const EXTRACT_226: &str = "horizon-qualify-226-checkpoint-continuation-extract-v3.service";
const BROKER_226: &str = "foundation-226-original225-broker-v3.service";
const GUARD_226: &str = "horizon-guard-226-checkpoint-continuation-extract-v3.service";
const TIMER_226: &str = "horizon-guard-226-checkpoint-continuation-extract-v3.timer";
const DRAIN_226: &str =
    "/var/lib/jetstreamer/horizon226-extract-v3/control/success-drain-completion.json";
const LAUNCH_226: (&str, &str) = (
    "/var/lib/jetstreamer/horizon226-extract-v3/fleet-launch.json",
    "30f1fd1a0009ff63c22f1aac39438caf570acaddfaf90bd656331e2895294df8",
);
const SUFFIX_226_ROOT: &str = "/var/lib/jetstreamer/horizon226-suffix-v1";
const SUFFIX_226_CAP: u64 = 160 << 30;
const REPLAY_230: &str = "horizon-qualify-230-middle-v1.service";
const TERMINAL_230: (&str, &str) = (
    "/var/lib/jetstreamer/horizon230-middle-fit-v1/terminal-execution-mismatch.json",
    "bd5e40f2c612b5e20cb9607379b2a8511983c4a7d9c71409ed3ed0fa3472882b",
);
const CADENCE_LOCK: &str =
    "/var/lib/jetstreamer/horizon-seven-publication-controller-v222/cycle.lock";
const STANDARD_GUARD: &str =
    "/var/lib/jetstreamer/horizon251-published-guard-20261118-v1/horizon251-standalone-guard";
const GUARD_288: &str = "/var/lib/jetstreamer/horizon288-shrink-debt-comparison-tools-v327/guard";
const GUARD_ENV_261: &str = "/var/lib/jetstreamer/horizon261-full-guard-v1/guard.env";
const GUARD_ENV_262: &str = "/var/lib/jetstreamer/horizon262-full-guard-v1/guard.env";
const GUARD_ENV_296: &str = "/var/lib/jetstreamer/horizon296-full-retry-guard-v1/guard.env";
const FULL_REPLAY_INPUTS: (&str, &str) = (
    "/var/lib/jetstreamer/horizon262-full-node-b9b95b02-v1/replay-inputs.json",
    "4375f4e590dc98d3f37ba6c646fa2c93cc65680267c7c920ba5d3255b67661d2",
);
const SIZING_REFERENCE: (&str, &str) = (
    "/var/lib/jetstreamer/horizon261-full-profile-v226-a1/profile.json",
    "6b27a27ff1596fe6688f207d460566c51d5c9552cef47817358d2008b484f281",
);
const FOUNDATION_RANGE_HANDOFF: (&str, &str) = (
    "/var/lib/jetstreamer/horizon262-foundation-roster-range-boundary-v399/roster.json",
    "5a8d5ec38bed4757a509eaca413b42de3c60c5144213a7b7e48ce8dadb6f2bd5",
);
const WITHDRAWN_AUDIT_INVOCATION: &str = "3375be6466ee4a8090e8e82e0fff5bcc";
const REPLAY_261: &str = "horizon-qualify-261-singleton-v1.service";
const GUARD_261: &str = "horizon-261-singleton-protective-v1.service";
const TIMER_261: &str = "horizon-261-singleton-protective-v1.timer";
const TERMINAL_261_COLLECTOR: (&str, &str) = (
    "/var/lib/jetstreamer/horizon261-cohort-commit-source-v1/horizon-epoch257-commit-source",
    "805646f57ba9b5262e17541e3f940390a5996138b4b4ddee4887915df0605499",
);
const DELIVERY_261_PREPARATION: (&str, &str) = (
    "/var/lib/jetstreamer/horizon261-current-reader-preparation-v1/preparation.json",
    "1d20967729c44e166611dd9df86e919b5ae0df4af337ed2d3cc0b5b4268d6a61",
);
const UPLOAD_261: &str = "horizon-upload-261-current-reader-v1.service";
const CLAIM_261: (&str, &str) = (
    "/var/lib/jetstreamer/horizon261-current-reader-delivery-v1/pipeline-claim.json",
    "c7082008cc50a19a622ac49de4f47f6fcf6d9f936625aca5b22a2b1d4337273a",
);
const UPLOAD_261_MEMORY: u64 = 64 << 30;
const UPLOAD_261_DISK: u64 = 1 << 30;
const REGISTERED_REPLAYS: [ReplayRegistration; 5] = [
    replay258::REGISTRATION,
    replay260::REGISTRATION,
    replay296::REGISTRATION,
    ReplayRegistration {
        epoch: 262,
        unit: "horizon-qualify-262-singleton-v1.service",
        receipt: (
            "/var/lib/jetstreamer/horizon262-full-guard-v1/cadence-registration.json",
            "1d509e8cf8217b6bff3d911cc340bb9d68b919450c5d29ab9a6f103c6581ca35",
        ),
        schema: "foundation-epoch262-replay-cadence-registration-v1",
        node_key: "replay_node",
        receipt_disk: 256 << 20,
    },
    ReplayRegistration {
        epoch: 296,
        unit: "horizon-qualify-296-full-retry-v1.service",
        receipt: (
            "/var/lib/jetstreamer/horizon296-full-retry-guard-v1/cadence-registration.json",
            "237a6a85b3325572e86f432b1277d7f1febbce80238adc94a6b604d623300164",
        ),
        schema: "foundation-epoch296-full-retry-cadence-registration-v1",
        node_key: "node",
        receipt_disk: 64 << 20,
    },
];
const RECOVERY_296: (&str, &str) = (
    "/var/lib/jetstreamer/horizon296-unbounded-worker-build-v1/full-fit-v341.json",
    "1fb5f9af69d405b32a0098bde182ac105e853b877572c7285eaf4be494453281",
);

struct FullReplayQuote {
    epoch: u64,
    reference: Bound,
    inputs: Bound,
    working_disk: u64,
    producer_memory: u64,
}

enum Quote {
    FullReplay(FullReplayQuote),
    Interval141(u8),
    Suffix226(Bound),
    Suffix226Preview,
    Delivery252,
    Delivery261(Bound),
    AdjacentIntake230(Bound),
    NextIntake266(Bound),
    SuccessorIntake266(Bound),
    Replay296(Replay296Quote),
    Focused(&'static focused::Focused, Bound),
}

const ADJACENT_230_SLOT: u64 = 99_445_304;
const ADJACENT_230_BYTES: u64 = 10_310_927_058;
const BOOTSTRAP_COPY_OVERHEAD: u64 = 16 << 20;
const BOOTSTRAP_COPY_MEMORY: u64 = 2 << 30;

fn adjacent_230_intake() -> Result<Bound> {
    let readiness = Bound::new(
        "/home/ubuntu/.jetstreamer-private/epoch230-adjacent-sources.20261127T221352Z.gZgDWf/adjacent-replay-readiness.json",
        "21c5f57015042eb21e7a38f7b54e73fd9efc87ab44bdb3bfa4790f6774060bc0",
    );
    let source = readiness.json()?;
    let route = &source["routes"][0];
    let metadata_ref = binding(&route["bootstrap_metadata"])?;
    let metadata = metadata_ref.json()?;
    ensure!(
        source["epoch"] == 230
            && source["publication_authorized"] == false
            && route["bootstrap_slot"] == ADJACENT_230_SLOT
            && route["first_slot"] == ADJACENT_230_SLOT + 1
            && route["last_slot"] == 99_461_591
            && route["bootstrap_payload_bytes"] == ADJACENT_230_BYTES
            && route["bootstrap_uri"] == metadata["storage_url"]
            && metadata["size"] == ADJACENT_230_BYTES
            && metadata["generation"] == "1633495970251676"
            && metadata["crc32c_hash"] == "5gcBCg=="
            && metadata["md5_hash"] == "M2BJKcmEIRupKTRT/LhO6Q==",
        "epoch 230 adjacent bootstrap metadata differs from the pinned copy"
    );
    Ok(readiness)
}

const NEXT_266_BOOTSTRAP: u64 = 114_929_697;
const NEXT_266_PAYLOAD: u64 = 15_514_070_431;
const NEXT_266_CPU: &str = "32";
const NEXT_266_EXCLUSIVE: &str = "32,96";
const NEXT_266_METADATA: (&str, &str) = (
    "/var/lib/jetstreamer/horizon266-next-input-metadata-v1/gcs-metadata.json",
    "1403b662c15e1d33b558f77c4f2e7da18b268b005b0ea23d684b57001bb34008",
);

fn next_266_intake() -> Result<Bound> {
    let seam_ref = Bound::new(
        "/var/lib/jetstreamer/horizon266-boundary-account-proof-runtime-v1/private-seam.json",
        "4abaa6a0a424ba2befb221dde64ed8afc107df66e474c5ca5542007c8507dadd",
    );
    let seam = seam_ref.sealed()?;
    let following = binding(&seam["following_terminal"])?.sealed()?;
    let metadata = Bound::new(NEXT_266_METADATA.0, NEXT_266_METADATA.1)
        .sealed()
        .context("read the sealed epoch 266 bootstrap metadata")?;
    let name = "114910768/hourly/snapshot-114929697-BevfHbX1MRE8ySXdbzp8WZB5i4W1spPhbsZ8UEUhU7di.tar.zst";
    let bucket = "mainnet-beta-ledger-us-ny5";
    let generation = "1641767198731933";
    ensure!(
        seam["schema"] == "foundation-epoch266-private-predecessor-overlap-seam-v1"
            && seam["epoch"] == 266
            && seam["publication_authorized"] == false
            && seam["covered_slots"] == json!([114_912_000, NEXT_266_BOOTSTRAP])
            && seam["first_uncovered_slot"] == NEXT_266_BOOTSTRAP + 1
            && following["schema"] == "foundation-epoch266-private-overlap-terminal-evidence-v1"
            && following["producer_drained"] == true
            && following["native_manifest_complete_verified"] == true
            && following["terminal_checkpoint"]["slot"] == NEXT_266_BOOTSTRAP
            && following["terminal_checkpoint"]["accounts_hash"] == "BevfHbX1MRE8ySXdbzp8WZB5i4W1spPhbsZ8UEUhU7di"
            && metadata["bucket"] == bucket && metadata["name"] == name
            && metadata["generation"] == generation
            && metadata["storage_url"] == format!("gs://{bucket}/{name}#{generation}")
            && metadata["size"] == NEXT_266_PAYLOAD && metadata["crc32c_hash"] == "exIgJw=="
            && metadata["md5_hash"] == "8VhGHIp7ijX7haXULetQ0A==" && metadata["etag"] == "CJ3dvLXbpfUCEAE=",
        "epoch 266 next bootstrap metadata differs from the verified private handoff"
    );
    Ok(seam_ref)
}

const SUCCESSOR_266_BOOTSTRAP: u64 = 114_936_474;
const SUCCESSOR_266_LAST: u64 = 114_943_135;
const SUCCESSOR_266_PAYLOAD: u64 = 15_568_220_095;
const SUCCESSOR_266_SOURCE: (&str, &str) = (
    "/var/lib/jetstreamer/horizon266-window-114936475-114943135-sources-v1/source-window.json",
    "7da6654f186299cd5911e89ecd84c026c87562c4e95d801d9cffab611529b36a",
);
const SUCCESSOR_266_METADATA: (&str, &str) = (
    "/var/lib/jetstreamer/horizon266-window-114936475-114943135-sources-v1/bootstrap-114936474.json",
    "dda3aa43c81acbfb39a11421fda9f0610440f18e005b0e95818919a40dae9f75",
);

fn successor_266_intake() -> Result<Bound> {
    let source_ref = Bound::new(SUCCESSOR_266_SOURCE.0, SUCCESSOR_266_SOURCE.1);
    let source = source_ref.sealed()?;
    let metadata_ref = Bound::new(SUCCESSOR_266_METADATA.0, SUCCESSOR_266_METADATA.1);
    let metadata = metadata_ref.sealed()?;
    let terminal_ref = binding(&source["predecessor_terminal"])?;
    let terminal = terminal_ref.sealed()?;
    let drain = binding(&source["predecessor_drain"])?.sealed()?;
    ensure!(
        source["schema"] == "foundation-epoch266-contiguous-private-window-source-v1"
            && source["epoch"] == 266
            && source["bootstrap_slot"] == SUCCESSOR_266_BOOTSTRAP
            && source["first_slot"] == SUCCESSOR_266_BOOTSTRAP + 1
            && source["last_slot"] == SUCCESSOR_266_LAST
            && source["slot_positions"] == SUCCESSOR_266_LAST - SUCCESSOR_266_BOOTSTRAP
            && source["original_epoch_root_still_required"] == true
            && source["publication_authorized"] == false
            && source["bootstrap_metadata"] == json!(metadata_ref)
            && source["bootstrap_generation"] == 1_641_767_207_323_715_u64
            && source["terminal_generation"] == 1_641_767_202_392_427_u64
            && drain["native_terminal"] == json!(terminal_ref)
            && drain["guard_drained"] == true && drain["state"] == "local-segment-committed"
            && terminal["invocation_id"] == drain["invocation_id"]
            && terminal["producer_drained"] == true
            && terminal["native_manifest_complete_verified"] == true
            && terminal["terminal_checkpoint"]["slot"] == SUCCESSOR_266_BOOTSTRAP
            && terminal["terminal_checkpoint"]["accounts_hash"] == "GqAWTNQiWMCFTZLC1N3SXe2NmykFDcMQdn4Saj4ALSCA"
            && metadata["bucket"] == "mainnet-beta-ledger-us-ny5"
            && metadata["name"] == "114910768/hourly/snapshot-114936474-GqAWTNQiWMCFTZLC1N3SXe2NmykFDcMQdn4Saj4ALSCA.tar.zst"
            && metadata["generation"] == "1641767207323715"
            && metadata["size"] == SUCCESSOR_266_PAYLOAD
            && metadata["crc32c_hash"] == "6Y4RtQ==" && metadata["md5_hash"] == "/rST1KqnZcalFjgY/Dz72A=="
            && metadata["etag"] == "CMOQybnbpfUCEAE=",
        "epoch 266 successor intake differs from its verified window and pinned source"
    );
    Ok(source_ref)
}

struct Replay296Quote {
    placement: replay296::Placement,
    prior_fit: Bound,
    worker: Bound,
    checkpoint: Bound,
    disk: u64,
    memory: u64,
}

struct ReplayRegistration {
    epoch: u64,
    unit: &'static str,
    receipt: (&'static str, &'static str),
    schema: &'static str,
    node_key: &'static str,
    receipt_disk: u64,
}

struct LiveReplay {
    reference: Bound,
    unit: &'static str,
    owner: Value,
    memory: u64,
    ticks: u64,
    guard_booking: Value,
    receipt_disk: u64,
}

fn full_replay_quote() -> Result<FullReplayQuote> {
    let reference = Bound::new(SIZING_REFERENCE.0, SIZING_REFERENCE.1);
    let profile = reference.sealed()?;
    let inputs = Bound::new(FULL_REPLAY_INPUTS.0, FULL_REPLAY_INPUTS.1);
    let plan = inputs.sealed()?;
    let terminal = binding(&plan["native_bootstrap_terminal"])?.sealed()?;
    ensure!(
        plan["schema"] == "foundation-epoch262-full-replay-input-envelope-v1"
            && plan["epoch"] == EPOCH
            && plan["full_replay_admitted"] == false
            && terminal["epoch"] == EPOCH
            && terminal["native_input_qualified"] == true
            && profile["unit"] == REPLAY_261,
        "epoch 262 full-replay quote inputs changed"
    );
    binding(&plan["replay_node"])?.artifact()?;
    Ok(FullReplayQuote {
        epoch: EPOCH,
        reference,
        inputs,
        working_disk: num(&profile, "maximum_root_physical_bytes")?,
        producer_memory: num(&profile, "maximum_memory_bytes")?,
    })
}

fn replay_296_quote(n: &mut Native) -> Result<Replay296Quote> {
    let placement = replay296::placement()?;
    replay296::verify_topology(&placement)?;
    let (worker, checkpoint) = focused::feature_296_terminal(n)?;
    let prior_fit = Bound::new(RECOVERY_296.0, RECOVERY_296.1);
    let prior = prior_fit.sealed()?;
    let sizing = binding(&prior["earlier_full_booking"])?.sealed()?;
    let sizing = &sizing["quote"];
    let disk = num(&prior, "required_disk_bytes")?;
    let memory = num(&prior, "required_memory_bytes")?;
    ensure!(
        prior["epoch"] == 296
            && prior["replay_admitted"] == false
            && disk
                == capacity::add(
                    num(sizing, "maximum_whole_tree_bytes")?,
                    num(sizing, "staging_reserve_bytes")?
                )?
            && memory
                == capacity::add(
                    num(sizing, "memory_max_bytes")?,
                    num(sizing, "guard_memory_bytes")?
                )?,
        "epoch 296 replay sizing or worker evidence changed"
    );
    Ok(Replay296Quote {
        placement,
        prior_fit,
        worker,
        checkpoint,
        disk,
        memory,
    })
}

fn withdrawn_audit(n: &mut Native, booking: &Value) -> Result<Bound> {
    let reference = Bound::new(FOUNDATION_RANGE_HANDOFF.0, FOUNDATION_RANGE_HANDOFF.1);
    let handoff = reference.sealed()?;
    let unit = AUXILIARY[1];
    let reservation = &booking["owners"][unit];
    let owners = handoff["owners"].as_object().context("range handoff owners")?;
    let guards = handoff["periodic_guards"].as_object().context("range handoff guards")?;
    ensure!(
        handoff["schema"] == "foundation-epoch226-suffix-roster-binding-v1"
            && handoff["booking"] == json!(Bound::new(REPLAY_BOOKING.0, REPLAY_BOOKING.1))
            && !owners.contains_key(unit)
            && !guards.contains_key("148")
            && reservation["Id"] == unit
            && reservation["InvocationID"] == WITHDRAWN_AUDIT_INVOCATION
            && reservation["ControlGroup"] == format!("/system.slice/{unit}")
            && reservation["MemoryMax"] == "17179869184",
        "withdrawn auxiliary differs from the original booking or Foundation range handoff"
    );
    let current = n.show_fields(
        unit,
        "Id,LoadState,ActiveState,SubState,InvocationID,MainPID,ControlPID,ControlGroup,Job,NRestarts,Triggers,TriggeredBy",
    )?;
    let cgroup = Path::new("/sys/fs/cgroup/system.slice").join(unit);
    check_withdrawn_audit(&current, cgroup.try_exists()?)?;
    Ok(reference)
}

fn check_withdrawn_audit(current: &Value, cgroup_present: bool) -> Result<()> {
    ensure!(
        current["Id"] == AUXILIARY[1]
            && matches!(current["LoadState"].as_str(), Some("loaded" | "not-found"))
            && current["ActiveState"] == "inactive"
            && current["SubState"] == "dead"
            && matches!(current["InvocationID"].as_str(), Some("" | WITHDRAWN_AUDIT_INVOCATION))
            && current["MainPID"] == "0"
            && current["ControlPID"] == "0"
            && current["NRestarts"] == "0"
            && current["Job"] == ""
            && current["ControlGroup"] == ""
            && current["Triggers"] == ""
            && current["TriggeredBy"] == ""
            && !cgroup_present,
        "withdrawn auxiliary still has a process, cgroup, trigger, job, or changed identity"
    );
    Ok(())
}

fn delivery_261_preparation() -> Result<Bound> {
    let reference = Bound::new(DELIVERY_261_PREPARATION.0, DELIVERY_261_PREPARATION.1);
    let preparation = reference.sealed()?;
    let reader_plan = binding(&preparation["reader_plan"])?.sealed()?;
    ensure!(
        preparation["schema"] == "foundation-epoch261-current-reader-preparation-v1"
            && preparation["epoch"] == 261
            && preparation["publication_authorized"] == false
            && reader_plan["schema"] == "horizon-current-reader-plan-v1"
            && reader_plan["threads"] == 8
            && preparation["independent_boundary"] == reader_plan["epoch_expectations"]["261"],
        "epoch 261 delivery preparation changed"
    );
    binding(&preparation["uploader"])?.artifact()?;
    Ok(reference)
}

fn live_delivery(n: &mut Native, epoch: u64) -> Result<(Bound, Value, u64, u64)> {
    let (unit, reference) = match epoch {
        252 => (
            delivery252::UPLOADER,
            Bound::new(delivery252::CLAIM, hash(Path::new(delivery252::CLAIM))?),
        ),
        261 => (UPLOAD_261, Bound::new(CLAIM_261.0, CLAIM_261.1)),
        _ => bail!("unsupported current-reader delivery epoch {epoch}"),
    };
    let claim = reference.sealed()?;
    let evidence = claim["evidence"]
        .as_array()
        .context("current-reader delivery evidence")?;
    ensure!(evidence.len() == 2, "epoch {epoch} delivery evidence count");
    let booking_ref = binding(&evidence[0])?;
    let booking = booking_ref.sealed()?;
    let launch_ref = binding(&evidence[1])?;
    let launch = launch_ref.sealed()?;
    let booked_fit = binding(&booking["storage_quote"])?.sealed()?;
    let owner = n.show_fields(unit, OWNER_FIELDS)?;
    let launched = &launch["owner"];
    let invocation = text(&claim, "invocation_id")?;
    let pid = text(&owner, "MainPID")?.parse()?;
    let ticks = process_ticks(pid)?;
    ensure!(
        claim["epoch"] == epoch
            && claim["unit"] == unit
            && claim["phase"] == "upload-readback"
            && booking["schema"] == format!("foundation-epoch{epoch}-delivery-booking-v1")
            && booking["epoch"] == epoch
            && booking["unit"] == unit
            && booking["staging_copy_required"] == false
            && booked_fit["capacity"]["fits"] == true
            && booked_fit["capacity"]["candidate_disk_bytes"] == UPLOAD_261_DISK
            && booked_fit["delivery_quote"]["delivery_memory_max_bytes"] == UPLOAD_261_MEMORY
            && launch["schema"]
                == format!("foundation-epoch{epoch}-current-reader-delivery-launch-v1")
            && (epoch == 261
                || (booking_ref.path == reference.path.with_file_name("booking.json")
                    && launch_ref.path == reference.path.with_file_name("launch.json")))
            && binding(&launch["booking"])? == booking_ref
            && launch["process_start_ticks"] == ticks
            && owner["AllowedCPUs"] == "24-31"
            && owner["ExecStart"] == claim["expected_exec_start"],
        "epoch {epoch} delivery booking or live invocation changed"
    );
    for field in [
        "Id",
        "InvocationID",
        "MainPID",
        "ControlGroup",
        "AllowedCPUs",
        "MemoryMax",
        "ExecStart",
    ] {
        ensure!(
            owner[field] == launched[field],
            "epoch {epoch} delivery changed {field}"
        );
    }
    let memory = live::finite_owner(&owner, unit, invocation, UPLOAD_261_MEMORY)?;
    Ok((reference, owner, memory, ticks))
}

fn live_replay(n: &mut Native, spec: &ReplayRegistration) -> Result<LiveReplay> {
    let ReplayRegistration {
        epoch,
        unit,
        receipt,
        schema,
        node_key,
        receipt_disk,
    } = *spec;
    let reference = if receipt.1.is_empty() {
        let path = Path::new(receipt.0);
        trusted_parents(path)?;
        Bound::new(path, hash(path)?)
    } else {
        Bound::new(receipt.0, receipt.1)
    };
    let registered = reference.sealed()?;
    let profile_ref = binding(&registered["profile"])?;
    let profile = profile_ref.sealed()?;
    let admission = binding(&registered["admission"])?.sealed()?;
    let handoff = binding(&registered["handoff"])?.sealed()?;
    let admitted_fit = binding(&admission["roster"])?.sealed()?;
    let (node, root, cap, memory_cap, cpus) = if unit == replay296::UNIT {
        replay296::check_live_binding(
            n,
            &registered,
            &admission,
            &admitted_fit,
            &profile_ref,
            &profile,
        )?;
        (
            binding(&profile["node"])?,
            &profile["run_root"],
            num(&profile["requested_cap"], "whole_tree_bytes")?,
            num(&profile["requested_cap"], "producer_memory_bytes")?,
            replay296::CPUS,
        )
    } else {
        let inputs_ref = binding(&profile["inputs"])?;
        match epoch {
            replay258::EPOCH => replay258::check_live_binding(
                &registered,
                &profile,
                &admission,
                &admitted_fit,
                &inputs_ref,
            )?,
            replay260::EPOCH => {
                replay260::check_live_binding(&registered, &admission, &admitted_fit, &inputs_ref)?
            }
            _ => {}
        }
        let inputs = inputs_ref.sealed()?;
        let node = binding(if epoch == replay258::EPOCH {
            &inputs["inputs"][node_key]
        } else {
            &inputs[node_key]
        })?;
        (
            node,
            &profile["worker_root"],
            num(&profile, "maximum_root_physical_bytes")?,
            num(&profile, "maximum_memory_bytes")?,
            text(&profile, "allowed_cpus")?,
        )
    };
    node.artifact()?;
    let owner = n.show_fields(unit, OWNER_FIELDS)?;
    let invocation = text(&registered, "invocation_id")?;
    let pid: u64 = text(&owner, "MainPID")?.parse()?;
    let ticks = process_ticks(pid)?;
    let running = fs::metadata(format!("/proc/{pid}/exe"))?;
    let sealed = fs::metadata(&node.path)?;
    let sample_ref = binding(&registered["active_guard"])?;
    let sample = sample_ref.json()?;
    let guard_plan_ref = Bound::new(text(&sample, "plan")?, text(&sample, "plan_sha256")?);
    let guard_plan = guard_plan_ref.sealed()?;
    if unit == replay296::UNIT {
        let cg = Path::new("/sys/fs/cgroup/system.slice").join(unit);
        ensure!(
            units::parse_cpu_list(&fs::read_to_string(cg.join("cpuset.cpus.effective"))?)?
                == units::parse_cpu_list(replay296::CPUS)?,
            "epoch 296 effective producer CPUs changed"
        );
        let argv = profile["argv"]
            .as_array()
            .context("epoch 296 replay arguments")?;
        let mut expected_argv = Vec::new();
        for argument in argv {
            expected_argv
                .extend_from_slice(argument.as_str().context("epoch 296 argument")?.as_bytes());
            expected_argv.push(0);
        }
        ensure!(
            fs::read(format!("/proc/{pid}/cmdline"))? == expected_argv
                && handoff["admission"] == registered["admission"]
                && handoff["guard_plan"] == json!(guard_plan_ref),
            "epoch 296 replay command or handoff differs from the bound invocation"
        );
    }
    let floor = num(&admission, "guard_minimum_free_bytes")?;
    ensure!(
        registered["schema"] == schema
            && registered["epoch"] == epoch
            && registered["unit"] == unit
            && registered["main_pid"] == pid
            && registered["run_root"] == *root
            && registered["run_root"] == guard_plan["worker_root"]
            && handoff["ready"] == false
            && handoff["producer"] == unit
            && handoff["invocation_id"] == invocation
            && admission["schema"] == format!("foundation-epoch{epoch}-full-replay-admission-v1")
            && admission["epoch"] == epoch
            && admission["publication_authorized"] == false
            && admitted_fit["capacity"]["guard_floor_bytes"] == floor
            && admitted_fit["capacity"]["fits"] == true
            && admitted_fit["capacity"]["candidate_disk_bytes"]
                == capacity::add(cap, receipt_disk)?
            && admitted_fit["capacity"]["candidate_total_memory_bytes"]
                == capacity::add(memory_cap, capacity::add(CONTROLLER_MEMORY, 1 << 30)?)?
            && owner["AllowedCPUs"] == cpus
            && (running.dev(), running.ino()) == (sealed.dev(), sealed.ino()),
        "epoch {epoch} replay booking or live invocation changed"
    );
    let memory = live::finite_owner(&owner, unit, invocation, memory_cap)?;
    Ok(LiveReplay {
        reference,
        unit,
        owner,
        memory,
        ticks,
        guard_booking: json!({"sample":sample_ref,"floor_bytes":floor,"cap_bytes":cap}),
        receipt_disk,
    })
}

fn latest_completion() -> Result<Bound> {
    let mut latest = None;
    for entry in fs::read_dir(FLEET_ROOT)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(generation) = name
            .to_str()
            .and_then(|name| name.strip_prefix(FLEET_PREFIX))
        else {
            continue;
        };
        let Ok(generation) = generation.parse::<u64>() else {
            continue;
        };
        let completion = entry.path().join("completion.json");
        if completion.try_exists()? && latest.as_ref().is_none_or(|(last, _)| generation > *last) {
            latest = Some((generation, completion));
        }
    }
    let (_, path) = latest.context("Foundation cadence has no accepted fleet")?;
    Ok(Bound::new(&path, hash(&path)?))
}

fn replay_261_guard_drained(n: &mut Native) -> Result<()> {
    let timer = n.show_fields(TIMER_261, "ActiveState,Job")?;
    let service = n.show_fields(GUARD_261, "ActiveState,MainPID,ControlGroup,Job")?;
    ensure!(
        timer["ActiveState"] == "inactive"
            && timer["Job"] == ""
            && matches!(service["ActiveState"].as_str(), Some("inactive" | "failed"))
            && service["MainPID"] == "0"
            && service["ControlGroup"] == ""
            && service["Job"] == "",
        "epoch 261 protective timer and service have not drained"
    );
    Ok(())
}

fn terminal_replay_261(n: &mut Native, booking: &Value) -> Result<Option<Value>> {
    let current = n.show_fields(REPLAY_261, "ActiveState")?;
    if current["ActiveState"] == "active" {
        return Ok(None);
    }
    let collector = Bound::new(TERMINAL_261_COLLECTOR.0, TERMINAL_261_COLLECTOR.1);
    collector.artifact()?;
    let terminal: Value =
        serde_json::from_slice(&n.run(TERMINAL_261_COLLECTOR.0, &["--epoch261"])?)?;
    collector.artifact()?;
    ensure!(
        terminal["schema"] == "foundation-epoch261-committed-cohort-source-v1"
            && terminal["state"] == "local-cohort-committed"
            && terminal["epoch"] == 261
            && terminal["unit"] == REPLAY_261
            && terminal["invocation_id"] == booking["owners"][REPLAY_261]["InvocationID"]
            && terminal["publication_authorized"] == false,
        "epoch 261 terminal does not match the booked replay"
    );
    replay_261_guard_drained(n)?;
    Ok(Some(json!({"collector":collector,"terminal":terminal})))
}

fn terminal_extract_226(n: &mut Native, booking: &Value, proof: &Bound) -> Result<()> {
    ensure!(
        proof.path == Path::new(DRAIN_226),
        "foreign extraction drain"
    );
    let terminal = proof.sealed()?;
    let launch_ref = Bound::new(LAUNCH_226.0, LAUNCH_226.1);
    let launch = launch_ref.sealed()?;
    let handoff = binding(&terminal["handoff"])?.sealed()?;
    ensure!(
        terminal["schema"] == "foundation-epoch226-extraction-success-drain-v1"
            && terminal["epoch"] == 226
            && terminal["prefix_retained"] == true
            && terminal["suffix_started"] == false
            && terminal["producer"]["Id"] == EXTRACT_226
            && terminal["producer"]["Result"] == "success"
            && terminal["after"]["broker"]["Id"] == BROKER_226
            && handoff["launch"] == json!(launch_ref)
            && launch["invocation_id"] == booking["owners"][EXTRACT_226]["InvocationID"]
            && launch["broker_invocation_id"] == booking["owners"][BROKER_226]["InvocationID"],
        "epoch 226 drain is outside the booked extraction"
    );
    let timer = n.show_fields(TIMER_226, "ActiveState,Job")?;
    ensure!(
        timer["ActiveState"] == "inactive" && timer["Job"] == "",
        "epoch 226 extraction timer has not drained"
    );
    for unit in [EXTRACT_226, BROKER_226, GUARD_226] {
        let state = n.show_fields(
            unit,
            "ActiveState,MainPID,ControlPID,ControlGroup,Job,InvocationID,Result",
        )?;
        ensure!(
            matches!(state["ActiveState"].as_str(), Some("inactive" | "failed"))
                && state["MainPID"] == "0"
                && state["ControlPID"] == "0"
                && state["ControlGroup"] == ""
                && state["Job"] == ""
                && !Path::new("/sys/fs/cgroup/system.slice").join(unit).exists(),
            "epoch 226 extraction owner {unit} has not drained"
        );
        if unit == EXTRACT_226 || unit == BROKER_226 {
            ensure!(
                state["InvocationID"] == ""
                    || state["InvocationID"] == booking["owners"][unit]["InvocationID"],
                "epoch 226 extraction owner {unit} was replaced"
            );
        }
    }
    Ok(())
}

fn terminal_replay_230(n: &mut Native, booking: &Value) -> Result<Option<Bound>> {
    let producer = n.show_fields(
        REPLAY_230,
        "ActiveState,InvocationID,MainPID,ControlGroup,Job,NRestarts,Result,ExecMainStatus",
    )?;
    if producer["ActiveState"] == "active" {
        return Ok(None);
    }
    let proof = Bound::new(TERMINAL_230.0, TERMINAL_230.1);
    let closed = proof.sealed()?;
    let invocation = &booking["owners"][REPLAY_230]["InvocationID"];
    let timer = n.show_fields("horizon-230-middle-protective-v1.timer", "ActiveState,Job")?;
    let guard = n.show_fields(
        "horizon-230-middle-protective-v1.service",
        "ActiveState,MainPID,ControlGroup,Job",
    )?;
    ensure!(
        closed["schema"] == "foundation-epoch230-middle-execution-mismatch-terminal-v1"
            && closed["epoch"] == 230
            && closed["producer"]["Id"] == REPLAY_230
            && &closed["producer"]["InvocationID"] == invocation
            && &closed["manager_event"]["INVOCATION_ID"] == invocation
            && closed["diagnostics_retained"] == true
            && closed["physical_reclamation_bytes"] == 0
            && producer["ActiveState"] == "failed"
            && &producer["InvocationID"] == invocation
            && producer["Result"] == "exit-code"
            && producer["ExecMainStatus"] == "1"
            && producer["MainPID"] == "0"
            && producer["ControlGroup"] == ""
            && producer["Job"] == ""
            && producer["NRestarts"] == "0"
            && timer["ActiveState"] == "inactive"
            && timer["Job"] == ""
            && matches!(guard["ActiveState"].as_str(), Some("inactive" | "failed"))
            && guard["MainPID"] == "0"
            && guard["ControlGroup"] == ""
            && guard["Job"] == "",
        "epoch 230 failed replay and protective guard do not match the recorded drain"
    );
    Ok(Some(proof))
}

// A producer can finish between the accepted observation and a new admission.
// Credit only this exact, closed diagnostic on the original observation's chain.
fn drain_first_7871(n: &mut Native, fleet: &mut Value) -> Result<Option<Bound>> {
    const TERMINAL: (&str, &str) = (
        "/var/lib/jetstreamer/horizon230-first-7871-runtime-v1/terminal.json",
        "16d546332a37fccd20a7b2609908288b426276a01908c6e255db886aba6ea8d2",
    );
    const REGISTRATION: (&str, &str) = (
        "/var/lib/jetstreamer/horizon230-first-7871-runtime-v1/cadence-registration.json",
        "837bca79f370c14e6345fa1f36af77ec43e8575c111bdacbfab111b1a96d7b0e",
    );
    const IID: &str = "02b7dd1683d24efbabf6b5c2f8ff6a43";
    let rows = fleet["active"].as_array_mut().context("Foundation active roster")?;
    let Some(index) = rows.iter().position(|row| {
        row["epoch"] == 230 && row["producer"]["Id"] == FIRST_7871_230.unit
    }) else {
        return Ok(None);
    };
    if !Path::new(TERMINAL.0).try_exists()? {
        return Ok(None);
    }
    let terminal_ref = Bound::new(TERMINAL.0, TERMINAL.1);
    let terminal = terminal_ref.sealed()?;
    let row = &rows[index];
    let invocation = &row["producer"]["InvocationID"];
    ensure!(
        row["phase"] == "diagnostic-qualification"
            && invocation == IID
            && row["launch_receipt"] == REGISTRATION.0
            && row["launch_receipt_sha256"] == REGISTRATION.1
            && terminal["schema"] == "foundation-epoch230-first-7871-terminal-v1"
            && terminal["unit"] == FIRST_7871_230.unit
            && terminal["invocation_id"] == IID
            && terminal["manager_event"]["INVOCATION_ID"] == IID
            && terminal["state"] == "local-segment-committed"
            && terminal["guard_drained"] == true
            && terminal["first_slot"] == 99_437_434_u64
            && terminal["last_slot"] == 99_445_304_u64
            && terminal["archive"]["independent_sha256"]
                == terminal["archive"]["native_sha256"],
        "the epoch 230 terminal phase does not bind the sampled producer"
    );
    let archived = &terminal["archive"];
    let path = Path::new(text(archived, "path")?);
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file()
            && metadata.len() == num(&archived["identity"], "length")?
            && metadata.ino() == num(&archived["identity"], "inode")?
            && metadata.dev() == num(&archived["identity"], "device")?,
        "the retained epoch 230 segment changed after terminal verification"
    );
    let fields = "ActiveState,InvocationID,MainPID,ControlPID,ControlGroup,Job";
    let producer = n.show_fields(FIRST_7871_230.unit, fields)?;
    let guard = n.show_fields(FIRST_7871_230.guard, fields)?;
    let timer = format!("{}.timer", FIRST_7871_230.guard.trim_end_matches(".service"));
    let timer = n.show_fields(&timer, "ActiveState,Job")?;
    for (name, state) in [(FIRST_7871_230.unit, &producer), (FIRST_7871_230.guard, &guard)] {
        ensure!(
            matches!(state["ActiveState"].as_str(), Some("inactive" | "failed"))
                && state["MainPID"] == "0"
                && state["ControlPID"] == "0"
                && state["ControlGroup"] == ""
                && state["Job"] == ""
                && !Path::new("/sys/fs/cgroup/system.slice").join(name).try_exists()?,
            "the closed epoch 230 scope still has a live unit or cgroup: {name}"
        );
    }
    ensure!(
        producer["ActiveState"] == "inactive"
            && matches!(producer["InvocationID"].as_str(), Some("" | IID))
            && timer["ActiveState"] == "inactive"
            && timer["Job"] == "",
        "the recorded epoch 230 producer or timer changed"
    );
    rows.remove(index);
    Ok(Some(terminal_ref))
}

fn terminal_delivery_257(n: &mut Native, booking: &Value, fleet: &Value) -> Result<Option<Bound>> {
    let state = n.show_fields(
        UPLOAD_257,
        "ActiveState,InvocationID,MainPID,ControlPID,ControlGroup,Job,NRestarts,Result",
    )?;
    if state["ActiveState"] == "active" {
        return Ok(None);
    }
    let terminal = Bound::new(TERMINAL_UPLOAD_257.0, TERMINAL_UPLOAD_257.1);
    if !terminal.path.try_exists()? {
        return Ok(None);
    }
    let completion = terminal.sealed()?;
    let claim = binding(&completion["claim"])?.sealed()?;
    let handoff = Bound::new(HANDOFF_UPLOAD_257.0, HANDOFF_UPLOAD_257.1).sealed()?;
    let finished = &handoff["terminal"]["finished"];
    // The uploader and status verifier write root-private 0600 receipts.
    let archive = binding(&completion["archive"])?.json()?;
    let deletion = binding(&completion["deletion"])?.json()?;
    let invocation = text(&booking["owners"][UPLOAD_257], "InvocationID")?;
    let entry = fleet["inventory"]["entries"]
        .as_array()
        .context("Foundation inventory")?
        .iter()
        .find(|row| row["epoch"] == 257)
        .context("missing epoch 257 inventory row")?;
    ensure!(
        state["ActiveState"] == "inactive"
            && matches!(state["InvocationID"].as_str(), Some(id) if id.is_empty() || id == invocation)
            && state["MainPID"] == "0"
            && state["ControlPID"] == "0"
            && state["ControlGroup"] == ""
            && state["Job"] == ""
            && state["NRestarts"] == "0"
            && state["Result"] == "success"
            && !Path::new("/sys/fs/cgroup/system.slice")
                .join(UPLOAD_257)
                .exists(),
        "epoch 257 delivery owner has not drained"
    );
    ensure!(
        completion["ready"] == true
            && completion["capacity_released"] == false
            && completion["local_retirement_authorized"] == false
            && claim["epoch"] == 257
            && claim["unit"] == UPLOAD_257
            && claim["invocation_id"] == invocation
            && handoff["claim"] == completion["claim"]
            && handoff["archive"] == completion["archive"]
            && finished["UNIT"] == UPLOAD_257
            && finished["INVOCATION_ID"] == invocation
            && finished["_PID"] == "1"
            && finished["_UID"] == "0"
            && finished["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448"
            && archive["epoch"] == 257
            && archive["remote_sha256_readback"] == true
            && deletion["binding"]["archive_receipt"] == completion["archive"]
            && deletion["authenticated_ready_pair_after"] == true
            && deletion["authenticated_status_absent_after"] == true
            && entry["state"] == "ready-pair"
            && entry["archive_length"] == archive["archive_length"]
            && entry["archive_etag"] == archive["archive_etag"]
            && entry["archive_metadata_sha256"] == archive["archive_sha256"]
            && entry["sidecar_sha256"] == archive["archive_sha256"],
        "epoch 257 completion does not match the booked upload and ready pair"
    );
    Ok(Some(terminal))
}

fn fleet_roster<'a>(
    fleet: &'a Value,
    booking: &Value,
    released: &BTreeMap<u64, &str>,
    deliveries: &BTreeMap<u64, (Bound, Value, u64, u64)>,
    live_replays: &BTreeMap<u64, LiveReplay>,
) -> Result<BTreeMap<u64, &'a Value>> {
    let rows = fleet["active"]
        .as_array()
        .context("Foundation active roster")?;
    let booked = booking["owners"]
        .as_object()
        .context("Foundation booked owners")?;
    let mut roster = BTreeMap::new();
    let mut observed_deliveries = BTreeSet::new();
    let mut observed_replays = BTreeSet::new();
    for row in rows {
        let epoch = num(row, "epoch")?;
        if matches!(epoch, 252 | 261) && row["phase"] == "upload-readback" {
            let (_, owner, _, _) = deliveries
                .get(&epoch)
                .with_context(|| format!("unbooked epoch {epoch} delivery in fleet"))?;
            ensure!(
                observed_deliveries.insert(epoch),
                "duplicate epoch {epoch} delivery in fleet"
            );
            live::same_owner(&row["unit"], owner)?;
            continue;
        }
        if let Some(replay) = live_replays.get(&epoch) {
            let phase = if matches!(epoch, 226 | 230)
                || SCOPES.iter().any(|spec| spec.unit == replay.unit)
            {
                "diagnostic-qualification"
            } else {
                "replay"
            };
            ensure!(
                row["phase"] == phase && observed_replays.insert(epoch),
                "unexpected or duplicate epoch {epoch} phase in fleet"
            );
            live::same_owner(&row["producer"], &replay.owner)?;
            continue;
        }
        let owner = match (epoch, text(row, "phase")?) {
            (226, "private-held-extraction")
            | (230, "diagnostic-qualification")
            | (252 | 261 | 288, "replay") => &row["producer"],
            (257, "upload-readback") => &row["unit"],
            _ => bail!("unregistered Foundation peer {epoch}"),
        };
        let unit = text(owner, "Id")?;
        let previous = booked
            .get(unit)
            .context("unbooked Foundation fleet owner")?;
        ensure!(
            owner["InvocationID"] == previous["InvocationID"]
                && owner["MainPID"] == previous["MainPID"]
                && owner["ControlGroup"] == previous["ControlGroup"]
                && roster.insert(epoch, owner).is_none(),
            "Foundation owner changed or duplicated for epoch {epoch}"
        );
    }
    ensure!(
        observed_deliveries
            .iter()
            .all(|epoch| !roster.contains_key(epoch)),
        "duplicate current-reader delivery phases in fleet"
    );
    ensure!(
        !live_replays
            .get(&230)
            .is_some_and(|replay| replay.unit == vote_boundary::UNIT)
            || observed_replays.contains(&230),
        "epoch 230 diagnostic is missing from the accepted fleet"
    );
    ensure!(
        !live_replays.contains_key(&226) || observed_replays.contains(&226),
        "epoch 226 suffix is missing from the accepted fleet"
    );
    let missing: BTreeMap<_, _> = released
        .iter()
        .filter_map(|(&epoch, &unit)| (!roster.contains_key(&epoch)).then_some((epoch, unit)))
        .collect();
    ensure!(
        roster.keys().copied().eq([226, 230, 252, 257, 261, 288]
            .into_iter()
            .filter(|epoch| !missing.contains_key(epoch))),
        "incomplete Foundation live roster"
    );
    let selected: BTreeSet<_> = roster
        .values()
        .map(|owner| text(owner, "Id"))
        .collect::<Result<_>>()?;
    ensure!(
        selected.len() == roster.len()
            && booked.keys().map(String::as_str).collect::<BTreeSet<_>>()
                == selected
                    .into_iter()
                    .chain(AUXILIARY)
                    .chain(missing.into_values())
                    .collect(),
        "missing or duplicate Foundation capacity booking"
    );
    Ok(roster)
}

#[cfg(test)]
mod roster_tests {
    use super::*;

    #[test]
    fn withdrawn_audit_requires_the_booked_unit_fully_drained() {
        let mut terminal = json!({
            "Id": AUXILIARY[1], "LoadState": "not-found", "ActiveState": "inactive",
            "SubState": "dead", "InvocationID": "", "ControlGroup": "", "Job": "",
            "ControlPID": "0", "MainPID": "0", "NRestarts": "0", "Triggers": "", "TriggeredBy": "",
        });
        assert!(check_withdrawn_audit(&terminal, false).is_ok());
        terminal["LoadState"] = json!("loaded");
        terminal["InvocationID"] = json!(WITHDRAWN_AUDIT_INVOCATION);
        assert!(check_withdrawn_audit(&terminal, false).is_ok());
        assert!(check_withdrawn_audit(&terminal, true).is_err());
        for (field, value) in [
            ("Id", "another.service"),
            ("InvocationID", "another-invocation"),
            ("MainPID", "123"),
            ("ControlPID", "234"),
            ("ControlGroup", "/system.slice/stale"),
            ("Job", "12"),
            ("NRestarts", "1"),
            ("ActiveState", "activating"),
            ("TriggeredBy", "handoff.timer"),
            ("Triggers", "guard.service"),
        ] {
            let mut changed = terminal.clone();
            changed[field] = json!(value);
            assert!(check_withdrawn_audit(&changed, false).is_err(), "{field}");
        }
    }

    #[test]
    #[ignore = "requires the Foundation range handoff and local systemd"]
    fn withdrawn_audit_uses_the_pinned_foundation_handoff() -> Result<()> {
        let root = tempfile::tempdir()?;
        let mut native = Native { root: root.path().to_owned(), counter: 0, deadline: None };
        let booking = Bound::new(REPLAY_BOOKING.0, REPLAY_BOOKING.1).sealed()?;
        assert_eq!(
            withdrawn_audit(&mut native, &booking)?,
            Bound::new(FOUNDATION_RANGE_HANDOFF.0, FOUNDATION_RANGE_HANDOFF.1),
        );
        Ok(())
    }

    #[test]
    fn epoch258_cpu_selection_respects_booked_replay_and_delivery_owners() {
        let cpus = units::parse_cpu_list(replay258::CPUS).unwrap();
        assert_eq!(cpus.len(), 8);
        let live260 = json!({"AllowedCPUs": "56-63"});
        assert!(require_disjoint_cpus(258, &cpus, replay260::UNIT, &live260).is_ok());
        let stale_template = units::parse_cpu_list("56-63").unwrap();
        let overlap = require_disjoint_cpus(258, &stale_template, replay260::UNIT, &live260)
            .unwrap_err()
            .to_string();
        assert!(overlap.contains(replay260::UNIT));
        assert!(
            require_disjoint_cpus(
                258,
                &cpus,
                "another-owner",
                &json!({"AllowedCPUs": "47-48"})
            )
            .is_err()
        );
        assert!(require_disjoint_cpus(258, &cpus, "unknown-owner", &json!({})).is_err());
    }

    #[test]
    fn funded_replay_can_leave_the_observer_only_after_validated_terminal() {
        let mut owners = serde_json::Map::new();
        let mut rows = Vec::new();
        for (epoch, phase) in [
            (226, "private-held-extraction"),
            (230, "diagnostic-qualification"),
            (252, "replay"),
            (257, "upload-readback"),
            (261, "replay"),
            (288, "replay"),
        ] {
            let unit = match epoch {
                226 => EXTRACT_226.to_owned(),
                252 => delivery252::REPLAY.to_owned(),
                257 => UPLOAD_257.to_owned(),
                261 => REPLAY_261.to_owned(),
                _ => format!("test-{epoch}.service"),
            };
            let owner = json!({"Id":unit,"InvocationID":format!("invocation-{epoch}"),
                "MainPID":epoch.to_string(),"ControlGroup":format!("/test/{epoch}")});
            owners.insert(unit, owner.clone());
            rows.push(json!({"epoch":epoch,"phase":phase,"producer":owner,"unit":owner}));
        }
        for unit in AUXILIARY {
            owners.insert(unit.to_owned(), Value::Null);
        }
        let booking = json!({"owners": owners});
        let before = json!({"active":rows});
        let none = BTreeMap::new();
        let first = BTreeMap::from([(261, REPLAY_261)]);
        let both = BTreeMap::from([(226, EXTRACT_226), (261, REPLAY_261)]);
        let live_replays = BTreeMap::new();
        let deliveries = BTreeMap::new();
        assert!(fleet_roster(&before, &booking, &none, &deliveries, &live_replays).is_ok());
        assert!(fleet_roster(&before, &booking, &both, &deliveries, &live_replays).is_ok());

        rows.retain(|row| row["epoch"] != 261);
        let after = json!({"active":rows});
        assert!(fleet_roster(&after, &booking, &none, &deliveries, &live_replays).is_err());
        assert!(fleet_roster(&after, &booking, &first, &deliveries, &live_replays).is_ok());

        rows.retain(|row| row["epoch"] != 226);
        let after = json!({"active":rows});
        assert!(fleet_roster(&after, &booking, &first, &deliveries, &live_replays).is_err());
        assert!(fleet_roster(&after, &booking, &both, &deliveries, &live_replays).is_ok());

        rows.retain(|row| row["epoch"] != 257);
        let after = json!({"active":rows});
        assert!(fleet_roster(&after, &booking, &both, &deliveries, &live_replays).is_err());
        let after_delivery =
            BTreeMap::from([(226, EXTRACT_226), (257, UPLOAD_257), (261, REPLAY_261)]);
        assert!(
            fleet_roster(
                &after,
                &booking,
                &after_delivery,
                &deliveries,
                &live_replays
            )
            .is_ok()
        );

        rows.retain(|row| row["epoch"] != 252);
        let after = json!({"active":rows});
        assert!(
            fleet_roster(
                &after,
                &booking,
                &after_delivery,
                &deliveries,
                &live_replays
            )
            .is_err()
        );
        let mut all_released = after_delivery;
        all_released.insert(252, delivery252::REPLAY);
        assert!(fleet_roster(&after, &booking, &all_released, &deliveries, &live_replays).is_ok());

        let successor = json!({"Id":suffix226::UNIT,"InvocationID":"suffix-invocation",
            "MainPID":"1226","ControlGroup":"/test/226-suffix","NRestarts":"0","Result":"success",
            "LoadState":"loaded","ActiveState":"active","SubState":"running",
            "ExecStart":"{ path=/node ; argv[]=/node 226 ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=1226 ; code=(null) ; status=0/0 }"});
        let live_suffix = BTreeMap::from([(
            226,
            LiveReplay {
                reference: Bound::new("/test/226-suffix.json", "test"),
                unit: suffix226::UNIT,
                owner: successor.clone(),
                memory: 0,
                ticks: 0,
                guard_booking: Value::Null,
                receipt_disk: DISK_RECEIPTS,
            },
        )]);
        assert!(fleet_roster(&after, &booking, &all_released, &deliveries, &live_suffix).is_err());
        rows.push(json!({"epoch":226,"phase":"diagnostic-qualification","producer":successor}));
        let handoff = json!({"active":rows});
        assert!(fleet_roster(&handoff, &booking, &all_released, &deliveries, &live_suffix).is_ok());
        all_released.remove(&226);
        assert!(
            fleet_roster(&handoff, &booking, &all_released, &deliveries, &live_suffix).is_err()
        );
    }
}

fn require_disjoint_cpus(
    epoch: u64,
    selected: &BTreeSet<u64>,
    unit: &str,
    owner: &Value,
) -> Result<()> {
    ensure!(
        selected.is_disjoint(&units::parse_cpu_list(text(owner, "AllowedCPUs")?)?),
        "epoch {epoch} CPUs overlap {unit}"
    );
    Ok(())
}

fn listed_owners(n: &mut Native) -> Result<BTreeSet<String>> {
    let raw = n.run(
        "/usr/bin/systemctl",
        &[
            "list-units",
            "--type=service",
            "--state=running,activating",
            "--plain",
            "--no-legend",
            "--no-pager",
        ],
    )?;
    Ok(std::str::from_utf8(&raw)?
        .lines()
        .filter_map(|line| {
            let unit = line.split_whitespace().next()?;
            let scoped = ["horizon-", "foundation-", "archive-", "jetstreamer-"]
                .iter()
                .any(|prefix| unit.starts_with(prefix));
            (scoped
                && unit != vote_boundary::GUARD_SERVICE
                && unit != suffix226::GUARD_SERVICE
                && unit != replay296::GUARD_SERVICE
                && !interval141::is_guard(unit)
                && !SCOPES
                    .iter()
                    .any(|spec| unit == format!("{}.service", spec.guard))
                && !KNOWN_GUARDS
                    .iter()
                    .any(|(_, guard)| unit == format!("{guard}.service")))
            .then(|| unit.to_owned())
        })
        .collect())
}

fn latest_guard_invocation(n: &Native, plan: &Value) -> Result<String> {
    let directory = Path::new(text(plan, "receipt_directory")?);
    trusted_parents(&directory.join("sample.json"))?;
    let mut latest = None;
    for entry in fs::read_dir(directory)? {
        n.check()?;
        let entry = entry?;
        let name = entry.file_name();
        let Some(iid) = name.to_str().and_then(|name| {
            name.strip_prefix("sample-")
                .and_then(|name| name.strip_suffix(".json"))
        }) else {
            continue;
        };
        if hex(iid, 32) && entry.file_type()?.is_file() {
            let candidate = (entry.metadata()?.modified()?, iid.to_owned());
            if latest.as_ref().is_none_or(|prior| candidate > *prior) {
                latest = Some(candidate);
            }
        }
    }
    Ok(latest.context("no completed Foundation guard sample")?.1)
}

fn guard_binding(
    n: &mut Native,
    epoch: u64,
    guard: &str,
    booking: &Value,
    owner: &Value,
    device: u64,
) -> Result<Value> {
    let proof = binding(&booking["sample"])?;
    let sample = proof.json()?;
    let guard_unit = format!("{guard}.service");
    let timer_unit = format!("{guard}.timer");
    let service = n.show_fields(&guard_unit, GUARD_FIELDS)?;
    let timer = n.show_fields(&timer_unit, GUARD_FIELDS)?;
    let plan = Bound::new(text(&sample, "plan")?, text(&sample, "plan_sha256")?);
    let body = plan.sealed()?;
    let command = text(&service, "ExecStart")?;
    // Systemd appends changing execution timestamps after the stable argument framing.
    let guard_pin = Bound::new(
        if guard == vote_boundary::GUARD {
            vote_boundary::GUARD_BINARY
        } else if epoch == 288 {
            GUARD_288
        } else {
            STANDARD_GUARD
        },
        text(&sample, "guard_sha256")?,
    );
    guard_pin.artifact()?;
    let guard_environment = match epoch {
        261 => Some((
            GUARD_ENV_261,
            "HORIZON261_GUARD_PLAN_SHA256",
            "${HORIZON261_GUARD_PLAN_SHA256}",
        )),
        262 => Some((
            GUARD_ENV_262,
            "HORIZON262_GUARD_PLAN_SHA256",
            "${HORIZON262_GUARD_PLAN_SHA256}",
        )),
        296 if guard != replay296::GUARD && !SCOPES.iter().any(|scope| guard == scope.guard) => {
            Some((
                GUARD_ENV_296,
                "HORIZON296_GUARD_PLAN_SHA256",
                "${HORIZON296_GUARD_PLAN_SHA256}",
            ))
        }
        _ => None,
    };
    let plan_arg = if let Some((path, variable, argument)) = guard_environment {
        let env = n.show_fields(
            &guard_unit,
            "Environment,EnvironmentFiles,PassEnvironment,UnsetEnvironment",
        )?;
        ensure!(
            env["EnvironmentFiles"] == format!("{path} (ignore_errors=no)")
                && ["Environment", "PassEnvironment", "UnsetEnvironment"]
                    .iter()
                    .all(|key| env[*key] == ""),
            "epoch {epoch} guard environment changed"
        );
        let path = Path::new(path);
        let source = Bound::new(path, hash(path)?);
        trusted_parents(path)?;
        let bytes = source.bytes(true)?;
        ensure!(
            bytes == format!("{variable}={}\n", plan.sha256).as_bytes(),
            "epoch {epoch} guard plan environment differs"
        );
        argument
    } else {
        &plan.sha256
    };
    let expected = format!(
        "{{ path={} ; argv[]={0} {} --plan-sha256 {} --self-sha256 {} ; ignore_errors=no",
        guard_pin.path.display(),
        plan.path.display(),
        plan_arg,
        guard_pin.sha256
    );
    ensure!(
        service["Id"] == guard_unit
            && service["LoadState"] == "loaded"
            && service["MemoryMax"] == "1073741824"
            && periodic::stable_command(command)? == expected
            && timer["Id"] == timer_unit
            && timer["LoadState"] == "loaded"
            && timer["ActiveState"] == "active"
            && timer["Unit"] == guard_unit
            && hex(text(&timer, "InvocationID")?, 32),
        "Foundation peer guard or timer changed: {guard}"
    );
    ensure!(
        sample["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && sample["producer_invocation_id"] == owner["InvocationID"]
            && sample["producer"]["pid"].as_u64() == Some(text(owner, "MainPID")?.parse()?)
            && sample["producer"]["cgroup"] == owner["ControlGroup"]
            && sample["producer_stop_enabled"] == true
            && sample["trip_reason"].is_null()
            && body["unit"] == owner["Id"]
            && body["invocation_id"] == owner["InvocationID"]
            && body["minimum_free_bytes"] == booking["floor_bytes"]
            && body["maximum_root_physical_bytes"] == booking["cap_bytes"]
            && fs::metadata(text(&body, "filesystem")?)?.dev() == device,
        "Foundation guard plan differs from booked peer {guard}"
    );
    let latest_iid = latest_guard_invocation(n, &body)?;
    let latest_proof = peer_window::guard_sample_ref(&body, &latest_iid)?;
    let latest =
        peer_window::validate_guard_sample(&latest_proof, &plan, &guard_pin, &body, &latest_iid)?;
    ensure!(
        latest["producer"] == sample["producer"],
        "Foundation guard changed producer identity: {guard}"
    );
    Ok(
        json!({"unit":guard_unit,"timer":timer_unit,"timer_invocation_id":timer["InvocationID"],
        "plan":plan,"executable":guard_pin,"retained_guard_sample":proof,"latest_guard_sample":latest_proof,
        "guard_command":expected,"producer":owner,
        "minimum_free_bytes":body["minimum_free_bytes"],"maximum_root_physical_bytes":body["maximum_root_physical_bytes"]}),
    )
}

pub(super) struct Controller<'a> {
    pub unit: &'a str,
    pub invocation: &'a str,
    pub held: bool,
}

impl Controller<'_> {
    fn check(&self, n: &mut Native) -> Result<Value> {
        ensure!(
            self.unit.starts_with("horizon-native262-controller-")
                && self.unit.ends_with(".service")
                && self
                    .unit
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c))
                && fs::read_to_string("/proc/self/cgroup")?.trim()
                    == format!("0::/system.slice/{}", self.unit),
            "capacity check is outside epoch 262's booked controller"
        );
        let row = n.show_fields(self.unit, &format!("{OWNER_FIELDS},Type"))?;
        ensure!(
            row["Type"] == "exec" && text(&row, "MainPID")?.parse::<u32>()? == std::process::id(),
            "epoch 262 capacity checker is not the booked main process"
        );
        live::finite_owner(&row, self.unit, self.invocation, CONTROLLER_MEMORY)?;
        Ok(row)
    }
}

fn held_owner(n: &mut Native) -> Result<(Value, u64)> {
    let held = n.show_fields(UNIT, OWNER_FIELDS)?;
    let iid = text(&held, "InvocationID")?;
    let pid = text(&held, "MainPID")?.parse()?;
    live::finite_owner(&held, UNIT, iid, MEMORY)?;
    gate::held_image(pid, iid, UNIT, HARNESS)?;
    Ok((held, process_ticks(pid)?))
}

pub(super) fn receipt(n: &mut Native, controller: Option<Controller<'_>>) -> Result<Value> {
    measure(n, controller, None)
}

fn measure(
    n: &mut Native,
    controller: Option<Controller<'_>>,
    quote: Option<Quote>,
) -> Result<Value> {
    let first_7871_candidate = matches!(&quote, Some(Quote::Focused(scope, _)) if scope.unit == FIRST_7871_230.unit);
    let v1627_candidate = matches!(&quote, Some(Quote::Focused(scope, _)) if scope.unit == V1627_230.unit);
    let adjacent_replay_candidate = matches!(&quote, Some(Quote::Focused(scope, _)) if scope.unit == ADJACENT_230.unit);
    let retry_next_v1627 = matches!(&quote, Some(Quote::Focused(scope, _)) if scope.unit == RETRY_NEXT_V1627_230.unit);
    let next_v1627_candidate = retry_next_v1627
        || matches!(&quote, Some(Quote::Focused(scope, _)) if scope.unit == NEXT_V1627_230.unit);
    let failed_predecessor = retry_next_v1627
        .then(|| focused::next_v1627_failed_start_drained(n))
        .transpose()?;
    let checkpoint_predecessor = (v1627_candidate || adjacent_replay_candidate)
        .then(|| focused::first_7871_drained(n))
        .transpose()?;
    let next_predecessor = next_v1627_candidate
        .then(|| focused::next_v1627_predecessor(n))
        .transpose()?;
    let completion = latest_completion()?;
    let done = completion.json()?;
    let fleet_ref = binding(&done["fleet"])?;
    let observer_ref = binding(&done["observer"])?;
    ensure!(
        fleet_ref.path == completion.path.with_file_name("fleet.json"),
        "Foundation fleet path"
    );
    let fleet = fleet_ref.json()?;
    let observer = observer_ref.json()?;
    fresh(num(&fleet, "recorded_unix_seconds")?, now()?, 1800)?;
    ensure!(
        fleet["schema"] == "jetstreamer-horizon-campaign-fleet-v1"
            && fleet["first_epoch"] == 201
            && fleet["last_epoch"] == 300
            && fleet["inventory"]["anomalies"] == 0
            && fleet["observer_receipt"] == json!(observer_ref.path)
            && fleet["observer_sha256"] == observer_ref.sha256
            && observer["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && fleet["sampled_at_utc"] == observer["recorded_at_utc"],
        "Foundation fleet and observation differ"
    );
    let booking_ref = Bound::new(REPLAY_BOOKING.0, REPLAY_BOOKING.1);
    let booking = booking_ref.sealed()?;
    let mut released_replays = BTreeMap::new();
    let extraction_drain = match &quote {
        Some(Quote::Suffix226(proof)) => Some(proof.clone()),
        Some(Quote::Suffix226Preview) | None => None,
        Some(_) if Path::new(DRAIN_226).try_exists()? => {
            Some(Bound::new(DRAIN_226, hash(Path::new(DRAIN_226))?))
        }
        _ => None,
    };
    if let Some(proof) = &extraction_drain {
        terminal_extract_226(n, &booking, proof)?;
        released_replays.insert(226, EXTRACT_226);
    }
    let suffix = match &quote {
        Some(Quote::Suffix226(proof)) => Some(proof),
        _ => None,
    };
    let closed_replay252 = if quote.is_some() {
        delivery252::terminal(n, &booking)?
    } else {
        None
    };
    let delivery_252 = matches!(&quote, Some(Quote::Delivery252));
    ensure!(
        !delivery_252 || closed_replay252.is_some(),
        "epoch 252 delivery requires a committed archive and drained replay guard"
    );
    if closed_replay252.is_some() {
        released_replays.insert(252, delivery252::REPLAY);
    }
    let closed_replay = if quote.is_some() {
        terminal_replay_261(n, &booking)?
    } else {
        None
    };
    let delivery_261 = matches!(&quote, Some(Quote::Delivery261(_)));
    ensure!(
        !delivery_261 || closed_replay.is_some(),
        "epoch 261 delivery requires a committed archive and drained replay guard"
    );
    if closed_replay.is_some() {
        released_replays.insert(261, REPLAY_261);
    }
    let closed_230 = if quote.is_some() {
        terminal_replay_230(n, &booking)?
    } else {
        None
    };
    if closed_230.is_some() {
        released_replays.insert(230, REPLAY_230);
    }
    let closed_257 = if quote.is_some() {
        terminal_delivery_257(n, &booking, &fleet)?
    } else {
        None
    };
    if closed_257.is_some() {
        released_replays.insert(257, UPLOAD_257);
    }
    let before = listed_owners(n)?;
    let active_holding_296 = before
        .contains(holding296::UNIT)
        .then(|| holding296::active(n))
        .transpose()?;
    let active_restore_266 = before
        .contains(restore266::UNIT)
        .then(|| restore266::active(n))
        .transpose()?;
    let auxiliary = [
        (holding296::UNIT, active_holding_296.as_ref()),
        (restore266::UNIT, active_restore_266.as_ref()),
    ];
    let active_interval_141 = interval141::enrolled(n, &before)?;
    let private_141 = match &quote {
        Some(Quote::Interval141(ordinal)) => Some(interval141::candidate(*ordinal, &before)?),
        _ => None,
    };
    let mut active_deliveries = BTreeMap::new();
    for (epoch, unit, candidate, closed) in [
        (
            252,
            delivery252::UPLOADER,
            delivery_252,
            closed_replay252.is_some(),
        ),
        (261, UPLOAD_261, delivery_261, closed_replay.is_some()),
    ] {
        if quote.is_some() && before.contains(unit) {
            ensure!(
                !candidate && closed,
                "epoch {epoch} delivery overlaps its candidate or replay"
            );
            active_deliveries.insert(epoch, live_delivery(n, epoch)?);
        }
    }
    let epoch = match &quote {
        Some(Quote::Interval141(_)) => 141,
        Some(Quote::FullReplay(full)) => full.epoch,
        Some(Quote::Suffix226(_) | Quote::Suffix226Preview) => 226,
        Some(Quote::Delivery252) => 252,
        Some(Quote::Delivery261(_)) => 261,
        Some(Quote::AdjacentIntake230(_)) => 230,
        Some(Quote::NextIntake266(_) | Quote::SuccessorIntake266(_)) => 266,
        Some(Quote::Replay296(_)) => 296,
        Some(Quote::Focused(spec, _)) => spec.epoch,
        _ => EPOCH,
    };
    let mut live_replays = BTreeMap::new();
    if before.contains(suffix226::UNIT) {
        ensure!(
            extraction_drain.is_some() && epoch != 226,
            "epoch 226 suffix overlaps an existing booking"
        );
        live_replays.insert(226, suffix226::live(n)?);
    }
    for spec in &REGISTERED_REPLAYS {
        if before.contains(spec.unit) {
            ensure!(
                quote.is_some() && spec.epoch != epoch,
                "epoch {} full replay already owns its lane",
                spec.epoch
            );
            ensure!(
                !live_replays.contains_key(&spec.epoch),
                "epoch {} has duplicate replay owners",
                spec.epoch
            );
            live_replays.insert(spec.epoch, live_replay(n, spec)?);
        }
    }
    if before.contains(vote_boundary::UNIT) {
        ensure!(
            closed_230.is_some() && epoch != 230,
            "another epoch 230 owner has not drained"
        );
        live_replays.insert(230, vote_boundary::live(n)?);
    }
    for spec in SCOPES {
        if before.contains(spec.unit) {
            ensure!(
                quote.is_some() && epoch != spec.epoch && !live_replays.contains_key(&spec.epoch),
                "epoch {} already has a live replay or diagnostic",
                spec.epoch
            );
            live_replays.insert(spec.epoch, spec.live(n)?);
        }
    }
    let mut admission_fleet = fleet.clone();
    let closed_first_7871 = if quote.is_some() {
        drain_first_7871(n, &mut admission_fleet)?
    } else {
        None
    };
    let mut closed_v1627_230 = None;
    let mut closed_adjacent_230 = None;
    let mut closed_overlap_266 = None;
    let mut closed_predecessor_266 = None;
    let mut closed_window_266 = None;
    let rows = admission_fleet["active"].as_array_mut().context("Foundation active roster")?;
    if quote.is_some() && !live_replays.contains_key(&230)
        && let Some(index) = rows.iter().position(|row| {
            row["epoch"] == 230 && row["producer"]["Id"] == V1627_230.unit
        })
        && let Some(proof) = focused::v1627_230_drained(n, &rows[index])?
    {
        closed_v1627_230 = Some((rows.remove(index), proof));
    }
    if quote.is_some() && !live_replays.contains_key(&230)
        && let Some(index) = rows.iter().position(|row| {
            row["epoch"] == 230 && row["producer"]["Id"] == ADJACENT_230.unit
        })
        && let Some(proof) = focused::adjacent_230_drained(n, &rows[index])?
    {
        closed_adjacent_230 = Some((rows.remove(index), proof));
    }
    if quote.is_some() && !live_replays.contains_key(&266)
        && let Some(index) = rows.iter().position(|row| {
            row["epoch"] == 266 && row["producer"]["Id"] == OVERLAP_266.unit
        })
        && let Some(proof) = focused::overlap_266_drained(n, &rows[index])?
    {
        closed_overlap_266 = Some((rows.remove(index), proof));
    }
    if quote.is_some() && !live_replays.contains_key(&266)
        && let Some(index) = rows.iter().position(|row| {
            row["epoch"] == 266 && row["producer"]["Id"] == PREDECESSOR_266.unit
        })
        && let Some(proof) = focused::predecessor_266_drained(n, &rows[index])?
    {
        closed_predecessor_266 = Some((rows.remove(index), proof));
    }
    if quote.is_some() && !live_replays.contains_key(&266)
        && let Some(index) = rows.iter().position(|row| {
            row["epoch"] == 266 && row["producer"]["Id"] == WINDOW_266.unit
        })
        && let Some(proof) = focused::window_266_drained(n, &rows[index])?
    {
        closed_window_266 = Some((rows.remove(index), proof));
    }
    let roster = fleet_roster(
        &admission_fleet,
        &booking,
        &released_replays,
        &active_deliveries,
        &live_replays,
    )?;
    if private_141.is_none() {
        let missing: Vec<_> = fleet["inventory"]["entries"]
            .as_array()
            .context("Foundation inventory")?
            .iter()
            .filter(|row| row["epoch"] == epoch)
            .collect();
        ensure!(
            missing.len() == 1 && missing[0]["state"] == "missing",
            "epoch {epoch} inventory no longer missing"
        );
    }
    let booked: BTreeSet<String> = booking["owners"]
        .as_object()
        .context("booked owners")?
        .keys()
        .cloned()
        .collect();
    let mut released_units: BTreeSet<_> = released_replays.into_values().collect();
    if extraction_drain.is_some() {
        released_units.insert(BROKER_226);
    }
    let closed_audit = quote
        .as_ref()
        .map(|_| withdrawn_audit(n, &booking))
        .transpose()?;
    if closed_audit.is_some() {
        released_units.insert(AUXILIARY[1]);
    }
    let mut expected = booked.clone();
    for unit in &released_units {
        ensure!(
            expected.remove(*unit),
            "released Foundation reservation {unit} is missing"
        );
    }
    let controller_owner = controller.as_ref().map(|c| c.check(n)).transpose()?;
    let held = if controller.as_ref().is_some_and(|c| c.held) {
        Some(held_owner(n)?)
    } else {
        None
    };
    if let Some(c) = &controller {
        ensure!(
            expected.insert(c.unit.to_owned()),
            "epoch 262 controller already booked as a peer"
        );
    }
    if held.is_some() {
        ensure!(
            expected.insert(UNIT.to_owned()),
            "epoch 262 held owner already booked as a peer"
        );
    }
    for (unit, owner) in auxiliary {
        if owner.is_some() {
            ensure!(expected.insert(unit.to_owned()), "{unit} booked twice");
        }
    }
    for interval in &active_interval_141 {
        ensure!(expected.insert(interval.unit.to_owned()), "epoch 141 replay booked twice");
    }
    for (_, owner, _, _) in active_deliveries.values() {
        let unit = text(owner, "Id")?;
        ensure!(
            expected.insert(unit.to_owned()),
            "delivery {unit} booked twice"
        );
    }
    for replay in live_replays.values() {
        ensure!(
            expected.insert(replay.unit.to_owned()),
            "replay {} booked twice",
            replay.unit
        );
    }
    ensure!(
        before == expected,
        "unaccounted or missing Foundation owners: {:?}",
        before.symmetric_difference(&expected).collect::<Vec<_>>()
    );
    let device = fs::metadata(FILESYSTEM)?.dev();
    ensure!(
        fs::metadata(text(&observer["filesystem"], "path")?)?.dev() == device,
        "Foundation filesystem changed"
    );
    let mount = if quote.is_some() {
        ensure!(
            fs::metadata("/home/ubuntu/.jetstreamer-private")?.dev() == device,
            "Foundation replay output filesystem changed"
        );
        Value::Null
    } else {
        pristine(device)?
    };
    let resources_before = live::resources_at(Path::new(FILESYSTEM))?;
    let adjacent_230 = matches!(&quote, Some(Quote::AdjacentIntake230(_)));
    let next_266 = matches!(&quote, Some(Quote::NextIntake266(_) | Quote::SuccessorIntake266(_)));
    let selected = if let Some(candidate) = &private_141 {
        candidate.cpus()
    } else {
        units::parse_cpu_list(match epoch {
        226 => "16-23",
        230 => match &quote {
            Some(Quote::AdjacentIntake230(_)) => "48",
            Some(Quote::Focused(spec, _)) => spec.cpus,
            _ => GAP_230.cpus,
        },
        256 => replay256::CPUS,
        258 if matches!(&quote, Some(Quote::FullReplay(_))) => replay258::CPUS,
        258 => RESTORE_258.cpus,
        260 => RESTORE_260.cpus,
        266 if next_266 => NEXT_266_CPU,
        266 => OVERLAP_266.cpus,
        252 | 261 => "24-31",
        296 if matches!(&quote, Some(Quote::Replay296(_))) => replay296::CPUS,
        296 => "56-63",
        _ => "40-47",
        })?
    };
    let cpu_width = if adjacent_230 || next_266 { 1 } else if private_141.is_some() { 3 } else { 8 };
    let cpus = units::affinity_width(&json!({"cpu_affinity":selected}), cpu_width)?;
    let private_exclusive = private_141.as_ref().map(interval141::Candidate::exclusive).transpose()?;
    let overlap_exclusive = units::parse_cpu_list(OVERLAP_266_EXCLUSIVE)?;
    let bridge_group = units::parse_cpu_list("48-55,112-119")?;
    let adjacent_copy_group = units::parse_cpu_list("48,112")?;
    let next_266_group = units::parse_cpu_list(NEXT_266_EXCLUSIVE)?;
    let exclusive = match &quote {
        Some(Quote::NextIntake266(_) | Quote::SuccessorIntake266(_)) => {
            replay296::verify_cpu_group(NEXT_266_CPU, &next_266_group)?;
            &next_266_group
        }
        Some(Quote::AdjacentIntake230(_)) => {
            replay296::verify_cpu_group("48", &adjacent_copy_group)?;
            &adjacent_copy_group
        }
        Some(Quote::Focused(_, _)) if first_7871_candidate => {
            focused::second_hourly_drained(n)?;
            replay296::verify_cpu_group(FIRST_7871_230.cpus, &bridge_group)?;
            &bridge_group
        }
        Some(Quote::Focused(spec, _)) if v1627_candidate || adjacent_replay_candidate || next_v1627_candidate => {
            replay296::verify_cpu_group(spec.cpus, &bridge_group)?;
            &bridge_group
        }
        Some(Quote::Focused(spec, _)) if spec.epoch == 266 => {
            replay296::verify_cpu_group("30,32-39", &overlap_exclusive)?;
            &overlap_exclusive
        }
        Some(Quote::Replay296(replay)) => &replay.placement.exclusive_cpus,
        _ => private_exclusive.as_ref().unwrap_or(&selected),
    };
    let mut recorded = BTreeMap::new();
    for unit in booked
        .iter()
        .filter(|unit| !released_units.contains(unit.as_str()))
    {
        let owner = n.show_fields(unit, OWNER_FIELDS)?;
        let recorded_owner = &booking["owners"][unit];
        for field in [
            "MainPID",
            "InvocationID",
            "ControlGroup",
            "AllowedCPUs",
            "MemoryMax",
        ] {
            ensure!(
                owner[field] == recorded_owner[field] && !owner[field].is_null(),
                "booked owner {unit} changed {field}"
            );
        }
        if let Some(prior) = roster.values().find(|prior| prior["Id"] == *unit) {
            live::same_owner(prior, &owner)?;
        }
        let cap = text(&owner, "MemoryMax")?.parse()?;
        require_disjoint_cpus(epoch, exclusive, unit, &owner)?;
        let memory = live::finite_owner(&owner, unit, text(&owner, "InvocationID")?, cap)?;
        let process_start_ticks = process_ticks(text(&owner, "MainPID")?.parse()?)?;
        recorded.insert(unit.clone(), (owner, memory, process_start_ticks));
    }
    for (unit, owner) in auxiliary {
        if let Some(aux) = owner {
            require_disjoint_cpus(epoch, exclusive, unit, &aux.owner)?;
            recorded.insert(unit.to_owned(), (aux.owner.clone(), aux.memory, aux.ticks));
        }
    }
    if active_restore_266.is_some() {
        ensure!(exclusive.is_disjoint(&units::parse_cpu_list("32-39,96-103")?),
            "epoch {epoch} overlaps the epoch 266 checkpoint's physical cores");
    }
    for interval in &active_interval_141 {
        interval.require_disjoint(exclusive)?;
        recorded.insert(
            interval.unit.to_owned(),
            (interval.owner.clone(), interval.memory, interval.ticks),
        );
    }
    for (_, owner, memory, ticks) in active_deliveries.values() {
        let unit = text(owner, "Id")?;
        require_disjoint_cpus(epoch, exclusive, unit, owner)?;
        recorded.insert(unit.to_owned(), (owner.clone(), *memory, *ticks));
    }
    let bridge_windows = [FIRST_7871_230.unit, V1627_230.unit, ADJACENT_230.unit, NEXT_V1627_230.unit, RETRY_NEXT_V1627_230.unit];
    for replay in live_replays.values() {
        require_disjoint_cpus(epoch, exclusive, replay.unit, &replay.owner)?;
        if [OVERLAP_266.unit, PREDECESSOR_266.unit, WINDOW_266.unit].contains(&replay.unit) {
            replay296::verify_cpu_group("30,32-39", &overlap_exclusive)?;
            ensure!(
                exclusive.is_disjoint(&overlap_exclusive),
                "epoch {epoch} overlaps the epoch 266 diagnostic's physical cores"
            );
        }
        if bridge_windows.contains(&replay.unit) {
            replay296::verify_cpu_group(V1627_230.cpus, &bridge_group)?;
            ensure!(exclusive.is_disjoint(&bridge_group), "epoch {epoch} overlaps the running epoch 230 physical cores");
        }
        if replay.unit == replay296::UNIT {
            ensure!(
                selected.is_disjoint(&replay296::placement()?.exclusive_cpus),
                "epoch {epoch} CPUs overlap the running epoch 296 physical cores"
            );
        }
        recorded.insert(
            replay.unit.to_owned(),
            (replay.owner.clone(), replay.memory, replay.ticks),
        );
    }
    let mut guards = BTreeMap::new();
    for (guard_epoch, guard) in KNOWN_GUARDS {
        if guard_epoch == 226 && extraction_drain.is_some() {
            if let Some(replay) = live_replays.get(&226) {
                guards.insert(
                    226,
                    guard_binding(
                        n,
                        226,
                        suffix226::GUARD,
                        &replay.guard_booking,
                        &replay.owner,
                        device,
                    )?,
                );
            }
            continue;
        }
        let focused = SCOPES.into_iter().find(|spec| {
            live_replays
                .get(&guard_epoch)
                .is_some_and(|row| row.unit == spec.unit)
        });
        if (guard_epoch == 230 && closed_230.is_some() && focused.is_none())
            || (guard_epoch == 252 && closed_replay252.is_some())
            || (guard_epoch == 261 && closed_replay.is_some())
        {
            continue;
        }
        let (owner, guard_booking) = if let Some(replay) = live_replays.get(&guard_epoch) {
            (&replay.owner, &replay.guard_booking)
        } else {
            if matches!(guard_epoch, 258 | 260 | 266)
                || REGISTERED_REPLAYS
                    .iter()
                    .any(|spec| spec.epoch == guard_epoch)
            {
                continue;
            }
            let unit = text(roster[&guard_epoch], "Id")?;
            (
                &recorded[unit].0,
                &booking["guard_growth"][guard_epoch.to_string()],
            )
        };
        let guard = if live_replays
            .get(&guard_epoch)
            .is_some_and(|row| row.unit == replay296::UNIT)
        {
            replay296::GUARD
        } else {
            focused.map_or(guard, |spec| spec.guard)
        };
        guards.insert(
            guard_epoch,
            guard_binding(n, guard_epoch, guard, guard_booking, owner, device)?,
        );
    }
    let disk_floor = guards
        .values()
        .map(|guard| num(guard, "minimum_free_bytes"))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .max()
        .context("missing Foundation guard floor")?;
    let allocation = allocation::measure(n, &guards, device)?;
    if let Some(diagnostic) = live_replays
        .get(&230)
        .filter(|row| row.unit == vote_boundary::UNIT)
    {
        guards.insert(230, vote_boundary::guard(n, diagnostic, device)?);
    }
    for (unit, (owner, memory, start_ticks)) in &mut recorded {
        let after = n.show_fields(unit, OWNER_FIELDS)?;
        live::same_owner(owner, &after)?;
        ensure!(
            owner["MemoryMax"] == after["MemoryMax"]
                && owner["AllowedCPUs"] == after["AllowedCPUs"]
                && *start_ticks == process_ticks(text(&after, "MainPID")?.parse()?)?,
            "owner cap, CPUs or process changed for {unit}"
        );
        *memory = (*memory).min(live::finite_owner(
            &after,
            unit,
            text(owner, "InvocationID")?,
            text(owner, "MemoryMax")?.parse()?,
        )?);
    }
    ensure!(
        listed_owners(n)? == before && latest_completion()? == completion,
        "Foundation cohort changed during roster binding"
    );
    if let Some(reference) = &closed_audit {
        ensure!(
            &withdrawn_audit(n, &booking)? == reference,
            "Foundation range handoff changed"
        );
    }
    if closed_replay.is_some() {
        ensure!(
            terminal_replay_261(n, &booking)? == closed_replay,
            "epoch 261 terminal changed during roster binding"
        );
    }
    if closed_230.is_some() {
        ensure!(
            terminal_replay_230(n, &booking)? == closed_230,
            "epoch 230 terminal changed during roster binding"
        );
    }
    if let Some((row, proof)) = &closed_v1627_230 {
        ensure!(
            focused::v1627_230_drained(n, row)?.as_ref() == Some(proof),
            "epoch 230 v1.6.27 terminal changed during roster binding"
        );
    }
    if let Some((row, proof)) = &closed_adjacent_230 {
        ensure!(
            focused::adjacent_230_drained(n, row)?.as_ref() == Some(proof),
            "epoch 230 adjacent terminal changed during roster binding"
        );
    }
    if let Some((row, proof)) = &closed_overlap_266 {
        ensure!(
            focused::overlap_266_drained(n, row)?.as_ref() == Some(proof),
            "epoch 266 terminal changed during roster binding"
        );
    }
    if let Some((row, proof)) = &closed_predecessor_266 {
        ensure!(
            focused::predecessor_266_drained(n, row)?.as_ref() == Some(proof),
            "epoch 266 predecessor terminal changed during roster binding"
        );
    }
    if let Some((row, proof)) = &closed_window_266 {
        ensure!(
            focused::window_266_drained(n, row)?.as_ref() == Some(proof),
            "epoch 266 checkpoint window terminal changed during roster binding"
        );
    }
    if let Some(proof) = &extraction_drain {
        terminal_extract_226(n, &booking, proof)?;
    }
    if first_7871_candidate {
        focused::second_hourly_drained(n)?;
    }
    if let Some(expected) = &checkpoint_predecessor {
        ensure!(&focused::first_7871_drained(n)? == expected, "epoch 230 predecessor changed");
    }
    if let Some(expected) = &failed_predecessor {
        ensure!(&focused::next_v1627_failed_start_drained(n)? == expected, "epoch 230 failed-start evidence changed");
    }
    if let Some(expected) = &next_predecessor {
        ensure!(&focused::next_v1627_predecessor(n)? == expected, "epoch 230 v1.6.27 predecessor changed");
    }
    if let Some(Quote::Replay296(full)) = &quote {
        let checkpoint = full.checkpoint.sealed()?;
        focused::feature_296_drained(n, text(&checkpoint, "invocation_id")?)?;
    }
    for guard in guards.values() {
        let timer = n.show_fields(text(guard, "timer")?, "ActiveState,InvocationID,Unit")?;
        ensure!(
            timer["ActiveState"] == "active"
                && timer["InvocationID"] == guard["timer_invocation_id"]
                && timer["Unit"] == guard["unit"],
            "Foundation guard timer changed during roster binding"
        );
    }
    if let (Some(controller), Some(prior)) = (&controller, &controller_owner) {
        live::same_owner(prior, &controller.check(n)?)?;
    }
    if let Some((prior, start)) = &held {
        let (after, new_start) = held_owner(n)?;
        live::same_owner(prior, &after)?;
        ensure!(*start == new_start, "held epoch 262 process was replaced");
    }
    let resources_after = live::resources_at(Path::new(FILESYSTEM))?;
    ensure!(
        resources_before.0 == resources_after.0
            && if quote.is_some() {
                fs::metadata("/home/ubuntu/.jetstreamer-private")?.dev() == device
            } else {
                mount == pristine(device)?
            },
        "epoch {epoch} resources or scratch mount changed"
    );
    let delivery_ref = Bound::new(DELIVERY_BOOKING.0, DELIVERY_BOOKING.1);
    let delivery = delivery_ref.sealed()?;
    let prior_growth = booking["guard_growth"]
        .as_object()
        .context("prior growth reservations")?
        .values()
        .try_fold(0, |sum, row| {
            capacity::add(sum, num(row, "remaining_growth_bytes")?)
        })?;
    let non_guard_disk = num(&booking, "full_protection_bytes")?
        .checked_sub(capacity::add(disk_floor, prior_growth)?)
        .context("prior protection arithmetic changed")?;
    ensure!(
        non_guard_disk >= num(&delivery, "receipt_scratch_maximum_bytes")?,
        "epoch 257 retained disk reserve missing"
    );
    let growth = allocation["roots"]
        .as_object()
        .context("allocation roots")?
        .values()
        .try_fold(0, |sum, row| {
            capacity::add(sum, num(row, "remaining_upper_bound_bytes")?)
        })?;
    let delivery_252_disk = active_deliveries.get(&252).map_or(0, |_| UPLOAD_261_DISK);
    let delivery_261_disk = active_deliveries.get(&261).map_or(0, |_| UPLOAD_261_DISK);
    let replay_disk = live_replays
        .values()
        .try_fold(0, |total, replay| capacity::add(total, replay.receipt_disk))?;
    let holding_296_disk = active_holding_296.as_ref().map_or(0, |_| holding296::RECEIPT_DISK);
    let restore_266_disk = active_restore_266.as_ref().map_or(0, |_| restore266::RECEIPT_DISK);
    let interval_141_disk = active_interval_141.len() as u64 * interval141::DISK;
    let shares_suffix = adjacent_230 || next_266 || matches!(&quote, Some(Quote::Focused(scope, _))
        if bridge_windows.contains(&scope.unit) || scope.epoch == 266)
        || live_replays.get(&230).is_some_and(|replay| bridge_windows.contains(&replay.unit))
        || live_replays.contains_key(&266);
    let suffix_quote = matches!(&quote, Some(Quote::Suffix226(_) | Quote::Suffix226Preview));
    let suffix_active = live_replays.contains_key(&226);
    let (pending_suffix_disk, pending_suffix_memory) = if suffix226::reserve_for_overlap(shares_suffix, suffix_quote, suffix_active) {
        ensure!(before.contains(EXTRACT_226) || extraction_drain.is_some(),
            "epoch 226 extraction or exact drain is required for the protected suffix");
        suffix226::pending_reservation(n)?
    } else {
        (0, 0)
    };
    let protected = capacity::add(
        capacity::add(
            capacity::add(disk_floor, non_guard_disk)?,
            capacity::add(
                capacity::add(delivery_252_disk, delivery_261_disk)?,
                capacity::add(capacity::add(replay_disk, restore_266_disk)?, capacity::add(holding_296_disk, interval_141_disk)?)?,
            )?,
        )?,
        capacity::add(growth, pending_suffix_disk)?,
    )?;
    let (candidate_disk, candidate) = match &quote {
        Some(Quote::Interval141(_)) => private_141.as_ref().context("private 141 inputs")?.resources()?,
        Some(Quote::FullReplay(quote)) => (
            capacity::add(quote.working_disk, DISK_RECEIPTS)?,
            capacity::add(
                quote.producer_memory,
                capacity::add(CONTROLLER_MEMORY, 1 << 30)?,
            )?,
        ),
        Some(Quote::Suffix226(_) | Quote::Suffix226Preview) => (
            capacity::add(SUFFIX_226_CAP, DISK_RECEIPTS)?,
            capacity::add(SUFFIX_226_CAP, capacity::add(CONTROLLER_MEMORY, 1 << 30)?)?,
        ),
        Some(Quote::Delivery252) => (
            UPLOAD_261_DISK,
            capacity::add(UPLOAD_261_MEMORY, CONTROLLER_MEMORY)?,
        ),
        Some(Quote::Delivery261(_)) => (
            num(&delivery, "receipt_scratch_maximum_bytes")?,
            capacity::add(
                num(&delivery, "memory_max_bytes")?,
                capacity::add(CONTROLLER_MEMORY, num(&delivery, "guard_memory_allowance")?)?,
            )?,
        ),
        Some(Quote::NextIntake266(_)) => (
            capacity::add(NEXT_266_PAYLOAD, BOOTSTRAP_COPY_OVERHEAD)?,
            BOOTSTRAP_COPY_MEMORY,
        ),
        Some(Quote::SuccessorIntake266(_)) => (
            capacity::add(SUCCESSOR_266_PAYLOAD, BOOTSTRAP_COPY_OVERHEAD)?,
            BOOTSTRAP_COPY_MEMORY,
        ),
        Some(Quote::AdjacentIntake230(_)) => (
            capacity::add(ADJACENT_230_BYTES, BOOTSTRAP_COPY_OVERHEAD)?,
            BOOTSTRAP_COPY_MEMORY,
        ),
        Some(Quote::Replay296(quote)) => {
            (quote.disk, capacity::add(quote.memory, CONTROLLER_MEMORY)?)
        }
        Some(Quote::Focused(spec, _)) => (
            capacity::add(spec.scratch_cap, spec.receipt_disk)?,
            capacity::add(
                spec.producer_memory,
                capacity::add(spec.control_memory(), 1 << 30)?,
            )?,
        ),
        None => (
            DISK_RECEIPTS,
            capacity::add(MEMORY, capacity::add(CONTROLLER_MEMORY, GUARD_MEMORY)?)?,
        ),
    };
    let required = capacity::add(protected, candidate_disk)?;
    let free = num(&allocation, "conservative_available_bytes")?
        .min(resources_before.2)
        .min(resources_after.2);
    let periodic_reserve = capacity::add(
        num(&delivery, "guard_memory_allowance")?,
        capacity::add(
            (live_replays.len() as u64) << 30,
            if live_replays.contains_key(&230) {
                CONTROLLER_MEMORY
            } else {
                0
            },
        )?,
    )?;
    let periodic_reserve = capacity::add(
        periodic_reserve,
        live_replays.get(&266).map_or(0, |_| OVERLAP_266.control_memory()),
    )?;
    let guard_141_memory = active_interval_141.len() as u64 * interval141::GUARD_MEMORY;
    let restore_allowance = active_restore_266.as_ref().map_or(0, |_| restore266::ADDITIONAL_MEMORY);
    let guarded_memory = capacity::add(guard_141_memory, restore_allowance)?;
    let headroom = capacity::add(resources_before.0 / 10, pending_suffix_memory)?;
    let reserve = capacity::add(headroom, capacity::add(periodic_reserve, guarded_memory)?)?;
    let base_memory = capacity::add(reserve, candidate)?;
    let (hard, growth_memory) = recorded.values().try_fold(
        (base_memory, base_memory),
        |(hard, growth), (owner, current, _)| {
            let cap: u64 = text(owner, "MemoryMax")?.parse()?;
            Ok::<_, anyhow::Error>((
                capacity::add(hard, cap)?,
                capacity::add(
                    growth,
                    cap.checked_sub(*current)
                        .context("owner current exceeds cap")?,
                )?,
            ))
        },
    )?;
    let available_memory = resources_before.1.min(resources_after.1);
    let fit = json!({"guard_floor_bytes":disk_floor,"inherited_non_guard_disk_bytes":non_guard_disk,
        "active_delivery_252_disk_bytes":delivery_252_disk,"active_delivery_261_disk_bytes":delivery_261_disk,
        "active_holding_296_disk_bytes":holding_296_disk,
        "active_restore_266_receipt_bytes":restore_266_disk,
        "active_restore_266_additional_memory_bytes":restore_allowance,
        "active_interval_141_disk_bytes":interval_141_disk,
        "active_diagnostic_230_receipt_disk_bytes":live_replays.get(&230).map_or(0, |lane| lane.receipt_disk),
        "active_replay_262_receipt_disk_bytes":live_replays.get(&262).map_or(0, |lane| lane.receipt_disk),
        "active_replay_296_receipt_disk_bytes":live_replays.get(&296).map_or(0, |lane| lane.receipt_disk),
        "protected_226_suffix_state":if !shares_suffix {"outside-quote"} else if suffix_quote {"candidate"}
            else if suffix_active {"live"} else if pending_suffix_disk > 0 {"pending"} else {"verified-closed"},
        "pending_suffix226_disk_bytes":pending_suffix_disk,"pending_suffix226_memory_bytes":pending_suffix_memory,
        "remaining_guard_growth_bytes":growth,"protected_existing_disk_bytes":protected,
        "candidate_disk_bytes":candidate_disk,"required_disk_bytes":required,"available_disk_bytes":free,
        "disk_shortfall_bytes":required.saturating_sub(free),"disk_margin_bytes":free.saturating_sub(required),
        "combined_host_and_periodic_memory_reserve_bytes":reserve,"candidate_total_memory_bytes":candidate,
        "required_hard_memory_bytes":hard,"host_total_memory_bytes":resources_before.0,
        "required_remaining_memory_bytes":growth_memory,"available_memory_bytes":available_memory,
        "memory_shortfall_bytes":hard.saturating_sub(resources_before.0).max(growth_memory.saturating_sub(available_memory)),
        "fits":required<=free && hard<=resources_before.0 && growth_memory<=available_memory,
        "cpus":cpus,"candidate_mount":mount,"delivery_booking":delivery_ref});
    let on_host_owners: BTreeMap<_, _> = recorded
        .into_iter()
        .map(|(unit, (owner, memory, ticks))| {
            (
                unit,
                json!({"systemd":owner,"memory_current_bytes":memory,"process_start_ticks":ticks}),
            )
        })
        .collect();
    let private_schema = private_141.as_ref().map(interval141::Candidate::schema);
    let schema = match epoch {
        141 => private_schema.as_deref().context("private 141 schema")?,
        226 => "foundation-epoch226-suffix-roster-binding-v1",
        230 if adjacent_230 => "foundation-epoch230-adjacent-intake-roster-binding-v1",
        230 if matches!(&quote, Some(Quote::Focused(spec, _)) if spec.unit == HOURLY_230.unit) => {
            "foundation-epoch230-hourly-first-roster-binding-v1"
        }
        230 if matches!(&quote, Some(Quote::Focused(spec, _)) if spec.unit == SECOND_HOURLY_230.unit) => {
            "foundation-epoch230-hourly-second-roster-binding-v1"
        }
        230 if first_7871_candidate => "foundation-epoch230-first-7871-roster-binding-v1",
        230 if adjacent_replay_candidate => "foundation-epoch230-adjacent-replay-roster-binding-v1",
        230 if v1627_candidate => "foundation-epoch230-v1627-window-roster-binding-v1",
        230 if retry_next_v1627 => "foundation-epoch230-next-v1627-retry-roster-binding-v2",
        230 if next_v1627_candidate => "foundation-epoch230-next-v1627-roster-binding-v1",
        230 => "foundation-epoch230-short-gap-roster-binding-v1",
        252 => "foundation-epoch252-delivery-roster-binding-v1",
        256 => replay256::ROSTER_SCHEMA,
        258 if matches!(&quote, Some(Quote::FullReplay(_))) => replay258::ROSTER_SCHEMA,
        258 => "foundation-epoch258-native-restore-roster-binding-v1",
        260 if matches!(&quote, Some(Quote::FullReplay(_))) => replay260::ROSTER_SCHEMA,
        260 => "foundation-epoch260-native-restore-roster-binding-v1",
        261 => "foundation-epoch261-delivery-roster-binding-v1",
        266 if matches!(&quote, Some(Quote::SuccessorIntake266(_))) =>
            "foundation-epoch266-successor-bootstrap-intake-roster-binding-v1",
        266 if next_266 => "foundation-epoch266-next-bootstrap-intake-roster-binding-v1",
        266 if matches!(&quote, Some(Quote::Focused(spec, _)) if spec.unit == WINDOW_266.unit) =>
            "foundation-epoch266-private-window-roster-binding-v1",
        266 if matches!(&quote, Some(Quote::Focused(spec, _)) if spec.unit == PREDECESSOR_266.unit) =>
            "foundation-epoch266-original-predecessor-roster-binding-v1",
        266 => "foundation-epoch266-hourly-overlap-roster-binding-v1",
        296 => "foundation-epoch296-replay-roster-binding-v1",
        _ => "foundation-epoch262-roster-binding-v1",
    };
    let mut evidence = json!({"schema":schema,"epoch":epoch,
        "recorded_unix_seconds":now()?,"fleet":fleet_ref,"observer":observer_ref,
        "completion":completion,"booking":booking_ref,"filesystem_device":device,
        "owners":on_host_owners,"periodic_guards":guards,"local_allocation":allocation,"capacity":fit,
        "controller":controller_owner,"candidate_held":held.is_some(),"admission_issued":false,
        "closed_middle_replay":closed_230,
        "closed_first_7871_replay":closed_first_7871,
        "closed_v1627_230_replay":closed_v1627_230.map(|(_, proof)| proof),
        "closed_adjacent_230_replay":closed_adjacent_230.map(|(_, proof)| proof),
        "closed_overlap_266_replay":closed_overlap_266.map(|(_, proof)| proof),
        "closed_predecessor_266_replay":closed_predecessor_266.map(|(_, proof)| proof),
        "closed_window_266_replay":closed_window_266.map(|(_, proof)| proof),
        "closed_extraction_226":extraction_drain,
        "active_suffix_226_registration":live_replays.get(&226).map(|replay| &replay.reference),
        "active_diagnostic_230_registration":live_replays.get(&230).map(|replay| &replay.reference),
        "active_restore_258_registration":live_replays.get(&258).filter(|r| r.unit == RESTORE_258.unit).map(|r| &r.reference),
        "active_replay_258_registration":live_replays.get(&258).filter(|r| r.unit == replay258::UNIT).map(|r| &r.reference),
        "active_restore_260_registration":live_replays.get(&260).filter(|r| r.unit == RESTORE_260.unit).map(|r| &r.reference),
        "active_replay_260_registration":live_replays.get(&260).filter(|r| r.unit == replay260::UNIT).map(|r| &r.reference),
        "closed_delivery_257":closed_257,
        "active_holding_296_launch":active_holding_296.as_ref().map(|holding| &holding.launch),
        "active_restore_266_launch":active_restore_266.as_ref().map(|restore| &restore.launch),
        "active_overlap_266_registration":live_replays.get(&266).filter(|replay| replay.unit == OVERLAP_266.unit).map(|replay| &replay.reference),
        "active_predecessor_266_registration":live_replays.get(&266).filter(|replay| replay.unit == PREDECESSOR_266.unit).map(|replay| &replay.reference),
        "active_window_266_registration":live_replays.get(&266).filter(|replay| replay.unit == WINDOW_266.unit).map(|replay| &replay.reference),
        "active_interval_141_launch":active_interval_141.iter().find(|interval| interval.ordinal() <= 3).map(|interval| &interval.launch),
        "active_interval_141_fourth_launch":active_interval_141.iter().find(|interval| interval.ordinal() == 4).map(|interval| &interval.launch),
        "active_interval_141_fifth_launch":active_interval_141.iter().find(|interval| interval.ordinal() == 5).map(|interval| &interval.launch),
        "active_interval_141_sixth_launch":active_interval_141.iter().find(|interval| interval.ordinal() == 6).map(|interval| &interval.launch),
        "active_interval_141_seventh_launch":active_interval_141.iter().find(|interval| interval.ordinal() == 7).map(|interval| &interval.launch),
        "active_delivery_252_claim":active_deliveries.get(&252).map(|(claim, _, _, _)| claim),
        "active_delivery_261_claim":active_deliveries.get(&261).map(|(claim, _, _, _)| claim),
        "active_replay_262_registration":live_replays.get(&262).map(|replay| &replay.reference),
        "active_replay_296_registration":live_replays.get(&296).map(|replay| &replay.reference)});
    if let Some(candidate) = &private_141 {
        evidence["private_interval_141_candidate"] = candidate.inputs.clone();
    }
    if let Some(Quote::FullReplay(quote)) = &quote {
        evidence["full_replay_quote"] = json!({"sizing_reference":quote.reference,"inputs":quote.inputs,
            "whole_tree_bytes":quote.working_disk,"producer_memory_bytes":quote.producer_memory,
            "receipt_disk_bytes":DISK_RECEIPTS,"control_memory_bytes":CONTROLLER_MEMORY,
            "guard_memory_bytes":1u64 << 30,"closed_audit":closed_audit,
            "reserved_audit_memory_bytes":0,"closed_replay":closed_replay});
    }
    if let Some(proof) = suffix {
        evidence["suffix_quote"] = json!({
            "completion":proof,"candidate_cap_bytes":SUFFIX_226_CAP,
            "candidate_memory_max_bytes":SUFFIX_226_CAP,"candidate_cpus":selected,
            "closed_audit":closed_audit,"reserved_audit_memory_bytes":0,"closed_replay":closed_replay,
        });
    }
    if matches!(&quote, Some(Quote::Suffix226Preview)) {
        ensure!(
            before.contains(EXTRACT_226),
            "epoch 226 preview requires live extraction"
        );
        evidence["suffix_preview"] = json!({
            "extraction_reservation_retained":true,
            "candidate_cap_bytes":SUFFIX_226_CAP,"candidate_memory_max_bytes":SUFFIX_226_CAP,
            "candidate_cpus":selected,
        });
    }
    if let Some(Quote::Delivery261(preparation)) = &quote {
        evidence["delivery_quote"] = json!({
            "preparation":preparation,"delivery_memory_max_bytes":num(&delivery, "memory_max_bytes")?,
            "receipt_scratch_maximum_bytes":candidate_disk,"candidate_cpus":selected,
            "closed_audit":closed_audit,"reserved_audit_memory_bytes":0,"closed_replay":closed_replay,
        });
    }
    if delivery_252 {
        evidence["delivery_quote"] = json!({"handoff":closed_replay252,
            "delivery_memory_max_bytes":UPLOAD_261_MEMORY,"receipt_scratch_maximum_bytes":candidate_disk,
            "candidate_cpus":selected,"closed_replay":closed_replay252});
    }
    if let Some(Quote::Replay296(quote)) = &quote {
        evidence["replay_296_quote"] = json!({
            "prior_fit":quote.prior_fit,"repaired_worker":quote.worker,
            "checkpoint_qualification":quote.checkpoint,"placement":quote.placement.reference,
            "candidate_cpus":selected,"exclusive_online_cpus":quote.placement.exclusive_cpus,
            "candidate_disk_bytes":quote.disk,"candidate_memory_bytes":candidate,
            "closed_audit":closed_audit,"reserved_audit_memory_bytes":0,"closed_replay":closed_replay,
        });
    }
    if let Some(Quote::Focused(spec, preflight)) = &quote {
        evidence[spec.quote_key()] = json!({
            "preflight":preflight,"candidate_disk_bytes":candidate_disk,
            "candidate_memory_bytes":candidate,"candidate_cpus":selected,
        });
    }
    if let Some(Quote::NextIntake266(seam)) = &quote {
        evidence["next_266_intake_quote"] = json!({
            "seam":seam,"metadata":Bound::new(NEXT_266_METADATA.0,NEXT_266_METADATA.1),
            "bootstrap_slot":NEXT_266_BOOTSTRAP,"payload_bytes":NEXT_266_PAYLOAD,
            "stage_peak_bytes":candidate_disk,"memory_bytes":candidate,"candidate_cpu":32,
            "exclusive_online_cpus":next_266_group,"single_payload_copy":true,
        });
    }
    if let Some(Quote::SuccessorIntake266(source)) = &quote {
        evidence["successor_266_intake_quote"] = json!({
            "source_window":source,"metadata":Bound::new(SUCCESSOR_266_METADATA.0,SUCCESSOR_266_METADATA.1),
            "bootstrap_slot":SUCCESSOR_266_BOOTSTRAP,"last_slot":SUCCESSOR_266_LAST,
            "payload_bytes":SUCCESSOR_266_PAYLOAD,"stage_peak_bytes":candidate_disk,
            "memory_bytes":candidate,"candidate_cpu":32,"exclusive_online_cpus":next_266_group,
            "single_payload_copy":true,
        });
    }
    if let Some(Quote::AdjacentIntake230(source)) = &quote {
        evidence["adjacent_230_intake_quote"] = json!({
            "readiness":source,"bootstrap_slot":ADJACENT_230_SLOT,"payload_bytes":ADJACENT_230_BYTES,
            "stage_peak_bytes":candidate_disk,"memory_bytes":candidate,"candidate_cpu":48,
            "exclusive_online_cpus":adjacent_copy_group,"single_payload_copy":true,
        });
    }
    if let Some(Quote::Focused(spec, _)) = &quote
        && spec.epoch == 266
    {
        let binding = &mut evidence[spec.quote_key()];
        binding["exclusive_online_cpus"] = json!(overlap_exclusive);
        if spec.unit == PREDECESSOR_266.unit {
            binding["bootstrap_custody"] = json!(spec.predecessor_custody()?);
        } else if spec.unit == WINDOW_266.unit {
            binding["bootstrap_custody"] = json!(spec.window_266_custody()?);
        }
    }
    if first_7871_candidate {
        evidence[FIRST_7871_230.quote_key()]["exclusive_online_cpus"] = json!(bridge_group);
        evidence[FIRST_7871_230.quote_key()]["predecessor_terminal"] = json!(Bound::new(
            Path::new("/var/lib/jetstreamer/horizon230-middle-hourly-second-runtime-v1/terminal.json"),
            "2ed2322cffebec1575bc9ba4dea1894e9e710c3b970c9db504153869f70a9b56"));
    }
    if let (Some(Quote::Focused(spec, _)), Some(predecessor)) = (&quote, checkpoint_predecessor.or(next_predecessor)) {
        let binding = &mut evidence[spec.quote_key()];
        binding["exclusive_online_cpus"] = json!(bridge_group);
        binding["predecessor_terminal"] = json!(predecessor);
        if let Some(failed) = failed_predecessor {
            binding["failed_predecessor_terminal"] = json!(failed);
        }
    }
    deny_authority(&mut evidence);
    Ok(evidence)
}

/// Price the layered Foundation suffix while the caller holds the fleet cadence lock.
pub fn quote_226_suffix(drain_path: &Path, drain_sha256: &str) -> Result<Value> {
    use std::os::unix::fs::DirBuilderExt;

    ensure!(
        unsafe { libc::geteuid() } == 0 && drain_path == Path::new(DRAIN_226),
        "epoch 226 suffix quote scope"
    );
    let proof = Bound::new(drain_path, drain_sha256);
    let root = Path::new(SUFFIX_226_ROOT).join(format!(
        "capacity-witness-{}-{}",
        std::process::id(),
        mono()?
    ));
    trusted_parents(&root)?;
    fs::DirBuilder::new().mode(0o700).create(&root)?;
    let mut native = Native {
        root,
        counter: 0,
        deadline: Some(capacity::add(mono()?, 60_000_000)?),
    };
    let roster = measure(&mut native, None, Some(Quote::Suffix226(proof.clone())))?;
    let fit = &roster["capacity"];
    let suffix = &roster["suffix_quote"];
    Ok(json!({
        "epoch":226,"resource_fit":fit["fits"],
        "disk_shortfall_bytes":fit["disk_shortfall_bytes"],
        "memory_shortfall_bytes":fit["memory_shortfall_bytes"],
        "protected_disk_bytes":fit["protected_existing_disk_bytes"],
        "required_disk_bytes":fit["required_disk_bytes"],
        "candidate_cap_bytes":suffix["candidate_cap_bytes"],
        "candidate_memory_max_bytes":suffix["candidate_memory_max_bytes"],
        "candidate_cpus":suffix["candidate_cpus"],
        "extraction226_terminal":{"completion":proof},
        "capacity_witness":native.root,"roster":roster,"publication_authorized":false,
    }))
}

pub(crate) fn cadence_lock() -> Result<File> {
    let path = Path::new(CADENCE_LOCK);
    trusted_parents(path)?;
    let lock = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = lock.metadata()?;
    ensure!(
        metadata.is_file() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0,
        "Foundation cadence lock custody"
    );
    use std::os::fd::AsRawFd;
    ensure!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "Foundation cadence lock is busy"
    );
    Ok(lock)
}

pub fn run() -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    let mut args = std::env::args_os().skip(1);
    let root = PathBuf::from(
        args.next()
            .context("provide a new Foundation roster evidence directory")?,
    );
    let command = args.next();
    let controller_unit = match command.as_deref() {
        None => None,
        Some(flag)
            if matches!(
                flag.to_str(),
                Some(
                    "--full-replay-quote"
                        | "--full256-quote"
                        | "--full258-quote"
                        | "--full260-quote"
                        | "--delivery252-quote"
                        | "--delivery261-quote"
                        | "--replay296-quote"
                        | "--focused230-quote"
                        | "--hourly230-quote"
                        | "--hourly230-second-quote"
                        | "--first7871-230-quote"
                        | "--v1627-230-quote"
                        | "--next-v1627-230-quote"
                        | "--retry-next-v1627-230-quote"
                        | "--focused258-quote"
                        | "--focused260-quote"
                        | "--overlap266-quote"
                        | "--window266-quote"
                        | "--predecessor266-quote"
                        | "--adjacent230-intake-quote"
                        | "--next266-intake-quote"
                        | "--successor266-intake-quote"
                        | "--adjacent230-replay-quote"
                        | "--focused296-quote"
                        | "--trace296-quote"
                        | "--feature296-quote"
                        | "--suffix226-preview"
                        | "--interval141-third-quote"
                        | "--interval141-fourth-quote"
                        | "--interval141-fifth-quote"
                        | "--interval141-sixth-quote"
                        | "--interval141-seventh-quote"
                )
            ) =>
        {
            None
        }
        Some(flag) if flag == "--as-controller" => Some(
            args.next()
                .context("controller unit")?
                .into_string()
                .map_err(|_| anyhow::anyhow!("invalid controller name"))?,
        ),
        Some(_) => bail!(
            "use --as-controller UNIT, --full-replay-quote, --full256-quote, --full258-quote, --full260-quote, --delivery252-quote, --delivery261-quote, --replay296-quote, --focused230-quote, --hourly230-quote, --hourly230-second-quote, --first7871-230-quote, --v1627-230-quote, --next-v1627-230-quote, --retry-next-v1627-230-quote, --focused258-quote, --focused260-quote, --overlap266-quote, --focused296-quote, --trace296-quote, --feature296-quote, --suffix226-preview, --interval141-third-quote, --interval141-fourth-quote, --interval141-fifth-quote, --interval141-sixth-quote or --interval141-seventh-quote"
        ),
    };
    let synchronize = match args.next() {
        None => false,
        Some(flag) if flag == "--synchronize-peer-guards" && controller_unit.is_some() => true,
        Some(_) => bail!("guard synchronization requires the booked controller"),
    };
    ensure!(
        args.next().is_none()
            && unsafe { libc::geteuid() } == 0
            && root.parent() == Some(Path::new(FILESYSTEM))
            && root
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("horizon262-foundation-roster-")),
        "Foundation roster evidence directory scope"
    );
    trusted_parents(&root)?;
    let _lock = cadence_lock()?;
    fs::DirBuilder::new().mode(0o700).create(&root)?;
    let mut native = Native {
        root,
        counter: 0,
        deadline: Some(capacity::add(mono()?, 60_000_000)?),
    };
    let invocation = controller_unit
        .as_ref()
        .map(|_| std::env::var("INVOCATION_ID"))
        .transpose()?;
    let controller =
        controller_unit
            .as_deref()
            .zip(invocation.as_deref())
            .map(|(unit, invocation)| Controller {
                unit,
                invocation,
                held: false,
            });
    let result = match command.as_deref() {
        Some(flag) if flag == "--full-replay-quote" => full_replay_quote()
            .and_then(|quote| measure(&mut native, None, Some(Quote::FullReplay(quote)))),
        Some(flag) if flag == "--full256-quote" => replay256::quote()
            .and_then(|quote| measure(&mut native, None, Some(Quote::FullReplay(quote)))),
        Some(flag) if flag == "--full258-quote" => replay258::quote()
            .and_then(|quote| measure(&mut native, None, Some(Quote::FullReplay(quote)))),
        Some(flag) if flag == "--full260-quote" => replay260::quote()
            .and_then(|quote| measure(&mut native, None, Some(Quote::FullReplay(quote)))),
        Some(flag) if flag == "--delivery252-quote" => {
            measure(&mut native, None, Some(Quote::Delivery252))
        }
        Some(flag) if flag == "--delivery261-quote" => delivery_261_preparation()
            .and_then(|prep| measure(&mut native, None, Some(Quote::Delivery261(prep)))),
        Some(flag) if flag == "--replay296-quote" => replay_296_quote(&mut native)
            .and_then(|quote| measure(&mut native, None, Some(Quote::Replay296(quote)))),
        Some(flag) if flag == "--next266-intake-quote" => next_266_intake()
            .and_then(|seam| measure(&mut native, None, Some(Quote::NextIntake266(seam)))),
        Some(flag) if flag == "--successor266-intake-quote" => successor_266_intake()
            .and_then(|source| measure(&mut native, None, Some(Quote::SuccessorIntake266(source)))),
        Some(flag) if flag == "--adjacent230-intake-quote" => adjacent_230_intake()
            .and_then(|source| measure(&mut native, None, Some(Quote::AdjacentIntake230(source)))),
        Some(flag)
            if matches!(
                flag.to_str(),
                Some(
                    "--focused230-quote"
                        | "--hourly230-quote"
                        | "--hourly230-second-quote"
                        | "--first7871-230-quote"
                        | "--v1627-230-quote"
                        | "--next-v1627-230-quote"
                        | "--retry-next-v1627-230-quote"
                        | "--adjacent230-replay-quote"
                        | "--focused258-quote"
                        | "--focused260-quote"
                        | "--overlap266-quote"
                        | "--window266-quote"
                        | "--predecessor266-quote"
                        | "--focused296-quote"
                        | "--trace296-quote"
                        | "--feature296-quote"
                )
            ) =>
        {
            let spec = match flag.to_str() {
                Some("--focused230-quote") => &GAP_230,
                Some("--hourly230-quote") => &HOURLY_230,
                Some("--hourly230-second-quote") => &SECOND_HOURLY_230,
                Some("--first7871-230-quote") => &FIRST_7871_230,
                Some("--v1627-230-quote") => &V1627_230,
                Some("--next-v1627-230-quote") => &NEXT_V1627_230,
                Some("--retry-next-v1627-230-quote") => &RETRY_NEXT_V1627_230,
                Some("--adjacent230-replay-quote") => &ADJACENT_230,
                Some("--focused258-quote") => &RESTORE_258,
                Some("--focused260-quote") => &RESTORE_260,
                Some("--overlap266-quote") => &OVERLAP_266,
                Some("--window266-quote") => &WINDOW_266,
                Some("--predecessor266-quote") => &PREDECESSOR_266,
                Some("--trace296-quote") => &TRACE_296,
                Some("--feature296-quote") => &FEATURE_296,
                _ => &LOADER_296,
            };
            spec.preflight()
                .and_then(|receipt| measure(&mut native, None, Some(Quote::Focused(spec, receipt))))
        }
        Some(flag) if flag == "--suffix226-preview" => {
            measure(&mut native, None, Some(Quote::Suffix226Preview))
        }
        Some(flag) if flag == "--interval141-third-quote" => measure(&mut native, None, Some(Quote::Interval141(3))),
        Some(flag) if flag == "--interval141-fourth-quote" => measure(&mut native, None, Some(Quote::Interval141(4))),
        Some(flag) if flag == "--interval141-fifth-quote" => measure(&mut native, None, Some(Quote::Interval141(5))),
        Some(flag) if flag == "--interval141-sixth-quote" => measure(&mut native, None, Some(Quote::Interval141(6))),
        Some(flag) if flag == "--interval141-seventh-quote" => measure(&mut native, None, Some(Quote::Interval141(7))),
        _ => receipt(&mut native, controller),
    };
    match result {
        Ok(evidence) => {
            let fit = save_json(&native.root, "roster.json", &evidence)?;
            if controller_unit.is_some() {
                let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
                let review = json!({"fleet":evidence["fleet"],"observer":evidence["observer"],"boot_id":boot.trim(),
                    "synchronize_peer_guards":synchronize});
                let review_ref = save_json(&native.root, "controller-check-review.json", &review)?;
                let context = json!({"review":review_ref,"foundation_roster":fit});
                let result = if synchronize {
                    peer_window::capture(&mut native, &review, &context)
                } else {
                    peer_window::select_minimum(&mut native, &review, &context, 1)
                };
                let window = match result {
                    Ok(window) => window,
                    Err(error) => {
                        save_json(
                            &native.root,
                            "peer-window-failure.json",
                            &json!({"fit":fit,"error":format!("{error:#}"),"admission_issued":false}),
                        )?;
                        return Err(error);
                    }
                };
                println!(
                    "{}",
                    json!({"fit":fit,"peer_window":window.receipt,"admission_issued":false})
                );
            } else {
                println!("{}", serde_json::to_string(&fit)?);
            }
        }
        Err(error) => {
            save_json(
                &native.root,
                "failure.json",
                &json!({"error":format!("{error:#}"),"admission_issued":false}),
            )?;
            return Err(error);
        }
    }
    Ok(())
}
