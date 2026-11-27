//! Price the exact prepared epoch 256 singleton against the shared live roster.
use super::*;

pub(super) const CPUS: &str = "48-55";
pub(super) const ROSTER_SCHEMA: &str = "foundation-epoch256-full-replay-roster-binding-v1";
const EPOCH: u64 = 256;
const UNIT: &str = "horizon-qualify-256-singleton-v1.service";
const ROOT: &str = "/home/ubuntu/.jetstreamer-private/qualification-256-singleton-v1";
const HANDOFF: (&str, &str) = (
    "/var/lib/jetstreamer/horizon256-full-replay-runtime-v1/preparation.json",
    "8449e033363bc956a3ae15c3b213183acb5e3ff40abf2d7794871b978a21e4f7",
);
const CAP: u64 = 514_359_320_727;
const MEMORY: u64 = 160 << 30;
const BOOTSTRAP_SLOT: u64 = 110_591_110;
const CHECKPOINT_SLOT: u64 = 111_022_650;

fn check_bootstrap(bootstrap: &Value, restored: &Value) -> Result<()> {
    let path = Path::new(text(bootstrap, "path")?);
    let (device, inode, length, uid, mode, _, mtime, mtime_ns, ctime, ctime_ns) = identity(path)?;
    ensure!(
        uid == 1000
            && mode & 0o022 == 0
            && bootstrap["device"] == device
            && bootstrap["inode"] == inode
            && bootstrap["size"] == length
            && bootstrap["mtime_ns"].as_i64().map(i128::from)
                == Some(i128::from(mtime) * 1_000_000_000 + i128::from(mtime_ns))
            && bootstrap["ctime_ns"].as_i64().map(i128::from)
                == Some(i128::from(ctime) * 1_000_000_000 + i128::from(ctime_ns))
            && bootstrap["generation"] == 1639314144411280u64
            && bootstrap["generation"] == restored["snapshot_generation"]
            && bootstrap["sha256"] == restored["snapshot_sha256"],
        "epoch 256 staged bootstrap differs from the qualified restore"
    );
    Ok(())
}

pub(super) fn quote() -> Result<FullReplayQuote> {
    let reference = Bound::new(HANDOFF.0, HANDOFF.1);
    let handoff = reference.sealed()?;
    let inputs = binding(&handoff["inputs"])?;
    let source = inputs.sealed()?;
    let profile_ref = binding(&handoff["profile"])?;
    let profile = profile_ref.sealed()?;
    let namespace = binding(&handoff["namespace"])?.sealed()?;
    let guard_plan = binding(&handoff["guard_plan"])?;
    let guard = guard_plan.sealed()?;
    let validation = binding(&handoff["guard_validation"])?.sealed()?;
    // These durable invocation receipts are root-writable. Read them through
    // their digest bindings, which also check ownership and file identity.
    let restore_ref = binding(&source["restore"])?;
    trusted_parents(&restore_ref.path)?;
    let restore = restore_ref.json()?;
    let restored_ref = binding(&restore["native_result"])?;
    trusted_parents(&restored_ref.path)?;
    let restored = restored_ref.json()?;
    let capacity = &handoff["capacity_model"];
    ensure!(
        handoff["schema"] == "foundation-epoch256-full-static-handoff-v1"
            && handoff["epoch"] == EPOCH
            && handoff["admission_issued"] == false
            && handoff["replay_launched"] == false
            && handoff["publication_authorized"] == false
            && source["schema"] == "foundation-epoch256-full-replay-input-envelope-v1"
            && source["epoch"] == EPOCH
            && source["full_replay_admitted"] == false
            && source["publication_authorized"] == false
            && source["capacity_model"] == *capacity
            && source["terminal_checkpoint"]["slot"] == CHECKPOINT_SLOT
            && source["terminal_checkpoint"]["generation"] == 1639566907008841u64
            && capacity["working_tree_cap_bytes"] == CAP
            && capacity["producer_memory_max_bytes"] == MEMORY
            && capacity["receipt_reserve_bytes"] == DISK_RECEIPTS
            && capacity["guard_memory_max_bytes"] == 1u64 << 30
            && capacity["cpus"] == CPUS
            && profile["unit"] == UNIT
            && profile["worker_root"] == ROOT
            && profile["allowed_cpus"] == CPUS
            && profile["inputs"] == json!(inputs)
            && profile["static_guard_plan"] == json!(guard_plan)
            && profile["maximum_memory_bytes"] == MEMORY
            && profile["maximum_root_physical_bytes"] == CAP
            && profile["readonly_bindings"] == source["readonly_bindings"]
            && namespace["profile"] == json!(profile_ref)
            && namespace["host_guard_sees_empty_placeholders"] == true
            && namespace["private_state_writable"] == true
            && namespace["worker_started"] == false
            && guard["unit"] == UNIT
            && guard["worker_root"] == ROOT
            && guard["maximum_root_physical_bytes"] == CAP
            && validation["unit"] == UNIT
            && validation["validated"] == true
            && validation["producer_signaled"] == false
            && validation["plan_sha256"] == guard_plan.sha256
            && restore["schema"] == "foundation-epoch256-native-restore-ram-qualification-v1"
            && restore["epoch"] == EPOCH
            && restore["slot"] == BOOTSTRAP_SLOT
            && restored["slot"] == BOOTSTRAP_SLOT
            && restored["replay_entries_sent"] == 0
            && restored["matched_pinned_accounts_root"] == true
            && restored["worker_shutdown_succeeded"] == true
            && restored["worker_sha256"] == source["worker"]["sha256"],
        "epoch 256 replay, restored checkpoint, or namespace evidence differs"
    );
    binding(&source["node"])?.artifact()?;
    binding(&source["worker"])?.artifact()?;
    binding(&profile["guard"])?.artifact()?;
    binding(&source["manifest"])?.sealed()?;
    let overrides = binding(&source["slot_ranges_override"])?.sealed()?;
    let ranges = overrides["entries"]
        .as_array()
        .context("epoch 256 slot-range overrides")?;
    let binds = source["readonly_bindings"]
        .as_array()
        .context("epoch 256 read-only projections")?;
    ensure!(binds.len() == 4, "epoch 256 projection count changed");
    check_bootstrap(&source["bootstrap"], &restored)?;
    for artifact in ranges.iter().chain(&binds[1..]) {
        Bound::new(text(artifact, "path")?, text(artifact, "sha256")?).artifact()?;
    }
    Ok(FullReplayQuote {
        epoch: EPOCH,
        reference,
        inputs,
        working_disk: CAP,
        producer_memory: MEMORY,
    })
}
