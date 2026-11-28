//! Price the workerless epoch 226 assembly while retaining both private segments.
use super::*;

pub const UNIT: &str = "horizon-qualify-226-checkpoint-continuation-assemble-v1.service";
pub const GUARD: &str = "horizon-guard-226-checkpoint-continuation-assemble-v1";
pub const GUARD_SERVICE: &str = "horizon-guard-226-checkpoint-continuation-assemble-v1.service";
pub const TIMER: &str = "horizon-guard-226-checkpoint-continuation-assemble-v1.timer";
pub const ROOT: &str = "/home/ubuntu/.jetstreamer-private/checkpoint-continuation-226-assemble-v1";
pub const STATE: &str = "/var/lib/jetstreamer/horizon226-assembly-v1";
pub const CPUS: &str = "16-23";
pub const GUARD_CPU: &str = "14";
pub(super) const EXCLUSIVE: &str = "14,16-23,78,80-87";
pub const CAP: u64 = 160 << 30;
pub const RECEIPTS: u64 = 256 << 20;
pub const MEMORY: u64 = CAP;
pub const ROSTER_SCHEMA: &str = "foundation-epoch226-private-assembly-roster-v1";
pub const REGISTRATION_SCHEMA: &str = "foundation-epoch226-private-assembly-launch-v1";
pub const NODE: (&str, &str) = (
    "/run/foundation-epoch226-release.y35rokj7/jetstreamer-node",
    "7e17105ad9429fccbeb53dcd38650adb3f469bc1d3fe797360afff2cc7379ded",
);
pub const PREFLIGHT: (&str, &str) = (
    "/var/lib/jetstreamer/horizon226-assembly-static-v1/preflight.json",
    "9fe6a8d50a28c165be4a8c51b9411d861a4be38fd7f75e25f0f09705654b4789",
);
pub const SOURCES: (&str, &str) = (
    "/var/lib/jetstreamer/horizon226-suffix-v1/assembly-source-handoff.json",
    "0a3092438c7c4a521def4ebd8ffef42bf87299b01e587c94a14411a39f422a08",
);

pub(super) fn preparation(n: &mut Native) -> Result<Bound> {
    let preflight = Bound::new(PREFLIGHT.0, PREFLIGHT.1);
    let proof = preflight.sealed()?;
    let sources = Bound::new(SOURCES.0, SOURCES.1);
    let handoff = sources.sealed()?;
    ensure!(
        suffix226::pending_reservation(n)? == (0, 0)
            && proof["schema"] == "foundation-epoch226-private-assembly-static-v1"
            && proof["sources"] == json!(sources)
            && proof["node"] == json!(Bound::new(NODE.0, NODE.1))
            && proof["unit"] == UNIT
            && proof["run_root"] == ROOT
            && proof["scope_sha256"] == handoff["stage_sha256"]
            && proof["sandbox"]["readonly_segments_verified"] == true
            && proof["sandbox"]["fresh_private_root"] == true
            && proof["static_guard_check"]["validated"] == true
            && proof["admission_issued"] == false
            && handoff["stage"]["operation"] == "assemble"
            && handoff["publication_authorized"] == false,
        "epoch 226 assembly inputs or verified suffix drain differ"
    );
    let root = Path::new(ROOT);
    let info = root.symlink_metadata()?;
    ensure!(
        root.canonicalize()? == root
            && info.is_dir()
            && info.uid() == 1000
            && info.mode() & 0o777 == 0o700
            && fs::read_dir(root)?.next().is_none(),
        "epoch 226 assembly run directory is not empty and private"
    );
    Ok(preflight)
}

pub(super) fn live(n: &mut Native) -> Result<LiveReplay> {
    let path = Path::new(STATE).join("cadence-registration.json");
    let reference = Bound::new(&path, hash(&path)?);
    let row = reference.sealed()?;
    let admission_ref = binding(&row["admission"])?;
    let admission = admission_ref.sealed()?;
    let plan = binding(&row["plan"])?.sealed()?;
    let guard_ref = binding(&row["guard_plan"])?;
    let guard = guard_ref.sealed()?;
    let sample_ref = binding(&row["active_guard"])?;
    let sample = sample_ref.json()?;
    let floor = num(&guard, "minimum_free_bytes")?;
    let sources = Bound::new(SOURCES.0, SOURCES.1);
    let handoff = sources.sealed()?;
    let owner = n.show_fields(UNIT, OWNER_FIELDS)?;
    let clock = n.show_fields(TIMER, "ActiveState,InvocationID,Unit")?;
    let guard_owner = n.show_fields(GUARD_SERVICE, "AllowedCPUs,MemoryMax")?;
    let pid = text(&owner, "MainPID")?.parse()?;
    let invocation = text(&row, "invocation_id")?;
    let memory = live::finite_owner(&owner, UNIT, invocation, MEMORY)?;
    let ticks = process_ticks(pid)?;
    let node = Bound::new(NODE.0, NODE.1);
    node.artifact()?;
    let proc = PathBuf::from(format!("/proc/{pid}"));
    let argv = [
        NODE.0.to_owned(),
        "226".into(),
        format!("{ROOT}/ledger"),
        "--verify".into(),
        format!("--checkpoint-continuation-plan={STATE}/plan.json"),
        format!(
            "--checkpoint-continuation-plan-sha256={}",
            text(&row["plan"], "sha256")?
        ),
    ]
    .join("\0")
        + "\0";
    ensure!(
        row["schema"] == REGISTRATION_SCHEMA
            && row["unit"] == UNIT
            && row["run_root"] == ROOT
            && row["epoch"] == 226
            && row["main_pid"] == pid
            && row["node_path"] == NODE.0
            && row["assembly_only_no_replay"] == true
            && row["launched"] == true
            && row["publication_authorized"] == false
            && admission["operation"] == "assemble"
            && admission["admitted"] == true
            && admission["handoff"] == json!(sources)
            && admission["stage_sha256"] == handoff["stage_sha256"]
            && admission["publication_authorized"] == false
            && plan["admission"] == json!(admission_ref)
            && plan["stage"] == handoff["stage"]
            && guard["unit"] == UNIT
            && guard["worker_root"] == ROOT
            && guard["maximum_root_physical_bytes"] == CAP
            && sample["plan_sha256"] == guard_ref.sha256
            && sample["producer_invocation_id"] == invocation
            && sample["producer"]["pid"] == pid
            && sample["trip_reason"].is_null()
            && sample["workers"] == json!([])
            && clock["ActiveState"] == "active"
            && clock["Unit"] == GUARD_SERVICE
            && clock["InvocationID"] == row["launch_token"]["guard_timer_invocation"]
            && owner["AllowedCPUs"] == CPUS
            && guard_owner["AllowedCPUs"] == GUARD_CPU
            && guard_owner["MemoryMax"] == "1073741824"
            && fs::read_link(proc.join("exe"))? == node.path
            && metadata_identity(&fs::metadata(proc.join("exe"))?) == identity(&node.path)?
            && fs::read(proc.join("cmdline"))? == argv.as_bytes()
            && process_ticks(pid)? == ticks,
        "epoch 226 live assembly differs from its admitted source or guard"
    );
    Ok(LiveReplay {
        reference,
        unit: UNIT,
        owner,
        memory,
        ticks,
        guard_booking: json!({"sample":sample_ref,"floor_bytes":floor,"cap_bytes":CAP}),
        receipt_disk: RECEIPTS,
    })
}

pub(super) fn launched_since_sample(
    replay: &LiveReplay,
    fleet: &Bound,
    observer: &Bound,
    booking: &Bound,
) -> Result<Bound> {
    let launch = replay.reference.sealed()?;
    let admission = binding(&launch["admission"])?.sealed()?;
    let reference = binding(&admission["capacity"])?;
    let roster = reference.sealed()?;
    ensure!(
        reference.path == Path::new(STATE).join("accepted-capacity.json")
            && roster["schema"] == ROSTER_SCHEMA
            && roster["capacity"]["fits"] == true
            && roster["fleet"] == json!(fleet)
            && roster["observer"] == json!(observer)
            && roster["booking"] == json!(booking)
            && roster["active_assembly_226_registration"].is_null()
            && roster["assembly_226_quote"]["sources"] == admission["handoff"],
        "epoch 226 assembly was admitted against another accepted fleet"
    );
    Ok(reference)
}
