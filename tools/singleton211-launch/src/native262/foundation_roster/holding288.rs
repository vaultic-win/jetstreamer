//! Account for encrypted epoch 288 custody alongside native Foundation owners.
use super::*;

pub const UNIT: &str = "foundation-288-closed-partial-custody-v1.service";
pub const ROOT: &str = "/var/lib/jetstreamer/horizon288-full-partial-custody-hash-v1";
pub const SOURCE_PROOF: &str = "7b57d40aeeb8103218477a00525e6bf32b771eaa16cbbe8e77da5a6b7de45d75";
pub const TMPFS: &str = "/tmp/foundation-288-closed-custody";
pub const TMPFS_BYTES: u64 = 176 << 30;
pub const MEMORY_BYTES: u64 = 224 << 30;
pub const RECEIPT_BYTES: u64 = 256 << 20;
pub const CPUS: &str = "28-29";
pub(super) const EXCLUSIVE: &str = "28-29,92-93";
pub const ROSTER_SCHEMA: &str = "foundation-epoch288-partial-custody-roster-v1";
pub const ADMISSION_SCHEMA: &str = "foundation-epoch288-partial-custody-admission-v1";
pub const PARK: &str = "holding-foundation-288-partial-park";
pub const ADMISSION: &str = "park-admission.json";
const BINARY: &str =
    "/var/lib/jetstreamer/horizon288-closed-partial-custody-tools-v1/jetstreamer-r2";

pub(super) fn preparation() -> Result<Bound> {
    let source = Bound::new(
        Path::new(ROOT).join("closed-source-binding.json"),
        SOURCE_PROOF,
    );
    let row = source.sealed()?;
    ensure!(
        row["schema"] == "foundation-epoch288-full-partial-source-binding-v1"
            && row["epoch"] == 288
            && row["archive_complete"] == false
            && row["remote_custody_verified"] == false
            && row["retirement_authorized"] == false
            && row["publication_authorized"] == false,
        "foreign or complete epoch 288 source"
    );
    Ok(source)
}

pub(super) fn active(n: &mut Native) -> Result<AuxiliaryOwner> {
    let owner = n.show_fields(UNIT, OWNER_FIELDS)?;
    let iid = text(&owner, "InvocationID")?;
    let memory = live::finite_owner(&owner, UNIT, iid, MEMORY_BYTES)?;
    ensure!(
        owner["AllowedCPUs"] == CPUS,
        "epoch 288 custody CPU set changed"
    );
    let launch_path = Path::new(ROOT).join("park-launch.json");
    let launch = Bound::new(&launch_path, hash(&launch_path)?);
    let launched = launch.sealed()?;
    for key in [
        "Id",
        "InvocationID",
        "MainPID",
        "AllowedCPUs",
        "MemoryMax",
        "MemorySwapMax",
    ] {
        ensure!(
            launched["actual"][key] == owner[key] && !owner[key].is_null(),
            "epoch 288 custody launch changed {key}"
        );
    }
    let admission_ref = binding(&launched["admission"])?;
    let admission = admission_ref.sealed()?;
    let image = binding(&admission["binary"])?;
    let spec = binding(&launched["spec"])?;
    let scope = spec.sealed()?;
    ensure!(
        launched["schema"] == "foundation-epoch288-partial-custody-launch-v1"
            && admission_ref.path == Path::new(ROOT).join(ADMISSION)
            && admission["schema"] == ADMISSION_SCHEMA
            && admission["unit"] == UNIT
            && admission["source"] == json!(preparation()?)
            && admission["retirement_authorized"] == false
            && admission["publication_authorized"] == false
            && image.path == Path::new(BINARY)
            && spec.path == Path::new(ROOT).join("park.json")
            && scope["schema"] == "foundation-epoch288-partial-custody-plan-v1"
            && scope["admission"] == json!(admission_ref),
        "epoch 288 custody capacity enrollment differs"
    );
    image.artifact()?;
    let pid = text(&owner, "MainPID")?.parse()?;
    let ticks = process_ticks(pid)?;
    let proc = PathBuf::from(format!("/proc/{pid}"));
    let exe = proc.join("exe");
    let expected = [
        BINARY,
        PARK,
        spec.path.to_str().context("invalid epoch 288 plan path")?,
        "--spec-sha256",
        &spec.sha256,
        "--self-sha256",
        &image.sha256,
    ]
    .join("\0")
        + "\0";
    ensure!(
        fs::read_link(&exe)? == image.path
            && metadata_identity(&fs::metadata(&exe)?) == identity(&image.path)?
            && fs::read(proc.join("cmdline"))? == expected.as_bytes()
            && process_ticks(pid)? == ticks,
        "epoch 288 custody process or command differs from its admission"
    );
    Ok(AuxiliaryOwner {
        launch,
        owner,
        memory,
        ticks,
    })
}
