//! Account for the PID1 exit watcher on the live epoch 266 retry.
use super::*;

pub(super) const UNIT: &str = "foundation-266-following-retry-pid1-exit-v2.service";
pub(super) const MEMORY: u64 = 256 << 20;
const CPUS: &str = "24";
const IMAGE: (&str, &str) = (
    "/var/lib/jetstreamer/horizon266-following-retry-terminal-v2/horizon266-overlap-compare",
    "e60ac33ee3384391164c14dafffebbfeac6f62cf76ca0f0497019c569b02c150",
);
const LAUNCH: (&str, &str) = (
    "/var/lib/jetstreamer/horizon266-window-114943136-114949777-runtime-v2/cadence-registration.json",
    "8761e063a74800dd3f9471281e707be178609ce1882f10b8655813a716eeb1ab",
);
const EXIT_RECEIPT: &str =
    "/var/lib/jetstreamer/horizon266-following-window-pid1-exit-v2/evidence/pid1-exit.json";

pub(super) fn active(n: &mut Native) -> Result<AuxiliaryOwner> {
    let owner = n.show_fields(UNIT, OWNER_FIELDS)?;
    let memory = live::finite_owner(&owner, UNIT, text(&owner, "InvocationID")?, MEMORY)?;
    let launch = Bound::new(LAUNCH.0, LAUNCH.1);
    let replay = launch.sealed()?;
    ensure!(
        owner["AllowedCPUs"] == CPUS
            && replay["unit"] == FOLLOWING_WINDOW_266_RETRY.unit
            && replay["epoch"] == 266
            && replay["launched"] == true,
        "epoch 266 exit watcher envelope or producer binding changed"
    );
    let image = Bound::new(IMAGE.0, IMAGE.1);
    image.artifact()?;
    let pid = text(&owner, "MainPID")?.parse()?;
    let ticks = process_ticks(pid)?;
    let proc = PathBuf::from(format!("/proc/{pid}"));
    let expected = [
        IMAGE.0,
        "capture-following266-retry-exit",
        LAUNCH.1,
        EXIT_RECEIPT,
    ]
    .join("\0")
        + "\0";
    ensure!(
        fs::read_link(proc.join("exe"))? == image.path
            && metadata_identity(&fs::metadata(proc.join("exe"))?) == identity(&image.path)?
            && fs::read(proc.join("cmdline"))? == expected.as_bytes()
            && process_ticks(pid)? == ticks,
        "epoch 266 exit watcher image or arguments changed"
    );
    Ok(AuxiliaryOwner {
        launch,
        owner,
        memory,
        ticks,
    })
}
