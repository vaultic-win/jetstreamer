//! The original continuation is drained. Its sealed release only admits its old invocation.
use super::*;

const ROOT: &str = "/home/sol/.jetstreamer-private/checkpoint-continuation-154-20261029-v1";
const STEM: &str = "epoch-154-bafyreib4sohvq2t25yrbsbslhdc6figmuounoadv6h7qyhnuf62wrecuje-mainnet";
const UNIT: &str = "horizon-qualify-154-checkpoint-continuation-20261029-v1.service";
const CONTROLLER: &str = "horizon-native154-suffix-control-20261029-v1.service";
const INVOCATION: &str = "edc1d1915dcb4c2785d2cf24cdaa10c2";

pub(crate) fn is_index(t: &Target) -> bool {
    let relative = |suffix: &str| {
        Path::new(ROOT)
            .join("ledger/compact-indexes/154")
            .join(format!("{STEM}-{suffix}.index"))
    };
    let s = &t.identity;
    t.epoch == 154
        && (s.dev, s.uid, s.gid, s.mode, s.nlink) == (64512, 1001, 1003, 0o100600, 1)
        && ((t.path == relative("cid-to-offset-and-size")
            && (s.ino, s.len, s.blocks) == (99157544, 7397645762, 14448552))
            || (t.path == relative("slot-to-cid")
                && (s.ino, s.len, s.blocks) == (99157543, 11815431, 23080)))
}

pub(crate) fn lock() -> Result<File> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/home/sol/.jetstreamer-private/checkpoint-continuation-154.lock")?;
    let s = f.metadata()?;
    ensure!(
        (s.dev(), s.ino(), s.uid(), s.gid(), s.mode(), s.nlink())
            == (64512, 93726303, 1001, 1003, 0o100600, 1),
        "different original continuation lock"
    );
    ensure!(
        unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "original continuation lock busy"
    );
    Ok(f)
}

fn pinned(path: &str, sha256: &str) -> Result<Vec<u8>> {
    bound(
        &Bound {
            path: path.into(),
            sha256: sha256.into(),
        },
        LIMIT,
    )
}

pub(crate) fn check_owners() -> Result<()> {
    let terminal: Value = serde_json::from_slice(&pinned(
        "/var/lib/jetstreamer/horizon-native154-suffix-20261029-v1/terminal.json",
        "ec1f4455f70444f63602c7b26700c0eaee8d7528f2f00befb6fd327c9b19b16b",
    )?)?;
    let release: Value = serde_json::from_slice(&pinned(
        "/usr/local/lib/jetstreamer/horizon-native154-suffix-release-20261029-v1/release.json",
        "3469292ede4a1c1519aedd443e9b127e373524493e50f95eefcc604dd34fc7d9",
    )?)?;
    let ready: Value = serde_json::from_slice(&pinned(
        "/home/sol/.jetstreamer-private/checkpoint-continuation-154-launch-20261029-v1/ready.json",
        "b8fab6cafc23d693f3cc7d1a29ec4a5b41ec1e05cf9e62f04861040031dd8a48",
    )?)?;
    let ended: Value = serde_json::from_slice(&pinned(
        "/var/lib/jetstreamer/horizon-original154-unused-future-DATA-20261110-v1/edc1d1915dcb4c2785d2cf24cdaa10c2/ended.json",
        "81701d992a014f2cd15060b60c4f94362dc3f100b7ebffdc6796bf93da39b0d6",
    )?)?;
    ensure!(
        terminal["control_group_drained"] == true
            && terminal["producer_invocation_id"] == INVOCATION
            && ready["invocation_id"] == INVOCATION
            && release["producer_invocation_id"] == INVOCATION
            && ended["original_invocation_id"] == INVOCATION
            && ended["unused_future_DATA_ended_bytes"] == 352187318272_u64,
        "different ended 154 continuation"
    );
    let linked = format!("/run/systemd/system/{UNIT}");
    let fragment =
        format!("/usr/local/lib/jetstreamer/horizon-native154-suffix-execution-20261029-v1/{UNIT}");
    ensure!(
        fs::canonicalize(&linked)? == Path::new(&fragment),
        "154 linked unit replaced"
    );
    pinned(
        &fragment,
        "4bee1f80a48a07c54e7303bc8c7f272c337318492dc1472ce9f22668ab2edcd8",
    )?;
    pinned(
        "/usr/local/lib/jetstreamer/horizon-native154-suffix-control-tools-20261029-v1/jetstreamer-native154-suffix-control",
        "166f1ed64aed6eac023da39321a88e5fb7b7a5abd4ee38b64568f58ce510f2b8",
    )?;
    let defs = Command::new("/usr/bin/rg")
        .args([
            "--no-ignore",
            "--hidden",
            "--follow",
            "--files-with-matches",
            "--fixed-strings",
            "-e",
            ROOT,
            "-e",
            "jetstreamer-native154-suffix-control wrapper",
            "-e",
            "horizon-native154-suffix-control-20261029-v1",
            "/etc/systemd/system",
            "/run/systemd/system",
            "/run/systemd/transient",
            "/usr/lib/systemd/system",
        ])
        .output()?;
    ensure!(
        defs.status.success()
            && defs.stderr.is_empty()
            && std::str::from_utf8(&defs.stdout)?.trim() == linked,
        "staged 154 owner set changed"
    );
    for (unit, state) in [(UNIT, "failed"), (CONTROLLER, "inactive")] {
        let out = Command::new("/usr/bin/systemctl").args(["show","--all","-p","Id,LoadState,ActiveState,SubState,MainPID,ControlPID,Job,Triggers,TriggeredBy,ExecStart,InvocationID,DropInPaths,NeedDaemonReload,FragmentPath","--",unit]).output()?;
        ensure!(
            matches!(out.status.code(), Some(0 | 4)) && out.stderr.is_empty(),
            "cannot inspect {unit}"
        );
        let lines = std::str::from_utf8(&out.stdout)?;
        let has = |field: &str| lines.lines().any(|s| s == field);
        ensure!(
            has(&format!("Id={unit}"))
                && has(&format!("ActiveState={state}"))
                && has("MainPID=0")
                && has("ControlPID=0")
                && has("Job=")
                && has("Triggers=")
                && has("TriggeredBy=")
                && has("DropInPaths="),
            "154 owner changed: {unit}"
        );
        if unit == UNIT {
            ensure!(has("SubState=failed") && has(&format!("InvocationID={INVOCATION}")) && has(&format!("FragmentPath={linked}")) && has("NeedDaemonReload=no") && has("LoadState=loaded")
             && lines.lines().find(|s|s.starts_with("ExecStart=")).is_some_and(|s|s.contains("jetstreamer-native154-suffix-control wrapper /usr/local/lib/jetstreamer/horizon-native154-suffix-policy-20261030-v1/policy.json --policy-sha256 170f05aa2ac0ddfcb4b0f35478fdc510970e0b171c7d80a03b0140f8bf15ecd7 --self-sha256 166f1ed64aed6eac023da39321a88e5fb7b7a5abd4ee38b64568f58ce510f2b8 ;")), "154 linked wrapper changed");
        } else {
            ensure!(
                has("SubState=dead") && has("LoadState=not-found") && has("FragmentPath="),
                "native 154 controller is staged"
            );
        }
    }
    Ok(())
}
