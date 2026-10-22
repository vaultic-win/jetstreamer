//! Legacy watcher units are epoch198 owners only while their real child is busy.
use super::*;
pub(crate) const FULL: &str = "jetstreamer-horizon-audit-epochs182-200-v5.service";
pub(crate) const PLUGIN: &str =
    "jetstreamer-horizon-plugin-receipt-watcher-shard-e-v5-fsync.service";
pub(crate) const UPLOAD: &str =
    "horizon-r2-progressive-epochs101-200-v21-rust-authenticated.service";
const ARCHIVE: &str = "/home/sol/horizon/epoch-198.jet";
fn profile(
    phase: &str,
    unit: &str,
) -> Option<(
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
)> {
    match (phase, unit) {
        ("upload-readback", UPLOAD) => Some((
            "e4e455fbd455483282107652ca37b83d",
            "3283422",
            "/usr/local/lib/jetstreamer/horizon-epoch198-uploader-transition-20261021-v1/upload-progressive.zsh",
            "a0b1fba9a9e456532da9a73e121fd0b4eb7c3e7bc0c8923393b6b3d611419150",
            "/usr/local/lib/jetstreamer/horizon-r2-rust-20261017-v3-auth-only/jetstreamer-r2",
        )),
        ("full-verification", FULL) => Some((
            "4dc3b0631e2646cca4302e6ee8807479",
            "199904",
            "/usr/local/lib/jetstreamer/horizon-parallel-audit-20261001-v7/verify_horizon_range.sh",
            "a64fed21248715b2214292ea961a82afc5367a34b337d35afdbbc48d62c04bed",
            "/usr/local/lib/jetstreamer/horizon-parallel-audit-20261001-v7/verify_archive",
        )),
        ("plugin-verification", PLUGIN) => Some((
            "db3c2cdb0f4f4572ae0cdf0ce64048bf",
            "200292",
            "/usr/local/lib/jetstreamer/horizon-plugin-receipt-watcher-20261001-v1/watch_horizon_plugin_progressive.sh",
            "2b0202515b166ccdf131e86dc66a26b3e461805d56352fe02c5e9bd28be18890",
            "/usr/local/lib/jetstreamer/horizon-plugin-post-update-20261001-v2/horizon_pipeline",
        )),
        _ => None,
    }
}
pub(crate) fn namespace(phase: &str, unit: &str) -> bool {
    profile(phase, unit).is_some()
}
fn child_matches(phase: &str, executable: &str, argv: &[&str], worker: &str) -> bool {
    if executable == "/usr/bin/sha256sum" {
        return phase != "upload-readback"
            && argv.len() == 3
            && argv[1] == "--"
            && argv[2] == ARCHIVE;
    }
    if executable != worker {
        return false;
    }
    match phase {
        "upload-readback" => {
            argv == [
                worker,
                "sync",
                "/home/sol/horizon",
                "--epochs",
                "198-198",
                "--receipt-directory",
                "/home/sol/.jetstreamer-private/r2-receipts",
                "--legacy-part-size-mib",
                "5",
                "--concurrency",
                "4",
            ]
        }
        "full-verification" => {
            argv == [
                worker,
                ARCHIVE,
                "--full",
                "--internal-full",
                "--threads",
                "10",
            ]
        }
        "plugin-verification" => {
            argv == [
                worker,
                "198:198",
                "/home/sol/horizon",
                "--threads",
                "16",
                "--verify-only",
            ]
        }
        _ => false,
    }
}
pub(super) fn immutable(path: &str, digest: &str) -> Result<()> {
    pinned_member(path, digest, false)
}
pub(super) fn legacy160_member(path: &str, digest: &str) -> Result<()> {
    ensure!(
        path == "/usr/local/lib/jetstreamer/horizon-plugin-merged-main-20260930-v1/horizon_pipeline"
            && digest == "9f4abe27011b04d0c33cb3e24d0d9bc14dbce9f46528f22c4bde367af97a7070",
        "foreign legacy160 member"
    );
    pinned_member(path, digest, true)
}
fn pinned_member(path: &str, digest: &str, legacy160: bool) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && if legacy160 {
                m.mode() & 0o7777 == 0o755
            } else {
                m.mode() & 0o222 == 0
            },
        "198 watcher input is not immutable"
    );
    ensure!(
        m.len() <= 512 << 20,
        "198 watcher executable exceeds binary bound"
    );
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    ensure!(
        identity(&file.metadata()?) == identity(&m),
        "198 watcher executable changed at open"
    );
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65536];
    let mut total = 0u64;
    loop {
        let size = file.read(&mut buffer)?;
        if size == 0 {
            break;
        }
        total = total
            .checked_add(size as u64)
            .context("198 executable length overflow")?;
        ensure!(total <= m.len(), "198 executable grew");
        hash.update(&buffer[..size]);
    }
    ensure!(
        total == m.len()
            && identity(&file.metadata()?) == identity(&m)
            && regular_identity(Path::new(path))? == identity(&m)
            && hex_lower(&hash.finalize()) == digest,
        "198 watcher executable changed"
    );
    Ok(())
}
/// Returns the current child start, never an ETA or a verification receipt.
pub(crate) fn child_start(phase: &str, current: &Value) -> Result<Option<u64>> {
    let name = current["Id"].as_str().context("198 watcher unit")?;
    let (iid, pid, script, script_sha, worker) =
        profile(phase, name).context("foreign198 watcher")?;
    ensure!(
        current["InvocationID"] == iid
            && current["MainPID"] == pid
            && current["NRestarts"] == "0"
            && current["ActiveState"] == "active"
            && current["SubState"] == "running"
            && current["ExecStart"]
                .as_str()
                .is_some_and(|s| s.contains(script)),
        "198 watcher owner changed"
    );
    immutable(script, script_sha)?;
    immutable(
        worker,
        match phase {
            "full-verification" => {
                "1ca95efa1b02e45a24409c1431a177c75712177406ccd4220fd26068788b1319"
            }
            "plugin-verification" => {
                "831151d939a51690fedff391a792055e06efadd7ebb83fd46732feddbd07d394"
            }
            "upload-readback" => "7b21414c1c105cefb18f5bf3ca8bb96759c14c529ea42232a70835bdc864b990",
            _ => anyhow::bail!("foreign198 stage"),
        },
    )?;
    scan_children(phase, current, worker, child_matches)
}
pub(super) fn scan_children(
    phase: &str,
    current: &Value,
    worker: &str,
    matches: impl Fn(&str, &str, &[&str], &str) -> bool,
) -> Result<Option<u64>> {
    let name = current["Id"].as_str().context("watcher unit missing")?;
    let group = format!("/system.slice/{name}");
    ensure!(
        current["ControlGroup"] == group,
        "198 watcher cgroup differs"
    );
    let members = fs::read_to_string(format!("/sys/fs/cgroup{group}/cgroup.procs"))?;
    let mut starts = Vec::new();
    let boot = fs::read_to_string("/proc/stat")?
        .lines()
        .find_map(|l| l.strip_prefix("btime ").and_then(|s| s.parse::<u64>().ok()))
        .context("boot clock missing")?;
    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    ensure!(hz > 0, "invalid tick clock");
    for child in members.split_whitespace() {
        let child: u32 = child.parse()?;
        let result = (|| -> Result<Option<u64>> {
            let root = PathBuf::from(format!("/proc/{child}"));
            let before = fs::read_to_string(root.join("stat"))?;
            let command = fs::read(root.join("cmdline"))?;
            let executable = fs::read_link(root.join("exe"))?;
            let argv = command
                .split(|b| *b == 0)
                .filter(|a| !a.is_empty())
                .map(std::str::from_utf8)
                .collect::<std::result::Result<Vec<_>, _>>()?;
            if !matches(phase, executable.to_str().unwrap_or(""), &argv, worker) {
                return Ok(None);
            }
            ensure!(
                fs::read_to_string(root.join("cgroup"))?
                    .lines()
                    .any(|s| s == format!("0::{group}")),
                "198 child left owner cgroup"
            );
            let fields: Vec<_> = before
                .rsplit_once(')')
                .context("198 child stat")?
                .1
                .split_whitespace()
                .collect();
            let ticks = fields.get(19).context("198 child start")?.parse::<u64>()?;
            let after = fs::read_to_string(root.join("stat"))?;
            let after_fields: Vec<_> = after
                .rsplit_once(')')
                .context("198 child restat")?
                .1
                .split_whitespace()
                .collect();
            ensure!(
                after_fields.get(19) == fields.get(19),
                "198 child identity changed"
            );
            Ok(Some(
                boot.checked_mul(1000)
                    .and_then(|n| n.checked_add(ticks.checked_mul(1000)? / (hz as u64)))
                    .context("198 child clock overflow")?,
            ))
        })();
        match result {
            Ok(Some(start)) => starts.push(start),
            Ok(None) => (),
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) => {}
            Err(error) => return Err(error),
        }
    }
    ensure!(
        starts.len() <= if phase == "upload-readback" { 1 } else { 2 },
        "198 watcher has ambiguous concurrent children"
    );
    Ok(starts.into_iter().min())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "root read-only exact progressive198 child proof; no network, sampling or writes"]
    fn root_actual198_progressive_upload_child_is_readable() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let before = unit(UPLOAD).unwrap();
        assert!(child_start("upload-readback", &before).unwrap().is_some());
        assert_eq!(unit(UPLOAD).unwrap(), before);
    }
    #[test]
    fn progressive_upload_requires_exact198_child_not_coordinator_or_other_epoch() {
        let worker = profile("upload-readback", UPLOAD).unwrap().4;
        let argv = [
            worker,
            "sync",
            "/home/sol/horizon",
            "--epochs",
            "198-198",
            "--receipt-directory",
            "/home/sol/.jetstreamer-private/r2-receipts",
            "--legacy-part-size-mib",
            "5",
            "--concurrency",
            "4",
        ];
        assert!(child_matches("upload-readback", worker, &argv, worker));
        for index in [1, 2, 4, 6, 8, 10] {
            let mut bad = argv;
            bad[index] = "other";
            assert!(!child_matches("upload-readback", worker, &bad, worker));
        }
        assert!(!child_matches(
            "upload-readback",
            "/usr/bin/zsh",
            &argv,
            worker
        ));
        assert!(!child_matches(
            "upload-readback",
            "/usr/bin/sha256sum",
            &["sha256sum", "--", ARCHIVE],
            worker
        ));
        assert!(!namespace("upload-readback", FULL));
        assert!(!namespace("full-verification", UPLOAD));
    }
    #[test]
    #[ignore = "root read-only actual198 watcher child sandbox capability; no resources sampled or remote access"]
    fn root_actual198_children_are_scoped_and_readable() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let mut active = 0;
        for (phase, name) in [("full-verification", FULL), ("plugin-verification", PLUGIN)] {
            let before = unit(name).unwrap();
            if child_start(phase, &before).unwrap().is_some() {
                active += 1;
            }
            assert_eq!(unit(name).unwrap(), before);
        }
        assert!(active > 0, "no active198 verifier child");
    }
    #[test]
    fn a_live_watcher_or_other_epoch_is_not_actual198_work() {
        let worker = profile("full-verification", FULL).unwrap().4;
        assert!(child_matches(
            "full-verification",
            worker,
            &[
                worker,
                ARCHIVE,
                "--full",
                "--internal-full",
                "--threads",
                "10"
            ],
            worker
        ));
        assert!(!child_matches(
            "full-verification",
            worker,
            &[worker, "/home/sol/horizon/epoch-199.jet", "--full"],
            worker
        ));
        assert!(!child_matches(
            "full-verification",
            "/usr/bin/bash",
            &[worker, ARCHIVE],
            worker
        ));
        assert!(!namespace("plugin-verification", FULL));
        assert!(child_matches(
            "full-verification",
            "/usr/bin/sha256sum",
            &["sha256sum", "--", ARCHIVE],
            worker
        ));
    }
}
