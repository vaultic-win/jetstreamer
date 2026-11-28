//! Hold the exact normal epoch-172 node until the matching first guard and post-fit.
use std::{
    env, fs, io,
    os::unix::{fs::MetadataExt, process::CommandExt},
    path::Path,
    process::Command,
    thread,
    time::{Duration, Instant},
};

const UNIT: &str = "horizon-qualify-172-full-half-core-20261120-v1.service";
// The guard treats every executable beneath the worker tree as a historical worker.
const NODE_ALIAS: &str = "/run/horizon-full172-half-core/jetstreamer-node";
const PERMIT: &str = "/run/horizon-full172-half-core/barrier/allow";
const ROOT: &str = "/home/sol/.jetstreamer-private/epoch172-standard-lane-20261110-v1/full-metered-20261120-v1";
const FINGERPRINT: &str = "--cohort-manifest-fingerprint=sha256:b0009b16376d984d14df0d8fce66b696912710f8e4087dc4250231b9dce8c4db";
const BOOTSTRAP: &str = "--snapshot-archive=/home/sol/.jetstreamer-private/epoch172-standard-lane-20261110-v1/private/destination-312c1fcbc12c0fcd3361b5a8fdeb5c442cc76496e8e3a8e9b59aa167bee142c9/work/root-cohort-172-172/run-431228-1794286711430587255/inputs/snapshot-74303701-A4a2VMV6mmHxSGDDwizEB8AzfKymoy9QeFC8nXQeZ3BR.tar.zst";

fn exact_argv() -> Vec<String> {
    vec![
        format!("{ROOT}/runtime/jetstreamer-node"), "172".into(), format!("{ROOT}/ledger"),
        "--verify".into(), "--root-checkpoint-cohort".into(),
        format!("--cohort-manifest={ROOT}/runtime/preflight-172-v4.json"),
        FINGERPRINT.into(), BOOTSTRAP.into(),
    ]
}

fn iid_ok(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && id.bytes().any(|b| b != b'0')
}

fn permit(path: &Path, id: &str) -> io::Result<bool> {
    let file = match fs::OpenOptions::new().read(true).open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };
    let m = file.metadata()?;
    if !m.is_file() || m.uid() != 0 || m.nlink() != 1 || m.mode() & 0o7777 != 0o444
        || m.len() != 32 || !fs::symlink_metadata(path)?.is_file()
    {
        return Err(io::Error::other("invalid permit custody"));
    }
    let bytes = io::read_to_string(file)?;
    if bytes != id { return Err(io::Error::other("permit belongs to another invocation")); }
    Ok(true)
}

fn main() -> io::Result<()> {
    let args: Vec<_> = env::args().skip(1).collect();
    if args != exact_argv() { return Err(io::Error::other("unexpected canonical command")); }
    let id = env::var("INVOCATION_ID").map_err(io::Error::other)?;
    if !iid_ok(&id)
        || fs::read_to_string("/proc/self/cgroup")?.trim() != format!("0::/system.slice/{UNIT}")
        || fs::metadata("/proc/self")?.uid() != 1001 || fs::metadata("/proc/self")?.gid() != 1003
    { return Err(io::Error::other("unexpected gate identity")); }
    // The measured root scan and second capacity fit can both run before this deadline.
    let deadline = Instant::now() + Duration::from_secs(600);
    while Instant::now() < deadline {
        if permit(Path::new(PERMIT), &id)? {
            return Err(Command::new(NODE_ALIAS).arg0(&args[0]).args(&args[1..]).exec());
        }
        thread::sleep(Duration::from_millis(200));
    }
    Err(io::Error::other("guard and post-fit permit expired"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn invocation_identity() {
        assert!(iid_ok("0123456789abcdef0123456789abcdef"));
        for id in ["", "00000000000000000000000000000000", "0123456789abcdef0123456789abcdeG"] {
            assert!(!iid_ok(id));
        }
    }
    #[test] fn canonical_command() {
        let a = exact_argv();
        assert_eq!(a.len(), 8);
        assert_eq!(&a[1], "172");
        assert!(a.contains(&"--verify".into()) && a.contains(&"--root-checkpoint-cohort".into()));
        assert!(a.last().unwrap().contains("snapshot-74303701-"));
    }
}
