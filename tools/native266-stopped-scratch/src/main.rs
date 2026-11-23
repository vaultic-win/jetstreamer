//! Read-only check of the original guard-stopped cad28704 guest. The controller
//! separately binds its completed stop, live fleet, process census and service grant.
#[cfg_attr(feature = "stopped-v210", path = "profile_v210.rs")]
#[cfg_attr(
    all(feature = "stopped-v207", not(feature = "stopped-v210")),
    path = "profile_v207.rs"
)]
#[cfg_attr(
    all(
        feature = "stopped-v194",
        not(any(feature = "stopped-v207", feature = "stopped-v210"))
    ),
    path = "profile_v194.rs"
)]
#[cfg_attr(
    not(any(
        feature = "stopped-v194",
        feature = "stopped-v207",
        feature = "stopped-v210"
    )),
    path = "profile_v169.rs"
)]
mod profile;
use profile::*;
mod closure;
mod controller;
mod journal;
mod preservation;
mod retained;
mod retirement;

use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const SNAPSHOT: &str = "snapshot-114910768-HnePfSpTtWaPDFx9RrPeuamDZREhoUXa7xpK6fbtPGyK.tar.zst";
const DIRECTORY: i32 = 0o200000;
const NOFOLLOW: i32 = 0o400000;
const PATH_ONLY: i32 = 0o10000000;

fn need(ok: bool, message: &str) -> io::Result<()> {
    if ok {
        Ok(())
    } else {
        Err(io::Error::other(message))
    }
}

fn open(path: &Path, flags: i32) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(flags | NOFOLLOW)
        .open(path)
}

fn check_fd(file: &File, directory: bool) -> io::Result<fs::Metadata> {
    let m = file.metadata()?;
    let info = fs::read_to_string(format!("/proc/self/fdinfo/{}", file.as_raw_fd()))?;
    let mount = info
        .lines()
        .find_map(|s| s.strip_prefix("mnt_id:"))
        .and_then(|s| s.trim().parse::<u64>().ok());
    need(
        mount == Some(MOUNT)
            && m.dev() == DEVICE
            && m.uid() == 1000
            && m.gid() == 1000
            && m.mode() & 0o022 == 0,
        "unexpected mount, owner, or permissions",
    )?;
    need(
        if directory {
            m.is_dir()
        } else {
            m.is_file() && m.nlink() == 1
        },
        "unexpected file type or link",
    )?;
    Ok(m)
}

fn dir_name(parts: &[&str]) -> bool {
    match parts {
        ["bound-bootstrap" | "bound-worker"] => true,
        [RUNTIME] | [RUNTIME, "genesis-unpacked" | "accounts-state" | "unpacked"] => true,
        [RUNTIME, "accounts-state", "0" | "1" | "2" | "3"] => true,
        [RUNTIME, "unpacked", "accounts" | "snapshots"] => true,
        [RUNTIME, "unpacked", "snapshots", "114910768"] => true,
        _ => false,
    }
}

fn leaf_name(parts: &[&str], name: &str) -> bool {
    let numeric = |s: &str| !s.is_empty() && s.len() <= 20 && s.bytes().all(|x| x.is_ascii_digit());
    match parts {
        ["bound-bootstrap"] => name == SNAPSHOT,
        ["bound-worker"] => name == "historical-worker",
        [RUNTIME, "genesis-unpacked"] => name == "genesis.bin",
        [RUNTIME, "unpacked"] => name == "version",
        [RUNTIME, "unpacked", "snapshots"] => name == "status_cache",
        [RUNTIME, "unpacked", "snapshots", "114910768"] => name == "114910768",
        [RUNTIME, "unpacked", "accounts"] | [RUNTIME, "accounts-state", "0" | "1" | "2" | "3"] => {
            name.split_once('.')
                .is_some_and(|(a, b)| numeric(a) && numeric(b))
        }
        _ => false,
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
struct Counts {
    files: u64,
    directories: u64,
    logical: u64,
    allocated_files: u64,
}

fn inspect(dir: &File, relative: &Path, counts: &mut Counts, until: Instant) -> io::Result<()> {
    let parent = PathBuf::from(format!("/proc/self/fd/{}", dir.as_raw_fd()));
    let parts = relative
        .iter()
        .map(OsStr::to_str)
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| io::Error::other("directory name"))?;
    for entry in fs::read_dir(&parent)? {
        need(
            Instant::now() < until && counts.files + counts.directories < MAX_ENTRIES,
            "phase bound",
        )?;
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_str().ok_or_else(|| io::Error::other("leaf name"))?;
        let path = parent.join(name);
        let fd = open(&path, PATH_ONLY)?;
        if fd.metadata()?.is_dir() {
            let mut child = parts.clone();
            child.push(name);
            need(dir_name(&child), "unexpected derived directory")?;
            let id = check_fd(&fd, true)?.ino();
            let sub = open(&path, DIRECTORY)?;
            need(
                check_fd(&sub, true)?.ino() == id,
                "rebound derived directory",
            )?;
            counts.directories += 1;
            inspect(&sub, &relative.join(name), counts, until)?;
        } else {
            let m = check_fd(&fd, false)?;
            need(leaf_name(&parts, name), "unexpected derived file")?;
            counts.files += 1;
            counts.logical += m.len();
            counts.allocated_files += m.blocks() * 512;
        }
    }
    Ok(())
}

fn run() -> io::Result<()> {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    if args == [OsStr::new("--check-terminal")] {
        controller::check_terminal()?;
    }
    if args == [OsStr::new("--retire")] || args == [OsStr::new("--close")] {
        return controller::run(args[0] == "--close");
    }
    need(
        args == [OsStr::new("--check-only")] || args == [OsStr::new("--check-terminal")],
        "expected --check-only",
    )?;
    let parent = Path::new(preservation::RUN).join("scratch/.historical-runtime");
    need(parent.canonicalize()? == parent, "noncanonical parent")?;
    let base = open(&parent, DIRECTORY)?;
    need(
        check_fd(&base, true)?.ino() == PARENT_INODE,
        "original producer directory",
    )?;
    let tree = open(
        &PathBuf::from(format!("/proc/self/fd/{}", base.as_raw_fd())).join(CHILD),
        DIRECTORY,
    )?;
    need(
        check_fd(&tree, true)?.ino() == CHILD_INODE,
        "original derived root",
    )?;
    let retained = preservation::originals()?;
    let mut counts = Counts::default();
    inspect(
        &tree,
        Path::new(""),
        &mut counts,
        Instant::now() + Duration::from_secs(240),
    )?;
    need(counts == EXPECTED, "stopped inventory differs")?;
    need(
        parent.join(CHILD).symlink_metadata()?.ino() == tree.metadata()?.ino(),
        "rebound root",
    )?;
    for member in &retained {
        need(
            preservation::Stamp::from(&member.path.symlink_metadata()?) == member.original,
            "retained file rebound",
        )?;
    }
    println!(
        "{{\"files\":{},\"directories\":{},\"file_bytes\":{},\"allocated_file_bytes\":{},\"partial_sha256\":\"{}\",\"state_sha256\":\"{}\"}}",
        counts.files,
        counts.directories,
        counts.logical,
        counts.allocated_files,
        retained[0].sha256,
        retained[1].sha256
    );
    Ok(())
}
fn main() -> io::Result<()> {
    run()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_known_appendvec_layout_and_names() {
        for n in ["", "1", "1.2.3", "-1.2", "184467440737095516160.0"] {
            assert!(!leaf_name(&[RUNTIME, "accounts-state", "0"], n));
        }
        assert!(leaf_name(
            &[RUNTIME, "accounts-state", "3"],
            "114747368.1203181467"
        ));
        assert!(!leaf_name(&[RUNTIME, "accounts-state", "4"], "1.0"));
        assert!(!dir_name(&[RUNTIME, "unpacked", "snapshots", "114910769"]));
        assert!(!dir_name(&["archives"]));
    }
}

#[cfg(test)]
mod interrupted;
