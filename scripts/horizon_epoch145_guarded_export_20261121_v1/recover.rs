//! Recover only the empty, already charged inode from the first private run.
use super::*;
const OLD: &str = "81c627e75fb340bc991a31958938401f";
const INODE: u64 = 103237059;
fn receipt(name: &str, digest: &str) -> Result<Value> {
    custody::evidence(&Bound {
        path: Path::new(BASE).join("state").join(OLD).join(name),
        sha256: digest.into(),
    })
}
fn check(m: &fs::Metadata) -> Result<()> {
    ensure!(
        m.is_file()
            && m.nlink() == 1
            && m.uid() == 0
            && m.gid() == 0
            && m.mode() & 0o777 == 0o600
            && m.dev() == 64512
            && m.ino() == INODE
            && m.len() == 0
            && m.blocks() * 512 == 105611071488,
        "predecessor output identity, allocation or logical length changed"
    );
    Ok(())
}
pub fn predecessor(root: &Path) -> Result<Option<PathBuf>> {
    let entries = fs::read_dir(root)?
        .map(|e| e.map(|v| v.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    if entries.is_empty() {
        return Ok(None);
    }
    let a = receipt(
        "allocated.json",
        "e9c7751ba9f0ab1f1d201ba83c8199cefc1693cd67a54113f402a0d420849953",
    )?;
    let g = receipt(
        "post-allocation-guard.json",
        "3643c4e122c60b08da27e861882b94badba80fd25ef5c1f980b738e267479bf9",
    )?;
    let f = receipt(
        "failed.json",
        "32ff8f869d5f2aaa5c00f87c7f08a1eb7ece07e163a98768a40a7ba3708c599d",
    )?;
    let p = root.join(".tmp36MvkN");
    ensure!(
        entries == [p.clone()]
            && a["iid"] == OLD
            && g["iid"] == OLD
            && f["iid"] == OLD
            && a["temporary"] == p.to_str().unwrap()
            && a["device"] == 64512
            && a["inode"] == INODE
            && g["inode"] == INODE
            && a["logical_bytes"] == 0
            && a["pid"] == 3470300
            && f["error"]
                .as_str()
                .is_some_and(|e| e.starts_with("stale or invalid native guard sample ")),
        "predecessor custody or failure changed"
    );
    let events = capacity::run(
        "/usr/bin/journalctl",
        &[
            "--no-pager",
            "-ojson",
            "--output-fields=UNIT,INVOCATION_ID,MESSAGE_ID,EXIT_STATUS,EXIT_CODE",
            "_PID=1",
            &format!("UNIT={UNIT}"),
            &format!("INVOCATION_ID={OLD}"),
            "MESSAGE_ID=98e322203f7a4ed290d09fe03c09fe15",
        ],
        "8",
    )?;
    let ok = events
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .any(|v| {
            v["UNIT"] == UNIT
                && v["INVOCATION_ID"] == OLD
                && v["EXIT_CODE"] == "exited"
                && v["EXIT_STATUS"] == "1"
        });
    ensure!(
        ok && native::ticks(3470300).ok() != Some(357328155),
        "predecessor still active or missing native termination"
    );
    check(&fs::symlink_metadata(&p)?)?;
    Ok(Some(p))
}
pub fn open(path: &Path) -> Result<tempfile::NamedTempFile> {
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    check(&f.metadata()?)?;
    check(&fs::symlink_metadata(path)?)?;
    // A successful exclusive kernel lease excludes all preexisting readers,
    // writers and conflicting mappings before this private leaf is reused.
    ensure!(
        unsafe { libc::fcntl(f.as_raw_fd(), libc::F_SETLEASE, libc::F_WRLCK) } == 0,
        "predecessor inode has a live consumer or writer"
    );
    check(&f.metadata()?)?;
    check(&fs::symlink_metadata(path)?)?;
    ensure!(
        unsafe { libc::fcntl(f.as_raw_fd(), libc::F_SETLEASE, libc::F_UNLCK) } == 0,
        "release custody probe"
    );
    Ok(tempfile::NamedTempFile::from_parts(
        f,
        tempfile::TempPath::try_from_path(path)?,
    ))
}
