//! Recover only the empty, already charged inode from the last private run.
use super::*;
const OLD: &str = "022092e08a1c4f05bacb9453faead223";
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
        "053fb2c0894bc74b069fb4a37aa2ae439129fb44b98d6e22b1ae842daebb5289",
    )?;
    let g = receipt(
        "post-allocation-guard.json",
        "5cac329a193875b76960cbe1f61b66cfc60d265bd3a90940231d1d1f60990f87",
    )?;
    let f = receipt(
        "failed.json",
        "9c774cd75a790d45411080c6c04231c0c72464a0dbd7616c95819ddf40e78382",
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
            && a["pid"] == 3476538
            && f["error"]
                .as_str()
                .is_some_and(|e| e.starts_with("resource gate: HOME ")),
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
        ok && native::ticks(3476538).ok() != Some(357388027),
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
