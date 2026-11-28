//! The private prefix writes directly to its exact output path, never cohort import.
use super::*;
#[derive(Serialize)]
pub(super) struct Measurement {
    pub jet_size_bytes: u64,
    path: PathBuf,
    source: &'static str,
    plan_sha256: String,
}
fn directory(p: &Path, uid: u32) -> Result<()> {
    let m = fs::symlink_metadata(p)?;
    ensure!(
        m.is_dir() && m.uid() == uid && m.mode() & 0o077 == 0 && p.canonicalize()? == p,
        "prefix partial archive directory is not owner-private"
    );
    Ok(())
}
fn measured(p: &Path, uid: u32) -> Result<u64> {
    let a = match fs::symlink_metadata(p) {
        Ok(a) => a,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e.into()),
    };
    let b = fs::symlink_metadata(p)?;
    ensure!(
        a.is_file()
            && b.is_file()
            && a.uid() == uid
            && b.uid() == uid
            && a.nlink() == 1
            && b.nlink() == 1
            && a.mode() & 0o077 == 0
            && b.mode() & 0o077 == 0
            && a.dev() == b.dev()
            && a.ino() == b.ino()
            && b.len() >= a.len(),
        "prefix partial archive is linked/replaced or shrank"
    );
    Ok(a.len())
}
pub(super) fn measure(root: &Path, pid: u64, plan_sha: &str, uid: u32) -> Result<Measurement> {
    ensure!(
        root == Path::new(c::ROOT) && pid > 1 && plan_sha == c::PLAN_SHA,
        "prefix partial archive scope differs"
    );
    directory(root, uid)?;
    let output = root.join("output");
    directory(&output, uid)?;
    let path = output.join("epoch-223.jet");
    let bytes = measured(&path, uid)?;
    Ok(Measurement {
        jet_size_bytes: bytes,
        path,
        source: "private-known-root-prefix",
        plan_sha256: plan_sha.into(),
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn absent_or_growing_private_prefix_is_counted_without_accepting_a_link() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("epoch-223.jet");
        let uid = unsafe { libc::geteuid() };
        assert_eq!(measured(&p, uid).unwrap(), 0);
        fs::write(&p, b"partial").unwrap();
        fs::set_permissions(&p, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
        assert_eq!(measured(&p, uid).unwrap(), 7);
        fs::remove_file(&p).unwrap();
        std::os::unix::fs::symlink("/outside", &p).unwrap();
        assert!(measured(&p, uid).is_err());
    }
}
