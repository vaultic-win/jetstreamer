use super::*;
use std::collections::BTreeMap;
pub const ROOT: &str =
    "/home/ubuntu/.jetstreamer-private/qualification-266-instructions-2789f821-v169";
pub const Q: &str = ".horizon266-cad28704-derived-quarantine";
pub const IMAGE: &str =
    "/var/lib/jetstreamer/horizon266-instructions-2789f821-v169-control/pilot/private.ext4";
pub const LOOP: &str = "/dev/loop9";
pub fn parent() -> PathBuf {
    Path::new(preservation::RUN).join("scratch/.historical-runtime")
}
fn walk(
    path: &Path,
    root: &Path,
    expected: &BTreeMap<&str, &str>,
    n: &mut usize,
) -> io::Result<()> {
    if path == parent().join(CHILD) || path == root.join("lost+found").join(Q) {
        need(
            path.symlink_metadata()?.is_dir()
                && path.symlink_metadata()?.ino() == 5767184
                && path.symlink_metadata()?.dev() == DEVICE,
            "unexpected derived root",
        )?;
        return Ok(());
    }
    let rel = path
        .strip_prefix(root)
        .map_err(io::Error::other)?
        .to_str()
        .ok_or_else(|| io::Error::other("retained name"))?;
    let rel = if rel.is_empty() { "." } else { rel };
    let want = expected
        .get(rel)
        .ok_or_else(|| io::Error::other(format!("unexpected retained entry {rel}")))?;
    let m = path.symlink_metadata()?;
    let mut s = format!(
        "{} {} {} {} {}",
        m.dev(),
        m.ino(),
        m.uid(),
        m.gid(),
        m.mode()
    );
    if !m.is_dir() {
        need(m.is_file() && m.nlink() == 1, "retained type/link")?;
        s += &format!(
            " {} {} {}",
            m.len(),
            m.mtime() as i128 * 1_000_000_000 + m.mtime_nsec() as i128,
            m.ctime() as i128 * 1_000_000_000 + m.ctime_nsec() as i128
        );
    }
    need(s == **want, "retained entry identity changed")?;
    *n += 1;
    need(*n <= expected.len(), "retained tree overflow")?;
    if m.is_dir() {
        for r in fs::read_dir(path)? {
            walk(&r?.path(), root, expected, n)?
        }
    }
    Ok(())
}
pub fn manifest() -> io::Result<()> {
    let expected: BTreeMap<_, _> = include_str!("retained.tsv")
        .lines()
        .map(|s| s.split_once('\t').expect("compiled retained row"))
        .collect();
    let mut n = 0;
    walk(Path::new(ROOT), Path::new(ROOT), &expected, &mut n)?;
    need(n == 29 && n == expected.len(), "retained file disappeared")
}
