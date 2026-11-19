use super::*;

fn hex(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub(super) fn identity(
    m: &fs::Metadata,
) -> (u64, u64, u64, u64, i64, i64, i64, i64, u32, u32, u32) {
    (
        m.dev(),
        m.ino(),
        m.len(),
        m.nlink(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
        m.uid(),
        m.gid(),
        m.mode(),
    )
}
pub(crate) fn hash_file(path: &Path, maximum: u64) -> Result<(String, fs::Metadata)> {
    hash_file_links(path, maximum, 1)
}
pub(crate) fn hash_working_image() -> Result<(String, fs::Metadata)> {
    let path = Path::new("/tmp/holding141-target/debug/jetstreamer-r2");
    let result = hash_file_links(path, 256 << 20, 2)?;
    ensure!(
        result.1.dev() == 2304
            && result.1.ino() == 6714227
            && result.1.uid() == 1001
            && result.1.gid() == 1001,
        "wrong retained working image identity"
    );
    Ok(result)
}
fn hash_file_links(path: &Path, maximum: u64, links: u64) -> Result<(String, fs::Metadata)> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let before = file.metadata()?;
    ensure!(
        before.is_file() && before.nlink() == links && before.len() <= maximum,
        "unsafe/oversized retained file"
    );
    let mut hash = Sha256::new();
    let mut bytes = 0u64;
    let mut buffer = [0u8; 65536];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        bytes = bytes
            .checked_add(read as u64)
            .context("file length overflow")?;
        ensure!(bytes <= maximum, "file exceeded bound while read");
        hash.update(&buffer[..read]);
    }
    ensure!(
        bytes == before.len()
            && identity(&before) == identity(&file.metadata()?)
            && identity(&before) == identity(&fs::symlink_metadata(path)?),
        "retained file changed"
    );
    Ok((format!("{:x}", hash.finalize()), before))
}
pub(crate) fn bound_json(bound: &Bound) -> Result<Value> {
    bound_json_with_limit(bound, 1 << 20)
}
pub(crate) fn bound_partial_check(bound: &Bound) -> Result<Value> {
    let value = bound_json_with_limit(bound, PARTIAL_CHECK_MAX_BYTES)?;
    ensure!(
        value["schema"] == SCHEMA && value["profile"] == PROFILE,
        "not a historical compiler partial-cleanup check"
    );
    Ok(value)
}
fn bound_json_with_limit(bound: &Bound, maximum: u64) -> Result<Value> {
    ensure!(
        hex(&bound.sha256, 64)
            && bound.path.is_absolute()
            && bound.path.canonicalize()? == bound.path,
        "noncanonical evidence binding"
    );
    let (sha, m) = hash_file(&bound.path, maximum)?;
    ensure!(
        sha == bound.sha256 && m.uid() == 0 && m.mode() & 0o222 == 0,
        "mutable or mismatching evidence"
    );
    let mut bytes = Vec::new();
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(&bound.path)?
        .take(maximum + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= maximum
            && format!("{:x}", Sha256::digest(&bytes)) == bound.sha256
            && identity(&m) == identity(&fs::symlink_metadata(&bound.path)?),
        "evidence changed at decode"
    );
    Ok(serde_json::from_slice(&bytes)?)
}
pub(crate) fn properties(unit: &str, names: &str) -> Result<BTreeMap<String, String>> {
    let result = Command::new("/usr/bin/systemctl")
        .args(["show", unit, "--no-pager", "--property", names])
        .output()?;
    ensure!(
        result.status.success() && result.stdout.len() <= 65536,
        "unit properties unavailable"
    );
    let mut values = BTreeMap::new();
    for line in std::str::from_utf8(&result.stdout)?.lines() {
        let (key, value) = line.split_once('=').context("malformed property")?;
        ensure!(
            values.insert(key.into(), value.into()).is_none(),
            "duplicate property"
        );
    }
    Ok(values)
}
#[cfg(test)]
mod link_tests {
    use super::*;
    #[test]
    fn shared_working_image_hash_does_not_relax_single_link_evidence() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("image");
        fs::write(&path, b"retained binary fixture").unwrap();
        fs::hard_link(&path, directory.path().join("alias")).unwrap();
        assert!(hash_file(&path, 1024).is_err());
        assert_eq!(
            hash_file_links(&path, 1024, 2).unwrap().0,
            sha(b"retained binary fixture")
        );
        fs::hard_link(&path, directory.path().join("unexpected-alias")).unwrap();
        assert!(hash_file_links(&path, 1024, 2).is_err());
    }
}
