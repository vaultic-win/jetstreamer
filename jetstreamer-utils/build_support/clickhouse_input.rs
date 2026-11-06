//! Explicit, immutable offline input for the ClickHouse build script.
use sha2::{Digest, Sha256};
use std::{
    ffi::OsString,
    fs::{self, File, Metadata, OpenOptions},
    io::{self, Read},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

const MAX_BYTES: u64 = 1 << 30;

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

pub fn selected_input(
    path: Option<OsString>,
    digest: Option<OsString>,
) -> io::Result<Option<(PathBuf, String)>> {
    match (path, digest) {
        (None, None) => Ok(None),
        (Some(path), Some(digest)) => {
            let digest = digest
                .into_string()
                .map_err(|_| invalid("non-UTF-8 digest"))?;
            if digest.len() != 64
                || !digest
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(invalid("SHA-256 must be exactly 64 lowercase hex digits"));
            }
            let path = PathBuf::from(path);
            if !path.is_absolute() || path.to_str().is_none() {
                return Err(invalid("input path must be absolute UTF-8"));
            }
            Ok(Some((path, digest)))
        }
        _ => Err(invalid(
            "set both JETSTREAMER_CLICKHOUSE_BINARY and JETSTREAMER_CLICKHOUSE_SHA256",
        )),
    }
}

fn identity(m: &Metadata) -> (u64, u64, u32, u32, u32, u64, u64, i64, i64, i64, i64) {
    (
        m.dev(),
        m.ino(),
        m.mode(),
        m.uid(),
        m.gid(),
        m.nlink(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}

fn custody(path: &Path) -> io::Result<Metadata> {
    if !path.is_absolute() || path.canonicalize()? != path {
        return Err(invalid("input path is not canonical"));
    }
    for parent in path.ancestors().skip(1) {
        let m = fs::symlink_metadata(parent)?;
        if !m.is_dir() || m.uid() != 0 || m.mode() & 0o022 != 0 {
            return Err(invalid(
                "input ancestor is not a root-owned protected directory",
            ));
        }
    }
    let m = fs::symlink_metadata(path)?;
    if !m.is_file()
        || m.uid() != 0
        || m.nlink() != 1
        || m.mode() & 0o222 != 0
        || m.len() == 0
        || m.len() > MAX_BYTES
    {
        return Err(invalid(
            "input must be a nonempty immutable root-owned single-link regular file at most 1 GiB",
        ));
    }
    Ok(m)
}

pub fn verify(path: &Path, expected: &str) -> io::Result<()> {
    // Validate even direct callers, rather than trusting environment parsing alone.
    selected_input(Some(path.as_os_str().into()), Some(expected.into()))?;
    let before = custody(path)?;
    let mut file: File = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    if identity(&before) != identity(&file.metadata()?) {
        return Err(invalid("input identity changed before open"));
    }
    let mut hash = Sha256::new();
    let mut total = 0u64;
    let mut buf = [0u8; 65536];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        total = total
            .checked_add(n as u64)
            .ok_or_else(|| invalid("length overflow"))?;
        if total > before.len() {
            return Err(invalid("input grew while hashing"));
        }
        hash.update(&buf[..n]);
    }
    let actual = format!("{:x}", hash.finalize());
    if total != before.len()
        || actual != expected
        || identity(&before) != identity(&file.metadata()?)
        || identity(&before) != identity(&custody(path)?)
    {
        return Err(invalid("input digest, length or identity changed"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requires_complete_pair_and_canonical_digest() {
        let hash = "0".repeat(64);
        assert!(selected_input(None, None).unwrap().is_none());
        assert!(selected_input(Some("/x".into()), None).is_err());
        assert!(selected_input(None, Some(hash.clone().into())).is_err());
        for bad in ["A".repeat(64), "g".repeat(64), "0".repeat(63), "".into()] {
            assert!(selected_input(Some("/x".into()), Some(bad.into())).is_err());
        }
        assert!(selected_input(Some("relative".into()), Some(hash.into())).is_err());
    }

    #[test]
    fn rejects_mutable_or_noncanonical_input() {
        assert!(verify(Path::new("/etc/passwd"), &"0".repeat(64)).is_err());
        assert!(verify(Path::new("/etc/../etc/passwd"), &"0".repeat(64)).is_err());
        assert!(verify(Path::new("/proc/self/exe"), &"0".repeat(64)).is_err());
    }

    #[test]
    #[ignore = "requires a separately sealed root-owned native fixture"]
    fn sealed_fixture_and_mismatch() {
        // Native qualification supplies the genuine, separately Rust-sealed input.
        // This test must fail when invoked without that explicit qualification input.
        let path =
            std::env::var_os("HORIZON_TEST_CLICKHOUSE_INPUT").expect("native sealed fixture path");
        let digest =
            std::env::var("HORIZON_TEST_CLICKHOUSE_SHA256").expect("native sealed fixture digest");
        let path = PathBuf::from(path);
        verify(&path, &digest).unwrap();
        let wrong = if digest.starts_with('0') {
            "1".repeat(64)
        } else {
            "0".repeat(64)
        };
        assert!(verify(&path, &wrong).is_err());
    }
}
