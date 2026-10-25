//! Deterministic local-only embedding. Never downloads or executes an input.
use sha2::{Digest, Sha256};
use std::{
    ffi::OsStr,
    fs::{self, File, Metadata, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

const MAX_BYTES: u64 = 1024 * 1024 * 1024;
static NEXT_COPY: AtomicU64 = AtomicU64::new(0);

fn reject(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[derive(PartialEq, Eq)]
struct FileIdentity {
    dev: u64,
    ino: u64,
    len: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
    mode: u32,
    uid: u32,
    gid: u32,
    links: u64,
}
fn identity(metadata: &Metadata) -> FileIdentity {
    FileIdentity {
        dev: metadata.dev(),
        ino: metadata.ino(),
        len: metadata.len(),
        mtime: (metadata.mtime(), metadata.mtime_nsec()),
        ctime: (metadata.ctime(), metadata.ctime_nsec()),
        mode: metadata.mode(),
        uid: metadata.uid(),
        gid: metadata.gid(),
        links: metadata.nlink(),
    }
}

fn validate_path(path: &Path) -> io::Result<Metadata> {
    if !path.is_absolute()
        || !path
            .to_str()
            .is_some_and(|value| !value.chars().any(char::is_control))
        || fs::canonicalize(path)? != path
    {
        return Err(reject(
            "binary must have an absolute canonical UTF-8 path without symlinks",
        ));
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.mode() & 0o022 != 0
        || metadata.mode() & 0o111 == 0
        || metadata.len() == 0
        || metadata.len() > MAX_BYTES
    {
        return Err(reject(
            "binary must be a nonempty singly linked executable regular file, not group/other writable, at most 1 GiB",
        ));
    }
    Ok(metadata)
}

fn capture(
    source: &Path,
    expected: &str,
    out: &Path,
    after_copy: impl FnOnce(),
) -> io::Result<PathBuf> {
    let before = validate_path(source)?;
    let mut input = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(source)?;
    if identity(&input.metadata()?) != identity(&before) {
        return Err(reject("binary changed while opening"));
    }
    let sequence = NEXT_COPY.fetch_add(1, Ordering::Relaxed);
    let destination = out.join(format!(
        "clickhouse-capture-{}-{sequence}",
        std::process::id()
    ));
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&destination)?;
    let mut hash = Sha256::new();
    let mut bytes = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        bytes = bytes
            .checked_add(count as u64)
            .ok_or_else(|| reject("binary length overflow"))?;
        if bytes > before.len() {
            return Err(reject("binary grew while copying"));
        }
        hash.update(&buffer[..count]);
        output.write_all(&buffer[..count])?;
    }
    after_copy();
    if bytes != before.len()
        || identity(&input.metadata()?) != identity(&before)
        || identity(&validate_path(source)?) != identity(&before)
    {
        return Err(reject("binary changed while copying"));
    }
    if format!("{:x}", hash.finalize()) != expected {
        return Err(reject(
            "binary SHA-256 does not match the separately supplied digest",
        ));
    }
    output.set_permissions(fs::Permissions::from_mode(0o400))?;
    output.sync_all()?;
    File::open(out)?.sync_all()?;
    Ok(destination)
}

pub(crate) fn generate(
    source: Option<&OsStr>,
    digest: Option<&OsStr>,
    out: &Path,
) -> io::Result<()> {
    if !out.is_absolute() || fs::canonicalize(out)? != out {
        return Err(reject("output directory must be absolute and canonical"));
    }
    let content = match (source, digest) {
        (None, None) => "/// No ClickHouse binary was supplied at build time.\npub const CLICKHOUSE_BINARY: &[u8] = &[];\n".to_owned(),
        (Some(source), Some(digest)) => {
            let digest = digest.to_str().ok_or_else(|| reject("SHA-256 is not UTF-8"))?;
            if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                || digest.bytes().all(|b| b == b'0')
            {
                return Err(reject("SHA-256 must be 64 nonzero lowercase hexadecimal characters"));
            }
            let captured = capture(Path::new(source), digest, out, || {})?;
            format!("/// Digest-verified local ClickHouse bytes, captured without execution.\npub const CLICKHOUSE_BINARY: &[u8] = include_bytes!({:?});\n", captured.to_str().ok_or_else(|| reject("output path is not UTF-8"))?)
        }
        _ => return Err(reject("supply both JETSTREAMER_CLICKHOUSE_BINARY and JETSTREAMER_CLICKHOUSE_SHA256, or neither")),
    };
    let mut generated = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(0o600)
        .open(out.join("embed_clickhouse.rs"))?;
    generated.write_all(content.as_bytes())?;
    generated.sync_all()?;
    File::open(out)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf, String) {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("local-binary");
        let out = root.path().join("out");
        fs::create_dir(&out).unwrap();
        fs::write(&source, b"test bytes only; never executed").unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o700)).unwrap();
        let digest = format!("{:x}", Sha256::digest(fs::read(&source).unwrap()));
        (root, source, out, digest)
    }

    #[test]
    fn default_generates_no_embedded_binary() {
        let root = tempfile::tempdir().unwrap();
        generate(None, None, root.path()).unwrap();
        assert!(
            fs::read_to_string(root.path().join("embed_clickhouse.rs"))
                .unwrap()
                .contains("= &[]")
        );
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);
    }

    #[test]
    fn valid_local_input_is_captured_independently_of_source() {
        let (_root, source, out, digest) = fixture();
        generate(Some(source.as_os_str()), Some(OsStr::new(&digest)), &out).unwrap();
        let generated = fs::read_to_string(out.join("embed_clickhouse.rs")).unwrap();
        assert!(!generated.contains(source.to_str().unwrap()));
        let captured = fs::read_dir(&out)
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| {
                p.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("clickhouse-capture-")
            })
            .unwrap();
        let bytes = fs::read(&captured).unwrap();
        fs::write(&source, b"mutated source after completed capture").unwrap();
        assert_eq!(fs::read(&captured).unwrap(), bytes);
        assert_eq!(fs::metadata(captured).unwrap().mode() & 0o222, 0);
    }

    #[test]
    fn rejects_partial_malformed_missing_and_mismatched_inputs() {
        let (_root, source, out, digest) = fixture();
        assert!(generate(Some(source.as_os_str()), None, &out).is_err());
        assert!(generate(None, Some(OsStr::new(&digest)), &out).is_err());
        for value in [
            "",
            "abcdef",
            &"A".repeat(64),
            &"0".repeat(64),
            &"a".repeat(64),
        ] {
            assert!(generate(Some(source.as_os_str()), Some(OsStr::new(value)), &out).is_err());
        }
        assert!(
            generate(
                Some(out.join("missing").as_os_str()),
                Some(OsStr::new(&digest)),
                &out
            )
            .is_err()
        );
        assert!(!out.join("embed_clickhouse.rs").exists());
    }

    #[test]
    fn rejects_symlink_and_unsafe_sources() {
        let (root, source, out, digest) = fixture();
        let link = root.path().join("symlink");
        symlink(&source, &link).unwrap();
        assert!(generate(Some(link.as_os_str()), Some(OsStr::new(&digest)), &out).is_err());
        fs::set_permissions(&source, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(generate(Some(source.as_os_str()), Some(OsStr::new(&digest)), &out).is_err());
        assert!(!out.join("embed_clickhouse.rs").exists());
    }

    #[test]
    fn rejects_source_changed_during_capture() {
        let (_root, source, out, digest) = fixture();
        let changed = source.clone();
        let error = capture(&source, &digest, &out, || {
            fs::write(changed, b"source replacement during capture").unwrap();
        })
        .unwrap_err();
        assert!(error.to_string().contains("changed while copying"));
        assert!(!out.join("embed_clickhouse.rs").exists());
    }
}
