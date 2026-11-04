//! Bounded, read-only exact-tree process reference census for artifact lifecycle
//! gates. No file removal, process signals, resource sampling or mount changes.
use {
    anyhow::{Context, Result, ensure},
    serde::Serialize,
    std::{
        fs::{self, File},
        io::{ErrorKind, Read},
        os::unix::ffi::OsStrExt,
        path::{Path, PathBuf},
    },
};

const MAX_PROC_BYTES: u64 = 1 << 30;
const CHUNK_BYTES: usize = 64 << 10;

/// Exact process references plus the scope of a complete, fail-closed scan.
#[derive(Debug, Serialize)]
pub struct Scan {
    /// Number of numeric process directories inspected (excluding this process).
    pub inspected_processes: u64,
    /// Every observed command/map/link reference to the exact tree.
    pub references: Vec<String>,
}

pub(crate) fn encoded_reference(bytes: &[u8], needle: &[u8], end_of_file: bool) -> bool {
    bytes.windows(needle.len()).enumerate().any(|(i, word)| {
        let end = i + needle.len();
        word == needle
            && if end == bytes.len() {
                end_of_file
            } else {
                b"/\0\n\r\t '\";|&()<>[]{}".contains(&bytes[end])
            }
    })
}

// Stream mmap-heavy process maps rather than allocating a whole maps file.
// Keep the complete undecided suffix, including a match awaiting its boundary.
fn stream_reference(mut reader: impl Read, needle: &[u8], maximum: u64) -> Result<bool> {
    ensure!(
        !needle.is_empty() && needle.len() < CHUNK_BYTES,
        "invalid reference needle"
    );
    let mut buffer = vec![0; CHUNK_BYTES + needle.len()];
    let mut carry = 0;
    let mut total = 0u64;
    loop {
        let read = reader.read(&mut buffer[carry..carry + CHUNK_BYTES])?;
        total = total
            .checked_add(read as u64)
            .context("process scan size overflow")?;
        ensure!(total <= maximum, "process reference source exceeds bound");
        let end = carry + read;
        if encoded_reference(&buffer[..end], needle, read == 0) {
            return Ok(true);
        }
        if read == 0 {
            return Ok(false);
        }
        carry = needle.len().min(end);
        buffer.copy_within(end - carry..end, 0);
    }
}

fn missing(error: &std::io::Error) -> bool {
    error.kind() == ErrorKind::NotFound
}

fn proc_reference(path: &Path, needle: &[u8]) -> Result<bool> {
    match File::open(path) {
        Ok(file) => stream_reference(file, needle, MAX_PROC_BYTES),
        Err(error) if missing(&error) => Ok(false),
        Err(error) => {
            Err(error).with_context(|| format!("incomplete process read: {}", path.display()))
        }
    }
}

fn link_reference(path: &Path, target: &Path) -> Result<bool> {
    match fs::read_link(path) {
        Ok(link) => {
            let bytes = link.as_os_str().as_bytes();
            let bytes = bytes.strip_suffix(b" (deleted)").unwrap_or(bytes);
            let path = Path::new(std::ffi::OsStr::from_bytes(bytes));
            Ok(path == target || path.starts_with(target))
        }
        Err(error) if missing(&error) => Ok(false),
        Err(error) => {
            Err(error).with_context(|| format!("incomplete process link: {}", path.display()))
        }
    }
}

/// Inspect commands, maps, cwd/root/exe and descriptors for the exact target.
/// Permission failures, unreadable state and source-size excess are fatal;
/// only disappearing proc entries are tolerated. The caller independently
/// authenticates the target, owner, terminal units and immutable lifecycle plan.
/// This scan alone never authorizes deletion or unmounting.
pub fn scan(proc_root: &Path, target: &Path) -> Result<Scan> {
    ensure!(
        target.is_absolute() && target.parent().is_some() && target != Path::new("/"),
        "reference target must be an explicit non-root absolute path"
    );
    let needle = target.as_os_str().as_bytes();
    ensure!(
        !needle.is_empty() && needle.len() < CHUNK_BYTES,
        "reference target is oversized"
    );
    let mut result = Scan {
        inspected_processes: 0,
        references: Vec::new(),
    };
    for process in fs::read_dir(proc_root)? {
        let process = process?;
        let name = process.file_name();
        let Some(pid) = name
            .to_str()
            .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
        else {
            continue;
        };
        if pid.parse::<u32>().ok() == Some(std::process::id()) {
            continue;
        }
        result.inspected_processes += 1;
        let root: PathBuf = process.path();
        for name in ["cmdline", "maps"] {
            if proc_reference(&root.join(name), needle)? {
                result.references.push(format!("pid {pid} {name}"));
            }
        }
        for name in ["cwd", "root", "exe"] {
            if link_reference(&root.join(name), target)? {
                result.references.push(format!("pid {pid} {name}"));
            }
        }
        match fs::read_dir(root.join("fd")) {
            Ok(fds) => {
                for fd in fds {
                    let fd = fd?;
                    if link_reference(&fd.path(), target)? {
                        result
                            .references
                            .push(format!("pid {pid} fd {}", fd.file_name().to_string_lossy()));
                    }
                }
            }
            Err(error) if missing(&error) => (),
            Err(error) => return Err(error).context("incomplete process descriptor census"),
        }
    }
    result.references.sort();
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn streaming_boundaries_are_exact_even_across_chunks() {
        for offset in [
            0,
            CHUNK_BYTES - 4,
            CHUNK_BYTES - 1,
            CHUNK_BYTES,
            CHUNK_BYTES + 1,
        ] {
            for (suffix, expected) in [
                ("", true),
                ("/file", true),
                ("\0", true),
                ("-sibling", false),
            ] {
                let mut bytes = vec![b'x'; offset];
                bytes.extend_from_slice(b"/private/target");
                bytes.extend_from_slice(suffix.as_bytes());
                assert_eq!(
                    stream_reference(bytes.as_slice(), b"/private/target", 1 << 20).unwrap(),
                    expected,
                    "offset={offset} suffix={suffix:?}"
                );
            }
        }
    }

    #[test]
    fn resource_bound_and_io_errors_fail_closed() {
        assert!(stream_reference(&b"too long"[..], b"needle", 3).is_err());
        struct Denied;
        impl Read for Denied {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::from(ErrorKind::PermissionDenied))
            }
        }
        assert!(stream_reference(Denied, b"needle", 100).is_err());
    }

    #[test]
    fn census_finds_commands_maps_deleted_links_and_fds_but_not_siblings() {
        let temp = tempfile::tempdir().unwrap();
        let proc = temp.path().join("12345");
        fs::create_dir(&proc).unwrap();
        fs::create_dir(proc.join("fd")).unwrap();
        fs::write(proc.join("cmdline"), b"node\0--scratch=/private/target\0").unwrap();
        fs::write(proc.join("maps"), b"000 /private/target/accounts\n").unwrap();
        symlink("/private/target/file (deleted)", proc.join("exe")).unwrap();
        symlink("/private/target-sibling", proc.join("cwd")).unwrap();
        symlink("/private/target/file", proc.join("fd/7")).unwrap();
        let result = scan(temp.path(), Path::new("/private/target")).unwrap();
        assert_eq!(result.inspected_processes, 1);
        assert_eq!(result.references.len(), 4);
        assert!(!result.references.iter().any(|s| s.ends_with("cwd")));
        assert!(scan(temp.path(), Path::new("/")).is_err());
        assert!(scan(temp.path(), Path::new("relative")).is_err());
    }

    #[test]
    fn unexpected_proc_shapes_fail_instead_of_implying_no_references() {
        let temp = tempfile::tempdir().unwrap();
        let proc = temp.path().join("12345");
        fs::create_dir(&proc).unwrap();
        fs::create_dir(proc.join("cmdline")).unwrap();
        assert!(scan(temp.path(), Path::new("/private/target")).is_err());
    }
}
