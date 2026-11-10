//! Bounded fail-closed process reader. This supplements, never replaces, the
//! independently bound closed-owner, staged-input and indirect-consumer closure.
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use std::{
    fs::{self, File},
    io::{ErrorKind, Read},
    os::unix::ffi::OsStrExt,
    path::{Component, Path, PathBuf},
};
const MAX_PROC_BYTES: u64 = 1 << 30;
const CHUNK_BYTES: usize = 64 << 10;
#[derive(Debug, Serialize)]
pub struct Scan {
    pub inspected_processes: u64,
    pub references: Vec<String>,
}
fn delimiter(b: u8) -> bool {
    b"/\0\n\r\t '\";|&()<>[]{}=:".contains(&b)
}
pub(crate) fn encoded_reference(bytes: &[u8], needle: &[u8], end_of_file: bool) -> bool {
    if needle.is_empty() {
        return false;
    }
    bytes.windows(needle.len()).enumerate().any(|(i, x)| {
        let end = i + needle.len();
        x == needle
            && (i == 0 || delimiter(bytes[i - 1]))
            && (if end == bytes.len() {
                end_of_file
            } else {
                delimiter(bytes[end])
            })
    })
}
fn stream_reference(mut reader: impl Read, needle: &[u8], maximum: u64) -> Result<bool> {
    ensure!(
        !needle.is_empty() && needle.len() < CHUNK_BYTES,
        "invalid needle"
    );
    let mut buffer = vec![0; CHUNK_BYTES + needle.len() + 1];
    let mut carry = 0;
    let mut total = 0u64;
    loop {
        let count = reader.read(&mut buffer[carry..carry + CHUNK_BYTES])?;
        total = total.checked_add(count as u64).context("scan overflow")?;
        ensure!(total <= maximum, "process source bound");
        let end = carry + count;
        if encoded_reference(&buffer[..end], needle, count == 0) {
            return Ok(true);
        }
        if count == 0 {
            return Ok(false);
        }
        carry = (needle.len() + 1).min(end);
        buffer.copy_within(end - carry..end, 0);
    }
}
fn disappearing(error: &std::io::Error, process: &Path) -> bool {
    error.kind() == ErrorKind::NotFound && !process.exists()
}
fn read_process(path: &Path, process: &Path) -> Result<Option<Vec<u8>>> {
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(e) if disappearing(&e, process) => return Ok(None),
        Err(e) => return Err(e).context("incomplete live command read"),
    };
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(1 << 20)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() < 1 << 20, "process command bound");
    Ok(Some(bytes))
}
fn link(path: &Path, process: &Path, optional: bool) -> Result<Option<PathBuf>> {
    match fs::read_link(path) {
        Ok(p) => {
            let bytes = p.as_os_str().as_bytes();
            let b = bytes.strip_suffix(b" (deleted)").unwrap_or(bytes);
            Ok(Some(PathBuf::from(std::ffi::OsStr::from_bytes(b))))
        }
        Err(e) if disappearing(&e, process) || (optional && e.kind() == ErrorKind::NotFound) => {
            Ok(None)
        }
        Err(e) => Err(e).context("incomplete process link"),
    }
}
fn process_identity(root: &Path) -> Result<Option<(u64, bool)>> {
    let Some(raw) = read_process(&root.join("stat"), root)? else {
        return Ok(None);
    };
    let text = std::str::from_utf8(&raw)?;
    let end = text.rfind(')').context("process stat comm boundary")?;
    let fields: Vec<_> = text[end + 1..].split_whitespace().collect();
    ensure!(fields.len() >= 20, "incomplete process stat");
    let flags = fields[6].parse::<u64>()?;
    let start = fields[19].parse::<u64>()?;
    Ok(Some((
        start,
        flags & 0x00200000 != 0 || matches!(fields[0], "Z" | "X"),
    )))
}
fn relation(path: &Path, target: &Path, scope: &Path) -> bool {
    path == target
        || path.starts_with(target)
        || (path.starts_with(scope) && target.starts_with(path))
}
fn normalized(base: &Path, p: &Path) -> PathBuf {
    let mut result = if p.is_absolute() {
        PathBuf::new()
    } else {
        base.to_path_buf()
    };
    for c in p.components() {
        match c {
            Component::RootDir => result.push("/"),
            Component::Normal(s) => result.push(s),
            Component::CurDir => (),
            Component::ParentDir => {
                result.pop();
            }
            Component::Prefix(_) => (),
        }
    }
    result
}
fn command_reference(
    bytes: &[u8],
    cwd: &Path,
    target: &Path,
    scope: &Path,
    indirect: &[PathBuf],
) -> bool {
    if encoded_reference(bytes, target.as_os_str().as_bytes(), true) {
        return true;
    }
    for arg in bytes.split(|b| *b == 0).filter(|x| !x.is_empty()) {
        let text = std::ffi::OsStr::from_bytes(arg);
        let value = arg.split(|b| *b == b'=').next_back().unwrap_or(arg);
        for candidate in [
            Path::new(text),
            Path::new(std::ffi::OsStr::from_bytes(value)),
        ] {
            let p = normalized(cwd, candidate);
            if relation(&p, target, scope) || indirect.contains(&p) {
                return true;
            }
        }
    }
    false
}
pub fn scan(proc_root: &Path, target: &Path, scope: &Path, indirect: &[PathBuf]) -> Result<Scan> {
    ensure!(
        target.is_absolute()
            && scope.is_absolute()
            && target.starts_with(scope)
            && scope != Path::new("/"),
        "explicit bounded reference scope required"
    );
    let mut result = Scan {
        inspected_processes: 0,
        references: Vec::new(),
    };
    for e in fs::read_dir(proc_root)? {
        let e = e?;
        let name = e.file_name();
        let Some(pid) = name
            .to_str()
            .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
        else {
            continue;
        };
        if pid.parse::<u32>().ok() == Some(std::process::id()) {
            continue;
        }
        let root = e.path();
        result.inspected_processes += 1;
        let Some((start, optional)) = process_identity(&root)? else {
            continue;
        };
        let Some(cmd) = read_process(&root.join("cmdline"), &root)? else {
            continue;
        };
        let cwd = link(&root.join("cwd"), &root, optional)?.unwrap_or_else(|| PathBuf::from("/"));
        if command_reference(&cmd, &cwd, target, scope, indirect) {
            result
                .references
                .push(format!("pid {pid} command/relative/indirect"));
        }
        match File::open(root.join("maps")) {
            Ok(mut f) => {
                if stream_reference(&mut f, target.as_os_str().as_bytes(), MAX_PROC_BYTES)? {
                    result.references.push(format!("pid {pid} maps"));
                }
            }
            Err(e) if disappearing(&e, &root) => continue,
            Err(e) => return Err(e).context("incomplete maps read"),
        }
        for name in ["cwd", "root", "exe"] {
            if let Some(p) = link(&root.join(name), &root, optional)?
                && (relation(&p, target, scope) || indirect.contains(&p))
            {
                result.references.push(format!("pid {pid} {name}"));
            }
        }
        match fs::read_dir(root.join("fd")) {
            Ok(fds) => {
                for fd in fds {
                    let fd = fd?;
                    let p = match fs::read_link(fd.path()) {
                        Ok(p) => p,
                        Err(e) if e.kind() == ErrorKind::NotFound => continue,
                        Err(e) => return Err(e).context("incomplete fd link"),
                    };
                    let bytes = p.as_os_str().as_bytes();
                    let b = bytes.strip_suffix(b" (deleted)").unwrap_or(bytes);
                    let p = Path::new(std::ffi::OsStr::from_bytes(b));
                    if relation(p, target, scope) || indirect.iter().any(|x| x.as_path() == p) {
                        result
                            .references
                            .push(format!("pid {pid} fd {}", fd.file_name().to_string_lossy()));
                    }
                }
            }
            Err(e) if disappearing(&e, &root) => (),
            Err(e) => return Err(e).context("incomplete descriptor census"),
        }
        if let Some((after, _)) = process_identity(&root)? {
            ensure!(after == start, "PID reused during reference census");
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
    fn exact_reference_has_both_boundaries() {
        assert!(encoded_reference(b"--input=/x/body\0", b"/x/body", true));
        assert!(!encoded_reference(b"other/x/body\0", b"/x/body", true));
        assert!(!encoded_reference(b"/x/body.other", b"/x/body", true));
    }
    #[test]
    fn relative_and_parent_input_arguments_are_references() {
        let cwd = Path::new("/closed/run/archives");
        let target = cwd.join("body.jet");
        let scope = Path::new("/closed");
        for b in [
            b"node\0body.jet\0".as_slice(),
            b"node\0--input=../archives/body.jet\0".as_slice(),
            b"node\0/closed/run\0".as_slice(),
        ] {
            assert!(command_reference(b, cwd, &target, scope, &[]));
        }
        assert!(!command_reference(
            b"node\0/closed/run-other\0",
            cwd,
            &target,
            scope,
            &[]
        ));
    }
    #[test]
    fn ancestor_descriptors_are_references_only_within_scoped_lane() {
        let target = Path::new("/closed/run/archives/body.jet");
        let scope = Path::new("/closed");
        assert!(relation(Path::new("/closed/run"), target, scope));
        assert!(!relation(Path::new("/"), target, scope));
        assert!(!relation(Path::new("/closed/run-sibling"), target, scope));
    }
    #[test]
    fn streaming_preserves_left_and_right_boundaries_across_chunks() {
        for offset in [CHUNK_BYTES - 3, CHUNK_BYTES, CHUNK_BYTES + 1] {
            let mut bytes = vec![b' '; offset];
            bytes.extend_from_slice(b"/x/body\n");
            assert!(stream_reference(bytes.as_slice(), b"/x/body", 1 << 20).unwrap());
        }
    }
    #[test]
    fn process_fixture_finds_relative_input_and_ancestor_fd() {
        let temp = tempfile::tempdir().unwrap();
        let p = temp.path().join("12345");
        fs::create_dir(&p).unwrap();
        fs::create_dir(p.join("fd")).unwrap();
        fs::write(
            p.join("stat"),
            b"12345 (node) S 1 1 1 1 1 0 1 1 1 1 1 1 1 1 1 1 1 10 1\n",
        )
        .unwrap();
        fs::write(p.join("cmdline"), b"node\0body.jet\0").unwrap();
        fs::write(p.join("maps"), b"").unwrap();
        symlink("/closed/run/archives", p.join("cwd")).unwrap();
        symlink("/", p.join("root")).unwrap();
        symlink("/usr/bin/node", p.join("exe")).unwrap();
        symlink("/closed/run", p.join("fd/4")).unwrap();
        let s = scan(
            temp.path(),
            Path::new("/closed/run/archives/body.jet"),
            Path::new("/closed"),
            &[],
        )
        .unwrap();
        assert_eq!(s.references.len(), 3);
    }
    #[test]
    fn live_missing_or_unreadable_inputs_fail_closed() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir(temp.path().join("12345")).unwrap();
        assert!(
            scan(
                temp.path(),
                Path::new("/closed/body"),
                Path::new("/closed"),
                &[]
            )
            .is_err()
        );
    }
}
