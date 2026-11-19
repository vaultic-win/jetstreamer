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
    // ESRCH can occur after opening a proc file when its task exits. Require
    // positive absence of the PID directory: exists() would hide access errors.
    (error.kind() == ErrorKind::NotFound || error.raw_os_error() == Some(libc::ESRCH))
        && matches!(fs::symlink_metadata(process), Err(e) if e.kind() == ErrorKind::NotFound)
}
fn read_process(path: &Path, process: &Path) -> Result<Option<Vec<u8>>> {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) if disappearing(&e, process) => return Ok(None),
        Err(e) => return Err(e).context("incomplete live command read"),
    };
    read_command(file, process)
}
fn read_command(reader: impl Read, process: &Path) -> Result<Option<Vec<u8>>> {
    let mut bytes = Vec::new();
    match reader.take(1 << 20).read_to_end(&mut bytes) {
        Ok(_) => (),
        Err(e) if disappearing(&e, process) => return Ok(None),
        Err(e) => return Err(e).context("incomplete live command read"),
    }
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ProcessIdentity {
    start: u64,
    optional_links: bool,
    kernel_thread: bool,
    terminal: bool,
    threads: u64,
}
fn process_identity(root: &Path) -> Result<Option<ProcessIdentity>> {
    let Some(raw) = read_process(&root.join("stat"), root)? else {
        return Ok(None);
    };
    let text = std::str::from_utf8(&raw)?;
    let end = text.rfind(')').context("process stat comm boundary")?;
    let fields: Vec<_> = text[end + 1..].split_whitespace().collect();
    ensure!(fields.len() >= 20, "incomplete process stat");
    let flags = fields[6].parse::<u64>()?;
    let start = fields[19].parse::<u64>()?;
    Ok(Some(ProcessIdentity {
        start,
        optional_links: flags & 0x00200000 != 0 || matches!(fields[0], "Z" | "X"),
        kernel_thread: flags & 0x00200000 != 0,
        terminal: matches!(fields[0], "Z" | "X"),
        threads: fields[17].parse()?,
    }))
}
fn has_no_userspace_environment(root: &Path, before: ProcessIdentity) -> Result<bool> {
    if before.kernel_thread {
        return Ok(true);
    }
    if !before.terminal || before.threads != 1 {
        return Ok(false);
    }
    // A zombie group leader may still have live sibling threads. Only a
    // complete one-task census with the same terminal identity proves absence.
    let mut tasks = fs::read_dir(root.join("task"))?;
    let Some(task) = tasks.next().transpose()? else {
        return Ok(false);
    };
    ensure!(
        tasks.next().transpose()?.is_none(),
        "terminal task has sibling threads"
    );
    Ok(root.file_name() == Some(task.file_name().as_os_str())
        && process_identity(&task.path())? == Some(before))
}
fn environment(root: &Path, before: ProcessIdentity) -> Result<Option<Vec<u8>>> {
    environment_result(read_process(&root.join("environ"), root), root, before)
}
fn environment_result(
    result: Result<Option<Vec<u8>>>,
    root: &Path,
    before: ProcessIdentity,
) -> Result<Option<Vec<u8>>> {
    match result {
        Ok(bytes) => Ok(bytes),
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.raw_os_error() == Some(libc::ESRCH))
                && has_no_userspace_environment(root, before)? =>
        {
            // Kernel threads have no userspace mm/environment. Still inspect
            // their links, maps and descriptors, and require the same identity.
            ensure!(
                process_identity(root)? == Some(before),
                "task changed while reading absent environment"
            );
            Ok(Some(Vec::new()))
        }
        Err(error) => Err(error),
    }
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
        let Some(identity) = process_identity(&root)? else {
            continue;
        };
        let optional = identity.optional_links;
        let Some(cmd) = read_process(&root.join("cmdline"), &root)? else {
            continue;
        };
        let cwd = link(&root.join("cwd"), &root, optional)?.unwrap_or_else(|| PathBuf::from("/"));
        if command_reference(&cmd, &cwd, target, scope, indirect) {
            result
                .references
                .push(format!("pid {pid} command/relative/indirect"));
        }
        let Some(environment) = environment(&root, identity)? else {
            continue;
        };
        if command_reference(&environment, &cwd, target, scope, indirect) {
            result
                .references
                .push(format!("pid {pid} environment/relative/indirect"));
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
        if let Some(after) = process_identity(&root)? {
            ensure!(
                after.start == identity.start,
                "PID reused during reference census"
            );
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
    fn only_identity_stable_kernel_esrch_proves_absent_environment() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let stat = |flags: u64, start: u64| {
            format!("2 (kthreadd) S 0 0 0 0 -1 {flags} 0 0 0 0 0 0 0 0 20 0 1 0 {start} 0\n")
        };
        fs::write(root.join("stat"), stat(0x00200000, 134)).unwrap();
        let before = process_identity(root).unwrap().unwrap();
        let error = |errno| Err(std::io::Error::from_raw_os_error(errno).into());
        assert_eq!(
            environment_result(error(libc::ESRCH), root, before).unwrap(),
            Some(vec![])
        );
        for errno in [libc::EACCES, libc::EPERM, libc::EIO, libc::ENOENT] {
            assert!(environment_result(error(errno), root, before).is_err());
        }
        fs::write(root.join("stat"), stat(0x00200000, 135)).unwrap();
        assert!(environment_result(error(libc::ESRCH), root, before).is_err());
        fs::write(root.join("stat"), stat(0, 134)).unwrap();
        let user = process_identity(root).unwrap().unwrap();
        assert!(environment_result(error(libc::ESRCH), root, user).is_err());
        assert!(environment_result(error(libc::ESRCH), root, before).is_err());
    }
    #[test]
    fn zombie_environment_requires_complete_single_terminal_task_census() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("12345");
        let task = root.join("task/12345");
        fs::create_dir_all(&task).unwrap();
        let stat = b"12345 (node) Z 1 1 1 1 1 0 1 1 1 1 1 1 1 1 1 0 1 0 10 1\n";
        fs::write(root.join("stat"), stat).unwrap();
        fs::write(task.join("stat"), stat).unwrap();
        let before = process_identity(&root).unwrap().unwrap();
        let error = || Err(std::io::Error::from_raw_os_error(libc::ESRCH).into());
        assert!(before.terminal && before.threads == 1);
        assert_eq!(
            environment_result(error(), &root, before).unwrap(),
            Some(vec![])
        );
        fs::create_dir(root.join("task/12346")).unwrap();
        assert!(environment_result(error(), &root, before).is_err());
        fs::remove_dir(root.join("task/12346")).unwrap();
        fs::write(
            task.join("stat"),
            String::from_utf8_lossy(stat).replace(") Z", ") S"),
        )
        .unwrap();
        assert!(environment_result(error(), &root, before).is_err());
        fs::remove_file(task.join("stat")).unwrap();
        assert!(environment_result(error(), &root, before).is_err());
    }
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
        fs::write(p.join("environ"), b"").unwrap();
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
    #[test]
    fn disappearance_requires_absent_pid_and_expected_errno() {
        let temp = tempfile::tempdir().unwrap();
        let pid = temp.path().join("12345");
        for errno in [libc::ENOENT, libc::ESRCH] {
            assert!(disappearing(
                &std::io::Error::from_raw_os_error(errno),
                &pid
            ));
        }
        for errno in [libc::EACCES, libc::EPERM, libc::EIO] {
            assert!(!disappearing(
                &std::io::Error::from_raw_os_error(errno),
                &pid
            ));
        }
        fs::create_dir(&pid).unwrap();
        for errno in [libc::ENOENT, libc::ESRCH, libc::EACCES] {
            assert!(!disappearing(
                &std::io::Error::from_raw_os_error(errno),
                &pid
            ));
        }
        fs::remove_dir(&pid).unwrap();
        // A reused PID is present again and must never be excused as gone.
        fs::create_dir(&pid).unwrap();
        assert!(!disappearing(
            &std::io::Error::from_raw_os_error(libc::ESRCH),
            &pid
        ));
    }
    #[test]
    fn disappearance_does_not_follow_pid_aliases_or_hide_metadata_errors() {
        let temp = tempfile::tempdir().unwrap();
        let pid = temp.path().join("12345");
        symlink(temp.path().join("absent"), &pid).unwrap();
        assert!(!disappearing(
            &std::io::Error::from_raw_os_error(libc::ESRCH),
            &pid
        ));
        let file = temp.path().join("file");
        fs::write(&file, b"").unwrap();
        assert!(!disappearing(
            &std::io::Error::from_raw_os_error(libc::ESRCH),
            &file.join("pid")
        ));
    }
    #[test]
    fn task_exit_after_open_is_accepted_only_when_pid_is_absent() {
        struct ExitRead {
            pid: PathBuf,
            replace: bool,
        }
        impl Read for ExitRead {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                fs::remove_dir(&self.pid)?;
                if self.replace {
                    fs::create_dir(&self.pid)?;
                }
                Err(std::io::Error::from_raw_os_error(libc::ESRCH))
            }
        }
        let temp = tempfile::tempdir().unwrap();
        let pid = temp.path().join("12345");
        fs::create_dir(&pid).unwrap();
        assert!(
            read_command(
                ExitRead {
                    pid: pid.clone(),
                    replace: false
                },
                &pid
            )
            .unwrap()
            .is_none()
        );
        fs::create_dir(&pid).unwrap();
        assert!(
            read_command(
                ExitRead {
                    pid: pid.clone(),
                    replace: true
                },
                &pid
            )
            .is_err()
        );
    }
}
