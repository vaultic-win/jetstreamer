//! Closed descriptor-relative socket route for retry-0005's long root.
//! No external path, root override or connection to the retained old socket.
#![allow(dead_code)] // Node consumes connect; the independent helper consumes bind.
use super::scope;
use std::{
    fs::{self, File, OpenOptions},
    io,
    os::{
        fd::AsRawFd,
        unix::{
            fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
            net::{UnixListener, UnixStream},
        },
    },
    path::{Path, PathBuf},
};
fn denied(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn root() -> io::Result<File> {
    let path = Path::new(scope::ROOT);
    let before = fs::symlink_metadata(path)?;
    if !before.is_dir()
        || before.uid() != 0
        || before.gid() != 0
        || before.mode() & 0o7777 != 0o711
        || path.canonicalize()? != path
    {
        return Err(denied(
            "retry-0005 root is not the exact canonical root-owned directory",
        ));
    }
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let opened = f.metadata()?;
    let after = fs::symlink_metadata(path)?;
    if !same_root(&before, &opened) || !same_root(&before, &after) {
        return Err(denied("retry-0005 root changed at descriptor capture"));
    }
    Ok(f)
}
fn same_root(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    a.is_dir()
        && b.is_dir()
        && a.dev() == b.dev()
        && a.ino() == b.ino()
        && a.uid() == b.uid()
        && a.gid() == b.gid()
        && a.mode() == b.mode()
}
fn address(root: &File) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}/entry.sock", root.as_raw_fd()))
}
fn socket(root: &File) -> io::Result<fs::Metadata> {
    let m = fs::symlink_metadata(address(root))?;
    if !m.file_type().is_socket() || m.uid() != 0 || m.nlink() != 1 {
        return Err(denied(
            "retry-0005 socket is not root-owned and singly linked",
        ));
    }
    Ok(m)
}
pub(crate) fn bind() -> io::Result<(File, UnixListener)> {
    let directory = root()?;
    // bind is no-clobber for an occupied filesystem socket. No unlink exists.
    let listener = UnixListener::bind(address(&directory))?;
    fs::set_permissions(address(&directory), fs::Permissions::from_mode(0o666))?;
    socket(&directory)?;
    Ok((directory, listener))
}
pub(crate) fn connect() -> io::Result<UnixStream> {
    let directory = root()?;
    let before = socket(&directory)?;
    let stream = UnixStream::connect(address(&directory))?;
    let after = socket(&directory)?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.uid() != after.uid()
        || before.gid() != after.gid()
        || before.mode() != after.mode()
    {
        return Err(denied("retry-0005 socket changed while connecting"));
    }
    Ok(stream)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn long_logical_socket_connects_through_independent_fixed_root_descriptors() {
        let temp = tempfile::tempdir().unwrap();
        let long = temp.path().join("a".repeat(100));
        fs::create_dir(&long).unwrap();
        assert!(long.join("entry.sock").as_os_str().len() > 108);
        let first = File::open(&long).unwrap();
        let second = File::open(&long).unwrap();
        assert_ne!(first.as_raw_fd(), second.as_raw_fd());
        let listener = UnixListener::bind(address(&first)).unwrap();
        let _connection = UnixStream::connect(address(&second)).unwrap();
        let _accepted = listener.accept().unwrap();
        assert!(same_root(
            &first.metadata().unwrap(),
            &second.metadata().unwrap()
        ));
        assert!(UnixListener::bind(address(&first)).is_err());
        assert!(
            fs::symlink_metadata(long.join("entry.sock"))
                .unwrap()
                .file_type()
                .is_socket()
        );
    }
    #[test]
    fn replacement_directory_and_symlink_do_not_match_the_original_descriptor() {
        let temp = tempfile::tempdir().unwrap();
        let first = temp.path().join("first");
        let other = temp.path().join("other");
        fs::create_dir(&first).unwrap();
        fs::create_dir(&other).unwrap();
        let old = File::open(&first).unwrap();
        let replacement = File::open(&other).unwrap();
        assert!(!same_root(
            &old.metadata().unwrap(),
            &replacement.metadata().unwrap()
        ));
        std::os::unix::fs::symlink(&first, temp.path().join("link")).unwrap();
        assert!(!same_root(
            &old.metadata().unwrap(),
            &fs::symlink_metadata(temp.path().join("link")).unwrap()
        ));
    }
}
