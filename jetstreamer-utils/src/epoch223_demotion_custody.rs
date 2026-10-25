//! Host-wide serialization for new issuing paths, not a fleet lease or grant.
use super::*;
use std::os::fd::AsRawFd;
const LOCK: &str = "/run/lock/jetstreamer-horizon-admission.lock";

pub(super) struct Custody {
    file: File,
    path: PathBuf,
    device: u64,
    inode: u64,
    uid: u32,
}
impl Custody {
    pub(super) fn acquire(timeout_millis: u64) -> Result<Self> {
        ensure!(
            unsafe { libc::geteuid() } == 0,
            "223 admission custody requires root"
        );
        Self::at(Path::new(LOCK), 0, timeout_millis)
    }
    fn at(path: &Path, uid: u32, timeout_millis: u64) -> Result<Self> {
        ensure!(
            timeout_millis > 0 && timeout_millis <= 120_000,
            "223 admission custody requires a bounded timeout"
        );
        let parent = path.parent().context("223 custody parent")?;
        ensure!(
            parent.canonicalize()? == parent,
            "223 admission lock parent redirected"
        );
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let file = match options.create_new(true).open(path) {
            Ok(file) => {
                file.set_permissions(fs::Permissions::from_mode(0o600))?;
                file.sync_all()?;
                File::open(parent)?.sync_all()?;
                file
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(path)?,
            Err(error) => return Err(error.into()),
        };
        let metadata = file.metadata()?;
        let custody = Self {
            file,
            path: path.into(),
            device: metadata.dev(),
            inode: metadata.ino(),
            uid,
        };
        custody.validate()?;
        let started = Instant::now();
        loop {
            custody.validate()?;
            if unsafe { libc::flock(custody.file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0
            {
                custody.validate()?;
                ensure!(
                    started.elapsed() < Duration::from_millis(timeout_millis),
                    "223 custody deadline elapsed at acquisition"
                );
                return Ok(custody);
            }
            let error = std::io::Error::last_os_error();
            ensure!(
                matches!(
                    error.raw_os_error(),
                    Some(libc::EWOULDBLOCK) | Some(libc::EINTR)
                ),
                "223 admission custody lock failed: {error}"
            );
            ensure!(
                started.elapsed() < Duration::from_millis(timeout_millis),
                "223 admission custody timed out"
            );
            thread::sleep(Duration::from_millis(5).min(Duration::from_millis(timeout_millis)));
        }
    }
    pub(super) fn validate(&self) -> Result<()> {
        let opened = self.file.metadata()?;
        let named = fs::symlink_metadata(&self.path)?;
        for metadata in [&opened, &named] {
            ensure!(
                metadata.is_file()
                    && metadata.uid() == self.uid
                    && metadata.mode() & 0o777 == 0o600
                    && metadata.nlink() == 1
                    && metadata.dev() == self.device
                    && metadata.ino() == self.inode,
                "223 admission custody inode/ownership/mode replaced"
            );
        }
        ensure!(
            self.path.canonicalize()? == self.path,
            "223 admission lock redirected"
        );
        Ok(())
    }
    pub(super) fn evidence(&self) -> Result<Value> {
        self.validate()?;
        Ok(
            json!({"path":self.path,"device":self.device,"inode":self.inode,
            "exclusive_flock_held":true,"all_new_issuers_must_participate":true,
            "legacy_nonparticipating_helpers_must_be_quiescent":true}),
        )
    }
}
// Closing the descriptor releases flock even when an issuer terminates; no
// process may unlink/replace the lock to recover from a presumed stale holder.

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn lock_wait_is_bounded_and_closed_holder_releases_kernel_custody() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("lock");
        let uid = unsafe { libc::geteuid() };
        let first = Custody::at(&path, uid, 100).unwrap();
        assert!(Custody::at(&path, uid, 1).is_err());
        let inode = first.inode;
        drop(first); // interrupted/terminated holder's FD closure releases flock
        let next = Custody::at(&path, uid, 100).unwrap();
        assert_eq!(next.inode, inode);
    }
    #[test]
    fn a_replacement_inode_or_alias_is_never_custody() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("lock");
        let uid = unsafe { libc::geteuid() };
        let first = Custody::at(&path, uid, 100).unwrap();
        fs::rename(&path, directory.path().join("old-lock")).unwrap();
        let _replacement = Custody::at(&path, uid, 100).unwrap();
        assert!(first.validate().is_err());
        fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(directory.path().join("old-lock"), &path).unwrap();
        assert!(Custody::at(&path, uid, 100).is_err());
    }
}
