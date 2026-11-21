//! Kernel-enforced exclusion of positive write opens on the exact two source
//! inodes. Both descriptors stay open until the guarded private export exits.
use anyhow::{Context, Result, ensure};
use std::{
    fs::{self, File, OpenOptions},
    io,
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
};

extern "C" fn lease_break(_: libc::c_int) {
    // Async-signal-safe. Never continue transforming an input after a writer
    // requested a lease break; PID1 retains the distinct exit and invocation.
    unsafe { libc::_exit(74) }
}

pub fn arm_break_signal() -> Result<()> {
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = lease_break as *const () as usize;
    let mut mask: libc::sigset_t = unsafe { std::mem::zeroed() };
    let ok = unsafe {
        libc::sigemptyset(&mut action.sa_mask) == 0
            && libc::sigaction(libc::SIGIO, &action, std::ptr::null_mut()) == 0
            && libc::sigemptyset(&mut mask) == 0
            && libc::sigaddset(&mut mask, libc::SIGIO) == 0
            && libc::pthread_sigmask(libc::SIG_UNBLOCK, &mask, std::ptr::null_mut()) == 0
    };
    ensure!(ok, "could not install private exporter lease-break stop");
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileIdentity {
    pub device: u64,
    pub inode: u64,
    pub bytes: u64,
    pub mtime_ns: i128,
    pub ctime_ns: i128,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
}
impl From<&fs::Metadata> for FileIdentity {
    fn from(m: &fs::Metadata) -> Self {
        Self {
            device: m.dev(),
            inode: m.ino(),
            bytes: m.len(),
            mtime_ns: i128::from(m.mtime()) * 1_000_000_000 + i128::from(m.mtime_nsec()),
            ctime_ns: i128::from(m.ctime()) * 1_000_000_000 + i128::from(m.ctime_nsec()),
            mode: m.mode(),
            uid: m.uid(),
            gid: m.gid(),
        }
    }
}
pub struct ReadLease {
    path: PathBuf,
    expected: FileIdentity,
    file: File,
}

impl ReadLease {
    pub fn acquire(path: &Path, expected: FileIdentity) -> Result<Self> {
        ensure!(
            path.is_absolute() && path.canonicalize()? == path,
            "source lease path alias"
        );
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        let m = file.metadata()?;
        ensure!(
            m.is_file()
                && m.nlink() == 1
                && m.mode() & 0o222 == 0
                && FileIdentity::from(&m) == expected,
            "source lease identity changed or writable"
        );
        let fd = file.as_raw_fd();
        let own = unsafe { libc::fcntl(fd, libc::F_SETOWN, libc::getpid()) };
        if own == -1 {
            return Err(io::Error::last_os_error()).context("set source lease owner");
        }
        let grant = unsafe { libc::fcntl(fd, libc::F_SETLEASE, libc::F_RDLCK) };
        if grant == -1 {
            return Err(io::Error::last_os_error())
                .context("obtain kernel read lease (existing writer or unsupported storage)");
        }
        let lease = Self {
            path: path.to_path_buf(),
            file,
            expected,
        };
        lease.check()?;
        Ok(lease)
    }
    pub fn check(&self) -> Result<()> {
        let fd = self.file.as_raw_fd();
        let current = unsafe { libc::fcntl(fd, libc::F_GETLEASE) };
        ensure!(current == libc::F_RDLCK, "source lease changed or breaking");
        let a = self.file.metadata()?;
        let b = fs::symlink_metadata(&self.path)?;
        ensure!(
            a.nlink() == 1
                && b.nlink() == 1
                && FileIdentity::from(&a) == self.expected
                && FileIdentity::from(&b) == self.expected,
            "source lease pathname or inode changed"
        );
        Ok(())
    }
}
