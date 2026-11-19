//! Test-only launcher preserving a framed stdout pipe across the native test
//! harness. The selected synthetic worker is not a production runtime backend.
use sha2::{Digest, Sha256};
use std::{
    fs::OpenOptions,
    io::Read,
    os::{
        fd::AsRawFd,
        unix::{
            fs::{MetadataExt, OpenOptionsExt},
            process::CommandExt,
        },
    },
    path::PathBuf,
    process::Command,
};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = PathBuf::from(
        std::env::var_os("JETSTREAMER_CHECKPOINT_FIXTURE_IMAGE").ok_or("missing fixture image")?,
    );
    let expected = std::env::var("JETSTREAMER_CHECKPOINT_FIXTURE_IMAGE_SHA256")?;
    if !path.is_absolute() || path.canonicalize()? != path || expected.len() != 64 {
        return Err("invalid fixture binding".into());
    }
    let mut image = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)?;
    let meta = image.metadata()?;
    if !meta.is_file()
        || meta.uid() != 0
        || meta.mode() & 0o222 != 0
        || meta.len() > 256 * 1024 * 1024
    {
        return Err("fixture image must be bounded, immutable and root-owned".into());
    }
    let mut sha = Sha256::new();
    let mut buf = [0; 65536];
    loop {
        let n = image.read(&mut buf)?;
        if n == 0 {
            break;
        }
        sha.update(&buf[..n]);
    }
    if format!("{:x}", sha.finalize()) != expected {
        return Err("fixture image digest mismatch".into());
    }
    // Execute the very inode just hashed. Retain the parent's original stdout
    // independently; Rust's test harness writes its own banners to stderr.
    let fd = unsafe { libc::fcntl(1, libc::F_DUPFD, 3) };
    if fd < 3
        || unsafe { libc::dup2(2, 1) } < 0
        || unsafe { libc::fcntl(image.as_raw_fd(), libc::F_SETFD, 0) } < 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    let error = Command::new(format!("/proc/self/fd/{}", image.as_raw_fd()))
        .args([
            "--ignored",
            "--exact",
            "runtime::tests::checkpoint_export_live_ipc_fixture",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("JETSTREAMER_CHECKPOINT_FIXTURE_OUTPUT_FD", fd.to_string())
        .exec();
    Err(error.into())
}
