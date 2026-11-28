//! Process-local write confinement without splitting rename mount identities.
//! Landlock does not mediate chmod/chown: the publisher's exact inode/path and
//! privilege-drop checks remain mandatory independently of this write policy.

use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    fs::{self, OpenOptions},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::{ffi::OsStrExt, fs::OpenOptionsExt},
    },
    path::Path,
};

// Linux Landlock ABI v3 filesystem mutations; reads and execution are unhandled.
const WRITE: u64 = 1 << 1;
const REMOVE_DIR: u64 = 1 << 4;
const REMOVE_FILE: u64 = 1 << 5;
const MAKE_DIR: u64 = 1 << 7;
const MAKE_REG: u64 = 1 << 8;
const REFER: u64 = 1 << 13;
const TRUNCATE: u64 = 1 << 14;
const ALLOWED: u64 = WRITE | REMOVE_DIR | REMOVE_FILE | MAKE_DIR | MAKE_REG | REFER | TRUNCATE;
const HANDLED: u64 = ALLOWED | (1 << 6) | (1 << 9) | (1 << 10) | (1 << 11) | (1 << 12);

#[repr(C)]
struct Ruleset {
    handled_access_fs: u64,
}
#[repr(C, packed)]
struct PathRule {
    allowed_access: u64,
    parent_fd: i32,
}

fn abi() -> Result<i64> {
    let result = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<u8>(),
            0usize,
            1u32,
        )
    };
    ensure!(
        result >= 3,
        "Landlock ABI >=3 required: {}",
        std::io::Error::last_os_error()
    );
    Ok(result)
}

fn mount_id(path: &Path) -> Result<u64> {
    let name = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    let mut stat = std::mem::MaybeUninit::<libc::statx>::zeroed();
    ensure!(
        unsafe {
            libc::statx(
                libc::AT_FDCWD,
                name.as_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
                libc::STATX_MNT_ID,
                stat.as_mut_ptr(),
            )
        } == 0,
        "statx mount identity failed: {}",
        path.display()
    );
    let stat = unsafe { stat.assume_init() };
    ensure!(
        stat.stx_mask & libc::STATX_MNT_ID != 0 && stat.stx_mnt_id != 0,
        "mount identity unavailable"
    );
    Ok(stat.stx_mnt_id)
}

pub(super) fn same_mount(paths: &[&Path]) -> Result<u64> {
    let first = mount_id(paths.first().context("no rename paths")?)?;
    for path in paths {
        ensure!(
            mount_id(path)? == first,
            "publisher rename paths span distinct mount IDs; no files moved"
        );
    }
    Ok(first)
}

pub(super) fn confine(paths: &[&Path]) -> Result<Value> {
    let tasks = fs::read_dir("/proc/self/task")?.collect::<std::io::Result<Vec<_>>>()?;
    ensure!(
        tasks.len() == 1,
        "write confinement requires single-threaded admission"
    );
    restrict_writes(paths)
}

fn restrict_writes(paths: &[&Path]) -> Result<Value> {
    ensure!(!paths.is_empty(), "empty write scope");
    let abi = abi()?;
    let attribute = Ruleset {
        handled_access_fs: HANDLED,
    };
    let result = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &attribute,
            std::mem::size_of::<Ruleset>(),
            0u32,
        )
    };
    ensure!(
        result >= 0,
        "create write ruleset: {}",
        std::io::Error::last_os_error()
    );
    let ruleset = unsafe { OwnedFd::from_raw_fd(i32::try_from(result)?) };
    for path in paths {
        ensure!(
            path.is_absolute() && fs::canonicalize(path)? == *path && path.is_dir(),
            "write root is not a canonical directory"
        );
        ensure!(
            ![
                "/",
                "/var",
                "/var/lib",
                "/var/lib/jetstreamer",
                "/home",
                "/home/ubuntu",
                "/tmp"
            ]
            .iter()
            .any(|wide| *path == Path::new(wide)),
            "write root is too broad"
        );
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let rule = PathRule {
            allowed_access: ALLOWED,
            parent_fd: directory.as_raw_fd(),
        };
        ensure!(
            unsafe {
                libc::syscall(
                    libc::SYS_landlock_add_rule,
                    ruleset.as_raw_fd(),
                    1u32,
                    &rule,
                    0u32,
                )
            } == 0,
            "add write root: {}",
            std::io::Error::last_os_error()
        );
    }
    ensure!(
        unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } == 0,
        "set no-new-privileges failed"
    );
    ensure!(
        unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset.as_raw_fd(), 0u32) } == 0,
        "restrict write scope: {}",
        std::io::Error::last_os_error()
    );
    Ok(
        json!({"schema":"jetstreamer-private-epoch213-write-scope-v1","landlock_abi":abi,"handled_mutation_rights":HANDLED,"allowed_mutation_rights":ALLOWED,"write_roots":paths,"no_new_privs":true,"chmod_chown_still_bound_by_publisher_path_checks":true}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abi_wire_structs_are_exact() {
        assert_eq!(std::mem::size_of::<Ruleset>(), 8);
        assert_eq!(std::mem::size_of::<PathRule>(), 12);
        assert_eq!(ALLOWED & !HANDLED, 0);
        assert_eq!(HANDLED & ((1 << 0) | (1 << 2) | (1 << 3)), 0);
    }

    #[test]
    #[ignore = "isolated kernel capability child; run explicitly, never restrict the libtest parent"]
    fn isolated_kernel_child() {
        let root = std::env::var_os("JETSTREAMER_213_SCOPE_TEST_ROOT").expect("test root");
        let root = Path::new(&root);
        let a = root.join("source");
        let b = root.join("work");
        let c = root.join("destination");
        same_mount(&[&a, &b, &c]).unwrap();
        // The idle libtest harness thread is outside this disposable child's
        // restricted test thread. Production confine() enforces one thread.
        restrict_writes(&[&a, &b, &c]).unwrap();
        assert!(fs::write(root.join("forbidden"), b"denied").is_err());
        assert!(
            OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(root.join("preserve"))
                .is_err()
        );
        fs::write(a.join("fixture"), b"not an archive").unwrap();
        fs::rename(a.join("fixture"), b.join("fixture")).unwrap();
        fs::rename(b.join("fixture"), c.join("fixture")).unwrap();
        assert_eq!(fs::read(c.join("fixture")).unwrap(), b"not an archive");
    }

    #[test]
    fn kernel_confinement_is_exercised_only_in_a_disposable_process() {
        // The production gate never skips or falls back on an unsupported host.
        if abi().is_err() {
            eprintln!("kernel Landlock unavailable; operational capability remains mandatory");
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        for name in ["source", "work", "destination"] {
            fs::create_dir(temp.path().join(name)).unwrap();
        }
        fs::write(temp.path().join("preserve"), b"preserve").unwrap();
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "write_scope::tests::isolated_kernel_child",
                "--ignored",
                "--nocapture",
            ])
            .env("JETSTREAMER_213_SCOPE_TEST_ROOT", temp.path())
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(fs::read(temp.path().join("preserve")).unwrap(), b"preserve");
        assert!(!temp.path().join("forbidden").exists());
    }
}
