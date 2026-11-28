//! A lower bound on physically resident, distinct regular files. A changing
//! unrelated database entry must never invalidate an independently visible
//! file's allocation. Every counted inode is reopened beneath its exact root
//! without traversing symlinks or mount points.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    ffi::CString,
    fs::{self, File},
    io,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt},
        },
    },
    path::{Path, PathBuf},
};
#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}
pub(super) fn beneath(root: &File, relative: &Path, flags: i32) -> io::Result<File> {
    let name = CString::new(relative.as_os_str().as_bytes())?;
    const RESOLVE_NO_XDEV: u64 = 0x01;
    const RESOLVE_NO_SYMLINKS: u64 = 0x04;
    const RESOLVE_BENEATH: u64 = 0x08;
    let how = OpenHow {
        flags: (flags | libc::O_CLOEXEC) as u64,
        mode: 0,
        resolve: RESOLVE_NO_XDEV | RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH,
    };
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            root.as_raw_fd(),
            name.as_ptr(),
            &how,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd as i32) })
}
fn candidate(m: &fs::Metadata, dev: u64) -> Option<(u64, u64)> {
    if !m.is_file() || m.dev() != dev || m.nlink() != 1 {
        return None;
    }
    let bytes = m.blocks().checked_mul(512)?.min(m.len() / 4096 * 4096);
    (bytes >= 2 << 20).then_some((m.ino(), bytes))
}
pub fn measure(path: &Path) -> Result<(u64, Value)> {
    stable_subset(path, false)
}
/// A drained diagnostic's paid accounts database can be rechecked alongside
/// its other retained files. Count only root-relative, twice witnessed blocks.
pub fn measure_closed(path: &Path) -> Result<(u64, Value)> {
    stable_subset(path, true)
}
fn stable_subset(path: &Path, drained: bool) -> Result<(u64, Value)> {
    let root = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let rm = root.metadata()?;
    let dev = rm.dev();
    ensure!(path.canonicalize()? == path, "peer root path changed");
    let mut remaining = vec![PathBuf::from(".")];
    let mut candidates = BTreeMap::new();
    let mut count = 0;
    let (max_entries, max_files, per_dir) = if drained {
        let mut limit = std::mem::MaybeUninit::uninit();
        ensure!(
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, limit.as_mut_ptr()) } == 0,
            "descriptor budget unavailable"
        );
        let open = fs::read_dir("/proc/self/fd")?.count();
        let spare = usize::try_from(unsafe { limit.assume_init() }.rlim_cur)
            .unwrap_or(usize::MAX)
            .saturating_sub(open + 64);
        (100_000, 16_384.min(spare), 32_768)
    } else {
        (20_000, 400, 384)
    };
    while let Some(rel) = remaining.pop() {
        if count >= max_entries || candidates.len() >= max_files {
            break;
        }
        let Ok(d) = beneath(&root, &rel, libc::O_DIRECTORY | libc::O_RDONLY) else {
            continue;
        };
        let inodes = fs::read_dir(format!("/proc/self/fd/{}", d.as_raw_fd()))?;
        for entry in inodes.take(per_dir) {
            count += 1;
            let Ok(e) = entry else {
                continue;
            };
            let child = rel.join(e.file_name());
            let Ok(ty) = e.file_type() else {
                continue;
            };
            if ty.is_dir() {
                // The large appendvec database supplies no credit in this
                // bounded subset. Its complete cap remains in the native fit.
                if (drained || e.file_name() != "accounts-state") && child.components().count() < 24
                {
                    remaining.push(child);
                }
            } else if ty.is_file() {
                let Ok(file) = beneath(&root, &child, libc::O_PATH) else {
                    continue;
                };
                if let Some((inode, bytes)) = candidate(&file.metadata()?, dev) {
                    candidates.entry(inode).or_insert((child, file, bytes));
                    if candidates.len() >= max_files {
                        break;
                    }
                }
            }
        }
    }
    let mut samples = Vec::new();
    let mut total = 0u64;
    for (inode, (name, file, first)) in candidates {
        let Ok(reopened) = beneath(&root, &name, libc::O_PATH) else {
            continue;
        };
        let same = candidate(&file.metadata()?, dev).zip(candidate(&reopened.metadata()?, dev));
        if let Some(((a, b), (c, d))) = same
            && a == inode
            && c == inode
        {
            let bytes = first.min(b).min(d);
            total = total
                .checked_add(bytes)
                .context("subset allocation overflow")?;
            samples.push((name, inode, bytes));
        }
    }
    let now = fs::symlink_metadata(path)?;
    ensure!(
        now.dev() == dev && now.ino() == rm.ino() && path.canonicalize()? == path,
        "peer root renamed"
    );
    let evidence = json!({"root":path,"root_dev":dev,"root_inode":rm.ino(),"lower_bound":total,
        "file_count":samples.len(),"files_sha256":crate::custody::sha(&serde_json::to_vec(&samples)?),"bounded_entries":count});
    Ok((total, evidence))
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::Write, os::unix::fs::symlink};
    #[test]
    fn unique_positive_allocations_only() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().join("root");
        fs::create_dir(&root).unwrap();
        let a = root.join("real");
        let mut f = File::create(&a).unwrap();
        f.write_all(&vec![1; 3 << 20]).unwrap();
        f.sync_all().unwrap();
        let sparse = File::create(root.join("sparse")).unwrap();
        sparse.set_len(20 << 20).unwrap();
        symlink(&a, root.join("symlink")).unwrap();
        let external = d.path().join("external");
        fs::create_dir(&external).unwrap();
        symlink(&external, root.join("external")).unwrap();
        assert_eq!(measure(&root).unwrap().0, 3 << 20);
        fs::hard_link(&a, external.join("alias")).unwrap();
        assert_eq!(measure(&root).unwrap().0, 0);
    }
}
