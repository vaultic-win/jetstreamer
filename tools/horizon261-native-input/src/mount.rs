// Both processes verify their own view of a dedicated, kernel-limited mount.
use super::profile::{FILESYSTEM, ROOT};
use anyhow::{Context, Result, ensure};
use std::{
    fs::{self, File},
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    path::Path,
};

pub(crate) struct Usage {
    pub device: u64,
    pub inode: u64,
    pub bytes: u64,
    pub free_inodes: u64,
}

pub(crate) fn mount_row(table: &str, device: u64, require_writable: bool) -> Result<()> {
    let wanted = format!("{}:{}", libc::major(device), libc::minor(device));
    let mut found = false;
    for line in table.lines() {
        let (before, after) = line.split_once(" - ").context("invalid mount record")?;
        let fields: Vec<_> = before.split_whitespace().collect();
        let target = Path::new(fields.get(4).context("missing mount target")?);
        if !target.starts_with(ROOT) {
            continue;
        }
        ensure!(
            target == Path::new(ROOT) && !found,
            "nested or stacked scratch mount"
        );
        let kind: Vec<_> = after.split_whitespace().collect();
        let flags: Vec<_> = fields.get(5).context("mount flags")?.split(',').collect();
        ensure!(
            fields[2] == wanted
                && fields[3] == "/"
                && kind.len() == 3
                && kind[0] == "tmpfs"
                && kind[1] == SOURCE
                && kind[2].split(',').any(|option| option == "noswap")
                && ["nodev", "nosuid", "noexec"]
                    .iter()
                    .all(|f| flags.contains(f))
                && (!require_writable || flags.contains(&"rw")),
            "scratch mount type, source, device, root or flags changed"
        );
        found = true;
    }
    ensure!(found, "scratch mount missing");
    Ok(())
}

pub(crate) fn observe(require_writable: bool) -> Result<Usage> {
    let path = Path::new(ROOT);
    ensure!(path.canonicalize()? == path, "noncanonical scratch");
    let fd = File::open(path)?;
    let m = fd.metadata()?;
    ensure!(
        m.is_dir()
            && m.ino() == 1
            && m.uid() == 1000
            && m.gid() == 1000
            && m.mode() & 0o7777 == 0o700
            && m.dev() != fs::metadata(FILESYSTEM)?.dev(),
        "scratch root custody/device differs"
    );
    mount_row(
        &fs::read_to_string("/proc/self/mountinfo")?,
        m.dev(),
        require_writable,
    )?;
    let mut s: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(fd.as_raw_fd(), &mut s) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let block = u64::try_from(s.f_bsize)?;
    ensure!(
        s.f_type == libc::TMPFS_MAGIC
            && s.f_blocks.checked_mul(block) == Some(BYTES)
            && s.f_files == INODES
            && s.f_ffree <= INODES
            && s.f_bavail <= s.f_blocks,
        "scratch tmpfs limits changed"
    );
    let recheck = fs::metadata(path)?;
    ensure!(
        (m.dev(), m.ino()) == (recheck.dev(), recheck.ino()),
        "scratch replaced"
    );
    Ok(Usage {
        device: m.dev(),
        inode: m.ino(),
        bytes: (s.f_blocks - s.f_bavail) * block,
        free_inodes: s.f_ffree,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_subtree_overmounts_other_devices_flags_and_aliases() {
        let d = libc::makedev(0, 88);
        let row = format!(
            "9 2 0:88 / {ROOT} rw,nosuid,nodev,noexec - tmpfs {SOURCE} rw,noswap,size=134217728k"
        );
        mount_row(&row, d, true).unwrap();
        assert!(mount_row(&row.replace(" rw,nosuid", " ro,nosuid"), d, true).is_err());
        for bad in [
            row.replace("0:88", "0:89"),
            row.replace(" / ", " /child "),
            row.replace("nodev", "dev"),
            row.replace(SOURCE, "foreign-scratch"),
            format!("{row}\n{row}"),
            format!("{row}\n{}", row.replace(ROOT, &format!("{ROOT}/scratch"))),
        ] {
            assert!(mount_row(&bad, d, false).is_err());
        }
    }
}
