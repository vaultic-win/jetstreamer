//! The dedicated superblock counts all tmpfs blocks, including unlinked open files.
use super::{profile, tmpfs};
use anyhow::{Result, ensure};
use serde::Serialize;
use std::{fs, os::unix::fs::MetadataExt, path::Path};

#[derive(Serialize)]
pub(super) struct Observation {
    pub exceeds_budget: bool,
    maximum_physical_bytes: u64,
    conservative_physical_bytes: u64,
    device: u64,
    inode: u64,
    tmpfs_capacity_bytes: u64,
    free_inodes: u64,
    total_inodes: u64,
}

pub(super) fn observe(root: &Path, maximum: u64) -> Result<Observation> {
    ensure!(
        root == Path::new(profile::ROOT) && maximum == profile::ROOT_CAP,
        "foreign root budget"
    );
    let sampled = tmpfs::observe(false)?;
    let pid = super::unit()?.pid;
    ensure!(pid > 1, "producer unavailable");
    let producer = fs::metadata(format!("/proc/{pid}/root{}", profile::ROOT))?;
    ensure!(
        (producer.dev(), producer.ino()) == (sampled.device, sampled.inode),
        "producer and guard see different mounts"
    );
    tmpfs::mount_row(
        &fs::read_to_string(format!("/proc/{pid}/mountinfo"))?,
        producer.dev(),
        true,
    )?;
    Ok(Observation {
        exceeds_budget: sampled.bytes > maximum || sampled.free_inodes < 4096,
        maximum_physical_bytes: maximum,
        conservative_physical_bytes: sampled.bytes,
        device: sampled.device,
        inode: sampled.inode,
        tmpfs_capacity_bytes: tmpfs::BYTES,
        free_inodes: sampled.free_inodes,
        total_inodes: tmpfs::INODES,
    })
}
