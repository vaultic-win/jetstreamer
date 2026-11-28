use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::path::Path;

fn sealed(reference: &Value) -> Result<Value> {
    let path = Path::new(reference["path"].as_str().context("evidence path")?);
    let hash = reference["sha256"].as_str().context("evidence digest")?;
    ensure!(
        path.starts_with("/var/lib/jetstreamer"),
        "unexpected evidence location"
    );
    Ok(serde_json::from_slice(&super::read_small(
        path,
        hash,
        2 << 20,
    )?)?)
}

pub(super) fn admit() -> Result<Value> {
    let first = super::first_guard::admit().map_err(|e| anyhow::anyhow!("{e}"))?;
    let plan = sealed(&first["startup_plan"])?;
    let admission = sealed(&plan["admission"])?;
    let token = sealed(&first["token"])?;
    let sample = sealed(&token["guard_sample"])?;
    let observed = super::tmpfs::observe(true)?;
    let root = &sample["root_physical_observation"];
    let mount = &admission["tmpfs"];
    ensure!(
        mount["root"] == super::ROOT
            && mount["bytes"] == super::tmpfs::BYTES
            && mount["inodes"] == super::tmpfs::INODES
            && mount["device"] == observed.device
            && mount["inode"] == observed.inode
            && mount["charged_within_memory_max"] == true
            && admission["disk_filesystem"] == super::FILESYSTEM
            && root["device"] == observed.device
            && root["inode"] == observed.inode
            && root["tmpfs_capacity_bytes"] == super::tmpfs::BYTES
            && root["total_inodes"] == super::tmpfs::INODES
            && root["conservative_physical_bytes"] == 0
            && observed.bytes == 0
            && root["free_inodes"] == observed.free_inodes
            && observed.free_inodes >= super::tmpfs::INODES - 1,
        "admitted mount, guard and pristine producer scratch differ"
    );
    // The original gate's deadline still applies to our extra evidence reads.
    let expires = admission["expires_unix_seconds"]
        .as_u64()
        .context("admission expiry")?;
    ensure!(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs()
            < expires,
        "expired tmpfs admission"
    );
    let mut clock: libc::timespec = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut clock) } == 0,
        "clock failed"
    );
    let micros = u64::try_from(clock.tv_sec)?
        .checked_mul(1_000_000)
        .and_then(|us| us.checked_add(clock.tv_nsec as u64 / 1000))
        .context("clock overflow")?;
    ensure!(
        micros
            < plan["expires_monotonic_us"]
                .as_u64()
                .context("startup deadline")?,
        "tmpfs startup deadline expired"
    );
    Ok(first)
}
