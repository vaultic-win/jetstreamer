pub(super) fn sample(n: &super::NativeConfig) -> anyhow::Result<(serde_json::Value, u64)> {
    use anyhow::ensure;
    use std::path::Path;
    let sample = tmpfs::observe(false)?;
    ensure!(
        n.scratch_path == Path::new(profile::ROOT),
        "foreign native scratch"
    );
    let used = sample.bytes;
    Ok((
        serde_json::json!({"device":sample.device,"inode":sample.inode,"tmpfs_capacity_bytes":tmpfs::BYTES,"total_inodes":tmpfs::INODES,"free_inodes":sample.free_inodes,"conservative_physical_bytes":used,"exceeds_budget":used > ROOT_CAP || sample.free_inodes < 4096}),
        used,
    ))
}
