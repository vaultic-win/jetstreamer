use super::*;

// The held process has yet to receive its token. No use of the scratch mount,
// including an unlinked allocation, is expected on either side of first fire.
pub(super) fn check_devices(latest: &Value, admitted: &Value) -> Result<()> {
    ensure!(
        latest["disk_filesystem"] == FILESYSTEM
            && latest["disk_device"] == admitted["disk_device"]
            && latest["boot_id"] == admitted["boot_id"]
            && latest["tmpfs"] == admitted["tmpfs"],
        "{EPOCH} devices changed since admission"
    );
    Ok(())
}
pub(super) fn check_mount_sample(a: &Value, g: &Value) -> Result<()> {
    let m = &a["tmpfs"];
    let r = &g["root_physical_observation"];
    ensure!(
        a["disk_filesystem"] == FILESYSTEM
            && num(a, "disk_device")? != num(m, "device")?
            && num(m, "inode")? > 0
            && m["root"] == ROOT
            && m["bytes"] == tmpfs::BYTES
            && m["inodes"] == tmpfs::INODES
            && m["used_bytes"] == 0
            && m["charged_within_memory_max"] == true
            && m["maximum_root_physical_bytes"] == ROOT_CAP
            && m["minimum_free_bytes"] == tmpfs::BYTES - ROOT_CAP
            && m["minimum_free_inodes"] == 4096
            && (tmpfs::INODES - 1..=tmpfs::INODES).contains(&num(m, "free_inodes")?)
            && r["device"] == m["device"]
            && r["inode"] == m["inode"]
            && r["total_inodes"] == m["inodes"]
            && r["tmpfs_capacity_bytes"] == m["bytes"]
            && r["free_inodes"] == m["free_inodes"]
            && r["maximum_physical_bytes"] == ROOT_CAP
            && r["conservative_physical_bytes"] == 0
            && r["exceeds_budget"] == false,
        "{EPOCH} first guard did not protect the admitted empty tmpfs"
    );
    Ok(())
}
#[cfg(test)]
pub(super) fn sample_fixture(a: &mut Value, g: &mut Value) {
    a["disk_filesystem"] = json!(FILESYSTEM);
    a["disk_device"] = json!(8);
    a["tmpfs"] = json!({"device":9,"inode":1,"root":ROOT,"bytes":tmpfs::BYTES,"inodes":tmpfs::INODES,"used_bytes":0,"free_inodes":tmpfs::INODES-1,"minimum_free_inodes":4096,"maximum_root_physical_bytes":ROOT_CAP,"minimum_free_bytes":tmpfs::BYTES-ROOT_CAP,"charged_within_memory_max":true});
    g["root_physical_observation"] = json!({"device":9,"inode":1,"total_inodes":tmpfs::INODES,"free_inodes":tmpfs::INODES-1,"tmpfs_capacity_bytes":tmpfs::BYTES,"maximum_physical_bytes":ROOT_CAP,"conservative_physical_bytes":0,"exceeds_budget":false});
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_changed_mount_funding_and_inode_consumption() {
        let (mut a, mut g) = (json!({}), json!({}));
        sample_fixture(&mut a, &mut g);
        check_mount_sample(&a, &g).unwrap();
        for field in [
            "device",
            "inode",
            "total_inodes",
            "free_inodes",
            "tmpfs_capacity_bytes",
            "conservative_physical_bytes",
            "exceeds_budget",
        ] {
            let mut s = g.clone();
            s["root_physical_observation"][field] = Value::Null;
            assert!(check_mount_sample(&a, &s).is_err());
        }
        a["tmpfs"]["charged_within_memory_max"] = json!(false);
        assert!(check_mount_sample(&a, &g).is_err());
    }
}
