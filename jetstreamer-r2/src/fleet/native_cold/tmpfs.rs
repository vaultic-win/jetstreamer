fn valid_expiry(a: &Value) -> Result<bool> {
    Ok(num(a, "expires_unix_seconds")?
        .checked_sub(num(a, "issued_unix_seconds")?)
        .is_some_and(|d| (1..=60).contains(&d)))
}
fn sample_mount(first: &Value, sample: &Value) -> Result<()> {
    let original = &first["root_physical_observation"];
    let root = &sample["root_physical_observation"];
    ensure!(
        num(original, "device")? == num(root, "device")?
            && num(original, "inode")? == num(root, "inode")?
            && root["total_inodes"] == 1_048_576
            && root["tmpfs_capacity_bytes"] == TMPFS_BYTES
            && (4096..=1_048_576).contains(&num(root, "free_inodes")?)
            && root["exceeds_budget"] == false
            && num(root, "conservative_physical_bytes")? <= PROFILE.scratch,
        "{EPOCH} tmpfs identity or limits changed"
    );
    Ok(())
}
fn pin_mount(first: &Value, pin: &Value) -> Result<()> {
    let root = &first["root_physical_observation"];
    ensure!(
        num(root, "device")? == num(pin, "device")? && num(root, "inode")? == num(pin, "inode")?,
        "{EPOCH} terminal root pin changed"
    );
    Ok(())
}
#[cfg(test)]
fn mount_fixture(sample: &mut Value, pin: &mut Value) {
    let r = &mut sample["root_physical_observation"];
    r["device"] = json!(15);
    r["inode"] = json!(1);
    r["total_inodes"] = json!(1_048_576);
    r["tmpfs_capacity_bytes"] = json!(TMPFS_BYTES);
    r["free_inodes"] = json!(1_048_575);
    pin["device"] = r["device"].clone();
    pin["inode"] = r["inode"].clone();
}
fn observation_mount(observation: &Value, h: &Value) -> Result<()> {
    let first = sealed(&binding(&h["first_guard_sample"])?)?;
    let mut peak = 0;
    for k in ["scratch_pass_1", "scratch_pass_2"] {
        let r = &observation[k];
        sample_mount(&first, &json!({"root_physical_observation":r}))?;
        peak = peak.max(num(r, "conservative_physical_bytes")?);
    }
    ensure!(
        observation["scratch_measurement_method"] == "dedicated tmpfs superblock"
            && observation["conservative_observed_physical_bytes"] == peak,
        "{EPOCH} observer scratch accounting differs"
    );
    Ok(())
}

#[cfg(test)]
mod mount_tests {
    use super::*;
    #[test]
    fn periodic_samples_and_terminal_pin_keep_the_admitted_superblock() {
        let mut s = json!({"root_physical_observation":{"exceeds_budget":false,"conservative_physical_bytes":100}});
        let mut pin = json!({});
        mount_fixture(&mut s, &mut pin);
        sample_mount(&s, &s).unwrap();
        pin_mount(&s, &pin).unwrap();
        for key in [
            "device",
            "inode",
            "tmpfs_capacity_bytes",
            "free_inodes",
            "total_inodes",
            "conservative_physical_bytes",
            "exceeds_budget",
        ] {
            let mut changed = s.clone();
            changed["root_physical_observation"][key] = Value::Null;
            assert!(sample_mount(&s, &changed).is_err());
        }
        pin["device"] = json!(16);
        assert!(pin_mount(&s, &pin).is_err());
    }
}
