//! Read-only closure and namespace check for the byte-restored epoch 228 image.
use super::{snapshot288::Stamp, *};
use std::collections::{BTreeMap, BTreeSet};
mod retire;

pub(super) fn retire(self_sha: &str, fit_sha: &str, remote_sha: &str) -> Result<()> {
    retire::run(self_sha, fit_sha, remote_sha)
}

const IMAGE: &str = "/var/lib/jetstreamer/horizon228-native-root-tail-v166-a1/pilot/private.ext4";
const TARGET: &str = "/home/ubuntu/.jetstreamer-private/qualification-228-demotion-root-tail-v1";
const LOOP: &str = "/dev/loop6";
const LOOP_DEVICE: &str = "7:6";
const KEY: &str = "/var/lib/jetstreamer/horizon228-private-guest-staging-v1/ext4-custody.key";
const UNIT: &str = "horizon-qualify-228-demotion-root-tail-16d4b158-v1.service";
const RESTORE_UNIT: &str = "horizon-restore-228-ext4-check-v1.service";
const RESTORE_IID: &str = "2f551b08ebe245f78105eca39ac8842c";
const RESTORE: &str = "/var/lib/jetstreamer/horizon-foundation-closed-private-holding-v1/receipts/ext4-228-restore-check-ae0a442fd488bea33793d7eba7cf1c6998956370bce500835b1d7fc643daa636.json";
const RESTORE_SHA: &str = "daab83badad2c57eaf0fcaee26595f87abfc65677f0e1fe9bebb3387c2174a61";
const STAGED: &str = "/var/lib/jetstreamer/horizon228-private-guest-staging-v1/completion.json";
const STAGED_SHA: &str = "50e47040a041c590e48126f21b3ce32a0bcef052f262ef7177a9a4de87791420";
const BUNDLE_RELEASE: &str =
    "/var/lib/jetstreamer/horizon228-ext4-custody-plan-v1/bundle-release-completion.json";
const BUNDLE_RELEASE_SHA: &str = "10ccf19c2bb31e53d6150d6a087cc783eee49d4f9002dbc53cbcb73fa427353b";
const GUEST_SHA: &str = "74f8b4e404a3c2133508e82840229a4219def94b434f2d00c1797173493b98b8";
const BYTES: u64 = 120_259_084_288;
const ALLOCATED: u64 = 100_193_267_712;
const DEVICE: u64 = 66_305;
const INODE: u64 = 18_330_573;
const HOST_MOUNT_ID: &str = "1167";

fn clean_restore() -> Result<Value> {
    let restore: Value = read_bound(Path::new(RESTORE), RESTORE_SHA, JSON_LIMIT)?;
    let custody = value(&restore["custody"])?;
    let staged: Value = read_bound(Path::new(STAGED), STAGED_SHA, JSON_LIMIT)?;
    let release: Value = read_bound(Path::new(BUNDLE_RELEASE), BUNDLE_RELEASE_SHA, JSON_LIMIT)?;
    let body = &restore["restored_guest"];
    ensure!(
        restore["schema"] == "foundation-epoch228-ext4-restore-check-receipt-v1"
            && restore["epoch"] == 228
            && restore["unit"] == RESTORE_UNIT
            && restore["invocation_id"] == RESTORE_IID
            && restore["remote_decryption_authenticated"] == true
            && restore["local_retirement_authorized"] == false
            && restore["publication_authorized"] == false
            && body["sha256"] == GUEST_SHA
            && body["bytes"] == BYTES
            && body["e2fsck_exit_status"] == 0
            && restore["object_key"] == custody["manifest"]["object_key"]
            && restore["object_etag"] == custody["object_etag"]
            && restore["cipher_sha256"] == custody["manifest"]["sha256"]
            && custody["remote_sha256_readback"] == true
            && custody["remote_authenticated_decryption_verified"] == true
            && custody["manifest"]["guest_sha256"] == GUEST_SHA
            && custody["manifest"]["guest_length"] == BYTES
            && staged["closed_guest"]["path"] == IMAGE
            && staged["closed_guest"]["sha256"] == GUEST_SHA
            && staged["closed_guest"]["allocated_bytes"] == ALLOCATED
            && staged["closed_guest"]["logical_bytes"] == BYTES
            && release["allocated_bundle_bytes_released"] == 70_136_893_440u64,
        "exact encrypted custody, restore, or original image evidence differs"
    );
    let message = format!("{RESTORE_UNIT}: Deactivated successfully.");
    let output = Command::new("/usr/bin/journalctl")
        .args([
            "--quiet",
            "--no-pager",
            "-b",
            "-o",
            "json",
            "--lines=2",
            "_PID=1",
        ])
        .args([
            format!("UNIT={RESTORE_UNIT}"),
            format!("INVOCATION_ID={RESTORE_IID}"),
            format!("MESSAGE={message}"),
        ])
        .output()?;
    ensure!(
        output.status.success(),
        "could not read restore terminal event"
    );
    let event: Value = serde_json::from_slice(&output.stdout)?;
    ensure!(
        event["_SYSTEMD_UNIT"] == "init.scope"
            && event["UNIT"] == RESTORE_UNIT
            && event["MESSAGE"] == message
            && event["INVOCATION_ID"] == RESTORE_IID,
        "wrong restore manager event"
    );
    Ok(json!({"receipt":Binding {path:RESTORE.into(),sha256:RESTORE_SHA.into()},"terminal":event}))
}

fn device_rows(table: &str) -> Vec<(&str, Vec<&str>, Vec<&str>)> {
    table
        .lines()
        .filter_map(|row| {
            let (front, back) = row.split_once(" - ")?;
            let fields: Vec<_> = front.split_whitespace().collect();
            (fields.get(2) == Some(&LOOP_DEVICE))
                .then(|| (row, fields, back.split_whitespace().collect()))
        })
        .collect()
}

fn inherited_mount(table: &str, master: Option<&str>) -> Result<Option<String>> {
    let mounts = device_rows(table);
    ensure!(mounts.len() <= 1, "stacked or aliased epoch 228 ext4 mount");
    let Some((row, fields, filesystem)) = mounts.first() else {
        return Ok(None);
    };
    ensure!(
        fields.get(3..5) == Some(&["/", TARGET])
            && filesystem.get(..2) == Some(&["ext4", LOOP])
            && filesystem
                .get(2)
                .is_some_and(|options| options.split(',').any(|value| value == "ro")),
        "foreign or writable epoch 228 ext4 mount"
    );
    if let Some(master) = master {
        ensure!(
            fields.get(6..).is_some_and(|tags| tags.contains(&master)),
            "guest mount outside the host propagation group"
        );
    } else {
        ensure!(
            fields[0] == HOST_MOUNT_ID && fields[5].split(',').any(|value| value == "ro"),
            "original host ext4 mount differs"
        );
    }
    Ok(Some((*row).to_owned()))
}

fn mount_census(expect_host_mount: bool) -> Result<Value> {
    let host = Path::new("/proc/1");
    let host_ns = host.join("ns/mnt").read_link()?;
    ensure!(
        Path::new("/proc/self/ns/mnt").read_link()? == host_ns,
        "check must use the host mount namespace"
    );
    let host_table = fs::read_to_string(host.join("mountinfo"))?;
    let host_row = inherited_mount(&host_table, None)?;
    ensure!(
        host_row.is_some() == expect_host_mount,
        "host loop6 mount differs from the retirement phase"
    );
    let propagation = host_row
        .as_ref()
        .map(|row| {
            let id = row
                .split_once(" - ")
                .context("host mountinfo")?
                .0
                .split_whitespace()
                .skip(6)
                .find_map(|tag| tag.strip_prefix("shared:"))
                .context("host ext4 mount is not shared")?;
            ensure!(
                id.bytes().all(|byte| byte.is_ascii_digit()),
                "invalid mount propagation ID"
            );
            Ok::<_, anyhow::Error>(id.to_owned())
        })
        .transpose()?;
    let master = propagation.as_ref().map(|id| format!("master:{id}"));
    let mut visited = BTreeSet::from([host_ns.clone()]);
    let mut matching = BTreeMap::new();
    if let Some(row) = host_row {
        matching.insert(host_ns, row);
    }
    for entry in fs::read_dir("/proc")? {
        let process = entry?;
        if !process
            .file_name()
            .as_encoded_bytes()
            .iter()
            .all(u8::is_ascii_digit)
        {
            continue;
        }
        let process = process.path();
        let link = process.join("ns/mnt");
        let namespace = match link.read_link() {
            Ok(namespace) => namespace,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        if visited.contains(&namespace) {
            continue;
        }
        let inspected = (|| -> Result<Option<String>> {
            let table = fs::read_to_string(process.join("mountinfo"))?;
            ensure!(
                table.len() <= 16 << 20 && link.read_link()? == namespace,
                "mount census changed"
            );
            if let Some(master) = &master {
                inherited_mount(&table, Some(master))
            } else {
                ensure!(
                    device_rows(&table).is_empty(),
                    "loop6 mount survived host unmount"
                );
                Ok(None)
            }
        })();
        match inspected {
            Ok(row) => {
                if let Some(row) = row {
                    matching.insert(namespace.clone(), row);
                }
                visited.insert(namespace);
            }
            Err(_) if !process.try_exists()? => {}
            Err(error) => return Err(error),
        }
    }
    Ok(
        json!({"inspected_namespaces":visited.len(),"host_shared_group":propagation,"mounts":matching}),
    )
}

fn closed() -> Result<()> {
    terminal_unit(UNIT)?;
    terminal_unit(RESTORE_UNIT)?;
    terminal_unit("horizon-228-root-tail-protective-v1.timer")?;
    for unit in [
        "horizon-228-root-tail-protective-v1.service",
        "horizon-228-root-tail-protective-v1-failsafe.service",
    ] {
        let response = Command::new("/usr/bin/systemctl")
            .args([
                "show",
                unit,
                "-p",
                "ActiveState,MainPID,ControlPID,Job,ControlGroup",
            ])
            .output()?;
        let fields = std::str::from_utf8(&response.stdout)?;
        ensure!(
            response.status.success()
                && [
                    "ActiveState=failed",
                    "MainPID=0",
                    "ControlPID=0",
                    "Job=",
                    "ControlGroup="
                ]
                .iter()
                .all(|field| fields.lines().any(|line| line == *field)),
            "original 228 guard is not closed"
        );
    }
    Ok(())
}

fn image_identity() -> Result<Metadata> {
    let image = Path::new(IMAGE);
    let file = open_regular(image)?;
    let meta = file.metadata()?;
    ensure!(
        meta.dev() == DEVICE
            && meta.ino() == INODE
            && meta.len() == BYTES
            && meta.uid() == 0
            && meta.gid() == 0
            && meta.mode() & 0o7777 == 0o600
            && meta.blocks().checked_mul(512) == Some(ALLOCATED)
            && (
                meta.mtime(),
                meta.mtime_nsec(),
                meta.ctime(),
                meta.ctime_nsec()
            ) == (1795329893, 696304720, 1795329893, 696304720),
        "closed image no longer matches authenticated staging identity"
    );
    ensure!(
        identity(&meta) == identity(&image.symlink_metadata()?),
        "closed ext4 image changed during check"
    );
    Ok(meta)
}

fn key_identity() -> Result<Metadata> {
    let key = Path::new(KEY).symlink_metadata()?;
    ensure!(
        Path::new(KEY).canonicalize()? == Path::new(KEY)
            && key.is_file()
            && key.nlink() == 1
            && key.dev() == DEVICE
            && key.uid() == 0
            && key.gid() == 0
            && key.mode() & 0o7777 == 0o400
            && key.len() == 65,
        "durable custody key identity differs"
    );
    Ok(key)
}

fn bound_loop() -> Result<()> {
    let loop_info = Command::new("/usr/sbin/losetup")
        .args(["-n", "-O", "NAME,RO,BACK-INO,BACK-FILE", LOOP])
        .output()?;
    ensure!(
        loop_info.status.success()
            && std::str::from_utf8(&loop_info.stdout)?
                .split_whitespace()
                .eq([LOOP, "1", "18330573", IMAGE])
            && fs::read_dir("/sys/class/block/loop6/holders")?
                .next()
                .is_none(),
        "loop6 was replaced, became writable, or has block consumers"
    );
    Ok(())
}

fn references() -> Result<BTreeMap<&'static str, process_references::Scan>> {
    let mut references = BTreeMap::new();
    for path in [TARGET, IMAGE, LOOP] {
        let scan = process_references::scan(Path::new("/proc"), Path::new(path))?;
        references.insert(path, scan);
    }
    Ok(references)
}

pub(super) fn check(self_sha: &str) -> Result<()> {
    let restore = clean_restore()?;
    closed()?;
    let meta = image_identity()?;
    let key = key_identity()?;
    bound_loop()?;
    let mounts = mount_census(true)?;
    let schedule = scheduled_census(Path::new(TARGET), Path::new(TARGET))?;
    let references = references()?;
    ensure!(
        identity(&meta) == identity(&Path::new(IMAGE).symlink_metadata()?),
        "closed ext4 image changed during check"
    );
    println!(
        "{}",
        json!({
            "schema":"foundation-epoch228-ext4-retirement-precheck-v1","epoch":228,
            "self_sha256":self_sha,"authenticated_restore":restore,"image":IMAGE,"image_stamp":Stamp::of(&meta)?,
            "key_location":KEY,"key_device":key.dev(),"key_inode":key.ino(),
            "mount_census":mounts,"process_references":references,"scheduled_references":schedule,
            "historical_extent_credit_bytes":0,"reclaimed_bytes":0,"source_retirement_authorized":false,
            "r2_mutations":false
        })
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inherited_mount_must_keep_the_exact_read_only_superblock_and_target() {
        let host = format!(
            "{HOST_MOUNT_ID} 47 7:6 / {TARGET} ro,nosuid,nodev shared:1380 - ext4 {LOOP} ro"
        );
        let child = format!(
            "1475 74 7:6 / {TARGET} rw,nosuid,nodev shared:1391 master:1380 - ext4 {LOOP} ro"
        );
        assert!(inherited_mount(&host, None).unwrap().is_some());
        assert!(
            inherited_mount(&child, Some("master:1380"))
                .unwrap()
                .is_some()
        );
        for invalid in [
            child.replace("master:1380", "master:1381"),
            child.replace(TARGET, "/other/path"),
            child.replace(&format!("{LOOP} ro"), &format!("{LOOP} rw")),
            format!("{child}\n{child}"),
        ] {
            assert!(inherited_mount(&invalid, Some("master:1380")).is_err());
        }
    }
}
