//! Retain and mask only the already-stopped, obsolete136–147 controller.
//! No replay-data removal, producer signal or remote access.
use super::*;

const ORIGINAL: &str =
    "/etc/systemd/system/jetstreamer-epochs136-147-target4-controller-v1-r2.service";
const ARCHIVE: &str = "/usr/local/lib/jetstreamer/horizon-terminal136-controller-backup-20261023-v1/retained-controller.service.txt";
const CONFIG_SHA: &str = "104025f3fec6c25b011415802c4c53ce54c4c2b0d5d93a1882e908177d16148a";
const ROOT: &str = "/var/lib/jetstreamer/horizon-terminal136-controller-retirement-20261023-v1";
const RETAINED: &str = "/var/lib/jetstreamer/horizon-terminal136-controller-retirement-20261023-v1/original-controller.service.txt";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Disable {
    schema: String,
    mapping: Bound,
    terminal: Bound,
    qualification: Bound,
    archived_unit: Bound,
}

fn checked_bytes(path: &Path, sha: &str, uid: u32) -> Result<Vec<u8>> {
    let before = regular_identity(path)?;
    let md = fs::symlink_metadata(path)?;
    ensure!(
        path.canonicalize()? == path
            && md.uid() == uid
            && md.mode() & 0o022 == 0
            && before.length <= 1 << 20,
        "unsafe136 controller configuration"
    );
    let bytes = fs::read(path)?;
    ensure!(
        regular_identity(path)? == before && hex_lower(&Sha256::digest(&bytes)) == sha,
        "136 controller configuration differs"
    );
    Ok(bytes)
}

// Shared with disposable fixture tests; production paths are fixed above.
fn retain_and_mask(original: &Path, retained: &Path, sha: &str, uid: u32) -> Result<()> {
    match fs::symlink_metadata(original) {
        Ok(md) if md.is_file() => {
            checked_bytes(original, sha, uid)?;
            ensure!(
                fs::symlink_metadata(retained)
                    .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
                "136 retained controller is occupied"
            );
            rename_noreplace(original, retained)?;
            File::open(original.parent().context("controller source parent")?)?.sync_all()?;
        }
        Ok(md) if md.file_type().is_symlink() => {
            ensure!(
                fs::read_link(original)? == Path::new("/dev/null"),
                "foreign controller alias"
            );
            checked_bytes(retained, sha, uid)?;
            return Ok(());
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Intent and the separately sealed original are checked by caller.
            // Resume a crash after the original inode was durably retained.
            checked_bytes(retained, sha, uid)?;
        }
        Err(e) => return Err(e.into()),
        _ => bail!("unsupported136 controller path"),
    }
    checked_bytes(retained, sha, uid)?;
    std::os::unix::fs::symlink("/dev/null", original)?;
    File::open(original.parent().context("controller mask parent")?)?.sync_all()?;
    ensure!(
        fs::read_link(original)? == Path::new("/dev/null"),
        "controller mask differs"
    );
    Ok(())
}

pub(super) fn disable(m: &Mapping, p: &Disable, spec: &Bound) -> Result<()> {
    ensure!(
        p.schema == "jetstreamer-horizon-holding-disable136-retry-plan-v2"
            && p.archived_unit.path == Path::new(ARCHIVE)
            && p.archived_unit.sha256 == CONFIG_SHA,
        "foreign136 controller retirement scope"
    );
    let supplied: Mapping = serde_json::from_value(bound(&p.mapping)?)?;
    mapping(&supplied)?;
    ensure!(
        supplied.host == m.host && supplied.prefix == m.prefix,
        "136 control mapping changed"
    );
    let common = Inspect {
        schema: "jetstreamer-horizon-holding-inspect136-plan-v2".into(),
        mapping: p.mapping.clone(),
        terminal: p.terminal.clone(),
        qualification: p.qualification.clone(),
    };
    scope(&common, m, &bound(&p.terminal)?, &bound(&p.qualification)?)?;
    let md = fs::symlink_metadata(ARCHIVE)?;
    ensure!(
        md.uid() == 0 && md.mode() & 0o222 == 0,
        "136 configuration backup is mutable"
    );
    checked_bytes(Path::new(ARCHIVE), CONFIG_SHA, 0)?;
    let before = terminal_unit(CONTROLLER)?;
    terminal_unit(PRODUCER)?;
    private(Path::new(ROOT))?;
    let intent = Path::new(ROOT).join("intent.json");
    let completion = Path::new(ROOT).join("completion.json");
    let descriptor = json!({"schema":"jetstreamer-terminal136-controller-retirement-intent-v2",
        "host":HOST,"controller":CONTROLLER,"original":ORIGINAL,"retained":RETAINED,
        "config_sha256":CONFIG_SHA,"archived_unit":p.archived_unit,"mapping":p.mapping,
        "terminal":p.terminal,"qualification":p.qualification,
        "producer_signal_authorized":false,"replay_data_retirement_authorized":false,
        "replay_launch_authorized":false,"remote_mutations":false,"r2_mutations":false});
    if fs::symlink_metadata(ORIGINAL).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
        || fs::symlink_metadata(ORIGINAL)?.file_type().is_symlink()
    {
        let mut expected = serde_json::to_vec_pretty(&descriptor)?;
        expected.push(b'\n');
        let recorded = checked_bytes(&intent, &hex_lower(&Sha256::digest(&expected)), 0)?;
        ensure!(
            serde_json::from_slice::<Value>(&recorded)? == descriptor,
            "136 recovery intent differs"
        );
    }
    persist(&intent, &descriptor)?;
    retain_and_mask(Path::new(ORIGINAL), Path::new(RETAINED), CONFIG_SHA, 0)?;
    let reload = std::process::Command::new("/usr/bin/systemctl")
        .arg("daemon-reload")
        .output()?;
    ensure!(
        reload.status.success(),
        "136 controller mask is durable but manager reload failed"
    );
    let after = terminal_unit(CONTROLLER)?;
    ensure!(
        after["LoadState"] == "masked",
        "136 old controller not masked in manager"
    );
    terminal_unit(PRODUCER)?;
    let intent_sha = hex_lower(&Sha256::digest(fs::read(&intent)?));
    // Completion preserves first transition bytes across idempotent retries.
    if completion.try_exists()? {
        let old: Value = serde_json::from_slice(&fs::read(&completion)?)?;
        ensure!(
            old["intent_sha256"] == intent_sha
                && old["masked"] == true
                && old["config_sha256"] == CONFIG_SHA,
            "136 mask completion conflict"
        );
    } else {
        persist(
            &completion,
            &json!({"schema":"jetstreamer-terminal136-controller-retirement-v2",
            "host":HOST,"controller":CONTROLLER,"intent_sha256":intent_sha,
            "config_sha256":CONFIG_SHA,"retained":RETAINED,"masked":true,
            "spec":{"path":spec.path,"sha256":spec.sha256},"before":before,"after":after,
            "replay_data_removed":false,"producer_signalled":false,"replay_launch_authorized":false,
            "remote_mutations":false,"r2_mutations":false,"new_resource_samples":0}),
        )?;
    }
    println!("{}", completion.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stopped_configuration_is_retained_before_mask_and_retry_preserves_bytes() {
        let d = tempfile::tempdir().unwrap();
        let original = d.path().join("original.service");
        let retained = d.path().join("retained.txt");
        let bytes = b"[Service]\nExecStart=/fixture/never-launched\n";
        fs::write(&original, bytes).unwrap();
        fs::set_permissions(&original, fs::Permissions::from_mode(0o600)).unwrap();
        let sha = hex_lower(&Sha256::digest(bytes));
        let uid = unsafe { libc::geteuid() };
        retain_and_mask(&original, &retained, &sha, uid).unwrap();
        assert_eq!(fs::read_link(&original).unwrap(), Path::new("/dev/null"));
        assert_eq!(fs::read(&retained).unwrap(), bytes);
        retain_and_mask(&original, &retained, &sha, uid).unwrap();
        assert_eq!(fs::read(&retained).unwrap(), bytes);
        fs::remove_file(&original).unwrap();
        retain_and_mask(&original, &retained, &sha, uid).unwrap();
        assert_eq!(fs::read_link(&original).unwrap(), Path::new("/dev/null"));
    }
    #[test]
    fn changed_or_conflicting_configuration_is_never_replaced() {
        let d = tempfile::tempdir().unwrap();
        let original = d.path().join("original.service");
        let retained = d.path().join("retained.txt");
        fs::write(&original, b"original").unwrap();
        fs::write(&retained, b"conflict").unwrap();
        fs::set_permissions(&original, fs::Permissions::from_mode(0o600)).unwrap();
        let uid = unsafe { libc::geteuid() };
        let sha = hex_lower(&Sha256::digest(b"original"));
        assert!(retain_and_mask(&original, &retained, &sha, uid).is_err());
        assert_eq!(fs::read(&original).unwrap(), b"original");
        assert_eq!(fs::read(&retained).unwrap(), b"conflict");
        fs::remove_file(&retained).unwrap();
        assert!(retain_and_mask(&original, &retained, &"a".repeat(64), uid).is_err());
        assert_eq!(fs::read(&original).unwrap(), b"original");
    }
}
