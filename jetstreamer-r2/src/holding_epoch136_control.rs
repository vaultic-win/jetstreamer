//! Retain bytes and mask only the stopped, obsolete 136–147 controller.
//! Copies cross sandbox bind mounts; rename/exchange stay within one parent.
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct OriginalId {
    device: u64,
    inode: u64,
    length: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
}
impl From<FileIdentity> for OriginalId {
    fn from(id: FileIdentity) -> Self {
        Self {
            device: id.device,
            inode: id.inode,
            length: id.length,
            modified_seconds: id.modified_seconds,
            modified_nanoseconds: id.modified_nanoseconds,
        }
    }
}

fn checked_bytes(path: &Path, sha: &str, uid: u32) -> Result<Vec<u8>> {
    let before = regular_identity(path)?;
    let md = fs::symlink_metadata(path)?;
    ensure!(
        path.canonicalize()? == path
            && md.uid() == uid
            && md.nlink() == 1
            && md.mode() & 0o022 == 0
            && before.length <= 1 << 20,
        "unsafe 136 controller configuration"
    );
    let bytes = read_stable_bounded(path, 1 << 20, "136 controller bytes")?;
    ensure!(
        regular_identity(path)? == before && hex_lower(&Sha256::digest(&bytes)) == sha,
        "136 controller configuration differs"
    );
    Ok(bytes)
}

fn state_record(path: &Path, uid: u32) -> Result<Option<Value>> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
        Ok(md) => {
            ensure!(
                md.uid() == uid
                    && md.mode() & 0o222 == 0
                    && md.nlink() == 1
                    && md.is_file()
                    && path.canonicalize()? == path,
                "unsafe 136 control state"
            );
            Ok(Some(serde_json::from_slice(&read_stable_bounded(
                path,
                1 << 20,
                "136 control state",
            )?)?))
        }
    }
}
fn temporary_mask(original: &Path) -> Result<PathBuf> {
    let name = original
        .file_name()
        .and_then(|n| n.to_str())
        .context("136 controller filename")?;
    Ok(original.with_file_name(format!(".{name}.holding-mask.pending")))
}
fn partial_copy(retained: &Path) -> Result<PathBuf> {
    let name = retained
        .file_name()
        .and_then(|n| n.to_str())
        .context("136 retained filename")?;
    Ok(retained.with_file_name(format!(".{name}.copy.partial")))
}
fn absent(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(e) => Err(e.into()),
        Ok(_) => Ok(false),
    }
}

fn retained_copy(
    original: &Path,
    retained: &Path,
    sha: &str,
    uid: u32,
    expected: OriginalId,
) -> Result<()> {
    private(retained.parent().context("136 copy parent")?)?;
    let partial = partial_copy(retained)?;
    if !absent(retained)? {
        ensure!(
            absent(&partial)?,
            "136 copy has conflicting final and partial files"
        );
        checked_bytes(retained, sha, uid)?;
        ensure!(
            fs::symlink_metadata(retained)?.mode() & 0o222 == 0,
            "136 retained copy is mutable"
        );
        return Ok(());
    }
    ensure!(
        OriginalId::from(regular_identity(original)?) == expected,
        "136 original identity changed before copy"
    );
    let bytes = checked_bytes(original, sha, uid)?;
    ensure!(
        OriginalId::from(regular_identity(original)?) == expected,
        "136 original changed during copy read"
    );
    let mut file = match OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&partial)
    {
        Ok(file) => Some(file),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let md = fs::symlink_metadata(&partial)?;
            ensure!(
                md.is_file()
                    && md.nlink() == 1
                    && md.uid() == uid
                    && md.len() <= expected.length
                    && partial.canonicalize()? == partial,
                "unsafe 136 partial config copy"
            );
            if md.mode() & 0o777 == 0o400 {
                checked_bytes(&partial, sha, uid)?;
                None
            } else {
                ensure!(
                    md.mode() & 0o777 == 0o600,
                    "136 partial config copy mode differs"
                );
                let file = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(&partial)?;
                ensure!(
                    identity(&file.metadata()?) == regular_identity(&partial)?,
                    "136 partial config copy changed"
                );
                Some(file)
            }
        }
        Err(e) => return Err(e.into()),
    };
    if let Some(file) = file.as_mut() {
        file.set_len(0)?;
        file.seek(SeekFrom::Start(0))?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        file.set_permissions(fs::Permissions::from_mode(0o400))?;
        file.sync_all()?;
    }
    checked_bytes(&partial, sha, uid)?;
    rename_noreplace(&partial, retained)?; // Same ROOT parent, never /etc→/var.
    checked_bytes(retained, sha, uid)?;
    Ok(())
}

fn exchange(original: &Path, temporary: &Path) -> Result<()> {
    let a = std::ffi::CString::new(original.as_os_str().as_encoded_bytes())?;
    let b = std::ffi::CString::new(temporary.as_os_str().as_encoded_bytes())?;
    ensure!(
        unsafe {
            libc::renameat2(
                libc::AT_FDCWD,
                a.as_ptr(),
                libc::AT_FDCWD,
                b.as_ptr(),
                libc::RENAME_EXCHANGE,
            )
        } == 0,
        "136 atomic mask exchange failed: {}",
        std::io::Error::last_os_error()
    );
    File::open(original.parent().context("136 exchange parent")?)?.sync_all()?;
    Ok(())
}

// Production paths are compile-bound above. Fixtures cover copy/exchange/unlink
// interruptions with two independent parents and no host configuration access.
fn retain_and_mask(
    original: &Path,
    retained: &Path,
    sha: &str,
    uid: u32,
    expected: OriginalId,
    exchanged: &Path,
    mut owner_gate: impl FnMut() -> Result<()>,
) -> Result<()> {
    let temporary = temporary_mask(original)?;
    match fs::symlink_metadata(original) {
        Ok(md) if md.is_file() => {
            ensure!(
                OriginalId::from(regular_identity(original)?) == expected,
                "136 original inode changed"
            );
            retained_copy(original, retained, sha, uid, expected)?;
            if absent(&temporary)? {
                std::os::unix::fs::symlink("/dev/null", &temporary)?;
            }
            ensure!(
                fs::symlink_metadata(&temporary)?.file_type().is_symlink()
                    && fs::read_link(&temporary)? == Path::new("/dev/null"),
                "136 pending mask is occupied"
            );
            File::open(original.parent().context("136 mask parent")?)?.sync_all()?;
            owner_gate()?;
            ensure!(
                OriginalId::from(regular_identity(original)?) == expected,
                "136 original changed before exchange"
            );
            checked_bytes(original, sha, uid)?;
            exchange(original, &temporary)?;
        }
        Ok(md) if md.file_type().is_symlink() => {
            ensure!(
                fs::read_link(original)? == Path::new("/dev/null"),
                "foreign 136 controller alias"
            );
            checked_bytes(retained, sha, uid)?;
            ensure!(
                absent(&partial_copy(retained)?)?,
                "136 retained copy has a conflicting partial"
            );
        }
        Err(e) => {
            return Err(e)
                .context("136 original path absent or unreadable outside atomic exchange");
        }
        _ => bail!("unsupported 136 controller path"),
    }
    ensure!(
        fs::read_link(original)? == Path::new("/dev/null"),
        "136 original is not masked"
    );
    checked_bytes(retained, sha, uid)?;
    ensure!(
        fs::symlink_metadata(retained)?.mode() & 0o222 == 0,
        "136 retained copy is mutable"
    );
    let descriptor = json!({"schema":"jetstreamer-terminal136-controller-mask-exchanged-v2",
        "original":original,"retained":retained,"temporary":temporary,"config_sha256":sha,
        "original_identity":expected,"original_bytes_retained":true,"copy_fsynced":true});
    if !absent(&temporary)? {
        ensure!(
            OriginalId::from(regular_identity(&temporary)?) == expected,
            "136 exchanged original identity differs"
        );
        checked_bytes(&temporary, sha, uid)?;
        if let Some(old) = state_record(exchanged, uid)? {
            ensure!(old == descriptor, "136 exchanged frontier conflicts");
        } else {
            persist(exchanged, &descriptor)?;
        }
        owner_gate()?;
        ensure!(
            fs::read_link(original)? == Path::new("/dev/null")
                && OriginalId::from(regular_identity(&temporary)?) == expected,
            "136 exchanged state changed before cleanup"
        );
        checked_bytes(retained, sha, uid)?;
        checked_bytes(&temporary, sha, uid)?;
        fs::remove_file(&temporary)?;
        File::open(original.parent().unwrap())?.sync_all()?;
    } else {
        ensure!(
            state_record(exchanged, uid)?.as_ref() == Some(&descriptor),
            "136 mask has unexplained absence of original temporary configuration"
        );
    }
    Ok(())
}

pub(super) fn disable(m: &Mapping, p: &Disable, spec: &Bound) -> Result<()> {
    ensure!(
        p.schema == "jetstreamer-horizon-holding-disable136-retry-plan-v2"
            && p.archived_unit.path == Path::new(ARCHIVE)
            && p.archived_unit.sha256 == CONFIG_SHA,
        "foreign 136 controller retirement scope"
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
    ensure!(
        fs::symlink_metadata(ARCHIVE)?.mode() & 0o222 == 0,
        "136 configuration backup is mutable"
    );
    checked_bytes(Path::new(ARCHIVE), CONFIG_SHA, 0)?;
    let before = terminal_unit(CONTROLLER)?;
    terminal_unit(PRODUCER)?;
    private(Path::new(ROOT))?;
    let intent = Path::new(ROOT).join("intent.json");
    let exchanged = Path::new(ROOT).join("mask-exchanged.json");
    let completion = Path::new(ROOT).join("completion.json");
    let mut descriptor = json!({"schema":"jetstreamer-terminal136-controller-retirement-intent-v2",
        "operation":"copy-config-and-atomic-mask-exchange","host":HOST,"controller":CONTROLLER,
        "original":ORIGINAL,"retained":RETAINED,"config_sha256":CONFIG_SHA,
        "archived_unit":p.archived_unit,"mapping":p.mapping,"terminal":p.terminal,"qualification":p.qualification,
        "producer_signal_authorized":false,"replay_data_retirement_authorized":false,
        "replay_launch_authorized":false,"remote_mutations":false,"r2_mutations":false});
    let expected: OriginalId = if let Some(old) = state_record(&intent, 0)? {
        let identity: OriginalId = serde_json::from_value(old["original_identity"].clone())?;
        descriptor["original_identity"] = serde_json::to_value(identity)?;
        ensure!(old == descriptor, "136 recovery intent differs");
        identity
    } else {
        let expected = OriginalId::from(regular_identity(Path::new(ORIGINAL))?);
        checked_bytes(Path::new(ORIGINAL), CONFIG_SHA, 0)?;
        ensure!(
            OriginalId::from(regular_identity(Path::new(ORIGINAL))?) == expected,
            "136 original changed before intent"
        );
        for path in [
            PathBuf::from(RETAINED),
            partial_copy(Path::new(RETAINED))?,
            temporary_mask(Path::new(ORIGINAL))?,
            exchanged.clone(),
            completion.clone(),
        ] {
            ensure!(
                absent(&path)?,
                "136 first intent has an occupied transition path"
            );
        }
        descriptor["original_identity"] = serde_json::to_value(expected)?;
        persist(&intent, &descriptor)?;
        expected
    };
    retain_and_mask(
        Path::new(ORIGINAL),
        Path::new(RETAINED),
        CONFIG_SHA,
        0,
        expected,
        &exchanged,
        || {
            terminal_unit(CONTROLLER)?;
            terminal_unit(PRODUCER)?;
            Ok(())
        },
    )?;
    if before["LoadState"] != "masked" {
        let reload = std::process::Command::new("/usr/bin/systemctl")
            .arg("daemon-reload")
            .output()?;
        ensure!(
            reload.status.success(),
            "136 mask is durable but manager reload failed"
        );
    }
    let after = terminal_unit(CONTROLLER)?;
    ensure!(
        after["LoadState"] == "masked",
        "136 old controller not masked in manager"
    );
    terminal_unit(PRODUCER)?;
    let intent_sha = hex_lower(&Sha256::digest(fs::read(&intent)?));
    if let Some(old) = state_record(&completion, 0)? {
        ensure!(
            old["intent_sha256"] == intent_sha
                && old["masked"] == true
                && old["config_sha256"] == CONFIG_SHA
                && old["original_bytes_retained"] == true,
            "136 mask completion conflict"
        );
    } else {
        persist(
            &completion,
            &json!({"schema":"jetstreamer-terminal136-controller-retirement-v2",
            "host":HOST,"controller":CONTROLLER,"intent_sha256":intent_sha,
            "config_sha256":CONFIG_SHA,"retained":RETAINED,"masked":true,
            "original_bytes_retained":true,"original_inode_retained":false,
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
    fn fixture() -> (
        tempfile::TempDir,
        PathBuf,
        PathBuf,
        PathBuf,
        String,
        OriginalId,
    ) {
        let d = tempfile::tempdir().unwrap();
        fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let etc = d.path().join("etc");
        fs::create_dir(&etc).unwrap();
        let var = d.path().join("var");
        fs::create_dir(&var).unwrap();
        fs::set_permissions(&var, fs::Permissions::from_mode(0o700)).unwrap();
        let source = etc.join("old.service");
        let retained = var.join("retained.txt");
        let exchanged = var.join("exchanged.json");
        let bytes = b"[Service]\nExecStart=/fixture/never-launched\n";
        fs::write(&source, bytes).unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o600)).unwrap();
        let id = OriginalId::from(regular_identity(&source).unwrap());
        (
            d,
            source,
            retained,
            exchanged,
            hex_lower(&Sha256::digest(bytes)),
            id,
        )
    }
    #[test]
    fn independent_parents_copy_before_atomic_mask_and_retry_preserves_bytes() {
        let (_d, s, r, x, sha, id) = fixture();
        let uid = unsafe { libc::geteuid() };
        let bytes = fs::read(&s).unwrap();
        retain_and_mask(&s, &r, &sha, uid, id, &x, || Ok(())).unwrap();
        assert_eq!(fs::read_link(&s).unwrap(), Path::new("/dev/null"));
        assert_eq!(fs::read(&r).unwrap(), bytes);
        assert_ne!(
            OriginalId::from(regular_identity(&r).unwrap()).inode,
            id.inode
        );
        let marker = fs::read(&x).unwrap();
        retain_and_mask(&s, &r, &sha, uid, id, &x, || Ok(())).unwrap();
        assert_eq!(fs::read(&x).unwrap(), marker);
        assert!(absent(&temporary_mask(&s).unwrap()).unwrap());
    }
    #[test]
    fn partial_copy_and_exchange_frontiers_resume_without_losing_configuration() {
        for frontier in 0..=3 {
            let (_d, s, r, x, sha, id) = fixture();
            let uid = unsafe { libc::geteuid() };
            let bytes = fs::read(&s).unwrap();
            if frontier == 0 {
                let p = partial_copy(&r).unwrap();
                fs::write(&p, &bytes[..5]).unwrap();
                fs::set_permissions(p, fs::Permissions::from_mode(0o600)).unwrap();
            } else {
                retained_copy(&s, &r, &sha, uid, id).unwrap();
                let temp = temporary_mask(&s).unwrap();
                std::os::unix::fs::symlink("/dev/null", &temp).unwrap();
                if frontier >= 2 {
                    exchange(&s, &temp).unwrap();
                }
                if frontier == 3 {
                    let mut calls = 0;
                    assert!(
                        retain_and_mask(&s, &r, &sha, uid, id, &x, || {
                            calls += 1;
                            bail!("fixture interruption before cleanup")
                        })
                        .is_err()
                    );
                    assert_eq!(calls, 1);
                    assert!(temp.exists());
                }
            }
            retain_and_mask(&s, &r, &sha, uid, id, &x, || Ok(())).unwrap();
            assert_eq!(fs::read(&r).unwrap(), bytes);
            assert_eq!(fs::read_link(&s).unwrap(), Path::new("/dev/null"));
        }
    }
    #[test]
    fn changed_conflicting_or_unexplained_masks_are_never_replaced() {
        let (_d, s, r, x, sha, id) = fixture();
        let uid = unsafe { libc::geteuid() };
        fs::write(&r, b"conflict").unwrap();
        assert!(retain_and_mask(&s, &r, &sha, uid, id, &x, || Ok(())).is_err());
        assert_eq!(fs::read(&r).unwrap(), b"conflict");
        fs::remove_file(&r).unwrap();
        assert!(retain_and_mask(&s, &r, &"a".repeat(64), uid, id, &x, || Ok(())).is_err());
        assert_eq!(
            fs::read(&s).unwrap(),
            b"[Service]\nExecStart=/fixture/never-launched\n"
        );
        retained_copy(&s, &r, &sha, uid, id).unwrap();
        fs::remove_file(&s).unwrap();
        std::os::unix::fs::symlink("/dev/null", &s).unwrap();
        assert!(retain_and_mask(&s, &r, &sha, uid, id, &x, || Ok(())).is_err());
        assert!(r.exists());
    }

    #[test]
    fn completed_partial_copy_recovers_and_conflicting_partial_is_preserved() {
        let (_d, s, r, x, sha, id) = fixture();
        let uid = unsafe { libc::geteuid() };
        let partial = partial_copy(&r).unwrap();
        fs::write(&partial, fs::read(&s).unwrap()).unwrap();
        fs::set_permissions(&partial, fs::Permissions::from_mode(0o400)).unwrap();
        retained_copy(&s, &r, &sha, uid, id).unwrap();
        assert!(absent(&partial).unwrap());
        fs::write(&partial, b"foreign partial").unwrap();
        assert!(retain_and_mask(&s, &r, &sha, uid, id, &x, || Ok(())).is_err());
        assert_eq!(fs::read(&partial).unwrap(), b"foreign partial");
        assert_eq!(OriginalId::from(regular_identity(&s).unwrap()), id);
    }

    #[test]
    fn failed_owner_gate_leaves_original_unmasked_and_retryable() {
        let (_d, s, r, x, sha, id) = fixture();
        let uid = unsafe { libc::geteuid() };
        assert!(
            retain_and_mask(&s, &r, &sha, uid, id, &x, || {
                bail!("fixture changed owner before exchange")
            })
            .is_err()
        );
        assert_eq!(OriginalId::from(regular_identity(&s).unwrap()), id);
        assert_eq!(fs::read(&s).unwrap(), fs::read(&r).unwrap());
        assert!(absent(&x).unwrap());
        retain_and_mask(&s, &r, &sha, uid, id, &x, || Ok(())).unwrap();
        assert_eq!(fs::read_link(&s).unwrap(), Path::new("/dev/null"));
    }
}
