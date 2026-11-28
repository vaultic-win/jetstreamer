//! Qualified local inputs replace network acquisition; no authentication success is claimed.
use super::*;
use base64::{Engine as _, engine::general_purpose::STANDARD};
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LocalInputs {
    pub bootstrap: Bound,
    pub genesis: Bound,
    pub deployment_seal: Bound,
    pub capability: Bound,
}
fn opened(path: &Path) -> Result<File> {
    let parent = directory(path.parent().context("local member parent")?)?;
    let name = CString::new(path.file_name().context("local member name")?.as_bytes())?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0,
        )
    };
    ensure!(fd >= 0, "local member open failed");
    let f = unsafe { File::from_raw_fd(fd) };
    let m = f.metadata()?;
    ensure!(
        m.is_file() && m.uid() == 0 && m.nlink() == 1 && m.mode() & 0o7777 == 0o444,
        "immutable Root local member required"
    );
    ensure!(
        identity(&m) == identity(&fs::symlink_metadata(path)?),
        "local member replaced"
    );
    Ok(f)
}
fn measured(member: &Bound, expected_size: u64) -> Result<Value> {
    ensure!(
        lower_hex(&member.sha256, 64) && expected_size > 0 && expected_size <= 3 << 30,
        "bounded local member digest/size"
    );
    let mut f = opened(&member.path)?;
    let before = f.metadata()?;
    ensure!(before.len() == expected_size, "local member size differs");
    let mut sha = Sha256::new();
    let mut md5 = <md5::Md5 as md5::Digest>::new();
    let crc = crc::Crc::<u32>::new(&crc::CRC_32_ISCSI);
    let mut cd = crc.digest();
    let mut bytes = 0u64;
    let mut buffer = [0u8; 128 * 1024];
    loop {
        let n = f.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        bytes = bytes.checked_add(n as u64).context("local byte overflow")?;
        ensure!(bytes <= expected_size, "local member grew");
        sha.update(&buffer[..n]);
        md5::Digest::update(&mut md5, &buffer[..n]);
        cd.update(&buffer[..n]);
    }
    let observed = format!("{:x}", sha.finalize());
    ensure!(
        bytes == expected_size
            && observed == member.sha256
            && identity(&before) == identity(&f.metadata()?)
            && identity(&before) == identity(&fs::symlink_metadata(&member.path)?),
        "local member digest or identity changed"
    );
    Ok(
        json!({"path":member.path,"bytes":bytes,"sha256":observed,"crc32c":STANDARD.encode(cd.finalize().to_be_bytes()),"md5_hash":STANDARD.encode(md5::Digest::finalize(md5)),"identity":identity(&before)}),
    )
}
pub(super) fn validate_inputs(
    inputs: &LocalInputs,
    proof: &Value,
    manifest: &Value,
    p: &Plan,
    s: &Profile,
    at: u64,
) -> Result<()> {
    let cache = PathBuf::from(format!(
        "/usr/local/lib/jetstreamer/horizon-standard-local-input{}-20261110-v1",
        p.epoch
    ));
    let boot = &manifest["manifest"]["verification_cohorts"][0]["bootstrap"];
    let filename = boot["uri"]
        .as_str()
        .context("bootstrap URI")?
        .rsplit('/')
        .next()
        .context("snapshot filename")?;
    ensure!(
        inputs.bootstrap.path == cache.join(filename)
            && inputs.genesis.path == cache.join("genesis.tar.bz2")
            && inputs.deployment_seal.path == cache.join("deployment-seal-receipt.json"),
        "exact local input deployment required"
    );
    ensure!(
        proof["schema"] == "horizon-standard-local-input-route-request-v1"
            && proof["owner"] == "/root"
            && proof["primary_thread"] == THREAD
            && proof["epoch"] == p.epoch
            && proof["authentication_qualified"] == false
            && proof["network_GCS_probe_performed"] == false
            && proof["local_inputs"] == serde_json::to_value(inputs)?,
        "local route cannot impersonate authenticated acquisition"
    );
    let when = proof["recorded_unix_seconds"]
        .as_u64()
        .context("local request clock")?;
    ensure!(when <= at && at - when <= 1800, "stale local input request");
    let seal = bound(&inputs.deployment_seal)?;
    ensure!(
        seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && seal["destination"] == cache.to_str().context("cache path")?
            && seal["sealer_sha256"]
                == "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3"
            && seal["replay_launch_authorized"] == false
            && seal["remote_mutations"] == false,
        "normal cache deployment seal required"
    );
    for (b, name) in [
        (&inputs.bootstrap, filename),
        (&inputs.genesis, "genesis.tar.bz2"),
    ] {
        let members = seal["members"].as_array().context("sealed cache members")?;
        let selected: Vec<_> = members.iter().filter(|m| m["name"] == name).collect();
        ensure!(
            selected.len() == 1
                && selected[0]["sha256"] == b.sha256
                && selected[0]["mode"] == "0444",
            "cache member seal differs"
        );
    }
    let cap = bound(&inputs.capability)?;
    ensure!(
        cap["schema"] == "horizon-cached-standard-node-input-capability-v1"
            && cap["owner"] == "/root"
            && cap["epoch"] == p.epoch
            && cap["node"]["path"] == format!("{}/jetstreamer-node", s.package)
            && cap["node"]["sha256"] == NODE_SHA
            && cap["manifest"]["sha256"] == s.manifest_sha
            && cap["no_replay_scratch_or_archive_created"] == true
            && cap["authentication_qualified"] == false,
        "genuine exact cached-input capability required"
    );
    for (key, marker) in [
        (
            "fingerprint_control",
            "cohort manifest fingerprint mismatch",
        ),
        (
            "schema_control",
            "root-checkpoint cohort snapshot override filename mismatch",
        ),
    ] {
        let b: Bound = serde_json::from_value(cap[key].clone())?;
        let v = bound(&b)?;
        ensure!(
            v["code"] == 1
                && format!(
                    "{}{}",
                    v["stdout"].as_str().context("control stdout")?,
                    v["stderr"].as_str().context("control stderr")?
                )
                .contains(marker),
            "actual cache control failed"
        );
    }
    let observed = measured(
        &inputs.bootstrap,
        boot["size"].as_u64().context("bootstrap bytes")?,
    )?;
    ensure!(
        observed["crc32c"] == boot["crc32c"] && observed["md5_hash"] == boot["md5_hash"],
        "manifest-bound local CRC32C or MD5 mismatch"
    );
    let genesis_size = opened(&inputs.genesis.path)?.metadata()?.len();
    ensure!(genesis_size <= 1 << 20, "bounded retained genesis archive");
    let _ = measured(&inputs.genesis, genesis_size)?;
    Ok(())
}
fn ledger_at(
    dir: &File,
    prefix: &str,
    device: u64,
    depth: usize,
    rows: &mut BTreeMap<String, Value>,
    bytes: &mut u64,
) -> Result<()> {
    ensure!(
        depth <= 64 && rows.len() < 100_000,
        "local lane ledger bound exceeded"
    );
    let before = dir.metadata()?;
    ensure!(
        before.is_dir() && before.dev() == device,
        "foreign ledger directory/device"
    );
    rows.insert(prefix.into(),json!({"identity":identity(&before),"physical_bytes":before.blocks().checked_mul(512).context("directory blocks overflow")?}));
    *bytes = bytes
        .checked_add(
            before
                .blocks()
                .checked_mul(512)
                .context("directory allocation overflow")?,
        )
        .context("ledger sum overflow")?;
    let mut names = fs::read_dir(format!("/proc/self/fd/{}", dir.as_raw_fd()))?
        .map(|e| e.map(|e| e.file_name()))
        .collect::<std::io::Result<Vec<_>>>()?;
    names.sort();
    for name in names {
        ensure!(rows.len() < 100_000, "ledger count exceeded");
        let leaf = name.to_str().context("non-UTF8 ledger member")?;
        ensure!(
            !leaf.contains('/') && leaf != "." && leaf != "..",
            "ledger leaf spelling"
        );
        let relative = if prefix.is_empty() {
            leaf.into()
        } else {
            format!("{prefix}/{leaf}")
        };
        ensure!(relative.len() <= 4096, "ledger path bound");
        let c = CString::new(name.as_bytes())?;
        let fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                c.as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0,
            )
        };
        ensure!(fd >= 0, "ledger member cannot be opened");
        let child = unsafe { File::from_raw_fd(fd) };
        let m = child.metadata()?;
        ensure!(
            m.dev() == device && (m.is_dir() || m.is_file()) && (!m.is_file() || m.nlink() == 1),
            "ledger link/special/foreign mount rejected"
        );
        if m.is_dir() {
            let fd = unsafe {
                libc::openat(
                    dir.as_raw_fd(),
                    c.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    0,
                )
            };
            ensure!(fd >= 0, "ledger subdirectory open");
            let sub = unsafe { File::from_raw_fd(fd) };
            ensure!(
                identity(&m) == identity(&sub.metadata()?),
                "ledger directory changed"
            );
            ledger_at(&sub, &relative, device, depth + 1, rows, bytes)?;
        } else {
            let allocated = m
                .blocks()
                .checked_mul(512)
                .context("file allocation overflow")?;
            *bytes = bytes
                .checked_add(allocated)
                .context("ledger bytes overflow")?;
            rows.insert(
                relative,
                json!({"identity":identity(&m),"physical_bytes":allocated}),
            );
        }
        let path = PathBuf::from(format!("/proc/self/fd/{}", dir.as_raw_fd())).join(&name);
        ensure!(
            identity(&m) == identity(&fs::symlink_metadata(path)?),
            "ledger member replaced"
        );
    }
    ensure!(
        identity(&before) == identity(&dir.metadata()?),
        "ledger directory changed during scan"
    );
    Ok(())
}
pub(super) fn physical_ledger(root: &Path) -> Result<Value> {
    let dir = directory(root)?;
    let mut previous = None;
    for _ in 0..2 {
        let mut rows = BTreeMap::new();
        let mut bytes = 0u64;
        ledger_at(&dir, "", dir.metadata()?.dev(), 0, &mut rows, &mut bytes)?;
        let captured = json!({"physical_bytes":bytes,"entries":rows});
        if let Some(previous) = previous {
            ensure!(
                previous == captured,
                "lane changed across complete ledger capture"
            );
            return Ok(captured);
        }
        previous = Some(captured);
    }
    anyhow::bail!("missing second lane capture")
}
pub(super) fn stage_genesis(fresh: &Path, member: &Bound) -> Result<Value> {
    let input = raw(&member.path, 1 << 20, true)?;
    ensure!(
        !input.is_empty() && digest(&input) == member.sha256,
        "sealed genesis digest differs"
    );
    let parent = directory(fresh)?;
    let leaf = CString::new("output")?;
    ensure!(
        unsafe { libc::mkdirat(parent.as_raw_fd(), leaf.as_ptr(), 0o700) } == 0,
        "output already exists; preserve prior attempt"
    );
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            leaf.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0,
        )
    };
    ensure!(fd >= 0, "open new output");
    let output = unsafe { File::from_raw_fd(fd) };
    let name = CString::new("genesis.tar.bz2")?;
    let fd = unsafe {
        libc::openat(
            output.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    ensure!(fd >= 0, "no-clobber genesis output");
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(&input)?;
    file.sync_all()?;
    ensure!(
        unsafe { libc::fchown(file.as_raw_fd(), 1001, 1003) } == 0
            && unsafe { libc::fchown(output.as_raw_fd(), 1001, 1003) } == 0,
        "genesis target ownership"
    );
    file.sync_all()?;
    output.sync_all()?;
    parent.sync_all()?;
    let installed = fresh.join("output/genesis.tar.bz2");
    let mut check = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&installed)?;
    let before = check.metadata()?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut check)
        .take((1 << 20) + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes == input
            && identity(&before) == identity(&check.metadata()?)
            && identity(&before) == identity(&fs::symlink_metadata(&installed)?)
            && before.uid() == 1001
            && before.gid() == 1003
            && before.mode() & 0o7777 == 0o600,
        "genesis copy readback differs"
    );
    Ok(
        json!({"path":installed,"sha256":digest(&bytes),"bytes":bytes.len(),"identity":identity(&before),"no_clobber":true,"source":member,"gcloud_invoked":false}),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn sparse_metadata_uses_allocated_blocks_and_includes_directories() {
        let t = tempfile::tempdir().unwrap();
        let f = File::create(t.path().join("sparse")).unwrap();
        f.set_len(1 << 28).unwrap();
        let v = physical_ledger(t.path()).unwrap();
        assert_eq!(
            v["physical_bytes"].as_u64().unwrap(),
            fs::metadata(t.path()).unwrap().blocks() * 512 + f.metadata().unwrap().blocks() * 512
        );
        assert!(v["physical_bytes"].as_u64().unwrap() < 1 << 28);
    }
    #[test]
    fn ledger_rejects_symlinks_and_hardlinks() {
        use std::os::unix::fs::symlink;
        let t = tempfile::tempdir().unwrap();
        fs::write(t.path().join("one"), b"x").unwrap();
        symlink("one", t.path().join("alias")).unwrap();
        assert!(physical_ledger(t.path()).is_err());
        fs::remove_file(t.path().join("alias")).unwrap();
        fs::hard_link(t.path().join("one"), t.path().join("hard")).unwrap();
        assert!(physical_ledger(t.path()).is_err());
    }
    #[test]
    fn local_digest_matches_independent_known_md5_crc_and_sha() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("input");
        fs::write(&p, b"123456789").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o444)).unwrap();
        let b = Bound {
            path: p,
            sha256: digest(b"123456789"),
        };
        let v = measured(&b, 9).unwrap();
        assert_eq!(v["crc32c"], "4waSgw==");
        assert_eq!(v["md5_hash"], "JfnnlDI7RTiF9RgfG2JNCw==");
        assert!(measured(&b, 8).is_err());
    }
    #[test]
    fn wrong_local_digest_is_rejected() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("input");
        fs::write(&p, b"fixture").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o444)).unwrap();
        assert!(
            measured(
                &Bound {
                    path: p,
                    sha256: "a".repeat(64)
                },
                7
            )
            .is_err()
        );
    }
    #[test]
    fn genesis_copy_is_private_exact_and_no_clobber() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("source");
        fs::write(&p, b"disposable-genesis").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o444)).unwrap();
        let fresh = t.path().join("fresh");
        fs::create_dir(&fresh).unwrap();
        let b = Bound {
            path: p,
            sha256: digest(b"disposable-genesis"),
        };
        let v = stage_genesis(&fresh, &b).unwrap();
        assert_eq!(v["no_clobber"], true);
        assert!(stage_genesis(&fresh, &b).is_err());
        assert_eq!(
            fs::read(fresh.join("output/genesis.tar.bz2")).unwrap(),
            b"disposable-genesis"
        );
    }
}
#[cfg(test)]
mod staged_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    fn setup() -> (tempfile::TempDir, PathBuf, Value) {
        let t = tempfile::tempdir().unwrap();
        let source = t.path().join("input");
        fs::write(&source, b"fixture-genesis").unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o444)).unwrap();
        let fresh = t.path().join("fresh");
        fs::create_dir(&fresh).unwrap();
        fs::set_permissions(&fresh, fs::Permissions::from_mode(0o700)).unwrap();
        let file = File::open(&fresh).unwrap();
        assert_eq!(unsafe { libc::fchown(file.as_raw_fd(), 1001, 1003) }, 0);
        let v = stage_genesis(
            &fresh,
            &Bound {
                path: source,
                sha256: digest(b"fixture-genesis"),
            },
        )
        .unwrap();
        (t, fresh, v)
    }
    #[test]
    fn genuine_staged_genesis_can_be_revalidated_without_copy() {
        let (_t, p, v) = setup();
        let first = staged_genesis(&p, &v).unwrap();
        assert_eq!(first, staged_genesis(&p, &v).unwrap());
        assert_eq!(
            fs::read(p.join("output/genesis.tar.bz2")).unwrap(),
            b"fixture-genesis"
        );
    }
    #[test]
    fn staged_content_replacement_is_rejected() {
        let (_t, p, v) = setup();
        fs::write(p.join("output/genesis.tar.bz2"), b"changed").unwrap();
        assert!(staged_genesis(&p, &v).is_err());
    }
    #[test]
    fn unexpected_staged_member_cannot_be_hidden() {
        let (_t, p, v) = setup();
        fs::write(p.join("extra"), b"x").unwrap();
        assert!(staged_genesis(&p, &v).is_err());
    }
}

pub(super) fn staged_genesis(fresh: &Path, expected: &Value) -> Result<Value> {
    let dir = directory(fresh)?;
    let root = dir.metadata()?;
    ensure!(
        root.uid() == 1001 && root.gid() == 1003 && root.mode() & 0o7777 == 0o700,
        "staged root must remain sol:horizon0700"
    );
    let mut names = fs::read_dir(fresh)?
        .map(|e| e.map(|e| e.file_name()))
        .collect::<std::io::Result<Vec<_>>>()?;
    names.sort();
    ensure!(
        names == [std::ffi::OsString::from("output")],
        "unexpected staged root member"
    );
    let output = directory(&fresh.join("output"))?;
    let m = output.metadata()?;
    ensure!(
        m.uid() == 1001 && m.gid() == 1003 && m.mode() & 0o7777 == 0o700,
        "staged output ownership"
    );
    let names = fs::read_dir(fresh.join("output"))?
        .map(|e| e.map(|e| e.file_name()))
        .collect::<std::io::Result<Vec<_>>>()?;
    ensure!(
        names == [std::ffi::OsString::from("genesis.tar.bz2")],
        "unexpected staged output member"
    );
    let path = fresh.join("output/genesis.tar.bz2");
    ensure!(
        expected["path"] == path.to_str().context("genesis path")?
            && expected["no_clobber"] == true
            && expected["gcloud_invoked"] == false,
        "unqualified staged genesis record"
    );
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)?;
    let before = file.metadata()?;
    ensure!(
        before.is_file()
            && before.nlink() == 1
            && before.uid() == 1001
            && before.gid() == 1003
            && before.mode() & 0o7777 == 0o600
            && before.len() <= 1 << 20
            && identity(&before) == expected["identity"],
        "staged genesis identity changed"
    );
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take((1 << 20) + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        digest(&bytes) == expected["sha256"].as_str().context("staged digest")?
            && identity(&before) == identity(&file.metadata()?)
            && identity(&before) == identity(&fs::symlink_metadata(path)?),
        "staged genesis content changed"
    );
    ensure!(
        identity(&root) == identity(&dir.metadata()?)
            && identity(&m) == identity(&output.metadata()?),
        "staged directory changed during recheck"
    );
    Ok(identity(&root))
}

pub(super) fn ledger_summary(ledger: &Value) -> Result<Value> {
    let entries = ledger["entries"]
        .as_object()
        .context("complete ledger entries")?;
    let bytes = ledger["physical_bytes"]
        .as_u64()
        .context("complete ledger physical bytes")?;
    Ok(
        json!({"physical_bytes":bytes,"complete_ledger_entry_count":entries.len(),"complete_ledger_sha256":digest(&serde_json::to_vec(ledger)?),"full_two_capture_identity_and_allocation_check_passed":true}),
    )
}
#[cfg(test)]
mod summary_tests {
    use super::*;
    #[test]
    fn unchanged_allocated_bytes_cannot_hide_changed_full_ledger_identity() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("file");
        fs::write(&p, b"a").unwrap();
        let a = physical_ledger(t.path()).unwrap();
        let f = OpenOptions::new().write(true).open(&p).unwrap();
        f.set_len(2).unwrap();
        let b = physical_ledger(t.path()).unwrap();
        assert_eq!(a["physical_bytes"], b["physical_bytes"]);
        assert_ne!(
            ledger_summary(&a).unwrap()["complete_ledger_sha256"],
            ledger_summary(&b).unwrap()["complete_ledger_sha256"]
        );
    }
}
