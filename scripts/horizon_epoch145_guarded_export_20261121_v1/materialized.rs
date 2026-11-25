//! Receipt recovery for the complete private inode left when V4's six-owner
//! guard terminates. A read-only bind projection exercises the original
//! full source and existing-candidate decoder without promoting any bytes.
use super::*;
use std::{
    ffi::CString,
    os::unix::{ffi::OsStrExt, fs::PermissionsExt},
};
const ORIGINAL: &str = "de6780b860b3467bae21fbd19176ca14";
const LEAF: &str = ".tmp36MvkN";
const VIEW: &str =
    "/home/sol/.jetstreamer-private/epoch145-prefix-extract-materialized-view-20261121-v1";
#[cfg(continuity145_only)]
pub const IMAGE: &str = continuity::IMAGE;
#[cfg(all(partial145_only, not(continuity145_only)))]
pub const IMAGE: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch145-partial-recovery-20261121-v1/tools/export145";
#[cfg(not(partial145_only))]
pub const IMAGE: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch145-materialized-recovery-20261121-v1/tools-v2/export145";
const ALLOC: &str = "95b714939cf8837d26ce612d7ddd37fe99e32273c9afb86aa2952e397cd601bd";
const POST_ALLOC: &str = "bb66d17aa06f51157fc90d6f6258086640b51dc42a388c7c7e2cccfd648192f8";
const VALID: &str = "02806450a410c6721f4e7dcdbc5c9875cce99e21962fa12d0e6a18f96b05f33b";
const FIRST: &str = "5860cc4748c58a76b34ec56234e1d8fd2ae7293df8cb424f22f1cc1dca677be4";
fn state(iid: &str) -> PathBuf {
    Path::new(BASE).join("state").join(iid)
}
fn canonical() -> PathBuf {
    Path::new(OUTPUT).join("epoch-145.jet")
}
fn view() -> PathBuf {
    Path::new(VIEW).join("epoch-145.jet")
}
fn read(path: &Path) -> Result<Value> {
    custody::evidence(&custody::binding(path)?)
}
fn pred() -> Result<Value> {
    ensure!(
        native::ticks(3501708).ok() != Some(357609519)
            && native::ticks(3501881).ok() != Some(357611090),
        "original 145 owner still live"
    );
    let base = state(ORIGINAL);
    let mut proofs = json!({});
    for (file, hash) in [
        ("first-guard.json", FIRST),
        ("allocated.json", ALLOC),
        ("post-allocation-guard.json", POST_ALLOC),
        ("source-validated.json", VALID),
    ] {
        let b = Bound {
            path: base.join(file),
            sha256: hash.to_owned(),
        };
        custody::evidence(&b)?;
        proofs[file] = json!(b);
    }
    let failed = custody::binding(&base.join("failed.json"))?;
    let f = custody::evidence(&failed)?;
    ensure!(
        f["iid"] == ORIGINAL
            && f["error"].as_str().is_some_and(|s| !s.is_empty())
            && !base.join("complete.json").try_exists()?,
        "original export has not failed as recorded"
    );
    let journal = capacity::run(
        "/usr/bin/journalctl",
        &[
            "-ojson",
            "--no-pager",
            "--output-fields=UNIT,INVOCATION_ID,MESSAGE_ID,EXIT_CODE,EXIT_STATUS",
            "_PID=1",
            &format!("UNIT={UNIT}"),
            &format!("INVOCATION_ID={ORIGINAL}"),
            "MESSAGE_ID=98e322203f7a4ed290d09fe03c09fe15",
        ],
        "10",
    )?;
    let event = journal
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .find(|v| {
            v["UNIT"] == UNIT
                && v["INVOCATION_ID"] == ORIGINAL
                && v["EXIT_CODE"] == "exited"
                && v["EXIT_STATUS"] == "1"
        })
        .context("original exporter lacks native nonzero exit")?;
    Ok(
        json!({"original":ORIGINAL,"native_failure":event,"failure":failed,"native_receipts":proofs}),
    )
}
fn check_file(m: &fs::Metadata) -> Result<()> {
    check_geometry(
        m,
        64512,
        103237059,
        BYTES,
        capacity::output_allocation(),
        105611071488 + (128 << 20),
    )
}
pub(super) fn check_geometry(
    m: &fs::Metadata,
    device: u64,
    inode: u64,
    bytes: u64,
    allocated: u64,
    cap: u64,
) -> Result<()> {
    ensure!(
        m.is_file()
            && m.nlink() == 1
            && m.uid() == 0
            && m.gid() == 0
            && m.dev() == device
            && m.ino() == inode
            && m.len() == bytes
            && matches!(m.mode() & 0o777, 0o400 | 0o600)
            && (allocated..=cap).contains(&(m.blocks() * 512)),
        "candidate is not the original fully materialized paid inode"
    );
    Ok(())
}
pub(super) fn leaf() -> Result<PathBuf> {
    let root = Path::new(OUTPUT);
    custody::private_directory(root)?;
    let files = fs::read_dir(root)?
        .map(|x| x.map(|v| v.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    ensure!(
        files.len() == 1 && (files[0] == root.join(LEAF) || files[0] == canonical()),
        "private paid output namespace changed"
    );
    let path = &files[0];
    ensure!(path.canonicalize()? == *path, "candidate alias");
    inspect_leaf(&fs::symlink_metadata(path)?)?;
    Ok(path.clone())
}
fn inspect_leaf(m: &fs::Metadata) -> Result<()> {
    if cfg!(continuity145_only) {
        check_file(m)?;
        ensure!(
            m.mode() & 0o777 == 0o400,
            "frozen recovery cannot open an unfinished candidate"
        );
        Ok(())
    } else if cfg!(partial145_only) {
        partial::check(m)
    } else {
        check_file(m)
    }
}
pub(super) fn prove_view(file: &Path) -> Result<()> {
    let projected = view();
    let p = fs::symlink_metadata(&projected)?;
    let m = fs::symlink_metadata(file)?;
    inspect_leaf(&m)?;
    inspect_leaf(&p)?;
    ensure!(
        projected.canonicalize()? == projected && p.ino() == m.ino() && p.dev() == m.dev(),
        "private verifier projection changed"
    );
    read_only_view(&projected, Path::new(VIEW))
}
fn read_only_view(projected: &Path, root: &Path) -> Result<()> {
    let mountinfo = fs::read_to_string("/proc/self/mountinfo")?;
    let readonly = |p: &Path| {
        mountinfo.lines().any(|l| {
            let mut f = l.split_whitespace().skip(4);
            f.next() == p.to_str() && f.next().is_some_and(|v| v.split(',').any(|x| x == "ro"))
        })
    };
    ensure!(
        readonly(projected) && readonly(root),
        "private verifier projections are not read-only mounts"
    );
    Ok(())
}
fn seal_candidate(path: &Path) -> Result<()> {
    check_file(&fs::symlink_metadata(path)?)?;
    freeze_inode(path, check_file)
}
fn freeze_inode(path: &Path, check: impl Fn(&fs::Metadata) -> Result<()>) -> Result<()> {
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    check(&f.metadata()?)?;
    ensure!(
        unsafe { libc::fcntl(f.as_raw_fd(), libc::F_SETLEASE, libc::F_WRLCK) } == 0,
        "materialized candidate has another open or writable mapping"
    );
    check(&fs::symlink_metadata(path)?)?;
    f.set_permissions(fs::Permissions::from_mode(0o400))?;
    f.sync_all()?;
    Ok(())
}
pub(super) fn lease(path: &Path) -> Result<source_lease::ReadLease> {
    source_lease::ReadLease::acquire(
        path,
        source_lease::FileIdentity::from(&fs::symlink_metadata(path)?),
    )
}
pub(super) fn guard_parent(parent: u32) -> Result<()> {
    ensure!(
        parent > 1 && unsafe { libc::getppid() } as u32 == parent,
        "recovery verifier lacks native parent"
    );
    let p = fs::metadata(format!("/proc/{parent}/exe"))?;
    let myself = fs::metadata("/proc/self/exe")?;
    ensure!(
        p.dev() == myself.dev()
            && p.ino() == myself.ino()
            && fs::read_to_string(format!("/proc/{parent}/cgroup"))?
                == fs::read_to_string("/proc/self/cgroup")?,
        "foreign recovery verifier parent"
    );
    ensure!(
        fs::read_to_string("/proc/locks")?.lines().any(|l| {
            let v = l.split_whitespace().collect::<Vec<_>>();
            v.len() == 8
                && v[1..4] == ["FLOCK", "ADVISORY", "WRITE"]
                && v[4] == parent.to_string()
                && v[5..8] == ["fc:00:95818311", "0", "EOF"]
        }),
        "recovery verifier parent does not hold the paid serial lock"
    );
    Ok(())
}
pub fn verify(parent: u32, sha: &str) -> Result<()> {
    check_image(sha, Path::new(IMAGE))?;
    let iid = verify_cgroup()?;
    guard_parent(parent)?;
    let file = leaf()?;
    prove_view(&file)?;
    source_lease::arm_break_signal()?;
    let src = lease(Path::new(SOURCE))?;
    let manifest = lease(Path::new(MANIFEST))?;
    let candidate = lease(&file)?;
    #[cfg(incident_lease_start145_only)]
    {
        post::lease_startup::stop_after_leases()?;
        src.check()?;
        manifest.check()?;
        candidate.check()?;
    }
    source_identity()?;
    let before = custody::frozen_identity(&file)?;
    let mut source = epoch145_extract::PinnedSource::open(
        Path::new(SOURCE),
        Path::new(MANIFEST),
        decode_sha(MANIFEST_SHA)?,
        epoch145_extract::PINNED_WORKER_SHA256,
    )?;
    let deny_write = |_| {
        Err(std::io::Error::other(
            "frozen verifier cannot write an archive",
        ))
    };
    let extraction = if cfg!(continuity145_only) {
        source.extract_with_source_pass(Path::new(VIEW), BYTES, None, deny_write, |derive| {
            continuity::source_pass(&iid, sha, &file, derive)
        })?
    } else {
        source.extract_private(Path::new(VIEW), BYTES, deny_write)?
    };
    ensure!(
        extraction.archive == view()
            && extraction.archive_bytes == BYTES
            && extraction.output_slot_count == 432000
            && extraction.independent_output_reread_passed
            && extraction.source_archive_sha256 == SOURCE_SHA
            && extraction.source_manifest_sha256 == MANIFEST_SHA
            && !extraction.publication_authorized
            && custody::frozen_identity(&file)? == before,
        "materialized verification result or identity changed"
    );
    guard_parent(parent)?;
    prove_view(&file)?;
    src.check()?;
    manifest.check()?;
    candidate.check()?;
    custody::write_new(
        &state(&iid).join("verified-frozen.json"),
        &json!({"iid":iid,"parent":parent,"pid":std::process::id(),"paid_source":file,
        "private_projection":view(),"original_export":ORIGINAL,"before":before,"extraction":extraction,"r2_mutations":false}),
    )?;
    Ok(())
}
fn promote(source: &Path, target: &Path) -> Result<()> {
    let a = CString::new(source.as_os_str().as_bytes())?;
    let b = CString::new(target.as_os_str().as_bytes())?;
    let result = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            a.as_ptr(),
            libc::AT_FDCWD,
            b.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    File::open(target.parent().context("publication directory")?)?.sync_all()?;
    Ok(())
}
#[cfg(incident_v5y_guard_recovery145_only)]
pub(super) fn check_recovery_custody(sha: &str) -> Result<()> {
    check_image(sha, Path::new(IMAGE))?;
    let _lock = lock()?;
    pending()?;
    let prior = pred().context("materialized predecessor custody")?;
    let recovery = continuity::predecessor().context("frozen predecessor custody")?;
    source_identity().context("frozen source identity")?;
    let candidate = leaf().context("paid candidate custody")?;
    prove_view(&candidate).context("read-only paid candidate view")?;
    ensure!(accepted_owner()?.is_none(), "a successful export already owns the paid archive");
    println!("{}", json!({
        "schema":"horizon-epoch145-v5z-native-custody-preflight-v1",
        "predecessor":prior,
        "frozen_recovery":recovery,
        "candidate":candidate,
        "archive_publication_authorized":false,
        "r2_mutations":false
    }));
    Ok(())
}

pub fn run(fleet: Bound, sha: &str) -> Result<()> {
    check_image(sha, Path::new(IMAGE))?;
    let iid = verify_cgroup()?;
    let _lock = lock()?;
    pending()?;
    let prior = pred()?;
    let prior_recovery = if cfg!(continuity145_only) {
        Some(continuity::predecessor()?)
    } else {
        None
    };
    source_identity()?;
    let file = leaf()?;
    prove_view(&file)?;
    #[cfg(incident145_only)]
    let fit = crate::incident_fit::Fit::capture(&fleet)?;
    #[cfg(not(incident145_only))]
    let fit = capacity::capture_phase(&fleet, cfg!(continuity145_only))?;
    fit.await_topology()?;
    let initial = fit.await_current(0)?;
    ensure!(
        accepted_owner()?.is_none(),
        "a successful export already owns the paid archive"
    );
    let root = state(&iid);
    fs::DirBuilder::new().mode(0o700).create(&root)?;
    custody::write_new(
        &root.join("recovery-started.json"),
        &json!({"iid":iid,"predecessor":prior,"prior_frozen_recovery":prior_recovery,"file":file,"image":sha,"fresh_fit":fit.evidence,"initial":initial,"r2_mutations":false}),
    )?;
    let attempt = (|| -> Result<()> {
        source_lease::arm_break_signal()?;
        let original = lease(Path::new(SOURCE))?;
        let manifest = lease(Path::new(MANIFEST))?;
        if cfg!(all(partial145_only, not(continuity145_only)))
            && fs::symlink_metadata(&file)?.len() < BYTES
        {
            post::run_child(
                Command::new(IMAGE).args(["recover-append", &std::process::id().to_string(), sha]),
                &fit,
                &original,
            )?;
        }
        if !cfg!(continuity145_only) {
            seal_candidate(&file)?;
        }
        let candidate = lease(&file)?;
        let id = custody::frozen_identity(&file)?;
        let prior_verified = if cfg!(continuity145_only) {
            continuity::reusable_completion(&iid, sha, &file, &view())?
        } else {
            None
        };
        if let Some(verified) = prior_verified {
            custody::write_new(&root.join("verified-frozen.json"), &verified)?;
        } else {
            post::run_child_with_startup(
                Command::new(IMAGE).args(["recover-worker", &std::process::id().to_string(), sha]),
                &fit,
                &original,
                cfg!(incident_lease_start145_only),
            )?;
        }
        let verification = custody::binding(&root.join("verified-frozen.json"))?;
        let v = custody::evidence(&verification)?;
        ensure!(
            v["iid"] == iid
                && v["parent"] == std::process::id()
                && v["before"] == json!(id)
                && v["private_projection"] == json!(view())
                && v["paid_source"] == json!(file),
            "unbound materialized verifier result"
        );
        fit.await_topology()?;
        fit.await_current(0)?;
        original.check()?;
        manifest.check()?;
        candidate.check()?;
        prove_view(&file)?;
        let target = canonical();
        if file != target {
            promote(&file, &target)?;
        }
        let m = custody::frozen_identity(&target)?;
        ensure!(
            m.device == id.device
                && m.inode == id.inode
                && m.bytes == id.bytes
                && m.mtime_ns == id.mtime_ns
                && fs::symlink_metadata(&target)?.mode() & 0o777 == 0o400,
            "promoted inode changed"
        );
        let mut e = v["extraction"].clone();
        ensure!(e["archive"] == json!(view()), "wrong verifier leaf");
        e["archive"] = json!(target);
        let cc = custody::write_new(
            &root.join("extraction-complete.json"),
            &json!({"schema":"horizon-epoch145-guarded-private-prefix-completion-v1","actor_iid":iid,"at_unix_seconds":custody::now()?,"extraction":e,"original_export":ORIGINAL,"verified_frozen":verification,"recovery_evidence":custody::binding(&root.join("recovery-started.json"))?,"archive_publication_authorized":false,"r2_mutations":false}),
        )?;
        custody::write_new(
            &root.join("complete.json"),
            &json!({"iid":iid,"at":custody::now()?,"receipt":cc,"recovered_from":ORIGINAL,"r2_mutations":false}),
        )?;
        Ok(())
    })();
    if let Err(err) = &attempt {
        let _ = custody::write_new(
            &root.join("failed.json"),
            &json!({"iid":iid,"at":custody::now()?,"error":format!("{err:#}")}),
        );
    }
    attempt
}
pub fn completion_owner() -> Result<String> {
    accepted_owner()?.context("missing successful materialized export")
}
fn accepted_owner() -> Result<Option<String>> {
    let original = state(ORIGINAL).join("complete.json");
    if original.try_exists()? {
        post::terminal(ORIGINAL)?;
        return Ok(Some(ORIGINAL.to_owned()));
    }
    let mut accepted = Vec::new();
    for d in fs::read_dir(Path::new(BASE).join("state"))? {
        let d = d?;
        let who = d.file_name();
        let Some(iid) = who.to_str() else { continue };
        if !custody::hex(iid, 32) {
            continue;
        }
        let p = d.path().join("complete.json");
        if !p.try_exists()? {
            continue;
        }
        let r = read(&p)?;
        if r["recovered_from"] == ORIGINAL
            && r["iid"] == iid
            && r["r2_mutations"] == false
            && post::terminal(iid).is_ok()
        {
            ensure!(
                !d.path().join("failed.json").try_exists()?,
                "completed recovery with failed receipt"
            );
            accepted.push(iid.to_owned());
        }
    }
    ensure!(
        accepted.len() <= 1,
        "expected one successful completed paid-inode recovery"
    );
    Ok(accepted.pop())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "requires the root-owned native read-only test projection"]
    fn paid_inode_native_projection() {
        let src = PathBuf::from(std::env::var("RECOVERY_FIXTURE_SOURCE").unwrap());
        let projected = PathBuf::from(std::env::var("RECOVERY_FIXTURE_VIEW").unwrap());
        let meta = fs::metadata(&src).unwrap();
        let blocks = meta.blocks() * 512;
        let check = |m: &fs::Metadata| {
            check_geometry(m, meta.dev(), meta.ino(), meta.len(), blocks, blocks)
        };
        assert!(
            check_geometry(
                &meta,
                meta.dev(),
                meta.ino(),
                meta.len() + 1,
                blocks,
                blocks
            )
            .is_err()
        );
        assert!(
            check_geometry(
                &meta,
                meta.dev(),
                meta.ino() + 1,
                meta.len(),
                blocks,
                blocks
            )
            .is_err()
        );
        check(&fs::metadata(&projected).unwrap()).unwrap();
        read_only_view(&projected, projected.parent().unwrap()).unwrap();
        let open = File::open(&projected).unwrap();
        assert!(freeze_inode(&src, check).is_err());
        drop(open);
        freeze_inode(&src, check).unwrap();
        source_lease::arm_break_signal().unwrap();
        let held = lease(&src).unwrap();
        assert_eq!(fs::read(&src).unwrap(), fs::read(&projected).unwrap());
        held.check().unwrap();
        // The bind is read-only even to this root-native service.
        assert_eq!(
            OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(&projected)
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EROFS)
        );
        #[cfg(incident145_only)]
        {
            closed166::drained().unwrap();
            crate::continuity::failure(crate::incident145::PREVIOUS).unwrap();
        }
        #[cfg(not(incident145_only))]
        assert!(closed166::drained().is_err());
        let live = Path::new(OUTPUT).join(LEAF);
        let meta = fs::symlink_metadata(live).unwrap();
        if cfg!(continuity145_only) {
            check_file(&meta).unwrap();
            assert_eq!(meta.mode() & 0o777, 0o400);
        } else {
            assert!(check_file(&meta).is_err());
        }
    }
    #[test]
    fn promotion_preserves_prior_target_and_reuses_the_original_inode() {
        let d = tempfile::tempdir().unwrap();
        let a = d.path().join("candidate");
        let b = d.path().join("epoch-145.jet");
        fs::write(&a, b"complete").unwrap();
        let ino = fs::metadata(&a).unwrap().ino();
        fs::write(&b, b"existing").unwrap();
        assert!(promote(&a, &b).is_err());
        assert_eq!(fs::read(&b).unwrap(), b"existing");
        assert_eq!(fs::read(&a).unwrap(), b"complete");
        fs::remove_file(&b).unwrap();
        promote(&a, &b).unwrap();
        assert_eq!(fs::metadata(&b).unwrap().ino(), ino);
        assert!(!a.exists());
    }
}
