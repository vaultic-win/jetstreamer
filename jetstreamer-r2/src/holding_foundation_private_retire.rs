//! Exact single-file local retirement after authenticated cold-private custody.
//! Canonical archives/sidecars, directories and remote objects are never removed.
use super::*;
use std::{ffi::CString, os::fd::AsRawFd};

pub(super) fn absent(p: &Path) -> Result<bool> {
    match fs::symlink_metadata(p) {
        Ok(_) => Ok(false),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(e) => Err(e.into()),
    }
}
fn quarantine(a: Artifact, sha: &str) -> Result<PathBuf> {
    ensure!(digest(sha), "invalid quarantine digest");
    Ok(Path::new(STATE)
        .join("quarantine")
        .join(format!("{}-{sha}.blob", a.epoch())))
}
fn name(a: Artifact, sha: &str, phase: &str) -> String {
    format!("private-retire-{}-{sha}-{phase}.json", a.epoch())
}
fn record(a: Artifact, sha: &str, phase: &str, op: &Value) -> Result<Value> {
    let path = Path::new(STATE).join("receipts").join(name(a, sha, phase));
    record_at(&path, op, 0)
}
pub(super) fn record_at(path: &Path, op: &Value, required_uid: u32) -> Result<Value> {
    let before = regular_identity(path)?;
    let bytes = read_stable_bounded(path, 8 << 20, "private retirement record")?;
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.uid() == required_uid
            // The unchanged shared durable writer publishes mode 0440; retain
            // compatibility with existing owner-only readonly mode 0400.
            // Production still requires UID 0 inside its root-private 0700 state.
            && matches!(m.mode() & 0o777, 0o400 | 0o440)
            && m.nlink() == 1
            && regular_identity(path)? == before,
        "unsafe private retirement record"
    );
    let v: Value = serde_json::from_slice(&bytes)?;
    ensure!(
        v["operation"] == *op,
        "interrupted private retirement belongs to another custody/generation"
    );
    Ok(v)
}
fn exists(a: Artifact, sha: &str, phase: &str) -> Result<bool> {
    Ok(!absent(
        &Path::new(STATE).join("receipts").join(name(a, sha, phase)),
    )?)
}
#[cfg(test)]
fn lifecycle(
    source: bool,
    q: bool,
    intent: bool,
    verified: bool,
    unlink: bool,
    complete: bool,
) -> Result<()> {
    runner::RetireState {
        source,
        quarantine: q,
        intent,
        verified,
        unlink,
        complete,
    }
    .validate()
}

fn body(path: &Path, a: Artifact, sha: &str, original: bool) -> Result<Stamp> {
    body_at(path, &a.expected(), sha, original)
}
pub(super) fn body_at(path: &Path, expected: &Stamp, sha: &str, original: bool) -> Result<Stamp> {
    ensure!(
        path.canonicalize()? == path,
        "aliased local retirement target"
    );
    let m = fs::symlink_metadata(path)?;
    let stamp = Stamp::of(&m);
    ensure!(
        m.is_file()
            && if original {
                stamp == *expected
            } else {
                stamp.same_body_identity(expected)
            },
        "local private target generation changed"
    );
    let id = regular_identity(path)?;
    let proof = hash_and_etag(path, id, DEFAULT_PART_SIZE)?;
    ensure!(
        proof.sha256_hex == sha
            && regular_identity(path)? == id
            && Stamp::of(&fs::symlink_metadata(path)?) == stamp,
        "local private body changed or digest differs"
    );
    Ok(stamp)
}
fn child(name: &std::ffi::OsStr) -> Result<CString> {
    use std::os::unix::ffi::OsStrExt;
    ensure!(
        Path::new(name).components().count() == 1
            && matches!(
                Path::new(name).components().next(),
                Some(std::path::Component::Normal(_))
            ),
        "invalid exact child"
    );
    Ok(CString::new(name.as_bytes())?)
}
pub(super) fn rename_child(
    from: &File,
    old: &std::ffi::OsStr,
    to: &File,
    new: &std::ffi::OsStr,
) -> Result<()> {
    let old = child(old)?;
    let new = child(new)?;
    let rc = unsafe {
        libc::renameat2(
            from.as_raw_fd(),
            old.as_ptr(),
            to.as_raw_fd(),
            new.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    ensure!(
        rc == 0,
        "private no-clobber quarantine rename failed: {}",
        std::io::Error::last_os_error()
    );
    from.sync_all()?;
    to.sync_all()?;
    Ok(())
}
pub(super) fn unlink_child(dir: &File, name: &std::ffi::OsStr) -> Result<()> {
    let name = child(name)?;
    ensure!(
        unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) } == 0,
        "exact private unlink failed: {}",
        std::io::Error::last_os_error()
    );
    dir.sync_all()?;
    Ok(())
}
fn move_original(a: Artifact, sha: &str) -> Result<()> {
    let source = a.source();
    let target = quarantine(a, sha)?;
    let parent = source.parent().unwrap();
    ensure!(parent.canonicalize()? == parent, "source parent aliased");
    let from = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(parent)?;
    let to = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(target.parent().unwrap())?;
    ensure!(
        from.metadata()?.dev() == to.metadata()?.dev(),
        "private quarantine must be on the source filesystem"
    );
    super::source(a)?;
    rename_child(
        &from,
        source.file_name().unwrap(),
        &to,
        target.file_name().unwrap(),
    )?;
    ensure!(
        Stamp::of(&fs::symlink_metadata(&target)?).same_body_identity(&a.expected())
            && absent(&source)?,
        "foreign quarantine or original name reappeared"
    );
    Ok(())
}
fn unlink_exact(a: Artifact, sha: &str, stamp: &Stamp) -> Result<()> {
    let path = quarantine(a, sha)?;
    let parent = path.parent().unwrap();
    private(parent)?;
    ensure!(
        Stamp::of(&fs::symlink_metadata(&path)?) == *stamp,
        "quarantine identity changed before unlink"
    );
    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(parent)?;
    unlink_child(&dir, path.file_name().unwrap())?;
    Ok(())
}
fn chain(a: Artifact, sha: &str, op: &Value) -> Result<()> {
    let v = record(a, sha, "quarantine-verified", op)?;
    let d = record(a, sha, "unlink-intent", op)?;
    validate_chain(&a.expected(), &v, &d)
}
pub(super) fn validate_chain(expected: &Stamp, v: &Value, d: &Value) -> Result<()> {
    let q: Stamp = serde_json::from_value(v["quarantine_stamp"].clone())?;
    ensure!(
        v["complete_local_sha256_verified"] == true
            && v["source_body_identity"] == serde_json::to_value(expected)?
            && q.same_body_identity(expected)
            && d["quarantine_verification"] == v["quarantine_stamp"],
        "missing exact quarantine hash/unlink chain"
    );
    Ok(())
}
struct NativeRetire<'a> {
    client: &'a Client,
    p: CustodySpec,
    spec: &'a Bound,
    custody: Value,
    artifact: Artifact,
    sha: String,
    entry: u64,
    quarantine: PathBuf,
    operation: Value,
    closure_before: Option<Value>,
    stamp: Option<Stamp>,
}
impl runner::RetireOperations for NativeRetire<'_> {
    fn state(&self) -> Result<runner::RetireState> {
        let a = self.artifact;
        let sha = &self.sha;
        Ok(runner::RetireState {
            source: !absent(&a.source())?,
            quarantine: !absent(&self.quarantine)?,
            intent: exists(a, sha, "intent")?,
            verified: exists(a, sha, "quarantine-verified")?,
            unlink: exists(a, sha, "unlink-intent")?,
            complete: exists(a, sha, "completion")?,
        })
    }
    async fn step(&mut self, step: runner::RetireStep) -> Result<()> {
        use runner::RetireStep::*;
        let a = self.artifact;
        let sha = &self.sha;
        let op = &self.operation;
        match step {
            VerifyComplete => {
                let done = record(a, sha, "completion", op)?;
                record(a, sha, "intent", op)?;
                chain(a, sha, op)?;
                ensure!(
                    done["source_and_quarantine_absent"] == true
                        && absent(&a.source())?
                        && absent(&self.quarantine)?,
                    "completed private namespace changed"
                );
                println!("{}", serde_json::to_string(&done)?);
            }
            Inspect => {
                canonical_exclusion(a)?;
                self.closure_before = Some(closure::inspect(
                    a,
                    &self.p.closure,
                    self.entry,
                    !absent(&a.source())?,
                )?);
                ensure!(
                    metadata(a)? == self.custody["manifest"]["raw_metadata"],
                    "retained local private metadata changed"
                );
            }
            HashOriginal => {
                self.stamp = Some(body(&a.source(), a, sha, true)?);
            }
            CheckOnly => {
                if a.requires_prior_check() {
                    if exists(a, sha, "intent")? {
                        // Recovery checks are diagnostic, never a renewed fresh
                        // destructive capability after the original intent.
                        println!(
                            "{}",
                            json!({"status":"interrupted-retirement-check-passed",
                            "operation":op,"new_retirement_check_capability":false})
                        );
                        return Ok(());
                    }
                    let after = closure::inspect(a, &self.p.closure, self.entry, true)?;
                    source(a)?;
                    ensure!(
                        metadata(a)? == self.custody["manifest"]["raw_metadata"],
                        "successor private metadata changed after the complete check hash"
                    );
                    let name = format!("{}-check-{}.json", a.check_label(), self.spec.sha256);
                    let path = Path::new(STATE).join("receipts").join(&name);
                    if old237::existing_check(&path, op, self.spec)? {
                        println!("{}", path.display());
                        return Ok(());
                    }
                    let value = json!({"schema":format!("jetstreamer-{}-private-retirement-check-v1", a.check_label()),
                        "operation":op,"check_spec":self.spec,"check_only":true,"local_retirement_authorized":false,
                        "closure":self.closure_before,"closure_after_hash":after,"source_stamp":self.stamp,
                        "original_source_hash_verified":self.stamp.as_ref() == Some(&a.expected()),
                        "recorded_unix_seconds":clock()?});
                    println!("{}", receipt(&name, &value)?.display());
                    return Ok(());
                }
                println!(
                    "{}",
                    json!({"status":if exists(a,sha,"intent")?{"interrupted-retirement-check-passed"}else{"check-passed"},
                    "operation":op,"closure":self.closure_before,"source_stamp":self.stamp})
                );
            }
            Intent => {
                if a.requires_prior_check() {
                    old237::prior_check(
                        self.p
                            .prior_check
                            .as_ref()
                            .context("successor private prior check absent")?,
                        op,
                        clock()?,
                    )?;
                }
                receipt(
                    &name(a, sha, "intent"),
                    &json!({"operation":op,"spec":self.spec,"recorded_unix_seconds":clock()?,
                    "closure":self.closure_before,"source_stamp":self.stamp.as_ref().context("original body was not verified")?,
                    "raw_metadata_retained_locally":true,"remote_custody_fsynced":true}),
                )?;
            }
            ReconcileIntent => {
                record(a, sha, "intent", op)?;
                if !absent(&a.source())? {
                    self.stamp = Some(body(&a.source(), a, sha, true)?);
                } else if !absent(&self.quarantine)? {
                    self.stamp = Some(body(&self.quarantine, a, sha, false)?);
                } else {
                    chain(a, sha, op)?;
                }
            }
            BeforeRename => {
                closure::inspect(a, &self.p.closure, self.entry, !absent(&a.source())?)?;
                remote_custody(self.client, &self.custody).await?;
            }
            Rename => {
                move_original(a, sha)?;
            }
            HashQuarantine => {
                self.stamp = Some(body(&self.quarantine, a, sha, false)?);
            }
            QuarantineProof => {
                let stamp = self
                    .stamp
                    .as_ref()
                    .context("quarantine body was not verified")?;
                if !exists(a, sha, "quarantine-verified")? {
                    receipt(
                        &name(a, sha, "quarantine-verified"),
                        &json!({"operation":op,"source_body_identity":a.expected(),
                        "quarantine_stamp":stamp,"complete_local_sha256_verified":true,"recorded_unix_seconds":clock()?}),
                    )?;
                } else {
                    ensure!(
                        record(a, sha, "quarantine-verified", op)?["quarantine_stamp"]
                            == serde_json::to_value(stamp)?,
                        "quarantine stamp changed"
                    );
                }
            }
            UnlinkIntent => {
                let stamp = self
                    .stamp
                    .as_ref()
                    .context("quarantine body was not verified")?;
                if !exists(a, sha, "unlink-intent")? {
                    receipt(
                        &name(a, sha, "unlink-intent"),
                        &json!({"operation":op,"quarantine_verification":stamp,"recorded_unix_seconds":clock()?}),
                    )?;
                }
                chain(a, sha, op)?;
            }
            BeforeUnlink => {
                closure::inspect(a, &self.p.closure, self.entry, false)?;
                remote_custody(self.client, &self.custody).await?;
                ensure!(absent(&a.source())?, "original private name reappeared");
            }
            Unlink => {
                unlink_exact(
                    a,
                    sha,
                    self.stamp
                        .as_ref()
                        .context("quarantine body was not verified")?,
                )?;
            }
            VerifyChain => {
                ensure!(absent(&a.source())?, "original private name reappeared");
                chain(a, sha, op)?;
            }
            Complete => {
                ensure!(
                    absent(&a.source())? && absent(&self.quarantine)?,
                    "private retirement target remains"
                );
                let result = json!({"operation":op,"status":"complete","source_and_quarantine_absent":true,"all_other_local_files_preserved":true,
                    "recorded_unix_seconds":clock()?,"capacity_credit_requires_fresh_independent_observation":true});
                println!(
                    "{}",
                    receipt(&name(a, sha, "completion"), &result)?.display()
                );
            }
        }
        Ok(())
    }
}
pub(super) async fn run(client: &Client, p: CustodySpec, spec: &Bound, check: bool) -> Result<()> {
    ensure!(
        p.schema == "jetstreamer-foundation-closed-private-retirement-plan-v1"
            && p.local_private_retirement_authorized,
        "private cold retirement is not authorized by this exact plan"
    );
    mapping(&p.mapping)?;
    let custody = saved(&p.custody)?;
    let (artifact, sha) = remote_custody(client, &custody).await?;
    let quarantine = quarantine(artifact, &sha)?;
    let mut operation = json!({"schema":"jetstreamer-foundation-closed-private-retirement-operation-v1","artifact":artifact,"source":artifact.source(),
        "source_body_identity":artifact.expected(),"sha256":sha,"custody":p.custody,"object_key":key(&sha)?,"object_etag":custody["object_etag"],
        "quarantine":quarantine,"canonical_archive":false,"remote_mutations":false,"canonical_retirement_authorized":false});
    if artifact.requires_prior_check() {
        if let Some(prior) = &p.prior_check {
            operation[artifact.prior_check_field()] = serde_json::to_value(prior)?;
            // A durable exact intent carries an already-admitted check across
            // interrupted retries. New operations use the actual current time.
            let at = if exists(artifact, &sha, "intent")? {
                record(artifact, &sha, "intent", &operation)?["recorded_unix_seconds"]
                    .as_u64()
                    .context("successor private original intent clock absent")?
            } else {
                clock()?
            };
            old237::prior_check(prior, &operation, at)?;
        } else {
            ensure!(
                check,
                "successor private retirement requires a separately completed fresh check"
            );
        }
    } else {
        ensure!(
            p.prior_check.is_none(),
            "original private variant cannot borrow a successor check"
        );
    }
    let mut native = NativeRetire {
        client,
        p,
        spec,
        custody,
        artifact,
        sha,
        entry: clock()?,
        quarantine,
        operation,
        closure_before: None,
        stamp: None,
    };
    runner::retire(&mut native, check).await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn interruption_states_are_reconciled_without_deleting_a_reappeared_source() {
        for x in [
            (true, false, false, false, false, false),
            (true, false, true, false, false, false),
            (false, true, true, false, false, false),
            (false, true, true, true, false, false),
            (false, true, true, true, true, false),
            (false, false, true, true, true, false),
            (false, false, true, true, true, true),
        ] {
            lifecycle(x.0, x.1, x.2, x.3, x.4, x.5).unwrap();
        }
        for x in [
            (true, true, true, true, true, false),
            (true, false, true, true, true, false),
            (false, false, true, false, true, false),
            (false, false, false, false, false, true),
        ] {
            assert!(lifecycle(x.0, x.1, x.2, x.3, x.4, x.5).is_err());
        }
    }
    #[test]
    fn quarantine_keys_are_fixed_under_root_private_state() {
        let q = quarantine(Artifact::ThroughRoot206, &"a".repeat(64)).unwrap();
        assert!(q.starts_with(Path::new(STATE).join("quarantine")));
        assert!(quarantine(Artifact::Singleton207, "../other").is_err());
        assert!(child(std::ffi::OsStr::new("../other")).is_err());
    }
    fn fixture_state(root: &Path) -> Result<()> {
        lifecycle(
            !absent(&root.join("source/partial.jet"))?,
            !absent(&root.join("state/partial.blob"))?,
            !absent(&root.join("state/intent.json"))?,
            !absent(&root.join("state/verified.json"))?,
            !absent(&root.join("state/unlink.json"))?,
            !absent(&root.join("state/complete.json"))?,
        )
    }
    fn fixture_advance(root: &Path, stage: u8) -> Result<()> {
        fixture_state(root)?;
        let source = File::open(root.join("source"))?;
        let state = File::open(root.join("state"))?;
        let v = json!({"fixture":"preserved closed private bytes"});
        if stage >= 1 && absent(&root.join("state/intent.json"))? {
            persist(&root.join("state/intent.json"), &v)?;
        }
        if stage >= 2 && !absent(&root.join("source/partial.jet"))? {
            rename_child(
                &source,
                std::ffi::OsStr::new("partial.jet"),
                &state,
                std::ffi::OsStr::new("partial.blob"),
            )?;
        }
        if stage >= 3 && absent(&root.join("state/verified.json"))? {
            ensure!(
                fs::read(root.join("state/partial.blob"))? == b"retained bytes",
                "fixture body changed"
            );
            persist(&root.join("state/verified.json"), &v)?;
        }
        if stage >= 4 && absent(&root.join("state/unlink.json"))? {
            persist(&root.join("state/unlink.json"), &v)?;
        }
        if stage >= 5 && !absent(&root.join("state/partial.blob"))? {
            unlink_child(&state, std::ffi::OsStr::new("partial.blob"))?;
        }
        if stage >= 6 && absent(&root.join("state/complete.json"))? {
            persist(&root.join("state/complete.json"), &v)?;
        }
        fixture_state(root)
    }
    #[test]
    fn actual_filesystem_recovery_preserves_neighboring_archives_and_sidecars() -> Result<()> {
        for boundary in 0..=6 {
            let root = tempfile::tempdir()?;
            fs::create_dir(root.path().join("source"))?;
            fs::create_dir(root.path().join("state"))?;
            fs::set_permissions(root.path().join("state"), fs::Permissions::from_mode(0o700))?;
            fs::write(root.path().join("source/partial.jet"), b"retained bytes")?;
            fs::write(
                root.path().join("source/epoch-209.jet.sha256"),
                b"canonical neighbor preserved",
            )?;
            let inode = fs::metadata(root.path().join("source/partial.jet"))?.ino();
            fixture_advance(root.path(), boundary)?;
            if (2..5).contains(&boundary) {
                assert_eq!(
                    fs::metadata(root.path().join("state/partial.blob"))?.ino(),
                    inode
                );
            }
            // Previous invocation descriptors are closed; reopen persisted state.
            fixture_advance(root.path(), 6)?;
            fixture_advance(root.path(), 6)?;
            assert!(
                absent(&root.path().join("source/partial.jet"))?
                    && absent(&root.path().join("state/partial.blob"))?
            );
            assert_eq!(
                fs::read(root.path().join("source/epoch-209.jet.sha256"))?,
                b"canonical neighbor preserved"
            );
        }
        Ok(())
    }
    #[test]
    fn existing_quarantine_is_never_overwritten() -> Result<()> {
        let root = tempfile::tempdir()?;
        fs::write(root.path().join("source"), b"original")?;
        fs::write(root.path().join("foreign"), b"foreign")?;
        let dir = File::open(root.path())?;
        assert!(
            rename_child(
                &dir,
                std::ffi::OsStr::new("source"),
                &dir,
                std::ffi::OsStr::new("foreign")
            )
            .is_err()
        );
        assert_eq!(fs::read(root.path().join("source"))?, b"original");
        assert_eq!(fs::read(root.path().join("foreign"))?, b"foreign");
        Ok(())
    }
    struct Harness {
        root: tempfile::TempDir,
        expected: Stamp,
        sha: String,
        operation: Value,
        stamp: Option<Stamp>,
        fault: Option<runner::RetireStep>,
        unlinks: usize,
    }
    impl Harness {
        fn new() -> Result<Self> {
            let root = tempfile::tempdir()?;
            fs::create_dir(root.path().join("source"))?;
            fs::create_dir(root.path().join("state"))?;
            fs::set_permissions(root.path().join("state"), fs::Permissions::from_mode(0o700))?;
            fs::write(root.path().join("source/private.jet"), b"retained bytes")?;
            fs::set_permissions(
                root.path().join("source/private.jet"),
                fs::Permissions::from_mode(0o600),
            )?;
            fs::write(
                root.path().join("source/epoch-209.jet.sha256"),
                b"canonical neighbor",
            )?;
            let expected = Stamp::of(&fs::metadata(root.path().join("source/private.jet"))?);
            let operation = json!({"source_identity":expected,"custody":{"path":"/fixture/custody.json","sha256":"a".repeat(64)}});
            persist(
                &root.path().join("state/custody.json"),
                &json!({"operation":operation,"authenticated_remote_readback":true}),
            )?;
            Ok(Self {
                root,
                expected,
                sha: hex_lower(&Sha256::digest(b"retained bytes")),
                operation,
                stamp: None,
                fault: None,
                unlinks: 0,
            })
        }
        fn source(&self) -> PathBuf {
            self.root.path().join("source/private.jet")
        }
        fn q(&self) -> PathBuf {
            self.root.path().join("state/private.blob")
        }
        fn path(&self, n: &str) -> PathBuf {
            self.root.path().join("state").join(format!("{n}.json"))
        }
        fn read(&self, n: &str) -> Result<Value> {
            record_at(&self.path(n), &self.operation, unsafe { libc::geteuid() })
        }
        fn write(&self, n: &str, v: &Value) -> Result<()> {
            persist(&self.path(n), v)
        }
        fn chain(&self) -> Result<()> {
            validate_chain(
                &self.expected,
                &self.read("verified")?,
                &self.read("unlink")?,
            )
        }
        fn corrupt(&self, n: &str, mutate: impl FnOnce(&mut Value)) -> Result<()> {
            let p = self.path(n);
            let mut v: Value = serde_json::from_slice(&fs::read(&p)?)?;
            mutate(&mut v);
            fs::set_permissions(&p, fs::Permissions::from_mode(0o600))?;
            fs::write(&p, serde_json::to_vec(&v)?)?;
            fs::set_permissions(&p, fs::Permissions::from_mode(0o440))?;
            File::open(&p)?.sync_all()?;
            Ok(())
        }
    }
    #[test]
    fn retirement_records_bind_actual_writer_mode_owner_and_single_link() -> Result<()> {
        let h = Harness::new()?;
        let path = h.path("custody");
        assert_eq!(fs::symlink_metadata(&path)?.mode() & 0o777, 0o440);
        h.read("custody")?;
        let uid = unsafe { libc::geteuid() };
        let other_uid = if uid == 0 { 1 } else { 0 };
        assert!(record_at(&path, &h.operation, other_uid).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400))?;
        h.read("custody")?;
        for mode in [0o000, 0o600, 0o640, 0o444] {
            fs::set_permissions(&path, fs::Permissions::from_mode(mode))?;
            assert!(h.read("custody").is_err());
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(0o440))?;
        h.read("custody")?;
        fs::hard_link(&path, h.path("extra-link"))?;
        assert!(h.read("custody").is_err());
        Ok(())
    }
    impl runner::RetireOperations for Harness {
        fn state(&self) -> Result<runner::RetireState> {
            let c = self.read("custody")?;
            ensure!(
                c["authenticated_remote_readback"] == true,
                "no durable custody"
            );
            Ok(runner::RetireState {
                source: !absent(&self.source())?,
                quarantine: !absent(&self.q())?,
                intent: !absent(&self.path("intent"))?,
                verified: !absent(&self.path("verified"))?,
                unlink: !absent(&self.path("unlink"))?,
                complete: !absent(&self.path("complete"))?,
            })
        }
        async fn step(&mut self, s: runner::RetireStep) -> Result<()> {
            use runner::RetireStep::*;
            match s {
                VerifyComplete => {
                    self.read("complete")?;
                    self.read("intent")?;
                    self.chain()?;
                    ensure!(
                        absent(&self.source())? && absent(&self.q())?,
                        "namespace reappeared"
                    );
                }
                Inspect | BeforeRename | BeforeUnlink => {
                    self.read("custody")?;
                }
                HashOriginal => {
                    self.stamp = Some(body_at(&self.source(), &self.expected, &self.sha, true)?);
                }
                CheckOnly => {}
                Intent => {
                    self.write(
                        "intent",
                        &json!({"operation":self.operation,"stamp":self.stamp}),
                    )?;
                }
                ReconcileIntent => {
                    self.read("intent")?;
                    if !absent(&self.source())? {
                        self.stamp =
                            Some(body_at(&self.source(), &self.expected, &self.sha, true)?);
                    } else if !absent(&self.q())? {
                        self.stamp = Some(body_at(&self.q(), &self.expected, &self.sha, false)?);
                    } else {
                        self.chain()?;
                    }
                }
                Rename => {
                    let from = File::open(self.root.path().join("source"))?;
                    let to = File::open(self.root.path().join("state"))?;
                    rename_child(
                        &from,
                        std::ffi::OsStr::new("private.jet"),
                        &to,
                        std::ffi::OsStr::new("private.blob"),
                    )?;
                }
                HashQuarantine => {
                    self.stamp = Some(body_at(&self.q(), &self.expected, &self.sha, false)?);
                }
                QuarantineProof => {
                    if absent(&self.path("verified"))? {
                        self.write("verified",&json!({"operation":self.operation,
                    "source_body_identity":self.expected,"quarantine_stamp":self.stamp,"complete_local_sha256_verified":true}))?;
                    } else {
                        ensure!(
                            self.read("verified")?["quarantine_stamp"]
                                == serde_json::to_value(&self.stamp)?,
                            "conflicting recorded stamp"
                        );
                    }
                }
                UnlinkIntent => {
                    if absent(&self.path("unlink"))? {
                        self.write("unlink",&json!({"operation":self.operation,"quarantine_verification":self.stamp}))?;
                    }
                    self.chain()?;
                }
                Unlink => {
                    ensure!(
                        Stamp::of(&fs::metadata(self.q())?)
                            == self.stamp.clone().context("missing fixture proof")?,
                        "stamp changed before unlink"
                    );
                    let dir = File::open(self.root.path().join("state"))?;
                    unlink_child(&dir, std::ffi::OsStr::new("private.blob"))?;
                    self.unlinks += 1;
                }
                VerifyChain => {
                    self.chain()?;
                }
                Complete => {
                    ensure!(
                        absent(&self.source())? && absent(&self.q())?,
                        "remaining candidate bytes"
                    );
                    self.write(
                        "complete",
                        &json!({"operation":self.operation,"source_and_quarantine_absent":true}),
                    )?;
                }
            }
            Ok(())
        }
        fn checkpoint(&mut self, s: runner::RetireStep) -> Result<()> {
            if self.fault == Some(s) {
                self.fault = None;
                bail!("injected interruption after {s:?}");
            }
            Ok(())
        }
    }
    #[tokio::test]
    async fn production_runner_resumes_every_durable_retirement_boundary() -> Result<()> {
        for point in [
            runner::RetireStep::Intent,
            runner::RetireStep::Rename,
            runner::RetireStep::QuarantineProof,
            runner::RetireStep::UnlinkIntent,
            runner::RetireStep::Unlink,
            runner::RetireStep::Complete,
        ] {
            let mut h = Harness::new()?;
            h.fault = Some(point);
            assert!(runner::retire(&mut h, false).await.is_err());
            runner::retire(&mut h, false).await?;
            runner::retire(&mut h, false).await?;
            assert_eq!(h.unlinks, 1);
            assert!(absent(&h.source())? && absent(&h.q())?);
            assert_eq!(
                fs::read(h.root.path().join("source/epoch-209.jet.sha256"))?,
                b"canonical neighbor"
            );
        }
        Ok(())
    }
    #[tokio::test]
    async fn production_runner_preserves_conflicting_custody_stamps_and_namespaces() -> Result<()> {
        let mut h = Harness::new()?;
        h.fault = Some(runner::RetireStep::Intent);
        assert!(runner::retire(&mut h, false).await.is_err());
        h.operation["custody"]["sha256"] = json!("b".repeat(64));
        let replacement = h.operation.clone();
        h.corrupt("custody", |v| v["operation"] = replacement)?;
        assert!(runner::retire(&mut h, false).await.is_err());
        assert!(h.source().exists());
        assert_eq!(h.unlinks, 0);
        let mut h = Harness::new()?;
        h.fault = Some(runner::RetireStep::QuarantineProof);
        assert!(runner::retire(&mut h, false).await.is_err());
        h.corrupt("verified", |v| v["quarantine_stamp"]["inode"] = json!(123))?;
        assert!(runner::retire(&mut h, false).await.is_err());
        assert!(h.q().exists());
        assert_eq!(h.unlinks, 0);
        let mut h = Harness::new()?;
        h.fault = Some(runner::RetireStep::Rename);
        assert!(runner::retire(&mut h, false).await.is_err());
        fs::write(h.source(), b"reappeared foreign file")?;
        assert!(runner::retire(&mut h, false).await.is_err());
        assert!(h.source().exists() && h.q().exists());
        let mut h = Harness::new()?;
        h.fault = Some(runner::RetireStep::Intent);
        assert!(runner::retire(&mut h, false).await.is_err());
        fs::write(h.q(), b"conflicting quarantine")?;
        assert!(runner::retire(&mut h, false).await.is_err());
        assert_eq!(fs::read(h.q())?, b"conflicting quarantine");
        let mut h = Harness::new()?;
        h.fault = Some(runner::RetireStep::Unlink);
        assert!(runner::retire(&mut h, false).await.is_err());
        fs::remove_file(h.path("verified"))?;
        assert!(runner::retire(&mut h, false).await.is_err());
        assert!(!h.path("complete").exists());
        Ok(())
    }
    #[tokio::test]
    async fn production_runner_never_retires_without_custody_or_during_check_only() -> Result<()> {
        let mut h = Harness::new()?;
        fs::remove_file(h.path("custody"))?;
        assert!(runner::retire(&mut h, false).await.is_err());
        assert!(h.source().exists());
        assert_eq!(h.unlinks, 0);
        let mut h = Harness::new()?;
        runner::retire(&mut h, true).await?;
        assert!(h.source().exists());
        assert!(!h.path("intent").exists());
        assert_eq!(h.unlinks, 0);
        Ok(())
    }
}
