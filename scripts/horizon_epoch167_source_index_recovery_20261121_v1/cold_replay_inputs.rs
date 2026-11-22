// Shared preparation and live read-only mount validation for cold replay sessions.
pub fn node() -> PathBuf {
    Path::new(PACKAGE).join("jetstreamer-node")
}
pub fn worker_image() -> PathBuf {
    Path::new(PACKAGE).join("jetstreamer-historical-worker-v1-5-6")
}
pub fn node_arg() -> String {
    node().display().to_string()
}
fn original() -> PathBuf {
    Path::new(LANE).join(PREVIOUS)
}
fn source_index(i: &Index) -> PathBuf {
    original().join("output/compact-indexes").join(i.0)
}
fn target_index(i: &Index) -> PathBuf {
    run().join("output/compact-indexes").join(i.0)
}

fn cache(i: &Index, full: bool) -> Result<Value> {
    let path = source_index(i);
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&path)?;
    let meta = f.metadata()?;
    let key = |m: &fs::Metadata| {
        (
            m.dev(),
            m.ino(),
            m.len(),
            m.mtime() * 1_000_000_000 + m.mtime_nsec(),
            m.ctime() * 1_000_000_000 + m.ctime_nsec(),
        )
    };
    ensure!(
        path.canonicalize()? == path
            && meta.is_file()
            && meta.nlink() == 1
            && meta.uid() == 1001
            && meta.gid() == 1003
            && key(&meta) == (64512, i.1, i.2, i.3, i.4),
        "different retained compact index {}",
        path.display()
    );
    if full {
        let mut hash = Sha256::new();
        std::io::copy(&mut f, &mut hash)?;
        ensure!(
            format!("{:x}", hash.finalize()) == i.5,
            "compact index digest differs: {}",
            path.display()
        );
    }
    ensure!(
        key(&fs::symlink_metadata(&path)?) == key(&meta) && key(&f.metadata()?) == key(&meta),
        "index changed during validation"
    );
    Ok(json!({"path":path,"identity":key(&meta),"sha256":i.5,"target":target_index(i)}))
}

pub fn profile() -> Result<Value> {
    let (argv, ar) = doc(
        &rt(OLD).join(format!(
            "launch-state/epoch{EPOCH}/ORIGINAL_PRODUCER_ARGV.json"
        )),
        Some(ORIGINAL_ARGV_SHA),
    )?;
    let mut argv: Vec<String> = serde_json::from_value(argv)?;
    let mut changes = 0;
    let before = original().display().to_string();
    let after = run().display().to_string();
    let mut bindings = vec![format!("{PACKAGE}:{PACKAGE}:rbind")];
    bindings.push(format!(
        "{INPUTS}/genesis.tar.bz2:{after}/output/genesis.tar.bz2"
    ));
    #[cfg(any(epoch166_retry11, epoch170_retry11, epoch170_retry12, epoch170_retry13))]
    bindings.push(format!(
        "{}:{INPUTS}/{BOOT}",
        retry11::bootstrap().display()
    ));
    for i in INDEXES {
        bindings.push(format!(
            "{}:{}",
            source_index(i).display(),
            target_index(i).display()
        ));
    }
    for a in &mut argv {
        if a == &format!("--unit={OLD_UNIT}") {
            *a = format!("--unit={UNIT}");
            changes += 1;
        } else if a == &format!("--property=ReadWritePaths={LANE}") {
            *a = format!("--property=ReadWritePaths={after}");
            changes += 1;
        } else if a == &format!("--property=BindReadOnlyPaths={PACKAGE}:{PACKAGE}:rbind") {
            *a = format!("--property=BindReadOnlyPaths={}", bindings.join(" "));
            changes += 1;
        } else if a.contains(&before) {
            *a = a.replace(&before, &after);
            changes += 1;
        }
    }
    ensure!(
        changes == 7
            && argv[argv.len() - 8..]
                == [
                    node_arg(),
                    EPOCH.to_string(),
                    run().join("output").display().to_string(),
                    "--verify".into(),
                    "--root-checkpoint-cohort".into(),
                    format!("--cohort-manifest={PACKAGE}/preflight-{EPOCH}-v4.json"),
                    format!("--cohort-manifest-fingerprint={FINGERPRINT}"),
                    format!("--snapshot-archive={INPUTS}/{BOOT}")
                ],
        "different original producer profile"
    );
    let p = json!({"producer_argv":argv,"source_argv":ar,"fresh_attempt":run(),"indexes":INDEXES.iter().map(|i|cache(i,false)).collect::<Result<Vec<_>>>()?});
    #[cfg(any(epoch166_retry11, epoch170_retry11, epoch170_retry12, epoch170_retry13))]
    let p = {
        let mut registered = p;
        registered["producer_unit"] = json!(UNIT);
        registered["guard_timer"] = json!(TIMER);
        registered["guard_worker_root"] = json!(LANE);
        registered["guard_binary_sha256"] = json!(GUARD_SHA);
        registered
    };
    Ok(p)
}

pub fn prepare() -> Result<Value> {
    let baseline = files()?;
    let (manifest, _) = doc(
        &Path::new(PACKAGE).join(format!("preflight-{EPOCH}-v4.json")),
        Some(MANIFEST_SHA),
    )?;
    let e = &manifest["manifest"]["epochs"][0];
    ensure!(
        manifest["manifest_fingerprint"] == FINGERPRINT
            && e["epoch"] == EPOCH
            && e["bootstrap"]["slot"] == BOOT_SLOT
            && e["post_bootstrap_root_checkpoints"][0]["slot"] == CHECKPOINT_SLOT
            && e["post_bootstrap_root_checkpoints"][0]["accounts_hash"] == CHECKPOINT_HASH,
        "incorrect full epoch root lineage"
    );
    let receipt = base().join("PREPARED.json");
    if receipt.try_exists()? {
        let (v, r) = doc(&receipt, None)?;
        ensure!(v["baseline"] == baseline, "prepared generation changed");
        return Ok(r);
    }
    ensure!(
        native(UNIT)?["LoadState"] == "not-found" && members(UNIT)?.is_empty(),
        "successor already active"
    );
    for (path, digest) in [
        (node(), NODE_SHA),
        (worker_image(), WORKER_SHA),
        #[cfg(not(any(epoch166_retry11, epoch170_retry11, epoch170_retry12, epoch170_retry13)))]
        (Path::new(INPUTS).join(BOOT), BOOT_SHA),
        (Path::new(INPUTS).join("genesis.tar.bz2"), GENESIS_SHA),
    ] {
        ensure!(
            file_digest(&path)? == digest,
            "sealed input differs: {}",
            path.display()
        );
    }
    #[cfg(any(epoch166_retry11, epoch170_retry11, epoch170_retry12, epoch170_retry13))]
    retry11::snapshot(true)?;
    let mut verified = Vec::new();
    for i in INDEXES {
        verified.push(cache(i, true)?);
    }
    let log = run().join("producer.log");
    let log_fd = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&log)?;
    let lm = log_fd.metadata()?;
    ensure!(
        lm.dev() == 64512
            && lm.ino() == LOG_INODE
            && lm.is_file()
            && lm.nlink() == 1
            && lm.len() == 0
            && lm.mode() & 0o7777 == 0o600
            && matches!((lm.uid(), lm.gid()), (1001, 1003) | (0, 0))
            && same(
                &log,
                &Path::new("/proc/self/fd").join(log_fd.as_raw_fd().to_string())
            )?,
        "untrusted precreated observer log"
    );
    std::os::unix::fs::fchown(&log_fd, Some(0), Some(0))?;
    log_fd.sync_all()?;
    // Mount destinations exist before PID1 requests the readonly genesis and compact-index projections.
    for dir in [
        "output/compact-indexes".to_string(),
        format!("output/compact-indexes/{}", EPOCH - 1),
        format!("output/compact-indexes/{EPOCH}"),
    ] {
        let target = run().join(dir);
        if !target.try_exists()? {
            fs::create_dir(&target)?;
            fs::set_permissions(&target, fs::Permissions::from_mode(0o755))?;
            File::open(target.parent().unwrap())?.sync_all()?;
        }
        let m = fs::symlink_metadata(&target)?;
        ensure!(
            target.canonicalize()? == target && m.is_dir() && m.uid() == 0 && m.mode() & 0o022 == 0,
            "altered cache directory"
        );
    }
    for target in INDEXES
        .iter()
        .map(target_index)
        .chain(std::iter::once(run().join("output/genesis.tar.bz2")))
    {
        if !target.try_exists()? {
            let f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o444)
                .open(&target)?;
            f.set_permissions(fs::Permissions::from_mode(0o444))?;
            f.sync_all()?;
            File::open(target.parent().unwrap())?.sync_all()?;
        }
        let m = fs::symlink_metadata(&target)?;
        ensure!(
            target.canonicalize()? == target
                && m.is_file()
                && m.uid() == 0
                && m.nlink() == 1
                && m.len() == 0
                && m.mode() & 0o7777 == 0o444,
            "occupied bind target"
        );
    }
    ensure!(baseline == files()?, "source changed during preparation");
    for d in ["guard-receipts"] {
        let dir = base().join(d);
        if !dir.try_exists()? {
            fs::DirBuilder::new().create(&dir)?;
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
            File::open(base())?.sync_all()?;
        }
        let dm = dir.symlink_metadata()?;
        ensure!(
            dm.is_dir() && dm.uid() == 0 && dm.mode() & 0o077 == 0 && dir.canonicalize()? == dir,
            "unsafe guard receipts"
        );
    }
    let prepared = json!({"schema":format!("horizon-{EPOCH}-replay-recovery-preparation-v1"),"epoch":EPOCH,"baseline":baseline,
        "indexes":verified,"node_sha256":NODE_SHA,"worker_sha256":WORKER_SHA,"original_run_retained":true,"replay_launch_authorized":false});
    #[cfg(any(epoch166_retry11, epoch170_retry11, epoch170_retry12, epoch170_retry13))]
    let prepared = {
        let mut registered = prepared;
        registered["profile"] = registered["baseline"]["profile"].clone();
        registered
    };
    record("PREPARED.json", &prepared)
}

pub fn ready() -> Result<Value> {
    let (p, r) = doc(&base().join("PREPARED.json"), None)?;
    let m = run().join("producer.log").symlink_metadata()?;
    ensure!(
        p["baseline"] == files()?
            && m.dev() == 64512
            && m.ino() == LOG_INODE
            && m.uid() == 0
            && m.gid() == 0
            && m.mode() & 0o7777 == 0o600
            && m.len() == 0
            && fs::read_dir(run().join("private"))?.next().is_none(),
        "changed staged namespace or log"
    );
    for target in INDEXES
        .iter()
        .map(target_index)
        .chain(std::iter::once(run().join("output/genesis.tar.bz2")))
    {
        let m = target.symlink_metadata()?;
        ensure!(
            target.canonicalize()? == target
                && m.is_file()
                && m.uid() == 0
                && m.nlink() == 1
                && m.len() == 0
                && m.mode() & 0o7777 == 0o444,
            "changed staged mount target"
        );
    }
    Ok(r)
}

pub fn index_selected() -> Result<()> {
    let actor = native(UNIT)?;
    let pid = st(&actor, "MainPID")?.parse::<u64>()?;
    ensure!(pid > 1, "missing actual producer");
    let p = Path::new("/proc").join(pid.to_string());
    let mounts = fs::read_to_string(p.join("mountinfo"))?;
    #[cfg(any(epoch166_retry11, epoch170_retry11, epoch170_retry12, epoch170_retry13))]
    let extra = Some((retry11::bootstrap(), Path::new(INPUTS).join(BOOT)));
    #[cfg(not(any(epoch166_retry11, epoch170_retry11, epoch170_retry12, epoch170_retry13)))]
    let extra: Option<(PathBuf, PathBuf)> = None;
    for (src, target) in INDEXES
        .iter()
        .map(|i| (source_index(i), target_index(i)))
        .chain(std::iter::once((
            Path::new(INPUTS).join("genesis.tar.bz2"),
            run().join("output/genesis.tar.bz2"),
        )))
        .chain(extra)
    {
        let target_in_namespace = p.join("root").join(target.strip_prefix("/")?);
        ensure!(
            same(&src, &target_in_namespace)?
                && mounts.lines().any(|l| {
                    let a: Vec<_> = l.split_whitespace().take(6).collect();
                    a.len() == 6
                        && a[4] == target.to_str().unwrap_or_default()
                        && a[5].split(',').any(|x| x == "ro")
                }),
            "missing original read-only mount in source process: {}",
            target.display()
        );
    }
    ensure!(
        native(UNIT)?["InvocationID"] == actor["InvocationID"],
        "actor changed during projection check"
    );
    Ok(())
}

pub fn prepare_log() -> Result<Value> {
    let p = run().join("producer.log");
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&p)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file()
            && m.dev() == 64512
            && m.ino() == LOG_INODE
            && m.uid() == 0
            && m.gid() == 0
            && m.nlink() == 1
            && m.len() == 0
            && m.mode() & 0o7777 == 0o600
            && same(
                &p,
                &Path::new("/proc/self/fd").join(f.as_raw_fd().to_string())
            )?
            && native(UNIT)?["LoadState"] == "not-found"
            && members(UNIT)?.is_empty(),
        "observer log or cold owner changed"
    );
    let receipt = base().join("OBSERVER_LOG_PREPARED.json");
    let proof = json!({"schema":format!("horizon-{EPOCH}-root-owned-observer-log-v1"),"prepared":doc(&base().join("PREPARED.json"),None)?.1,
        "path":p,"device":m.dev(),"inode":m.ino(),"uid":m.uid(),"gid":m.gid(),"mode":m.mode()&0o7777,"nlink":m.nlink(),"size":m.len()});
    if receipt.try_exists()? {
        let (v, r) = doc(&receipt, None)?;
        ensure!(v == proof, "foreign observer log receipt");
        return Ok(r);
    }
    record("OBSERVER_LOG_PREPARED.json", &proof)
}
