// Compile the census against this retirement profile's exact paths and identity.
mod consumers {
    include!("holding_epoch166_retry6_consumers.rs");
}
pub(super) fn inspect_consumers(spec: &Bound) -> Result<()> {
    consumers::inspect(spec)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Retire {
    schema: String,
    mapping: Bound,
    eligibility: Bound,
    inspection: Bound,
    custody: Bound,
    park_terminal: Bound,
    consumer_closure: Bound,
    prior_check: Option<Bound>,
}
fn binding(path: &str, sha: &str) -> Bound {
    Bound {
        path: path.into(),
        sha256: sha.into(),
    }
}
fn same_bound(a: &Bound, b: &Bound) -> bool {
    a.path == b.path && a.sha256 == b.sha256
}
fn clock() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}
fn directory(path: &Path) -> Result<File> {
    use std::os::unix::ffi::OsStrExt;
    ensure!(path.is_absolute(), "epoch 166 directory must be absolute");
    let mut dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")?;
    for part in path.components() {
        match part {
            std::path::Component::RootDir => (),
            std::path::Component::Normal(name) => {
                let name = CString::new(name.as_bytes())?;
                let fd = unsafe {
                    libc::openat(
                        dir.as_raw_fd(),
                        name.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                ensure!(
                    fd >= 0,
                    "epoch 166 no-follow parent open failed: {}",
                    std::io::Error::last_os_error()
                );
                dir = unsafe { File::from_raw_fd(fd) };
            }
            _ => bail!("epoch 166 noncanonical parent component"),
        }
    }
    Ok(dir)
}
fn stable_directory(m: &fs::Metadata) -> Value {
    json!([m.dev(), m.ino(), m.uid(), m.gid(), m.mode()])
}
fn preserved_entry(path: &Path) -> Result<Value> {
    let md = fs::symlink_metadata(path)?;
    ensure!(
        md.dev() == 64512
            && md.uid() == 1001
            && md.gid() == 1003
            && md.mode() & 0o022 == 0
            && (md.is_dir() || md.is_file())
            && (md.is_dir() || md.nlink() == 1),
        "epoch 166 retained artifact changed"
    );
    Ok(json!([
        md.dev(),
        md.ino(),
        md.uid(),
        md.gid(),
        md.mode(),
        md.nlink(),
        md.len(),
        md.blocks(),
        md.mtime(),
        md.mtime_nsec(),
        md.ctime(),
        md.ctime_nsec()
    ]))
}
fn walk_inputs(path: &Path, out: &mut BTreeMap<String, Value>, depth: usize) -> Result<()> {
    ensure!(
        depth <= 32 && out.len() < 4096,
        "epoch 166 retained input census exceeded bound"
    );
    out.insert(path.to_string_lossy().into_owned(), preserved_entry(path)?);
    if fs::symlink_metadata(path)?.is_dir() {
        let _ = directory(path)?;
        for entry in fs::read_dir(path)? {
            walk_inputs(&entry?.path(), out, depth + 1)?;
        }
    }
    Ok(())
}
fn preserved() -> Result<Value> {
    let run = Path::new(RUN);
    let md = directory(run)?.metadata()?;
    ensure!(
        md.dev() == 64512 && md.ino() == RUN_INODE && md.uid() == 1001 && md.gid() == 1003,
        "epoch 166 run replaced"
    );
    let scratch = run.join("scratch");
    let sm = directory(&scratch)?.metadata()?;
    ensure!(
        sm.dev() == 64512 && sm.ino() == SCRATCH_INODE && sm.uid() == 1001 && sm.gid() == 1003,
        "epoch 166 retained scratch root replaced"
    );
    let state = run.join("cohort-state.json");
    let st = fs::symlink_metadata(&state)?;
    ensure!(
        st.ino() == STATE_INODE && st.len() == 222,
        "epoch 166 state changed"
    );
    let state_id = preserved_entry(&state)?;
    let bytes = read_stable_bounded(&state, 222, "epoch 166 retained state")?;
    ensure!(
        hex_lower(&Sha256::digest(&bytes)) == STATE_SHA,
        "epoch 166 cohort state digest changed"
    );
    let mut inputs = BTreeMap::new();
    walk_inputs(&run.join("inputs"), &mut inputs, 0)?;
    let ancestors: BTreeMap<_, _> = run
        .ancestors()
        .map(|path| {
            Ok((
                path.to_string_lossy().into_owned(),
                stable_directory(&directory(path)?.metadata()?),
            ))
        })
        .collect::<Result<_>>()?;
    let mut retained = json!({"run":preserved_entry(run)?,"scratch":preserved_entry(&scratch)?,"state":state_id,
        "state_sha256":STATE_SHA,"inputs":inputs,"ancestors":ancestors,
        "archives_directory":stable_directory(&directory(&run.join("archives"))?.metadata()?)});
    retain_profile_inputs(&mut retained)?;
    Ok(retained)
}
fn locks() -> Result<Vec<(PathBuf, File, Value)>> {
    [(MUTATION_LOCK, 101135013), (EPOCH_LOCK, EPOCH_LOCK_INODE)]
        .into_iter()
        .chain(SIBLING_LOCK)
        .map(|(path, inode)| {
            let path = PathBuf::from(path);
            let _parent = directory(path.parent().context("lock parent")?)?;
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&path)?;
            let md = file.metadata()?;
            ensure!(
                md.dev() == 64512
                    && md.ino() == inode
                    && md.uid() == 1001
                    && md.gid() == 1003
                    && md.is_file()
                    && md.nlink() == 1
                    && md.mode() & 0o7777 == 0o600,
                "epoch 166 exact existing lock changed"
            );
            let before = preserved_entry(&path)?;
            ensure!(
                unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
                "epoch 166 shared/epoch lock occupied"
            );
            Ok((path, file, before))
        })
        .collect()
}
fn check_locks(held: &[(PathBuf, File, Value)]) -> Result<()> {
    for (path, file, before) in held {
        ensure!(
            preserved_entry(path)? == *before
                && identity(&file.metadata()?) == regular_identity(path)?,
            "epoch 166 lock changed while held"
        );
    }
    Ok(())
}
fn source_identity(path: &Path) -> Result<FileIdentity> {
    let id = regular_identity(path)?;
    let md = fs::symlink_metadata(path)?;
    ensure!(
        id.device == 64512
            && id.inode == INODE
            && id.length == LENGTH
            && id.modified_seconds == MTIME_SEC
            && id.modified_nanoseconds == MTIME_NSEC
            && md.uid() == 1001
            && md.gid() == 1003
            && md.mode() & 0o7777 == 0o600
            && md.nlink() == 1
            && md.blocks().checked_mul(512) == Some(ALLOCATED),
        "epoch 166 exact partial identity changed"
    );
    Ok(id)
}
fn native(unit: &str) -> Result<Value> {
    let properties = "Id,LoadState,ActiveState,SubState,InvocationID,MainPID,ControlPID,ExecMainPID,ExecMainStartTimestamp,NRestarts,Job,Result,ExecMainStatus,Restart,TriggeredBy,ExecStart,FragmentPath,DropInPaths";
    let mut command = std::process::Command::new("/usr/bin/systemctl");
    command.args(["show", unit, "-p", properties]);
    if unit == super::epoch166_retry8_retire::PARK_UNIT
        || unit == super::epoch166_retry10_retire::PARK_UNIT
        || unit == super::epoch168_metered_retire::PARK
    {
        command.args(["-p", "Names,Transient,NeedDaemonReload,ControlGroup,ExecMainCode,ExecMainExitTimestamp,ExecMainStartTimestampMonotonic,ExecMainExitTimestampMonotonic"]);
    }
    native_fields(&mut command)
}
fn native_fields(command: &mut std::process::Command) -> Result<Value> {
    let out = command.output()?;
    ensure!(
        out.status.success() && out.stderr.is_empty() && out.stdout.len() <= 256 << 10,
        "epoch 166 native owner query failed"
    );
    let mut map = serde_json::Map::new();
    for line in std::str::from_utf8(&out.stdout)?.lines() {
        let (key, value) = line.split_once('=').context("epoch 166 native field")?;
        ensure!(
            map.insert(key.into(), json!(value)).is_none(),
            "duplicate native field"
        );
    }
    Ok(Value::Object(map))
}
fn closed(row: &Value, unit: &str) -> Result<()> {
    ensure!(
        row["Id"] == unit
            && row["ActiveState"] == "inactive"
            && row["SubState"] == "dead"
            && row["Job"] == ""
            && (row["MainPID"].is_null() || row["MainPID"] == "0")
            && (row["ControlPID"].is_null() || row["ControlPID"] == "0"),
        "epoch 166 owner active or queued: {unit}"
    );
    Ok(())
}
fn park_shape(row: &Value, iid: &str) -> Result<()> {
    ensure!(
        iid.len() == 32
            && iid
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "park invocation differs from genuine original start event"
    );
    ensure!(
        row["Id"] == PARK
            && row["InvocationID"] == iid
            && ((row["ActiveState"] == "inactive" && row["SubState"] == "dead")
                || (row["ActiveState"] == "active" && row["SubState"] == "exited"))
            && row["Result"] == "success"
            && row["ExecMainStatus"] == "0"
            && row["MainPID"] == "0"
            && row["ControlPID"] == "0"
            && row["Job"] == ""
            && row["Restart"] == "no"
            && row["TriggeredBy"] == "",
        "epoch 166 park is not the exact successful terminal invocation"
    );
    Ok(())
}
fn park(p: &Retire) -> Result<Value> {
    let proof = bound(&p.park_terminal)?;
    let iid = proof["invocation_id"]
        .as_str()
        .context("recorded park invocation")?;
    validate_transfer_provenance(&proof, iid)?;
    validate_terminal_custody(p, &proof)?;
    park_shape(&proof["native"], iid)?;
    let helper: Bound = serde_json::from_value(proof["helper"].clone())?;
    let md = fs::symlink_metadata(&helper.path)?;
    ensure!(
        md.is_file()
            && md.uid() == 0
            && md.mode() & 0o222 == 0
            && digest(&helper.sha256)
            && hex_lower(&Sha256::digest(read_stable_bounded(
                &helper.path,
                128 << 20,
                "park helper"
            )?)) == helper.sha256,
        "recorded park helper changed"
    );
    let argv = format!(
        "{} holding-park {PARK_PLAN} --spec-sha256 {PARK_PLAN_SHA} --self-sha256 {}",
        helper.path.display(),
        helper.sha256
    );
    let exec = proof["native"]["ExecStart"]
        .as_str()
        .context("park native command")?;
    ensure!(
        exec.contains(&format!("argv[]={argv} ;")) && exec.matches("argv[]=").count() == 1,
        "park command does not bind exact held source plan"
    );
    let row = native(PARK)?;
    park_shape(&row, iid)?;
    if row["ExecStart"] != proof["native"]["ExecStart"] {
        match PARK {
            super::epoch166_retry8_retire::PARK_UNIT => {
                super::epoch166_retry8_retire::validate_reloaded_park(
                    &proof["native"],
                    &row,
                    &helper,
                    &argv,
                )?;
            }
            super::epoch166_retry10_retire::PARK_UNIT => {
                super::epoch166_retry10_retire::validate_reloaded_park(
                    &proof["native"],
                    &row,
                    &helper,
                    &argv,
                )?;
            }
            super::epoch168_metered_retire::PARK => {
                super::epoch168_metered_retire::validate_reloaded_park(
                    &proof["native"],
                    &row,
                    &helper,
                    &argv,
                )?;
            }
            _ => bail!("park native command changed"),
        }
    }
    Ok(row)
}
fn scope(p: &Retire) -> Result<Value> {
    ensure!(
        p.schema == profile!(epoch "jetstreamer-horizon-holding-retire", "-plan-v1")
            && same_bound(&p.mapping, &binding(MAPPING, MAPPING_SHA))
            && same_bound(&p.eligibility, &binding(ELIGIBILITY, ELIGIBILITY_SHA))
            && p.inspection.sha256 == INSPECTION_SHA,
        "foreign epoch 166 partial retirement scope"
    );
    let plan = bound(&binding(PARK_PLAN, PARK_PLAN_SHA))?;
    let e = bound(&p.eligibility)?;
    let park_plan: Park = serde_json::from_value(plan)?;
    source_scope(&park_plan, &e)?;
    ensure!(
        park_plan.source == Path::new(SOURCE)
            && park_plan.sha256 == SHA
            && park_plan.length == LENGTH
            && same_bound(&park_plan.mapping, &p.mapping)
            && same_bound(&park_plan.eligibility, &p.eligibility),
        "epoch 166 park/eligibility binding differs"
    );
    let inspected = bound(&p.inspection)?;
    validate_inspection(&inspected, &e)?;
    // That historical false is preserved. The distinct fresh consumer graph below
    // must supply the missing authority; it is never inferred from this inspection.
    Ok(inspected)
}
fn exact_custody(c: &Value, p: &Retire) -> Result<()> {
    ensure!(
        c["source"] == SOURCE
            && c["sha256"] == SHA
            && c["length"] == LENGTH
            && c["eligibility"] == serde_json::to_value(&p.eligibility)?
            && c["mapping"] == serde_json::to_value(&p.mapping)?
            && c["manifest"]["uid"] == 1001
            && c["manifest"]["gid"] == 1003
            && c["manifest"]["mode"] == 0o600,
        "epoch 166 custody does not bind exact inspected partial"
    );
    Ok(())
}
async fn remote(client: &Client, m: &Mapping, c: &Value, p: &Retire) -> Result<RemoteArchive> {
    let (key, etag, sha, length) = custody(c, m)?;
    exact_custody(c, p)?;
    let owner = owner_bytes(m)?;
    ensure!(
        get_mutable_object(client, BUCKET, &format!("{}owner.json", m.prefix))
            .await?
            .is_some_and(|o| o.bytes == owner),
        "epoch 166 holding owner differs"
    );
    let manifest = get_mutable_object(
        client,
        BUCKET,
        c["manifest_key"].as_str().context("manifest key")?,
    )
    .await?
    .context("held manifest absent")?;
    ensure!(
        hex_lower(&Sha256::digest(&manifest.bytes)) == c["manifest_sha256"]
            && serde_json::from_slice::<Value>(&manifest.bytes)? == c["manifest"],
        "epoch 166 held manifest changed"
    );
    let blob = head_archive(client, BUCKET, &key)
        .await?
        .context("epoch 166 held object absent")?;
    remote_matches(&blob, &key, length, &sha, Some(&etag))?;
    Ok(blob)
}
fn closure(p: &Retire, current: Option<&Path>) -> Result<Value> {
    let units = [
        PRODUCER.to_owned(),
        format!("{GUARD}.service"),
        format!("{GUARD}.timer"),
    ];
    let mut owners = BTreeMap::new();
    for unit in units {
        let row = native(&unit)?;
        closed(&row, &unit)?;
        owners.insert(unit, row);
    }
    let park = park(p)?;
    let process = no_references(Path::new(RUN))?;
    let current_process = current.map(no_references).transpose()?;
    let graph = consumers::verify(p)?;
    for (unit, before) in &owners {
        ensure!(
            native(unit)? == *before,
            "epoch 166 owner changed across consumer closure"
        );
    }
    ensure!(
        self::park(p)? == park,
        "epoch 166 park changed across closure"
    );
    Ok(
        json!({"owners":owners,"park":park,"process":process,"transition_process":current_process,
        "consumer_closure":p.consumer_closure,"transitive_graph":graph}),
    )
}
fn record(path: &Path) -> Result<Option<Value>> {
    if !exists(path)? {
        return Ok(None);
    }
    let md = fs::symlink_metadata(path)?;
    ensure!(
        md.is_file()
            && md.uid() == 0
            && md.nlink() == 1
            && md.mode() & 0o222 == 0
            && md.len() <= 1 << 20,
        "unsafe epoch 166 transition record"
    );
    let bytes = read_stable_bounded(path, 1 << 20, "epoch 166 transition")?;
    Ok(Some(serde_json::from_slice(&bytes)?))
}
fn transition_shape(
    intent: bool,
    moved: bool,
    unlink: bool,
    complete: bool,
    source: bool,
    quarantine: bool,
) -> Result<()> {
    ensure!(!moved || intent, "epoch 166 moved without intent");
    ensure!(!unlink || moved, "epoch 166 unlink without moved proof");
    ensure!(
        !complete || unlink,
        "epoch 166 complete without unlink intent"
    );
    ensure!(!(source && quarantine), "epoch 166 duplicate local source");
    ensure!(!quarantine || intent, "epoch 166 quarantine without intent");
    ensure!(
        !moved || !source,
        "epoch 166 moved proof conflicts with source"
    );
    ensure!(
        source || quarantine || unlink,
        "epoch 166 local absence without durable unlink intent"
    );
    ensure!(
        !complete || (!source && !quarantine),
        "epoch 166 source reappeared after completion"
    );
    Ok(())
}
fn parallel_hash(path: &Path, expected: FileIdentity, part_size: u64) -> Result<LocalProof> {
    ensure!(
        part_size > 0 && part_size <= DEFAULT_PART_SIZE,
        "invalid bounded hash part size"
    );
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    ensure!(
        identity(&file.metadata()?) == expected,
        "archive changed before hashing"
    );
    let mut whole = Sha256::new();
    let mut combined_md5 = Md5::new();
    let mut combined_sha256 = Sha256::new();
    let mut remaining = expected.length;
    let mut parts = 0u64;
    let mut buffer = vec![0u8; usize::try_from(part_size.min(remaining))?];
    while remaining > 0 {
        let count = usize::try_from(remaining.min(part_size))?;
        file.read_exact(&mut buffer[..count])?;
        let bytes = &buffer[..count];
        let (md5, sha256) = std::thread::scope(|scope| -> Result<_> {
            let whole_worker = scope.spawn(|| whole.update(bytes));
            let md5_worker = scope.spawn(|| Md5::digest(bytes));
            let part_sha256 = Sha256::digest(bytes);
            whole_worker
                .join()
                .map_err(|_| anyhow::anyhow!("whole-file hasher panicked"))?;
            let part_md5 = md5_worker
                .join()
                .map_err(|_| anyhow::anyhow!("part MD5 hasher panicked"))?;
            Ok((part_md5, part_sha256))
        })?;
        combined_md5.update(md5);
        combined_sha256.update(sha256);
        parts += 1;
        remaining -= count as u64;
    }
    ensure!(
        identity(&file.metadata()?) == expected,
        "archive changed while hashing"
    );
    ensure!(
        regular_identity(path)? == expected,
        "archive namespace changed while hashing"
    );
    Ok(LocalProof {
        sha256_hex: format!("{:x}", whole.finalize()),
        multipart_etag: format!("{:x}-{parts}", combined_md5.finalize()),
        composite_sha256: BASE64_STANDARD.encode(combined_sha256.finalize()),
    })
}

fn move_exact(source: &Path, quarantine: &Path) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let from = directory(source.parent().context("source parent")?)?;
    let to = directory(quarantine.parent().context("quarantine parent")?)?;
    let a = CString::new(source.file_name().context("source name")?.as_bytes())?;
    let b = CString::new(
        quarantine
            .file_name()
            .context("quarantine name")?
            .as_bytes(),
    )?;
    source_identity(source)?;
    ensure!(
        unsafe {
            libc::renameat2(
                from.as_raw_fd(),
                a.as_ptr(),
                to.as_raw_fd(),
                b.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        } == 0,
        "epoch 166 no-clobber quarantine move failed: {}",
        std::io::Error::last_os_error()
    );
    from.sync_all()?;
    to.sync_all()?;
    source_identity(quarantine)?;
    Ok(())
}
fn unlink_exact(path: &Path, expected: FileIdentity) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;
    ensure!(
        path == Path::new(QUARANTINE) && source_identity(path)? == expected,
        "foreign epoch 166 unlink target"
    );
    let parent = directory(path.parent().context("quarantine parent")?)?;
    let name = CString::new(path.file_name().context("quarantine name")?.as_bytes())?;
    ensure!(
        unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) } == 0,
        "epoch 166 unlink failed: {}",
        std::io::Error::last_os_error()
    );
    parent.sync_all()?;
    Ok(())
}

pub(super) async fn run(
    client: &Client,
    m: &Mapping,
    p: &Retire,
    spec: &Bound,
    check: bool,
) -> Result<()> {
    ensure!(
        fs::read_link("/proc/self/exe")?.parent() == Some(Path::new(LIFECYCLE))
            && evidence_bundle_path(&p.consumer_closure.path)
            && evidence_bundle_path(&spec.path),
        "epoch 166 requires its sealed runtime and separate versioned evidence bundles"
    );
    scope(p)?;
    if PARK == super::epoch166_retry8_retire::PARK_UNIT
        || PARK == super::epoch166_retry10_retire::PARK_UNIT
        || PARK == super::epoch168_metered_retire::PARK
    {
        // Check the recorded native dispatch before spending a full archive hash.
        // The normal closure still repeats this check before and after its census.
        park(p)?;
    }
    let held = locks()?;
    let supplied: Mapping = serde_json::from_value(bound(&p.mapping)?)?;
    mapping(&supplied)?;
    ensure!(
        supplied.host == m.host && supplied.prefix == m.prefix,
        "epoch 166 holding mapping changed"
    );
    let c = bound(&p.custody)?;
    remote(client, m, &c, p).await?;
    let root = Path::new(STATE).join("retirements");
    private(&root)?;
    let source = Path::new(SOURCE);
    let quarantine = Path::new(QUARANTINE);
    let intent_path = root.join(profile!(epoch "epoch", "-intent.json"));
    let moved_path = root.join(profile!(epoch "epoch", "-moved.json"));
    let unlink_path = root.join(profile!(epoch "epoch", "-unlink-intent.json"));
    let completion_path = root.join(profile!(epoch "epoch", "-completion.json"));
    let retained = preserved()?;
    // A fresh consumer closure may change after interruption, but the exact
    // original held bytes, park invocation, custody and preserved run may not.
    let descriptor = json!({"schema":profile!(epoch "jetstreamer-holding-retire", "-intent-v1"),
        "source":SOURCE,"quarantine":QUARANTINE,"sha256":SHA,"length":LENGTH,"inode":INODE,
        "eligibility":p.eligibility,"inspection":p.inspection,"custody":p.custody,"mapping":p.mapping,
        "park_terminal":p.park_terminal,"preserved":retained,
        "canonical_archive":false,"scratch_retirement_authorized":false,"resource_credit_bytes":0,
        "resource_promise_ending_authorized":false,"replay_launch_authorized":false,
        "remote_mutations":false,"r2_mutations":false});
    let expected_moved = json!({"schema":profile!(epoch "jetstreamer-holding-retire", "-moved-v1"),"intent":descriptor,
        "local_sha256":SHA,"local_multipart_etag":c["object_etag"]});
    let expected_unlink = json!({"schema":profile!(epoch "jetstreamer-holding-retire", "-unlink-intent-v1"),
        "moved":expected_moved,"authenticated_custody_revalidated":true});
    let expected_completion = json!({"schema":profile!(epoch "jetstreamer-holding-retire", "-completion-v1"),
        "intent":descriptor,"source_absent":true,"quarantine_absent":true,"preserved":retained,
        "retired_censused_physical_bytes":ALLOCATED,"actual_free_delta_claimed":false,
        "authenticated_custody_revalidated":true,"scratch_retirement_authorized":false,
        "resource_credit_bytes":0,"resource_promise_ending_authorized":false,"replay_launch_authorized":false,
        "remote_mutations":false,"r2_mutations":false});
    let old_intent = record(&intent_path)?;
    let old_moved = record(&moved_path)?;
    let old_unlink = record(&unlink_path)?;
    let old_completion = record(&completion_path)?;
    for (old, want) in [
        (&old_intent, &descriptor),
        (&old_moved, &expected_moved),
        (&old_unlink, &expected_unlink),
        (&old_completion, &expected_completion),
    ] {
        ensure!(
            old.as_ref().is_none_or(|v| v == want),
            "epoch 166 immutable transition proof differs"
        );
    }
    let has_source = exists(source)?;
    let has_quarantine = exists(quarantine)?;
    transition_shape(
        old_intent.is_some(),
        old_moved.is_some(),
        old_unlink.is_some(),
        old_completion.is_some(),
        has_source,
        has_quarantine,
    )?;
    let current = if has_source {
        Some(source)
    } else if has_quarantine {
        Some(quarantine)
    } else {
        None
    };
    if old_completion.is_some() {
        closure(p, None)?;
        check_locks(&held)?;
        println!("{}", completion_path.display());
        return Ok(());
    }
    let local_proof = if let Some(path) = current {
        let id = source_identity(path)?;
        let proof = parallel_hash(path, id, DEFAULT_PART_SIZE)?;
        ensure!(
            proof.sha256_hex == SHA && proof.multipart_etag == c["object_etag"],
            "epoch 166 source differs from authenticated holding custody"
        );
        Some(json!({"identity":id,"sha256":proof.sha256_hex,"multipart_etag":proof.multipart_etag}))
    } else {
        None
    };
    let gate = closure(p, current)?;
    remote(client, m, &c, p).await?;
    ensure!(
        preserved()? == retained,
        "epoch 166 preserved artifacts changed during hash/closure"
    );
    check_locks(&held)?;
    let attempt = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let check_path = Path::new(STATE).join("receipts").join(format!(
        "{}-{}-{attempt}.json",
        profile!(epoch "retire", "-check"),
        spec.sha256
    ));
    if check {
        ensure!(
            p.prior_check.is_none(),
            "epoch 166 check cannot borrow another check"
        );
        persist(
            &check_path,
            &json!({"schema":profile!(epoch "jetstreamer-holding-retire", "-check-v1"),
            "descriptor":descriptor,"checked":true,"data_removed":false,"local_proof":local_proof,
            "recovering_after_durable_unlink":current.is_none()&&old_unlink.is_some(),
            "consumer_closure":p.consumer_closure,"gates":gate,"recorded_unix_seconds":clock()?}),
        )?;
        println!("{}", check_path.display());
        return Ok(());
    }
    let prior_binding = p
        .prior_check
        .as_ref()
        .context("epoch 166 execution requires sealed successful check")?;
    let prior = bound(prior_binding)?;
    let at = clock()?;
    ensure!(
        prior["schema"] == profile!(epoch "jetstreamer-holding-retire", "-check-v1")
            && prior["descriptor"] == descriptor
            && prior["checked"] == true
            && prior["data_removed"] == false
            && prior["recorded_unix_seconds"]
                .as_u64()
                .is_some_and(|t| t <= at && at - t <= 900),
        "epoch 166 check stale or foreign"
    );
    // Refresh before each mutation and retain a hash-bound record of the actual
    // graph/closure used, independently of the stable interruption descriptor.
    let qualification_path = root.join(format!(
        "{}-{}-{attempt}.json",
        profile!(epoch "epoch", "-qualified"),
        spec.sha256
    ));
    persist(
        &qualification_path,
        &json!({"schema":profile!(epoch "jetstreamer-holding-retire", "-qualified-v1"),
        "spec":spec,"check":prior_binding,"descriptor":descriptor,"consumer_closure":p.consumer_closure,"gates":gate}),
    )?;
    if old_intent.is_none() {
        persist(&intent_path, &descriptor)?;
    }
    if current == Some(source) {
        closure(p, Some(source))?;
        remote(client, m, &c, p).await?;
        check_locks(&held)?;
        ensure!(
            preserved()? == retained,
            "epoch 166 retained data changed before move"
        );
        move_exact(source, quarantine)?;
        ensure!(
            preserved()? == retained,
            "epoch 166 retained data changed after move"
        );
    }
    if exists(quarantine)? {
        let id = source_identity(quarantine)?;
        let proof = parallel_hash(quarantine, id, DEFAULT_PART_SIZE)?;
        ensure!(
            proof.sha256_hex == SHA && proof.multipart_etag == c["object_etag"],
            "epoch 166 quarantined bytes differ"
        );
        if old_moved.is_none() {
            persist(&moved_path, &expected_moved)?;
        }
        closure(p, Some(quarantine))?;
        remote(client, m, &c, p).await?;
        check_locks(&held)?;
        if old_unlink.is_none() {
            persist(&unlink_path, &expected_unlink)?;
        }
        ensure!(
            !exists(source)? && source_identity(quarantine)? == id,
            "epoch 166 source reappeared or quarantine replaced"
        );
        ensure!(
            preserved()? == retained,
            "epoch 166 retained data changed before unlink"
        );
        unlink_exact(quarantine, id)?;
    }
    ensure!(
        !exists(source)? && !exists(quarantine)?,
        "epoch 166 partial remains"
    );
    ensure!(
        preserved()? == retained,
        "epoch 166 retained run changed after unlink"
    );
    closure(p, None)?;
    remote(client, m, &c, p).await?;
    check_locks(&held)?;
    persist(&completion_path, &expected_completion)?;
    println!("{}", completion_path.display());
    Ok(())
}

fn evidence_bundle_path(path: &Path) -> bool {
    path.parent().is_some_and(|bundle| {
        bundle.parent() == Some(Path::new(EVIDENCE_ROOT))
            && bundle
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|name| {
                    !name.is_empty()
                        && name.len() <= 128
                        && name
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
                })
    }) && path.extension().is_some_and(|s| s == "json")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn evidence_versions_are_separate_from_the_already_sealed_runtime() {
        for version in ["check-v1", "execute-v1", "renewed-closure-v2"] {
            assert!(evidence_bundle_path(
                &Path::new(EVIDENCE_ROOT).join(version).join("plan.json")
            ));
        }
        for path in [
            Path::new(LIFECYCLE).join("plan.json"),
            Path::new(EVIDENCE_ROOT).join("plan.json"),
            Path::new(EVIDENCE_ROOT).join("version/nested/plan.json"),
            Path::new(EVIDENCE_ROOT).join("../plan.json"),
            Path::new(EVIDENCE_ROOT).join("version/tool.sh"),
        ] {
            assert!(!evidence_bundle_path(&path));
        }
    }
    #[test]
    fn transitions_recover_only_durable_move_and_unlink_windows() {
        for row in [
            (false, false, false, false, true, false),
            (true, false, false, false, true, false),
            (true, false, false, false, false, true),
            (true, true, false, false, false, true),
            (true, true, true, false, false, true),
            (true, true, true, false, false, false),
            (true, true, true, true, false, false),
        ] {
            transition_shape(row.0, row.1, row.2, row.3, row.4, row.5).unwrap();
        }
        for row in [
            (false, false, false, false, false, true),
            (false, true, false, false, false, true),
            (true, false, true, false, false, false),
            (true, true, false, false, false, false),
            (true, true, true, true, true, false),
            (true, true, false, false, true, true),
        ] {
            assert!(transition_shape(row.0, row.1, row.2, row.3, row.4, row.5).is_err());
        }
    }
    #[test]
    fn park_gate_rejects_running_restarted_failed_and_foreign_invocations() {
        let iid = "c".repeat(32);
        let iid = iid.as_str();
        let good = json!({"Id":PARK,"InvocationID":iid,"ActiveState":"active","SubState":"exited",
            "Result":"success","ExecMainStatus":"0","MainPID":"0","ControlPID":"0","Job":"","Restart":"no","TriggeredBy":""});
        park_shape(&good, iid).unwrap();
        for (key, value) in [
            ("InvocationID", json!("b".repeat(32))),
            ("SubState", json!("running")),
            ("MainPID", json!("1")),
            ("Job", json!("1/start")),
            ("Result", json!("exit-code")),
            ("Restart", json!("always")),
        ] {
            let mut changed = good.clone();
            changed[key] = value;
            assert!(park_shape(&changed, iid).is_err());
        }
        assert!(park_shape(&good, &"a".repeat(32)).is_err());
    }
    #[test]
    fn inherited_parallel_proof_matches_serial_and_rejects_replaced_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("input");
        for length in [1, 63, 64, 65, 65537] {
            fs::write(
                &path,
                (0..length).map(|i| (i % 251) as u8).collect::<Vec<_>>(),
            )
            .unwrap();
            let id = regular_identity(&path).unwrap();
            for size in [63, 64, 65536, DEFAULT_PART_SIZE] {
                let a = hash_and_etag(&path, id, size).unwrap();
                let b = parallel_hash(&path, id, size).unwrap();
                assert_eq!(a.sha256_hex, b.sha256_hex);
                assert_eq!(a.multipart_etag, b.multipart_etag);
                assert_eq!(a.composite_sha256, b.composite_sha256);
            }
        }
        let id = regular_identity(&path).unwrap();
        fs::write(&path, b"changed").unwrap();
        assert!(parallel_hash(&path, id, 64).is_err());
    }
    #[test]
    fn custody_cannot_borrow_another_retry_or_use_unqualified_remote_bytes() {
        let p = Retire {
            schema: profile!(epoch "jetstreamer-horizon-holding-retire", "-plan-v1").into(),
            mapping: binding(MAPPING, MAPPING_SHA),
            eligibility: binding(ELIGIBILITY, ELIGIBILITY_SHA),
            inspection: binding("/sealed/inspection.json", INSPECTION_SHA),
            custody: binding("/sealed/custody.json", &"a".repeat(64)),
            park_terminal: binding("/sealed/terminal.json", &"b".repeat(64)),
            consumer_closure: binding("/sealed/closure.json", &"c".repeat(64)),
            prior_check: None,
        };
        let c = json!({"source":SOURCE,"sha256":SHA,"length":LENGTH,"eligibility":p.eligibility,"mapping":p.mapping,
            "manifest":{"uid":1001,"gid":1003,"mode":0o600}});
        exact_custody(&c, &p).unwrap();
        for (key, value) in [
            ("source", json!(format!("{SOURCE}.foreign"))),
            ("sha256", json!("d".repeat(64))),
            ("length", json!(LENGTH + 1)),
            ("manifest", json!({"uid":1001,"gid":1003,"mode":0o100600})),
        ] {
            let mut changed = c.clone();
            changed[key] = value;
            assert!(exact_custody(&changed, &p).is_err());
        }
        let m = Mapping {
            schema: "jetstreamer-horizon-host-holding-prefix-v2".into(),
            host: HOST.into(),
            prefix: "node_02/".into(),
            user_provided_prefix: true,
            authorization_reference: "test fixture".into(),
        };
        assert!(custody(&c, &m).is_err()); // Exact local fields never substitute for full readback custody.
    }
}
