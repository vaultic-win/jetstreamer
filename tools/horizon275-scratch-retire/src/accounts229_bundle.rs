//! Retire the closed epoch 229 compressed bundle after authenticated restoration.
use super::{
    appendvec288::lock_issuer, selective_accounts::record, snapshot288::lookup_receipt, *,
};
use std::{ffi::CString, os::unix::ffi::OsStrExt, time::SystemTime};

const STATE: &str = "/var/lib/jetstreamer/horizon229-holding-custody-v1";
const TRANSITION: &str =
    "/var/lib/jetstreamer/horizon-foundation-closed-private-holding-v1/transition.lock";
const SOURCE: &str =
    "/var/lib/jetstreamer/horizon229-v1-accounts-custody-v1/epoch-229-closed-accounts.pax.zst";
const CLEAR_SHA: &str = "67787eef74f004504b443892637f9d30ace339e344b41793de88a364e6fb1de5";
const TERMINAL_SHA: &str = "c21a6ba72c6f21137d3c42de9702b56c1697effd14951b0bd5885bc2d44fa291";
const CUSTODY_SHA: &str = "75b31d10298cfbee7181ac46e341b6e0807a1ff3882e10112a978ea45661de1e";
const PARK_UNIT: &str = "foundation-229-holding-custody-v1.service";
const STAGE_UNIT: &str = "foundation-229-closed-accounts-stage-v1.service";

fn private_dir(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        path.canonicalize()? == path
            && identity(&metadata) == identity(&path.symlink_metadata()?)
            && metadata.uid() == 0
            && metadata.gid() == 0
            && metadata.mode() & 0o7777 == 0o700,
        "unsafe epoch 229 private directory"
    );
    Ok(file)
}

fn terminal_evidence(state: &Path) -> Result<(Binding, Value)> {
    let path = state.join("park-attempt-v2-terminal.json");
    let terminal: Value = read_bound(&path, TERMINAL_SHA, JSON_LIMIT)?;
    let custody = value(&terminal["custody"])?;
    ensure!(
        terminal["unit"] == PARK_UNIT
            && terminal["status"]["ActiveState"] == "inactive"
            && terminal["status"]["MainPID"] == "0"
            && terminal["verified_custody"] == true
            && terminal["custody"]["sha256"] == CUSTODY_SHA
            && custody["source"] == SOURCE
            && custody["manifest"]["clear_bundle_sha256"] == CLEAR_SHA
            && custody["remote_sha256_readback"] == true
            && custody["remote_authenticated_decryption_verified"] == true
            && custody["restored_bundle_reread_verified"] == true
            && custody["publication_authorized"] == false,
        "missing exact epoch 229 authenticated restoration evidence"
    );
    Ok((
        Binding {
            path,
            sha256: TERMINAL_SHA.into(),
        },
        custody,
    ))
}

fn fresh_recheck(
    state: &Path,
    recheck: &Binding,
    terminal: &Binding,
    custody: &Value,
) -> Result<u64> {
    ensure!(
        recheck.path.parent() == Some(state)
            && recheck
                .path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(
                    |name| name.starts_with("park-remote-recheck-") && name.ends_with(".json")
                ),
        "foreign epoch 229 remote check path"
    );
    let wrapper: Value = read_bound(&recheck.path, &recheck.sha256, JSON_LIMIT)?;
    let proof = &wrapper["native_readback"];
    ensure!(
        wrapper["terminal"] == json!(terminal)
            && proof["schema"] == "foundation-epoch229-encrypted-accounts-recheck-v1"
            && proof["authenticated_manifest_and_object_match"] == true
            && proof["custody"]["sha256"] == CUSTODY_SHA
            && proof["source_identity"] == custody["original_identity"]
            && proof["manifest"] == custody["manifest"]
            && proof["manifest_sha256"] == custody["manifest_sha256"]
            && proof["manifest_key"] == custody["manifest_key"]
            && proof["remote_mutations"] == false
            && proof["publication_authorized"] == false,
        "authenticated remote check differs from epoch 229 custody"
    );
    let sampled = proof["recorded_unix_seconds"]
        .as_u64()
        .context("missing remote check time")?;
    ensure!(
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_secs()
            .checked_sub(sampled)
            .is_some_and(|age| age < 1800),
        "refresh the authenticated epoch 229 remote identity"
    );
    Ok(sampled)
}

fn local_stamp(metadata: &Metadata) -> Value {
    let nanos = |seconds, fractional| i128::from(seconds) * 1_000_000_000 + i128::from(fractional);
    json!({"device":metadata.dev(),"inode":metadata.ino(),"length":metadata.len(),
        "uid":metadata.uid(),"gid":metadata.gid(),"mode":metadata.mode() & 0o7777,
        "links":metadata.nlink(),"mtime_ns":nanos(metadata.mtime(),metadata.mtime_nsec()),
        "ctime_ns":nanos(metadata.ctime(),metadata.ctime_nsec())})
}

fn readers(scope: &Path, source: &Path) -> Result<Value> {
    terminal_unit(STAGE_UNIT)?;
    terminal_unit(PARK_UNIT)?;
    let scheduled = scheduled_census(scope, source)?;
    ensure!(
        scheduled["remaining"] == json!([]),
        "epoch 229 has scheduled readers: {}",
        scheduled["remaining"]
    );
    let scan = process_references::scan(Path::new("/proc"), source)?;
    ensure!(
        scan.inspected_processes > 0 && scan.references.is_empty(),
        "epoch 229 bundle has a live reader"
    );
    Ok(json!({"scheduled":scheduled,"processes":scan}))
}

fn preserved_key(state: &Path) -> Result<()> {
    let path = state.join("accounts-custody.key");
    let key = path.symlink_metadata()?;
    ensure!(
        key.is_file()
            && key.ino() == 104_624_077
            && key.len() == 65
            && key.uid() == 0
            && key.gid() == 0
            && key.nlink() == 1
            && key.mode() & 0o7777 == 0o400,
        "epoch 229 custody key identity changed"
    );
    Ok(())
}

pub(super) fn run(apply: bool, recheck: Binding) -> Result<()> {
    let _issuer = lock_issuer()?;
    let _cycle = lock(CYCLE_LOCK)?;
    let _local = lock(LOCAL_LOCK)?;
    let _holding = lock(TRANSITION)?;
    let state = Path::new(STATE);
    private_dir(state)?;
    let source = Path::new(SOURCE);
    let scope = source.parent().context("missing bundle parent")?;
    let dir = private_dir(scope)?;
    let (terminal, custody) = terminal_evidence(state)?;
    preserved_key(state)?;
    let anchor = json!({"terminal":terminal,"custody_sha256":CUSTODY_SHA,
        "source":SOURCE,"source_identity":custody["original_identity"],"sha256":CLEAR_SHA});
    let intent_path = state.join("bundle-retirement-intent.json");
    let completion_path = state.join("bundle-retirement-completion.json");
    let pending = lookup_receipt(&intent_path)?;
    if let Some((_, intent)) = &pending {
        ensure!(
            intent["evidence"] == anchor,
            "foreign epoch 229 retirement intent"
        );
    }
    let present = match source.symlink_metadata() {
        Ok(_) => true,
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => return Err(error.into()),
    };
    if let Some((reference, done)) = lookup_receipt(&completion_path)? {
        ensure!(
            pending.is_some() && !present && done["evidence"] == anchor,
            "epoch 229 completion conflicts with local state"
        );
        println!("{}", serde_json::to_string(&reference)?);
        return Ok(());
    }
    let before = available(scope)?;
    let (intent, removed) = if present {
        let first_scan = readers(scope, source)?;
        fresh_recheck(state, &recheck, &terminal, &custody)?;
        let mut file = open_regular(source)?;
        let info = file.metadata()?;
        ensure!(
            local_stamp(&info) == anchor["source_identity"] && digest(&mut file)? == CLEAR_SHA,
            "local epoch 229 bundle differs from authenticated custody"
        );
        let second_scan = readers(scope, source)?;
        fresh_recheck(state, &recheck, &terminal, &custody)?;
        ensure!(
            identity(&dir.metadata()?) == identity(&scope.symlink_metadata()?)
                && local_stamp(&file.metadata()?) == anchor["source_identity"]
                && local_stamp(&source.symlink_metadata()?) == anchor["source_identity"],
            "epoch 229 namespace changed during verification"
        );
        let blocks = info
            .blocks()
            .checked_mul(512)
            .context("allocation overflow")?;
        if !apply {
            ensure!(pending.is_none(), "epoch 229 retirement already started");
            println!(
                "{}",
                json!({"evidence":anchor,"recheck":recheck,"readers":second_scan,
                "allocated_bytes":blocks,"check_only":true,"retirement_performed":false})
            );
            return Ok(());
        }
        let intent = match pending {
            Some((binding, previous)) => {
                ensure!(
                    previous["allocated_bytes"] == blocks,
                    "source allocation changed"
                );
                binding
            }
            None => record(
                &intent_path,
                &json!({"evidence":anchor,"recheck":recheck,
                "before_hash_readers":first_scan,"after_hash_readers":second_scan,
                "allocated_bytes":blocks,"free_before_bytes":before}),
            )?,
        };
        let name = CString::new(
            source
                .file_name()
                .context("missing bundle name")?
                .as_bytes(),
        )?;
        ensure!(
            local_stamp(&source.symlink_metadata()?) == anchor["source_identity"]
                && local_stamp(&file.metadata()?) == anchor["source_identity"],
            "epoch 229 bundle changed before unlink"
        );
        if unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) } != 0 {
            return Err(io::Error::last_os_error()).context("unlink exact epoch 229 local bundle");
        }
        dir.sync_all()?;
        ensure!(
            file.metadata()?.nlink() == 0,
            "retired epoch 229 inode retains a link"
        );
        drop(file);
        (intent, blocks)
    } else {
        ensure!(apply, "epoch 229 source is absent");
        let (intent, previous) = pending.context("epoch 229 source absent without an intent")?;
        dir.sync_all()?;
        let blocks = previous["allocated_bytes"]
            .as_u64()
            .context("missing retired allocation")?;
        (intent, blocks)
    };
    ensure!(
        matches!(source.symlink_metadata(), Err(error) if error.kind() == io::ErrorKind::NotFound),
        "epoch 229 source still present after retirement"
    );
    preserved_key(state)?;
    let done = record(
        &completion_path,
        &json!({
            "schema":"foundation-epoch229-local-bundle-retirement-v1","epoch":229,
            "evidence":anchor,"intent":intent,"source_absent":true,
            "allocated_bytes_removed":removed,"free_at_attempt_start_bytes":before,
            "free_after_bytes":available(scope)?,"r2_mutations":false,"publication_authorized":false
        }),
    )?;
    println!("{}", serde_json::to_string(&done)?);
    Ok(())
}
