//! Retire the exact closed epoch 296 diagnostic after authenticated R2 custody.
use super::{
    appendvec288::lock_issuer, selective_accounts::record, snapshot288::lookup_receipt, *,
};
use std::{
    collections::BTreeMap,
    ffi::CString,
    os::unix::ffi::OsStrExt,
    time::{SystemTime, UNIX_EPOCH},
};

const ROOT: &str = "/var/lib/jetstreamer/horizon296-closed-first-retry-custody-v1";
const HOLDING: &str = "/var/lib/jetstreamer/horizon-foundation-closed-private-holding-v1";
const SCOPE: &str = "/home/ubuntu/.jetstreamer-private/qualification-296-full-retry-v1";
const CLOSED_SHA: &str = "0066541f0c6112951ffe8b5eb24c3b3da136d2ecb2806edd1b962179321cbb80";
const CLEAR_SHA: &str = "1efb77f6f812d345d1dde5dd5201a1088d4db178f61a30979a3c8659db424e2d";
const CENSUS_SHA: &str = "eafcc12fd9a44fd20de873517cb3b27078378bc4e07d929aaa95f1a985eeec2d";
const CUSTODY_SHA: &str = "0d1174f7260693daa0712a9806569a818e3f725de6486d3d31b5d745972205be";
const PARK_UNIT: &str = "foundation-296-closed-retry-custody-v1.service";
const FREEZE: &str = "[Unit]\nRefuseManualStart=yes\nConditionPathExists=!/var/lib/jetstreamer/horizon-foundation-closed-private-holding-v1/receipts/failed296-custody-8be4b0651537f67c86af335852972c03150535b88164b5fb9855cdcd8e3212c4.json\n";
const PRODUCER: &str = "horizon-qualify-296-full-retry-v1.service";
const GUARD: &str = "horizon-296-full-retry-protective-v1.service";
const TIMER: &str = "horizon-296-full-retry-protective-v1.timer";
const RECIPES: [(&str, &str); 3] = [
    (
        PRODUCER,
        "fbea96481ed9a45aa4df92aed7f78812fe6c7d74835da5518de7f46a331e411d",
    ),
    (
        GUARD,
        "b406f3b68e36ebb4643cf2b41c583322159ba8b2eba78fad19be7831710c922a",
    ),
    (
        TIMER,
        "6b8bd8f418ddf3f5314cabc294dbf9a5e7aa1e27347eede562cf0eb85dc47d6f",
    ),
];

fn file_stamp(m: &Metadata) -> Value {
    let ns = |time, fractional| i128::from(time) * 1_000_000_000 + i128::from(fractional);
    json!({"device":m.dev(),"inode":m.ino(),"bytes":m.len(),"blocks":m.blocks(),
        "uid":m.uid(),"gid":m.gid(),"mode":m.mode(),"links":m.nlink(),
        "mtime_ns":ns(m.mtime(),m.mtime_nsec()),"ctime_ns":ns(m.ctime(),m.ctime_nsec())})
}

fn verify_recipe(unit: &str, sha: &str, terminal: &Value) -> Result<Value> {
    let path = Path::new("/run/systemd/system").join(unit);
    let target = Path::new("/var/lib/jetstreamer/horizon296-full-retry-profile-v1").join(unit);
    let link = path.symlink_metadata()?;
    let mut recipe = open_regular(&target)?;
    let metadata = recipe.metadata()?;
    ensure!(
        link.is_symlink()
            && link.uid() == 0
            && fs::read_link(&path)? == target
            && metadata.uid() == 0
            && metadata.mode() & 0o222 == 0
            && digest(&mut recipe)? == sha,
        "changed epoch 296 recipe {unit}"
    );
    let freeze = path
        .with_file_name(format!("{unit}.d"))
        .join("90-closed-custody.conf");
    let freeze_file = open_regular(&freeze)?;
    let freeze_meta = freeze_file.metadata()?;
    let mut contents = String::new();
    freeze_file.take(1024).read_to_string(&mut contents)?;
    ensure!(
        freeze_meta.uid() == 0 && freeze_meta.mode() & 0o222 == 0 && contents == FREEZE,
        "epoch 296 historical recipe is not frozen: {unit}"
    );
    let mut properties = terminal
        .as_object()
        .context("missing terminal model")?
        .clone();
    let extra = json!({
        "ControlGroup":"","MainPID":"0","ControlPID":"0",
        "LoadState":"loaded","Transient":"no","FragmentPath":path,"UnitFileState":"linked-runtime",
        "TriggeredBy":"","Triggers":if unit == TIMER { GUARD } else { "" },
        "WantedBy":"","RequiredBy":"","DropInPaths":freeze,"RefuseManualStart":"yes",
    });
    properties.extend(extra.as_object().unwrap().clone());
    if unit == TIMER {
        properties.remove("MainPID");
        properties.remove("ControlPID");
        properties.remove("ControlGroup");
    }
    let output = Command::new("/usr/bin/systemctl")
        .args([
            "show",
            unit,
            "-p",
            &properties.keys().cloned().collect::<Vec<_>>().join(","),
        ])
        .output()?;
    ensure!(
        output.status.success(),
        "cannot inspect epoch 296 recipe {unit}"
    );
    let output = String::from_utf8(output.stdout)?;
    let fields = output
        .lines()
        .map(|line| line.split_once('=').context("invalid systemd row"))
        .collect::<Result<BTreeMap<_, _>>>()?;
    ensure!(
        serde_json::to_value(fields)? == Value::Object(properties)
            && !Path::new("/sys/fs/cgroup/system.slice").join(unit).exists(),
        "epoch 296 recipe no longer has its sealed terminal state: {unit}"
    );
    Ok(
        json!({"unit":unit,"path":path,"sha256":sha,"freeze":freeze,"restore_required_before_retry":true}),
    )
}

fn readers(source: &Path, closed: &Value, prior: &Value) -> Result<Value> {
    terminal_unit(PARK_UNIT)?;
    assert_no_nested_mount(source)?;
    let scheduled = scheduled_census(Path::new(SCOPE), source)?;
    ensure!(
        scheduled["remaining"] == prior["scan"]["remaining"],
        "the epoch 296 scheduled reference set changed"
    );
    let recipes = RECIPES
        .iter()
        .map(|(unit, sha)| verify_recipe(unit, sha, &closed["manager"][unit]))
        .collect::<Result<Vec<_>>>()?;
    let observed = process_references::scan(Path::new("/proc"), source)?;
    ensure!(
        observed.inspected_processes > 0 && observed.references.is_empty(),
        "epoch 296 source has a live reader"
    );
    Ok(json!({"scheduled":scheduled,"closed_recipes":recipes,"processes":observed}))
}

fn freshness(proof: &Value) -> Result<()> {
    let observed = proof["recorded_unix_seconds"]
        .as_u64()
        .context("missing R2 observation time")?;
    ensure!(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs()
            .checked_sub(observed)
            .is_some_and(|age| age < 1800),
        "refresh authenticated epoch 296 custody"
    );
    Ok(())
}

pub(super) fn run(apply: bool, recheck: Binding) -> Result<()> {
    let _issuer = lock_issuer()?;
    let _cycle = lock(CYCLE_LOCK)?;
    let _local = lock(LOCAL_LOCK)?;
    let _holding = lock(&format!("{HOLDING}/transition.lock"))?;
    let state = Path::new(ROOT);
    let closed_path = state.join("closed-byte-evidence.json");
    let closed: Value = read_bound(&closed_path, CLOSED_SHA, JSON_LIMIT)?;
    let previous_census: Value = read_bound(
        &state.join("future-retirement-scheduled-census-v1.json"),
        CENSUS_SHA,
        JSON_LIMIT,
    )?;
    let source: PathBuf = serde_json::from_value(closed["source"]["path"].clone())?;
    ensure!(
        source.starts_with(SCOPE)
            && closed["source"]["sha256"] == CLEAR_SHA
            && closed["source"]["identity"]["bytes"] == 41_628_130_271u64
            && previous_census["source"] == json!(source),
        "closed evidence disagrees on the local artifact"
    );
    let receipt_root = Path::new(HOLDING).join("receipts");
    ensure!(
        recheck.path.parent() == Some(receipt_root.as_path())
            && recheck
                .path
                .file_name()
                .and_then(|f| f.to_str())
                .is_some_and(
                    |name| name.starts_with("failed296-remote-recheck-") && name.ends_with(".json")
                ),
        "foreign epoch 296 R2 observation"
    );
    let proof: Value = read_bound(&recheck.path, &recheck.sha256, JSON_LIMIT)?;
    let custody = value(&proof["custody"])?;
    let expected = &closed["source"]["identity"];
    let key = state.join("failed-retry-custody.key");
    let key_meta = open_regular(&key)?.metadata()?;
    let mut key_identity = file_stamp(&key_meta);
    key_identity.as_object_mut().unwrap().remove("blocks");
    key_identity["length"] = key_identity
        .as_object_mut()
        .unwrap()
        .remove("bytes")
        .unwrap();
    key_identity["mode"] = json!(key_meta.mode() & 0o7777);
    ensure!(
        proof["schema"] == "foundation-epoch296-encrypted-custody-recheck-v1"
            && proof["epoch"] == 296
            && proof["authenticated_manifest_and_object_match"] == true
            && proof["remote_mutations"] == false
            && proof["publication_authorized"] == false
            && proof["custody"]["sha256"] == CUSTODY_SHA
            && proof["manifest"] == custody["manifest"]
            && proof["manifest_sha256"] == custody["manifest_sha256"]
            && proof["manifest_key"] == custody["manifest_key"]
            && custody["closed_evidence"] == json!({"path":closed_path,"sha256":CLOSED_SHA})
            && custody["remote_ciphertext_sha256_verified"] == true
            && custody["remote_authenticated_decryption_verified"] == true
            && custody["restored_plaintext_reread_verified"] == true
            && proof["manifest"]["plaintext_sha256"] == CLEAR_SHA
            && proof["manifest"]["plaintext_length"] == expected["bytes"]
            && proof["source_identity"]["inode"] == expected["inode"]
            && proof["source_identity"]["device"] == expected["device"]
            && proof["source_identity"]["ctime_ns"] == expected["ctime_ns"]
            && proof["key_file_identity"] == key_identity
            && key_meta.uid() == 0
            && key_meta.nlink() == 1
            && key_meta.mode() & 0o7777 == 0o400,
        "epoch 296 remote custody or recovery key differs"
    );
    let anchor = json!({"source":source,"identity":expected,"clear_sha256":CLEAR_SHA,
        "custody_sha256":CUSTODY_SHA,"manifest_sha256":proof["manifest_sha256"]});
    let intent_path = state.join("retry-bundle-retirement-intent.json");
    let completion_path = state.join("retry-bundle-retirement-completion.json");
    let pending = lookup_receipt(&intent_path)?;
    let open = match open_regular(&source) {
        Ok(file) => Some(file),
        Err(error)
            if error
                .downcast_ref::<io::Error>()
                .is_some_and(|e| e.kind() == io::ErrorKind::NotFound) =>
        {
            None
        }
        Err(error) => return Err(error),
    };
    if let Some((_, saved)) = &pending {
        ensure!(saved["evidence"] == anchor, "changed retirement intent");
    }
    if let Some((binding, saved)) = lookup_receipt(&completion_path)? {
        ensure!(
            pending.is_some() && open.is_none() && saved["evidence"] == anchor,
            "retirement conflicts with local state"
        );
        println!("{}", serde_json::to_string(&binding)?);
        return Ok(());
    }
    let scope = source
        .parent()
        .context("missing epoch 296 archive parent")?;
    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(scope)?;
    let info = dir.metadata()?;
    ensure!(
        scope.canonicalize()? == scope && info.uid() == 1000 && info.mode() & 0o7777 == 0o700,
        "changed epoch 296 archive directory"
    );
    let before = available(scope)?;
    let allocated = expected["blocks"]
        .as_u64()
        .context("missing allocated blocks")?
        .checked_mul(512)
        .context("allocation overflow")?;
    let intent = if let Some(mut file) = open {
        freshness(&proof)?;
        let first = readers(&source, &closed, &previous_census)?;
        ensure!(
            file_stamp(&file.metadata()?) == *expected && digest(&mut file)? == CLEAR_SHA,
            "local epoch 296 bytes differ"
        );
        let second = readers(&source, &closed, &previous_census)?;
        freshness(&proof)?;
        if !apply {
            ensure!(pending.is_none(), "retirement already in progress");
            println!(
                "{}",
                json!({"evidence":anchor,"check_only":true,
                "scheduled_recipes_closed":true,"allocated_bytes":allocated,"retirement_performed":false})
            );
            return Ok(());
        }
        let intent = match pending {
            Some((binding, _)) => binding,
            None => record(
                &intent_path,
                &json!({"evidence":anchor,"recheck":recheck,
                "before_hash_readers":first,"after_hash_readers":second,
                "allocated_bytes":allocated,"free_before_bytes":before}),
            )?,
        };
        ensure!(
            identity(&dir.metadata()?) == identity(&scope.symlink_metadata()?)
                && file_stamp(&file.metadata()?) == *expected
                && file_stamp(&source.symlink_metadata()?) == *expected,
            "epoch 296 archive identity changed before unlink"
        );
        let name = CString::new(
            source
                .file_name()
                .context("missing archive name")?
                .as_bytes(),
        )?;
        if unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) } != 0 {
            return Err(io::Error::last_os_error())
                .context("unlink exact closed epoch 296 artifact");
        }
        dir.sync_all()?;
        ensure!(
            file.metadata()?.nlink() == 0,
            "retired epoch 296 inode retains a link"
        );
        intent
    } else {
        ensure!(apply, "epoch 296 source already absent");
        dir.sync_all()?;
        pending
            .context("epoch 296 source absent without retirement intent")?
            .0
    };
    ensure!(
        source
            .symlink_metadata()
            .is_err_and(|e| e.kind() == io::ErrorKind::NotFound)
            && identity(&open_regular(&key)?.metadata()?) == identity(&key_meta),
        "retired path or recovery key changed"
    );
    let done = record(
        &completion_path,
        &json!({
            "schema":"foundation-epoch296-local-retry-bundle-retirement-v1","epoch":296,
            "evidence":anchor,"intent":intent,"source_absent":true,"allocated_bytes_removed":allocated,
            "free_at_attempt_start_bytes":before,"free_after_bytes":available(scope)?,
            "r2_mutations":false,"publication_authorized":false
        }),
    )?;
    println!("{}", serde_json::to_string(&done)?);
    Ok(())
}
