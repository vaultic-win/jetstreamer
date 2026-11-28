//! Release only the closed epoch 224 canary after encrypted custody and a fresh R2 recheck.
use super::{
    appendvec288::lock_issuer, selective_accounts::record, snapshot288::lookup_receipt, *,
};
use std::time::{SystemTime, UNIX_EPOCH};

const SCOPE: &str = "/home/ubuntu/.jetstreamer-private/bounded-resource-224-8f80ce8-v1";
const ROOT: &str = "/var/lib/jetstreamer/horizon224-canary-native-custody-v1";
const HOLDING: &str = "/var/lib/jetstreamer/horizon-foundation-closed-private-holding-v1";
const CLOSURE: &str =
    "/var/lib/jetstreamer/horizon224-closed-canary-holding-candidate-v1/candidate.json";
const CLOSURE_SHA: &str = "bc77cfe12be9f2f8bdcc77478634651e931c6e1b022574a5544e9eddfd9793e8";
const LAUNCH: &str = "/var/lib/jetstreamer/horizon224-canary-production-launch-v1/park-launch.json";
const PARK_UNIT: &str = "foundation-224-canary-native-custody-v1.service";
const PRODUCER: &str = "horizon-qualify-224-bounded-resource-8f80ce8-v1.service";
const SHA: &str = "7d2bfc7dc2e57ffd8dea2989216eba0ccc2237c1658efadbe803dd747a0bd51b";
const BYTES: u64 = 9_598_810_524;
const ALLOCATED: u64 = 9_598_824_448;

fn stamp(meta: &Metadata) -> Value {
    let ns = |sec, part| i128::from(sec) * 1_000_000_000 + i128::from(part);
    json!({"device":meta.dev(),"inode":meta.ino(),"length":meta.len(),"uid":meta.uid(),"gid":meta.gid(),
        "links":meta.nlink(),"mode":meta.mode() & 0o7777,
        "mtime_ns":ns(meta.mtime(),meta.mtime_nsec()),"ctime_ns":ns(meta.ctime(),meta.ctime_nsec())})
}

fn bound_value(value: &Value) -> Result<Value> {
    let binding: Binding = serde_json::from_value(value.clone())?;
    read_bound(&binding.path, &binding.sha256, JSON_LIMIT)
}

fn fresh(proof: &Value) -> Result<()> {
    let at = proof["recorded_unix_seconds"]
        .as_u64()
        .context("missing recheck time")?;
    ensure!(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs()
            .checked_sub(at)
            .is_some_and(|age| age < 1800),
        "refresh authenticated canary custody"
    );
    Ok(())
}

fn source_readers(path: &Path) -> Result<Value> {
    terminal_unit(PRODUCER)?;
    terminal_unit(PARK_UNIT)?;
    assert_no_nested_mount(path)?;
    let scheduled = scheduled(Path::new(SCOPE), path)?;
    let live = process_references::scan(Path::new("/proc"), path)?;
    ensure!(
        live.inspected_processes > 0 && live.references.is_empty(),
        "canary has a live reader"
    );
    Ok(json!({"scheduled":scheduled,"live":live}))
}

pub(super) fn run(apply: bool, recheck: Binding) -> Result<()> {
    let _issuer = lock_issuer()?;
    let _cycle = lock(CYCLE_LOCK)?;
    let _local = lock(LOCAL_LOCK)?;
    let _holding = lock(&format!("{HOLDING}/transition.lock"))?;
    let receipts = Path::new(HOLDING).join("receipts");
    ensure!(
        recheck.path.parent() == Some(receipts.as_path())
            && recheck
                .path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(
                    |name| name.starts_with("canary224-recheck-") && name.ends_with(".json")
                ),
        "foreign canary R2 receipt"
    );
    let proof: Value = read_bound(&recheck.path, &recheck.sha256, JSON_LIMIT)?;
    let custody = bound_value(&proof["custody"])?;
    let launch = bound_value(&proof["launch"])?;
    let closure: Value = read_bound(Path::new(CLOSURE), CLOSURE_SHA, JSON_LIMIT)?;
    let path = Path::new(SCOPE).join("output/epoch-224-canary.jet");
    let root = Path::new(ROOT);
    let key = root.join("canary-custody.key");
    let key_meta = open_regular(&key)?.metadata()?;
    let identity = &custody["source_identity"];
    ensure!(
        proof["schema"] == "foundation-epoch224-encrypted-canary-recovery-v1"
            && proof["operation"] == "recheck"
            && proof["epoch"] == 224
            && proof["authenticated_manifest_and_object_match"] == true
            && proof["remote_mutations"] == false
            && proof["manifest"] == custody["manifest"]
            && proof["manifest_key"] == custody["manifest_key"]
            && proof["manifest_sha256"] == custody["manifest_sha256"]
            && proof["launch"]["path"] == LAUNCH
            && launch["epoch"] == 224
            && launch["unit"] == PARK_UNIT
            && proof["park_terminal"]["invocation_id"] == launch["invocation_id"]
            && custody["schema"] == "foundation-epoch224-encrypted-canary-custody-v1"
            && custody["invocation_id"] == launch["invocation_id"]
            && custody["closure"] == json!({"path":CLOSURE,"sha256":CLOSURE_SHA})
            && custody["remote_authenticated_decryption_verified"] == true
            && custody["restored_plaintext_reread_verified"] == true
            && proof["manifest"]["plaintext_sha256"] == SHA
            && proof["manifest"]["plaintext_length"] == BYTES
            && proof["manifest"]["canonical_archive"] == false
            && closure["source"]["path"] == json!(path)
            && closure["source"]["sha256"] == SHA
            && identity["device"] == 66305
            && identity["inode"] == 24588968
            && identity["length"] == BYTES
            && identity["links"] == 1
            && proof["key_file_identity"] == stamp(&key_meta)
            && key_meta.uid() == 0
            && key_meta.len() == 65
            && key_meta.nlink() == 1
            && key_meta.mode() & 0o7777 == 0o400,
        "canary source, custody or private recovery key differs"
    );
    let evidence = json!({"source":path,"identity":identity,"sha256":SHA,"custody":proof["custody"],
        "manifest_sha256":proof["manifest_sha256"]});
    let intent_path = root.join("canary-retirement-intent.json");
    let completion_path = root.join("canary-retirement-completion.json");
    let pending = lookup_receipt(&intent_path)?;
    if let Some((_, entry)) = &pending {
        ensure!(
            entry["evidence"] == evidence,
            "canary retirement intent differs"
        );
    }
    if let Some((binding, completed)) = lookup_receipt(&completion_path)? {
        ensure!(
            pending.is_some()
                && completed["evidence"] == evidence
                && path
                    .symlink_metadata()
                    .is_err_and(|err| err.kind() == io::ErrorKind::NotFound),
            "canary retirement completion conflicts with local state"
        );
        println!("{}", serde_json::to_string(&binding)?);
        return Ok(());
    }
    let parent = path.parent().context("missing canary parent")?;
    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(parent)?;
    let meta = dir.metadata()?;
    ensure!(
        parent.canonicalize()? == parent && meta.uid() == 1000 && meta.mode() & 0o7777 == 0o700,
        "unsafe canary source parent"
    );
    let before = available(parent)?;
    let open = match open_regular(&path) {
        Ok(file) => Some(file),
        Err(error)
            if error
                .downcast_ref::<io::Error>()
                .is_some_and(|err| err.kind() == io::ErrorKind::NotFound) =>
        {
            None
        }
        Err(error) => return Err(error),
    };
    let intent = if let Some(mut file) = open {
        fresh(&proof)?;
        let first = source_readers(&path)?;
        ensure!(
            stamp(&file.metadata()?) == *identity
                && file.metadata()?.blocks() * 512 == ALLOCATED
                && digest(&mut file)? == SHA,
            "local canary bytes or extent count changed"
        );
        let second = source_readers(&path)?;
        fresh(&proof)?;
        if !apply {
            println!(
                "{}",
                json!({"evidence":evidence,"check_only":true,"allocated_bytes":ALLOCATED,
                "readers":second,"retirement_performed":false})
            );
            return Ok(());
        }
        let intent = match pending {
            Some((binding, _)) => binding,
            None => record(
                &intent_path,
                &json!({"evidence":evidence,"recheck":recheck,
                "before_hash_readers":first,"after_hash_readers":second,"free_before_bytes":before}),
            )?,
        };
        ensure!(
            stamp(&file.metadata()?) == *identity
                && stamp(&path.symlink_metadata()?) == *identity
                && dir.metadata()?.ino() == parent.symlink_metadata()?.ino(),
            "canary inode changed before retirement"
        );
        let name = std::ffi::CString::new("epoch-224-canary.jet")?;
        ensure!(
            unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) } == 0,
            "unlink exact canary: {}",
            io::Error::last_os_error()
        );
        dir.sync_all()?;
        ensure!(
            file.metadata()?.nlink() == 0,
            "retired canary inode retains a link"
        );
        intent
    } else {
        ensure!(apply, "canary source already absent");
        dir.sync_all()?;
        pending
            .context("canary source absent without retirement intent")?
            .0
    };
    ensure!(
        path.symlink_metadata()
            .is_err_and(|err| err.kind() == io::ErrorKind::NotFound)
            && stamp(&open_regular(&key)?.metadata()?) == stamp(&key_meta),
        "retired canary path or recovery key changed"
    );
    let binding = record(
        &completion_path,
        &json!({"schema":"foundation-epoch224-canary-retirement-v1",
        "epoch":224,"evidence":evidence,"intent":intent,"allocated_bytes_removed":ALLOCATED,
        "source_absent":true,"actual_free_after_bytes":available(parent)?,"r2_mutations":false,"publication_authorized":false}),
    )?;
    println!("{}", serde_json::to_string(&binding)?);
    Ok(())
}
