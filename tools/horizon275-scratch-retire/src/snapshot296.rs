//! Evict only the generation-pinned bootstrap of the completed epoch 296 diagnostic.
use super::*;
use std::{
    ffi::CString,
    time::{SystemTime, UNIX_EPOCH},
};

const STATE: &str = "/var/lib/jetstreamer/horizon296-feature-bootstrap-retirement-v1";
const REPLAY_STATE: &str = "/var/lib/jetstreamer/horizon296-feature-account-v4";
const NAME: &str = "snapshot-127953993-BMnmBoeq3oiF3H84GVF1u5gTXPngfDa2fwW2QZpKARDn.tar.zst";
const CACHE: &str = "/home/ubuntu/.jetstreamer-private/epoch296-checkpoint-127953993-generation-1649156946072810-v1";
const SHA: &str = "d03e28d9b0707ff760320d5fb1f2679accdcc882013ad32ffc8fd2d8d7da9653";
const SIZE: u64 = 21_398_102_198;
const TERMINAL_SHA: &str = "89fb50edf452aca9205c8022670e8dd6863cc131090c95383c6a3f352e20ea05";
const VERIFICATION_SHA: &str = "37276363340f3df8904ffffc61cef7cf42ef341e7738848f1a64fb6f1e2bb2ac";
const FULL_PROFILE_SHA: &str = "c9287ddad9c6bba36fda7bedb7c76cf42ca57576b76c3b6a648ce1b7f473d0f0";
const RESTORE_SHA: &str = "5f4a07cb9c71ad33e7104c25d6509f674705387b7d45361308c10ed18296a111";
const UNITS: [&str; 3] = [
    "horizon-qualify-296-feature-account-v4.service",
    "horizon-296-feature-account-protective-v4.service",
    "horizon-296-feature-account-protective-v4.timer",
];

fn stamp(m: &Metadata) -> Value {
    json!({"identity":identity(m),"physical_bytes":m.blocks()*512,"mode":m.mode(),"uid":m.uid(),"links":m.nlink()})
}

fn observe(target: &Path) -> Result<(Value, process_references::Scan)> {
    for unit in UNITS {
        terminal_unit(unit)?;
        ensure!(
            !Path::new("/sys/fs/cgroup/system.slice").join(unit).exists(),
            "{unit} retains a cgroup"
        );
    }
    assert_no_nested_mount(target)?;
    let schedule = scheduled(Path::new(CACHE), target)?;
    let consumers = process_references::scan(Path::new("/proc"), target)?;
    ensure!(
        consumers.inspected_processes > 0 && consumers.references.is_empty(),
        "epoch 296 diagnostic bootstrap is still referenced"
    );
    Ok((schedule, consumers))
}

pub(super) fn run(
    apply: bool,
    self_sha: &str,
    proof_path: &Path,
    metadata_sha: &str,
) -> Result<()> {
    let state = Path::new(STATE);
    let info = state.symlink_metadata()?;
    ensure!(
        state.canonicalize()? == state
            && info.is_dir()
            && info.uid() == 0
            && info.mode() & 0o077 == 0,
        "unsafe retirement receipts directory"
    );
    let path = Path::new(CACHE).join(NAME);
    ensure!(
        proof_path.parent() == Some(state)
            && proof_path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(
                    |name| name.starts_with("generation-recheck-") && name.ends_with(".json")
                ),
        "foreign generation recheck path"
    );
    let proof: Value = read_bound(proof_path, metadata_sha, JSON_LIMIT)?;
    let object = &proof["object"];
    ensure!(
        proof["schema"] == "foundation-epoch296-diagnostic-bootstrap-generation-recheck-v1"
            && proof["snapshot_sha256"] == SHA
            && object["bucket"] == "mainnet-beta-ledger-us-ny5"
            && object["name"] == format!("127870084/hourly/{NAME}")
            && object["generation"] == "1649156946072810"
            && object["size"] == SIZE
            && object["crc32c"] == "sVkoFA=="
            && object["md5"] == "aWUFLp/pWP9OmMZ334PWZw=="
            && object["etag"] == "COqpzK/k/PYCEAE=",
        "epoch 296 GCS restore identity differs"
    );
    let restore: Value = read_bound(&state.join("prior-restore.json"), RESTORE_SHA, JSON_LIMIT)?;
    ensure!(
        restore["snapshot_slot"] == 127953993
            && restore["generation"] == 1649156946072810u64
            && restore["destination"] == json!(path)
            && restore["file"]["sha256"] == SHA
            && restore["file"]["size"] == SIZE
            && restore["file"]["crc32c_base64"] == object["crc32c"]
            && restore["file"]["md5_base64"] == object["md5"],
        "retained generation download receipt differs"
    );
    let terminal: Value = read_bound(
        &Path::new(REPLAY_STATE).join("terminal.json"),
        TERMINAL_SHA,
        JSON_LIMIT,
    )?;
    let verified: Value = read_bound(
        &Path::new(REPLAY_STATE).join("bounded-archive-full-verification-v1.json"),
        VERIFICATION_SHA,
        JSON_LIMIT,
    )?;
    ensure!(
        terminal["invocation_id"] == "2a5350a4bde2444fbe6abfacdaf632e6"
            && terminal["guard_drained"] == true
            && terminal["state"] == "checkpoint-verified"
            && verified["terminal"]["sha256"] == TERMINAL_SHA
            && verified["verified"] == true
            && verified["canonical_publication_authorized"] == false,
        "diagnostic terminal or verified archive differs"
    );
    let archive = Path::new(
        verified["archive"]["path"]
            .as_str()
            .context("verified archive path")?,
    );
    let archive_state = || -> Result<()> {
        let meta = open_regular(archive)?.metadata()?;
        ensure!(
            verified["archive"]["identity"]
                == json!([
                    meta.dev(),
                    meta.ino(),
                    meta.len(),
                    i128::from(meta.mtime()) * 1_000_000_000 + i128::from(meta.mtime_nsec()),
                    i128::from(meta.ctime()) * 1_000_000_000 + i128::from(meta.ctime_nsec())
                ]),
            "verified diagnostic archive changed"
        );
        Ok(())
    };
    archive_state()?;
    let next: Value = read_bound(
        Path::new("/var/lib/jetstreamer/horizon296-full-retry-preparation-v2/profile.json"),
        FULL_PROFILE_SHA,
        JSON_LIMIT,
    )?;
    let readers = next["readonly_bindings"]
        .as_array()
        .context("missing full replay inputs")?;
    ensure!(
        next["bootstrap"]["slot"] == 127870084
            && readers.len() == 5
            && readers
                .iter()
                .all(|row| row["path"].as_str().is_some_and(|p| Path::new(p) != path)),
        "full epoch 296 replay depends on this cache"
    );

    let _cycle = lock(CYCLE_LOCK)?;
    let _mutation = lock(LOCAL_LOCK)?;
    let context = json!({"source":path,"source_sha256":SHA,"terminal_sha256":TERMINAL_SHA,
            "verified_archive_sha256":VERIFICATION_SHA,"restore_sha256":RESTORE_SHA,
            "tool_sha256":self_sha,"generation":object});
    let intent_path = state.join("intent.json");
    let check_path = state.join("check.json");
    let done_path = state.join("completion.json");
    if let Some((r, done)) = snapshot288::lookup_receipt(&done_path)? {
        ensure!(
            done["scope"] == context
                && path
                    .symlink_metadata()
                    .is_err_and(|e| e.kind() == io::ErrorKind::NotFound),
            "retirement receipt disagrees with disk"
        );
        println!("{}", serde_json::to_string(&r)?);
        return Ok(());
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let observed = proof["observed_unix_seconds"]
        .as_u64()
        .context("missing GCS observation time")?;
    ensure!(
        now.checked_sub(observed).is_some_and(|age| age <= 900),
        "GCS generation recheck is stale"
    );
    let (scheduled, consumers) = observe(&path)?;
    let parent = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(CACHE)?;
    let parent_identity = identity(&parent.metadata()?);
    let relative = PathBuf::from(format!("/proc/self/fd/{}", parent.as_raw_fd())).join(NAME);
    let pending = snapshot288::lookup_receipt(&intent_path)?;
    let current = match relative.symlink_metadata() {
        Ok(meta) => {
            let mut file = open_regular(&path)?;
            ensure!(
                meta.is_file()
                    && meta.uid() == 1000
                    && meta.nlink() == 1
                    && meta.mode() & 0o022 == 0
                    && meta.len() == SIZE
                    && restore["file"]["device"] == meta.dev()
                    && restore["file"]["inode"] == meta.ino()
                    && restore["file"]["mtime_ns"]
                        == json!(
                            i128::from(meta.mtime()) * 1_000_000_000
                                + i128::from(meta.mtime_nsec())
                        )
                    && stamp(&file.metadata()?) == stamp(&meta)
                    && digest(&mut file)? == SHA
                    && stamp(&file.metadata()?) == stamp(&meta),
                "diagnostic snapshot identity or SHA-256 changed"
            );
            ensure!(
                stamp(&relative.symlink_metadata()?) == stamp(&meta),
                "cache replaced during hashing"
            );
            Some(stamp(&meta))
        }
        Err(e) if apply && e.kind() == io::ErrorKind::NotFound && pending.is_some() => None,
        Err(e) => return Err(e).context("unexplained diagnostic cache absence"),
    };
    if !apply {
        ensure!(pending.is_none(), "retirement already started");
        let receipt = write_json(
            &check_path,
            &json!({"scope":context,"file":current,"metadata_sha256":metadata_sha,"scheduled":scheduled,"consumers":consumers}),
        );
        println!("{}", serde_json::to_string(&receipt?)?);
        return Ok(());
    }
    let (check_ref, check) =
        snapshot288::lookup_receipt(&check_path)?.context("missing check-only receipt")?;
    ensure!(
        check["scope"] == context && current.as_ref().is_none_or(|value| *value == check["file"]),
        "check-only scope or recorded file identity changed"
    );
    let released = check["file"]["physical_bytes"]
        .as_u64()
        .context("missing measured cache allocation")?;
    let intent = if let Some((r, saved)) = pending {
        ensure!(
            saved["scope"] == context && saved["check"] == json!(check_ref),
            "foreign retirement intent"
        );
        r
    } else {
        write_json(
            &intent_path,
            &json!({"scope":context,"check":check_ref,"metadata_sha256":metadata_sha,
            "free_before_bytes":available(Path::new(CACHE))?,"scheduled":scheduled,"consumers":consumers}),
        )?
    };
    let (schedule, consumers) = observe(&path)?;
    archive_state()?;
    ensure!(
        Path::new(CACHE).canonicalize()? == Path::new(CACHE)
            && identity(&fs::symlink_metadata(CACHE)?) == parent_identity,
        "cache parent replaced"
    );
    if let Some(stable) = current {
        ensure!(
            stamp(&relative.symlink_metadata()?) == stable,
            "cache changed before retirement"
        );
        let name = CString::new(NAME)?;
        ensure!(
            unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) } == 0,
            "could not retire bound cache: {}",
            io::Error::last_os_error()
        );
    }
    parent.sync_all()?;
    archive_state()?;
    ensure!(
        path.symlink_metadata()
            .is_err_and(|e| e.kind() == io::ErrorKind::NotFound),
        "cache still present"
    );
    let receipt = write_json(
        &done_path,
        &json!({"scope":context,"intent":intent,"allocated_bytes_removed":released,
        "free_after_bytes":available(Path::new(CACHE))?,"scheduled":schedule,"consumers":consumers,
        "archive_preserved":true,"source_restorable_by_pinned_generation":true,"r2_mutations":false,"remote_mutations":false}),
    );
    println!("{}", serde_json::to_string(&receipt?)?);
    Ok(())
}
