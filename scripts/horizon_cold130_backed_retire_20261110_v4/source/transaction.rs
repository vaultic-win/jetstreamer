//! One-body capture transaction. The private capture is atomically no-clobber,
//! then fully rehashed through its descriptor before an unlink can be attempted.
//! Source-name absence alone never earns file-block or resource credit.
use crate::atomic_fs::{self, AnchoredParent};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::Read,
    os::fd::AsRawFd,
    os::unix::fs::MetadataExt,
    path::Path,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
const QUARANTINE: &str = ".cold130-retirement-20261110-v2";
const CAPTURE: &str = "captured-original.jet";
fn stable_identity(m: &fs::Metadata) -> Value {
    json!([
        m.dev(),
        m.ino(),
        m.uid(),
        m.gid(),
        m.mode(),
        m.nlink(),
        m.len(),
        m.mtime(),
        m.mtime_nsec()
    ])
}
fn original_stable(original: &Value) -> Result<Value> {
    let a = original.as_array().context("source identity array")?;
    ensure!(a.len() == 11, "source identity fields");
    Ok(json!(&a[..9]))
}
fn hash_fd(f: &mut File, expected_identity: &Value, length: u64, digest: &str) -> Result<Value> {
    let before = f.metadata()?;
    ensure!(
        before.is_file()
            && before.nlink() == 1
            && before.mode() & 0o022 == 0
            && stable_identity(&before) == original_stable(expected_identity)?
            && before.len() == length,
        "captured file is not the original body"
    );
    let started = Instant::now();
    let mut reported = Instant::now();
    eprintln!(
        "epoch130 body-hash start unix={} length={length}",
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()
    );
    let mut h = Sha256::new();
    let mut b = vec![0u8; 1 << 20];
    let mut total = 0u64;
    loop {
        let n = f.read(&mut b)?;
        if n == 0 {
            break;
        }
        total = total
            .checked_add(n as u64)
            .context("body length overflow")?;
        ensure!(total <= length, "captured source grew");
        h.update(&b[..n]);
        if reported.elapsed() >= Duration::from_secs(60) {
            eprintln!(
                "epoch130 body-hash progress unix={} bytes={total}/{length} elapsed_seconds={} last_substantive_progress=now",
                SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
                started.elapsed().as_secs()
            );
            reported = Instant::now();
        }
    }
    ensure!(
        total == length
            && format!("{:x}", h.finalize()) == digest
            && crate::ident(&before) == crate::ident(&f.metadata()?),
        "captured source changed or digest differs"
    );
    eprintln!(
        "epoch130 body-hash complete unix={} bytes={total} elapsed_seconds={}",
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        started.elapsed().as_secs()
    );
    Ok(
        json!({"identity":crate::ident(&before),"original_stable_identity":stable_identity(&before),"length":length,"sha256":digest,"allocated_file_blocks_bytes":before.blocks().checked_mul(512).context("blocks overflow")?}),
    )
}
fn free_bytes(parent: &File) -> Result<u64> {
    let mut value = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    ensure!(
        unsafe { libc::fstatvfs(parent.as_raw_fd(), value.as_mut_ptr()) } == 0,
        "descriptor-relative filesystem free-space observation failed"
    );
    let value = unsafe { value.assume_init() };
    value
        .f_bavail
        .checked_mul(value.f_frsize)
        .context("filesystem free bytes overflow")
}
fn completed_receipt(
    p: &Value,
    known: bool,
    body: Option<&Value>,
    closure: Value,
    native: &Value,
    intent: Value,
    parent: &File,
) -> Result<Value> {
    let mut v = completion(p, known, body, closure, native, intent);
    v["filesystem_available_after_bytes"] = json!(free_bytes(parent)?);
    Ok(v)
}
fn read_json(out: &File, name: &str) -> Result<Value> {
    Ok(serde_json::from_slice(&atomic_fs::read_at(out, name)?)?)
}
fn scope(p: &Value) -> Value {
    json!({"source":p["source"],"sha256":p["sha256"],"length":p["length"],"source_identity":p["source_identity"],"source_ancestor_identities":p["source_ancestor_identities"],"custody":p["custody"],"indirect_consumers_review":p["indirect_consumers_review"],"holding_transport_qualification":p["holding_transport_qualification"],"holding_original_completion":p["holding_original_completion"],"park_spec":p["park_spec"]})
}
fn receipt_bound(out: &File, name: &str) -> Result<Value> {
    let bytes = atomic_fs::read_at(out, name)?;
    Ok(json!({"leaf":name,"sha256":crate::sha(&bytes)}))
}
fn validate_receipt(v: &Value, p: &Value, schema: &str) -> Result<()> {
    ensure!(
        v["schema"] == schema
            && v["scope"] == scope(p)
            && v["resource_credit_bytes"] == 0
            && v["replay_launch_authorized"] == false,
        "retirement receipt scope changed"
    );
    Ok(())
}
fn conflicts(out: &File, p: &Value, reason: &str, observed: Value) -> Result<()> {
    if !atomic_fs::exists_at(out, "conflict.json")? {
        atomic_fs::publish(
            out,
            "conflict.json",
            &json!({"schema":"horizon-cold130-private-capture-conflict-v2","scope":scope(p),"reason":reason,"observed":observed,"all_local_paths_preserved_for_explicit_reconciliation":true,"resource_credit_bytes":0,"replay_launch_authorized":false}),
        )?;
    }
    anyhow::bail!("retirement conflict preserved: {reason}")
}
#[derive(Debug, PartialEq)]
enum State {
    Fresh,
    ResumeSource,
    ResumeCapture,
    RecoverUnknownAbsence,
    Done,
}
fn state(intent: bool, completion: bool, source: bool, capture: bool) -> Result<State> {
    match (intent, completion, source, capture) {
        (false, false, true, false) => Ok(State::Fresh),
        (true, false, true, false) => Ok(State::ResumeSource),
        (true, false, false, true) => Ok(State::ResumeCapture),
        (true, false, false, false) => Ok(State::RecoverUnknownAbsence),
        (true, true, false, false) => Ok(State::Done),
        _ => anyhow::bail!(
            "unexplained absence, replacement, duplicate source/capture or completion conflict"
        ),
    }
}
fn completion(
    p: &Value,
    known_unlink: bool,
    body: Option<&Value>,
    closure: Value,
    native: &Value,
    intent: Value,
) -> Value {
    json!({"schema":"horizon-cold130-backed-private-body-retirement-complete-v2","scope":scope(p),"intent":intent,"native":native,"source_name_absent":true,"source_parent_and_capture_directories_fsynced":true,"captured_original_unlink_observed_in_this_invocation":known_unlink,"original_inode_file_blocks_unlinked_bytes":if known_unlink {body.and_then(|b|b["allocated_file_blocks_bytes"].as_u64()).unwrap_or(0)}else{0},"physical_file_bytes_retired":0,"physical_reclamation_proven":false,"reclamation_note":"Allocated file blocks unlinked are reported separately. Concurrent allocations and shared extents preclude crediting filesystem free-space change. Recovered absence never proves who unlinked the inode.","final_consumers":closure,"canonical_objects_untouched":true,"hard_promises_released_bytes":0,"resource_credit_bytes":0,"replay_launch_authorized":false,"remote_mutations":false})
}
pub(crate) fn run(p: &Value, execute: bool, native: &Value) -> Result<()> {
    let source = Path::new(crate::SOURCE);
    let parent = source.parent().context("source parent")?;
    let leaf = source
        .file_name()
        .and_then(|s| s.to_str())
        .context("source leaf")?;
    let anchored = AnchoredParent::open(parent, &p["source_ancestor_identities"])?;
    let out = crate::open_output()?;
    let reconciled = atomic_fs::reconcile_staging(&out)?;
    ensure!(
        !atomic_fs::exists_at(&out, "conflict.json")?,
        "prior conflict needs explicit independent reconciliation; preserve both sides"
    );
    // This capture root is mode0700 and owned by the retirement identity. The
    // bound parent may be user-owned: all access to captured children remains
    // relative to this retained descriptor, never through that writable parent.
    let quarantine = atomic_fs::private_child(&anchored.directory, QUARANTINE)?;
    let have_source = atomic_fs::exists_at(&anchored.directory, leaf)?;
    let have_capture = atomic_fs::exists_at(&quarantine, CAPTURE)?;
    let have_intent = atomic_fs::exists_at(&out, "intent.json")?;
    let have_done = atomic_fs::exists_at(&out, "completion.json")?;
    let current = match state(have_intent, have_done, have_source, have_capture) {
        Ok(s) => s,
        Err(e) => {
            return conflicts(
                &out,
                p,
                &e.to_string(),
                json!({"source":have_source,"capture":have_capture,"intent":have_intent,"completion":have_done}),
            );
        }
    };
    if have_intent {
        validate_receipt(
            &read_json(&out, "intent.json")?,
            p,
            "horizon-cold130-backed-private-body-retirement-intent-v2",
        )?;
    }
    if current == State::Done {
        validate_receipt(
            &read_json(&out, "completion.json")?,
            p,
            "horizon-cold130-backed-private-body-retirement-complete-v2",
        )?;
        let _closure = crate::closure::census(p)?;
        anchored.recheck()?;
        anchored.directory.sync_all()?;
        quarantine.sync_all()?;
        ensure!(
            !atomic_fs::exists_at(&anchored.directory, leaf)?
                && !atomic_fs::exists_at(&quarantine, CAPTURE)?,
            "source or capture reappeared after completion"
        );
        return Ok(());
    }
    if !execute {
        ensure!(
            current == State::Fresh,
            "check-only is valid only before retirement starts"
        );
        let mut file = atomic_fs::open_at(&anchored.directory, leaf, libc::O_RDONLY)?;
        ensure!(
            crate::ident(&file.metadata()?) == p["source_identity"],
            "original exact pre-capture identity changed"
        );
        let body = hash_fd(&mut file, &p["source_identity"], crate::LENGTH, crate::SHA)?;
        drop(file);
        let closure = crate::closure::census(p)?;
        anchored.recheck()?;
        ensure!(crate::own(false)? == *native, "check unit changed");
        return atomic_fs::publish(
            &out,
            "check.json",
            &json!({"schema":"horizon-cold130-backed-private-body-check-v2","scope":scope(p),"body":body,"consumers":closure,"native":native,"reconciled_interrupted_staging":reconciled,"local_removal_performed":false,"resource_credit_bytes":0,"replay_launch_authorized":false,"remote_mutations":false}),
        );
    }
    let check = crate::bound(&p["check_receipt"])?;
    validate_receipt(&check, p, "horizon-cold130-backed-private-body-check-v2")?;
    ensure!(
        check["local_removal_performed"] == false,
        "check performed removal"
    );
    if current == State::RecoverUnknownAbsence {
        // The intent predates the final closure and unlink. Re-establish closure,
        // fsync both known parent descriptors, and claim only name absence.
        let closure = crate::closure::census(p)?;
        anchored.recheck()?;
        anchored.directory.sync_all()?;
        quarantine.sync_all()?;
        ensure!(
            !atomic_fs::exists_at(&anchored.directory, leaf)?
                && !atomic_fs::exists_at(&quarantine, CAPTURE)?,
            "source/capture reappeared during absence recovery"
        );
        ensure!(crate::own(true)? == *native, "recovery unit changed");
        return atomic_fs::publish(
            &out,
            "completion.json",
            &completed_receipt(
                p,
                false,
                None,
                closure,
                native,
                receipt_bound(&out, "intent.json")?,
                &anchored.directory,
            )?,
        );
    }
    if current == State::Fresh || current == State::ResumeSource {
        let mut file = atomic_fs::open_at(&anchored.directory, leaf, libc::O_RDONLY)?;
        ensure!(
            crate::ident(&file.metadata()?) == p["source_identity"],
            "source changed before capture"
        );
        let body = hash_fd(&mut file, &p["source_identity"], crate::LENGTH, crate::SHA)?;
        drop(file);
        let closure = crate::closure::census(p)?;
        anchored.recheck()?;
        if !have_intent {
            atomic_fs::publish(
                &out,
                "intent.json",
                &json!({"schema":"horizon-cold130-backed-private-body-retirement-intent-v2","scope":scope(p),"body":body,"consumers":closure,"native":native,"capture_directory":QUARANTINE,"capture_directory_identity":atomic_fs::dir_identity(&quarantine.metadata()?),"reconciled_interrupted_staging":reconciled,"holding_custody_and_restore_lineage_validated":true,"filesystem_available_before_bytes":free_bytes(&anchored.directory)?,"canonical_objects_untouched":true,"resource_credit_bytes":0,"replay_launch_authorized":false,"remote_mutations":false}),
            )?;
        }
        ensure!(
            crate::own(true)? == *native,
            "execute owner changed before capture"
        );
        // RENAME_NOREPLACE captures whichever inode is named at this single atomic
        // instant. It does not delete it. The captured inode is independently checked
        // and rehashed below before any unlink can occur.
        if let Err(e) =
            atomic_fs::rename_no_replace(&anchored.directory, leaf, &quarantine, CAPTURE)
        {
            return conflicts(
                &out,
                p,
                &e.to_string(),
                json!({"capture_attempt_failed":true}),
            );
        }
        quarantine.sync_all()?;
        anchored.directory.sync_all()?;
    }
    let intent = read_json(&out, "intent.json")?;
    ensure!(
        intent["capture_directory_identity"] == atomic_fs::dir_identity(&quarantine.metadata()?),
        "quarantine directory replaced after intent"
    );
    let mut captured = match atomic_fs::open_at(&quarantine, CAPTURE, libc::O_RDONLY) {
        Ok(file) => file,
        Err(error) => {
            return conflicts(
                &out,
                p,
                &error.to_string(),
                json!({"captured_child_open_failed":true,"capture_name_present":atomic_fs::exists_at(&quarantine,CAPTURE)?,"all_surviving_paths_preserved":true}),
            );
        }
    };
    let body = match hash_fd(
        &mut captured,
        &p["source_identity"],
        crate::LENGTH,
        crate::SHA,
    ) {
        Ok(v) => v,
        Err(e) => {
            return conflicts(
                &out,
                p,
                &e.to_string(),
                json!({"captured_identity":crate::ident(&captured.metadata()?),"captured_path_preserved":true}),
            );
        }
    };
    if atomic_fs::exists_at(&anchored.directory, leaf)? {
        return conflicts(
            &out,
            p,
            "source name reappeared after capture",
            json!({"captured_original":body}),
        );
    }
    if !atomic_fs::exists_at(&out, "capture.json")? {
        atomic_fs::publish(
            &out,
            "capture.json",
            &json!({"schema":"horizon-cold130-private-body-capture-v2","scope":scope(p),"body":body,"capture_directory_identity":atomic_fs::dir_identity(&quarantine.metadata()?),"source_parent_fsynced":true,"resource_credit_bytes":0,"replay_launch_authorized":false}),
        )?;
    } else {
        let receipt = read_json(&out, "capture.json")?;
        validate_receipt(&receipt, p, "horizon-cold130-private-body-capture-v2")?;
        ensure!(
            receipt["body"] == body,
            "capture changed after durable capture receipt"
        );
    }
    let unlink_result = verified_unlink(
        &anchored.directory,
        leaf,
        &quarantine,
        CAPTURE,
        &captured,
        &body,
        || {
            let closure = crate::closure::census(p)?;
            anchored.recheck()?;
            ensure!(
                crate::own(true)? == *native,
                "execute owner changed before unlink"
            );
            Ok(closure)
        },
    );
    let closure = match unlink_result {
        Ok(closure) => closure,
        Err(error) => {
            return conflicts(
                &out,
                p,
                &error.to_string(),
                json!({"captured_body":body,"source_name_present":atomic_fs::exists_at(&anchored.directory,leaf)?,"capture_name_present":atomic_fs::exists_at(&quarantine,CAPTURE)?,"all_surviving_paths_preserved":true}),
            );
        }
    };
    drop(captured);
    atomic_fs::publish(
        &out,
        "completion.json",
        &completed_receipt(
            p,
            true,
            Some(&body),
            closure,
            native,
            receipt_bound(&out, "intent.json")?,
            &anchored.directory,
        )?,
    )
}
/// Exact primitive used by production and isolated fixtures. The closure is
/// re-evaluated after capture/hash and before the final descriptor comparison.
fn verified_unlink(
    source_parent: &File,
    source_leaf: &str,
    quarantine: &File,
    capture_leaf: &str,
    captured: &File,
    body: &Value,
    final_closure: impl FnOnce() -> Result<Value>,
) -> Result<Value> {
    let closure = final_closure()?;
    ensure!(
        !atomic_fs::exists_at(source_parent, source_leaf)?,
        "source reappeared before unlink"
    );
    let verify = atomic_fs::open_at(quarantine, capture_leaf, libc::O_RDONLY)?;
    ensure!(
        crate::ident(&verify.metadata()?) == crate::ident(&captured.metadata()?)
            && crate::ident(&captured.metadata()?) == body["identity"],
        "capture inode changed before unlink"
    );
    drop(verify);
    atomic_fs::unlink_at(quarantine, capture_leaf)?;
    quarantine.sync_all()?;
    source_parent.sync_all()?;
    ensure!(
        !atomic_fs::exists_at(quarantine, capture_leaf)?
            && !atomic_fs::exists_at(source_parent, source_leaf)?,
        "source/capture remains or reappeared"
    );
    Ok(closure)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn interruption_states_distinguish_capture_and_unknown_absence() {
        assert_eq!(state(false, false, true, false).unwrap(), State::Fresh);
        assert_eq!(
            state(true, false, true, false).unwrap(),
            State::ResumeSource
        );
        assert_eq!(
            state(true, false, false, true).unwrap(),
            State::ResumeCapture
        );
        assert_eq!(
            state(true, false, false, false).unwrap(),
            State::RecoverUnknownAbsence
        );
        assert_eq!(state(true, true, false, false).unwrap(), State::Done);
        for x in [
            (false, false, false, false),
            (false, false, false, true),
            (true, false, true, true),
            (true, true, true, false),
            (true, true, false, true),
        ] {
            assert!(state(x.0, x.1, x.2, x.3).is_err());
        }
    }
    #[test]
    fn unknown_absence_never_claims_physical_retirement() {
        let c = completion(&json!({}), false, None, json!({}), &json!({}), json!({}));
        assert_eq!(c["physical_file_bytes_retired"], 0);
        assert_eq!(c["original_inode_file_blocks_unlinked_bytes"], 0);
        assert_eq!(c["resource_credit_bytes"], 0);
        assert_eq!(c["physical_reclamation_proven"], false);
    }
    #[test]
    fn known_unlink_still_keeps_physical_and_reservation_credit_separate() {
        let b = json!({"allocated_file_blocks_bytes":4096});
        let c = completion(&json!({}), true, Some(&b), json!({}), &json!({}), json!({}));
        assert_eq!(c["original_inode_file_blocks_unlinked_bytes"], 4096);
        assert_eq!(c["physical_file_bytes_retired"], 0);
        assert_eq!(c["hard_promises_released_bytes"], 0);
    }
    #[test]
    fn capture_replacement_is_preserved_before_any_unlink() {
        use std::io::Write;
        let t = tempfile::tempdir().unwrap();
        let parent = File::open(t.path()).unwrap();
        let mut original = File::create(t.path().join("source")).unwrap();
        original.write_all(b"original").unwrap();
        let expected = crate::ident(&original.metadata().unwrap());
        drop(original);
        let quarantine = atomic_fs::private_child(&parent, "quarantine").unwrap();
        fs::rename(t.path().join("source"), t.path().join("moved-original")).unwrap();
        fs::write(t.path().join("source"), b"foreign!").unwrap();
        atomic_fs::rename_no_replace(&parent, "source", &quarantine, "captured").unwrap();
        let mut captured = atomic_fs::open_at(&quarantine, "captured", libc::O_RDONLY).unwrap();
        assert!(hash_fd(&mut captured, &expected, 8, &crate::sha(b"original")).is_err());
        assert_eq!(
            fs::read(t.path().join("quarantine/captured")).unwrap(),
            b"foreign!"
        );
        assert_eq!(
            fs::read(t.path().join("moved-original")).unwrap(),
            b"original"
        );
    }
    #[test]
    fn captured_original_survives_interruption_before_capture_receipt() {
        let t = tempfile::tempdir().unwrap();
        fs::write(t.path().join("source"), b"original").unwrap();
        let id = crate::ident(&fs::metadata(t.path().join("source")).unwrap());
        let parent = File::open(t.path()).unwrap();
        let quarantine = atomic_fs::private_child(&parent, "q").unwrap();
        atomic_fs::rename_no_replace(&parent, "source", &quarantine, "captured").unwrap();
        quarantine.sync_all().unwrap();
        parent.sync_all().unwrap();
        let mut body = atomic_fs::open_at(&quarantine, "captured", libc::O_RDONLY).unwrap();
        let verified = hash_fd(&mut body, &id, 8, &crate::sha(b"original")).unwrap();
        assert_eq!(verified["length"], 8);
        assert!(!atomic_fs::exists_at(&parent, "source").unwrap());
        assert!(atomic_fs::exists_at(&quarantine, "captured").unwrap());
    }
    fn fixture_capture() -> (tempfile::TempDir, File, File, File, Value) {
        let t = tempfile::tempdir().unwrap();
        fs::write(t.path().join("source"), b"original").unwrap();
        let expected = crate::ident(&fs::metadata(t.path().join("source")).unwrap());
        let parent = File::open(t.path()).unwrap();
        let q = atomic_fs::private_child(&parent, "q").unwrap();
        atomic_fs::rename_no_replace(&parent, "source", &q, "captured").unwrap();
        let mut f = atomic_fs::open_at(&q, "captured", libc::O_RDONLY).unwrap();
        let body = hash_fd(&mut f, &expected, 8, &crate::sha(b"original")).unwrap();
        (t, parent, q, f, body)
    }
    #[test]
    fn reader_reappearance_after_capture_aborts_actual_unlink() {
        let (t, parent, q, f, body) = fixture_capture();
        assert!(
            verified_unlink(
                &parent,
                "source",
                &q,
                "captured",
                &f,
                &body,
                || anyhow::bail!("reader resumed")
            )
            .is_err()
        );
        assert_eq!(fs::read(t.path().join("q/captured")).unwrap(), b"original");
    }
    #[test]
    fn source_name_replacement_after_capture_preserves_both_bodies() {
        let (t, parent, q, f, body) = fixture_capture();
        fs::write(t.path().join("source"), b"new-body").unwrap();
        assert!(
            verified_unlink(&parent, "source", &q, "captured", &f, &body, || Ok(
                json!({"clear":true})
            ))
            .is_err()
        );
        assert_eq!(fs::read(t.path().join("source")).unwrap(), b"new-body");
        assert_eq!(fs::read(t.path().join("q/captured")).unwrap(), b"original");
    }
    #[test]
    fn verified_unlink_uses_captured_inode_and_leaves_other_files() {
        let (t, parent, q, f, body) = fixture_capture();
        fs::write(t.path().join("other"), b"keep").unwrap();
        verified_unlink(&parent, "source", &q, "captured", &f, &body, || {
            Ok(json!({"clear":true}))
        })
        .unwrap();
        drop(f);
        assert!(!atomic_fs::exists_at(&q, "captured").unwrap());
        assert_eq!(fs::read(t.path().join("other")).unwrap(), b"keep");
    }
    #[test]
    fn interruption_after_actual_unlink_recovers_only_name_absence() {
        let (_t, parent, q, f, body) = fixture_capture();
        verified_unlink(&parent, "source", &q, "captured", &f, &body, || {
            Ok(json!({"clear":true}))
        })
        .unwrap();
        drop(f);
        assert_eq!(
            state(
                true,
                false,
                atomic_fs::exists_at(&parent, "source").unwrap(),
                atomic_fs::exists_at(&q, "captured").unwrap()
            )
            .unwrap(),
            State::RecoverUnknownAbsence
        );
        let recovered = completion(&json!({}), false, None, json!({}), &json!({}), json!({}));
        assert_eq!(recovered["physical_file_bytes_retired"], 0);
        assert_eq!(recovered["original_inode_file_blocks_unlinked_bytes"], 0);
    }
}
