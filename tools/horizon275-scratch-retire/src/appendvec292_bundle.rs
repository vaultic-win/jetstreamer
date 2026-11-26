//! Retire only the redundant local compressed bundle after a verified remote restore.

use super::{parked_accounts::sealed, selective_accounts::record, snapshot288::lookup_receipt, *};
use std::{ffi::CString, os::unix::ffi::OsStrExt};

const STATE: &str = "/var/lib/jetstreamer/horizon292-appendvec-retirement-v308";
const SOURCE_ROOT: &str = "/var/lib/jetstreamer/horizon292-closed-appendvec-staging-v308";
const BUNDLE: &str = "epoch-292-closed-appendvecs.pax.zst";
const COMPLETION_SHA: &str = "d2fed211df5d4e55808b400e6b48ce1ece8b03a5fdf9b11cd63500649f130a17";

fn matching_etag(head: &Value, custody: &Value) -> bool {
    head.as_str()
        .zip(custody.as_str())
        .is_some_and(|(head, custody)| {
            !custody.is_empty()
                && head
                    .strip_prefix('"')
                    .and_then(|etag| etag.strip_suffix('"'))
                    == Some(custody)
        })
}

fn same_bundle(metadata: &Metadata, expected: &Value, renamed: bool) -> bool {
    metadata.is_file()
        && expected["device"] == metadata.dev()
        && expected["inode"] == metadata.ino()
        && expected["logical_bytes"] == metadata.len()
        && metadata
            .blocks()
            .checked_mul(512)
            .is_some_and(|bytes| expected["physical_bytes"] == bytes)
        && expected["uid"] == metadata.uid()
        && expected["mode"] == metadata.mode() & 0o7777
        && expected["links"] == 1
        && metadata.nlink() == 1
        && expected["mtime_ns"].as_i64()
            == metadata
                .mtime()
                .checked_mul(1_000_000_000)
                .and_then(|n| n.checked_add(metadata.mtime_nsec()))
        && (renamed
            || expected["ctime_ns"].as_i64()
                == metadata
                    .ctime()
                    .checked_mul(1_000_000_000)
                    .and_then(|n| n.checked_add(metadata.ctime_nsec())))
}

fn closed_consumers(source: &Path, bundle: &Path) -> Result<Value> {
    for unit in [
        "foundation-292-closed-appendvec-staging-v308.service",
        "foundation-292-appendvec-custody-v308.service",
        "horizon-restore-292-appendvec-ram-v308.service",
    ] {
        terminal_unit(unit)?;
    }
    snapshot288::closed292()?;
    let configuration = scheduled(source, bundle)?;
    let processes = process_references::scan(Path::new("/proc"), bundle)?;
    ensure!(
        processes.inspected_processes > 0 && processes.references.is_empty(),
        "292 bundle has a live consumer"
    );
    Ok(json!({"configuration": configuration, "processes": processes}))
}

pub(super) fn run(apply: bool, self_sha: &str, recheck: Binding) -> Result<()> {
    let _issuer = appendvec288::lock_issuer()?;
    let _cycle = lock(CYCLE_LOCK)?;
    let _local = lock(LOCAL_LOCK)?;
    let state = Path::new(STATE);
    let completed = sealed(&state.join("completion.json"), JSON_LIMIT)?;
    ensure!(
        completed.sha256 == COMPLETION_SHA,
        "different AccountsDb retirement"
    );
    let retired = value(&serde_json::to_value(&completed)?)?;
    let anchors = &retired["authorization"]["anchors"];
    ensure!(
        retired["epoch"] == 292
            && retired["empty_root_retained"] == true
            && retired["verified_allocated_bytes_removed"] == 432_056_471_552u64,
        "AccountsDb retirement has not completed"
    );
    ensure!(
        recheck.path == state.join("bundle-retirement-holding-identity.json")
            && sealed(&recheck.path, JSON_LIMIT)?.sha256 == recheck.sha256,
        "require sealed authenticated holding recheck"
    );
    let remote = value(&serde_json::to_value(&recheck)?)?;
    let comparison = value(&anchors["comparison"])?;
    let custody = value(&comparison["custody"])?;
    ensure!(
        remote["schema"] == "foundation-epoch292-staged-bundle-holding-identity-v1"
            && remote["epoch"] == 292
            && remote["completion"] == serde_json::to_value(&completed)?
            && remote["comparison"] == anchors["comparison"]
            && remote["custody"] == comparison["custody"]
            && remote["whole_readback_reused_from_matching_custody"] == true
            && remote["restore_comparison_matches"] == true
            && remote["r2_mutations"] == false
            && comparison["compressed_bundle_restored"] == true
            && comparison["remote_sha256_readback"] == true
            && comparison["comparison"]["full_sparse_payload_matches"] == true
            && custody["remote_sha256_readback"] == true
            && custody["local_source_revalidated"] == true
            && remote["object_key"] == custody["object_key"]
            && matching_etag(&remote["object_etag"], &custody["object_etag"])
            && remote["sha256"] == custody["manifest"]["sha256"]
            && remote["length"] == custody["manifest"]["length"]
            && remote["manifest_key"] == custody["manifest_key"]
            && remote["manifest_sha256"] == custody["manifest_sha256"],
        "holding identity or restore evidence changed"
    );

    let source = Path::new(SOURCE_ROOT);
    let parent = source.join("bundle");
    let bundle = parent.join(BUNDLE);
    let quarantine = state.join("closed-bundle-quarantine.pax.zst");
    let kept = Path::new(snapshot288::RUN292).join("archives/epoch-292.jet");
    let expected = &anchors["local_bundle"];
    ensure!(
        state.canonicalize()? == state
            && state.metadata()?.uid() == 0
            && state.metadata()?.mode() & 0o777 == 0o700
            && parent.canonicalize()? == parent,
        "unsafe bundle or retirement directory"
    );
    ensure!(
        state.metadata()?.dev() == parent.metadata()?.dev()
            && parent.metadata()?.dev() == Path::new("/").metadata()?.dev(),
        "bundle and quarantine must share the guarded filesystem"
    );
    assert_no_nested_mount(&bundle)?;
    let check_archive = || -> Result<()> {
        ensure!(
            same_bundle(
                &open_regular(&kept)?.metadata()?,
                &anchors["retained_archive"],
                false
            ),
            "epoch 292 partial archive changed"
        );
        Ok(())
    };
    check_archive()?;
    let authorization = json!({"self_sha256":self_sha,"completed_accounts_retirement":completed,
        "holding_recheck": recheck,"bundle":bundle,"stamp":expected,"quarantine":quarantine});
    let done_path = state.join("bundle-retirement-completion.json");
    if let Some((reference, done)) = lookup_receipt(&done_path)? {
        ensure!(
            done["authorization"] == authorization
                && !bundle.try_exists()?
                && !quarantine.try_exists()?,
            "conflicting bundle retirement completion"
        );
        println!("{}", serde_json::to_string(&reference)?);
        return Ok(());
    }
    let readers = closed_consumers(source, &bundle)?;
    let before = available(&parent)?;
    let intent_path = state.join("bundle-retirement-intent.json");
    let pending = lookup_receipt(&intent_path)?;
    if !apply || pending.is_none() {
        ensure!(
            !quarantine.try_exists()?
                && same_bundle(&open_regular(&bundle)?.metadata()?, expected, false),
            "closed staged bundle identity changed"
        );
    }
    if !apply {
        println!(
            "{}",
            json!({"authorization":authorization,"readers":readers,"free_before_bytes":before})
        );
        return Ok(());
    }
    let intent = if let Some((reference, value)) = pending {
        ensure!(
            value["authorization"] == authorization,
            "conflicting bundle retirement intent"
        );
        reference
    } else {
        record(
            &intent_path,
            &json!({"authorization":authorization,"readers":readers,"free_before_bytes":before}),
        )?
    };
    if bundle.try_exists()? {
        ensure!(
            same_bundle(&open_regular(&bundle)?.metadata()?, expected, false),
            "bundle changed before quarantine"
        );
        let from = CString::new(bundle.as_os_str().as_bytes())?;
        let to = CString::new(quarantine.as_os_str().as_bytes())?;
        if unsafe {
            libc::renameat2(
                libc::AT_FDCWD,
                from.as_ptr(),
                libc::AT_FDCWD,
                to.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        } != 0
        {
            return Err(io::Error::last_os_error()).context("quarantine exact 292 staging bundle");
        }
        File::open(&parent)?.sync_all()?;
        File::open(state)?.sync_all()?;
    }
    let unlink_path = state.join("bundle-retirement-unlink-intent.json");
    let expected_unlink = json!({"intent":intent,"authorization":authorization});
    if quarantine.try_exists()? {
        ensure!(
            same_bundle(&open_regular(&quarantine)?.metadata()?, expected, true),
            "unexpected quarantined inode; all bytes were preserved"
        );
        closed_consumers(source, &bundle)?;
        let processes = process_references::scan(Path::new("/proc"), &quarantine)?;
        ensure!(
            processes.inspected_processes > 0 && processes.references.is_empty(),
            "quarantined bundle has a reader"
        );
        if let Some((_, saved)) = lookup_receipt(&unlink_path)? {
            ensure!(
                saved == expected_unlink,
                "different quarantine unlink intent"
            );
        } else {
            record(&unlink_path, &expected_unlink)?;
        }
        fs::remove_file(&quarantine)?;
        File::open(state)?.sync_all()?;
    } else {
        let (_, saved) =
            lookup_receipt(&unlink_path)?.context("bundle absent without durable unlink intent")?;
        ensure!(
            saved == expected_unlink,
            "different quarantine unlink intent"
        );
    }
    ensure!(
        !bundle.try_exists()? && !quarantine.try_exists()?,
        "bundle path was repopulated"
    );
    check_archive()?;
    let done = record(
        &done_path,
        &json!({"schema":"foundation-epoch292-local-stage-bundle-retirement-v1",
        "epoch":292,"authorization":authorization,"intent":intent,"verified_allocated_bytes_removed":expected["physical_bytes"],
        "free_at_attempt_start_bytes":before,"free_after_bytes":available(&parent)?,"partial_archive_preserved":true,
        "publication_authorized":false,"r2_mutations":false}),
    )?;
    println!("{}", serde_json::to_string(&done)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authenticated_head_quotes_the_custody_etag() {
        assert!(matching_etag(
            &json!("\"digest-1005\""),
            &json!("digest-1005")
        ));
        assert!(!matching_etag(
            &json!("\"digest-1004\""),
            &json!("digest-1005")
        ));
        assert!(!matching_etag(&Value::Null, &Value::Null));
    }

    #[test]
    fn quarantine_relaxes_only_the_rename_timestamp() -> Result<()> {
        let file = tempfile::NamedTempFile::new()?;
        let metadata = file.as_file().metadata()?;
        let mut stamp = serde_json::to_value(snapshot288::Stamp::of(&metadata)?)?;
        stamp["mode"] = json!(metadata.mode() & 0o7777);
        assert!(same_bundle(&metadata, &stamp, false));
        stamp["ctime_ns"] = json!(stamp["ctime_ns"].as_i64().unwrap() - 1);
        assert!(!same_bundle(&metadata, &stamp, false));
        assert!(same_bundle(&metadata, &stamp, true));
        stamp["inode"] = json!(metadata.ino().wrapping_add(1));
        assert!(!same_bundle(&metadata, &stamp, true));
        Ok(())
    }
}
