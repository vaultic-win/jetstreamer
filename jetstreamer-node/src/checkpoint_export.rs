//! Focused checkpoint export policy and frozen replay evidence.
//! Export evidence alone grants neither resume nor pressure-stop authority.

use std::{fs, ops::Range, os::unix::fs::MetadataExt, path::Path};

/// A paused report preserves native stop evidence, but is not a verified prefix
/// or a resource-release receipt. Publish it only after export and shutdown.
pub(crate) fn write_paused_evidence(
    directory: &Path,
    report: &serde_json::Value,
) -> Result<(), String> {
    use std::io::Write;
    let mut file = tempfile::NamedTempFile::new_in(directory).map_err(|e| e.to_string())?;
    serde_json::to_writer_pretty(file.as_file_mut(), report).map_err(|e| e.to_string())?;
    file.write_all(b"\n")
        .and_then(|()| file.as_file().sync_all())
        .map_err(|e| e.to_string())?;
    file.persist_noclobber(directory.join("paused.json"))
        .map_err(|e| e.to_string())?;
    fs::File::open(directory)
        .and_then(|f| f.sync_all())
        .map_err(|e| e.to_string())
}

/// Checkpoint identity retained for replay provenance and runtime handoff.
/// Account writes are deliberately excluded from this cloneable summary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HistoricalCheckpointSummary {
    pub(crate) slot: u64,
    pub(crate) bank_hash: [u8; 32],
    pub(crate) accounts_hash: [u8; 32],
    pub(crate) last_blockhash: [u8; 32],
    pub(crate) capitalization: u64,
    pub(crate) transaction_count: u64,
    pub(crate) tick_height: u64,
    pub(crate) slot_complete: bool,
    pub(crate) write_count: u64,
    pub(crate) next_write_version: u64,
}

/// Evidence produced by one uninterrupted historical runtime segment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HistoricalReplayEvidence {
    pub(crate) bootstrap: HistoricalCheckpointSummary,
    pub(crate) terminal: HistoricalCheckpointSummary,
    /// Raw worker versions emitted at or after the segment's live start;
    /// empty at the terminal cursor when no such writes were emitted.
    pub(crate) emitted_write_versions: Range<u64>,
}

pub(crate) fn validate_checkpoint_export_mode(
    focused: bool,
    explicit_verifies: usize,
    incompatible_mode: bool,
) -> Result<(), String> {
    if !focused || explicit_verifies != 1 || incompatible_mode {
        return Err("--qualification-checkpoint-export requires standalone focused qualification with exactly one --verify and no recovery, cohort or handoff override".into());
    }
    Ok(())
}

pub(crate) fn validate_checkpoint_export_directory(path: &Path) -> Result<(), String> {
    if !path.is_absolute()
        || fs::canonicalize(path).map_err(|e| format!("checkpoint export directory: {e}"))? != path
    {
        return Err("checkpoint export requires an absolute canonical directory".into());
    }
    let metadata =
        fs::symlink_metadata(path).map_err(|e| format!("checkpoint export directory: {e}"))?;
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        return Err("checkpoint export requires an owned private directory".into());
    }
    if fs::read_dir(path)
        .map_err(|e| format!("checkpoint export directory: {e}"))?
        .next()
        .is_some()
    {
        return Err(
            "checkpoint export requires a new empty directory; retain earlier attempts".into(),
        );
    }
    Ok(())
}

pub(crate) fn validate_checkpoint_export_evidence(
    before: &HistoricalReplayEvidence,
    after: &HistoricalReplayEvidence,
) -> Result<(), String> {
    let mut expected = before.clone();
    // The first freeze's writes were already recorded. The fresh freeze after
    // serialization must yield no writes and preserve every field and cursor.
    expected.terminal.write_count = 0;
    if after != &expected {
        return Err(
            "checkpoint export changed frozen state, emitted new writes or moved its cursor".into(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    #[test]
    fn paused_evidence_is_private_and_never_replaces_an_earlier_attempt() {
        let directory = tempfile::tempdir().unwrap();
        let report =
            serde_json::json!({"full_range_completed":false,"resource_release_authorized":false});
        write_paused_evidence(directory.path(), &report).unwrap();
        let path = directory.path().join("paused.json");
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        let original = fs::read(&path).unwrap();
        assert!(write_paused_evidence(directory.path(), &serde_json::json!({})).is_err());
        assert_eq!(fs::read(&path).unwrap(), original);
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    fn evidence() -> HistoricalReplayEvidence {
        let checkpoint = HistoricalCheckpointSummary {
            slot: 42,
            bank_hash: [1; 32],
            accounts_hash: [2; 32],
            last_blockhash: [3; 32],
            capitalization: 100,
            transaction_count: 7,
            tick_height: 64,
            slot_complete: true,
            write_count: 5,
            next_write_version: 18,
        };
        HistoricalReplayEvidence {
            bootstrap: checkpoint.clone(),
            terminal: checkpoint,
            emitted_write_versions: 13..18,
        }
    }

    #[test]
    fn only_explicit_standalone_focused_mode_qualifies() {
        assert!(validate_checkpoint_export_mode(true, 1, false).is_ok());
        for focused in [false, true] {
            for count in [0, 1, 2] {
                for incompatible in [false, true] {
                    assert_eq!(
                        validate_checkpoint_export_mode(focused, count, incompatible).is_ok(),
                        focused && count == 1 && !incompatible
                    );
                }
            }
        }
    }

    #[test]
    fn output_must_be_fresh_private_canonical_directory() {
        let root = tempfile::tempdir().unwrap();
        let path = fs::canonicalize(root.path()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(validate_checkpoint_export_directory(&path).is_ok());
        assert!(validate_checkpoint_export_directory(Path::new("relative")).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o750)).unwrap();
        assert!(validate_checkpoint_export_directory(&path).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        let file = path.join("earlier-attempt");
        fs::write(&file, b"preserve").unwrap();
        assert!(validate_checkpoint_export_directory(&path).is_err());
        assert!(validate_checkpoint_export_directory(&file).is_err());
        let links = tempfile::tempdir().unwrap();
        let link = links.path().join("alias");
        symlink(&path, &link).unwrap();
        assert!(validate_checkpoint_export_directory(&link).is_err());
        assert_eq!(fs::read(&file).unwrap(), b"preserve");
    }

    #[test]
    fn serialization_must_preserve_every_checkpoint_field_and_cursor() {
        let before = evidence();
        let mut after = before.clone();
        after.terminal.write_count = 0;
        assert!(validate_checkpoint_export_evidence(&before, &after).is_ok());
        let mutations: &[fn(&mut HistoricalCheckpointSummary)] = &[
            |v| v.slot += 1,
            |v| v.bank_hash[0] ^= 1,
            |v| v.accounts_hash[0] ^= 1,
            |v| v.last_blockhash[0] ^= 1,
            |v| v.capitalization += 1,
            |v| v.transaction_count += 1,
            |v| v.tick_height += 1,
            |v| v.slot_complete = false,
            |v| v.write_count += 1,
            |v| v.next_write_version += 1,
        ];
        for mutate in mutations {
            let mut changed = after.clone();
            mutate(&mut changed.terminal);
            assert!(validate_checkpoint_export_evidence(&before, &changed).is_err());
            let mut changed = after.clone();
            mutate(&mut changed.bootstrap);
            assert!(validate_checkpoint_export_evidence(&before, &changed).is_err());
        }
        let mut changed = after.clone();
        changed.emitted_write_versions.start += 1;
        assert!(validate_checkpoint_export_evidence(&before, &changed).is_err());
        changed = after;
        changed.emitted_write_versions.end += 1;
        assert!(validate_checkpoint_export_evidence(&before, &changed).is_err());
        assert!(validate_checkpoint_export_evidence(&before, &before).is_err());
    }
}
