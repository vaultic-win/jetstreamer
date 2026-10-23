//! Read the current producer's private archive before cohort import.
use super::*;
use std::os::unix::ffi::OsStrExt;

#[derive(Serialize)]
pub(super) struct Measurement {
    pub jet_size_bytes: u64,
    path: PathBuf,
    source: &'static str,
    cohort_state_sha256: Option<String>,
}

fn private_directory(path: &Path, uid: u32) -> Result<(u64, u64)> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_dir() && m.uid() == uid && m.mode() & 0o077 == 0 && path.canonicalize()? == path,
        "full227 archive directory is not canonical and owner-private: {}",
        path.display()
    );
    Ok((m.dev(), m.ino()))
}

fn size(path: &Path, uid: u32) -> Result<Option<u64>> {
    let a = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    ensure!(
        a.is_file() && a.uid() == uid && a.nlink() == 1,
        "full227 unsafe partial archive"
    );
    let b = fs::symlink_metadata(path)?;
    ensure!(
        b.is_file()
            && b.uid() == uid
            && b.nlink() == 1
            && b.dev() == a.dev()
            && b.ino() == a.ino()
            && b.len() >= a.len(),
        "full227 partial archive was replaced or shrank"
    );
    Ok(Some(a.len()))
}

pub(super) fn measure(root: &Path, pid: u64, fingerprint: &str, uid: u32) -> Result<Measurement> {
    ensure!(pid > 1, "full227 invalid producer PID");
    let output = root.join("output");
    let private = root.join("private");
    let scope = private.join(format!(
        "destination-{}",
        hex_lower(&Sha256::digest(output.as_os_str().as_bytes()))
    ));
    let work = scope.join("work");
    let cohort = work.join("root-cohort-227-227");
    let mut directories = Vec::new();
    for p in [root, &output, &private, &scope, &work, &cohort] {
        directories.push((p.to_owned(), private_directory(p, uid)?));
    }
    let final_path = output.join("epoch-227.jet");
    let final_size = size(&final_path, uid)?;
    let prefix = format!("run-{pid}-");
    let mut candidates = Vec::new();
    for (index, entry) in fs::read_dir(&cohort)?.enumerate() {
        ensure!(index < 64, "full227 cohort run census exceeds its bound");
        let entry = entry?;
        let name = entry.file_name();
        let Some(suffix) = name.to_str().and_then(|s| s.strip_prefix(&prefix)) else {
            continue;
        };
        ensure!(
            !suffix.is_empty()
                && suffix.bytes().all(|b| b.is_ascii_digit())
                && suffix.parse::<u128>().is_ok_and(|n| n > 0),
            "full227 malformed producer run identity"
        );
        candidates.push(entry.path());
    }
    ensure!(candidates.len() <= 1, "full227 ambiguous producer run");
    let measurement = if let Some(run) = candidates.first() {
        let archives = run.join("archives");
        for p in [run, &archives] {
            directories.push((p.to_owned(), private_directory(p, uid)?));
        }
        let state_path = run.join("cohort-state.json");
        let state_meta = fs::symlink_metadata(&state_path)?;
        ensure!(
            state_meta.is_file()
                && state_meta.uid() == uid
                && state_meta.nlink() == 1
                && state_meta.mode() & 0o777 == 0o600,
            "full227 unsafe cohort state"
        );
        let bytes = read_stable_bounded(&state_path, 65536, "full227 cohort state")?;
        let state: Value = serde_json::from_slice(&bytes)?;
        ensure!(
            state
                == json!({"schema":"jetstreamer-root-cohort-run-v1","status":"running-private",
                "start_epoch":227,"end_epoch":227,"manifest_fingerprint":fingerprint}),
            "full227 cohort state does not bind the producer's manifest"
        );
        let path = archives.join("epoch-227.jet");
        let private_size = size(&path, uid)?;
        if let (Some(a), Some(b)) = (private_size, final_size) {
            ensure!(
                a == b,
                "full227 private and imported archive lengths differ"
            );
        }
        match (private_size, final_size) {
            (None, Some(imported)) => Measurement {
                jet_size_bytes: imported,
                path: final_path,
                source: "import-destination",
                cohort_state_sha256: Some(hex_lower(&Sha256::digest(&bytes))),
            },
            (partial, _) => Measurement {
                jet_size_bytes: partial.unwrap_or(0),
                path,
                source: "private-root-cohort",
                cohort_state_sha256: Some(hex_lower(&Sha256::digest(&bytes))),
            },
        }
    } else {
        Measurement {
            jet_size_bytes: final_size
                .context("full227 current producer run and archive absent")?,
            path: final_path,
            source: "import-destination",
            cohort_state_sha256: None,
        }
    };
    for (path, identity) in directories {
        ensure!(
            private_directory(&path, uid)? == identity,
            "full227 archive directory changed during measurement"
        );
    }
    Ok(measurement)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt, symlink};
    const PID: u64 = 1234;
    fn fixture() -> (tempfile::TempDir, PathBuf) {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let output = root.path().join("output");
        let cohort = root
            .path()
            .join("private")
            .join(format!(
                "destination-{}",
                hex_lower(&Sha256::digest(output.as_os_str().as_bytes()))
            ))
            .join("work/root-cohort-227-227");
        let run = cohort.join(format!("run-{PID}-1000000000000000000"));
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(run.join("archives"))
            .unwrap();
        fs::DirBuilder::new().mode(0o700).create(output).unwrap();
        fs::write(
            run.join("cohort-state.json"),
            serde_json::to_vec(&json!({
            "schema":"jetstreamer-root-cohort-run-v1","status":"running-private", "start_epoch":227,
            "end_epoch":227,"manifest_fingerprint":"sha256:fixture"}))
            .unwrap(),
        )
        .unwrap();
        fs::set_permissions(
            run.join("cohort-state.json"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        (root, run)
    }
    fn read(root: &Path) -> Result<Measurement> {
        measure(root, PID, "sha256:fixture", unsafe { libc::geteuid() })
    }
    #[test]
    fn measures_live_private_growth_before_the_import_destination_exists() {
        let (root, run) = fixture();
        assert_eq!(read(root.path()).unwrap().jet_size_bytes, 0);
        let path = run.join("archives/epoch-227.jet");
        fs::write(&path, b"private-prefix").unwrap();
        assert_eq!(read(root.path()).unwrap().jet_size_bytes, 14);
        fs::write(&path, b"private-prefix-more").unwrap();
        assert_eq!(read(root.path()).unwrap().jet_size_bytes, 19);
        assert!(!root.path().join("output/epoch-227.jet").exists());
    }
    #[test]
    fn rejects_foreign_or_ambiguous_runs_and_wrong_manifests() {
        let (root, run) = fixture();
        assert!(
            measure(root.path(), PID + 1, "sha256:fixture", unsafe {
                libc::geteuid()
            })
            .is_err()
        );
        assert!(measure(root.path(), PID, "sha256:wrong", unsafe { libc::geteuid() }).is_err());
        let other = run
            .parent()
            .unwrap()
            .join(format!("run-{PID}-2000000000000000000"));
        fs::DirBuilder::new().mode(0o700).create(&other).unwrap();
        assert!(read(root.path()).is_err());
    }
    #[test]
    fn never_follows_archive_symlinks_or_multiple_hard_links() {
        let (root, run) = fixture();
        let source = root.path().join("unrelated");
        fs::write(&source, b"unrelated").unwrap();
        let path = run.join("archives/epoch-227.jet");
        symlink(&source, &path).unwrap();
        assert!(read(root.path()).is_err());
        fs::remove_file(&path).unwrap();
        fs::hard_link(&source, &path).unwrap();
        assert!(read(root.path()).is_err());
    }
    #[test]
    fn retains_the_imported_size_after_committed_run_cleanup() {
        let (root, run) = fixture();
        fs::write(root.path().join("output/epoch-227.jet"), b"imported").unwrap();
        fs::remove_dir_all(&run).unwrap();
        let m = read(root.path()).unwrap();
        assert_eq!(m.jet_size_bytes, 8);
        assert_eq!(m.source, "import-destination");
    }
}
