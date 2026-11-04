//! Diagnostic native reads bound to every retained file of a complete tar census.
//! An authenticated tar may still be an incomplete original backup. This module
//! never promotes native open success or a value into source/liveness authority.

use {
    crate::horizon_ledger_tar::DiagnosticCollection,
    anyhow::{Context, Result, ensure},
    rocksdb::{DB, Options, ReadOptions},
    serde::Serialize,
    sha2::{Digest, Sha256},
    std::{
        collections::BTreeSet,
        fs::{self, OpenOptions},
        io::Read,
        os::unix::fs::{MetadataExt, OpenOptionsExt},
        path::{Component, Path},
    },
};

/// A bounded exact logical lookup. Key order is caller-defined and preserved.
#[derive(Debug)]
pub struct NativeQuery {
    /// Exact independently allowed column family.
    pub family: String,
    /// Complete key, never a first-match/prefix internal-version selection.
    pub key: Vec<u8>,
}

/// One native-resolved candidate, still lacking original-backup completeness proof.
#[derive(Debug, Serialize)]
pub struct NativeCandidate {
    /// Exact queried family.
    pub family: String,
    /// Exact queried key.
    pub key: Vec<u8>,
    /// Logical value after native WAL/version/tombstone resolution, or absence.
    /// Absence is not canonical absence without the separate source gates.
    pub value: Option<Vec<u8>>,
}

/// Complete-census diagnostic read result, never publication or liveness authority.
#[derive(Debug, Serialize)]
pub struct NativeResolution {
    /// Entire sorted manifest-declared family set, exactly matching caller policy.
    pub families: Vec<String>,
    /// Every requested exact logical lookup, in original order.
    pub candidates: Vec<NativeCandidate>,
    /// Number of native live SST references checked against the retained census.
    pub live_sst_references: usize,
    /// Every retained member and exact directory membership rehashed before/after.
    pub complete_census_revalidated: bool,
    /// Always false: full tar membership does not prove original backup completeness.
    pub source_completeness_proven: bool,
    /// Always false: native candidate reads alone are not trusted historical live state.
    pub live_state_proven: bool,
    /// Always false: no canonical checkpoint, PoH or publication gate is performed.
    pub publication_authorized: bool,
}

/// Explicit aggregate envelope for one read-only native session.
#[derive(Clone, Copy, Debug)]
pub struct NativeReadBudget {
    /// Maximum nonempty batches, at most 65,536.
    pub batches: usize,
    /// Maximum aggregate exact lookups, at most 16,777,216.
    pub queries: usize,
    /// Maximum aggregate returned value bytes, at most 32 GiB.
    pub value_bytes: u64,
}

/// A bounded reader; no native mutation handle is exposed.
///
/// Values read through this handle remain provisional until its enclosing
/// `with_native_read_session` returns successfully after closing and rehashing
/// the complete database. Durable batch outputs must say diagnostic/provisional;
/// only a subsequent final receipt may bind the completed session summary.
pub struct NativeReadSession {
    database: DB,
    families: BTreeSet<String>,
    budget: NativeReadBudget,
    batches: usize,
    queries: usize,
    value_bytes: u64,
    poisoned: bool,
}

/// Completed read-only session accounting, never source/publication authority.
#[derive(Debug, Serialize)]
pub struct NativeReadSummary {
    /// Exact full family census used by every batch.
    pub families: Vec<String>,
    /// Number of retained live SST references checked at native open.
    pub live_sst_references: usize,
    /// Number of nonempty batches completed.
    pub batches: usize,
    /// Total exact lookups completed, including deliberate metadata rechecks.
    pub queries: usize,
    /// Total returned value bytes across all batches.
    pub value_bytes: u64,
    /// Entire immutable file census rehashed before and after native close.
    pub complete_census_revalidated: bool,
    /// Always false: backup completeness is independently owed.
    pub source_completeness_proven: bool,
    /// Always false: original historical liveness is independently owed.
    pub live_state_proven: bool,
    /// Always false: no PoH, canonical root, or publication gate is performed.
    pub publication_authorized: bool,
}

impl NativeReadSession {
    /// Read one independently bounded exact-key batch in caller order.
    ///
    /// Every batch retains the legacy 65,536-query/64-MiB/1-MiB-per-value
    /// ceilings. Aggregate budgets additionally cap the entire session. Repeated
    /// keys across batches are permitted for explicit metadata rechecks; duplicate
    /// keys within a batch remain forbidden. Any error invalidates the session.
    pub fn read_candidates(
        &mut self,
        queries: &[NativeQuery],
        guard: &mut impl FnMut() -> Result<()>,
    ) -> Result<Vec<NativeCandidate>> {
        ensure!(!self.poisoned, "previous native batch failed");
        self.poisoned = true;
        ensure!(
            !queries.is_empty() && queries.len() <= 65_536,
            "native query bound exceeded"
        );
        self.batches = self.batches.checked_add(1).context("batch overflow")?;
        self.queries = self
            .queries
            .checked_add(queries.len())
            .context("query overflow")?;
        ensure!(
            self.batches <= self.budget.batches && self.queries <= self.budget.queries,
            "aggregate native query/batch budget exceeded"
        );
        let mut keys = BTreeSet::new();
        for query in queries {
            ensure!(
                self.families.contains(&query.family)
                    && !query.key.is_empty()
                    && query.key.len() <= 512
                    && keys.insert((query.family.clone(), query.key.clone())),
                "unsafe/duplicate native query"
            );
        }
        let mut candidates = Vec::with_capacity(queries.len());
        let mut read_options = ReadOptions::default();
        read_options.set_verify_checksums(true);
        let mut returned_bytes = 0u64;
        for query in queries {
            guard()?;
            let cf = self
                .database
                .cf_handle(&query.family)
                .context("opened family absent")?;
            let pinned = self
                .database
                .get_pinned_cf_opt(cf, &query.key, &read_options)?;
            if let Some(value) = &pinned {
                returned_bytes = returned_bytes
                    .checked_add(value.len() as u64)
                    .context("native result overflow")?;
                self.value_bytes = self
                    .value_bytes
                    .checked_add(value.len() as u64)
                    .context("aggregate native result overflow")?;
                ensure!(
                    value.len() <= 1024 * 1024
                        && returned_bytes <= 64 * 1024 * 1024
                        && self.value_bytes <= self.budget.value_bytes,
                    "native result byte bound exceeded"
                );
            }
            candidates.push(NativeCandidate {
                family: query.family.clone(),
                key: query.key.clone(),
                value: pinned.map(|value| value.to_vec()),
            });
        }
        self.poisoned = false;
        Ok(candidates)
    }
}

fn plain_basename(name: &str) -> bool {
    let path = Path::new(name);
    !name.is_empty()
        && name.len() <= 255
        && path.components().count() == 1
        && path.components().all(|c| matches!(c, Component::Normal(_)))
}

fn private_directory(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "noncanonical database/log directory"
    );
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_dir() && m.uid() == unsafe { libc::geteuid() } && m.mode() & 0o077 == 0,
        "database/log directory must be owned and private"
    );
    Ok(())
}

fn file_identity(m: &fs::Metadata) -> (u64, u64, u64, u32, u32, u64, i64, i64, i64, i64) {
    (
        m.dev(),
        m.ino(),
        m.len(),
        m.uid(),
        m.mode(),
        m.nlink(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}

type FileIdentity = (u64, u64, u64, u32, u32, u64, i64, i64, i64, i64);

fn verify_census(
    path: &Path,
    census: &DiagnosticCollection,
    guard: &mut impl FnMut() -> Result<()>,
) -> Result<Vec<FileIdentity>> {
    private_directory(path)?;
    ensure!(
        census.files_retained && !census.files.is_empty() && census.files.len() <= 100_000,
        "native reads require a bounded retained census, not a census-only scan"
    );
    let mut names = BTreeSet::new();
    let mut total = 0u64;
    let mut identities = Vec::with_capacity(census.files.len());
    let mut current_bytes = None;
    for file in &census.files {
        ensure!(
            plain_basename(&file.name) && names.insert(file.name.clone()),
            "unsafe/duplicate census member"
        );
        ensure!(
            file.sha256.len() == 64
                && file
                    .sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "invalid member digest"
        );
        total = total
            .checked_add(file.bytes)
            .context("census byte overflow")?;
        ensure!(
            total <= 16 * 1024 * 1024 * 1024 * 1024,
            "census input bound exceeded"
        );
        guard()?;
        let name = path.join(&file.name);
        let mut input = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(&name)?;
        let before = input.metadata()?;
        ensure!(
            before.is_file()
                && before.nlink() == 1
                && before.uid() == unsafe { libc::geteuid() }
                && before.mode() & 0o222 == 0
                && before.len() == file.bytes,
            "unsafe or mismatching retained member"
        );
        let mut hash = Sha256::new();
        let mut current = Vec::new();
        if file.name == "CURRENT" {
            ensure!(file.bytes <= 4096, "CURRENT exceeds metadata bound");
        }
        let mut count = 0u64;
        let mut buffer = [0u8; 65536];
        loop {
            guard()?;
            let n = input.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            count = count.checked_add(n as u64).context("read byte overflow")?;
            ensure!(count <= file.bytes, "retained member grew");
            hash.update(&buffer[..n]);
            if file.name == "CURRENT" {
                current.extend_from_slice(&buffer[..n]);
            }
        }
        ensure!(
            count == file.bytes && format!("{:x}", hash.finalize()) == file.sha256,
            "retained member digest/length mismatch"
        );
        ensure!(
            file_identity(&before) == file_identity(&input.metadata()?)
                && file_identity(&before) == file_identity(&fs::symlink_metadata(name)?),
            "retained member identity changed"
        );
        identities.push(file_identity(&before));
        if file.name == "CURRENT" {
            current_bytes = Some(current);
        }
    }
    ensure!(total == census.total_bytes, "census total mismatch");
    let actual: BTreeSet<_> = fs::read_dir(path)?
        .map(|e| {
            e?.file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("non-UTF8 database member"))
        })
        .collect::<Result<_>>()?;
    ensure!(
        names == actual,
        "retained directory membership differs from complete census"
    );
    ensure!(
        plain_basename(&census.current_manifest)
            && census.current_manifest.starts_with("MANIFEST-")
            && census
                .files
                .iter()
                .any(|f| f.name == census.current_manifest && f.bytes > 0),
        "CURRENT census manifest missing"
    );
    ensure!(
        current_bytes.context("CURRENT absent")?
            == format!("{}\n", census.current_manifest).as_bytes(),
        "CURRENT binding differs from census"
    );
    let wal: BTreeSet<_> = census
        .files
        .iter()
        .filter(|f| {
            f.name.ends_with(".log")
                && f.name[..f.name.len() - 4]
                    .bytes()
                    .all(|b| b.is_ascii_digit())
                && f.name.len() > 4
        })
        .map(|f| f.name.clone())
        .collect();
    ensure!(
        wal == census.wal_files.iter().cloned().collect(),
        "WAL census differs"
    );
    Ok(identities)
}

/// Resolve bounded exact keys with all native families, MANIFEST and WAL inputs.
///
/// Every input file is rehashed before opening and after closing the read-only
/// database. Live SST references must name retained files of the exact size.
/// The independent expected-family allowlist must equal the full native list,
/// including default; unknown or omitted families fail closed. Diagnostic logs
/// go only to a separate empty private directory. Guard checks cover streaming
/// hashes and each lookup; persistent callers still owe admission, process memory,
/// filesystem and wall-time protection around native calls. No backup-completeness,
/// shred decoding, canonical absence, historical liveness or publication is proven.
pub fn resolve_native_candidates(
    path: &Path,
    census: &DiagnosticCollection,
    log_path: &Path,
    expected_families: &[String],
    queries: &[NativeQuery],
    mut guard: impl FnMut() -> Result<()>,
) -> Result<NativeResolution> {
    let (candidates, summary) = with_native_read_session(
        path,
        census,
        log_path,
        expected_families,
        NativeReadBudget {
            batches: 1,
            queries: 65_536,
            value_bytes: 64 * 1024 * 1024,
        },
        &mut guard,
        |reader, guard| reader.read_candidates(queries, guard),
    )?;
    Ok(NativeResolution {
        families: summary.families,
        candidates,
        live_sst_references: summary.live_sst_references,
        complete_census_revalidated: summary.complete_census_revalidated,
        source_completeness_proven: false,
        live_state_proven: false,
        publication_authorized: false,
    })
}

/// Execute bounded batches inside one immutable, read-only native database open.
///
/// Rehashes every retained file before open and after close, enforces exact full
/// column-family and live-SST membership, and returns no successful final summary
/// if the callback, guard, or revalidation fails. Callback outputs may be streamed
/// to private provisional no-clobber records; those records must never claim the
/// session completed before this function returns. Persistent callers still owe
/// fresh admission, output budgets, service identity and hard resource ceilings.
#[allow(clippy::too_many_arguments)]
pub fn with_native_read_session<T, G: FnMut() -> Result<()>>(
    path: &Path,
    census: &DiagnosticCollection,
    log_path: &Path,
    expected_families: &[String],
    budget: NativeReadBudget,
    guard: &mut G,
    consume: impl FnOnce(&mut NativeReadSession, &mut G) -> Result<T>,
) -> Result<(T, NativeReadSummary)> {
    ensure!(
        (1..=65_536).contains(&budget.batches)
            && (1..=16_777_216).contains(&budget.queries)
            && (1..=32 * 1024 * 1024 * 1024).contains(&budget.value_bytes),
        "invalid aggregate native read budget"
    );
    let expected: BTreeSet<_> = expected_families.iter().cloned().collect();
    ensure!(
        expected.len() == expected_families.len()
            && expected.len() <= 64
            && expected.contains("default")
            && expected.iter().all(|f| plain_basename(f)),
        "invalid/duplicate native family allowlist"
    );
    let before_files = verify_census(path, census, guard)?;
    private_directory(log_path)?;
    ensure!(
        !log_path.starts_with(path)
            && !path.starts_with(log_path)
            && fs::read_dir(log_path)?.next().is_none(),
        "native logs overlap input or are not empty"
    );
    let before_directory = fs::symlink_metadata(path)?;
    let mut options = Options::default();
    options.set_db_log_dir(log_path);
    options.set_max_log_file_size(4 * 1024 * 1024);
    options.set_keep_log_file_num(2);
    options.set_max_open_files(128);
    options.set_paranoid_checks(true);
    guard()?;
    let families = DB::list_cf(&options, path)?;
    ensure!(
        families.iter().cloned().collect::<BTreeSet<_>>() == expected,
        "native full family census differs from independent allowlist"
    );
    let database = DB::open_cf_for_read_only(&options, path, &families, false)?;
    let live = database.live_files()?;
    ensure!(!live.is_empty(), "native manifest has no live SSTs");
    for item in &live {
        let name = item.name.strip_prefix('/').unwrap_or(&item.name);
        ensure!(
            plain_basename(name)
                && expected.contains(&item.column_family_name)
                && census
                    .files
                    .iter()
                    .any(|f| f.name == name && f.bytes == item.size as u64),
            "native live file reference absent from exact retained census"
        );
    }
    let mut session = NativeReadSession {
        database,
        families: expected.clone(),
        budget,
        batches: 0,
        queries: 0,
        value_bytes: 0,
        poisoned: false,
    };
    let result = consume(&mut session, guard)?;
    ensure!(
        !session.poisoned,
        "callback suppressed a native batch failure"
    );
    let NativeReadSession {
        database,
        batches,
        queries,
        value_bytes,
        ..
    } = session;
    ensure!(batches > 0, "native session performed no reads");
    drop(database);
    guard()?;
    let after_directory = fs::symlink_metadata(path)?;
    ensure!(
        (
            before_directory.dev(),
            before_directory.ino(),
            before_directory.uid(),
            before_directory.mode()
        ) == (
            after_directory.dev(),
            after_directory.ino(),
            after_directory.uid(),
            after_directory.mode()
        ),
        "database directory identity changed"
    );
    ensure!(
        before_files == verify_census(path, census, guard)?,
        "retained file identities changed across native resolution"
    );
    Ok((
        result,
        NativeReadSummary {
            families: expected.into_iter().collect(),
            batches,
            queries,
            value_bytes,
            live_sst_references: live.len(),
            complete_census_revalidated: true,
            source_completeness_proven: false,
            live_state_proven: false,
            publication_authorized: false,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::horizon_ledger_tar::CollectedFile;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn fixture() -> (tempfile::TempDir, DiagnosticCollection) {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let files: Vec<_> = [
            ("CURRENT", b"MANIFEST-1\n".as_slice()),
            ("MANIFEST-1", b"fixture-manifest".as_slice()),
            ("000002.sst", b"fixture-table".as_slice()),
            ("000003.log", b"fixture-wal".as_slice()),
        ]
        .into_iter()
        .map(|(name, bytes)| {
            let path = root.path().join(name);
            fs::write(&path, bytes).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o444)).unwrap();
            CollectedFile {
                name: name.into(),
                bytes: bytes.len() as u64,
                sha256: format!("{:x}", Sha256::digest(bytes)),
            }
        })
        .collect();
        let total_bytes = files.iter().map(|f| f.bytes).sum();
        (
            root,
            DiagnosticCollection {
                files_retained: true,
                archive_root: "rocksdb".into(),
                files,
                total_bytes,
                current_manifest: "MANIFEST-1".into(),
                wal_files: vec!["000003.log".into()],
                source_completeness_proven: false,
                live_state_resolved: false,
                publication_authorized: false,
            },
        )
    }

    #[test]
    fn complete_input_census_rejects_omission_extra_mutation_or_guard_failure() {
        let (root, census) = fixture();
        verify_census(root.path(), &census, &mut || Ok(())).unwrap();
        assert!(
            verify_census(root.path(), &census, &mut || anyhow::bail!("guard stopped")).is_err()
        );
        fs::remove_file(root.path().join("000003.log")).unwrap();
        assert!(verify_census(root.path(), &census, &mut || Ok(())).is_err());
        let (root, census) = fixture();
        fs::write(root.path().join("extra"), b"not in census").unwrap();
        assert!(verify_census(root.path(), &census, &mut || Ok(())).is_err());
        let (root, census) = fixture();
        let path = root.path().join("000003.log");
        fs::remove_file(&path).unwrap();
        fs::write(&path, b"changed-wal").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).unwrap();
        assert!(verify_census(root.path(), &census, &mut || Ok(())).is_err());
    }

    #[test]
    fn invalid_session_budgets_fail_before_any_guard_or_native_open() {
        let (root, census) = fixture();
        for budget in [
            NativeReadBudget {
                batches: 0,
                queries: 1,
                value_bytes: 1,
            },
            NativeReadBudget {
                batches: 65_537,
                queries: 1,
                value_bytes: 1,
            },
            NativeReadBudget {
                batches: 1,
                queries: 0,
                value_bytes: 1,
            },
            NativeReadBudget {
                batches: 1,
                queries: 16_777_217,
                value_bytes: 1,
            },
            NativeReadBudget {
                batches: 1,
                queries: 1,
                value_bytes: 0,
            },
            NativeReadBudget {
                batches: 1,
                queries: 1,
                value_bytes: 32 * 1024 * 1024 * 1024 + 1,
            },
        ] {
            let mut guard_calls = 0;
            let result = with_native_read_session(
                root.path(),
                &census,
                root.path(),
                &["default".into()],
                budget,
                &mut || {
                    guard_calls += 1;
                    Ok(())
                },
                |_, _| Ok(()),
            );
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("aggregate native read budget")
            );
            assert_eq!(guard_calls, 0);
        }
    }

    #[test]
    fn cannot_substitute_census_only_or_change_current_wal_and_total_bindings() {
        for change in 0..4 {
            let (root, mut census) = fixture();
            match change {
                0 => census.files_retained = false,
                1 => census.current_manifest = "MANIFEST-99".into(),
                2 => census.wal_files.clear(),
                _ => census.total_bytes += 1,
            }
            assert!(verify_census(root.path(), &census, &mut || Ok(())).is_err());
        }
    }

    #[test]
    fn rejects_linked_or_writable_inputs_and_detects_same_content_replacement() {
        for change in 0..3 {
            let (root, census) = fixture();
            let path = root.path().join("000003.log");
            match change {
                0 => fs::set_permissions(path, fs::Permissions::from_mode(0o644)).unwrap(),
                1 => {
                    fs::remove_file(&path).unwrap();
                    symlink("000002.sst", path).unwrap();
                }
                _ => {
                    fs::remove_file(&path).unwrap();
                    fs::hard_link(root.path().join("000002.sst"), path).unwrap();
                }
            }
            assert!(verify_census(root.path(), &census, &mut || Ok(())).is_err());
        }
        let (root, census) = fixture();
        let before = verify_census(root.path(), &census, &mut || Ok(())).unwrap();
        let path = root.path().join("000003.log");
        fs::rename(&path, root.path().join("preserve-original")).unwrap();
        fs::write(&path, b"fixture-wal").unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o444)).unwrap();
        fs::remove_file(root.path().join("preserve-original")).unwrap();
        let after = verify_census(root.path(), &census, &mut || Ok(())).unwrap();
        assert_ne!(before, after);
    }
}
