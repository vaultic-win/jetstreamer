//! Retire only snapshot-reproducible files from the stopped epoch 288 accounts directory.
use super::{snapshot288::Stamp, *};
use std::{collections::BTreeMap, ffi::CString, os::unix::ffi::OsStrExt as _};

const REPRODUCTION: &str =
    "/var/lib/jetstreamer/horizon288-full-v303/unpacked-accounts-reproduction-v327.json";
const REPRODUCTION_SHA: &str = "37442a3c57a4882e719521ac60464ea1b1a47432112c9be493a9db355a29a567";
const BOOTSTRAP_COMPLETION: &str =
    "/var/lib/jetstreamer/horizon288-bootstrap-retirement-v327/completion.json";
const BOOTSTRAP_COMPLETION_SHA: &str =
    "fee12aff151d187cbd050afc5702ca9ad9de397c2ae7aa9b6a6f30be77958880";
const STATE: &str = "/var/lib/jetstreamer/horizon288-unpacked-retirement-v328";
const MATCHING: usize = 322_833;
const PROTECTED: usize = 7_757;
const MATCHING_BYTES: u64 = 51_918_905_344;
const PROTECTED_BYTES: u64 = 1_470_701_568;
const DEVICE: u64 = 66_305;
const INODE: u64 = 42_148_866;
const BATCH_SIZE: usize = 8192;

#[derive(Deserialize, Serialize)]
struct Asset {
    path: PathBuf,
    #[serde(flatten)]
    stamp: Stamp,
}

#[derive(Deserialize, Serialize)]
struct FileEntry {
    name: String,
    stamp: Stamp,
}

#[derive(Deserialize, Serialize)]
struct Ledger {
    anchors: Value,
    matching: Vec<FileEntry>,
    protected: Vec<FileEntry>,
}

struct Scope {
    run: PathBuf,
    target: PathBuf,
    bootstrap: Asset,
    archive: Asset,
    bank: Asset,
    anchors: Value,
}

impl Scope {
    fn from_receipts(proof: &Value, self_sha: &str) -> Result<Self> {
        ensure!(
            proof["schema"] == "foundation-epoch288-unpacked-accounts-reproduction-v327"
                && proof["epoch"] == 288
                && proof["checked_files"].as_u64() == Some(MATCHING as u64)
                && proof["file_count"].as_u64() == Some((MATCHING + PROTECTED) as u64)
                && proof["allocated_bytes"] == MATCHING_BYTES + PROTECTED_BYTES
                && proof["missing_from_snapshot"] == json!([])
                && proof["scratch_retired"] == false
                && proof["target"]["device"] == DEVICE
                && proof["target"]["inode"] == INODE
                && proof["target"]["uid"] == 1000,
            "reproduction receipt has the wrong scope"
        );
        let previous: Value = read_bound(
            Path::new(BOOTSTRAP_COMPLETION),
            BOOTSTRAP_COMPLETION_SHA,
            JSON_LIMIT,
        )?;
        let intent = value(&previous["intent"])?;
        let prior = &intent["anchors"];
        let copy: PathBuf = serde_json::from_value(prior["copy"].clone())?;
        let run = snapshot288::run_path(&copy)?.to_owned();
        let historical = copy
            .parent()
            .and_then(Path::parent)
            .context("historical root")?
            .join("jetstreamer-historical-v1.8.11-y3aKJ1");
        let target = historical.join("unpacked/accounts");
        let bootstrap: Asset = serde_json::from_value(proof["sealed_bootstrap"].clone())?;
        let archive = Asset {
            path: serde_json::from_value(prior["archive"].clone())?,
            stamp: serde_json::from_value(prior["archive_stamp"].clone())?,
        };
        let bank = Asset {
            path: serde_json::from_value(prior["bank"].clone())?,
            stamp: serde_json::from_value(prior["bank_stamp"].clone())?,
        };
        ensure!(
            proof["target"]["path"].as_str() == target.to_str()
                && prior["snapshot"].as_str() == bootstrap.path.to_str()
                && prior["qualification_sha256"] == proof["proof"]["sha256"]
                && archive.path == run.join("archives/epoch-288.jet")
                && bank.path == historical.join("accounts-state")
                && previous["epoch"] == 288
                && previous["original_snapshot_retained"] == true
                && previous["partial_archive_retained"] == true
                && previous["evolved_bank_retained"] == true,
            "reproduction and retired-bootstrap receipts disagree"
        );
        let anchors = json!({
            "epoch": 288, "self_sha256": self_sha,
            "reproduction_sha256": REPRODUCTION_SHA,
            "bootstrap_retirement_completion_sha256": BOOTSTRAP_COMPLETION_SHA,
            "target": proof["target"], "bootstrap": bootstrap, "archive": archive, "bank": bank,
            "batch_size": BATCH_SIZE,
        });
        Ok(Self {
            run,
            target,
            bootstrap,
            archive,
            bank,
            anchors,
        })
    }

    fn stable(&self, root: &File) -> Result<()> {
        self.bootstrap.stamp.at(&self.bootstrap.path)?;
        self.archive.stamp.at(&self.archive.path)?;
        self.bank.stamp.at(&self.bank.path)?;
        let current = self.target.symlink_metadata()?;
        ensure!(
            self.target.canonicalize()? == self.target
                && current.is_dir()
                && current.dev() == DEVICE
                && current.ino() == INODE
                && current.uid() == 1000
                && current.gid() == 1000
                && Stamp::of(&current)? == Stamp::of(&root.metadata()?)?,
            "unpacked accounts directory was replaced"
        );
        assert_no_nested_mount(&self.target)?;
        snapshot288::closed()
    }

    fn readers(&self) -> Result<Value> {
        let schedule = scheduled(&self.run, &self.target)?;
        let consumers = process_references::scan(Path::new("/proc"), &self.target)?;
        ensure!(
            consumers.inspected_processes > 0 && consumers.references.is_empty(),
            "live unpacked accounts reference"
        );
        Ok(json!({"scheduled": schedule, "consumers": consumers}))
    }
}

fn member_name(name: &str) -> Result<()> {
    let numeric = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    ensure!(
        name.len() <= 41
            && name
                .split_once('.')
                .is_some_and(|(slot, id)| numeric(slot) && numeric(id)),
        "invalid unpacked accounts member: {name:?}"
    );
    Ok(())
}

fn names(directory: &Path, maximum: usize) -> Result<Vec<String>> {
    let mut names = Vec::new();
    for item in fs::read_dir(directory)? {
        let name = item?
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("non-UTF8 unpacked accounts member"))?;
        member_name(&name)?;
        names.push(name);
        ensure!(
            names.len() <= maximum,
            "unexpected extra unpacked accounts members"
        );
    }
    names.sort_unstable();
    Ok(names)
}

fn file_stamp(m: &Metadata) -> Result<Stamp> {
    ensure!(
        m.is_file()
            && m.dev() == DEVICE
            && m.uid() == 1000
            && m.gid() == 1000
            && m.mode() & 0o7777 == 0o644
            && m.nlink() == 1,
        "unsafe unpacked accounts member"
    );
    Stamp::of(m)
}

// Publish a completely synchronized receipt under its final name in one no-clobber operation.
fn record(path: &Path, data: &impl Serialize) -> Result<Binding> {
    let parent = path.parent().context("receipt parent")?;
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    let tmp = parent.join(format!(".pending-{}-{nonce}", std::process::id()));
    let binding = write_json(&tmp, data)?;
    let from = CString::new(tmp.as_os_str().as_bytes())?;
    let to = CString::new(path.as_os_str().as_bytes())?;
    let result = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            from.as_ptr(),
            libc::AT_FDCWD,
            to.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result != 0 {
        let error = io::Error::last_os_error();
        fs::remove_file(&tmp)?;
        return Err(error).context("publish no-clobber receipt");
    }
    File::open(parent)?.sync_all()?;
    Ok(Binding {
        path: path.into(),
        sha256: binding.sha256,
    })
}

fn qualify(state: &Path, scope: &Scope, root: &File, dir: &Path, proof: &Value) -> Result<Binding> {
    let ledger_path = state.join("ledger.json");
    ensure!(
        ledger_path
            .symlink_metadata()
            .is_err_and(|error| error.kind() == io::ErrorKind::NotFound),
        "qualification ledger already exists or cannot be inspected"
    );
    let exceptions = proof["unexpected_or_changed_members"]
        .as_array()
        .context("missing protected members")?;
    let mut expected = BTreeMap::new();
    for entry in exceptions {
        let name = entry["name"].as_str().context("protected member name")?;
        member_name(name)?;
        let actual = entry["actual"].as_str().context("missing actual digest")?;
        ensure!(
            entry["reason"] == "digest"
                && entry["expected"] != actual
                && expected.insert(name, actual).is_none(),
            "invalid protected member evidence"
        );
    }
    ensure!(expected.len() == PROTECTED, "wrong protected member count");

    let readers = scope.readers()?;
    let before = Stamp::of(&root.metadata()?)?;
    let names = names(dir, MATCHING + PROTECTED)?;
    let mut aggregate = Sha256::new();
    let mut matching = Vec::with_capacity(MATCHING);
    let mut protected = Vec::with_capacity(PROTECTED);
    for name in names {
        let path = dir.join(&name);
        let stamp = file_stamp(&path.symlink_metadata()?)?;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NOATIME | libc::O_NONBLOCK)
            .open(&path)?;
        ensure!(
            file_stamp(&file.metadata()?)? == stamp,
            "member changed while opening: {name}"
        );
        let mut hash = Sha256::new();
        io::copy(&mut BufReader::new(&file), &mut hash)?;
        let hash = hash.finalize();
        ensure!(
            file_stamp(&file.metadata()?)? == stamp,
            "member changed while hashing: {name}"
        );
        stamp.at(&path)?;
        if let Some(expected_hash) = expected.remove(name.as_str()) {
            ensure!(
                format!("{hash:x}") == expected_hash,
                "protected member changed: {name}"
            );
            protected.push(FileEntry { name, stamp });
        } else {
            aggregate.update(name.as_bytes());
            aggregate.update([0]);
            aggregate.update(hash);
            matching.push(FileEntry { name, stamp });
        }
    }
    ensure!(
        expected.is_empty()
            && proof["file_hash_manifest_sha256"] == format!("{:x}", aggregate.finalize())
            && count_bytes(&matching, MATCHING)? == MATCHING_BYTES
            && count_bytes(&protected, PROTECTED)? == PROTECTED_BYTES,
        "current bytes do not reproduce the qualified partition"
    );
    scope.stable(root)?;
    ensure!(
        Stamp::of(&root.metadata()?)? == before,
        "directory changed while hashing"
    );
    let ledger = Ledger {
        anchors: scope.anchors.clone(),
        matching,
        protected,
    };
    let binding = record(&ledger_path, &ledger)?;
    record(
        &state.join("check.json"),
        &json!({"anchors": scope.anchors, "ledger": binding, "matching_files": MATCHING,
            "matching_allocated_bytes": MATCHING_BYTES, "protected_files": PROTECTED,
            "protected_allocated_bytes": PROTECTED_BYTES, "readers": readers}),
    )
}

fn count_bytes(files: &[FileEntry], count: usize) -> Result<u64> {
    ensure!(files.len() == count, "wrong ledger member count");
    files.iter().try_fold(0u64, |sum, file| {
        sum.checked_add(file.stamp.physical_bytes)
            .context("allocation overflow")
    })
}

fn present(dir: &Path, entry: &FileEntry, allow_absent: bool) -> Result<bool> {
    member_name(&entry.name)?;
    let path = dir.join(&entry.name);
    match path.symlink_metadata() {
        Ok(metadata) => {
            ensure!(
                Stamp::of(&metadata)? == entry.stamp,
                "member replaced or changed: {}",
                entry.name,
            );
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound && allow_absent => Ok(false),
        Err(error) => Err(error).with_context(|| format!("inspect {}", entry.name)),
    }
}

fn remove_planned(root: &File, dir: &Path, planned: &[FileEntry], resuming: bool) -> Result<()> {
    for entry in planned {
        if present(dir, entry, resuming)? {
            let name = CString::new(entry.name.as_str())?;
            let rc = unsafe { libc::unlinkat(root.as_raw_fd(), name.as_ptr(), 0) };
            ensure!(
                rc == 0,
                "unlink {}: {}",
                entry.name,
                io::Error::last_os_error()
            );
        }
    }
    root.sync_all()?;
    Ok(())
}

fn apply(state: &Path, scope: &Scope, root: &File, dir: &Path, batch: usize) -> Result<Binding> {
    let ledger_path = state.join("ledger.json");
    let (check_ref, check) = snapshot288::lookup_receipt(&state.join("check.json"))?
        .context("missing check-only receipt")?;
    let ledger_ref: Binding = serde_json::from_value(check["ledger"].clone())?;
    ensure!(
        ledger_ref.path == ledger_path && check["anchors"] == scope.anchors,
        "check-only receipt belongs to another operation"
    );
    let ledger: Ledger = read_bound(&ledger_path, &ledger_ref.sha256, LEDGER_LIMIT)?;
    ensure!(
        ledger.anchors == scope.anchors
            && count_bytes(&ledger.matching, MATCHING)? == MATCHING_BYTES
            && count_bytes(&ledger.protected, PROTECTED)? == PROTECTED_BYTES,
        "wrong unpacked retirement ledger"
    );
    let batches = MATCHING.div_ceil(BATCH_SIZE);
    ensure!(batch < batches, "batch index out of range");
    let start = batch * BATCH_SIZE;
    let end = (start + BATCH_SIZE).min(MATCHING);
    let planned = &ledger.matching[start..end];
    let completion_path = |i| state.join(format!("batch-{i:03}-completion.json"));
    let mut basis = json!({"check": check_ref, "batch": batch, "start": start, "end": end,
        "allocated_bytes": count_bytes(planned, end - start)?});
    if batch > 0 {
        let (reference, prior) = snapshot288::lookup_receipt(&completion_path(batch - 1))?
            .context("preceding retirement batch is incomplete")?;
        ensure!(
            prior["batch"] == batch - 1
                && prior["check"] == basis["check"]
                && prior["end"] == start,
            "preceding batch belongs to another ledger"
        );
        basis["predecessor"] = serde_json::to_value(reference)?;
    }

    let _cycle = lock(CYCLE_LOCK)?;
    let _mutation = lock(LOCAL_LOCK)?;
    scope.stable(root)?;
    let readers = scope.readers()?;
    let intent_path = state.join(format!("batch-{batch:03}-intent.json"));
    let pending = snapshot288::lookup_receipt(&intent_path)?;
    if let Some((_, prior)) = &pending {
        ensure!(
            prior["basis"] == basis,
            "batch intent belongs to another operation"
        );
    }
    let completion = snapshot288::lookup_receipt(&completion_path(batch))?;
    for entry in planned {
        let found = present(dir, entry, pending.is_some())?;
        ensure!(
            completion.is_none() || !found,
            "completed batch member still exists"
        );
    }
    for entry in &ledger.protected {
        present(dir, entry, false)?;
    }
    if let Some((reference, prior)) = completion {
        let (intent_ref, _) = pending.context("completion has no intent")?;
        ensure!(
            prior["check"] == basis["check"]
                && prior["batch"] == batch
                && prior["end"] == end
                && prior["intent"] == serde_json::to_value(intent_ref)?,
            "completion belongs to another operation"
        );
        return Ok(reference);
    }
    let resuming = pending.is_some();
    let intent = match pending {
        Some((reference, _)) => reference,
        None => record(&intent_path, &json!({"basis": basis, "readers": readers}))?,
    };
    scope.stable(root)?;
    remove_planned(root, dir, planned, resuming)?;
    scope.stable(root)?;
    for entry in planned {
        ensure!(!present(dir, entry, true)?, "batch member still exists");
    }
    for entry in &ledger.protected {
        present(dir, entry, false)?;
    }
    let final_batch = end == MATCHING;
    if final_batch {
        let current = names(dir, PROTECTED)?;
        ensure!(
            current
                .iter()
                .map(String::as_str)
                .eq(ledger.protected.iter().map(|e| e.name.as_str())),
            "final accounts inventory differs from the protected ledger"
        );
    }
    record(
        &completion_path(batch),
        &json!({"check": check_ref, "intent": intent, "batch": batch, "end": end,
            "allocated_bytes_removed": basis["allocated_bytes"], "retirement_complete": final_batch,
            "free_after_bytes": available(&scope.target)?, "readers": readers}),
    )
}

pub(super) fn run(self_sha: &str, batch: Option<usize>) -> Result<()> {
    let state = Path::new(STATE);
    let mode = state.symlink_metadata()?;
    ensure!(
        state.canonicalize()? == state
            && mode.is_dir()
            && mode.uid() == 0
            && mode.mode() & 0o077 == 0,
        "unsafe unpacked retirement state directory"
    );
    let proof: Value = read_bound(Path::new(REPRODUCTION), REPRODUCTION_SHA, JSON_LIMIT)?;
    let scope = Scope::from_receipts(&proof, self_sha)?;
    let root = stopped_tree::open_root(&scope.target, DEVICE, INODE)?;
    let dir = PathBuf::from(format!("/proc/self/fd/{}", root.as_raw_fd()));
    scope.stable(&root)?;
    let receipt = match batch {
        Some(batch) => apply(state, &scope, &root, &dir, batch)?,
        None => qualify(state, &scope, &root, &dir, &proof)?,
    };
    println!("{}", serde_json::to_string(&receipt)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checks_identity_and_only_allows_intent_backed_absence() {
        let temp = tempfile::tempdir().unwrap();
        let name = "123.456";
        let file = temp.path().join(name);
        fs::write(&file, b"matching").unwrap();
        let entry = FileEntry {
            name: name.into(),
            stamp: Stamp::of(&file.symlink_metadata().unwrap()).unwrap(),
        };
        assert!(present(temp.path(), &entry, false).unwrap());
        fs::write(&file, b"changed").unwrap();
        assert!(present(temp.path(), &entry, true).is_err());
        fs::rename(&file, temp.path().join("old")).unwrap();
        assert!(present(temp.path(), &entry, false).is_err());
        assert!(!present(temp.path(), &entry, true).unwrap());
        fs::write(&file, b"matching").unwrap();
        assert!(present(temp.path(), &entry, true).is_err());
    }

    #[test]
    fn rejects_paths_and_nonnumeric_member_names() {
        assert!(member_name("123.4").is_ok());
        for name in [
            "", ".", "..", "123", "1.2.3", "../1.2", "1/2.3", "1.a", "1.",
        ] {
            assert!(member_name(name).is_err(), "{name:?}");
        }
    }

    #[test]
    fn resumes_a_partly_removed_batch_and_preserves_protected_members() {
        let temp = tempfile::tempdir().unwrap();
        let root = File::open(temp.path()).unwrap();
        let dir = PathBuf::from(format!("/proc/self/fd/{}", root.as_raw_fd()));
        let entry = |name: &str| {
            let path = dir.join(name);
            fs::write(&path, b"original").unwrap();
            FileEntry {
                name: name.into(),
                stamp: Stamp::of(&path.symlink_metadata().unwrap()).unwrap(),
            }
        };
        let planned = [entry("1.1"), entry("1.2")];
        let protected = entry("1.3");
        fs::remove_file(dir.join("1.1")).unwrap();
        assert!(remove_planned(&root, &dir, &planned, false).is_err());
        assert!(present(&dir, &planned[1], false).unwrap());
        remove_planned(&root, &dir, &planned, true).unwrap();
        assert!(present(&dir, &protected, false).unwrap());
        assert_eq!(names(&dir, 1).unwrap(), ["1.3"]);
    }
}
