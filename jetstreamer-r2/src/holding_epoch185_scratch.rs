//! Exact stopped epoch 185 contents-only retirement. Network, replay, guard
//! changes and archive mutation are outside this profile's authority.
use super::*;
#[path = "../../jetstreamer-horizon-observe/src/stopped203_tree.rs"]
mod stopped_tree;

const DEVICE: u64 = 64512;
const INODE: u64 = 100270084;
const UID: u32 = 1001;
const GID: u32 = 1003;
const MAX_LEDGER: u64 = 1 << 30;
const MAX_PHYSICAL: u64 = 1_099_511_627_776;
const REVIEW_SHA: &str = "79a90c6852fe0092b5ac97edc5648932e698bd67d3696503bc7258a831858710";
const STATE_SHA: &str = "030ccd6e1f38d6ac38c993b55755daf73db50e297e16527e1ad2001ae301b365";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    mapping: Bound,
    archive_basis: Bound,
    retained_work: Value,
    source_review: Bound,
    diagnostic_packet: Bound,
    resource_budget: Bound,
    root: PathBuf,
    ledger: PathBuf,
    check_receipt: PathBuf,
    prior_check: Option<Bound>,
    intent: PathBuf,
    completion: PathBuf,
    contents_only_retirement_authorized: bool,
    preserve_scratch_inode: bool,
    replay_launch_authorized: bool,
    archive_deletion_authorized: bool,
    claim_release_authorized: bool,
    remote_mutations: bool,
    r2_mutations: bool,
}

fn scratch() -> PathBuf {
    Path::new(SOURCE)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("scratch")
}

fn authority(p: &Plan) -> Result<()> {
    ensure!(
        p.schema == "jetstreamer-horizon-epoch185-scratch-plan-v2"
            && p.root == scratch()
            && p.contents_only_retirement_authorized
            && p.preserve_scratch_inode
            && !p.replay_launch_authorized
            && !p.archive_deletion_authorized
            && !p.claim_release_authorized
            && !p.remote_mutations
            && !p.r2_mutations,
        "invalid epoch 185 contents-only authority"
    );
    Ok(())
}

fn scope(p: &Plan) -> Result<()> {
    authority(p)?;
    let paths = [&p.ledger, &p.check_receipt, &p.intent, &p.completion];
    let parent = p.ledger.parent().context("scratch ledger parent")?;
    ensure!(
        parent.starts_with("/var/lib/jetstreamer") && !parent.starts_with(&p.root),
        "scratch evidence must remain outside the run"
    );
    private(parent)?;
    let unique: BTreeSet<_> = paths.into_iter().collect();
    ensure!(
        unique.len() == 4
            && unique
                .iter()
                .all(|path| path.is_absolute() && path.parent() == Some(parent)),
        "scratch lifecycle paths overlap"
    );
    ensure!(
        p.retained_work["run_directory"] == p.root.parent().unwrap().to_str().unwrap()
            && p.retained_work["scratch"] == p.root.to_str().unwrap()
            && p.retained_work["run_uid"] == UID
            && p.retained_work["operator_review"] == serde_json::to_value(&p.source_review)?
            && p.source_review.sha256 == REVIEW_SHA,
        "scratch retained-work scope differs"
    );
    let root = fs::symlink_metadata(&p.root)?;
    ensure!(
        root.is_dir()
            && root.dev() == DEVICE
            && root.ino() == INODE
            && root.uid() == UID
            && root.gid() == GID
            && root.mode() & 0o7777 == 0o700,
        "epoch 185 scratch directory identity changed"
    );
    let review = bound(&p.source_review)?;
    ensure!(
        review["schema"] == "jetstreamer-epoch185-scratch-source-review-v2"
            && review["scratch_inode"] == INODE
            && review["scratch_device"] == DEVICE
            && review["producer_invocation_id"] == PRODUCER_ID
            && review["controller_invocation_id"] == CONTROLLER_ID
            && review["qualified_in_place_continuation"] == false
            && review["preserve_exact_scratch_directory_inode"] == true
            && review["contents_only_profile_required"] == true,
        "source review does not bind the exact non-resumable generation"
    );
    Ok(())
}

fn packet(p: &Plan) -> Result<Value> {
    let v = bound(&p.diagnostic_packet)?;
    ensure!(
        v["schema"] == "jetstreamer-epoch185-scratch-diagnostics-v2"
            && v["source_review"] == serde_json::to_value(&p.source_review)?
            && v["scratch"] == p.root.to_str().unwrap(),
        "foreign scratch diagnostic packet"
    );
    let entries = v["files"].as_array().context("diagnostic files missing")?;
    ensure!(entries.len() <= 64, "diagnostic member budget exceeded");
    let mut roles = BTreeSet::new();
    let mut total = 0u64;
    for item in entries {
        let role = item["role"].as_str().context("diagnostic role missing")?;
        ensure!(roles.insert(role), "duplicate diagnostic role");
        let b: Bound = serde_json::from_value(item["binding"].clone())?;
        ensure!(
            !b.path.starts_with(Path::new(LANE)),
            "diagnostics still inside retired run"
        );
        let identity = fs::symlink_metadata(&b.path)?;
        ensure!(
            identity.is_file()
                && identity.uid() == 0
                && identity.mode() & 0o222 == 0
                && identity.nlink() == 1
                && identity.len() <= 128 << 20
                && b.path.canonicalize()? == b.path,
            "unsafe diagnostic member"
        );
        total = total
            .checked_add(identity.len())
            .context("diagnostic size overflow")?;
        ensure!(
            total <= 512 << 20 && stream_hash(&b.path)? == b.sha256,
            "diagnostic bytes changed or budget exceeded"
        );
        if role == "cohort-state" {
            ensure!(b.sha256 == STATE_SHA, "diagnostic state differs");
        }
    }
    for role in [
        "cohort-state",
        "source-excerpts",
        "build-evidence",
        "unit-configs",
        "worker-journal",
        "controller-journal",
        "checkpoint-metadata",
        "segment-manifests",
    ] {
        ensure!(
            roles.contains(role),
            "required diagnostic role missing: {role}"
        );
    }
    Ok(v)
}

fn stream_hash(path: &Path) -> Result<String> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let before = identity(&file.metadata()?);
    let mut hash = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hash.update(&buf[..n]);
    }
    ensure!(
        before == identity(&file.metadata()?) && before == regular_identity(path)?,
        "scratch evidence changed while hashing"
    );
    Ok(hex_lower(&hash.finalize()))
}

fn fences(p: &Plan, m: &Mapping) -> Result<(Value, Value)> {
    scope(p)?;
    let archive = bound(&p.archive_basis)?;
    ensure!(
        archive["mapping"] == serde_json::to_value(&p.mapping)?,
        "archive mapping differs"
    );
    let (fresh, disposition, retired) = retire::scratch_basis(m, archive)?;
    growth::queued_entry_check()?;
    let lifecycle = staged::fenced_for_growth()?;
    mount_scope(&fs::read_to_string("/proc/self/mountinfo")?, &p.root)?;
    let processes = no_references(Path::new(LANE))?;
    let staged =
        jetstreamer_horizon_observe::dev_cache_check::sol_staged_path_references(Path::new(LANE))?;
    ensure!(
        staged["references"] == json!([]),
        "scratch still has staged consumers"
    );
    let retained = reserve_scratch::preserved185(p.retained_work.clone(), retired)?;
    let diagnostic = packet(p)?;
    let common = json!({"root":p.root,"device":DEVICE,"inode":INODE,"uid":UID,"gid":GID,
        "tool_sha256":stream_hash(&fs::read_link("/proc/self/exe")?)?,
        "mapping":p.mapping,"retained_work":retained,"archive_disposition":disposition,
        "source_review":p.source_review,"diagnostic_packet":p.diagnostic_packet,"diagnostic":diagnostic,
        "resource_budget_scope":resource_budget(p, &fresh)?,
        "ledger":p.ledger,"check_receipt":p.check_receipt,"intent":p.intent,"completion":p.completion,
        "contents_only":true,"scratch_inode_preserved":true,"claims_released":false,
        "replay_launch_authorized":false,"archive_deletion_authorized":false,
        "remote_mutations":false,"r2_mutations":false});
    Ok((
        common,
        json!({"capacity":fresh,"lifecycle":lifecycle,"processes":processes,"staged":staged,
            "resource_budget":p.resource_budget}),
    ))
}

fn resource_budget(p: &Plan, fresh: &Value) -> Result<Value> {
    let mut b = bound(&p.resource_budget)?;
    ensure!(
        b["schema"] == "jetstreamer-epoch185-scratch-resource-budget-v2"
            && b["host"] == HOST
            && b["epoch"] == 185
            && b["ledger_max_bytes"] == MAX_LEDGER
            && b["diagnostics_max_bytes"] == 512u64 << 20
            && b["memory_max_bytes"] == 4u64 << 30
            && b["cpu_quota_percent"] == 100
            && b["ledger_and_diagnostics_filesystem"] == "/var/lib"
            && b["additional_data_growth_bytes"] == 0
            && b["pre_cleanup_free_space_credit"] == 0
            && b["claim_release_authorized"] == false
            && b["new_launch_authorized"] == false,
        "scratch resource budget is missing or grants broader capacity"
    );
    let admission: Bound = serde_json::from_value(b["resource_admission"].clone())?;
    let admitted = evidence(&admission, false)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    ensure!(
        admitted["schema"] == "jetstreamer-epoch185-scratch-resource-admission-v2"
            && admitted["host"] == HOST
            && admitted["epoch"] == 185
            && admitted["scratch"] == p.root.to_str().unwrap()
            && admitted["fleet"] == fresh["fleet"]
            && admitted["memory_reservation_bytes"] == 4u64 << 30
            && admitted["os_reservation_bytes"] == 1_627_389_952u64
            && admitted["data_reservation_bytes"] == 0
            && admitted["other_claims_preserved"] == true
            && admitted["new_launch_authorized"] == false
            && admitted["pre_cleanup_free_space_credit"] == 0
            && admitted["recorded_unix_seconds"]
                .as_u64()
                .is_some_and(|t| t <= now && now - t <= 900),
        "scratch resource admission is stale, foreign or incomplete"
    );
    b.as_object_mut()
        .context("resource budget object")?
        .remove("resource_admission");
    Ok(b)
}

fn mount_scope(mountinfo: &str, target: &Path) -> Result<()> {
    for line in mountinfo.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        ensure!(
            fields.len() >= 10 && fields.contains(&"-"),
            "malformed scratch mountinfo"
        );
        let mount = Path::new(fields[4]);
        // The sandbox may bind the exact, independently inode-checked root.
        // Any descendant mount creates an unqualified traversal boundary.
        ensure!(
            mount == target || !mount.starts_with(target),
            "scratch contains a nested mount"
        );
    }
    Ok(())
}

struct BoundedWriter {
    file: File,
    written: u64,
}
impl std::io::Write for BoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.written.saturating_add(bytes.len() as u64) > MAX_LEDGER {
            return Err(std::io::Error::other("scratch ledger exceeds 1 GiB"));
        }
        let n = self.file.write(bytes)?;
        self.written += n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

fn write_ledger(path: &Path, ledger: &stopped_tree::Ledger) -> Result<Bound> {
    let parent = path.parent().context("scratch ledger parent missing")?;
    private(parent)?;
    let temp = tempfile::Builder::new()
        .prefix(".scratch-ledger.")
        .tempfile_in(parent)?;
    let file = temp.as_file().try_clone()?;
    let mut writer = BoundedWriter { file, written: 0 };
    serde_json::to_writer(&mut writer, ledger)?;
    writer.file.sync_all()?;
    writer
        .file
        .set_permissions(fs::Permissions::from_mode(0o400))?;
    drop(writer);
    persist_noclobber(temp, path)?;
    Ok(Bound {
        path: path.into(),
        sha256: stream_hash(path)?,
    })
}

fn read_ledger(b: &Bound) -> Result<stopped_tree::Ledger> {
    let metadata = fs::symlink_metadata(&b.path)?;
    let before = regular_identity(&b.path)?;
    ensure!(
        metadata.uid() == 0
            && metadata.mode() & 0o7777 == 0o400
            && metadata.nlink() == 1
            && before.length <= MAX_LEDGER
            && stream_hash(&b.path)? == b.sha256,
        "scratch ledger binding differs"
    );
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&b.path)?;
    ensure!(
        identity(&file.metadata()?) == before,
        "scratch ledger changed at open"
    );
    let ledger = serde_json::from_reader(std::io::BufReader::new(file))?;
    ensure!(
        regular_identity(&b.path)? == before,
        "scratch ledger changed at read"
    );
    Ok(ledger)
}

fn bounded_tree(root: &File) -> Result<stopped_tree::Ledger> {
    let ledger = stopped_tree::capture(root, DEVICE, UID, GID)?;
    // The primitive's fields are intentionally private. Inspect its serialized
    // metadata without opening or reading any mutable replay data file.
    let mut physical = 0u64;
    for entry in ledger.values() {
        let v = serde_json::to_value(entry)?;
        physical = physical
            .checked_add(
                v["blocks"]
                    .as_u64()
                    .context("scratch block count")?
                    .checked_mul(512)
                    .context("scratch block overflow")?,
            )
            .context("scratch size overflow")?;
        ensure!(
            physical <= MAX_PHYSICAL,
            "scratch exceeds the 1 TiB physical scope"
        );
    }
    Ok(ledger)
}

fn record(path: &Path) -> Result<Option<Value>> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).context("scratch lifecycle metadata unavailable"),
        Ok(_) => {
            let sha256 = stream_hash(path)?;
            Ok(Some(evidence(
                &Bound {
                    path: path.into(),
                    sha256,
                },
                false,
            )?))
        }
    }
}

pub(super) fn run(m: &Mapping, value: Value, spec: &Bound, check: bool) -> Result<()> {
    let p: Plan = serde_json::from_value(value)?;
    let _mutation = retire::mutation_lock()?;
    let (common, observed) = fences(&p, m)?;
    let root = stopped_tree::open_root(&p.root, DEVICE, INODE)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    if check {
        ensure!(
            p.prior_check.is_none()
                && record(&p.intent)?.is_none()
                && record(&p.completion)?.is_none(),
            "scratch check cannot borrow lifecycle authority"
        );
        let ledger = bounded_tree(&root)?;
        let ledger_bound = write_ledger(&p.ledger, &ledger)?;
        let again = bounded_tree(&root)?;
        stopped_tree::validate_remaining(&ledger, &again, false)?;
        ensure!(
            fences(&p, m)?.0 == common,
            "preserved work changed during scratch check"
        );
        persist(
            &p.check_receipt,
            &json!({"schema":"jetstreamer-epoch185-scratch-check-v2",
            "spec":spec,"common":common,"ledger":ledger_bound,"observed":observed,
            "checked":true,"data_removed":false,
            "recorded_unix_seconds":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()}),
        )?;
        println!("{}", p.check_receipt.display());
        return Ok(());
    }
    let prior_bound = p
        .prior_check
        .as_ref()
        .context("scratch execution requires prior CHECK")?;
    ensure!(
        prior_bound.path == p.check_receipt,
        "foreign scratch CHECK path"
    );
    let checked = evidence(prior_bound, false)?;
    ensure!(
        checked["schema"] == "jetstreamer-epoch185-scratch-check-v2"
            && checked["common"] == common
            && checked["checked"] == true
            && checked["data_removed"] == false,
        "scratch CHECK scope differs"
    );
    let ledger_bound: Bound = serde_json::from_value(checked["ledger"].clone())?;
    ensure!(ledger_bound.path == p.ledger, "foreign scratch ledger path");
    let expected = read_ledger(&ledger_bound)?;
    let intent = json!({"schema":"jetstreamer-epoch185-scratch-intent-v2","common":common,
        "ledger":ledger_bound,"prior_check":prior_bound});
    let old_intent = record(&p.intent)?;
    let completed = record(&p.completion)?;
    if let Some(old) = &old_intent {
        ensure!(*old == intent, "scratch intent differs");
    }
    if let Some(done) = completed {
        ensure!(
            old_intent.is_some()
                && done["intent"] == intent
                && done["schema"] == "jetstreamer-epoch185-scratch-completion-v2"
                && done["contents_removed"] == true
                && done["scratch_inode_preserved"] == true
                && done["claims_released"] == false
                && bounded_tree(&root)?.len() == 1,
            "scratch completed state changed"
        );
        println!("{}", p.completion.display());
        return Ok(());
    }
    if old_intent.is_none() {
        ensure!(
            checked["recorded_unix_seconds"]
                .as_u64()
                .is_some_and(|t| t <= now && now - t <= 900),
            "scratch CHECK is stale"
        );
        stopped_tree::validate_remaining(&expected, &bounded_tree(&root)?, false)?;
        persist(&p.intent, &intent)?;
    } else {
        stopped_tree::validate_remaining(&expected, &bounded_tree(&root)?, true)?;
    }
    ensure!(
        fences(&p, m)?.0 == common,
        "preserved work changed before scratch unlink"
    );
    let removed = stopped_tree::remove_contents(&root, &expected, DEVICE, UID, GID)?;
    ensure!(
        bounded_tree(&root)?.len() == 1 && fences(&p, m)?.0 == common,
        "scratch root, preserved work or claims changed"
    );
    persist(
        &p.completion,
        &json!({"schema":"jetstreamer-epoch185-scratch-completion-v2",
        "intent":intent,"contents_removed":true,"scratch_inode_preserved":true,
        "removed_entries_this_invocation":removed,"claims_released":false,
        "recorded_unix_seconds":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()}),
    )?;
    println!("{}", p.completion.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn fixture() -> Value {
        let b = json!({"path":"/sealed/input.json","sha256":"a".repeat(64)});
        json!({"schema":"jetstreamer-horizon-epoch185-scratch-plan-v2",
            "mapping":b,"archive_basis":b,"source_review":b,"diagnostic_packet":b,"resource_budget":b,
            "retained_work":{},"root":scratch(),"ledger":"/var/lib/jetstreamer/profile/ledger.json",
            "check_receipt":"/var/lib/jetstreamer/profile/check.json","prior_check":null,
            "intent":"/var/lib/jetstreamer/profile/intent.json",
            "completion":"/var/lib/jetstreamer/profile/completion.json",
            "contents_only_retirement_authorized":true,"preserve_scratch_inode":true,
            "replay_launch_authorized":false,"archive_deletion_authorized":false,
            "claim_release_authorized":false,"remote_mutations":false,"r2_mutations":false})
    }

    #[test]
    fn scratch_authority_cannot_select_another_run_archive_or_parent() {
        let good: Plan = serde_json::from_value(fixture()).unwrap();
        authority(&good).unwrap();
        for root in [
            PathBuf::from(LANE),
            PathBuf::from(SOURCE),
            scratch().join("accounts"),
            PathBuf::from("/home/sol/.jetstreamer-private/other-run/scratch"),
        ] {
            let mut v = fixture();
            v["root"] = json!(root);
            assert!(authority(&serde_json::from_value(v).unwrap()).is_err());
        }
    }

    #[test]
    fn scratch_plan_cannot_release_claims_or_grant_other_authority() {
        for field in [
            "replay_launch_authorized",
            "archive_deletion_authorized",
            "claim_release_authorized",
            "remote_mutations",
            "r2_mutations",
            "contents_only_retirement_authorized",
            "preserve_scratch_inode",
        ] {
            let mut v = fixture();
            v[field] = json!(!v[field].as_bool().unwrap());
            assert!(
                authority(&serde_json::from_value(v).unwrap()).is_err(),
                "{field}"
            );
        }
        let mut v = fixture();
        v["remove_root"] = json!(true);
        assert!(serde_json::from_value::<Plan>(v).is_err());
    }

    #[test]
    fn exact_root_mount_is_allowed_but_descendant_and_malformed_mounts_are_not() {
        let target = scratch();
        mount_scope(
            &format!("1 0 1:2 / {} rw - ext4 disk rw", target.display()),
            &target,
        )
        .unwrap();
        assert!(
            mount_scope(
                &format!("1 0 1:2 / {}/accounts rw - ext4 disk rw", target.display()),
                &target
            )
            .is_err()
        );
        assert!(mount_scope("malformed", &target).is_err());
        mount_scope(
            &format!("1 0 1:2 / {}-sibling rw - ext4 disk rw", target.display()),
            &target,
        )
        .unwrap();
    }

    #[test]
    fn primitive_preserves_root_and_authenticates_partial_unlink_recovery() {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let md = fs::metadata(temp.path()).unwrap();
        for name in ["a", "b"] {
            fs::write(temp.path().join(name), b"discardable").unwrap();
        }
        let root = stopped_tree::open_root(temp.path(), md.dev(), md.ino()).unwrap();
        let expected = stopped_tree::capture(&root, md.dev(), md.uid(), md.gid()).unwrap();
        fs::remove_file(temp.path().join("a")).unwrap();
        let remaining = stopped_tree::capture(&root, md.dev(), md.uid(), md.gid()).unwrap();
        assert!(stopped_tree::validate_remaining(&expected, &remaining, false).is_err());
        stopped_tree::validate_remaining(&expected, &remaining, true).unwrap();
        stopped_tree::remove_contents(&root, &expected, md.dev(), md.uid(), md.gid()).unwrap();
        assert_eq!(fs::metadata(temp.path()).unwrap().ino(), md.ino());
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 0);
    }

    #[test]
    fn primitive_rejects_injected_replacement_and_links_before_unlink() {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let md = fs::metadata(temp.path()).unwrap();
        let root = stopped_tree::open_root(temp.path(), md.dev(), md.ino()).unwrap();
        fs::write(temp.path().join("old"), b"retained").unwrap();
        let expected = stopped_tree::capture(&root, md.dev(), md.uid(), md.gid()).unwrap();
        symlink("old", temp.path().join("injected")).unwrap();
        assert!(
            stopped_tree::remove_contents(&root, &expected, md.dev(), md.uid(), md.gid()).is_err()
        );
        assert!(temp.path().join("old").exists());
        fs::remove_file(temp.path().join("injected")).unwrap();
        fs::rename(temp.path().join("old"), temp.path().join("replaced")).unwrap();
        fs::write(temp.path().join("old"), b"replacement").unwrap();
        assert!(
            stopped_tree::remove_contents(&root, &expected, md.dev(), md.uid(), md.gid()).is_err()
        );
        assert!(temp.path().join("old").exists());
    }

    #[test]
    fn ledger_byte_budget_fails_without_writing_the_excess() {
        let temp = tempfile::tempfile().unwrap();
        let mut writer = BoundedWriter {
            file: temp,
            written: MAX_LEDGER - 1,
        };
        assert!(writer.write_all(b"xx").is_err());
        assert_eq!(writer.file.metadata().unwrap().len(), 0);
    }
}
