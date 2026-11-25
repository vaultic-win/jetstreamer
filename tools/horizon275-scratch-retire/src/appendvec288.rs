//! Retire only the closed epoch 288 AccountsDb proven by authenticated restoration.
use super::{
    parked_accounts::{self, sealed},
    selective_accounts::record,
    snapshot288::Stamp,
    *,
};
use std::{ffi::CString, os::unix::ffi::OsStrExt};

const CONTROL: &str = "/var/lib/jetstreamer/horizon288-closed-appendvec-study-v1";
const STATE: &str = "/var/lib/jetstreamer/horizon288-appendvec-retirement-v1";
const ISSUER: &str = "/run/horizon292-300-finite-v205-a1/issuer.lock";
const RECEIPTS: &str = "/var/lib/jetstreamer/horizon-foundation-closed-private-holding-v1/receipts";
const SAMPLE_SHA: &str = "5c07a84b6b2c7fd38dd5c3eb74db191b826d53b8827b5b9735d5c214188d6272";
const TERMINAL: &str = "/var/lib/jetstreamer/horizon288-full-v303/terminal.json";
const TERMINAL_SHA: &str = "876b040f74480907639e0321016b3f0187a2f45347ae8bc8523e32535db874d1";
const STAGE_UNIT: &str = "foundation-288-appendvec-stage-v2.service";
const CUSTODY_UNIT: &str = "foundation-288-appendvec-custody-v1.service";
const RESTORE_UNIT: &str = "horizon-restore-288-appendvec-stream-v1.service";
const BUNDLE: &str = "/home/ubuntu/.jetstreamer-private/epoch288-appendvec-stage-tmpfs-v1/epoch-288-closed-appendvecs.pax.zst";
const CENSUS_SHA: &str = "287f5bd0fa48f9d32b38198704762d462b9975702c9b64c5233944d8e19d8931";
const FILES: usize = 178_655;
const ALLOCATION: u64 = 421_629_886_464;
const DEVICE: u64 = 66_305;
const INODE: u64 = 54_691_869;

fn journal_event(matches: &[String]) -> Result<Value> {
    let output = Command::new("/usr/bin/journalctl")
        .args(["--quiet", "--no-pager", "-b", "--output=json", "--lines=2"])
        .args(matches)
        .output()?;
    ensure!(
        output.status.success(),
        "cannot inspect epoch 288 restoration journal"
    );
    serde_json::from_slice(&output.stdout)
        .context("missing unique epoch 288 restoration journal event")
}

fn restore_start(comparison: &Binding, result: &Value) -> Result<Binding> {
    let path = Path::new(CONTROL).join("comparison-start.json");
    let reference = sealed(&path, JSON_LIMIT)?;
    let start: Value = read_bound(&path, &reference.sha256, JSON_LIMIT)?;
    let invocation = start["owner"]["InvocationID"]
        .as_str()
        .context("missing comparison invocation")?;
    let pid = start["owner"]["MainPID"]
        .as_str()
        .context("missing comparison PID")?;
    let binary: Binding = serde_json::from_value(start["binary"].clone())?;
    ensure!(
        start["schema"] == "foundation-epoch288-appendvec-comparison-start-v1"
            && start["epoch"] == 288
            && start["unit"] == RESTORE_UNIT
            && start["plan"] == result["spec"]
            && start["owner"]["ControlGroup"] == format!("/system.slice/{RESTORE_UNIT}")
            && invocation.len() == 32
            && invocation.bytes().all(|b| b.is_ascii_hexdigit())
            && pid.parse::<u64>().is_ok_and(|id| id > 0)
            && start["canonical_archive_mutations"] == false
            && sealed(&binary.path, 128 << 20)?.sha256 == binary.sha256,
        "foreign comparison launch binding"
    );
    terminal_unit(RESTORE_UNIT)?;
    let terminal_message = format!("{RESTORE_UNIT}: Deactivated successfully.");
    let terminal = journal_event(&[
        "_PID=1".into(),
        format!("UNIT={RESTORE_UNIT}"),
        format!("INVOCATION_ID={invocation}"),
        format!("MESSAGE={terminal_message}"),
    ])?;
    let report = journal_event(&[
        format!("_PID={pid}"),
        format!("_SYSTEMD_UNIT={RESTORE_UNIT}"),
        format!("_SYSTEMD_INVOCATION_ID={invocation}"),
        format!("MESSAGE={}", comparison.path.display()),
    ])?;
    ensure!(
        terminal["_SYSTEMD_UNIT"] == "init.scope"
            && terminal["INVOCATION_ID"] == invocation
            && terminal["MESSAGE"] == terminal_message
            && report["_EXE"].as_str() == binary.path.to_str()
            && report["_SYSTEMD_INVOCATION_ID"] == invocation
            && report["MESSAGE"].as_str() == comparison.path.to_str(),
        "receipt did not come from the clean exact restore invocation"
    );
    Ok(reference)
}

fn lock_issuer() -> Result<File> {
    let issuer = open_regular(Path::new(ISSUER))?;
    let mode = issuer.metadata()?;
    ensure!(
        mode.uid() == 0
            && mode.gid() == 0
            && mode.mode() & 0o777 == 0o644
            && unsafe { libc::flock(issuer.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "epoch 288 issuer lock is unsafe or busy"
    );
    Ok(issuer)
}

pub(super) fn run(apply: bool, self_sha: &str, comparison: Binding) -> Result<()> {
    let _issuer = lock_issuer()?;
    let _cycle = lock(CYCLE_LOCK)?;
    let _local = lock(LOCAL_LOCK)?;
    ensure!(
        comparison.path.parent() == Some(Path::new(RECEIPTS))
            && sealed(&comparison.path, JSON_LIMIT)?.sha256 == comparison.sha256,
        "comparison must be a sealed Foundation holding receipt"
    );
    let result: Value = read_bound(&comparison.path, &comparison.sha256, JSON_LIMIT)?;
    let spec_sha = result["spec"]["sha256"]
        .as_str()
        .context("missing comparison spec hash")?;
    ensure!(
        comparison.path
            == Path::new(RECEIPTS).join(format!("appendvec288-stream-comparison-{spec_sha}.json"))
            && result["schema"] == "foundation-epoch288-appendvec-stream-comparison-v1"
            && result["epoch"] == 288
            && result["authenticated_remote_sha256_readback"] == true
            && result["complete_sparse_payload_matches"] == true
            && result["members"] == FILES
            && result["source_retirement_authorized"] == false
            && result["publication_authorized"] == false,
        "missing complete authenticated 288 source comparison"
    );
    for key in ["source_census_before", "source_census_after"] {
        let census = &result[key];
        ensure!(
            census["epoch"] == 288
                && census["census_sha256"] == CENSUS_SHA
                && census["process_scan"]["references"] == json!([]),
            "288 source census differs"
        );
    }
    let start = restore_start(&comparison, &result)?;
    terminal_unit(STAGE_UNIT)?;
    terminal_unit(CUSTODY_UNIT)?;
    snapshot288::closed()?;

    let spec = value(&result["spec"])?;
    let custody = value(&result["custody"])?;
    let sample_path = Path::new(CONTROL).join("sample-qualification.json");
    let sample: Value = read_bound(&sample_path, SAMPLE_SHA, JSON_LIMIT)?;
    let manifest = &custody["manifest"];
    ensure!(
        result["spec"]["path"] == format!("{CONTROL}/comparison.json")
            && spec["custody"] == result["custody"]
            && custody["schema"] == "foundation-epoch288-appendvec-custody-v1"
            && custody["epoch"] == 288
            && custody["remote_sha256_readback"] == true
            && custody["local_source_revalidated"] == true
            && custody["local_retirement_authorized"] == false
            && custody["publication_authorized"] == false
            && custody["object_key"] == result["object_key"]
            && custody["object_etag"] == result["object_etag"]
            && manifest["length"] == result["length"]
            && manifest["sha256"] == result["sha256"]
            && manifest["stage"]["source"] == sample["source"]
            && manifest["preserved_archive"] == sample["preserved_archive"]
            && manifest["source_census"] == sample["source_census"]
            && sample["source_census"]["allocated_bytes"] == ALLOCATION
            && result["source"] == sample["source"],
        "custody, original source, or restored object identity differs"
    );
    let terminal: Value = read_bound(Path::new(TERMINAL), TERMINAL_SHA, JSON_LIMIT)?;
    ensure!(
        terminal["epoch"] == 288
            && terminal["root_preserved"] == true
            && terminal["producer"]["LoadState"] == "not-found"
            && terminal["publication_authorized"] == false,
        "predecessor terminal receipt differs"
    );
    let target = Path::new(sample["source"].as_str().context("missing 288 source")?);
    let run = target
        .ancestors()
        .nth(5)
        .context("missing stopped run directory")?;
    let archive = run.join("archives/epoch-288.jet");
    ensure!(
        run.ends_with("root-cohort-288-288/run-750660-1795547371821978162")
            && target.starts_with(run.join("scratch"))
            && target
                .file_name()
                .is_some_and(|name| name == "accounts-state")
            && sample["preserved_archive"]["path"].as_str() == archive.to_str(),
        "wrong original 288 source or retained archive"
    );
    let archived = open_regular(&archive)?.metadata()?;
    ensure!(
        archived.uid() == 1000
            && archived.gid() == 1000
            && archived.mode() & 0o7777 == 0o600
            && archived.dev() == DEVICE
            && archived.ino() == 42_147_904
            && sample["preserved_archive"]["length"] == archived.len(),
        "retained 288 partial archive differs"
    );
    let bundle = Path::new(BUNDLE);
    let staged = open_regular(bundle)?.metadata()?;
    ensure!(
        staged.uid() == 0
            && staged.gid() == 0
            && staged.mode() & 0o7777 == 0o400
            && result["length"] == staged.len(),
        "retained verified 288 bundle differs"
    );
    let state = Path::new(STATE);
    let permissions = state.symlink_metadata()?;
    ensure!(
        state.canonicalize()? == state
            && permissions.is_dir()
            && permissions.uid() == 0
            && permissions.mode() & 0o777 == 0o700,
        "unsafe retirement state"
    );
    let root = stopped_tree::open_root(target, DEVICE, INODE)?;
    assert_no_nested_mount(target)?;
    let scheduled = scheduled(run, target)?;
    let processes = process_references::scan(Path::new("/proc"), target)?;
    ensure!(
        processes.inspected_processes > 0 && processes.references.is_empty(),
        "live epoch 288 source reference"
    );
    parked_accounts::run(
        apply,
        parked_accounts::Tree {
            epoch: 288,
            state,
            root: &root,
            target,
            device: DEVICE,
            files: FILES,
            allocation: ALLOCATION,
            census_sha: CENSUS_SHA,
            anchors: json!({
                "self_sha256":self_sha,"comparison":comparison,"restore_start":start,
                "target":target,"device":DEVICE,"inode":INODE,
                "retained_archive":Stamp::of(&archived)?,"local_bundle":Stamp::of(&staged)?,
            }),
            readers: json!({"scheduled":scheduled,"processes":processes}),
        },
        || {
            ensure!(
                identity(&archived) == identity(&archive.symlink_metadata()?)
                    && identity(&staged) == identity(&bundle.symlink_metadata()?),
                "retained 288 evidence changed"
            );
            Ok(())
        },
    )
}

pub(super) fn retire_bundle(apply: bool, self_sha: &str, retirement: Binding) -> Result<()> {
    let _issuer = lock_issuer()?;
    let _cycle = lock(CYCLE_LOCK)?;
    let _local = lock(LOCAL_LOCK)?;
    let state = Path::new(STATE);
    ensure!(
        retirement.path == state.join("completion.json")
            && sealed(&retirement.path, JSON_LIMIT)?.sha256 == retirement.sha256,
        "require the exact sealed AccountsDb retirement completion"
    );
    let completed: Value = value(&serde_json::to_value(&retirement)?)?;
    let anchors = &completed["authorization"]["anchors"];
    ensure!(
        completed["epoch"] == 288
            && completed["verified_allocated_bytes_removed"] == ALLOCATION
            && completed["empty_root_retained"] == true
            && completed["r2_mutations"] == false
            && completed["publication_authorized"] == false,
        "AccountsDb retirement has not completed"
    );
    let comparison: Binding = serde_json::from_value(anchors["comparison"].clone())?;
    let verified = value(&anchors["comparison"])?;
    ensure!(
        verified["schema"] == "foundation-epoch288-appendvec-stream-comparison-v1"
            && verified["authenticated_remote_sha256_readback"] == true
            && verified["complete_sparse_payload_matches"] == true
            && verified["members"] == FILES,
        "missing authenticated comparison of the holding bundle"
    );
    let start = restore_start(&comparison, &verified)?;
    ensure!(
        anchors["restore_start"] == serde_json::to_value(start)?,
        "retirement and restore invocation disagree"
    );
    for unit in [STAGE_UNIT, CUSTODY_UNIT] {
        terminal_unit(unit)?;
    }
    let source = Path::new(
        verified["source"]
            .as_str()
            .context("missing AccountsDb path")?,
    );
    let source_metadata = source.symlink_metadata()?;
    ensure!(
        anchors["target"] == verified["source"]
            && source.canonicalize()? == source
            && source_metadata.dev() == DEVICE
            && source_metadata.ino() == INODE
            && source.read_dir()?.next().is_none(),
        "retired AccountsDb root changed or contains files"
    );
    let custody = value(&verified["custody"])?;
    let archive = Path::new(
        custody["manifest"]["preserved_archive"]["path"]
            .as_str()
            .context("missing retained partial archive path")?,
    );
    let preserved: Stamp = serde_json::from_value(anchors["retained_archive"].clone())?;
    preserved.at(archive)?;
    let bundle = Path::new(BUNDLE);
    let mount = bundle.parent().context("missing staging mount")?;
    ensure!(mount.canonicalize()? == mount, "aliased staging mount");
    let parent = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(mount)?;
    let parent_meta = parent.metadata()?;
    let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe { libc::fstatfs(parent.as_raw_fd(), &mut fs) } == 0
            && fs.f_type == libc::TMPFS_MAGIC
            && parent_meta.dev() != Path::new("/").metadata()?.dev()
            && parent_meta.uid() == 0
            && parent_meta.gid() == 0
            && parent_meta.mode() & 0o777 == 0o700,
        "staging mount is not the private tmpfs"
    );
    let stamp: Stamp = serde_json::from_value(anchors["local_bundle"].clone())?;
    let authorization = json!({
        "source_retirement":retirement, "comparison":comparison, "bundle":bundle,
        "bundle_stamp":stamp, "self_sha256":self_sha,
    });
    let intent_path = state.join("bundle-retirement-intent.json");
    let completion_path = state.join("bundle-retirement-completion.json");
    let pending = snapshot288::lookup_receipt(&intent_path)?;
    if let Some((_, intent)) = &pending {
        ensure!(
            intent["authorization"] == authorization,
            "conflicting bundle retirement"
        );
    }
    let present = bundle.try_exists()?;
    let entries = mount.read_dir()?.collect::<io::Result<Vec<_>>>()?;
    ensure!(
        entries.len() == usize::from(present) && entries.iter().all(|entry| entry.path() == bundle),
        "unexpected staging mount contents"
    );
    if present {
        let metadata = open_regular(bundle)?.metadata()?;
        ensure!(
            Stamp::of(&metadata)? == stamp
                && metadata.uid() == 0
                && metadata.gid() == 0
                && metadata.mode() & 0o777 == 0o400
                && metadata.dev() == parent_meta.dev()
                && verified["length"] == metadata.len(),
            "staged bundle differs from the authenticated retirement anchors"
        );
    } else {
        ensure!(
            pending.is_some(),
            "staged bundle absent before retirement intent"
        );
    }
    if let Some((reference, done)) = snapshot288::lookup_receipt(&completion_path)? {
        ensure!(
            !present && done["authorization"] == authorization,
            "completed bundle retirement no longer matches the staging mount"
        );
        println!("{}", serde_json::to_string(&reference)?);
        return Ok(());
    }
    let readers = process_references::scan(Path::new("/proc"), bundle)?;
    ensure!(
        readers.inspected_processes > 0 && readers.references.is_empty(),
        "staged bundle has a live consumer"
    );
    let before = available(mount)?;
    if !apply {
        ensure!(
            pending.is_none() && present,
            "bundle retirement already started"
        );
        println!(
            "{}",
            json!({"authorization":authorization,"readers":readers,"free_before_bytes":before})
        );
        return Ok(());
    }
    let intent = match pending {
        Some((reference, _)) => reference,
        None => record(
            &intent_path,
            &json!({
                "authorization":authorization,"readers":readers,"free_before_bytes":before,
            }),
        )?,
    };
    if present {
        stamp.at(bundle)?;
        let name = CString::new(
            bundle
                .file_name()
                .context("missing bundle name")?
                .as_bytes(),
        )?;
        let result = unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) };
        if result != 0 {
            return Err(io::Error::last_os_error()).context("retire qualified tmpfs bundle");
        }
        parent.sync_all()?;
    }
    ensure!(
        mount.read_dir()?.next().is_none(),
        "staging mount not empty after retirement"
    );
    preserved.at(archive)?;
    let done = record(
        &completion_path,
        &json!({
            "schema":"foundation-epoch288-local-stage-bundle-retirement-v1","epoch":288,
            "authorization":authorization,"intent":intent,"verified_tmpfs_bytes_removed":stamp.physical_bytes,
            "free_at_attempt_start_bytes":before,"free_after_bytes":available(mount)?,
            "partial_archive_preserved":true,"publication_authorized":false,"r2_mutations":false,
        }),
    )?;
    println!("{}", serde_json::to_string(&done)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "read-only census of the original Foundation AccountsDb"]
    fn original_source_matches_retirement_census() -> Result<()> {
        let sample: Value = read_bound(
            &Path::new(CONTROL).join("sample-qualification.json"),
            SAMPLE_SHA,
            JSON_LIMIT,
        )?;
        let target = Path::new(sample["source"].as_str().context("288 source")?);
        let root = stopped_tree::open_root(target, DEVICE, INODE)?;
        assert_no_nested_mount(target)?;
        let entries = stopped_tree::capture(&root, DEVICE, 1000, 1000)?;
        ensure!(entries.len() == FILES + 5, "wrong source entry count");
        parked_accounts::require_census(target, FILES, CENSUS_SHA)?;
        stopped_tree::validate_remaining(
            &entries,
            &stopped_tree::capture(&root, DEVICE, 1000, 1000)?,
            false,
        )?;
        let archive = Path::new(
            sample["preserved_archive"]["path"]
                .as_str()
                .context("288 archive")?,
        );
        let meta = open_regular(archive)?.metadata()?;
        ensure!(
            sample["preserved_archive"]["device"] == meta.dev()
                && sample["preserved_archive"]["inode"] == meta.ino()
                && sample["preserved_archive"]["length"] == meta.len(),
            "retained partial archive differs"
        );
        Ok(())
    }
}
