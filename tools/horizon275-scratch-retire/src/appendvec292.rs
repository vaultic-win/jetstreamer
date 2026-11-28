//! Local retirement of the one stopped AccountsDb tree proven by R2 restoration.
use super::{
    parked_accounts::{self, sealed},
    snapshot288::Stamp,
    *,
};
#[path = "appendvec292_failed_stage.rs"]
pub(super) mod failed;

const STATE: &str = "/var/lib/jetstreamer/horizon292-appendvec-retirement-v308";
const ISSUER_LOCK: &str = "/run/horizon292-300-finite-v205-a1/issuer.lock";
const RESTORE: &str = "/var/lib/jetstreamer/horizon292-appendvec-ram-restore-v308";
const RECEIPTS: &str = "/var/lib/jetstreamer/horizon-foundation-closed-private-holding-v1/receipts";
const QUALIFICATION: &str =
    "/var/lib/jetstreamer/horizon292-appendvec-ram-7bacea04-v308/qualification.json";
const QUALIFICATION_SHA: &str = "a1a92682d2a886acf4ffa988243fbb897d1bdffc5c6817d03f8e4822b4409d79";
const RESTORE_UNIT: &str = "horizon-restore-292-appendvec-ram-v308.service";
const STAGING_UNIT: &str = "foundation-292-closed-appendvec-staging-v308.service";
const TERMINAL: &str = "/var/lib/jetstreamer/horizon292-full-v322/terminal.json";
const TERMINAL_SHA: &str = "81cf3186abb14fb2033104606e761baa0b57b1d6468d206ca28511e1fffef48d";
const METADATA: &str = "/var/lib/jetstreamer/horizon230-remaining-replay-rotation-v1/epoch292-restore-metadata-v304.json";
const METADATA_SHA: &str = "3816233ef8a5e99b60b3618c9e4b211f5bfe7e0bc22ff6086b2552ff16e2563b";
const BUNDLE: &str = "/var/lib/jetstreamer/horizon292-closed-appendvec-staging-v308/bundle/epoch-292-closed-appendvecs.pax.zst";
const FILES: usize = 249_167;
const ALLOCATION: u64 = 432_056_471_552;
const CENSUS_SHA: &str = "ee80e57c04c0cc124272a5267905ccea878ba00f51bb1f5fa94d36e8d0c7f98a";

fn require_restore_exit(invocation: &str) -> Result<()> {
    ensure!(
        invocation.len() == 32 && invocation.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid RAM restore invocation"
    );
    terminal_unit(RESTORE_UNIT)?;
    let output = Command::new("/usr/bin/journalctl")
        .args(["-q", "--no-pager", "-o", "json", "_PID=1"])
        .arg(format!("UNIT={RESTORE_UNIT}"))
        .arg(format!("INVOCATION_ID={invocation}"))
        .output()?;
    ensure!(
        output.status.success(),
        "cannot read RAM restore terminal evidence"
    );
    let mut clean = 0;
    for line in output
        .stdout
        .split(|b| *b == b'\n')
        .filter(|line| !line.is_empty())
    {
        let event: Value = serde_json::from_slice(line)?;
        if event["MESSAGE"] == format!("{RESTORE_UNIT}: Deactivated successfully.") {
            ensure!(
                event["_PID"] == "1"
                    && event["UNIT"] == RESTORE_UNIT
                    && event["INVOCATION_ID"] == invocation,
                "foreign RAM restore terminal event"
            );
            clean += 1;
        }
    }
    ensure!(clean == 1, "RAM restore lacks a unique clean manager exit");
    Ok(())
}

fn file_stamp(metadata: &Metadata) -> Result<Value> {
    let mut stamp = serde_json::to_value(Stamp::of(metadata)?)?;
    stamp["mode"] = json!(metadata.mode() & 0o7777);
    Ok(stamp)
}

fn check_retained_archive(metadata: &Metadata, expected: &Value) -> Result<Value> {
    let actual = file_stamp(metadata)?;
    for key in [
        "device",
        "inode",
        "logical_bytes",
        "physical_bytes",
        "uid",
        "mode",
        "mtime_ns",
        "ctime_ns",
    ] {
        ensure!(
            actual[key] == expected[key],
            "retained stopped archive changed"
        );
    }
    Ok(actual)
}

pub(super) fn run(
    apply: bool,
    failed_stage: bool,
    self_sha: &str,
    comparison: Binding,
) -> Result<()> {
    let issuer = open_regular(Path::new(ISSUER_LOCK))?;
    let mode = issuer.metadata()?;
    ensure!(
        mode.uid() == 0
            && mode.gid() == 0
            && mode.mode() & 0o777 == 0o644
            && unsafe { libc::flock(issuer.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "epoch 292 issuer lock is unsafe or busy"
    );
    let _cycle = lock(CYCLE_LOCK)?;
    let _local = lock(LOCAL_LOCK)?;
    let comparison_ref = serde_json::to_value(&comparison)?;
    ensure!(
        comparison.path.parent() == Some(Path::new(RECEIPTS))
            && sealed(&comparison.path, JSON_LIMIT)?.sha256 == comparison.sha256,
        "comparison must be a sealed Foundation holding receipt"
    );
    let result: Value = read_bound(&comparison.path, &comparison.sha256, JSON_LIMIT)?;
    let spec_sha = result["spec"]["sha256"]
        .as_str()
        .context("missing restore spec digest")?;
    ensure!(
        comparison.path
            == Path::new(RECEIPTS).join(format!("appendvec292-ram-comparison-{spec_sha}.json"))
            && result["schema"] == "foundation-epoch292-appendvec-ram-comparison-v1"
            && result["epoch"] == 292
            && result["unit"] == RESTORE_UNIT
            && result["remote_sha256_readback"] == true
            && result["compressed_bundle_restored"] == true
            && result["comparison"]["full_sparse_payload_matches"] == true
            && result["comparison"]["source_census_matches_before_and_after"] == true
            && result["comparison"]["members"] == FILES
            && result["comparison"]["allocated_bytes"] == ALLOCATION
            && result["source_retirement_authorized"] == false
            && result["publication_authorized"] == false,
        "receipt does not prove a complete authenticated 292 restoration and tree comparison"
    );
    let start_path = Path::new(RESTORE).join("start.json");
    let start_ref = sealed(&start_path, JSON_LIMIT)?;
    let start: Value = read_bound(&start_path, &start_ref.sha256, JSON_LIMIT)?;
    let invocation = result["invocation_id"]
        .as_str()
        .context("missing restore invocation")?;
    ensure!(
        start["plan"] == result["spec"]
            && start["owner"]["InvocationID"] == invocation
            && start["owner"]["Id"] == RESTORE_UNIT
            && start["qualification"] == json!({"path":QUALIFICATION,"sha256":QUALIFICATION_SHA}),
        "restoration belongs to another service or sealed release"
    );
    let spec = value(&result["spec"])?;
    let custody = value(&result["custody"])?;
    ensure!(
        result["spec"]["path"] == format!("{RESTORE}/plan.json")
            && spec["custody"] == result["custody"]
            && spec["admission"] == result["admission"]
            && custody["schema"] == "foundation-epoch292-appendvec-custody-v1"
            && custody["epoch"] == 292
            && custody["remote_sha256_readback"] == true
            && custody["local_source_revalidated"] == true
            && custody["object_key"] == result["object_key"]
            && custody["object_etag"] == result["object_etag"]
            && custody["manifest"]["sha256"] == result["sha256"]
            && custody["manifest"]["length"] == result["length"]
            && custody["local_retirement_authorized"] == false
            && custody["publication_authorized"] == false,
        "foreign 292 custody or restored object identity"
    );
    require_restore_exit(invocation)?;
    terminal_unit(STAGING_UNIT)?;
    snapshot288::closed292()?;
    let metadata: Value = read_bound(Path::new(METADATA), METADATA_SHA, JSON_LIMIT)?;
    let target = Path::new(metadata["source"].as_str().context("missing 292 source")?);
    let terminal: Value = read_bound(Path::new(TERMINAL), TERMINAL_SHA, JSON_LIMIT)?;
    let native = value(&terminal["native_exit"])?;
    let retained = &native["original_custody"]["files"];
    let archive = Path::new(
        retained["archive"]["path"]
            .as_str()
            .context("missing stopped archive")?,
    );
    let run = Path::new(snapshot288::RUN292);
    ensure!(
        result["comparison"]["source"] == metadata["source"]
            && result["comparison"]["metadata"] == metadata
            && custody["manifest"]["restore_metadata"] == metadata
            && retained["evolved_accounts"]["path"] == metadata["source"]
            && target.starts_with(run.join("scratch"))
            && target.file_name().is_some_and(|p| p == "accounts-state")
            && archive == run.join("archives/epoch-292.jet"),
        "wrong stopped 292 source or retained archive"
    );
    let kept = open_regular(archive)?;
    let a = kept.metadata()?;
    let retained_stamp = check_retained_archive(&a, &retained["archive"])?;
    let bundle = open_regular(Path::new(BUNDLE))?;
    let b = bundle.metadata()?;
    ensure!(
        b.uid() == 1000 && b.mode() & 0o777 == 0o400 && result["length"] == b.len(),
        "closed local holding bundle is no longer retained"
    );
    let root_metadata = &metadata["directory_metadata"]["."];
    let device = root_metadata["device"]
        .as_u64()
        .context("missing source device")?;
    let inode = root_metadata["inode"]
        .as_u64()
        .context("missing source inode")?;
    let root = stopped_tree::open_root(target, device, inode)?;
    let anchors = json!({
        "self_sha256":self_sha,"comparison":comparison_ref,"restore_start":start_ref,
        "target":target,"device":device,"inode":inode,"retained_archive":retained_stamp,"local_bundle":file_stamp(&b)?,
    });
    let state = Path::new(STATE);
    let permissions = state.symlink_metadata()?;
    ensure!(
        state.canonicalize()? == state
            && permissions.is_dir()
            && permissions.uid() == 0
            && permissions.mode() & 0o777 == 0o700,
        "unsafe retirement state"
    );
    let capture = || stopped_tree::capture(&root, device, 1000, 1000);
    assert_no_nested_mount(target)?;
    if failed_stage {
        let (tree_ref, done) = snapshot288::lookup_receipt(&state.join("completion.json"))?
            .context("original AccountsDb retirement must be complete")?;
        ensure!(
            done["authorization"]["anchors"] == anchors
                && done["epoch"] == 292
                && done["empty_root_retained"] == true
                && capture()?.len() == 1,
            "failed-stage cleanup requires the same AccountsDb retirement and an empty root"
        );
        return failed::run(apply, state, &result, tree_ref);
    }
    let readers = failed::accounts_readers(run, target)?;
    parked_accounts::run(
        apply,
        parked_accounts::Tree {
            epoch: 292,
            state,
            root: &root,
            target,
            device,
            files: FILES,
            allocation: ALLOCATION,
            census_sha: CENSUS_SHA,
            anchors,
            readers,
        },
        || {
            ensure!(
                identity(&a) == identity(&archive.symlink_metadata()?)
                    && identity(&b) == identity(&Path::new(BUNDLE).symlink_metadata()?),
                "retained 292 evidence changed"
            );
            Ok(())
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "read-only probe against the original Foundation epoch 292 staging source"]
    fn original_staging_census_matches_retirement_preflight() -> Result<()> {
        let metadata: Value = read_bound(Path::new(METADATA), METADATA_SHA, JSON_LIMIT)?;
        let target = Path::new(metadata["source"].as_str().context("missing 292 source")?);
        let expected = &metadata["directory_metadata"]["."];
        let device = expected["device"]
            .as_u64()
            .context("missing source device")?;
        let inode = expected["inode"].as_u64().context("missing source inode")?;
        let root = stopped_tree::open_root(target, device, inode)?;
        let entries = stopped_tree::capture(&root, device, 1000, 1000)?;
        parked_accounts::require_census(target, FILES, CENSUS_SHA)?;
        ensure!(
            entries.len() == FILES + 5,
            "wrong original 292 tree member count"
        );
        let terminal: Value = read_bound(Path::new(TERMINAL), TERMINAL_SHA, JSON_LIMIT)?;
        let native = value(&terminal["native_exit"])?;
        let expected_archive = &native["original_custody"]["files"]["archive"];
        let archive = Path::new(
            expected_archive["path"]
                .as_str()
                .context("missing retained archive path")?,
        );
        check_retained_archive(&open_regular(archive)?.metadata()?, expected_archive)?;
        failed::accounts_readers(Path::new(snapshot288::RUN292), target)?;
        Ok(())
    }
}
