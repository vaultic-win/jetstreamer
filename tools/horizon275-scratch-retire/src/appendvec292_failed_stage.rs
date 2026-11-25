//! Reclaim the failed staging file after the verified replacement retires its source tree.
use super::*;
use std::ffi::CString;

const STAGING: &str = "/var/lib/jetstreamer/horizon292-closed-appendvec-staging-v304";
const PART: &str = "epoch-292-closed-appendvecs.pax.zst.part";
const NORMALIZED: &str = "/var/lib/jetstreamer/horizon292-closed-appendvec-staging-v308/original-stage-normalized-tar-comparison.json";
const NORMALIZED_SHA: &str = "5f929fa5d08af50c0483237a1a0823e9d009381f6db7a95332ec16ccb50c7f51";
const PREFIX_SHA: &str = "554c078ba51a8917448b3ff45733e3a05e49cd4c9aec6783eb52cf1d5f89112c";
const FAILURE_SHA: &str = "242676ccd61cf7ea6d483a392d5955994cb545719c3dca91798b2a94871b75bb";
const TERMINAL_SHA: &str = "a220ca6d68b5fd7ef61ffdbbdbfc67ca7d70e7d7a7769de60a9fa0a32f253d42";
const DEVICE: u64 = 66_305;
const BUNDLE_DIR_INODE: u64 = 70_999_187;
const PART_INODE: u64 = 70_999_190;
const PART_ALLOCATION: u64 = 67_427_381_248;

// These are only stopped definitions of the original writer and its one
// read-only diagnosis. Any new scheduled or live reference blocks retirement.
const STOPPED: [(&str, &str, &str); 2] = [
    (
        "foundation-292-closed-appendvec-staging-v304.service",
        "6979fb77543c406d9f016656303e86cc",
        "8e23f5a0a03f4cab97e2470ec7a8cc8042f045a95ef6a4c2a6176535105d0fb5",
    ),
    (
        "foundation-292-staged-part-diagnosis-v307.service",
        "1e02b3d840774baa86f48fd6748f881f",
        "c41ccbd13e2a2a7fe69264d00b4d43f2f13a7d0b92c02d6634e61101b243ff68",
    ),
];

fn no_readers(scope: &Path, target: &Path) -> Result<Value> {
    let report = scheduled_census(scope, target)?;
    for (unit, invocation, _) in STOPPED {
        let output = Command::new("/usr/bin/systemctl")
            .args(["show", unit, "-p",
                "LoadState,ActiveState,MainPID,ControlPID,ControlGroup,Job,InvocationID,Restart,RequiredBy,WantedBy,Triggers,TriggeredBy,NRestarts"])
            .output()?;
        ensure!(
            output.status.success(),
            "cannot inspect stopped unit {unit}"
        );
        let text = std::str::from_utf8(&output.stdout)?;
        let lines: std::collections::BTreeSet<_> = text.lines().collect();
        for field in [
            "MainPID=0",
            "ControlPID=0",
            "ControlGroup=",
            "Job=",
            "RequiredBy=",
            "WantedBy=",
            "Triggers=",
            "TriggeredBy=",
        ] {
            ensure!(
                lines.contains(field),
                "old stage consumer {unit} is still scheduled"
            );
        }
        let failed = [
            "LoadState=loaded",
            "ActiveState=failed",
            "Restart=no",
            "NRestarts=0",
            &format!("InvocationID={invocation}"),
        ];
        let collected = [
            "LoadState=not-found",
            "ActiveState=inactive",
            "InvocationID=",
        ];
        ensure!(
            (failed.iter().all(|field| lines.contains(field))
                || collected.iter().all(|field| lines.contains(field)))
                && !Path::new("/sys/fs/cgroup/system.slice").join(unit).exists(),
            "foreign or still-running invocation for {unit}"
        );
    }
    for referrer in report["remaining"]
        .as_array()
        .context("invalid scheduled-reader response")?
    {
        ensure!(
            STOPPED.iter().any(|(unit, _, digest)| {
                referrer["origin"] == format!("/run/systemd/transient/{unit}")
                    && referrer["sha256"] == *digest
            }) && referrer["chain"] == json!([])
                && referrer["targets"] == json!([target]),
            "unexpected scheduled reference to failed stage"
        );
    }
    let processes = process_references::scan(Path::new("/proc"), target)?;
    ensure!(
        processes.inspected_processes > 0 && processes.references.is_empty(),
        "live failed-stage reference"
    );
    Ok(json!({"scheduled":report,"processes":processes}))
}

fn stage_stamp(m: &Metadata) -> Result<Value> {
    let stamp = file_stamp(m)?;
    Ok(json!({
        "device":stamp["device"],"inode":stamp["inode"],"bytes":stamp["logical_bytes"],
        "allocated":stamp["physical_bytes"],"uid":stamp["uid"],"gid":m.gid(),"mode":stamp["mode"],
        "links":stamp["links"],"mtime_ns":stamp["mtime_ns"],"ctime_ns":stamp["ctime_ns"],
    }))
}

fn partial_stamp(m: &Metadata) -> Result<Value> {
    ensure!(
        m.is_file()
            && m.dev() == DEVICE
            && m.ino() == PART_INODE
            && m.nlink() == 1
            && m.uid() == 1000
            && m.gid() == 1000
            && m.mode() & 0o777 == 0o600,
        "failed-stage file identity or permissions changed"
    );
    stage_stamp(m)
}

fn source_evidence(target: &Path, restored_sha: &Value, restored_length: &Value) -> Result<Value> {
    let normalized: Value = read_bound(Path::new(NORMALIZED), NORMALIZED_SHA, JSON_LIMIT)?;
    ensure!(
        normalized["schema"]
            == "foundation-epoch292-tar-sparse-header-normalized-supersession-v308-v1"
            && normalized["source"]["sha256"] == PREFIX_SHA
            && normalized["payload_prefix_equal"] == true
            && normalized["decoded_bytes_compared"] == 432_480_190_464u64
            && normalized["normalized_sparse_headers"] == 81_247
            && normalized["decoded_bytes_in_replacement_after_original"] == 587_776
            && normalized["retain_original_until_remote_restore_verified"] == true
            && normalized["source_bytes_reclaimed"] == 0,
        "missing exact decoded supersession proof"
    );
    let prefix = value(&normalized["source"])?;
    let failed = &prefix["original_partial"];
    let replacement = &prefix["newer_bundle"];
    ensure!(
        prefix["original_failure"]["sha256"] == FAILURE_SHA
            && prefix["complete_stage"]["sha256"] == TERMINAL_SHA
            && failed["path"] == json!(target)
            && failed["stamp"]["allocated"] == PART_ALLOCATION
            && replacement["path"] == BUNDLE
            && replacement["sha256"] == *restored_sha
            && replacement["stamp"]["bytes"] == *restored_length,
        "failed and replacement staging identities do not match the restore"
    );
    let failure = value(&prefix["original_failure"])?;
    ensure!(
        failure["original_manager_exit_status"] == 153
            && failure["failed_bytes_preserved"] == true
            && failure["retained_partial"]["inode"] == PART_INODE
            && failure["retained_partial"]["sha256"] == failed["sha256"]
            && failure["retained_partial"]["length"] == failed["stamp"]["bytes"],
        "failed-stage history differs"
    );
    let bundle = open_regular(Path::new(BUNDLE))?;
    ensure!(
        stage_stamp(&bundle.metadata()?)? == replacement["stamp"],
        "locally retained replacement changed after the decoded comparison"
    );
    Ok(failed.clone())
}

pub(super) fn run(apply: bool, state: &Path, restored: &Value, tree: Binding) -> Result<()> {
    let scope = Path::new(STAGING);
    let directory = scope.join("bundle");
    let target = directory.join(PART);
    let expected = source_evidence(&target, &restored["sha256"], &restored["length"])?;
    assert_no_nested_mount(scope)?;
    let directory_fd = stopped_tree::open_root(&directory, DEVICE, BUNDLE_DIR_INODE)?;
    let directory_mode = directory_fd.metadata()?;
    ensure!(
        directory_mode.uid() == 1000
            && directory_mode.gid() == 1000
            && directory_mode.mode() & 0o777 == 0o700,
        "failed-stage directory permissions changed"
    );
    let readers = no_readers(scope, &target)?;
    let evidence = json!({"tree_retirement":tree,"failed_source":expected,
        "normalized_comparison":{"path":NORMALIZED,"sha256":NORMALIZED_SHA}});
    let check_path = state.join("failed-stage-check.json");
    let intent_path = state.join("failed-stage-intent.json");
    let done_path = state.join("failed-stage-completion.json");
    let pending = snapshot288::lookup_receipt(&intent_path)?;
    let file = match target.symlink_metadata() {
        Ok(before) => {
            let file = open_regular(&target)?;
            ensure!(
                partial_stamp(&before)? == expected["stamp"]
                    && partial_stamp(&file.metadata()?)? == expected["stamp"],
                "failed-stage inode changed"
            );
            Some(file)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound && apply && pending.is_some() => None,
        Err(error) => return Err(error).context("cannot open the failed stage"),
    };
    if !apply && !check_path.try_exists()? {
        let checked = record(&check_path, &json!({"evidence":evidence,"readers":readers}))?;
        println!("{}", serde_json::to_string(&checked)?);
        return Ok(());
    }
    let (check_ref, checked) =
        snapshot288::lookup_receipt(&check_path)?.context("missing failed-stage check receipt")?;
    ensure!(
        checked["evidence"] == evidence,
        "different failed-stage check"
    );
    if !apply {
        println!("{}", serde_json::to_string(&check_ref)?);
        return Ok(());
    }
    let intent_data = json!({"check":check_ref,"evidence":evidence});
    let intent = match pending {
        Some((reference, value)) => {
            ensure!(
                value["intent"] == intent_data,
                "conflicting failed-stage intent"
            );
            reference
        }
        None => record(
            &intent_path,
            &json!({"intent":intent_data,"free_before_bytes":available(&directory)?}),
        )?,
    };
    if let Some((reference, done)) = snapshot288::lookup_receipt(&done_path)? {
        ensure!(
            file.is_none() && done["intent"] == serde_json::to_value(&intent)?,
            "failed-stage completion disagrees with local state"
        );
        println!("{}", serde_json::to_string(&reference)?);
        return Ok(());
    }
    if let Some(file) = file {
        let held_path = PathBuf::from(format!(
            "/proc/self/fd/{}/{}",
            directory_fd.as_raw_fd(),
            PART
        ));
        ensure!(
            partial_stamp(&held_path.symlink_metadata()?)? == expected["stamp"]
                && partial_stamp(&file.metadata()?)? == expected["stamp"],
            "failed-stage inode changed before unlink"
        );
        let leaf = CString::new(PART)?;
        ensure!(
            unsafe { libc::unlinkat(directory_fd.as_raw_fd(), leaf.as_ptr(), 0) } == 0,
            "failed-stage unlink failed: {}",
            io::Error::last_os_error()
        );
    }
    directory_fd.sync_all()?;
    ensure!(
        target
            .symlink_metadata()
            .is_err_and(|e| e.kind() == io::ErrorKind::NotFound)
            && directory.symlink_metadata()?.ino() == BUNDLE_DIR_INODE,
        "failed-stage final state differs"
    );
    let done = record(
        &done_path,
        &json!({
            "epoch":292,"intent":intent,"removed_allocated_bytes":PART_ALLOCATION,
            "free_after_bytes":available(&directory)?,"replacement_object_preserved":true,
            "r2_mutations":false,
        }),
    )?;
    println!("{}", serde_json::to_string(&done)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "read-only proof and manager census on the Foundation host"]
    fn exact_failed_artifact_has_only_the_two_stopped_writer_references() -> Result<()> {
        let scope = Path::new(STAGING);
        let target = scope.join("bundle").join(PART);
        let proof: Value = read_bound(Path::new(NORMALIZED), NORMALIZED_SHA, JSON_LIMIT)?;
        let prefix = value(&proof["source"])?;
        let evidence = source_evidence(
            &target,
            &prefix["newer_bundle"]["sha256"],
            &prefix["newer_bundle"]["stamp"]["bytes"],
        )?;
        ensure!(partial_stamp(&target.symlink_metadata()?)? == evidence["stamp"]);
        no_readers(scope, &target)?;
        Ok(())
    }
}
