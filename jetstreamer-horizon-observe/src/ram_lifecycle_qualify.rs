//! Actual persistent-RAM scratch lifecycle qualification. The only new mutable
//! data is one explicitly disposable 4096-byte fixture beneath a completed
//! no-entry capability's empty scratch. No replay or remote access occurs.
use {
    crate::{ram_artifact_retention as retained, ram_scratch_retire as retirement},
    anyhow::{Context, Result, ensure},
    serde::Deserialize,
    serde_json::{Value, json},
    sha2::{Digest, Sha256},
    std::{
        env,
        fs::{self, File, OpenOptions},
        io::Write,
        os::{
            fd::AsRawFd,
            unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        },
        path::{Path, PathBuf},
        process::Command,
    },
};
const MARKER: &str = ".retirement-lifecycle-fixture";
const BYTES: [u8; 4096] = [0xa5; 4096];
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    retirement_plan: retained::Bound,
    retirement_binary: retained::Bound,
    worker_sha256: String,
    output: PathBuf,
}
fn validate_plan(p: &Plan) -> Result<()> {
    ensure!(
        p.schema == "jetstreamer-private-epoch203-ram-lifecycle-qualification-plan-v1"
            && matches!(
                p.worker_sha256.as_str(),
                "3f5e8efec328b3e00dd9ce5ae396fc4067e6be6554e4da8831a13273186a748a"
                    | "4aeca56378a4bb2c55d0e590c1e334c4afa6a375a2c0d94894b412bea261f1cc"
            ),
        "unbound lifecycle profile"
    );
    ensure!(
        p.output
            .file_name()
            .is_some_and(|s| s == "qualification.json")
            && p.output.parent().and_then(Path::parent) == Some(Path::new("/var/lib/jetstreamer"))
            && p.output
                .parent()
                .and_then(Path::file_name)
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with("horizon-203-ram-lifecycle-qualify-")),
        "unsafe lifecycle evidence destination"
    );
    Ok(())
}
fn verify_binary(bound: &retained::Bound) -> Result<()> {
    let (sha, m) = retained::hash_file(&bound.path, 32 << 20)?;
    ensure!(
        sha == bound.sha256
            && m.uid() == 0
            && m.mode() & 0o222 == 0
            && bound.path.canonicalize()? == bound.path
            && bound
                .path
                .file_name()
                .is_some_and(|s| s == "jetstreamer-epoch203-ram-retire-scratch"),
        "unsealed or wrong scratch retirement executable"
    );
    Ok(())
}
fn create_fixture(scratch: &Path, device: u64, inode: u64) -> Result<Value> {
    let before = fs::symlink_metadata(scratch)?;
    ensure!(
        scratch.canonicalize()? == scratch
            && before.is_dir()
            && before.dev() == device
            && before.ino() == inode
            && before.uid() == 1000
            && before.gid() == 1000
            && before.mode() & 0o777 == 0o700
            && fs::read_dir(scratch)?.next().is_none(),
        "fixture requires exact EMPTY completed capability scratch"
    );
    let path = scratch.join(MARKER);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)?;
    file.write_all(&BYTES)?;
    ensure!(
        unsafe { libc::fchown(file.as_raw_fd(), 1000, 1000) } == 0,
        "fixture ownership failed"
    );
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    file.sync_all()?;
    let m = file.metadata()?;
    ensure!(
        m.is_file()
            && m.dev() == device
            && m.uid() == 1000
            && m.gid() == 1000
            && m.nlink() == 1
            && m.len() == 4096,
        "fixture identity differs"
    );
    File::open(scratch)?.sync_all()?;
    Ok(
        json!({"relative_path":format!("scratch/{MARKER}"),"bytes":4096,"device":m.dev(),"inode":m.ino(),
        "sha256":format!("{:x}",Sha256::digest(BYTES)),"disposable_fixture_only":true,"canonical_archive":false}),
    )
}
fn invoke(p: &Plan, check: bool, output: &Path) -> Result<Value> {
    verify_binary(&p.retirement_binary)?;
    let mut command = Command::new(&p.retirement_binary.path);
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .arg(&p.retirement_plan.path)
        .args([
            "--plan-sha256",
            &p.retirement_plan.sha256,
            "--self-sha256",
            &p.retirement_binary.sha256,
        ]);
    if check {
        command.arg("--check-only");
    }
    let result = command.output()?;
    ensure!(
        result.stdout.len() <= 65536 && result.stderr.len() <= 65536,
        "child output exceeds qualification bound"
    );
    let child = json!({"program":p.retirement_binary.path,"program_sha256":p.retirement_binary.sha256,
        "plan":p.retirement_plan.path,"plan_sha256":p.retirement_plan.sha256,"check_only":check,
        "exit_code":result.status.code(),"success":result.status.success(),
        "stdout":String::from_utf8_lossy(&result.stdout),"stderr":String::from_utf8_lossy(&result.stderr)});
    retirement::persist(output, &child)?;
    ensure!(
        result.status.success(),
        "lifecycle retirement child failed; preserve fixture and exact child evidence"
    );
    Ok(child)
}
fn validate_no_entry(outcome: &Value, worker: &str) -> Result<()> {
    ensure!(
        outcome["schema"] == "jetstreamer-private-epoch203-ram-supervisor-storage-capability-v1"
            && outcome["entry_replay"] == false
            && outcome["node_arguments_executed"] == false
            && outcome["worker_ipc_qualified"] == false
            && outcome["worker_sha256"] == worker
            && outcome["profile"] == "jetstreamer-private-epoch203-ram-bounded-runner-plan-v1",
        "fixture mutation is limited to an actual completed NO-ENTRY capability"
    );
    Ok(())
}
fn validate_completed(
    p: &Plan,
    check: &Value,
    check_sha: &str,
    intent: &Value,
    completed: &Value,
) -> Result<()> {
    ensure!(
        check["schema"] == "jetstreamer-private-epoch203-ram-scratch-check-v1"
            && check["plan_sha256"] == p.retirement_plan.sha256
            && check["self_sha256"] == p.retirement_binary.sha256
            && check["tree"]
                .as_object()
                .is_some_and(|t| t.len() == 2 && t.contains_key("") && t.contains_key(MARKER))
            && intent["schema"] == "jetstreamer-private-epoch203-ram-scratch-intent-v1"
            && intent["plan_sha256"] == p.retirement_plan.sha256
            && intent["self_sha256"] == p.retirement_binary.sha256
            && intent["check_sha256"] == check_sha
            && completed["schema"] == "jetstreamer-private-epoch203-ram-scratch-completion-v1"
            && completed["plan_sha256"] == p.retirement_plan.sha256
            && completed["self_sha256"] == p.retirement_binary.sha256
            && completed["check_sha256"] == check_sha
            && completed["removed_entries_this_invocation"] == 1
            && completed["resumed"] == false
            && completed["scratch_empty"] == true
            && completed["scratch_root_preserved"] == true
            && completed["archive_and_metadata_preserved"] == true
            && completed["mount_preserved"] == true
            && completed["archive_deletion_authorized"] == false
            && completed["unmount_authorized"] == false
            && completed["r2_mutations"] == false,
        "actual populated scratch lifecycle proof is incomplete or mismatched"
    );
    Ok(())
}

/// Qualify actual RAM create/check/intent/unlink/preserve operations with no
/// entries, worker IPC, runtime promotion or publication authority.
pub fn run() -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "lifecycle qualification requires root"
    );
    let args: Vec<_> = env::args().collect();
    ensure!(
        args.len() == 6 && args[2] == "--plan-sha256" && args[4] == "--self-sha256",
        "usage: qualify PLAN --plan-sha256 HEX --self-sha256 HEX"
    );
    let (self_sha, m) = retained::hash_file(&fs::read_link("/proc/self/exe")?, 32 << 20)?;
    ensure!(
        self_sha == args[5] && m.uid() == 0 && m.mode() & 0o222 == 0,
        "unsealed qualification executable"
    );
    let plan_bound = retained::Bound {
        path: args[1].clone().into(),
        sha256: args[3].clone(),
    };
    let p: Plan = serde_json::from_value(retained::bound_json(&plan_bound)?)?;
    validate_plan(&p)?;
    verify_binary(&p.retirement_binary)?;
    let r: retirement::Plan = serde_json::from_value(retained::bound_json(&p.retirement_plan)?)?;
    retirement::validate_plan(&r)?;
    let original: retained::Plan =
        serde_json::from_value(retained::bound_json(&r.retention_plan)?)?;
    retained::validate_plan(&original)?;
    let report = retained::bound_json(&r.retention_receipt)?;
    let outcome = retained::bound_json(&original.outcome)?;
    validate_no_entry(&outcome, &p.worker_sha256)?;
    for dir in [
        p.output.parent().context("output parent missing")?,
        r.receipt_directory.as_path(),
    ] {
        let m = fs::symlink_metadata(dir)?;
        ensure!(
            dir.canonicalize()? == dir && m.is_dir() && m.uid() == 0 && m.mode() & 0o077 == 0,
            "unsafe lifecycle receipt directory"
        );
        ensure!(
            fs::read_dir(dir)?.next().is_none(),
            "lifecycle attempt directory is not empty"
        );
    }
    let before = retirement::preserved(&r, &original, &report)?;
    let device = libc::makedev(
        u32::try_from(original.mount_device[0])?,
        u32::try_from(original.mount_device[1])?,
    );
    let scratch = original.run_root.join("scratch");
    let parent = p.output.parent().context("output parent missing")?;
    retirement::persist(
        &parent.join("fixture-intent.json"),
        &json!({"schema":"jetstreamer-private-epoch203-ram-lifecycle-fixture-intent-v1",
        "plan_sha256":plan_bound.sha256,"self_sha256":self_sha,"run_root":original.run_root,
        "scratch_inode":r.expected_scratch_inode,"relative_fixture":format!("scratch/{MARKER}"),
        "fixture_bytes":4096,"fixture_sha256":format!("{:x}",Sha256::digest(BYTES)),"replay_entries":false,"r2_mutations":false}),
    )?;
    let fixture = create_fixture(&scratch, device, r.expected_scratch_inode)?;
    // No source descriptors may remain open while the child independently
    // scans /proc; otherwise this parent would rightly block retirement.
    retirement::persist(&parent.join("fixture-created.json"), &fixture)?;
    invoke(&p, true, &parent.join("child-check.json"))?;
    let (check, check_sha) = retirement::read_json(&r.receipt_directory.join("check.json"))?;
    ensure!(
        scratch.join(MARKER).try_exists()?,
        "check-only unexpectedly removed fixture"
    );
    let (fixture_sha, fixture_metadata) = retained::hash_file(&scratch.join(MARKER), 4096)?;
    ensure!(
        fixture_sha == fixture["sha256"]
            && fixture_metadata.ino() == fixture["inode"]
            && check["tree"][MARKER]["inode"] == fixture["inode"]
            && check["tree"][MARKER]["device"] == fixture["device"]
            && check["tree"][MARKER]["size"] == 4096
            && check["tree"][MARKER]["directory"] == false,
        "check-only did not bind the exact newly created disposable fixture"
    );
    invoke(&p, false, &parent.join("child-retire.json"))?;
    let (intent, intent_sha) = retirement::read_json(&r.receipt_directory.join("intent.json"))?;
    let (completed, completion_sha) =
        retirement::read_json(&r.receipt_directory.join("completion.json"))?;
    validate_completed(&p, &check, &check_sha, &intent, &completed)?;
    ensure!(
        fs::read_dir(&scratch)?.next().is_none()
            && fs::symlink_metadata(&scratch)?.ino() == r.expected_scratch_inode,
        "fixture scratch did not return to original empty inode"
    );
    let after = retirement::preserved(&r, &original, &report)?;
    ensure!(
        before["files"] == after["files"] && before["mount"] == after["mount"],
        "retained artifacts or mount changed"
    );
    retirement::persist(
        &p.output,
        &json!({"schema":"jetstreamer-private-epoch203-ram-retention-capability-v1",
        "self_sha256":self_sha,"plan_sha256":plan_bound.sha256,"passed":true,"simulated":false,
        "supervisor_profile":"jetstreamer-private-epoch203-ram-bounded-runner-plan-v1",
        "worker_sha256":p.worker_sha256,"maximum_entry_replays":4,"maximum_auxiliary_diagnostics":1,
        "scope":"actual persistent-RAM filesystem lifecycle; disposable fixture bytes only",
        "fixture":fixture,"retention_receipt_sha256":r.retention_receipt.sha256,
        "retirement_binary_sha256":p.retirement_binary.sha256,"retirement_plan_sha256":p.retirement_plan.sha256,
        "scratch_check_sha256":check_sha,"scratch_intent_sha256":intent_sha,"scratch_completion_sha256":completion_sha,
        "actual_fixture_unlink_verified":true,"persistent_artifact_lifecycle_verified":true,
        "preserved_artifact_hashes_and_identities":after["files"],"persistent_mount":after["mount"],
        "entry_replay":false,"worker_ipc_qualified":false,"full_cold_epoch_peak_qualified":false,
        "fresh_fleet_admission_passed":false,"ordinary_replay_authorized":false,"runtime_promotion_authorized":false,
        "publication_authorized":false,"remote_mutations":false,"r2_mutations":false,"unmount_authorized":false}),
    )?;
    println!("{}", p.output.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn plan() -> Plan {
        serde_json::from_value(
            json!({"schema":"jetstreamer-private-epoch203-ram-lifecycle-qualification-plan-v1",
        "retirement_plan":{"path":"/sealed/plan","sha256":"a".repeat(64)},
        "retirement_binary":{"path":"/sealed/retire","sha256":"b".repeat(64)},
        "worker_sha256":"3f5e8efec328b3e00dd9ce5ae396fc4067e6be6554e4da8831a13273186a748a",
        "output":"/var/lib/jetstreamer/horizon-203-ram-lifecycle-qualify-test/qualification.json"}),
        )
        .unwrap()
    }
    #[test]
    fn qualification_never_selects_an_unbound_worker_or_public_output() {
        validate_plan(&plan()).unwrap();
        let mut p = plan();
        p.worker_sha256 = "a".repeat(64);
        assert!(validate_plan(&p).is_err());
        p = plan();
        p.output = "/home/ubuntu/horizon/qualification.json".into();
        assert!(validate_plan(&p).is_err());
    }
    #[test]
    fn only_actual_no_entry_outcomes_allow_fixture_mutation() {
        let p = plan();
        let mut v = json!({"schema":"jetstreamer-private-epoch203-ram-supervisor-storage-capability-v1",
            "entry_replay":false,"node_arguments_executed":false,"worker_ipc_qualified":false,
            "worker_sha256":p.worker_sha256,"profile":"jetstreamer-private-epoch203-ram-bounded-runner-plan-v1"});
        validate_no_entry(&v, &p.worker_sha256).unwrap();
        v["entry_replay"] = json!(true);
        assert!(validate_no_entry(&v, &p.worker_sha256).is_err());
        v["entry_replay"] = json!(false);
        v["node_arguments_executed"] = json!(true);
        assert!(validate_no_entry(&v, &p.worker_sha256).is_err());
    }
    #[test]
    fn no_fixture_creation_into_nonempty_or_replaced_scratch() {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let m = fs::metadata(temp.path()).unwrap();
        fs::write(temp.path().join("preserve"), b"do not replace").unwrap();
        assert!(create_fixture(temp.path(), m.dev(), m.ino()).is_err());
        assert_eq!(
            fs::read(temp.path().join("preserve")).unwrap(),
            b"do not replace"
        );
    }
    #[test]
    fn empty_or_unbound_retirement_cannot_be_called_populated_ram_qualification() {
        let p = plan();
        assert!(validate_completed(&p, &json!({}), "x", &json!({}), &json!({})).is_err());
    }

    #[test]
    fn populated_proof_requires_one_real_unlink_and_preservation_of_every_sibling() {
        let p = plan();
        let check = json!({"schema":"jetstreamer-private-epoch203-ram-scratch-check-v1",
            "plan_sha256":p.retirement_plan.sha256,"self_sha256":p.retirement_binary.sha256,
            "tree":std::collections::BTreeMap::from([("",json!({})),(MARKER,json!({}))])});
        let intent = json!({"schema":"jetstreamer-private-epoch203-ram-scratch-intent-v1",
            "plan_sha256":p.retirement_plan.sha256,"self_sha256":p.retirement_binary.sha256,"check_sha256":"check"});
        let completed = json!({"schema":"jetstreamer-private-epoch203-ram-scratch-completion-v1",
            "plan_sha256":p.retirement_plan.sha256,"self_sha256":p.retirement_binary.sha256,"check_sha256":"check",
            "removed_entries_this_invocation":1,"resumed":false,"scratch_empty":true,"scratch_root_preserved":true,
            "archive_and_metadata_preserved":true,"mount_preserved":true,"archive_deletion_authorized":false,
            "unmount_authorized":false,"r2_mutations":false});
        validate_completed(&p, &check, "check", &intent, &completed).unwrap();
        for (field, value) in [
            ("removed_entries_this_invocation", json!(0)),
            ("resumed", json!(true)),
            ("mount_preserved", json!(false)),
            ("archive_and_metadata_preserved", json!(false)),
            ("r2_mutations", json!(true)),
        ] {
            let mut wrong = completed.clone();
            wrong[field] = value;
            assert!(
                validate_completed(&p, &check, "check", &intent, &wrong).is_err(),
                "{field}"
            );
        }
    }
}
