//! Terminal, retained-evidence-bound retirement of RAM benchmark scratch only.
//! Archives, ledger, metadata and the independent mount remain untouched.
use {
    crate::{process_references, ram_artifact_retention as retained, ram_scratch_tree as tree},
    anyhow::{Context, Result, ensure},
    serde::Deserialize,
    serde_json::{Value, json},
    sha2::{Digest, Sha256},
    std::{
        env,
        fs::{self, File, OpenOptions},
        io::{Read, Write},
        os::unix::fs::{MetadataExt, OpenOptionsExt},
        path::{Path, PathBuf},
    },
};
const LIMIT: u64 = 64 << 20;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Plan {
    schema: String,
    pub(crate) retention_plan: retained::Bound,
    pub(crate) retention_receipt: retained::Bound,
    pub(crate) retention_binary: retained::Bound,
    pub(crate) expected_scratch_inode: u64,
    pub(crate) receipt_directory: PathBuf,
}
pub(crate) fn read_json(path: &Path) -> Result<(Value, String)> {
    let (sha, m) = retained::hash_file(path, LIMIT)?;
    ensure!(
        path.canonicalize()? == path && m.uid() == 0 && m.mode() & 0o222 == 0,
        "unsafe retirement evidence"
    );
    let mut bytes = Vec::new();
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?
        .take(LIMIT + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= LIMIT && format!("{:x}", Sha256::digest(&bytes)) == sha,
        "retirement evidence changed"
    );
    Ok((serde_json::from_slice(&bytes)?, sha))
}
pub(crate) fn persist(path: &Path, value: &Value) -> Result<String> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    ensure!(
        bytes.len() as u64 <= LIMIT,
        "retirement receipt exceeds bound"
    );
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    File::open(path.parent().context("receipt parent missing")?)?.sync_all()?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}
pub(crate) fn validate_plan(p: &Plan) -> Result<()> {
    ensure!(
        p.schema == "jetstreamer-private-epoch203-ram-scratch-retire-plan-v1"
            && p.expected_scratch_inode > 0,
        "wrong retirement scope"
    );
    ensure!(
        p.receipt_directory.parent() == Some(Path::new("/var/lib/jetstreamer"))
            && p.receipt_directory
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with("horizon-203-ram-scratch-retire-")),
        "retirement receipts must be private durable metadata"
    );
    Ok(())
}
pub(crate) fn preserved(p: &Plan, r: &retained::Plan, report: &Value) -> Result<Value> {
    let outcome = retained::bound_json(&r.outcome)?;
    retained::validate_outcome(&outcome, r)?;
    let no_entry =
        outcome["schema"] == "jetstreamer-private-epoch203-ram-supervisor-storage-capability-v1";
    let plan = if no_entry {
        ensure!(
            outcome["entry_replay"] == false,
            "capability outcome executed entries"
        );
        retained::Bound {
            path: outcome["plan"]["plan_path"]
                .as_str()
                .context("supervisor plan path missing")?
                .into(),
            sha256: outcome["plan"]["plan_sha256"]
                .as_str()
                .context("supervisor plan digest missing")?
                .into(),
        }
    } else {
        ensure!(
            outcome["epoch"] == 203 && outcome["target_slot"] == 87_720_000u64,
            "unreviewed bounded target"
        );
        serde_json::from_value(outcome["plan"].clone())?
    };
    let envelope = retained::bound_json(&plan)?;
    ensure!(
        envelope["schema"] == "jetstreamer-private-epoch203-ram-supervisor-plan-v1"
            && envelope["runner"]["schema"]
                == "jetstreamer-private-epoch203-ram-bounded-runner-plan-v1"
            && envelope["runner"]["unit"] == r.producer_unit
            && envelope["runner"]["run_root"].as_str() == r.run_root.to_str()
            && envelope["runner"]["target_slot"] == 87_720_000u64
            && envelope["runner"]["terminal_slot"] == 88_127_580u64,
        "scratch does not bind the reviewed isolated bootstrap runner"
    );
    let parent = outcome
        .get("node_sha256")
        .unwrap_or(&outcome["parent_sha256"]);
    ensure!(
        parent == "025757b9b337abf05435c427f143f590d9bfa542b5e4493aae783c158b4f2d3d"
            && outcome["snapshot_sha256"]
                == "e45584858d0c825f095a43ff5e5909e62a68d197d39c042a76727454525228c4"
            && matches!(
                outcome["worker_sha256"].as_str(),
                Some(
                    "3f5e8efec328b3e00dd9ce5ae396fc4067e6be6554e4da8831a13273186a748a"
                        | "4aeca56378a4bb2c55d0e590c1e334c4afa6a375a2c0d94894b412bea261f1cc"
                )
            ),
        "scratch is not the reviewed cursor-free bounded bootstrap profile"
    );
    ensure!(
        report["schema"] == "jetstreamer-private-epoch203-ram-retained-artifacts-v1"
            && report["plan_sha256"] == p.retention_plan.sha256
            && report["self_sha256"] == p.retention_binary.sha256
            && report["unit"] == r.producer_unit
            && report["invocation_id"] == r.producer_invocation_id
            && report["run_root"].as_str() == r.run_root.to_str()
            && report["outcome_sha256"] == r.outcome.sha256
            && report["artifacts_retained_in_place"] == true
            && report["retirement_authorized"] == false
            && report["publication_authorized"] == false
            && report["r2_mutations"] == false,
        "retention receipt differs from exact owner and artifacts"
    );
    let names = "Id,LoadState,ActiveState,SubState,InvocationID,MainPID,NRestarts,Restart,Triggers,TriggeredBy,Result,ExecMainStatus,ExecMainPID,ExecMainStartTimestampMonotonic,ExecMainExitTimestampMonotonic";
    let owner = retained::properties(&r.producer_unit, names)?;
    retained::validate_terminal(&owner, r)?;
    let (mount, device) = retained::mount(r)?;
    // A same-device bind mount is still not disposable scratch. This namespace
    // may bind the exact scratch root writable, but never a descendant mount.
    let scratch = r.run_root.join("scratch");
    for line in fs::read_to_string("/proc/self/mountinfo")?.lines() {
        let point = line
            .split_whitespace()
            .nth(4)
            .context("malformed mountinfo")?;
        ensure!(
            !Path::new(point).starts_with(&scratch) || Path::new(point) == scratch,
            "nested mount beneath scratch"
        );
    }
    let references = process_references::scan(Path::new("/proc"), &r.run_root)?;
    ensure!(
        references.references.is_empty(),
        "live references prevent scratch retirement"
    );
    let inventory = retained::inventory(r, device)?;
    ensure!(
        inventory["files"] == report["artifacts"]["files"],
        "preserved archive/input/receipt bytes or identities changed"
    );
    ensure!(
        retained::properties(&r.producer_unit, names)? == owner
            && retained::mount(r)? == (mount.clone(), device),
        "owner or mount changed during retirement gate"
    );
    Ok(
        json!({"owner":owner,"mount":mount,"files":inventory["files"],"process_reference_scan":references}),
    )
}

/// Execute the tightly scoped scratch-only retirement CLI. Check-only is
/// mandatory before an intent can authorize any descriptor-relative unlink.
pub fn run() -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "scratch retirement requires root"
    );
    let args: Vec<_> = env::args().collect();
    ensure!(
        (args.len() == 6 || (args.len() == 7 && args[6] == "--check-only"))
            && args[2] == "--plan-sha256"
            && args[4] == "--self-sha256",
        "usage: retire PLAN --plan-sha256 HEX --self-sha256 HEX [--check-only]"
    );
    let (self_sha, m) = retained::hash_file(&fs::read_link("/proc/self/exe")?, 32 << 20)?;
    ensure!(
        self_sha == args[5] && m.uid() == 0 && m.mode() & 0o222 == 0,
        "unsealed retirement executable"
    );
    let plan_bound = retained::Bound {
        path: args[1].clone().into(),
        sha256: args[3].clone(),
    };
    let p: Plan = serde_json::from_value(retained::bound_json(&plan_bound)?)?;
    validate_plan(&p)?;
    let r: retained::Plan = serde_json::from_value(retained::bound_json(&p.retention_plan)?)?;
    retained::validate_plan(&r)?;
    let report = retained::bound_json(&p.retention_receipt)?;
    let (sha, binary) = retained::hash_file(&p.retention_binary.path, 32 << 20)?;
    ensure!(
        sha == p.retention_binary.sha256
            && binary.uid() == 0
            && binary.mode() & 0o222 == 0
            && p.retention_binary
                .path
                .file_name()
                .is_some_and(|s| s == "jetstreamer-epoch203-ram-retain"),
        "retention verifier binary binding differs"
    );
    let directory = fs::symlink_metadata(&p.receipt_directory)?;
    ensure!(
        p.receipt_directory.canonicalize()? == p.receipt_directory
            && directory.is_dir()
            && directory.uid() == 0
            && directory.mode() & 0o077 == 0,
        "unsafe receipt directory"
    );
    let check_path = p.receipt_directory.join("check.json");
    let intent_path = p.receipt_directory.join("intent.json");
    let completion_path = p.receipt_directory.join("completion.json");
    ensure!(
        !completion_path.try_exists()?,
        "retirement is already complete"
    );
    let proof = preserved(&p, &r, &report)?;
    let scratch = r.run_root.join("scratch");
    let device = libc::makedev(
        u32::try_from(r.mount_device[0])?,
        u32::try_from(r.mount_device[1])?,
    );
    let root = tree::open_root(&scratch, device, p.expected_scratch_inode)?;
    let current = tree::capture(&root, device, 1000, 1000)?;
    if args.len() == 7 {
        ensure!(
            !intent_path.try_exists()?,
            "cannot requalify an interrupted retirement"
        );
        persist(
            &check_path,
            &json!({"schema":"jetstreamer-private-epoch203-ram-scratch-check-v1",
            "plan_sha256":plan_bound.sha256,"self_sha256":self_sha,"tree":current,"preserved":proof,
            "scratch_retirement_authorized":false,"archive_deletion_authorized":false,"unmount_authorized":false,"r2_mutations":false}),
        )?;
        println!("{}", check_path.display());
        return Ok(());
    }
    let (check, check_sha) = read_json(&check_path)?;
    ensure!(
        check["schema"] == "jetstreamer-private-epoch203-ram-scratch-check-v1"
            && check["plan_sha256"] == plan_bound.sha256
            && check["self_sha256"] == self_sha
            && check["preserved"]["files"] == proof["files"],
        "check-only qualification does not bind this exact retirement"
    );
    let expected: tree::Ledger = serde_json::from_value(check["tree"].clone())?;
    let resumed = intent_path.try_exists()?;
    tree::validate_remaining(&expected, &current, resumed)?;
    if resumed {
        let (intent, _) = read_json(&intent_path)?;
        ensure!(
            intent["schema"] == "jetstreamer-private-epoch203-ram-scratch-intent-v1"
                && intent["plan_sha256"] == plan_bound.sha256
                && intent["self_sha256"] == self_sha
                && intent["check_sha256"] == check_sha
                && intent["scratch"].as_str() == scratch.to_str(),
            "interrupted retirement binding differs"
        );
    } else {
        persist(
            &intent_path,
            &json!({"schema":"jetstreamer-private-epoch203-ram-scratch-intent-v1",
            "plan_sha256":plan_bound.sha256,"self_sha256":self_sha,"check_sha256":check_sha,
            "scratch":scratch,"scratch_inode":p.expected_scratch_inode,
            "archive_deletion_authorized":false,"unmount_authorized":false,"r2_mutations":false}),
        )?;
    }
    // Recheck all independent gates after intent is durable, before the first
    // unlink. No code path can remove the scratch directory or its siblings.
    preserved(&p, &r, &report)?;
    let removed = tree::remove_contents(&root, &expected, device, 1000, 1000)?;
    let final_scratch = fs::symlink_metadata(&scratch)?;
    ensure!(
        final_scratch.is_dir()
            && final_scratch.dev() == device
            && final_scratch.ino() == p.expected_scratch_inode,
        "scratch namespace changed during retirement"
    );
    let after = preserved(&p, &r, &report)?;
    ensure!(
        after["files"] == proof["files"],
        "preserved artifacts changed during retirement"
    );
    persist(
        &completion_path,
        &json!({"schema":"jetstreamer-private-epoch203-ram-scratch-completion-v1",
        "plan_sha256":plan_bound.sha256,"self_sha256":self_sha,"check_sha256":check_sha,
        "removed_entries_this_invocation":removed,"resumed":resumed,"scratch_empty":true,
        "scratch_root_preserved":true,"archive_and_metadata_preserved":true,"mount_preserved":true,
        "preserved":after,"archive_deletion_authorized":false,"unmount_authorized":false,
        "replay_launch_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false}),
    )?;
    println!("{}", completion_path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn plan_never_accepts_broad_output_or_zero_scratch_identity() {
        let value = json!({"schema":"jetstreamer-private-epoch203-ram-scratch-retire-plan-v1",
            "retention_plan":{"path":"/sealed/plan","sha256":"a".repeat(64)},
            "retention_receipt":{"path":"/sealed/receipt","sha256":"b".repeat(64)},
            "retention_binary":{"path":"/sealed/binary","sha256":"c".repeat(64)},
            "expected_scratch_inode":2,"receipt_directory":"/var/lib/jetstreamer/horizon-203-ram-scratch-retire-test"});
        validate_plan(&serde_json::from_value(value.clone()).unwrap()).unwrap();
        for (key, v) in [
            ("receipt_directory", json!("/var/lib/jetstreamer")),
            ("expected_scratch_inode", json!(0)),
        ] {
            let mut wrong = value.clone();
            wrong[key] = v;
            assert!(validate_plan(&serde_json::from_value(wrong).unwrap()).is_err());
        }
    }
}
