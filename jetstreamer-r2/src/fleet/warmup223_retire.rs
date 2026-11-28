//! Retire only superseded first 16 native 20 scratch; preserve output and receipts.
use super::*;
const ROOT: &str =
    "/home/ubuntu/.jetstreamer-private/qualification-223-v1620-prefix-warmup-8457f800-v2";
const UNIT: &str = "horizon-qualify-223-v1620-warmup-resource-8457f800-v2.service";
const IID: &str = "58ab3d9221a6452685b8eab3ceabdb49";
const PROOF: &str = "/var/lib/jetstreamer/horizon-warmup223-native20-terminal-58ab-v2/proof.json";
const PROOF_SHA: &str = "6790592b9188e7c4a3d32171a326b743f84fc6c5b5ad07f94182c104876b7028";
const RESOURCE: &str =
    "/var/lib/jetstreamer/horizon-warmup223-native20-terminal-58ab-v2/resource.json";
const RESOURCE_SHA: &str = "4040a077d90eca93e0208485a86131b1541564527acc4ab9de746292e32504d3";
const STATE: &str = "/var/lib/jetstreamer/horizon-warmup223-58ab-scratch-retirement-v1";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    mode: String,
    scratch: PathBuf,
    receipt_directory: PathBuf,
}
fn scope(s: &Spec) -> Result<()> {
    ensure!(
        s.schema == "jetstreamer-warmup223-58ab-scratch-retirement-spec-v1"
            && matches!(s.mode.as_str(), "check-only" | "retire")
            && s.scratch == Path::new(ROOT).join("scratch")
            && s.receipt_directory == Path::new(STATE),
        "warmup scratch retirement scope differs"
    );
    Ok(())
}
fn prerequisites() -> Result<Value> {
    let proof = bound_json(&BoundFile {
        path: PROOF.into(),
        sha256: PROOF_SHA.into(),
    })?;
    let (name, iid) = warmup223::terminal_identity(&proof)?;
    ensure!(
        name == UNIT
            && iid == IID
            && proof["bounded_warmup_complete"] == true
            && proof["canonical_prefix_qualified"] == false
            && proof["native_restart_qualified"] == false
            && proof["full_epoch_qualified"] == false
            && proof["assembly_qualified"] == false
            && proof["repair_closed"] == false
            && proof["publication_authorized"] == false,
        "retirement lacks exact bounded success"
    );
    warmup223::terminal_not_replaced(&proof)?;
    let jobs = ProcessCommand::new("/usr/bin/systemctl")
        .args(["list-jobs", "--no-legend", "--plain", "--no-pager"])
        .output()?;
    ensure!(
        jobs.status.success() && jobs.stdout.len() <= 1 << 20,
        "cannot inspect pending warmup jobs"
    );
    let jobs = std::str::from_utf8(&jobs.stdout)?;
    ensure!(
        !jobs.split_whitespace().any(|s| [
            UNIT,
            "horizon-warmup223-native20-protective-v2.service",
            "horizon-warmup223-native20-protective-v2.timer"
        ]
        .contains(&s)),
        "warmup retirement has pending systemd jobs"
    );
    let u = unit(UNIT)?;
    ensure!(
        u["MainPID"] == "0"
            && u["NRestarts"] == "0"
            && u["ActiveState"] == "inactive"
            && u["SubState"] == "dead"
            && u["Result"] == "success"
            && u["ExecMainStatus"] == "0"
            && (u["InvocationID"] == "" || u["InvocationID"] == IID)
            && pipeline_status::same_exec_start(
                u["ExecStart"]
                    .as_str()
                    .context("retirement owner command")?,
                proof["terminal_manager"]["ExecStart"]
                    .as_str()
                    .context("proved owner command")?
            ),
        "warmup owner is not unchanged terminal success"
    );
    for name in [
        "horizon-warmup223-native20-protective-v2.service",
        "horizon-warmup223-native20-protective-v2.timer",
    ] {
        let g = singleton227_capture::properties(name, "ActiveState,MainPID")?;
        ensure!(
            g.get("ActiveState")
                .is_some_and(|s| s == "inactive" || s == "failed")
                && g.get("MainPID").is_none_or(|s| s == "0"),
            "warmup protection still active"
        );
    }
    let resource = bound_json(&BoundFile {
        path: RESOURCE.into(),
        sha256: RESOURCE_SHA.into(),
    })?;
    ensure!(
        resource["success"] == true
            && resource["target_reached"] == true
            && resource["observed_slot"] == 96335554u64
            && resource["target_slot"] == 96335554u64
            && resource["invocation_id"] == IID
            && resource["storage_evidence"]["worker_entry_end_exclusive"] == 96335555u64
            && resource["storage_evidence"]["canonical_prefix_qualified"] == false,
        "warmup resource scope differs"
    );
    // Rehash the already-proven immutable cold input. Its source survives this retirement.
    let input = bound_json(&BoundFile {
        path: "/var/lib/jetstreamer/horizon-native223-input-proof-release-v1/input-proof.json"
            .into(),
        sha256: "a76a8e809e1c4fd102461620a45bf09021dd00a660b6a68834b0ec9086e7711a".into(),
    })?;
    ensure!(
        input["native_input_qualified"] == true && input["entry_replay"] == false,
        "retirement lost native input proof"
    );
    let source = Path::new(
        "/var/lib/jetstreamer/horizon-223-known-root-prefix-b1670f57-v1/snapshot-96335538-Gavt9cmcj5BFXuZnz44JktRGbM9oxRkJqoWRF8PvMBTE.tar.zst",
    );
    let m = fs::symlink_metadata(source)?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o222 == 0
            && crate::hash_and_etag(source, crate::identity(&m), 8 << 20)?.sha256_hex
                == "301110cad7eb56ed68c99d31cf6769b7622e2c166f33aec084dc51592d0cd665",
        "retained cold snapshot differs"
    );
    Ok(
        json!({"proof":{"path":PROOF,"sha256":PROOF_SHA},"resource":{"path":RESOURCE,"sha256":RESOURCE_SHA},"owner":u}),
    )
}
fn disposable_name(name: &str) -> bool {
    !(name.ends_with(".jet")
        || name.ends_with(".sha256")
        || name.ends_with(".segment.json")
        || name.ends_with(".tar.zst")
        || name.ends_with(".tar.bz2")
        || name.contains("checkpoint")
        || name == "root-prefix.json"
        || name == "result.json")
}
fn no_artifact_tree(scratch: &Path) -> Result<()> {
    let mut pending = vec![scratch.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let p = entry.path();
            let m = fs::symlink_metadata(&p)?;
            ensure!(
                m.is_file() || m.is_dir(),
                "scratch contains a link or special file"
            );
            ensure!(
                disposable_name(
                    entry
                        .file_name()
                        .to_str()
                        .context("non-UTF8 warmup scratch name")?
                ),
                "scratch includes an archive/snapshot/checkpoint; preserve and review separately"
            );
            if m.is_dir() {
                pending.push(p);
            }
        }
    }
    Ok(())
}
fn inspect(s: &Spec) -> Result<Value> {
    let tree = crate::reserve_scratch::tree(&s.scratch, 1000)?;
    no_artifact_tree(&s.scratch)?;
    let scan =
        jetstreamer_horizon_observe::process_references::scan(Path::new("/proc"), &s.scratch)?;
    ensure!(
        scan.references.is_empty(),
        "live process references warmup scratch"
    );
    Ok(json!({"tree":tree,"references":scan}))
}
pub(super) fn run() -> Result<()> {
    let (binding, self_sha) = publication203::parsed_args("retire-warmup223-scratch")?;
    let s: Spec = serde_json::from_value(bound_json(&binding)?)?;
    scope(&s)?;
    let evidence = prerequisites()?;
    let before = inspect(&s)?;
    let record = json!({"schema":"jetstreamer-warmup223-58ab-scratch-retirement-v1","spec":private157::binding(&binding),"self_sha256":self_sha,"evidence":evidence,"scratch":before,"output_and_receipts_preserved":true,"checkpoint_or_resume_state_qualified":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false});
    if s.mode == "check-only" {
        private157::immutable_receipt(&s.receipt_directory.join("check.json"), &record)?;
        println!("{}", record);
        return Ok(());
    }
    let intent = s.receipt_directory.join("intent.json");
    match fs::symlink_metadata(&intent) {
        Ok(_) => {
            let prior = bound_json(&serde_json::from_value(private157::file_binding(&intent)?)?)?;
            ensure!(
                prior["schema"] == record["schema"]
                    && prior["spec"] == record["spec"]
                    && prior["evidence"] == evidence
                    && prior["scratch"]["tree"]["identity"] == before["tree"]["identity"],
                "retirement retry has another intent or scratch identity"
            );
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            private157::immutable_receipt(&intent, &record)?
        }
        Err(e) => return Err(e.into()),
    }
    ensure!(
        prerequisites()? == evidence && inspect(&s)?["tree"] == before["tree"],
        "warmup scratch or owner changed before retirement"
    );
    for entry in fs::read_dir(&s.scratch)? {
        let p = entry?.path();
        let m = fs::symlink_metadata(&p)?;
        if m.is_dir() {
            fs::remove_dir_all(p)?;
        } else {
            ensure!(m.is_file(), "scratch changed type");
            fs::remove_file(p)?;
        }
    }
    File::open(&s.scratch)?.sync_all()?;
    ensure!(
        fs::read_dir(&s.scratch)?.next().is_none(),
        "warmup scratch not empty after retirement"
    );
    let completion = s.receipt_directory.join("completion.json");
    let result = json!({"schema":"jetstreamer-warmup223-58ab-scratch-retirement-completion-v1","intent":private157::file_binding(&intent)?,"source_proof_sha256":PROOF_SHA,"output_and_receipts_preserved":true,"scratch_directory_preserved":true,"remote_mutations":false,"r2_mutations":false});
    match fs::symlink_metadata(&completion) {
        Ok(_) => ensure!(
            bound_json(&serde_json::from_value(private157::file_binding(
                &completion
            )?)?)?
                == result,
            "retirement completion differs"
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            private157::immutable_receipt(&completion, &result)?
        }
        Err(e) => return Err(e.into()),
    }
    println!("exact terminal warmup scratch retired; output and receipts preserved");
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nested_checkpoint_archive_and_link_are_preserved_by_refusal() {
        let d = tempfile::tempdir().unwrap();
        let nested = d.path().join("runtime/accounts-state");
        fs::create_dir_all(&nested).unwrap();
        fs::write(nested.join("5.0"), b"reproducible appendvec").unwrap();
        no_artifact_tree(d.path()).unwrap();
        for name in [
            "native-checkpoint.json",
            "snapshot-42.tar.zst",
            "epoch-223.jet",
        ] {
            let file = nested.join(name);
            fs::write(&file, b"must preserve").unwrap();
            assert!(no_artifact_tree(d.path()).is_err());
            assert_eq!(fs::read(&file).unwrap(), b"must preserve");
            fs::remove_file(file).unwrap();
        }
        std::os::unix::fs::symlink("/outside", nested.join("link")).unwrap();
        assert!(no_artifact_tree(d.path()).is_err());
    }
    #[test]
    fn retirement_cannot_select_output_other_owner_or_unbounded_mode() {
        let mut s = Spec {
            schema: "jetstreamer-warmup223-58ab-scratch-retirement-spec-v1".into(),
            mode: "check-only".into(),
            scratch: Path::new(ROOT).join("scratch"),
            receipt_directory: STATE.into(),
        };
        scope(&s).unwrap();
        s.mode = "retire".into();
        scope(&s).unwrap();
        for suffix in ["output", "receipts", "ledger", "scratch/child"] {
            s.scratch = Path::new(ROOT).join(suffix);
            assert!(scope(&s).is_err());
        }
        s.scratch = Path::new(ROOT).join("scratch");
        s.mode = "anything".into();
        assert!(scope(&s).is_err());
        for name in [
            "epoch-223.jet",
            "snapshot-123.tar.zst",
            "native-checkpoint.json",
            "epoch-223.jet.segment.json",
            "root-prefix.json",
        ] {
            assert!(!disposable_name(name));
        }
        for name in ["accounts-state", "5.0", "append-vec-42"] {
            assert!(disposable_name(name));
        }
    }
}
