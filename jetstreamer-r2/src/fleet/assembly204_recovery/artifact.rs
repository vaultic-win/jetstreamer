//! The exact production capture and source QA are independent immutable facts.
//! Configuration checkpoints keep their actual pre-build/capture scope.
use super::*;
mod helper_capture;
const PACKAGE: &str = "/var/lib/jetstreamer/horizon-204-assembly-recovery-aac7c8ca-v2";
const SEAL: &str = "4fbda2b98a08bd46cb1ee9636b4b2ec83aa489495cafd10773e9215aa24770c8";
const ARTIFACT: &str = "2fe7aa3ffa3acabbb0454c0aa9a65d6fba606dd27216d57283af5004db1cf877";
const REVISION: &str = RETRY_HELPER_SOURCE;
const TREE: &str = "8a95eec50f7e89745a870f6da7c99d408b86090c";
const QA: &str = "7c93606343449323791322db8cd4ecd170a2ad74a1ff43804b622142ca133240";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Member {
    source: PathBuf,
    name: String,
    sha256: String,
    bytes: u64,
    mode: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Seal {
    schema: String,
    plan_sha256: String,
    sealer_sha256: String,
    destination: PathBuf,
    members: Vec<Member>,
    created_unix_seconds: u64,
    publication_authorized: bool,
    replay_launch_authorized: bool,
    remote_mutations: bool,
    r2_mutations: bool,
}
fn selected_member<'a>(seal: &'a Seal, name: &str, sha: &str, maximum: u64) -> Result<&'a Member> {
    let matches = seal
        .members
        .iter()
        .filter(|m| m.name == name)
        .collect::<Vec<_>>();
    ensure!(
        matches.len() == 1,
        "204 production member missing/duplicate: {name}"
    );
    let m = matches[0];
    let mode = u32::from_str_radix(&m.mode, 8)?;
    ensure!(
        m.sha256 == sha
            && m.bytes > 0
            && m.bytes <= maximum
            && m.source.is_absolute()
            && mode & 0o222 == 0
            && matches!(mode, 0o400 | 0o444 | 0o500 | 0o555),
        "204 production member identity/mode differs: {name}"
    );
    Ok(m)
}
fn member(seal: &Seal, name: &str, sha: &str, maximum: u64) -> Result<BoundFile> {
    let m = selected_member(seal, name, sha, maximum)?;
    let mode = u32::from_str_radix(&m.mode, 8)?;
    let b = BoundFile {
        path: Path::new(PACKAGE).join(name),
        sha256: sha.into(),
    };
    let metadata = fs::symlink_metadata(&b.path)?;
    ensure!(
        metadata.len() == m.bytes && metadata.mode() & 0o777 == mode,
        "204 actual sealed member differs: {name}"
    );
    sealed(&b, maximum)?;
    Ok(b)
}
fn qa_shape(qa: &Value, annex: &Value) -> Result<()> {
    ensure!(
        qa["schema"] == "jetstreamer-epoch204-assembly-recovery-focused-qa-result-v1"
            && qa["final_frozen_commit"] == REVISION
            && qa["final_tree"] == TREE
            && qa["source_qa_passed"] == true
            && qa["production_or_runtime_qualification_passed"] == false
            && qa["test_counts"]["total_distinct_passed"] == 33
            && qa["test_counts"]["recovery_binary"] == 4
            && qa["test_counts"]["recovery_evidence"] == 8
            && qa["test_counts"]["existing_capped_prefix_native_regressions"] == 11
            && qa["test_counts"]["checkpoint_provenance_codec"] == 9
            && qa["test_counts"]["genuine_root_writer_reader"] == 1
            && qa["strict_clippy"]["horizon_library"] == "passed"
            && qa["strict_clippy"]["node_library_and_recovery_binary"] == "passed"
            && annex["schema"] == "jetstreamer-epoch204-recovery-qa-exec-completion-v1"
            && annex["final_frozen_commit"] == REVISION
            && annex["qa_report"]["sha256"] == QA
            && annex["all_cargo_commands_completed"] == true
            && annex["detached_cargo_jobs_started"] == false
            && annex["actual_exec_sessions"]
                .as_array()
                .is_some_and(|a| !a.is_empty() && a.iter().all(|s| s["completed"] == true)),
        "204 genuine source QA/completion facts differ; passing source QA is not runtime qualification"
    );
    Ok(())
}
fn seal_shape(seal: &Seal) -> Result<()> {
    ensure!(
        seal.schema == "jetstreamer-sealed-deployment-receipt-v1"
            && seal.destination == Path::new(PACKAGE)
            && seal.plan_sha256
                == "97503ed4e13c27c95ce56e442d63e4975c0505524bf387ea4415225156b03773"
            && is_lower_hex(&seal.sealer_sha256, 64)
            && seal.created_unix_seconds > 0
            && !seal.publication_authorized
            && !seal.replay_launch_authorized
            && !seal.remote_mutations
            && !seal.r2_mutations,
        "204 deployment seal scope/authority differs"
    );
    Ok(())
}
pub(super) fn validate(bound: &BoundFile, assembler: &BoundFile) -> Result<Value> {
    ensure!(
        bound.path == Path::new(PACKAGE).join("deployment-seal-receipt.json")
            && bound.sha256 == SEAL
            && assembler.path == Path::new(PACKAGE).join("jetstreamer-epoch204-assembly-only")
            && assembler.sha256 == ARTIFACT,
        "204 assembler is not the actual frozen aac generation 2 production capture"
    );
    let metadata = fs::symlink_metadata(PACKAGE)?;
    ensure!(
        Path::new(PACKAGE).canonicalize()? == Path::new(PACKAGE)
            && metadata.is_dir()
            && metadata.uid() == 0
            && metadata.mode() & 0o222 == 0,
        "204 production package custody differs"
    );
    let seal: Seal = serde_json::from_value(read(bound)?)?;
    seal_shape(&seal)?;
    ensure!(
        private157::binding(&member(
            &seal,
            "jetstreamer-epoch204-assembly-only",
            ARTIFACT,
            128 << 20
        )?) == private157::binding(assembler),
        "204 production binary binding differs"
    );
    let candidate = member(
        &seal,
        "candidate-manifest.json",
        "c7b56a4d43bd072ff8b751bf6a1751775c71b91ae50199c1dd53d7cf983f3692",
        16 << 20,
    )?;
    let qa = member(&seal, "candidate-evidence--qa-result.json", QA, 16 << 20)?;
    let annex = member(
        &seal,
        "candidate-evidence--qa-exec-completion.json",
        "4b27307d32a639c268446ace62e61c83a21cb00c4484986a8e0545dc6d7e1b40",
        16 << 20,
    )?;
    let qa_value = read(&qa)?;
    qa_shape(&qa_value, &read(&annex)?)?;
    let facts = helper_capture::validate(&seal, &read(&candidate)?, &qa_value)?;
    let top = member(
        &seal,
        "CANDIDATE-SHA256.json",
        "304836b9927d4e97f04e8e59323c6c0905cc57392c0c8c4210af63482b2d555a",
        16 << 20,
    )?;
    read(&top)?;
    Ok(
        json!({"deployment_seal":bound,"artifact":assembler,"source_revision":REVISION,"source_tree":TREE,"frozen_candidate":candidate,
        "source_qa":qa,"qa_exec_completion":annex,"capture_facts":facts,"candidate_sha256":top,
        "runtime_launch_qualified":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false}),
    )
}
/// A downstream tool, its raw source capture, raw QA report and logs must be
/// actual members of one immutable deployment. Positive flags are insufficient.
pub(super) fn validate_member_binding(
    seal_bound: &BoundFile,
    b: &BoundFile,
    maximum: u64,
) -> Result<()> {
    let seal: Seal = serde_json::from_value(read(seal_bound)?)?;
    ensure!(
        seal.schema == "jetstreamer-sealed-deployment-receipt-v1"
            && !seal.publication_authorized
            && !seal.replay_launch_authorized
            && !seal.remote_mutations
            && !seal.r2_mutations
            && is_lower_hex(&seal.plan_sha256, 64)
            && is_lower_hex(&seal.sealer_sha256, 64),
        "204 tool seal scope/authority differs"
    );
    let parent = fs::symlink_metadata(&seal.destination)?;
    ensure!(
        seal.destination.is_absolute()
            && seal.destination.canonicalize()? == seal.destination
            && parent.is_dir()
            && parent.uid() == 0
            && parent.mode() & 0o222 == 0
            && b.path.parent() == Some(seal.destination.as_path()),
        "204 tool evidence escaped immutable deployed members"
    );
    let matches = seal
        .members
        .iter()
        .filter(|m| seal.destination.join(&m.name) == b.path && m.sha256 == b.sha256)
        .collect::<Vec<_>>();
    ensure!(
        matches.len() == 1,
        "204 tool evidence lacks one exact sealed member"
    );
    let m = matches[0];
    let mode = u32::from_str_radix(&m.mode, 8)?;
    let meta = fs::symlink_metadata(&b.path)?;
    ensure!(
        m.source.is_absolute()
            && m.bytes > 0
            && m.bytes <= maximum
            && mode & 0o222 == 0
            && meta.len() == m.bytes
            && meta.mode() & 0o777 == mode,
        "204 tool member identity differs"
    );
    sealed(b, maximum)?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn flag_only_production_envelope_has_no_seal_or_artifact_authority() {
        let fake = BoundFile {
            path: "/sealed/qa-verified.json".into(),
            sha256: "a".repeat(64),
        };
        let executable = BoundFile {
            path: "/sealed/assembler".into(),
            sha256: ARTIFACT.into(),
        };
        assert!(validate(&fake, &executable).is_err());
    }
}
