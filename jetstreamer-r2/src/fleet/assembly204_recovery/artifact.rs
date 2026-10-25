//! The exact production capture and source QA are independent immutable facts.
//! In particular the actual post-build configuration audit is not a preflight.
use super::*;
const PACKAGE: &str = "/var/lib/jetstreamer/horizon-204-assembly-recovery-94705c5d-v1";
const SEAL: &str = "650dd82061693363e5fd94cc6e76a28b808a3e301da864ffda90483f4d7f9a04";
const ARTIFACT: &str = "226f9a6c7b6b54a181b3795cf644efa67161289935371f787fe2a378c61ac215";
const REVISION: &str = "94705c5d546341f4fdfc6cc50c819c4031f9ab1d";
const TREE: &str = "c591128f9828f3206a9d7dfb5ae6f4fce63fb2d7";
const QA: &str = "cdcba0fd6e8d86eeefc6e03ee73c06fd4218f68c202cd52fed52e60b64d52b76";
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
fn member(seal: &Seal, name: &str, sha: &str, maximum: u64) -> Result<BoundFile> {
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
            && qa["test_counts"]["total_distinct_passed"] == 31
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
pub(super) fn validate(bound: &BoundFile, assembler: &BoundFile) -> Result<Value> {
    ensure!(
        bound.path == Path::new(PACKAGE).join("deployment-seal-receipt.json")
            && bound.sha256 == SEAL
            && assembler.path == Path::new(PACKAGE).join("jetstreamer-epoch204-assembly-only")
            && assembler.sha256 == ARTIFACT,
        "204 assembler is not the actual frozen947 production capture"
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
    ensure!(
        seal.schema == "jetstreamer-sealed-deployment-receipt-v1"
            && seal.destination == Path::new(PACKAGE)
            && is_lower_hex(&seal.plan_sha256, 64)
            && is_lower_hex(&seal.sealer_sha256, 64)
            && seal.created_unix_seconds > 0
            && !seal.publication_authorized
            && !seal.replay_launch_authorized
            && !seal.remote_mutations
            && !seal.r2_mutations,
        "204 deployment seal scope/authority differs"
    );
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
        "capture-1518",
        "8864e04a814d7b6ccd4d65c2c4e93ec2f583fb52ef1c22a260615ebed4db39aa",
        16 << 20,
    )?;
    let qa = member(&seal, "capture-1539", QA, 16 << 20)?;
    let annex = member(
        &seal,
        "capture-1538",
        "b07fb22f654b5021f1a2b61eb6a57025814a1f5adaf6abf23118d72ce8f57099",
        16 << 20,
    )?;
    let audit = member(
        &seal,
        "capture-1530",
        "28a42f3f71462956b0bb0b27f8357c207d457210116197a71ca5c699657b67cb",
        16 << 20,
    )?;
    ensure!(
        read(&candidate)?["schema"] == "jetstreamer-epoch204-assembly-recovery-frozen-candidate-v1",
        "204 frozen production candidate schema differs"
    );
    qa_shape(&read(&qa)?, &read(&annex)?)?;
    read(&audit)?;
    let top = BoundFile {
        path: Path::new(PACKAGE).join("CANDIDATE-SHA256.json"),
        sha256: "082c116be1481cb54d78f312922392b8dfe3de8fb3acafdebd7648b22945d62f".into(),
    };
    read(&top)?;
    Ok(
        json!({"deployment_seal":bound,"artifact":assembler,"source_revision":REVISION,"source_tree":TREE,"frozen_candidate":candidate,
        "source_qa":qa,"qa_exec_completion":annex,"actual_post_build_config_audit":audit,"candidate_sha256":top,
        "config_audit_scope":"actual post-build configuration audit; not a retroactive preflight","runtime_launch_qualified":false}),
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
