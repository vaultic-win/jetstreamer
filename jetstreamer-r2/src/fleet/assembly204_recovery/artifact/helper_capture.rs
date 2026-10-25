//! Exact aac capture facts; the seal does not turn a source QA pass into a
//! runtime qualification or expand the capture's stated transitive audit scope.
use super::*;
mod integrity;
const ROOT_RESULT: &str = "8a16139c2ea8122dad7133113aa8e7b8a7908581c3ab5c939302cf92fbca08ad";
const ROOT_ELF: &str = "edd14b5d1765fbbc52c7c7ba211fbe5d68730efb0c44716d5c8f0c78652d2ab4";
const CONFIG: &str = "9310658f14f6c6d50900a708057ccd61004ff1a3c89ad51d5736b2f7554a53a3";
fn candidate_shape(v: &Value) -> Result<()> {
    let artifacts = v["artifacts"]
        .as_array()
        .context("204 captured artifacts missing")?;
    ensure!(
        v["schema"] == "jetstreamer-epoch204-assembly-recovery-frozen-candidate-v1"
            && v["source_commit"] == REVISION
            && v["source_tree"] == TREE
            && v["source_clean_before_and_after"] == true
            && artifacts.len() == 1
            && artifacts[0]["name"] == "jetstreamer-epoch204-assembly-only"
            && artifacts[0]["candidate_path"] == "jetstreamer-epoch204-assembly-only"
            && artifacts[0]["sha256"] == ARTIFACT
            && artifacts[0]["bytes"] == 4_993_664u64
            && v["scope"]["deployment_sealed"] == false
            && v["scope"]["operational_actions"] == false
            && v["scope"]["r2_mutations"] == false
            && v["scope"]["limits"].as_str().is_some_and(|s| !s.is_empty()),
        "204 actual candidate source, artifact or capture scope differs"
    );
    Ok(())
}
fn root_shape(qa: &Value, result: &Value, executable: &Value, sandbox: &Value) -> Result<()> {
    let claim = &qa["root_test"];
    ensure!(
        claim["sha256"] == ROOT_RESULT
            && claim["exact_executable_sha256"] == ROOT_ELF
            && claim["selected_test_passed"] == true
            && claim["effective_capability_mask_only"] == 2
            && claim["actual_inaccessible_campaign_mounts"] == 3
            && result["source_revision"] == REVISION
            && result["test_executable_sha256"] == ROOT_ELF
            && result["exit_code"] == 0
            && result["selected_test_passed"] == true
            && result["summary"] == json!([["1", "0", "0"]])
            && result["archive_inputs"] == false
            && result["production_or_campaign_runtime_actions"] == false
            && executable["source_revision"] == REVISION
            && executable["sha256"] == ROOT_ELF
            && executable["bytes"] == 1_180_496u64
            && executable["immutable_memfd_seals"] == 15
            && executable["production_or_campaign_command"] == false
            && executable["argv"]
                == json!([
                    "/proc/self/fd/4",
                    "--ignored",
                    "--exact",
                    "tests::atomic_runtime_writer_and_guard_readers_roundtrip_all_published_modes",
                    "--test-threads=1",
                    "--nocapture"
                ])
            && sandbox["effective_uid"] == 0
            && sandbox["unit"] == claim["unit"]
            && sandbox["manager_properties"]["Id"] == claim["unit"]
            && sandbox["manager_properties"]["InvocationID"] == claim["invocation_id"]
            && sandbox["campaign_inaccessible_mounts"]
                .as_array()
                .is_some_and(|v| v.len() == 3)
            && ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"]
                .iter()
                .all(|k| sandbox["actual_capabilities"][*k] == 2),
        "204 genuine root writer/reader executable, sandbox or result differs"
    );
    Ok(())
}
fn configuration_shape(preflight: &Value, captured: &Value) -> Result<()> {
    ensure!(preflight["source_commit"] == REVISION && preflight["source_tree"] == TREE
        && preflight["inherited_overrides"] == json!({})
        && preflight["scope"] == "Actual pre-build current source/config checkpoint; no production Cargo has run. Wrapper rechecks these inputs before and after build/capture.",
        "204 pre-build configuration checkpoint scope differs");
    let configs = preflight["configuration"]
        .as_array()
        .context("204 configuration checkpoint missing")?;
    let inputs = captured
        .as_array()
        .context("204 captured manifest/config input list missing")?;
    ensure!(
        configs.len() == 2
            && configs
                .iter()
                .all(|c| c["sha256"] == CONFIG && c["bytes"] == 489)
            && configs.iter().all(|c| inputs
                .iter()
                .any(|i| i["input"]["literal_path"] == c["path"]
                    && i["input"]["sha256"] == c["sha256"])),
        "204 actual captured configuration differs from pre-build checkpoint"
    );
    Ok(())
}
fn production_shape(build: &Value, capture: &Value) -> Result<()> {
    ensure!(
        build["schema"] == "jetstreamer-epoch204-assembly-recovery-production-build-result-v1"
            && build["source_commit"] == REVISION
            && build["source_tree"] == TREE
            && build["exit_code"] == 0
            && build["stop_reason"].is_null()
            && build["candidate_executed"] == false
            && build["operational_actions"] == false
            && capture["source"]["commit"] == REVISION
            && capture["source"]["tree"] == TREE
            && capture["artifact"]["sha256"] == ARTIFACT
            && capture["artifact"]["bytes"] == 4_993_664u64
            && capture["candidate_manifest_sha256"]
                == "c7b56a4d43bd072ff8b751bf6a1751775c71b91ae50199c1dd53d7cf983f3692"
            && capture["checksum_manifest_sha256"]
                == "304836b9927d4e97f04e8e59323c6c0905cc57392c0c8c4210af63482b2d555a"
            && capture["all_members_independently_rehashed"] == true
            && capture["candidate_executed"] == false
            && capture["admission_attempted"] == false
            && capture["r2_mutations"] == false,
        "204 actual production build/capture result or authority differs"
    );
    Ok(())
}
pub(super) fn validate(seal: &Seal, candidate: &Value, qa: &Value) -> Result<Value> {
    candidate_shape(candidate)?;
    let pinned = |name: &str, sha: &str| member(seal, name, sha, 16 << 20);
    let result = pinned("candidate-evidence--root-test-result.json", ROOT_RESULT)?;
    let executable = pinned(
        "candidate-evidence--root-test-executable-binding.json",
        "4f452b99b9186055e9e25552b6fb5935e307d95cf7b045a2fa290a0ed62d6d96",
    )?;
    let sandbox = pinned(
        "candidate-evidence--root-sandbox-proof.json",
        "efbb1d36d9a477eed0bec542536c9962e409d81045abed6680fd2bec5d64f7c4",
    )?;
    root_shape(qa, &read(&result)?, &read(&executable)?, &read(&sandbox)?)?;
    let preflight = pinned(
        "candidate-evidence--execution-preflight-v1.json",
        "62ef71e5ec32f65372fbbd63b86e3d8ca4f2914d6228dab1f93e01c64c4214a6",
    )?;
    let configuration = pinned(
        "manifest-and-config-inputs.json",
        "08103c87966aa42dd1c05fc3b9894dd593bc0ec6010821a1134034e069380a3f",
    )?;
    configuration_shape(&read(&preflight)?, &read(&configuration)?)?;
    let build = pinned(
        "candidate-evidence--production-build-result-v1.json",
        "23645eb6041cc680c053127cacf925cf7d06c89aa896055ea2f147177f48671b",
    )?;
    let capture = pinned(
        "supplement-production-capture-completion-v1.json",
        "585aad1bca24688ec973bc6e047c38b7b06b278bac7334d6410a6ec8c80503af",
    )?;
    production_shape(&read(&build)?, &read(&capture)?)?;
    let integrity = integrity::validate(seal, &read(&preflight)?, &read(&capture)?)?;
    Ok(
        json!({"genuine_root_test":result,"root_test_executable_binding":executable,"root_sandbox_proof":sandbox,
        "actual_pre_build_configuration_checkpoint":preflight,"captured_configuration_inputs":configuration,
        "actual_production_build":build,"actual_capture_completion":capture,"capture_scope":candidate["scope"],"before_after_integrity":integrity,
        "configuration_scope":"Actual pre-build checkpoint matched to captured configuration bytes; no invented old947 post-build audit schema.",
        "runtime_launch_qualified":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false}),
    )
}

#[cfg(test)]
mod tests;
