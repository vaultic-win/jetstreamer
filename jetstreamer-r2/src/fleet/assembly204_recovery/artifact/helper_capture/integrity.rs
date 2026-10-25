//! Agreement of the actual pre-build pins, captured source/configuration and
//! final rechecks. Cargo/rustfmt are wrapper-checked tools, not captured compilers.
use super::*;
const WORKTREE: &str = "/home/ubuntu/workspace/jetstreamer/.codex/tmp-readiness/epoch204-helper-immutable-reader-source-v1";
const STATIC: &str = "50e5af49cb424b0d60da0add3430e9b598f76e8b4a1e7a83eae99124a411cb0e";
const WRAPPER: &str = "6396feecb1193a0c3fa3b220556af423a15d0ad20b283d5080dc66e797700eb0";
fn shape(
    inputs: &Value,
    checkpoint: &Value,
    tracked: &Value,
    rechecks: &Value,
    command: &Value,
    capture: &Value,
    preflight: &Value,
) -> Result<()> {
    ensure!(
        inputs["source_commit"] == REVISION
            && inputs["source_tree"] == TREE
            && checkpoint["commit"] == REVISION
            && checkpoint["tree"] == TREE
            && tracked["commit"] == REVISION
            && tracked["tree"] == TREE
            && command["source"]["commit"] == REVISION
            && command["source"]["tree"] == TREE
            && command["static_inputs_sha256"] == STATIC
            && command["script_sha256"] == inputs["script_sha256"]
            && inputs["script_sha256"]["run-bounded-build-capture.py"] == WRAPPER
            && inputs["script_sha256"]["run-production-build-v1.py"]
                == "17c0c5149e7d28a6d55ce3bc9c725e84dc780e2f43c61705cce351f4c9d00877"
            && inputs["script_sha256"]["capture-candidate-v1.py"]
                == "081a1f25a1e4947775652a692f76ea49924d35f4af3c70d048520bb48dfbc6b5"
            && capture["capture_workflow_unchanged"] == true
            && rechecks["all_reopened_and_rehashed"] == true,
        "204 frozen source, tool/config pins or before/after workflow differs"
    );
    let files = checkpoint["files"]
        .as_object()
        .context("204 frozen source hashes missing")?;
    let tracked_files = tracked["tracked_files"]
        .as_array()
        .context("204 captured tracked source missing")?;
    let mut seen = BTreeSet::new();
    ensure!(
        !files.is_empty() && files.len() == tracked_files.len(),
        "204 captured source census differs"
    );
    for file in tracked_files {
        let path = s(file, "relative_path")?;
        ensure!(
            seen.insert(path)
                && files.get(path) == Some(&file["sha256"])
                && canonical_digest(&file["sha256"]),
            "204 pre-build/captured tracked source hash differs"
        );
    }
    let records = rechecks["records"]
        .as_array()
        .context("204 final input rechecks missing")?;
    ensure!(
        records.iter().all(|r| r["identity_unchanged"] == true),
        "204 final captured input identity changed"
    );
    let matching = |path: &str, digest: &Value| {
        records
            .iter()
            .any(|r| r["path"] == path && r["sha256"] == *digest)
    };
    let pins = inputs["input_sha256"]
        .as_object()
        .context("204 static tool/config input hashes missing")?;
    ensure!(pins.len() == 9, "204 static tool/config census differs");
    for (path, digest) in pins {
        ensure!(
            canonical_digest(digest),
            "204 static tool/config digest missing"
        );
        if let Some(relative) = path.strip_prefix(&format!("{WORKTREE}/")) {
            ensure!(
                files.get(relative) == Some(digest) && matching(path, digest),
                "204 pre-build/captured/final manifest or configuration hash differs"
            );
        } else {
            let (tool, expected) = if path.ends_with("/bin/rustc") {
                (
                    "rustc",
                    "3690cc576ede140504698405d5d8fa3826aaadbe71699c6c4ed0a565d6f493e2",
                )
            } else if path.ends_with("/bin/cargo") {
                (
                    "cargo",
                    "ff3022fcbd13b08434ea7afde9a0ef9d5b3f5c17b5fc7a40031be3ee000a6a24",
                )
            } else {
                ensure!(
                    path.ends_with("/bin/rustfmt"),
                    "204 unknown static tool scope"
                );
                (
                    "rustfmt",
                    "5005cdcd39ded526dca8fa6ccd716d42fc7da54469034e055dbf54649bec7877",
                )
            };
            let expected_path = format!(
                "/home/ubuntu/.rustup/toolchains/1.98.0-x86_64-unknown-linux-gnu/bin/{tool}"
            );
            ensure!(
                path.as_str() == expected_path.as_str()
                    && digest.as_str() == Some(expected)
                    && (tool != "rustc" || matching(path, digest)),
                "204 captured compiler or wrapper-checked tool hash differs"
            );
        }
    }
    for c in preflight["configuration"]
        .as_array()
        .context("204 preflight configs missing")?
    {
        ensure!(
            matching(s(c, "path")?, &c["sha256"]),
            "204 pre-build/final configuration hash differs"
        );
    }
    Ok(())
}
pub(super) fn validate(seal: &Seal, preflight: &Value, capture: &Value) -> Result<Value> {
    let pinned = |name: &str, sha: &str| member(seal, name, sha, 16 << 20);
    let inputs = pinned("candidate-evidence--production-static-inputs.json", STATIC)?;
    let checkpoint = pinned(
        "candidate-evidence--source-checkpoint.json",
        "3a128b31031257c2abaa4abaa71ae9c95f5a3323013d424a78cb374d76e3f436",
    )?;
    let tracked = pinned(
        "tracked-source-manifest.json",
        "f37e665bda5a3205019306dbd1ea84301eed31cc48259c554e1acef6798e75ca",
    )?;
    let rechecks = pinned(
        "final-input-identity-rechecks.json",
        "d7b226b3e0c7406b6202abd6af19a9325a81b84ce223621cf83d4b35af915e9c",
    )?;
    let command = pinned(
        "candidate-evidence--production-command.json",
        "ba68904b06c7a27bf6ce37217308ec56d0a72101a29bc11a838c16af954f6adf",
    )?;
    let wrapper = pinned("candidate-evidence--run-bounded-build-capture.py", WRAPPER)?;
    let build_workflow = pinned(
        "candidate-evidence--run-production-build-v1.py",
        "17c0c5149e7d28a6d55ce3bc9c725e84dc780e2f43c61705cce351f4c9d00877",
    )?;
    let capture_workflow = pinned(
        "candidate-evidence--capture-candidate-v1.py",
        "081a1f25a1e4947775652a692f76ea49924d35f4af3c70d048520bb48dfbc6b5",
    )?;
    shape(
        &read(&inputs)?,
        &read(&checkpoint)?,
        &read(&tracked)?,
        &read(&rechecks)?,
        &read(&command)?,
        capture,
        preflight,
    )?;
    Ok(
        json!({"pre_build_static_input_pins":inputs,"pre_build_frozen_source_hashes":checkpoint,
        "captured_tracked_source_hashes":tracked,"final_input_identity_rechecks":rechecks,
        "actual_production_command":command,"reviewed_before_after_wrapper":wrapper,
        "build_workflow":build_workflow,"capture_workflow":capture_workflow,
        "source_and_configuration_before_after_agree":true,
        "tool_scope":"Pinned wrapper rehashes cargo/rustfmt/rustc before build, before capture and after capture; final captured compiler record independently matches rustc. Cargo/rustfmt are not claimed as captured compiler records.",
        "transitive_audit_expanded":false,"runtime_launch_qualified":false,"publication_authorized":false,
        "remote_mutations":false,"r2_mutations":false}),
    )
}
#[cfg(test)]
mod tests;
