//! The accepted packet supplies immutable identity evidence; no large reads on startup clock.
use super::*;
const CAPABILITY: &str =
    "/var/lib/jetstreamer/horizon265-replacement-20261119-static-v3/input-capability.json";
const PRODUCER_TEMPLATE: &str =
    include_str!("../config/horizon-qualify-265-replacement-20261119-v3.service");
const GUARD_TEMPLATE: &str =
    include_str!("../config/horizon-265-replacement-20261119-protective-v3.service");
const TIMER_TEMPLATE: &str =
    include_str!("../config/horizon-265-replacement-20261119-protective-v3.timer");
const RETENTION_TEMPLATE: &str =
    include_str!("../config/horizon265-replacement-terminal-retention-v3.target");
fn packet_identity(p: &Path) -> Result<Value> {
    let m = fs::symlink_metadata(p)?;
    ensure!(
        p.canonicalize()? == p
            && m.is_file()
            && m.uid() == 0
            && m.gid() == 0
            && m.mode() & 0o222 == 0
            && m.nlink() == 1,
        "input no longer immutable"
    );
    Ok(
        json!({"device":m.dev(),"inode":m.ino(),"bytes":m.len(),"uid":m.uid(),"gid":m.gid(),"mode":m.mode(),"nlink":m.nlink(),"mtime":m.mtime(),"mtime_nsec":m.mtime_nsec(),"ctime":m.ctime(),"ctime_nsec":m.ctime_nsec()}),
    )
}
pub(super) fn check_inputs() -> Result<Value> {
    let v = bound(&json!({"path":AUTH,"sha256":AUTH_SHA}))?;
    ensure!(
        v["schema"] == "horizon265-input-packet-v1"
            && v["epoch"] == 265
            && v["sealed_file_bytes_and_index_structure_accepted"] == true
            && v["source_commit"] == "1ae137f752f605463e52dad3055ab8cb161b64e2",
        "input packet differs"
    );
    let files = v["files"].as_array().context("packet files")?;
    let expected = [
        (
            SNAPSHOT,
            "04eb59e2dbbc2b0d4f1535741fa9d56794c32ad18e14c98df4fa76a5ae397641",
        ),
        (NODE, NODE_SHA),
        (
            WORKER,
            "c3b2c33420bcf6b6809d7f0b43309e7d57d2791a88e2d4074d21d4f636c521e4",
        ),
        (
            GENESIS,
            "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945",
        ),
    ];
    ensure!(files.len() == expected.len(), "packet artifact census");
    for (path, sha) in expected {
        let selected: Vec<_> = files
            .iter()
            .filter(|v| v["path"] == path && v["sha256"] == sha)
            .collect();
        ensure!(
            selected.len() == 1 && selected[0]["identity"] == packet_identity(Path::new(path))?,
            "packet member changed {path}"
        );
    }
    ensure!(
        v["manifest"]
            == json!({"path":MANIFEST,"sha256":"a269b418dc5bcd508850d0293cf05e64875d7610c402b696cf8d15f9775c5fcf"}),
        "manifest differs"
    );
    bound(&v["manifest"])?;
    let seal = bound(&v["cache_seal"])?;
    ensure!(seal["destination"] == CACHE, "cache namespace changed");
    let indexes = v["indexes"].as_array().context("packet indexes")?;
    ensure!(indexes.len() == 3, "index count differs");
    for index in indexes {
        let b = &index["binding"];
        let p = Path::new(text(b, "path")?);
        ensure!(
            p.parent() == Some(Path::new(CACHE)) && b["identity"] == packet_identity(p)?,
            "sealed index changed"
        );
    }
    check_static()?;
    capabilities(&bound(&pin(Path::new(CAPABILITY))?)?)?;
    ensure!(
        hash(Path::new(SEALER))? == SEALER_SHA && hash(Path::new(GUARD))? == GUARD_SHA,
        "tool changed"
    );
    Ok(v)
}
pub(super) fn check_static() -> Result<()> {
    let seal_path = Path::new(STATIC).join("deployment-seal-receipt.json");
    let seal = bound(&pin(&seal_path)?)?;
    ensure!(
        seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && seal["destination"] == STATIC
            && seal["sealer_sha256"] == SEALER_SHA
            && seal["publication_authorized"] == false
            && seal["replay_launch_authorized"] == false
            && seal["remote_mutations"] == false,
        "static seal differs"
    );
    for (name, bytes) in [
        (UNIT, PRODUCER_TEMPLATE),
        (GUARD_UNIT, GUARD_TEMPLATE),
        (TIMER, TIMER_TEMPLATE),
        (RETENTION, RETENTION_TEMPLATE),
    ] {
        let p = Path::new(STATIC).join(name);
        packet_identity(&p)?;
        ensure!(
            small(&p)? == bytes.as_bytes()
                && seal["members"]
                    .as_array()
                    .context("static members")?
                    .iter()
                    .filter(|m| m["name"] == name
                        && m["sha256"] == hash_bytes(bytes.as_bytes())
                        && m["mode"] == "0444")
                    .count()
                    == 1,
            "static template differs {name}"
        );
    }
    let capability = Path::new(CAPABILITY);
    packet_identity(capability)?;
    ensure!(
        seal["members"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|m| m["name"] == "input-capability.json"
                && m["sha256"] == hash(capability).unwrap_or_default()
                && m["mode"] == "0444")
            .count()
            == 1,
        "capability not sealed"
    );
    Ok(())
}
#[cfg(test)]
fn accepted_terminal(v: &Value) -> Result<()> {
    ensure!(
        v["LoadState"] == "loaded"
            && v["ActiveState"] == "inactive"
            && v["SubState"] == "dead"
            && v["Result"] == "success"
            && v["ExecMainCode"] == "1"
            && v["ExecMainStatus"] == "0"
            && v["NRestarts"] == "0"
            && v["MainPID"] == "0"
            && v["ControlPID"] == "0"
            && iid(text(v, "InvocationID")?),
        "qualification not a clean natural terminal"
    );
    Ok(())
}
/// Main seals genuine qualification proofs. The input packet itself explicitly denies them.
pub(super) fn capabilities(v: &Value) -> Result<()> {
    ensure!(
        v["schema"] == "horizon265-main-input-capability-v1"
            && v["epoch"] == 265
            && v["Main_accepted"] == true
            && v["input_packet"] == json!({"path":AUTH,"sha256":AUTH_SHA})
            && v["node"] == json!({"path":NODE,"sha256":NODE_SHA})
            && v["worker"]
                == json!({"path":WORKER,"sha256":"c3b2c33420bcf6b6809d7f0b43309e7d57d2791a88e2d4074d21d4f636c521e4"}),
        "foreign input capability"
    );
    for k in [
        "replay_launch_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
        "full_epoch_qualified",
    ] {
        ensure!(v[k] == false, "capability overclaims {k}");
    }
    for k in [
        "codec_regressions",
        "native_input",
        "node_negative_probes",
        "network",
    ] {
        bound(&v[k])?;
    }
    codec(&v["codec_regressions"])?;
    super::current::native_input(&v["native_input"])?;
    let probes = bound(&v["node_negative_probes"])?;
    ensure!(
        probes["schema"] == "horizon265-selected-node-negative-probes-v1"
            && probes["node"] == v["node"]
            && probes["manifest_sha256"]
                == "a269b418dc5bcd508850d0293cf05e64875d7610c402b696cf8d15f9775c5fcf"
            && probes["fingerprint_rejection_passed"] == true
            && probes["manifest_decoded_before_snapshot_filename_rejection"] == true
            && probes["output_and_work_directories_empty"] == true,
        "node capability missing"
    );
    for key in ["fingerprint", "wrong_filename"] {
        let p = bound(&probes[key])?;
        ensure!(
            p["terminal"]["ActiveState"] == "failed"
                && p["terminal"]["Result"] == "exit-code"
                && p["terminal"]["ExecMainStatus"] == "1"
                && p["terminal"]["NRestarts"] == "0"
                && p["terminal"]["MainPID"] == "0"
                && iid(text(&p["terminal"], "InvocationID")?),
            "negative probe not at expected failure gate"
        );
        bound(&p["actual_command_and_journal"])?;
    }
    network(&bound(&v["network"])?)?;
    Ok(())
}
fn codec(binding: &Value) -> Result<()> {
    // Bind the actual accepted source-equivalence review. Its older commit label
    // is not evidence that the later fixture additions were part of that commit.
    ensure!(
        *binding
            == json!({
                "path":"/var/lib/jetstreamer/horizon265-codec-test-evidence-20261119-v1/review.json",
                "sha256":"dadba3fc392359dc328ca899ca8fbac24dea3f79621bcbd5da1a898d72cf03f6"
            }),
        "codec source-equivalence review differs"
    );
    let review = bound(binding)?;
    ensure!(
        review["schema"] == "horizon265-codec-test-source-equivalence-v1"
            && review["epoch"] == 265
            && review["selected_node_source"] == "1ae137f752f605463e52dad3055ab8cb161b64e2"
            && review["actual_passed_tests"] == 256
            && review["actual_failed_tests"] == 0
            && review["original_tests_executed"] == true
            && review["new_tests_executed"] == false,
        "codec historical evidence differs"
    );
    for key in [
        "native_runtime_qualified",
        "replay_launch_authorized",
        "admission_authorized",
        "publication_authorized",
        "resource_release_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(review[key] == false, "codec review overclaims {key}");
    }
    // Original admission binds exact tested source and fixture bytes. Historical
    // completion can have a blank PID1 InvocationID after unit collection; the
    // retained original invocation is bound in the accepted completion receipt.
    bound(&review["original_test_admission"])?;
    bound(&review["original_first_guard"])?;
    let completion = bound(&review["original_test_completion"])?;
    ensure!(
        completion["schema"] == "horizon-qualified-library-tests-natural-completion-v1"
            && completion["Main_accepted"] == true
            && completion["unit"] == review["original_test_unit"]
            && completion["original_invocation_id"] == review["original_test_invocation_id"]
            && iid(text(&completion, "original_invocation_id")?)
            && completion["actual_passed_tests"] == 256
            && completion["actual_failed_tests"] == 0
            && completion["guard_stopped_after_natural_closure"] == true
            && completion["production_deployment_or_replay_qualified"] == false
            && completion["original_test_journal"] == review["original_test_journal"],
        "codec original completion differs"
    );
    let terminal = &completion["native_terminal"];
    for (key, value) in [
        ("ActiveState", "inactive"),
        ("SubState", "dead"),
        ("Result", "success"),
        ("MainPID", "0"),
        ("ControlPID", "0"),
        ("ExecMainStatus", "0"),
        ("NRestarts", "0"),
    ] {
        ensure!(terminal[key] == value, "codec completion terminal {key}");
    }
    let passed = completion["actual_passed_test_names"]
        .as_array()
        .context("passed codec tests")?;
    for test in review["relevant_passed_tests"]
        .as_array()
        .context("relevant codec tests")?
    {
        ensure!(
            passed.contains(test),
            "codec regression absent from actual completion"
        );
    }
    let journal = &review["original_test_journal"];
    let p = Path::new(text(journal, "path")?);
    let m = fs::symlink_metadata(p)?;
    ensure!(
        m.uid() == 0 && m.mode() & 0o022 == 0,
        "mutable codec journal"
    );
    // JSONL is deliberately verified as bytes, not decoded as a single JSON object.
    ensure!(
        hash_bytes(&small(p)?) == text(journal, "sha256")?,
        "codec journal changed"
    );
    Ok(())
}
fn network(proof: &Value) -> Result<()> {
    ensure!(
        proof["schema"] == "horizon265-service-effective-car-header-proof-v1"
            && proof["http_status"] == 206
            && proof["expected_root_cid"]
                == "bafyreibgf4smruua7seioyolngrziiqsgeae3d4zmcvptg7m4xwzyafqwu"
            && proof["car_header_accepted"] == true
            && proof["service_effective_namespace_verified"] == true
            && proof["producer_template_sha256"] == hash_bytes(PRODUCER_TEMPLATE.as_bytes())
            && proof["replay_launch_authorized"] == false,
        "network proof differs"
    );
    for name in ["headers", "body"] {
        let path = Path::new(ROOT).join("network-proof").join(name);
        ensure!(
            proof[name]["path"] == path.to_str().context("path UTF8")?
                && hash(&path)? == text(&proof[name], "sha256")?
                && identity(&path)?["bytes"] == proof[name]["identity"]["bytes"],
            "network artifact changed"
        );
    }
    Ok(())
}
pub(super) fn check_network() -> Result<()> {
    let capability = bound(&pin(Path::new(CAPABILITY))?)?;
    network(&bound(&capability["network"])?)
}
pub(super) fn plan_validate(p: &Value) -> Result<()> {
    ensure!(
        p["schema"] == "horizon265-current-fleet-launch-plan-v1"
            && p["candidate_epoch"] == 265
            && p["worker_root"] == ROOT
            && p["state_directory"] == STATE
            && p["producer_unit"] == UNIT
            && p["guard_unit"] == GUARD_UNIT
            && p["timer_unit"] == TIMER
            && p["setup_seconds"] == 60
            && p["operator_deadline_seconds"] == 50
            && p["maximum_root_physical_bytes"] == CAP
            && p["memory_high_bytes"] == HIGH
            && p["memory_max_bytes"] == MAX
            && p["maximum_worker_vmas"] == 3500000
            && p["input_auth"] == json!({"path":AUTH,"sha256":AUTH_SHA})
            && p["input_capability"] == pin(Path::new(CAPABILITY))?
            && p["static_seal"] == pin(&Path::new(STATIC).join("deployment-seal-receipt.json"))?,
        "unsupported launch plan"
    );
    for k in [
        "remote_mutations",
        "archive_retirement_authorized",
        "reuse_original_invocation_authorized",
        "full_epoch_qualified",
    ] {
        ensure!(p[k] == false, "foreign plan authority");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn template_preserves_exact_replacement_inputs_and_no_override_routes() {
        assert!(PRODUCER_TEMPLATE.contains(&format!(
            "ExecStart={NODE} 265 {ROOT}/output --verify --root-checkpoint-cohort"
        )));
        assert!(PRODUCER_TEMPLATE.contains(&format!("--snapshot-archive={SNAPSHOT}")));
        assert!(PRODUCER_TEMPLATE.contains(&format!("{CACHE}:{ROOT}/output/compact-indexes/264")));
        assert!(PRODUCER_TEMPLATE.contains(&format!("{CACHE}:{ROOT}/output/compact-indexes/265")));
        assert!(PRODUCER_TEMPLATE.contains(&format!(
            "/usr/bin/test -f {TOKENS}/${{INVOCATION_ID}}/guard-admission.json"
        )));
        assert!(
            !PRODUCER_TEMPLATE
                .lines()
                .any(|s| s.starts_with("EnvironmentFile=") || s.starts_with("PassEnvironment="))
        );
        assert!(RETENTION_TEMPLATE.contains(&format!("After={UNIT}")));
        for key in ["Wants=", "Requires=", "BindsTo=", "Upholds="] {
            assert!(!RETENTION_TEMPLATE.contains(key));
        }
    }
    #[test]
    fn packet_and_old_owner_cannot_substitute_for_native_input_proof() {
        assert!(capabilities(&json!({"schema":"horizon265-input-packet-v1","epoch":265,"sealed_file_bytes_and_index_structure_accepted":true})).is_err());
        let mut good = json!({"LoadState":"loaded","ActiveState":"inactive","SubState":"dead","Result":"success","ExecMainCode":"1","ExecMainStatus":"0","NRestarts":"0","MainPID":"0","ControlPID":"0","InvocationID":"a".repeat(32)});
        accepted_terminal(&good).unwrap();
        good["ActiveState"] = json!("active");
        assert!(accepted_terminal(&good).is_err());
        good["ActiveState"] = json!("inactive");
        good["ExecMainStatus"] = json!("1");
        assert!(accepted_terminal(&good).is_err());
    }
}
