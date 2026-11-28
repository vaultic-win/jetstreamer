//! Accept the sealed retry8 guard built with the shared writer-query deadline.
use super::*;

const PROOF: &str = "e1adf77ea469cf2e60f68ba421314f5ba8fab0e9b4ca7128efbc2825d7aa5cce";
const SEAL: &str = "8756dca34813d3fa5caec5a4ebe43a8729565b84a8443aeab85015f94ca0b90a";

fn member(name: &str, hash: &str) -> Bound {
    Bound {
        path: Path::new(retry170::GUARD_RUNTIME)
            .parent()
            .unwrap()
            .join(name),
        sha256: hash.to_owned(),
    }
}
fn validate(proof: &Value, seal: &Value) -> Result<()> {
    ensure!(
        proof["schema"] == "horizon-retry3-guard-build-acceptance-v1"
            && proof["owner"] == "/root"
            && proof["primary_thread"] == THREAD
            && proof["source_commit"] == "47830d36737f5210ba7f536713b649882fc6c36d"
            && proof["source_contained_in_origin_account_updates"] == true
            && proof["runtime"] == serde_json::to_value(member("guard", retry170::GUARD_SHA))?
            && proof["features"] == json!([])
            && proof["strict_clippy_all_targets_passed"] == true
            && proof["production_release_build_passed"] == true
            && proof["ordinary_tests_passed"] == 110
            && proof["ordinary_tests_ignored"] == 0
            && proof["ordinary_tests_failed"] == 0
            && proof["ordinary_tests_filtered"] == 0
            && proof["executions"]["build"]["invocation_id"] == "1c070a42c04c43a1a44015b5cfd5cc75"
            && proof["executions"]["ordinary-tests"]["invocation_id"]
                == "f5312150f4da4d50b4f83a9edb92e21d"
            && proof["resource_credit_bytes"] == 0
            && proof["replay_launch_authorized"] == false,
        "guard release proof or native suite mismatch"
    );
    ensure!(
        seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && seal["destination"]
                == Path::new(retry170::GUARD_RUNTIME)
                    .parent()
                    .unwrap()
                    .to_str()
                    .unwrap()
            && seal["sealer_sha256"]
                == "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3"
            && seal["remote_mutations"] == false
            && seal["replay_launch_authorized"] == false,
        "wrong guard seal"
    );
    let members = seal["members"].as_array().context("sealed members")?;
    let sealed = |name: &str, hash: &str, mode: &str| {
        members
            .iter()
            .filter(|m| m["name"] == name && m["sha256"] == hash && m["mode"] == mode)
            .count()
            == 1
    };
    ensure!(
        sealed("guard", retry170::GUARD_SHA, "0555")
            && sealed("artifact-proof.json", PROOF, "0444"),
        "missing sealed guard/proof"
    );
    let sources = proof["source_members"]
        .as_array()
        .context("guard source closure")?;
    for (name, data) in [
        (
            "writer_query.rs",
            include_bytes!("../../horizon_retry7_170_20261120_v1/guard/writer_query.rs").as_slice(),
        ),
        (
            "completed_output_scope.rs",
            include_bytes!("../../horizon_retry7_170_20261120_v1/guard/completed_output_scope.rs")
                .as_slice(),
        ),
    ] {
        let repository_path = format!("scripts/horizon_retry7_170_20261120_v1/guard/{name}");
        let sha = digest(data);
        let r = sources
            .iter()
            .find(|r| r["repository_path"] == repository_path)
            .context("guard deadline source missing")?;
        ensure!(
            r["bytes"] == data.len()
                && r["sha256"] == sha
                && sealed(
                    r["sealed_name"].as_str().context("missing source member")?,
                    &sha,
                    "0444"
                ),
            "sealed guard writer deadline differs"
        );
    }
    Ok(())
}
pub(super) fn authenticate(r: &prelaunch_data::Request) -> Result<()> {
    ensure!(
        r.runtime == member("guard", retry170::GUARD_SHA)
            && r.qualification == member("artifact-proof.json", PROOF)
            && r.runtime_seal == member("deployment-seal-receipt.json", SEAL),
        "wrong guard bindings"
    );
    validate(&bound(&r.qualification)?, &bound(&r.runtime_seal)?)?;
    fixed(retry170::GUARD_RUNTIME, retry170::GUARD_SHA, 32 << 20)?;
    ensure!(
        fs::symlink_metadata(retry170::GUARD_RUNTIME)?.mode() & 0o7777 == 0o555,
        "sealed guard mode"
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sealed_source_matches_new_guard() {
        let proof = bound(&member("artifact-proof.json", PROOF)).unwrap();
        let seal = bound(&member("deployment-seal-receipt.json", SEAL)).unwrap();
        validate(&proof, &seal).unwrap();
        let mut bad = proof;
        bad["source_members"] = json!([]);
        assert!(validate(&bad, &seal).is_err());
    }
}
