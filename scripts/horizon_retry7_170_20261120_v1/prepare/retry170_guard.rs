//! Bind the successor's genuine combined Clippy/release execution and 108 native tests.
//! The earlier five-separate-execution schema is not fabricated for this deployment.
use super::*;

const IMAGE_SHA: &str = "6b9b398287815ca9581ed3fbd5e15e772eceef3eacd31a7463822288b5641c6a";
const PROOF_SHA: &str = "6caf7eef815f867ebccac5d6240d90c26fbaa4289e892c32c87f44e7988deb59";
const SEAL_SHA: &str = "13d42d64ff013439ea93dfa778a2fc638780c8f59b856ed47da4e14fa8c6b4c6";
const COMMIT: &str = "f9f30cc9d43b5915578d178a1b1fadea84f874c3";

fn exact(leaf: &str, sha256: &str) -> Bound {
    Bound {
        path: Path::new(retry170::GUARD_RUNTIME)
            .parent()
            .unwrap()
            .join(leaf),
        sha256: sha256.into(),
    }
}

fn validate(proof: &Value, seal: &Value, tests: &Value) -> Result<()> {
    ensure!(
        proof["schema"] == "horizon-retry3-guard-build-acceptance-v1"
            && proof["owner"] == "/root"
            && proof["primary_thread"] == THREAD
            && proof["source_commit"] == COMMIT
            && proof["source_contained_in_origin_account_updates"] == true
            && proof["runtime"] == serde_json::to_value(exact("guard", IMAGE_SHA))?
            && proof["features"] == json!([])
            && proof["four_strict_configurations_passed"] == true
            && proof["ordinary_tests_passed"] == 108
            && proof["ordinary_tests_failed"] == 0
            && proof["ordinary_tests_ignored"] == 0
            && proof["replay_launch_authorized"] == false
            && proof["remote_mutations"] == false
            && proof["resource_credit_bytes"] == 0,
        "exact successor guard qualification differs"
    );
    ensure!(
        seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && seal["sealer_sha256"]
                == "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3"
            && seal["destination"]
                == Path::new(retry170::GUARD_RUNTIME)
                    .parent()
                    .unwrap()
                    .to_str()
                    .unwrap()
            && seal["replay_launch_authorized"] == false
            && seal["remote_mutations"] == false,
        "normal successor guard deployment seal differs"
    );
    let members = seal["members"].as_array().context("sealed members")?;
    for (name, sha, mode) in [
        ("guard", IMAGE_SHA, "0555"),
        ("artifact-proof.json", PROOF_SHA, "0444"),
    ] {
        let rows: Vec<_> = members.iter().filter(|v| v["name"] == name).collect();
        ensure!(
            rows.len() == 1 && rows[0]["sha256"] == sha && rows[0]["mode"] == mode,
            "exact sealed successor member differs"
        );
    }
    let production = &proof["executions"]["production"];
    let clippy = &proof["executions"]["clippy-tests-and-production"];
    ensure!(
        production["unit"] == "horizon-170-retry7-guard-clippy-release-20261120-v2.service"
            && production["invocation_id"] == "9d4da24a8a5042ff9966ce903cf3b054"
            && production["unit"] == clippy["unit"]
            && production["invocation_id"] == clippy["invocation_id"]
            && production["cargo_artifact"]["features"] == json!([])
            && production["cargo_artifact"]["profile"]["opt_level"] == "3"
            && production["cargo_artifact"]["profile"]["test"] == false,
        "actual combined production and Clippy execution differs"
    );
    ensure!(
        tests["schema"] == "horizon-guard170-native-test-completion-v1"
            && tests["unit"] == "horizon-170-retry7-guard-native-tests-20261120-v2.service"
            && tests["invocation_id"] == "fe3d617c6fab46e8a6c78d27b88bd048"
            && tests["passed"] == 108
            && tests["failed"] == 0
            && tests["ignored"] == 0
            && tests["filtered_out"] == 0
            && tests["test_image"]["sha256"]
                == "c63cffe4e881d2e7d252a347886e17fe3edfb91d740be1feb1c75a1f085bf7a7"
            && tests["runtime_native_witness_and_replay_admission_completed"] == false,
        "genuine full native test completion differs"
    );
    Ok(())
}

pub(super) fn authenticate(r: &prelaunch_data::Request) -> Result<()> {
    ensure!(
        r.runtime == exact("guard", IMAGE_SHA)
            && r.qualification == exact("artifact-proof.json", PROOF_SHA)
            && r.runtime_seal == exact("deployment-seal-receipt.json", SEAL_SHA),
        "only exact normally sealed successor accepted"
    );
    let proof = bound(&r.qualification)?;
    let seal = bound(&r.runtime_seal)?;
    let tests = bound(&serde_json::from_value(
        proof["executions"]["ordinary-tests"].clone(),
    )?)?;
    validate(&proof, &seal, &tests)?;
    fixed(retry170::GUARD_RUNTIME, IMAGE_SHA, 32 << 20)?;
    ensure!(
        fs::symlink_metadata(retry170::GUARD_RUNTIME)?.mode() & 0o7777 == 0o555,
        "normally sealed successor mode required"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual_sealed_guard_and_native_tests_are_accepted() {
        let proof = bound(&exact("artifact-proof.json", PROOF_SHA)).unwrap();
        let seal = bound(&exact("deployment-seal-receipt.json", SEAL_SHA)).unwrap();
        let tests =
            bound(&serde_json::from_value(proof["executions"]["ordinary-tests"].clone()).unwrap())
                .unwrap();
        validate(&proof, &seal, &tests).unwrap();
        for key in [
            "runtime",
            "features",
            "source_commit",
            "ordinary_tests_passed",
            "executions",
        ] {
            let mut bad = proof.clone();
            bad[key] = Value::Null;
            assert!(validate(&bad, &seal, &tests).is_err(), "{key}");
        }
        for key in [
            "invocation_id",
            "test_image",
            "passed",
            "failed",
            "filtered_out",
        ] {
            let mut bad = tests.clone();
            bad[key] = Value::Null;
            assert!(validate(&proof, &seal, &bad).is_err(), "{key}");
        }
        let mut bad = seal.clone();
        bad["members"] = json!([]);
        assert!(validate(&proof, &bad, &tests).is_err());
    }
}
