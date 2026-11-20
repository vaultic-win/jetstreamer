//! Validate the exact sealed preparer, source closure and qualified guard.
use super::*;
const BUILD_COMMIT: &str = env!("HORIZON170_RETRY9_SOURCE_COMMIT");
const PREPARE_PACKAGE: &str =
    "/home/sol/workspace/jetstreamer/scripts/horizon_retry9_170_20261120_v1/prepare";
const AUDIT_SOURCE: &str = "/home/sol/workspace/jetstreamer/scripts/horizon_audit79_budget_v10_20261120_v1/audit_budget.rs";
pub(super) fn validate() -> Result<()> {
    let passed = env!("HORIZON170_RETRY9_NATIVE_TEST_COUNT").parse::<u64>()?;
    ensure!(
        passed > 0
            && BUILD_COMMIT.len() == 40
            && BUILD_COMMIT.bytes().all(|b| b.is_ascii_hexdigit()),
        "exact published successor build/test pins required"
    );
    fixed(PREPARER_IMAGE, PREPARER_SHA, 64 << 20)?;
    fixed(PREPARER_BUILD_PROOF, PREPARER_BUILD_PROOF_SHA, 1 << 20)?;
    let proof: Value = serde_json::from_slice(&read_regular(
        Path::new(PREPARER_BUILD_PROOF),
        1 << 20,
        true,
    )?)?;
    ensure!(
        proof["schema"] == "horizon-170-joined-preparer-build-proof-v1"
            && proof["epoch"] == 170
            && proof["attempt"] == "local3retry9"
            && proof["production"]["sha256"] == PREPARER_SHA
            && proof["equivalent_build_source_commit"] == BUILD_COMMIT
            && proof["source_contained_in_origin_account_updates"] == true
            && proof["tests_passed"] == passed
            && proof["tests_failed"] == 0
            && proof["production_clippy_passed"] == true
            && proof["features"] == json!(["preparation"]),
        "preparer qualification differs"
    );
    let root = Path::new(PREPARER_IMAGE)
        .parent()
        .context("runtime parent")?;
    let seal: Value = serde_json::from_slice(&read_regular(
        &root.join("deployment-seal-receipt.json"),
        1 << 20,
        true,
    )?)?;
    ensure!(
        seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && seal["destination"] == root.to_str().unwrap()
            && seal["sealer_sha256"] == SEALER_SHA,
        "preparer normal seal differs"
    );
    let members = seal["members"].as_array().context("seal members")?;
    for (name, sha, mode) in [
        ("prepare", PREPARER_SHA, "0555"),
        ("artifact-proof.json", PREPARER_BUILD_PROOF_SHA, "0444"),
    ] {
        ensure!(
            members
                .iter()
                .filter(|r| r["name"] == name && r["sha256"] == sha && r["mode"] == mode)
                .count()
                == 1,
            "runtime member differs"
        );
    }
    let sources = proof["source_members"]
        .as_array()
        .context("source closure")?;
    let closure: Value = serde_json::from_str(include_str!("../prepare/SOURCE_CLOSURE.json"))?;
    let expected = closure["files"]
        .as_array()
        .context("compiled source closure")?;
    ensure!(
        sources.len() == expected.len(),
        "incomplete preparer source closure"
    );
    let mut names = std::collections::BTreeSet::new();
    let mut main_member = None;
    for (index, (binding, declared)) in sources.iter().zip(expected).enumerate() {
        let source = Path::new(string(binding, "path")?);
        ensure!(
            source == Path::new("/home/sol/workspace/jetstreamer").join(string(declared, "path")?)
                && binding["sha256"] == declared["sha256"]
                && binding["bytes"] == declared["bytes"],
            "source member differs from compiled exact closure"
        );
        let leaf = source
            .file_name()
            .and_then(|s| s.to_str())
            .context("source leaf")?;
        names.insert(leaf);
        let name = format!("source-{index:03}-{leaf}");
        ensure!(binding["sealed_name"] == name, "source seal name differs");
        if source == Path::new(PREPARE_PACKAGE).join("main.rs") {
            main_member = Some(name.clone());
        }
        let sha = string(binding, "sha256")?;
        if source == Path::new(AUDIT_SOURCE) {
            ensure!(
                source == Path::new(AUDIT_SOURCE) && sha == audit_budget::compiled_source_sha256(),
                "preparer and launcher audit budget source differs"
            );
        }
        ensure!(
            members
                .iter()
                .filter(|r| r["name"] == name && r["sha256"] == sha && r["mode"] == "0444")
                .count()
                == 1,
            "source not sealed"
        );
        fixed(
            root.join(name).to_str().context("source path")?,
            sha,
            16 << 20,
        )?;
    }
    for name in [
        "main.rs",
        "retry170.rs",
        "resident_memory.rs",
        "data_fulfillment.rs",
        "audit_budget.rs",
        "Cargo.toml",
        "Cargo.lock",
    ] {
        ensure!(names.contains(name), "required source missing");
    }
    let main = read_regular(
        &root.join(main_member.context("sealed main source")?),
        1 << 20,
        true,
    )?;
    ensure!(
        String::from_utf8(main)?.contains(PREPARER_IMAGE),
        "source runtime path differs"
    );
    Ok(())
}
pub(super) fn guard() -> Result<()> {
    let root = Path::new(GUARD_IMAGE).parent().context("guard parent")?;
    let path = root.join("artifact-proof.json");
    fixed(
        root.join("deployment-seal-receipt.json")
            .to_str()
            .context("guard seal path")?,
        "cf0cc04561dd6f9c98e540b324a2352540ab48c0d13cd665280bc06ad18ee2eb",
        1 << 20,
    )?;
    fixed(
        path.to_str().unwrap(),
        "d78e0dd5f64df1f618cc1f94ae1174ec9fa176ff1095e27160c2b9f26acca2bd",
        1 << 20,
    )?;
    let proof: Value = serde_json::from_slice(&read_regular(&path, 1 << 20, true)?)?;
    ensure!(
        proof["schema"] == "horizon-retry3-guard-build-acceptance-v1"
            && proof["production"]["sha256"] == GUARD_SHA
            && proof["strict_clippy_all_targets_passed"] == true
            && proof["production_release_build_passed"] == true
            && proof["ordinary_tests_passed"] == 111
            && proof["features"] == json!([])
            && proof["source_contained_in_origin_account_updates"] == true,
        "guard qualification differs"
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_deployed_preparer_and_guard_provenance_are_consumable() {
        validate().unwrap();
        guard().unwrap();
    }
}
