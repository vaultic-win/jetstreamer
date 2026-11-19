//! Validate the exact sealed preparer, source closure and qualified guard.
use super::*;
const BUILD_COMMIT: &str = "60ef954d8c1665a0f259cde34ba9fc46a5683d1a";
const PREPARE_PACKAGE: &str = "/home/sol/workspace/jetstreamer/scripts/horizon_retry6_170_20261118_v1/prepare-live166retry8-v1";
pub(super) fn validate() -> Result<()> {
    fixed(PREPARER_IMAGE, PREPARER_SHA, 64 << 20)?;
    fixed(PREPARER_BUILD_PROOF, PREPARER_BUILD_PROOF_SHA, 1 << 20)?;
    let proof: Value = serde_json::from_slice(&read_regular(
        Path::new(PREPARER_BUILD_PROOF),
        1 << 20,
        true,
    )?)?;
    ensure!(
        proof["schema"] == "horizon-live166retry8-preparer-build-proof-v1"
            && proof["epoch"] == 170
            && proof["attempt"] == "local3retry6"
            && proof["production"]["sha256"] == PREPARER_SHA
            && proof["equivalent_build_source_commit"] == BUILD_COMMIT
            && proof["source_contained_in_origin_account_updates"] == true
            && proof["tests_passed"] == 305
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
    ensure!(sources.len() >= 40, "incomplete preparer source closure");
    let mut names = std::collections::BTreeSet::new();
    for binding in sources {
        let source = Path::new(string(binding, "path")?);
        ensure!(
            source.parent() == Some(Path::new(PREPARE_PACKAGE)),
            "foreign source member"
        );
        let leaf = source
            .file_name()
            .and_then(|s| s.to_str())
            .context("source leaf")?;
        ensure!(names.insert(leaf), "duplicate source member");
        let name = format!("source-{leaf}");
        let sha = string(binding, "sha256")?;
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
        "Cargo.toml",
        "Cargo.lock",
    ] {
        ensure!(names.contains(name), "required source missing");
    }
    let main = read_regular(&root.join("source-main.rs"), 1 << 20, true)?;
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
        path.to_str().unwrap(),
        "936090b337c3fe4981f046df3fd9ff2b007d10430b7a11a5f6abe546bca701ec",
        1 << 20,
    )?;
    let proof: Value = serde_json::from_slice(&read_regular(&path, 1 << 20, true)?)?;
    ensure!(
        proof["schema"] == "horizon-retry3-guard-build-acceptance-v1"
            && proof["production"]["sha256"] == GUARD_SHA
            && proof["four_strict_configurations_passed"] == true
            && proof["ordinary_tests_passed"] == 98
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
