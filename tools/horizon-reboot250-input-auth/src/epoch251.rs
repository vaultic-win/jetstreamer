//! Bind reused sealed epoch 251 inputs to the authenticated original restore.
use super::*;
const MANIFEST251: (&str, &str) = (
    "/var/lib/jetstreamer/horizon251-single-epoch-manifest-20261118-v1/preflight-251-single-epoch.json",
    "e40e8d0341440d29cff7cd35e79e5f713d7908ce42f3a1c4995e1b2924551f14",
);
const INPUT: &str = "/var/lib/jetstreamer/horizon251-native-input-20261118-v1";
const PUBLISHED_NODE: (&str, &str) = (
    "/var/lib/jetstreamer/horizon234-production-eabd0b6a-candidate922-v1/jetstreamer-node",
    "02f42f2988dd31437e2c874414f247667200663c874042783406b5517b0d519b",
);
const NODE_SOURCE: (&str, &str) = (
    "/var/lib/jetstreamer/horizon234-production-eabd0b6a-candidate922-v1/source-manifest.json",
    "e389f94315910f81fc7e63337a62498b09ddafbe303d9b5e066b4290360eee55",
);
const NODE_BUILD: (&str, &str) = (
    "/var/lib/jetstreamer/horizon234-production-eabd0b6a-candidate922-v1/production-build-proof.json",
    "817e6ae6f82cdc3b688d8e148d81a076a2d08ca429e43ea70efdfc7d78369b27",
);
const NODE_SEAL: (&str, &str) = (
    "/var/lib/jetstreamer/horizon234-production-eabd0b6a-candidate922-v1/deployment-seal-receipt.json",
    "ebfb9bea01effdf7da4aaa92ff9f752bcccae368139860e79f320f3c063f052c",
);
const BOOTSTRAP251: (&str, &str) = (
    "/var/lib/jetstreamer/horizon251-native-input-20261118-v1/snapshot-108431365-C5eqGwzDFEDfeBovidro6WnY3Drw7caJ2p2mjnJbGJVE.tar.zst",
    "b7af2058dd498bdf8c0f7e2a717a0d7c8153c20027eca2c3c2de15351b87b311",
);
const NATIVE: (&str, &str) = (
    "/home/ubuntu/.codex/diagnostics/horizon251-native-small-terminal-20261118-v1/terminal-receipt.json",
    "f0e1235e880ec1f8c9a2137256db9ef568f34aef9b0218b3447ad5a0be8da0b3",
);
const SOURCE: (&str, &str) = (
    "/home/ubuntu/.jetstreamer-private/qualification-251-native-input-20261118-v2/source-basis.json",
    "eed60529f1229597101307cf1c8b77fc1d015ce7f2cdb1e3760c812b93f4aca4",
);
fn sealed(value: &Value) -> Result<()> {
    ensure!(
        value["identity"]["uid"] == 0
            && value["identity"]["gid"] == 0
            && value["identity"]["mode"].as_u64().context("mode")? & 0o222 == 0,
        "input must remain immutable and root-owned"
    );
    Ok(())
}
fn validate_scope(m: &Value) -> Result<()> {
    let v = &m["manifest"];
    ensure!(
        m["manifest_fingerprint"]
            == "sha256:e214b640c55cc6ec0e431c66f9cbd0076c4620578c2dea1e6c2324e7f616789e"
            && v["first_epoch"] == 251
            && v["last_epoch"] == 251
            && v["publication_boundary_epoch"] == 251
            && v["epochs"].as_array().is_some_and(|e| e.len() == 1)
            && v["epochs"][0]["epoch"] == 251
            && v["epochs"][0]["runtime"] == "solana-v1.7.15",
        "foreign singleton manifest"
    );
    let e = &v["epochs"][0];
    ensure!(
        e["bootstrap"]["slot"] == 108431365
            && e["bootstrap"]["generation"] == 1638079985418599u64
            && e["bootstrap"]["accounts_hash"] == "C5eqGwzDFEDfeBovidro6WnY3Drw7caJ2p2mjnJbGJVE"
            && e["verification_cohort"]["first_epoch"] == 251
            && e["verification_cohort"]["last_epoch"] == 251,
        "wrong bootstrap or cohort"
    );
    let checkpoints = e["post_bootstrap_root_checkpoints"]
        .as_array()
        .context("checkpoints")?;
    ensure!(
        checkpoints.len() == 1
            && checkpoints[0]["slot"] == 108863259
            && checkpoints[0]["accounts_hash"] == "7h1Ynk3rFxcF7GuUQ3vjxzSvXe8sykWqCkYYHLXFJ6nz"
            && checkpoints[0]["generation"] == 1638317210911330u64,
        "canonical checkpoint changed"
    );
    Ok(())
}
fn validate_node_build(source: &Value, build: &Value) -> Result<()> {
    ensure!(
        source["source_commit"] == "eabd0b6a78464130d1e30eff30bb75267502abde"
            && source["no_tracked_diffs"] == true
            && build["all_source_members_revalidated_at_natural_closure"] == true
            && build["actual_terminal"]["Result"] == "success"
            && build["actual_terminal"]["ExecMainStatus"] == "0"
            && build["clean_full_source_manifest"]["sha256"] == NODE_SOURCE.1,
        "node source/build evidence differs"
    );
    let nodes: Vec<_> = build["artifacts"]
        .as_array()
        .context("build artifacts")?
        .iter()
        .filter(|a| a["target"] == "jetstreamer-node")
        .collect();
    ensure!(nodes.len() == 1, "node build artifact must be unique");
    ensure!(
        nodes[0]["binary"]["sha256"] == PUBLISHED_NODE.1 && nodes[0]["actual_features"] == "[]",
        "node build binding differs"
    );
    Ok(())
}
fn captured_node_evidence() -> Result<Value> {
    let source = pin(NODE_SOURCE)?;
    let build = pin(NODE_BUILD)?;
    let seal = pin(NODE_SEAL)?;
    for value in [&source, &build, &seal] {
        sealed(value)?;
    }
    validate_node_build(
        &serde_json::from_slice(&fs::read(NODE_SOURCE.0)?)?,
        &serde_json::from_slice(&fs::read(NODE_BUILD.0)?)?,
    )?;
    Ok(json!({"source":source,"build":build,"seal":seal,
        "exact_epoch251_node_replay_qualified":false,
        "fresh_source_publication_admission_check_required":true}))
}
pub(super) fn run(published_node: bool) -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    ensure!(
        args.len() == 3 && unsafe { libc::geteuid() } == 0,
        "usage as root: check-251[-published-node] OUTPUT_JSON"
    );
    let output = Path::new(&args[2]);
    let parent = output.parent().context("output parent")?;
    ensure!(
        output.is_absolute()
            && parent.canonicalize()? == parent
            && fs::symlink_metadata(parent)?.uid() == 0
            && fs::symlink_metadata(parent)?.mode() & 0o077 == 0,
        "output parent must be root-private"
    );
    let manifest = pin(MANIFEST251)?;
    sealed(&manifest)?;
    let m: Value = serde_json::from_slice(&fs::read(MANIFEST251.0)?)?;
    validate_scope(&m)?;
    // The old epoch-250 final-root download is exactly epoch-251's bootstrap.
    // Verify its original generation/CRC/MD5 receipt, then hash the reused copy.
    let restore_pin = pin(FINAL_RECEIPT)?;
    let restored: Value = serde_json::from_slice(&fs::read(FINAL_RECEIPT.0)?)?;
    restore(
        &restored,
        &m["manifest"]["epochs"][0]["bootstrap"],
        FINAL.0,
        BOOTSTRAP251.1,
    )?;
    let input_seal = pin((
        &format!("{INPUT}/deployment-seal-receipt.json"),
        "1478564db113a40f8870c54f3c9b0c2cc91abd3943e34b823018994f40cafd7c",
    ))?;
    let native = pin(NATIVE)?;
    let source = pin(SOURCE)?;
    let n: Value = serde_json::from_slice(&fs::read(NATIVE.0)?)?;
    let s: Value = serde_json::from_slice(&fs::read(SOURCE.0)?)?;
    ensure!(
        n["one_exact_test_passed"] == true
            && n["manager_success"] == true
            && n["guard_trips"] == 0
            && n["test_invocation_id"] == "df8a786b87fa44fb9f167330af255f67"
            && s["production_source_revision"] == "e3f15eb22a6da570eb142853eabc8b91871cb99f"
            && s["production_worker_sha256"] == WORKER.1,
        "native source qualification differs"
    );
    eprintln!("epoch 251: hashing sealed bootstrap and exact deployed binaries");
    let bootstrap = pin(BOOTSTRAP251)?;
    let genesis = pin((&format!("{INPUT}/genesis.tar.bz2"), GENESIS.1))?;
    let node = pin(if published_node { PUBLISHED_NODE } else { NODE })?;
    let node_build = if published_node {
        Some(captured_node_evidence()?)
    } else {
        None
    };
    let worker = pin(WORKER)?;
    for v in [&bootstrap, &genesis, &node, &worker, &input_seal] {
        sealed(v)?;
    }
    ensure!(
        bootstrap["identity"]["size"] == m["manifest"]["epochs"][0]["bootstrap"]["size"],
        "bootstrap size mismatch"
    );
    let mut receipt = json!({"schema":"horizon251-exact-input-custody-v1","epoch":251,"manifest":manifest,"bootstrap":bootstrap,"genesis":genesis,"node":node,"worker":worker,"input_seal":input_seal,"original_restore_receipt":restore_pin,"native_test_terminal":native,"native_test_source":source,"canonical_checkpoint":m["manifest"]["epochs"][0]["post_bootstrap_root_checkpoints"][0],"final_root_snapshot_copy_required":false,"accepted_input_custody":true,"recorded_unix_seconds":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),"replay_launch_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false});
    if let Some(evidence) = node_build {
        receipt["schema"] = json!("horizon251-captured-node-input-custody-v2");
        receipt["node_build_evidence"] = evidence;
    }
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .open(output)?;
    serde_json::to_writer_pretty(&mut f, &receipt)?;
    f.write_all(b"\n")?;
    f.sync_all()?;
    File::open(parent)?.sync_all()?;
    println!("{}", output.display());
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn captured_node_rejects_mismatched_source_build_and_features() {
        let source = json!({"source_commit":"eabd0b6a78464130d1e30eff30bb75267502abde","no_tracked_diffs":true});
        let build = json!({"all_source_members_revalidated_at_natural_closure":true,
            "actual_terminal":{"Result":"success","ExecMainStatus":"0"},
            "clean_full_source_manifest":{"sha256":NODE_SOURCE.1},
            "artifacts":[{"target":"jetstreamer-node","binary":{"sha256":PUBLISHED_NODE.1},"actual_features":"[]"}]});
        validate_node_build(&source, &build).unwrap();
        for pointer in ["/no_tracked_diffs", "/source_commit"] {
            let mut bad = source.clone();
            *bad.pointer_mut(pointer).unwrap() = Value::Null;
            assert!(validate_node_build(&bad, &build).is_err());
        }
        for pointer in [
            "/all_source_members_revalidated_at_natural_closure",
            "/actual_terminal/Result",
            "/actual_terminal/ExecMainStatus",
            "/clean_full_source_manifest/sha256",
            "/artifacts/0/binary/sha256",
            "/artifacts/0/actual_features",
        ] {
            let mut bad = build.clone();
            *bad.pointer_mut(pointer).unwrap() = Value::Null;
            assert!(validate_node_build(&source, &bad).is_err());
        }
        let mut duplicate = build.clone();
        duplicate["artifacts"]
            .as_array_mut()
            .unwrap()
            .push(build["artifacts"][0].clone());
        assert!(validate_node_build(&source, &duplicate).is_err());
    }
    #[test]
    fn sealed_input_rejects_writable_or_foreign_ownership() {
        let good = json!({"identity":{"uid":0,"gid":0,"mode":0o100444}});
        sealed(&good).unwrap();
        for (k, v) in [("uid", 1000), ("gid", 1000), ("mode", 0o100644)] {
            let mut wrong = good.clone();
            wrong["identity"][k] = json!(v);
            assert!(sealed(&wrong).is_err());
        }
    }
    #[test]
    fn scope_rejects_wrong_checkpoint_or_epoch() {
        let mut m = json!({"manifest_fingerprint":"sha256:e214b640c55cc6ec0e431c66f9cbd0076c4620578c2dea1e6c2324e7f616789e","manifest":{"first_epoch":251,"last_epoch":251,"publication_boundary_epoch":251,"epochs":[{"epoch":251,"runtime":"solana-v1.7.15","bootstrap":{"slot":108431365,"generation":1638079985418599u64,"accounts_hash":"C5eqGwzDFEDfeBovidro6WnY3Drw7caJ2p2mjnJbGJVE"},"verification_cohort":{"first_epoch":251,"last_epoch":251},"post_bootstrap_root_checkpoints":[{"slot":108863259,"accounts_hash":"7h1Ynk3rFxcF7GuUQ3vjxzSvXe8sykWqCkYYHLXFJ6nz","generation":1638317210911330u64}]}]}});
        validate_scope(&m).unwrap();
        m["manifest"]["epochs"][0]["post_bootstrap_root_checkpoints"][0]["slot"] = json!(108863258);
        assert!(validate_scope(&m).is_err());
        m["manifest"]["last_epoch"] = json!(252);
        assert!(validate_scope(&m).is_err());
    }
}
