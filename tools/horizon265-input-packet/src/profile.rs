use super::*;
pub(super) const SOURCE: &str = "1ae137f752f605463e52dad3055ab8cb161b64e2";
pub(super) const MANIFEST: (&str, &str) = (
    "/var/lib/jetstreamer/horizon265-singleton-manifest-20261119-v1/preflight-265-singleton.json",
    "a269b418dc5bcd508850d0293cf05e64875d7610c402b696cf8d15f9775c5fcf",
);
pub(super) const INCIDENT: (&str, &str) = (
    "/var/lib/jetstreamer/horizon-singleton265-format-capacity-failure-cycle621-v1/incident.json",
    "6852a9148a4c66cf793944e963120b2a636ad6f44ad34d33686ab4c1e54d1720",
);
pub(super) const BUILD: (&str, &str) = (
    "/var/lib/jetstreamer/horizon253255-node-index-20261118-v2/production-build-binding.json",
    "ea6b6b53fb3c025300b2044752b5d001c8868a14b520e0d78321595544253c7d",
);
pub(super) const WORKER_SOURCE: (&str, &str) = (
    "/var/lib/jetstreamer/horizon-supported235-shrink-debt-e3f15eb2-v1/worker-source-provenance.json",
    "6077eba1256607a4a163992d507bb33193b4ed7bad7a5a5a95bd8fb99c04467f",
);
pub(super) const CODEC: &[(&str, &str)] = &[
    (
        "jetstreamer-horizon/src/limits.rs",
        "92833dd26374a50121fc6c4cf28c4f300d3acb1490a363b4250be48a5720ee74",
    ),
    (
        "jetstreamer-horizon/src/message_instructions.rs",
        "dc8ce8068720f99ebc40be200eab9f2fa83bd6db1ac644460a2f68ca2f3e47bb",
    ),
    (
        "jetstreamer-horizon/src/convert.rs",
        "3b1ad76919749581733372b6cebaaa16518c27e2b1600ad1a03baa2e73afc39e",
    ),
];
pub(super) const ARTIFACTS: &[(&str, &str, u64)] = &[
    (
        "/var/lib/jetstreamer/horizon-contiguous-265-265-current-46b4b4a-v1/snapshot-114479281-Jo2p1i6wNNn71fwwkyoA6shEtYtovbqzVc6p2W16FzW.tar.zst",
        "04eb59e2dbbc2b0d4f1535741fa9d56794c32ad18e14c98df4fa76a5ae397641",
        16483458670,
    ),
    (
        "/var/lib/jetstreamer/horizon253255-node-index-20261118-v2/jetstreamer-node",
        "2789f8211dafc4230a084910867db99699e6470b4a08a6fd8cc6dc00bf080f32",
        49064824,
    ),
    (
        "/var/lib/jetstreamer/horizon-supported235-shrink-debt-e3f15eb2-v1/jetstreamer-historical-worker-v1-7-15",
        "c3b2c33420bcf6b6809d7f0b43309e7d57d2791a88e2d4074d21d4f636c521e4",
        6519904,
    ),
    (
        "/var/lib/jetstreamer/horizon-foundation-holding-probe-input-v1/genesis.tar.bz2",
        "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945",
        20144,
    ),
];
pub(super) const CID264: &str = "bafyreidjr3q2eqeytn3eyapobwzwrb6iw5tiu3ovsrc5akqblbysgzahgi";
pub(super) const CID265: &str = "bafyreibgf4smruua7seioyolngrziiqsgeae3d4zmcvptg7m4xwzyafqwu";
pub(super) const INDEXES: &[(u64, &str, &str, u64)] = &[
    (264, CID264, "slot-to-cid", 15875725),
    (265, CID265, "slot-to-cid", 15484110),
    (265, CID265, "cid-to-offset-and-size", 10904092766),
];
pub(super) fn validate_manifest(m: &Value) -> Result<()> {
    let v = &m["manifest"];
    ensure!(
        m["manifest_fingerprint"]
            == "sha256:a126bce31196effaf656230c7185e92f73db9574e13a45e3976aae1859461e28"
            && v["schema"] == "jetstreamer-gcs-snapshot-preflight-v4"
            && v["epoch_slots"] == 432000
            && v["first_epoch"] == 265
            && v["last_epoch"] == 265
            && v["publication_boundary_epoch"] == 265,
        "manifest range/fingerprint differs"
    );
    let epochs = v["epochs"].as_array().context("manifest epochs")?;
    ensure!(epochs.len() == 1, "not a singleton");
    let e = &epochs[0];
    ensure!(
        e["epoch"] == 265
            && e["runtime"] == "solana-v1.7.15"
            && e["verification_cohort"]["first_epoch"] == 265
            && e["verification_cohort"]["last_epoch"] == 265,
        "foreign runtime or cohort"
    );
    let b = &e["bootstrap"];
    ensure!(
        b["slot"] == 114479281
            && b["generation"] == 1641500477962489u64
            && b["accounts_hash"] == "Jo2p1i6wNNn71fwwkyoA6shEtYtovbqzVc6p2W16FzW"
            && b["size"] == ARTIFACTS[0].2
            && b["crc32c"] == "+0CPhA=="
            && b["md5_hash"] == "Q0FEYKFkXAJiwZNXZtq6rQ==",
        "bootstrap identity differs"
    );
    let roots = e["post_bootstrap_root_checkpoints"]
        .as_array()
        .context("canonical roots")?;
    ensure!(
        roots.len() == 1
            && roots[0]["slot"] == 114910768
            && roots[0]["generation"] == 1641767242524970u64
            && roots[0]["accounts_hash"] == "HnePfSpTtWaPDFx9RrPeuamDZREhoUXa7xpK6fbtPGyK",
        "canonical root differs"
    );
    Ok(())
}
pub(super) fn validate_incident(v: &Value) -> Result<()> {
    ensure!(
        v["schema"] == "horizon-epoch265-natural-format-capacity-failure-v1"
            && v["epoch"] == 265
            && v["owner_invocation_id"] == "9cbdde333dc64ce8ab3503b8aedeabe0"
            && v["natural_failure"] == true
            && v["failure"] == "message.instructions length 65 exceeds inline capacity 64"
            && v["failure_slot"] == 114480089
            && v["transaction_index"] == 1368
            && v["retry_unchanged_authorized"] == false,
        "original failure binding differs"
    );
    Ok(())
}
pub(super) fn validate_build(v: &Value) -> Result<()> {
    ensure!(
        v["schema"] == "horizon253255-production-node-build-binding-v1"
            && v["source_revision"] == SOURCE
            && v["build_result"] == "success"
            && v["node_sha256"] == ARTIFACTS[1].1
            && v["node_bytes"] == ARTIFACTS[1].2
            && v["features"] == "[\"default\"]"
            && v["rustflags"] == json!([])
            && v["publication_authorized"] == false
            && v["replay_launch_authorized"] == false,
        "candidate node build differs"
    );
    Ok(())
}
pub(super) fn validate_worker(v: &Value) -> Result<()> {
    ensure!(
        v["schema"] == "horizon-v1715-shrink-debt-artifact-source-provenance-v1"
            && v["source_revision"] == "e3f15eb22a6da570eb142853eabc8b91871cb99f"
            && v["no_poh_force_soft_feature"] == true
            && v["snapshot_replay_abi_or_lane_budget_qualified"] == false,
        "worker provenance differs"
    );
    let selected: Vec<_> = v["artifacts"]
        .as_array()
        .context("worker artifacts")?
        .iter()
        .filter(|v| v["kind"] == "production")
        .collect();
    ensure!(
        selected.len() == 1
            && selected[0]["sha256"] == ARTIFACTS[2].1
            && selected[0]["bytes"] == ARTIFACTS[2].2,
        "worker artifact differs"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn singleton_manifest_rejects_wrong_generation_root_or_boundary() {
        let good = json!({"manifest_fingerprint":"sha256:a126bce31196effaf656230c7185e92f73db9574e13a45e3976aae1859461e28","manifest":{"schema":"jetstreamer-gcs-snapshot-preflight-v4","epoch_slots":432000,"first_epoch":265,"last_epoch":265,"publication_boundary_epoch":265,"epochs":[{"epoch":265,"runtime":"solana-v1.7.15","verification_cohort":{"first_epoch":265,"last_epoch":265},"bootstrap":{"slot":114479281,"generation":1641500477962489u64,"accounts_hash":"Jo2p1i6wNNn71fwwkyoA6shEtYtovbqzVc6p2W16FzW","size":ARTIFACTS[0].2,"crc32c":"+0CPhA==","md5_hash":"Q0FEYKFkXAJiwZNXZtq6rQ=="},"post_bootstrap_root_checkpoints":[{"slot":114910768,"generation":1641767242524970u64,"accounts_hash":"HnePfSpTtWaPDFx9RrPeuamDZREhoUXa7xpK6fbtPGyK"}]}]}});
        validate_manifest(&good).unwrap();
        for pointer in [
            "/manifest/publication_boundary_epoch",
            "/manifest/last_epoch",
            "/manifest/epochs/0/bootstrap/generation",
            "/manifest/epochs/0/bootstrap/size",
            "/manifest/epochs/0/post_bootstrap_root_checkpoints/0/accounts_hash",
            "/manifest/epochs/0/post_bootstrap_root_checkpoints/0/slot",
        ] {
            let mut bad = good.clone();
            *bad.pointer_mut(pointer).unwrap() = Value::Null;
            assert!(validate_manifest(&bad).is_err(), "{pointer}");
        }
    }
    #[test]
    fn original_failure_cannot_be_laundered_into_unchanged_retry() {
        let good = json!({"schema":"horizon-epoch265-natural-format-capacity-failure-v1","epoch":265,"owner_invocation_id":"9cbdde333dc64ce8ab3503b8aedeabe0","natural_failure":true,"failure":"message.instructions length 65 exceeds inline capacity 64","failure_slot":114480089,"transaction_index":1368,"retry_unchanged_authorized":false});
        validate_incident(&good).unwrap();
        for k in [
            "schema",
            "epoch",
            "owner_invocation_id",
            "natural_failure",
            "failure",
            "failure_slot",
            "transaction_index",
            "retry_unchanged_authorized",
        ] {
            let mut bad = good.clone();
            bad[k] = Value::Null;
            assert!(validate_incident(&bad).is_err(), "{k}");
        }
        assert_eq!(no_authority()["native_runtime_qualified"], false);
        assert_eq!(no_authority()["codec_tests_executed"], false);
    }
    #[test]
    fn candidate_build_requires_exact_node_source_and_features() {
        let good = json!({"schema":"horizon253255-production-node-build-binding-v1","source_revision":SOURCE,"build_result":"success","node_sha256":ARTIFACTS[1].1,"node_bytes":ARTIFACTS[1].2,"features":"[\"default\"]","rustflags":[],"publication_authorized":false,"replay_launch_authorized":false});
        validate_build(&good).unwrap();
        for k in [
            "source_revision",
            "build_result",
            "node_sha256",
            "node_bytes",
            "features",
            "rustflags",
            "publication_authorized",
            "replay_launch_authorized",
        ] {
            let mut bad = good.clone();
            bad[k] = Value::Null;
            assert!(validate_build(&bad).is_err(), "{k}");
        }
    }
    #[test]
    fn old_worker_is_not_the_selected_capped_worker() {
        let mut v = json!({"schema":"horizon-v1715-shrink-debt-artifact-source-provenance-v1","source_revision":"e3f15eb22a6da570eb142853eabc8b91871cb99f","no_poh_force_soft_feature":true,"snapshot_replay_abi_or_lane_budget_qualified":false,"artifacts":[{"kind":"production","sha256":ARTIFACTS[2].1,"bytes":ARTIFACTS[2].2}]});
        validate_worker(&v).unwrap();
        v["artifacts"][0]["sha256"] = json!("88581898");
        assert!(validate_worker(&v).is_err());
    }
}
