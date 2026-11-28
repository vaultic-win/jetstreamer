use super::{Evidence, MAX_JSON_BYTES, Plan, file_sha256, read_secure};
use anyhow::{Result, ensure};
use serde_json::Value;
use std::{fs, os::unix::fs::MetadataExt, path::Path};

pub const OUTCOME_SCHEMA: &str = "jetstreamer-private-epoch223-v1620-warmup-resource-v1";
const ROOT: &str =
    "/home/ubuntu/.jetstreamer-private/qualification-223-v1620-prefix-warmup-d15ee08b-v1";
const UNIT: &str = "horizon-qualify-223-v1620-warmup-resource-d15ee08b-v1.service";
const INVOCATION: &str = "13a5f755a196442e991c6930b410c04f";
const GUARD: &str = "horizon-warmup223-native20-protective-v1.service";
const TIMER: &str = "horizon-warmup223-native20-protective-v1.timer";
const SOURCE: &str =
    "/var/lib/jetstreamer/horizon-223-v1620-warmup-envelope480-v1/actual-plan.json";
const SOURCE_SHA: &str = "f9d5dccfc3c5587ddefb8fba758133d53ce7b66cf46a83f2839e52f814d56a7b";
const FAILURE: &str =
    "/var/lib/jetstreamer/horizon-warmup223-native20-terminal-13a5-v1/failure.json";
const FAILURE_SHA: &str = "188f4cf1254dabd65fc9de625767ac073c77f14fe9cdc1962d19e93a9c784419";
const SNAPSHOT_SHA: &str = "301110cad7eb56ed68c99d31cf6769b7622e2c166f33aec084dc51592d0cd665";
const NODE_SHA: &str = "99f643ff0dbbcd37d1fbc524a1c1088d7273c7fc91330df059d30d51b8b0fcd4";
const WORKER_SHA: &str = "52d6c86a8103b8965ca68ead96af471a7899a0a0e6e69c48989b39fd5d922f0c";
const SUCCESSOR: &str =
    "/var/lib/jetstreamer/horizon-warmup223-native20-terminal-58ab-v2/resource.json";
const SUCCESSOR_IID: &str = "58ab3d9221a6452685b8eab3ceabdb49";
const LOCAL_EVIDENCE: [(&str, &str); 3] = [
    ("failure.json", FAILURE_SHA),
    (
        "target-capture.json",
        "8af72f20b8e3f9ddbfd7cf1bfdc5bdd0ed4b2d0d41ed67676db091e845b6732d",
    ),
    (
        "target-stop.json",
        "ec9221e27fc84720a28ff358d7bce9ac9e3847030e5cf908343c0d0f098c1876",
    ),
];
const SEALED_EVIDENCE: [(&str, &str); 4] = [
    (SOURCE, SOURCE_SHA),
    (
        "/var/lib/jetstreamer/horizon-warmup223-native20-terminal-13a5-v1/proof.json",
        "15f180fb61563ce762a99924a53a957e12857e90dbd64500d80bf2c64072590e",
    ),
    (
        "/var/lib/jetstreamer/horizon-warmup223-native20-terminal-58ab-v2/proof.json",
        "6790592b9188e7c4a3d32171a326b743f84fc6c5b5ad07f94182c104876b7028",
    ),
    (
        SUCCESSOR,
        "4040a077d90eca93e0208485a86131b1541564527acc4ab9de746292e32504d3",
    ),
];

pub(super) fn evidence_uid(path: &Path) -> u32 {
    if path.starts_with(Path::new(ROOT).join("receipts")) {
        1000
    } else {
        0
    }
}

fn evidence_is_bound(evidence: &[Evidence], path: &Path, sha: &str) -> bool {
    evidence
        .iter()
        .any(|entry| entry.path == path && entry.sha256 == sha)
}

pub(super) fn validate_profile(plan: &Plan) -> Result<()> {
    ensure!(
        !plan.restore_only_probe
            && !plan.warmup223_v2
            && !plan.warmup223_v3
            && plan.run_root == Path::new(ROOT)
            && plan.producer.unit == UNIT
            && plan.producer.invocation_id == INVOCATION
            && plan.guard.unit == GUARD
            && plan.inactive_units == [TIMER]
            && plan.outcome.path == Path::new(FAILURE)
            && plan.outcome.sha256 == FAILURE_SHA,
        "native 20 cleanup must bind the exact failed warmup"
    );
    for (name, sha) in LOCAL_EVIDENCE {
        ensure!(
            evidence_is_bound(
                &plan.evidence,
                &plan.run_root.join("receipts").join(name),
                sha
            ),
            "missing original native 20 capture evidence {name}"
        );
    }
    for (path, sha) in SEALED_EVIDENCE {
        ensure!(
            evidence_is_bound(&plan.evidence, Path::new(path), sha),
            "missing sealed native 20 evidence {path}"
        );
    }
    Ok(())
}

pub(super) fn validate_retained_evidence(plan: &Plan, failure: &Value) -> Result<()> {
    ensure!(
        failure["invocation_id"] == INVOCATION
            && failure["unit"] == UNIT
            && failure["success"] == false
            && failure["target_reached"] == true
            && failure["child_return_code"] == 130
            && failure["observed_slot"] == 96_335_554
            && failure["capture"].is_object()
            && failure["plan"]["path"] == SOURCE
            && failure["plan"]["sha256"] == SOURCE_SHA
            && failure["authority"]["ordinary_replay_authorized"] == false
            && failure["authority"]["publication_authorized"] == false
            && failure["authority"]["r2_mutations"] == false,
        "native 20 outcome is not the failed target-capture invocation"
    );
    let successor: Value =
        serde_json::from_slice(&read_secure(Path::new(SUCCESSOR), MAX_JSON_BYTES, 0)?)?;
    ensure!(
        successor["invocation_id"] == SUCCESSOR_IID
            && successor["success"] == true
            && successor["target_reached"] == true
            && successor["observed_slot"] == 96_335_554
            && successor["snapshot_sha256"] == SNAPSHOT_SHA
            && successor["node_sha256"] == NODE_SHA
            && successor["worker_sha256"] == WORKER_SHA,
        "the replacement warmup did not reproduce the captured target"
    );
    let output = plan.run_root.join("output");
    let mut names = fs::read_dir(&output)?;
    let archive = names.next().transpose()?.map(|entry| entry.path());
    ensure!(
        archive.as_deref() == Some(output.join("epoch-223.jet").as_path())
            && names.next().is_none(),
        "failed native 20 output layout changed"
    );
    let archive = fs::symlink_metadata(output.join("epoch-223.jet"))?;
    ensure!(
        archive.is_file() && archive.len() == 0 && archive.nlink() == 1 && archive.ino() == 2759759,
        "failed native 20 output is no longer the empty original"
    );
    for (path, sha) in [
        (
            "/var/lib/jetstreamer/horizon-223-known-root-prefix-b1670f57-v1/snapshot-96335538-Gavt9cmcj5BFXuZnz44JktRGbM9oxRkJqoWRF8PvMBTE.tar.zst",
            SNAPSHOT_SHA,
        ),
        (
            "/var/lib/jetstreamer/horizon-223-v1620-cooperative-parent-80202938-v1/jetstreamer-historical-worker-v1-6-20",
            WORKER_SHA,
        ),
        (
            "/var/lib/jetstreamer/horizon-223-v1620-cooperative-parent-80202938-v1/jetstreamer-node",
            NODE_SHA,
        ),
        (
            "/var/lib/jetstreamer/horizon-223-v1620-cooperative-parent-80202938-v1/epoch-hashes-223-prefix.txt",
            "9ce886d556f70e84386dbf1b2c4abc4b4fb7ea57064b903e50ff6b34479a0c15",
        ),
        (
            "/var/lib/jetstreamer/horizon-223-known-root-prefix-b1670f57-v1/genesis.tar.bz2",
            "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945",
        ),
    ] {
        let path = Path::new(path);
        let m = fs::symlink_metadata(path)?;
        ensure!(
            m.is_file() && m.uid() == 0 && m.mode() & 0o222 == 0 && file_sha256(path)? == sha,
            "retained native 20 input differs: {}",
            path.display()
        );
    }
    Ok(())
}
