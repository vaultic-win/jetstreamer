//! Preserve the original twelve-inode allocation proof and the absolute guard floor after a cold restart.
use super::*;
use crate::Plan;

const RUNTIME: &str = "/var/lib/jetstreamer/horizon_runtime_data";
#[cfg(feature = "epoch170-384")]
const IMAGE: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch170-retry10-guard384-20261121-v1/tools/guard";
#[cfg(not(any(
    feature = "epoch170-384",
    feature = "epoch167-cold-v3",
    feature = "epoch166-retry11",
    feature = "epoch168-cold-v2",
    feature = "epoch168-cold-v3",
    feature = "epoch168-cold-v4",
    feature = "epoch168-cold-v5",
    feature = "epoch170-retry11",
    feature = "epoch170-retry12",
    feature = "epoch170-retry13",
    feature = "epoch170-full-metered",
    feature = "epoch166-write-version-reproduction"
)))]
const IMAGE: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/incident-replay-guard-20261121-v1/tools/guard";
#[cfg(feature = "epoch167-cold-v3")]
const IMAGE: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch167-cold-guard-20261122-v3/tools/guard";
#[cfg(feature = "epoch168-cold-v2")]
const IMAGE: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch168-cold-guard-20261122-v2/tools/guard";
#[cfg(feature = "epoch168-cold-v3")]
const IMAGE: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch168-cold-guard-20261123-v3/tools/guard";
#[cfg(feature = "epoch168-cold-v4")]
const IMAGE: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch168-cold-guard-20261123-v4/tools/guard";
#[cfg(feature = "epoch166-write-version-reproduction")]
const IMAGE: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch166-write-version-reproduction-guard-20261124-v1/tools/guard";
#[cfg(feature = "epoch166-write-version-reproduction")]
const REPRODUCTION_RUN: &str =
    "epoch166-independent-cold-20261120-v1/bounded-write-version-20261124-v1";
#[cfg(feature = "epoch168-cold-v5")]
const IMAGE: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch168-cold-guard-20261125-v5/tools/guard";
#[cfg(feature = "epoch168-cold-v5")]
const RETRY5_RUN: &str =
    "epoch168-standard-lane-20261109-v1/full-metered-20261121-v1/cold-retry5-20261125";
#[cfg(feature = "epoch166-retry11")]
const IMAGE: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch166-retry11-guard-20261122-v1/tools/guard";
#[cfg(feature = "epoch170-retry11")]
const IMAGE: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch170-retry11-guard-20261122-v1/tools/guard";
#[cfg(feature = "epoch170-retry12")]
const IMAGE: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch170-retry12-guard-20261122-v1/tools/guard";
#[cfg(feature = "epoch170-retry13")]
const IMAGE: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch170-retry13-guard-20261122-v1/tools/guard";
#[cfg(feature = "epoch170-full-metered")]
const IMAGE: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch170-full-metered-guard-20261124-v1/tools/guard";
#[cfg(feature = "epoch170-full-metered")]
const METERED_RUN: &str = "epoch170-standard-lane-20261109-v1/replacement-local3retry7-20261110-v1/replacement-local3retry10-20261121-v1/full-metered-20261124-v1";
const HOME: &str = "/home/sol/.jetstreamer-private";
const MIN_FLOOR: u64 = 8_297_502_499_408;

struct Lane {
    unit: &'static str,
    tree: &'static str,
    runtime: &'static str,
    cap: u64,
}

#[cfg(feature = "epoch167-cold-v3")]
const LANES: &[Lane] = &[Lane {
    unit: "horizon-qualify-167-source-index-v3-20261122.service",
    tree: "epoch167-standard-lane-20261109-v1",
    runtime: "epoch167-source-index-rebook-20261122-v3",
    cap: 512 << 30,
}];
#[cfg(feature = "epoch168-cold-v2")]
const LANES: &[Lane] = &[Lane {
    unit: "horizon-qualify-168-full-metered-cold-v2-20261122.service",
    tree: "epoch168-standard-lane-20261109-v1",
    runtime: "epoch168-retry2-rebook-20261122-v1",
    cap: 288 << 30,
}];
#[cfg(feature = "epoch168-cold-v3")]
const LANES: &[Lane] = &[Lane {
    unit: "horizon-qualify-168-full-metered-cold-v3-20261123.service",
    tree: "epoch168-standard-lane-20261109-v1",
    runtime: "epoch168-retry3-rebook-20261123-v1",
    cap: 288 << 30,
}];
#[cfg(feature = "epoch168-cold-v4")]
const LANES: &[Lane] = &[Lane {
    unit: "horizon-qualify-168-full-metered-cold-v4-20261123.service",
    tree: "epoch168-standard-lane-20261109-v1",
    runtime: "epoch168-retry4-rebook-20261123-v1",
    cap: 288 << 30,
}];
#[cfg(feature = "epoch166-write-version-reproduction")]
const LANES: &[Lane] = &[Lane {
    unit: "horizon-qualify-166-write-version-reproduction-20261124-v1.service",
    tree: "epoch166-independent-cold-20261120-v1",
    runtime: "epoch166-write-version-gap-20261124-v1",
    cap: 288 << 30,
}];
#[cfg(feature = "epoch168-cold-v5")]
const LANES: &[Lane] = &[Lane {
    unit: "horizon-qualify-168-full-metered-cold-v5-20261125.service",
    tree: "epoch168-standard-lane-20261109-v1",
    runtime: "epoch168-retry5-rebook-20261125-v1",
    cap: 512 << 30,
}];
#[cfg(feature = "epoch166-retry11")]
const LANES: &[Lane] = &[Lane {
    unit: "horizon-qualify-166-independent-retry11-20261122.service",
    tree: "epoch166-independent-cold-20261120-v1",
    runtime: "epoch166-retry11-rebook-20261122-v1",
    cap: 288 << 30,
}];
#[cfg(feature = "epoch170-retry11")]
const LANES: &[Lane] = &[Lane {
    unit: "horizon-qualify-170-replacement-local3retry11-20261122.service",
    tree: "epoch170-standard-lane-20261109-v1",
    runtime: "epoch170-retry11-rebook-20261122-v1",
    cap: 384 << 30,
}];
#[cfg(feature = "epoch170-retry12")]
const LANES: &[Lane] = &[Lane {
    unit: "horizon-qualify-170-replacement-local3retry12-20261122.service",
    tree: "epoch170-standard-lane-20261109-v1",
    runtime: "epoch170-retry12-rebook-20261122-v1",
    cap: 384 << 30,
}];
#[cfg(feature = "epoch170-retry13")]
const LANES: &[Lane] = &[Lane {
    unit: "horizon-qualify-170-replacement-local3retry13-20261122.service",
    tree: "epoch170-standard-lane-20261109-v1",
    runtime: "epoch170-retry13-rebook-20261122-v1",
    cap: 384 << 30,
}];
#[cfg(feature = "epoch170-full-metered")]
const LANES: &[Lane] = &[Lane {
    unit: "horizon-qualify-170-full-metered-20261124-v1.service",
    tree: "epoch170-standard-lane-20261109-v1",
    runtime: "epoch170-full-metered-rebook-20261124-v1",
    cap: 384 << 30,
}];
#[cfg(feature = "epoch170-384")]
const LANES: &[Lane] = &[Lane {
    unit: "horizon-qualify-170-replacement-local3retry10-20261121-v1.service",
    tree: "epoch170-standard-lane-20261109-v1",
    runtime: "epoch170-retry10-recovery-20261121-v1",
    cap: 384 << 30,
}];
#[cfg(not(any(
    feature = "epoch170-384",
    feature = "epoch167-cold-v3",
    feature = "epoch166-retry11",
    feature = "epoch168-cold-v2",
    feature = "epoch168-cold-v3",
    feature = "epoch168-cold-v4",
    feature = "epoch168-cold-v5",
    feature = "epoch170-retry11",
    feature = "epoch170-retry12",
    feature = "epoch170-retry13",
    feature = "epoch170-full-metered",
    feature = "epoch166-write-version-reproduction"
)))]
const LANES: &[Lane] = &[
    Lane {
        unit: "horizon-qualify-166-independent-recovery-20261121-v1.service",
        tree: "epoch166-independent-cold-20261120-v1",
        runtime: "epoch166-independent-cold-recovery-20261121-v1",
        cap: CAP,
    },
    Lane {
        unit: "horizon-qualify-167-source-index-v1-20261121.service",
        tree: "epoch167-standard-lane-20261109-v1",
        runtime: "epoch167-source-index-recovery-20261121-v1",
        cap: 512 << 30,
    },
    Lane {
        unit: "horizon-qualify-170-replacement-local3retry10-20261121-v1.service",
        tree: "epoch170-standard-lane-20261109-v1",
        runtime: "epoch170-retry10-recovery-20261121-v1",
        cap: CAP,
    },
];

pub(crate) fn is_route(unit: &str) -> bool {
    LANES.iter().any(|r| r.unit == unit)
}

pub(crate) fn validate(p: &Plan) -> Result<()> {
    let lane = LANES
        .iter()
        .find(|r| r.unit == p.unit)
        .context("unknown recovery guard unit")?;
    ensure!(
        p.worker_root == Path::new(HOME).join(lane.tree)
            && p.receipt_directory == Path::new(RUNTIME).join(lane.runtime).join("guard-receipts")
            && p.filesystem == Path::new("/home/sol")
            && p.minimum_free_bytes >= MIN_FLOOR
            && p.maximum_root_physical_bytes == Some(lane.cap)
            && p.maximum_worker_vmas == 3_500_000
            && p.data_fulfillment.is_some()
            && p.bounded_canary.is_none()
            && p.bounded_measurement.is_none()
            && p.native_main.is_none(),
        "recovery unit, tree, physical cap, floor, receipt path or DATA proof differs"
    );
    Ok(())
}

#[cfg(any(
    feature = "epoch167-cold-v3",
    feature = "epoch166-retry11",
    feature = "epoch168-cold-v2",
    feature = "epoch168-cold-v3",
    feature = "epoch168-cold-v4",
    feature = "epoch168-cold-v5",
    feature = "epoch170-retry11",
    feature = "epoch170-retry12",
    feature = "epoch170-retry13",
    feature = "epoch170-full-metered",
    feature = "epoch166-write-version-reproduction"
))]
pub(crate) fn validate_cold_contract(plan: &Plan, image_sha256: &str) -> Result<()> {
    let deployment = Path::new(IMAGE)
        .parent()
        .and_then(Path::parent)
        .context("invalid guard deployment path")?;
    let proof = plan
        .data_fulfillment
        .as_ref()
        .context("missing cold replay DATA proof")?;
    let binding: Binding = serde_json::from_value(proof.clone())?;
    ensure!(
        binding.contract.path == deployment.join("contract/contract.json"),
        "expected the cold replay sealed contract"
    );
    let contract: Contract = serde_json::from_value(sealed(
        &binding.contract,
        &binding.deployment_seal,
        "contract.json",
    )?)?;
    ensure!(
        contract.qualified_native_witness.path == deployment.join("NATIVE_WITNESS.json"),
        "expected the cold replay native witness"
    );
    let witness = bound(&contract.qualified_native_witness)?;
    ensure!(
        witness["native_identity"]["executable"] == IMAGE
            && witness["native_identity"]["executable_sha256"] == image_sha256,
        "cold replay witness belongs to another guard"
    );
    Ok(())
}

// Check the hash-bound original namespace receipts and reopen the directories from / without symlinks.
// Once replay is running the sizes and times of these private output directories legitimately change.
pub(crate) fn qualification_roots(image: &Path) -> Result<Value> {
    ensure!(image == Path::new(IMAGE), "use the sealed incident guard");
    let receipts = [
        #[cfg(feature = "epoch166-write-version-reproduction")]
        (
            "epoch166-write-version-gap-20261124-v1/SUCCESSOR_ROOT.json",
            "6330ad3f82a308d4d616c7ddcf610faad5a97b4accfc0254013532ec821bdd15",
        ),
        #[cfg(feature = "epoch166-write-version-reproduction")]
        (
            "epoch166-write-version-gap-20261124-v1/sealed/deployment-seal-receipt.json",
            "003af2196b0eba330a05ed78dafe3508c598bcc1566caf9528c6818ff076df50",
        ),
        #[cfg(feature = "epoch166-write-version-reproduction")]
        (
            "epoch166-retry11-rebook-20261122-v1/WRITE_VERSION_TERMINAL_20261124.json",
            "d14e5b66958981056b8606e6354f08615c801ed9c1c5414747723c225d2c9bc0",
        ),
        #[cfg(feature = "epoch170-retry11")]
        (
            "epoch170-retry11-rebook-20261122-v1/SUCCESSOR_ROOT.json",
            "8420a1b00afa2d643a24e36c5b12c82fdd0b43d5238c9045c0c0c53097021728",
        ),
        #[cfg(feature = "epoch170-retry12")]
        (
            "epoch170-retry12-rebook-20261122-v1/SUCCESSOR_ROOT.json",
            "466f48f20716b258189e242eef4d4e2e54fbf6202e6ecd4ff008eb3dd0d10b19",
        ),
        #[cfg(any(feature = "epoch170-retry13", feature = "epoch170-full-metered"))]
        (
            "epoch170-retry13-rebook-20261122-v1/SUCCESSOR_ROOT.json",
            "654e6612f8ce9ee2f9f5c9f172f79f9ce5da4b0f6f02443c856f3a5228a5ca69",
        ),
        #[cfg(feature = "epoch168-cold-v2")]
        (
            "epoch168-retry2-rebook-20261122-v1/SUCCESSOR_ROOT.json",
            "ec909d6701ce7dcbee72da319bf0179ba375e1cf6e284aa29686e1dd0a3cbecc",
        ),
        #[cfg(feature = "epoch168-cold-v3")]
        (
            "epoch168-retry3-rebook-20261123-v1/SUCCESSOR_ROOT.json",
            "a3042cdfc0bbe51408f032a1ee33e2f33d635060f77e4db260f10c18224c86d4",
        ),
        #[cfg(any(feature = "epoch168-cold-v4", feature = "epoch168-cold-v5"))]
        (
            "epoch168-retry4-rebook-20261123-v1/SUCCESSOR_ROOT.json",
            "713e94750dd3d430c2f54c1ccb2af7ed708dec802af5cbf210ee4963a992d0f4",
        ),
        #[cfg(any(
            feature = "epoch166-retry11",
            feature = "epoch166-write-version-reproduction"
        ))]
        (
            "epoch166-independent-closed-accounts-20261122-v1/SUCCESSOR_ROOT.json",
            "02ca91b396f6bc9327b626eb80583af4ce004d63fb6854c7a5e2c50f38c12329",
        ),
        (
            "epoch166-independent-cold-recovery-20261121-v1/ROOTS_BEFORE_WITNESS.json",
            "cc7d780afe3d0180de6785cdad4f1e38e70feb82df1c95d21ab342c5974782e2",
        ),
        (
            "epoch168-full-metered-20261121-v1/STABLE_167_168_ROOTS_BEFORE_DATA_WITNESS.json",
            "57d99faeaed6817dc1afc29dec368039ae4cb4f1cbad28df2075b894d397321d",
        ),
        (
            "epoch170-ancestor-accounts-20261121-v1/RETRY10_ROOT_PRECREATED.json",
            "dfde6272e53a73ab669a56fe273a72c183c1871be5406b951c22452349bdf7a0",
        ),
    ];
    let mut refs = Vec::new();
    for (name, sha) in receipts {
        let r = Bound {
            path: Path::new(RUNTIME).join(name),
            sha256: sha.to_owned(),
        };
        bound(&r)?;
        refs.push(r);
    }
    #[cfg(feature = "epoch166-write-version-reproduction")]
    {
        let root = Path::new(HOME).join(REPRODUCTION_RUN);
        let mut dir = root_directory()?;
        for part in safe_components(&root)? {
            dir = openat(&dir, part, true)?;
        }
        let m = dir.metadata()?;
        ensure!(
            (m.dev(), m.ino(), m.uid(), m.gid(), m.mode() & 0o7777)
                == (64512, 93797556, 0, 0, 0o755),
            "epoch 166 reproduction directory changed"
        );
    }
    for (rel, ino) in [
        #[cfg(feature = "epoch170-retry11")]
        (
            "epoch170-standard-lane-20261109-v1/replacement-local3retry7-20261110-v1/replacement-local3retry10-20261121-v1/cold-retry11-20261122",
            113704962,
        ),
        #[cfg(feature = "epoch170-retry12")]
        (
            "epoch170-standard-lane-20261109-v1/replacement-local3retry7-20261110-v1/replacement-local3retry10-20261121-v1/cold-retry12-20261122",
            113836033,
        ),
        #[cfg(any(feature = "epoch170-retry13", feature = "epoch170-full-metered"))]
        (
            "epoch170-standard-lane-20261109-v1/replacement-local3retry7-20261110-v1/replacement-local3retry10-20261121-v1/cold-retry13-20261122",
            113981945,
        ),
        #[cfg(feature = "epoch168-cold-v2")]
        (
            "epoch168-standard-lane-20261109-v1/full-metered-20261121-v1/cold-retry2-20261122",
            103481350,
        ),
        #[cfg(feature = "epoch168-cold-v3")]
        (
            "epoch168-standard-lane-20261109-v1/full-metered-20261121-v1/cold-retry3-20261123",
            103481378,
        ),
        #[cfg(any(feature = "epoch168-cold-v4", feature = "epoch168-cold-v5"))]
        (
            "epoch168-standard-lane-20261109-v1/full-metered-20261121-v1/cold-retry4-20261123",
            103481722,
        ),
        #[cfg(any(
            feature = "epoch166-retry11",
            feature = "epoch166-write-version-reproduction"
        ))]
        (
            "epoch166-independent-cold-20261120-v1/replacement-local3retry10-20261121-v1/cold-retry11-20261122",
            93782068,
        ),
        #[cfg(feature = "epoch167-cold-v3")]
        (
            "epoch167-standard-lane-20261109-v1/replacement-source-index-v1-20261121/cold-source-index-v3-20261122",
            114491410,
        ),
        (
            "epoch166-independent-cold-20261120-v1/replacement-local3retry10-20261121-v1",
            93782017,
        ),
        (
            "epoch167-standard-lane-20261109-v1/replacement-source-index-v1-20261121",
            107675649,
        ),
        (
            "epoch167-standard-lane-20261109-v1/replacement-source-index-rollback-v1-20261121",
            107675650,
        ),
        (
            "epoch168-standard-lane-20261109-v1/full-metered-20261121-v1",
            103350354,
        ),
        (
            "epoch170-standard-lane-20261109-v1/replacement-local3retry7-20261110-v1/replacement-local3retry10-20261121-v1",
            113710084,
        ),
    ] {
        let path = Path::new(HOME).join(rel);
        let mut dir = root_directory()?;
        for part in safe_components(&path)? {
            dir = openat(&dir, part, true)?;
        }
        let m = dir.metadata()?;
        ensure!(
            m.dev() == 64512
                && m.ino() == ino
                && m.uid() == 1001
                && m.gid() == 1003
                && m.mode() & 0o7777 == 0o700,
            "precreated successor root changed: {rel}"
        );
    }
    #[cfg(feature = "epoch170-full-metered")]
    {
        let path = Path::new(RUNTIME)
            .join(LANES[0].runtime)
            .join("SUCCESSOR_ROOT.json");
        let bytes = crate::read_private(&path)?;
        let evidence: Value = serde_json::from_slice(&bytes)?;
        let root = Path::new(HOME).join(METERED_RUN);
        let mut dir = root_directory()?;
        for part in safe_components(&root)? {
            dir = openat(&dir, part, true)?;
        }
        let meta = dir.metadata()?;
        ensure!(
            evidence["schema"] == "horizon-epoch170-metered-successor-root-v1"
                && evidence["root"] == json!(root)
                && evidence["device"] == meta.dev()
                && evidence["inode"] == meta.ino()
                && evidence["retained_retry13_terminal_sha256"]
                    == "16664fda43d296d115858ff67a173d6d0cccb5f2ac90d446aa797da34a2f6c9d"
                && meta.dev() == 64512
                && meta.uid() == 1001
                && meta.gid() == 1003
                && meta.mode() & 0o7777 == 0o700,
            "metered epoch 170 successor directory changed"
        );
        let reference = Bound {
            path,
            sha256: crate::sha(&bytes),
        };
        bound(&reference)?;
        refs.push(reference);
    }
    #[cfg(feature = "epoch168-cold-v5")]
    {
        let path = Path::new(RUNTIME)
            .join(LANES[0].runtime)
            .join("SUCCESSOR_ROOT.json");
        let bytes = crate::read_private(&path)?;
        let evidence: Value = serde_json::from_slice(&bytes)?;
        let root = Path::new(HOME).join(RETRY5_RUN);
        let mut dir = root_directory()?;
        for part in safe_components(&root)? {
            dir = openat(&dir, part, true)?;
        }
        let meta = dir.metadata()?;
        ensure!(
            evidence["schema"] == "horizon-epoch168-retry5-successor-root-v1"
                && evidence["root"] == json!(root)
                && evidence["device"] == meta.dev()
                && evidence["inode"] == meta.ino()
                && evidence["source_control_sha256"]
                    == "488dbd9e630511b97a0ad0704241a0a1fdec71a614caf17c6cd1d3a63b3dc0b2"
                && evidence["whole_tree_cap_bytes"] == LANES[0].cap
                && meta.dev() == 64512
                && meta.uid() == 1001
                && meta.gid() == 1003
                && meta.mode() & 0o7777 == 0o700,
            "retry5 epoch 168 successor directory changed"
        );
        let reference = Bound {
            path,
            sha256: crate::sha(&bytes),
        };
        bound(&reference)?;
        refs.push(reference);
    }
    Ok(json!({"schema":"horizon-incident-native-successor-roots-v1","receipts":refs}))
}

pub(super) fn observe(binding: &Value, scope: &Scope<'_>) -> Result<Observation> {
    let image = fs::read_link("/proc/self/exe")?;
    let roots = qualification_roots(&image)?;
    let b: Binding = serde_json::from_value(binding.clone())?;
    let contract: Contract =
        serde_json::from_value(sealed(&b.contract, &b.deployment_seal, "contract.json")?)?;
    let witness = bound(&contract.qualified_native_witness)?;
    ensure!(
        witness["independent_roots_receipt"] == roots,
        "witness does not bind the restored namespaces"
    );
    let mut result = observe_allocation(
        binding,
        scope.filesystem,
        scope.initial_available_bytes,
        &image,
        scope.guard_sha256,
    )?;
    ensure!(
        qualification_roots(&image)? == roots,
        "restored namespace changed during allocation"
    );
    // The shared post-stop fit already derives an absolute free-space requirement.
    // Adding the observed legacy fulfillment to free space would charge it twice.
    result.evidence["measured_legacy_fulfillment_bytes"] = json!(result.fulfilled_bytes);
    result.fulfilled_bytes = 0;
    result.available_plus_fulfilled_bytes = result.conservative_available_bytes;
    result.effective_required_free_bytes = scope.raw_floor;
    result.evidence["fulfilled_bytes"] = json!(0);
    result.evidence["available_plus_fulfilled_bytes"] = json!(result.conservative_available_bytes);
    result.evidence["effective_required_free_bytes"] = json!(scope.raw_floor);
    result.evidence["enforced_raw_minimum_free_bytes"] = json!(scope.raw_floor);
    result.evidence["successor_roots"] = roots;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "epoch168-cold-v2")]
    #[test]
    fn metered168_accepts_only_its_new_cold_generation() {
        assert_eq!(LANES.len(), 1);
        assert_eq!(LANES[0].cap, 288 << 30);
        assert!(is_route(
            "horizon-qualify-168-full-metered-cold-v2-20261122.service"
        ));
        for other in [
            "horizon-qualify-168-full-metered-20261121-v1.service",
            "horizon-qualify-166-independent-retry11-20261122.service",
            "horizon-qualify-170-replacement-local3retry13-20261122.service",
        ] {
            assert!(!is_route(other));
        }
    }

    #[cfg(feature = "epoch168-cold-v3")]
    #[test]
    fn metered168_retry3_rejects_its_spent_predecessor() {
        assert_eq!(LANES.len(), 1);
        assert_eq!(LANES[0].cap, 288 << 30);
        assert!(is_route(
            "horizon-qualify-168-full-metered-cold-v3-20261123.service"
        ));
        for other in [
            "horizon-qualify-168-full-metered-cold-v2-20261122.service",
            "horizon-qualify-168-full-metered-20261121-v1.service",
            "horizon-qualify-166-independent-retry11-20261122.service",
            "horizon-qualify-170-replacement-local3retry13-20261122.service",
        ] {
            assert!(!is_route(other));
        }
    }

    #[cfg(feature = "epoch168-cold-v4")]
    #[test]
    fn metered168_retry4_rejects_its_spent_predecessor() {
        assert_eq!(LANES.len(), 1);
        assert_eq!(LANES[0].cap, 288 << 30);
        assert!(is_route(
            "horizon-qualify-168-full-metered-cold-v4-20261123.service"
        ));
        for other in [
            "horizon-qualify-168-full-metered-cold-v3-20261123.service",
            "horizon-qualify-168-full-metered-cold-v2-20261122.service",
            "horizon-qualify-168-full-metered-20261121-v1.service",
            "horizon-qualify-166-independent-retry11-20261122.service",
            "horizon-qualify-170-replacement-local3retry13-20261122.service",
        ] {
            assert!(!is_route(other));
        }
    }

    #[cfg(feature = "epoch168-cold-v5")]
    #[test]
    fn metered168_retry5_requires_the_repriced_generation() {
        assert_eq!(LANES.len(), 1);
        assert_eq!(LANES[0].cap, 512 << 30);
        assert!(is_route(
            "horizon-qualify-168-full-metered-cold-v5-20261125.service"
        ));
        assert!(!is_route(
            "horizon-qualify-168-full-metered-cold-v4-20261123.service"
        ));
    }

    #[cfg(feature = "epoch166-retry11")]
    #[test]
    fn independent_retry11_rejects_the_previous_worker() {
        assert_eq!(LANES.len(), 1);
        assert_eq!(LANES[0].cap, 288 << 30);
        assert!(is_route(
            "horizon-qualify-166-independent-retry11-20261122.service"
        ));
        assert!(!is_route(
            "horizon-qualify-166-independent-recovery-20261121-v1.service"
        ));
    }

    #[cfg(feature = "epoch170-retry11")]
    #[test]
    fn retry11_170_accepts_only_its_384_gib_successor() {
        assert_eq!(LANES.len(), 1);
        assert_eq!(LANES[0].cap, 384 << 30);
        assert!(is_route(
            "horizon-qualify-170-replacement-local3retry11-20261122.service"
        ));
        assert!(!is_route(
            "horizon-qualify-170-replacement-local3retry10-20261121-v1.service"
        ));
        assert!(!is_route(
            "horizon-qualify-166-independent-retry11-20261122.service"
        ));
    }

    #[cfg(feature = "epoch170-retry12")]
    #[test]
    fn retry12_170_accepts_only_its_384_gib_successor() {
        assert_eq!(LANES.len(), 1);
        assert_eq!(LANES[0].cap, 384 << 30);
        assert!(is_route(
            "horizon-qualify-170-replacement-local3retry12-20261122.service"
        ));
        assert!(!is_route(
            "horizon-qualify-170-replacement-local3retry11-20261122.service"
        ));
        assert!(!is_route(
            "horizon-qualify-166-independent-retry11-20261122.service"
        ));
    }

    #[cfg(feature = "epoch170-retry13")]
    #[test]
    fn retry13_170_accepts_only_its_384_gib_successor() {
        assert_eq!(LANES.len(), 1);
        assert_eq!(LANES[0].cap, 384 << 30);
        assert!(is_route(
            "horizon-qualify-170-replacement-local3retry13-20261122.service"
        ));
        assert!(!is_route(
            "horizon-qualify-170-replacement-local3retry12-20261122.service"
        ));
        assert!(!is_route(
            "horizon-qualify-166-independent-retry11-20261122.service"
        ));
    }

    #[cfg(feature = "epoch166-write-version-reproduction")]
    #[test]
    fn bounded_166_uses_the_whole_tree_booking_and_a_separate_guard() {
        assert_eq!(LANES.len(), 1);
        assert_eq!(LANES[0].cap, 288 << 30);
        assert_eq!(LANES[0].tree, "epoch166-independent-cold-20261120-v1");
        assert!(is_route(
            "horizon-qualify-166-write-version-reproduction-20261124-v1.service"
        ));
        assert!(!is_route(
            "horizon-qualify-166-independent-retry11-20261122.service"
        ));
    }

    #[cfg(feature = "epoch170-full-metered")]
    #[test]
    fn metered_170_guard_recognizes_only_the_corrected_producer() {
        assert_eq!(LANES.len(), 1);
        assert_eq!(LANES[0].cap, 384 << 30);
        assert!(is_route(
            "horizon-qualify-170-full-metered-20261124-v1.service"
        ));
        assert!(!is_route(
            "horizon-qualify-170-replacement-local3retry13-20261122.service"
        ));
    }

    #[cfg(feature = "epoch167-cold-v3")]
    #[test]
    fn cold167_accepts_only_the_v3_source_index_unit() {
        assert_eq!(LANES.len(), 1);
        assert_eq!(LANES[0].cap, 512 << 30);
        assert!(is_route(
            "horizon-qualify-167-source-index-v3-20261122.service"
        ));
        assert!(!is_route(
            "horizon-qualify-167-source-index-v2-20261122.service"
        ));
        assert!(!is_route(
            "horizon-qualify-167-source-index-v1-20261121.service"
        ));
    }
    #[cfg(feature = "epoch170-384")]
    #[test]
    fn enlarged_cap_is_exclusive_to_the_170_successor() {
        assert_eq!(LANES.len(), 1);
        assert_eq!(LANES[0].cap, 384 << 30);
        assert!(is_route(
            "horizon-qualify-170-replacement-local3retry10-20261121-v1.service"
        ));
        assert!(!is_route(
            "horizon-qualify-166-independent-recovery-20261121-v1.service"
        ));
        assert!(!is_route(
            "horizon-qualify-167-source-index-v1-20261121.service"
        ));
    }
    #[test]
    #[ignore = "requires the original root-owned namespace evidence on dev-samjohnson"]
    fn original_namespace_receipts_and_all_precreated_roots() {
        let roots = qualification_roots(Path::new(IMAGE)).unwrap();
        let expected = if cfg!(any(
            feature = "epoch166-retry11",
            feature = "epoch168-cold-v2",
            feature = "epoch168-cold-v3",
            feature = "epoch168-cold-v4",
            feature = "epoch168-cold-v5",
            feature = "epoch170-retry11",
            feature = "epoch170-retry12",
            feature = "epoch170-retry13"
        )) {
            4
        } else {
            3
        };
        let expected = if cfg!(feature = "epoch166-write-version-reproduction") {
            7
        } else if cfg!(any(
            feature = "epoch170-full-metered",
            feature = "epoch168-cold-v5"
        )) {
            5
        } else {
            expected
        };
        assert_eq!(roots["receipts"].as_array().unwrap().len(), expected);
        assert!(qualification_roots(Path::new("/tmp/guard")).is_err());
    }

    #[test]
    fn incident_unit_root_cap_floor_and_receipt_directory_are_inseparable() {
        for lane in LANES {
            let mut p: Plan = serde_json::from_value(json!({
                "schema":"jetstreamer-horizon-standalone-guard-plan-v1", "unit":lane.unit,
                "invocation_id":"a".repeat(32), "filesystem":"/home/sol", "minimum_free_bytes":MIN_FLOOR,
                "worker_root":Path::new(HOME).join(lane.tree), "maximum_worker_vmas":3500000,
                "maximum_root_physical_bytes":lane.cap,
                "receipt_directory":Path::new(RUNTIME).join(lane.runtime).join("guard-receipts"),
                "data_fulfillment":{"contract":"placeholder"}})).unwrap();
            validate(&p).unwrap();
            p.minimum_free_bytes -= 1;
            assert!(validate(&p).is_err());
            p.minimum_free_bytes += 1;
            p.maximum_root_physical_bytes = Some(lane.cap + 1);
            assert!(validate(&p).is_err());
            p.maximum_root_physical_bytes = Some(lane.cap);
            p.worker_root.push("new-epoch-only");
            assert!(validate(&p).is_err());
            p.worker_root.pop();
            p.receipt_directory.push("sibling");
            assert!(validate(&p).is_err());
            p.receipt_directory.pop();
            p.data_fulfillment = None;
            assert!(validate(&p).is_err());
        }
    }
}
