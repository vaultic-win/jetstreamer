use super::*;

mod closed_indexes;
pub(super) use closed_indexes::{
    is_early_singleton_index, is_index, is_singleton_index, lock_early_singleton_controllers,
    lock_index_controllers, lock_singleton_controllers,
};

const REVIEW: &str = "/home/sol/.jetstreamer-private/epoch145-v5t-stopped-price-20261124.zjcggc_6/RETIREMENT_CANDIDATES_130_195.json";
const REVIEW_SHA: &str = "6b4563c22f4d586bb8c2fc38c91e4a5c1b8180463b7b27de8de2fa1b115a1291";
const FIRST_SWEEP_REVIEW: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/closed119121-retirement-20261125-v1/REVIEW.json";
const FIRST_SWEEP_SHA: &str = "8211fd22d7184f44c418f0602ec251037796b76278d38c966d802df3756a6bd0";
const FIRST_SWEEP_SCHEMA: &str = "horizon-119-121-obsolete-sweep-output-review-v1";
const FIRST_SWEEP: &str = "epochs119-147-20260922-v1";
const FIRST_SWEEP_TARGETS: &[(u64, &str)] = &[
    (
        119,
        "lane-a/private/destination-c5be130f620a62fd07b3a0e691623913d741234fcf5f181878e8e8dc2f646948/work/root-cohort-119-120/run-4191867-1790037445238974158/archives/epoch-119.jet",
    ),
    (
        119,
        "lane-a/output/compact-indexes/119/epoch-119-bafyreid47uzzln4we2csgomwa2xic7rs3msd77sf2kp3vhlo3qinj2bety-mainnet-cid-to-offset-and-size.index",
    ),
    (
        119,
        "lane-a/output/compact-indexes/119/epoch-119-bafyreid47uzzln4we2csgomwa2xic7rs3msd77sf2kp3vhlo3qinj2bety-mainnet-slot-to-cid.index",
    ),
    (
        121,
        "lane-b/private/destination-63c0e82273553ec9d7941677ba71a9a819f878af17a6dc89d21909285635f7cb/work/root-cohort-121-121/run-4191894-1790037445364594405/archives/epoch-121.jet",
    ),
    (
        121,
        "lane-b/output/compact-indexes/121/epoch-121-bafyreibothqfnoljwaplz5ru6kvuyrvtw24mskfmajvhknh4qkaue32gwa-mainnet-cid-to-offset-and-size.index",
    ),
    (
        121,
        "lane-b/output/compact-indexes/121/epoch-121-bafyreibothqfnoljwaplz5ru6kvuyrvtw24mskfmajvhknh4qkaue32gwa-mainnet-slot-to-cid.index",
    ),
];
const FOLLOWUP_REVIEW: &str = "/var/lib/jetstreamer/horizon_runtime_data/closed-canaries-retirement-134-154-20261124-v1/REVIEW.json";
const FOLLOWUP_REVIEW_SHA: &str =
    "3e4fb8c99b53cbec9ad8e8d2b0d63862c22a21d191229d539d3124f262710474";
const FOLLOWUP_SCHEMA: &str = "horizon-closed-canary-retirement-review-v1";
const SNAPSHOT_REVIEW: &str =
    "/home/sol/.jetstreamer-private/epochs191-194-snapshot-retirement-20261124-v1/REVIEW.json";
const SNAPSHOT_REVIEW_SHA: &str =
    "e4acc2dd74d569d66d5f9440c97bce2ca180ce8490249ce3bda783bd4d8bc664";
const SNAPSHOT_SCHEMA: &str = "horizon-191-194-bootstrap-duplicate-review-v1";
const SNAPSHOT_DIR: &str = "epochs191-194-bootstrap-revalidation-20261016-v1";
const SNAPSHOT_NAME: &str =
    "snapshot-82511783-6wKFbWHJ2FFVaexQWuTrRVsGL53ef8k8CgNqPWvGuymm.tar.zst";
const SNAPSHOT_KEEPER: &str = "/usr/local/lib/jetstreamer/deploy-epochs191-194-target5-20261016-v1";
const BENCHMARK_BOOTSTRAP_REVIEW: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch195-closed-bootstrap-retirement-20261125-v1/REVIEW.json";
const BENCHMARK_BOOTSTRAP_REVIEW_SHA: &str =
    "710cdf97b75b0d05ae527f06fd3a2203ace478081f468fcf66de2554748ee0fb";
const BENCHMARK_BOOTSTRAP_SCHEMA: &str = "horizon-195-closed-benchmark-bootstrap-review-v1";
const BENCHMARK_BOOTSTRAP_DIR: &str = "epoch195-rayon-qualification-v1";
const BENCHMARK_BOOTSTRAP_NAME: &str =
    "snapshot-84239250-GCANVakrcunYu9VRe1WdNd7xAPKGdoZNFgpQbagdB9zq.tar.zst";
const BOOTSTRAP_REVIEW: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch197-bootstrap-retirement-20261124-v1/REVIEW.json";
const BOOTSTRAP_REVIEW_SHA: &str =
    "1a0fe33ab596047495bac621d14bab451034044b302a72230242a08771a15944";
const BOOTSTRAP_SCHEMA: &str = "horizon-197-bootstrap-retirement-review-v1";
const BOOTSTRAP_DIR: &str = "epoch197-singleton-20261017-v1/bootstrap";
const BOOTSTRAP_NAME: &str =
    "snapshot-85103144-3VddsRMBDanRrgVeyJGzKvqAKoNjBrwkoSj6BEAvx2qB.tar.zst";
const INVENTORY: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch145-publication-20261121-v1/uploader-tools/jetstreamer-r2";
const INVENTORY_SHA: &str = "eb448ede557144f04446dbe00a2d2ec7ad88c934a7a227797d0569a15307a904";
const DIAGNOSTIC: &str = "diagnostic-epoch130-v1417-qualification-v1";
const BENCHMARK: &str = "performance-ab-195-rayon-20261009-v2";
const DIAGNOSTIC_134: &str = "diagnostic-epoch134-v1419-status-probe-v1";
const BENCHMARK_154: &str = "performance-ab-154-v158-rayon-20261009-v3";

fn is_benchmark_bootstrap(t: &Target) -> bool {
    t.epoch == 195
        && t.path
            == Path::new(HOME_ROOT)
                .join(".jetstreamer-private")
                .join(BENCHMARK_BOOTSTRAP_DIR)
                .join("inputs")
                .join(BENCHMARK_BOOTSTRAP_NAME)
}

pub(super) fn is_target(t: &Target) -> bool {
    let root = Path::new(HOME_ROOT).join(".jetstreamer-private");
    match t.epoch {
        119 | 121 => FIRST_SWEEP_TARGETS.iter().any(|(epoch, relative)| {
            t.epoch == *epoch && t.path == root.join(FIRST_SWEEP).join(relative)
        }),
        129 | 130 | 133 | 134 if is_early_singleton_index(t) => true,
        130 => {
            t.path
                == root
                    .join(DIAGNOSTIC)
                    .join("output/epoch-130-v1417-qualification.jet")
        }
        134 => {
            t.path
                == root
                    .join(DIAGNOSTIC_134)
                    .join("output/epoch-134-through-58019044.jet")
        }
        154 => ["control64", "candidate10"].iter().any(|case| {
            t.path
                == root
                    .join(BENCHMARK_154)
                    .join(case)
                    .join("output/epoch-154-through-66958784.jet")
        }),
        191..=194 if is_index(t) => true,
        195..=197 if is_singleton_index(t) => true,
        191 => t.path == root.join(SNAPSHOT_DIR).join("inputs").join(SNAPSHOT_NAME),
        195 if is_benchmark_bootstrap(t) => true,
        195 => ["control32", "candidate8"].iter().any(|case| {
            t.path
                == root
                    .join(BENCHMARK)
                    .join(case)
                    .join("output/epoch-195-through-84247825.jet")
        }),
        197 => t.path == root.join(BOOTSTRAP_DIR).join("inputs").join(BOOTSTRAP_NAME),
        _ => false,
    }
}

fn identity(t: &Target) -> Value {
    let s = &t.identity;
    json!({
        "dev": s.dev, "ino": s.ino, "nlink": s.nlink, "mode": s.mode,
        "uid": s.uid, "gid": s.gid, "size": s.len, "blocks": s.blocks,
        "mtime_ns": s.mtime * 1_000_000_000 + s.mtime_ns,
        "ctime_ns": s.ctime * 1_000_000_000 + s.ctime_ns,
    })
}

pub(super) fn verify_scope(p: &Plan, epochs: &BTreeSet<u64>, lock: &File) -> Result<Option<Value>> {
    let (path, sha256, schema, expected_epochs): (&str, &str, &str, &[u64]) =
        if p.targets.iter().any(is_early_singleton_index) {
            ensure!(
                closed_indexes::complete_selection(&p.targets, 6, is_early_singleton_index),
                "incomplete epoch 130 and 134 CAR index selection"
            );
            (
                closed_indexes::EARLY_SINGLETON_REVIEW,
                closed_indexes::EARLY_SINGLETON_SHA,
                closed_indexes::EARLY_SINGLETON_SCHEMA,
                &[129, 130, 133, 134],
            )
        } else if p.targets.iter().any(is_singleton_index) {
            ensure!(
                closed_indexes::complete_selection(&p.targets, 6, is_singleton_index),
                "incomplete singleton CAR index selection"
            );
            (
                closed_indexes::SINGLETON_REVIEW,
                closed_indexes::SINGLETON_SHA,
                closed_indexes::SINGLETON_SCHEMA,
                &[195, 196, 197],
            )
        } else if p.targets.iter().any(is_benchmark_bootstrap) {
            ensure!(
                closed_indexes::complete_selection(&p.targets, 1, is_benchmark_bootstrap),
                "expected the single reviewed epoch 195 bootstrap"
            );
            (
                BENCHMARK_BOOTSTRAP_REVIEW,
                BENCHMARK_BOOTSTRAP_REVIEW_SHA,
                BENCHMARK_BOOTSTRAP_SCHEMA,
                &[195],
            )
        } else if epochs.iter().any(|&epoch| matches!(epoch, 130 | 195)) {
            (
                REVIEW,
                REVIEW_SHA,
                "horizon-epoch145-disk-recovery-candidates-v1",
                &[130, 195],
            )
        } else if p
            .targets
            .iter()
            .any(|target| matches!(target.epoch, 134 | 154) && is_target(target))
        {
            (
                FOLLOWUP_REVIEW,
                FOLLOWUP_REVIEW_SHA,
                FOLLOWUP_SCHEMA,
                &[134, 154],
            )
        } else if epochs.contains(&119) || epochs.contains(&121) {
            (
                FIRST_SWEEP_REVIEW,
                FIRST_SWEEP_SHA,
                FIRST_SWEEP_SCHEMA,
                &[119, 121],
            )
        } else if p.targets.iter().any(is_index) {
            ensure!(
                closed_indexes::complete_selection(&p.targets, 8, is_index),
                "incomplete index retirement selection"
            );
            (
                closed_indexes::REVIEW,
                closed_indexes::SHA,
                closed_indexes::SCHEMA,
                &[191, 192, 193, 194],
            )
        } else if epochs.contains(&191) {
            (
                SNAPSHOT_REVIEW,
                SNAPSHOT_REVIEW_SHA,
                SNAPSHOT_SCHEMA,
                &[191],
            )
        } else if epochs.contains(&197) {
            (
                BOOTSTRAP_REVIEW,
                BOOTSTRAP_REVIEW_SHA,
                BOOTSTRAP_SCHEMA,
                &[197],
            )
        } else {
            return Ok(None);
        };
    let m = lock.metadata()?;
    ensure!(
        (m.dev(), m.ino(), m.uid(), m.gid()) == (64512, 101135013, 1001, 1003),
        "different shared mutation lock"
    );
    ensure!(
        epochs.iter().all(|epoch| expected_epochs.contains(epoch))
            && p.inventory_binary.path == Path::new(INVENTORY)
            && p.inventory_binary.sha256 == INVENTORY_SHA,
        "different canary retirement scope or inventory reader"
    );
    let review: Value = serde_json::from_slice(&bound(
        &Bound {
            path: path.into(),
            sha256: sha256.into(),
        },
        LIMIT,
    )?)?;
    ensure!(
        review["schema"] == schema
            && review["actual_reclaimed_bytes"] == 0
            && review["retirement_authorized"] == false,
        "different canary review"
    );
    let targets = review["targets"]
        .as_array()
        .context("missing reviewed targets")?;
    for target in &p.targets {
        let reviewed = targets
            .iter()
            .find(|v| v["epoch"] == target.epoch && v["path"].as_str() == target.path.to_str())
            .context("target was not reviewed")?;
        ensure!(
            reviewed["identity"] == identity(target),
            "different canary inode"
        );
        let terminal: Bound = serde_json::from_value(reviewed["terminal"].clone())?;
        bound(&terminal, LIMIT)?;
    }
    for proof in &p.proofs {
        let reference = &review["delivery_evidence"][proof.epoch.to_string()]["whole_object_receipts"]
            [proof.epoch.to_string()];
        ensure!(
            reference["path"].as_str() == proof.receipt.path.to_str()
                && reference["sha256"] == proof.receipt.sha256,
            "different canonical delivery receipt"
        );
    }
    check_owners(&review)?;
    if schema == SNAPSHOT_SCHEMA {
        verify_snapshot(&review, &p.targets[0])?;
    }
    if schema == BOOTSTRAP_SCHEMA {
        verify_gcs_bootstrap(&review, &p.targets[0])?;
    }
    if schema == BENCHMARK_BOOTSTRAP_SCHEMA {
        verify_benchmark_bootstrap(&review, &p.targets[0])?;
    }
    Ok(Some(review))
}

fn verify_benchmark_bootstrap(review: &Value, target: &Target) -> Result<()> {
    let item = &review["targets"][0];
    let reference: Bound = serde_json::from_value(item["terminal"].clone())?;
    let provenance: Value = serde_json::from_slice(&bound(&reference, LIMIT)?)?;
    ensure!(
        reference.path
            == target
                .path
                .parent()
                .and_then(Path::parent)
                .context("missing benchmark parent")?
                .join("checkpoint-provenance-84247825.json")
            && provenance["schema"] == "jetstreamer-canonical-checkpoint-provenance-v1"
            && provenance["bootstrap"]
                == json!({"slot":84239250,"archive":BENCHMARK_BOOTSTRAP_NAME})
            && provenance["checkpoint"]["slot"] == 84247825
            && provenance["qualification"]["publication_authorized"] == false
            && provenance["qualification"]["remote_mutations_authorized"] == false,
        "different closed benchmark bootstrap provenance"
    );
    ensure!(
        item["body_sha256"].as_str() == Some(digest(&target.path)?.as_str())
            && stamp(&exact(&target.path)?) == target.identity,
        "benchmark bootstrap changed after review"
    );
    Ok(())
}

fn verify_snapshot(review: &Value, target: &Target) -> Result<()> {
    let screen: Bound = serde_json::from_value(review["snapshot_screen"].clone())?;
    let screen: Value = serde_json::from_slice(&bound(&screen, LIMIT)?)?;
    let keeper_dir = Path::new(SNAPSHOT_KEEPER);
    let keeper = keeper_dir.join(SNAPSHOT_NAME);
    let parent = fs::symlink_metadata(keeper_dir)?;
    let saved_keeper = stamp(&exact(&keeper)?);
    let seal_path = keeper_dir.join("deployment-seal-receipt.json");
    let seal_digest = screen["evidence"][seal_path.to_str().context("non-UTF-8 seal path")?]
        .as_str()
        .context("missing deployment seal binding")?;
    let seal: Value = serde_json::from_slice(&bound(
        &Bound {
            path: seal_path,
            sha256: seal_digest.into(),
        },
        LIMIT,
    )?)?;
    let expected = screen["content_sha256"]
        .as_str()
        .context("missing snapshot SHA-256")?;
    ensure!(
        screen["schema"] == "horizon-obsolete-191-194-snapshot-screen-v1"
            && screen["source"].as_str() == target.path.to_str()
            && screen["keeper"].as_str() == keeper.to_str()
            && screen["compared_bytes"] == target.identity.len
            && parent.is_dir()
            && parent.uid() == 0
            && parent.mode() & 0o222 == 0
            && saved_keeper.uid == 0
            && saved_keeper.mode & 0o222 == 0
            && saved_keeper.dev != target.identity.dev
            && saved_keeper.len == target.identity.len
            && seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && seal["destination"] == SNAPSHOT_KEEPER
            && seal["members"].as_array().is_some_and(|members| {
                members.iter().any(|member| {
                    member["source"].as_str() == target.path.to_str()
                        && member["name"] == SNAPSHOT_NAME
                        && member["bytes"] == target.identity.len
                        && member["sha256"] == expected
                })
            }),
        "retained snapshot or seal differs from the reviewed copy"
    );
    ensure!(
        digest(&keeper)? == expected
            && digest(&target.path)? == expected
            && stamp(&exact(&keeper)?) == saved_keeper
            && stamp(&exact(&target.path)?) == target.identity,
        "snapshot bodies or file identities changed"
    );
    Ok(())
}

fn verify_gcs_bootstrap(review: &Value, target: &Target) -> Result<()> {
    let restore: Bound = serde_json::from_value(review["targets"][0]["terminal"].clone())?;
    let restore: Value = serde_json::from_slice(&bound(&restore, LIMIT)?)?;
    let metadata: Bound = serde_json::from_value(review["gcs_metadata"].clone())?;
    let metadata: Value = serde_json::from_slice(&bound(&metadata, LIMIT)?)?;
    let original = &restore["remote_object"];
    let generation = 1_634_789_304_042_914_u64;
    let key = format!("85103144/{BOOTSTRAP_NAME}");
    ensure!(
        restore["schema"] == "jetstreamer-bound-gcs-snapshot-restore-v1"
            && restore["remote_mutations"] == false
            && restore["r2_mutations"] == false
            && restore["destination"].as_str() == target.path.to_str()
            && restore["generation"] == generation
            && restore["file"]["size"] == target.identity.len
            && original["bucket"] == "mainnet-beta-ledger-us-ny5"
            && original["bucket"] == metadata["bucket"]
            && original["name"] == key
            && original["name"] == metadata["name"]
            && original["generation"] == generation
            && metadata["generation"].as_str().and_then(|v| v.parse().ok()) == Some(generation)
            && original["size"] == target.identity.len
            && original["size"] == metadata["size"]
            && original["md5_base64"]
                .as_str()
                .is_some_and(|value| !value.is_empty())
            && original["md5_base64"] == metadata["md5_hash"]
            && original["crc32c_base64"]
                .as_str()
                .is_some_and(|value| !value.is_empty())
            && original["crc32c_base64"] == metadata["crc32c_hash"],
        "GCS generation differs from the original authenticated snapshot restore"
    );
    let sha = restore["file"]["sha256"]
        .as_str()
        .context("missing restored snapshot digest")?;
    ensure!(
        digest(&target.path)? == sha && stamp(&exact(&target.path)?) == target.identity,
        "restored snapshot body or identity changed"
    );
    Ok(())
}

pub(super) fn check_owners(review: &Value) -> Result<()> {
    let markers: &[&str] = match review["schema"].as_str() {
        Some(FIRST_SWEEP_SCHEMA) => &[
            FIRST_SWEEP,
            "epochs119-147-20260922-v28",
            "historical-119-147-v28",
            "run-4191867-1790037445238974158",
            "run-4191894-1790037445364594405",
        ],
        Some(FOLLOWUP_SCHEMA) => &[DIAGNOSTIC_134, BENCHMARK_154],
        Some(SNAPSHOT_SCHEMA) => &[SNAPSHOT_DIR],
        Some(BOOTSTRAP_SCHEMA) => &[BOOTSTRAP_DIR],
        Some(BENCHMARK_BOOTSTRAP_SCHEMA) => &[BENCHMARK_BOOTSTRAP_DIR, BENCHMARK_BOOTSTRAP_NAME],
        _ => &[DIAGNOSTIC, BENCHMARK],
    };
    if review["schema"] == FIRST_SWEEP_SCHEMA {
        // The epoch 185 unit mounted the historical batch directory read-only.
        // Its sealed plan operates on a different run. The loader qualification
        // names a snapshot in inputs/, which stays alongside the cohort state.
        for key in ["source_generation", "epoch185_spec", "preserved_snapshot"] {
            bound(&serde_json::from_value(review[key].clone())?, LIMIT)?;
        }
        let screen: Value = serde_json::from_slice(&bound(
            &serde_json::from_value(review["installed_reference_screen"].clone())?,
            LIMIT,
        )?)?;
        for file in screen["matches"]
            .as_array()
            .context("missing swept references")?
        {
            let bound_file = Bound {
                path: PathBuf::from(file["path"].as_str().context("reference path")?),
                sha256: file["sha256"]
                    .as_str()
                    .context("reference digest")?
                    .to_owned(),
            };
            bound(&bound_file, LIMIT)?;
        }
    }
    if matches!(
        review["schema"].as_str(),
        Some(
            closed_indexes::SCHEMA
                | closed_indexes::SINGLETON_SCHEMA
                | closed_indexes::EARLY_SINGLETON_SCHEMA
        )
    ) {
        return closed_indexes::check_owners(review);
    }
    let scan = Command::new("/usr/bin/rg")
        .args(["--files-with-matches", "--fixed-strings"])
        .args(markers.iter().flat_map(|pattern| ["-e", pattern]))
        .args([
            "/etc/systemd/system",
            "/run/systemd/transient",
            "/usr/lib/systemd/system",
            "/run/systemd/system",
        ])
        .output()?;
    ensure!(
        matches!(scan.status.code(), Some(0 | 1)) && scan.stderr.is_empty(),
        "staged owner scan failed"
    );
    let definitions = review["definitions"]
        .as_array()
        .context("missing staged definitions")?;
    for path in String::from_utf8(scan.stdout)?.lines() {
        ensure!(
            definitions.iter().any(|entry| entry == path),
            "unreviewed staged owner {path}"
        );
    }
    let managers = review["inactive_units"]
        .as_object()
        .context("missing reviewed managers")?;
    let units: Vec<_> = managers.keys().cloned().collect();
    inactive(&units)?;
    for unit in units {
        let result = Command::new("/usr/bin/systemctl")
            .args(["show", &unit, "-p", "Id,ControlPID,Triggers,TriggeredBy"])
            .output()?;
        ensure!(
            result.status.success() && result.stderr.is_empty(),
            "cannot inspect {unit}"
        );
        let state = String::from_utf8(result.stdout)?;
        for expected in [
            format!("Id={unit}").as_str(),
            "ControlPID=0",
            "Triggers=",
            "TriggeredBy=",
        ] {
            ensure!(
                state.lines().any(|line| line == expected),
                "scheduled canary owner {unit}"
            );
        }
    }
    Ok(())
}

pub(super) fn inventory_range(review: &Value, range: (u64, u64)) -> (u64, u64) {
    if review["schema"] == SNAPSHOT_SCHEMA {
        (190, 195)
    } else {
        (range.0 - 1, range.1 + 1)
    }
}

pub(super) fn verify_delivery(
    review: &Value,
    epochs: &BTreeSet<u64>,
    inventory: &Value,
) -> Result<()> {
    let snapshot_epochs = BTreeSet::from([191, 192, 193, 194]);
    let epochs = if review["schema"] == SNAPSHOT_SCHEMA {
        &snapshot_epochs
    } else {
        epochs
    };
    for &epoch in epochs {
        let evidence = &review["delivery_evidence"][epoch.to_string()];
        let mut digests = Vec::new();
        for n in epoch - 1..=epoch + 1 {
            let receipt: Bound =
                serde_json::from_value(evidence["whole_object_receipts"][n.to_string()].clone())?;
            let body: Value = serde_json::from_slice(&bound(&receipt, LIMIT)?)?;
            ready(n, &body, inventory)?;
            digests.push(
                body["archive_sha256"]
                    .as_str()
                    .context("missing delivered digest")?
                    .to_owned(),
            );
        }
        let [left, center, right] = digests.as_slice() else {
            unreachable!("three epoch receipts")
        };
        let gates = evidence["verification_gates"]
            .as_array()
            .context("missing verification receipts")?;
        ensure!(gates.len() == 4, "incomplete canary verification receipts");
        for (gate, expected) in gates.iter().zip([
            vec![center.as_str()],
            vec![center.as_str()],
            vec![left.as_str(), center.as_str()],
            vec![center.as_str(), right.as_str()],
        ]) {
            let bytes = bound(&serde_json::from_value(gate.clone())?, 4096)?;
            let fields: Vec<_> = std::str::from_utf8(&bytes)?.split_whitespace().collect();
            ensure!(
                fields.len() == expected.len() + 2 && fields.starts_with(&expected),
                "verification receipt differs from the authenticated archive digests"
            );
        }
    }
    Ok(())
}

pub(super) fn lock_first_sweep_controller() -> Result<File> {
    controller_lock(
        "/var/lib/jetstreamer-root-sweep-epochs119-147-20260922-v28/controller.lock",
        3276851,
    )
}

fn controller_lock(path: &str, inode: u64) -> Result<File> {
    let lock = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let m = lock.metadata()?;
    ensure!(
        m.is_file()
            && (
                m.dev(),
                m.ino(),
                m.uid(),
                m.gid(),
                m.nlink(),
                m.mode() & 0o7777
            ) == (2304, inode, 0, 0, 1, 0o600),
        "different original sweep lock"
    );
    ensure!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "original sweep controller is occupied"
    );
    Ok(lock)
}

#[cfg(test)]
mod first_sweep_tests {
    use super::*;

    #[test]
    fn first_sweep_selection_binds_both_epoch_and_exact_file() {
        let root = Path::new(HOME_ROOT)
            .join(".jetstreamer-private")
            .join(FIRST_SWEEP);
        for (epoch, relative) in FIRST_SWEEP_TARGETS {
            let mut target: Target = serde_json::from_value(json!({
                "epoch": epoch, "path": root.join(relative), "reason": "test",
                "identity": {
                    "dev": 1, "ino": 2, "nlink": 1, "mode": 0o100600, "uid": 1001,
                    "gid": 1003, "len": 10, "blocks": 1, "mtime": 1, "mtime_ns": 0,
                    "ctime": 1, "ctime_ns": 0
                }
            }))
            .unwrap();
            assert!(is_target(&target));
            target.epoch = if *epoch == 119 { 121 } else { 119 };
            assert!(!is_target(&target));
            target.epoch = *epoch;
            target.path.set_file_name("snapshot-51407922.tar.zst");
            assert!(!is_target(&target));
        }
    }
}
