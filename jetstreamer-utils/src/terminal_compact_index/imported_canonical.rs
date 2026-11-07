// Exact original235/237 cache profiles after canonical import. No foreign
// recipe exemption, owner-tree deletion or archive-payload read is added.
use super::*;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ImportedCanonical {
    epoch: u64,
    archive: Preserved,
    checksum: Evidence,
    ready_acceptance: Evidence,
    original_metadata: Vec<Evidence>,
}

struct Profile {
    root: &'static str,
    unit: &'static str,
    iid: &'static str,
    ready: &'static str,
    ready_sha: &'static str,
    metadata: &'static [&'static str],
}

fn profile(epoch: u64) -> Result<Profile> {
    Ok(match epoch {
        235 => Profile {
            root: "qualification-235-general-shrink-debt-budget506-e3f15eb2-v1",
            unit: "horizon-qualify-235-general-shrink-debt-budget506-e3f15eb2-v2.service",
            iid: "b8c33086cca3407a8a1d79953b40b542",
            ready: "/var/lib/jetstreamer/horizon235-ready-completion870-Main-v1/authenticated-ready-pair-and-native-completion.json",
            ready_sha: "8e1306269113dbf1501f7687b4c53572f8ff8b64e0a3686436e5c2aa034e79a9",
            metadata: &[
                "state/destination-e748bbe05a30e82d20c8d3719401380224b340a7e8fdb7016c69f42c7c9701ce/work/root-cohort-235-235/run-2634498-1793673351962548044/cohort-state.json",
                "state/destination-e748bbe05a30e82d20c8d3719401380224b340a7e8fdb7016c69f42c7c9701ce/evidence/archive-batches/destination-0000000000010301-0000000000e5d46e/batch-a9756e58dea8404bd48896e41a3362641bac8afbac744423fdadd1900c2f7768.json",
            ],
        },
        237 => Profile {
            root: "qualification-237-general-shrink-debt-budget506-e3f15eb2-v4",
            unit: "horizon-qualify-237-general-shrink-debt-budget506-e3f15eb2-v4.service",
            iid: "cf9e7cff3df04e00939d6b7687180b60",
            ready: "/var/lib/jetstreamer/horizon237-ready909-event-v1/ready-pair-acceptance.json",
            ready_sha: "79f7f186be192412ac8ec37b101419d43aeac47302a4c9dd4fcd215a4327b335",
            metadata: &[
                "state/destination-84b1112cdb16efc508dc92c7bacafd8acddd7b341578d82ae5734bbb2540d584/evidence/archive-batches/destination-0000000000010301-0000000000e5d387/batch-b730b4ee11cf5aa96863493a891198f97aad89a37ca4b2d78193de09aa46e68e.json",
            ],
        },
        _ => anyhow::bail!("no imported-canonical cache profile for this epoch"),
    })
}

pub(super) fn validate_owner(owner: &Owner, imported: &ImportedCanonical) -> Result<()> {
    let p = profile(imported.epoch)?;
    ensure!(
        owner.root == Path::new(PRIVATE).join(p.root)
            && owner
                .actors
                .iter()
                .any(|a| a.unit == p.unit && a.invocation_id == p.iid),
        "imported profile requires its original root and terminal producer"
    );
    ensure!(
        imported.archive.path
            == Path::new("/home/ubuntu/horizon").join(format!("epoch-{}.jet", imported.epoch))
            && imported.archive.identity.uid == 1000
            && imported.archive.identity.gid == 1000
            && imported.archive.identity.nlink == 1
            && imported.archive.identity.mode == (libc::S_IFREG | 0o440)
            && imported.checksum.path == imported.archive.path.with_extension("jet.sha256")
            && imported.checksum.uid == 1000
            && imported.ready_acceptance.path == Path::new(p.ready)
            && imported.ready_acceptance.sha256 == p.ready_sha
            && imported.ready_acceptance.uid == 0,
        "imported canonical custody/acceptance profile changed"
    );
    ensure!(
        imported.original_metadata.len() == p.metadata.len(),
        "missing or additional original metadata binding"
    );
    for relative in p.metadata {
        let path = owner.root.join(relative);
        ensure!(
            imported
                .original_metadata
                .iter()
                .filter(|e| e.path == path && e.uid == 1000 && valid_sha(&e.sha256))
                .count()
                == 1
                && owner.preserved.iter().filter(|f| f.path == path).count() == 1,
            "required original metadata must retain both digest and original inode identity"
        );
    }
    Ok(())
}

pub(super) fn validate_index(
    owner: &Owner,
    imported: &ImportedCanonical,
    index: &Index,
) -> Result<()> {
    validate_owner(owner, imported)?;
    ensure!(
        index.epoch == imported.epoch
            && index.path.parent()
                == Some(
                    owner
                        .root
                        .join(format!("output/compact-indexes/{}", imported.epoch))
                        .as_path()
                ),
        "imported profile excludes adjacent indexes and alternative cache trees"
    );
    Ok(())
}

fn preserved_identity(file: &Preserved) -> Result<()> {
    let m = fs::symlink_metadata(&file.path)?;
    ensure!(
        file.path.canonicalize()? == file.path
            && identity(&m) == file.identity
            && m.ctime() == file.ctime
            && m.ctime_nsec() == file.ctime_nsec,
        "imported canonical archive identity changed"
    );
    Ok(())
}

pub(super) fn preserved(owner: &Owner, imported: &ImportedCanonical, plan: &Plan) -> Result<()> {
    validate_owner(owner, imported)?;
    preserved_identity(&imported.archive)?;
    let ready: Value = serde_json::from_slice(&evidence(&imported.ready_acceptance)?)?;
    let (schema, receipt_field, binding_field) = match imported.epoch {
        235 => (
            "horizon235-genuine-ready-pair-Main-acceptance870-v1",
            "receipt",
            "qualified_Rust_archive_receipt",
        ),
        237 => (
            "horizon237-genuine-ready-pair909-acceptance-v1",
            "remote_receipt_contents",
            "remote_receipt",
        ),
        _ => anyhow::bail!("unsupported imported epoch"),
    };
    ensure!(
        ready["schema"] == schema && ready["Main_accepted"] == true,
        "foreign ready acceptance"
    );
    let receipt = &ready[receipt_field];
    canonical_receipt(receipt, imported.epoch)?;
    ensure!(
        receipt["archive_length"] == imported.archive.identity.size,
        "imported length differs from genuine readback"
    );
    let digest = receipt["archive_sha256"]
        .as_str()
        .context("canonical digest")?;
    ensure!(
        evidence(&imported.checksum)?
            == format!("{digest}  epoch-{}.jet\n", imported.epoch).as_bytes(),
        "imported canonical checksum differs from genuine readback"
    );
    for index in plan.indexes.iter().filter(|i| {
        plan.owners
            .get(i.owner)
            .is_some_and(|o| o.root == owner.root)
    }) {
        let actual: Value = serde_json::from_slice(&evidence(&index.canonical_r2_receipt)?)?;
        ensure!(
            actual == *receipt
                && ready[binding_field]["path"].as_str()
                    == index.canonical_r2_receipt.path.to_str()
                && ready[binding_field]["sha256"] == index.canonical_r2_receipt.sha256,
            "index receipt differs from exact accepted imported canonical archive"
        );
    }
    for original in &imported.original_metadata {
        evidence(original)?;
    }
    // Fresh full owner-root /proc and staged-recipe checks in the caller remain
    // unchanged. This function gives no reader, process or recipe exemption.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(epoch: u64) -> Owner {
        let p = profile(epoch).unwrap();
        let root = Path::new(PRIVATE).join(p.root);
        let id = Identity {
            device: 1,
            inode: 2,
            size: 3,
            blocks: 8,
            uid: 1000,
            gid: 1000,
            mode: libc::S_IFREG | 0o440,
            nlink: 1,
            mtime: 4,
            mtime_nsec: 5,
        };
        let keep = |path: PathBuf| Preserved {
            path,
            identity: id.clone(),
            ctime: 6,
            ctime_nsec: 7,
        };
        Owner {
            root: root.clone(),
            actors: vec![Actor {
                unit: p.unit.into(),
                invocation_id: p.iid.into(),
                historical_provenance: None,
            }],
            preserved: p.metadata.iter().map(|r| keep(root.join(r))).collect(),
            imported_canonical: Some(ImportedCanonical {
                epoch,
                archive: keep(Path::new("/home/ubuntu/horizon").join(format!("epoch-{epoch}.jet"))),
                checksum: Evidence {
                    path: format!("/home/ubuntu/horizon/epoch-{epoch}.jet.sha256").into(),
                    sha256: "a".repeat(64),
                    uid: 1000,
                },
                ready_acceptance: Evidence {
                    path: p.ready.into(),
                    sha256: p.ready_sha.into(),
                    uid: 0,
                },
                original_metadata: p
                    .metadata
                    .iter()
                    .map(|r| Evidence {
                        path: root.join(r),
                        sha256: "b".repeat(64),
                        uid: 1000,
                    })
                    .collect(),
            }),
        }
    }

    #[test]
    fn only_two_exact_imported_profiles_retain_original_metadata() {
        for epoch in [235, 237] {
            let owner = sample(epoch);
            validate_owner(&owner, owner.imported_canonical.as_ref().unwrap()).unwrap();
        }
        for epoch in [202, 234, 236, 238, 301] {
            assert!(profile(epoch).is_err());
        }
    }

    #[test]
    fn imported_custody_rejects_substituted_roots_archive_metadata_acceptance_and_original_paths() {
        for epoch in [235, 237] {
            let baseline = serde_json::to_value(sample(epoch)).unwrap();
            for (pointer, value) in [
                ("/root", json!(format!("{PRIVATE}/qualification-202"))),
                ("/actors/0/invocation_id", json!("f".repeat(32))),
                ("/imported_canonical/epoch", json!(234)),
                (
                    "/imported_canonical/archive/path",
                    json!("/tmp/copied-epoch.jet"),
                ),
                ("/imported_canonical/archive/identity/nlink", json!(2)),
                (
                    "/imported_canonical/archive/identity/mode",
                    json!(libc::S_IFREG | 0o640),
                ),
                (
                    "/imported_canonical/ready_acceptance/sha256",
                    json!("0".repeat(64)),
                ),
                (
                    "/imported_canonical/original_metadata/0/path",
                    json!("/tmp/metadata-backup.json"),
                ),
                ("/preserved/0/path", json!("/tmp/metadata-backup.json")),
            ] {
                let mut value_under_test = baseline.clone();
                *value_under_test.pointer_mut(pointer).unwrap() = value;
                let owner: Owner = serde_json::from_value(value_under_test).unwrap();
                assert!(
                    validate_owner(&owner, owner.imported_canonical.as_ref().unwrap()).is_err(),
                    "accepted {pointer}"
                );
            }
            let mut owner = sample(epoch);
            owner.preserved.clear();
            assert!(validate_owner(&owner, owner.imported_canonical.as_ref().unwrap()).is_err());
        }
    }

    #[test]
    fn imported_cache_selection_rejects_previous_epoch_and_sibling_trees() {
        for epoch in [235, 237] {
            let owner = sample(epoch);
            let imported = owner.imported_canonical.as_ref().unwrap();
            let mut index = Index {
                path: owner
                    .root
                    .join(format!("output/compact-indexes/{epoch}/cache.index")),
                identity: imported.archive.identity.clone(),
                original_ctime: 0,
                original_ctime_nsec: 0,
                owner: 0,
                epoch,
                header_hex: String::new(),
                reproduction_url: String::new(),
                canonical_r2_receipt: Evidence {
                    path: "/var/lib/unused".into(),
                    sha256: "a".repeat(64),
                    uid: 0,
                },
            };
            validate_index(&owner, imported, &index).unwrap();
            index.epoch = epoch - 1;
            assert!(validate_index(&owner, imported, &index).is_err());
            index.epoch = epoch;
            index.path = owner
                .root
                .join(format!("other-output/compact-indexes/{epoch}/cache.index"));
            assert!(validate_index(&owner, imported, &index).is_err());
        }
    }

    #[test]
    fn retained_actual_four_index_headers_pass_full_plan_shape_with_original_metadata() {
        let bindings: Value =
            serde_json::from_str(include_str!("fixtures/imported235237-bindings.json")).unwrap();
        for row in bindings["profiles"].as_array().unwrap() {
            let epoch = row["epoch"].as_u64().unwrap();
            let p = profile(epoch).unwrap();
            let imported: ImportedCanonical =
                serde_json::from_value(row["imported_canonical"].clone()).unwrap();
            let owner = Owner {
                root: row["owner_root"].as_str().unwrap().into(),
                actors: vec![Actor {
                    unit: p.unit.into(),
                    invocation_id: p.iid.into(),
                    historical_provenance: None,
                }],
                preserved: serde_json::from_value(row["preserved"].clone()).unwrap(),
                imported_canonical: Some(imported),
            };
            let indexes: Vec<Index> = row["selected_indexes"]
                .as_array()
                .unwrap()
                .iter()
                .map(|i| Index {
                    path: i["path"].as_str().unwrap().into(),
                    identity: serde_json::from_value(i["identity"].clone()).unwrap(),
                    original_ctime: i["ctime"].as_i64().unwrap(),
                    original_ctime_nsec: i["ctime_nsec"].as_i64().unwrap(),
                    owner: 0,
                    epoch,
                    header_hex: i["header_hex"].as_str().unwrap().into(),
                    reproduction_url: i["reproduction_url"].as_str().unwrap().into(),
                    canonical_r2_receipt: Evidence {
                        path: format!(
                            "/home/ubuntu/.jetstreamer-private/r2-receipts/epoch-{epoch}.r2.json"
                        )
                        .into(),
                        sha256: if epoch == 235 {
                            "0d0d6c5ef1e5759e9ce13b1c6579154058db44dd0628672965f7eb2991eea277"
                        } else {
                            "191d4a0e07348da4496dc2c63843a52900063ec97397d2dc90aff6008226a8cb"
                        }
                        .into(),
                        uid: 0,
                    },
                })
                .collect();
            assert_eq!(indexes.len(), 2);
            let plan = Plan {
                schema: "jetstreamer-terminal-compact-index-retirement-plan-v1".into(),
                state: "/var/lib/jetstreamer/unused-test-state".into(),
                owners: vec![owner],
                indexes,
                source_review: Evidence {
                    path: "/var/lib/unused-review".into(),
                    sha256: "a".repeat(64),
                    uid: 0,
                },
                inert_recipes: vec![],
                typed_recipes: vec![],
                current_operation: None,
                local_index_retirement_authorized: true,
                archive_deletion_authorized: false,
                remote_mutations: false,
                r2_mutations: false,
            };
            // Pure validation only: no host actor, /proc or filesystem operation.
            validate_plan(&plan).unwrap();
        }
    }
}
