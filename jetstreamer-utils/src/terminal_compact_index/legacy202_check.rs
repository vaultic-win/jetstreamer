// Exact legacy202 diagnostic upgrade. This profile can never retire a file.
use super::*;
pub(super) const UNIT: &str = "horizon-202-index949-check-only-v1.service";
const SCHEMA: &str = "horizon-legacy202-exact-check-only-v1";
const ORIGINAL: &str =
    "/var/lib/jetstreamer/horizon202-two-index-retirement919-preparation-v1/plan.json";
const ORIGINAL_SHA: &str = "c65e7c06c1e012540819c2ae248141a009ccbab63e3db119cf61eadc8dd23462";
const OLD_STATE: &str = "/var/lib/jetstreamer/horizon202-two-index-retirement919-state-v1";
const STATE: &str = "/var/lib/jetstreamer/horizon202-index949-check-state-v1";
const OWNER: &str = "/home/ubuntu/.jetstreamer-private/qualification-202";
const PARENT: &str = "/home/ubuntu/.jetstreamer-private/qualification-202/diagnostic-output-selected-store8-v1/compact-indexes/202";
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Profile {
    schema: String,
    original_plan: Evidence,
}
fn selector(p: &Plan) -> Result<()> {
    let profile = p
        .legacy202_check
        .as_ref()
        .context("missing legacy202 check-only profile")?;
    ensure!(
        profile.schema == SCHEMA
            && profile.original_plan.path == Path::new(ORIGINAL)
            && profile.original_plan.sha256 == ORIGINAL_SHA
            && profile.original_plan.uid == 0,
        "legacy202 original plan reference differs"
    );
    ensure!(
        p.state == Path::new(STATE)
            && p.owners.len() == 1
            && p.indexes.len() == 2
            && p.owners[0].root == Path::new(OWNER)
            && p.owners[0].imported_canonical.is_none()
            && p.owners[0].actors.len() == 1
            && p.owners[0].actors[0].unit == "horizon-qualify-202-selected-store8-v1.service"
            && p.owners[0].actors[0].invocation_id == "8ae2897ece784e1988b7b4fb4ef3616e"
            && p.indexes.iter().all(|i| i.epoch == 202
                && i.owner == 0
                && i.path.parent() == Some(Path::new(PARENT)))
            && p.completed_check.is_none(),
        "legacy202 exact selection/owner/state differs"
    );
    let kinds: BTreeSet<_> = p.indexes.iter().map(name_parts).collect::<Result<_>>()?;
    ensure!(
        kinds.len() == 2
            && kinds
                .iter()
                .map(|(_, kind)| kind.as_str())
                .collect::<BTreeSet<_>>()
                == BTreeSet::from(["slot-to-cid", "cid-to-offset-and-size"]),
        "legacy202 exact pair required"
    );
    Ok(())
}
pub(super) fn validate_shape(p: &Plan) -> Result<()> {
    if p.legacy202_check.is_none() {
        return Ok(());
    }
    selector(p)?;
    ensure!(
        p.current_operation
            .as_ref()
            .is_some_and(|o| o.is_legacy202_check()),
        "legacy202 requires its exact current check-only operation"
    );
    ensure!(
        typed::has_complete_fixed_registry(p),
        "legacy202 requires the complete retained typed recipe registry"
    );
    Ok(())
}
pub(super) fn action_allowed(p: &Plan, check: bool) -> Result<()> {
    ensure!(
        p.legacy202_check.is_none() || check,
        "legacy202 profile grants check-only diagnostics, never retirement authority"
    );
    Ok(())
}
fn compare_original(p: &Plan, original: &Plan) -> Result<()> {
    ensure!(
        original.state == Path::new(OLD_STATE)
            && original.current_operation.is_none()
            && original.legacy202_check.is_none()
            && original.completed_check.is_none()
            && original.typed_recipes.is_empty(),
        "legacy202 original plan phase differs"
    );
    ensure!(
        p.schema == original.schema
            && p.local_index_retirement_authorized == original.local_index_retirement_authorized
            && p.archive_deletion_authorized == original.archive_deletion_authorized
            && p.remote_mutations == original.remote_mutations
            && p.r2_mutations == original.r2_mutations
            && serde_json::to_value(&p.owners)? == serde_json::to_value(&original.owners)?
            && serde_json::to_value(&p.indexes)? == serde_json::to_value(&original.indexes)?
            && serde_json::to_value(&p.source_review)?
                == serde_json::to_value(&original.source_review)?
            && serde_json::to_value(&p.inert_recipes)?
                == serde_json::to_value(&original.inert_recipes)?,
        "legacy202 original indexes/archives/actors/review/inert recipes changed"
    );
    Ok(())
}
pub(super) fn authenticate_original(p: &Plan) -> Result<()> {
    let Some(profile) = &p.legacy202_check else {
        return Ok(());
    };
    selector(p)?;
    let original: Plan = serde_json::from_slice(&evidence(&profile.original_plan)?)?;
    compare_original(p, &original)?;
    let old = fs::symlink_metadata(OLD_STATE)?;
    ensure!(
        old.is_dir()
            && old.uid() == 0
            && old.gid() == 0
            && old.mode() & 0o7777 == 0o700
            && Path::new(OLD_STATE).canonicalize()? == Path::new(OLD_STATE),
        "legacy202 original state custody differs"
    );
    for name in [
        "intent.json",
        "completion.json",
        "index-0.quarantine",
        "index-1.quarantine",
        "file-0.intent.json",
        "file-0.closure.json",
        "file-1.intent.json",
        "file-1.closure.json",
    ] {
        ensure!(
            absent(&Path::new(OLD_STATE).join(name))?,
            "legacy202 prior operation has mutation state; preserve/reconcile it"
        );
    }
    Ok(())
}
pub(super) fn same_parent(p: &Plan, index: &Index) -> bool {
    p.legacy202_check.is_some() && index.epoch == 202 && index.owner == 0
}
pub(super) fn metadata_paths(p: &Plan) -> Vec<&'static Path> {
    if p.legacy202_check.is_some() {
        vec![Path::new(ORIGINAL), Path::new(OLD_STATE)]
    } else {
        Vec::new()
    }
}
pub(super) fn metadata_reference(bytes: &[u8], p: &Plan) -> bool {
    metadata_paths(p)
        .into_iter()
        .any(|path| path_reference(bytes, path.as_os_str().as_bytes()))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn original() -> Plan {
        serde_json::from_slice(include_bytes!("fixtures/legacy202-original919-plan.json")).unwrap()
    }
    fn plan() -> Plan {
        let mut p = original();
        p.state = STATE.into();
        p.legacy202_check = Some(Profile {
            schema: SCHEMA.into(),
            original_plan: Evidence {
                path: ORIGINAL.into(),
                sha256: ORIGINAL_SHA.into(),
                uid: 0,
            },
        });
        p
    }
    #[test]
    fn legacy202_exact_original_pair_is_a_read_only_diagnostic_selector() {
        assert_eq!(
            hash(include_bytes!("fixtures/legacy202-original919-plan.json")),
            ORIGINAL_SHA
        );
        let p = plan();
        selector(&p).unwrap();
        compare_original(&p, &original()).unwrap();
        assert!(action_allowed(&p, true).is_ok());
    }
    #[test]
    fn legacy202_diagnostic_cannot_gain_retirement_authority() {
        assert!(action_allowed(&plan(), false).is_err());
        let mut p = plan();
        p.legacy202_check = None;
        assert!(action_allowed(&p, false).is_ok());
    }
    #[test]
    fn legacy202_reference_schema_path_digest_and_uid_are_pinned() {
        for field in ["schema", "path", "digest", "uid"] {
            let mut p = plan();
            let profile = p.legacy202_check.as_mut().unwrap();
            match field {
                "schema" => profile.schema.push('x'),
                "path" => {
                    profile.original_plan.path =
                        PathBuf::from("/var/lib/jetstreamer/substitute.json")
                }
                "digest" => profile.original_plan.sha256 = "a".repeat(64),
                _ => profile.original_plan.uid = 1000,
            };
            assert!(selector(&p).is_err(), "{field}");
        }
    }
    #[test]
    fn legacy202_selector_rejects_mixed_or_incomplete_owners_and_epochs() {
        let mut p = plan();
        p.indexes.pop();
        assert!(selector(&p).is_err());
        let mut p = plan();
        p.indexes[1].epoch = 203;
        assert!(selector(&p).is_err());
        let mut p = plan();
        p.owners[0].root = Path::new(PRIVATE).join("qualification-203");
        assert!(selector(&p).is_err());
        let mut p = plan();
        p.owners[0].actors[0].invocation_id = "a".repeat(32);
        assert!(selector(&p).is_err());
        let mut p = plan();
        p.state = OLD_STATE.into();
        assert!(selector(&p).is_err());
    }
    #[test]
    fn legacy202_requires_a_current_operation_before_any_native_allowance() {
        let p = plan();
        assert!(validate_shape(&p).is_err());
    }
    #[test]
    fn legacy202_original_index_archive_and_actor_identity_cannot_be_rewritten() {
        let old = original();
        let mut p = plan();
        p.indexes[0].identity.inode += 1;
        assert!(compare_original(&p, &old).is_err());
        let mut p = plan();
        p.owners[0].preserved[0].ctime += 1;
        assert!(compare_original(&p, &old).is_err());
        let mut p = plan();
        p.owners[0].actors[0].invocation_id = "b".repeat(32);
        assert!(compare_original(&p, &old).is_err());
        let mut p = plan();
        p.inert_recipes.clear();
        assert!(compare_original(&p, &old).is_err());
    }
    #[test]
    fn legacy202_quarantine_stays_on_exact_source_parent_and_has_operation_digest() {
        let p = plan();
        let q = quarantine_path(&p, &p.indexes[0], 0, &"a".repeat(64)).unwrap();
        assert_eq!(q.parent(), p.indexes[0].path.parent());
        assert!(
            q.file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .contains(&"a".repeat(64))
        );
        assert!(quarantine_path(&p, &p.indexes[0], 0, "bad").is_err());
    }
    #[test]
    fn legacy202_original_plan_and_old_state_remain_indirect_reader_inputs() {
        let p = plan();
        assert!(metadata_reference(
            format!("runner --plan {ORIGINAL}\n").as_bytes(),
            &p
        ));
        assert!(metadata_reference(
            format!("{OLD_STATE}/intent.json").as_bytes(),
            &p
        ));
        assert!(!metadata_reference(
            format!("{ORIGINAL}-unrelated").as_bytes(),
            &p
        ));
        assert!(!metadata_reference(
            format!("{OLD_STATE}-unrelated").as_bytes(),
            &p
        ));
        let mut ordinary = plan();
        ordinary.legacy202_check = None;
        assert!(!metadata_reference(ORIGINAL.as_bytes(), &ordinary));
    }
}
