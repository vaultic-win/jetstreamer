//! Two independently bound exact-file retirements. No recursive deletion.
use super::*;
fn operation(p: &Spec) -> Value {
    json!({"profile":PROFILE,"mapping":p.mapping,"custody":p.custody,"restoration":p.restoration})
}
fn directory(p: &Spec) -> Result<PathBuf> {
    Ok(Path::new(STATE).join(format!(
        "retirement-{}",
        hex_lower(&Sha256::digest(serde_json::to_vec(&operation(p))?))
    )))
}
fn label(original: bool) -> &'static str {
    if original {
        "original203"
    } else {
        "restored203"
    }
}
fn expected_target(original: bool, r: &Value) -> Result<(PathBuf, Value)> {
    if original {
        Ok((SOURCE.into(), original_id()))
    } else {
        let id = r["restored_identity"].clone();
        ensure!(
            id["length"] == LENGTH
                && id["uid"] == 0
                && id["gid"] == 0
                && id["mode"] == 0o400
                && id["nlink"] == 1
                && id["inode"].as_u64().is_some_and(|n| n > 0),
            "holding203 restored identity is not a private full file"
        );
        Ok((restored(), id))
    }
}
fn original_completion(p: &Spec, dir: &Path) -> Result<Value> {
    let b = p
        .original_retirement
        .as_ref()
        .context("holding203 original retirement proof absent")?;
    ensure!(
        b.path == dir.join("original203.deleted.json"),
        "holding203 original retirement path differs"
    );
    ensure!(
        journal::binding(&b.path)? == bound_value(b),
        "holding203 original completion was replaced"
    );
    let value = journal::read_record(&b.path)?;
    let deletion = dir.join("original203.unlink.json");
    let intent = journal::read_record(&deletion)?;
    ensure!(
        intent["schema"] == "jetstreamer-foundation203-unlink-intent-v1"
            && intent["operation"] == operation(p)
            && intent["target"] == "original203"
            && intent["identity"] == original_id()
            && intent["sha256"] == SHA
            && intent["length"] == LENGTH,
        "holding203 original deletion proof is foreign"
    );
    ensure!(
        value["schema"] == "jetstreamer-foundation203-retired-v1"
            && value["operation"] == operation(p)
            && value["target"] == "original203"
            && value["deletion_intent"] == journal::binding(&deletion)?
            && value["selected_logical_bytes"] == LENGTH
            && value["remote_mutations"] == false
            && journal::absence(Path::new(SOURCE))?,
        "holding203 original retirement not complete"
    );
    Ok(value)
}
fn valid_intent(
    v: &Value,
    p: &Spec,
    source: &Path,
    quarantine: &Path,
    expected: &Value,
    original: bool,
) -> Result<()> {
    ensure!(
        v["schema"] == "jetstreamer-foundation203-retirement-intent-v1"
            && v["operation"] == operation(p)
            && v["target"] == label(original)
            && v["source"] == source.to_string_lossy().as_ref()
            && v["quarantine"] == quarantine.to_string_lossy().as_ref()
            && v["identity"] == *expected
            && v["sha256"] == SHA
            && v["length"] == LENGTH
            && v["remote_mutations_authorized"] == false,
        "holding203 conflicting retirement intent"
    );
    Ok(())
}
pub(super) async fn run(client: &Client, p: &Spec, spec: &Bound, action: &str) -> Result<()> {
    let c = record(p.custody.as_ref().context("holding203 custody absent")?)?;
    custody(&c, p)?;
    let r = record(
        p.restoration
            .as_ref()
            .context("holding203 restoration absent")?,
    )?;
    restoration(&r, p, &c)?;
    let original = action == "holding-foundation203-retire-original";
    let dir = directory(p)?;
    if journal::absence(&dir)? {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().mode(0o700).create(&dir)?;
        File::open(STATE)?.sync_all()?;
    }
    private(&dir)?;
    if !original {
        original_completion(p, &dir)?;
    }
    let (source, expected) = expected_target(original, &r)?;
    let quarantine = dir.join(format!("{}.quarantine", label(original)));
    let intent = dir.join(format!("{}.intent.json", label(original)));
    let deletion = dir.join(format!("{}.unlink.json", label(original)));
    let complete = dir.join(format!("{}.deleted.json", label(original)));
    let source_exists = !journal::absence(&source)?;
    let quarantine_exists = !journal::absence(&quarantine)?;
    if journal::absence(&intent)? {
        ensure!(
            source_exists
                && !quarantine_exists
                && journal::absence(&deletion)?
                && journal::absence(&complete)?,
            "holding203 missing target without durable intent"
        );
        hash_at(&source, &expected, original)?;
        // A historical restoration receipt alone is insufficient: the entire
        // full restored copy must still exist when original removal starts.
        if original {
            let (_, id) = expected_target(false, &r)?;
            hash_at(&restored(), &id, false)?;
        }
        let allocated = fs::symlink_metadata(&source)?
            .blocks()
            .checked_mul(512)
            .context("holding203 allocated length overflow")?;
        let closure = gates(p, action, spec, false)?;
        remote(client, &c).await?;
        write(
            &intent,
            &json!({"schema":"jetstreamer-foundation203-retirement-intent-v1","operation":operation(p),"initial_spec":spec,
            "target":label(original),"source":source,"quarantine":quarantine,"identity":expected,"sha256":SHA,"length":LENGTH,
            "allocated_bytes_at_intent":allocated,"remote_mutations_authorized":false,"closure":closure}),
        )?;
    }
    valid_intent(
        &journal::read_record(&intent)?,
        p,
        &source,
        &quarantine,
        &expected,
        original,
    )?;
    // Reentry into completed or interrupted phases revalidates the exact
    // remote custody and current closure before trusting any local absence.
    gates(p, action, spec, false)?;
    remote(client, &c).await?;
    let state = journal::resume_state(
        source_exists,
        quarantine_exists,
        !journal::absence(&deletion)?,
        !journal::absence(&complete)?,
    )?;
    if state == journal::ResumeState::Complete {
        let v = journal::read_record(&complete)?;
        ensure!(
            v["operation"] == operation(p)
                && v["target"] == label(original)
                && v["deletion_intent"] == journal::binding(&deletion)?,
            "holding203 completion conflict"
        );
        println!("{}", complete.display());
        return Ok(());
    }
    let anchor = journal::pinned_directory(&dir, Some(0), true)?;
    if state == journal::ResumeState::Move {
        hash_at(&source, &expected, original)?;
        no_references(&source)?;
        gates(p, action, spec, false)?;
        if original {
            let (_, id) = expected_target(false, &r)?;
            hash_at(&restored(), &id, false)?;
        }
        journal::rename_pinned(&source, &anchor, Path::new(quarantine.file_name().unwrap()))?;
    }
    if !journal::absence(&quarantine)? {
        hash_at(&quarantine, &expected, false)?;
        let refs = no_references(&quarantine)?;
        let closure = gates(p, action, spec, false)?;
        remote(client, &c).await?;
        if original {
            let (_, id) = expected_target(false, &r)?;
            hash_at(&restored(), &id, false)?;
        }
        let proposed = json!({"schema":"jetstreamer-foundation203-unlink-intent-v1","operation":operation(p),"target":label(original),
            "identity":expected,"sha256":SHA,"length":LENGTH,"initial_intent":journal::binding(&intent)?,"references":refs,"closure":closure});
        if journal::absence(&deletion)? {
            write(&deletion, &proposed)?;
        } else {
            let old = journal::read_record(&deletion)?;
            for k in [
                "schema",
                "operation",
                "target",
                "identity",
                "sha256",
                "length",
                "initial_intent",
            ] {
                ensure!(
                    old[k] == proposed[k],
                    "holding203 unlink intent conflict:{k}"
                );
            }
        }
        ensure!(
            journal::absence(&source)?,
            "holding203 original name reappeared"
        );
        no_references(&quarantine)?;
        gates(p, action, spec, false)?;
        identity_at(&quarantine, &expected, false)?;
        journal::unlink_pinned(
            &anchor,
            Path::new(quarantine.file_name().unwrap()),
            &expected,
        )?;
    } else {
        ensure!(
            state == journal::ResumeState::Unlinked,
            "holding203 target absent without durable unlink intent"
        );
        let v = journal::read_record(&deletion)?;
        ensure!(
            v["schema"] == "jetstreamer-foundation203-unlink-intent-v1"
                && v["operation"] == operation(p)
                && v["identity"] == expected
                && v["target"] == label(original)
                && v["sha256"] == SHA
                && v["length"] == LENGTH
                && v["initial_intent"] == journal::binding(&intent)?,
            "holding203 interrupted unlink proof differs"
        );
    }
    ensure!(
        journal::absence(&source)? && journal::absence(&quarantine)?,
        "holding203 target reappeared"
    );
    let b = write(
        &complete,
        &json!({"schema":"jetstreamer-foundation203-retired-v1","operation":operation(p),"target":label(original),
        "deletion_intent":journal::binding(&deletion)?,"selected_logical_bytes":LENGTH,"remote_mutations":false,
        "canonical_and_failure_artifacts_preserved":true,"net_reclaim_credit_claimed":false,
        "allocated_bytes_at_intent":journal::read_record(&intent)?["allocated_bytes_at_intent"],"available_bytes_after":available(Path::new(STATE))?}),
    )?;
    println!("{}", b.path.display());
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn restored_target_never_selects_the_original_or_an_arbitrary_manifest_path() {
        let r = json!({"restored_identity":{"device":66305,"inode":1,"length":LENGTH,"uid":0,"gid":0,"mode":0o400,"nlink":1}});
        let (path, _) = expected_target(false, &r).unwrap();
        assert_eq!(path, restored());
        assert_ne!(path, Path::new(SOURCE));
        for (key, value) in [
            ("length", json!(1)),
            ("uid", json!(1000)),
            ("mode", json!(0o600)),
            ("nlink", json!(2)),
        ] {
            let mut bad = r.clone();
            bad["restored_identity"][key] = value;
            assert!(expected_target(false, &bad).is_err(), "{key}");
        }
        assert_eq!(expected_target(true, &r).unwrap().1, original_id());
    }
    #[test]
    fn replaying_completed_retirement_requires_durable_unlink_intent_and_absence() {
        assert!(journal::resume_state(false, false, false, true).is_err());
        assert!(journal::resume_state(true, false, true, true).is_err());
        assert_eq!(
            journal::resume_state(false, false, true, false).unwrap(),
            journal::ResumeState::Unlinked
        );
        assert_eq!(
            journal::resume_state(false, true, false, false).unwrap(),
            journal::ResumeState::Quarantined
        );
    }
    #[test]
    fn intent_reentry_cannot_change_source_identity_custody_or_selected_copy() {
        let bound = Bound {
            path: "/sealed/custody.json".into(),
            sha256: "a".repeat(64),
        };
        let mut p = Spec {
            schema: "jetstreamer-foundation203-plan-v1".into(),
            mapping: Bound {
                path: host::MAPPING.into(),
                sha256: host::MAPPING_SHA.into(),
            },
            resource_basis: json!({}),
            admissions_must_be_serialized_until_phase_complete: true,
            custody: Some(bound.clone()),
            restoration: Some(bound),
            original_retirement: None,
        };
        let source = Path::new(SOURCE);
        let quarantine = Path::new("/private/original203.quarantine");
        let intent = json!({"schema":"jetstreamer-foundation203-retirement-intent-v1","operation":operation(&p),"target":"original203","source":source,"quarantine":quarantine,
            "identity":original_id(),"sha256":SHA,"length":LENGTH,"remote_mutations_authorized":false});
        valid_intent(&intent, &p, source, quarantine, &original_id(), true).unwrap();
        for (path, value) in [
            ("/source", json!("/other/archive.jet")),
            ("/target", json!("restored203")),
            ("/identity/inode", json!(999)),
            ("/length", json!(1)),
            ("/sha256", json!("f".repeat(64))),
            ("/remote_mutations_authorized", json!(true)),
        ] {
            let mut bad = intent.clone();
            *bad.pointer_mut(path).unwrap() = value;
            assert!(
                valid_intent(&bad, &p, source, quarantine, &original_id(), true).is_err(),
                "{path}"
            );
        }
        p.resource_basis = json!({"fresh_basis":true});
        valid_intent(&intent, &p, source, quarantine, &original_id(), true).unwrap();
        p.custody.as_mut().unwrap().sha256 = "b".repeat(64);
        assert!(valid_intent(&intent, &p, source, quarantine, &original_id(), true).is_err());
    }
}
