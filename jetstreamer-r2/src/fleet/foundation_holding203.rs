//! Exact old203 partial eligibility; capacity retains every typed live peer.
use super::*;
const ROOT: &str = "/home/ubuntu/.jetstreamer-private/root-prefix-resource-203-v1";
const UNIT: &str = "horizon-qualify-203-root-prefix-resource-v1.service";
const IID: &str = "92e367eb7cf944a1825fe5a20d9243ca";
fn original_command() -> &'static str {
    "{ path=/var/lib/jetstreamer/horizon-203-root-prefix-resource-v1/jetstreamer-epoch203-root-prefix-resource ; argv[]=/var/lib/jetstreamer/horizon-203-root-prefix-resource-v1/jetstreamer-epoch203-root-prefix-resource /var/lib/jetstreamer/horizon-203-root-prefix-resource-v1/resource-plan.json --plan-sha256 90c64b0a516ca23d7e93c6906b48c4182833128d68426d07f8addf880622d99d --self-sha256 dee8959e8436ebd856b5b8d7e18f06464377b26fadb3a7a9f09ab158f9fd4a4e"
}
const RESTORES: &str =
    "/home/ubuntu/.jetstreamer-private/r2-holding-foundation-node-01-v1/foundation203-restores";
const TOOL: &str = "jetstreamer-foundation203-partial-v1.service";
fn old_owner(v: &Value) -> Result<()> {
    ensure!(
        v["Id"] == UNIT
            && v["MainPID"] == "0"
            && v["NRestarts"] == "0"
            && matches!(v["ActiveState"].as_str(), Some("inactive" | "failed"))
            && matches!(v["SubState"].as_str(), Some("dead" | "failed"))
            && (v["InvocationID"] == IID || v["InvocationID"] == ""),
        "old203 owner live or replaced"
    );
    if v["LoadState"] == "loaded" {
        ensure!(
            v["Names"] == UNIT
                && v["DropInPaths"] == ""
                && v["Restart"] == "no"
                && v["Triggers"] == ""
                && v["TriggeredBy"] == ""
                && [
                    "ExecStartPre",
                    "ExecStartPost",
                    "ExecStop",
                    "ExecStopPost",
                    "ExecCondition"
                ]
                .iter()
                .all(|k| v[*k] == ""),
            "old203 owner can restart or has lifecycle hooks"
        );
        let cmd = v["ExecStart"].as_str().context("old203 command absent")?;
        ensure!(
            cmd.split_once(" ; ignore_errors=")
                .is_some_and(|(s, _)| s == original_command()),
            "old203 command changed"
        );
        if v["InvocationID"] == IID {
            ensure!(
                v["ActiveState"] == "failed"
                    && v["SubState"] == "failed"
                    && v["Result"] == "exit-code"
                    && v["ExecMainStatus"] == "1",
                "old203 historical failure was relabeled"
            );
        }
    } else {
        ensure!(
            v["LoadState"] == "not-found" && v["InvocationID"] == "",
            "old203 unit unavailable"
        );
    }
    Ok(())
}
fn current_owner() -> Result<Value> {
    let fields = "Id,Names,DropInPaths,LoadState,ActiveState,SubState,MainPID,InvocationID,NRestarts,Restart,Result,ExecMainStatus,Triggers,TriggeredBy,ExecStart,ExecStartPre,ExecStartPost,ExecStop,ExecStopPost,ExecCondition";
    let v = serde_json::to_value(singleton227_capture::properties(UNIT, fields)?)?;
    old_owner(&v)?;
    inactive_status::no_pending_owner_trigger(UNIT, false)?;
    let group = capped204205_work::empty_terminal_cgroup(UNIT)?;
    let mut guard = BTreeMap::new();
    for name in [
        "horizon-root-prefix-203-reserve-v2.timer",
        "horizon-root-prefix-203-reserve-v2.service",
    ] {
        let properties = singleton227_capture::properties(
            name,
            "Id,LoadState,ActiveState,SubState,MainPID,InvocationID,NRestarts",
        )?;
        ensure!(
            properties.get("Id").is_some_and(|v| v == name)
                && properties
                    .get("ActiveState")
                    .is_some_and(|v| matches!(v.as_str(), "inactive" | "failed"))
                && properties
                    .get("SubState")
                    .is_some_and(|v| matches!(v.as_str(), "dead" | "failed")),
            "old203 protective retry is not inactive"
        );
        guard.insert(name.to_owned(), properties);
    }
    Ok(json!({"producer":v,"cgroup":group,"guard_units":guard}))
}
fn claims(f: &Value) -> Result<()> {
    for row in f["active"]
        .as_array()
        .context("holding203 full active roster missing")?
    {
        ensure!(
            row["epoch"] != 203 && !serde_json::to_string(row)?.contains(ROOT),
            "old203 has a current consumer"
        );
    }
    ensure!(
        f["epochs"]
            .as_array()
            .context("holding203 complete repair ledger missing")?
            .iter()
            .any(|e| e["epoch"] == 203),
        "old203 vanished from repair/campaign ledger"
    );
    Ok(())
}
fn entry_stamp(path: &Path) -> Result<Value> {
    let m = fs::symlink_metadata(path)?;
    Ok(
        json!({"device":m.dev(),"inode":m.ino(),"length":m.len(),"mode":m.mode(),
        "uid":m.uid(),"gid":m.gid(),"links":m.nlink(),"ctime":[m.ctime(),m.ctime_nsec()],
        "mtime":[m.mtime(),m.mtime_nsec()],"target":if m.file_type().is_symlink() {Some(fs::read_link(path)?)} else {None}}),
    )
}
fn staged_text(path: &Path, text: &str) -> Result<()> {
    if text.contains(ROOT) || text.contains(RESTORES) {
        ensure!(
            (path == Path::new("/run/systemd/transient").join(UNIT)
                && !text.contains(RESTORES)
                && text
                    .contains("90c64b0a516ca23d7e93c6906b48c4182833128d68426d07f8addf880622d99d"))
                || (path == Path::new("/run/systemd/transient").join(TOOL)
                    && text.contains("holding-foundation203-")),
            "holding203 new or staged consumer references original root"
        );
    }
    Ok(())
}
fn dangling_target(path: &Path, target: &Path) -> Result<PathBuf> {
    let joined = if target.is_absolute() {
        target.to_path_buf()
    } else {
        path.parent()
            .context("holding203 staged link parent")?
            .join(target)
    };
    let mut normalized = PathBuf::new();
    for component in joined.components() {
        match component {
            std::path::Component::RootDir => normalized.push("/"),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            std::path::Component::Normal(name) => normalized.push(name),
            std::path::Component::Prefix(_) => bail!("holding203 foreign staged link prefix"),
        }
    }
    // Missing targets cannot be canonicalized. Lexical resolution still
    // exposes relative links into either selected root without following them.
    ensure!(
        !normalized.starts_with(ROOT)
            && !normalized.starts_with(RESTORES)
            && !target.to_string_lossy().contains(ROOT)
            && !target.to_string_lossy().contains(RESTORES),
        "holding203 dangling staged source reference"
    );
    Ok(normalized)
}
fn staged_entry(path: &Path, after_read: impl FnOnce() -> Result<()>) -> Result<Value> {
    let before = entry_stamp(path)?;
    let md = fs::symlink_metadata(path)?;
    ensure!(
        md.is_file() || md.file_type().is_symlink(),
        "holding203 staged special object"
    );
    let real = match path.canonicalize() {
        Ok(real) => Some(real),
        Err(error)
            if error.kind() == std::io::ErrorKind::NotFound && md.file_type().is_symlink() =>
        {
            None
        }
        Err(error) => return Err(error.into()),
    };
    let result = if let Some(real) = &real {
        if real == Path::new("/dev/null") {
            json!({"entry":before,"canonical":real,"masked":true})
        } else {
            ensure!(
                !fs::symlink_metadata(real)?.is_dir(),
                "holding203 staged directory alias"
            );
            let target_before = entry_stamp(real)?;
            let bytes = read_stable_bounded(real, 4 << 20, "holding203 staged metadata")?;
            let text = std::str::from_utf8(&bytes).context("holding203 nontext staged metadata")?;
            // Exceptions belong to the original transient entry, never an enabled alias.
            staged_text(path, text)?;
            let target_after = entry_stamp(real)?;
            ensure!(
                target_before == target_after,
                "holding203 staged target changed while read"
            );
            json!({"entry":before,"canonical":real,"target":target_after,"sha256":hex_lower(&Sha256::digest(bytes))})
        }
    } else {
        let target = fs::read_link(path)?;
        let normalized = dangling_target(path, &target)?;
        json!({"entry":before,"dangling":target,"lexical_target":normalized})
    };
    after_read()?;
    ensure!(
        entry_stamp(path)? == before,
        "holding203 staged entry changed while read"
    );
    match real {
        Some(real) => {
            ensure!(
                path.canonicalize()? == real,
                "holding203 staged resolution changed"
            );
            if real != Path::new("/dev/null") {
                ensure!(
                    entry_stamp(&real)? == result["target"],
                    "holding203 staged target substituted"
                );
            }
        }
        None => ensure!(
            matches!(path.canonicalize(), Err(e) if e.kind() == std::io::ErrorKind::NotFound),
            "holding203 dangling entry resolved during census"
        ),
    }
    Ok(result)
}
fn staged() -> Result<Value> {
    let mut found = BTreeMap::new();
    for root in [
        "/etc/systemd/system",
        "/run/systemd/system",
        "/run/systemd/transient",
        "/home/ubuntu/.jetstreamer-private/systemd-staging",
    ] {
        let mut pending = vec![(PathBuf::from(root), 0)];
        let mut count = 0usize;
        while let Some((dir, depth)) = pending.pop() {
            ensure!(depth <= 12, "holding203 staged metadata depth exceeded");
            for e in fs::read_dir(dir)? {
                let path = e?.path();
                count += 1;
                ensure!(count <= 20000, "holding203 staged census exceeded bound");
                let md = fs::symlink_metadata(&path)?;
                if md.is_dir() {
                    pending.push((path, depth + 1));
                    continue;
                }
                let entry = staged_entry(&path, || Ok(()))?;
                found.insert(path, entry);
            }
        }
    }
    Ok(serde_json::to_value(found)?)
}
pub(super) fn check(value: &Value, restoring: bool) -> Result<Value> {
    let fbound: BoundFile = serde_json::from_value(value["fleet"].clone())?;
    let obound: BoundFile = serde_json::from_value(value["observer"].clone())?;
    let f = assembly204_recovery::accepted_context(&fbound, &obound)?;
    claims(&f)?;
    let before = current_owner()?;
    let staged_before = staged()?;
    let references =
        jetstreamer_horizon_observe::process_references::scan(Path::new("/proc"), Path::new(ROOT))?;
    ensure!(
        references.references.is_empty(),
        "holding203 original root has live process references"
    );
    let jobs = ProcessCommand::new("/usr/bin/systemctl")
        .args([
            "list-jobs",
            "--no-legend",
            "--no-pager",
            "--plain",
            "--full",
        ])
        .output()?;
    ensure!(
        jobs.status.success() && jobs.stdout.len() <= 1 << 20,
        "holding203 jobs unavailable"
    );
    let jobs = inactive_status::queued_job_units(&jobs.stdout)?;
    ensure!(
        jobs.iter().all(|name| *name == TOOL
            || !name
                .split(|c: char| !c.is_ascii_digit())
                .any(|n| n == "203")),
        "holding203 replacement job queued"
    );
    let capacity = maintenance_capacity::check_foundation203(value, restoring)?;
    let after = current_owner()?;
    let staged_after = staged()?;
    let after_refs =
        jetstreamer_horizon_observe::process_references::scan(Path::new("/proc"), Path::new(ROOT))?;
    ensure!(
        before == after && staged_before == staged_after && after_refs.references.is_empty(),
        "holding203 closure changed during capacity check"
    );
    Ok(
        json!({"schema":"jetstreamer-foundation203-eligibility-v1","fleet":fbound,"observer":obound,
        "original_unit":before,"staged_metadata":staged_after,"references_before":references,"references_after":after_refs,
        "pending_jobs":jobs,"capacity":capacity,"new_resource_samples":0,"canonical_publication_authorized":false,
        "job_resume_authorized":false,"local_retirement_authorized":false}),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    #[test]
    fn foundation203_relative_dangling_links_cannot_hide_selected_roots() {
        let staged = Path::new("/home/ubuntu/.jetstreamer-private/systemd-staging/retry.service");
        for target in [
            "../root-prefix-resource-203-v1/missing.service",
            "../r2-holding-foundation-node-01-v1/foundation203-restores/missing.service",
            "../systemd-staging/../root-prefix-resource-203-v1/missing.service",
        ] {
            assert!(!target.contains(ROOT) && !target.contains(RESTORES));
            assert!(
                dangling_target(staged, Path::new(target)).is_err(),
                "{target}"
            );
        }
        // A traversal containing the literal root must also be rejected.
        assert!(
            dangling_target(
                staged,
                Path::new("../../../../home/ubuntu/.jetstreamer-private/root-prefix-resource-203-v1/missing.service")
            )
            .is_err()
        );
        assert_eq!(
            dangling_target(staged, Path::new("../unrelated/missing.service")).unwrap(),
            Path::new("/home/ubuntu/.jetstreamer-private/unrelated/missing.service")
        );
    }
    fn staged_fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("producer.service");
        let enabled = dir.path().join("enabled.service");
        fs::write(&target, "[Service]\nExecStart=/usr/bin/true\n").unwrap();
        symlink("producer.service", &enabled).unwrap();
        (dir, target, enabled)
    }
    #[test]
    fn foundation203_enabled_regular_target_and_mask_keep_exact_link_binding() {
        let (dir, target, enabled) = staged_fixture();
        let link = staged_entry(&enabled, || Ok(())).unwrap();
        assert_eq!(link["canonical"], target.to_string_lossy().as_ref());
        assert_eq!(link["entry"]["target"], "producer.service");
        assert_eq!(
            link["sha256"],
            staged_entry(&target, || Ok(())).unwrap()["sha256"]
        );
        let masked = dir.path().join("masked.service");
        symlink("/dev/null", &masked).unwrap();
        let mask = staged_entry(&masked, || Ok(())).unwrap();
        assert_eq!(mask["masked"], true);
        assert_eq!(mask["entry"]["target"], "/dev/null");
    }
    #[test]
    fn foundation203_staged_link_replacement_is_rejected_even_for_identical_bytes() {
        let (dir, _, enabled) = staged_fixture();
        fs::write(
            dir.path().join("replacement.service"),
            "[Service]\nExecStart=/usr/bin/true\n",
        )
        .unwrap();
        assert!(
            staged_entry(&enabled, || {
                fs::remove_file(&enabled)?;
                symlink("replacement.service", &enabled)?;
                Ok(())
            })
            .is_err()
        );
    }
    #[test]
    fn foundation203_staged_target_replacement_is_rejected_with_unchanged_link() {
        let (dir, target, enabled) = staged_fixture();
        assert!(
            staged_entry(&enabled, || {
                fs::rename(&target, dir.path().join("old.service"))?;
                fs::write(&target, "[Service]\nExecStart=/usr/bin/true\n")?;
                Ok(())
            })
            .is_err()
        );
    }
    #[test]
    fn foundation203_directory_aliases_and_dangling_selected_references_reject() {
        let (dir, _, _) = staged_fixture();
        let alias = dir.path().join("directory.service");
        symlink(dir.path(), &alias).unwrap();
        assert!(staged_entry(&alias, || Ok(())).is_err());
        for (i, root) in [ROOT, RESTORES].iter().enumerate() {
            let path = dir.path().join(format!("dangling-{i}.service"));
            symlink(format!("{root}/missing.service"), &path).unwrap();
            assert!(staged_entry(&path, || Ok(())).is_err());
        }
        let dangling = dir.path().join("harmless.service");
        symlink("missing.service", &dangling).unwrap();
        assert_eq!(
            staged_entry(&dangling, || Ok(())).unwrap()["dangling"],
            "missing.service"
        );
        assert!(
            staged_entry(&dangling, || {
                fs::write(dir.path().join("missing.service"), "[Unit]\n")?;
                Ok(())
            })
            .is_err()
        );
    }
    #[test]
    fn foundation203_enabled_alias_cannot_borrow_transient_exception() {
        let (dir, target, enabled) = staged_fixture();
        let body =
            format!("{ROOT}\n90c64b0a516ca23d7e93c6906b48c4182833128d68426d07f8addf880622d99d\n");
        staged_text(&Path::new("/run/systemd/transient").join(UNIT), &body).unwrap();
        fs::write(&target, &body).unwrap();
        assert!(staged_entry(&enabled, || Ok(())).is_err());
        let restored_body = format!("{RESTORES}\nholding-foundation203-restore\n");
        staged_text(
            &Path::new("/run/systemd/transient").join(TOOL),
            &restored_body,
        )
        .unwrap();
        fs::write(&target, restored_body).unwrap();
        assert!(staged_entry(&dir.path().join("enabled.service"), || Ok(())).is_err());
    }
    #[test]
    fn terminal_absence_never_accepts_a_live_replacement_or_missing_repair_ledger() {
        let dead = json!({"Id":UNIT,"MainPID":"0","NRestarts":"0","ActiveState":"inactive","SubState":"dead","InvocationID":"","LoadState":"not-found"});
        old_owner(&dead).unwrap();
        for (k, v) in [
            ("MainPID", json!("42")),
            ("InvocationID", json!("f".repeat(32))),
            ("NRestarts", json!("1")),
            ("LoadState", json!("error")),
        ] {
            let mut bad = dead.clone();
            bad[k] = v;
            assert!(old_owner(&bad).is_err(), "{k}");
        }
        let f = json!({"active":[],"epochs":[{"epoch":203,"state":"failed-needs-repair"}]});
        claims(&f).unwrap();
        let mut bad = f.clone();
        bad["active"] = json!([{"epoch":203}]);
        assert!(claims(&bad).is_err());
        let mut bad = f;
        bad["epochs"] = json!([]);
        assert!(claims(&bad).is_err());
    }
}
