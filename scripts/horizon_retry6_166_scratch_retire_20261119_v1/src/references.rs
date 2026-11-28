//! Fresh, bounded consumer exclusion scoped to the old retry6 destination.
use super::*;
use std::os::unix::ffi::OsStrExt;

pub(super) const DEFINITION_ROOTS: &[&str] = &[
    "/etc/systemd/system",
    "/run/systemd/system",
    "/run/systemd/transient",
    "/usr/lib/systemd/system",
    "/run/systemd/generator",
    "/run/systemd/generator.early",
    "/run/systemd/generator.late",
    "/home/sol/.config/systemd/user",
    "/etc/crontab",
    "/etc/cron.d",
    "/var/spool/cron/crontabs",
    "/etc/cron.hourly",
    "/etc/cron.daily",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
];
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AllowedDefinition {
    unit: String,
    binding: Bound,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DependencyReview {
    schema: String,
    owner: String,
    epoch: u64,
    destination: PathBuf,
    run: PathBuf,
    scratch: PathBuf,
    no_resume_review: Bound,
    recorded_unix_seconds: u64,
    reviewed_definition_roots: Vec<String>,
    original_terminal_chain_reviewed: bool,
    no_active_or_staged_consumer_requires_scratch_contents: bool,
    compiled_and_indirect_readers_reviewed: bool,
    no_unreviewed_continuation_or_export_evidence: bool,
    all_future_reopening_excluded_during_transition: bool,
    all_existing_resource_promises_retained: bool,
    evidence: Vec<Bound>,
    allowed_terminal_definitions: Vec<AllowedDefinition>,
}
fn validate_review(p: &Plan, r: &DependencyReview, at: u64) -> Result<()> {
    ensure!(
        r.schema == "horizon-retry6-166-scratch-dependency-review-v1"
            && r.owner == "/root"
            && r.epoch == 166
            && r.destination == Path::new(DESTINATION)
            && r.run == Path::new(RUN)
            && r.scratch == Path::new(SCRATCH)
            && r.no_resume_review == p.no_resume_review
            && r.recorded_unix_seconds <= at
            && at - r.recorded_unix_seconds <= 1800
            && r.reviewed_definition_roots == DEFINITION_ROOTS
            && r.original_terminal_chain_reviewed
            && r.no_active_or_staged_consumer_requires_scratch_contents
            && r.compiled_and_indirect_readers_reviewed
            && r.no_unreviewed_continuation_or_export_evidence
            && r.all_future_reopening_excluded_during_transition
            && r.all_existing_resource_promises_retained,
        "fresh exact retry6 dependency closure required"
    );
    ensure!(
        !r.evidence.is_empty()
            && r.evidence.len() <= 128
            && r.allowed_terminal_definitions.len() <= 64,
        "dependency evidence missing or excessive"
    );
    Ok(())
}
pub(super) fn dependency(p: &Plan) -> Result<DependencyReview> {
    let r: DependencyReview = serde_json::from_slice(&bound(&p.dependency_review, MAX_JSON)?)?;
    validate_review(p, &r, now()?)?;
    for b in &r.evidence {
        ensure!(
            !b.path.starts_with(DESTINATION) && b.path != p.dependency_review.path,
            "dependency proof must remain outside selected destination"
        );
        bound(b, MAX_JSON)?;
    }
    let mut paths = BTreeSet::new();
    for a in &r.allowed_terminal_definitions {
        let file_is_unit =
            a.binding.path.file_name().and_then(|n| n.to_str()) == Some(a.unit.as_str());
        let dropin = format!("{}.d", a.unit);
        let file_is_dropin = a
            .binding
            .path
            .parent()
            .and_then(Path::file_name)
            .and_then(|n| n.to_str())
            == Some(dropin.as_str());
        ensure!(
            !a.unit.contains('/')
                && !a.unit.is_empty()
                && (file_is_unit || file_is_dropin)
                && paths.insert(a.binding.path.clone()),
            "terminal definition not tied to its exact owner"
        );
        bound(&a.binding, 16 << 20)?;
        unit_closed(&a.unit)?;
    }
    Ok(r)
}
fn decode_mount_path(raw: &[u8]) -> Result<PathBuf> {
    let mut decoded = Vec::new();
    let mut at = 0;
    while at < raw.len() {
        if raw[at] == b'\\' {
            ensure!(
                at + 3 < raw.len()
                    && raw[at + 1..=at + 3]
                        .iter()
                        .all(|b| (b'0'..=b'7').contains(b)),
                "invalid escaped mount path"
            );
            let value = (raw[at + 1] - b'0') as u16 * 64
                + (raw[at + 2] - b'0') as u16 * 8
                + (raw[at + 3] - b'0') as u16;
            ensure!(value > 0 && value <= 255, "invalid mount path byte");
            decoded.push(value as u8);
            at += 4;
        } else {
            decoded.push(raw[at]);
            at += 1;
        }
    }
    let path = Path::new(std::ffi::OsStr::from_bytes(&decoded));
    ensure!(path.is_absolute(), "nonabsolute mount path");
    Ok(path.to_owned())
}
pub(super) fn reject_mounts(bytes: &[u8], target: &Path) -> Result<()> {
    ensure!(bytes.len() <= 4 << 20, "mount census exceeded bound");
    for line in bytes.split(|b| *b == b'\n').filter(|line| !line.is_empty()) {
        let fields: Vec<_> = line
            .split(|b| *b == b' ')
            .filter(|s| !s.is_empty())
            .collect();
        ensure!(
            fields.len() >= 10 && fields.contains(&b"-".as_slice()),
            "invalid mount census row"
        );
        for field in [fields[3], fields[4]] {
            // Root catches an external bind alias of selected scratch as well
            // as mountpoints placed at/below scratch, including same-device binds.
            let path = decode_mount_path(field)?;
            ensure!(
                !path.starts_with(target),
                "scratch is mounted, contains a mount, or has a bind alias"
            );
        }
    }
    Ok(())
}
pub(super) fn mounts() -> Result<Value> {
    let mut out = BTreeMap::new();
    for path in ["/proc/self/mountinfo", "/proc/1/mountinfo"] {
        let mut bytes = Vec::new();
        File::open(path)?
            .take((4 << 20) + 1)
            .read_to_end(&mut bytes)?;
        reject_mounts(&bytes, Path::new(SCRATCH))?;
        out.insert(path, sha(&bytes));
    }
    Ok(serde_json::to_value(out)?)
}
fn mentions_old_destination(bytes: &[u8]) -> bool {
    [DESTINATION, RUN, SCRATCH]
        .iter()
        .any(|scope| process_references::encoded_reference(bytes, scope.as_bytes(), true))
}
fn masked_unit(path: &Path) -> Result<bool> {
    let m = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e.into()),
    };
    let unit = path.file_name().and_then(|s| s.to_str()).is_some_and(|s| {
        [
            ".service",
            ".timer",
            ".socket",
            ".path",
            ".target",
            ".slice",
            ".scope",
            ".mount",
            ".automount",
            ".swap",
        ]
        .iter()
        .any(|suffix| s.ends_with(suffix))
    });
    Ok(unit
        && m.uid() == 0
        && m.file_type().is_symlink()
        && fs::read_link(path)? == Path::new("/dev/null"))
}
fn staged_walk(
    path: &Path,
    depth: usize,
    visited: &mut BTreeSet<PathBuf>,
    count: &mut u64,
    total: &mut u64,
    allowed: &[AllowedDefinition],
) -> Result<()> {
    ensure!(
        depth <= 24 && *count < 100_000 && *total <= 512 << 20,
        "staged definition budget exceeded"
    );
    if masked_unit(path)? {
        *count += 1;
        return Ok(());
    }
    let m = match fs::metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            ensure!(
                matches!(fs::symlink_metadata(path),Err(e) if e.kind() == std::io::ErrorKind::NotFound),
                "dangling staged definition must be independently resolved"
            );
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    };
    let canonical = path.canonicalize()?;
    if !visited.insert(canonical.clone()) {
        return Ok(());
    }
    *count += 1;
    if m.is_dir() {
        for entry in fs::read_dir(path)? {
            staged_walk(&entry?.path(), depth + 1, visited, count, total, allowed)?;
        }
    } else if m.is_file() {
        ensure!(
            [0, UID].contains(&m.uid()) && m.len() <= 16 << 20,
            "unsafe staged definition"
        );
        let bytes = raw(&canonical, 16 << 20, m.uid())?;
        *total = total
            .checked_add(bytes.len() as u64)
            .context("staged byte overflow")?;
        ensure!(
            *total <= 512 << 20,
            "staged definition byte budget exceeded"
        );
        if mentions_old_destination(&bytes) {
            ensure!(
                allowed
                    .iter()
                    .any(|a| a.binding.path == canonical && a.binding.sha256 == sha(&bytes)),
                "unreviewed staged definition references old retry6: {}",
                path.display()
            );
        }
    } else {
        anyhow::bail!("unexpected staged definition type: {}", path.display());
    }
    Ok(())
}
pub(super) fn staged(review: &DependencyReview) -> Result<Value> {
    let mut visited = BTreeSet::new();
    let (mut count, mut bytes) = (0, 0);
    for root in DEFINITION_ROOTS {
        staged_walk(
            Path::new(root),
            0,
            &mut visited,
            &mut count,
            &mut bytes,
            &review.allowed_terminal_definitions,
        )?;
    }
    for allowed in &review.allowed_terminal_definitions {
        bound(&allowed.binding, 16 << 20)?;
        unit_closed(&allowed.unit)?;
    }
    Ok(
        json!({"definitions":count,"bytes":bytes,"roots":DEFINITION_ROOTS,
        "allowed_terminal_definitions":review.allowed_terminal_definitions}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn nested_root_and_external_alias_mounts_fail_even_on_same_device() {
        for text in [
            "24 1 252:0 / /scratch rw - ext4 /dev/vda rw\n",
            "24 1 252:0 / /scratch/nested rw - ext4 /dev/vda rw\n",
            "24 1 252:0 /scratch/accounts /elsewhere rw - ext4 /dev/vda rw\n",
        ] {
            assert!(reject_mounts(text.as_bytes(), Path::new("/scratch")).is_err());
        }
        assert!(
            reject_mounts(
                b"24 1 252:0 / /scratch-peer rw - ext4 /dev/vda rw\n",
                Path::new("/scratch")
            )
            .is_ok()
        );
        assert!(
            reject_mounts(
                b"24 1 252:0 / /scratch\\040space/child rw - ext4 /dev/vda rw\n",
                Path::new("/scratch space")
            )
            .is_err()
        );
        assert!(reject_mounts(b"invalid mount", Path::new("/scratch")).is_err());
    }
    #[test]
    fn staged_target_requires_exact_reviewed_bytes_but_new_destinations_are_independent() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("old.service");
        let original = format!("ExecStart=node --destination={DESTINATION}\n");
        fs::write(&path, &original).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let scan = |allowed: &[AllowedDefinition]| {
            staged_walk(&path, 0, &mut BTreeSet::new(), &mut 0, &mut 0, allowed)
        };
        assert!(scan(&[]).is_err());
        let allowed = [AllowedDefinition {
            unit: "old.service".into(),
            binding: Bound {
                path: path.clone(),
                sha256: sha(original.as_bytes()),
            },
        }];
        assert!(scan(&allowed).is_ok());
        fs::write(&path, format!("{original}# changed\n")).unwrap();
        assert!(scan(&allowed).is_err());
        fs::write(
            &path,
            format!("ExecStart=node --destination={DESTINATION}-independent-retry8\n"),
        )
        .unwrap();
        assert!(scan(&[]).is_ok());
        assert!(!mentions_old_destination(
            b"epoch166 replacement-local3retry8 epoch167 replacement-local3retry7"
        ));
    }
    #[test]
    fn dependency_review_cannot_be_stale_or_substitute_another_no_resume_review() {
        let p = crate::tests::plan();
        let mut r: DependencyReview = serde_json::from_value(json!({
            "schema":"horizon-retry6-166-scratch-dependency-review-v1","owner":"/root","epoch":166,
            "destination":DESTINATION,"run":RUN,"scratch":SCRATCH,"no_resume_review":p.no_resume_review,
            "recorded_unix_seconds":100,"reviewed_definition_roots":DEFINITION_ROOTS,
            "original_terminal_chain_reviewed":true,"no_active_or_staged_consumer_requires_scratch_contents":true,
            "compiled_and_indirect_readers_reviewed":true,"no_unreviewed_continuation_or_export_evidence":true,
            "all_future_reopening_excluded_during_transition":true,"all_existing_resource_promises_retained":true,
            "evidence":[{"path":"/sealed/evidence.json","sha256":"a".repeat(64)}],"allowed_terminal_definitions":[]
        })).unwrap();
        assert!(validate_review(&p, &r, 1900).is_ok());
        assert!(validate_review(&p, &r, 1901).is_err());
        r.no_resume_review.sha256 = "b".repeat(64);
        assert!(validate_review(&p, &r, 101).is_err());
    }
}
