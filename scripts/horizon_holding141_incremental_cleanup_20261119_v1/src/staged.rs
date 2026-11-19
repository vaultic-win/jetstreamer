use super::*;
use evidence::properties;

fn missing_unit_is_nonlaunchable(
    unit: &str,
    p: &std::collections::BTreeMap<String, String>,
) -> Result<()> {
    for (key, want) in [
        ("Id", unit),
        ("LoadState", "not-found"),
        ("ActiveState", "inactive"),
        ("SubState", "dead"),
        ("MainPID", "0"),
        ("Triggers", ""),
        ("TriggeredBy", ""),
    ] {
        ensure!(
            p.get(key).map(String::as_str) == Some(want),
            "dangling alias may still launch: {key}"
        );
    }
    for key in [
        "ExecStart",
        "ExecStartPre",
        "ExecStartPost",
        "ExecCondition",
        "ExecStop",
        "ExecStopPost",
        "ExecReload",
    ] {
        ensure!(
            p.get(key).is_none_or(String::is_empty),
            "missing unit retains cached command: {key}"
        );
    }
    Ok(())
}
pub(super) fn staged_references(
    roots: &[&Path],
    target: &Path,
    missing: &mut Vec<Value>,
) -> Result<Vec<String>> {
    let mut queue: Vec<_> = roots.iter().map(|p| (p.to_path_buf(), 0u32)).collect();
    let mut seen = BTreeSet::new();
    let mut refs = Vec::new();
    let mut entries = 0;
    while let Some((path, depth)) = queue.pop() {
        entries += 1;
        ensure!(
            entries <= 65536 && depth <= 32,
            "unit census exceeded bound"
        );
        let metadata = match fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e.into()),
            Ok(m) => m,
        };
        let canonical = match path.canonicalize() {
            Ok(p) => p,
            Err(e)
                if e.kind() == std::io::ErrorKind::NotFound
                    && metadata.file_type().is_symlink() =>
            {
                let link = fs::read_link(&path)?;
                ensure!(
                    !process_references::encoded_reference(
                        link.as_os_str().as_bytes(),
                        target.as_os_str().as_bytes(),
                        true
                    ) && !relative_cache_reference(link.as_os_str().as_bytes(), target),
                    "dangling alias targets dev cache"
                );
                let name = path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .context("nonUTF8 dangling unit")?;
                ensure!(
                    name.ends_with(".service")
                        && !name.starts_with('-')
                        && name.len() <= 255
                        && name
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"-_.@\\".contains(&b)),
                    "unsupported dangling alias"
                );
                let names = "Id,LoadState,ActiveState,SubState,MainPID,ExecStart,ExecStartPre,ExecStartPost,ExecCondition,ExecStop,ExecStopPost,ExecReload,Triggers,TriggeredBy";
                let before = properties(name, names)?;
                missing_unit_is_nonlaunchable(name, &before)?;
                let after = fs::symlink_metadata(&path)?;
                ensure!(
                    fs::read_link(&path)? == link
                        && metadata.dev() == after.dev()
                        && metadata.ino() == after.ino()
                        && metadata.ctime() == after.ctime()
                        && metadata.ctime_nsec() == after.ctime_nsec()
                        && properties(name, names)? == before,
                    "dangling alias/manager changed during check"
                );
                missing.push(json!({"alias":path,"missing_target":link,"manager_state":before,"before_after_stable":true}));
                continue;
            }
            Err(e) => {
                return Err(e).with_context(|| format!("resolve staged unit {}", path.display()));
            }
        };
        if canonical == Path::new("/dev/null") || !seen.insert(canonical.clone()) {
            continue;
        }
        let m = fs::metadata(&canonical)?;
        if m.is_dir() {
            for e in fs::read_dir(&canonical)? {
                queue.push((e?.path(), depth + 1));
            }
        } else {
            ensure!(
                m.is_file() && m.len() <= 1 << 20,
                "unreadable/nonregular staged unit input"
            );
            let bytes = fs::read(&canonical)?;
            ensure!(bytes.len() <= 1 << 20, "unit grew during read");
            if process_references::encoded_reference(&bytes, target.as_os_str().as_bytes(), true)
                || relative_cache_reference(&bytes, target)
            {
                refs.push(canonical.display().to_string());
            }
        }
    }
    refs.sort();
    Ok(refs)
}
