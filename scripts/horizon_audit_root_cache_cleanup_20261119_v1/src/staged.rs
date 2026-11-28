use super::*;
use evidence::properties;

const NETWORK_ALIAS: &str =
    "/run/systemd/generator/multi-user.target.wants/systemd-networkd.service";
const NETWORK_FRAGMENT: &str = "/usr/lib/systemd/system/systemd-networkd.service";
const NETWORK_FRAGMENT_SHA: &str =
    "38ab8b44491353e11502b1eab3a8e67cd1845845397ae09db36e211a6d8bfce7";

fn network_alias_shape(
    path: &Path,
    link: &Path,
    p: &BTreeMap<String, String>,
    target: &Path,
) -> Result<()> {
    ensure!(
        path == Path::new(NETWORK_ALIAS) && link == Path::new("../systemd-networkd.service"),
        "foreign generated alias"
    );
    for (key, value) in [
        ("Id", "systemd-networkd.service"),
        ("LoadState", "loaded"),
        ("FragmentPath", NETWORK_FRAGMENT),
        ("DropInPaths", ""),
    ] {
        ensure!(
            p.get(key).map(String::as_str) == Some(value),
            "generated network alias differs: {key}"
        );
    }
    let start = p.get("ExecStart").context("network command")?;
    ensure!(start.starts_with("{ path=/usr/lib/systemd/systemd-networkd ; argv[]=/usr/lib/systemd/systemd-networkd ; ignore_errors=no ;") && start.matches("{ path=").count() == 1, "foreign network command");
    for key in [
        "ExecStartPre",
        "ExecStartPost",
        "ExecCondition",
        "ExecStop",
        "ExecStopPost",
        "ExecReload",
    ] {
        ensure!(
            p.get(key).is_none_or(String::is_empty),
            "network alias gained command: {key}"
        );
    }
    let raw = serde_json::to_vec(p)?;
    ensure!(
        !process_references::encoded_reference(&raw, target.as_os_str().as_bytes(), true)
            && !relative_cache_reference(&raw, target),
        "resolved network alias references cache"
    );
    Ok(())
}

fn resolved_network_alias(
    path: &Path,
    link: &Path,
    p: &BTreeMap<String, String>,
    target: &Path,
) -> Result<Value> {
    network_alias_shape(path, link, p, target)?;
    let (digest, md) = hash_file(Path::new(NETWORK_FRAGMENT), 1 << 20)?;
    ensure!(
        digest == NETWORK_FRAGMENT_SHA && md.uid() == 0 && md.gid() == 0 && md.mode() & 0o022 == 0,
        "network fragment custody differs"
    );
    Ok(
        json!({"path":NETWORK_FRAGMENT,"sha256":digest,"identity":evidence::identity(&md),"resolution":"exact generated alias resolved by PID1 to the installed distribution unit"}),
    )
}

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
                let names = "Id,LoadState,ActiveState,SubState,MainPID,ExecStart,ExecStartPre,ExecStartPost,ExecCondition,ExecStop,ExecStopPost,ExecReload,Triggers,TriggeredBy,FragmentPath,DropInPaths";
                let before = properties(name, names)?;
                let resolved = if path == Path::new(NETWORK_ALIAS) {
                    resolved_network_alias(&path, &link, &before, target)?
                } else {
                    missing_unit_is_nonlaunchable(name, &before)?;
                    Value::Null
                };
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
                if !resolved.is_null() {
                    ensure!(
                        resolved_network_alias(&path, &link, &before, target)? == resolved,
                        "resolved network fragment changed"
                    );
                }
                missing.push(json!({"alias":path,"missing_target":link,"manager_state":before,"resolved_distribution_unit":resolved,"before_after_stable":true}));
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

#[cfg(test)]
mod tests {
    use super::*;
    fn native() -> BTreeMap<String, String> {
        [("Id", "systemd-networkd.service"), ("LoadState", "loaded"), ("FragmentPath", NETWORK_FRAGMENT), ("DropInPaths", ""), ("ExecStart", "{ path=/usr/lib/systemd/systemd-networkd ; argv[]=/usr/lib/systemd/systemd-networkd ; ignore_errors=no ; pid=0 }")].into_iter().map(|(k,v)|(k.into(),v.into())).collect()
    }
    #[test]
    fn distribution_alias_requires_exact_resolution_and_commands() {
        let p = native();
        network_alias_shape(
            Path::new(NETWORK_ALIAS),
            Path::new("../systemd-networkd.service"),
            &p,
            Path::new(TARGETS[0].0),
        )
        .unwrap();
        for key in [
            "Id",
            "LoadState",
            "FragmentPath",
            "DropInPaths",
            "ExecStart",
            "ExecStartPre",
            "ExecStopPost",
        ] {
            let mut bad = p.clone();
            bad.insert(key.into(), "changed".into());
            assert!(
                network_alias_shape(
                    Path::new(NETWORK_ALIAS),
                    Path::new("../systemd-networkd.service"),
                    &bad,
                    Path::new(TARGETS[0].0)
                )
                .is_err()
            );
        }
        assert!(
            network_alias_shape(
                Path::new("/run/foreign.service"),
                Path::new("../systemd-networkd.service"),
                &p,
                Path::new(TARGETS[0].0)
            )
            .is_err()
        );
    }
    #[test]
    fn unknown_loaded_alias_remains_rejected() {
        assert!(missing_unit_is_nonlaunchable("systemd-networkd.service", &native()).is_err());
        let mut p = native();
        p.insert(
            "ExecStartPre".into(),
            format!("/bin/cat {}/a.o", TARGETS[0].0),
        );
        assert!(
            network_alias_shape(
                Path::new(NETWORK_ALIAS),
                Path::new("../systemd-networkd.service"),
                &p,
                Path::new(TARGETS[0].0)
            )
            .is_err()
        );
    }
}
