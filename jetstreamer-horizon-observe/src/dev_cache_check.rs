//! Exact reproducible dev-cache evidence. Never removes files or runs Cargo.
use {
    crate::{
        process_references,
        ram_artifact_retention::{Bound, bound_json, hash_file, properties},
    },
    anyhow::{Context, Result, ensure},
    serde::Deserialize,
    serde_json::{Value, json},
    std::{
        collections::BTreeSet,
        env,
        fs::{self, File},
        io::Write,
        os::unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, PermissionsExt},
        },
        path::{Path, PathBuf},
        process::Command,
    },
};
const REPO: &str = "/home/ubuntu/workspace/jetstreamer";
const TARGET: &str = "/home/ubuntu/workspace/jetstreamer/target/debug";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    source_commit: String,
    cargo_lock_sha256: String,
    output: PathBuf,
}
fn hex(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn git(args: &[&str]) -> Result<Vec<u8>> {
    let o = Command::new("/usr/bin/git")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .args([
            "-c",
            &format!("safe.directory={REPO}"),
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.untrackedCache=false",
            "-C",
            REPO,
        ])
        .args(args)
        .output()?;
    ensure!(
        o.status.success() && o.stdout.len() <= 65536,
        "source/git-ignore check failed"
    );
    Ok(o.stdout)
}
fn validate_plan(p: &Plan) -> Result<()> {
    ensure!(
        p.schema == "jetstreamer-horizon-dev-cache-check-plan-v1"
            && hex(&p.source_commit, 40)
            && hex(&p.cargo_lock_sha256, 64),
        "invalid cache-check plan"
    );
    ensure!(
        p.output.file_name().is_some_and(|s| s == "check.json")
            && p.output.parent().and_then(Path::parent) == Some(Path::new("/var/lib/jetstreamer"))
            && p.output
                .parent()
                .and_then(Path::file_name)
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with("horizon-dev-cache-check-")
                    && s.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))),
        "unsafe cache-check output"
    );
    Ok(())
}
fn cache_tree(target: &Path) -> Result<Value> {
    let root = fs::symlink_metadata(target)?;
    ensure!(
        target.canonicalize()? == target && root.is_dir() && root.uid() == 1000,
        "unsafe dev-cache identity"
    );
    let mut queue = vec![(target.to_path_buf(), 0u32)];
    let mut entries = 0u64;
    let mut physical = 0u64;
    let mut regular = 0u64;
    let mut links = 0u64;
    while let Some((path, depth)) = queue.pop() {
        entries += 1;
        ensure!(
            entries <= 1_000_000 && depth <= 128,
            "cache census exceeded bound"
        );
        let m = fs::symlink_metadata(&path)?;
        ensure!(
            m.dev() == root.dev() && (m.is_dir() || m.is_file() || m.file_type().is_symlink()),
            "foreign mount or special cache entry"
        );
        physical = physical
            .checked_add(m.blocks().checked_mul(512).context("block overflow")?)
            .context("tree overflow")?;
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .context("nonUTF8 cache member")?;
        ensure!(
            !name.ends_with(".jet")
                && !name.ends_with(".sha256")
                && !name.starts_with("snapshot-")
                && !name.ends_with(".tar.zst")
                && !name.ends_with(".tar.bz2"),
            "archive/snapshot/sidecar found in cache"
        );
        if m.is_dir() {
            for e in fs::read_dir(&path)? {
                queue.push((e?.path(), depth + 1));
            }
        } else if m.is_file() {
            regular += 1;
        } else {
            links += 1;
        }
    }
    let after = fs::symlink_metadata(target)?;
    ensure!(
        root.dev() == after.dev() && root.ino() == after.ino(),
        "cache root changed"
    );
    Ok(
        json!({"path":target,"device":root.dev(),"inode":root.ino(),"uid":root.uid(),"mode":format!("{:04o}",root.mode()&0o7777),
        "physical_bytes":physical,"regular_files":regular,"symlinks_not_followed":links,"entries":entries}),
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
fn staged_references(
    roots: &[&Path],
    target: &Path,
    missing: &mut Vec<Value>,
) -> Result<Vec<String>> {
    staged_references_inner(roots, target, missing, &BTreeSet::new(), true)
}

/// Read-only exact-path census shared with a separately scoped terminal checker.
/// Only independently authenticated terminal-owner fragments may be excluded.
pub(crate) fn staged_references_exact(
    roots: &[&Path],
    target: &Path,
    missing: &mut Vec<Value>,
    terminal_fragments: &BTreeSet<PathBuf>,
) -> Result<Vec<String>> {
    staged_references_inner(roots, target, missing, terminal_fragments, false)
}

fn staged_references_inner(
    roots: &[&Path],
    target: &Path,
    missing: &mut Vec<Value>,
    terminal_fragments: &BTreeSet<PathBuf>,
    dev_cache_literal: bool,
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
                    ) && !(dev_cache_literal
                        && link
                            .as_os_str()
                            .as_bytes()
                            .windows(b"target/debug".len())
                            .any(|b| b == b"target/debug")),
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
            if !terminal_fragments.contains(&canonical)
                && (process_references::encoded_reference(
                    &bytes,
                    target.as_os_str().as_bytes(),
                    true,
                ) || (dev_cache_literal
                    && bytes
                        .windows(b"target/debug".len())
                        .any(|s| s == b"target/debug")))
            {
                refs.push(canonical.display().to_string());
            }
        }
    }
    refs.sort();
    Ok(refs)
}
fn persist(path: &Path, v: &Value) -> Result<()> {
    let parent = path.parent().context("output parent")?;
    let m = fs::symlink_metadata(parent)?;
    ensure!(
        parent.canonicalize()? == parent
            && m.is_dir()
            && m.uid() == 0
            && m.mode() & 0o7777 == 0o700,
        "unsafe receipt directory"
    );
    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
    tmp.as_file()
        .set_permissions(fs::Permissions::from_mode(0o400))?;
    serde_json::to_writer_pretty(tmp.as_file_mut(), v)?;
    tmp.write_all(b"\n")?;
    tmp.as_file().sync_all()?;
    tmp.persist_noclobber(path)
        .map_err(|e| anyhow::anyhow!("occupied cache-check receipt: {e}"))?;
    File::open(parent)?.sync_all()?;
    Ok(())
}
pub fn run() -> Result<()> {
    let a: Vec<_> = env::args().collect();
    ensure!(
        a.len() == 6 && a[2] == "--plan-sha256" && a[4] == "--self-sha256",
        "usage: dev-cache-check PLAN --plan-sha256 HEX --self-sha256 HEX"
    );
    ensure!(unsafe { libc::geteuid() } == 0, "cache check requires root");
    let exe = fs::read_link("/proc/self/exe")?;
    let (sha, m) = hash_file(&exe, 256 << 20)?;
    ensure!(
        sha == a[5] && hex(&a[5], 64) && m.uid() == 0 && m.mode() & 0o222 == 0,
        "checker executable differs"
    );
    let pb = Bound {
        path: a[1].clone().into(),
        sha256: a[3].clone(),
    };
    let p: Plan = serde_json::from_value(bound_json(&pb)?)?;
    validate_plan(&p)?;
    ensure!(
        git(&["rev-parse", "HEAD"])? == format!("{}\n", p.source_commit).as_bytes()
            && git(&["status", "--porcelain", "--untracked-files=no"])?.is_empty(),
        "source revision is not preserved/clean"
    );
    git(&["check-ignore", "target/debug"])?;
    let lock = Path::new(REPO).join("Cargo.lock");
    ensure!(
        hash_file(&lock, 16 << 20)?.0 == p.cargo_lock_sha256,
        "Cargo.lock differs"
    );
    let tree = cache_tree(Path::new(TARGET))?;
    let mut missing = Vec::new();
    let staged = staged_references(
        &[
            Path::new("/etc/systemd/system"),
            Path::new("/run/systemd/transient"),
            Path::new("/home/ubuntu/.config/systemd/user"),
        ],
        Path::new(TARGET),
        &mut missing,
    )?;
    let scan = process_references::scan(Path::new("/proc"), Path::new(TARGET))?;
    ensure!(
        staged.is_empty() && scan.references.is_empty(),
        "cache has live or staged references: {:?} {:?}",
        scan.references,
        staged
    );
    let root = fs::symlink_metadata(TARGET)?;
    ensure!(
        tree["device"] == root.dev() && tree["inode"] == root.ino(),
        "cache identity changed before receipt"
    );
    persist(
        &p.output,
        &json!({"schema":"jetstreamer-horizon-dev-cache-check-v1","self_sha256":a[5],"plan":{"path":pb.path,"sha256":pb.sha256},
        "source_commit":p.source_commit,"cargo_lock_sha256":p.cargo_lock_sha256,"cache":tree,"process_scan":scan,"staged_unit_references":staged,"missing_inactive_unit_aliases":missing,
        "retirement_authorized":false,"archive_deletion_authorized":false,"replay_scratch_deletion_authorized":false,"remote_mutations":false,"r2_mutations":false}),
    )?;
    println!("{}", p.output.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_staged_census_never_borrows_cache_literal_or_implicit_exclusions() {
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("owner.service");
        let target = Path::new("/private/exact-stopped-run");
        fs::write(&file, b"ExecStart=/unrelated/target/debug/tool\n").unwrap();
        let mut missing = Vec::new();
        assert_eq!(
            staged_references(&[d.path()], target, &mut missing).unwrap(),
            vec![file.display().to_string()]
        );
        assert!(
            staged_references_exact(&[d.path()], target, &mut missing, &BTreeSet::new())
                .unwrap()
                .is_empty()
        );
        fs::write(
            &file,
            format!("ReadWritePaths={}/scratch\n", target.display()),
        )
        .unwrap();
        assert_eq!(
            staged_references_exact(&[d.path()], target, &mut missing, &BTreeSet::new()).unwrap(),
            vec![file.display().to_string()]
        );
        assert!(
            staged_references_exact(
                &[d.path()],
                target,
                &mut missing,
                &BTreeSet::from([file.canonicalize().unwrap()])
            )
            .unwrap()
            .is_empty()
        );
    }
    #[test]
    fn staged_units_follow_real_aliases_and_match_only_exact_cache_or_relative_target() {
        let t = tempfile::tempdir().unwrap();
        let unit = t.path().join("test.service");
        fs::write(&unit, b"ExecStart=/cache/debug-sibling/worker\n").unwrap();
        assert!(
            staged_references(&[t.path()], Path::new("/cache/debug"), &mut Vec::new())
                .unwrap()
                .is_empty()
        );
        fs::write(&unit, b"ExecStart=/cache/debug/worker\n").unwrap();
        std::os::unix::fs::symlink(&unit, t.path().join("alias.service")).unwrap();
        assert_eq!(
            staged_references(&[t.path()], Path::new("/cache/debug"), &mut Vec::new())
                .unwrap()
                .len(),
            1
        );
        fs::write(&unit, b"ExecStart=target/debug/worker\n").unwrap();
        assert_eq!(
            staged_references(&[t.path()], Path::new("/cache/debug"), &mut Vec::new())
                .unwrap()
                .len(),
            1
        );
    }
    #[test]
    fn plan_cannot_select_any_deletion_target_or_nonprivate_output() {
        let mut p = Plan {
            schema: "jetstreamer-horizon-dev-cache-check-plan-v1".into(),
            source_commit: "a".repeat(40),
            cargo_lock_sha256: "b".repeat(64),
            output: "/var/lib/jetstreamer/horizon-dev-cache-check-test/check.json".into(),
        };
        validate_plan(&p).unwrap();
        p.output = "/home/ubuntu/horizon/check.json".into();
        assert!(validate_plan(&p).is_err());
        assert!(serde_json::from_value::<Plan>(json!({"schema":p.schema,"source_commit":p.source_commit,"cargo_lock_sha256":p.cargo_lock_sha256,"output":p.output,"target":"/"})).is_err());
    }

    #[test]
    fn cache_inventory_never_follows_links_or_admits_archive_snapshot_data() {
        let t = tempfile::tempdir().unwrap();
        fs::write(
            t.path().join("compiled-object"),
            b"reproducible build bytes",
        )
        .unwrap();
        if unsafe { libc::geteuid() } != 1000 {
            assert!(cache_tree(t.path()).is_err());
            return;
        }
        let external = tempfile::tempdir().unwrap();
        fs::write(external.path().join("epoch-203.jet"), b"never selected").unwrap();
        std::os::unix::fs::symlink(external.path(), t.path().join("external-link")).unwrap();
        let v = cache_tree(t.path()).unwrap();
        assert_eq!(v["symlinks_not_followed"], 1);
        assert_eq!(v["regular_files"], 1);
        fs::write(t.path().join("epoch-203.jet"), b"must block cleanup").unwrap();
        assert!(cache_tree(t.path()).is_err());
    }

    #[test]
    fn dangling_unit_requires_positive_manager_absence_not_unreadable_or_cached_commands() {
        let p = std::collections::BTreeMap::from([
            ("Id".into(), "missing.service".into()),
            ("LoadState".into(), "not-found".into()),
            ("ActiveState".into(), "inactive".into()),
            ("SubState".into(), "dead".into()),
            ("MainPID".into(), "0".into()),
            ("Triggers".into(), "".into()),
            ("TriggeredBy".into(), "".into()),
        ]);
        missing_unit_is_nonlaunchable("missing.service", &p).unwrap();
        for (key, value) in [
            ("LoadState", "loaded"),
            ("ActiveState", "active"),
            ("MainPID", "123"),
            ("ExecStart", "/cached/command"),
            ("ExecStartPre", "/cached/hook"),
            ("TriggeredBy", "future.timer"),
        ] {
            let mut bad = p.clone();
            bad.insert(key.into(), value.into());
            assert!(
                missing_unit_is_nonlaunchable("missing.service", &bad).is_err(),
                "{key}"
            );
        }
        let mut bad = p;
        bad.remove("LoadState");
        assert!(missing_unit_is_nonlaunchable("missing.service", &bad).is_err());
    }

    #[test]
    fn dangling_alias_to_cache_cannot_be_exempted_as_a_missing_system_service() {
        let t = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(
            "/cache/debug/missing.service",
            t.path().join("missing.service"),
        )
        .unwrap();
        assert!(
            staged_references(&[t.path()], Path::new("/cache/debug"), &mut Vec::new()).is_err()
        );
    }
}
