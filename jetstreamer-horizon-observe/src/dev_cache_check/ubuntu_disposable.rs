//! Two closed Ubuntu compiler-cache profiles. No source/runtime/data scope.
use super::*;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::os::{fd::AsRawFd, unix::fs::OpenOptionsExt};

pub(super) const RELEASE_PROFILE: &str = "jetstreamer-horizon-ubuntu-release-deps-cache-plan-v2";
pub(super) const INCREMENTAL_PROFILE: &str =
    "jetstreamer-horizon-ubuntu-debug-incremental-cache-plan-v2";
pub(super) const RELEASE_DEPS: &str = "/home/ubuntu/workspace/jetstreamer/target/release/deps";
pub(super) const DEBUG_INCREMENTAL: &str =
    "/home/ubuntu/workspace/jetstreamer/target/debug/incremental";
const LEDGER_SCHEMA: &str = "jetstreamer-horizon-ubuntu-disposable-cache-check-v2";
const LEDGER_BOUND: u64 = 256 << 20;

fn target(profile: &str) -> Result<&'static Path> {
    match profile {
        RELEASE_PROFILE => Ok(Path::new(RELEASE_DEPS)),
        INCREMENTAL_PROFILE => Ok(Path::new(DEBUG_INCREMENTAL)),
        _ => anyhow::bail!("not a closed Ubuntu disposable cache profile"),
    }
}
pub(super) fn reference_scope_for_target(t: &Path) -> Option<&'static Path> {
    if t == Path::new(RELEASE_DEPS) {
        Some(Path::new(RELEASE_TARGET))
    } else if t == Path::new(DEBUG_INCREMENTAL) {
        Some(Path::new(DEBUG_INCREMENTAL))
    } else {
        None
    }
}
pub(super) fn cache_reference(bytes: &[u8], scope: &Path) -> bool {
    if process_references::encoded_reference(bytes, scope.as_os_str().as_bytes(), true) {
        return true;
    }
    let relative = scope
        .strip_prefix(REPO)
        .ok()
        .map(|p| p.as_os_str().as_bytes());
    relative.is_some_and(|needle| {
        bytes.windows(needle.len()).enumerate().any(|(i, w)| {
            w == needle
                && (i == 0 || b"=\0\n\r\t '\"".contains(&bytes[i - 1]))
                && process_references::encoded_reference(&bytes[i..], needle, true)
        })
    }) || relative.is_some_and(|needle| {
        let mut dotted = b"./".to_vec();
        dotted.extend_from_slice(needle);
        bytes.windows(dotted.len()).enumerate().any(|(i, w)| {
            w == dotted
                && (i == 0 || b"=\0\n\r\t '\"".contains(&bytes[i - 1]))
                && process_references::encoded_reference(&bytes[i..], &dotted, true)
        })
    })
}
fn source(p: &Plan) -> Result<()> {
    ensure!(
        git(REPO, &["rev-parse", "HEAD"])? == format!("{}\n", p.source_commit).as_bytes()
            && git(REPO, &["status", "--porcelain", "--untracked-files=no"])?.is_empty(),
        "cache source revision is changed/unclean"
    );
    ensure!(
        hash_file(&Path::new(REPO).join("Cargo.lock"), 16 << 20)?.0 == p.cargo_lock_sha256,
        "cache source Cargo.lock changed"
    );
    let t = target(&p.schema)?;
    git(
        REPO,
        &[
            "check-ignore",
            t.strip_prefix(REPO)?
                .to_str()
                .context("cache relative path")?,
        ],
    )?;
    ensure!(
        git(
            REPO,
            &["ls-files", "--", t.to_str().context("cache target UTF8")?]
        )?
        .is_empty(),
        "selected cache contains tracked source"
    );
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Node {
    kind: String,
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    size: u64,
    blocks: u64,
    modified: i64,
    nanos: i64,
    links: u64,
    symlink: Option<PathBuf>,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Manifest {
    nodes: std::collections::BTreeMap<PathBuf, Node>,
    unique_inode_physical_bytes: u64,
    pathname_allocated_bytes: u64,
}
fn node(path: &Path) -> Result<Node> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.uid() == 1000 && (m.is_file() || m.is_dir() || m.file_type().is_symlink()),
        "cache contains foreign owner/special node"
    );
    let kind = if m.is_dir() {
        "directory"
    } else if m.is_file() {
        "file"
    } else {
        "symlink"
    };
    Ok(Node {
        kind: kind.into(),
        device: m.dev(),
        inode: m.ino(),
        uid: m.uid(),
        gid: m.gid(),
        mode: m.mode(),
        size: if m.is_dir() { 0 } else { m.len() },
        blocks: if m.is_dir() { 0 } else { m.blocks() },
        modified: if m.is_dir() { 0 } else { m.mtime() },
        nanos: if m.is_dir() { 0 } else { m.mtime_nsec() },
        links: if m.is_dir() { 0 } else { m.nlink() },
        symlink: if m.file_type().is_symlink() {
            Some(fs::read_link(path)?)
        } else {
            None
        },
    })
}
fn forbidden(path: &Path) -> bool {
    path.file_name().and_then(|s| s.to_str()).is_none_or(|s| {
        s.ends_with(".jet")
            || s.ends_with(".sha256")
            || s.starts_with("snapshot-")
            || s.ends_with(".tar.zst")
            || s.ends_with(".tar.bz2")
            || s.contains("checkpoint")
            || matches!(s, "Cargo.lock" | ".cargo-lock")
    })
}
fn manifest(t: &Path) -> Result<Manifest> {
    ensure!(t.canonicalize()? == t, "cache path is redirected");
    let root = node(t)?;
    ensure!(root.kind == "directory", "cache root is not a directory");
    let mut queue = vec![(t.to_path_buf(), 0u32)];
    let mut nodes = std::collections::BTreeMap::new();
    let mut seen = BTreeSet::new();
    let mut unique = 0u64;
    let mut all = 0u64;
    while let Some((p, depth)) = queue.pop() {
        ensure!(
            depth <= 128 && nodes.len() < 1_000_000,
            "cache manifest bound"
        );
        let n = node(&p)?;
        ensure!(
            n.device == root.device,
            "cache crosses a filesystem boundary"
        );
        ensure!(
            !forbidden(&p),
            "archive/checkpoint/lock/source artifact found inside cache"
        );
        let physical = fs::symlink_metadata(&p)?
            .blocks()
            .checked_mul(512)
            .context("cache block overflow")?;
        all = all.checked_add(physical).context("cache byte overflow")?;
        if seen.insert((n.device, n.inode)) {
            unique = unique
                .checked_add(physical)
                .context("cache unique-byte overflow")?;
        }
        if n.kind == "directory" {
            for e in fs::read_dir(&p)? {
                queue.push((e?.path(), depth + 1));
            }
        }
        ensure!(
            nodes.insert(p.strip_prefix(t)?.to_path_buf(), n).is_none(),
            "duplicate cache node"
        );
    }
    ensure!(
        nodes.get(Path::new("")) == Some(&node(t)?),
        "cache root changed while scanned"
    );
    Ok(Manifest {
        nodes,
        unique_inode_physical_bytes: unique,
        pathname_allocated_bytes: all,
    })
}
fn same_node(current: &Node, original: &Node) -> bool {
    let mut adjusted = current.clone();
    adjusted.links = original.links;
    adjusted == *original && current.links <= original.links
}
fn subset(current: &Manifest, original: &Manifest) -> Result<()> {
    for (path, n) in &current.nodes {
        ensure!(
            original
                .nodes
                .get(path)
                .is_some_and(|old| same_node(n, old)),
            "cache node appeared, changed or was replaced:{}",
            path.display()
        );
    }
    for (path, n) in &original.nodes {
        if n.kind == "directory" {
            ensure!(
                current.nodes.get(path) == Some(n),
                "checked cache directory changed/disappeared:{}",
                path.display()
            );
        }
    }
    Ok(())
}
fn empty(m: &Manifest) -> bool {
    m.nodes.values().all(|n| n.kind == "directory")
}
fn free(t: &Path) -> Result<u64> {
    let path = std::ffi::CString::new(t.as_os_str().as_bytes())?;
    let mut s = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    ensure!(
        unsafe { libc::statvfs(path.as_ptr(), s.as_mut_ptr()) } == 0,
        "cache free-space measurement failed"
    );
    let s = unsafe { s.assume_init() };
    s.f_bavail
        .checked_mul(s.f_frsize)
        .context("cache free-space overflow")
}
fn checks(p: &Plan, t: &Path) -> Result<Value> {
    source(p)?;
    no_builders(Path::new("/proc"))?;
    let scope = reference_scope_for_target(t).context("unknown cache reference scope")?;
    let roots = [
        Path::new("/etc/systemd/system"),
        Path::new("/run/systemd/transient"),
        Path::new("/run/systemd/system"),
        Path::new("/home/ubuntu/.config/systemd/user"),
    ];
    let mut missing = Vec::new();
    let staged = staged_references(&roots, t, &mut missing)?;
    let scan = process_references::scan(Path::new("/proc"), scope)?;
    ensure!(
        staged.is_empty() && scan.references.is_empty(),
        "cache has staged/live references:{staged:?} {:?}",
        scan.references
    );
    Ok(
        json!({"process_scan":scan,"staged_unit_references":staged,"missing_inactive_unit_aliases":missing,
        "builder_census_complete":true,"active_builders":[],"reference_scope":scope}),
    )
}
fn read_large(bound: &Bound) -> Result<Value> {
    ensure!(
        bound.path.canonicalize()? == bound.path,
        "cache ledger path redirected"
    );
    let (sha, m) = hash_file(&bound.path, LEDGER_BOUND)?;
    ensure!(
        sha == bound.sha256 && m.uid() == 0 && m.mode() & 0o222 == 0,
        "cache ledger is not immutable/root/SHA-bound"
    );
    let bytes = fs::read(&bound.path)?;
    ensure!(
        bytes.len() as u64 <= LEDGER_BOUND
            && format!("{:x}", sha2::Sha256::digest(&bytes)) == bound.sha256,
        "cache ledger changed while read"
    );
    Ok(serde_json::from_slice(&bytes)?)
}
fn read_record(path: &Path) -> Result<Value> {
    let sha = hash_file(path, LEDGER_BOUND)?.0;
    read_large(&Bound {
        path: path.into(),
        sha256: sha,
    })
}
fn identity_match(path: &Path, expected: &Node) -> Result<()> {
    ensure!(
        same_node(&node(path)?, expected),
        "cache node changed immediately before unlink:{}",
        path.display()
    );
    Ok(())
}
fn clear_files(t: &Path, current: &Manifest) -> Result<()> {
    for (relative, n) in &current.nodes {
        if n.kind == "directory" {
            continue;
        }
        let parent = relative.parent().context("cache member parent missing")?;
        let full_parent = t.join(parent);
        let expected = current
            .nodes
            .get(parent)
            .context("cache parent absent from ledger")?;
        let handle = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open(&full_parent)?;
        let m = handle.metadata()?;
        ensure!(
            expected.kind == "directory" && m.dev() == expected.device && m.ino() == expected.inode,
            "cache directory replaced before unlink"
        );
        identity_match(&t.join(relative), n)?;
        let name = std::ffi::CString::new(
            relative
                .file_name()
                .context("cache member name missing")?
                .as_bytes(),
        )?;
        ensure!(
            unsafe { libc::unlinkat(handle.as_raw_fd(), name.as_ptr(), 0) } == 0,
            "cannot unlink identity-checked cache member"
        );
    }
    // Keep every original directory, including the selected root, for bounded
    // interrupted recovery. No deletion can reach the parent profile lock.
    for (relative, n) in &current.nodes {
        if n.kind == "directory" {
            File::open(t.join(relative))?.sync_all()?;
        }
    }
    Ok(())
}
fn validate_prior(v: &Value, p: &Plan, t: &Path, self_sha: &str) -> Result<Manifest> {
    ensure!(
        v["schema"] == LEDGER_SCHEMA
            && v["cache_profile"] == p.schema
            && v["source_commit"] == p.source_commit
            && v["cargo_lock_sha256"] == p.cargo_lock_sha256
            && v["self_sha256"] == self_sha
            && v["target"] == t.to_string_lossy().as_ref()
            && v["checks"]["builder_census_complete"] == true
            && v["checks"]["active_builders"] == json!([])
            && v["checks"]["process_scan"]["references"] == json!([])
            && v["checks"]["staged_unit_references"] == json!([])
            && v["r2_mutations"] == false
            && v["remote_mutations"] == false
            && v["archive_deletion_authorized"] == false
            && v["replay_scratch_deletion_authorized"] == false
            && v["replay_launch_authorized"] == false
            && v["retirement_authorized"] == false,
        "cache prior positive ledger profile/source/authority differs"
    );
    Ok(serde_json::from_value(v["manifest"].clone())?)
}
pub(super) fn run(p: &Plan, plan: &Bound, self_sha: &str) -> Result<()> {
    let t = target(&p.schema)?;
    source(p)?;
    no_builders(Path::new("/proc"))?;
    let parent = t.parent().context("cache parent profile")?;
    let profile_lock = cargo_profile_lock(parent)?;
    let lock_metadata = profile_lock.metadata()?;
    ensure!(
        lock_metadata.uid() == 1000 && lock_metadata.nlink() == 1,
        "unexpected parent Cargo lock identity"
    );
    let evidence = checks(p, t)?;
    let current = manifest(t)?;
    let base = json!({"schema":LEDGER_SCHEMA,"cache_profile":p.schema,"source_commit":p.source_commit,"cargo_lock_sha256":p.cargo_lock_sha256,
        "self_sha256":self_sha,"target":t,"parent_cargo_lock_device":lock_metadata.dev(),"parent_cargo_lock_inode":lock_metadata.ino(),
        "archive_deletion_authorized":false,"replay_scratch_deletion_authorized":false,"replay_launch_authorized":false,"remote_mutations":false,"r2_mutations":false});
    if p.retirement.is_none() {
        checks(p, t)?;
        ensure!(
            manifest(t)? == current,
            "cache changed during positive census"
        );
        let mut record = base;
        record["retirement_authorized"] = json!(false);
        record["checks"] = evidence;
        record["manifest"] = serde_json::to_value(&current)?;
        record["plan"] = json!({"path":plan.path,"sha256":plan.sha256});
        record["filesystem_available_bytes"] = json!(free(t)?);
        ensure!(
            (serde_json::to_vec_pretty(&record)?.len() as u64) < LEDGER_BOUND,
            "cache identity ledger exceeds bound"
        );
        persist(&p.output, &record)?;
        println!(
            "{}",
            json!({"status":"check-passed","output":p.output,"unique_inode_physical_bytes":current.unique_inode_physical_bytes,"entries":current.nodes.len(),"retirement_performed":false})
        );
        return Ok(());
    }
    let previous = &p
        .retirement
        .as_ref()
        .context("cache prior check missing")?
        .prior_check;
    let positive = read_large(previous)?;
    let original = validate_prior(&positive, p, t, self_sha)?;
    ensure!(
        positive["parent_cargo_lock_device"] == lock_metadata.dev()
            && positive["parent_cargo_lock_inode"] == lock_metadata.ino(),
        "parent Cargo lock replaced since positive check"
    );
    subset(&current, &original)?;
    let mut binding = base;
    binding["plan"] = json!({"path":plan.path,"sha256":plan.sha256});
    binding["prior_check"] = json!({"path":previous.path,"sha256":previous.sha256});
    let state = p.output.parent().context("cache receipt directory")?;
    let intent = state.join("intent.json");
    let completion = state.join("completion.json");
    if p.output.try_exists()? {
        let checked = read_record(&p.output)?;
        ensure!(
            checked["binding"] == binding && checked["retirement_performed"] == false,
            "interrupted retirement check differs"
        );
    } else {
        ensure!(
            !intent.try_exists()? && !completion.try_exists()? && current == original,
            "cache changed or interrupted history lost its check"
        );
        persist(
            &p.output,
            &json!({"binding":binding,"checks":evidence,"retirement_performed":false}),
        )?;
    }
    let second_check_sha256 = hash_file(&p.output, 1 << 20)?.0;
    if completion.try_exists()? {
        let done = read_record(&completion)?;
        let started = read_record(&intent)?;
        ensure!(
            done["binding"] == binding
                && empty(&current)
                && done["intent_sha256"] == hash_file(&intent, 1 << 20)?.0
                && started["binding"] == binding
                && started["second_check_sha256"] == second_check_sha256,
            "cache completion changed or files reappeared"
        );
        println!(
            "{}",
            json!({"status":"already-complete","completion":completion})
        );
        return Ok(());
    }
    if intent.try_exists()? {
        let started = read_record(&intent)?;
        ensure!(
            started["binding"] == binding && started["second_check_sha256"] == second_check_sha256,
            "cache interrupted-recovery intent differs"
        );
    } else {
        ensure!(
            current == original,
            "cache changed after check; no retirement without a new reviewed check"
        );
        persist(
            &intent,
            &json!({"binding":binding,"second_check_sha256":second_check_sha256,"available_bytes_before":free(t)?,"original_entries":original.nodes.len()}),
        )?;
    }
    checks(p, t)?;
    ensure!(
        manifest(t)? == current,
        "cache changed after deletion intent"
    );
    let current_lock = fs::symlink_metadata(parent.join(".cargo-lock"))?;
    ensure!(
        current_lock.dev() == lock_metadata.dev() && current_lock.ino() == lock_metadata.ino(),
        "Cargo lock inode changed before unlink"
    );
    clear_files(t, &current)?;
    let after = manifest(t)?;
    subset(&after, &original)?;
    ensure!(empty(&after), "cache members remain after unlink");
    let final_lock = fs::symlink_metadata(parent.join(".cargo-lock"))?;
    ensure!(
        final_lock.is_file()
            && final_lock.nlink() == 1
            && final_lock.dev() == lock_metadata.dev()
            && final_lock.ino() == lock_metadata.ino(),
        "parent Cargo lock changed during retirement"
    );
    File::open(t)?.sync_all()?;
    persist(
        &completion,
        &json!({"binding":binding,"intent_sha256":hash_file(&intent,1<<20)?.0,"available_bytes_after":free(t)?,
        "original_unique_inode_physical_bytes":original.unique_inode_physical_bytes,"remaining_unique_inode_physical_bytes":after.unique_inode_physical_bytes,
        "all_original_directories_preserved":true,"parent_cargo_lock_preserved":true,"retirement_completed":true}),
    )?;
    println!("{}", json!({"status":"complete","completion":completion}));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn plan(profile: &str) -> Plan {
        Plan {
            schema: profile.into(),
            source_commit: "a".repeat(40),
            cargo_lock_sha256: "b".repeat(64),
            output:
                "/var/lib/jetstreamer/horizon-dev-cache-check-ubuntu-disposable-test/check.json"
                    .into(),
            retirement: Some(Retirement {
                prior_check: Bound {
                    path: "/var/lib/jetstreamer/horizon-dev-cache-check-prior/check.json".into(),
                    sha256: "c".repeat(64),
                },
            }),
        }
    }
    #[test]
    fn new_profiles_cannot_borrow_source_lock_helper_or_other_profile_checks() {
        for profile in [RELEASE_PROFILE, INCREMENTAL_PROFILE] {
            let p = plan(profile);
            validate_plan(&p).unwrap();
            let t = target(profile).unwrap();
            let good = json!({"schema":LEDGER_SCHEMA,"cache_profile":profile,"source_commit":p.source_commit,"cargo_lock_sha256":p.cargo_lock_sha256,
                "self_sha256":"d".repeat(64),"target":t,"checks":{"builder_census_complete":true,"active_builders":[],"process_scan":{"references":[]},"staged_unit_references":[]},
                "retirement_authorized":false,"r2_mutations":false,"remote_mutations":false,"archive_deletion_authorized":false,
                "replay_scratch_deletion_authorized":false,"replay_launch_authorized":false,
                "manifest":{"nodes":{},"unique_inode_physical_bytes":0,"pathname_allocated_bytes":0}});
            validate_prior(&good, &p, t, &"d".repeat(64)).unwrap();
            for (pointer, value) in [
                ("/cache_profile", json!("other-profile")),
                ("/source_commit", json!("e".repeat(40))),
                ("/cargo_lock_sha256", json!("e".repeat(64))),
                ("/self_sha256", json!("e".repeat(64))),
                ("/target", json!("/home/ubuntu/.jetstreamer-private")),
                ("/retirement_authorized", json!(true)),
                ("/checks/active_builders", json!([123])),
                (
                    "/checks/staged_unit_references",
                    json!(["consumer.service"]),
                ),
            ] {
                let mut bad = good.clone();
                *bad.pointer_mut(pointer).unwrap() = value;
                assert!(validate_prior(&bad, &p, t, &"d".repeat(64)).is_err());
            }
        }
        let mut old = plan(RELEASE_PROFILE);
        old.schema = "jetstreamer-horizon-release-cache-check-plan-v1".into();
        assert!(validate_plan(&old).is_err());
    }
    fn fixture() -> (tempfile::TempDir, Manifest) {
        let d = tempfile::tempdir().unwrap();
        fs::create_dir(d.path().join("generation")).unwrap();
        fs::write(d.path().join("generation/object.o"), b"reproducible object").unwrap();
        let m = manifest(d.path()).unwrap();
        (d, m)
    }
    #[test]
    fn targets_and_reference_scopes_are_closed_and_distinct() {
        assert_eq!(target(RELEASE_PROFILE).unwrap(), Path::new(RELEASE_DEPS));
        assert_eq!(
            target(INCREMENTAL_PROFILE).unwrap(),
            Path::new(DEBUG_INCREMENTAL)
        );
        assert!(target("debug").is_err());
        assert!(cache_reference(
            b"ExecStart=./target/release/tool",
            Path::new(RELEASE_TARGET)
        ));
        assert!(!cache_reference(
            b"ExecStart=/private/other/target/release/tool",
            Path::new(RELEASE_TARGET)
        ));
        assert!(cache_reference(
            b"arg=target/debug/incremental/session",
            Path::new(DEBUG_INCREMENTAL)
        ));
        assert!(!cache_reference(
            b"ExecStart=target/debug/tool",
            Path::new(DEBUG_INCREMENTAL)
        ));
    }
    #[test]
    fn real_retirement_keeps_directories_lock_and_symlink_targets() {
        if unsafe { libc::geteuid() } != 1000 {
            return;
        }
        let (d, _) = fixture();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("retain"), b"retained").unwrap();
        std::os::unix::fs::symlink(outside.path().join("retain"), d.path().join("link")).unwrap();
        let before = manifest(d.path()).unwrap();
        clear_files(d.path(), &before).unwrap();
        let after = manifest(d.path()).unwrap();
        subset(&after, &before).unwrap();
        assert!(empty(&after));
        assert!(d.path().join("generation").is_dir());
        assert_eq!(
            fs::read(outside.path().join("retain")).unwrap(),
            b"retained"
        );
        clear_files(d.path(), &after).unwrap();
    }
    #[test]
    fn partial_recovery_rejects_new_changed_files_and_replaced_directories() {
        if unsafe { libc::geteuid() } != 1000 {
            return;
        }
        let (d, before) = fixture();
        fs::remove_file(d.path().join("generation/object.o")).unwrap();
        subset(&manifest(d.path()).unwrap(), &before).unwrap();
        fs::write(d.path().join("new.o"), b"new valid work").unwrap();
        assert!(subset(&manifest(d.path()).unwrap(), &before).is_err());
        fs::remove_file(d.path().join("new.o")).unwrap();
        fs::remove_dir(d.path().join("generation")).unwrap();
        fs::create_dir(d.path().join("generation")).unwrap();
        assert!(subset(&manifest(d.path()).unwrap(), &before).is_err());
    }
    #[test]
    fn links_and_directory_changes_never_hide_archive_or_lock_files() {
        if unsafe { libc::geteuid() } != 1000 {
            return;
        }
        let (d, _) = fixture();
        for name in [
            "epoch-223.jet",
            "epoch-223.sha256",
            "snapshot-42.tar.zst",
            "native-checkpoint.json",
            ".cargo-lock",
            "Cargo.lock",
        ] {
            fs::write(d.path().join(name), b"preserve").unwrap();
            assert!(manifest(d.path()).is_err());
            assert!(d.path().join(name).exists());
            fs::remove_file(d.path().join(name)).unwrap();
        }
    }
    #[test]
    fn retained_parent_cargo_lock_remains_exclusive_while_cache_is_cleared() {
        if unsafe { libc::geteuid() } != 1000 {
            return;
        }
        let d = tempfile::tempdir().unwrap();
        fs::write(d.path().join(".cargo-lock"), b"").unwrap();
        let cache = d.path().join("deps");
        fs::create_dir(&cache).unwrap();
        fs::write(cache.join("object.o"), b"cache").unwrap();
        let lock = cargo_profile_lock(d.path()).unwrap();
        assert!(cargo_profile_lock(d.path()).is_err());
        clear_files(&cache, &manifest(&cache).unwrap()).unwrap();
        assert!(d.path().join(".cargo-lock").is_file());
        assert!(cargo_profile_lock(d.path()).is_err());
        drop(lock);
        cargo_profile_lock(d.path()).unwrap();
    }
}
