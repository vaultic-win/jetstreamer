//! One finite probe of the actual operational cache/state mount geometry.
//! Only IID-named create-new sentinels are mutable; no lifecycle authority.
use super::*;
use std::io::Write;

const PARENT: &str = "/home/ubuntu/.jetstreamer-private";
const CONFIG: &str = "/home/ubuntu/.config/gcloud";

fn bound_ref(b: &Bound) -> Value {
    json!({"path":b.path,"sha256":b.sha256})
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Admission {
    schema: String,
    issued_unix_seconds: u64,
    expires_unix_seconds: u64,
    self_binary: Bound,
    normal_build: Bound,
    full_source_manifest: Bound,
    profile: Bound,
    parent_identity: DirectoryIdentity,
    cache_identity: DirectoryIdentity,
    state_identity: DirectoryIdentity,
    protected_siblings: BTreeMap<PathBuf, DirectoryIdentity>,
    original_snapshot: Identity,
    output: PathBuf,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Profile {
    schema: String,
    unit: String,
    invocation_id: String,
    expected_properties: BTreeMap<String, String>,
}
#[derive(Debug, PartialEq, Eq, Serialize)]
struct Mount {
    id: u64,
    parent: u64,
    point: PathBuf,
    root: PathBuf,
    options: BTreeSet<String>,
    raw: String,
}
fn unescape(s: &str) -> Result<String> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' {
            ensure!(i + 3 < b.len(), "short mount escape");
            let digits = &b[i + 1..i + 4];
            ensure!(
                digits.iter().all(|x| (b'0'..=b'7').contains(x)),
                "invalid mount escape"
            );
            let value = (digits[0] - b'0') as u16 * 64
                + (digits[1] - b'0') as u16 * 8
                + (digits[2] - b'0') as u16;
            ensure!(
                matches!(value, 9 | 10 | 32 | 92),
                "unsupported mount escape"
            );
            out.push(value as u8);
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    Ok(String::from_utf8(out)?)
}
fn mounts(text: &str) -> Result<Vec<Mount>> {
    ensure!(text.len() <= 16 << 20, "mount table exceeds bound");
    let mut out = Vec::new();
    let mut ids = BTreeSet::new();
    for line in text.lines() {
        let (left, right) = line.split_once(" - ").context("malformed mount table")?;
        let a: Vec<_> = left.split_whitespace().collect();
        ensure!(
            a.len() >= 6 && right.split_whitespace().count() == 3,
            "malformed mount row"
        );
        let id: u64 = a[0].parse()?;
        let options: BTreeSet<_> = a[5].split(',').map(str::to_owned).collect();
        ensure!(
            id > 0
                && ids.insert(id)
                && !options.contains("")
                && options.len() == a[5].split(',').count()
                && (options.contains("rw") ^ options.contains("ro")),
            "invalid mount identity/options"
        );
        out.push(Mount {
            id,
            parent: a[1].parse()?,
            point: unescape(a[4])?.into(),
            root: unescape(a[3])?.into(),
            options,
            raw: line.into(),
        });
    }
    ensure!(
        !out.is_empty() && out.len() <= 32768,
        "empty/oversized mount table"
    );
    Ok(out)
}
fn fd_mount(dir: &Directory) -> Result<u64> {
    dir.validate()?;
    file_mount(&dir.file)
}
fn file_mount(file: &File) -> Result<u64> {
    let text = fs::read_to_string(format!("/proc/self/fdinfo/{}", file.as_raw_fd()))?;
    let rows: Vec<_> = text
        .lines()
        .filter_map(|l| l.strip_prefix("mnt_id:\t"))
        .collect();
    ensure!(
        rows.len() == 1,
        "descriptor mount identity missing/ambiguous"
    );
    Ok(rows[0].parse()?)
}
fn below_mount(rows: &[Mount], mut id: u64, ancestor: u64) -> Result<bool> {
    let mut visited = BTreeSet::new();
    loop {
        if id == ancestor {
            return Ok(true);
        }
        ensure!(visited.insert(id), "cycle in mount ancestry");
        let Some(row) = rows.iter().find(|r| r.id == id) else {
            return Ok(false);
        };
        id = row.parent;
    }
}
fn enrollment(a: &Admission) -> Result<()> {
    ensure!(
        a.protected_siblings.len() <= 4096,
        "sibling enrollment exceeds bound"
    );
    let parent = Directory::open(Path::new(PARENT), &a.parent_identity)?;
    let mut expected = BTreeSet::from([PathBuf::from(CACHE_ROOT), PathBuf::from(STATE)]);
    for (path, id) in &a.protected_siblings {
        ensure!(
            path.parent() == Some(Path::new(PARENT)) && expected.insert(path.clone()),
            "foreign/duplicate writable-parent sibling"
        );
        let m = fs::symlink_metadata(path)?;
        ensure!(
            (m.is_dir() || m.is_file())
                && path.canonicalize()? == *path
                && DirectoryIdentity::of(&m) == *id,
            "protected sibling replaced or aliased"
        );
    }
    let actual: BTreeSet<_> = fs::read_dir(PARENT)?
        .map(|e| Ok(e?.path()))
        .collect::<Result<_>>()?;
    ensure!(actual == expected, "new or unbound writable-parent sibling");
    parent.validate()
}
fn scoped_mounts<'a>(
    rows: &'a [Mount],
    common: u64,
    siblings: &BTreeMap<PathBuf, DirectoryIdentity>,
) -> Result<Vec<&'a Mount>> {
    let base = rows
        .iter()
        .find(|m| m.id == common)
        .context("descriptor mount not enrolled")?;
    ensure!(
        base.point == Path::new(PARENT) && base.options.contains("rw"),
        "wrong common writable mount"
    );
    for path in siblings.keys() {
        let mut exact = Vec::new();
        for row in rows.iter().filter(|m| m.point == *path) {
            if below_mount(rows, row.id, common)? {
                exact.push(row);
            }
        }
        ensure!(
            exact.len() == 1 && exact[0].options.contains("ro"),
            "sibling lacks exact read-only mount"
        );
    }
    let mut scoped = Vec::new();
    for row in rows {
        if row.point.starts_with(PARENT) && below_mount(rows, row.id, common)? {
            ensure!(
                !row.point.starts_with(CACHE_ROOT) && !row.point.starts_with(STATE),
                "submount over operational cache/state would invalidate leaf rename proof"
            );
            ensure!(
                row.id == common || row.options.contains("ro"),
                "writable submount bypasses sibling mask"
            );
            scoped.push(row);
        }
    }
    Ok(scoped)
}
fn topology(
    a: &Admission,
    parent: &Directory,
    cache: &Directory,
    state: &Directory,
) -> Result<Value> {
    enrollment(a)?;
    let text = fs::read_to_string("/proc/self/mountinfo")?;
    let rows = mounts(&text)?;
    let common = fd_mount(parent)?;
    ensure!(
        fd_mount(cache)? == common && fd_mount(state)? == common,
        "cache/state are not on the same actual writable mount"
    );
    let scoped = scoped_mounts(&rows, common, &a.protected_siblings)?;
    let mut descriptors = BTreeMap::new();
    for (path, identity) in &a.protected_siblings {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        ensure!(
            DirectoryIdentity::of(&file.metadata()?) == *identity,
            "opened protected sibling differs from admission"
        );
        let id = file_mount(&file)?;
        ensure!(
            scoped
                .iter()
                .any(|m| m.id == id && m.point == *path && m.options.contains("ro")),
            "actual sibling descriptor bypasses read-only mask"
        );
        descriptors.insert(path.clone(), id);
    }
    let mut covered_lower = Vec::new();
    for row in rows.iter().filter(|m| m.point.starts_with(PARENT)) {
        if !below_mount(&rows, row.id, common)? {
            covered_lower.push(row);
        }
    }
    let ro = |path: &Path| -> Result<()> {
        let resolved = rows
            .iter()
            .filter(|m| path.starts_with(&m.point))
            .max_by_key(|m| m.point.components().count())
            .context("missing ancestor mount")?;
        ensure!(
            resolved.options.contains("ro"),
            "home/system ancestor is not read-only"
        );
        Ok(())
    };
    ro(Path::new("/home/ubuntu"))?;
    ro(Path::new("/etc"))?;
    Ok(
        json!({"mountinfo_sha256":sha(text.as_bytes()),"common_mount_id":common,"cache_mount_id":fd_mount(cache)?,"state_mount_id":fd_mount(state)?,"protected_sibling_count":a.protected_siblings.len(),"private_parent_mounts":scoped,"protected_sibling_descriptor_mounts":descriptors,"covered_lower_mounts":covered_lower}),
    )
}
fn native(a: &Admission, p: &Profile) -> Result<Value> {
    ensure!(
        p.schema == "jetstreamer-snapshot92447542-operational-mount-profile-v1"
            && safe_unit(&p.unit)
            && p.invocation_id.len() == 32
            && p.invocation_id
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "invalid mount profile"
    );
    let expected = &p.expected_properties;
    let output_parent = a.output.parent().context("output parent missing")?;
    for (key, value) in [
        ("Id", p.unit.as_str()),
        ("InvocationID", p.invocation_id.as_str()),
        ("ActiveState", "active"),
        ("SubState", "running"),
        ("ControlPID", "0"),
        ("NRestarts", "0"),
        ("Type", "exec"),
        ("Restart", "no"),
        ("MemoryMax", "536870912"),
        ("MemorySwapMax", "0"),
        ("CPUQuotaPerSecUSec", "2s"),
        ("TasksMax", "128"),
        ("RuntimeMaxUSec", "3min"),
        ("NoNewPrivileges", "yes"),
        ("ProtectSystem", "strict"),
        ("ProtectHome", "read-only"),
        ("AllowedCPUs", "56-63"),
        ("CPUAffinity", "56-63"),
        ("KillMode", "control-group"),
        ("Delegate", "no"),
        ("BindPaths", ""),
        ("BindReadOnlyPaths", ""),
        ("TemporaryFileSystem", ""),
        ("RootDirectory", ""),
        ("RootImage", ""),
    ] {
        ensure!(
            expected.get(key).map(String::as_str) == Some(value),
            "mount profile property mismatch: {key}"
        );
    }
    for key in [
        "MainPID",
        "ExecStart",
        "User",
        "Group",
        "ReadWritePaths",
        "ReadOnlyPaths",
        "InaccessiblePaths",
        "CapabilityBoundingSet",
        "AmbientCapabilities",
        "ControlGroup",
    ] {
        ensure!(
            expected.contains_key(key),
            "mount profile property missing: {key}"
        );
    }
    let paths = |key: &str| {
        expected[key]
            .split_whitespace()
            .map(PathBuf::from)
            .collect::<BTreeSet<_>>()
    };
    ensure!(
        paths("ReadWritePaths")
            == BTreeSet::from([
                PathBuf::from(PARENT),
                PathBuf::from(CONFIG),
                output_parent.into()
            ])
            && paths("ReadOnlyPaths") == a.protected_siblings.keys().cloned().collect()
            && expected["InaccessiblePaths"].is_empty(),
        "unexpected mount write/mask scope"
    );
    ensure!(
        matches!(expected["User"].as_str(), "" | "root")
            && matches!(expected["Group"].as_str(), "" | "root")
            && expected["MainPID"] == std::process::id().to_string()
            && !expected["ExecStart"].is_empty()
            && env::var("INVOCATION_ID")? == p.invocation_id,
        "mount owner identity differs"
    );
    // Complete sibling masks exceed the shared retention reader's 64KiB cap.
    // Keep that shared contract unchanged; this finite, separately admitted
    // route permits at most 2MiB and still compares the complete exact map.
    let response = Command::new("/usr/bin/systemctl")
        .args([
            "show",
            &p.unit,
            "--no-pager",
            "--property",
            &expected.keys().cloned().collect::<Vec<_>>().join(","),
        ])
        .output()?;
    ensure!(
        response.status.success() && response.stdout.len() <= 2 << 20,
        "operational mount properties unavailable or oversized"
    );
    let mut actual = BTreeMap::new();
    for line in std::str::from_utf8(&response.stdout)?.lines() {
        let (key, value) = line.split_once('=').context("malformed mount property")?;
        ensure!(
            actual.insert(key.to_owned(), value.to_owned()).is_none(),
            "duplicate mount property"
        );
    }
    ensure!(
        actual == *expected,
        "actual mount service differs from sealed profile"
    );
    let group = format!("/system.slice/{}", p.unit);
    ensure!(
        expected["ControlGroup"] == group
            && fs::read_to_string("/proc/self/cgroup")? == format!("0::{group}\n"),
        "mount probe actual cgroup differs"
    );
    let text = fs::read_to_string("/proc/self/status")?;
    let status: BTreeMap<_, _> = text
        .lines()
        .map(|line| {
            let (k, v) = line.split_once(':').context("malformed kernel status")?;
            Ok((k.to_owned(), v.trim().to_owned()))
        })
        .collect::<Result<_>>()?;
    for key in ["Uid", "Gid"] {
        ensure!(
            status
                .get(key)
                .context("kernel identity missing")?
                .split_whitespace()
                .collect::<Vec<_>>()
                == vec!["0"; 4],
            "kernel Root identity differs"
        );
    }
    for key in ["CapEff", "CapPrm", "CapBnd"] {
        ensure!(
            u64::from_str_radix(status.get(key).context("kernel capabilities missing")?, 16)?
                == 0x800e3,
            "kernel capability envelope differs"
        );
    }
    ensure!(
        u64::from_str_radix(
            status
                .get("CapAmb")
                .context("ambient capabilities missing")?,
            16
        )? & !0x800e3
            == 0
            && status.get("NoNewPrivs").map(String::as_str) == Some("1")
            && status.get("Cpus_allowed_list").map(String::as_str) == Some("56-63"),
        "kernel privilege/CPU envelope differs"
    );
    let cg = Path::new("/sys/fs/cgroup").join(group.trim_start_matches('/'));
    for (file, value) in [
        ("memory.max", "536870912"),
        ("memory.swap.max", "0"),
        ("pids.max", "128"),
    ] {
        ensure!(
            fs::read_to_string(cg.join(file))?.trim() == value,
            "kernel mount probe resource differs"
        );
    }
    let cpu = fs::read_to_string(cg.join("cpu.max"))?;
    let cpu: Vec<_> = cpu.split_whitespace().collect();
    ensure!(
        cpu.len() == 2
            && cpu[1].parse::<u64>()? > 0
            && cpu[0].parse::<u64>()?
                == cpu[1]
                    .parse::<u64>()?
                    .checked_mul(2)
                    .context("CPU quota overflow")?,
        "kernel CPU quota differs"
    );
    Ok(json!({"properties":actual,"kernel_status":status,"actual_cgroup":group}))
}
fn lineage(a: &Admission) -> Result<()> {
    let b: Value = serde_json::from_slice(&root_bound_file(&a.normal_build, 1 << 20, true)?)?;
    ensure!(
        b["Main_accepted_normal_workspace_artifact_only"] == true
            && b["features"] == json!([])
            && b["actual_normal_binary"]["sha256"] == a.self_binary.sha256
            && b["actual_root_Cargo_artifact"]["profile"]["test"] == false
            && b["actual_normal_library_artifact"]["profile"]["test"] == false
            && b["actual_bin_extern_bound_to_normal_library_without_test_cfg"] == true
            && b["actual_workspace_release_profile"]["lto"] == true
            && b["actual_workspace_release_profile"]["codegen-units"] == 1
            && b["full_source_manifest"]
                == json!({"path":a.full_source_manifest.path,"sha256":a.full_source_manifest.sha256}),
        "mount probe normal build lineage differs"
    );
    let m: Value =
        serde_json::from_slice(&root_bound_file(&a.full_source_manifest, 8 << 20, true)?)?;
    let members = m["tracked_source_files"]
        .as_array()
        .context("source members missing")?;
    for (name, bytes) in [
        (
            "jetstreamer-horizon-observe/src/snapshot92447542_mount_probe.rs",
            include_bytes!("snapshot92447542_mount_probe.rs").as_slice(),
        ),
        (
            "jetstreamer-horizon-observe/src/snapshot92447542_cache.rs",
            include_bytes!("snapshot92447542_cache.rs").as_slice(),
        ),
        (
            "jetstreamer-horizon-observe/src/snapshot92447542_lifecycle_engine.rs",
            include_bytes!("snapshot92447542_lifecycle_engine.rs").as_slice(),
        ),
        (
            "jetstreamer-horizon-observe/Cargo.toml",
            include_bytes!("../Cargo.toml").as_slice(),
        ),
    ] {
        ensure!(
            members
                .iter()
                .any(|row| row["path"] == name && row["sha256"] == sha(bytes)),
            "mount probe compiled source differs"
        );
    }
    Ok(())
}
fn create(dir: &Directory, name: &str, bytes: &[u8]) -> Result<Identity> {
    dir.validate()?;
    let c = component(name)?;
    let fd = unsafe {
        libc::openat(
            dir.file.as_raw_fd(),
            c.as_ptr(),
            libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("create-new mount sentinel");
    }
    let mut f = unsafe { File::from_raw_fd(fd) };
    f.write_all(bytes)?;
    f.sync_all()?;
    let id = Identity::of(&f.metadata()?);
    ensure!(
        id.uid == 0
            && id.gid == 0
            && id.links == 1
            && id.mode & 0o177777 == 0o100600
            && id.length == bytes.len() as u64,
        "foreign mount sentinel identity"
    );
    dir.sync()?;
    ensure!(
        Identity::of(&fs::symlink_metadata(dir.path.join(name))?) == id,
        "mount sentinel replaced"
    );
    Ok(id)
}
fn inspect(dir: &Directory, name: &str, original: &Identity, bytes: &[u8]) -> Result<Identity> {
    let mut file = dir.open_file(name)?;
    let id = Identity::of(&file.metadata()?);
    ensure!(
        id.renamed_from(original),
        "mount sentinel inode/custody changed"
    );
    let mut content = Vec::new();
    (&mut file).take(4097).read_to_end(&mut content)?;
    ensure!(
        content == bytes
            && Identity::of(&file.metadata()?) == id
            && Identity::of(&fs::symlink_metadata(dir.path.join(name))?) == id,
        "mount sentinel bytes/path changed"
    );
    Ok(id)
}
fn protected(a: &Admission, cache: &Directory) -> Result<Value> {
    validate_original(&a.original_snapshot)?;
    ensure!(
        Identity::of(&fs::symlink_metadata(cache.path.join(NAME))?) == a.original_snapshot,
        "original snapshot changed"
    );
    // This reads only the small historical receipt; never the original body.
    let h = historical(cache)?;
    Ok(json!({"snapshot_identity":a.original_snapshot,"historical":h}))
}
pub(super) fn run(path: &str, admission_sha: &str, self_sha: &str) -> Result<()> {
    let admission = Bound {
        path: path.into(),
        sha256: admission_sha.into(),
    };
    let a: Admission = serde_json::from_slice(&root_bound_file(&admission, 4 << 20, true)?)?;
    let start = now()?;
    ensure!(
        a.schema == "jetstreamer-snapshot92447542-operational-mount-admission-v1"
            && a.issued_unix_seconds <= start
            && start <= a.expires_unix_seconds
            && a.expires_unix_seconds > a.issued_unix_seconds
            && a.expires_unix_seconds - a.issued_unix_seconds <= 180
            && a.self_binary.sha256 == self_sha,
        "expired/wrong mount admission"
    );
    root_bound_file(&a.self_binary, 256 << 20, true)?;
    ensure!(
        fs::canonicalize("/proc/self/exe")? == a.self_binary.path
            && Identity::of(&fs::metadata("/proc/self/exe")?)
                == Identity::of(&fs::symlink_metadata(&a.self_binary.path)?),
        "wrong actual mount probe executable"
    );
    lineage(&a)?;
    let profile: Profile = serde_json::from_slice(&root_bound_file(&a.profile, 4 << 20, true)?)?;
    let output_parent = a.output.parent().context("output parent missing")?;
    ensure!(
        a.output
            .file_name()
            .is_some_and(|n| n == "operational-mount-result.json")
            && output_parent.starts_with("/var/lib/jetstreamer")
            && output_parent.canonicalize()? == output_parent
            && absent(&a.output)?,
        "invalid mount probe result path"
    );
    private_dir(output_parent)?;
    let owner_before = native(&a, &profile)?;
    let parent = Directory::open(Path::new(PARENT), &a.parent_identity)?;
    let cache = Directory::open(Path::new(CACHE_ROOT), &a.cache_identity)?;
    let state = Directory::open(Path::new(STATE), &a.state_identity)?;
    ensure!(
        a.cache_identity.device == 66305
            && a.cache_identity.uid == 1000
            && a.cache_identity.gid == 1000
            && a.cache_identity.mode == 0o40700,
        "operational cache directory custody differs"
    );
    let before = protected(&a, &cache)?;
    let mounts_before = topology(&a, &parent, &cache, &state)?;
    ensure!(
        now()? <= a.expires_unix_seconds,
        "mount admission expired before mutation"
    );
    // Acquire the same lifecycle lock before even creating disposable sentinels.
    let _lock = lock(&state.path)?;
    let name = format!(".slot92447542-mount-probe-{}", profile.invocation_id);
    let collision = format!("{name}-collision");
    ensure!(
        cache.absent(&name)? && state.absent(&name)? && state.absent(&collision)?,
        "preexisting mount sentinel retained"
    );
    // Both files are <=4KiB, with distinct contents for collision verification.
    let bytes = format!(
        "slot92447542 mount sentinel {} {}\n",
        profile.invocation_id, admission_sha
    )
    .into_bytes();
    let foreign = b"owned collision witness, must not be overwritten\n";
    persist(
        &output_parent.join("operational-mount-intent.json"),
        &json!({
            "schema":"jetstreamer-snapshot92447542-operational-mount-intent-v1",
            "admission":bound_ref(&admission),"profile":bound_ref(&a.profile),"original":before,
            "cache_sentinel":cache.path.join(&name),"state_sentinel":state.path.join(&name),
            "collision_witness":state.path.join(&collision),"sentinel_sha256":sha(&bytes),
            "collision_sha256":sha(foreign),"shared_retirement_lock_may_be_created":true,
            "failure_policy":"Preserve exact owned files and intent on failure; no broad cleanup or foreign unlink."
        }),
    )?;
    let source = create(&cache, &name, &bytes)?;
    let destination = create(&state, &collision, foreign)?;
    let error = rename_noreplace(&cache, &name, &state, &collision)
        .err()
        .context("destination collision unexpectedly succeeded")?;
    ensure!(
        error
            .downcast_ref::<std::io::Error>()
            .and_then(std::io::Error::raw_os_error)
            == Some(libc::EEXIST),
        "collision did not return actual EEXIST"
    );
    inspect(&cache, &name, &source, &bytes)?;
    inspect(&state, &collision, &destination, foreign)?;
    rename_noreplace(&cache, &name, &state, &name)?;
    ensure!(
        cache.absent(&name)?,
        "source remains after quarantine rename"
    );
    let moved = inspect(&state, &name, &source, &bytes)?;
    rename_noreplace(&state, &name, &cache, &name)?;
    ensure!(
        state.absent(&name)?,
        "state sentinel remains after reverse rename"
    );
    let returned = inspect(&cache, &name, &source, &bytes)?;
    unlink_at(&cache, &name, &returned)?;
    unlink_at(&state, &collision, &destination)?;
    ensure!(
        cache.absent(&name)? && state.absent(&name)? && state.absent(&collision)?,
        "owned sentinels not retired"
    );
    let mounts_after = topology(&a, &parent, &cache, &state)?;
    let after = protected(&a, &cache)?;
    let owner_after = native(&a, &profile)?;
    ensure!(
        before == after
            && mounts_before == mounts_after
            && owner_before["properties"] == owner_after["properties"]
            && now()?.saturating_sub(start) < 180,
        "mount probe state/profile changed or exceeded deadline"
    );
    persist(
        &a.output,
        &json!({"schema":"jetstreamer-snapshot92447542-operational-mount-result-v1", "admission":bound_ref(&admission),
        "profile":bound_ref(&a.profile),"normal_build":bound_ref(&a.normal_build),"full_source_manifest":bound_ref(&a.full_source_manifest),
        "self_binary":bound_ref(&a.self_binary),"owner_before":owner_before,"owner_after":owner_after,
        "mounts_before":mounts_before,"mounts_after":mounts_after,"original_before":before,"original_after":after,
        "sentinel_original":source,"sentinel_moved":moved,"sentinel_returned":returned,"sentinel_sha256":sha(&bytes),
        "collision_preserved":true,"collision_errno":libc::EEXIST,"sentinels_removed":true,
        "actual_operational_cache_state_noreplace_rename_passed":true,"original_body_read":false,
        "campaign_reclaimed_bytes":0,"operational_lifecycle_qualified":false,"replay_authorized":false,"remote_mutations":false}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mount_parser_rejects_ambiguous_ids_options_and_bad_escapes() {
        let line =
            "123 1 259:1 /home/ubuntu/private /home/ubuntu/private rw,nosuid - ext4 /dev/test rw\n";
        let rows = mounts(line).unwrap();
        assert_eq!(rows[0].id, 123);
        assert!(mounts(&format!("{line}{line}")).is_err());
        assert!(mounts(&line.replace("rw,nosuid", "rw,ro")).is_err());
        assert!(mounts(&line.replace("rw,nosuid", "nosuid")).is_err());
        assert!(mounts(&line.replace("rw,nosuid", "rw,rw")).is_err());
        assert_eq!(unescape(r"/x\040y\134z").unwrap(), "/x y\\z");
        for value in [r"/x\", r"/x\09a", r"/x\777", r"/x\000"] {
            assert!(unescape(value).is_err());
        }
    }
    #[test]
    fn scoped_mounts_reject_missing_masks_nested_writes_and_separate_writable_binds() {
        let sibling = Path::new(PARENT).join("protected");
        let siblings = BTreeMap::from([(
            sibling.clone(),
            DirectoryIdentity {
                device: 1,
                inode: 2,
                uid: 1000,
                gid: 1000,
                mode: 0o40700,
            },
        )]);
        let base = format!("123 1 259:1 {PARENT} {PARENT} rw - ext4 /dev/test rw\n");
        let good = format!(
            "{base}124 123 259:1 {} {} ro - ext4 /dev/test rw\n",
            sibling.display(),
            sibling.display()
        );
        assert_eq!(
            scoped_mounts(&mounts(&good).unwrap(), 123, &siblings)
                .unwrap()
                .len(),
            2
        );
        let covered = format!(
            "{good}88 1 0:67 / {} rw - tmpfs tmpfs rw\n",
            sibling.display()
        );
        assert_eq!(
            scoped_mounts(&mounts(&covered).unwrap(), 123, &siblings)
                .unwrap()
                .len(),
            2
        );
        let cycle = format!(
            "{good}88 89 0:67 / {} rw - tmpfs tmpfs rw\n89 88 0:67 / {}/nested ro - tmpfs tmpfs rw\n",
            sibling.display(),
            sibling.display()
        );
        assert!(scoped_mounts(&mounts(&cycle).unwrap(), 123, &siblings).is_err());
        assert!(scoped_mounts(&mounts(&base).unwrap(), 123, &siblings).is_err());
        for point in [
            sibling.join("nested"),
            PathBuf::from(CACHE_ROOT),
            PathBuf::from(STATE),
        ] {
            let changed = format!(
                "{good}125 123 259:1 {} {} rw - ext4 /dev/test rw\n",
                point.display(),
                point.display()
            );
            assert!(scoped_mounts(&mounts(&changed).unwrap(), 123, &siblings).is_err());
        }
        assert!(scoped_mounts(&mounts(&good).unwrap(), 124, &siblings).is_err());
        for point in [
            Path::new(CACHE_ROOT).join(NAME),
            Path::new(STATE).join("retirement.lock"),
        ] {
            let leaf_mount = format!(
                "{good}125 123 259:1 {} {} ro - ext4 /dev/test rw\n",
                point.display(),
                point.display()
            );
            assert!(scoped_mounts(&mounts(&leaf_mount).unwrap(), 123, &siblings).is_err());
        }
    }
}
