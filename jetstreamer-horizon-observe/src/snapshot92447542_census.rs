//! Fixed, read-only discovery for the slot92447542 consumer review.
//! Captures unit inputs and references. It never interprets an absent literal as
//! a complete readset and grants no check, eviction, restore or launch authority.
use {
    crate::{
        bootstrap227_cache_retire::{persist, private_dir},
        dev_cache_check, process_references,
        ram_artifact_retention::{self as evidence, Bound},
        snapshot92447542_cache,
    },
    anyhow::{Context, Result, ensure},
    serde::Deserialize,
    serde_json::{Value, json},
    sha2::{Digest, Sha256},
    std::{
        collections::{BTreeMap, BTreeSet},
        env,
        fs::{self, File, OpenOptions},
        io::{Read, Write},
        os::unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        },
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    },
};
const CACHE: &str = "/home/ubuntu/.jetstreamer-private/qualification-later-snapshots";
const NAME: &str = "snapshot-92447542-4gX8J8Y3c36L6W4D38ax2RYShfKmYxHWuDHAkQKeNzqd.tar.zst";
const ROOTS: &[&str] = &[
    "/etc/systemd/system",
    "/run/systemd/transient",
    "/run/systemd/system",
    "/usr/lib/systemd/system",
    "/lib/systemd/system",
    "/run/systemd/generator",
    "/run/systemd/generator.early",
    "/run/systemd/generator.late",
    "/run/systemd/system.control",
    "/etc/systemd/system.control",
    "/run/systemd/system.attached",
    "/etc/systemd/system.attached",
    "/usr/local/lib/systemd/user",
    "/usr/lib/systemd/user",
    "/etc/systemd/user",
    "/run/systemd/user",
    "/run/user/1000/systemd/user",
    "/run/user/1000/systemd/generator",
    "/run/user/1000/systemd/generator.early",
    "/run/user/1000/systemd/generator.late",
    "/usr/local/lib/systemd/system",
    "/usr/local/etc/systemd/system",
    "/home/ubuntu/.config/systemd/user",
    "/home/ubuntu/.config/systemd/user.control",
    "/home/ubuntu/.local/share/systemd/user",
    "/run/user/1000/systemd/user.control",
    "/run/user/1000/systemd/transient",
    "/usr/local/share/systemd/user",
    "/usr/share/systemd/user",
];
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Admission {
    schema: String,
    self_binary: Bound,
    issued_unix_seconds: u64,
    expires_unix_seconds: u64,
    unit: String,
    invocation_id: String,
    expected_exec_start: String,
    output: PathBuf,
}
fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn digest(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
fn identity(m: &fs::Metadata) -> Value {
    json!([
        m.dev(),
        m.ino(),
        m.len(),
        m.nlink(),
        m.uid(),
        m.gid(),
        m.mode(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec()
    ])
}
fn read_input(path: &Path) -> Result<(Vec<u8>, Value)> {
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let before = f.metadata()?;
    ensure!(
        before.is_file() && before.len() <= 1 << 20,
        "nonregular/oversized staged input"
    );
    let mut bytes = Vec::new();
    (&mut f).take((1 << 20) + 1).read_to_end(&mut bytes)?;
    let id = identity(&before);
    ensure!(
        bytes.len() as u64 == before.len()
            && id == identity(&f.metadata()?)
            && id == identity(&fs::symlink_metadata(path)?),
        "staged input changed while reading"
    );
    Ok((bytes, id))
}
// Capture every discovered unit/config input, including lexical aliases. The
// independently reviewed source/argument expansion is a separate requirement.
fn capture(roots: &[&Path], destination: &Path) -> Result<Value> {
    fs::create_dir(destination)?;
    fs::set_permissions(destination, fs::Permissions::from_mode(0o700))?;
    let mut queue: Vec<_> = roots.iter().map(|p| (p.to_path_buf(), 0u32)).collect();
    let mut directories = BTreeSet::new();
    let mut directory_entries = BTreeMap::new();
    let mut files = BTreeMap::new();
    let mut aliases = Vec::new();
    let mut absent = Vec::new();
    let mut entries = 0u64;
    let mut total = 0u64;
    while let Some((path, depth)) = queue.pop() {
        entries += 1;
        ensure!(
            entries <= 65536 && depth <= 32,
            "unit capture bound exceeded"
        );
        let original = match fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                absent.push(path);
                continue;
            }
            Err(e) => return Err(e.into()),
        };
        let link = if original.file_type().is_symlink() {
            Some(fs::read_link(&path)?)
        } else {
            None
        };
        let canonical = match path.canonicalize() {
            Ok(p) => p,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && link.is_some() => {
                aliases.push(json!({"path":path,"link":link,"identity":identity(&original),"target_missing":true}));
                continue;
            }
            Err(e) => {
                return Err(e).with_context(|| format!("resolve staged input {}", path.display()));
            }
        };
        if let Some(link) = &link {
            ensure!(
                fs::read_link(&path)? == *link
                    && identity(&original) == identity(&fs::symlink_metadata(&path)?),
                "staged alias changed"
            );
            aliases.push(json!({"path":path,"link":link,"canonical":canonical,"identity":identity(&original),"target_missing":false}));
        }
        if canonical == Path::new("/dev/null") {
            continue;
        }
        let m = fs::symlink_metadata(&canonical)?;
        if m.is_dir() {
            if directories.insert(canonical.clone()) {
                let mut children = fs::read_dir(&canonical)?
                    .map(|e| Ok(e?.path()))
                    .collect::<Result<Vec<_>>>()?;
                children.sort();
                directory_entries.insert(
                    canonical.clone(),
                    json!({"identity":identity(&m),"children":children}),
                );
                queue.extend(children.into_iter().map(|p| (p, depth + 1)));
            }
        } else if !files.contains_key(&canonical) {
            let (bytes, id) = read_input(&canonical)?;
            total = total
                .checked_add(bytes.len() as u64)
                .context("capture byte overflow")?;
            ensure!(total <= 256 << 20, "unit capture byte bound exceeded");
            let sha = digest(&bytes);
            let saved = destination.join(&sha);
            if !saved.try_exists()? {
                let mut f = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o400)
                    .custom_flags(libc::O_NOFOLLOW)
                    .open(&saved)?;
                f.write_all(&bytes)?;
                f.sync_all()?;
            } else {
                ensure!(read_input(&saved)?.0 == bytes, "capture digest collision");
            }
            files.insert(
                canonical,
                json!({"sha256":sha,"bytes":bytes.len(),"identity":id,"captured_source":saved}),
            );
        }
    }
    File::open(destination)?.sync_all()?;
    Ok(
        json!({"roots":roots,"directories":directories,"directory_entries":directory_entries,"files":files,"aliases":aliases,"absent_roots_or_entries":absent,"entries":entries,"total_input_bytes":total}),
    )
}
fn validate_capture(c: &Value) -> Result<()> {
    for (name, row) in c["directory_entries"]
        .as_object()
        .context("directory capture missing")?
    {
        let path = Path::new(name);
        let mut children = fs::read_dir(path)?
            .map(|e| Ok(e?.path()))
            .collect::<Result<Vec<_>>>()?;
        children.sort();
        ensure!(
            identity(&fs::symlink_metadata(path)?) == row["identity"]
                && serde_json::to_value(children)? == row["children"],
            "staged directory enrollment changed"
        );
    }
    for (name, row) in c["files"].as_object().context("file capture missing")? {
        let (bytes, id) = read_input(Path::new(name))?;
        ensure!(
            id == row["identity"] && digest(&bytes) == row["sha256"],
            "staged input changed after capture"
        );
    }
    for row in c["aliases"].as_array().context("alias capture missing")? {
        let path = Path::new(row["path"].as_str().context("alias path missing")?);
        ensure!(
            identity(&fs::symlink_metadata(path)?) == row["identity"]
                && fs::read_link(path)?.as_os_str().as_bytes()
                    == row["link"]
                        .as_str()
                        .context("alias target missing")?
                        .as_bytes(),
            "staged alias changed after capture"
        );
        if row["target_missing"] == true {
            ensure!(
                path.canonicalize()
                    .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
                "dangling alias became present"
            );
        } else {
            ensure!(
                path.canonicalize()?
                    == Path::new(
                        row["canonical"]
                            .as_str()
                            .context("canonical alias missing")?
                    ),
                "staged alias destination changed"
            );
        }
    }
    for row in c["absent_roots_or_entries"]
        .as_array()
        .context("absent capture missing")?
    {
        let path = Path::new(row.as_str().context("absent path missing")?);
        ensure!(
            fs::symlink_metadata(path).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
            "absent staged root appeared"
        );
    }
    Ok(())
}
fn load_paths() -> Result<Value> {
    let mut observed = BTreeMap::new();
    for (kind, args) in [
        ("system", vec!["unit-paths"]),
        ("ubuntu-user", vec!["--user", "unit-paths"]),
    ] {
        let output = std::process::Command::new("/usr/bin/systemd-analyze")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", "/home/ubuntu")
            .env("XDG_RUNTIME_DIR", "/run/user/1000")
            .args(args)
            .output()?;
        ensure!(
            output.status.success() && output.stdout.len() <= 16384,
            "native unit load-path query failed"
        );
        let paths = String::from_utf8(output.stdout)?
            .lines()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        ensure!(
            paths.iter().all(|p| ROOTS.contains(&p.as_str())),
            "unenrolled actual system/user unit load path"
        );
        observed.insert(kind, paths);
    }
    Ok(serde_json::to_value(observed)?)
}
fn owner(a: &Admission) -> Result<Value> {
    ensure!(
        a.unit.ends_with(".service")
            && a.unit
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
            && a.invocation_id.len() == 32
            && a.invocation_id
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "invalid owner binding"
    );
    let p = evidence::properties(
        &a.unit,
        "Id,ActiveState,SubState,InvocationID,MainPID,ControlPID,NRestarts,ControlGroup,ExecStart,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec,TasksMax,RuntimeMaxUSec,NoNewPrivileges,ProtectSystem,ProtectHome,ReadWritePaths",
    )?;
    for (k, v) in [
        ("Id", a.unit.as_str()),
        ("ActiveState", "active"),
        ("SubState", "running"),
        ("InvocationID", a.invocation_id.as_str()),
        ("NRestarts", "0"),
        ("ControlPID", "0"),
        ("ExecStart", a.expected_exec_start.as_str()),
        ("MemoryMax", "536870912"),
        ("MemorySwapMax", "0"),
        ("CPUQuotaPerSecUSec", "2s"),
        ("TasksMax", "128"),
        ("RuntimeMaxUSec", "3min"),
        ("NoNewPrivileges", "yes"),
        ("ProtectSystem", "strict"),
        ("ProtectHome", "read-only"),
    ] {
        ensure!(
            p.get(k).map(String::as_str) == Some(v),
            "census native property changed: {k}"
        );
    }
    ensure!(
        p["MainPID"] == std::process::id().to_string()
            && p["ReadWritePaths"]
                == a.output
                    .parent()
                    .context("output parent missing")?
                    .to_str()
                    .context("output parent UTF8")?
            && env::var("INVOCATION_ID")? == a.invocation_id,
        "census owner/write scope mismatch"
    );
    let group = format!("/system.slice/{}", a.unit);
    ensure!(
        p["ControlGroup"] == group
            && fs::read_to_string("/proc/self/cgroup")? == format!("0::{group}\n"),
        "census actual cgroup changed"
    );
    Ok(serde_json::to_value(p)?)
}
/// One bounded foreground discovery. No caller-provided scan target or exclusions.
pub fn run() -> Result<()> {
    let args: Vec<_> = env::args().skip(1).collect();
    ensure!(args.len() == 2, "usage: BIN ADMISSION ADMISSION_SHA256");
    ensure!(unsafe { libc::geteuid() } == 0, "census requires Root");
    let bound = Bound {
        path: PathBuf::from(&args[0]),
        sha256: args[1].clone(),
    };
    let a: Admission = serde_json::from_value(evidence::bound_json(&bound)?)?;
    ensure!(
        a.schema == "jetstreamer-snapshot92447542-consumer-census-admission-v1"
            && a.issued_unix_seconds <= now()?
            && now()? <= a.expires_unix_seconds
            && a.expires_unix_seconds > a.issued_unix_seconds
            && a.expires_unix_seconds - a.issued_unix_seconds <= 180,
        "census admission expired/wrong route"
    );
    let self_path = fs::canonicalize("/proc/self/exe")?;
    ensure!(
        self_path == a.self_binary.path && self_path.canonicalize()? == self_path,
        "census executable path mismatch"
    );
    let (sha, m) = evidence::hash_file(&self_path, 256 << 20)?;
    ensure!(
        sha == a.self_binary.sha256 && m.uid() == 0 && m.mode() & 0o222 == 0,
        "census executable binding mismatch"
    );
    let output_parent = a.output.parent().context("output parent missing")?;
    private_dir(output_parent)?;
    ensure!(
        a.output.file_name().is_some_and(|n| n == "census.json") && !a.output.try_exists()?,
        "census output occupied/unsafe"
    );
    let before = owner(&a)?;
    let actual_unit_load_paths = load_paths()?;
    let roots: Vec<_> = ROOTS.iter().map(Path::new).collect();
    let capture = capture(&roots, &output_parent.join("unit-inputs"))?;
    let mut missing = Vec::new();
    let staged = dev_cache_check::staged_references_exact(
        &roots,
        Path::new(CACHE),
        &mut missing,
        &BTreeSet::new(),
    )?;
    let target = Path::new(CACHE).join(NAME);
    let m = fs::symlink_metadata(&target)?;
    ensure!(
        m.is_file()
            && m.dev() == 66305
            && m.ino() == 2508808
            && m.len() == 8894131881
            && m.uid() == 1000
            && m.mode() & 0o7777 == 0o600,
        "original cache identity changed"
    );
    let cache_identity = identity(&m);
    let inode_refs =
        snapshot92447542_cache::inode_references(Path::new("/proc"), m.dev(), m.ino())?;
    let live = process_references::scan(Path::new("/proc"), &target)?;
    validate_capture(&capture)?;
    ensure!(
        load_paths()? == actual_unit_load_paths,
        "unit load paths changed during census"
    );
    ensure!(
        identity(&fs::symlink_metadata(&target)?) == cache_identity,
        "cache identity changed during census"
    );
    let after = owner(&a)?;
    ensure!(
        before == after && now()? <= a.expires_unix_seconds,
        "census owner/clock changed"
    );
    persist(
        &a.output,
        &json!({"schema":"jetstreamer-snapshot92447542-staged-consumer-discovery-v1","admission":{"path":bound.path,"sha256":bound.sha256},"completed_unix_seconds":now()?,"before":before,"after":after,"actual_system_and_ubuntu_user_load_paths":actual_unit_load_paths,"unit_input_capture":capture,"unexcluded_literal_parent_references":staged,"missing_inactive_unit_aliases":missing,"original_cache_identity":cache_identity,"inode_alias_references":inode_refs,"live_exact_path_references":live,"interpretation_complete":false,"readset_expansion_review_still_required":true,"metadata_only":true,"cache_body_read":false,"retirement_authorized":false,"restore_authorized":false,"replay_authorized":false,"remote_mutations":false}),
    )?;
    println!("slot92447542 bounded consumer discovery captured; interpretation still required");
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn lexical_alias_and_content_are_bound_and_replacement_rejects() {
        let t = tempfile::tempdir().unwrap();
        let units = t.path().join("units");
        fs::create_dir(&units).unwrap();
        let input = units.join("fixture.service");
        fs::write(&input, b"[Service]\nExecStart=/fixture\n").unwrap();
        std::os::unix::fs::symlink(&input, units.join("alias.service")).unwrap();
        let c = capture(&[&units], &t.path().join("captured")).unwrap();
        assert_eq!(c["aliases"].as_array().unwrap().len(), 1);
        validate_capture(&c).unwrap();
        fs::rename(&input, units.join("old")).unwrap();
        fs::write(&input, b"[Service]\nExecStart=/fixture\n").unwrap();
        assert!(validate_capture(&c).is_err());
    }
    #[test]
    fn dangling_alias_and_absent_root_cannot_silently_become_live() {
        let t = tempfile::tempdir().unwrap();
        let units = t.path().join("units");
        fs::create_dir(&units).unwrap();
        let absent = units.join("absent.service");
        std::os::unix::fs::symlink(&absent, units.join("alias.service")).unwrap();
        let c = capture(
            &[&units, &t.path().join("missing-root")],
            &t.path().join("captured"),
        )
        .unwrap();
        validate_capture(&c).unwrap();
        fs::write(&absent, b"changed").unwrap();
        assert!(validate_capture(&c).is_err());
    }
    #[test]
    fn newly_enrolled_unit_rejects_even_without_a_cache_literal() {
        let t = tempfile::tempdir().unwrap();
        let units = t.path().join("units");
        fs::create_dir(&units).unwrap();
        let c = capture(&[&units], &t.path().join("captured")).unwrap();
        fs::write(units.join("new.service"), b"ExecStart=/other/launcher").unwrap();
        assert!(validate_capture(&c).is_err());
    }
    #[test]
    fn discovery_preserves_expansion_carriers_without_asserting_readsets() {
        let t = tempfile::tempdir().unwrap();
        let units = t.path().join("units");
        fs::create_dir(&units).unwrap();
        let bytes=b"[Service]\nEnvironmentFile=/root/input.env\nWorkingDirectory=/fixture\nExecStart=/fixture/launcher ${INPUT} %i\n";
        fs::write(units.join("fixture@.service"), bytes).unwrap();
        let c = capture(&[&units], &t.path().join("captured")).unwrap();
        let row = c["files"].as_object().unwrap().values().next().unwrap();
        assert_eq!(
            fs::read(row["captured_source"].as_str().unwrap()).unwrap(),
            bytes
        );
        validate_capture(&c).unwrap();
    }
}
