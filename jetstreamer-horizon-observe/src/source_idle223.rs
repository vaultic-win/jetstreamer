//! Closed current-source-idle checks shared by 223 admission and assembly.
//! Historical success/lineage must be authenticated by the handoff caller.
//! No resource sample, file mutation, service action, signal or remote access.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs, io,
    path::Path,
    process::Command,
};

#[derive(Clone, Copy, Debug)]
pub enum Source {
    Prefix,
    Tail,
}
impl Source {
    pub fn unit(self) -> &'static str {
        match self {
            Self::Prefix => "horizon-qualify-223-v1620-root-prefix-resource-full-v1.service",
            Self::Tail => "horizon-qualify-223-v1625-tail-1743245a-v3.service",
        }
    }
    pub fn historical_invocation(self) -> &'static str {
        match self {
            Self::Prefix => "e70aaf097e7c4583b216aba454145910",
            Self::Tail => "20dc145d1e8c41fdbc682046b6fe4289",
        }
    }
    pub fn archive(self) -> &'static Path {
        Path::new(match self {
            Self::Prefix => {
                "/home/ubuntu/.jetstreamer-private/qualification-223-v1620-prefix-full-root-v1/output/epoch-223.jet"
            }
            Self::Tail => {
                "/home/ubuntu/.jetstreamer-private/qualification-223-v1625-tail-1743245a-v3/output/epoch-223.jet"
            }
        })
    }
}
// Keep the public historical Source API closed and unchanged. The later
// assembly owner has an actual future invocation, supplied only after its
// separate completion/PID1 history has been authenticated by the caller.
#[derive(Clone, Copy)]
struct Owner<'a> {
    unit: &'static str,
    invocation: &'a str,
    archive: &'a Path,
}
impl<'a> Owner<'a> {
    fn unit(self) -> &'static str {
        self.unit
    }
    fn historical_invocation(self) -> &'a str {
        self.invocation
    }
    fn archive(self) -> &'a Path {
        self.archive
    }
}
impl From<Source> for Owner<'static> {
    fn from(source: Source) -> Self {
        Self {
            unit: source.unit(),
            invocation: source.historical_invocation(),
            archive: source.archive(),
        }
    }
}
fn assembly_owner(invocation: &str) -> Result<Owner<'_>> {
    ensure!(
        invocation.len() == 32
            && invocation
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && invocation.bytes().any(|b| b != b'0'),
        "invalid actual 223 assembly invocation"
    );
    Ok(Owner {
        unit: "horizon-assemble-223-native20-native25-v1.service",
        invocation,
        archive: Path::new(
            "/var/lib/jetstreamer/horizon-223-native20-native25-private-assembly-v1/epoch-223-private-v3.jet",
        ),
    })
}
fn verification_owner<'a>(invocation: &'a str, archive: &'a Path) -> Result<Owner<'a>> {
    // Reuse the exact nonzero invocation grammar; do not infer historical success.
    assembly_owner(invocation)?;
    ensure!(
        archive.is_absolute()
            && archive.file_name().is_some_and(|n| n == "epoch-223.jet")
            && archive.parent().is_some_and(|directory| directory.parent()
                == Some(Path::new("/var/lib/jetstreamer"))
                && directory
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("horizon-223-private-v3-scan-")
                        && n.len() > "horizon-223-private-v3-scan-".len()
                        && n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))),
        "verification archive escaped the private 223 scan namespace"
    );
    Ok(Owner {
        unit: "horizon-verify-223-native20-native25-private-v3-v1.service",
        invocation,
        archive,
    })
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn unit_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 256
        && name.contains('.')
        && !name.starts_with('.')
        && name.bytes().all(|b| b.is_ascii_graphic() && b != b'/')
}
fn loaded(bytes: &[u8]) -> Result<BTreeSet<String>> {
    ensure!(
        bytes.len() <= 8 << 20,
        "oversized complete loaded-unit census"
    );
    let mut names = BTreeSet::new();
    for line in std::str::from_utf8(bytes)?
        .lines()
        .filter(|s| !s.trim().is_empty())
    {
        let fields: Vec<_> = line.split_whitespace().collect();
        ensure!(
            fields.len() >= 4 && unit_name(fields[0]) && names.insert(fields[0].to_owned()),
            "malformed/duplicate loaded-unit census row"
        );
    }
    ensure!(!names.is_empty(), "empty complete loaded-unit census");
    Ok(names)
}
fn jobs(bytes: &[u8]) -> Result<BTreeSet<String>> {
    ensure!(
        bytes.len() <= 8 << 20,
        "oversized complete pending-job census"
    );
    let text = std::str::from_utf8(bytes)?.trim();
    if text.is_empty() || text == "No jobs running." {
        return Ok(BTreeSet::new());
    }
    let mut result = BTreeSet::new();
    let mut ids = BTreeSet::new();
    for line in text.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        ensure!(
            fields.len() >= 4
                && fields[0].parse::<u64>().is_ok()
                && ids.insert(fields[0])
                && unit_name(fields[1]),
            "malformed/duplicate job census row"
        );
        result.insert(fields[1].to_owned());
    }
    Ok(result)
}
fn properties(bytes: &[u8]) -> Result<Value> {
    ensure!(bytes.len() <= 16384, "oversized terminal-source properties");
    let mut fields = serde_json::Map::new();
    for line in std::str::from_utf8(bytes)?.lines() {
        let (key, value) = line
            .split_once('=')
            .context("malformed source-unit property")?;
        ensure!(
            fields.insert(key.into(), json!(value)).is_none(),
            "duplicate source-unit property"
        );
    }
    Ok(Value::Object(fields))
}
fn loaded_terminal(source: Owner<'_>, p: &Value) -> Result<()> {
    for (key, value) in [
        ("Id", source.unit()),
        ("LoadState", "loaded"),
        ("MainPID", "0"),
        ("NRestarts", "0"),
        ("Restart", "no"),
        ("Result", "success"),
        ("ExecMainStatus", "0"),
        ("ActiveState", "inactive"),
        ("SubState", "dead"),
        ("Job", ""),
    ] {
        ensure!(p[key] == value, "source loaded manager differs: {key}");
    }
    ensure!(
        p["InvocationID"] == "" || p["InvocationID"] == source.historical_invocation(),
        "source manager is another invocation"
    );
    ensure!(
        p["ControlGroup"] == "" || p["ControlGroup"] == format!("/system.slice/{}", source.unit()),
        "source cgroup escaped exact unit"
    );
    Ok(())
}
struct Snapshot {
    present: bool,
    properties: Option<Value>,
    evidence: Value,
}
fn validate_snapshot(
    source: Owner<'_>,
    units: &[u8],
    pending: &[u8],
    props: Option<Value>,
) -> Result<Snapshot> {
    let units_set = loaded(units)?;
    let pending_set = jobs(pending)?;
    ensure!(
        !pending_set.contains(source.unit()),
        "source has a queued manager job"
    );
    let present = units_set.contains(source.unit());
    match (present, &props) {
        (true, Some(p)) => loaded_terminal(source, p)?,
        (false, None) => (),
        _ => anyhow::bail!("source manager presence/properties contradict complete census"),
    }
    Ok(Snapshot {
        present,
        properties: props.clone(),
        evidence: json!({"complete_loaded_unit_census":true,
        "loaded_unit_count":units_set.len(),"loaded_unit_census_sha256":digest(units),"source_unit_present":present,
        "complete_pending_job_census":true,"pending_job_census_sha256":digest(pending),"source_pending_jobs":0,
        "loaded_properties":props}),
    })
}
fn output(args: &[&str], maximum: usize) -> Result<Vec<u8>> {
    let out = Command::new("/usr/bin/systemctl")
        .env("LC_ALL", "C")
        .env("SYSTEMD_COLORS", "0")
        .args(args)
        .output()?;
    ensure!(
        out.status.success() && out.stdout.len() <= maximum,
        "complete source-manager query failed/oversized"
    );
    Ok(out.stdout)
}
fn snapshot(source: Owner<'_>) -> Result<Snapshot> {
    let units = output(
        &[
            "list-units",
            "--all",
            "--plain",
            "--no-legend",
            "--no-pager",
            "--full",
        ],
        8 << 20,
    )?;
    let pending = output(
        &["list-jobs", "--all", "--no-legend", "--no-pager", "--full"],
        8 << 20,
    )?;
    let props = if loaded(&units)?.contains(source.unit()) {
        Some(properties(&output(
            &[
                "show",
                source.unit(),
                "--property=Id,LoadState,InvocationID,MainPID,NRestarts,Restart,Result,ExecMainStatus,ActiveState,SubState,Job,ControlGroup",
            ],
            16384,
        )?)?)
    } else {
        None
    };
    validate_snapshot(source, &units, &pending, props)
}
fn group(cgroup_root: &Path, source: Owner<'_>) -> Result<Value> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let parent = cgroup_root.join("system.slice");
    ensure!(
        cgroup_root.canonicalize()? == cgroup_root
            && parent.canonicalize()? == parent
            && fs::symlink_metadata(&parent)?.is_dir(),
        "source cgroup parent redirected/absent"
    );
    let path = parent.join(source.unit());
    let metadata = match fs::symlink_metadata(&path) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Ok(json!({"path":path,"state":"absent"}));
        }
        Err(e) => return Err(e.into()),
    };
    ensure!(
        metadata.is_dir() && path.canonicalize()? == path,
        "source cgroup redirected/non-directory"
    );
    let event_path = path.join("cgroup.events");
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&event_path)?;
    use std::io::Read;
    let mut bytes = Vec::new();
    (&mut file).take(4097).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 4096, "oversized cgroup events");
    let mut events = BTreeMap::new();
    for line in std::str::from_utf8(&bytes)?.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        ensure!(
            fields.len() == 2 && events.insert(fields[0], fields[1]).is_none(),
            "malformed/duplicate cgroup events"
        );
    }
    ensure!(
        events.get("populated") == Some(&"0"),
        "original source cgroup or descendant remains populated"
    );
    let after = fs::symlink_metadata(&path)?;
    ensure!(
        after.dev() == metadata.dev() && after.ino() == metadata.ino() && after.is_dir(),
        "source cgroup changed during check"
    );
    Ok(
        json!({"path":path,"state":"unpopulated","device":metadata.dev(),"inode":metadata.ino(),"events_sha256":digest(&bytes)}),
    )
}
fn stable(before: &Snapshot, after: &Snapshot) -> Result<()> {
    ensure!(
        before.present == after.present && before.properties == after.properties,
        "source manager changed across reference census"
    );
    Ok(())
}
/// Admission-control/lifecycle check; never a routine replay/resource sampler.
/// An unloaded unit is accepted only after successful complete manager queries,
/// no queued job, empty/absent exact cgroup and a complete archive-reference scan.
pub fn observe(source: Source) -> Result<Value> {
    observe_owner(source.into())
}
/// Current idle only for the fixed private 223 assembler. This does not prove
/// historical success; caller must first bind its real completion and PID1
/// terminal evidence. No future invocation or positive receipt is invented.
pub fn observe_assembly(invocation: &str) -> Result<Value> {
    observe_owner(assembly_owner(invocation)?)
}
/// Current idle only for the exact private 223 verifier and canonical-name copy.
/// The caller must independently authenticate genuine terminal success first.
pub fn observe_verification(invocation: &str, archive: &Path) -> Result<Value> {
    observe_owner(verification_owner(invocation, archive)?)
}
fn observe_owner(source: Owner<'_>) -> Result<Value> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "source-idle census requires root"
    );
    let before = snapshot(source)?;
    let cgroup_before = group(Path::new("/sys/fs/cgroup"), source)?;
    let references = crate::process_references::scan(Path::new("/proc"), source.archive())?;
    ensure!(
        references.references.is_empty(),
        "source archive still has a live process reference"
    );
    let cgroup_after = group(Path::new("/sys/fs/cgroup"), source)?;
    let after = snapshot(source)?;
    stable(&before, &after)?;
    Ok(
        json!({"schema":"jetstreamer-epoch223-source-idle-v1","source_archive":source.archive(),"unit":source.unit(),
        "historical_invocation_id":source.historical_invocation(),"current_source_idle":true,
        "current_manager_state":if before.present {"loaded-terminal-success"}else{"unloaded-confirmed-by-complete-manager-censuses"},
        "manager_before":before.evidence,"manager_after":after.evidence,"cgroup_before":cgroup_before,"cgroup_after":cgroup_after,
        "process_reference_census":references,"historical_success_proven_by_this_check":false,
        "resource_sample_performed":false,"publication_authorized":false,"replay_launch_authorized":false,"r2_mutations":false}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn terminal(source: Owner<'_>) -> Value {
        json!({"Id":source.unit(),"LoadState":"loaded","MainPID":"0","NRestarts":"0","Restart":"no",
        "Result":"success","ExecMainStatus":"0","ActiveState":"inactive","SubState":"dead","Job":"","InvocationID":source.historical_invocation(),"ControlGroup":""})
    }
    #[test]
    fn assembly_owner_is_exact_and_requires_the_real_nonzero_lowercase_invocation() {
        let id = "1234567890abcdef1234567890abcdef";
        let owner = assembly_owner(id).unwrap();
        assert_eq!(
            owner.unit(),
            "horizon-assemble-223-native20-native25-v1.service"
        );
        assert_eq!(
            owner.archive(),
            Path::new(
                "/var/lib/jetstreamer/horizon-223-native20-native25-private-assembly-v1/epoch-223-private-v3.jet"
            )
        );
        let units = format!("{} loaded inactive dead Exact assembly\n", owner.unit());
        validate_snapshot(owner, units.as_bytes(), b"", Some(terminal(owner))).unwrap();
        validate_snapshot(
            owner,
            b"unrelated.service loaded active running X\n",
            b"",
            None,
        )
        .unwrap();
        let mut wrong = terminal(owner);
        wrong["InvocationID"] = json!("a".repeat(32));
        assert!(validate_snapshot(owner, units.as_bytes(), b"", Some(wrong)).is_err());
        for bad in [
            "",
            "0",
            "00000000000000000000000000000000",
            "1234567890ABCDEF1234567890abcdef",
            "1234567890abcdef1234567890abcdeg",
        ] {
            assert!(assembly_owner(bad).is_err(), "{bad}");
        }
    }
    #[test]
    fn verification_owner_is_scoped_to_one_private_scan_copy() {
        let iid = "1".repeat(32);
        let good =
            Path::new("/var/lib/jetstreamer/horizon-223-private-v3-scan-attempt1/epoch-223.jet");
        let owner = verification_owner(&iid, good).unwrap();
        assert_eq!(owner.archive(), good);
        assert_eq!(
            owner.unit(),
            "horizon-verify-223-native20-native25-private-v3-v1.service"
        );
        for bad in [
            "/tmp/horizon-223-private-v3-scan-attempt1/epoch-223.jet",
            "/var/lib/jetstreamer/horizon-223-private-v3-scan-/epoch-223.jet",
            "/var/lib/jetstreamer/horizon-223-private-v3-scan-attempt1/epoch-224.jet",
            "/var/lib/jetstreamer/horizon-223-private-v3-scan-attempt1/sub/epoch-223.jet",
            "/var/lib/jetstreamer/horizon-223-private-v3-scan-../epoch-223.jet",
        ] {
            assert!(verification_owner(&iid, Path::new(bad)).is_err(), "{bad}");
        }
        assert!(verification_owner(&"0".repeat(32), good).is_err());
    }
    #[test]
    fn complete_unloaded_census_is_distinct_from_failed_show_or_missing_properties() {
        let source = Owner::from(Source::Tail);
        let units = b"unrelated.service loaded active running Example\n";
        let s = validate_snapshot(source, units, b"No jobs running.", None).unwrap();
        assert!(!s.present);
        assert!(validate_snapshot(source, units, b"", Some(terminal(source))).is_err());
        let units = format!("{} loaded inactive dead Original\n", source.unit());
        assert!(validate_snapshot(source, units.as_bytes(), b"", None).is_err());
        assert!(loaded(b"Failed to list units").is_err());
        assert!(jobs(b"permission denied").is_err());
    }
    #[test]
    fn loaded_sources_require_exact_terminal_identity_and_no_queue() {
        for source in [Source::Prefix, Source::Tail].map(Owner::from) {
            let units = format!("{} loaded inactive dead Original\n", source.unit());
            let good = terminal(source);
            validate_snapshot(source, units.as_bytes(), b"", Some(good.clone())).unwrap();
            for (key, value) in [
                ("InvocationID", "foreign"),
                ("MainPID", "12"),
                ("NRestarts", "1"),
                ("Result", "exit-code"),
                ("ExecMainStatus", "1"),
                ("ActiveState", "active"),
                ("LoadState", "not-found"),
                ("Job", "21"),
            ] {
                let mut bad = good.clone();
                bad[key] = json!(value);
                assert!(
                    validate_snapshot(source, units.as_bytes(), b"", Some(bad)).is_err(),
                    "{key}"
                );
            }
            let pending = format!("7 {} start waiting\n", source.unit());
            assert!(
                validate_snapshot(
                    source,
                    b"unrelated.service loaded active running X\n",
                    pending.as_bytes(),
                    None
                )
                .is_err()
            );
        }
    }
    #[test]
    fn partial_duplicate_or_changing_manager_snapshots_refuse() {
        let source = Owner::from(Source::Prefix);
        let line = format!("{} loaded inactive dead X\n", source.unit());
        assert!(loaded(format!("{line}{line}").as_bytes()).is_err());
        assert!(jobs(b"1 x.service start waiting\n1 y.service start waiting\n").is_err());
        assert!(properties(b"Id=a\nId=b\n").is_err());
        let absent = validate_snapshot(
            source,
            b"unrelated.service loaded active running X\n",
            b"",
            None,
        )
        .unwrap();
        let present =
            validate_snapshot(source, line.as_bytes(), b"", Some(terminal(source))).unwrap();
        assert!(stable(&absent, &present).is_err());
    }
    #[test]
    fn descendant_population_and_cgroup_aliases_are_not_idle() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("system.slice").join(Source::Prefix.unit());
        fs::create_dir(root.path().join("system.slice")).unwrap();
        assert_eq!(
            group(root.path(), Source::Prefix.into()).unwrap()["state"],
            "absent"
        );
        fs::create_dir_all(&path).unwrap();
        fs::write(path.join("cgroup.events"), b"populated 0\nfrozen 0\n").unwrap();
        assert_eq!(
            group(root.path(), Source::Prefix.into()).unwrap()["state"],
            "unpopulated"
        );
        fs::write(path.join("cgroup.events"), b"populated 1\nfrozen 0\n").unwrap();
        assert!(group(root.path(), Source::Prefix.into()).is_err());
        fs::remove_file(path.join("cgroup.events")).unwrap();
        symlink("/not-allowed", path.join("cgroup.events")).unwrap();
        assert!(group(root.path(), Source::Prefix.into()).is_err());
    }
}
