//! Closed parent telemetry for private epoch 223 archive stages. These are not
//! historical replay workers and never contribute slot-execution progress.
use super::*;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Bound {
    path: PathBuf,
    sha256: String,
}
#[derive(Clone, Copy, Debug, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Stage {
    Assembly,
    Verification,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Binding {
    stage: Stage,
    launch_receipt: Bound,
    executable: Bound,
}
#[derive(Clone, Debug, PartialEq, Serialize)]
struct ArchiveSnapshot {
    device: u64,
    inode: u64,
    length: u64,
}
fn archive_path(stage: Stage) -> &'static Path {
    match stage {
        Stage::Assembly | Stage::Verification => Path::new(
            "/var/lib/jetstreamer/horizon-223-native20-native25-private-assembly-v1/epoch-223-private-v3.jet",
        ),
    }
}
fn archive_snapshot(stage: Stage) -> Result<Option<ArchiveSnapshot>> {
    let path = archive_path(stage);
    ensure!(
        path.parent()
            .is_some_and(|p| p.canonicalize().is_ok_and(|c| c == p)),
        "private 223 archive snapshot parent redirected"
    );
    match fs::symlink_metadata(path) {
        Ok(m) => {
            ensure!(
                m.is_file()
                    && m.uid() == 0
                    && m.nlink() == 1
                    && m.mode() & 0o777 == 0o600
                    && m.len() <= 160u64 << 30,
                "private 223 archive snapshot type/owner/envelope differs"
            );
            Ok(Some(ArchiveSnapshot {
                device: m.dev(),
                inode: m.ino(),
                length: m.len(),
            }))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && stage == Stage::Assembly => Ok(None),
        Err(e) => Err(e.into()),
    }
}
fn snapshot_stable(stage: Stage, a: &Option<ArchiveSnapshot>, b: &Option<ArchiveSnapshot>) -> bool {
    match (a, b) {
        (None, None) | (None, Some(_)) => stage == Stage::Assembly,
        (Some(x), Some(y)) => {
            x.device == y.device
                && x.inode == y.inode
                && if stage == Stage::Assembly {
                    y.length >= x.length
                } else {
                    y.length == x.length
                }
        }
        _ => false,
    }
}
#[derive(Clone, Debug, PartialEq, Serialize)]
pub(super) struct Proof {
    stage: Stage,
    unit: String,
    invocation_id: String,
    main_pid: u64,
    launch_receipt: Bound,
    executable: Bound,
    ordinary_replay_worker: bool,
    archive_path: PathBuf,
    archive_snapshot: Option<ArchiveSnapshot>,
}
fn digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn opened(path: &Path, maximum: u64) -> Result<(File, fs::Metadata)> {
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "private archive telemetry path redirected"
    );
    let f = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o222 == 0
            && m.len() <= maximum,
        "private archive telemetry requires a bounded sealed root file"
    );
    Ok((f, m))
}
fn fingerprint(m: &fs::Metadata) -> (u64, u64, u64, i64, i64, i64, i64) {
    (
        m.dev(),
        m.ino(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}
fn bytes(b: &Bound) -> Result<Vec<u8>> {
    ensure!(
        digest(&b.sha256),
        "private archive telemetry digest malformed"
    );
    let (mut f, m) = opened(&b.path, 8 << 20)?;
    let mut raw = Vec::new();
    (&mut f).take((8 << 20) + 1).read_to_end(&mut raw)?;
    ensure!(
        raw.len() as u64 == m.len()
            && sha256(&raw) == b.sha256
            && fingerprint(&m) == fingerprint(&f.metadata()?)
            && fingerprint(&m) == fingerprint(&fs::symlink_metadata(&b.path)?),
        "private archive telemetry launch changed"
    );
    Ok(raw)
}
fn shape(r: &ReplayConfig, b: &Binding) -> Result<()> {
    let (unit, name) = match b.stage {
        Stage::Assembly => (
            "horizon-assemble-223-native20-native25-v1.service",
            "jetstreamer-epoch223-private-assemble",
        ),
        Stage::Verification => (
            "horizon-verify-223-native20-native25-private-v3-v1.service",
            "jetstreamer-epoch223-private-verify",
        ),
    };
    ensure!(
        r.range == "223-223"
            && r.controller_unit == unit
            && r.producer_unit == unit
            && r.expected_controller_invocation_id == r.expected_producer_invocation_id
            && r.worker_executable_basename == name
            && r.append_log.is_none()
            && digest(&b.executable.sha256),
        "private archive telemetry cannot borrow another worker/epoch/progress source"
    );
    ensure!(
        b.executable.path.file_name().and_then(|n| n.to_str()) == Some(name),
        "private archive telemetry executable name differs"
    );
    match b.stage {
        Stage::Assembly => ensure!(
            r.scratch_path
                == Path::new(
                    "/var/lib/jetstreamer/horizon-223-native20-native25-private-assembly-v1"
                )
                && b.executable.path
                    == Path::new(
                        "/var/lib/jetstreamer/horizon-223-private-assembly-tools-529fc90f-v1/jetstreamer-epoch223-private-assemble"
                    )
                && b.executable.sha256
                    == "d1475bc12efb6f543c6772735c9ff08667b1ecd99660b01d6a390fbf87773eab"
                && b.launch_receipt.path
                    == Path::new(
                        "/var/lib/jetstreamer/horizon-223-private-assembly-capture-v1/launch.json"
                    ),
            "private assembly telemetry scope differs"
        ),
        Stage::Verification => ensure!(
            r.scratch_path.parent() == Some(Path::new("/var/lib/jetstreamer"))
                && r.scratch_path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("horizon-223-private-v3-scan-"))
                && b.executable.path.parent().and_then(Path::parent)
                    == Some(Path::new("/var/lib/jetstreamer"))
                && b.executable
                    .path
                    .parent()
                    .and_then(Path::file_name)
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("horizon-223-private-v3-final-tools-"))
                && b.launch_receipt.path.parent().and_then(Path::parent)
                    == Some(Path::new("/var/lib/jetstreamer"))
                && b.launch_receipt
                    .path
                    .parent()
                    .and_then(Path::file_name)
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("horizon-223-private-verification-capture-"))
                && b.launch_receipt
                    .path
                    .file_name()
                    .is_some_and(|n| n == "launch.json"),
            "private verification telemetry scope differs"
        ),
    }
    Ok(())
}
pub(super) fn validate(r: &ReplayConfig) -> Result<()> {
    if let Some(b) = &r.private_archive223 {
        shape(r, b)?;
    }
    Ok(())
}
pub(super) fn observe(r: &ReplayConfig, producer: &UnitObservation) -> Result<WorkerObservation> {
    let b = r
        .private_archive223
        .as_ref()
        .context("private archive telemetry binding missing")?;
    shape(r, b)?;
    let launch: Value = serde_json::from_slice(&bytes(&b.launch_receipt)?)?;
    let schema = match b.stage {
        Stage::Assembly => "jetstreamer-private223-v3-assembly-launch-v1",
        Stage::Verification => "jetstreamer-private223-v3-verification-launch-v1",
    };
    let key = match b.stage {
        Stage::Assembly => "assembler_sha256",
        Stage::Verification => "verifier_sha256",
    };
    ensure!(
        launch["schema"] == schema
            && launch["epoch"] == 223
            && launch["unit"] == r.producer_unit
            && launch["invocation_id"] == producer.invocation_id
            && launch[key] == b.executable.sha256
            && launch["producer_at_capture"]["MainPID"].as_str()
                == Some(producer.main_pid.to_string().as_str())
            && producer.unit == r.producer_unit
            && producer.invocation_id == r.expected_producer_invocation_id
            && producer.main_pid > 1
            && producer.restarts == 0
            && producer.control_group == Path::new(&format!("/system.slice/{}", r.producer_unit)),
        "private archive parent is not the captured invocation"
    );
    let directory_key = match b.stage {
        Stage::Assembly => "output_root",
        Stage::Verification => "private_directory",
    };
    ensure!(
        launch[directory_key].as_str() == r.scratch_path.to_str()
            && r.scratch_path.canonicalize()? == r.scratch_path,
        "private archive telemetry is not the captured output directory"
    );
    ensure!(
        launch["ordinary_replay_claim"] == false
            && launch["publication_authorized"] == false
            && launch["r2_mutations"] == false,
        "private archive telemetry launch acquired authority"
    );
    let pid = producer.main_pid;
    let executable = fs::read_link(format!("/proc/{pid}/exe"))?;
    ensure!(
        executable == b.executable.path,
        "private archive parent executable changed"
    );
    let (mut file, m) = opened(&b.executable.path, 128 << 20)?;
    let mut hash = Sha256::new();
    let mut buf = [0u8; 131072];
    let mut total = 0u64;
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        total = total
            .checked_add(n as u64)
            .context("parent executable byte overflow")?;
        ensure!(total <= 128 << 20, "parent executable exceeds bound");
        hash.update(&buf[..n]);
    }
    ensure!(
        format!("{:x}", hash.finalize()) == b.executable.sha256
            && total == m.len()
            && fingerprint(&m) == fingerprint(&file.metadata()?)
            && fingerprint(&m) == fingerprint(&fs::symlink_metadata(&b.executable.path)?),
        "private archive parent executable digest/identity changed"
    );
    let process_exe = File::open(format!("/proc/{pid}/exe"))?;
    ensure!(
        fingerprint(&process_exe.metadata()?) == fingerprint(&m),
        "private archive parent executable inode differs"
    );
    let member = fs::read_to_string(format!("/proc/{pid}/cgroup"))?;
    ensure!(
        member
            .lines()
            .any(|l| l == format!("0::{}", producer.control_group.display())),
        "private archive parent cgroup changed"
    );
    let maps = fs::read_to_string(format!("/proc/{pid}/maps"))?;
    ensure!(
        fs::read_link(format!("/proc/{pid}/exe"))? == executable,
        "private archive parent changed during telemetry"
    );
    Ok(WorkerObservation {
        pid,
        executable,
        executable_beneath_bound_scratch: false,
        vmas: maps.lines().count() as u64,
        matching_workers: 1,
        private_archive_parent: Some(Proof {
            stage: b.stage,
            unit: r.producer_unit.clone(),
            invocation_id: producer.invocation_id.clone(),
            main_pid: pid,
            launch_receipt: b.launch_receipt.clone(),
            executable: b.executable.clone(),
            ordinary_replay_worker: false,
            archive_path: archive_path(b.stage).into(),
            archive_snapshot: archive_snapshot(b.stage)?,
        }),
    })
}
pub(super) fn stable(a: &WorkerObservation, b: &WorkerObservation) -> bool {
    a.private_archive_parent
        .as_ref()
        .zip(b.private_archive_parent.as_ref())
        .is_some_and(|(x, y)| {
            let mut left = x.clone();
            let mut right = y.clone();
            left.archive_snapshot = None;
            right.archive_snapshot = None;
            left == right
                && snapshot_stable(x.stage, &x.archive_snapshot, &y.archive_snapshot)
                && !x.ordinary_replay_worker
                && x.main_pid == a.pid
                && y.main_pid == b.pid
        })
        && !a.executable_beneath_bound_scratch
        && !b.executable_beneath_bound_scratch
}
#[cfg(test)]
mod tests {
    use super::*;
    fn config() -> ReplayConfig {
        let mut r = ReplayConfig {
            range: "223-223".into(),
            controller_unit: String::new(),
            producer_unit: String::new(),
            expected_controller_invocation_id: "1".repeat(32),
            expected_producer_invocation_id: "1".repeat(32),
            scratch_path: PathBuf::new(),
            worker_executable_basename: String::new(),
            append_log: None,
            private_archive223: None,
        };
        r.controller_unit = "horizon-assemble-223-native20-native25-v1.service".into();
        r.producer_unit = r.controller_unit.clone();
        r.expected_producer_invocation_id = r.expected_controller_invocation_id.clone();
        r.scratch_path =
            "/var/lib/jetstreamer/horizon-223-native20-native25-private-assembly-v1".into();
        r.worker_executable_basename = "jetstreamer-epoch223-private-assemble".into();
        r.private_archive223=Some(Binding{stage:Stage::Assembly,
            launch_receipt:Bound{path:"/var/lib/jetstreamer/horizon-223-private-assembly-capture-v1/launch.json".into(),sha256:"a".repeat(64)},
            executable:Bound{path:"/var/lib/jetstreamer/horizon-223-private-assembly-tools-529fc90f-v1/jetstreamer-epoch223-private-assemble".into(),sha256:"d1475bc12efb6f543c6772735c9ff08667b1ecd99660b01d6a390fbf87773eab".into()}});
        r
    }
    fn copy_observation(a: &WorkerObservation) -> WorkerObservation {
        WorkerObservation {
            pid: a.pid,
            executable: a.executable.clone(),
            executable_beneath_bound_scratch: a.executable_beneath_bound_scratch,
            vmas: a.vmas,
            matching_workers: a.matching_workers,
            private_archive_parent: a.private_archive_parent.clone(),
        }
    }
    #[test]
    fn exact_parent_binding_is_diagnostic_and_cannot_borrow_a_replay_or_other_directory() {
        let r = config();
        validate_replay_configs(&[], std::slice::from_ref(&r)).unwrap();
        assert!(validate_replay_configs(std::slice::from_ref(&r), &[]).is_err());
        for which in 0..4 {
            let mut bad = config();
            match which {
                0 => bad.range = "224-224".into(),
                1 => bad.scratch_path = "/other".into(),
                2 => bad.worker_executable_basename = "historical-worker".into(),
                _ => bad.private_archive223.as_mut().unwrap().executable.sha256 = "f".repeat(64),
            };
            assert!(validate_replay_configs(&[], &[bad]).is_err(), "{which}");
        }
    }
    #[test]
    fn sampled_archive_can_only_grow_under_exact_assembly_owner() {
        let before = Some(ArchiveSnapshot {
            device: 1,
            inode: 2,
            length: 100,
        });
        let grown = Some(ArchiveSnapshot {
            device: 1,
            inode: 2,
            length: 101,
        });
        assert!(snapshot_stable(Stage::Assembly, &before, &grown));
        assert!(!snapshot_stable(Stage::Verification, &before, &grown));
        assert!(!snapshot_stable(Stage::Assembly, &grown, &before));
        assert!(!snapshot_stable(Stage::Assembly, &before, &None));
        assert!(!snapshot_stable(
            Stage::Assembly,
            &before,
            &Some(ArchiveSnapshot {
                device: 1,
                inode: 3,
                length: 101
            })
        ));
        assert!(snapshot_stable(Stage::Assembly, &None, &grown));
        assert!(!snapshot_stable(Stage::Verification, &None, &grown));
    }
    #[test]
    fn parent_identity_does_not_claim_an_executable_beneath_replay_scratch() {
        let r = config();
        let binding = r.private_archive223.unwrap();
        let a = WorkerObservation {
            pid: 42,
            executable: binding.executable.path.clone(),
            executable_beneath_bound_scratch: false,
            vmas: 10,
            matching_workers: 1,
            private_archive_parent: Some(Proof {
                stage: binding.stage,
                unit: r.producer_unit,
                invocation_id: r.expected_producer_invocation_id,
                main_pid: 42,
                launch_receipt: binding.launch_receipt,
                executable: binding.executable,
                ordinary_replay_worker: false,
                archive_path: archive_path(binding.stage).into(),
                archive_snapshot: None,
            }),
        };
        assert!(stable_worker(&a, &a));
        let mut bad = copy_observation(&a);
        bad.private_archive_parent = None;
        assert!(!stable_worker(&a, &bad));
        let mut bad = copy_observation(&a);
        bad.private_archive_parent
            .as_mut()
            .unwrap()
            .ordinary_replay_worker = true;
        assert!(!stable_worker(&a, &bad));
        let mut bad = copy_observation(&a);
        bad.executable_beneath_bound_scratch = true;
        assert!(!stable_worker(&a, &bad));
    }
}
