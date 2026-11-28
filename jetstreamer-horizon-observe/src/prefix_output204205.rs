//! Metadata-only allocation evidence for the two exact live prefix producers.
//! No archive contents, configurable paths, independent census, or admission.
use super::*;
use std::{
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::ffi::OsStrExt,
    },
    path::Component,
};

const SCHEMA: &str = "jetstreamer-exact-prefix-output-file-v1";
const OWNER: u32 = 1000;
const MODE: u32 = libc::S_IFREG | 0o600;

#[derive(Clone, Copy, Debug)]
struct Profile {
    epoch: u64,
    range: &'static str,
    unit: &'static str,
    invocation: &'static str,
    pid: u64,
    start_ticks: u64,
    scratch: &'static str,
    output: &'static str,
}

const PROFILES: [Profile; 2] = [
    Profile {
        epoch: 204,
        range: "204-204",
        unit: "horizon-qualify-204-shrink-root-prefix-resource-fcbf3992-v1.service",
        invocation: "448da7f2a3a34217afe7e115120b3cea",
        pid: 3_822_861,
        start_ticks: 170_369_985,
        scratch: "/home/ubuntu/.jetstreamer-private/shrink-root-prefix-resource-204-fcbf3992-v1/scratch",
        output: "/home/ubuntu/.jetstreamer-private/shrink-root-prefix-resource-204-fcbf3992-v1/output/epoch-204-prefix.jet",
    },
    Profile {
        epoch: 205,
        range: "205-205",
        unit: "horizon-qualify-205-shrink-root-prefix-resource-5c01bf93-v1.service",
        invocation: "373359a11aef4993a1a949e19ff617c3",
        pid: 3_730_044,
        start_ticks: 169_848_742,
        scratch: "/home/ubuntu/.jetstreamer-private/shrink-root-prefix-resource-205-5c01bf93-v1/scratch",
        output: "/home/ubuntu/.jetstreamer-private/shrink-root-prefix-resource-205-5c01bf93-v1/output/epoch-205-prefix.jet",
    },
];

fn selected(replay: &ReplayConfig) -> Option<Profile> {
    PROFILES.into_iter().find(|p| {
        replay.range == p.range
            && replay.controller_unit == p.unit
            && replay.producer_unit == p.unit
            && replay.expected_controller_invocation_id == p.invocation
            && replay.expected_producer_invocation_id == p.invocation
            && replay.scratch_path == Path::new(p.scratch)
            && replay.worker_executable_basename == "historical-worker"
            && replay.append_log.is_none()
            && replay.private_archive223.is_none()
    })
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(super) struct Snapshot {
    device: u64,
    inode: u64,
    uid: u32,
    mode: u32,
    nlink: u64,
    logical_bytes: u64,
    allocated_bytes: u64,
}

fn allocated_bytes(blocks: u64) -> Result<u64> {
    blocks
        .checked_mul(512)
        .context("output allocation byte overflow")
}

impl Snapshot {
    fn capture(metadata: &fs::Metadata) -> Result<Self> {
        let value = Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            uid: metadata.uid(),
            mode: metadata.mode(),
            nlink: metadata.nlink(),
            logical_bytes: metadata.len(),
            allocated_bytes: allocated_bytes(metadata.blocks())?,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            self.inode > 0 && self.uid == OWNER && self.mode == MODE && self.nlink == 1,
            "output must be an ubuntu-owned singly linked mode-0600 regular file"
        );
        Ok(())
    }
}

// O_PATH cannot read the archive. Walk every component relative to a pinned
// directory FD, rejecting symlinks in parents as well as at the leaf.
fn metadata_handle(path: &Path) -> Result<File> {
    ensure!(path.is_absolute(), "output path is not absolute");
    let mut directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open("/")?;
    let mut components = path.components().peekable();
    ensure!(
        components.next() == Some(Component::RootDir),
        "output path lacks root"
    );
    while let Some(component) = components.next() {
        let Component::Normal(name) = component else {
            anyhow::bail!("output path has a noncanonical component");
        };
        let name = CString::new(name.as_bytes())?;
        let is_parent = components.peek().is_some();
        let flags = libc::O_PATH
            | libc::O_CLOEXEC
            | libc::O_NOFOLLOW
            | if is_parent { libc::O_DIRECTORY } else { 0 };
        // SAFETY: name is NUL terminated, directory is held for this syscall,
        // and a successful new descriptor is immediately owned by File.
        let fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
        ensure!(
            fd >= 0,
            "cannot inspect output component: {}",
            std::io::Error::last_os_error()
        );
        let opened = unsafe { File::from_raw_fd(fd) };
        if !is_parent {
            ensure!(
                opened.metadata()?.is_file(),
                "output leaf is not a regular file"
            );
            return Ok(opened);
        }
        directory = opened;
    }
    anyhow::bail!("output path has no leaf")
}

pub(super) struct Capture {
    // Keep the first inode alive until the second capture, preventing inode
    // recycling from disguising namespace replacement between metadata passes.
    _handle: File,
    snapshot: Snapshot,
}

fn capture(path: &Path) -> Result<Capture> {
    let handle = metadata_handle(path)?;
    let snapshot = Snapshot::capture(&handle.metadata()?)?;
    Ok(Capture {
        _handle: handle,
        snapshot,
    })
}

pub(super) struct Pending {
    profile: Profile,
    first: Result<Capture>,
}

pub(super) fn begin(replay: &ReplayConfig) -> Option<Pending> {
    selected(replay).map(|profile| Pending {
        profile,
        first: capture(Path::new(profile.output)),
    })
}

pub(super) fn second(pending: &Option<Pending>) -> Option<Result<Capture>> {
    pending
        .as_ref()
        .map(|p| capture(Path::new(p.profile.output)))
}

#[derive(Debug, Serialize)]
pub(super) struct Report {
    schema: &'static str,
    epoch: u64,
    producer_unit: &'static str,
    producer_invocation_id: &'static str,
    producer_main_pid: u64,
    producer_start_ticks: u64,
    path: &'static str,
    pass_1: Snapshot,
    pass_2: Snapshot,
    identity_stable: bool,
    append_only_growth: bool,
    invocation_binding_stable: bool,
    conservative_observed_physical_bytes: u64,
}

fn allocation_credit(first: &Snapshot, second: &Snapshot) -> Result<u64> {
    first.validate()?;
    second.validate()?;
    ensure!(
        first.device == second.device
            && first.inode == second.inode
            && first.uid == second.uid
            && first.mode == second.mode
            && first.nlink == second.nlink,
        "output file identity changed"
    );
    ensure!(
        second.logical_bytes >= first.logical_bytes
            && second.allocated_bytes >= first.allocated_bytes,
        "output file logical or allocated length shrank"
    );
    Ok(first.allocated_bytes.min(second.allocated_bytes))
}

fn bound_unit(profile: Profile, unit: &UnitObservation) -> Result<()> {
    ensure!(
        unit.unit == profile.unit
            && unit.invocation_id == profile.invocation
            && unit.main_pid == profile.pid
            && unit.restarts == 0
            && unit.load_state == "loaded"
            && unit.active_state == "active"
            && unit.sub_state == "running"
            && unit.result == "success"
            && unit.control_group == Path::new("/system.slice").join(profile.unit)
            && unit.cgroup.path == Path::new("/sys/fs/cgroup/system.slice").join(profile.unit)
            && unit.rss.stable_process_start_ticks(profile.pid)? == profile.start_ticks,
        "output producer unit or process identity differs"
    );
    Ok(())
}

fn report(
    profile: Profile,
    first: Capture,
    second: Capture,
    before: (&UnitObservation, &UnitObservation),
    after: (&UnitObservation, &UnitObservation),
    invocation_binding_stable: bool,
) -> Result<Report> {
    ensure!(
        invocation_binding_stable,
        "output invocation binding is unstable"
    );
    for unit in [before.0, before.1, after.0, after.1] {
        bound_unit(profile, unit)?;
    }
    let credit = allocation_credit(&first.snapshot, &second.snapshot)?;
    Ok(Report {
        schema: SCHEMA,
        epoch: profile.epoch,
        producer_unit: profile.unit,
        producer_invocation_id: profile.invocation,
        producer_main_pid: profile.pid,
        producer_start_ticks: profile.start_ticks,
        path: profile.output,
        pass_1: first.snapshot,
        pass_2: second.snapshot,
        identity_stable: true,
        append_only_growth: true,
        invocation_binding_stable: true,
        conservative_observed_physical_bytes: credit,
    })
}

pub(super) fn finish(
    pending: Option<Pending>,
    second: Option<Result<Capture>>,
    before: (&UnitObservation, &UnitObservation),
    after: (&UnitObservation, &UnitObservation),
    invocation_binding_stable: bool,
) -> Option<Report> {
    let pending = pending?;
    let result = (|| {
        report(
            pending.profile,
            pending.first?,
            second.context("second output metadata pass is absent")??,
            before,
            after,
            invocation_binding_stable,
        )
    })();
    match result {
        Ok(value) => Some(value),
        Err(error) => {
            // Preserve the existing healthy scratch observation. The new strict
            // consumer must refuse absent evidence rather than assume zero.
            eprintln!(
                "epoch {} output allocation evidence unavailable: {error:#}",
                pending.profile.epoch
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn snapshot() -> Snapshot {
        Snapshot {
            device: 42,
            inode: 77,
            uid: OWNER,
            mode: MODE,
            nlink: 1,
            logical_bytes: 10_000,
            allocated_bytes: 8_192,
        }
    }

    fn replay(profile: Profile) -> ReplayConfig {
        ReplayConfig {
            range: profile.range.into(),
            controller_unit: profile.unit.into(),
            expected_controller_invocation_id: profile.invocation.into(),
            producer_unit: profile.unit.into(),
            expected_producer_invocation_id: profile.invocation.into(),
            scratch_path: profile.scratch.into(),
            worker_executable_basename: "historical-worker".into(),
            append_log: None,
            private_archive223: None,
        }
    }

    fn unit(profile: Profile) -> UnitObservation {
        UnitObservation {
            unit: profile.unit.into(),
            invocation_id: profile.invocation.into(),
            load_state: "loaded".into(),
            active_state: "active".into(),
            sub_state: "running".into(),
            result: "success".into(),
            restarts: 0,
            main_pid: profile.pid,
            memory_current_bytes: 0,
            memory_peak_bytes: 0,
            control_group: Path::new("/system.slice").join(profile.unit),
            cgroup: CgroupObservation {
                path: Path::new("/sys/fs/cgroup/system.slice").join(profile.unit),
                io_counters_available: false,
                gauges: BTreeMap::new(),
                counters: BTreeMap::new(),
            },
            rss: rss::Report::test_process(profile.pid as u32, profile.start_ticks),
        }
    }

    fn fixture() -> (tempfile::TempDir, PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("epoch.jet");
        fs::write(&path, vec![42; 8192]).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        (temp, path)
    }

    fn synthetic_capture(snapshot: Snapshot) -> Capture {
        Capture {
            _handle: tempfile::tempfile().unwrap(),
            snapshot,
        }
    }

    #[test]
    fn only_exact_original_profiles_are_selected_without_io() {
        for profile in PROFILES {
            assert_eq!(selected(&replay(profile)).unwrap().epoch, profile.epoch);
            for mutation in 0..7 {
                let mut r = replay(profile);
                match mutation {
                    0 => r.range = "204-205".into(),
                    1 => r.controller_unit.push_str(".foreign"),
                    2 => r.producer_unit.push_str(".foreign"),
                    3 => r.expected_controller_invocation_id = "f".repeat(32),
                    4 => r.expected_producer_invocation_id = "f".repeat(32),
                    5 => r.scratch_path = "/arbitrary/scratch".into(),
                    _ => r.worker_executable_basename = "foreign-worker".into(),
                }
                assert!(selected(&r).is_none());
                assert!(begin(&r).is_none());
            }
            assert!(!Path::new(profile.output).starts_with(profile.scratch));
        }
    }

    #[test]
    fn minimum_physical_allocation_is_used_for_monotonic_append_growth() {
        let first = snapshot();
        let mut second = first.clone();
        second.logical_bytes += 100_000;
        second.allocated_bytes += 98_304;
        assert_eq!(allocation_credit(&first, &second).unwrap(), 8192);
        assert_eq!(allocation_credit(&first, &first).unwrap(), 8192);
    }

    #[test]
    fn sparse_logical_bytes_are_never_substituted_for_allocation() {
        let mut first = snapshot();
        first.logical_bytes = 160 << 30;
        first.allocated_bytes = 0;
        assert_eq!(allocation_credit(&first, &first).unwrap(), 0);
    }

    #[test]
    fn allocation_multiplication_is_checked_at_u64_boundary() {
        assert_eq!(
            allocated_bytes(u64::MAX / 512).unwrap(),
            u64::MAX / 512 * 512
        );
        assert!(allocated_bytes(u64::MAX / 512 + 1).is_err());
        assert_eq!(allocated_bytes(0).unwrap(), 0);
    }

    #[test]
    fn changed_metadata_and_logical_or_physical_shrink_are_rejected() {
        for mutation in 0..9 {
            let first = snapshot();
            let mut second = first.clone();
            match mutation {
                0 => second.device += 1,
                1 => second.inode += 1,
                2 => second.uid = 0,
                3 => second.mode = libc::S_IFREG | 0o400,
                4 => second.mode = libc::S_IFLNK | 0o600,
                5 => second.nlink = 2,
                6 => second.logical_bytes -= 1,
                7 => second.allocated_bytes -= 512,
                _ => second.inode = 0,
            }
            assert!(
                allocation_credit(&first, &second).is_err(),
                "mutation {mutation}"
            );
            if mutation != 6 && mutation != 7 {
                assert!(
                    allocation_credit(&second, &first).is_err(),
                    "first pass {mutation}"
                );
            }
        }
    }

    #[test]
    fn no_follow_walk_rejects_leaf_parent_links_nonregular_and_missing_files() {
        let (temp, path) = fixture();
        assert!(
            metadata_handle(&path)
                .unwrap()
                .metadata()
                .unwrap()
                .is_file()
        );
        let link = temp.path().join("link.jet");
        symlink(&path, &link).unwrap();
        assert!(metadata_handle(&link).is_err());
        let parent_link = temp.path().join("parent");
        symlink(temp.path(), &parent_link).unwrap();
        assert!(metadata_handle(&parent_link.join("epoch.jet")).is_err());
        assert!(metadata_handle(temp.path()).is_err());
        assert!(metadata_handle(&temp.path().join("missing.jet")).is_err());
        assert!(metadata_handle(Path::new("relative.jet")).is_err());
        let fifo = temp.path().join("pipe.jet");
        let raw = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(raw.as_ptr(), 0o600) }, 0);
        assert!(metadata_handle(&fifo).is_err());
    }

    #[test]
    fn handles_are_metadata_only_and_allocation_comes_from_stat_blocks() {
        let (_temp, path) = fixture();
        let mut handle = metadata_handle(&path).unwrap();
        let mut byte = [0];
        assert_eq!(
            handle.read(&mut byte).unwrap_err().raw_os_error(),
            Some(libc::EBADF)
        );
        let metadata = handle.metadata().unwrap();
        // The production profile is deliberately pinned to uid 1000. These
        // fixtures run under the same uid; a different test user uses synthetic
        // snapshots for the profile checks instead of weakening production.
        if metadata.uid() == OWNER {
            let captured = Snapshot::capture(&metadata).unwrap();
            assert_eq!(
                captured.allocated_bytes,
                metadata.blocks().checked_mul(512).unwrap()
            );
            assert_eq!(captured.logical_bytes, 8192);
        }
    }

    #[test]
    fn real_hardlink_and_mode_changes_refuse_metadata_credit() {
        let (temp, path) = fixture();
        fs::hard_link(&path, temp.path().join("hardlink.jet")).unwrap();
        assert!(capture(&path).is_err());
        fs::remove_file(temp.path().join("hardlink.jet")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(capture(&path).is_err());
    }

    #[test]
    fn replaced_namespace_is_detected_while_original_inode_is_pinned() {
        let (temp, path) = fixture();
        let held = metadata_handle(&path).unwrap();
        let before = held.metadata().unwrap();
        fs::rename(&path, temp.path().join("old.jet")).unwrap();
        fs::write(&path, vec![42; 8192]).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let after = metadata_handle(&path).unwrap().metadata().unwrap();
        assert_ne!(before.ino(), after.ino());
        if before.uid() == OWNER {
            assert!(
                allocation_credit(
                    &Snapshot::capture(&before).unwrap(),
                    &Snapshot::capture(&after).unwrap()
                )
                .is_err()
            );
        }
    }

    #[test]
    fn unit_binding_rejects_pid_reuse_restarts_and_foreign_census() {
        for profile in PROFILES {
            bound_unit(profile, &unit(profile)).unwrap();
            for mutation in 0..11 {
                let mut changed = unit(profile);
                match mutation {
                    0 => changed.main_pid += 1,
                    1 => changed.invocation_id = "a".repeat(32),
                    2 => changed.unit.push_str(".foreign"),
                    3 => changed.restarts = 1,
                    4 => changed.active_state = "inactive".into(),
                    5 => changed.sub_state = "dead".into(),
                    6 => changed.control_group = "/system.slice/foreign".into(),
                    7 => changed.cgroup.path = "/sys/fs/cgroup/foreign".into(),
                    8 => {
                        changed.rss =
                            rss::Report::test_process(profile.pid as u32, profile.start_ticks + 1)
                    }
                    9 => changed.rss = rss::Report::default(),
                    _ => changed.result = "exit-code".into(),
                }
                assert!(
                    bound_unit(profile, &changed).is_err(),
                    "mutation {mutation}"
                );
            }
        }
    }

    #[test]
    fn report_uses_closed_contract_and_same_sample_original_producer() {
        for profile in PROFILES {
            let before = unit(profile);
            let after = unit(profile);
            let mut growing = snapshot();
            growing.logical_bytes += 8192;
            growing.allocated_bytes += 8192;
            let report = report(
                profile,
                synthetic_capture(snapshot()),
                synthetic_capture(growing),
                (&before, &before),
                (&after, &after),
                true,
            )
            .unwrap();
            let value = serde_json::to_value(report).unwrap();
            assert_eq!(value["schema"], SCHEMA);
            assert_eq!(value["epoch"], profile.epoch);
            assert_eq!(value["producer_main_pid"], profile.pid);
            assert_eq!(value["producer_start_ticks"], profile.start_ticks);
            assert_eq!(value["path"], profile.output);
            assert_eq!(value["conservative_observed_physical_bytes"], 8192);
            assert_eq!(value.as_object().unwrap().len(), 13);
            assert_eq!(value["pass_1"].as_object().unwrap().len(), 7);
            assert_eq!(value["pass_1"]["mode"], 33152);
        }
    }

    #[test]
    fn failed_or_missing_metadata_never_becomes_a_successful_zero_credit() {
        let profile = PROFILES[0];
        let units = unit(profile);
        for failed_pass in 0..3 {
            let first = if failed_pass == 0 {
                Err(anyhow!("unavailable first pass"))
            } else {
                Ok(synthetic_capture(snapshot()))
            };
            let second = match failed_pass {
                1 => Some(Err(anyhow!("unavailable second pass"))),
                2 => None,
                _ => Some(Ok(synthetic_capture(snapshot()))),
            };
            assert!(
                finish(
                    Some(Pending { profile, first }),
                    second,
                    (&units, &units),
                    (&units, &units),
                    true
                )
                .is_none()
            );
        }
        assert!(finish(None, None, (&units, &units), (&units, &units), true).is_none());
    }

    #[test]
    fn changed_outer_binding_or_any_one_unit_snapshot_refuses_credit() {
        let profile = PROFILES[0];
        let original = unit(profile);
        assert!(
            report(
                profile,
                synthetic_capture(snapshot()),
                synthetic_capture(snapshot()),
                (&original, &original),
                (&original, &original),
                false
            )
            .is_err()
        );
        let mut changed = unit(profile);
        changed.main_pid += 1;
        for changed_index in 0..4 {
            let mut units = [&original; 4];
            units[changed_index] = &changed;
            assert!(
                report(
                    profile,
                    synthetic_capture(snapshot()),
                    synthetic_capture(snapshot()),
                    (units[0], units[1]),
                    (units[2], units[3]),
                    true
                )
                .is_err()
            );
        }
    }
}
