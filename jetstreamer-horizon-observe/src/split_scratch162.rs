//! The split 162 worker and scratch directory are visible in the producer's mount namespace.

use {
    super::{ReplayConfig, UnitObservation, WorkerObservation, read_bounded},
    anyhow::{Context, Result, ensure},
    serde::Serialize,
    serde_json::Value,
    sha2::{Digest, Sha256},
    std::{
        fs,
        os::unix::fs::MetadataExt,
        path::{Path, PathBuf},
    },
};

pub(super) const UNIT: &str = "horizon-qualify-162-first-hourly-completion-20261127-v2.service";
const SCRATCH: &str =
    "/home/sol/.jetstreamer-private/epoch162-first-hourly-completion-20261127-v2/scratch";
const HELD: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch162-first-hourly-completion-20261127-v2/split-v1/HELD_OWNER.json";

#[derive(Debug, PartialEq, Serialize)]
pub(super) struct View {
    pub(super) path: PathBuf,
    producer_pid: u64,
    mount_namespace_inode: u64,
    scratch_device: u64,
    scratch_inode: u64,
    worker_inode: u64,
    held_owner_sha256: String,
}

fn check_files(
    root: &Path,
    scratch: &Path,
    worker_exe: &Path,
    kernel_exe: &Path,
    device: u64,
) -> Result<(PathBuf, u64, u64)> {
    ensure!(
        worker_exe.starts_with(scratch) && worker_exe != scratch,
        "162 worker outside scratch"
    );
    let path = root.join(scratch.strip_prefix("/")?);
    let scratch_meta = fs::symlink_metadata(&path)?;
    let worker_meta = fs::symlink_metadata(root.join(worker_exe.strip_prefix("/")?))?;
    let kernel_meta = fs::metadata(kernel_exe)?;
    ensure!(
        scratch_meta.is_dir()
            && scratch_meta.dev() == device
            && worker_meta.is_file()
            && worker_meta.dev() == device
            && (worker_meta.dev(), worker_meta.ino()) == (kernel_meta.dev(), kernel_meta.ino()),
        "162 producer scratch or executable differs from the held mount"
    );
    Ok((path, scratch_meta.ino(), worker_meta.ino()))
}

pub(super) fn capture(
    replay: &ReplayConfig,
    producer: &UnitObservation,
    worker: &WorkerObservation,
) -> Result<Option<View>> {
    if replay.producer_unit != UNIT {
        return Ok(None);
    }
    ensure!(
        replay.controller_unit == UNIT
            && replay.range == "162"
            && replay.scratch_path == Path::new(SCRATCH)
            && replay.worker_executable_basename == "historical-worker"
            && producer.main_pid > 1
            && producer.invocation_id == replay.expected_controller_invocation_id
            && producer.invocation_id == replay.expected_producer_invocation_id,
        "different split 162 assignment"
    );
    let held_path = Path::new(HELD);
    let meta = fs::symlink_metadata(held_path)?;
    ensure!(
        meta.uid() == 0 && meta.mode() & 0o222 == 0 && fs::canonicalize(held_path)? == held_path,
        "unsealed 162 held owner"
    );
    let bytes = read_bounded(held_path, 64 << 10, "162 held owner")?;
    let held: Value = serde_json::from_slice(&bytes)?;
    let proc = Path::new("/proc").join(producer.main_pid.to_string());
    let stat = fs::read_to_string(proc.join("stat"))?;
    let ticks: u64 = stat
        .rsplit_once(')')
        .and_then(|(_, tail)| tail.split_whitespace().nth(19))
        .context("unreadable 162 producer start ticks")?
        .parse()?;
    ensure!(
        held["producer_unit"] == UNIT
            && held["producer_invocation_id"] == producer.invocation_id
            && held["producer_pid"] == producer.main_pid
            && held["start_ticks"] == ticks
            && held["boot_id"] == fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim()
            && fs::read_to_string(producer.cgroup.path.join("cgroup.procs"))?
                .lines()
                .any(|line| line.parse::<u64>().ok() == Some(worker.pid)),
        "unbound 162 producer or worker"
    );
    let device = held["mounts"]["scratch_device"]
        .as_u64()
        .context("162 held owner lacks scratch device")?;
    let (path, scratch_inode, worker_inode) = check_files(
        &proc.join("root"),
        &replay.scratch_path,
        &worker.executable,
        &Path::new("/proc").join(worker.pid.to_string()).join("exe"),
        device,
    )?;
    Ok(Some(View {
        path,
        scratch_device: device,
        scratch_inode,
        worker_inode,
        producer_pid: producer.main_pid,
        mount_namespace_inode: fs::metadata(proc.join("ns/mnt"))?.ino(),
        held_owner_sha256: format!("{:x}", Sha256::digest(&bytes)),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn split_worker_can_be_enrolled_only_as_a_diagnostic() {
        let cfg: ReplayConfig = serde_json::from_value(serde_json::json!({
            "range": "162", "controller_unit": UNIT, "producer_unit": UNIT,
            "expected_controller_invocation_id": "a".repeat(32), "expected_producer_invocation_id": "a".repeat(32),
            "scratch_path": SCRATCH, "worker_executable_basename": "historical-worker",
        })).unwrap();
        assert!(crate::validate_replay_configs(std::slice::from_ref(&cfg), &[]).is_err());
        crate::validate_replay_configs(&[], &[cfg]).unwrap();
    }

    #[test]
    fn scan_uses_producer_view_and_authenticates_worker_inode() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let scratch = Path::new("/private/scratch");
        let executable = scratch.join("bound/historical-worker");
        fs::create_dir_all(root.join("private/scratch/bound")).unwrap();
        let file = root.join("private/scratch/bound/historical-worker");
        fs::write(&file, b"worker").unwrap();
        let kernel = root.join("exe");
        std::os::unix::fs::symlink(&file, &kernel).unwrap();
        let dev = fs::metadata(&file).unwrap().dev();
        let (path, _, ino) = check_files(root, scratch, &executable, &kernel, dev).unwrap();
        assert_eq!(path, root.join("private/scratch"));
        for _ in 0..2 {
            let scan = crate::scan_scratch(&path).unwrap();
            assert_eq!(scan.regular_files, 1);
            assert_eq!(scan.directories, 2);
        }
        assert_eq!(ino, fs::metadata(&kernel).unwrap().ino());
        assert!(check_files(root, scratch, &executable, &kernel, dev + 1).is_err());
        let other = root.join("other");
        fs::write(&other, b"worker").unwrap();
        assert!(check_files(root, scratch, &executable, &other, dev).is_err());
    }
}
