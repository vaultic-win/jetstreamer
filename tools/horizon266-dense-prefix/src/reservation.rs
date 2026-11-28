use crate::{MEMORY_CAP, ROOT_CAP, Result, check};
use serde::Deserialize;
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    mem::MaybeUninit,
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const UNIT: &str = "epoch266-dense-prefix-convert-v1.service";
const ADMISSION_DIRECTORY: &str = "/var/lib/jetstreamer/horizon266-dense-prefix-admission-v1";

#[derive(Deserialize)]
struct Admission {
    schema: String,
    unit: String,
    source: PathBuf,
    trailer: PathBuf,
    output_directory: PathBuf,
    filesystem_device: u64,
    protected_existing_disk_bytes: u64,
    maximum_working_root_bytes: u64,
    allowed_cpus: String,
    recorded_unix_seconds: u64,
    expires_unix_seconds: u64,
}

pub(super) struct Reservation<'a> {
    admission: Admission,
    output_directory: &'a File,
}

fn now() -> io::Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .map_err(io::Error::other)
}

fn available(directory: &File) -> io::Result<u64> {
    let mut stat = MaybeUninit::<libc::statvfs>::uninit();
    if unsafe { libc::fstatvfs(directory.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let stat = unsafe { stat.assume_init() };
    stat.f_bavail
        .checked_mul(stat.f_frsize)
        .ok_or_else(|| io::Error::other("filesystem free-space overflow"))
}

impl<'a> Reservation<'a> {
    pub(super) fn enter(
        plan: &Path,
        source: &Path,
        trailer: &Path,
        output: &Path,
        output_directory: &'a File,
    ) -> Result<Self> {
        let parent = plan.parent().ok_or("missing admission directory")?;
        let parent_meta = fs::symlink_metadata(parent)?;
        check(
            parent == Path::new(ADMISSION_DIRECTORY)
                && parent.canonicalize()? == parent
                && parent_meta.is_dir()
                && parent_meta.uid() == 0
                && parent_meta.mode() & 0o022 == 0,
            "foreign epoch 266 admission directory",
        )?;
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(plan)?;
        let meta = file.metadata()?;
        check(
            meta.is_file()
                && meta.uid() == 0
                && meta.nlink() == 1
                && meta.mode() & 0o777 == 0o444
                && meta.len() <= 16_384,
            "unsafe epoch 266 admission receipt",
        )?;
        let mut bytes = Vec::new();
        (&mut file).take(16_385).read_to_end(&mut bytes)?;
        let admission: Admission = serde_json::from_slice(&bytes)?;
        let entry = now()?;
        check(
            admission.schema == "foundation-epoch266-dense-prefix-admission-v1"
                && admission.unit == UNIT
                && admission.source == source
                && admission.trailer == trailer
                && admission.output_directory == output
                && admission.filesystem_device == output_directory.metadata()?.dev()
                && admission.maximum_working_root_bytes == ROOT_CAP
                && admission.protected_existing_disk_bytes > 0
                && entry
                    .checked_sub(admission.recorded_unix_seconds)
                    .is_some_and(|age| age <= 120)
                && admission.expires_unix_seconds > entry,
            "epoch 266 admission is stale or differs from this conversion",
        )?;
        let invocation = std::env::var("INVOCATION_ID")?;
        check(
            invocation.len() == 32
                && invocation.bytes().all(|byte| byte.is_ascii_hexdigit())
                && fs::read_to_string("/proc/self/cgroup")?.trim()
                    == format!("0::/system.slice/{UNIT}"),
            "foreign conversion invocation or service scope",
        )?;
        let controllers = Path::new("/sys/fs/cgroup/system.slice").join(UNIT);
        let quota = fs::read_to_string(controllers.join("cpu.max"))?;
        let quotas: Vec<u64> = quota
            .split_whitespace()
            .map(str::parse)
            .collect::<std::result::Result<_, _>>()?;
        check(
            fs::read_to_string(controllers.join("memory.max"))?.trim() == MEMORY_CAP.to_string()
                && fs::read_to_string(controllers.join("memory.swap.max"))?.trim() == "0"
                && fs::read_to_string(controllers.join("cpuset.cpus.effective"))?.trim()
                    == admission.allowed_cpus
                && matches!(quotas.as_slice(), [limit, period] if *limit > 0 && limit <= period),
            "conversion service resources differ from admission",
        )?;
        let reservation = Self {
            admission,
            output_directory,
        };
        reservation.check(0)?;
        Ok(reservation)
    }

    pub(super) fn check(&self, allocated_bytes: u64) -> io::Result<()> {
        let remaining = ROOT_CAP
            .checked_sub(allocated_bytes)
            .ok_or_else(|| io::Error::other("conversion exceeded its allocation cap"))?;
        let required = self
            .admission
            .protected_existing_disk_bytes
            .checked_add(remaining)
            .ok_or_else(|| io::Error::other("conversion reservation overflow"))?;
        if now()? >= self.admission.expires_unix_seconds
            || available(self.output_directory)? < required
        {
            return Err(io::Error::other(
                "epoch 266 protected disk reservation no longer fits",
            ));
        }
        Ok(())
    }

    pub(super) fn check_file(&self, file: &File) -> io::Result<()> {
        let allocated = file
            .metadata()?
            .blocks()
            .checked_mul(512)
            .ok_or_else(|| io::Error::other("conversion allocation overflow"))?;
        self.check(allocated)
    }
}

pub(super) struct ReservedWriter<'a, 'dir> {
    file: &'a mut File,
    reservation: &'a Reservation<'dir>,
    last_check: Instant,
}

impl<'a, 'dir> ReservedWriter<'a, 'dir> {
    pub(super) fn new(file: &'a mut File, reservation: &'a Reservation<'dir>) -> io::Result<Self> {
        reservation.check_file(file)?;
        Ok(Self {
            file,
            reservation,
            last_check: Instant::now(),
        })
    }
}

impl Write for ReservedWriter<'_, '_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.last_check.elapsed() >= Duration::from_secs(1) {
            self.reservation.check_file(self.file)?;
            self.last_check = Instant::now();
        }
        self.file.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.reservation.check_file(self.file)?;
        self.file.flush()
    }
}
