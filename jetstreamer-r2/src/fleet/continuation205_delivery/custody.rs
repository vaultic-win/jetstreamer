//! Frozen tuples, writer census and first measured copy. These functions are
//! called only after the typed root startup release by the payload executor.
use super::*;
use std::io::{BufRead, Read, Write};
use std::time::{Duration, Instant};
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Stamp {
    pub device: u64,
    pub inode: u64,
    pub bytes: u64,
    pub links: u64,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub mtime: i64,
    pub mtime_nanos: i64,
    pub ctime: i64,
    pub ctime_nanos: i64,
}
impl Stamp {
    pub fn of(m: &fs::Metadata) -> Self {
        Self {
            device: m.dev(),
            inode: m.ino(),
            bytes: m.len(),
            links: m.nlink(),
            uid: m.uid(),
            gid: m.gid(),
            mode: m.mode(),
            mtime: m.mtime(),
            mtime_nanos: m.mtime_nsec(),
            ctime: m.ctime(),
            ctime_nanos: m.ctime_nsec(),
        }
    }
    pub fn frozen(&self) -> Result<()> {
        ensure!(
            self.bytes > 0
                && self.bytes <= OUTPUT_MAX
                && self.links == 1
                && self.uid == 0
                && self.mode & libc::S_IFMT == libc::S_IFREG
                && self.mode & 0o7777 == 0o400,
            "205 source is not exact root0400 single-link bounded regular data"
        );
        Ok(())
    }
}
pub(super) fn open(path: &Path) -> Result<File> {
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "205 source path redirected"
    );
    Ok(OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?)
}
pub(super) fn tuple(path: &Path) -> Result<Stamp> {
    let f = open(path)?;
    let stamp = Stamp::of(&f.metadata()?);
    stamp.frozen()?;
    Ok(stamp)
}
fn stream(input: &mut impl Read, output: &mut impl Write, expected: u64) -> Result<String> {
    let mut hash = Sha256::new();
    let mut total = 0u64;
    let mut buf = [0u8; 65536];
    loop {
        let n = input.read(&mut buf)?;
        if n == 0 {
            break;
        }
        total = total
            .checked_add(n as u64)
            .context("205 measured copy length overflow")?;
        ensure!(total <= expected, "205 measured source grew");
        hash.update(&buf[..n]);
        output.write_all(&buf[..n])?;
    }
    ensure!(total == expected, "205 measured source was truncated");
    Ok(hex_lower(&hash.finalize()))
}
#[derive(Serialize)]
pub(super) struct Measured {
    pub source: PathBuf,
    pub source_identity: Stamp,
    pub copy: PathBuf,
    pub copy_identity: Stamp,
    pub bytes: u64,
    pub sha256: String,
}
pub(super) fn copy_and_measure(source: &Path, target: &Path, expected: &Stamp) -> Result<Measured> {
    expected.frozen()?;
    let mut input = open(source)?;
    ensure!(
        Stamp::of(&input.metadata()?) == *expected
            && Stamp::of(&fs::symlink_metadata(source)?) == *expected,
        "205 source tuple changed before first measurement"
    );
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(target)?;
    let sha256 = stream(&mut input, &mut output, expected.bytes)?;
    ensure!(
        Stamp::of(&input.metadata()?) == *expected
            && Stamp::of(&fs::symlink_metadata(source)?) == *expected,
        "205 source changed during first copy-and-measure"
    );
    output.sync_all()?;
    File::open(target.parent().context("205 copy parent")?)?.sync_all()?;
    let copied = Stamp::of(&output.metadata()?);
    copied.frozen()?;
    ensure!(
        copied.bytes == expected.bytes,
        "205 copied tuple length differs"
    );
    Ok(Measured {
        source: source.into(),
        source_identity: expected.clone(),
        copy: target.into(),
        copy_identity: copied,
        bytes: expected.bytes,
        sha256,
    })
}
pub(super) fn hash_exact(path: &Path, expected: &Stamp, digest: &str) -> Result<()> {
    expected.frozen()?;
    ensure!(is_lower_hex(digest, 64), "205 measured digest is malformed");
    let mut input = open(path)?;
    ensure!(
        Stamp::of(&input.metadata()?) == *expected,
        "205 measured input replaced"
    );
    let actual = stream(&mut input, &mut std::io::sink(), expected.bytes)?;
    ensure!(
        actual == digest
            && Stamp::of(&input.metadata()?) == *expected
            && Stamp::of(&fs::symlink_metadata(path)?) == *expected,
        "205 measured digest/identity changed"
    );
    Ok(())
}
fn vanished(error: &std::io::Error) -> bool {
    matches!(error.raw_os_error(), Some(libc::ENOENT | libc::ESRCH))
}
/// Require a positive inode-based census; inaccessible FD metadata is not absence.
pub(super) fn no_writers(proc_root: &Path, source: &Stamp) -> Result<Value> {
    let begin = Instant::now();
    let mut processes = 0usize;
    let mut fds = 0usize;
    let mut readonly = Vec::new();
    let mut maps_bytes = 0u64;
    let mut mapped_readonly = Vec::new();
    for process in fs::read_dir(proc_root)? {
        ensure!(
            begin.elapsed() < Duration::from_secs(60),
            "205 writer census exceeded bounded time"
        );
        let process = process?;
        let name = process.file_name();
        let Some(name) = name.to_str() else { continue };
        if !name.bytes().all(|b| b.is_ascii_digit()) || name.is_empty() {
            continue;
        }
        processes += 1;
        ensure!(
            processes <= 4096,
            "205 writer census process bound exceeded"
        );
        let entries = match fs::read_dir(process.path().join("fd")) {
            Ok(v) => v,
            Err(e) if vanished(&e) => continue,
            Err(e) => return Err(e.into()),
        };
        for fd in entries {
            fds += 1;
            ensure!(
                fds <= 1_000_000 && begin.elapsed() < Duration::from_secs(60),
                "205 writer census FD/time bound exceeded"
            );
            let fd = fd?;
            let meta = match fs::metadata(fd.path()) {
                Ok(v) => v,
                Err(e) if vanished(&e) => continue,
                Err(e) => return Err(e.into()),
            };
            if meta.dev() != source.device || meta.ino() != source.inode {
                continue;
            }
            let info = process.path().join("fdinfo").join(fd.file_name());
            let bytes = read_stable_bounded(&info, 65536, "205 matching inode FD flags")?;
            let text = std::str::from_utf8(&bytes)?;
            let flags = text
                .lines()
                .filter_map(|l| l.strip_prefix("flags:\t"))
                .collect::<Vec<_>>();
            ensure!(
                flags.len() == 1,
                "205 matching inode FD flags missing/ambiguous"
            );
            let flags = u64::from_str_radix(flags[0], 8)?;
            ensure!(
                flags & libc::O_ACCMODE as u64 == libc::O_RDONLY as u64,
                "205 anchor/source inode has an active writer"
            );
            let after = fs::metadata(fd.path())?;
            ensure!(
                after.dev() == meta.dev() && after.ino() == meta.ino(),
                "205 matching inode FD changed during census"
            );
            readonly.push(json!({"pid":name,"fd":fd.file_name(),"access":"readonly"}));
        }
        let map_file = match File::open(process.path().join("maps")) {
            Ok(v) => v,
            Err(e) if vanished(&e) => continue,
            Err(e) => return Err(e.into()),
        };
        let mut reader = std::io::BufReader::new(map_file);
        let mut process_bytes = 0u64;
        loop {
            let mut line = Vec::new();
            let n = (&mut reader).take(16385).read_until(b'\n', &mut line)?;
            if n == 0 {
                break;
            }
            process_bytes += n as u64;
            maps_bytes += n as u64;
            ensure!(
                n <= 16384
                    && process_bytes <= 512 << 20
                    && maps_bytes <= 2 << 30
                    && begin.elapsed() < Duration::from_secs(60),
                "205 writer maps census line/byte/time bound exceeded"
            );
            if mapping_is_source_readonly(std::str::from_utf8(&line)?, source)? {
                mapped_readonly.push(json!({"pid":name,"access":"readonly"}));
            }
        }
    }
    Ok(
        json!({"schema":"jetstreamer-delivery205-inode-writer-census-v1","source_device":source.device,"source_inode":source.inode,
        "active_writers":0,"writable_mappings":0,"readonly_consumers":readonly,"mapped_readonly_consumers":mapped_readonly,
        "maps_bytes_scanned":maps_bytes,"processes":processes,"fds":fds,"uncertainty_accepted":false}),
    )
}
fn mapping_is_source_readonly(line: &str, source: &Stamp) -> Result<bool> {
    let f = line.split_whitespace().collect::<Vec<_>>();
    ensure!(f.len() >= 5, "205 process map row malformed");
    let perms = f[1].as_bytes();
    ensure!(
        perms.len() == 4
            && matches!(perms[0], b'r' | b'-')
            && matches!(perms[1], b'w' | b'-')
            && matches!(perms[2], b'x' | b'-')
            && matches!(perms[3], b's' | b'p'),
        "205 process map permissions unsupported"
    );
    let (major, minor) = f[3]
        .split_once(':')
        .context("205 process map device malformed")?;
    let major = u64::from_str_radix(major, 16)?;
    let minor = u64::from_str_radix(minor, 16)?;
    let inode = f[4].parse::<u64>()?;
    let matches = major == libc::major(source.device) as u64
        && minor == libc::minor(source.device) as u64
        && inode == source.inode;
    ensure!(
        !matches || perms[1] != b'w',
        "205 source inode has a surviving writable mapping"
    );
    Ok(matches)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn continuation205_first_copy_digest_is_measured_and_requires_exact_length() {
        let data = b"measured205";
        let mut output = Vec::new();
        let digest = stream(&mut data.as_slice(), &mut output, data.len() as u64).unwrap();
        assert_eq!(digest, hex_lower(&Sha256::digest(data)));
        assert_eq!(output, data);
        assert!(stream(&mut data.as_slice(), &mut Vec::new(), data.len() as u64 + 1).is_err());
        assert!(stream(&mut data.as_slice(), &mut Vec::new(), data.len() as u64 - 1).is_err());
    }
    #[test]
    fn continuation205_frozen_tuple_rejects_mutable_user_owned_or_multiple_links() {
        let good = Stamp {
            device: 1,
            inode: 2,
            bytes: 100,
            links: 1,
            uid: 0,
            gid: 0,
            mode: libc::S_IFREG | 0o400,
            mtime: 0,
            mtime_nanos: 0,
            ctime: 0,
            ctime_nanos: 0,
        };
        good.frozen().unwrap();
        let mut bad = good.clone();
        bad.mode |= 0o200;
        assert!(bad.frozen().is_err());
        bad = good.clone();
        bad.uid = 1000;
        assert!(bad.frozen().is_err());
        bad = good;
        bad.links = 2;
        assert!(bad.frozen().is_err());
    }
    #[test]
    fn continuation205_writer_census_rejects_closed_fd_writable_maps_and_unknown_permissions() {
        let source = Stamp {
            device: libc::makedev(259, 1),
            inode: 544857,
            bytes: 100,
            links: 1,
            uid: 0,
            gid: 0,
            mode: libc::S_IFREG | 0o400,
            mtime: 0,
            mtime_nanos: 0,
            ctime: 0,
            ctime_nanos: 0,
        };
        assert!(
            mapping_is_source_readonly("1-2 r--s 00000000 103:01 544857 /frozen.jet", &source)
                .unwrap()
        );
        assert!(
            mapping_is_source_readonly("1-2 rw-s 00000000 103:01 544857 /frozen.jet", &source)
                .is_err()
        );
        assert!(
            mapping_is_source_readonly("1-2 rw-p 00000000 103:01 544857 /frozen.jet", &source)
                .is_err()
        );
        assert!(
            mapping_is_source_readonly("1-2 ???? 00000000 103:01 544857 /frozen.jet", &source)
                .is_err()
        );
        assert!(
            !mapping_is_source_readonly("1-2 rw-s 00000000 103:01 99 /other.jet", &source).unwrap()
        );
    }
}
