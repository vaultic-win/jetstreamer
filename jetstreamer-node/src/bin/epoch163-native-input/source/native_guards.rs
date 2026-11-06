//! Exact restore-probe namespace, mapped image and VMA checks; no input body loading.
use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{BufRead, BufReader, Read},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};
pub const VMA_STOP: u64 = 1_048_576;
fn identity(m: &fs::Metadata) -> (u64, u64, u64, u32, u32, u64, i64, i64, i64, i64) {
    (
        m.dev(),
        m.ino(),
        m.len(),
        m.uid(),
        m.mode(),
        m.nlink(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}

pub fn layout(snapshot: &Path, ledger: &Path, scratch: &Path, state: &Path) -> Result<()> {
    ensure!(snapshot.is_absolute(), "absolute immutable snapshot");
    let owned = [ledger, scratch, state];
    for (i, root) in owned.iter().enumerate() {
        ensure!(
            root.is_absolute() && !snapshot.starts_with(root),
            "immutable snapshot overlaps mutable namespace"
        );
        for other in owned.iter().skip(i + 1) {
            ensure!(
                !root.starts_with(other) && !other.starts_with(root),
                "overlapping owned namespaces"
            );
        }
    }
    Ok(())
}
pub fn readonly(path: &Path) -> Result<()> {
    let name = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())?;
    let mut state = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    ensure!(
        unsafe { libc::statvfs(name.as_ptr(), state.as_mut_ptr()) } == 0,
        "source namespace statvfs"
    );
    ensure!(
        unsafe { state.assume_init() }.f_flag & libc::ST_RDONLY != 0,
        "source namespace must be mounted read-only"
    );
    Ok(())
}
fn ticks(pid: u32) -> Result<u64> {
    let text = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    text.rsplit_once(") ")
        .context("process stat framing")?
        .1
        .split_whitespace()
        .nth(19)
        .context("process start ticks")?
        .parse()
        .context("process start tick number")
}
pub fn mapped_worker(pid: u32, scratch: &Path, expected: &str, cgroup: &str) -> Result<u64> {
    ensure!(pid > 1, "owned worker PID");
    let before = ticks(pid)?;
    ensure!(
        fs::read_to_string(format!("/proc/{pid}/cgroup"))?.trim() == format!("0::{cgroup}"),
        "mapped worker escaped actor cgroup"
    );
    let proc = PathBuf::from(format!("/proc/{pid}/exe"));
    let image = fs::read_link(&proc)?;
    ensure!(
        image.starts_with(scratch)
            && image.ends_with("bound-worker/historical-worker")
            && image.canonicalize()? == image,
        "mapped worker must be the measured private executable"
    );
    let mut file = fs::File::open(&proc)?;
    let m = file.metadata()?;
    let named = fs::symlink_metadata(&image)?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o222 == 0
            && m.len() > 0
            && m.len() <= 256 << 20
            && (m.dev(), m.ino(), m.len()) == (named.dev(), named.ino(), named.len()),
        "mapped worker inode/mode/size"
    );
    let mut hash = Sha256::new();
    let mut buf = [0u8; 65536];
    let mut bytes = 0u64;
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        bytes = bytes
            .checked_add(n as u64)
            .context("image length overflow")?;
        ensure!(bytes <= m.len(), "mapped image grew");
        hash.update(&buf[..n]);
    }
    let after = file.metadata()?;
    let named_after = fs::symlink_metadata(&image)?;
    ensure!(
        bytes == m.len()
            && format!("{:x}", hash.finalize()) == expected
            && identity(&m) == identity(&after)
            && identity(&m) == identity(&named_after)
            && ticks(pid)? == before,
        "mapped worker digest/identity changed"
    );
    ensure!(
        fs::read_to_string(format!("/proc/{pid}/cgroup"))?.trim() == format!("0::{cgroup}"),
        "mapped worker cgroup changed"
    );
    Ok(before)
}
fn map_count<R: BufRead>(mut input: R, limit: u64) -> Result<u64> {
    ensure!(limit > 0, "nonzero map limit");
    let mut count = 0;
    let mut row = Vec::new();
    loop {
        row.clear();
        let mut line = Read::by_ref(&mut input).take(65537);
        let n = line.read_until(b'\n', &mut row)?;
        if n == 0 {
            break;
        }
        ensure!(
            row.len() <= 65536 && row.last() == Some(&b'\n'),
            "bounded complete map record"
        );
        count += 1;
        ensure!(count < limit, "native VMA stop");
    }
    ensure!(count > 0, "empty live process maps");
    Ok(count)
}
fn members(group: &Path) -> Result<Vec<u32>> {
    let raw = fs::read_to_string(group.join("cgroup.procs"))?;
    ensure!(raw.len() <= 4096, "bounded process census");
    let mut ids = Vec::new();
    for line in raw.lines() {
        let id = line.parse::<u32>()?;
        ensure!(id > 1 && !ids.contains(&id), "unique owned process PID");
        ids.push(id);
    }
    ensure!(
        !ids.is_empty() && ids.len() <= 16,
        "native process census bound"
    );
    Ok(ids)
}
pub fn vmas(group: &Path, cgroup: &str) -> Result<()> {
    let kernel = fs::read_to_string("/proc/sys/vm/max_map_count")?
        .trim()
        .parse::<u64>()?;
    ensure!(kernel > VMA_STOP, "native VMA kernel headroom");
    let mut total = 0u64;
    for pid in members(group)? {
        let maps = match fs::File::open(format!("/proc/{pid}/maps")) {
            Ok(f) => f,
            Err(e)
                if e.kind() == std::io::ErrorKind::NotFound && !members(group)?.contains(&pid) =>
            {
                continue;
            }
            Err(e) => return Err(e.into()),
        };
        let before = match ticks(pid) {
            Ok(n) => n,
            Err(_) if !members(group)?.contains(&pid) => continue,
            Err(e) => return Err(e),
        };
        let count = match map_count(BufReader::new(maps), VMA_STOP) {
            Ok(n) => n,
            Err(_) if !members(group)?.contains(&pid) => continue,
            Err(e) => return Err(e),
        };
        match ticks(pid) {
            Ok(n) => ensure!(n == before, "owned PID recycled during VMA check"),
            Err(_) if !members(group)?.contains(&pid) => continue,
            Err(e) => return Err(e),
        };
        ensure!(
            fs::read_to_string(format!("/proc/{pid}/cgroup"))?.trim() == format!("0::{cgroup}"),
            "VMA owner cgroup changed"
        );
        total = total.checked_add(count).context("aggregate VMA overflow")?;
        ensure!(total < VMA_STOP, "aggregate native VMA stop");
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn immutable_input_is_separate_and_owned_namespaces_cannot_overlap() {
        let snapshot = Path::new("/private/inputs/snapshot");
        layout(
            snapshot,
            Path::new("/private/ledger"),
            Path::new("/private/scratch"),
            Path::new("/private/state"),
        )
        .unwrap();
        for root in ["/private", "/private/inputs", "/private/inputs/snapshot"] {
            assert!(
                layout(
                    snapshot,
                    Path::new(root),
                    Path::new("/scratch"),
                    Path::new("/state")
                )
                .is_err()
            );
        }
        assert!(
            layout(
                snapshot,
                Path::new("/owned"),
                Path::new("/owned/scratch"),
                Path::new("/state")
            )
            .is_err()
        );
    }
    #[test]
    fn map_stream_has_strict_count_line_and_truncation_bounds() {
        assert_eq!(map_count(&b"one\ntwo\n"[..], 3).unwrap(), 2);
        assert!(map_count(&b"one\ntwo\n"[..], 2).is_err());
        assert!(map_count(&b"partial"[..], 3).is_err());
        assert!(map_count(&b""[..], 3).is_err());
        assert!(map_count(std::io::BufReader::new(std::io::repeat(b'a')), 3).is_err());
    }
    #[test]
    #[ignore = "Root disposable exec tmpfs only; no native snapshot or historical worker"]
    fn root_actual_mapped_copy_has_exact_inode_digest_scope_and_owned_pid() {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let root = PathBuf::from(std::env::var("JETSTREAMER_NATIVE163_TMPFS_PROBE_ROOT").unwrap());
        assert_eq!(root.canonicalize().unwrap(), root);
        let dir = root.join("bound-worker");
        fs::create_dir(&dir).unwrap();
        let image = dir.join("historical-worker");
        fs::copy("/usr/bin/sleep", &image).unwrap();
        fs::set_permissions(&image, fs::Permissions::from_mode(0o555)).unwrap();
        let expected = format!("{:x}", Sha256::digest(fs::read(&image).unwrap()));
        struct Owned(std::process::Child);
        impl Drop for Owned {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let child = Owned(
            std::process::Command::new(&image)
                .arg("30")
                .spawn()
                .unwrap(),
        );
        let id = child.0.id();
        let cg = fs::read_to_string("/proc/self/cgroup").unwrap();
        let cg = cg.trim().strip_prefix("0::").unwrap();
        assert!(mapped_worker(id, &root, &expected, cg).unwrap() > 0);
        assert!(mapped_worker(id, &root, &"0".repeat(64), cg).is_err());
        assert!(mapped_worker(id, Path::new("/outside"), &expected, cg).is_err());
        assert!(mapped_worker(id, &root, &expected, "/foreign").is_err());
        vmas(
            &Path::new("/sys/fs/cgroup").join(cg.trim_start_matches('/')),
            cg,
        )
        .unwrap();
        drop(child);
    }
}
