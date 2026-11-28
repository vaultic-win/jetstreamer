//! Complete the prepaid V4 inode. Existing bytes are compared before any
//! append. The ordinary materialized verifier independently verifies the full result.
use super::*;
use std::io::{self, Read, Seek};

pub const NODE: &str = "horizon-qualify-168-trace-local3-20261120-v1.service";
pub(super) const GUARD: &str = "horizon-guard-168-trace-local3-20261120-v1.timer";
pub(super) const NODE_PROPERTIES: &str =
    "Id,InvocationID,ActiveState,MainPID,ControlGroup,Job,NRestarts,ExecMainStatus,Result";
pub(super) const GUARD_PROPERTIES: &str = "Id,ActiveState,Job,LoadState";
const TERMINAL: &str = "epoch168-terminal-trace-20261121-v1/TERMINAL.json";
const ORIGINAL: u64 = 40_871_330_316;
pub const CUSTODY: &str = "epoch145-partial-recovery-20261121-v1/TERMINAL_PARTIAL.json";

fn receipt(path: &str, sha256: &str) -> Result<Value> {
    custody::evidence(&Bound {
        path: Path::new(capacity::RUNTIME).join(path),
        sha256: sha256.into(),
    })
}
pub fn drained() -> Result<()> {
    let row = joint_candidate::show(NODE, NODE_PROPERTIES)?;
    ensure!(
        row["Id"] == NODE
            && row["InvocationID"] == "c081016844dd40c5a78b594bf7ede73a"
            && row["ActiveState"] == "failed"
            && row["ExecMainStatus"] == "1"
            && row["Result"] == "exit-code"
            && row["MainPID"] == "0"
            && row["ControlGroup"] == ""
            && row["Job"] == ""
            && row["NRestarts"] == "0",
        "168 original native terminal changed"
    );
    let timer = joint_candidate::show(GUARD, GUARD_PROPERTIES)?;
    ensure!(
        timer["ActiveState"] == "inactive" && timer["Job"] == "",
        "168 guard reactivated"
    );
    Ok(())
}
pub fn closed168() -> Result<Value> {
    let t = receipt(
        TERMINAL,
        "29672efbaff97d23a9a9d45a824840cb2d4cf43c6f5e8427ed3b532b41a38de2",
    )?;
    let c = receipt(
        CUSTODY,
        "87f25966f59a9324904fc123ef528ca9ed35bda5c77ed6ca5c8ed6e5648bbc08",
    )?;
    ensure!(
        t["unit"] == NODE
            && t["resource_credit_bytes"] == 0
            && t["archive_verified"] == false
            && c["output"]["bytes"] == ORIGINAL
            && c["terminal168"]["sha256"]
                == "29672efbaff97d23a9a9d45a824840cb2d4cf43c6f5e8427ed3b532b41a38de2"
            && t["boot"]
                == fs::read_to_string("/proc/sys/kernel/random/boot_id")?
                    .trim()
                    .replace('-', ""),
        "168 custody lineage"
    );
    let p = Path::new(t["partial"]["path"].as_str().context("168 partial")?);
    let m = fs::symlink_metadata(p)?;
    ensure!(
        m.is_file()
            && p.canonicalize()? == p
            && m.dev() == 64512
            && m.ino() == 104804528
            && m.len() == 42215375916,
        "168 partial custody changed"
    );
    drained()?;
    Ok(json!({"terminal":t,"partial145":c,"resource_credit_bytes":0}))
}
pub fn check(m: &fs::Metadata) -> Result<()> {
    let bytes = m.len();
    ensure!(
        (ORIGINAL..=BYTES).contains(&bytes),
        "paid prefix EOF outside recovery range"
    );
    if bytes < BYTES {
        ensure!(m.mode() & 0o777 == 0o600, "incomplete prefix is frozen");
    }
    materialized::check_geometry(
        m,
        64512,
        103237059,
        bytes,
        capacity::output_allocation(),
        105611071488 + (128 << 20),
    )
}

struct Resume<'a, T> {
    file: &'a mut T,
    remaining: u64,
    position: u64,
    limit: u64,
    scratch: Vec<u8>,
}
impl<T: Read + Write> Write for Resume<'_, T> {
    fn write(&mut self, mut data: &[u8]) -> io::Result<usize> {
        let len = data.len();
        let end = self
            .position
            .checked_add(len as u64)
            .filter(|n| *n <= self.limit)
            .ok_or_else(|| io::Error::other("encoded output exceeds prepaid limit"))?;
        while !data.is_empty() && self.remaining > 0 {
            let n = data
                .len()
                .min(self.scratch.len())
                .min(self.remaining as usize);
            self.file.read_exact(&mut self.scratch[..n])?;
            if self.scratch[..n] != data[..n] {
                return Err(io::Error::other(
                    "retained prefix differs from authenticated encoded source",
                ));
            }
            self.remaining -= n as u64;
            data = &data[n..];
        }
        self.file.write_all(data)?;
        self.position = end;
        Ok(len)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}
pub fn append(parent: u32, sha: &str) -> Result<()> {
    check_image(sha, Path::new(materialized::IMAGE))?;
    let iid = verify_cgroup()?;
    materialized::guard_parent(parent)?;
    let path = materialized::leaf()?;
    ensure!(
        path == Path::new(OUTPUT).join(".tmp36MvkN"),
        "not original V4 temporary"
    );
    source_lease::arm_break_signal()?;
    let src = materialized::lease(Path::new(SOURCE))?;
    let manifest = materialized::lease(Path::new(MANIFEST))?;
    source_identity()?;
    let mut fd = OpenOptions::new()
        .read(true)
        .append(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&path)?;
    check(&fd.metadata()?)?;
    ensure!(
        unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETOWN, libc::getpid()) } >= 0
            && unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETLEASE, libc::F_WRLCK) } == 0,
        "paid partial has another opener or mapping"
    );
    let meta = fd.metadata()?;
    ensure!(
        source_lease::FileIdentity::from(&meta)
            == source_lease::FileIdentity::from(&fs::symlink_metadata(&path)?),
        "output changed at open"
    );
    materialized::prove_view(&path)?;
    let count = meta.len();
    ensure!(count < BYTES, "partial is complete");
    let source = epoch145_extract::PinnedSource::open(
        Path::new(SOURCE),
        Path::new(MANIFEST),
        decode_sha(MANIFEST_SHA)?,
        epoch145_extract::PINNED_WORKER_SHA256,
    )?;
    src.check()?;
    manifest.check()?;
    fd.rewind()?;
    let mut writer = Resume {
        file: &mut fd,
        remaining: count,
        position: 0,
        limit: BYTES,
        scratch: vec![0; 1 << 20],
    };
    source.write_authenticated_prefix(&mut writer)?;
    ensure!(
        writer.position == BYTES && writer.remaining == 0,
        "incomplete verified append"
    );
    fd.sync_all()?;
    src.check()?;
    manifest.check()?;
    ensure!(
        unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETLEASE) } == libc::F_WRLCK
            && fd.metadata()?.len() == BYTES,
        "lost exclusive output custody"
    );
    materialized::guard_parent(parent)?;
    custody::write_new(
        &Path::new(BASE)
            .join("state")
            .join(iid)
            .join("append-complete.json"),
        &json!({"prefix_bytes_compared":count,"appended":BYTES-count,"source_sha256":SOURCE_SHA,"device":meta.dev(),"inode":meta.ino(),"no_semantic_verification_claimed":true}),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "requires the genuine stopped V4 inode, closed168 witness and read-only fixture mount"]
    fn actual_terminal_and_append_descriptor() {
        closed168().unwrap();
        let path = materialized::leaf().unwrap();
        let m = fs::symlink_metadata(path).unwrap();
        check(&m).unwrap();
        assert_eq!(
            m.len(),
            if cfg!(continuity145_only) {
                BYTES
            } else {
                ORIGINAL
            }
        );
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("partial");
        fs::write(&path, b"sample").unwrap();
        let mut file = OpenOptions::new()
            .read(true)
            .append(true)
            .open(&path)
            .unwrap();
        let inode = file.metadata().unwrap().ino();
        assert_eq!(
            unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETLEASE, libc::F_WRLCK) },
            0
        );
        file.rewind().unwrap();
        let mut w = Resume {
            file: &mut file,
            remaining: 6,
            position: 0,
            limit: 11,
            scratch: vec![0; 3],
        };
        w.write_all(b"sam").unwrap();
        w.write_all(b"ple plus!").unwrap_err();
        w.write_all(b"ple plus").unwrap();
        assert_eq!((w.remaining, w.position), (0, 11));
        file.sync_all().unwrap();
        assert_eq!(file.metadata().unwrap().ino(), inode);
        file.rewind().unwrap();
        let mut body = vec![];
        file.read_to_end(&mut body).unwrap();
        assert_eq!(&body, b"sample plus");
    }
    #[test]
    fn resumes_across_a_write_and_never_discards_a_mismatch() {
        for bad in [false, true] {
            let pre = if bad { b"abcXef" } else { b"abcdef" };
            let mut file = io::Cursor::new(pre.to_vec());
            let mut w = Resume {
                file: &mut file,
                remaining: 6,
                position: 0,
                limit: 9,
                scratch: vec![0; 2],
            };
            w.write_all(b"abc").unwrap();
            if bad {
                assert!(w.write_all(b"defghi").is_err());
                assert_eq!(file.into_inner(), pre);
            } else {
                w.write_all(b"defghi").unwrap();
                assert!(w.write_all(b"x").is_err());
                assert_eq!(file.into_inner(), b"abcdefghi");
            }
        }
    }
}
