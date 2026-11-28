use super::model::{Bound, Identity};
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

pub fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
pub fn boottime() -> Result<u64> {
    let mut t: libc::timespec = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut t) } == 0,
        "boottime"
    );
    u64::try_from(t.tv_sec)?
        .checked_mul(1000)
        .context("clock overflow")?
        .checked_add(u64::try_from(t.tv_nsec)? / 1_000_000)
        .context("clock overflow")
}
pub fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
pub fn hex(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub fn identity(m: &fs::Metadata) -> Identity {
    Identity {
        device: m.dev(),
        inode: m.ino(),
        bytes: m.len(),
        mtime_ns: i128::from(m.mtime()) * 1_000_000_000 + i128::from(m.mtime_nsec()),
        ctime_ns: i128::from(m.ctime()) * 1_000_000_000 + i128::from(m.ctime_nsec()),
        mode: m.mode(),
        uid: m.uid(),
        gid: m.gid(),
    }
}
pub fn frozen_identity(path: &Path) -> Result<Identity> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        path.is_absolute()
            && path.canonicalize()? == path
            && m.is_file()
            && m.uid() == 0
            && m.gid() == 0
            && m.nlink() == 1
            && m.mode() & 0o222 == 0,
        "input must be canonical Root-owned frozen regular single-link: {}",
        path.display()
    );
    Ok(identity(&m))
}
pub fn bytes(bound: &Bound, maximum: u64, immutable: bool) -> Result<Vec<u8>> {
    ensure!(hex(&bound.sha256, 64), "bound SHA shape");
    let before = if immutable {
        frozen_identity(&bound.path)?
    } else {
        let m = fs::symlink_metadata(&bound.path)?;
        ensure!(
            bound.path.is_absolute()
                && bound.path.canonicalize()? == bound.path
                && m.is_file()
                && m.uid() == 0
                && m.gid() == 0
                && m.nlink() == 1
                && m.mode() & 0o777 == 0o600,
            "private evidence custody"
        );
        identity(&m)
    };
    ensure!(before.bytes <= maximum, "bounded evidence oversized");
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&bound.path)?;
    ensure!(
        identity(&f.metadata()?) == before,
        "opened evidence changed"
    );
    let mut b = Vec::new();
    (&mut f).take(maximum + 1).read_to_end(&mut b)?;
    ensure!(
        b.len() as u64 == before.bytes
            && identity(&f.metadata()?) == before
            && identity(&fs::symlink_metadata(&bound.path)?) == before
            && sha(&b) == bound.sha256,
        "evidence identity/digest changed: {}",
        bound.path.display()
    );
    Ok(b)
}
pub fn json(bound: &Bound, immutable: bool) -> Result<Value> {
    Ok(serde_json::from_slice(&bytes(bound, 8 << 20, immutable)?)?)
}
/// Qualified source evidence can be immutable or an owner-private original
/// receipt. Both paths retain descriptor identity and complete digest checks.
pub fn evidence(bound: &Bound) -> Result<Value> {
    let m = fs::symlink_metadata(&bound.path)?;
    json(bound, m.mode() & 0o222 == 0)
}
pub fn binding(path: &Path) -> Result<Bound> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.gid() == 0
            && m.nlink() == 1
            && m.mode() & 0o777 == 0o600
            && m.len() <= 8 << 20,
        "private binding custody"
    );
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let before = identity(&m);
    ensure!(identity(&f.metadata()?) == before, "binding open changed");
    let mut b = Vec::new();
    (&mut f).take((8 << 20) + 1).read_to_end(&mut b)?;
    ensure!(
        b.len() as u64 == before.bytes
            && identity(&f.metadata()?) == before
            && identity(&fs::symlink_metadata(path)?) == before,
        "binding changed"
    );
    Ok(Bound {
        path: path.into(),
        sha256: sha(&b),
    })
}
pub fn private_directory(path: &Path) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        path.is_absolute()
            && path.canonicalize()? == path
            && m.is_dir()
            && m.uid() == 0
            && m.gid() == 0
            && m.mode() & 0o777 == 0o700,
        "private directory custody"
    );
    Ok(())
}
/// One descriptor-bound snapshot of the mutable guard token. An atomic newer
/// publication may unlink this inode during the read; its still-fresh complete
/// payload remains valid. Do not hash then reopen a mutable token pathname.
pub fn token_snapshot(path: &Path) -> Result<Vec<u8>> {
    private_directory(path.parent().context("token parent")?)?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let before = file.metadata()?;
    ensure!(
        before.is_file()
            && before.uid() == 0
            && before.gid() == 0
            && before.nlink() <= 1
            && before.mode() & 0o777 == 0o600
            && before.len() <= 1 << 20,
        "mutable token custody"
    );
    let mut bytes = Vec::new();
    (&mut file).take((1 << 20) + 1).read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    let same_payload = |m: &fs::Metadata| {
        (
            m.dev(),
            m.ino(),
            m.len(),
            m.mtime(),
            m.mtime_nsec(),
            m.mode(),
            m.uid(),
            m.gid(),
        )
    };
    ensure!(
        bytes.len() as u64 == before.len() && same_payload(&before) == same_payload(&after),
        "mutable token bytes changed in place"
    );
    Ok(bytes)
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    #[test]
    fn digest_shape_rejects_uppercase_truncation_and_shell_text() {
        assert!(hex(&"a".repeat(64), 64));
        for s in ["A".repeat(64), "a".repeat(63), ";".repeat(64)] {
            assert!(!hex(&s, 64));
        }
    }
    fn evidence_fixture(mode: u32) -> (tempfile::TempDir, Bound) {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            unsafe { libc::geteuid() },
            0,
            "admitted Root-only synthetic QA"
        );
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("original-witness.json");
        let payload = br#"{"witness":"original"}"#;
        fs::write(&path, payload).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        (
            dir,
            Bound {
                path,
                sha256: sha(payload),
            },
        )
    }
    #[test]
    fn frozen_original_evidence_accepts_root0400_without_permission_change() {
        let (_dir, bound) = evidence_fixture(0o400);
        let before = identity(&fs::symlink_metadata(&bound.path).unwrap());
        assert_eq!(evidence(&bound).unwrap()["witness"], "original");
        assert_eq!(
            identity(&fs::symlink_metadata(&bound.path).unwrap()),
            before
        );
    }
    #[test]
    fn mutable_private_evidence_accepts_root0600_without_freezing_original() {
        let (_dir, bound) = evidence_fixture(0o600);
        let before = identity(&fs::symlink_metadata(&bound.path).unwrap());
        assert_eq!(evidence(&bound).unwrap()["witness"], "original");
        assert_eq!(
            identity(&fs::symlink_metadata(&bound.path).unwrap()),
            before
        );
    }
    #[test]
    fn evidence_rejects_wrong_owner_and_nonprivate_writable_metadata() {
        use std::os::{fd::AsRawFd, unix::fs::PermissionsExt};
        let (_dir, bound) = evidence_fixture(0o400);
        let file = File::open(&bound.path).unwrap();
        assert_eq!(unsafe { libc::fchown(file.as_raw_fd(), 1001, 1001) }, 0);
        assert!(evidence(&bound).is_err());
        assert_eq!(unsafe { libc::fchown(file.as_raw_fd(), 0, 0) }, 0);
        for mode in [0o640, 0o644, 0o660, 0o666] {
            fs::set_permissions(&bound.path, fs::Permissions::from_mode(mode)).unwrap();
            assert!(
                evidence(&bound).is_err(),
                "writable/nonprivate mode {mode:o}"
            );
        }
    }
    #[test]
    fn evidence_rejects_crossed_original_and_foreign_digest() {
        let (_dir, bound) = evidence_fixture(0o400);
        let foreign_path = bound.path.parent().unwrap().join("foreign-witness.json");
        fs::write(&foreign_path, br#"{"witness":"foreign"}"#).unwrap();
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&foreign_path, fs::Permissions::from_mode(0o400)).unwrap();
        assert!(
            evidence(&Bound {
                path: foreign_path,
                sha256: bound.sha256
            })
            .is_err()
        );
    }
}
