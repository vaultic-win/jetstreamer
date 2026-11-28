use std::{
    env,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};
const PROGRAM: &str =
    "/usr/local/lib/jetstreamer/horizon-cohort193-admission-installer-20261024-v1/installer";
const DIRECTORY: &str =
    "/var/lib/jetstreamer/horizon-cohort191-delivery-queue-20261023-v1/admissions";
unsafe extern "C" {
    fn geteuid() -> u32;
    fn renameat2(
        olddirfd: i32,
        oldpath: *const std::ffi::c_char,
        newdirfd: i32,
        newpath: *const std::ffi::c_char,
        flags: u32,
    ) -> i32;
}
fn require(ok: bool, why: &str) -> io::Result<()> {
    if ok {
        Ok(())
    } else {
        Err(io::Error::other(why))
    }
}
fn digest(path: &Path) -> io::Result<String> {
    let o = Command::new("/usr/bin/sha256sum")
        .arg("--")
        .arg(path)
        .output()?;
    require(
        o.status.success() && o.stdout.len() < 2048,
        "SHA-256 command failed",
    )?;
    let s = std::str::from_utf8(&o.stdout).map_err(io::Error::other)?;
    let h = s.split_whitespace().next().unwrap_or("");
    require(
        h.len() == 64
            && h.bytes()
                .all(|x| x.is_ascii_digit() || (b'a'..=b'f').contains(&x)),
        "invalid digest",
    )?;
    Ok(h.into())
}
fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn selection(epoch: &str, stage: &str) -> io::Result<(PathBuf, String)> {
    if epoch == "193" && stage == "full-recovery-v1" {
        return Ok((
            PathBuf::from(
                "/usr/local/lib/jetstreamer/horizon-cohort193-queue-admission-full-recovery-20261024-v1/admission.json",
            ),
            "epoch-193-full-recovery-v1.json".into(),
        ));
    }
    require(
        matches!(epoch, "191" | "192" | "193" | "194")
            && matches!(stage, "full" | "plugin" | "sync"),
        "foreign admission family selection",
    )?;
    Ok((
        PathBuf::from(format!(
            "/usr/local/lib/jetstreamer/horizon-cohort191-queue-admission-{epoch}-{stage}-20261024-v1/admission.json"
        )),
        format!("epoch-{epoch}-{stage}.json"),
    ))
}
fn valid_slot(slot: &str) -> bool {
    slot == "epoch-193-full-recovery-v1.json"
        || ["191", "192", "193", "194"].iter().any(|epoch| {
            ["full", "plugin", "sync"]
                .iter()
                .any(|stage| slot == format!("epoch-{epoch}-{stage}.json"))
        })
}
fn bytes_digest(bytes: &[u8]) -> io::Result<String> {
    let mut child = Command::new("/usr/bin/sha256sum")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("missing hash input"))?
        .write_all(bytes)?;
    let output = child.wait_with_output()?;
    require(
        output.status.success() && output.stdout.len() < 2048,
        "byte digest failed",
    )?;
    let hash = std::str::from_utf8(&output.stdout)
        .map_err(io::Error::other)?
        .split_whitespace()
        .next()
        .unwrap_or("");
    require(valid_digest(hash), "invalid byte digest")?;
    Ok(hash.into())
}
fn atomic_install(directory: &Path, slot: &str, bytes: &[u8]) -> io::Result<PathBuf> {
    let d = fs::symlink_metadata(directory)?;
    require(
        d.is_dir()
            && d.uid() == 0
            && d.mode() & 0o777 == 0o700
            && directory.canonicalize()? == directory,
        "unsafe operational admission directory",
    )?;
    require(valid_slot(slot), "foreign admission slot")?;
    let dir = File::open(directory)?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_nanos();
    let name = format!(".cohort191-{}-{nonce}.tmp", std::process::id());
    let tmp = directory.join(&name);
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(0x20000)
        .open(&tmp)?;
    f.write_all(bytes)?;
    f.set_permissions(fs::Permissions::from_mode(0o400))?;
    f.sync_all()?;
    let before = f.metadata()?;
    let old = std::ffi::CString::new(name).map_err(io::Error::other)?;
    let new = std::ffi::CString::new(slot).map_err(io::Error::other)?;
    let result = unsafe {
        renameat2(
            dir.as_raw_fd(),
            old.as_ptr(),
            dir.as_raw_fd(),
            new.as_ptr(),
            1,
        )
    };
    if result != 0 {
        let error = io::Error::last_os_error();
        fs::remove_file(&tmp)?;
        dir.sync_all()?;
        return Err(error);
    }
    dir.sync_all()?;
    let destination = directory.join(slot);
    let after = fs::symlink_metadata(&destination)?;
    require(
        after.is_file()
            && after.uid() == 0
            && after.nlink() == 1
            && after.mode() & 0o777 == 0o400
            && before.ino() == after.ino()
            && before.dev() == after.dev(),
        "published admission identity changed",
    )?;
    require(
        fs::read(&destination)? == bytes,
        "published admission bytes changed",
    )?;
    Ok(destination)
}
fn run() -> io::Result<()> {
    let args: Vec<_> = env::args().collect();
    require(
        args.len() == 5 && unsafe { geteuid() } == 0,
        "family installer requires root, epoch, stage, source SHA-256 and self SHA-256",
    )?;
    require(
        fs::read_link("/proc/self/exe")? == Path::new(PROGRAM)
            && valid_digest(&args[4])
            && digest(Path::new(PROGRAM))? == args[4],
        "installer self binding changed",
    )?;
    let (source, slot) = selection(&args[1], &args[2])?;
    require(valid_digest(&args[3]), "invalid source SHA-256")?;
    let p = source.as_path();
    let md = fs::symlink_metadata(p)?;
    require(
        p.canonicalize()? == p
            && md.is_file()
            && md.uid() == 0
            && md.nlink() == 1
            && md.mode() & 0o777 == 0o400
            && md.len() <= 1 << 20,
        "unsafe sealed admission source",
    )?;
    require(digest(p)? == args[3], "sealed admission digest changed")?;
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(0x20000)
        .open(p)?;
    let id = f.metadata()?;
    require(
        id.ino() == md.ino() && id.dev() == md.dev(),
        "source inode changed",
    )?;
    let mut bytes = Vec::new();
    f.read_to_end(&mut bytes)?;
    require(
        bytes.len() as u64 == md.len() && digest(p)? == args[3] && bytes_digest(&bytes)? == args[3],
        "source changed while read",
    )?;
    let dest = atomic_install(Path::new(DIRECTORY), &slot, &bytes)?;
    require(digest(&dest)? == args[3], "destination digest mismatch")?;
    println!("{} {}", dest.display(), args[3]);
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("cohort 191 admission installation failed: {e}");
        std::process::exit(1)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    const SLOT: &str = "epoch-191-sync.json";
    #[test]
    fn successor_slot_is_exact_and_cannot_overwrite_original() {
        let (source, slot) = selection("193", "full-recovery-v1").unwrap();
        assert_eq!(slot, "epoch-193-full-recovery-v1.json");
        assert!(valid_slot(&slot));
        assert_ne!(source, selection("193", "full").unwrap().0);
        for epoch in ["191", "192", "194"] {
            assert!(selection(epoch, "full-recovery-v1").is_err());
        }
        assert!(!valid_slot("epoch-193-full-recovery-v2.json"));
    }
    #[test]
    fn family_is_exact_and_bytes_are_hashed() {
        for epoch in ["191", "192", "193", "194"] {
            for stage in ["full", "plugin", "sync"] {
                let (source, slot) = selection(epoch, stage).unwrap();
                assert!(valid_slot(&slot));
                assert_eq!(
                    source,
                    PathBuf::from(format!(
                        "/usr/local/lib/jetstreamer/horizon-cohort191-queue-admission-{epoch}-{stage}-20261024-v1/admission.json"
                    ))
                );
            }
        }
        for (epoch, stage) in [
            ("190", "full"),
            ("195", "sync"),
            ("0191", "full"),
            ("191", "../full"),
            ("191", "upload"),
        ] {
            assert!(selection(epoch, stage).is_err());
        }
        assert!(!valid_slot("../epoch-191-sync.json"));
        assert_eq!(
            bytes_digest(b"abc").unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert!(!valid_digest(&"A".repeat(64)));
    }
    #[test]
    fn publication_is_immutable_atomic_and_never_replaces_an_existing_slot() {
        let p = env::temp_dir().join(format!(
            "cohort191-install-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&p).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
        let out = atomic_install(&p, SLOT, b"reviewed admission").unwrap();
        let md = fs::metadata(&out).unwrap();
        assert_eq!(md.mode() & 0o777, 0o400);
        assert_eq!(fs::read(&out).unwrap(), b"reviewed admission");
        assert!(atomic_install(&p, SLOT, b"replacement").is_err());
        assert_eq!(fs::metadata(&out).unwrap().ino(), md.ino());
        assert_eq!(fs::read(&out).unwrap(), b"reviewed admission");
        assert_eq!(fs::read_dir(&p).unwrap().count(), 1);
        assert!(atomic_install(&p, "other-slot.json", b"other").is_err());
        fs::remove_dir_all(p).unwrap();
    }
}
