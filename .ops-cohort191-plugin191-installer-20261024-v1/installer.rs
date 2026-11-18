use std::{
    env,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};
const SOURCE: &str =
    "/usr/local/lib/jetstreamer/horizon-cohort191-plugin191-admission-20261024-v1/admission.json";
const SOURCE_SHA: &str = "512851ce8d99cc1726d8a93aca0ed69c3785831eb28b2a841358137951bdf30f";
const PROGRAM: &str = "/usr/local/lib/jetstreamer/horizon-cohort191-plugin191-admission-installer-20261024-v1/installer";
const DIRECTORY: &str =
    "/var/lib/jetstreamer/horizon-cohort191-delivery-queue-20261023-v1/admissions";
const SLOT: &str = "epoch-191-plugin.json";
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
fn atomic_install(directory: &Path, slot: &str, bytes: &[u8]) -> io::Result<PathBuf> {
    let d = fs::symlink_metadata(directory)?;
    require(
        d.is_dir()
            && d.uid() == 0
            && d.mode() & 0o777 == 0o700
            && directory.canonicalize()? == directory,
        "unsafe operational admission directory",
    )?;
    require(slot == SLOT, "foreign admission slot")?;
    let dir = File::open(directory)?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_nanos();
    let name = format!(".plugin191-{}-{nonce}.tmp", std::process::id());
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
        args.len() == 2 && unsafe { geteuid() } == 0,
        "exact installer requires root and its self SHA-256",
    )?;
    require(
        fs::read_link("/proc/self/exe")? == Path::new(PROGRAM)
            && digest(Path::new(PROGRAM))? == args[1],
        "installer self binding changed",
    )?;
    let p = Path::new(SOURCE);
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
    require(digest(p)? == SOURCE_SHA, "sealed admission digest changed")?;
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
        bytes.len() as u64 == md.len() && digest(p)? == SOURCE_SHA,
        "source changed while read",
    )?;
    let dest = atomic_install(Path::new(DIRECTORY), SLOT, &bytes)?;
    require(digest(&dest)? == SOURCE_SHA, "destination digest mismatch")?;
    println!("{} {}", dest.display(), SOURCE_SHA);
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("exact plugin191 admission installation failed: {e}");
        std::process::exit(1)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn publication_is_immutable_atomic_and_never_replaces_an_existing_slot() {
        let p = env::temp_dir().join(format!(
            "plugin191-install-test-{}-{}",
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
