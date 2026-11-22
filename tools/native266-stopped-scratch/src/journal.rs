//! Individually atomic, no-clobber, fsynced phase records. An O_TMPFILE has no
//! orphan pathname if the process dies between writing and publishing it.
use super::*;
use std::{
    ffi::CString,
    io::{ErrorKind, Read, Write},
    os::unix::fs::PermissionsExt,
};
unsafe extern "C" {
    fn linkat(old: i32, name: *const i8, new: i32, dest: *const i8, flags: i32) -> i32;
}
pub struct Journal {
    dir: File,
}
impl Journal {
    pub fn new(path: &Path, uid: u32) -> io::Result<Self> {
        need(
            path.canonicalize()? == path,
            "state directory is not canonical",
        )?;
        let dir = open(path, DIRECTORY)?;
        let m = dir.metadata()?;
        need(
            m.uid() == uid && m.gid() == uid && m.mode() & 0o7777 == 0o700,
            "state directory ownership",
        )?;
        Ok(Self { dir })
    }
    pub fn get(&self, name: &str) -> io::Result<Option<String>> {
        need(
            !name.is_empty()
                && name
                    .bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-'),
            "invalid receipt name",
        )?;
        let p = PathBuf::from(format!("/proc/self/fd/{}", self.dir.as_raw_fd())).join(name);
        let f = match open(&p, 0) {
            Ok(f) => f,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let m = f.metadata()?;
        need(
            m.is_file()
                && m.uid() == self.dir.metadata()?.uid()
                && m.mode() & 0o7777 == 0o400
                && m.nlink() == 1
                && m.len() < 32768,
            "receipt custody",
        )?;
        let mut s = String::new();
        f.take(32768).read_to_string(&mut s)?;
        self.dir.sync_all()?;
        Ok(Some(s))
    }
    pub fn put(&self, name: &str, body: &str) -> io::Result<()> {
        if let Some(s) = self.get(name)? {
            return need(s == body, "immutable phase receipt differs");
        };
        need(body.len() < 32768, "receipt bound")?;
        let base = format!("/proc/self/fd/{}", self.dir.as_raw_fd());
        let mut f = OpenOptions::new()
            .read(true)
            .write(true)
            .mode(0o400)
            .custom_flags(0o20200000)
            .open(base)?;
        f.write_all(body.as_bytes())?;
        f.set_permissions(fs::Permissions::from_mode(0o400))?;
        f.sync_all()?;
        let d = CString::new(name)?;
        let rc = unsafe {
            linkat(
                f.as_raw_fd(),
                c"".as_ptr(),
                self.dir.as_raw_fd(),
                d.as_ptr(),
                0x1000,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        self.dir.sync_all()?;
        need(self.get(name)?.as_deref() == Some(body), "receipt readback")
    }
}
