use anyhow::{Context, Result, ensure};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}

pub fn output(program: &str, args: &[&str]) -> Result<String> {
    let out = Command::new("/usr/bin/timeout")
        .args(["--kill-after=2", "40", program])
        .args(args)
        .env("SYSTEMD_COLORS", "0")
        .output()
        .with_context(|| format!("execute {program}"))?;
    ensure!(
        out.status.success(),
        "{program} {:?}: {}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
    Ok(String::from_utf8(out.stdout)?.trim_end().to_owned())
}
pub fn ctl(args: &[&str]) -> Result<String> {
    output("/usr/bin/systemctl", args)
}
pub fn show(unit: &str, fields: &str) -> Result<Value> {
    ensure!(
        unit.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)),
        "invalid unit"
    );
    let values = ctl(&["show", unit, "-p", fields])?;
    let mut row = Map::new();
    for line in values.lines() {
        let (key, value) = line.split_once('=').context("missing systemd value")?;
        ensure!(
            row.insert(key.into(), json!(value)).is_none(),
            "duplicate property"
        );
    }
    ensure!(
        fields.split(',').all(|k| row.contains_key(k)),
        "missing systemd property for {unit}"
    );
    Ok(Value::Object(row))
}
pub fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
pub fn read(path: &Path) -> Result<Vec<u8>> {
    ensure!(
        path.is_absolute() && fs::canonicalize(path)? == path,
        "noncanonical evidence {}",
        path.display()
    );
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let meta = f.metadata()?;
    ensure!(
        meta.is_file()
            && meta.uid() == 0
            && meta.nlink() == 1
            && meta.mode() & 0o022 == 0
            && meta.len() <= 32 << 20,
        "unsafe evidence {}",
        path.display()
    );
    let mut bytes = Vec::new();
    (&mut f).take((32 << 20) + 1).read_to_end(&mut bytes)?;
    let after = fs::symlink_metadata(path)?;
    ensure!(
        bytes.len() as u64 == meta.len()
            && (
                meta.dev(),
                meta.ino(),
                meta.mtime(),
                meta.mtime_nsec(),
                meta.ctime(),
                meta.ctime_nsec()
            ) == (
                after.dev(),
                after.ino(),
                after.mtime(),
                after.mtime_nsec(),
                after.ctime(),
                after.ctime_nsec()
            ),
        "evidence changed"
    );
    Ok(bytes)
}
pub fn bound(path: &Path) -> Result<Value> {
    Ok(json!({"path":path,"sha256":sha(&read(path)?)}))
}
pub fn pinned(path: &Path, digest: &str) -> Result<Value> {
    let bytes = read(path)?;
    ensure!(
        sha(&bytes) == digest,
        "digest changed at {}",
        path.display()
    );
    Ok(serde_json::from_slice(&bytes)?)
}
pub fn from_ref(r: &Value) -> Result<Value> {
    pinned(
        Path::new(r["path"].as_str().context("no path")?),
        r["sha256"].as_str().context("no digest")?,
    )
}
pub fn text(v: &Value) -> Result<&str> {
    v.as_str().context("expected a string")
}
pub fn create(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let parent = path.parent().context("no parent")?;
    ensure!(
        parent == fs::canonicalize(parent)?
            && fs::metadata(parent)?.uid() == 0
            && fs::metadata(parent)?.mode() & 0o022 == 0,
        "unsafe receipt parent"
    );
    let temp = parent.join(format!(
        ".audit73-{}-{}.new",
        std::process::id(),
        path.file_name().unwrap().to_string_lossy()
    ));
    let mut fd = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(mode)
        .open(&temp)?;
    let installed = (|| -> Result<()> {
        fd.write_all(bytes)?;
        fd.sync_all()?;
        let a = CString::new(temp.as_os_str().as_bytes())?;
        let b = CString::new(path.as_os_str().as_bytes())?;
        let rc = unsafe {
            libc::renameat2(
                libc::AT_FDCWD,
                a.as_ptr(),
                libc::AT_FDCWD,
                b.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        if rc < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if installed.is_err() {
        let _ = fs::remove_file(&temp);
    }
    installed
}
pub fn save(path: &Path, v: &Value) -> Result<()> {
    let mut buf = serde_json::to_vec_pretty(v)?;
    buf.push(b'\n');
    create(path, &buf, 0o600)
}
pub fn ticks(pid: i32) -> Result<u64> {
    let s = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    Ok(s.rsplit_once(')')
        .context("proc stat")?
        .1
        .split_whitespace()
        .nth(19)
        .context("proc start")?
        .parse()?)
}
pub fn group_members(group: &str) -> Result<Vec<i32>> {
    let path = Path::new("/sys/fs/cgroup")
        .join(group.trim_start_matches('/'))
        .join("cgroup.procs");
    match fs::read_to_string(path) {
        Ok(c) => c.split_whitespace().map(|v| Ok(v.parse()?)).collect(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e.into()),
    }
}
pub fn proc_path(pid: i32, k: &str) -> PathBuf {
    PathBuf::from(format!("/proc/{pid}/{k}"))
}
pub fn proc_exe(pid: i32) -> Result<PathBuf> {
    Ok(fs::read_link(proc_path(pid, "exe"))?)
}
pub fn string_path(p: &Path) -> Result<&str> {
    p.to_str().context("invalid path")
}
