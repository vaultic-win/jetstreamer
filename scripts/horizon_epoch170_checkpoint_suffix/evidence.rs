//! Root-owned immutable evidence, native process identities, and no-clobber writes.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    ffi::OsStr,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

pub fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
pub fn digest(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
pub fn word<'a>(row: &'a Value, k: &str) -> Result<&'a str> {
    row[k].as_str().with_context(|| format!("missing {k}"))
}
pub fn num(row: &Value, k: &str) -> Result<u64> {
    row[k].as_u64().with_context(|| format!("missing {k}"))
}
pub fn stamp(p: &Path) -> Result<Value> {
    let m = fs::symlink_metadata(p)?;
    Ok(json!([
        m.dev(),
        m.ino(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec()
    ]))
}
pub fn trusted(p: &Path) -> Result<Vec<u8>> {
    ensure!(
        p.is_absolute() && p.canonicalize()? == p,
        "indirect evidence {}",
        p.display()
    );
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(p)?;
    let m = f.metadata()?;
    let initial = stamp(p)?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.gid() == 0
            && m.nlink() == 1
            && m.mode() & 0o022 == 0
            && m.len() <= 96 << 20,
        "evidence custody {}",
        p.display()
    );
    ensure!(
        m.dev() == initial[0].as_u64().unwrap() && m.ino() == initial[1].as_u64().unwrap(),
        "opened different inode"
    );
    let mut b = Vec::new();
    (&f).take((96 << 20) + 1).read_to_end(&mut b)?;
    ensure!(
        b.len() as u64 == m.len() && stamp(p)? == initial,
        "changed evidence {}",
        p.display()
    );
    Ok(b)
}
pub fn reference(p: &Path) -> Result<Value> {
    Ok(json!({"path":p,"sha256":digest(&trusted(p)?)}))
}
pub fn bound(r: &Value) -> Result<Value> {
    let p = Path::new(word(r, "path")?);
    let b = trusted(p)?;
    ensure!(
        digest(&b) == word(r, "sha256")?,
        "digest differs {}",
        p.display()
    );
    Ok(serde_json::from_slice(&b)?)
}
pub fn member(seal: &Value, name: &str) -> Result<PathBuf> {
    ensure!(!name.contains('/') && !name.is_empty(), "invalid member");
    let d = bound(seal)?;
    let dest = Path::new(word(&d, "destination")?);
    ensure!(
        Path::new(word(seal, "path")?) == dest.join("deployment-seal-receipt.json"),
        "invalid seal path"
    );
    let rows = d["members"].as_array().context("missing members")?;
    let matches = rows
        .iter()
        .filter(|r| r["name"] == name)
        .collect::<Vec<_>>();
    ensure!(matches.len() == 1, "unknown member {name}");
    let p = dest.join(name);
    ensure!(
        reference(&p)?["sha256"] == matches[0]["sha256"],
        "changed member {name}"
    );
    Ok(p)
}
pub fn receipt(p: &Path, val: &Value) -> Result<Value> {
    let mut bytes = serde_json::to_vec_pretty(val)?;
    bytes.push(b'\n');
    publish(p, &bytes, 0o400)?;
    reference(p)
}
pub fn publish(p: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let parent = p.parent().context("missing parent")?;
    let m = fs::symlink_metadata(parent)?;
    ensure!(
        parent.canonicalize()? == parent
            && m.is_dir()
            && m.uid() == 0
            && m.gid() == 0
            && m.mode() & 0o022 == 0,
        "untrusted output directory"
    );
    let tmp = parent.join(format!(
        ".pending-{}-{}",
        std::process::id(),
        p.file_name().context("missing filename")?.to_string_lossy()
    ));
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&tmp)?;
    let result = (|| -> Result<()> {
        f.write_all(bytes)?;
        f.set_permissions(fs::Permissions::from_mode(mode))?;
        f.sync_all()?;
        fs::hard_link(&tmp, p)?;
        Ok(())
    })();
    fs::remove_file(tmp)?;
    File::open(parent)?.sync_all()?;
    result
}
pub fn command<P: AsRef<OsStr>>(program: &str, args: &[P]) -> Result<String> {
    let o = Command::new(program).args(args).output()?;
    ensure!(
        o.status.success(),
        "{} {:?}: {}",
        program,
        o.status,
        String::from_utf8_lossy(&o.stderr)
            .chars()
            .rev()
            .take(1600)
            .collect::<String>()
            .chars()
            .rev()
            .collect::<String>()
    );
    Ok(String::from_utf8(o.stdout)?)
}
pub fn props(unit: &str, fields: &str) -> Result<BTreeMap<String, String>> {
    let found = Command::new("/usr/bin/systemctl")
        .args(["show", "--all", "-p", fields, "--", unit])
        .output()?;
    let row: BTreeMap<_, _> = String::from_utf8(found.stdout)?
        .lines()
        .filter_map(|l| l.split_once('=').map(|(a, b)| (a.to_owned(), b.to_owned())))
        .collect();
    ensure!(
        (found.status.success()
            || found.status.code() == Some(4)
                && row.get("LoadState").is_some_and(|s| s == "not-found"))
            && fields.split(',').all(|s| row.contains_key(s)),
        "incomplete PID1 properties {unit}: {row:?}"
    );
    Ok(row)
}
pub fn idle(unit: &str) -> Result<()> {
    if unit.ends_with(".timer") {
        let s = props(unit, "Id,LoadState,ActiveState,Job")?;
        ensure!(
            s["Id"] == unit && s["ActiveState"] == "inactive" && s["Job"].is_empty(),
            "occupied timer {unit}"
        );
        return Ok(());
    }
    let s = props(unit, "Id,LoadState,ActiveState,MainPID,ControlPID,Job")?;
    ensure!(
        s["Id"] == unit
            && matches!(s["ActiveState"].as_str(), "inactive" | "failed")
            && s["MainPID"] == "0"
            && s["ControlPID"] == "0"
            && s["Job"].is_empty(),
        "occupied unit {unit}"
    );
    Ok(())
}
pub fn ticks(pid: u32) -> Result<u64> {
    let s = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    Ok(s.rsplit_once(") ")
        .context("unreadable pid stat")?
        .1
        .split_whitespace()
        .nth(19)
        .context("missing start ticks")?
        .parse()?)
}
pub fn inode(p: &Path) -> Result<(u64, u64)> {
    let m = fs::metadata(p)?;
    Ok((m.dev(), m.ino()))
}
pub fn du(p: &str) -> Result<u64> {
    Ok(command("/usr/bin/du", &["-sx", "-B1", "--", p])?
        .split_whitespace()
        .next()
        .context("missing allocation")?
        .parse()?)
}
pub fn available() -> Result<(u64, u64)> {
    let c = c"/home/sol";
    let mut s = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    ensure!(
        unsafe { libc::statvfs(c.as_ptr(), s.as_mut_ptr()) } == 0,
        "home statvfs"
    );
    let s = unsafe { s.assume_init() };
    let mem = fs::read_to_string("/proc/meminfo")?;
    let m = mem
        .lines()
        .find_map(|l| l.strip_prefix("MemAvailable:"))
        .context("missing MemAvailable")?
        .split_whitespace()
        .next()
        .context("no memory value")?
        .parse::<u64>()?;
    Ok((s.f_bavail * s.f_frsize, m * 1024))
}
