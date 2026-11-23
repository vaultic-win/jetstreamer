use super::*;

pub const R: &str = "/var/lib/jetstreamer/horizon_runtime_data";
#[cfg(not(any(
    epoch167_cold_rebook,
    epoch166_retry11,
    epoch170_retry11,
    epoch170_retry12,
    epoch170_retry13,
    epoch168_cold_rebook
)))]
pub const COMMON: &str = "incident-replay-guard-20261121-v1";
#[cfg(not(any(
    epoch167_cold_rebook,
    epoch166_retry11,
    epoch170_retry11,
    epoch170_retry12,
    epoch170_retry13,
    epoch168_cold_rebook
)))]
pub const PROVIDER: &str = "incident-replay-fit-20261121-v1/tools/post-stop-fit";
pub const SEALER: &str = "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3";
pub fn rt(s: &str) -> PathBuf {
    Path::new(R).join(s)
}
pub fn base() -> PathBuf {
    rt(BASE)
}
pub fn run() -> PathBuf {
    Path::new(LANE).join(ATTEMPT)
}
pub fn n(v: &Value, key: &str) -> Result<u64> {
    v[key].as_u64().with_context(|| format!("missing {key}"))
}
pub fn st<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v[key].as_str().with_context(|| format!("missing {key}"))
}
pub fn sha(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
pub fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
pub fn hex(s: &str, len: usize) -> bool {
    s.len() == len
        && s.as_bytes()
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
}
pub fn raw(p: &Path, max: u64) -> Result<Vec<u8>> {
    ensure!(
        p.is_absolute() && p.canonicalize()? == p,
        "indirect file {}",
        p.display()
    );
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(p)?;
    let a = f.metadata()?;
    ensure!(
        a.is_file() && a.uid() == 0 && a.mode() & 0o022 == 0 && a.len() > 0 && a.len() <= max,
        "untrusted file {}",
        p.display()
    );
    let mut bytes = Vec::new();
    (&mut f).take(max + 1).read_to_end(&mut bytes)?;
    let b = f.metadata()?;
    let c = fs::symlink_metadata(p)?;
    ensure!(
        a.len() == bytes.len() as u64
            && (a.dev(), a.ino(), a.ctime(), a.ctime_nsec())
                == (c.dev(), c.ino(), b.ctime(), b.ctime_nsec()),
        "file changed"
    );
    Ok(bytes)
}
pub fn doc(p: &Path, digest: Option<&str>) -> Result<(Value, Value)> {
    let b = raw(p, 64 << 20)?;
    let h = sha(&b);
    ensure!(
        digest.is_none_or(|x| x == h),
        "changed JSON {}",
        p.display()
    );
    Ok((serde_json::from_slice(&b)?, json!({"path":p,"sha256":h})))
}
pub fn bound(k: &Value, p: &Path) -> Result<Value> {
    ensure!(k["path"] == json!(p), "wrong path");
    Ok(doc(p, Some(st(k, "sha256")?))?.0)
}
pub fn file_digest(p: &Path) -> Result<String> {
    ensure!(p.canonicalize()? == p, "indirect input");
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(p)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file() && m.uid() == 0 && m.mode() & 0o022 == 0,
        "unsealed input {}",
        p.display()
    );
    let mut h = Sha256::new();
    std::io::copy(&mut f, &mut h)?;
    let n = fs::symlink_metadata(p)?;
    ensure!(
        (m.dev(), m.ino(), m.len(), m.ctime(), m.ctime_nsec())
            == (n.dev(), n.ino(), n.len(), n.ctime(), n.ctime_nsec()),
        "input changed"
    );
    Ok(format!("{:x}", h.finalize()))
}
pub fn record(name: &str, v: &Value) -> Result<Value> {
    ensure!(!name.contains('/'), "foreign record");
    let dir = base();
    let path = dir.join(name);
    let mut b = serde_json::to_vec_pretty(v)?;
    b.push(b'\n');
    let mut f = tempfile::NamedTempFile::new_in(&dir)?;
    f.as_file()
        .set_permissions(fs::Permissions::from_mode(0o444))?;
    f.write_all(&b)?;
    f.as_file().sync_all()?;
    f.persist_noclobber(&path)?;
    File::open(dir)?.sync_all()?;
    Ok(json!({"path":path,"sha256":sha(&b)}))
}
pub fn command(program: &str, args: &[&str], seconds: u64) -> Result<Vec<u8>> {
    let out = Command::new("/usr/bin/timeout")
        .arg(format!("{seconds}s"))
        .arg(program)
        .args(args)
        .output()?;
    ensure!(
        out.status.success(),
        "{} {:?}: {}",
        program,
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    Ok(out.stdout)
}
pub fn native(unit: &str) -> Result<Value> {
    let b = command(
        "/usr/bin/systemctl",
        &[
            "show",
            "-p",
            "Id,LoadState,ActiveState,SubState,InvocationID,MainPID,ControlPID,Job,NRestarts,ControlGroup,Result,CPUQuotaPerSecUSec,MemoryMax,MemorySwapMax,Triggers,TriggeredBy",
            unit,
        ],
        10,
    )?;
    let mut v = json!({});
    for l in std::str::from_utf8(&b)?.lines() {
        let (k, x) = l.split_once('=').context("manager property")?;
        v[k] = x.into();
    }
    Ok(v)
}
pub fn proc_row(pid: u64) -> Result<(u64, u64, String)> {
    let p = Path::new("/proc").join(pid.to_string());
    let t = fs::read_to_string(p.join("stat"))?;
    let f: Vec<_> = t
        .rsplit_once(") ")
        .context("stat comm")?
        .1
        .split_whitespace()
        .collect();
    Ok((
        f[1].parse()?,
        f[19].parse()?,
        fs::read_to_string(p.join("cgroup"))?.trim().into(),
    ))
}
pub fn same(a: &Path, b: &Path) -> Result<bool> {
    let x = fs::metadata(a)?;
    let y = fs::metadata(b)?;
    Ok((x.dev(), x.ino()) == (y.dev(), y.ino()))
}
pub fn members(unit: &str) -> Result<Vec<u64>> {
    let p = Path::new("/sys/fs/cgroup/system.slice")
        .join(unit)
        .join("cgroup.procs");
    if !p.try_exists()? {
        return Ok(vec![]);
    }
    fs::read_to_string(p)?
        .lines()
        .map(|x| x.parse().map_err(Into::into))
        .collect()
}
