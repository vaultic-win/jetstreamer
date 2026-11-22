//! Exact Foundation CID-index byte custody for epoch 268.
mod transport;
use std::{
    env,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
};
use transport::{Client, OWNER, R, Transport, hash, hash_bytes, hex, require};
const SRC: &str = "/var/lib/jetstreamer/horizon268-cid-input-v175-a1/index.body";
const SIZE: u64 = 12_161_495_866;
const SHA: &str = "c4555600164ccd37313ae7f02c3fd36fd47a8117c91a92b812c1052ab2b2ce68";
const PART: usize = 32 << 20;
const PREFIX: &str = "foundation_node_01/closed-private-v1/epoch268-cid-index-v1";
const MAP: &str =
    "/var/lib/jetstreamer/horizon-r2-holding-foundation-node-01-user-mapping-v1/mapping.json";
const MAP_SHA: &str = "50736c4c6633b4a97f4a717a1ba5f83374b4e2af4b7ef22c90ed4e007cad35b6";
const RECOVERY: &str =
    "/home/ubuntu/.codex/diagnostics/horizon268-cid-recovery-v175-a1/completion.json";
const REC_SHA: &str = "d374ac0907aefdf3e5b6969afb77e1e28298969eaf2330f1c6220c9dd4363c8d";
const STRUCTURAL: &str =
    "/home/ubuntu/.codex/diagnostics/horizon268-structural-check-v175-a1/completion.json";
const STR_SHA: &str = "224c59913bdbb6c0093d677f0e1da5b3dbe2f5f1e141734711b118aa8782dd90";
const TMP: &str = "/run/horizon268-cid-holding-work";
const DEST: &str = "/var/lib/jetstreamer/horizon268-cid-holding-restore-v1";
const KEY: &str = "index-c4555600-v1.manifest";
fn ioe(e: io::Error) -> String {
    e.to_string()
}
fn bound(p: &str, sha: &str) -> R<()> {
    let p = Path::new(p);
    let m = p.symlink_metadata().map_err(ioe)?;
    require(
        p.canonicalize().map_err(ioe)? == p
            && m.is_file()
            && m.nlink() == 1
            && m.uid() == 0
            && m.mode() & 0o022 == 0
            && m.len() < 4 << 20
            && hash(p)? == sha,
        "different fixed evidence",
    )
}
fn authority() -> R<()> {
    require(
        fs::read_to_string("/proc/sys/kernel/hostname")
            .map_err(ioe)?
            .trim()
            == "horizon-vaultic",
        "different Foundation host",
    )?;
    for (p, h) in [(MAP, MAP_SHA), (RECOVERY, REC_SHA), (STRUCTURAL, STR_SHA)] {
        bound(p, h)?;
    }
    let hash_path = Path::new("/usr/bin/sha256sum");
    let target = hash_path.canonicalize().map_err(ioe)?;
    let m = target.symlink_metadata().map_err(ioe)?;
    require(
        target == Path::new("/usr/lib/cargo/bin/coreutils/sha256sum")
            && m.is_file()
            && m.uid() == 0
            && m.mode() & 0o022 == 0
            && hash(&target)? == "27a7d8f6a005702618e92c88f20b829d38247ad3369e0c35b1ff219d15194bd1",
        "different installed SHA-256 tool",
    )?;
    Ok(())
}
fn original(path: &Path) -> R<File> {
    require(
        path == Path::new(SRC) && path.canonicalize().map_err(ioe)? == path,
        "source alias",
    )?;
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(0x20000)
        .open(path)
        .map_err(ioe)?;
    for m in [
        f.metadata().map_err(ioe)?,
        path.symlink_metadata().map_err(ioe)?,
    ] {
        require(
            m.is_file()
                && (
                    m.dev(),
                    m.ino(),
                    m.len(),
                    m.uid(),
                    m.gid(),
                    m.mode() & 0o7777,
                    m.nlink(),
                ) == (66305, 18336466, SIZE, 0, 0, 0o400, 1)
                && (m.mtime(), m.mtime_nsec(), m.ctime(), m.ctime_nsec())
                    == (1795317228, 600534172, 1795317228, 862535056),
            "closed original 268 CID table changed",
        )?;
    }
    Ok(f)
}
fn private_dir(dir: &Path) -> R<()> {
    let m = dir.symlink_metadata().map_err(ioe)?;
    require(
        dir.canonicalize().map_err(ioe)? == dir
            && m.is_dir()
            && m.uid() == 0
            && m.mode() & 0o7777 == 0o700,
        "unsafe private work or restore directory",
    )
}
struct Whole(Option<Child>);
impl Whole {
    fn new() -> R<Self> {
        Ok(Self(Some(
            Command::new("/usr/bin/sha256sum")
                .env_clear()
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .map_err(ioe)?,
        )))
    }
    fn add(&mut self, data: &[u8]) -> R<()> {
        self.0
            .as_mut()
            .and_then(|p| p.stdin.as_mut())
            .ok_or("whole hash closed")?
            .write_all(data)
            .map_err(ioe)
    }
    fn done(mut self, sha: &str) -> R<()> {
        let mut p = self.0.take().ok_or("hash process absent")?;
        drop(p.stdin.take());
        let o = p.wait_with_output().map_err(ioe)?;
        require(
            o.status.success()
                && std::str::from_utf8(&o.stdout)
                    .ok()
                    .and_then(|s| s.split_whitespace().next())
                    == Some(sha),
            "whole authenticated reconstruction digest",
        )
    }
}
impl Drop for Whole {
    fn drop(&mut self) {
        if let Some(mut p) = self.0.take() {
            drop(p.stdin.take());
            let _ = p.kill();
            let _ = p.wait();
        }
    }
}
fn key(h: &str) -> String {
    format!("{PREFIX}/parts/{h}.blob")
}
fn fixed() -> String {
    format!("{PREFIX}/{KEY}")
}
fn manifest(header: &str, hashes: &[String]) -> Vec<u8> {
    format!("{header}\n{}\n", hashes.join("\n")).into_bytes()
}
fn header() -> String {
    format!(
        "horizon268-cid-index-v1 epoch=268 bytes={SIZE} sha256={SHA} part_bytes={PART} car_bytes=476675176389 entries=1013057978 buckets=300000 mapping={MAP_SHA} recovery={REC_SHA} structural={STR_SHA} canonical=false"
    )
}
fn parse(bytes: &[u8], profile: &str, size: u64, part: usize) -> R<Vec<String>> {
    let s = std::str::from_utf8(bytes).map_err(|_| "invalid manifest")?;
    let mut lines = s.lines();
    require(
        lines.next() == Some(profile) && bytes.len() < 65536,
        "different manifest profile",
    )?;
    let parts: Vec<_> = lines.map(str::to_owned).collect();
    require(
        part > 0
            && parts.len() as u64 == size.div_ceil(part as u64)
            && parts.iter().all(|h| hex(h, 64))
            && manifest(profile, &parts) == bytes,
        "invalid chunk manifest",
    )?;
    Ok(parts)
}
struct Scratch(PathBuf);
impl Scratch {
    fn new(root: &Path, purpose: &str, data: &[u8]) -> R<Self> {
        let p = root.join(format!("{purpose}-{}", std::process::id()));
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&p)
            .map_err(ioe)?;
        let scratch = Self(p);
        f.write_all(data).map_err(ioe)?;
        Ok(scratch)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}
fn parked<T: Transport>(
    client: &T,
    src: &mut impl Read,
    size: u64,
    part: usize,
    sha: &str,
    scratch: &Path,
) -> R<Vec<String>> {
    require(part > 0 && size > 0, "empty part geometry")?;
    let mut left = size;
    let mut hashes = Vec::new();
    let mut total = Whole::new()?;
    while left != 0 {
        let n = left.min(part as u64) as usize;
        let mut local = vec![0; n];
        src.read_exact(&mut local).map_err(ioe)?;
        let h = hash_bytes(&local)?;
        let k = key(&h);
        let (code, mut data) = client.request(&k, None, (n as u64).max(4096))?;
        if code == 404 {
            drop(data);
            let tmp = Scratch::new(scratch, "part", &local)?;
            let (status, _) = client.request(&k, Some(&tmp.0), 32768)?;
            require(
                status == 200 || status == 412,
                "conditional part create failed",
            )?;
            let (status, got) = client.request(&k, None, (n as u64).max(4096))?;
            require(status == 200, "missing part after conditional create")?;
            data = got;
        } else {
            require(code == 200, "could not determine existing part")?;
        }
        require(data == local, "authenticated part differs from original")?;
        total.add(&data)?;
        hashes.push(h);
        left -= n as u64;
    }
    require(src.read(&mut [0]).map_err(ioe)? == 0, "extra source bytes")?;
    total.done(sha)?;
    Ok(hashes)
}
fn remote_manifest<T: Transport>(
    c: &T,
    profile: &str,
    size: u64,
    part: usize,
) -> R<(Vec<String>, String)> {
    let (s, m) = c.request(&fixed(), None, 65536)?;
    require(s == 200, "missing registered manifest")?;
    let sha = hash_bytes(&m)?;
    let (s, b) = c.request(&format!("{PREFIX}/manifests/{sha}.manifest"), None, 65536)?;
    require(s == 200 && m == b, "immutable manifest differs")?;
    Ok((parse(&m, profile, size, part)?, sha))
}
fn recover<T: Transport>(
    c: &T,
    hashes: &[String],
    size: u64,
    part: usize,
    sha: &str,
    write: &mut impl Write,
) -> R<()> {
    let mut left = size;
    let mut total = Whole::new()?;
    for h in hashes {
        let n = left.min(part as u64);
        require(n > 0, "manifest overflow")?;
        let (s, b) = c.request(&key(h), None, n)?;
        require(
            s == 200 && b.len() as u64 == n && hash_bytes(&b)? == *h,
            "restored part missing or corrupt",
        )?;
        total.add(&b)?;
        write.write_all(&b).map_err(ioe)?;
        left -= n;
    }
    require(left == 0, "manifest short")?;
    total.done(sha)
}
fn completed(path: &Path, size: u64, sha: &str) -> R<()> {
    let m = path.symlink_metadata().map_err(ioe)?;
    require(
        path.canonicalize().map_err(ioe)? == path
            && m.is_file()
            && m.uid() == unsafe { getuid() }
            && m.mode() & 0o7777 == 0o400
            && m.nlink() == 1
            && m.len() == size
            && hash(path)? == sha,
        "restored destination conflict",
    )
}
unsafe extern "C" {
    fn getuid() -> u32;
    fn renameat2(d1: i32, p1: *const i8, d2: i32, p2: *const i8, f: u32) -> i32;
}
fn publish(p: &Path, d: &Path) -> R<()> {
    use std::{ffi::CString, os::unix::ffi::OsStrExt};
    let a = CString::new(p.as_os_str().as_bytes()).map_err(|_| "path")?;
    let b = CString::new(d.as_os_str().as_bytes()).map_err(|_| "path")?;
    if unsafe { renameat2(-100, a.as_ptr(), -100, b.as_ptr(), 1) } != 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    Ok(())
}
fn restore<T: Transport>(
    c: &T,
    parts: &[String],
    size: u64,
    part: usize,
    sha: &str,
    dir: &Path,
) -> R<()> {
    let out = dir.join("index.body");
    if out.try_exists().map_err(ioe)? {
        completed(&out, size, sha)?;
        recover(c, parts, size, part, sha, &mut io::sink())?;
        return File::open(dir).and_then(|d| d.sync_all()).map_err(ioe);
    }
    let p = dir.join(".index.partial");
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&p)
        .or_else(|e| {
            if e.kind() == io::ErrorKind::AlreadyExists {
                OpenOptions::new()
                    .read(true)
                    .write(true)
                    .custom_flags(0x20000)
                    .open(&p)
            } else {
                Err(e)
            }
        })
        .map_err(ioe)?;
    let m = file.metadata().map_err(ioe)?;
    let base = p.symlink_metadata().map_err(ioe)?;
    require(
        p.canonicalize().map_err(ioe)? == p
            && m.dev() == base.dev()
            && m.ino() == base.ino()
            && m.is_file()
            && m.uid() == unsafe { getuid() }
            && m.nlink() == 1
            && matches!(m.mode() & 0o7777, 0o600 | 0o400)
            && m.len() <= size,
        "unexpected restore partial",
    )?;
    // Verify each already written byte against its authenticated part and append only the remainder.
    struct Resume<'a> {
        f: &'a mut File,
        existing: u64,
    }
    impl Write for Resume<'_> {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            let n = self.existing.min(data.len() as u64) as usize;
            let mut old = vec![0; n];
            self.f.read_exact(&mut old)?;
            if old != data[..n] {
                return Err(io::Error::other("restore partial prefix differs"));
            }
            self.f.write_all(&data[n..])?;
            self.existing -= n as u64;
            Ok(data.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            self.f.flush()
        }
    }
    recover(
        c,
        parts,
        size,
        part,
        sha,
        &mut Resume {
            f: &mut file,
            existing: m.len(),
        },
    )?;
    file.sync_all().map_err(ioe)?;
    require(hash(&p)? == sha, "local restoration digest")?;
    file.set_permissions(fs::Permissions::from_mode(0o400))
        .map_err(ioe)?;
    file.sync_all().map_err(ioe)?;
    publish(&p, &out)?;
    File::open(dir).and_then(|d| d.sync_all()).map_err(ioe)?;
    completed(&out, size, sha)
}
fn approved_owner(code: u16, body: &[u8]) -> R<()> {
    require(
        code == 200 && body == OWNER,
        "unexpected Foundation remote owner",
    )
}
fn run() -> R<()> {
    let args: Vec<_> = env::args().collect();
    require(
        args.len() == 2 && matches!(args[1].as_str(), "park" | "verify" | "restore"),
        "use park, verify or restore",
    )?;
    authority()?;
    let c = Client::new()?;
    let (s, owner) = c.request("foundation_node_01/owner.json", None, 4096)?;
    approved_owner(s, &owner)?;
    let h = header();
    if args[1] == "park" {
        let p = Path::new(SRC);
        let work = Path::new(TMP);
        private_dir(work)?;
        let mut f = original(p)?;
        require(hash(p)? == SHA, "wrong source bytes")?;
        let parts = parked(&c, &mut f, SIZE, PART, SHA, work)?;
        drop(original(p)?);
        require(
            hash(p)? == SHA,
            "source changed after authenticated readback",
        )?;
        drop(original(p)?);
        let m = manifest(&h, &parts);
        parse(&m, &h, SIZE, PART)?;
        let tmp = Scratch::new(work, "manifest", &m)?;
        c.small(
            &format!("{PREFIX}/manifests/{}.manifest", hash_bytes(&m)?),
            &tmp.0,
        )?;
        c.small(&fixed(), &tmp.0)?;
    }
    let (parts, msha) = remote_manifest(&c, &h, SIZE, PART)?;
    match args[1].as_str() {
        "restore" => {
            let d = Path::new(DEST);
            private_dir(d)?;
            restore(&c, &parts, SIZE, PART, SHA, d)?;
        }
        "verify" => recover(&c, &parts, SIZE, PART, SHA, &mut io::sink())?,
        _ => {}
    }
    println!(
        "{{\"epoch\":268,\"kind\":\"cid-to-offset-and-size\",\"operation\":\"{}\",\"manifest_sha256\":\"{msha}\",\"sha256\":\"{SHA}\",\"bytes\":{SIZE},\"parts\":{},\"capacity_credit\":0,\"canonical_publication\":false}}",
        args[1],
        parts.len()
    );
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(1)
    }
}
#[cfg(test)]
mod tests;
