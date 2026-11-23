//! Private Foundation byte custody for the selected immutable source.
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
const MAP: &str =
    "/var/lib/jetstreamer/horizon-r2-holding-foundation-node-01-user-mapping-v1/mapping.json";
const MAP_SHA: &str = "50736c4c6633b4a97f4a717a1ba5f83374b4e2af4b7ef22c90ed4e007cad35b6";
const PART: usize = 32 << 20;
#[cfg(not(any(epoch249, epoch250, epoch251, epoch267)))]
mod profile {
    pub(super) const SRC: &str = "/var/lib/jetstreamer/horizon268-cid-input-v175-a1/index.body";
    pub(super) const SIZE: u64 = 12_161_495_866;
    pub(super) const SHA: &str = "c4555600164ccd37313ae7f02c3fd36fd47a8117c91a92b812c1052ab2b2ce68";
    pub(super) const PREFIX: &str = "foundation_node_01/closed-private-v1/epoch268-cid-index-v1";
    pub(super) const RECOVERY: &str =
        "/home/ubuntu/.codex/diagnostics/horizon268-cid-recovery-v175-a1/completion.json";
    pub(super) const REC_SHA: &str =
        "d374ac0907aefdf3e5b6969afb77e1e28298969eaf2330f1c6220c9dd4363c8d";
    pub(super) const STRUCTURAL: &str =
        "/home/ubuntu/.codex/diagnostics/horizon268-structural-check-v175-a1/completion.json";
    pub(super) const STR_SHA: &str =
        "224c59913bdbb6c0093d677f0e1da5b3dbe2f5f1e141734711b118aa8782dd90";
    pub(super) const TMP: &str = "/run/horizon268-cid-holding-work";
    pub(super) const DEST: &str = "/var/lib/jetstreamer/horizon268-cid-holding-restore-v1";
    pub(super) const KEY: &str = "index-c4555600-v1.manifest";
    pub(super) const EPOCH: u64 = 268;
    pub(super) const CAR_BYTES: u64 = 476675176389;
    pub(super) const ENTRIES: u64 = 1013057978;
    pub(super) const BUCKETS: u64 = 300000;
    pub(super) const INODE: u64 = 18336466;
    pub(super) const TIMES: (i64, i64, i64, i64) = (1795317228, 600534172, 1795317228, 862535056);
}
#[cfg(epoch267)]
mod profile {
    pub(super) const SRC: &str = "/var/lib/jetstreamer/horizon267-cid-input-v173-a1/index.body";
    pub(super) const SIZE: u64 = 10_392_794_246;
    pub(super) const SHA: &str = "03ee92c1cd55485275d21633e4fd2a759eb6fb21484b580a0c6e98901795a9fc";
    pub(super) const PREFIX: &str = "foundation_node_01/closed-private-v1/epoch267-cid-index-v1";
    pub(super) const RECOVERY: &str =
        "/home/ubuntu/.codex/diagnostics/horizon267-cid-input-v173-a1/completion.json";
    pub(super) const REC_SHA: &str =
        "e922dd18dca95c0eb9a05d2d09aaf43af210d291121a5c352d54dbf6a04ef2ca";
    pub(super) const STRUCTURAL: &str =
        "/home/ubuntu/.codex/diagnostics/horizon267-cid-validate-v174-a1/completion.json";
    pub(super) const STR_SHA: &str =
        "b260b65cd84557bfc41954b9987237df61b855723beb9ac65c7e6c5f28be3daa";
    pub(super) const TMP: &str = "/run/horizon267-cid-holding-work";
    pub(super) const DEST: &str = "/var/lib/jetstreamer/horizon267-cid-holding-restore-v1";
    pub(super) const KEY: &str = "index-03ee92c1-v1.manifest";
    pub(super) const EPOCH: u64 = 267;
    pub(super) const CAR_BYTES: u64 = 428826209761;
    pub(super) const ENTRIES: u64 = 865950715;
    pub(super) const BUCKETS: u64 = 86596;
    pub(super) const INODE: u64 = 18336175;
    pub(super) const TIMES: (i64, i64, i64, i64) = (1795315093, 251462982, 1795315093, 465463670);
}
#[cfg(epoch250)]
mod profile {
    pub(super) const SRC: &str = "/home/ubuntu/.jetstreamer-private/qualification-250-reboot-20261117-v1/output/epoch-250.jet";
    pub(super) const SIZE: u64 = 185_599_540_324;
    pub(super) const SHA: &str = "070c6021b56452489de8ec8edf1a9fb92dd47715f30f4c9781fcbb10503aa0ce";
    pub(super) const PREFIX: &str =
        "foundation_node_01/closed-private-v1/epoch250-closed-archive-v1";
    pub(super) const RECOVERY: &str =
        "/home/ubuntu/.codex/diagnostics/horizon250-closed-source-check-v200-a2/completion.json";
    pub(super) const REC_SHA: &str =
        "44de880ab329ab1fea9b9d812f2c185287ceb3c8e0e0ed599275847688f55b69";
    pub(super) const STRUCTURAL: &str =
        "/home/ubuntu/.codex/diagnostics/horizon250-holding-compat-v199-a1/completion.json";
    pub(super) const STR_SHA: &str =
        "60077cbc90a49c68d7f524b524ba88b2c4d27273ed6a8dc3fe113db6412ac0ab";
    pub(super) const TMP: &str = "/run/horizon250-closed-archive-holding-work";
    pub(super) const DEST: &str =
        "/var/lib/jetstreamer/horizon250-closed-archive-holding-restore-v1";
    pub(super) const KEY: &str = "archive-070c6021-v1.manifest";
    pub(super) const RESTORE_FILE: &str = "epoch-250.jet";
    pub(super) const EPOCH: u64 = 250;
    pub(super) const INODE: u64 = 15_060_654;
    pub(super) const OUTPUT_INODE: u64 = 8_820_259;
    pub(super) const TIMES: (i64, i64, i64, i64) =
        (1_795_169_606, 173_593_399, 1_795_173_253, 625_459_056);
}
#[cfg(epoch249)]
mod profile {
    pub(super) const EPOCH: u64 = 249;
    pub(super) const SRC: &str = "/home/ubuntu/.jetstreamer-private/qualification-249-reboot-20261117-v1/output/epoch-249.jet";
    pub(super) const SIZE: u64 = 180_924_777_820;
    pub(super) const SHA: &str = "d6802f70fa854af0ca12e6c425d9b4fbdc0b443bec680a1b631993d6b3269ded";
    pub(super) const PREFIX: &str =
        "foundation_node_01/closed-private-v1/epoch249-closed-archive-v1";
    pub(super) const RECOVERY: &str =
        "/var/lib/jetstreamer/horizon-singleton-delivery249-20261119-v1/terminal-handoff.json";
    pub(super) const REC_SHA: &str =
        "a98b6967565b73618b0e8913f7579231577bcdce13e6c5756cbf9927fa09533b";
    pub(super) const STRUCTURAL: &str =
        "/var/lib/jetstreamer/horizon-singleton-delivery249-20261119-v1/terminal-drain.json";
    pub(super) const STR_SHA: &str =
        "9f03c4b51dc06001620153d2da369daf0b94646fc063205abb368e22b84c41ac";
    pub(super) const TMP: &str = "/run/horizon249-closed-archive-holding-work";
    pub(super) const DEST: &str =
        "/var/lib/jetstreamer/horizon249-closed-archive-holding-restore-v1";
    pub(super) const RESTORE_FILE: &str = "epoch-249.jet";
    pub(super) const KEY: &str = "archive-d6802f70-v1.manifest";
    pub(super) const INODE: u64 = 8_820_166;
    pub(super) const OUTPUT_INODE: u64 = 8_824_374;
    pub(super) const TIMES: (i64, i64, i64, i64) =
        (1_795_107_202, 152_908_668, 1_795_111_167, 802_019_027);
}
#[cfg(epoch251)]
mod profile {
    pub(super) const EPOCH: u64 = 251;
    pub(super) const SRC: &str = "/home/ubuntu/.jetstreamer-private/qualification-251-replacement-20261118-v1/output/epoch-251.jet";
    pub(super) const SIZE: u64 = 180_869_655_584;
    pub(super) const SHA: &str = "8248727043dc05b54effd1b383e8094283970d673a33dd65e0ff9aababa968b2";
    pub(super) const PREFIX: &str =
        "foundation_node_01/closed-private-v1/epoch251-closed-archive-v1";
    pub(super) const RECOVERY: &str =
        "/var/lib/jetstreamer/horizon-singleton-delivery251-20261119-v1/terminal-handoff.json";
    pub(super) const REC_SHA: &str =
        "85a9e5c794ebbb2699f00e0371aaaa2d8c4550c17622b967ae35defd13a0d65d";
    pub(super) const STRUCTURAL: &str =
        "/var/lib/jetstreamer/horizon-singleton-delivery251-20261119-v1/terminal-drain.json";
    pub(super) const STR_SHA: &str =
        "dc4e672d2b95528a5758ae06355819d8a2f7bfe17fa80d2218c7f3c8ad1f6194";
    pub(super) const TMP: &str = "/run/horizon251-closed-archive-holding-work";
    pub(super) const DEST: &str =
        "/var/lib/jetstreamer/horizon251-closed-archive-holding-restore-v1";
    pub(super) const RESTORE_FILE: &str = "epoch-251.jet";
    pub(super) const KEY: &str = "archive-82487270-v1.manifest";
    pub(super) const INODE: u64 = 31_112_947;
    pub(super) const OUTPUT_INODE: u64 = 31_110_842;
    pub(super) const TIMES: (i64, i64, i64, i64) =
        (1_795_273_267, 403_475_475, 1_795_273_837, 624_069_856);
}
#[cfg(any(epoch249, epoch250, epoch251))]
const SOURCE_OWNER_MODE: (u32, u32, u32) = (1000, 1000, 0o440);
#[cfg(not(any(epoch249, epoch250, epoch251)))]
const SOURCE_OWNER_MODE: (u32, u32, u32) = (0, 0, 0o400);

#[cfg(not(any(epoch249, epoch250, epoch251)))]
const RESTORE_FILE: &str = "index.body";
use profile::*;
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
                    (m.uid(), m.gid(), m.mode() & 0o7777),
                    m.nlink(),
                ) == (66305, INODE, SIZE, SOURCE_OWNER_MODE, 1)
                && (m.mtime(), m.mtime_nsec(), m.ctime(), m.ctime_nsec()) == TIMES,
            "closed original source changed",
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
#[cfg(any(epoch249, epoch251))]
fn header() -> String {
    format!(
        "horizon{EPOCH}-closed-archive-v1 epoch={EPOCH} bytes={SIZE} sha256={SHA} part_bytes={PART} mapping={MAP_SHA} terminal_handoff={REC_SHA} terminal_drain={STR_SHA} canonical=false"
    )
}
#[cfg(epoch250)]
fn header() -> String {
    format!(
        "horizon{EPOCH}-closed-archive-v1 epoch={EPOCH} bytes={SIZE} sha256={SHA} part_bytes={PART} mapping={MAP_SHA} original_source={REC_SHA} recovery={STR_SHA} canonical=false"
    )
}
#[cfg(not(any(epoch249, epoch250, epoch251)))]
fn header() -> String {
    format!(
        "horizon{EPOCH}-cid-index-v1 epoch={EPOCH} bytes={SIZE} sha256={SHA} part_bytes={PART} car_bytes={CAR_BYTES} entries={ENTRIES} buckets={BUCKETS} mapping={MAP_SHA} recovery={REC_SHA} structural={STR_SHA} canonical=false"
    )
}
fn manifest_length(profile: &str, size: u64, part: usize) -> R<u64> {
    require(size > 0 && part > 0, "empty part geometry")?;
    let parts = size.div_ceil(part as u64);
    // One newline after the header, then one 64-character digest and newline per part.
    let length = parts
        .checked_mul(65)
        .and_then(|n| n.checked_add(profile.len() as u64))
        .and_then(|n| n.checked_add(1))
        .ok_or("manifest size overflow")?;
    require(length <= 1 << 20, "manifest exceeds holding metadata limit")?;
    Ok(length)
}
fn parse(bytes: &[u8], profile: &str, size: u64, part: usize) -> R<Vec<String>> {
    require(
        bytes.len() as u64 == manifest_length(profile, size, part)?,
        "different manifest length",
    )?;
    let s = std::str::from_utf8(bytes).map_err(|_| "invalid manifest")?;
    let mut lines = s.lines();
    require(lines.next() == Some(profile), "different manifest profile")?;
    let parts: Vec<_> = lines.map(str::to_owned).collect();
    require(
        parts.len() as u64 == size.div_ceil(part as u64)
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
    let length = manifest_length(profile, size, part)?;
    let (s, m) = c.request(&fixed(), None, length)?;
    require(s == 200, "missing registered manifest")?;
    let parts = parse(&m, profile, size, part)?;
    let sha = hash_bytes(&m)?;
    let (s, b) = c.request(&format!("{PREFIX}/manifests/{sha}.manifest"), None, length)?;
    require(s == 200 && m == b, "immutable manifest differs")?;
    Ok((parts, sha))
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
fn recover_partial<T: Transport>(
    c: &T,
    parts: &[String],
    size: u64,
    part: usize,
    sha: &str,
    file: &mut File,
) -> R<()> {
    use std::io::Seek;
    file.rewind().map_err(ioe)?;
    let existing = file.metadata().map_err(ioe)?.len();
    require(existing <= size, "oversized restore prefix")?;
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
    recover(c, parts, size, part, sha, &mut Resume { f: file, existing })
}
fn restore<T: Transport>(
    c: &T,
    parts: &[String],
    size: u64,
    part: usize,
    sha: &str,
    dir: &Path,
) -> R<()> {
    let out = dir.join(RESTORE_FILE);
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
    recover_partial(c, parts, size, part, sha, &mut file)?;
    file.sync_all().map_err(ioe)?;
    require(hash(&p)? == sha, "local restoration digest")?;
    file.set_permissions(fs::Permissions::from_mode(0o400))
        .map_err(ioe)?;
    file.sync_all().map_err(ioe)?;
    publish(&p, &out)?;
    File::open(dir).and_then(|d| d.sync_all()).map_err(ioe)?;
    completed(&out, size, sha)
}
#[cfg(any(epoch249, epoch250, epoch251))]
struct HeldInode {
    device: u64,
    inode: u64,
    owner_mode: (u32, u32, u32),
    modified: std::time::SystemTime,
}

#[cfg(any(epoch249, epoch250, epoch251))]
impl HeldInode {
    fn original() -> Self {
        use std::time::{Duration, UNIX_EPOCH};
        Self {
            device: 66305,
            inode: INODE,
            owner_mode: SOURCE_OWNER_MODE,
            modified: UNIX_EPOCH + Duration::new(TIMES.0 as u64, TIMES.1 as u32),
        }
    }

    fn check(&self, metadata: &fs::Metadata) -> R<()> {
        require(
            metadata.is_file()
                && metadata.nlink() == 1
                && (metadata.dev(), metadata.ino()) == (self.device, self.inode)
                && (metadata.uid(), metadata.gid(), metadata.mode() & 0o7777) == self.owner_mode,
            "wrong quarantined original inode",
        )
    }

    fn refill<T: Transport>(
        &self,
        path: &Path,
        c: &T,
        parts: &[String],
        size: u64,
        part: usize,
        sha: &str,
    ) -> R<()> {
        self.check(&path.symlink_metadata().map_err(ioe)?)?;
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(0x20000)
            .open(path)
            .map_err(ioe)?;
        file.try_lock().map_err(|e| e.to_string())?;
        self.check(&file.metadata().map_err(ioe)?)?;
        recover_partial(c, parts, size, part, sha, &mut file)?;
        file.sync_all().map_err(ioe)?;
        self.check(&path.symlink_metadata().map_err(ioe)?)?;
        require(hash(path)? == sha, "refilled inode digest")?;
        file.set_modified(self.modified).map_err(ioe)?;
        file.sync_all().map_err(ioe)?;
        let m = path.symlink_metadata().map_err(ioe)?;
        self.check(&m)?;
        require(
            m.len() == size && m.modified().map_err(ioe)? == self.modified,
            "refilled inode metadata",
        )
    }
}

#[cfg(any(epoch249, epoch250, epoch251))]
fn refill_original(c: &Client, parts: &[String]) -> R<()> {
    let dir = Path::new(DEST);
    private_dir(dir)?;
    require(
        matches!(Path::new(SRC).symlink_metadata(), Err(e) if e.kind() == io::ErrorKind::NotFound),
        "original delivery path must be vacant during private recovery",
    )?;
    let held = HeldInode::original();
    held.refill(&dir.join("original-inode"), c, parts, SIZE, PART, SHA)?;
    File::open(dir).and_then(|dir| dir.sync_all()).map_err(ioe)
}

#[cfg(any(epoch249, epoch250, epoch251))]
fn refill_and_return_original(c: &Client, parts: &[String]) -> R<()> {
    let path = Path::new(SRC);
    let output = path.parent().ok_or("missing output directory")?;
    let quarantine = output.join(".horizon-private-holding");
    private_dir(&quarantine)?;
    let metadata = output.symlink_metadata().map_err(ioe)?;
    require(
        output.canonicalize().map_err(ioe)? == output
            && metadata.is_dir()
            && (
                metadata.dev(),
                metadata.ino(),
                metadata.uid(),
                metadata.gid(),
            ) == (
                66305,
                OUTPUT_INODE,
                SOURCE_OWNER_MODE.0,
                SOURCE_OWNER_MODE.1,
            ),
        "different delivery directory",
    )?;
    let held = HeldInode::original();
    if matches!(path.symlink_metadata(), Err(e) if e.kind() == io::ErrorKind::NotFound) {
        held.refill(
            &quarantine.join("original-inode"),
            c,
            parts,
            SIZE,
            PART,
            SHA,
        )?;
    }
    held.return_to_delivery(&quarantine, path, SIZE, SHA, &metadata)
}

#[cfg(any(epoch249, epoch250, epoch251))]
impl HeldInode {
    fn return_to_delivery(
        &self,
        holding: &Path,
        delivery: &Path,
        size: u64,
        sha: &str,
        original_dir: &fs::Metadata,
    ) -> R<()> {
        use std::os::fd::AsRawFd;
        let parent = delivery.parent().ok_or("missing delivery parent")?;
        let directory = |p: &Path| {
            OpenOptions::new()
                .read(true)
                .custom_flags(0o200000 | 0o400000)
                .open(p)
                .map_err(ioe)
        };
        let source_dir = directory(holding)?;
        let dest_dir = directory(parent)?;
        let directory_identity = |m: &fs::Metadata| (m.dev(), m.ino(), m.uid(), m.gid(), m.mode());
        let check_dirs = || -> R<()> {
            let source = source_dir.metadata().map_err(ioe)?;
            require(
                source.is_dir()
                    && source.dev() == self.device
                    && source.uid() == unsafe { getuid() }
                    && source.mode() & 0o7777 == 0o700
                    && directory_identity(&source)
                        == directory_identity(&holding.symlink_metadata().map_err(ioe)?)
                    && directory_identity(original_dir)
                        == directory_identity(&dest_dir.metadata().map_err(ioe)?)
                    && directory_identity(original_dir)
                        == directory_identity(&parent.symlink_metadata().map_err(ioe)?),
                "quarantine or delivery directory changed",
            )
        };
        check_dirs()?;
        let anchored = |dir: &File| PathBuf::from(format!("/proc/self/fd/{}", dir.as_raw_fd()));
        let held_name = anchored(&source_dir).join("original-inode");
        let dest_name = anchored(&dest_dir).join(delivery.file_name().ok_or("delivery name")?);
        let exists = |p: &Path| match p.symlink_metadata() {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(ioe(e)),
        };
        let at_source = exists(&held_name)?;
        require(
            at_source != exists(&dest_name)?,
            "both original names occupied or vacant",
        )?;
        let current = if at_source { &held_name } else { &dest_name };
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(0o400000)
            .open(current)
            .map_err(ioe)?;
        file.try_lock().map_err(|e| e.to_string())?;
        let validate = |m: &fs::Metadata| {
            self.check(m)?;
            require(
                m.len() == size && m.modified().map_err(ioe)? == self.modified,
                "incomplete refill",
            )
        };
        let before = file.metadata().map_err(ioe)?;
        validate(&before)?;
        let digest = Command::new("/usr/bin/sha256sum")
            .env_clear()
            .stdin(Stdio::from(file.try_clone().map_err(ioe)?))
            .output()
            .map_err(ioe)?;
        require(
            digest.status.success() && digest.stdout == format!("{sha}  -\n").as_bytes(),
            "delivery inode digest",
        )?;
        let after = current.symlink_metadata().map_err(ioe)?;
        validate(&after)?;
        require(
            (before.ctime(), before.ctime_nsec()) == (after.ctime(), after.ctime_nsec()),
            "original changed during hash",
        )?;
        check_dirs()?;
        if at_source {
            publish(&held_name, &dest_name)?;
        }
        dest_dir.sync_all().map_err(ioe)?;
        source_dir.sync_all().map_err(ioe)?;
        check_dirs()?;
        validate(&dest_name.symlink_metadata().map_err(ioe)?)?;
        validate(&delivery.symlink_metadata().map_err(ioe)?)?;
        require(
            !exists(&held_name)? && !exists(&holding.join("original-inode"))?,
            "quarantine name reappeared",
        )
    }
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
        args.len() == 2
            && (matches!(args[1].as_str(), "park" | "verify" | "restore")
                || (cfg!(any(epoch249, epoch250, epoch251))
                    && matches!(
                        args[1].as_str(),
                        "refill-original" | "refill-and-return-original"
                    ))),
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
        let length = manifest_length(&h, SIZE, PART)?;
        c.small(
            &format!("{PREFIX}/manifests/{}.manifest", hash_bytes(&m)?),
            &tmp.0,
            length,
        )?;
        c.small(&fixed(), &tmp.0, length)?;
    }
    let (parts, msha) = remote_manifest(&c, &h, SIZE, PART)?;
    match args[1].as_str() {
        "restore" => {
            let d = Path::new(DEST);
            private_dir(d)?;
            restore(&c, &parts, SIZE, PART, SHA, d)?;
        }
        #[cfg(any(epoch249, epoch250, epoch251))]
        "refill-original" => refill_original(&c, &parts)?,
        #[cfg(any(epoch249, epoch250, epoch251))]
        "refill-and-return-original" => refill_and_return_original(&c, &parts)?,
        "verify" => recover(&c, &parts, SIZE, PART, SHA, &mut io::sink())?,
        _ => {}
    }
    let kind = if cfg!(any(epoch249, epoch250, epoch251)) {
        "closed-archive"
    } else {
        "cid-to-offset-and-size"
    };
    println!(
        "{{\"epoch\":{EPOCH},\"kind\":\"{kind}\",\"operation\":\"{}\",\"manifest_sha256\":\"{msha}\",\"sha256\":\"{SHA}\",\"bytes\":{SIZE},\"parts\":{},\"capacity_credit\":0,\"canonical_publication\":false}}",
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
