//! Retire only the closed original-entry preparation file after verifying the separate sealed input and private custody.
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    env,
    ffi::CString,
    fs::{self, File, Metadata, OpenOptions},
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt},
        },
    },
    path::Path,
    process::Command,
};

const BASE: &str = "/home/sol/.jetstreamer-private";
const SOURCE_DIR: &str = "/home/sol/.jetstreamer-private/epoch141-original-bundle-20261023-v1";
const KEEPER_DIR: &str = "/usr/local/lib/jetstreamer/horizon-epoch141-original-input-20261023-v1";
const STATE: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch141-preparation-retirement-20261127-v1";
const SHA: &str = "5605dd1ba08b7e790227b0efc388a74a02cdf665220d2455c3ed39f803feada0";
const CUSTODY: &str = "46b23d41f1e2c7818d0224bacee1f6396071505bf7119676574b0d17ef4eb878";
const LENGTH: u64 = 15_067_873_514;
const ALLOCATED: u64 = 15_067_901_952;
const UNIT: &str = "horizon-141-preparation-retirement-20261127-v1.service";
const CLOSED: [(&str, &str, &str, &str); 3] = [
    (
        "horizon141-original-bundle-prepare-20261023-v1.service",
        "384807c380184ba7aae93c68d722422b",
        "active",
        "exited",
    ),
    (
        "horizon141-original-input-seal-20261023-v1.service",
        "0ffe666435344c7598ffe9d62516fd03",
        "active",
        "exited",
    ),
    (
        "jetstreamer-holding-scratch185-execute-0946-20261024-v2.service",
        "551ebb811ccb4b3da1acf9d06f3fbf56",
        "failed",
        "failed",
    ),
];
fn open_ro(path: &Path) -> Result<File> {
    ensure!(
        path.canonicalize()? == path,
        "aliased path {}",
        path.display()
    );
    Ok(OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?)
}
fn hash(f: &File) -> Result<String> {
    // Feed the same open file description to the native SHA-256 reader and keep its lease.
    let command = Command::new("/usr/bin/sha256sum")
        .arg("-")
        .stdin(f.try_clone()?)
        .output()?;
    let output = std::str::from_utf8(&command.stdout)?;
    let digest = output
        .strip_suffix("  -\n")
        .context("invalid SHA-256 result")?;
    ensure!(
        command.status.success()
            && digest.len() == 64
            && digest
                .bytes()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "native SHA-256 read failed"
    );
    Ok(digest.to_owned())
}
fn pinned(path: &Path, sha: &str) -> Result<Vec<u8>> {
    let f = open_ro(path)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file() && m.uid() == 0 && m.nlink() == 1 && m.len() <= 10 << 20,
        "foreign bound member"
    );
    let mut b = Vec::new();
    f.take((10 << 20) + 1).read_to_end(&mut b)?;
    ensure!(
        format!("{:x}", Sha256::digest(&b)) == sha,
        "bound digest differs {}",
        path.display()
    );
    Ok(b)
}
fn lock(path: &Path, ino: u64, uid: u32) -> Result<File> {
    let f = open_ro(path)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file()
            && (m.dev(), m.ino(), m.uid(), m.nlink(), m.mode() & 0o7777)
                == (64512, ino, uid, 1, 0o600),
        "foreign lock"
    );
    ensure!(
        unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "lock occupied"
    );
    Ok(f)
}
#[derive(Clone, Copy)]
struct Identity {
    device: u64,
    inode: u64,
    bytes: u64,
    allocated: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    mtime: (i64, i64),
    ctime: (i64, i64),
}
impl Identity {
    fn from(m: &Metadata) -> Self {
        Self {
            device: m.dev(),
            inode: m.ino(),
            bytes: m.len(),
            allocated: m.blocks() * 512,
            uid: m.uid(),
            gid: m.gid(),
            mode: m.mode() & 0o7777,
            mtime: (m.mtime(), m.mtime_nsec()),
            ctime: (m.ctime(), m.ctime_nsec()),
        }
    }
    fn check(&self, m: &Metadata, moved: bool) -> Result<()> {
        let a = Self::from(m);
        ensure!(
            m.is_file()
                && m.nlink() == 1
                && (
                    a.device,
                    a.inode,
                    a.bytes,
                    a.allocated,
                    a.uid,
                    a.gid,
                    a.mode,
                    a.mtime
                ) == (
                    self.device,
                    self.inode,
                    self.bytes,
                    self.allocated,
                    self.uid,
                    self.gid,
                    self.mode,
                    self.mtime
                )
                && (moved || a.ctime == self.ctime),
            "file identity changed"
        );
        Ok(())
    }
}
const SOURCE_ID: Identity = Identity {
    device: 64512,
    inode: 95227316,
    bytes: LENGTH,
    allocated: ALLOCATED,
    uid: 0,
    gid: 0,
    mode: 0o600,
    mtime: (1792731923, 413011612),
    ctime: (1792731923, 413011612),
};
const KEEPER_ID: Identity = Identity {
    device: 64512,
    inode: 100539636,
    bytes: LENGTH,
    allocated: ALLOCATED,
    uid: 0,
    gid: 0,
    mode: 0o444,
    mtime: (1792733026, 759152813),
    ctime: (1795118103, 963465226),
};
fn leased(path: &Path, id: Identity, moved: bool, kind: i32) -> Result<File> {
    let f = open_ro(path)?;
    id.check(&f.metadata()?, moved)?;
    // An exclusive source lease refuses an inode with another open file or a shared writable mapping.
    ensure!(
        unsafe { libc::fcntl(f.as_raw_fd(), libc::F_SETLEASE, kind) } == 0,
        "lease unavailable on {}: {}",
        path.display(),
        std::io::Error::last_os_error()
    );
    Ok(f)
}
fn lease_valid(f: &File, kind: i32) -> Result<()> {
    ensure!(
        unsafe { libc::fcntl(f.as_raw_fd(), libc::F_GETLEASE) } == kind,
        "lease break requested"
    );
    Ok(())
}
fn unit(name: &str) -> Result<std::collections::HashMap<String, String>> {
    let r=Command::new("/usr/bin/systemctl").args(["show",name,"-p","Id,ActiveState,SubState,InvocationID,MainPID,ControlPID,Restart,Job,TriggeredBy,NRestarts,FragmentPath"]).output()?;
    ensure!(r.status.success(), "cannot inspect {name}");
    Ok(String::from_utf8(r.stdout)?
        .lines()
        .map(|s| {
            s.split_once('=')
                .context("invalid systemctl row")
                .map(|(k, v)| (k.to_string(), v.to_string()))
        })
        .collect::<Result<_>>()?)
}
fn no_source_mounts(dir: &Path, current: &Path) -> Result<()> {
    let source = dir.join("original-entries.data");
    let mut names = BTreeSet::new();
    for p in [source.as_path(), current] {
        names.insert(format!("/{}", p.strip_prefix("/home/sol")?.display()));
    }
    let mut checked = BTreeSet::new();
    for proc in fs::read_dir("/proc")? {
        let proc = proc?;
        if proc
            .file_name()
            .to_str()
            .is_none_or(|v| v.parse::<u32>().is_err())
        {
            continue;
        }
        let pid = proc.path();
        let mount_ns = pid.join("ns/mnt");
        let first = match fs::metadata(&mount_ns) {
            Ok(v) => (v.dev(), v.ino()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e.into()),
        };
        if checked.contains(&first) {
            continue;
        }
        let mounts = match fs::read_to_string(pid.join("mountinfo")) {
            Ok(m) => m,
            Err(_) if !mount_ns.try_exists()? => continue,
            Err(e) => return Err(e.into()),
        };
        for line in mounts.lines() {
            let mut f = line.split_ascii_whitespace().skip(2);
            let device = f.next().context("mountinfo missing device")?;
            let root = f.next().context("mountinfo missing root")?;
            ensure!(
                device != "252:0" || !names.contains(root),
                "open file bind in {}",
                pid.display()
            );
        }
        let last = match fs::metadata(&mount_ns) {
            Ok(v) => (v.dev(), v.ino()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e.into()),
        };
        ensure!(
            first == last,
            "mount namespace changed during reference check"
        );
        checked.insert(first);
    }
    Ok(())
}
fn closure(dir: &Path, current: &Path) -> Result<()> {
    let own = unit(UNIT)?;
    ensure!(
        own["MainPID"] == std::process::id().to_string()
            && own["InvocationID"] == env::var("INVOCATION_ID")?,
        "foreign native process"
    );
    let mut accepted = BTreeSet::from([own["FragmentPath"].clone()]);
    for (name, iid, active, sub) in CLOSED {
        let row = unit(name)?;
        for (key, val) in [
            ("Id", name),
            ("InvocationID", iid),
            ("ActiveState", active),
            ("SubState", sub),
            ("MainPID", "0"),
            ("ControlPID", "0"),
            ("Job", ""),
            ("Restart", "no"),
            ("TriggeredBy", ""),
        ] {
            ensure!(
                row.get(key).is_some_and(|x| x == val),
                "historical controller changed {name} {key}"
            );
        }
        accepted.insert(row["FragmentPath"].clone());
    }
    no_source_mounts(dir, current)?;
    for p in [dir, current] {
        let scan = jetstreamer_horizon_observe::process_references::scan(Path::new("/proc"), p)?;
        ensure!(
            scan.references.is_empty(),
            "consumer of {}: {:?}",
            p.display(),
            scan.references
        );
        if p.try_exists()? {
            let staged =
                jetstreamer_horizon_observe::dev_cache_check::sol_staged_path_references(p)?;
            for r in staged["references"]
                .as_array()
                .context("bad staged census")?
            {
                ensure!(
                    accepted.contains(r.as_str().context("bad unit path")?),
                    "foreign staged owner {r}"
                );
            }
        }
    }
    Ok(())
}
fn check_siblings(dir: &Path) -> Result<()> {
    for (n, s) in [
        (
            "intent.json",
            "762b0a3b17a7c96f9a3465ebe2a3bca5f9314ded046e508da22c87abbfd1f959",
        ),
        (
            "completion.json",
            "def71cf63f591407c7770b7374e7d1b7513c2874dce82cb87811b1674d33a597",
        ),
        (
            "index.json",
            "fe38bd4ce018996349c10029720dd7f738340fb0ad30ce6b8577b9651bf87df3",
        ),
    ] {
        pinned(&dir.join(n), s)?;
    }
    Ok(())
}
fn custody(state: &Path) -> Result<Value> {
    let b = Path::new(BASE).join(format!(
        "r2-holding-state-dev-samjohnson-v1/receipts/custody-{CUSTODY}.json"
    ));
    let c: Value = serde_json::from_slice(&pinned(
        &b,
        "15331cf0f3f4d7aaae17a3927139b2aa54526ec4f1adf970f08d639f672596ee",
    )?)?;
    let r = Command::new("/usr/bin/python3")
        .args(["-IB"])
        .arg(state.join("tools/holding_read.py"))
        .output()?;
    ensure!(
        r.status.success(),
        "authenticated metadata check failed: {}",
        String::from_utf8_lossy(&r.stderr)
    );
    let j: Value = serde_json::from_slice(&r.stdout)?;
    ensure!(
        c["remote_sha256_readback"] == true
            && c["local_source_revalidated"] == true
            && c["sha256"] == SHA
            && c["length"] == LENGTH
            && c["manifest"] == j["manifest"]
            && j["manifest_sha256"] == CUSTODY
            && j["blob"]["key"] == c["object_key"]
            && j["blob"]["etag"].as_str().map(|v| v.trim_matches('"')) == c["object_etag"].as_str(),
        "custody differs"
    );
    Ok(j)
}
fn available(dir: &Path) -> Result<u64> {
    let p = CString::new(dir.as_os_str().as_bytes())?;
    let mut stat = std::mem::MaybeUninit::uninit();
    ensure!(
        unsafe { libc::statvfs(p.as_ptr(), stat.as_mut_ptr()) } == 0,
        "statvfs failed"
    );
    let s = unsafe { stat.assume_init() };
    s.f_bavail.checked_mul(s.f_frsize).context("space overflow")
}
fn rename(from: &Path, to: &Path) -> Result<()> {
    let a = CString::new(from.as_os_str().as_bytes())?;
    let b = CString::new(to.as_os_str().as_bytes())?;
    if unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            a.as_ptr(),
            libc::AT_FDCWD,
            b.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}
fn record(path: &Path, v: &Value) -> Result<()> {
    let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .open(&tmp)?;
    serde_json::to_writer(&mut f, v)?;
    f.write_all(b"\n")?;
    f.sync_all()?;
    rename(&tmp, path)?;
    File::open(path.parent().unwrap())?.sync_all()?;
    Ok(())
}
fn read_record(p: &Path) -> Result<Option<Value>> {
    match fs::symlink_metadata(p) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
        Ok(m) => {
            ensure!(
                m.is_file()
                    && m.uid() == 0
                    && m.nlink() == 1
                    && m.mode() & 0o7777 == 0o400
                    && m.len() < 1 << 20,
                "foreign journal"
            );
            Ok(Some(serde_json::from_reader(open_ro(p)?)?))
        }
    }
}
fn exists(p: &Path) -> Result<bool> {
    match fs::symlink_metadata(p) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}
fn main() -> Result<()> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    let [mode, self_sha] = args.as_slice() else {
        bail!("expected check|execute and image SHA-256")
    };
    ensure!(
        matches!(mode.as_str(), "check" | "execute")
            && hash(&File::open("/proc/self/exe")?)? == *self_sha
            && unsafe { libc::geteuid() } == 0,
        "unbound invocation"
    );
    let state = Path::new(STATE);
    let dir = Path::new(SOURCE_DIR);
    let src = dir.join("original-entries.data");
    let q = dir.join(".original-entries.data.retiring");
    let keep = Path::new(KEEPER_DIR).join("original-entries.data");
    let md = fs::symlink_metadata(dir)?;
    ensure!(
        dir.canonicalize()? == dir
            && md.is_dir()
            && (md.dev(), md.ino(), md.uid(), md.mode() & 0o7777) == (64512, 95227315, 0, 0o700),
        "foreign source parent"
    );
    let _transition = lock(
        &Path::new(BASE).join("r2-holding-state-dev-samjohnson-v1/transition.lock"),
        95818311,
        0,
    )?;
    let _local = lock(
        &Path::new(BASE).join("r2-receipts/local-mutation.lock"),
        101135013,
        1001,
    )?;
    pinned(
        &Path::new(KEEPER_DIR).join("deployment-seal-receipt.json"),
        "4c02b6792ea8ad06c2bd38f5c18f35959b9e00b76ae613ec911eeafe42d6c6a8",
    )?;
    check_siblings(dir)?;
    let intent = state.join("intent.json");
    let baseline = state.join("unlink-intent.json");
    let done = state.join("complete.json");
    let op = json!({"source":src,"inode":SOURCE_ID.inode,"keeper":keep,"keeper_inode":KEEPER_ID.inode,"sha256":SHA,"length":LENGTH,"custody_manifest":CUSTODY});
    let started = read_record(&intent)?;
    let pre = read_record(&baseline)?;
    let completed = read_record(&done)?;
    for r in [&started, &pre, &completed].into_iter().flatten() {
        ensure!(r["operation"] == op, "foreign journal operation");
    }
    let had = exists(&src)?;
    let moved = exists(&q)?;
    ensure!(
        !(had && moved)
            && (!moved || started.is_some())
            && (pre.is_none() || started.is_some() && !had)
            && (completed.is_none() || pre.is_some() && !moved)
            && (had || moved || pre.is_some()),
        "conflicting journal/namespace"
    );
    let current = if had { &src } else { &q };
    let signed = custody(state)?;
    closure(dir, current)?;
    // Read leases allow the running replay to keep using the independently sealed input.
    let retained = leased(&keep, KEEPER_ID, false, libc::F_RDLCK)?;
    ensure!(hash(&retained)? == SHA, "keeper content changed");
    KEEPER_ID.check(&fs::symlink_metadata(&keep)?, false)?;
    if completed.is_some() {
        println!("{}", done.display());
        return Ok(());
    }
    let mut held = None;
    if had || moved {
        let f = leased(current, SOURCE_ID, moved, libc::F_WRLCK)?;
        ensure!(hash(&f)? == SHA, "source content changed");
        held = Some(f);
    }
    closure(dir, current)?;
    lease_valid(&retained, libc::F_RDLCK)?;
    let iid = env::var("INVOCATION_ID")?;
    if mode == "check" {
        ensure!(had && started.is_none(), "check requires intact source");
        println!(
            "{}",
            json!({"checked":true,"operation":op,"signed":signed,"invocation":iid,"image_sha256":self_sha,"allocated_bytes":ALLOCATED})
        );
        return Ok(());
    }
    if had {
        let src_fd = held.as_ref().context("no source lease")?;
        lease_valid(src_fd, libc::F_WRLCK)?;
        SOURCE_ID.check(&fs::symlink_metadata(&src)?, false)?;
        if started.is_none() {
            record(
                &intent,
                &json!({"operation":op,"invocation":iid,"signed":signed}),
            )?;
        }
        rename(&src, &q)?;
        File::open(dir)?.sync_all()?;
    }
    let mut before = pre.as_ref().and_then(|r| r["available_before"].as_u64());
    if let Some(f) = held.take() {
        SOURCE_ID.check(&fs::symlink_metadata(&q)?, true)?;
        ensure!(!exists(&src)?, "original reappeared");
        if before.is_none() {
            let b = available(dir)?;
            record(
                &baseline,
                &json!({"operation":op,"available_before":b,"invocation":iid}),
            )?;
            before = Some(b);
        }
        lease_valid(&f, libc::F_WRLCK)?;
        lease_valid(&retained, libc::F_RDLCK)?;
        fs::remove_file(&q)?;
        File::open(dir)?.sync_all()?;
        ensure!(f.metadata()?.nlink() == 0, "different file unlinked");
        drop(f);
    }
    let after = available(dir)?;
    let before = before.context("missing unlink baseline")?;
    ensure!(!exists(&q)? && !exists(&src)?, "source still present");
    KEEPER_ID.check(&fs::symlink_metadata(&keep)?, false)?;
    lease_valid(&retained, libc::F_RDLCK)?;
    check_siblings(dir)?;
    let verified = custody(state)?;
    record(
        &done,
        &json!({"operation":op,"invocation":iid,"image_sha256":self_sha,"available_before":before,"available_after":after,"measured_delta":i128::from(after)-i128::from(before),"allocated_bytes_removed":ALLOCATED,"remote":verified,"remote_mutations":false,"retained_siblings":["intent.json","completion.json","index.json"]}),
    )?;
    println!("{}", done.display());
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_reader_hashes_the_leased_inode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data");
        fs::write(&path, b"abc").unwrap();
        let id = Identity::from(&fs::symlink_metadata(&path).unwrap());
        let f = leased(&path, id, false, libc::F_WRLCK).unwrap();
        assert_eq!(
            hash(&f).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        lease_valid(&f, libc::F_WRLCK).unwrap();
        id.check(&fs::symlink_metadata(&path).unwrap(), false)
            .unwrap();
    }
    #[test]
    fn changed_source_or_open_consumer_does_not_reach_unlink() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("data");
        let q = dir.path().join("replacement");
        fs::write(&p, b"same bytes").unwrap();
        fs::write(&q, b"same bytes").unwrap();
        let id = Identity::from(&fs::symlink_metadata(&p).unwrap());
        assert!(leased(&q, id, false, libc::F_WRLCK).is_err());
        let reader = File::open(&p).unwrap();
        assert!(leased(&p, id, false, libc::F_WRLCK).is_err());
        assert_eq!(fs::read(&p).unwrap(), b"same bytes");
        drop(reader);
        let file = leased(&p, id, false, libc::F_WRLCK).unwrap();
        assert!(rename(&p, &q).is_err());
        assert!(p.exists());
        drop(file);
    }
}
