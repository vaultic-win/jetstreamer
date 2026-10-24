//! Append one previously qualified wrapper; never replace a sealed member.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    ffi::CString,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
};

const TARGET: &str = "/usr/local/lib/jetstreamer/horizon-cohort191-delivery-tools-20261023-v1";
const SOURCE: &str = "/usr/local/lib/jetstreamer/horizon-cohort191-build-artifacts-20261023-v1/jetstreamer-horizon-verify-pair";
const STATE: &str = "/var/lib/jetstreamer/horizon-cohort191-wrapper-augmentation-20261024-v1";
const WRAPPER: &str = "jetstreamer-horizon-verify-pair";
const STAGE: &str = ".jetstreamer-horizon-verify-pair.partial";
const SHA: &str = "b89641f4bfe5cdd141652cd32905233937439725ca523ec18b66a411460e436a";
const R2_SHA: &str = "0f0f7c9475b69b3371098dfb0b7702a772de989189d0974359c2569020caab1f";
const NAMES: [&str; 4] = [
    "jetstreamer-r2",
    "qualification-binding.json",
    "SHA256SUMS",
    "deployment-seal-receipt.json",
];

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Stamp {
    device: u64,
    inode: u64,
    length: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    links: u64,
    mtime: i64,
    mtime_ns: i64,
    ctime: i64,
    ctime_ns: i64,
    sha256: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    target_directory: PathBuf,
    wrapper_source: PathBuf,
    state_directory: PathBuf,
    original_members: BTreeMap<String, Stamp>,
    wrapper_sha256: String,
    existing_members_may_change: bool,
    r2_mutations_authorized: bool,
}
fn meta(m: &fs::Metadata, sha256: String) -> Stamp {
    Stamp {
        device: m.dev(),
        inode: m.ino(),
        length: m.len(),
        mode: m.mode() & 0o7777,
        uid: m.uid(),
        gid: m.gid(),
        links: m.nlink(),
        mtime: m.mtime(),
        mtime_ns: m.mtime_nsec(),
        ctime: m.ctime(),
        ctime_ns: m.ctime_nsec(),
        sha256,
    }
}
fn stamp(p: &Path, owner: u32, executable: bool) -> Result<Stamp> {
    let before = fs::symlink_metadata(p)?;
    ensure!(
        p.canonicalize()? == p
            && before.is_file()
            && before.uid() == owner
            && before.nlink() == 1
            && before.mode() & 0o222 == 0
            && (!executable || before.mode() & 0o111 != 0)
            && before.len() <= 512 << 20,
        "unsafe sealed file {}",
        p.display()
    );
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(p)?;
    ensure!(
        meta(&before, String::new()) == meta(&f.metadata()?, String::new()),
        "file replaced on open"
    );
    let mut h = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    ensure!(
        meta(&before, String::new()) == meta(&f.metadata()?, String::new())
            && meta(&before, String::new()) == meta(&fs::symlink_metadata(p)?, String::new()),
        "sealed file changed"
    );
    Ok(meta(&before, format!("{:x}", h.finalize())))
}
fn directory(p: &Path, owner: u32, mode: u32) -> Result<()> {
    let m = fs::symlink_metadata(p)?;
    ensure!(
        p.canonicalize()? == p && m.is_dir() && m.uid() == owner && m.mode() & 0o7777 == mode,
        "unsafe directory"
    );
    Ok(())
}
fn originals(p: &Plan, owner: u32) -> Result<()> {
    directory(&p.target_directory, owner, 0o555)?;
    ensure!(
        p.original_members.len() == 4 && NAMES.iter().all(|n| p.original_members.contains_key(*n)),
        "original member selection differs"
    );
    for name in NAMES {
        ensure!(
            stamp(
                &p.target_directory.join(name),
                owner,
                name == "jetstreamer-r2"
            )? == p.original_members[name],
            "original sealed member changed: {name}"
        );
    }
    for e in fs::read_dir(&p.target_directory)? {
        let n = e?.file_name();
        let n = n.to_str().context("nonUTF8 package entry")?;
        ensure!(
            NAMES.contains(&n) || n == WRAPPER || n == STAGE,
            "unexpected package entry"
        );
    }
    Ok(())
}
fn sync_dir(p: &Path) -> Result<()> {
    File::open(p)?.sync_all()?;
    Ok(())
}
fn record(p: &Path, v: &serde_json::Value) -> Result<()> {
    if p.try_exists()? {
        ensure!(
            serde_json::from_slice::<serde_json::Value>(&fs::read(p)?)? == *v,
            "existing frontier differs"
        );
        return Ok(());
    }
    let mut bytes = serde_json::to_vec_pretty(v)?;
    bytes.push(b'\n');
    let stage = p.with_extension("json.partial");
    let mut f = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&stage)?;
    let m = f.metadata()?;
    // SAFETY: geteuid has no arguments or side effects.
    ensure!(
        m.is_file()
            && m.uid() == unsafe { libc::geteuid() }
            && m.nlink() == 1
            && m.mode() & 0o7777 == 0o600
            && m.len() <= bytes.len() as u64,
        "unsafe receipt stage"
    );
    let mut prefix = Vec::new();
    f.read_to_end(&mut prefix)?;
    ensure!(
        bytes.starts_with(&prefix),
        "preserve conflicting receipt stage"
    );
    f.write_all(&bytes[prefix.len()..])?;
    f.sync_all()?;
    no_replace(&stage, p)?;
    sync_dir(p.parent().unwrap())
}
fn lock(p: &Path, owner: u32) -> Result<File> {
    use std::os::fd::AsRawFd;
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(p)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file() && m.uid() == owner && m.nlink() == 1 && m.mode() & 0o777 == 0o600,
        "unsafe mutation lock"
    );
    // SAFETY: the live descriptor is kept for the entire transition.
    ensure!(
        unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "augmentation occupied"
    );
    Ok(f)
}
fn prepare_stage(source: &Path, stage: &Path, owner: u32, digest: &str) -> Result<()> {
    let source_stamp = stamp(source, owner, true)?;
    let mut src = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(source)?;
    let mut dst = if stage.try_exists()? {
        let m = fs::symlink_metadata(stage)?;
        ensure!(
            m.is_file()
                && m.uid() == owner
                && m.nlink() == 1
                && matches!(m.mode() & 0o7777, 0o600 | 0o555)
                && m.len() <= source_stamp.length,
            "unsafe existing stage"
        );
        if m.mode() & 0o7777 == 0o555 {
            ensure!(
                stamp(stage, owner, true)?.sha256 == digest,
                "readonly stage differs"
            );
            return Ok(());
        }
        OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(stage)?
    } else {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(stage)?
    };
    let prefix = dst.metadata()?.len();
    let mut left = prefix;
    let mut a = [0u8; 65536];
    let mut b = [0u8; 65536];
    while left > 0 {
        let n = usize::try_from(left.min(a.len() as u64))?;
        src.read_exact(&mut a[..n])?;
        dst.read_exact(&mut b[..n])?;
        ensure!(a[..n] == b[..n], "preserve conflicting partial stage");
        left -= n as u64;
    }
    ensure!(
        dst.metadata()?.len() == prefix,
        "stage changed during prefix check"
    );
    dst.seek(SeekFrom::End(0))?;
    let copied = std::io::copy(
        &mut Read::by_ref(&mut src).take(source_stamp.length - prefix),
        &mut dst,
    )?;
    ensure!(
        copied == source_stamp.length - prefix && dst.metadata()?.len() == source_stamp.length,
        "short or growing copy"
    );
    dst.sync_all()?;
    dst.set_permissions(fs::Permissions::from_mode(0o555))?;
    dst.sync_all()?;
    sync_dir(stage.parent().unwrap())?;
    ensure!(
        stamp(source, owner, true)? == source_stamp && stamp(stage, owner, true)?.sha256 == digest,
        "wrapper copy changed"
    );
    Ok(())
}
fn no_replace(from: &Path, to: &Path) -> Result<()> {
    let a = CString::new(from.as_os_str().as_bytes())?;
    let b = CString::new(to.as_os_str().as_bytes())?;
    // SAFETY: both C strings are live; the fixed NOREPLACE operation never replaces a target.
    ensure!(
        unsafe {
            libc::renameat2(
                libc::AT_FDCWD,
                a.as_ptr(),
                libc::AT_FDCWD,
                b.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        } == 0,
        "no-clobber publication failed: {}",
        std::io::Error::last_os_error()
    );
    Ok(())
}
fn execute(p: &Plan, plan_sha: &str, owner: u32, check_only: bool) -> Result<()> {
    ensure!(
        p.schema == "jetstreamer-exact191-wrapper-augmentation-plan-v1"
            && !p.existing_members_may_change
            && !p.r2_mutations_authorized,
        "augmentation scope differs"
    );
    originals(p, owner)?;
    directory(&p.state_directory, owner, 0o700)?;
    let source = stamp(&p.wrapper_source, owner, true)?;
    ensure!(
        source.sha256 == p.wrapper_sha256,
        "wrapper source digest differs"
    );
    ensure!(
        fs::metadata(&p.state_directory)?.dev() == fs::metadata(&p.target_directory)?.dev(),
        "staging must use the same filesystem"
    );
    let _lock = lock(&p.state_directory.join("lock"), owner)?;
    let intent = serde_json::json!({"schema":"jetstreamer-exact191-wrapper-augmentation-intent-v1","plan_sha256":plan_sha,"original_members":p.original_members,"source":source,"target":p.target_directory.join(WRAPPER),"existing_members_may_change":false,"r2_mutations":false});
    let ip = p.state_directory.join("intent.json");
    let cp = p.state_directory.join("completion.json");
    let target = p.target_directory.join(WRAPPER);
    if target.try_exists()? {
        ensure!(
            !p.target_directory.join(STAGE).try_exists()?,
            "preserve unexplained simultaneous wrapper stage"
        );
        ensure!(
            ip.try_exists()?
                && serde_json::from_slice::<serde_json::Value>(&fs::read(&ip)?)? == intent,
            "unexplained existing wrapper"
        );
        ensure!(
            stamp(&target, owner, true)?.sha256 == p.wrapper_sha256,
            "existing wrapper conflicts"
        );
    } else {
        ensure!(!cp.try_exists()?, "completed wrapper disappeared");
        if check_only {
            return Ok(());
        }
        record(&ip, &intent)?;
        // Keep rename within one sandbox bind mount. Equal st_dev alone does not
        // permit rename between separately mounted ReadWritePaths.
        let stage = p.target_directory.join(STAGE);
        prepare_stage(&p.wrapper_source, &stage, owner, &p.wrapper_sha256)?;
        originals(p, owner)?;
        no_replace(&stage, &target)?;
        sync_dir(&p.target_directory)?;
        sync_dir(&p.state_directory)?;
    }
    originals(p, owner)?;
    let new = stamp(&target, owner, true)?;
    ensure!(new.sha256 == p.wrapper_sha256, "published wrapper differs");
    if check_only {
        return Ok(());
    }
    let completion = serde_json::json!({"schema":"jetstreamer-exact191-wrapper-augmentation-completion-v1","intent":intent,"new_member":new,"original_members_unchanged":true,"original_seal_and_sha256sums_unchanged":true,"r2_mutations":false,"archive_mutations":false,"replay_launch_authorized":false});
    record(&cp, &completion)?;
    println!("{}", cp.display());
    Ok(())
}
fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let capture = args.len() == 4 && args[1] == "--capture-plan" && args[2] == "--self-sha256";
    ensure!(
        capture
            || ((args.len() == 6 || args.len() == 7 && args[6] == "--check-only")
                && args[2] == "--plan-sha256"
                && args[4] == "--self-sha256"),
        "closed augmentation argv required"
    );
    // SAFETY: geteuid has no arguments or side effects.
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "root augmentation required"
    );
    let own = fs::read_link("/proc/self/exe")?;
    ensure!(
        stamp(&own, 0, true)?.sha256 == args[if capture { 3 } else { 5 }],
        "augmentation executable differs"
    );
    if capture {
        directory(Path::new(STATE), 0, 0o700)?;
        directory(Path::new(TARGET), 0, 0o555)?;
        let _lock = lock(&Path::new(STATE).join("lock"), 0)?;
        ensure!(
            stamp(Path::new(SOURCE), 0, true)?.sha256 == SHA,
            "foreign wrapper source"
        );
        let mut original_members = BTreeMap::new();
        for name in NAMES {
            original_members.insert(
                name.into(),
                stamp(&Path::new(TARGET).join(name), 0, name == "jetstreamer-r2")?,
            );
        }
        ensure!(
            original_members["jetstreamer-r2"].sha256 == R2_SHA,
            "foreign original publisher"
        );
        let p = Plan {
            schema: "jetstreamer-exact191-wrapper-augmentation-plan-v1".into(),
            target_directory: TARGET.into(),
            wrapper_source: SOURCE.into(),
            state_directory: STATE.into(),
            original_members,
            wrapper_sha256: SHA.into(),
            existing_members_may_change: false,
            r2_mutations_authorized: false,
        };
        originals(&p, 0)?;
        record(
            &Path::new(STATE).join("plan.json"),
            &serde_json::to_value(&p)?,
        )?;
        println!("{STATE}/plan.json");
        return Ok(());
    }
    let plan = Path::new(&args[1]);
    ensure!(
        stamp(plan, 0, false)?.sha256 == args[3],
        "augmentation plan differs"
    );
    let p: Plan = serde_json::from_slice(&fs::read(plan)?)?;
    ensure!(
        p.target_directory == Path::new(TARGET)
            && p.wrapper_source == Path::new(SOURCE)
            && p.state_directory == Path::new(STATE)
            && p.wrapper_sha256 == SHA
            && p.original_members
                .get("jetstreamer-r2")
                .is_some_and(|m| m.sha256 == R2_SHA),
        "foreign augmentation target/source"
    );
    execute(&p, &args[3], 0, args.len() == 7)
}
fn main() {
    if let Err(e) = run() {
        eprintln!("wrapper augmentation failed closed: {e:#}");
        std::process::exit(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (tempfile::TempDir, Plan, u32) {
        let d = tempfile::tempdir().unwrap();
        let owner = unsafe { libc::geteuid() };
        let target = d.path().join("package");
        let state = d.path().join("state");
        fs::create_dir(&target).unwrap();
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        for n in NAMES {
            fs::write(target.join(n), n).unwrap();
            fs::set_permissions(
                target.join(n),
                fs::Permissions::from_mode(if n == "jetstreamer-r2" { 0o555 } else { 0o444 }),
            )
            .unwrap();
        }
        let source = d.path().join("source");
        fs::write(&source, b"qualified-wrapper").unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o555)).unwrap();
        let original_members = NAMES
            .into_iter()
            .map(|n| {
                (
                    n.into(),
                    stamp(&target.join(n), owner, n == "jetstreamer-r2").unwrap(),
                )
            })
            .collect();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o555)).unwrap();
        let sha = stamp(&source, owner, true).unwrap().sha256;
        (
            d,
            Plan {
                schema: "jetstreamer-exact191-wrapper-augmentation-plan-v1".into(),
                target_directory: target,
                wrapper_source: source,
                state_directory: state,
                original_members,
                wrapper_sha256: sha,
                existing_members_may_change: false,
                r2_mutations_authorized: false,
            },
            owner,
        )
    }
    #[test]
    fn preflight_is_readonly_and_unknown_or_changed_members_fail() {
        let (_d, p, o) = fixture();
        execute(&p, "a", o, true).unwrap();
        assert!(!p.state_directory.join("intent.json").exists());
        fs::set_permissions(
            p.target_directory.join("SHA256SUMS"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(execute(&p, "a", o, true).is_err());
    }
    #[test]
    fn unexplained_target_and_symlink_source_fail() {
        let (_d, mut p, o) = fixture();
        let alias = p.state_directory.join("alias");
        std::os::unix::fs::symlink(&p.wrapper_source, &alias).unwrap();
        p.wrapper_source = alias;
        assert!(execute(&p, "a", o, true).is_err());
    }
    #[test]
    fn partial_copy_recovery_preserves_prefix_and_rejects_conflicts() {
        let (_d, p, o) = fixture();
        let stage = p.state_directory.join("wrapper.partial");
        fs::write(&stage, b"qualified").unwrap();
        fs::set_permissions(&stage, fs::Permissions::from_mode(0o600)).unwrap();
        prepare_stage(&p.wrapper_source, &stage, o, &p.wrapper_sha256).unwrap();
        assert_eq!(fs::read(&stage).unwrap(), b"qualified-wrapper");
        let bad = p.state_directory.join("bad.partial");
        fs::write(&bad, b"wrong").unwrap();
        fs::set_permissions(&bad, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(prepare_stage(&p.wrapper_source, &bad, o, &p.wrapper_sha256).is_err());
        assert_eq!(fs::read(bad).unwrap(), b"wrong");
    }
    #[test]
    fn receipt_publication_recovers_partial_and_preserves_conflicts() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("intent.json");
        let stage = p.with_extension("json.partial");
        let v = serde_json::json!({"binding":"original"});
        let bytes = serde_json::to_vec_pretty(&v).unwrap();
        fs::write(&stage, &bytes[..7]).unwrap();
        fs::set_permissions(&stage, fs::Permissions::from_mode(0o600)).unwrap();
        record(&p, &v).unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&fs::read(&p).unwrap()).unwrap(),
            v
        );
        record(&p, &v).unwrap();
        assert!(record(&p, &serde_json::json!({"binding":"different"})).is_err());
        let other = d.path().join("other.json");
        let bad = other.with_extension("json.partial");
        fs::write(&bad, b"conflict").unwrap();
        fs::set_permissions(&bad, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(record(&other, &v).is_err());
        assert_eq!(fs::read(&bad).unwrap(), b"conflict");
        assert!(!other.exists());
    }
    #[test]
    fn no_replace_preserves_both_files() {
        let d = tempfile::tempdir().unwrap();
        let a = d.path().join("a");
        let b = d.path().join("b");
        fs::write(&a, b"source").unwrap();
        fs::write(&b, b"existing").unwrap();
        assert!(no_replace(&a, &b).is_err());
        assert_eq!(fs::read(a).unwrap(), b"source");
        assert_eq!(fs::read(b).unwrap(), b"existing");
    }
    #[test]
    #[ignore = "root CAP_DAC_OVERRIDE is required to append to a sealed0555 directory"]
    fn append_reentry_and_publication_frontier_recovery() {
        let (_d, p, o) = fixture();
        assert_eq!(o, 0);
        let target = p.target_directory.join(WRAPPER);
        fs::copy(&p.wrapper_source, &target).unwrap();
        assert!(execute(&p, "a", o, false).is_err());
        assert!(!p.state_directory.join("intent.json").exists());
        fs::remove_file(&target).unwrap();
        execute(&p, "a", o, false).unwrap();
        let old = p.original_members.clone();
        execute(&p, "a", o, false).unwrap();
        assert_eq!(p.original_members, old);
        fs::remove_file(p.state_directory.join("completion.json")).unwrap();
        execute(&p, "a", o, false).unwrap();
        assert!(p.state_directory.join("completion.json").exists());
        assert!(execute(&p, "different", o, false).is_err());
    }
}
