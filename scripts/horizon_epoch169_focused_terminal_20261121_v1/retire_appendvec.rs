//! Retire only the four original stopped G4 account shards. The published archive,
//! private partial, snapshot, log and all replay bookings are outside this operation.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    ffi::CString,
    fs::{self, File, OpenOptions},
    io::{self, BufRead, BufReader, Read, Write},
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        io::AsRawFd,
    },
    path::{Path, PathBuf},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
};
use tempfile::NamedTempFile;

#[path = "../horizon_retry6_166_scratch_retire_20261119_v1/src/process_references.rs"]
mod process_references;
#[path = "../horizon_retry6_166_scratch_retire_20261119_v1/src/stopped_tree.rs"]
mod stopped_tree;

const PRIVATE: &str = "/home/sol/.jetstreamer-private";
const SOURCE: &str = "/home/sol/.jetstreamer-private/epoch169-focused-diagnostic-20261117-v1/v158/scratch/.historical-runtime/jetstreamer-historical-parent-6hfz7E/jetstreamer-historical-v1.5.8-eHT65K/accounts-state";
const PACKAGE: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch169-g4-appendvec-20261123-v1/tools-v3";
const DEVICE: u64 = 64512;
const ROOT_INODE: u64 = 114770421;
const BYTES: u64 = 50285883392;
const LEDGER_MAX: u64 = 32 << 20;
const SHARDS: [(u64, u64, u64); 4] = [
    (114770422, 99149, 12769189888),
    (114770423, 99789, 12367679488),
    (114770424, 99109, 12278554624),
    (114770425, 99206, 12870455296),
];
const LEASE: &str = "/home/sol/.jetstreamer-private/epoch169-focused-diagnostic-20261117-v1/attempt-g4/private/destination-3fe3d8794185d5eb0c7ff8c5bf4d9593ad5dcb3b5a6d72b0127e59f799c5d78d/locks/epoch-169.lock";

fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn blob(p: &Path, limit: u64) -> Result<Vec<u8>> {
    let f = File::open(p)?;
    let m = f.metadata()?;
    ensure!(
        p.canonicalize()? == p
            && m.is_file()
            && m.uid() == 0
            && m.gid() == 0
            && m.nlink() == 1
            && m.mode() & 0o222 == 0
            && m.len() <= limit,
        "foreign receipt {}",
        p.display()
    );
    let mut buf = Vec::new();
    f.take(limit + 1).read_to_end(&mut buf)?;
    let end = fs::symlink_metadata(p)?;
    ensure!(
        end.dev() == m.dev()
            && end.ino() == m.ino()
            && end.ctime_nsec() == m.ctime_nsec()
            && end.ctime() == m.ctime()
            && buf.len() as u64 == m.len(),
        "receipt changed"
    );
    Ok(buf)
}
fn save(p: &Path, v: &Value) -> Result<()> {
    let b = serde_json::to_vec(v)?;
    if p.try_exists()? {
        ensure!(blob(p, 2 << 20)? == b, "different {}", p.display());
        return Ok(());
    }
    let mut t = NamedTempFile::new_in(p.parent().context("receipt parent")?)?;
    t.write_all(&b)?;
    t.as_file()
        .set_permissions(fs::Permissions::from_mode(0o400))?;
    t.as_file().sync_all()?;
    t.persist_noclobber(p)?;
    File::open(p.parent().unwrap())?.sync_all()?;
    Ok(())
}
fn lock(p: &Path, ino: u64, shared: bool) -> Result<File> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(p)?;
    let m = f.metadata()?;
    ensure!(
        p.canonicalize()? == p
            && m.dev() == DEVICE
            && m.ino() == ino
            && m.uid() == 1001
            && m.gid() == 1003
            && m.is_file()
            && m.nlink() == 1
            && m.mode() & 0o7777 == 0o600,
        "different campaign lock"
    );
    let mode = if shared { libc::LOCK_SH } else { libc::LOCK_EX };
    ensure!(
        unsafe { libc::flock(f.as_raw_fd(), mode | libc::LOCK_NB) } == 0,
        "campaign lock occupied"
    );
    Ok(f)
}
fn allocated(root: &Path, ledger: &stopped_tree::Ledger) -> Result<(u64, Vec<(u64, u64, u64)>)> {
    let mut shards = BTreeMap::<String, (u64, u64, u64)>::new();
    for (path, ent) in ledger {
        let v = serde_json::to_value(ent)?;
        if path.is_empty() {
            continue;
        }
        if v["directory"] == true {
            ensure!(
                matches!(path.as_str(), "0" | "1" | "2" | "3"),
                "unexpected accounts-state directory"
            );
            let m = fs::symlink_metadata(root.join(path))?;
            ensure!(
                v["inode"] == m.ino() && m.is_dir() && m.mode() & 0o7777 == 0o700,
                "wrong shard identity"
            );
            ensure!(
                shards
                    .insert(path.clone(), (m.ino(), 0, m.blocks() * 512))
                    .is_none(),
                "duplicate directory"
            );
        } else {
            let (dir, file) = path.split_once('/').context("file outside shard")?;
            let (slot, id) = file
                .split_once('.')
                .context("unexpected AppendVec filename")?;
            ensure!(
                [slot, id].iter().all(|n| !n.is_empty()
                    && n.len() <= 20
                    && n.bytes().all(|c| c.is_ascii_digit()))
                    && matches!(v["mode"].as_u64().context("mode")?, 0o100600 | 0o100644),
                "unexpected AppendVec entry {path}"
            );
            let row = shards.get_mut(dir).context("unknown shard")?;
            row.1 += 1;
            row.2 += v["blocks"].as_u64().context("blocks")? * 512;
        }
    }
    let rows: Vec<_> = shards.into_values().collect();
    Ok((
        fs::symlink_metadata(root)?.blocks() * 512 + rows.iter().map(|r| r.2).sum::<u64>(),
        rows,
    ))
}
fn original_shards(fd: &File, source: &Path) -> Result<stopped_tree::Ledger> {
    let tree = stopped_tree::capture(fd, DEVICE, 1001, 1003)?;
    let (bytes, shards) = allocated(source, &tree)?;
    ensure!(
        bytes == BYTES && shards == SHARDS,
        "actual scope or allocation changed"
    );
    Ok(tree)
}
struct Limited<W> {
    inner: W,
    left: u64,
}
impl<W: Write> Write for Limited<W> {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        if b.len() as u64 > self.left {
            return Err(io::Error::other("compressed ledger exceeds booked maximum"));
        }
        let n = self.inner.write(b)?;
        self.left -= n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
fn ledger_file(p: &Path, tree: &stopped_tree::Ledger) -> Result<String> {
    if p.try_exists()? {
        let b = blob(p, LEDGER_MAX)?;
        ensure!(unpack(&b)? == *tree, "different previously captured ledger");
        return Ok(sha(&b));
    }
    let mut t = NamedTempFile::new_in(p.parent().context("ledger parent")?)?;
    let mut z = zstd::stream::write::Encoder::new(
        Limited {
            inner: t.as_file_mut(),
            left: LEDGER_MAX,
        },
        3,
    )?;
    serde_json::to_writer(&mut z, tree)?;
    z.finish()?.flush()?;
    t.as_file()
        .set_permissions(fs::Permissions::from_mode(0o400))?;
    t.as_file().sync_all()?;
    t.persist_noclobber(p)?;
    File::open(p.parent().unwrap())?.sync_all()?;
    Ok(sha(&blob(p, LEDGER_MAX)?))
}
fn unpack(bytes: &[u8]) -> Result<stopped_tree::Ledger> {
    Ok(serde_json::from_reader(
        zstd::stream::read::Decoder::new(bytes)?.take(192 << 20),
    )?)
}
fn norename(from: &Path, to: &Path) -> Result<()> {
    let a = CString::new(from.as_os_str().as_bytes())?;
    let b = CString::new(to.as_os_str().as_bytes())?;
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
        "atomic handback failed: {}",
        io::Error::last_os_error()
    );
    File::open(from.parent().unwrap())?.sync_all()?;
    File::open(to.parent().unwrap())?.sync_all()?;
    Ok(())
}
// The old root and sibling custody need one mount for RENAME_NOREPLACE. Landlock
// limits writes inside that shared mount to these two directories before any input is opened.
fn restrict_writes(first: &Path, second: &Path) -> Result<()> {
    use std::os::fd::FromRawFd;
    #[repr(C)]
    struct Rule {
        access: u64,
        parent: i32,
    }
    let handled: u64 = (1 << 1) | ((0x7ffu64) << 4);
    let permitted: u64 =
        (1 << 1) | (1 << 4) | (1 << 5) | (1 << 7) | (1 << 8) | (1 << 13) | (1 << 14);
    ensure!(
        unsafe { libc::syscall(libc::SYS_landlock_create_ruleset, 0, 0, 1) } >= 3,
        "Landlock ABI with REFER and TRUNCATE required"
    );
    let raw = unsafe { libc::syscall(libc::SYS_landlock_create_ruleset, &handled, 8, 0) };
    ensure!(
        raw >= 0,
        "create Landlock ruleset: {}",
        io::Error::last_os_error()
    );
    let set = unsafe { File::from_raw_fd(raw as i32) };
    for path in [first, second] {
        let fd = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(path)?;
        let rule = Rule {
            access: permitted,
            parent: fd.as_raw_fd(),
        };
        ensure!(
            unsafe { libc::syscall(libc::SYS_landlock_add_rule, set.as_raw_fd(), 1, &rule, 0) }
                == 0,
            "add scoped write path: {}",
            io::Error::last_os_error()
        );
    }
    ensure!(
        unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } == 0
            && unsafe { libc::syscall(libc::SYS_landlock_restrict_self, set.as_raw_fd(), 0) } == 0,
        "confine cleanup writes: {}",
        io::Error::last_os_error()
    );
    Ok(())
}

struct Observer {
    child: Child,
    commands: ChildStdin,
    results: BufReader<ChildStdout>,
}
impl Observer {
    fn start(mode: &str, fleet: &Path) -> Result<Self> {
        let mut child = Command::new("/usr/bin/python3")
            .arg("-IB")
            .arg(Path::new(PACKAGE).join("gate.py"))
            .arg("observe")
            .arg(mode)
            .arg(fleet)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;
        let commands = child.stdin.take().context("observer command pipe")?;
        let results = BufReader::new(child.stdout.take().context("observer result pipe")?);
        Ok(Self {
            child,
            commands,
            results,
        })
    }
    fn check(&mut self, action: &str) -> Result<Value> {
        writeln!(&mut self.commands, "{action}")?;
        self.commands.flush()?;
        let mut out = String::new();
        ensure!(
            (&mut self.results).take(1 << 20).read_line(&mut out)? > 0,
            "read-only observer exited before {action}"
        );
        let row: Value = serde_json::from_str(&out)?;
        ensure!(
            row["action"] == action && row["ok"] == true,
            "observer {action} failed: {}",
            row["error"]
        );
        Ok(row["result"].clone())
    }
}
impl Drop for Observer {
    fn drop(&mut self) {
        let _ = writeln!(&mut self.commands, "exit");
        let _ = self.commands.flush();
        let _ = self.child.wait();
    }
}
fn scanner(which: &str) -> Result<()> {
    ensure!(
        std::env::current_exe()? == Path::new(PACKAGE).join("retire169")
            && unsafe { libc::geteuid() } == 0
            && unsafe { libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0) } == 2,
        "native read-only observer image required"
    );
    let target = match which {
        "source-readers" => PathBuf::from(SOURCE),
        "held-readers" => {
            Path::new(PRIVATE).join("epoch169-g4-appendvec-custody-20261123-v1/accounts-state")
        }
        _ => anyhow::bail!("unknown read-only reference scope"),
    };
    let result = process_references::scan(Path::new("/proc"), &target)?;
    ensure!(
        result.inspected_processes > 0 && result.references.is_empty(),
        "active G4 scratch readers: {:?}",
        result.references
    );
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}
fn run() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() == 3 && args[1] == "scan" {
        return scanner(&args[2]);
    }
    ensure!(
        args.len() == 3
            && matches!(args[1].as_str(), "check" | "execute" | "qualify")
            && unsafe { libc::geteuid() } == 0,
        "use guarded check or execute FLEET"
    );
    let mode = &args[1];
    let fleet = Path::new(&args[2]);
    ensure!(
        std::env::current_exe()? == Path::new(PACKAGE).join("retire169"),
        "use installed image"
    );
    let dir = Path::new(PRIVATE).join("epoch169-g4-appendvec-custody-20261123-v1");
    let md = fs::symlink_metadata(&dir)?;
    ensure!(
        dir.canonicalize()? == dir
            && md.dev() == DEVICE
            && md.uid() == 0
            && md.gid() == 0
            && md.is_dir()
            && md.mode() & 0o7777 == 0o700,
        "untrusted handback root"
    );
    let src = Path::new(SOURCE);
    let held = dir.join("accounts-state");
    // The read-only monitor starts outside the writer's Landlock domain. An
    // inherited Landlock domain cannot inspect arbitrary host proc entries.
    let mut observer = Observer::start(mode, fleet)?;
    restrict_writes(src.parent().context("source parent")?, &dir)?;
    if mode == "qualify" {
        let price = observer.check("initial")?;
        let source = observer.check("source-readers")?;
        let held_readers = observer.check("held-readers")?;
        ensure!(!held.try_exists()?, "source already entered handback");
        let fd = stopped_tree::open_root(src, DEVICE, ROOT_INODE)?;
        let tree = original_shards(&fd, src)?;
        println!(
            "{}",
            json!({"scope":"normal installed read-only qualification","price":price,"original_scope":source,
                  "quarantine_scope":held_readers,"production_cleanup_started":false,
                  "source_inode":ROOT_INODE,"source_device":DEVICE,"entries_including_root":tree.len(),
                  "shards":SHARDS,"allocated_bytes":BYTES,"source_bytes_read":0,"r2_mutations":false})
        );
        return Ok(());
    }
    let _mutation = lock(
        &Path::new(PRIVATE).join("r2-receipts/local-mutation.lock"),
        101135013,
        false,
    )?;
    // The producer requires exclusive custody. Shared observation locks also allow the
    // normal native pricing service to authenticate the old producer while this job runs.
    let _epoch = lock(Path::new(LEASE), 114688013, true)?;
    let ledger = dir.join("checked-ledger.json.zst");
    let checked = dir.join("check.json");
    let intent = dir.join("intent.json");
    let cleared = dir.join("contents-cleared.json");
    let completion = dir.join("completion.json");
    let first = observer.check("initial")?;
    if mode == "check" {
        ensure!(
            !held.try_exists()? && !intent.try_exists()? && !completion.try_exists()?,
            "retirement already started"
        );
        observer.check("source-readers")?;
        let fd = stopped_tree::open_root(src, DEVICE, ROOT_INODE)?;
        let tree = original_shards(&fd, src)?;
        stopped_tree::validate_remaining(
            &tree,
            &stopped_tree::capture(&fd, DEVICE, 1001, 1003)?,
            false,
        )?;
        let hash = ledger_file(&ledger, &tree)?;
        let evidence = json!({"device":DEVICE,"root_inode":ROOT_INODE,"source":src,"quarantine":held,
            "ledger_sha256":hash,"size_bytes":BYTES,"shards":SHARDS,"entries_including_root":tree.len(),
            "semantic_owner":first["terminal"],"preserved_log":first["log"],"preserved_partial":first["partial"],
            "reclaimed_bytes":0,"released_reservation_bytes":0});
        save(&checked, &evidence)?;
        println!("{}", serde_json::to_string(&evidence)?);
        return Ok(());
    }
    let cbytes = blob(&checked, 2 << 20)?;
    let c: Value = serde_json::from_slice(&cbytes)?;
    let packed = blob(&ledger, LEDGER_MAX)?;
    ensure!(
        c["source"] == json!(src)
            && c["quarantine"] == json!(held)
            && c["device"] == DEVICE
            && c["root_inode"] == ROOT_INODE
            && c["size_bytes"] == BYTES
            && c["ledger_sha256"] == sha(&packed)
            && c["shards"] == json!(SHARDS)
            && c["semantic_owner"] == first["terminal"]
            && c["preserved_log"] == first["log"]
            && c["preserved_partial"] == first["partial"],
        "different scope, owner, or check"
    );
    let original = unpack(&packed)?;
    drop(packed);
    let binding = json!({"check_sha256":sha(&cbytes),"source":src,"quarantine":held,"shards":SHARDS,"root_inode":ROOT_INODE,"bytes":BYTES});
    if completion.try_exists()? {
        let done: Value = serde_json::from_slice(&blob(&completion, 2 << 20)?)?;
        ensure!(
            done["binding"] == binding
                && !src.try_exists()?
                && !held.try_exists()?
                && done["releases_no_booking"] == true,
            "changed completion"
        );
        observer.check("settled")?;
        println!("{}", done);
        return Ok(());
    }
    ensure!(
        src.try_exists()? || intent.try_exists()?,
        "source absent without original intent"
    );
    if src.try_exists()? {
        ensure!(
            !held.try_exists()? && !cleared.try_exists()?,
            "two owners or inconsistent cleanup"
        );
        observer.check("source-readers")?;
        let fd = stopped_tree::open_root(src, DEVICE, ROOT_INODE)?;
        stopped_tree::validate_remaining(
            &original,
            &stopped_tree::capture(&fd, DEVICE, 1001, 1003)?,
            false,
        )?;
        let _ = observer.check("before-rename")?;
        save(&intent, &binding)?;
        norename(src, &held)?;
        ensure!(
            fs::symlink_metadata(&held)?.ino() == fd.metadata()?.ino() && !src.try_exists()?,
            "quarantine changed"
        );
    }
    ensure!(
        serde_json::from_slice::<Value>(&blob(&intent, 2 << 20)?)? == binding
            && !src.try_exists()?,
        "different retirement intent"
    );
    if held.try_exists()? {
        observer.check("held-readers")?;
        observer.check("source-readers")?;
        let fd = stopped_tree::open_root(&held, DEVICE, ROOT_INODE)?;
        observer.check("quarantined")?;
        stopped_tree::remove_contents(&fd, &original, DEVICE, 1001, 1003)?;
        save(&cleared, &binding)?;
        ensure!(
            fs::symlink_metadata(&held)?.ino() == fd.metadata()?.ino(),
            "quarantine replaced"
        );
        fs::remove_dir(&held)?;
        File::open(&dir)?.sync_all()?;
    }
    ensure!(
        serde_json::from_slice::<Value>(&blob(&cleared, 2 << 20)?)? == binding
            && !held.try_exists()?
            && !src.try_exists()?,
        "missing cleared handback"
    );
    let final_state = observer.check("settled")?;
    let done = json!({"binding":binding,"source_absent":true,"quarantine_absent":true,"physically_retired_bytes":BYTES,
        "semantic_owner":final_state["terminal"],"preserved_log":final_state["log"],"preserved_partial":final_state["partial"],
        "repriced_booking":final_state["booking"],"releases_no_booking":true,"resource_credit_bytes":0,"r2_mutations":false});
    save(&completion, &done)?;
    println!("{}", done);
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("{e:#}");
        std::process::exit(1)
    }
}

#[cfg(test)]
mod appendvec_tests {
    use super::*;
    fn make(root: &Path) {
        fs::create_dir(root).unwrap();
        fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
        for i in 0..4 {
            let d = root.join(i.to_string());
            fs::create_dir(&d).unwrap();
            fs::set_permissions(&d, fs::Permissions::from_mode(0o700)).unwrap();
            let p = d.join(format!("73238440.{i}"));
            fs::write(&p, b"scratch fixture").unwrap();
            let mode = if i % 2 == 0 { 0o644 } else { 0o600 };
            fs::set_permissions(p, fs::Permissions::from_mode(mode)).unwrap();
        }
    }
    #[test]
    fn exact_four_shards_can_move_and_resume_without_touching_the_neighbor() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("source");
        let dst = tmp.path().join("held");
        make(&src);
        let keeper = tmp.path().join("private.jet");
        fs::write(&keeper, b"retain").unwrap();
        let m = src.metadata().unwrap();
        let fd = stopped_tree::open_root(&src, m.dev(), m.ino()).unwrap();
        let original = stopped_tree::capture(&fd, m.dev(), m.uid(), m.gid()).unwrap();
        assert_eq!(
            allocated(&src, &original)
                .unwrap()
                .1
                .iter()
                .map(|x| x.1)
                .collect::<Vec<_>>(),
            vec![1, 1, 1, 1]
        );
        let ledger = tmp.path().join("ledger.zst");
        let sum = ledger_file(&ledger, &original).unwrap();
        assert_eq!(sum, ledger_file(&ledger, &original).unwrap());
        let retained = unpack(&fs::read(&ledger).unwrap()).unwrap();
        assert_eq!(retained, original);
        norename(&src, &dst).unwrap();
        assert_eq!(dst.metadata().unwrap().ino(), m.ino());
        fs::remove_file(dst.join("2/73238440.2")).unwrap();
        let left = stopped_tree::capture(&fd, m.dev(), m.uid(), m.gid()).unwrap();
        assert!(stopped_tree::validate_remaining(&original, &left, false).is_err());
        stopped_tree::validate_remaining(&original, &left, true).unwrap();
        assert_eq!(
            stopped_tree::remove_contents(&fd, &retained, m.dev(), m.uid(), m.gid()).unwrap(),
            7
        );
        assert_eq!(fs::read(keeper).unwrap(), b"retain");
        assert!(!src.exists());
    }
    #[test]
    fn unrelated_leaf_modes_are_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("source");
        make(&root);
        let leaf = root.join("1/73238440.1");
        let m = root.metadata().unwrap();
        let fd = stopped_tree::open_root(&root, m.dev(), m.ino()).unwrap();
        for mode in [0o640, 0o400, 0o755, 0o4644, 0o666] {
            fs::set_permissions(&leaf, fs::Permissions::from_mode(mode)).unwrap();
            let result = stopped_tree::capture(&fd, m.dev(), m.uid(), m.gid())
                .and_then(|tree| allocated(&root, &tree));
            assert!(result.is_err(), "accepted mode {mode:o}");
        }
    }
    #[test]
    fn unexpected_leaf_or_existing_quarantine_denied() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("source");
        make(&src);
        let stranger = src.join("2/log");
        fs::write(&stranger, b"unrelated").unwrap();
        fs::set_permissions(&stranger, fs::Permissions::from_mode(0o600)).unwrap();
        let m = src.metadata().unwrap();
        let fd = stopped_tree::open_root(&src, m.dev(), m.ino()).unwrap();
        let tree = stopped_tree::capture(&fd, m.dev(), m.uid(), m.gid()).unwrap();
        assert!(allocated(&src, &tree).is_err());
        let dest = tmp.path().join("occupied");
        fs::create_dir(&dest).unwrap();
        assert!(norename(&src, &dest).is_err());
        assert!(stranger.exists());
        assert!(dest.exists());
    }
    #[test]
    fn write_sandbox_preserves_other_outputs_while_allowing_atomic_move() {
        let tmp = tempfile::tempdir().unwrap();
        for dir in ["old", "quarantine", "evidence"] {
            fs::create_dir(tmp.path().join(dir)).unwrap();
        }
        make(&tmp.path().join("old/source"));
        let exe = std::env::current_exe().unwrap();
        let rc = Command::new(exe)
            .args([
                "--ignored",
                "--exact",
                "appendvec_tests::restricted_child",
                "--test-threads=1",
            ])
            .env("G4_SHARD_FIXTURE", tmp.path())
            .status()
            .unwrap();
        assert!(rc.success());
        assert!(tmp.path().join("quarantine/moved").exists());
    }
    #[test]
    #[ignore = "runs in a child with its own irreversible filesystem sandbox"]
    fn restricted_child() {
        let r = PathBuf::from(std::env::var("G4_SHARD_FIXTURE").unwrap());
        restrict_writes(&r.join("old"), &r.join("quarantine")).unwrap();
        assert!(fs::write(r.join("evidence/foreign"), b"denied").is_err());
        let f = r.join("quarantine/scratch");
        fs::write(&f, b"bounded").unwrap();
        fs::remove_file(f).unwrap();
        norename(&r.join("old/source"), &r.join("quarantine/moved")).unwrap();
    }
    #[test]
    fn caps_compressed_output_before_authorizing_an_effect() {
        let mut limited = Limited {
            inner: Vec::new(),
            left: 4,
        };
        assert!(limited.write_all(b"oversize").is_err());
        assert!(limited.inner.is_empty());
    }
}
