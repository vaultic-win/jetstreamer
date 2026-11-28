//! Exact retirement of the already-empty, completed native265 scratch directory.
//! No recursive deletion, ledger deletion, service mutation, replay or R2 route.
mod process_references;
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    env,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    process::Command,
};
const ROOT: &str = "/home/ubuntu/.jetstreamer-private/native-input265-selected-20261119-v1";
const SCRATCH: &str =
    "/home/ubuntu/.jetstreamer-private/native-input265-selected-20261119-v1/scratch";
const UNIT: &str = "horizon-265-native-input-20261119-v1.service";
const IID: &str = "ce5f66a82fdd4c0e93ca99f27b925112";
const STATE: &str = "/var/lib/jetstreamer/horizon-native265-scratch-retirement-20261120-v2";
const IMAGE: &str =
    "/var/lib/jetstreamer/horizon-native265-scratch-retirer-20261120-v2/native265-scratch-retire";
const LOCK: &str = "/home/ubuntu/.jetstreamer-private/r2-receipts/local-mutation.lock";
const TERMINAL: &str =
    "/var/lib/jetstreamer/horizon-native265-terminal-proof-2048-20261119-v1/proof.json";
const TERMINAL_SHA: &str = "62d7d71ee1a9c7215c4fffa7d5fec49ef449bb6be24de3e450432217a3efa519";
const RESULT_SHA: &str = "06f9a0b021943a0b481a175bdc27a76231cec49bce7f48cb5039cfe46579db95";
const PACKET: &str =
    "/var/lib/jetstreamer/horizon265-native-input-evidence-20261119-v1/input-packet.json";
const PACKET_SHA: &str = "f7dbb6eedd4f47c940c959639d399ea3af68343f18fc894c736170f6dc089153";
const GENESIS_SHA: &str = "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945";
const DEV: u64 = 66305;
const ROOT_INO: u64 = 95092619;
const SCRATCH_INO: u64 = 95092622;
const LIMIT: u64 = 8 << 20;
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Bound {
    path: PathBuf,
    sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    main_accepted: bool,
    exclusive_campaign_mutation_owner: bool,
    no_staged_scratch_consumers_confirmed: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct Stamp {
    dev: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    nlink: u64,
    len: u64,
    mtime: i64,
    mtime_ns: i64,
    ctime: i64,
    ctime_ns: i64,
}
fn stamp(m: &fs::Metadata) -> Stamp {
    Stamp {
        dev: m.dev(),
        ino: m.ino(),
        uid: m.uid(),
        gid: m.gid(),
        mode: m.mode(),
        nlink: m.nlink(),
        len: m.len(),
        mtime: m.mtime(),
        mtime_ns: m.mtime_nsec(),
        ctime: m.ctime(),
        ctime_ns: m.ctime_nsec(),
    }
}
fn sha(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
fn digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn absent(p: &Path) -> Result<()> {
    match fs::symlink_metadata(p) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
        Ok(_) => bail!("expected absent exact path: {}", p.display()),
    }
}
fn file_bytes(
    p: &Path,
    expected: &str,
    uid: u32,
    ino: Option<u64>,
    immutable: bool,
) -> Result<Vec<u8>> {
    ensure!(digest(expected), "digest syntax");
    let m = fs::symlink_metadata(p)?;
    ensure!(
        p.canonicalize()? == p
            && m.is_file()
            && m.uid() == uid
            && m.gid() == uid
            && m.nlink() == 1
            && m.mode() & 0o022 == 0
            && (!immutable || m.mode() & 0o222 == 0)
            && m.len() <= LIMIT
            && ino.is_none_or(|i| i == m.ino())
            && (uid != 1000 || (m.dev() == DEV && m.mode() & 0o7777 == 0o600)),
        "file custody: {}",
        p.display()
    );
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(p)?;
    ensure!(stamp(&f.metadata()?) == stamp(&m), "file open race");
    let mut raw = Vec::new();
    Read::by_ref(&mut f).take(LIMIT + 1).read_to_end(&mut raw)?;
    ensure!(
        raw.len() as u64 <= LIMIT
            && sha(&raw) == expected
            && stamp(&f.metadata()?) == stamp(&m)
            && stamp(&fs::symlink_metadata(p)?) == stamp(&m),
        "file changed/hash mismatch"
    );
    Ok(raw)
}
fn bound(b: &Bound) -> Result<Value> {
    ensure!(
        b.path.starts_with("/var/lib/jetstreamer"),
        "immutable evidence namespace"
    );
    for p in b.path.ancestors().skip(1) {
        let m = fs::symlink_metadata(p)?;
        ensure!(
            m.is_dir() && m.uid() == 0 && m.mode() & 0o022 == 0,
            "evidence ancestor custody"
        );
    }
    Ok(serde_json::from_slice(&file_bytes(
        &b.path, &b.sha256, 0, None, true,
    )?)?)
}
fn write_new(p: &Path, v: &Value) -> Result<Bound> {
    let raw = serde_json::to_vec_pretty(v)?;
    ensure!(raw.len() as u64 <= LIMIT, "receipt limit");
    let parent = p.parent().context("receipt parent")?;
    let mut f = OpenOptions::new()
        .read(true)
        .write(true)
        .mode(0o444)
        .custom_flags(libc::O_TMPFILE | libc::O_CLOEXEC)
        .open(parent)?;
    f.write_all(&raw)?;
    f.sync_all()?;
    let parent_fd = File::open(parent)?;
    let source = std::ffi::CString::new(format!("/proc/self/fd/{}", f.as_raw_fd()))?;
    let name = std::ffi::CString::new(p.file_name().context("receipt name")?.as_encoded_bytes())?;
    // Publish the fully synced anonymous inode. An interrupted write leaves no
    // named partial receipt, and linkat cannot replace an existing name.
    if unsafe {
        libc::linkat(
            libc::AT_FDCWD,
            source.as_ptr(),
            parent_fd.as_raw_fd(),
            name.as_ptr(),
            libc::AT_SYMLINK_FOLLOW,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    parent_fd.sync_all()?;
    Ok(Bound {
        path: p.into(),
        sha256: sha(&raw),
    })
}
fn saved(name: &str, hash: &str) -> Result<Value> {
    bound(&Bound {
        path: Path::new(STATE).join(name),
        sha256: hash.into(),
    })
}
fn directory(p: &Path, ino: u64) -> Result<File> {
    ensure!(p.canonicalize()? == p, "directory alias");
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(p)?;
    let m = f.metadata()?;
    ensure!(
        m.dev() == DEV
            && m.ino() == ino
            && m.uid() == 1000
            && m.gid() == 1000
            && m.mode() & 0o7777 == 0o700,
        "directory identity"
    );
    Ok(f)
}
fn names(p: &Path) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for e in fs::read_dir(p)? {
        out.push(
            e?.file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("nonUTF8 child"))?,
        );
        ensure!(out.len() < 16, "unexpected runtime children");
    }
    out.sort();
    Ok(out)
}
fn baseline(scratch_present: bool) -> Result<Value> {
    let root = directory(Path::new(ROOT), ROOT_INO)?;
    let mut expected = vec!["ledger", "native-result.json", "tmp", "worker.stderr"];
    if scratch_present {
        expected.push("scratch");
    }
    expected.sort();
    ensure!(
        names(Path::new(ROOT))? == expected,
        "original runtime root has changed members"
    );
    let sentinel = file_bytes(
        &Path::new(ROOT).join("native-result.json"),
        RESULT_SHA,
        1000,
        Some(95092626),
        false,
    )?;
    let result: Value = serde_json::from_slice(&sentinel)?;
    ensure!(
        result["schema"] == "horizon265-exact-worker-cold-input-result-v1"
            && result["epoch"] == 265
            && result["full_accounts_commitment_verified"] == true
            && result["worker_reaped"] == true
            && result["worker_shutdown_acknowledged"] == true
            && result["worker_pid"] == 1307832
            && result["first_guard"]["invocation_id"] == IID,
        "native completion sentinel differs"
    );
    let ledger = directory(&Path::new(ROOT).join("ledger"), 95092621)?;
    let tmp = directory(&Path::new(ROOT).join("tmp"), 95092623)?;
    ensure!(
        names(&Path::new(ROOT).join("ledger"))? == ["genesis.tar.bz2"]
            && names(&Path::new(ROOT).join("tmp"))?.is_empty(),
        "original ledger/tmp changed"
    );
    file_bytes(
        &Path::new(ROOT).join("ledger/genesis.tar.bz2"),
        GENESIS_SHA,
        1000,
        Some(95092624),
        false,
    )?;
    file_bytes(
        &Path::new(ROOT).join("worker.stderr"),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        1000,
        Some(95092625),
        false,
    )?;
    let mut preserved = BTreeMap::new();
    for name in [
        "native-result.json",
        "ledger/genesis.tar.bz2",
        "worker.stderr",
    ] {
        preserved.insert(
            name,
            stamp(&fs::symlink_metadata(Path::new(ROOT).join(name))?),
        );
    }
    // Root directory timestamps/link count change only when the empty scratch child
    // is unlinked. Every file and the retained ledger/tmp directory stays exact.
    Ok(
        json!({"root_device":root.metadata()?.dev(),"root_inode":root.metadata()?.ino(),"ledger":stamp(&ledger.metadata()?),"tmp":stamp(&tmp.metadata()?),"files":preserved,"sentinel_sha256":RESULT_SHA}),
    )
}
fn proofs() -> Result<Value> {
    let reference = Bound {
        path: TERMINAL.into(),
        sha256: TERMINAL_SHA.into(),
    };
    let t = bound(&reference)?;
    ensure!(
        t["schema"] == "jetstreamer-private-epoch265-native-terminal-proof-v1"
            && t["unit"] == UNIT
            && t["invocation_id"] == IID
            && t["main_pid"] == 1307638
            && t["native_input_qualified"] == true
            && t["boot_id"] == fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim(),
        "terminal proof owner/boot"
    );
    for k in [
        "native_result",
        "guard_history",
        "startup_handoff",
        "capture_spec",
        "consumer_transition",
    ] {
        let b: Bound = serde_json::from_value(t[k].clone())?;
        bound(&b)?;
    }
    let b: Bound = serde_json::from_value(t["native_result"].clone())?;
    ensure!(b.sha256 == RESULT_SHA, "original result sentinel binding");
    // The unchanged original harness rejects a nonempty ROOT before worker
    // creation. The preserved exact result sentinel keeps that restart fence.
    file_bytes(
        Path::new(
            "/var/lib/jetstreamer/horizon265-native-input-daa786c0-20261119-v1/horizon265-native-input",
        ),
        "0dbcd28e231f7158b88701666bff89cbdf36cc2033c0e5e826e54a8c87db76e9",
        0,
        None,
        true,
    )?;
    let packet = bound(&Bound {
        path: PACKET.into(),
        sha256: PACKET_SHA.into(),
    })?;
    let files = packet["files"].as_array().context("input packet files")?;
    ensure!(files.len() == 4, "input packet membership");
    for v in files {
        let p = Path::new(v["path"].as_str().context("input path")?);
        let m = fs::symlink_metadata(p)?;
        let i = &v["identity"];
        ensure!(
            p.canonicalize()? == p
                && m.is_file()
                && m.uid() == 0
                && m.gid() == 0
                && m.nlink() == 1
                && m.mode() & 0o222 == 0
                && i["device"] == m.dev()
                && i["inode"] == m.ino()
                && i["bytes"] == m.len()
                && i["mode"] == m.mode()
                && i["mtime"] == m.mtime()
                && i["mtime_nsec"] == m.mtime_nsec()
                && i["ctime"] == m.ctime()
                && i["ctime_nsec"] == m.ctime_nsec(),
            "original input metadata changed"
        );
    }
    Ok(json!({"terminal_proof":reference,"original_evidence":t,"input_packet":packet}))
}
fn show() -> Result<BTreeMap<String, String>> {
    let out=Command::new("/usr/bin/systemctl").args(["show",UNIT,"--property=Id,LoadState,ActiveState,SubState,InvocationID,MainPID,ControlPID,ExecMainPID,ExecMainCode,ExecMainStatus,NRestarts,Result,Job,Restart,KillMode,Delegate,ControlGroup,TriggeredBy,ExecStart,FragmentPath,DropInPaths,MemoryMax,MemoryHigh,MemorySwapMax,TasksMax,Type,User,Group"]).output()?;
    ensure!(
        out.status.success() && out.stdout.len() < 1 << 20,
        "terminal PID1 query"
    );
    let mut m = BTreeMap::new();
    for line in std::str::from_utf8(&out.stdout)?.lines() {
        let (k, v) = line.split_once('=').context("PID1 framing")?;
        ensure!(
            m.insert(k.into(), v.into()).is_none(),
            "duplicate PID1 property"
        );
    }
    Ok(m)
}
// PID1 may clear only its presentation history while retaining this terminal
// invocation. Accept the two observed exact histories; never normalize commands.
const NATIVE_COMMAND: &str = "{ path=/var/lib/jetstreamer/horizon265-native-input-daa786c0-20261119-v1/horizon265-native-input ; argv[]=/var/lib/jetstreamer/horizon265-native-input-daa786c0-20261119-v1/horizon265-native-input ; ignore_errors=no";
const ORIGINAL_HISTORY: &str = "[Thu 2026-11-19 19:54:52 UTC] ; stop_time=[Thu 2026-11-19 20:04:20 UTC] ; pid=1307638 ; code=exited ; status=0 }";
const RESET_HISTORY: &str = "[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }";
fn native_command(value: &str) -> Result<&str> {
    ensure!(
        value.matches(" ; start_time=").count() == 1,
        "ambiguous native265 command framing"
    );
    let (command, history) = value
        .split_once(" ; start_time=")
        .context("native265 command history")?;
    ensure!(
        command == NATIVE_COMMAND && matches!(history, ORIGINAL_HISTORY | RESET_HISTORY),
        "native265 command or terminal display history changed"
    );
    Ok(command)
}
fn terminal_properties(m: &BTreeMap<String, String>, proof: &Value) -> Result<()> {
    for (k, want) in [
        ("Id", UNIT),
        ("InvocationID", IID),
        ("LoadState", "loaded"),
        ("ActiveState", "inactive"),
        ("SubState", "dead"),
        ("MainPID", "0"),
        ("ControlPID", "0"),
        ("NRestarts", "0"),
        ("Result", "success"),
        ("ExecMainCode", "1"),
        ("ExecMainPID", "1307638"),
        ("ExecMainStatus", "0"),
        ("Job", ""),
        ("Restart", "no"),
        ("KillMode", "control-group"),
        ("Delegate", "no"),
        ("TriggeredBy", ""),
    ] {
        ensure!(
            m.get(k).map(String::as_str) == Some(want),
            "native terminal {k} differs"
        );
    }
    let old = &proof["original_evidence"]["terminal_manager"];
    ensure!(
        native_command(m.get("ExecStart").context("current native ExecStart")?)?
            == native_command(
                old["ExecStart"]
                    .as_str()
                    .context("original native ExecStart")?
            )?,
        "native265 exact command changed"
    );
    for k in [
        "FragmentPath",
        "DropInPaths",
        "MemoryMax",
        "MemoryHigh",
        "MemorySwapMax",
        "TasksMax",
        "Type",
        "User",
        "Group",
    ] {
        ensure!(
            old[k].as_str() == m.get(k).map(String::as_str),
            "original terminal binding changed {k}"
        );
    }
    ensure!(
        m.get("ControlGroup")
            .is_some_and(|s| s.is_empty() || s == &format!("/system.slice/{UNIT}")),
        "native group differs"
    );
    Ok(())
}
fn terminal(m: &BTreeMap<String, String>, proof: &Value) -> Result<()> {
    terminal_properties(m, proof)?;
    for pid in [1307638, 1307832] {
        absent(Path::new(&format!("/proc/{pid}")))?;
    }
    absent(Path::new(&format!("/sys/fs/cgroup/system.slice/{UNIT}")))?;
    Ok(())
}
fn unescape(s: &str) -> Result<String> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' {
            ensure!(i + 3 < b.len(), "mount escape");
            let oct = &b[i + 1..i + 4];
            ensure!(
                oct.iter().all(|c| (b'0'..=b'7').contains(c)),
                "mount escape"
            );
            let value = u16::from(oct[0] - b'0') * 64
                + u16::from(oct[1] - b'0') * 8
                + u16::from(oct[2] - b'0');
            ensure!(value <= 255, "mount escape exceeds byte");
            out.push(value as u8);
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    Ok(String::from_utf8(out)?)
}
fn mount_check(raw: &str, target: &Path) -> Result<()> {
    for line in raw.lines() {
        let words: Vec<_> = line.split_whitespace().collect();
        ensure!(
            words.len() >= 10 && words.contains(&"-"),
            "mountinfo framing"
        );
        let mount_root = PathBuf::from(unescape(words[3])?);
        let mount_point = PathBuf::from(unescape(words[4])?);
        ensure!(
            !(mount_point == target || mount_point.starts_with(target)),
            "scratch has a mountpoint"
        );
        let device = format!("{}:{}", libc::major(DEV), libc::minor(DEV));
        if words[2] == device {
            ensure!(
                !(mount_root == target || mount_root.starts_with(target)),
                "scratch bind alias"
            );
            if let Ok(suffix) = target.strip_prefix(&mount_root) {
                ensure!(
                    mount_point.join(suffix) == target,
                    "ancestor bind alias exposes old scratch"
                );
            }
        }
    }
    Ok(())
}
fn no_owners() -> Result<Value> {
    let scan = process_references::scan(Path::new("/proc"), Path::new(ROOT))?;
    ensure!(
        scan.references.is_empty(),
        "scratch has process references: {:?}",
        scan.references
    );
    let mut inspected = 0;
    for e in fs::read_dir("/proc")? {
        let e = e?;
        let name = e.file_name();
        if !name.to_string_lossy().bytes().all(|c| c.is_ascii_digit()) {
            continue;
        }
        if name.to_string_lossy() == std::process::id().to_string() {
            continue;
        }
        let p = e.path();
        let check = || -> Result<()> {
            let stat = fs::read_to_string(p.join("stat"))?;
            let tail = stat.rsplit_once(')').context("process stat")?.1;
            let group = tail
                .split_whitespace()
                .nth(2)
                .context("process group")?
                .parse::<u32>()?;
            ensure!(
                ![1307638, 1307832].contains(&group),
                "original process group remains"
            );
            let cg = fs::read_to_string(p.join("cgroup"))?;
            ensure!(
                !cg.contains(&format!("/system.slice/{UNIT}")),
                "native cgroup still owns process"
            );
            let mounts = fs::read(p.join("mountinfo"))?;
            ensure!(mounts.len() < 16 << 20, "mountinfo bound");
            mount_check(std::str::from_utf8(&mounts)?, Path::new(SCRATCH))?;
            for link in ["cwd", "root", "exe"] {
                match fs::metadata(p.join(link)) {
                    Ok(m) => ensure!(
                        !(m.dev() == DEV && [ROOT_INO, SCRATCH_INO].contains(&m.ino())),
                        "alias reference to original scratch inode"
                    ),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                    Err(e) => return Err(e.into()),
                }
            }
            for fd in fs::read_dir(p.join("fd"))? {
                match fs::metadata(fd?.path()) {
                    Ok(m) => ensure!(
                        !(m.dev() == DEV && [ROOT_INO, SCRATCH_INO].contains(&m.ino())),
                        "open scratch inode through alias"
                    ),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                    Err(e) => return Err(e.into()),
                }
            }
            Ok(())
        };
        if let Err(err) = check()
            && p.try_exists()?
        {
            return Err(err);
        }
        inspected += 1;
    }
    mount_check(
        &fs::read_to_string("/proc/self/mountinfo")?,
        Path::new(SCRATCH),
    )?;
    Ok(
        json!({"path_reference_scan":scan,"mount_and_inode_processes_inspected":inspected,"original_process_group_absent":true,"scratch_mount_aliases_absent":true}),
    )
}
fn lock() -> Result<File> {
    let p = Path::new(LOCK);
    let m = fs::symlink_metadata(p)?;
    ensure!(
        p.canonicalize()? == p
            && m.is_file()
            && m.nlink() == 1
            && [0, 1000].contains(&m.uid())
            && m.mode() & 0o077 == 0,
        "shared mutation lock custody"
    );
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(p)?;
    ensure!(
        stamp(&f.metadata()?) == stamp(&m)
            && unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "mutation lock race/busy"
    );
    Ok(f)
}
fn check_empty(fd: &File) -> Result<()> {
    ensure!(
        fs::read_dir(format!("/proc/self/fd/{}", fd.as_raw_fd()))?
            .next()
            .is_none(),
        "scratch is not already empty; no recursive deletion is qualified"
    );
    Ok(())
}
fn remove_empty(parent: &File, expected: &Stamp) -> Result<()> {
    let p = PathBuf::from(format!("/proc/self/fd/{}/scratch", parent.as_raw_fd()));
    let m = fs::symlink_metadata(&p)?;
    ensure!(
        stamp(&m) == *expected && m.is_dir(),
        "scratch identity changed at unlink"
    );
    let name = std::ffi::CString::new("scratch")?;
    ensure!(
        unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) } == 0,
        "exact empty directory removal refused: {}",
        std::io::Error::last_os_error()
    );
    parent.sync_all()?;
    Ok(())
}
fn wall() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs())
}
fn booking_valid(b: &Value) -> Result<()> {
    let issued = b["recorded_unix_seconds"]
        .as_u64()
        .context("booking issue clock")?;
    let expires = b["expires_unix_seconds"]
        .as_u64()
        .context("booking expiry")?;
    let current = wall()?;
    ensure!(
        issued <= current
            && current < expires
            && expires <= issued.checked_add(600).context("booking clock overflow")?,
        "expired/future retirement booking"
    );
    Ok(())
}
fn run() -> Result<()> {
    let a: Vec<_> = env::args().collect();
    ensure!(
        a.len() >= 7,
        "usage: retire check|retire|resume|attest PLAN PLAN_SHA SELF_SHA BOOKING BOOKING_SHA [CHECK_SHA [INTENT_SHA]] | attest PLAN PLAN_SHA SELF_SHA BOOKING BOOKING_SHA COMPLETION_SHA"
    );
    let mode = &a[1];
    ensure!(
        matches!(mode.as_str(), "check" | "retire" | "resume" | "attest")
            && a.len()
                == match mode.as_str() {
                    "check" => 7,
                    "resume" => 9,
                    _ => 8,
                },
        "mode/argument count"
    );
    ensure!(
        unsafe { libc::geteuid() } == 0 && env::current_exe()? == Path::new(IMAGE) && digest(&a[4]),
        "sealed helper identity"
    );
    for ancestor in Path::new(IMAGE).ancestors().skip(1) {
        let m = fs::symlink_metadata(ancestor)?;
        ensure!(
            m.is_dir() && m.uid() == 0 && m.mode() & 0o022 == 0,
            "helper ancestor custody"
        );
    }
    let em = fs::symlink_metadata(IMAGE)?;
    ensure!(
        em.is_file()
            && Path::new(IMAGE).canonicalize()? == Path::new(IMAGE)
            && em.uid() == 0
            && em.gid() == 0
            && em.nlink() == 1
            && em.mode() & 0o222 == 0
            && em.len() < 64 << 20
            && sha(&fs::read("/proc/self/exe")?) == a[4],
        "helper image custody/hash"
    );
    let plan_ref = Bound {
        path: a[2].clone().into(),
        sha256: a[3].clone(),
    };
    let p: Plan = serde_json::from_value(bound(&plan_ref)?)?;
    ensure!(
        p.schema == "horizon-native265-empty-scratch-retirement-plan-v1"
            && p.main_accepted
            && p.exclusive_campaign_mutation_owner
            && p.no_staged_scratch_consumers_confirmed,
        "retirement review scope"
    );
    let booking_ref = Bound {
        path: a[5].clone().into(),
        sha256: a[6].clone(),
    };
    let booking = bound(&booking_ref)?;
    ensure!(
        booking["schema"] == "horizon-native265-runtime-retirement-booking-v1"
            && booking["Main_accepted"] == true
            && booking["maximum_memory_bytes"] == 268435456
            && booking["maximum_metadata_bytes"] == 16777216
            && booking["maximum_wall_seconds"] == 120
            && booking["future_growth_credit_taken_bytes"] == 0
            && booking["plan"] == json!(plan_ref),
        "missing exact fresh phase booking"
    );
    booking_valid(&booking)?;
    let controller = format!("horizon-native265-scratch-retirement-{mode}-20261120-v2.service");
    ensure!(
        fs::read_to_string("/proc/self/cgroup")?.trim() == format!("0::/system.slice/{controller}"),
        "run only in the exact bounded retirement controller"
    );
    let _lock = lock()?;
    if mode != "check" || Path::new(STATE).try_exists()? {
        let m = fs::symlink_metadata(STATE)?;
        ensure!(
            m.is_dir() && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o7777 == 0o700,
            "state custody"
        );
        if mode == "check" {
            ensure!(
                names(Path::new(STATE))?.is_empty(),
                "check namespace already used"
            );
        }
    }
    if mode == "retire" || mode == "resume" {
        absent(&Path::new(STATE).join("completion.json"))?;
        absent(&Path::new(STATE).join("absence-v1.json"))?;
    }
    let proof = proofs()?;
    let before = show()?;
    terminal(&before, &proof)?;
    let present = mode == "check" || mode == "retire";
    if mode == "resume" {
        let intent = saved("intent.json", &a[8])?;
        ensure!(
            intent["schema"] == "horizon-native265-empty-scratch-retirement-intent-v1"
                && intent["plan"] == json!(plan_ref)
                && intent["helper_sha256"] == a[4]
                && intent["check"]
                    == json!(Bound {
                        path: Path::new(STATE).join("check.json"),
                        sha256: a[7].clone()
                    })
                && intent["only_empty_scratch_directory_removal_authorized"] == true,
            "resume original intent binding"
        );
    }
    let actual_present = match fs::symlink_metadata(SCRATCH) {
        Ok(_) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => return Err(e.into()),
    };
    ensure!(
        !present || actual_present,
        "fresh operation needs original scratch directory"
    );
    ensure!(
        mode != "attest" || !actual_present,
        "scratch reappeared after retirement"
    );
    let preserved = baseline(actual_present)?;
    let ownership = no_owners()?;
    if mode == "check" {
        let fd = directory(Path::new(SCRATCH), SCRATCH_INO)?;
        check_empty(&fd)?;
        let after = show()?;
        terminal(&after, &proof)?;
        ensure!(
            before == after && baseline(true)? == preserved,
            "scope changed during check"
        );
        if !Path::new(STATE).try_exists()? {
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new().mode(0o700).create(STATE)?;
        }
        File::open("/var/lib/jetstreamer")?.sync_all()?;
        let receipt = write_new(
            &Path::new(STATE).join("check.json"),
            &json!({"schema":"horizon-native265-empty-scratch-retirement-check-v1","recorded_unix_seconds":wall()?,"plan":plan_ref,"helper_sha256":a[4],"booking":booking_ref,"terminal":before,"proofs":proof,"preserved":preserved,"scratch":stamp(&fd.metadata()?),"ownership":ownership,"scratch_already_empty":true,"retirement_performed":false,"resource_release_authorized":false,"replay_launch_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false}),
        )?;
        println!("{}", serde_json::to_string(&receipt)?);
        return Ok(());
    }
    if mode == "attest" {
        let c = saved("completion.json", &a[7])?;
        ensure!(
            c["schema"] == "horizon-native265-empty-scratch-retirement-completion-v1"
                && c["plan"] == json!(plan_ref)
                && c["helper_sha256"] == a[4]
                && c["preserved"] == preserved
                && c["terminal"] == json!(before),
            "completion scope changed"
        );
        let after = show()?;
        terminal(&after, &proof)?;
        ensure!(
            before == after && baseline(false)? == preserved,
            "absence attestation changed"
        );
        absent(Path::new(SCRATCH))?;
        let receipt = write_new(
            &Path::new(STATE).join("absence-v1.json"),
            &json!({"schema":"horizon-native265-empty-scratch-absence-v1","recorded_unix_seconds":wall()?,"completion":Bound{path:Path::new(STATE).join("completion.json"),sha256:a[7].clone()},"plan":plan_ref,"helper_sha256":a[4],"booking":booking_ref,"terminal":after,"preserved":preserved,"ownership":ownership,"scratch_absent":true,"memory_release_authorized":false,"future_growth_release_authorized":false,"physical_reclamation_credit_bytes":0,"replay_launch_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false}),
        )?;
        println!("{}", serde_json::to_string(&receipt)?);
        return Ok(());
    }
    let check = saved("check.json", &a[7])?;
    ensure!(
        check["schema"] == "horizon-native265-empty-scratch-retirement-check-v1"
            && check["plan"] == json!(plan_ref)
            && check["helper_sha256"] == a[4]
            && check["scratch_already_empty"] == true
            && check["preserved"] == preserved
            && check["terminal"] == json!(before)
            && check["proofs"] == proof,
        "original check changed"
    );
    let expected: Stamp = serde_json::from_value(check["scratch"].clone())?;
    if mode == "resume" {
        let intent = saved("intent.json", &a[8])?;
        ensure!(
            intent["scratch"] == check["scratch"]
                && intent["preserved"] == preserved
                && intent["terminal"] == json!(before),
            "resume original intent scope changed"
        );
    }
    let parent = directory(Path::new(ROOT), ROOT_INO)?;
    if actual_present {
        let fd = directory(Path::new(SCRATCH), SCRATCH_INO)?;
        check_empty(&fd)?;
        ensure!(
            stamp(&fd.metadata()?) == expected,
            "scratch changed after check"
        );
    }
    if mode == "retire" {
        write_new(
            &Path::new(STATE).join("intent.json"),
            &json!({"schema":"horizon-native265-empty-scratch-retirement-intent-v1","recorded_unix_seconds":wall()?,"plan":plan_ref,"helper_sha256":a[4],"booking":booking_ref,"check":Bound{path:Path::new(STATE).join("check.json"),sha256:a[7].clone()},"scratch":expected,"preserved":preserved,"terminal":before,"ownership":ownership,"only_empty_scratch_directory_removal_authorized":true,"resource_release_authorized":false,"replay_launch_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false}),
        )?;
    }
    let current = show()?;
    terminal(&current, &proof)?;
    ensure!(
        current == before && baseline(actual_present)? == preserved,
        "owner/sentinel changed before removal"
    );
    no_owners()?;
    booking_valid(&booking)?;
    if actual_present {
        remove_empty(&parent, &expected)?;
    }
    absent(Path::new(SCRATCH))?;
    let after = show()?;
    terminal(&after, &proof)?;
    ensure!(
        after == before && baseline(false)? == preserved && proofs()? == proof,
        "scope changed after retirement"
    );
    let after_ownership = no_owners()?;
    let intent_reference = Bound {
        path: Path::new(STATE).join("intent.json"),
        sha256: sha(&fs::read(Path::new(STATE).join("intent.json"))?),
    };
    if mode == "resume" {
        ensure!(
            intent_reference.sha256 == a[8],
            "original resume intent changed"
        );
    }
    let intent = bound(&intent_reference)?;
    ensure!(
        intent["plan"] == json!(plan_ref)
            && intent["helper_sha256"] == a[4]
            && intent["check"]["sha256"] == a[7],
        "final intent provenance"
    );
    let receipt = write_new(
        &Path::new(STATE).join("completion.json"),
        &json!({"schema":"horizon-native265-empty-scratch-retirement-completion-v1","recorded_unix_seconds":wall()?,"plan":plan_ref,"helper_sha256":a[4],"booking":booking_ref,"unit":UNIT,"invocation_id":IID,"terminal":after,"proofs":proof,"preserved":preserved,"ownership":after_ownership,"check":Bound{path:Path::new(STATE).join("check.json"),sha256:a[7].clone()},"intent":intent_reference,"retired_paths":[SCRATCH],"scratch_absent":true,"scratch_was_already_empty":true,"ledger_tmp_result_stderr_and_input_cache_preserved":true,"original_root_preserved":true,"live_v3_not_read_or_changed":true,"memory_release_authorized":false,"future_growth_release_authorized":false,"physical_reclamation_credit_bytes":0,"replay_launch_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false}),
    )?;
    println!("{}", serde_json::to_string(&receipt)?);
    Ok(())
}
fn main() -> Result<()> {
    run()
}
#[cfg(test)]
mod tests;
