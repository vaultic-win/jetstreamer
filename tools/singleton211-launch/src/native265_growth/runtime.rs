//! Read-only revalidation of the exact scratch-only retirement scope.
use super::super::*;
#[path = "process_references.rs"]
pub(super) mod process_references;
const ROOT: &str = "/home/ubuntu/.jetstreamer-private/native-input265-selected-20261119-v1";
const SCRATCH: &str =
    "/home/ubuntu/.jetstreamer-private/native-input265-selected-20261119-v1/scratch";
const UNIT: &str = "horizon-265-native-input-20261119-v1.service";
const IID: &str = "ce5f66a82fdd4c0e93ca99f27b925112";

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
fn show(n: &mut Native) -> Result<BTreeMap<String, String>> {
    let bytes = n.run("/usr/bin/systemctl", &["show",UNIT,"--property=Id,LoadState,ActiveState,SubState,InvocationID,MainPID,ControlPID,ExecMainPID,ExecMainCode,ExecMainStatus,NRestarts,Result,Job,Restart,KillMode,Delegate,ControlGroup,TriggeredBy,ExecStart,FragmentPath,DropInPaths,MemoryMax,MemoryHigh,MemorySwapMax,TasksMax,Type,User,Group"])?;
    let mut m = BTreeMap::new();
    for line in std::str::from_utf8(&bytes)?.lines() {
        let (k, v) = line.split_once('=').context("native265 property framing")?;
        ensure!(
            m.insert(k.into(), v.into()).is_none(),
            "duplicate terminal property"
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
fn proc_identity(stat: &str) -> Result<(&str, u32, u64)> {
    let fields: Vec<_> = stat
        .rsplit_once(')')
        .context("process stat comm")?
        .1
        .split_ascii_whitespace()
        .collect();
    ensure!(fields.len() > 19, "incomplete process stat");
    Ok((fields[0], fields[2].parse()?, fields[19].parse()?))
}

fn released_mount_namespace(proc: &Path, group: u32, start: u64) -> Result<()> {
    // Linux returns EINVAL for mountinfo after exit releases nsproxy.
    // A zombie group leader can still have live sibling threads.
    let stat_path = proc.join("stat");
    let same_zombie = || -> Result<bool> {
        Ok(proc_identity(&fs::read_to_string(&stat_path)?)? == ("Z", group, start))
    };
    ensure!(
        same_zombie()?,
        "mountinfo EINVAL for a live or replaced owner"
    );
    let pid = proc.file_name().context("process directory")?;
    let mut tasks = fs::read_dir(proc.join("task"))?;
    ensure!(
        tasks
            .next()
            .transpose()?
            .is_some_and(|t| t.file_name() == pid)
            && tasks.next().transpose()?.is_none(),
        "mountinfo EINVAL with another task"
    );
    match fs::read_link(proc.join("ns/mnt")) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => return Err(e.into()),
        Ok(_) => bail!("mountinfo EINVAL with surviving mount namespace"),
    }
    ensure!(
        same_zombie()?,
        "process identity changed after mountinfo EINVAL"
    );
    Ok(())
}

fn inspect_mountinfo(proc: &Path, group: u32, start: u64, scratch: &Path) -> Result<()> {
    let file = proc.join("mountinfo");
    match fs::read(&file) {
        Ok(mounts) => {
            ensure!(mounts.len() < 16 << 20, "mountinfo bound");
            mount_check(std::str::from_utf8(&mounts)?, scratch)
        }
        Err(error) if error.raw_os_error() == Some(libc::EINVAL) => {
            released_mount_namespace(proc, group, start)
        }
        Err(error) => Err(error.into()),
    }
    .with_context(|| format!("read and verify {}", file.display()))
}

pub(crate) fn scratch_ownership(
    root: &Path,
    scratch: &Path,
    unit: &str,
    original_pids: &[u32],
    original_inodes: &[u64],
) -> Result<Value> {
    let scan =
        process_references::scan(Path::new("/proc"), root).context("scratch process references")?;
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
            let (_, group, start) = proc_identity(&stat)?;
            ensure!(
                !original_pids.contains(&group),
                "original process group remains"
            );
            let cg = fs::read_to_string(p.join("cgroup"))?;
            ensure!(
                !cg.contains(&format!("/system.slice/{unit}")),
                "native cgroup still owns process"
            );
            inspect_mountinfo(&p, group, start, scratch)?;
            for link in ["cwd", "root", "exe"] {
                match fs::metadata(p.join(link)) {
                    Ok(m) => ensure!(
                        !(m.dev() == DEV && original_inodes.contains(&m.ino())),
                        "alias reference to original scratch inode"
                    ),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                    Err(e) => return Err(e.into()),
                }
            }
            for fd in fs::read_dir(p.join("fd"))? {
                match fs::metadata(fd?.path()) {
                    Ok(m) => ensure!(
                        !(m.dev() == DEV && original_inodes.contains(&m.ino())),
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
            return Err(err).with_context(|| format!("scratch ownership {}", p.display()));
        }
        inspected += 1;
    }
    mount_check(&fs::read_to_string("/proc/self/mountinfo")?, scratch)?;
    Ok(
        json!({"path_reference_scan":scan,"mount_and_inode_processes_inspected":inspected,"original_process_group_absent":true,"scratch_mount_aliases_absent":true}),
    )
}

pub(super) fn capture(n: &mut Native) -> Result<Value> {
    n.check()?;
    absent(Path::new(SCRATCH))?;
    let proof = proofs()?;
    let before = show(n)?;
    terminal(&before, &proof)?;
    let preserved = baseline(false)?;
    let ownership = scratch_ownership(
        Path::new(ROOT),
        Path::new(SCRATCH),
        UNIT,
        &[1307638, 1307832],
        &[ROOT_INO, SCRATCH_INO],
    )?;
    let after = show(n)?;
    terminal(&after, &proof)?;
    ensure!(
        before == after && baseline(false)? == preserved && proofs()? == proof,
        "native265 retirement state changed during admission"
    );
    absent(Path::new(SCRATCH))?;
    n.check()?;
    Ok(json!({"proofs":proof,"terminal":after,"preserved":preserved,"ownership":ownership}))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn linux_mountinfo_einval_requires_the_original_lone_zombie() {
        // WNOWAIT leaves the child visible in procfs until our explicit reap.
        let mut child = std::process::Command::new("/bin/true").spawn().unwrap();
        let pid = child.id();
        let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::uninit();
        assert_eq!(
            unsafe {
                libc::waitid(
                    libc::P_PID,
                    pid,
                    info.as_mut_ptr(),
                    libc::WEXITED | libc::WNOWAIT,
                )
            },
            0
        );
        let proc = PathBuf::from(format!("/proc/{pid}"));
        let stat = fs::read_to_string(proc.join("stat")).unwrap();
        let (state, group, start) = proc_identity(&stat).unwrap();
        let errno = fs::read(proc.join("mountinfo")).unwrap_err().raw_os_error();
        let good = inspect_mountinfo(&proc, group, start, Path::new(SCRATCH));
        let reused = inspect_mountinfo(&proc, group, start + 1, Path::new(SCRATCH));
        child.wait().unwrap();
        assert_eq!(state, "Z");
        assert_eq!(errno, Some(libc::EINVAL));
        good.unwrap();
        assert!(reused.is_err());
    }

    #[test]
    fn detached_namespace_does_not_exempt_live_or_multithreaded_owners() {
        use std::os::unix::fs::symlink;
        let tmp = tempfile::tempdir().unwrap();
        let proc = tmp.path().join("187");
        fs::create_dir_all(proc.join("task/187")).unwrap();
        fs::create_dir(proc.join("ns")).unwrap();
        let write_stat = |state: &str| {
            let mut fields = vec!["0"; 20];
            fields[0] = state;
            fields[2] = "100";
            fields[19] = "998";
            fs::write(
                proc.join("stat"),
                format!("187 (held worker)) {}", fields.join(" ")),
            )
            .unwrap();
        };
        write_stat("S");
        assert!(released_mount_namespace(&proc, 100, 998).is_err());
        write_stat("Z");
        released_mount_namespace(&proc, 100, 998).unwrap();
        assert!(released_mount_namespace(&proc, 101, 998).is_err());
        assert!(released_mount_namespace(&proc, 100, 997).is_err());
        fs::create_dir(proc.join("task/188")).unwrap();
        assert!(released_mount_namespace(&proc, 100, 998).is_err());
        fs::remove_dir(proc.join("task/188")).unwrap();
        symlink("mnt:[5]", proc.join("ns/mnt")).unwrap();
        assert!(released_mount_namespace(&proc, 100, 998).is_err());
    }

    #[test]
    fn retained_actual_terminal_rejects_changed_owner_caps_and_commands() {
        let terminal: Value =
            serde_json::from_str(include_str!("fixtures/original-terminal.json")).unwrap();
        let proof = json!({"original_evidence":terminal});
        let m: BTreeMap<String, String> =
            serde_json::from_value(proof["original_evidence"]["terminal_manager"].clone()).unwrap();
        terminal_properties(&m, &proof).unwrap();
        for (k, v) in [
            ("MainPID", "42"),
            ("ControlPID", "42"),
            ("ExecMainPID", "42"),
            ("InvocationID", "wrong"),
            ("MemoryMax", "1"),
            ("Restart", "always"),
            ("TriggeredBy", "restart.timer"),
            ("ExecStart", "replacement"),
            ("Job", "1/start"),
        ] {
            let mut changed = m.clone();
            changed.insert(k.into(), v.into());
            assert!(terminal_properties(&changed, &proof).is_err(), "{k}");
        }
    }
    #[test]
    fn scratch_mount_alias_and_escaped_malformed_bytes_fail_closed() {
        let p = Path::new("/private/native/scratch");
        for raw in [
            "1 0 259:1 /private/native/scratch /alias rw - ext4 /dev/test rw\n",
            "1 0 259:1 / /private/native/scratch rw - ext4 /dev/test rw\n",
            "1 0 259:1 /private /different rw - ext4 /dev/test rw\n",
        ] {
            assert!(mount_check(raw, p).is_err());
        }
        assert!(mount_check("1 0 259:1 / / rw - ext4 /dev/test rw\n", p).is_ok());
        assert!(unescape("/bad\\777").is_err());
    }

    #[test]
    fn actual_post_reload_display_preserves_all_twenty_eight_terminal_properties() {
        let original: Value =
            serde_json::from_str(include_str!("fixtures/original-terminal.json")).unwrap();
        let old: BTreeMap<String, String> =
            serde_json::from_value(original["terminal_manager"].clone()).unwrap();
        let current: BTreeMap<String, String> =
            include_str!("fixtures/post-reload-terminal.properties")
                .lines()
                .map(|l| {
                    let (k, v) = l.split_once('=').unwrap();
                    (k.into(), v.into())
                })
                .collect();
        assert_eq!(current.len(), 28);
        assert_ne!(current["ExecStart"], old["ExecStart"]);
        for (k, v) in &current {
            if k != "ExecStart" {
                assert_eq!(v, &old[k], "{k}");
            }
        }
        assert_eq!(
            native_command(&current["ExecStart"]).unwrap(),
            native_command(&old["ExecStart"]).unwrap()
        );
        let proof = json!({"original_evidence":original});
        terminal_properties(&old, &proof).unwrap();
        terminal_properties(&current, &proof).unwrap();
    }
    #[test]
    fn display_reset_never_accepts_changed_command_or_malformed_suffix_even_when_equal() {
        let original = format!("{NATIVE_COMMAND} ; start_time={ORIGINAL_HISTORY}");
        let reset = format!("{NATIVE_COMMAND} ; start_time={RESET_HISTORY}");
        for bad in [
            original.replace(
                "horizon265-native-input-daa786c0",
                "replacement-native-input",
            ),
            reset.replace("ignore_errors=no", "ignore_errors=yes"),
            reset.replace("argv[]=", "argv[]=--extra "),
            reset.replace("pid=0", "pid=1307638"),
            reset.replace("code=(null)", "code=exited"),
            reset.replace("status=0/0", "status=0"),
            reset.replace("start_time=[n/a]", "start_time=[]"),
            reset.replace("stop_time=[n/a]", "stop_time=[unknown]"),
            format!("{reset} trailing"),
            format!("{reset} ; start_time={RESET_HISTORY}"),
            "unframed".into(),
        ] {
            assert!(native_command(&bad).is_err(), "{bad}");
            let mut m: BTreeMap<String, String> = serde_json::from_value(
                serde_json::from_str::<Value>(include_str!("fixtures/original-terminal.json"))
                    .unwrap()["terminal_manager"]
                    .clone(),
            )
            .unwrap();
            m.insert("ExecStart".into(), bad);
            let proof = json!({"original_evidence":{"terminal_manager":m}});
            assert!(terminal_properties(&m, &proof).is_err());
        }
    }
}
