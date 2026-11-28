//! Close only a genuine completed fleet writer's exact output. No JSON rewrite,
//! archive access, /proc FD scan, clock reset, or consumer-integrity exception.
use crate::*;
use std::{
    io::{Read, Seek, SeekFrom},
    os::fd::AsRawFd,
    os::unix::fs::PermissionsExt,
};
const F_SET_SIGNAL: libc::c_int = 10; // Linux F_SETSIG; pinned libc omits this binding.
const FLEET_ROOT: &str = "/var/lib/jetstreamer-horizon-fleet-101-200-20261019-v1";
const CONTROL_PREFIX: &str = "epoch185-positive-upstream-fleet-custody-control-";
const CONTROL_BYTES: &[u8] =
    b"{\"schema\":\"positive185-harmless-completed-fleet-writer-v1\",\"campaign_work\":false}\n";
const LIMIT: u64 = 16 << 20;
fn success(v: &Value) -> Result<()> {
    ensure!(
        v["program"] == "/usr/bin/systemd-run"
            && v["exit_code"] == 0
            && v["exit_signal"].is_null()
            && v["wait_error"].is_null()
            && v["stdout_overflow"] == false
            && v["stderr_overflow"] == false
            && v["stdout_read_error"].is_null()
            && v["stderr_read_error"].is_null()
            && v["cleanup_terminal_code"].is_null()
            && v["cleanup_wait_error"].is_null(),
        "completed fleet requires actual original successful bounded/reaped writer"
    );
    Ok(())
}
fn output_scope(path: &Path, iid: &str) -> Result<()> {
    ensure!(
        storage::hex(iid, 32)
            && path == Path::new(FLEET_ROOT).join(format!("fleet-positive185-original-{iid}.json")),
        "fleet closure cannot target unrelated output or prior owner"
    );
    Ok(())
}
fn terminal(n: &Value, unit: &str, iid: &str) -> Result<()> {
    ensure!(
        n["Id"] == unit
            && n["MainPID"] == "0"
            && n["ControlPID"] == "0"
            && n["NRestarts"] == "0"
            && n["Job"] == ""
            && n["ActiveState"] == "inactive"
            && n["SubState"] == "dead",
        "original fleet child is still running/queued or changed owner"
    );
    match n["LoadState"].as_str() {
        Some("not-found") => ensure!(
            n["InvocationID"] == "",
            "absent fleet child retains unexplained invocation"
        ),
        Some("loaded") => ensure!(
            n["Result"] == "success"
                && n["ExecMainStatus"] == "0"
                && (n["InvocationID"] == iid || n["InvocationID"] == ""),
            "completed fleet native result/IID differs"
        ),
        _ => anyhow::bail!("unknown original fleet native load state"),
    }
    Ok(())
}
fn completed_event(rows: &[Value], unit: &str, started: u64, finished: u64) -> Result<Value> {
    ensure!(
        started <= finished && finished - started <= 65,
        "fleet original writer clock bound"
    );
    let matches = rows
        .iter()
        .filter(|v| {
            v["_PID"] == "1"
                && v["_UID"] == "0"
                && v["UNIT"] == unit
                && v["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448"
                && v["__REALTIME_TIMESTAMP"]
                    .as_str()
                    .and_then(|s| s.parse::<u64>().ok())
                    .is_some_and(|t| (started..=finished).contains(&(t / 1_000_000)))
        })
        .collect::<Vec<_>>();
    ensure!(
        matches.len() == 1
            && matches[0]["INVOCATION_ID"]
                .as_str()
                .is_some_and(|v| storage::hex(v, 32)),
        "one actual PID1 original fleet completion required"
    );
    Ok(matches[0].clone())
}
fn cgroup_empty(unit: &str) -> Result<()> {
    let cg = Path::new("/sys/fs/cgroup/system.slice").join(unit);
    if !cg.try_exists()? {
        return Ok(());
    }
    ensure!(
        fs::symlink_metadata(&cg)?.is_dir(),
        "fleet cgroup is not a directory"
    );
    for e in fs::read_dir(&cg)? {
        ensure!(
            !e?.file_type()?.is_dir(),
            "fleet child delegated cgroup remains"
        );
    }
    ensure!(
        fs::read_to_string(cg.join("cgroup.procs"))?
            .trim()
            .is_empty()
            && fs::read_to_string(cg.join("cgroup.events"))?
                .lines()
                .any(|s| s == "populated 0"),
        "original fleet child cgroup not drained"
    );
    Ok(())
}
struct CompletedWriter {
    evidence: Value,
}
fn completed(
    r: &mut process::Runner<'_>,
    b: &Bound,
    outer: &Value,
    started: u64,
    unit: &str,
    tail: &[String],
) -> Result<CompletedWriter> {
    success(outer)?;
    ensure!(
        outer["original_iid"] == r.iid,
        "fleet outer crossed Root operation"
    );
    let argv: Vec<String> = serde_json::from_value(outer["argv"].clone())?;
    let expected_stdout = format!("{}\n", b.path.display());
    let stdout: Vec<u8> = serde_json::from_value(outer["stdout_bytes"].clone())?;
    ensure!(argv.iter().any(|a|a=="--wait")&&argv.iter().any(|a|a=="--pipe")
        &&argv.iter().any(|a|a=="--service-type=exec")&&argv.ends_with(tail)
        &&argv.windows(2).filter(|v|v[0]=="--unit"&&Some(v[1].as_str())==unit.strip_suffix(".service")).count()==1
        &&stdout==expected_stdout.as_bytes(),"fleet writer command/output differs from exact original plan");
    let finished = n(outer, "wall_finished_at")?;
    ensure!(finished <= now()?, "fleet completion future clock");
    let mut journal = Command::new("/usr/bin/journalctl");
    journal.args(["--all", "--no-pager", "-ojson", "-u", unit]);
    let raw = r.run(
        "completed-fleet-original-PID1",
        journal,
        Duration::from_secs(5),
    )?;
    let bytes: Vec<u8> = serde_json::from_value(raw["stdout_bytes"].clone())?;
    let rows = std::str::from_utf8(&bytes)?
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let event = completed_event(&rows, unit, started, finished)?;
    let iid = text(&event, "INVOCATION_ID")?;
    let native = r.native(unit)?;
    terminal(&native, unit, iid)?;
    cgroup_empty(unit)?;
    Ok(CompletedWriter {
        evidence: json!({"unit":unit,"invocation_id":iid,"actual_outer":outer,
        "original_PID1_completion":event,"native_terminal":native,"all_original_processes_and_cgroups_drained":true,
        "original_start":started,"original_finish":finished,"no_retry_or_clock_renewal":true}),
    })
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct Identity {
    dev: u64,
    ino: u64,
    len: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    links: u64,
    mtime: i64,
    mtime_ns: i64,
    ctime: i64,
    ctime_ns: i64,
}
fn id(m: &fs::Metadata) -> Identity {
    Identity {
        dev: m.dev(),
        ino: m.ino(),
        len: m.len(),
        uid: m.uid(),
        gid: m.gid(),
        mode: m.mode(),
        links: m.nlink(),
        mtime: m.mtime(),
        mtime_ns: m.mtime_nsec(),
        ctime: m.ctime(),
        ctime_ns: m.ctime_nsec(),
    }
}
fn original_file(m: &Identity, regular: bool) -> Result<()> {
    ensure!(
        regular
            && m.uid == 0
            && m.gid == 0
            && m.links == 1
            && m.len > 0
            && m.len <= LIMIT
            && m.mode & 0o7777 == 0o600,
        "completed fleet must be exact Root0600 one-link bounded regular output"
    );
    Ok(())
}
fn unchanged_content(a: &Identity, b: &Identity) -> Result<()> {
    ensure!(
        a.dev == b.dev
            && a.ino == b.ino
            && a.len == b.len
            && a.uid == b.uid
            && a.gid == b.gid
            && a.links == b.links
            && a.mtime == b.mtime
            && a.mtime_ns == b.mtime_ns
            && b.mode & 0o7777 == 0o444,
        "fleet closure changed bytes/inode/ownership/mtime beyond intended readonly mode"
    );
    Ok(())
}
// A read lease is a kernel-wide proof that no writable FD/mapping survives. It
// also blocks a new writer during chmod/hash/fsync. SIGIO is blocked only on
// this thread and addressed to its TID; any break request rejects the closure.
// No /proc descriptor census can touch protected199.
struct ReadLease<'a> {
    file: &'a fs::File,
    signal_fd: i32,
    old_mask: libc::sigset_t,
    held: bool,
}
#[repr(C)]
struct FileOwner {
    kind: libc::c_int,
    pid: libc::pid_t,
}
impl<'a> ReadLease<'a> {
    fn acquire(file: &'a fs::File) -> Result<Self> {
        let mut set = unsafe { std::mem::zeroed::<libc::sigset_t>() };
        let mut old = unsafe { std::mem::zeroed::<libc::sigset_t>() };
        ensure!(
            unsafe { libc::sigemptyset(&mut set) } == 0
                && unsafe { libc::sigaddset(&mut set, libc::SIGIO) } == 0,
            "fleet lease signal set"
        );
        let mut pending = unsafe { std::mem::zeroed::<libc::sigset_t>() };
        ensure!(
            unsafe { libc::sigpending(&mut pending) } == 0
                && unsafe { libc::sigismember(&pending, libc::SIGIO) } == 0,
            "preexisting SIGIO outside fleet closure"
        );
        ensure!(
            unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &set, &mut old) } == 0,
            "fleet lease signal mask"
        );
        let signal_fd = unsafe { libc::signalfd(-1, &set, libc::SFD_CLOEXEC | libc::SFD_NONBLOCK) };
        if signal_fd < 0 {
            unsafe {
                libc::pthread_sigmask(libc::SIG_SETMASK, &old, std::ptr::null_mut());
            }
            return Err(std::io::Error::last_os_error()).context("fleet lease signalfd");
        }
        let mut lease = Self {
            file,
            signal_fd,
            old_mask: old,
            held: false,
        };
        let owner = FileOwner {
            kind: 0,
            pid: unsafe { libc::syscall(libc::SYS_gettid) as libc::pid_t },
        };
        ensure!(
            unsafe { libc::fcntl(file.as_raw_fd(), 15, &owner) } == 0,
            "fleet lease F_SETOWN_EX/TID"
        );
        ensure!(
            unsafe { libc::fcntl(file.as_raw_fd(), F_SET_SIGNAL, libc::SIGIO) } == 0,
            "fleet lease SIGIO binding"
        );
        let status = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETLEASE, libc::F_RDLCK) };
        if status < 0 {
            return Err(std::io::Error::last_os_error())
                .context("fleet still writable or filesystem cannot authenticate read lease");
        }
        lease.held = true;
        lease.intact()?;
        Ok(lease)
    }
    fn intact(&self) -> Result<()> {
        ensure!(
            unsafe { libc::fcntl(self.file.as_raw_fd(), libc::F_GETLEASE) } == libc::F_RDLCK,
            "fleet read lease was broken/requested"
        );
        let mut event = unsafe { std::mem::zeroed::<libc::signalfd_siginfo>() };
        let count = unsafe {
            libc::read(
                self.signal_fd,
                (&mut event as *mut libc::signalfd_siginfo).cast(),
                std::mem::size_of_val(&event),
            )
        };
        ensure!(
            count < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::WouldBlock,
            "fleet writer requested lease break"
        );
        Ok(())
    }
}
impl Drop for ReadLease<'_> {
    fn drop(&mut self) {
        if self.held {
            unsafe {
                libc::fcntl(self.file.as_raw_fd(), libc::F_SETLEASE, libc::F_UNLCK);
            }
        }
        let mut event = unsafe { std::mem::zeroed::<libc::signalfd_siginfo>() };
        while unsafe {
            libc::read(
                self.signal_fd,
                (&mut event as *mut libc::signalfd_siginfo).cast(),
                std::mem::size_of_val(&event),
            )
        } > 0
        {}
        unsafe {
            libc::close(self.signal_fd);
            libc::pthread_sigmask(libc::SIG_SETMASK, &self.old_mask, std::ptr::null_mut());
        }
    }
}
fn read_exact(file: &fs::File, len: u64) -> Result<Vec<u8>> {
    let mut source = file;
    source.seek(SeekFrom::Start(0))?;
    let mut raw = Vec::new();
    Read::by_ref(&mut source)
        .take(LIMIT + 1)
        .read_to_end(&mut raw)?;
    ensure!(raw.len() as u64 == len, "fleet output length raced");
    Ok(raw)
}
fn close_file(b: &Bound) -> Result<Value> {
    deny_original199(&b.path)?;
    ensure!(
        b.path.is_absolute() && b.path.canonicalize()? == b.path && storage::hex(&b.sha256, 64),
        "fleet close exact no-symlink binding"
    );
    let parent = b.path.parent().context("fleet parent")?;
    let pm = fs::symlink_metadata(parent)?;
    ensure!(
        pm.is_dir() && pm.uid() == 0 && pm.mode() & 0o022 == 0,
        "fleet parent custody"
    );
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(&b.path)?;
    let before_m = file.metadata()?;
    let before = id(&before_m);
    original_file(&before, before_m.is_file())?;
    let lease = ReadLease::acquire(&file)?;
    let raw = read_exact(&file, before.len)?;
    ensure!(
        storage::sha(&raw) == b.sha256
            && id(&file.metadata()?) == before
            && id(&fs::symlink_metadata(&b.path)?) == before,
        "completed fleet original digest/identity changed before closure"
    );
    lease.intact()?;
    file.set_permissions(fs::Permissions::from_mode(0o444))?;
    file.sync_all()?;
    let after = id(&file.metadata()?);
    unchanged_content(&before, &after)?;
    ensure!(
        read_exact(&file, after.len)? == raw
            && id(&file.metadata()?) == after
            && id(&fs::symlink_metadata(&b.path)?) == after,
        "completed fleet changed during readonly transition"
    );
    lease.intact()?;
    drop(lease);
    drop(file);
    fs::File::open(parent)?.sync_all()?;
    ensure!(
        id(&fs::symlink_metadata(&b.path)?) == after && storage::bytes(b, LIMIT, true)? == raw,
        "closed fleet final custody/bytes changed"
    );
    Ok(
        json!({"schema":"horizon-positive185-enrolled-fleet-readonly-closure-v1","fleet":b,"before":before,"after":after,
        "kernel_read_lease_authenticated_no_writable_descriptors_or_mappings":true,"no_lease_break_request":true,
        "file_and_parent_fsynced":true,"closure_descriptors_closed_before_consumer":true,"bytes_preserved_exactly":true,
        "new_fleet_or_archive_integrity_not_claimed":true,"resource_credit_bytes":0,"publication_authorized":false}),
    )
}
pub(super) fn complete_enrolled(
    r: &mut process::Runner<'_>,
    b: &Bound,
    plan: &Bound,
    iid: &str,
    outer: &Value,
    started: u64,
) -> Result<()> {
    output_scope(&b.path, iid)?;
    let p = storage::json(plan)?;
    ensure!(
        p["output"] == json!(b.path)
            && p["epoch185_cold_startpre_registration"]["path"]
                == Path::new(REGISTRY)
                    .join(iid)
                    .join("registration.json")
                    .display()
                    .to_string(),
        "fleet closure crosses genuine enrolled plan"
    );
    let tail = vec![
        FLEET_HELPER.into(),
        "fleet-reconcile".into(),
        plan.path.display().to_string(),
        "--plan-sha256".into(),
        plan.sha256.clone(),
    ];
    let unit = format!("horizon-positive185-upstream-{}-fleet.service", r.iid);
    let completed = completed(r, b, outer, started, &unit, &tail)?;
    ensure!(
        Instant::now() < r.deadline.min(r.pool_deadline),
        "original fleet closure deadline exhausted"
    );
    let closure = close_file(b)?;
    ensure!(
        Instant::now() < r.deadline.min(r.pool_deadline),
        "original setup budget consumed by fleet closure"
    );
    storage::save(
        r.root,
        "enrolled-fleet-completed-writer-closure.json",
        &json!({"writer":completed.evidence,"closure":closure,"operation":r.self_image,
        "original_setup_clock_not_renewed":true,"earlier_failed_namespaces_preserved":true}),
    )?;
    Ok(())
}
fn control_root(root: &Path) -> Result<()> {
    ensure!(
        root.parent() == Some(Path::new("/home/sol/.jetstreamer-private"))
            && root
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with(CONTROL_PREFIX)),
        "fleet custody harmless control root only"
    );
    private(root, false)
}
pub(super) fn harmless_writer(spec: &Bound, own: &Bound) -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "Root-only harmless fleet writer"
    );
    let v = storage::json(spec)?;
    ensure!(
        v["schema"] == "horizon-positive185-fleet-custody-harmless-writer-v1"
            && v["candidate"] == json!(own)
            && v.as_object().is_some_and(|v| v.len() == 3),
        "harmless fleet writer exact schema/image"
    );
    let output = PathBuf::from(text(&v, "output")?);
    control_root(output.parent().context("control output parent")?)?;
    ensure!(
        output.file_name().and_then(|s| s.to_str()) == Some("actual-completed-writer-fleet.json"),
        "harmless writer exact output leaf"
    );
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&output)?;
    file.write_all(CONTROL_BYTES)?;
    file.sync_all()?;
    drop(file);
    fs::File::open(output.parent().context("control parent")?)?.sync_all()?;
    println!("{}", output.display());
    Ok(())
}
pub(super) fn qualify(r: &mut process::Runner<'_>) -> Result<()> {
    control_root(r.root)?;
    let output = r.root.join("actual-completed-writer-fleet.json");
    let spec = storage::save(
        r.root,
        "harmless-completed-writer-spec.json",
        &json!({"schema":"horizon-positive185-fleet-custody-harmless-writer-v1","candidate":r.self_image,"output":output}),
    )?;
    let unitbase = format!("horizon-positive185-fleet-custody-control-{}", r.iid);
    let unit = format!("{unitbase}.service");
    let tail = vec![
        r.self_image.path.display().to_string(),
        "fleet-custody-harmless-writer".into(),
        spec.path.display().to_string(),
        "--request-sha256".into(),
        spec.sha256.clone(),
        "--self-sha256".into(),
        r.self_image.sha256.clone(),
    ];
    let mut command = Command::new("/usr/bin/systemd-run");
    command.args([
        "--wait",
        "--pipe",
        "--service-type=exec",
        "--unit",
        &unitbase,
    ]);
    for p in [
        "User=root",
        "Group=root",
        "Restart=no",
        "UMask=0077",
        "MemoryMax=64M",
        "MemorySwapMax=0",
        "CPUQuota=100%",
        "TasksMax=16",
        "RuntimeMaxSec=10",
        "TimeoutStopSec=1",
        "KillMode=control-group",
        "NoNewPrivileges=yes",
        "PrivateNetwork=yes",
        "CapabilityBoundingSet=CAP_DAC_OVERRIDE",
        "AmbientCapabilities=CAP_DAC_OVERRIDE",
    ] {
        command.arg(format!("--property={p}"));
    }
    command.args(&tail);
    let started = now()?;
    let outer = r.run(
        "harmless-original-fleet-writer",
        command,
        Duration::from_secs(15),
    )?;
    let b = process::bind_file(&output, LIMIT)?;
    let completed = completed(r, &b, &outer, started, &unit, &tail)?;
    let actual = close_file(&b)?;
    ensure!(
        storage::bytes(&b, LIMIT, true)? == CONTROL_BYTES,
        "native fleet closure changed original control bytes"
    );
    // Genuine regressions use only new files in this booked control namespace.
    let negative = r.root.join("actual-rejection-fixtures");
    fs::DirBuilder::new().mode(0o700).create(&negative)?;
    let mut rejected = serde_json::Map::new();
    for case in ["wrong-digest", "live-writable-fd", "hard-link"] {
        let path = negative.join(format!("{case}.json"));
        let mut writer = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        writer.write_all(CONTROL_BYTES)?;
        writer.sync_all()?;
        let bound = Bound {
            path: path.clone(),
            sha256: if case == "wrong-digest" {
                "0".repeat(64)
            } else {
                storage::sha(CONTROL_BYTES)
            },
        };
        let outcome = if case == "live-writable-fd" {
            close_file(&bound)
        } else {
            drop(writer);
            if case == "hard-link" {
                fs::hard_link(&path, negative.join("retained-hard-link.json"))?;
            }
            close_file(&bound)
        };
        ensure!(
            outcome.is_err() && fs::symlink_metadata(&path)?.mode() & 0o7777 == 0o600,
            "native fleet rejection mutated wrong input"
        );
        rejected.insert(case.into(),json!({"rejected":true,"original_mode_preserved":true,"original_bytes_preserved":fs::read(&path)?==CONTROL_BYTES}));
    }
    let proof = storage::save(
        r.root,
        "actual-enrolled-fleet-custody-control.json",
        &json!({"schema":"horizon-positive185-completed-fleet-custody-native-control-v1",
        "program":r.self_image,"actual_completed_writer":completed.evidence,"actual_readonly_closure":actual,"actual_rejections":rejected,
        "production_completed_writer_and_kernel_lease_primitive_exercised":true,"all_control_outputs_preserved":true,
        "campaign_mutations":false,"replay_launch_authorized":false,"publication_authorized":false,"resource_credit_bytes":0}),
    )?;
    println!(
        "{}",
        json!({"actual_completed_fleet_custody_control":proof})
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn meta() -> Identity {
        Identity {
            dev: 1,
            ino: 2,
            len: 100,
            uid: 0,
            gid: 0,
            mode: 0o100600,
            links: 1,
            mtime: 10,
            mtime_ns: 11,
            ctime: 12,
            ctime_ns: 13,
        }
    }
    #[test]
    fn output_closure_rejects_unrelated_epoch_owner_and_protected_paths() {
        let iid = "a".repeat(32);
        output_scope(
            &Path::new(FLEET_ROOT).join(format!("fleet-positive185-original-{iid}.json")),
            &iid,
        )
        .unwrap();
        for path in [
            "/tmp/fleet.json",
            "/var/lib/other/fleet.json",
            "/var/lib/jetstreamer-horizon-fleet-101-200-20261019-v1/fleet-positive185-original-foreign.json",
        ] {
            assert!(output_scope(Path::new(path), &iid).is_err());
        }
        assert!(output_scope(Path::new(FLEET_ROOT), "../foreign").is_err());
    }
    #[test]
    fn completed_file_requires_private_root_single_link_regular_and_bounded() {
        let m = meta();
        original_file(&m, true).unwrap();
        assert!(original_file(&m, false).is_err());
        for field in 0..7 {
            let mut b = m.clone();
            match field {
                0 => b.uid = 1001,
                1 => b.gid = 1003,
                2 => b.links = 2,
                3 => b.len = 0,
                4 => b.len = LIMIT + 1,
                5 => b.mode = 0o100644,
                _ => b.mode = 0o100444,
            };
            assert!(original_file(&b, true).is_err(), "{field}");
        }
    }
    #[test]
    fn readonly_transition_cannot_change_inode_bytes_owner_or_mtime() {
        let before = meta();
        let mut after = before.clone();
        after.mode = 0o100444;
        after.ctime += 1;
        unchanged_content(&before, &after).unwrap();
        for field in 0..8 {
            let mut b = after.clone();
            match field {
                0 => b.dev += 1,
                1 => b.ino += 1,
                2 => b.len += 1,
                3 => b.uid = 1001,
                4 => b.gid = 1003,
                5 => b.links += 1,
                6 => b.mtime += 1,
                _ => b.mode = 0o100600,
            };
            assert!(unchanged_content(&before, &b).is_err(), "{field}");
        }
    }
    #[test]
    fn writer_terminal_gate_rejects_live_queued_failed_or_crossed_native() {
        let u = "horizon-positive185-upstream-fixture-fleet.service";
        let iid = "a".repeat(32);
        let n = json!({"Id":u,"InvocationID":iid,"MainPID":"0","ControlPID":"0","NRestarts":"0","Job":"","ActiveState":"inactive","SubState":"dead","LoadState":"loaded","Result":"success","ExecMainStatus":"0"});
        terminal(&n, u, &iid).unwrap();
        for (k, v) in [
            ("MainPID", "12"),
            ("ControlPID", "12"),
            ("Job", "1"),
            ("NRestarts", "1"),
            ("Result", "exit-code"),
            ("InvocationID", "foreign"),
        ] {
            let mut bad = n.clone();
            bad[k] = json!(v);
            assert!(terminal(&bad, u, &iid).is_err(), "{k}");
        }
    }
    #[test]
    fn native_completion_cannot_borrow_other_owner_or_duplicate_old_event() {
        let u = "horizon-positive185-upstream-fixture-fleet.service";
        let row = json!({"_PID":"1","_UID":"0","UNIT":u,"MESSAGE_ID":"7ad2d189f7e94e70a38c781354912448","INVOCATION_ID":"a".repeat(32),"__REALTIME_TIMESTAMP":"1001000000"});
        completed_event(std::slice::from_ref(&row), u, 1000, 1002).unwrap();
        assert!(completed_event(&[row.clone(), row.clone()], u, 1000, 1002).is_err());
        assert!(
            completed_event(std::slice::from_ref(&row), "foreign.service", 1000, 1002).is_err()
        );
        assert!(completed_event(&[row], u, 1100, 1102).is_err());
    }
    #[test]
    fn successful_outer_must_be_original_bounded_writer_not_partial_or_failed() {
        let v = json!({"program":"/usr/bin/systemd-run","exit_code":0,"exit_signal":null,"wait_error":null,"stdout_overflow":false,"stderr_overflow":false,"stdout_read_error":null,"stderr_read_error":null,"cleanup_terminal_code":null,"cleanup_wait_error":null});
        success(&v).unwrap();
        for (k, x) in [
            ("exit_code", json!(1)),
            ("stdout_overflow", json!(true)),
            ("wait_error", json!("timeout")),
            ("program", json!("/bin/false")),
        ] {
            let mut bad = v.clone();
            bad[k] = x;
            assert!(success(&bad).is_err(), "{k}");
        }
    }
}
