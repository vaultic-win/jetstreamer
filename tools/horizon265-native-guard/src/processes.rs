//! Exact cgroup membership plus mapped-image and start-time binding, no name matching.
use super::*;
use std::io::{BufRead, BufReader};

pub(super) fn stat(proc_root: &Path, pid: u32) -> Result<(u32, u64)> {
    let s = fs::read_to_string(proc_root.join(pid.to_string()).join("stat"))?;
    let (first, tail) = s.rsplit_once(')').context("stat comm")?;
    ensure!(
        first.split_whitespace().next() == Some(pid.to_string().as_str()),
        "stat pid differs"
    );
    let fields: Vec<_> = tail.split_whitespace().collect();
    ensure!(fields.len() >= 20, "truncated proc stat");
    let parent = fields[1].parse()?;
    let start = fields[19].parse()?;
    ensure!(start > 0, "missing start ticks");
    Ok((parent, start))
}
fn pids_at(root: &Path) -> Result<Vec<u32>> {
    let m = fs::symlink_metadata(root)?;
    ensure!(
        m.is_dir() && !m.file_type().is_symlink(),
        "unsafe cgroup directory"
    );
    // Delegate=no: even an empty nested cgroup is outside this closed profile.
    for entry in fs::read_dir(root)? {
        let e = entry?;
        ensure!(!e.file_type()?.is_dir(), "unexpected nested cgroup");
    }
    let b = fs::read_to_string(root.join("cgroup.procs"))?;
    ensure!(b.len() <= 4096, "cgroup PID census too large");
    let mut pids: Vec<u32> = b
        .lines()
        .map(str::parse)
        .collect::<std::result::Result<_, _>>()?;
    ensure!(pids.iter().all(|p| *p > 1), "invalid cgroup PID");
    pids.sort_unstable();
    ensure!(
        !pids.windows(2).any(|w| w[0] == w[1]),
        "duplicate cgroup process"
    );
    Ok(pids)
}
fn membership(pids: &[u32], main: u32, token: bool) -> Result<Option<u32>> {
    ensure!(
        pids.len() == 1 || (token && pids.len() == 2),
        "unexpected process count or child before first-guard token"
    );
    ensure!(pids.contains(&main), "missing harness process");
    Ok(pids.iter().copied().find(|p| *p != main))
}
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
#[serde(deny_unknown_fields)]
struct Pin {
    pid: u32,
    parent_pid: u32,
    start_ticks: u64,
    boot_id: String,
    executable: PathBuf,
    sha256: String,
    device: u64,
    inode: u64,
    bytes: u64,
    uid: u32,
    mode: u32,
    nlink: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
}
fn artifact_matches(expected: &fs::Metadata, mapped: &fs::Metadata) -> bool {
    metadata_id(expected) == metadata_id(mapped)
}
fn observe_one(
    proc_root: &Path,
    pid: u32,
    exe: &str,
    digest: &str,
    boot: &str,
) -> Result<(Pin, u64)> {
    let path = Path::new(exe);
    trusted_parents(path)?;
    let expected = fs::symlink_metadata(path)?;
    ensure!(
        expected.is_file()
            && expected.uid() == 0
            && expected.nlink() == 1
            && expected.mode() & 0o222 == 0
            && expected.len() <= 64 << 20,
        "unsafe selected executable"
    );
    let root = proc_root.join(pid.to_string());
    let initial = stat(proc_root, pid)?;
    ensure!(
        fs::read_link(root.join("exe"))? == path,
        "foreign/deleted mapped image"
    );
    ensure!(
        fs::read_to_string(root.join("cgroup"))?.trim() == format!("0::/system.slice/{UNIT}"),
        "process escaped cgroup"
    );
    let status = fs::read_to_string(root.join("status"))?;
    for k in ["Uid:", "Gid:"] {
        let row = status
            .lines()
            .find_map(|line| line.strip_prefix(k))
            .context("process identity")?;
        let values: Vec<u32> = row
            .split_whitespace()
            .map(str::parse)
            .collect::<std::result::Result<_, _>>()?;
        ensure!(values == vec![1000; 4], "process uid/gid differs");
    }
    ensure!(
        status.lines().any(|s| s
            .strip_prefix("CapEff:")
            .is_some_and(|v| v.trim() == "0000000000000000"))
            && status.lines().any(|s| s
                .strip_prefix("NoNewPrivs:")
                .is_some_and(|v| v.trim() == "1")),
        "process effective capabilities or NoNewPrivileges changed"
    );
    let mut f = File::open(root.join("exe"))?;
    ensure!(
        artifact_matches(&expected, &f.metadata()?),
        "mapped inode differs"
    );
    let mut h = Sha256::new();
    let mut buf = [0; 65536];
    let mut count = 0u64;
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        count += n as u64;
        ensure!(count <= 64 << 20, "mapped image bound");
        h.update(&buf[..n]);
    }
    ensure!(
        count == expected.len() && format!("{:x}", h.finalize()) == digest,
        "mapped executable digest differs"
    );
    let mut reader = BufReader::new(File::open(root.join("maps"))?);
    let mut line = String::new();
    let mut vmas = 0u64;
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        vmas += 1;
        ensure!(line.len() <= 16384 && vmas < VMAS, "VMA bound exceeded");
    }
    ensure!(vmas > 0, "empty process maps");
    ensure!(
        initial == stat(proc_root, pid)?
            && artifact_matches(&expected, &f.metadata()?)
            && artifact_matches(&expected, &fs::symlink_metadata(path)?)
            && fs::read_link(root.join("exe"))? == path
            && fs::read_to_string(root.join("cgroup"))?.trim()
                == format!("0::/system.slice/{UNIT}"),
        "process changed during observation"
    );
    Ok((
        Pin {
            pid,
            parent_pid: initial.0,
            start_ticks: initial.1,
            boot_id: boot.into(),
            executable: path.into(),
            sha256: digest.into(),
            device: expected.dev(),
            inode: expected.ino(),
            bytes: expected.len(),
            uid: expected.uid(),
            mode: expected.mode(),
            nlink: expected.nlink(),
            mtime: expected.mtime(),
            mtime_nsec: expected.mtime_nsec(),
            ctime: expected.ctime(),
            ctime_nsec: expected.ctime_nsec(),
        },
        vmas,
    ))
}
fn pin_envelope(p: &Plan, plan_sha: &str, kind: &str, pin: &Pin) -> Value {
    json!({"schema":PROCESS_PIN,"kind":kind,"plan_sha256":plan_sha,"producer_invocation_id":p.invocation_id,"pin":pin,"remote_mutations":false})
}
fn retain(p: &Plan, plan_sha: &str, kind: &str, pin: &Pin) -> Result<()> {
    let path = p.receipt_directory.join(format!("{kind}-pin.json"));
    let v = pin_envelope(p, plan_sha, kind, pin);
    match prior(&path)? {
        Some(old) => ensure!(old == v, "{kind} process image/identity changed"),
        None => persist(&path, &v)?,
    }
    Ok(())
}
fn known(p: &Plan, plan_sha: &str, kind: &str) -> Result<Option<Pin>> {
    let Some(v) = prior(&p.receipt_directory.join(format!("{kind}-pin.json")))? else {
        return Ok(None);
    };
    let pin: Pin = serde_json::from_value(v["pin"].clone())?;
    ensure!(
        v == pin_envelope(p, plan_sha, kind, &pin),
        "foreign process pin"
    );
    Ok(Some(pin))
}
pub(super) fn observe(p: &Plan, plan_sha: &str, has_token: bool) -> Result<Value> {
    ensure!(boot()? == p.boot_id, "boot changed");
    for _ in 0..3 {
        let ids = pids_at(&cgroup())?;
        let child = membership(&ids, p.native_main.main_pid, has_token)?;
        let (main, mv) = observe_one(
            Path::new(PROCS),
            p.native_main.main_pid,
            HARNESS,
            HARNESS_SHA,
            &p.boot_id,
        )?;
        ensure!(
            main.start_ticks == p.main_start_ticks && main.parent_pid == 1,
            "main start/parent differs"
        );
        retain(p, plan_sha, "main", &main)?;
        let mut workers = vec![(main.pid, mv)];
        let mut pins = vec![main];
        if let Some(pid) = child {
            let observed = observe_one(Path::new(PROCS), pid, WORKER, WORKER_SHA, &p.boot_id);
            let (worker, wv) = match observed {
                Ok(v) => v,
                Err(e)
                    if e.downcast_ref::<std::io::Error>()
                        .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound)
                        && !pids_at(&cgroup())?.contains(&pid) =>
                {
                    continue;
                }
                Err(e) => return Err(e),
            };
            ensure!(
                worker.parent_pid == p.native_main.main_pid
                    && worker.start_ticks >= p.main_start_ticks,
                "worker is not direct child of exact harness"
            );
            retain(p, plan_sha, "worker", &worker)?;
            workers.push((pid, wv));
            pins.push(worker);
        } else if let Some(old) = known(p, plan_sha, "worker")? {
            // cgroup.procs can drop an exiting child before the harness reaps it.
            // A live process outside the cgroup still trips the guard immediately.
            exited_worker_reaped(old.pid, old.parent_pid, old.start_ticks)?;
        }
        if ids == pids_at(&cgroup())? {
            ensure!(boot()? == p.boot_id, "boot changed during sample");
            return Ok(
                json!({"workers":workers,"processes":pins,"token_present":has_token,"boot_id":p.boot_id,"stable_census":true}),
            );
        }
    }
    bail!("cgroup membership did not stabilize within bounded observation")
}
fn process_identity(pid: u32) -> Result<Option<(u32, u64)>> {
    match stat(Path::new(PROCS), pid) {
        Ok(identity) => Ok(Some(identity)),
        Err(e)
            if e.downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
        {
            Ok(None)
        }
        Err(e) => Err(e),
    }
}

fn exited_worker_reaped(pid: u32, parent: u32, start: u64) -> Result<()> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::time::{Duration, Instant};

    // Bind the pidfd before reading /proc so a recycled PID cannot supply the
    // exit event for a still-live original worker.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
    if fd < 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ESRCH) {
            return Ok(());
        }
        return Err(err.into());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let deadline = Instant::now() + Duration::from_millis(500);
    loop {
        let Some((actual_parent, ticks)) = process_identity(pid)? else {
            return Ok(());
        };
        if ticks != start {
            return Ok(());
        }
        ensure!(
            actual_parent == parent,
            "missing worker {pid} changed parent to {actual_parent}"
        );
        let mut poll = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut poll, 1, 0) };
        if ready < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        ensure!(
            ready == 1 && poll.revents & libc::POLLIN != 0,
            "pinned live worker {pid} absent from cgroup (start ticks {start})"
        );
        ensure!(
            Instant::now() < deadline,
            "exited worker {pid} still unreaped after 500 ms"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn gone(pin: &Pin) -> Result<()> {
    ensure!(
        process_identity(pin.pid)?.is_none_or(|(_, ticks)| ticks != pin.start_ticks),
        "original process still exists, possibly escaped cgroup"
    );
    Ok(())
}
pub(super) fn drain(p: &Plan, plan_sha: &str) -> Result<Value> {
    let kernel = match fs::symlink_metadata(cgroup()) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => "absent",
        Err(e) => return Err(e.into()),
        Ok(_) => {
            ensure!(
                pids_at(&cgroup())?.is_empty(),
                "terminal cgroup has processes"
            );
            let events = fs::read_to_string(cgroup().join("cgroup.events"))?;
            ensure!(
                events.lines().any(|s| s == "populated 0"),
                "terminal cgroup populated"
            );
            "empty"
        }
    };
    // Even if the first observation failed before publishing a pin, the plan
    // supplies the exact harness PID/start-time required to exclude escape.
    match stat(Path::new(PROCS), p.native_main.main_pid) {
        Ok((_, ticks)) => ensure!(ticks != p.main_start_ticks, "terminal harness still exists"),
        Err(e)
            if e.downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) => {}
        Err(e) => return Err(e),
    }
    let mut pins = Vec::new();
    for kind in ["main", "worker"] {
        if let Some(pin) = known(p, plan_sha, kind)? {
            gone(&pin)?;
            pins.push(pin);
        }
    }
    ensure!(boot()? == p.boot_id, "terminal boot changed");
    Ok(
        json!({"kernel_cgroup":kernel,"original_processes_gone":true,"retained_process_pins":pins,"resource_release_authorized":false}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn before_token_is_harness_only_and_after_token_is_at_most_one_child() {
        assert_eq!(membership(&[42], 42, false).unwrap(), None);
        assert!(membership(&[42, 43], 42, false).is_err());
        assert_eq!(membership(&[42, 43], 42, true).unwrap(), Some(43));
        for pids in [vec![], vec![43], vec![42, 43, 44]] {
            assert!(membership(&pids, 42, true).is_err());
        }
    }
    #[test]
    fn missing_child_must_exit_and_be_reaped() {
        use std::process::Command;
        use std::time::Duration;
        let mut child = Command::new("/usr/bin/sleep").arg("30").spawn().unwrap();
        let pid = child.id();
        let (parent, start) = stat(Path::new(PROCS), pid).unwrap();
        assert!(exited_worker_reaped(pid, parent, start).is_err());
        let unit = fs::read_to_string(format!("/proc/{pid}/cgroup")).unwrap();
        let group = Path::new("/sys/fs/cgroup").join(unit.trim().strip_prefix("0::/").unwrap());
        assert!(
            fs::read_to_string(group.join("cgroup.procs"))
                .unwrap()
                .lines()
                .any(|line| line == pid.to_string())
        );
        child.kill().unwrap();
        // waitid(WNOWAIT) guarantees the pinned child is a zombie while its
        // parent still owns the wait status.
        let mut info = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::waitid(libc::P_PID, pid, &mut info, libc::WEXITED | libc::WNOWAIT) },
            0
        );
        let members = fs::read_to_string(group.join("cgroup.procs")).unwrap();
        assert!(!members.lines().any(|line| line == pid.to_string()));
        assert!(exited_worker_reaped(pid, parent, start).is_err());
        let reaper = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(30));
            child.wait().unwrap();
        });
        exited_worker_reaped(pid, parent, start).unwrap();
        reaper.join().unwrap();
    }

    #[test]
    fn proc_stat_handles_spaces_and_parentheses_in_comm_and_binds_pid() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("42");
        fs::create_dir(&path).unwrap();
        let mut fields = vec!["0"; 20];
        fields[0] = "S";
        fields[1] = "1";
        fields[19] = "123";
        fs::write(
            path.join("stat"),
            format!("42 (name with ) parens) {}", fields.join(" ")),
        )
        .unwrap();
        assert_eq!(stat(d.path(), 42).unwrap(), (1, 123));
        fs::write(path.join("stat"), "43 (foreign) S 1").unwrap();
        assert!(stat(d.path(), 42).is_err());
    }
    #[test]
    fn cgroup_refuses_nested_missing_or_invalid_membership() {
        let d = tempfile::tempdir().unwrap();
        fs::write(d.path().join("cgroup.procs"), "42\n43\n").unwrap();
        assert_eq!(pids_at(d.path()).unwrap(), vec![42, 43]);
        fs::create_dir(d.path().join("nested")).unwrap();
        assert!(pids_at(d.path()).is_err());
        fs::remove_dir(d.path().join("nested")).unwrap();
        fs::write(d.path().join("cgroup.procs"), "42\n42\n").unwrap();
        assert!(pids_at(d.path()).is_err());
    }
    #[test]
    fn mapped_identity_rejects_replacement_inode_and_changed_bytes_metadata() {
        let d = tempfile::tempdir().unwrap();
        let a = d.path().join("a");
        let b = d.path().join("b");
        fs::write(&a, b"image").unwrap();
        fs::write(&b, b"image").unwrap();
        let original = fs::metadata(&a).unwrap();
        assert!(artifact_matches(&original, &fs::metadata(&a).unwrap()));
        assert!(!artifact_matches(&original, &fs::metadata(&b).unwrap()));
        fs::write(&a, b"changed image").unwrap();
        assert!(!artifact_matches(&original, &fs::metadata(&a).unwrap()));
    }
}
