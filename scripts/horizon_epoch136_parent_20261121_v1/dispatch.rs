//! Consume both file events from a single already-running admission session.
use super::*;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::{Duration, Instant};

fn pidfd(pid: i32) -> Result<OwnedFd> {
    let n = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if n < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(n as i32) })
}

fn wait_event(path: &Path, writer: &OwnedFd, until: Instant) -> Result<()> {
    loop {
        if path.try_exists()? {
            return Ok(());
        }
        let left = until.saturating_duration_since(Instant::now());
        ensure!(
            !left.is_zero(),
            "writer event deadline at {}",
            path.display()
        );
        let mut p = libc::pollfd {
            fd: writer.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ret = unsafe { libc::poll(&mut p, 1, left.as_millis().clamp(1, 400) as i32) };
        if ret < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e.into());
        }
        if ret > 0 {
            ensure!(
                path.try_exists()?,
                "writer exited before {}",
                path.display()
            );
            return Ok(());
        }
    }
}

pub fn run(iid: &str, args: &[String]) -> Result<()> {
    require_iid(&json!(iid))?;
    let (plan, _, package, _) = qualified_package(args)?;
    status::check_registration_environment()?;
    let native_row = native(WRITER)?;
    let pid: i32 = text(&native_row["MainPID"])?.parse()?;
    let owner = pidfd(pid)?;
    let ticks_at_start = ticks(pid)?;
    let cmd = fs::read(proc_path(pid, "cmdline"))?;
    let argv = cmd.split(|b| *b == 0).collect::<Vec<_>>();
    ensure!(
        native_row["InvocationID"] == iid
            && native_row["ActiveState"] == "active"
            && native_row["SubState"] == "running"
            && native_row["ControlGroup"] == format!("/system.slice/{WRITER}")
            && same_inode(&proc_path(pid, "exe"), &package.join("admit136"))?
            && argv.len() == 7
            && argv[1] == b"session"
            && argv[2] == text(&plan["path"])?.as_bytes()
            && argv[3] == text(&plan["sha256"])?.as_bytes()
            && argv[6].is_empty(),
        "expected original writer session"
    );
    wait_event(
        &at("parent-launch-request.json"),
        &owner,
        Instant::now() + Duration::from_secs(45 * 60),
    )?;
    let x = Input::load(args)?;
    ensure!(
        x.request["writer_invocation_id"] == iid
            && x.writer_pid == pid
            && x.writer_ticks == ticks_at_start,
        "writer instance changed before admission"
    );
    actor::launch(&x)?;
    let until = x.request["launch_expires_unix_seconds"]
        .as_u64()
        .context("admission expiry")?;
    let stop = Instant::now() + Duration::from_secs(until.saturating_sub(now()).min(900));
    wait_event(&receipts().join("parent-status-request.json"), &owner, stop)?;
    if let Err(e) = status::register(&x) {
        // If the remote accepted a PUT just before a failure, retain its verified
        // chain even after a writer exits. This recovery never submits a PUT.
        if let Err(r) = status::reconcile() {
            eprintln!("waiting-status recovery: {r:#}");
        }
        return Err(e.context("parent registration"));
    }
    let request = from_ref(&bound(&receipts().join("parent-status-request.json"))?)?;
    let deadline = request["handoff_deadline_unix_seconds"]
        .as_u64()
        .context("release deadline")?;
    let path = receipts().join("parent-release.json");
    wait_event(
        &path,
        &owner,
        Instant::now() + Duration::from_secs(deadline.saturating_sub(now()).min(175)),
    )?;
    let receipt = bound(&path)?;
    let r = immutable(&receipt)?;
    ensure!(
        r["writer_invocation_id"] == iid
            && r["invocation_id"] == request["invocation_id"]
            && r["ready"] == request["ready"]
            && r["launch"] == request["launch"]
            && r["node_spawn_authorized"] == true
            && r["initialize_authorized"] == false
            && r["positive_worker_release_still_required"] == true
            && r["status_registration"]
                == bound(&receipts().join("parent-status-registration.json"))?,
        "writer release is unbound"
    );
    println!(
        "{}",
        json!({"writer_release":receipt,"ordinary_replay_claim":false})
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn existing_files_deadlines_and_dead_writer_have_distinct_results() {
        let live = pidfd(std::process::id() as i32).unwrap();
        assert!(wait_event(Path::new("/proc/self/stat"), &live, Instant::now()).is_ok());
        let missing = Path::new("/proc/self/never-a-writer-event");
        assert!(
            wait_event(missing, &live, Instant::now())
                .unwrap_err()
                .to_string()
                .contains("deadline")
        );
        let mut child = std::process::Command::new("/usr/bin/sleep")
            .arg("5")
            .spawn()
            .unwrap();
        let dead = pidfd(child.id() as i32).unwrap();
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(
            wait_event(missing, &dead, Instant::now() + Duration::from_secs(2))
                .unwrap_err()
                .to_string()
                .contains("exited")
        );
    }
}
