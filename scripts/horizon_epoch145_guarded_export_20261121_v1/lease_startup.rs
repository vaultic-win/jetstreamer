//! Rendezvous before the frozen epoch 145 worker's first archive read.
use std::{
    io,
    process::Child,
    time::{Duration, Instant},
};

pub(crate) fn stop_after_leases() -> io::Result<()> {
    if unsafe { libc::raise(libc::SIGSTOP) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(super) fn wait_for_lease_stop(child: &Child, deadline: Instant) -> io::Result<()> {
    loop {
        // An exit remains waitable by Child. Only a real SIGSTOP on this
        // still-unreaped direct child is a candidate for the full lease census.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            libc::waitid(
                libc::P_PID,
                child.id(),
                &mut info,
                libc::WSTOPPED | libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if rc == -1 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        } else if unsafe { info.si_pid() } != 0 {
            if info.si_code == libc::CLD_STOPPED && unsafe { info.si_status() } == libc::SIGSTOP {
                return Ok(());
            }
            return Err(io::Error::other(
                "recovery worker exited or changed state before lease readiness",
            ));
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "waiting for recovery worker's lease-ready stop",
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(all(test, incident_lease_start145_only))]
mod tests {
    use super::*;
    use std::{fs, process::Command};

    #[test]
    fn worker_stop_fixture() {
        let Some(marker) = std::env::var_os("EPOCH145_STARTUP_TEST_MARKER") else {
            return;
        };
        stop_after_leases().unwrap();
        fs::write(marker, b"resumed").unwrap();
    }

    #[test]
    fn first_sample_precedes_worker_continuation() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("after-first-sample");
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "post::lease_startup::tests::worker_stop_fixture"])
            .env("EPOCH145_STARTUP_TEST_MARKER", &marker)
            .spawn()
            .unwrap();
        let check = (|| -> io::Result<()> {
            wait_for_lease_stop(&child, Instant::now() + Duration::from_secs(5))?;
            if marker.exists() {
                return Err(io::Error::other("worker advanced before first sample"));
            }
            if unsafe { libc::kill(child.id() as i32, libc::SIGCONT) } != 0 {
                return Err(io::Error::last_os_error());
            }
            if !child.wait()?.success() || fs::read(marker)? != b"resumed" {
                return Err(io::Error::other("worker did not resume"));
            }
            Ok(())
        })();
        if check.is_err() {
            let _ = child.kill();
            let _ = child.wait();
        }
        check.unwrap();
    }

    #[test]
    fn exited_child_remains_reapable_and_never_counts_as_ready() {
        let mut child = Command::new("/usr/bin/false").spawn().unwrap();
        let error =
            wait_for_lease_stop(&child, Instant::now() + Duration::from_secs(5)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert_eq!(child.wait().unwrap().code(), Some(1));
    }
}
