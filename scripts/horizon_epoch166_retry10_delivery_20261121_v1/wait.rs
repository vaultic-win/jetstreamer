//! A durable batch can precede the final producer log and PID 1 event.
use super::*;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::{Duration, Instant};

pub(super) fn committed(live: &Value) -> Result<Value> {
    let parent = &live["native"]["parent"];
    let pid = parent["pid"].as_i64().context("missing producer PID")?;
    if process_bound(parent)? {
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
        if raw < 0 {
            let error = std::io::Error::last_os_error();
            ensure!(
                error.raw_os_error() == Some(libc::ESRCH),
                "pidfd_open: {error}"
            );
        } else {
            let fd = unsafe { OwnedFd::from_raw_fd(raw) };
            if process_bound(parent)? {
                ensure!(
                    show(UNIT)?["InvocationID"] == IID,
                    "foreign original producer"
                );
                let mut poll = libc::pollfd {
                    fd: fd.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                let result = unsafe { libc::poll(&mut poll, 1, 300_000) };
                ensure!(
                    result == 1 && poll.revents & libc::POLLIN != 0,
                    "producer has not exited after local commit"
                );
            }
        }
    }
    let end = Instant::now() + Duration::from_secs(20);
    loop {
        match complete(live) {
            Ok(v) => return Ok(v),
            Err(error) if Instant::now() >= end => return Err(error),
            Err(_) => std::thread::sleep(Duration::from_millis(350)),
        }
    }
}
