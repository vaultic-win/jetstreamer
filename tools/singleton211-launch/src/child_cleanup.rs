//! A bounded wait for a child process. The caller owns timeout disposition.
use std::{
    process::Child,
    time::{Duration, Instant},
};
pub(crate) fn wait_for_cleanup(
    child: &mut Child,
    timeout: Duration,
) -> std::io::Result<Option<std::process::ExitStatus>> {
    let end = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        let remaining = end.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(None);
        }
        std::thread::sleep(remaining.min(Duration::from_millis(200)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::process::{Command, Stdio};
    #[test]
    fn cleanup_wait_does_not_kill_or_invent_a_launcher_status() {
        let mut child = Command::new("/bin/sh")
            .args(["-c", "read token; exit 7"])
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        assert!(
            wait_for_cleanup(&mut child, Duration::ZERO)
                .unwrap()
                .is_none()
        );
        drop(child.stdin.take());
        let status = wait_for_cleanup(&mut child, Duration::from_secs(5))
            .unwrap()
            .unwrap();
        assert_eq!(status.code(), Some(7));
    }
    #[test]
    fn acknowledges_then_exits_cleanly_after_the_caller_starts_waiting() {
        let mut child = Command::new("/bin/sh")
            .args(["-c", "read token; test \"$token\" = close"])
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        let mut input = child.stdin.take().unwrap();
        assert!(
            wait_for_cleanup(&mut child, Duration::from_millis(10))
                .unwrap()
                .is_none()
        );
        input.write_all(b"close\n").unwrap();
        drop(input);
        assert!(
            wait_for_cleanup(&mut child, Duration::from_secs(5))
                .unwrap()
                .unwrap()
                .success()
        );
    }
}
