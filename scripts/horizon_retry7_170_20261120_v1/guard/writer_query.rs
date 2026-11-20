//! The two writer snapshots bracketing a retained-tree check share a bounded wait.
use anyhow::{Context, Result, ensure};
use std::{
    os::unix::process::ExitStatusExt,
    process::{Command, Output},
    time::{Duration, Instant},
};

const MAX_STDOUT_BYTES: usize = 16_384;
const DIAGNOSTIC_BYTES: usize = 512;
// Two original 10-second calls. A PID 1 reload can occupy more than 10 seconds.
pub(super) const PAIR_BUDGET: Duration = Duration::from_secs(20);

fn diagnostic(bytes: &[u8]) -> String {
    // JSON-style escaping keeps child output inside one readable diagnostic line.
    format!(
        "{:?}",
        String::from_utf8_lossy(&bytes[..bytes.len().min(DIAGNOSTIC_BYTES)])
    )
}

fn accept(output: Output, elapsed: Duration, phase: &str) -> Result<Output> {
    ensure!(
        output.status.success()
            && output.stderr.is_empty()
            && output.stdout.len() < MAX_STDOUT_BYTES,
        "bounded writer query failed; phase={phase:?}; elapsed_millis={}; exit_code={:?}; signal={:?}; stdout_bytes={}; stderr_bytes={}; stdout_prefix={}; stderr_prefix={}",
        elapsed.as_millis(),
        output.status.code(),
        output.status.signal(),
        output.stdout.len(),
        output.stderr.len(),
        diagnostic(&output.stdout),
        diagnostic(&output.stderr),
    );
    Ok(output)
}

fn bounded(command: &[&str], phase: &str, remaining: &mut Duration) -> Result<Output> {
    ensure!(
        !remaining.is_zero(),
        "writer query budget exhausted; phase={phase:?}"
    );
    // GNU timeout treats zero as unlimited. Keep fractional seconds, including the
    // final query's subsecond remainder, and also enforce the bound on child exit.
    let limit = format!("{}.{:09}", remaining.as_secs(), remaining.subsec_nanos());
    let started = Instant::now();
    let output = Command::new("/usr/bin/timeout")
        .args(["--signal=KILL", &limit])
        .args(command)
        .env("LC_ALL", "C")
        .output()
        .with_context(|| format!("bounded writer query spawn failed; phase={phase:?}"))?;
    let elapsed = started.elapsed();
    let output = accept(output, elapsed, phase)?;
    *remaining = remaining
        .checked_sub(elapsed)
        .with_context(|| format!("writer query exceeded remaining budget; phase={phase:?}"))?;
    Ok(output)
}

pub(super) fn query(
    units: &[&str],
    fields: &str,
    phase: &str,
    remaining: &mut Duration,
) -> Result<Output> {
    let mut command = vec!["/usr/bin/systemctl", "show"];
    command.extend_from_slice(units);
    command.extend(["--all", "--no-pager", "-p", fields]);
    bounded(&command, phase, remaining)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::ExitStatus;

    fn output(code: i32, stdout: Vec<u8>, stderr: Vec<u8>) -> Output {
        Output {
            status: ExitStatus::from_raw(code << 8),
            stdout,
            stderr,
        }
    }

    #[test]
    fn slow_first_query_leaves_its_actual_remainder_for_the_second() {
        let mut budget = PAIR_BUDGET;
        bounded(&["/usr/bin/sleep", "11"], "before", &mut budget).unwrap();
        assert!(budget <= Duration::from_secs(9));
        bounded(&["/usr/bin/true"], "after", &mut budget).unwrap();
    }

    #[test]
    fn exhausted_and_fractional_budgets_fail_closed() {
        let mut budget = Duration::ZERO;
        assert!(bounded(&["/usr/bin/true"], "after", &mut budget).is_err());
        let mut budget = Duration::from_millis(50);
        assert!(bounded(&["/usr/bin/sleep", "1"], "after", &mut budget).is_err());
    }

    #[test]
    fn accepts_only_the_original_success_envelope() {
        let bytes = b"Id=retired.service\nLoadState=not-found\n".to_vec();
        let value = accept(output(0, bytes.clone(), vec![]), Duration::ZERO, "before").unwrap();
        assert_eq!(value.stdout, bytes);
        // Query success is not an absence claim: the unchanged outer parser still
        // validates all fields, complete unit order, hooks and invocation state.
    }

    #[test]
    fn exit_status_and_stderr_survive_flat_error_serialization() {
        let error = accept(
            output(
                1,
                vec![],
                b"Failed to connect to bus: Connection reset by peer\n".to_vec(),
            ),
            Duration::from_millis(19),
            "before retained-tree verification",
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("exit_code=Some(1)"));
        assert!(error.contains("Connection reset by peer\\n"));
        assert!(error.contains("elapsed_millis=19"));
        assert!(error.contains("before retained-tree verification"));
    }

    #[test]
    fn stderr_still_fails_even_when_exit_status_is_zero() {
        let error = accept(
            output(0, vec![], b"warning\n".to_vec()),
            Duration::ZERO,
            "after",
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("stderr_bytes=8"));
        assert!(error.contains("exit_code=Some(0)"));
    }

    #[test]
    fn output_boundary_remains_exclusive_and_diagnostics_are_bounded() {
        assert!(
            accept(
                output(0, vec![b'a'; MAX_STDOUT_BYTES - 1], vec![]),
                Duration::ZERO,
                "before"
            )
            .is_ok()
        );
        let error = accept(
            output(0, vec![b'a'; MAX_STDOUT_BYTES], vec![]),
            Duration::ZERO,
            "before",
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("stdout_bytes=16384"));
        assert!(error.len() < 1024);
    }

    #[test]
    fn killed_timeout_keeps_the_signal_and_elapsed_time() {
        let result = Output {
            status: ExitStatus::from_raw(libc::SIGKILL),
            stdout: vec![],
            stderr: vec![],
        };
        let error = accept(result, Duration::from_secs(10), "after")
            .unwrap_err()
            .to_string();
        assert!(error.contains("signal=Some(9)"));
        assert!(error.contains("exit_code=None"));
        assert!(error.contains("elapsed_millis=10000"));
    }

    #[test]
    fn timeout_wrapper_exit_code_is_not_a_success() {
        let error = accept(
            output(124, vec![], vec![]),
            Duration::from_secs(10),
            "before",
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("exit_code=Some(124)"));
    }

    #[test]
    fn non_utf8_and_control_bytes_cannot_hide_the_failure_context() {
        let error = accept(
            output(2, vec![], vec![0xff, b'\n', 0]),
            Duration::ZERO,
            "after",
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("stderr_bytes=3"));
        assert!(!error.contains('\n'));
        assert!(!error.contains('\0'));
    }

    #[test]
    fn native_failed_command_retains_real_exit_status_and_stderr() {
        let started = Instant::now();
        let result = Command::new("/usr/bin/stat")
            .args(["--", "/proc/self/this-horizon-fixture-path-must-not-exist"])
            .env("LC_ALL", "C")
            .output()
            .unwrap();
        assert!(!result.status.success() && !result.stderr.is_empty());
        let error = accept(result, started.elapsed(), "native-command-failure")
            .unwrap_err()
            .to_string();
        assert!(error.contains("No such file or directory"));
        assert!(error.contains("exit_code=Some(1)"));
        assert!(error.contains("native-command-failure"));
    }

    #[test]
    fn native_excess_output_is_rejected_after_successful_child_exit() {
        let started = Instant::now();
        let result = Command::new("/usr/bin/head")
            .args(["-c", "16384", "/dev/zero"])
            .output()
            .unwrap();
        assert!(result.status.success() && result.stderr.is_empty());
        assert_eq!(result.stdout.len(), MAX_STDOUT_BYTES);
        let error = accept(result, started.elapsed(), "native-output-bound")
            .unwrap_err()
            .to_string();
        assert!(error.contains("stdout_bytes=16384"));
        assert!(error.len() < 2048);
    }

    #[test]
    fn native_ten_second_timeout_is_reaped_and_preserved() {
        let started = Instant::now();
        let result = Command::new("/usr/bin/timeout")
            .args(["--signal=KILL", "10", "/usr/bin/sleep", "11"])
            .output()
            .unwrap();
        let elapsed = started.elapsed();
        assert!(elapsed >= Duration::from_secs(10));
        assert!(!result.status.success());
        let error = accept(result, elapsed, "native-timeout")
            .unwrap_err()
            .to_string();
        assert!(error.contains("signal=Some(9)"));
        assert!(error.contains("native-timeout"));
    }
}
