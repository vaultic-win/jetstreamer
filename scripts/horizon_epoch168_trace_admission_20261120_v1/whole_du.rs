use anyhow::{Context, Result, bail, ensure};
use guard168::LANE;
use std::process::Output;

const ATTEMPTS: usize = 6;
const SCRATCH: &str =
    "/replacement-local1-20261110-v1/trace-local3-20261120-v1/scratch/.historical-runtime/";
fn digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}
fn temp_dir(s: &str, prefix: &str) -> bool {
    s.strip_prefix(prefix)
        .is_some_and(|v| v.len() == 6 && v.bytes().all(|b| b.is_ascii_alphanumeric()))
}
fn vanished(line: &str) -> bool {
    let Some(path) = line
        .strip_prefix("/usr/bin/du: cannot access '")
        .and_then(|s| s.strip_suffix("': No such file or directory"))
        .and_then(|s| s.strip_prefix(LANE))
        .and_then(|s| s.strip_prefix(SCRATCH))
    else {
        return false;
    };
    let mut parts = path.split('/');
    let (Some(parent), Some(runtime), Some("accounts-state"), Some(shard), Some(file), None) = (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) else {
        return false;
    };
    temp_dir(parent, "jetstreamer-historical-parent-")
        && temp_dir(runtime, "jetstreamer-historical-v1.5.6-")
        && digits(shard)
        && file
            .split_once('.')
            .is_some_and(|(slot, id)| digits(slot) && digits(id))
}
pub(super) fn scan(mut run: impl FnMut() -> Result<Output>) -> Result<u64> {
    for attempt in 1..=ATTEMPTS {
        let r = run().with_context(|| format!("whole 168 scan {attempt}/{ATTEMPTS}"))?;
        if r.status.success() && r.stderr.is_empty() {
            let raw = std::str::from_utf8(&r.stdout)?
                .strip_suffix('\n')
                .context("unterminated du record")?;
            let (bytes, root) = raw.split_once('\t').context("malformed du record")?;
            ensure!(
                digits(bytes) && root == LANE,
                "unexpected whole 168 du record"
            );
            return Ok(bytes.parse()?);
        }
        // A failed GNU du emits a plausible *partial* total. Discard that stream entirely.
        if r.status.code() == Some(1)
            && attempt < ATTEMPTS
            && std::str::from_utf8(&r.stderr)
                .is_ok_and(|s| !s.is_empty() && s.ends_with('\n') && s.lines().all(vanished))
        {
            continue;
        }
        bail!(
            "whole 168 allocation scan {attempt}/{ATTEMPTS} failed ({}), stderr {} bytes: {}",
            r.status,
            r.stderr.len(),
            String::from_utf8_lossy(&r.stderr[..r.stderr.len().min(4096)])
        );
    }
    unreachable!("last unsuccessful scan returns diagnostic")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{os::unix::process::ExitStatusExt, process::ExitStatus};
    fn output(status: i32, bytes: u64, stderr: &str) -> Output {
        Output {
            status: ExitStatus::from_raw(status),
            stdout: format!("{bytes}\t{LANE}\n").into_bytes(),
            stderr: stderr.as_bytes().to_vec(),
        }
    }
    fn churn() -> String {
        format!(
            "/usr/bin/du: cannot access '{LANE}{SCRATCH}jetstreamer-historical-parent-PQe7vz/jetstreamer-historical-v1.5.6-Hmpepq/accounts-state/3/72606089.1154638350': No such file or directory\n"
        )
    }
    #[test]
    fn failed_stdout_never_counts_towards_either_complete_scan() {
        let mut sequence = [
            output(256, 1, &churn()),
            output(0, 71, ""),
            output(256, 2, &churn()),
            output(0, 82, ""),
        ]
        .into_iter();
        let mut run = || Ok(sequence.next().unwrap());
        assert_eq!(scan(&mut run).unwrap(), 71);
        assert_eq!(scan(&mut run).unwrap(), 82);
        assert!(sequence.next().is_none());
    }
    #[test]
    fn permanent_or_mixed_errors_fail_immediately() {
        let c = churn();
        for (code, stderr) in [
            (
                1 << 8,
                c.replace("No such file or directory", "Permission denied"),
            ),
            (1 << 8, c.clone() + "du: I/O error\n"),
            (1 << 8, c.replace("accounts-state", "../accounts-state")),
            (1 << 8, c.replace(SCRATCH, "/other/")),
            (1 << 8, String::new()),
            (9, c.clone()),
            (124 << 8, c.clone()),
            (0, c),
        ] {
            let mut n = 0;
            let err = scan(|| {
                n += 1;
                Ok(output(code, 1, &stderr))
            })
            .unwrap_err()
            .to_string();
            assert_eq!(n, 1);
            assert!(err.contains("1/6"));
        }
    }
    #[test]
    fn retry_exhaustion_reports_reason_without_using_partial_total() {
        let mut n = 0;
        let err = scan(|| {
            n += 1;
            Ok(output(256, 99, &churn()))
        })
        .unwrap_err()
        .to_string();
        assert_eq!(n, ATTEMPTS);
        assert!(err.contains("6/6") && err.contains("No such file"));
    }
}
