//! Fixed-purpose metadata children; no caller-supplied command vectors.
use crate::storage::{self, Bound};
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};
use std::{
    fs,
    io::Read,
    os::unix::process::{CommandExt, ExitStatusExt},
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};
pub const SEALER: &str = "/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment";
pub const SEALER_SHA: &str = "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3";
const OUTPUT_LIMIT: usize = 1 << 20;
pub struct Runner<'a> {
    pub root: &'a Path,
    pub self_image: &'a Bound,
    pub iid: &'a str,
    pub deadline: Instant,
    pub pool_deadline: Instant,
    pub sequence: u32,
}
struct Captured {
    bytes: Vec<u8>,
    overflow: bool,
    error: Option<String>,
}
fn bounded_pipe(mut p: impl Read) -> Captured {
    let mut out = Vec::new();
    let error = p
        .by_ref()
        .take((OUTPUT_LIMIT + 1) as u64)
        .read_to_end(&mut out)
        .err()
        .map(|e| e.to_string());
    let overflow = out.len() > OUTPUT_LIMIT;
    Captured {
        bytes: out,
        overflow,
        error,
    }
}
fn wait_pidfd(
    child: &mut std::process::Child,
    timeout: Duration,
) -> Result<std::process::ExitStatus> {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, child.id(), 0) as i32 };
    ensure!(fd >= 0, "cannot obtain stable original child pidfd");
    let until = Instant::now() + timeout;
    let result = (|| {
        loop {
            let remaining = until
                .checked_duration_since(Instant::now())
                .context("metadata child deadline")?;
            let mut p = libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            };
            let ms = remaining.as_millis().clamp(1, i32::MAX as u128) as i32;
            let r = unsafe { libc::poll(&mut p, 1, ms) };
            if r < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            ensure!(
                r > 0 && p.revents & libc::POLLIN != 0,
                "metadata child deadline or invalid pidfd event"
            );
            return Ok(child.wait()?);
        }
    })();
    unsafe {
        libc::close(fd);
    }
    result
}
impl Runner<'_> {
    pub(super) fn run(&mut self, label: &str, cmd: Command, limit: Duration) -> Result<Value> {
        self.run_inner(label, cmd, limit, false)
    }
    fn run_inner(
        &mut self,
        label: &str,
        mut cmd: Command,
        limit: Duration,
        allow_native_unit_absent: bool,
    ) -> Result<Value> {
        ensure!(
            !label.contains('/') && self.sequence < 2048,
            "finite child count/label"
        );
        let left = self
            .deadline
            .min(self.pool_deadline)
            .checked_duration_since(Instant::now())
            .context("original final deadline exhausted")?;
        let timeout = limit.min(left);
        ensure!(!timeout.is_zero(), "no original child budget");
        self.sequence += 1;
        let stem = format!("{:02}-{label}", self.sequence);
        let program = cmd.get_program().to_string_lossy().into_owned();
        let argv = cmd
            .get_args()
            .map(|x| x.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        storage::save(
            self.root,
            &format!("{stem}-intent.json"),
            &json!({"program":program,"argv":argv,
            "wall_started_at":crate::now()?,"timeout_millis":timeout.as_millis(),"original_iid":self.iid,
            "no_retry_or_clock_reset":true}),
        )?;
        let left = self
            .deadline
            .min(self.pool_deadline)
            .checked_duration_since(Instant::now())
            .context("original child/normal-pool budget consumed by intent persistence")?;
        let timeout = timeout.min(left);
        ensure!(
            !timeout.is_zero(),
            "no child budget after intent persistence"
        );
        cmd.env("LC_ALL", "C")
            .env_remove("SYSTEMD_HOST")
            .env_remove("SYSTEMD_BUS_ADDRESS")
            .env_remove("DBUS_SYSTEM_BUS_ADDRESS")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = cmd.spawn().context("finite metadata child spawn")?;
        let stdout = child.stdout.take().context("child stdout")?;
        let stderr = child.stderr.take().context("child stderr")?;
        let out = std::thread::spawn(move || bounded_pipe(stdout));
        let err = std::thread::spawn(move || bounded_pipe(stderr));
        let status = wait_pidfd(&mut child, timeout);
        let cleanup = if status.is_err() {
            // Only our unreaped original child can receive this kill. A systemd
            // helper's separately admitted RuntimeMax20s still bounds its unit.
            let _ = child.kill();
            Some(child.wait())
        } else {
            None
        };
        let panic_capture = || Captured {
            bytes: Vec::new(),
            overflow: false,
            error: Some("capture thread panicked".into()),
        };
        let stdout = out.join().unwrap_or_else(|_| panic_capture());
        let stderr = err.join().unwrap_or_else(|_| panic_capture());
        let receipt = json!({"program":program,"argv":argv,"wall_finished_at":crate::now()?,
            "exit_code":status.as_ref().ok().and_then(|s|s.code()),
            "exit_signal":status.as_ref().ok().and_then(|s|s.signal()),
            "wait_error":status.as_ref().err().map(|e|format!("{e:#}")),
            "stdout_bytes":stdout.bytes,"stderr_bytes":stderr.bytes,
            "stdout_overflow":stdout.overflow,"stderr_overflow":stderr.overflow,
            "stdout_read_error":stdout.error,"stderr_read_error":stderr.error,
            "cleanup_terminal_code":cleanup.as_ref().and_then(|s|s.as_ref().ok()).and_then(|s|s.code()),
            "cleanup_terminal_signal":cleanup.as_ref().and_then(|s|s.as_ref().ok()).and_then(|s|s.signal()),
            "cleanup_wait_error":cleanup.as_ref().and_then(|s|s.as_ref().err()).map(|e|e.to_string()),
            "original_iid":self.iid,
            "no_retry_or_clock_reset":true});
        storage::save(
            self.root,
            &format!("{stem}-original-outcome.json"),
            &receipt,
        )?;
        ensure!(
            !stdout.overflow
                && !stderr.overflow
                && stdout.error.is_none()
                && stderr.error.is_none(),
            "original child output overflow/read failure; actual captured prefix retained"
        );
        let status = status?;
        ensure!(
            status.success() || (allow_native_unit_absent && status.code() == Some(4)),
            "original finite metadata child failed: {label}"
        );
        Ok(receipt)
    }
    pub fn seal(&mut self, label: &str, plan: &Bound) -> Result<()> {
        let mut c = Command::new(SEALER);
        c.arg(&plan.path)
            .args(["--plan-sha256", &plan.sha256, "--self-sha256", SEALER_SHA]);
        unsafe {
            c.pre_exec(|| {
                libc::umask(0o022);
                Ok(())
            });
        }
        self.run(label, c, Duration::from_secs(5))?;
        Ok(())
    }
    pub fn native(&mut self, name: &str) -> Result<Value> {
        ensure!(crate::unit_name(name), "native unit syntax");
        let fields = "Id,LoadState,ActiveState,SubState,InvocationID,MainPID,ControlPID,NRestarts,Job,Result,ExecMainStatus,ExecMainStartTimestampMonotonic,LastTriggerUSecMonotonic,Unit";
        let mut c = Command::new("/usr/bin/systemctl");
        c.args(["show", name, "--no-pager", &format!("--property={fields}")]);
        let receipt = self.run_inner("native-original-owner", c, Duration::from_secs(5), true)?;
        let bytes: Vec<u8> = serde_json::from_value(receipt["stdout_bytes"].clone())?;
        let mut result = serde_json::Map::new();
        for line in std::str::from_utf8(&bytes)?.lines() {
            let (k, v) = line.split_once('=').context("native scalar line")?;
            ensure!(
                result.insert(k.into(), json!(v)).is_none(),
                "duplicate native scalar"
            );
        }
        ensure!(
            result.get("Id") == Some(&json!(name)),
            "native unit identity changed"
        );
        if result.get("LoadState") == Some(&json!("not-found")) {
            ensure!(
                result.get("InvocationID") == Some(&json!(""))
                    && result.get("ActiveState") == Some(&json!("inactive"))
                    && result.get("Job") == Some(&json!("")),
                "actual absent native unit framing"
            );
        }
        Ok(json!(result))
    }
}
pub fn bind_file(p: &Path, limit: u64) -> Result<Bound> {
    crate::deny_original199(p)?;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let mut f = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(p)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file() && m.uid() == 0 && m.nlink() == 1 && m.mode() & 0o022 == 0 && m.len() <= limit,
        "bounded original Root generated file custody"
    );
    let mut raw = Vec::new();
    f.by_ref().take(limit + 1).read_to_end(&mut raw)?;
    ensure!(
        raw.len() as u64 == m.len(),
        "original generated length raced"
    );
    let b = Bound {
        path: p.into(),
        sha256: storage::sha(&raw),
    };
    ensure!(
        storage::bytes(&b, limit, false)? == raw,
        "original generated source raced"
    );
    Ok(b)
}
pub fn stdout_json(receipt: &Value) -> Result<Value> {
    let raw: Vec<u8> = serde_json::from_value(receipt["stdout_bytes"].clone())?;
    if raw.is_empty() {
        bail!("child emitted no JSON")
    }
    Ok(serde_json::from_slice(&raw)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_capture_preserves_exact_bytes_and_rejects_overflow() {
        let original = b"original child bytes\n";
        let actual = bounded_pipe(&original[..]);
        assert_eq!(actual.bytes, original);
        assert!(!actual.overflow);
        let overflow = bounded_pipe(std::io::Cursor::new(vec![0; OUTPUT_LIMIT + 1]));
        assert!(overflow.overflow);
        assert_eq!(overflow.bytes.len(), OUTPUT_LIMIT + 1);
    }
    #[test]
    fn pidfd_reaps_the_actual_original_finite_child() {
        let mut child = Command::new("/usr/bin/true").spawn().unwrap();
        assert!(
            wait_pidfd(&mut child, Duration::from_secs(2))
                .unwrap()
                .success()
        );
    }
    #[test]
    fn pidfd_timeout_does_not_invent_a_successful_child() {
        let mut child = Command::new("/usr/bin/sleep").arg("1").spawn().unwrap();
        let outcome = wait_pidfd(&mut child, Duration::from_millis(10));
        let _ = child.kill();
        let terminal = child.wait().unwrap();
        assert!(outcome.is_err());
        assert!(!terminal.success());
    }
}
