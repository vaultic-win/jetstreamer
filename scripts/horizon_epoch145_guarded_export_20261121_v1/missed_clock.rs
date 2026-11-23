//! A missed host RSS observation can keep an already leased child stopped for one clock.
use super::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Pending {
    pub(crate) deadline: u64,
    prior: Bound,
    config: Bound,
    terminal: Bound,
    expected_fleet: PathBuf,
}
impl Pending {
    pub(crate) fn confirm(&self, sample: &Value) -> Result<()> {
        let evidence = observation(&self.prior)?;
        ensure!(
            evidence["state"] == "accepted"
                && evidence["config"] == json!(self.config)
                && evidence["terminal"] == json!(self.terminal)
                && evidence["fleet"] == sample["fleet"]
                && evidence["fleet"]["path"] == json!(self.expected_fleet),
            "full price did not use the registered replacement"
        );
        Ok(())
    }
}

impl std::fmt::Display for Pending {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            out,
            "waiting for the registered replacement fleet, deadline {}",
            self.deadline
        )
    }
}

impl std::error::Error for Pending {}

pub(super) fn replacement(fleet: &Bound, data: &Value) -> Result<Option<Bound>> {
    let cfg: Bound = serde_json::from_value(data["sole_next_observer"].clone())?;
    ensure!(
        custody::hex(&cfg.sha256, 64),
        "invalid next observation digest"
    );
    let registration = Path::new(super::RUNTIME)
        .join("survivor172-cadence-20261122-v1")
        .join(format!("recover-{}", &cfg.sha256[..20]))
        .join("REGISTERED.json");
    if !registration.try_exists()? {
        return Ok(None);
    }
    let result = observation(fleet)?;
    match result["state"].as_str() {
        Some("accepted") => Ok(Some(serde_json::from_value(result["fleet"].clone())?)),
        Some("pending") => Err(Pending {
            deadline: capacity::n(&result, "deadline")?,
            prior: fleet.clone(),
            config: serde_json::from_value(result["config"].clone())?,
            terminal: serde_json::from_value(result["terminal"].clone())?,
            expected_fleet: serde_json::from_value(result["expected_fleet"].clone())?,
        }
        .into()),
        _ => anyhow::bail!("registered replacement disappeared or changed"),
    }
}

fn observation(fleet: &Bound) -> Result<Value> {
    let result = Command::new("/usr/bin/timeout")
        .args([
            "--kill-after=2s",
            "10s",
            "/usr/bin/python3",
            "-IB",
            "-c",
            include_str!("missed_clock.py"),
        ])
        .arg(&fleet.path)
        .arg(&fleet.sha256)
        .output()?;
    ensure!(
        result.status.success() && result.stderr.is_empty() && result.stdout.len() <= 4096,
        "invalid registered cadence replacement: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    Ok(serde_json::from_slice(&result.stdout)?)
}

pub(crate) fn stopped_leases(pid: u32, ticks: u64) -> Result<()> {
    let ids = [100214429, 100214450, 103237059].map(|ino| (64512, ino));
    leases(pid, ticks, &ids)
}

fn leases(pid: u32, ticks: u64, ids: &[(u64, u64); 3]) -> Result<()> {
    prove_stopped_child(pid, ticks)?;
    for owner in [std::process::id(), pid] {
        let mut held = std::collections::BTreeSet::new();
        let root = PathBuf::from(format!("/proc/{owner}"));
        for entry in fs::read_dir(root.join("fd"))? {
            let entry = entry?;
            let m = match fs::metadata(entry.path()) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                result => result?,
            };
            if !ids.contains(&(m.dev(), m.ino())) {
                continue;
            }
            let info = fs::read_to_string(root.join("fdinfo").join(entry.file_name()))?;
            if info.lines().any(|line| {
                let cols: Vec<_> = line.split_whitespace().collect();
                cols.len() >= 7
                    && cols[0] == "lock:"
                    && cols[2..5] == ["LEASE", "ACTIVE", "READ"]
                    && cols[5].parse::<u32>() == Ok(owner)
            }) {
                held.insert((m.dev(), m.ino()));
            }
        }
        ensure!(
            held.len() == 3,
            "frozen verifier lost an original source lease"
        );
    }
    prove_stopped_child(pid, ticks)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn kernel_stopped_pair_requires_all_six_read_leases() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let paths = ["first", "second", "third"].map(|s| dir.path().join(s));
        let mut handles = Vec::new();
        let mut ids = [(0, 0); 3];
        for (i, path) in paths.iter().enumerate() {
            fs::write(path, b"lease fixture")?;
            let file = File::open(path)?;
            ensure!(
                unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETLEASE, libc::F_RDLCK) } == 0,
                "test parent failed to acquire read lease"
            );
            let st = file.metadata()?;
            ids[i] = (st.dev(), st.ino());
            handles.push(file);
        }
        let mut child = Command::new("/usr/bin/python3")
            .args(["-IB", "-c", "import fcntl,os,signal,sys; f=[open(p,'rb') for p in sys.argv[1:]]; [fcntl.fcntl(x,fcntl.F_SETLEASE,fcntl.F_RDLCK) for x in f]; os.kill(os.getpid(),signal.SIGSTOP)"])
            .args(&paths)
            .spawn()?;
        let result = (|| -> Result<()> {
            let pid = child.id();
            let ticks = native::ticks(pid)?;
            let mut state = 0;
            ensure!(
                unsafe { libc::waitpid(pid as i32, &mut state, libc::WUNTRACED) } == pid as i32
                    && libc::WIFSTOPPED(state),
                "fixture child did not stop"
            );
            leases(pid, ticks, &ids)?;
            drop(handles.pop());
            ensure!(
                leases(pid, ticks, &ids).is_err(),
                "missing parent lease was accepted"
            );
            Ok(())
        })();
        let _ = child.kill();
        let _ = child.wait();
        result
    }
}
