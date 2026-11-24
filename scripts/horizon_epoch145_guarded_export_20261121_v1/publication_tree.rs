//! Freeze the admitted uploader and all of its nested readers together. Only
//! the supervisor stays outside the delegated leaf to measure and release it.
use super::*;
use std::process::Child;

pub(super) struct Tree {
    leaf: PathBuf,
}

impl Tree {
    pub(super) fn create() -> Result<Self> {
        let own = fs::read_to_string("/proc/self/cgroup")?;
        let base = "/system.slice/";
        #[cfg(all(test, incident_registered136_post145_only))]
        let expected = if cfg!(incident_v5q_136_post145_only) {
            "0::/horizonaudit.slice/horizon-145-v5q-136-post-build-v1.service"
        } else if cfg!(incident_v5o_136_post145_only) {
            "0::/horizonaudit.slice/horizon-145-v5o-136-post-build-v1.service"
        } else if cfg!(incident_v5n_136_post145_only) {
            "0::/horizonaudit.slice/horizon-145-v5n-136-post-build-v1.service"
        } else if cfg!(incident_v5n_post145_only) {
            "0::/horizonaudit.slice/horizon-145-v5n-post-build-v1.service"
        } else if cfg!(incident_v5m_post145_only) {
            "0::/horizonaudit.slice/horizon-145-v5m-post-build-v1.service"
        } else if cfg!(incident_v5k_post145_only) {
            "0::/horizonaudit.slice/horizon-145-v5k-post-build-v1.service"
        } else if cfg!(incident_v5j_retry1_post145_only) {
            "0::/horizonaudit.slice/horizon-145-v5j-post-build-v2.service"
        } else if cfg!(incident_v5j_post145_only) {
            "0::/horizonaudit.slice/horizon-145-v5j-post-build-v1.service"
        } else if cfg!(incident_fixture_post145_only) {
            "0::/horizonaudit.slice/horizon-incident-145-post-fixture-build-v1.service"
        } else {
            "0::/horizonaudit.slice/horizon-incident-145-post-registered-build-v1.service"
        };
        #[cfg(all(test, incident_registered136_post145_only))]
        let base = if own.trim() == expected {
            "/horizonaudit.slice/"
        } else {
            base
        };
        let name = own
            .trim()
            .strip_prefix(&format!("0::{base}"))
            .context("unexpected supervisor cgroup")?;
        ensure!(
            name.ends_with(".service") && !name.contains('/'),
            "expected one service"
        );
        let parent = Path::new("/sys/fs/cgroup")
            .join(base.trim_matches('/'))
            .join(name);
        let leaf = parent.join("publication");
        fs::create_dir(&leaf).context("create delegated publication cgroup")?;
        let group = Self { leaf };
        ensure!(
            !group.event("populated")? && !group.event("frozen")?,
            "new cgroup already occupied"
        );
        Ok(group)
    }

    fn event(&self, property: &str) -> Result<bool> {
        let events = fs::read_to_string(self.leaf.join("cgroup.events"))?;
        let mut rows = events
            .lines()
            .filter_map(|line| line.split_once(' '))
            .filter(|(key, _)| *key == property);
        let value = rows.next().context("missing cgroup event")?.1;
        ensure!(rows.next().is_none(), "duplicate cgroup event");
        match value {
            "1" => Ok(true),
            "0" => Ok(false),
            _ => anyhow::bail!("invalid cgroup event"),
        }
    }

    fn wait_event(&self, event: &str, expected: bool, deadline: Instant) -> Result<()> {
        loop {
            if self.event(event)? == expected {
                return Ok(());
            }
            ensure!(Instant::now() < deadline, "cgroup {event} timeout");
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn freeze(&self, stopped: bool) -> Result<()> {
        fs::write(
            self.leaf.join("cgroup.freeze"),
            if stopped { b"1" } else { b"0" },
        )?;
        self.wait_event("frozen", stopped, Instant::now() + Duration::from_secs(3))
    }

    fn spawn(&self, command: &mut Command) -> Result<Child> {
        ensure!(
            !self.event("populated")? && !self.event("frozen")?,
            "payload subtree is occupied"
        );
        let membership = OpenOptions::new()
            .write(true)
            .open(self.leaf.join("cgroup.procs"))?;
        let parent = std::process::id();
        unsafe {
            command.pre_exec(move || {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0
                    || libc::getppid() as u32 != parent
                    || libc::write(membership.as_raw_fd(), b"0".as_ptr().cast(), 1) != 1
                {
                    return Err(std::io::Error::other(
                        "failed to enter supervised payload cgroup",
                    ));
                }
                Ok(())
            });
        }
        Ok(command.stdin(Stdio::null()).spawn()?)
    }

    pub(super) fn run(
        &self,
        command: &mut Command,
        fit: &impl post::VerificationGuard,
        archive: &source_lease::ReadLease,
        checksum: &source_lease::ReadLease,
    ) -> Result<()> {
        let confirm = |frozen: bool| -> Result<()> {
            let mut deadline = Instant::now() + Duration::from_secs(90);
            loop {
                ensure!(
                    deadline.saturating_duration_since(Instant::now()) >= Duration::from_secs(12)
                        && if frozen {
                            self.event("frozen")?
                        } else {
                            !self.event("populated")?
                        },
                    "publisher census requires a frozen or vacant group within its deadline"
                );
                archive.check()?;
                checksum.check()?;
                match fit.topology().and_then(|_| fit.current(0)) {
                    Ok(_) => {
                        ensure!(
                            cfg!(incident_post145_only) || Instant::now() < deadline,
                            "late publisher census"
                        );
                        ensure!(
                            if frozen {
                                self.event("frozen")?
                            } else {
                                !self.event("populated")?
                            },
                            "publication group changed across complete fit"
                        );
                        return Ok(());
                    }
                    Err(e)
                        if (cfg!(continuity145_only) && e.is::<peer_terminal::Pending>())
                            || (cfg!(incident_post145_only)
                                && (e.is::<capacity::Reprice>()
                                    || e.is::<capacity::TopologyTimeout>())) =>
                    {
                        eprintln!("epoch145 holding publication group for a fresh fit: {e:#}");
                        thread::sleep(Duration::from_secs(10));
                        deadline = Instant::now() + Duration::from_secs(90);
                    }
                    Err(e)
                        if e.is::<capacity::TopologyTimeout>()
                            || e.is::<capacity::GuardInFlight>() =>
                    {
                        thread::sleep(Duration::from_secs(1))
                    }
                    Err(e) => return Err(e),
                }
            }
        };
        confirm(false)?;
        let mut child = self.spawn(command)?;
        let mut sampled = Instant::now();
        let result = (|| -> Result<()> {
            loop {
                if let Some(status) = child.try_wait()? {
                    ensure!(status.success(), "publisher phase failed with {status}");
                    ensure!(!self.event("populated")?, "publisher left descendants");
                    return Ok(());
                }
                archive.check()?;
                checksum.check()?;
                let pending = match fit.current(0) {
                    Ok(_) => false,
                    Err(e)
                        if e.is::<capacity::GuardInFlight>()
                            || e.is::<capacity::Reprice>()
                            || (cfg!(continuity145_only) && e.is::<peer_terminal::Pending>()) =>
                    {
                        true
                    }
                    Err(e) => return Err(e),
                };
                if pending || sampled.elapsed() >= Duration::from_secs(30) {
                    self.freeze(true)?;
                    confirm(true)?;
                    self.freeze(false)?;
                    sampled = Instant::now();
                }
                thread::sleep(Duration::from_secs(3));
            }
        })();
        if result.is_err() {
            fs::write(self.leaf.join("cgroup.kill"), b"1")
                .context("kill failed publisher subtree")?;
            child.wait()?;
            self.wait_event("populated", false, Instant::now() + Duration::from_secs(5))?;
        }
        result
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        // PID1's KillMode=control-group also covers a supervisor crash or lease break.
        let _ = fs::write(self.leaf.join("cgroup.kill"), b"1");
        let _ = fs::remove_dir(&self.leaf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires a separately booked, delegated native fixture service"]
    fn freezer_covers_uploader_and_grandchild() {
        let tree = Tree::create().unwrap();
        let mut shell = tree
            .spawn(Command::new("/bin/sh").args(["-c", "sleep 60 & wait"]))
            .unwrap();
        let procs = tree.leaf.join("cgroup.procs");
        let deadline = Instant::now() + Duration::from_secs(3);
        while fs::read_to_string(&procs).unwrap().lines().count() != 2 {
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(10));
        }
        tree.freeze(true).unwrap();
        assert!(tree.event("frozen").unwrap());
        assert_eq!(fs::read_to_string(&procs).unwrap().lines().count(), 2);
        tree.freeze(false).unwrap();
        assert!(!tree.event("frozen").unwrap());
        tree.freeze(true).unwrap();
        fs::write(tree.leaf.join("cgroup.kill"), b"1").unwrap();
        assert!(!shell.wait().unwrap().success());
        tree.wait_event("populated", false, Instant::now() + Duration::from_secs(5))
            .unwrap();
    }
}
