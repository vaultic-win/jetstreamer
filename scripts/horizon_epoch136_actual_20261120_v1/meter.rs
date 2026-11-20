//! One in-flight scan. Pending or late results are unavailable, never a byte estimate.
use super::*;
use anyhow::bail;
use std::sync::mpsc::{self, Receiver, TryRecvError};

const MAX_SCAN_TIME: Duration = Duration::from_secs(30);
#[cfg(test)]
type NativeBlockedFixture = (Pending, mpsc::SyncSender<()>, Receiver<()>, Receiver<()>);
pub(super) struct Pending {
    started: Instant,
    result: Receiver<(Duration, Result<root_budget::Observation>)>,
}
impl Pending {
    #[cfg(test)]
    pub(super) fn native_blocked_fixture(
        root: PathBuf,
        maximum: u64,
    ) -> Result<NativeBlockedFixture> {
        let (release, blocked) = mpsc::sync_channel(1);
        let (entered, entering) = mpsc::sync_channel(1);
        let (finished, finishing) = mpsc::sync_channel(1);
        let pending = Self::start(move || {
            entered.send(()).context("fixture entered")?;
            blocked.recv().context("fixture released")?;
            let result = root_budget::observe(&root, maximum);
            let _ = finished.send(());
            result
        })?;
        Ok((pending, release, entering, finishing))
    }
    #[cfg(test)]
    pub(super) fn native_failure_fixture(kind: &str) -> Self {
        let (sender, result) = mpsc::sync_channel(1);
        let started = Instant::now();
        match kind {
            "error" => sender
                .send((
                    Duration::ZERO,
                    Err(anyhow::anyhow!("native fixture scan error")),
                ))
                .unwrap(),
            "late" => sender
                .send((MAX_SCAN_TIME, Err(anyhow::anyhow!("late fixture"))))
                .unwrap(),
            "disconnected" | "timeout" => (),
            _ => panic!("unknown native failure fixture"),
        }
        drop(sender);
        Self {
            started: if kind == "timeout" {
                started - MAX_SCAN_TIME
            } else {
                started
            },
            result,
        }
    }
    pub(super) fn begin(root: PathBuf, maximum: u64) -> Result<Self> {
        Self::start(move || root_budget::observe(&root, maximum))
    }
    fn start(
        scan: impl FnOnce() -> Result<root_budget::Observation> + Send + 'static,
    ) -> Result<Self> {
        let started = Instant::now();
        let (sender, result) = mpsc::sync_channel(1);
        thread::Builder::new()
            .name("epoch136-suffix-physical".into())
            .spawn(move || {
                let observed = scan();
                let _ = sender.send((started.elapsed(), observed));
            })?;
        Ok(Self { started, result })
    }
    #[cfg(test)]
    pub(super) fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }
    pub(super) fn poll(&self) -> Result<Option<root_budget::Observation>> {
        self.poll_at(Instant::now())
    }
    fn poll_at(&self, now: Instant) -> Result<Option<root_budget::Observation>> {
        ensure!(
            now.duration_since(self.started) < MAX_SCAN_TIME,
            "physical metering unavailable: asynchronous scan deadline exceeded"
        );
        match self.result.try_recv() {
            Ok((elapsed, result)) => {
                ensure!(
                    elapsed < MAX_SCAN_TIME,
                    "physical metering unavailable: scan completed after its deadline"
                );
                result.map(Some)
            }
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => {
                bail!("physical metering unavailable: scanner disconnected")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pending_scan_never_yields_a_cached_or_zero_measurement_and_times_out() {
        let (_sender, result) = mpsc::sync_channel(1);
        let started = Instant::now();
        let pending = Pending { started, result };
        assert!(pending.poll_at(started).unwrap().is_none());
        let error = pending
            .poll_at(started + MAX_SCAN_TIME)
            .unwrap_err()
            .to_string();
        assert!(error.contains("unavailable"));
    }
    #[test]
    fn failed_disconnected_and_late_scans_never_become_complete_measurements() {
        for (kind, expected) in [
            ("error", "fixture scan error"),
            ("late", "completed after its deadline"),
            ("disconnected", "disconnected"),
            ("timeout", "asynchronous scan deadline exceeded"),
        ] {
            let pending = Pending::native_failure_fixture(kind);
            let error = pending.poll().unwrap_err().to_string();
            assert!(error.contains(expected), "{kind}: {error}");
        }
    }
    #[test]
    fn complete_timely_measurement_is_the_only_result_released_to_the_guard() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("owned"), vec![1; 8192]).unwrap();
        let measured = root_budget::observe(temp.path(), 1 << 20).unwrap();
        let bytes = measured.conservative_physical_bytes;
        let started = Instant::now();
        let (sender, result) = mpsc::sync_channel(1);
        sender.send((Duration::ZERO, Ok(measured))).unwrap();
        let pending = Pending { started, result };
        assert_eq!(
            pending
                .poll_at(started)
                .unwrap()
                .unwrap()
                .conservative_physical_bytes,
            bytes
        );
        assert!(pending.poll_at(started).unwrap().is_none());
    }
    #[test]
    fn blocked_scan_runs_off_the_supervisor_path_until_released() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().to_path_buf();
        let (pending, release, entered, finished) =
            Pending::native_blocked_fixture(root, 1 << 20).unwrap();
        entered.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(pending.poll().unwrap().is_none());
        assert!(pending.elapsed() < MAX_SCAN_TIME);
        release.send(()).unwrap();
        finished.recv_timeout(Duration::from_secs(5)).unwrap();
        let (elapsed, result) = pending.result.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(elapsed < MAX_SCAN_TIME);
        assert!(!result.unwrap().exceeds_budget);
    }
}
