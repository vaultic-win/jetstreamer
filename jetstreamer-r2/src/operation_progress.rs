//! Diagnostic output from existing operation loops; never an admission receipt.
use std::{
    io::{self, Write},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub(crate) struct ProgressLog<W: Write = io::Stderr> {
    sink: W,
    operation: &'static str,
    epoch: u64,
    phase: &'static str,
    started: Instant,
    started_unix_millis: u64,
    last_progress: Duration,
    last_output: Duration,
    finished: bool,
}
fn millis(value: Duration) -> u64 {
    value.as_millis().try_into().unwrap_or(u64::MAX)
}
impl ProgressLog {
    pub(crate) fn new(operation: &'static str, epoch: u64, phase: &'static str) -> Self {
        Self::with_writer(io::stderr(), operation, epoch, phase)
    }
}
impl<W: Write> ProgressLog<W> {
    fn with_writer(sink: W, operation: &'static str, epoch: u64, phase: &'static str) -> Self {
        let mut value = Self {
            sink,
            operation,
            epoch,
            phase,
            started: Instant::now(),
            started_unix_millis: millis(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default(),
            ),
            last_progress: Duration::ZERO,
            last_output: Duration::ZERO,
            finished: false,
        };
        value.emit("started", Duration::ZERO, None, None);
        value
    }
    fn emit(
        &mut self,
        event: &str,
        elapsed: Duration,
        wait: Option<&str>,
        remaining: Option<Duration>,
    ) {
        let record = serde_json::json!({
            "schema": "horizon-operation-progress-v1", "event": event,
            "operation": self.operation, "epoch": self.epoch, "phase": self.phase,
            "recorded_unix_millis": self.started_unix_millis.saturating_add(millis(elapsed)),
            "elapsed_millis": millis(elapsed),
            "last_progress_unix_millis": self.started_unix_millis.saturating_add(millis(self.last_progress)),
            "since_progress_millis": millis(elapsed.saturating_sub(self.last_progress)),
            "waiting_for": wait, "remaining_millis": remaining.map(millis),
            "observational_only": true
        });
        // A broken diagnostic sink must not change the operation's gate result.
        let _ = writeln!(self.sink, "{record}");
        let _ = self.sink.flush();
        self.last_output = elapsed;
    }
    pub(crate) fn phase(&mut self, phase: &'static str) {
        self.phase_at(phase, self.started.elapsed());
    }
    fn phase_at(&mut self, phase: &'static str, elapsed: Duration) {
        self.phase = phase;
        self.last_progress = elapsed;
        self.emit("phase", elapsed, None, None);
    }
    pub(crate) fn waiting(&mut self, condition: &'static str, remaining: Duration) {
        self.waiting_at(condition, remaining, self.started.elapsed());
    }
    pub(crate) fn wait_started(&mut self, condition: &'static str, remaining: Duration) {
        self.emit(
            "waiting",
            self.started.elapsed(),
            Some(condition),
            Some(remaining),
        );
    }
    fn waiting_at(&mut self, condition: &'static str, remaining: Duration, elapsed: Duration) {
        if elapsed.saturating_sub(self.last_output) >= Duration::from_secs(60) {
            self.emit("heartbeat", elapsed, Some(condition), Some(remaining));
        }
    }
    pub(crate) fn finish(&mut self, success: bool) {
        self.finished = true;
        self.emit(
            if success { "completed" } else { "failed" },
            self.started.elapsed(),
            None,
            None,
        );
    }
}
impl<W: Write> Drop for ProgressLog<W> {
    fn drop(&mut self) {
        if !self.finished {
            self.emit("aborted", self.started.elapsed(), None, None);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progress_heartbeat_preserves_last_advance_and_rate_limits_output() {
        let mut bytes = Vec::new();
        {
            let mut log = ProgressLog::with_writer(&mut bytes, "fixture", 207, "prepare");
            log.waiting_at(
                "guard fire",
                Duration::from_secs(240),
                Duration::from_secs(59),
            );
            log.waiting_at(
                "guard fire",
                Duration::from_secs(240),
                Duration::from_secs(60),
            );
            log.waiting_at(
                "guard fire",
                Duration::from_secs(239),
                Duration::from_secs(61),
            );
            log.phase_at("capture", Duration::from_secs(70));
            log.waiting_at(
                "guard fire",
                Duration::from_secs(100),
                Duration::from_secs(130),
            );
            log.finished = true;
        }
        let rows: Vec<serde_json::Value> = String::from_utf8(bytes)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(rows.len(), 4);
        assert_eq!(rows[1]["event"], "heartbeat");
        assert_eq!(rows[1]["since_progress_millis"], 60000);
        assert_eq!(
            rows[1]["last_progress_unix_millis"],
            rows[0]["last_progress_unix_millis"]
        );
        assert_eq!(rows[2]["phase"], "capture");
        assert_eq!(rows[3]["since_progress_millis"], 60000);
    }

    #[test]
    fn progress_unfinished_scope_reports_abort_without_claiming_completion() {
        let mut bytes = Vec::new();
        {
            let _log = ProgressLog::with_writer(&mut bytes, "fixture", 207, "capture");
        }
        let rows: Vec<serde_json::Value> = String::from_utf8(bytes)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(rows.last().unwrap()["event"], "aborted");
        assert!(rows.iter().all(|row| row["event"] != "completed"));
    }

    #[test]
    fn progress_broken_log_sink_does_not_fail_the_operation() {
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> io::Result<()> {
                Err(io::ErrorKind::BrokenPipe.into())
            }
        }
        let mut log = ProgressLog::with_writer(Broken, "fixture", 207, "prepare");
        log.phase("capture");
        log.waiting_at("guard fire", Duration::ZERO, Duration::from_secs(60));
        log.finish(true);
    }
}
