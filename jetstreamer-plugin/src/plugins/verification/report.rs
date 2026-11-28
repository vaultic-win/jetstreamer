//! Durable full-epoch playback results; remote identity is bound by the uploader.

use std::io;

/// Aggregated result from one verified epoch.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct VerificationReport {
    /// Epoch whose callbacks were verified.
    pub epoch: u64,
    /// Number of parallel plugin workers that participated.
    pub worker_count: usize,
    /// Slot notifications delivered to the plugin.
    pub slots: u64,
    /// Lowest slot actually delivered to the plugin (including leader skips).
    pub first_slot: u64,
    /// Highest slot actually delivered to the plugin (including leader skips).
    pub last_slot: u64,
    /// Non-skipped block notifications.
    pub blocks: u64,
    /// Leader-skipped slot notifications.
    pub skipped: u64,
    /// PoH entry records attached to blocks.
    pub entries: u64,
    /// Transaction callbacks.
    pub transactions: u64,
    /// Account updates attributed to transactions.
    pub transaction_updates: u64,
    /// Runtime-direct account updates attributed to blocks.
    pub orphan_updates: u64,
    /// Account updates attributed to the epoch boundary.
    pub epoch_updates: u64,
    /// Account-data bytes consumed across every update category.
    pub account_data_bytes: u64,
    /// SHA-256 over the ordered list of per-worker stream digests.
    pub stream_digest: [u8; 32],
}

impl VerificationReport {
    /// Persists a successful full-epoch plugin result without replacing evidence.
    ///
    /// This is playback evidence only. The caller must separately bind the reader
    /// artifact, remote readback identity and digest, and successful process exit.
    pub fn write_json(
        &self,
        path: &std::path::Path,
        source: &str,
        invocation: &[String],
        expected_range: (u64, u64),
    ) -> io::Result<()> {
        use std::io::Write;

        if !path.is_absolute() {
            return Err(io::Error::other(
                "verification report path must be absolute",
            ));
        }
        let (first, last) = expected_range;
        if self.first_slot != first
            || self.last_slot != last
            || last.checked_sub(first).and_then(|n| n.checked_add(1)) != Some(self.slots)
            || self.blocks.checked_add(self.skipped) != Some(self.slots)
            || self.worker_count == 0
        {
            return Err(io::Error::other(
                "verification report lacks full epoch coverage",
            ));
        }
        let payload = serde_json::json!({
            "schema": "jetstreamer-horizon-plugin-playback-v1",
            "source": source,
            "invocation": invocation,
            "expected_first_slot": first,
            "expected_last_slot": last,
            "full_epoch_verified": true,
            "report": self,
        });
        let mut bytes = serde_json::to_vec_pretty(&payload)?;
        bytes.push(b'\n');
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(path)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        std::fs::File::open(path.parent().expect("absolute file path"))?.sync_all()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report() -> VerificationReport {
        VerificationReport {
            epoch: 251,
            worker_count: 2,
            slots: 3,
            first_slot: 100,
            last_slot: 102,
            blocks: 2,
            skipped: 1,
            entries: 7,
            transactions: 8,
            transaction_updates: 9,
            orphan_updates: 10,
            epoch_updates: 11,
            account_data_bytes: 12,
            stream_digest: [13; 32],
        }
    }

    #[test]
    fn complete_report_preserves_boundaries_counts_and_invocation_without_clobber() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("playback.json");
        let args = vec!["pipeline".into(), "--verify-only".into()];
        report()
            .write_json(&path, "/readback", &args, (100, 102))
            .unwrap();
        let before = std::fs::read(&path).unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&before).unwrap();
        assert_eq!(payload["schema"], "jetstreamer-horizon-plugin-playback-v1");
        assert_eq!(payload["report"]["first_slot"], 100);
        assert_eq!(payload["report"]["last_slot"], 102);
        assert_eq!(payload["report"]["skipped"], 1);
        assert_eq!(payload["invocation"], serde_json::json!(args));
        assert_eq!(
            report()
                .write_json(&path, "/different", &[], (100, 102))
                .unwrap_err()
                .kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(std::fs::read(path).unwrap(), before);
    }

    #[test]
    fn incomplete_or_inconsistent_report_creates_no_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("playback.json");
        for mutation in 0..5 {
            let mut value = report();
            match mutation {
                0 => value.first_slot += 1,
                1 => value.last_slot -= 1,
                2 => value.slots -= 1,
                3 => value.blocks -= 1,
                _ => value.worker_count = 0,
            }
            assert!(
                value
                    .write_json(&path, "/readback", &[], (100, 102))
                    .is_err()
            );
            assert!(!path.exists());
        }
    }

    #[test]
    fn invalid_range_and_relative_path_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("playback.json");
        for range in [(102, 100), (0, u64::MAX), (101, 103)] {
            assert!(report().write_json(&path, "/readback", &[], range).is_err());
        }
        assert!(
            report()
                .write_json(
                    std::path::Path::new("relative.json"),
                    "/readback",
                    &[],
                    (100, 102)
                )
                .is_err()
        );
        assert!(!path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn existing_symlink_is_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        let path = dir.path().join("playback.json");
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(
            report()
                .write_json(&path, "/readback", &[], (100, 102))
                .is_err()
        );
        assert!(!target.exists());
    }
}
