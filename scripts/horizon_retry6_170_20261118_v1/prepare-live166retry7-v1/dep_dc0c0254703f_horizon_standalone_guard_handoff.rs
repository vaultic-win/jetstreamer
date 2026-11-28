//! Strict, finite workerless-drain proof for a bounded measurement only.
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

const MAX_BYTES: u64 = 16 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BoundedMeasurement {
    pub intent_path: PathBuf,
    pub producer_uid: u32,
    pub target_slot: u64,
    pub maximum_drain_seconds: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    schema: String,
    systemd_invocation_id: String,
    target_slot: u64,
    observed_stop_slot: u64,
    child_pid: u32,
    controlled_stop_signal: i32,
    scratch_snapshot_captured: bool,
    external_signal: Value,
    written_unix_seconds: f64,
}

impl BoundedMeasurement {
    pub fn validate(&self, worker_root: &Path) -> Result<()> {
        let parent = self
            .intent_path
            .parent()
            .context("handoff parent missing")?;
        ensure!(
            self.target_slot > 0 && (1..=900).contains(&self.maximum_drain_seconds),
            "invalid bounded measurement target/drain interval"
        );
        ensure!(
            self.intent_path.is_absolute()
                && parent.canonicalize()? == parent
                && worker_root.parent() == Some(parent)
                && self
                    .intent_path
                    .file_name()
                    .is_some_and(|name| name == "target-stop-intent.json"),
            "handoff must be a direct member of the isolated measurement root"
        );
        let metadata = fs::symlink_metadata(parent)?;
        ensure!(
            metadata.is_dir()
                && metadata.uid() == self.producer_uid
                && metadata.mode() & 0o077 == 0,
            "handoff parent must be producer-private"
        );
        Ok(())
    }

    pub fn read(&self, invocation: &str, now: u64) -> Result<Value> {
        let parent = self
            .intent_path
            .parent()
            .context("handoff parent missing")?;
        ensure!(
            parent.canonicalize()? == parent,
            "handoff parent became noncanonical"
        );
        let directory = fs::symlink_metadata(parent)?;
        ensure!(
            directory.is_dir()
                && directory.uid() == self.producer_uid
                && directory.mode() & 0o077 == 0,
            "handoff parent identity or privacy changed"
        );
        let before = fs::symlink_metadata(&self.intent_path)?;
        ensure!(
            before.is_file()
                && before.nlink() == 1
                && before.uid() == self.producer_uid
                && before.mode() & 0o7777 == 0o600
                && before.len() <= MAX_BYTES,
            "unsafe bounded target-stop intent"
        );
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&self.intent_path)?;
        let identity = |m: &fs::Metadata| {
            (
                m.dev(),
                m.ino(),
                m.len(),
                m.uid(),
                m.mode(),
                m.nlink(),
                m.mtime(),
                m.mtime_nsec(),
                m.ctime(),
                m.ctime_nsec(),
            )
        };
        ensure!(
            identity(&before) == identity(&file.metadata()?),
            "handoff replaced before read"
        );
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(MAX_BYTES + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 == before.len()
                && identity(&before) == identity(&file.metadata()?)
                && identity(&before) == identity(&fs::symlink_metadata(&self.intent_path)?),
            "handoff changed while read"
        );
        let after_directory = fs::symlink_metadata(parent)?;
        ensure!(
            directory.dev() == after_directory.dev()
                && directory.ino() == after_directory.ino()
                && directory.uid() == after_directory.uid()
                && directory.mode() == after_directory.mode()
                && parent.canonicalize()? == parent,
            "handoff parent changed while read"
        );
        let intent: Intent = serde_json::from_slice(&bytes)?;
        ensure!(
            intent.schema == "jetstreamer-historical-performance-target-stop-v1"
                && intent.systemd_invocation_id == invocation
                && intent.target_slot == self.target_slot
                && intent.observed_stop_slot >= self.target_slot
                && intent.child_pid > 0
                && intent.child_pid <= i32::MAX as u32
                && intent.controlled_stop_signal == libc::SIGINT
                && intent.scratch_snapshot_captured
                && intent.external_signal == Value::Null
                && intent.written_unix_seconds.is_finite()
                && intent.written_unix_seconds <= now as f64 + 5.0
                && now as f64 - intent.written_unix_seconds <= self.maximum_drain_seconds as f64,
            "handoff does not prove fresh invocation-bound post-target drainage"
        );
        Ok(
            json!({"path":self.intent_path,"sha256":format!("{:x}",Sha256::digest(&bytes)),
            "producer_uid":self.producer_uid,"target_slot":self.target_slot,
            "observed_stop_slot":intent.observed_stop_slot,"child_pid":intent.child_pid,
            "written_unix_seconds":intent.written_unix_seconds,"maximum_drain_seconds":self.maximum_drain_seconds}),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn fixture() -> (tempfile::TempDir, BoundedMeasurement, Value) {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let config = BoundedMeasurement {
            intent_path: root.path().join("target-stop-intent.json"),
            producer_uid: unsafe { libc::geteuid() },
            target_slot: 66577778,
            maximum_drain_seconds: 600,
        };
        let intent = json!({"schema":"jetstreamer-historical-performance-target-stop-v1",
            "systemd_invocation_id":"a".repeat(32),"target_slot":66577778,
            "observed_stop_slot":66577780,"child_pid":7,"controlled_stop_signal":2,
            "scratch_snapshot_captured":true,"external_signal":null,"written_unix_seconds":1000.25});
        (root, config, intent)
    }

    fn write(config: &BoundedMeasurement, value: &Value) {
        fs::write(&config.intent_path, value.to_string()).unwrap();
        fs::set_permissions(&config.intent_path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[test]
    fn valid_handoff_has_exact_scope_and_a_nonextendable_drain_deadline() {
        let (root, config, intent) = fixture();
        config.validate(&root.path().join("scratch")).unwrap();
        write(&config, &intent);
        config.read(&"a".repeat(32), 1001).unwrap();
        config.read(&"a".repeat(32), 1600).unwrap();
        assert!(config.read(&"a".repeat(32), 1601).is_err());
        assert!(config.read(&"b".repeat(32), 1001).is_err());
        assert!(config.validate(&root.path().join("other/scratch")).is_err());
    }

    #[test]
    fn missing_stale_foreign_pretarget_external_signal_or_unmeasured_handoff_fails() {
        let (_root, config, intent) = fixture();
        assert!(config.read(&"a".repeat(32), 1001).is_err());
        for (field, value) in [
            ("schema", json!("wrong")),
            ("systemd_invocation_id", json!("b".repeat(32))),
            ("target_slot", json!(66577779)),
            ("observed_stop_slot", json!(66577777)),
            ("observed_stop_slot", json!(66577780.0)),
            ("child_pid", json!(0)),
            ("child_pid", json!(u32::MAX)),
            ("controlled_stop_signal", json!(15)),
            ("scratch_snapshot_captured", json!(false)),
            ("external_signal", json!(15)),
            ("written_unix_seconds", json!(1007.0)),
            ("written_unix_seconds", json!(1.0)),
        ] {
            let mut bad = intent.clone();
            bad[field] = value;
            write(&config, &bad);
            assert!(config.read(&"a".repeat(32), 1001).is_err(), "{field}");
        }
        for field in intent.as_object().unwrap().keys() {
            let mut bad = intent.clone();
            bad.as_object_mut().unwrap().remove(field);
            write(&config, &bad);
            assert!(
                config.read(&"a".repeat(32), 1001).is_err(),
                "missing {field}"
            );
        }
        let mut bad = intent;
        bad["unexpected"] = json!(true);
        write(&config, &bad);
        assert!(config.read(&"a".repeat(32), 1001).is_err());
    }

    #[test]
    fn unsafe_owner_mode_links_symlink_and_oversized_inputs_fail_closed() {
        let (root, mut config, intent) = fixture();
        write(&config, &intent);
        fs::set_permissions(&config.intent_path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(config.read(&"a".repeat(32), 1001).is_err());
        fs::set_permissions(&config.intent_path, fs::Permissions::from_mode(0o600)).unwrap();
        config.producer_uid = config.producer_uid.wrapping_add(1);
        assert!(config.read(&"a".repeat(32), 1001).is_err());
        config.producer_uid = unsafe { libc::geteuid() };
        fs::hard_link(&config.intent_path, root.path().join("alias")).unwrap();
        assert!(config.read(&"a".repeat(32), 1001).is_err());
        fs::remove_file(root.path().join("alias")).unwrap();
        fs::rename(&config.intent_path, root.path().join("saved")).unwrap();
        std::os::unix::fs::symlink(root.path().join("saved"), &config.intent_path).unwrap();
        assert!(config.read(&"a".repeat(32), 1001).is_err());
        fs::remove_file(&config.intent_path).unwrap();
        fs::write(&config.intent_path, vec![b' '; MAX_BYTES as usize + 1]).unwrap();
        fs::set_permissions(&config.intent_path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(config.read(&"a".repeat(32), 1001).is_err());
    }
}
