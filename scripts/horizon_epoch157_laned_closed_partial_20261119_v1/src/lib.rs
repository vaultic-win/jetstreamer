//! Exact old lane-d partial only. Never a canonical publication or retirement tool.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

pub const RUN: &str = "/home/sol/.jetstreamer-private/epochs150-173-20260923-v2/lane-d/private/destination-0b7ad71c41faf6eb847f0327cab4c67067e2b6ff55be1f2ab499ca6787159dcc/work/root-cohort-157-157/run-642701-1790799438469365438";
pub const SOURCE: &str = concat!(
    "/home/sol/.jetstreamer-private/epochs150-173-20260923-v2/lane-d/private/destination-0b7ad71c41faf6eb847f0327cab4c67067e2b6ff55be1f2ab499ca6787159dcc/work/root-cohort-157-157/run-642701-1790799438469365438",
    "/archives/epoch-157.jet"
);
pub const SNAPSHOT: &str = concat!(
    "/home/sol/.jetstreamer-private/epochs150-173-20260923-v2/lane-d/private/destination-0b7ad71c41faf6eb847f0327cab4c67067e2b6ff55be1f2ab499ca6787159dcc/work/root-cohort-157-157/run-642701-1790799438469365438",
    "/inputs/snapshot-67823809-2mfgWDcrXmDMRrPtUJtJgE1oJ9jKgRZ9ETru9XjsdmuF.tar.zst"
);
pub const PRODUCER: &str =
    "jetstreamer-root-sweep-historical-151-173-v91-e157-157-lane-d-63.service";
pub const LENGTH: u64 = 122_379_391_003;
pub const SCHEMA: &str = "horizon-epoch157-laned-closed-partial-inspection-v1";
pub const INSPECTION: &str =
    "/var/lib/jetstreamer/epoch157-laned-holding-review-20261119-v1/INSPECTION.json";
pub const PLAN_ROOT: &str = "/var/lib/jetstreamer/epoch157-laned-holding-plan-20261119-v1";
pub const PLAN_DEST: &str =
    "/usr/local/lib/jetstreamer/horizon-closed157-laned-holding-plan-20261119-v1";
pub const SNAPSHOT_UNIT: &str =
    "/etc/systemd/system/horizon-epoch157-bootstrap-revalidate-20261012-v2.service";
pub const PINS_PATH: &str =
    "/usr/local/lib/jetstreamer/horizon-private152-hash-source-20261113-v4/creator-pins.json";
pub const PINS_SHA: &str = "559778bcebc7c7e0ca63c894d4e5004fd578518ae1650436c3f8b7693812d645";
pub const REVIEW_PATH: &str =
    "/usr/local/lib/jetstreamer/horizon-private152-hash-source-20261113-v4/creator-review.json";
pub const REVIEW_SHA: &str = "93423facc65a6693e18625a2e397d60874221b5e8962d52296ce0eb966cbc5ec";

pub fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
pub fn digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
pub fn identity(m: &fs::Metadata) -> Value {
    json!([
        m.dev(),
        m.ino(),
        m.len(),
        m.blocks(),
        m.uid(),
        m.gid(),
        m.mode(),
        m.nlink(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec()
    ])
}
pub fn expected_source() -> Value {
    json!([
        64512, 99418151, LENGTH, 239022640, 1001, 1003, 33152, 1, 1791080938, 139629319,
        1791080938, 139629319
    ])
}
pub fn expected_snapshot() -> Value {
    json!([
        64512, 99418792, 1663314014, 3248672, 1001, 1003, 33152, 1, 1790799461, 181574643,
        1790799462, 272581851
    ])
}
pub fn exact_source() -> Result<Value> {
    let p = Path::new(SOURCE);
    ensure!(p.canonicalize()? == p, "source alias");
    let m = fs::symlink_metadata(p)?;
    ensure!(
        m.is_file() && identity(&m) == expected_source(),
        "exact source identity changed"
    );
    // lstat detects a dangling sidecar symlink as occupied too.
    match fs::symlink_metadata(format!("{SOURCE}.sha256")) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => return Err(e.into()),
        Ok(_) => anyhow::bail!("unexpected canonical readiness sidecar"),
    }
    Ok(identity(&m))
}
pub fn preserved_snapshot() -> Result<Value> {
    let p = Path::new(SNAPSHOT);
    ensure!(p.canonicalize()? == p, "snapshot alias");
    let m = fs::symlink_metadata(p)?;
    ensure!(
        m.is_file() && identity(&m) == expected_snapshot(),
        "preserved sibling snapshot changed"
    );
    Ok(identity(&m))
}
pub fn small(path: &Path, root_owned: bool) -> Result<Vec<u8>> {
    ensure!(path.canonicalize()? == path, "metadata alias");
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file()
            && m.nlink() == 1
            && m.mode() & 0o022 == 0
            && (!root_owned || m.uid() == 0)
            && m.len() <= 2 << 20,
        "unsafe metadata"
    );
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut f)
        .take((2 << 20) + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == m.len()
            && identity(&m) == identity(&f.metadata()?)
            && identity(&m) == identity(&fs::symlink_metadata(path)?),
        "metadata changed"
    );
    Ok(bytes)
}
pub fn bound(path: &str, expected_sha: &str) -> Result<Vec<u8>> {
    ensure!(digest(expected_sha), "invalid expected metadata digest");
    let bytes = small(Path::new(path), true)?;
    ensure!(
        sha(&bytes) == expected_sha,
        "metadata digest changed: {path}"
    );
    Ok(bytes)
}
pub fn empty_root(path: &Path) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_dir()
            && m.uid() == 0
            && m.mode() & 0o7777 == 0o700
            && path.canonicalize()? == path
            && fs::read_dir(path)?.next().is_none(),
        "empty root-owned 0700 metadata directory required"
    );
    Ok(())
}
pub fn save(path: &Path, value: &Value) -> Result<Value> {
    let parent = path.parent().context("receipt parent")?;
    let m = fs::symlink_metadata(parent)?;
    ensure!(
        m.is_dir()
            && m.uid() == 0
            && m.mode() & 0o7777 == 0o700
            && parent.canonicalize()? == parent,
        "unsafe receipt parent"
    );
    let bytes = serde_json::to_vec_pretty(value)?;
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    f.write_all(&bytes)?;
    f.sync_all()?;
    File::open(parent)?.sync_all()?;
    Ok(json!({"path":path,"sha256":sha(&bytes)}))
}
pub fn validate_inspection(i: &Value, current_time: u64) -> Result<&str> {
    let hash = i["sha256"]
        .as_str()
        .context("missing actual archive hash")?;
    let timestamp = i["recorded_unix_seconds"]
        .as_u64()
        .context("inspection time")?;
    ensure!(
        digest(hash) && current_time >= timestamp && current_time - timestamp <= 3600,
        "invalid digest or stale/future inspection"
    );
    ensure!(
        i["schema"] == SCHEMA
            && i["source"] == SOURCE
            && i["length"] == LENGTH
            && i["source_identity"] == expected_source()
            && i["snapshot_identity"] == expected_snapshot()
            && i["source_stable"] == true
            && i["native_consumers_clear"] == true
            && i["creator_fence_held_across_hash"] == true
            && i["original_process_absent"] == true
            && i["historical_stop_proven"] == false
            && i["original_invocation_id"].is_null()
            && i["complete_transitive_consumer_graph_qualified"] == false
            && i["local_retirement_authorized"] == false
            && i["canonical_publication_authorized"] == false
            && i["resource_credit_bytes"] == 0,
        "exact fenced inspection required"
    );
    Ok(hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn accepted() -> Value {
        json!({"schema":SCHEMA,"source":SOURCE,"length":LENGTH,"source_identity":expected_source(),"snapshot_identity":expected_snapshot(),"sha256":"a".repeat(64),"recorded_unix_seconds":100,"source_stable":true,"native_consumers_clear":true,"creator_fence_held_across_hash":true,"original_process_absent":true,"historical_stop_proven":false,"original_invocation_id":null,"complete_transitive_consumer_graph_qualified":false,"local_retirement_authorized":false,"canonical_publication_authorized":false,"resource_credit_bytes":0})
    }
    #[test]
    fn binds_exact_partial_not_runtime_segment() {
        let mut i = accepted();
        assert!(validate_inspection(&i, 101).is_ok());
        i["source"] = json!(
            "/home/sol/.jetstreamer-private/epochs150-173-20260923-v2/lane-j/output/.epoch-157.jet.runtime-segments/epoch-157.segment-00-67824000-68140177.jet"
        );
        assert!(validate_inspection(&i, 101).is_err());
    }
    #[test]
    fn missing_or_occupied_fence_denied() {
        for key in [
            "native_consumers_clear",
            "creator_fence_held_across_hash",
            "original_process_absent",
            "source_stable",
        ] {
            let mut i = accepted();
            i[key] = json!(false);
            assert!(validate_inspection(&i, 101).is_err());
        }
    }
    #[test]
    fn no_historical_terminal_or_retirement_authority_invented() {
        for key in [
            "historical_stop_proven",
            "local_retirement_authorized",
            "canonical_publication_authorized",
            "complete_transitive_consumer_graph_qualified",
        ] {
            let mut i = accepted();
            i[key] = json!(true);
            assert!(validate_inspection(&i, 101).is_err());
        }
    }
    #[test]
    fn digest_and_time_are_required() {
        let mut i = accepted();
        assert!(validate_inspection(&i, 99).is_err());
        assert!(validate_inspection(&i, 3701).is_err());
        i["sha256"] = Value::Null;
        assert!(validate_inspection(&i, 101).is_err());
    }
    #[test]
    fn preserved_sibling_cannot_be_substituted() {
        let mut i = accepted();
        i["snapshot_identity"][1] = json!(0);
        assert!(validate_inspection(&i, 101).is_err());
    }
}
