//! Metadata-only equivalent of node/segment_manifest.rs V1. No archive read or
//! worker/ABI/runtime qualification. Original bytes remain in the manifest.
use super::*;

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Admission {
    Verified,
    Candidate,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Runtime {
    generation_profile: String,
    runtime_profile: String,
    runtime_admission: Admission,
    runtime_revision: String,
    runtime_toolchain: String,
    runtime_target: String,
    genesis_hash: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    slot: u64,
    bank_hash: String,
    accounts_hash: String,
    last_blockhash: String,
    capitalization: u64,
    transaction_count: u64,
    tick_height: u64,
    slot_complete: bool,
    write_count: u64,
    next_write_version: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawVersions {
    start: u64,
    end: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoricalSegmentManifest {
    schema_version: u32,
    epoch: u64,
    output_slot_start: u64,
    output_slot_count: u64,
    runtime: Runtime,
    worker_executable_sha256: String,
    archive_sha256: String,
    #[serde(default)]
    bootstrap_archive_sha256: Option<String>,
    bootstrap: Checkpoint,
    terminal: Checkpoint,
    emitted_raw_write_versions: RawVersions,
}
fn hash(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty() && value.len() <= 44,
        "segment hash text bound"
    );
    let bytes = bs58::decode(value).into_vec().map_err(|error| anyhow::anyhow!("invalid segment hash: {error}"))?;
    ensure!(
        bytes.len() == 32 && bs58::encode(&bytes).into_string() == value,
        "noncanonical segment consensus hash"
    );
    Ok(())
}
fn checkpoint(c: &Checkpoint) -> Result<()> {
    ensure!(c.slot_complete, "incomplete segment checkpoint");
    hash(&c.bank_hash)?;
    hash(&c.accounts_hash)?;
    hash(&c.last_blockhash)?;
    // These are exact integers retained by the typed schema, not floating point.
    let _ = (
        c.capitalization,
        c.transaction_count,
        c.tick_height,
        c.write_count,
    );
    Ok(())
}
pub(super) fn validate(bytes: &[u8], a: Artifact, archive_sha: &str) -> Result<()> {
    ensure!(
        bytes.len() as u64 <= MAX_METADATA,
        "oversized historical segment"
    );
    let m: HistoricalSegmentManifest = serde_json::from_slice(bytes)?;
    ensure!(
        m.schema_version == 1
            && m.epoch == a.epoch()
            && m.archive_sha256 == archive_sha
            && archive_sha == a.sha()
            && digest(&m.archive_sha256)
            && digest(&m.worker_executable_sha256)
            && m.output_slot_count > 0,
        "segment schema/epoch/archive digest differs"
    );
    if let Some(sha) = &m.bootstrap_archive_sha256 {
        ensure!(
            digest(sha) && sha.as_str() != "0".repeat(64),
            "invalid optional bootstrap digest"
        );
    }
    for s in [
        &m.runtime.generation_profile,
        &m.runtime.runtime_profile,
        &m.runtime.runtime_revision,
        &m.runtime.runtime_toolchain,
        &m.runtime.runtime_target,
    ] {
        ensure!(
            !s.is_empty() && s.len() <= 1024,
            "historical segment runtime identity text bound"
        );
    }
    let _ = &m.runtime.runtime_admission;
    hash(&m.runtime.genesis_hash)?;
    checkpoint(&m.bootstrap)?;
    checkpoint(&m.terminal)?;
    let end = m
        .output_slot_start
        .checked_add(m.output_slot_count)
        .context("segment slot range overflow")?;
    ensure!(
        m.bootstrap.slot < m.output_slot_start
            && m.terminal.slot >= m.bootstrap.slot
            && m.terminal.slot < end
            && m.terminal.next_write_version >= m.bootstrap.next_write_version,
        "segment checkpoint/span ordering differs"
    );
    let r = &m.emitted_raw_write_versions;
    ensure!(
        r.start <= r.end
            && r.end == m.terminal.next_write_version
            && (if r.start == r.end {
                r.start == m.terminal.next_write_version
            } else {
                r.start >= m.bootstrap.next_write_version
            }),
        "segment raw write-version range differs"
    );
    Ok(())
}

#[cfg(test)]
pub(super) fn fixture(a: Artifact) -> &'static [u8] {
    match a {
        Artifact::ThroughRoot206 => include_bytes!("test-data/closed-private-206.segment.json"),
        Artifact::Original225 => include_bytes!("test-data/closed-private-225.segment.json"),
        _ => panic!("fixture only covers the two required historical segment profiles"),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_historical_schema_binds_epoch_digest_and_all_nested_fields() {
        for a in [Artifact::ThroughRoot206, Artifact::Original225] {
            validate(fixture(a), a, a.sha()).unwrap();
            let original: Value = serde_json::from_slice(fixture(a)).unwrap();
            for (pointer, value) in [
                ("/epoch", json!(999)),
                ("/archive_sha256", json!("f".repeat(64))),
                ("/schema_version", json!(2)),
                ("/output_slot_count", json!(0)),
                ("/terminal/slot_complete", json!(false)),
                ("/runtime/genesis_hash", json!("foreign")),
                ("/emitted_raw_write_versions/end", json!(0)),
            ] {
                let mut bad = original.clone();
                *bad.pointer_mut(pointer).unwrap() = value;
                assert!(validate(&serde_json::to_vec(&bad).unwrap(), a, a.sha()).is_err());
            }
            for pointer in [
                "",
                "/runtime",
                "/bootstrap",
                "/terminal",
                "/emitted_raw_write_versions",
            ] {
                let mut bad = original.clone();
                let v = if pointer.is_empty() {
                    &mut bad
                } else {
                    bad.pointer_mut(pointer).unwrap()
                };
                v.as_object_mut()
                    .unwrap()
                    .insert("credentials".into(), json!("forbidden unknown field"));
                assert!(validate(&serde_json::to_vec(&bad).unwrap(), a, a.sha()).is_err());
            }
        }
        assert!(
            validate(
                br#"{"diagnostic_only":true}"#,
                Artifact::ThroughRoot206,
                Artifact::ThroughRoot206.sha()
            )
            .is_err()
        );
    }
}
