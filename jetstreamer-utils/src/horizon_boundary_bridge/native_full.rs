//! Bind the native uploader's full PoH result to the original producer inode.
//! The acceptance names the archive path, while the terminal handoff records
//! the digest and both file identities before the uploader was started.
use super::*;
use serde_json::{json, Value};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Binding {
    acceptance_sha256: String,
    handoff: BoundFile,
    reader_plan: BoundFile,
}

fn document(bound: &BoundFile) -> Result<Value> {
    let (bytes, identity) = read_regular(Path::new(&bound.path), MAX_EVIDENCE_BYTES)?;
    ensure!(
        identity.uid == 0
            && identity.links == 1
            && u32::from_str_radix(&identity.mode, 8)? & 0o022 == 0
            && sha256(&bytes) == bound.sha256,
        "native document owner, mode or digest mismatch: {}",
        bound.path
    );
    Ok(serde_json::from_slice(&bytes)?)
}

fn producer_identity(i: &FileIdentity) -> Result<Value> {
    let seconds_nanos = |v: i128| -> Result<(i64, u32)> {
        Ok((
            v.div_euclid(1_000_000_000).try_into()?,
            v.rem_euclid(1_000_000_000).try_into()?,
        ))
    };
    let (ctime, cn) = seconds_nanos(i.changed_nanoseconds)?;
    let (mtime, mn) = seconds_nanos(i.modified_nanoseconds)?;
    Ok(
        json!({"device": i.device, "inode": i.inode, "length": i.bytes, "link_count": i.links,
        "uid": i.uid, "gid": i.gid, "mode": libc::S_IFREG | u32::from_str_radix(&i.mode, 8)?,
        "changed_seconds":ctime, "changed_nanoseconds":cn, "modified_seconds":mtime,"modified_nanoseconds":mn}),
    )
}

impl Binding {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn verify(
        &self,
        evidence: &ArchiveEvidence,
        epoch: u64,
        digest: &str,
        archive: &FileIdentity,
        sidecar: &FileIdentity,
        bytes: &[u8],
        allow: &FullReceiptAllowlist,
    ) -> Result<String> {
        ensure!(
            sha256(bytes) == self.acceptance_sha256,
            "unapproved native acceptance"
        );
        let handoff = document(&self.handoff)?;
        ensure!(
            handoff["schema"] == "horizon-singleton-delivery-handoff-v1"
                && handoff["epoch"] == epoch
                && handoff["source"]["archive"]
                    == json!({"path":evidence.archive,"sha256":digest,"identity":producer_identity(archive)?})
                && handoff["source"]["sidecar"]
                    == json!({"path":evidence.sidecar,"identity":producer_identity(sidecar)?}),
            "archive or sidecar differs from the producer handoff"
        );
        let plan = document(&self.reader_plan)?;
        let accepted: Value = serde_json::from_slice(bytes)?;
        let verifier = plan["full_verifier"]["sha256"]
            .as_str()
            .context("missing full verifier digest")?;
        let args = accepted["full_invocation"]
            .as_array()
            .context("missing full invocation")?;
        let threads = plan["threads"]
            .as_u64()
            .filter(|n| *n > 0)
            .context("invalid thread count")?;
        ensure!(
            plan["schema"] == "horizon-current-reader-plan-v1"
                && accepted["schema"] == "horizon-current-reader-local-acceptance-v1"
                && accepted["reader_plan"] == json!(self.reader_plan)
                && accepted["full_verifier"] == plan["full_verifier"]
                && allow.verifier_sha256.iter().any(|h| h == verifier)
                && accepted["full_exit_code"].as_i64() == Some(0)
                && args.starts_with(&[
                    json!(evidence.archive),
                    json!("--full"),
                    json!("--threads"),
                    json!(threads.to_string())
                ]),
            "full verifier, invocation or exit did not match the approved reader"
        );
        let expectation: BoundFile =
            serde_json::from_value(plan["epoch_expectations"][epoch.to_string()].clone())?;
        let expected = document(&expectation)?;
        let slot = |key: &str| -> Result<Value> {
            Ok(json!(expected[key]
                .as_u64()
                .context("missing expected slot")?
                .to_string()))
        };
        let hash = |key: &str| -> Result<Value> {
            Ok(json!(expected[key]
                .as_str()
                .filter(|h| !h.is_empty())
                .context("missing expected hash")?))
        };
        ensure!(
            expected["schema"] == "horizon-current-reader-epoch-expectation-v1"
                && expected["epoch"] == epoch,
            "wrong epoch expectation"
        );
        let mut tail = vec![
            json!("--anchor"),
            slot("parent_slot")?,
            hash("parent_blockhash")?,
            json!("--expected-terminal"),
            slot("terminal_slot")?,
            hash("terminal_blockhash")?,
        ];
        if !expected["successor"].is_null() {
            let successor_slot = expected["successor"]["slot"]
                .as_u64()
                .context("missing successor slot")?;
            tail.extend([
                json!("--expected-successor"),
                json!(successor_slot.to_string()),
                slot("terminal_slot")?,
                hash("terminal_blockhash")?,
            ]);
        }
        if !expected["provenance_sha256"].is_null() {
            tail.extend([
                json!("--expected-provenance-sha256"),
                hash("provenance_sha256")?,
            ]);
        }
        ensure!(
            args[4..] == tail,
            "anchored full verification arguments differ"
        );
        let parent = evidence
            .full_receipt
            .parent()
            .context("missing acceptance directory")?;
        let scratch = plan["scratch_directory"]
            .as_str()
            .context("missing scratch directory")?;
        let run_name = parent
            .file_name()
            .and_then(|n| n.to_str())
            .context("invalid native run directory")?;
        let (pid, timestamp) = run_name
            .strip_prefix(&format!("epoch-{epoch}-"))
            .and_then(|s| s.split_once('-'))
            .context("foreign native run directory")?;
        let start_ns: u64 = timestamp.parse()?;
        ensure!(
            parent.parent() == Some(Path::new(scratch))
                && pid.parse::<u32>()? > 0
                && archive.changed_nanoseconds <= i128::from(start_ns)
                && sidecar.changed_nanoseconds <= i128::from(start_ns),
            "artifact changed since the native verification began"
        );
        let plugin = &accepted["local_playback"];
        let report: BoundFile = serde_json::from_value(plugin["report_binding"].clone())?;
        ensure!(
            Path::new(&report.path) == parent.join("local-plugin.json")
                && document(&report)? == plugin["report"],
            "local plugin report binding mismatch"
        );
        ensure!(
            plugin["process_exit_code"].as_i64() == Some(0)
                && plugin["report"]["full_epoch_verified"] == true
                && plugin["report"]["source"] == json!(evidence.archive.parent())
                && plugin["report"]["report"]["epoch"] == epoch
                && plugin["pipeline"] == plan["pipeline"],
            "native plugin archive, pipeline or completion mismatch"
        );
        Ok(verifier.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn producer_identity_preserves_nanoseconds_and_file_type() {
        let id = FileIdentity {
            device: 1,
            inode: 2,
            bytes: 17,
            modified_nanoseconds: 1_987_654_321,
            changed_nanoseconds: 2_123_456_789,
            links: 1,
            uid: 1000,
            gid: 1000,
            mode: "0440".into(),
        };
        assert_eq!(
            producer_identity(&id).unwrap(),
            json!({
                "device":1,"inode":2,"length":17,"link_count":1,"uid":1000,"gid":1000,
                "mode":0o100440,"changed_seconds":2,"changed_nanoseconds":123456789,
                "modified_seconds":1,"modified_nanoseconds":987654321
            })
        );
    }
}
