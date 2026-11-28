//! Exactly one new full transfer for the inspected untyped HTTP status rejection.
//! Bind the original authenticated identity and cleanup from the root-owned audit state.
use super::*;
pub(super) const RESULT: &str = "d05c0f397a4b4c96a16454869bb0834135735a931136ee9a0ce3ba88393daa9c";
const ATTEMPT: &str = "epoch-90-1795179901632621427";
const ERROR: &str = "GET exact pinned archive range: response error: horizon-audit-exact-range-response read_before_deserialization interceptor encountered an error: range GET requires HTTP206";
const IDENTITY: &str = "c3cd3fb22c8c91e1b1ee793eb49c2a11b91618bbd7a68c10ced1f72cc0636381";
const PLAN: &str = "4def85b7653fc18284b31d1adddf011df315e82c634fdbfc1cb8f689821ed028";
const CLEANUP: &str = "4e9c2ca9ea26023f416e9d6828e0124be79f49a64217932e9788804ae632f2b3";
pub(super) fn eligible(result: &Outcome, hash: &str) -> bool {
    hash == RESULT
        && result.epoch == 90
        && result.status == "failed"
        && result.object.epoch == 90
        && result.object.key == "epoch-90.jet"
        && result.object.etag == "\"66b96fa28d94fbdfb445351a4db83861-6315\""
        && result.object.bytes == 33_103_735_008
        && result.retry_of.is_none()
        && result.transfer_interruption.is_none()
        && result.download.is_none()
        && result.playback.is_none()
        && result.invocation.is_empty()
        && !result.remote_mutations
        && result.error.as_deref() == Some(ERROR)
        && result.attempt.file_name().is_some_and(|s| s == ATTEMPT)
}
fn bound(dir: &Path, name: &str, sha: &str) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    open_read(&dir.join(name))?
        .take(8193)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 8192 && digest(&bytes) == sha,
        "epoch90 original {name} differs"
    );
    Ok(bytes)
}
pub(super) fn evidence(result: &Outcome) -> Result<TransferIdentity> {
    let id: TransferIdentity =
        serde_json::from_slice(&bound(&result.attempt, "download-identity.json", IDENTITY)?)?;
    ensure!(
        id.object == result.object,
        "epoch90 original identity differs"
    );
    // Digests bind the matching 494-range plan and the completed private scratch cleanup.
    bound(&result.attempt, "range-transfer-plan.json", PLAN)?;
    bound(&result.attempt, "cleanup.json", CLEANUP)?;
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote::Object;
    #[test]
    fn specific_legacy_failure_is_never_reconstructed_from_error_text_alone() {
        let mut out = Outcome {
            schema: "horizon-r2-chronological-plugin-audit-result-v1".into(),
            epoch: 90,
            status: "failed".into(),
            object: Object {
                epoch: 90,
                key: "epoch-90.jet".into(),
                etag: "\"66b96fa28d94fbdfb445351a4db83861-6315\"".into(),
                bytes: 33_103_735_008,
            },
            attempt: PathBuf::from(ATTEMPT),
            started_at: 1,
            finished_at: 2,
            download: None,
            reader: None,
            playback: None,
            invocation: vec![],
            error: Some(ERROR.into()),
            transfer_interruption: None,
            retry_of: None,
            remote_mutations: false,
        };
        assert!(eligible(&out, RESULT));
        assert!(!eligible(&out, &"a".repeat(64)));
        out.invocation.push("plugin".into());
        assert!(!eligible(&out, RESULT));
        out.invocation.clear();
        out.object.bytes -= 1;
        assert!(!eligible(&out, RESULT));
    }
    #[test]
    fn different_or_oversize_evidence_cannot_authorize_a_ticket() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("evidence");
        fs::write(&f, b"proof").unwrap();
        assert_eq!(
            bound(d.path(), "evidence", &digest(b"proof")).unwrap(),
            b"proof"
        );
        assert!(bound(d.path(), "evidence", &digest(b"old")).is_err());
        let b = vec![0; 8193];
        fs::write(f, &b).unwrap();
        assert!(bound(d.path(), "evidence", &digest(&b)).is_err());
    }
    #[test]
    #[ignore = "privileged, read-only inspection of the authentic epoch90 audit predecessor"]
    fn authentic_predecessor_selects_one_pinned_transfer() {
        let state = Path::new("/var/lib/jetstreamer/r2-chronological-plugin-audit-20261118-v1");
        let cfg: Config = read_json(&state.join("accepted-config.json")).unwrap();
        let inv: crate::remote::Inventory = read_json(&state.join("inventory.json")).unwrap();
        let obj = inv.objects.iter().find(|o| o.epoch == 90).unwrap();
        let v = view(&cfg, obj).unwrap().unwrap();
        assert_eq!(v.original_sha256, RESULT);
        assert_eq!(v.retry_limit(), 1);
        assert!(v.retry_available());
        let id = prior_identity(&v).unwrap().unwrap();
        assert_eq!(
            id.sidecar_sha256.as_deref(),
            Some("1a888b66ed5fe43f805ef9fbd6e1d672f7a67f8093b6445565fbc6521243265b")
        );
        assert_eq!(
            id.sidecar_etag.as_deref(),
            Some("\"36bfc9accc0636dee99abd4ca3e215fb\"")
        );
        assert_eq!(
            cfg.download_capacity_requirements(obj.bytes, 0).unwrap(),
            (33_271_507_168, 0)
        );
        assert_eq!(obj.bytes.div_ceil(crate::range::RANGE_BYTES), 494);
    }
}
