//! Exact accepted success-receipt grammar, copied from the qualified progressive
//! gates (exact_words/gate_receipt_matches/boundary_receipt_matches). These pins
//! are independently recorded in the existing immutable cold130 eligibility.
use crate::{CANONICAL_SHA, bound, raw, s, sha};
use anyhow::{Result, ensure};
use serde_json::Value;
use std::path::Path;
const FULL: (&str, &str, &str, &str) = (
    "/home/sol/.jetstreamer-private/final-audits/epochs-101-200-parallel-v1/receipts/epoch-130.full.ok",
    "7bddfffc6a6f2074238875b992bdf2f8211d02b921a58006a086bcc50524c338",
    "51bb4a90dcac0a2475b46b2820470c3a53a0a541720a233dac288934cc864336",
    "a64fed21248715b2214292ea961a82afc5367a34b337d35afdbbc48d62c04bed",
);
const PLUGIN: (&str, &str, &str, &str) = (
    "/home/sol/.jetstreamer-private/horizon-plugin-current-101-200-v2/receipts/epoch-130.plugin.ok",
    "2aa15b0aafe3d2140cce85fb1990a3717e28e485ddb70699ee889a2575fb4d82",
    "9f4abe27011b04d0c33cb3e24d0d9bc14dbce9f46528f22c4bde367af97a7070",
    "738cc186a6d701d051c7c2b84371f023aee69ffc25fc208c0eab7bb85f05c2cf",
);
const LEFT: (&str, &str, &str) = (
    "/home/sol/.jetstreamer-private/horizon-boundary-audit-101-200-v1/receipts/boundary-129-130.ok",
    "ff1fee70213fe3daa3d28e318e448057dbfe36fe0c51ffbe792f54b262615e05",
    "0351ba9d23802432759058d038b48fe8586ad747f6e17178e22e344ad25327aa",
);
const RIGHT: (&str, &str, &str) = (
    "/home/sol/.jetstreamer-private/horizon-boundary-audit-101-200-v1/receipts/boundary-130-131.ok",
    "93449d97e3c357567ba391eb9300a17e1b5ce6181ce2d23877e375c84cdd10ce",
    "05fd174fca4eeb966817b82cec473cd9b303be9485bf1e8a83d3b7dff0cd14b2",
);
const BINARY: &str = "2cd38370fc4087ac0f01c0c9429296757affc4317a694be868b1553b627ddfc3";
const SCRIPT: &str = "24de5d678f6723d28b1161f4904119ff5952d7ba92a1b794ead32efd03058e80";
pub(crate) fn words(bytes: &[u8], count: usize) -> Result<Vec<&str>> {
    let text = std::str::from_utf8(bytes)?;
    ensure!(
        text.ends_with('\n') && !text[..text.len() - 1].contains('\n'),
        "canonical success receipt must have exactly one terminated line"
    );
    let fields: Vec<_> = text[..text.len() - 1].split(' ').collect();
    ensure!(
        fields.len() == count
            && fields.iter().all(|s| s.len() == 64
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))),
        "canonical success receipt word grammar differs"
    );
    Ok(fields)
}
fn exact_binding(binding: &Value, path: &str, digest: &str) -> Result<Vec<u8>> {
    ensure!(
        s(binding, "path")? == path && s(binding, "sha256")? == digest,
        "foreign canonical success receipt binding"
    );
    let bytes = raw(Path::new(path), 4096, false)?;
    ensure!(sha(&bytes) == digest, "canonical receipt bytes differ");
    Ok(bytes)
}
pub(crate) fn validate(p: &Value) -> Result<()> {
    let b = &p["canonical_R2_receipt"];
    ensure!(
        s(b, "path")? == "/home/sol/.jetstreamer-private/r2-receipts/epoch-130.r2.json"
            && s(b, "sha256")?
                == "44f1fcb628e4674acdf5e523bbc776042bf16ff9ed7b29c2b8fe10f4af9fc522",
        "canonical durable receipt pin differs"
    );
    let r = bound(b)?;
    ensure!(
        r["schema"] == "jetstreamer-horizon-r2-receipt-v1"
            && r["bucket"] == "solana-archive-with-accounts-data"
            && r["epoch"] == 130
            && r["archive_sha256"] == CANONICAL_SHA
            && r["archive_length"] == 83_405_061_082u64
            && r["archive_key"] == "epoch-130.jet"
            && r["checksum_key"] == "epoch-130.jet.sha256"
            && r["remote_sha256_readback"] == true
            && r["archive_etag"] == "73d501e604900b1c9a079d9453459a52-1243"
            && r["verified_unix_seconds"] == 1791483748u64,
        "canonical durable completion semantics differ"
    );
    for (key, pin) in [("canonical_full", FULL), ("canonical_plugin", PLUGIN)] {
        let bytes = exact_binding(&p[key], pin.0, pin.1)?;
        validate_gate(&bytes, CANONICAL_SHA, pin.2, pin.3)?;
    }
    for (key, pin, left) in [
        ("canonical_left_boundary", LEFT, true),
        ("canonical_right_boundary", RIGHT, false),
    ] {
        let bytes = exact_binding(&p[key], pin.0, pin.1)?;
        let fields = words(&bytes, 4)?;
        ensure!(
            fields[2] == BINARY && fields[3] == SCRIPT,
            "boundary verifier/wrapper differs"
        );
        ensure!(
            if left {
                fields[0] == pin.2 && fields[1] == CANONICAL_SHA
            } else {
                fields[0] == CANONICAL_SHA && fields[1] == pin.2
            },
            "canonical adjacent boundary positions differ"
        );
    }
    Ok(())
}
fn validate_gate(bytes: &[u8], archive: &str, binary: &str, script: &str) -> Result<()> {
    let fields = words(bytes, 3)?;
    ensure!(
        fields == [archive, binary, script],
        "canonical archive/verifier/wrapper success tuple differs"
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn accepts_exact_success_grammar_only() {
        let line = format!("{CANONICAL_SHA} {} {}\n", FULL.2, FULL.3);
        validate_gate(line.as_bytes(), CANONICAL_SHA, FULL.2, FULL.3).unwrap();
        for bad in [
            format!("failure {CANONICAL_SHA}\n"),
            format!("{line}{line}"),
            line.trim_end().to_owned(),
            line.replace(' ', "  "),
            format!("{} {CANONICAL_SHA} {}\n", FULL.2, FULL.3),
        ] {
            assert!(validate_gate(bad.as_bytes(), CANONICAL_SHA, FULL.2, FULL.3).is_err());
        }
    }
    #[test]
    fn foreign_verifier_and_private_body_digest_are_not_success() {
        for (archive, binary, script) in [
            (crate::SHA, FULL.2, FULL.3),
            (CANONICAL_SHA, PLUGIN.2, FULL.3),
            (CANONICAL_SHA, FULL.2, PLUGIN.3),
        ] {
            let line = format!("{archive} {binary} {script}\n");
            assert!(validate_gate(line.as_bytes(), CANONICAL_SHA, FULL.2, FULL.3).is_err());
        }
    }
    #[test]
    fn boundary_receipts_keep_both_adjacent_digests() {
        let line = format!("{} {CANONICAL_SHA} {BINARY} {SCRIPT}\n", LEFT.2);
        let x = words(line.as_bytes(), 4).unwrap();
        assert_eq!(x[1], CANONICAL_SHA);
        assert_ne!(x[0], CANONICAL_SHA);
        assert!(words(format!("{CANONICAL_SHA} {BINARY} {SCRIPT}\n").as_bytes(), 4).is_err());
    }
}
