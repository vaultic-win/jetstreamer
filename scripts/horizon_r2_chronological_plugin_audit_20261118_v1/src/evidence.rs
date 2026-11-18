use crate::{local::*, remote::valid_digest};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    io::{BufRead, BufReader},
    path::Path,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PlaybackReport {
    pub epoch: u64,
    pub first_slot: u64,
    pub last_slot: u64,
    pub slot_range_evidence: String,
    pub counters: BTreeMap<String, u64>,
    pub workers: u64,
    pub stream_sha256: String,
    pub log_sha256: String,
    pub clean_process_exit: bool,
    pub native_report_path: String,
    pub native_report_sha256: String,
}
pub fn validate_native_report(
    path: &Path,
    report: &mut PlaybackReport,
    invocation: &[String],
    source: &Path,
) -> Result<()> {
    let value: serde_json::Value = read_json(path)?;
    let native = &value["report"];
    ensure!(
        value["schema"] == "jetstreamer-horizon-plugin-playback-v1"
            && value["full_epoch_verified"] == true
            && value["source"] == source.to_string_lossy().as_ref()
            && value["invocation"] == serde_json::json!(invocation)
            && value["expected_first_slot"] == report.first_slot
            && value["expected_last_slot"] == report.last_slot
            && native["epoch"] == report.epoch
            && native["worker_count"] == report.workers
            && native["first_slot"] == report.first_slot
            && native["last_slot"] == report.last_slot,
        "native plugin report does not bind this entire epoch/invocation"
    );
    for (log_key, native_key) in [
        ("slots", "slots"),
        ("blocks", "blocks"),
        ("skipped", "skipped"),
        ("entries", "entries"),
        ("transactions", "transactions"),
        ("tx_updates", "transaction_updates"),
        ("orphan_updates", "orphan_updates"),
        ("epoch_updates", "epoch_updates"),
        ("account_bytes", "account_data_bytes"),
    ] {
        ensure!(
            native[native_key].as_u64() == report.counters.get(log_key).copied(),
            "native plugin counter differs: {native_key}"
        );
    }
    let bytes: Vec<u8> = serde_json::from_value(native["stream_digest"].clone())?;
    ensure!(
        bytes.len() == 32 && hex(&bytes) == report.stream_sha256,
        "native plugin stream digest differs"
    );
    report.native_report_path = path.to_string_lossy().into_owned();
    report.native_report_sha256 = hash_file(path)?;
    report.slot_range_evidence="Actual first/last slot observations from the plugin's durable full-epoch report, corroborated by complete slot-set checks, counters, stream digest, invocation and clean process exit".into();
    Ok(())
}
pub fn validate_playback(
    log: &Path,
    epoch: u64,
    threads: u64,
    max_log: u64,
) -> Result<PlaybackReport> {
    let file = open_read(log)?;
    ensure!(
        file.metadata()?.len() <= max_log,
        "playback log exceeds bound"
    );
    let mut report = parse_playback(file, epoch, threads)?;
    report.log_sha256 = hash_file(log)?;
    Ok(report)
}
fn parse_playback(file: impl std::io::Read, epoch: u64, threads: u64) -> Result<PlaybackReport> {
    let first = epoch.checked_mul(432000).context("epoch range overflow")?;
    let last = first.checked_add(431999).context("epoch range overflow")?;
    let begin =
        format!("horizon pipeline: epoch {epoch} (slots {first}..={last}) with {threads} threads");
    let end = format!("horizon pipeline: epoch {epoch} complete");
    let prefix = format!("verified epoch {epoch} through ");
    let mut phase = 0;
    let mut result = None;
    let mut reader = BufReader::new(file);
    loop {
        let mut line = Vec::new();
        use std::io::Read;
        let n = reader
            .by_ref()
            .take(1024 * 1024 + 1)
            .read_until(b'\n', &mut line)?;
        if n == 0 {
            break;
        }
        ensure!(n <= 1024 * 1024, "playback log line exceeds bound");
        let line = std::str::from_utf8(&line)?.trim_end();
        ensure!(
            !line.contains(" ERROR ")
                && !line.starts_with("error:")
                && !line.contains("panicked at"),
            "playback logged an error"
        );
        if line.ends_with("verification-only mode; ClickHouse is disabled") {
            ensure!(phase == 0, "duplicate/out-of-order verification mode");
            phase = 1;
        }
        if line.ends_with(&begin) {
            ensure!(phase == 1, "duplicate/out-of-order epoch start");
            phase = 2;
        }
        if let Some((_, summary)) = line.split_once(&prefix) {
            ensure!(phase == 2, "duplicate/out-of-order verification report");
            let (workers, fields) = summary
                .split_once(" workers: ")
                .context("invalid worker report")?;
            let workers: u64 = workers.parse()?;
            ensure!(workers > 0 && workers <= threads, "invalid worker count");
            let mut counters = BTreeMap::new();
            let mut stream_sha256 = None;
            for pair in fields.split_ascii_whitespace() {
                let (name, value) = pair.split_once('=').context("invalid report field")?;
                if name == "stream_sha256" {
                    ensure!(
                        stream_sha256.is_none() && valid_digest(value),
                        "invalid/duplicate stream digest"
                    );
                    stream_sha256 = Some(value.to_owned());
                } else {
                    ensure!(
                        counters
                            .insert(name.into(), value.parse::<u64>()?)
                            .is_none(),
                        "duplicate counter"
                    );
                }
            }
            let expected = [
                "slots",
                "blocks",
                "skipped",
                "entries",
                "transactions",
                "tx_updates",
                "orphan_updates",
                "epoch_updates",
                "account_bytes",
            ];
            ensure!(
                counters.len() == expected.len()
                    && expected.iter().all(|k| counters.contains_key(*k)),
                "missing/unexpected verification counters"
            );
            ensure!(
                counters["slots"] == 432000
                    && counters["blocks"].checked_add(counters["skipped"]) == Some(432000),
                "incomplete epoch slot coverage"
            );
            result = Some(PlaybackReport { epoch, first_slot:first, last_slot:last,
                slot_range_evidence:"VerificationPlugin validated the complete expected slot set, range, ordering, slot count, sum, square sum, XOR and epoch notification; endpoints are inferred from that full-range validation, not individual slot log lines".into(),
                counters, workers, stream_sha256:stream_sha256.context("missing stream digest")?,
                log_sha256:String::new(), clean_process_exit:true, native_report_path:String::new(), native_report_sha256:String::new() });
            phase = 3;
        }
        if line.ends_with(&end) {
            ensure!(
                phase == 3,
                "missing verification report or duplicate completion"
            );
            phase = 4;
        }
    }
    ensure!(phase == 4, "full epoch completion evidence missing");
    result.context("verification report absent")
}
#[cfg(test)]
mod tests {
    use super::*;
    fn complete() -> String {
        format!(
            "verification-only mode; ClickHouse is disabled\nhorizon pipeline: epoch 2 (slots 864000..=1295999) with 4 threads\nverified epoch 2 through 4 workers: slots=432000 blocks=431990 skipped=10 entries=7 transactions=8 tx_updates=9 orphan_updates=0 epoch_updates=4 account_bytes=20 stream_sha256={}\nhorizon pipeline: epoch 2 complete\n",
            "a".repeat(64)
        )
    }
    #[test]
    fn full_epoch_accepts_genuine_leader_skips() {
        let r = parse_playback(complete().as_bytes(), 2, 4).unwrap();
        assert_eq!(r.first_slot, 864000);
        assert_eq!(r.last_slot, 1295999);
        assert_eq!(r.counters["skipped"], 10);
    }
    #[test]
    fn native_report_binds_actual_boundaries_invocation_and_log() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("report.json");
        let source = dir.path().join("scratch");
        let argv = vec!["pipeline".to_owned(), "2:2".into()];
        let mut parsed = parse_playback(complete().as_bytes(), 2, 4).unwrap();
        let native = serde_json::json!({"schema":"jetstreamer-horizon-plugin-playback-v1","source":source,
            "invocation":argv,"expected_first_slot":864000,"expected_last_slot":1295999,"full_epoch_verified":true,
            "report":{"epoch":2,"worker_count":4,"slots":432000,"first_slot":864000,"last_slot":1295999,
            "blocks":431990,"skipped":10,"entries":7,"transactions":8,"transaction_updates":9,"orphan_updates":0,
            "epoch_updates":4,"account_data_bytes":20,"stream_digest":vec![0xaa_u8;32]}});
        fs_write(&path, &native);
        validate_native_report(&path, &mut parsed, &argv, &source).unwrap();
        assert_eq!(parsed.native_report_sha256.len(), 64);
        for mutation in 0..5 {
            let mut bad = native.clone();
            match mutation {
                0 => bad["report"]["first_slot"] = serde_json::json!(864001),
                1 => bad["report"]["last_slot"] = serde_json::json!(1295998),
                2 => bad["invocation"] = serde_json::json!(["other-reader"]),
                3 => bad["report"]["transaction_updates"] = serde_json::json!(10),
                _ => bad["report"]["stream_digest"] = serde_json::json!(vec![0_u8; 32]),
            }
            fs_write(&path, &bad);
            assert!(validate_native_report(&path, &mut parsed, &argv, &source).is_err());
        }
    }
    fn fs_write(path: &Path, value: &serde_json::Value) {
        std::fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
    }
    #[test]
    fn missing_truncated_duplicate_or_wrong_range_fails() {
        for log in [
            complete().replace("epoch 2 complete", "interrupted"),
            complete().replace("slots=432000", "slots=431999"),
            complete().replace("864000..=1295999", "864001..=1295999"),
            complete() + "horizon pipeline: epoch 2 complete\n",
            complete().replace("skipped=10", "skipped=0"),
            complete() + "ERROR ignored\nerror: decoder failed\n",
        ] {
            assert!(parse_playback(log.as_bytes(), 2, 4).is_err());
        }
    }
}
