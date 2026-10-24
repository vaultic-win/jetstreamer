//! Same-sample metadata estimate, never remote or archive integrity proof.
use super::*;
const UNIT: &str = "horizon-upload-203-v4-20261023-v1.service";
const IID: &str = "4a9d184a487540409e4edcd1ac353cf4";
const TOTAL: u64 = 103_802_397_352;
const SHA: &str = "7efb3b28b2761cd646d20fa282d87c508249488fd0fb27ce8e033a1aed7d39ad";

fn estimate(records: &Value, sample_micros: u64) -> Result<Value> {
    let rows = records.as_array().context("203 progress journal array")?;
    ensure!(
        !rows.is_empty() && rows.len() <= 4096,
        "203 progress journal size"
    );
    let mut hashing = None;
    let mut upload = None;
    let mut readback = None;
    let mut last = None;
    let mut previous_clock = 0;
    for row in rows {
        ensure!(
            row["_SYSTEMD_UNIT"] == UNIT && row["_SYSTEMD_INVOCATION_ID"] == IID,
            "203 foreign progress journal owner"
        );
        let clock = row["__REALTIME_TIMESTAMP"]
            .as_str()
            .context("203 journal clock")?
            .parse::<u64>()?;
        ensure!(
            clock >= previous_clock && clock <= sample_micros,
            "203 progress clock out of sample order"
        );
        previous_clock = clock;
        let message = row["MESSAGE"].as_str().context("203 journal message")?;
        if message == "epoch 203: hashing /home/ubuntu/horizon/epoch-203.jet" {
            ensure!(hashing.replace(clock).is_none(), "duplicate203sourcehash");
        }
        if !message.starts_with('{') {
            continue;
        }
        let event: Value = serde_json::from_str(message)?;
        match event["event"].as_str() {
            Some("r2-upload-start") => {
                ensure!(
                    event["epoch"] == 203
                        && event["key"] == "epoch-203.jet"
                        && event["total_bytes"] == TOTAL
                        && upload.replace(clock).is_none(),
                    "foreign/duplicate203upload"
                );
            }
            Some("r2-readback-start") => {
                ensure!(
                    event["key"] == "epoch-203.jet"
                        && event["total_bytes"] == TOTAL
                        && event["expected_sha256"] == SHA
                        && readback.replace(clock).is_none(),
                    "foreign/duplicate203readback"
                );
            }
            Some("r2-readback-progress") => {
                ensure!(
                    readback.is_some()
                        && event["key"] == "epoch-203.jet"
                        && event["total_bytes"] == TOTAL,
                    "203 readback scope differs"
                );
                let bytes = event["hashed_bytes"].as_u64().context("203 hashed bytes")?;
                let elapsed = event["elapsed_millis"]
                    .as_u64()
                    .context("203 readback elapsed")?;
                ensure!(
                    bytes > 0 && bytes <= TOTAL && elapsed > 0,
                    "invalid 203 readback counters"
                );
                if let Some((old_bytes, old_elapsed, _)) = last {
                    ensure!(
                        bytes > old_bytes && elapsed >= old_elapsed,
                        "203 readback counters rolled back"
                    );
                }
                last = Some((bytes, elapsed, clock));
            }
            _ => (),
        }
    }
    let hashing = hashing.context("203 initial hash clock missing")?;
    let upload = upload.context("203 upload clock missing")?;
    let readback = readback.context("203 readback start missing")?;
    let (bytes, elapsed, clock) = last.context("203 measured readback progress missing")?;
    ensure!(
        hashing <= upload && upload <= readback && readback <= clock,
        "203 stage clocks disagree"
    );
    // Include time since the last marker; an unreported interval must not be
    // treated as demonstrated progress or hidden when the stream slows/stalls.
    let sample_elapsed = elapsed
        .checked_add((sample_micros - clock) / 1000)
        .context("203 elapsed overflow")?;
    let numerator = u128::from(TOTAL - bytes) * u128::from(sample_elapsed);
    let remaining: u64 = numerator.div_ceil(u128::from(bytes)).try_into()?;
    let source_allowance = ((upload - hashing) / 1000)
        .checked_mul(2)
        .context("203 source allowance overflow")?
        .max(300_000)
        .checked_add(30_000)
        .context("203 sidecar allowance overflow")?;
    Ok(
        json!({"schema":"jetstreamer-exact203-readback-estimate-v1","epoch":203,"phase":"readback",
        "total_bytes":TOTAL,"last_observed_hashed_bytes":bytes,"last_observed_elapsed_millis":elapsed,
        "sample_elapsed_millis":sample_elapsed,"estimated_remaining_readback_millis":remaining,
        "source_revalidation_and_sidecar_allowance_millis":source_allowance,
        "estimated_remaining_millis":remaining.checked_add(source_allowance).context("203 ETA overflow")?,
        "estimate_basis":"Cumulative measured readback rate including time since the last marker; final source revalidation allows twice observed initial hash/preparation time, minimum five minutes, plus thirty seconds for sidecar commit/readback.",
        "current_best_guess":true,"whole_file_sha256_verification_claimed":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false}),
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    observer: BoundFile,
    fleet: BoundFile,
    progress: BoundFile,
    output_directory: PathBuf,
}
pub(super) fn run() -> Result<()> {
    let (binding, self_sha) = publication203::parsed_args("estimate-readback203")?;
    let s: Spec = serde_json::from_value(bound_json(&binding)?)?;
    ensure!(
        s.schema == "jetstreamer-exact203-readback-estimate-spec-v1"
            && s.output_directory.parent() == Some(Path::new("/var/lib/jetstreamer"))
            && s.output_directory
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with("horizon-readback203-estimate-")),
        "203 estimate output scope"
    );
    let m = fs::symlink_metadata(&s.output_directory)?;
    ensure!(
        m.is_dir()
            && m.uid() == 0
            && m.mode() & 0o777 == 0o700
            && s.output_directory.canonicalize()? == s.output_directory,
        "203 estimate output privacy"
    );
    let o = bound_json(&s.observer)?;
    let f = bound_json(&s.fleet)?;
    let sample = utc_seconds(
        o["recorded_at_utc"]
            .as_str()
            .context("203 estimate sample time")?,
    )?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    ensure!(
        o["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && sample <= now
            && now - sample <= 1800
            && f["schema"] == SCHEMA
            && f["first_epoch"] == 201
            && f["last_epoch"] == 300
            && f["observer_sha256"] == s.observer.sha256
            && f["observer_receipt"].as_str() == s.observer.path.to_str()
            && f["sampled_at_utc"] == o["recorded_at_utc"]
            && f["inventory"]["anomalies"] == 0,
        "203 estimate requires fresh accepted sample/fleet"
    );
    ensure!(
        f["active"]
            .as_array()
            .context("203 estimate active census")?
            .iter()
            .filter(|a| a["epoch"] == 203
                && a["phase"] == "upload-readback"
                && a["unit"]["Id"] == UNIT
                && a["unit"]["InvocationID"] == IID
                && a["unit"]["NRestarts"] == "0")
            .count()
            == 1,
        "203 estimate has no exact live delivery owner"
    );
    let mut result = estimate(
        &bound_json(&s.progress)?,
        sample
            .checked_mul(1_000_000)
            .context("203 sample overflow")?,
    )?;
    result["observer"] = private157::binding(&s.observer);
    result["fleet"] = private157::binding(&s.fleet);
    result["progress"] = private157::binding(&s.progress);
    result["spec"] = private157::binding(&binding);
    result["self_sha256"] = json!(self_sha);
    private157::immutable_receipt(&s.output_directory.join("estimate.json"), &result)?;
    println!("203 readback estimate written; no resources polled or remote mutation performed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Value {
        let row = |time: u64, message: String| json!({"_SYSTEMD_UNIT":UNIT,"_SYSTEMD_INVOCATION_ID":IID,"__REALTIME_TIMESTAMP":time.to_string(),"MESSAGE":message});
        json!([row(1_000_000,"epoch 203: hashing /home/ubuntu/horizon/epoch-203.jet".into()),
            row(2_000_000,json!({"event":"r2-upload-start","epoch":203,"key":"epoch-203.jet","total_bytes":TOTAL}).to_string()),
            row(3_000_000,json!({"event":"r2-readback-start","key":"epoch-203.jet","total_bytes":TOTAL,"expected_sha256":SHA}).to_string()),
            row(5_000_000,json!({"event":"r2-readback-progress","key":"epoch-203.jet","total_bytes":TOTAL,"hashed_bytes":1_000_000_000u64,"elapsed_millis":2000}).to_string())])
    }
    #[test]
    fn slower_or_stalled_readback_increases_eta_and_keeps_final_validation_allowance() {
        let fast = estimate(&fixture(), 5_000_000).unwrap();
        let stalled = estimate(&fixture(), 7_000_000).unwrap();
        assert!(
            stalled["estimated_remaining_millis"].as_u64().unwrap()
                > fast["estimated_remaining_millis"].as_u64().unwrap()
        );
        assert_eq!(
            fast["source_revalidation_and_sidecar_allowance_millis"],
            330_000
        );
        assert_eq!(fast["estimated_remaining_readback_millis"], 205_605);
        assert_eq!(fast["publication_authorized"], false);
    }
    #[test]
    fn foreign_owners_future_progress_or_missing_measurements_produce_no_estimate() {
        let mut v = fixture();
        v[3]["_SYSTEMD_INVOCATION_ID"] = json!("f".repeat(32));
        assert!(estimate(&v, 5_000_000).is_err());
        assert!(estimate(&fixture(), 4_000_000).is_err());
        let mut v = fixture();
        v.as_array_mut().unwrap().pop();
        assert!(estimate(&v, 5_000_000).is_err());
    }
}
