//! Definite forecasts from authenticated child progress, not readiness evidence.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
const LENGTH: u64 = super::events::LENGTH;
const UPLOAD: u64 = 1620446;
const READBACK: u64 = 1518621;
const SOURCE_HASH: u64 = 310199;
const MARGIN: u64 = 600000;
const MAX_PROGRESS_AGE: u64 = 1800000;
fn integer(v: &Value, key: &str) -> Result<u64> {
    v[key]
        .as_u64()
        .with_context(|| format!("missing integer {key}"))
}
fn remaining(bytes: u64, elapsed: u64) -> Result<u64> {
    ensure!(
        bytes > 0 && bytes <= LENGTH && elapsed > 0,
        "progress cannot establish a rate"
    );
    u64::try_from((u128::from(LENGTH - bytes) * u128::from(elapsed)).div_ceil(u128::from(bytes)))
        .context("rate forecast overflow")
}
fn deadline(entered: u64, sample: u64, budget: u64) -> Result<u64> {
    let elapsed = sample
        .checked_sub(entered)
        .context("forecast precedes phase")?;
    budget
        .checked_sub(elapsed)
        .filter(|n| *n > 0)
        .context("phase forecast overdue; diagnose before publishing a replacement ETA")
}
pub(crate) fn estimate(progress: &Value, calibration: &Value) -> Result<Value> {
    ensure!(
        calibration["schema"] == "jetstreamer-exact144-delivery-timing-calibration-v1"
            && calibration["estimate"]["target_archive_bytes"] == LENGTH
            && calibration["estimate"]["scaled_upload_millis"] == UPLOAD
            && calibration["estimate"]["scaled_readback_and_revalidation_millis"] == READBACK
            && calibration["estimate"]["scaled_hash_millis"] == SOURCE_HASH
            && calibration["estimate"]["dispatch_margin_millis"] == MARGIN
            && calibration["publication_authorized"] == false
            && calibration["r2_mutations"] == false,
        "forecast requires separately bound historical calibration"
    );
    ensure!(
        progress["total_bytes"] == LENGTH
            && progress["archive_ready_pair_proven"] == false
            && progress["sidecar_committed"] == false
            && progress["r2_mutations"] == false,
        "forecast cannot borrow archive readiness or another object"
    );
    let sample = integer(progress, "sampled_at_millis")?;
    let start = integer(progress, "phase_started_at_millis")?;
    let entered = integer(progress, "phase_entered_at_millis")?;
    let last = integer(progress, "last_progress_at_millis")?;
    let bytes = integer(progress, "completed_phase_bytes")?;
    let age = sample.checked_sub(last).context("future progress")?;
    ensure!(
        start <= entered
            && entered <= last
            && integer(progress, "progress_age_millis")? == age
            && age <= MAX_PROGRESS_AGE,
        "stale or inconsistent progress; diagnose stalled child"
    );
    // Use wall time through the sample, not only the client's last checkpoint
    // elapsed counter. A silent stall must slow the estimated rate, not vanish.
    let wall = sample
        .checked_sub(start)
        .context("sample precedes phase start")?;
    let debt = READBACK
        .checked_add(SOURCE_HASH)
        .and_then(|n| n.checked_add(MARGIN))
        .context("forecast debt overflow")?;
    let phase = progress["phase"].as_str().context("progress phase")?;
    let (work, downstream, basis) = match phase {
        "pre-upload-source-hash" => {
            ensure!(
                bytes == 0
                    && progress["multipart_committed"] == false
                    && progress["whole_file_readback_verified"] == false,
                "initial source hash cannot borrow later progress"
            );
            (
                deadline(entered, sample, SOURCE_HASH + MARGIN)?,
                UPLOAD + debt,
                "initial source-hash deadline anchored to exact client marker,plus full upload/readback/revalidation/sidecar debt",
            )
        }
        "upload" => {
            ensure!(
                progress["multipart_committed"] == false
                    && progress["whole_file_readback_verified"] == false,
                "upload cannot claim commit or verified readback"
            );
            let rate = if bytes == 0 {
                deadline(start, sample, UPLOAD)?
            } else {
                remaining(bytes, wall)?
            };
            // Retain a prorated historical allowance when observed upload is
            // faster. Never extrapolate a fast first acknowledgement alone.
            let historical = u64::try_from(
                (u128::from(
                    LENGTH
                        .checked_sub(bytes)
                        .context("oversized upload progress")?,
                ) * u128::from(UPLOAD))
                .div_ceil(u128::from(LENGTH)),
            )?;
            (
                rate.max(historical),
                debt,
                "max(observed wall-time rate,historical byte-scaled upload),plus complete readback/source revalidation/sidecar debt",
            )
        }
        "awaiting-readback" => {
            ensure!(
                bytes == LENGTH
                    && progress["multipart_committed"] == true
                    && progress["whole_file_readback_verified"] == false,
                "readback wait lacks exact multipart commit"
            );
            (
                deadline(entered, sample, debt)?,
                0,
                "fixed downstream deadline anchored to actual multipart commit;never reset at observation",
            )
        }
        "readback" => {
            ensure!(
                progress["whole_file_readback_verified"] == false,
                "readback progress cannot already be verified"
            );
            let rate = if bytes == 0 {
                deadline(start, sample, READBACK)?
            } else {
                remaining(bytes, wall)?
            };
            let historical = u64::try_from(
                (u128::from(
                    LENGTH
                        .checked_sub(bytes)
                        .context("oversized readback progress")?,
                ) * u128::from(READBACK))
                .div_ceil(u128::from(LENGTH)),
            )?;
            (
                rate.max(historical),
                SOURCE_HASH + MARGIN,
                "max(observed ordered-hashed wall-time rate,historical byte-scaled readback),plus source revalidation/sidecar debt",
            )
        }
        "source-revalidation-sidecar" => {
            ensure!(
                bytes == LENGTH && progress["whole_file_readback_verified"] == true,
                "source revalidation lacks complete verified readback"
            );
            (
                deadline(entered, sample, SOURCE_HASH + MARGIN)?,
                0,
                "fixed source-revalidation/sidecar deadline anchored to actual verified readback;never reset at observation",
            )
        }
        "sidecar-commit" => {
            ensure!(
                bytes == LENGTH && progress["whole_file_readback_verified"] == true,
                "sidecar wait lacks verified readback"
            );
            (
                deadline(entered, sample, MARGIN)?,
                0,
                "sidecar allowance anchored to exact source-revalidation completion;not remote readiness",
            )
        }
        _ => anyhow::bail!("unsupported actual child phase;queue requires its own ownership model"),
    };
    let total = work
        .checked_add(downstream)
        .filter(|n| *n > 0)
        .context("invalid sidecar forecast")?;
    Ok(
        json!({"schema":"jetstreamer-exact144-child-sidecar-forecast-v1","epoch":144,
        "phase":phase,"sampled_at_millis":sample,"estimated_remaining_millis":total,
        "remaining_active_work_millis":work,"downstream_allowance_millis":downstream,
        "phase_wall_elapsed_millis":wall,"progress_age_millis":age,"estimate_basis":basis,
        "queue_wait_included":false,"queue_phase_supported":false,"archive_ready_pair_proven":false,
        "status_publication_authorized":false,"r2_mutations":false}),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    fn calibration() -> Value {
        json!({"schema":"jetstreamer-exact144-delivery-timing-calibration-v1","estimate":{"target_archive_bytes":LENGTH,"scaled_upload_millis":UPLOAD,"scaled_readback_and_revalidation_millis":READBACK,"scaled_hash_millis":SOURCE_HASH,"dispatch_margin_millis":MARGIN},"publication_authorized":false,"r2_mutations":false})
    }
    fn progress(phase: &str, bytes: u64) -> Value {
        json!({"phase":phase,"total_bytes":LENGTH,"completed_phase_bytes":bytes,"phase_started_at_millis":1000,"phase_entered_at_millis":1000,"last_progress_at_millis":101000,"sampled_at_millis":101000,"progress_age_millis":0,"multipart_committed":false,"whole_file_readback_verified":false,"archive_ready_pair_proven":false,"sidecar_committed":false,"r2_mutations":false})
    }
    #[test]
    fn upload_keeps_all_downstream_debt_and_historical_floor() {
        let p = progress("upload", LENGTH / 2);
        let v = estimate(&p, &calibration()).unwrap();
        assert!(v["remaining_active_work_millis"].as_u64().unwrap() >= UPLOAD / 2);
        assert_eq!(
            v["downstream_allowance_millis"],
            READBACK + SOURCE_HASH + MARGIN
        );
    }
    #[test]
    fn silent_time_slows_observed_rate_instead_of_counting_down() {
        let mut p = progress("upload", LENGTH / 10);
        let before = estimate(&p, &calibration()).unwrap();
        p["sampled_at_millis"] = json!(1001000);
        p["progress_age_millis"] = json!(900000);
        let after = estimate(&p, &calibration()).unwrap();
        assert!(
            after["estimated_remaining_millis"].as_u64()
                > before["estimated_remaining_millis"].as_u64()
        );
    }
    #[test]
    fn completed_phase_deadlines_are_not_reset_or_clamped() {
        let mut p = progress("source-revalidation-sidecar", LENGTH);
        p["whole_file_readback_verified"] = json!(true);
        p["phase_entered_at_millis"] = json!(101000);
        let before = estimate(&p, &calibration()).unwrap();
        p["sampled_at_millis"] = json!(201000);
        p["progress_age_millis"] = json!(100000);
        assert_eq!(
            estimate(&p, &calibration()).unwrap()["estimated_remaining_millis"],
            before["estimated_remaining_millis"].as_u64().unwrap() - 100000
        );
        p["sampled_at_millis"] = json!(101000 + SOURCE_HASH + MARGIN);
        p["progress_age_millis"] = json!(SOURCE_HASH + MARGIN);
        assert!(estimate(&p, &calibration()).is_err());
    }
    #[test]
    fn readback_and_commit_remain_distinct_from_sidecar_readiness() {
        let p = progress("readback", LENGTH / 2);
        let v = estimate(&p, &calibration()).unwrap();
        assert_eq!(v["downstream_allowance_millis"], SOURCE_HASH + MARGIN);
        let mut p = progress("awaiting-readback", LENGTH);
        assert!(estimate(&p, &calibration()).is_err());
        p["multipart_committed"] = json!(true);
        assert!(estimate(&p, &calibration()).is_ok());
        p["sidecar_committed"] = json!(true);
        assert!(estimate(&p, &calibration()).is_err());
    }
    #[test]
    fn missing_rate_stale_progress_wrong_calibration_and_queue_fail_closed() {
        let mut p = progress("upload", 1);
        p["sampled_at_millis"] = json!(2001001);
        p["progress_age_millis"] = json!(1900001);
        assert!(estimate(&p, &calibration()).is_err());
        assert!(estimate(&progress("queued-upload", 0), &calibration()).is_err());
        let mut c = calibration();
        c["estimate"]["scaled_upload_millis"] = json!(1);
        assert!(estimate(&progress("upload", 1), &c).is_err());
        assert!(remaining(0, 100).is_err());
        assert!(remaining(LENGTH + 1, 100).is_err());
        assert!(remaining(1, u64::MAX).is_err());
    }
    #[test]
    fn source_hash_and_sidecar_wait_preserve_full_debt_and_original_deadlines() {
        let p = progress("pre-upload-source-hash", 0);
        let v = estimate(&p, &calibration()).unwrap();
        assert_eq!(
            v["downstream_allowance_millis"],
            UPLOAD + READBACK + SOURCE_HASH + MARGIN
        );
        let mut p = progress("sidecar-commit", LENGTH);
        p["whole_file_readback_verified"] = json!(true);
        assert_eq!(
            estimate(&p, &calibration()).unwrap()["estimated_remaining_millis"],
            MARGIN - 100000
        );
        p["sampled_at_millis"] = json!(1000 + MARGIN);
        p["progress_age_millis"] = json!(MARGIN - 100000);
        assert!(estimate(&p, &calibration()).is_err());
    }
}
