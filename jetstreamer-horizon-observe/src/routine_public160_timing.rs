//! Measured upload-only forecast. Never resets the original execution clock or
//! counts already completed replay/import/full/plugin scans as remaining work.
use super::*;
#[path = "routine_public160_readback.rs"]
mod readback;
const CALIBRATION: &str =
    "/var/lib/jetstreamer/horizon-publication144-calibration-20261022-v1/eta.json";
const CALIBRATION_SHA: &str = "bc2c99fc95e795424cfa9a1f383765d37d34dcc35b35945d7e9cb2943b135dd7";
const UPLOADER: &str = "horizon-r2-progressive-epochs101-200-v21-rust-authenticated.service";
const IID: &str = "e4e455fbd455483282107652ca37b83d";
const MARKER: &str = "epoch 160: progressive R2 sync started";
const LENGTH: u64 = 148095631232;
const SOURCE_LENGTH: u64 = 99381250591;
const START_MICROS: u64 = 1792689265662323;
fn calibration() -> Bound {
    Bound {
        path: CALIBRATION.into(),
        sha256: CALIBRATION_SHA.into(),
    }
}
pub(super) fn enabled(p: &Plan) -> bool {
    p.epoch160_delivery.as_ref().is_some_and(|v| v.timed_upload)
}
pub(super) fn enable(p: &mut Plan) -> Result<()> {
    ensure!(
        public160::enabled(p)
            && !enabled(p)
            && p.sample_target_utc == "2026-10-22T17:58:00Z"
            && p.previous_observer
                .path
                .ends_with("sample-20261022T172800Z.json"),
        "160 timing must follow accepted 1728"
    );
    budget(&bound_json(&calibration(), false)?)?;
    p.epoch160_delivery.as_mut().unwrap().timed_upload = true;
    Ok(())
}
fn budget(v: &Value) -> Result<(u64, Value)> {
    ensure!(
        v["schema"] == "jetstreamer-exact144-delivery-timing-calibration-v1"
            && v["tool_sha256"]
                == "91ff592e5bd6579c80c5890aa2cb44a70eaf3180bbbf9512d8f3375ddf993438"
            && v["source_epoch"] == 198
            && v["historical_archive_bytes"] == SOURCE_LENGTH
            && v["historical_r2_receipt"]["sha256"]
                == "81470e448a855612c57c2727e11f08dbb9b52a19bbe6168cea440fe1b17ae1f3"
            && v["publication_authorized"] == false
            && v["r2_mutations"] == false,
        "foreign 160 timing calibration"
    );
    let mut sum = 600_000u64;
    let mut phases = serde_json::Map::new();
    for phase in ["hash", "upload", "readback_and_revalidation"] {
        let old = v["durations_millis"][phase]
            .as_u64()
            .filter(|n| *n > 0)
            .context("missing measured phase duration")?;
        let scaled = u64::try_from(
            (u128::from(old) * u128::from(LENGTH)).div_ceil(u128::from(SOURCE_LENGTH)),
        )?;
        sum = sum.checked_add(scaled).context("160 timing overflow")?;
        phases.insert(phase.into(), json!(scaled));
    }
    Ok((
        sum,
        json!({"target_archive_bytes":LENGTH,"historical_archive_bytes":SOURCE_LENGTH,
        "scaled_phase_millis":phases,"dispatch_margin_millis":600000,"total_upload_to_sidecar_millis":sum,
        "method":"Ceiling scale exact verified198 hash/upload/readback-and-source-revalidation durations by full 160 byte length; add 10 minutes dispatch margin, anchor once to actual 160 uploader dispatch. Completed replay/import/full/plugin are excluded; no deadline reset, remaining-time clamp or skipped integrity gate."}),
    ))
}
fn event_start(records: &[Value]) -> Result<u64> {
    let rows: Vec<_> = records.iter().filter(|e| e["MESSAGE"] == MARKER).collect();
    ensure!(rows.len() == 1, "160 dispatch event missing or duplicate");
    let e = rows[0];
    ensure!(
        e["_SYSTEMD_UNIT"] == UPLOADER
            && e["_SYSTEMD_INVOCATION_ID"] == IID
            && e["_PID"] == "3283422"
            && e["_UID"] == "1001"
            && e["_GID"] == "1003"
            && e["_EXE"]
                == "/usr/local/lib/jetstreamer/horizon-r2-rust-20261017-v3-auth-only/jetstreamer-r2-progressive"
            && e["_SYSTEMD_CGROUP"] == format!("/system.slice/{UPLOADER}"),
        "160 dispatch event owner differs"
    );
    let micros = e["__REALTIME_TIMESTAMP"]
        .as_str()
        .context("160 event timestamp")?
        .parse::<u64>()?;
    ensure!(micros == START_MICROS, "160 dispatch timestamp differs");
    Ok(micros.div_ceil(1000))
}
fn remaining(start: u64, total: u64, sample: u64) -> Result<u64> {
    ensure!(start <= sample, "160 dispatch began after sample");
    let deadline = start.checked_add(total).context("160 deadline overflow")?;
    let value = deadline.checked_sub(sample).context(
        "160 measured upload forecast overdue; diagnose actual phase, never reset deadline",
    )?;
    ensure!(value > 0, "160 measured forecast expired");
    Ok(value)
}
pub(super) fn preview(p: &Plan) -> Result<Value> {
    ensure!(
        is_101(p)? && public160::enabled(p),
        "160 timing requires canonical delivery profile"
    );
    let cal = calibration();
    let c = bound_json(&cal, false)?;
    let (total, formula) = budget(&c)?;
    let o = Command::new("/usr/bin/journalctl")
        .args([
            &format!("_SYSTEMD_UNIT={UPLOADER}"),
            &format!("_SYSTEMD_INVOCATION_ID={IID}"),
            "--since=2026-10-22 17:14:20 UTC",
            "--until=2026-10-22 17:14:30 UTC",
            "--output=json",
            "--no-pager",
        ])
        .output()?;
    ensure!(
        o.status.success() && o.stdout.len() <= 1 << 20,
        "160 dispatch journal unavailable or oversized"
    );
    let records: Vec<Value> = std::str::from_utf8(&o.stdout)?
        .lines()
        .map(serde_json::from_str)
        .collect::<std::result::Result<_, _>>()?;
    let start = event_start(&records)?;
    let sample = utc_seconds(&p.sample_target_utc)?
        .checked_mul(1000)
        .context("160 sample overflow")?;
    let (remaining, readback_revision) = match remaining(start, total, sample) {
        Ok(value) => (value, Value::Null),
        Err(_) => {
            let (value, evidence) = readback::estimate(sample, &c)?;
            (value, evidence)
        }
    };
    Ok(
        json!({"schema":"horizon-exact160-upload-timing-v1","calibration":cal,
        "dispatch_event":records.iter().find(|e|e["MESSAGE"]==MARKER).unwrap(),"formula":formula,
        "upload_start_millis":start,"sampled_at_utc":p.sample_target_utc,"estimated_remaining_millis":remaining,
        "readback_revision":readback_revision,
        "original_producer_clock_unchanged":true,"new_resource_samples":0,"archive_hash_performed":false,
        "replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false}),
    )
}
pub(super) fn seal(p: &Plan, owner: &Value) -> Result<(u64, Bound)> {
    ensure!(
        enabled(p)
            && owner["phase"] == "upload-readback"
            && owner["unit"]["Id"] == UPLOADER
            && owner["unit"]["InvocationID"] == IID
            && owner["unit"]["NRestarts"] == "0",
        "160 timed estimate requires exact live uploader"
    );
    let value = preview(p)?;
    let eta = value["estimated_remaining_millis"]
        .as_u64()
        .context("160 ETA")?;
    let package =
        delivery198::seal_values(p, "delivery160-upload-timing", &[("timing.json", value)])?;
    let path = package.join("timing.json");
    let bytes = read_checked(&path, LIMIT, 0, true)?;
    Ok((
        eta,
        Bound {
            path,
            sha256: sha(&bytes),
        },
    ))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_original_authenticated_dispatch_can_anchor_the_deadline() {
        let e = json!({"MESSAGE":MARKER,"_SYSTEMD_UNIT":UPLOADER,"_SYSTEMD_INVOCATION_ID":IID,
            "_PID":"3283422","_UID":"1001","_GID":"1003","_EXE":"/usr/local/lib/jetstreamer/horizon-r2-rust-20261017-v3-auth-only/jetstreamer-r2-progressive",
            "_SYSTEMD_CGROUP":format!("/system.slice/{UPLOADER}"),"__REALTIME_TIMESTAMP":START_MICROS.to_string()});
        assert_eq!(
            event_start(std::slice::from_ref(&e)).unwrap(),
            START_MICROS.div_ceil(1000)
        );
        assert!(event_start(&[]).is_err());
        assert!(event_start(&[e.clone(), e.clone()]).is_err());
        for key in [
            "MESSAGE",
            "_SYSTEMD_UNIT",
            "_SYSTEMD_INVOCATION_ID",
            "_PID",
            "_UID",
            "_GID",
            "_EXE",
            "_SYSTEMD_CGROUP",
            "__REALTIME_TIMESTAMP",
        ] {
            let mut bad = e.clone();
            bad[key] = json!("foreign");
            assert!(event_start(&[bad]).is_err(), "{key}");
        }
    }
    #[test]
    fn measured_forecast_never_clamps_or_resets_an_overdue_deadline() {
        assert_eq!(remaining(1000, 5000, 4000).unwrap(), 2000);
        assert!(remaining(1000, 5000, 999).is_err());
        assert!(remaining(1000, 5000, 6000).is_err());
        assert!(remaining(1000, 5000, 6001).is_err());
        assert!(remaining(u64::MAX, u64::MAX, u64::MAX).is_err());
    }
    #[test]
    fn upload_only_scaling_has_no_import_or_verifier_debt() {
        let v = json!({"schema":"jetstreamer-exact144-delivery-timing-calibration-v1",
            "tool_sha256":"91ff592e5bd6579c80c5890aa2cb44a70eaf3180bbbf9512d8f3375ddf993438","source_epoch":198,
            "historical_archive_bytes":SOURCE_LENGTH,"historical_r2_receipt":{"sha256":"81470e448a855612c57c2727e11f08dbb9b52a19bbe6168cea440fe1b17ae1f3"},
            "durations_millis":{"hash":282365,"upload":1475047,"readback_and_revalidation":1382358},"publication_authorized":false,"r2_mutations":false});
        let (sum, formula) = budget(&v).unwrap();
        let phases = &formula["scaled_phase_millis"];
        assert_eq!(
            sum,
            600000
                + phases["hash"].as_u64().unwrap()
                + phases["upload"].as_u64().unwrap()
                + phases["readback_and_revalidation"].as_u64().unwrap()
        );
        assert!((5_000_000..5_500_000).contains(&sum));
        for key in [
            "source_epoch",
            "historical_archive_bytes",
            "r2_mutations",
            "publication_authorized",
            "tool_sha256",
        ] {
            let mut bad = v.clone();
            bad[key] = json!("foreign");
            assert!(budget(&bad).is_err(), "{key}");
        }
    }
}
