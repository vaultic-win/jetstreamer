//! Exact client progress is operational evidence, never a ready-pair receipt.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};

pub(crate) const LENGTH: u64 = 109177480876;
pub(crate) const DIGEST: &str = "153d3e5e5b7cbdc31bb4229315786000b84442a75b3b83cf4a50184b20b84a33";
pub(crate) const UNIT: &str = "horizon-upload-144-v4-20261022-v1.service";
pub(crate) const CLIENT: &str =
    "/usr/local/lib/jetstreamer/horizon-publication144-progress-client-20261022-v1/jetstreamer-r2";
pub(crate) const CLIENT_SHA: &str =
    "c91b5ab379e876c6426be82adb381644927e7b5a199e3709dc9ce59dc2a6d96a";

#[derive(Default)]
struct Counter {
    started: bool,
    bytes: u64,
    elapsed: u64,
    last_at: u64,
    points: u64,
}
impl Counter {
    fn start(&mut self, bytes: u64, elapsed: u64, at: u64) -> Result<()> {
        ensure!(
            !self.started && bytes == 0 && elapsed == 0,
            "duplicate or invalid progress start"
        );
        self.started = true;
        self.last_at = at;
        Ok(())
    }
    fn advance(&mut self, bytes: u64, elapsed: u64, at: u64, terminal: bool) -> Result<()> {
        ensure!(
            self.started && bytes <= LENGTH && elapsed > 0 && at >= self.last_at,
            "invalid progress point"
        );
        ensure!(
            bytes > self.bytes || (terminal && bytes == self.bytes && bytes == LENGTH),
            "repeated or regressing progress bytes"
        );
        ensure!(elapsed >= self.elapsed, "regressing progress clock");
        self.bytes = bytes;
        self.elapsed = elapsed;
        self.last_at = at;
        self.points += 1;
        Ok(())
    }
}

/// Inputs are trusted journald envelopes, not payload-provided PID/UID fields.
/// Every relevant event must belong to the single authenticated client child.
pub(crate) fn summarize(
    events: &[Value],
    iid: &str,
    pid: u32,
    spawned: u64,
    sample: u64,
) -> Result<Value> {
    ensure!(
        spawned <= sample && pid > 0,
        "progress sample precedes child"
    );
    let mut upload = Counter::default();
    let mut readback = Counter::default();
    let mut committed = false;
    let mut verified = false;
    let mut last = 0;
    let mut relevant = 0;
    for envelope in events {
        let Some(message) = envelope["MESSAGE"].as_str() else {
            continue;
        };
        let Ok(v) = serde_json::from_str::<Value>(message) else {
            continue;
        };
        let Some(event) = v["event"].as_str() else {
            continue;
        };
        if !matches!(
            event,
            "r2-upload-start"
                | "r2-upload-progress"
                | "r2-upload-committed"
                | "r2-readback-start"
                | "r2-readback-progress"
                | "r2-readback-verified"
        ) {
            continue;
        }
        ensure!(
            envelope["_SYSTEMD_UNIT"] == UNIT
                && envelope["_SYSTEMD_INVOCATION_ID"] == iid
                && envelope["_PID"]
                    .as_str()
                    .and_then(|s| s.parse::<u32>().ok())
                    == Some(pid)
                && envelope["_UID"] == "1001"
                && envelope["_EXE"] == CLIENT,
            "foreign progress journal owner"
        );
        let at = envelope["__REALTIME_TIMESTAMP"]
            .as_str()
            .context("journal timestamp")?
            .parse::<u64>()?
            / 1000;
        ensure!(
            at >= spawned && at >= last && at <= sample,
            "progress timestamp outside sampled child lifetime"
        );
        last = at;
        ensure!(
            v["key"] == "epoch-144.jet" && v["total_bytes"] == LENGTH,
            "foreign progress object or length"
        );
        let elapsed = v["elapsed_millis"]
            .as_u64()
            .context("integer progress elapsed")?;
        ensure!(
            elapsed <= at - spawned,
            "progress elapsed exceeds child lifetime"
        );
        if event.starts_with("r2-upload-") {
            ensure!(
                v["epoch"] == 144
                    && !readback.started
                    && !committed
                    && v["whole_file_sha256_verified"] == false,
                "upload phase or integrity claim changed"
            );
            let bytes = v["acknowledged_bytes"]
                .as_u64()
                .context("integer acknowledged bytes")?;
            match event {
                "r2-upload-start" => upload.start(bytes, elapsed, at)?,
                "r2-upload-progress" => upload.advance(bytes, elapsed, at, false)?,
                _ => {
                    ensure!(bytes == LENGTH, "short multipart commit");
                    upload.advance(bytes, elapsed, at, true)?;
                    committed = true;
                }
            }
        } else {
            ensure!(
                !verified && (committed || !upload.started),
                "readback before upload commit or after verification"
            );
            let bytes = v["hashed_bytes"].as_u64().context("integer hashed bytes")?;
            match event {
                "r2-readback-start" => {
                    ensure!(
                        v["expected_sha256"] == DIGEST
                            && v["expected_etag"].as_str().is_some_and(|s| !s.is_empty())
                            && v["whole_file_sha256_verified"] == false,
                        "readback start lacks bound digest/ETag"
                    );
                    readback.start(bytes, elapsed, at)?;
                }
                "r2-readback-progress" => {
                    ensure!(
                        v["whole_file_sha256_verified"] == false,
                        "premature verification claim"
                    );
                    readback.advance(bytes, elapsed, at, false)?;
                }
                _ => {
                    ensure!(
                        bytes == LENGTH && v["whole_file_sha256_verified"] == true,
                        "short or unverified readback"
                    );
                    readback.advance(bytes, elapsed, at, true)?;
                    verified = true;
                }
            }
        }
        relevant += 1;
    }
    ensure!(
        relevant > 0,
        "no authenticated client progress yet; do not invent a phase or ETA"
    );
    let (phase, counter) = if verified {
        ("source-revalidation-sidecar", &readback)
    } else if readback.started {
        ("readback", &readback)
    } else if committed {
        ("awaiting-readback", &upload)
    } else {
        ("upload", &upload)
    };
    Ok(
        json!({"phase":phase,"completed_phase_bytes":counter.bytes,"total_bytes":LENGTH,
        "phase_elapsed_millis":counter.elapsed,"last_progress_at_millis":last,
        "sampled_at_millis":sample,"progress_age_millis":sample-last,"progress_points":counter.points,
        "multipart_committed":committed,"whole_file_readback_verified":verified,
        "archive_ready_pair_proven":false,"sidecar_committed":false,"current_sidecar_eta_valid":false,
        "status_publication_authorized":false,"r2_mutations":false}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn event(name: &str, bytes: u64, elapsed: u64, at: u64) -> Value {
        let upload = name.starts_with("r2-upload-");
        let mut v = json!({"event":name,"epoch":144,"key":"epoch-144.jet","total_bytes":LENGTH,
            "elapsed_millis":elapsed,"whole_file_sha256_verified":name=="r2-readback-verified",
            "expected_sha256":DIGEST,"expected_etag":"bound-etag"});
        v[if upload {
            "acknowledged_bytes"
        } else {
            "hashed_bytes"
        }] = json!(bytes);
        json!({"MESSAGE":v.to_string(),"_SYSTEMD_UNIT":UNIT,"_SYSTEMD_INVOCATION_ID":"a".repeat(32),
            "_PID":"123","_UID":"1001","_EXE":CLIENT,"__REALTIME_TIMESTAMP":(at*1000).to_string()})
    }
    fn run(e: &[Value]) -> Result<Value> {
        summarize(e, &"a".repeat(32), 123, 1000, 10000)
    }
    fn upload() -> Vec<Value> {
        vec![
            event("r2-upload-start", 0, 0, 1000),
            event("r2-upload-progress", LENGTH, 1000, 2000),
            event("r2-upload-committed", LENGTH, 1100, 2100),
        ]
    }
    #[test]
    fn multipart_is_not_whole_object_or_sidecar_proof() {
        let v = run(&upload()).unwrap();
        assert_eq!(v["phase"], "awaiting-readback");
        assert_eq!(v["multipart_committed"], true);
        assert_eq!(v["whole_file_readback_verified"], false);
        assert_eq!(v["archive_ready_pair_proven"], false);
    }
    #[test]
    fn full_readback_still_owes_revalidation_and_sidecar() {
        let mut e = upload();
        e.extend([
            event("r2-readback-start", 0, 0, 2200),
            event("r2-readback-progress", LENGTH, 1000, 3200),
            event("r2-readback-verified", LENGTH, 1100, 3300),
        ]);
        let v = run(&e).unwrap();
        assert_eq!(v["phase"], "source-revalidation-sidecar");
        assert_eq!(v["whole_file_readback_verified"], true);
        assert_eq!(v["sidecar_committed"], false);
        assert_eq!(v["current_sidecar_eta_valid"], false);
    }
    #[test]
    fn idempotent_existing_archive_may_begin_with_readback() {
        assert_eq!(
            run(&[event("r2-readback-start", 0, 0, 1500)]).unwrap()["phase"],
            "readback"
        );
    }
    #[test]
    fn missing_foreign_and_spoofed_owner_fail_closed() {
        assert!(run(&[]).is_err());
        for field in [
            "_SYSTEMD_UNIT",
            "_SYSTEMD_INVOCATION_ID",
            "_PID",
            "_UID",
            "_EXE",
        ] {
            let mut e = upload();
            e[1][field] = json!("foreign");
            assert!(run(&e).is_err(), "{field}");
        }
    }
    #[test]
    fn retries_regressions_phase_reversals_and_clock_resets_fail_closed() {
        let start = event("r2-upload-start", 0, 0, 1000);
        for point in [
            event("r2-upload-progress", 0, 100, 1100),
            event("r2-upload-progress", LENGTH + 1, 100, 1100),
            event("r2-upload-committed", 1, 100, 1100),
            event("r2-readback-start", 0, 0, 1100),
        ] {
            assert!(run(&[start.clone(), point]).is_err());
        }
        assert!(run(&[start.clone(), start]).is_err());
        let mut e = upload();
        e.push(event("r2-upload-progress", LENGTH, 1200, 2200));
        assert!(run(&e).is_err());
        let mut e = upload();
        e[1]["__REALTIME_TIMESTAMP"] = json!("999000");
        assert!(run(&e).is_err());
        let mut e = upload();
        e[1]["__REALTIME_TIMESTAMP"] = json!("10001000");
        assert!(run(&e).is_err());
    }
    #[test]
    fn changed_object_digest_and_numeric_shape_are_fatal() {
        for (field, value) in [
            ("key", json!("epoch-145.jet")),
            ("total_bytes", json!(0)),
            ("elapsed_millis", json!("1000")),
            ("whole_file_sha256_verified", json!(true)),
        ] {
            let mut e = upload();
            let mut v: Value = serde_json::from_str(e[1]["MESSAGE"].as_str().unwrap()).unwrap();
            v[field] = value;
            e[1]["MESSAGE"] = json!(v.to_string());
            assert!(run(&e).is_err(), "{field}");
        }
        let mut e = event("r2-readback-start", 0, 0, 1500);
        let mut v: Value = serde_json::from_str(e["MESSAGE"].as_str().unwrap()).unwrap();
        v["expected_sha256"] = json!("b".repeat(64));
        e["MESSAGE"] = json!(v.to_string());
        assert!(run(&[e]).is_err());
    }
}
