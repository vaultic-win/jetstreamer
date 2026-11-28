//! Historical delivery timing evidence only; no resource sample or R2 access.
#[allow(dead_code)]
#[path = "../../jetstreamer-utils/src/epoch141_ledger_common.rs"]
mod evidence;
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{fs, path::Path, process::Command};
const UNIT: &str = "horizon-r2-progressive-epochs101-200-v21-rust-authenticated.service";
const IID: &str = "e4e455fbd455483282107652ca37b83d";
const EXE: &str = "/usr/local/lib/jetstreamer/horizon-r2-rust-20261017-v3-auth-only/jetstreamer-r2";
const RECEIPT: &str =
    "/usr/local/lib/jetstreamer/horizon-publication144-calibration-20261022-v1/epoch198-r2.json";
const RECEIPT_SHA: &str = "81470e448a855612c57c2727e11f08dbb9b52a19bbe6168cea440fe1b17ae1f3";
const OUTPUT: &str = "/var/lib/jetstreamer/horizon-publication144-calibration-20261022-v1/eta.json";
const LENGTH: u64 = 99381250591;
const TARGET: u64 = 109177480876;
const MARKERS: [&str; 4] = [
    "epoch 198: hashing /home/sol/horizon/epoch-198.jet",
    "epoch 198: uploading 99381250591 bytes",
    "epoch 198: reading the completed R2 object back for whole-file SHA-256",
    "epoch 198: verified in R2, receipt /home/sol/.jetstreamer-private/r2-receipts/epoch-198.r2.json",
];
fn durations(events: &[Value], r: &Value) -> Result<[u64; 3]> {
    ensure!(
        events.len() == 4
            && r["schema"] == "jetstreamer-horizon-r2-receipt-v1"
            && r["epoch"] == 198
            && r["archive_length"] == LENGTH
            && r["remote_sha256_readback"] == true
            && r["archive_key"] == "epoch-198.jet"
            && r["checksum_key"] == "epoch-198.jet.sha256",
        "not exact verified historical delivery"
    );
    let mut times = Vec::new();
    for (e, msg) in events.iter().zip(MARKERS) {
        ensure!(
            e["_SYSTEMD_UNIT"] == UNIT
                && e["_SYSTEMD_INVOCATION_ID"] == IID
                && e["_PID"] == "3304399"
                && e["_UID"] == "1001"
                && e["_EXE"] == EXE
                && e["MESSAGE"] == msg,
            "historical timing owner/message differs"
        );
        let t = e["__REALTIME_TIMESTAMP"]
            .as_str()
            .context("timing timestamp")?
            .parse::<u64>()?;
        ensure!(
            times.last().is_none_or(|prior| t > *prior),
            "timing order differs"
        );
        times.push(t);
    }
    ensure!(
        r["verified_unix_seconds"] == times[3] / 1_000_000,
        "final timing does not bind verified receipt"
    );
    Ok([
        (times[1] - times[0]).div_ceil(1000),
        (times[2] - times[1]).div_ceil(1000),
        (times[3] - times[2]).div_ceil(1000),
    ])
}
fn budgets(d: [u64; 3]) -> Result<Value> {
    let scale = |n: u64| -> Result<u64> {
        u64::try_from((n as u128 * TARGET as u128).div_ceil(LENGTH as u128))
            .context("timing overflow")
    };
    let hash = scale(d[0])?;
    let upload = scale(d[1])?;
    let readback = scale(d[2])?;
    let import = hash.checked_mul(3).context("import timing overflow")?;
    let r2 = hash
        .checked_add(upload)
        .and_then(|n| n.checked_add(readback))
        .context("R2 timing overflow")?;
    let total = import
        .checked_add(r2)
        .and_then(|n| n.checked_add(600_000))
        .context("total timing overflow")?;
    Ok(
        json!({"target_archive_bytes":TARGET,"scaled_hash_millis":hash,"copy_hash_and_independent_reread_millis":import,"scaled_upload_millis":upload,"scaled_readback_and_revalidation_millis":readback,"r2_hash_upload_readback_sidecar_millis":r2,"dispatch_margin_millis":600000,"publication_to_sidecar_millis":total,"method":"Scale exact 198 phase durations by complete 144/198 byte ratio with ceiling. Import gets three hash-equivalent passes for copy/write/hash plus independent reread. R2 retains its separate hash/upload/readback/source-revalidation/sidecar debt; add 10 minutes dispatch margin. Forecast only, not a gate or upper bound; diagnose observed slowdown rather than indefinitely resetting deadline."}),
    )
}
fn run() -> Result<()> {
    let a: Vec<_> = std::env::args().collect();
    ensure!(
        (a.len() == 3 || (a.len() == 4 && a[3] == "--check-only"))
            && a[1] == "--self-sha256"
            && unsafe { libc::geteuid() } == 0,
        "usage: publication144-calibrate --self-sha256 SHA [--check-only]"
    );
    evidence::bound_file(&fs::read_link("/proc/self/exe")?, &a[2], 128 << 20, true)?;
    let r: Value = serde_json::from_slice(&evidence::bound_file(
        Path::new(RECEIPT),
        RECEIPT_SHA,
        1 << 20,
        true,
    )?)?;
    let out = Command::new("/usr/bin/journalctl")
        .args([
            &format!("_SYSTEMD_INVOCATION_ID={IID}"),
            "_PID=3304399",
            "--output=json",
            "--no-pager",
        ])
        .output()?;
    ensure!(
        out.status.success() && out.stdout.len() <= 4 << 20,
        "historical journal unavailable/oversized"
    );
    let mut events = Vec::new();
    for line in std::str::from_utf8(&out.stdout)?.lines() {
        let e: Value = serde_json::from_str(line)?;
        if MARKERS.iter().any(|s| e["MESSAGE"] == *s) {
            let mut selected = serde_json::Map::new();
            for key in [
                "_SYSTEMD_UNIT",
                "_SYSTEMD_INVOCATION_ID",
                "_PID",
                "_UID",
                "_EXE",
                "MESSAGE",
                "__REALTIME_TIMESTAMP",
            ] {
                selected.insert(key.into(), e[key].clone());
            }
            events.push(Value::Object(selected));
        }
    }
    let d = durations(&events, &r)?;
    let estimate = budgets(d)?;
    if a.len() == 4 {
        println!("exact historical delivery timing inputs validated; no receipt or remote access");
        return Ok(());
    }
    evidence::write_receipt(
        Path::new(OUTPUT),
        &json!({"schema":"jetstreamer-exact144-delivery-timing-calibration-v1","tool_sha256":a[2],"source_epoch":198,"historical_archive_bytes":LENGTH,"historical_r2_receipt":{"path":RECEIPT,"sha256":RECEIPT_SHA},"events":events,"durations_millis":{"hash":d[0],"upload":d[1],"readback_and_revalidation":d[2]},"estimate":estimate,"new_resource_samples":0,"archive_mutations":false,"replay_launch_authorized":false,"publication_authorized":false,"retirement_authorized":false,"remote_mutations":false,"r2_mutations":false}),
    )?;
    println!("{OUTPUT}");
    Ok(())
}
fn main() -> Result<()> {
    run()
}
#[cfg(test)]
mod tests {
    use super::*;
    fn events() -> Vec<Value> {
        [1792620605659278u64,1792620888024140,1792622363070307,1792623745427991].into_iter().zip(MARKERS).map(|(t,m)|json!({"_SYSTEMD_UNIT":UNIT,"_SYSTEMD_INVOCATION_ID":IID,"_PID":"3304399","_UID":"1001","_EXE":EXE,"MESSAGE":m,"__REALTIME_TIMESTAMP":t.to_string()})).collect()
    }
    fn receipt() -> Value {
        json!({"schema":"jetstreamer-horizon-r2-receipt-v1","epoch":198,"archive_length":LENGTH,"remote_sha256_readback":true,"archive_key":"epoch-198.jet","checksum_key":"epoch-198.jet.sha256","verified_unix_seconds":1792623745})
    }
    #[test]
    fn timings_bind_one_exact_successful_receipt_not_elapsed_waiting() {
        let e = events();
        let r = receipt();
        let d = durations(&e, &r).unwrap();
        assert_eq!(d, [282365, 1475047, 1382358]);
        for key in [
            "_SYSTEMD_UNIT",
            "_SYSTEMD_INVOCATION_ID",
            "_PID",
            "_UID",
            "_EXE",
            "MESSAGE",
            "__REALTIME_TIMESTAMP",
        ] {
            let mut bad = e.clone();
            bad[1][key] = json!("wrong");
            assert!(durations(&bad, &r).is_err(), "{key}");
        }
        let mut bad = e.clone();
        bad.push(e[0].clone());
        assert!(durations(&bad, &r).is_err());
        let mut bad = r;
        bad["verified_unix_seconds"] = json!(1);
        assert!(durations(&e, &bad).is_err());
    }
    #[test]
    fn forecast_keeps_copy_and_r2_revalidation_separate() {
        let e = budgets([282365, 1475047, 1382358]).unwrap();
        assert_eq!(
            e["publication_to_sidecar_millis"].as_u64().unwrap(),
            e["copy_hash_and_independent_reread_millis"]
                .as_u64()
                .unwrap()
                + e["r2_hash_upload_readback_sidecar_millis"]
                    .as_u64()
                    .unwrap()
                + 600000
        );
        assert!(
            e["r2_hash_upload_readback_sidecar_millis"]
                .as_u64()
                .unwrap()
                > 3_000_000
        );
        assert!(budgets([u64::MAX, u64::MAX, u64::MAX]).is_err());
    }
}
