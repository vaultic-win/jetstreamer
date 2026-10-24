//! Revised estimate after the historical forecast expires. Transport bytes are
//! estimation evidence only, never verified progress or an archive receipt.
use super::*;
const CHILD: &str = "4043474";
const EXE: &str = "/usr/local/lib/jetstreamer/horizon-r2-rust-20261017-v3-auth-only/jetstreamer-r2";
const READBACK_MICROS: u64 = 1792691971119098;
const MESSAGE: &str = "epoch 160: reading the completed R2 object back for whole-file SHA-256";
fn child() -> Result<(String, String)> {
    let status = fs::read_to_string(format!("/proc/{CHILD}/status"))?;
    ensure!(
        status.lines().any(|l| l == "PPid:\t3283422")
            && status.lines().any(|l| l == "Uid:\t1001\t1001\t1001\t1001")
            && fs::read_link(format!("/proc/{CHILD}/exe"))? == Path::new(EXE)
            && fs::read_to_string(format!("/proc/{CHILD}/cgroup"))?.trim()
                == format!("0::/system.slice/{UPLOADER}"),
        "160 readback child identity differs"
    );
    let stat = fs::read_to_string(format!("/proc/{CHILD}/stat"))?;
    let start = stat
        .rsplit_once(')')
        .context("child stat")?
        .1
        .split_whitespace()
        .nth(19)
        .context("child start ticks")?
        .to_owned();
    Ok((
        start,
        status
            .lines()
            .find(|l| l.starts_with("Gid:"))
            .context("child gid")?
            .to_owned(),
    ))
}
fn socket_map() -> Result<BTreeMap<u32, PathBuf>> {
    let mut map = BTreeMap::new();
    for entry in fs::read_dir(format!("/proc/{CHILD}/fd"))? {
        let entry = entry?;
        let fd = entry
            .file_name()
            .to_str()
            .context("noncanonical child fd")?
            .parse::<u32>()?;
        let path = fs::read_link(entry.path())?;
        if path.to_string_lossy().starts_with("socket:[") {
            map.insert(fd, path);
        }
    }
    Ok(map)
}
fn bytes(text: &str) -> Result<(u64, Vec<u32>)> {
    let lines: Vec<_> = text.lines().collect();
    let mut total = 0u64;
    let mut fds = BTreeSet::new();
    for (i, line) in lines.iter().enumerate() {
        if !line.contains(&format!("pid={CHILD},")) {
            continue;
        }
        ensure!(
            line.starts_with("ESTAB ")
                && ["172.64.190.1:443", "172.64.66.1:443"]
                    .iter()
                    .any(|peer| line.split_whitespace().nth(4) == Some(*peer))
                && line.matches("pid=").count() == 1,
            "readback TCP owner/endpoint differs"
        );
        let fd = line
            .split_once(&format!("pid={CHILD},fd="))
            .context("TCP fd")?
            .1
            .split(')')
            .next()
            .context("TCP fd end")?
            .parse::<u32>()?;
        ensure!(fds.insert(fd), "duplicate readback socket");
        let detail = lines.get(i + 1).context("missing TCP_INFO")?;
        let fields: Vec<_> = detail
            .split_whitespace()
            .filter_map(|s| s.strip_prefix("bytes_received:"))
            .collect();
        ensure!(fields.len() == 1, "missing/duplicate TCP byte counter");
        total = total
            .checked_add(fields[0].parse::<u64>()?)
            .context("TCP byte overflow")?;
    }
    ensure!(
        fds.len() == 4 && total > 4u64 << 20,
        "160 readback needs exact four current sockets and useful received bytes"
    );
    Ok((total, fds.into_iter().collect()))
}
fn forecast(received: u64, elapsed: u64, revalidation: u64) -> Result<(u64, u64)> {
    // Deduct1MiB/socket for TLS/HTTP/control traffic and discount another 10%.
    // Closed connections are omitted, conservatively undercounting transport.
    // These are approximate received bytes, explicitly not authenticated bytes.
    let useful = received
        .checked_sub(4u64 << 20)
        .context("no useful readback traffic")?
        / 10
        * 9;
    ensure!(
        elapsed > 0 && useful > 0 && useful < LENGTH,
        "readback estimate lacks bounded progress"
    );
    let millis = u64::try_from(
        (u128::from(LENGTH - useful) * u128::from(elapsed)).div_ceil(u128::from(useful)),
    )?
    .checked_add(revalidation)
    .and_then(|n| n.checked_add(600000))
    .context("readback ETA overflow")?;
    Ok((millis, useful))
}
pub(super) fn estimate(sample: u64, calibration: &Value) -> Result<(u64, Value)> {
    let before = child()?;
    let journal = Command::new("/usr/bin/journalctl")
        .args([
            &format!("_SYSTEMD_UNIT={UPLOADER}"),
            &format!("_SYSTEMD_INVOCATION_ID={IID}"),
            &format!("_PID={CHILD}"),
            "--since=2026-10-22 17:59:25 UTC",
            "--output=json",
            "--no-pager",
        ])
        .output()?;
    ensure!(
        journal.status.success() && journal.stdout.len() <= 1 << 20,
        "readback journal unavailable"
    );
    let rows: Vec<Value> = std::str::from_utf8(&journal.stdout)?
        .lines()
        .map(serde_json::from_str)
        .collect::<std::result::Result<_, _>>()?;
    ensure!(
        rows.len() == 1,
        "readback stage changed, retried or ambiguous; requalify estimate"
    );
    let event = &rows[0];
    ensure!(
        event["MESSAGE"] == MESSAGE
            && event["_PID"] == CHILD
            && event["_UID"] == "1001"
            && event["_GID"] == "1003"
            && event["_EXE"] == EXE
            && event["_SYSTEMD_UNIT"] == UPLOADER
            && event["_SYSTEMD_INVOCATION_ID"] == IID
            && event["_SYSTEMD_CGROUP"] == format!("/system.slice/{UPLOADER}")
            && event["__REALTIME_TIMESTAMP"]
                .as_str()
                .and_then(|s| s.parse::<u64>().ok())
                == Some(READBACK_MICROS),
        "readback event differs"
    );
    let before_sockets = socket_map()?;
    let output = Command::new("/usr/bin/ss")
        .args(["-tinp", "( dport = :443 )"])
        .output()?;
    ensure!(
        output.status.success() && output.stdout.len() <= 1 << 20,
        "readback TCP_INFO unavailable"
    );
    let text = std::str::from_utf8(&output.stdout)?;
    let (received, fds) = bytes(text)?;
    let mut sockets = Vec::new();
    for fd in &fds {
        let path = fs::read_link(format!("/proc/{CHILD}/fd/{fd}"))?;
        ensure!(
            before_sockets.get(fd) == Some(&path) && path.to_string_lossy().starts_with("socket:["),
            "TCP fd changed"
        );
        sockets.push((fd, path));
    }
    ensure!(
        before == child()?,
        "readback child changed during measurement"
    );
    let measured = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis();
    let sample_age = measured
        .checked_sub(u128::from(sample))
        .filter(|n| *n <= 600000)
        .context("readback transport sample outside the bounded 10 minute metadata cycle")?;
    let elapsed = u64::try_from(measured)?
        .checked_sub(READBACK_MICROS.div_ceil(1000))
        .context("future readback event")?;
    let (total, _) = budget(calibration)?;
    // Retain the independently calibrated whole-file local hash allowance.
    let old_hash = calibration["durations_millis"]["hash"]
        .as_u64()
        .context("hash duration")?;
    let hash = u64::try_from(
        (u128::from(old_hash) * u128::from(LENGTH)).div_ceil(u128::from(SOURCE_LENGTH)),
    )?;
    let (at_measurement, useful) = forecast(received, elapsed, hash)?;
    let eta = at_measurement
        .checked_add(sample_age.try_into()?)
        .context("sample-anchored readback ETA overflow")?;
    Ok((
        eta,
        json!({"schema":"horizon-exact160-readback-transport-forecast-v1","readback_event":event,
        "child_start_and_gid":before,"socket_fds_and_inodes":sockets,"measured_at_unix_millis":measured,
        "received_transport_bytes":received,"estimated_useful_received_bytes":useful,"readback_elapsed_millis":elapsed,
        "local_revalidation_millis":hash,"dispatch_margin_millis":600000,"estimated_remaining_millis":eta,
        "estimated_remaining_at_measurement_millis":at_measurement,"sample_to_measurement_millis":sample_age,
        "superseded_historical_total_millis":total,"verified_readback_progress_proven":false,"archive_completion_proven":false,
        "method":"Current exact child four-socket TCP receive counters minus1MiB/socket and10percent transport margin; estimate outstanding bytes at measured since-readback average. Add calibrated whole-file source hash and10minutes sidecar margin. No deadline reset or integrity gate bypass.",
        "replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false}),
    ))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "root exact live160 overdue-readback event diagnostic only; no resource observer, archive read, R2 request or status publication"]
    fn actual_readback_transport_revision_is_bound_to_live_child() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let c = bound_json(&calibration(), false).unwrap();
        let (eta, proof) = estimate(now.try_into().unwrap(), &c).unwrap();
        assert!(eta > 0);
        assert_eq!(proof["verified_readback_progress_proven"], false);
        let bound = write_new(
            Path::new(
                "/var/lib/jetstreamer/horizon-readback160-qualification-20261022-v3/proof.json",
            ),
            &proof,
        )
        .unwrap();
        println!("{} {}", bound.path.display(), bound.sha256);
    }
    #[test]
    fn transport_parse_requires_exact_owner_four_sockets_and_endpoint() {
        let text = (6..10).map(|fd| format!("ESTAB 0 0 67.213.123.65:1 172.64.190.1:443 users:((\"jetstreamer-r2\",pid={CHILD},fd={fd}))\n bbr bytes_received:10000000\n")).collect::<String>();
        assert_eq!(bytes(&text).unwrap(), (40000000, vec![6, 7, 8, 9]));
        assert_eq!(
            bytes(&text.replace("172.64.190.1", "172.64.66.1"))
                .unwrap()
                .0,
            40000000
        );
        for bad in [
            text.replace("172.64.190.1", "127.0.0.1"),
            text.replace("fd=9", "fd=8"),
            text.replace("bytes_received:", "other:"),
        ] {
            assert!(bytes(&bad).is_err());
        }
    }
    #[test]
    fn transport_forecast_reacts_to_observed_slower_readback_without_zero_or_reset() {
        let fast = forecast(30u64 << 30, 3000000, 420000).unwrap().0;
        let slow = forecast(20u64 << 30, 3000000, 420000).unwrap().0;
        assert!(slow > fast && fast > 0);
        assert!(forecast(0, 1, 1).is_err());
        assert!(forecast(20u64 << 30, 0, 1).is_err());
        assert!(forecast(u64::MAX, u64::MAX, u64::MAX).is_err());
    }
}
