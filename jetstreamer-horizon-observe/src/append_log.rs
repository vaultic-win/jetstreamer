//! Optional progress source bound to the live producer's append-only stdout.
use super::*;
use std::io::{Seek, SeekFrom};

const MAX_TAIL: u64 = 8 * 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Config {
    path: PathBuf,
    device: u64,
    inode: u64,
}

#[derive(Debug, Serialize)]
pub(super) struct Evidence {
    path: PathBuf,
    device: u64,
    inode: u64,
    producer_main_pid: u64,
    snapshot_length_bytes: u64,
    read_offset_bytes: u64,
    read_bytes: u64,
    read_sha256: String,
    stdout_append_binding_verified: bool,
}

fn validate_metadata(config: &Config, metadata: &fs::Metadata) -> Result<()> {
    ensure!(
        metadata.is_file() && metadata.nlink() == 1,
        "log must be a singly linked regular file"
    );
    ensure!(
        metadata.uid() == 0 && metadata.mode() & 0o077 == 0,
        "log must be root-owned and owner-only"
    );
    ensure!(
        metadata.dev() == config.device && metadata.ino() == config.inode,
        "log identity mismatch"
    );
    Ok(())
}

fn bind_stdout(config: &Config, pid: u64) -> Result<()> {
    ensure!(pid > 0, "producer has no main PID");
    let fd = PathBuf::from(format!("/proc/{pid}/fd/1"));
    ensure!(
        fs::read_link(&fd)? == config.path,
        "producer stdout path mismatch"
    );
    validate_metadata(config, &fs::metadata(fd)?)?;
    let info = fs::read_to_string(format!("/proc/{pid}/fdinfo/1"))?;
    let flags = info
        .lines()
        .find_map(|line| line.strip_prefix("flags:\t"))
        .ok_or_else(|| anyhow!("stdout flags missing"))?;
    let flags = u32::from_str_radix(flags.trim(), 8)?;
    ensure!(
        flags & libc::O_APPEND as u32 != 0,
        "stdout is not append-only"
    );
    Ok(())
}

fn timestamp(line: &str) -> Result<u64> {
    let stamp = line
        .strip_prefix('[')
        .and_then(|s| s.split_once(' ').map(|p| p.0))
        .ok_or_else(|| anyhow!("progress line lacks timestamp"))?;
    ensure!(stamp.is_ascii(), "progress timestamp must be ASCII");
    let (seconds, fraction) = stamp
        .split_once('.')
        .ok_or_else(|| anyhow!("progress timestamp lacks fraction"))?;
    let fraction = fraction
        .strip_suffix('Z')
        .ok_or_else(|| anyhow!("progress timestamp is not UTC"))?;
    ensure!(
        !fraction.is_empty() && fraction.len() <= 9 && fraction.bytes().all(|b| b.is_ascii_digit()),
        "invalid progress fraction"
    );
    let micros: u64 = format!("{fraction:0<6}")[..6].parse()?;
    parse_utc(&format!("{seconds}Z"))?
        .checked_mul(1_000_000)
        .and_then(|v| v.checked_add(micros))
        .ok_or_else(|| anyhow!("timestamp overflow"))
}

fn points(bytes: &[u8], offset: u64, since: u64, until: u64) -> Result<Vec<ProgressPoint>> {
    let text = std::str::from_utf8(bytes).context("log tail is not UTF-8")?;
    let mut lines = text.split_inclusive('\n');
    if offset > 0 {
        lines.next();
    }
    let mut points = Vec::new();
    let mut covers_start = offset == 0;
    let mut previous = None;
    for line in lines {
        // Ignore a concurrently incomplete final write, not malformed complete markers.
        if !line.ends_with('\n') || !line.contains("progress slot ") {
            continue;
        }
        let stamp = timestamp(line)?;
        ensure!(
            previous.is_none_or(|p| stamp >= p),
            "append-log progress timestamps moved backwards"
        );
        previous = Some(stamp);
        covers_start |= stamp / 1_000_000 < since || stamp == since.saturating_mul(1_000_000);
        if stamp / 1_000_000 >= since && stamp / 1_000_000 < until {
            points.push(
                parse_progress_point(line, stamp)
                    .ok_or_else(|| anyhow!("malformed append-log progress"))?,
            );
        }
    }
    ensure!(
        covers_start,
        "bounded log tail does not cover observation window"
    );
    Ok(points)
}

pub(super) fn observe(
    config: &Config,
    producer: &UnitObservation,
    since: u64,
    until: u64,
) -> Result<ProgressWindow> {
    ensure!(
        config.path.is_absolute() && config.path.canonicalize()? == config.path,
        "log path must be canonical and absolute"
    );
    bind_stdout(config, producer.main_pid)?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&config.path)?;
    let before = file.metadata()?;
    validate_metadata(config, &before)?;
    let offset = before.len().saturating_sub(MAX_TAIL);
    file.seek(SeekFrom::Start(offset))?;
    let mut bytes = Vec::new();
    (&mut file)
        .take(before.len() - offset)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == before.len() - offset,
        "log truncated during read"
    );
    let after = file.metadata()?;
    validate_metadata(config, &after)?;
    ensure!(
        after.len() >= before.len(),
        "log truncated during observation"
    );
    validate_metadata(config, &fs::symlink_metadata(&config.path)?)?;
    bind_stdout(config, producer.main_pid)?;
    let current = observe_unit(&producer.unit, &producer.invocation_id)?;
    ensure!(
        stable_unit(producer, &current) && producer.main_pid == current.main_pid,
        "producer changed during log observation"
    );
    let mut window = progress_window_from_points(
        &producer.invocation_id,
        since,
        until,
        points(&bytes, offset, since, until)?,
    )?;
    window.append_log_evidence = Some(Evidence {
        path: config.path.clone(),
        device: config.device,
        inode: config.inode,
        producer_main_pid: producer.main_pid,
        snapshot_length_bytes: before.len(),
        read_offset_bytes: offset,
        read_bytes: bytes.len() as u64,
        read_sha256: sha256(&bytes),
        stdout_append_binding_verified: true,
    });
    Ok(window)
}

#[cfg(test)]
mod tests {
    use super::*;
    const LINE: &str = "[2026-10-19T14:07:02.568164507Z INFO  jetstreamer_node] progress slot 62485144/62639490 (64.23%) txs=150558432 accounts=500018890 slots_per_sec=0.93\n";

    #[test]
    fn exact_legacy_line_and_window_filter() {
        let since = parse_utc("2026-10-19T14:07:02Z").unwrap();
        let parsed = points(LINE.as_bytes(), 0, since, since + 1).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].slot, 62485144);
        assert_eq!(parsed[0].realtime_microseconds, since * 1_000_000 + 568164);
        assert!(
            points(LINE.as_bytes(), 0, since + 1, since + 2)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn rejects_incomplete_coverage_malformed_timestamp_and_backwards_time() {
        assert!(points(LINE.as_bytes(), 1, 0, u64::MAX).is_err());
        assert!(timestamp("[garbage INFO] progress slot 1/2").is_err());
        assert!(timestamp(&LINE.replace("568164507Z", "xZ")).is_err());
        let backwards = format!("{}{}", LINE, LINE.replace("14:07:02", "14:07:01"));
        assert!(points(backwards.as_bytes(), 0, 0, u64::MAX).is_err());
        assert!(
            points(LINE.trim_end().as_bytes(), 0, 0, u64::MAX)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn metadata_rejects_unbound_identity() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("log");
        fs::write(&path, LINE).unwrap();
        let metadata = fs::metadata(&path).unwrap();
        let config = Config {
            path,
            device: metadata.dev(),
            inode: metadata.ino() + 1,
        };
        assert!(validate_metadata(&config, &metadata).is_err());
    }

    #[test]
    fn root_live_stdout_binding_and_file_policy() {
        // Run this explicit capability regression as root before deployment.
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("log");
        let file = OpenOptions::new()
            .create_new(true)
            .append(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        let metadata = file.metadata().unwrap();
        let mut config = Config {
            path: path.clone(),
            device: metadata.dev(),
            inode: metadata.ino(),
        };
        validate_metadata(&config, &metadata).unwrap();
        let mut child = Command::new("/usr/bin/sleep")
            .arg("10")
            .stdout(file)
            .spawn()
            .unwrap();
        let correct = bind_stdout(&config, child.id() as u64);
        config.inode += 1;
        let wrong_inode = bind_stdout(&config, child.id() as u64);
        child.kill().unwrap();
        child.wait().unwrap();
        correct.unwrap();
        assert!(wrong_inode.is_err());
        config.inode -= 1;
        let file = OpenOptions::new().write(true).open(&path).unwrap();
        let mut child = Command::new("/usr/bin/sleep")
            .arg("10")
            .stdout(file)
            .spawn()
            .unwrap();
        let non_append = bind_stdout(&config, child.id() as u64);
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(non_append.is_err());
        fs::hard_link(&path, directory.path().join("hard-link")).unwrap();
        assert!(validate_metadata(&config, &fs::metadata(&path).unwrap()).is_err());
        fs::remove_file(directory.path().join("hard-link")).unwrap();
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(validate_metadata(&config, &fs::metadata(&path).unwrap()).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        std::os::unix::fs::symlink(&path, directory.path().join("symlink")).unwrap();
        assert!(
            validate_metadata(
                &config,
                &fs::symlink_metadata(directory.path().join("symlink")).unwrap()
            )
            .is_err()
        );
    }
}
