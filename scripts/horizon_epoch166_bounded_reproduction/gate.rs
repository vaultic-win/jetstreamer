//! Hold the epoch 166 reproduction until its invocation passes the native guard and capacity checks.
use std::{
    env, fs, io,
    os::unix::{fs::MetadataExt, process::CommandExt},
    path::Path,
    process::Command,
    thread,
    time::{Duration, Instant},
};

const UNIT: &str = "horizon-qualify-166-write-version-reproduction-20261124-v1.service";
const ALIAS: &str = "/run/horizon-166-write-version-v1";
const RUN: &str = "/home/sol/.jetstreamer-private/epoch166-independent-cold-20261120-v1/bounded-write-version-20261124-v1";
const SNAPSHOT: &str = "snapshot-71998051-6GepGUiRjT1G4UpKJKDbCahrzyTeZLPqgZzw7g9td7jm.tar.zst";
const TERMINAL_SLOT: u64 = 72_004_310;
const RELEASE_TIMEOUT: Duration = Duration::from_secs(180);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(60);

fn replay_args() -> Vec<String> {
    vec![
        "166".into(),
        format!("{RUN}/ledger"),
        "--verify".into(),
        format!("--snapshot-archive={ALIAS}/{SNAPSHOT}"),
        format!("--epoch-hashes={ALIAS}/canonical-hashes.txt"),
        format!("--horizon-output={RUN}/ledger/epoch-166.diagnostic.jet"),
        format!("--replay-scratch={RUN}/scratch"),
        format!("--qualification-end-slot={TERMINAL_SLOT}"),
    ]
}

fn invocation_id_is_valid(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && id.bytes().any(|b| b != b'0')
}

fn is_released(path: &Path, invocation: &str) -> io::Result<bool> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    if !meta.is_file()
        || meta.uid() != 0
        || meta.nlink() != 1
        || meta.mode() & 0o7777 != 0o444
        || meta.len() != 32
    {
        return Err(io::Error::other("invalid epoch 166 release file"));
    }
    let file = fs::File::open(path)?;
    let opened = file.metadata()?;
    if (opened.dev(), opened.ino()) != (meta.dev(), meta.ino())
        || io::read_to_string(file)? != invocation
    {
        return Err(io::Error::other(
            "release belongs to a different invocation",
        ));
    }
    Ok(true)
}

fn main() -> io::Result<()> {
    if env::args_os().len() != 1 {
        return Err(io::Error::other("unexpected epoch 166 gate arguments"));
    }
    let invocation = env::var("INVOCATION_ID").map_err(io::Error::other)?;
    let process = fs::metadata("/proc/self")?;
    if !invocation_id_is_valid(&invocation)
        || fs::read_to_string("/proc/self/cgroup")?.trim() != format!("0::/system.slice/{UNIT}")
        || (process.uid(), process.gid()) != (1001, 1003)
    {
        return Err(io::Error::other("unexpected epoch 166 gate identity"));
    }
    let release = Path::new(ALIAS).join("barrier/allow");
    let started = Instant::now();
    let mut next_heartbeat = started + HEARTBEAT_INTERVAL;
    eprintln!(
        "epoch 166: invocation {invocation} waiting at most {} seconds for guard and capacity release",
        RELEASE_TIMEOUT.as_secs()
    );
    while started.elapsed() < RELEASE_TIMEOUT {
        if is_released(&release, &invocation)? {
            eprintln!(
                "epoch 166: invocation {invocation} released after {} seconds through slot {TERMINAL_SLOT}",
                started.elapsed().as_secs()
            );
            return Err(Command::new(format!("{ALIAS}/jetstreamer-node"))
                .args(replay_args())
                .exec());
        }
        if Instant::now() >= next_heartbeat {
            eprintln!(
                "epoch 166: invocation {invocation} still waiting for guard and capacity release, {} seconds remaining",
                RELEASE_TIMEOUT.saturating_sub(started.elapsed()).as_secs()
            );
            next_heartbeat += HEARTBEAT_INTERVAL;
        }
        thread::sleep(Duration::from_millis(200));
    }
    Err(io::Error::other(
        "epoch 166 guard and capacity release expired",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invocation_identity() {
        assert!(invocation_id_is_valid("0123456789abcdef0123456789abcdef"));
        for id in [
            "",
            "00000000000000000000000000000000",
            "0123456789abcdef0123456789abcdeG",
        ] {
            assert!(!invocation_id_is_valid(id));
        }
    }

    #[test]
    fn replay_uses_the_pinned_snapshot_and_private_bounded_output() {
        let args = replay_args();
        assert_eq!(args[0], "166");
        assert_eq!(args[2], "--verify");
        assert_eq!(args[3], format!("--snapshot-archive={ALIAS}/{SNAPSHOT}"));
        assert_eq!(
            args[5],
            format!("--horizon-output={RUN}/ledger/epoch-166.diagnostic.jet")
        );
        assert_eq!(args[7], "--qualification-end-slot=72004310");
    }
}
